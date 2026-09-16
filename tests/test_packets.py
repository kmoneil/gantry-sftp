"""Packet encode/decode: golden frames both directions, round-trip properties, rejections.

The golden frames below are written out by hand from the field layouts in
``draft-ietf-secsh-filexfer-02``, byte by byte, and asserted on **encode and decode**. That
is the whole point of them: a codec checked only against its own encoder is checked against
nothing, and would happily agree with itself about a layout no server uses.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from allocation import (
    DECODE_PEAK_PER_BYTE,
    FIXED_OVERHEAD,
    RETAINED_NOISE,
    decode_quietly,
    empty_free_lists,
    peak_allocation,
    retained_allocation,
    warm_enum_caches,
)
from gantry_sftp.codec import (
    DEFAULT_MAX_FRAME_LENGTH,
    Attrs,
    AttrsReply,
    Close,
    Data,
    Extended,
    ExtendedReply,
    FrameSplitter,
    FSetStat,
    FStat,
    Handle,
    Init,
    LStat,
    MkDir,
    Name,
    NameEntry,
    Open,
    OpenDir,
    OpenFlag,
    Owner,
    PacketType,
    Read,
    ReadDir,
    ReadLink,
    RealPath,
    Remove,
    Rename,
    RmDir,
    SetStat,
    Stat,
    Status,
    StatusCode,
    SymLink,
    Times,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.codec._packets import _DECODERS, _MIN_NAME_ENTRY_LENGTH
from gantry_sftp.exceptions import ProtocolError

# The codec neither knows nor needs this -- it is what `session/` will actually put in a
# WRITE by default, imported rather than restated so the bulk-payload cases below keep
# tracking the real one if it moves.
from gantry_sftp.session._limits import PREFERRED_WRITE_LENGTH


def decode_frame(wire: bytes):
    """Round a full frame through the splitter, the way a transport would."""
    splitter = FrameSplitter()
    (frame,) = splitter.feed(wire)
    return decode(frame)


def roundtrip(packet):
    return decode_frame(encode(packet))


# --- golden frames ----------------------------------------------------------------------
#
# (packet, exact wire bytes). Asserted in both directions.

GOLDEN = [
    pytest.param(
        Init(version=3),
        b"\x00\x00\x00\x05\x01\x00\x00\x00\x03",
        id="INIT-v3",
    ),
    pytest.param(
        Version(version=3, extensions=((b"copy-data", b"1"),)),
        b"\x00\x00\x00\x17\x02\x00\x00\x00\x03\x00\x00\x00\x09copy-data\x00\x00\x00\x011",
        id="VERSION-one-extension",
    ),
    pytest.param(
        Open(request_id=1, filename=b"/a", pflags=OpenFlag.READ),
        b"\x00\x00\x00\x13\x03\x00\x00\x00\x01\x00\x00\x00\x02/a\x00\x00\x00\x01\x00\x00\x00\x00",
        id="OPEN-read-no-attrs",
    ),
    pytest.param(
        Close(request_id=9, handle=b"\x00\x00\x00\x00"),
        b"\x00\x00\x00\x0d\x04\x00\x00\x00\x09\x00\x00\x00\x04\x00\x00\x00\x00",
        id="CLOSE",
    ),
    pytest.param(
        Read(request_id=2, handle=b"H", offset=4096, length=32768),
        b"\x00\x00\x00\x16"
        b"\x05"
        b"\x00\x00\x00\x02"
        b"\x00\x00\x00\x01H"
        b"\x00\x00\x00\x00\x00\x00\x10\x00"
        b"\x00\x00\x80\x00",
        id="READ-offset-4096",
    ),
    pytest.param(
        Write(request_id=3, handle=b"H", offset=0, data=b"hi"),
        b"\x00\x00\x00\x18"
        b"\x06"
        b"\x00\x00\x00\x03"
        b"\x00\x00\x00\x01H"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x02hi",
        id="WRITE",
    ),
    pytest.param(
        SymLink(request_id=6, targetpath=b"T", linkpath=b"L"),
        b"\x00\x00\x00\x0f\x14\x00\x00\x00\x06\x00\x00\x00\x01T\x00\x00\x00\x01L",
        id="SYMLINK-target-first",
    ),
    pytest.param(
        Rename(request_id=7, oldpath=b"o", newpath=b"n"),
        b"\x00\x00\x00\x0f\x12\x00\x00\x00\x07\x00\x00\x00\x01o\x00\x00\x00\x01n",
        id="RENAME",
    ),
    pytest.param(
        Status(request_id=3, code=StatusCode.EOF),
        b"\x00\x00\x00\x11\x65\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
        id="STATUS-eof",
    ),
    pytest.param(
        Status(request_id=4, code=StatusCode.NO_SUCH_FILE, message=b"No such file"),
        b"\x00\x00\x00\x1d"
        b"\x65"
        b"\x00\x00\x00\x04"
        b"\x00\x00\x00\x02"
        b"\x00\x00\x00\x0cNo such file"
        b"\x00\x00\x00\x00",
        id="STATUS-openssh-message-empty-lang",
    ),
    pytest.param(
        Handle(request_id=4, handle=b"\x00\x00\x00\x00"),
        b"\x00\x00\x00\x0d\x66\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00",
        id="HANDLE-four-nul-bytes",
    ),
    pytest.param(
        Data(request_id=5, data=memoryview(b"hi")),
        b"\x00\x00\x00\x0b\x67\x00\x00\x00\x05\x00\x00\x00\x02hi",
        id="DATA",
    ),
    pytest.param(
        Name(request_id=7, entries=(NameEntry(b"f", b"lf", Attrs()),)),
        b"\x00\x00\x00\x18"
        b"\x68"
        b"\x00\x00\x00\x07"
        b"\x00\x00\x00\x01"
        b"\x00\x00\x00\x01f"
        b"\x00\x00\x00\x02lf"
        b"\x00\x00\x00\x00",
        id="NAME-one-entry",
    ),
    pytest.param(
        AttrsReply(request_id=8, attrs=Attrs(size=10)),
        b"\x00\x00\x00\x11\x69\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0a",
        id="ATTRS-size-only",
    ),
    pytest.param(
        Extended(request_id=1, name=b"limits@openssh.com"),
        b"\x00\x00\x00\x1b\xc8\x00\x00\x00\x01\x00\x00\x00\x12limits@openssh.com",
        id="EXTENDED-limits",
    ),
    pytest.param(
        ExtendedReply(request_id=1, data=b"\x00\x00\x00\x00\x00\x04\x00\x00"),
        b"\x00\x00\x00\x0d\xc9\x00\x00\x00\x01\x00\x00\x00\x00\x00\x04\x00\x00",
        id="EXTENDED_REPLY",
    ),
    # The twelve below share three body shapes between them -- `id, path`, `id, handle`, and
    # `id, path, ATTRS` -- so the *type byte* is the only thing distinguishing most of them on
    # the wire. That is exactly the transposition a round-trip property cannot see:
    # `decode(encode(x)) == x` holds just as well if LSTAT and FSTAT swap numbers, and so does
    # a type-byte check that reads the number off the class it is checking. The literal below
    # is written from draft-ietf-secsh-filexfer-02 and OpenSSH's `sftp.h`, so it agrees with
    # something other than us.
    pytest.param(
        LStat(request_id=20, path=b"/lstat"),
        b"\x00\x00\x00\x0f\x07\x00\x00\x00\x14\x00\x00\x00\x06/lstat",
        id="LSTAT",
    ),
    pytest.param(
        FStat(request_id=21, handle=b"\x00\x00\x00\x01"),
        b"\x00\x00\x00\x0d\x08\x00\x00\x00\x15\x00\x00\x00\x04\x00\x00\x00\x01",
        id="FSTAT",
    ),
    # draft-02 6.9. Three flags, so the flags word and the field order are both pinned: size
    # is a uint64 and comes first, permissions is a uint32 and comes after it, and atime
    # precedes mtime under one shared bit. An ATTRS body checked only in its empty form
    # asserts none of that.
    pytest.param(
        SetStat(
            request_id=22,
            path=b"/setstat",
            attrs=Attrs(size=1, permissions=0o644, times=Times(atime=2, mtime=3)),
        ),
        b"\x00\x00\x00\x29"
        b"\x09"
        b"\x00\x00\x00\x16"
        b"\x00\x00\x00\x08/setstat"
        b"\x00\x00\x00\x0d"  # flags: SIZE | PERMISSIONS | ACMODTIME
        b"\x00\x00\x00\x00\x00\x00\x00\x01"  # size, uint64
        b"\x00\x00\x01\xa4"  # permissions, 0o644
        b"\x00\x00\x00\x02"  # atime
        b"\x00\x00\x00\x03",  # mtime
        id="SETSTAT-size-permissions-times",
    ),
    # The uid/gid pair, which is the other place a field order can silently transpose: two
    # uint32s under one flag bit, and nothing on the wire says which is which.
    pytest.param(
        FSetStat(
            request_id=23,
            handle=b"\x00\x00\x00\x02",
            attrs=Attrs(owner=Owner(uid=1000, gid=100), permissions=0o600),
        ),
        b"\x00\x00\x00\x1d"
        b"\x0a"
        b"\x00\x00\x00\x17"
        b"\x00\x00\x00\x04\x00\x00\x00\x02"
        b"\x00\x00\x00\x06"  # flags: UIDGID | PERMISSIONS
        b"\x00\x00\x03\xe8"  # uid 1000
        b"\x00\x00\x00\x64"  # gid 100
        b"\x00\x00\x01\x80",  # permissions, 0o600
        id="FSETSTAT-uidgid-permissions",
    ),
    pytest.param(
        OpenDir(request_id=24, path=b"/dir"),
        b"\x00\x00\x00\x0d\x0b\x00\x00\x00\x18\x00\x00\x00\x04/dir",
        id="OPENDIR",
    ),
    pytest.param(
        ReadDir(request_id=25, handle=b"\x00\x00\x00\x03"),
        b"\x00\x00\x00\x0d\x0c\x00\x00\x00\x19\x00\x00\x00\x04\x00\x00\x00\x03",
        id="READDIR",
    ),
    pytest.param(
        Remove(request_id=26, path=b"/gone"),
        b"\x00\x00\x00\x0e\x0d\x00\x00\x00\x1a\x00\x00\x00\x05/gone",
        id="REMOVE",
    ),
    # The EXTENDED attribute bit is 0x80000000, and a flags word read as signed mangles it.
    # This is the only golden frame that carries it, so it is the only one that would notice.
    pytest.param(
        MkDir(
            request_id=27,
            path=b"/new",
            attrs=Attrs(permissions=0o755, extended=((b"x", b"y"),)),
        ),
        b"\x00\x00\x00\x23"
        b"\x0e"
        b"\x00\x00\x00\x1b"
        b"\x00\x00\x00\x04/new"
        b"\x80\x00\x00\x04"  # flags: EXTENDED | PERMISSIONS
        b"\x00\x00\x01\xed"  # permissions, 0o755
        b"\x00\x00\x00\x01"  # extended_count
        b"\x00\x00\x00\x01x"
        b"\x00\x00\x00\x01y",
        id="MKDIR-permissions-and-an-extended-pair",
    ),
    pytest.param(
        RmDir(request_id=28, path=b"/old"),
        b"\x00\x00\x00\x0d\x0f\x00\x00\x00\x1c\x00\x00\x00\x04/old",
        id="RMDIR",
    ),
    pytest.param(
        RealPath(request_id=29, path=b"."),
        b"\x00\x00\x00\x0a\x10\x00\x00\x00\x1d\x00\x00\x00\x01.",
        id="REALPATH",
    ),
    pytest.param(
        Stat(request_id=30, path=b"/stat"),
        b"\x00\x00\x00\x0e\x11\x00\x00\x00\x1e\x00\x00\x00\x05/stat",
        id="STAT",
    ),
    pytest.param(
        ReadLink(request_id=31, path=b"/link"),
        b"\x00\x00\x00\x0e\x13\x00\x00\x00\x1f\x00\x00\x00\x05/link",
        id="READLINK",
    ),
]


@pytest.mark.parametrize(("packet", "wire"), GOLDEN)
def test_golden_encode(packet, wire: bytes):
    assert encode(packet) == wire


@pytest.mark.parametrize(("packet", "wire"), GOLDEN)
def test_golden_decode(packet, wire: bytes):
    assert decode_frame(wire) == packet


@pytest.mark.parametrize(("packet", "wire"), GOLDEN)
def test_golden_length_prefix_matches_body(packet, wire: bytes):
    assert int.from_bytes(wire[:4], "big") == len(wire) - 4


# --- the bulk payload, which is the case the copy-free rule is about ---------------------


@pytest.mark.parametrize("size", [0, 1, 7, 4096, PREFERRED_WRITE_LENGTH])
def test_a_write_frames_a_bulk_payload_at_every_interesting_size(size: int):
    # `encode` derives the length prefix from a running count rather than from the joined
    # body (D-112), so the sizes that matter are the ones where an off-by-one in that count
    # would still produce a parseable frame. A prefix short by one desynchronises the stream
    # at the *next* packet, which is the failure this library's reassembler exists to
    # prevent, so it is asserted here rather than left to a round trip.
    payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    frame = encode(Write(request_id=9, handle=b"\x00\x00\x00\x01", offset=1 << 40, data=payload))

    assert int.from_bytes(frame[:4], "big") == len(frame) - 4
    assert len(frame) == 4 + 1 + 4 + 4 + 4 + 8 + 4 + size  # prefix, type, id, handle, offset
    decoded = decode_frame(frame)
    assert isinstance(decoded, Write)
    assert decoded.data == payload
    assert decoded.offset == 1 << 40


@pytest.mark.parametrize("size", [0, 1, 7, 4096, PREFERRED_WRITE_LENGTH])
def test_a_write_payload_encodes_the_same_as_bytes_or_as_a_memoryview(size: int):
    # `Write.data` accepts a view so a caller's buffer reaches the wire without being
    # materialised first. The two spellings must not differ by a byte.
    payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    common = {"request_id": 9, "handle": b"\x00\x00\x00\x01", "offset": 1 << 40}
    assert encode(Write(data=memoryview(payload), **common)) == encode(
        Write(data=payload, **common)
    )


# --- SYMLINK: the field order that contradicts the specification ------------------------


def test_symlink_puts_target_before_link_on_the_wire():
    # draft-ietf-secsh-filexfer-02 specifies `string linkpath, string targetpath`. OpenSSH
    # implements the reverse, and OpenSSH is the de-facto specification. Sending the draft
    # order to a real sftp-server returns FAILURE and creates nothing -- see
    # tests/test_real_sftp_server.py, which runs both orders against a live server.
    body = encode(SymLink(request_id=1, targetpath=b"TARGET", linkpath=b"LINK"))[9:]
    assert body == b"\x00\x00\x00\x06TARGET\x00\x00\x00\x04LINK"
    assert body.index(b"TARGET") < body.index(b"LINK")


def test_symlink_fields_survive_a_round_trip_without_swapping():
    # The names must mean the same thing coming back as going out. Swapping them in exactly
    # one of encode/decode would keep this library self-consistent and wrong on the wire.
    out = roundtrip(SymLink(request_id=1, targetpath=b"/the/target", linkpath=b"/the/link"))
    assert out.targetpath == b"/the/target"
    assert out.linkpath == b"/the/link"


# --- STATUS: the optional tail ----------------------------------------------------------


def test_status_without_a_message_tail_decodes_to_empty_strings():
    # Legal in the field: some servers stop after the code. That is terse, not malformed.
    wire = b"\x00\x00\x00\x09\x65\x00\x00\x00\x07\x00\x00\x00\x04"
    status = decode_frame(wire)
    assert status == Status(request_id=7, code=StatusCode.FAILURE, message=b"", language=b"")


def test_status_with_a_message_but_no_language_tag_decodes():
    wire = b"\x00\x00\x00\x15\x65\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x08too many"
    status = decode_frame(wire)
    assert status.message == b"too many"
    assert status.language == b""


def test_status_degrades_a_code_outside_the_defined_range_to_the_catch_all():
    # D-145. This used to raise, and `Codec.receive` latches a ProtocolError as terminal -- so a
    # number with no name in our enum cost the whole connection. It is not a mis-parse: the
    # length, the type, the id and the code field are all well-formed and the codec knows exactly
    # where the frame ends. `FAILURE` is the v3 catch-all and this is what it is for.
    wire = b"\x00\x00\x00\x09\x65\x00\x00\x00\x01\x00\x00\x00\x63"
    status = decode_frame(wire)
    assert status.code is StatusCode.FAILURE
    assert status.raw_code == 99
    assert status.request_id == 1


def test_a_degraded_status_re_encodes_to_the_bytes_it_arrived_as():
    # The degradation must not be lossy on the wire. Re-encoding 99 as 4 would make the round
    # trip a rewrite, and this codec's whole claim is that it is not one.
    #
    # A *full* frame, tail included, because decode is permissive and encode is canonical --
    # see `test_encoding_a_status_is_canonical_even_when_the_decoded_one_was_terse`. A terse
    # frame legitimately does not survive a round trip, and using one here would have tested
    # that rule instead of this one.
    body = (
        b"\x00\x00\x00\x01"  # request id
        b"\x00\x00\x00\x63"  # code 99, which v3 cannot name
        b"\x00\x00\x00\x02"
        b"no"  # message
        b"\x00\x00\x00\x00"  # language
    )
    wire = b"\x00\x00\x00\x13\x65" + body
    assert encode(decode_frame(wire)) == wire


def test_an_ordinary_status_carries_no_raw_code():
    # The field is the exception's evidence, not a second copy of the code. Setting it on every
    # status would make "did this arrive degraded?" unanswerable.
    wire = b"\x00\x00\x00\x09\x65\x00\x00\x00\x01\x00\x00\x00\x04"
    status = decode_frame(wire)
    assert status.code is StatusCode.FAILURE
    assert status.raw_code is None


def test_encoding_a_status_is_canonical_even_when_the_decoded_one_was_terse():
    # Decode is permissive, encode is not. A Status that arrived without a tail re-encodes
    # with an empty tail rather than reproducing the truncation -- we are not in the
    # business of emitting frames that are merely tolerated.
    terse = decode_frame(b"\x00\x00\x00\x09\x65\x00\x00\x00\x07\x00\x00\x00\x04")
    assert encode(terse) == (
        b"\x00\x00\x00\x11\x65\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00"
    )


# --- OPEN: bits v3 does not define ----------------------------------------------------
#
# D-209. Kept whole as a number rather than built into an `OpenFlag`, because CPython keeps every
# flag member it builds and a peer choosing the bits would choose how much memory stayed behind.


def open_frame(pflags: int) -> bytes:
    """An OPEN of ``/a`` by request 5, carrying ``pflags`` and no attributes."""
    return (
        bytes([PacketType.OPEN])
        + b"\x00\x00\x00\x05"
        + b"\x00\x00\x00\x02/a"
        + pflags.to_bytes(4, "big")
        + b"\x00\x00\x00\x00"
    )


def test_an_open_setting_undefined_pflags_keeps_the_wire_value_whole():
    frame = open_frame(0x101)
    packet = decode(frame)
    assert packet == Open(5, b"/a", OpenFlag.READ, Attrs(), raw_pflags=0x101)
    assert encode(packet)[4:] == frame, "the bits it could not name must survive a re-encode"


def test_undefined_pflags_alone_set_no_defined_flag():
    packet = decode(open_frame(0x40))
    assert (packet.pflags, packet.raw_pflags) == (OpenFlag(0), 0x40)


@pytest.mark.parametrize("pflags", [0x00, 0x01, 0x1A, 0x3F])
def test_an_open_with_only_defined_pflags_carries_no_raw_value(pflags: int):
    # 0x3F is every defined bit at once: the widest value that is still ordinary.
    packet = decode(open_frame(pflags))
    assert (packet.pflags, packet.raw_pflags) == (OpenFlag(pflags), None)


@given(wire=st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_any_pflags_value_survives_decode_and_encode_byte_for_byte(wire: int):
    frame = open_frame(wire)
    packet = decode(frame)
    assert encode(packet)[4:] == frame
    assert packet.pflags == wire & 0x3F
    assert packet.raw_pflags == (wire if wire > 0x3F else None)


def test_decoding_undefined_pflags_keeps_nothing_afterwards():
    """D-209: a thousand different ``pflags`` values leave the process as they found it.

    A client never legitimately receives an OPEN, and ``decode`` reads one anyway before the codec
    refuses it -- so building the whole value into an ``OpenFlag`` let any server leave an enum
    member behind per connection, kept for the life of the process.
    """
    warm_enum_caches()
    frames = [open_frame((n + 2) << 8) for n in range(1000)]
    with retained_allocation() as kept:
        for frame in frames:
            decode_quietly(frame)
    assert kept.bytes <= RETAINED_NOISE, f"{kept.bytes} bytes outlived 1000 decodes"


# --- the framing exception --------------------------------------------------------------


def test_init_and_version_have_no_request_id_field():
    assert not hasattr(Init(), "request_id")
    assert not hasattr(Version(), "request_id")


def test_version_body_second_word_is_the_version_not_an_id():
    wire = encode(Version(version=3))
    assert int.from_bytes(wire[5:9], "big") == 3


def test_version_extensions_run_to_the_end_of_the_frame_with_no_count():
    packet = Version(version=3, extensions=((b"a", b"1"), (b"bb", b"22")))
    assert roundtrip(packet) == packet


def test_version_with_no_extensions_decodes_to_an_empty_tuple():
    assert decode_frame(encode(Version(version=3))).extensions == ()


# --- rejections -------------------------------------------------------------------------


def test_unknown_packet_type_is_rejected():
    with pytest.raises(ProtocolError) as exc:
        decode_frame(b"\x00\x00\x00\x05\x7f\x00\x00\x00\x01")
    assert exc.value.args[0].startswith("unknown packet type 127; filexfer v3 defines")
    assert exc.value.packet_type == 127
    # The frame is carried, not described. An unknown type byte is the signature of a
    # server we have never met, and a bug report holding its actual bytes is the difference
    # between adding support for it and guessing at it.
    assert exc.value.raw_frame == b"\x7f\x00\x00\x00\x01"


def test_trailing_bytes_after_a_complete_packet_are_rejected():
    # Our idea of the layout disagreeing with the server's is worth hearing about at the
    # packet that caused it, not at the next one.
    wire = b"\x00\x00\x00\x10\x66\x00\x00\x00\x04\x00\x00\x00\x04abcdXYZ"
    with pytest.raises(ProtocolError) as exc:
        decode_frame(wire)
    assert exc.value.args[0] == ("HANDLE frame has 3 trailing bytes after a complete packet")
    assert exc.value.packet_type == int(PacketType.HANDLE)
    assert exc.value.raw_frame == b"\x66\x00\x00\x00\x04\x00\x00\x00\x04abcdXYZ"


def test_a_truncated_body_is_rejected():
    wire = b"\x00\x00\x00\x07\x05\x00\x00\x00\x02\x00\x00"
    with pytest.raises(ProtocolError) as exc:
        decode_frame(wire)
    # The reader is handed the packet type precisely so a truncation *inside* a body names
    # which packet ran short, rather than reporting a bare offset into an anonymous frame.
    assert exc.value.args[0] == "truncated frame: need 4 more bytes at offset 5, 2 available"
    assert exc.value.packet_type == int(PacketType.READ)
    assert exc.value.raw_frame == b"\x05\x00\x00\x00\x02\x00\x00"


def test_a_frame_with_only_a_type_byte_is_rejected():
    with pytest.raises(ProtocolError):
        decode_frame(b"\x00\x00\x00\x01\x05")


# Every type with a field after its request id, so a refusal there can name it. EXTENDED_REPLY has
# none -- its data runs to the end of the frame -- and INIT and VERSION carry a version instead.
REFUSABLE_AFTER_THE_ID = sorted(
    set(PacketType) - {PacketType.INIT, PacketType.VERSION, PacketType.EXTENDED_REPLY}
)


@pytest.mark.parametrize("packet_type", REFUSABLE_AFTER_THE_ID, ids=lambda t: t.name)
def test_a_refusal_after_the_request_id_names_the_request(packet_type: PacketType):
    frame = bytes([packet_type]) + b"\x00\x00\x30\x39"
    with pytest.raises(ProtocolError) as exc:
        decode(frame)
    assert (exc.value.packet_type, exc.value.request_id) == (packet_type, 12345)


def test_an_extended_reply_cannot_be_refused_after_its_id():
    # Why the list above leaves it out, asserted rather than asserted about.
    assert decode(bytes([PacketType.EXTENDED_REPLY]) + b"\x00\x00\x30\x39") == ExtendedReply(
        12345, b""
    )


# --- what a frame costs (D-209) ---------------------------------------------------------


def name_frame(count: int, entries: int, *, name: bytes = b"") -> bytes:
    """A NAME answering request 7: ``entries`` entries named ``name`` twice, under ``count``."""
    string = len(name).to_bytes(4, "big") + name
    entry = string + string + b"\x00\x00\x00\x00"
    head = bytes([PacketType.NAME]) + b"\x00\x00\x00\x07" + count.to_bytes(4, "big")
    return head + entry * entries


def test_the_smallest_name_entry_is_twelve_bytes():
    # 12 = an empty filename (4) + an empty longname (4) + an ATTRS with no flag set (4), from
    # draft-ietf-secsh-filexfer-02 7 and 5. The encoder is the independent check.
    assert _MIN_NAME_ENTRY_LENGTH == 12
    entry = NameEntry(b"", b"", Attrs())
    assert len(encode(Name(1, (entry, entry)))) - len(encode(Name(1, (entry,)))) == 12


def test_a_count_of_minimal_entries_filling_the_frame_decodes_and_one_more_is_refused():
    # Sixteen entries, more than an entry has bytes, so a minimum one short would still fail
    # to refuse the second frame on its claim.
    assert decode(name_frame(count=16, entries=16)) == Name(7, (NameEntry(b"", b"", Attrs()),) * 16)
    with pytest.raises(ProtocolError) as exc:
        decode(name_frame(count=17, entries=16))
    assert exc.value.args[0] == (
        "NAME entry count 17 at offset 5 cannot fit in the frame: each takes at least 12 bytes "
        "and 192 remain after the count"
    )


def test_a_hostile_name_count_is_refused_before_any_entry_is_decoded():
    """D-209: a NAME claiming four billion entries is refused on the claim, and costs nothing.

    The shape the card was filed on: the largest frame the splitter admits, packed with the
    smallest legal entries, under a count no frame could hold. The refusal was always correct. It
    came from the first read past the end, after an entry had been built for every twelve bytes,
    which held an order of magnitude more memory than the frame.
    """
    frame = name_frame(count=0xFFFFFFFF, entries=(DEFAULT_MAX_FRAME_LENGTH - 9) // 12)
    peaks = []
    for wire in (name_frame(count=0xFFFFFFFF, entries=64), frame):
        decode_quietly(wire)
        with peak_allocation() as peak:
            decode_quietly(wire)
        peaks.append(peak.bytes)
    assert peaks[1] <= peaks[0] + 1024, f"refusing grew with the frame: {peaks}"
    assert peaks[1] <= FIXED_OVERHEAD

    with pytest.raises(ProtocolError) as exc:
        decode(frame)
    assert exc.value.args[0] == (
        "NAME entry count 4294967295 at offset 5 cannot fit in the frame: each takes at least "
        f"12 bytes and {len(frame) - 9} remain after the count"
    )
    assert (exc.value.packet_type, exc.value.request_id) == (PacketType.NAME, 7)
    assert exc.value.raw_frame == frame[: ProtocolError.max_frame_excerpt]


# The shapes that cost the most per wire byte. One-byte names are the densest because an empty
# `bytes` is a shared singleton and a one-byte one is not; the owner and times pairs add a tuple
# and two large integers each for eight bytes.
BIG = 0xFFFFFFF0
DENSE_ENTRIES = [
    NameEntry(b"n", b"n", Attrs()),
    NameEntry(b"n", b"n", Attrs(owner=Owner(BIG, BIG))),
    NameEntry(b"n", b"n", Attrs(owner=Owner(BIG, BIG), times=Times(BIG, BIG))),
    NameEntry(b"", b"", Attrs()),
]


def test_the_decode_bound_is_derived_from_the_densest_legal_frame():
    """``DECODE_PEAK_PER_BYTE`` sits just above the costliest well-formed reply.

    Above it, because the property below quantifies over legal frames too, and a bound below a
    legal reply refuses a server doing nothing wrong. Within a quarter of it, because a bound that
    has drifted far above the real worst case stops noticing a decoder that got more expensive.
    Measured here rather than recorded, since the interpreter moves it: 3.14 costs a few per cent
    more than 3.13 for the same frame.
    """
    ratios = {}
    for entry in DENSE_ENTRIES:
        frame = encode(Name(1, (entry,) * 4096))[4:]
        decode_quietly(frame)
        empty_free_lists()
        with peak_allocation() as peak:
            decode_quietly(frame)
        ratios[entry] = peak.bytes / len(frame)
    densest = max(ratios.values())
    assert densest <= DECODE_PEAK_PER_BYTE, f"a legal frame holds {densest:.2f} per byte"
    assert densest >= DECODE_PEAK_PER_BYTE * 0.75, (
        f"the bound is {DECODE_PEAK_PER_BYTE} and the densest legal frame holds {densest:.2f} "
        f"per byte; lower the bound to match"
    )


# --- the decoder table is complete ------------------------------------------------------


def test_every_packet_type_has_a_golden_frame():
    # The other half of the sweep. A decoder proves a type can be parsed; a golden frame is
    # the only thing that proves it is parsed the way the specification says. Adding a packet
    # type without adding a fixture fails here, rather than on the first server that sends it.
    covered = {packet.packet_type for packet, _wire in (param.values for param in GOLDEN)}
    assert covered == set(PacketType)


def test_every_packet_type_has_a_decoder():
    # The completeness sweep, enforced. Adding a member to PacketType without adding a
    # decoder fails here rather than at runtime on the one server that sends it.
    assert set(_DECODERS) == set(PacketType)


def test_every_decoder_produces_the_packet_type_it_is_registered_under():
    for packet_type, decoder in _DECODERS.items():
        owner = decoder.__self__  # type: ignore[attr-defined]
        assert owner.packet_type == packet_type, (
            f"{owner.__name__} is registered under {packet_type.name}"
        )


# --- round-trip properties --------------------------------------------------------------

paths = st.binary(max_size=64)
handles = st.binary(max_size=16)
ids = st.integers(min_value=0, max_value=0xFFFFFFFF)
u32 = st.integers(min_value=0, max_value=0xFFFFFFFF)
u64 = st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF)

attrs = st.builds(
    Attrs,
    size=st.one_of(st.none(), u64),
    owner=st.one_of(st.none(), st.builds(Owner, u32, u32)),
    permissions=st.one_of(st.none(), u32),
    times=st.one_of(st.none(), st.builds(Times, u32, u32)),
    extended=st.lists(st.tuples(st.binary(max_size=8), st.binary(max_size=8)), max_size=3).map(
        tuple
    ),
)


def open_as_decoded(request_id: int, filename: bytes, wire_pflags: int, attrs: Attrs) -> Open:
    """An OPEN as a decoder builds one from ``wire_pflags``: the six defined bits typed, and the
    value kept whole when it sets any other."""
    raw_pflags = wire_pflags if wire_pflags > 0x3F else None
    return Open(request_id, filename, OpenFlag(wire_pflags & 0x3F), attrs, raw_pflags)


packets = st.one_of(
    st.builds(
        Init,
        version=u32,
        extensions=st.lists(st.tuples(paths, paths), max_size=3).map(tuple),
    ),
    st.builds(
        Version,
        version=u32,
        extensions=st.lists(st.tuples(paths, paths), max_size=3).map(tuple),
    ),
    st.builds(
        open_as_decoded,
        request_id=ids,
        filename=paths,
        wire_pflags=st.one_of(st.integers(min_value=0, max_value=0x3F), u32),
        attrs=attrs,
    ),
    st.builds(Close, request_id=ids, handle=handles),
    st.builds(Read, request_id=ids, handle=handles, offset=u64, length=u32),
    st.builds(Write, request_id=ids, handle=handles, offset=u64, data=st.binary(max_size=128)),
    st.builds(LStat, request_id=ids, path=paths),
    st.builds(FStat, request_id=ids, handle=handles),
    st.builds(SetStat, request_id=ids, path=paths, attrs=attrs),
    st.builds(FSetStat, request_id=ids, handle=handles, attrs=attrs),
    st.builds(OpenDir, request_id=ids, path=paths),
    st.builds(ReadDir, request_id=ids, handle=handles),
    st.builds(Remove, request_id=ids, path=paths),
    st.builds(MkDir, request_id=ids, path=paths, attrs=attrs),
    st.builds(RmDir, request_id=ids, path=paths),
    st.builds(RealPath, request_id=ids, path=paths),
    st.builds(Stat, request_id=ids, path=paths),
    st.builds(Rename, request_id=ids, oldpath=paths, newpath=paths),
    st.builds(ReadLink, request_id=ids, path=paths),
    st.builds(SymLink, request_id=ids, targetpath=paths, linkpath=paths),
    st.builds(Extended, request_id=ids, name=paths, data=st.binary(max_size=32)),
    st.builds(
        Status,
        request_id=ids,
        code=st.sampled_from(StatusCode),
        message=st.binary(max_size=32),
        language=st.binary(max_size=8),
    ),
    st.builds(Handle, request_id=ids, handle=handles),
    st.builds(Data, request_id=ids, data=st.binary(max_size=128).map(memoryview)),
    st.builds(
        Name,
        request_id=ids,
        entries=st.lists(st.builds(NameEntry, paths, paths, attrs), max_size=3).map(tuple),
    ),
    st.builds(AttrsReply, request_id=ids, attrs=attrs),
    st.builds(ExtendedReply, request_id=ids, data=st.binary(max_size=32)),
)


@given(packet=packets)
def test_every_packet_round_trips(packet):
    assert roundtrip(packet) == packet


@given(packet=packets)
def test_encoding_is_stable(packet):
    # Encode/decode/encode must reach a fixed point. If it does not, one direction is
    # dropping or inventing a field.
    once = encode(packet)
    assert encode(decode_frame(once)) == once


@given(packet=packets)
def test_the_type_byte_matches_the_class(packet):
    assert encode(packet)[4] == packet.packet_type


@given(data=st.binary(max_size=256))
def test_arbitrary_frames_decode_or_raise_protocol_error(data: bytes):
    # A file-transfer library parsing hostile server input must fail predictably or not at
    # all. ProtocolError is a decision; ValueError from an enum or IndexError from a slice
    # is a bug.
    if not data:
        return
    with contextlib.suppress(ProtocolError):
        decode(data)


@st.composite
def packed_frames(draw: st.DrawFn) -> bytes:
    """A NAME, ATTRS or VERSION packed with small items under a count that may lie, maybe cut.

    The regime the blob fuzzers above never reach (D-209). A few hundred arbitrary bytes rarely
    spell a NAME with more than a handful of entries, and a reply costs the most per byte when
    every item is as small as it can be.
    """
    kind = draw(st.sampled_from([PacketType.NAME, PacketType.ATTRS, PacketType.VERSION]))
    items = draw(
        st.one_of(
            st.integers(min_value=0, max_value=64), st.integers(min_value=256, max_value=4096)
        )
    )
    name = b"n" * draw(st.integers(min_value=0, max_value=2))
    string = len(name).to_bytes(4, "big") + name
    count = draw(st.one_of(st.just(items), u32)).to_bytes(4, "big")
    if kind is PacketType.NAME:
        attrs = draw(st.sampled_from([b"\x00\x00\x00\x00", b"\x00\x00\x00\x02" + bytes(8)]))
        body = b"\x00\x00\x00\x01" + count + (string + string + attrs) * items
    elif kind is PacketType.ATTRS:
        body = b"\x00\x00\x00\x01\x80\x00\x00\x00" + count + (string + string) * items
    else:
        body = b"\x00\x00\x00\x03" + (string + string) * items
    frame = bytes([kind]) + body
    whole = st.just(len(frame))
    return frame[: draw(st.one_of(whole, st.integers(min_value=1, max_value=len(frame))))]


hostile_frames = st.one_of(
    st.binary(max_size=4096),
    packets.map(lambda packet: encode(packet)[4:]),
    packed_frames(),
)


# No deadline on the two below: tracemalloc slows every allocation, and the packed frames are
# the point. A hang is what the deadline would catch, and the property above still catches it.
@settings(deadline=None)
@given(frame=hostile_frames)
def test_decoding_holds_at_most_a_fixed_multiple_of_the_frame(frame: bytes):
    """D-209: the third leg of the codec's invariant, over arbitrary bytes.

    Measured on a second decode, so a cache the first one filled is not charged to the frame --
    what a decode keeps is the next property's business. The bound is a multiple rather than the
    frame itself because a legal reply costs more than its bytes; see ``DECODE_PEAK_PER_BYTE``.
    """
    decode_quietly(frame)
    with peak_allocation() as peak:
        decode_quietly(frame)
    assert peak.bytes <= DECODE_PEAK_PER_BYTE * len(frame) + FIXED_OVERHEAD, (
        f"{peak.bytes} bytes held decoding a {len(frame)}-byte frame"
    )


# Fewer examples, each a batch: a retention reading needs a full collection, which costs tens of
# milliseconds over this suite's heap.
@settings(deadline=None, max_examples=25)
@given(frames=st.lists(hostile_frames, min_size=1, max_size=16))
def test_decoding_arbitrary_frames_keeps_nothing_afterwards(frames: list[bytes]):
    """D-209: once a decode's result is dropped, nothing it built is left.

    With the enum caches warm -- every member the codec is entitled to build, built -- anything
    left over grows with what a peer sent and outlives the connection it arrived on. The
    ``IntFlag`` cache was exactly that, and this is the instrument that found it.
    """
    warm_enum_caches()
    with retained_allocation() as kept:
        for frame in frames:
            decode_quietly(frame)
    assert kept.bytes <= RETAINED_NOISE, f"{kept.bytes} bytes outlived {len(frames)} decodes"


# --- non-UTF-8 paths --------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        b"\xff\xfe",
        b"\xed\xa0\x80",  # lone surrogate
        b"caf\xe9",  # latin-1 e-acute, not UTF-8
        b"with space and \n newline",
        b"",
        b"..%2f..%2fetc",
    ],
)
def test_paths_are_bytes_and_survive_verbatim(path: bytes):
    # Server-supplied names are attacker-controlled and routinely not UTF-8. The codec
    # neither decodes nor normalises them; policy belongs where it can be configured.
    assert roundtrip(Stat(request_id=1, path=path)).path == path


# --- Data lifetime ----------------------------------------------------------------------


def test_data_payload_aliases_the_frame_rather_than_copying_it():
    splitter = FrameSplitter()
    (frame,) = splitter.feed(encode(Data(request_id=1, data=memoryview(b"payload"))))
    packet = decode(frame)
    assert isinstance(packet.data, memoryview)
    assert bytes(packet.data) == b"payload"
    # Same underlying buffer as the splitter's -- no copy happened on the way through.
    assert packet.data.obj is frame.obj


def test_a_decoded_data_payload_survives_later_feeds():
    # A DATA payload is a slice of its frame, which is precisely the shape no
    # release-based lifetime rule can reach. Holding one across feeds has to be safe, or
    # zero-copy reads are unusable in a pipelined session.
    splitter = FrameSplitter()
    (frame,) = splitter.feed(encode(Data(request_id=1, data=memoryview(b"payload"))))
    packet = decode(frame)
    for n in range(5):
        splitter.feed(encode(Status(request_id=n + 2, code=StatusCode.OK)))
    assert bytes(packet.data) == b"payload"


def test_several_data_payloads_from_one_feed_stay_independent():
    # Pipelining means many DATA frames land together and get written out one at a time.
    # They must not alias each other.
    splitter = FrameSplitter()
    wire = b"".join(
        encode(Data(request_id=n, data=memoryview(bytes([n]) * 8))) for n in range(1, 5)
    )
    packets = [decode(frame) for frame in splitter.feed(wire)]
    splitter.feed(encode(Status(request_id=99, code=StatusCode.OK)))
    assert [bytes(p.data) for p in packets] == [bytes([n]) * 8 for n in range(1, 5)]

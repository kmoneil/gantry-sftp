"""Packet encode/decode: golden frames both directions, round-trip properties, rejections.

The golden frames below are written out by hand from the field layouts in
``draft-ietf-secsh-filexfer-02``, byte by byte, and asserted on **encode and decode**. That
is the whole point of them: a codec checked only against its own encoder is checked against
nothing, and would happily agree with itself about a layout no server uses.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import (
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
from gantry_sftp.codec._packets import _DECODERS
from gantry_sftp.exceptions import ProtocolError


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


def test_status_rejects_a_code_outside_the_defined_range():
    wire = b"\x00\x00\x00\x09\x65\x00\x00\x00\x01\x00\x00\x00\x63"
    with pytest.raises(ProtocolError) as exc:
        decode_frame(wire)
    assert exc.value.args[0] == ("STATUS carries undefined status code 99; filexfer v3 defines 0-8")
    assert exc.value.request_id == 1


def test_encoding_a_status_is_canonical_even_when_the_decoded_one_was_terse():
    # Decode is permissive, encode is not. A Status that arrived without a tail re-encodes
    # with an empty tail rather than reproducing the truncation -- we are not in the
    # business of emitting frames that are merely tolerated.
    terse = decode_frame(b"\x00\x00\x00\x09\x65\x00\x00\x00\x07\x00\x00\x00\x04")
    assert encode(terse) == (
        b"\x00\x00\x00\x11\x65\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00"
    )


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
        Open,
        request_id=ids,
        filename=paths,
        pflags=st.integers(min_value=0, max_value=0x3F).map(OpenFlag),
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

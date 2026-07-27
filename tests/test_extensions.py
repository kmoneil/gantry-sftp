"""Extension request bodies: golden frames both directions, and the field order measured.

The layouts here were read off a real ``sftp-server``, and the tests at the bottom keep them
that way. ``SYMLINK`` is the precedent: its field order contradicts the draft, and a layout
written from memory passes every unit test in the suite while corrupting every real
operation. So the field order is not asserted against our own encoder alone -- it is asserted
against a live server that answers differently when the fields are swapped.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import (
    EXTENSION_FSYNC,
    EXTENSION_LIMITS,
    EXTENSION_POSIX_RENAME,
    FSYNC_NAME,
    LIMITS_NAME,
    OPENSSH_ADVERTISED_EXTENSIONS,
    POSIX_RENAME_NAME,
    CheckFile,
    CheckFileReply,
    Extended,
    ExtendedReply,
    Fsync,
    OpenFlag,
    PacketType,
    PosixRename,
    StatusCode,
    WireWriter,
    decode,
    encode,
)
from gantry_sftp.exceptions import NoSuchFileError, ProtocolError, ServerError
from gantry_sftp.session import LIMITS_EXTENSION, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio


def frame(*parts: bytes) -> bytes:
    """Assemble a full frame: uint32 length, then the body."""
    body = b"".join(parts)
    return len(body).to_bytes(4, "big") + body


def string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


# --- the wire names ----------------------------------------------------------------------


def test_the_bytes_names_are_the_advertised_names():
    # One wire string, spelled once. Two spellings of an extension name is exactly how
    # `copy-data@openssh.com` happened: a name that never matches degrades to the fallback
    # forever and passes every test written against the same wrong constant.
    assert EXTENSION_POSIX_RENAME.encode("ascii") == POSIX_RENAME_NAME
    assert EXTENSION_FSYNC.encode("ascii") == FSYNC_NAME
    assert EXTENSION_LIMITS.encode("ascii") == LIMITS_NAME
    assert LIMITS_EXTENSION == LIMITS_NAME


@pytest.mark.parametrize("name", [EXTENSION_POSIX_RENAME, EXTENSION_FSYNC, EXTENSION_LIMITS])
def test_every_name_we_use_is_one_a_real_server_advertises(name: str):
    advertised = {advertised_name for advertised_name, _ in OPENSSH_ADVERTISED_EXTENSIONS}
    assert name in advertised


def test_the_class_attribute_and_the_module_constant_agree():
    assert PosixRename.extension_name == POSIX_RENAME_NAME
    assert Fsync.extension_name == FSYNC_NAME


# --- golden frames -----------------------------------------------------------------------
#
# Hand-written from the field layouts, byte by byte, and asserted on encode AND decode. A
# codec checked against its own encoder agrees with itself about layouts no server uses.

POSIX_RENAME_GOLDEN = frame(
    bytes([PacketType.EXTENDED]),
    (7).to_bytes(4, "big"),
    string(b"posix-rename@openssh.com"),
    string(b"/incoming/.report.csv.deadbeef.part"),
    string(b"/incoming/report.csv"),
)

FSYNC_GOLDEN = frame(
    bytes([PacketType.EXTENDED]),
    (9).to_bytes(4, "big"),
    string(b"fsync@openssh.com"),
    string(b"\x00\x00\x00\x00"),
)


def test_posix_rename_encodes_to_its_golden_frame():
    request = PosixRename(7, b"/incoming/.report.csv.deadbeef.part", b"/incoming/report.csv")
    assert encode(request.to_extended()) == POSIX_RENAME_GOLDEN


def test_posix_rename_decodes_from_its_golden_frame():
    packet = decode(memoryview(POSIX_RENAME_GOLDEN)[4:])
    assert isinstance(packet, Extended)
    assert PosixRename.from_extended(packet) == PosixRename(
        7, b"/incoming/.report.csv.deadbeef.part", b"/incoming/report.csv"
    )


def test_fsync_encodes_to_its_golden_frame():
    assert encode(Fsync(9, b"\x00\x00\x00\x00").to_extended()) == FSYNC_GOLDEN


def test_fsync_decodes_from_its_golden_frame():
    packet = decode(memoryview(FSYNC_GOLDEN)[4:])
    assert isinstance(packet, Extended)
    assert Fsync.from_extended(packet) == Fsync(9, b"\x00\x00\x00\x00")


# --- check-file, captured from a server that really speaks it ------------------------------

FIXTURES = Path(__file__).parent / "fixtures"

CHECK_FILE_REQUEST = FIXTURES / "check_file_request.bin"
"""The request this library sent, captured off the wire on 2026-07-27.

Committed so the *encoder* is pinned to bytes a real server accepted, not to bytes the
decoder happens to agree with. A codec tested only against its own encoder is tested against
nothing.
"""

CHECK_FILE_REPLY = FIXTURES / "paramiko_check_file_reply.bin"
"""Paramiko 5.0.0's answer to it, same capture.

`check-file` is in **no** secsh draft -- 05, 09 and 13 were each fetched and searched -- so
this frame and paramiko's `SFTPServer._check_file` are the only sources for the layout. That
makes the fixture load-bearing rather than a convenience: there is no document to fall back
on if it goes stale.
"""


def test_check_file_encodes_to_the_frame_a_real_server_accepted():
    # The request in the capture: paramiko's handle is the ASCII string b"hx1" rather than
    # the packed integer OpenSSH uses -- handles are opaque, and this fixture is a reminder
    # that anything reading structure into one is reading its own convention back.
    request = CheckFile(2, b"hx1", algorithms=b"sha1", start_offset=0, length=0, block_size=1024)
    assert encode(request.to_extended()) == CHECK_FILE_REQUEST.read_bytes()


def test_check_file_decodes_from_the_frame_it_sent():
    packet = decode(memoryview(CHECK_FILE_REQUEST.read_bytes())[4:])
    assert isinstance(packet, Extended)
    assert CheckFile.from_extended(packet) == CheckFile(
        2, b"hx1", algorithms=b"sha1", start_offset=0, length=0, block_size=1024
    )


def test_a_real_check_file_reply_decodes_to_ten_sha1_digests():
    """The reply layout, and the two things a from-memory version gets wrong.

    It **echoes the extension name** before the algorithm, which an EXTENDED_REPLY is under
    no general obligation to do. And the digest field is **not length-prefixed** -- paramiko
    writes it with ``add_bytes``, so it runs to the end of the frame. Reading it as a string
    would consume four bytes of the first digest as a length and then overrun.
    """
    packet = decode(memoryview(CHECK_FILE_REPLY.read_bytes())[4:])
    assert isinstance(packet, ExtendedReply)

    parsed = CheckFileReply.from_reply(packet)
    assert parsed.algorithm == b"sha1"
    # 10 KiB of content at 1 KiB blocks, sha1 being 20 bytes wide.
    assert len(parsed.digests) == 200
    digests = parsed.split(20)
    assert len(digests) == 10
    assert len(set(digests)) == 10, "the capture must have distinct blocks or it proves little"


def test_the_captured_digests_are_the_hashes_of_the_content_that_produced_them():
    # Ties the fixture to arithmetic anyone can redo. The capture hashed ten 1 KiB blocks,
    # block n being the byte n repeated -- so the expected digests are computable here without
    # a server, and a fixture that drifts fails against them rather than against itself.
    packet = decode(memoryview(CHECK_FILE_REPLY.read_bytes())[4:])
    assert isinstance(packet, ExtendedReply)
    digests = CheckFileReply.from_reply(packet).split(20)

    expected = tuple(
        hashlib.sha1(bytes([n]) * 1024, usedforsecurity=False).digest() for n in range(10)
    )
    assert digests == expected


def test_a_reply_echoing_the_wrong_extension_name_is_refused():
    writer = WireWriter()
    writer.write_string(b"something-else")
    writer.write_string(b"sha1")
    with pytest.raises(ProtocolError) as exc:
        CheckFileReply.from_reply(ExtendedReply(3, writer.getvalue()))
    assert exc.value.args[0] == (
        "check-file reply echoed b'something-else' where b'check-file' was expected"
    )


def test_a_reply_truncated_before_the_algorithm_is_refused():
    writer = WireWriter()
    writer.write_string(b"check-file")
    with pytest.raises(ProtocolError) as exc:
        CheckFileReply.from_reply(ExtendedReply(3, writer.getvalue()))
    assert exc.value.args[0] == "check-file reply is truncated before the algorithm name"


def test_a_reply_with_no_digests_at_all_is_not_an_error():
    # An empty range is a legitimate thing to ask about, and zero digests is the right answer
    # to it. Refusing here would turn a boundary into a failure.
    writer = WireWriter()
    writer.write_string(b"check-file")
    writer.write_string(b"sha1")
    parsed = CheckFileReply.from_reply(ExtendedReply(3, writer.getvalue()))
    assert parsed.digests == b""
    assert parsed.split(20) == ()


@pytest.mark.parametrize("digest_size", [0, -1])
def test_splitting_by_a_nonsense_digest_size_is_refused(digest_size: int):
    parsed = CheckFileReply(3, b"sha1", b"x" * 20)
    with pytest.raises(ValueError) as exc:
        parsed.split(digest_size)
    assert exc.value.args[0] == f"digest_size must be at least 1, got {digest_size}"


def test_digests_that_do_not_divide_evenly_are_refused_rather_than_split():
    # A remainder means the algorithm we sized against is not the one that produced these
    # bytes. Splitting anyway hands back digests that are silently misaligned, which is the
    # failure mode of every "verified" transfer that was not.
    parsed = CheckFileReply(3, b"sha1", b"x" * 25)
    with pytest.raises(ValueError) as exc:
        parsed.split(20)
    assert exc.value.args[0] == (
        "25 digest bytes do not divide into 20-byte digests, so this is not b'sha1' output"
    )


# --- round trips -------------------------------------------------------------------------


@given(
    request_id=st.integers(min_value=0, max_value=0xFFFFFFFF),
    oldpath=st.binary(max_size=64),
    newpath=st.binary(max_size=64),
)
def test_posix_rename_round_trips(request_id: int, oldpath: bytes, newpath: bytes):
    original = PosixRename(request_id, oldpath, newpath)
    assert PosixRename.from_extended(original.to_extended()) == original


@given(
    request_id=st.integers(min_value=0, max_value=0xFFFFFFFF),
    handle=st.binary(max_size=64),
    algorithms=st.binary(max_size=32),
    start_offset=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    length=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    block_size=st.integers(min_value=0, max_value=0xFFFFFFFF),
)
def test_check_file_round_trips(
    request_id: int,
    handle: bytes,
    algorithms: bytes,
    start_offset: int,
    length: int,
    block_size: int,
):
    # Six fields, two of them uint64, and their order is the thing no unit test written
    # against our own encoder can catch. The golden frame above is what pins the order; this
    # pins that nothing is lost or transposed across the full range of each field.
    original = CheckFile(request_id, handle, algorithms, start_offset, length, block_size)
    assert CheckFile.from_extended(original.to_extended()) == original


@given(
    request_id=st.integers(min_value=0, max_value=0xFFFFFFFF),
    algorithm=st.binary(max_size=16),
    digests=st.binary(max_size=128),
)
def test_a_check_file_reply_survives_being_built_and_read(
    request_id: int, algorithm: bytes, digests: bytes
):
    writer = WireWriter()
    writer.write_string(b"check-file")
    writer.write_string(algorithm)
    body = writer.getvalue() + digests

    parsed = CheckFileReply.from_reply(ExtendedReply(request_id, body))
    assert parsed == CheckFileReply(request_id, algorithm, digests)


@given(
    request_id=st.integers(min_value=0, max_value=0xFFFFFFFF),
    handle=st.binary(max_size=64),
)
def test_fsync_round_trips(request_id: int, handle: bytes):
    original = Fsync(request_id, handle)
    assert Fsync.from_extended(original.to_extended()) == original


@given(oldpath=st.binary(max_size=64), newpath=st.binary(max_size=64))
def test_posix_rename_survives_the_frame(oldpath: bytes, newpath: bytes):
    # Through the actual framing layer, not just the body: a length prefix that disagrees
    # with the body is a class of bug the body-only round trip cannot see.
    original = PosixRename(3, oldpath, newpath)
    packet = decode(memoryview(encode(original.to_extended()))[4:])
    assert isinstance(packet, Extended)
    assert PosixRename.from_extended(packet) == original


# --- the parse refuses what it should ----------------------------------------------------


def test_a_body_named_for_another_extension_is_refused():
    # The failure this prevents: reading a `fsync` body as a rename, which decodes the handle
    # as a path and then renames something the caller never named.
    wrong = Fsync(4, b"\x00\x00\x00\x01").to_extended()
    with pytest.raises(ProtocolError) as exc:
        _ = PosixRename.from_extended(wrong)
    assert exc.value.args[0] == (
        "expected extension 'posix-rename@openssh.com', got b'fsync@openssh.com'"
    )
    assert exc.value.request_id == 4
    assert exc.value.packet_type == int(PacketType.EXTENDED)
    assert exc.value.raw_frame == b"\x00\x00\x00\x04\x00\x00\x00\x01"


def test_a_truncated_posix_rename_body_is_refused():
    truncated = Extended(5, POSIX_RENAME_NAME, string(b"/only/one/path"))
    with pytest.raises(ProtocolError) as exc:
        _ = PosixRename.from_extended(truncated)
    assert exc.value.args[0] == "truncated frame: need 4 more bytes at offset 18, 0 available"
    # The reader over an extension body is built with the packet type and the request id
    # for exactly this error: EXTENDED bodies all look alike on the wire, so an offset with
    # no packet and no id names nothing a caller can act on.
    assert exc.value.packet_type == int(PacketType.EXTENDED)
    assert exc.value.request_id == 5


def test_a_truncated_fsync_body_is_refused():
    with pytest.raises(ProtocolError) as exc:
        _ = Fsync.from_extended(Extended(6, FSYNC_NAME, b"\x00\x00"))
    assert exc.value.args[0] == "truncated frame: need 4 more bytes at offset 0, 2 available"
    assert exc.value.packet_type == int(PacketType.EXTENDED)
    assert exc.value.request_id == 6


def test_trailing_bytes_are_tolerated_rather_than_rejected():
    # Consistent with how the rest of the codec decodes a tail it did not expect: a future
    # revision of an extension may append a field, and refusing to parse the part we do
    # understand gains nothing.
    padded = Extended(7, FSYNC_NAME, string(b"\x00\x00\x00\x00") + b"later revision")
    assert Fsync.from_extended(padded) == Fsync(7, b"\x00\x00\x00\x00")


# --- against a real server ---------------------------------------------------------------


async def test_posix_rename_uses_the_field_order_a_real_server_expects(tmp_path: Path):
    """The SYMLINK lesson, applied before it can bite again.

    With only the source present, the specified order answers ``OK`` and the reversed order
    answers ``NO_SUCH_FILE``. So the two are distinguishable on the wire, which is what makes
    this a measurement rather than a preference -- and a transposed layout would otherwise
    pass every test above.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "source.txt"
    source.write_bytes(b"payload")
    destination = tmp_path / "destination.txt"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        # Reversed: (newpath, oldpath). The server looks for a file that is not there.
        with pytest.raises(NoSuchFileError) as exc:
            await sftp.posix_rename(str(destination), str(source))
        assert exc.value.message == b"No such file"
        assert source.exists(), "the reversed order must not have moved anything"

        await sftp.posix_rename(str(source), str(destination))

    assert destination.read_bytes() == b"payload"
    assert not source.exists()


async def test_posix_rename_overwrites_an_existing_target_on_a_real_server(tmp_path: Path):
    # The entire reason atomic publish needs this extension. Plain RENAME cannot do it.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "new.txt"
    source.write_bytes(b"new contents")
    target = tmp_path / "existing.txt"
    target.write_bytes(b"old contents")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.supports(EXTENSION_POSIX_RENAME)
        await sftp.posix_rename(str(source), str(target))

    assert target.read_bytes() == b"new contents"


async def test_plain_rename_refuses_an_existing_target_on_a_real_server(tmp_path: Path):
    """The measured claim the whole fallback ladder rests on.

    v3 RENAME cannot overwrite. That is why a successful plain rename proves the destination
    appeared whole, and why replacing a file without ``posix-rename`` needs a REMOVE first --
    with a window in which nothing is there.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "src.txt"
    source.write_bytes(b"new")
    target = tmp_path / "dst.txt"
    target.write_bytes(b"old")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as exc:
            await sftp.rename(str(source), str(target))
        assert exc.value.code == int(StatusCode.FAILURE)

        # And onto a name that is free, the same request succeeds.
        await sftp.rename(str(source), str(tmp_path / "free.txt"))

    assert target.read_bytes() == b"old", "the refused rename must have changed nothing"
    assert (tmp_path / "free.txt").read_bytes() == b"new"


async def test_fsync_must_come_before_the_close_on_a_real_server(tmp_path: Path):
    """Measured ordering, not assumed: a closed handle is not a handle any more.

    The reference server answers ``NO_SUCH_FILE`` for a flush of a handle it has already
    closed, so an implementation that flushed after closing would report durability it never
    obtained -- and every unit test with a permissive fake would agree with it.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    target = tmp_path / "durable.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.supports(EXTENSION_FSYNC)
        handle = await sftp.open(str(target), OpenFlag.WRITE | OpenFlag.CREAT)
        await sftp.fsync(handle)
        await sftp.close(handle)

        with pytest.raises(NoSuchFileError) as exc:
            await sftp.fsync(handle)
    assert exc.value.message == b"No such file"

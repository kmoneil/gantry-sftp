"""Extension request bodies: golden frames both directions, and the field order measured.

The layouts here were read off a real ``sftp-server``, and the tests at the bottom keep them
that way. ``SYMLINK`` is the precedent: its field order contradicts the draft, and a layout
written from memory passes every unit test in the suite while corrupting every real
operation. So the field order is not asserted against our own encoder alone -- it is asserted
against a live server that answers differently when the fields are swapped.
"""

from __future__ import annotations

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
    Extended,
    Fsync,
    OpenFlag,
    PacketType,
    PosixRename,
    StatusCode,
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


def test_a_truncated_posix_rename_body_is_refused():
    truncated = Extended(5, POSIX_RENAME_NAME, string(b"/only/one/path"))
    with pytest.raises(ProtocolError) as exc:
        _ = PosixRename.from_extended(truncated)
    assert exc.value.args[0] == "truncated frame: need 4 more bytes at offset 18, 0 available"


def test_a_truncated_fsync_body_is_refused():
    with pytest.raises(ProtocolError) as exc:
        _ = Fsync.from_extended(Extended(6, FSYNC_NAME, b"\x00\x00"))
    assert exc.value.args[0] == "truncated frame: need 4 more bytes at offset 0, 2 available"


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

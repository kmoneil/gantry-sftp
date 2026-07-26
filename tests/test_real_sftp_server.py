"""The codec against a real OpenSSH sftp-server, over a pipe. No ssh, no network.

This is ``LocalServerTransport`` from DESIGN.md 4.3 in embryo, and it is here rather than
in ``live-tests/`` deliberately: it needs no container, no keys and no network, so it runs
in the fast lane on every commit.

The distinction it exists to enforce: a fake proves the codec agrees with our idea of a
server. This proves it agrees with the server everyone else's client is tested against.
Both are necessary and neither substitutes for the other.

Values that vary by OpenSSH build are asserted as invariants rather than as numbers -- the
1024-byte gap between ``max-packet-length`` and ``max-read-length`` is the finding, not the
particular 261120 this machine reports.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from gantry_sftp.codec import (
    OPENSSH_ADVERTISED_EXTENSIONS,
    PROTOCOL_VERSION,
    FrameSplitter,
    OpenFlag,
    PacketType,
    StatusCode,
    WireReader,
    WireWriter,
)

pytestmark = pytest.mark.sftp_server


class LocalSftpServer:
    """Drives a real sftp-server subprocess through the codec's own framing."""

    def __init__(self, binary: Path, cwd: Path) -> None:
        self._proc = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
        )
        self._splitter = FrameSplitter()
        self._request_id = 0

    def _send(self, packet_type: PacketType, body: bytes) -> None:
        frame = bytes([packet_type]) + body
        assert self._proc.stdin is not None
        self._proc.stdin.write(len(frame).to_bytes(4, "big") + frame)
        self._proc.stdin.flush()

    def _recv(self) -> bytes:
        """Read until the splitter yields exactly one frame, then copy it out.

        The copy is the zero-copy contract being honoured rather than violated: the frame
        has to outlive the next feed, so it is copied explicitly and visibly.
        """
        assert self._proc.stdout is not None
        while True:
            frames = self._splitter.feed(self._proc.stdout.read(1))
            if frames:
                assert len(frames) == 1
                return bytes(frames[0])

    def init(self) -> tuple[int, list[tuple[str, str]]]:
        w = WireWriter()
        w.write_uint32(PROTOCOL_VERSION)
        self._send(PacketType.INIT, w.getvalue())
        r = WireReader(self._recv())
        assert r.read_uint8() == PacketType.VERSION
        version = r.read_uint32()
        extensions = []
        while not r.at_end:
            name = bytes(r.read_string()).decode("ascii")
            value = bytes(r.read_string()).decode("ascii")
            extensions.append((name, value))
        return version, extensions

    def request(self, packet_type: PacketType, body: bytes) -> tuple[PacketType, WireReader]:
        self._request_id += 1
        w = WireWriter()
        w.write_uint32(self._request_id)
        w.write_bytes(body)
        self._send(packet_type, w.getvalue())

        r = WireReader(self._recv())
        reply_type = PacketType(r.read_uint8())
        request_id = r.read_uint32()
        assert request_id == self._request_id, "reply correlated to the wrong request"
        r.set_request_id(request_id)
        return reply_type, r

    def close(self) -> None:
        # Closing stdin is what tells sftp-server to exit; closing stdout is what stops the
        # descriptor leaking. Missing the second one shows up as an unraisable exception at
        # GC time, several tests later, attributed to whatever was running then.
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=10)
        finally:
            self._proc.stdout.close()


@pytest.fixture
def server(sftp_server_binary: Path, tmp_path: Path) -> Iterator[LocalSftpServer]:
    s = LocalSftpServer(sftp_server_binary, tmp_path)
    s.init()
    yield s
    s.close()


def string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


# --- VERSION ---------------------------------------------------------------------------


def test_init_negotiates_version_3(sftp_server_binary: Path, tmp_path: Path):
    s = LocalSftpServer(sftp_server_binary, tmp_path)
    try:
        version, _ = s.init()
        assert version == PROTOCOL_VERSION
    finally:
        s.close()


def test_live_extension_advertisement_matches_the_committed_constant(
    sftp_server_binary: Path, tmp_path: Path
):
    # The committed tuple and the fixture both came from a server. This checks them
    # against *this* machine's server, so a version bump that changes the set is caught
    # here rather than by a confusing failure much later.
    s = LocalSftpServer(sftp_server_binary, tmp_path)
    try:
        _, extensions = s.init()
    finally:
        s.close()
    assert tuple(extensions) == OPENSSH_ADVERTISED_EXTENSIONS


# --- limits ----------------------------------------------------------------------------


def test_limits_reserves_framing_headroom_below_the_packet_ceiling(server: LocalSftpServer):
    reply_type, r = server.request(PacketType.EXTENDED, string(b"limits@openssh.com"))
    assert reply_type == PacketType.EXTENDED_REPLY

    max_packet = r.read_uint64()
    max_read = r.read_uint64()
    max_write = r.read_uint64()
    max_handles = r.read_uint64()
    assert r.at_end

    # The finding: the payload ceiling sits *below* the packet ceiling, because the packet
    # also carries type, request id, handle and offset. So a request size of exactly
    # max-packet-length is never achievable, and defaulting to the round number means every
    # request is silently clamped forever.
    assert 0 < max_read < max_packet
    assert 0 < max_write < max_packet
    assert max_handles > 0


# The "0 means no limit" trap -- min(our_size, 0) yields a zero-length READ, an infinite
# loop that reads as a hang -- gets its test alongside the clamp, in the scheduler. There is
# no clamp yet, and a test whose assertion is true by construction is not a placeholder for
# one.


# --- STATUS ----------------------------------------------------------------------------


def test_status_carries_a_message_and_an_empty_language_tag(server: LocalSftpServer):
    reply_type, r = server.request(PacketType.LSTAT, string(b"/nonexistent/definitely/not/here"))
    assert reply_type == PacketType.STATUS
    assert StatusCode(r.read_uint32()) == StatusCode.NO_SUCH_FILE

    message = bytes(r.read_string())
    language = bytes(r.read_string())
    assert message  # OpenSSH does send one; some servers send nothing at all
    # The tag is empty, not "en". A decoder demanding a well-formed RFC-1766 tag rejects
    # every error the reference server sends.
    assert language == b""
    assert r.at_end


# --- handles ---------------------------------------------------------------------------


def test_handles_are_opaque_binary_and_need_not_be_text(server: LocalSftpServer, tmp_path: Path):
    target = tmp_path / "handle.txt"
    target.write_bytes(b"x")

    reply_type, r = server.request(
        PacketType.OPEN,
        string(str(target).encode()) + OpenFlag.READ.to_bytes(4, "big") + (0).to_bytes(4, "big"),
    )
    assert reply_type == PacketType.HANDLE
    handle = bytes(r.read_string())

    # OpenSSH's first handle is four NUL bytes -- a packed integer, not a string. Typing
    # handles as str would corrupt this the moment anyone decoded it.
    assert isinstance(handle, bytes)
    assert not handle.isascii() or b"\x00" in handle

    server.request(PacketType.CLOSE, string(handle))


# --- reads: success, legally-partial, and EOF ------------------------------------------


def test_a_short_read_is_data_and_eof_is_a_status(server: LocalSftpServer, tmp_path: Path):
    # The classic bug in this protocol: treat a short DATA as end-of-file and every
    # pipelined transfer truncates at the first partial response, silently, producing a
    # file that is plausible and wrong. They are different frame types and this proves it
    # against the real server rather than against our idea of one.
    target = tmp_path / "ten.bin"
    target.write_bytes(b"0123456789")

    reply_type, r = server.request(
        PacketType.OPEN,
        string(str(target).encode()) + OpenFlag.READ.to_bytes(4, "big") + (0).to_bytes(4, "big"),
    )
    assert reply_type == PacketType.HANDLE
    handle = bytes(r.read_string())

    # Full read.
    reply_type, r = server.request(
        PacketType.READ, string(handle) + (0).to_bytes(8, "big") + (4).to_bytes(4, "big")
    )
    assert reply_type == PacketType.DATA
    assert bytes(r.read_string()) == b"0123"

    # Asking for 100 bytes starting at 8 of a 10-byte file: a legal short read.
    reply_type, r = server.request(
        PacketType.READ, string(handle) + (8).to_bytes(8, "big") + (100).to_bytes(4, "big")
    )
    assert reply_type == PacketType.DATA, "a short read must not arrive as EOF"
    assert bytes(r.read_string()) == b"89"

    # Reading at the end: EOF, as a STATUS.
    reply_type, r = server.request(
        PacketType.READ, string(handle) + (10).to_bytes(8, "big") + (4).to_bytes(4, "big")
    )
    assert reply_type == PacketType.STATUS
    assert StatusCode(r.read_uint32()) == StatusCode.EOF

    server.request(PacketType.CLOSE, string(handle))


# --- capability probing ----------------------------------------------------------------


@pytest.mark.parametrize("name", [b"check-file@openssh.com", b"check-file", b"check-file-name"])
def test_check_file_is_unsupported_under_every_spelling(server: LocalSftpServer, name: bytes):
    reply_type, r = server.request(
        PacketType.EXTENDED, string(name) + string(b"/etc/hostname") + string(b"md5")
    )
    assert reply_type == PacketType.STATUS
    assert StatusCode(r.read_uint32()) == StatusCode.OP_UNSUPPORTED


def test_probing_an_unknown_extension_leaves_the_session_usable(server: LocalSftpServer):
    # This is what makes probe-based capability detection safe, and DESIGN.md 4.2 now
    # relies on it: an EXTENDED with an unknown name is a question, not a protocol
    # violation. If a server ever answered by closing the connection, capability probing
    # would have to be abandoned -- so the property is asserted, not assumed.
    reply_type, r = server.request(
        PacketType.EXTENDED, string(b"no-such-extension@example.invalid")
    )
    assert reply_type == PacketType.STATUS
    assert StatusCode(r.read_uint32()) == StatusCode.OP_UNSUPPORTED

    reply_type, r = server.request(PacketType.REALPATH, string(b"."))
    assert reply_type == PacketType.NAME
    assert r.read_uint32() == 1


# --- NAME ------------------------------------------------------------------------------


def test_realpath_longname_is_the_path_not_an_ls_line(server: LocalSftpServer):
    # longname's shape depends on which request produced it: an ls -l line from READDIR,
    # the bare path from REALPATH. That is the argument for never parsing it.
    reply_type, r = server.request(PacketType.REALPATH, string(b"."))
    assert reply_type == PacketType.NAME
    assert r.read_uint32() == 1
    filename = bytes(r.read_string())
    longname = bytes(r.read_string())
    assert longname == filename

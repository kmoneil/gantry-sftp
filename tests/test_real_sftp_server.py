"""The codec against a real OpenSSH sftp-server, over a pipe. No ssh, no network.

This is ``LocalServerTransport`` from DESIGN.md 4.3 in embryo, and it is here rather than
in ``live-tests/`` deliberately: it needs no container, no keys and no network, so it runs
in the fast lane on every commit.

The distinction it exists to enforce: a fake proves the codec agrees with our idea of a
server. This proves it agrees with the server everyone else's client is tested against.
Both are necessary and neither substitutes for the other. Everything below goes through
``encode``/``decode`` rather than hand-rolled struct calls, so what is under test is the
shipped codec and not a second implementation that happens to live in the test file.

Values that vary by OpenSSH build are asserted as invariants rather than as numbers -- the
gap between ``max-packet-length`` and ``max-read-length`` is the finding, not the particular
261120 this machine reports.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from gantry_sftp.codec import (
    OPENSSH_ADVERTISED_EXTENSIONS,
    PROTOCOL_VERSION,
    Close,
    Codec,
    CodecState,
    Completed,
    Data,
    Extended,
    ExtendedReply,
    FrameSplitter,
    Handle,
    Init,
    LStat,
    Name,
    Negotiated,
    Open,
    OpenFlag,
    Packet,
    Read,
    RealPath,
    Status,
    StatusCode,
    SymLink,
    Version,
    WireReader,
    decode,
    encode,
)

pytestmark = pytest.mark.sftp_server


class LocalSftpServer:
    """Drives a real sftp-server subprocess through the shipped codec."""

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

    def send(self, packet: Packet) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(encode(packet))
        self._proc.stdin.flush()

    def recv(self) -> Packet:
        """Read until one complete frame arrives, then decode it.

        A byte at a time because a pipe will not tell us how much is available without
        blocking. Slow, and irrelevant at this scale.
        """
        assert self._proc.stdout is not None
        while True:
            frames = self._splitter.feed(self._proc.stdout.read(1))
            if frames:
                assert len(frames) == 1
                return decode(frames[0])

    def next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def init(self) -> Version:
        self.send(Init())
        reply = self.recv()
        assert isinstance(reply, Version)
        return reply

    def request(self, packet: Packet) -> Packet:
        self.send(packet)
        reply = self.recv()
        assert reply.request_id == packet.request_id, "reply correlated to the wrong request"
        return reply

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


def open_file(server: LocalSftpServer, path: Path, pflags: OpenFlag = OpenFlag.READ) -> bytes:
    reply = server.request(Open(server.next_id(), str(path).encode(), pflags))
    assert isinstance(reply, Handle), reply
    return reply.handle


# --- VERSION ----------------------------------------------------------------------------


def test_init_negotiates_version_3(sftp_server_binary: Path, tmp_path: Path):
    s = LocalSftpServer(sftp_server_binary, tmp_path)
    try:
        assert s.init().version == PROTOCOL_VERSION
    finally:
        s.close()


def test_live_extension_advertisement_matches_the_committed_constant(
    sftp_server_binary: Path, tmp_path: Path
):
    # The committed tuple and the golden fixture both came from a server. This checks them
    # against *this* machine's server, so a version bump that changes the set is caught
    # here rather than by a confusing failure much later.
    s = LocalSftpServer(sftp_server_binary, tmp_path)
    try:
        version = s.init()
    finally:
        s.close()
    decoded = tuple((name.decode(), value.decode()) for name, value in version.extensions)
    assert decoded == OPENSSH_ADVERTISED_EXTENSIONS


def test_the_committed_golden_frame_decodes_to_what_the_live_server_sends(
    sftp_server_binary: Path, tmp_path: Path
):
    # Ties the on-disk fixture to the live server. If they ever disagree, the fixture is
    # stale and the constants derived from it are suspect.
    fixture = (Path(__file__).parent / "fixtures" / "openssh_version_frame.bin").read_bytes()
    from_fixture = decode(fixture)

    s = LocalSftpServer(sftp_server_binary, tmp_path)
    try:
        from_server = s.init()
    finally:
        s.close()
    assert from_fixture == from_server


# --- limits -----------------------------------------------------------------------------


def test_limits_reserves_framing_headroom_below_the_packet_ceiling(server: LocalSftpServer):
    reply = server.request(Extended(server.next_id(), b"limits@openssh.com"))
    assert isinstance(reply, ExtendedReply), reply

    r = WireReader(reply.data)
    max_packet = r.read_uint64()
    max_read = r.read_uint64()
    max_write = r.read_uint64()
    max_handles = r.read_uint64()
    assert r.at_end

    # The finding: the payload ceiling sits *below* the packet ceiling, because the packet
    # also carries type, request id, handle and offset. So a request size of exactly
    # max-packet-length is never achievable, and defaulting to that round number means
    # every request is silently clamped, forever.
    assert 0 < max_read < max_packet
    assert 0 < max_write < max_packet
    assert max_handles > 0


# The "0 means no limit" trap -- min(our_size, 0) yields a zero-length READ, an infinite
# loop that reads as a hang -- gets its test alongside the clamp, in the scheduler. There is
# no clamp yet, and a test whose assertion is true by construction is not a placeholder for
# one.


# --- STATUS -----------------------------------------------------------------------------


def test_status_carries_a_message_and_an_empty_language_tag(server: LocalSftpServer):
    reply = server.request(LStat(server.next_id(), b"/nonexistent/definitely/not/here"))
    assert isinstance(reply, Status), reply
    assert reply.code == StatusCode.NO_SUCH_FILE
    assert reply.message  # OpenSSH does send one; some servers send nothing at all
    # The tag is empty, not "en". A decoder demanding a well-formed RFC-1766 tag rejects
    # every error the reference server sends.
    assert reply.language == b""


# --- handles ----------------------------------------------------------------------------


def test_handles_are_opaque_binary_and_need_not_be_text(server: LocalSftpServer, tmp_path: Path):
    target = tmp_path / "handle.txt"
    target.write_bytes(b"x")
    handle = open_file(server, target)

    # OpenSSH's first handle is four NUL bytes -- a packed integer, not a string. Typing
    # handles as str would corrupt this the moment anyone decoded it.
    assert isinstance(handle, bytes)
    assert not handle.isascii() or b"\x00" in handle
    server.request(Close(server.next_id(), handle))


# --- reads: success, legally-partial, and EOF -------------------------------------------


def test_a_short_read_is_data_and_eof_is_a_status(server: LocalSftpServer, tmp_path: Path):
    # The classic bug in this protocol: treat a short DATA as end-of-file and every
    # pipelined transfer truncates at the first partial response, silently, producing a
    # file that is plausible and wrong. They are different frame types, and this proves it
    # against the real server rather than against our idea of one.
    target = tmp_path / "ten.bin"
    target.write_bytes(b"0123456789")
    handle = open_file(server, target)

    full = server.request(Read(server.next_id(), handle, offset=0, length=4))
    assert isinstance(full, Data), full
    assert bytes(full.data) == b"0123"

    # Asking for 100 bytes starting at 8 of a 10-byte file: a legal short read.
    short = server.request(Read(server.next_id(), handle, offset=8, length=100))
    assert isinstance(short, Data), "a short read must not arrive as EOF"
    assert bytes(short.data) == b"89"

    # Reading at the end: EOF, as a STATUS.
    end = server.request(Read(server.next_id(), handle, offset=10, length=4))
    assert isinstance(end, Status), end
    assert end.code == StatusCode.EOF

    server.request(Close(server.next_id(), handle))


def test_a_read_payload_stays_valid_while_later_replies_arrive(
    server: LocalSftpServer, tmp_path: Path
):
    # Zero-copy DATA is only usable if a payload survives the reads that follow it, because
    # a pipelined session has several in flight at once.
    target = tmp_path / "chunks.bin"
    target.write_bytes(b"AAAABBBBCCCC")
    handle = open_file(server, target)

    payloads = [
        server.request(Read(server.next_id(), handle, offset=off, length=4)) for off in (0, 4, 8)
    ]
    for packet in payloads:
        assert isinstance(packet, Data)
    server.request(Close(server.next_id(), handle))

    assert [bytes(p.data) for p in payloads] == [b"AAAA", b"BBBB", b"CCCC"]


# --- SYMLINK: the field order that contradicts the specification ------------------------


def test_symlink_uses_openssh_field_order_and_the_draft_order_fails(
    server: LocalSftpServer, tmp_path: Path
):
    """draft-ietf-secsh-filexfer-02 and OpenSSH disagree, and OpenSSH wins.

    The draft specifies ``string linkpath, string targetpath``. OpenSSH sends and expects
    the reverse. Both orders are exercised here so the claim is a measurement rather than a
    comment: the draft order fails and creates nothing, ours succeeds and creates the link.
    If a future OpenSSH ever changed its mind, the first assertion is what would notice.
    """
    target = tmp_path / "TARGET.txt"
    target.write_bytes(b"payload\n")

    # Draft order, spelled out positionally: field one is the link, field two the target.
    draft_order = SymLink(
        server.next_id(),
        targetpath=str(tmp_path / "DRAFT_LINK").encode(),  # goes out first
        linkpath=str(target).encode(),  # goes out second
    )
    reply = server.request(draft_order)
    assert isinstance(reply, Status)
    assert reply.code == StatusCode.FAILURE, "the draft's field order unexpectedly worked"
    assert not (tmp_path / "DRAFT_LINK").exists()

    # Our order: targetpath first, linkpath second.
    link = tmp_path / "LINK"
    reply = server.request(
        SymLink(server.next_id(), targetpath=str(target).encode(), linkpath=str(link).encode())
    )
    assert isinstance(reply, Status)
    assert reply.code == StatusCode.OK
    assert link.is_symlink()
    assert link.readlink() == target


# --- capability probing -----------------------------------------------------------------


@pytest.mark.parametrize("name", [b"check-file@openssh.com", b"check-file", b"check-file-name"])
def test_check_file_is_unsupported_under_every_spelling(server: LocalSftpServer, name: bytes):
    reply = server.request(Extended(server.next_id(), name, data=b"\x00\x00\x00\x00"))
    assert isinstance(reply, Status), reply
    assert reply.code == StatusCode.OP_UNSUPPORTED


def test_probing_an_unknown_extension_leaves_the_session_usable(server: LocalSftpServer):
    # This is what makes probe-based capability detection safe, and DESIGN.md 4.2 now
    # relies on it: an EXTENDED with an unknown name is a question, not a protocol
    # violation. If a server ever answered by closing the connection, capability probing
    # would have to be abandoned -- so the property is asserted, not assumed.
    reply = server.request(Extended(server.next_id(), b"no-such-extension@example.invalid"))
    assert isinstance(reply, Status), reply
    assert reply.code == StatusCode.OP_UNSUPPORTED

    still_working = server.request(RealPath(server.next_id(), b"."))
    assert isinstance(still_working, Name)
    assert len(still_working.entries) == 1


# --- NAME -------------------------------------------------------------------------------


def test_realpath_longname_is_the_path_not_an_ls_line(server: LocalSftpServer):
    # longname's shape depends on which request produced it: an ls -l line from READDIR,
    # the bare path from REALPATH. That is the argument for never parsing it.
    reply = server.request(RealPath(server.next_id(), b"."))
    assert isinstance(reply, Name), reply
    (entry,) = reply.entries
    assert entry.longname == entry.filename


# --- the state machine, end to end ------------------------------------------------------


class CodecDrivenServer:
    """Drives sftp-server through the full :class:`Codec`, not just encode/decode.

    The handshake, id allocation and correlation are the codec's; this only moves bytes.
    """

    def __init__(self, binary: Path, cwd: Path) -> None:
        self._proc = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
        )
        self.codec = Codec()

    def write(self, data: bytes) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def pump(self, count: int) -> list[Completed | Negotiated]:
        """Read until the codec has reported ``count`` events."""
        assert self._proc.stdout is not None
        events: list[Completed | Negotiated] = []
        while len(events) < count:
            events.extend(self.codec.receive(self._proc.stdout.read(1)))
        return events

    def close(self) -> None:
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=10)
        finally:
            self._proc.stdout.close()


@pytest.fixture
def driven(sftp_server_binary: Path, tmp_path: Path) -> Iterator[CodecDrivenServer]:
    s = CodecDrivenServer(sftp_server_binary, tmp_path)
    yield s
    s.close()


def test_the_codec_negotiates_with_a_real_server(driven: CodecDrivenServer):
    driven.write(driven.codec.initiate())
    (event,) = driven.pump(1)
    assert isinstance(event, Negotiated)
    assert event.version == PROTOCOL_VERSION
    assert driven.codec.state is CodecState.READY
    assert driven.codec.extensions[b"limits@openssh.com"] == b"1"


def test_pipelined_reads_correlate_against_a_real_server(driven: CodecDrivenServer, tmp_path: Path):
    """Issue every READ before reading any reply, then check each landed on its own offset.

    This is the property the whole library is for. Localhost will not reorder these, so
    passing here does not prove the scheduler is right under latency -- that is what the
    netem lane is for. What it does prove is that correlation survives contact with a real
    server rather than only with our own encoder.
    """
    codec = driven.codec
    driven.write(codec.initiate())
    driven.pump(1)

    chunk_size = 4
    contents = b"".join(bytes([65 + n]) * chunk_size for n in range(8))  # AAAA BBBB CCCC ...
    target = tmp_path / "pipelined.bin"
    target.write_bytes(contents)

    open_id = codec.allocate_request_id()
    driven.write(codec.send(Open(open_id, str(target).encode(), OpenFlag.READ)))
    (opened,) = driven.pump(1)
    assert isinstance(opened, Completed)
    assert isinstance(opened.response, Handle)
    handle = opened.response.handle

    # Every request goes out before any reply is read.
    offsets = [n * chunk_size for n in range(8)]
    for offset in offsets:
        request_id = codec.allocate_request_id()
        driven.write(codec.send(Read(request_id, handle, offset=offset, length=chunk_size)))
    assert codec.outstanding == len(offsets)

    events = driven.pump(len(offsets))
    assert codec.outstanding == 0

    # Each reply is matched back to the request that asked for it, so the offset comes from
    # the request rather than from arrival order. Reassembling by arrival order is the bug
    # this design exists to make impossible.
    reassembled = bytearray(len(contents))
    for event in events:
        assert isinstance(event, Completed)
        assert isinstance(event.request, Read)
        assert isinstance(event.response, Data)
        offset = event.request.offset
        payload = bytes(event.response.data)
        reassembled[offset : offset + len(payload)] = payload

    assert bytes(reassembled) == contents

    close_id = codec.allocate_request_id()
    driven.write(codec.send(Close(close_id, handle)))
    driven.pump(1)


def test_a_real_servers_error_completes_the_request_that_caused_it(
    driven: CodecDrivenServer, tmp_path: Path
):
    codec = driven.codec
    driven.write(codec.initiate())
    driven.pump(1)

    request_id = codec.allocate_request_id()
    request = Open(request_id, str(tmp_path / "absent").encode(), OpenFlag.READ)
    driven.write(codec.send(request))
    (event,) = driven.pump(1)

    assert isinstance(event, Completed)
    assert event.request is request
    assert isinstance(event.response, Status)
    assert event.response.code == StatusCode.NO_SUCH_FILE
    assert codec.outstanding == 0

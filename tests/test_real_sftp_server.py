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
    Attrs,
    AttrsReply,
    Close,
    Codec,
    CodecState,
    Completed,
    Data,
    Extended,
    ExtendedReply,
    FrameSplitter,
    FSetStat,
    FStat,
    Handle,
    Init,
    LStat,
    Name,
    Negotiated,
    Open,
    OpenFlag,
    Packet,
    Read,
    ReadLink,
    RealPath,
    SetStat,
    Status,
    StatusCode,
    SymLink,
    Times,
    Version,
    WireReader,
    decode,
    encode,
)
from gantry_sftp.session import ServerLimits, negotiate_transfer_sizes

pytestmark = pytest.mark.sftp_server


def _died(proc: subprocess.Popen[bytes]) -> str:
    """Explain an EOF on the server's stdout, which is the server having exited.

    ``sftp-server`` calls ``fatal_fr()`` and exits on a body it cannot parse -- it does not
    answer ``BAD_MESSAGE``. So a packet whose layout is wrong shows up here as a closed pipe
    and nothing else, and a reader that waits for a reply waits forever. Both loops in this
    file read a byte at a time, and ``read(1)`` returns ``b""`` only at EOF, so this is the
    one place the difference between "slow" and "gone" is visible. Naming it turns a hung
    suite into a failure that says which request killed the server.
    """
    return (
        f"sftp-server exited (returncode {proc.poll()}) without answering; a frame it could "
        f"not parse is fatal to it, so this is what a wrong packet layout looks like"
    )


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
            chunk = self._proc.stdout.read(1)
            if not chunk:
                raise AssertionError(_died(self._proc))
            frames = self._splitter.feed(chunk)
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


def test_the_derived_read_size_is_one_the_server_actually_accepts(
    server: LocalSftpServer, tmp_path: Path
):
    """Close the loop on D-2 against the real thing, not just against our arithmetic.

    Ask the server for its limits, derive a read size from them, then issue a read of
    *exactly* that size and confirm a full-length DATA comes back. If the derivation were
    off by even the 1024 bytes of framing headroom, the server would clamp and this would
    come back short -- which is precisely the silent failure the whole calculation exists to
    avoid.
    """
    reply = server.request(Extended(server.next_id(), b"limits@openssh.com"))
    assert isinstance(reply, ExtendedReply), reply
    limits = ServerLimits.from_extended_reply(reply.data)

    target = tmp_path / "big.bin"
    handle_length = 4  # OpenSSH's handles; asserted below rather than assumed

    sizes = negotiate_transfer_sizes(limits, handle_length=handle_length)
    target.write_bytes(bytes(sizes.read_length))

    opened = server.request(
        Open(server.next_id(), str(target).encode(), OpenFlag.READ),
    )
    assert isinstance(opened, Handle), opened
    assert len(opened.handle) == handle_length, "handle length assumption no longer holds"

    data = server.request(Read(server.next_id(), opened.handle, offset=0, length=sizes.read_length))
    assert isinstance(data, Data), data
    assert len(data.data) == sizes.read_length, (
        f"server returned {len(data.data)} bytes for a {sizes.read_length}-byte read; "
        f"the derived size exceeds what it will actually serve"
    )
    server.request(Close(server.next_id(), opened.handle))


def test_a_read_one_byte_over_the_derived_size_is_where_the_server_starts_clamping(
    server: LocalSftpServer, tmp_path: Path
):
    """The other side of the boundary, which is what makes the test above mean something.

    A size-boundary test that only checks the accepted side cannot distinguish "we computed
    the maximum" from "we computed something small enough". Asking for one byte more must
    come back short.
    """
    reply = server.request(Extended(server.next_id(), b"limits@openssh.com"))
    assert isinstance(reply, ExtendedReply), reply
    limits = ServerLimits.from_extended_reply(reply.data)
    sizes = negotiate_transfer_sizes(limits, handle_length=4)

    target = tmp_path / "bigger.bin"
    target.write_bytes(bytes(sizes.read_length + 1))

    opened = server.request(Open(server.next_id(), str(target).encode(), OpenFlag.READ))
    assert isinstance(opened, Handle), opened

    data = server.request(
        Read(server.next_id(), opened.handle, offset=0, length=sizes.read_length + 1)
    )
    assert isinstance(data, Data), data
    assert len(data.data) == sizes.read_length, (
        "asking for one byte more than the derived size was served in full, so the "
        "derivation is not at the server's actual ceiling"
    )
    server.request(Close(server.next_id(), opened.handle))


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


# --- READLINK ---------------------------------------------------------------------------


def test_readlink_returns_the_target_as_a_single_name(server: LocalSftpServer, tmp_path: Path):
    """READLINK has no session surface, so this is the only lane that can send one.

    Its reply is the odd one in v3: a NAME frame whose single entry is not a filename in a
    directory but the *contents* of the link, with a cleared attribute set. Reading it as a
    directory listing, or expecting an ATTRS because the request looks like a stat, both
    parse -- and both are wrong.
    """
    target = tmp_path / "READLINK_TARGET.txt"
    target.write_bytes(b"payload\n")
    link = tmp_path / "READLINK_LINK"

    created = server.request(
        SymLink(server.next_id(), targetpath=str(target).encode(), linkpath=str(link).encode())
    )
    assert isinstance(created, Status)
    assert created.code == StatusCode.OK

    reply = server.request(ReadLink(server.next_id(), str(link).encode()))
    assert isinstance(reply, Name), reply
    (entry,) = reply.entries
    assert entry.filename == str(target).encode()
    # OpenSSH sends the same string twice and clears the attributes -- draft-02 6.10's
    # "dummy attributes value", which is an empty flags word rather than a stat of the link.
    assert entry.longname == entry.filename
    assert entry.attrs == Attrs()


def test_readlink_on_a_plain_file_answers_bad_message_not_failure(
    server: LocalSftpServer, tmp_path: Path
):
    """The errored third state, and it arrives under a code that describes something else.

    A reply to READLINK is a NAME *or* a STATUS, so code that unpacks ``reply.entries``
    without checking crashes on the ordinary case of a path that is not a link. The code it
    arrives under is the surprise: ``readlink(2)`` on a plain file sets ``EINVAL``, and
    OpenSSH's ``errno_to_portable`` maps ``EINVAL`` and ``ENAMETOOLONG`` to
    ``SSH2_FX_BAD_MESSAGE``. So ``BAD_MESSAGE`` here does **not** mean the frame we sent was
    malformed -- it means the filesystem said no. Treating that code as a protocol violation
    would tear down a working session over a correct request about an ordinary file.

    Asserted because the library's own handling depends on it: ``BAD_MESSAGE`` maps to
    ``ServerError`` and is absent from ``RETRYABLE_STATUS_CODES``, which is right for both
    readings and would be wrong for one of them if either changed.
    """
    plain = tmp_path / "not_a_link.txt"
    plain.write_bytes(b"x")

    reply = server.request(ReadLink(server.next_id(), str(plain).encode()))
    assert isinstance(reply, Status), reply
    # And not NO_SUCH_FILE, which is the other plausible guess: the path exists, it is just
    # not a symlink.
    assert reply.code == StatusCode.BAD_MESSAGE


# --- FSTAT, SETSTAT, FSETSTAT: the attrs bodies, against a server ------------------------
#
# These three have no `Session` surface either, so before this they had never been sent
# anywhere. That matters more here than for the path-shaped requests, because an ATTRS body
# is a flags word followed by positional fields: a transposition inside it is invisible to a
# round trip through our own encoder, and produces a *successful* STATUS from the server
# while setting the wrong thing.


def test_fstat_reports_the_size_of_an_open_handle(server: LocalSftpServer, tmp_path: Path):
    target = tmp_path / "fstat.bin"
    target.write_bytes(b"0123456")
    handle = open_file(server, target)

    reply = server.request(FStat(server.next_id(), handle))
    assert isinstance(reply, AttrsReply), reply
    assert reply.attrs.size == 7
    server.request(Close(server.next_id(), handle))


def test_fstat_of_a_closed_handle_is_a_status_not_an_attrs(server: LocalSftpServer, tmp_path: Path):
    # The errored third state for FSTAT, and the code is not the one the same condition
    # produces elsewhere: CLOSE of an unknown handle answers NO_SUCH_FILE, while FSTAT of one
    # answers the catch-all. Two requests, one bad handle, two different codes -- so a
    # handle-validity check written against either one does not generalise to the other.
    target = tmp_path / "fstat_closed.bin"
    target.write_bytes(b"x")
    handle = open_file(server, target)
    server.request(Close(server.next_id(), handle))

    reply = server.request(FStat(server.next_id(), handle))
    assert isinstance(reply, Status), reply
    assert reply.code == StatusCode.FAILURE


def test_setstat_applies_permissions_and_times_from_the_positions_the_layout_claims(
    server: LocalSftpServer, tmp_path: Path
):
    """The field-order proof, and the reason a single-flag ATTRS would not have been one.

    Two flags are set at once, and the two fields under ACMODTIME are given different values.
    So the assertions below fail three distinct ways: if permissions and atime swap position,
    the mode is nonsense; if atime and mtime swap, the timestamps land on each other's
    fields; and if the flags word itself is wrong, the server applies neither. A golden frame
    proves we emit what the draft describes. This proves the draft describes what the server
    reads.
    """
    target = tmp_path / "setstat.txt"
    target.write_bytes(b"x")
    target.chmod(0o600)
    atime, mtime = 1_000_000_500, 1_000_000_000  # deliberately unequal, and atime the larger

    reply = server.request(
        SetStat(
            server.next_id(),
            str(target).encode(),
            attrs=Attrs(permissions=0o642, times=Times(atime=atime, mtime=mtime)),
        )
    )
    assert isinstance(reply, Status), reply
    assert reply.code == StatusCode.OK

    stat = target.stat()
    assert stat.st_mode & 0o7777 == 0o642
    assert stat.st_mtime == mtime
    assert stat.st_atime == atime


def test_fsetstat_truncates_and_chmods_through_an_open_handle(
    server: LocalSftpServer, tmp_path: Path
):
    # The size field is a uint64 and sits first in the ATTRS body, ahead of the uint32s. A
    # width error there does not desynchronise our own decoder -- it agrees with itself --
    # but it truncates to the wrong length here, which is visible.
    target = tmp_path / "fsetstat.bin"
    target.write_bytes(b"0123456789")
    target.chmod(0o600)
    handle = open_file(server, target, OpenFlag.READ | OpenFlag.WRITE)

    reply = server.request(
        FSetStat(server.next_id(), handle, attrs=Attrs(size=4, permissions=0o640))
    )
    assert isinstance(reply, Status), reply
    assert reply.code == StatusCode.OK
    server.request(Close(server.next_id(), handle))

    assert target.read_bytes() == b"0123"
    assert target.stat().st_mode & 0o7777 == 0o640


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
            chunk = self._proc.stdout.read(1)
            if not chunk:
                raise AssertionError(_died(self._proc))
            events.extend(self.codec.receive(chunk))
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

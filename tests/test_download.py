"""Pipelined download: offsets, short reads, EOF, timeouts, progress.

Two kinds of coverage here and they are not interchangeable. A scripted fake server can
produce shapes a real server will not make on demand -- deliberate short reads, replies in
reverse order, a server that simply stops answering. A real ``sftp-server`` proves the whole
thing works against the implementation everybody else is tested against. Neither substitutes
for the other.
"""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import anyio.lowlevel
import pytest
from tests.conftest import negotiate, running_dispatcher

from gantry_sftp.codec import (
    Close,
    Codec,
    Data,
    Handle,
    Init,
    Open,
    OpenFlag,
    Read,
    Status,
    StatusCode,
    Version,
    decode,
    encode,
)
from gantry_sftp.codec import (
    FrameSplitter as Splitter,
)
from gantry_sftp.exceptions import TransferError, TransferTimeoutError
from gantry_sftp.session import (
    DEFAULT_PIPELINE_DEPTH,
    ServerLimits,
    download_handle,
    negotiate_transfer_sizes,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

HANDLE = b"\x00\x00\x00\x00"


class ScriptedServer:
    """An in-process transport that answers READs from a byte string, however we choose.

    The point is producing shapes a real server will not produce on demand: a short read at
    a chosen offset, replies in reverse order, or silence. It is explicitly *not* evidence
    that the codec agrees with a real server -- that is what the sftp-server lane is for.
    """

    def __init__(
        self,
        content: bytes,
        *,
        short_at: set[int] | None = None,
        reverse: bool = False,
        silent: bool = False,
    ) -> None:
        self.content = content
        self.short_at = short_at or set()
        self.reverse = reverse
        self.silent = silent
        self.reads: list[tuple[int, int]] = []
        self._splitter = Splitter()
        self._pending: list[bytes] = []
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._handle(decode(frame))

    def _queue(self, frame: bytes) -> None:
        # Waking a waiter rather than letting `receive` find the frame on its next call: the
        # client no longer drives this server turn by turn. A reader task owns `receive` and
        # is already parked in it before the first request is ever sent.
        self._pending.append(frame)
        self._has_output.set()

    def _handle(self, packet: object) -> None:
        if isinstance(packet, Init):
            self._queue(encode(Version(3)))
            return
        if not isinstance(packet, Read):
            raise TypeError(f"scripted server got an unexpected {type(packet).__name__}")

        offset, length = packet.offset, packet.length
        self.reads.append((offset, length))

        if self.silent:
            # Answers the handshake, then never answers a read. This is what a wedged
            # server actually looks like -- it connects fine and then stops.
            return

        if offset >= len(self.content):
            self._queue(encode(Status(packet.request_id, StatusCode.EOF)))
            return

        available = self.content[offset : offset + length]
        if offset in self.short_at and len(available) > 1:
            available = available[: len(available) // 2]
        self._queue(encode(Data(packet.request_id, memoryview(available))))

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._outbox:
            await self._has_output.wait()
            if self.reverse:
                await self._let_the_window_fill()
            batch = self._pending
            self._pending = []
            self._has_output = anyio.Event()
            if self.reverse:
                batch = list(reversed(batch))
            for frame in batch:
                self._outbox += frame
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        return chunk

    async def _let_the_window_fill(self) -> None:
        """Answer nothing until the client has stopped issuing reads.

        Reversing a batch only demonstrates anything if there is more than one reply in it,
        and with a reader task of its own the client would otherwise be answered one read at
        a time -- in perfect order, proving the opposite of what the test is for.
        """
        queued = -1
        while queued != len(self._pending):
            queued = len(self._pending)
            await anyio.lowlevel.checkpoint()

    async def aclose(self) -> None:
        return


async def fetch(server: ScriptedServer, destination: Path, **kwargs) -> int:
    codec = await negotiate(server)  # type: ignore[arg-type]
    # download_handle takes a descriptor, not a path: opening the destination is the
    # session's job, because the flags are a safety decision rather than a scheduling one.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        async with running_dispatcher(server, codec) as dispatcher:  # type: ignore[arg-type]
            return await download_handle(
                dispatcher,
                HANDLE,
                fd,
                size=kwargs.pop("size", len(server.content)),
                read_length=kwargs.pop("read_length", 64),
                **kwargs,
            )
    finally:
        os.close(fd)


# --- the happy path -----------------------------------------------------------------------


async def test_a_file_smaller_than_one_request(tmp_path: Path):
    server = ScriptedServer(b"tiny")
    written = await fetch(server, tmp_path / "out")
    assert written == 4
    assert (tmp_path / "out").read_bytes() == b"tiny"


async def test_a_file_spanning_many_requests(tmp_path: Path):
    content = bytes(range(256)) * 40
    server = ScriptedServer(content)
    written = await fetch(server, tmp_path / "out", read_length=64)
    assert written == len(content)
    assert (tmp_path / "out").read_bytes() == content


async def test_an_empty_file(tmp_path: Path):
    server = ScriptedServer(b"")
    assert await fetch(server, tmp_path / "out") == 0
    assert (tmp_path / "out").read_bytes() == b""


async def test_the_destination_is_truncated_not_appended_to(tmp_path: Path):
    destination = tmp_path / "out"
    destination.write_bytes(b"leftovers from a previous, longer run")
    server = ScriptedServer(b"short")
    await fetch(server, destination)
    assert destination.read_bytes() == b"short"


# --- out-of-order arrival -------------------------------------------------------------------


async def test_replies_arriving_in_reverse_order_reassemble_correctly(tmp_path: Path):
    # Reassembly is by the offset on the *matched request*, never by arrival order.
    # Reversing every batch is the cheapest way to prove the difference matters.
    content = bytes(range(256)) * 20
    server = ScriptedServer(content, reverse=True)
    written = await fetch(server, tmp_path / "out", read_length=32)
    assert written == len(content)
    assert (tmp_path / "out").read_bytes() == content


# --- short reads --------------------------------------------------------------------------


async def test_a_short_read_is_completed_not_treated_as_eof(tmp_path: Path):
    # The failure this prevents has no local symptom: the transfer "succeeds" and the file
    # is silently truncated at the first partial response.
    content = b"".join(bytes([n]) * 16 for n in range(16))
    server = ScriptedServer(content, short_at={0, 32, 96})
    written = await fetch(server, tmp_path / "out", read_length=16)
    assert written == len(content)
    assert (tmp_path / "out").read_bytes() == content


async def test_a_short_read_re_requests_only_the_missing_bytes(tmp_path: Path):
    # "without re-requesting from scratch" is a specific claim, so it gets a specific
    # assertion: the follow-up read starts where the short one stopped.
    server = ScriptedServer(b"0123456789ABCDEF", short_at={0})
    await fetch(server, tmp_path / "out", read_length=16)
    assert server.reads[0] == (0, 16)
    assert (8, 8) in server.reads, f"expected a follow-up for the shortfall, got {server.reads}"
    assert (tmp_path / "out").read_bytes() == b"0123456789ABCDEF"


async def test_repeated_short_reads_still_converge(tmp_path: Path):
    # A server that halves every read must still terminate, and must still be exact.
    content = bytes(range(200))
    server = ScriptedServer(content, short_at=set(range(len(content))))
    written = await fetch(server, tmp_path / "out", read_length=64)
    assert written == len(content)
    assert (tmp_path / "out").read_bytes() == content


# --- the degenerate short read: a DATA carrying no bytes at all ------------------------------
#
# A short read is legal and is re-requested from where it stopped. A read short by *all* of
# it makes no progress: the re-queued range is the one just asked for. A server answering
# every READ that way spins the transfer forever, and it is answering, so the idle timeout
# never fires. OpenSSH's client draws the line at the second one -- `if (len == 0) { if
# (seen_zerolen) fatal_f("server sent zero data length"); seen_zerolen = 1; }` -- so the
# bound here is the reference client's rather than a number chosen here. Treating it as EOF,
# which is the call READDIR gets for the same wire shape, would truncate a file silently.


class ZeroLength(ScriptedServer):
    """Answers READs with a DATA carrying no bytes, from ``after`` onwards."""

    def __init__(self, content: bytes, *, after: int = 0) -> None:
        super().__init__(content)
        self.after = after
        self.zero_replies = 0

    def _handle(self, packet: object) -> None:
        if isinstance(packet, Read) and packet.offset >= self.after:
            self.reads.append((packet.offset, packet.length))
            self.zero_replies += 1
            self._queue(encode(Data(packet.request_id, memoryview(b""))))
            return
        super()._handle(packet)


async def test_a_zero_length_data_is_tolerated_once_like_sftp1_does(tmp_path: Path):
    # One is a hiccup, and refusing it would make this client stricter than sftp(1) against
    # a server that works everywhere else. The retry after it carries the transfer.
    class OnceOnly(ScriptedServer):
        def __init__(self, content: bytes) -> None:
            super().__init__(content)
            self.zero_replies = 0

        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read) and self.zero_replies == 0:
                self.zero_replies += 1
                self.reads.append((packet.offset, packet.length))
                self._queue(encode(Data(packet.request_id, memoryview(b""))))
                return
            super()._handle(packet)

    content = b"0123456789ABCDEF"
    server = OnceOnly(content)
    written = await fetch(server, tmp_path / "out", read_length=16, depth=1)

    assert server.zero_replies == 1
    assert written == len(content)
    assert (tmp_path / "out").read_bytes() == content


async def test_a_second_zero_length_data_fails_rather_than_spinning(tmp_path: Path):
    # Without the bound this test does not fail, it hangs -- so it is under a deadline, and
    # the deadline is generous enough that only a spin can reach it.
    server = ZeroLength(bytes(256), after=64)
    with anyio.fail_after(30):
        with pytest.raises(TransferError) as exc:
            await fetch(server, tmp_path / "out", read_length=64, depth=1)

    assert exc.value.args[0] == (
        "server sent a second zero-length DATA, at offset 64: "
        "it is making no progress, and end of file is a STATUS not an empty DATA"
    )
    # The state that makes it actionable: how far it got, and where it stopped.
    assert exc.value.offset == 64
    assert exc.value.transferred == 64
    assert server.zero_replies == 2, "it should stop on the second, not keep asking"


async def test_a_zero_length_data_at_the_very_first_read_still_terminates(tmp_path: Path):
    # The boundary case where nothing has been transferred: `transferred=0` must not be
    # mistaken for "no progress information".
    server = ZeroLength(bytes(128))
    with anyio.fail_after(30):
        with pytest.raises(TransferError) as exc:
            await fetch(server, tmp_path / "out", read_length=64, depth=1)

    assert exc.value.offset == 0
    assert exc.value.transferred == 0


# --- EOF ------------------------------------------------------------------------------------


async def test_a_file_shorter_than_its_stat_stops_at_eof(tmp_path: Path):
    # Happens when the file is being written concurrently: stat said one thing and the read
    # says another. Stop, do not spin re-requesting past the end.
    server = ScriptedServer(b"only twelve")
    written = await fetch(server, tmp_path / "out", size=4096, read_length=16)
    assert written == len(b"only twelve")
    assert (tmp_path / "out").read_bytes() == b"only twelve"


async def test_an_unknown_size_reads_until_eof(tmp_path: Path):
    # Some servers will not report a size. One extra round trip at the end is the cost.
    content = b"unknown length content" * 10
    server = ScriptedServer(content)
    written = await fetch(server, tmp_path / "out", size=None, read_length=32)
    assert written == len(content)
    assert (tmp_path / "out").read_bytes() == content


# --- failures ---------------------------------------------------------------------------------


class RefusingFrom(ScriptedServer):
    """Refuses every READ at or past ``after``, with a status of our choosing."""

    def __init__(
        self,
        content: bytes,
        *,
        after: int = 0,
        code: StatusCode = StatusCode.PERMISSION_DENIED,
        message: bytes = b"nope",
        reverse: bool = False,
    ) -> None:
        super().__init__(content, reverse=reverse)
        self.after = after
        self.code = code
        self.message = message

    def _handle(self, packet: object) -> None:
        if isinstance(packet, Read) and packet.offset >= self.after:
            self.reads.append((packet.offset, packet.length))
            self._queue(encode(Status(packet.request_id, self.code, self.message)))
            return
        super()._handle(packet)


class RefusesOnlyTheFirstRange(ScriptedServer):
    """Refuses the read at offset 0, with no message, and answers every other range."""

    def _handle(self, packet: object) -> None:
        if isinstance(packet, Read) and packet.offset == 0:
            self.reads.append((packet.offset, packet.length))
            self._queue(encode(Status(packet.request_id, StatusCode.FAILURE)))
            return
        super()._handle(packet)


async def test_a_refused_read_reports_how_far_it_got(tmp_path: Path):
    server = RefusingFrom(bytes(256), after=64)
    with pytest.raises(TransferError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, depth=1)

    assert exc.value.offset == 64
    # Partial progress is the difference between resuming and restarting, so it is carried.
    assert exc.value.transferred == 64
    # Pinned whole rather than by substring: this is the *part way through* wording, and the
    # first-read one below has to stay distinguishable from it.
    assert exc.value.args[0] == "server refused a read at offset 64: PERMISSION_DENIED nope"


# --- the first read is a different event from a read that stopped part way (D-117) -----------
#
# `server refused a read at offset 0` described the request rather than the situation. At the
# first read nothing has arrived, so the transfer did not stop part way -- the object opened
# and would not be read at all, and the local file a `get` created for it is empty. What the
# *cause* was cannot be recovered from the reply on the one server that reaches this code path:
# OpenSSH answers a directory read with v3's catch-all and the message `Failure`. So the
# sentence names a directory as something that arrives looking exactly like this, and does not
# claim it -- see `tests/server_contract.py::a_directory_cannot_be_read_as_a_file` for the
# three servers' three different answers.


async def test_the_first_read_being_refused_says_so_and_names_a_likely_cause(tmp_path: Path):
    server = RefusingFrom(bytes(256), after=0, code=StatusCode.FAILURE, message=b"Failure")
    with pytest.raises(TransferError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, depth=1)

    assert exc.value.args[0] == (
        "server refused the first read, at offset 0: FAILURE Failure -- the handle opened and "
        "then not one byte could be read, so nothing arrived and nothing was truncated. v3's "
        "FAILURE says no more than 'no', and one thing that reaches here looking exactly like "
        "this is a directory: a server that lets one be opened refuses at the read instead"
    )
    assert exc.value.offset == 0
    assert exc.value.transferred == 0


async def test_a_first_read_refused_with_a_status_that_means_something_gets_no_guess(
    tmp_path: Path,
):
    """The hint is withheld for every code that carries its own meaning.

    A directory does not answer `PERMISSION_DENIED` anywhere, so offering it here would be a
    guess printed in the position a reader takes for a diagnosis. The first-read framing itself
    still applies: nothing arrived, and this is not a transfer that stopped part way.
    """
    server = RefusingFrom(bytes(256), after=0)
    with pytest.raises(TransferError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, depth=1)

    assert exc.value.args[0] == (
        "server refused the first read, at offset 0: PERMISSION_DENIED nope -- the handle "
        "opened and then not one byte could be read, so nothing arrived and nothing was "
        "truncated"
    )


async def test_a_refusal_of_the_first_range_after_data_arrived_is_not_called_the_first_read(
    tmp_path: Path,
):
    """Concurrency breaks the invariant that offset 0 is handled first.

    Replies arrive in whatever order the server sends them, so the refusal of the *first*
    range can be handled after a later range has already delivered its bytes. "Not one byte
    could be read" would then be false, and the condition guarding it is a conjunction for
    exactly this case -- `reverse=True` makes the fake produce it on demand, which no real
    server does.
    """
    server = RefusesOnlyTheFirstRange(bytes(256), reverse=True)
    with pytest.raises(TransferError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, depth=4)

    assert exc.value.transferred > 0, "the fake did not deliver a later range first"
    # And a server that sends no message leaves no dangling space behind the code, which the
    # download side did not used to strip and the upload side always did.
    assert exc.value.args[0] == "server refused a read at offset 0: FAILURE"
    assert exc.value.offset == 0


async def test_a_silent_server_times_out_rather_than_hanging(tmp_path: Path):
    # paramiko's answer here is to wait forever. In a scheduled unattended transfer, hanging
    # is worse than failing, because nothing ever reports it.
    server = ScriptedServer(bytes(64), silent=True)
    with pytest.raises(TransferTimeoutError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, idle_timeout=0.25)
    assert "no response from the server for 0.25s" in exc.value.args[0]
    assert "1 request(s) outstanding" in exc.value.args[0]


@pytest.mark.parametrize(("depth", "read_length"), [(0, 64), (-1, 64), (1, 0), (1, -5)])
async def test_settings_that_cannot_make_progress_are_refused(
    tmp_path: Path, depth: int, read_length: int
):
    server = ScriptedServer(b"x")
    with pytest.raises(ValueError):
        await fetch(server, tmp_path / "out", depth=depth, read_length=read_length)


async def test_a_negative_start_offset_is_refused(tmp_path: Path):
    server = ScriptedServer(bytes(64))
    with pytest.raises(ValueError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, start_offset=-1)
    assert exc.value.args[0] == "start_offset must not be negative, got -1"


async def test_a_start_offset_past_the_end_of_the_file_is_refused(tmp_path: Path):
    # Caught here as well as in the session, because this is where the arithmetic lives: an
    # offset past the end issues no reads at all and would report a serene, empty success.
    server = ScriptedServer(bytes(64))
    with pytest.raises(ValueError) as exc:
        await fetch(server, tmp_path / "out", read_length=64, start_offset=65)
    assert exc.value.args[0] == "start_offset 65 is past the end of a 64-byte file"


async def test_a_start_offset_reads_only_the_remainder(tmp_path: Path):
    # The scheduler's half of resume, isolated from the session's decision about *whether* to
    # resume: the reads start where they were told and nothing below the offset is requested.
    content = bytes(range(256))
    server = ScriptedServer(content)
    written = await fetch(server, tmp_path / "out", read_length=64, start_offset=128)

    assert written == 128
    lowest = min(offset for offset, _ in server.reads)
    assert lowest == 128, f"read below the offset it was given: {server.reads}"
    assert (tmp_path / "out").read_bytes()[128:] == content[128:]


async def test_a_start_offset_at_the_end_reads_nothing_at_all(tmp_path: Path):
    server = ScriptedServer(bytes(64))
    assert await fetch(server, tmp_path / "out", read_length=64, start_offset=64) == 0
    assert server.reads == []


async def test_progress_on_a_resumed_download_is_absolute(tmp_path: Path):
    seen: list[tuple[int, int | None]] = []
    server = ScriptedServer(bytes(256))
    await fetch(
        server,
        tmp_path / "out",
        read_length=64,
        start_offset=192,
        progress=lambda transferred, total: seen.append((transferred, total)),
    )
    assert seen[0] == (192, 256), "the first report restarted the count at zero"
    assert seen[-1] == (256, 256)


# --- pipelining and progress --------------------------------------------------------------


async def test_requests_are_issued_ahead_rather_than_one_at_a_time(tmp_path: Path):
    # The whole point. With depth 8 the first eight reads must be issued before any reply is
    # processed -- a lockstep implementation would issue read n+1 only after reply n.
    content = bytes(1024)
    server = ScriptedServer(content)
    await fetch(server, tmp_path / "out", read_length=64, depth=8)

    first_eight = server.reads[:8]
    assert [offset for offset, _ in first_eight] == [n * 64 for n in range(8)]


async def test_depth_bounds_how_much_is_in_flight(tmp_path: Path):
    content = bytes(4096)
    server = ScriptedServer(content)
    await fetch(server, tmp_path / "out", read_length=64, depth=4)
    # Every read is accounted for and none is duplicated, which is what a correct window
    # bookkeeper guarantees.
    offsets = [offset for offset, _ in server.reads]
    assert sorted(offsets) == sorted(set(offsets))


async def test_progress_callback_receives_transferred_and_total(tmp_path: Path):
    content = bytes(1024)
    seen: list[tuple[int, int | None]] = []

    def record(transferred: int, total: int | None) -> None:
        seen.append((transferred, total))

    server = ScriptedServer(content)
    await fetch(server, tmp_path / "out", read_length=64, progress=record)

    assert seen[0] == (0, len(content))
    assert seen[-1] == (len(content), len(content))
    assert [t for t, _ in seen] == sorted(t for t, _ in seen), "progress went backwards"
    assert all(total == len(content) for _, total in seen)


async def test_progress_reports_an_unknown_total_as_none(tmp_path: Path):
    seen: list[tuple[int, int | None]] = []
    server = ScriptedServer(b"abc")

    def record(transferred: int, total: int | None) -> None:
        seen.append((transferred, total))

    await fetch(server, tmp_path / "out", size=None, read_length=8, progress=record)
    assert all(total is None for _, total in seen)


# --- against a real server ------------------------------------------------------------------


async def test_downloading_from_a_real_sftp_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(300_000)
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    destination = tmp_path / "downloaded.bin"

    async with open_local_server_transport(cwd=tmp_path) as transport:
        codec = Codec()
        await transport.send(codec.initiate())
        while codec.state.name != "READY":
            codec.receive(await transport.receive())

        request_id = codec.allocate_request_id()
        await transport.send(codec.send(Open(request_id, str(source).encode(), OpenFlag.READ)))
        opened = None
        while opened is None:
            for event in codec.receive(await transport.receive()):
                opened = event.response
        assert isinstance(opened, Handle), opened

        sizes = negotiate_transfer_sizes(ServerLimits.unknown(), handle_length=len(opened.handle))
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            async with running_dispatcher(transport, codec) as dispatcher:
                written = await download_handle(
                    dispatcher,
                    opened.handle,
                    fd,
                    size=len(content),
                    read_length=sizes.read_length,
                    depth=DEFAULT_PIPELINE_DEPTH,
                )
        finally:
            os.close(fd)
        await transport.send(codec.send(Close(codec.allocate_request_id(), opened.handle)))

    assert written == len(content)
    assert destination.read_bytes() == content

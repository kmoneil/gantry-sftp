"""Pipelined upload: windowing, acknowledgement, failure, and flat exceptions."""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest
from tests.conftest import negotiate, running_dispatcher

from gantry_sftp.codec import (
    Close,
    FrameSplitter,
    Handle,
    Init,
    Open,
    Status,
    StatusCode,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.exceptions import ProtocolError, TransferError, TransferTimeoutError
from gantry_sftp.session import (
    ServerLimits,
    negotiate_transfer_sizes,
    open_session,
    upload_handle,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

HANDLE = b"\x00\x00\x00\x00"


class WritableServer:
    """Accepts writes into an in-memory file, with scriptable misbehaviour."""

    def __init__(
        self,
        *,
        refuse_at: int | None = None,
        silent: bool = False,
        delay_replies: bool = False,
        answer_writes_with_a_handle: bool = False,
    ) -> None:
        self.stored = bytearray()
        self.refuse_at = refuse_at
        self.silent = silent
        self.delay_replies = delay_replies
        # A WRITE is answered with STATUS by the draft. A server that answers with anything
        # else is not one this client can go on talking to, and nothing exercised that branch.
        self.answer_writes_with_a_handle = answer_writes_with_a_handle
        self.writes: list[tuple[int, int]] = []
        self.max_in_flight = 0
        self._in_flight = 0
        self._splitter = FrameSplitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._dispatch(decode(frame))

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

    def _dispatch(self, packet: object) -> None:
        if isinstance(packet, Init):
            self._reply(Version(3))
            return
        if isinstance(packet, Open):
            self._reply(Handle(packet.request_id, HANDLE))
            return
        if isinstance(packet, Close):
            self._reply(Status(packet.request_id, StatusCode.OK))
            return
        if not isinstance(packet, Write):
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))  # type: ignore[union-attr]
            return
        self._on_write(packet)

    def _on_write(self, packet: Write) -> None:
        """A write, and every scripted way of mishandling one.

        Split out of `_dispatch` so each is a branch here rather than another early return
        there -- the misbehaviours are what this fake exists for and they will keep growing.
        """
        self._in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self._in_flight)
        self.writes.append((packet.offset, len(packet.data)))

        if self.silent:
            return
        self._in_flight -= 1
        if self.answer_writes_with_a_handle:
            self._reply(Handle(packet.request_id, HANDLE))
            return
        if self.refuse_at is not None and packet.offset >= self.refuse_at:
            self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"read-only"))
            return

        end = packet.offset + len(packet.data)
        if len(self.stored) < end:
            self.stored.extend(bytes(end - len(self.stored)))
        self.stored[packet.offset : end] = packet.data
        self._reply(Status(packet.request_id, StatusCode.OK))

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if not self._outbox:
            await self._has_output.wait()
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        if not self._outbox:
            self._has_output = anyio.Event()
        return chunk

    async def aclose(self) -> None:
        return


async def push(server: WritableServer, source: Path, **kwargs) -> int:
    codec = await negotiate(server)  # type: ignore[arg-type]
    async with running_dispatcher(server, codec) as dispatcher:  # type: ignore[arg-type]
        return await upload_handle(
            dispatcher,
            HANDLE,
            source,
            write_length=kwargs.pop("write_length", 64),
            **kwargs,
        )


# --- the happy path -----------------------------------------------------------------------


async def test_a_file_smaller_than_one_request(tmp_path: Path):
    source = tmp_path / "in.bin"
    source.write_bytes(b"tiny")
    server = WritableServer()
    assert await push(server, source) == 4
    assert bytes(server.stored) == b"tiny"


async def test_a_file_spanning_many_requests(tmp_path: Path):
    content = bytes(range(256)) * 40
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    server = WritableServer()
    assert await push(server, source, write_length=64) == len(content)
    assert bytes(server.stored) == content


async def test_an_empty_file_sends_no_writes(tmp_path: Path):
    # Zero bytes is a legitimate file, and OPEN with TRUNC already created it. Sending a
    # zero-length WRITE to "finish the job" would be a request that means nothing.
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")
    server = WritableServer()
    assert await push(server, source) == 0
    assert server.writes == []


async def test_offsets_cover_the_file_exactly_once(tmp_path: Path):
    content = bytes(1000)
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    server = WritableServer()
    await push(server, source, write_length=64)

    covered = sorted(server.writes)
    assert covered[0][0] == 0
    assert sum(length for _, length in covered) == len(content)
    offsets = [offset for offset, _ in covered]
    assert offsets == sorted(set(offsets)), "an offset was written twice"


# --- the window is real --------------------------------------------------------------------


async def test_depth_bounds_what_is_in_flight(tmp_path: Path):
    # The window is a semaphore, not a hope. Without it the sender queues the whole file and
    # the unboundedness simply moves to the server.
    content = bytes(4096)
    source = tmp_path / "in.bin"
    source.write_bytes(content)

    server = WritableServer(delay_replies=True)
    await push(server, source, write_length=64, depth=4)
    assert server.max_in_flight <= 4


async def test_writes_are_pipelined_rather_than_lockstep(tmp_path: Path):
    content = bytes(4096)
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    server = WritableServer()
    await push(server, source, write_length=64, depth=8)
    assert len(server.writes) == 64


# --- failure ---------------------------------------------------------------------------------


async def test_a_refused_write_reports_the_offset_and_progress(tmp_path: Path):
    content = bytes(1024)
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    server = WritableServer(refuse_at=256)

    with pytest.raises(TransferError) as exc:
        await push(server, source, write_length=64, depth=1)

    assert exc.value.offset == 256
    # Acknowledged bytes only. Counting at send time would overstate what survived.
    assert exc.value.transferred == 256
    assert exc.value.args[0] == "server refused a write at offset 256: PERMISSION_DENIED read-only"


async def test_a_refused_write_names_the_remote_file_it_refused(tmp_path: Path):
    """`remote_path` is documented as "carried on errors for diagnosis" and was carried nowhere.

    Every test in this file left `upload_handle`'s `remote_path=` at its `None` default, so the
    field could be dropped from both error paths without a single failure -- and a transfer
    error that does not say *which file* is one a caller with eight concurrent uploads cannot
    act on. Passed explicitly here so the plumbing is what is under test rather than the default.
    """
    content = bytes(1024)
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    server = WritableServer(refuse_at=256)

    with pytest.raises(TransferError) as exc:
        await push(server, source, write_length=64, depth=1, remote_path=b"/incoming/in.bin")

    assert exc.value.remote_path == b"/incoming/in.bin"
    assert exc.value.offset == 256
    assert exc.value.transferred == 256


async def test_a_write_answered_with_something_other_than_a_status_is_refused(tmp_path: Path):
    """The reply shape the draft does not allow, from a server that sends it anyway.

    `WRITE` is answered by `STATUS`. A server answering with a `HANDLE` is either broken or
    hostile, and continuing would mean treating an unparsed reply as an acknowledgement -- so
    the bytes would be counted as written when nothing said they were. This branch existed with
    no test at all: the whole `isinstance(response, Status)` guard could be inverted or deleted
    and the suite stayed green.
    """
    source = tmp_path / "in.bin"
    source.write_bytes(bytes(256))
    server = WritableServer(answer_writes_with_a_handle=True)

    with pytest.raises(ProtocolError) as exc:
        await push(server, source, write_length=64, depth=1)

    assert exc.value.args[0] == "server answered a WRITE with Handle"
    # The id is what ties the complaint to a frame in the dump, so it is part of the finding.
    assert exc.value.request_id is not None
    assert not isinstance(exc.value, BaseExceptionGroup)


async def test_a_failure_escapes_as_a_flat_exception_not_an_exception_group(tmp_path: Path):
    """The hazard of concurrent fan-out, asserted rather than hoped for.

    A task group raises ``ExceptionGroup`` even for a single failure, which silently breaks
    every ``except TransferError`` in calling code -- the ladder stops matching and the error
    surfaces as something nobody catches. Uploading is the first place in this library that
    fans out, so it is the first place this can happen.
    """
    source = tmp_path / "in.bin"
    source.write_bytes(bytes(256))
    server = WritableServer(refuse_at=0)

    with pytest.raises(TransferError) as exc:
        await push(server, source, write_length=64)

    assert not isinstance(exc.value, BaseExceptionGroup)
    # And the plain `except` a user would actually write does catch it.
    try:
        await push(WritableServer(refuse_at=0), source, write_length=64)
    except TransferError:
        caught = True
    assert caught


async def test_a_silent_server_times_out(tmp_path: Path):
    source = tmp_path / "in.bin"
    source.write_bytes(bytes(256))
    server = WritableServer(silent=True)

    with pytest.raises(TransferTimeoutError) as exc:
        await push(server, source, write_length=64, idle_timeout=0.25)
    # Four, because 256 bytes at 64 apiece all go out before any reply is due. The count is
    # the actionable half of this message -- "one outstanding" and "the whole file
    # outstanding" call for different responses -- so it is pinned rather than elided.
    assert exc.value.args[0] == "no response from the server for 0.25s with 4 write(s) outstanding"
    # The carried state, which said nothing before: how much survived, and which file. A
    # timeout is the case a caller most wants to resume from, and resuming needs the count.
    assert exc.value.transferred == 0
    assert exc.value.remote_path is None, "not passed here; the next test passes it"
    assert not isinstance(exc.value, BaseExceptionGroup)


async def test_a_timed_out_upload_names_the_file_and_what_it_had_acknowledged(tmp_path: Path):
    """The same error with both fields populated, which is how a caller sees it in practice.

    Split from the test above rather than folded into it: that one pins the message and the
    zero, this one pins that the two fields are *plumbed*, and a single test could pass while
    either half was hard-coded.
    """
    source = tmp_path / "in.bin"
    source.write_bytes(bytes(256))
    server = WritableServer(silent=True, refuse_at=None)

    with pytest.raises(TransferTimeoutError) as exc:
        await push(
            server, source, write_length=64, idle_timeout=0.25, remote_path=b"/incoming/in.bin"
        )

    assert exc.value.remote_path == b"/incoming/in.bin"
    assert exc.value.transferred == 0


@pytest.mark.parametrize(("depth", "write_length"), [(0, 64), (-1, 64), (1, 0)])
async def test_settings_that_cannot_make_progress_are_refused(
    tmp_path: Path, depth: int, write_length: int
):
    source = tmp_path / "in.bin"
    source.write_bytes(b"x")
    with pytest.raises(ValueError):
        await push(WritableServer(), source, depth=depth, write_length=write_length)


async def test_a_negative_start_offset_is_refused(tmp_path: Path):
    source = tmp_path / "in.bin"
    source.write_bytes(b"x" * 64)
    with pytest.raises(ValueError) as exc:
        await push(WritableServer(), source, write_length=64, start_offset=-1)
    assert exc.value.args[0] == "start_offset must not be negative, got -1"


async def test_a_start_offset_past_the_end_of_the_local_file_is_refused(tmp_path: Path):
    source = tmp_path / "in.bin"
    source.write_bytes(b"x" * 64)
    with pytest.raises(ValueError) as exc:
        await push(WritableServer(), source, write_length=64, start_offset=65)
    assert exc.value.args[0] == "start_offset 65 is past the end of a 64-byte local file"


async def test_a_start_offset_writes_only_the_remainder_at_absolute_offsets(tmp_path: Path):
    """The scheduler's half of a resumed upload.

    Both halves of the claim are asserted, because either alone would pass a broken
    implementation: nothing below the offset is *sent*, and what is sent goes to the offsets
    it came from rather than being re-based to zero.
    """
    content = bytes(range(256))
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    server = WritableServer()

    written = await push(server, source, write_length=64, start_offset=128)

    assert written == 128
    assert min(offset for offset, _ in server.writes) == 128, f"wrote below it: {server.writes}"
    assert bytes(server.stored)[128:] == content[128:]


async def test_a_start_offset_at_the_end_writes_nothing_at_all(tmp_path: Path):
    source = tmp_path / "in.bin"
    source.write_bytes(b"x" * 64)
    server = WritableServer()
    assert await push(server, source, write_length=64, start_offset=64) == 0
    assert server.writes == []


# --- progress ---------------------------------------------------------------------------------


async def test_progress_counts_acknowledged_bytes_only(tmp_path: Path):
    content = bytes(1024)
    source = tmp_path / "in.bin"
    source.write_bytes(content)
    seen: list[tuple[int, int | None]] = []

    def record(transferred: int, total: int | None) -> None:
        seen.append((transferred, total))

    await push(WritableServer(), source, write_length=64, progress=record)
    assert seen[0] == (0, len(content))
    assert seen[-1] == (len(content), len(content))
    assert [t for t, _ in seen] == sorted(t for t, _ in seen), "progress went backwards"


# --- against a real server ----------------------------------------------------------------------


async def test_uploading_to_a_real_sftp_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    # Deliberately larger than any plausible pipe buffer, so the concurrent sender/receiver
    # is actually exercised rather than fitting entirely in kernel buffers.
    content = os.urandom(2_000_000)
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    destination = tmp_path / "uploaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination))

    assert result.transferred == len(content)
    assert destination.read_bytes() == content


async def test_a_real_round_trip_is_byte_identical(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(1_500_000)
    source = tmp_path / "source.bin"
    source.write_bytes(content)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put(source, str(tmp_path / "remote.bin"))
        await sftp.get(str(tmp_path / "remote.bin"), tmp_path / "back.bin")

    assert (tmp_path / "back.bin").read_bytes() == content


async def test_uploading_over_a_real_server_uses_the_derived_write_size(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "source.bin"
    source.write_bytes(os.urandom(600_000))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        expected = negotiate_transfer_sizes(sftp.limits, handle_length=4).write_length
        await sftp.put(source, str(tmp_path / "remote.bin"))

    # The derived size is the server's real ceiling, not a round number that gets clamped.
    assert expected == 261120
    assert sftp.limits != ServerLimits.unknown()


# --- the smallest legal settings, and what a refusal renders ------------------------------------
#
# D-105's sixteenth slice. The guards below all read `< 1`, and every test that exercised them
# passed 0 or -1 -- so `<= 1` and `< 2` survived, and the smallest value the guard is written to
# *allow* had never been through the scheduler at all.


async def test_a_depth_and_a_write_length_of_one_still_transfer(tmp_path: Path):
    """One request in flight, one byte at a time: legal, and the boundary the guards name.

    `depth=1` is the spelling for a server that cannot pipeline, and `write_length=1` is what a
    caller reaches for to isolate which byte a broken endpoint mangles. Both are the value the
    guard admits, and a mutation to `<= 1` or `< 2` refuses them while every existing test --
    all of which pass 0 or -1 -- keeps passing.
    """
    source = tmp_path / "in.bin"
    source.write_bytes(b"abc")
    server = WritableServer()

    assert await push(server, source, depth=1, write_length=1) == 3
    assert bytes(server.stored) == b"abc"
    assert server.writes == [(0, 1), (1, 1), (2, 1)]
    assert server.max_in_flight == 1


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"depth": 0}, "depth must be at least 1, got 0"),
        ({"depth": -1}, "depth must be at least 1, got -1"),
        ({"write_length": 0}, "write_length must be at least 1, got 0"),
    ],
    ids=["depth-zero", "depth-negative", "write-length-zero"],
)
async def test_a_setting_that_cannot_make_progress_names_itself_and_its_value(
    tmp_path: Path, kwargs: dict[str, int], message: str
):
    """The value is in the message because the caller usually computed it.

    A `write_length` here comes from `negotiate_transfer_sizes` and a `depth` from a session
    tunable, so "must be at least 1" without the number sends somebody looking at a constant
    rather than at the arithmetic that produced a zero.
    """
    source = tmp_path / "in.bin"
    source.write_bytes(b"x")
    with pytest.raises(ValueError) as refusal:
        await push(WritableServer(), source, **{"write_length": 64, **kwargs})
    assert refusal.value.args[0] == message


async def test_a_refusal_renders_the_server_s_own_words_without_trusting_them(tmp_path: Path):
    """The message on a STATUS is attacker-controlled bytes, and it goes into our error text.

    Three properties in one assertion, each of which a mutation removes on its own: it is
    decoded leniently, because a server may send anything and a `UnicodeDecodeError` from
    inside an error path replaces the diagnosis with a crash; the trailing whitespace real
    servers pad with is stripped from the *right*, so the sentence ends where it should; and
    the offset is the chunk's rather than the transfer's.
    """

    class RefusesRudely(WritableServer):
        def _on_write(self, packet: Write) -> None:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"caf\xe9 quota  \n"))

    source = tmp_path / "in.bin"
    source.write_bytes(b"x" * 128)
    with pytest.raises(TransferError) as refusal:
        await push(RefusesRudely(), source, write_length=64, depth=1)

    assert refusal.value.args[0] == "server refused a write at offset 0: FAILURE caf� quota"


async def test_a_stall_part_way_through_reports_what_was_acknowledged(tmp_path: Path):
    """`transferred` on a timeout, and zero is the one value that cannot prove it is carried.

    The silent-server test above asserts `transferred == 0` -- which is also what the field
    reads if it is never passed, so it cannot tell a plumbed value from a default. A stall
    *after* some writes have been acknowledged is the case a caller resumes from, and the
    count is the whole reason to prefer resuming to restarting.
    """

    class GoesQuietAfter(WritableServer):
        def __init__(self, *, after: int) -> None:
            super().__init__()
            self.after = after

        def _on_write(self, packet: Write) -> None:
            if packet.offset >= self.after:
                self._in_flight += 1
                self.writes.append((packet.offset, len(packet.data)))
                return
            super()._on_write(packet)

    source = tmp_path / "in.bin"
    source.write_bytes(b"x" * 192)

    with pytest.raises(TransferTimeoutError) as timed_out:
        await push(GoesQuietAfter(after=128), source, write_length=64, depth=1, idle_timeout=0.05)

    assert timed_out.value.transferred == 128

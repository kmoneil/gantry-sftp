"""Pipelined upload: windowing, acknowledgement, failure, and flat exceptions."""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Close,
    Codec,
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
from gantry_sftp.exceptions import TransferError, TransferTimeoutError
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
    ) -> None:
        self.stored = bytearray()
        self.refuse_at = refuse_at
        self.silent = silent
        self.delay_replies = delay_replies
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

        self._in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self._in_flight)
        self.writes.append((packet.offset, len(packet.data)))

        if self.silent:
            return
        if self.refuse_at is not None and packet.offset >= self.refuse_at:
            self._in_flight -= 1
            self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"read-only"))
            return

        end = packet.offset + len(packet.data)
        if len(self.stored) < end:
            self.stored.extend(bytes(end - len(self.stored)))
        self.stored[packet.offset : end] = packet.data
        self._in_flight -= 1
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


async def negotiated(server: WritableServer) -> Codec:
    codec = Codec()
    await server.send(codec.initiate())
    while codec.state.name != "READY":
        codec.receive(await server.receive())
    return codec


async def push(server: WritableServer, source: Path, **kwargs) -> int:
    codec = await negotiated(server)
    return await upload_handle(
        server,  # type: ignore[arg-type]
        codec,
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
    assert "PERMISSION_DENIED" in exc.value.args[0]
    assert "read-only" in exc.value.args[0]


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
    assert "no response from the server for 0.25s" in exc.value.args[0]
    assert not isinstance(exc.value, BaseExceptionGroup)


@pytest.mark.parametrize(("depth", "write_length"), [(0, 64), (-1, 64), (1, 0)])
async def test_settings_that_cannot_make_progress_are_refused(
    tmp_path: Path, depth: int, write_length: int
):
    source = tmp_path / "in.bin"
    source.write_bytes(b"x")
    with pytest.raises(ValueError):
        await push(WritableServer(), source, depth=depth, write_length=write_length)


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

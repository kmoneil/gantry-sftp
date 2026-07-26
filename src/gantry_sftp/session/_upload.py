"""Pipelined upload: many writes in flight, without deadlocking.

Why this is not the downloader with the arrows reversed
------------------------------------------------------
A READ request is about thirty bytes and its payload comes back in the reply. A WRITE
carries its payload *in the request*, so the asymmetry runs the other way and the sender
cannot simply queue everything and read the answers afterwards.

**A caveat on the usual justification, because it did not survive being tested.** The
expected failure is deadlock: we fill the child's stdin while the child, blocked writing
replies into a pipe we are not draining, stops reading ours. Against a real ``sftp-server``
on a pipe that does not happen -- measured, not assumed. Queuing 16 MB of payload across 64
unacknowledged writes never blocked, and neither did 50,000 small writes leaving roughly
850 KB of replies undrained, because OpenSSH's server buffers its output in memory instead
of blocking on it. Deadlock is still plausible against a server that does not buffer, and
over an SSH channel with its own windowing, but this module does not get to assert it as a
fact it has not observed.

What the concurrent design *does* buy, and what is defensible:

* **Bounded memory on both sides.** The window is a semaphore rather than a hope. Queuing a
  whole file without reading replies moves the unboundedness to the server, which was
  exactly what the 50,000-write experiment demonstrated -- no deadlock, just a server
  accumulating.
* **Failures are noticed when they happen.** A refused write surfaces immediately instead of
  after the entire file has been pushed, which is the difference between "failed at offset
  N" and "failed, somewhere".

So the sender takes a permit per request and the receiver returns one per reply, and the two
make progress against each other rather than one running to completion first.

Retry is deliberately absent
----------------------------
A READ at an explicit offset is idempotent -- reissuing it is free, which is why the
downloader re-queues a shortfall without a second thought. A WRITE is not. Replaying one
after a reconnect can duplicate or interleave bytes, and a generic ``@retry`` wrapped around
this would corrupt files quietly. Retry here needs to be protocol-aware and needs resume,
and both are separate work; until then a failed upload fails, and says how far it got.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import anyio
from anyio.to_thread import run_sync

from gantry_sftp.codec import Codec, Completed, Status, StatusCode, Write
from gantry_sftp.exceptions import ProtocolError, TransferError, TransferTimeoutError
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    ProgressCallback,
)
from gantry_sftp.transport import Transport

__all__ = ["upload_handle"]


@dataclass(frozen=True, slots=True)
class _Chunk:
    offset: int
    length: int


def _flatten(error: BaseException) -> BaseException:
    """Reduce an ``ExceptionGroup`` to the first thing that actually went wrong.

    A task group raises ``ExceptionGroup`` even for a single failure, which quietly breaks
    every ``except TransferError`` in calling code -- the ladder stops matching and the error
    surfaces as something nobody catches. CLAUDE.md calls this out as the default hazard of
    concurrent fan-out rather than an edge case, so the group is unwrapped here, at the
    boundary, and callers keep the flat exception they were written against.
    """
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


class _Uploader:
    """Drives one file's worth of pipelined writes."""

    def __init__(
        self,
        transport: Transport,
        codec: Codec,
        handle: bytes,
        fd: int,
        *,
        size: int,
        write_length: int,
        depth: int,
        idle_timeout: float | None,
        progress: ProgressCallback | None,
        remote_path: bytes | None,
    ) -> None:
        self._transport = transport
        self._codec = codec
        self._handle = handle
        self._fd = fd
        self._size = size
        self._write_length = write_length
        self._idle_timeout = idle_timeout
        self._progress = progress
        self._remote_path = remote_path

        self._window = anyio.Semaphore(depth)
        self._outstanding: dict[int, _Chunk] = {}
        self._acknowledged = 0
        self._all_sent = False
        self._finished = anyio.Event()

    def _settle(self) -> None:
        """Finish once everything has been sent and every write acknowledged."""
        if self._all_sent and not self._outstanding:
            self._finished.set()

    async def _send_all(self) -> None:
        offset = 0
        while offset < self._size:
            length = min(self._write_length, self._size - offset)
            # Reading the local file in a worker thread keeps a slow disk from stalling the
            # receive side, which is the half that has to keep draining for either to move.
            # `run_sync` is imported directly rather than reached as `anyio.to_thread...`:
            # that attribute only resolves because anyio happens to import the submodule
            # eagerly today, which ty flags and which would break silently if it stopped.
            payload = await run_sync(os.pread, self._fd, length, offset)
            if not payload:
                break

            await self._window.acquire()
            request_id = self._codec.allocate_request_id()
            await self._transport.send(
                self._codec.send(Write(request_id, self._handle, offset, payload))
            )
            self._outstanding[request_id] = _Chunk(offset, len(payload))
            offset += len(payload)

        self._all_sent = True
        self._settle()

    async def _receive_replies(self) -> None:
        while not self._finished.is_set():
            for event in self._codec.receive(await self._receive_chunk()):
                if isinstance(event, Completed):
                    self._acknowledge(event)
            if self._progress is not None:
                self._progress(self._acknowledged, self._size)

    async def _receive_chunk(self) -> bytes:
        if self._idle_timeout is None:
            return await self._transport.receive()
        try:
            with anyio.fail_after(self._idle_timeout):
                return await self._transport.receive()
        except TimeoutError as exc:
            raise TransferTimeoutError(
                f"no response from the server for {self._idle_timeout}s with "
                f"{len(self._outstanding)} write(s) outstanding",
                transferred=self._acknowledged,
                remote_path=self._remote_path,
            ) from exc

    def _acknowledge(self, event: Completed) -> None:
        chunk = self._outstanding.pop(event.request.request_id, None)
        if chunk is None:  # pragma: no cover -- the codec refuses unknown ids first
            raise ProtocolError("reply for a write we never sent")

        response = event.response
        if not isinstance(response, Status):
            raise ProtocolError(
                f"server answered a WRITE with {type(response).__name__}",
                request_id=event.request.request_id,
            )
        if response.code is not StatusCode.OK:
            raise TransferError(
                f"server refused a write at offset {chunk.offset}: "
                f"{response.code.name} "
                f"{bytes(response.message).decode('utf-8', 'replace')}".rstrip(),
                transferred=self._acknowledged,
                offset=chunk.offset,
                remote_path=self._remote_path,
            )

        # Counted only once the server has confirmed it. Counting at send time would report
        # progress for bytes that may still be refused, and would overstate what a failure
        # left behind.
        self._acknowledged += chunk.length
        self._window.release()
        self._settle()

    async def run(self) -> int:
        """Transfer the file. Returns the number of bytes the server acknowledged."""
        if self._progress is not None:
            self._progress(0, self._size)
        if self._size == 0:
            return 0

        try:
            async with anyio.create_task_group() as task_group:
                _ = task_group.start_soon(self._receive_replies)
                await self._send_all()
                await self._finished.wait()
                task_group.cancel_scope.cancel()
        except BaseExceptionGroup as group:
            raise _flatten(group) from None

        if self._progress is not None:
            self._progress(self._acknowledged, self._size)
        return self._acknowledged


async def upload_handle(
    transport: Transport,
    codec: Codec,
    handle: bytes,
    source: Path | str,
    *,
    write_length: int,
    depth: int = DEFAULT_PIPELINE_DEPTH,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    progress: ProgressCallback | None = None,
    remote_path: bytes | None = None,
) -> int:
    """Upload ``source`` into an already-open remote file.

    Args:
        transport: Connected transport.
        codec: Negotiated codec.
        handle: An open remote file handle, writable.
        source: Local file to read.
        write_length: Payload bytes per request, from
            :func:`~gantry_sftp.session.negotiate_transfer_sizes`.
        depth: Requests in flight. Note each one holds ``write_length`` bytes of payload, so
            this multiplies into real memory in a way the download side does not.
        idle_timeout: Seconds without any response before giving up.
        progress: Called with ``(transferred, total)`` as writes are acknowledged.
        remote_path: Carried on errors for diagnosis.

    Returns:
        Bytes the server acknowledged.

    Raises:
        TransferError: If the server refuses a write.
        TransferTimeoutError: If the server stops responding.
        ValueError: If ``depth`` or ``write_length`` would make no progress.
    """
    if depth < 1:
        raise ValueError(f"depth must be at least 1, got {depth}")
    if write_length < 1:
        raise ValueError(f"write_length must be at least 1, got {write_length}")

    fd = os.open(source, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        uploader = _Uploader(
            transport,
            codec,
            handle,
            fd,
            size=size,
            write_length=write_length,
            depth=depth,
            idle_timeout=idle_timeout,
            progress=progress,
            remote_path=remote_path,
        )
        return await uploader.run()
    finally:
        os.close(fd)

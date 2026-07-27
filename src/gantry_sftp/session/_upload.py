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
from gantry_sftp.exceptions import (
    ProtocolError,
    TransferError,
    TransferTimeoutError,
    flatten_exception_group,
)
from gantry_sftp.session._dispatch import Dispatcher, Exchange
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    ProgressCallback,
    Span,
)

__all__ = ["upload_handle"]


@dataclass(frozen=True, slots=True)
class _Chunk:
    offset: int
    length: int


class _Uploader:
    """Drives one file's worth of pipelined writes."""

    def __init__(
        self,
        codec: Codec,
        exchange: Exchange,
        handle: bytes,
        fd: int,
        *,
        span: Span,
        write_length: int,
        depth: int,
        idle_timeout: float | None,
        progress: ProgressCallback | None,
        remote_path: bytes | None,
    ) -> None:
        self._codec = codec
        self._exchange = exchange
        self._handle = handle
        self._fd = fd
        self._span = span
        """Where this run starts and where the local file ends. A non-zero start is a resume,
        and the bytes below it are assumed to be on the server already -- a claim the session
        makes and this layer cannot check."""

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
        offset = self._span.start
        while self._span.end is None or offset < self._span.end:
            length = self._write_length
            if self._span.end is not None:
                length = min(length, self._span.end - offset)
            # Reading the local file in a worker thread keeps a slow disk from stalling the
            # receive side, which is the half that has to keep draining for either to move.
            # `run_sync` is imported directly rather than reached as `anyio.to_thread...`:
            # that attribute only resolves because anyio happens to import the submodule
            # eagerly today, which ty flags and which would break silently if it stopped.
            payload = await run_sync(os.pread, self._fd, length, offset)
            if not payload:
                break

            await self._window.acquire()
            # Recorded before the send, not after it. The drain task runs concurrently, so a
            # reply can be delivered the moment the write lands -- while this coroutine is
            # still suspended inside `send` and has not reached the assignment. Registering
            # afterwards left a window in which a perfectly good acknowledgement looked like
            # a reply to a write we never sent.
            request_id = self._codec.allocate_request_id()
            self._outstanding[request_id] = _Chunk(offset, len(payload))
            await self._exchange.send(Write(request_id, self._handle, offset, payload))
            offset += len(payload)

        self._all_sent = True
        self._settle()

    async def _receive_replies(self) -> None:
        while not self._finished.is_set():
            self._acknowledge(await self._next_reply())
            if self._progress is not None:
                # Absolute, not per-run: "4.5 GB of 9 GB" is what a caller displays, and
                # "0.5 GB of 9 GB" after a resume is a lie about how much is left.
                self._progress(self._span.start + self._acknowledged, self._span.end)

    async def _next_reply(self) -> Completed:
        if self._idle_timeout is None:
            return await self._exchange.receive()
        try:
            with anyio.fail_after(self._idle_timeout):
                return await self._exchange.receive()
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
        """Transfer the file.

        Returns:
            Bytes the server acknowledged **in this run**, which is the file's size only when
            the span starts at 0. Progress, by contrast, is reported absolutely.
        """
        if self._progress is not None:
            self._progress(self._span.start, self._span.end)
        if self._span.end is not None and self._span.start >= self._span.end:
            # Nothing left: an empty file, or a resume of one already fully uploaded. Both
            # are successes that move no bytes, and neither may open a task group to find out.
            return 0

        try:
            async with anyio.create_task_group() as task_group:
                _ = task_group.start_soon(self._receive_replies)
                await self._send_all()
                await self._finished.wait()
                task_group.cancel_scope.cancel()
        except BaseExceptionGroup as group:
            raise flatten_exception_group(group) from None

        if self._progress is not None:
            self._progress(self._span.start + self._acknowledged, self._span.end)
        return self._acknowledged


async def upload_handle(
    dispatcher: Dispatcher,
    handle: bytes,
    source: Path | str,
    *,
    write_length: int,
    depth: int = DEFAULT_PIPELINE_DEPTH,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    progress: ProgressCallback | None = None,
    remote_path: bytes | None = None,
    start_offset: int = 0,
) -> int:
    """Upload ``source`` into an already-open remote file.

    Args:
        dispatcher: The session's reader. One exchange is opened for this transfer and
            retired when it ends, so several of these can run over one connection.
        handle: An open remote file handle, writable.
        source: Local file to read.
        write_length: Payload bytes per request, from
            :func:`~gantry_sftp.session.negotiate_transfer_sizes`.
        depth: Requests in flight. Note each one holds ``write_length`` bytes of payload, so
            this multiplies into real memory in a way the download side does not.
        idle_timeout: Seconds without any response before giving up.
        progress: Called with ``(transferred, total)`` as writes are acknowledged. Reports
            the *absolute* position, so a resumed upload starts the display where it left off.
        remote_path: Carried on errors for diagnosis.
        start_offset: Byte of the local file to begin at. Non-zero resumes, and the writes go
            to the same absolute offsets on the server -- so the remote file must already
            hold exactly the first ``start_offset`` bytes of this source. Nothing here can
            check that; it is the session's claim, made from a stat, and a weak one.

    Returns:
        Bytes the server acknowledged in this call, which is the file's size only when
        ``start_offset`` is 0.

    Raises:
        TransferError: If the server refuses a write.
        TransferTimeoutError: If the server stops responding.
        ValueError: If ``depth`` or ``write_length`` would make no progress, or if
            ``start_offset`` is negative or past the end of the local file.
    """
    if depth < 1:
        raise ValueError(f"depth must be at least 1, got {depth}")
    if write_length < 1:
        raise ValueError(f"write_length must be at least 1, got {write_length}")
    if start_offset < 0:
        raise ValueError(f"start_offset must not be negative, got {start_offset}")

    fd = os.open(source, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        if start_offset > size:
            raise ValueError(
                f"start_offset {start_offset} is past the end of a {size}-byte local file"
            )
        with dispatcher.exchange() as exchange:
            uploader = _Uploader(
                dispatcher.codec,
                exchange,
                handle,
                fd,
                span=Span(start_offset, size),
                write_length=write_length,
                depth=depth,
                idle_timeout=idle_timeout,
                progress=progress,
                remote_path=remote_path,
            )
            return await uploader.run()
    finally:
        os.close(fd)

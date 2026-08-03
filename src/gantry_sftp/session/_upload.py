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
from typing import Protocol

import anyio
from anyio.to_thread import run_sync

from gantry_sftp.codec import Codec, Completed, Status, StatusCode, Write
from gantry_sftp.exceptions import (
    ProtocolError,
    TransferError,
    TransferTimeoutError,
    _flatten_exception_group,
)
from gantry_sftp.session._dispatch import Dispatcher, Exchange
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    ProgressCallback,
    Span,
)

__all__ = ["BufferSource", "DescriptorSource", "Source", "upload_handle", "write_range_from"]


class Source(Protocol):
    """Where an uploaded payload comes from.

    The mirror of a download's :class:`~gantry_sftp.session.Sink`, parameterised for the same
    reason. A public ``write_at`` sends bytes the caller is holding, not bytes on local disk, and it
    must not become a second sender: the window, the reply drain and the offset bookkeeping
    below are the parts that are easy to get subtly wrong.

    It is ``async`` because the descriptor implementation reads in a worker thread, and a
    protocol that was not would force the disk read back onto the event loop.
    """

    async def read_at(self, offset: int, length: int) -> bytes | memoryview:
        """Return up to ``length`` bytes at ``offset``. Empty means end of source."""
        ...


class DescriptorSource:
    """Reads the payload from an open local file.

    In a worker thread, which keeps a slow disk from stalling the receive side -- the half
    that has to keep draining for either to move. ``run_sync`` is imported directly rather
    than reached as ``anyio.to_thread...``: that attribute only resolves because anyio happens
    to import the submodule eagerly today, which ty flags and which would break silently if it
    stopped.

    Not a dataclass, for the reason given on
    :class:`~gantry_sftp.session.DescriptorSink` (D-129). The body here is one call, and its
    three arguments are exactly the kind mutmut reorders and nulls -- ``os.pread`` takes
    ``(fd, length, offset)`` in that order, which is not the order this method receives them.
    """

    __slots__ = ("fd",)

    def __init__(self, fd: int) -> None:
        self.fd = fd

    async def read_at(self, offset: int, length: int) -> bytes | memoryview:
        return await run_sync(os.pread, self.fd, length, offset)


class BufferSource:
    """Reads the payload from a buffer the caller already has.

    No thread and no copy: a ``memoryview`` slice is a view, so the payload handed to the
    codec is a window onto the caller's bytes right up to the point the frame is built.

    Not a dataclass (D-129), for the reason given on
    :class:`~gantry_sftp.session.DescriptorSink`.

    Attributes:
        view: The bytes to send.
        base: Absolute remote offset of ``view[0]``, so this answers the same absolute-offset
            question a descriptor does.
    """

    __slots__ = ("base", "view")

    def __init__(self, view: memoryview, base: int) -> None:
        self.view = view
        self.base = base

    async def read_at(self, offset: int, length: int) -> bytes | memoryview:
        start = offset - self.base
        return self.view[start : start + length]


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
        source: Source,
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
        self._source = source

        if span.end is None:
            raise ValueError("an upload span must have an end; a sender knows its own length")
        self._start = span.start
        """Where this run starts. A non-zero start is a resume, and the bytes below it are
        assumed to be on the server already -- a claim the session makes and this layer
        cannot check."""

        self._end = span.end
        """Where the payload ends.

        :class:`Span` is shared with the download side, where this is ``None`` for a server
        that would not report a size and the run reads until EOF. **That shape does not exist
        in this direction**: a sender knows how many bytes it is sending, from ``os.fstat`` in
        :func:`upload_handle` and from ``len(payload)`` in :func:`write_range_from`. So it is
        refused above rather than carried into the request loop as three branches no caller
        can take -- which is what it was, and the mutation lane could not tell the difference.
        """

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
        offset = self._start
        while offset < self._end:
            # Clamped, so a source that has *grown* since it was measured cannot push bytes
            # past the end this run promised -- `os.pread` answers with whatever the file
            # holds now, not with what `os.fstat` saw when the transfer started.
            length = min(self._write_length, self._end - offset)
            payload = await self._source.read_at(offset, length)
            if not payload:
                # And the other direction: a source that has *shrunk* runs out before the span
                # does. What was acknowledged is what arrived, and `run` returns it. `break`
                # rather than `return`, because the two lines below are what let `run` finish
                # at all -- leaving without them parks it on an event nothing will set.
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
                self._progress(self._start + self._acknowledged, self._end)

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
            self._progress(self._start, self._end)
        if self._start >= self._end:
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
            raise _flatten_exception_group(group) from None

        if self._progress is not None:
            self._progress(self._start + self._acknowledged, self._end)
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
                DescriptorSource(fd),
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


async def write_range_from(
    dispatcher: Dispatcher,
    handle: bytes,
    payload: memoryview,
    *,
    offset: int,
    write_length: int,
    depth: int = DEFAULT_PIPELINE_DEPTH,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    remote_path: bytes | None = None,
) -> int:
    """Write ``payload`` at ``offset``, pipelined, from memory rather than from a file.

    The sending half of a byte-range surface, and the same reuse argument as
    :func:`~gantry_sftp.session.read_range_into`: the window and the reply drain are the parts
    that are hard, and a second implementation of them for in-memory writes would be a second
    place for an offset to be wrong.

    **No local file is involved, so this runs on every platform** -- ``os.pread`` is what
    scopes ``put`` to POSIX, and it is not on this path.

    Args:
        dispatcher: The session's reader.
        handle: An open remote file handle, writable.
        payload: The bytes to send. Not copied.
        offset: Absolute remote offset to write the first byte at.
        write_length: Payload bytes per request.
        depth: Requests in flight.
        idle_timeout: Seconds without any response before giving up.
        remote_path: Carried on errors for diagnosis.

    Returns:
        Bytes the server acknowledged, which is ``len(payload)`` on success.

    Raises:
        TransferError: If the server refuses a write.
        TransferTimeoutError: If the server stops responding.
        ValueError: If ``offset`` is negative, or ``depth``/``write_length`` make no progress.
    """
    if depth < 1:
        raise ValueError(f"depth must be at least 1, got {depth}")
    if write_length < 1:
        raise ValueError(f"write_length must be at least 1, got {write_length}")
    if offset < 0:
        raise ValueError(f"offset must not be negative, got {offset}")
    if not len(payload):
        return 0

    with dispatcher.exchange() as exchange:
        uploader = _Uploader(
            dispatcher.codec,
            exchange,
            handle,
            BufferSource(payload, offset),
            span=Span(offset, offset + len(payload)),
            write_length=write_length,
            depth=depth,
            idle_timeout=idle_timeout,
            progress=None,
            remote_path=remote_path,
        )
        return await uploader.run()

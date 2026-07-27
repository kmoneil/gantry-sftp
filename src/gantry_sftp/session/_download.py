"""Pipelined download: many reads in flight, reassembled by offset.

This is where the thesis stops being about protocol correctness and starts being about
speed. Throughput over a high-latency link is bounded by bytes in flight::

    throughput ~= (outstanding_requests * request_size) / RTT

so the loop below issues as many READs as the window allows before waiting for any reply,
and writes each payload with ``os.pwrite`` at the offset **the matching request asked for**.
Reassembling by arrival order instead would corrupt every out-of-order transfer, and
out-of-order is the normal case rather than the exception -- it is the entire point of
pipelining.

Three response shapes, all of which happen
------------------------------------------
A READ can come back three ways and each needs a decision:

* **Full** -- the requested length arrived. Write it and move on.
* **Short** -- fewer bytes than requested, which is *legal* and is **not** end of file.
  Verified against a real ``sftp-server``: reading 100 bytes at offset 8 of a ten-byte file
  returns a two-byte DATA frame. Treating that as EOF truncates the transfer at its first
  partial response -- silently, producing a file that is plausible and wrong. The shortfall
  is re-queued as a fresh read of the missing range, never a restart.
* **EOF** -- a STATUS, a different frame type entirely. The file ended earlier than its size
  said, which happens when it is being written concurrently.

A consumer, not a driver
------------------------
This reads its replies from an :class:`~gantry_sftp.session._dispatch.Exchange` rather than
from the transport. That is the difference between one download at a time and several: a
scheduler that calls ``transport.receive()`` itself owns the connection for the duration, and
a second one running beside it would decode the first one's frames. Here the only thing this
owns is its own window.
"""

from __future__ import annotations

import os
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import anyio

from gantry_sftp.codec import (
    Codec,
    Completed,
    Data,
    Read,
    Status,
    StatusCode,
)
from gantry_sftp.exceptions import ProtocolError, TransferError, TransferTimeoutError
from gantry_sftp.session._dispatch import Dispatcher, Exchange

__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_PIPELINE_DEPTH",
    "NO_FOLLOW",
    "ProgressCallback",
    "download_handle",
]

NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)
"""``O_NOFOLLOW`` where the platform has it, and ``0`` where it does not.

Windows has no equivalent, so the flag silently becomes nothing there rather than the open
failing. That is a documented weakness rather than a hidden one: on Windows the containment
check in ``_localpath`` is the whole defence, and it is checked before the open rather than
enforced by it.
"""

DEFAULT_PIPELINE_DEPTH = 64
"""Requests in flight per file.

Matches ``sftp(1)``'s ``-R`` default, which is the number this project exists to argue is
too low in combination with a 32 KiB buffer. With a derived 255 KiB request size it already
gives ~16 MiB in flight rather than 2 MiB. Adaptive ramping is a separate change and needs
the netem lane to be honest about (see ``_plans/deferred.md`` D-3).
"""

DEFAULT_IDLE_TIMEOUT = 60.0
"""Seconds without a single byte from the server before a transfer gives up.

Not a total deadline -- a large transfer over a slow link is healthy and must not be killed
for taking a long time. This fires only when nothing at all arrives while requests are
outstanding, which means the far end has stopped answering. The alternative, which is
paramiko's, is to wait forever; in a scheduled unattended transfer, hanging is worse than
failing because nothing ever reports it.
"""


class ProgressCallback(Protocol):
    """Called as bytes arrive.

    Args:
        transferred: Bytes written so far.
        total: Expected total, or ``None`` when the size is unknown.

    The signature is fixed across every long operation in the library, so a caller writes
    one progress reporter and uses it everywhere.
    """

    def __call__(self, transferred: int, total: int | None) -> None: ...


@dataclass(frozen=True, slots=True)
class _Range:
    """A byte range still to be requested."""

    offset: int
    length: int


class _Downloader:
    """Drives one file's worth of pipelined reads.

    A single task, not a task group: SFTP is request/response over one stream, so there is
    nothing *within* one file to run concurrently. Requests are tiny -- around thirty bytes
    -- so filling the window cannot fill the pipe and deadlock against a server waiting for
    us to read. That reasoning does *not* carry over to uploads, where the payload travels in
    the request, and the upload path has its own answer.

    Concurrency across files is a level up: several of these share one connection through the
    dispatcher, each with its own window and its own exchange.
    """

    def __init__(
        self,
        codec: Codec,
        exchange: Exchange,
        handle: bytes,
        fd: int,
        *,
        size: int | None,
        read_length: int,
        depth: int,
        idle_timeout: float | None,
        progress: ProgressCallback | None,
        remote_path: bytes | None,
    ) -> None:
        self._codec = codec
        self._exchange = exchange
        self._handle = handle
        self._fd = fd
        self._size = size
        self._read_length = read_length
        self._depth = depth
        self._idle_timeout = idle_timeout
        self._progress = progress
        self._remote_path = remote_path

        self._backlog: deque[_Range] = deque()
        self._next_offset = 0
        self._outstanding: dict[int, _Range] = {}
        self._written = 0
        self._eof_at: int | None = None

    def _more_to_issue(self) -> bool:
        if self._backlog:
            return True
        if self._eof_at is not None:
            return False
        return self._size is None or self._next_offset < self._size

    def _next_range(self) -> _Range:
        """Take the next range to request, preferring re-queued shortfalls.

        Shortfalls go first so a gap is filled while the surrounding data is still nearby,
        rather than being left until the end of the file.
        """
        if self._backlog:
            return self._backlog.popleft()
        length = self._read_length
        if self._size is not None:
            length = min(length, self._size - self._next_offset)
        issued = _Range(self._next_offset, length)
        self._next_offset += length
        return issued

    async def _fill_window(self) -> None:
        while len(self._outstanding) < self._depth and self._more_to_issue():
            issued = self._next_range()
            # Allocation and send with no await between them: an id is only reserved once
            # the codec records it, so a yield here would let a concurrent transfer take
            # the same one.
            request_id = self._codec.allocate_request_id()
            self._outstanding[request_id] = issued
            await self._exchange.send(Read(request_id, self._handle, issued.offset, issued.length))

    async def _next_reply(self) -> Completed:
        """Wait for the next reply to one of *our* reads.

        The idle timeout is per transfer rather than per connection, which is what makes it
        mean the right thing when several transfers share one: a file whose server has
        stopped answering fails, and its neighbours -- still receiving -- do not.

        Raises:
            TransferTimeoutError: If nothing arrives within the idle timeout while requests
                are outstanding.
        """
        try:
            if self._idle_timeout is None:
                return await self._exchange.receive()
            with anyio.fail_after(self._idle_timeout):
                return await self._exchange.receive()
        except TimeoutError as exc:
            raise TransferTimeoutError(
                f"no response from the server for {self._idle_timeout}s with "
                f"{len(self._outstanding)} request(s) outstanding",
                transferred=self._written,
                remote_path=self._remote_path,
            ) from exc

    def _write_at(self, offset: int, payload: memoryview) -> int:
        """Write ``payload`` at an explicit offset, looping over short writes.

        ``pwrite`` needs no ordering and no seeking, which is what lets replies be handled
        in whatever order they arrive. It can also write fewer bytes than asked, and a
        version of this that ignored that would silently drop the tail of a payload.
        """
        written = 0
        while written < len(payload):
            written += os.pwrite(self._fd, payload[written:], offset + written)
        return written

    def _handle_data(self, issued: _Range, response: Data) -> None:
        payload = response.data
        self._write_at(issued.offset, payload)
        self._written += len(payload)

        if len(payload) < issued.length:
            # Legal, and not EOF. Re-queue only what is missing.
            self._backlog.append(_Range(issued.offset + len(payload), issued.length - len(payload)))

    def _handle_status(self, issued: _Range, response: Status) -> None:
        if response.code is StatusCode.EOF:
            # The file ended sooner than its size claimed -- it is being written
            # concurrently, or the size was a guess. Stop issuing past here; ranges already
            # in flight beyond it will answer EOF too, harmlessly.
            self._eof_at = min(self._eof_at or issued.offset, issued.offset)
            return
        raise TransferError(
            f"server refused a read at offset {issued.offset}: "
            f"{response.code.name} {bytes(response.message).decode('utf-8', 'replace')}",
            transferred=self._written,
            offset=issued.offset,
            remote_path=self._remote_path,
        )

    def _dispatch(self, event: Completed) -> None:
        request = event.request
        if not isinstance(request, Read):  # pragma: no cover -- we only issue reads here
            raise ProtocolError(f"unexpected completion for a {type(request).__name__}")
        issued = self._outstanding.pop(request.request_id)

        if isinstance(event.response, Data):
            self._handle_data(issued, event.response)
        elif isinstance(event.response, Status):
            self._handle_status(issued, event.response)
        else:
            raise ProtocolError(
                f"server answered a READ with {type(event.response).__name__}",
                request_id=request.request_id,
            )

    async def run(self) -> int:
        """Transfer the file. Returns the number of bytes written."""
        if self._progress is not None:
            self._progress(0, self._size)

        while True:
            await self._fill_window()
            if not self._outstanding:
                break
            self._dispatch(await self._next_reply())
            if self._progress is not None:
                self._progress(self._written, self._size)

        return self._written


async def download_handle(
    dispatcher: Dispatcher,
    handle: bytes,
    fd: int,
    *,
    size: int | None,
    read_length: int,
    depth: int = DEFAULT_PIPELINE_DEPTH,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    progress: ProgressCallback | None = None,
    remote_path: bytes | None = None,
) -> int:
    """Download an already-open remote file into an already-open local one.

    Takes a handle and a file descriptor rather than two paths, because opening, stat-ing and
    closing are the session's business; this is the scheduler and nothing else. That is not
    just tidiness -- the flags the destination is opened with are a *safety* decision
    (``O_NOFOLLOW``, the mode) that belongs with the layer that knows where the file is
    allowed to be, and a scheduler with an fd can just as well write into a pipe.

    Args:
        dispatcher: The session's reader. One exchange is opened for this transfer and
            retired when it ends, so several of these can run over one connection.
        handle: An open remote file handle.
        fd: Writable file descriptor. Written at explicit offsets, never seeked, and not
            closed here -- whoever opened it owns it.
        size: Expected size, from a stat. ``None`` reads until EOF, which costs one extra
            round trip at the end and is the only option when the server will not say.
        read_length: Payload bytes per request, from
            :func:`~gantry_sftp.session.negotiate_transfer_sizes`.
        depth: Requests in flight.
        idle_timeout: Seconds without any response before giving up. ``None`` waits forever.
        progress: Called with ``(transferred, total)`` as data arrives.
        remote_path: Carried on errors for diagnosis.

    Returns:
        Bytes written.

    Raises:
        TransferError: If the server refuses a read.
        TransferTimeout: If the server stops responding.
        ValueError: If ``depth`` or ``read_length`` would make no progress.
    """
    if depth < 1:
        raise ValueError(f"depth must be at least 1, got {depth}")
    if read_length < 1:
        raise ValueError(f"read_length must be at least 1, got {read_length}")

    with dispatcher.exchange() as exchange:
        downloader = _Downloader(
            dispatcher.codec,
            exchange,
            handle,
            fd,
            size=size,
            read_length=read_length,
            depth=depth,
            idle_timeout=idle_timeout,
            progress=progress,
            remote_path=remote_path,
        )
        return await downloader.run()


ProgressReporter = Callable[[int, int | None], None]
"""Plain-callable spelling of :class:`ProgressCallback`, for annotating callers."""

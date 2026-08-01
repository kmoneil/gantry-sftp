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

And a fourth that is a server bug rather than a shape: a DATA short by *all* of it. Zero bytes
re-queues the range just asked for, so it never terminates, and the server is answering the
whole time so the idle timeout never fires either. One is tolerated and the second fails --
:meth:`_Downloader._refuse_a_second_zero_length` has the reasoning and the source.

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
from pathlib import Path
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
from gantry_sftp.session._publish import SizeCheck, TimePreservation
from gantry_sftp.session._verify import ContentCheck, ResumeCheck

__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_PIPELINE_DEPTH",
    "BufferSink",
    "DescriptorSink",
    "DownloadResult",
    "ProgressCallback",
    "Sink",
    "Span",
    "download_handle",
    "read_range_into",
]

DEFAULT_PIPELINE_DEPTH = 64
"""Requests in flight per file.

Matches ``sftp(1)``'s ``-R`` default, which is the number this project exists to argue is too
low **in combination with its 32 KiB buffer** -- 64 x 32768 is exactly the 2 MiB the channel
window holds, so the reference client saturates it and stops.

What this depth buys is not more bytes in flight. 64 requests of a derived 255 KiB is what we
*issue*; what the connection can hold is the SSH channel window, measured at 2 MiB. The point
of issuing past it is that a server which clamps the request size still reaches the ceiling,
and the ceiling is reached with room to spare rather than exactly.

**The window is reachable, but not on a connection's first transfer.** A depth this deep puts
more than an initial TCP congestion window in flight immediately, so the opening round trips
are spent waiting for that window to open rather than for the server. The same download is
measurably faster as a connection's second transfer than as its first, and the warm figure
reaches most of what the 2 MiB channel window implies once the metadata round trips
``get`` makes -- ``STAT``, ``OPEN``, ``CLOSE`` -- are subtracted. Both figures, with their link
profile and their date, come out of ``benchmarks/`` when it is run; they are not repeated here
and are not committed anywhere, because a number in a docstring ages without anybody noticing
(D-23, D-88, D-94).

**What it costs is this depth times the derived request size**, about 16 MiB at the shipped
defaults, and that is the whole of a transfer's memory: neither direction accumulates a *file*.
Downloading, the payload is placed with ``os.pwrite`` and dropped, and what bounds the total is
the exchange's reply deque -- at most ``depth`` entries, because that is how many reads are
outstanding. Uploading, the bound is the codec's outstanding map, which holds each ``WRITE``
with its payload until the reply. Same figure, two mechanisms; README's "What a transfer costs
in memory" states the expression and `tests/test_packaging.py` derives it from the constants.

That cost belongs to the transport rather than to this scheduler, and it is paid once per
connection: a session that moves several files amortises it, which is an argument for
``ControlMaster`` and for reusing a session, not for a different depth here. An earlier
version of this note blamed the shortfall on ``CHANNEL_WINDOW_ADJUST`` refilling the window at
half rate. That was a hypothesis, it was never measured, and it was wrong.

Raising this further does not raise throughput; it raises memory and issue-side work. The
number that would is a second connection.
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


class Sink(Protocol):
    """Where a downloaded payload goes.

    The scheduler below is the only pipelining implementation in this library, and it existed
    for one destination: a file descriptor written with ``os.pwrite``. A public byte-range read
    needs the same scheduler with the bytes landing in memory instead, and the way to get that
    is **not** a second scheduler -- one `READ` issued per call and awaited is precisely the
    shape that makes the incumbent's file object 25x slower than its own `get`
    (``paramiko#2453``).

    So the destination is a parameter. It takes a ``memoryview`` and places it at an absolute
    file offset; it never returns bytes to be concatenated, because a data path that
    concatenates has copied.
    """

    def write_at(self, offset: int, payload: memoryview) -> None:
        """Place ``payload`` at ``offset``, an absolute position in the remote file."""
        ...


@dataclass(frozen=True, slots=True)
class DescriptorSink:
    """Writes into an open local file at explicit offsets.

    ``pwrite`` needs no ordering and no seeking, which is what lets replies be handled in
    whatever order they arrive -- and it is why this sink is POSIX-only while
    :class:`BufferSink` is not. That split is the whole of the platform story for this layer.
    """

    fd: int

    def write_at(self, offset: int, payload: memoryview) -> None:
        """Write the whole payload, looping over short writes.

        ``os.pwrite`` can write fewer bytes than asked, and a version of this that ignored
        that would silently drop the tail of a payload.
        """
        written = 0
        while written < len(payload):
            written += os.pwrite(self.fd, payload[written:], offset + written)


@dataclass(frozen=True, slots=True)
class BufferSink:
    """Writes into a caller's buffer, which is what makes a byte-range read possible.

    ``base`` is the file offset the buffer's first byte corresponds to, so a range read of
    ``[base, base + len(view))`` fills it exactly. Slice assignment into a ``memoryview`` is a
    copy of the payload into the caller's memory and nothing more -- no intermediate ``bytes``,
    no concatenation, and no per-payload allocation.

    Attributes:
        view: Writable view over the destination, exactly as long as the range being read.
        base: Absolute file offset of ``view[0]``.
    """

    view: memoryview
    base: int

    def write_at(self, offset: int, payload: memoryview) -> None:
        start = offset - self.base
        self.view[start : start + len(payload)] = payload


@dataclass(frozen=True, slots=True)
class _Range:
    """A byte range still to be requested."""

    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class Span:
    """The region of a file one run is responsible for.

    Lives here rather than in a module of its own because this one is already where the
    upload side gets ``ProgressCallback`` and the two transfer defaults -- the name says
    "download" and the contents are "transfer plumbing shared by both directions", which is
    a smell worth naming rather than hiding. Splitting it out is a rename touching every
    import, and is not worth doing for four fields.

    Two fields that used to be two parameters, which is what pushed the constructor past the
    argument ceiling -- and they belong together anyway: ``start`` without ``end`` cannot say
    whether there is anything left to do, and a resume is exactly the case where ``start`` is
    not 0 and the distinction starts to matter.

    Attributes:
        start: First byte this run asks for. Non-zero when resuming.
        end: The file's size, from a stat, or ``None`` when the server would not report one
            and the run has to read until EOF.
    """

    start: int
    end: int | None


class _Downloader:
    """Drives one file's worth of pipelined reads.

    A single task, not a task group: SFTP is request/response over one stream, so there is
    nothing *within* one file to run concurrently. Requests are tiny -- around thirty bytes --
    so *this* transfer's window cannot fill the pipe on its own. That reasoning does not carry
    over to uploads, where the payload travels in the request, and the upload path has its own
    answer.

    **It also stopped being a safety argument once transfers began sharing a connection.** The
    pipe is per session, not per transfer: an upload's 255 KiB ``WRITE`` fills it, and this
    task's next thirty-byte ``READ`` then blocks behind it. Being a single task is what makes
    that fatal -- there is no second task here waiting on the idle timeout, so the send is the
    one place a download can stop with nobody watching. The bound is the dispatcher's send
    deadline (D-40), not this docstring.

    Concurrency across files is a level up: several of these share one connection through the
    dispatcher, each with its own window and its own exchange.
    """

    def __init__(
        self,
        codec: Codec,
        exchange: Exchange,
        handle: bytes,
        sink: Sink,
        *,
        span: Span,
        read_length: int,
        depth: int,
        idle_timeout: float | None,
        progress: ProgressCallback | None,
        remote_path: bytes | None,
    ) -> None:
        self._codec = codec
        self._exchange = exchange
        self._handle = handle
        self._sink = sink
        self._span = span
        self._read_length = read_length
        self._depth = depth
        self._idle_timeout = idle_timeout
        self._progress = progress
        self._remote_path = remote_path

        self._backlog: deque[_Range] = deque()
        self._next_offset = span.start
        self._outstanding: dict[int, _Range] = {}
        self._written = 0
        self._eof_at: int | None = None
        self._seen_zero_length = False
        """Whether a DATA carrying no bytes has already been let through -- see
        :meth:`_refuse_a_second_zero_length`. Per transfer, matching OpenSSH's own scope."""

    def _more_to_issue(self) -> bool:
        if self._backlog:
            return True
        if self._eof_at is not None:
            return False
        return self._span.end is None or self._next_offset < self._span.end

    def _next_range(self) -> _Range:
        """Take the next range to request, preferring re-queued shortfalls.

        Shortfalls go first so a gap is filled while the surrounding data is still nearby,
        rather than being left until the end of the file.
        """
        if self._backlog:
            return self._backlog.popleft()
        length = self._read_length
        if self._span.end is not None:
            length = min(length, self._span.end - self._next_offset)
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

    def _handle_data(self, issued: _Range, response: Data, request_id: int) -> None:
        payload = response.data
        if len(payload) > issued.length:
            self._refuse_an_overlong_data(issued, len(payload), request_id)
        if not payload:
            self._refuse_a_second_zero_length(issued)
        self._sink.write_at(issued.offset, payload)
        self._written += len(payload)

        if len(payload) < issued.length:
            # Legal, and not EOF. Re-queue only what is missing.
            self._backlog.append(_Range(issued.offset + len(payload), issued.length - len(payload)))

    def _refuse_an_overlong_data(self, issued: _Range, arrived: int, request_id: int) -> None:
        """Refuse a DATA carrying **more** than the READ asked for.

        Short is legal and handled above. Long is not: a server has no way to know what the
        caller intended to do with the extra bytes, and every destination this can write into
        is sized by the request. Writing them anyway meant a descriptor sink scribbling over
        the range the *next* request owns -- silently, since nothing downstream re-checks a
        length -- and a buffer sink raising ``ValueError`` from a slice assignment several
        frames from the cause.

        Named for what it is: server-supplied lengths are attacker-controlled input, and this
        is the one place the transfer's own arithmetic can be steered from the far end.

        Raises:
            ProtocolError: Always. The frame is malformed with respect to its request rather
                than the file being wrong, so this is not a ``TransferError``.
        """
        raise ProtocolError(
            f"server answered a {issued.length}-byte READ at offset {issued.offset} with "
            f"{arrived} bytes; a DATA may be short but never long",
            request_id=request_id,
        )

    def _refuse_a_second_zero_length(self, issued: _Range) -> None:
        """Let one zero-length DATA through, and no more.

        A DATA carrying no bytes makes no progress: the shortfall re-queued above is exactly
        the range that was just asked for, so a server answering every READ that way spins
        the transfer forever -- and it is *answering*, so the idle timeout never fires. End
        of file is a STATUS of EOF, not an empty DATA.

        **One is tolerated rather than none because that is what OpenSSH's client does**:
        ``if (len == 0) { if (seen_zerolen) fatal_f("server sent zero data length");
        seen_zerolen = 1; }``. Being stricter than ``sftp(1)`` refuses servers that work
        everywhere else, and the bound is the reference client's rather than a number chosen
        here.

        Counting it as end of file instead -- which is the call READDIR gets, for the same
        wire shape -- would silently truncate a *file*. A listing that stops early is a
        listing; a download that stops early is data loss wearing a success's clothes.

        Raises:
            TransferError: On the second one. ``TransferError`` rather than ``ProtocolError``
                because the state a caller needs here is how far the transfer got and where
                it stopped, and the message says what the server did wrong.
        """
        if not self._seen_zero_length:
            self._seen_zero_length = True
            return
        raise TransferError(
            f"server sent a second zero-length DATA, at offset {issued.offset}: "
            f"it is making no progress, and end of file is a STATUS not an empty DATA",
            transferred=self._written,
            offset=issued.offset,
            remote_path=self._remote_path,
        )

    def _handle_status(self, issued: _Range, response: Status) -> None:
        if response.code is StatusCode.EOF:
            # The file ended sooner than its size claimed -- it is being written
            # concurrently, or the size was a guess. Stop issuing past here; ranges already
            # in flight beyond it will answer EOF too, harmlessly.
            self._eof_at = min(self._eof_at or issued.offset, issued.offset)
            return
        raise TransferError(
            self._refusal(issued, response),
            transferred=self._written,
            offset=issued.offset,
            remote_path=self._remote_path,
        )

    def _refusal(self, issued: _Range, response: Status) -> str:
        """Describe a refused READ, which is not the same situation at every offset.

        Part way through a transfer, the offset *is* the diagnosis: bytes arrived, and then
        one range did not. The first read is a different event and used to read as the same
        one -- ``server refused a read at offset 0`` describes the request rather than what
        happened, which is that the object opened and then would not be read at all. Nothing
        was truncated, nothing arrived, and the file that a ``get`` created for it is empty.

        **The cause cannot be read off the reply, so it is not claimed.** Measured across the
        matrix (``tests/server_contract.py::a_directory_cannot_be_read_as_a_file``): OpenSSH
        permits ``open(2)`` on a directory and refuses at the ``read(2)`` with v3's catch-all,
        message ``Failure``; asyncssh refuses the ``OPEN`` with ``Is a directory``; paramiko
        refuses the ``OPEN`` with ``Failure``. So on the one server that reaches this code
        path at all there is nothing in the status to match on, and the honest sentence names
        a directory as *something that arrives looking exactly like this* rather than as the
        diagnosis. A ``STAT`` to settle it would be a round trip on every download to improve
        one message, and D-110 had just removed one from this path.

        The hint is withheld for every other status because those codes carry their own
        meaning -- ``NO_SUCH_FILE`` at the first read is a file that went away between the
        ``OPEN`` and the ``READ``, and a directory does not answer that anywhere.
        """
        said = f"{response.code.name} {bytes(response.message).decode('utf-8', 'replace')}".rstrip()
        if self._written or issued.offset != self._span.start:
            return f"server refused a read at offset {issued.offset}: {said}"
        # Both conditions, because replies arrive out of order: a refusal of the *first* range
        # can be handled after a later one has already delivered data, and "not one byte could
        # be read" would then be false.
        first = (
            f"server refused the first read, at offset {issued.offset}: {said} -- the handle "
            f"opened and then not one byte could be read, so nothing arrived and nothing was "
            f"truncated"
        )
        if response.code is not StatusCode.FAILURE:
            return first
        return (
            f"{first}. v3's FAILURE says no more than 'no', and one thing that reaches here "
            f"looking exactly like this is a directory: a server that lets one be opened "
            f"refuses at the read instead"
        )

    def _dispatch(self, event: Completed) -> None:
        request = event.request
        if not isinstance(request, Read):  # pragma: no cover -- we only issue reads here
            raise ProtocolError(f"unexpected completion for a {type(request).__name__}")
        issued = self._outstanding.pop(request.request_id)

        if isinstance(event.response, Data):
            self._handle_data(issued, event.response, request.request_id)
        elif isinstance(event.response, Status):
            self._handle_status(issued, event.response)
        else:
            raise ProtocolError(
                f"server answered a READ with {type(event.response).__name__}",
                request_id=request.request_id,
            )

    async def run(self) -> int:
        """Transfer the file.

        Returns:
            Bytes written **by this run**, which is not the file's size when resuming. The
            progress callback gets the absolute position instead, because "4.5 GB of 9 GB" is
            what a caller wants to display and "0.5 GB of 9 GB" after a resume is a lie about
            how much is left.
        """
        if self._progress is not None:
            self._progress(self._span.start, self._span.end)

        while True:
            await self._fill_window()
            if not self._outstanding:
                break
            self._dispatch(await self._next_reply())
            if self._progress is not None:
                self._progress(self._span.start + self._written, self._span.end)

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
    start_offset: int = 0,
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
        progress: Called with ``(transferred, total)`` as data arrives. Reports the
            *absolute* position, so a resumed transfer starts the display where it left off
            rather than at zero.
        remote_path: Carried on errors for diagnosis.
        start_offset: Byte to begin at. Non-zero resumes: reads start there and the
            descriptor is written at absolute offsets, so whatever is already in the file
            below this point is left alone. Whether that content is *right* is not knowable
            from here -- the session decides that before calling.

    Returns:
        Bytes written by this call, which is the file's size only when ``start_offset`` is 0.

    Raises:
        TransferError: If the server refuses a read.
        TransferTimeout: If the server stops responding.
        ValueError: If ``depth`` or ``read_length`` would make no progress, or if
            ``start_offset`` is negative or past the end of the file.
    """
    if depth < 1:
        raise ValueError(f"depth must be at least 1, got {depth}")
    if read_length < 1:
        raise ValueError(f"read_length must be at least 1, got {read_length}")
    if start_offset < 0:
        raise ValueError(f"start_offset must not be negative, got {start_offset}")
    if size is not None and start_offset > size:
        raise ValueError(f"start_offset {start_offset} is past the end of a {size}-byte file")

    with dispatcher.exchange() as exchange:
        downloader = _Downloader(
            dispatcher.codec,
            exchange,
            handle,
            DescriptorSink(fd),
            span=Span(start_offset, size),
            read_length=read_length,
            depth=depth,
            idle_timeout=idle_timeout,
            progress=progress,
            remote_path=remote_path,
        )
        return await downloader.run()


async def read_range_into(
    dispatcher: Dispatcher,
    handle: bytes,
    buffer: memoryview,
    *,
    offset: int,
    read_length: int,
    depth: int = DEFAULT_PIPELINE_DEPTH,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    remote_path: bytes | None = None,
) -> int:
    """Read ``len(buffer)`` bytes from ``offset`` into ``buffer``, pipelined.

    The same scheduler as :func:`download_handle` with the destination swapped, which is the
    point: a byte-range read that issued one ``READ`` and awaited it would cost a round trip
    per call, and that is the documented pathology of the file object this library exists to
    improve on. A 1 MiB read here is four requests in flight against a server that will clamp
    each one to ``max-read-length`` anyway.

    **No local file is involved, so this runs on every platform** -- ``os.pwrite`` is what
    scopes ``get`` to POSIX, and it is not on this path.

    Args:
        dispatcher: The session's reader.
        handle: An open remote file handle.
        buffer: Writable destination, filled from its first byte. Its length is the range.
        offset: Absolute file offset to read from.
        read_length: Payload bytes per request.
        depth: Requests in flight.
        idle_timeout: Seconds without any response before giving up.
        remote_path: Carried on errors for diagnosis.

    Returns:
        Bytes actually read, which is short of ``len(buffer)`` only at end of file. The rest
        of the buffer is left untouched rather than zeroed -- the caller owns it and a
        library that scribbles on the part it did not fill is doing something the caller
        cannot undo.

    Raises:
        ValueError: If ``offset`` is negative, or ``depth``/``read_length`` make no progress.
    """
    if depth < 1:
        raise ValueError(f"depth must be at least 1, got {depth}")
    if read_length < 1:
        raise ValueError(f"read_length must be at least 1, got {read_length}")
    if offset < 0:
        raise ValueError(f"offset must not be negative, got {offset}")
    if not len(buffer):
        return 0

    with dispatcher.exchange() as exchange:
        downloader = _Downloader(
            dispatcher.codec,
            exchange,
            handle,
            BufferSink(buffer, offset),
            span=Span(offset, offset + len(buffer)),
            read_length=read_length,
            depth=depth,
            idle_timeout=idle_timeout,
            progress=None,
            remote_path=remote_path,
        )
        return await downloader.run()


ProgressReporter = Callable[[int, int | None], None]
"""Plain-callable spelling of :class:`ProgressCallback`, for annotating callers."""


@dataclass(frozen=True, slots=True)
class DownloadResult:
    """What one ``get`` actually did.

    Returned rather than an ``int`` because the byte count was never the whole answer and,
    until 0.11, the rest of it was computed and thrown away (D-99). A ``get`` establishes the
    remote file's size, gates whatever a resume adopted, stamps the local file, sets its mode
    and checks the length that arrived -- and had one integer to report all of it through. The
    visible consequence was that ``get`` could not offer ``verify=`` at all: with nowhere to
    say ``unavailable``, a content check that could not run would have had to either pass
    silently or fail the transfer, and DESIGN.md 6's ladder exists to make that exact silence
    impossible.

    It lives here rather than beside :class:`~gantry_sftp.session.UploadResult`, which is in
    ``_publish.py``, because that module is about how an upload *becomes visible* and a
    download publishes nothing. The two types are re-exported side by side, which is where a
    reader compares them.

    A caller who only wants the count reads :attr:`transferred`; a caller who resumed reads
    :attr:`size`, because ``transferred`` is the remainder and not the file.

    Attributes:
        transferred: Bytes written **by this call**. On a resume that is the remainder, and on
            a resume of an already-complete file it is ``0``.
        remote_path: What was read, as it was sent on the wire.
        local_path: What was written.
        size_check: Whether what arrived was checked against the size the server reported --
            rung 3 of DESIGN.md 6's ladder. A mismatch raises rather than appearing here.
        times: Whether the remote file's timestamps survived onto the local one. ``SKIPPED``
            unless ``preserve_times=True`` was asked for. ``UNAVAILABLE`` is the case the
            docstring for ``preserve_times`` used to have to apologise for in prose: a server
            that reports no times leaves the local file stamped with now, and this is where it
            says so.
        content_check: Whether the *content* was verified, and by which rung. ``SKIPPED``
            unless ``verify=`` asked for one.
        resume_check: Whether the partial a resume adopted was proven to be a prefix of the
            remote file. ``SKIPPED`` when nothing was adopted.
        adopted: Bytes that were already on local disk and were kept. ``0`` unless ``resume``.
        mode: The permission bits the local file was left with, or ``None`` when ``mode=`` was
            not passed and it stayed at the ``0o600`` every download is created with.
    """

    transferred: int
    remote_path: bytes
    local_path: Path
    size_check: SizeCheck
    times: TimePreservation = TimePreservation.SKIPPED
    content_check: ContentCheck = ContentCheck.SKIPPED
    resume_check: ResumeCheck = ResumeCheck.SKIPPED
    adopted: int = 0
    mode: int | None = None

    @property
    def size(self) -> int:
        """Bytes the local file holds now: :attr:`adopted` plus :attr:`transferred`.

        The number a caller almost always means. ``transferred`` alone answers "what did this
        call cost", which is the question a progress meter asks and not the one a manifest
        does -- and a resumed transfer is exactly where the two differ.
        """
        return self.adopted + self.transferred

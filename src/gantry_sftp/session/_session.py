"""The session: what a user actually calls.

Ties a transport and a codec together, performs the handshake, probes what the server can
do, and exposes operations in terms of paths and files rather than packets and request ids.

Concurrency
-----------
**A session multiplexes.** Several tasks may share one -- transfers included -- and their
requests interleave over the single channel the way request ids were designed for::

    async with anyio.create_task_group() as group:
        for name in names:
            group.start_soon(sftp.get, f"/incoming/{name}", local / name)

This used to be a lock. The obstacle was never the protocol: it was that a scheduler calling
``transport.receive()`` itself owns the connection while it runs, so a second one beside it
would decode the first one's frames. :mod:`gantry_sftp.session._dispatch` moves that single
read into one reader task and hands every operation an exchange to wait on, which is what
turns "correct results in some order" into overlap.

Two things it does not do. It does not bound how many operations run at once -- that is the
caller's task group, because the right number is a fact about the far end rather than about
this layer. And it does not make a *single* operation safe to drive from two tasks: one
``get`` is one exchange with one consumer.

One thing it does not buy, stated so it is not read in: **more bytes in flight than the
channel allows.** ``ssh -s sftp`` runs the subsystem on one SSH channel, so one transport is
one 2 MiB window and everything multiplexed onto this session shares it. Concurrency reaches
that ceiling where a single small file cannot, and removes the round trips a file-at-a-time
loop leaves the link idle for; passing it needs a second transport (DESIGN.md 5.1).
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, Sequence
from contextlib import aclosing, asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePath
from types import TracebackType
from typing import override

import anyio

from gantry_sftp._logging import operation, session_logger
from gantry_sftp.codec import (
    EMPTY_ATTRS,
    EXTENSION_CHECK_FILE,
    EXTENSION_FSYNC,
    EXTENSION_LSETSTAT,
    EXTENSION_POSIX_RENAME,
    LIMITS_NAME,
    Attrs,
    AttrsReply,
    CheckFile,
    CheckFileReply,
    Close,
    Codec,
    CodecState,
    Completed,
    FSetStat,
    FStat,
    Fsync,
    Handle,
    LSetStat,
    LStat,
    MkDir,
    Name,
    Open,
    OpenDir,
    OpenFlag,
    Owner,
    PosixRename,
    ReadDir,
    ReadLink,
    RealPath,
    Remove,
    Rename,
    Request,
    Response,
    RmDir,
    SetStat,
    Stat,
    Status,
    StatusCode,
    SymLink,
    Times,
    render_field,
)
from gantry_sftp.codec import (
    Extended as ExtendedRequest,
)
from gantry_sftp.codec import (
    ExtendedReply as ExtendedReplyPacket,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    DestinationCollisionError,
    NoSuchFileError,
    PathCollision,
    PermissionDeniedError,
    ProtocolError,
    ServerError,
    SFTPError,
    StateError,
    TransferError,
    TransferTimeoutError,
    UnsupportedError,
    _flatten_exception_group,
)
from gantry_sftp.session._dispatch import Dispatcher
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    ProgressCallback,
    download_handle,
    read_range_into,
)
from gantry_sftp.session._glob import RECURSIVE, match_component, split_pattern
from gantry_sftp.session._limits import ServerLimits, TransferSizes, negotiate_transfer_sizes
from gantry_sftp.session._listing import (
    DOT_ENTRIES,
    DirEntry,
    EntryKind,
    entry_kind,
    modified_at,
)
from gantry_sftp.session._localpath import DestinationLedger, check_contained, local_child
from gantry_sftp.session._localtree import remote_component, walk_local
from gantry_sftp.session._mode import (
    CREATE_BITS,
    PERMISSION_BITS,
    Mode,
    create_bits,
    local_mode,
    resolve_mode,
)
from gantry_sftp.session._platform import NO_FOLLOW, require_local_io
from gantry_sftp.session._pool import for_each_bounded
from gantry_sftp.session._publish import (
    Durability,
    Publish,
    PublishMechanism,
    SizeCheck,
    TimePreservation,
    UploadResult,
    publish_from_legacy,
    split_parent,
    staged_path,
    staging_token,
)
from gantry_sftp.session._quirks import ServerProfile, identify
from gantry_sftp.session._recursive import (
    GlobMatch,
    Skipped,
    SkipReason,
    TreeResult,
    WalkEntry,
    check_listed_name,
    join_remote,
)
from gantry_sftp.session._upload import upload_handle, write_range_from
from gantry_sftp.session._verify import (
    CHECK_FILE_BLOCK_SIZE,
    ContentCheck,
    ResumeCheck,
    Verify,
    local_block_digests,
    ranges_equal,
)
from gantry_sftp.transport import Transport

__all__ = [
    "DEFAULT_REQUEST_TIMEOUT",
    "DEFAULT_SESSION_OPTIONS",
    "LIMITS_EXTENSION",
    "Session",
    "SessionOptions",
    "open_session",
]

DEFAULT_REQUEST_TIMEOUT = 30.0
"""Seconds a single round trip may take before it is abandoned.

Covers the handshake and every one-shot request -- OPEN, STAT, CLOSE, REALPATH. Bulk
transfers do **not** use this; they have their own idle timeout, because a large transfer is
allowed to take as long as it takes so long as bytes keep arriving.

The alternative is paramiko's, which is to wait forever. A connection that completes and
then never answers a STAT is the exact shape of an unattended job that hangs until someone
notices, which in a scheduled-transfer context can be days.
"""

LIMITS_EXTENSION = LIMITS_NAME
"""Kept as an alias rather than a second bytes literal.

One wire string, spelled once, in the same table the advertisement fixture is checked
against. Two spellings of an extension name is how a client silently never negotiates it.
"""

_STATUS_ERRORS = {
    StatusCode.NO_SUCH_FILE: NoSuchFileError,
    StatusCode.PERMISSION_DENIED: PermissionDeniedError,
    StatusCode.OP_UNSUPPORTED: UnsupportedError,
}

_LOCAL_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
"""How a downloaded file is opened locally, before any safety flags are added."""

_LOCAL_RESUME_FLAGS = os.O_WRONLY | os.O_CREAT
"""The same without ``O_TRUNC``, for a resumed download.

Not ``O_APPEND``: every write goes to an explicit offset with ``os.pwrite``, and ``O_APPEND``
would ignore those offsets and redirect every reply to the end of the file -- which for
out-of-order pipelined replies means a file assembled in arrival order. Silently, and wrong.
"""


@dataclass(frozen=True, slots=True)
class SessionOptions:
    """How a session schedules and how long it waits: the three tunables, as one type.

    A parameter object where ``pyproject.toml`` normally argues against one -- and the argument
    it makes is about the *connection* entry points, where ``host`` and ``identity_file`` are
    genuinely unrelated. These three are not: they are one scheduling policy, which is the same
    reasoning that made ``Publish`` a type in 0.9 rather than five arguments.

    It exists because :func:`~gantry_sftp.connect` fuses two signatures that together come to
    thirteen arguments against a ceiling of ten, and the ssh half is precisely the half that
    cannot be grouped. Grouping the half that *is* one concept is what makes the fused entry
    point fit without an exemption.

    :func:`open_session` keeps its three flat keyword arguments and is unchanged -- it takes a
    transport rather than a host, so it was never near the ceiling.

    Attributes:
        request_timeout: Seconds for the handshake, for each one-shot request, and for each
            write -- including the wait for the connection's send lock. ``None`` waits forever,
            which also makes teardown unbounded against a peer that has stopped answering.
        idle_timeout: Seconds of total silence during a bulk transfer. A large transfer over a
            slow link is healthy so long as bytes keep arriving, so this fires only on silence.
        depth: Default requests in flight per transfer. Raising it past the default buys
            nothing: one session is one channel is one 2 MiB window.
    """

    request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT
    depth: int = DEFAULT_PIPELINE_DEPTH


DEFAULT_SESSION_OPTIONS = SessionOptions()
"""The tunables :func:`open_session` uses when it is not told otherwise.

A module-level singleton so it can be a default argument without a mutable-default hazard --
:class:`SessionOptions` is frozen -- and so ``session is DEFAULT_SESSION_OPTIONS`` is a usable
question.
"""

_LOGGED_EXTENSIONS = 12
"""Advertised extension names the handshake record will list before it stops.

A count as well as the names, so a server advertising two hundred of them is visible as that
rather than as a truncated list. Twelve covers every server in the matrix with room to spare --
OpenSSH advertises six."""

_TRUNCATE_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
"""Open flags for writing a file in place: create it, or replace what is there."""

_RESUME_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT
"""Open flags for a resumed upload: adopt what is there, and do not truncate it.

No ``TRUNC``, obviously, and no ``EXCL`` -- adopting an existing file is the whole point, and
``EXCL`` is the flag that refuses to. Losing it loses the collision check with it, which is
why a resumed atomic publish demands a caller-chosen staging name."""

_STAGE_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL
"""Open flags for a staging file, and ``EXCL`` is the load-bearing one.

Without it, a name collision means two publishers writing into one file at different offsets,
producing a result that is the wrong length or interleaved -- plausible, and wrong, which is
the failure class this whole module exists to prevent. With it, a collision is an error.

Measured cost: OpenSSH answers ``FAILURE`` for ``CREAT|EXCL`` on an existing file, which is
the v3 catch-all, so a server that does not implement ``EXCL`` and one whose staging name is
taken are indistinguishable from the status code alone. The escape hatch for such a server is
``atomic=False``, and the error says so.
"""


def raise_for_status(status: Status, *, path: bytes | None = None) -> None:
    """Turn a non-OK STATUS into a typed exception.

    ``OK`` and ``EOF`` return quietly: ``EOF`` is a normal terminating condition for READDIR
    and for reads at the end of a file, not a failure.

    Args:
        status: The STATUS packet.
        path: Path the request concerned, attached to the error for diagnosis.

    Raises:
        ServerError: Or the subclass matching the code.
    """
    if status.code in (StatusCode.OK, StatusCode.EOF):
        return
    error_class = _STATUS_ERRORS.get(status.code, ServerError)
    detail = bytes(status.message).decode("utf-8", "replace").strip()
    summary = f"server returned {status.code.name}"
    if detail:
        summary = f"{summary}: {detail}"
    raise error_class(summary, code=int(status.code), message=bytes(status.message), path=path)


class _StagedIsTheOnlyCopyError(Exception):
    """Internal signal: the destination may be gone and the staging file is all that is left.

    Raised only from the ``REMOVE``-then-``RENAME`` fallback. The normal cleanup would delete
    the staging file, which in this window holds the *only* copy of the data, turning a
    recoverable failure into an unrecoverable one.

    Never escapes the session: it is unwrapped at the boundary and the original failure is what
    the caller sees, with a note saying where the file is.

    Args:
        failure: What went wrong, re-raised unchanged at the boundary. May be a cancellation.
        destination_removed: Whether the ``REMOVE`` is *known* to have succeeded. False when
            the remove itself failed in a way that does not say -- a timeout, a lost
            connection, cancellation -- because the request may well have been executed with
            only the answer going missing. The two cases get different notes: telling somebody
            their file was deleted when it may still be there sends them to restore a backup
            they did not need.
    """

    def __init__(self, failure: BaseException, *, destination_removed: bool) -> None:
        super().__init__("the destination was removed and the staged file could not replace it")
        self.failure = failure
        self.destination_removed = destination_removed


@dataclass(frozen=True, slots=True)
class _Upload:
    """The knobs one ``put`` carries through its helpers.

    A parameter object rather than eight more positional arguments threaded through four
    methods: the staging path and the destination differ between them, everything here does
    not.
    """

    local_path: Path | str
    fsync: bool
    require_fsync: bool
    progress: ProgressCallback | None
    depth: int | None
    resume: bool = False
    preserve_times: bool = False
    verify: Verify = Verify.SIZE
    # Already resolved to a number by `put`: `Mode.PRESERVE` needs the local file, and reading
    # it once at the top beats every helper below deciding again whether to stat.
    mode: int | None = None


class DirectoryScan:
    """One directory, streamed batch by batch instead of accumulated.

    :meth:`Session.listdir` follows every ``READDIR`` to the end and hands back a list. That
    is what a caller wants for an ordinary directory and it is a **peer-driven memory
    bound**: the server decides how many names there are, and a server willing to answer
    ``READDIR`` with new names forever makes the client allocate forever. Capping the list
    would be the worse bug -- it breaks the legitimate large directory and reports success --
    so the fix is an iterating form, and this is it. Memory here is one batch.

    It is a **context manager and not a bare async generator**, because it holds a directory
    handle open across the yield and a suspended async generator that is merely dropped is
    not finalised by trio -- the handle would sit on the server until the garbage collector
    happened to feel like it, if ever::

        async with sftp.scandir(b"/incoming") as entries:
            async for entry in entries:
                if entry.name.endswith(".csv"):
                    break                     # the handle is closed on the way out

    ``.`` and ``..`` are filtered, matching :meth:`Session.listdir`. Nothing else is: names
    are server-supplied and are surfaced verbatim, exactly as everywhere else.

    Other operations may run on the session inside the loop -- a ``stat`` per entry, or a
    ``get`` -- because a session multiplexes and this holds no lock. That was not always
    true, and it is the reason this shape was cheap to build.

    Args:
        session: The session to read through.
        path: Remote directory, already encoded.
    """

    def __init__(self, session: Session, path: bytes) -> None:
        self._session = session
        self._path = path
        self._handle: bytes | None = None
        self._entered = False
        self._batch: tuple[DirEntry, ...] = ()
        self._index = 0
        self._exhausted = False

    @override
    def __repr__(self) -> str:
        state = "open" if self._handle is not None else ("spent" if self._entered else "unopened")
        return f"<DirectoryScan {self._path!r} {state}>"

    async def __aenter__(self) -> DirectoryScan:
        """Open the directory.

        Raises:
            StateError: If this scan has already been entered. One scan is one handle; a
                second ``async with`` on the same object would silently restart the listing.
            NoSuchFileError: If the path does not exist -- which is also what a server
                answers for a path that exists and is not a directory.
            ServerError: If the server refuses.
        """
        if self._entered:
            raise StateError("this scandir() has already been used; call scandir() again")
        self._entered = True
        self._handle = await self._session.opendir(self._path)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the directory handle, whichever way the block ended.

        A ``CLOSE`` that fails on the way *out* of a clean block is reported, the same as
        :meth:`Session.listdir`. On the way out of a failing one it is swallowed: a
        housekeeping complaint must not replace the diagnosis that is already on its way up.
        """
        handle, self._handle = self._handle, None
        self._batch = ()
        self._index = 0
        if handle is None:
            return
        if exc_type is None:
            await self._session.close(handle)
        else:
            await _close_quietly(self._session, handle)

    def __aiter__(self) -> DirectoryScan:
        """Iterate the entries.

        Raises:
            StateError: If the scan was never entered. Iterating a scandir() that is not
                inside its ``async with`` would leak the handle it is holding, so it is
                refused rather than half-supported.
        """
        if self._handle is None:
            raise StateError("scandir() must be entered with `async with` before iterating")
        return self

    async def __anext__(self) -> DirEntry:
        """The next entry, asking the server for another batch when this one runs out."""
        while (entry := self._next_buffered()) is None:
            await self._fill()
        return entry

    def _next_buffered(self) -> DirEntry | None:
        """The next non-dot entry from the batch in hand, or ``None`` once it is used up."""
        while self._index < len(self._batch):
            entry = self._batch[self._index]
            self._index += 1
            if entry.filename not in DOT_ENTRIES:
                return entry
        return None

    async def _fill(self) -> None:
        """Fetch the next batch.

        Raises:
            StopAsyncIteration: At end of directory. Latched, so an iterator driven past the
                end does not spend a round trip re-asking a server that already said EOF.
            StateError: If the scan is no longer open, which means iteration outlived the
                ``async with`` that owns the handle.
            ServerError: If the server refuses mid-listing. The handle is still closed, by
                the ``async with`` this must be inside.
        """
        if self._handle is None:
            raise StateError("this scandir() is closed; its `async with` block has ended")
        if self._exhausted:
            raise StopAsyncIteration
        batch = await self._session.readdir(self._handle)
        if batch is None:
            self._exhausted = True
            raise StopAsyncIteration
        self._batch = batch
        self._index = 0


class RemoteFile:
    """One open remote file with a cursor: ranges, tails, appends and streaming.

    Everything else in this library moves a *whole file between a remote path and a local
    path*. That covers the common case and excludes a real one -- reading a header, tailing a
    log, appending a record, or streaming a remote file into a parser or a hash without
    staging it on disk first. This is that surface, and it is a context manager because it
    holds a server-side handle::

        async with sftp.open_file(b"/logs/today.jsonl") as remote:
            first = await remote.read(512)

    **Pipelined, which is the whole design constraint.** Every read here goes through the same
    scheduler a ``get`` uses, so ``read(1 << 20)`` is several ``READ``s in flight rather than
    one round trip per call. The obvious implementation -- one request per call, awaited --
    is what makes the incumbent's file object 25x slower than its own whole-file download
    (``paramiko#2453``), and it would have shipped that complaint under a new name.

    **One file object is one task.** The cursor is mutable shared state: two tasks reading the
    same object interleave their positions and each gets a subset of what it asked for. Use
    :meth:`Session.readinto_at` and :meth:`Session.write_at` to fan out over one file -- they
    take the offset as an argument, so there is no shared position to race on.

    Attributes:
        path: The remote path, as bytes.
    """

    def __init__(
        self, session: Session, path: bytes, pflags: OpenFlag, *, mode: int | None = None
    ) -> None:
        self._session = session
        self._path = path
        self._pflags = pflags
        self._mode = mode
        self._handle: bytes | None = None
        self._entered = False
        self._position = 0

    @property
    def path(self) -> bytes:
        """The remote path, encoded.

        Bytes rather than ``str`` for the same reason every other server-facing name here is:
        a remote filename need not be valid UTF-8.
        """
        return self._path

    @override
    def __repr__(self) -> str:
        """Names the file, which half of the lifetime it is in, and where the cursor is.

        The position is in it because the position is what a caller debugging this surface is
        actually asking about -- a read that returned less than expected is usually a cursor
        somewhere other than where its author believed.
        """
        state = "open" if self._handle is not None else ("closed" if self._entered else "unopened")
        return f"<RemoteFile {self._path!r} {state} at {self._position}>"

    def _open_handle(self) -> bytes:
        """The handle, or the error explaining which half of the lifetime we are in.

        Raises:
            StateError: If the file is not currently open.
        """
        if self._handle is None:
            if self._entered:
                raise StateError("this open_file() is closed; its `async with` block has ended")
            raise StateError("this open_file() is not open; use it in an `async with` block")
        return self._handle

    async def __aenter__(self) -> RemoteFile:
        """Open the file.

        Raises:
            StateError: If this object has already been entered. One file object is one
                handle; a second ``async with`` would silently reopen at position zero.
            NoSuchFileError: If the path does not exist and was not to be created.
            PermissionDeniedError: If the server will not open it.
        """
        if self._entered:
            raise StateError("this open_file() has already been used; call open_file() again")
        self._entered = True
        self._handle = await self._session.open(self._path, self._pflags, mode=self._mode)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the handle, whichever way the block ended.

        A ``CLOSE`` that fails on the way out of a clean block is reported; one that fails
        while an exception is already propagating is not allowed to replace it, because the
        first exception is the one that explains what happened.
        """
        handle, self._handle = self._handle, None
        if handle is None:
            return
        if exc is None:
            await self._session.close(handle)
            return
        await _close_quietly(self._session, handle)

    def tell(self) -> int:
        """The cursor, without asking the server.

        Not a round trip, and never stale in the direction that matters: it is where the
        *next* read or write will start.
        """
        return self._position

    async def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor and return its new absolute position.

        ``SEEK_SET`` and ``SEEK_CUR`` are local arithmetic and send nothing. ``SEEK_END``
        costs one ``FSTAT``, because only the server knows where the end is -- and the answer
        is a snapshot: a file being appended to has moved by the time you read.

        Seeking past the end is legal and does not extend the file. A read there returns
        ``b""``; a write there leaves a hole that reads back as zeroes.

        Args:
            offset: Displacement, which may be negative for ``SEEK_CUR`` and ``SEEK_END``.
            whence: One of ``os.SEEK_SET``, ``os.SEEK_CUR``, ``os.SEEK_END``.

        Returns:
            The new absolute position.

        Raises:
            ValueError: If ``whence`` is not one of the three, or the result is negative.
            StateError: If the file is not open.
        """
        handle = self._open_handle()
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self._position + offset
        elif whence == os.SEEK_END:
            attrs = await self._session.fstat(handle)
            if attrs.size is None:
                raise ValueError(
                    "the server did not report a size, so SEEK_END has nothing to seek from"
                )
            target = attrs.size + offset
        else:
            raise ValueError(f"whence must be os.SEEK_SET, SEEK_CUR or SEEK_END, got {whence}")
        if target < 0:
            raise ValueError(f"seek would put the position at {target}, before the start")
        self._position = target
        return target

    async def read(self, length: int | None = None) -> bytes:
        """Read from the cursor and advance it.

        Args:
            length: Bytes to read, or ``None`` for "the rest of the file", which costs one
                extra ``FSTAT`` to find the end. The rest is a snapshot taken at that moment;
                a file being written underneath you is not something a client can freeze.

        Returns:
            Exactly ``length`` bytes, unless end of file arrived first, and ``b""`` at the
            end. A short return is **only** end of file -- a short ``DATA`` mid-file is legal
            and is re-requested rather than handed back, so no caller has to loop.

        Raises:
            ValueError: If ``length`` is negative.
            StateError: If the file is not open.
        """
        handle = self._open_handle()
        if length is None:
            attrs = await self._session.fstat(handle)
            if attrs.size is None:
                raise ValueError(
                    "the server did not report a size, so read() cannot tell where the file "
                    "ends; pass a length"
                )
            length = max(0, attrs.size - self._position)
        data = await self._session.read_at(handle, self._position, length)
        self._position += len(data)
        return data

    async def readinto(self, buffer: bytearray | memoryview) -> int:
        """Read into a buffer you already own, with no copy, and advance the cursor.

        Returns:
            Bytes read, short of ``len(buffer)`` only at end of file.

        Raises:
            StateError: If the file is not open.
        """
        handle = self._open_handle()
        filled = await self._session.readinto_at(handle, buffer, self._position)
        self._position += filled
        return filled

    async def write(self, data: bytes | memoryview) -> int:
        """Write at the cursor and advance it.

        Note what ``APPEND`` does to this: a file opened with ``OpenFlag.APPEND`` has every
        write placed at the *server's* idea of the end regardless of the offset sent, so the
        cursor tracked here stops describing where the bytes landed. That is the flag's
        meaning rather than a defect, and it is why appending is spelled with the flag rather
        than with a seek.

        Returns:
            Bytes the server acknowledged, which is ``len(data)`` on success.

        Raises:
            StateError: If the file is not open.
            TransferError: If the server refuses a write, carrying how far it got.
        """
        handle = self._open_handle()
        written = await self._session.write_at(handle, self._position, data)
        self._position += written
        return written

    async def stat(self) -> Attrs:
        """Attributes of the open file, from its handle rather than its name.

        Raises:
            StateError: If the file is not open.
        """
        return await self._session.fstat(self._open_handle())

    async def truncate(self, size: int | None = None) -> None:
        """Set the file's length, defaulting to the current cursor.

        Does not move the cursor, matching ``io``: truncating below the position leaves it
        past the end, where a read returns ``b""``.

        Raises:
            ValueError: If ``size`` is negative.
            StateError: If the file is not open.
        """
        handle = self._open_handle()
        await self._session.ftruncate(handle, self._position if size is None else size)

    async def fsync(self) -> None:
        """Ask the server to flush this file to its disk, where it supports it.

        Raises:
            UnsupportedError: If the server does not advertise ``fsync@openssh.com``.
            StateError: If the file is not open.
        """
        await self._session.fsync(self._open_handle())


class Session:
    """An SFTP conversation with one server.

    Built by :func:`open_session`, which owns the handshake, starts the reader task every
    operation depends on, and makes sure the connection is torn down. Constructing one
    directly is not supported: a session without a running reader accepts requests and never
    answers them.

    Args:
        dispatcher: The connection's single reader, already running.
        limits: What the server said it would accept, or all-``None``.
        request_timeout: Seconds for one one-shot request, and for one write.
        idle_timeout: Seconds of silence during a bulk transfer.
        depth: Default requests in flight per transfer.
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        limits: ServerLimits,
        *,
        request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
        idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
        depth: int = DEFAULT_PIPELINE_DEPTH,
    ) -> None:
        self._dispatcher = dispatcher
        self._codec = dispatcher.codec
        self._limits = limits
        self._request_timeout = request_timeout
        self._idle_timeout = idle_timeout
        self._depth = depth
        self._profile = identify(dispatcher.codec.extensions)
        """Which implementation we believe is at the other end.

        Worked out once, from the extension list the handshake already carried, so it costs
        no round trip. Diagnostic only -- see :mod:`gantry_sftp.session._quirks` on why a
        fingerprint is deliberately not allowed to change behaviour."""

        self._unsupported: set[bytes] = set()
        """Extensions this server answered ``OP_UNSUPPORTED`` for, so we stop asking.

        Only definitive answers go in here. A server that refuses for some other reason has
        told us about one request, not about its capabilities."""

        self._root: bytes | None = None
        """This server's canonical form of ``.``, or ``None`` until something needed it.

        Probed lazily and never at connect time, because most sessions never need it: an
        operation given a ``/``-rooted path has its arithmetic defined by the draft and asks
        nothing. See :meth:`_require_rooted_paths`.

        **Distinct from :attr:`_cwd`, and it stays that way even after a ``chdir``**: this is
        where the *server* put us, and the probe that reads it deliberately bypasses the
        client-side prefix. A field that meant "the server's root, unless somebody moved"
        would make :attr:`server_root` a lie at exactly the moment it became interesting."""

        self._cwd: bytes | None = None
        """The prefix :meth:`chdir` prepends to relative paths, or ``None`` for none.

        Always absolute when set: :meth:`chdir` canonicalises through ``REALPATH`` and refuses
        on a namespace that is not ``/``-rooted, which is what makes prefixing idempotent.
        Resolving an already-absolute path is a no-op, so a path this library built by joining
        onto a resolved root cannot be prefixed twice however many layers it passes through."""

    @property
    def limits(self) -> ServerLimits:
        """What the server said it will accept, or all-``None`` if it said nothing."""
        return self._limits

    @property
    def depth(self) -> int:
        """Requests this session keeps in flight per transfer, unless a call overrides it.

        Readable because it was previously visible only inside ``repr()``, which made
        "did my tunable take effect" a question answerable by string-matching a diagnostic --
        and :func:`~gantry_sftp.connect` gave callers a second way to set it, so there are now
        two spellings whose agreement someone will want to check.
        """
        return self._depth

    @property
    def extensions(self) -> Mapping[bytes, bytes]:
        """Extensions the server advertised. Frequently empty, which is not an error."""
        return self._codec.extensions

    @property
    def server_version(self) -> int | None:
        """Protocol version negotiated."""
        return self._codec.server_version

    @property
    def reaped(self) -> int:
        """Handles this session has closed on behalf of an ``OPEN`` nobody was left to receive.

        An ``OPEN`` abandoned by a timeout or a cancellation is still answered by the server,
        which allocates a handle nothing here would otherwise close. They are cleaned up
        automatically -- see :meth:`~gantry_sftp.session.Dispatcher.reap_orphans` -- and this
        is the count, which is worth watching: a number that climbs is a caller giving up on
        this server often enough to be worth knowing about, not a leak.
        """
        return self._dispatcher.reaped

    @property
    def requests_sent(self) -> int:
        """Requests this session has written, cumulatively. Excludes the handshake.

        Cumulative rather than instantaneous, which is the half that was missing: ``depth``
        and ``outstanding`` say what is happening now, and only a total can answer "did the
        retry loop actually retry?" or "how many round trips did that tree cost?".
        """
        return self._dispatcher.requests_sent

    @property
    def replies_received(self) -> int:
        """Replies this session has routed, cumulatively, including unclaimed ones."""
        return self._dispatcher.replies_received

    @property
    def bytes_sent(self) -> int:
        """Bytes this session has written to the transport, framing included."""
        return self._dispatcher.bytes_sent

    @property
    def bytes_received(self) -> int:
        """Bytes this session has read from the transport, framing included.

        Larger than the payload of a download by the framing, and larger again than the file
        on disk if anything was re-read -- a resume gate verifying an adopted prefix moves
        bytes that never reach the destination file.
        """
        return self._dispatcher.bytes_received

    @property
    def profile(self) -> ServerProfile:
        """Which SFTP implementation this looks like, from what it advertised.

        Identification only: nothing in the library changes behaviour based on it, and
        :mod:`gantry_sftp.session._quirks` explains why that bound is deliberate. Useful for
        a log line, a bug report, and for a caller who *does* want to special-case a server
        and would otherwise fingerprint it themselves, worse.
        """
        return self._profile

    @override
    def __repr__(self) -> str:
        """Report the tunables a slow transfer would make you want to check.

        ``outstanding`` is here because a session is no longer one operation at a time: a
        number that stays pinned at the pipeline depth while nothing finishes is a stalled
        transfer, and one that is unexpectedly large is more concurrency than intended.

        ``requests`` and ``bytes`` are the cumulative pair beside it. A gauge alone cannot
        answer whether anything is *moving*: two reprs a second apart with the same
        ``outstanding`` and different totals is a slow link, and with the same totals it is a
        stall.

        ``cwd`` is present only when :meth:`chdir` has been called, because it is the one
        piece of state here that changes what a *path* in the caller's own code means.
        """
        # `cwd` appears only once set, and that is the point rather than brevity: it changes
        # what every relative path in the program means, so its absence has to read as "no
        # prefix" rather than as a field somebody skimmed past.
        cwd = "" if self._cwd is None else f"cwd={self._cwd!r} "
        return (
            f"<Session server={self._profile.label} version={self._codec.server_version} "
            f"extensions={len(self._codec.extensions)} {cwd}depth={self._depth} "
            f"outstanding={self._codec.outstanding} "
            f"requests={self._dispatcher.requests_sent}/{self._dispatcher.replies_received} "
            f"bytes={self._dispatcher.bytes_sent}/{self._dispatcher.bytes_received} "
            f"request_timeout={self._request_timeout} idle_timeout={self._idle_timeout}>"
        )

    def _server_note(self) -> str:
        """One line naming the peer, for a capability refusal to carry.

        "This server does not advertise X" is a complaint about a server the message does not
        name. A user reading it in a log two days later has to work out which endpoint the
        job was talking to; the connection already knew, and threw it away.
        """
        return (
            f"the server identifies as {self._profile.label} ({self._profile.description}) "
            f"and advertises {len(self._codec.extensions)} extension(s)"
        )

    def sizes_for(self, handle: bytes) -> TransferSizes:
        """Payload size per request for a given handle.

        The handle is part of every request header, so its length is part of the budget --
        OpenSSH's are four bytes and nothing promises another server's are.
        """
        return negotiate_transfer_sizes(self._limits, handle_length=len(handle))

    # --- one round trip ------------------------------------------------------------------

    async def request(self, request: Request) -> Response:
        """Send a request and return its reply.

        Safe to call from several tasks at once: each gets its own exchange, and the reader
        routes each reply to the request it answers. The version of this that read the
        transport itself had to hold a lock for exactly that reason -- it discarded every
        reply that was not the one it was waiting for, which is fine alone and is theft with
        company.

        The deadline covers the whole round trip rather than each chunk of it. Per-chunk
        would let a server dribble a byte at a time and never time out, which is a hang
        wearing a timeout's clothes.

        Raises:
            TransferTimeoutError: If the reply does not arrive in ``request_timeout``.
        """
        if self._request_timeout is None:
            return (await self._dispatcher.round_trip(request)).response
        try:
            with anyio.fail_after(self._request_timeout):
                return (await self._dispatcher.round_trip(request)).response
        except TimeoutError as exc:
            raise TransferTimeoutError(
                f"{type(request).__name__} was not answered within {self._request_timeout}s"
            ) from exc

    def _next(self) -> int:
        return self._codec.allocate_request_id()

    async def _expect_status(self, request: Request, *, path: bytes | None = None) -> None:
        """Send a request whose only useful answer is a STATUS, and raise unless it said OK.

        Raises:
            ServerError: Or the subclass matching the code, for a non-OK STATUS.
            ProtocolError: If the server answered with something other than a STATUS. Both
                ``EXTENDED`` requests this library sends are specified to answer with one and
                a real ``sftp-server`` does; a reply of another shape is a server we cannot
                interpret rather than a refusal we can report.
        """
        reply = await self.request(request)
        if isinstance(reply, Status):
            raise_for_status(reply, path=path)
            return
        raise _unexpected(reply, expected="STATUS", path=path)

    # --- capabilities --------------------------------------------------------------------

    def supports(self, extension: bytes | str) -> bool:
        """Whether the server *advertised* an extension.

        Advertisement only, and **absence here is not proof of absence**: endpoints implement
        extensions they never list, which is most of DESIGN.md 4.2. So this is the cheap
        question rather than the true one, and the library does not decide anything on it
        alone -- ``posix-rename`` and ``fsync`` are attempted whether or not they appear here,
        and what the server *answers* is what gets recorded (:meth:`refuses`).

        Every name OpenSSH is known to advertise has an ``EXTENSION_*`` constant, including
        the ones this library does not implement, so asking about one never means typing a
        wire string by hand.

        Args:
            extension: Wire name, as ``bytes`` or as one of the ``EXTENSION_*`` constants.
        """
        name = extension.encode("ascii") if isinstance(extension, str) else extension
        return name in self._codec.extensions

    def refuses(self, extension: bytes | str) -> bool:
        """Whether this server has answered ``OP_UNSUPPORTED`` for an extension, this session.

        The *definitive* half of capability detection, and the reason it exists separately
        from :meth:`supports`: an advertisement is a claim, and this is an answer. Only
        ``OP_UNSUPPORTED`` lands here. A refusal for any other reason -- permissions, a
        read-only directory, a file it does not like -- is a fact about one request rather
        than about the server, and caching it would turn one bad path into a capability this
        session never tries again.

        Cached per session because there is nowhere else to put it: extensions are negotiated
        per connection, and a new connection has to ask again.

        Args:
            extension: Wire name, as ``bytes`` or as one of the ``EXTENSION_*`` constants.
        """
        name = extension.encode("ascii") if isinstance(extension, str) else extension
        return name in self._unsupported

    async def _attempt_extension(
        self, extension: str, attempt: Callable[[], Awaitable[object]]
    ) -> bool:
        """Send an extension request that has a fallback, and say whether it was performed.

        **The one place an ``OP_UNSUPPORTED`` is recorded**, so that "we already asked" is a
        property of the session rather than of whichever call site remembered to check. Before
        this, the cache had exactly one reader and one writer, both inside the posix-rename
        path, and ``fsync`` and ``check-file`` neither consulted nor populated it (D-51).

        ``False`` means the server did not do it, for one of three reasons, and the difference
        matters at the call site rather than here:

        * it already answered ``OP_UNSUPPORTED`` this session -- no round trip is made;
        * it answers ``OP_UNSUPPORTED`` now -- recorded, so the next call is free;
        * it refused for some other reason **while not advertising** the extension -- in which
          case we do not know what we just asked of it, so the fallback stands and nothing is
          cached, because that answer was not definitive.

        A refusal from a server that *did* advertise the extension propagates instead. It is
        telling us about this operation -- the path, the permissions -- and falling through to
        a fallback that will fail the same way only buries the explanation.

        Args:
            extension: Wire name of the extension being attempted.
            attempt: Sends the request. Called at most once.

        Returns:
            Whether the server performed it.

        Raises:
            ServerError: For a non-``OP_UNSUPPORTED`` refusal of an advertised extension.
        """
        if self.refuses(extension):
            return False
        advertised = self.supports(extension)
        try:
            _ = await attempt()
        except UnsupportedError:
            self._unsupported.add(extension.encode("ascii"))
            return False
        except ServerError:
            if advertised:
                raise
            return False
        return True

    # --- operations ----------------------------------------------------------------------

    async def stat(self, path: bytes | str) -> Attrs:
        """Attributes of ``path``, following symlinks.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        reply = await self.request(Stat(self._next(), encoded))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS", path=encoded)

    async def lstat(self, path: bytes | str) -> Attrs:
        """Attributes of ``path`` itself, **not** following symlinks.

        The difference is not academic where this is used: ``stat`` on a symlink whose target
        is gone reports ``NO_SUCH_FILE``, so it answers "is there a file at the end of this
        name" while ``lstat`` answers "is this name taken". Publishing needs the second
        question.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        reply = await self.request(LStat(self._next(), encoded))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS", path=encoded)

    # --- the working directory, which this protocol does not have ---------------------------

    def _resolve(self, path: bytes | str) -> bytes:
        """Encode a caller's path and apply the working directory, if there is one.

        **Every public path argument goes through here**, which is what makes ``chdir`` mean
        the same thing to ``stat`` and to ``glob`` without either of them knowing it exists.
        The alternative -- each method prepending for itself -- is a per-method decision
        nobody re-reads, and the one that got forgotten would silently operate on a different
        file from the one the caller named.

        **Idempotent by construction, which is the property the recursive operations need.**
        Only a *relative* path is prefixed, and :attr:`_cwd` is always absolute, so a resolved
        path resolves to itself. ``walk`` resolves its root once and then joins child names
        onto that absolute root; every child therefore passes through here again -- from the
        walk, and again from whatever the caller does with it -- and is unchanged both times.
        A prefix applied to whatever it was handed would double on exactly those paths, and
        the resulting name would still be legal, so nothing would have failed.
        """
        encoded = _encode_path(path)
        if self._cwd is None or encoded.startswith(b"/"):
            return encoded
        return join_remote(self._cwd, encoded)

    async def chdir(self, path: bytes | str) -> None:
        """Set the directory relative paths resolve against, for this session.

        **SFTP v3 has no working directory**, so there is nothing on the wire to set: this is a
        prefix *this library* prepends, and every relative path given to this session
        afterwards is joined onto it. The server still has a default directory of its own --
        :attr:`server_root` -- and that is what relative paths resolve against until this is
        called.

        Two round trips, and both are the reason to use it rather than string arithmetic:

        - **``REALPATH`` first**, so what is stored is canonical. A prefix holding ``..`` is a
          prefix a symlink can make point somewhere else between the ``chdir`` and the
          operation, which is the same class of hazard as the containment checks on the
          download side. It also makes :meth:`getcwd` truthful rather than an echo.
        - **Then one ``STAT``**, because ``REALPATH`` checks nothing: canonicalising a path
          that does not exist *succeeds* on OpenSSH, measured against 10.0p2. Without it a
          ``chdir`` to a typo would be accepted and every later operation would fail somewhere
          else, naming a path the caller never typed. A ``STAT`` rather than
          :meth:`isdir` so that the three answers stay distinct in one round trip: absent
          raises ``NoSuchFileError``, present-but-not-a-directory raises with what it is, and
          a server that sends no permission bits refuses rather than being guessed at.

        Relative arguments compose, as a shell's do: two ``chdir("a")`` calls land in
        ``a/a``. Passing an absolute path replaces the prefix outright.

        **It does not survive a reconnect**, and that is consistent rather than an oversight:
        :func:`~gantry_sftp.session.with_reconnect` builds a new session per attempt and
        nothing survives one -- not the handles, not the request ids, not the negotiated
        limits. An operation that needs a working directory sets it *inside* the operation,
        which is the same shape that function already requires for everything else.

        Args:
            path: Directory to work from. Relative paths resolve against the current one.

        Raises:
            CapabilityError: If this server's namespace is not rooted at ``/``. A prefix is
                ``/`` arithmetic, so there is nothing correct to prepend -- the same refusal,
                for the same reason, as the recursive operations (D-77).
            CapabilityError: Also if the server sent no permission bits, leaving "is it a
                directory" unanswerable -- the same refusal :meth:`isdir` makes.
            NoSuchFileError: If the path is not there.
            ServerError: If it is not a directory, or the server refuses to canonicalise it.
        """
        requested = self._resolve(path)
        await self._require_rooted_paths(requested, feature="chdir()")
        canonical = await self._realpath_raw(requested)
        kind = self._classify(await self.stat(canonical), path=canonical, caller="chdir")
        if kind is not EntryKind.DIRECTORY:
            raise ServerError(
                f"chdir() needs a directory and {canonical!r} is a {kind.value}",
                code=int(StatusCode.FAILURE),
                path=canonical,
            )
        # Assigned last, so a refusal at any step above leaves the session where it was.
        self._cwd = canonical

    async def getcwd(self) -> bytes:
        """The directory relative paths resolve against right now.

        Whatever :meth:`chdir` last set, or -- before any ``chdir`` -- **the server's own
        default directory**, which is a ``REALPATH`` of ``.`` probed once and cached for the
        session. That probe is not new: it is what :meth:`_require_rooted_paths` has always
        done to decide whether path arithmetic is safe here, and :attr:`server_root` is the
        same value read without asking for it.

        Bytes, like everything else a server chose the spelling of.

        Returns:
            An absolute path, on any server whose namespace is rooted at ``/``. On one whose
            is not, whatever that server calls its default directory -- which is why this
            does *not* refuse where :meth:`chdir` does: reporting where you are asks no
            arithmetic, and prepending to it does.

        Raises:
            ServerError: If the server will not canonicalise ``.``, which is the only way the
                question can fail to have an answer.
        """
        if self._cwd is not None:
            return self._cwd
        if self._root is None:
            self._root = await self._realpath_raw(b".")
        return self._root

    # --- predicates ------------------------------------------------------------------------

    async def _attrs_or_absent(self, path: bytes, *, follow_symlinks: bool) -> Attrs | None:
        """Attributes for a predicate: ``None`` where the path is not there, nothing swallowed.

        **The whole of the three-state rule is here**, so that no predicate below gets to
        decide it separately. ``NO_SUCH_FILE`` is the server *answering* "no" and becomes
        ``None``; every other status is the server declining to answer and is raised. A
        predicate that collapses a refusal into ``False`` tells its caller a path is free when
        it may be occupied by something they are not allowed to see, and the caller then
        creates over it.

        Which conditions land in which state is a property of the far end rather than a
        deduction, so it was measured against OpenSSH 10.0p2
        (``_plans/probes/predicate_third_state_probe.py``):

        - A path *under* a file component answers ``NO_SUCH_FILE``. OpenSSH folds ``ENOTDIR``
          in there, so ``exists(b"/etc/passwd/nope")`` is an ordinary ``False``.
        - A symlink loop answers ``NO_SUCH_FILE`` as well (``ELOOP``), which matches what
          :func:`os.path.exists` reports for one locally.
        - A path inside a directory the caller may not traverse answers
          ``PERMISSION_DENIED``. **This is the third state**, it is reachable in one line of
          setup, and it is the case the rule exists for.
        - A name longer than the far end's ``NAME_MAX`` answers ``BAD_MESSAGE``, which reads
          as "your frame was malformed" and is nothing of the kind -- it is ``ENAMETOOLONG``
          arriving under a code that describes the wrong layer. It is a plain
          :class:`~gantry_sftp.exceptions.ServerError`, so catching anything broader than
          ``NoSuchFileError`` here would answer "not there" for a path that was merely long.

        Args:
            path: Encoded remote path.
            follow_symlinks: ``STAT`` when true, ``LSTAT`` when false.

        Returns:
            The attributes, or ``None`` if the server said ``NO_SUCH_FILE``.
        """
        try:
            return await (self.stat(path) if follow_symlinks else self.lstat(path))
        except NoSuchFileError:
            return None

    async def _kind_is(
        self, path: bytes | str, expected: EntryKind, *, follow_symlinks: bool, predicate: str
    ) -> bool:
        """Whether the server positively classifies ``path`` as ``expected``.

        ``False`` for absent and for a kind that is not the one asked about;
        :class:`~gantry_sftp.exceptions.CapabilityError` for a server that answered without
        permission bits, because v3 carries the file type *in* those bits and there is then
        nothing to classify from. Returning ``False`` there would report "not a directory"
        for an entry the server declined to describe -- the guess
        :attr:`~gantry_sftp.session.EntryKind.UNKNOWN` exists to prevent, and the reason
        recursive downloads silently skip directories on some servers.

        Args:
            path: Remote path.
            expected: The kind being asked about.
            follow_symlinks: Whether to resolve a symlink before classifying.
            predicate: Name of the calling method, for the error message.

        Returns:
            Whether the path is of that kind.

        Raises:
            CapabilityError: If the server reported no permission bits.
            PermissionDeniedError: If the path could not be reached.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        attributes = await self._attrs_or_absent(encoded, follow_symlinks=follow_symlinks)
        if attributes is None:
            return False
        return self._classify(attributes, path=encoded, caller=predicate) is expected

    def _classify(self, attributes: Attrs, *, path: bytes, caller: str) -> EntryKind:
        """What an entry is, refusing to guess where the server sent no permission bits.

        Shared by the predicates and by :meth:`chdir`, which need the same refusal for the
        same reason and differ only in what they do with a *missing* path -- a predicate
        answers ``False`` and ``chdir`` raises. Splitting the classification out is what lets
        each of them spend one round trip rather than two.
        """
        found = entry_kind(attributes)
        if found is not EntryKind.UNKNOWN:
            return found
        unclassifiable = CapabilityError(
            f"{caller}() cannot be answered for {path!r}: the server returned "
            f"attributes with no permission bits, and filexfer v3 carries the file type "
            f"in those bits, so there is nothing here to classify. Returning False would "
            f"report a definite 'no' for a question the server did not answer. Call "
            f"stat() or lstat() and decide from Attrs.permissions, or use walk(), which "
            f"reports an entry it cannot settle as skipped rather than guessing",
            feature=f"{caller}() against a server that sends no permission bits",
            path=path,
        )
        unclassifiable.add_note(self._server_note())
        raise unclassifiable

    async def exists(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        """Whether anything is at ``path``.

        ``False`` means the server said ``NO_SUCH_FILE`` and nothing else. A refusal it will
        not explain -- ``PERMISSION_DENIED`` on a directory you may not traverse, the v3
        ``FAILURE`` catch-all, a read-only mount -- is **raised**, because "I may not look" is
        not "there is nothing there", and a caller who treats it as one goes on to create
        something on top of whatever is already in the way.

        **Follows symlinks by default**, like :func:`os.path.exists`, so a link whose target is
        gone is ``False``. ``follow_symlinks=False`` asks the other question -- *is this name
        taken* -- which is the one publishing needs, and answers ``True`` for that broken link.

        Args:
            path: Remote path.
            follow_symlinks: Resolve a final symlink before answering. ``False`` reports on the
                link itself.

        Returns:
            Whether the path exists.

        Raises:
            PermissionDeniedError: If the path could not be reached to find out.
            ServerError: For any other refusal, including the ``BAD_MESSAGE`` OpenSSH answers
                for a name that is merely too long.
        """
        return (
            await self._attrs_or_absent(self._resolve(path), follow_symlinks=follow_symlinks)
            is not None
        )

    async def isdir(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        """Whether ``path`` is a directory.

        ``False`` for a path that is not there and for one that is something else; a refusal is
        raised, as in :meth:`exists`. Follows symlinks by default, so a link pointing at a
        directory is one -- :func:`os.path.isdir`'s answer. ``follow_symlinks=False`` reports on
        the link itself, which is then a symlink and not a directory.

        Args:
            path: Remote path.
            follow_symlinks: Resolve a final symlink before classifying.

        Returns:
            Whether it is a directory.

        Raises:
            CapabilityError: If the server sent no permission bits, leaving the kind unknowable.
            PermissionDeniedError: If the path could not be reached.
            ServerError: For any other refusal.
        """
        return await self._kind_is(
            path, EntryKind.DIRECTORY, follow_symlinks=follow_symlinks, predicate="isdir"
        )

    async def isfile(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        """Whether ``path`` is a regular file.

        Regular specifically: a fifo, a socket or a device node is ``False`` rather than
        "not a directory, therefore a file". Follows symlinks by default, matching
        :func:`os.path.isfile`.

        Args:
            path: Remote path.
            follow_symlinks: Resolve a final symlink before classifying.

        Returns:
            Whether it is a regular file.

        Raises:
            CapabilityError: If the server sent no permission bits, leaving the kind unknowable.
            PermissionDeniedError: If the path could not be reached.
            ServerError: For any other refusal.
        """
        return await self._kind_is(
            path, EntryKind.FILE, follow_symlinks=follow_symlinks, predicate="isfile"
        )

    async def islink(self, path: bytes | str) -> bool:
        """Whether ``path`` is a symlink.

        **No** ``follow_symlinks`` argument, unlike its neighbours: following the link first is
        what makes the question unanswerable, since what is at the end of one is never the link.
        This is ``LSTAT`` always, which is also why a *broken* link is ``True`` here and
        ``False`` from ``exists()`` -- between them those two separate "this name is taken" from
        "there is a file at the end of it".

        Args:
            path: Remote path.

        Returns:
            Whether the name is a symlink.

        Raises:
            CapabilityError: If the server sent no permission bits, leaving the kind unknowable.
            PermissionDeniedError: If the path could not be reached.
            ServerError: For any other refusal.
        """
        return await self._kind_is(
            path, EntryKind.SYMLINK, follow_symlinks=False, predicate="islink"
        )

    async def getsize(self, path: bytes | str, *, follow_symlinks: bool = True) -> int | None:
        """Size of ``path`` in bytes, or ``None`` where the server did not report one.

        **Not a predicate, and the two absences are different.** A path that is not there
        raises ``NoSuchFileError`` -- as :func:`os.path.getsize` raises rather than returning
        anything -- while ``None`` means the file is there and the server sent an ``ATTRS``
        with no ``SIZE`` bit in it. Every field of a v3 ``ATTRS`` is optional, so that is legal
        and it happens; returning ``0`` for it would report an empty file, which reads as a
        successful answer and is the silent-wrong-answer class :meth:`get` was fixed for.

        With ``follow_symlinks=False`` on a symlink this is the length of the *target string*,
        which is what ``lstat`` reports and what :func:`os.lstat` gives for one locally.

        Args:
            path: Remote path.
            follow_symlinks: Resolve a final symlink before measuring.

        Returns:
            The size, or ``None`` if the server reported no size at all.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        attributes = await (self.stat(path) if follow_symlinks else self.lstat(path))
        return attributes.size

    async def getmtime(self, path: bytes | str, *, follow_symlinks: bool = True) -> datetime | None:
        """When ``path`` was last modified, or ``None`` where the server did not say.

        **An aware UTC :class:`~datetime.datetime`, not a float**, and deliberately not
        :func:`os.path.getmtime`'s return type: this library reports timestamps through
        :func:`~gantry_sftp.session.modified_at`, whose whole reason for existing is that
        ``datetime.fromtimestamp(seconds)`` with no timezone yields the *client's* local wall
        clock and then silently disagrees with everything rendered server-side. A method
        handing back a bare number would put that trap back at the call site.

        ``None`` is "the server sent no ``ACMODTIME``", which is legal in v3 and is not
        1970 -- the coercion that makes every file look ancient to an ``if remote > local``
        and turns a sync into either a full re-transfer or a no-op, depending on which way the
        comparison runs. A path that is not there raises, as in :meth:`getsize`.

        Second-granular, since v3 has no sub-second field, so this is not a change detector on
        its own. See :func:`~gantry_sftp.session.modified_at` for the ``uint32`` range limit.

        Args:
            path: Remote path.
            follow_symlinks: Resolve a final symlink before reading its time.

        Returns:
            The modification time as an aware UTC datetime, or ``None`` if unstated.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        attributes = await (self.stat(path) if follow_symlinks else self.lstat(path))
        return modified_at(attributes)

    async def _set_one_attribute(
        self, path: bytes, attrs: Attrs, *, follow_symlinks: bool, operation: str
    ) -> None:
        """Apply one ATTRS field to a path, following the symlink or refusing to.

        **One field per call is the caller's job and this method's assumption.** OpenSSH's
        ``process_setstat`` and ``process_extended_lsetstat`` both walk the flags in sequence,
        applying each and recording only the last failure in the single ``STATUS`` they send
        back -- so a multi-field call that fails has already applied the fields before the
        failing one and does not say which. Every public caller here sends exactly one flag,
        which makes a refusal unambiguous and leaves nothing else moved.

        ``follow_symlinks=False`` needs ``lsetstat@openssh.com`` and **refuses without it**,
        rather than degrading to the following version. That is the opposite of what most
        extension use does here, and the reason is that there is nothing to degrade *to*: v3
        has no non-following spelling, so the fallback would be to perform a different
        operation than the one asked for, on a target the caller was trying to avoid.

        Attempted even where the server did not advertise the extension, since endpoints
        implement extensions they never list -- and an ``OP_UNSUPPORTED`` is cached, so a
        second call in the same session costs no round trip.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        if follow_symlinks:
            await self._expect_status(SetStat(self._next(), path, attrs), path=path)
            return
        try:
            performed = await self._attempt_extension(
                EXTENSION_LSETSTAT,
                lambda: self._expect_status(
                    LSetStat(self._next(), path, attrs).to_extended(), path=path
                ),
            )
        except ServerError as refusal:
            # OpenSSH's FAILURE carries no message worth reading -- five distinct conditions
            # all render as "Failure" -- and for this one flag there is a specific, common and
            # unfixable cause that the bare status sends a reader looking in the wrong place.
            if attrs.permissions is not None:
                refusal.add_note(
                    "the server may be refusing because it cannot do this at all: Linux has "
                    "no lchmod, so fchmodat(AT_SYMLINK_NOFOLLOW) answers ENOTSUP and OpenSSH "
                    "maps that to a contentless FAILURE. A symlink's own permission bits are "
                    "ignored by the Linux kernel and are always 0o777, so there is nothing to "
                    "set. The times and owner of a symlink can be set there; the mode cannot. "
                    "Pass follow_symlinks=True to change what the link points at, if that is "
                    "what you meant."
                )
            raise
        if not performed:
            unavailable = CapabilityError(
                f"follow_symlinks=False needs {EXTENSION_LSETSTAT}, which this server will "
                f"not perform, and filexfer v3 has no other way to {operation} a symlink "
                f"without following it. Passing follow_symlinks=True would {operation} "
                f"whatever {path!r} points at, which is a different operation",
                feature=f"{operation} without following a symlink",
                missing=(EXTENSION_LSETSTAT,),
                path=path,
            )
            unavailable.add_note(self._server_note())
            raise unavailable

    async def chmod(self, path: bytes | str, mode: int, *, follow_symlinks: bool = True) -> None:
        """Set the permission bits of ``path``.

        ``SETSTAT`` carrying **only** ``PERMISSIONS``, and the single flag is the decision
        rather than an economy. OpenSSH's ``process_setstat`` walks the ATTRS flags in order --
        ``SIZE`` to ``truncate``, ``PERMISSIONS`` to ``chmod``, ``ACMODTIME`` to ``utimes``,
        ``UIDGID`` to ``chown`` -- applying each in turn and recording only the *last* failure
        in the single ``STATUS`` it sends back. So a multi-field ``SETSTAT`` that fails has
        already applied the fields before the failing one, and the answer does not say which
        field it was. One field per call makes a refusal unambiguous and leaves nothing else
        moved.

        **It follows symlinks by default**, because ``SETSTAT`` is ``chmod(2)`` and that is what
        ``chmod(2)`` does -- the same default as :func:`os.chmod`. Where the path may be a
        symlink planted by someone else, that is a chmod of whatever it points at.
        ``follow_symlinks=False`` uses ``lsetstat@openssh.com`` and **refuses** where the server
        will not, rather than silently doing the following version: v3 has no other spelling, so
        there is nothing to degrade to.

        **On a Linux server that refusal is unconditional, and the extension being present does
        not change it.** Linux has no ``lchmod``: ``fchmodat(AT_SYMLINK_NOFOLLOW)`` answers
        ``ENOTSUP``, measured, so ``lsetstat``'s permissions branch cannot succeed there however
        the server is configured. A symlink's own mode is meaningless to that kernel and always
        reads ``0o777``. The refusal arrives as OpenSSH's contentless ``FAILURE`` and this
        library attaches a note saying so. :meth:`utime` and :meth:`chown` *do* work on a link
        there -- ``utimensat`` and ``fchownat`` accept the flag -- so this limit is the mode's
        alone, not the extension's.

        Args:
            path: What to modify.
            mode: Permission bits. Masked to ``0o7777``, which is what ``chmod(2)`` takes and
                what OpenSSH applies (``a.perm & 07777``); the file-type bits an ``st_mode``
                carries are not permissions and are dropped rather than sent.
            follow_symlinks: Whether to act on the link's target. ``False`` needs
                ``lsetstat@openssh.com`` -- advertised by OpenSSH and asyncssh, absent from
                paramiko -- **and** a server platform with ``lchmod``, which Linux is not.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        await self._set_one_attribute(
            encoded,
            Attrs(permissions=mode & PERMISSION_BITS),
            follow_symlinks=follow_symlinks,
            operation="chmod",
        )

    async def chown(
        self, path: bytes | str, uid: int, gid: int, *, follow_symlinks: bool = True
    ) -> None:
        """Set the numeric owner and group of ``path``.

        **Both together or neither**, because ``UIDGID`` is one flag covering two fields --
        there is no way to send a uid without a gid, so "leave the group alone" has to be
        spelled by reading the current gid back with :meth:`stat` and sending it unchanged.
        That is the wire's shape rather than ours; :class:`~gantry_sftp.codec.Owner` exists to
        make the pairing visible instead of leaving two loose integers.

        **Numeric ids only.** Turning them into names needs
        ``users-groups-by-id@openssh.com``, which is not implemented here, and the display
        string in ``longname`` is not a source -- it is rendered by the server, in the server's
        name resolution, for a human.

        Args:
            path: What to modify.
            uid: Numeric user id.
            gid: Numeric group id.
            follow_symlinks: Whether to act on the link's target. ``False`` needs
                ``lsetstat@openssh.com``.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it -- which is the common
                answer, since changing a file's owner is root's privilege on every ordinary
                Unix server.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        await self._set_one_attribute(
            encoded,
            Attrs(owner=Owner(uid=uid, gid=gid)),
            follow_symlinks=follow_symlinks,
            operation="chown",
        )

    async def utime(
        self, path: bytes | str, atime: int, mtime: int, *, follow_symlinks: bool = True
    ) -> None:
        """Set the access and modification times of ``path``, in whole seconds.

        **Both together or neither**, for the same reason :meth:`chown` pairs its two: they
        share one ``ACMODTIME`` flag.

        v3 carries ``uint32`` seconds, so sub-second precision does not exist here and a value
        that does not fit is refused rather than truncated -- see
        :data:`~gantry_sftp.codec.MAX_V3_TIMESTAMP`. Whether the *transfer* methods carry times
        across is ``preserve_times=``; this is the standalone call, for a file already there.

        Args:
            path: What to modify.
            atime: Access time, seconds since the epoch.
            mtime: Modification time, seconds since the epoch.
            follow_symlinks: Whether to act on the link's target. ``False`` needs
                ``lsetstat@openssh.com``.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
            ValueError: If either value does not fit filexfer v3's ``uint32`` seconds.
        """
        encoded = self._resolve(path)
        await self._set_one_attribute(
            encoded,
            Attrs(times=Times(atime=atime, mtime=mtime)),
            follow_symlinks=follow_symlinks,
            operation="utime",
        )

    async def truncate(self, path: bytes | str, size: int) -> None:
        """Set the length of ``path``, discarding anything past it or zero-filling to reach it.

        ``SETSTAT`` carrying only ``SIZE``, which OpenSSH answers with ``truncate(2)``.

        **There is no ``follow_symlinks=False`` here, and its absence is the server's decision
        rather than an omission.** ``process_extended_lsetstat`` rejects ``SIZE`` outright --
        ``BAD_MESSAGE``, with the comment ``/* nonsensical for links */`` -- so the extension
        every other method on this page uses for the non-following case cannot carry a
        truncation at all. A parameter that could only ever fail would be worse than not having
        one.

        Args:
            path: What to modify. Followed if it is a symlink, necessarily.
            size: The new length in bytes. Growing a file this way makes a hole rather than
                writing zeroes, so the space is not reserved and a later write can still fail
                with ``ENOSPC``.

        Raises:
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        await self._expect_status(SetStat(self._next(), encoded, Attrs(size=size)), path=encoded)

    async def ftruncate(self, handle: bytes, size: int) -> None:
        """Set the length of an **open file**, by handle rather than by path.

        The handle-addressed :meth:`truncate`, and the difference is the same one :meth:`fstat`
        exists for: a path can be replaced between the ``OPEN`` and the ``SETSTAT``, so a
        writer that truncates by name can truncate a file it is not the one holding open. It
        is also the only form available to a caller who has a handle and no usable path --
        which is every caller of :meth:`open_file`.

        ``FSETSTAT`` carrying only ``SIZE``. Growing a file this way makes a hole rather than
        writing zeroes, so the space is not reserved and a later write can still fail with
        ``ENOSPC``.

        Args:
            handle: An open file handle, opened for writing.
            size: The new length in bytes.

        Raises:
            ValueError: If ``size`` is negative.
            ServerError: If the server refuses. A read-only handle answers ``NO_SUCH_FILE``
                here, the same misdirection a write on one gives.
        """
        if size < 0:
            raise ValueError(f"size must not be negative, got {size}")
        await self._expect_status(FSetStat(self._next(), handle, Attrs(size=size)))

    async def fstat(self, handle: bytes) -> Attrs:
        """Attributes of an open handle.

        The handle-addressed :meth:`stat`, and the difference is worth the method: a path can
        be replaced between the ``OPEN`` and the ``STAT``, so asking the handle is asking about
        the file this session actually has open rather than about whatever currently answers to
        that name.

        Raises:
            ServerError: If the server refuses -- which includes a handle it does not know, and
                a server that does not implement ``FSTAT`` on a directory handle.
        """
        reply = await self.request(FStat(self._next(), handle))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS")

    async def readlink(self, path: bytes | str) -> bytes:
        """Read the target of a symlink, without following it.

        **The answer is attacker-controlled and is returned raw.** A link target is an
        arbitrary byte string chosen by whoever created the link -- it may be absolute, may
        climb with ``..``, may not be valid UTF-8, and may name something that does not exist.
        Nothing is validated here because there is nothing to validate against: every one of
        those is a legal symlink. **Do not join it onto a local path** without the containment
        check :meth:`get_tree` uses; that is the zip-slip class, and this method is the
        shortest route to it.

        **A path that is not a symlink answers ``BAD_MESSAGE``**, not ``FAILURE`` and not
        ``NO_SUCH_FILE``. That code reads as "the frame you sent was malformed" and here means
        ``EINVAL`` -- OpenSSH maps ``EINVAL`` and ``ENAMETOOLONG`` onto it, so the status that
        looks like a bug in this library is how ``readlink`` says "that is not a link".
        Measured, and in DESIGN 13.

        Returns:
            The link target exactly as the server sent it.

        Raises:
            ProtocolError: If the server answers with something other than a NAME, or with a
                NAME carrying any number of names other than one. Same strictness as
                :meth:`realpath` and for the same reason: ``send_names`` sends exactly one, so
                a different count is a server we do not understand rather than a choice to make.
            NoSuchFileError: If the path does not exist.
            ServerError: If the path is not a symlink (``BAD_MESSAGE``), or for any other
                refusal.
        """
        encoded = self._resolve(path)
        reply = await self.request(ReadLink(self._next(), encoded))
        if not isinstance(reply, Name):
            raise _unexpected(reply, expected="NAME", path=encoded)
        if len(reply.entries) != 1:
            raise ProtocolError(
                f"READLINK of {encoded!r} answered with {len(reply.entries)} names, "
                f"and a link has exactly one target",
                request_id=reply.request_id,
            )
        return reply.entries[0].filename

    async def symlink(self, target: bytes | str, link_path: bytes | str) -> None:
        """Create a symlink at ``link_path`` pointing at ``target``.

        Argument order matches :func:`os.symlink` -- target first, then the name being created
        -- which is **not** the order these fields take on the wire. OpenSSH sends
        ``targetpath`` then ``linkpath`` where ``draft-ietf-secsh-filexfer-02`` specifies the
        reverse, and the reference implementation is what binds: sending the draft order
        against a real ``sftp-server`` returns ``FAILURE`` and creates nothing. That reversal
        lives in :class:`~gantry_sftp.codec.SymLink`'s encoder, checked against a server, and
        not here.

        ``target`` is not resolved, checked, or required to exist. A dangling symlink is a
        legal thing to create and some deployments create one deliberately.

        **That includes not resolving it against :meth:`chdir`'s working directory**, which is
        the one place this library's prefix must not reach: ``target`` is a *string stored
        inside the link*, interpreted by the server relative to the link's own directory, not
        a path this client is about to operate on. Prefixing it would silently turn
        ``symlink(b"data.csv", b"alias.csv")`` -- a relative link, which is what a shell makes
        and what survives the directory being moved -- into an absolute one pointing at
        wherever the session happened to be standing. Caught by the sweep that routed every
        other path through the resolver: this docstring already said the rule, and the sweep
        made it false.

        Args:
            target: What the link should point at.
            link_path: The name to create.

        Raises:
            PermissionDeniedError: If the server will not create it.
            ServerError: For any other refusal, including a name that is already taken.
        """
        encoded = self._resolve(link_path)
        await self._expect_status(
            SymLink(self._next(), targetpath=_encode_path(target), linkpath=encoded),
            path=encoded,
        )

    async def realpath(self, path: bytes | str = b".") -> bytes:
        """Canonicalise ``path`` on the server.

        Servers disagree about what this does for a path that does not exist -- some
        canonicalise anyway, some refuse. That disagreement belongs to the quirks layer and
        is not smoothed over here.

        **Exactly one name, and a count that is not one is an error rather than a guess.**
        Unlike READDIR -- where the draft and OpenSSH's client disagree about strictness and
        the client wins (see :meth:`readdir`) -- here they agree: the draft specifies a single
        name, and ``sftp-client.c`` does ``if (count != 1) fatal("Got multiple names (%d)")``.
        Where both are strict there is nothing for us to be lenient *towards*. Taking the
        first of several would be picking one of the server's answers and calling it the
        canonical path, which is the silently-wrong failure this layer exists to prevent.

        **A relative argument resolves against :meth:`getcwd`**, like every other path this
        session takes, so ``realpath(b".")`` after a :meth:`chdir` canonicalises the directory
        you moved to rather than the one the server started you in. :attr:`server_root` is the
        other question and keeps its own answer.

        Raises:
            ProtocolError: If the server answers with something other than a NAME, or with a
                NAME carrying any number of names other than one.
            NoSuchFileError: If the server refuses because the path does not exist.
            ServerError: For any other refusal.
        """
        return await self._realpath_raw(self._resolve(path))

    async def _realpath_raw(self, encoded: bytes) -> bytes:
        """``REALPATH`` of an already-resolved path, with no working directory applied.

        The split exists for one caller and it is load-bearing: the rootedness probe below
        asks *the server* where its default directory is, and running that through the
        client-side prefix would answer with wherever :meth:`chdir` last went. It would then
        cache that as :attr:`server_root`, which is a different question with a public name.
        """
        reply = await self.request(RealPath(self._next(), encoded))
        if not isinstance(reply, Name):
            raise _unexpected(reply, expected="NAME", path=encoded)
        if len(reply.entries) != 1:
            raise ProtocolError(
                f"REALPATH of {encoded!r} answered with {len(reply.entries)} names, "
                f"and exactly one is the only useful answer",
                request_id=reply.request_id,
            )
        return reply.entries[0].filename

    async def _require_rooted_paths(self, path: bytes, *, feature: str) -> None:
        """Refuse an operation whose path arithmetic this server's namespace does not fit.

        Every remote path this library builds -- joining a child onto a directory, splitting a
        staging file's parent off its target -- is ``/`` arithmetic on bytes. That is what
        ``draft-ietf-secsh-filexfer-02`` §6.2 says to assume: *"File names are assumed to use
        the slash ('/') character as a directory separator"*, and *"otherwise, no syntax is
        defined for file names by this specification"*. There is therefore no correct way to
        join a path in a namespace that is not ``/``-shaped -- VMS ``DISK$USER:[DIR]FILE.TXT``,
        an MVS dataset name -- because the protocol does not describe one, and guessing per
        vendor is a different project. So the answer is to refuse rather than to build a path
        the server does not mean.

        **An absolute path asks nothing and costs nothing.** §6.2 also says *"File names
        starting with a slash are 'absolute', and are relative to the root of the file
        system"* -- so a caller who passed one has already asserted the namespace this
        arithmetic assumes, and no probe is sent. Only a relative path is in question, because
        that one is *"relative to the user's default directory"*, and whether **that**
        namespace uses ``/`` is the thing we cannot know without asking.

        The probe is one ``REALPATH`` of ``.``, cached for the life of the session.

        Args:
            path: The remote path the operation was given, already encoded.
            feature: What is being attempted, in the caller's terms, for the error.

        Raises:
            CapabilityError: If this server's default directory is not rooted at ``/``.
        """
        if path.startswith(b"/"):
            return
        if self._root is None:
            self._root = await self._realpath_raw(b".")
        if self._root.startswith(b"/"):
            return
        refusal = CapabilityError(
            f"{feature} builds remote paths by '/' arithmetic and this server's default "
            f"directory is not rooted at '/': REALPATH of b'.' answered {self._root!r}. "
            f"draft-ietf-secsh-filexfer-02 6.2 defines no other filename syntax, so joining "
            f"or splitting {path!r} would produce a path this server does not mean. Pass an "
            f"absolute '/'-rooted path, or drive the per-file operations yourself with paths "
            f"you build",
            feature=feature,
            path=path,
        )
        refusal.add_note(self._server_note())
        raise refusal

    @property
    def server_root(self) -> bytes | None:
        """This server's canonical form of ``.``, if anything has needed to ask.

        ``None`` means the question never came up, **not** that the server has no root: the
        probe is lazy because an operation given an absolute path never needs it.
        """
        return self._root

    async def open(
        self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ, *, mode: int | None = None
    ) -> bytes:
        """Open a remote file and return its handle.

        Args:
            path: What to open.
            pflags: Access and creation flags.
            mode: Permission bits for a file this call **creates**, or ``None`` to leave it to
                the server. Ignored by the server when the file already exists, exactly as
                ``open(2)``'s mode argument is, so this is not a way to change an existing
                file's permissions -- :meth:`chmod` is.

                ``None`` is not neutral and it is worth knowing what it means: OpenSSH's
                ``process_open`` reads this ATTRS for ``PERMISSIONS`` and nothing else,
                defaulting to ``0666`` when the flag is absent, so a file created without it
                arrives ``0666 & ~umask`` -- world-readable under the usual umask.

        Raises:
            NoSuchFileError: If the path does not exist and was not to be created.
            PermissionDeniedError: If the server will not open it.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        attrs = EMPTY_ATTRS if mode is None else Attrs(permissions=mode)
        reply = await self.request(Open(self._next(), encoded, pflags, attrs))
        if isinstance(reply, Handle):
            return reply.handle
        raise _unexpected(reply, expected="HANDLE", path=encoded)

    async def readinto_at(self, handle: bytes, buffer: bytearray | memoryview, offset: int) -> int:
        """Read ``len(buffer)`` bytes from ``offset`` into ``buffer``. The zero-copy primitive.

        Pipelined: a range longer than one request becomes several in flight, exactly as a
        ``get`` does, because a byte-range read that issues one ``READ`` and awaits it costs a
        round trip per call. That is not a hypothetical -- it is the documented behaviour of
        the incumbent's file object, which runs 25x slower than its own whole-file download
        (``paramiko#2453``).

        **Safe to call from several tasks at once**, on the same handle or on different ones:
        the offset is an argument rather than a cursor, so there is no shared position for two
        tasks to interleave. :meth:`open_file` is the cursor-bearing form and is not.

        Args:
            handle: An open remote file handle, opened for reading.
            buffer: Writable destination, filled from its first byte. Its length is the range.
            offset: Absolute offset in the remote file.

        Returns:
            Bytes read. Short of ``len(buffer)`` **only at end of file** -- a short ``DATA`` is
            legal mid-file and is re-requested rather than returned, so a caller never has to
            loop to fill a range. ``0`` means the offset was at or past the end.

            The unfilled tail of ``buffer`` is left as it was rather than zeroed.

        Raises:
            ValueError: If ``offset`` is negative.
            TransferError: If the server refuses the read -- **not** the typed status error
                :meth:`open` would raise, because this is the transfer scheduler and a refusal
                here carries how far the range got. The status name is in the message.

                Two of those messages mislead and it is the server's doing rather than ours: a
                handle opened write-only answers ``NO_SUCH_FILE``, and so does a handle that
                has already been closed. OpenSSH's handle lookup checks the direction, so "No
                such file" is what a perfectly good path reports when the handle is the wrong
                kind.
            TransferTimeoutError: If the server stops responding.
        """
        view = memoryview(buffer) if isinstance(buffer, bytearray) else buffer
        return await read_range_into(
            self._dispatcher,
            handle,
            view,
            offset=offset,
            read_length=self.sizes_for(handle).read_length,
            depth=self._depth,
            idle_timeout=self._idle_timeout,
        )

    async def read_at(self, handle: bytes, offset: int, length: int) -> bytes:
        """Read up to ``length`` bytes from ``offset``, pipelined.

        The ergonomic form of :meth:`readinto_at`, and the one copy in it is the return type:
        handing back immutable ``bytes`` means copying out of the buffer that was filled.
        Reach for ``readinto_at`` when that matters.

        **A zero-length read is answered here rather than on the wire.** OpenSSH replies to a
        zero-length ``READ`` with an empty ``DATA``, which is also exactly how a server making
        no progress looks -- the transfer scheduler tolerates one and fails on the second, and
        it is right to. Rather than teach it an exception for a case whose answer is already
        known, this returns ``b""`` without asking.

        Args:
            handle: An open remote file handle, opened for reading.
            offset: Absolute offset in the remote file.
            length: Bytes to read. May exceed the server's ``max-read-length``; the range is
                split across requests, so there is no ceiling a caller has to know about.

        Returns:
            The bytes read: exactly ``length`` of them unless end of file arrived first, and
            ``b""`` at or past the end.

        Raises:
            ValueError: If ``offset`` or ``length`` is negative.
        """
        if length < 0:
            raise ValueError(f"length must not be negative, got {length}")
        if offset < 0:
            raise ValueError(f"offset must not be negative, got {offset}")
        if length == 0:
            return b""
        buffer = bytearray(length)
        filled = await self.readinto_at(handle, buffer, offset)
        del buffer[filled:]
        return bytes(buffer)

    async def write_at(self, handle: bytes, offset: int, data: bytes | memoryview) -> int:
        """Write ``data`` at ``offset``, pipelined.

        Longer than one request becomes several in flight, and the payload is not copied on
        the way to the wire.

        **Safe to call from several tasks at once on different ranges**; two tasks writing the
        same range is a race this cannot arbitrate, exactly as with two processes and
        ``pwrite``. Unlike a read, a write is **not idempotent** -- nothing here retries one,
        and a caller reissuing a failed write has to know what the server already stored.

        Writing past the end of the file is legal and leaves a hole, which reads back as
        zeroes. Verified against ``sftp-server`` rather than assumed.

        Args:
            handle: An open remote file handle, opened for writing.
            offset: Absolute offset in the remote file.
            data: The bytes to write. Empty writes no bytes and costs no round trip.

        Returns:
            Bytes the server acknowledged, which is ``len(data)`` on success.

        Raises:
            ValueError: If ``offset`` is negative.
            TransferError: If the server refuses the write, carrying how far it got. A handle
                opened read-only answers ``NO_SUCH_FILE`` inside that message, for the same
                reason a read on a write-only handle does.
        """
        if offset < 0:
            raise ValueError(f"offset must not be negative, got {offset}")
        payload = memoryview(data) if isinstance(data, bytes) else data
        if not len(payload):
            return 0
        return await write_range_from(
            self._dispatcher,
            handle,
            payload,
            offset=offset,
            write_length=self.sizes_for(handle).write_length,
            depth=self._depth,
            idle_timeout=self._idle_timeout,
        )

    def open_file(
        self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ, *, mode: int | None = None
    ) -> RemoteFile:
        """Open a remote file as a cursor-bearing object, for ranges and streaming.

        The shape a caller reaches for when the file does not fit the whole-file transfer
        model: a header, a range, a tail, an append, or a stream into a parser::

            async with sftp.open_file("/logs/today.jsonl") as remote:
                header = await remote.read(512)
                await remote.seek(-4096, io.SEEK_END)
                tail = await remote.read()

        A context manager rather than a bare object, for the same reason
        :meth:`scandir` is one: it holds a server-side handle open, and an object that is
        merely dropped is not finalised by trio -- the handle would sit on the server until
        the garbage collector felt like it, if ever.

        **One file object is one task.** The cursor is mutable shared state, so two tasks
        reading the same object interleave their positions and each gets a subset of the bytes
        it asked for -- a correctness bug that reads as a scheduling one. That is not a
        limitation of the session, which multiplexes happily; it is what a cursor *is*. For
        concurrent access to one file, use :meth:`readinto_at` and :meth:`write_at`, which take
        the offset as an argument and are safe to fan out.

        Args:
            path: What to open.
            pflags: Access and creation flags, exactly as :meth:`open`.
            mode: Permission bits for a file this call creates. Omitting it means the file
                arrives ``0666 & ~umask`` -- world-readable under the usual umask -- and no
                later ``chmod`` closes the window between creation and the fix.

        Returns:
            An unopened :class:`RemoteFile`. Nothing is sent until it is entered.
        """
        return RemoteFile(self, self._resolve(path), pflags, mode=mode)

    async def opendir(self, path: bytes | str) -> bytes:
        """Open a remote directory and return its handle.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: If it is not a directory, or the server refuses.
        """
        encoded = self._resolve(path)
        reply = await self.request(OpenDir(self._next(), encoded))
        if isinstance(reply, Handle):
            return reply.handle
        raise _unexpected(reply, expected="HANDLE", path=encoded)

    async def readdir(self, handle: bytes) -> tuple[DirEntry, ...] | None:
        """Read one batch of entries, or ``None`` at the end of the directory.

        One READDIR is **not** a whole directory: the server returns as many entries as it
        feels like -- OpenSSH caps a batch at 100 -- and the caller keeps asking until this
        answers ``None``. Treating the first batch as the listing is how a client silently
        loses everything after the hundredth file.

        ``.`` and ``..`` are **not** filtered here. This is the raw batch; the filtering
        belongs to :meth:`listdir`, and keeping one place that shows what the server actually
        sent is what makes that filtering testable.

        **A NAME carrying zero names ends the directory too, and that is a decision.** The
        draft is explicit that it should not happen -- SSH_FXP_READDIR is answered with "one
        or more names", and end of directory is a ``STATUS`` of ``EOF`` -- and OpenSSH's
        server never sends one: ``process_readdir`` is ``if (count > 0) send_names(...) else
        send_status(id, SSH2_FX_EOF)``. So a zero-count NAME is a server bug whichever way we
        read it, and the only question is which way to fail on it.

        Treating it as an empty *batch* and asking again is what a literal reading gives, and
        it is a **livelock**: a server that answers every READDIR that way pins the client at
        100% CPU forever, in the operation every recursive transfer starts with. Refusing it
        with a ``ProtocolError`` would be defensible from the draft alone, but it would make
        this library **stricter than ``sftp(1)``** -- OpenSSH's own client reads the count and
        does ``if (count == 0) break;``, on the line above its ``SSH2_FX_EOF`` check. Every
        server in production has been tested against that client, which is what makes the
        truncation risk here structural rather than merely unlikely: a server that sends an
        empty NAME with entries still to come already silently truncates for every OpenSSH
        user, so it does not survive to ship. A server that sends one *as* its end-of-listing
        marker works fine with ``sftp(1)`` and therefore can and does exist.

        So it ends the listing, matching the reference client. Sourced in DESIGN.md 7.

        Returns:
            The batch, or ``None`` once the directory is finished -- by ``EOF`` or by an empty
            NAME, which are treated alike.

        Raises:
            ServerError: If the server refuses.
        """
        reply = await self.request(ReadDir(self._next(), handle))
        if isinstance(reply, Name):
            # An empty NAME is end of directory, not an empty batch. Returning `()` here is
            # what made every batch-following loop in this file spin forever on one.
            if not reply.entries:
                return None
            return tuple(DirEntry.from_name_entry(entry) for entry in reply.entries)
        if isinstance(reply, Status):
            if reply.code is StatusCode.EOF:
                return None
            raise_for_status(reply)
        raise _unexpected(reply, expected="NAME")

    def scandir(self, path: bytes | str) -> DirectoryScan:
        """Stream a directory, one batch at a time, holding one handle open.

        The bounded-memory listing. :meth:`listdir` accumulates the whole directory, which is
        a memory cost the *server* chooses; this one holds a batch. Reach for it when the
        directory may be enormous, when the server is not one you control, or when the answer
        you want is the first entry that matches::

            async with sftp.scandir("/incoming") as entries:
                async for entry in entries:
                    if entry.is_file and entry.name.endswith(".csv"):
                        break

        The ``async with`` is not decoration -- it owns the directory handle. Iterating
        without it raises :class:`~gantry_sftp.exceptions.StateError` rather than leaking one.

        Not a coroutine: it returns the scan object, so it is ``async with sftp.scandir(...)``
        and never ``async with await sftp.scandir(...)``.

        Args:
            path: Remote directory.

        Returns:
            A :class:`DirectoryScan`, which opens the directory when it is entered. Entries
            come in the order the server sent them, which is not guaranteed to be sorted, and
            ``.`` and ``..`` are excluded exactly as in :meth:`listdir`.
        """
        return DirectoryScan(self, self._resolve(path))

    async def listdir(self, path: bytes | str) -> list[DirEntry]:
        """List a directory, following the batches to the end.

        ``.`` and ``..`` are excluded, because every caller wants them gone and the one who
        forgets writes a recursion that never terminates. OpenSSH sends both; a server that
        does not needs no special case.

        **The whole listing is accumulated in memory, and the server decides how large that
        is.** For an ordinary directory that is exactly what a caller wants. For one with
        millions of entries, or a server willing to answer READDIR with new names forever, it
        is unbounded allocation driven by the peer -- so use :meth:`scandir`, which holds one
        batch. Nothing is capped here, because a silent cap breaks the legitimate large
        directory *and* reports success, which is the worse bug.

        Args:
            path: Remote directory.

        Returns:
            Entries in the order the server sent them, which is not guaranteed to be sorted.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: If it is not a directory, or the server refuses.
        """
        async with self.scandir(path) as entries:
            return [entry async for entry in entries]

    async def close(self, handle: bytes) -> None:
        """Close a remote handle.

        Not merely bookkeeping: some servers report a write failure here rather than on the
        WRITE that caused it, so a CLOSE that returns an error is the transfer failing.
        """
        await self._expect_status(Close(self._next(), handle))

    async def mkdir(self, path: bytes | str, *, exist_ok: bool = False) -> None:
        """Create a directory.

        ``exist_ok`` costs a round trip when it fires, and it has to: v3 answers a failed
        MKDIR with ``FAILURE``, the catch-all that means nothing, so "it is already there" is
        indistinguishable from "the parent is read-only" by status code. The only honest way
        to tell them apart is to look, which is what this does -- and it checks the path is a
        *directory*, since a file of the same name is a different problem wearing the same
        status.

        Raises:
            ServerError: If the server refuses, and ``exist_ok`` does not excuse it.
        """
        encoded = self._resolve(path)
        try:
            await self._expect_status(MkDir(self._next(), encoded, EMPTY_ATTRS), path=encoded)
        except ServerError:
            if not exist_ok or not await self._is_directory(encoded):
                raise

    async def makedirs(self, path: bytes | str, *, exist_ok: bool = False) -> None:
        """Create a directory and any missing ancestors of it.

        :func:`os.makedirs` semantics, including the part that is easy to miss: **an existing
        ancestor is always fine, and ``exist_ok`` governs the last component only.** So
        ``makedirs`` on a directory that is already there raises by default, and the argument
        is how a caller says they meant "make sure it exists".

        Cheap in the common case and only in it. One ``MKDIR`` when the parent is already
        there, and a walk up the path -- one round trip per level -- only when a level is
        genuinely absent. The alternative, creating every ancestor unconditionally, charges
        every caller the depth of their destination to help the one whose destination was
        three levels missing.

        **A refusal names the deepest component that could not be created**, which is not
        always the one you asked for: ``makedirs(b"/locked/a/b")`` against a directory you may
        not write reports ``/locked/a``, because that is the one to fix. v3 answers a failed
        ``MKDIR`` with the contentless ``FAILURE`` -- OpenSSH 10.0p2 sends the single word
        ``Failure`` whether the path is occupied by a file, occupied by a directory, or on a
        full disk -- so where something *is* in the way this looks, and says which of those it
        was, in a note on the error.

        Args:
            path: Remote directory to create, with its ancestors.
            exist_ok: Do not raise if the last component is already a directory. An existing
                ancestor never raises regardless.

        Raises:
            PermissionDeniedError: If a level could not be created.
            ServerError: For any other refusal, including the destination already existing
                when ``exist_ok`` is false, and something that is not a directory being in
                the way.
        """
        encoded = self._resolve(path)
        try:
            await self._mkdir_parents(encoded, exist_ok=exist_ok)
        except ServerError as refusal:
            await self._note_what_is_in_the_way(refusal)
            raise

    async def _note_what_is_in_the_way(self, refusal: ServerError) -> None:
        """Turn a bare ``FAILURE`` from a ``MKDIR`` into something that names the obstacle.

        One ``LSTAT``, on an already-failing path, because the status code carries nothing:
        five distinct conditions render as ``Failure`` on OpenSSH and none of them says
        whether a file is sitting where the directory should go. A server that will not answer
        the ``LSTAT`` either leaves the error exactly as it was -- a note is worth having and
        never worth inventing.
        """
        if refusal.path is None:
            return
        try:
            attributes = await self.lstat(refusal.path)
        except ServerError:
            return
        kind = entry_kind(attributes)
        if kind is EntryKind.DIRECTORY:
            refusal.add_note(
                f"{refusal.path!r} is already a directory; pass exist_ok=True to accept that "
                f"rather than treating it as a failure"
            )
            return
        refusal.add_note(
            f"{refusal.path!r} already exists and is a {kind.value}, not a directory, so "
            f"nothing can be created at that name until it is moved or removed"
        )

    async def _is_directory(self, path: bytes) -> bool:
        """Whether the server positively reports ``path`` as a directory.

        ``LSTAT``, so a symlink is not mistaken for what it points at, and every failure --
        including a server that sends no permissions at all -- answers ``False``. Used to
        decide whether a refusal can be excused, and "the server would not say" is not an
        excuse.

        Distinct from :meth:`isdir`, which is the public question and raises where this
        returns ``False``: here the caller is deciding whether to *excuse* a refusal it
        already has, and an unexplained answer must not excuse anything.
        """
        try:
            attributes = await self.lstat(path)
        except ServerError:
            return False
        return entry_kind(attributes) is EntryKind.DIRECTORY

    async def remove(self, path: bytes | str) -> None:
        """Delete a file, a symlink, or any other non-directory entry.

        ``REMOVE`` is ``unlink(2)``: it deletes the *name*, so a symlink is removed rather
        than what it points at, and a directory is refused rather than emptied. That refusal
        is load-bearing for :meth:`rmtree`, which is the only recursive delete here.

        Raises:
            NoSuchFileError: If the path is not there.
            ServerError: For any other refusal, including the path being a directory.
        """
        encoded = self._resolve(path)
        await self._expect_status(Remove(self._next(), encoded), path=encoded)

    async def rmdir(self, path: bytes | str) -> None:
        """Delete an **empty** directory.

        ``RMDIR`` is ``rmdir(2)`` and does not recurse. A directory with anything left in it
        is refused, which is what makes a bottom-up :meth:`rmtree` self-checking: if anything
        was missed, the parent's removal fails rather than the tree quietly half-disappearing.

        Raises:
            NoSuchFileError: If the path is not there.
            ServerError: For any other refusal, including the directory not being empty.
        """
        encoded = self._resolve(path)
        await self._expect_status(RmDir(self._next(), encoded), path=encoded)

    async def rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        """Rename with plain v3 ``RENAME``, which **cannot overwrite**.

        Measured against OpenSSH 10.0p2: renaming onto a path that already exists answers
        ``FAILURE`` and changes nothing. That is the specification's intent and it is why
        :meth:`posix_rename` exists. Servers disagree here -- some overwrite, some silently
        do nothing -- so a caller who needs replacement should ask for it rather than assume
        this does it.

        Raises:
            ServerError: If the server refuses, which includes the target already existing.
        """
        encoded = self._resolve(new_path)
        await self._expect_status(
            Rename(self._next(), self._resolve(old_path), encoded), path=encoded
        )

    async def posix_rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        """Rename with ``posix-rename@openssh.com``, which **does** overwrite, atomically.

        Sent whether or not the server advertised the extension, because advertisement is
        not the only evidence -- endpoints implement extensions they never list. A server
        that does not have it answers ``OP_UNSUPPORTED`` and stays perfectly usable, which is
        measured, not hoped: three unknown extension names in a row on a real ``sftp-server``
        each returned ``OP_UNSUPPORTED`` and the session survived all three.

        Raises:
            UnsupportedError: If the server does not implement the extension.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(new_path)
        request = PosixRename(self._next(), self._resolve(old_path), encoded)
        await self._expect_status(request.to_extended(), path=encoded)

    async def fsync(self, handle: bytes) -> None:
        """Flush an open handle to stable storage with ``fsync@openssh.com``.

        Must be sent **before** the ``CLOSE``, and that ordering is measured rather than
        assumed: the same handle after a close answers ``NO_SUCH_FILE``.

        This covers the file, not the directory entry. SFTP has no way to flush a directory,
        so a rename that publishes the file is never itself durable -- a limitation to state
        rather than to imply.

        Raises:
            UnsupportedError: If the server does not implement the extension.
            ServerError: For any other refusal, including a handle it does not recognise.
        """
        await self._expect_status(Fsync(self._next(), handle).to_extended())

    async def check_file(
        self,
        handle: bytes,
        *,
        algorithms: bytes = b"sha256,sha1,md5",
        start_offset: int = 0,
        length: int = 0,
        block_size: int = CHECK_FILE_BLOCK_SIZE,
    ) -> tuple[bytes, tuple[bytes, ...]]:
        """Ask the server to hash a file it already has, without moving the bytes again.

        Rung 1 of DESIGN.md 6's verification ladder, and the only rung that verifies
        *content* rather than byte count. **Most servers do not have it** -- OpenSSH answers
        ``OP_UNSUPPORTED`` under all three spellings, measured -- so a caller that needs
        verification everywhere still falls back to rung 3, a size check, and is told so
        rather than left to assume.

        The handle must have been opened for **reading**. Paramiko hashes by reading through
        it, so a WRITE-only handle -- the one an upload is holding -- answers ``FAILURE``
        with ``"Unable to hash file"``. Verifying something being uploaded therefore costs a
        second ``OPEN``, and cannot reuse the handle the bytes are going through.

        The digest count is not on the wire: the server sends one digest per block,
        concatenated, and how many that is follows from ``block_size`` and the digest size of
        whichever algorithm it picked. That size comes from ``hashlib`` here, so an algorithm
        this Python does not know is an error rather than a silently mis-split answer.

        Args:
            handle: An **open**, readable file handle, from :meth:`open`. Not a path --
                paramiko's spelling of this extension takes a handle, and answers
                ``BAD_MESSAGE`` for one it does not recognise.
            algorithms: Preference order as a name-list. The server picks the first it
                supports and names its choice in the reply.
            start_offset: First byte to hash.
            length: Bytes to hash, or ``0`` for the rest of the file.
            block_size: Bytes per digest. Defaults to
                :data:`~gantry_sftp.session.CHECK_FILE_BLOCK_SIZE`, which is 64 KiB and is the
                largest block paramiko answers correctly.

                ``0`` is the wire value for "one digest over the whole range" and it was this
                parameter's default until 0.9. **Do not send it**, and do not send anything
                above 64 KiB either: measured against paramiko, a block over 64 KiB returns
                digests of the wrong bytes, and once its runaway offsets pass EOF the server
                loops forever and answers nothing -- permanently, from our side as well as
                its own. ``0`` also fails outright below 256 bytes, because paramiko rewrites
                it to the range length and then rejects that as too small. The reasons are in
                :data:`~gantry_sftp.session.CHECK_FILE_BLOCK_SIZE`.

        Returns:
            The algorithm the server chose, and one digest per block.

        Raises:
            UnsupportedError: If the server does not implement the extension. Raised without a
                round trip once this server has answered that in this session -- verification
                asks per file, and re-asking a settled question is a round trip per file for an
                answer that cannot have changed.
            ServerError: If it refuses -- including ``FAILURE`` when it supports none of the
                algorithms offered, and ``BAD_MESSAGE`` for an unknown handle.
            ProtocolError: If the reply is not a well-formed check-file answer, or names an
                algorithm whose digest size does not divide the bytes it sent.
        """
        if self.refuses(EXTENSION_CHECK_FILE):
            raise UnsupportedError(
                f"this server has already answered OP_UNSUPPORTED for {EXTENSION_CHECK_FILE}",
                code=StatusCode.OP_UNSUPPORTED,
            )
        request = CheckFile(
            self._next(),
            handle,
            algorithms=algorithms,
            start_offset=start_offset,
            length=length,
            block_size=block_size,
        )
        reply = await self.request(request.to_extended())
        if isinstance(reply, Status) and reply.code is StatusCode.OP_UNSUPPORTED:
            # Recorded here rather than by catching the exception `_unexpected` raises two
            # lines down: the status is the definitive answer, and reading it where it arrives
            # keeps the recording next to the fact rather than next to the error handling.
            self._unsupported.add(EXTENSION_CHECK_FILE.encode("ascii"))
        if not isinstance(reply, ExtendedReplyPacket):
            raise _unexpected(reply, expected="EXTENDED_REPLY")

        parsed = CheckFileReply.from_reply(reply)
        try:
            digest_size = hashlib.new(parsed.algorithm.decode("ascii")).digest_size
        except (ValueError, UnicodeDecodeError) as unknown:
            raise ProtocolError(
                f"server hashed with {parsed.algorithm!r}, which this Python cannot size, "
                f"so its {len(parsed.digests)} digest bytes cannot be split",
                request_id=reply.request_id,
            ) from unknown
        try:
            return parsed.algorithm, parsed.split(digest_size)
        except ValueError as misaligned:
            raise ProtocolError(
                str(misaligned), request_id=reply.request_id, raw_frame=reply.data
            ) from misaligned

    # --- verification, rungs 1 and 2 of DESIGN.md 6 -----------------------------------------

    async def _hashes_agree(
        self, path: bytes, local_path: Path | str, *, start: int, length: int
    ) -> bool | None:
        """Rung 1 over one range: does the server's hash of it match the local file's?

        ``None`` is the third state and it is the *common* one -- the extension is absent, or
        advertised and then refused. It says the question could not be asked, which is a
        different fact from the answer being "no" and must never collapse into it: one is
        "unverified", the other is "corrupt".

        Costs its own ``OPEN`` and ``CLOSE``. ``check-file`` hashes by reading through the
        handle, so the WRITE-only one an upload is holding answers ``FAILURE`` -- measured
        against paramiko, which is the only server that implements this at all.

        An **empty range short-circuits and never reaches the wire**, because ``length=0`` on
        the wire means "to the end of the file" rather than "nothing". Sending it would hash
        the whole file and compare it against no local blocks at all.
        """
        if self.refuses(EXTENSION_CHECK_FILE):
            # Asked once per session, not once per file. Advertisement is not consulted here
            # any more (D-51): the endpoints most likely to under-advertise are the ones where
            # rung 1 is worth having, and the cost of finding out is one exchange for the whole
            # session -- against the OPEN and CLOSE below, which this pays per file anyway.
            return None
        if length == 0:
            return True
        handle = await self.open(path, OpenFlag.READ)
        try:
            algorithm, theirs = await self.check_file(
                handle, start_offset=start, length=length, block_size=CHECK_FILE_BLOCK_SIZE
            )
        except ServerError:
            # Advertised and unusable -- no algorithm in common, a handle it will not read,
            # a range it will not hash. Rung 1 is unavailable here, which is exactly what an
            # unadvertised extension also means, so the two collapse to the same answer.
            return None
        finally:
            # Quietly, and on the success path too: this handle exists only to ask a question,
            # and failing a transfer because the *probe's* CLOSE was refused would be
            # housekeeping replacing the diagnosis.
            await _close_quietly(self, handle)
        try:
            mine = await local_block_digests(local_path, algorithm, start=start, length=length)
        except ValueError:
            # The server hashed with something this Python cannot compute. There is nothing to
            # compare against, so the rung is unavailable rather than failed.
            return None
        return theirs == mine

    async def _reread_agrees(
        self, path: bytes, local_path: Path | str, *, start: int, length: int
    ) -> bool:
        """Rung 2 over one range: read the bytes back off the server and compare them.

        Works against **any** server, because it asks for nothing but ``READ``. That is the
        whole point of the rung: ``check-file`` is absent from nearly every endpoint in the
        field, so without this there is no content verification available at all off a
        paramiko-backed server.

        The bytes land in a temporary file and are compared from there, rather than being
        compared as they arrive. Two reasons, and the second is the load-bearing one: replies
        arrive out of order, so a streaming comparison would have to reassemble them, which is
        the scheduler this library already has exactly one of; and writing to a descriptor is
        what :func:`~gantry_sftp.session.download_handle` does, so the re-read runs at the
        pipelined speed of an ordinary download instead of one round trip per block. **The
        cost is temporary local disk equal to the range**, in ``$TMPDIR``, and that is stated
        rather than hidden -- it is the reason this rung is opt-in.
        """
        if length == 0:
            return True
        handle = await self.open(path, OpenFlag.READ)
        try:
            with tempfile.NamedTemporaryFile(prefix="gantry-verify-") as scratch:
                await download_handle(
                    self._dispatcher,
                    handle,
                    scratch.fileno(),
                    size=start + length,
                    read_length=self.sizes_for(handle).read_length,
                    depth=self._depth,
                    idle_timeout=self._idle_timeout,
                    remote_path=path,
                    start_offset=start,
                )
                return await ranges_equal(scratch.fileno(), local_path, start=start, length=length)
        finally:
            await _close_quietly(self, handle)

    async def _gate_resume(
        self, path: bytes, local_path: Path | str, adopted: int, verify: Verify
    ) -> ResumeCheck:
        """Gate the adopted prefix on a rung, which is what DESIGN.md 6 asks for in as many words.

        The offset was established from the size the server reported, and a size match proves
        only that the byte count agrees. What it cannot refuse is the case that matters most --
        a remote partial of the *right* length from the *wrong* source, which this completes,
        publishes, and passes rung 3 on, because the finished length is correct.

        **Rung 1 runs by default and rung 2 does not**, and the asymmetry is the decision.
        Rung 1 moves no bytes, so gating on it where it exists is free correctness and there
        is no case for making a caller ask. Rung 2 re-reads the whole adopted prefix, which is
        most of what resume set out to avoid; making *that* automatic would silently turn a
        bandwidth optimisation into a bandwidth cost. It is worth asking for on an asymmetric
        link, where reading back is cheaper than sending again -- but that is the caller's fact
        about their link, not ours.

        Raises:
            TransferError: If the adopted prefix is provably not a prefix of the local file.
                Before a single byte is sent, so nothing is published and the partial is left
                exactly as it was found -- it may be somebody else's, and it is the only
                evidence of what went wrong.
        """
        if adopted == 0:
            return ResumeCheck.SKIPPED
        if verify is Verify.REREAD:
            agreed: bool | None = await self._reread_agrees(
                path, local_path, start=0, length=adopted
            )
        else:
            agreed = await self._hashes_agree(path, local_path, start=0, length=adopted)
        if agreed is None:
            return ResumeCheck.UNAVAILABLE
        if not agreed:
            raise TransferError(
                f"cannot resume: the {adopted} bytes already at {path!r} are not a prefix of "
                f"{local_path} -- the partial is from a different source file or a different "
                f"run, and continuing would publish a file of the right length and the wrong "
                f"contents. Upload without resume=True to replace it",
                transferred=0,
                offset=adopted,
                remote_path=path,
                local_path=str(local_path),
            )
        return ResumeCheck.MATCHED

    async def _verify_content(
        self, path: bytes, local_path: Path | str, expected: int, verify: Verify
    ) -> ContentCheck:
        """Check what the server now holds against the local file, at the rung asked for.

        Args:
            path: What to read back. On the atomic path this is the **staging file**, checked
                before the rename, for the same reason rung 3 is: content that fails belongs
                to a file no consumer has ever been able to see.
            local_path: The source of truth.
            expected: Bytes the file should hold -- the local file's length, not what this run
                moved, which differs under ``resume``.
            verify: Which rung to try.

        Raises:
            TransferError: If the content disagrees.
        """
        if verify is Verify.SIZE:
            return ContentCheck.SKIPPED
        if verify is Verify.HASH:
            agreed = await self._hashes_agree(path, local_path, start=0, length=expected)
            if agreed is None:
                return ContentCheck.UNAVAILABLE
            reached = ContentCheck.HASHED
        else:
            agreed = await self._reread_agrees(path, local_path, start=0, length=expected)
            reached = ContentCheck.REREAD
        if not agreed:
            raise TransferError(
                f"{path!r} does not hold the contents of {local_path}: it is {expected} bytes "
                f"long, as it should be, and the bytes differ. The upload is corrupt rather "
                f"than short, which is the failure a size check cannot see",
                transferred=expected,
                offset=0,
                remote_path=path,
                local_path=str(local_path),
            )
        return reached

    async def get(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
        no_follow: bool = False,
        resume: bool = False,
        verify_size: bool = True,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
    ) -> int:
        """Download ``remote_path`` to ``local_path``.

        The size is taken from a STAT so the transfer is bounded, the progress callback has a
        total to report against, and -- as of 0.8 -- what arrived is checked against it. A
        server that declines to report one is fine: the download reads until EOF instead, at
        the cost of one extra round trip and of rung 3 being unavailable rather than passed.

        Args:
            remote_path: Path on the server.
            local_path: Local destination. Created, and truncated unless ``resume``.
            progress: Called with ``(transferred, total)`` as data arrives. On a resume the
                first call reports the offset it started from, not zero.
            depth: Requests in flight, overriding the session default.
            no_follow: Refuse to write through a local symlink at ``local_path``. Off by
                default, because pointing a download at a link you made yourself is a
                legitimate thing to do; on for every file in a recursive download, where a
                link in the destination tree is the last step of a path traversal.
            resume: Continue an interrupted download instead of starting over. Off by
                default -- see :meth:`put` for why resuming is always opt-in. This direction
                is the **stronger** of the two: the partial file is on the local disk, so its
                length is a fact rather than a report, and reads at an explicit offset are
                idempotent. What it still cannot know is whether those bytes came from *this*
                remote file, so a local partial longer than the remote file is refused rather
                than truncated, and a server that will not report a size makes the check
                impossible and the resume is refused too.
            verify_size: Refuse a download that ended short of the size the server reported --
                rung 3 of DESIGN.md 6's ladder. On by default and free: the ``STAT`` it
                compares against is the one ``get`` already makes.

                What it catches is the case an SFTP client is most likely to get wrong. A
                short ``DATA`` is legal, and an ``EOF`` arriving before the stated size is
                legal too, so the scheduler treats both as "stop issuing" rather than as an
                error -- correct for the scheduler, and on its own it means a truncating
                appliance or a file being rewritten under us produces a short local file and a
                *successful* call. Pass ``False`` only when reading something that is
                genuinely changing size underneath, and know that the result is then a
                snapshot of unknown completeness.

                It is a length comparison, not a hash: it catches truncation and nothing else.

            preserve_times: Stamp the local file with the remote file's atime and mtime instead
                of the time of the download. **Off by default**, matching ``scp -p`` and
                ``rsync -t``; see :meth:`put` for why the default is a decision rather than an
                omission.

                It costs no round trip -- the times come from the ``STAT`` ``get`` already
                makes -- and it is applied to the open descriptor after the last write, so a
                resumed transfer stamps the file once it is whole rather than while it is
                partial.

                **A server that reports no times leaves the local file stamped with now**, and
                says so nowhere: ``get`` returns a byte count, and widening that to a result
                object for one uncommon case is a worse trade than documenting it here. Read
                :attr:`~gantry_sftp.session.DirEntry.modified` or ``stat()`` first if you need
                to know whether there was a timestamp to preserve. v3 carries seconds, so
                sub-second precision is lost whatever this is set to.
            mode: Permission bits for the local file. ``None`` -- the default -- leaves it at
                the ``0o600`` this library creates every download with, so a downloaded file is
                private to you unless you say otherwise.

                An integer sets them exactly. :data:`~gantry_sftp.session.Mode.PRESERVE` carries
                the *remote* file's bits across, from the ``STAT`` ``get`` already makes, so it
                costs no round trip.

                Applied to the open **descriptor** after the last write, for both the reasons
                ``preserve_times`` is: a re-open of the path would hand a second chance to
                whatever ``no_follow`` refused, and a mode carrying setuid or setgid should not
                be on a file that is still partial. The creation mode stays ``0o600`` whatever
                this is set to, so widening happens only once the content is there.

                **Unlike the upload side, a server that reports no permissions is an error
                here.** ``Mode.PRESERVE`` with nothing to preserve would otherwise leave the
                file at ``0o600`` and report success, which looks identical to having preserved
                a ``0o600`` file -- so it raises instead. A terse server therefore fails on the
                first file rather than silently mirroring a tree at the wrong permissions.

        Returns:
            Bytes written **by this call**. On a resume that is the remainder, not the file's
            size, and on a resume of an already-complete file it is ``0``.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before anything is sent; see :mod:`._platform`.
            TypeError: If ``mode`` is neither an octal mode nor
                :data:`~gantry_sftp.session.Mode.PRESERVE`.
            ValueError: If ``mode`` is out of range.
            NoSuchFileError: If the remote path does not exist.
            ServerError: If the server refuses.
            TransferError: If the transfer fails partway, if ``resume`` cannot establish a
                safe offset, or if ``verify_size`` finds fewer bytes arrived than the server
                said there were.
        """
        require_local_io("get()")
        _check_local_path(local_path, method="get()")
        encoded = self._resolve(remote_path)
        requested_mode = resolve_mode(mode, caller="get()")
        with operation(session_logger, "get", remote=encoded, local=local_path) as record:
            attributes = await self.stat(encoded)
            local_bits = _download_mode(requested_mode, attributes, encoded)
            start = _download_resume_offset(local_path, attributes.size, encoded) if resume else 0
            # DESIGN.md 6's gate, on the direction that is usually assumed safe. The local
            # partial being *ours* makes its length trustworthy; it does not make its contents a
            # prefix of this remote file. A partial left by a previous run against a different
            # source is the same corruption as on the upload side, and it is caught here before
            # the first READ. `get` returns an `int`, so this can refuse but cannot report --
            # see D-38.
            _ = await self._gate_resume(encoded, local_path, start, Verify.SIZE)
            if resume and start == attributes.size:
                # Already complete: nothing to open and nothing to move. Deliberately *after*
                # the gate rather than before it -- this is the case that adopts the entire file
                # and returns success having verified nothing, which makes it the one most worth
                # gating, not the one to skip for a round trip.
                #
                # The mode is still applied, and skipping it here would be the silent wrong
                # answer this argument exists to prevent: the destination the caller named
                # exists, they said what permissions it should have, and "it was already there"
                # is not an answer to that. The partial was not necessarily left by this
                # library, so its mode is not necessarily the 0o600 a download creates.
                if local_bits is not None:
                    _chmod_local(local_path, local_bits, no_follow=no_follow)
                record["bytes"] = 0
                record["adopted"] = start
                return 0

            handle = await self.open(encoded, OpenFlag.READ)
            try:
                transferred = await self._download_into(
                    local_path,
                    handle,
                    size=attributes.size,
                    depth=depth,
                    progress=progress,
                    remote_path=encoded,
                    no_follow=no_follow,
                    start_offset=start,
                    times=attributes.times if preserve_times else None,
                    mode=local_bits,
                )
            except BaseException:
                # Closing is not optional: a leaked handle counts against max-open-handles and
                # is invisible from this side until the server starts refusing to open anything.
                # It must not replace the transfer's error with one about the close, though --
                # the first error is the diagnosis and the second is housekeeping.
                await _close_quietly(self, handle)
                raise
            await self.close(handle)
            record["bytes"] = transferred
            # Rung 3, and it costs no round trip: the STAT above is the one `get` already makes.
            # `start + transferred` rather than `transferred`, because a resume returns only the
            # remainder and comparing that against the whole file would fail every resume.
            if (
                verify_size
                and attributes.size is not None
                and start + transferred != attributes.size
            ):
                raise TransferError(
                    f"{encoded!r} is {attributes.size} bytes but the download ended after "
                    f"{start + transferred}; it was truncated or the file shrank underneath it",
                    transferred=start + transferred,
                    offset=start + transferred,
                    remote_path=encoded,
                    local_path=str(local_path),
                )
            return transferred

    async def _download_into(
        self,
        local_path: Path | str,
        handle: bytes,
        *,
        size: int | None,
        depth: int | None,
        progress: ProgressCallback | None,
        remote_path: bytes,
        no_follow: bool,
        start_offset: int = 0,
        times: Times | None = None,
        mode: int | None = None,
    ) -> int:
        """Open the local destination and let the scheduler fill it.

        The open lives here rather than in the scheduler because the flags are a safety
        decision: ``O_NOFOLLOW`` where a recursive download must not write through a link
        somebody planted in the destination tree, and mode 0600 so a file is never briefly
        world-readable while it is being written.

        ``O_TRUNC`` is dropped when resuming, and that is the whole of the local-side change:
        writes already go to explicit offsets, so keeping the first ``start_offset`` bytes is
        a matter of not deleting them.

        ``times`` and ``mode`` are applied to the **descriptor**, not to the path, and only once
        every write has landed. Both halves matter: a write updates mtime, so stamping earlier
        would be undone by the transfer itself; and re-opening the path to stamp it would hand a
        second chance to whatever the ``O_NOFOLLOW`` above exists to refuse. The creation mode
        stays ``0o600`` regardless of ``mode``, so the widening -- if it is a widening -- happens
        only once there is a complete file to widen.
        """
        flags = _LOCAL_WRITE_FLAGS if not start_offset else _LOCAL_RESUME_FLAGS
        fd = os.open(local_path, flags | (NO_FOLLOW if no_follow else 0), 0o600)
        try:
            transferred = await download_handle(
                self._dispatcher,
                handle,
                fd,
                size=size,
                read_length=self.sizes_for(handle).read_length,
                depth=self._depth if depth is None else depth,
                idle_timeout=self._idle_timeout,
                progress=progress,
                remote_path=remote_path,
                start_offset=start_offset,
            )
            if mode is not None:
                os.fchmod(fd, mode)
            if times is not None:
                os.utime(fd, (times.atime, times.mtime))
        finally:
            os.close(fd)
        return transferred

    # --- walking a tree ---------------------------------------------------------------------

    async def walk(
        self, path: bytes | str, *, max_depth: int | None = None
    ) -> AsyncGenerator[WalkEntry]:
        """Walk a remote tree, top down, yielding one entry per directory.

        Symlinks are **reported and never followed**. Following them needs loop detection,
        which needs a ``REALPATH`` per directory to defend against something only a hostile or
        misconfigured server does; it is deliberately absent rather than half-built, and the
        entries are surfaced so a caller can decide for themselves.

        **Nothing server-side is held between yields** -- each directory's handle is opened
        and closed inside a single :meth:`scandir` -- so stopping early, which is the natural
        way to use a walk, leaks nothing on the server. It is still an async generator, so
        close it rather than dropping it::

            async with aclosing(sftp.walk(b"/incoming")) as walker:
                async for entry in walker:
                    ...

        That is not decoration. Abandoning a suspended async generator leaves it to the
        garbage collector, and trio will not finalise one for you -- it surfaces as
        ``Exception ignored in: <async_generator object Session.walk>`` at some unrelated
        point later. Found by the trio lane, which is what the trio lane is for.

        Args:
            path: Root of the walk. Reported first, with an empty ``relative``.
            max_depth: How many levels below the root to descend, or ``None`` for no limit.
                ``0`` lists the root and nothing else. The bound exists because an infinite
                tree is something a hostile server can simply answer with.

        Yields:
            One :class:`~gantry_sftp.session.WalkEntry` per directory visited. Each carries
            one directory's classified entries, so peak memory is the largest directory in
            the tree rather than the tree -- a bound the walk cannot drop, because it cannot
            know where to descend until it has seen every name. :meth:`scandir` is the
            listing API with no such bound.

        Raises:
            NoSuchFileError: If the root does not exist. Note this is *also* what the server
                answers for a path that exists and is not a directory.
            CapabilityError: If ``path`` is relative and this server's default directory is
                not rooted at ``/``, so descending would build paths it does not mean.
            ServerError: If the server refuses a listing.
        """
        root = self._resolve(path)
        await self._require_rooted_paths(root, feature="walking a tree")
        pending: list[tuple[bytes, tuple[bytes, ...]]] = [(root, ())]
        while pending:
            directory, relative = pending.pop()
            entry = await self._walk_one(directory, relative, max_depth=max_depth)
            yield entry
            # Reversed so the traversal comes out in listing order rather than mirrored,
            # which matters only to whoever reads the output, which is everyone.
            pending.extend(
                (join_remote(directory, child.filename), (*relative, child.filename))
                for child in reversed(entry.directories)
            )

    async def _walk_one(
        self, directory: bytes, relative: tuple[bytes, ...], *, max_depth: int | None
    ) -> WalkEntry:
        """List one directory and sort its entries into descend / transfer / skip.

        Streamed through :meth:`scandir` rather than :meth:`listdir`: classifying as the
        entries arrive means the raw listing and the sorted one are never both in memory, and
        the ``LSTAT`` an unknown entry costs happens *inside* the open directory handle. That
        second part is only legal because a session multiplexes -- under the lock this layer
        used to hold, a stat between two READDIRs on the same connection was a deadlock.

        One directory is still materialised, and that is structural rather than an oversight:
        a top-down walk cannot know where to descend until it has seen every name.
        :meth:`scandir` is the API with no such bound.
        """
        directories: list[DirEntry] = []
        files: list[DirEntry] = []
        skipped: list[Skipped] = []
        at_limit = max_depth is not None and len(relative) >= max_depth

        async with self.scandir(directory) as children:
            async for child in children:
                path = join_remote(directory, child.filename)
                kind = await self._settle_kind(path, child)
                if kind is EntryKind.DIRECTORY and at_limit:
                    skipped.append(Skipped(path, child, SkipReason.TOO_DEEP))
                elif kind is EntryKind.DIRECTORY:
                    directories.append(child)
                elif kind is EntryKind.FILE:
                    files.append(child)
                else:
                    skipped.append(Skipped(path, child, _skip_reason(kind)))

        return WalkEntry(directory, relative, tuple(directories), tuple(files), tuple(skipped))

    async def _settle_kind(self, path: bytes, entry: DirEntry) -> EntryKind:
        """Resolve an entry whose kind the listing did not report.

        One ``LSTAT``, and only for the entries that need it -- so a server that sends
        attributes (all the common ones) pays nothing, and a server that does not gets a
        correct walk rather than a fast wrong one. ``LSTAT`` because a symlink must stay a
        symlink here; if that still settles nothing, the entry is skipped with a reason rather
        than guessed at.
        """
        if entry.kind is not EntryKind.UNKNOWN:
            return entry.kind
        try:
            return entry_kind(await self.lstat(path))
        except ServerError:
            return EntryKind.UNKNOWN

    async def glob(
        self,
        pattern: bytes | str,
        *,
        max_depth: int | None = None,
        case_sensitive: bool = True,
    ) -> AsyncGenerator[GlobMatch]:
        """Match a pattern against remote names, streaming each match as it is found.

        The one-line task a transfer script is usually written for::

            async with aclosing(sftp.glob("/incoming/*.csv")) as matches:
                async for match in matches:
                    await sftp.get(match.path, local_dir / os.fsdecode(match.name))

        **The dialect is `glob(3)`'s, because that is what `sftp(1)` uses** -- it globs
        client-side through POSIX ``glob(3)``, so this is the pattern language a user of the
        reference client already has. In particular ``*`` and ``?`` do not cross ``/``, and a
        leading period must be matched **explicitly**: ``*`` does not match ``.hidden``, which
        is what keeps a glob over a drop directory from picking up half-written staging files,
        including the ones this library's own atomic publish creates. ``[abc]``, ``[a-z]`` and
        ``[!a-z]`` (also spelled ``[^a-z]``) are supported, a backslash escapes the next
        character, and an unterminated ``[`` is a literal bracket. Brace expansion is **not**
        supported -- `sftp(1)` itself only applies it to ``ls`` and not to ``get`` -- and
        neither is ``~``, which is a server-side path expansion rather than a pattern.

        ``**`` matches zero or more directory levels. It is an **addition** to what `sftp(1)`
        understands, so a pattern using it is not portable back to that client; it is here
        because every ecosystem a caller arrives from has it. A trailing ``**`` means
        ``**/*``, and a trailing ``/`` restricts the match to directories, both as in a shell.

        **A name the server sends is validated before it becomes part of a path.** That is the
        reason to use this rather than a hand-rolled ``listdir`` plus match: the join happens
        here, once, against a component checked for separators and dot entries, so
        :attr:`GlobMatch.path` is a path this library built rather than one the server steered.
        A server that answers a listing with a name containing ``/`` gets an
        :class:`~gantry_sftp.exceptions.UnsafePathError` rather than a quietly wrong path.

        **Symlinks are matched but never descended into**, exactly as in :meth:`walk` and for
        the same reason: following them needs loop detection this library deliberately does not
        have. A symlink to a directory therefore matches ``/x/*`` and is not searched by
        ``/x/*/*``.

        Memory is one listing batch per pattern component, not one per directory in the tree,
        because nothing is accumulated -- matches are yielded as they are found. It is an async
        generator, so close it rather than dropping it, exactly as :meth:`walk` documents.

        Args:
            pattern: The pattern, absolute or relative. A pattern with no magic in it is a
                path, and yields one match if it exists and nothing if it does not.
            max_depth: How far ``**`` may descend below the point it appears, or ``None`` for
                no limit. Ignored by a pattern that does not use ``**``, since every other
                component consumes exactly one level. The bound exists because an infinite tree
                is something a hostile server can simply answer with.
            case_sensitive: Match case exactly. Pass ``False`` on a server whose filesystem
                folds case -- Windows-hosted, macOS, several appliances -- where a sensitive
                match will otherwise miss files the *server* considers the same name. Folding
                is ASCII-only: a remote name is bytes of unstated encoding, and folding a byte
                above 127 would be folding part of a character in an encoding nobody has
                established. This library cannot detect the server's behaviour, which is why
                this is an argument rather than a guess.

                **It folds the names being matched, not the directory you typed.** In
                ``/incoming/*.csv`` the ``/incoming`` is named to the server as written and
                ``*.csv`` is matched case-insensitively. Folding the directory part too would
                mean listing ``/`` to find out whether ``/Incoming`` is ``/incoming`` -- a
                round trip per level for a question the caller did not ask. A wholly literal
                pattern is still matched rather than named, so ``/x/report.csv`` does find
                ``REPORT.CSV``; accepting the argument and silently doing nothing was the bug
                the live test caught here.

        Yields:
            One :class:`~gantry_sftp.session.GlobMatch` per matching entry, in the order the
            server listed each directory -- which is not guaranteed to be sorted, and is not
            sorted here, because sorting means accumulating and accumulating is what
            :meth:`listdir` is for.

        Raises:
            UnsafePathError: If the server sends a name that cannot be one path component.
            CapabilityError: If ``pattern`` is relative and this server's default directory is
                not rooted at ``/``, so joining would build paths it does not mean.
            ServerError: If the server refuses a listing of a directory the pattern reached.
                A directory that does not exist is **not** an error -- it matches nothing, the
                same as a name that does not match. **This is a deliberate divergence from**
                ``glob(3)``, which passes no error function and therefore skips a directory it
                cannot read: silently, and indistinguishably from that directory being empty.
                A glob that answers "no matches" when it means "I was not allowed to look" is
                the shape of partial success this library refuses everywhere else, so an
                unreadable directory in the pattern's path is raised rather than swallowed.
        """
        encoded = self._resolve(pattern)
        await self._require_rooted_paths(encoded, feature="globbing")
        base, components, directories_only = split_pattern(encoded, case_sensitive=case_sensitive)
        if not components:
            literal = await self._glob_literal(base, directories_only=directories_only)
            if literal is not None:
                yield literal
            return
        async with aclosing(
            self._glob_in(
                base,
                components,
                max_depth=max_depth,
                case_sensitive=case_sensitive,
                directories_only=directories_only,
            )
        ) as found:
            async for match in found:
                yield match

    async def _glob_literal(self, path: bytes, *, directories_only: bool) -> GlobMatch | None:
        """Resolve a pattern that turned out to have no magic in it.

        One ``LSTAT``. ``LSTAT`` rather than ``STAT`` so a symlink stays a symlink, matching
        what the matching path does for every other component; and a missing path is ``None``
        rather than an error, because a pattern matching nothing is the ordinary case and a
        literal pattern is still a pattern.
        """
        try:
            attributes = await self.lstat(path)
        except (NoSuchFileError, ServerError):
            return None
        entry = DirEntry(filename=path.rpartition(b"/")[2], longname=b"", attrs=attributes)
        if directories_only and entry_kind(attributes) is not EntryKind.DIRECTORY:
            return None
        return GlobMatch(path, entry)

    async def _glob_in(
        self,
        directory: bytes,
        components: tuple[bytes, ...],
        *,
        max_depth: int | None,
        case_sensitive: bool,
        directories_only: bool,
    ) -> AsyncGenerator[GlobMatch]:
        """Match ``components`` against the contents of one directory, descending as needed.

        Recursive, and the recursion depth is the number of pattern components rather than the
        depth of the tree -- so it is bounded by something the caller wrote, not by something
        the server can answer with. One directory handle is open per level for the same reason.

        **Every inner generator is wrapped in ``aclosing``, including this module's own.** An
        ``async for`` does not close the generator it iterates, so a chain of them abandoned
        part-way -- by a caller that stopped early, or by
        :func:`~gantry_sftp.session.check_listed_name` refusing a name mid-listing -- leaves
        each link to the garbage collector. trio does not finalise those, and it surfaces as
        ``Exception ignored in: <async_generator object ...>`` at some unrelated later point.
        This is the idiom :meth:`walk` tells *callers* to use, applied to the callers inside
        this class; it was not theoretical, and the test that refuses a hostile name is what
        found it.
        """
        head, rest = components[0], components[1:]
        if head == RECURSIVE:
            async with aclosing(
                self._glob_recursive(
                    directory,
                    rest,
                    max_depth=max_depth,
                    case_sensitive=case_sensitive,
                    directories_only=directories_only,
                )
            ) as found:
                async for match in found:
                    yield match
            return

        async with aclosing(self._glob_listing(directory)) as entries:
            async for entry in entries:
                name = check_listed_name(entry.filename, directory=directory)
                if not match_component(head, name, case_sensitive=case_sensitive):
                    continue
                path = join_remote(directory, name)
                if rest:
                    async with aclosing(
                        self._glob_descend(
                            path,
                            entry,
                            rest,
                            max_depth=max_depth,
                            case_sensitive=case_sensitive,
                            directories_only=directories_only,
                        )
                    ) as deeper:
                        async for match in deeper:
                            yield match
                elif not directories_only or await self._is_glob_directory(path, entry):
                    yield GlobMatch(path, entry)

    async def _glob_listing(self, directory: bytes) -> AsyncGenerator[DirEntry]:
        """List one directory for a glob, where "not there" means "matches nothing".

        A pattern naming a directory that does not exist matches nothing, exactly as a name
        that does not match matches nothing -- ``/root/absent/*.csv`` is not an error, it is an
        empty result. **And the same is true of a path component that exists and is not a
        directory**, which falls out of the protocol rather than needing a second case:
        ``OPENDIR`` on a plain file answers ``NO_SUCH_FILE`` because ``ENOTDIR`` is remapped.

        Only that status is swallowed. ``PERMISSION_DENIED`` on a directory the pattern reached
        is raised, because a glob that answers "no matches" when it means "I was not allowed to
        look" is a partial success wearing a complete one's clothes -- which is the shape this
        library refuses everywhere else, and is where it diverges from ``glob(3)``.

        The ``NO_SUCH_FILE`` can only come from the ``OPENDIR`` this opens: a ``READDIR`` past
        the end answers ``EOF``, which :meth:`scandir` turns into the end of the iteration.
        """
        try:
            async with self.scandir(directory or b".") as entries:
                async for entry in entries:
                    yield entry
        except NoSuchFileError:
            return

    async def _glob_descend(
        self,
        path: bytes,
        entry: DirEntry,
        rest: tuple[bytes, ...],
        *,
        max_depth: int | None,
        case_sensitive: bool,
        directories_only: bool,
    ) -> AsyncGenerator[GlobMatch]:
        """Continue matching inside a matched entry, if it is a directory we may enter."""
        if not await self._is_glob_directory(path, entry):
            return
        async with aclosing(
            self._glob_in(
                path,
                rest,
                max_depth=max_depth,
                case_sensitive=case_sensitive,
                directories_only=directories_only,
            )
        ) as found:
            async for match in found:
                yield match

    async def _glob_recursive(
        self,
        directory: bytes,
        rest: tuple[bytes, ...],
        *,
        max_depth: int | None,
        case_sensitive: bool,
        directories_only: bool,
    ) -> AsyncGenerator[GlobMatch]:
        """Match the components after a ``**`` at this directory and at every descendant.

        Driven by :meth:`walk`, which is where the bounded traversal, the symlink policy and
        the ``max_depth`` refusal already live -- reimplementing the descent here would be a
        second place for those three decisions to be made differently.

        A trailing ``**`` is ``**/*``: it matches everything below its position, at every
        level, which is what a shell with ``globstar`` does and what the alternative -- a
        pattern that matches only directories, or only the root -- would surprise a caller
        with.
        """
        remaining = rest or (b"*",)
        async with aclosing(self.walk(directory or b".", max_depth=max_depth)) as walker:
            async for visited in walker:
                # `walk(b".")` reports `.` and `./sub`; a relative pattern's other components
                # join onto `b""` and produce `sub`. Left alone, one pattern would answer in
                # two spellings depending on whether it happened to contain `**`.
                reached = visited.path if directory else _strip_dot_prefix(visited.path)
                async with aclosing(
                    self._glob_in(
                        reached,
                        remaining,
                        max_depth=max_depth,
                        case_sensitive=case_sensitive,
                        directories_only=directories_only,
                    )
                ) as found:
                    async for match in found:
                        yield match

    async def _is_glob_directory(self, path: bytes, entry: DirEntry) -> bool:
        """Whether a matched entry is a directory this glob may look inside.

        :meth:`_settle_kind` rather than a bare attribute read, so an entry the server sent no
        permissions for costs one ``LSTAT`` instead of being guessed at -- and ``LSTAT`` is
        what keeps a symlink a symlink, which is what makes "matched but never descended into"
        true rather than aspirational.
        """
        return await self._settle_kind(path, entry) is EntryKind.DIRECTORY

    async def get_tree(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        max_depth: int | None = None,
        progress: ProgressCallback | None = None,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        resume: bool = False,
        concurrency: int = 1,
    ) -> TreeResult:
        """Download a remote tree into ``local_path``, refusing to escape it.

        **Every name the server supplies is validated before it becomes a path**, and the
        finished path is re-checked against the destination after symlinks are resolved. A
        server answering ``../../etc/cron.d/x`` gets an
        :class:`~gantry_sftp.exceptions.UnsafePathError` and nothing is written -- this is the
        zip-slip class, and it is a real and exploited pattern in file-transfer clients.

        **Transfers are sequential by default and overlap on request** (``concurrency=``, new
        in 0.10). The walk feeds a bounded pool rather than starting a task per file: a tree's
        size is the server's choice, so a task per entry is unbounded allocation driven by the
        peer. The producer blocks while every worker is busy, so peak memory is the worker
        count and not the tree.

        Args:
            remote_path: Remote directory to copy.
            local_path: Local destination. Created if absent, and everything is confined to it.
            max_depth: Levels below the root to descend, or ``None`` for no limit.
            progress: Called with ``(transferred, total)`` per file, so ``total`` resets for
                each one. A tree-wide total would need the whole walk up front.

                **Refused with ``concurrency`` above 1**, rather than passed through: the
                signature carries no file identity, so several workers reporting at once is one
                stream of counters that reset unpredictably and a bar built on it jumps
                backwards. Silently passing it would be a wrong answer with no symptom.
            preserve_times: Carry each file's remote timestamps onto its local copy, and each
                created directory's onto the local directory. Off by default -- see
                :meth:`put` for the argument. Costs no round trip either way: a file's times
                come from the ``STAT`` :meth:`get` already makes, and a directory's from the
                ``READDIR`` that listed its parent.

                **The destination directory you named is not stamped**, only directories this
                call creates inside it. Restamping a directory the caller already had would be
                a side effect on something they did not ask to have modified.
            mode: Permission bits for each downloaded file, as :meth:`get` describes them.
                ``None`` leaves every file at the ``0o600`` a download creates.

                **An integer applies to files only; only**
                :data:`~gantry_sftp.session.Mode.PRESERVE` **carries directories too.** A file
                mode applied to a directory is usually unusable -- ``0o600`` on a directory
                cannot be entered, so the tree would be complete and unreadable -- and inventing
                a second mapping from a file mode to a directory mode would be a guess. A
                caller who wants both names both: pass ``mode=`` for the files and
                :meth:`chmod` the directories.

                Directory modes are applied **after** the walk, for the reason the timestamps
                are: a directory created ``0o500`` cannot have files written into it, so its
                real mode has to wait until everything inside it has arrived. As with the
                timestamps, the destination directory you named is left alone.
            resume: Continue an interrupted tree instead of re-transferring it. Forwarded to
                :meth:`get` per file, so it inherits that method's guarantees exactly: an
                already-complete file costs one ``STAT`` and moves nothing, a partial one
                continues from its local length, and a local partial *longer* than the remote
                file is refused rather than truncated. The nine-gigabyte mirror interrupted at
                95% is the case this exists for.

                Off by default for the same reason it is on :meth:`get`: adopting bytes
                already on disk is a decision about whether those bytes came from this remote
                file, and only the caller knows whether the destination is theirs.
            concurrency: Files transferred at once. ``1`` -- the default -- keeps the exact
                sequential path this method has always had. Above 1 the walk feeds a bounded
                worker pool.

                What it buys is round trips, not bandwidth: a session is one channel with one
                2 MiB window (§5.1), so concurrency **reaches** the ceiling on a tree of small
                files rather than lifting it. It cannot be combined with ``progress`` -- see
                that argument -- and above 1 the order files are transferred in is not the
                walk's, so a failure part-way leaves an unpredictable subset transferred.

        Returns:
            Counts, bytes, and every entry that was skipped with the reason it was.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before the walk starts; see :mod:`._platform`.
            UnsafePathError: If a server-supplied name would escape the destination.
            DestinationCollisionError: If two remote names resolved to one local file. Raised
                at the end rather than on contact, so everything transferable still transfers;
                what is refused is only the write that would have destroyed an earlier one.
            NoSuchFileError: If the remote directory does not exist.
            ServerError: If the server refuses.
            TransferError: If a transfer fails partway.
        """
        require_local_io("get_tree()")
        _check_local_path(local_path, method="get_tree()")
        _check_tree_concurrency(concurrency, progress=progress, caller="get_tree")
        requested_mode = resolve_mode(mode, caller="get_tree()")
        destination = _ensure_directory(Path(local_path), parents=True)
        state = _DownloadState()

        with operation(
            session_logger, "get_tree", remote=self._resolve(remote_path), local=destination
        ) as record:

            async def transfer(item: _TreeDownload) -> None:
                # Appended rather than `state.transferred += ...`: augmented assignment loads
                # the target before evaluating the right-hand side, so with `concurrency > 1`
                # every worker finishing inside another's await adds to a value it read before
                # the others finished. The lost update understates the byte count, and it is
                # the same trap `download_many_concurrently` documents in `benchmarks/`.
                state.moved.append(
                    await self.get(
                        item.remote,
                        item.target,
                        progress=progress,
                        no_follow=True,
                        resume=resume,
                        preserve_times=preserve_times,
                        mode=requested_mode,
                    )
                )

            await for_each_bounded(
                self._walk_for_download(
                    remote_path,
                    destination=destination,
                    max_depth=max_depth,
                    preserve_times=preserve_times,
                    mode=requested_mode,
                    state=state,
                ),
                transfer,
                concurrency=concurrency,
            )

            _stamp_local_directories(state.directory_times)
            _chmod_local_directories(state.directory_modes)
            result = TreeResult(
                len(state.moved), state.directories, sum(state.moved), tuple(state.skipped)
            )
            record["files"] = result.files
            record["directories"] = result.directories
            record["bytes"] = result.transferred
            record["skipped"] = len(result.skipped)
            if state.collisions:
                raise _collision_error(state.collisions, destination, result)
            return result

    async def _walk_for_download(
        self,
        remote_path: bytes | str,
        *,
        destination: Path,
        max_depth: int | None,
        preserve_times: bool,
        mode: int | Mode | None,
        state: _DownloadState,
    ) -> AsyncGenerator[_TreeDownload]:
        """Walk the remote tree and hand out one settled file at a time.

        **Everything that touches the ledger happens here**, in one task and in walk order,
        before any transfer is queued -- which is what makes the collision check safe under
        concurrency. See :meth:`_claim_download` for why that matters and what it used to be
        resting on.

        Extracted from :meth:`get_tree` rather than nested inside it because the two together
        sit over the cognitive-complexity ceiling, and the split falls on a real seam: this
        decides *what* to transfer, the caller decides *how many at once*.

        ``aclosing`` on the walk, because the common exit is an exception -- a refused name, a
        failed worker -- and a suspended async generator that is merely dropped is left to the
        garbage collector, which trio will not finalise for it.
        """
        async with aclosing(self.walk(remote_path, max_depth=max_depth)) as walker:
            async for entry in walker:
                local_directory = _local_directory(destination, entry.relative)
                _settle_directory(
                    entry,
                    local_directory=local_directory,
                    preserve_times=preserve_times,
                    mode=mode,
                    state=state,
                )
                for child in entry.files:
                    item, collision = self._claim_download(
                        destination=destination,
                        local_directory=local_directory,
                        entry=entry,
                        child=child,
                        ledger=state.ledger,
                    )
                    if collision is not None:
                        state.collisions.append(collision)
                        state.skipped.append(
                            Skipped(collision.remote, child, SkipReason.DESTINATION_COLLISION)
                        )
                    elif item is not None:
                        yield item

    def _claim_download(
        self,
        *,
        destination: Path,
        local_directory: Path,
        entry: WalkEntry,
        child: DirEntry,
        ledger: DestinationLedger,
    ) -> tuple[_TreeDownload | None, PathCollision | None]:
        """Settle one walked file's destination, or report the collision that refuses it.

        Synchronous and called only from the producer, which is what makes the ledger safe
        under concurrency: every check and every claim happens in one task, in walk order,
        before any transfer is queued.

        **The destination file is created here, empty, before the check** -- and that is what
        makes the check mean anything. A collision is two remote names that the *filesystem*
        resolves to one file, which it can only be asked about once an inode exists; until
        0.10 the check ran before the transfer that created it, so it detected a collision
        only because the *previous* file's transfer had already finished. With workers running
        concurrently that stopped being true, and two colliding names would both have opened
        the same file with ``O_TRUNC``, the second destroying the first while ``get_tree``
        reported success. Creating it here restores the sequential guarantee exactly.

        ``O_CREAT`` without ``O_TRUNC``: an existing file keeps its bytes, so a ``resume=True``
        tree still finds the partial it left last run. ``O_NOFOLLOW`` because the containment
        check above resolves symlinks and this must not undo it.

        Returns:
            ``(item, None)`` to transfer, or ``(None, collision)`` to refuse. Never both.
        """
        target = check_contained(destination, local_child(local_directory, child.filename))
        remote = join_remote(entry.path, child.filename)
        _touch_destination(target)
        first = ledger.collides_with(target)
        if first is not None:
            return None, PathCollision(str(target), remote, first)
        ledger.claim(target, remote)
        return _TreeDownload(remote, target), None

    async def put(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        publish: Publish | None = None,
        resume: bool = False,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        verify: Verify = Verify.SIZE,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
        **legacy: bool | bytes | str | None,
    ) -> UploadResult:
        """Upload ``local_path`` to ``remote_path``, publishing it atomically by default.

        With ``atomic=True`` the bytes go to a hidden sibling staging file, are flushed, and
        are then renamed over the destination, so a consumer polling the directory sees the
        old file or the new one and never a partial one. DESIGN.md 6 calls that partial read
        the single most common bug in production SFTP integrations.

        **Every step of it is an optional extension**, so the result says which mechanism
        actually ran rather than implying the strongest one --
        :attr:`~gantry_sftp.session.UploadResult.mechanism` and
        :attr:`~gantry_sftp.session.UploadResult.durability`, with
        :attr:`~gantry_sftp.session.UploadResult.atomic` as the one-line answer. A caller who
        needs the real guarantee passes ``require_atomic=True`` and gets a
        :class:`~gantry_sftp.exceptions.CapabilityError` instead of a downgrade, because an
        ``atomic=True`` that quietly was not is worse than one that refused.

        Args:
            local_path: Local file to read.
            remote_path: Destination on the server.
            publish: How the bytes become visible at the destination --
                :class:`~gantry_sftp.session.Publish`, holding ``atomic``, ``fsync``,
                ``require_atomic``, ``require_fsync`` and ``staging_name``. Omit it for the
                default policy: stage, flush, rename, and accept a downgrade where the server
                cannot do one of those.

                Those five used to be arguments here and **still work under their old names**,
                with a :class:`DeprecationWarning` and unchanged meaning. Passing both spellings
                at once raises :exc:`TypeError` rather than picking one.
            resume: Continue an interrupted upload from the size the server reports, instead
                of sending the file again. **Off by default, and it is the weaker of the two
                directions.** A size match proves the byte *count* agrees and nothing else:
                the remote partial may be from a different run, a different source file, or a
                concurrent writer. See :meth:`get` for the download side, where the partial is
                on local disk and the claim is correspondingly stronger.

                **Where a content check is available it is applied to the adopted prefix, and
                a mismatch refuses before a byte is sent.** That is rung 1 automatically, since
                it moves nothing, and rung 2 only when ``verify=Verify.REREAD`` asks for it,
                since re-reading the prefix costs most of what resume was saving.
                :attr:`~gantry_sftp.session.UploadResult.resume_check` reports which happened,
                and says ``UNAVAILABLE`` rather than success where neither rung could run --
                which is the default case, because almost no server implements ``check-file``.
            verify: Which rung of DESIGN.md 6's verification ladder to reach for the *content*,
                as opposed to the length. ``Verify.SIZE`` is the default and adds nothing: the
                length is compared on every upload regardless, and a file of the right length
                with the wrong bytes passes it every time.

                ``Verify.HASH`` is rung 1 -- the server hashes what it holds and the digests
                are compared here. It moves no payload, and it is ``UNAVAILABLE`` on nearly
                every real endpoint, because OpenSSH answers ``OP_UNSUPPORTED`` to
                ``check-file`` under all three spellings.

                ``Verify.REREAD`` is rung 2 -- read the bytes back and compare them. It works
                against **any** server, and it costs a second transfer plus temporary local
                disk equal to the file, in ``$TMPDIR``. That is the price of the only content
                check most endpoints can offer, and it is opt-in for exactly that reason.

                Whichever ran is reported on
                :attr:`~gantry_sftp.session.UploadResult.content_check`; a *mismatch* raises
                rather than being reported, and on the atomic path it raises before the rename,
                so corrupt content never becomes the destination.

                It also interacts with ``atomic``, and not in the way it first looks. The
                obstacle is *not* that ``CREAT|EXCL`` refuses to adopt a leftover staging
                file -- it never meets one, because :func:`~gantry_sftp.session.staging_token`
                puts fresh randomness in the name on every call. The obstacle is that the
                previous run's staging file therefore has a name this run cannot know. So
                ``resume=True`` with ``atomic=True`` needs an explicit ``staging_name``, and
                raises ``ValueError`` without one rather than silently re-uploading.

                Making the staging name deterministic instead was considered and refused:
                that is exactly the collision ``EXCL`` exists to catch, and two publishers
                resuming into one predictable name would interleave into a single file. When
                ``staging_name`` is given, ``EXCL`` is dropped so the file *can* be adopted,
                which hands that collision risk to the caller who named it.
            preserve_times: Stamp the uploaded file with the local file's atime and mtime
                instead of the time of the upload. **Off by default**, and the default is a
                decision rather than an omission.

                Off matches ``scp -p`` and ``rsync -t``, so it is the behaviour a reader
                already expects. More importantly, on-by-default breaks a real deployment: the
                SFTP landing zone whose consumer collects "files modified since X" never picks
                up a file that arrived wearing last year's date. That failure is as silent as
                the one preserving fixes, and it points the other way.

                What it costs when you do want it: one ``FSETSTAT`` on the open handle, which
                pipelines with the writes rather than adding a round trip of its own. A server
                that refuses it does **not** fail the upload -- the bytes are the payload -- and
                :attr:`~gantry_sftp.session.UploadResult.times` says which happened. v3 carries
                seconds, so sub-second precision is lost whatever this is set to.
            mode: Permission bits for the published file. ``None`` -- the default -- leaves them
                to the server, which for OpenSSH means ``0666 & ~umask``: **world-readable under
                the usual umask**, because the ``OPEN`` carries no ``PERMISSIONS`` and
                ``process_open`` defaults to ``0666`` when it is absent.

                An integer sets them exactly. :data:`~gantry_sftp.session.Mode.PRESERVE` carries
                the local file's own bits across, which is what a mirror or a deploy wants.

                **The mode is on the file before anyone can open it by its published name.** It
                rides on the ``OPEN`` that creates the staging file -- narrowed to ``0o777``
                there, so a setuid file never exists half-written -- and the exact bits land via
                an ``FSETSTAT`` on the handle before the rename that publishes it. In place,
                where there is no rename, they land before the first byte is written. Neither
                order leaves a window in which the destination is more permissive than asked.

                **A server that refuses it fails the upload**, unlike ``preserve_times``, and
                the asymmetry is deliberate: a file published with the wrong timestamps is
                cosmetically wrong, while one published world-readable when ``0o600`` was asked
                for is the exact failure the argument exists to prevent, reported as success. On
                the atomic path the refusal arrives before the rename, so the staging file is
                discarded and the destination is never replaced.
                :attr:`~gantry_sftp.session.UploadResult.mode` reports what was set.
            progress: Called with ``(transferred, total)`` as writes are acknowledged. On a
                resume the first call reports the offset it started from, not zero.
            depth: Requests in flight, overriding the session default. Each one holds a full
                payload in memory, so this costs more here than on the download side.
            **legacy: The five publish arguments under their pre-:class:`Publish` names. Absorbed
                here rather than declared so the compatibility is real and the signature stays
                inside the project's argument ceiling. A name that is not one of the five raises
                :exc:`TypeError` naming them, because ``**`` means Python no longer rejects a
                misspelling for us and a silently ignored ``atmoic=False`` would publish
                non-atomically while the caller believed otherwise.

        Returns:
            What actually happened, including which publish mechanism was used and whether the
            length was confirmed.

            **The length is always confirmed**, which is rung 3 of DESIGN.md 6's ladder and
            has no flag. Under ``atomic`` the check runs against the *staging file, before the
            rename*, so a truncated upload never becomes the destination; in place it
            necessarily runs afterwards, because the destination is the file being written.
            It costs one ``STAT``, and the outcome is
            :attr:`~gantry_sftp.session.UploadResult.size_check` -- which says ``UNAVAILABLE``
            rather than success on a server that will not report a length. It catches
            truncation and nothing else; it is not a hash.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before anything is sent; see :mod:`._platform`.
            TypeError: If ``mode`` is neither an octal mode nor
                :data:`~gantry_sftp.session.Mode.PRESERVE`.
            ValueError: If a ``require_*`` flag contradicts the flag it strengthens, or if
                ``mode`` is out of range.
            CapabilityError: If a required guarantee is not available on this server.
            PermissionDeniedError: If the server will not create or write the file.
            ServerError: For any other refusal, including a refused ``mode``.
            TransferError: If the transfer fails partway, or if the published length
                disagrees with the local file's.
        """
        require_local_io("put()")
        _check_local_path(local_path, method="put()")
        target = self._resolve(remote_path)
        # Before the OPEN and before anything is sent, so a bad `mode=` costs no round trip and
        # no staging file. `PRESERVE` resolves here because this is where the local file is
        # named; every helper below takes a number or nothing.
        requested_mode = resolve_mode(mode, caller="put()")
        policy = publish_from_legacy(publish, legacy, caller="put")
        _check_publish_flags(
            atomic=policy.atomic,
            fsync=policy.fsync,
            require_atomic=policy.require_atomic,
            require_fsync=policy.require_fsync,
            resume=resume,
            staging_name=policy.staging_name,
        )
        # Refused here only when the answer is already *known* -- this server answered
        # OP_UNSUPPORTED earlier in the session. It used to refuse on advertisement, which is a
        # claim rather than an answer, and got it wrong on the endpoints this library is aimed
        # at: they advertise nothing and implement some of it (D-51). The unknown case is
        # settled by a probe on the staging handle, before any bytes move.
        if policy.require_fsync and self.refuses(EXTENSION_FSYNC):
            refusal = CapabilityError(
                f"require_fsync=True and this server has already answered OP_UNSUPPORTED for "
                f"{EXTENSION_FSYNC}, so nothing can promise the bytes reached stable storage",
                feature="durable upload",
                missing=(EXTENSION_FSYNC,),
                path=target,
            )
            refusal.add_note(self._server_note())
            raise refusal

        upload = _Upload(
            local_path=local_path,
            fsync=policy.fsync,
            require_fsync=policy.require_fsync,
            progress=progress,
            depth=depth,
            resume=resume,
            preserve_times=preserve_times,
            # Normalised rather than trusted: `Verify` is a `StrEnum`, so `verify="reread"`
            # reaches here as a plain `str` from anyone not running a type checker, and
            # `verify is Verify.REREAD` would then be False while `==` was True. A name that
            # is not a rung raises `ValueError` listing the three, which is what a silently
            # unverified upload would otherwise cost.
            verify=Verify(verify),
            mode=local_mode(local_path) if requested_mode is Mode.PRESERVE else requested_mode,
        )
        with operation(session_logger, "put", local=local_path, remote=target) as record:
            result = await self._publish_upload(upload, target, policy)
            record["bytes"] = result.transferred
            record["mechanism"] = result.mechanism.name
            return result

    async def _publish_upload(
        self, upload: _Upload, target: bytes, policy: Publish
    ) -> UploadResult:
        """Route one prepared upload to the in-place or the staged path.

        Split out of :meth:`put` so the operation record has a result to close over -- and only
        that far, because everything above it is argument handling that can raise before a byte
        moves, and a record for an upload that never started is noise.
        """
        if not policy.atomic:
            return await self._put_in_place(upload, target)
        staged_name = _optional_path(policy.staging_name)
        if staged_name is None or b"/" not in staged_name:
            # A staging name carrying a separator is used verbatim, so no parent is derived
            # from the target and there is nothing for a foreign namespace to break.
            await self._require_rooted_paths(target, feature="atomic publish")
        staged = staged_path(target, staging_token(), name=staged_name)
        return await self._put_atomically(
            upload, target, staged, require_atomic=policy.require_atomic
        )

    # --- put, in its two shapes ------------------------------------------------------------

    async def _confirm_size(self, path: bytes, expected: int) -> SizeCheck:
        """Rung 3 of DESIGN.md 6's ladder: does the remote file have the length it should?

        Args:
            path: Remote file to measure. On the atomic path this is the *staging* file, so
                the answer arrives before anything is published.
            expected: Length it should have -- the local file's size, not the byte count this
                run moved, which differs under ``resume``.

        Returns:
            Which of the two answerable outcomes happened. A *mismatch* is not among them.

        Raises:
            TransferError: If the server reports a length and it is not ``expected``. Raised
                rather than reported, because there is no useful thing a caller does with a
                published file of the wrong size, and returning it as a value is how a
                truncation gets logged and ignored.
        """
        # Three states, and the errored one decided explicitly. A server that refuses to STAT
        # the file it just accepted has told us nothing about its length -- it has not told us
        # the upload failed. Propagating would replace the diagnosis with an unrelated one on
        # the very path where the diagnosis matters most: `_publish`'s fallback needs the
        # rename's refusal to be the error the caller sees. This is the same call
        # `_confirmed_present` makes for the same reason, and the same one the `limits` probe
        # makes -- an optional measurement that fails degrades, it does not fail the operation
        # it was measuring.
        try:
            size = (await self.stat(path)).size
        except ServerError:
            return SizeCheck.UNAVAILABLE
        if size is None:
            # Not a failure either. Every server in the matrix reports one, so this branch
            # keeps a server we have not met from being refused over a tuning fact -- and it
            # reports unavailable rather than passed, because a check that could not run did
            # not run.
            return SizeCheck.UNAVAILABLE
        if size != expected:
            raise TransferError(
                f"uploaded {expected} bytes but {path!r} is {size} bytes on the server; "
                f"the transfer was truncated or the file changed underneath it",
                transferred=size,
                offset=size,
                remote_path=path,
            )
        return SizeCheck.MATCHED

    async def _put_in_place(self, upload: _Upload, target: bytes) -> UploadResult:
        """Write the destination directly, which a consumer can observe half-written.

        Nothing is cleaned up on failure, and that is not an oversight: the destination *is*
        the file being written, so there is nothing to remove that would not be deleting the
        caller's data. A failed in-place write leaves a truncated destination, which is what
        ``atomic=False`` means.

        Resuming here reads the destination's own length and continues into it. That is the
        one place the two flags cooperate without an extra name: in-place has already given
        up on the consumer never seeing a partial file, which is the same thing a resumable
        upload leaves lying around between runs.
        """
        start = await self._upload_resume_offset(upload, target)
        # Before the OPEN, so a refused prefix leaves the destination exactly as it was found.
        # The sibling refusals in `_upload_resume_offset` are at this same point for the same
        # reason, and a gate that first truncates what it is about to reject is not a gate.
        resume_check = await self._gate_resume(target, upload.local_path, start, upload.verify)
        handle = await self.open(
            target,
            _RESUME_FLAGS if upload.resume else _TRUNCATE_FLAGS,
            mode=create_bits(upload.mode),
        )
        if upload.mode is not None:
            # **Before the first byte, and only on this path.** `open(2)` applies its mode
            # argument to a file it *creates* and ignores it for one that already exists, so
            # writing in place over an existing destination would otherwise fill it while it
            # still wore whatever permissions it had before -- the window `mode=` exists to
            # close, in the one case where the OPEN cannot close it. The staged path has no
            # equivalent: its file is always new, `EXCL` proves it, and nothing can open the
            # destination by name until the rename.
            await self._set_mode(handle, upload.mode & CREATE_BITS, path=target)
        transferred, durability, times, published_mode = await self._fill_and_close(
            upload, handle, target, start_offset=start
        )
        # After the fact, necessarily: in place, the destination *is* the file being written,
        # so there is no earlier moment at which a short write could have been caught. That is
        # the same trade `atomic=False` already makes, and it is why the atomic path checks
        # the staging file instead.
        expected = _local_size(upload.local_path)
        size_check = await self._confirm_size(target, expected)
        content_check = await self._verify_content(
            target, upload.local_path, expected, upload.verify
        )
        return UploadResult(
            transferred,
            target,
            PublishMechanism.IN_PLACE,
            durability,
            size_check,
            times,
            content_check,
            resume_check,
            mode=published_mode,
        )

    async def _put_atomically(
        self, upload: _Upload, target: bytes, staged: bytes, *, require_atomic: bool
    ) -> UploadResult:
        """Stage, flush, then publish -- and clean the staging file up on any failure.

        ``require_atomic`` is answered from what the server *advertised*, deliberately, even
        though :meth:`_try_posix_rename` will attempt the extension regardless. A demand for a
        guarantee should not be answered by an experiment that costs a nine-gigabyte upload
        first. The opportunistic attempt belongs on the path where the fallback is acceptable;
        the strict path gets a cheap, deterministic answer, and the cost of that choice is a
        false refusal against a server that both under-advertises *and* has a destination
        already in place. Such a caller drops ``require_atomic`` and reads
        :attr:`~gantry_sftp.session.UploadResult.mechanism` instead.
        """
        if require_atomic and not self.supports(EXTENSION_POSIX_RENAME):
            await self._refuse_unpublishable(target)

        start = await self._upload_resume_offset(upload, staged)
        # Outside the try, with the sibling refusals, and that placement is the decision. A
        # rejected prefix inside it would reach `_discard` and delete the staging file -- which
        # is the caller's named file under `resume=`, is possibly another publisher's, and is
        # the only evidence of what went wrong. Refusing must not also destroy.
        resume_check = await self._gate_resume(staged, upload.local_path, start, upload.verify)
        handle = await self._open_staging_file(
            staged, target, resume=upload.resume, mode=create_bits(upload.mode)
        )
        try:
            if upload.require_fsync:
                # Inside the try, so a refusal takes the staging file with it. One round trip,
                # paid only by a caller who demanded durability against a server that did not
                # claim it -- and it saves that caller a whole upload when the answer is no.
                await self._probe_durability(handle, staged)
            # The times and the mode land on the *staging* handle, inside `_fill_and_close`,
            # which is the only place they can: `rename(2)` alters neither, so setting them
            # before the publish is what makes the published file carry them. Setting them
            # after the rename would need a second round trip to a path that a consumer can
            # already see, and would briefly publish a file with the wrong timestamps -- or,
            # for the mode, with permissions the caller explicitly asked it not to have.
            transferred, durability, times, published_mode = await self._fill_and_close(
                upload, handle, staged, start_offset=start
            )
            # Before the rename, deliberately. Checking the *destination* afterwards would
            # report a truncation that consumers can already see, which is the failure atomic
            # publish exists to prevent; checking the staging file means a short upload never
            # becomes the destination at all. A mismatch raises into the cleanup path below,
            # so the staging file goes and the destination is left alone.
            expected = _local_size(upload.local_path)
            size_check = await self._confirm_size(staged, expected)
            # Same moment and the same argument, one rung up: corrupt content that never
            # becomes the destination is a failed upload, and corrupt content that does is a
            # consumer reading it. This one is inside the try on purpose -- unlike the resume
            # gate, the staging file it would discard is one we just wrote and know is wrong.
            content_check = await self._verify_content(
                staged, upload.local_path, expected, upload.verify
            )
            mechanism = await self._publish(staged, target, require_atomic=require_atomic)
        except _StagedIsTheOnlyCopyError as lost:
            # Do NOT clean up. The destination has already been removed, or may have been, and
            # this file is the only copy of the data; deleting it here would turn a failure
            # someone can undo by hand into one nobody can. The original failure is re-raised
            # unchanged -- which matters when it is a cancellation, because converting one into
            # an ordinary exception would break the structured concurrency it belongs to.
            lost.failure.add_note(
                (
                    f"the destination {target!r} was removed and the rename that should have "
                    f"replaced it failed; the uploaded file is intact at {staged!r} and is now "
                    f"the only copy of it"
                )
                if lost.destination_removed
                else (
                    f"the destination {target!r} may already have been removed and was not "
                    f"replaced; the uploaded file is intact at {staged!r} and may now be the "
                    f"only copy of it"
                )
            )
            raise lost.failure from None
        except BaseException as error:
            await self._discard(staged, error)
            raise
        return UploadResult(
            transferred,
            target,
            mechanism,
            durability,
            size_check,
            times,
            content_check,
            resume_check,
            staged_at=staged,
            mode=published_mode,
        )

    async def _open_staging_file(
        self, staged: bytes, target: bytes, *, resume: bool, mode: int | None = None
    ) -> bytes:
        """Create the staging file, or fail in a way that names what to do about it.

        Kept separate because **a failed OPEN must not reach the cleanup path**: nothing of
        ours exists yet, and the most likely reason for `EXCL` to refuse is that somebody else
        is publishing to the same destination. Removing the file in the way would destroy the
        upload they are in the middle of.

        The note matters more than it looks. This is the first failure a user meets when the
        new default does not suit their server, and without it the message names a dot-file
        they never typed, in answer to a call about a path they did.

        ``resume`` drops ``EXCL``, because adopting the previous run's staging file is the
        entire point and ``EXCL`` exists to refuse exactly that. What is lost with it is the
        collision check -- so this only happens when the caller named the staging file
        themselves, which is enforced a layer up in :func:`_check_publish_flags`.

        ``mode`` is the *creation* mode, so the staging file is never briefly more permissive
        than the destination it is going to become. On a resume it does nothing, which is
        correct rather than a gap: the file already exists, ``open(2)`` ignores the mode for
        one that does, and the exact bits land on the handle before the publish either way.
        """
        try:
            return await self.open(staged, _RESUME_FLAGS if resume else _STAGE_FLAGS, mode=mode)
        except SFTPError as refusal:
            refusal.add_note(
                f"{staged!r} is the staging file for {target!r}. Publishing atomically needs "
                f"the right to create and rename a second name in that directory, and a name "
                f"that is not already taken -- pass atomic=False to write the destination "
                f"directly instead, or staging_name= to put the staging file elsewhere."
            )
            raise

    async def _probe_durability(self, handle: bytes, path: bytes) -> None:
        """Settle whether this server can flush, before the upload rather than after it.

        DESIGN.md 4.2 says capability detection is advertisement **plus an optional probe**,
        and this is the one probe the library sends. It is here because this is the one place
        a probe is both safe and free: an ``fsync`` on a staging file that was created moments
        ago and holds nothing is idempotent, touches nobody else's data, and answers the
        question a ``require_fsync`` caller asked for a definite answer to.

        **Only on the atomic path**, and the asymmetry is deliberate rather than an oversight.
        In place, the destination has already been opened -- truncated, usually -- by the time
        a handle exists, so refusing here would destroy the caller's file to report a
        capability that was never going to be used. There the honest moment is after the
        bytes: the data is written and complete, and only the guarantee is missing, which is
        what :meth:`_flush` raises.

        Skipped when the server advertises the extension: the claim is enough to proceed on,
        and a server that then answers ``OP_UNSUPPORTED`` is caught by :meth:`_flush` with the
        upload already discarded by the staging path's cleanup.

        Raises:
            CapabilityError: If the server did not perform it.
        """
        if self.supports(EXTENSION_FSYNC):
            return
        if not await self._attempt_extension(EXTENSION_FSYNC, lambda: self.fsync(handle)):
            refusal = CapabilityError(
                f"require_fsync=True and this server did not perform {EXTENSION_FSYNC} when "
                f"asked, so nothing can promise the bytes reached stable storage",
                feature="durable upload",
                missing=(EXTENSION_FSYNC,),
                path=path,
            )
            refusal.add_note(self._server_note())
            raise refusal

    async def _set_mode(self, handle: bytes, mode: int, *, path: bytes) -> None:
        """Set an open handle's permission bits, and fail the upload if the server will not.

        ``FSETSTAT`` carrying **only** ``PERMISSIONS``. One flag per call for the reason
        :meth:`chmod` gives: ``process_fsetstat`` applies the flags in sequence and reports a
        single status, so a multi-field call that fails has already applied part of itself and
        does not say which part.

        **No ``suppress`` here, unlike :meth:`_set_times` and :meth:`_set_directory_times`.**
        Those degrade because timestamps are metadata and the bytes are the payload. A mode is
        not in that category: the caller asked for it because the file must not be readable by
        whoever the default would let read it, and publishing anyway while reporting success is
        the failure ``mode=`` exists to prevent. On the atomic path this raises before the
        rename, so the staging file is discarded and the destination is left alone.
        """
        await self._expect_status(
            FSetStat(self._next(), handle, Attrs(permissions=mode)), path=path
        )

    async def _fill_and_close(
        self, upload: _Upload, handle: bytes, path: bytes, *, start_offset: int = 0
    ) -> tuple[int, Durability, TimePreservation, int | None]:
        """Push the file through an open handle, set its metadata, flush it, and close it.

        Everything except the write happens while the handle is still open, because that is
        the only time it can: ``fsync@openssh.com`` on a closed handle answers
        ``NO_SUCH_FILE``, and a handle is the only thing ``FSETSTAT`` can address.

        **Mode, then times, then the flush**, so the metadata the caller asked for is inside the
        durability barrier rather than outside it. Getting this order backwards would flush the
        bytes and then modify the inode, which is a narrower window than the one ``fsync``
        exists to close but is the same class of mistake.

        **The mode lands only now, after the content is complete**, and that is what the
        ``0o777`` narrowing on the creating ``OPEN`` is for: setuid, setgid and sticky are
        deliberately withheld until there is a finished file to apply them to, because a setuid
        file that exists half-written is privileged before it is finished. The ordinary bits are
        already correct from birth -- ``umask`` can only clear them, so a file created with the
        requested mode is never *more* permissive than what lands here.

        Both publish paths route through here, which is what makes one insertion cover them
        both -- and on the atomic path the handle is the *staging* file's, so the mode and the
        times are set before the rename that publishes it.
        """
        try:
            transferred = await upload_handle(
                self._dispatcher,
                handle,
                upload.local_path,
                write_length=self.sizes_for(handle).write_length,
                depth=self._depth if upload.depth is None else upload.depth,
                idle_timeout=self._idle_timeout,
                progress=upload.progress,
                remote_path=path,
                start_offset=start_offset,
            )
            if upload.mode is not None:
                await self._set_mode(handle, upload.mode, path=path)
            times = await self._set_times(upload, handle)
            durability = await self._flush(upload, handle)
        except BaseException:
            # Closing is not optional -- a leaked handle counts against max-open-handles and
            # is invisible from this side until the server refuses to open anything. But it
            # must not replace the error that got us here with one about the close.
            await _close_quietly(self, handle)
            raise
        await self.close(handle)
        return transferred, durability, times, upload.mode

    async def _upload_resume_offset(self, upload: _Upload, path: bytes) -> int:
        """How much of ``path`` the server already holds, if we are allowed to trust it.

        ``0`` for a fresh upload, and ``0`` when the file is not there yet -- which is the
        ordinary case for a first attempt with ``resume=True`` and is not an error.

        Two refusals, both in the direction that raises:

        * **The server will not report a size.** Then there is no offset to continue from and
          nothing to check, and guessing zero would silently re-send a nine-gigabyte file
          while the caller believes they asked not to.
        * **The remote is longer than the local file.** Whatever is there, it is not a prefix
          of what we are sending. Continuing would leave a file that is part one upload and
          part another, of the right length, and wrong.

        What it cannot check is the case that matters most: a remote partial of the *right*
        length from the *wrong* source. A size match proves the byte count agrees. That is
        why this is opt-in and documented as the weaker claim rather than presented as
        "resume support".
        """
        if not upload.resume:
            return 0
        local_size = _local_size(upload.local_path)
        try:
            attributes = await self.stat(path)
        except NoSuchFileError:
            return 0
        if attributes.size is None:
            raise TransferError(
                f"resume needs a size for {path!r} and this server did not report one, "
                f"so there is no offset to continue from and nothing to check it against",
                remote_path=path,
                local_path=str(upload.local_path),
            )
        if attributes.size > local_size:
            raise TransferError(
                f"cannot resume: {path!r} is {attributes.size} bytes on the server and the "
                f"local file is only {local_size}, so what is there is not a prefix of what "
                f"we are sending",
                transferred=0,
                offset=attributes.size,
                remote_path=path,
                local_path=str(upload.local_path),
            )
        return attributes.size

    async def _set_directory_times(self, entries: Sequence[tuple[bytes, Times]]) -> None:
        """Stamp remote directories, once every file inside them has been written.

        **After, necessarily.** Creating or renaming a file inside a directory updates *that
        directory's* mtime, so stamping one before its contents exist is undone by the very
        next transfer. Setting the times of a nested directory does **not** dirty its parent --
        that only tracks changes to its own entries -- so the order within this pass does not
        matter and none is imposed.

        ``SETSTAT`` on the path rather than ``FSETSTAT``, because no handle is held: a
        directory handle comes from ``OPENDIR`` and exists to be read, not written through.

        A refusal is swallowed per directory. The tree's *files* are the payload and they are
        already published; failing a completed upload because a server would not restamp a
        directory would be the wrong trade, and it is the same one :meth:`_set_times` makes for
        a file.
        """
        for path, times in entries:
            with suppress(ServerError):
                await self._expect_status(SetStat(self._next(), path, Attrs(times=times)))

    async def _set_directory_modes(self, entries: Sequence[tuple[bytes, int]]) -> None:
        """Set remote directory modes, once every file inside them has been written.

        **After, necessarily**, and for a stronger reason than :meth:`_set_directory_times`
        has: a directory created ``0o500`` would refuse the uploads that belong in it, so its
        source mode cannot be applied on the way down. Nothing here depends on order --
        changing a nested directory's mode does not touch its parent's.

        ``SETSTAT`` on the path rather than ``FSETSTAT``, because no handle is held: a directory
        handle comes from ``OPENDIR`` and exists to be read. One flag per call, for the reason
        :meth:`chmod` gives.

        A refusal is swallowed per directory, matching the timestamps and *not* matching a
        file's mode, which fails the upload. The difference is what the caller asked for: a file
        mode is the thing ``mode=`` controls, and a directory mode is carried along beside it.
        The tree's files are the payload and they are already published.
        """
        for path, mode in entries:
            with suppress(ServerError):
                await self._expect_status(
                    SetStat(self._next(), path, Attrs(permissions=mode & PERMISSION_BITS))
                )

    async def _set_times(self, upload: _Upload, handle: bytes) -> TimePreservation:
        """Stamp the open handle with the local file's times, or report why not.

        ``FSETSTAT`` rather than ``SETSTAT`` on the path, for two reasons. On the atomic path
        the file's name is the staging name and it is about to change, so addressing it by
        handle is addressing the thing rather than a name for it. And a path-based call between
        the write and the publish is a second chance for something else to swap what that name
        refers to.

        The times cannot ride along on the ``OPEN`` that created the handle. OpenSSH's
        ``process_open`` reads only ``PERMISSIONS`` out of that request's ATTRS, to pass as
        ``open(2)``'s mode, and ignores ``ACMODTIME`` entirely -- verified in ``sftp-server.c``,
        not assumed from the draft, which describes the field as settable there.
        """
        if not upload.preserve_times:
            return TimePreservation.SKIPPED
        attrs = Attrs(times=_local_times(upload.local_path))
        try:
            await self._expect_status(FSetStat(self._next(), handle, attrs))
        except ServerError:
            # Not fatal, and deliberately so: the bytes are the payload. A server that will
            # not set times has still stored the file correctly, and discarding a completed
            # upload over its metadata would be the wrong trade. The result says which
            # happened -- see TimePreservation.UNAVAILABLE.
            return TimePreservation.UNAVAILABLE
        return TimePreservation.PRESERVED

    async def _flush(self, upload: _Upload, handle: bytes) -> Durability:
        """Flush the handle, reporting what was possible rather than promising what was not.

        **Attempted rather than pre-judged on advertisement** (D-51). This used to return
        ``UNAVAILABLE`` without sending anything when ``fsync@openssh.com`` was not in the
        server's list -- which under-reports durability on exactly the population this library
        is aimed at, since the enterprise endpoints of DESIGN.md 7 advertise nothing and
        implement some of it. The cost of asking is one round trip, once per session: an
        ``OP_UNSUPPORTED`` is cached, so the second upload does not ask again.

        It is also what makes the policy consistent. ``posix-rename`` has always been
        attempted regardless of advertisement, on the argument that advertisement is a claim
        and the answer is a fact; there was never a reason for ``fsync`` to be judged
        differently, only an asymmetry nobody had noticed.
        """
        if not upload.fsync:
            return Durability.SKIPPED
        try:
            flushed = await self._attempt_extension(EXTENSION_FSYNC, lambda: self.fsync(handle))
        except ServerError:
            # Advertised and then refused. The bytes may still be in a cache, which the
            # result says; a caller who cannot accept that asked for require_fsync.
            if upload.require_fsync:
                raise
            return Durability.UNAVAILABLE
        if flushed:
            return Durability.FSYNCED
        if upload.require_fsync:
            # Two ways here, and neither is the atomic path's ordinary one. An in-place upload
            # never probes -- opening the destination has already truncated it, so there is no
            # cheap moment left to refuse at, and the honest report is that the bytes are
            # written and the guarantee is not. Or a server that *advertised* the extension
            # answered OP_UNSUPPORTED when asked, in which case the claim was false and the
            # staging file is about to be discarded. See `_probe_durability`.
            refusal = CapabilityError(
                f"require_fsync=True and this server did not perform {EXTENSION_FSYNC}, "
                f"so nothing can promise the bytes reached stable storage",
                feature="durable upload",
                missing=(EXTENSION_FSYNC,),
            )
            refusal.add_note(self._server_note())
            raise refusal
        return Durability.UNAVAILABLE

    # --- publishing --------------------------------------------------------------------------

    async def _publish(
        self, staged: bytes, target: bytes, *, require_atomic: bool
    ) -> PublishMechanism:
        """Move the staged file onto the destination by the strongest available mechanism."""
        if await self._try_posix_rename(staged, target):
            return PublishMechanism.POSIX_RENAME
        return await self._publish_by_plain_rename(staged, target, require_atomic=require_atomic)

    async def _try_posix_rename(self, staged: bytes, target: bytes) -> bool:
        """Attempt the one-step publish, answering whether this server could do it.

        **Sent whether or not the extension was advertised**, which looks like it contradicts
        DESIGN.md 4.2's rule that probes are only for read-only or idempotent extensions. It
        does not: this is not a probe. It is the operation we came here to perform, and the
        only question is whether the server answers ``OP_UNSUPPORTED`` instead of doing it.
        The rule exists to forbid *discovering* a capability by mutating something unrelated.

        This matters because endpoints under-advertise. A server that implements
        ``posix-rename`` and never lists it would otherwise be pushed onto the
        ``REMOVE``-then-``RENAME`` path -- a window with no file at all -- for no reason but
        its own reticence. The cost when the answer really is no is one round trip, and only
        the first time: ``OP_UNSUPPORTED`` is a definitive answer and is remembered for the
        session.

        A refusal that is *not* ``OP_UNSUPPORTED`` is treated differently depending on what
        the server claimed. If it advertised the extension, the refusal is about this
        operation -- permissions, a read-only directory -- and propagates, because falling
        through to a fallback that will fail the same way only obscures it. If it did not, we
        have no idea what we just asked of it, so the fallback stands. That answer is *not*
        cached: it was not definitive.
        """
        return await self._attempt_extension(
            EXTENSION_POSIX_RENAME, lambda: self.posix_rename(staged, target)
        )

    async def _publish_by_plain_rename(
        self, staged: bytes, target: bytes, *, require_atomic: bool
    ) -> PublishMechanism:
        """Plain ``RENAME``, and the documented non-atomic fallback when that will not do.

        A plain rename onto an absent target *is* atomic -- v3 RENAME cannot overwrite, so a
        success proves the destination appeared whole. The refusal is the interesting case,
        and ``FAILURE`` is a v3 catch-all that names nothing: it could be the target being in
        the way, or the directory being read-only. So the target is STATed before anything is
        deleted. Removing a good file on the strength of a guess about an error string is a
        worse outcome than the failure it was trying to recover from.

        Raises:
            _StagedIsTheOnlyCopyError: If the destination was removed and the rename after it
                failed, so that the caller knows not to clean the staging file up.
        """
        try:
            await self.rename(staged, target)
        except ServerError as refusal:
            if not await self._confirmed_present(target):
                raise
            if require_atomic:
                raise CapabilityError(
                    f"require_atomic=True but {target!r} already exists and this server does "
                    f"not advertise {EXTENSION_POSIX_RENAME}; replacing it would mean "
                    f"removing it first, leaving a window with no file at all",
                    feature="atomic publish",
                    missing=(EXTENSION_POSIX_RENAME,),
                    path=target,
                ) from refusal
        else:
            return PublishMechanism.RENAME

        # The window this rung is named for. Everything from the REMOVE onwards is unwindable
        # only by hand, so *any* failure from here must leave the staged file where it is --
        # including a failure of the REMOVE itself. That was the D-74 bug: this call sat
        # outside the guard, so a REMOVE the server performed but never acknowledged fell
        # through to the ordinary cleanup, which deleted the staging file with the destination
        # already gone. Both copies, and a message saying only that a request timed out.
        try:
            await self.remove(target)
        except BaseException as removal_failure:
            if isinstance(removal_failure, ServerError):
                # Definitive: the server answered and said no, so nothing was removed and the
                # destination is intact. The staging file is litter, not the only copy, and
                # leaving it behind would trade one silent failure for another.
                raise
            # Anything else -- a timeout, a lost connection, cancellation -- leaves us unable
            # to say whether the REMOVE ran, and very often it did: the request goes out, the
            # server performs it, and only the answer is missing. Assuming it ran costs a
            # staging file left behind; assuming it did not costs the only remaining copy.
            raise _StagedIsTheOnlyCopyError(
                removal_failure, destination_removed=False
            ) from removal_failure

        try:
            await self.rename(staged, target)
        except BaseException as second_failure:
            # `BaseException`, not `Exception`: anyio's cancellation is a `BaseException`, and
            # concurrent transfers are the whole point of this library -- a sibling task
            # failing inside a task group cancels this one, in the one window where the
            # staging file is the only copy of the data. The cancellation itself is re-raised
            # unchanged at the boundary, so structured concurrency is preserved; all this
            # suppresses is the cleanup.
            raise _StagedIsTheOnlyCopyError(
                second_failure, destination_removed=True
            ) from second_failure
        return PublishMechanism.REMOVE_RENAME

    async def _refuse_unpublishable(self, target: bytes) -> None:
        """Refuse before the transfer if the destination cannot be replaced atomically.

        Raises:
            CapabilityError: If the destination exists and there is no atomic overwrite.
        """
        if not await self._confirmed_present(target):
            return
        refusal = CapabilityError(
            f"require_atomic=True but {target!r} already exists and this server does not "
            f"advertise {EXTENSION_POSIX_RENAME}, so it cannot be replaced in one step",
            feature="atomic publish",
            missing=(EXTENSION_POSIX_RENAME,),
            path=target,
        )
        refusal.add_note(self._server_note())
        raise refusal

    async def _confirmed_present(self, path: bytes) -> bool:
        """Whether the server *positively reported* that the name ``path`` is taken.

        Three states, and the third one is why this is not called ``_exists``: the request can
        succeed, report ``NO_SUCH_FILE``, or fail for some third reason -- permissions, a
        server that refuses to stat that path, a ``FAILURE`` meaning who knows what. Only the
        first is evidence. Anything else answers ``False``, because this predicate's callers
        use it to decide whether to *delete* something, and "the server would not tell us" is
        not a licence to do that.

        ``LSTAT`` rather than ``STAT``, because the question is whether the *name* is in the
        way. A destination that is a symlink whose target has been rotated away is still a
        name a rename cannot land on, and ``STAT`` would call it absent -- leaving the publish
        to fail with the rename's uninformative ``FAILURE`` and no fallback attempted.
        """
        try:
            _ = await self.lstat(path)
        except ServerError:
            return False
        return True

    # --- trees, the other way ------------------------------------------------------------------

    async def put_tree(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        max_depth: int | None = None,
        publish: Publish | None = None,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        progress: ProgressCallback | None = None,
        resume: bool = False,
        concurrency: int = 1,
        **legacy: bool | bytes | str | None,
    ) -> TreeResult:
        """Upload a local tree into ``remote_path``, creating directories as it goes.

        The mirror of :meth:`get_tree`, with the untrusted input on the other side. Every name
        here comes from the local filesystem, so the zip-slip machinery a download needs does
        not apply -- but **symlinks are still not followed**, in this direction because a link
        in the tree pointing at ``/etc/shadow`` would otherwise copy it to the server under an
        innocent name. Links are reported in ``skipped``, exactly as the download reports them.

        **``atomic`` here is per file, not per tree, and that distinction is the honest part.**
        Each file is staged and renamed, so no consumer ever sees a partial *file*. Nothing
        makes the *tree* appear in one step: that would mean uploading to a staging directory
        and renaming it over the destination, and ``rename`` onto a non-empty directory fails
        on every POSIX server -- so it could only ever work for a destination that does not
        exist yet, which is not the mirroring case anyone has. A flag that delivered the
        guarantee sometimes would be worse than not having it. See DESIGN.md 6.

        Missing parents of ``remote_path`` are created. That costs one extra round trip only
        when a level is actually absent, because v3 answers a failed ``MKDIR`` with the
        catch-all ``FAILURE`` and "it is already there" has to be distinguished by looking.

        Transfers are sequential by default and overlap on request (``concurrency=``), through
        the same bounded pool :meth:`get_tree` uses and with the same back-pressure.

        Args:
            local_path: Local directory to copy. Followed if it is itself a symlink, because
                the caller named it; nothing inside it is.
            remote_path: Remote destination. Created, with any missing parents, if absent.
            max_depth: Levels below the root to descend, or ``None`` for no limit.
            publish: Publish policy applied to **every file** in the tree -- see :meth:`put`.
                ``staging_name`` is the one field that makes no sense here, since a tree has
                many files and one name cannot serve them all; it raises :exc:`ValueError`.
            preserve_times: Carry each local file's timestamps onto its remote copy, and each
                created directory's onto the remote directory. Off by default -- see
                :meth:`put` for the argument. Directories are stamped in a final pass, after
                every file has been written, because writing into a directory updates that
                directory's own mtime.

                **The root you named is not stamped**, only directories this call creates
                under it, matching :meth:`get_tree`.
            mode: Permission bits for each uploaded file, as :meth:`put` describes them.
                ``None`` leaves every file to the server, which for OpenSSH is
                ``0666 & ~umask`` -- so a tree delivered without this is a tree of
                world-readable files.

                **An integer applies to files only; only**
                :data:`~gantry_sftp.session.Mode.PRESERVE` **carries directories too**, in a
                final pass after every file has been written. Both halves match
                :meth:`get_tree`, and for the same two reasons: a file mode on a directory is
                usually unusable, and a directory created with its source's restrictive mode
                could not have been written into.

                A refused *file* mode fails the tree, as it fails a single :meth:`put`. A
                refused *directory* mode does not -- the files are the payload and they are
                already published.
            progress: Called with ``(transferred, total)`` per file, so ``total`` resets for
                each one. A tree-wide total would need the whole walk up front. **Refused with
                ``concurrency`` above 1** -- see :meth:`get_tree` for why.
            resume: Continue an interrupted tree instead of re-uploading it. Forwarded to
                :meth:`put` per file, so it inherits that method's gate: the adopted prefix is
                checked against a verification rung wherever one is available, because a remote
                partial of the right length from the wrong source is the failure resume exists
                to avoid.

                **Requires ``publish=Publish(atomic=False)``** and raises :exc:`ValueError`
                otherwise. Each file stages under a name generated fresh per call, so last
                run's partial cannot be found again -- and a ``staging_name`` cannot be fixed
                for a whole tree. Deriving one per file from the target would make it
                predictable for every file at once, which is what
                :func:`~gantry_sftp.session.staging_token` exists to prevent, so the
                combination is refused rather than silently downgraded. Resuming therefore
                means resuming the destination files themselves, and a consumer polling the
                directory can see a partial file while it happens.
            concurrency: Files uploaded at once. ``1`` -- the default -- keeps the exact
                sequential path this method has always had. See :meth:`get_tree` for what
                concurrency buys, what it cannot lift, and what it costs in ordering.
            **legacy: The publish arguments under their pre-:class:`Publish` names, as
                :meth:`put` accepts them and for the same reason.

        Returns:
            Counts, bytes, and every entry that was skipped with the reason it was.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before the walk starts; see :mod:`._platform`.
            UnsafePathError: If a local name could not be a remote path component.
            ValueError: If ``publish`` carries a ``staging_name``, which one tree's many files
                cannot share; if ``resume`` is asked for with atomic publishing, which has
                nothing findable to resume into; or if ``concurrency`` is below 1 or is above 1
                with a ``progress`` callback.
            OSError: If a local directory or file cannot be read.
            CapabilityError: If a required guarantee is not available on this server, or if
                ``remote_path`` is relative and this server's default directory is not rooted
                at ``/``, so building the tree beneath it would produce paths it does not mean.
            ServerError: If the server refuses a directory or a file.
            TransferError: If a transfer fails partway.
        """
        require_local_io("put_tree()")
        _check_local_path(local_path, method="put_tree()")
        _check_tree_concurrency(concurrency, progress=progress, caller="put_tree")
        root = self._resolve(remote_path)
        policy = publish_from_legacy(publish, legacy, caller="put_tree")
        if resume and policy.atomic:
            # The decision D-54 had to make, and it is `put`'s rule reaching a tree rather
            # than a new one. `put(resume=True, atomic=True)` needs an explicit staging_name,
            # because the generated one carries fresh randomness per call and last run's
            # partial cannot be found again -- and `put_tree` cannot take a staging_name at
            # all, since one name cannot serve a tree's many files. Deriving one per file from
            # the target was rejected rather than overlooked: a predictable staging name is
            # exactly what `staging_token` exists to avoid, and here it would be predictable
            # for every file in the tree at once, so two mirrors resuming into one destination
            # would interleave file by file. So tree resume means resuming the destination
            # itself, which is `atomic=False`, and the caller is told rather than downgraded.
            raise ValueError(
                "put_tree() cannot resume with atomic publishing: each file stages under a "
                "name generated fresh per call, so a previous run's partial cannot be found, "
                "and a staging_name cannot be fixed for a whole tree. Pass "
                "publish=Publish(atomic=False) to resume the destination files themselves, "
                "or drop resume=True to re-upload the tree atomically"
            )
        if policy.staging_name is not None:
            # Caught here rather than at the first file, because the failure is in the request
            # and not in any one transfer: every file in the tree would stage under the same
            # name, so the second would collide with the first and the report would blame a
            # file chosen by walk order.
            raise ValueError(
                "put_tree() cannot take a staging_name: it applies to every file in the tree, "
                "so they would all stage under one name and overwrite each other. Leave it "
                "unset to get a generated hidden sibling per file."
            )
        requested_mode = resolve_mode(mode, caller="put_tree()")
        await self._require_rooted_paths(root, feature="uploading a tree")
        await self._mkdir_parents(root, exist_ok=True)
        directories = 0
        moved: list[int] = []
        skipped: list[Skipped] = []

        # Collected during the walk and applied after it -- see _set_directory_times. Local
        # `stat` is free, so this costs nothing until the final pass.
        directory_times: list[tuple[bytes, Times]] = []
        # Same collection and the same final pass, plus one reason the timestamps do not have:
        # a directory created with a restrictive source mode could not have its files written
        # into it. Only `Mode.PRESERVE` fills this -- an integer `mode=` is a file mode.
        directory_modes: list[tuple[bytes, int]] = []

        with operation(session_logger, "put_tree", local=local_path, remote=root) as record:

            async def produce() -> AsyncGenerator[_TreeUpload]:
                """Create each directory, then hand out its files one at a time.

                The ``mkdir`` is awaited **here**, in the producer, before any of that
                directory's files are queued -- so a worker never writes into a directory that
                does not exist yet. `walk_local` is top-down, which is what makes that
                sufficient rather than merely usual.
                """
                nonlocal directories
                for entry in walk_local(Path(local_path), max_depth=max_depth):
                    remote_directory = _remote_directory(root, entry.relative)
                    if entry.relative:
                        await self.mkdir(remote_directory, exist_ok=True)
                        directories += 1
                        if preserve_times:
                            directory_times.append((remote_directory, _local_times(entry.path)))
                        if requested_mode is Mode.PRESERVE:
                            directory_modes.append((remote_directory, local_mode(entry.path)))
                    skipped.extend(entry.skipped)
                    for name in entry.files:
                        yield _TreeUpload(
                            entry.path / os.fsdecode(name),
                            join_remote(remote_directory, remote_component(name)),
                        )

            async def transfer(item: _TreeUpload) -> None:
                result = await self.put(
                    item.source,
                    item.remote,
                    publish=policy,
                    preserve_times=preserve_times,
                    mode=requested_mode,
                    progress=progress,
                    resume=resume,
                )
                # Appended rather than `transferred += ...`: see `get_tree` for the lost
                # update augmented assignment produces once several workers finish inside one
                # another's awaits.
                moved.append(result.transferred)

            await for_each_bounded(produce(), transfer, concurrency=concurrency)

            await self._set_directory_times(directory_times)
            await self._set_directory_modes(directory_modes)
            record["files"] = len(moved)
            record["directories"] = directories
            record["bytes"] = sum(moved)
            record["skipped"] = len(skipped)
            return TreeResult(len(moved), directories, sum(moved), tuple(skipped))

    async def _mkdir_parents(self, path: bytes, *, exist_ok: bool) -> None:
        """Create ``path`` and any missing ancestors, cheaply in the common case.

        One ``MKDIR`` when the directory is already there or its parent is, and a walk up the
        path only when a level is genuinely absent. The alternative -- creating every ancestor
        unconditionally -- is a round trip per level of the destination on every call, paid by
        every caller to help the one whose destination was three levels missing.

        ``exist_ok`` applies to ``path`` and **not** to what it recurses into: an ancestor that
        already exists is never an error, whatever the caller asked about the destination. That
        asymmetry is :func:`os.makedirs`'s and it is the reason this takes the argument at all
        rather than tolerating everything, which is what it did while :meth:`put_tree` was its
        only caller.
        """
        try:
            await self.mkdir(path, exist_ok=exist_ok)
        except ServerError:
            parent, _ = split_parent(path)
            stripped = parent.rstrip(b"/")
            if not stripped or stripped == path:
                raise
            await self._mkdir_parents(stripped, exist_ok=True)
            await self.mkdir(path, exist_ok=exist_ok)

    async def rmtree(self, path: bytes | str) -> TreeResult:
        """Remove a remote tree, including ``path`` itself.

        **Bottom-up, and it descends only into what the walk positively established is a
        directory.** That is the whole safety argument. :meth:`walk` classifies an entry from
        the attributes the listing carried, falls back to one ``LSTAT`` when the server sent
        none, and reports anything it still cannot settle rather than guessing -- so nothing
        here recurses into something that might be a file, and nothing renames or follows a
        symlink out of the tree.

        Everything that is *not* a directory -- files, symlinks, sockets, fifos, and entries
        whose kind the server would not report -- is removed with ``REMOVE``, which is
        ``unlink(2)``. That is deliberate and it is not the dangerous guess: unlink refuses a
        directory, so an unclassifiable entry either was not one and is gone, or was one and
        the server said so. Either way the blast radius is bounded by the tree the caller
        named, because a single ``REMOVE`` of a name inside it cannot reach outside it.

        There is no ``max_depth``. A depth-limited recursive delete leaves the deepest
        directories populated and their parents unremovable, so it would fail having done
        half the work.

        The walk is collected before anything is deleted, because children have to go before
        their parents. That holds one entry per name in memory -- the same bound
        :meth:`listdir` has, and for the same reason.

        Args:
            path: Remote directory to remove.

        Returns:
            How many files and directories were removed, and anything skipped. ``transferred``
            is always ``0``: nothing moves.

        Raises:
            NoSuchFileError: If the tree does not exist.
            ServerError: If the server refuses a removal -- including refusing to unlink an
                entry that turned out to be a directory, which names that exact path.
        """
        root = self._resolve(path)
        with operation(session_logger, "rmtree", remote=root) as record:
            entries: list[WalkEntry] = []
            async with aclosing(self.walk(root)) as walker:
                async for entry in walker:
                    entries.append(entry)

            files = directories = 0
            # Reversed: walk yields top down, and a directory cannot go before its contents.
            for entry in reversed(entries):
                for name in [child.filename for child in entry.files]:
                    await self.remove(join_remote(entry.path, name))
                    files += 1
                for skip in entry.skipped:
                    await self.remove(skip.path)
                    files += 1
                await self.rmdir(entry.path)
                directories += 1

            record["files"] = files
            record["directories"] = directories
            return TreeResult(files, directories, 0, ())

    # --- cleanup ------------------------------------------------------------------------------

    async def _discard(self, staged: bytes, error: BaseException) -> None:
        """Remove a staging file after a failure, and say so if that did not work.

        Shielded from cancellation, because a cancelled nine-gigabyte upload is precisely
        when a staging file gets left behind, and it is still bounded: every request carries
        ``request_timeout``, so a dead connection cannot make cleanup hang. That bound only
        means anything because the reader outlives the cancellation as well -- a ``REMOVE``
        whose reply nobody can route waits out the whole timeout and then leaves the file
        behind anyway. See :meth:`~gantry_sftp.session.Dispatcher.run`.

        The failure is recorded as a note on the original exception rather than swallowed or
        raised. Swallowing it means the caller never learns a file was left on the server;
        raising it means replacing the real error with a housekeeping one.
        """
        with anyio.CancelScope(shield=True):
            try:
                await self.remove(staged)
            except Exception as cleanup_failure:  # see _close_quietly on the breadth
                error.add_note(
                    f"the staging file {staged!r} was left on the server: "
                    f"removing it also failed ({cleanup_failure!r})"
                )


async def _close_quietly(session: Session, handle: bytes) -> None:
    """Close a handle during failure handling, shielded and without raising.

    ``Exception`` rather than a precise tuple on purpose. This runs while another error is
    already on its way up, and *anything* raised here replaces the diagnosis with a
    housekeeping complaint. Cancellation is not caught -- it derives from ``BaseException``
    -- and cannot arrive anyway inside the shield.

    The shield is half of what makes this work and the reader outliving the same cancellation
    is the other half: this sends a ``CLOSE`` and waits for its ``STATUS``, so with the reader
    gone it waits out ``request_timeout`` and, with no timeout set, forever. See
    :meth:`~gantry_sftp.session.Dispatcher.run`.

    A free function rather than a method because :class:`DirectoryScan` needs it too, and
    two copies of a cleanup path is how one of them ends up not fixed.
    """
    with anyio.CancelScope(shield=True), suppress(Exception):
        await session.close(handle)


def _ensure_directory(path: Path, *, parents: bool = False) -> Path:
    """Create a local directory if it is not there, from outside an async frame.

    A plain function because ASYNC240 is right: filesystem calls block the event loop. These
    are metadata operations on a local disk rather than a transfer, so they are not worth a
    thread -- but they are worth keeping out of the coroutine where the rule can see them.
    """
    path.mkdir(parents=parents, exist_ok=True)
    return path


def _remote_directory(root: bytes, relative: tuple[bytes, ...]) -> bytes:
    """Build the remote directory for a walked local position, validating every component.

    The counterpart of :func:`_local_directory`, and it checks each name for the same reason
    even though the names are ours: one component at a time is what catches a bug in our own
    joining, and a joined path has already lost which name was the problem.
    """
    remote = root
    for name in relative:
        remote = join_remote(remote, remote_component(name))
    return remote


def _local_directory(destination: Path, relative: tuple[bytes, ...]) -> Path:
    """Build the local directory for a walked position, validating every component.

    Each name is checked and joined one at a time rather than joined and then checked: a
    single ``..`` in the middle of an otherwise innocent chain is exactly the shape of the
    attack, and a joined path has already lost which component was the problem.
    """
    local = destination
    for name in relative:
        local = local_child(local, name)
    return check_contained(destination, local)


def _claim_directory(
    ledger: DestinationLedger, local_directory: Path, entry: WalkEntry
) -> tuple[PathCollision, ...]:
    """Claim a walked directory's local path, reporting a collision rather than merging.

    Directories collapse the same way files do -- ``Docs`` and ``docs`` are one directory on a
    case-folding filesystem -- and the consequence is quieter: the two remote directories'
    contents merge, so the *structure* is wrong even where no individual file is lost. Returns
    a one-element tuple on collision and an empty one otherwise, so the caller stays flat.
    """
    first = ledger.collides_with(local_directory)
    if first is None:
        ledger.claim(local_directory, entry.path)
        return ()
    return (PathCollision(str(local_directory), entry.path, first),)


def _collision_error(
    collisions: list[PathCollision], destination: Path, result: TreeResult
) -> DestinationCollisionError:
    """Build the error that ends a tree the destination could not keep the names apart in."""
    noun, verb = ("path", "was") if len(collisions) == 1 else ("paths", "were")
    return DestinationCollisionError(
        f"{len(collisions)} remote {noun} resolved onto a local file this download had "
        f"already written, and {verb} refused rather than overwriting it",
        collisions=tuple(collisions),
        destination=str(destination),
        files=result.files,
        transferred=result.transferred,
    )


def _skip_reason(kind: EntryKind) -> str:
    """Name why a walk passed over an entry of this kind."""
    if kind is EntryKind.SYMLINK:
        return SkipReason.SYMLINK
    if kind is EntryKind.UNKNOWN:
        return SkipReason.UNKNOWN_KIND
    return SkipReason.NOT_A_FILE


def _check_publish_flags(
    *,
    atomic: bool,
    fsync: bool,
    require_atomic: bool,
    require_fsync: bool,
    resume: bool = False,
    staging_name: bytes | str | None = None,
) -> None:
    """Refuse a combination of flags that contradict each other.

    ``require_atomic=True, atomic=False`` is not a policy this can satisfy by picking one --
    it is two opposite instructions, and honouring either silently would be guessing about
    the guarantee the caller cares most about.

    ``resume=True, atomic=True`` with no ``staging_name`` is the same shape for a subtler
    reason. The default staging name carries fresh randomness per call, so the file a
    previous run left behind has a name this run cannot reconstruct: there is nothing to
    resume *into*. Falling back to a full upload would be the silent downgrade this library
    refuses everywhere else, so it is refused here and the message names the fix.

    Deriving the staging name from the target instead -- making it findable -- was rejected
    rather than overlooked: a predictable staging name is what
    :func:`~gantry_sftp.session.staging_token` exists to avoid, and two publishers resuming
    into one would interleave into a single file.

    Raises:
        ValueError: If a ``require_*`` flag strengthens a flag that is switched off, or if
            ``resume`` is asked for where nothing could be resumed.
    """
    if require_atomic and not atomic:
        raise ValueError("require_atomic=True contradicts atomic=False")
    if require_fsync and not fsync:
        raise ValueError("require_fsync=True contradicts fsync=False")
    if resume and atomic and staging_name is None:
        raise ValueError(
            "resume=True needs staging_name= when atomic=True: the default staging file is "
            "named with fresh randomness each call, so a previous run's partial upload "
            "cannot be found. Pass staging_name= to fix the name, or atomic=False to resume "
            "the destination itself"
        )


def _local_size(path: Path | str) -> int:
    """Size of a local file, or ``0`` if it is not there.

    A plain function because ASYNC240 is right that a filesystem call blocks the event loop,
    and a single ``stat`` is not worth a thread. Absent is ``0`` rather than an error: a
    first ``resume=True`` attempt with no local file is a caller mistake the ``open`` will
    report far more clearly than this could.
    """
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


def _local_times(path: Path | str) -> Times:
    """A local file's atime and mtime, truncated to the seconds filexfer v3 can carry.

    ``int()`` rather than ``round()``: rounding a timestamp *up* invents a modification that
    has not happened yet, and a file dated one second into the future is exactly what makes a
    "modified since" sweep behave differently between two runs of the same upload.
    """
    stat_result = Path(path).stat()
    return Times(atime=int(stat_result.st_atime), mtime=int(stat_result.st_mtime))


def _download_mode(mode: int | Mode | None, attributes: Attrs, remote_path: bytes) -> int | None:
    """What permission bits a download should end up with, or ``None`` to leave 0o600 alone.

    Raises:
        TransferError: If :data:`Mode.PRESERVE` was asked for and the server reported no
            permissions at all. **Absent is not zero and it is not a default**: v3 ATTRS makes
            every field optional and a server is entitled to send none of them, so there is
            genuinely nothing to preserve. Leaving the file at its 0o600 creation mode and
            returning success would be indistinguishable from having preserved a 0o600 file,
            which is the shape of wrong answer this whole argument exists to remove. Raised
            before the first ``READ``, so a terse server costs no transfer.
    """
    if mode is None:
        return None
    if mode is not Mode.PRESERVE:
        return mode
    if attributes.permissions is None:
        raise TransferError(
            f"mode=Mode.PRESERVE was asked for but the server sent no permissions for "
            f"{remote_path!r}, so there is nothing to preserve; pass an explicit mode= or "
            f"leave it unset to keep the 0o600 a download creates",
            transferred=0,
            offset=0,
            remote_path=remote_path,
        )
    return attributes.permissions & PERMISSION_BITS


def _chmod_local(path: Path | str, mode: int, *, no_follow: bool) -> None:
    """Apply a mode to a local file that is already complete, without following a link to it.

    Used only where there is no open descriptor to hand -- a resumed download that finds the
    file already whole. Everywhere else the mode goes onto the descriptor the transfer is
    already holding, which is stronger; here the ``O_NOFOLLOW`` is re-applied on a fresh
    read-only open so that a symlink swapped in since the containment check still cannot
    redirect the ``chmod`` onto whatever it points at.
    """
    fd = os.open(path, os.O_RDONLY | (NO_FOLLOW if no_follow else 0))
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _stamp_local_directories(entries: Sequence[tuple[Path, Times]]) -> None:
    """Apply remote directory times locally, once everything inside them has been written.

    **After, necessarily**, for the reason :meth:`Session._set_directory_times` gives: writing
    a file into a directory updates that directory's mtime, so stamping it earlier is undone
    by the next transfer. Touching a nested directory does not dirty its parent, so no order is
    imposed within this pass.

    A failure is swallowed per directory. The files are the payload and they have all arrived;
    a directory whose timestamp could not be set -- because the destination is read-only to us,
    or on a filesystem that will not take one -- is not a reason to fail a completed download.
    """
    for path, times in entries:
        with suppress(OSError):
            os.utime(path, (times.atime, times.mtime))


def _chmod_local_directories(entries: Sequence[tuple[Path, int]]) -> None:
    """Apply remote directory modes locally, once everything inside them has been written.

    **After, necessarily**, and for a stronger reason than the timestamps have: a directory
    created ``0o500`` cannot have a file written into it, so applying a source mode on the way
    down would fail the transfers underneath it. Deepest-last is not required either -- changing
    a nested directory's mode does not affect its parent's -- so no order is imposed.

    A failure is swallowed per directory, for the reason :func:`_stamp_local_directories` gives:
    the files are the payload and they have all arrived. That is the opposite of what a *file*'s
    mode does, which fails the transfer, and the difference is that a file's mode is what the
    caller asked to control while a directory's is carried along with it.
    """
    for path, mode in entries:
        with suppress(OSError):
            path.chmod(mode)


def _download_resume_offset(local_path: Path | str, size: int | None, remote_path: bytes) -> int:
    """Where a resumed download should continue from.

    The mirror of :meth:`Session._upload_resume_offset`, and the *stronger* of the two: the
    partial is on local disk, so its length is a fact rather than a report, and a read at an
    explicit offset is idempotent. The refusals are the same two, for the same reasons -- no
    remote size means nothing to check against, and a local partial longer than the remote
    file is not a prefix of it.

    Raises:
        TransferError: If no safe offset can be established.
    """
    have = _local_size(local_path)
    if size is None:
        raise TransferError(
            f"resume needs a size for {remote_path!r} and this server did not report one, "
            f"so a local partial cannot be checked against it",
            remote_path=remote_path,
            local_path=str(local_path),
        )
    if have > size:
        raise TransferError(
            f"cannot resume: {local_path} already holds {have} bytes and {remote_path!r} is "
            f"only {size}, so what is on disk is not a prefix of what is being downloaded",
            transferred=0,
            offset=have,
            remote_path=remote_path,
            local_path=str(local_path),
        )
    return have


def _check_local_path(local_path: object, *, method: str) -> None:
    """Refuse a local path that is not a ``Path`` or a ``str``, naming the argument (D-96).

    **The mirror of the remote-path rule, and the two disagreed before this existed.** A
    transfer takes one path of each kind, and passing ``bytes`` for the local one used to
    reach four different endings: ``get`` accepted it and wrote the file, because POSIX
    ``open`` takes bytes; ``put``, ``get_tree`` and ``put_tree`` raised ``pathlib``'s own
    ``TypeError``, which names neither the method nor the argument. Accepted-here and
    refused-there is the per-site decision nobody re-reads, so it is decided once: the
    declared type is the accepted type.

    ``bytes`` is called out specifically, since it is not a typo -- it is the *remote* rule
    applied one argument over, and the fix is to say which side is which rather than which
    type is wrong.

    Raises:
        TypeError: If ``local_path`` is neither ``Path`` nor ``str``.
    """
    if isinstance(local_path, Path | str):
        return
    kind = type(local_path).__name__
    detail = (
        "bytes is the rule for the *remote* path, which goes on the wire; a local path is "
        "opened by this process"
        if isinstance(local_path, bytes)
        else "it is opened by this process, so it has to be something pathlib accepts"
    )
    raise TypeError(f"{method} needs a Path or str for its local path, not {kind}: {detail}")


def _optional_path(path: bytes | str | None) -> bytes | None:
    """Encode a path that may be absent, keeping ``None`` distinct from an empty name."""
    return None if path is None else _encode_path(path)


def _encode_path(path: bytes | str) -> bytes:
    """Paths go on the wire as bytes.

    ``str`` is encoded with ``surrogateescape`` so a name that came back from the server as
    invalid UTF-8, was decoded leniently, and is now being sent again survives the round
    trip unchanged. Server-supplied names are frequently not valid UTF-8, and a client that
    cannot re-send what it was just given cannot operate on those files at all.

    Anything else is refused here rather than by whatever it fails inside (D-96).

    Raises:
        TypeError: If ``path`` is neither ``bytes`` nor ``str``.
    """
    if isinstance(path, bytes | str):
        return path if isinstance(path, bytes) else path.encode("utf-8", "surrogateescape")
    raise TypeError(_wrong_path_type(path))


def _wrong_path_type(path: object) -> str:
    r"""Explain a remote path that is not ``bytes`` or ``str``, and say why not a ``Path``.

    **A ``Path`` gets its own sentence because it is the type callers actually pass**, and
    because "unsupported" would be the wrong reason. ``pathlib`` is a type whose job is to
    normalise, and a remote name has to survive byte for byte: ``PurePosixPath`` drops a
    trailing slash on construction, and on Windows ``str(Path("/incoming/x"))`` is
    ``'\\incoming\\x'`` -- which the server does not refuse, because a backslash is a legal
    character in a POSIX filename. It would create a file *named* ``\\incoming\\x``. So a
    silent ``os.fsencode`` here would be a data-placement bug wearing a convenience's clothes.

    The asymmetry is named too. ``get``/``put`` take a ``Path`` for their **local** side, so a
    caller who has just written one is not confused about ``pathlib`` -- they are one argument
    out on a rule nothing had ever stated.
    """
    kind = type(path).__name__
    if isinstance(path, PurePath):
        return (
            f"a remote path must be bytes or str, not {kind}: pathlib normalises and a remote "
            f"name has to survive byte for byte -- a trailing slash goes on construction, and "
            f"str(Path(...)) on Windows renders separators as backslashes, which a server takes "
            f"as part of the filename rather than as separators. Pass str(path) if it really is "
            f"posix-shaped, or the bytes the server gave you. The local side of get()/put() is "
            f"the argument that takes a Path"
        )
    return (
        f"a remote path must be bytes or str, not {kind}: it goes on the wire as bytes, and "
        f"str is encoded with surrogateescape so a name the server sent can be sent back "
        f"unchanged"
    )


def _strip_dot_prefix(path: bytes) -> bytes:
    """Drop the ``./`` a walk rooted at ``.`` prefixes onto every path below it.

    Only the prefix a walk this library started is responsible for -- a server that genuinely
    returns a name beginning with a dot keeps it, because ``.hidden`` is an ordinary filename
    and ``..`` never reaches here (a listing excludes it and
    :func:`~gantry_sftp.session.check_listed_name` refuses it).
    """
    if path == b".":
        return b""
    return path[2:] if path.startswith(b"./") else path


@dataclass(slots=True)
class _DownloadState:
    """What a tree download accumulates while its producer walks and its workers transfer.

    A mutable object rather than a pile of ``nonlocal`` bindings, so the producer can be a
    method instead of a closure -- which is what keeps :meth:`Session.get_tree` under the
    cognitive-complexity ceiling without an exemption.

    Everything here except ``moved`` is written **only by the producer**, which runs in one
    task; ``moved`` is appended to by the workers, and appending is the point -- see
    :meth:`Session.get_tree`.
    """

    ledger: DestinationLedger = field(default_factory=DestinationLedger)
    directories: int = 0
    moved: list[int] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    collisions: list[PathCollision] = field(default_factory=list)
    # Collected during the walk and applied after it -- see _stamp_local_directories. A
    # directory's times come from its *parent's* listing, which READDIR already returned, so
    # this costs no round trip.
    directory_times: list[tuple[Path, Times]] = field(default_factory=list)
    # Same collection, same listing, same after-the-walk pass -- and for a second reason on top
    # of the timestamps': a directory created 0o500 cannot have files written into it, so its
    # real mode has to wait until everything inside it has arrived.
    directory_modes: list[tuple[Path, int]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _TreeDownload:
    """One file a tree download has settled a destination for, waiting to be transferred."""

    remote: bytes
    target: Path


@dataclass(frozen=True, slots=True)
class _TreeUpload:
    """One file a tree upload has settled a destination for, waiting to be transferred."""

    source: Path
    remote: bytes


def _settle_directory(
    entry: WalkEntry,
    *,
    local_directory: Path,
    preserve_times: bool,
    mode: int | Mode | None,
    state: _DownloadState,
) -> None:
    """Create one walked directory locally and record what it contributes to the report.

    The root is deliberately not counted, stamped or chmodded: the caller named it, so creating
    it is :meth:`Session.get_tree`'s own ``_ensure_directory`` and modifying it would be a side
    effect on something they did not ask to have modified.

    **Only ``Mode.PRESERVE`` reaches directories.** An explicit integer is a *file* mode, and
    applying it here would make ``mode=0o600`` produce a tree nothing can descend into. A
    directory the server declined to report permissions for is skipped rather than raising, which
    is the opposite of what a *file* does under ``PRESERVE`` -- the file is the payload and a
    silently wrong mode on it is the failure being prevented, while a directory whose mode could
    not be carried leaves a readable tree and a listing that says what was skipped.
    """
    if entry.relative:
        _ = _ensure_directory(local_directory)
        state.directories += 1
        state.collisions.extend(_claim_directory(state.ledger, local_directory, entry))
    if preserve_times:
        state.directory_times.extend(
            (local_child(local_directory, child.filename), child.attrs.times)
            for child in entry.directories
            if child.attrs.times is not None
        )
    if mode is Mode.PRESERVE:
        state.directory_modes.extend(
            (
                local_child(local_directory, child.filename),
                child.attrs.permissions & PERMISSION_BITS,
            )
            for child in entry.directories
            if child.attrs.permissions is not None
        )
    state.skipped.extend(entry.skipped)


def _touch_destination(target: Path) -> None:
    """Create ``target`` empty if it is not there, without truncating it if it is.

    See :meth:`Session._claim_download` for why this runs before the collision check rather
    than being left to the transfer's own ``open``.
    """
    os.close(os.open(target, os.O_CREAT | os.O_WRONLY | NO_FOLLOW, 0o600))


def _check_tree_concurrency(
    concurrency: int, *, progress: ProgressCallback | None, caller: str
) -> None:
    """Refuse a concurrency argument that cannot mean what the caller wants.

    ``progress`` is the interesting half. :class:`~gantry_sftp.session.ProgressCallback` is
    ``(transferred, total)`` and carries **no file identity** -- deliberately, so one reporter
    works everywhere -- and a tree calls it per file, so ``total`` resets at each one. With a
    single worker that is a sequence a reporter can follow. With several it is several files'
    counters interleaved into one stream with nothing to tell them apart, and a progress bar
    built on it would jump backwards at random. Passing it through anyway would be a silent
    wrong answer, which this library refuses everywhere else, so it is refused here and the
    message names both fixes.

    Tree-wide progress, or a second callback shape carrying identity, is a real feature and a
    real decision (D-55) -- it is not made here by accident.

    Raises:
        ValueError: If ``concurrency`` is below 1, or if it is above 1 with a ``progress``
            callback that could not be interpreted.
    """
    if concurrency < 1:
        raise ValueError(
            f"{caller}() concurrency must be at least 1, got {concurrency}; "
            f"1 transfers the tree one file at a time"
        )
    if concurrency > 1 and progress is not None:
        raise ValueError(
            f"{caller}() cannot take progress= with concurrency={concurrency}: the callback is "
            f"(transferred, total) per file and carries no file identity, so several workers "
            f"reporting at once produce one stream of counters that reset unpredictably. Use "
            f"concurrency=1 to keep per-file progress, or drop progress= to keep the "
            f"concurrency and read the counts from the returned TreeResult"
        )


def _unexpected(reply: Response, *, expected: str, path: bytes | None = None) -> SFTPError:
    """Build the right error for a reply we cannot use.

    Returned rather than raised so the call site reads ``raise _unexpected(...)``, which
    both a reader and a static analyser can see terminates the function.

    A non-OK STATUS is the server declining, and gets a :class:`ServerError` -- that path
    raises from inside :func:`raise_for_status`. A STATUS of ``OK`` where a HANDLE or ATTRS
    was due is a different thing entirely: the server claiming success while withholding the
    result, which is a protocol violation rather than a refusal.
    """
    if isinstance(reply, Status):
        raise_for_status(reply, path=path)
        return ProtocolError(
            f"server answered with STATUS {reply.code.name} where {expected} was expected",
            request_id=reply.request_id,
        )
    return ProtocolError(
        f"server answered with {type(reply).__name__} where {expected} was expected",
        request_id=reply.request_id,
    )


async def _read_limits(transport: Transport, codec: Codec) -> ServerLimits:
    """Ask for ``limits@openssh.com`` and wait for the answer."""
    request = ExtendedRequest(codec.allocate_request_id(), LIMITS_EXTENSION)
    await transport.send(codec.send(request))
    while True:
        for event in codec.receive(await transport.receive()):
            if not isinstance(event, Completed):
                continue
            if isinstance(event.response, ExtendedReplyPacket):
                return ServerLimits.from_extended_reply(event.response.data)
            # Advertised, then refused. Our defaults work; not worth failing over.
            return ServerLimits.unknown()


async def _probe_limits(transport: Transport, codec: Codec, deadline: float | None) -> ServerLimits:
    """Read the server's limits, tolerating every way that can go wrong.

    Never advertised, advertised then refused, or advertised then silent -- all three end in
    the same place: our defaults, which are perfectly workable. Failing a connection over an
    optional tuning hint would be absurd, and the silent case is why this has a deadline of
    its own rather than inheriting the caller's patience.
    """
    if LIMITS_EXTENSION not in codec.extensions:
        return ServerLimits.unknown()
    if deadline is None:
        return await _read_limits(transport, codec)
    with anyio.move_on_after(deadline):
        return await _read_limits(transport, codec)
    return ServerLimits.unknown()


@asynccontextmanager
async def open_session(
    transport: Transport,
    *,
    request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    depth: int = DEFAULT_PIPELINE_DEPTH,
) -> AsyncGenerator[Session]:
    """Perform the handshake over ``transport``, start the reader, and yield a ready session.

    The handshake runs first and drives the transport directly, because VERSION is not a
    reply to anything -- it has no request id to route. Only once the connection is
    negotiated does the reader take ownership of ``receive``, and from then on nothing else
    calls it.

    The reader lives in a task group that ends with this block, so leaving it stops the
    reader whether the body returned or raised. Its exceptions are flattened on the way out:
    an anyio task group wraps even a single failure in an ``ExceptionGroup``, and a caller
    who wrote ``except NoSuchFileError`` around this line would otherwise stop matching.

    **Cancelling this block from outside is supported and bounded**, which is the spelling a
    timeout reaches for::

        with anyio.move_on_after(30):
            async with open_session(transport) as sftp:
                await sftp.get("/big.iso", "big.iso")

    The transfer stops, its handle is closed on the server, and the block unwinds in about
    one round trip -- not in ``request_timeout``, and not never. What buys that is the reader
    ignoring the same cancellation: see :meth:`~gantry_sftp.session.Dispatcher.run`.

    **One round trip is what it costs against a peer that is still answering**, and cleanup is
    shielded, so cancelling again does not hurry it. Against one that is not, the unwind costs
    ``request_timeout`` instead -- the cleanup ``CLOSE`` waits that long for its answer, and if
    the peer has stopped reading its socket the write itself waits that long for the send lock
    and the pipe. ``request_timeout=None`` opts out of both, which makes teardown unbounded
    there by construction: a shield is what makes the cleanup reliable, and nothing outside can
    cancel through one. It is a legitimate thing to ask for and it is not the default.

    Args:
        transport: A connected transport. Its lifetime is the caller's; this only drives it.
        request_timeout: Seconds for the handshake, for each one-shot request, and for each
            write -- including the wait for the connection's send lock. A write that runs out
            of time ends the connection, because a half-written frame cannot be recovered from.
        idle_timeout: Seconds of total silence during a bulk transfer.
        depth: Default requests in flight per transfer.

    Yields:
        A negotiated session, usable from several tasks at once.

    Raises:
        TransferTimeoutError: If the handshake does not complete within ``request_timeout`` --
            either half of it, since the message names which one stalled.
        ConnectError: If the transport fails, carrying the child's stderr.
    """
    codec = Codec()
    # Inside the handshake deadline rather than before it. INIT is nine bytes and cannot fill a
    # pipe on a fresh connection, so this was reasoned to be safe -- but "cannot happen" and
    # "is not bounded" are different claims, and the second one is what a caller reads as
    # "timeouts on every wait". A transport whose write never returns hung here forever (D-40).
    await _negotiate(transport, codec, request_timeout)
    limits = await _probe_limits(transport, codec, request_timeout)
    # The one handshake record. `gantry_sftp.frames` cannot cover INIT and VERSION: they are
    # exchanged before the dispatcher owns `receive`, and VERSION is not a reply to anything --
    # it has no request id to route. So the two facts a bug report needs from the handshake are
    # stated here instead, and the dump begins at the first request.
    if session_logger.isEnabledFor(logging.DEBUG):
        session_logger.debug(
            "negotiated version=%s extensions=%d [%s]",
            codec.server_version,
            len(codec.extensions),
            " ".join(render_field(name) for name in tuple(codec.extensions)[:_LOGGED_EXTENSIONS]),
        )

    # The send deadline is `request_timeout`: a write is the first half of a round trip whose
    # whole is already bounded by it, and a peer that cannot accept one frame in that time is
    # not a peer this transfer finishes against. `None` stays unbounded, like everything else.
    dispatcher = Dispatcher(transport, codec, send_timeout=request_timeout)
    try:
        async with anyio.create_task_group() as reader:
            _ = reader.start_soon(dispatcher.run)
            # Beside the reader rather than inside it: the reaper sends, sending takes the
            # send lock, and a reader waiting on that lock stops draining the pipe. See
            # `Dispatcher.reap_orphans`.
            _ = reader.start_soon(dispatcher.reap_orphans)
            try:
                yield Session(
                    dispatcher,
                    limits,
                    request_timeout=request_timeout,
                    idle_timeout=idle_timeout,
                    depth=depth,
                )
            finally:
                # Stops the reader, and is the only thing that does: it is shielded, so the
                # cancellation that ends the body leaves it reading. That is what a cancelled
                # transfer's shielded CLOSE needs -- somebody to route the reply it waits for
                # -- and this line runs after the body has finished unwinding, which is after
                # that cleanup. Cancelling `reader.cancel_scope` here would be a no-op now,
                # and used to be the bug (D-34). It also refuses further sends, so anything
                # still trying during teardown gets a StateError naming the reason.
                dispatcher.close()
    except BaseExceptionGroup as group:
        raise _flatten_exception_group(group) from None


async def _read_version(transport: Transport, codec: Codec) -> None:
    while codec.state is not CodecState.READY:
        codec.receive(await transport.receive())


async def _negotiate(transport: Transport, codec: Codec, deadline: float | None) -> None:
    """Do the handshake within a deadline covering both halves of it.

    Without this, a server that completes the connection and then says nothing hangs the
    caller forever -- which is exactly what an unattended job must not do, because nothing
    ever reports it.

    **The send is inside the deadline too**, which it was not until D-40. A transport that
    accepts the connection and never finishes a write hung here with nothing to stop it. Nine
    bytes cannot fill a pipe, so the case needed a peer that was already wedged -- but a bound
    that holds only while the failure is implausible is not a bound, and this library's own
    README promises timeouts on every wait.

    The deadline spans the handshake rather than each chunk of it: per-chunk would let a
    server dribble one byte at a time indefinitely and never trip, which is a hang wearing a
    timeout's clothes.
    """
    if deadline is None:
        await transport.send(codec.initiate())
        await _read_version(transport, codec)
        return

    # Which half ran out of time is the whole diagnosis, and one message for both would give
    # the wrong one half the time: "the server never answered" reads as a server problem, and a
    # peer that never accepted our nine bytes is a different animal. The flag is set inside the
    # scope and read outside it, which is the cheapest way to know how far we got.
    sent = False
    try:
        with anyio.fail_after(deadline):
            await transport.send(codec.initiate())
            sent = True
            await _read_version(transport, codec)
    except TimeoutError as exc:
        stalled = (
            "server did not send VERSION" if sent else "the connection did not accept our INIT"
        )
        raise TransferTimeoutError(f"{stalled} within {deadline}s") from exc

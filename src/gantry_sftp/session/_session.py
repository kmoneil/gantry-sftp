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

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Literal, overload, override

import anyio

from gantry_sftp._logging import operation, session_logger
from gantry_sftp.codec import (
    EXTENSION_FSYNC,
    LIMITS_NAME,
    Attrs,
    Codec,
    CodecState,
    Completed,
    OpenFlag,
    StatusCode,
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
    NoSuchFileError,
    PathCollision,
    ServerError,
    StateError,
    TransferError,
    TransferTimeoutError,
    _flatten_exception_group,
)
from gantry_sftp.session._core import (
    DEFAULT_REQUEST_TIMEOUT,
)
from gantry_sftp.session._dispatch import Dispatcher
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DownloadResult,
    ProgressCallback,
)
from gantry_sftp.session._glob import (
    GlobRunner,
    split_pattern,
    validate_pattern,
)
from gantry_sftp.session._handles import close_quietly
from gantry_sftp.session._journal import UploadJournal, source_identity
from gantry_sftp.session._limits import ServerLimits
from gantry_sftp.session._listing import (
    DOT_ENTRIES,
    DirEntry,
    EntryKind,
    entry_kind,
    modified_at,
)
from gantry_sftp.session._localpath import (
    DestinationLedger,
    FoldedNameLedger,
    check_contained,
    local_child,
)
from gantry_sftp.session._localtree import remote_component, walk_local
from gantry_sftp.session._mode import (
    Mode,
    local_mode,
    resolve_mode,
)
from gantry_sftp.session._operations import _SessionOperations
from gantry_sftp.session._platform import NO_FOLLOW, require_local_io
from gantry_sftp.session._policy import (
    _already_complete,
    _check_local_path,
    _check_publish_flags,
    _check_tree_concurrency,
    _check_tree_publish,
    _chmod_local_directories,
    _collision_error,
    _confirm_download_size,
    _download_mode,
    _download_resume_offset,
    _DownloadState,
    _ensure_directory,
    _local_directory,
    _local_size,
    _name_the_local_file,
    _note_planned,
    _optional_path,
    _preservation,
    _remote_directory,
    _settle_directory,
    _settle_remote_directory,
    _skip_reason,
    _stamp_local_directories,
    _touch_destination,
    _TreeDownload,
    _TreeUpload,
    refuses_the_name,
)
from gantry_sftp.session._pool import for_each_bounded
from gantry_sftp.session._publish import (
    Publish,
    UploadResult,
    publish_from_legacy,
    resume_target,
    split_parent,
    staged_path,
    staging_token,
)
from gantry_sftp.session._put import (
    _FEATURE_ATOMIC_PUBLISH,
    _FEATURE_DURABLE_UPLOAD,
    _put_atomically,
    _put_in_place,
    _set_directory_modes,
    _set_directory_times,
    _Upload,
)
from gantry_sftp.session._recursive import (
    GlobMatch,
    PlanLimit,
    PotentialCollision,
    Skipped,
    SkipReason,
    TreePlan,
    TreeResult,
    WalkEntry,
    join_remote,
)
from gantry_sftp.session._sync import (
    SyncManifest,
    SyncOutcome,
    SyncResult,
    _SyncCandidate,
    append_record,
    candidates_in,
    manifest_entry_for,
    prepare_manifest,
    summarise,
)
from gantry_sftp.session._verify import (
    Verify,
    gate_resume,
    verify_downloaded_content,
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


LIMITS_EXTENSION = LIMITS_NAME
"""Kept as an alias rather than a second bytes literal.

One wire string, spelled once, in the same table the advertisement fixture is checked
against. Two spellings of an extension name is how a client silently never negotiates it.
"""


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
    reasoning that made ``Publish`` a type rather than five arguments.

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
        depth: Default requests in flight per transfer, and therefore what a transfer costs
            in memory: peak is ``depth`` x the derived request size, about 16 MiB at the
            shipped defaults and the same in both directions. Raising it past the default
            buys nothing -- one session is one channel is one 2 MiB window -- so this is a
            knob for *lowering*, when a container's limit is what binds. See
            ``docs/tuning.md``, "What a transfer costs in memory".
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
        if self._handle is not None:
            state = "open"
        elif self._entered:
            state = "spent"
        else:
            state = "unopened"
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
            await close_quietly(self._session, handle)

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
        if self._handle is not None:
            state = "open"
        elif self._entered:
            state = "closed"
        else:
            state = "unopened"
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
        await close_quietly(self._session, handle)

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


class Session(_SessionOperations):
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

    # --- one round trip ------------------------------------------------------------------

    # --- capabilities --------------------------------------------------------------------

    # --- operations ----------------------------------------------------------------------

    # --- the working directory, which this protocol does not have ---------------------------

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
        raise self._unclassifiable(path, caller=caller)

    def _unclassifiable(self, path: bytes, *, caller: str) -> CapabilityError:
        """The refusal for an entry the server described without a type in it.

        A factory rather than a ``raise`` inside :meth:`_classify`, because `glob` reaches this
        state having already spent the attributes on :meth:`_settle_kind` and must produce the
        *same* refusal (D-103). One wording, one place -- the alternative is two messages that
        drift, describing one decision.
        """
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
        return unclassifiable

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

    # --- get, and the two round trips it opens with -------------------------------------------
    #
    # This banner used to read "verification, rungs 1 and 2 of DESIGN.md 6" and the rungs are no
    # longer here: D-146 moved them to `session/_verify.py` as functions taking a session, and
    # what is left is the download they were reached from. A section banner naming a concern the
    # section no longer holds is worse than none -- it is what a reader greps for.

    async def _stat_and_open_for_download(
        self, path: bytes, *, together: bool
    ) -> tuple[Attrs, bytes | None]:
        """The ``STAT`` and the ``OPEN`` a download begins with, in one round trip where it can.

        Both requests are addressed by path and neither reads the other's answer, so on the
        default path there is nothing between them that makes them sequential -- the ordering
        was incidental. Issued together they cost one round trip instead of two, which is one
        of the four a small ``get`` makes and about a quarter of its latency on any link where
        a round trip costs anything (D-110). ``tests/test_round_trips.py`` pins the count.

        **``together=False`` is the resume path and it is a correctness requirement rather than
        an optimisation declined.** Resuming needs the size before anything else happens:
        :func:`_download_resume_offset` derives the offset from it, :meth:`_gate_resume` refuses
        on it, and a resume of an already-complete file returns without opening anything at all.
        Opening concurrently there would send an ``OPEN`` for a transfer that is not going to
        happen.

        **What the caller sees when it fails is unchanged**, which was checked against all three
        servers in the matrix rather than reasoned about. A missing path answers ``NO_SUCH_FILE``
        from *both* requests everywhere, so the exception is the same class with the same message
        either way. For a directory every server's ``STAT`` succeeds and it is the ``OPEN`` that
        decides -- permitted by OpenSSH, refused by asyncssh and paramiko -- and the ``OPEN``
        decides in the sequential arrangement too. The group is flattened here because an anyio
        task group wraps even a single failure, and control flow above routes on flat ``except``.

        Returns:
            The attributes, and the handle when one was opened. ``None`` for the handle on the
            resume path, where the caller opens later or returns without opening.

        Raises:
            ServerError: Whatever either request was refused with, flat rather than grouped.
        """
        if not together:
            return await self.stat(path), None

        # One-element collectors rather than two `| None` locals: a task group returns nothing,
        # and appending keeps both results at their real types instead of widening them to
        # optional and then narrowing again at a `return` the type checker cannot verify.
        described: list[Attrs] = []
        opened: list[bytes] = []

        async def _describe() -> None:
            described.append(await self.stat(path))

        async def _open() -> None:
            opened.append(await self.open(path, OpenFlag.READ))

        try:
            async with anyio.create_task_group() as pair:
                # `_ =` because anyio's `start_soon` returns a handle and mypy's
                # `unused-awaitable` rightly refuses a discarded one; the repo spells it this
                # way at every other fan-out site.
                _ = pair.start_soon(_describe)
                _ = pair.start_soon(_open)
        except BaseExceptionGroup as group:
            # The OPEN can win while the STAT loses, which leaves a handle nobody asked for and
            # nobody will close. A reply that never arrived is the reaper's job (D-75); one that
            # did arrive is ours, and it is closed here rather than at the call site because this
            # is the only frame that still has it.
            if opened:
                await close_quietly(self, opened[0])
            raise _flatten_exception_group(group) from None

        return described[0], opened[0]

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
        verify: Verify = Verify.SIZE,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
    ) -> DownloadResult:
        """Download ``remote_path`` to ``local_path``.

        The size is taken from a STAT so the transfer is bounded, the progress callback has a
        total to report against, and what arrived is checked against it. A
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
                Turning it off is reported as
                :data:`~gantry_sftp.session.SizeCheck.SKIPPED` rather than being silent.

            verify: Which rung of DESIGN.md 6's ladder to check the *content* against, on top
                of the length ``verify_size`` compares. Reported as
                :attr:`~gantry_sftp.session.DownloadResult.content_check`; a *mismatch* raises
                :class:`~gantry_sftp.exceptions.TransferError`.

                :data:`~gantry_sftp.session.Verify.SIZE` -- the default -- checks no content,
                which is what this originally did and could not say. It is the same
                default ``put`` has, for the same reason: both other rungs cost something.

                :data:`~gantry_sftp.session.Verify.HASH` is rung 1, one round trip and no
                payload, and it needs ``check-file@openssh.com`` -- which nearly no endpoint
                has, so this reports
                :data:`~gantry_sftp.session.ContentCheck.UNAVAILABLE` far more often than it
                reports a pass. That is the point of the value existing.

                :data:`~gantry_sftp.session.Verify.REREAD` is rung 2 and works against
                **every** server, because it asks for nothing but ``READ``. On this side that
                means downloading the file a second time into ``$TMPDIR`` and comparing it
                against what was just written, so it costs a second transfer and scratch disk
                equal to the file.

                **It proves something narrower here than it does on ``put``, and the
                difference is worth knowing rather than assuming.** Uploading, rung 2 proves
                the server holds what you sent. Downloading, both copies come from the same
                place, so what it actually checks is the *local* half: this library's
                reassembly, its offsets, and the disk they were written to. Rung 1 is the
                end-to-end check on this side, when the server can answer it.

                **This is the parameter ``get`` could not have while it returned an ``int``**
                (D-99): a rung that cannot run has to be reportable, and a content check that
                silently passes when it did not happen is the one outcome the whole ladder
                exists to prevent.

                On a resume it also selects the rung the adopted prefix is gated on, which is
                what ``put``'s ``verify`` has always done. A resume that adopts the *whole*
                file is gated over the whole file, so that gate is the content check and is
                reported as both.

            preserve_times: Stamp the local file with the remote file's atime and mtime instead
                of the time of the download. **Off by default**, matching ``scp -p`` and
                ``rsync -t``; see :meth:`put` for why the default is a decision rather than an
                omission.

                It costs no round trip -- the times come from the ``STAT`` ``get`` already
                makes -- and it is applied to the open descriptor after the last write, so a
                resumed transfer stamps the file once it is whole rather than while it is
                partial.

                **A server that reports no times leaves the local file stamped with now**, and
                it says so:
                :attr:`~gantry_sftp.session.DownloadResult.times` is ``UNAVAILABLE`` rather
                than ``PRESERVED``. Until then ``get`` returned a byte count and this
                docstring argued that widening it for one uncommon case was the worse trade;
                D-99 found the case was not one, and not uncommon enough to be worth a
                paragraph of apology in place of a field. v3 carries seconds, so sub-second
                precision is lost whatever this is set to.
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
            A :class:`~gantry_sftp.session.DownloadResult` describing what happened: what
            moved, what was already there, which checks ran and which could not.
            :attr:`~gantry_sftp.session.DownloadResult.transferred` is what this call wrote --
            on a resume the remainder, and ``0`` for a file that was already complete --
            while :attr:`~gantry_sftp.session.DownloadResult.size` is what the local file
            holds now.

            **This was an ``int`` before the first release and the break is deliberate**
            (D-99). A call that
            only wants the count reads ``.transferred``; there is no ``int`` subclass to make
            the old spelling keep working, because a type that lies about what it is turns
            every downstream ``isinstance`` into an accident that happens to work.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before anything is sent; see :mod:`._platform`.
            TypeError: If ``mode`` is neither an octal mode nor
                :data:`~gantry_sftp.session.Mode.PRESERVE`.
            ValueError: If ``mode`` is out of range.
            NoSuchFileError: If the remote path does not exist.
            ServerError: If the server refuses.
            TransferError: If the transfer fails partway, if ``resume`` cannot establish a
                safe offset, if ``verify_size`` finds fewer bytes arrived than the server
                said there were, or if ``verify`` finds the content disagrees. **Every one of
                them names ``local_path``**, and once the transfer has begun the local file is
                left exactly where it is -- see :meth:`_download_into` for why deleting it
                would be the expensive choice rather than the tidy one. A failure before the
                first ``READ`` creates nothing at all.
        """
        require_local_io("get()")
        _check_local_path(local_path, method="get()")
        encoded = self._resolve(remote_path)
        requested_mode = resolve_mode(mode, caller="get()")
        # Normalised rather than trusted, for the reason `put` gives: `Verify` is a `StrEnum`,
        # so `verify="size"` arrives as a plain `str` from anyone not running a type checker
        # and every `verify is Verify.SIZE` below would be False while `==` was True. Here that
        # would fall past both named rungs into the `else`, so asking for the *default* would
        # silently download the file a second time.
        wanted = Verify(verify)
        try:
            with operation(session_logger, "get", remote=encoded, local=local_path) as record:
                attributes, opened = await self._stat_and_open_for_download(
                    encoded, together=not resume
                )
                local_bits = _download_mode(requested_mode, attributes, encoded)
                start = (
                    _download_resume_offset(local_path, attributes.size, encoded) if resume else 0
                )
                # DESIGN.md 6's gate, on the direction that is usually assumed safe. The local
                # partial being *ours* makes its length trustworthy; it does not make its contents a
                # prefix of this remote file. A partial left by a previous run against a different
                # source is the same corruption as on the upload side, and it is caught here before
                # the first READ. It refused but could not report until D-99 gave `get` somewhere
                # to say so -- see D-38 for the refusal.
                resume_check = await gate_resume(self, encoded, local_path, start, wanted)
                times_result = _preservation(preserve_times, attributes.times)
                if resume and start == attributes.size:
                    # Already complete: nothing to open and nothing to move. Deliberately *after*
                    # the gate rather than before it -- this is the case that adopts the entire file
                    # and returns success having verified nothing, which makes it the one most worth
                    # gating, not the one to skip for a round trip.
                    return _already_complete(
                        encoded,
                        local_path,
                        record,
                        adopted=start,
                        mode=local_bits,
                        no_follow=no_follow,
                        times=attributes.times if preserve_times else None,
                        times_result=times_result,
                        resume_check=resume_check,
                        verify=wanted,
                    )

                # Already open on the default path -- the concurrent pair above returns the handle.
                # The resume path opens here instead, after the gate and after the early return that
                # must not open anything at all.
                handle = opened if opened is not None else await self.open(encoded, OpenFlag.READ)
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
                    await close_quietly(self, handle)
                    raise
                await self.close(handle)
                record["bytes"] = transferred
                size_check = _confirm_download_size(
                    encoded,
                    local_path,
                    arrived=start + transferred,
                    announced=attributes.size,
                    asked=verify_size,
                )
                content_check = await verify_downloaded_content(
                    self, encoded, local_path, start + transferred, wanted
                )
                return DownloadResult(
                    transferred,
                    encoded,
                    Path(local_path),
                    size_check,
                    times=times_result,
                    content_check=content_check,
                    resume_check=resume_check,
                    adopted=start,
                    mode=local_bits,
                )
        except TransferError as failure:
            # The one place a download's error learns which file it was writing. Every
            # raise site above is inside this method, so the field is carried by
            # construction rather than by anybody remembering to pass it.
            _name_the_local_file(failure, local_path)
            raise

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
        start_offset: int,
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

        **A failed download leaves the file it opened, and the error says where it is** (D-117).
        That is a decision rather than an omission, and it is the same one
        :meth:`_put_in_place` makes in the other direction: the destination *is* the caller's
        named file, not a staging name of ours, so removing it would be deleting their data
        rather than cleaning up after ourselves. Three things say keep it. ``resume=True``
        continues from exactly this partial and reads its length off the disk, so a client that
        deleted on failure would delete what its own retry needs. ``no_follow`` is off by
        default, so the path may be a symlink the caller made, and an ``unlink`` would remove
        their link rather than the bytes. And it may hold most of a nine-gigabyte transfer,
        which is the one thing nobody can get back.

        What that costs is the shape the note below exists to name: a ``get`` of something the
        server will open and not read leaves a **zero-byte file with the right name**, and
        ``if os.path.exists`` reads that as a download that happened.
        """
        flags = _LOCAL_WRITE_FLAGS if not start_offset else _LOCAL_RESUME_FLAGS
        try:
            fd = os.open(local_path, flags | (NO_FOLLOW if no_follow else 0), 0o600)
        except OSError as refusal:
            # The one local error that is about the *name* rather than about the I/O (D-150).
            # A bare `OSError` escaping `get` is outside this library's hierarchy entirely, so
            # `except SFTPError` does not catch it and nothing carries the remote path -- and on
            # a tree of two hundred files the local path is a name the caller never chose. Every
            # other errno keeps propagating as it did; see `refuses_the_name`.
            if not refuses_the_name(refusal):
                raise
            raise TransferError(
                f"the local filesystem will not accept the name {Path(local_path).name!r}: "
                f"{refusal.strerror}. The remote name is bytes and this filesystem requires "
                f"valid UTF-8, so this file cannot be written here under its own name",
                remote_path=remote_path,
                local_path=str(local_path),
            ) from refusal
        try:
            transferred = await self.download_into(
                handle,
                fd,
                size=size,
                depth=depth,
                progress=progress,
                remote_path=remote_path,
                start_offset=start_offset,
            )
            if mode is not None:
                os.fchmod(fd, mode)
            if times is not None:
                os.utime(fd, (times.atime, times.mtime))
        except TransferError as failure:
            # Only here, and not wherever a `TransferError` can reach `get`: this is the one
            # path that has opened a local file, and the same sentence attached to a refusal
            # from `_download_mode` or a resume gate would describe a file nothing created.
            failure.add_note(
                f"{local_path} was left where it is, holding whatever had arrived when this "
                f"failed -- nothing here removes it, because the destination is your file "
                f"rather than a staging name of ours and resume=True continues from exactly "
                f"this partial. Delete it yourself if you are not going to resume: a file of "
                f"the right name and the wrong length is what a consumer misreads."
            )
            raise
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
            ServerError: If the server refuses a **listing**. A refusal of the ``LSTAT`` that
                settles one entry's kind is recorded in that entry's
                :attr:`~gantry_sftp.session.WalkEntry.skipped` instead and the walk carries on
                -- see :meth:`_settle_for_walk` for why the two are answered differently, and
                :class:`~gantry_sftp.session.SkipReason` for the three ways a settle can fail.
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
                settled = await self._settle_for_walk(path, child)
                if isinstance(settled, Skipped):
                    skipped.append(settled)
                elif settled is EntryKind.DIRECTORY and at_limit:
                    skipped.append(Skipped(path, child, SkipReason.TOO_DEEP))
                elif settled is EntryKind.DIRECTORY:
                    directories.append(child)
                elif settled is EntryKind.FILE:
                    files.append(child)
                else:
                    skipped.append(Skipped(path, child, _skip_reason(settled)))

        return WalkEntry(directory, relative, tuple(directories), tuple(files), tuple(skipped))

    async def _settle_for_walk(self, path: bytes, entry: DirEntry) -> EntryKind | Skipped:
        """Settle an entry's kind for a walk, where a server that will not answer is not a stop.

        The three states :meth:`_settle_kind` produces, each mapped to what a walk does with it.
        All three are *reported* and none is fatal, because a walk has somewhere to put them and
        a recursive transfer that died on one unstattable entry would be worse than one that
        names it. `glob` reaches the same helper and may only swallow the absence, since it has
        no such channel -- that asymmetry is D-103's whole subject, and it is the channel rather
        than the surface that decides it.

        They are three reasons rather than one because they are three different facts about the
        far end: attributes with no type bits in them, a name that was listed and is now gone,
        and a server that refused to say. A report that renders all three as "a stat did not
        settle it" costs its reader the only thing the record exists for.
        """
        try:
            kind = await self._settle_kind(path, entry)
        except ServerError:
            return Skipped(path, entry, SkipReason.KIND_REFUSED)
        if kind is None:
            return Skipped(path, entry, SkipReason.VANISHED)
        return kind

    async def _settle_kind(self, path: bytes, entry: DirEntry) -> EntryKind | None:
        """Resolve an entry whose kind the listing did not report.

        One ``LSTAT``, and only for the entries that need it -- so a server that sends
        attributes (all the common ones) pays nothing, and a server that does not gets a
        correct walk rather than a fast wrong one. ``LSTAT`` because a symlink must stay a
        symlink here.

        **Through :meth:`_attrs_or_absent`, and returning ``None`` rather than swallowing, which
        is the whole of the fix for D-103.** This used to catch ``ServerError`` and answer
        ``UNKNOWN``, so a server refusing to stat an entry was indistinguishable from one
        describing it unhelpfully -- and `glob` read that ``UNKNOWN`` as "not a directory" and
        dropped whatever was underneath it. Three states arrive here as three states: a kind, a
        ``None`` for an entry that was listed and is no longer there, and a raise for a server
        that will not say. **Which of the three each caller may swallow is the caller's to
        answer**, because the answer differs: :meth:`walk` records all of them and continues,
        :meth:`~gantry_sftp.session._glob.GlobRunner.is_directory` may only swallow the absence.

        Returns:
            The settled kind, or ``None`` where the entry is not there any more -- the listing
            named it and the ``LSTAT`` answered ``NO_SUCH_FILE``, which is a race with whoever
            else is writing to that directory rather than a refusal.
        """
        if entry.kind is not EntryKind.UNKNOWN:
            return entry.kind
        attributes = await self._attrs_or_absent(path, follow_symlinks=False)
        return None if attributes is None else entry_kind(attributes)

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

        **POSIX character classes work**: ``*.[[:digit:]]``, ``[[:upper:]]*`` and the other ten
        names, inside a bracket expression and alongside ordinary members and ranges. They are
        **ASCII-only** -- no byte above 127 is in any class -- because which bytes are letters
        is a property of a locale, and a remote name is bytes whose encoding the protocol never
        states. The other two POSIX sub-expressions, equivalence classes (``[[=a=]]``) and
        collating symbols (``[[.a.]]``), are *defined* by a locale's collation table and are
        refused rather than guessed at; so is a class name that does not exist, which is what
        ``[[:digits:]]`` is. All three raise :exc:`ValueError` before anything is listed.

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
                path, and yields one match if it exists and nothing if it does not -- with
                "does not exist" meaning ``NO_SUCH_FILE`` specifically, not any refusal to
                answer. A server that will not stat it raises, the same as for a directory
                the pattern reached; see ``Raises``.
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
            ValueError: If the pattern contains a bracket sub-expression this library will not
                honour: a character class that does not exist, an equivalence class or a
                collating symbol. Raised **before any listing**, which is the point of it --
                a refusal that needed a name to be raised against would answer "no matches" for
                the same broken pattern whenever the directory happened to be empty.
            UnsafePathError: If the server sends a name that cannot be one path component.
            CapabilityError: If ``pattern`` is relative and this server's default directory is
                not rooted at ``/``, so joining would build paths it does not mean.
            ServerError: If the server refuses a listing of a directory the pattern reached,
                **or refuses to stat a wholly literal pattern**. Only ``NO_SUCH_FILE`` is
                swallowed, and only into an empty result: a path that does not exist matches
                nothing, the same as a name that does not match. **This is a deliberate
                divergence from** ``glob(3)``, which passes no error function and therefore
                skips what it cannot read: silently, and indistinguishably from it being
                empty. A glob that answers "no matches" when it means "I was not allowed to
                look" is the shape of partial success this library refuses everywhere else.

                Both halves of the pattern space, and that is D-102 rather than a restatement:
                the literal half originally caught every ``ServerError`` and answered "no
                matches" to ``PERMISSION_DENIED`` and to the ``BAD_MESSAGE`` an over-long name
                arrives as. Whether the caller's pattern happened to contain a ``*`` decided
                which of two opposite answers they got.
        """
        encoded = self._resolve(pattern)
        validate_pattern(encoded)
        await self._require_rooted_paths(encoded, feature="globbing")
        base, components, directories_only = split_pattern(encoded, case_sensitive=case_sensitive)
        runner = self._glob_runner()
        if not components:
            literal = await runner.literal(base, directories_only=directories_only)
            if literal is not None:
                yield literal
            return
        async with aclosing(
            runner.match_in(
                base,
                components,
                max_depth=max_depth,
                case_sensitive=case_sensitive,
                directories_only=directories_only,
            )
        ) as found:
            async for match in found:
                yield match

    def _glob_runner(self) -> GlobRunner:
        """Bind what a glob needs from this session, and hand it nothing else.

        **The binding happens here because this is where the private members are ours** (D-128).
        :class:`~gantry_sftp.session._glob.GlobRunner` holds five callables and no session, so the
        traversal is exercisable with no transport and no server; reaching ``_settle_kind`` and
        its two siblings from that module instead would be private access across a module
        boundary at seven call sites.

        Three of the five are private and two are the public API a caller could have driven by
        hand. That is the honest split: ``scandir`` and ``walk`` are what a glob is, and the
        other three are decisions this class makes for every path that asks about a name --
        which is why globbing shares them rather than re-deciding them.
        """
        return GlobRunner(
            attrs_or_absent=self._attrs_or_absent,
            scandir=self.scandir,
            walk=self.walk,
            settle_kind=self._settle_kind,
            unclassifiable=self._unclassifiable,
        )

    # Overloaded on `dry_run` so the flag picks the return type rather than every existing
    # caller inheriting a union to narrow (D-163). Without this, adding a preview would be a
    # source break on code that has never asked for one: `(await sftp.get_tree(...)).transferred`
    # stops type-checking the day the flag lands, which is the shape "public API is stable or
    # the break is deliberate" exists to catch.
    @overload
    async def get_tree(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        progress: ProgressCallback | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[False] = ...,
    ) -> TreeResult: ...

    @overload
    async def get_tree(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        progress: ProgressCallback | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[True],
    ) -> TreePlan: ...

    # The third one is what a *forwarding* caller needs: `SFTPPath.download_tree` passes its own
    # `dry_run` through as a plain `bool`, which matches neither literal, and without this the
    # facade would have to branch and call twice to say one thing. A caller holding the flag in
    # a variable gets the union and narrows it, which is correct -- they do not know either.
    @overload
    async def get_tree(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        progress: ProgressCallback | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: bool,
    ) -> TreeResult | TreePlan: ...

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
        dry_run: bool = False,
    ) -> TreeResult | TreePlan:
        """Download a remote tree into ``local_path``, refusing to escape it.

        **Every name the server supplies is validated before it becomes a path**, and the
        finished path is re-checked against the destination after symlinks are resolved. A
        server answering ``../../etc/cron.d/x`` gets an
        :class:`~gantry_sftp.exceptions.UnsafePathError` and nothing is written -- this is the
        zip-slip class, and it is a real and exploited pattern in file-transfer clients.

        **Transfers are sequential by default and overlap on request** (``concurrency=``).
        The walk feeds a bounded pool rather than starting a task per file: a tree's
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

                **This bounds one call and nothing adds the calls up.** M of them in your task
                group is M x this number in flight, and the total is the caller's to own -- it
                is close to free on one session and it is the session count that costs. The
                ``docs/concurrency.md``'s *"``concurrency=`` bounds one call, and you own the
                product"* is where that lives and DESIGN.md §5.2 has the measurement (D-116).

            dry_run: Report what this call would do and do none of it, returning a
                :class:`TreePlan` instead of a :class:`TreeResult`.

                **Makes no writes** -- nothing is downloaded, no directory of the tree is
                created, not even the destination root, and the empty file each remote name
                would reserve is not created either. It reads only what the download would
                read anyway, and for this direction that is most of the answer: walking a
                remote tree *is* reading, so the plan carries every file, every skipped entry
                with its reason, and the byte total from the sizes the listing already
                returned. A server volunteering no size leaves that total short rather than
                guessed, and says so through :data:`PlanLimit.UNREPORTED_SIZES`.

                **The collision check is the one thing a preview cannot deliver in full, and
                it degrades rather than disappearing.** The real download names two remote
                paths as one local file by creating the file and asking ``lstat`` -- which is
                a write, and the only answer that is right on every filesystem. A dry run
                folds names instead (case and Unicode normalisation), so it reports
                :class:`PotentialCollision` in
                :attr:`TreePlan.potential_collisions` rather than raising
                :exc:`~gantry_sftp.exceptions.DestinationCollisionError`, and it is wrong in
                both directions: a case-sensitive destination keeps apart pairs listed there,
                and a hard link or symlink already sitting in the destination has no name to
                fold and is missed entirely. :data:`PlanLimit.DESTINATION_FILESYSTEM_RULES`
                says so, and it is always present. Those files stay in ``files`` and
                ``bytes_to_transfer`` for the same reason -- on most destinations they do
                transfer.

        Returns:
            Counts, bytes, and every entry that was skipped with the reason it was -- or a
            :class:`TreePlan` when ``dry_run`` is set.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before the walk starts; see :mod:`._platform`.
            UnsafePathError: If a server-supplied name would escape the destination. A dry run
                raises it too: the name alone decides, so nothing is being guessed at.
            DestinationCollisionError: If two remote names resolved to one local file. Raised
                at the end rather than on contact, so everything transferable still transfers;
                what is refused is only the write that would have destroyed an earlier one.
                **Never raised by a dry run**, which has not created the files the filesystem
                would need in order to say so -- see ``dry_run`` above.
            NoSuchFileError: If the remote directory does not exist.
            ServerError: If the server refuses.
            TransferError: If a transfer fails partway.
        """
        require_local_io("get_tree()")
        _check_local_path(local_path, method="get_tree()")
        _check_tree_concurrency(concurrency, progress=progress, caller="get_tree")
        requested_mode = resolve_mode(mode, caller="get_tree()")
        destination = (
            Path(local_path) if dry_run else _ensure_directory(Path(local_path), parents=True)
        )
        state = _DownloadState(ledger=FoldedNameLedger() if dry_run else DestinationLedger())

        with operation(
            session_logger, "get_tree", remote=self._resolve(remote_path), local=destination
        ) as record:

            async def transfer(item: _TreeDownload) -> None:
                if dry_run:
                    return
                # Appended rather than `state.transferred += ...`: augmented assignment loads
                # the target before evaluating the right-hand side, so with `concurrency > 1`
                # every worker finishing inside another's await adds to a value it read before
                # the others finished. The lost update understates the byte count, and it is
                # the same trap `download_many_concurrently` documents in `benchmarks/`.
                #
                # The byte count is kept and the rest of each `DownloadResult` is dropped, which
                # is what `put_tree` already does with its `UploadResult`s. `TreeResult` stays a
                # summary: `skipped` is bounded by the number of *problems* and is worth holding
                # in full, per-file results are bounded by the number of *files*, and a tree of
                # a hundred thousand of them should not cost a hundred thousand objects for a
                # report almost nobody reads. A caller who wants them calls `get` per file --
                # which is what the consumer behind D-99 does.
                result = await self.get(
                    item.remote,
                    item.target,
                    progress=progress,
                    no_follow=True,
                    resume=resume,
                    preserve_times=preserve_times,
                    mode=requested_mode,
                )
                state.moved.append(result.transferred)

            await for_each_bounded(
                self._walk_for_download(
                    remote_path,
                    destination=destination,
                    max_depth=max_depth,
                    preserve_times=preserve_times,
                    mode=requested_mode,
                    state=state,
                    dry_run=dry_run,
                ),
                transfer,
                concurrency=concurrency,
            )

            if dry_run:
                undetermined = [
                    PlanLimit.DESTINATION_COMPARISON,
                    PlanLimit.DESTINATION_FILESYSTEM_RULES,
                    PlanLimit.PER_FILE_TRANSFER_DECISIONS,
                ]
                if state.sizes_unreported:
                    undetermined.append(PlanLimit.UNREPORTED_SIZES)
                plan = TreePlan(
                    files=state.planned_files,
                    directories=state.directories,
                    bytes_to_transfer=state.planned_bytes,
                    skipped=tuple(state.skipped),
                    # Reported, never raised. The walk collected these through a
                    # `FoldedNameLedger`, so each is "one filesystem away from being a
                    # collision" rather than one -- and `DestinationCollisionError` means the
                    # filesystem said so. Converting here rather than at the walk keeps one
                    # collision rule and puts the change of certainty at the boundary where
                    # the result type changes too.
                    potential_collisions=tuple(
                        PotentialCollision(item.local, item.remote, item.first)
                        for item in state.collisions
                    ),
                    undetermined=tuple(undetermined),
                )
                record["files"] = plan.files
                record["directories"] = plan.directories
                record["bytes"] = plan.bytes_to_transfer
                record["skipped"] = len(plan.skipped)
                record["collisions"] = len(plan.potential_collisions)
                record["dry_run"] = True
                return plan

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
        dry_run: bool = False,
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
                    dry_run=dry_run,
                )
                for child in entry.files:
                    item = self._settle_file(
                        destination=destination,
                        local_directory=local_directory,
                        entry=entry,
                        child=child,
                        state=state,
                        dry_run=dry_run,
                    )
                    if item is not None:
                        yield item

    def _settle_file(
        self,
        *,
        destination: Path,
        local_directory: Path,
        entry: WalkEntry,
        child: DirEntry,
        state: _DownloadState,
        dry_run: bool,
    ) -> _TreeDownload | None:
        """Settle one walked file and record whatever stopped it, or hand it back to transfer.

        The reporting half of :meth:`_claim_download`, split from it so that one decides a
        destination and this one decides what a refusal *means* for the report. Extracted from
        :meth:`_walk_for_download` when the preview's branches took that method over the
        cognitive-complexity ceiling, and the seam is real rather than convenient: everything
        here appends to the report and nothing here walks.

        Returns:
            The file to transfer, or ``None`` if it was skipped or refused.
        """
        try:
            if dry_run:
                _note_planned(state, child)
            item, collision = self._claim_download(
                destination=destination,
                local_directory=local_directory,
                entry=entry,
                child=child,
                ledger=state.ledger,
                dry_run=dry_run,
            )
        except OSError as refusal:
            # The destination filesystem refusing the *name* (D-150), which on a Mac is any
            # name that is not UTF-8. Reported like a collision rather than raised, for the
            # reason `SkipReason` exists: one unlucky filename must not cost every file after
            # it in the walk. Narrow by errno -- a full disk or a denied directory still
            # aborts, and reporting either of those as "bad name" is the failure a wide
            # `except OSError` here would have.
            if not refuses_the_name(refusal):
                raise
            state.skipped.append(
                Skipped(
                    join_remote(entry.path, child.filename),
                    child,
                    SkipReason.DESTINATION_REFUSED_THE_NAME,
                )
            )
            return None
        if collision is None:
            return item
        state.collisions.append(collision)
        # Not a skip in a preview, and the asymmetry is the point (D-163): a dry run's ledger
        # folds names instead of asking the filesystem, so "these two are one file" is
        # conditional on a destination nobody looked at. Recording a skip would make the plan
        # disagree with the real run on every case-sensitive destination -- reporting it as a
        # `PotentialCollision` says the same thing without asserting it.
        if not dry_run:
            state.skipped.append(Skipped(collision.remote, child, SkipReason.DESTINATION_COLLISION))
        return None

    def _claim_download(
        self,
        *,
        destination: Path,
        local_directory: Path,
        entry: WalkEntry,
        child: DirEntry,
        ledger: DestinationLedger | FoldedNameLedger,
        dry_run: bool = False,
    ) -> tuple[_TreeDownload | None, PathCollision | None]:
        """Settle one walked file's destination, or report the collision that refuses it.

        Synchronous and called only from the producer, which is what makes the ledger safe
        under concurrency: every check and every claim happens in one task, in walk order,
        before any transfer is queued.

        **The destination file is created here, empty, before the check** -- and that is what
        makes the check mean anything. A collision is two remote names that the *filesystem*
        resolves to one file, which it can only be asked about once an inode exists; the check
        originally ran before the transfer that created it, so it detected a collision
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
        # The local write in this builder, and it is easy to miss because the name does not
        # say it writes: `O_CREAT` reserves the destination so two remote names cannot race
        # onto it. A preview must not leave that file behind, and skipping it is what forces
        # `dry_run` to carry a `FoldedNameLedger` -- with no file there is no inode, and the
        # inode is the only thing that can answer this question for certain.
        if not dry_run:
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
                disagrees with the local file's. Every one names ``local_path``, which on this
                side is the **source** rather than the staging file -- the staging name is
                already on the message, and the caller's file is the one they can act on.
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
            journal=policy.journal,
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
                feature=_FEATURE_DURABLE_UPLOAD,
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
        try:
            with operation(session_logger, "put", local=local_path, remote=target) as record:
                result = await self._publish_upload(upload, target, policy)
                record["bytes"] = result.transferred
                record["mechanism"] = result.mechanism.name
                return result
        except TransferError as failure:
            # The mirror of `get`'s, and it has to be here rather than assumed from that one:
            # the two directions have disagreed before on exactly this kind of symmetry (D-96,
            # D-103), so neither is evidence about the other.
            _name_the_local_file(failure, local_path)
            raise

    async def _publish_upload(
        self, upload: _Upload, target: bytes, policy: Publish
    ) -> UploadResult:
        """Route one prepared upload to the in-place or the staged path.

        Split out of :meth:`put` so the operation record has a result to close over -- and only
        that far, because everything above it is argument handling that can raise before a byte
        moves, and a record for an upload that never started is noise.
        """
        if not policy.atomic:
            return await _put_in_place(self, upload, target)
        staged_name = _optional_path(policy.staging_name)
        if staged_name is None or b"/" not in staged_name:
            # A staging name carrying a separator is used verbatim, so no parent is derived
            # from the target and there is nothing for a foreign namespace to break.
            await self._require_rooted_paths(target, feature=_FEATURE_ATOMIC_PUBLISH)
        # Read once and used for both the lookup and the record (D-166). Two reads would leave
        # a window in which the source changes between them, and the upload would then resume
        # a partial of the old bytes while recording the identity of the new ones.
        source = source_identity(upload.local_path)
        continuing = resume_target(
            policy.journal, target, source, resume=upload.resume, name=staged_name
        )
        staged = (
            staged_path(target, staging_token(), name=staged_name)
            if continuing is None
            else continuing
        )
        return await _put_atomically(
            self,
            upload,
            target,
            staged,
            require_atomic=policy.require_atomic,
            journal=policy.journal,
            source=source,
        )

    # --- put, in its two shapes ------------------------------------------------------------

    # --- publishing --------------------------------------------------------------------------

    async def discard_staged(self, journal: UploadJournal) -> tuple[bytes, ...]:
        """Remove the staging files a killed run left behind, and clear their records (D-166).

        **Nothing could do this before the journal existed.** Every in-process failure path
        cleans up after itself, but a process that is killed reaches none of them, and the
        staging name it chose carries fresh randomness that nothing can reconstruct -- so the
        file sits in the destination directory forever, hidden by its leading dot, owned by
        nobody. A directory that slowly fills with ``.part`` files is the half of this feature
        a user notices first.

        Safe to call at the start of a run, which is the intended place: it removes only files
        **this journal** recorded staging, never anything it merely found by listing. A sweep
        that globbed for ``.*.part`` would delete another publisher's in-flight upload.

        Args:
            journal: The journal to sweep. Emptied of in-flight records and compacted.

        Returns:
            The staging paths this call actually deleted, in the order it deleted them. A
            record whose file had already gone is cleared and **not** listed -- "removed" is a
            claim about what happened, and reporting a file nobody deleted as deleted is the
            kind of small lie this library's result objects exist to avoid.

        Raises:
            ServerError: If a removal is refused for any reason other than the file being
                absent -- a read-only directory, a permission change. Records already cleared
                stay cleared, because each is written as it happens, so a later sweep retries
                only what is left. That is what an append-only log buys.
        """
        removed: list[bytes] = []
        for entry in journal.in_flight().values():
            try:
                await self.remove(entry.staged)
            except NoSuchFileError:
                # Already gone -- published by a run whose `published` line was lost, or swept
                # by hand. The record is still stale and is still worth clearing.
                pass
            else:
                removed.append(entry.staged)
            journal.published(entry.target)
        _ = journal.compact()
        return tuple(removed)

    # --- trees, the other way ------------------------------------------------------------------

    # Overloaded for the reason :meth:`get_tree` is, and note what `**legacy` does to the
    # narrowing: a caller passing a deprecated publish spelling matches on `dry_run` alone, so
    # the two overloads have to stay distinguishable by that keyword and nothing else.
    @overload
    async def put_tree(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        max_depth: int | None = ...,
        publish: Publish | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        progress: ProgressCallback | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[False] = ...,
        **legacy: bool | bytes | str | None,
    ) -> TreeResult: ...

    @overload
    async def put_tree(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        max_depth: int | None = ...,
        publish: Publish | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        progress: ProgressCallback | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[True],
        **legacy: bool | bytes | str | None,
    ) -> TreePlan: ...

    @overload
    async def put_tree(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        max_depth: int | None = ...,
        publish: Publish | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        progress: ProgressCallback | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: bool,
        **legacy: bool | bytes | str | None,
    ) -> TreeResult | TreePlan: ...

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
        dry_run: bool = False,
        **legacy: bool | bytes | str | None,
    ) -> TreeResult | TreePlan:
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

                **Needs either a journal or ``publish=Publish(atomic=False)``**, and raises
                :exc:`ValueError` with neither. Each file stages under a name generated fresh
                per call, so last run's partials cannot be found again unless something wrote
                them down -- and a ``staging_name`` cannot be fixed for a whole tree. Deriving
                one per file from the target would make it predictable for every file at once,
                which is what :func:`~gantry_sftp.session.staging_token` exists to prevent, so
                that is still refused rather than silently downgraded.

                The two spellings differ in what a consumer can observe. With
                ``publish=Publish(journal=UploadJournal(path))`` the tree keeps atomic
                publishing: each file's random staging name is recorded durably before its
                ``OPEN``, a later process reads them back, and nothing incomplete is ever
                visible at a destination path. With ``publish=Publish(atomic=False)`` there is
                no staging file to find, resuming means resuming the destination files
                themselves, and a consumer polling the directory can see a partial file while
                it happens.
            concurrency: Files uploaded at once. ``1`` -- the default -- keeps the exact
                sequential path this method has always had. See :meth:`get_tree` for what
                concurrency buys, what it cannot lift, what it costs in ordering, and why the
                total across several calls is the caller's and not this argument's.
            dry_run: Report what this call would do and do none of it, returning a
                :class:`TreePlan` instead of a :class:`TreeResult`.

                **The contract is that it makes no writes** -- no ``MKDIR``, no ``OPEN``, no
                ``SETSTAT`` -- and it reads only what the upload would read anyway, which for
                this direction is the local filesystem alone. So the plan is complete about
                everything local: every file, every byte, every skipped entry with its reason,
                and every name that could not be a remote path component, which still raises
                :exc:`UnsafePathError` here exactly as it would in a real run.

                **It is silent about the destination on purpose.** Whether those directories
                already exist, and which files are already there, would cost a round trip per
                entry and is a mirror's question rather than a preview's; asking it here would
                mean two implementations of one comparison. `TreePlan.undetermined` says so in
                as many words rather than leaving the gap to be inferred.

                A different type rather than a ``TreeResult`` with its counters at zero:
                ``transferred == 0`` already means "nothing needed moving", and a preview's
                zero would mean "nothing was attempted".
            **legacy: The publish arguments under their pre-:class:`Publish` names, as
                :meth:`put` accepts them and for the same reason.

        Returns:
            Counts, bytes, and every entry that was skipped with the reason it was -- or a
            :class:`TreePlan` when ``dry_run`` is set.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O -- today,
                Windows. Raised before the walk starts; see :mod:`._platform`.
            UnsafePathError: If a local name could not be a remote path component.
            ValueError: If ``publish`` carries a ``staging_name``, which one tree's many files
                cannot share; if ``resume`` is asked for with atomic publishing and no journal,
                which leaves nothing findable to resume into; if ``publish`` contradicts itself
                the way :meth:`put` refuses; or if ``concurrency`` is below 1 or is above 1
                with a ``progress`` callback. All of them are raised **before the walk starts**,
                so a refused request creates no directory on the server.
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
        _check_tree_publish(policy, resume=resume, caller="put_tree")
        requested_mode = resolve_mode(mode, caller="put_tree()")
        await self._require_rooted_paths(root, feature="uploading a tree")
        if not dry_run:
            await self._mkdir_parents(root, exist_ok=True)
        directories = 0
        planned: list[int] = []
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
                        # The one write in this producer, and the reason `dry_run` is checked
                        # here rather than around the whole loop: everything else in it --
                        # the walk, the component validation that raises `UnsafePathError`,
                        # the skip reasons -- is what a preview exists to report, so a
                        # preview has to run it rather than skip it.
                        if not dry_run:
                            await self.mkdir(remote_directory, exist_ok=True)
                        directories += 1
                        _settle_remote_directory(
                            entry,
                            remote_directory,
                            preserve_times=preserve_times,
                            mode=requested_mode,
                            times=directory_times,
                            modes=directory_modes,
                        )
                    skipped.extend(entry.skipped)
                    for name in entry.files:
                        yield _TreeUpload(
                            entry.path / os.fsdecode(name),
                            join_remote(remote_directory, remote_component(name)),
                        )

            async def transfer(item: _TreeUpload) -> None:
                if dry_run:
                    # A local `stat`, which is free and needs no server -- so an upload plan
                    # reports its byte total in full where a download plan can only report
                    # what the far end volunteered.
                    planned.append(_local_size(item.source))
                    return
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

            if dry_run:
                record["files"] = len(planned)
                record["directories"] = directories
                record["bytes"] = sum(planned)
                record["skipped"] = len(skipped)
                record["dry_run"] = True
                return TreePlan(
                    files=len(planned),
                    directories=directories,
                    bytes_to_transfer=sum(planned),
                    skipped=tuple(skipped),
                    # Every one of these is a consequence of making no writes, and an upload
                    # preview cannot escape any of them: it never asked the server anything.
                    undetermined=(
                        PlanLimit.REMOTE_DIRECTORY_EXISTENCE,
                        PlanLimit.PER_FILE_TRANSFER_DECISIONS,
                        PlanLimit.DESTINATION_COMPARISON,
                    ),
                )

            await _set_directory_times(self, directory_times)
            await _set_directory_modes(self, directory_modes)
            record["files"] = len(moved)
            record["directories"] = directories
            record["bytes"] = sum(moved)
            record["skipped"] = len(skipped)
            return TreeResult(len(moved), directories, sum(moved), tuple(skipped))

    async def sync_tree(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        manifest: Path | str,
        max_depth: int | None = None,
        publish: Publish | None = None,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        progress: ProgressCallback | None = None,
        concurrency: int = 1,
    ) -> SyncResult:
        """Make ``remote_path`` match a local tree, sending only what is not already there.

        **The defining operation is deciding not to transfer something**, and a wrong decision
        leaves a changed file wearing its old contents on the server while this returns a
        successful result. That is why the comparison, not the saving of bytes, is the feature:
        see :mod:`gantry_sftp.session._sync` for the ladder and
        :class:`~gantry_sftp.session.SyncResult` for what comes back.

        **What it compares against is its own record, not the destination's clock** (D-164).
        ``preserve_times`` is off by default, so a file uploaded by :meth:`put_tree` normally
        carries the *upload* time rather than the local one -- comparing those two finds every
        file changed on every run, forever. ``manifest`` is where this library writes what it
        sent, and the comparison is against that. It records **both sides**, so a file changed
        on the server behind us is still detected: a record of the local half alone would skip
        it and leave the destination wrong.

        Three outcomes per file, and the third is the one to read: ``transferred`` differed,
        ``skipped`` was proven identical, and ``undecidable`` **was sent** because this server
        volunteered no size or no modification time for it. Undecidable is not folded into
        either neighbour, because a mirror that quietly re-sends everything and one that quietly
        skips are both things you want to find out about early.

        The remote listing costs nothing extra: v3 returns attributes with ``READDIR``, so one
        listing per directory -- which the walk needs anyway -- carries every size and time the
        comparison reads. Only a file that is actually sent costs a ``STAT`` afterwards, to
        record what the destination ended up holding.

        Not in scope, deliberately, and it is not an oversight: **nothing here deletes.** A file
        on the server that is no longer in the local tree is left alone. Deletion is the one
        mirror operation whose mistakes are unrecoverable, and which of "extraneous" and
        "somebody else's" a remote file is cannot be decided from this side.

        Args:
            local_path: Local directory to mirror from.
            remote_path: Remote directory to mirror into. Created with its missing parents.
            manifest: Where to read and write the record of what was sent -- one JSON record
                per line, appended **as each file lands** and compacted when the run ends, so a
                run killed partway through keeps what it did (D-173). Absent, unreadable, torn
                mid-line or written by a future version all mean "that much is not known",
                which costs a re-send and loses nothing. Opened before the walk starts, so a
                path that cannot be written raises here rather than from inside the walk.
            max_depth: Stop descending below this many levels.
            publish: How each file becomes visible, as :meth:`put` takes it.
            preserve_times: Carry each local file's times across. Independent of the comparison
                -- the record is what makes the mirror work, and this only decides what the
                destination's own metadata says afterwards.
            mode: Permission bits for the files this creates, as :meth:`put` takes them.
            progress: Called as bytes move, for files that are actually sent.
            concurrency: Files in flight at once.

        Returns:
            Counts, the per-file outcomes with the reason for each, and the walk's own skips.

        Raises:
            NotImplementedError: On a platform without offset-addressed local I/O.
            UnsafePathError: If a local name cannot be one remote path component.
            ValueError: If ``publish`` carries a ``staging_name`` or contradicts itself the way
                :meth:`put` refuses, or if ``concurrency`` is below 1 or is above 1 with a
                ``progress`` callback. Raised before the walk starts.
        """
        require_local_io("sync_tree()")
        _check_local_path(local_path, method="sync_tree()")
        _check_tree_concurrency(concurrency, progress=progress, caller="sync_tree")
        root = self._resolve(remote_path)
        policy = publish_from_legacy(publish, {}, caller="sync_tree")
        _check_tree_publish(policy, resume=False, caller="sync_tree")
        requested_mode = resolve_mode(mode, caller="sync_tree()")
        record_file = Path(manifest)
        # Before the first round trip, so a manifest path that cannot be written is reported as
        # what it is rather than by the first worker to reach it (D-173).
        prepare_manifest(record_file)
        await self._require_rooted_paths(root, feature="mirroring a tree")
        await self._mkdir_parents(root, exist_ok=True)

        recorded = SyncManifest.load(record_file)
        directories = 0
        outcomes: list[SyncOutcome] = []
        walk_skipped: list[Skipped] = []
        directory_times: list[tuple[bytes, Times]] = []
        directory_modes: list[tuple[bytes, int]] = []

        with operation(session_logger, "sync_tree", local=local_path, remote=root) as record:

            async def produce() -> AsyncGenerator[_SyncCandidate]:
                """Create each directory, list it once, and decide about every file in it.

                The listing happens **after** the ``mkdir``, which is what makes it total: the
                directory is there by the time it is read, so a missing one is not a case this
                has to tell apart from an empty one.
                """
                nonlocal directories
                for entry in walk_local(Path(local_path), max_depth=max_depth):
                    remote_directory = _remote_directory(root, entry.relative)
                    if entry.relative:
                        await self.mkdir(remote_directory, exist_ok=True)
                        directories += 1
                        _settle_remote_directory(
                            entry,
                            remote_directory,
                            preserve_times=preserve_times,
                            mode=requested_mode,
                            times=directory_times,
                            modes=directory_modes,
                        )
                    walk_skipped.extend(entry.skipped)
                    present = await self._listing_by_name(remote_directory)
                    for candidate in candidates_in(
                        entry, remote_directory, present, recorded, outcomes
                    ):
                        yield candidate

            async def transfer(item: _SyncCandidate) -> None:
                result = await self.put(
                    item.source,
                    item.remote,
                    publish=policy,
                    preserve_times=preserve_times,
                    mode=requested_mode,
                    progress=progress,
                )
                outcomes.append(
                    SyncOutcome(
                        item.remote,
                        item.verdict.decision,
                        item.verdict.reason,
                        result.transferred,
                    )
                )
                landed = await self.stat(item.remote)
                entry = manifest_entry_for(item.source, landed)
                if entry is not None:
                    # **Appended as the file lands, not collected for the end** (D-173). A run
                    # killed partway through used to keep nothing, so the next one re-sent the
                    # whole tree -- and on a mirror large enough to be interrupted, that is
                    # every run. One `os.write` to an `O_APPEND` descriptor, which is also why
                    # several workers finishing inside one another's awaits is no longer
                    # something a collected list has to protect against.
                    append_record(record_file, item.remote, entry)
                    recorded.record(item.remote, entry)

            await for_each_bounded(produce(), transfer, concurrency=concurrency)

            await _set_directory_times(self, directory_times)
            await _set_directory_modes(self, directory_modes)
            # Compaction, so the log does not grow across runs. Interrupted before here, the
            # appended records are what the next run reads.
            recorded.save(record_file)

            report = summarise(outcomes, directories=directories, walk_skipped=walk_skipped)
            record["files"] = report.transferred
            record["directories"] = directories
            record["bytes"] = report.bytes_transferred
            record["skipped"] = report.skipped
            record["undecidable"] = report.undecidable
            return report

    async def _listing_by_name(self, directory: bytes) -> dict[bytes, Attrs]:
        """One directory's entries, by filename, as the comparison reads them.

        A ``dict`` rather than a scan the caller iterates, because the mirror asks about names
        it got from the *local* walk and needs random access. One ``READDIR`` sequence per
        directory either way, and the attributes ride along with it -- which is the whole reason
        the comparison costs no round trips of its own.
        """
        async with self.scandir(directory) as scan:
            return {entry.filename: entry.attrs async for entry in scan}

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
        ProtocolError: If the server negotiates a filexfer version other than 3. Both
            directions of that are refused and the message says which happened: a server
            answering *below* 3 is obeying ``draft-ietf-secsh-filexfer-02`` 4 and is simply not
            usable by this client, and one answering *above* 3 is violating it. Neither can be
            spoken to with a v3 decoder, so the connection ends here rather than at whichever
            later packet the layout difference happened to corrupt.
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
    documentation promises timeouts on every wait (``docs/reliability.md``).

    The deadline spans the handshake rather than each chunk of it: per-chunk would let a
    server dribble one byte at a time indefinitely and never trip, which is a hang wearing a
    timeout's clothes.

    **The version itself is the codec's to judge, not this function's**, and it is judged --
    :meth:`~gantry_sftp.codec.Codec.receive` refuses anything but 3. It belongs there because
    that is the layer that would misparse: a v4 ATTRS carries a ``byte type`` this decoder has
    no place for. What this function has to get right is only that the refusal travels as the
    ``ProtocolError`` it is, rather than being swallowed into the ``TimeoutError`` handler
    below and reported as a server that went quiet.
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

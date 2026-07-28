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
import os
from collections.abc import AsyncGenerator, Mapping
from contextlib import aclosing, asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import override

import anyio

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    EXTENSION_FSYNC,
    EXTENSION_POSIX_RENAME,
    LIMITS_NAME,
    POSIX_RENAME_NAME,
    Attrs,
    AttrsReply,
    CheckFile,
    CheckFileReply,
    Close,
    Codec,
    CodecState,
    Completed,
    Fsync,
    Handle,
    LStat,
    MkDir,
    Name,
    Open,
    OpenDir,
    OpenFlag,
    PosixRename,
    ReadDir,
    RealPath,
    Remove,
    Rename,
    Request,
    Response,
    RmDir,
    Stat,
    Status,
    StatusCode,
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
    PermissionDeniedError,
    ProtocolError,
    ServerError,
    SFTPError,
    StateError,
    TransferError,
    TransferTimeoutError,
    UnsupportedError,
    flatten_exception_group,
)
from gantry_sftp.session._dispatch import Dispatcher
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    NO_FOLLOW,
    ProgressCallback,
    download_handle,
)
from gantry_sftp.session._limits import ServerLimits, TransferSizes, negotiate_transfer_sizes
from gantry_sftp.session._listing import DOT_ENTRIES, DirEntry, EntryKind, entry_kind
from gantry_sftp.session._localpath import check_contained, local_child
from gantry_sftp.session._localtree import remote_component, walk_local
from gantry_sftp.session._publish import (
    Durability,
    PublishMechanism,
    SizeCheck,
    UploadResult,
    split_parent,
    staged_path,
    staging_token,
)
from gantry_sftp.session._quirks import ServerProfile, identify
from gantry_sftp.session._recursive import (
    Skipped,
    SkipReason,
    TreeResult,
    WalkEntry,
    join_remote,
)
from gantry_sftp.session._upload import upload_handle
from gantry_sftp.transport import Transport

__all__ = ["DEFAULT_REQUEST_TIMEOUT", "LIMITS_EXTENSION", "Session", "open_session"]

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


class Session:
    """An SFTP conversation with one server.

    Built by :func:`open_session`, which owns the handshake, starts the reader task every
    operation depends on, and makes sure the connection is torn down. Constructing one
    directly is not supported: a session without a running reader accepts requests and never
    answers them.

    Args:
        dispatcher: The connection's single reader, already running.
        limits: What the server said it would accept, or all-``None``.
        request_timeout: Seconds for one one-shot request.
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

    @property
    def limits(self) -> ServerLimits:
        """What the server said it will accept, or all-``None`` if it said nothing."""
        return self._limits

    @property
    def extensions(self) -> Mapping[bytes, bytes]:
        """Extensions the server advertised. Frequently empty, which is not an error."""
        return self._codec.extensions

    @property
    def server_version(self) -> int | None:
        """Protocol version negotiated."""
        return self._codec.server_version

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
        """
        return (
            f"<Session server={self._profile.label} version={self._codec.server_version} "
            f"extensions={len(self._codec.extensions)} depth={self._depth} "
            f"outstanding={self._codec.outstanding} "
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

        Advertisement only. Absence is not proof: DESIGN.md 4.2 makes capability detection
        advertisement **plus** an optional probe, because endpoints implement extensions they
        never list -- and the probe is only ever sent for read-only or idempotent ones, since
        you do not discover ``posix-rename`` support by renaming something.

        Args:
            extension: Wire name, as ``bytes`` or as one of the ``EXTENSION_*`` constants.
        """
        name = extension.encode("ascii") if isinstance(extension, str) else extension
        return name in self._codec.extensions

    # --- operations ----------------------------------------------------------------------

    async def stat(self, path: bytes | str) -> Attrs:
        """Attributes of ``path``, following symlinks.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        encoded = _encode_path(path)
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
        encoded = _encode_path(path)
        reply = await self.request(LStat(self._next(), encoded))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS", path=encoded)

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

        Raises:
            ProtocolError: If the server answers with something other than a NAME, or with a
                NAME carrying any number of names other than one.
            NoSuchFileError: If the server refuses because the path does not exist.
            ServerError: For any other refusal.
        """
        encoded = _encode_path(path)
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

    async def open(self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ) -> bytes:
        """Open a remote file and return its handle."""
        encoded = _encode_path(path)
        reply = await self.request(Open(self._next(), encoded, pflags, EMPTY_ATTRS))
        if isinstance(reply, Handle):
            return reply.handle
        raise _unexpected(reply, expected="HANDLE", path=encoded)

    async def opendir(self, path: bytes | str) -> bytes:
        """Open a remote directory and return its handle.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: If it is not a directory, or the server refuses.
        """
        encoded = _encode_path(path)
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
        return DirectoryScan(self, _encode_path(path))

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
        encoded = _encode_path(path)
        try:
            await self._expect_status(MkDir(self._next(), encoded, EMPTY_ATTRS), path=encoded)
        except ServerError:
            if not exist_ok or not await self._is_directory(encoded):
                raise

    async def _is_directory(self, path: bytes) -> bool:
        """Whether the server positively reports ``path`` as a directory.

        ``LSTAT``, so a symlink is not mistaken for what it points at, and every failure --
        including a server that sends no permissions at all -- answers ``False``. Used to
        decide whether a refusal can be excused, and "the server would not say" is not an
        excuse.
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
        encoded = _encode_path(path)
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
        encoded = _encode_path(path)
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
        encoded = _encode_path(new_path)
        await self._expect_status(
            Rename(self._next(), _encode_path(old_path), encoded), path=encoded
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
        encoded = _encode_path(new_path)
        request = PosixRename(self._next(), _encode_path(old_path), encoded)
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
        block_size: int = 0,
    ) -> tuple[bytes, tuple[bytes, ...]]:
        """Ask the server to hash a file it already has, without moving the bytes again.

        Rung 1 of DESIGN.md 6's verification ladder, and the only rung that verifies
        *content* rather than byte count. **Most servers do not have it** -- OpenSSH answers
        ``OP_UNSUPPORTED`` under all three spellings, measured -- so a caller that needs
        verification everywhere still falls back to rung 3, a size check, and is told so
        rather than left to assume.

        The digest count is not on the wire: the server sends one digest per block,
        concatenated, and how many that is follows from ``block_size`` and the digest size of
        whichever algorithm it picked. That size comes from ``hashlib`` here, so an algorithm
        this Python does not know is an error rather than a silently mis-split answer.

        Args:
            handle: An **open** file handle, from :meth:`open`. Not a path -- paramiko's
                spelling of this extension takes a handle, and answers ``BAD_MESSAGE`` for
                one it does not recognise.
            algorithms: Preference order as a name-list. The server picks the first it
                supports and names its choice in the reply.
            start_offset: First byte to hash.
            length: Bytes to hash, or ``0`` for the rest of the file.
            block_size: Bytes per digest, or ``0`` for a single digest over the whole range.
                Paramiko refuses anything between 1 and 255, so this is ``0`` or ``>= 256``.

        Returns:
            The algorithm the server chose, and one digest per block.

        Raises:
            UnsupportedError: If the server does not implement the extension.
            ServerError: If it refuses -- including ``FAILURE`` when it supports none of the
                algorithms offered, and ``BAD_MESSAGE`` for an unknown handle.
            ProtocolError: If the reply is not a well-formed check-file answer, or names an
                algorithm whose digest size does not divide the bytes it sent.
        """
        request = CheckFile(
            self._next(),
            handle,
            algorithms=algorithms,
            start_offset=start_offset,
            length=length,
            block_size=block_size,
        )
        reply = await self.request(request.to_extended())
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

        Returns:
            Bytes written **by this call**. On a resume that is the remainder, not the file's
            size, and on a resume of an already-complete file it is ``0``.

        Raises:
            NoSuchFileError: If the remote path does not exist.
            ServerError: If the server refuses.
            TransferError: If the transfer fails partway, if ``resume`` cannot establish a
                safe offset, or if ``verify_size`` finds fewer bytes arrived than the server
                said there were.
        """
        encoded = _encode_path(remote_path)
        attributes = await self.stat(encoded)
        start = _download_resume_offset(local_path, attributes.size, encoded) if resume else 0
        if resume and start == attributes.size:
            # Already complete. Nothing to open, nothing to move, and saying so costs one
            # STAT rather than a transfer that writes nothing.
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
            )
        except BaseException:
            # Closing is not optional: a leaked handle counts against max-open-handles and is
            # invisible from this side until the server starts refusing to open anything. It
            # must not replace the transfer's error with one about the close, though -- the
            # first error is the diagnosis and the second is housekeeping.
            await _close_quietly(self, handle)
            raise
        await self.close(handle)
        # Rung 3, and it costs no round trip: the STAT above is the one `get` already makes.
        # `start + transferred` rather than `transferred`, because a resume returns only the
        # remainder and comparing that against the whole file would fail every resume.
        if verify_size and attributes.size is not None and start + transferred != attributes.size:
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
    ) -> int:
        """Open the local destination and let the scheduler fill it.

        The open lives here rather than in the scheduler because the flags are a safety
        decision: ``O_NOFOLLOW`` where a recursive download must not write through a link
        somebody planted in the destination tree, and mode 0600 so a file is never briefly
        world-readable while it is being written.

        ``O_TRUNC`` is dropped when resuming, and that is the whole of the local-side change:
        writes already go to explicit offsets, so keeping the first ``start_offset`` bytes is
        a matter of not deleting them.
        """
        flags = _LOCAL_WRITE_FLAGS if not start_offset else _LOCAL_RESUME_FLAGS
        fd = os.open(local_path, flags | (NO_FOLLOW if no_follow else 0), 0o600)
        try:
            return await download_handle(
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
        finally:
            os.close(fd)

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
            ServerError: If the server refuses a listing.
        """
        root = _encode_path(path)
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

    async def get_tree(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        max_depth: int | None = None,
        progress: ProgressCallback | None = None,
    ) -> TreeResult:
        """Download a remote tree into ``local_path``, refusing to escape it.

        **Every name the server supplies is validated before it becomes a path**, and the
        finished path is re-checked against the destination after symlinks are resolved. A
        server answering ``../../etc/cron.d/x`` gets an
        :class:`~gantry_sftp.exceptions.UnsafePathError` and nothing is written -- this is the
        zip-slip class, and it is a real and exploited pattern in file-transfer clients.

        Transfers are sequential **here**, which is no longer a property of the session. The
        session multiplexes, so a caller who wants files to overlap can fan out over
        :meth:`get` with a task group today. What this method does not yet have is a
        ``concurrency`` parameter of its own, because a walk that runs ahead of its transfers
        needs bounded back-pressure, and a progress callback reporting per file means little
        when several files report at once. Registered rather than implied.

        Args:
            remote_path: Remote directory to copy.
            local_path: Local destination. Created if absent, and everything is confined to it.
            max_depth: Levels below the root to descend, or ``None`` for no limit.
            progress: Called with ``(transferred, total)`` per file, so ``total`` resets for
                each one. A tree-wide total would need the whole walk up front.

        Returns:
            Counts, bytes, and every entry that was skipped with the reason it was.

        Raises:
            UnsafePathError: If a server-supplied name would escape the destination.
            NoSuchFileError: If the remote directory does not exist.
            ServerError: If the server refuses.
            TransferError: If a transfer fails partway.
        """
        destination = _ensure_directory(Path(local_path), parents=True)
        files = directories = transferred = 0
        skipped: list[Skipped] = []

        # aclosing, because the common exit from this loop is an exception -- a refused name,
        # a failed transfer -- and a suspended async generator that is merely dropped is left
        # to the garbage collector, which trio will not finalise for it.
        async with aclosing(self.walk(remote_path, max_depth=max_depth)) as walker:
            async for entry in walker:
                local_directory = _local_directory(destination, entry.relative)
                if entry.relative:
                    _ = _ensure_directory(local_directory)
                    directories += 1
                skipped.extend(entry.skipped)
                for child in entry.files:
                    target = check_contained(
                        destination, local_child(local_directory, child.filename)
                    )
                    transferred += await self.get(
                        join_remote(entry.path, child.filename),
                        target,
                        progress=progress,
                        no_follow=True,
                    )
                    files += 1

        return TreeResult(files, directories, transferred, tuple(skipped))

    async def put(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        atomic: bool = True,
        fsync: bool = True,
        require_atomic: bool = False,
        require_fsync: bool = False,
        staging_name: bytes | str | None = None,
        resume: bool = False,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
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
            atomic: Publish via a staging file and a rename. ``False`` writes the destination
                in place, which is what every other SFTP client does by default and is the
                behaviour a write-only drop directory may require, since staging needs the
                right to create *and* rename a second name. In place also means a failure
                leaves the destination truncated: there is no copy to fall back to, which is
                the other half of what atomic publish buys.
            fsync: Send ``fsync@openssh.com`` before publishing. Silently unavailable on a
                server without it, which the result reports as
                :attr:`~gantry_sftp.session.Durability.UNAVAILABLE`.
            require_atomic: Fail rather than fall back to a mechanism with a window in which
                the destination is missing or partial.
            require_fsync: Fail rather than publish with no durability barrier.
            staging_name: Override the staging file's name. A bare name is resolved as a
                sibling of the destination; a value containing ``/`` is used verbatim and must
                be on the same filesystem. For servers that forbid dot-files or mandate a
                staging directory -- and the only way to make ``resume`` possible under
                ``atomic``, since the default staging name is deliberately unguessable.
            resume: Continue an interrupted upload from the size the server reports, instead
                of sending the file again. **Off by default, and it is the weaker of the two
                directions.** A size match proves the byte *count* agrees and nothing else:
                the remote partial may be from a different run, a different source file, or a
                concurrent writer, and there is no cheap way to tell from here. See
                :meth:`get` for the download side, where the partial is on local disk and the
                claim is correspondingly stronger.

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
            progress: Called with ``(transferred, total)`` as writes are acknowledged. On a
                resume the first call reports the offset it started from, not zero.
            depth: Requests in flight, overriding the session default. Each one holds a full
                payload in memory, so this costs more here than on the download side.

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
            ValueError: If a ``require_*`` flag contradicts the flag it strengthens.
            CapabilityError: If a required guarantee is not available on this server.
            PermissionDeniedError: If the server will not create or write the file.
            ServerError: For any other refusal.
            TransferError: If the transfer fails partway, or if the published length
                disagrees with the local file's.
        """
        target = _encode_path(remote_path)
        _check_publish_flags(
            atomic=atomic,
            fsync=fsync,
            require_atomic=require_atomic,
            require_fsync=require_fsync,
            resume=resume,
            staging_name=staging_name,
        )
        if require_fsync and not self.supports(EXTENSION_FSYNC):
            refusal = CapabilityError(
                f"require_fsync=True but this server does not advertise {EXTENSION_FSYNC}, "
                f"so nothing can promise the bytes reached stable storage",
                feature="durable upload",
                missing=(EXTENSION_FSYNC,),
                path=target,
            )
            refusal.add_note(self._server_note())
            raise refusal

        upload = _Upload(
            local_path=local_path,
            fsync=fsync,
            require_fsync=require_fsync,
            progress=progress,
            depth=depth,
            resume=resume,
        )
        if not atomic:
            return await self._put_in_place(upload, target)
        staged = staged_path(target, staging_token(), name=_optional_path(staging_name))
        return await self._put_atomically(upload, target, staged, require_atomic=require_atomic)

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
        handle = await self.open(target, _RESUME_FLAGS if upload.resume else _TRUNCATE_FLAGS)
        transferred, durability = await self._fill_and_close(
            upload, handle, target, start_offset=start
        )
        # After the fact, necessarily: in place, the destination *is* the file being written,
        # so there is no earlier moment at which a short write could have been caught. That is
        # the same trade `atomic=False` already makes, and it is why the atomic path checks
        # the staging file instead.
        size_check = await self._confirm_size(target, _local_size(upload.local_path))
        return UploadResult(transferred, target, PublishMechanism.IN_PLACE, durability, size_check)

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
        handle = await self._open_staging_file(staged, target, resume=upload.resume)
        try:
            transferred, durability = await self._fill_and_close(
                upload, handle, staged, start_offset=start
            )
            # Before the rename, deliberately. Checking the *destination* afterwards would
            # report a truncation that consumers can already see, which is the failure atomic
            # publish exists to prevent; checking the staging file means a short upload never
            # becomes the destination at all. A mismatch raises into the cleanup path below,
            # so the staging file goes and the destination is left alone.
            size_check = await self._confirm_size(staged, _local_size(upload.local_path))
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
        return UploadResult(transferred, target, mechanism, durability, size_check, staged)

    async def _open_staging_file(self, staged: bytes, target: bytes, *, resume: bool) -> bytes:
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
        """
        try:
            return await self.open(staged, _RESUME_FLAGS if resume else _STAGE_FLAGS)
        except SFTPError as refusal:
            refusal.add_note(
                f"{staged!r} is the staging file for {target!r}. Publishing atomically needs "
                f"the right to create and rename a second name in that directory, and a name "
                f"that is not already taken -- pass atomic=False to write the destination "
                f"directly instead, or staging_name= to put the staging file elsewhere."
            )
            raise

    async def _fill_and_close(
        self, upload: _Upload, handle: bytes, path: bytes, *, start_offset: int = 0
    ) -> tuple[int, Durability]:
        """Push the file through an open handle, flush it, and close it.

        The flush happens while the handle is still open, because that is the only time it
        can: ``fsync@openssh.com`` on a closed handle answers ``NO_SUCH_FILE``.
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
            durability = await self._flush(upload, handle)
        except BaseException:
            # Closing is not optional -- a leaked handle counts against max-open-handles and
            # is invisible from this side until the server refuses to open anything. But it
            # must not replace the error that got us here with one about the close.
            await _close_quietly(self, handle)
            raise
        await self.close(handle)
        return transferred, durability

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

    async def _flush(self, upload: _Upload, handle: bytes) -> Durability:
        """Flush the handle, reporting what was possible rather than promising what was not."""
        if not upload.fsync:
            return Durability.SKIPPED
        if not self.supports(EXTENSION_FSYNC):
            return Durability.UNAVAILABLE
        try:
            await self.fsync(handle)
        except ServerError:
            # Advertised and then refused. The bytes may still be in a cache, which the
            # result says; a caller who cannot accept that asked for require_fsync.
            if upload.require_fsync:
                raise
            return Durability.UNAVAILABLE
        return Durability.FSYNCED

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
        if POSIX_RENAME_NAME in self._unsupported:
            return False
        advertised = self.supports(EXTENSION_POSIX_RENAME)
        try:
            await self.posix_rename(staged, target)
        except UnsupportedError:
            self._unsupported.add(POSIX_RENAME_NAME)
            return False
        except ServerError:
            if advertised:
                raise
            return False
        return True

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
        atomic: bool = True,
        fsync: bool = True,
        require_atomic: bool = False,
        require_fsync: bool = False,
        progress: ProgressCallback | None = None,
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

        Transfers are sequential here, for the same reason :meth:`get_tree`'s are -- and with
        the same escape, a task group over :meth:`put`.

        Args:
            local_path: Local directory to copy. Followed if it is itself a symlink, because
                the caller named it; nothing inside it is.
            remote_path: Remote destination. Created, with any missing parents, if absent.
            max_depth: Levels below the root to descend, or ``None`` for no limit.
            atomic: Publish each file via a staging file and a rename. See :meth:`put`.
            fsync: Send ``fsync@openssh.com`` before publishing each file.
            require_atomic: Fail rather than fall back to a mechanism with a window.
            require_fsync: Fail rather than publish with no durability barrier.
            progress: Called with ``(transferred, total)`` per file, so ``total`` resets for
                each one. A tree-wide total would need the whole walk up front.

        Returns:
            Counts, bytes, and every entry that was skipped with the reason it was.

        Raises:
            UnsafePathError: If a local name could not be a remote path component.
            OSError: If a local directory or file cannot be read.
            CapabilityError: If a required guarantee is not available on this server.
            ServerError: If the server refuses a directory or a file.
            TransferError: If a transfer fails partway.
        """
        root = _encode_path(remote_path)
        await self._mkdir_parents(root)
        files = directories = transferred = 0
        skipped: list[Skipped] = []

        for entry in walk_local(Path(local_path), max_depth=max_depth):
            remote_directory = _remote_directory(root, entry.relative)
            if entry.relative:
                await self.mkdir(remote_directory, exist_ok=True)
                directories += 1
            skipped.extend(entry.skipped)
            for name in entry.files:
                result = await self.put(
                    entry.path / os.fsdecode(name),
                    join_remote(remote_directory, remote_component(name)),
                    atomic=atomic,
                    fsync=fsync,
                    require_atomic=require_atomic,
                    require_fsync=require_fsync,
                    progress=progress,
                )
                transferred += result.transferred
                files += 1

        return TreeResult(files, directories, transferred, tuple(skipped))

    async def _mkdir_parents(self, path: bytes) -> None:
        """Create ``path`` and any missing ancestors, cheaply in the common case.

        One ``MKDIR`` when the directory is already there or its parent is, and a walk up the
        path only when a level is genuinely absent. The alternative -- creating every ancestor
        unconditionally -- is a round trip per level of the destination on every call, paid by
        every caller to help the one whose destination was three levels missing.
        """
        try:
            await self.mkdir(path, exist_ok=True)
        except ServerError:
            parent, _ = split_parent(path)
            stripped = parent.rstrip(b"/")
            if not stripped or stripped == path:
                raise
            await self._mkdir_parents(stripped)
            await self.mkdir(path, exist_ok=True)

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
        root = _encode_path(path)
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

        return TreeResult(files, directories, 0, ())

    # --- cleanup ------------------------------------------------------------------------------

    async def _discard(self, staged: bytes, error: BaseException) -> None:
        """Remove a staging file after a failure, and say so if that did not work.

        Shielded from cancellation, because a cancelled nine-gigabyte upload is precisely
        when a staging file gets left behind, and it is still bounded: every request carries
        ``request_timeout``, so a dead connection cannot make cleanup hang.

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


def _optional_path(path: bytes | str | None) -> bytes | None:
    """Encode a path that may be absent, keeping ``None`` distinct from an empty name."""
    return None if path is None else _encode_path(path)


def _encode_path(path: bytes | str) -> bytes:
    """Paths go on the wire as bytes.

    ``str`` is encoded with ``surrogateescape`` so a name that came back from the server as
    invalid UTF-8, was decoded leniently, and is now being sent again survives the round
    trip unchanged. Server-supplied names are frequently not valid UTF-8, and a client that
    cannot re-send what it was just given cannot operate on those files at all.
    """
    return path if isinstance(path, bytes) else path.encode("utf-8", "surrogateescape")


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

    Args:
        transport: A connected transport. Its lifetime is the caller's; this only drives it.
        request_timeout: Seconds for the handshake and each one-shot request.
        idle_timeout: Seconds of total silence during a bulk transfer.
        depth: Default requests in flight per transfer.

    Yields:
        A negotiated session, usable from several tasks at once.

    Raises:
        TransferTimeoutError: If the server never sends VERSION.
        ConnectError: If the transport fails, carrying the child's stderr.
    """
    codec = Codec()
    await transport.send(codec.initiate())
    await _await_version(transport, codec, request_timeout)
    limits = await _probe_limits(transport, codec, request_timeout)

    dispatcher = Dispatcher(transport, codec)
    try:
        async with anyio.create_task_group() as reader:
            _ = reader.start_soon(dispatcher.run)
            try:
                yield Session(
                    dispatcher,
                    limits,
                    request_timeout=request_timeout,
                    idle_timeout=idle_timeout,
                    depth=depth,
                )
            finally:
                # Cancelling is the only way to stop a task parked in `transport.receive()`.
                # `close()` first so that anything still trying to send during teardown gets
                # a StateError naming the reason rather than hanging on a dead reader.
                dispatcher.close()
                reader.cancel_scope.cancel()
    except BaseExceptionGroup as group:
        raise flatten_exception_group(group) from None


async def _read_version(transport: Transport, codec: Codec) -> None:
    while codec.state is not CodecState.READY:
        codec.receive(await transport.receive())


async def _await_version(transport: Transport, codec: Codec, deadline: float | None) -> None:
    """Wait for the server's VERSION, within a deadline covering the whole handshake.

    Without this, a server that completes the connection and then says nothing hangs the
    caller forever -- which is exactly what an unattended job must not do, because nothing
    ever reports it.

    The deadline spans the handshake rather than each chunk of it: per-chunk would let a
    server dribble one byte at a time indefinitely and never trip, which is a hang wearing a
    timeout's clothes.
    """
    if deadline is None:
        await _read_version(transport, codec)
        return
    try:
        with anyio.fail_after(deadline):
            await _read_version(transport, codec)
    except TimeoutError as exc:
        raise TransferTimeoutError(f"server did not send VERSION within {deadline}s") from exc

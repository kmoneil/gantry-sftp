"""The session: what a user actually calls.

Ties a transport and a codec together, performs the handshake, probes what the server can
do, and exposes operations in terms of paths and files rather than packets and request ids.

Concurrency, honestly
---------------------
A session serialises its operations behind a lock. SFTP multiplexes fine over one channel --
that is what request ids are for -- but exploiting it needs a single reader task dispatching
replies to per-request waiters, and the downloader currently drives its own receive loop.
Serialising is the honest intermediate: two coroutines calling this session get correct
results in some order, rather than two receive loops stealing each other's frames. Turning
that into real per-file concurrency is registered as deferred work, not pretended away.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
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
    Close,
    Codec,
    CodecState,
    Completed,
    Fsync,
    Handle,
    LStat,
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
    TransferTimeoutError,
    UnsupportedError,
)
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    ProgressCallback,
    download_handle,
)
from gantry_sftp.session._limits import ServerLimits, TransferSizes, negotiate_transfer_sizes
from gantry_sftp.session._listing import DOT_ENTRIES, DirEntry
from gantry_sftp.session._publish import (
    Durability,
    PublishMechanism,
    UploadResult,
    staged_path,
    staging_token,
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

_TRUNCATE_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
"""Open flags for writing a file in place: create it, or replace what is there."""

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
    """Internal signal: the destination is gone and the staging file is all that is left.

    Raised only from the ``REMOVE``-then-``RENAME`` fallback, when the remove succeeded and
    the rename after it did not -- a concurrent writer recreating the destination in between
    is enough, since v3 ``RENAME`` refuses an existing target. The normal cleanup would then
    delete the staging file, which at that moment holds the *only* copy of the data, turning a
    recoverable failure into an unrecoverable one.

    Never escapes the session: it is unwrapped at the boundary and the original refusal is
    what the caller sees, with a note saying where the file is.
    """

    def __init__(self, failure: BaseException) -> None:
        super().__init__("the destination was removed and the staged file could not replace it")
        self.failure = failure


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


class Session:
    """An SFTP conversation with one server.

    Built by :func:`open_session`, which owns the handshake and makes sure the connection is
    torn down.
    """

    def __init__(
        self,
        transport: Transport,
        codec: Codec,
        limits: ServerLimits,
        *,
        request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
        idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
        depth: int = DEFAULT_PIPELINE_DEPTH,
    ) -> None:
        self._transport = transport
        self._codec = codec
        self._limits = limits
        self._request_timeout = request_timeout
        self._idle_timeout = idle_timeout
        self._depth = depth
        self._lock = anyio.Lock()
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

    @override
    def __repr__(self) -> str:
        """Report the tunables a slow transfer would make you want to check."""
        return (
            f"<Session version={self._codec.server_version} "
            f"extensions={len(self._codec.extensions)} depth={self._depth} "
            f"request_timeout={self._request_timeout} idle_timeout={self._idle_timeout}>"
        )

    def sizes_for(self, handle: bytes) -> TransferSizes:
        """Payload size per request for a given handle.

        The handle is part of every request header, so its length is part of the budget --
        OpenSSH's are four bytes and nothing promises another server's are.
        """
        return negotiate_transfer_sizes(self._limits, handle_length=len(handle))

    # --- one round trip ------------------------------------------------------------------

    async def _round_trip(self, request: Request) -> Response:
        """Send one request and wait for the reply that matches it."""
        await self._transport.send(self._codec.send(request))
        while True:
            for event in self._codec.receive(await self._transport.receive()):
                if isinstance(event, Completed) and event.request.request_id == request.request_id:
                    return event.response

    async def request(self, request: Request) -> Response:
        """Send a request and return its reply, serialised against other operations.

        The deadline covers the whole round trip rather than each chunk of it. Per-chunk
        would let a server dribble a byte at a time and never time out, which is a hang
        wearing a timeout's clothes.

        Raises:
            TransferTimeoutError: If the reply does not arrive in ``request_timeout``.
        """
        async with self._lock:
            if self._request_timeout is None:
                return await self._round_trip(request)
            try:
                with anyio.fail_after(self._request_timeout):
                    return await self._round_trip(request)
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
        """
        encoded = _encode_path(path)
        reply = await self.request(RealPath(self._next(), encoded))
        if isinstance(reply, Name) and reply.entries:
            return reply.entries[0].filename
        raise _unexpected(reply, expected="NAME", path=encoded)

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

        Returns:
            The batch, or ``None`` once the server answers ``EOF``.

        Raises:
            ServerError: If the server refuses.
        """
        reply = await self.request(ReadDir(self._next(), handle))
        if isinstance(reply, Name):
            return tuple(DirEntry.from_name_entry(entry) for entry in reply.entries)
        if isinstance(reply, Status):
            if reply.code is StatusCode.EOF:
                return None
            raise_for_status(reply)
        raise _unexpected(reply, expected="NAME")

    async def listdir(self, path: bytes | str) -> list[DirEntry]:
        """List a directory, following the batches to the end.

        ``.`` and ``..`` are excluded, because every caller wants them gone and the one who
        forgets writes a recursion that never terminates. OpenSSH sends both; a server that
        does not needs no special case.

        The whole listing is accumulated in memory. For an ordinary directory that is what
        you want; for a directory with millions of entries, or a server willing to answer
        READDIR forever, it is a memory cost this cannot bound without also breaking the
        legitimate large case. Streaming lands with ``walk()``; the trade-off is registered
        rather than hidden.

        Args:
            path: Remote directory.

        Returns:
            Entries in the order the server sent them, which is not guaranteed to be sorted.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: If it is not a directory, or the server refuses.
        """
        handle = await self.opendir(path)
        entries: list[DirEntry] = []
        try:
            while (batch := await self.readdir(handle)) is not None:
                entries.extend(entry for entry in batch if entry.filename not in DOT_ENTRIES)
        except BaseException:
            await self._close_quietly(handle)
            raise
        await self.close(handle)
        return entries

    async def close(self, handle: bytes) -> None:
        """Close a remote handle.

        Not merely bookkeeping: some servers report a write failure here rather than on the
        WRITE that caused it, so a CLOSE that returns an error is the transfer failing.
        """
        await self._expect_status(Close(self._next(), handle))

    async def remove(self, path: bytes | str) -> None:
        """Delete a file. Not a directory -- that is ``RMDIR``, which does not exist yet.

        Raises:
            NoSuchFileError: If the path is not there.
            ServerError: For any other refusal.
        """
        encoded = _encode_path(path)
        await self._expect_status(Remove(self._next(), encoded), path=encoded)

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

    async def get(
        self,
        remote_path: bytes | str,
        local_path: Path | str,
        *,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
    ) -> int:
        """Download ``remote_path`` to ``local_path``.

        The size is taken from a STAT so the transfer is bounded and the progress callback
        has a total to report against. A server that declines to report one is fine -- the
        download reads until EOF instead, at the cost of one extra round trip.

        Args:
            remote_path: Path on the server.
            local_path: Local destination. Created or truncated.
            progress: Called with ``(transferred, total)`` as data arrives.
            depth: Requests in flight, overriding the session default.

        Returns:
            Bytes written.

        Raises:
            NoSuchFileError: If the remote path does not exist.
            ServerError: If the server refuses.
            TransferError: If the transfer fails partway.
        """
        encoded = _encode_path(remote_path)
        attributes = await self.stat(encoded)
        handle = await self.open(encoded, OpenFlag.READ)
        try:
            async with self._lock:
                transferred = await download_handle(
                    self._transport,
                    self._codec,
                    handle,
                    local_path,
                    size=attributes.size,
                    read_length=self.sizes_for(handle).read_length,
                    depth=self._depth if depth is None else depth,
                    idle_timeout=self._idle_timeout,
                    progress=progress,
                    remote_path=encoded,
                )
        except BaseException:
            # Closing is not optional: a leaked handle counts against max-open-handles and is
            # invisible from this side until the server starts refusing to open anything. It
            # must not replace the transfer's error with one about the close, though -- the
            # first error is the diagnosis and the second is housekeeping.
            await self._close_quietly(handle)
            raise
        await self.close(handle)
        return transferred

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
                staging directory.
            progress: Called with ``(transferred, total)`` as writes are acknowledged.
            depth: Requests in flight, overriding the session default. Each one holds a full
                payload in memory, so this costs more here than on the download side.

        Returns:
            What actually happened, including which publish mechanism was used.

        Raises:
            ValueError: If a ``require_*`` flag contradicts the flag it strengthens.
            CapabilityError: If a required guarantee is not available on this server.
            PermissionDeniedError: If the server will not create or write the file.
            ServerError: For any other refusal.
            TransferError: If the transfer fails partway.
        """
        target = _encode_path(remote_path)
        _check_publish_flags(
            atomic=atomic,
            fsync=fsync,
            require_atomic=require_atomic,
            require_fsync=require_fsync,
        )
        if require_fsync and not self.supports(EXTENSION_FSYNC):
            raise CapabilityError(
                f"require_fsync=True but this server does not advertise {EXTENSION_FSYNC}, "
                f"so nothing can promise the bytes reached stable storage",
                feature="durable upload",
                missing=(EXTENSION_FSYNC,),
                path=target,
            )

        upload = _Upload(
            local_path=local_path,
            fsync=fsync,
            require_fsync=require_fsync,
            progress=progress,
            depth=depth,
        )
        if not atomic:
            return await self._put_in_place(upload, target)
        staged = staged_path(target, staging_token(), name=_optional_path(staging_name))
        return await self._put_atomically(upload, target, staged, require_atomic=require_atomic)

    # --- put, in its two shapes ------------------------------------------------------------

    async def _put_in_place(self, upload: _Upload, target: bytes) -> UploadResult:
        """Write the destination directly, which a consumer can observe half-written.

        Nothing is cleaned up on failure, and that is not an oversight: the destination *is*
        the file being written, so there is nothing to remove that would not be deleting the
        caller's data. A failed in-place write leaves a truncated destination, which is what
        ``atomic=False`` means.
        """
        handle = await self.open(target, _TRUNCATE_FLAGS)
        transferred, durability = await self._fill_and_close(upload, handle, target)
        return UploadResult(transferred, target, PublishMechanism.IN_PLACE, durability)

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

        handle = await self._open_staging_file(staged, target)
        try:
            transferred, durability = await self._fill_and_close(upload, handle, staged)
            mechanism = await self._publish(staged, target, require_atomic=require_atomic)
        except _StagedIsTheOnlyCopyError as lost:
            # Do NOT clean up. The destination has already been removed and this file is the
            # only copy of the data; deleting it here would turn a failure someone can undo
            # by hand into one nobody can.
            lost.failure.add_note(
                f"the destination {target!r} was removed and the rename that should have "
                f"replaced it failed; the uploaded file is intact at {staged!r} and is now the "
                f"only copy of it"
            )
            raise lost.failure from None
        except BaseException as error:
            await self._discard(staged, error)
            raise
        return UploadResult(transferred, target, mechanism, durability, staged)

    async def _open_staging_file(self, staged: bytes, target: bytes) -> bytes:
        """Create the staging file, or fail in a way that names what to do about it.

        Kept separate because **a failed OPEN must not reach the cleanup path**: nothing of
        ours exists yet, and the most likely reason for `EXCL` to refuse is that somebody else
        is publishing to the same destination. Removing the file in the way would destroy the
        upload they are in the middle of.

        The note matters more than it looks. This is the first failure a user meets when the
        new default does not suit their server, and without it the message names a dot-file
        they never typed, in answer to a call about a path they did.
        """
        try:
            return await self.open(staged, _STAGE_FLAGS)
        except SFTPError as refusal:
            refusal.add_note(
                f"{staged!r} is the staging file for {target!r}. Publishing atomically needs "
                f"the right to create and rename a second name in that directory, and a name "
                f"that is not already taken -- pass atomic=False to write the destination "
                f"directly instead, or staging_name= to put the staging file elsewhere."
            )
            raise

    async def _fill_and_close(
        self, upload: _Upload, handle: bytes, path: bytes
    ) -> tuple[int, Durability]:
        """Push the file through an open handle, flush it, and close it.

        The flush happens while the handle is still open, because that is the only time it
        can: ``fsync@openssh.com`` on a closed handle answers ``NO_SUCH_FILE``.
        """
        try:
            async with self._lock:
                transferred = await upload_handle(
                    self._transport,
                    self._codec,
                    handle,
                    upload.local_path,
                    write_length=self.sizes_for(handle).write_length,
                    depth=self._depth if upload.depth is None else upload.depth,
                    idle_timeout=self._idle_timeout,
                    progress=upload.progress,
                    remote_path=path,
                )
            # Outside the lock: anyio's Lock is not reentrant and the flush is a request of
            # its own.
            durability = await self._flush(upload, handle)
        except BaseException:
            # Closing is not optional -- a leaked handle counts against max-open-handles and
            # is invisible from this side until the server refuses to open anything. But it
            # must not replace the error that got us here with one about the close.
            await self._close_quietly(handle)
            raise
        await self.close(handle)
        return transferred, durability

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

        # The window this rung is named for. Everything after the REMOVE is unwindable only by
        # hand, so a failure past this point must leave the staged file where it is.
        await self.remove(target)
        try:
            await self.rename(staged, target)
        except Exception as second_failure:
            raise _StagedIsTheOnlyCopyError(second_failure) from second_failure
        return PublishMechanism.REMOVE_RENAME

    async def _refuse_unpublishable(self, target: bytes) -> None:
        """Refuse before the transfer if the destination cannot be replaced atomically.

        Raises:
            CapabilityError: If the destination exists and there is no atomic overwrite.
        """
        if not await self._confirmed_present(target):
            return
        raise CapabilityError(
            f"require_atomic=True but {target!r} already exists and this server does not "
            f"advertise {EXTENSION_POSIX_RENAME}, so it cannot be replaced in one step",
            feature="atomic publish",
            missing=(EXTENSION_POSIX_RENAME,),
            path=target,
        )

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

    # --- cleanup ------------------------------------------------------------------------------

    async def _close_quietly(self, handle: bytes) -> None:
        """Close a handle during failure handling, shielded and without raising.

        ``Exception`` rather than a precise tuple on purpose. This runs while another error is
        already on its way up, and *anything* raised here replaces the diagnosis with a
        housekeeping complaint. Cancellation is not caught -- it derives from
        ``BaseException`` -- and cannot arrive anyway inside the shield.
        """
        with anyio.CancelScope(shield=True), suppress(Exception):
            await self.close(handle)

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


def _check_publish_flags(
    *, atomic: bool, fsync: bool, require_atomic: bool, require_fsync: bool
) -> None:
    """Refuse a pair of flags that contradict each other.

    ``require_atomic=True, atomic=False`` is not a policy this can satisfy by picking one --
    it is two opposite instructions, and honouring either silently would be guessing about
    the guarantee the caller cares most about.

    Raises:
        ValueError: If a ``require_*`` flag strengthens a flag that is switched off.
    """
    if require_atomic and not atomic:
        raise ValueError("require_atomic=True contradicts atomic=False")
    if require_fsync and not fsync:
        raise ValueError("require_fsync=True contradicts fsync=False")


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
) -> AsyncIterator[Session]:
    """Perform the handshake over ``transport`` and yield a ready session.

    Args:
        transport: A connected transport. Its lifetime is the caller's; this only drives it.
        request_timeout: Seconds for the handshake and each one-shot request.
        idle_timeout: Seconds of total silence during a bulk transfer.
        depth: Default requests in flight per transfer.

    Yields:
        A negotiated session.

    Raises:
        TransferTimeoutError: If the server never sends VERSION.
        ConnectError: If the transport fails, carrying the child's stderr.
    """
    codec = Codec()
    await transport.send(codec.initiate())
    await _await_version(transport, codec, request_timeout)
    limits = await _probe_limits(transport, codec, request_timeout)
    yield Session(
        transport,
        codec,
        limits,
        request_timeout=request_timeout,
        idle_timeout=idle_timeout,
        depth=depth,
    )


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

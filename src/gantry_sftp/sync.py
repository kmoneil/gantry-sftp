"""The blocking surface: one implementation, reached from a thread that has no event loop.

    from gantry_sftp.sync import connect

    with connect("example.com", user="bob") as sftp:
        sftp.get("/incoming/data.parquet", "data.parquet")

**This is a facade over the async code, not a second implementation of it** (D-8, D-84). The
event loop runs on a background thread inside
:func:`anyio.from_thread.start_blocking_portal`, and every method here is the same
:class:`~gantry_sftp.session.Session` method, called across the thread boundary. The
scheduler, the pipelining, the shielded cleanup and the reconnect logic are not reimplemented
and cannot drift, because there is nothing here to drift *from* -- what a caller gets is the
async object with a portal in front of it.

The rule this replaces said the blocking API was generated at build time with ``unasync``, and
it was wrong rather than merely unbuilt: token substitution has no sync ``create_task_group``,
so honouring it meant hand-writing a second concurrency runtime -- threads for the reader and
the reaper, ``threading`` locks, a selector transport, and a re-derivation of cancellation.
:mod:`tests.test_sync_facade` asserts parity by deriving this module's names and signatures
from the async ones, which is what the generator was there to guarantee.

**Three shapes needed care, and each was measured against a real ``sftp-server`` before it was
written** (``_plans/probes/sync_portal_probe.py``):

- **Async context managers take a double hop.** ``portal.wrap_async_context_manager`` wants the
  context manager *object*, and constructing one runs the decorated function -- which has to
  happen on the portal's thread. The spelling is
  ``portal.wrap_async_context_manager(portal.call(factory))``, and it is hidden in
  :func:`_sync_context` so no caller has to know it.
- **Async generators** -- :meth:`SyncSession.walk` and :meth:`SyncSession.glob` -- are driven
  with ``portal.call(iterator.__anext__)`` and ``StopAsyncIteration`` translated to
  ``StopIteration``. The finaliser runs on the portal's thread too: what these return is an
  ordinary Python generator, so breaking out of the ``for`` closes it, and with it the async
  generator underneath.
- **:class:`~gantry_sftp.session.DirectoryScan`** is a hand-written async context manager
  holding a directory handle, and a sync caller who ``break``s out of the loop still has to
  reach its ``__aexit__``. :class:`SyncDirectoryScan` is the same shape one layer up, and
  ``tests/test_sync_facade.py`` proves against a real server that the handle is gone
  afterwards rather than merely unreferenced.

**Exceptions arrive as themselves and flat.** Everything
:func:`~gantry_sftp.exceptions._flatten_exception_group` and the reader's shielding buy
survives the thread hop, so ``except NoSuchFileError`` around a blocking call matches for the
same reason it matches around an ``await``.

**One session, many threads.** "Many transfers over one connection" is a task group
asynchronously; a blocking caller has no task group, so the spelling here is threads.
``portal.call`` posts to the loop from whatever thread it is on, so a :class:`SyncSession`
shared across a thread pool fans out onto the one reader that already routes replies by
request id -- the same multiplexing, reached differently. Tested.

**A ``progress`` callback runs on the portal's thread**, because that is where the transfer
is, and that thread is the one thread that cannot wait on the portal. Calling back into the
session from inside a callback is refused by anyio with ``RuntimeError: This method cannot be
called from the event loop thread`` -- loudly rather than as a deadlock, which is the failure
worth ruling out and is tested. Keep a callback to what it is for: counting bytes, updating a
bar, and returning.

**Two things are deliberately not here.**

- :func:`~gantry_sftp.session.with_reconnect` takes a callable that receives a session, so a
  blocking form would have to run the caller's function on the portal's thread -- which is the
  one thread that cannot call back into the portal -- and therefore needs a third thread to
  re-enter from. That is a mechanism decision of its own rather than a wrapper, and it is
  carded rather than half-built.
- A ``backend=`` argument. The module-level entry points start an asyncio portal, which is the
  right default for a caller who has no loop at all. Trio is reached by owning the portal --
  see :class:`BoundPortal`, which is also the answer for anyone who wants several sessions on
  one loop instead of a thread apiece.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Iterator, Mapping
from contextlib import AbstractAsyncContextManager, AbstractContextManager, contextmanager
from datetime import datetime
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import Self, override

from anyio.from_thread import BlockingPortal, start_blocking_portal

from gantry_sftp._connect import connect as _async_connect
from gantry_sftp.codec import Attrs, OpenFlag, Request, Response
from gantry_sftp.exceptions import StateError
from gantry_sftp.session import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_SESSION_OPTIONS,
    DirectoryScan,
    DirEntry,
    DownloadResult,
    GlobMatch,
    Mode,
    ProgressCallback,
    Publish,
    RemoteFile,
    ServerLimits,
    ServerProfile,
    Session,
    SessionOptions,
    TransferSizes,
    TreeResult,
    UploadResult,
    Verify,
    WalkEntry,
)
from gantry_sftp.session import open_session as _async_open_session
from gantry_sftp.transport import Transport
from gantry_sftp.transport import open_local_server_transport as _async_open_local_server_transport
from gantry_sftp.transport import open_ssh_transport as _async_open_ssh_transport

__all__ = [
    "BoundPortal",
    "SyncDirectoryScan",
    "SyncRemoteFile",
    "SyncSession",
    "SyncTransport",
    "connect",
    "open_local_server_transport",
    "open_session",
    "open_ssh_transport",
]


def _sync_context[T](
    portal: BlockingPortal, factory: Callable[[], AbstractAsyncContextManager[T]]
) -> AbstractContextManager[T]:
    """Turn an async context manager into one an ordinary ``with`` can enter.

    The double hop the probe found, in the one place that needs to know about it.
    ``wrap_async_context_manager`` takes the context-manager *object*, and building one calls
    the ``@asynccontextmanager``-decorated function, which creates an async generator and so
    belongs on the thread whose loop will run it.

    Args:
        portal: The portal whose thread owns the loop.
        factory: Called on the portal's thread; returns the async context manager.

    Returns:
        A context manager whose ``__enter__`` and ``__exit__`` run on the portal's thread.
    """
    return portal.wrap_async_context_manager(portal.call(factory))


class SyncTransport:
    """A connected transport and the portal its I/O runs on.

    Both halves are needed together: a transport is driven by a loop, and
    :func:`open_session` has to use the *same* loop rather than starting a second one. Pairing
    them in one object is what lets the two-call spelling work without the caller ever naming
    a portal::

        with open_ssh_transport("example.com", user="bob") as transport:
            with open_session(transport) as sftp:
                ...

    Built by the entry points in this module; constructing one directly is not supported.

    Args:
        portal: The portal whose thread owns the loop this transport is running on.
        transport: The connected transport itself.
    """

    def __init__(self, portal: BlockingPortal, transport: Transport) -> None:
        self._portal = portal
        self._transport = transport

    @override
    def __repr__(self) -> str:
        return f"<SyncTransport over {self._transport!r}>"

    @property
    def portal(self) -> BlockingPortal:
        """The portal this transport's loop runs on."""
        return self._portal

    @property
    def transport(self) -> Transport:
        """The async transport underneath, for anything this facade does not cover."""
        return self._transport


class SyncDirectoryScan:
    """One directory, streamed batch by batch, from a thread with no event loop.

    The blocking form of :class:`~gantry_sftp.session.DirectoryScan`, and the same shape for
    the same reason: it holds a directory handle open across the loop, so it is a context
    manager rather than a bare iterator::

        with sftp.scandir("/incoming") as entries:
            for entry in entries:
                if entry.is_file and entry.name.endswith(".csv"):
                    break                      # the handle is closed on the way out

    ``.`` and ``..`` are filtered and every other name is surfaced verbatim, exactly as in the
    async form -- this adds no policy of its own, because the object underneath is the one
    doing the work.

    Iterating one that has not been entered raises
    :class:`~gantry_sftp.exceptions.StateError`, again from the object underneath rather than
    from a second check here.

    Args:
        portal: The portal whose thread owns the loop.
        scan: The async scan to drive.
    """

    def __init__(self, portal: BlockingPortal, scan: DirectoryScan) -> None:
        self._portal = portal
        self._scan = scan

    @override
    def __repr__(self) -> str:
        return f"<SyncDirectoryScan over {self._scan!r}>"

    def __enter__(self) -> Self:
        """Open the directory on the portal's thread."""
        _ = self._portal.call(self._scan.__aenter__)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the directory handle, whichever way the block ended."""
        _ = self._portal.call(self._scan.__aexit__, exc_type, exc, traceback)

    def __iter__(self) -> Self:
        """Iterate the entries.

        Raises:
            StateError: If the scan was never entered, which would leak the handle it holds.
        """
        _ = self._scan.__aiter__()  # pure, and the state check we want to inherit rather than copy
        return self

    def __next__(self) -> DirEntry:
        """The next entry, asking the server for another batch when this one runs out."""
        try:
            return self._portal.call(self._scan.__anext__)
        except StopAsyncIteration:
            raise StopIteration from None


class SyncRemoteFile:
    """One open remote file with a cursor, from a thread with no event loop.

    The blocking form of :class:`~gantry_sftp.session.RemoteFile`, and the same shape for the
    same reason: it holds a server-side handle, so it is a context manager rather than a bare
    object::

        with sftp.open_file("/logs/today.jsonl") as remote:
            header = remote.read(512)
            remote.seek(-4096, os.SEEK_END)
            tail = remote.read()

    Every method is the async one through the portal, so the semantics -- what a short read
    means, what ``APPEND`` does to the cursor, which calls are round trips -- are documented
    there and are not restated here. **The single-task rule carries over unchanged**: the
    cursor is shared mutable state, and two threads driving one of these interleave their
    positions. Use :meth:`SyncSession.readinto_at` and :meth:`SyncSession.write_at` to work on
    one file from several threads.

    Args:
        portal: The portal whose thread owns the loop.
        remote: The async file object to drive.
    """

    def __init__(self, portal: BlockingPortal, remote: RemoteFile) -> None:
        self._portal = portal
        self._remote = remote

    @override
    def __repr__(self) -> str:
        return f"<SyncRemoteFile over {self._remote!r}>"

    @property
    def path(self) -> bytes:
        """The remote path, as bytes."""
        return self._remote.path

    def __enter__(self) -> Self:
        """Open the file on the portal's thread."""
        _ = self._portal.call(self._remote.__aenter__)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the handle, whichever way the block ended."""
        _ = self._portal.call(self._remote.__aexit__, exc_type, exc, traceback)

    def tell(self) -> int:
        """The cursor. Pure, so it does not cross the thread boundary at all."""
        return self._remote.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the cursor and return its new absolute position."""
        return self._portal.call(partial(self._remote.seek, offset, whence))

    def read(self, length: int | None = None) -> bytes:
        """Read from the cursor and advance it."""
        return self._portal.call(partial(self._remote.read, length))

    def readinto(self, buffer: bytearray | memoryview) -> int:
        """Read into a buffer you already own, and advance the cursor."""
        return self._portal.call(partial(self._remote.readinto, buffer))

    def write(self, data: bytes | memoryview) -> int:
        """Write at the cursor and advance it."""
        return self._portal.call(partial(self._remote.write, data))

    def stat(self) -> Attrs:
        """Attributes of the open file, from its handle rather than its name."""
        return self._portal.call(self._remote.stat)

    def truncate(self, size: int | None = None) -> None:
        """Set the file's length, defaulting to the current cursor."""
        return self._portal.call(partial(self._remote.truncate, size))

    def fsync(self) -> None:
        """Ask the server to flush this file to its disk, where it supports it."""
        return self._portal.call(self._remote.fsync)


class SyncSession:
    """An SFTP conversation with one server, driven from a thread with no event loop.

    Every method is the identically-named :class:`~gantry_sftp.session.Session` method called
    through a portal, so the argument names, the defaults and the exceptions are that method's
    and are documented there. What differs is only that these return values rather than
    awaitables, and that the two streaming shapes come back as ordinary Python iterators.

    Built by :func:`connect` or :func:`open_session`; constructing one directly is not
    supported, because it needs a portal whose loop is already running the session's reader.

    Args:
        portal: The portal whose thread owns the loop.
        session: The session to drive.
    """

    def __init__(self, portal: BlockingPortal, session: Session) -> None:
        self._portal = portal
        self._session = session
        self._live = True

    @override
    def __repr__(self) -> str:
        state = "" if self._live else " closed"
        return f"<SyncSession{state} over {self._session!r}>"

    def _finish(self) -> None:
        """Mark the session spent, once the block that owns it has ended.

        The portal usually goes with it, so a later call would surface as anyio's
        ``RuntimeError`` about a portal that is not running -- which names the mechanism
        rather than the mistake. It also tells the generator finalisers below that there is no
        longer anything to close: the handles went with the connection.
        """
        self._live = False

    def _ready(self) -> BlockingPortal:
        """The portal, refusing the call if the block that owns this session has ended."""
        if not self._live:
            raise StateError("this session is closed; its `with` block has ended")
        return self._portal

    def _run[T](self, call: Callable[[], Awaitable[T]]) -> T:
        """Run one coroutine on the portal's thread and block until it answers."""
        return self._ready().call(call)

    def _iterate[T](self, factory: Callable[[], AsyncGenerator[T]]) -> Iterator[T]:
        """Drive an async generator from the calling thread, finalising it on the portal's.

        A generator rather than an iterator class, deliberately: breaking out of a ``for``
        drops it, CPython closes it, and the ``finally`` below runs ``aclose`` where the loop
        is. The async generator underneath chains several more (D-25), and only closing the
        outermost one closes those.

        ``factory`` is called through the portal rather than awaited: an async generator
        *function* hands back the generator object without running any of it, and that object
        belongs on the thread whose loop will drive it.
        """
        source = self._ready().call(factory)
        try:
            while True:
                try:
                    yield self._ready().call(source.__anext__)
                except StopAsyncIteration:
                    return
        finally:
            # Not `_run`: this is a finaliser, and the case it exists for is a generator that
            # outlived the session's block. There is nothing left to close there -- the
            # handles went with the connection -- and raising `StateError` out of a garbage
            # collector's callback would only produce an ignored-exception warning.
            if self._live:
                self._portal.call(source.aclose)

    # --- what the session is talking to ---------------------------------------------------

    @property
    def limits(self) -> ServerLimits:
        """The server's negotiated limits."""
        return self._session.limits

    @property
    def depth(self) -> int:
        """Default requests in flight per transfer."""
        return self._session.depth

    @property
    def extensions(self) -> Mapping[bytes, bytes]:
        """What the server advertised at handshake."""
        return self._session.extensions

    @property
    def server_version(self) -> int | None:
        """The protocol version in force."""
        return self._session.server_version

    @property
    def server_root(self) -> bytes | None:
        """The server's root, once something has needed to know it."""
        return self._session.server_root

    @property
    def profile(self) -> ServerProfile:
        """Which server this looks like, and what that implies."""
        return self._session.profile

    @property
    def reaped(self) -> int:
        """Handles the reaper has closed behind abandoned requests."""
        return self._session.reaped

    @property
    def requests_sent(self) -> int:
        """Requests written to the wire."""
        return self._session.requests_sent

    @property
    def replies_received(self) -> int:
        """Replies read off the wire."""
        return self._session.replies_received

    @property
    def bytes_sent(self) -> int:
        """Payload bytes written."""
        return self._session.bytes_sent

    @property
    def bytes_received(self) -> int:
        """Payload bytes read."""
        return self._session.bytes_received

    def supports(self, extension: bytes | str) -> bool:
        """Whether the server advertised an extension. Pure, so no round trip."""
        return self._session.supports(extension)

    def refuses(self, extension: bytes | str) -> bool:
        """Whether an extension has been tried and answered ``OP_UNSUPPORTED``."""
        return self._session.refuses(extension)

    def sizes_for(self, handle: bytes) -> TransferSizes:
        """The negotiated read and write sizes for one handle."""
        return self._session.sizes_for(handle)

    def request(self, request: Request) -> Response:
        """Send one request and wait for its reply. The escape hatch under everything else."""
        return self._run(partial(self._session.request, request))

    # --- attributes and links -------------------------------------------------------------

    def stat(self, path: bytes | str) -> Attrs:
        """Attributes of a path, following symlinks."""
        return self._run(partial(self._session.stat, path))

    def chdir(self, path: bytes | str) -> None:
        """Set the directory relative paths resolve against, for this session."""
        return self._run(partial(self._session.chdir, path))

    def getcwd(self) -> bytes:
        """Where relative paths resolve from: the prefix, or the server's own default."""
        return self._run(self._session.getcwd)

    def exists(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        """Whether anything is at a path -- ``False`` only for ``NO_SUCH_FILE``."""
        return self._run(partial(self._session.exists, path, follow_symlinks=follow_symlinks))

    def isdir(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        """Whether a path is a directory."""
        return self._run(partial(self._session.isdir, path, follow_symlinks=follow_symlinks))

    def isfile(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        """Whether a path is a regular file."""
        return self._run(partial(self._session.isfile, path, follow_symlinks=follow_symlinks))

    def islink(self, path: bytes | str) -> bool:
        """Whether a path is a symlink. Never follows, so a broken link is still one."""
        return self._run(partial(self._session.islink, path))

    def getsize(self, path: bytes | str, *, follow_symlinks: bool = True) -> int | None:
        """Size in bytes, or ``None`` where the server reported no size."""
        return self._run(partial(self._session.getsize, path, follow_symlinks=follow_symlinks))

    def getmtime(self, path: bytes | str, *, follow_symlinks: bool = True) -> datetime | None:
        """Modification time as an aware UTC datetime, or ``None`` where unstated."""
        return self._run(partial(self._session.getmtime, path, follow_symlinks=follow_symlinks))

    def lstat(self, path: bytes | str) -> Attrs:
        """Attributes of a path without following a final symlink."""
        return self._run(partial(self._session.lstat, path))

    def fstat(self, handle: bytes) -> Attrs:
        """Attributes of an open handle."""
        return self._run(partial(self._session.fstat, handle))

    def chmod(self, path: bytes | str, mode: int, *, follow_symlinks: bool = True) -> None:
        """Change a path's permission bits."""
        return self._run(partial(self._session.chmod, path, mode, follow_symlinks=follow_symlinks))

    def chown(self, path: bytes | str, uid: int, gid: int, *, follow_symlinks: bool = True) -> None:
        """Change a path's owner and group."""
        return self._run(
            partial(self._session.chown, path, uid, gid, follow_symlinks=follow_symlinks)
        )

    def utime(
        self, path: bytes | str, atime: int, mtime: int, *, follow_symlinks: bool = True
    ) -> None:
        """Set a path's access and modification times."""
        return self._run(
            partial(self._session.utime, path, atime, mtime, follow_symlinks=follow_symlinks)
        )

    def truncate(self, path: bytes | str, size: int) -> None:
        """Truncate or extend a file to a length."""
        return self._run(partial(self._session.truncate, path, size))

    def readlink(self, path: bytes | str) -> bytes:
        """Read a symlink's target."""
        return self._run(partial(self._session.readlink, path))

    def symlink(self, target: bytes | str, link_path: bytes | str) -> None:
        """Create a symlink. Argument order is this library's, not the wire's."""
        return self._run(partial(self._session.symlink, target, link_path))

    def realpath(self, path: bytes | str = b".") -> bytes:
        """Canonicalise a path on the server."""
        return self._run(partial(self._session.realpath, path))

    # --- handles --------------------------------------------------------------------------

    def open(
        self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ, *, mode: int | None = None
    ) -> bytes:
        """Open a file and return its handle."""
        return self._run(partial(self._session.open, path, pflags, mode=mode))

    def readinto_at(self, handle: bytes, buffer: bytearray | memoryview, offset: int) -> int:
        """Read ``len(buffer)`` bytes from ``offset`` into ``buffer``. The zero-copy primitive."""
        return self._run(partial(self._session.readinto_at, handle, buffer, offset))

    def read_at(self, handle: bytes, offset: int, length: int) -> bytes:
        """Read up to ``length`` bytes from ``offset``, pipelined."""
        return self._run(partial(self._session.read_at, handle, offset, length))

    def write_at(self, handle: bytes, offset: int, data: bytes | memoryview) -> int:
        """Write ``data`` at ``offset``, pipelined."""
        return self._run(partial(self._session.write_at, handle, offset, data))

    def ftruncate(self, handle: bytes, size: int) -> None:
        """Set the length of an open file, by handle rather than by path."""
        return self._run(partial(self._session.ftruncate, handle, size))

    def open_file(
        self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ, *, mode: int | None = None
    ) -> SyncRemoteFile:
        """Open a remote file as a cursor-bearing object, for ranges and streaming.

        Not a blocking call: it returns the file, so it is ``with sftp.open_file(...)``. The
        liveness check happens here rather than at ``__enter__``, for the same reason
        :meth:`scandir`'s does -- a file asked for after the session's block has ended should
        name the block rather than the portal.
        """
        return SyncRemoteFile(self._ready(), self._session.open_file(path, pflags, mode=mode))

    def opendir(self, path: bytes | str) -> bytes:
        """Open a directory and return its handle."""
        return self._run(partial(self._session.opendir, path))

    def readdir(self, handle: bytes) -> tuple[DirEntry, ...] | None:
        """One batch of directory entries, or ``None`` at end of directory."""
        return self._run(partial(self._session.readdir, handle))

    def close(self, handle: bytes) -> None:
        """Close a handle. Closes the *handle*, never the session."""
        return self._run(partial(self._session.close, handle))

    def fsync(self, handle: bytes) -> None:
        """Flush a handle's data to the server's disk, where the extension exists."""
        return self._run(partial(self._session.fsync, handle))

    def check_file(
        self,
        handle: bytes,
        *,
        algorithms: bytes = b"sha256,sha1,md5",
        start_offset: int = 0,
        length: int = 0,
        block_size: int = 65536,
    ) -> tuple[bytes, tuple[bytes, ...]]:
        """Ask the server to hash a range of an open file, where the extension exists."""
        return self._run(
            partial(
                self._session.check_file,
                handle,
                algorithms=algorithms,
                start_offset=start_offset,
                length=length,
                block_size=block_size,
            )
        )

    # --- directories ----------------------------------------------------------------------

    def scandir(self, path: bytes | str) -> SyncDirectoryScan:
        """Stream a directory, holding one handle and one batch.

        Not a blocking call: it returns the scan, so it is ``with sftp.scandir(...)``. The
        liveness check still happens here rather than at ``__enter__``, so a scan asked for
        after the session's block has ended names the block rather than the portal.
        """
        return SyncDirectoryScan(self._ready(), self._session.scandir(path))

    def listdir(self, path: bytes | str) -> list[DirEntry]:
        """List a directory, following the batches to the end."""
        return self._run(partial(self._session.listdir, path))

    def mkdir(self, path: bytes | str, *, exist_ok: bool = False) -> None:
        """Create a directory."""
        return self._run(partial(self._session.mkdir, path, exist_ok=exist_ok))

    def makedirs(self, path: bytes | str, *, exist_ok: bool = False) -> None:
        """Create a directory and any missing ancestors of it."""
        return self._run(partial(self._session.makedirs, path, exist_ok=exist_ok))

    def rmdir(self, path: bytes | str) -> None:
        """Remove an empty directory."""
        return self._run(partial(self._session.rmdir, path))

    def remove(self, path: bytes | str) -> None:
        """Remove a file."""
        return self._run(partial(self._session.remove, path))

    def rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        """Rename, refusing to overwrite -- the v3 semantics."""
        return self._run(partial(self._session.rename, old_path, new_path))

    def posix_rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        """Rename, replacing atomically, where the extension exists."""
        return self._run(partial(self._session.posix_rename, old_path, new_path))

    def rmtree(self, path: bytes | str) -> TreeResult:
        """Remove a directory and everything under it."""
        return self._run(partial(self._session.rmtree, path))

    # --- walking --------------------------------------------------------------------------

    def walk(self, path: bytes | str, *, max_depth: int | None = None) -> Iterator[WalkEntry]:
        """Walk a remote tree, one directory at a time.

        The blocking form of :meth:`Session.walk`. Breaking out of the ``for`` closes the
        listing underneath, so no directory handle is left open on the server.
        """
        return self._iterate(partial(self._session.walk, path, max_depth=max_depth))

    def glob(
        self, pattern: bytes | str, *, max_depth: int | None = None, case_sensitive: bool = True
    ) -> Iterator[GlobMatch]:
        """Expand a glob pattern against the server, yielding matches as they are found.

        The blocking form of :meth:`Session.glob`, and the same on breaking out early.
        """
        return self._iterate(
            partial(self._session.glob, pattern, max_depth=max_depth, case_sensitive=case_sensitive)
        )

    # --- transfers ------------------------------------------------------------------------

    def get(
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
        """Download a file, returning a report of what it did."""
        return self._run(
            partial(
                self._session.get,
                remote_path,
                local_path,
                progress=progress,
                depth=depth,
                no_follow=no_follow,
                resume=resume,
                verify_size=verify_size,
                verify=verify,
                preserve_times=preserve_times,
                mode=mode,
            )
        )

    def put(
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
        """Upload a file, atomically by default, returning what was published and how."""
        return self._run(
            partial(
                self._session.put,
                local_path,
                remote_path,
                publish=publish,
                resume=resume,
                preserve_times=preserve_times,
                mode=mode,
                verify=verify,
                progress=progress,
                depth=depth,
                **legacy,
            )
        )

    def get_tree(
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
        """Download a directory tree."""
        return self._run(
            partial(
                self._session.get_tree,
                remote_path,
                local_path,
                max_depth=max_depth,
                progress=progress,
                preserve_times=preserve_times,
                mode=mode,
                resume=resume,
                concurrency=concurrency,
            )
        )

    def put_tree(
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
        """Upload a directory tree."""
        return self._run(
            partial(
                self._session.put_tree,
                local_path,
                remote_path,
                max_depth=max_depth,
                publish=publish,
                preserve_times=preserve_times,
                mode=mode,
                progress=progress,
                resume=resume,
                concurrency=concurrency,
                **legacy,
            )
        )


class BoundPortal:
    """The blocking entry points, bound to a portal the caller owns.

    The module-level functions each start a portal, use it, and stop it, which is the right
    trade for a script that opens one connection. Two cases want the portal to outlive the
    connection, and this is how they say so:

    - **Several sessions on one loop.** Portal-per-connection means a thread and a loop per
      connection, which for a fan-out job is a real cost paid for nothing -- the loop is idle
      between calls.
    - **A backend other than asyncio.** ``start_blocking_portal(backend="trio")`` is the whole
      of it; nothing else in this module changes.

    ::

        from anyio.from_thread import start_blocking_portal
        from gantry_sftp.sync import BoundPortal

        with start_blocking_portal() as portal:
            gantry = BoundPortal(portal)
            with gantry.connect("a.example.com") as one, gantry.connect("b.example.com") as two:
                one.get("/data.csv", "a.csv")
                two.get("/data.csv", "b.csv")

    The portal stays the caller's: nothing here starts or stops it.

    Args:
        portal: A running portal, from :func:`anyio.from_thread.start_blocking_portal`.
    """

    def __init__(self, portal: BlockingPortal) -> None:
        self._portal = portal

    @override
    def __repr__(self) -> str:
        return f"<BoundPortal {self._portal!r}>"

    @property
    def portal(self) -> BlockingPortal:
        """The portal this is bound to."""
        return self._portal

    @contextmanager
    def connect(
        self,
        host: str,
        *,
        user: str | None = None,
        port: int | None = None,
        identity_file: str | os.PathLike[str] | None = None,
        password: str | None = None,
        config_file: str | os.PathLike[str] | None = None,
        options: Mapping[str, str] | None = None,
        env: Mapping[str, str] | None = None,
        ssh_executable: str | None = None,
        session: SessionOptions = DEFAULT_SESSION_OPTIONS,
    ) -> Generator[SyncSession]:
        """Open an ``ssh`` connection and a session over it, on this portal.

        Blocking form of :func:`gantry_sftp.connect`, whose docstring documents every argument
        and what it raises.

        Yields:
            A ready :class:`SyncSession`. Both the session and the connection close when the
            block exits.
        """
        factory = partial(
            _async_connect,
            host,
            user=user,
            port=port,
            identity_file=identity_file,
            password=password,
            config_file=config_file,
            options=options,
            env=env,
            ssh_executable=ssh_executable,
            session=session,
        )
        with _sync_context(self._portal, factory) as opened:
            yield from self._hold(opened)

    @contextmanager
    def open_ssh_transport(
        self,
        host: str,
        *,
        user: str | None = None,
        port: int | None = None,
        config_file: str | os.PathLike[str] | None = None,
        identity_file: str | os.PathLike[str] | None = None,
        options: Mapping[str, str] | None = None,
        subsystem: str = "sftp",
        ssh_executable: str | None = None,
        env: Mapping[str, str] | None = None,
        password: str | None = None,
    ) -> Generator[SyncTransport]:
        """Spawn ``ssh`` and yield the connected transport, on this portal.

        Blocking form of :func:`gantry_sftp.open_ssh_transport`, whose docstring documents
        every argument and what it raises.

        Yields:
            A :class:`SyncTransport`, carrying this portal so :meth:`open_session` uses the
            same loop rather than starting a second one.
        """
        factory = partial(
            _async_open_ssh_transport,
            host,
            user=user,
            port=port,
            config_file=config_file,
            identity_file=identity_file,
            options=options,
            subsystem=subsystem,
            ssh_executable=ssh_executable,
            env=env,
            password=password,
        )
        with _sync_context(self._portal, factory) as transport:
            yield SyncTransport(self._portal, transport)

    @contextmanager
    def open_local_server_transport(
        self,
        *,
        server_path: str | os.PathLike[str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Generator[SyncTransport]:
        """Spawn a local ``sftp-server`` on a pipe and yield the transport, on this portal.

        Blocking form of :func:`gantry_sftp.transport.open_local_server_transport`. No ``ssh``,
        no network and no credentials, which is what makes an example runnable with no
        arguments and a test runnable with no container.

        Yields:
            A :class:`SyncTransport` speaking to a local server process.
        """
        factory = partial(
            _async_open_local_server_transport, server_path=server_path, cwd=cwd, env=env
        )
        with _sync_context(self._portal, factory) as transport:
            yield SyncTransport(self._portal, transport)

    @contextmanager
    def open_session(
        self,
        transport: SyncTransport,
        *,
        request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
        idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
        depth: int = DEFAULT_PIPELINE_DEPTH,
    ) -> Generator[SyncSession]:
        """Handshake over a transport and yield a ready session, on this portal.

        Blocking form of :func:`gantry_sftp.open_session`, whose docstring documents every
        argument and what it raises.

        Args:
            transport: A :class:`SyncTransport` from one of the transport entry points. Its
                portal is ignored in favour of this one, so a transport opened on another
                portal is a mistake this cannot detect -- keep the pair together.
            request_timeout: Seconds for the handshake and each one-shot request.
            idle_timeout: Seconds of total silence during a bulk transfer.
            depth: Default requests in flight per transfer.

        Yields:
            A ready :class:`SyncSession`, closed when the block exits.
        """
        factory = partial(
            _async_open_session,
            transport.transport,
            request_timeout=request_timeout,
            idle_timeout=idle_timeout,
            depth=depth,
        )
        with _sync_context(self._portal, factory) as opened:
            yield from self._hold(opened)

    def _hold(self, session: Session) -> Iterator[SyncSession]:
        """Yield the facade and mark it spent afterwards, however the block ended.

        Both session entry points need this and neither should own it: a facade left usable
        after its block has exited would reach a portal that may already have stopped, and
        anyio's complaint there names the mechanism rather than the mistake.
        """
        wrapper = SyncSession(self._portal, session)
        try:
            yield wrapper
        finally:
            wrapper._finish()  # noqa: SLF001  (the facade's own lifecycle, not another object's)


@contextmanager
def connect(
    host: str,
    *,
    user: str | None = None,
    port: int | None = None,
    identity_file: str | os.PathLike[str] | None = None,
    password: str | None = None,
    config_file: str | os.PathLike[str] | None = None,
    options: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    ssh_executable: str | None = None,
    session: SessionOptions = DEFAULT_SESSION_OPTIONS,
) -> Generator[SyncSession]:
    """Open an ``ssh`` connection and a session over it, and yield the session.

    ::

        with connect("example.com", user="bob") as sftp:
            sftp.get("/incoming/data.parquet", "data.parquet")

    Blocking form of :func:`gantry_sftp.connect`, whose docstring documents every argument and
    what it raises. An asyncio portal is started for the duration of the block and stopped when
    it ends; :class:`BoundPortal` is how to own that portal instead, which is what to reach for
    with several connections or a different anyio backend.

    Yields:
        A ready :class:`SyncSession`. The session, the connection and the loop behind them all
        end with the block.
    """
    with (
        start_blocking_portal() as portal,
        BoundPortal(portal).connect(
            host,
            user=user,
            port=port,
            identity_file=identity_file,
            password=password,
            config_file=config_file,
            options=options,
            env=env,
            ssh_executable=ssh_executable,
            session=session,
        ) as sftp,
    ):
        yield sftp


@contextmanager
def open_ssh_transport(
    host: str,
    *,
    user: str | None = None,
    port: int | None = None,
    config_file: str | os.PathLike[str] | None = None,
    identity_file: str | os.PathLike[str] | None = None,
    options: Mapping[str, str] | None = None,
    subsystem: str = "sftp",
    ssh_executable: str | None = None,
    env: Mapping[str, str] | None = None,
    password: str | None = None,
) -> Generator[SyncTransport]:
    """Spawn ``ssh`` and yield the connected transport.

    Blocking form of :func:`gantry_sftp.open_ssh_transport`, whose docstring documents every
    argument and what it raises. Reach for this over :func:`connect` when the connection's
    lifetime differs from the session's::

        with open_ssh_transport("example.com", user="bob") as transport:
            with open_session(transport) as sftp:
                ...

    Yields:
        A :class:`SyncTransport` carrying the portal started for this block, so
        :func:`open_session` runs on the same loop.
    """
    with (
        start_blocking_portal() as portal,
        BoundPortal(portal).open_ssh_transport(
            host,
            user=user,
            port=port,
            config_file=config_file,
            identity_file=identity_file,
            options=options,
            subsystem=subsystem,
            ssh_executable=ssh_executable,
            env=env,
            password=password,
        ) as transport,
    ):
        yield transport


@contextmanager
def open_local_server_transport(
    *,
    server_path: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> Generator[SyncTransport]:
    """Spawn a local ``sftp-server`` on a pipe and yield the transport.

    Blocking form of :func:`gantry_sftp.transport.open_local_server_transport`. No ``ssh``, no
    network and no credentials.

    Yields:
        A :class:`SyncTransport` speaking to a local server process.
    """
    with (
        start_blocking_portal() as portal,
        BoundPortal(portal).open_local_server_transport(
            server_path=server_path, cwd=cwd, env=env
        ) as transport,
    ):
        yield transport


@contextmanager
def open_session(
    transport: SyncTransport,
    *,
    request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    depth: int = DEFAULT_PIPELINE_DEPTH,
) -> Generator[SyncSession]:
    """Handshake over a transport and yield a ready session.

    Blocking form of :func:`gantry_sftp.open_session`, whose docstring documents every argument
    and what it raises. The loop is the transport's -- this starts no portal of its own, which
    is what makes the two-call spelling one thread rather than two.

    Args:
        transport: A :class:`SyncTransport` from one of the transport entry points.
        request_timeout: Seconds for the handshake and each one-shot request.
        idle_timeout: Seconds of total silence during a bulk transfer.
        depth: Default requests in flight per transfer.

    Yields:
        A ready :class:`SyncSession`, closed when the block exits.
    """
    with BoundPortal(transport.portal).open_session(
        transport,
        request_timeout=request_timeout,
        idle_timeout=idle_timeout,
        depth=depth,
    ) as sftp:
        yield sftp

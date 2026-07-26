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
from contextlib import asynccontextmanager
from pathlib import Path
from typing import override

import anyio

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    Attrs,
    AttrsReply,
    Close,
    Codec,
    CodecState,
    Completed,
    Handle,
    Name,
    Open,
    OpenFlag,
    RealPath,
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

LIMITS_EXTENSION = b"limits@openssh.com"

_STATUS_ERRORS = {
    StatusCode.NO_SUCH_FILE: NoSuchFileError,
    StatusCode.PERMISSION_DENIED: PermissionDeniedError,
    StatusCode.OP_UNSUPPORTED: UnsupportedError,
}


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

    async def close(self, handle: bytes) -> None:
        """Close a remote handle."""
        reply = await self.request(Close(self._next(), handle))
        if isinstance(reply, Status):
            raise_for_status(reply)
            return
        raise _unexpected(reply, expected="STATUS")

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
                return await download_handle(
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
        finally:
            # Closing is not optional: a leaked handle counts against max-open-handles and
            # is invisible from this side until the server starts refusing to open anything.
            await self.close(handle)

    async def put(
        self,
        local_path: Path | str,
        remote_path: bytes | str,
        *,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
    ) -> int:
        """Upload ``local_path`` to ``remote_path``, truncating whatever is there.

        The remote file is written **in place**, so a reader watching the directory can see
        it half-written. Publishing atomically -- upload to a sibling temp name, fsync,
        rename over the target -- is the single most common thing production SFTP
        integrations get wrong, and it is deliberately not silently implied here: it needs
        ``posix-rename@openssh.com`` or a documented non-atomic fallback, and it lands as its
        own change rather than as an undocumented side effect of this one.

        Args:
            local_path: Local file to read.
            remote_path: Destination on the server.
            progress: Called with ``(transferred, total)`` as writes are acknowledged.
            depth: Requests in flight, overriding the session default. Each one holds a full
                payload in memory, so this costs more here than on the download side.

        Returns:
            Bytes the server acknowledged.

        Raises:
            PermissionDeniedError: If the server will not create or write the file.
            ServerError: For any other refusal.
            TransferError: If the transfer fails partway.
        """
        encoded = _encode_path(remote_path)
        handle = await self.open(encoded, OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC)
        try:
            async with self._lock:
                return await upload_handle(
                    self._transport,
                    self._codec,
                    handle,
                    local_path,
                    write_length=self.sizes_for(handle).write_length,
                    depth=self._depth if depth is None else depth,
                    idle_timeout=self._idle_timeout,
                    progress=progress,
                    remote_path=encoded,
                )
        finally:
            await self.close(handle)


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

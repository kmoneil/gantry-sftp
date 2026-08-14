"""What a session *is*, before it is asked to do anything.

The bottom of the three layers `Session` is built from, split out under D-143. It owns the ten
attributes -- eight of them written once in `__init__` and never again -- the eleven properties
that report them, and the one primitive every other layer is built on: :meth:`request`, which
sends a packet and returns its reply.

**The layering is enforced rather than intended.** Nothing here may call an operation or a
transfer; `tests/test_layer_discipline.py` asserts it, because a layer boundary that exists only
in a docstring is a boundary the next feature crosses without noticing. The direction that is
allowed is the useful one: everything above may call down.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import override

import anyio

from gantry_sftp.codec import (
    Request,
    Response,
    Status,
    StatusCode,
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
from gantry_sftp.session._dispatch import Dispatcher
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
)
from gantry_sftp.session._limits import ServerLimits, TransferSizes, negotiate_transfer_sizes
from gantry_sftp.session._quirks import ServerProfile, identify

DEFAULT_REQUEST_TIMEOUT = 30.0
"""Seconds a single round trip may take before it is abandoned.

Covers the handshake and every one-shot request -- OPEN, STAT, CLOSE, REALPATH. Bulk
transfers do **not** use this; they have their own idle timeout, because a large transfer is
allowed to take as long as it takes so long as bytes keep arriving.

The alternative is paramiko's, which is to wait forever. A connection that completes and
then never answers a STAT is the exact shape of an unattended job that hangs until someone
notices, which in a scheduled-transfer context can be days.
"""


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
    if status.raw_code is not None:
        # D-145. The code arrived as something v3 has no name for and was degraded to the
        # catch-all so the connection survives. Reporting only `FAILURE` would throw away the
        # single fact that distinguishes this from an ordinary refusal -- and it is the fact an
        # operator needs, because it says the server is answering in a later dialect rather
        # than saying no.
        summary = f"{summary} (wire status {status.raw_code}, which filexfer v3 does not define)"
    if detail:
        summary = f"{summary}: {detail}"
    raise error_class(summary, code=int(status.code), message=bytes(status.message), path=path)


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


class _SessionCore:
    """State and the one primitive above it.

    See :class:`~gantry_sftp.session.Session` for what a session is and how one is built;
    this class is not constructed directly and is not exported.
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
        """Protocol version negotiated, which on a session that opened is always 3.

        A constant, and reported anyway, because it is the *negotiated* value rather than a
        library fact: what makes it constant is the handshake refusing anything else, and the
        two are worth being able to tell apart when a connection did not open.
        """
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

        Useful for a log line, a bug report, and for a caller who *does* want to special-case
        a server and would otherwise fingerprint it themselves, worse.

        **Almost identification only, and the exception is one field.** This used to say
        "nothing in the library changes behaviour based on it", which stopped being true when
        D-30 shipped and was not corrected then; the same sentence was found in DESIGN.md and
        struck at the same time. What changed: ``transient_messages`` decides whether a
        ``FAILURE`` whose text this server's profile classifies causes an ``OPEN`` to be
        *repeated* -- same request, same session, three attempts. Only asyncssh carries
        markers, and a server this library has no fingerprint for carries none.

        The bound that matters survives, which is why the correction is narrow: a profile
        still cannot change how a reply is *read*. The mechanism repeats a request and never
        reinterprets one, so a wrong guess costs attempts and raises the server's own error
        unchanged rather than producing a wrong answer in a file.
        :mod:`gantry_sftp.session._quirks` explains why that bound is deliberate.
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

    def sizes_for(self, handle: bytes) -> TransferSizes:
        """Payload size per request for a given handle.

        The handle is part of every request header, so its length is part of the budget --
        OpenSSH's are four bytes and nothing promises another server's are.
        """
        return negotiate_transfer_sizes(self._limits, handle_length=len(handle))

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

    @property
    def server_root(self) -> bytes | None:
        """This server's canonical form of ``.``, if anything has needed to ask.

        ``None`` means the question never came up, **not** that the server has no root: the
        probe is lazy because an operation given an absolute path never needs it.
        """
        return self._root

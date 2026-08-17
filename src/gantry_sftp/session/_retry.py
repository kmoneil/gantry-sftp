"""Retry, and why a generic ``@retry`` decorator is a corruption bug in this library.

Two facts shape everything here, and neither is about backoff arithmetic.

**A session cannot reconnect itself.** :func:`~gantry_sftp.session.open_session` is handed a
transport whose lifetime belongs to the caller -- it drives one, it does not know how to make
another. So "reconnect and resume" cannot live inside ``Session``; it needs something that
holds the *recipe* for a connection and can run it again. That something is
:func:`with_reconnect`, and the recipe is any zero-argument callable returning the transport
context manager that already exists::

    recipe = functools.partial(open_ssh_transport, "example.com", user="bob")

**A retry is an at-least-once execution, and most operations are not idempotent.** This runs
the caller's operation against a *fresh session* each time, from the beginning. A ``get`` with
``resume=True`` picks up where the local file stopped; a ``rename`` that succeeded and lost
its reply will fail the second time with "target exists". So the contract is stated rather
than implied: **the operation must be idempotent or resumable**, and the docstring below says
which spellings are which. Write safety comes from ``resume``'s own checks -- a known-good
offset, and a refusal when it cannot establish one -- not from new machinery here.

What is *not* here: retrying an individual request inside a live connection. That lives in
:mod:`gantry_sftp.session._transient`, and the split is worth understanding rather than
guessing at. v3's ``FAILURE`` is a catch-all -- a permission problem, a full disk, a name
collision and a momentary appliance hiccup all arrive as the same code, and OpenSSH's message
for every one of them is the constant word ``Failure``. So "transient" is undecidable *here*,
where all this module knows is the exception, and :func:`is_retryable` keeps ``FAILURE``
terminal for that reason.

It becomes decidable for the subset of servers that put a ``strerror`` in the message, which is
a question about the *server* rather than about the exception -- so it needs the fingerprint,
and the rule that reads it repeats one request on the session already open rather than
reconnecting. A transient refusal of a download's ``OPEN`` is retried there. A transient
``FAILURE`` mid-transfer on a ``READ`` still fails the transfer, and on OpenSSH it still cannot
be fixed at any layer.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager

import anyio

from gantry_sftp._logging import fields_of, session_logger, summarise
from gantry_sftp.codec import StatusCode
from gantry_sftp.exceptions import (
    AuthenticationError,
    ConnectError,
    HostKeyError,
    ServerError,
    TransferTimeoutError,
)
from gantry_sftp.session._download import DEFAULT_IDLE_TIMEOUT, DEFAULT_PIPELINE_DEPTH
from gantry_sftp.session._session import DEFAULT_REQUEST_TIMEOUT, Session, open_session
from gantry_sftp.transport import Transport

__all__ = [
    "DEFAULT_ATTEMPTS",
    "DEFAULT_BACKOFF",
    "DEFAULT_BACKOFF_MAX",
    "RETRYABLE_STATUS_CODES",
    "is_retryable",
    "with_reconnect",
]

DEFAULT_ATTEMPTS = 3
"""Total tries, not retries: ``3`` is one attempt and two more after it.

Small on purpose. Every attempt after the first pays a fresh ``ssh`` fork, key exchange and
authentication, which DESIGN.md 12.1 measures as this architecture's one clear loss against
paramiko and asyncssh. Reconnecting is for a link that dropped, not for a server that is down.
"""

DEFAULT_BACKOFF = 1.0
"""Seconds before the second attempt, doubling from there."""

DEFAULT_BACKOFF_MAX = 30.0
"""Ceiling on the doubling, so a long ``attempts`` cannot schedule a retry hours away."""

RETRYABLE_STATUS_CODES = frozenset({StatusCode.NO_CONNECTION, StatusCode.CONNECTION_LOST})
"""Server statuses that mean "the link, not the request".

Notably **not** ``FAILURE``. DESIGN.md 6 says to distinguish "transient ``FAILURE``" from
terminal, and that distinction cannot be drawn: v3's ``FAILURE`` is the catch-all that a
permission problem, a full disk, a name collision and a momentary appliance hiccup all arrive
as. Retrying it treats every terminal error as transient -- turning a fast, clear failure into
three slow ones with the same message -- so it is terminal here until the quirks layer can
match a server's message text and say otherwise. That is a real gap and it is registered.

Both of these are also rare in the field: OpenSSH's server does not send either. They are
here because the codec knows them and a non-OpenSSH endpoint may not share that habit.
"""


def is_retryable(error: BaseException) -> bool:
    """Whether ``error`` is worth another attempt on a fresh connection.

    Retryable:

    * :class:`~gantry_sftp.exceptions.ConnectError` -- the transport died, which is the case
      this whole module exists for.
    * :class:`~gantry_sftp.exceptions.TransferTimeoutError` -- the far end went quiet. Its own
      docstring already drew this distinction: "a refusal means stop, a timeout means the far
      end went quiet and retrying may well work".
    * :class:`~gantry_sftp.exceptions.ServerError` carrying a status in
      :data:`RETRYABLE_STATUS_CODES`.

    Not retryable, and two of these are the interesting ones:

    * :class:`~gantry_sftp.exceptions.AuthenticationError` and
      :class:`~gantry_sftp.exceptions.HostKeyError`. Both are ``ConnectError`` subclasses, so
      they would otherwise be swept in by the first rule -- and retrying them is not merely
      wasteful. **OpenSSH 9.8+ applies ``PerSourcePenalties``**: repeated failed
      authentication from one address gets that address progressively locked out, so a retry
      loop turns one rejected key into a host that stops answering for everyone behind that
      IP. Credentials do not become correct by being offered again.
    * :class:`~gantry_sftp.exceptions.ProtocolError` -- its own docstring says it: the stream
      can no longer be trusted, and a reconnect would not make the server's framing valid.
    * Everything terminal: ``NoSuchFileError``, ``PermissionDeniedError``, ``UnsupportedError``,
      ``UnsafePathError``, ``StateError``, ``CapabilityError``, and a plain ``TransferError``
      from a refused read or write.
    * An ``ExceptionGroup``. Several things failed at once and there is no single answer to
      classify; not retrying is the safe direction, and it should not happen -- the reader
      task records its failure rather than raising it, so an operation sees one flat error.

    Args:
        error: The exception an attempt raised.

    Returns:
        Whether another attempt is warranted.
    """
    if isinstance(error, AuthenticationError | HostKeyError):
        return False
    if isinstance(error, ConnectError | TransferTimeoutError):
        return True
    if isinstance(error, ServerError):
        return error.code in RETRYABLE_STATUS_CODES
    return False


async def with_reconnect[T](
    connect: Callable[[], AbstractAsyncContextManager[Transport]],
    operation: Callable[[Session], Awaitable[T]],
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    backoff: float = DEFAULT_BACKOFF,
    backoff_max: float = DEFAULT_BACKOFF_MAX,
    request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    depth: int = DEFAULT_PIPELINE_DEPTH,
) -> T:
    """Run ``operation`` against a fresh session, reconnecting if the link drops.

    ::

        recipe = functools.partial(open_ssh_transport, "example.com", user="bob")

        moved = await with_reconnect(
            recipe,
            lambda sftp: sftp.get("/incoming/big.iso", "big.iso", resume=True),
        )

    **``operation`` is re-run from the beginning, against a session that did not exist
    before.** Nothing survives a reconnect: not the remote handles, not the request ids, not
    the negotiated limits, and **not a working directory set with**
    :meth:`~gantry_sftp.session.Session.chdir` -- which is worth naming because it is the one
    of those a caller can set from outside and might expect to persist. An operation that
    needs one calls ``chdir`` *inside* itself, exactly as it re-establishes everything else.
    So the operation has to be one of two things.

    *Resumable*, which is the case this is built for::

        lambda sftp: sftp.get(remote, local, resume=True)
        lambda sftp: sftp.put(local, remote, atomic=False, resume=True)

    Each attempt re-establishes the offset from what is actually there and refuses if it
    cannot -- which is why "writes are never blindly replayed" needs no machinery here. It is
    ``resume``'s check, and it is the weaker claim on the upload side exactly as documented on
    :meth:`~gantry_sftp.session.Session.put`. An automatic retry makes that weak claim once
    per attempt.

    *Or idempotent*, which most things are and some conspicuously are not::

        lambda sftp: sftp.listdir("/incoming")            # fine
        lambda sftp: sftp.get_tree(remote, local)         # fine, re-walks and re-fetches
        lambda sftp: sftp.rename(old, new)                # NOT fine: v3 RENAME refuses an
                                                         # existing target, so a lost reply
                                                         # makes attempt two fail

    A ``put`` with the default ``atomic=True`` is safe to retry but not resumable: each
    attempt stages under a fresh random name and publishes, so a failed attempt leaves a
    staging file behind and the next starts from zero. That is a wasted transfer, not a
    corruption.

    Args:
        connect: Zero-argument callable returning a transport context manager -- called once
            per attempt, so it must produce a *new* transport each time. A
            ``functools.partial`` of :func:`~gantry_sftp.transport.open_ssh_transport` is the
            intended spelling; a plain ``lambda`` works too.
        operation: What to do with the session. Awaited once per attempt.
        attempts: Total tries including the first. Must be at least 1.
        backoff: Seconds before the second attempt, doubled after each failure.
        backoff_max: Ceiling on that doubling.
        request_timeout: Forwarded to :func:`~gantry_sftp.session.open_session`.
        idle_timeout: Forwarded to :func:`~gantry_sftp.session.open_session`.
        depth: Forwarded to :func:`~gantry_sftp.session.open_session`.

    Returns:
        Whatever ``operation`` returned.

    Raises:
        ValueError: If ``attempts`` is less than 1.
        Exception: The last failure, unchanged apart from a note saying how many attempts
            were made. A terminal error is re-raised immediately, without waiting out a
            backoff nobody wanted -- being slow to report a permission problem is its own
            bug.
    """
    if attempts < 1:
        raise ValueError(f"attempts must be at least 1, got {attempts}")

    delay = backoff
    attempt = 0
    while True:
        attempt += 1
        try:
            async with (
                connect() as transport,
                open_session(
                    transport,
                    request_timeout=request_timeout,
                    idle_timeout=idle_timeout,
                    depth=depth,
                ) as sftp,
            ):
                return await operation(sftp)
        except Exception as error:
            # `Exception`, never `BaseException`: cancellation is how a caller stops this and
            # must not be retried. anyio's cancelled exception derives from BaseException on
            # both backends, so this is the line that keeps a cancelled transfer cancelled.
            if not is_retryable(error) or attempt >= attempts:
                # `is_retryable` a second time rather than threading a flag out of the
                # condition above: the note has to say *which* of the two exits was taken, and
                # a reader can see that here without holding the negation in their head. The
                # predicate is pure, so asking twice costs nothing.
                _note_attempts(error, attempt, attempts, exhausted=is_retryable(error))
                raise
            # The library's only WARNING, and the reason it is one: this failure is about to be
            # swallowed. Every other error in this package reaches the caller as a typed
            # exception carrying its own state, so logging those as well would report them
            # twice. A retried one reaches nobody -- without this record, a link that drops on
            # every second transfer is indistinguishable at runtime from a healthy one.
            session_logger.warning(
                "attempt %d of %d failed (%s), reconnecting in %.1fs",
                attempt,
                attempts,
                summarise(error),
                delay,
                # The one WARNING is also the one record an alert is most likely to be written
                # on, so it carries the same fields as everything else: `error` is the class
                # name, matching what a failed operation records, and `attempt`/`attempts` are
                # numbers because "the third of three" is a threshold question.
                extra=fields_of(
                    operation="reconnect",
                    event="retrying",
                    attempt=attempt,
                    attempts=attempts,
                    error=type(error).__name__,
                    delay=delay,
                ),
            )
        await anyio.sleep(delay)
        delay = min(delay * 2, backoff_max)


def _note_attempts(error: BaseException, attempt: int, attempts: int, *, exhausted: bool) -> None:
    """Say how many attempts were made and why they stopped, but only when more than one was.

    A note on a first-and-only failure would be noise on every terminal error -- and the
    common case for this helper is an operation that succeeds immediately. When it *did*
    retry, the count is the thing a reader needs: "failed" and "failed three times over
    ninety seconds" call for different responses.

    **Two exits reach here and they need different sentences** (D-195). Until then there was
    one, `"gave up after N of M attempt(s), all retryable"`, and it described only the exit
    where the attempts ran out. On the other -- a retryable failure followed by a terminal one
    -- it made two false claims in a sentence: that the attempts were spent, when one remained,
    and that every failure was retryable, when the one that stopped the loop was not. It
    pointed a reader at the link when the answer was a permission problem.

    Args:
        error: The failure about to be raised. The note goes on this one.
        attempt: Which attempt it was, counting from 1.
        attempts: The total this call was allowed.
        exhausted: Whether the loop stopped because the attempts ran out, rather than because
            this failure is one no reconnect can fix. Computed by the caller from
            :func:`is_retryable`, which is the same question the loop's own condition asked.
    """
    if attempt <= 1:
        return
    if exhausted:
        error.add_note(f"gave up after {attempt} of {attempts} attempt(s), all retryable")
    else:
        error.add_note(
            f"stopped after {attempt} of {attempts} attempt(s): this failure is not "
            f"retryable, so the remaining attempt(s) were not spent"
        )

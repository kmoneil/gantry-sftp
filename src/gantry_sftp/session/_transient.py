"""Retrying one request inside a live connection, for the servers that say why they refused.

This is the half :mod:`gantry_sftp.session._retry` names as *not* being there. That module
reconnects a whole operation against a fresh session when the link dies; this one repeats a
single request on the session already open, when the server's own message says the refusal was
about a resource rather than about the file.

**Why this could not be built until now, and what changed.** v3's ``FAILURE`` is the catch-all
that a permission problem, a full disk, a name collision and a momentary appliance hiccup all
arrive as, so "transient" is undecidable from the status code. It stays undecidable on OpenSSH,
whose message for every one of those is the constant word ``Failure`` -- measured against five
terminal conditions, and now against a genuinely transient one too, which is the row that closes
the argument rather than merely supporting it. It becomes decidable on a server that puts a
``strerror`` in the message, and D-30 measured one: with the server under a descriptor limit, an
``OPEN`` past the ceiling is refused ``FAILURE`` / ``Too many open files``, and the identical
request succeeds once one descriptor is released.

That condition is exactly what DESIGN.md 7 means by appliance servers that "degrade rather than
error under deep pipelining", and it is the reason the retry goes where it does. Three properties
of the design are load-bearing:

* **It repeats, it never reinterprets.** The worst a misclassification can do is spend the
  attempts and raise the server's original error, unchanged.
* **It is bounded, and the bound is the point.** Descriptor exhaustion is precisely the failure
  where every client retrying without limit is what keeps the server exhausted. Three attempts
  and a short doubling delay, not a loop that waits for the server to recover.
* **It never sees a reply that went missing, and that is what the rest rests on.**
  :func:`is_transient_refusal` re-raises anything that is not a
  :class:`~gantry_sftp.exceptions.ServerError` carrying ``FAILURE``; a lost reply is a
  :class:`~gantry_sftp.exceptions.TransferTimeoutError` and a dropped link is
  ``CONNECTION_LOST``, both of which belong to :mod:`gantry_sftp.session._retry`. So every
  refusal here is one the server *chose to send* -- a statement that the request was not
  performed, rather than the absence of a statement.

  **This is the distinction that kept the upload side out for two releases**, and it was a
  category error rather than a bound: "a ``WRITE`` whose reply was lost may or may not have
  landed" is true and is about the other mechanism. What an upload's ``OPEN`` needs from this
  one is only that repeating it reaches the same state, and every set of flags the upload path
  opens with does -- it rewrites the file from an offset computed before the open, so even a
  server that truncated and *then* refused leaves a state the retry reproduces.

  ``EXCL`` was held back from that for one release and is admitted by D-187, because the
  argument against it was about a case the ladder cannot reach. An exclusive create is a claim
  about a precondition, so a first attempt that created the file and then refused would leave the
  retry colliding with our own orphan -- but a collision is refused with a message no profile
  classifies (``File exists`` on the one server that explains itself at all), so it is terminal
  on the first sight of it. The retry cannot loop on one and cannot turn one into anything but
  the raise that happened without it. Measured rather than reasoned:
  ``_plans/probes/d187_excl_orphan_probe.py`` finds the file is not created at all under the
  condition this classifies, and the identical open succeeds once a descriptor is released.

  :func:`is_repeatable_open` is a separate predicate and stays that way. It is asked of the
  *caller's* flags on ``open_file``, where nothing knows what happens next, so it admits only an
  open that mutates nothing -- a stricter rule for a surface with less information, not an
  older version of the same one.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import anyio

from gantry_sftp._logging import fields_of, session_logger, summarise
from gantry_sftp.codec import OpenFlag, StatusCode
from gantry_sftp.exceptions import ServerError
from gantry_sftp.session._quirks import ServerProfile

__all__ = [
    "REPEATABLE_FLAGS",
    "TRANSIENT_ATTEMPTS",
    "TRANSIENT_BACKOFF",
    "TRANSIENT_BACKOFF_MAX",
    "is_repeatable_open",
    "is_transient_refusal",
    "open_for_read",
    "with_transient_retry",
]

REPEATABLE_FLAGS = OpenFlag.READ
"""The only ``pflags`` bit whose presence leaves an ``OPEN`` safe to issue twice.

Stated as what may be set rather than as what may not, and the difference is not stylistic.
``WRITE``, ``APPEND``, ``CREAT``, ``TRUNC`` and ``EXCL`` are the five that change something
today, so the two spellings agree on every flag v3 defines -- but they disagree on a bit v3 does
not, and they disagree in opposite directions. An allowlist refuses it; a denylist of the five
admits it, and ``~OpenFlag.READ`` is a denylist however it reads, because ``IntFlag`` inverts
over its *defined* members and yields exactly those five.

The failure directions are not symmetric, which is what settles it: too narrow costs a retry
nobody notices, too wide replays an ``OPEN`` that may have truncated a file.
"""

TRANSIENT_ATTEMPTS = 3
"""Total tries, not retries: one attempt and two more after it.

The same number :data:`~gantry_sftp.session.DEFAULT_ATTEMPTS` uses, for a different reason.
There, each attempt costs a fresh ``ssh`` fork and key exchange, so the bound is about expense.
Here an attempt costs one more request on a connection that is already open, and the bound is
about *the server*: the condition this exists for is resource exhaustion, and a client that
retries until it succeeds is a client helping to keep the resource exhausted.
"""

TRANSIENT_BACKOFF = 0.25
"""Seconds before the second attempt, doubling from there.

Shorter than :data:`~gantry_sftp.session.DEFAULT_BACKOFF`, and deliberately. That one waits out
a link that dropped, where a fresh connection is a fork and a handshake away. Recovery here is
another transfer on the same server closing a descriptor, which is neither -- the probe that
measured this condition saw the identical request succeed immediately once one was released.
"""

TRANSIENT_BACKOFF_MAX = 2.0
"""Ceiling on the doubling.

With :data:`TRANSIENT_ATTEMPTS` at 3 this is never reached, and it is here so that raising the
attempt count cannot silently turn a per-file retry into a multi-second stall per file in a
tree walk.
"""


async def open_for_read(
    opener: Callable[[bytes, OpenFlag], Awaitable[bytes]],
    path: bytes,
    profile: ServerProfile,
    *,
    what: str = "get",
) -> bytes:
    """``OPEN`` for reading, repeated while the server says its refusal was transient.

    Every read-open this library issues *on flags of its own choosing* goes through here: a
    download's concurrent ``STAT``/``OPEN`` pair, its resume path, both verification rungs, and
    :meth:`~gantry_sftp.session.Session.open_for_read`, which is this function with a session
    bound and the only spelling of it a caller outside the library has. ``get_tree`` needs no
    wiring of its own because it transfers by calling ``get`` per file.

    The one place that opens on flags the *caller* chose is
    :meth:`~gantry_sftp.session.RemoteFile.__aenter__`, which reaches
    :func:`with_transient_retry` directly under :func:`is_repeatable_open` rather than coming
    through here -- this function's whole signature is the assertion that the flags are ``READ``,
    and a variant taking them as an argument would be that assertion deleted (D-185).

    **The mechanism lives here rather than on ``Session`` deliberately**, and the public method
    above does not contradict that. ``Session`` is under a method ceiling that
    ``tests/test_layer_discipline.py`` enforces, whose advice is that an orchestration belongs
    beside the responsibility it orchestrates; this module is that responsibility, so the retry,
    its bound, its classifier and its log record stay together and the method on the class is
    one line of forwarding. The opener is passed in rather than the session, which also keeps
    this importable by the module ``Session`` itself imports.

    **Why the open and not the read.** The condition that made this buildable is descriptor
    exhaustion, and a ``READ`` runs against a descriptor the server already holds -- it cannot
    hit ``EMFILE``. So the refusal lands here, on the request that acquires the resource, and
    the downloader's shortfall re-queue is a different mechanism for a different failure. A
    transient mid-transfer ``READ`` is something nothing in the matrix has been made to produce.

    **Repeating an ``OPEN`` for reading is safe**, and that is what bounds this to reads. It
    acquires no exclusive claim, creates nothing and truncates nothing; an attempt whose reply
    was lost leaks a handle the reaper already owns (D-75). The upload side's ``WRITE`` has none
    of those properties, so it does not come through here -- it retries too, on a different
    argument its own opener carries (``_put._open_for_upload``), which is why this signature
    hard-codes ``READ`` instead of growing a flags parameter that would erase the distinction.

    **One read-open deliberately does not retry at all** (D-182), because "everything that opens
    for reading" would be the wrong rule: ``compatibility.py``'s probe must report what the
    server did, since retrying would paper over the behaviour the battery exists to observe. It
    calls :meth:`~gantry_sftp.session.Session.open` directly, so that stays true without an
    opt-out anybody has to remember -- and it says so at the site, because a missing retry is
    invisible.

    ``fsspec.py``'s two were the other exception and are not one any more (D-185). They reach
    the session through the blocking portal, which this signature cannot cross -- so the
    crossing is made once, by :meth:`~gantry_sftp.session.Session.open_for_read` and the twin
    the portal derives from it, rather than by the adapter reaching past the facade for a
    profile and a private ``_run``.

    Args:
        opener: The session's ``open``, bound.
        path: Remote path to open, already encoded and prefix-resolved.
        profile: Fingerprint of the server, which decides what counts as transient.
        what: Operation name for the log record. It is the only place this appears, and it must
            name the operation the *caller* is performing -- a verification retry recorded as
            ``get`` makes the one record of a swallowed refusal point at the wrong request.

    Returns:
        The handle.

    Raises:
        ServerError: The last refusal, unchanged. A refusal this server's profile does not
            classify as transient is raised on the first attempt.
    """
    return await with_transient_retry(
        lambda: opener(path, OpenFlag.READ), profile=profile, what=what
    )


def is_repeatable_open(pflags: OpenFlag) -> bool:
    """Whether an ``OPEN`` with these flags is safe to issue more than once.

    The property is *acquires no exclusive claim, creates nothing, truncates nothing* -- which
    is a statement about the mutating bits and not about ``READ`` being present. ``OpenFlag(0)``
    is a legal thing to pass and a degenerate open that servers refuse; repeating it is as safe
    as repeating a read, so an equality test against ``READ`` would classify it as a write.

    Compared as plain integers rather than with :class:`~gantry_sftp.codec.OpenFlag`'s own
    inversion, because ``~OpenFlag.READ`` is bounded to the members the enum defines and lets an
    undefined bit through as repeatable. A bit v3 does not define is a caller error either way;
    it costs nothing to have it fall on the safe side of one.

    Args:
        pflags: The flags the caller asked to open with.

    Returns:
        Whether the retry ladder may repeat this open.
    """
    return not int(pflags) & ~int(REPEATABLE_FLAGS)


def is_transient_refusal(error: BaseException, profile: ServerProfile) -> bool:
    """Whether ``error`` is a refusal ``profile`` says will pass on its own.

    Three conditions, and each excludes a way of being wrong:

    * a :class:`~gantry_sftp.exceptions.ServerError` -- a local failure, a protocol error or a
      cancellation is not the server refusing anything;
    * carrying ``FAILURE`` specifically, so a ``NO_SUCH_FILE`` whose message happens to contain
      a marker cannot match. v3's catch-all is the only code whose meaning is unknown enough to
      need the message read;
    * whose message this server's profile classifies, which is itself gated on the profile
      having measured messages at all.

    Args:
        error: The exception an attempt raised.
        profile: The fingerprint of the server that raised it.

    Returns:
        Whether one more attempt is warranted on the same session.
    """
    if not isinstance(error, ServerError):
        return False
    if error.code != StatusCode.FAILURE:
        return False
    return profile.classifies_transient(error.message)


async def with_transient_retry[T](
    request: Callable[[], Awaitable[T]],
    *,
    profile: ServerProfile,
    what: str,
    attempts: int = TRANSIENT_ATTEMPTS,
    backoff: float = TRANSIENT_BACKOFF,
    backoff_max: float = TRANSIENT_BACKOFF_MAX,
) -> T:
    """Run ``request``, repeating it while the server says its refusal was transient.

    The request must be safe to issue more than once, and **nothing here makes an unsafe one
    safe** -- that judgement belongs to the caller, which is the only code that knows what
    follows its own request. Every caller today is an ``OPEN``: for reading, where repeating
    acquires nothing and changes nothing, or one of the upload path's, where the argument is
    that the same file is rewritten from an offset computed beforehand. This sentence said
    *"every caller today is an ``OPEN`` for reading"* until D-187, and D-30's upload slice had
    already made that false.

    Args:
        request: Zero-argument callable issuing the request, awaited once per attempt.
        profile: Fingerprint of the server, which decides what counts as transient.
        what: Short name of the request, for the log record only.
        attempts: Total tries, including the first.
        backoff: Seconds before the second attempt, doubled after each refusal.
        backoff_max: Ceiling on that doubling.

    Returns:
        Whatever ``request`` returned.

    Raises:
        ValueError: If ``attempts`` is less than 1.
        ServerError: The last refusal, unchanged. A refusal the profile does not classify is
            re-raised immediately, without waiting out a backoff nobody wanted.
    """
    if attempts < 1:
        raise ValueError(f"attempts must be at least 1, got {attempts}")

    delay = backoff
    attempt = 0
    while True:
        attempt += 1
        try:
            return await request()
        except Exception as error:
            # `Exception`, never `BaseException`, matching `with_reconnect` -- but note what
            # actually keeps a cancelled transfer cancelled here, because the two are not the
            # same line. There, the narrowing *is* the guard. Here `is_transient_refusal`
            # refuses anything that is not a `ServerError`, and `ServerError` derives from
            # `Exception`, so widening this to `BaseException` is currently unobservable:
            # a cancellation would be caught and immediately re-raised by the check below.
            # Verified rather than assumed -- the mutation stays green against this file's
            # suite. It is kept narrow as defence in depth: a future classifier that grew a
            # broader rule would make this line load-bearing without anyone editing it.
            if not is_transient_refusal(error, profile) or attempt >= attempts:
                raise
            # Logged for the same reason `with_reconnect` logs: this failure is about to be
            # swallowed, and without a record a server that refuses every second OPEN is
            # indistinguishable at runtime from a healthy one.
            session_logger.warning(
                "%s refused as transient (attempt %d of %d), retrying in %.2fs",
                what,
                attempt,
                attempts,
                delay,
                extra=fields_of(
                    operation=what,
                    event="retrying_transient",
                    attempt=attempt,
                    attempts=attempts,
                    error=summarise(error),
                    delay=delay,
                    profile=profile.label,
                ),
            )
        await anyio.sleep(delay)
        delay = min(delay * 2, backoff_max)

"""The logger tree, the masking chokepoint, and the per-operation timer.

Three loggers, named so a caller can turn on exactly the volume they want:

``gantry_sftp.transport``
    Spawning the child, the environment overlay it is given, and teardown. DEBUG.

``gantry_sftp.session``
    One record when an operation starts and one when it ends, carrying what it moved and how
    long it took. DEBUG, plus the one WARNING below.

``gantry_sftp.frames``
    Every packet, both directions, rendered by :func:`gantry_sftp.codec.describe`. DEBUG, and
    genuinely per-frame -- a 16 MiB download is a few hundred lines, a recursive tree is
    thousands. Enable it for a protocol question, not as a matter of course.

**The library raises errors; it does not log them.** There is exactly one WARNING in the tree --
a retryable failure that :func:`~gantry_sftp.session.with_reconnect` swallowed and retried -- and
it exists because that is the one failure a caller never sees. Everything else that goes wrong
arrives as a typed exception carrying its own state, which is the surface that is *supposed* to
carry it; logging it as well would report it twice and invite handling it in the wrong place.

**Nothing is emitted unless the application configures logging.** The package logger gets a
:class:`logging.NullHandler`, so an unconfigured caller sees nothing at all -- not even
``logging.lastResort``'s stderr write for the WARNING.

Redaction
---------
:func:`mask_environment` is the chokepoint CLAUDE.md's Definition of Done 3 requires, and
:data:`SENSITIVE_ENVIRONMENT_KEYS` is its key list. It is used wherever an environment mapping
can reach a log record, and it is deliberately *not* the only defence:
:class:`~gantry_sftp.transport.Secret` already stops the same value rendering in a frame-locals
dump. Two mechanisms because they cover different surfaces -- ``Secret`` defends ``repr`` of a
*value*, this defends a *mapping* whoever built it, including one assembled from
``os.environ`` by a caller.

The value never reaches argv at all, which is why there is no argv masker: a password on a
command line is readable by every user on the machine through ``ps``, so this library puts it in
the child's environment via an askpass helper instead. See :mod:`gantry_sftp.transport._askpass`
for what that trade does and does not buy.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import PurePath
from time import monotonic

__all__ = [
    "MASKED",
    "MAX_VALUE_CHARS",
    "SENSITIVE_ENVIRONMENT_KEYS",
    "SENSITIVE_KEY_MARKERS",
    "frames_logger",
    "mask_environment",
    "operation",
    "session_logger",
    "summarise",
    "transport_logger",
]

logging.getLogger("gantry_sftp").addHandler(logging.NullHandler())

session_logger = logging.getLogger("gantry_sftp.session")
transport_logger = logging.getLogger("gantry_sftp.transport")
frames_logger = logging.getLogger("gantry_sftp.frames")

MASKED = "<redacted>"
"""What a masked value renders as. The same spelling :class:`gantry_sftp.transport.Secret` uses."""

MAX_VALUE_CHARS = 96
"""Characters of one rendered field a record will carry before it says how many it dropped.

The same bound :data:`gantry_sftp.codec.MAX_FIELD_BYTES` puts on a frame dump, for the same
reason: a remote path is chosen by the server, and a record per file is a per-file decision about
how much of the operator's disk this fills.
"""

SENSITIVE_ENVIRONMENT_KEYS = frozenset({"GANTRY_SFTP_ASKPASS_ANSWER"})
"""Environment variables this library knows carry a credential, matched exactly.

Currently one: the variable the askpass helper reads the answer from. Its own docstring says it
was named distinctly "so that a redaction key list has one unambiguous name to mask" -- this is
that list.
"""

SENSITIVE_KEY_MARKERS = ("PASSWORD", "PASSPHRASE", "SECRET", "TOKEN", "CREDENTIAL")
"""Substrings that make *any* variable a credential as far as this masker is concerned.

Matched case-insensitively and against variables this library never sets, on purpose: a caller
who passes their own ``env=`` overlay through gets covered too, and the failure mode of an
over-broad rule here is an unhelpful log line rather than a leaked secret. The exact-name list
above is what we *know*; this is what we *assume*.
"""


def mask_environment(env: Mapping[str, str]) -> dict[str, str]:
    """Copy ``env`` with every credential-bearing value replaced by :data:`MASKED`.

    Keys are preserved in full. Which variables were set is the diagnostic value of logging an
    environment at all -- this repository has already paid to learn that ``SSH_ASKPASS`` alone
    does not arm anything and ``SSH_ASKPASS_REQUIRE`` does -- and a key name is not a secret.

    Args:
        env: The environment, or the overlay applied to it.

    Returns:
        A new mapping. The input is never modified: it is frequently the very dictionary that
        is about to be handed to the child process.
    """
    return {key: MASKED if _is_sensitive(key) else value for key, value in env.items()}


def _is_sensitive(key: str) -> bool:
    """Whether a variable name means its value must not be rendered."""
    if key in SENSITIVE_ENVIRONMENT_KEYS:
        return True
    folded = key.upper()
    return any(marker in folded for marker in SENSITIVE_KEY_MARKERS)


@contextmanager
def operation(logger: logging.Logger, name: str, **fields: object) -> Iterator[dict[str, object]]:
    """Log the start and the end of one operation, with what it moved and how long it took.

    The yielded dictionary is where the body reports what it did -- ``result["bytes"] = n`` --
    so the closing record can carry a number that is only known at the end. Fields given here
    appear on both records; fields added to the dictionary appear only on the closing one.

    Cancellation and failure both close the record rather than losing it, which is the case
    worth having: "started, and you never heard from it again" is the log of a hang, and a
    transfer that was cancelled after 40 seconds looks exactly like one that hung unless
    something says so.

    Args:
        logger: Where the records go, so the caller's module names itself.
        name: The operation, in the spelling a user would recognise -- ``get``, ``put_tree``.
        **fields: Rendered onto both records. Untrusted values are safe: everything goes
            through :func:`repr`.

    Yields:
        A dictionary to record results into.
    """
    started = monotonic()
    result: dict[str, object] = {}
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("%s start%s", name, _render(fields))
    try:
        yield result
    except BaseException as error:
        # BaseException, so a cancelled transfer closes its record too. Re-raised unchanged --
        # this observes, it does not participate.
        if logger.isEnabledFor(logging.DEBUG):
            # `result` too: a tree that failed on its ninth file has recorded eight, and how far
            # it got is the first thing anyone asks. It is empty for an operation that failed
            # before recording anything, which renders as nothing at all.
            logger.debug(
                "%s failed%s%s %s elapsed=%.3fs",
                name,
                _render(fields),
                _render(result),
                type(error).__name__,
                monotonic() - started,
            )
        raise
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "%s ok%s%s elapsed=%.3fs", name, _render(fields), _render(result), monotonic() - started
        )


def summarise(error: BaseException) -> str:
    """One bounded, escaped line naming an exception and what it said.

    **Never interpolate an exception into a log record directly.**
    :class:`~gantry_sftp.exceptions.ConnectError` renders ``ssh``'s stderr verbatim, complete
    with newlines, and a server chooses part of that: OpenSSH prints a *server-supplied* banner
    there. Straight into a log stream that is a forged record per line. Correct for a traceback,
    which is what that rendering is for; wrong for a log, which is what this is for.

    Args:
        error: The exception to summarise.

    Returns:
        The class name and a ``repr``-escaped, truncated rendering of its message.
    """
    return f"{type(error).__name__} {_capped(repr(str(error)))}"


def _render(fields: Mapping[str, object]) -> str:
    """Render ``key=value`` pairs, escaping anything a server could have chosen.

    Every value goes through :func:`repr` unless it is a number, for the reason
    :mod:`gantry_sftp.codec._describe` gives at length: a filename is attacker-controlled, and a
    raw one in a log stream can forge a record with a newline or drive a terminal with an escape
    sequence. ``repr`` escapes both. Paths render as the string inside them rather than as
    ``PosixPath(...)``, which is the same escaping with less noise.
    """
    return "".join(f" {key}={_value(value)}" for key, value in fields.items())


def _value(value: object) -> str:
    if isinstance(value, bool | int | float):
        return str(value)
    if isinstance(value, PurePath):
        # `str(path)` rather than `repr(path)`: the escaping is identical, since it is applied
        # to the string either way, and `'/incoming/x'` reads better than `PosixPath('/incoming/x')`
        # in a line that already says which field it is.
        return _capped(repr(str(value)))
    return _capped(repr(value))


def _capped(rendered: str) -> str:
    """Bound one rendered value, because a server chooses how long its names are.

    Deliberately a second copy of the rule :data:`gantry_sftp.codec.MAX_FIELD_BYTES` states,
    rather than an import of it: the codec may not import :mod:`logging`, and this module is
    imported by ``transport/``, which has no business depending on the codec. Four lines is the
    price of keeping both of those true -- do not "consolidate" them.
    """
    if len(rendered) <= MAX_VALUE_CHARS:
        return rendered
    return f"{rendered[:MAX_VALUE_CHARS]}+{len(rendered) - MAX_VALUE_CHARS}"

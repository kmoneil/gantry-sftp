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

**The first two carry their fields as data, not only inside the message** (D-98). Every record
they emit has an ``extra`` mapping under :data:`LOG_FIELDS`, read back with
:func:`record_fields`, so a JSON sink indexes ``operation`` / ``bytes`` / ``elapsed`` instead of
re-parsing a sentence this module formatted. ``frames`` deliberately does not: it renders through
``codec.describe``, which returns a string by design, and a frame dump is text.

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
from collections.abc import Generator, Iterator, Mapping
from contextlib import contextmanager
from pathlib import PurePath
from time import monotonic

__all__ = [
    "LOG_FIELDS",
    "MASKED",
    "MAX_VALUE_CHARS",
    "SENSITIVE_ENVIRONMENT_KEYS",
    "SENSITIVE_KEY_MARKERS",
    "fields_of",
    "frames_logger",
    "mask_environment",
    "operation",
    "record_fields",
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

_SHORTEST_LITERAL = 2
"""Length of the shortest quoted ``repr`` there is: two quote characters and nothing between."""

MAX_VALUE_CHARS = 96
"""Characters of one rendered field a record will carry before it says how many it dropped.

The same bound :data:`gantry_sftp.codec.MAX_FIELD_BYTES` puts on a frame dump, for the same
reason: a remote path is chosen by the server, and a record per file is a per-file decision about
how much of the operator's disk this fills.
"""

LOG_FIELDS = "gantry"
"""The ``LogRecord`` attribute every structured field is attached under (D-98).

**One attribute holding a mapping, rather than one attribute per field**, and the reason is
that :mod:`logging` reserves its own: passing ``extra={"name": ...}`` or ``{"module": ...}``
raises ``KeyError: "Attempt to overwrite 'name' in LogRecord"`` **at emit time**, which turns a
log call into an application crash in whatever code path happened to log. Nesting under one
attribute of our own makes that collision impossible by construction rather than by a key list
somebody has to keep checking -- including for fields added later, which is the half a list
does not cover.

A formatter reads it with :func:`record_fields`, or directly::

    getattr(record, "gantry", {})

Records this library emits before an operation exists -- there are none today -- would carry
nothing, so a formatter must tolerate the attribute being absent. That is what
:func:`record_fields` is for.
"""

SENSITIVE_ENVIRONMENT_KEYS = frozenset({"GANTRY_SFTP_ASKPASS_ANSWER"})
"""Environment variables this library knows carry a credential, matched exactly.

Currently one: the variable the askpass helper reads the answer from. Its own docstring says it
was named distinctly "so that a redaction key list has one unambiguous name to mask" -- this is
that list.
"""

SENSITIVE_KEY_MARKERS = ("PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "TOKEN", "CREDENTIAL")
"""Substrings that make *any* variable a credential as far as this masker is concerned.

Matched case-insensitively and against variables this library never sets, on purpose: a caller
who passes their own ``env=`` overlay through gets covered too, and the failure mode of an
over-broad rule here is an unhelpful log line rather than a leaked secret. The exact-name list
above is what we *know*; this is what we *assume*.

``PASSWD`` is listed separately because it is **not** a substring of ``PASSWORD`` -- D-127, and
the shape is worth keeping in mind for the next entry: a marker list reads as though it covers
the spellings of a word and covers only the literal strings in it. ``SSH_PASSWD`` and
``FTP_PASSWD`` matched nothing until it was added.

``PWD`` is deliberately **not** here, which is why these are written out at their full length
rather than trimmed to a shorter common stem: ``$PWD`` is the working directory, it is purely
diagnostic, and masking it would redact a useful field on every record forever.
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


def fields_of(**fields: object) -> dict[str, dict[str, object]]:
    """Build the ``extra=`` mapping for one record, with every value made sink-safe.

    Use it wherever a record is emitted outside :func:`operation`::

        logger.debug("spawned pid=%s", pid, extra=fields_of(operation="spawn", pid=pid))

    **The values are the same ones the message renders**, converted by the same function, which
    is what stops the two drifting: a field that reads one way in the text and another in the
    JSON is worse than not having the field.

    Numbers stay numbers, because a threshold alert on ``bytes`` is the point of having the key
    at all. Everything else is ``repr``-escaped and capped exactly as in the message -- and for
    a remote path that is a decision rather than a formality. A server chooses its own names, so
    a path is neither guaranteed to be valid UTF-8 nor safe to hand to a sink raw: `bytes` is
    not JSON-serialisable at all, a lenient decode produces lone surrogates that
    ``json.dumps(...).encode()`` then refuses, and an unescaped name can carry the control
    characters a frame dump escapes for the same reason. ``repr`` of ``bytes`` is pure ASCII and
    survives every sink.

    Args:
        **fields: The record's fields, in the key set documented on :func:`operation`.

    Returns:
        A mapping suitable for ``extra=``, with everything nested under :data:`LOG_FIELDS`.
    """
    return _extra(fields)


def _extra(fields: Mapping[str, object]) -> dict[str, dict[str, object]]:
    r""":func:`fields_of` for a mapping that is already assembled.

    Separate from the keyword form for one reason, and it is a crash rather than a style
    preference: ``fields_of(**a, **b)`` raises ``TypeError`` when ``a`` and ``b`` share a key,
    inside a logging call, in whatever code path happened to be logging. Merging into a dict
    literal first lets the later value win -- which is also the right answer, since what an
    operation *recorded* is more current than what it was *called with*.

    **Every value is escaped; no key is exempt** (D-130). There used to be an
    ``OUR_OWN_VOCABULARY`` allowlist of four keys -- ``operation``, ``event``, ``error``,
    ``mechanism`` -- whose values skipped :func:`_structured` on the grounds that this library
    picks them from a closed set and that escaping would render ``"operation": "'get'"``. Both
    halves were wrong by the time the mutation lane reached this module. The quotes had already
    gone: :func:`_unquoted` strips them, so escaping an ASCII identifier is the identity
    function and the exemption bought *nothing* for the three keys that really are closed. And
    ``error`` is not closed -- it is ``type(exc).__name__`` for whatever exception crossed
    :func:`operation`, and ``type("bad\\nname", (Exception,), {})`` is a legal class, so the one
    key the allowlist could not vouch for was the one it exempted. `docs/observability.md` had
    said "names are escaped" without qualification throughout; the code was the half that was
    wrong. The allowlist shape is the finding, not its contents: it omitted silently, which is
    the same mechanism as D-132's.
    """
    return {LOG_FIELDS: {key: _structured(value) for key, value in fields.items()}}


def record_fields(record: logging.LogRecord) -> dict[str, object]:
    """The structured fields on ``record``, or an empty mapping if it carries none.

    The accessor a formatter should use, so that "which attribute" is this library's decision to
    change rather than a string in everybody's configuration.

    Args:
        record: Any log record, including one from another library.

    Returns:
        The fields, or ``{}``.
    """
    fields = getattr(record, LOG_FIELDS, None)
    return dict(fields) if isinstance(fields, dict) else {}


@contextmanager
def operation(logger: logging.Logger, name: str, **fields: object) -> Generator[dict[str, object]]:
    """Log the start and the end of one operation, with what it moved and how long it took.

    The yielded dictionary is where the body reports what it did -- ``result["bytes"] = n`` --
    so the closing record can carry a number that is only known at the end. Fields given here
    appear on both records; fields added to the dictionary appear only on the closing one.

    Cancellation and failure both close the record rather than losing it, which is the case
    worth having: "started, and you never heard from it again" is the log of a hang, and a
    transfer that was cancelled after 40 seconds looks exactly like one that hung unless
    something says so.

    **Every field is on the record as data as well as in the message** (D-98), under the
    :data:`LOG_FIELDS` attribute, so a JSON sink indexes them instead of re-parsing text this
    library formatted. Three keys are added here rather than by the call site, and they are the
    ones an operator filters on before any of the others:

    ``operation``
        ``name``, so a query can select every ``get`` without matching the message.
    ``event``
        ``"start"``, ``"ok"`` or ``"failed"`` -- the one field that says which of the pair a
        record is, and the one a "started but never finished" query needs.
    ``elapsed``
        Seconds, on the closing record only. ``error`` joins it on a failure, carrying the
        exception's class name.

    Args:
        logger: Where the records go, so the caller's module names itself.
        name: The operation, in the spelling a user would recognise -- ``get``, ``put_tree``.
        **fields: Rendered onto both records, and attached to both. Untrusted values are safe:
            everything goes through :func:`repr`.

    Yields:
        A dictionary to record results into.

    Note:
        The body is :func:`_operation` and **that split is for the mutation lane** (D-107),
        exactly as :func:`~gantry_sftp.transport._askpass.askpass_environment` is split. mutmut
        does not instrument a decorated function, so this one -- three ``isEnabledFor`` guards,
        two subtractions, and the ``start`` / ``ok`` / ``failed`` literals every record in the
        library is keyed on -- generated no mutants at all while it was decorated. Undecorated,
        the body is instrumented. Do not fold it back in.
    """
    yield from _operation(logger, name, **fields)


def _operation(logger: logging.Logger, name: str, **fields: object) -> Iterator[dict[str, object]]:
    """The body of :func:`operation`; see there for what it does and why it is split.

    Yields:
        The result dictionary, exactly once. ``yield from`` in the wrapper forwards a throw at
        the yield point straight into this generator, so the ``except BaseException`` below
        still sees a cancellation -- which is the whole reason the closing record survives one.
    """
    started = monotonic()
    result: dict[str, object] = {}
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "%s start%s",
            name,
            _render(fields),
            extra=_extra({"operation": name, "event": "start", **fields}),
        )
    try:
        yield result
    except BaseException as error:
        # BaseException, so a cancelled transfer closes its record too. Re-raised unchanged --
        # this observes, it does not participate.
        if logger.isEnabledFor(logging.DEBUG):
            # `result` too: a tree that failed on its ninth file has recorded eight, and how far
            # it got is the first thing anyone asks. It is empty for an operation that failed
            # before recording anything, which renders as nothing at all.
            elapsed = monotonic() - started
            logger.debug(
                "%s failed%s%s %s elapsed=%.3fs",
                name,
                _render(fields),
                _render(result),
                # Escaped here and raw below, so each is escaped exactly once: the message is
                # written straight out, while the field goes through `_extra`, which escapes
                # every value it is handed. See `_class_name` for why a class name needs it.
                _class_name(error),
                elapsed,
                extra=_extra(
                    {
                        "operation": name,
                        "event": "failed",
                        **fields,
                        **result,
                        "error": type(error).__name__,
                        "elapsed": elapsed,
                    }
                ),
            )
        raise
    if logger.isEnabledFor(logging.DEBUG):
        elapsed = monotonic() - started
        logger.debug(
            "%s ok%s%s elapsed=%.3fs",
            name,
            _render(fields),
            _render(result),
            elapsed,
            extra=_extra(
                {"operation": name, "event": "ok", **fields, **result, "elapsed": elapsed}
            ),
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
    return f"{_class_name(error)} {_capped(repr(str(error)))}"


def _class_name(error: BaseException) -> str:
    r"""An exception's class name, escaped like any other string this library did not choose.

    **A class name is not a closed set** (D-130). It reads like one -- every exception this
    library raises is declared with ``class`` and so has an identifier for a name -- which is
    why three sites interpolated ``type(error).__name__`` raw into a record. But ``__name__`` is
    whatever the type was built with, and ``type("bad\\nname", (Exception,), {})`` is a legal
    class, so a caller's exception could put a newline in a log line and forge the record after
    it. Escaping is free where the name really is an identifier: ``repr`` of one, with
    :func:`_unquoted` taking the quotes back off, is the identity function.
    """
    return _scalar(type(error).__name__)


def _render(fields: Mapping[str, object]) -> str:
    """Render ``key=value`` pairs, escaping anything a server could have chosen.

    Every value goes through :func:`repr` unless it is a number, for the reason
    :mod:`gantry_sftp.codec._describe` gives at length: a filename is attacker-controlled, and a
    raw one in a log stream can forge a record with a newline or drive a terminal with an escape
    sequence. ``repr`` escapes both. Paths render as the string inside them rather than as
    ``PosixPath(...)``, which is the same escaping with less noise.
    """
    return "".join(f" {key}={_value(value)}" for key, value in fields.items())


def _structured(value: object) -> object:
    """One value, keeping a collection's shape instead of flattening it into a string.

    **The cap belongs on a scalar, not on a rendered collection**, and getting that wrong made
    the field carry *less* than the sentence it came from -- the exact inversion D-98 exists to
    fix. ``argv`` and the steering environment render past 96 characters easily, so capping the
    whole ``repr`` truncated the spawn record mid-key: the one thing that record is for is
    which variables were set, and this repository has already paid to learn that ``SSH_ASKPASS``
    alone arms nothing while ``SSH_ASKPASS_REQUIRE`` does.

    So a list stays a list and a mapping stays a mapping -- which a JSON sink indexes as an
    array and an object rather than as one long string -- and the cap and the escaping apply to
    each scalar inside. Mapping *keys* go through the same escaping as values: a caller's own
    ``env=`` overlay reaches this surface, and a key is as capable of carrying a newline as a
    value is.
    """
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, Mapping):
        return {_scalar(key): _structured(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_structured(item) for item in value]
    return _scalar(value)


def _scalar(value: object) -> str:
    """One leaf value: escaped as the message escapes it, capped, and without the quotes."""
    return _capped(_unquoted(_rendered(value)))


def _value(value: object) -> str:
    if isinstance(value, bool | int | float):
        return str(value)
    return _capped(_rendered(value))


def _rendered(value: object) -> str:
    """``repr`` of one value, with a ``Path`` rendered as the string inside it.

    `str(path)` rather than `repr(path)`: the escaping is identical, since it is applied to the
    string either way, and `'/incoming/x'` reads better than `PosixPath('/incoming/x')` in a
    line that already says which field it is.
    """
    return repr(str(value)) if isinstance(value, PurePath) else repr(value)


def _unquoted(rendered: str) -> str:
    r"""``repr``'s escaping without ``repr``'s outer quotes, for a field a sink will index.

    The quotes are framing for a *sentence*: in ``remote=b'/incoming/x'`` they say where the
    value ends. In a JSON field they become part of the value, so an operator filtering on
    ``/incoming/x`` matches nothing and has to learn to write ``b'/incoming/x'`` instead --
    which is re-parsing our rendering, one layer in, and the thing D-98 is about.

    **Only the framing goes; every escape stays.** A newline is still ``\n`` and a
    non-ASCII byte still ``\xe9``, so a name the server chose cannot forge structure or drive
    a terminal, and a lone surrogate cannot break the sink's own encoder. Anything whose
    ``repr`` is not a quoted literal -- a list, a dict -- is returned untouched.
    """
    body = rendered[1:] if rendered.startswith(("b'", 'b"')) else rendered
    quoted = len(body) >= _SHORTEST_LITERAL and body[0] == body[-1] and body[0] in {"'", '"'}
    return body[1:-1] if quoted else rendered


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

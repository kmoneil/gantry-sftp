"""Exception hierarchy.

Errors carry state, not strings. The rule from DESIGN.md 9 is that an error names what
failed, where, and what to do about it -- so every class here holds the structured facts a
caller would otherwise have to recover by parsing a message.

**The whole hierarchy lives here**, in one module, which is not what this docstring used to
say: it described the transport and session errors as landing "with the layers that raise
them", and they were already ninety lines below it. One module is the right arrangement for a
different reason -- an ``except`` ladder is written against the tree, so the tree should be
readable in one place -- and the rule it was really stating survives: an exception class
nobody raises is dead code that looks like API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import override

__all__ = [
    "AuthenticationError",
    "CapabilityError",
    "ConnectError",
    "DestinationCollisionError",
    "DestinationNotAllowedError",
    "HostKeyError",
    "InsecureOptionWarning",
    "NoSuchFileError",
    "PathCollision",
    "PermissionDeniedError",
    "ProtocolError",
    "SFTPError",
    "SFTPWarning",
    "ServerError",
    "StateError",
    "TransferError",
    "TransferTimeoutError",
    "UnsafePathError",
    "UnsupportedError",
]


class SFTPError(Exception):
    """Base for every error this library raises.

    Catching this catches everything from the library and nothing from anywhere else.
    """


class StateError(SFTPError):
    """The library was asked to do something illegal in its current state.

    This is a **caller** error, and it is deliberately not a
    :class:`ProtocolError`: nothing was written to the wire, the peer never saw it, and the
    connection is still perfectly usable. Sending a request before the handshake finishes,
    or reusing a request id that is still in flight, raises this and changes nothing else.

    Keeping the two apart matters because the recovery differs. A ``ProtocolError`` means
    the stream can no longer be trusted and the connection is finished. A ``StateError``
    means fix the call.
    """


class ProtocolError(SFTPError):
    """The peer sent bytes this client cannot go on reading as filexfer v3.

    Almost always the *server's* fault or a transport corruption -- a well-formed request
    cannot provoke it. It is not retryable.

    **One case is nobody's fault**, and it is worth naming rather than filing under the
    sentence above: a server that speaks only filexfer v2 answers the handshake with ``2``,
    which ``draft-ietf-secsh-filexfer-02`` 4 requires of it. That server is correct and this
    client still cannot use it, so the refusal arrives here -- the stream after it is not v3
    and reading on would mean guessing at a layout. The message says which of the two happened;
    see :func:`gantry_sftp.codec._codec._version_refusal`.

    Attributes:
        packet_type: Numeric packet type, if the frame got far enough to have one.
        request_id: Request id the frame claimed, if it got far enough to have one.
        raw_frame: The offending bytes, truncated to ``max_frame_excerpt``. Held so a bug
            report can carry the actual frame instead of a description of it.
    """

    max_frame_excerpt = 256
    """Bytes of ``raw_frame`` retained. A hostile server can send a very large frame; the
    excerpt is capped so an exception cannot itself become the memory-exhaustion vector."""

    def __init__(
        self,
        message: str,
        *,
        packet_type: int | None = None,
        request_id: int | None = None,
        raw_frame: bytes | memoryview | None = None,
    ) -> None:
        super().__init__(message)
        self.packet_type = packet_type
        self.request_id = request_id
        self.raw_frame: bytes | None = (
            bytes(raw_frame[: self.max_frame_excerpt]) if raw_frame is not None else None
        )

    @override
    def __str__(self) -> str:
        """Render the message with whatever state was captured alongside it."""
        parts = [super().__str__()]
        if self.packet_type is not None:
            parts.append(f"packet_type={self.packet_type}")
        if self.request_id is not None:
            parts.append(f"request_id={self.request_id}")
        if self.raw_frame is not None:
            parts.append(f"raw_frame={self.raw_frame!r}")
        return " ".join(parts)


class ConnectError(SFTPError):
    """The transport could not be established, or died.

    Named ``ConnectError`` rather than ``ConnectionError`` on purpose. ``ConnectionError``
    is a builtin, and a user who writes ``from gantry_sftp import ConnectionError`` would
    silently stop catching the builtin one everywhere else in that module -- including the
    ``OSError`` subclasses their socket code depends on. Shadowing a builtin exception in a
    library that people will ``import *`` from is a trap, and DESIGN.md 9 is amended to
    match.

    Attributes:
        stderr: OpenSSH's standard error, **verbatim**, and bounded: the first 8 KiB and the
            last 56 KiB, with ``... [N bytes of stderr omitted] ...`` in between when a
            chatty child overflows it. Both ends are kept because the first lines say what
            was attempted and the last say how it ended, and ``ssh -vvv`` is exactly the
            situation that overflows the cap. This is the whole point of the class.
            ``Error reading SSH protocol banner`` is what paramiko tells you when the real
            message was ``Permission denied (publickey)`` or ``Host key verification
            failed`` -- the diagnosis was always there, and it was thrown away. It is not
            parsed here either, because parsing it would mean guessing, and the raw text is
            worth more than our guess about it. See
            :class:`~gantry_sftp.transport.StderrBuffer` for the two limits as tunables.
        argv: The exact command that was run, with no shell involved. Useful in a bug
            report and safe to show: credentials never appear in argv (see
            ``SSH_ASKPASS``), which is itself a design constraint rather than a habit.
        returncode: Exit status of the ``ssh`` process, if it exited.
        hint: What to do about it, when this client's own configuration or environment is
            what made the failure inevitable -- empty otherwise. It is separate from
            ``stderr`` because they have different authors: ``stderr`` is what OpenSSH and
            the server said, and a hint is what *we* know about the arguments we passed.
            Merging them would put words in the server's mouth. **Two functions produce
            one**, and between them they cover the two failures OpenSSH cannot explain
            itself: :func:`gantry_sftp.transport.password_auth_hint`, where two opposite
            causes print byte-identical stderr, and
            :func:`gantry_sftp.transport.missing_executable_hint`, where there is no stderr
            at all because ``ssh`` never ran.
    """

    def __init__(
        self,
        message: str,
        *,
        stderr: str = "",
        argv: tuple[str, ...] = (),
        returncode: int | None = None,
        hint: str = "",
    ) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.argv = argv
        self.returncode = returncode
        self.hint = hint

    @override
    def __str__(self) -> str:
        """Render the message with the subprocess's own diagnosis appended."""
        parts = [super().__str__()]
        if self.returncode is not None:
            parts.append(f"(exit status {self.returncode})")
        if self.stderr:
            parts.append(f"\nssh stderr:\n{self.stderr.rstrip()}")
        if self.hint:
            # Last, and labelled, so it is never mistaken for something the server said.
            parts.append(f"\nhint: {self.hint}")
        return " ".join(parts)


class AuthenticationError(ConnectError):
    """Authentication was refused.

    Raised when OpenSSH's stderr establishes it -- ``Permission denied`` in any of its
    variants, or ``Too many authentication failures``. The markers are captured from a real
    server rather than recalled, and the classifier is
    :func:`gantry_sftp.transport.classify_failure`.

    It exists because ``except AuthenticationError`` is the question users actually ask, and
    answering it with a substring search in their own code is worse. A refusal we cannot
    positively identify stays a plain :class:`ConnectError` with the stderr attached, because a
    class that sometimes means "we guessed" is worth less than one that always means what it
    says.
    """


class HostKeyError(ConnectError):
    """The server's host key was not accepted.

    Covers both shapes: a host that is not in ``known_hosts`` under strict checking, and a host
    whose key has *changed* -- which is the one that may be interception, and which OpenSSH
    escalates to a full warning banner. That banner reaches the caller intact.

    Distinguished from :class:`AuthenticationError` because the remedy is completely different,
    and because silently downgrading this one is how interception goes unnoticed. The
    classifier checks host-key markers *first* for exactly that reason: of the two possible
    misclassifications, only "a changed host key reported as a bad password" actually costs
    anything.

    Deliberately **not** raised for ``Unable to negotiate ... no matching host key type``. That
    mentions host keys and is not one -- the remedy is a ``HostKeyAlgorithms`` setting, not a
    changed identity, and folding it in would make this class mean two different things.
    """


class DestinationNotAllowedError(ConnectError):
    """The connection was refused by this process's own allowlist, before any host was dialled.

    D-121. Raised by :func:`gantry_sftp.allowed_hosts`' policy when the destination satisfies
    fewer than all of the active layers, and **also** when the destination cannot be determined
    at all -- a failed, timed-out or unparseable ``ssh -G`` probe. That second case is the
    errored third state of the predicate, and it refuses: any way of breaking the probe would
    otherwise be a way of defeating the allowlist.

    A :class:`ConnectError` rather than a sibling of it, because to the caller it is a
    connection that did not happen, and ``except ConnectError`` should not start missing
    failures because a policy was switched on.

    The distinction it carries that a message cannot: ``host`` is what the caller asked for and
    ``effective_host`` is what ``ssh_config`` turned it into, which are different whenever a
    ``Hostname`` or ``Match host`` rewrite is in play -- and telling an operator only the first
    would name a host that is not the one being refused. ``effective_host`` is ``None`` when the
    probe never got that far.

    Attributes:
        host: The destination as the caller supplied it.
        effective_host: What ``ssh -G`` reported, or ``None`` if it could not be read.
        layers: Every allowlist layer that was in force, outermost first.
    """

    def __init__(
        self,
        message: str,
        *,
        host: str,
        effective_host: str | None,
        layers: tuple[tuple[str, ...], ...],
        stderr: str = "",
        argv: tuple[str, ...] = (),
        returncode: int | None = None,
    ) -> None:
        # stderr/argv/returncode go to ConnectError rather than into the message, so a failed
        # probe renders through the same __str__ as every other connection failure. OpenSSH's
        # stderr verbatim is the base class's whole point; a subclass that formatted its own
        # copy would be the one place it arrived differently.
        super().__init__(message, stderr=stderr, argv=argv, returncode=returncode)
        self.host = host
        self.effective_host = effective_host
        self.layers = layers


class UnsafePathError(SFTPError):
    """A server-supplied name was refused rather than written to the filesystem.

    Names from ``READDIR`` and ``READLINK`` are chosen by the far end. A server answering with
    ``../../etc/cron.d/x`` during a recursive download is the zip-slip pattern, and it is a
    real and exploited vulnerability class in file-transfer clients rather than a theoretical
    one. This is raised **before** anything is opened, so nothing was written.

    Not a :class:`ServerError`: the server did not refuse anything, and the request was not
    even sent. It is closer to a protocol violation than to a refusal, but it is not that
    either -- a name containing ``..`` is legal SFTP, and it is only dangerous because of what
    we were about to do with it.

    Attributes:
        name: The offending name, verbatim and undecoded. Bytes, because a name that could not
            be decoded is exactly the kind that gets mishandled.
        reason: Short phrase naming what is wrong with it.
        destination: The directory the write was confined to, where there was one.
    """

    def __init__(
        self,
        message: str,
        *,
        name: bytes,
        reason: str,
        destination: str | None = None,
    ) -> None:
        super().__init__(message)
        self.name = name
        self.reason = reason
        self.destination = destination

    @override
    def __str__(self) -> str:
        """Render the message with the name and the boundary it would have crossed."""
        parts = [super().__str__()]
        if self.destination is not None:
            parts.append(f"destination={self.destination!r}")
        return " ".join(parts)


@dataclass(frozen=True, slots=True)
class PathCollision:
    """Two distinct remote paths that the local filesystem made into one file.

    Attributes:
        local: The local path both remote names produced.
        remote: The remote path that was refused. Bytes, because a name that could not be
            decoded is exactly the kind that collides in surprising ways.
        first: The remote path that reached that local file first, and whose contents are
            what is on disk. Which of the two arrives first is ``READDIR`` order, so it is
            the server's choice and is not reproducible.
    """

    local: str
    remote: bytes
    first: bytes


class DestinationCollisionError(SFTPError):
    """A recursive download could not be written faithfully: two remote names, one local file.

    **The local filesystem, not the server, is what makes this happen.** A remote tree holding
    both ``README.md`` and ``readme.md`` is entirely legal on a case-sensitive server and is a
    single file on APFS and NTFS -- the default on macOS and Windows. The same class of
    collapse produces ``report.`` and ``report`` on Windows, and an NFC/NFD pair on HFS+. So
    this is not an exotic-server problem: it is reachable by downloading an ordinary Linux tree
    onto an ordinary laptop.

    **Why it is an error and not a skip.** Without the check, the second write truncates the
    first and the walk reports success -- the tree looks copied, and one file's contents are
    gone with nothing anywhere saying so. Unlike the zip-slip case
    :class:`UnsafePathError` covers, containment cannot see this one: both paths are
    legitimately inside the destination. Everything transferable is still transferred before
    this is raised; what is refused is only the write that would have destroyed an earlier one.

    Attributes:
        collisions: Every refused path, with the remote path that already held its local file.
        destination: The directory the download was confined to.
        files: Files that did transfer before this was raised.
        transferred: Bytes that did transfer before this was raised.
    """

    def __init__(
        self,
        message: str,
        *,
        collisions: tuple[PathCollision, ...],
        destination: str,
        files: int = 0,
        transferred: int = 0,
    ) -> None:
        super().__init__(message)
        self.collisions = collisions
        self.destination = destination
        self.files = files
        self.transferred = transferred

    @override
    def __str__(self) -> str:
        """Render the message with the first collision and what did get through."""
        parts = [super().__str__(), f"destination={self.destination!r}"]
        if self.collisions:
            first = self.collisions[0]
            parts.append(f"{first.remote!r} would overwrite {first.first!r} at {first.local!r}")
        parts.append(f"(transferred {self.files} files, {self.transferred} bytes)")
        return " ".join(parts)


class SFTPWarning(UserWarning):
    """Base for warnings this library emits.

    A distinct category so callers can escalate ours to errors, or silence ours alone,
    without touching every other warning in their process.
    """


class InsecureOptionWarning(SFTPWarning):
    """A setting was chosen that weakens a security guarantee.

    Emitted rather than raised because these are legitimate choices in some environments --
    a throwaway container, a host key that genuinely rotates. "Overridable, loudly" means
    the override works and leaves a record; it does not mean it is a good idea.
    """


class TransferError(SFTPError):
    """A transfer failed partway through.

    Attributes:
        transferred: Bytes successfully moved before the failure. Partial progress is a fact
            the caller needs -- it is the difference between resuming and restarting, and
            discarding it is why so much SFTP tooling restarts a nine-gigabyte file from
            zero.
        offset: File offset the failing request covered.
        remote_path: The remote file, if known.
        local_path: The local file, if known -- and on a failed ``get`` that is **the file
            still sitting on disk**, because a download leaves its destination where it is
            rather than deleting the caller's file. Every failure ``get`` and ``put`` can
            raise carries it; a byte-range read or write has no local file and leaves it
            ``None``, which is the case that keeps "both paths" from becoming "invent the
            second one". It was absent from the download scheduler's errors until D-117 --
            exactly the path that creates an artefact worth naming.

    A failed transfer may also carry a **note**: :meth:`add_note` is where the transfer paths
    say what they left behind, since that is a fact about the operation rather than a field
    with a value. ``str()`` renders the fields; a traceback renders both.
    """

    def __init__(
        self,
        message: str,
        *,
        transferred: int = 0,
        offset: int | None = None,
        remote_path: bytes | None = None,
        local_path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.transferred = transferred
        self.offset = offset
        self.remote_path = remote_path
        self.local_path = local_path

    @override
    def __str__(self) -> str:
        """Render the message with the progress and location it happened at."""
        parts = [super().__str__()]
        parts.append(f"(after {self.transferred} bytes")
        if self.offset is not None:
            parts.append(f"at offset {self.offset}")
        parts.append(")")
        if self.remote_path is not None:
            parts.append(f"remote={self.remote_path!r}")
        if self.local_path is not None:
            parts.append(f"local={self.local_path!r}")
        return " ".join(parts).replace(" )", ")")


class TransferTimeoutError(TransferError):
    """The peer stopped responding while requests were outstanding.

    Separate from a plain :class:`TransferError` because the remedy differs: a refusal means
    stop, a timeout means the far end went quiet and retrying may well work.
    """


class ServerError(SFTPError):
    """The server refused an operation, and said so with a STATUS.

    This is the *server* declining, not a protocol violation and not our mistake -- the
    request was well-formed and the answer was no.

    Attributes:
        code: The numeric ``SSH_FX_*`` status.
        message: The server's own explanation, verbatim and undecoded. Servers are not
            required to send one and many do not, so this is frequently empty.
        path: The path the request concerned, where there was one.

    ``FAILURE`` is a v3 catch-all meaning nothing more than "no", which is why this class
    exists rather than a subclass per code: turning ``FAILURE`` into something actionable
    means reading ``message``, and ``message`` is exactly the field a server is free to omit.
    The subclasses below cover the codes that *are* unambiguous.
    """

    def __init__(
        self,
        message_text: str,
        *,
        code: int,
        message: bytes = b"",
        path: bytes | None = None,
    ) -> None:
        super().__init__(message_text)
        self.code = code
        self.message = message
        self.path = path

    @override
    def __str__(self) -> str:
        """Render our summary with the server's own words, where it supplied any."""
        parts = [super().__str__()]
        if self.path is not None:
            parts.append(f"path={self.path!r}")
        if self.message:
            parts.append(f"server said: {self.message.decode('utf-8', 'replace')!r}")
        return " ".join(parts)


class NoSuchFileError(ServerError):
    """``SSH_FX_NO_SUCH_FILE``. The path does not exist."""


class PermissionDeniedError(ServerError):
    """``SSH_FX_PERMISSION_DENIED``. The path exists and you may not have it."""


class UnsupportedError(ServerError):
    """``SSH_FX_OP_UNSUPPORTED``. The server does not implement this operation.

    Expected rather than exceptional: it is the answer to probing for an extension a server
    does not have, and the whole reason capability detection can be done by asking.
    """


class CapabilityError(SFTPError):
    """A guarantee was demanded that this server cannot provide, so nothing was attempted.

    Deliberately **not** a :class:`ServerError`, which is a refusal the server actually sent
    as a STATUS. This is our own refusal to silently downgrade: the caller asked for a
    property -- an atomic publish, a durability barrier -- and the extensions that deliver it
    are absent, so the operation stops rather than quietly doing something weaker that looks
    the same from the outside. An ``atomic=True`` that quietly was not is worse than one that
    refused.

    Distinguishing it from :class:`UnsupportedError` matters because the remedies differ.
    ``UnsupportedError`` means the server answered ``OP_UNSUPPORTED`` to something we sent;
    this means we did not send it, and the fix is either a different server or accepting the
    documented weaker mechanism.

    Attributes:
        feature: What was being attempted, in the caller's terms.
        missing: Extension names that would have made it possible. Empty when the obstacle is
            not an extension -- an existing target with no way to replace it in one step.
        path: The path concerned, where there was one.
    """

    def __init__(
        self,
        message: str,
        *,
        feature: str,
        missing: tuple[str, ...] = (),
        path: bytes | None = None,
    ) -> None:
        super().__init__(message)
        self.feature = feature
        self.missing = missing
        self.path = path

    @override
    def __str__(self) -> str:
        """Render the message with the feature and the extensions that would deliver it."""
        parts = [super().__str__()]
        parts.append(f"(feature={self.feature!r}")
        if self.missing:
            parts.append(f"missing={', '.join(self.missing)}")
        parts.append(")")
        if self.path is not None:
            parts.append(f"path={self.path!r}")
        return " ".join(parts).replace(" )", ")")


def _flatten_exception_group(error: BaseException) -> BaseException:
    """Reduce an ``ExceptionGroup`` to the first thing that actually went wrong.

    An anyio task group raises ``ExceptionGroup`` **even for a single failure**, which quietly
    breaks every ``except ConnectError`` and ``except TransferError`` in calling code: the
    ladder stops matching and the error surfaces as something nobody catches. CLAUDE.md names
    this as the default hazard of concurrent fan-out rather than an edge case, so every layer
    that runs a task group unwraps at its own boundary and callers keep the flat exception they
    were written against.

    It lives here rather than in either layer because both ``transport/`` and ``session/`` need
    it and neither imports the other -- and because two copies of this is how one of them ends
    up not applied, which is precisely the bug it exists to prevent. It was one copy, in
    ``session/_upload.py``, and the transport did not have it: an ``except ConnectError`` placed
    outside ``async with open_ssh_transport(...)`` -- the natural spelling, and the one the
    README documents -- never matched.

    Args:
        error: The exception to unwrap. Anything that is not a group is returned unchanged.

    Returns:
        The first leaf exception, or ``error`` itself if it is not a group. Nesting is followed
        all the way down, since a task group inside a task group nests the groups too.
    """
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error

"""Exception hierarchy.

Errors carry state, not strings. The rule from DESIGN.md 9 is that an error names what
failed, where, and what to do about it -- so every class here holds the structured facts a
caller would otherwise have to recover by parsing a message.

Only the classes something actually raises are defined. The rest of the hierarchy in
DESIGN.md 9 (``ConnectionError``, ``ServerError``, ``TransferError`` and their children)
lands with the layers that raise them; an exception class nobody raises is dead code that
looks like API.
"""

from __future__ import annotations

from typing import override

__all__ = [
    "AuthenticationError",
    "CapabilityError",
    "ConnectError",
    "HostKeyError",
    "InsecureOptionWarning",
    "NoSuchFileError",
    "PermissionDeniedError",
    "ProtocolError",
    "SFTPError",
    "SFTPWarning",
    "ServerError",
    "StateError",
    "TransferError",
    "TransferTimeoutError",
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
    """The peer sent bytes that are not valid filexfer v3.

    This is always the *server's* fault or a transport corruption -- a well-formed request
    cannot provoke it. It is not retryable.

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
        stderr: OpenSSH's standard error, **verbatim and untruncated**. This is the whole
            point of the class. ``Error reading SSH protocol banner`` is what paramiko
            tells you when the real message was ``Permission denied (publickey)`` or
            ``Host key verification failed`` -- the diagnosis was always there, and it was
            thrown away. It is not parsed here either, because parsing it would mean
            guessing, and the raw text is worth more than our guess about it.
        argv: The exact command that was run, with no shell involved. Useful in a bug
            report and safe to show: credentials never appear in argv (see
            ``SSH_ASKPASS``), which is itself a design constraint rather than a habit.
        returncode: Exit status of the ``ssh`` process, if it exited.
    """

    def __init__(
        self,
        message: str,
        *,
        stderr: str = "",
        argv: tuple[str, ...] = (),
        returncode: int | None = None,
    ) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.argv = argv
        self.returncode = returncode

    @override
    def __str__(self) -> str:
        """Render the message with the subprocess's own diagnosis appended."""
        parts = [super().__str__()]
        if self.returncode is not None:
            parts.append(f"(exit status {self.returncode})")
        if self.stderr:
            parts.append(f"\nssh stderr:\n{self.stderr.rstrip()}")
        return " ".join(parts)


class AuthenticationError(ConnectError):
    """Authentication was refused.

    Recognising this from OpenSSH's stderr is a job for the quirks layer; nothing raises it
    yet. It exists because ``except AuthenticationError`` is the question users actually
    ask, and answering it with a substring search in their own code is worse.
    """


class HostKeyError(ConnectError):
    """The server's host key was not accepted.

    Distinguished from :class:`AuthenticationError` because the remedy is completely
    different -- and because silently downgrading this one is how interception goes
    unnoticed.
    """


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
        local_path: The local file, if known.
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

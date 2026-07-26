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

__all__ = ["ProtocolError", "SFTPError", "StateError"]


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

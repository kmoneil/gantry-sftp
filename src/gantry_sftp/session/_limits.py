"""Server limits, and the request sizes derived from them.

Pure. Bytes and integers in, integers out -- no I/O, so the arithmetic that decides how fast
a transfer can possibly go is testable without a server.

Two traps live here, and both are the kind that ship silently wrong rather than visibly
broken. They are handled structurally rather than by remembering:

**A reported limit of ``0`` means "no limit", not zero.** The obvious
``min(our_size, server_limit)`` produces a zero-length READ, which makes no progress and
reads as a hang rather than a crash. Rather than trusting every future call site to
special-case it, ``0`` is normalised to ``None`` at construction, so the field's *type* is
``int | None`` and ``min()`` against it does not type-check. The illegal state is not
guarded against; it is unrepresentable.

**The payload ceiling sits below the packet ceiling.** Measured on OpenSSH 10.0p2:
``max-packet-length`` 262144 but ``max-read-length`` 261120, a 1024-byte gap for the type
byte, request id, handle and offset. So a request size of exactly ``max-packet-length`` is
never achievable — it gets clamped on every single request, forever, and the tuning knob
silently never means what it says. Sizes are therefore *derived* from the limits with the
framing overhead computed explicitly, never defaulted to a round number.
"""

from __future__ import annotations

from dataclasses import dataclass

from gantry_sftp.codec import WireReader

__all__ = [
    "DEFAULT_MAX_PACKET_LENGTH",
    "PREFERRED_READ_LENGTH",
    "PREFERRED_WRITE_LENGTH",
    "ServerLimits",
    "TransferSizes",
    "read_request_overhead",
    "write_request_overhead",
]

PREFERRED_READ_LENGTH = 261120
"""What we ask for when the server does not constrain us.

Not 262144. That round number is exactly the wrong default: it is 1024 bytes above what a
real OpenSSH server permits as a payload, so it would be clamped on every request. This is
the largest value OpenSSH actually allows, which makes the common case exact rather than
approximately right.
"""

PREFERRED_WRITE_LENGTH = 261120
"""Symmetric with :data:`PREFERRED_READ_LENGTH`, and clamped the same way."""

DEFAULT_MAX_PACKET_LENGTH = 262144
"""Assumed packet ceiling when the server does not advertise ``limits@openssh.com``.

Most enterprise endpoints advertise no extensions at all, so this is the normal path rather
than a fallback. It matches OpenSSH's value because OpenSSH is the only implementation whose
number we have actually measured.
"""

_MINIMUM_USEFUL_LENGTH = 1
"""A transfer request of zero bytes makes no progress. Sizes are clamped to at least this."""


def _no_limit_as_none(value: int) -> int | None:
    """Normalise the protocol's ``0``-means-unlimited into ``None``.

    Done once, here, so that nothing downstream can accidentally treat ``0`` as a clamp.
    """
    return value if value else None


@dataclass(frozen=True, slots=True)
class ServerLimits:
    """What the server says it will accept.

    Every field is ``None`` when the server imposes no limit, never ``0``. See the module
    docstring for why that distinction is enforced by the type rather than by a comment.
    """

    max_packet_length: int | None = None
    max_read_length: int | None = None
    max_write_length: int | None = None
    max_open_handles: int | None = None

    @classmethod
    def unknown(cls) -> ServerLimits:
        """Limits for a server that does not advertise ``limits@openssh.com``.

        Everything is ``None``: the server has told us nothing, which is different from
        telling us it has no limits. The distinction does not change the arithmetic --
        unknown and unlimited both mean "use our preference" -- but it does change what an
        honest ``repr`` can claim, and the quirks layer will care.
        """
        return cls()

    @classmethod
    def from_extended_reply(cls, data: bytes | memoryview) -> ServerLimits:
        """Decode the body of a ``limits@openssh.com`` EXTENDED_REPLY.

        Four ``uint64`` in order: max-packet-length, max-read-length, max-write-length,
        max-open-handles.

        Args:
            data: The reply body, with the request id already consumed.

        Returns:
            The decoded limits, with ``0`` normalised to ``None``.

        Raises:
            ProtocolError: If the body is not four ``uint64``.
        """
        reader = WireReader(data)
        return cls(
            max_packet_length=_no_limit_as_none(reader.read_uint64()),
            max_read_length=_no_limit_as_none(reader.read_uint64()),
            max_write_length=_no_limit_as_none(reader.read_uint64()),
            max_open_handles=_no_limit_as_none(reader.read_uint64()),
        )

    @property
    def effective_max_packet_length(self) -> int:
        """The packet ceiling to plan against, whether or not the server named one."""
        return self.max_packet_length or DEFAULT_MAX_PACKET_LENGTH


def read_request_overhead(handle_length: int) -> int:
    """Bytes a READ request costs on the wire before any payload.

    ``byte type`` + ``uint32 id`` + ``string handle`` + ``uint64 offset`` + ``uint32 len``.
    The length prefix is framing and is not counted against ``max-packet-length``.
    """
    return 1 + 4 + (4 + handle_length) + 8 + 4


def write_request_overhead(handle_length: int) -> int:
    """Bytes a WRITE request costs on the wire before its payload.

    ``byte type`` + ``uint32 id`` + ``string handle`` + ``uint64 offset`` + the ``uint32``
    length prefix of the data string.
    """
    return 1 + 4 + (4 + handle_length) + 8 + 4


class TransferSizes:
    """How many payload bytes to ask for per request, in each direction.

    Derived, never defaulted. Both values are guaranteed to be at least
    :data:`_MINIMUM_USEFUL_LENGTH`, so no caller can be handed a request size that makes no
    progress.

    **Not a dataclass, and the validation is in ``__init__`` rather than ``__post_init__``**
    (D-129). mutmut does not instrument the methods of a decorated class, so both guards below
    generated no mutants -- and a `< 1` guard is the exact shape D-105's sixteenth slice found
    survivors in on both schedulers, because every test passes a value the guard *rejects* and
    none passes the smallest it admits. Nothing compares these, so dataclass equality was
    buying nothing here either.
    """

    __slots__ = ("read_length", "write_length")

    def __init__(self, read_length: int, write_length: int) -> None:
        """Refuse to exist in a state that cannot make progress."""
        if read_length < _MINIMUM_USEFUL_LENGTH:
            raise ValueError(f"read_length must be at least 1, got {read_length}")
        if write_length < _MINIMUM_USEFUL_LENGTH:
            raise ValueError(f"write_length must be at least 1, got {write_length}")
        self.read_length = read_length
        self.write_length = write_length


def negotiate_transfer_sizes(
    limits: ServerLimits,
    *,
    handle_length: int,
    preferred_read: int = PREFERRED_READ_LENGTH,
    preferred_write: int = PREFERRED_WRITE_LENGTH,
) -> TransferSizes:
    """Work out the largest payload that will actually fit, in each direction.

    Three constraints apply and the smallest wins: what we would like, what the server says
    it will accept as a payload, and what leaves room for the request's own header inside
    ``max-packet-length``. The third is the one that is easy to forget and impossible to
    notice, because exceeding it does not error -- the server just clamps, on every request,
    forever.

    Args:
        limits: What the server advertised, or :meth:`ServerLimits.unknown`.
        handle_length: Length of the open handle, which is part of every request's header
            and therefore part of the budget. OpenSSH's are four bytes; nothing says
            another server's are.
        preferred_read: Largest read we would like to issue.
        preferred_write: Largest write we would like to issue.

    Returns:
        Sizes that fit every constraint, and are never zero.
    """
    packet_ceiling = limits.effective_max_packet_length

    read_budget = packet_ceiling - read_request_overhead(handle_length)
    read_length = min(preferred_read, read_budget)
    if limits.max_read_length is not None:
        read_length = min(read_length, limits.max_read_length)

    write_budget = packet_ceiling - write_request_overhead(handle_length)
    write_length = min(preferred_write, write_budget)
    if limits.max_write_length is not None:
        write_length = min(write_length, limits.max_write_length)

    # A pathological server -- a tiny max-packet-length, or a handle longer than the packet
    # ceiling -- can drive these to zero or below. Refusing to make progress is worse than
    # sending a request the server may reject, and a rejection at least says something.
    return TransferSizes(
        read_length=max(read_length, _MINIMUM_USEFUL_LENGTH),
        write_length=max(write_length, _MINIMUM_USEFUL_LENGTH),
    )

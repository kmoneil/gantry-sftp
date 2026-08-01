"""The client-side protocol state machine. Bytes in, events out.

Owns the three things that have to agree with each other: the handshake, request-id
allocation, and request/response correlation. They are one object because they are one
invariant -- an id is allocated, becomes outstanding, and is retired by the reply that
matches it, and a counter designed apart from the table it feeds gets the wrong interface.

Still pure. No clock, no sockets, no ``await``. Feed it what the transport read; it returns
what happened.

Usage::

    codec = Codec()
    transport.send(codec.initiate())

    request_id = codec.allocate_request_id()
    transport.send(codec.send(RealPath(request_id, b".")))

    for event in codec.receive(transport.recv()):
        match event:
            case Negotiated(version=v):
                ...
            case Completed(request=req, response=resp):
                ...

This drives the client half. A server implementation is a sibling state machine over the
same codec, not a flag on this one -- the two have different legal packets, a different
handshake direction, and no shared state to justify the branching.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, auto
from types import MappingProxyType
from typing import override

from gantry_sftp.codec._constants import PROTOCOL_VERSION
from gantry_sftp.codec._framing import DEFAULT_MAX_FRAME_LENGTH, FrameSplitter
from gantry_sftp.codec._packets import (
    Init,
    Request,
    Response,
    Version,
    decode,
    encode,
)
from gantry_sftp.exceptions import ProtocolError, StateError

__all__ = ["Codec", "CodecState", "Completed", "Event", "Negotiated"]

_MIN_REQUEST_ID = 1
_MAX_REQUEST_ID = 0xFFFFFFFF


class CodecState(Enum):
    """Where the connection is in its lifecycle."""

    NEW = auto()
    """Nothing sent yet. :meth:`Codec.initiate` is the only legal move."""

    AWAITING_VERSION = auto()
    """INIT sent, VERSION not yet received. Requests are illegal until it arrives."""

    READY = auto()
    """Negotiated. Requests may be sent and replies correlated."""

    FAILED = auto()
    """A protocol error occurred. Terminal.

    Nothing is recoverable from here, and pretending otherwise is how a desynchronised
    stream turns into wrong data instead of an error.
    """


@dataclass(frozen=True, slots=True)
class Negotiated:
    """The server answered INIT with VERSION.

    Attributes:
        version: The protocol version the server chose.
        extensions: Advertised name/version pairs, in advertisement order. Versions are
            byte strings (``b"1"``), not integers.
    """

    version: int
    extensions: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True, slots=True)
class Completed:
    """A response arrived and matched an outstanding request.

    The request is carried alongside the response because the caller almost always needs
    it -- to know which path a STATUS refers to, or which offset a DATA belongs at -- and
    making them re-derive it from an id is how offsets get mismatched.

    A ``Completed`` carrying a :class:`~gantry_sftp.codec.Data` response holds a view into
    the frame buffer; it stays valid for as long as it is referenced.
    """

    request: Request
    response: Response


Event = Negotiated | Completed
"""Anything the codec can report from a chunk of received bytes."""


class Codec:
    """Client-side filexfer v3 state machine.

    Args:
        max_frame_length: Passed through to the frame splitter as a DoS bound.
    """

    __slots__ = ("_extensions", "_next_id", "_outstanding", "_splitter", "_state", "_version")

    def __init__(self, *, max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH) -> None:
        self._splitter = FrameSplitter(max_frame_length=max_frame_length)
        self._state = CodecState.NEW
        self._version: int | None = None
        self._extensions: dict[bytes, bytes] = {}
        self._outstanding: dict[int, Request] = {}
        self._next_id = _MIN_REQUEST_ID

    # --- introspection -------------------------------------------------------------------

    @property
    def state(self) -> CodecState:
        """Current lifecycle state."""
        return self._state

    @property
    def server_version(self) -> int | None:
        """Version the server negotiated, or ``None`` before VERSION arrives."""
        return self._version

    @property
    def extensions(self) -> Mapping[bytes, bytes]:
        """Extensions the server advertised, as a read-only mapping of name to version.

        Empty before negotiation, and empty afterwards for the many servers that advertise
        nothing at all. Absence is the normal case, not an error.
        """
        return MappingProxyType(self._extensions)

    @property
    def outstanding(self) -> int:
        """How many requests have been sent and not yet answered."""
        return len(self._outstanding)

    @override
    def __repr__(self) -> str:
        """Show the state a debugging session actually needs."""
        version = "-" if self._version is None else self._version
        return (
            f"<Codec {self._state.name} version={version} "
            f"extensions={len(self._extensions)} outstanding={len(self._outstanding)}>"
        )

    # --- sending -------------------------------------------------------------------------

    def initiate(self, version: int = PROTOCOL_VERSION) -> bytes:
        """Encode the INIT that opens the connection.

        Args:
            version: Protocol version to request. Any value may be *asked* for, but the only
                one this codec can decode is :data:`~gantry_sftp.codec.PROTOCOL_VERSION`, so
                :meth:`receive` refuses a VERSION that negotiates anything else -- see
                :func:`_version_refusal` for the two ways that happens and why neither can be
                spoken to with a v3 decoder.

        Returns:
            Bytes to write to the transport.

        Raises:
            StateError: If INIT has already been sent. The handshake happens once.
            ProtocolError: If the connection has already failed.
        """
        self._require_state(CodecState.NEW, "send INIT")
        self._state = CodecState.AWAITING_VERSION
        return encode(Init(version=version))

    def allocate_request_id(self) -> int:
        """Reserve the next request id.

        Deterministic: a fresh codec hands out 1, 2, 3, and so on. Ids are ``uint32`` and
        wrap, skipping any that are still outstanding -- reusing an in-flight id would
        correlate a reply to the wrong request, which is indistinguishable from data
        corruption at every layer above.

        Zero is never issued. It is a legal wire value, but reserving it leaves an
        unambiguous "no request" sentinel for logs and debuggers.

        Returns:
            An id not currently in flight.

        Raises:
            StateError: If every id is in flight, which needs four billion concurrent
                requests and is here so the wrap loop cannot spin forever.
        """
        if len(self._outstanding) > _MAX_REQUEST_ID - _MIN_REQUEST_ID:
            raise StateError("every request id is in flight; cannot allocate another")

        while self._next_id in self._outstanding:
            self._next_id = self._advance(self._next_id)

        allocated = self._next_id
        self._next_id = self._advance(allocated)
        return allocated

    @staticmethod
    def _advance(request_id: int) -> int:
        return _MIN_REQUEST_ID if request_id >= _MAX_REQUEST_ID else request_id + 1

    def send(self, request: Request) -> bytes:
        """Record ``request`` as outstanding and encode it.

        Args:
            request: The request to send, carrying an id from :meth:`allocate_request_id`.

        Returns:
            Bytes to write to the transport.

        Raises:
            StateError: If the handshake has not completed, or if the request's id is
                already in flight. A duplicate id is refused rather than accepted, because
                the reply to it could not be attributed to either sender. Neither case
                touches the wire, so neither ends the connection.
            ProtocolError: If the connection has already failed.
        """
        self._require_state(CodecState.READY, f"send {type(request).__name__}")

        request_id = request.request_id
        if request_id in self._outstanding:
            existing = type(self._outstanding[request_id]).__name__
            raise StateError(
                f"request id {request_id} is already in flight for a {existing}; "
                f"ids come from allocate_request_id() and are free again once answered"
            )

        wire = encode(request)
        self._outstanding[request_id] = request
        return wire

    # --- receiving -----------------------------------------------------------------------

    def receive(self, data: bytes | memoryview) -> list[Event]:
        """Feed received bytes and return everything that completed.

        Args:
            data: Bytes as read from the transport.

        Returns:
            Events in wire order. Empty if ``data`` did not finish a frame.

            **Events decoded before a failing frame in the same chunk are discarded with the
            error**, and that is a decision rather than an oversight. One call cannot return
            a value and raise, the connection is terminal either way, and the discard costs
            an operation that really did complete being reported as failed -- which is the
            safe direction. Reporting the reverse is what this class exists to prevent.

        Raises:
            ProtocolError: On a malformed frame, a packet illegal in the current state, or a
                reply that matches no outstanding request. All are terminal: the codec moves
                to :attr:`CodecState.FAILED` and every later call raises.
        """
        if self._state is CodecState.FAILED:
            raise ProtocolError("codec is in a failed state; the connection is not recoverable")

        events: list[Event] = []
        try:
            for frame in self._splitter.feed(data):
                events.append(self._handle(decode(frame)))
        except ProtocolError:
            # Three sources, one consequence. `_handle` fails the codec for the cases it owns
            # -- a reply nobody asked for, a second VERSION, a server-sent request -- and
            # until 0.8 the other two were not covered at all: a length the splitter rejects
            # and a body the decoder cannot parse both left the state at READY, so the next
            # `receive()` carried on reading a stream whose frame boundaries are no longer
            # known. That does not surface as an error; it surfaces as replies correlated to
            # the wrong requests, which is a DATA payload written at another request's offset
            # -- a file of exactly the right length with the wrong contents.
            self._state = CodecState.FAILED
            raise
        return events

    def _handle(self, packet: object) -> Event:
        if isinstance(packet, Version):
            return self._handle_version(packet)
        if isinstance(packet, Init):
            raise self._fail("server sent INIT; INIT is a client-to-server packet")
        if not isinstance(packet, Response):
            raise self._fail(
                f"server sent {type(packet).__name__}, which is a request; "
                f"a client never receives requests"
            )
        return self._handle_response(packet)

    def _handle_version(self, packet: Version) -> Negotiated:
        if self._state is not CodecState.AWAITING_VERSION:
            raise self._fail(
                f"server sent VERSION while {self._state.name}; the handshake happens once"
            )
        if packet.version != PROTOCOL_VERSION:
            raise self._fail(_version_refusal(packet.version))
        self._state = CodecState.READY
        self._version = packet.version
        # Last wins, matching how a dict of advertised pairs would be built anywhere else.
        # The ordered tuple is preserved on the event for anyone who cares.
        self._extensions = dict(packet.extensions)
        return Negotiated(version=packet.version, extensions=packet.extensions)

    def _handle_response(self, packet: Response) -> Completed:
        if self._state is not CodecState.READY:
            raise self._fail(
                f"server sent {type(packet).__name__} while {self._state.name}; "
                f"nothing is answerable before VERSION"
            )

        request = self._outstanding.pop(packet.request_id, None)
        if request is None:
            raise self._fail(
                f"server sent {type(packet).__name__} for request id {packet.request_id}, "
                f"which is not outstanding; it was never sent, or it was already answered",
                request_id=packet.request_id,
            )
        return Completed(request=request, response=packet)

    # --- failure -------------------------------------------------------------------------

    def _require_state(self, expected: CodecState, action: str) -> None:
        """Guard a caller-driven operation.

        A failed connection and a merely-premature call are different problems with
        different fixes, so they raise different exceptions. Neither writes to the wire, so
        neither makes things worse.
        """
        if self._state is CodecState.FAILED:
            raise ProtocolError("codec is in a failed state; the connection is not recoverable")
        if self._state is not expected:
            raise StateError(f"cannot {action} while {self._state.name}")

    def _fail(self, message: str, *, request_id: int | None = None) -> ProtocolError:
        """Build the terminal error to raise. The latch itself lives in :meth:`receive`.

        Only for peer misbehaviour. A caller mistake raises
        :class:`~gantry_sftp.exceptions.StateError` and leaves the connection alone -- the
        wire was never touched, so there is nothing to distrust.

        Returned rather than raised so the call site reads ``raise self._fail(...)`` and
        static analysis can see the control flow.

        This set :attr:`CodecState.FAILED` itself until 0.8. Widening the latch to
        ``receive``'s ``except ProtocolError`` -- which had to happen, because a length the
        splitter rejects and a body the decoder cannot parse never reach this method -- made
        that assignment dead: every call site is inside that ``try``, so the handler
        overwrote whatever was written here. The mutation lane is what noticed. Setting
        ``None`` instead survived every test, not because a test was missing but because no
        reachable path could tell the two apart.
        """
        return ProtocolError(message, request_id=request_id)


def _version_refusal(version: int) -> str:
    """Why a negotiated version that is not ours cannot be spoken to. Two cases, two messages.

    **Nothing checked this until 0.12**, and the gap was not that a violation went unreported
    -- it was that the *legal* case went unreported. ``draft-ietf-secsh-filexfer-02`` 4 has the
    server answer with the lower of its own version and the client's, so a server that speaks
    only v2 answering ``2`` is behaving correctly and this client then spoke v3 at it anyway.

    The two cases are kept apart because the remedies are opposite: below is a server doing the
    right thing that this client cannot use, above is a server violating the handshake. Both
    are terminal -- :meth:`Codec.receive` latches :attr:`CodecState.FAILED` on the
    :class:`~gantry_sftp.exceptions.ProtocolError` this builds -- because a stream whose ATTRS
    layout we have guessed wrong is not one to keep reading.

    Args:
        version: What the server put in its VERSION reply.

    Returns:
        The message, naming the version, the rule it broke or kept, and what goes wrong next.
    """
    if version < PROTOCOL_VERSION:
        return (
            f"server negotiated filexfer v{version} and this client implements only "
            f"v{PROTOCOL_VERSION}; draft-ietf-secsh-filexfer-02 4 has the server answer with "
            f"the lower of its own version and ours, so this server is behaving correctly and "
            f"simply cannot speak v3 -- 10.1 lists READLINK, SYMLINK and EXTENDED as v3 "
            f"additions, and nothing tells a v3 client which of its requests this server knows"
        )
    return (
        f"server negotiated filexfer v{version}, above the v{PROTOCOL_VERSION} this client "
        f"implements; draft-ietf-secsh-filexfer-02 4 requires the answer to be the lower of "
        f"the two versions, so a version above ours is a protocol violation -- and v4 ATTRS "
        f"puts a 'byte type' ahead of every optional field (draft-04 5), which a v3 decoder "
        f"reads as the leading byte of whatever comes next"
    )

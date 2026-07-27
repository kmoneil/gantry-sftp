"""One reader task, and the per-request waiters it feeds.

SFTP already multiplexes. Request ids exist so that many operations can share one channel and
each reply can be attributed to the request it answers. What stopped this library exploiting
that was not the protocol but the plumbing: **two receive loops on one pipe steal each other's
frames.** Whichever task happens to read the chunk carrying a reply is the task that decodes
it, and the task actually waiting for that reply never sees it. So the session serialised
everything behind a lock -- correct, and unable to overlap a single round trip with another.

This module is the fix, and it is the whole of it. :class:`Dispatcher` owns
``transport.receive()`` and nothing else calls it. An operation opens an :class:`Exchange`,
sends its requests through that, and reads replies from it; the reader routes each
``Completed`` to the exchange whose request it answers. A download is then a *consumer* of
replies rather than a driver of the connection, which is what lets two of them run at once.

Three properties are load-bearing
---------------------------------
* **The reader never raises.** A transport that dies or a server that speaks nonsense is
  recorded as the dispatcher's failure and handed to every live exchange, and the reader
  returns. Letting it raise instead would surface a connection failure as an
  ``ExceptionGroup`` from the ``async with open_session(...)`` line -- at the *session's*
  boundary rather than at the call that failed -- and would report it twice, once to the
  waiter and once to the task group. See :func:`~gantry_sftp.exceptions.flatten_exception_group`
  for why a group at a public boundary is a bug rather than a detail.
* **A failure reaches every waiter.** Concurrent fan-out means a dead connection can have
  several tasks parked on it, and one that is never woken is a hang. Every exchange is
  registered for the lifetime of its operation, not merely while it has a request in flight.
* **Writes are serialised.** anyio raises ``BusyResourceError`` if two tasks write to one
  stream at once, and an interleaved write would corrupt the frame anyway. Order between
  independent requests is not a protocol requirement -- ids correlate the replies -- so a lock
  around the write costs nothing but the hand-off.

What this does *not* do is bound concurrency. How many operations run at once is the caller's
decision, made with an anyio task group; this only makes sure they do not tread on each other.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override

import anyio

from gantry_sftp.codec import Codec, Completed, Event, Request
from gantry_sftp.exceptions import ProtocolError, StateError
from gantry_sftp.transport import Transport

__all__ = ["Dispatcher", "Exchange"]


class Exchange:
    """The requests one operation has in flight, and the queue their replies arrive in.

    Opened by :meth:`Dispatcher.exchange`, which retires whatever is still outstanding when
    the block ends. One task consumes an exchange; :meth:`send` may be called from a second
    one, which is what the uploader does -- it sends and drains concurrently so that neither
    half has to finish before the other starts.

    :meth:`deliver` and :meth:`fail` are the dispatcher's half of the arrangement and are not
    for callers.
    """

    __slots__ = ("_arrived", "_dispatcher", "_failure", "_outstanding", "_ready")

    def __init__(self, dispatcher: Dispatcher) -> None:
        self._dispatcher = dispatcher
        self._outstanding: set[int] = set()
        self._ready: deque[Completed] = deque()
        self._arrived = anyio.Event()
        self._failure: BaseException | None = None

    @property
    def outstanding(self) -> int:
        """Requests sent through this exchange and not yet answered."""
        return len(self._outstanding)

    @property
    def request_ids(self) -> frozenset[int]:
        """Ids this exchange is still expecting replies for."""
        return frozenset(self._outstanding)

    @override
    def __repr__(self) -> str:
        """Show what a stalled operation would make you want to look at."""
        state = "failed" if self._failure is not None else "open"
        return f"<Exchange {state} outstanding={len(self._outstanding)} ready={len(self._ready)}>"

    async def send(self, request: Request) -> None:
        """Send ``request``, routing its reply here.

        The id must come from :meth:`~gantry_sftp.codec.Codec.allocate_request_id` and must
        reach here without an ``await`` in between -- an id is only reserved once the codec
        records it as outstanding, which happens inside this call. Every caller builds the
        packet and sends it in one synchronous stretch, so the window never opens; a caller
        that did not would get a loud ``StateError`` about a duplicate id rather than a
        misrouted reply.

        Raises:
            StateError: If the session is closed, or the id is already in flight.
            ConnectError: If the connection has already failed, or fails on the write.
            ProtocolError: If the codec has already failed.
        """
        self._outstanding.add(request.request_id)
        await self._dispatcher.submit(request, self)

    async def receive(self) -> Completed:
        """Wait for the next reply to one of this exchange's requests.

        Replies are returned in arrival order, which is **not** the order they were sent in.
        Out-of-order completion is the normal case for a pipelined transfer, not an anomaly.

        Raises:
            ConnectError: If the connection failed while waiting.
            ProtocolError: If the server sent something the codec could not accept.
        """
        while True:
            if self._ready:
                return self._ready.popleft()
            if self._failure is not None:
                raise self._failure
            # Re-armed before the wait and never after: `deliver` appends and then sets, so
            # anything that arrives before this line is already visible in `_ready` above,
            # and anything after it sets the event this is about to wait on. There is no
            # await between the two statements, so no delivery can fall between them.
            self._arrived = anyio.Event()
            await self._arrived.wait()

    def deliver(self, event: Completed) -> None:
        """Hand a reply to whoever is waiting. Called by the dispatcher."""
        self._outstanding.discard(event.request.request_id)
        self._ready.append(event)
        self._arrived.set()

    def fail(self, error: BaseException) -> None:
        """Report that the connection is finished. Called by the dispatcher.

        Replies that already arrived are still delivered first: they are real data, they
        were paid for, and discarding them would turn a clean short transfer into a failure.
        """
        self._failure = error
        self._arrived.set()


class Dispatcher:
    """The single reader over one transport, and the router for what it decodes.

    Args:
        transport: A connected transport whose handshake is already done. From construction
            on, nothing else may call ``receive`` on it.
        codec: The negotiated codec. Owned jointly with the session, which reads the
            negotiated version and the advertised extensions off it.
    """

    __slots__ = (
        "_closed",
        "_codec",
        "_exchanges",
        "_failure",
        "_routes",
        "_send_lock",
        "_transport",
        "_unclaimed",
    )

    def __init__(self, transport: Transport, codec: Codec) -> None:
        self._transport = transport
        self._codec = codec
        self._routes: dict[int, Exchange] = {}
        self._exchanges: set[Exchange] = set()
        self._send_lock = anyio.Lock(fast_acquire=True)
        """Serialises writes, and deliberately does not yield to take an uncontended one.

        anyio's default ``Lock`` runs a checkpoint on every acquire even when nothing is
        holding it, so the plain spelling would cost an event-loop round trip per request --
        on a path that issues one per 255 KiB of a transfer. The starvation that
        ``fast_acquire`` normally risks needs a loop with no other checkpoint in it, and the
        write this guards is itself one."""
        self._failure: BaseException | None = None
        self._closed = False
        self._unclaimed = 0

    @property
    def codec(self) -> Codec:
        """The state machine this reader feeds.

        Exposed because the session reports the negotiated version and the server's
        advertised extensions, and allocates request ids, from the same object -- handing it
        over rather than passing it twice is what keeps the two from being different codecs.
        """
        return self._codec

    @property
    def failure(self) -> BaseException | None:
        """What killed the connection, or ``None`` while it is healthy."""
        return self._failure

    @property
    def unclaimed(self) -> int:
        """Replies that arrived for a request nobody was waiting for any more.

        Never an error, and worth counting. A request abandoned by a timeout stays
        outstanding on the server, so its reply turns up later with no waiter left; a
        non-zero count here is the visible trace of that, and the first thing to look at
        when a session is behaving as though it is one reply behind.
        """
        return self._unclaimed

    @override
    def __repr__(self) -> str:
        """Report the routing state a stalled or leaking session would need."""
        state = "closed" if self._closed else "failed" if self._failure is not None else "open"
        return (
            f"<Dispatcher {state} exchanges={len(self._exchanges)} "
            f"routes={len(self._routes)} unclaimed={self._unclaimed}>"
        )

    # --- the reader ------------------------------------------------------------------------

    async def run(self) -> None:
        """Read the transport until it ends, routing everything it decodes.

        **Never raises**, cancellation excepted. Whatever goes wrong becomes the failure
        every live exchange is handed, so it surfaces at the operation that was waiting for
        it rather than at the session's context manager -- with its own type intact instead
        of wrapped in an ``ExceptionGroup``.

        Runs until cancelled, which is what :func:`~gantry_sftp.session.open_session` does
        when its block ends: a blocking read cannot be stopped any other way.
        """
        try:
            while True:
                for event in self._codec.receive(await self._transport.receive()):
                    self._route(event)
        except Exception as error:
            # Deliberately as broad as it can be without swallowing cancellation, which is
            # a BaseException and is how this task is meant to end. Anything narrower would
            # let an unforeseen failure kill the reader while every waiter stayed parked --
            # a hang instead of an error, on the one task nobody is awaiting.
            self._fail(error)

    def _route(self, event: Event) -> None:
        if not isinstance(event, Completed):  # pragma: no cover -- codec refuses a 2nd VERSION
            raise ProtocolError(f"server sent {type(event).__name__} after the handshake")
        exchange = self._routes.pop(event.request.request_id, None)
        if exchange is None:
            self._unclaimed += 1
            return
        exchange.deliver(event)

    def _fail(self, error: BaseException) -> None:
        """Record the failure and wake everyone parked on this connection.

        Every live exchange gets the same exception instance. Constructing a copy per waiter
        would lose the state these errors exist to carry -- ``ConnectError`` holds ssh's
        stderr verbatim -- and the shared instance is what makes two concurrent transfers
        report the same cause rather than two guesses at it.
        """
        self._failure = error
        self._routes.clear()
        for exchange in self._exchanges:
            exchange.fail(error)

    def close(self) -> None:
        """Refuse further work. Does not stop the reader; cancelling ``run`` does that."""
        self._closed = True

    # --- exchanges -------------------------------------------------------------------------

    @contextmanager
    def exchange(self) -> Iterator[Exchange]:
        """Open an exchange for one operation, and retire it when the block ends.

        Retiring matters on the failure path. An operation abandoned by a timeout leaves
        requests outstanding on the server, and their replies will arrive; without this the
        routing table would keep a dead exchange alive for each one, which is a leak that
        grows with every timeout.
        """
        exchange = Exchange(self)
        self._exchanges.add(exchange)
        try:
            yield exchange
        finally:
            self.retire(exchange)

    def retire(self, exchange: Exchange) -> None:
        """Forget an exchange and any reply still routed to it."""
        self._exchanges.discard(exchange)
        for request_id in exchange.request_ids:
            _ = self._routes.pop(request_id, None)

    async def submit(self, request: Request, exchange: Exchange) -> None:
        """Encode ``request``, route its reply to ``exchange``, and write it.

        Called by :meth:`Exchange.send`; the split exists so that the routing table and the
        send lock stay owned by the reader rather than copied into every exchange.

        Raises:
            StateError: If the session is closed, or the id is already in flight.
            ConnectError: If the connection has already failed, or fails on the write.
            ProtocolError: If the codec has already failed.
        """
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise StateError("the session is closed; no further requests can be sent")

        # Synchronous through to the routing entry. `codec.send` is what reserves the id --
        # an await before this point could let another task allocate the same one.
        wire = self._codec.send(request)
        self._routes[request.request_id] = exchange
        async with self._send_lock:
            await self._transport.send(wire)

    async def round_trip(self, request: Request) -> Completed:
        """Send one request and wait for its reply. The one-shot case, spelled once.

        No timeout of its own: how long a given operation is willing to wait is the
        session's policy, not the router's, and it differs between a one-shot ``STAT`` and a
        transfer that is allowed to take as long as bytes keep arriving.
        """
        with self.exchange() as exchange:
            await exchange.send(request)
            return await exchange.receive()

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
  waiter and once to the task group. See :func:`~gantry_sftp.exceptions._flatten_exception_group`
  for why a group at a public boundary is a bug rather than a detail.
* **A failure reaches every waiter.** Concurrent fan-out means a dead connection can have
  several tasks parked on it, and one that is never woken is a hang. Every exchange is
  registered for the lifetime of its operation, not merely while it has a request in flight.
* **Writes are serialised.** anyio raises ``BusyResourceError`` if two tasks write to one
  stream at once, and an interleaved write would corrupt the frame anyway. Order between
  independent requests is not a protocol requirement -- ids correlate the replies -- so a lock
  around the write costs nothing but the hand-off.
* **The reader outlives the cancellation that stops the operations.** Cleanup after a
  cancelled transfer is shielded, and shielded cleanup that sends a request still needs
  somebody to read the answer. See :meth:`Dispatcher.run`.

What this does *not* do is bound concurrency. How many operations run at once is the caller's
decision, made with an anyio task group; this only makes sure they do not tread on each other.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import override

import anyio

from gantry_sftp._logging import frames_logger
from gantry_sftp.codec import Close, Codec, Completed, Event, Handle, Request, describe
from gantry_sftp.exceptions import ProtocolError, StateError, TransferTimeoutError
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
        "_bytes_received",
        "_bytes_sent",
        "_closed",
        "_codec",
        "_exchanges",
        "_failure",
        "_orphan_arrived",
        "_orphans",
        "_reader_scope",
        "_reading",
        "_reaped",
        "_reaper_scope",
        "_replies_received",
        "_requests_sent",
        "_routes",
        "_send_lock",
        "_send_timeout",
        "_transport",
        "_unclaimed",
    )

    def __init__(
        self, transport: Transport, codec: Codec, *, send_timeout: float | None = None
    ) -> None:
        self._transport = transport
        self._codec = codec
        self._send_timeout = send_timeout
        """Seconds one write may take, including waiting for the send lock. ``None`` for no bound.

        The write is the half of a round trip that had no deadline. Receives were bounded
        everywhere and this was not, on the argument that a full pipe needs a peer that has
        stopped reading -- which is precisely the failure an unattended transfer must survive
        (D-40). Set from ``request_timeout`` by :func:`~gantry_sftp.session.open_session`, so the
        two halves of a round trip are bounded by the same number."""
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
        self._reader_scope: anyio.CancelScope | None = None
        """The reader's own scope, so :meth:`close` can stop a task it did not start."""
        self._reading = False
        self._orphans: deque[bytes] = deque()
        """Handles from an ``OPEN`` nobody was waiting for. Drained by :meth:`reap_orphans`."""
        self._orphan_arrived = anyio.Event()
        self._reaper_scope: anyio.CancelScope | None = None
        self._reaped = 0
        self._requests_sent = 0
        self._replies_received = 0
        self._bytes_sent = 0
        self._bytes_received = 0

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

    @property
    def requests_sent(self) -> int:
        """Requests written to this connection since it opened. Cumulative, never reset.

        Counts what was **committed to the wire**, not what was acknowledged -- incremented
        before the write rather than after it, for the reason :meth:`_close_orphan` states and
        this repository has already paid to learn once (D-74): a request whose reply never
        arrived may well have been performed. A counter that only counted answered requests
        would under-report exactly the connection somebody is trying to diagnose.

        Excludes the handshake, which is sent before this object owns the transport.
        """
        return self._requests_sent

    @property
    def replies_received(self) -> int:
        """Replies decoded and routed since the connection opened, including unclaimed ones.

        The gap between this and :attr:`requests_sent` is what is in flight plus what will
        never come back; :attr:`~gantry_sftp.codec.Codec.outstanding` is the instantaneous
        half of the same picture.
        """
        return self._replies_received

    @property
    def bytes_sent(self) -> int:
        """Bytes handed to the transport, framing included.

        Payload accounting is per operation (``UploadResult.transferred`` and the progress
        callback); this is the connection's own total, which is the one that can be compared
        against what a link was expected to carry.
        """
        return self._bytes_sent

    @property
    def bytes_received(self) -> int:
        """Bytes read from the transport, framing included.

        Counted per read rather than per frame, so a chunk that did not complete a frame is
        still in the total -- a connection receiving bytes that never become packets is a
        distinct failure from one receiving nothing, and only this counter tells them apart.
        """
        return self._bytes_received

    @property
    def reaped(self) -> int:
        """Orphaned handles a ``CLOSE`` has been sent for by :meth:`reap_orphans`.

        A subset of :attr:`unclaimed`: the replies that were a ``HANDLE``, which are the only
        unclaimed ones holding a resource open on the far end. Non-zero means abandoned
        ``OPEN``s are happening -- a timeout, a cancel, a caller that gave up on a slow server
        -- and that they were cleaned up rather than left to accumulate.
        """
        return self._reaped

    @override
    def __repr__(self) -> str:
        """Report the routing state a stalled or leaking session would need.

        ``reader`` is here because it can no longer be inferred from the rest: the reader is
        shielded, so a session whose task group was cancelled still has one, and a reader
        nobody stopped is a task group that will not exit.

        The two totals are what distinguishes a stall from a slow link without a packet
        capture: ``sent`` climbing while ``received`` does not is a server that has stopped
        answering, and both frozen is a transfer that stopped asking.
        """
        state = "closed" if self._closed else "failed" if self._failure is not None else "open"
        reader = (
            "reading" if self._reading else "unstarted" if self._reader_scope is None else "stopped"
        )
        return (
            f"<Dispatcher {state} reader={reader} exchanges={len(self._exchanges)} "
            f"routes={len(self._routes)} unclaimed={self._unclaimed} reaped={self._reaped} "
            f"sent={self._requests_sent}/{self._bytes_sent}B "
            f"received={self._replies_received}/{self._bytes_received}B>"
        )

    # --- the reader ------------------------------------------------------------------------

    async def run(self) -> None:
        """Read the transport until it ends, routing everything it decodes.

        **Never raises**, cancellation excepted. Whatever goes wrong becomes the failure
        every live exchange is handed, so it surfaces at the operation that was waiting for
        it rather than at the session's context manager -- with its own type intact instead
        of wrapped in an ``ExceptionGroup``.

        **Runs until** :meth:`close` **stops it, and ambient cancellation deliberately does
        not.** The loop is shielded, so cancelling the task group the reader lives in leaves
        it reading; only ``close()`` ends it. That inversion is the fix for D-34, and the bug
        it fixes is worth stating because the obvious spelling has it backwards. Cleanup
        after a cancelled transfer is shielded -- a ``CLOSE`` for the handle, a ``REMOVE``
        for the staging file -- and every one of those sends a request and waits for its
        answer. If the same cancellation that triggered the cleanup also stopped the reader,
        the answer has nobody to route it: the shielded wait then costs a full
        ``request_timeout`` (30 s by default) and, with ``request_timeout=None``, never ends
        at all. Measured before the fix, on both backends. A reader that cannot be cancelled
        by accident is what makes the shields upstream mean what they say.

        Raises:
            StateError: If this dispatcher already had a reader. Two of them steal each
                other's frames -- the failure this module exists to prevent -- and with the
                shield, ``close()`` could only stop the second.
        """
        if self._reader_scope is not None:
            raise StateError("this dispatcher already has a reader; run() is called once")
        with anyio.CancelScope(shield=True) as scope:
            # Synchronous from the check above to here, so two tasks cannot both pass it.
            self._reader_scope = scope
            if self._closed:
                # `close()` landed between `start_soon` and this task's first tick, so it
                # cancelled nothing. Without this the reader would start anyway, shielded,
                # with the one thing that can stop it already spent.
                return
            self._reading = True
            try:
                while True:
                    chunk = await self._transport.receive()
                    self._bytes_received += len(chunk)
                    for event in self._codec.receive(chunk):
                        self._route(event)
            except Exception as error:
                # Deliberately as broad as it can be without swallowing cancellation, which
                # is a BaseException and is how this task is meant to end. Anything narrower
                # would let an unforeseen failure kill the reader while every waiter stayed
                # parked -- a hang instead of an error, on the one task nobody is awaiting.
                self._fail(error)
            finally:
                self._reading = False

    def _route(self, event: Event) -> None:
        if not isinstance(event, Completed):  # pragma: no cover -- codec refuses a 2nd VERSION
            raise ProtocolError(f"server sent {type(event).__name__} after the handshake")
        self._replies_received += 1
        if frames_logger.isEnabledFor(logging.DEBUG):
            # Before the routing decision, so a reply nobody claimed is still in the dump --
            # which is the frame you want when a session is behaving as though it is one
            # reply behind.
            frames_logger.debug("<- %s", describe(event.response))
        exchange = self._routes.pop(event.request.request_id, None)
        if exchange is None:
            self._unclaimed += 1
            self._orphan(event)
            return
        exchange.deliver(event)

    def _orphan(self, event: Completed) -> None:
        """Queue a handle from a reply nobody was left to receive.

        A ``HANDLE`` is by definition the answer to an ``OPEN`` or an ``OPENDIR``, so the
        response type is the whole test -- an abandoned request that failed answers with a
        ``STATUS`` and allocated nothing. Asking the event rather than tracking which ids were
        opens keeps this free of bookkeeping that can go stale.
        """
        if not isinstance(event.response, Handle):
            return
        self._orphans.append(event.response.handle)
        self._orphan_arrived.set()

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

    async def reap_orphans(self) -> None:
        """Close handles from an ``OPEN`` nobody was left to receive. Runs beside the reader.

        A request abandoned by a timeout or a cancellation is still outstanding on the server,
        and when it was an ``OPEN`` the server answers it by allocating a handle. That reply
        arrives with no waiter left, and the handle is then open on a session that is otherwise
        perfectly healthy -- invisible from this side until the server starts refusing to open
        anything. **Nothing at the call site can prevent it.** There is no checkpoint between
        the reply and the variable it is assigned to, so what is missing is not a ``try`` in a
        better place but somebody to notice a reply nobody claimed. This is that somebody
        (D-75), and it covers the timeout case as much as the cancelled one -- reproduced with
        no cancellation anywhere, on a default ``request_timeout``.

        **A separate task rather than the reader itself, and that is not a style choice.**
        Sending takes the send lock, and a reader parked on that lock is a reader not draining
        the pipe: with a large ``WRITE`` in flight the peer stops reading, our write blocks
        behind a full channel window, and neither side ever moves again.

        **Never raises**, for the same reason :meth:`run` does not -- it is nobody's awaited
        task, so anything it raised would surface at the session's boundary or nowhere.
        Stopped by :meth:`close`, and shielded like the reader, because this *is* cleanup.
        """
        with anyio.CancelScope(shield=True) as scope:
            self._reaper_scope = scope
            while not self._closed:
                while self._orphans:
                    await self._close_orphan(self._orphans.popleft())
                # Re-armed before the wait and never after, exactly as `Exchange.receive`
                # does: there is no await between finding the queue empty and arming the
                # event, so no arrival can fall between them.
                self._orphan_arrived = anyio.Event()
                await self._orphan_arrived.wait()

    async def _close_orphan(self, handle: bytes) -> None:
        """Send one ``CLOSE`` and wait for it, swallowing whatever the connection says.

        A connection that cannot carry the ``CLOSE`` is one whose handles the server releases
        when the channel closes, so a failure here is not worth reporting and not worth
        retrying.

        The count moves before the wait, not after, because it counts what was *sent*: an
        unanswered request may still have been performed, which this repository has already
        paid to learn once (D-74). Waiting at all is for the reply's sake rather than the
        count's -- routing it to an exchange is what stops every reap inflating
        :attr:`unclaimed`, the counter that says a session is a reply behind.
        """
        self._reaped += 1
        with suppress(Exception):
            _ = await self.round_trip(Close(self._codec.allocate_request_id(), handle))

    def close(self) -> None:
        """Refuse further work, and stop the reader. The only thing that stops the reader.

        The two used to be separate -- this refused work, and the caller cancelled the task
        group to end the reader. Under cancellation that ordering is impossible to get right
        from the outside, because the cancel arrives at the reader and at the operation's
        shielded cleanup simultaneously (see :meth:`run`). So the reader ignores ambient
        cancellation and takes its instruction from here, where the session's ``finally`` can
        give it *after* the cleanup it has to serve.

        Idempotent, and safe before either task starts or after it has stopped.
        """
        self._closed = True
        for scope in (self._reader_scope, self._reaper_scope):
            if scope is not None:
                scope.cancel()

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
            TransferTimeoutError: If the write does not complete within the send timeout. The
                connection is finished at that point -- see :meth:`_write`.
        """
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise StateError("the session is closed; no further requests can be sent")

        # Synchronous through to the routing entry. `codec.send` is what reserves the id --
        # an await before this point could let another task allocate the same one.
        wire = self._codec.send(request)
        self._routes[request.request_id] = exchange
        self._requests_sent += 1
        self._bytes_sent += len(wire)
        if frames_logger.isEnabledFor(logging.DEBUG):
            frames_logger.debug("-> %s", describe(request))
        await self._write(wire, request)

    async def _write(self, wire: bytes, request: Request) -> None:
        """Take the send lock and write one frame, within the send timeout.

        **The deadline covers the lock as well as the write, and that is not tidiness.** A task
        parked on a lock held by a stalled sender is stalled by transitivity, so a deadline that
        started after the acquire would bound the wrong wait -- and with one pipe per session,
        every sender is behind the same lock.

        **A timed-out write ends the connection**, which is the decision this method exists to
        make. ``transport.send`` writes a whole frame and anyio's stream loops internally to do
        it, so cancelling it part-way leaves *part of a frame* in the pipe: the peer's next parse
        reads a length prefix out of the middle of our payload. That is the desynchronised stream
        :class:`~gantry_sftp.exceptions.ProtocolError` exists for, arriving silently. So the
        failure is recorded here and handed to every live exchange, exactly as a dead transport
        is -- one operation reporting a timeout while the others keep writing into a corrupted
        stream would be the worse half of both outcomes.

        The error is a :class:`~gantry_sftp.exceptions.TransferTimeoutError`, which
        :func:`~gantry_sftp.session.is_retryable` already treats as retryable, so
        :func:`~gantry_sftp.session.with_reconnect` answers a wedged peer with a fresh
        connection rather than with a poisoned one.

        Raises:
            TransferTimeoutError: If the whole operation takes longer than the send timeout.
        """
        if self._send_timeout is None:
            async with self._send_lock:
                await self._transport.send(wire)
            return
        try:
            with anyio.fail_after(self._send_timeout):
                async with self._send_lock:
                    await self._transport.send(wire)
        except TimeoutError as exc:
            stalled = TransferTimeoutError(
                f"the connection did not accept {len(wire)} bytes of "
                f"{type(request).__name__} within {self._send_timeout}s; the peer has stopped "
                f"reading and the stream can no longer be trusted"
            )
            self._fail(stalled)
            raise stalled from exc

    async def round_trip(self, request: Request) -> Completed:
        """Send one request and wait for its reply. The one-shot case, spelled once.

        No timeout of its own: how long a given operation is willing to wait is the
        session's policy, not the router's, and it differs between a one-shot ``STAT`` and a
        transfer that is allowed to take as long as bytes keep arriving.
        """
        with self.exchange() as exchange:
            await exchange.send(request)
            return await exchange.receive()

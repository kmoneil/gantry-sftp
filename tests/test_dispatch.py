"""Multiplexing: one reader, many waiters, and the failures that must reach all of them.

The headline tests here are deadlock detectors rather than assertions. A server that answers
nothing until two operations have a request in flight cannot be satisfied by a client that
serialises -- it hangs. So `test_two_downloads_are_in_flight_at_once` passing is not evidence
that concurrency is *allowed*; it is evidence that it happened, because nothing else can make
that server reply.

Every test that could hang carries `anyio.fail_after`. A regression in this area is a hang,
and a hang in a suite with no timeout plugin is a CI job that runs until someone kills it.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    Close,
    Codec,
    Data,
    FrameSplitter,
    Handle,
    Init,
    Open,
    Read,
    RealPath,
    Stat,
    Status,
    StatusCode,
    Version,
    decode,
    encode,
)
from gantry_sftp.exceptions import (
    ConnectError,
    NoSuchFileError,
    ProtocolError,
    StateError,
    TransferTimeoutError,
)
from gantry_sftp.session import Dispatcher, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

DEADLINE = 10.0
"""Long enough that a slow machine is not a failure, short enough that a hang is."""


def ready_codec() -> Codec:
    """A codec past the handshake, without a transport to drive it."""
    codec = Codec()
    _ = codec.initiate()
    _ = codec.receive(encode(Version(3)))
    return codec


class Wire:
    """A transport whose replies the test writes by hand, and can stop writing."""

    def __init__(self) -> None:
        self.sent = bytearray()
        self.waits = 0
        """How many times the reader has run out of input and blocked for more."""
        self._inbox = bytearray()
        self._has_input = anyio.Event()
        self._idle = anyio.Event()
        self._failure: BaseException | None = None

    async def send(self, data: bytes | memoryview) -> None:
        self.sent += bytes(data)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._inbox:
            if self._failure is not None:
                raise self._failure
            self.waits += 1
            self._idle.set()
            self._has_input = anyio.Event()
            await self._has_input.wait()
        chunk = bytes(self._inbox[:max_bytes])
        del self._inbox[:max_bytes]
        return chunk

    async def settle(self) -> None:
        """Return once the reader has consumed everything pushed and gone back to waiting.

        A rendezvous rather than a sleep. Polling until a counter moves would pass on this
        machine and flake on a loaded one, and `anyio.sleep` in a loop is what a test writes
        when it does not know what it is waiting for -- here we know exactly: the reader
        asking for more input is the proof it finished with what it had.
        """
        seen = self.waits
        while self.waits == seen:
            self._idle = anyio.Event()
            await self._idle.wait()

    def push(self, packet: object) -> None:
        self._inbox += encode(packet)  # type: ignore[arg-type]
        self._has_input.set()

    def die(self, error: BaseException) -> None:
        self._failure = error
        self._has_input.set()

    async def aclose(self) -> None:
        return


class Rendezvous:
    """A server that answers nothing until ``release_at`` requests are waiting on it.

    Not a simulation of anything real -- it is a deadlock detector wearing a server's
    clothes. A client that keeps one request in flight at a time can never make it reply, so
    a test built on it either demonstrates that two operations were genuinely in flight
    together or it hangs. Nothing in between, and nothing a scheduling accident can fake.

    It **latches open** the first time the barrier is met. Otherwise every test would have to
    be built from two operations issuing exactly the same number of requests, and the odd one
    out would strand a reply nobody ever asks for again. Once the barrier has been met, it has
    proved what it exists to prove; ``rendezvous`` records which requests were waiting
    together so a test can assert they came from different operations rather than from one
    pipelined one.
    """

    def __init__(self, files: dict[bytes, bytes], *, release_at: int) -> None:
        self.files = files
        self.release_at = release_at
        self.requests: list[object] = []
        self.rendezvous: list[tuple[object, ...]] = []
        self._latched = False
        self._handles: dict[bytes, bytes] = {}
        self._next_handle = 0
        self._held: list[tuple[object, bytes]] = []
        self._outbox = bytearray()
        self._has_output = anyio.Event()
        self._splitter = FrameSplitter()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._dispatch(decode(frame))

    def _hold(self, request: object, reply: object) -> None:
        self._held.append((request, encode(reply)))  # type: ignore[arg-type]
        if not self._latched and len(self._held) < self.release_at:
            return
        if len(self._held) >= self.release_at:
            self.rendezvous.append(tuple(waiting for waiting, _ in self._held))
        self._latched = True
        for _, frame in self._held:
            self._outbox += frame
        self._held.clear()
        self._has_output.set()

    def _dispatch(self, packet: object) -> None:
        if isinstance(packet, Init):
            # The handshake is not part of the barrier: there is only ever one of it, so a
            # barrier of two would deadlock before a test could start.
            self._outbox += encode(Version(3))
            self._has_output.set()
            return

        self.requests.append(packet)
        rid = packet.request_id  # type: ignore[union-attr]
        if isinstance(packet, Stat):
            self._hold(packet, AttrsReply(rid, Attrs(size=len(self.files[packet.path]))))
        elif isinstance(packet, RealPath):
            self._hold(packet, Status(rid, StatusCode.OK, packet.path))
        elif isinstance(packet, Open):
            self._next_handle += 1
            handle = self._next_handle.to_bytes(4, "big")
            self._handles[handle] = packet.filename
            self._hold(packet, Handle(rid, handle))
        elif isinstance(packet, Read):
            content = self.files[self._handles[packet.handle]]
            chunk = content[packet.offset : packet.offset + packet.length]
            self._hold(
                packet, Data(rid, memoryview(chunk)) if chunk else Status(rid, StatusCode.EOF)
            )
        elif isinstance(packet, Close):
            self._hold(packet, Status(rid, StatusCode.OK))
        else:  # pragma: no cover -- an unscripted packet is a broken test, not a scenario
            self._hold(packet, Status(rid, StatusCode.FAILURE, b"unscripted"))

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._outbox:
            self._has_output = anyio.Event()
            await self._has_output.wait()
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        return chunk

    async def aclose(self) -> None:
        return


def paths_waiting_together(server: Rendezvous) -> list[set[bytes]]:
    """The paths of every path-addressed request held by the barrier at the same moment.

    Named rather than inlined because the assertion it feeds is the point of these tests: a
    barrier could in principle be satisfied by one pipelined operation issuing several
    requests, so what is asserted is that two *different* operations were waiting together --
    two distinct paths, since each operation here works on one file.

    **It reads every path-bearing request rather than only the STATs, and that is a
    correction.** It was `Stat`-only while a `get` issued exactly one STAT and issued it first,
    so one STAT stood for one operation. D-110 made `get` issue its STAT and its OPEN together,
    which broke that correspondence in the direction that matters: a barrier of two latched on
    one operation's own pair, the helper saw a single path, and the tests failed. Had they been
    written the other way round -- asserting a count rather than the paths -- they would have
    gone on passing while proving nothing, which is the reason to widen the helper rather than
    lower the barrier.
    """
    return [
        # `Stat.path` and `Open.filename` are the same idea under two names, which is the
        # draft's spelling rather than ours -- so the two branches are the packet layout
        # showing through, not a distinction this helper is drawing.
        {
            request.path if isinstance(request, Stat) else request.filename
            for request in waiting
            if isinstance(request, Stat | Open)
        }
        for waiting in server.rendezvous
    ]


# --- the claim: a session multiplexes -----------------------------------------------------


async def test_two_downloads_are_in_flight_at_once(tmp_path: Path):
    """The card's whole point, proved by a server that will not answer a serialised client.

    Every reply is held until two requests are waiting, so this hangs -- and fails on the
    deadline -- against the version of this library that put a lock around every operation.
    """
    files = {b"/a.bin": bytes(range(256)) * 4, b"/b.bin": bytes(range(128, 256)) * 8}
    # Three, not two: since D-110 a single `get` opens with a STAT and an OPEN together, so a
    # barrier of two is satisfiable by one transfer and would stop being a deadlock detector.
    # Three cannot be reached by one `get`, which holds exactly that pair before it can make
    # any further progress.
    server = Rendezvous(files, release_at=3)

    with anyio.fail_after(DEADLINE):
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            async with anyio.create_task_group() as group:
                group.start_soon(sftp.get, b"/a.bin", tmp_path / "a.bin")
                group.start_soon(sftp.get, b"/b.bin", tmp_path / "b.bin")

    assert (tmp_path / "a.bin").read_bytes() == files[b"/a.bin"]
    assert (tmp_path / "b.bin").read_bytes() == files[b"/b.bin"]
    assert {b"/a.bin", b"/b.bin"} in paths_waiting_together(server), (
        "the two transfers never had a request in flight together"
    )


async def test_two_one_shot_requests_each_get_their_own_reply():
    """The bug the lock was hiding: a round trip that discards everything but its own reply.

    Two concurrent STATs, held until both have arrived, so they must be answered out of the
    order a single-threaded round trip would expect. Each caller has to get the size of the
    file it asked about rather than whichever reply landed first.
    """
    files = {b"/small": bytes(3), b"/large": bytes(9000)}
    server = Rendezvous(files, release_at=2)
    sizes: dict[bytes, int | None] = {}

    async def stat_into(path: bytes) -> None:
        sizes[path] = (await sftp.stat(path)).size

    with anyio.fail_after(DEADLINE):
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            async with anyio.create_task_group() as group:
                group.start_soon(stat_into, b"/small")
                group.start_soon(stat_into, b"/large")

    assert sizes == {b"/small": 3, b"/large": 9000}
    assert {b"/small", b"/large"} in paths_waiting_together(server)


async def test_a_transfer_and_a_one_shot_share_the_connection(tmp_path: Path):
    files = {b"/data.bin": bytes(range(256)) * 2, b"/other": bytes(11)}
    # Three: the transfer's own STAT/OPEN pair is two, and the one-shot STAT is the third. See
    # `test_two_downloads_are_in_flight_at_once` for why two no longer proves anything here.
    server = Rendezvous(files, release_at=3)
    seen: list[int | None] = []

    with anyio.fail_after(DEADLINE):
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            async with anyio.create_task_group() as group:
                group.start_soon(sftp.get, b"/data.bin", tmp_path / "data.bin")

                async def stat_other() -> None:
                    seen.append((await sftp.stat(b"/other")).size)

                group.start_soon(stat_other)

    assert seen == [11]
    assert (tmp_path / "data.bin").read_bytes() == files[b"/data.bin"]
    assert {b"/data.bin", b"/other"} in paths_waiting_together(server)


# --- routing ------------------------------------------------------------------------------


async def test_replies_reach_the_exchange_that_asked_even_out_of_order():
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with dispatcher.exchange() as first, dispatcher.exchange() as second:
        await first.send(Stat(codec.allocate_request_id(), b"/first"))
        await second.send(Stat(codec.allocate_request_id(), b"/second"))
        assert first.outstanding == 1
        assert second.outstanding == 1

        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            # Answered in reverse, because arrival order is not correlation order.
            wire.push(AttrsReply(2, Attrs(size=222)))
            wire.push(AttrsReply(1, Attrs(size=111)))

            with anyio.fail_after(DEADLINE):
                second_reply = await second.receive()
                first_reply = await first.receive()
            dispatcher.close()

    assert isinstance(first_reply.request, Stat)
    assert first_reply.request.path == b"/first"
    assert isinstance(first_reply.response, AttrsReply)
    assert first_reply.response.attrs.size == 111
    assert isinstance(second_reply.response, AttrsReply)
    assert second_reply.response.attrs.size == 222


async def test_a_reply_with_no_waiter_left_is_counted_not_raised():
    """A timed-out request stays outstanding on the server, so its reply still arrives.

    Dropping it is right -- there is nobody to give it to -- but dropping it silently is how
    a session that is one reply behind stays undiagnosable. The count is the visible trace.
    """
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with dispatcher.exchange() as exchange:
        await exchange.send(Stat(codec.allocate_request_id(), b"/abandoned"))
    # The exchange is retired here, exactly as it would be by a timeout unwinding the block.

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            wire.push(AttrsReply(1, Attrs(size=1)))
            await wire.settle()
            dispatcher.close()

    assert dispatcher.unclaimed == 1
    assert dispatcher.failure is None, "an unclaimed reply is not a connection failure"


async def test_retiring_an_exchange_leaves_no_route_behind():
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with dispatcher.exchange() as exchange:
        await exchange.send(Stat(codec.allocate_request_id(), b"/one"))
        assert "routes=1" in repr(dispatcher)

    assert "routes=0" in repr(dispatcher)
    assert "exchanges=0" in repr(dispatcher)


# --- what the counters count ----------------------------------------------------------------


async def yielded_during(work: Callable[[], Awaitable[None]]) -> bool:
    """Whether ``work`` handed the event loop to another task even once.

    A task started with ``start_soon`` cannot run until the task that started it reaches a
    checkpoint, so "did it run" is an exact reading of "was there a checkpoint". Counting
    scheduler turns instead reads differently on the two backends -- trio does not hand two
    ready tasks the loop in the order asyncio does -- and the count is not the claim anyway.
    """
    ran = False

    async def competitor() -> None:
        nonlocal ran
        ran = True

    async with anyio.create_task_group() as group:
        group.start_soon(competitor)
        await work()
        observed = ran
        group.cancel_scope.cancel()
    return observed


async def send_several(dispatcher: Dispatcher, codec: Codec, count: int) -> None:
    with dispatcher.exchange() as exchange:
        for _ in range(count):
            await exchange.send(Stat(codec.allocate_request_id(), b"/p"))


async def test_the_send_lock_does_not_yield_the_loop_to_take_an_uncontended_permit():
    # `Wire.send` contains no await of its own, so the lock's acquire is the only checkpoint on
    # this path -- which turns "did another task get to run" into an exact reading of it. The
    # docstring on `_send_lock` claims the plain spelling costs an event-loop round trip per
    # request, on a path that issues one per 255 KiB of a transfer, and nothing measured it.
    codec = ready_codec()
    dispatcher = Dispatcher(Wire(), codec)  # type: ignore[arg-type]

    assert await yielded_during(lambda: send_several(dispatcher, codec, 16)) is False

    # The control, and it is load-bearing rather than decoration: the assertion above is only
    # about *our* spelling while anyio's default still checkpoints. If that ever changed, this
    # line fails and says so, instead of the one above passing for a dispatcher that had lost
    # `fast_acquire` altogether.
    plain_codec = ready_codec()
    plain = Dispatcher(Wire(), plain_codec)  # type: ignore[arg-type]
    plain._send_lock = anyio.Lock()  # noqa: SLF001
    assert await yielded_during(lambda: send_several(plain, plain_codec, 16)) is True


async def test_the_byte_counter_totals_what_the_transport_was_actually_handed():
    # The oracle is the transport's own tally rather than a size this test computes: `bytes_sent`
    # is meant to be what went out, so what went out is the thing to compare it against.
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    assert dispatcher.bytes_sent == 0
    assert "sent=0/0B" in repr(dispatcher)

    with dispatcher.exchange() as exchange:
        await exchange.send(Stat(codec.allocate_request_id(), b"/one"))
        after_one = dispatcher.bytes_sent
        assert after_one == len(wire.sent)

        # A second request, of a deliberately different length. A counter that *assigns* agrees
        # with one that accumulates for exactly as long as only one request is ever sent -- and
        # one request is what every other test in this file sends.
        await exchange.send(Stat(codec.allocate_request_id(), b"/a-considerably-longer-name"))

    assert dispatcher.bytes_sent == len(wire.sent)
    assert dispatcher.bytes_sent > after_one
    assert dispatcher.requests_sent == 2
    assert f"sent=2/{len(wire.sent)}B" in repr(dispatcher)


# --- the reader's lifetime ----------------------------------------------------------------


def test_a_fresh_dispatcher_reports_that_nothing_is_reading():
    assert "reader=unstarted" in repr(Dispatcher(Wire(), ready_codec()))  # type: ignore[arg-type]


async def test_the_reader_ignores_cancellation_of_the_task_group_it_lives_in():
    """The mechanism behind `tests/test_cancellation.py`, asserted where it lives.

    A cancelled transfer cleans up under a shield: it sends a CLOSE and waits for the STATUS.
    If the cancellation that triggered the cleanup also stopped the reader, that wait has
    nobody left to satisfy it -- a full `request_timeout`, or forever when there is none
    (D-34). So the reader is shielded and only `close()` ends it.

    The nesting is `open_session`'s, and it is the whole of the bug: the caller's scope is
    *outside* the task group the reader lives in, so one cancel reaches both the operation
    and its router. A test that cancelled a scope beside the reader instead of around it
    would pass against the broken code.

    The `fail_after` is *inside* the shield deliberately. Outside it would be ignored, which
    is what a shield is for, and this test would hang exactly the way the bug did.
    """
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]
    observed: list[object] = []

    with dispatcher.exchange() as exchange:
        caller = anyio.CancelScope()  # a `move_on_after` around the whole session
        with caller:
            async with anyio.create_task_group() as group:  # what `open_session` owns
                group.start_soon(dispatcher.run)
                try:
                    await wire.settle()
                    caller.cancel()
                    await anyio.sleep_forever()
                finally:
                    # What `_close_quietly` does, in the same order and under the same
                    # shield, followed by the `close()` that `open_session` does after it.
                    with anyio.CancelScope(shield=True):
                        try:
                            request_id = codec.allocate_request_id()
                            await exchange.send(Stat(request_id, b"/late"))
                            wire.push(AttrsReply(request_id, Attrs(size=9)))
                            with anyio.fail_after(DEADLINE):
                                observed.append(await exchange.receive())
                            observed.append(repr(dispatcher))
                        finally:
                            # In its own `finally` so that a regression fails this test
                            # rather than leaving a shielded reader nothing can stop.
                            dispatcher.close()

    reply, snapshot = observed
    assert isinstance(reply.response, AttrsReply)  # type: ignore[union-attr]
    assert reply.response.attrs.size == 9, "no reply was routed after the cancellation"
    assert "reader=reading" in snapshot  # type: ignore[operator]
    assert "reader=stopped" in repr(dispatcher)


async def test_closing_before_the_reader_starts_stops_it_anyway():
    """`close()` can land between `start_soon` and the reader's first tick.

    It cancels a scope the reader has not created yet, so without the check in `run` the
    reader would start with its only stop signal already spent -- and being shielded, would
    then be a task group that never exits.

    The wire is armed to fail rather than to block, so a regression here fails the test
    instead of hanging the suite: a reader that read anything at all leaves a `failure`
    behind to prove it.
    """
    codec = ready_codec()
    wire = Wire()
    wire.die(ConnectError("the reader read the transport after close() said not to"))
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            dispatcher.close()

    assert dispatcher.failure is None, "the reader read the transport after close()"
    assert wire.waits == 0
    assert "reader=stopped" in repr(dispatcher)


async def test_a_dispatcher_refuses_a_second_reader():
    """Two readers on one transport steal each other's frames, which is what this module
    exists to prevent -- and now `close()` could only stop whichever of them registered last.
    """
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            await wire.settle()
            with pytest.raises(StateError) as exc:
                await dispatcher.run()
            dispatcher.close()

    assert exc.value.args[0] == "this dispatcher already has a reader; run() is called once"


# --- failure reaches everyone -------------------------------------------------------------


async def test_a_dead_connection_wakes_every_waiter():
    """Concurrent fan-out means a dead connection can have several tasks parked on it.

    One that is never woken is a hang, and a hang is the failure mode this library exists to
    stop shipping. Both exchanges must get the error, and it must be ssh's, not a substitute.
    """
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]
    raised: list[BaseException] = []

    async def wait_on(exchange) -> None:
        try:
            _ = await exchange.receive()
        except ConnectError as error:
            raised.append(error)

    with dispatcher.exchange() as first, dispatcher.exchange() as second:
        await first.send(Stat(codec.allocate_request_id(), b"/one"))
        await second.send(Stat(codec.allocate_request_id(), b"/two"))

        with anyio.fail_after(DEADLINE):
            async with anyio.create_task_group() as group:
                group.start_soon(dispatcher.run)
                group.start_soon(wait_on, first)
                group.start_soon(wait_on, second)
                await anyio.sleep(0.05)
                wire.die(ConnectError("connection closed by the remote end", stderr="banner\n"))

    assert len(raised) == 2
    assert {error.args[0] for error in raised} == {"connection closed by the remote end"}
    assert all(error.stderr == "banner\n" for error in raised)  # type: ignore[attr-defined]
    assert isinstance(dispatcher.failure, ConnectError)


async def test_the_reader_survives_a_protocol_violation_and_reports_it():
    """A frame the codec refuses must reach the waiter as a ProtocolError, not kill the task.

    If the reader raised instead, the error would surface from the session's context manager
    wrapped in an ExceptionGroup, at a line that did nothing wrong.
    """
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with dispatcher.exchange() as exchange:
        await exchange.send(Stat(codec.allocate_request_id(), b"/one"))

        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            # A reply to a request id nobody sent. The codec treats that as terminal, and it
            # is right to: the stream is no longer trustworthy.
            wire.push(AttrsReply(4242, Attrs(size=0)))

            with anyio.fail_after(DEADLINE), pytest.raises(ProtocolError) as exc:
                _ = await exchange.receive()
            dispatcher.close()

    assert exc.value.request_id == 4242
    assert isinstance(dispatcher.failure, ProtocolError)


async def test_sending_after_a_failure_raises_it_rather_than_hanging():
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with anyio.fail_after(DEADLINE):
        # No cancel: the reader returns of its own accord once it has recorded the failure,
        # which is the property under test as much as the exception is.
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            wire.die(ConnectError("ssh exited while we were writing to it"))

    assert dispatcher.failure is not None
    with dispatcher.exchange() as exchange, pytest.raises(ConnectError) as exc:
        await exchange.send(Stat(codec.allocate_request_id(), b"/late"))
    assert exc.value.args[0] == "ssh exited while we were writing to it"


async def test_sending_after_close_names_the_reason():
    codec = ready_codec()
    dispatcher = Dispatcher(Wire(), codec)  # type: ignore[arg-type]
    dispatcher.close()

    with dispatcher.exchange() as exchange, pytest.raises(StateError) as exc:
        await exchange.send(Stat(codec.allocate_request_id(), b"/late"))
    assert exc.value.args[0] == "the session is closed; no further requests can be sent"
    assert "closed" in repr(dispatcher)


async def test_replies_already_queued_survive_a_later_failure():
    """Data that arrived was paid for. A failure afterwards must not discard it."""
    codec = ready_codec()
    wire = Wire()
    dispatcher = Dispatcher(wire, codec)  # type: ignore[arg-type]

    with dispatcher.exchange() as exchange:
        await exchange.send(Stat(codec.allocate_request_id(), b"/one"))

        with anyio.fail_after(DEADLINE):
            async with anyio.create_task_group() as group:
                group.start_soon(dispatcher.run)
                wire.push(AttrsReply(1, Attrs(size=77)))
                await wire.settle()
                assert exchange.outstanding == 0, "the reply had not been delivered yet"
                wire.die(ConnectError("connection closed by the remote end"))

        assert dispatcher.failure is not None
        delivered = await exchange.receive()
        assert isinstance(delivered.response, AttrsReply)
        assert delivered.response.attrs.size == 77

        with pytest.raises(ConnectError):
            _ = await exchange.receive()


# --- the session boundary -----------------------------------------------------------------


async def test_an_error_from_the_body_stays_flat():
    """`open_session` runs a task group, and a task group wraps even one exception.

    A caller who writes `except NoSuchFileError` around the `async with` has to keep matching.
    """
    server = Rendezvous({}, release_at=1)

    with anyio.fail_after(DEADLINE), pytest.raises(NoSuchFileError) as exc:
        async with open_session(server):  # type: ignore[arg-type]
            raise NoSuchFileError("nothing here", code=2, message=b"No such file")

    assert exc.value.args[0] == "nothing here"
    assert not isinstance(exc.value, BaseExceptionGroup)


async def test_the_reader_stops_when_the_session_does():
    server = Rendezvous({b"/x": b"x"}, release_at=1)
    with anyio.fail_after(DEADLINE):
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            assert (await sftp.stat(b"/x")).size == 1
        # Leaving the block cancelled the reader; nothing is left running to hang the test.


async def test_a_silent_server_times_out_one_operation_without_killing_the_session():
    """A per-operation deadline is not a connection-level one, and the difference now matters.

    One request going unanswered must fail that request. The session has to stay usable,
    because a neighbouring transfer on the same connection did nothing wrong.
    """

    class SilentOnce(Rendezvous):
        def _dispatch(self, packet: object) -> None:
            if isinstance(packet, RealPath):
                self.requests.append(packet)
                return
            super()._dispatch(packet)

    server = SilentOnce({b"/x": b"hello"}, release_at=1)

    with anyio.fail_after(DEADLINE):
        async with open_session(server, request_timeout=0.2) as sftp:  # type: ignore[arg-type]
            with pytest.raises(TransferTimeoutError) as exc:
                _ = await sftp.realpath(b"/ignored")
            assert exc.value.args[0] == "RealPath was not answered within 0.2s"
            # Still usable: the connection was never the problem.
            assert (await sftp.stat(b"/x")).size == 5


# --- against a real server ------------------------------------------------------------------


async def test_concurrent_downloads_from_a_real_sftp_server(tmp_path: Path):
    """A fake can only confirm what its author believed. This is the boundary crossing.

    Four files at once over one `sftp-server`, checked byte for byte -- so the proof covers
    real framing, real batching of replies into whatever chunks the pipe hands back, and real
    out-of-order completion rather than the shapes a scripted fake was told to produce.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    sources = {}
    for index in range(4):
        source = tmp_path / f"source-{index}.bin"
        source.write_bytes(os.urandom(200_000 + index))
        sources[index] = source

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with anyio.fail_after(120.0):
            async with anyio.create_task_group() as group:
                for index, source in sources.items():
                    group.start_soon(sftp.get, str(source), tmp_path / f"out-{index}.bin")

    for index, source in sources.items():
        assert (tmp_path / f"out-{index}.bin").read_bytes() == source.read_bytes()


async def test_concurrent_uploads_to_a_real_sftp_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    sources = {}
    for index in range(4):
        source = tmp_path / f"upload-{index}.bin"
        source.write_bytes(os.urandom(150_000 + index))
        sources[index] = source

    destination = tmp_path / "landed"
    destination.mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with anyio.fail_after(120.0):
            async with anyio.create_task_group() as group:
                for index, source in sources.items():
                    group.start_soon(sftp.put, source, str(destination / f"landed-{index}.bin"))

    for index, source in sources.items():
        assert (destination / f"landed-{index}.bin").read_bytes() == source.read_bytes()

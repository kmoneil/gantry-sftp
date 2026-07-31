"""An `OPEN` nobody was left to receive still opened a file on the server.

The window is not at the call site. `Session.open` is `reply = await self.request(...)`,
an `isinstance`, and a `return`, with no checkpoint between the reply and the variable — so a
`try` in a better place cannot catch anything. What is missing is somebody to notice a reply
that arrives with no waiter: the server allocated the handle, the client walked away, and the
handle stays open on a session that is otherwise perfectly healthy (D-75).

**Two shapes, and only one of them is a cancellation.** A `request_timeout` that fires while an
`OPEN` is in flight leaks a handle with nothing cancelled anywhere — the same lesson D-74 wrote
down about `REMOVE`, that an unanswered request may still have been performed. Both are tested,
because a fix aimed only at cancellation would leave the commoner case open.

The server fakes withhold the *reply* and allocate the handle when the request arrives, which is
the race exactly. A fake that also withheld the allocation would agree with a client that never
looked.
"""

from __future__ import annotations

import anyio
import pytest

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    Attrs,
    AttrsReply,
    Close,
    FrameSplitter,
    Handle,
    Open,
    OpenDir,
    OpenFlag,
    Stat,
    Status,
    StatusCode,
    decode,
)
from gantry_sftp.exceptions import TransferTimeoutError
from gantry_sftp.session import Dispatcher, open_session
from test_dispatch import DEADLINE, Wire, ready_codec
from test_recursive import TreeServer

pytestmark = pytest.mark.anyio

IMPATIENT = 0.2
"""`request_timeout` for the abandoned-request cases. Nothing here waits it out on purpose."""


class HoldsTheHandle(TreeServer):
    """Allocates the handle when the request arrives and withholds only the reply.

    `arrived` fires when the request lands, so a test cancels at a rendezvous rather than after
    a sleep; `release()` then answers as a real server would a moment later.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.arrived = anyio.Event()
        self.closed = anyio.Event()
        self._held: Handle | None = None

    def _hold(self, packet, path: bytes) -> None:
        self._held = Handle(packet.request_id, self._handle_for(path))
        self.arrived.set()

    def _on_open(self, packet: Open) -> None:
        if packet.filename not in self.files:
            super()._on_open(packet)
            return
        self._hold(packet, packet.filename)

    def _on_opendir(self, packet: OpenDir) -> None:
        if packet.path not in self.tree:
            super()._on_opendir(packet)
            return
        self._hold(packet, packet.path)

    def release(self) -> None:
        assert self._held is not None, "nothing was being held"
        self._reply(self._held)
        self._held = None

    def _on_close(self, packet) -> None:
        super()._on_close(packet)
        self.closed.set()


async def until_closed(server: HoldsTheHandle) -> None:
    """Wait for the server's handle table to empty, or fail rather than hang.

    The reap is asynchronous by construction -- it happens when the abandoned reply turns up,
    which is after the operation that asked for it has gone -- so the assertion is "eventually",
    bounded, and made on the server rather than on the client's intention to send.
    """
    with anyio.fail_after(DEADLINE):
        await server.closed.wait()
    assert server.open_handles == set(), f"still open: {sorted(server.open_handles)}"


# --- the session, both shapes -----------------------------------------------------------------


async def test_a_cancelled_open_does_not_leak_the_handle_the_server_allocated(tmp_path):
    """Cancel while the OPEN is in flight, with the session surviving.

    The session has to survive for this to be a leak worth naming: one that ends takes the
    handle with it, because the server releases everything when the channel closes.
    """
    server = HoldsTheHandle(tree={b"/": ()}, files={b"/big.bin": b"x" * 4096})

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        async with anyio.create_task_group() as group:

            async def cancel_when_in_flight(scope: anyio.CancelScope) -> None:
                await server.arrived.wait()
                scope.cancel()

            caller = anyio.CancelScope()
            group.start_soon(cancel_when_in_flight, caller)
            with caller:
                _ = await sftp.get("/big.bin", tmp_path / "out.bin")

        assert caller.cancel_called, "the get finished on its own; nothing was abandoned"
        assert server.open_handles, "the fake did not hold a handle open to leak"
        server.release()  # the server answers the abandoned OPEN, as a real one does

        await until_closed(server)
        # And the session is still healthy, which is what makes the leak a leak.
        assert (await sftp.stat("/big.bin")).size == 4096


async def test_a_timed_out_open_does_not_leak_either_and_nothing_was_cancelled(tmp_path):
    """The commoner shape, and the one a cancellation-shaped fix would miss.

    `request_timeout` fires, the caller gets its error, and the server answers afterwards. No
    cancel scope anywhere -- on the shipped 30 s default this is a slow server, not a bug.
    """
    server = HoldsTheHandle(tree={b"/": ()}, files={b"/big.bin": b"x" * 4096})

    async with open_session(server, request_timeout=IMPATIENT) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferTimeoutError) as exc:
            _ = await sftp.get("/big.bin", tmp_path / "out.bin")
        assert exc.value.args[0] == f"Open was not answered within {IMPATIENT}s"

        assert server.open_handles, "the fake did not hold a handle open to leak"
        server.release()

        await until_closed(server)
        assert (await sftp.stat("/big.bin")).size == 4096


async def test_an_abandoned_opendir_is_reaped_too():
    """The sweep: `OPENDIR` allocates a handle by the same rule, and `scandir` abandons one."""
    server = HoldsTheHandle(tree={b"/root": ()}, files={})

    async with open_session(server, request_timeout=IMPATIENT) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferTimeoutError):
            _ = await sftp.opendir(b"/root")

        assert server.open_handles
        server.release()
        await until_closed(server)


# --- the dispatcher, where the decision is made -----------------------------------------------


class ClosingWire(Wire):
    """A wire that watches for the reaper's CLOSE, and optionally answers it.

    Two rendezvous rather than a poll: `saw_close` fires when the frame reaches the transport
    and `answered` when the reply goes back. Answering is optional because a server that never
    answers a CLOSE is the case the reaper must not be stuck in.
    """

    def __init__(self, *, answer: bool = True) -> None:
        super().__init__()
        self.answer = answer
        self.saw_close = anyio.Event()
        self.answered = anyio.Event()
        self._splitter = FrameSplitter()

    async def send(self, data: bytes | memoryview) -> None:
        await super().send(data)
        for frame in self._splitter.feed(bytes(data)):
            packet = decode(frame)
            if not isinstance(packet, Close):
                continue
            self.saw_close.set()
            if self.answer:
                self.push(Status(packet.request_id, StatusCode.OK))
                self.answered.set()


def orphan_dispatcher(wire: Wire):
    codec = ready_codec()
    return Dispatcher(wire, codec), codec  # type: ignore[arg-type]


def closes_in(wire: Wire) -> list[bytes]:
    """The handles a CLOSE was actually written to the wire for."""
    return [
        packet.handle
        for packet in (decode(frame) for frame in FrameSplitter().feed(bytes(wire.sent)))
        if isinstance(packet, Close)
    ]


async def test_an_unclaimed_handle_is_closed_and_counted():
    wire = ClosingWire()
    dispatcher, codec = orphan_dispatcher(wire)

    with dispatcher.exchange() as exchange:
        await exchange.send(Open(codec.allocate_request_id(), b"/one", OpenFlag.READ, EMPTY_ATTRS))
    # Retired here, exactly as a timeout unwinding the block would leave it.

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            group.start_soon(dispatcher.reap_orphans)
            wire.push(Handle(1, b"\x07\x07\x07\x07"))
            await wire.answered.wait()
            dispatcher.close()

    assert closes_in(wire) == [b"\x07\x07\x07\x07"]
    assert dispatcher.reaped == 1
    assert dispatcher.unclaimed == 1, "it is still an unclaimed reply as well"
    assert "reaped=1" in repr(dispatcher)


async def test_an_unclaimed_status_is_counted_and_nothing_is_sent():
    """The negative half: a reply that allocated nothing must not produce a CLOSE.

    An abandoned request that *failed* answers with a STATUS, and closing something on the
    strength of one would be inventing a handle out of a refusal.
    """
    wire = ClosingWire()
    dispatcher, codec = orphan_dispatcher(wire)

    with dispatcher.exchange() as exchange:
        await exchange.send(Open(codec.allocate_request_id(), b"/one", OpenFlag.READ, EMPTY_ATTRS))

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            group.start_soon(dispatcher.reap_orphans)
            wire.push(Status(1, StatusCode.NO_SUCH_FILE, b"No such file"))
            await wire.settle()  # the reader has consumed it and gone back to waiting
            dispatcher.close()

    assert dispatcher.unclaimed == 1
    assert dispatcher.reaped == 0
    assert closes_in(wire) == []
    assert not wire.saw_close.is_set()


class GatedWire(ClosingWire):
    """A `ClosingWire` whose sends can be parked, so a test can hold the send lock open."""

    def __init__(self) -> None:
        super().__init__()
        self.hold = False
        self.parked = anyio.Event()
        self.released = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        if self.hold:
            self.parked.set()
            await self.released.wait()
        await super().send(data)


async def test_the_reaper_sending_does_not_stop_the_reader_routing():
    """The structural claim, asserted rather than commented.

    The reaper closes orphans from its own task because sending takes the send lock, and a
    reader waiting on that lock is a reader not draining the pipe -- with a large WRITE in
    flight that is a deadlock, not a slow moment. So: park the reaper's CLOSE inside the
    transport and the reader must still deliver a reply to a waiting exchange.

    Written the wrong way -- closing orphans inside the reader loop -- this hangs, which the
    `fail_after` turns into a failure.
    """
    wire = GatedWire()
    dispatcher, codec = orphan_dispatcher(wire)

    with dispatcher.exchange() as abandoned:
        await abandoned.send(
            Open(codec.allocate_request_id(), b"/abandoned", OpenFlag.READ, EMPTY_ATTRS)
        )

    with dispatcher.exchange() as live, anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            group.start_soon(dispatcher.reap_orphans)
            await live.send(Stat(codec.allocate_request_id(), b"/live"))

            wire.hold = True  # everything sent from here on parks inside the transport
            wire.push(Handle(1, b"\x01\x01\x01\x01"))
            await wire.parked.wait()  # the reaper is inside `send`, holding the lock

            wire.push(AttrsReply(2, Attrs(size=42)))
            delivered = await live.receive()  # the reader is still routing, or this hangs

            wire.released.set()
            await wire.answered.wait()
            dispatcher.close()

    assert isinstance(delivered.response, AttrsReply)
    assert delivered.response.attrs.size == 42
    assert closes_in(wire) == [b"\x01\x01\x01\x01"]


async def test_closing_stops_a_reaper_waiting_on_a_close_nobody_will_answer():
    """A session that is ending releases its handles anyway, so teardown does not wait.

    The reaper is shielded like the reader, so `close()` is the only thing that ends it -- and
    it must end it from inside the round trip, not merely between two of them.
    """
    wire = ClosingWire(answer=False)
    dispatcher, codec = orphan_dispatcher(wire)

    with dispatcher.exchange() as exchange:
        await exchange.send(Open(codec.allocate_request_id(), b"/one", OpenFlag.READ, EMPTY_ATTRS))

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            group.start_soon(dispatcher.run)
            group.start_soon(dispatcher.reap_orphans)
            wire.push(Handle(1, b"\x02\x02\x02\x02"))
            await wire.saw_close.wait()  # sent, and now waiting for a reply that never comes
            dispatcher.close()

    assert dispatcher.reaped == 1, "the CLOSE went out even though it was never answered"
    assert closes_in(wire) == [b"\x02\x02\x02\x02"]


# --- what the mutation lane found nothing was defending (D-105) --------------------------------
#
# The first `session/` mutmut run put three survivors in this module, and each is a claim some
# docstring here already makes and no test was checking. The shield is the one that matters:
# `reap_orphans` is wrapped in `anyio.CancelScope(shield=True)` and both that method and
# `test_closing_stops_a_reaper_waiting_on_a_close_nobody_will_answer` say so in prose --
# "shielded like the reader, because this *is* cleanup" -- but flipping it to `False` broke
# nothing. The other two are counters that only ever saw one of the thing they count, so a
# `+= 1` mutated to `= 1` is invisible.


class CountsCloses(ClosingWire):
    """A `ClosingWire` that can be waited on for the *n*th CLOSE rather than only the first.

    `ClosingWire.saw_close` is a single `Event`, so it stays set after the first one and cannot
    say "both have gone". A counter is what separates a reaper that closes every orphan from one
    that closes the first and stops -- which is the failure `reaped = 1` would be.
    """

    def __init__(self, expected: int) -> None:
        super().__init__()
        self._expected = expected
        self.enough = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        await super().send(data)
        if len(closes_in(self)) >= self._expected:
            self.enough.set()


async def test_an_ambient_cancel_does_not_stop_the_reaper_mid_close():
    """The shield, asserted rather than described. `close()` ends the reaper; a cancel does not.

    This is the other half of `test_closing_stops_a_reaper_waiting_on_a_close_nobody_will_answer`
    and the half that was missing: that test proves `close()` *can* stop the reaper, and nothing
    proved that anything else *cannot*. Without the shield the two are the same event, and the
    reaper dies to whatever cancel is already unwinding the session -- which is exactly when its
    handles need closing, because a cancelled transfer is how they were orphaned in the first
    place (D-75).

    The cancel has to land while the reaper is *inside* the round trip rather than between two
    of them, so the CLOSE is parked in the transport at the moment the scope is cancelled. A
    cancel delivered between orphans would unwind cleanly either way and prove nothing.
    """
    wire = GatedWire()
    dispatcher, codec = orphan_dispatcher(wire)
    ambient: list[anyio.CancelScope] = []

    async def reaper() -> None:
        # An ordinary, unshielded scope *around* `reap_orphans`, which is what a task group
        # unwinding the session looks like from the reaper's side.
        with anyio.CancelScope() as scope:
            ambient.append(scope)
            await dispatcher.reap_orphans()

    with dispatcher.exchange() as exchange:
        await exchange.send(Open(codec.allocate_request_id(), b"/one", OpenFlag.READ, EMPTY_ATTRS))

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            # `close()` in a `finally`, which the other tests here do not need and this one
            # cannot do without. They only ever reach it on the happy path; this one asserts
            # about a *cancel*, so on failure the body is cancelled before its last line --
            # and `run` is shielded too, so a reader that never gets `close()` keeps the task
            # group open and the `fail_after` above cannot end it either. Without this the
            # test hangs instead of failing, which is the one outcome worse than not having it.
            try:
                group.start_soon(dispatcher.run)
                group.start_soon(reaper)

                wire.hold = True  # the reaper's CLOSE will park inside the transport
                wire.push(Handle(1, b"\x0b\x0b\x0b\x0b"))
                await wire.parked.wait()  # it is mid-send, holding the lock

                ambient[0].cancel()  # the shield must ignore this
                wire.released.set()
                await wire.answered.wait()  # so the CLOSE completes anyway
            finally:
                dispatcher.close()

    assert closes_in(wire) == [b"\x0b\x0b\x0b\x0b"], "the reaper died to an ambient cancel"
    assert dispatcher.reaped == 1


async def test_every_orphan_is_counted_rather_than_the_count_being_a_flag():
    """Two orphans, because one cannot tell `+= 1` from `= 1`.

    `reaped` is on `repr(dispatcher)` and is what an operator reads to decide whether a session
    is leaking handles. A count stuck at 1 says "this has happened" where the number is the
    whole point -- and every existing test here orphans exactly one handle.
    """
    wire = CountsCloses(expected=2)
    dispatcher, codec = orphan_dispatcher(wire)

    for path in (b"/one", b"/two"):
        with dispatcher.exchange() as exchange:
            await exchange.send(Open(codec.allocate_request_id(), path, OpenFlag.READ, EMPTY_ATTRS))

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            try:
                group.start_soon(dispatcher.run)
                group.start_soon(dispatcher.reap_orphans)
                wire.push(Handle(1, b"\x0c\x0c\x0c\x0c"))
                wire.push(Handle(2, b"\x0d\x0d\x0d\x0d"))
                await wire.enough.wait()
            finally:
                dispatcher.close()

    assert closes_in(wire) == [b"\x0c\x0c\x0c\x0c", b"\x0d\x0d\x0d\x0d"]
    assert dispatcher.reaped == 2
    assert dispatcher.unclaimed == 2
    assert "reaped=2" in repr(dispatcher)


async def test_every_unclaimed_reply_is_counted_even_when_none_allocates_anything():
    """The same arithmetic on the other counter, on the path that sends no CLOSE.

    `unclaimed` counts replies nobody was waiting for; `reaped` counts the handles among them.
    Two failed abandoned requests move one counter twice and the other not at all, which is the
    shape that separates them -- and the shape a single-orphan test cannot see.
    """
    wire = ClosingWire()
    dispatcher, codec = orphan_dispatcher(wire)

    for path in (b"/one", b"/two"):
        with dispatcher.exchange() as exchange:
            await exchange.send(Open(codec.allocate_request_id(), path, OpenFlag.READ, EMPTY_ATTRS))

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as group:
            try:
                group.start_soon(dispatcher.run)
                group.start_soon(dispatcher.reap_orphans)
                wire.push(Status(1, StatusCode.NO_SUCH_FILE, b"No such file"))
                wire.push(Status(2, StatusCode.PERMISSION_DENIED, b"Permission denied"))
                await wire.settle()
            finally:
                dispatcher.close()

    assert dispatcher.unclaimed == 2
    assert dispatcher.reaped == 0
    assert closes_in(wire) == []

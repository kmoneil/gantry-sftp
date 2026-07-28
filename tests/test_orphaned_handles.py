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

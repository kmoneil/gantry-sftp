"""The write half of a round trip, and what happens when the peer stops reading.

Receives were bounded everywhere in this library and writes were not (D-40). The gap was
reasoned about rather than measured, and the reasoning was about *reachability*: a request is
around thirty bytes, a pipe holds 64 KiB, so a sender cannot fill it. That was true when a
session ran one transfer at a time. Since the session multiplexes, one upload's 255 KiB ``WRITE``
fills the pipe and every other task's write queues behind it — so a plain concurrent ``get``
against a peer that has stopped draining hung forever, with nothing anywhere to stop it.

Every test here uses a server that answers normally and then stops draining, which is what an
appliance that stops reading its socket looks like from this side. Blocking inside ``send`` is
the honest model: a full pipe does not fail a write, it simply never completes it, and everything
the writer holds — the send lock included — stays held.

The deadline is deliberately fatal to the connection rather than to the operation, and
:meth:`Dispatcher._write` gives the argument: a cancelled write leaves part of a frame in the
pipe, and the peer's next parse reads a length prefix out of the middle of our payload.
"""

from __future__ import annotations

import ast
import os
import signal
import sys
from pathlib import Path

import anyio
import pytest

from conftest import negotiate, running_dispatcher
from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    Close,
    Codec,
    Data,
    Extended,
    ExtendedReply,
    FrameSplitter,
    FSetStat,
    FStat,
    Handle,
    Init,
    LStat,
    Open,
    OpenFlag,
    Packet,
    Read,
    RealPath,
    Remove,
    Rename,
    Stat,
    Status,
    StatusCode,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.exceptions import TransferTimeoutError
from gantry_sftp.session import Dispatcher, Publish, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = [pytest.mark.anyio]

needs_a_real_pipe = pytest.mark.skipif(
    sys.platform != "linux",
    reason=(
        "these two rows spawn a real `sftp-server` and push a payload sized against a pipe's "
        "capacity, which is a platform constant; what a SIGCONTed server does with the "
        "half-written frame left behind is not known off Linux -- see D-160"
    ),
)
"""The two rows that spawn a process, and the whole of what D-160 leaves unproven off Linux.

**This replaced a skip over the entire module, whose stated reason was wrong** (D-160). That
reason was that every row wedges a peer, that teardown then makes a shielded uncancellable write,
and that whether it completes "comes down to whether the peer's buffer has room". `StallingServer`
has no buffer: it is an in-process object whose `send` either sleeps forever or appends to an
unbounded `bytearray`, with no pipe, no socket and no child anywhere in it. Nothing in it can
differ by platform, and `os.kill`, `signal` and `open_local_server_transport` appear in this module
**only** inside the two rows below.

The evidence in the original report says the same thing and was read past: the hung macOS job left
an orphaned `sftp-server`, and these two rows are the only place one is spawned. The inference that
sent the skip module-wide -- that pytest never printing the file's name meant it stalled on the
file's *first* row -- does not hold either, because that name is written without a newline and sits
in a block-buffered stream until something flushes it.

So fourteen rows are back on every platform and two are not, which is the scope the evidence
supports. What stays open is *why* these two hang there, and that needs a macOS run to answer.

**Both rows carry it, including the control, which does not stop anything and could not hang the
same way.** A control that runs where its subject is skipped is worse than no control: it goes
green, and green from a control reads as a claim having been checked. The pair moves together or
it stops meaning anything.
"""

SEND_TIMEOUT = 0.5
"""Short, because every test here waits it out. The shipped default is `request_timeout`."""

WATCHDOG = 10.0
"""A regression in this module is a hang, and a hang in a suite with no timeout plugin is a CI
job that runs until somebody kills it. Every test that could hang carries this."""

REMOTE_SIZE = 700_000
"""Big enough that a download issues several READs, so a test can stall the second one and
prove the scheduler was already in flight rather than stuck on its first move."""
HANDLE = b"h"

PIPE_FILLING_PAYLOAD = 200_000
"""One write that cannot fit in a pipe buffer, and that a real `sftp-server` will still accept.

Linux pipes hold 64 KiB. OpenSSH's server refuses a message over 256 KiB by calling `fatal()`
and exiting, so "as big as possible" is the wrong choice -- it tests our framing against their
ceiling instead of testing a blocked write."""


class StallingServer:
    """Answers every request, until it is asked to stop draining and never starts again.

    ``stall_on`` picks the packet type that wedges it, so a test can get a transfer genuinely
    under way before the pipe fills.

    **The wedge latches, and that is the whole model** (D-81). Blocking only the call being
    stalled makes the stall end when our send deadline cancels that call, so the *next* frame
    is served normally -- a peer that resumes draining the moment we give up. No peer does
    that, and the real-pipe rows at the bottom of this module do not: they ``SIGSTOP`` an
    `sftp-server`, which stays stopped. A fake that recovers where the real one does not is a
    fake confirming what its author believed, and here it cost a flake -- the second uploader's
    ``OPEN`` slipped through the recovered server into a race between its own deadline and the
    connection failure the first uploader had just recorded.

    ``wedge=False`` restores the recovering behaviour for the one row that needs it, and that
    row says why.
    """

    def __init__(
        self,
        *,
        stall_on: type[Packet] | None = None,
        stall_after: int = 1,
        wedge: bool = True,
    ) -> None:
        self.stall_on = stall_on
        self.stall_after = stall_after
        self.seen = 0
        self.stalled = anyio.Event()
        self.sent: list[Packet] = []
        self._wedge = wedge
        self._wedged = False
        self._splitter = FrameSplitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        if self._wedged:
            await anyio.sleep_forever()
        for frame in self._splitter.feed(data):
            packet = decode(frame)
            self.sent.append(packet)
            if self.stall_on is not None and isinstance(packet, self.stall_on):
                self.seen += 1
                if self.seen >= self.stall_after:
                    self._wedged = self._wedge
                    self.stalled.set()
                    await anyio.sleep_forever()
            self._reply(packet)

    def _reply(self, packet: Packet) -> None:
        answer = _answer(packet)
        if answer is None:  # pragma: no cover -- every packet these tests send has an answer
            return
        self._outbox += encode(answer)
        self._has_output.set()

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._outbox:
            self._has_output = anyio.Event()
            await self._has_output.wait()
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        return chunk

    async def aclose(self) -> None:
        return


def _answer(packet: Packet) -> Packet | None:
    """The smallest server that gets a transfer moving."""
    answer: Packet | None = None
    if isinstance(packet, Init):
        answer = Version(3)
    elif isinstance(packet, Stat | LStat | FStat):
        answer = AttrsReply(packet.request_id, Attrs(size=REMOTE_SIZE, permissions=0o100644))
    elif isinstance(packet, Open):
        answer = Handle(packet.request_id, HANDLE)
    elif isinstance(packet, Read):
        answer = _read_answer(packet)
    elif isinstance(packet, Write | Close | Remove | Rename | FSetStat):
        answer = Status(packet.request_id, StatusCode.OK)
    elif isinstance(packet, Extended):
        answer = ExtendedReply(packet.request_id, b"")
    return answer


def _read_answer(packet: Read) -> Packet:
    """DATA until the file runs out, then EOF -- the shape a real listing of reads gets."""
    if packet.offset >= REMOTE_SIZE:
        return Status(packet.request_id, StatusCode.EOF)
    length = min(packet.length, REMOTE_SIZE - packet.offset)
    return Data(packet.request_id, memoryview(bytes(length)))


def session(server: StallingServer, **overrides: object):
    """Open a session against ``server`` with the short deadlines these tests wait out."""
    settings: dict[str, object] = {"request_timeout": SEND_TIMEOUT, "idle_timeout": 5.0}
    settings.update(overrides)
    return open_session(server, **settings)  # type: ignore[arg-type]


# --- the two paths that hung ---------------------------------------------------------------


async def test_a_handshake_whose_init_is_never_accepted_times_out():
    """INIT used to be sent outside the deadline that covers VERSION.

    Nine bytes cannot fill a pipe on a fresh connection, which is why this was reasoned to be
    safe -- and "cannot happen" is a different claim from "is bounded", which is what a reader
    of "timeouts on every wait" is being promised.

    The message names *which half* stalled. One message for both would report a peer that never
    read our INIT as a server that never answered, which sends the reader to look at the wrong
    machine -- and the existing "server did not send VERSION" case is asserted, unchanged, in
    `test_session.py`.
    """
    with anyio.fail_after(WATCHDOG), pytest.raises(TransferTimeoutError) as exc:
        async with session(StallingServer(stall_on=Init)):
            pytest.fail("the handshake completed against a server that never read it")

    assert exc.value.args[0] == (f"the connection did not accept our INIT within {SEND_TIMEOUT}s")


async def test_a_download_whose_read_is_never_accepted_times_out(tmp_path: Path):
    """The one the card had reasoned away, and the one with no second task to save it.

    The download scheduler is a single task: it fills the window, then waits for replies with
    the idle timeout. A write that never completes happens *inside* the filling, where nothing
    else is waiting to time out -- so before this deadline the transfer hung with no error, no
    log line and no way out but a debugger.
    """
    server = StallingServer(stall_on=Read, stall_after=2)
    with anyio.fail_after(WATCHDOG), pytest.raises(TransferTimeoutError) as exc:
        async with session(server) as sftp:
            _ = await sftp.get(b"/remote/file.bin", tmp_path / "out.bin")

    # 26 bytes is a READ frame with a one-byte handle: 4 length, 1 type, 4 id, 5 handle,
    # 8 offset, 4 length. Pinned rather than approximated, because the count is how a reader
    # tells a stalled request from a stalled payload.
    assert exc.value.args[0] == (
        f"the connection did not accept 26 bytes of Read within {SEND_TIMEOUT}s; "
        f"the peer has stopped reading and the stream can no longer be trusted"
    )


async def test_an_upload_whose_write_is_never_accepted_times_out(tmp_path: Path):
    """The upload path had a bound already -- the drain task's idle timeout -- and now it has
    the tighter, more accurate one. The error names the write rather than the silence."""
    source = tmp_path / "upload.bin"
    _ = source.write_bytes(os.urandom(100))

    server = StallingServer(stall_on=Write)
    with anyio.fail_after(WATCHDOG), pytest.raises(TransferTimeoutError) as exc:
        async with session(server) as sftp:
            _ = await sftp.put(source, b"/remote/upload.bin", publish=Publish(atomic=False))

    # 126 bytes: the 22-byte WRITE header plus a 4-byte length and the 100-byte payload.
    assert exc.value.args[0] == (
        f"the connection did not accept 126 bytes of Write within {SEND_TIMEOUT}s; "
        f"the peer has stopped reading and the stream can no longer be trusted"
    )


# --- what the deadline covers, and what it ends --------------------------------------------


async def test_a_second_sender_behind_the_held_lock_reports_rather_than_queueing_forever(
    tmp_path: Path,
):
    """A task parked on a lock held by a stalled sender is stalled by transitivity.

    One pipe per session means one lock, so a deadline that started *after* the acquire would
    bound the wrong wait. That is why :meth:`Dispatcher._write` puts the acquire inside the
    scope, and this is the shape it is there for.

    **What the assertion below records, because it surprised the recon:** the second operation
    is stopped at its ``OPEN`` rather than at its ``WRITE``. Every transfer's first move is a
    one-shot request, and those are bounded by ``Session.request`` whether or not a write has a
    deadline of its own. The case where the acquire deadline is the only bound is a transfer
    that already holds its handle -- a download issuing its next ``READ`` while an upload holds
    the lock -- and it is
    :func:`test_a_sender_parked_on_the_lock_is_bounded_from_when_it_started_waiting` below.

    **Why the second uploader's message is deterministic, since this row flaked once (D-81).**
    It reported the *first* uploader's exception instead of its own -- the same object, handed
    to every exchange when a timed-out write finishes the connection. That was reproducible at
    about 1 run in 30 with a probe, and the cause was the fake rather than the library: the
    server used to serve the next frame normally once our deadline cancelled the send it was
    stalling, so the second ``OPEN`` went out into the window between the first uploader's
    ``_fail`` and its own deadline, and whichever of two sub-millisecond scheduling sequences
    finished first decided the message. ``StallingServer`` now stays wedged, so the second
    uploader is still inside its own ``OPEN`` when the deadlines fire, and *which* deadline
    that is follows from entry order rather than from timing: ``Session.request`` enters its
    scope before :meth:`Dispatcher._write` enters the send scope, both for ``request_timeout``
    seconds, so the outer deadline is strictly the earlier one -- and anyio delivers a
    cancellation to the outermost scope whose deadline has passed, on both backends.
    """
    source = tmp_path / "upload.bin"
    _ = source.write_bytes(os.urandom(100))
    server = StallingServer(stall_on=Write)
    reported: list[str] = []

    async def upload(sftp, remote: bytes) -> None:
        with anyio.move_on_after(WATCHDOG):
            try:
                _ = await sftp.put(source, remote, publish=Publish(atomic=False))
            except TransferTimeoutError as error:
                reported.append(error.args[0])

    with anyio.fail_after(WATCHDOG):
        async with (
            session(server, idle_timeout=WATCHDOG) as sftp,
            anyio.create_task_group() as group,
        ):
            group.start_soon(upload, sftp, b"/remote/first.bin")
            await server.stalled.wait()
            group.start_soon(upload, sftp, b"/remote/second.bin")

    assert sorted(reported) == [
        f"Open was not answered within {SEND_TIMEOUT}s",
        f"the connection did not accept 126 bytes of Write within {SEND_TIMEOUT}s; "
        f"the peer has stopped reading and the stream can no longer be trusted",
    ]
    # The idle timeout is the watchdog itself here, so neither message can be the "server went
    # quiet" one -- a queued sender that waited out the stall would have said that instead.


async def test_a_sender_parked_on_the_lock_is_bounded_from_when_it_started_waiting():
    """The case the row above names and cannot reach: the acquire deadline as the only bound.

    A request that already holds its handle -- the ``READ`` a download issues after the first
    one -- goes out through :meth:`Dispatcher.round_trip`, which has no deadline of its own on
    purpose. So the send scope is the whole bound, and *where the scope starts* is the entire
    question: inside covers the wait for the lock, outside starts counting only once the lock
    is free.

    Both spellings report, which is why the elapsed time is asserted and not just the message.
    With the acquire inside, this reports one ``SEND_TIMEOUT`` after it began waiting. With the
    acquire outside it would report one ``SEND_TIMEOUT`` after the *holder* gave up, which is
    two of them from here -- so the threshold sits halfway between, a quarter of a second from
    either, rather than being a number picked to pass.
    """
    server = StallingServer(stall_on=Write)
    codec = await negotiate(server)  # type: ignore[arg-type]
    reported: list[str] = []
    waited: list[float] = []

    async def holder(dispatcher: Dispatcher) -> None:
        # Total, because a child of a task group that raises turns every assertion below into
        # an ExceptionGroup mismatch rather than a failure that names itself.
        with anyio.move_on_after(WATCHDOG), pytest.raises(TransferTimeoutError):
            _ = await dispatcher.round_trip(Write(codec.allocate_request_id(), HANDLE, 0, b"x"))

    async def parked(dispatcher: Dispatcher) -> None:
        began = anyio.current_time()
        with anyio.move_on_after(WATCHDOG):
            try:
                _ = await dispatcher.round_trip(Read(codec.allocate_request_id(), HANDLE, 0, 32768))
            except TransferTimeoutError as error:
                reported.append(error.args[0])
                waited.append(anyio.current_time() - began)

    with anyio.fail_after(WATCHDOG):
        async with (
            running_dispatcher(server, codec, send_timeout=SEND_TIMEOUT) as dispatcher,  # type: ignore[arg-type]
            anyio.create_task_group() as group,
        ):
            group.start_soon(holder, dispatcher)
            await server.stalled.wait()
            group.start_soon(parked, dispatcher)

    # Its own message, naming its own frame -- 26 bytes for a READ with a one-byte handle, the
    # same arithmetic the download row above pins. The holder's WRITE message would mean it had
    # been handed the shared connection failure instead of reaching its own deadline.
    assert reported == [
        f"the connection did not accept 26 bytes of Read within {SEND_TIMEOUT}s; "
        f"the peer has stopped reading and the stream can no longer be trusted"
    ]
    assert SEND_TIMEOUT <= waited[0] < SEND_TIMEOUT * 1.5


async def test_a_timed_out_send_ends_the_connection_rather_than_the_operation(tmp_path: Path):
    """The load-bearing decision, and the reason it is not "fail this transfer and carry on".

    ``transport.send`` writes a whole frame and anyio's stream loops internally to do it, so a
    cancelled write leaves *part of a frame* in the pipe. Whatever the peer parses next reads a
    length prefix out of the middle of our payload. Letting other operations keep writing into
    that stream would turn one reported timeout into silent corruption, so the failure is
    recorded on the dispatcher and handed to everyone -- exactly as a dead transport is.
    """
    server = StallingServer(stall_on=Read, stall_after=2)
    with anyio.fail_after(WATCHDOG):
        async with session(server) as sftp:
            with pytest.raises(TransferTimeoutError) as first:
                _ = await sftp.get(b"/remote/file.bin", tmp_path / "out.bin")

            with pytest.raises(TransferTimeoutError) as second:
                _ = await sftp.realpath(b".")

    # The same exception object, not a fresh one of the same class: every waiter on a dead
    # connection is told the same thing, which is what stops two transfers reporting two
    # guesses at one cause.
    assert second.value is first.value


async def test_no_send_timeout_means_no_bound_at_all(tmp_path: Path):
    """``request_timeout=None`` is a legitimate thing to ask for and is never the default.

    Spelled as "still blocked when we stopped waiting" rather than as a hang, because a test
    that proves the absence of a timeout by hanging is a test that cannot fail.

    **The one row that keeps a recovering server** (``wedge=False``), and the reason is the
    claim itself. With no deadlines *and* a peer that stays wedged, the shielded ``CLOSE`` this
    block's teardown sends takes :meth:`Dispatcher._write`'s no-deadline branch and blocks
    forever -- and no cancel scope can end it, because the shield is what makes the cleanup
    reliable in the first place. That is the honest consequence of ``request_timeout=None``,
    it is now written down in :func:`~gantry_sftp.session.open_session`, and it cannot be
    asserted here: a test proving it would have to hang to do so. This row's subject is the
    absence of a bound on the *transfer*, which the recovering server proves without wedging
    the suite.

    **And "recovering" turned out to be a Linux fact** (D-160). On macOS this hung the whole
    lane for 45 minutes and left an orphaned `sftp-server` behind: the peer did not drain the
    way it does here, so the shielded `CLOSE` took exactly the no-deadline branch this docstring
    warns about. Nothing in-process can rescue that -- `move_on_after` cannot cancel a shield,
    which is the property that makes the shield worth having -- so the only bound is the CI
    job's own `timeout-minutes`. Skipped by platform rather than by probe because there is no
    probe for "will this fake drain here", and inventing one would be pretending.
    """
    server = StallingServer(stall_on=Read, stall_after=2, wedge=False)
    with anyio.move_on_after(1.0) as scope:
        async with session(server, request_timeout=None, idle_timeout=None) as sftp:
            _ = await sftp.get(b"/remote/file.bin", tmp_path / "out.bin")

    assert scope.cancelled_caught, "the transfer ended on its own with every deadline disabled"


async def test_a_dispatcher_defaults_to_no_send_deadline():
    """The bound arrives from `open_session`, which is the object that knows the timeouts.

    A default deadline on the dispatcher itself would apply to callers who deliberately asked
    for none, since `None` has to keep meaning `None` all the way down.
    """
    dispatcher = Dispatcher(StallingServer(), Codec())  # type: ignore[arg-type]
    assert dispatcher._send_timeout is None  # noqa: SLF001  # the field is the assertion


# --- the paths that were already bounded, kept so they stay that way -------------------------


async def test_a_one_shot_request_whose_send_stalls_still_reports():
    """`Session.request` wraps the whole round trip, so this was bounded before D-40 too.

    Kept because the send now has a deadline of its own inside that one: whichever fires first,
    the caller must still get a `TransferTimeoutError` rather than an unwrapped `TimeoutError`
    from a cancel scope.
    """
    with anyio.fail_after(WATCHDOG), pytest.raises(TransferTimeoutError):
        async with session(StallingServer(stall_on=RealPath)) as sftp:
            _ = await sftp.realpath(b".")


async def test_cancelling_a_blocked_send_from_outside_still_unwinds(tmp_path: Path):
    """The D-34 shape, checked rather than assumed: cleanup sends too.

    A blocked write holds the send lock, and the shielded cleanup after a cancelled transfer --
    the CLOSE for the handle, the REMOVE for a staging file -- queues behind it. Those are
    bounded by `request_timeout` through `Session.request`, so the block unwinds on the
    caller's schedule rather than waiting out the stall.
    """
    source = tmp_path / "upload.bin"
    _ = source.write_bytes(os.urandom(100))
    server = StallingServer(stall_on=Write)

    started = anyio.current_time()
    with anyio.fail_after(WATCHDOG):
        with anyio.move_on_after(0.2):
            async with session(server) as sftp:
                _ = await sftp.put(source, b"/remote/upload.bin", publish=Publish(atomic=False))

    assert anyio.current_time() - started < WATCHDOG / 2


def test_only_the_marked_rows_reach_for_a_real_process():
    """The premise the platform skip rests on, asserted rather than believed.

    `needs_a_real_pipe` is narrow because `StallingServer` owns no operating-system object --
    it cannot fill a pipe, stop a child or behave differently on another platform. That is a
    claim about *this file*, and a claim about a file rots the moment somebody adds a row. A
    single unmarked row that spawns an `sftp-server` puts the macOS hang back, and it would
    come back as a twenty-minute job with no failing assertion anywhere.

    So the file checks its own shape, in the spirit of `test_layer_discipline.py`: anything
    naming a process, a signal or the local-server transport has to carry the marker. Names are
    matched as source identifiers rather than imported, which is why this row can list them
    without listing itself.
    """
    spawning = {"open_local_server_transport", "find_sftp_server", "kill", "signal"}
    module = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    unmarked: list[str] = []
    for node in module.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        marked = any(
            isinstance(decorator, ast.Name) and decorator.id == "needs_a_real_pipe"
            for decorator in node.decorator_list
        )
        names = {
            child.id if isinstance(child, ast.Name) else child.attr
            for child in ast.walk(node)
            if isinstance(child, ast.Name | ast.Attribute)
        }
        if names & spawning and not marked:
            unmarked.append(node.name)

    assert unmarked == [], (
        f"these rows reach for a real process without `@needs_a_real_pipe`: {unmarked}. "
        "Either mark them or they will hang the macOS lane the way D-160 did."
    )


# --- a real pipe, genuinely full ------------------------------------------------------------


@needs_a_real_pipe
async def test_a_stopped_server_fills_the_pipe_and_the_deadline_reports_it(tmp_path: Path):
    """The fake above decides not to return. This one cannot return.

    ``SIGSTOP`` the real ``sftp-server`` and it stops reading its stdin. Push more at it than a
    pipe holds -- 64 KiB on Linux -- and the write blocks in the kernel, which is the condition
    every test above models. A fake proves the deadline fires when a coroutine never completes;
    only this proves that a peer which stops draining produces that condition at all.

    ``round_trip`` has no timeout of its own, deliberately, so the send deadline is the only
    thing that can end this. ``SIGCONT`` runs in a ``finally``: leaving a stopped child behind
    would wedge the next test rather than fail this one.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    # Well past a 64 KiB pipe and well under OpenSSH's own 256 KiB message ceiling. Bigger
    # than that is not a bigger test: `sftp-server` calls fatal() on an oversized frame and
    # exits, which fails as a dead child rather than as a blocked write.
    payload = os.urandom(PIPE_FILLING_PAYLOAD)
    remote = str(tmp_path / "stalled.bin").encode()

    async with open_local_server_transport(cwd=tmp_path) as transport:
        codec = await negotiate(transport)
        async with running_dispatcher(transport, codec, send_timeout=SEND_TIMEOUT) as dispatcher:
            opened = await dispatcher.round_trip(
                Open(
                    codec.allocate_request_id(),
                    remote,
                    OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC,
                )
            )
            assert isinstance(opened.response, Handle)
            handle = opened.response.handle

            os.kill(transport.pid, signal.SIGSTOP)
            try:
                with anyio.fail_after(WATCHDOG), pytest.raises(TransferTimeoutError) as exc:
                    _ = await dispatcher.round_trip(
                        Write(codec.allocate_request_id(), handle, 0, payload)
                    )
            finally:
                os.kill(transport.pid, signal.SIGCONT)

    # 25 bytes of frame plus the handle: 4 length, 1 type, 4 id, 4+n handle, 8 offset, 4 data
    # length. Derived from the handle the server actually issued -- OpenSSH's are four bytes,
    # and nothing promises another server's are.
    assert exc.value.args[0] == (
        f"the connection did not accept {25 + len(handle) + len(payload)} bytes of Write within "
        f"{SEND_TIMEOUT}s; the peer has stopped reading and the stream can no longer be trusted"
    )


@needs_a_real_pipe
async def test_a_running_server_accepts_the_same_write(tmp_path: Path):
    """The control, and it is not a formality.

    Without it, the test above passes just as happily if 300 KB were too much for this
    connection for some entirely different reason -- and it would then be asserting that our
    own limits are wrong rather than that a stopped peer stalls.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    payload = os.urandom(PIPE_FILLING_PAYLOAD)
    remote = str(tmp_path / "accepted.bin").encode()

    async with open_local_server_transport(cwd=tmp_path) as transport:
        codec = await negotiate(transport)
        async with running_dispatcher(transport, codec, send_timeout=SEND_TIMEOUT) as dispatcher:
            opened = await dispatcher.round_trip(
                Open(
                    codec.allocate_request_id(),
                    remote,
                    OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC,
                )
            )
            assert isinstance(opened.response, Handle)
            with anyio.fail_after(WATCHDOG):
                written = await dispatcher.round_trip(
                    Write(codec.allocate_request_id(), opened.response.handle, 0, payload)
                )
            assert isinstance(written.response, Status)
            assert written.response.code is StatusCode.OK
            _ = await dispatcher.round_trip(
                Close(codec.allocate_request_id(), opened.response.handle)
            )

    # `os.stat` rather than `Path.stat`: this file's lint rules ban blocking pathlib calls from
    # async code, and the point here is the byte count rather than the spelling.
    assert os.stat(os.fsdecode(remote)).st_size == len(payload)  # noqa: PTH116

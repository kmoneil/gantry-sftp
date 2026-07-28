"""Cancellation: what stops, what gets cleaned up, and what the unwind costs.

Cleanup after a failed transfer runs under `CancelScope(shield=True)`, and that shield is the
only reason a cancelled `get` returns its handle instead of leaking it. Every existing proof
of that release takes the *error* path -- and error and cancellation take different routes
through anyio, which is precisely why the shield is in the code at all (D-34).

The cancel arrives from **outside** `open_session` in every test here. That is the spelling a
caller reaches for, a timeout around a whole session, and it is the one that was broken: the
cleanup was shielded but the reader that has to route the cleanup's reply was not, so it went
with the same cancellation and the shielded `CLOSE` waited a full `request_timeout` for an
answer nobody was left to deliver -- forever, when `request_timeout` was None. Hence the
elapsed-time assertion in `run_cancelled`: the regression this file guards against makes
these operations slow rather than wrong, and an assertion on packets alone would pass while
every cancelled transfer took thirty seconds to notice.

The fakes are imported rather than rewritten. `TreeServer` already keeps the handle table
these tests read and `PublishingServer` already implements the staging ladder; a ninth
scripted server would prove a ninth author's idea of a server.
"""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import Close, MkDir, Open, OpenDir, Read, Status, StatusCode, Write
from gantry_sftp.session import open_session
from test_publish import PublishingServer
from test_recursive import SIMPLE_FILES, SIMPLE_TREE, TreeServer

pytestmark = pytest.mark.anyio

PATIENT = 5.0
"""`request_timeout` for these sessions.

Long enough that no unwind here can be waiting one out, and short enough that a regression
fails the suite in seconds instead of the thirty the shipped default would cost.
"""

BUDGET = 1.0
"""What unwinding a cancelled operation is allowed to take.

Two orders of magnitude above what an in-process fake needs and a fifth of `PATIENT`, so the
gap between "cancelled" and "waited out the timeout" cannot be closed by a loaded machine.
"""


async def cancel_when(ready: anyio.Event, scope: anyio.CancelScope) -> None:
    """Fire the caller's cancel at a known point in the conversation rather than after a sleep."""
    await ready.wait()
    scope.cancel()


async def run_cancelled(server, operation) -> None:
    """Run `operation` against `server`, cancelled from outside `open_session`.

    Asserts the two things every case here shares: that the cancel actually landed mid-flight
    rather than the operation finishing on its own, and that unwinding cost a round trip
    rather than a `request_timeout`. That nothing escapes is an assertion too -- a cancelled
    operation must surface as the cancellation the caller's scope absorbs, not as a
    `TransferError` and not as an `ExceptionGroup` from the `async with` line.
    """
    started = anyio.current_time()
    async with anyio.create_task_group() as group:
        caller = anyio.CancelScope()
        group.start_soon(cancel_when, server.stalled, caller)
        with caller:
            async with open_session(server, request_timeout=PATIENT) as sftp:
                await operation(sftp)
    elapsed = anyio.current_time() - started

    assert caller.cancel_called, "nothing was cancelled: the operation finished on its own"
    assert elapsed < BUDGET, (
        f"unwinding took {elapsed:.2f}s of a {PATIENT}s request_timeout -- the shielded "
        f"cleanup is waiting for a reply the reader is no longer there to route"
    )


class StallingTreeServer(TreeServer):
    """A tree server that stops answering READ, so a transfer parks with a handle open.

    Silence rather than a refusal on purpose: a refusal takes the error path, which is the
    one already proven. `stalled` fires on the first READ so the cancel lands at the same
    point in the conversation on every run and on both backends.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stalled = anyio.Event()

    def _on_read(self, packet: Read) -> None:
        self.stalled.set()


class StallingPublishServer(PublishingServer):
    """The same shape one layer up: a publish that parks with its staging file open."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stalled = anyio.Event()

    def _on_write(self, packet: Write) -> None:
        self.stalled.set()


class StallingUploadTreeServer(StallingPublishServer):
    """`StallingPublishServer` plus the one packet a tree upload needs and a publish does not."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.directories: list[bytes] = []

    def _dispatch(self, packet) -> None:
        if isinstance(packet, MkDir):
            self.seen.append(packet)
            self.directories.append(packet.path)
            self._reply(Status(packet.request_id, StatusCode.OK))
            return
        super()._dispatch(packet)


def kinds(server) -> list[str]:
    """The conversation as packet names, for the servers that do not report it themselves."""
    return [type(packet).__name__ for packet in server.seen]


# --- one file, both directions --------------------------------------------------------------


async def test_a_cancelled_get_stops_reading_and_closes_its_handle(tmp_path: Path):
    """The card's first clause: no further READ, and a CLOSE that reached the *server*.

    Asserted on the server's handle table rather than on the client having sent a CLOSE,
    because those are different claims and only one of them is the leak.
    """
    server = StallingTreeServer(tree={b"/": ()}, files={b"/big.bin": b"x" * 4096})

    await run_cancelled(server, lambda sftp: sftp.get("/big.bin", tmp_path / "big.bin"))

    conversation = kinds(server)
    assert "Read" in conversation, "the cancel landed before the transfer was in flight"
    assert conversation[-1] == "Close", (
        f"the conversation ended with {conversation[-1]}, not the shielded CLOSE"
    )
    assert conversation.count("Close") == 1
    assert server.open_handles == set(), "the server is still holding the file open"


async def test_a_cancelled_put_closes_its_handle_and_removes_the_staging_file(tmp_path: Path):
    """A cancelled nine-gigabyte upload is exactly when a staging file gets left behind.

    Both halves of the cleanup are shielded and both are asserted here: the handle comes back
    (`_close_quietly`) and the staging file goes (`_discard`), in that order, because a
    `REMOVE` of a file still open is a different question on some servers.
    """
    source = tmp_path / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")
    server = StallingPublishServer()

    await run_cancelled(server, lambda sftp: sftp.put(source, b"/incoming/report.csv"))

    assert server.kinds()[-2:] == ["Close", "Remove"], server.kinds()
    assert server.handles == {}, "the staging handle was never closed"
    assert server.files == {}, f"left on the server: {sorted(server.files)}"


# --- trees, where the walk must stop too ------------------------------------------------------


async def test_a_cancelled_get_tree_stops_walking_rather_than_draining(tmp_path: Path):
    """Two claims, and the second is the one a shield alone would not give you.

    The current file's handle comes back, *and* the walk stops where it was: no OPENDIR for
    the directory it had not reached. A cancellation that only unwound the transfer would
    leave the generator to be resumed or finalised somewhere it cannot be.
    """
    server = StallingTreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)

    await run_cancelled(server, lambda sftp: sftp.get_tree(b"/root", tmp_path / "local"))

    opened = [p.path for p in server.seen if isinstance(p, OpenDir)]
    assert opened == [b"/root"], f"the walk kept going: {opened}"
    assert [p.filename for p in server.seen if isinstance(p, Open)] == [b"/root/a.csv"]
    assert server.open_handles == set(), "a directory or file handle was left open"


async def test_a_cancelled_put_tree_stops_walking_and_leaves_no_staging_file(tmp_path: Path):
    """The upload direction of the same two claims. The local walk is ours, so it must stop."""
    source = tmp_path / "local"
    (source / "sub").mkdir(parents=True)
    (source / "a.csv").write_bytes(b"aaa")
    (source / "b.csv").write_bytes(b"bbb")
    (source / "sub" / "c.csv").write_bytes(b"ccc")
    server = StallingUploadTreeServer()

    await run_cancelled(server, lambda sftp: sftp.put_tree(source, b"/remote"))

    assert len([p for p in server.seen if isinstance(p, Open)]) == 1, "the walk kept going"
    assert server.handles == {}, "the staging handle was never closed"
    assert server.files == {}, f"left on the server: {sorted(server.files)}"
    assert [p for p in server.seen if isinstance(p, Close)], "no CLOSE was sent at all"

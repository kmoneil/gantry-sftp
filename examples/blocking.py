"""The same library from a program that has no event loop and does not want one.

    python examples/blocking.py                 # against a local sftp-server, no network
    python examples/blocking.py user@host /dir  # against a real server over ssh

`gantry_sftp.sync` is a facade, not a second library. Every call below is the identically
named `Session` method with a portal in front of it -- one implementation, so the blocking
surface cannot disagree with the async one about what `put` does, and `tests/test_sync_facade.py`
derives the parity check from the async signatures rather than from a list somebody maintains.

Six things this shows, in the order they bite.

**A `with`, not an `async with`.** The event loop runs on a background thread for the length of
the block. Nothing above this line is a coroutine and nothing below it needs to be.

**Streaming shapes come back as ordinary Python objects.** `walk` and `glob` are async
generators underneath and are plain iterators here; `scandir` is a context manager holding one
directory handle, exactly as it is asynchronously, because that is *why* it is a context
manager. Breaking out of either closes the handle on the server -- proved by asking the server,
not inferred from the absence of a complaint.

**Errors arrive as themselves.** `except NoSuchFileError` matches across the thread boundary,
flat, with no `ExceptionGroup` in the way.

**Many transfers over one connection is spelled with threads.** A blocking caller has no task
group, and a `SyncSession` is safe to share across a pool: each call posts to the same loop, so
the fan-out lands on the one reader that routes replies by request id.

**Owning the portal is how you get several sessions on one loop** -- or a backend other than
asyncio. `BoundPortal` is the whole of that story.

**`with_reconnect` runs your function on a third thread**, and it is the last section here
because it is the one place the blocking surface is not simply the async one with the `await`
removed. It hands you a session, and the portal's own thread cannot use one, so your function
goes to a worker from anyio's pool -- which is also why its `connect` recipe is the async
transport entry point rather than the blocking twin of the same name.
"""

from __future__ import annotations

import sys
import tempfile
import threading
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import Any

from anyio.from_thread import start_blocking_portal

from gantry_sftp import ConnectError, NoSuchFileError
from gantry_sftp.sync import (
    BoundPortal,
    SyncSession,
    connect,
    open_local_server_transport,
    open_session,
    with_reconnect,
)
from gantry_sftp.transport import (
    open_local_server_transport as async_open_local_server_transport,
)
from gantry_sftp.transport import (
    open_ssh_transport as async_open_ssh_transport,
)


def recipe_for(destination: str | None, workdir: Path) -> Callable[[], Any]:
    """The transport recipe `with_reconnect` calls once per attempt.

    The **async** entry points, which is the one asymmetry in this module: everything else a
    blocking caller touches is the same name out of `gantry_sftp.sync`, and this argument is
    not, because the transport is opened on the portal's loop rather than on this thread.
    """
    if destination is not None:
        user, _, host = destination.rpartition("@")
        return partial(async_open_ssh_transport, host, user=user or None)
    return partial(async_open_local_server_transport, cwd=workdir)


@contextmanager
def session_for(destination: str | None, workdir: Path) -> Generator[SyncSession]:
    """A blocking session, one call where there is a host and two where there is not."""
    if destination is not None:
        user, _, host = destination.rpartition("@")
        # The whole entry point. A portal is started for the block and stopped with it.
        with connect(host, user=user or None) as sftp:
            yield sftp
        return
    # No host to connect to, so a local `sftp-server` on a pipe -- and the two-call spelling,
    # which shares one portal because the transport carries it.
    with (
        open_local_server_transport(cwd=workdir) as transport,
        open_session(transport) as sftp,
    ):
        yield sftp


def populate(workdir: Path) -> Path:
    source = workdir / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")
    (workdir / "nested").mkdir()
    for index in range(4):
        (workdir / "nested" / f"part-{index}.csv").write_bytes(b"x" * (index + 1))
    return source


def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        source = populate(workdir)
        base = Path(remote_dir) if remote_dir else workdir
        remote = base / "report.csv"
        back = workdir / "downloaded.csv"

        with session_for(destination, workdir) as sftp:
            print(f"connected: {sftp!r}\n")

            result = sftp.put(source, str(remote).encode())
            print(f"put   {result.transferred} bytes  mechanism={result.mechanism.value}")
            print(
                f"get   {sftp.get(str(remote).encode(), back).transferred} bytes  ->  {back.name}"
            )
            print(f"same bytes: {back.read_bytes() == source.read_bytes()}\n")

            # An async generator, driven by an ordinary `for`.
            print("walk:")
            for entry in sftp.walk(str(base).encode()):
                print(
                    f"  {entry.path.decode()}  "
                    f"({len(entry.directories)} directories, {len(entry.files)} files)"
                )

            # A context manager, because it holds a directory handle across the loop. Breaking
            # out closes it: the `__exit__` reaches the thread the loop is on.
            print("\nscandir, stopping at the first .csv:")
            with sftp.scandir(str(base / "nested").encode()) as entries:
                for entry in entries:
                    if entry.name.endswith(".csv"):
                        print(f"  found {entry.name}, and the handle closes on the way out")
                        break

            print("\nglob:")
            for match in sftp.glob(str(base / "nested" / "*.csv").encode()):
                print(f"  {match.path.decode()}")

            # Flat and typed, across the thread boundary.
            try:
                sftp.stat(str(base / "definitely-not-here").encode())
            except NoSuchFileError as error:
                print(f"\nerror arrives as itself: {type(error).__name__}, code={error.code}")

            # "Many transfers over one connection" is a task group asynchronously. With no
            # event loop it is a thread pool: each call posts to the same loop, so the fan-out
            # lands on the one reader that already routes replies by request id.
            print("\neight downloads at once, over one connection:")
            with ThreadPoolExecutor(max_workers=8) as pool:
                sizes = list(
                    pool.map(
                        lambda index: (
                            sftp.get(
                                str(base / "nested" / f"part-{index % 4}.csv").encode(),
                                workdir / f"fan-{index}.csv",
                            ).transferred
                        ),
                        range(8),
                    )
                )
            print(f"  {len(sizes)} transfers, {sum(sizes)} bytes, one session, one channel")

            print(f"\nreader: {sftp.requests_sent} requests, {sftp.replies_received} replies")

        print(f"after the block: {sftp!r}")

        # --- and when one loop should serve several connections ---------------------------
        #
        # The module-level entry points start a portal each, which is right for a script with
        # one connection and wasteful for a job with ten. Owning the portal is how to say so,
        # and it is also how to run on trio instead of asyncio.
        print("\nseveral sessions on one portal:")
        with start_blocking_portal() as portal:
            gantry = BoundPortal(portal)
            with (
                gantry.open_local_server_transport(cwd=workdir) as first_transport,
                gantry.open_session(first_transport) as first,
                gantry.open_local_server_transport(cwd=workdir) as second_transport,
                gantry.open_session(second_transport) as second,
            ):
                print(f"  session A sees report.csv at {first.stat(b'report.csv').size} bytes")
                print(f"  session B lists {len(second.listdir(b'.'))} entries")
                print(f"  one loop for both: {first_transport.portal is second_transport.portal}")

        reconnecting(destination, workdir)


def reconnecting(destination: str | None, workdir: Path) -> None:
    """The last section, extracted because it is the one that is not simply the async
    call with the `await` removed -- and because `main` is at ruff's statement ceiling.
    """
    # --- and when the link may drop underneath you ----------------------------------------
    #
    # `with_reconnect` is the one entry point that hands your function a session rather
    # than yielding one, so the blocking form has to run that function somewhere it can
    # use what it was given -- which is not the portal's own thread. It goes on a worker
    # from anyio's pool, and the two consequences are visible below: the thread differs,
    # and an exception raised there is classified by the same rules as an async one.
    #
    # The recipe is the ASYNC transport entry point, because a transport is opened per
    # attempt on the portal's loop. The blocking twin of the same name is refused.
    print("\nreconnecting, without an event loop:")
    recipe = recipe_for(destination, workdir)
    attempts: list[int] = []

    def flaky(sftp: SyncSession) -> int:
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            raise ConnectError("pretending the link dropped on attempt one")
        return len(sftp.listdir(b"."))

    entries = with_reconnect(recipe, flaky, attempts=3, backoff=0.05)
    print(f"  {entries} entries, after {len(attempts)} attempts")
    assert attempts == [1, 2], "the first attempt should have failed and the second run"

    caller_thread = with_reconnect(recipe, lambda sftp: threading.get_ident())
    print(f"  this thread {threading.get_ident()}, your function's {caller_thread}")
    assert caller_thread != threading.get_ident(), "it ran here, so it is not a worker"

    # And the refusal that saves an afternoon: the blocking recipe is the wrong half.
    try:
        _ = with_reconnect(partial(open_local_server_transport, cwd=workdir), lambda s: None)
    except TypeError as exc:
        print(f"  a blocking recipe is refused: {str(exc)[:58]}...")
    else:
        raise AssertionError("a blocking transport recipe should have been refused")


if __name__ == "__main__":
    main()

"""The bounded worker pool: back-pressure, ordering, and the exception it owes you.

Tested on its own rather than only through the tree transfers, because the three properties
that make it correct are invisible from there. A pool that quietly buffered the whole producer
would still transfer the right bytes; so would one that raised an ``ExceptionGroup``; so would
one that ran four workers when asked for two. Each of those is a bug the callers cannot see.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import anyio
import anyio.lowlevel
import pytest

from gantry_sftp.session._pool import for_each_bounded

pytestmark = pytest.mark.anyio


async def counting(limit: int, *, produced: list[int] | None = None) -> AsyncGenerator[int]:
    for index in range(limit):
        if produced is not None:
            produced.append(index)
        yield index


async def test_one_worker_runs_the_items_in_order():
    # `concurrency=1` takes a separate branch on purpose -- it is the guarantee that the
    # sequential behaviour already shipped is the code already shipped, not a pool of one that
    # ought to be equivalent.
    seen: list[int] = []

    async def handle(item: int) -> None:
        await anyio.lowlevel.checkpoint()
        seen.append(item)

    await for_each_bounded(counting(10), handle, concurrency=1)
    assert seen == list(range(10))


async def test_every_item_is_handled_exactly_once_when_workers_overlap():
    seen: list[int] = []

    async def handle(item: int) -> None:
        await anyio.lowlevel.checkpoint()
        seen.append(item)

    await for_each_bounded(counting(50), handle, concurrency=8)
    assert sorted(seen) == list(range(50))
    assert len(seen) == 50


async def test_never_more_than_the_requested_number_run_at_once():
    in_flight = 0
    peak = 0

    async def handle(_item: int) -> None:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await anyio.sleep(0.01)
        in_flight -= 1

    await for_each_bounded(counting(30), handle, concurrency=4)
    assert peak == 4, f"asked for 4 workers and {peak} ran at once"


async def test_the_producer_cannot_run_ahead_of_the_pool():
    """The property the whole design exists for: a tree's size is the server's choice.

    `group.start_soon(...)` inside the walk is the obvious spelling and it materialises a task
    per entry, so a peer answering with a million names gets a million pending tasks. A
    zero-buffer stream means the producer is at most one item ahead of a busy pool.
    """
    produced: list[int] = []
    started = anyio.Event()

    async def handle(_item: int) -> None:
        started.set()
        await anyio.sleep(10)

    with anyio.move_on_after(0.5):
        async with anyio.create_task_group() as group:

            async def run() -> None:
                await for_each_bounded(counting(1000, produced=produced), handle, concurrency=4)

            group.start_soon(run)
            await started.wait()
            await anyio.sleep(0.05)
            group.cancel_scope.cancel()

    # Four in workers plus at most one blocked in `send`. Emphatically not 1000.
    assert len(produced) <= 5, f"the producer ran {len(produced)} ahead of four busy workers"


async def test_a_worker_failure_arrives_flat_rather_than_as_an_exception_group():
    # An anyio task group wraps even a single failure, which silently breaks every
    # `except TransferError` in calling code. CLAUDE.md names concurrent fan-out as the
    # default case for this rather than an edge one, so the pool owes the unwrap.
    async def boom(item: int) -> None:
        raise ValueError(f"item {item} failed")

    with pytest.raises(ValueError) as caught:
        await for_each_bounded(counting(10), boom, concurrency=4)

    assert caught.value.args[0].startswith("item ")
    assert not isinstance(caught.value, BaseExceptionGroup)


async def test_a_producer_failure_propagates_unwrapped_too():
    async def failing() -> AsyncGenerator[int]:
        yield 1
        raise RuntimeError("the walk failed")

    async def handle(_item: int) -> None:
        await anyio.lowlevel.checkpoint()

    for concurrency in (1, 4):
        with pytest.raises(RuntimeError) as caught:
            await for_each_bounded(failing(), handle, concurrency=concurrency)
        assert caught.value.args[0] == "the walk failed"


async def test_the_producer_is_closed_when_a_worker_stops_the_run():
    """An `async for` does not close the generator it iterates.

    The producers here wrap a `walk`, which holds a server-side directory handle, so a
    generator abandoned when a worker fails is a handle left open -- and trio does not
    finalise it. Proven by the generator's own `finally`, which only runs on close.
    """
    closed = False

    async def producer() -> AsyncGenerator[int]:
        nonlocal closed
        try:
            for index in range(1000):
                yield index
        finally:
            closed = True

    async def boom(_item: int) -> None:
        raise ValueError("stop")

    with pytest.raises(ValueError):
        await for_each_bounded(producer(), boom, concurrency=4)
    assert closed, "the producer was abandoned rather than closed"


@pytest.mark.parametrize("concurrency", [0, -1])
async def test_a_concurrency_below_one_is_refused(concurrency: int):
    async def handle(_item: int) -> None:
        await anyio.lowlevel.checkpoint()

    with pytest.raises(ValueError) as caught:
        await for_each_bounded(counting(1), handle, concurrency=concurrency)
    assert caught.value.args[0] == f"concurrency must be at least 1, got {concurrency}"

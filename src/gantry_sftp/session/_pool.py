"""A bounded worker pool over a producer that must not run ahead of it.

The shape both recursive transfers need, and the reason it is a pool rather than a task group
over the walk: **the tree's size is the server's choice.** ``group.start_soon(...)`` inside
``async for entry in walker`` is the obvious spelling and it is wrong for the same reason
building a whole listing in memory is wrong -- a peer that answers with a million entries gets
a million pending tasks, which is D-18's shape with extra steps.

So the producer feeds a **zero-buffer** memory object stream. ``send`` on one of those blocks
until a worker is actually ready to receive, which means the walk stops advancing while every
worker is busy. Back-pressure is the default rather than a thing to remember to add, and the
peak task count is ``concurrency`` no matter what the far end says the tree contains.

Two details that are load-bearing rather than incidental:

**``concurrency=1`` takes a different path on purpose.** Not an optimisation -- it is the
guarantee that the sequential behaviour this library already shipped is byte-for-byte the code
it already shipped, rather than a pool of one that merely ought to be equivalent. A stream, a
task group and a clone per worker are three places for a one-worker pool to differ from a
``for`` loop, and the public-API rule says the old spelling keeps resolving the old way.

**The exception is flattened at this boundary.** An anyio task group raises ``ExceptionGroup``
even for a single failure, so an untouched pool would turn every ``except TransferError`` in
calling code into an error nobody catches. CLAUDE.md names concurrent fan-out as the default
case for this rather than an edge one, and this is the boundary that owes the unwrap.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import aclosing

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream

from gantry_sftp.exceptions import flatten_exception_group

__all__ = ["for_each_bounded"]


async def for_each_bounded[T](
    items: AsyncGenerator[T],
    handle: Callable[[T], Awaitable[None]],
    *,
    concurrency: int,
) -> None:
    """Run ``handle`` over ``items``, at most ``concurrency`` of them at once.

    The producer is consumed lazily and blocks while every worker is busy, so nothing is
    materialised: memory is ``concurrency`` in-flight items, not the length of ``items``.

    Ordering is **not** preserved above ``concurrency=1``, and neither is the point at which
    an error stops the run: the first failure cancels the others, so some items may have been
    handled and some not. Both are properties of asking for concurrency, and the callers here
    document them where a user reads them.

    Args:
        items: The work, produced lazily. Typed as a generator rather than an ``AsyncIterable``
            because this closes it: an ``async for`` does not, and the producers here are
            generators wrapping a ``walk``, which holds a server-side directory handle. The
            common exit above ``concurrency=1`` is a *worker* failing, which stops the
            iteration from outside -- exactly the abandonment trio declines to finalise.
            Anything the producer raises propagates unchanged: it runs in this task, not in a
            worker, so it is not wrapped in a group.
        handle: Called once per item. Must be total: an exception here cancels every other
            worker and ends the run.
        concurrency: Workers. Must be at least 1; ``1`` runs the items in order in this task.

    Raises:
        ValueError: If ``concurrency`` is below 1, which is a caller mistake rather than a
            request for zero work.
        BaseException: Whatever ``handle`` or ``items`` raised, **flattened** out of the
            ``ExceptionGroup`` an anyio task group would otherwise wrap it in.
    """
    if concurrency < 1:
        raise ValueError(f"concurrency must be at least 1, got {concurrency}")
    if concurrency == 1:
        async with aclosing(items):
            async for item in items:
                await handle(item)
        return

    # Zero buffer: `send` waits for a receiver, so the producer cannot run ahead of the pool.
    send, receive = anyio.create_memory_object_stream[T](max_buffer_size=0)
    try:
        async with aclosing(items), anyio.create_task_group() as workers:
            for _ in range(concurrency):
                # A clone per worker, and each worker closes its own: the receive side stays
                # open while any clone is, so the pool drains rather than one worker's exit
                # ending the stream for the others.
                _ = workers.start_soon(_worker, receive.clone(), handle)
            # Ours is closed immediately -- the clones are what the workers hold, and leaving
            # this one open would keep the stream alive after the producer is done, so the
            # workers would wait forever on a stream nobody will send to.
            await receive.aclose()
            async with send:
                async for item in items:
                    await send.send(item)
    except BaseException as error:
        raise flatten_exception_group(error) from None


async def _worker[T](
    stream: MemoryObjectReceiveStream[T],
    handle: Callable[[T], Awaitable[None]],
) -> None:
    """Take items until the producer closes the stream, handling each one."""
    async with stream:
        async for item in stream:
            await handle(item)

"""What the codec allocates, measured: the third leg of its invariant (D-209).

CLAUDE.md says the codec "must not crash, hang, or over-allocate on arbitrary bytes". The first
two legs have properties in every codec module's tests. Nothing measured the third until D-209,
and measuring it found a leak no crash or hang property could see: CPython keeps every
``IntFlag`` member it builds, so a peer choosing flag bits chose how much this process kept.

Over-allocation has two shapes, so there are two instruments:

* :func:`peak_allocation` -- the most a call holds at once. That is bounded by a *multiple* of
  the input rather than by the input, because a well-formed reply costs more than its bytes:
  every NAME entry becomes Python objects.
* :func:`retained_allocation` -- what outlives a call once its result is dropped. That is bounded
  by noise alone. Anything that survives a decode and grows with what a peer sent is memory the
  peer controls for the life of the process.

Both read ``tracemalloc``, which counts the bytes Python asked its allocators for. That depends
on the code and the interpreter, not on the machine or its load, so the bounds are not timing
bounds and do not flake under contention. The interpreter is what moves them: the suite runs on
3.13 locally and 3.14 in CI, and the two disagree by a few per cent. Each bound is therefore
re-derived by a test on whatever interpreter runs it, rather than stated as a figure here.
"""

from __future__ import annotations

import contextlib
import gc
import os
import tracemalloc
from collections.abc import Generator
from dataclasses import dataclass

import pytest

from gantry_sftp.codec import AttrFlag, OpenFlag, PacketType, decode, describe
from gantry_sftp.exceptions import ProtocolError

DECODE_PEAK_PER_BYTE = 20
"""The most :func:`~gantry_sftp.codec.decode` may hold per byte of frame, over the fixed cost.

Derived from the densest *legal* frame and not from a hostile one, because the property using it
quantifies over arbitrary bytes and a legal frame is one of them. D-209's card said to take it
from its probe's post-fix reading. That reading is zero once a lying count is refused before
anything is built, and a well-formed frame of the same size costs more than the lying one ever
did, so a bound taken from it would refuse legal replies.

The densest legal frame is a NAME packed with minimal entries whose two names are one byte
each: an empty ``bytes`` is a shared singleton and a one-byte one is not, so two of them cost
more than the two wire bytes they add. ``tests/test_packets.py`` measures that frame and holds
this constant within a quarter of it, so it can neither go stale below a real reply nor drift
far enough above one to stop meaning anything.
"""

RECEIVE_PEAK_PER_BYTE = 48
"""The most :meth:`~gantry_sftp.codec.Codec.receive` may hold per byte it could process in one
call, over the fixed cost.

Higher than the decoder's, and the difference is the frame splitter.
:meth:`~gantry_sftp.codec.FrameSplitter.feed` slices every complete frame in a chunk before the
codec decodes the first, so a chunk of five-byte frames costs a ``memoryview`` object each --
dozens of times the frame -- before the first of them is refused. The transport reads at most
``DEFAULT_RECEIVE_SIZE`` at a time, which is what keeps that small in practice, and D-219 is the
card for pulling frames one at a time instead. ``tests/test_codec.py`` measures the shape and
holds this constant within a quarter of it.
"""

BUFFER_REGROWTH_PER_BYTE = 2
"""What a feed may hold per byte the splitter's buffer will contain, its consumed prefix included.

Appending to a ``bytearray`` can reallocate all of it, with an eighth to spare, and the splitter
keeps the prefix it has already parsed until that reaches ``_COMPACT_THRESHOLD`` -- the trade its
module docstring states. A reading charges the whole new block, because the old one was allocated
before the measurement began. So a six-byte chunk that completes a frame can hold ten kilobytes,
and that is the buffer, not the frame.
"""

FIXED_OVERHEAD = 8 * 1024
"""What a call may hold whatever the input's size: a refusal, its message and traceback, and the
excerpt of the frame it keeps. Measured at a few kilobytes, with room for a mutation lane whose
trampolines add a frame and its locals to every call."""

RETAINED_NOISE = 256
"""What a batch of decodes may leave behind once the enum caches are warm.

Below the few hundred bytes one leaked ``IntFlag`` member costs, so a single one fails the
property. What is left once the caches are warm measures as nothing at all.
"""

_ATTR_FLAGS = (
    AttrFlag.SIZE,
    AttrFlag.UIDGID,
    AttrFlag.PERMISSIONS,
    AttrFlag.ACMODTIME,
    AttrFlag.EXTENDED,
)


def _skip_during_mutmut_stats() -> None:
    """Report the test as skipped when this process is mutmut's coverage pass.

    That pass runs every call through a trampoline that records each call edge it has not seen
    before in a set, and the set keeps growing for the whole run. So a block that takes a new path
    reads as having allocated, and as having kept it, and none of that is the codec. The block has
    already run by the time this is called, so the pass still learns which tests reach which
    functions. Every other lane value -- the clean run, and each mutant's own run -- measures
    normally, which is where a mutant that allocates gets killed.
    """
    if os.environ.get("MUTANT_UNDER_TEST") == "stats":
        pytest.skip("mutmut's coverage pass allocates for its own bookkeeping")


@dataclass
class Allocation:
    """What a measurement found, filled in when its block ends."""

    bytes: int = 0


@contextlib.contextmanager
def peak_allocation() -> Generator[Allocation]:
    """Measure the most the block held at once, over what was held when it began.

    Leaves ``tracemalloc`` as it found it, so a caller already tracing keeps its traces.
    """
    measured = Allocation()
    started = not tracemalloc.is_tracing()
    if started:
        tracemalloc.start()
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        try:
            yield measured
        finally:
            measured.bytes = tracemalloc.get_traced_memory()[1] - baseline
    finally:
        if started:
            tracemalloc.stop()
    _skip_during_mutmut_stats()


@contextlib.contextmanager
def retained_allocation() -> Generator[Allocation]:
    """Measure what the block left allocated once everything it dropped is really released.

    That takes a full collection, and cycles are the lesser reason. A refusal is a cycle -- an
    exception, its traceback, a frame holding the exception it chained -- but CPython also keeps
    freed objects of several types on free lists for reuse rather than returning them, so a block
    that built and dropped a thousand pairs reads as having kept them until something empties
    those lists. Only a full collection does. It costs tens of milliseconds over this suite's
    heap, which is why the property using this runs fewer examples than its neighbours.
    """
    measured = Allocation()
    started = not tracemalloc.is_tracing()
    if started:
        tracemalloc.start()
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        try:
            yield measured
        finally:
            _collect_quietly()
            measured.bytes = tracemalloc.get_traced_memory()[0] - baseline
    finally:
        if started:
            tracemalloc.stop()
    _skip_during_mutmut_stats()


def _collect_quietly() -> None:
    """A full collection that calls nobody's ``gc`` callback.

    Each callback is handed a fresh dictionary per collection, and hypothesis installs one that
    stores a timestamp. Both outlive the collection, on a free list or in a global, and would read
    as retained by whichever block happened to trigger it. None of that is the codec's.
    """
    callbacks = gc.callbacks[:]
    gc.callbacks.clear()
    try:
        gc.collect()
    finally:
        gc.callbacks.extend(callbacks)


def empty_free_lists() -> None:
    """Make the next peak reading the true one, by emptying the interpreter's free lists.

    An allocation served from a free list reuses memory freed before tracing began, which
    ``tracemalloc`` never sees, so a peak read after heavy churn can be lower than what the code
    holds. That only ever errs towards passing, so the properties skip this for speed; the tests
    that *derive* a bound call it, because a bound derived from an underestimate is too low.
    """
    gc.collect()


def decode_quietly(frame: bytes) -> object:
    """Decode and describe ``frame`` as the frame dumper would, or return ``None`` on a refusal.

    The rendering is part of what is measured, because the dumper runs on every reply when it is
    enabled and is the other place a wire value meets an enum.
    """
    with contextlib.suppress(ProtocolError):
        packet = decode(frame)
        return (packet, describe(packet))
    return None


def warm_enum_caches() -> None:
    """Build every member the codec is *entitled* to cache, so a leak is all that is left.

    ``OpenFlag`` can take 64 values made of defined bits and ``AttrFlag`` 32, and each is cached
    the first time it is built. That is bounded, so it is not a leak -- but it happens at a moment
    no test controls, and a retention measurement taken across it would read the fill as one.
    The corpus also takes each refusal path once, since the first exception of a class sets up
    state its later instances share.
    """
    for value in range(64):
        OpenFlag(value)
    for subset in range(1 << len(_ATTR_FLAGS)):
        combined = AttrFlag(0)
        for position, flag in enumerate(_ATTR_FLAGS):
            if subset >> position & 1:
                combined |= flag
    request_id = b"\x00\x00\x00\x01"
    for packet_type in PacketType:
        decode_quietly(bytes([packet_type]) + request_id)
        decode_quietly(bytes([packet_type]) + request_id + bytes(16))
    decode_quietly(b"\x7f")
    undefined = (0x100).to_bytes(4, "big")
    decode_quietly(bytes([PacketType.ATTRS]) + request_id + undefined)
    empty_path = bytes(4)
    decode_quietly(bytes([PacketType.OPEN]) + request_id + empty_path + undefined + bytes(4))

"""Detecting a resource this suite acquired and did not release.

**D-115.** `live-tests/test_orphaned_handles.py` asks a real *server* whether it is still
holding a handle, which is a good test and a different question. Nothing watched **our own
process**, and the last leak found here -- `Process.aclose()` never called, leaving the pipe
transports open for the garbage collector -- surfaced as failures in **unrelated later tests**.
A leak whose blame lands on a test that did not cause it is indistinguishable from flakiness
while it is happening, and costs an afternoon of reading the wrong module.

Why live counts of a few types, and not the three more obvious instruments
--------------------------------------------------------------------------
All four were measured against the two leak shapes this repository has actually had -- an
`anyio` `Process` never closed, and an async generator chain abandoned mid-iteration -- and
against a clean transfer repeated three times:

===========================  ======  ==============  ==========================================
case                         fds     total objects   watched types
===========================  ======  ==============  ==========================================
clean transfer (x3)          +0      +1              ``{}``
a plain file left open       +1      +3              ``{}``
``Process`` never closed     +0      +29             ``{'Process': 2}``
async generator abandoned    +0      +100            ``{Dispatcher, Process, Session, ...}``
===========================  ======  ==============  ==========================================

**`tracemalloc` bytes and total object count both see the leaks, and neither can be
thresholded.** Measured across 294 real tests, 22% grow the total object count and one reaches
**146 objects** -- an fsspec test whose subject is a `storage_options` dict, nothing to do with
a transport. The real leaks are +29 and +100. A threshold that clears the noise misses the
leak. This is the card's own "not one fixed threshold" warning arriving with numbers, and it
also rules out deriving the bound from the transfer tunables: the noise is first-call caching
in unrelated modules, and no pipeline constant predicts it.

**Live counts of the resource-bearing types have no threshold at all.** One survivor is a
failure. Across the same 294 tests the count of watched types grew **zero** times, so the
signal needs no tuning and cannot drift with a tunable. It also *names what leaked*, which is
the whole point given that the last one was diagnosed in the wrong module.

**The fd count is kept as a second, cheaper signal**, because it catches the one shape the type
list misses -- a plain file object left open, which is +1 fd and no watched type. Note for
anyone reading the register: `/proc/<pid>/fd` **is readable here**, for our own pid and for a
child, and the count tracks opens and closes exactly. The earlier note saying otherwise was
measured in 2026-07 and no longer holds; verified again on 2026-08-03 before this was written.
It still probes rather than assumes, because a counter that silently reports zero because it
cannot see is worse than no counter -- that is the failure this file exists to avoid.

What this cannot see
--------------------
Anything the garbage collector reclaims before the second `collect()`. Both `collect()` calls
are deliberate: the first establishes a floor so a previous test's garbage is not charged here,
and the second gives finalizers their chance so an object that *would* be reclaimed is not
reported as leaked. What survives both is genuinely still referenced.
"""

from __future__ import annotations

import gc
import os
import types
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "LEAK_CHECK_ENV",
    "WATCHED_TYPES",
    "ResourceCount",
    "fd_count",
    "leak_check_enabled",
    "live_resources",
]

LEAK_CHECK_ENV = "GANTRY_SFTP_LEAK_CHECK"
"""Set to a non-empty value to arm the autouse fixture. Off by default -- see the lane."""

WATCHED_TYPES = frozenset(
    {
        "SubprocessTransport",
        "MemoryTransport",
        "Session",
        "Dispatcher",
        "Process",
    }
)
"""Types whose survival past a test means a resource was not released.

Deliberately narrow, and that is the finding rather than a shortcut: a cache growing by 146
dicts is not a leak and an undisposed transport is, and only a list this specific can tell the
two apart. Async generators are counted separately because they are matched by type identity
rather than by name.

**Adding a transport, a session-like object or anything else holding a child process means
adding it here.** Nothing enforces that automatically, which is why `test_leakcheck.py` asserts
the list covers every `Transport` implementation the package exports.
"""

_PROC_SELF_FD = Path("/proc/self/fd")


@dataclass(frozen=True)
class ResourceCount:
    """What was alive at one instant."""

    types: Counter[str]
    fds: int | None
    """``None`` when this platform has no readable ``/proc/self/fd``, so a caller can say
    "not measured" rather than reporting a clean zero it did not observe."""

    def growth_since(self, earlier: ResourceCount) -> dict[str, int]:
        """What is alive now that was not alive then.

        Returns:
            One entry per type that grew, plus ``"open fds"`` if descriptors grew and both
            readings could see them. Empty when nothing leaked.
        """
        grown = {
            name: self.types[name] - earlier.types[name]
            for name in sorted(set(self.types) | set(earlier.types))
            if self.types[name] > earlier.types[name]
        }
        if self.fds is not None and earlier.fds is not None and self.fds > earlier.fds:
            grown["open fds"] = self.fds - earlier.fds
        return grown


def fd_count() -> int | None:
    """Open file descriptors, or ``None`` if this platform will not say.

    Probed rather than assumed, which is the rule this project already applies to ``tc netem``:
    capability introspection was wrong there and probing was right. A counter that returns 0
    because it cannot see reads as proof that nothing leaked.
    """
    try:
        return sum(1 for _ in _PROC_SELF_FD.iterdir())
    except OSError:
        return None


def live_resources() -> ResourceCount:
    """Count the live objects that represent a held resource.

    One pass over ``gc.get_objects()``, which is the expensive part and which scales with the
    live heap rather than costing a flat amount per test -- measured at a few tens of
    milliseconds on a short run and several times that once the whole suite's heap is alive.
    That is why the fixture is armed by an environment variable rather than always on.
    """
    counts: Counter[str] = Counter()
    for obj in gc.get_objects():
        if isinstance(obj, types.AsyncGeneratorType):
            counts["async generator"] += 1
            continue
        name = type(obj).__name__
        if name in WATCHED_TYPES:
            counts[name] += 1
    return ResourceCount(types=counts, fds=fd_count())


def settle() -> ResourceCount:
    """Collect twice, then count.

    Twice on purpose. The first pass drops the previous test's garbage so it is not charged to
    this one; the second gives finalizers scheduled by the first their chance, so an object
    that *would* be reclaimed is not reported as a leak.
    """
    _ = gc.collect()
    _ = gc.collect()
    return live_resources()


def leak_check_enabled(environ: dict[str, str] | None = None) -> bool:
    """Whether the autouse fixture should measure anything.

    Args:
        environ: Environment to read. Injectable so the test for this does not depend on the
            developer's own shell, which is the rule for anything that changes what the suite
            does.
    """
    environ = os.environ if environ is None else environ
    return bool(environ.get(LEAK_CHECK_ENV, "").strip())

"""The gate over the one resource claim this project makes and had never measured.

`docs/tuning.md` puts it on the deployment screen, where a Cloud Run reader meets it: peak memory
is ``concurrent transfers x depth x request size``, about 16 MiB per transfer at the shipped
defaults, and **independent of the file's size in both directions**. Until this lane, the only
thing standing behind that was `tests/test_packaging.py` checking the sentence against
``DEFAULT_PIPELINE_DEPTH`` and ``PREFERRED_READ_LENGTH`` -- arithmetic over the documented values,
which cannot tell you whether a transfer stays inside them.

Two assertions, both internal to one run and needing nothing committed, which is the same shape
the two instruction gates have:

- **Flat**: the peak must not grow with the file, across a 16x range of sizes.
- **Bounded**: the most any rung costs over an empty session must stay under the *documented*
  expression, derived here from the same two constants the docs quote -- so a run fails when the
  code and the deployment page disagree, whichever of them moved.

Read `_memory.py`'s docstring before changing the harness. The obvious instrument -- ``ru_maxrss``
-- reports the *parent's* peak across ``posix_spawn``, and a first pass with it said this library
buffers whole files in both directions. It does not (D-138).
"""

from __future__ import annotations

import platform
from pathlib import Path

import pytest
from _instructions import MIB
from _memory import (
    MemoryLadder,
    MemoryRung,
    measure_peak,
    peak_unavailable_reason,
    render_memory,
    workload_source,
)

from gantry_sftp.session import DEFAULT_PIPELINE_DEPTH, PREFERRED_READ_LENGTH
from gantry_sftp.transport import find_sftp_server

LADDER: tuple[int, ...] = (16 * MIB, 64 * MIB, 256 * MIB)
"""Sizes measured, in both directions.

A 16x range, and it starts where it does on purpose. The claim is about *growth*, so what matters
is reach rather than resolution: 256 MiB is sixteen times the documented per-transfer bound, so a
run that buffered even a quarter of the largest file would be unmissable against the ~1% these
rungs actually differ by. Starting at 16 MiB rather than 1 keeps every rung above the bound, where
a buffer that is going to fill has filled.

Cheap, unlike the instruction ladder: nothing runs under cachegrind here, so the whole sweep is
seconds. The 336 MiB of payload is written once per run into pytest's temporary directory.
"""

GROWTH_TOLERANCE = 1.25
"""How far a rung's peak may rise above the smallest peak below it.

Measured span on a healthy run is about **1.01** across the whole ladder in both directions, so
this is twenty times the observed noise. It is set where a *pathology* lives rather than where
noise does, for the reason the size sweep's halving is: the failure this catches is a buffer that
grows with the file, and at these sizes that is not a 25% effect, it is a 900% one.
"""

DOCUMENTED_BOUND = DEFAULT_PIPELINE_DEPTH * PREFERRED_READ_LENGTH
"""One transfer's payload buffering, from the two constants `docs/tuning.md` quotes.

Derived rather than written down, so this gate and the deployment page cannot drift apart: change
either constant and both the documentation's arithmetic test and this measurement move with it.
The docs add "a few hundred KiB per connection for the frame splitter and the transport's read
buffer" on top, which :data:`BOUND_SLACK` is.
"""

BOUND_SLACK = 4 * MIB
"""What the measurement is allowed over :data:`DOCUMENTED_BOUND` before the gate fails.

The documented figure bounds *payload buffering*; a process also holds the frame splitter, the
transport's read buffer, the destination file's page-cache-backed writes and whatever the
interpreter's allocator has not returned. Four MiB is generous against a measured cost of about
1.3 MiB over the control, and it is still far under the 16 MiB the bound itself allows -- so the
gate has room for the allocator and none at all for a second copy of a file.
"""


def _fill(path: Path, size: int) -> None:
    """Write ``size`` bytes without ever holding them.

    In chunks, and that is load-bearing rather than tidy: a parent that builds a 256 MiB object
    raises its own high-water mark, and `_memory.py`'s docstring records what that does to a
    child's ``ru_maxrss``. This harness reads ``VmHWM`` and is immune, but a payload writer that
    only works because of which counter the reader chose is a trap left for the next person.
    """
    block = bytes(range(256)) * 4096
    with path.open("wb") as handle:
        written = 0
        while written < size:
            chunk = block[: min(len(block), size - written)]
            handle.write(chunk)
            written += len(chunk)


def _ladder_for(direction: str, workdir: Path, control: int) -> MemoryLadder:
    """Measure one direction, one process per rung."""
    rungs = []
    for size in LADDER:
        source = f"payload-{size}.bin"
        path = workdir / source
        if not path.exists():
            _fill(path, size)
        peak = measure_peak(workload_source(direction, cwd=workdir, source=source), cwd=workdir)
        rungs.append(MemoryRung(size_bytes=size, peak_kib=peak))
    return MemoryLadder(direction=direction, control=control, rungs=tuple(rungs))


def _growth_failures(ladders: list[MemoryLadder]) -> list[str]:
    """One line per direction whose peak grew with the file."""
    failures = []
    for ladder in ladders:
        grew = ladder.growth(tolerance=GROWTH_TOLERANCE)
        if grew:
            failures.append(f"{ladder.direction}: {'; '.join(g.describe() for g in grew)}")
    return failures


def _bound_failures(ladders: list[MemoryLadder]) -> list[str]:
    """One line per direction that cost more over an empty session than the docs allow."""
    ceiling = (DOCUMENTED_BOUND + BOUND_SLACK) // 1024
    return [
        f"{ladder.direction} cost {ladder.over_control_kib():,} KiB over an empty session, "
        f"against a documented {DOCUMENTED_BOUND / MIB:.0f} MiB plus {BOUND_SLACK / MIB:.0f} MiB "
        f"of slack"
        for ladder in ladders
        if ladder.over_control_kib() > ceiling
    ]


def _write_report(ladders: list[MemoryLadder]) -> None:
    """Write `_reports/memory.md` before anything asserts, so a failure ships its table."""
    reports = Path(__file__).resolve().parent.parent / "_reports"
    reports.mkdir(exist_ok=True)
    tables = "\n".join(render_memory(ladder, bound_bytes=DOCUMENTED_BOUND) for ladder in ladders)
    spans = ", ".join(f"{ladder.direction} {ladder.widest_span:.3f}" for ladder in ladders)
    (reports / "memory.md").write_text(
        f"# gantry-sftp peak memory\n\n"
        f"- **Host:** {platform.platform()} ({platform.machine()})\n"
        f"- **Python:** CPython {platform.python_version()}\n"
        f"- **Link:** no link -- `sftp-server` on a pipe\n\n"
        f"## Results\n\n{tables}\n"
        f"## What these numbers do not say\n\n"
        f"- **`VmHWM` from `/proc/self/status`, one process per rung.** `getrusage`'s "
        f"`ru_maxrss` is not a coarser version of this -- it reports the *parent's* peak "
        f"across `posix_spawn`, and a harness that builds payloads in-process poisons every "
        f"rung by the same amount, which is what makes the result look consistent (D-138).\n"
        f"- **One process per rung is required**, not tidy: `VmHWM` is a high-water mark, so a "
        f"second transfer in the same process can only report the first one's peak.\n"
        f"- **This process only.** `sftp-server` has its own memory and it is not counted here.\n"
        f"- **This run's widest span was {spans}**, against a "
        f"{GROWTH_TOLERANCE:.2f}x tolerance. A span approaching it means the tolerance has "
        f"become a measurement of the machine.\n"
    )


def test_peak_memory_does_not_grow_with_the_file_and_stays_inside_the_documented_bound(
    tmp_path: Path,
) -> None:
    """Both directions, one process per rung, then gate on flatness and on the bound."""
    reason = peak_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)
    if find_sftp_server() is None:
        pytest.skip("sftp-server not found; it ships in openssh-server")

    control = measure_peak(workload_source("control", cwd=tmp_path, source=""), cwd=tmp_path)
    ladders = [_ladder_for(direction, tmp_path, control) for direction in ("download", "upload")]
    _write_report(ladders)

    grew = _growth_failures(ladders)
    assert not grew, (
        f"peak memory grew with the file -- {'  |  '.join(grew)}. The ladder is in "
        f"`_reports/memory.md`. Buffering is bounded by depth x request size and is documented "
        f"as independent of the file's size in both directions, so a peak that tracks the file "
        f"is that claim being false."
    )
    over = _bound_failures(ladders)
    assert not over, (
        f"a transfer cost more memory than the documented expression allows -- "
        f"{'  |  '.join(over)}. The ladder is in `_reports/memory.md`. Either the buffering "
        f"changed or `docs/tuning.md` is now wrong; the gate cannot tell you which, but one of "
        f"them has to move."
    )

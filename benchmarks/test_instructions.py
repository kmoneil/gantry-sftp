"""The lane that gates CPU per byte, and the one that catches a superlinear cost.

Two assertions, and they need different things, which is why they are described apart.

**The shape gate needs nothing committed.** Marginal instructions per MiB -- what the bytes one
rung adds over the rung below cost -- is one number under work that is linear in the file size,
whatever the per-transfer fixed cost is. A rise in it is superlinearity, and it is visible while
throughput is still rising, which is where D-92's wall-clock sweep is blind by construction: a
fall in throughput is what that gate looks for, and a cost can be growing quadratically for a
long time before the curve turns over. Measured, in `_plans/probes/superlinear_blind_spot_probe.py`:
an O(n^2) reassembler costing 32% at 16 MiB passes both wall-clock gates, in both directions, on
the profile where it is most visible -- and no statistic of that lane separates it, because the
marginal-cost ratio it produces (1.11-1.50) sits inside the same statistic's own run-to-run range
on a healthy run (0.71-1.11).

**The regression gate needs a committed baseline, and that is what makes it D-63.** No lane here
could fail on a *figure* moving, because a figure needs something to be compared against and a
committed throughput figure is exactly what the Docs Rule forbids. An instruction count is a
count of work rather than a rate -- the same category as a golden frame -- so it may be
committed, and `instructions-<arch>.json` is. What it gates is **our own CPU per byte**, which is
DESIGN.md 5.2's second ceiling and the entire class of work D-112 belongs to: an ~11x improvement
in `encode(WRITE)` that no clock in this repository could see, landed on the strength of a
hand-built instrument that was thrown away afterwards.

**What it does not gate**, stated because the lane's name would imply otherwise: nothing about
pipelining, round trips, or the link. Round-trip counts are already asserted elsewhere (D-111)
and by the same reasoning -- a count is variance-free and is a shape rather than a figure.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

import pytest
from _harness import Environment, render_report
from _instructions import (
    DOWNLOAD,
    MIB,
    UPLOAD,
    Baseline,
    InstructionLadder,
    Rung,
    measure_all,
    measure_least,
    render_ladder,
    valgrind_unavailable_reason,
    workload_source,
)

from gantry_sftp.transport import find_sftp_server

LADDER: tuple[int, ...] = (1 * MIB, 4 * MIB, 8 * MIB, 16 * MIB)
"""Sizes measured, in both directions.

Four rungs rather than the wall-clock sweep's ten, and they are chosen for a different property.
That ladder brackets *boundaries*, because a cliff is only visible if a size sits either side of
the byte count it hides on. This one measures a *slope*, so what matters is that each step is a
doubling with a large absolute difference: a step's cost is a difference of two counts, so it
inherits their noise while being divided by the bytes between them. That is also why the gated
steps start at :data:`STEP_FLOOR` -- the same few percent of variation is a quarter of the signal
over 1 MiB and a fraction of it over 8.

Nine measurements, :data:`SAMPLES` runs each. Cachegrind is a two-orders-of-magnitude slowdown,
so this is a lane and never a hook -- the mutmut precedent, for the same reason.
"""

SAMPLES = 3
"""Runs per measurement, of which the cheapest is kept -- see :func:`_instructions.measure_least`.

Three rather than one because the first baseline taken here was one run, and its 8 MiB download
rung landed 2.6% above the two runs either side of it. Three rather than *more* because a 24-run
pool of one rung showed the minimum barely converging: min-of-six was no tighter than min-of-three
(1.020 against 1.021), and only min-of-twelve reached 1.001. Past three, samples buy wall clock
and not precision, so the band is where the rest of the variation has to be absorbed.
"""

STEP_FLOOR = 4 * MIB
"""Smallest rung a gated step may start from. See :data:`LADDER` for why a floor exists at all."""

SHAPE_TOLERANCE = 1.25
"""How far a step's cost per byte may rise above the cheapest step below it.

Set from the ratio's own spread across runs rather than from taste. Over three consecutive runs
of both directions the gated ratio came out at 1.004, 1.062, 1.000, 0.988, 1.001 and 1.001 -- so
a healthy run reaches about **1.06**, and the pathology this exists to catch measures **1.53**
(`_plans/probes/superlinear_blind_spot_probe.py`, and the numbers are asserted in
`tests/test_instruction_harness.py`). The tolerance sits between them, four times the observed
noise and well under the signal.

It is a *ratio of differences*, so it is looser than :data:`BASELINE_BAND` on the same data and
has to be: both counts it subtracts carry the read-granularity variation.
"""

BASELINE_BAND = 0.08
"""Fractional drift from the committed count that fails the run.

**Set from a 24-run pool, after two smaller samples each produced a number that was the
instrument rather than the code.** Two runs suggested 0.06% and a third pair suggested 0.5%; a
pool of twenty-four runs of one rung spans **2.6%**, minimum-of-three groups within it span
2.1%, and a group taken an hour earlier fell below that pool's floor entirely -- so the honest
figure across a session is about **4%**. Eight percent is twice that.

**What that costs, stated rather than left for somebody to discover.** This gate catches a
change of roughly a tenth or more in our CPU per byte. D-112's class -- an ~11x -- it catches
with three orders of magnitude to spare. A single extra copy of the payload on the data path is
about 2.6% here and it does **not**. Tightening that needs the read granularity held still,
which means a deterministic in-process transport rather than a real pipe, and that is named in
the card as the follow-on rather than pretended away with a smaller number.

The interpreter's own count is not what is loose here: with the hash seed pinned it is
bit-identical. The variance is entirely in how much of the stream each ``read`` returns, which
is the operating system's decision and moves with what else is on the machine.
"""


def baseline_path() -> Path:
    """Where this machine's committed counts live.

    Architecture is in the filename rather than inside the file, so a missing baseline is
    visible in a directory listing instead of being discovered by a gate that declined to fire.
    """
    return Path(__file__).resolve().parent / f"instructions-{platform.machine()}.json"


WRITE_BASELINE = "GANTRY_SFTP_INSTRUCTION_BASELINE"
"""Set to ``write`` to regenerate the baseline instead of asserting against it.

An explicit act producing a reviewed diff, never an automatic overwrite: a baseline that
refreshed itself whenever it disagreed with a run would agree with every run, including the one
that made everything twice as expensive.
"""


def _fill(path: Path, size: int) -> None:
    """Write ``size`` deterministic bytes -- the same reasoning as the wall-clock corpus."""
    block = bytes(range(256))
    path.write_bytes(block * (size // len(block)))


def _ladder_for(direction: str, workdir: Path, control: int) -> tuple[InstructionLadder, float]:
    """Measure one direction, net of an already-measured control.

    Returns:
        The ladder, and the widest spread seen within any one rung's samples. The spread goes in
        the report beside the verdict: a gate that prints a number without its precision cannot
        be checked for whether the number means anything, and this instrument's precision is the
        thing two earlier estimates of :data:`BASELINE_BAND` got wrong.
    """
    rungs, worst = [], 1.0
    for size in LADDER:
        source = f"payload-{size}.bin"
        _fill(workdir / source, size)
        samples = measure_all(
            workload_source(direction, cwd=workdir, source=source), cwd=workdir, samples=SAMPLES
        )
        nets = [total - control for total in samples]
        worst = max(worst, max(nets) / min(nets))
        rungs.append(Rung(size_bytes=size, instructions=min(nets)))
    return InstructionLadder(direction=direction, control=control, rungs=tuple(rungs)), worst


def _shape_failures(ladders: list[InstructionLadder]) -> list[str]:
    """One line per direction whose cost per byte grew with the file."""
    failures = []
    for ladder in ladders:
        rises = ladder.rises(tolerance=SHAPE_TOLERANCE, floor_bytes=STEP_FLOOR)
        if rises:
            failures.append(f"{ladder.direction}: {'; '.join(rise.describe() for rise in rises)}")
    return failures


def _baseline_findings(
    baseline: Baseline | None, ladders: list[InstructionLadder]
) -> tuple[list[str], list[str]]:
    """Split the baseline comparison into what fails and what is only worth saying.

    Returns:
        ``(failures, notes)``. A rung that got *costlier* fails. A rung that got cheaper, and a
        rung the baseline has never heard of, are notes -- neither is a regression, and both
        mean the committed file should be regenerated before it stops being able to see one.
    """
    if baseline is None:
        return [], [f"No baseline at `{baseline_path().name}`, so nothing gates our CPU per byte."]
    mismatch = baseline.mismatch()
    if mismatch is not None:
        return [], [f"The baseline did not apply and no figure was gated: {mismatch}."]

    failures, notes = [], []
    for ladder in ladders:
        for drift in baseline.drifts(ladder, band=BASELINE_BAND):
            (failures if drift.costlier else notes).append(drift.describe())
        unknown = baseline.unknown_rungs(ladder)
        if unknown:
            sizes = ", ".join(f"{size // MIB} MiB" for size in unknown)
            notes.append(f"The baseline says nothing about {ladder.direction} at {sizes}.")
    return failures, notes


def _precision_note(spread: float) -> str:
    """What this run's own samples say about how much its numbers can be trusted.

    In the report rather than only in a constant's docstring, because the band below was set
    twice from too few samples before a 24-run pool settled it. A run whose own spread has
    quietly grown past the band is a run whose gate has stopped meaning anything, and this is
    the line that would show it.
    """
    return (
        f"**This run's widest within-rung spread was {spread:.3f}**, against a "
        f"{BASELINE_BAND:.0%} band. The residue is the operating system's choice of how much of "
        f"the stream each `read` returns; a spread approaching the band means the band is now "
        f"measuring the machine rather than the code."
    )


def _write_report(ladders: list[InstructionLadder], baseline: Baseline | None, notes: list[str]):
    """Write `_reports/instructions.md`, before anything asserts.

    Same rule the wall-clock lane follows: a gate that destroys the evidence for its own verdict
    is worse than no gate, so the tables are on disk before the assertion that reads them.
    """
    reports = Path(__file__).resolve().parent.parent / "_reports"
    reports.mkdir(exist_ok=True)
    environment = Environment.capture(
        sftp_server_path=str(find_sftp_server()),
        library_versions={"valgrind": "cachegrind", "python": platform.python_version()},
    )
    text = render_report(
        title="gantry-sftp instruction counts",
        environment=environment,
        profile="no link -- `sftp-server` on a pipe, under cachegrind",
        sections=[render_ladder(ladder, baseline=baseline) for ladder in ladders],
        caveats=[
            "**Instructions retired by this process only.** `sftp-server` runs outside "
            "cachegrind and its work is not counted, which is the point: what this measures is "
            "the Python side, which is the ceiling more transports would run into (DESIGN.md "
            "5.2).",
            "**Net of a control** that opens and closes the same session moving no bytes, "
            "because 97% of a run's count is interpreter startup and cachegrind cannot "
            "attribute it away -- it counts machine code, and every Python frame is inside one "
            "eval loop.",
            "**A count is reproducible against one instruction set and one interpreter.** Both "
            "are in the environment block above and in the baseline's own fields; a baseline "
            "that does not match says so rather than passing quietly.",
            "This lane says nothing about pipelining, round trips or the link. It is CPU per "
            "byte and the shape of it.",
            *notes,
        ],
    )
    (reports / "instructions.md").write_text(text)


def test_instruction_counts_are_linear_in_the_bytes_and_match_the_baseline(tmp_path: Path) -> None:
    """Measure both directions, then gate on shape and on the committed counts.

    The order is deliberate and is the wall-clock lane's: measure everything, write the report,
    and only then assert -- so a failure ships the table that proves it.
    """
    reason = valgrind_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)
    if find_sftp_server() is None:
        pytest.skip("sftp-server not found; it ships in openssh-server")

    control = measure_least(
        workload_source("control", cwd=tmp_path, source=""), cwd=tmp_path, samples=SAMPLES
    )
    measured = [_ladder_for(direction, tmp_path, control) for direction in (DOWNLOAD, UPLOAD)]
    ladders = [ladder for ladder, _ in measured]
    precision = max(spread for _, spread in measured)

    if os.environ.get(WRITE_BASELINE) == "write":
        written = Baseline.of_this_machine(control, ladders)
        baseline_path().write_text(written.dumps())
        pytest.skip(f"wrote {baseline_path().name}; review the diff and commit it")

    path = baseline_path()
    baseline = Baseline.loads(path.read_text()) if path.exists() else None
    failures, notes = _baseline_findings(baseline, ladders)
    _write_report(ladders, baseline, [*notes, _precision_note(precision)])

    shape = _shape_failures(ladders)
    assert not shape, (
        f"instructions per byte grew with the file -- {'  |  '.join(shape)}. The ladder is in "
        f"`_reports/instructions.md`. Work linear in the transfer costs the same per byte at "
        f"every size, so a step above {SHAPE_TOLERANCE:.2f}x the cheapest below it is a "
        f"superlinear cost, and it is one the wall-clock sweep cannot see while throughput is "
        f"still rising."
    )
    assert not failures, (
        f"CPU per byte regressed against `{path.name}` -- {'  |  '.join(failures)}. The ladder "
        f"is in `_reports/instructions.md`. If the change is intended, regenerate with "
        f"`{WRITE_BASELINE}=write` and commit the diff."
    )


if __name__ == "__main__":  # pragma: no cover - convenience for a one-off measurement
    sys.exit(pytest.main([__file__, "-s"]))

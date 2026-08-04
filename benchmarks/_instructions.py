"""Counting the work a transfer costs, rather than timing it.

The wall-clock lane beside this one answers "how fast", and it cannot gate: a figure needs a
committed baseline to be compared against, and a committed *throughput* figure is what the Docs
Rule forbids (D-94). This module answers a different question -- **how much work** -- and an
instruction count is not a rate. It is the same category as a golden frame: an exact number,
committed, that a run either reproduces or does not.

Three findings shaped every decision here, and each one is a measurement rather than an
argument. They are in ``_plans/probes/`` under the names given.

**The instrument is exact once the hash seed is pinned** (``instruction_count_probe.py``).
Cachegrind on an unpinned interpreter reproduced to about 0.1%; with ``PYTHONHASHSEED=0`` a
pure-codec workload came back **bit-identical** four runs running. Real I/O costs some of that
back -- a 16 MiB download over a real ``sftp-server`` varies by about 0.06%, because the
operating system decides how much of the stream each ``read`` returns -- but the residue is two
orders of magnitude under the wall-clock lane's spread, which reaches 10 on the same rungs.

**Ninety-seven percent of the count is interpreter startup, and it cannot be attributed away.**
Cachegrind counts machine code; every Python frame in the process is inside the same eval loop,
so the out file's per-function records name ``_PyEval_EvalFrameDefault`` and nothing of ours.
Hence :class:`InstructionLadder` carries a **control** -- the same session, opened and closed,
moving no bytes -- and every figure here is net of it. A ladder without its control would be a
gate on CPython's import graph.

**The shape test is the part that needs no baseline, and it is why this module exists at all**
(``superlinear_blind_spot_probe.py``, and D-92's gate is what it was run against). Under linear
work the *marginal* cost of each rung -- instructions for the bytes it adds over the rung below
-- is the same number at every size. A superlinear cost makes it rise. That comparison is
internal to one run, so it needs nothing committed and it fires on a machine no baseline was
ever generated for.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

MIB = 1024 * 1024

I_REFS = re.compile(r"I\s+refs:\s+([\d,]+)")
"""Cachegrind's summary line. The only number this module reads out of the tool."""

DOWNLOAD = "download"
UPLOAD = "upload"


@dataclass(frozen=True, slots=True)
class Rung:
    """One transfer size and what it cost, net of the control.

    Attributes:
        size_bytes: Bytes moved by the measured transfer.
        instructions: Instructions retired by this process, with the control's count already
            subtracted. Net rather than total because the total is nine parts interpreter
            startup -- see the module docstring.
    """

    size_bytes: int
    instructions: int

    def __post_init__(self) -> None:
        if self.size_bytes <= 0:
            raise ValueError(f"a rung must move bytes, got {self.size_bytes}")
        if self.instructions <= 0:
            raise ValueError(
                f"{self.size_bytes} bytes cost {self.instructions} instructions net of the "
                f"control; a transfer that costs nothing over an empty session was not measured"
            )

    @property
    def mib(self) -> float:
        return self.size_bytes / MIB

    @property
    def instructions_per_mib(self) -> float:
        """Average cost per MiB, which still carries the per-transfer fixed cost.

        Falls as the file grows even when nothing is wrong, because the fixed cost is being
        amortised. :class:`Step` is the quantity that does not.
        """
        return self.instructions / self.mib


@dataclass(frozen=True, slots=True)
class Step:
    """Two rungs, and what the bytes between them cost.

    The load-bearing quantity in this module. Under work that is linear in the file size the
    marginal cost per MiB is the *same number* for every step, whatever the per-transfer fixed
    cost is -- so a rise in it is a statement about the rate rather than about the ladder, and
    it needs no baseline to be read.
    """

    smaller: Rung
    larger: Rung

    def __post_init__(self) -> None:
        if self.larger.size_bytes <= self.smaller.size_bytes:
            raise ValueError(
                f"a step goes up: {self.smaller.size_bytes} to {self.larger.size_bytes}"
            )

    @property
    def added_mib(self) -> float:
        return (self.larger.size_bytes - self.smaller.size_bytes) / MIB

    @property
    def instructions_per_mib(self) -> float:
        """Instructions for the added bytes, per MiB of them."""
        return (self.larger.instructions - self.smaller.instructions) / self.added_mib

    def describe(self) -> str:
        return f"{self.smaller.mib:.0f}->{self.larger.mib:.0f} MiB"


@dataclass(frozen=True, slots=True)
class Rise:
    """A step whose marginal cost per byte rose against a cheaper step below it.

    The superlinearity finding, and the reason the reference is the *cheapest* step below
    rather than the one immediately before: the same structure :meth:`SizeSweep.cliffs` uses
    for the wall-clock curve, where the reference is the best throughput below rather than the
    previous rung. One noisy step must not become the yardstick every later step is forgiven
    against.
    """

    step: Step
    reference: Step

    @property
    def ratio(self) -> float:
        return self.step.instructions_per_mib / self.reference.instructions_per_mib

    def describe(self) -> str:
        return (
            f"{self.step.describe()} costs {self.step.instructions_per_mib:,.0f} "
            f"instructions/MiB, {self.ratio:.2f}x the {self.reference.instructions_per_mib:,.0f} "
            f"measured over {self.reference.describe()}"
        )


@dataclass(frozen=True, slots=True)
class InstructionLadder:
    """Instructions against transfer size, for one direction, net of an empty session.

    Attributes:
        direction: ``"download"`` or ``"upload"``. Both are measured because they are different
            code -- D-112's ~11x improvement was in ``encode(WRITE)``, which only the upload
            path reaches, and a lane that swept reads would have been blind to the change it
            exists to have caught.
        control: Instructions for the same session opened and closed, moving no bytes. Already
            subtracted from every rung; kept so a report can state what was taken off.
        rungs: Ascending by size.
    """

    direction: str
    control: int
    rungs: tuple[Rung, ...]

    def __post_init__(self) -> None:
        if self.control <= 0:
            raise ValueError(f"the control cost {self.control} instructions; nothing was measured")
        if len(self.rungs) < 2:
            raise ValueError(f"{self.direction} has no shape: {len(self.rungs)} rung")
        sizes = [rung.size_bytes for rung in self.rungs]
        if sizes != sorted(set(sizes)):
            raise ValueError(f"{self.direction} rungs are not strictly ascending")

    def steps(self, *, floor_bytes: int) -> tuple[Step, ...]:
        """Every adjacent pair at or above ``floor_bytes``.

        Args:
            floor_bytes: Smallest rung a step may start from. A floor exists because a step's
                cost is a *difference*, so the measurement noise it inherits is fixed while the
                bytes it is divided by are not: over 1 MiB the residual 0.06% of a 490M-count
                run is a quarter of the signal, and over 8 MiB it is under two percent.

        Returns:
            The steps, in ascending order. Empty when fewer than two rungs clear the floor,
            which is a ladder that cannot answer the question rather than one that passed.
        """
        eligible = [rung for rung in self.rungs if rung.size_bytes >= floor_bytes]
        return tuple(Step(smaller=smaller, larger=larger) for smaller, larger in pairwise(eligible))

    def rises(self, *, tolerance: float, floor_bytes: int) -> tuple[Rise, ...]:
        """Every step costing more per byte than ``tolerance`` x the cheapest step below it.

        Args:
            tolerance: Ratio a step may reach before it counts. ``1.0`` would fail on the
                measurement noise; see the lane for where the shipped number comes from.
            floor_bytes: Passed to :meth:`steps`.

        Returns:
            One :class:`Rise` per offending step. Empty is the result this lane exists to keep
            true: the work stays linear in the bytes.

        Raises:
            ValueError: If ``tolerance`` is below 1.0, which would fail a ladder for being
                *cheaper* at the top than at the bottom -- the shape of an improvement.
        """
        if tolerance < 1.0:
            raise ValueError(f"tolerance is a ratio at or above 1.0, got {tolerance}")
        steps = self.steps(floor_bytes=floor_bytes)
        found = []
        for index, step in enumerate(steps[1:], start=1):
            reference = min(steps[:index], key=lambda s: s.instructions_per_mib)
            if step.instructions_per_mib > tolerance * reference.instructions_per_mib:
                found.append(Rise(step=step, reference=reference))
        return tuple(found)


@dataclass(frozen=True, slots=True)
class Drift:
    """One rung measured against what a committed baseline says it cost."""

    direction: str
    rung: Rung
    expected: int

    @property
    def ratio(self) -> float:
        return self.rung.instructions / self.expected

    @property
    def costlier(self) -> bool:
        """Whether the run costs *more* than the baseline. The direction that fails."""
        return self.ratio > 1.0

    def describe(self) -> str:
        return (
            f"{self.direction} at {self.rung.mib:.0f} MiB cost {self.rung.instructions:,} "
            f"instructions against a baseline of {self.expected:,} ({self.ratio:.3f}x)"
        )


@dataclass(frozen=True, slots=True)
class Baseline:
    """Committed instruction counts for one architecture and one interpreter.

    **Why this may be committed when a throughput figure may not.** The Docs Rule forbids a
    committed file carrying a throughput figure, because a rate is a claim about a machine and
    a link that the reader does not have. A count of instructions is a claim about *this code*:
    it moves when the code moves and stays put when the machine is busy. That is why the two
    identifying fields below are not decoration -- a count is only reproducible against the
    interpreter and the instruction set it was taken on, so a baseline that cannot say which
    ones it belongs to is a number with no claim attached.

    Attributes:
        architecture: ``platform.machine()`` where this was taken.
        python: ``platform.python_version()`` where this was taken. Pinned to the patch
            release, because a bytecode change moves every count here and a gate that
            silently forgave that would be reporting on an interpreter nobody is running.
        control: Instructions for the empty session, recorded so a drift in the *fixed* cost
            is visible rather than being subtracted out of sight.
        ladders: Direction to ``{size_bytes: instructions}``, net of the control.
    """

    architecture: str
    python: str
    control: int
    ladders: Mapping[str, Mapping[int, int]]

    @classmethod
    def of_this_machine(cls, control: int, ladders: Sequence[InstructionLadder]) -> Baseline:
        """Build a baseline from a run on the machine executing this call."""
        return cls(
            architecture=platform.machine(),
            python=platform.python_version(),
            control=control,
            ladders={
                ladder.direction: {rung.size_bytes: rung.instructions for rung in ladder.rungs}
                for ladder in ladders
            },
        )

    @classmethod
    def loads(cls, text: str) -> Baseline:
        """Read a baseline from JSON, with the sizes back as integers.

        Raises:
            ValueError: If a required field is missing, so a truncated or hand-edited file is
                a stated failure rather than a gate that quietly compares against zero.
        """
        raw = json.loads(text)
        try:
            return cls(
                architecture=raw["architecture"],
                python=raw["python"],
                control=raw["control"],
                ladders={
                    direction: {int(size): count for size, count in rungs.items()}
                    for direction, rungs in raw["ladders"].items()
                },
            )
        except KeyError as exc:
            raise ValueError(f"baseline is missing {exc.args[0]!r}") from exc

    def dumps(self) -> str:
        """Render as JSON, sorted and newline-terminated, so a regeneration diffs cleanly."""
        return (
            json.dumps(
                {
                    "architecture": self.architecture,
                    "python": self.python,
                    "control": self.control,
                    "ladders": {
                        direction: {str(size): count for size, count in sorted(rungs.items())}
                        for direction, rungs in sorted(self.ladders.items())
                    },
                },
                indent=2,
            )
            + "\n"
        )

    def mismatch(self) -> str | None:
        """Why this baseline does not describe the machine running now, or ``None``.

        A sentence rather than a boolean, and the lane prints it. A gate that cannot run must
        say so in the words that would make it run -- the alternative is a lane reporting clean
        because it looked at nothing, which is the failure three cards in this repository are
        named for.
        """
        machine, running = platform.machine(), platform.python_version()
        if machine != self.architecture:
            return (
                f"baseline was taken on {self.architecture} and this is {machine}; instruction "
                f"counts do not cross instruction sets"
            )
        if running != self.python:
            return (
                f"baseline was taken on CPython {self.python} and this is {running}; a patch "
                f"release moves every count here"
            )
        return None

    def drifts(self, ladder: InstructionLadder, *, band: float) -> tuple[Drift, ...]:
        """Every rung whose cost left ``band`` of the baseline, in either direction.

        Args:
            ladder: A measured ladder.
            band: Fractional tolerance. ``0.02`` allows two percent either way.

        Returns:
            One :class:`Drift` per rung outside the band, including the ones that got
            *cheaper*: an improvement is not a failure, but a baseline that quietly stays
            pessimistic is a gate that stops being able to see the next regression. The caller
            decides which half fails; :attr:`Drift.costlier` is how it tells them apart.

            A rung with no counterpart in the baseline is skipped here and reported by
            :meth:`unknown_rungs`, so a ladder that grew a rung is a stated gap rather than a
            silent pass.
        """
        expected = self.ladders.get(ladder.direction, {})
        return tuple(
            Drift(direction=ladder.direction, rung=rung, expected=expected[rung.size_bytes])
            for rung in ladder.rungs
            if rung.size_bytes in expected
            and abs(rung.instructions / expected[rung.size_bytes] - 1.0) > band
        )

    def unknown_rungs(self, ladder: InstructionLadder) -> tuple[int, ...]:
        """Sizes in ``ladder`` this baseline says nothing about, ascending."""
        expected = self.ladders.get(ladder.direction, {})
        return tuple(rung.size_bytes for rung in ladder.rungs if rung.size_bytes not in expected)


WORKLOAD = '''\
"""Generated by benchmarks/_instructions.py. One transfer, or none, then exit."""

import sys
from pathlib import Path

import anyio

from gantry_sftp.session import Publish, open_session
from gantry_sftp.transport import open_local_server_transport


async def main() -> None:
    async with open_local_server_transport(cwd={cwd!r}) as transport:
        async with open_session(transport) as sftp:
            {body}


anyio.run(main)
'''

BODIES = {
    "control": "pass",
    DOWNLOAD: 'await sftp.get({source!r}, Path({cwd!r}) / "received.bin")',
    UPLOAD: (
        "await sftp.put("
        'Path({cwd!r}) / {source!r}, "sent.bin", '
        "publish=Publish(atomic=False, fsync=False))"
    ),
}
"""What each workload does inside an open session.

The control opens the session and closes it, so subtracting it removes the interpreter, the
imports, the ``sftp-server`` handshake and the session teardown -- everything except the
transfer and the three metadata round trips a transfer makes. Those stay in, deliberately: they
are a fixed cost per transfer, they cancel in every :class:`Step`, and hiding them would make
the absolute figure describe a call nobody makes.

The upload uses ``atomic=False, fsync=False`` for the same reason the wall-clock lane's upload
row does -- it is the work the comparison libraries do, and what our default publish costs is a
separate question with a separate row.
"""


def valgrind_unavailable_reason() -> str | None:
    """Why this lane cannot run here, or ``None``.

    Returns:
        A sentence naming what to install. Cachegrind rather than the article's
        ``py-perf-event``: ``perf_event_open`` needs a privilege this project's container does
        not have -- the same reason ``tc`` goes through sudo -- while cachegrind is userspace
        simulation and needs none.
    """
    if shutil.which("valgrind") is None:
        return "valgrind is not installed (apt-get install valgrind); cachegrind is in it"
    return None


def workload_source(kind: str, *, cwd: Path, source: str) -> str:
    """The script one measured run executes.

    Args:
        kind: ``"control"``, ``"download"`` or ``"upload"``.
        cwd: Directory the child runs in, which is also the server's root.
        source: File the transfer moves, relative to ``cwd``.

    Returns:
        Python source. Written to a file rather than passed to ``-c`` because an argv of
        several hundred bytes changes the child's initial stack layout, and the whole premise
        here is that two runs differ only in the thing under test.

    Raises:
        KeyError: If ``kind`` is not one of the three.
    """
    return WORKLOAD.format(cwd=str(cwd), body=BODIES[kind].format(cwd=str(cwd), source=source))


def measure(source: str, *, cwd: Path, python: str | None = None) -> int:
    """Instructions retired by one run of ``source`` under cachegrind.

    Args:
        source: Script to run.
        cwd: Where to write it and run it.
        python: Interpreter to measure. Defaults to the one running this.

    Returns:
        The ``I refs`` total, including interpreter startup. Subtract a control.

    Raises:
        RuntimeError: If the child failed, or if cachegrind printed no summary -- both are
            "the measurement did not happen", and returning a number for either would be worse
            than raising.
    """
    script = cwd / "workload.py"
    script.write_text(source)
    result = subprocess.run(
        [
            "valgrind",
            "--tool=cachegrind",
            "--cache-sim=no",
            "--branch-sim=no",
            f"--cachegrind-out-file={cwd / 'cachegrind.out'}",
            python or sys.executable,
            str(script),
        ],
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
        # Replaced rather than layered. The child's environment is part of what is being held
        # still: PYTHONHASHSEED pins the dict ordering that made an unpinned run vary by 0.1%,
        # and a developer's exported variables change the initial stack size and with it the
        # count. PATH and HOME are what `sftp-server` and the interpreter need to start.
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "PYTHONHASHSEED": "0",
        },
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"the measured child exited {result.returncode}:\n{result.stderr[-2000:]}"
        )
    found = I_REFS.search(result.stderr)
    if found is None:
        raise RuntimeError(f"cachegrind printed no instruction count:\n{result.stderr[-2000:]}")
    return int(found.group(1).replace(",", ""))


def measure_all(source: str, *, cwd: Path, samples: int) -> tuple[int, ...]:
    """Every count from ``samples`` runs of ``source``, in the order they were taken.

    Kept rather than summarised so the caller can report the instrument's own precision beside
    its verdict -- the same reason :class:`SizePoint` keeps its wall times. A gate that prints
    one number cannot be checked for whether that number means anything.

    Args:
        source: Script to run.
        cwd: Where to write it and run it.
        samples: Runs to take. At least one.

    Returns:
        The counts.

    Raises:
        ValueError: If ``samples`` is below 1, which would make :func:`measure_least` a
            minimum over nothing.
    """
    if samples < 1:
        raise ValueError(f"samples must be at least 1, got {samples}")
    return tuple(measure(source, cwd=cwd) for _ in range(samples))


def measure_least(source: str, *, cwd: Path, samples: int) -> int:
    """The cheapest of ``samples`` runs of ``source``.

    **The minimum rather than the median, and what it does and does not buy was measured.** With
    the hash seed pinned a pure-compute workload is bit-identical, so everything left is the
    operating system's choice of how much of the stream each ``read`` returns, and fewer larger
    reads is less work for the same bytes. That makes the cheapest run the one closest to the
    code's own cost.

    **It does not converge the way a floor-plus-noise distribution would, and assuming it did
    was wrong twice in one afternoon.** A 24-run pool of one 16 MiB download spanned 2.6%, and
    the minimum of six runs was no tighter than the minimum of three (1.020 against 1.021); only
    at twelve did it reach 1.001, on two groups. So the distribution is broad rather than a hard
    floor with occasional spikes, three samples is where the cost stops buying precision, and
    the *band* is what has to absorb the rest. Two earlier estimates of that band -- 3% from a
    single pair of runs, then 2% from a lucky one -- were both the instrument being measured
    with too few samples to see itself.

    Args:
        source: Script to run.
        cwd: Where to write it and run it.
        samples: Runs to take. At least one.

    Returns:
        The smallest instruction count seen.

    Raises:
        ValueError: If ``samples`` is below 1.
    """
    return min(measure_all(source, cwd=cwd, samples=samples))


LADDER_HEADER = (
    "| size | net instructions | per MiB | marginal/MiB | vs baseline |\n"
    "| ---- | ---------------- | ------- | ------------ | ----------- |"
)


def _marginal_cell(ladder: InstructionLadder, index: int) -> str:
    if index == 0:
        return "--"
    step = Step(smaller=ladder.rungs[index - 1], larger=ladder.rungs[index])
    return f"{step.instructions_per_mib:,.0f}"


def _baseline_cell(baseline: Baseline | None, direction: str, rung: Rung) -> str:
    if baseline is None:
        return "--"
    expected = baseline.ladders.get(direction, {}).get(rung.size_bytes)
    if expected is None:
        return "not in baseline"
    return f"{rung.instructions / expected:.3f}x"


def render_ladder(ladder: InstructionLadder, *, baseline: Baseline | None) -> str:
    """One markdown table for one direction.

    Args:
        ladder: The measured ladder.
        baseline: The committed counts, or ``None`` when none applies here -- in which case the
            column reads ``--`` rather than being dropped, so a reader can tell a run with no
            baseline from a run that matched one.

    Returns:
        A markdown fragment: heading, table, and the control it is net of.
    """
    rows = "\n".join(
        f"| {rung.mib:.0f} MiB | {rung.instructions:,} | {rung.instructions_per_mib:,.0f} "
        f"| {_marginal_cell(ladder, index)} "
        f"| {_baseline_cell(baseline, ladder.direction, rung)} |"
        for index, rung in enumerate(ladder.rungs)
    )
    return (
        f"#### {ladder.direction}\n\n{LADDER_HEADER}\n{rows}\n\n"
        f"Net of a {ladder.control:,}-instruction control: the same session opened and closed, "
        f"moving no bytes.\n"
    )

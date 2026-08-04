"""What a transfer costs in memory, measured rather than derived from the constants.

`docs/tuning.md` states the bound as an expression -- ``concurrent transfers x depth x request
size``, about 16 MiB per transfer at the shipped defaults -- and says the load-bearing half out
loud: it is **independent of the file's size in both directions**. `tests/test_packaging.py`
checks that the sentence agrees with ``DEFAULT_PIPELINE_DEPTH`` and ``PREFERRED_READ_LENGTH``,
which is arithmetic over the documented values. Nothing measured a transfer (D-138).

Two things about the instrument, both of which cost a wrong answer before they were understood.

**``getrusage`` is the wrong counter here, and it fails silently.** ``ru_maxrss`` came back
byte-identical in every child of one harness -- at the *parent's* peak, because ``subprocess``
reaches the child through ``posix_spawn``, whose ``vfork`` window shares the parent's address
space, and the high-water mark recorded there survives the ``execve``. A harness that builds its
payloads in-process therefore poisons every rung by the same amount, which is what makes the
result look consistent. The first pass with it reported peak memory growing 1:1 with the file in
both directions, byte-identical between them -- indistinguishable from this library buffering
whole files, and entirely the measurement. ``VmHWM`` in ``/proc/self/status`` is read from the
new ``mm`` and is right.

**One process per rung is not optional.** ``VmHWM`` is a high-water mark, so a second transfer in
the same process can only ever report the first one's peak: a ladder measured in one process is a
test that cannot fail, whatever the code does.
"""

from __future__ import annotations

import platform
import subprocess
import sys
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from _instructions import BODIES, MIB, WORKLOAD

KIB = 1024

PEAK_LINE = "VmHWM:"
"""The peak resident set a process has reached, in ``/proc/self/status``."""

REPORT_PEAK = """
from pathlib import Path as _status_path

_lines = _status_path("/proc/self/status").read_text().splitlines()
print("PEAK_KIB", next(l.split()[1] for l in _lines if l.startswith("VmHWM:")))
"""
"""Appended to a workload so the child reports its own peak on the way out.

Read after the session has closed, deliberately: the number wanted is the high-water mark of the
whole operation, and a reading taken mid-transfer would be a race with the scheduler rather than
a measurement of it.
"""


def peak_unavailable_reason() -> str | None:
    """Why peak memory cannot be measured here, or ``None``.

    Returns:
        A sentence naming what is missing. Linux only, and stated rather than worked around:
        ``getrusage`` is not a portable fallback for this, it is a *different quantity* that
        reports the parent's peak through ``posix_spawn`` -- see the module docstring. A gate
        that silently swapped to it would report a number that has nothing to do with the code.
    """
    if platform.system() != "Linux":
        return (
            f"peak memory is read from /proc/self/status, which {platform.system()} does not "
            f"have; getrusage is not a substitute (it reports the parent's peak across "
            f"posix_spawn)"
        )
    if not Path("/proc/self/status").exists():
        return "/proc is not mounted, so there is nowhere to read a peak resident set from"
    return None


@dataclass(frozen=True, slots=True)
class MemoryRung:
    """One transfer size and the peak resident set the process reached moving it.

    Attributes:
        size_bytes: Bytes moved.
        peak_kib: ``VmHWM`` after the session closed, in kibibytes as ``/proc`` reports it.
    """

    size_bytes: int
    peak_kib: int

    def __post_init__(self) -> None:
        if self.size_bytes <= 0:
            raise ValueError(f"a rung must move bytes, got {self.size_bytes}")
        if self.peak_kib <= 0:
            raise ValueError(
                f"{self.size_bytes} bytes peaked at {self.peak_kib} KiB; a process that reached "
                f"no resident set was not measured"
            )

    @property
    def mib(self) -> float:
        return self.size_bytes / MIB


@dataclass(frozen=True, slots=True)
class Growth:
    """A rung whose peak rose against a smaller one, beyond what the bound allows."""

    rung: MemoryRung
    reference: MemoryRung

    @property
    def ratio(self) -> float:
        return self.rung.peak_kib / self.reference.peak_kib

    def describe(self) -> str:
        return (
            f"{self.rung.mib:.0f} MiB peaked at {self.rung.peak_kib:,} KiB, {self.ratio:.2f}x the "
            f"{self.reference.peak_kib:,} KiB reached at {self.reference.mib:.0f} MiB"
        )


@dataclass(frozen=True, slots=True)
class MemoryLadder:
    """Peak resident set against transfer size, for one direction.

    The claim under test is that this is a *flat line*. It is the only ladder in this directory
    whose interesting result is no slope at all -- the instruction ladder's rungs are expected to
    rise with the bytes and only their *marginal* is flat, whereas a bounded buffer means the
    whole curve stays put however large the file gets.

    Attributes:
        direction: ``"download"`` or ``"upload"``.
        control: Peak for the same session opened and closed, moving no bytes.
        rungs: Ascending by size.
    """

    direction: str
    control: int
    rungs: tuple[MemoryRung, ...]

    def __post_init__(self) -> None:
        if self.control <= 0:
            raise ValueError(f"the control peaked at {self.control} KiB; nothing was measured")
        if len(self.rungs) < 2:
            raise ValueError(f"{self.direction} has no shape: {len(self.rungs)} rung")
        sizes = [rung.size_bytes for rung in self.rungs]
        if sizes != sorted(set(sizes)):
            raise ValueError(f"{self.direction} rungs are not strictly ascending")

    @property
    def widest_span(self) -> float:
        """Largest peak over smallest, across the whole ladder.

        The run's own precision, reported beside the verdict for the reason the instruction
        lane reports its spread: a tolerance is only meaningful while the noise under it is
        smaller, and the way that stops being true is quietly.
        """
        peaks = [rung.peak_kib for rung in self.rungs]
        return max(peaks) / min(peaks)

    def over_control_kib(self) -> int:
        """The most any rung cost above an empty session.

        What the documented expression bounds. Above the control rather than in absolute terms,
        because the control is the interpreter, the imports and one open session -- none of which
        is what ``depth x request size`` is about.
        """
        return max(rung.peak_kib - self.control for rung in self.rungs)

    def growth(self, *, tolerance: float) -> tuple[Growth, ...]:
        """Every rung whose peak rose above ``tolerance`` x a smaller rung's.

        Args:
            tolerance: Ratio a rung may reach against any smaller rung before it counts.

        Returns:
            One :class:`Growth` per offending rung, ascending. Empty is the result the claim
            predicts: a bounded buffer does not grow with the file.

        Raises:
            ValueError: If ``tolerance`` is below 1.0, which would fail a ladder for using
                *less* memory as the file grows.
        """
        if tolerance < 1.0:
            raise ValueError(f"tolerance is a ratio at or above 1.0, got {tolerance}")
        found = []
        for index, rung in enumerate(self.rungs[1:], start=1):
            # The *smallest* peak below, not the rung before: one rung that happened to allocate
            # early must not become the allowance every later rung is measured against.
            reference = min(self.rungs[:index], key=lambda r: r.peak_kib)
            if rung.peak_kib > tolerance * reference.peak_kib:
                found.append(Growth(rung=rung, reference=reference))
        return tuple(found)

    def steepest_step(self) -> float:
        """Largest peak ratio between adjacent rungs, for the report's shape column."""
        return max(
            (larger.peak_kib / smaller.peak_kib for smaller, larger in pairwise(self.rungs)),
            default=1.0,
        )


def workload_source(kind: str, *, cwd: Path, source: str) -> str:
    """The script one measured run executes, ending in a peak-memory report.

    Shares :data:`_instructions.BODIES` with the instruction lane rather than restating the three
    workloads, so the two lanes cannot drift into measuring different operations and calling them
    by the same name.

    Args:
        kind: ``"control"``, ``"download"`` or ``"upload"``.
        cwd: Directory the child runs in, which is also the server's root.
        source: File the transfer moves, relative to ``cwd``.

    Returns:
        Python source.

    Raises:
        KeyError: If ``kind`` is not one of the three.
    """
    body = WORKLOAD.format(cwd=str(cwd), body=BODIES[kind].format(cwd=str(cwd), source=source))
    return body + REPORT_PEAK


def measure_peak(source: str, *, cwd: Path, python: str | None = None) -> int:
    """Peak resident set of one run of ``source``, in kibibytes.

    Args:
        source: Script to run.
        cwd: Where to write it and run it.
        python: Interpreter to measure. Defaults to the one running this.

    Returns:
        ``VmHWM`` as the child reported it about itself.

    Raises:
        RuntimeError: If the child failed, or printed no peak. Both are "the measurement did not
            happen", and a number returned for either would be worse than an exception.
    """
    script = cwd / "peak-workload.py"
    script.write_text(source)
    result = subprocess.run(
        [python or sys.executable, str(script)],
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"the measured child exited {result.returncode}:\n{result.stderr[-2000:]}"
        )
    for line in result.stdout.splitlines():
        if line.startswith("PEAK_KIB "):
            return int(line.split()[1])
    raise RuntimeError(f"the child reported no peak:\n{result.stdout[-2000:]}")


MEMORY_HEADER = (
    "| size | peak KiB | over control KiB | vs smallest rung |\n"
    "| ---- | -------- | ---------------- | ---------------- |"
)


def render_memory(ladder: MemoryLadder, *, bound_bytes: int) -> str:
    """One markdown table for one direction.

    Args:
        ladder: The measured ladder.
        bound_bytes: The documented per-transfer bound, so the table carries what it is being
            read against rather than leaving a reader to look it up.

    Returns:
        A markdown fragment: heading, table, and what the numbers are net of.
    """
    smallest = min(rung.peak_kib for rung in ladder.rungs)
    rows = "\n".join(
        f"| {rung.mib:.0f} MiB | {rung.peak_kib:,} | {rung.peak_kib - ladder.control:,} "
        f"| {rung.peak_kib / smallest:.3f}x |"
        for rung in ladder.rungs
    )
    return (
        f"#### {ladder.direction}\n\n{MEMORY_HEADER}\n{rows}\n\n"
        f"Control -- the same session opened and closed, moving no bytes -- peaked at "
        f"{ladder.control:,} KiB. The documented bound for one transfer is "
        f"{bound_bytes / MIB:.0f} MiB; the most any rung cost above the control was "
        f"{ladder.over_control_kib():,} KiB.\n"
    )

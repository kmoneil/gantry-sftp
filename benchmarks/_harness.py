"""Measuring a transfer honestly: what is timed, what is counted, and what neither can say.

This module is where every performance number this project has comes from -- none of which is
committed, since 0.11: a run writes the gitignored `_reports/benchmarks.md` (D-94). Until
it existed, no throughput number was allowed to appear in any document, and the rule it is
built to satisfy is the Docs Rule: *a number names the link profile, the server, and the
benchmark that produced it, or it is not stated.*

Three decisions shape everything here.

**Wall clock alone cannot see the thesis.** The claim is not "we move bytes faster than
`cryptography` can decrypt them" -- it is that the SSH work happens in OpenSSH rather than in
Python. On a link fast enough for that to matter, all three clients hit the *same* 2 MiB
channel window (measured for OpenSSH in DESIGN.md 5.1, and read off the source for the other
two: `paramiko.transport.DEFAULT_WINDOW_SIZE` and `asyncssh.connection._DEFAULT_WINDOW` are
both exactly 2 MiB) and finish in similar time. So **CPU seconds are measured beside the wall
clock**, because that is the axis the architecture actually moves.

**CPU is counted for the whole session, not the transfer, and that is forced rather than
chosen.** ``getrusage(RUSAGE_CHILDREN)`` only accounts for children that have been *waited
for*, so the ``ssh`` subprocess contributes nothing until it has exited and been reaped. There
is no way to sample it mid-transfer without reading ``/proc``, which would make the harness
Linux-only for a number that is still only an estimate. So the CPU window spans connect
through close, the ``connect`` scenario measures the connect half on its own, and a reader who
wants the transfer's share subtracts. Every client is measured the same way, which is what
makes the comparison fair even though the window is wider than the operation.

**A ratio is only stated when the samples do not overlap.** Repeats are few -- a 200 ms
profile is slow -- so a median difference between two clients can easily be noise wearing a
result's clothes. :class:`Comparison` carries ``separable``, and the renderer marks a ratio it
cannot stand behind rather than printing it with the same confidence as one it can.

**A size sweep is a different measurement and it drops the CPU column rather than faking
one.** :class:`SizeSweep` answers "does throughput ever *fall* as the file grows", which is
the shape people actually report against the incumbent -- a cliff at a byte count, not a
ratio (D-92). Two consequences follow. The whole ladder for one client and one direction runs
on **one connection**, because a fresh connection per size would time TCP slow start at the
small end and publish congestion control as a cliff (D-81); and one connection means one
reaped child, so per-sample CPU is not recoverable and is therefore not reported. Wall clock
is what the question is about.
"""

from __future__ import annotations

import platform
import resource
import statistics
import subprocess
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

MIB = 1024 * 1024


def own_cpu_seconds() -> float:
    """User + system CPU consumed by **this process alone**, in seconds.

    The counterpart of :func:`cpu_seconds`, and the two answer different questions. That one
    includes the children because the thesis is that the expensive work *relocated* into a C
    subprocess, and a counter blind to the child would report the relocation as free. This one
    excludes them because there is a second question the wide window cannot answer: what a
    *second* transport would cost us.

    More ``ssh`` children are more channels and more windows, but one process is one GIL, and
    every session's reader task, framing, decode and ``pwrite`` runs on it. So underneath the
    2 MiB channel window DESIGN.md 5.1 measured there is a second ceiling, it is a bandwidth
    number rather than a byte count, and it is this figure that sets it (D-113).

    Returns:
        Seconds of CPU, monotonically non-decreasing within a process.
    """
    mine = resource.getrusage(resource.RUSAGE_SELF)
    return mine.ru_utime + mine.ru_stime


def cpu_seconds() -> float:
    """User + system CPU consumed by this process and its reaped children, in seconds.

    The children half is what makes this the right measurement for this project: the whole
    thesis is that the expensive work happens in an ``ssh`` subprocess written in C, and a
    counter that only saw Python would report the thesis as free rather than as relocated.

    Returns:
        Seconds of CPU, monotonically non-decreasing within a process.
    """
    theirs = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own_cpu_seconds() + theirs.ru_utime + theirs.ru_stime


@dataclass(frozen=True, slots=True)
class Sample:
    """One run of one scenario by one client.

    Attributes:
        wall_seconds: Time for the operation under test, with the connection already open.
        cpu_seconds: CPU for the whole session -- connect, operation, close -- because the
            ``ssh`` child's usage only becomes visible once it is reaped. See the module
            docstring.
        own_cpu_seconds: The share of ``cpu_seconds`` spent in *this* process. Collected on
            every sample because it costs one ``getrusage`` call that was already being made,
            and reported by one scenario: for the two comparison libraries it is almost all of
            ``cpu_seconds``, and for this one it is the ceiling a second connection would run
            into. See :class:`CpuCeiling`.
    """

    wall_seconds: float
    cpu_seconds: float
    own_cpu_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class Measurement:
    """Repeated samples of one (scenario, client) pair, and what may be said about them."""

    scenario: str
    client: str
    bytes_moved: int
    samples: tuple[Sample, ...]

    def __post_init__(self) -> None:
        if not self.samples:
            raise ValueError(f"{self.client}/{self.scenario} has no samples")

    @property
    def wall_seconds(self) -> float:
        """Median wall time. Median rather than mean: one stalled run must not define it."""
        return statistics.median(s.wall_seconds for s in self.samples)

    @property
    def cpu_seconds(self) -> float:
        """Median session CPU."""
        return statistics.median(s.cpu_seconds for s in self.samples)

    @property
    def own_cpu_seconds(self) -> float:
        """Median CPU spent in this process, excluding the ``ssh`` child."""
        return statistics.median(s.own_cpu_seconds for s in self.samples)

    @property
    def fastest_wall_seconds(self) -> float:
        return min(s.wall_seconds for s in self.samples)

    @property
    def slowest_wall_seconds(self) -> float:
        return max(s.wall_seconds for s in self.samples)

    @property
    def spread(self) -> float:
        """Slowest run divided by fastest, as a run-to-run stability figure.

        Printed beside every row on purpose. A 1.02 says the median means something; a 1.9
        says the profile is noisy and the reader should distrust a 1.3x difference in it.
        """
        return self.slowest_wall_seconds / self.fastest_wall_seconds

    @property
    def throughput_mib_per_second(self) -> float:
        return (self.bytes_moved / MIB) / self.wall_seconds

    @property
    def cpu_seconds_per_mib(self) -> float:
        """Session CPU per MiB moved -- the axis on which the architecture differs.

        For a scenario that moves no bytes (``connect``) this is meaningless and the renderer
        omits it rather than dividing by zero.
        """
        return self.cpu_seconds / (self.bytes_moved / MIB) if self.bytes_moved else 0.0

    @property
    def mib_moved(self) -> float:
        return self.bytes_moved / MIB


@dataclass(frozen=True, slots=True)
class Comparison:
    """One client measured against a baseline, with an honest verdict on the difference."""

    scenario: str
    subject: Measurement
    baseline: Measurement

    @property
    def wall_ratio(self) -> float:
        """How many times faster the subject is than the baseline. Below 1.0 means slower."""
        return self.baseline.wall_seconds / self.subject.wall_seconds

    @property
    def cpu_ratio(self) -> float:
        """How many times less CPU the subject spent. Below 1.0 means more."""
        if self.subject.cpu_seconds == 0.0:
            return float("inf")
        return self.baseline.cpu_seconds / self.subject.cpu_seconds

    @property
    def separable(self) -> bool:
        """Whether the two clients' wall-clock sample ranges fail to overlap.

        The weakest claim worth making, and deliberately not a t-test: with three to five
        samples a significance test would be theatre. Non-overlapping ranges is something a
        reader can check by eye against the spread column, and it is the difference between
        "faster" and "measured faster".
        """
        return (
            self.subject.slowest_wall_seconds < self.baseline.fastest_wall_seconds
            or self.baseline.slowest_wall_seconds < self.subject.fastest_wall_seconds
        )


def size_label(size_bytes: int) -> str:
    """A byte count rendered the way the boundary it brackets is written.

    Exact division only, so ``261120`` reads as ``255 KiB`` and a size that is not a whole
    number of units keeps its byte count rather than being rounded into a lie.
    """
    for unit, name in ((MIB, "MiB"), (1024, "KiB")):
        if size_bytes >= unit and size_bytes % unit == 0:
            return f"{size_bytes // unit} {name}"
    return f"{size_bytes} B"


@dataclass(frozen=True, slots=True)
class SizePoint:
    """One file size, timed repeatedly on one already-warm connection.

    Attributes:
        size_bytes: Bytes moved by each timed transfer.
        note: What boundary this size brackets, printed beside the row so the table explains
            why the point exists rather than leaving a reader to recognise the number.
        wall_seconds: One entry per timed transfer. Kept rather than summarised, because the
            spread is what decides whether a fall in throughput is a cliff or noise.
    """

    size_bytes: int
    note: str
    wall_seconds: tuple[float, ...]

    def __post_init__(self) -> None:
        if self.size_bytes <= 0:
            raise ValueError(f"a size point must move bytes, got {self.size_bytes}")
        if not self.wall_seconds:
            raise ValueError(f"{size_label(self.size_bytes)} has no samples")
        if min(self.wall_seconds) <= 0.0:
            raise ValueError(f"{size_label(self.size_bytes)} has a non-positive wall time")

    @property
    def wall(self) -> float:
        """Median wall time. Median rather than mean: one stalled run must not define it."""
        return statistics.median(self.wall_seconds)

    @property
    def throughput_mib_per_second(self) -> float:
        return (self.size_bytes / MIB) / self.wall

    @property
    def best_throughput_mib_per_second(self) -> float:
        """Throughput of this size's *fastest* run -- its most flattering sample."""
        return (self.size_bytes / MIB) / min(self.wall_seconds)

    @property
    def worst_throughput_mib_per_second(self) -> float:
        """Throughput of this size's *slowest* run -- its least flattering sample."""
        return (self.size_bytes / MIB) / max(self.wall_seconds)

    @property
    def spread(self) -> float:
        return max(self.wall_seconds) / min(self.wall_seconds)


@dataclass(frozen=True, slots=True)
class Cliff:
    """A size whose throughput collapsed against a smaller one, beyond what noise explains.

    The two throughputs compared are deliberately the *unflattering* pair: this point's
    fastest run against the reference's slowest. A fall that survives that comparison cannot
    be the run-to-run variation, which is why :meth:`SizeSweep.cliffs` may be asserted on
    while the printed ratio beside a row may not.
    """

    point: SizePoint
    reference: SizePoint

    @property
    def ratio(self) -> float:
        """Median throughput here over median throughput at the reference size."""
        return self.point.throughput_mib_per_second / self.reference.throughput_mib_per_second

    def describe(self) -> str:
        return (
            f"{size_label(self.point.size_bytes)} runs at "
            f"{self.point.throughput_mib_per_second:.2f} MiB/s, {self.ratio:.2f}x the "
            f"{self.reference.throughput_mib_per_second:.2f} MiB/s measured at "
            f"{size_label(self.reference.size_bytes)}"
        )


def _fastest_below(points: Sequence[SizePoint], index: int) -> SizePoint | None:
    """The smaller size with the highest median throughput, or ``None`` for the first point."""
    smaller = points[:index]
    if not smaller:
        return None
    return max(smaller, key=lambda p: p.throughput_mib_per_second)


def _fell_below(point: SizePoint, reference: SizePoint, fraction: float) -> bool:
    """Whether this point's *fastest* run still came in under ``fraction`` of the reference's
    *slowest* -- that is, whether even its luckiest sample fell that far short.

    One predicate serves two questions. At ``fraction = 1.0`` it is separability -- the same
    non-overlapping-ranges test :attr:`Comparison.separable` applies to a cross-library ratio.
    Below 1.0 it is the cliff test, which is separability with a margin.
    """
    return (
        point.best_throughput_mib_per_second < fraction * reference.worst_throughput_mib_per_second
    )


@dataclass(frozen=True, slots=True)
class SizeSweep:
    """Throughput as a function of file size, for one client in one direction.

    The interesting output is not a number, it is the shape: throughput should rise as the
    per-transfer fixed cost is amortised and then plateau at whatever the link and the channel
    window allow. It must never fall.
    """

    scenario: str
    client: str
    points: tuple[SizePoint, ...]

    def __post_init__(self) -> None:
        if len(self.points) < 2:
            raise ValueError(
                f"{self.client}/{self.scenario} has no shape: {len(self.points)} point"
            )
        sizes = [p.size_bytes for p in self.points]
        if sizes != sorted(set(sizes)):
            raise ValueError(f"{self.client}/{self.scenario} sizes are not strictly ascending")

    def _falls(self, *, tolerance: float, separable: bool) -> tuple[Cliff, ...]:
        if not 0.0 < tolerance <= 1.0:
            raise ValueError(f"tolerance must be in (0, 1], got {tolerance}")
        found = []
        for index, point in enumerate(self.points):
            reference = _fastest_below(self.points, index)
            if reference is None:
                continue
            fell = (
                _fell_below(point, reference, tolerance)
                if separable
                else point.throughput_mib_per_second
                < tolerance * reference.throughput_mib_per_second
            )
            if fell:
                found.append(Cliff(point=point, reference=reference))
        return tuple(found)

    def cliffs(self, *, tolerance: float) -> tuple[Cliff, ...]:
        """Every size whose throughput fell below ``tolerance`` x the best measured below it,
        by a margin the run's own samples separate.

        The strict half of the pair, and the only one worth asserting on: it compares this
        size's *fastest* run against the reference's *slowest*, so a fall it reports cannot be
        the run-to-run variation. It is a subset of :meth:`dips` by construction.

        Args:
            tolerance: Fraction of the best smaller throughput a point may fall to before it
                counts as a cliff. ``0.5`` means a halving.

        Returns:
            One :class:`Cliff` per offending size, in ascending size order. Empty is the
            result this suite exists to keep true.
        """
        return self._falls(tolerance=tolerance, separable=True)

    def dips(self, *, tolerance: float) -> tuple[Cliff, ...]:
        """The same fall measured on medians alone, without the separability requirement.

        The loose half, for the curves that are **reported rather than asserted** -- the
        control libraries. A bimodal stall is exactly what an incumbent's size cliff looks like
        in a small sample (paramiko's 32 KiB upload came out with a spread of 44 on the first
        run of this sweep), and a stall whose fast mode is still fast will never satisfy
        :meth:`cliffs`. Refusing to *fail* on that is right; refusing to *mention* it would be
        throwing away the control's whole reason for existing.
        """
        return self._falls(tolerance=tolerance, separable=False)


def _shape(sweep: SizeSweep, index: int, *, tolerance: float) -> str:
    """The ``shape`` cell for one row: rising, dipping, or a cliff.

    Derived from the same two predicates :meth:`SizeSweep.cliffs` uses, so the word in the
    table and the assertion that fires can never disagree -- a report saying `rising` beside a
    failing run would be worse than no report.
    """
    point = sweep.points[index]
    reference = _fastest_below(sweep.points, index)
    if reference is None:
        return "--"
    ratio = point.throughput_mib_per_second / reference.throughput_mib_per_second
    if ratio >= 1.0:
        return "rising"
    if _fell_below(point, reference, tolerance):
        return f"**CLIFF** -- {ratio:.2f}x best below"
    # A fall the samples cannot separate is printed with the same marker a cross-library ratio
    # gets, and for the same reason: three repeats cannot tell a small dip from a busy machine.
    overlapping = "" if _fell_below(point, reference, 1.0) else " (overlapping)"
    return f"{ratio:.2f}x best below{overlapping}"


SWEEP_HEADER = (
    "| size | boundary | wall s | MiB/s | spread | shape |\n"
    "| ---- | -------- | ------ | ----- | ------ | ----- |"
)


def render_size_sweep(sweep: SizeSweep, *, tolerance: float) -> str:
    """One markdown table for one client's throughput-against-size curve.

    Args:
        sweep: The measured curve, ascending by size.
        tolerance: Passed through to the shape verdict, so the printed word and the gate's
            threshold are the same number.

    Returns:
        A markdown fragment: heading, table, and nothing else. No CPU column -- see the module
        docstring; a sweep runs on one connection and its child is reaped once.
    """
    rows = "\n".join(
        f"| {size_label(p.size_bytes)} | {p.note} | {p.wall:.4f} "
        f"| {p.throughput_mib_per_second:.2f} | {p.spread:.2f} "
        f"| {_shape(sweep, index, tolerance=tolerance)} |"
        for index, p in enumerate(sweep.points)
    )
    return f"#### {sweep.scenario} -- {sweep.client}\n\n{SWEEP_HEADER}\n{rows}\n"


def _command_output(argv: list[str]) -> str:
    """First line of a version command's output, or a note that it could not be read."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - environment
        return f"unavailable ({exc})"
    combined = (result.stdout + result.stderr).strip().splitlines()
    return combined[0] if combined else "unavailable (no output)"


@dataclass(frozen=True, slots=True)
class Environment:
    """Everything a number needs beside it before it may be quoted.

    A throughput figure without these is not a measurement, it is an anecdote: the same code
    on the same link reports different numbers on a different CPU, a different OpenSSH, or a
    different Python.
    """

    captured_at: str
    host_platform: str
    processor: str
    python: str
    ssh: str
    sftp_server: str
    library_versions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def capture(cls, *, sftp_server_path: str, library_versions: dict[str, str]) -> Environment:
        """Read the environment the run is about to happen in."""
        return cls(
            captured_at=datetime.now(tz=UTC).isoformat(timespec="seconds"),
            host_platform=platform.platform(),
            processor=platform.machine(),
            python=f"CPython {sys.version.split()[0]}",
            ssh=_command_output(["ssh", "-V"]),
            sftp_server=f"{sftp_server_path} ({_command_output(['sshd', '-V'])})",
            library_versions=dict(library_versions),
        )

    def lines(self) -> list[str]:
        versions = ", ".join(f"{name} {v}" for name, v in sorted(self.library_versions.items()))
        return [
            f"- **Captured:** {self.captured_at}",
            f"- **Host:** {self.host_platform} ({self.processor})",
            f"- **Python:** {self.python}",
            f"- **ssh:** {self.ssh}",
            f"- **Server:** {self.sftp_server}",
            f"- **Libraries:** {versions}",
        ]


async def take_samples(
    run_once: Callable[[], Awaitable[tuple[float, int]]],
    *,
    scenario: str,
    client: str,
    repeats: int,
    warmups: int = 1,
) -> Measurement:
    """Run one (scenario, client) pair repeatedly and collect its samples.

    Args:
        run_once: Opens a connection, times the operation, closes, and returns
            ``(operation_wall_seconds, bytes_moved)``. Closing inside this callable is not
            incidental -- the ``ssh`` child's CPU is invisible until it has been reaped.
        scenario: Name of the scenario, for the report.
        client: Name of the library, for the report.
        repeats: Samples to keep.
        warmups: Runs to discard first. One by default, because the first run of any client
            pays for imports, lazily-built cipher tables and a cold page cache on the source
            file, and attributing that to the library is a measurement of Python's importer.

    Returns:
        The measurement, carrying every kept sample rather than a summary, so the spread is
        recoverable and a ratio can be checked for separability.
    """
    for _ in range(warmups):
        await run_once()

    samples: list[Sample] = []
    moved = 0
    for _ in range(repeats):
        before, own_before = cpu_seconds(), own_cpu_seconds()
        wall, moved = await run_once()
        samples.append(
            Sample(
                wall_seconds=wall,
                cpu_seconds=cpu_seconds() - before,
                own_cpu_seconds=own_cpu_seconds() - own_before,
            )
        )
    return Measurement(scenario=scenario, client=client, bytes_moved=moved, samples=tuple(samples))


def _row(measurement: Measurement, baseline: Measurement | None) -> str:
    throughput = f"{measurement.throughput_mib_per_second:.1f}" if measurement.bytes_moved else "--"
    per_mib = f"{measurement.cpu_seconds_per_mib:.3f}" if measurement.bytes_moved else "--"
    if baseline is None:
        # No row to compare against. Saying "baseline" here would label every row as the
        # reference and quietly imply a comparison that was never made.
        verdict = "--"
    elif baseline is measurement:
        verdict = "baseline"
    else:
        comparison = Comparison(
            scenario=measurement.scenario, subject=measurement, baseline=baseline
        )
        mark = "" if comparison.separable else " (overlapping)"
        verdict = f"{comparison.wall_ratio:.2f}x wall, {comparison.cpu_ratio:.2f}x CPU{mark}"
    return (
        f"| {measurement.client} | {measurement.wall_seconds:.3f} | {throughput} "
        f"| {measurement.cpu_seconds:.3f} | {per_mib} | {measurement.spread:.2f} | {verdict} |"
    )


HEADER = (
    "| client | wall s | MiB/s | session CPU s | CPU s/MiB | spread | vs baseline |\n"
    "| ------ | ------ | ----- | ------------- | --------- | ------ | ----------- |"
)


@dataclass(frozen=True, slots=True)
class CpuCeiling:
    """What *this process's* own CPU would allow, for one direction, net of connecting.

    DESIGN.md 5.1 measured the ceiling above this one -- OpenSSH's 2 MiB channel window -- and
    concluded that the route past it is more transports or a native one. That conclusion is
    about the *link*, and it silently assumes the Python side scales alongside it. It does
    not: more ``ssh`` children are more channels and more windows, but one process is one GIL,
    and every session's reader task, framing, decode and ``pwrite`` runs on it. This is the
    second ceiling, and it is a bandwidth number rather than a byte count (D-113).

    **The connect measurement is subtracted rather than left to the reader**, which is the one
    place this departs from the module docstring's convention. That convention is right for the
    published matrix, where every client is measured the same wide way and a reader comparing
    two rows has the connect cost in both. Here the output is a *ceiling asserted against a
    plan*, so leaving a fixed cost in it would understate the ceiling by an amount that shrinks
    as the file grows -- which is the same mistake D-23 found the matrix making with TCP slow
    start, one layer down.

    Attributes:
        direction: ``"download"`` or ``"upload"``, for the report.
        transfer: The transfer, measured cold like every other row.
        connect: ``connect_and_close`` by the same client on the same link, moving no bytes.
    """

    direction: str
    transfer: Measurement
    connect: Measurement

    def __post_init__(self) -> None:
        if not self.transfer.bytes_moved:
            raise ValueError(f"{self.direction} moved no bytes; there is no ceiling to derive")
        if self.connect.bytes_moved:
            raise ValueError(
                f"the connect measurement moved {self.connect.bytes_moved} bytes; it is meant "
                f"to be the session lifecycle on its own"
            )

    @property
    def own_cpu_seconds(self) -> float:
        """Our CPU for the transfer alone, with the session lifecycle taken out.

        Floored at zero. The subtraction is of two medians from different sample sets, so on a
        profile where connecting costs about what the transfer does it can legitimately go
        negative -- and a negative CPU cost is a measurement artefact, not a finding.
        """
        return max(self.transfer.own_cpu_seconds - self.connect.own_cpu_seconds, 0.0)

    @property
    def own_cpu_seconds_per_mib(self) -> float:
        return self.own_cpu_seconds / self.transfer.mib_moved

    @property
    def ceiling_mib_per_second(self) -> float:
        """MiB/s this process could sustain if its own CPU were the only constraint.

        An **upper** bound and deliberately a generous one: it assumes a whole core available
        and perfect overlap with the ``ssh`` child, neither of which a real deployment gets. A
        route past the channel window that would need more than this does not have a link
        problem.

        Infinite when no CPU was measurable at all, which means the sample was too short to
        register against the clock tick. Reported as infinite rather than papered over, because
        a ceiling derived from an unmeasurable cost is not a ceiling.
        """
        per_mib = self.own_cpu_seconds_per_mib
        return 1.0 / per_mib if per_mib else float("inf")

    @property
    def headroom(self) -> float:
        """How many times the measured throughput would fit under the ceiling.

        The number the card is actually for. Large means the link is the constraint and Python
        is nowhere near it; near 1.0 means this process is the constraint and no amount of
        channel window would help.
        """
        return self.ceiling_mib_per_second / self.transfer.throughput_mib_per_second


CPU_CEILING_HEADER = (
    "| direction | our CPU s/MiB | implied ceiling MiB/s | measured MiB/s | headroom |\n"
    "| --------- | ------------- | --------------------- | -------------- | -------- |"
)


def render_cpu_ceiling(ceilings: Sequence[CpuCeiling]) -> str:
    """The second ceiling, per direction.

    A separate table from :func:`render_scenario` rather than two more columns on it, for the
    reason ``SizeSweep`` gets its own: this is not a comparison and it has no baseline. It is
    one client measured against a *constraint*, and rendering it beside "vs baseline" would
    invite exactly the reading it is not -- that ours is being scored against paramiko's Python
    CPU, which is a different and already-published row.
    """
    rows = "\n".join(
        f"| {c.direction} | {c.own_cpu_seconds_per_mib:.4f} "
        f"| {c.ceiling_mib_per_second:.0f} "
        f"| {c.transfer.throughput_mib_per_second:.1f} "
        f"| {c.headroom:.1f}x |"
        for c in ceilings
    )
    return (
        "#### our own CPU per byte, and the ceiling it implies\n\n"
        f"{CPU_CEILING_HEADER}\n{rows}\n\n"
        "Not a comparison, and not a throughput claim: it is the bound on **more transports**. "
        "One process is one GIL however many `ssh` children it spawns, so the route past the "
        "2 MiB channel window that DESIGN.md 5.1 names runs into this instead. The connect "
        "cost is subtracted; the ceiling assumes a whole core and perfect overlap with the "
        "child, so it is generous by construction. Headroom is how many times the measured "
        "rate fits under it (D-113).\n"
    )


def render_scenario(
    scenario: str, measurements: Sequence[Measurement], *, baseline_client: str
) -> str:
    """One markdown table for one scenario on one link profile.

    Args:
        scenario: Scenario name, used as the heading.
        measurements: One per client. Order is preserved, so the caller decides the reading
            order rather than the renderer sorting by result and flattering whoever won.
        baseline_client: Client every other row is expressed against. This is
            ``gantry-sftp``'s own row only when the point is to compare the others to it; the
            renderer does not assume it.

    Returns:
        A markdown fragment: heading, table, and nothing else.
    """
    baseline = next((m for m in measurements if m.client == baseline_client), None)
    rows = "\n".join(_row(m, baseline) for m in measurements)
    return f"#### {scenario}\n\n{HEADER}\n{rows}\n"


def render_report(
    *,
    title: str,
    environment: Environment,
    profile: str,
    sections: Sequence[str],
    caveats: Sequence[str],
) -> str:
    """A whole report: what was measured, on what, and what it does not say.

    ``caveats`` is not decoration and it is not optional. Every number here was produced on
    shaped *loopback*, by one server implementation, on one machine -- and a reader who takes
    a row as a general claim about SFTP has been misled by an omission rather than by a
    falsehood.
    """
    body = "\n".join(sections)
    notes = "\n".join(f"- {c}" for c in caveats)
    return (
        f"# {title}\n\n"
        f"{chr(10).join(environment.lines())}\n"
        f"- **Link:** {profile}\n\n"
        f"## Results\n\n{body}\n"
        f"## What these numbers do not say\n\n{notes}\n"
    )

"""Measuring a transfer honestly: what is timed, what is counted, and what neither can say.

This module is the source of truth for every performance claim this repository makes. Until
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


def cpu_seconds() -> float:
    """User + system CPU consumed by this process and its reaped children, in seconds.

    The children half is what makes this the right measurement for this project: the whole
    thesis is that the expensive work happens in an ``ssh`` subprocess written in C, and a
    counter that only saw Python would report the thesis as free rather than as relocated.

    Returns:
        Seconds of CPU, monotonically non-decreasing within a process.
    """
    mine = resource.getrusage(resource.RUSAGE_SELF)
    theirs = resource.getrusage(resource.RUSAGE_CHILDREN)
    return mine.ru_utime + mine.ru_stime + theirs.ru_utime + theirs.ru_stime


@dataclass(frozen=True, slots=True)
class Sample:
    """One run of one scenario by one client.

    Attributes:
        wall_seconds: Time for the operation under test, with the connection already open.
        cpu_seconds: CPU for the whole session -- connect, operation, close -- because the
            ``ssh`` child's usage only becomes visible once it is reaped. See the module
            docstring.
    """

    wall_seconds: float
    cpu_seconds: float


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
        before = cpu_seconds()
        wall, moved = await run_once()
        samples.append(Sample(wall_seconds=wall, cpu_seconds=cpu_seconds() - before))
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

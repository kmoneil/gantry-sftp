"""The benchmark matrix: three libraries, one server, five link profiles.

The scenario list is deliberately not counted here -- ``benchmarks/README.md`` has the table and
it grows; a number in this sentence would be a second place to update and the one nobody does.

This is a pytest module rather than a script on purpose. A benchmark that is not also a test
drifts until it measures something other than what it claims, and there is no assertion to
notice -- so every scenario here **verifies the bytes it moved** before its number is allowed
into the report. A client that returns fast and wrong must fail, not win. One scenario goes
further and asserts on its *result*: the size sweep fails a run whose throughput falls as the
file grows (D-92).

Run it explicitly; it is out of the default test run for the same reason ``live-tests/`` is::

    .venv/bin/pytest benchmarks/ -s

``-s`` because the report is printed as well as written. The written copy lands in
``_reports/``, which is gitignored: a generated table is evidence for a claim, not a source
file, and committing it would mean re-committing it on every run.

Every profile shapes loopback, so the whole matrix skips with a fix-it message on a machine
that cannot shape -- except the unshaped profile, which needs no ``tc`` at all and is the one
row that runs anywhere.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from _clients import BASELINE, Client, GantryClient, ParamikoClient, available, library_versions
from _harness import (
    CpuCeiling,
    Environment,
    Measurement,
    SizePoint,
    SizeSweep,
    render_cpu_ceiling,
    render_report,
    render_scenario,
    render_size_sweep,
    size_label,
    take_samples,
)
from sshd import SFTP_SERVER_CANDIDATES, SSHServer, first_existing

from conftest import Corpus, SweepFile

pytestmark = pytest.mark.anyio

REPEATS = 3
"""Samples kept per (scenario, client). Small because a 200 ms profile is slow, which is
exactly why :attr:`_harness.Measurement.spread` is printed beside every row and why a ratio
drawn from overlapping samples is marked rather than asserted."""

SMALL_FILE_CONCURRENCY = 8
"""Transfers in flight in the concurrent small-file row.

A number chosen for this bench and not a library default -- there isn't one, deliberately. It
is small enough to stay well inside OpenSSH's per-connection open-handle allowance and large
enough that the round trips it overlaps are visible on a 50 ms link.
"""

RTT_TOLERANCE = 0.35
"""How far the measured round trip may sit from the requested one before the run is refused.

Loose, because netem on loopback is approximate and the container is busy; but present,
because the report names a link profile and a report that names a link it did not get is
worse than no report.
"""

SWEEP_WARMUPS = 1
"""Transfers discarded before timing begins, per size, on that size's own connection.

One, and *of the same size as the rungs being timed*, which is the part that matters: D-81
found every published row was timing a connection's first transfer, and the small end of a
size ladder is where a fixed startup cost does the most damage. Warming with the same size
warms the congestion window in proportion to what the rung actually needs.
"""

CLIFF_TOLERANCE = 0.5
"""Fraction of the best throughput measured at any smaller size that a rung may fall to.

A halving, and it **gates** -- see the sweep scenario's docstring for why that does not
duplicate D-63. Set where a pathology lives rather than where noise does: the complaints this
sweep answers are a 99% collapse (`paramiko#2438`) and a 25x gap (`paramiko#2453`), while the
run-to-run spread on this lane sits near 1.1 and reaches 1.9 on the unshaped profile. The
tolerance is not what keeps noise out of the gate, though -- :func:`_harness._fell_below`
compares the rung's *fastest* run against the reference's *slowest*, so a fall the samples
cannot separate is printed and not failed.
"""


@dataclass(frozen=True, slots=True)
class Profile:
    """One link the whole matrix is measured on."""

    name: str
    rtt_ms: float | None = None
    rate_mbit: float | None = None
    small_files: int = 0
    """Files in each small-file scenario, or ``0`` to skip them on this profile.

    It scales down as latency rises because those scenarios cost several round trips *per
    file*: 200 files at 200 ms RTT is minutes per sample, and the shape of the result is
    already visible at 24. One count drives the download row, the upload row and the
    concurrency row, so the three stay comparable to each other on any given profile.
    """

    sweep_repeats: tuple[int, int] | None = None
    """Samples per sweep rung ``(below the 2 MiB channel window, at or above it)``, or ``None``
    not to sweep this profile at all (D-92).

    **Two profiles sweep, not five.** The sweep is ten sizes x two directions x every available
    client, so it costs about what the rest of a profile costs, and its answer is a *shape*
    which does not need five links to be visible. ``unshaped`` is in because it needs no ``tc``
    and is therefore what a plain checkout gets, and because a framing or per-packet cliff
    shows up with no latency at all. ``50ms`` is in because a *pipelining* cliff needs a link
    where a round trip costs something, and 50 ms is where this suite's other latency findings
    have been legible. 200 ms would triple the wall clock for the same curve.

    **Both halves are per profile because a rung costs two orders of magnitude more on one
    profile than another** -- roughly 2 ms unshaped against 220 ms at 50 ms RTT -- so one
    sample count cannot serve both. The unshaped profile needs the larger one and can afford
    it: three samples there reported 262144 bytes downloading at 0.47x the throughput of
    261120, which read as a cost for crossing from one request to two.
    ``_plans/probes/size_boundary_probe.py`` took that crossing 25 times and found the
    opposite -- a **one-byte** step from 261120 to 261121 *raises* the median from 2.41 ms to
    1.73 ms, because the second request pipelines behind the first and there is nothing for a
    single-request transfer to overlap a scheduler hiccup with. Its p90 is 7.1 ms against a
    1.7 ms floor: the fat tail is real, the fall was not, and a three-sample median lands
    anywhere in between. Nine samples still put it on the wrong rung; twenty-five settle it and
    cost under a second.
    """

    @property
    def sweeps(self) -> bool:
        return self.sweep_repeats is not None


PROFILES = (
    Profile(name="unshaped", small_files=200, sweep_repeats=(25, 9)),
    Profile(name="5ms", rtt_ms=5.0, small_files=100),
    Profile(name="50ms", rtt_ms=50.0, small_files=24, sweep_repeats=(9, 3)),
    Profile(name="200ms", rtt_ms=200.0),
    Profile(name="50ms-100mbit", rtt_ms=50.0, rate_mbit=100.0),
)

CAVEATS = (
    "Shaped **loopback**, not a network. There is no competing traffic, no middlebox, and no "
    "real bandwidth ceiling unless the profile names one.",
    "**One server implementation** -- OpenSSH's `sftp-server`. Nothing here says anything "
    "about SFTPGo, ProFTPD, MOVEit, GoAnywhere or an appliance; that is the server matrix's "
    "job and it does not exist yet.",
    "**One machine.** Wall clock on a latency-bound profile is mostly the link; CPU is mostly "
    "this CPU. Both ratios travel better than either absolute number.",
    "CPU is measured over **connect through close**, not over the transfer alone -- "
    "`getrusage(RUSAGE_CHILDREN)` cannot see the `ssh` child until it is reaped. The "
    "`connect` scenario measures that half on its own so it can be subtracted.",
    "The cross-library small-file scenarios are **sequential for all three clients**. This "
    "library can overlap files as of the multiplexing change, and so can the other two -- "
    "paramiko with a thread per transfer, asyncssh with a task group. Racing our concurrent "
    "path against their sequential one would measure a feature gap while looking like a speed "
    "gap, so the comparison rows stay sequential and the concurrency gain is measured "
    "separately, against ourselves.",
    "The small-file **upload** row is where a per-file cost is visible at all. Both 16 MiB "
    "upload rows move one file, so a round trip added to every `put` -- as the size check "
    "did -- rounds to nothing there. At 8 KiB the number is round trips, so that row is the "
    "one that can catch it.",
    "**Every cross-library row is a connection's first transfer.** Connections are not reused "
    "across samples, so the comparison rows all include TCP slow start -- fairly, since all "
    "three clients pay it, but it is not what a pipeline sustains once the congestion window "
    "is open. The `download 16 MiB, one connection` row measures that difference against "
    "ourselves (D-23), and its CPU column is **not** comparable with the cold row's: the "
    "session it is measured in also moved the discarded warmup transfer, so its `CPU s/MiB` "
    "counts roughly twice the bytes the row credits. Wall clock and MiB/s are what that row "
    "is for.",
    "The `concurrent` small-file row is **gantry-sftp against gantry-sftp**, like the atomic "
    "publish row: same files, same one connection, sequential versus overlapped. It is not a "
    "claim about the other two libraries.",
    "**The `our own CPU per byte` table runs on the unshaped profile only, and it is the one "
    "row that subtracts the connect cost** rather than leaving it for the reader. Both are "
    "the same decision: it derives a *ceiling* that unbuilt work gets ranked against, so a "
    "link constraint or a fixed per-session cost left inside it would understate the ceiling "
    "by an amount that changes with the file size. It is an upper bound and a generous one -- "
    "a whole core, perfect overlap with the `ssh` child -- and what it bounds is **more "
    "transports**, since one process is one GIL however many `ssh` children it spawns "
    "(D-113).",
    "Our upload row is `atomic=False, fsync=False`, which is the work the other two do. What "
    "our default costs is the separate `atomic publish` scenario.",
    "**The `throughput against size` sweeps are the one place a connection is reused, and "
    "their numbers are therefore not comparable with any table above them.** Each rung runs "
    "on its own connection with a same-size warmup discarded first, because a fresh "
    "connection per size would time TCP slow start at the small end and publish congestion "
    "control as a cliff (D-81). They carry no CPU column for the same reason: one connection "
    "is one reaped child, so per-sample CPU does not exist. The other two libraries are swept "
    "as **controls** -- reported, never asserted; an incumbent's pathology must not be able to "
    "fail this lane. Our own curve does gate, on shape rather than on any figure: a rung that "
    "falls below half the best throughput measured at a smaller size, by a margin its own "
    "samples separate, fails the run. Whether a *number* moving between runs should fail CI "
    "is still D-63's open question and this does not answer it.",
    "**Comparing the two small-file rows against each other measures two libraries' direction "
    "asymmetries at once, not one.** Each client has its own ratio between its `get` and its "
    "`put`, and a cross-library row cannot separate them -- D-72 was filed reading the "
    "unshaped download win and upload loss as a single fact about this library, and ranging "
    "each client against *itself* on the same corpus showed most of the swing was the "
    "control's: paramiko's small-file `get` runs several times its own `put`, which inflates "
    "our download row without saying anything about our scheduler. Re-derive both self-ratios "
    "before quoting either cross-library number as evidence about this library.",
)


@dataclass
class ReportSink:
    """Sections accumulated across profiles, written out once at the end of the session."""

    sections: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    """Findings a run produced that no table states in words -- a control's size cliff.

    They land in the report's caveats rather than in a table because they are claims about
    another library, and a claim about another library is only honest with its versions beside
    it, which is what the environment header carries.
    """

    @property
    def complete(self) -> bool:
        """Whether every profile in the matrix contributed a section."""
        return set(self.profiles) == {p.name for p in PROFILES}


@pytest.fixture(scope="session")
def report() -> ReportSink:
    return ReportSink()


@pytest.fixture(scope="session", autouse=True)
def _write_report(report: ReportSink) -> Iterator[None]:
    """Write the report at the end of the session -- to a different file if it is partial.

    A ``-k`` selection or a profile that skipped produces a report covering some of the matrix,
    and the first version of this overwrote the full one with it. That is worse than writing
    nothing: `benchmarks.md` is the artefact the README and DESIGN.md cite, and a five-minute
    ``-k unshaped`` run would silently replace every shaped number with the one profile that
    proves least. Partial runs land beside it under their own name, and every report names the
    profiles it actually contains.
    """
    yield
    if not report.sections:
        return
    sftp_server = first_existing(SFTP_SERVER_CANDIDATES) or "unknown"
    environment = Environment.capture(
        sftp_server_path=sftp_server, library_versions=library_versions()
    )
    ran = ", ".join(report.profiles)
    coverage = ran if report.complete else f"{ran} (PARTIAL -- the full matrix is {len(PROFILES)})"
    text = render_report(
        title="gantry-sftp benchmarks",
        environment=environment,
        profile=coverage,
        sections=report.sections,
        caveats=(*CAVEATS, *report.notes, *(f"Client skipped: {s}" for s in report.skipped)),
    )
    destination = Path(__file__).resolve().parent.parent / "_reports"
    destination.mkdir(exist_ok=True)
    out = destination / ("benchmarks.md" if report.complete else "benchmarks-partial.md")
    out.write_text(text)
    print(f"\n\n{text}\n\nwritten to {out}")


RunOnce = Callable[[], Awaitable[tuple[float, int]]]


async def _sweep(
    clients: Sequence[Client],
    *,
    scenario: str,
    make: Callable[[Client], RunOnce],
) -> list[Measurement]:
    """Measure one scenario across every available client, in a fixed order."""
    return [
        await take_samples(make(client), scenario=scenario, client=client.name, repeats=REPEATS)
        for client in clients
    ]


def _identical(produced: Path, expected: Path) -> bool:
    return produced.read_bytes() == expected.read_bytes()


def _hidden_names(directory: Path) -> list[str]:
    """Dot-prefixed entries in a directory. Synchronous, and called after the timed region."""
    return sorted(p.name for p in directory.iterdir() if p.name.startswith("."))


async def _scenario_connect(clients: Sequence[Client]) -> list[Measurement]:
    return await _sweep(
        clients, scenario="connect and close (no transfer)", make=lambda c: c.connect_and_close
    )


async def _scenario_download(
    clients: Sequence[Client], source: Path, workdir: Path
) -> list[Measurement]:
    def make(client: Client) -> RunOnce:
        destination = workdir / f"{client.name}-large.bin"
        return lambda: client.download(source, destination)

    measurements = await _sweep(clients, scenario="download 16 MiB", make=make)
    for client in clients:
        produced = workdir / f"{client.name}-large.bin"
        assert _identical(produced, source), f"{client.name} downloaded the wrong bytes"
    return measurements


async def _scenario_download_warm(
    clients: Sequence[Client], source: Path, workdir: Path
) -> list[Measurement]:
    """The 16 MiB download as a connection's first transfer and as its second (D-23).

    Us against us, like the atomic-publish and concurrency rows, and for a reason specific to
    this one: the cross-library rows open a fresh connection per sample on purpose, so *every*
    published number in this matrix times a transfer through TCP slow start. That keeps the
    comparison fair -- all three clients pay it -- but it means the matrix has never measured
    what this library's pipeline sustains once the congestion window is open, and D-23 was
    filed against the resulting figure: 40-50% of the 2 MiB channel window's implied ceiling,
    flat across a 40x range of RTT. Flat is the signature of a fixed number of round trips
    added to a transfer whose own cost is counted in round trips, which is what slow start is.

    So this row is the card's measurement, on the card's own scenario. The cold half is
    re-measured here rather than reused from the cross-library row above, for the same reason
    the concurrency row re-measures its sequential half: otherwise the two are comparable only
    if nothing about the link drifted in between.
    """
    gantry = next((c for c in clients if isinstance(c, GantryClient)), None)
    if gantry is None:  # pragma: no cover - gantry_sftp is always importable here
        return []
    cold = workdir / "gantry-cold.bin"
    warm = workdir / "gantry-warm.bin"
    scenario = "download 16 MiB, one connection"
    measurements = [
        await take_samples(
            lambda: gantry.download(source, cold),
            scenario=scenario,
            client="gantry-sftp (connection's first)",
            repeats=REPEATS,
        ),
        await take_samples(
            lambda: gantry.download_warm(source, warm),
            scenario=scenario,
            client="gantry-sftp (connection's second)",
            repeats=REPEATS,
        ),
    ]
    # Both halves verified. A warm path that returned early -- or reused a stale local file
    # from its own discarded warmup without re-fetching -- would report the speedup this row
    # exists to find, for work it did not do.
    for produced in (cold, warm):
        assert _identical(produced, source), f"{produced.name} holds the wrong bytes"
    return measurements


async def _scenario_upload(
    clients: Sequence[Client], source: Path, upload_dir: Path
) -> list[Measurement]:
    def make(client: Client) -> RunOnce:
        destination = upload_dir / f"{client.name}-up.bin"
        return lambda: client.upload(source, destination)

    measurements = await _sweep(clients, scenario="upload 16 MiB (in place)", make=make)
    for client in clients:
        produced = upload_dir / f"{client.name}-up.bin"
        assert _identical(produced, source), f"{client.name} uploaded the wrong bytes"
    return measurements


async def _scenario_cpu_ceiling(
    clients: Sequence[Client], profile: Profile, source: Path, upload_dir: Path, workdir: Path
) -> list[CpuCeiling]:
    """The second ceiling: what our own Python costs per byte, both directions (D-113).

    **Unshaped only, and that is the whole design of the row.** Every other profile puts a
    constraint between this process and the server, and a link constraint is exactly what this
    must not measure: on a 50 ms link the transfer is idle most of the time and the CPU per
    *byte* would come out the same while the CPU per *second* collapsed. The question is what
    this process can push when nothing else is stopping it, so it is asked on the one link that
    is not stopping anything.

    Us against a constraint rather than against another library. The comparison libraries'
    Python CPU is already published in every table's CPU column and is a different argument --
    that the work relocated. This one is about what a *second* transport would run into, and
    the answer is the same whether or not paramiko is installed.

    Both directions, because they are not symmetric: the download places payloads with
    ``os.pwrite`` and drops them, while the upload holds each ``WRITE`` with its payload in the
    codec's outstanding map until the reply. Same memory bound, two mechanisms -- and, it turns
    out, two different per-byte costs.
    """
    gantry = next((c for c in clients if isinstance(c, GantryClient)), None)
    # Two preconditions, one exit. The shaped half is taken on four of the five profiles and is
    # the row's whole design; the `gantry is None` half is unreachable in practice, since
    # gantry_sftp is always importable here, and is kept because the sequence is typed as
    # `Client` and a scenario that indexed into it blindly would fail confusingly.
    if gantry is None or profile.rtt_ms is not None:
        return []
    landed = workdir / "gantry-ceiling.bin"
    published = upload_dir / "gantry-ceiling-up.bin"
    scenario = "our own CPU per byte"

    # The subtrahend. Same client, same link, same sample count, moving no bytes -- so what it
    # measures is exactly the part of the transfer rows that is not the transfer.
    connect = await take_samples(
        gantry.connect_and_close,
        scenario=scenario,
        client="gantry-sftp (connect only)",
        repeats=REPEATS,
    )
    ceilings = [
        CpuCeiling(
            direction="download 16 MiB",
            transfer=await take_samples(
                lambda: gantry.download(source, landed),
                scenario=scenario,
                client="gantry-sftp (download)",
                repeats=REPEATS,
            ),
            connect=connect,
        ),
        CpuCeiling(
            direction="upload 16 MiB (in place)",
            transfer=await take_samples(
                lambda: gantry.upload(source, published),
                scenario=scenario,
                client="gantry-sftp (upload)",
                repeats=REPEATS,
            ),
            connect=connect,
        ),
    ]
    # Verified like every other row. A transfer that returned early would report a ceiling for
    # work it did not do, and a ceiling is the one output here that something else gets ranked
    # against.
    assert _identical(landed, source), "the download for the CPU row holds the wrong bytes"
    assert _identical(published, source), "the upload for the CPU row holds the wrong bytes"
    return ceilings


async def _scenario_small_files(
    clients: Sequence[Client], sources: Sequence[Path], workdir: Path, count: int
) -> list[Measurement]:
    chosen = list(sources[:count])

    def make(client: Client) -> RunOnce:
        into = workdir / f"{client.name}-small"
        into.mkdir(exist_ok=True)
        return lambda: client.download_many(chosen, into)

    scenario = f"download {count} x 8 KiB, sequential"
    measurements = await _sweep(clients, scenario=scenario, make=make)
    for client in clients:
        into = workdir / f"{client.name}-small"
        for source in chosen:
            assert _identical(into / source.name, source), (
                f"{client.name} downloaded {source.name} wrongly"
            )
    return measurements


async def _scenario_small_files_upload(
    clients: Sequence[Client], sources: Sequence[Path], upload_dir: Path, count: int
) -> list[Measurement]:
    """The mirror of the sequential download row, and the only row a per-file cost shows in.

    Added with D-69, after the size check gave every ``put`` an extra ``STAT`` and the matrix
    turned out to have no small-file upload to notice it with: every small-file row was a
    download, and both upload rows moved 16 MiB in a single file. Worth having on its own
    account too -- ``put_tree`` over a drop directory of small files is a headline workload
    that had no measurement behind it.
    """
    chosen = list(sources[:count])

    def make(client: Client) -> RunOnce:
        into = upload_dir / f"{client.name}-small-up"
        into.mkdir(exist_ok=True)
        return lambda: client.upload_many(chosen, into)

    scenario = f"upload {count} x 8 KiB, sequential"
    measurements = await _sweep(clients, scenario=scenario, make=make)
    for client in clients:
        into = upload_dir / f"{client.name}-small-up"
        for source in chosen:
            assert _identical(into / source.name, source), (
                f"{client.name} uploaded {source.name} wrongly"
            )
        # Per-client subdirectory, so no dot-prefixed staging file from one client can be
        # mistaken for another's -- and so the atomic row's `_hidden_names(upload_dir)` check
        # keeps meaning what it says. `atomic=False` should stage nothing; assert it does not,
        # because a leaked staging file here would inflate this row's time as well as litter.
        leftovers = _hidden_names(into)
        assert leftovers == [], f"{client.name} left staging files behind: {leftovers}"
    return measurements


async def _scenario_small_files_concurrent(
    clients: Sequence[Client], sources: Sequence[Path], workdir: Path, count: int
) -> list[Measurement]:
    """What multiplexing is worth on this link, measured against ourselves.

    Us against us, for the same reason the atomic-publish row is: the other two libraries can
    be driven concurrently as well, so a row pitting our task group against their `for` loop
    would be a feature gap dressed as a speed gap. The cross-library row above stays
    sequential and honest; this one answers the separate question of what the change bought.

    The sequential half is re-measured here rather than reused from that row, because the two
    would otherwise be comparable only if nothing about the link had drifted in between.
    """
    gantry = next((c for c in clients if isinstance(c, GantryClient)), None)
    if gantry is None:  # pragma: no cover - gantry_sftp is always importable here
        return []
    chosen = list(sources[:count])
    scenario = f"download {count} x 8 KiB, one connection"

    one_at_a_time = workdir / "gantry-seq"
    all_at_once = workdir / "gantry-conc"
    one_at_a_time.mkdir(exist_ok=True)
    all_at_once.mkdir(exist_ok=True)

    measurements = [
        await take_samples(
            lambda: gantry.download_many(chosen, one_at_a_time),
            scenario=scenario,
            client="gantry-sftp (sequential)",
            repeats=REPEATS,
        ),
        await take_samples(
            lambda: gantry.download_many_concurrently(
                chosen, all_at_once, concurrency=SMALL_FILE_CONCURRENCY
            ),
            scenario=scenario,
            client=f"gantry-sftp ({SMALL_FILE_CONCURRENCY} at once)",
            repeats=REPEATS,
        ),
    ]
    # Both halves verified, not just the interesting one. A concurrent path that quietly
    # dropped or interleaved bytes would report a speedup for work it did not do -- and
    # out-of-order reassembly across several transfers is exactly where that would happen.
    for into in (one_at_a_time, all_at_once):
        for source in chosen:
            assert _identical(into / source.name, source), (
                f"{into.name} produced the wrong bytes for {source.name}"
            )
    return measurements


async def _scenario_atomic(
    clients: Sequence[Client], source: Path, upload_dir: Path
) -> list[Measurement]:
    """What this library's own default publish costs, measured against its own in-place path.

    Not a comparison with the others: neither of them stages, flushes and renames, so there is
    nothing to compare against. It is here because a default whose cost is unmeasured is a
    default nobody can argue with.
    """
    gantry = next((c for c in clients if isinstance(c, GantryClient)), None)
    if gantry is None:  # pragma: no cover - gantry_sftp is always importable here
        return []
    in_place = upload_dir / "atomic-baseline.bin"
    published = upload_dir / "atomic-published.bin"
    measurements = [
        await take_samples(
            lambda: gantry.upload(source, in_place),
            scenario="atomic publish 16 MiB",
            client="gantry-sftp (in place)",
            repeats=REPEATS,
        ),
        await take_samples(
            lambda: gantry.upload_atomic(source, published),
            scenario="atomic publish 16 MiB",
            client="gantry-sftp (stage + fsync + rename)",
            repeats=REPEATS,
        ),
    ]
    # Both rows, not just the interesting one. An in-place baseline that quietly moved the
    # wrong bytes would make the atomic path look expensive for work it did not do.
    assert _identical(in_place, source), "the in-place upload produced the wrong bytes"
    assert _identical(published, source), "the atomic publish produced the wrong bytes"
    # The staging file is a hidden sibling and must not survive a successful publish -- litter
    # in a directory a consumer is polling is the failure atomic publish exists to prevent.
    leftovers = _hidden_names(upload_dir)
    assert leftovers == [], f"atomic publish left staging files behind: {leftovers}"
    return measurements


CHANNEL_WINDOW = 2 * 1024 * 1024
"""OpenSSH's `CHAN_SES_WINDOW_DEFAULT`, and paramiko's and asyncssh's, per DESIGN.md 5.1.

The line the two halves of :attr:`Profile.sweep_repeats` fall either side of, because it is
where a rung stops being a fixed cost and starts being bytes: below it a transfer fits in one
window and its wall clock is round trips, above it the window has to be refilled.
"""

FILE_OBJECT_BLOCKS: tuple[int, ...] = (261120, 1024 * 1024, CHANNEL_WINDOW)
"""Block sizes the file-object row reads with, and each one is a question.

261120 is exactly one request -- OpenSSH's `max-read-length`. 1 MiB is four requests, which is
half the channel window. `CHANNEL_WINDOW` is eight, which fills it. **The last entry is the one
that gates, and which entry that is was decided by the 50 ms profile rather than chosen.**

A `get` keeps its window full from the first request to the last. A `read(n)` fills the window,
drains it, and only then issues the next block, so a cursor read pays **one round trip per
block** -- `file_size / block_size` of them, and no block size removes it. Measured on a 50 ms
link: 0.36x of `get` at one request per block, 0.73x at 1 MiB, 0.81x at the window, where the
shortfall is eight blocks times one round trip and nothing else.

So the rule a caller acts on is "read in blocks of at least the channel window", and the gate
sits on that rung because it is the one where the remaining gap is structural rather than a
choice. Closing it entirely needs read-ahead, which is deliberately not built.
"""

SMALL_BLOCK = 8 * 1024
"""The block size a caller writes without thinking, measured on the **unshaped profile only**.

A cursor read cannot pipeline past the range it was asked for, so a loop of 8 KiB reads is one
round trip each -- and that is the cost worth publishing, because it is the difference between
`read(8192)` and `read(1 << 20)` on a link with any latency at all.

Unshaped only, and the reason is the finding itself: 16 MiB in 8 KiB blocks is 2048 round
trips, which at 50 ms RTT is a hundred seconds *per sample* -- twenty minutes of lane time to
re-measure something the unshaped row already shows at 0.1x. Bounding it is stated here rather
than silently, because a scenario that quietly skips a profile reads as one that passed it.
"""

FILE_OBJECT_FLOOR = 0.5
"""Fraction of our own `get` throughput the file object must reach at the largest block.

The acceptance criterion from D-91, as a number. It **gates**, and for the same reason the size
sweep does: it is a ratio between two rows of a *single run*, on one link, in one direction, so
it needs no committed baseline and is not the regression gate D-63 is about. What it catches is
the regression that matters -- a `read()` that stops pipelining is not 20% slower, it is one
round trip per block, and on any shaped profile that is an order of magnitude.
"""


async def _scenario_file_object(
    clients: Sequence[Client],
    source: Path,
    remote: Path,
    blocks: Sequence[int],
    *,
    control: bool,
) -> tuple[list[Measurement], list[str]]:
    """What reading through the file object costs against reading the whole file (D-86).

    Us against us for the row that gates, plus paramiko as a control. The control is the point
    of the exercise rather than decoration: `paramiko#2453` reports their `SFTPFile.read()` at
    25x their own `get`, and the obvious implementation of a byte-range read -- one `READ` per
    call, awaited -- reproduces it exactly. Having a file object was never the deliverable.

    Reported and never asserted for the control, asserted for ourselves, which is the same
    split the size sweep uses and for the same reason.

    **The control runs on the unshaped profile only, and the bound is a cost rather than a
    judgement.** paramiko's file object is round-trip-bound by construction, so at 50 ms RTT one
    16 MiB read is hundreds of round trips and four samples of it is minutes -- per block size,
    per profile. What it demonstrates it demonstrates unshaped, where it is already tens of
    times its own `get` with no latency to blame. Named here rather than left to a reader to
    notice a missing row, because a scenario that quietly drops a client reads as one that
    measured it.

    Returns:
        The measurements, and any failure lines. Failures are returned rather than raised so
        that one bad row still writes its table -- a gate that destroys the evidence for its
        own verdict is worse than no gate.
    """
    gantry = next((c for c in clients if isinstance(c, GantryClient)), None)
    if gantry is None:  # pragma: no cover - gantry_sftp is always importable here
        return [], []

    scenario = "read 16 MiB: file object vs whole file"
    baseline = await take_samples(
        lambda: gantry.download(remote, source.parent / "file-object-baseline.bin"),
        scenario=scenario,
        client="gantry-sftp (get)",
        repeats=REPEATS,
    )
    measurements = [baseline]
    wanted = (GantryClient, ParamikoClient) if control else (GantryClient,)
    for block in blocks:
        for client in clients:
            if not isinstance(client, wanted):
                continue
            measurements.append(
                await take_samples(
                    lambda c=client, b=block: c.read_in_blocks(remote, block_size=b),
                    scenario=scenario,
                    client=f"{client.name} (read {block // 1024} KiB blocks)",
                    repeats=REPEATS,
                )
            )

    largest = f"gantry-sftp (read {max(blocks) // 1024} KiB blocks)"
    ours = next((m for m in measurements if m.client == largest), None)
    failures = []
    if ours is not None and baseline.throughput_mib_per_second:
        fraction = ours.throughput_mib_per_second / baseline.throughput_mib_per_second
        if fraction < FILE_OBJECT_FLOOR:
            failures.append(
                f"the file object reached {fraction:.2f}x `get`'s throughput at "
                f"{max(blocks)}-byte blocks, below the {FILE_OBJECT_FLOOR}x floor: "
                f"a read that stopped pipelining costs one round trip per block (D-86)"
            )
    return measurements, failures


DOWNLOAD_SWEEP = "download: throughput against size"
UPLOAD_SWEEP = "upload: throughput against size"


def _repeats_for(size_bytes: int, repeats: tuple[int, int]) -> int:
    """Samples to keep for one rung -- see :attr:`Profile.sweep_repeats`."""
    below, at_or_above = repeats
    return below if size_bytes < CHANNEL_WINDOW else at_or_above


async def _download_sweep(
    client: Client, ladder: Sequence[SweepFile], workdir: Path, repeats: tuple[int, int]
) -> SizeSweep:
    into = workdir / f"sweep-{client.name}"
    into.mkdir(exist_ok=True)
    points = []
    for rung in ladder:
        destination = into / rung.path.name
        walls = await client.download_repeatedly(
            rung.path,
            destination,
            repeats=_repeats_for(rung.size_bytes, repeats),
            warmups=SWEEP_WARMUPS,
        )
        assert _identical(destination, rung.path), (
            f"{client.name} downloaded {size_label(rung.size_bytes)} wrongly"
        )
        points.append(
            SizePoint(size_bytes=rung.size_bytes, note=rung.note, wall_seconds=tuple(walls))
        )
    return SizeSweep(scenario=DOWNLOAD_SWEEP, client=client.name, points=tuple(points))


async def _upload_sweep(
    client: Client, ladder: Sequence[SweepFile], upload_dir: Path, repeats: tuple[int, int]
) -> SizeSweep:
    into = upload_dir / f"sweep-{client.name}"
    into.mkdir(exist_ok=True)
    points = []
    for rung in ladder:
        destination = into / rung.path.name
        walls = await client.upload_repeatedly(
            rung.path,
            destination,
            repeats=_repeats_for(rung.size_bytes, repeats),
            warmups=SWEEP_WARMUPS,
        )
        assert _identical(destination, rung.path), (
            f"{client.name} uploaded {size_label(rung.size_bytes)} wrongly"
        )
        points.append(
            SizePoint(size_bytes=rung.size_bytes, note=rung.note, wall_seconds=tuple(walls))
        )
    # Same check the small-file upload row makes: `atomic=False` must stage nothing, and a
    # staging file left behind would inflate the next rung's time as well as litter.
    leftovers = _hidden_names(into)
    assert leftovers == [], f"{client.name} left staging files behind: {leftovers}"
    return SizeSweep(scenario=UPLOAD_SWEEP, client=client.name, points=tuple(points))


async def _scenario_size_sweep(
    clients: Sequence[Client],
    ladder: Sequence[SweepFile],
    workdir: Path,
    upload_dir: Path,
    repeats: tuple[int, int],
) -> list[SizeSweep]:
    """Throughput against size, both directions, every available client (D-92).

    Three decisions, each one the card's and each one written down here because a later reader
    will otherwise read this as an ordinary parametrisation of the rows above.

    **It runs on one connection per rung, unlike every comparison row here.** That suspends
    this suite's no-connection-reuse rule deliberately and identically for all three clients:
    a fresh connection per size times TCP slow start at the small end (D-81), and a sweep
    looking for a cliff would have found congestion control and named it one. The consequence
    is that these numbers are **not** comparable with the fixed-size comparison tables above,
    which are all cold on purpose.

    **The other two libraries are swept as controls.** `paramiko#2438` reports a 99% collapse
    above 32675 bytes and `paramiko#2453` a 25x gap between two of its own APIs; the strongest
    form of "we have no cliff" is the same ladder showing their curve beside ours. It is
    reported and never asserted -- an incumbent's pathology must not be able to fail this
    lane. Both reproduce as of paramiko 5.0.0, `#2438` included and it is closed upstream: a
    ~40 ms stall floor at 32-64 KiB writes and at 128 KiB-1 MiB reads, intermittent rather than
    uniform, which is why the control's falls are read off :meth:`SizeSweep.dips`.

    **Our own curve gates, and that is not D-63's gate.** D-63 owns the missing *regression*
    gate, which needs a committed baseline to compare a run against and is blocked on not
    having one. This assertion needs no baseline and quotes no figure: it is internal to a
    single run, comparing rungs of one curve against each other, and it fails only when our
    throughput falls as the file grows by a margin the run's own samples can separate. Whether
    a *number* moving between runs should fail CI is still D-63's question.
    """
    sweeps = [await _download_sweep(client, ladder, workdir, repeats) for client in clients]
    return sweeps + [await _upload_sweep(client, ladder, upload_dir, repeats) for client in clients]


def _route_falls(sweeps: Sequence[SizeSweep], report: ReportSink, *, profile: str) -> list[str]:
    """Send each curve's falling rungs where they belong, and hand back the ones that fail.

    Two destinations, because the two kinds of curve carry different authority. A control's
    fall is a *finding* about another library: it goes into the report's caveats, is read off
    :meth:`SizeSweep.dips` because an incumbent's stall is bimodal and its fast mode would
    defeat the separability test, and it can never fail this lane. Ours is read off
    :meth:`SizeSweep.cliffs`, which is separable by construction, and it does.

    Args:
        sweeps: Every curve measured on this profile.
        report: Where a control's finding is recorded.
        profile: The profile's name, which goes into the note. Two profiles sweep, and a stall
            at 40 ms of fixed cost is a different claim at 0.2 ms per round trip than at 50 --
            an unattributed finding in a report covering both says neither.

    Returns:
        One entry per curve of *ours* that fell. Empty is the result the sweep exists to keep
        true.
    """
    ours = []
    for sweep in sweeps:
        if sweep.client != BASELINE:
            dips = [dip.describe() for dip in sweep.dips(tolerance=CLIFF_TOLERANCE)]
            if dips:
                report.notes.append(
                    f"Control finding on `{profile}` -- {sweep.client}, {sweep.scenario}: "
                    f"{'; '.join(dips)}"
                )
            continue
        cliffs = [cliff.describe() for cliff in sweep.cliffs(tolerance=CLIFF_TOLERANCE)]
        if cliffs:
            ours.append(f"{sweep.scenario}: {'; '.join(cliffs)}")
    return ours


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
async def test_benchmark_profile(
    profile: Profile,
    request: pytest.FixtureRequest,
    ssh_server: SSHServer,
    corpus: Corpus,
    tmp_path: Path,
    report: ReportSink,
) -> None:
    """Run every scenario for one link profile and append its tables to the report.

    ``shape_link`` is requested lazily so the unshaped profile runs on a machine with no
    ``tc`` at all. That is the row that makes this suite useful in a plain checkout, and
    making the whole module depend on netem would have thrown it away.
    """
    clients, skipped = available(ssh_server)
    report.skipped = skipped
    if len(clients) < 2:
        pytest.skip(f"fewer than two clients available: {', '.join(skipped)}")

    if profile.rtt_ms is None:
        description = "unshaped loopback (no netem qdisc)"
    else:
        link = request.getfixturevalue("shape_link")(
            rtt_ms=profile.rtt_ms, rate_mbit=profile.rate_mbit
        )
        drift = abs(link.measured_rtt_ms - profile.rtt_ms) / profile.rtt_ms
        assert drift < RTT_TOLERANCE, (
            f"asked for {profile.rtt_ms} ms RTT and measured {link.measured_rtt_ms:.1f} ms; "
            f"refusing to publish a number under a profile the link did not deliver"
        )
        description = link.describe()

    large, small = corpus.large, corpus.small
    upload_source, upload_dir = corpus.upload_source, corpus.upload_dir

    sections = [
        render_scenario(
            "connect and close (no transfer)",
            await _scenario_connect(clients),
            baseline_client=BASELINE,
        ),
        render_scenario(
            "download 16 MiB",
            await _scenario_download(clients, large, tmp_path),
            baseline_client=BASELINE,
        ),
        render_scenario(
            "upload 16 MiB (in place)",
            await _scenario_upload(clients, upload_source, upload_dir),
            baseline_client=BASELINE,
        ),
    ]
    warm = await _scenario_download_warm(clients, large, tmp_path)
    if warm:
        sections.append(
            render_scenario(
                "download 16 MiB, one connection",
                warm,
                baseline_client="gantry-sftp (connection's first)",
            )
        )
    shaped = profile.rtt_ms is not None
    blocks = FILE_OBJECT_BLOCKS if shaped else (SMALL_BLOCK, *FILE_OBJECT_BLOCKS)
    file_object, file_object_failures = await _scenario_file_object(
        clients, tmp_path, large, blocks, control=not shaped
    )
    if file_object:
        sections.append(
            render_scenario(
                "read 16 MiB: file object vs whole file",
                file_object,
                baseline_client="gantry-sftp (get)",
            )
        )
    if profile.small_files:
        sections.append(
            render_scenario(
                f"download {profile.small_files} x 8 KiB, sequential",
                await _scenario_small_files(clients, small, tmp_path, profile.small_files),
                baseline_client=BASELINE,
            )
        )
        sections.append(
            render_scenario(
                f"upload {profile.small_files} x 8 KiB, sequential",
                await _scenario_small_files_upload(clients, small, upload_dir, profile.small_files),
                baseline_client=BASELINE,
            )
        )
        overlapped = await _scenario_small_files_concurrent(
            clients, small, tmp_path, profile.small_files
        )
        if overlapped:
            sections.append(
                render_scenario(
                    f"download {profile.small_files} x 8 KiB, one connection",
                    overlapped,
                    baseline_client="gantry-sftp (sequential)",
                )
            )
    atomic = await _scenario_atomic(clients, upload_source, upload_dir)
    if atomic:
        sections.append(
            render_scenario(
                "atomic publish 16 MiB",
                atomic,
                baseline_client="gantry-sftp (in place)",
            )
        )
    # The unshaped-only gate lives in the scenario rather than here, like every other
    # precondition a scenario has about the link it needs.
    ceilings = await _scenario_cpu_ceiling(clients, profile, large, upload_dir, tmp_path)
    if ceilings:
        sections.append(render_cpu_ceiling(ceilings))

    sweeps: list[SizeSweep] = []
    if profile.sweep_repeats is not None:
        # Requested lazily like `shape_link`, so a selection that runs no sweep writes no
        # 27.8 MiB of ladder.
        ladder: Sequence[SweepFile] = request.getfixturevalue("sweep_corpus")
        sweeps = await _scenario_size_sweep(
            clients, ladder, tmp_path, upload_dir, profile.sweep_repeats
        )
        sections.extend(render_size_sweep(sweep, tolerance=CLIFF_TOLERANCE) for sweep in sweeps)

    report.sections.append(f"### Link: {description}\n\n" + "\n".join(sections))
    report.profiles.append(profile.name)

    # Asserted *after* the tables are in the report, not before. A cliff has to publish the
    # curve that proves it -- with the assertion first, the only evidence for a failure would
    # be its own message, and the section it belongs to would be missing from the report.
    assert not file_object_failures, (
        f"the file object did not keep up with `get` on {description} -- "
        f"{'  |  '.join(file_object_failures)}. The table is in the report."
    )

    ours = _route_falls(sweeps, report, profile=profile.name)
    assert not ours, (
        f"throughput fell as the file grew, on {description} -- "
        f"{'  |  '.join(ours)}. The curve is in the report; a rung that falls below "
        f"{CLIFF_TOLERANCE:.0%} of the best throughput measured at any smaller size, by a "
        f"margin its own samples separate, is the size cliff this sweep exists to refuse."
    )

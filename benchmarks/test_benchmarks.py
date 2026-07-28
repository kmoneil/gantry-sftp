"""The benchmark matrix: three libraries, six scenarios, five link profiles.

This is a pytest module rather than a script on purpose. A benchmark that is not also a test
drifts until it measures something other than what it claims, and there is no assertion to
notice -- so every scenario here **verifies the bytes it moved** before its number is allowed
into the report. A client that returns fast and wrong must fail, not win.

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
from _clients import BASELINE, Client, GantryClient, available, library_versions
from _harness import Environment, Measurement, render_report, render_scenario, take_samples
from sshd import SFTP_SERVER_CANDIDATES, SSHServer, first_existing

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


PROFILES = (
    Profile(name="unshaped", small_files=200),
    Profile(name="5ms", rtt_ms=5.0, small_files=100),
    Profile(name="50ms", rtt_ms=50.0, small_files=24),
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
    "The `concurrent` small-file row is **gantry-sftp against gantry-sftp**, like the atomic "
    "publish row: same files, same one connection, sequential versus overlapped. It is not a "
    "claim about the other two libraries.",
    "Our upload row is `atomic=False, fsync=False`, which is the work the other two do. What "
    "our default costs is the separate `atomic publish` scenario.",
)


@dataclass
class ReportSink:
    """Sections accumulated across profiles, written out once at the end of the session."""

    sections: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)

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
        caveats=(*CAVEATS, *(f"Client skipped: {s}" for s in report.skipped)),
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


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
async def test_benchmark_profile(
    profile: Profile,
    request: pytest.FixtureRequest,
    ssh_server: SSHServer,
    corpus: dict[str, object],
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

    large = corpus["large"]
    assert isinstance(large, Path)
    upload_source = corpus["upload_source"]
    assert isinstance(upload_source, Path)
    upload_dir = corpus["upload_dir"]
    assert isinstance(upload_dir, Path)
    small = corpus["small"]
    assert isinstance(small, list)

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

    report.sections.append(f"### Link: {description}\n\n" + "\n".join(sections))
    report.profiles.append(profile.name)

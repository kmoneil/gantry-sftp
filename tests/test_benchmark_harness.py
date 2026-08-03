"""The benchmark harness is code, so it is gated like code.

These live in ``tests/`` rather than in ``benchmarks/`` deliberately. The benchmark lane needs
a server and a shaped link and is therefore out of the default run -- but the arithmetic that
turns samples into a published ratio has no such requirement, and leaving it in the excluded
directory would mean the only thing standing behind every performance claim in this repository
was never checked by the gate that runs on every push.

The load-bearing test here is :func:`test_cpu_seconds_counts_a_reaped_childs_time`. The whole
CPU column rests on ``getrusage(RUSAGE_CHILDREN)`` seeing the ``ssh`` subprocess, and a counter
that silently returned only this process's time would not fail anything -- it would just
publish a number that says the thesis is free.
"""

from __future__ import annotations

import resource
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from hypothesis import given
from hypothesis import strategies as st

_ROOT = Path(__file__).resolve().parent.parent
_BENCHMARKS = _ROOT / "benchmarks"
# `live-tests/` too, because `_clients` imports `sshd` from it -- the server helper lives in a
# module rather than a conftest precisely so two suites can share it, and importing it starts
# nothing: it is stdlib-only and spawns `sshd` when a caller asks, not at import. Without this
# the `_clients` test below fails on `ModuleNotFoundError: sshd`, which reads like a missing
# dependency rather than a missing path entry.
for _extra in (_BENCHMARKS, _ROOT / "live-tests"):
    if str(_extra) not in sys.path:
        # Appended, not inserted. `benchmarks/` has its own `conftest.py`, and putting the
        # directory at the front of `sys.path` would let it win a name lookup against anything
        # the default run already imported. Nothing else is called `_harness`, so the end of the
        # path resolves it just as well and cannot shadow.
        sys.path.append(str(_extra))

import _harness  # noqa: E402  -- imported as a module so the clock can be monkeypatched
from _harness import (  # noqa: E402
    Comparison,
    CpuCeiling,
    Environment,
    Measurement,
    Sample,
    SizePoint,
    SizeSweep,
    _command_output,
    cpu_seconds,
    own_cpu_seconds,
    render_cpu_ceiling,
    render_report,
    render_scenario,
    render_size_sweep,
    size_label,
    take_samples,
)

BURN = "x = 0\nfor i in range(4_000_000):\n    x += i\n"
"""A child that spends CPU and does nothing else. Sized to be unmistakable, not precise."""


def burn_in_a_child() -> None:
    """Spend CPU in a subprocess and reap it, so ``RUSAGE_CHILDREN`` can account for it."""
    subprocess.run([sys.executable, "-c", BURN], check=True)


def measurement(
    client: str,
    walls: list[float],
    cpus: list[float],
    moved: int,
    own: list[float] | None = None,
) -> Measurement:
    mine = own if own is not None else cpus
    return Measurement(
        scenario="s",
        client=client,
        bytes_moved=moved,
        samples=tuple(
            Sample(wall_seconds=w, cpu_seconds=c, own_cpu_seconds=o)
            for w, c, o in zip(walls, cpus, mine, strict=True)
        ),
    )


def test_cpu_seconds_counts_a_reaped_childs_time():
    before_all = cpu_seconds()
    before_self = resource.getrusage(resource.RUSAGE_SELF)
    burn_in_a_child()
    after_self = resource.getrusage(resource.RUSAGE_SELF)
    after_all = cpu_seconds()

    combined = after_all - before_all
    self_only = (after_self.ru_utime + after_self.ru_stime) - (
        before_self.ru_utime + before_self.ru_stime
    )
    # The child did real work, and a SELF-only counter would have missed essentially all of
    # it. Asserting both halves is the point: the first alone would pass on a counter that
    # measured the parent's fork overhead and called it the child's transfer.
    assert combined > 0.05
    assert self_only < combined / 2


def test_a_measurement_with_no_samples_is_refused():
    with pytest.raises(ValueError) as exc:
        Measurement(scenario="s", client="c", bytes_moved=1, samples=())
    assert exc.value.args[0] == "c/s has no samples"


def test_the_median_is_used_so_one_stalled_run_does_not_define_the_result():
    m = measurement("c", [1.0, 1.1, 9.0], [0.1, 0.1, 0.1], moved=0)
    assert m.wall_seconds == 1.1
    assert m.fastest_wall_seconds == 1.0
    assert m.slowest_wall_seconds == 9.0
    assert m.spread == 9.0


def test_throughput_and_cpu_per_mib_are_derived_from_the_median():
    mib = 1024 * 1024
    m = measurement("c", [2.0, 2.0, 2.0], [4.0, 4.0, 4.0], moved=8 * mib)
    assert m.throughput_mib_per_second == 4.0
    assert m.cpu_seconds_per_mib == 0.5


def test_a_scenario_that_moves_no_bytes_does_not_divide_by_zero():
    m = measurement("c", [1.0], [1.0], moved=0)
    assert m.cpu_seconds_per_mib == 0.0


def test_ratios_point_the_way_the_column_header_claims():
    fast = measurement("fast", [1.0], [1.0], moved=1024 * 1024)
    slow = measurement("slow", [4.0], [8.0], moved=1024 * 1024)
    comparison = Comparison(scenario="s", subject=fast, baseline=slow)
    # "4x wall" has to mean the subject finished in a quarter of the time, not four times it.
    assert comparison.wall_ratio == 4.0
    assert comparison.cpu_ratio == 8.0


def test_a_client_that_spent_no_measurable_cpu_does_not_raise():
    subject = measurement("subject", [1.0], [0.0], moved=1)
    baseline = measurement("baseline", [1.0], [1.0], moved=1)
    assert Comparison(scenario="s", subject=subject, baseline=baseline).cpu_ratio == float("inf")


def test_separable_is_true_only_when_the_sample_ranges_do_not_overlap():
    subject = measurement("subject", [1.0, 1.1, 1.2], [1.0, 1.0, 1.0], moved=1)
    clear = measurement("clear", [3.0, 3.1, 3.2], [1.0, 1.0, 1.0], moved=1)
    muddy = measurement("muddy", [1.15, 3.0, 3.1], [1.0, 1.0, 1.0], moved=1)

    assert Comparison(scenario="s", subject=subject, baseline=clear).separable
    # The medians differ by more than 2x and the ranges still touch. This is precisely the
    # case a benchmark reports as a result and should not.
    assert not Comparison(scenario="s", subject=subject, baseline=muddy).separable


def test_a_ratio_drawn_from_overlapping_samples_is_marked_in_the_table():
    subject = measurement("gantry-sftp", [1.0, 1.1, 1.2], [1.0, 1.0, 1.0], moved=1024 * 1024)
    muddy = measurement("other", [1.15, 3.0, 3.1], [1.0, 1.0, 1.0], moved=1024 * 1024)
    table = render_scenario("s", [subject, muddy], baseline_client="gantry-sftp")

    assert "| gantry-sftp |" in table
    assert "baseline" in table
    assert "(overlapping)" in table


def test_a_separable_ratio_is_not_marked():
    subject = measurement("gantry-sftp", [1.0, 1.0, 1.0], [1.0, 1.0, 1.0], moved=1024 * 1024)
    clear = measurement("other", [3.0, 3.0, 3.0], [1.0, 1.0, 1.0], moved=1024 * 1024)
    table = render_scenario("s", [subject, clear], baseline_client="gantry-sftp")

    assert "0.33x wall" in table
    assert "overlapping" not in table


def test_a_zero_byte_scenario_renders_dashes_rather_than_a_throughput():
    m = measurement("gantry-sftp", [1.0], [1.0], moved=0)
    table = render_scenario("connect", [m], baseline_client="gantry-sftp")
    assert "| -- |" in table


def test_the_renderer_preserves_the_order_it_was_given():
    first = measurement("aaa", [3.0], [1.0], moved=1)
    second = measurement("zzz", [1.0], [1.0], moved=1)
    table = render_scenario("s", [first, second], baseline_client="aaa")
    # Sorting by result would put the winner first and flatter whoever won.
    assert table.index("| aaa |") < table.index("| zzz |")


def test_a_missing_baseline_client_leaves_every_row_unlabelled_rather_than_guessing():
    m = measurement("only", [1.0], [1.0], moved=1)
    table = render_scenario("s", [m], baseline_client="absent")
    row = next(line for line in table.splitlines() if line.startswith("| only |"))
    # Calling the only row "baseline" would imply a comparison against a client that did not
    # run -- which is exactly what happens when a library fails to install and nobody notices.
    # Asserted on the row rather than the table, because the header says "vs baseline".
    assert "baseline" not in row
    assert row.endswith("| -- |")


@pytest.mark.anyio
async def test_warmups_are_discarded_and_repeats_are_kept():
    calls = 0

    async def run_once() -> tuple[float, int]:
        nonlocal calls
        calls += 1
        return float(calls), 100

    result = await take_samples(run_once, scenario="s", client="c", repeats=3, warmups=2)
    assert calls == 5
    # The first two runs are gone, so the kept walls are 3, 4, 5 and the median is 4.
    assert [s.wall_seconds for s in result.samples] == [3.0, 4.0, 5.0]
    assert result.wall_seconds == 4.0
    assert result.bytes_moved == 100


@pytest.mark.anyio
async def test_the_warm_download_row_times_a_later_transfer_and_not_the_first(monkeypatch):
    """D-23's row must not time its own warmup, or it publishes cold numbers as warm.

    The failure this guards is silent and it produces a *number*: a ``download_warm`` that
    performed no warmup, or that started its clock before one, would report a connection's
    first transfer under a label saying it was the second -- and the conclusion drawn from
    that row is precisely that the two differ. Nothing downstream could notice.

    Driven against a fake session rather than a server: what is under test is which ``get``
    the stopwatch spans, which is this method's own arithmetic and needs no bytes to move.
    """
    from contextlib import asynccontextmanager  # noqa: PLC0415

    import _clients  # noqa: PLC0415

    class FakeSession:
        def __init__(self) -> None:
            self.gets = 0

        async def get(self, remote: str, local: Path) -> object:
            self.gets += 1
            # The warmups are slow and the timed transfer is fast, which is the opposite of
            # reality and the point: if the clock spanned a warmup the elapsed time could not
            # come out below its duration.
            await anyio.sleep(0.05 if self.gets <= 2 else 0.0)
            # A result object rather than an int since D-99, and the fake has to answer the
            # same shape or it stops modelling the thing the harness calls.
            return SimpleNamespace(transferred=self.gets)

    session = FakeSession()

    @asynccontextmanager
    async def fake_transport():
        yield object()

    @asynccontextmanager
    async def fake_open_session(_transport):
        yield session

    monkeypatch.setattr(_clients.GantryClient, "_transport", lambda self: fake_transport())
    monkeypatch.setattr(_clients, "open_session", fake_open_session)

    client = _clients.GantryClient(server=None)  # type: ignore[arg-type]
    elapsed, moved = await client.download_warm(Path("/remote"), Path("/local"), warmups=2)

    assert session.gets == 3, "two warmups and one timed transfer"
    # The byte count belongs to the timed run, not to a warmup and not to their sum. Returning
    # the sum is the mistake that would make the row's MiB/s three times the truth.
    assert moved == 3
    assert elapsed < 0.05, f"the clock spanned a warmup: {elapsed:.3f}s"


@pytest.mark.anyio
@pytest.mark.parametrize("direction", ["download", "upload"])
async def test_a_sweep_rung_runs_on_one_connection_and_times_neither_warmup(monkeypatch, direction):
    """D-92's rungs must reuse the connection, and nothing downstream could notice if they did not.

    A rung that opened a connection per repeat would still produce a curve, still pass every
    verification, and still be published -- it would just be timing TCP slow start at the small
    end and calling the result a size cliff. That is the exact mistake D-81 found in the rows
    above, so the departure from this suite's no-reuse rule is asserted rather than trusted.
    """
    from contextlib import asynccontextmanager  # noqa: PLC0415

    import _clients  # noqa: PLC0415

    opened = 0

    class FakeSession:
        def __init__(self) -> None:
            self.calls = 0

        async def _transfer(self):
            self.calls += 1
            # Warmups slow, timed transfers instant -- the reverse of reality, so a clock that
            # spanned a warmup could not come out below the warmup's duration.
            await anyio.sleep(0.05 if self.calls <= 2 else 0.0)

        async def get(self, remote: str, local: Path) -> int:
            await self._transfer()
            return 1

        async def put(self, local: Path, remote: str, *, publish):
            assert publish.atomic is False, "the sweep must match the other two clients"
            assert publish.fsync is False
            await self._transfer()

    session = FakeSession()

    @asynccontextmanager
    async def fake_transport():
        yield object()

    @asynccontextmanager
    async def fake_open_session(_transport):
        nonlocal opened
        opened += 1
        yield session

    monkeypatch.setattr(_clients.GantryClient, "_transport", lambda self: fake_transport())
    monkeypatch.setattr(_clients, "open_session", fake_open_session)

    client = _clients.GantryClient(server=None)  # type: ignore[arg-type]
    method = getattr(client, f"{direction}_repeatedly")
    walls = await method(Path("/a"), Path("/b"), repeats=3, warmups=2)

    assert opened == 1, "the ladder's whole point is that one connection carries the rung"
    assert session.calls == 5, "two warmups and three timed transfers"
    assert len(walls) == 3, "the warmups must not appear as samples"
    assert max(walls) < 0.05, f"a warmup landed inside a timed window: {walls}"


@pytest.mark.anyio
async def test_cpu_is_measured_per_sample_rather_than_cumulatively(
    monkeypatch: pytest.MonkeyPatch,
):
    """Each sample carries its own run's cost, not the total so far.

    A cumulative counter is how a benchmark reports a fictional slowdown: every sample looks
    worse than the one before it, and the last one looks catastrophic.

    **The clock is stubbed, and that is the fix for a real flake.** This used to burn CPU in a
    child twice and assert the second sample came in under 1.8x the first. It failed once in a
    full-suite run and the cause is not scheduling noise, which was measured and does not reach
    the bound -- ratios over 15 quiet runs spanned 0.85 to 1.19.

    The cause is that :func:`~benchmarks._harness.cpu_seconds` is own CPU **plus**
    ``RUSAGE_CHILDREN``, and ``RUSAGE_CHILDREN`` is *process-wide*: it accumulates every child
    this process reaps, whoever spawned it. A child belonging to something else, reaped inside
    the second sample's window, is charged to that sample. Measured: with one stray child in
    the window the ratio ran 1.07 to 2.56 and the old assertion failed 8 times in 10.

    That also rules out the obvious repair. Making the second run do a twentieth of the work,
    so the two hypotheses differ in sign rather than by a ratio, was tried and is **worse** --
    the noise is *additive*, so shrinking the honest second sample lets a stray child dominate
    it, and that version failed 9 times in 10 under the same conditions.

    So the timing comes out entirely. The claim here is arithmetic -- that the sampler records
    a difference rather than a reading -- and a stubbed monotonic clock pins it exactly, with
    the second sample deliberately *smaller* than the first, which no running total can do.
    The claim that the real counter sees a real child's CPU is a different one and is proved
    against the real clock by
    :func:`test_cpu_seconds_counts_a_reaped_childs_time`; splitting them is what lets each be
    tested with the instrument it needs.
    """
    # Monotonic, like the real counter, with known steps. The second interval is smaller than
    # the first: a cumulative implementation cannot produce that, because a running total
    # cannot decrease.
    combined = iter([10.0, 10.5, 10.5, 10.75])
    own = iter([1.0, 1.1, 1.1, 1.3])
    monkeypatch.setattr(_harness, "cpu_seconds", lambda: next(combined))
    monkeypatch.setattr(_harness, "own_cpu_seconds", lambda: next(own))

    async def run_once() -> tuple[float, int]:
        return 1.0, 1

    result = await take_samples(run_once, scenario="s", client="c", repeats=2, warmups=0)

    first, second = result.samples
    assert first.cpu_seconds == pytest.approx(0.5)
    assert second.cpu_seconds == pytest.approx(0.25)
    assert first.own_cpu_seconds == pytest.approx(0.1)
    assert second.own_cpu_seconds == pytest.approx(0.2)


# --- the second ceiling (D-113) -------------------------------------------------------------

MIB = 1024 * 1024


def ceiling(
    *, transfer_own: float, connect_own: float, walls: list[float], moved: int
) -> CpuCeiling:
    return CpuCeiling(
        direction="download",
        transfer=measurement(
            "g", walls, [9.0] * len(walls), moved, own=[transfer_own] * len(walls)
        ),
        connect=measurement("g (connect)", [0.1], [9.0], 0, own=[connect_own]),
    )


def test_own_cpu_seconds_excludes_a_reaped_childs_time():
    """The distinction the whole row rests on, proven against a child that really burns CPU.

    ``cpu_seconds`` and ``own_cpu_seconds`` differing is not enough on its own -- two counters
    that both grew would satisfy that. What is asserted is that essentially all of the child's
    work lands in one and essentially none of it in the other.
    """
    before_all, before_own = cpu_seconds(), own_cpu_seconds()
    burn_in_a_child()
    combined, mine = cpu_seconds() - before_all, own_cpu_seconds() - before_own

    assert combined > 0.05, "the child did not burn enough CPU for this test to mean anything"
    assert mine < combined / 2
    assert mine >= 0.0


def test_the_ceiling_is_the_reciprocal_of_the_cost_net_of_connecting():
    # 2.0 s of our CPU for the transfer, 1.0 s of it the session lifecycle, over 8 MiB:
    # 0.125 s/MiB, so 8 MiB/s if our CPU were the only thing in the way.
    c = ceiling(transfer_own=2.0, connect_own=1.0, walls=[2.0], moved=8 * MIB)
    assert c.own_cpu_seconds == 1.0
    assert c.own_cpu_seconds_per_mib == 0.125
    assert c.ceiling_mib_per_second == 8.0
    # Measured 4 MiB/s against a ceiling of 8: the link is leaving half the CPU unused.
    assert c.headroom == 2.0


def test_the_connect_cost_is_subtracted_and_a_row_that_forgot_it_would_read_lower():
    """The subtraction is the row's one departure from the module's convention, so it is pinned.

    A ceiling derived without it is not slightly wrong, it is wrong by a factor that changes
    with the file size -- which is the same shape of mistake D-23 found the matrix making with
    TCP slow start one layer down.
    """
    with_connect = ceiling(transfer_own=2.0, connect_own=1.0, walls=[1.0], moved=1 * MIB)
    without = ceiling(transfer_own=2.0, connect_own=0.0, walls=[1.0], moved=1 * MIB)
    assert with_connect.ceiling_mib_per_second == 1.0
    assert without.ceiling_mib_per_second == 0.5
    assert with_connect.ceiling_mib_per_second > without.ceiling_mib_per_second


def test_a_connect_measurement_costlier_than_the_transfer_floors_at_zero_rather_than_negative():
    """Two medians from different sample sets can cross. A negative CPU cost is an artefact.

    Floored rather than raised, because the profiles where it can happen are the ones where the
    transfer is trivially short -- and refusing to render a row there would remove the row from
    exactly the runs a reader is most likely to be checking by hand.
    """
    c = ceiling(transfer_own=0.5, connect_own=2.0, walls=[1.0], moved=4 * MIB)
    assert c.own_cpu_seconds == 0.0
    assert c.own_cpu_seconds_per_mib == 0.0
    assert c.ceiling_mib_per_second == float("inf")


def test_a_ceiling_needs_a_transfer_that_moved_bytes_and_a_connect_row_that_did_not():
    with pytest.raises(ValueError) as no_bytes:
        ceiling(transfer_own=1.0, connect_own=0.0, walls=[1.0], moved=0)
    assert no_bytes.value.args[0] == "download moved no bytes; there is no ceiling to derive"

    with pytest.raises(ValueError) as moved:
        CpuCeiling(
            direction="download",
            transfer=measurement("g", [1.0], [1.0], 8 * MIB),
            connect=measurement("g (connect)", [1.0], [1.0], 4096),
        )
    assert moved.value.args[0] == (
        "the connect measurement moved 4096 bytes; it is meant to be the session lifecycle "
        "on its own"
    )


def test_the_ceiling_table_says_what_it_is_not():
    """The prose is load-bearing: this table is the one most likely to be misread as a claim.

    It carries a MiB/s figure and no baseline, so a reader skimming for throughput numbers
    finds a big one. The table has to say, in the report itself, that the number bounds more
    transports rather than describing a transfer.
    """
    rendered = render_cpu_ceiling(
        [ceiling(transfer_own=2.0, connect_own=1.0, walls=[2.0], moved=8 * MIB)]
    )
    assert "| download | 0.1250 | 8 | 4.0 | 2.0x |" in rendered
    assert "Not a comparison" in rendered
    assert "one GIL" in rendered
    assert "D-113" in rendered


def test_the_report_carries_every_caveat_and_the_environment():
    environment = Environment(
        captured_at="2026-07-26T00:00:00+00:00",
        host_platform="Linux-test",
        processor="aarch64",
        python="CPython 3.13.14",
        ssh="OpenSSH_10.0p2",
        sftp_server="/usr/lib/openssh/sftp-server",
        library_versions={"paramiko": "5.0.0"},
    )
    text = render_report(
        title="T",
        environment=environment,
        profile="50 ms",
        sections=["#### s\n"],
        caveats=["loopback is not a network", "one server implementation"],
    )
    for expected in (
        "2026-07-26T00:00:00+00:00",
        "Linux-test",
        "aarch64",
        "CPython 3.13.14",
        "OpenSSH_10.0p2",
        "/usr/lib/openssh/sftp-server",
        "paramiko 5.0.0",
        "50 ms",
        "loopback is not a network",
        "one server implementation",
    ):
        assert expected in text, f"the report dropped {expected!r}"


def test_capturing_the_environment_reads_the_real_tools():
    if shutil.which("ssh") is None:  # pragma: no cover - ssh is a project requirement
        pytest.skip("ssh is not on PATH, so there is no version string to capture")
    environment = Environment.capture(sftp_server_path="/x", library_versions={})
    assert environment.captured_at.endswith("+00:00")
    assert "OpenSSH" in environment.ssh
    assert environment.python.startswith("CPython 3.")


def test_a_version_command_that_does_not_exist_is_reported_rather_than_raised():
    # Capturing the environment must never be the thing that fails a benchmark run: the
    # header is metadata, and a missing binary is a fact about the host worth printing.
    reported = _command_output(["definitely-not-a-real-binary-xyzzy", "-V"])
    assert reported.startswith("unavailable (")


# --- the size sweep (D-92) -------------------------------------------------------------------
#
# This half of the harness decides whether a *shape* is published as sound, and unlike the
# ratio columns above it also **gates the benchmark lane**. So the arithmetic gets the same
# treatment the ratio arithmetic got: a detector that never fires would leave the size cliff
# the sweep exists to refuse undetected, and one that fires on noise would make the lane
# unrunnable and get switched off.


def point(size: int, walls: list[float], note: str = "n") -> SizePoint:
    return SizePoint(size_bytes=size, note=note, wall_seconds=tuple(walls))


def rising_sweep() -> SizeSweep:
    """Throughput rising and then flattening -- the shape the library promises."""
    return SizeSweep(
        scenario="download",
        client="gantry-sftp",
        points=(
            point(4096, [0.010, 0.011, 0.012]),  # 0.4 MiB/s
            point(262144, [0.010, 0.011, 0.012]),  # 25 MiB/s
            point(2097152, [0.020, 0.021, 0.022]),  # 100 MiB/s
            point(16777216, [0.150, 0.155, 0.160]),  # 106 MiB/s -- the plateau
        ),
    )


def test_size_label_names_only_the_units_that_divide_exactly():
    # 261120 is the size the whole ladder is built around, and rendering it as "256 KiB" --
    # which is the number DESIGN.md 4.2 forbids as a request size -- would put the wrong
    # boundary in the report.
    assert size_label(261120) == "255 KiB"
    assert size_label(262144) == "256 KiB"
    assert size_label(16777216) == "16 MiB"
    assert size_label(4096) == "4 KiB"
    assert size_label(1000) == "1000 B"
    assert size_label(1048577) == "1048577 B"


def test_a_size_point_refuses_the_states_that_would_divide_by_zero():
    with pytest.raises(ValueError) as no_bytes:
        point(0, [0.1])
    assert no_bytes.value.args[0] == "a size point must move bytes, got 0"

    with pytest.raises(ValueError) as no_samples:
        point(4096, [])
    assert no_samples.value.args[0] == "4 KiB has no samples"

    with pytest.raises(ValueError) as instant:
        point(4096, [0.1, 0.0])
    assert instant.value.args[0] == "4 KiB has a non-positive wall time"


def test_throughput_uses_the_median_and_the_extremes_are_recoverable():
    one = point(1048576, [0.5, 1.0, 2.0])
    assert one.throughput_mib_per_second == 1.0
    assert one.best_throughput_mib_per_second == 2.0
    assert one.worst_throughput_mib_per_second == 0.5
    assert one.spread == 4.0


def test_a_sweep_of_one_point_has_no_shape_and_is_refused():
    with pytest.raises(ValueError) as exc:
        SizeSweep(scenario="download", client="c", points=(point(4096, [0.1]),))
    assert exc.value.args[0] == "c/download has no shape: 1 point"


def test_a_sweep_refuses_sizes_that_are_not_strictly_ascending():
    """The cliff detector reads "smaller" off the list order, so the order is an invariant.

    Handed a descending or duplicated ladder it would compare each rung against the wrong
    reference and report a rising curve as falling, or the reverse. That is a wrong *result*
    rather than a crash, which is why it is refused at construction.
    """
    with pytest.raises(ValueError) as descending:
        SizeSweep(
            scenario="download",
            client="c",
            points=(point(262144, [0.1]), point(4096, [0.1])),
        )
    assert descending.value.args[0] == "c/download sizes are not strictly ascending"

    with pytest.raises(ValueError) as duplicated:
        SizeSweep(
            scenario="download",
            client="c",
            points=(point(4096, [0.1]), point(4096, [0.1])),
        )
    assert duplicated.value.args[0] == "c/download sizes are not strictly ascending"


def test_a_rising_then_flat_curve_has_no_cliffs_and_no_dips():
    sweep = rising_sweep()
    assert sweep.cliffs(tolerance=0.5) == ()
    assert sweep.dips(tolerance=0.5) == ()


def test_a_collapse_is_a_cliff_and_names_where_it_fell_from():
    """paramiko#2438's shape: throughput dies at a byte count and the reference is upstream."""
    sweep = SizeSweep(
        scenario="upload",
        client="paramiko",
        points=(
            point(4096, [0.0008, 0.0008, 0.0009]),
            point(32768, [0.0420, 0.0421, 0.0422]),  # ~0.74 MiB/s against ~4.6
            point(131072, [0.0010, 0.0010, 0.0011]),
        ),
    )
    (cliff,) = sweep.cliffs(tolerance=0.5)
    assert cliff.point.size_bytes == 32768
    assert cliff.reference.size_bytes == 4096
    assert cliff.ratio < 0.2
    assert cliff.describe() == ("32 KiB runs at 0.74 MiB/s, 0.15x the 4.88 MiB/s measured at 4 KiB")


def test_a_bimodal_stall_is_a_dip_but_never_a_cliff():
    """The case that decided there are two detectors rather than one.

    An incumbent's stall is intermittent -- paramiko's 32 KiB upload came out of the first real
    run with a fastest-to-slowest range of 47x -- so its fast mode keeps the sample ranges
    overlapping. Failing a run on that would be failing on noise; not reporting it at all would
    throw away the control's whole reason for existing. So: reported, not asserted.
    """
    sweep = SizeSweep(
        scenario="upload",
        client="paramiko",
        points=(
            point(4096, [0.0010, 0.0010, 0.0010]),  # 3.9 MiB/s
            point(32768, [0.0010, 0.0400, 0.0470]),  # median 0.5 MiB/s, but one fast run
        ),
    )
    assert sweep.cliffs(tolerance=0.5) == ()
    (dip,) = sweep.dips(tolerance=0.5)
    assert dip.point.size_bytes == 32768


def test_the_reference_is_the_best_smaller_size_not_the_one_before_it():
    """A slide has no single step big enough to notice, and is still a collapse.

    Comparing each rung with its immediate predecessor would let throughput walk down 30% a
    rung forever without ever tripping the gate. The reference is the best rung *anywhere*
    below, which is what makes "never falls as the file grows" the actual assertion.
    """
    sweep = SizeSweep(
        scenario="download",
        client="gantry-sftp",
        points=(
            point(262144, [0.0025, 0.0025, 0.0025]),  # 100 MiB/s -- the peak
            point(1048576, [0.0140, 0.0140, 0.0140]),  # 71 MiB/s
            point(2097152, [0.0400, 0.0400, 0.0400]),  # 50 MiB/s
            point(8388608, [0.2400, 0.2400, 0.2400]),  # 33 MiB/s -- 0.33x the peak
        ),
    )
    falls = sweep.cliffs(tolerance=0.5)
    assert [c.point.size_bytes for c in falls] == [8388608]
    assert falls[0].reference.size_bytes == 262144


def test_a_tolerance_outside_the_unit_interval_is_refused():
    sweep = rising_sweep()
    for bad in (0.0, -0.5, 1.5):
        with pytest.raises(ValueError) as exc:
            sweep.cliffs(tolerance=bad)
        assert exc.value.args[0] == f"tolerance must be in (0, 1], got {bad}"
        with pytest.raises(ValueError) as also:
            sweep.dips(tolerance=bad)
        assert also.value.args[0] == f"tolerance must be in (0, 1], got {bad}"


def test_the_table_marks_a_cliff_on_exactly_the_rungs_the_gate_fails_on():
    """The report and the gate must be the same computation, not two spellings of one idea.

    A table reading `rising` beside a failing run -- or `CLIFF` beside a passing one -- would
    be worse than no table, because the table is the evidence the failure message points at.
    """
    sweep = SizeSweep(
        scenario="download",
        client="gantry-sftp",
        points=(
            point(4096, [0.0100, 0.0100, 0.0100]),
            point(262144, [0.0025, 0.0025, 0.0025]),  # 100 MiB/s
            point(1048576, [0.0500, 0.0500, 0.0500]),  # 20 MiB/s -- 0.2x, separable
        ),
    )
    rendered = render_size_sweep(sweep, tolerance=0.5)
    rows = [line for line in rendered.splitlines() if line.startswith("| ") and " KiB" in line]
    marked = [line for line in rendered.splitlines() if "CLIFF" in line]
    assert len(marked) == 1
    assert marked[0].startswith("| 1 MiB |")
    assert [c.point.size_bytes for c in sweep.cliffs(tolerance=0.5)] == [1048576]
    # The first rung has nothing below it, so its verdict is a dash rather than "rising" --
    # calling it rising would be a comparison against nothing.
    assert rows[0].startswith("| 4 KiB |")
    assert rows[0].endswith("| -- |")
    assert "255 KiB" not in rendered, "the ladder's own labels must survive into the table"
    assert "| rising |" in rendered
    # No CPU column, deliberately: one connection carries the whole ladder, so there is one
    # reaped child and per-sample CPU does not exist. See the module docstring.
    assert "CPU" not in rendered


@st.composite
def any_sweep(draw: st.DrawFn) -> SizeSweep:
    """An arbitrary curve: ascending sizes, arbitrary positive timings, any number of samples."""
    sizes = sorted(draw(st.sets(st.integers(min_value=1, max_value=10**8), min_size=2, max_size=6)))
    walls = st.lists(st.floats(min_value=1e-5, max_value=10.0), min_size=1, max_size=4)
    return SizeSweep(
        scenario="download", client="c", points=tuple(point(size, draw(walls)) for size in sizes)
    )


@given(any_sweep())
def test_every_cliff_is_also_a_dip(sweep: SizeSweep):
    """Containment, on any curve at all: the gate can only fire where the report already says so.

    The two detectors are separate code paths -- one compares medians, the other compares the
    unflattering extremes -- and the whole design rests on the strict one being a subset of the
    loose one. If it ever were not, a run could fail on a rung the table describes as fine.
    """
    cliffs = {c.point.size_bytes for c in sweep.cliffs(tolerance=0.5)}
    dips = {d.point.size_bytes for d in sweep.dips(tolerance=0.5)}
    assert cliffs <= dips


@given(
    sizes=st.sets(st.integers(min_value=1, max_value=10**8), min_size=2, max_size=8),
    walls=st.lists(st.floats(min_value=1e-5, max_value=10.0), min_size=1, max_size=5),
)
def test_a_curve_whose_throughput_only_rises_never_reports_a_fall(
    sizes: set[int], walls: list[float]
):
    """Equal timings at ascending sizes is throughput rising by construction -- the promise.

    Free of any assumption about the *sample* distribution: however noisy the timings are, if
    every rung is noisy the same way then throughput rises with size and nothing may be
    reported. A detector that fired here would fail the lane on a healthy library.
    """
    sweep = SizeSweep(
        scenario="download", client="c", points=tuple(point(s, walls) for s in sorted(sizes))
    )
    assert sweep.cliffs(tolerance=0.5) == ()
    assert sweep.dips(tolerance=0.5) == ()


def test_a_dip_the_samples_cannot_separate_is_marked_overlapping_in_the_table():
    sweep = SizeSweep(
        scenario="download",
        client="gantry-sftp",
        points=(
            point(262144, [0.0025, 0.0030, 0.0060]),
            point(1048576, [0.0100, 0.0180, 0.0400]),
        ),
    )
    rendered = render_size_sweep(sweep, tolerance=0.5)
    assert "(overlapping)" in rendered
    assert "CLIFF" not in rendered

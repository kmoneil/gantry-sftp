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

import anyio
import pytest

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

from _harness import (  # noqa: E402
    Comparison,
    Environment,
    Measurement,
    Sample,
    _command_output,
    cpu_seconds,
    render_report,
    render_scenario,
    take_samples,
)

BURN = "x = 0\nfor i in range(4_000_000):\n    x += i\n"
"""A child that spends CPU and does nothing else. Sized to be unmistakable, not precise."""


def burn_in_a_child() -> None:
    """Spend CPU in a subprocess and reap it, so ``RUSAGE_CHILDREN`` can account for it."""
    subprocess.run([sys.executable, "-c", BURN], check=True)


def measurement(client: str, walls: list[float], cpus: list[float], moved: int) -> Measurement:
    return Measurement(
        scenario="s",
        client=client,
        bytes_moved=moved,
        samples=tuple(
            Sample(wall_seconds=w, cpu_seconds=c) for w, c in zip(walls, cpus, strict=True)
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

        async def get(self, remote: str, local: Path) -> int:
            self.gets += 1
            # The warmups are slow and the timed transfer is fast, which is the opposite of
            # reality and the point: if the clock spanned a warmup the elapsed time could not
            # come out below its duration.
            await anyio.sleep(0.05 if self.gets <= 2 else 0.0)
            return self.gets

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
async def test_cpu_is_measured_per_sample_rather_than_cumulatively():
    async def run_once() -> tuple[float, int]:
        await anyio.to_thread.run_sync(burn_in_a_child)
        return 1.0, 1

    result = await take_samples(run_once, scenario="s", client="c", repeats=2, warmups=0)
    # Each sample carries its own run's cost. A cumulative counter would make the second
    # sample roughly twice the first, which is how a benchmark reports a fictional slowdown.
    first, second = result.samples
    assert first.cpu_seconds > 0.01
    assert second.cpu_seconds < first.cpu_seconds * 1.8


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

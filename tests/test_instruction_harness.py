"""The instruction lane's arithmetic is code, so it is gated like code.

Same placement argument as :mod:`test_benchmark_harness`, one lane over: the measurement needs
valgrind and a real ``sftp-server`` and is therefore out of the default run, but everything that
turns counts into a verdict needs neither -- and that verdict is the only performance regression
gate this repository has.

The load-bearing test here is
:func:`test_the_pathology_the_wall_clock_sweep_cannot_see_is_caught_here`. It carries the
measured numbers from both instruments side by side and asserts the thing D-63 was filed on: the
wall-clock gate reports a clean curve while the instruction gate fails. Every other test in this
file is a guard on the arithmetic that makes that one true.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

_ROOT = Path(__file__).resolve().parent.parent
for _extra in (_ROOT / "benchmarks", _ROOT / "live-tests"):
    if str(_extra) not in sys.path:
        # Appended rather than inserted, for the reason `test_benchmark_harness` gives: nothing
        # else is called `_instructions`, and the front of the path could shadow a real module.
        sys.path.append(str(_extra))

import _instructions  # noqa: E402  -- imported as a module so `measure` can be monkeypatched
from _harness import SizePoint, SizeSweep  # noqa: E402
from _instructions import (  # noqa: E402
    MIB,
    Baseline,
    Drift,
    InstructionLadder,
    Rise,
    Rung,
    Step,
    measure,
    measure_least,
    render_ladder,
    valgrind_unavailable_reason,
    workload_source,
)

# Every count below that is not obviously synthetic was measured on this machine and is quoted
# from `_reports/instructions.md` or from the probe named beside it. A test whose fixtures are
# invented numbers proves the arithmetic and nothing about the shape it is meant to detect.
HEALTHY_DOWNLOAD = {1: 5_503_390, 4: 13_092_473, 8: 23_182_911, 16: 43_474_149}
"""Net instructions for a download, measured. Marginal cost per MiB is flat to 0.5%."""

RESCAN = {1: 545_000, 4: 5_287_067, 8: 18_921_088, 16: 71_257_727}
"""What an O(n^2) reassembler adds, measured under cachegrind rather than modelled.

A reassembler that walks everything it already holds once per arriving chunk touches
``sum(k * 261120 for k in 1..n/261120)`` bytes. That loop was run at each of these sizes and
counted; the numbers quadruple as the size doubles, which is the shape they should have.
"""


def rung(mib: int, instructions: int) -> Rung:
    return Rung(size_bytes=mib * MIB, instructions=instructions)


def ladder(costs: dict[int, int], direction: str = "download") -> InstructionLadder:
    return InstructionLadder(
        direction=direction,
        control=487_878_037,
        rungs=tuple(rung(mib, instructions) for mib, instructions in sorted(costs.items())),
    )


def linear(per_mib: int, sizes: tuple[int, ...] = (1, 4, 8, 16), fixed: int = 1_000_000):
    """A ladder whose work really is linear in the bytes: the shape nothing should flag."""
    return ladder({mib: fixed + per_mib * mib for mib in sizes})


# --- the finding ------------------------------------------------------------------------


def test_the_pathology_the_wall_clock_sweep_cannot_see_is_caught_here():
    """D-63's third amendment, as an assertion over both instruments' real numbers.

    An O(n^2) reassembler costs 32% of the wall clock at 16 MiB, and `_plans/probes/
    superlinear_blind_spot_probe.py` measured what each gate makes of it. The wall-clock sweep
    reports a clean curve -- no cliff, not even a dip -- because its question is whether
    throughput *falls*, and a cost can grow quadratically for a long time before the curve turns
    over. The instruction ladder fails, because its question is whether the cost per byte is the
    same at every size, and that is answerable while throughput is still rising.
    """
    polluted = ladder({mib: HEALTHY_DOWNLOAD[mib] + RESCAN[mib] for mib in HEALTHY_DOWNLOAD})
    rises = polluted.rises(tolerance=1.25, floor_bytes=4 * MIB)
    assert [rise.describe() for rise in rises] == [
        "8->16 MiB costs 9,078,485 instructions/MiB, 1.53x the 5,931,115 measured over 4->8 MiB"
    ]

    # The same transfers, timed. Three samples standing in for the run's nine, carrying the
    # measured minimum, median and maximum of each rung so the separability test sees the real
    # ranges. Both detectors of the wall-clock lane come back empty on it.
    timed = SizeSweep(
        scenario="download: throughput against size",
        client="gantry-sftp",
        points=(
            SizePoint(size_bytes=1 * MIB, note="n", wall_seconds=(0.00488, 0.00673, 0.01118)),
            SizePoint(size_bytes=2 * MIB, note="n", wall_seconds=(0.00931, 0.01471, 0.01815)),
            SizePoint(size_bytes=8 * MIB, note="n", wall_seconds=(0.03475, 0.03854, 0.04448)),
            SizePoint(size_bytes=16 * MIB, note="n", wall_seconds=(0.08500, 0.10143, 0.11305)),
        ),
    )
    assert timed.cliffs(tolerance=0.5) == ()
    assert timed.dips(tolerance=0.5) == ()


def test_the_healthy_ladder_those_numbers_came_from_passes():
    """The other half of the pair: the same code with no pathology raises nothing.

    A detector that fired on the real curve would be worse than no detector, and this is the
    curve the numbers above were measured against.
    """
    assert ladder(HEALTHY_DOWNLOAD).rises(tolerance=1.25, floor_bytes=4 * MIB) == ()


# --- rungs, steps, ladders --------------------------------------------------------------


def test_a_rung_refuses_the_states_that_would_divide_by_zero_or_lie():
    with pytest.raises(ValueError) as no_bytes:
        Rung(size_bytes=0, instructions=1)
    assert no_bytes.value.args[0] == "a rung must move bytes, got 0"

    with pytest.raises(ValueError) as free:
        Rung(size_bytes=MIB, instructions=0)
    assert free.value.args[0] == (
        "1048576 bytes cost 0 instructions net of the control; a transfer that costs nothing "
        "over an empty session was not measured"
    )


def test_average_cost_per_mib_carries_the_fixed_cost_and_the_marginal_does_not():
    """Why both columns exist. The average falls on a healthy ladder; only the marginal is flat."""
    curve = linear(per_mib=2_000_000, fixed=4_000_000)
    averages = [round(r.instructions_per_mib) for r in curve.rungs]
    assert averages == [6_000_000, 3_000_000, 2_500_000, 2_250_000]
    marginals = [round(s.instructions_per_mib) for s in curve.steps(floor_bytes=0)]
    assert marginals == [2_000_000, 2_000_000, 2_000_000]


def test_a_step_goes_up_and_says_so_when_it_does_not():
    with pytest.raises(ValueError) as exc:
        Step(smaller=rung(8, 20), larger=rung(4, 10))
    assert exc.value.args[0] == "a step goes up: 8388608 to 4194304"


def test_a_ladder_refuses_what_it_cannot_read_a_shape_from():
    with pytest.raises(ValueError) as no_control:
        InstructionLadder(direction="download", control=0, rungs=(rung(1, 1), rung(2, 2)))
    assert no_control.value.args[0] == ("the control cost 0 instructions; nothing was measured")

    with pytest.raises(ValueError) as one:
        InstructionLadder(direction="download", control=1, rungs=(rung(1, 1),))
    assert one.value.args[0] == "download has no shape: 1 rung"

    with pytest.raises(ValueError) as order:
        InstructionLadder(direction="upload", control=1, rungs=(rung(4, 2), rung(1, 1)))
    assert order.value.args[0] == "upload rungs are not strictly ascending"


def test_the_floor_drops_the_steps_whose_divisor_is_too_small_to_trust():
    """The 1->4 step is measured and printed; it is not gated. See LADDER's docstring."""
    curve = linear(per_mib=2_000_000)
    assert [s.describe() for s in curve.steps(floor_bytes=0)] == [
        "1->4 MiB",
        "4->8 MiB",
        "8->16 MiB",
    ]
    assert [s.describe() for s in curve.steps(floor_bytes=4 * MIB)] == ["4->8 MiB", "8->16 MiB"]


def test_a_floor_above_the_whole_ladder_yields_no_steps_rather_than_a_pass():
    """Two rungs are needed for one step, and a ladder that cannot answer must not answer "no"."""
    curve = linear(per_mib=2_000_000)
    assert curve.steps(floor_bytes=32 * MIB) == ()
    assert curve.rises(tolerance=1.25, floor_bytes=32 * MIB) == ()


def test_the_reference_is_the_cheapest_step_below_not_the_one_before_it():
    """One expensive step must not become the yardstick every later step is forgiven against.

    Same structure as the wall-clock sweep's `_fastest_below`, and for the same reason: with the
    previous step as the reference, a curve that doubles its cost per byte and then holds steady
    would report one rise and then read as healthy.
    """
    # 4->8 costs 2.0M/MiB, 8->16 costs 4.0M/MiB, 16->32 holds at 4.0M/MiB.
    curve = ladder({4: 8_000_000, 8: 16_000_000, 16: 48_000_000, 32: 112_000_000})
    rises = curve.rises(tolerance=1.25, floor_bytes=4 * MIB)
    assert [rise.step.describe() for rise in rises] == ["8->16 MiB", "16->32 MiB"]
    assert [rise.reference.describe() for rise in rises] == ["4->8 MiB", "4->8 MiB"]


def test_a_tolerance_below_one_would_fail_a_ladder_for_getting_cheaper():
    with pytest.raises(ValueError) as exc:
        linear(per_mib=2_000_000).rises(tolerance=0.9, floor_bytes=0)
    assert exc.value.args[0] == "tolerance is a ratio at or above 1.0, got 0.9"


def test_a_ladder_that_gets_cheaper_per_byte_is_never_a_rise():
    """The shape of an improvement. Falling marginal cost is what amortisation looks like."""
    curve = ladder({4: 20_000_000, 8: 32_000_000, 16: 48_000_000})
    assert curve.rises(tolerance=1.0, floor_bytes=0) == ()


@given(
    per_mib=st.integers(min_value=1_000, max_value=10_000_000),
    fixed=st.integers(min_value=0, max_value=50_000_000),
    tolerance=st.floats(min_value=1.0, max_value=4.0),
)
def test_work_linear_in_the_bytes_never_rises_at_any_tolerance(per_mib, fixed, tolerance):
    """The property the gate rests on, stated directly.

    If the marginal cost were not constant under a linear model, every threshold here would be
    a threshold on the ladder's spacing rather than on the code.
    """
    assert linear(per_mib=per_mib, fixed=fixed).rises(tolerance=tolerance, floor_bytes=0) == ()


# --- the baseline -----------------------------------------------------------------------


def baseline(**overrides) -> Baseline:
    fields = {
        "architecture": "aarch64",
        "python": "3.13.14",
        "control": 487_878_037,
        "ladders": {"download": {mib * MIB: cost for mib, cost in HEALTHY_DOWNLOAD.items()}},
    }
    return Baseline(**{**fields, **overrides})


def test_a_baseline_round_trips_through_json_with_its_sizes_still_integers():
    """JSON has string keys, so a size read back as `"1048576"` would match no rung at all."""
    original = baseline()
    restored = Baseline.loads(original.dumps())
    assert restored == original
    assert restored.ladders["download"][1 * MIB] == 5_503_390


def test_a_baseline_missing_a_field_names_it_rather_than_comparing_against_nothing():
    with pytest.raises(ValueError) as exc:
        Baseline.loads('{"architecture": "aarch64", "python": "3.13.14", "control": 1}')
    assert exc.value.args[0] == "baseline is missing 'ladders'"


def test_a_baseline_from_another_machine_says_so_instead_of_applying():
    """The failure this project has written three cards about: a check that looked at nothing.

    A gate keyed to an architecture it is not running on must say which one it wanted, in the
    words that would make it run, rather than quietly passing.
    """
    assert baseline(architecture="x86_64").mismatch() == (
        "baseline was taken on x86_64 and this is aarch64; instruction counts do not cross "
        "instruction sets"
    )
    assert baseline(python="3.14.0").mismatch() == (
        "baseline was taken on CPython 3.14.0 and this is 3.13.14; a patch release moves every "
        "count here"
    )
    assert baseline().mismatch() is None


def test_a_run_inside_the_band_drifts_nothing():
    within = {mib: round(cost * 1.019) for mib, cost in HEALTHY_DOWNLOAD.items()}
    assert baseline().drifts(ladder(within), band=0.02) == ()


def test_a_run_outside_the_band_drifts_in_whichever_direction_it_left():
    costlier = ladder({**HEALTHY_DOWNLOAD, 16: round(HEALTHY_DOWNLOAD[16] * 1.5)})
    regressed = baseline().drifts(costlier, band=0.02)
    assert [drift.describe() for drift in regressed] == [
        "download at 16 MiB cost 65,211,224 instructions against a baseline of 43,474,149 (1.500x)"
    ]
    assert [drift.costlier for drift in regressed] == [True]

    cheaper = ladder({**HEALTHY_DOWNLOAD, 16: round(HEALTHY_DOWNLOAD[16] * 0.5)})
    improved = baseline().drifts(cheaper, band=0.02)
    assert [drift.costlier for drift in improved] == [False]


def test_a_direction_the_baseline_has_never_heard_of_drifts_nothing_and_is_reported():
    """An upload ladder against a download-only baseline. Silence here would read as agreement."""
    uploads = ladder(HEALTHY_DOWNLOAD, direction="upload")
    assert baseline().drifts(uploads, band=0.02) == ()
    assert baseline().unknown_rungs(uploads) == (1 * MIB, 4 * MIB, 8 * MIB, 16 * MIB)


def test_a_rung_the_baseline_does_not_carry_is_named_rather_than_skipped():
    grown = ladder({**HEALTHY_DOWNLOAD, 32: 86_000_000})
    assert baseline().unknown_rungs(grown) == (32 * MIB,)
    assert baseline().drifts(grown, band=0.02) == ()


def test_a_baseline_of_this_machine_records_what_makes_its_counts_reproducible():
    built = Baseline.of_this_machine(1_000, [ladder(HEALTHY_DOWNLOAD)])
    assert built.architecture == platform.machine()
    assert built.python == platform.python_version()
    assert built.mismatch() is None
    assert built.ladders["download"][16 * MIB] == 43_474_149


def test_the_committed_baseline_is_readable_and_covers_both_directions():
    """The file this repository actually ships, read the way the lane reads it.

    A baseline that does not parse, or that carries one direction, is a gate that fires on
    nothing -- and it would look exactly like a clean run.
    """
    committed = _ROOT / "benchmarks" / "instructions-aarch64.json"
    if not committed.exists():  # pragma: no cover - the file is committed
        pytest.skip("no aarch64 baseline in this checkout")
    loaded = Baseline.loads(committed.read_text())
    assert loaded.architecture == "aarch64"
    assert set(loaded.ladders) == {"download", "upload"}
    assert set(loaded.ladders["download"]) == {1 * MIB, 4 * MIB, 8 * MIB, 16 * MIB}
    assert loaded.control > 0


# --- the report -------------------------------------------------------------------------


def test_the_table_says_which_kind_of_run_it_was():
    """Three states in the baseline column, and a reader has to be able to tell them apart."""
    curve = ladder(HEALTHY_DOWNLOAD)
    without = render_ladder(curve, baseline=None)
    assert "| 1 MiB | 5,503,390 | 5,503,390 | -- | -- |" in without
    assert "Net of a 487,878,037-instruction control" in without

    grown = ladder({**HEALTHY_DOWNLOAD, 32: 86_000_000})
    with_baseline = render_ladder(grown, baseline=baseline())
    assert "| 16 MiB | 43,474,149 | 2,717,134 | 2,536,405 | 1.000x |" in with_baseline
    assert "| 32 MiB | 86,000,000 | 2,687,500 | 2,657,866 | not in baseline |" in with_baseline


# --- measuring --------------------------------------------------------------------------


def test_the_control_workload_transfers_nothing_and_the_others_name_their_file():
    control = workload_source("control", cwd=Path("/srv/measure"), source="")
    assert "sftp.get" not in control
    assert "sftp.put" not in control
    assert "open_local_server_transport(cwd='/srv/measure')" in control

    download = workload_source("download", cwd=Path("/srv/measure"), source="payload.bin")
    assert "await sftp.get('payload.bin', Path('/srv/measure') / \"received.bin\")" in download

    upload = workload_source("upload", cwd=Path("/srv/measure"), source="payload.bin")
    assert "publish=Publish(atomic=False, fsync=False)" in upload


def test_an_unknown_workload_is_refused_rather_than_measured_as_nothing():
    with pytest.raises(KeyError) as exc:
        workload_source("sideways", cwd=Path("/srv/measure"), source="p.bin")
    assert exc.value.args[0] == "sideways"


def test_the_cheapest_of_several_runs_is_kept(monkeypatch: pytest.MonkeyPatch):
    counts = iter([120, 100, 110])
    monkeypatch.setattr(_instructions, "measure", lambda *a, **k: next(counts))
    assert _instructions.measure_least("x", cwd=Path("/srv/measure"), samples=3) == 100


def test_measuring_zero_times_is_refused_rather_than_returning_an_empty_minimum():
    with pytest.raises(ValueError) as exc:
        measure_least("x", cwd=Path("/srv/measure"), samples=0)
    assert exc.value.args[0] == "samples must be at least 1, got 0"


def test_a_child_that_failed_is_not_a_measurement(monkeypatch: pytest.MonkeyPatch, tmp_path):
    class Failed:
        returncode = 1
        stderr = "Traceback: it did not run"

    monkeypatch.setattr(_instructions.subprocess, "run", lambda *a, **k: Failed())
    with pytest.raises(RuntimeError) as exc:
        measure("pass", cwd=tmp_path)
    assert exc.value.args[0] == "the measured child exited 1:\nTraceback: it did not run"


def test_output_with_no_count_in_it_is_not_a_measurement(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """Cachegrind that ran and said nothing. Returning 0 here would read as free work."""

    class Silent:
        returncode = 0
        stderr = "==1== Cachegrind, a high-precision tracing profiler"

    monkeypatch.setattr(_instructions.subprocess, "run", lambda *a, **k: Silent())
    with pytest.raises(RuntimeError) as exc:
        measure("pass", cwd=tmp_path)
    assert exc.value.args[0] == (
        "cachegrind printed no instruction count:\n"
        "==1== Cachegrind, a high-precision tracing profiler"
    )


def test_the_count_is_read_out_of_the_summary_with_its_thousands_separators(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    class Ran:
        returncode = 0
        stderr = "==1== \n==1== I refs:        455,866,374\n"

    monkeypatch.setattr(_instructions.subprocess, "run", lambda *a, **k: Ran())
    assert measure("pass", cwd=tmp_path) == 455_866_374


def test_the_measured_child_gets_a_replaced_environment_with_the_hash_seed_pinned(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    """The 0.1% an unpinned interpreter varies by is dict ordering, and it is the whole budget.

    The environment is replaced rather than layered for the same reason: a developer's exported
    variables change the child's initial stack, and two runs have to differ only in the thing
    under test.
    """
    seen = {}

    class Ran:
        returncode = 0
        stderr = "I refs:        1,000\n"

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        seen["argv"] = argv
        return Ran()

    monkeypatch.setenv("GANTRY_SFTP_NOISE", "loud")
    monkeypatch.setattr(_instructions.subprocess, "run", fake_run)
    measure("pass", cwd=tmp_path)

    assert seen["env"]["PYTHONHASHSEED"] == "0"
    assert "GANTRY_SFTP_NOISE" not in seen["env"]
    assert set(seen["env"]) == {"PATH", "HOME", "PYTHONHASHSEED"}
    assert seen["argv"][:2] == ["valgrind", "--tool=cachegrind"]
    assert "--cache-sim=no" in seen["argv"]


def test_a_missing_valgrind_names_the_package_that_carries_cachegrind(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(_instructions.shutil, "which", lambda _: None)
    assert valgrind_unavailable_reason() == (
        "valgrind is not installed (apt-get install valgrind); cachegrind is in it"
    )
    monkeypatch.setattr(_instructions.shutil, "which", lambda _: "/usr/bin/valgrind")
    assert valgrind_unavailable_reason() is None


def test_a_rise_and_a_drift_render_the_numbers_a_reader_would_check():
    """Both failure messages carry state rather than an adjective -- DESIGN.md 9's rule."""
    cheap = Step(smaller=rung(4, 10_000_000), larger=rung(8, 18_000_000))
    dear = Step(smaller=rung(8, 18_000_000), larger=rung(16, 50_000_000))
    assert Rise(step=dear, reference=cheap).describe() == (
        "8->16 MiB costs 4,000,000 instructions/MiB, 2.00x the 2,000,000 measured over 4->8 MiB"
    )
    assert Drift(direction="upload", rung=rung(16, 60_000_000), expected=50_000_000).describe() == (
        "upload at 16 MiB cost 60,000,000 instructions against a baseline of 50,000,000 (1.200x)"
    )

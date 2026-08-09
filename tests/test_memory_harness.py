"""The memory gate's arithmetic, in the lane that runs on every push.

Same placement argument as the two harness suites beside it: measuring a peak needs `/proc` and a
real `sftp-server`, but deciding whether a ladder is flat needs neither -- and that decision is
the only thing standing behind a resource claim this project prints on its deployment page.

The load-bearing test is :func:`test_a_transfer_that_really_held_the_file_is_caught`. It carries
two ladders measured on the same harness, differing by one injected line, and asserts the gate
separates them. Without it, every other test here proves the arithmetic runs and nothing about
whether it detects the thing it exists for.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _extra in (_ROOT / "benchmarks", _ROOT / "live-tests"):
    if str(_extra) not in sys.path:
        sys.path.append(str(_extra))

# Same chain and same reason as `test_instruction_harness.py`: `benchmarks/` reaches `resource`,
# which does not exist on Windows, and a module-scope import there aborts collection rather than
# failing a test.
_ = pytest.importorskip("resource", reason="benchmarks/ measures CPU via getrusage (POSIX-only)")

import _memory  # noqa: E402  # imported as a module so `subprocess` can be monkeypatched
from _instructions import MIB  # noqa: E402
from _memory import (  # noqa: E402
    Growth,
    MemoryLadder,
    MemoryRung,
    measure_peak,
    peak_unavailable_reason,
    render_memory,
    workload_source,
)

BOUNDED = {16: 30_008, 64: 30_108, 256: 30_084}
"""Peak KiB for a real download at each size. Measured, and flat: the claim holding."""

HOLDING = {16: 45_800, 64: 94_504, 256: 291_228}
"""The same downloads with one line added that keeps the received bytes alive.

Measured on the same harness, in the same temporary directory, differing from :data:`BOUNDED` by
a single ``read_bytes()``. It tracks the file one-for-one, which is what a client that buffers
whole files looks like from outside -- and is the failure this gate exists to refuse.
"""

CONTROL = 28_928
"""An empty session's peak, measured. What every "over control" figure is net of."""


def rung(mib: int, peak: int) -> MemoryRung:
    return MemoryRung(size_bytes=mib * MIB, peak_kib=peak)


def ladder(peaks: dict[int, int], direction: str = "download") -> MemoryLadder:
    return MemoryLadder(
        direction=direction,
        control=CONTROL,
        rungs=tuple(rung(mib, peak) for mib, peak in sorted(peaks.items())),
    )


# --- the finding ------------------------------------------------------------------------


def test_a_transfer_that_really_held_the_file_is_caught():
    """One injected `read_bytes()`, and the gate has to be able to tell.

    A gate nobody has watched fail is a claim rather than a check, and the two ladders here are
    the same code measured twice -- so this is not a synthetic curve chosen to fail, it is the
    real difference between bounded buffering and none.
    """
    grew = ladder(HOLDING).growth(tolerance=1.25)
    assert [g.describe() for g in grew] == [
        "64 MiB peaked at 94,504 KiB, 2.06x the 45,800 KiB reached at 16 MiB",
        "256 MiB peaked at 291,228 KiB, 6.36x the 45,800 KiB reached at 16 MiB",
    ]


def test_the_real_bounded_transfer_those_numbers_came_from_passes():
    """The other half of the pair: the shipped code, measured, raises nothing.

    A detector that fired on this curve would be worse than no detector.
    """
    assert ladder(BOUNDED).growth(tolerance=1.25) == ()
    assert round(ladder(BOUNDED).widest_span, 3) == 1.003


def test_the_bound_is_measured_over_the_control_not_in_absolute_terms():
    """29 MiB of interpreter is not what `depth x request size` bounds."""
    assert ladder(BOUNDED).over_control_kib() == 30_108 - CONTROL
    assert ladder(HOLDING).over_control_kib() == 291_228 - CONTROL


# --- rungs and ladders ------------------------------------------------------------------


def test_a_rung_refuses_what_cannot_have_been_measured():
    with pytest.raises(ValueError) as no_bytes:
        MemoryRung(size_bytes=0, peak_kib=1)
    assert no_bytes.value.args[0] == "a rung must move bytes, got 0"

    with pytest.raises(ValueError) as no_peak:
        MemoryRung(size_bytes=MIB, peak_kib=0)
    assert no_peak.value.args[0] == (
        "1048576 bytes peaked at 0 KiB; a process that reached no resident set was not measured"
    )


def test_a_ladder_refuses_what_it_cannot_read_a_shape_from():
    with pytest.raises(ValueError) as no_control:
        MemoryLadder(direction="download", control=0, rungs=(rung(1, 1), rung(2, 2)))
    assert no_control.value.args[0] == "the control peaked at 0 KiB; nothing was measured"

    with pytest.raises(ValueError) as one:
        MemoryLadder(direction="download", control=1, rungs=(rung(1, 1),))
    assert one.value.args[0] == "download has no shape: 1 rung"

    with pytest.raises(ValueError) as order:
        MemoryLadder(direction="upload", control=1, rungs=(rung(4, 2), rung(1, 1)))
    assert order.value.args[0] == "upload rungs are not strictly ascending"


def test_the_reference_is_the_smallest_peak_below_not_the_rung_before():
    """One rung that allocated early must not become every later rung's allowance.

    Against the previous rung, a curve that doubles and then holds reports one growth and then
    reads as flat -- which is a client that buffers, described as healthy.
    """
    grew = ladder({16: 30_000, 64: 60_000, 256: 60_500}).growth(tolerance=1.25)
    assert [g.rung.mib for g in grew] == [64.0, 256.0]
    assert [g.reference.mib for g in grew] == [16.0, 16.0]


def test_a_tolerance_below_one_would_fail_a_ladder_for_using_less():
    with pytest.raises(ValueError) as exc:
        ladder(BOUNDED).growth(tolerance=0.99)
    assert exc.value.args[0] == "tolerance is a ratio at or above 1.0, got 0.99"


def test_a_ladder_that_shrinks_is_never_growth():
    assert ladder({16: 40_000, 64: 30_000, 256: 29_000}).growth(tolerance=1.0) == ()


def test_the_span_and_the_steepest_step_are_different_questions():
    """A curve can step gently every rung and still double end to end."""
    creeping = ladder({16: 30_000, 64: 42_000, 256: 58_000})
    assert round(creeping.widest_span, 3) == 1.933
    assert round(creeping.steepest_step(), 3) == 1.400


# --- measuring --------------------------------------------------------------------------


def test_the_workload_shares_its_bodies_with_the_instruction_lane():
    """Two lanes measuring operations that drifted apart would report on different things."""
    download = workload_source("download", cwd=Path("/srv/measure"), source="p.bin")
    assert "await sftp.get('p.bin', Path('/srv/measure') / \"received.bin\")" in download
    assert download.endswith('if l.startswith("VmHWM:")))\n')

    control = workload_source("control", cwd=Path("/srv/measure"), source="")
    assert "sftp.get" not in control
    assert "sftp.put" not in control


def test_an_unknown_workload_is_refused_rather_than_measured_as_nothing():
    with pytest.raises(KeyError) as exc:
        workload_source("sideways", cwd=Path("/srv/measure"), source="p.bin")
    assert exc.value.args[0] == "sideways"


def test_the_peak_is_read_out_of_the_childs_own_report(monkeypatch: pytest.MonkeyPatch, tmp_path):
    class Ran:
        returncode = 0
        stdout = "some chatter\nPEAK_KIB 30084\n"
        stderr = ""

    monkeypatch.setattr(_memory.subprocess, "run", lambda *a, **k: Ran())
    assert measure_peak("pass", cwd=tmp_path) == 30_084


def test_a_child_that_failed_is_not_a_measurement(monkeypatch: pytest.MonkeyPatch, tmp_path):
    class Failed:
        returncode = 1
        stdout = ""
        stderr = "Traceback: it did not run"

    monkeypatch.setattr(_memory.subprocess, "run", lambda *a, **k: Failed())
    with pytest.raises(RuntimeError) as exc:
        measure_peak("pass", cwd=tmp_path)
    assert exc.value.args[0] == "the measured child exited 1:\nTraceback: it did not run"


def test_a_child_that_reported_no_peak_is_not_a_measurement(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    """Returning 0 here would read as a process that used no memory."""

    class Silent:
        returncode = 0
        stdout = "moved 16777216 bytes\n"
        stderr = ""

    monkeypatch.setattr(_memory.subprocess, "run", lambda *a, **k: Silent())
    with pytest.raises(RuntimeError) as exc:
        measure_peak("pass", cwd=tmp_path)
    assert exc.value.args[0] == "the child reported no peak:\nmoved 16777216 bytes\n"


def test_a_platform_without_proc_says_so_and_does_not_reach_for_getrusage(
    monkeypatch: pytest.MonkeyPatch,
):
    """The substitution that would look reasonable is the one that produced a false alarm.

    `ru_maxrss` is not a coarser `VmHWM`; across `posix_spawn` it reports the parent's peak, so
    a lane that fell back to it would compare this library against whatever the harness did.
    """
    monkeypatch.setattr(_memory.platform, "system", lambda: "Darwin")
    assert peak_unavailable_reason() == (
        "peak memory is read from /proc/self/status, which Darwin does not have; getrusage is "
        "not a substitute (it reports the parent's peak across posix_spawn)"
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="the lane's own platform")
def test_the_lane_is_available_on_the_platform_it_ships_for():
    """The unset case asserted, not assumed -- a skip reason nobody sees is a lane nobody runs."""
    assert peak_unavailable_reason() is None


@pytest.mark.skipif(platform.system() == "Linux", reason="the lane's own platform")
def test_the_lane_says_why_it_is_unavailable_on_a_platform_that_is_not_its_own():
    """The other half, and it is not the monkeypatched row above wearing a different hat.

    That row proves the branch fires when `platform.system()` answers `"Darwin"`. This one
    proves the answer here **is** that -- an unavailability that only ever appears under a
    substituted `platform.system` is a lane that could be silently available on a machine it
    cannot measure, reporting a peak read from a file that is not there (D-161).

    The whole sentence is asserted rather than a truthiness check, because a reason nobody can
    act on is the failure mode this function exists to avoid, and it interpolates the platform
    name -- so the two spellings have to agree on more than "not None".
    """
    reason = peak_unavailable_reason()
    assert reason == (
        f"peak memory is read from /proc/self/status, which {platform.system()} does not have; "
        f"getrusage is not a substitute (it reports the parent's peak across posix_spawn)"
    )


# --- the report -------------------------------------------------------------------------


def test_the_table_carries_the_bound_it_is_being_read_against():
    text = render_memory(ladder(BOUNDED), bound_bytes=64 * 261120)
    assert "| 16 MiB | 30,008 | 1,080 | 1.000x |" in text
    assert "| 256 MiB | 30,084 | 1,156 | 1.003x |" in text
    assert (
        "Control -- the same session opened and closed, moving no bytes -- peaked at 28,928" in text
    )
    assert "The documented bound for one transfer is 16 MiB" in text
    assert "the most any rung cost above the control was 1,180 KiB" in text


def test_a_growth_line_names_both_ends_rather_than_calling_it_a_leak():
    grown = Growth(rung=rung(256, 291_228), reference=rung(16, 45_800))
    assert grown.describe() == (
        "256 MiB peaked at 291,228 KiB, 6.36x the 45,800 KiB reached at 16 MiB"
    )

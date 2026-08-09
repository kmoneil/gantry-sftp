"""The leak detector, watched failing.

**D-115.** DoD 2's "call something inherent? probe it" applies to detectors first: one nobody
has watched fail is a decoration. So this file leaks on purpose, twice, in the two shapes this
repository has actually had -- and asserts the detector reports them, names what survived, and
stays silent on work that cleans up after itself.

These call :mod:`tests.leakcheck` directly rather than relying on the autouse fixture, because
that fixture is armed by an environment variable and a proof that only runs in one lane is a
proof that rots in the other.
"""

from __future__ import annotations

import gc
import subprocess
from collections import Counter
from pathlib import Path

import anyio
import pytest

import leakcheck
from gantry_sftp.session import open_session
from gantry_sftp.transport import Transport, open_local_server_transport
from leakcheck import (
    LEAK_CHECK_ENV,
    WATCHED_TYPES,
    ResourceCount,
    fd_count,
    leak_check_enabled,
    live_resources,
    settle,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """One backend: the subject is the detector, not the event loop."""
    return "asyncio"


# --- the detector fires, which is the whole point -------------------------------------------


async def test_it_catches_a_child_process_that_was_never_closed(
    sftp_server_binary: Path, tmp_path: Path
):
    """The recorded bug's exact shape: `Process.aclose()` not called (see the memory).

    Reaping the child is not releasing it -- the pipe transports stay open and cleanup is
    deferred to the garbage collector, which is what made the symptom appear somewhere else.
    """
    leaked = []
    before = settle()
    process = await anyio.open_process(
        [str(sftp_server_binary)],
        cwd=str(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    process.terminate()
    _ = await process.wait()
    leaked.append(process)  # deliberately no aclose()
    after = settle()

    grown = after.growth_since(before)
    assert "Process" in grown, f"the detector missed a leaked child process: {grown}"

    # And it goes quiet once the leak is cleaned up, which is the half that proves the
    # assertion above was not just measuring noise. `del` is required and is itself the
    # detector behaving correctly: a live local in this frame is a live reference, and
    # `aclose()` alone leaves the object reachable.
    await process.aclose()
    leaked.clear()
    del process
    assert "Process" not in settle().growth_since(before)


async def test_it_catches_an_abandoned_async_generator_chain(
    sftp_server_binary: Path, tmp_path: Path
):
    """The other recorded shape: `async for` does not close the generator.

    A listing walked away from mid-iteration holds the whole chain -- and with it the session,
    the dispatcher and the transport, which is why the report names four types rather than one.
    """
    _ = (tmp_path / "a.txt").write_bytes(b"x")
    _ = (tmp_path / "b.txt").write_bytes(b"y")

    leaked = []
    before = settle()
    async with (
        open_local_server_transport(cwd=str(tmp_path)) as transport,
        open_session(transport) as sftp,
    ):
        scan_manager = sftp.scandir(".")
        scan = await scan_manager.__aenter__()
        iterator = scan.__aiter__()
        _ = await iterator.__anext__()
        leaked.append((scan_manager, scan, iterator))
    after = settle()

    grown = after.growth_since(before)
    assert grown, "the detector missed an abandoned async generator chain"
    # The transport is what an operator would recognise; naming it is the reporting half.
    assert "SubprocessTransport" in grown, grown

    leaked.clear()
    del scan_manager, scan, iterator
    _ = gc.collect()


async def test_it_stays_quiet_when_the_work_cleans_up_after_itself(
    sftp_server_binary: Path, tmp_path: Path
):
    """A detector that fires on correct code is one that gets switched off.

    Measured over 294 real tests while this was designed: zero watched-type growth. The same
    work is done three times here because the *first* pass fills caches, and a detector that
    could not tell a cache from a leak is the instrument this file rejected.
    """
    _ = (tmp_path / "a.txt").write_bytes(b"x")

    async def transfer() -> None:
        async with (
            open_local_server_transport(cwd=str(tmp_path)) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.listdir(".")
            _ = await sftp.realpath(".")

    await transfer()  # warm: one-off structures are not a leak
    for _ in range(3):
        before = settle()
        await transfer()
        assert settle().growth_since(before) == {}


# --- the reporting, and the states that must not read as "clean" ----------------------------


def test_growth_names_every_type_that_grew_and_ignores_the_ones_that_shrank():
    before = ResourceCount(types=Counter({"Session": 1, "Process": 3}), fds=10)
    after = ResourceCount(types=Counter({"Session": 4, "Process": 1}), fds=10)
    assert after.growth_since(before) == {"Session": 3}


def test_growth_reports_descriptors_when_both_readings_could_see_them():
    before = ResourceCount(types=Counter(), fds=10)
    after = ResourceCount(types=Counter(), fds=13)
    assert after.growth_since(before) == {"open fds": 3}


@pytest.mark.parametrize(
    ("before_fds", "after_fds"),
    [(None, 13), (10, None), (None, None)],
)
def test_an_unmeasurable_descriptor_count_reports_nothing_rather_than_zero(
    before_fds: int | None, after_fds: int | None
):
    """The failure this whole module is written against: a counter that cannot see.

    `None` means "not measured". Reporting it as a clean zero would be proof of absence
    manufactured from an absence of proof, which is exactly how the earlier `/proc` note left
    an fd scan reading as a passing test.
    """
    before = ResourceCount(types=Counter(), fds=before_fds)
    after = ResourceCount(types=Counter(), fds=after_fds)
    assert after.growth_since(before) == {}


def test_the_descriptor_count_is_readable_here_and_tracks_opens_and_closes():
    """Probed, not assumed -- and it contradicts the note that said otherwise.

    `/proc/<pid>/fd` was recorded in 2026-07 as unreadable in this sandbox. It reads fine now.
    This test is the calibration step the earlier note said any fd-based proof needs: open
    known descriptors, assert the counter sees them, close them, assert it sees that too. If
    the sandbox regresses, this skips rather than silently reporting clean.

    **It stopped skipping on macOS in D-161.** There is no `/proc` there at all, so the whole
    descriptor half of every leak reading was `None` -- honest, and therefore silent. `/dev/fd`
    is the same per-process view under another name and this row is what proves it counts:
    running the calibration is the only thing separating "the fallback works" from "the
    fallback returns a number".
    """
    baseline = fd_count()
    if baseline is None:
        pytest.skip("no directory listing this process's descriptors is readable here")

    # SIM115 is suppressed rather than obeyed: holding these open *is* the measurement, and a
    # context manager would close them before the counter could see them.
    held = [Path("/dev/null").open("rb") for _ in range(5)]  # noqa: SIM115
    try:
        opened = fd_count()
        assert opened is not None
        assert opened - baseline == 5
    finally:
        for handle in held:
            handle.close()
    assert fd_count() == baseline


def test_the_descriptor_count_falls_through_to_the_next_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """The fallback that arms this on macOS, exercised where the first candidate is missing.

    On Linux `/proc/self/fd` answers and the second entry is never reached; on macOS the first
    raises and the second is the whole measurement. **A loop that took the first `OSError` as
    the answer would behave identically on Linux and count nothing on a Mac** -- so the fall-
    through is asserted on every platform rather than only where it happens to be load-bearing.
    """
    monkeypatch.setattr(leakcheck, "_FD_DIRECTORIES", (tmp_path / "no-such-dir", Path("/dev/fd")))
    counted = fd_count()
    assert counted is not None, "an unreadable first candidate ended the search"
    assert counted > 0


def test_the_descriptor_count_is_none_when_no_directory_answers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """The third state: unmeasurable, and it must say so rather than report a clean zero.

    `sum(1 for _ in ...)` over an empty directory is `0`, which is the shape of a perfect
    reading, and that collision is the reason this returns `None` at all.
    """
    monkeypatch.setattr(leakcheck, "_FD_DIRECTORIES", (tmp_path / "nope", tmp_path / "also-nope"))
    assert fd_count() is None


# --- arming, and the list that has to be maintained by hand ---------------------------------


@pytest.mark.parametrize(
    ("value", "armed"),
    [("1", True), ("yes", True), ("", False), ("   ", False)],
)
def test_the_check_is_armed_by_the_environment(value: str, armed: bool):
    assert leak_check_enabled({LEAK_CHECK_ENV: value}) is armed


def test_the_check_is_off_when_the_variable_is_absent():
    assert leak_check_enabled({}) is False


def test_every_transport_implementation_is_watched():
    """`WATCHED_TYPES` is maintained by hand, so something has to notice a new transport.

    A transport added to the package and not added there would leak silently under a detector
    that reports clean -- the exact shape this module exists to refuse. This is the
    enumerator sweep DoD 2 asks for, spelled as a test rather than as a habit.
    """
    implementations = {
        cls.__name__ for cls in Transport.__subclasses__() if not cls.__name__.startswith("_")
    }
    missing = implementations - WATCHED_TYPES
    assert not missing, (
        f"{sorted(missing)} implement Transport and are not in WATCHED_TYPES, so a test "
        f"leaking one would be reported as clean; add them to tests/leakcheck.py"
    )


def test_live_resources_reports_a_count_and_a_descriptor_reading():
    counted = live_resources()
    assert isinstance(counted.types, Counter)
    assert counted.fds is None or counted.fds > 0

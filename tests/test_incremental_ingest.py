"""The two traps in a scheduled ingest, as tests rather than as prose.

**D-100.** The example demonstrates them and `test_examples.py` runs it, which catches a total
break. This file is the narrower proof: it fails if somebody "simplifies" `>=` back to `>`, or
advances the watermark to "now", which are the two edits that look like cleanups and lose data
silently.

Driven against a real `sftp-server` on a pipe, because the trap *is* the protocol -- v3's
`ACMODTIME` is whole seconds -- and a fake with a float timestamp in it would confirm only that
its author knew about the problem. Modification times are set with `os.utime` rather than raced,
so the same-second collision is deterministic on any machine.
"""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "examples") not in sys.path:
    # Appended rather than inserted, matching `test_benchmark_harness.py`: `examples/` must
    # not win a name lookup against anything already imported.
    sys.path.append(str(_ROOT / "examples"))

from incremental_ingest import Watermark, populate, sweep  # noqa: E402

from gantry_sftp.session import DirEntry, open_session  # noqa: E402
from gantry_sftp.transport import open_local_server_transport  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """One backend: the subject is the protocol's timestamp granularity, not the event loop."""
    return "asyncio"


@pytest.fixture
def drop(tmp_path: Path, sftp_server_binary: Path) -> Path:
    """The example's own drop directory, so the test and the example cannot drift."""
    directory = tmp_path / "drop"
    directory.mkdir()
    populate(directory)
    return directory


async def listed(directory: Path) -> dict[str, DirEntry]:
    async with (
        open_local_server_transport(cwd=str(directory)) as transport,
        open_session(transport) as sftp,
    ):
        return {entry.name: entry for entry in await sftp.listdir(".")}


# --- trap 1: the same second ----------------------------------------------------------------


async def test_two_files_one_second_apart_are_indistinguishable_over_the_protocol(drop: Path):
    """The fact everything else here rests on, asserted against a real server.

    Local mtimes differ by 0.8 s. v3 carries whole seconds, so the wire cannot say which came
    first -- and any watermark comparison that assumes it can is wrong for that pair.
    """
    entries = await listed(drop)
    earlier, later = entries["orders-002.csv"], entries["orders-003.csv"]

    local = ((drop / "orders-002.csv").stat().st_mtime, (drop / "orders-003.csv").stat().st_mtime)
    assert local[0] < local[1], "the fixture must write them at different sub-second offsets"
    assert earlier.modified == later.modified, (
        "v3 ACMODTIME is whole seconds; if these differ the premise of this file is gone"
    )


async def test_a_file_landing_in_the_watermarks_own_second_is_still_taken(drop: Path):
    """The regression test the card was filed for.

    Fails if `wants` uses `>` instead of `>=`. The file is not older than the watermark -- the
    protocol simply cannot say -- and excluding it loses it on this run and every run after.
    """
    entries = await listed(drop)
    watermark = Watermark(drop.parent / "wm.json")
    # A first run that stopped after orders-002.csv, which is what set the watermark.
    watermark.advance([entries["orders-001.csv"], entries["orders-002.csv"]])

    assert watermark.wants(entries["orders-003.csv"]), (
        "orders-003.csv shares orders-002.csv's whole second and would be lost forever"
    )


async def test_the_file_that_set_the_watermark_is_not_taken_twice(drop: Path):
    """The other half, and why `>=` alone is not the fix.

    Without the record of names taken at the watermark's second, `>=` re-transfers the file
    that set it on every single run.
    """
    entries = await listed(drop)
    watermark = Watermark(drop.parent / "wm.json")
    watermark.advance([entries["orders-002.csv"]])

    assert not watermark.wants(entries["orders-002.csv"])


async def test_a_second_sweep_takes_nothing_when_nothing_changed(drop: Path, tmp_path: Path):
    """End to end: the loop is idempotent, which is the property an operator relies on."""
    landing = tmp_path / "landing"
    landing.mkdir()
    watermark = Watermark(tmp_path / "wm.json")

    async with (
        open_local_server_transport(cwd=str(drop)) as transport,
        open_session(transport) as sftp,
    ):
        first = await sweep(sftp, ".", watermark, landing)
        second = await sweep(sftp, ".", watermark, landing)

    assert set(first) == {
        "orders-001.csv",
        "orders-002.csv",
        "orders-003.csv",
        "orders-004.csv",
    }, "the first run takes every .csv, including both halves of the same-second pair"
    assert second == [], "nothing changed, so the second run must take nothing"
    assert not (landing / "README.txt").exists(), "an ingest takes what it recognises"


# --- trap 2: what the watermark advances to -------------------------------------------------


async def test_the_watermark_advances_to_the_newest_file_seen_and_not_to_now(drop: Path):
    """Fails if somebody advances the watermark to `datetime.now()`.

    "Now" is later than the newest file this run observed, so anything landing between the
    listing and the write is skipped by the *next* run as well. The largest mtime actually
    seen cannot skip a file, because a file nobody has listed yet is not in that maximum.
    """
    entries = await listed(drop)
    taken = [entries[name] for name in ("orders-001.csv", "orders-002.csv", "orders-003.csv")]
    watermark = Watermark(drop.parent / "wm.json")
    watermark.advance(taken)

    newest = max(entry.modified for entry in taken if entry.modified is not None)
    assert watermark.taken_at == newest
    assert watermark.taken_at < datetime.now(UTC), "a watermark ahead of the newest file skips"

    # And the file that landed during the run -- newer than everything taken -- is still
    # picked up next time, which is the whole point of not jumping ahead.
    assert watermark.wants(entries["orders-004.csv"])


async def test_the_watermark_never_moves_backwards(drop: Path):
    """A late-arriving old file must not rewind the watermark and re-take everything."""
    entries = await listed(drop)
    watermark = Watermark(drop.parent / "wm.json")
    watermark.advance([entries["orders-004.csv"]])
    ahead = watermark.taken_at

    watermark.advance([entries["orders-001.csv"]])
    assert watermark.taken_at == ahead


async def test_the_names_are_reset_when_the_watermark_moves(drop: Path):
    """Otherwise the record grows without bound and starts excluding unrelated files."""
    entries = await listed(drop)
    watermark = Watermark(drop.parent / "wm.json")
    watermark.advance([entries["orders-002.csv"], entries["orders-003.csv"]])
    assert watermark.names == {"orders-002.csv", "orders-003.csv"}

    watermark.advance([entries["orders-004.csv"]])
    assert watermark.names == {"orders-004.csv"}


async def test_the_watermark_survives_a_restart(drop: Path):
    """A scheduled job is a new process every time, so the state has to round-trip."""
    entries = await listed(drop)
    path = drop.parent / "wm.json"
    first = Watermark(path)
    first.advance([entries["orders-002.csv"], entries["orders-003.csv"]])

    reloaded = Watermark(path)
    assert reloaded.taken_at == first.taken_at
    assert reloaded.names == first.names
    assert not reloaded.wants(entries["orders-002.csv"])
    assert reloaded.wants(entries["orders-004.csv"])


# --- the third state: a server that sends no timestamp --------------------------------------


async def test_an_entry_with_no_modification_time_is_taken_rather_than_skipped(drop: Path):
    """v3 permits a listing with no ACMODTIME, and the choice has to be explicit.

    Treating a missing timestamp as 1970 makes the file look ancient and it is never ingested
    -- silent loss again, by a different route. The example takes it, and says so.
    """
    watermark = Watermark(drop.parent / "wm.json")
    watermark.advance([entry for entry in (await listed(drop)).values() if entry.is_file])

    # An entry the server described without an ACMODTIME. Built here rather than provoked,
    # because no server this project can start omits it on demand -- and the branch is a
    # decision the example makes, so it is asserted rather than left to a server's mood.
    borrowed = (await listed(drop))["README.txt"].attrs
    undated = DirEntry(
        filename=b"mystery.csv",
        longname=b"",
        attrs=replace(borrowed, times=None),
    )
    assert undated.modified is None
    assert watermark.wants(undated)


async def test_an_empty_run_leaves_the_watermark_alone(drop: Path):
    """Nothing taken is not a reason to move: it is the ordinary case for a quiet directory."""
    entries = await listed(drop)
    watermark = Watermark(drop.parent / "wm.json")
    watermark.advance([entries["orders-002.csv"]])
    before = watermark.taken_at

    watermark.advance([])
    assert watermark.taken_at == before


async def test_the_fixture_writes_a_same_second_pair_at_all(drop: Path):
    """The fixture is the premise, so it gets its own assertion rather than being trusted."""
    a = (drop / "orders-002.csv").stat().st_mtime
    b = (drop / "orders-003.csv").stat().st_mtime
    assert int(a) == int(b), "the pair must share a whole second"
    assert a != b, "...and differ within it, or the test proves nothing about truncation"
    assert timedelta(seconds=b - a) < timedelta(seconds=1)


def test_the_example_sets_times_rather_than_racing_them(tmp_path: Path):
    """No `time.sleep`, no "write two files quickly and hope". Determinism is the point."""
    directory = tmp_path / "drop"
    directory.mkdir()
    populate(directory)
    stamps = {path.name: path.stat().st_mtime for path in directory.iterdir()}
    # Every one is a value the example chose, not a value the clock supplied.
    assert all(stamp < datetime.now(UTC).timestamp() for stamp in stamps.values())
    assert len({int(stamp) for stamp in stamps.values()}) < len(stamps), (
        "at least one whole second must be shared, or trap 1 is not demonstrated"
    )
    assert os.path.getmtime(directory / "orders-003.csv") > os.path.getmtime(  # noqa: PTH204
        directory / "orders-002.csv"
    )

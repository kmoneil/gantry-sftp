"""The mirror's comparison and its record (D-164).

**A wrong skip here is data loss with a green result**, so this file's job is to pin every rung
of the ladder in :func:`compare_for_sync` and, more importantly, the *order* of the rungs. An
implementation that answered the right thing for the wrong reason would pass a test that only
checked the decision, which is why every row asserts the reason string too.

Nothing here needs a server. The comparison is a pure function over two
:class:`~gantry_sftp.codec.Attrs` and a record, which is the whole point of it being a separate
module -- the decision that loses data is testable without the machinery that transfers bytes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import Attrs, Times
from gantry_sftp.session import (
    MANIFEST_VERSION,
    Comparison,
    ManifestEntry,
    SyncDecision,
    SyncManifest,
    SyncReason,
    compare_for_sync,
    local_dir_entry,
)

SENT = ManifestEntry(local_size=28, local_mtime=1_700_000_000, remote_size=28, remote_mtime=999)
"""One file as it was when it was last sent.

The remote mtime is deliberately *not* the local one: with ``preserve_times`` off -- the default
-- the destination stamps the upload time, and a record that assumed the two matched would be a
record no real run could produce.
"""

LOCAL = Attrs(size=28, times=Times(atime=0, mtime=1_700_000_000))
REMOTE = Attrs(size=28, times=Times(atime=0, mtime=999))


# --- the ladder, rung by rung -------------------------------------------------------------


def test_nothing_on_record_transfers() -> None:
    """The first run, and every path the mirror has not seen before."""
    verdict = compare_for_sync(LOCAL, REMOTE, None)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.NO_RECORD)


def test_a_matching_pair_on_both_sides_is_the_only_skip() -> None:
    verdict = compare_for_sync(LOCAL, REMOTE, SENT)
    assert verdict == Comparison(SyncDecision.SKIPPED, SyncReason.IDENTICAL)
    assert not verdict.transfers


def test_a_local_size_change_transfers() -> None:
    verdict = compare_for_sync(Attrs(size=29, times=LOCAL.times), REMOTE, SENT)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.LOCAL_SIZE_CHANGED)


def test_a_local_mtime_change_transfers() -> None:
    """The ordinary edit-in-place, which does not have to change the size to matter."""
    changed = Attrs(size=28, times=Times(atime=0, mtime=1_700_000_001))
    verdict = compare_for_sync(changed, REMOTE, SENT)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.LOCAL_MTIME_CHANGED)


def test_a_file_deleted_on_the_server_transfers() -> None:
    """The listing no longer has it, so the record describes something that is gone."""
    verdict = compare_for_sync(LOCAL, None, SENT)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.REMOTE_GONE)


def test_a_file_truncated_on_the_server_transfers() -> None:
    """**The case a record-only comparison cannot see, and the reason both sides are stored.**

    The local file is untouched and matches the record exactly, so every local check passes. If
    the comparison stopped there it would skip, and the destination would keep the truncated
    copy forever -- a wrong skip, silent, produced by the mechanism meant to prevent them.
    """
    verdict = compare_for_sync(LOCAL, Attrs(size=3, times=REMOTE.times), SENT)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.REMOTE_SIZE_CHANGED)


def test_a_file_rewritten_on_the_server_at_the_same_size_transfers() -> None:
    """Same length, different content, and the mtime is the only thing that says so."""
    verdict = compare_for_sync(LOCAL, Attrs(size=28, times=Times(atime=0, mtime=1000)), SENT)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.REMOTE_MTIME_CHANGED)


def test_a_server_that_reports_no_size_is_undecidable_and_still_sends() -> None:
    """Not folded into "same", and not folded into a plain transfer either.

    Both halves matter. Calling it "same" loses the file; calling it "transferred" hides which
    entries could not be checked, which is the report a careful operator actually wants.
    """
    verdict = compare_for_sync(LOCAL, Attrs(times=REMOTE.times), SENT)
    assert verdict == Comparison(SyncDecision.UNDECIDABLE, SyncReason.REMOTE_SIZE_UNREPORTED)
    assert verdict.transfers


def test_a_server_that_reports_no_times_is_undecidable_and_still_sends() -> None:
    verdict = compare_for_sync(LOCAL, Attrs(size=28), SENT)
    assert verdict == Comparison(SyncDecision.UNDECIDABLE, SyncReason.REMOTE_TIMES_UNREPORTED)
    assert verdict.transfers


def test_a_local_entry_with_no_attributes_is_undecidable() -> None:
    """Unreachable from `local_dir_entry`, handled because `Attrs` is a shared type.

    A caller can build one by hand, and a comparison that assumed the local half was total would
    read "no size" as "size matches" -- the wrong direction, from the half that is supposed to be
    the reliable one.
    """
    verdict = compare_for_sync(Attrs(), REMOTE, SENT)
    assert verdict == Comparison(SyncDecision.UNDECIDABLE, SyncReason.LOCAL_ATTRS_UNREPORTED)
    assert verdict.transfers


# --- the order of the rungs, which is the part an implementation gets wrong ----------------


def test_local_evidence_outranks_a_server_that_volunteers_nothing() -> None:
    """A changed local file transfers even when the remote half cannot be read at all.

    The failure this catches is a ladder that asks the server first: the entry would come back
    *undecidable* rather than *transfer*, which sends the file either way today -- and would
    silently become a skip the moment somebody decided undecidable was cheap to ignore.
    """
    changed = Attrs(size=999, times=LOCAL.times)
    verdict = compare_for_sync(changed, Attrs(), SENT)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.LOCAL_SIZE_CHANGED)


def test_no_record_outranks_every_other_rung() -> None:
    """Even when both sides look unreadable, an unknown path is a transfer and says so."""
    verdict = compare_for_sync(Attrs(), None, None)
    assert verdict == Comparison(SyncDecision.TRANSFER, SyncReason.NO_RECORD)


def test_a_remote_change_is_only_consulted_once_the_local_half_matches() -> None:
    """Both sides differ; the report names the local one, because that is what was asked first.

    Pinned because the reason is the audit trail. "Why did this re-send" answered with the
    server's state, when the local file had changed too, sends an operator looking in the wrong
    place.
    """
    changed = Attrs(size=29, times=LOCAL.times)
    verdict = compare_for_sync(changed, Attrs(size=3, times=Times(atime=0, mtime=5)), SENT)
    assert verdict.reason == SyncReason.LOCAL_SIZE_CHANGED


# --- what a local entry actually carries ---------------------------------------------------


def test_a_local_entry_carries_the_times_the_comparison_needs(tmp_path: Path) -> None:
    """`local_dir_entry` gained `times` for D-164, and nothing else asserts it.

    The whole comparison rests on this: an entry that dropped its modification time would make
    every file undecidable, forever, with no test failing.
    """
    target = tmp_path / "report.csv"
    _ = target.write_bytes(b"payload")
    os.utime(target, (1_700_000_000.9, 1_700_000_000.9))

    entry = local_dir_entry(b"report.csv", target.stat())

    assert entry.attrs.size == 7
    assert entry.attrs.times is not None
    assert entry.attrs.times.mtime == 1_700_000_000


def test_a_local_mtime_is_truncated_rather_than_rounded(tmp_path: Path) -> None:
    """`int()`, not `round()`, and the difference is a file dated into the future.

    A `.9` fraction rounds *up* to the next second, which is a modification that has not
    happened. Against a wire timestamp of the truncated value that compares unequal, so a
    rounding implementation re-sends the file on every run.
    """
    target = tmp_path / "report.csv"
    _ = target.write_bytes(b"payload")
    os.utime(target, (1_700_000_000.9, 1_700_000_000.9))

    entry = local_dir_entry(b"report.csv", target.stat())

    assert entry.attrs.times is not None
    assert entry.attrs.times.mtime == 1_700_000_000, "rounded up rather than truncated"


# --- the manifest ---------------------------------------------------------------------------


def test_a_manifest_round_trips_through_disk(tmp_path: Path) -> None:
    manifest = SyncManifest.empty()
    manifest.record(b"/drop/report.csv", SENT)
    manifest.save(tmp_path / "state.json")

    assert SyncManifest.load(tmp_path / "state.json").recorded(b"/drop/report.csv") == SENT


def test_a_manifest_round_trips_a_name_that_is_not_valid_utf8(tmp_path: Path) -> None:
    """The names that are the reason you needed a mirror are the ones a naive format loses.

    JSON keys are `str`, and the remote path is bytes the server chose. `decode_name` is
    `surrogateescape`, `json.dumps` escapes a lone surrogate, and `json.loads` gives it back --
    asserted here rather than trusted, because the failure is a file that silently re-sends
    forever or, worse, matches the wrong record.
    """
    odd = b"/drop/rep\xe9ort.csv"
    manifest = SyncManifest.empty()
    manifest.record(odd, SENT)
    manifest.save(tmp_path / "state.json")

    assert SyncManifest.load(tmp_path / "state.json").recorded(odd) == SENT


def test_an_absent_manifest_loads_as_empty(tmp_path: Path) -> None:
    """The first run. Not an error -- there is nothing to have known yet."""
    assert SyncManifest.load(tmp_path / "never-written.json").entries == {}


def test_a_corrupt_manifest_loads_as_empty_rather_than_raising(tmp_path: Path) -> None:
    """A truncated file costs one full re-send. Raising costs the run.

    The file is a cache of evidence, so "unreadable" and "nothing recorded" are the same fact,
    and the comparison already resolves the second one safely.
    """
    state = tmp_path / "state.json"
    _ = state.write_text('{"version": 1, "entries": {"a"', encoding="utf-8")
    assert SyncManifest.load(state).entries == {}


def test_a_manifest_from_a_future_version_is_refused(tmp_path: Path) -> None:
    """Parsed on a best-effort basis, a field this version does not understand is a wrong skip."""
    state = tmp_path / "state.json"
    _ = state.write_text(
        json.dumps({"version": MANIFEST_VERSION + 1, "entries": {"/a": SENT.as_json()}}),
        encoding="utf-8",
    )
    assert SyncManifest.load(state).entries == {}


@pytest.mark.parametrize(
    ("record", "why"),
    [
        ({"local_size": 1}, "missing three fields"),
        ({"local_size": 1, "local_mtime": 2, "remote_size": 3, "remote_mtime": "4"}, "a string"),
        ({"local_size": 1, "local_mtime": 2, "remote_size": 3, "remote_mtime": None}, "a null"),
        ({"local_size": True, "local_mtime": 2, "remote_size": 3, "remote_mtime": 4}, "a bool"),
        ("not an object", "not a mapping at all"),
    ],
)
def test_one_unusable_record_is_dropped_and_the_rest_survive(
    tmp_path: Path, record: object, why: str
) -> None:
    """A bad line loses one path's evidence, not the whole file's.

    The `bool` row is the one that would slip through a naive check: `True` is an `int` in
    Python, so it type-checks as a size, round-trips as `true`, and compares unequal against the
    1 it was meant to be.
    """
    state = tmp_path / "state.json"
    _ = state.write_text(
        json.dumps(
            {"version": MANIFEST_VERSION, "entries": {"/bad": record, "/ok": SENT.as_json()}}
        ),
        encoding="utf-8",
    )

    loaded = SyncManifest.load(state)

    assert loaded.recorded(b"/bad") is None, f"kept a record that is {why}"
    assert loaded.recorded(b"/ok") == SENT


def test_saving_leaves_no_partial_file_behind(tmp_path: Path) -> None:
    """Written to a sibling and renamed, so an interrupted save cannot truncate the record."""
    manifest = SyncManifest.empty()
    manifest.record(b"/drop/report.csv", SENT)
    manifest.save(tmp_path / "state.json")

    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"]


def test_saving_replaces_an_earlier_record_for_the_same_path(tmp_path: Path) -> None:
    later = ManifestEntry(local_size=1, local_mtime=2, remote_size=3, remote_mtime=4)
    manifest = SyncManifest.empty()
    manifest.record(b"/a", SENT)
    manifest.record(b"/a", later)
    manifest.save(tmp_path / "state.json")

    assert SyncManifest.load(tmp_path / "state.json").recorded(b"/a") == later


@given(
    local_size=st.integers(min_value=0, max_value=2**63 - 1),
    local_mtime=st.integers(min_value=0, max_value=2**32 - 1),
    remote_size=st.integers(min_value=0, max_value=2**63 - 1),
    remote_mtime=st.integers(min_value=0, max_value=2**32 - 1),
    name=st.binary(min_size=1, max_size=40).filter(lambda raw: b"\x00" not in raw),
)
def test_any_entry_survives_the_json_round_trip(
    tmp_path_factory: pytest.TempPathFactory,
    local_size: int,
    local_mtime: int,
    remote_size: int,
    remote_mtime: int,
    name: bytes,
) -> None:
    """The parse shape gets the treatment every other parse shape in this repo gets.

    Sizes reach 2**63 and times 2**32 because those are the protocol's own ceilings, and a
    manifest that silently narrowed either would compare unequal against a file it had just
    written.
    """
    entry = ManifestEntry(local_size, local_mtime, remote_size, remote_mtime)
    state = tmp_path_factory.mktemp("manifest") / "state.json"
    manifest = SyncManifest.empty()
    manifest.record(b"/" + name, entry)
    manifest.save(state)

    assert SyncManifest.load(state).recorded(b"/" + name) == entry

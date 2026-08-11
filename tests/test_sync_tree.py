"""``sync_tree`` against a real ``sftp-server`` on a pipe (D-164).

**Driven against a real server rather than a fake, and the reason is the same one
`test_incremental_ingest.py` gives**: the thing under test is what a v3 listing actually carries
and what a v3 ``ACMODTIME`` actually holds. A fake with a float timestamp and a total ``Attrs``
in it would confirm only that its author knew what the answer should be -- and the answer here
was measured, not assumed: with ``preserve_times`` off the destination stamps the *upload* time,
which is why the comparison is against a record rather than against the remote clock.

Modification times are set with ``os.utime`` rather than raced, so a "nothing changed" run is
deterministic on any machine.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from gantry_sftp.session import (
    Session,
    SyncDecision,
    SyncManifest,
    SyncReason,
    SyncResult,
    open_session,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """One backend: the subject is the protocol and the filesystem, not the event loop."""
    return "asyncio"


@asynccontextmanager
async def _session() -> AsyncGenerator[Session]:
    server = find_sftp_server()
    if server is None:
        pytest.skip("sftp-server not found; it ships in openssh-server")
    async with (
        open_local_server_transport(server_path=server) as transport,
        open_session(transport) as sftp,
    ):
        yield sftp


@pytest.fixture
def source(tmp_path: Path) -> Path:
    """A small tree with one nested directory, at a pinned modification time."""
    root = tmp_path / "source"
    (root / "nested").mkdir(parents=True)
    _ = (root / "report.csv").write_bytes(b"id,total\n1,10\n")
    _ = (root / "nested" / "detail.csv").write_bytes(b"id,line\n1,a\n")
    for path in (root / "report.csv", root / "nested" / "detail.csv"):
        os.utime(path, (1_700_000_000, 1_700_000_000))
    return root


def _decisions(result: SyncResult) -> dict[bytes, SyncDecision]:
    """Outcomes keyed by the file's name, so a row does not depend on tmp_path's spelling."""
    return {
        outcome.remote_path.rsplit(b"/", 1)[-1]: outcome.decision for outcome in result.outcomes
    }


async def test_a_first_run_transfers_everything_and_records_it(
    source: Path, tmp_path: Path
) -> None:
    """Nothing is on record, so nothing can be proven identical."""
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        result = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert result.transferred == 2
    assert result.skipped == 0
    assert result.undecidable == 0
    assert result.complete
    assert (destination / "report.csv").read_bytes() == b"id,total\n1,10\n"
    assert (destination / "nested" / "detail.csv").read_bytes() == b"id,line\n1,a\n"
    assert set(_decisions(result)) == {b"report.csv", b"detail.csv"}


async def test_a_second_run_with_nothing_changed_sends_nothing(
    source: Path, tmp_path: Path
) -> None:
    """The whole point of the feature, and the run that proves the record is usable.

    A comparison against the *remote* mtime would fail here rather than pass: ``preserve_times``
    is off, so the destination is stamped with the upload time and does not match the local file
    at all.
    """
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)
        second = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert second.transferred == 0
    assert second.skipped == 2
    assert second.bytes_transferred == 0
    assert set(_decisions(second).values()) == {SyncDecision.SKIPPED}


async def test_an_edited_local_file_is_the_only_thing_re_sent(source: Path, tmp_path: Path) -> None:
    """One file changes; the other stays skipped, which is what makes this a mirror."""
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)
        _ = (source / "report.csv").write_bytes(b"id,total\n1,10\n2,20\n")
        os.utime(source / "report.csv", (1_700_000_500, 1_700_000_500))
        second = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert second.transferred == 1
    assert second.skipped == 1
    assert _decisions(second)[b"report.csv"] is SyncDecision.TRANSFER
    assert _decisions(second)[b"detail.csv"] is SyncDecision.SKIPPED
    assert (destination / "report.csv").read_bytes() == b"id,total\n1,10\n2,20\n"


async def test_a_file_truncated_on_the_server_is_repaired(source: Path, tmp_path: Path) -> None:
    """**The case a record-only mirror cannot see, against a real server.**

    Nothing local changed, so every local check passes and a comparison that stopped there would
    skip -- leaving the destination truncated forever while the run reported success. This is the
    wrong-skip D-164 exists to prevent, and it is the reason the record stores the remote side
    too.
    """
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)
        _ = (destination / "report.csv").write_bytes(b"corrupted")
        second = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert second.transferred == 1
    assert (destination / "report.csv").read_bytes() == b"id,total\n1,10\n"
    outcome = next(o for o in second.outcomes if o.remote_path.endswith(b"report.csv"))
    assert outcome.reason == SyncReason.REMOTE_SIZE_CHANGED


async def test_a_file_deleted_on_the_server_is_restored(source: Path, tmp_path: Path) -> None:
    """The record says it was sent; the listing says it is gone. The record does not win."""
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)
        (destination / "report.csv").unlink()
        second = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert second.transferred == 1
    assert (destination / "report.csv").exists()
    outcome = next(o for o in second.outcomes if o.remote_path.endswith(b"report.csv"))
    assert outcome.reason == SyncReason.REMOTE_GONE


async def test_a_lost_manifest_costs_a_full_re_send_and_no_data(
    source: Path, tmp_path: Path
) -> None:
    """The failure mode of the design decision, asserted rather than left as a claim.

    Losing the record cannot lose data -- it can only cost bytes. That is the trade the manifest
    was chosen for, so it gets a row.
    """
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)
        manifest.unlink()
        second = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert second.transferred == 2
    assert second.skipped == 0
    assert (destination / "report.csv").read_bytes() == b"id,total\n1,10\n"


async def test_the_manifest_records_both_sides(source: Path, tmp_path: Path) -> None:
    """The remote half is what makes a server-side change visible, so it must be written.

    Asserted on the file rather than through behaviour, because a manifest that recorded a
    plausible-looking remote size taken from the *local* file would pass every behavioural row
    above and fail only against a server that rewrites what it stores.
    """
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    entry = SyncManifest.load(manifest).recorded((destination / "report.csv").as_posix().encode())
    assert entry is not None
    assert entry.local_size == 14
    assert entry.remote_size == 14
    assert entry.local_mtime == 1_700_000_000
    # With `preserve_times` off the destination wears the upload time, which is *not* the local
    # one -- the fact that makes a remote-clock comparison unusable and this record necessary.
    assert entry.remote_mtime != entry.local_mtime


async def test_symlinks_are_reported_by_the_walk_and_not_mirrored(
    source: Path, tmp_path: Path
) -> None:
    """A mirror inherits the upload walk's refusal to follow links, and says so separately.

    ``walk_skipped`` rather than ``skipped``: one means "not looked at", the other means "looked
    at and proven identical", and a report that merged them would be unreadable in exactly the
    case where a link is hiding something.
    """
    (source / "escape").symlink_to("/etc/passwd")
    destination = tmp_path / "destination"

    async with _session() as sftp:
        result = await sftp.sync_tree(
            source, destination.as_posix().encode(), manifest=tmp_path / "state.json"
        )

    assert not (destination / "escape").exists()
    assert [skip.reason for skip in result.walk_skipped] == [
        "symlink, and symlinks are not followed"
    ]
    assert result.skipped == 0, "a walk skip must not be counted as a proven-identical skip"


async def test_a_mirror_does_not_delete_what_is_no_longer_local(
    source: Path, tmp_path: Path
) -> None:
    """Stated on the method and asserted here, because it is the surprising half.

    Deletion is the one mirror operation whose mistakes are unrecoverable, and this side cannot
    tell "extraneous" from "somebody else's file".
    """
    destination = tmp_path / "destination"
    manifest = tmp_path / "state.json"

    async with _session() as sftp:
        _ = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)
        (source / "report.csv").unlink()
        result = await sftp.sync_tree(source, destination.as_posix().encode(), manifest=manifest)

    assert (destination / "report.csv").exists()
    assert result.transferred == 0

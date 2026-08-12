"""Making a remote tree match a local one, and the skip that would lose data.

    python examples/mirror_tree.py     # local sftp-server, no network

"Make the remote match the local, repeatedly" is what most SFTP automation actually is -- a
nightly export, a vendor drop, a build artifact push. `put_tree` re-sends every byte every time,
so the alternative is a hand-rolled `if size differs` in somebody's cron job, which is a skip rule
nobody reviewed.

**The dangerous operation in a mirror is the one that does nothing.** Deciding two files are
identical when they are not leaves the old contents on the server and returns a successful
result -- data loss with a green report. So `sync_tree` reports a decision and a reason for every
file, and this example is mostly about the two decisions that are easy to get wrong.

**Trap 1: the remote modification time is not the local one.** `preserve_times` is off by
default -- deliberately, because a landing zone whose consumer collects "modified since X" must
not receive files wearing last year's date -- so an uploaded file carries the time of the
*upload*. A mirror comparing local mtime against remote mtime therefore finds every file changed
on every run, forever, and does nothing except waste the bandwidth it exists to save. Printed
below from a real server rather than asserted from memory.

So the comparison is against a **record of what was sent**, which is the `manifest` argument.

**Trap 2: a record of what we sent cannot see what the server did.** Truncate the remote file and
the local one still matches the record exactly. A mirror that trusted the record alone would skip
it and leave the destination broken forever -- the same wrong skip, arriving through the
mechanism meant to prevent it. The record therefore stores *both* sides, which costs nothing
because a v3 listing carries the sizes and times already. The last section here truncates a file
on the "server" and watches the mirror repair it.

**And a third state that is not a skip.** A server may volunteer no size and no modification time
for an entry, at any time and for any reason. That is reported as `UNDECIDABLE` and the file is
**sent**, because a file that could not be proven identical is not a file to leave alone.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import anyio

from gantry_sftp.session import Session, SyncManifest, SyncResult, open_session
from gantry_sftp.transport import open_local_server_transport

PINNED_MTIME = 1_700_000_000
"""Set explicitly rather than raced, so a "nothing changed" run is deterministic anywhere."""


def build_source(root: Path) -> None:
    """A small tree: two files and a nested directory, at a pinned modification time."""
    (root / "nested").mkdir(parents=True, exist_ok=True)
    _ = (root / "report.csv").write_bytes(b"id,total\n1,10\n")
    _ = (root / "nested" / "detail.csv").write_bytes(b"id,line\n1,a\n")
    for path in (root / "report.csv", root / "nested" / "detail.csv"):
        os.utime(path, (PINNED_MTIME, PINNED_MTIME))


def show(label: str, result: SyncResult) -> None:
    """One run's report: the counts, then every file with the reason it was or was not sent."""
    print(f"\n{label}")
    print(
        f"  {result.transferred} sent, {result.skipped} unchanged, "
        f"{result.undecidable} unproven, {result.bytes_transferred} bytes"
    )
    for outcome in sorted(result.outcomes, key=lambda item: item.remote_path):
        name = os.fsdecode(outcome.remote_path).rsplit("/", 1)[-1]
        print(f"    {name:<12} {outcome.decision:<12} {outcome.reason}")


async def main() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        area = Path(workspace)
        source = area / "source"
        destination = area / "destination"
        manifest = area / "state.json"
        build_source(source)

        async with (
            open_local_server_transport() as transport,
            open_session(transport) as sftp,
        ):
            remote = destination.as_posix().encode()

            first = await sftp.sync_tree(source, remote, manifest=manifest)
            show("First run -- nothing is on record, so nothing can be proven identical:", first)

            second = await sftp.sync_tree(source, remote, manifest=manifest)
            show("Second run -- unchanged, and this is the point of the feature:", second)
            assert second.transferred == 0, "an unchanged tree must send nothing"
            assert second.skipped == 2

            # Trap 1, from the server rather than from memory.
            entry = SyncManifest.load(manifest).recorded(
                (destination / "report.csv").as_posix().encode()
            )
            assert entry is not None
            print("\nWhy the comparison is not local-mtime against remote-mtime:")
            print(f"    local mtime  {entry.local_mtime}")
            print(f"    remote mtime {entry.remote_mtime}   <- the upload, not the file")
            print(f"    difference   {entry.remote_mtime - entry.local_mtime} seconds")
            assert entry.remote_mtime != entry.local_mtime, (
                "this example's first warning claims these differ; if they stop differing the "
                "warning is wrong and the text has to change"
            )

            _ = (source / "report.csv").write_bytes(b"id,total\n1,10\n2,20\n")
            os.utime(source / "report.csv", (PINNED_MTIME + 500, PINNED_MTIME + 500))
            edited = await sftp.sync_tree(source, remote, manifest=manifest)
            show("After editing one local file -- only that one moves:", edited)
            assert edited.transferred == 1
            assert edited.skipped == 1

            # Trap 2: nothing local changes, so only the remote half of the record can catch it.
            _ = (destination / "report.csv").write_bytes(b"corrupted")
            repaired = await sftp.sync_tree(source, remote, manifest=manifest)
            show(
                "After the file was truncated on the server -- the local side is untouched:",
                repaired,
            )
            assert repaired.transferred == 1, (
                "a record-only mirror skips here and leaves the destination truncated forever"
            )
            assert (destination / "report.csv").read_bytes() == b"id,total\n1,10\n2,20\n"

            # And what it will not do, which is the surprising half.
            (source / "nested" / "detail.csv").unlink()
            final = await sftp.sync_tree(source, remote, manifest=manifest)
            show("After deleting a local file -- the remote copy stays:", final)
            assert (destination / "nested" / "detail.csv").exists(), (
                "nothing here deletes: an extraneous remote file and somebody else's file are "
                "indistinguishable from this side"
            )

            await interrupted_run(sftp, area, source, remote, manifest)

        print("\nA mirror's defining act is deciding not to transfer. Every decision above")
        print("carries the evidence it rests on, because the wrong one is silent.")


async def interrupted_run(
    sftp: Session, area: Path, source: Path, remote: bytes, manifest: Path
) -> None:
    """A run that dies partway through, and the next one picking up where it stopped.

    The record is appended as each file lands rather than written when the run finishes, so this
    is what a deploy, an OOM or a laptop lid costs: nothing but the files that had not been sent
    yet. Written as an exception because an example should not kill itself twice --
    `examples/crash_resume.py` is the one that uses a real `SIGKILL`, and the property here is
    the same one: the record is on disk because it was appended, not because anything tidied up.
    """
    fresh = area / "second-mirror"
    fresh.mkdir()
    for index in range(4):
        _ = (source / f"batch-{index}.csv").write_bytes(f"id\n{index}\n".encode())
    log = area / "interrupted.json"

    def stop_once_something_is_recorded(_transferred: int, _total: int | None) -> None:
        if len(SyncManifest.load(log).entries) >= 2:
            raise RuntimeError("the deploy happened")

    try:
        _ = await sftp.sync_tree(
            source, str(fresh).encode(), manifest=log, progress=stop_once_something_is_recorded
        )
    except RuntimeError as interrupted:
        print(f"\nThe mirror died partway through: {interrupted}")

    kept = SyncManifest.load(log).entries
    assert kept, "the interrupted run recorded nothing, so the next one re-sends everything"
    print(f"  it had already recorded {len(kept)} files, with no chance to tidy up")

    resumed = await sftp.sync_tree(source, str(fresh).encode(), manifest=log)
    show("The next run sends only the rest:", resumed)
    assert resumed.skipped == len(kept), (
        "the record survived the interruption but the comparison did not use it"
    )


anyio.run(main)

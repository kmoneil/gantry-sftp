"""What a tree transfer would do, having done none of it -- and what it cannot know.

    python examples/dry_run.py     # local sftp-server, no network

This library's strongest features are decisions nobody sees. A symlink skipped with a reason, a
name that could not be a remote path component, two remote names a destination would merge --
each is a judgement made at speed inside a loop, and until now the only way to learn what it
would decide was to let it decide. `dry_run=True` runs the same walk, makes the same decisions,
and hands them back.

**The contract is one sentence: a dry run makes no writes.** No `MKDIR`, no `OPEN`, no
`SETSTAT`, no local directory -- not even the destination root -- and none of the empty files a
download creates to reserve its destinations. It reads only what the operation would read
anyway.

That contract is what makes the two directions preview so differently, and the asymmetry is
stated rather than hidden. Walking a remote tree *is* reading, so the download plan is nearly
complete. An upload's walk is local, so its plan is complete about every local fact and silent
about the destination -- which is a mirror's question, and would cost a round trip per entry to
answer.

**The interesting half is what a preview declines to claim.** `plan.undetermined` says what was
not found out, and the collision check is the one decision that cannot survive the no-writes
rule intact: the real download establishes that two remote names are one local file by creating
the file and asking `lstat` for its inode, which is authoritative on every filesystem and is a
write. A preview folds names instead, and reports the pair rather than refusing it -- because on
the case-sensitive filesystem this example runs on, those two names really are two files and the
real download transfers both. Refusing them on the strength of a `str.lower()` would be a guess
wearing a fact's clothes.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import anyio

from gantry_sftp.session import TreePlan, open_session
from gantry_sftp.transport import open_local_server_transport


def build_remote(root: Path) -> None:
    """A remote tree with a nested directory, a symlink, and a case-folding pair."""
    _ = (root / "README.md").write_bytes(b"the first file\n")
    _ = (root / "readme.md").write_bytes(b"a different file entirely\n")
    nested = root / "reports"
    nested.mkdir()
    _ = (nested / "q1.csv").write_bytes(b"1,2,3\n")
    (root / "shortcut").symlink_to(nested / "q1.csv")


def build_local(root: Path) -> None:
    """A local tree to upload, with the hazard this direction actually has."""
    _ = (root / "invoice.csv").write_bytes(b"4,5,6\n")
    nested = root / "archive"
    nested.mkdir()
    _ = (nested / "old.csv").write_bytes(b"7,8,9\n")
    # Never followed on upload: a link pointing at /etc/shadow would otherwise copy it to the
    # server under an innocent name. It is reported in `skipped`, which a preview shows first.
    (root / "elsewhere").symlink_to(nested)


def report(plan: TreePlan, destination: Path) -> None:
    """Print a plan the way a caller deciding whether to run it would read one."""
    print(f"  {plan.files} files, {plan.bytes_to_transfer} bytes, {plan.directories} directories")
    for skip in plan.skipped:
        print(f"  would skip {skip.path!r} -- {skip.reason}")
    for maybe in plan.potential_collisions:
        print(f"  {maybe.remote!r} and {maybe.first!r} would fold together")
        print(f"    at {maybe.local}, if the destination folds case or normalisation")
    print(f"  complete: {plan.complete}")
    for limit in plan.undetermined:
        print(f"  not determined -- {limit}")
    # The whole of the promise, and it is checkable rather than a claim in a docstring.
    print(f"  destination untouched: {not destination.exists()}")


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        remote = workdir / "remote"
        remote.mkdir()
        build_remote(remote)
        outgoing = workdir / "outgoing"
        outgoing.mkdir()
        build_local(outgoing)

        landing = workdir / "downloaded"

        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            print("download preview:")
            plan = await sftp.get_tree(str(remote), landing, dry_run=True)
            report(plan, landing)

            print()
            print("upload preview:")
            upload = await sftp.put_tree(outgoing, str(workdir / "uploaded"), dry_run=True)
            report(upload, workdir / "uploaded")

            print()
            print("and then, for real:")
            done = await sftp.get_tree(str(remote), landing)
            # The counts agree because both came from one walk. They are *not* a rerun of the
            # same arithmetic: the plan counted the sizes READDIR volunteered, and this counted
            # the bytes that arrived.
            print(f"  {done.files} files, {done.transferred} bytes -- plan said {plan.files}")
            print("  and the pair the preview flagged is two files here, both intact:")
            print(f"    README.md -> {(landing / 'README.md').read_bytes()!r}")
            print(f"    readme.md -> {(landing / 'readme.md').read_bytes()!r}")


if __name__ == "__main__":
    anyio.run(main)

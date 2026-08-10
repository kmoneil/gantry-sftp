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
a case-sensitive filesystem those two names really are two files and the real download transfers
both. Refusing them on the strength of a `str.lower()` would be a guess wearing a fact's clothes.

**On a folding filesystem this example cannot stage its own hazard**, and says so rather than
pretending otherwise. The "remote" tree here is a real directory, so on APFS `README.md` and
`readme.md` are one file before the server ever lists them -- the fold fires one layer upstream
of the preview that warns about it. Same shape as `destination_collision.py` skipping its hard
link where the destination already folds: a stand-in for a condition breaks on the platform that
has the condition for real.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import anyio

from gantry_sftp.session import TreePlan, open_session
from gantry_sftp.transport import open_local_server_transport


def build_remote(root: Path) -> bool:
    """A remote tree with a nested directory, a symlink, and — where possible — a folding pair.

    **On a case-folding filesystem the pair cannot be staged at all**, and that is worth saying
    out loud rather than working around. The "remote" here is a real directory served by
    `sftp-server`, so on APFS `README.md` and `readme.md` are one file: the second write lands
    on the first and the server lists a single name. The example's own fixture is consumed by
    the hazard the example is about, one layer earlier than where it warns about it.

    `examples/destination_collision.py` handles the mirror image the same way — it detects the
    fold and skips its hard link, because on a filesystem that already folds there is nothing to
    simulate. Asked with `st_ino` rather than by comparing names, which is the instrument the
    library itself uses and the only one that is right on every filesystem.

    Returns:
        Whether the two names ended up as two files.
    """
    first = root / "README.md"
    second = root / "readme.md"
    _ = first.write_bytes(b"the first file\n")
    _ = second.write_bytes(b"a different file entirely\n")
    nested = root / "reports"
    nested.mkdir()
    _ = (nested / "q1.csv").write_bytes(b"1,2,3\n")
    (root / "shortcut").symlink_to(nested / "q1.csv")
    return first.stat().st_ino != second.stat().st_ino


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
        staged_pair = build_remote(remote)
        outgoing = workdir / "outgoing"
        outgoing.mkdir()
        build_local(outgoing)

        landing = workdir / "downloaded"

        # Printed rather than assumed, because it decides what the rest of this output can
        # show -- and because the example is the only honest authority on the filesystem it
        # is actually running on. `test_examples.py` reads this line rather than probing for
        # itself, so the two cannot disagree about the same machine.
        held = "yes" if staged_pair else "no -- this filesystem folds them into one"
        print(f"remote tree holds both names: {held}")
        print()

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
            if staged_pair:
                print("  and the pair the preview flagged is two files here, both intact:")
                print(f"    README.md -> {(landing / 'README.md').read_bytes()!r}")
                print(f"    readme.md -> {(landing / 'readme.md').read_bytes()!r}")
            else:
                print("  the preview flagged no pair, and correctly: the fold happened when")
                print("  this tree was built, so the server only ever listed one name. What")
                print("  a preview cannot see is a hazard that already fired upstream of it.")


if __name__ == "__main__":
    anyio.run(main)

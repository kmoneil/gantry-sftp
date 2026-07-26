"""Mirror a local tree onto a server, then remove it again.

    python examples/recursive_upload.py                  # local sftp-server, no network
    python examples/recursive_upload.py user@host /dir   # a real server over ssh

Three things this shows that a loop around `put()` would not.

**Symlinks are reported, never followed** -- in this direction because a link in the upload
tree pointing at `/etc/shadow` would otherwise copy it to the server under an innocent name.
The result says what it did *not* send, and a mirroring tool that quietly followed links is an
exfiltration primitive.

**`atomic` is per file, not per tree.** Each file is staged and renamed, so a consumer polling
the directory sees the old file or the new one and never a partial one. Nothing makes the
whole tree appear at once, and the docstring says so rather than implying a guarantee that
`rename` onto a populated directory cannot deliver.

**`rmtree` goes bottom up and unlinks rather than follows.** The symlink pointing outside the
tree is removed; what it points at is untouched. That is the difference between `REMOVE`, which
deletes a name, and following it, which would delete somebody else's file.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp.session import open_session, walk_local
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def build_tree(root: Path, outside: Path) -> None:
    """A tree with the shapes that make a recursive upload interesting."""
    _ = (root / "report.csv").write_bytes(b"id,total\n1,42\n")
    (root / "daily").mkdir()
    _ = (root / "daily" / "2026-07-26.csv").write_bytes(b"rows\n" * 500)
    (root / "daily" / "archive").mkdir()
    _ = (root / "daily" / "archive" / "old.csv").write_bytes(b"older\n")
    # The link that must not be followed in either direction.
    (root / "daily" / "secrets.csv").symlink_to(outside)


async def main() -> None:
    destination_arg = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "outgoing"
        source.mkdir()
        outside = workdir / "not-yours.txt"
        _ = outside.write_bytes(b"this file is not in the tree\n")
        build_tree(source, outside)

        show_the_local_walk(source)

        if destination_arg is None:
            remote = workdir / "uploaded"
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                await mirror(sftp, source, str(remote))
        else:
            if remote_dir is None:
                sys.exit("usage: python examples/recursive_upload.py user@host /remote/dir")
            user, _, host = destination_arg.rpartition("@")
            async with (
                open_ssh_transport(host, user=user or None) as transport,
                open_session(transport) as sftp,
            ):
                await mirror(sftp, source, remote_dir)

        print(f"\nthe file the link pointed at: {outside.read_bytes()!r}")


def show_the_local_walk(source: Path) -> None:
    """The walk the upload is built on, which needs no connection at all."""
    print(f"walking {source} locally")
    for entry in walk_local(source):
        relative = b"/".join(entry.relative).decode() or "."
        print(f"  {relative}: {len(entry.directories)} dirs, {len(entry.files)} files")
        for skip in entry.skipped:
            print(f"    skipped {os.fsdecode(skip.path)} -- {skip.reason}")


async def mirror(sftp, source: Path, remote: str) -> None:
    """Upload the tree, print what happened, then remove it again."""
    result = await sftp.put_tree(source, remote)
    print(
        f"\nuploaded {result.files} files, {result.directories} directories, "
        f"{result.transferred} bytes -> {remote}"
    )
    print(f"complete={result.complete} (False just means something was skipped)")
    for skip in result.skipped:
        print(f"  not sent: {os.fsdecode(skip.path)} -- {skip.reason}")

    removed = await sftp.rmtree(remote)
    print(f"\nrmtree removed {removed.files} entries and {removed.directories} directories")


if __name__ == "__main__":
    anyio.run(main)

"""Two remote names, one local file -- and why the download stops instead of overwriting.

    python examples/destination_collision.py     # local sftp-server, no network

A server holding `README.md` beside `readme.md` is doing nothing wrong: both names are legal
on any case-sensitive filesystem, and Linux servers hold pairs like that routinely. Download
them onto APFS or NTFS -- the defaults on macOS and Windows -- and they are *one* file. The
second write truncates the first, and a `get_tree` that did not check would report success
with one file's contents gone and nothing anywhere saying so.

`check_contained` cannot catch this one. Both paths are legitimately inside the destination;
nothing escaped anywhere. It is not the zip-slip class at all.

**The check asks the filesystem, not the name.** Folding the names in Python would mean
reimplementing NTFS's uppercase table, APFS's folding and HFS+'s normalisation -- three
different tables, and a wrong guess either refuses a legitimate pair or misses a real
collision. Instead every file this download writes is remembered by `(st_dev, st_ino)`, and a
name that lands on an inode this run already wrote is refused. That never asks *why* two names
became one file, so the same check covers case folding, `report.` beside `report` on Windows,
and NFC/NFD pairs on HFS+.

This example runs on a case-sensitive filesystem, where `README.md` and `readme.md` are
genuinely two files -- so it reproduces the *identical* condition with a hard link, which is
also two names for one inode. That is the honest demonstration: the check is about file
identity, and case folding is only the commonest way to arrive at it.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import anyio

from gantry_sftp.exceptions import DestinationCollisionError
from gantry_sftp.session import open_session
from gantry_sftp.transport import open_local_server_transport


def build_remote(root: Path) -> None:
    """A remote tree with two names a case-folding destination cannot keep apart."""
    _ = (root / "README.md").write_bytes(b"the first file\n")
    _ = (root / "readme.md").write_bytes(b"a different file entirely\n")
    _ = (root / "notes.txt").write_bytes(b"nothing wrong with this one\n")


def make_destination_fold(destination: Path) -> None:
    """Give the destination two names for one file, as APFS and NTFS would."""
    destination.mkdir()
    placeholder = destination / "README.md"
    _ = placeholder.write_bytes(b"placeholder\n")
    os.link(placeholder, destination / "readme.md")


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        remote = workdir / "remote"
        remote.mkdir()
        build_remote(remote)

        destination = workdir / "downloaded"
        make_destination_fold(destination)

        survivor = b""
        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            try:
                result = await sftp.get_tree(str(remote), destination)
            except DestinationCollisionError as error:
                print(f"{error.files} files transferred, then:")
                print(f"  {error.args[0]}")
                print()
                for collision in error.collisions:
                    print(f"  refused: {collision.remote!r}")
                    print(f"    the local file {collision.local} already holds")
                    print(f"    {collision.first!r}, which got there first")
                survivor = error.collisions[0].first
            else:
                print(f"this filesystem keeps the names apart: {result.files} files, no collision")
                return

        # README.md and readme.md are one inode here, so either name reads the same bytes.
        # Which of the two arrives first is READDIR order, and that is the server's choice.
        print()
        print("on disk:")
        print(f"  the shared file holds {(destination / 'README.md').read_bytes()!r}")
        print(f"  which is {survivor!r}, intact -- the later write was refused, not applied")
        print(f"  notes.txt -> {(destination / 'notes.txt').read_bytes()!r}, unaffected")


if __name__ == "__main__":
    anyio.run(main)

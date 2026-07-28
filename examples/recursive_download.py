"""Download a whole tree, and refuse to be walked out of the destination.

    python examples/recursive_download.py                  # local sftp-server, no network
    python examples/recursive_download.py user@host /dir   # a real server over ssh

Two things this shows that a loop around `get()` would not.

`get_tree` validates **every** name the server supplies before it becomes a local path, and
re-checks the finished path against the destination once symlinks are resolved. A server
answering `../../etc/cron.d/x` gets an `UnsafePathError` and nothing is written. That is the
zip-slip class, and it is a real and exploited pattern in file-transfer clients. The last
section runs the names an attacker would send through the very check `get_tree` applies to
every one of them.

And the result says what it *did not* do. Symlinks are reported, never followed, and a
recursive download that quietly ignored them would quietly lose data.
"""

from __future__ import annotations

import os
import sys
import tempfile
from contextlib import aclosing
from pathlib import Path

import anyio

from gantry_sftp.exceptions import UnsafePathError
from gantry_sftp.session import check_component, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def build_tree(root: Path) -> None:
    """A tree with the shapes that make a recursive download interesting."""
    _ = (root / "report.csv").write_bytes(b"id,total\n1,42\n")
    (root / "daily").mkdir()
    _ = (root / "daily" / "2026-07-26.csv").write_bytes(b"rows\n" * 500)
    (root / "daily" / "archive").mkdir()
    _ = (root / "daily" / "archive" / "old.csv").write_bytes(b"older\n")
    (root / "latest.csv").symlink_to(root / "report.csv")


async def main() -> None:
    destination_arg = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        local = workdir / "downloaded"

        if destination_arg is None:
            remote = workdir / "remote"
            remote.mkdir()
            build_tree(remote)
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                await report(sftp, str(remote), local)
        else:
            if remote_dir is None:
                sys.exit("usage: python examples/recursive_download.py user@host /remote/dir")
            user, _, host = destination_arg.rpartition("@")
            async with (
                open_ssh_transport(host, user=user or None) as transport,
                open_session(transport) as sftp,
            ):
                await report(sftp, remote_dir, local)

        for path in sorted(local.rglob("*")):
            kind = "dir " if path.is_dir() else "file"
            print(f"  {kind} {path.relative_to(local)}")

    show_the_names_that_are_refused()


def show_the_names_that_are_refused() -> None:
    """The same check every downloaded name goes through, run on what an attacker sends."""
    print("\nnames a hostile server might send, and what happens to them:")
    for hostile in (b"../../etc/cron.d/x", b"/etc/passwd", b"sub/file", b"", b"report.csv"):
        try:
            check_component(hostile)
        except UnsafePathError as refusal:
            print(f"  {hostile!r:<22} refused: {refusal.reason}")
        else:
            print(f"  {hostile!r:<22} allowed")


async def report(sftp, remote: str, local: Path) -> None:
    """Walk the tree, then download it, printing both."""
    print(f"walking {remote}")
    # aclosing: a suspended async generator that is merely dropped is not finalised by trio,
    # and the library's docstring says so rather than leaving you to find out.
    async with aclosing(sftp.walk(remote)) as walker:
        async for entry in walker:
            name = os.fsdecode(entry.path)
            print(f"  {name}: {len(entry.directories)} dirs, {len(entry.files)} files")
            for skip in entry.skipped:
                print(f"    skipped {os.fsdecode(skip.path)} -- {skip.reason}")

    result = await sftp.get_tree(remote, local)
    print(
        f"\n{result.files} files, {result.directories} directories, "
        f"{result.transferred} bytes -> {local}"
    )
    print(f"complete={result.complete} (False just means something was skipped)")
    for skip in result.skipped:
        print(f"  not copied: {os.fsdecode(skip.path)} -- {skip.reason}")
    await show_where_the_arithmetic_is_allowed(sftp, remote)
    print()


async def show_where_the_arithmetic_is_allowed(sftp, remote: str) -> None:
    """Why a walk can join paths at all, and when it refuses to.

    Every remote path this library builds is `/` arithmetic on bytes, because
    draft-ietf-secsh-filexfer-02 6.2 says to assume it -- "File names are assumed to use the
    slash ('/') character as a directory separator", and "otherwise, no syntax is defined for
    file names by this specification". On an endpoint whose namespace is not `/`-shaped, VMS
    `DISK$USER:[DIR]FILE.TXT` or an MVS dataset name, there is no correct join to perform, so
    `walk`/`get_tree`/`put_tree`/`rmtree` and an atomic `put` raise `CapabilityError` instead
    of building a path the server does not mean.

    An absolute path costs nothing to check: 6.2 also says a name starting with `/` is
    absolute and relative to the root of the filesystem, so passing one asserts the namespace
    and no probe is sent at all. Only a relative path needs asking, and that is one REALPATH
    of `.`, cached for the session.
    """
    print(f"\nserver_root after an absolute walk: {sftp.server_root}  (None -- never asked)")
    async with aclosing(sftp.walk(".")) as walker:
        _ = await anext(aiter(walker))
    print(f"server_root after a relative walk: {sftp.server_root!r}")
    print(f"  starts with b'/', so joining onto {remote!r} is defined and the walk proceeds")


if __name__ == "__main__":
    anyio.run(main)

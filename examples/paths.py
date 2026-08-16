"""`SFTPPath` -- a remote path you can do arithmetic on, and then act on.

    python examples/paths.py                   # against a local sftp-server, no network
    python examples/paths.py user@host /dir    # against a real server over ssh

The `pathlib`-shaped surface: `p / name`, `p.parent`, `p.suffix`, `p.glob(...)`, and then
`await p.download(...)` on the thing you found. The reason to read this rather than the method
list is that two of its decisions look like inconveniences until you see what they prevent.

**Names come back as bytes, not `str`.** That is the same rule every other name in this library
follows -- `DirEntry.filename`, `realpath`, `readlink` -- and it exists because a remote name is
bytes whose encoding the protocol never states. The files whose names are the reason you needed
a listing are exactly the ones that are not valid UTF-8. `str(path)` is a *view*: it decodes
with `surrogateescape`, so re-encoding it gives back the original bytes for any name at all, and
`bytes(path)` is the value. Strings go in, bytes come out.

**`/` takes one component, and refuses `..`.** Not because a caller cannot be trusted with a
string, but because the right-hand side is almost always `entry.filename` -- a name the *server*
chose. A server answering `../../etc/cron.d/x` is the zip-slip pattern, and it is a real and
exploited class of bug in file-transfer clients. So the join checks, and going up is `.parent`,
which needs no string. Note where the line falls: the *constructor* accepts `/a/../b` happily,
because that argument was written by you.

**The binding is explicit.** `SFTPPath("/incoming")` is pure arithmetic and never opens a
connection; it raises `StateError` if you ask it to `stat`. `session=` is what makes it live, and
a path derived from a live one stays live. There is no ambient session and no
`SFTPPath("sftp://host/incoming")` constructor: that spelling needs a module-level default
client, which this library does not have and does not want.

`gantry_sftp.sync.SyncSFTPPath` is the same class without the `await`s.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp import SFTPPath, StateError, UnsafePathError, local_child
from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

HOSTILE = b"../../etc/cron.d/x"
"""What a compromised server answers when it would like you to join it onto a path."""


def populate(directory: Path) -> None:
    """A drop directory of the shape a transfer script actually meets."""
    (directory / "2026").mkdir()
    _ = (directory / "2026" / "report.csv").write_bytes(b"id,total\n1,42\n")
    _ = (directory / "2026" / "notes.txt").write_bytes(b"nothing to see\n")
    # A name that is not valid UTF-8. Ordinary, not exotic: this is what a Latin-1 endpoint
    # sends, and it is the file that breaks clients which decode names strictly.
    _ = (directory / "2026" / os.fsdecode(b"caf\xe9.csv")).write_bytes(b"id,total\n2,7\n")
    # A dotfile, so the glob below can demonstrate not picking it up.
    _ = (directory / "2026" / ".staging.csv").write_bytes(b"half-written\n")


@asynccontextmanager
async def connect(destination: str | None, workdir: Path) -> AsyncGenerator[Session]:
    """A session, either to a local `sftp-server` or over `ssh` to a real host."""
    if destination is None:
        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp
    else:
        user, _, host = destination.rpartition("@")
        async with (
            open_ssh_transport(host, user=user or None) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp


async def show_the_algebra() -> None:
    """Everything a path can answer without a connection, including the two refusals."""
    pure = SFTPPath("/incoming/2026/archive.tar.gz")
    print("arithmetic, with no session and no round trip:")
    print(f"  bytes(path)   {bytes(pure)!r}")
    print(f"  .name         {pure.name!r}       <- bytes, like every other name here")
    print(f"  .stem         {pure.stem!r}")
    print(f"  .suffixes     {pure.suffixes!r}")
    print(f"  .parent       {bytes(pure.parent)!r}")
    print(f"  .parts        {pure.parts!r}")
    print(f"  .match('*.gz')                {pure.match('*.gz')}")
    print(f"  .relative_to('/incoming')     {bytes(pure.relative_to('/incoming'))!r}")

    # A name no encoding explains survives both directions unchanged, which is the whole
    # reason the payload is bytes rather than str.
    awkward = SFTPPath(b"/incoming/caf\xe9.csv")
    assert str(awkward).encode("utf-8", "surrogateescape") == bytes(awkward)
    print(f"\n  an undecodable name round-trips: {bytes(awkward)!r} -> str -> the same bytes")

    print("\nand the two things it refuses:")
    try:
        _ = pure / HOSTILE
    except UnsafePathError as refused:
        print(f"  path / {HOSTILE!r}\n    -> {refused}")
    else:
        raise AssertionError("joining a server-supplied escape was not refused")

    try:
        _ = await pure.stat()
    except StateError as unbound:
        print(f"\n  an unbound path cannot reach a server:\n    -> {unbound}")
    else:
        raise AssertionError("an unbound path answered a question about a server")

    # The line the refusal above is *not* about: this one you wrote, so it is a path.
    print(f"\n  but the constructor takes what the join refuses: {bytes(SFTPPath('/a/../b'))!r}")


async def use_it(sftp: Session, base: bytes, destination: Path) -> None:
    """The one-line task a transfer script is written for, as paths rather than as bytes."""
    root = SFTPPath(base, session=sftp)
    print(f"\nin {root}:")

    # `iterdir` validates every name the server sent before it becomes a path, so a listing
    # cannot steer you out of the directory you asked about.
    async for entry in (root / b"2026").iterdir():
        kind = "dir " if await entry.is_dir() else "file"
        print(f"  {kind} {entry.name!r}")

    print("\nglob, then act on what it found:")
    matched: list[SFTPPath] = []
    async for found in root.glob("2026/*.csv"):
        matched.append(found)
        # `local_child` and not `destination / os.fsdecode(found.name)`: the remote half of
        # this path was validated by `glob`, and the *local* half is a second check with a
        # wider rule -- a name that cleared the remote one can still be `..\evil` or `CON`.
        local = local_child(destination, found.name)
        result = await found.download(local)
        print(f"  {found.name!r:<20} -> {local.name!r} ({result.transferred} bytes)")

    # `*` does not match a leading period -- `glob(3)`'s rule, and what keeps a drop-directory
    # sweep off half-written staging files, including the ones this library's own atomic
    # publish creates.
    names = {found.name for found in matched}
    assert b".staging.csv" not in names, "a leading dot was matched by `*`"
    print(f"  and .staging.csv was not matched: {sorted(names)}")

    print("\nwriting through a path:")
    receipt = root / "receipt.txt"
    written = await receipt.write_text(f"{len(matched)} files\n")
    # 0o600, not the server's 0666 & ~umask: there is no umask of ours on the far side, and a
    # later chmod would leave a window in which the file was world-readable.
    mode = (await receipt.stat()).permissions
    assert mode is not None, "the server reported no permissions for a file it just created"
    print(f"  {receipt.name!r} is {written} bytes, mode {mode & 0o777:o}")
    assert mode & 0o777 == 0o600, "write_bytes left the file readable"

    await receipt.unlink()
    assert not await receipt.exists()
    print(f"  and removed again: exists() -> {await receipt.exists()}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/paths.py user@host /remote/dir")

    await show_the_algebra()

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        downloads = workdir / "downloads"
        downloads.mkdir()
        if destination is None:
            populate(workdir)
        base = os.fsencode(remote_dir) if remote_dir is not None else os.fsencode(workdir)

        async with connect(destination, workdir) as sftp:
            await use_it(sftp, base, downloads)


if __name__ == "__main__":
    anyio.run(main)

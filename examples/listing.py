"""List a remote directory -- all of it, or only as much of it as you need.

    python examples/listing.py                  # against a local sftp-server, no network
    python examples/listing.py user@host /dir   # against a real server over ssh

Two things worth noticing in the output. The size and the kind come *with* the listing --
v3 sends ATTRS per entry, so asking the server again per file would be a round trip each and
is why listing a big directory is slow in most tools. And `kind` can be `unknown`: a server
is not obliged to send permissions, and answering "file" when it did not say is how a
recursive walk silently skips every directory.

Then the same directory again, streamed. `listdir()` follows every READDIR batch to the end
and hands back a list, which is what you want for an ordinary directory and is a memory cost
the *server* chooses: a directory with millions of entries, or a server willing to answer
READDIR with new names forever, is unbounded allocation driven by the peer. `scandir()` holds
one batch, and it is a context manager rather than a bare generator because it keeps a
directory handle open -- an abandoned async generator is not finalised by trio, and the
handle would sit on the server until the garbage collector felt like it, if ever.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp.session import DirEntry, EntryKind, Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def populate(directory: Path) -> None:
    """A directory with the shapes that make a listing interesting."""
    _ = (directory / "report.csv").write_bytes(b"id,total\n1,42\n")
    _ = (directory / "archive.tar").write_bytes(bytes(4096))
    (directory / "incoming").mkdir()
    (directory / "latest.csv").symlink_to(directory / "report.csv")
    # A name that is not valid UTF-8 -- ordinary on Linux, and the reason names are bytes.
    _ = (directory / "caf\udce9.csv").write_bytes(b"\xe9")


def describe(entry: DirEntry) -> str:
    size = "-" if entry.size is None else str(entry.size)
    warning = "   <-- the server sent no permissions" if entry.kind is EntryKind.UNKNOWN else ""
    return f"  {entry.kind:<10} {size:>8}  {entry.name}{warning}"


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


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/listing.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        if destination is None:
            populate(workdir)
        target = remote_dir if remote_dir is not None else str(workdir)

        async with connect(destination, workdir) as sftp:
            # The whole directory, accumulated. Fine here; unbounded if the server says so.
            listing = await sftp.listdir(target)

            print(f"{len(listing)} entries in {target}")
            for entry in sorted(listing, key=lambda item: item.filename):
                print(describe(entry))

            # The same directory, streamed, stopping at the first match. Memory is one
            # batch, and the `async with` is what returns the directory handle on the
            # `break` -- without it the server would hold it open.
            print("\nstreaming, stopping at the first regular file:")
            examined = 0
            async with sftp.scandir(target) as entries:
                async for entry in entries:
                    examined += 1
                    if entry.is_file:
                        print(f"  found {entry.name} (entries examined: {examined})")
                        break

            # And the two forms agree about what is in the directory. They share one
            # batch-following loop: listdir is scandir, collected.
            async with sftp.scandir(target) as entries:
                streamed = [entry.filename async for entry in entries]

    print(f"\nstreamed {len(streamed)} names, listed {len(listing)}")

    if streamed != [entry.filename for entry in listing]:
        raise AssertionError("the two listing forms disagree, which means one of them is wrong")

    # `.` and `..` are never in either: they are filtered, because the caller who forgets
    # writes a recursion that never terminates.
    assert not any(entry.filename in (b".", b"..") for entry in listing)

    # And the raw bytes are kept alongside the display name, so a file whose name is not
    # valid UTF-8 can still be operated on.
    for entry in listing:
        if entry.name.encode("utf-8", "surrogateescape") != entry.filename:
            raise AssertionError("a name that cannot be sent back is a name you cannot open")


if __name__ == "__main__":
    anyio.run(main)

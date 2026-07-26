"""List a remote directory, with the attributes the listing already carried.

    python examples/listing.py                  # against a local sftp-server, no network
    python examples/listing.py user@host /dir   # against a real server over ssh

Two things worth noticing in the output. The size and the kind come *with* the listing --
v3 sends ATTRS per entry, so asking the server again per file would be a round trip each and
is why listing a big directory is slow in most tools. And `kind` can be `unknown`: a server
is not obliged to send permissions, and answering "file" when it did not say is how a
recursive walk silently skips every directory.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp.session import DirEntry, EntryKind, open_session
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


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        if destination is None:
            populate(workdir)
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                listing = await sftp.listdir(str(workdir))
                target = str(workdir)
        else:
            if remote_dir is None:
                sys.exit("usage: python examples/listing.py user@host /remote/dir")
            user, _, host = destination.rpartition("@")
            async with (
                open_ssh_transport(host, user=user or None) as transport,
                open_session(transport) as sftp,
            ):
                listing = await sftp.listdir(remote_dir)
                target = remote_dir

    print(f"{len(listing)} entries in {target}")
    for entry in sorted(listing, key=lambda item: item.filename):
        print(describe(entry))

    # `.` and `..` are never in here: they are filtered, because the caller who forgets writes
    # a recursion that never terminates.
    assert not any(entry.filename in (b".", b"..") for entry in listing)

    # And the raw bytes are kept alongside the display name, so a file whose name is not
    # valid UTF-8 can still be operated on.
    for entry in listing:
        if entry.name.encode("utf-8", "surrogateescape") != entry.filename:
            raise AssertionError("a name that cannot be sent back is a name you cannot open")


if __name__ == "__main__":
    anyio.run(main)

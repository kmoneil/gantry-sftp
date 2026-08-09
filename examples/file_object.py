"""Read a byte range, tail a file, append a record -- without staging the whole thing.

    python examples/file_object.py                       # against a local sftp-server
    python examples/file_object.py user@host /remote/dir # against a real server over ssh

Everything else in this library moves a whole file between a remote path and a local path.
This is the surface for the cases that shape does not cover: a header, a range, a tail, an
append, or a stream into a parser without a scratch file on disk first.

Two shapes, and the difference matters more than it looks:

* ``open_file()`` gives a cursor -- ``read``, ``write``, ``seek``, ``tell``. **One file object
  is one task**, because a cursor is shared mutable state and two tasks reading it interleave
  their positions.
* ``read_at`` / ``write_at`` / ``readinto_at`` take the offset as an argument, so they are safe
  to fan out. That is what the fan-out section here does.
* ``download_into`` / ``upload_from`` move a *whole* file through a handle you opened, into or
  out of a descriptor rather than a path -- the last section. Reach for them when the
  destination is not something ``get()`` can open for you.

**Block size is the one performance decision this surface hands you.** A read is pipelined
*within* the range it was asked for, so ``read(1 << 20)`` is several requests in flight and
``read(8192)`` is one round trip. On loopback that is barely visible; at 50 ms RTT a loop of
8 KiB reads is one round trip per 8 KiB. Read in big blocks, or fan out with ``read_at``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp import OpenFlag
from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

RECORDS = [f'{{"seq": {index}, "level": "info"}}\n'.encode() for index in range(64)]


async def demonstrate(sftp: Session, directory: bytes) -> None:
    log = directory + b"/today.jsonl"

    # --- write it, through the same object -------------------------------------------------
    async with sftp.open_file(log, OpenFlag.WRITE | OpenFlag.CREAT, mode=0o600) as remote:
        for record in RECORDS:
            _ = await remote.write(record)
        print(f"wrote {remote.tell()} bytes as {os.fsdecode(log)}")

    # --- the header, without moving the file ----------------------------------------------
    async with sftp.open_file(log) as remote:
        header = await remote.read(32)
        print(f"first 32 bytes: {header!r}")

        # --- the tail, which is what a log is usually read for -----------------------------
        _ = await remote.seek(-64, os.SEEK_END)
        print(f"last 64 bytes:  {(await remote.read())!r}")

        # --- a range in the middle, by absolute position ------------------------------------
        _ = await remote.seek(100)
        print(f"bytes 100-116:  {(await remote.read(16))!r}")

        # Reading at the end is empty rather than an error: end of file is a STATUS the
        # server sends, and turning that into an exception would make every loop a try block.
        _ = await remote.seek(0, os.SEEK_END)
        print(f"at the end:     {(await remote.read(16))!r}")

    # --- appending, which is a flag rather than a seek --------------------------------------
    async with sftp.open_file(log, OpenFlag.WRITE | OpenFlag.APPEND) as remote:
        _ = await remote.write(b'{"seq": 999, "level": "warn"}\n')
    print("appended one record")

    # --- fanning out over one file, which the cursor form cannot do --------------------------
    # Four tasks, one handle, four disjoint ranges, no shared position. This is the shape to
    # reach for when the ranges are independent -- a `RemoteFile` here would interleave.
    handle = await sftp.open(log)
    ranges: dict[int, bytes] = {}

    async def fetch(index: int) -> None:
        ranges[index] = await sftp.read_at(handle, index * 64, 64)

    try:
        async with anyio.create_task_group() as tasks:
            for index in range(4):
                tasks.start_soon(fetch, index)
    finally:
        await sftp.close(handle)

    moved = sum(len(chunk) for chunk in ranges.values())
    print(f"read {len(ranges)} ranges concurrently over one handle, {moved} bytes")

    # --- into a buffer you already own, with no copy -----------------------------------------
    handle = await sftp.open(log)
    try:
        buffer = bytearray(48)
        filled = await sftp.readinto_at(handle, buffer, 0)
        print(f"readinto_at filled {filled} of {len(buffer)} bytes: {bytes(buffer[:16])!r}")
    finally:
        await sftp.close(handle)

    # --- a whole file through a descriptor you opened -----------------------------------------
    # The three calls above hand the range back in memory, which is fine for a header and wrong
    # for a large file. `download_into` fills a descriptor at this session's pipeline depth --
    # the same scheduler `get` uses -- and never opens or closes either end. The destination here
    # is an unnamed temporary file, which is the case `get` cannot serve: it opens the path it is
    # given, and there isn't one.
    handle = await sftp.open(log)
    try:
        size = (await sftp.fstat(handle)).size
        with tempfile.TemporaryFile() as scratch:
            moved = await sftp.download_into(handle, scratch.fileno(), size=size)
            _ = scratch.seek(0)
            print(f"download_into moved {moved} bytes into an unnamed file: {scratch.read(16)!r}")
    finally:
        await sftp.close(handle)


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if destination is None:
        with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
            workdir = Path(scratch)
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                await demonstrate(sftp, str(workdir).encode())
        return

    if remote_dir is None:
        sys.exit("usage: python examples/file_object.py user@host /remote/dir")
    user, _, host = destination.rpartition("@")
    async with (
        open_ssh_transport(host, user=user or None) as transport,
        open_session(transport) as sftp,
    ):
        await demonstrate(sftp, remote_dir.encode())


if __name__ == "__main__":
    anyio.run(main)

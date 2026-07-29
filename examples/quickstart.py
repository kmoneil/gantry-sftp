"""The shortest program that moves a file, and the namespace it needs.

    python examples/quickstart.py                 # against a local sftp-server, no network
    python examples/quickstart.py user@host /dir  # against a real server over ssh

Two things this is showing.

**One import and one call.** `from gantry_sftp import connect` is the whole entry point: it
opens the `ssh` connection and the session over it, and closes both when the block exits. Until
0.10 this was two imports from two subpackages and two nested context managers, and DESIGN 8
documented a `connect()` that did not exist.

**Nothing here reaches into `gantry_sftp.codec`.** Every type a caller receives or passes --
`OpenFlag` for an `open`, `Attrs` from a `stat`, `DirEntry` from a listing, `UploadResult` from
a `put` -- comes from the top level. The codec is public because a frame dumper and a fuzz
harness need it, not because ordinary programs do; before 0.10 `OpenFlag` lived only there, so
opening a file for writing meant importing from the layer the design calls internal.

**Why this file still has a branch.** `connect()` needs a host. With no arguments there is
nothing to connect *to*, so the no-network path uses the local `sftp-server` on a pipe with the
two-call spelling -- which is the same spelling you want whenever the connection's lifetime
differs from the session's. Both are real; neither is a fallback for the other.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp import (
    Attrs,
    OpenFlag,
    Session,
    SessionOptions,
    connect,
    open_session,
)
from gantry_sftp.transport import open_local_server_transport


@asynccontextmanager
async def session_for(destination: str | None, workdir: Path) -> AsyncIterator[Session]:
    """A session, one call where there is a host and two where there is not."""
    if destination is not None:
        user, _, host = destination.rpartition("@")
        # The whole entry point, and the point of the example.
        async with connect(host, user=user or None) as sftp:
            yield sftp
        return
    # No host to connect to, so the local server on a pipe -- and the two-call spelling, which
    # is what `connect()` composes and what you want when the two lifetimes differ.
    async with (
        open_local_server_transport(cwd=workdir) as transport,
        open_session(transport) as sftp,
    ):
        yield sftp


def describe(attrs: Attrs) -> str:
    """`Attrs` and its fields, all reachable from the top-level namespace."""
    size = "size unknown" if attrs.size is None else f"{attrs.size} bytes"
    mode = "mode unknown" if attrs.permissions is None else f"mode {attrs.permissions & 0o7777:04o}"
    return f"{size}, {mode}"


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        source = workdir / "report.csv"
        source.write_bytes(b"id,total\n1,42\n")
        base = Path(remote_dir) if remote_dir else workdir
        remote = base / "report.csv"
        back = workdir / "downloaded.csv"

        async with session_for(destination, workdir) as sftp:
            result = await sftp.put(source, str(remote).encode())
            print(f"put   {result.transferred} bytes  mechanism={result.mechanism.value}")

            transferred = await sftp.get(str(remote).encode(), back)
            print(f"get   {transferred} bytes  ->  {back.name}")
            print(f"stat  {describe(await sftp.stat(str(remote).encode()))}")

            # `OpenFlag` is the name D-58 was about: `Session.open` is typed on it, and until
            # 0.10 it existed only in `gantry_sftp.codec`.
            handle = await sftp.open(str(remote).encode(), OpenFlag.READ)
            try:
                print(f"open  handle held, fstat says {describe(await sftp.fstat(handle))}")
            finally:
                await sftp.close(handle)

            print("\nentries in the directory:")
            for entry in sorted(await sftp.listdir(str(base).encode()), key=lambda e: e.name):
                print(f"  {entry.name:<20} kind={entry.kind.value}")

        print(
            "\nEvery name above came from `gantry_sftp` itself -- no import crossed into\n"
            "`gantry_sftp.codec`, which is what D-58 closed. And with a host argument the\n"
            "whole connection is one call:\n"
            "\n"
            "    async with connect('example.com', user='bob') as sftp:\n"
            "        await sftp.get('/remote/data.parquet', 'data.parquet')\n"
            "\n"
            f"Session tunables ride in SessionOptions: {SessionOptions(depth=16)}\n"
            "-- one object because the ssh arguments already spend the argument budget."
        )


if __name__ == "__main__":
    anyio.run(main)

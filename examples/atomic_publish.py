"""Publish a file so that no consumer ever sees it half-written.

    python examples/atomic_publish.py                 # against a local sftp-server, no network
    python examples/atomic_publish.py user@host /dir  # against a real server over ssh

`put()` stages the bytes under a hidden sibling name, flushes them, and renames the staging
file over the destination. Every one of those steps is an optional OpenSSH extension, so the
result says which mechanism actually ran rather than implying the strongest one.

The last section is the point of the whole feature: with `atomic=False` a watcher sees the
destination grow, and with the default it never sees it until it is complete.
"""

from __future__ import annotations

import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp.exceptions import CapabilityError
from gantry_sftp.session import UploadResult, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


@asynccontextmanager
async def connect(destination: str | None, workdir: Path):
    """Either a real ssh connection, or the genuine sftp-server on a pipe.

    The second one needs no host, no keys and no network, which is what makes this example
    runnable as-is -- and it is a real OpenSSH server either way, not a simulation.
    """
    if destination is None:
        async with open_local_server_transport(cwd=workdir) as transport:
            yield transport
        return
    user, _, host = destination.rpartition("@")
    async with open_ssh_transport(host, user=user or None) as transport:
        yield transport


def describe(result: UploadResult) -> str:
    """One line a log file would be glad to have."""
    return (
        f"{result.transferred} bytes -> {result.remote_path.decode()}  "
        f"mechanism={result.mechanism}  durability={result.durability}  "
        f"size={result.size_check}  atomic={result.atomic}  durable={result.durable}"
    )


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "report.csv"
        # Comfortably more than one request's worth of payload, so the in-place watcher at
        # the end sees the file at several sizes rather than appearing complete in one go.
        rows = b"".join(b"%d,%d\n" % (i, i * 7) for i in range(80_000))
        _ = source.write_bytes(b"id,total\n" + rows)
        target_dir = Path(remote_dir) if remote_dir else workdir
        target = target_dir / "report.csv"

        async with connect(destination, workdir) as transport, open_session(transport) as sftp:
            print(f"server version {sftp.server_version}, {len(sftp.extensions)} extensions")
            print(f"  posix-rename: {sftp.supports('posix-rename@openssh.com')}")
            print(f"  fsync:        {sftp.supports('fsync@openssh.com')}\n")

            # 1. The default. Staged, flushed, renamed into place.
            result = await sftp.put(source, str(target))
            print("default    ", describe(result))
            print("            staged at", result.staged_at)

            # 2. Publishing over a file that is already there. With posix-rename this is
            #    still one step; without it, the fallback removes the old file first and the
            #    result says so, because the window matters to whoever is reading it.
            result = await sftp.put(source, str(target))
            print("republish  ", describe(result))

            # 3. Demanding the real guarantee. On a server with no posix-rename and a
            #    destination that exists, this raises instead of quietly downgrading.
            try:
                result = await sftp.put(source, str(target), require_atomic=True)
            except CapabilityError as refusal:
                print("strict      refused:", refusal)
            else:
                print("strict     ", describe(result))

            # 4. Opting out, which is what every other SFTP client does by default. A
            #    consumer polling the directory can see this one half-written.
            in_place = target_dir / "report-in-place.csv"
            sizes: list[int] = []

            def watch(transferred: int, total: int | None) -> None:
                sizes.append(in_place.stat().st_size if in_place.exists() else -1)

            result = await sftp.put(source, str(in_place), atomic=False, progress=watch)
            print("in place   ", describe(result))
            print(f"            a watcher saw sizes {sizes[:6]}... (-1 means 'not there yet')")

        if destination is None:
            print("\nverified:", target.stat().st_size, "bytes at", target)


if __name__ == "__main__":
    anyio.run(main)

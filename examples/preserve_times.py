"""Carry a file's timestamps across a transfer, and read one back correctly.

    python examples/preserve_times.py                 # against a local sftp-server, no network
    python examples/preserve_times.py user@host /dir  # against a real server over ssh

A transfer stamps its destination with the time of the transfer unless you ask otherwise --
here, in `scp`, in `rsync`, and in every other SFTP client. That default is fine and it is also
the quietest way to lose information this library moves: the bytes are right, the size check
passes, the result says success, and only a field nobody inspects has been rewritten with a
plausible number.

The last section is the one worth reading twice. `longname` looks like it carries a timestamp
and does not: it drops the year inside six months, drops the *time* outside it, and renders in
the server's timezone -- so scraping it yields a wrong date rather than a coarse one.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp.session import open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

# 2020-09-13, and atime deliberately different from mtime so a swapped pair would show.
KNOWN_MTIME = 1_600_000_000
KNOWN_ATIME = 1_600_000_007


@asynccontextmanager
async def connect(destination: str | None, workdir: Path):
    """Either a real ssh connection, or the genuine sftp-server on a pipe."""
    if destination is None:
        async with open_local_server_transport(cwd=workdir) as transport:
            yield transport
        return
    user, _, host = destination.rpartition("@")
    async with open_ssh_transport(host, user=user or None) as transport:
        yield transport


def show(label: str, path: Path) -> None:
    stamp = dt.datetime.fromtimestamp(int(path.stat().st_mtime), dt.UTC)
    expected = dt.datetime.fromtimestamp(KNOWN_MTIME, dt.UTC)
    verdict = "preserved" if stamp == expected else "stamped with the transfer time"
    print(f"  {label:<34} {stamp:%Y-%m-%d %H:%M:%S} UTC   ({verdict})")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        source = workdir / "quarterly.csv"
        source.write_bytes(b"id,total\n1,42\n")
        os.utime(source, (KNOWN_ATIME, KNOWN_MTIME))
        base = Path(remote_dir) if remote_dir else workdir

        async with connect(destination, workdir) as transport, open_session(transport) as sftp:
            print(
                f"source file is dated {dt.datetime.fromtimestamp(KNOWN_MTIME, dt.UTC):%Y-%m-%d}\n"
            )

            print("upload:")
            default = base / "default.csv"
            result = await sftp.put(source, str(default).encode())
            print(f"  UploadResult.times = {result.times}")
            show("put() with no flag", default)

            kept = base / "kept.csv"
            result = await sftp.put(source, str(kept).encode(), preserve_times=True)
            print(f"  UploadResult.times = {result.times}")
            show("put(preserve_times=True)", kept)

            # A server that will not set times does not fail the upload -- the bytes are the
            # payload. `result.times` would read `unavailable` and the file would still be
            # published, which is the same trade a missing fsync makes.

            print("\ndownload:")
            plain = workdir / "downloaded-default.csv"
            await sftp.get(str(kept).encode(), plain)
            show("get() with no flag", plain)

            carried = workdir / "downloaded-kept.csv"
            await sftp.get(str(kept).encode(), carried, preserve_times=True)
            show("get(preserve_times=True)", carried)

            print("\nreading a timestamp back:")
            entries = [e for e in await sftp.listdir(str(base).encode()) if e.name.endswith(".csv")]
            for entry in sorted(entries, key=lambda e: e.name):
                # `modified` is `datetime | None`. The None is not decoration: a server that
                # sends no ACMODTIME has told you nothing, and coercing that to 0 dates the
                # file to 1970 -- which reads as "very old" to every `if remote > local`.
                stamp = entry.modified.isoformat() if entry.modified else "server did not say"
                print(f"  {entry.name:<20} modified={stamp}")

            print("\n  and the same entries as longname, which cannot carry a usable date:")
            for entry in sorted(entries, key=lambda e: e.name):
                print(f"    {entry.longname.decode()}")
            print(
                "\n  Note what is missing. A file modified inside the last six months prints a\n"
                "  time and no year; an older one prints a year and no time; never both. It is\n"
                "  also rendered in the *server's* timezone, so the same instant can read as a\n"
                "  different calendar day. Read entry.modified instead -- it is exact."
            )


if __name__ == "__main__":
    anyio.run(main)

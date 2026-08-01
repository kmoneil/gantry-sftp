"""Download a file, with progress, over a pipelined connection.

    python examples/download.py                       # against a local sftp-server, no network
    python examples/download.py user@host /remote/f   # against a real server over ssh

`get()` issues as many READs as the window allows before waiting for any reply, and writes
each payload at the offset its own request asked for -- never by arrival order, because
out-of-order completion is the normal case and is the entire point of pipelining.

The last section shows the failure nobody plans for: asking to download something that turns
out to be a *directory*. It leaves a local file, and the error says which one.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def bar(transferred: int, total: int | None) -> None:
    """A progress callback with the stable signature every long operation here takes."""
    if total:
        done = 40 * transferred // total
        print(f"\r  [{'#' * done}{'.' * (40 - done)}] {transferred}/{total}", end="", flush=True)


async def show_what_a_failure_leaves(sftp, workdir: Path) -> None:
    """Download something that is a directory, and look at what is left on disk.

    OpenSSH permits `open(2)` on a directory, so the refusal arrives at the *read* -- by which
    time the destination has been created. It is left where it is rather than deleted: it is
    your file, not a staging name of the library's, and `resume=True` continues from exactly
    such a partial. So the error names it, and the note says what to do about it.
    """
    a_directory = workdir / "a-directory"
    a_directory.mkdir()
    landed = workdir / "not-a-file.bin"

    try:
        _ = await sftp.get(str(a_directory), landed)
    except TransferError as failure:
        print(f"\n{failure.args[0]}")
        print(f"local_path : {failure.local_path}")
        print(f"transferred: {failure.transferred}")
        print(f"still there: {landed.exists()}, {landed.stat().st_size} bytes")
        print(f"note       : {failure.__notes__[0]}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_path = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        local = workdir / "downloaded.bin"

        if destination is None:
            # No host: the genuine OpenSSH sftp-server on a pipe, serving this directory.
            # Same server program, no ssh, no keys, no network.
            remote = workdir / "remote.bin"
            _ = remote.write_bytes(bytes(range(256)) * 4096)
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                print(f"downloading {remote}")
                result = await sftp.get(str(remote), local, progress=bar)
                await show_what_a_failure_leaves(sftp, workdir)
        else:
            if remote_path is None:
                sys.exit("usage: python examples/download.py user@host /remote/path")
            user, _, host = destination.rpartition("@")
            async with (
                open_ssh_transport(host, user=user or None) as transport,
                open_session(transport) as sftp,
            ):
                print(f"downloading {remote_path} from {host}")
                result = await sftp.get(remote_path, local, progress=bar)

        # `get` returns a report rather than a byte count (D-99). `transferred` is what this
        # call moved; `size` is what the file holds, and the two differ on a resume.
        print(f"\n{result.transferred} bytes -> {result.local_path}")
        print(f"on disk: {local.stat().st_size} bytes")
        print(
            f"size check: {result.size_check.value}   content check: {result.content_check.value}"
        )


if __name__ == "__main__":
    anyio.run(main)

"""Resume an interrupted transfer, in both directions -- and what each one actually proves.

    python examples/resume.py                   # against a local sftp-server, no network
    python examples/resume.py user@host /dir    # against a real server over ssh

Both directions are **opt-in**, and not because resuming is hard. They are opt-in because a
resume is a claim about bytes nobody re-read.

Downloading is the stronger of the two. The partial file is on your disk, so its length is a
fact rather than a report, and a READ at an explicit offset is idempotent -- ask for the same
range twice and you get the same bytes. What it still cannot know is whether those bytes came
from *this* remote file, so a local partial longer than the remote is refused rather than
quietly truncated.

Uploading is weaker and the docs say so in those words. The offset comes from the size the
*server* reports, and a size match proves the byte count agrees and nothing else: the remote
partial may be from a different run, a different source file, or another writer entirely.

And there is one combination that cannot work, which this example demonstrates by catching
it. `atomic=True` writes to a staging file whose name carries fresh randomness on every call
-- that randomness is what stops two publishers colliding. It also means a previous run's
staging file has a name this run cannot reconstruct, so there is nothing to resume into.
Rather than silently re-uploading the whole file, `put()` refuses and names the two fixes.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import anyio

from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import Publish, Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

PAYLOAD = os.urandom(600_000)
INTERRUPT_AT = 250_000


class InterruptedTransferError(Exception):
    """Raised from a progress callback, to stop a transfer at a known point."""


def size_of(path: Path) -> int:
    """Filesystem calls live outside the async frames, which is what ASYNC240 asks for."""
    return path.stat().st_size


def matches_payload(path: Path) -> bool:
    return path.read_bytes() == PAYLOAD


def write_half_payload(path: Path) -> Path:
    _ = path.write_bytes(PAYLOAD[: len(PAYLOAD) // 2])
    return path


def stop_partway(transferred: int, total: int | None) -> None:
    """Abort once enough has moved to leave something worth resuming."""
    if transferred >= INTERRUPT_AT and (total is None or transferred < total):
        raise InterruptedTransferError


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


async def resume_a_download(sftp: Session, remote: str, local: Path) -> None:
    """Kill a download partway, then finish it without re-sending what arrived."""
    print("Download")
    with suppress(InterruptedTransferError):
        _ = await sftp.get(remote, local, depth=1, progress=stop_partway)

    partial = size_of(local)
    print(f"  interrupted with {partial:,} of {len(PAYLOAD):,} bytes on disk")

    moved = await sftp.get(remote, local, resume=True)
    print(f"  resumed, moved {moved:,} more (a fresh download would have moved {len(PAYLOAD):,})")

    if not matches_payload(local):
        raise AssertionError("the resumed file does not match the source")
    print("  the two halves join: byte-identical to the source")


async def resume_an_upload(sftp: Session, source: Path, remote: str) -> None:
    """The same in reverse, and the flag combination that cannot work."""
    print("\nUpload")

    # atomic=True is the default, and it cannot be resumed without a fixed staging name.
    # Caught rather than described, because a refusal you can see is worth more than a
    # paragraph saying it would happen.
    try:
        _ = await sftp.put(source, remote, resume=True)
    except ValueError as refusal:
        print(f"  atomic + resume, no staging_name -> refused:\n    {refusal}")

    # In place: the destination is its own staging file, so there is a name to resume into.
    with suppress(InterruptedTransferError):
        _ = await sftp.put(
            source, remote, publish=Publish(atomic=False), depth=1, progress=stop_partway
        )

    result = await sftp.put(source, remote, publish=Publish(atomic=False), resume=True)
    print(f"  resumed in place, moved {result.transferred:,} more")

    # And the refusal that stops resume being a corruption primitive: a remote partial that
    # cannot be a prefix of what we are sending.
    longer = write_half_payload(source.parent / "longer.bin")
    try:
        _ = await sftp.put(longer, remote, publish=Publish(atomic=False), resume=True)
    except TransferError as refusal:
        print(f"  remote longer than the source -> refused:\n    {refusal}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/resume.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "payload.bin"
        _ = source.write_bytes(PAYLOAD)

        async with connect(destination, workdir) as sftp:
            base = remote_dir if remote_dir is not None else str(workdir)
            await resume_a_download(sftp, f"{base}/payload.bin", workdir / "downloaded.bin")
            await resume_an_upload(sftp, source, f"{base}/uploaded.bin")

            if destination is not None:  # tidy up after ourselves on a real server
                await sftp.remove(f"{base}/uploaded.bin")

    print("\nBoth directions are off by default. A resume is a claim about bytes nobody re-read.")


if __name__ == "__main__":
    anyio.run(main)

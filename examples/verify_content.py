"""Verify what the server actually holds -- and the resume this stops from corrupting a file.

    python examples/verify_content.py                   # against a local sftp-server, no network
    python examples/verify_content.py user@host /dir    # against a real server over ssh

Every upload checks the published file's **length** against the local one. That catches
truncation, which is the common failure, and it catches nothing else. A file of exactly the
right length whose bytes are wrong passes it every time -- which is the whole reason this
example exists, because that is not a hypothetical shape.

Three rungs, and `verify=` names which one to reach for:

* `Verify.SIZE`   -- the default. Length only.
* `Verify.HASH`   -- ask the server to hash what it holds. Free of payload, and absent from
                     nearly every real endpoint: OpenSSH answers OP_UNSUPPORTED under all
                     three spellings of `check-file`, so this usually reports UNAVAILABLE.
* `Verify.REREAD` -- read the bytes back and compare. Works against **anything**, and costs a
                     second transfer plus scratch disk. It is the only content check most
                     endpoints can offer.

The library never reports a rung it did not reach. `result.content_check` says UNAVAILABLE
rather than success when a rung was asked for and could not run, because "not checked" quietly
reading as "checked and fine" is the failure the ladder exists to prevent.

The second half is the sharper one. `resume=True` continues from the size the server reports,
and a size match proves the byte *count* agrees. A remote partial of the right length from the
wrong source -- a previous run against a different file, a truncated staging file, another
writer -- gets completed, published, and passes the size check, because the finished length is
correct. Nothing anywhere reports a problem. Run this and watch it get refused instead.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import Publish, Session, Verify, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

PAYLOAD = os.urandom(300_000)
ADOPTED = 120_000


def write_bytes(path: Path, data: bytes) -> Path:
    """Filesystem calls live outside the async frames, which is what ASYNC240 asks for."""
    _ = path.write_bytes(data)
    return path


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


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


async def verify_an_upload(sftp: Session, source: Path, remote: str) -> None:
    """Ask for each rung in turn and print what was actually reached."""
    print("Verifying an upload")

    plain = await sftp.put(source, remote)
    print(f"  default            size_check={plain.size_check} content_check={plain.content_check}")

    # Rung 1. Against OpenSSH this comes back UNAVAILABLE, and that is the honest answer
    # rather than a failure -- the upload happened and its length was checked.
    hashed = await sftp.put(source, remote, verify=Verify.HASH)
    print(f"  verify=hash        content_check={hashed.content_check}")
    if hashed.content_check == "unavailable":
        print("    ^ this server does not implement check-file, which is the normal case")

    # Rung 2. Needs no extension at all, which is exactly why it is the one that works.
    reread = await sftp.put(source, remote, verify=Verify.REREAD)
    print(f"  verify=reread      content_check={reread.content_check}")
    print(f"    read {len(PAYLOAD):,} bytes back and compared them -- a second transfer")


async def resume_onto_a_partial_from_the_wrong_source(
    sftp: Session, workdir: Path, remote: str
) -> None:
    """Adopt a partial that is the right length and the wrong bytes, twice.

    Once ungated, to show what the failure actually looks like -- a successful call and a
    corrupt file. Then again with rung 2, which refuses it on any server.
    """
    print("\nResuming onto a partial from the wrong source")

    # What a previous run against a *different* file leaves behind. The length is fine; that
    # is the entire problem, because the length is all a size check has to go on.
    poisoned = write_bytes(workdir / "poisoned.bin", os.urandom(ADOPTED))
    remote_partial = f"{remote}.partial"
    _ = await sftp.put(poisoned, remote_partial, publish=Publish(atomic=False))
    print(f"  the server holds {ADOPTED:,} bytes that are not a prefix of our file")

    source = write_bytes(workdir / "source.bin", PAYLOAD)
    try:
        result = await sftp.put(source, remote_partial, publish=Publish(atomic=False), resume=True)
    except TransferError as refusal:
        # Rung 1 was available: the prefix was proven wrong before a byte moved.
        print(f"  refused before a byte was sent:\n    {refusal}")
        return

    # No check-file on this server, so the gate could not run. Note what came back: a
    # successful result whose *size check passed*, over a file that is half one upload and
    # half another. This is the failure the ladder exists to name.
    print(f"  no check-file here, so the gate could not run: resume_check={result.resume_check}")
    print(f"    size_check={result.size_check} -- passed, and the published file is corrupt")
    _ = await sftp.get(remote_partial, workdir / "published.bin")
    published = read_bytes(workdir / "published.bin")
    print(f"    {len(published):,} bytes, matches the source: {published == PAYLOAD}")

    # Rung 2 needs no extension, so it catches on exactly the servers rung 1 cannot.
    print("  asking for rung 2 instead, which any server can answer:")
    try:
        _ = await sftp.put(
            source,
            remote_partial,
            publish=Publish(atomic=False),
            resume=True,
            verify=Verify.REREAD,
        )
    except TransferError as refusal:
        print(f"    refused:\n      {refusal}")
    else:
        raise AssertionError("rung 2 should have caught the poisoned prefix")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/verify_content.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = write_bytes(workdir / "payload.bin", PAYLOAD)
        base = f"{remote_dir}/verified.bin" if remote_dir else str(workdir / "verified.bin")

        async with connect(destination, workdir) as sftp:
            await verify_an_upload(sftp, source, base)
            await resume_onto_a_partial_from_the_wrong_source(sftp, workdir, base)

        print("\nRung 3 always runs. Rungs 1 and 2 run when you ask, and say which one you got.")


if __name__ == "__main__":
    anyio.run(main)

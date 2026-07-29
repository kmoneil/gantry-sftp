"""Which server is at the other end, what it can do, and what happens when it cannot.

    python examples/server_capabilities.py                  # local sftp-server, no network
    python examples/server_capabilities.py user@host        # a real server over ssh

Two surfaces that shipped without a runnable example, and one lesson they share.

``session.profile`` names the implementation from the extensions the handshake already
carried, so it costs no round trip. It is **diagnostic only**: nothing in this library changes
behaviour because of it. A fingerprint that silently altered semantics would be a second,
invisible configuration layer, and the one thing worse than a server quirk is a client quirk
nobody can see.

``check_file()`` is rung 1 of the verification ladder -- the server hashes the file it already
has, so nothing moves twice. Against the OpenSSH server below it answers ``OP_UNSUPPORTED``,
and **that is the interesting path**, because it is the one nearly every real endpoint takes.
An example that only demonstrated the happy case would be demonstrating the rarer half.

The degradation is what this prints: ask, be refused, and fall back to the check that works
everywhere -- the size comparison ``put`` and ``get`` already perform on every transfer.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp import OpenFlag
from gantry_sftp.codec import EXTENSION_CHECK_FILE
from gantry_sftp.exceptions import ServerError, UnsupportedError
from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


async def describe_server(sftp: Session) -> None:
    """Everything the handshake already told us, printed rather than guessed at."""
    print(f"server:      {sftp.profile.label}")
    print(f"             {sftp.profile.description}")
    print(f"version:     {sftp.server_version}")
    print(f"extensions:  {len(sftp.extensions)}")
    for name, value in sftp.extensions.items():
        print(f"  {name.decode('ascii', 'replace')} = {value.decode('ascii', 'replace')!r}")
    # Advertisement is not the same question as support: DESIGN 4.2 makes capability detection
    # advertisement *plus* an optional probe, because endpoints implement extensions they never
    # list. `supports()` answers the first question only, and says so.
    print(f"\nadvertises check-file: {sftp.supports(EXTENSION_CHECK_FILE)}")
    print(f"repr: {sftp!r}")


async def try_to_hash_remotely(sftp: Session, remote: bytes) -> bytes | None:
    """Ask the server to hash the file. Return the digest, or ``None`` if it will not.

    The refusal arrives as an exception rather than as a return value on purpose: a server
    that cannot verify is a fact the caller has to handle, and a ``None`` that means both
    "no digest" and "not supported" is how an unverified transfer gets reported as verified.
    """
    handle = await sftp.open(remote, OpenFlag.READ)
    try:
        algorithm, digests = await sftp.check_file(handle)
    except UnsupportedError:
        print("  check-file: OP_UNSUPPORTED -- this server does not implement it")
        return None
    except ServerError as error:
        # Not the same thing, and worth separating: a server that *has* the extension can
        # still refuse this particular file. Paramiko refuses a write-only handle exactly here.
        print(f"  check-file: refused -- {error}")
        return None
    else:
        print(f"  check-file: {algorithm.decode()} over {len(digests)} block(s)")
        return digests[0]
    finally:
        await sftp.close(handle)


async def verify(sftp: Session, local: Path, remote: bytes) -> None:
    """Rung 1 if the server has it, rung 3 if it does not -- and say which one happened."""
    print("\nverifying what the server actually holds:")
    digest = await try_to_hash_remotely(sftp, remote)
    if digest is not None:
        print(f"  rung 1 (content, no bytes moved): {digest.hex()[:32]}...")
        return

    # The fallback every endpoint supports, and the one `put` already ran as part of the
    # upload. Repeated here so the example shows what the degradation *is* rather than
    # asserting that one exists.
    attributes = await sftp.stat(remote)
    # `os.stat` rather than `Path.stat`: a blocking pathlib call inside a coroutine is what
    # ASYNC240 is for, and the local size is one syscall on a file we just wrote.
    local_size = os.stat(local).st_size  # noqa: PTH116
    print(f"  rung 3 (size only): remote={attributes.size} local={local_size}")
    print(f"  agree: {attributes.size == local_size}")
    print("  what rung 3 cannot catch: the right number of wrong bytes.")


async def run(sftp: Session, workdir: Path, remote_dir: str) -> None:
    source = workdir / "capabilities.csv"
    _ = source.write_bytes(b"id,value\n" + b"7,x\n" * 500)
    remote = f"{remote_dir.rstrip('/')}/capabilities.csv".encode()

    await describe_server(sftp)
    result = await sftp.put(source, remote)
    print(f"\nuploaded {result.transferred} bytes, size_check={result.size_check.name}")
    await verify(sftp, source, remote)
    await sftp.remove(remote)


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        if destination is None:
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                await run(sftp, workdir, str(workdir))
            return

        user, _, host = destination.rpartition("@")
        async with (
            open_ssh_transport(host, user=user or None) as transport,
            open_session(transport) as sftp,
        ):
            await run(sftp, workdir, await _home(sftp))


async def _home(sftp: Session) -> str:
    """Where to put the file on a real server, asked rather than assumed."""
    return (await sftp.realpath(b".")).decode("utf-8", "replace")


if __name__ == "__main__":
    anyio.run(main)

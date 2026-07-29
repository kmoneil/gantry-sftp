"""Stop a transfer, and see what it leaves behind — which is nothing.

    python examples/cancellation.py                    # against a local sftp-server, no network
    python examples/cancellation.py user@host /remote  # against a real server over ssh

A timeout around a session is the ordinary spelling, and it is the one this example is really
about::

    with anyio.move_on_after(30):
        async with open_ssh_transport(...) as t, open_session(t) as sftp:
            await sftp.get("/incoming/big.iso", "big.iso")

That cancel reaches the transfer *and* the session's reader at the same instant. Cleanup —
closing the remote handle, removing the staging file of an interrupted upload — is shielded
so it still runs, and the reader is shielded too so there is still somebody to read the
replies that cleanup waits for. Without the second half the first one hangs: the shielded
CLOSE waits out `request_timeout` for an answer nobody is left to route.

`request_timeout` is also the *only* bound teardown has, because a shield is not cancellable
from outside. Against a peer that has stopped reading its socket, `request_timeout=None` means
leaving the block waits on that CLOSE forever — which is what asking for no bound at all asks
for, and it is never the default.

This run cancels from the progress callback instead of after a wall-clock deadline, so it
lands mid-transfer every time rather than most of the time. It is the same cancellation.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp.session import DEFAULT_REQUEST_TIMEOUT, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

SIZE = 4 << 20
"""Big enough to take many round trips, so a cancel lands in the middle of one."""


def stop_after_first_reply(scope: anyio.CancelScope, moved: list[int]):
    """A progress callback that cancels `scope` as soon as bytes have actually moved.

    Cancelling from inside the callback is ordinary: `CancelScope.cancel()` is synchronous
    and takes effect at the transfer's next checkpoint.
    """

    def watch(transferred: int, total: int | None) -> None:
        if transferred and not moved:
            moved.append(transferred)
            scope.cancel()

    return watch


def size_on_disk(path: Path) -> int:
    """A local `stat`, out of the coroutine: filesystem calls block the event loop."""
    return path.stat().st_size if path.exists() else 0


async def cancel_a_download(sftp, remote: str, local: Path) -> None:
    started = anyio.current_time()
    scope, moved = anyio.CancelScope(), []
    with scope:
        _ = await sftp.get(remote, local, progress=stop_after_first_reply(scope, moved))
    elapsed = anyio.current_time() - started

    partial = size_on_disk(local)
    print(f"  cancelled mid-transfer after {moved[0]} bytes")
    print(f"  unwound in {elapsed:.2f}s, with request_timeout={DEFAULT_REQUEST_TIMEOUT}s")
    print(f"  the partial file is still here, {partial} bytes of {SIZE}")


async def cancel_an_upload(sftp, local: Path, remote_directory: str) -> None:
    scope, moved = anyio.CancelScope(), []
    with scope:
        _ = await sftp.put(
            local,
            f"{remote_directory}/uploaded.bin",
            progress=stop_after_first_reply(scope, moved),
        )

    names = sorted(entry.name for entry in await sftp.listdir(remote_directory))
    # An interrupted atomic put stages under a dot-name and publishes by renaming it, so
    # anything left in either spelling is litter a consumer could trip over.
    litter = [name for name in names if name.startswith(".") or name == "uploaded.bin"]
    print(f"  cancelled mid-upload after {moved[0]} bytes")
    print(f"  the destination directory holds: {names}")
    print(f"  left behind: {', '.join(litter) if litter else 'none'}")


async def demonstrate(sftp, remote_directory: str, workdir: Path, source: Path) -> None:
    print("cancelling a download")
    await cancel_a_download(sftp, f"{remote_directory}/big.bin", workdir / "partial.bin")

    print("cancelling an upload")
    await cancel_an_upload(sftp, source, remote_directory)

    # The cancellation stopped the transfers, not the connection. A session that had leaked
    # the handle, or lost its reader, would fail or hang here rather than answer.
    attributes = await sftp.stat(f"{remote_directory}/big.bin")
    print(f"the session still works: the remote file is {attributes.size} bytes")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_directory = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "to-upload.bin"
        _ = source.write_bytes(bytes(range(256)) * (SIZE // 256))

        if destination is None:
            # No host: the genuine OpenSSH sftp-server on a pipe, serving this directory.
            remote_root = workdir / "remote"
            remote_root.mkdir()
            _ = (remote_root / "big.bin").write_bytes(bytes(range(256)) * (SIZE // 256))
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                await demonstrate(sftp, str(remote_root), workdir, source)
        else:
            if remote_directory is None:
                sys.exit("usage: python examples/cancellation.py user@host /remote/dir")
            user, _, host = destination.rpartition("@")
            async with (
                open_ssh_transport(host, user=user or None) as transport,
                open_session(transport) as sftp,
            ):
                # The remote directory must already hold a big.bin to interrupt.
                await demonstrate(sftp, remote_directory, workdir, source)


if __name__ == "__main__":
    anyio.run(main)

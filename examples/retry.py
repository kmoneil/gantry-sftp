"""Survive a dropped link: reconnect, and resume rather than start over.

    python examples/retry.py                    # against a local sftp-server, no network
    python examples/retry.py user@host /dir     # against a real server over ssh

A session cannot reconnect itself. `open_session()` is handed a transport whose lifetime
belongs to the caller -- it drives one, it does not know how to make another. So reconnection
lives one level up, in `with_reconnect()`, and what it needs from you is a *recipe*: any
zero-argument callable that produces a new transport.

    recipe = functools.partial(open_ssh_transport, "example.com", user="bob")

The operation is then re-run from the beginning against a session that did not exist before.
Nothing survives a reconnect -- not the remote handles, not the request ids, not the
negotiated limits -- so the operation has to be idempotent or resumable. `get(resume=True)`
is the resumable case, and it is why this reads as one line rather than a state machine.

The classification is the part worth reading twice. A failed *authentication* is never
retried, and not because it is merely futile: OpenSSH 9.8+ applies `PerSourcePenalties`, so
repeated failed auth from one address gets that address progressively locked out. A retry
loop would turn one wrong key into a host that stops answering for everything behind that IP.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

import anyio

from gantry_sftp.exceptions import (
    AuthenticationError,
    ConnectError,
    HostKeyError,
    NoSuchFileError,
    ServerError,
    TransferTimeoutError,
)
from gantry_sftp.session import Session, is_retryable, with_reconnect
from gantry_sftp.transport import Transport, open_local_server_transport, open_ssh_transport

PAYLOAD = bytes(range(256)) * 4_000  # 1 MB, several requests at any sane read length


class FlakyTransport:
    """A real transport that stops working partway, the way a dropped link does.

    Only here to make the example self-contained: a demonstration of reconnection needs a
    connection that dies, and waiting for a real one to drop is not a demo.
    """

    def __init__(self, inner: Transport, *, die_after_bytes: int) -> None:
        self._inner = inner
        self._budget = die_after_bytes
        self.delivered = 0

    async def send(self, data: bytes | memoryview) -> None:
        await self._inner.send(data)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if self.delivered >= self._budget:
            raise ConnectError("connection closed by the remote end", returncode=255)
        chunk = await self._inner.receive(max_bytes)
        self.delivered += len(chunk)
        return chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


def show_classification() -> None:
    """Which failures buy another attempt, and which are answers."""
    print("What counts as retryable:")
    for error in (
        ConnectError("ssh exited while we were writing to it"),
        TransferTimeoutError("no response for 60s"),
        AuthenticationError("Permission denied (publickey)"),
        HostKeyError("Host key verification failed"),
        NoSuchFileError("no such file", code=2, message=b"No such file"),
        ServerError("server returned FAILURE", code=4, message=b"Failure"),
    ):
        verdict = "retry" if is_retryable(error) else "stop "
        print(f"  {verdict}  {type(error).__name__}")
    print("  ^ AuthenticationError and HostKeyError are ConnectError subclasses, and are")
    print("    excluded on purpose: OpenSSH 9.8+ locks out the source address on repeats.")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/retry.py user@host /remote/dir")

    show_classification()

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "payload.bin"
        _ = source.write_bytes(PAYLOAD)
        local = workdir / "downloaded.bin"
        base = remote_dir if remote_dir is not None else str(workdir)
        connections = 0

        @asynccontextmanager
        async def recipe() -> AsyncGenerator[Transport]:
            """A new transport per attempt -- and the first one dies partway through."""
            nonlocal connections
            connections += 1
            opener = (
                partial(open_local_server_transport, cwd=workdir)
                if destination is None
                else partial(
                    open_ssh_transport,
                    destination.rpartition("@")[2],
                    user=destination.rpartition("@")[0] or None,
                )
            )
            async with opener() as transport:
                if connections > 1:
                    yield transport
                else:
                    yield FlakyTransport(transport, die_after_bytes=300_000)

        print("\nDownloading over a link that drops partway:")
        moved = await with_reconnect(
            recipe,
            lambda sftp: sftp.get(f"{base}/payload.bin", local, resume=True),
            attempts=3,
            backoff=0.1,
        )

        print(f"  connections used: {connections}")
        print(f"  moved on the second: {moved.transferred:,} of {len(PAYLOAD):,} bytes")
        print(f"  the first carried the rest: {moved.adopted:,}")

        if local.read_bytes() != PAYLOAD:
            raise AssertionError("the resumed download does not match the source")
        print("  byte-identical to the source")

        # A terminal error is raised at once rather than waited out three times: being slow
        # to report a missing file is its own bug.
        async def missing(sftp: Session) -> object:
            return await sftp.stat(f"{base}/definitely-not-here.bin")

        before = connections
        try:
            _ = await with_reconnect(recipe, missing, attempts=3, backoff=5)
        except NoSuchFileError as terminal:
            print(f"\nTerminal error, one connection and no backoff: {terminal}")
        print(f"  connections spent: {connections - before}")

    print("\nA retry is an at-least-once execution. Resumable or idempotent, or neither.")


if __name__ == "__main__":
    anyio.run(main)

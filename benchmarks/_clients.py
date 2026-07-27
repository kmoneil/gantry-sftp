"""One uniform interface over three SFTP clients, so the comparison is like for like.

The libraries being compared are the whole point of this directory, and the way they are
driven decides whether the numbers mean anything. Four fairness rules, each one a decision
that could have gone the other way:

**Each client uses its own best default API, not a hand-rolled loop.** ``paramiko.SFTPClient``
prefetches inside ``get``; ``asyncssh`` negotiates ``limits@openssh.com`` and picks its own
block size. Reimplementing either one to "match" ours would benchmark our idea of them.

**Everything that steers the client is turned off identically.** No agent, no
``~/.ssh/config``, no key search -- for us via :func:`sshd.scrubbed_ssh_env` and
``IdentitiesOnly``, for paramiko via ``allow_agent=False, look_for_keys=False``, for asyncssh
via ``agent_path=None, config=None``. A benchmark that reads the developer's ssh config
measures the developer's ssh config.

**Host keys are verified by all three.** It would have been simpler to give paramiko
``AutoAddPolicy`` and asyncssh ``known_hosts=None``, and it would have handed them a small
head start on a security check we perform. Verified against this server: paramiko parses
``ssh-keyscan``'s bracketed ``[127.0.0.1]:port`` entry and ``RejectPolicy`` still connects.

**The timed window excludes connect and close, and the session is closed inside it anyway.**
Closing matters even though it is not timed: the ``ssh`` child's CPU is invisible to
``getrusage`` until it has been reaped, so a client that left its connection open would report
its own subprocess as free. See :mod:`_harness`.

Our own upload is measured with ``atomic=False, fsync=False``, because that is the work the
other two do. Atomic publish is measured separately, as its own scenario, so what the
guarantee costs is a number rather than a footnote.
"""

from __future__ import annotations

import getpass
import importlib
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from importlib.util import find_spec
from pathlib import Path
from typing import ClassVar

import anyio
from sshd import SSHServer, connect_kwargs

from gantry_sftp.session import open_session
from gantry_sftp.transport import open_ssh_transport


def _username() -> str:
    return getpass.getuser()


def _file_size(path: Path) -> int:
    """Size on disk, as a plain synchronous call.

    A named helper rather than ``path.stat()`` inline, because the callers are ``async def``
    and this is genuinely blocking I/O in an async function -- the thing ASYNC240 exists to
    catch. It is outside both measured windows (the wall clock stops before it and the CPU
    delta is dominated by megabytes of transfer), so a thread hand-off would buy nothing; but
    silencing the rule inline would have made a real distinction invisible to the next reader.
    """
    return path.stat().st_size


class Client(ABC):
    """One SFTP library, driven the way its own documentation drives it.

    Every method opens a connection, times only the operation, closes, and returns
    ``(wall_seconds, bytes_moved)``. Connections are not reused across samples: a benchmark
    that connects once and loops hides the cost of connecting, which for two of these three
    libraries is a key exchange performed in Python.
    """

    name: ClassVar[str]
    module: ClassVar[str]

    def __init__(self, server: SSHServer) -> None:
        self.server = server

    @classmethod
    def unavailable_reason(cls) -> str | None:
        """Why this client cannot run, or ``None``.

        The comparison libraries live in the ``bench`` dependency group rather than in the
        project's dependencies -- they carry Python cryptography, which this library exists
        not to need -- so a checkout that skipped that group must skip these rows rather than
        fail on them.
        """
        if find_spec(cls.module) is None:
            return f"{cls.module} is not installed (uv sync --group bench)"
        return None

    @classmethod
    def version(cls) -> str:
        return str(getattr(importlib.import_module(cls.module), "__version__", "unknown"))

    @abstractmethod
    async def connect_and_close(self) -> tuple[float, int]:
        """Open a session and close it, timing the whole thing. Moves no bytes."""

    @abstractmethod
    async def download(self, remote: Path, local: Path) -> tuple[float, int]:
        """Fetch one file."""

    @abstractmethod
    async def upload(self, local: Path, remote: Path) -> tuple[float, int]:
        """Send one file, in place, with no atomic publish and no fsync."""

    @abstractmethod
    async def download_many(self, remotes: Sequence[Path], into: Path) -> tuple[float, int]:
        """Fetch many files over one connection, sequentially.

        Sequentially for all three on purpose. Concurrency across files is exactly what
        ``Session`` cannot do yet (deferred as D-12), and a benchmark in which only the other
        two libraries were allowed to overlap files would be measuring a feature gap while
        looking like it measured a speed gap. This measures round trips per file, which is
        the thing the gap is actually about.
        """


class GantryClient(Client):
    """This library: ``ssh -s sftp`` as a subprocess, no cryptography in Python."""

    name = "gantry-sftp"
    module = "gantry_sftp"

    def _transport(self) -> AbstractAsyncContextManager[object]:
        return open_ssh_transport("127.0.0.1", **connect_kwargs(self.server))

    async def connect_and_close(self) -> tuple[float, int]:
        started = time.perf_counter()
        async with self._transport() as transport, open_session(transport):
            pass
        return time.perf_counter() - started, 0

    async def download(self, remote: Path, local: Path) -> tuple[float, int]:
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            written = await sftp.get(str(remote), local)
            elapsed = time.perf_counter() - started
        return elapsed, written

    async def upload(self, local: Path, remote: Path) -> tuple[float, int]:
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            result = await sftp.put(local, str(remote), atomic=False, fsync=False)
            elapsed = time.perf_counter() - started
        return elapsed, result.transferred

    async def upload_atomic(self, local: Path, remote: Path) -> tuple[float, int]:
        """Upload with the staging file, the flush and the rename this library defaults to.

        Not part of :class:`Client`: the other two libraries have no equivalent, so this is a
        measurement of what our own default costs rather than a comparison.
        """
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            result = await sftp.put(local, str(remote), atomic=True, fsync=True)
            elapsed = time.perf_counter() - started
        return elapsed, result.transferred

    async def download_many(self, remotes: Sequence[Path], into: Path) -> tuple[float, int]:
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            moved = 0
            for remote in remotes:
                moved += await sftp.get(str(remote), into / remote.name)
            elapsed = time.perf_counter() - started
        return elapsed, moved

    async def download_many_concurrently(
        self, remotes: Sequence[Path], into: Path, *, concurrency: int
    ) -> tuple[float, int]:
        """The same files over the same one connection, overlapping.

        Not part of :class:`Client`, and that is a fairness decision rather than an oversight.
        paramiko and asyncssh can both be driven concurrently too -- with a thread per transfer
        and with a task group respectively -- so a row comparing our concurrent number against
        their sequential one would be measuring a feature gap while looking like a speed gap,
        which is the exact trap the sequential row's caveat already names. This is us against
        us, like the atomic-publish row: what our own multiplexing is worth on this link.
        """
        moved: list[int] = []
        limit = anyio.Semaphore(concurrency)

        async with self._transport() as transport, open_session(transport) as sftp:

            async def fetch(remote: Path) -> None:
                async with limit:
                    got = await sftp.get(str(remote), into / remote.name)
                # Appended, not `total += await ...`. Augmented assignment loads the target
                # *before* evaluating the right-hand side, so with the await on that side every
                # concurrent task adds to a value it read before the others finished -- a lost
                # update that understates the byte count and, since MiB/s is derived from it,
                # reports the fastest row as the slowest.
                moved.append(got)

            started = time.perf_counter()
            async with anyio.create_task_group() as group:
                for remote in remotes:
                    group.start_soon(fetch, remote)
            elapsed = time.perf_counter() - started
        return elapsed, sum(moved)


class ParamikoClient(Client):
    """paramiko: SSH implemented in Python, which is what every other library wraps.

    Synchronous, so every call runs in a worker thread. That costs a thread hand-off per
    operation and nothing else -- the timed region is inside the thread, and a thread's CPU is
    counted in ``RUSAGE_SELF`` exactly as the main thread's is.
    """

    name = "paramiko"
    module = "paramiko"

    def _open(self):
        # Deferred, not lazy-by-accident: this module must import on a checkout that skipped
        # the bench group, so that `available()` can report the absence instead of raising it.
        import paramiko  # noqa: PLC0415

        client = paramiko.SSHClient()
        client.get_host_keys().load(str(self.server.known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname="127.0.0.1",
            port=self.server.port,
            username=_username(),
            key_filename=str(self.server.identity_file),
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def _connect_and_close(self) -> tuple[float, int]:
        started = time.perf_counter()
        client = self._open()
        try:
            client.open_sftp().close()
        finally:
            client.close()
        return time.perf_counter() - started, 0

    def _download(self, remote: Path, local: Path) -> tuple[float, int]:
        client = self._open()
        try:
            sftp = client.open_sftp()
            started = time.perf_counter()
            sftp.get(str(remote), str(local))
            elapsed = time.perf_counter() - started
            sftp.close()
        finally:
            client.close()
        return elapsed, _file_size(local)

    def _upload(self, local: Path, remote: Path) -> tuple[float, int]:
        client = self._open()
        try:
            sftp = client.open_sftp()
            started = time.perf_counter()
            sftp.put(str(local), str(remote))
            elapsed = time.perf_counter() - started
            sftp.close()
        finally:
            client.close()
        return elapsed, _file_size(local)

    def _download_many(self, remotes: Sequence[Path], into: Path) -> tuple[float, int]:
        client = self._open()
        try:
            sftp = client.open_sftp()
            started = time.perf_counter()
            for remote in remotes:
                sftp.get(str(remote), str(into / remote.name))
            elapsed = time.perf_counter() - started
            sftp.close()
        finally:
            client.close()
        return elapsed, sum(_file_size(into / r.name) for r in remotes)

    async def connect_and_close(self) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._connect_and_close)

    async def download(self, remote: Path, local: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._download, remote, local)

    async def upload(self, local: Path, remote: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._upload, local, remote)

    async def download_many(self, remotes: Sequence[Path], into: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._download_many, remotes, into)


class AsyncsshClient(Client):
    """asyncssh: SSH in Python too, but asyncio-native and it negotiates ``limits``.

    Worth watching in the results rather than only in the table: it defaults to 128 requests
    in flight at the server's ``max_read_len`` -- 128 x 261120 is about 33 MB, sixteen times
    its own 2 MiB channel window (``asyncssh.connection._DEFAULT_WINDOW``). Depth past the
    window buys nothing, which is DESIGN.md 5.1 restated in a second implementation.
    """

    name = "asyncssh"
    module = "asyncssh"

    def _connect(self):
        # Deferred for the same reason paramiko's is -- see ParamikoClient._open.
        import asyncssh  # noqa: PLC0415

        return asyncssh.connect(
            "127.0.0.1",
            port=self.server.port,
            username=_username(),
            client_keys=[str(self.server.identity_file)],
            known_hosts=str(self.server.known_hosts),
            config=None,
            agent_path=None,
        )

    async def connect_and_close(self) -> tuple[float, int]:
        started = time.perf_counter()
        async with self._connect() as conn, conn.start_sftp_client():
            pass
        return time.perf_counter() - started, 0

    async def download(self, remote: Path, local: Path) -> tuple[float, int]:
        async with self._connect() as conn, conn.start_sftp_client() as sftp:
            started = time.perf_counter()
            await sftp.get(str(remote), str(local))
            elapsed = time.perf_counter() - started
        return elapsed, _file_size(local)

    async def upload(self, local: Path, remote: Path) -> tuple[float, int]:
        async with self._connect() as conn, conn.start_sftp_client() as sftp:
            started = time.perf_counter()
            await sftp.put(str(local), str(remote))
            elapsed = time.perf_counter() - started
        return elapsed, _file_size(local)

    async def download_many(self, remotes: Sequence[Path], into: Path) -> tuple[float, int]:
        async with self._connect() as conn, conn.start_sftp_client() as sftp:
            started = time.perf_counter()
            for remote in remotes:
                await sftp.get(str(remote), str(into / remote.name))
            elapsed = time.perf_counter() - started
        return elapsed, sum(_file_size(into / r.name) for r in remotes)


ALL_CLIENTS: tuple[type[Client], ...] = (GantryClient, ParamikoClient, AsyncsshClient)
BASELINE = GantryClient.name
"""Client every other row is expressed against.

Ours, because the question the report answers is "what does this architecture buy" -- but the
renderer takes it as an argument rather than assuming it, so a reader who wants paramiko as
the reference can have it without editing the harness.
"""


def available(server: SSHServer) -> tuple[list[Client], list[str]]:
    """Instantiate every client that can run here, and collect the reasons for the rest."""
    ready: list[Client] = []
    skipped: list[str] = []
    for cls in ALL_CLIENTS:
        reason = cls.unavailable_reason()
        if reason is None:
            ready.append(cls(server))
        else:
            skipped.append(f"{cls.name}: {reason}")
    return ready, skipped


def library_versions() -> dict[str, str]:
    """Version of every client library that is installed, for the report header."""
    return {cls.name: cls.version() for cls in ALL_CLIENTS if cls.unavailable_reason() is None}

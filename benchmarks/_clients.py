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
import hashlib
import importlib
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from importlib.util import find_spec
from pathlib import Path
from typing import ClassVar

import anyio
from sshd import SSHServer, connect_kwargs

from gantry_sftp.session import Publish, open_session
from gantry_sftp.transport import open_ssh_transport


def _username() -> str:
    return getpass.getuser()


def _digest_of(path: Path) -> str:
    """Content digest of a local file, for a scenario whose destination is memory.

    Every scenario verifies the bytes it moved. The ones that write a file compare the file;
    a read into memory has nothing on disk to compare, so it compares a digest instead -- and
    a client that returned fast and wrong still fails rather than winning.
    """
    return hashlib.blake2b(path.read_bytes()).hexdigest()


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

        Sequentially for all three on purpose -- and no longer because we have no choice.
        This said ``Session`` could not overlap files, deferred as D-12; multiplexing closed
        that, and :meth:`GantryClient.download_many_concurrently` two methods below is the
        proof. The rule survives its original reason because paramiko and asyncssh can be
        driven concurrently too, so racing our task group against their ``for`` loop would
        measure a feature gap while looking like a speed gap. This measures round trips per
        file, which is the thing the gap is actually about.
        """

    @abstractmethod
    async def download_repeatedly(
        self, remote: Path, local: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        """Fetch one file several times on **one** connection, timing each fetch separately.

        The size sweep's primitive (D-92), and the one place the class docstring's
        no-connection-reuse rule is deliberately suspended -- identically for all three
        clients, which is what keeps their curves comparable with each other. The reason is
        D-81: a fresh connection per size would spend the small end of the ladder in TCP slow
        start, and a sweep looking for a cliff would find congestion control and name it one.

        Returns:
            Wall seconds for each timed transfer, warmups excluded. No byte count and no CPU:
            the size is the caller's own ladder entry, the bytes are verified by comparing the
            produced file, and one connection means one reaped child so per-sample CPU does
            not exist. See :mod:`_harness`.
        """

    @abstractmethod
    async def upload_repeatedly(
        self, local: Path, remote: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        """Send one file several times on one connection. Mirror of ``download_repeatedly``.

        Both directions, because a cliff need not be symmetric: `paramiko#2438` is a *write*
        pathology and reads are what most of the tuning attention goes to.
        """

    @abstractmethod
    async def upload_many(self, sources: Sequence[Path], into: Path) -> tuple[float, int]:
        """Send many files over one connection, sequentially. Mirror of ``download_many``.

        This row exists because the matrix had no small-file *upload* at all: both upload
        scenarios moved 16 MiB in one file, where a per-file round trip is noise by
        construction, so a change that added one to every ``put`` was invisible to the lane
        whose job is to notice. At 8 KiB the number is round trips rather than bytes, which
        is the only place a per-file cost can show up -- and ``put_tree`` over a drop
        directory of small files is a headline workload, so it needed a row regardless.

        Sequential for all three for the same fairness reason ``download_many`` is.
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
            result = await sftp.put(local, str(remote), publish=Publish(atomic=False, fsync=False))
            elapsed = time.perf_counter() - started
        return elapsed, result.transferred

    async def download_warm(
        self, remote: Path, local: Path, *, warmups: int = 1
    ) -> tuple[float, int]:
        """The same download, timed as a connection's *second* transfer rather than its first.

        Not part of :class:`Client`, and not a comparison: it exists to separate this
        library's scheduling from the transport's congestion control. Every other row here
        opens a fresh connection per sample -- deliberately, see the class docstring -- so
        every other row times a transfer that spends its opening round trips in TCP slow
        start. That is honest for a cross-library comparison, because all three pay it; it is
        misleading as a measure of what the pipeline can sustain, because a deep pipeline asks
        for more than an initial congestion window immediately and then waits for it to open.

        D-81 measured the gap one layer up (6.0 round trips for a 768 KiB transfer as a
        connection's first, 1.0 as its fourth) and this row is the same question asked of the
        benchmark's own 16 MiB scenario, which had never been measured any way but cold.

        The connection is closed inside the call like every other method's, so the ``ssh``
        child is reaped and its CPU counted -- but the session CPU therefore covers the
        discarded warmup transfers too, which is why this row's CPU column is not comparable
        with the cold row's. The caveats say so; the wall clock is what this row is for.

        Args:
            remote: File to fetch.
            local: Destination, overwritten by each warmup and finally by the timed run.
            warmups: Transfers to perform and discard before timing one. One is enough --
                D-81 measured the congestion window open by the second transfer.

        Returns:
            ``(wall_seconds, bytes_moved)`` for the timed transfer only.
        """
        async with self._transport() as transport, open_session(transport) as sftp:
            for _ in range(warmups):
                await sftp.get(str(remote), local)
            started = time.perf_counter()
            written = await sftp.get(str(remote), local)
            elapsed = time.perf_counter() - started
        return elapsed, written

    async def upload_atomic(self, local: Path, remote: Path) -> tuple[float, int]:
        """Upload with the staging file, the flush and the rename this library defaults to.

        Not part of :class:`Client`: the other two libraries have no equivalent, so this is a
        measurement of what our own default costs rather than a comparison.
        """
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            result = await sftp.put(local, str(remote), publish=Publish(atomic=True, fsync=True))
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

    async def upload_many(self, sources: Sequence[Path], into: Path) -> tuple[float, int]:
        # `atomic=False, fsync=False` to match `upload` and the other two clients. The size
        # check D-32 added is *not* opt-out-able here and that is the point of the row: with
        # atomic off it runs after the write rather than before the rename, but it runs, so
        # its per-file round trip is inside the timed region exactly as a user would pay it.
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            moved = 0
            for source in sources:
                result = await sftp.put(
                    source, str(into / source.name), publish=Publish(atomic=False, fsync=False)
                )
                moved += result.transferred
            elapsed = time.perf_counter() - started
        return elapsed, moved

    async def download_repeatedly(
        self, remote: Path, local: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        async with self._transport() as transport, open_session(transport) as sftp:
            for _ in range(warmups):
                await sftp.get(str(remote), local)
            walls = []
            for _ in range(repeats):
                started = time.perf_counter()
                await sftp.get(str(remote), local)
                walls.append(time.perf_counter() - started)
        return walls

    async def upload_repeatedly(
        self, local: Path, remote: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        # `atomic=False, fsync=False` to match the other two clients, exactly as `upload` does.
        # The sweep's question is where throughput falls with size; measuring our publish
        # guarantee against their absence of one would put a constant in every rung.
        publish = Publish(atomic=False, fsync=False)
        async with self._transport() as transport, open_session(transport) as sftp:
            for _ in range(warmups):
                await sftp.put(local, str(remote), publish=publish)
            walls = []
            for _ in range(repeats):
                started = time.perf_counter()
                await sftp.put(local, str(remote), publish=publish)
                walls.append(time.perf_counter() - started)
        return walls

    async def read_in_blocks(self, remote: Path, *, block_size: int) -> tuple[float, int]:
        """Read a whole remote file through the **file object**, in fixed blocks, into memory.

        The acceptance criterion D-91 attached to the file-object card (D-86), made
        measurable. `paramiko#2453` reports `SFTPFile.read()` running 25x slower than the same
        library's `SFTPClient.get()`, and the cause is the obvious implementation: one `READ`
        per call, awaited. Shipping that under a new name would have shipped the complaint, so
        the row exists to say which one we shipped.

        Into memory, and nothing is kept: the destination is not the subject. Bytes are
        verified by digest rather than by comparing a produced file, because there is no file.
        """
        digest = hashlib.blake2b()
        moved = 0
        async with self._transport() as transport, open_session(transport) as sftp:
            started = time.perf_counter()
            async with sftp.open_file(str(remote)) as handle:
                while chunk := await handle.read(block_size):
                    digest.update(chunk)
                    moved += len(chunk)
            elapsed = time.perf_counter() - started
        assert digest.hexdigest() == _digest_of(remote), "the file object read the wrong bytes"
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

    def _read_in_blocks_positional(self, remote: Path, block_size: int) -> tuple[float, int]:
        """`run_sync` passes positional arguments only, and every other hop here does the same."""
        return self._read_in_blocks(remote, block_size=block_size)

    def _read_in_blocks(self, remote: Path, *, block_size: int) -> tuple[float, int]:
        """`SFTPFile.read()` in a loop -- the control for our own file-object row.

        `paramiko#2453` is the reason this exists: their file object is reported at 25x their
        own `get`, which is the pathology D-86 had to avoid rather than reproduce. Reported and
        never asserted, like every other control here: an incumbent's defect must not be able
        to fail our lane.
        """
        client = self._open()
        digest = hashlib.blake2b()
        moved = 0
        try:
            sftp = client.open_sftp()
            started = time.perf_counter()
            with sftp.open(str(remote), "rb") as handle:
                while chunk := handle.read(block_size):
                    digest.update(chunk)
                    moved += len(chunk)
            elapsed = time.perf_counter() - started
            sftp.close()
        finally:
            client.close()
        assert digest.hexdigest() == _digest_of(remote), "the file object read the wrong bytes"
        return elapsed, moved

    async def read_in_blocks(self, remote: Path, *, block_size: int) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._read_in_blocks_positional, remote, block_size)

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

    def _upload_many(self, sources: Sequence[Path], into: Path) -> tuple[float, int]:
        client = self._open()
        try:
            sftp = client.open_sftp()
            started = time.perf_counter()
            for source in sources:
                sftp.put(str(source), str(into / source.name))
            elapsed = time.perf_counter() - started
            sftp.close()
        finally:
            client.close()
        return elapsed, sum(_file_size(into / s.name) for s in sources)

    def _repeatedly(
        self, transfer: Callable[[], object], repeats: int, warmups: int
    ) -> list[float]:
        """Time ``transfer`` ``repeats`` times after discarding ``warmups`` of them.

        The connection is the caller's, already open: the sweep's whole point is that one
        connection carries the ladder, so this helper must not create one.
        """
        for _ in range(warmups):
            transfer()
        walls = []
        for _ in range(repeats):
            started = time.perf_counter()
            transfer()
            walls.append(time.perf_counter() - started)
        return walls

    def _download_repeatedly(
        self, remote: Path, local: Path, repeats: int, warmups: int
    ) -> list[float]:
        client = self._open()
        try:
            sftp = client.open_sftp()
            walls = self._repeatedly(
                lambda: sftp.get(str(remote), str(local)), repeats=repeats, warmups=warmups
            )
            sftp.close()
        finally:
            client.close()
        return walls

    def _upload_repeatedly(
        self, local: Path, remote: Path, repeats: int, warmups: int
    ) -> list[float]:
        client = self._open()
        try:
            sftp = client.open_sftp()
            walls = self._repeatedly(
                lambda: sftp.put(str(local), str(remote)), repeats=repeats, warmups=warmups
            )
            sftp.close()
        finally:
            client.close()
        return walls

    async def connect_and_close(self) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._connect_and_close)

    async def download(self, remote: Path, local: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._download, remote, local)

    async def upload(self, local: Path, remote: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._upload, local, remote)

    async def download_many(self, remotes: Sequence[Path], into: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._download_many, remotes, into)

    async def upload_many(self, sources: Sequence[Path], into: Path) -> tuple[float, int]:
        return await anyio.to_thread.run_sync(self._upload_many, sources, into)

    async def download_repeatedly(
        self, remote: Path, local: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        return await anyio.to_thread.run_sync(
            self._download_repeatedly, remote, local, repeats, warmups
        )

    async def upload_repeatedly(
        self, local: Path, remote: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        return await anyio.to_thread.run_sync(
            self._upload_repeatedly, local, remote, repeats, warmups
        )


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

    async def upload_many(self, sources: Sequence[Path], into: Path) -> tuple[float, int]:
        async with self._connect() as conn, conn.start_sftp_client() as sftp:
            started = time.perf_counter()
            for source in sources:
                await sftp.put(str(source), str(into / source.name))
            elapsed = time.perf_counter() - started
        return elapsed, sum(_file_size(into / s.name) for s in sources)

    async def download_repeatedly(
        self, remote: Path, local: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        async with self._connect() as conn, conn.start_sftp_client() as sftp:
            for _ in range(warmups):
                await sftp.get(str(remote), str(local))
            walls = []
            for _ in range(repeats):
                started = time.perf_counter()
                await sftp.get(str(remote), str(local))
                walls.append(time.perf_counter() - started)
        return walls

    async def upload_repeatedly(
        self, local: Path, remote: Path, *, repeats: int, warmups: int
    ) -> list[float]:
        async with self._connect() as conn, conn.start_sftp_client() as sftp:
            for _ in range(warmups):
                await sftp.put(str(local), str(remote))
            walls = []
            for _ in range(repeats):
                started = time.perf_counter()
                await sftp.put(str(local), str(remote))
                walls.append(time.perf_counter() - started)
        return walls


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

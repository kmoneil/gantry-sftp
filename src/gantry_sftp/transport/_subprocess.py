"""Transports backed by a child process.

Two of them, sharing everything but the argv:

* :func:`open_ssh_transport` spawns ``ssh -s sftp`` and is the whole thesis -- OpenSSH does
  the cryptography, key exchange, ``ssh_config`` handling and host-key checking, and hands
  back a plaintext framed SFTP stream. No cryptography happens in this package.
* :func:`open_local_server_transport` spawns ``sftp-server`` directly, with no ``ssh``, no
  keys and no network. This is what ``sftp(1) -D`` does. It exists because a fake only ever
  confirms what its author already believed, and this gives us the *real* OpenSSH server
  implementation in unit-test time.

Both capture stderr on a background task and attach it verbatim to any failure. That is not
a nicety. ``Error reading SSH protocol banner`` is what paramiko reports when OpenSSH said
``Permission denied (publickey)`` or ``Host key verification failed``; the diagnosis existed
and was discarded. Here it is the first thing in the exception.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import override

import anyio
from anyio.abc import Process

from gantry_sftp.exceptions import ConnectError, flatten_exception_group
from gantry_sftp.transport._argv import DEFAULT_SUBSYSTEM, build_ssh_argv
from gantry_sftp.transport._base import DEFAULT_RECEIVE_SIZE
from gantry_sftp.transport._diagnosis import classify_failure

__all__ = [
    "SFTP_SERVER_CANDIDATES",
    "StderrBuffer",
    "SubprocessTransport",
    "find_sftp_server",
    "open_local_server_transport",
    "open_ssh_transport",
]

_TERMINATE_GRACE_SECONDS = 5.0

# Named once because every exit from a closed transport must read identically: the message
# is asserted verbatim by the tests, and three hand-written copies are three chances for one
# of them to drift into a message no `except` clause and no test is looking for.
_CLOSED_MESSAGE = "transport is closed"

_STDERR_HEAD_BYTES = 8 * 1024
_STDERR_TAIL_BYTES = 56 * 1024


class StderrBuffer:
    """Accumulates a child's stderr under a hard cap, keeping the head and the tail.

    An unbounded buffer here is a memory leak with a trigger someone will eventually pull:
    ``ssh -vvv`` on a long-lived connection emits debug output continuously, and a transfer
    that runs for hours would grow this forever. Truncating is not optional.

    *Which* bytes to keep is the interesting part, and both ends matter. OpenSSH puts the
    decisive line last -- ``Permission denied``, ``Host key verification failed`` -- so a
    head-only buffer discards the answer. But the banner and the early key-exchange lines
    are at the front, and a tail-only buffer discards the context. So both ends are kept and
    the middle is dropped, with a marker saying how much went, because silently truncated
    diagnostics are how people conclude the tool is lying to them.
    """

    __slots__ = ("_dropped", "_head", "_head_limit", "_tail", "_tail_limit")

    def __init__(
        self,
        head_limit: int = _STDERR_HEAD_BYTES,
        tail_limit: int = _STDERR_TAIL_BYTES,
    ) -> None:
        self._head = bytearray()
        self._tail = bytearray()
        self._dropped = 0
        self._head_limit = head_limit
        self._tail_limit = tail_limit

    def extend(self, chunk: bytes) -> None:
        """Add received stderr bytes, discarding from the middle if over the cap."""
        if len(self._head) < self._head_limit:
            room = self._head_limit - len(self._head)
            self._head += chunk[:room]
            chunk = chunk[room:]
        if not chunk:
            return

        self._tail += chunk
        excess = len(self._tail) - self._tail_limit
        if excess > 0:
            del self._tail[:excess]
            self._dropped += excess

    @property
    def dropped(self) -> int:
        """Bytes discarded from the middle."""
        return self._dropped

    def text(self) -> str:
        """The captured stderr, decoded leniently, with any gap marked.

        ``errors="replace"`` because this is a diagnostic: a server emitting one stray
        non-UTF-8 byte in its banner must not turn an authentication failure into a
        ``UnicodeDecodeError`` about the message that was explaining it.
        """
        head = bytes(self._head).decode("utf-8", errors="replace")
        if not self._dropped:
            return head + bytes(self._tail).decode("utf-8", errors="replace")
        tail = bytes(self._tail).decode("utf-8", errors="replace")
        return f"{head}\n... [{self._dropped} bytes of stderr omitted] ...\n{tail}"


SFTP_SERVER_CANDIDATES = (
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
)
"""Where distributions put ``sftp-server``. It ships in ``openssh-server``, not the client."""


def find_sftp_server() -> str | None:
    """Locate the OpenSSH ``sftp-server`` binary, or return ``None`` if it is not installed."""
    for candidate in SFTP_SERVER_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


class SubprocessTransport:
    """A byte stream over a child process's stdin and stdout.

    Built by :func:`open_ssh_transport` or :func:`open_local_server_transport` rather than
    directly: the stderr drain is a background task, and a task needs a scope to live in.
    """

    __slots__ = ("_argv", "_closed", "_process", "_stderr")

    def __init__(self, process: Process, argv: Sequence[str], stderr: StderrBuffer) -> None:
        self._process = process
        self._argv = tuple(argv)
        self._stderr = stderr
        self._closed = False

    @property
    def argv(self) -> tuple[str, ...]:
        """The exact command that was spawned. No shell was involved."""
        return self._argv

    @property
    def stderr_text(self) -> str:
        """Whatever the child has written to stderr so far.

        Bounded -- see :class:`StderrBuffer` for what is kept when a chatty child overflows
        the cap, and why both ends are kept rather than one.
        """
        return self._stderr.text()

    @property
    def returncode(self) -> int | None:
        """Child exit status, or ``None`` while it is still running."""
        return self._process.returncode

    @override
    def __repr__(self) -> str:
        """Identify the child without dumping its whole command line."""
        state = "closed" if self._closed else "open"
        return f"<SubprocessTransport {self._argv[0]!r} pid={self._process.pid} {state}>"

    def _connection_lost(self, what: str) -> ConnectError:
        """Build the error for a dead connection, typed by what ``ssh`` said on the way out.

        Every failure that reaches a caller comes through here, so classifying in one place is
        what makes ``except AuthenticationError`` mean something. The base class is still the
        answer whenever the stderr does not establish a more specific one -- see
        :mod:`gantry_sftp.transport._diagnosis`.
        """
        stderr = self.stderr_text
        return classify_failure(stderr)(
            what,
            stderr=stderr,
            argv=self._argv,
            returncode=self._process.returncode,
        )

    async def send(self, data: bytes | memoryview) -> None:
        """Write ``data`` to the child's stdin, in full."""
        if self._closed:
            raise self._connection_lost(_CLOSED_MESSAGE)
        stdin = self._process.stdin
        if stdin is None:  # pragma: no cover -- always piped by the openers here
            raise self._connection_lost("transport has no stdin")
        try:
            await stdin.send(bytes(data))
        except (anyio.BrokenResourceError, anyio.ClosedResourceError) as exc:
            raise self._connection_lost("ssh exited while we were writing to it") from exc

    async def receive(self, max_bytes: int = DEFAULT_RECEIVE_SIZE) -> bytes:
        """Read up to ``max_bytes`` from the child's stdout.

        Raises:
            ConnectError: On end of stream, carrying the child's stderr and exit status.
                This is the good path for diagnosing a failed connection: ``ssh`` writes
                its reason to stderr and then closes stdout, so the two arrive together.
        """
        if self._closed:
            raise self._connection_lost(_CLOSED_MESSAGE)
        stdout = self._process.stdout
        if stdout is None:  # pragma: no cover -- always piped by the openers here
            raise self._connection_lost("transport has no stdout")
        try:
            return await stdout.receive(max_bytes)
        except anyio.EndOfStream as exc:
            # Wait briefly for the child so the exit status and the last of stderr are in
            # the exception rather than arriving after it.
            with anyio.CancelScope(shield=True), anyio.move_on_after(_TERMINATE_GRACE_SECONDS):
                await self._process.wait()
            raise self._connection_lost("connection closed by the remote end") from exc
        except anyio.ClosedResourceError as exc:
            raise self._connection_lost(_CLOSED_MESSAGE) from exc

    async def aclose(self) -> None:
        """Close stdin and make sure the child is gone.

        Shielded from cancellation throughout. A cancelled transfer must still reap its
        child -- "cancellation obviously works" is a claim about a subprocess, a pipe and a
        task group, and it is three places for a process to be left behind.
        """
        if self._closed:
            return
        self._closed = True
        with anyio.CancelScope(shield=True):
            await self._close_stdin()
            await self._release_pipes()
            await self._reap()

    async def _close_stdin(self) -> None:
        """Closing stdin is how a well-behaved sftp server is told to exit."""
        if self._process.stdin is None:  # pragma: no cover
            return
        with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
            await self._process.stdin.aclose()

    async def _release_pipes(self) -> None:
        """Hand the child's pipes back, which reaping alone does not do.

        **Not housekeeping: this is a descriptor leak.** Waiting for the child, or killing
        it, does nothing about the pipe objects on our side -- and closing our own stream
        wrappers is not enough either, because the *underlying* asyncio pipe transport stays
        open behind them. It surfaces as ``ResourceWarning: unclosed transport`` from a
        ``__del__``, at whatever unrelated moment the collector happens to run, which is why
        it went unnoticed: one connection per process leaks one descriptor and nobody
        notices, and until :func:`~gantry_sftp.session.with_reconnect` existed nothing in
        this library opened a second connection to the same server.

        ``Process.aclose()`` is anyio's own answer and closes both layers. It runs *before*
        :meth:`_reap`, and the order is the difference between a fast teardown and a
        five-second one. Closing stdin only tells a server that is *reading* to stop; one
        blocked writing into a stdout pipe nobody drains never gets that far, so it misses
        the EOF, sits out the whole grace period and is SIGTERMed. Closing the read end
        gives it ``EPIPE`` and it exits on its own. anyio's own comment on that code says
        the same thing, which is a good sign the ordering is not a local trick.

        It waits for the child, so it is bounded here and :meth:`_reap` still owns the
        escalation. On timeout anyio closes the transport, which kills and reaps -- so the
        polite SIGTERM stage is skipped only in the case where politeness already failed.

        Found by the retry lane, running two connections back to back for the first time.
        """
        with (
            anyio.move_on_after(_TERMINATE_GRACE_SECONDS),
            suppress(anyio.BrokenResourceError, anyio.ClosedResourceError),
        ):
            await self._process.aclose()

    async def _reap(self) -> None:
        """Wait, then escalate. Politeness first, but never indefinitely."""
        with anyio.move_on_after(_TERMINATE_GRACE_SECONDS):
            await self._process.wait()
            return

        self._process.terminate()
        with anyio.move_on_after(_TERMINATE_GRACE_SECONDS):
            await self._process.wait()
            return

        self._process.kill()
        await self._process.wait()


async def _drain_stderr(process: Process, into: StderrBuffer) -> None:
    """Read the child's stderr until it ends, accumulating it for diagnostics.

    A background task rather than a read-on-failure, because a pipe nobody drains fills up
    and blocks the writer. ``ssh -vvv`` produces far more than a pipe buffer holds, and a
    client that deadlocks when you turn on debugging is a client that cannot be debugged.
    """
    if process.stderr is None:  # pragma: no cover
        return
    try:
        async for chunk in process.stderr:
            into.extend(chunk)
    except (anyio.EndOfStream, anyio.ClosedResourceError):  # pragma: no cover
        pass


@asynccontextmanager
async def _open_process_transport(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> AsyncGenerator[SubprocessTransport]:
    """Spawn ``argv``, wire up the stderr drain, and guarantee the child is reaped."""
    stderr = StderrBuffer()
    try:
        process = await anyio.open_process(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=dict(env) if env is not None else None,
        )
    except OSError as exc:
        raise ConnectError(
            f"could not run {argv[0]!r}: {exc.strerror or exc}",
            argv=tuple(argv),
        ) from exc

    transport = SubprocessTransport(process, argv, stderr)
    try:
        try:
            async with anyio.create_task_group() as task_group:
                # The handle is deliberately discarded: the drain runs until the pipe ends
                # and is torn down with the task group, so there is nothing to await.
                _ = task_group.start_soon(_drain_stderr, process, stderr)
                try:
                    yield transport
                finally:
                    await transport.aclose()
                    task_group.cancel_scope.cancel()
        except BaseExceptionGroup as group:
            # The stderr drain runs in a task group, so *anything* the caller's body raises
            # comes back out of it wrapped -- anyio wraps even a single exception. Without
            # this, an `except ConnectError` placed outside `async with open_ssh_transport()`
            # never matches, which is the natural spelling and the one the README documents.
            # Re-raising the flattened exception is safe with @asynccontextmanager: it is the
            # same object contextlib threw in, so the `async with` propagates it normally.
            raise flatten_exception_group(group) from None
    finally:
        # The task group cannot outlive the process object, and a failure anywhere above
        # must not leave a child running.
        with anyio.CancelScope(shield=True):
            await transport.aclose()


@asynccontextmanager
async def open_ssh_transport(
    host: str,
    *,
    user: str | None = None,
    port: int | None = None,
    config_file: str | os.PathLike[str] | None = None,
    identity_file: str | os.PathLike[str] | None = None,
    options: Mapping[str, str] | None = None,
    subsystem: str = DEFAULT_SUBSYSTEM,
    ssh_executable: str | None = None,
    env: Mapping[str, str] | None = None,
) -> AsyncGenerator[SubprocessTransport]:
    """Open an SFTP byte stream by spawning ``ssh -s sftp``.

    Arguments are validated and assembled by
    :func:`~gantry_sftp.transport.build_ssh_argv`; see it for what is rejected and why.

    Args:
        host: Hostname or ``ssh_config`` alias.
        user: Remote username.
        port: Remote port.
        config_file: ``-F``. Pass ``os.devnull`` to ignore the user's ``ssh_config``.
        identity_file: ``-i``.
        options: ``-o`` options, overriding the defaults by name.
        subsystem: Subsystem name, or a path for a server with no subsystem configured.
        ssh_executable: Which ``ssh`` to run.
        env: Environment for the child. ``None`` inherits.

    Yields:
        A connected transport. Note that ``ssh`` is spawned immediately but authentication
        happens asynchronously, so a failure usually surfaces on the first
        :meth:`~SubprocessTransport.receive` -- with OpenSSH's stderr attached, which is
        where the real explanation always was.

    Raises:
        ValueError: If any argument could be misread as an ``ssh`` option.
        ConnectError: If ``ssh`` cannot be executed at all.
    """
    argv = build_ssh_argv(
        host,
        user=user,
        port=port,
        config_file=config_file,
        identity_file=identity_file,
        options=options,
        subsystem=subsystem,
        ssh_executable=ssh_executable,
    )
    async with _open_process_transport(argv, env=env) as transport:
        yield transport


@asynccontextmanager
async def open_local_server_transport(
    *,
    server_path: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> AsyncGenerator[SubprocessTransport]:
    """Open an SFTP byte stream by spawning ``sftp-server`` directly. No ``ssh``, no network.

    The equivalent of ``sftp(1) -D``. Everything runs as the current user with no
    authentication, so this is for testing and for local use, never for reaching another
    machine.

    Args:
        server_path: Path to ``sftp-server``. Located automatically when omitted.
        cwd: Working directory for the child, which is what relative paths resolve against.
        env: Environment for the child. ``None`` inherits.

    Yields:
        A connected transport.

    Raises:
        ConnectError: If ``sftp-server`` cannot be found or executed. It ships in
            ``openssh-server``; having only ``openssh-client`` is the usual reason.
    """
    resolved = os.fspath(server_path) if server_path is not None else find_sftp_server()
    if resolved is None:
        raise ConnectError(
            "sftp-server not found; it ships in the openssh-server package, not "
            f"openssh-client (looked in {', '.join(SFTP_SERVER_CANDIDATES)})"
        )
    async with _open_process_transport([resolved], cwd=cwd, env=env) as transport:
        yield transport

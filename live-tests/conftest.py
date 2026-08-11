"""Fixtures over the real OpenSSH server and the shaped link.

The server itself lives in :mod:`sshd` and the shaping in :mod:`netem`, both of which are
plain modules that report unavailability rather than skipping. This file is where those
reasons become ``pytest.skip`` calls, and it is deliberately thin: ``benchmarks/`` needs the
same server and the same scrubbed environment, and a conftest cannot be imported from a
sibling directory. Two copies of "how this suite connects" is how the scrubbed ``ssh``
environment ends up applied in one of them and not the other.

Nothing here is allowed to *fail* because a dependency is missing. It skips, with a reason.
"""

from __future__ import annotations

import socket
import tempfile
from collections.abc import AsyncGenerator, Callable, Iterator
from contextlib import ExitStack, asynccontextmanager
from pathlib import Path

import anyio
import pytest
from netem import ShapedLink, release_loopback, shape, unavailable_reason
from sshd import (
    ServerUnavailableError,
    SSHServer,
    connect_kwargs,
    running_sshd,
    scrubbed_ssh_env,
)

from gantry_sftp.codec import Codec, CodecState, StatusCode
from gantry_sftp.exceptions import ServerError, _flatten_exception_group
from gantry_sftp.session import Dispatcher
from gantry_sftp.transport import Transport, open_ssh_transport

__all__ = [
    "SSHServer",
    "connect",
    "negotiate",
    "running_dispatcher",
    "scrubbed_ssh_env",
    "short_socket_dir",
    "still_open",
]


@pytest.fixture
def short_socket_dir() -> Iterator[Path]:
    """A directory whose paths fit in ``sun_path``, which pytest's ``tmp_path`` does not.

    A ``ControlPath`` and an ``ssh-agent`` socket are both Unix domain sockets, so the *path* is
    bounded -- 108 bytes on Linux and **104 on macOS and the BSDs** -- and the bound is on the
    string, not on the file. pytest's ``tmp_path`` on macOS is
    ``/private/var/folders/<20 chars>/T/pytest-of-<user>/pytest-<n>/<test-name-cut-to-30>/``,
    which is past 104 before a filename is appended.

    **Both ways it then fails read as this library refusing to multiplex.** ``ssh-agent`` says
    ``unix_listener: path "..." too long for Unix domain socket`` and exits 1, so the fixture
    raising it errors the test at setup; ``ssh`` says ``ControlPath too long ('...' >= 104
    bytes)`` and exits 255, which reaches the caller as a ``ConnectError``. That is fourteen
    rows across two files on the first run of this lane off Linux -- the whole ControlMaster
    guarantee and the whole agent-defence truth table -- and ``test_control_master.py``'s own
    docstring predicted the shape while sizing the fix for Linux's bound alone.

    ``/tmp`` rather than the platform temporary directory, because the platform temporary
    directory is the problem. The path is then **checked by binding a socket to it** rather than
    compared against a constant: the constant differs per platform, is not exposed by Python,
    and a probe of the exact path is the question these tests actually have. It follows the same
    rule as every other capability this suite depends on -- netem, Docker, ``sftp-server``.

    Yields:
        An empty directory, removed when the test ends.
    """
    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        directory = Path(short)
        probe = directory / "probe.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(probe))
        except OSError as refusal:
            pytest.fail(
                f"no unix socket can be created under {short!r} "
                f"({len(str(probe).encode())} bytes): {refusal}"
            )
        finally:
            listener.close()
            probe.unlink(missing_ok=True)
        yield directory


async def still_open(sftp, handle: bytes) -> bool:
    """Whether the server still holds `handle`, asked in the only way the protocol allows.

    `/proc/<pid>/fd` is the obvious way to read a server's handle table and it is unavailable
    here -- this sandbox refuses the fd directory of a process it is the parent of. Asking in
    the protocol works wherever the protocol does: a CLOSE of a handle the server does not
    hold is refused, and one it does hold is accepted.

    Destructive by construction -- a handle that *was* open is closed by the asking -- which is
    right for "was one leaked": the answer is taken and the leak cleaned up in one step. Both
    directions of it are calibrated in the tests that lean on it, because "the probe found
    nothing" and "there is nothing to find" are otherwise the same green test.
    """
    refused: ServerError | None = None
    try:
        await sftp.close(handle)
    except ServerError as refusal:
        refused = refusal
    if refused is None:
        return True
    # Measured, not assumed: OpenSSH 10.0p2 answers NO_SUCH_FILE for a handle it does not
    # hold -- not the catch-all FAILURE that v3's status list invites you to expect. Both are
    # accepted because another server may spell the refusal the other way; what is asserted is
    # that a refusal came back rather than something misread as one.
    assert refused.code in {int(StatusCode.NO_SUCH_FILE), int(StatusCode.FAILURE)}, refused
    return False


def connect(server: SSHServer, **overrides):
    """Open a transport to the test server, with any argument replaceable.

    Defaults are merged rather than passed alongside the overrides, so a test can say
    ``port=...`` or ``identity_file=...`` without colliding with the value here.
    """
    return open_ssh_transport("127.0.0.1", **connect_kwargs(server, **overrides))


async def negotiate(transport: Transport, codec: Codec) -> None:
    """Drive the handshake to READY."""
    await transport.send(codec.initiate())
    while codec.state is not CodecState.READY:
        codec.receive(await transport.receive())


@asynccontextmanager
async def running_dispatcher(transport: Transport, codec: Codec) -> AsyncGenerator[Dispatcher]:
    """A dispatcher with its reader task running, stopped when the block ends.

    What `open_session` does, minus the handshake, for the lanes that drive `download_handle`
    directly because they need knobs the session deliberately does not expose. The flatten
    mirrors production for the reason `_flatten_exception_group` exists: a task group wraps
    even a single failure, and a lane whose assertions stopped matching would report a link
    problem as a nameless `ExceptionGroup`.

    `close()` is what stops the reader, and cancelling `reader.cancel_scope` would not: the
    reader is shielded (D-34).
    """
    dispatcher = Dispatcher(transport, codec)
    try:
        async with anyio.create_task_group() as reader:
            # `_ =` for the same reason every `start_soon` in `src/` carries one: anyio
            # returns a task handle and `unused-awaitable` flags discarding it.
            _ = reader.start_soon(dispatcher.run)
            _ = reader.start_soon(dispatcher.reap_orphans)
            try:
                yield dispatcher
            finally:
                dispatcher.close()
    except BaseExceptionGroup as group:
        raise _flatten_exception_group(group) from None


@pytest.fixture(params=["asyncio", "trio"])
def anyio_backend(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture(scope="session")
def ssh_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SSHServer]:
    """A running sshd serving the sftp subsystem, or a skip saying what is missing."""
    root = tmp_path_factory.mktemp("sshd")
    try:
        with running_sshd(root) as server:
            yield server
    except ServerUnavailableError as exc:
        pytest.skip(str(exc))


ShapeLink = Callable[..., ShapedLink]
"""Signature of the :func:`shape_link` fixture: ``(*, rtt_ms, loss_percent=0.0)``."""


@pytest.fixture(scope="session", autouse=True)
def _loopback_is_left_unshaped() -> Iterator[None]:
    """Leave the interface the way we found it, even if a test died holding a profile.

    :func:`netem.shape` removes its own qdisc in a ``finally``, which covers every ordinary
    exit including a failing assertion. This covers the ones that are not ordinary -- a
    session-scoped fixture erroring during teardown, a ``KeyboardInterrupt`` at the wrong
    moment -- because the cost of getting it wrong is not a failed test. It is a container
    whose loopback is still delayed by 200 ms after the run, which every later test silently
    measures and none of them mention.
    """
    yield
    release_loopback()


@pytest.fixture
def shape_link(ssh_server: SSHServer) -> Iterator[ShapeLink]:
    """Shape loopback for one test, or skip saying exactly what would fix it.

    Depends on ``ssh_server`` so that ``sshd`` is already listening and its host key already
    scanned before the link degrades. Starting a server through a 200 ms link would spend the
    startup budget on key exchange and report it as the server failing to start, which is a
    diagnosis pointing at the wrong component.

    Yields:
        A callable taking ``rtt_ms`` and optional ``loss_percent``, returning the measured
        :class:`~netem.ShapedLink`. Profiles are unshaped when the test ends, in reverse
        order, so a test may take more than one.
    """
    reason = unavailable_reason()
    if reason is not None:
        pytest.skip(reason)

    with ExitStack() as stack:

        def _shape(
            *, rtt_ms: float, loss_percent: float = 0.0, rate_mbit: float | None = None
        ) -> ShapedLink:
            return stack.enter_context(
                shape(rtt_ms=rtt_ms, loss_percent=loss_percent, rate_mbit=rate_mbit)
            )

        yield _shape

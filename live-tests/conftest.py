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

from collections.abc import AsyncGenerator, Callable, Iterator
from contextlib import ExitStack, asynccontextmanager

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

from gantry_sftp.codec import Codec, CodecState
from gantry_sftp.exceptions import flatten_exception_group
from gantry_sftp.session import Dispatcher
from gantry_sftp.transport import Transport, open_ssh_transport

__all__ = [
    "SSHServer",
    "connect",
    "negotiate",
    "running_dispatcher",
    "scrubbed_ssh_env",
]


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
    mirrors production for the reason `flatten_exception_group` exists: a task group wraps
    even a single failure, and a lane whose assertions stopped matching would report a link
    problem as a nameless `ExceptionGroup`.
    """
    dispatcher = Dispatcher(transport, codec)
    try:
        async with anyio.create_task_group() as reader:
            reader.start_soon(dispatcher.run)
            try:
                yield dispatcher
            finally:
                dispatcher.close()
                reader.cancel_scope.cancel()
    except BaseExceptionGroup as group:
        raise flatten_exception_group(group) from None


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

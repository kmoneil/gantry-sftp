"""Shared fixtures.

Anything that reaches outside the process is located explicitly and skips with a reason
when absent, rather than failing. A test that only passes on a machine with the right
packages installed is a test that reports the machine, not the code.
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import Codec
from gantry_sftp.exceptions import flatten_exception_group
from gantry_sftp.session import Dispatcher
from gantry_sftp.transport import Transport


@asynccontextmanager
async def running_dispatcher(transport: Transport, codec: Codec) -> AsyncGenerator[Dispatcher]:
    """A dispatcher with its reader task running, stopped when the block ends.

    What `open_session` does, minus the handshake, for the tests that drive `download_handle`
    and `upload_handle` directly. The flatten is not decoration: an anyio task group wraps
    even a single failure in an `ExceptionGroup`, so without it every
    `pytest.raises(TransferError)` in this suite would stop matching -- and the ones asserting
    on a message would fail with a group instead of proving anything.
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


async def negotiate(transport: Transport) -> Codec:
    """Drive the handshake over an in-process fake and hand back the ready codec."""
    codec = Codec()
    await transport.send(codec.initiate())
    while codec.state.name != "READY":
        codec.receive(await transport.receive())
    return codec


@pytest.fixture(params=["asyncio", "trio"])
def anyio_backend(request: pytest.FixtureRequest) -> str:
    """Run every async test on both anyio backends.

    The entire reason this library uses anyio rather than asyncio is that it costs nothing
    and buys trio support. Running the async suite on trio too is what turns that from a
    claim into a fact -- an anyio-shaped codebase that has only ever run on asyncio is one
    accidental ``asyncio.Queue`` away from not supporting trio at all.
    """
    return str(request.param)


# sftp-server ships in openssh-server, not openssh-client, and distributions disagree about
# where it lives. These are the three locations in the wild.
SFTP_SERVER_CANDIDATES = (
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
)


def find_sftp_server() -> Path | None:
    """Locate the OpenSSH sftp-server binary, or return ``None``."""
    for candidate in SFTP_SERVER_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return path
    found = shutil.which("sftp-server")
    return Path(found) if found else None


@pytest.fixture(scope="session")
def sftp_server_binary() -> Path:
    """Path to a real OpenSSH sftp-server, skipping the test if none is installed."""
    path = find_sftp_server()
    if path is None:
        pytest.skip(
            "sftp-server not found; install openssh-server to run the real-server lane "
            f"(looked in {', '.join(SFTP_SERVER_CANDIDATES)} and $PATH)"
        )
    return path


# The environment-scrubbing helper that used to live here now lives in live-tests/sshd.py,
# where something actually spawns ssh against a server that can authenticate it, and where
# live-tests/test_ssh_environment.py asserts what it does. Nothing in tests/ reaches an
# ssh_config: the ssh calls here either pass `config_file=os.devnull`, run a fake ssh that
# is a script and reads no config at all, or fail during argv validation before a process
# exists. So keeping a fixture nobody used was decoration that looked like a safeguard.

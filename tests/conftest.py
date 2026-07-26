"""Shared fixtures.

Anything that reaches outside the process is located explicitly and skips with a reason
when absent, rather than failing. A test that only passes on a machine with the right
packages installed is a test that reports the machine, not the code.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


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


# The environment-scrubbing helper that used to live here moved to live-tests/conftest.py,
# where something actually spawns ssh against a server that can authenticate it. Nothing in
# tests/ reaches an ssh_config -- every ssh here either passes `config_file=os.devnull` or
# fails before a connection is attempted -- so keeping a fixture nobody used was decoration
# that looked like a safeguard.

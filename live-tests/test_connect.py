"""`connect()` over a real `ssh` connection to a real `sshd`.

The unit tests for this function replace `open_ssh_transport`, because what they are checking
is the *composition* and a real connection there would need a host. That makes them the shape
DESIGN 4.3 warns about: a fake confirms what its author already believed. This file is the
other half -- the one call, spawning a real `ssh`, negotiating with a real `sftp-server`, and
moving a real file.

It is also where the scoped signature earns its keep or does not: every argument `connect()`
forwards has to arrive at `ssh` intact, and the suite's own connection arguments are the ones
that prove it, since a test server on a random port with an explicit identity file exercises
`port`, `identity_file`, `options`, `config_file` and `env` all at once.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sshd import SSHServer, connect_kwargs

from gantry_sftp import ConnectError, SessionOptions, connect

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """One backend: the subject is `ssh` and the signature, not the event loop."""
    return "asyncio"


async def test_connect_moves_a_file_over_a_real_connection(ssh_server: SSHServer, tmp_path: Path):
    """The whole point of the function, end to end and in one call.

    Deliberately the *only* import a program needs: `from gantry_sftp import connect`. Before
    0.10 this was two imports from two subpackages and two nested context managers, and DESIGN
    8 documented a `connect()` that did not exist.
    """
    payload = bytes(range(256)) * 40
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    remote = tmp_path / "uploaded.bin"
    back = tmp_path / "back.bin"

    async with connect("127.0.0.1", **connect_kwargs(ssh_server)) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, str(remote).encode())
        assert result.transferred == len(payload)
        assert (await sftp.get(str(remote).encode(), back)).transferred == len(payload)

    assert remote.read_bytes() == payload
    assert back.read_bytes() == payload


async def test_the_session_options_reach_the_session(ssh_server: SSHServer):
    """Forwarding, proven against a real handshake rather than a monkeypatched one.

    `depth` is the one of the three with a visible effect that costs no waiting -- a timeout
    would have to expire to be observed. It is readable on the session as of 0.10 precisely so
    this question has an answer that is not a substring of `repr()`.
    """
    async with connect(
        "127.0.0.1",
        **connect_kwargs(ssh_server),  # type: ignore[arg-type]
        session=SessionOptions(depth=8, request_timeout=11.0),
    ) as sftp:
        assert sftp.depth == 8
        assert sftp.server_version == 3


async def test_the_connection_and_the_session_both_close(ssh_server: SSHServer, tmp_path: Path):
    """Leaving the block must reap the `ssh` child, not just end the session.

    The two-call spelling makes the two lifetimes visible and therefore hard to get wrong; a
    fused call hides one inside the other, which is exactly where a leak would live. The
    session ending is not evidence of the connection ending -- that is the failure mode -- so
    what is asserted is the child's exit status rather than anything the session reports.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")

    async with connect("127.0.0.1", **connect_kwargs(ssh_server)) as sftp:  # type: ignore[arg-type]
        await sftp.put(source, str(tmp_path / "uploaded.bin").encode())
        # Reached through the dispatcher because `connect()` deliberately does not hand the
        # transport back -- which is the whole reason this leak would be invisible from
        # outside, and therefore the reason the test reaches in.
        transport = sftp._dispatcher._transport  # noqa: SLF001

    assert transport.returncode is not None, "the ssh child was not reaped when the block exited"


async def test_a_refused_connection_raises_through_the_fused_call(tmp_path: Path):
    """The error has to survive the extra layer, and it has to arrive flat.

    `connect()` nests two async context managers, and the session's own reader lives in a task
    group -- so the risk this pins is an `ExceptionGroup` reaching the caller and breaking
    `except ConnectError`. The library flattens its own groups for exactly this reason; a new
    entry point that wrapped them again would undo it silently.
    """
    with pytest.raises(ConnectError) as refusal:
        async with connect(
            "nonexistent.invalid",
            config_file=str(tmp_path / "empty_config"),
        ):
            pass  # pragma: no cover -- the connection never opens

    assert not isinstance(refusal.value, BaseExceptionGroup)
    assert refusal.value.stderr

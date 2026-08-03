"""The destination allowlist against a real `sshd`, over a real `ssh`.

**D-121.** The unit tests in `tests/test_destination.py` drive `ssh -G` for real, so the probe
itself is not faked there -- but they never complete a connection, and the thing this file
exists to prove is the pairing: a policy that admits the destination lets a real transfer
happen, and one that does not stops it *before* `ssh` is spawned at all.

That second half is the one a unit test cannot honestly make. "Nothing was spawned" is a claim
about a subprocess, and the only way to check it against a server that would otherwise answer
is to point the client at a server that is actually running and then observe that it saw
nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sshd import SSHServer, connect_kwargs

from gantry_sftp import DestinationNotAllowedError, allowed_hosts, connect
from gantry_sftp.transport import ALLOWED_HOSTS_ENV

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """One backend: the subject is the policy and `ssh`, not the event loop."""
    return "asyncio"


async def test_an_allowed_destination_still_transfers(ssh_server: SSHServer, tmp_path: Path):
    """The policy admits the host, and everything below it behaves exactly as before.

    A control that refuses correctly and also breaks the allowed path is not a control anyone
    will leave switched on, so the passing case is asserted as carefully as the failing one --
    down to the bytes arriving.
    """
    source = tmp_path / "payload.bin"
    _ = source.write_bytes(b"gantry" * 1024)
    remote = f"{ssh_server.root}/payload.bin"

    with allowed_hosts(["127.0.0.1", "localhost"]):
        async with connect("127.0.0.1", **connect_kwargs(ssh_server)) as sftp:
            _ = await sftp.put(source, remote)
            back = tmp_path / "returned.bin"
            _ = await sftp.get(remote, back)

    assert back.read_bytes() == source.read_bytes()


async def test_a_disallowed_destination_never_reaches_the_server(
    ssh_server: SSHServer, tmp_path: Path
):
    """Refused before the spawn, against a server that was running and ready to answer.

    The assertion that matters is `argv == ()`: the refusal carries no command line because
    there was no command. A check that ran after the connection would still raise, and would
    still look like this in a log.
    """
    with (
        allowed_hosts(["*.corp.example.com"]),
        pytest.raises(DestinationNotAllowedError) as exc,
    ):
        async with connect("127.0.0.1", **connect_kwargs(ssh_server)):
            pass  # pragma: no cover -- the refusal is the feature

    assert exc.value.host == "127.0.0.1"
    assert exc.value.effective_host == "127.0.0.1"
    assert exc.value.layers == (("*.corp.example.com",),)
    # No ssh was spawned for the connection, so there is no argv and no stderr to carry.
    assert exc.value.argv == ()
    assert exc.value.stderr == ""


async def test_the_environment_variable_governs_a_real_connection(
    ssh_server: SSHServer, monkeypatch: pytest.MonkeyPatch
):
    """The deployment-level spelling, exercised the way a deployment would set it.

    `monkeypatch.setenv` rather than a scope, because the environment layer is read from
    `os.environ` at connection time and this is the only test that proves that wiring -- every
    other one injects `environ=` and would pass with the real variable never consulted.
    """
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "*.corp.example.com")
    with pytest.raises(DestinationNotAllowedError) as exc:
        async with connect("127.0.0.1", **connect_kwargs(ssh_server)):
            pass  # pragma: no cover -- the refusal is the feature
    assert exc.value.layers == (("*.corp.example.com",),)


async def test_an_unset_policy_leaves_the_connection_untouched(
    ssh_server: SSHServer, monkeypatch: pytest.MonkeyPatch
):
    """The default path, which is every existing caller: no policy, no probe, no change.

    `delenv` is explicit rather than assumed. A developer with `GANTRY_SFTP_ALLOWED_HOSTS` set
    in their own shell would otherwise be running a different test from CI, which is exactly
    what the Definition of Done forbids of anything that steers a connection.
    """
    monkeypatch.delenv(ALLOWED_HOSTS_ENV, raising=False)
    assert ALLOWED_HOSTS_ENV not in __import__("os").environ

    async with connect("127.0.0.1", **connect_kwargs(ssh_server)) as sftp:
        assert await sftp.realpath(".") is not None

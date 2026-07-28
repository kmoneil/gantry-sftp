"""Password authentication, end to end, against a server that really asks for one.

D-78 was found by pointing the library at a third-party endpoint rather than by reading the
code against the design: nothing in either artifact was *wrong*, and the common deployment was
simply unreachable. `BatchMode=yes` ships as a default and suppresses the askpass helper
outright, so password authentication was not discouraged by it -- it was disabled by it, and
nothing said so.

**The server here is asyncssh rather than OpenSSH, and that is a measurement rather than a
preference.** See :func:`matrix.running_password_server`: an unprivileged `sshd` cannot read
`/etc/shadow`, so it can offer password authentication and never accept one. The client is
what these tests are about, and the client cannot tell the difference.

Every case below fails authentication on purpose except the first. That is safe on this lane
and would not be against OpenSSH: `PerSourcePenalties` punishes the *source address* after a
failed attempt and then breaks the next, unrelated connection from it -- a hazard this
repository has already been bitten by once. asyncssh has no equivalent.

The backend is pinned to asyncio. These are assertions about `ssh` and a server; running each
one twice would prove nothing about anyio.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from matrix import MatrixServer, password_server_unavailable_reason, running_password_server

from gantry_sftp.exceptions import AuthenticationError, ConnectError
from gantry_sftp.session import open_session
from gantry_sftp.transport import ASKPASS_ARMING_VARIABLES, open_ssh_transport

pytestmark = pytest.mark.anyio

PASSWORD = "s3cret-that-must-not-be-in-argv"
"""Distinctive on purpose: every redaction assertion here searches for this exact string."""


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def password_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[MatrixServer]:
    """A running server that accepts exactly one password, or a skip saying what is missing."""
    reason = password_server_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)
    root = tmp_path_factory.mktemp("password-server")
    with running_password_server(root, password=PASSWORD) as server:
        yield server


def connect(server: MatrixServer, **overrides: object) -> object:
    """Open a transport to the password server, with any argument replaceable."""
    kwargs = dict(server.connect)
    kwargs.update(overrides)
    host = kwargs.pop("host")
    assert isinstance(host, str)
    return open_ssh_transport(host, **kwargs)  # type: ignore[arg-type]


# --- the recipe works -----------------------------------------------------------------------


async def test_a_password_authenticates_and_the_session_is_usable(password_server):
    """The headline. Before this, the only way here was a hand-rolled askpass helper."""
    async with (
        connect(password_server, password=PASSWORD) as transport,
        open_session(transport) as sftp,
    ):
        cwd = await sftp.realpath(b".")
        assert cwd
        # Identified, not merely connected: the handshake completed and the profile was
        # matched, so the password bought a whole working session rather than a socket.
        assert sftp.profile.name == "asyncssh"
        assert await sftp.listdir(cwd) is not None


async def test_a_password_session_moves_a_file_both_ways(password_server, tmp_path: Path):
    """Authentication is not the feature; a working transfer over it is.

    The third-party endpoint that produced this card verified a 3.1 MB download by digest, so
    the lane asserts the same shape rather than stopping at a successful handshake.
    """
    payload = os.urandom(512 * 1024)
    source = tmp_path / "upload.bin"
    source.write_bytes(payload)
    remote = password_server.root / "uploaded.bin"
    destination = tmp_path / "downloaded.bin"

    async with (
        connect(password_server, password=PASSWORD) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put(source, str(remote).encode())
        await sftp.get(str(remote).encode(), destination)

    assert hashlib.sha256(destination.read_bytes()).hexdigest() == (
        hashlib.sha256(payload).hexdigest()
    )


async def test_the_password_reaches_the_server_without_reaching_argv(password_server):
    """The whole reason `password=` exists rather than a documented `sshpass` recipe.

    argv is world-readable through ``/proc/<pid>/cmdline``. This asserts the secret is absent
    from it while the connection is *live* and authenticated -- which is the window in which
    ``ps`` could have shown it to every user on the machine.
    """
    async with (
        connect(password_server, password=PASSWORD) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.realpath(b".")
        assert PASSWORD not in " ".join(transport.argv)
        assert PASSWORD not in repr(transport)
        assert PASSWORD not in transport.stderr_text


# --- the shipped default refuses, and now says why ------------------------------------------


async def test_the_shipped_defaults_cannot_authenticate_with_a_password(password_server):
    """The gap itself, as a red test that would have failed before the fix and after it.

    No `password=`, so `BatchMode=yes` stands. The connection fails even though the server
    offers password authentication and the secret is available -- which is exactly what a user
    hit before this card, with an error naming the server's methods and not our disabled one.
    """
    with pytest.raises(AuthenticationError) as exc:
        async with connect(password_server) as transport, open_session(transport):
            pytest.fail("authenticated with BatchMode=yes and no askpass helper")

    assert "Permission denied" in exc.value.stderr
    # The hint is the half that was missing. The stderr says which methods the *server*
    # offers; only we know which of ours was switched off.
    assert "BatchMode=yes suppresses the askpass helper outright" in exc.value.hint
    assert exc.value.hint in str(exc.value)


async def test_the_server_really_does_offer_the_method_we_could_not_use(password_server):
    """Calibrates the test above: a refusal proves nothing if nothing was on offer.

    OpenSSH names the server's methods in the refusal, so this is checkable rather than
    assumed -- and it is the same list the hint keys on.
    """
    with pytest.raises(AuthenticationError) as exc:
        async with connect(password_server) as transport, open_session(transport):
            pytest.fail("authenticated with BatchMode=yes and no askpass helper")

    offered = exc.value.stderr.partition("Permission denied (")[2].partition(")")[0]
    assert "password" in offered, exc.value.stderr


async def test_the_environment_this_lane_runs_in_could_not_answer_a_prompt(password_server):
    """Guards the guard. A stray `DISPLAY` would arm a helper and make the case above pass
    for a reason that has nothing to do with the default under test."""
    env = password_server.connect["env"]
    for name in ASKPASS_ARMING_VARIABLES:
        assert name not in env, f"{name} is set; the refusing case is not what it claims"
    assert "SSH_ASKPASS" not in env


# --- a wrong password is refused, and the diagnosis does not guess --------------------------


async def test_a_wrong_password_is_refused(password_server):
    with pytest.raises(AuthenticationError) as exc:
        async with (
            connect(password_server, password="not-the-password") as transport,
            open_session(transport),
        ):
            pytest.fail("authenticated with the wrong password")
    assert "Permission denied" in exc.value.stderr


async def test_a_wrong_password_gets_no_hint_because_we_did_answer_the_prompt(password_server):
    """The third state of the predicate. We supplied a secret and the server rejected it;
    why is between the user and the server, and a hint that guessed would be noise on the
    one failure where the message is already accurate."""
    with pytest.raises(AuthenticationError) as exc:
        async with (
            connect(password_server, password="not-the-password") as transport,
            open_session(transport),
        ):
            pytest.fail("authenticated with the wrong password")

    assert exc.value.hint == ""
    assert "hint: " not in str(exc.value)
    assert "not-the-password" not in str(exc.value)


async def test_a_wrong_password_is_offered_once_rather_than_three_times(password_server):
    """`NumberOfPasswordPrompts=1`, asserted where it can be seen.

    OpenSSH's default is three, and each retry re-runs the helper with the same wrong secret.
    Against a 9.8+ `sshd` that is three failed attempts for one connection attempt, which is
    what earns the source address a penalty that breaks the *next* test.
    """
    with pytest.raises(AuthenticationError) as exc:
        async with (
            connect(password_server, password="not-the-password") as transport,
            open_session(transport),
        ):
            pytest.fail("authenticated with the wrong password")

    assert "-o" in exc.value.argv
    assert "NumberOfPasswordPrompts=1" in exc.value.argv


# --- the contradiction is refused before anything is spawned -------------------------------


async def test_a_password_with_batchmode_yes_never_reaches_the_server(password_server):
    # It would fail on the wire anyway. Refusing here means the caller is told which of their
    # two contradictory instructions was the problem, rather than reading `Permission denied`.
    with pytest.raises(ValueError) as exc:
        async with connect(
            password_server, password=PASSWORD, options={"BatchMode": "yes"}
        ) as transport:
            pytest.fail(f"spawned {transport!r}")
    assert exc.value.args[0].startswith("password= needs BatchMode=no,")


async def test_the_refusal_is_a_value_error_rather_than_a_connect_error(password_server):
    # It is a programming mistake, not a connection failure, and `except ConnectError` must
    # not swallow it into the pile of things that are worth retrying.
    with pytest.raises(ValueError) as exc:
        async with connect(
            password_server, password=PASSWORD, options={"BatchMode": "yes"}
        ) as transport:
            pytest.fail(f"spawned {transport!r}")
    assert not isinstance(exc.value, ConnectError)

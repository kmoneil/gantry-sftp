"""A real OpenSSH server, on a real socket, for the tests that need one.

Everything here spawns ``sshd`` and connects to it over TCP. That is the boundary
``tests/`` cannot cross: a fake transport proves the codec agrees with our idea of a
server, and ``sftp-server`` on a pipe proves it agrees with the real server -- but neither
of them runs ``ssh``, does key exchange, authenticates, or fails the way a real connection
fails. This directory is where the thesis is actually tested.

Nothing here is allowed to *fail* because a dependency is missing. It skips, with a reason.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import pytest
from netem import ShapedLink, release_loopback, shape, unavailable_reason

from gantry_sftp.codec import Codec, CodecState
from gantry_sftp.transport import Transport, open_ssh_transport

SSHD_CANDIDATES = ("/usr/sbin/sshd", "/usr/local/sbin/sshd")
SFTP_SERVER_CANDIDATES = (
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
)
_STARTUP_TIMEOUT_SECONDS = 15.0


@pytest.fixture(params=["asyncio", "trio"])
def anyio_backend(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def scrubbed_ssh_env() -> dict[str, str]:
    """An environment with everything that steers ``ssh`` removed.

    ``SSH_AUTH_SOCK`` is the one that actually bites here. If the developer is running an
    agent, ``ssh`` may offer the keys it holds -- so a test that means to fail with the
    *wrong* key can quietly succeed with the right one, and the assertion that we surface
    ``Permission denied`` verifies nothing at all. ``IdentitiesOnly=yes`` already covers
    this, which is exactly why removing the variable too is worth doing: two independent
    defences, and this one costs a dict comprehension.

    ``HOME`` is redirected for the same reason it always is -- it drags ``~/.ssh/config``
    along with it, and a test that reads the developer's real config passes on their machine
    and proves nothing. This repo has already watched an unguarded probe surface a
    macOS-only ``UseKeychain`` key on Linux.
    """
    steering = {"SSH_AUTH_SOCK", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_AGENT_PID"}
    env = {k: v for k, v in os.environ.items() if k not in steering}
    env["HOME"] = "/nonexistent-home-for-live-tests"
    return env


def connect(server: SSHServer, **overrides):
    """Open a transport to the test server, with any argument replaceable.

    Defaults are merged rather than passed alongside the overrides, so a test can say
    ``port=...`` or ``identity_file=...`` without colliding with the value here.

    Lives in the conftest rather than in one test module because two modules need it, and
    two spellings of "how this suite connects" is how the scrubbed environment ends up
    applied in one of them and not the other.
    """
    options = server.connect_options()
    options.update(overrides.pop("options", {}))
    kwargs = {
        "port": server.port,
        "identity_file": str(server.identity_file),
        "config_file": os.devnull,
        # An agent holding a working key would make the wrong-key test pass for the wrong
        # reason. IdentitiesOnly already covers it; this is the second, independent defence.
        "env": scrubbed_ssh_env(),
    }
    kwargs.update(overrides)
    return open_ssh_transport("127.0.0.1", options=options, **kwargs)


async def negotiate(transport: Transport, codec: Codec) -> None:
    """Drive the handshake to READY."""
    await transport.send(codec.initiate())
    while codec.state is not CodecState.READY:
        codec.receive(await transport.receive())


def _first_existing(candidates: tuple[str, ...]) -> str | None:
    return next((c for c in candidates if Path(c).is_file()), None)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass(frozen=True)
class SSHServer:
    """A running sshd and everything needed to authenticate to it."""

    port: int
    identity_file: Path
    known_hosts: Path
    wrong_identity_file: Path
    empty_known_hosts: Path
    root: Path

    def connect_options(self) -> dict[str, str]:
        """Options that pin this test server and nothing else.

        ``IdentitiesOnly`` matters: without it ``ssh`` will also offer whatever the agent
        holds, so a test meant to fail on a wrong key can accidentally succeed on the
        developer's real one.
        """
        return {
            "UserKnownHostsFile": str(self.known_hosts),
            "IdentitiesOnly": "yes",
            "GlobalKnownHostsFile": "/dev/null",
        }


def _keygen(path: Path) -> None:
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(path), "-N", "", "-q"],
        check=True,
        capture_output=True,
        timeout=60,
    )


def _wait_until_listening(port: int, process: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.skip(f"sshd exited during startup: {log.read_text()[:2000]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    pytest.skip(f"sshd did not start listening within {_STARTUP_TIMEOUT_SECONDS}s")


@pytest.fixture(scope="session")
def ssh_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SSHServer]:
    """Start an sshd on localhost that accepts one key and serves the sftp subsystem.

    Runs unprivileged, which works because it only ever authenticates the user already
    running it. ``StrictModes no`` is required for the same reason -- the key material is in
    a temporary directory, not in a ``~/.ssh`` this process is allowed to write to.
    """
    sshd = _first_existing(SSHD_CANDIDATES)
    if sshd is None:
        pytest.skip(f"sshd not found (looked in {', '.join(SSHD_CANDIDATES)})")
    sftp_server = _first_existing(SFTP_SERVER_CANDIDATES)
    if sftp_server is None:
        pytest.skip("sftp-server not found; sshd cannot serve the sftp subsystem without it")

    root = tmp_path_factory.mktemp("sshd")
    host_key = root / "hostkey"
    identity = root / "userkey"
    wrong_identity = root / "wrongkey"
    _keygen(host_key)
    _keygen(identity)
    _keygen(wrong_identity)

    authorized_keys = root / "authorized_keys"
    authorized_keys.write_bytes(identity.with_suffix(".pub").read_bytes())

    port = _free_port()
    config = root / "sshd_config"
    config.write_text(
        f"ListenAddress 127.0.0.1\n"
        f"HostKey {host_key}\n"
        f"PidFile {root / 'sshd.pid'}\n"
        f"AuthorizedKeysFile {authorized_keys}\n"
        f"StrictModes no\n"
        f"UsePAM no\n"
        f"PasswordAuthentication no\n"
        f"KbdInteractiveAuthentication no\n"
        f"PermitRootLogin no\n"
        f"Subsystem sftp {sftp_server}\n"
        f"LogLevel VERBOSE\n"
    )

    log = root / "sshd.log"
    with log.open("wb") as log_handle:
        process = subprocess.Popen(
            [sshd, "-f", str(config), "-p", str(port), "-D", "-e"],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_until_listening(port, process, log)

            scan = subprocess.run(
                ["ssh-keyscan", "-p", str(port), "-t", "ed25519", "127.0.0.1"],
                capture_output=True,
                timeout=30,
                check=False,
            )
            known_hosts = root / "known_hosts"
            known_hosts.write_bytes(scan.stdout)
            if not scan.stdout.strip():
                pytest.skip("ssh-keyscan returned no host key for the test server")

            empty_known_hosts = root / "empty_known_hosts"
            empty_known_hosts.write_text("")

            yield SSHServer(
                port=port,
                identity_file=identity,
                known_hosts=known_hosts,
                wrong_identity_file=wrong_identity,
                empty_known_hosts=empty_known_hosts,
                root=root,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait(timeout=10)


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

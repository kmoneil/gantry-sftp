"""A real OpenSSH server, on a real socket, for the tests that need one.

Everything here spawns ``sshd`` and connects to it over TCP. That is the boundary
``tests/`` cannot cross: a fake transport proves the codec agrees with our idea of a
server, and ``sftp-server`` on a pipe proves it agrees with the real server -- but neither
of them runs ``ssh``, does key exchange, authenticates, or fails the way a real connection
fails. This directory is where the thesis is actually tested.

Nothing here is allowed to *fail* because a dependency is missing. It skips, with a reason.
"""

from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

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

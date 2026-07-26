"""A real OpenSSH server on a real socket, startable from outside pytest.

This is the boundary ``tests/`` cannot cross. A fake transport proves the codec agrees with
our idea of a server; ``sftp-server`` on a pipe proves it agrees with the real server. Neither
of them runs ``ssh``, does key exchange, authenticates, or fails the way a real connection
fails.

It lives in a module rather than in a ``conftest.py`` because **two suites need it** --
``live-tests/`` and ``benchmarks/`` -- and a conftest is not importable from a sibling
directory. Copying it would give this repository two spellings of "how this suite connects",
which is precisely how the scrubbed ``ssh`` environment ends up applied in one of them and not
the other. The fixtures in each suite are thin wrappers over what is here.

Nothing here calls ``pytest.skip``. Availability is reported by :func:`unavailable_reason` and
startup failures raise :class:`ServerUnavailableError`, so a plain script can use this module and a
fixture can turn either one into a skip. That is the same shape :mod:`netem` uses, for the same
reason: a helper that skips is a helper only pytest can call.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

SSHD_CANDIDATES = ("/usr/sbin/sshd", "/usr/local/sbin/sshd")
SFTP_SERVER_CANDIDATES = (
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
)
STARTUP_TIMEOUT_SECONDS = 15.0
_KEYGEN_TIMEOUT = 60.0
_KEYSCAN_TIMEOUT = 30.0
_SHUTDOWN_TIMEOUT = 10.0
_LOG_EXCERPT_BYTES = 2000


class ServerUnavailableError(RuntimeError):
    """The server could not be started, with a reason fit to be shown as a skip."""


def first_existing(candidates: tuple[str, ...]) -> str | None:
    """The first candidate path that is a file, or ``None``."""
    return next((c for c in candidates if Path(c).is_file()), None)


def unavailable_reason() -> str | None:
    """Why this machine cannot run the live server, or ``None`` if it can.

    Checked before anything is started, so a missing binary is reported as a skip rather than
    as a server that mysteriously failed to come up.
    """
    if first_existing(SSHD_CANDIDATES) is None:
        return f"sshd not found (looked in {', '.join(SSHD_CANDIDATES)})"
    if first_existing(SFTP_SERVER_CANDIDATES) is None:
        return "sftp-server not found; sshd cannot serve the sftp subsystem without it"
    return None


def scrubbed_ssh_env() -> dict[str, str]:
    """An environment with everything that steers ``ssh`` removed.

    ``SSH_AUTH_SOCK`` is the one that actually bites. If the developer is running an agent,
    ``ssh`` may offer the keys it holds -- so a test that means to fail with the *wrong* key
    can quietly succeed with the right one, and the assertion that we surface
    ``Permission denied`` verifies nothing at all. ``IdentitiesOnly=yes`` already covers this,
    which is exactly why removing the variable too is worth doing: two independent defences,
    and this one costs a dict comprehension.

    ``HOME`` is redirected for the same reason it always is -- it drags ``~/.ssh/config``
    along with it, and a test that reads the developer's real config passes on their machine
    and proves nothing. This repo has already watched an unguarded probe surface a macOS-only
    ``UseKeychain`` key on Linux.

    It matters for the benchmark too, and for a second reason: an ``ssh_config`` carrying
    ``Compression yes`` or a ``ControlMaster`` socket would change the number without changing
    the code, and the report would name a link profile it was not actually measured on.
    """
    steering = {"SSH_AUTH_SOCK", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_AGENT_PID"}
    env = {k: v for k, v in os.environ.items() if k not in steering}
    env["HOME"] = "/nonexistent-home-for-live-tests"
    return env


def free_port() -> int:
    """A port nothing is listening on, released immediately so ``sshd`` can take it."""
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


def connect_kwargs(server: SSHServer, **overrides: object) -> dict[str, object]:
    """Keyword arguments for :func:`~gantry_sftp.transport.open_ssh_transport`.

    Defaults are merged rather than passed alongside the overrides, so a caller can say
    ``port=...`` or ``identity_file=...`` without colliding with the value here.

    Returns:
        Arguments ready to splat, with ``options`` already merged.
    """
    options = server.connect_options()
    supplied = overrides.pop("options", {})
    assert isinstance(supplied, dict)
    options.update(supplied)
    kwargs: dict[str, object] = {
        "port": server.port,
        "identity_file": str(server.identity_file),
        "config_file": os.devnull,
        # An agent holding a working key would make the wrong-key test pass for the wrong
        # reason. IdentitiesOnly already covers it; this is the second, independent defence.
        "env": scrubbed_ssh_env(),
        "options": options,
    }
    kwargs.update(overrides)
    return kwargs


def _keygen(path: Path) -> None:
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(path), "-N", "", "-q"],
        check=True,
        capture_output=True,
        timeout=_KEYGEN_TIMEOUT,
    )


def _wait_until_listening(port: int, process: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            excerpt = log.read_text()[:_LOG_EXCERPT_BYTES]
            raise ServerUnavailableError(f"sshd exited during startup: {excerpt}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise ServerUnavailableError(f"sshd did not start listening within {STARTUP_TIMEOUT_SECONDS}s")


def _write_config(root: Path, *, host_key: Path, authorized_keys: Path, sftp_server: str) -> Path:
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
    return config


def _scan_host_key(port: int, root: Path) -> Path:
    scan = subprocess.run(
        ["ssh-keyscan", "-p", str(port), "-t", "ed25519", "127.0.0.1"],
        capture_output=True,
        timeout=_KEYSCAN_TIMEOUT,
        check=False,
    )
    known_hosts = root / "known_hosts"
    known_hosts.write_bytes(scan.stdout)
    if not scan.stdout.strip():
        raise ServerUnavailableError("ssh-keyscan returned no host key for the test server")
    return known_hosts


@contextmanager
def running_sshd(root: Path) -> Iterator[SSHServer]:
    """Start an sshd on localhost that accepts one key and serves the sftp subsystem.

    Runs unprivileged, which works because it only ever authenticates the user already running
    it. ``StrictModes no`` is required for the same reason -- the key material is in a
    temporary directory, not in a ``~/.ssh`` this process is allowed to write to.

    Args:
        root: Directory to hold keys, config and logs. Also the server's file tree.

    Yields:
        The running server.

    Raises:
        ServerUnavailableError: If a required binary is missing or the server does not come up.
    """
    reason = unavailable_reason()
    if reason is not None:
        raise ServerUnavailableError(reason)
    sshd = first_existing(SSHD_CANDIDATES)
    sftp_server = first_existing(SFTP_SERVER_CANDIDATES)
    assert sshd is not None  # unavailable_reason checked it
    assert sftp_server is not None  # and this one

    host_key = root / "hostkey"
    identity = root / "userkey"
    wrong_identity = root / "wrongkey"
    _keygen(host_key)
    _keygen(identity)
    _keygen(wrong_identity)

    authorized_keys = root / "authorized_keys"
    authorized_keys.write_bytes(identity.with_suffix(".pub").read_bytes())

    port = free_port()
    config = _write_config(
        root, host_key=host_key, authorized_keys=authorized_keys, sftp_server=sftp_server
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
            known_hosts = _scan_host_key(port, root)
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
                process.wait(timeout=_SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait(timeout=_SHUTDOWN_TIMEOUT)

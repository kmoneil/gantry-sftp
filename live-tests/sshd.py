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
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, Unpack

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


STEERING = (
    # The agent. This is the one that actually bites: if the developer is running an agent,
    # `ssh` offers the keys it holds, so a test that means to fail with the *wrong* key can
    # quietly succeed with the right one and the assertion that we surface `Permission
    # denied` verifies nothing. Measured against a real agent holding the right key --
    # `test_ssh_environment.py` has the truth table, including the row that authenticates.
    "SSH_AUTH_SOCK",
    # Kept for tidiness, and deliberately NOT described as steering. Measured: `ssh` and
    # `ssh-add` locate the agent through `SSH_AUTH_SOCK` alone -- with only `SSH_AGENT_PID`
    # set, `ssh-add -l` answers "Could not open a connection to your authentication agent".
    # It is removed because a pid pointing at an agent the child cannot reach is misleading,
    # not because leaving it would change what `ssh` does.
    "SSH_AGENT_PID",
    # The passphrase-prompt helper, and -- the part a list written from memory misses -- the
    # two variables that ARM it. `ssh` runs an askpass helper when a display is available, so
    # `DISPLAY` or `WAYLAND_DISPLAY` alone is sufficient; and clearing `SSH_ASKPASS` does not
    # disarm it, because this binary has `/usr/bin/ssh-askpass` compiled in as the default.
    # Measured: with an encrypted key the server accepts, `DISPLAY=:0` and
    # `WAYLAND_DISPLAY=wayland-0` each make the helper run and the connection AUTHENTICATE.
    # `WAYLAND_DISPLAY` appears nowhere in ssh(1); it is in the binary.
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    # `ssh` execs `$SHELL -c "exec <command>"` for `ProxyCommand`, `LocalCommand`, `Match
    # exec` and the `ProxyUseFdpass` dialer; `/bin/sh` is only the fallback when this is
    # unset. Measured with a marker script in `SHELL`, which duly ran with
    # `argv=-c exec /bin/echo hello`. Removing it makes "the proxy runs under /bin/sh" true
    # instead of "the proxy runs under whatever shell the developer happens to use".
    "SHELL",
    # Path to the helper `ssh` forks for a security-key (`-sk`) identity. Sourced from the
    # installed binary's own strings and from OpenSSH's `ssh-sk-client.c`, NOT measured:
    # provoking it needs a hardware token. Removed because it is the same class as
    # `SSH_ASKPASS` -- an executable path taken from the environment -- and because
    # over-removal costs nothing here.
    "SSH_SK_HELPER",
)
"""Every environment variable that changes what ``ssh`` does, with the evidence for each.

Sourced against OpenSSH 10.0p2 rather than recalled. Two of these were absent from the list
this module shipped with, and the reason is instructive: the original four were the names a
person remembers, and the ones that were missing are the *gates* rather than the mechanisms.
"""

REDIRECTED_HOME = "/nonexistent-home-for-live-tests"
"""Where ``HOME`` is pointed. See :func:`scrubbed_ssh_env` for what this does and does not do.

Public because it is the one *positive* signal that a connection's ``env`` came from
:func:`scrubbed_ssh_env` rather than from ``os.environ``. Absence assertions cannot say that:
on a runner where none of :data:`STEERING` happens to be set, "none of these names is present"
is equally true of an unscrubbed environment. This value is never present by accident.
"""


def scrubbed_ssh_env() -> dict[str, str]:
    """An environment with everything that steers ``ssh`` removed.

    :data:`STEERING` is the list and carries the evidence for each name. What follows is the
    part that is easy to get wrong, and that this module got wrong until 0.8.

    **Redirecting ``HOME`` does not stop ``ssh`` reading the developer's ``~/.ssh``.** That
    was the stated reason for doing it here, and it is false. ``ssh`` resolves ``~`` from the
    password database, not from ``$HOME``. Measured on OpenSSH 10.0p2: with ``HOME`` pointed
    at an empty directory, ``ssh -v`` still reads ``/home/dev/.ssh/config`` -- emitting the
    very ``UseKeychain`` errors DESIGN.md §4.3 cites as the incident that motivated this
    function -- and still loads ``/home/dev/.ssh/id_rsa`` and ``id_ed25519`` as candidate
    identities. **``-F`` is the defence**, which is why :func:`client_kwargs` passes
    ``os.devnull`` unconditionally and why a test now asserts that it does.

    The redirect is kept, with its real and much narrower scope stated: ``HOME`` is inherited
    by the children ``ssh`` spawns -- ``ProxyCommand``, ``LocalCommand``, an askpass helper --
    and it expands inside ``-o`` values, where ``ControlPath=${HOME}/...`` is the case that
    matters. Measured: ``HOME=/zzz-fake-home`` yields ``controlpath /zzz-fake-home/cp-dev``.

    It matters for the benchmark too, and for a second reason: an ``ssh_config`` carrying
    ``Compression yes`` or a ``ControlMaster`` socket would change the number without changing
    the code, and the report would name a link profile it was not actually measured on. That
    is ``-F``'s doing as well.

    Returns:
        A filtered copy. ``os.environ`` is not touched.
    """
    env = {k: v for k, v in os.environ.items() if k not in STEERING}
    env["HOME"] = REDIRECTED_HOME
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
    applied_directives: tuple[str, ...] = ()
    """Which of :data:`OPTIONAL_DIRECTIVES` this ``sshd`` actually accepted.

    Reported rather than assumed because :func:`_write_config` drops them *silently* when
    ``sshd -t`` refuses the config -- for any reason, not only an old ``sshd``. A lane that
    depends on one of them, as the agent-rescue lane depends on ``PerSourcePenalties no``,
    can then assert its precondition instead of being diagnosed later as a key-exchange
    reset in an unrelated test.
    """

    def connect_options(self) -> dict[str, str]:
        """Options that pin this test server and nothing else.

        ``IdentitiesOnly`` matters: without it ``ssh`` will also offer whatever the agent
        holds, so a test meant to fail on a wrong key can accidentally succeed on the
        developer's real one. It is the first of two independent defences and the scrubbed
        environment is the second; ``test_ssh_environment.py`` proves each holds alone, and
        asserts this dict still carries it -- deleting the line used to leave the whole live
        suite green, because the other defence covered for it.
        """
        return {
            "UserKnownHostsFile": str(self.known_hosts),
            "IdentitiesOnly": "yes",
            "GlobalKnownHostsFile": os.devnull,
        }


class ClientKwargs(TypedDict, total=False):
    """The keyword arguments this suite splats into ``open_ssh_transport`` and ``connect``.

    Both helpers below returned ``dict[str, object]`` until D-152, and that return type
    defeats the checker at every one of their call sites: splatting such a dict into a
    function with typed keyword parameters is one ``arg-type`` error *per parameter*, so the
    sites either carried an ignore or sat outside the gate. The value being ``object`` is
    what does it -- the key names were never the problem.

    ``total=False`` because :func:`connect_kwargs` merges caller overrides over these defaults
    and nothing here is mandatory at the splat; ``open_ssh_transport`` has its own default for
    every one. No value is ``| None`` even though every parameter it feeds accepts ``None``:
    absent and ``None`` are the same instruction to those functions, this suite only ever uses
    the first, and carrying the second costs every reader of a key a narrowing step for a state
    nothing produces.

    The keys are the **intersection** of what :func:`~gantry_sftp.connect` and
    :func:`~gantry_sftp.transport.open_ssh_transport` accept, because the same dict is
    splatted into both and a key only one of them takes is an error at the other. That is not
    a hypothetical: ``subsystem`` was in this list for one revision, no caller ever passed it,
    and it failed seven ``connect(...)`` sites immediately. Adding a key here is what makes it
    passable, which is the point -- an override this class does not name now fails at the call
    rather than at the server.
    """

    port: int
    identity_file: str | os.PathLike[str]
    config_file: str | os.PathLike[str]
    env: Mapping[str, str]
    options: Mapping[str, str]
    user: str
    password: str
    ssh_executable: str


def client_kwargs(
    *, port: int, identity_file: str | Path, options: Mapping[str, str]
) -> ClientKwargs:
    """The connection arguments every suite here must use, assembled in one place.

    Three call sites need these -- :func:`connect_kwargs` for the OpenSSH server, and the
    asyncssh and paramiko servers in :mod:`matrix` -- and the two that are not
    :func:`connect_kwargs` used to spell out ``config_file`` and ``env`` for themselves.
    That is precisely the arrangement this module's docstring exists to prevent: with more
    than one spelling of "how this suite connects", one of them eventually stops being
    scrubbed and nothing goes red.

    ``env`` is the second of two independent defences against an agent supplying a key the
    test never meant to offer; ``IdentitiesOnly`` in the caller's options is the first.
    ``test_ssh_environment.py`` proves each one holds without the other, and proves the
    hazard is real by removing both.

    Args:
        port: Port the server is listening on.
        identity_file: Private key to authenticate with, passed as ``-i``.
        options: ``-o`` options pinning this server. Copied, not aliased.

    Returns:
        Arguments ready to splat into
        :func:`~gantry_sftp.transport.open_ssh_transport`, host excluded.
    """
    return {
        "port": port,
        "identity_file": str(identity_file),
        "config_file": os.devnull,
        "env": scrubbed_ssh_env(),
        "options": dict(options),
    }


def connect_kwargs(server: SSHServer, **overrides: Unpack[ClientKwargs]) -> ClientKwargs:
    """Keyword arguments for :func:`~gantry_sftp.transport.open_ssh_transport`.

    Defaults are merged rather than passed alongside the overrides, so a caller can say
    ``port=...`` or ``identity_file=...`` without colliding with the value here.

    Returns:
        Arguments ready to splat, with ``options`` already merged.
    """
    options = server.connect_options()
    options.update(overrides.pop("options", {}))
    kwargs = client_kwargs(port=server.port, identity_file=server.identity_file, options=options)
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


OPTIONAL_DIRECTIVES = ("PerSourcePenalties no",)
"""Directives that help but do not exist on every sshd, so they are probed before being used.

``PerSourcePenalties`` arrived in **OpenSSH 9.8** and 10.x ships it *on*, with defaults
``authfail:5 noauth:1 ... min:15``. Every deliberately-failed authentication earns the source
address a timed penalty, and once one is active sshd drops the **next** connection from that
address during key exchange -- ``kex_exchange_identification: read: Connection reset by peer``,
which reads like a client bug and is not one.

This suite fails authentication on purpose (wrong key, unknown host key, changed host key), so
it accrues penalties and then breaks a later, unrelated test. It sat just under the threshold
until a third failure case was added, which is the worst way to discover a latent limit.

Turning it off is correct here and would be wrong anywhere else: the penalty is a real defence
against password-guessing, and nothing shipped touches sshd configuration. An older sshd rejects
the directive outright and refuses to start, so the config is validated with ``sshd -t`` and the
line dropped if it is not understood -- probed rather than inferred from a version string, the
same rule the netem lane follows.
"""


def _config_is_valid(sshd: str, config: Path, host_key: Path) -> bool:
    """Whether this sshd accepts the config, via its own ``-t`` syntax check."""
    result = subprocess.run(
        [sshd, "-t", "-f", str(config), "-h", str(host_key)],
        capture_output=True,
        text=True,
        timeout=_KEYSCAN_TIMEOUT,
        check=False,
    )
    return result.returncode == 0


def _write_config(
    root: Path, *, sshd: str, host_key: Path, authorized_keys: Path, sftp_server: str
) -> tuple[Path, tuple[str, ...]]:
    """Write an sshd config, dropping optional directives this sshd does not understand.

    Returns:
        The config path, and which of :data:`OPTIONAL_DIRECTIVES` survived. The second half
        is returned rather than discarded because dropping one is silent and its absence
        surfaces much later, in a different test, as a connection reset during key exchange.
    """
    base = (
        "ListenAddress 127.0.0.1",
        f"HostKey {host_key}",
        f"PidFile {root / 'sshd.pid'}",
        f"AuthorizedKeysFile {authorized_keys}",
        "StrictModes no",
        "UsePAM no",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin no",
        f"Subsystem sftp {sftp_server}",
        "LogLevel VERBOSE",
    )
    config = root / "sshd_config"
    for extras in (OPTIONAL_DIRECTIVES, ()):
        config.write_text("\n".join((*base, *extras)) + "\n")
        if _config_is_valid(sshd, config, host_key):
            return config, extras
    # Neither spelling validated: leave the plain one and let startup report the real reason,
    # which will be more specific than anything guessed here.
    return config, ()


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
def running_sshd(root: Path) -> Generator[SSHServer]:
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
    config, applied_directives = _write_config(
        root,
        sshd=sshd,
        host_key=host_key,
        authorized_keys=authorized_keys,
        sftp_server=sftp_server,
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
                applied_directives=applied_directives,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=_SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait(timeout=_SHUTDOWN_TIMEOUT)

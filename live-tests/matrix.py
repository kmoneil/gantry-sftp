"""Three SFTP server implementations, driven by the same client over real ``ssh``.

DESIGN.md 7 asserts that real endpoints differ -- on extensions, on limits, on error text, on
path semantics -- and until this module every one of those claims was sourced to nothing. One
server cannot disagree with itself, so a "quirks" design built against OpenSSH alone is a
design against a guess.

The matrix does not need Docker, which is what made it look expensive. **asyncssh and paramiko
are already here**, as the comparison clients ``benchmarks/`` runs against, and both ship an
SFTP *server* as well. So the same ``bench`` dependency group buys three implementations
instead of one, and the same rule applies to it: that group is deliberately not installed by
default, because paramiko and asyncssh drag in ``cryptography`` and this project exists not to
need it. Absent, these skip with that reason.

What each one is, stated so the evidence is not overclaimed:

* **openssh** -- the real ``sshd`` plus ``sftp-server``, via :mod:`sshd`. The reference.
* **asyncssh** -- asyncssh's own SSH server with ``sftp_factory=True``. Entirely theirs.
* **paramiko** -- paramiko's ``SFTPServer`` over paramiko's ``Transport``. The protocol half
  is theirs: what it advertises, how it maps errors, how it frames packets. The filesystem
  half is :class:`_ParamikoHandler` here, because paramiko ships the interface and leaves the
  implementation to the caller. Facts read off this server are about paramiko's protocol
  behaviour, not about the twenty lines of ``os.stat`` below it.

Both non-OpenSSH servers run on a thread with their own event loop rather than in the test's.
asyncssh is asyncio-only and the suite also runs on trio, and paramiko is threads to begin
with -- so a thread each keeps the matrix backend-agnostic instead of quietly asyncio-only.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import sshd

# Imported at the top and allowed to be absent, rather than inside the functions that need
# them. `bench` is deliberately not a default group -- paramiko and asyncssh drag in
# `cryptography`, which this project exists not to need -- so this module has to import
# cleanly without them or `unavailable_reason` could not report that they are missing.
try:
    import asyncssh
except ImportError:  # pragma: no cover -- exercised by not installing the group
    asyncssh = None  # type: ignore[assignment]

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]

SERVER_NAMES = ("openssh", "asyncssh", "paramiko")
"""Every implementation the matrix knows how to start, in reference-first order."""

_STARTUP_TIMEOUT = 30.0


@dataclass(frozen=True)
class MatrixServer:
    """A running server and what it takes to connect to it.

    Attributes:
        name: Which implementation, one of :data:`SERVER_NAMES`.
        version: Its own version string, for the report rather than for logic.
        connect: Keyword arguments for
            :func:`~gantry_sftp.transport.open_ssh_transport`, host included.
        root: A directory the server can read and write, for fixtures.
    """

    name: str
    version: str
    connect: dict[str, Any]
    root: Path = field(default=Path())


def unavailable_reason(name: str) -> str | None:
    """Why ``name`` cannot be started here, or ``None`` if it can.

    A reason rather than a bool, because a skipped live test that does not say what was
    missing is indistinguishable from one that silently stopped testing anything.
    """
    if name == "openssh":
        return sshd.unavailable_reason()
    if name == "asyncssh":
        return None if asyncssh is not None else "asyncssh not installed (uv sync --group bench)"
    if name == "paramiko":
        return None if paramiko is not None else "paramiko not installed (uv sync --group bench)"
    return f"unknown server {name!r}"


@contextmanager
def running_server(name: str, root: Path) -> Iterator[MatrixServer]:
    """Start ``name``, yield how to reach it, and stop it on the way out."""
    if name == "openssh":
        with _running_openssh(root) as server:
            yield server
    elif name == "asyncssh":
        with _running_asyncssh(root) as server:
            yield server
    elif name == "paramiko":
        with _running_paramiko(root) as server:
            yield server
    else:  # pragma: no cover -- guarded by unavailable_reason
        raise ValueError(f"unknown server {name!r}")


# --- OpenSSH, which already had a harness ------------------------------------------------------


@contextmanager
def _running_openssh(root: Path) -> Iterator[MatrixServer]:
    with sshd.running_sshd(root) as server:
        connect = dict(sshd.connect_kwargs(server))
        connect["host"] = "127.0.0.1"
        yield MatrixServer("openssh", _openssh_version(), connect, root)


def _openssh_version() -> str:
    finished = subprocess.run(["ssh", "-V"], capture_output=True, text=True, check=False)
    return (finished.stderr or finished.stdout).strip().splitlines()[0]


# --- keys, shared by the two servers that need their own ---------------------------------------


def _keypair(root: Path, stem: str) -> Path:
    """Generate an ed25519 key with ``ssh-keygen``, returning the private key's path.

    ``ssh-keygen`` rather than each library's own generator: the client is real ``ssh``, so
    the key has to be in a format it accepts, and one generator for both servers means a key
    problem cannot masquerade as a protocol difference.
    """
    path = root / stem
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
        check=True,
        capture_output=True,
    )
    return path


def _client_options(known_hosts: Path) -> dict[str, Any]:
    """Client options pinning this server and nothing else.

    ``IdentitiesOnly`` and a scrubbed environment matter for the same reason they do in
    :mod:`sshd`: an agent holding a working key would make a test pass without the key under
    test ever being offered.
    """
    return {
        "UserKnownHostsFile": str(known_hosts),
        "IdentitiesOnly": "yes",
        "StrictHostKeyChecking": "yes",
    }


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# --- asyncssh ----------------------------------------------------------------------------------


@contextmanager
def _listening_asyncssh(name: str, **listen_kwargs: Any) -> Iterator[None]:
    """Run ``asyncssh.listen`` on its own thread and event loop for the block's duration.

    Extracted because two servers here need it -- the matrix's key-authenticating one and the
    password-authenticating one the D-78 lane drives -- and a second copy of "how asyncssh is
    started and stopped" is the arrangement :mod:`sshd`'s docstring exists to prevent.

    asyncssh is asyncio-only and this suite also runs on trio, so it gets a thread of its own
    rather than the test's loop.
    """
    started = threading.Event()
    stopping = threading.Event()
    failure: list[BaseException] = []

    def serve() -> None:
        async def main() -> None:
            assert asyncssh is not None
            server = await asyncssh.listen("127.0.0.1", **listen_kwargs)
            started.set()
            while not stopping.is_set():  # noqa: ASYNC110 -- bridging a threading.Event
                await asyncio.sleep(0.05)
            server.close()

        try:
            asyncio.run(main())
        except BaseException as error:
            failure.append(error)
            started.set()

    thread = threading.Thread(target=serve, daemon=True, name=name)
    thread.start()
    if not started.wait(_STARTUP_TIMEOUT):
        raise sshd.ServerUnavailableError(f"{name} did not start")
    if failure:
        raise sshd.ServerUnavailableError(f"{name} failed to start: {failure[0]!r}")
    try:
        yield
    finally:
        stopping.set()
        thread.join(timeout=_STARTUP_TIMEOUT)


@contextmanager
def _running_asyncssh(root: Path) -> Iterator[MatrixServer]:
    assert asyncssh is not None
    host_key = _keypair(root, "asyncssh_host")
    client_key = _keypair(root, "asyncssh_client")
    port = _free_port()
    (root / "asyncssh_known_hosts").write_text(
        f"[127.0.0.1]:{port} {(root / 'asyncssh_host.pub').read_text().strip()}\n"
    )

    with _listening_asyncssh(
        "asyncssh-matrix",
        port=port,
        server_host_keys=[str(host_key)],
        authorized_client_keys=str(root / "asyncssh_client.pub"),
        sftp_factory=True,
    ):
        yield MatrixServer(
            "asyncssh",
            f"asyncssh {asyncssh.__version__}",
            {
                "host": "127.0.0.1",
                **sshd.client_kwargs(
                    port=port,
                    identity_file=client_key,
                    options=_client_options(root / "asyncssh_known_hosts"),
                ),
            },
            root,
        )


# --- a server that authenticates with a password, which OpenSSH's sshd cannot do here -------


def password_server_unavailable_reason() -> str | None:
    """Why :func:`running_password_server` cannot run here, or ``None``."""
    return unavailable_reason("asyncssh")


@contextmanager
def running_password_server(root: Path, *, password: str) -> Iterator[MatrixServer]:
    """A real SSH server that accepts exactly one password and offers nothing else.

    **Not OpenSSH, and the reason is measured rather than a preference.** ``live-tests`` runs
    ``sshd`` unprivileged, and an unprivileged ``sshd`` cannot verify a password: with
    ``PasswordAuthentication yes`` and ``UsePAM no`` it offers the method, refuses every
    attempt, and logs ``Could not get shadow information for dev`` -- ``/etc/shadow`` is
    ``root:shadow 0640``. Making that lane work needs root or a PAM stack, which is a change
    to the machine rather than to this repository.

    What is under test is the **client** -- the argv, the askpass helper, and the environment
    the child is given -- and the client does not care which implementation is at the far end.
    So the far end is asyncssh, which validates a password in-process with no privilege at
    all. It has a second advantage: ``PerSourcePenalties`` is an OpenSSH ``sshd`` feature, so
    the deliberately-failing cases here cannot poison a later, unrelated test the way they do
    against the reference server.

    Args:
        root: Directory for keys and the served file tree.
        password: The one secret this server accepts.

    Yields:
        The running server. ``connect`` carries no ``identity_file``: offering a key here
        would let a test pass without the password path being exercised at all.
    """
    assert asyncssh is not None

    class PasswordOnly(asyncssh.SSHServer):
        """Authentication by password and nothing else."""

        def begin_auth(self, username: str) -> bool:
            return True  # authentication is required; returning False would let anyone in

        def password_auth_supported(self) -> bool:
            return True

        def validate_password(self, username: str, password_attempt: str) -> bool:
            return secrets.compare_digest(password_attempt, password)

    host_key = _keypair(root, "password_host")
    port = _free_port()
    known_hosts = root / "password_known_hosts"
    known_hosts.write_text(
        f"[127.0.0.1]:{port} {(root / 'password_host.pub').read_text().strip()}\n"
    )

    with _listening_asyncssh(
        "asyncssh-password",
        port=port,
        server_factory=PasswordOnly,
        server_host_keys=[str(host_key)],
        sftp_factory=True,
    ):
        yield MatrixServer(
            "asyncssh",
            f"asyncssh {asyncssh.__version__}",
            {
                "host": "127.0.0.1",
                "port": port,
                "config_file": os.devnull,
                # Scrubbed for the usual reason and for one specific to this lane: it removes
                # every variable that would arm an askpass helper, so a test of the *refusing*
                # case is genuinely unable to answer a prompt rather than accidentally able.
                "env": sshd.scrubbed_ssh_env(),
                "options": _client_options(known_hosts),
            },
            root,
        )


# --- paramiko ----------------------------------------------------------------------------------


@contextmanager
def _running_paramiko(root: Path) -> Iterator[MatrixServer]:
    assert paramiko is not None
    host_key_path = _keypair(root, "paramiko_host")
    client_key_path = _keypair(root, "paramiko_client")
    host_key = paramiko.Ed25519Key(filename=str(host_key_path))
    client_key = paramiko.Ed25519Key(filename=str(client_key_path))

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = int(listener.getsockname()[1])
    (root / "paramiko_known_hosts").write_text(
        f"[127.0.0.1]:{port} {host_key.get_name()} {host_key.get_base64()}\n"
    )

    stopping = threading.Event()
    thread = threading.Thread(
        target=_paramiko_accept_loop,
        args=(listener, host_key, client_key, stopping),
        daemon=True,
        name="paramiko-matrix",
    )
    thread.start()

    try:
        yield MatrixServer(
            "paramiko",
            f"paramiko {paramiko.__version__}",
            {
                "host": "127.0.0.1",
                **sshd.client_kwargs(
                    port=port,
                    identity_file=client_key_path,
                    options=_client_options(root / "paramiko_known_hosts"),
                ),
            },
            root,
        )
    finally:
        stopping.set()
        with suppress(OSError):
            listener.close()
        thread.join(timeout=_STARTUP_TIMEOUT)


def _paramiko_accept_loop(
    listener: socket.socket, host_key: Any, client_key: Any, stopping: threading.Event
) -> None:
    """Serve connections until told to stop. One thread per connection, which is paramiko."""
    listener.settimeout(0.2)
    while not stopping.is_set():
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        session = threading.Thread(
            target=_paramiko_serve_one,
            args=(connection, host_key, client_key),
            daemon=True,
        )
        session.start()


def _paramiko_serve_one(connection: socket.socket, host_key: Any, client_key: Any) -> None:
    assert paramiko is not None
    transport = paramiko.Transport(connection)
    transport.add_server_key(host_key)
    transport.set_subsystem_handler("sftp", paramiko.SFTPServer, _ParamikoHandler)
    with suppress(Exception):
        transport.start_server(server=_ParamikoAuth(client_key))
        channel = transport.accept(_STARTUP_TIMEOUT)
        if channel is not None:
            while transport.is_active():
                transport.join(0.5)


if paramiko is not None:

    class _ParamikoAuth(paramiko.ServerInterface):
        """Public-key auth against exactly one known key."""

        def __init__(self, authorized: Any) -> None:
            self._authorized = authorized

        def get_allowed_auths(self, username: str) -> str:
            # Without this the default is "none": the client is told public keys are not
            # accepted and the failure reads as "Permission denied (password)", which sends
            # you looking for a key problem that is not there.
            return "publickey"

        def check_auth_publickey(self, username: str, key: Any) -> int:
            return paramiko.AUTH_SUCCESSFUL if key == self._authorized else paramiko.AUTH_FAILED

        def check_channel_request(self, kind: str, chanid: int) -> int:
            return paramiko.OPEN_SUCCEEDED

    class _ParamikoFileHandle(paramiko.SFTPHandle):
        """An open file, with ``stat`` implemented.

        ``SFTPHandle.stat`` is unimplemented in paramiko and answers ``OP_UNSUPPORTED`` --
        which is fine for reads and writes and is *not* fine for ``check-file``: its
        ``length=0`` case, meaning "hash to the end of the file", asks the handle how long
        the file is and reports "Unable to stat file" when it will not say. Found by the
        check-file test failing on exactly that path, which is the handler being incomplete
        rather than the protocol disagreeing with us.
        """

        def stat(self) -> Any:
            try:
                return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)

    class _ParamikoHandler(paramiko.SFTPServerInterface):
        """The filesystem half of paramiko's SFTP server.

        **This is ours, and the distinction decides what the matrix may claim.** Paramiko
        ships ``SFTPServer`` -- the packet handling, the advertised extensions, the mapping
        from ``errno`` to a status code and its message text -- and leaves the filesystem to
        the caller. So a fact about *what paramiko advertises or how it maps an error* is a
        fact about paramiko; a fact about *what RENAME does to an existing target* is a fact
        about the thirty lines below, and the tests say which is which rather than reporting
        our own choices as findings.
        """

        def list_folder(self, path: str) -> Any:
            try:
                entries = []
                for child in Path(path).iterdir():
                    attributes = paramiko.SFTPAttributes.from_stat(child.stat())
                    attributes.filename = child.name
                    entries.append(attributes)
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            return entries

        def stat(self, path: str) -> Any:
            try:
                return paramiko.SFTPAttributes.from_stat(Path(path).stat())
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)

        def lstat(self, path: str) -> Any:
            try:
                return paramiko.SFTPAttributes.from_stat(Path(path).lstat())
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)

        def open(self, path: str, flags: int, attr: Any) -> Any:
            try:
                descriptor = os.open(path, flags, 0o666)
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR))
            stream = os.fdopen(descriptor, "r+b" if writing else "rb")
            handle = _ParamikoFileHandle(flags)
            handle.filename = path
            handle.readfile = stream
            handle.writefile = stream if writing else None
            return handle

        def remove(self, path: str) -> int:
            try:
                Path(path).unlink()
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            return paramiko.SFTP_OK

        def rename(self, oldpath: str, newpath: str) -> int:
            # `Path.rename` replaces silently, and that is *this handler's* choice rather than
            # paramiko's protocol behaviour -- the draft says RENAME fails when the target
            # exists. Left as the obvious implementation, and excluded from the matrix's
            # rename assertions, because quietly making it conformant would be choosing the
            # answer to a question the matrix is supposed to be asking.
            try:
                Path(oldpath).rename(newpath)
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            return paramiko.SFTP_OK

        def mkdir(self, path: str, attr: Any) -> int:
            try:
                Path(path).mkdir()
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            return paramiko.SFTP_OK

        def rmdir(self, path: str) -> int:
            try:
                Path(path).rmdir()
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
            return paramiko.SFTP_OK

        def canonicalize(self, path: str) -> str:
            return os.path.normpath(Path.cwd() / path)

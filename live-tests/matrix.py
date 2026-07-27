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
def _running_asyncssh(root: Path) -> Iterator[MatrixServer]:
    assert asyncssh is not None
    host_key = _keypair(root, "asyncssh_host")
    client_key = _keypair(root, "asyncssh_client")
    port = _free_port()
    (root / "asyncssh_known_hosts").write_text(
        f"[127.0.0.1]:{port} {(root / 'asyncssh_host.pub').read_text().strip()}\n"
    )

    started = threading.Event()
    stopping = threading.Event()
    failure: list[BaseException] = []

    def serve() -> None:
        async def main() -> None:
            assert asyncssh is not None
            server = await asyncssh.listen(
                "127.0.0.1",
                port,
                server_host_keys=[str(host_key)],
                authorized_client_keys=str(root / "asyncssh_client.pub"),
                sftp_factory=True,
            )
            started.set()
            while not stopping.is_set():  # noqa: ASYNC110 -- bridging a threading.Event
                await asyncio.sleep(0.05)
            server.close()

        try:
            asyncio.run(main())
        except BaseException as error:
            failure.append(error)
            started.set()

    thread = threading.Thread(target=serve, daemon=True, name="asyncssh-matrix")
    thread.start()
    if not started.wait(_STARTUP_TIMEOUT):
        raise sshd.ServerUnavailableError("asyncssh server did not start")
    if failure:
        raise sshd.ServerUnavailableError(f"asyncssh server failed to start: {failure[0]!r}")

    try:
        yield MatrixServer(
            "asyncssh",
            f"asyncssh {asyncssh.__version__}",
            {
                "host": "127.0.0.1",
                "port": port,
                "identity_file": str(client_key),
                "config_file": os.devnull,
                "env": sshd.scrubbed_ssh_env(),
                "options": _client_options(root / "asyncssh_known_hosts"),
            },
            root,
        )
    finally:
        stopping.set()
        thread.join(timeout=_STARTUP_TIMEOUT)


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
                "port": port,
                "identity_file": str(client_key_path),
                "config_file": os.devnull,
                "env": sshd.scrubbed_ssh_env(),
                "options": _client_options(root / "paramiko_known_hosts"),
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
            handle = paramiko.SFTPHandle(flags)
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

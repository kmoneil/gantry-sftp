"""Authenticating with a password, without putting it where ``ps`` can read it.

    python examples/password_auth.py              # what the secret does and does not touch
    python examples/password_auth.py user@host    # against a real password-accepting server

Most of the enterprise SFTP endpoints this library was written for -- MOVEit, GoAnywhere,
Cleo, Sterling -- are password-first. ``ssh`` deliberately refuses to take a password as an
argument, and the two workarounds people reach for when a library appears not to support one,
``sshpass -p secret`` and an ``-o`` value, both put the credential in **argv**, where
``/proc/<pid>/cmdline`` makes it readable by every user on the machine for as long as the
process lives.

``password=`` is the supported path. It writes a throwaway ``SSH_ASKPASS`` helper -- containing
no secret, just a ``printf`` of an environment variable -- and hands ``ssh`` the secret in the
child's environment, which on Linux only this user and root can read. The helper is deleted
when the connection ends, successfully or not.

**It also relaxes one shipped default, and that is the whole reason this example exists.**
``BatchMode=yes`` ships on purpose: a transfer hung on an invisible prompt is the commonest way
an automated SFTP job fails silently. But it does not merely discourage a password prompt -- it
suppresses the askpass helper *outright*, so before ``password=`` existed, password
authentication was not awkward here. It was impossible, and nothing said so.

The no-argument run needs no server: it connects to a closed port, which is enough to prove
what did and did not reach the command line.
"""

from __future__ import annotations

import getpass
import os
import socket
import sys
from pathlib import Path

import anyio

import gantry_sftp
from gantry_sftp.exceptions import AuthenticationError, ConnectError
from gantry_sftp.session import open_session
from gantry_sftp.transport import (
    DEFAULT_SSH_OPTIONS,
    PASSWORD_AUTH_OPTIONS,
    open_ssh_transport,
)

PASSWORD_VARIABLE = "GANTRY_SFTP_PASSWORD"
"""Where this example reads the secret from when there is no terminal to prompt on."""


def closed_port() -> int:
    """A port with nothing listening on it, so the no-arguments run has something to fail on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def read_password() -> str:
    """The secret, from the environment or from a terminal -- never from a command line.

    Deliberately not an argument to this script either. An example that took ``sys.argv[2]``
    as a password would be teaching the exact habit the library exists to replace: it would
    show up in the reader's shell history and in ``ps`` output for every user on the box.
    """
    from_environment = os.environ.get(PASSWORD_VARIABLE)
    if from_environment:
        return from_environment
    if not sys.stdin.isatty():
        raise SystemExit(
            f"no terminal to prompt on: set {PASSWORD_VARIABLE} in the environment instead"
        )
    return getpass.getpass("password: ")


def dumped_frames(error: BaseException) -> str:
    """Render *the library's* frame locals the way a traceback reporter would.

    The surface nobody looks at. Sentry captures frame locals by default, and so do
    ``pytest --showlocals``, ``rich`` tracebacks and IPython's verbose mode -- all of them by
    calling ``repr()`` on every local. The environment dictionary carrying the secret is a
    local in an ``@asynccontextmanager`` generator, so its frame is alive for the whole
    connection and lands in exactly that dump.

    Only ``gantry_sftp``'s own frames are rendered, and the boundary is the point rather than
    a convenience: *this* function's caller holds the plaintext in a local called ``secret``
    and always will, because it is the thing being passed in. What the library controls is
    what happens to it afterwards -- and after it crosses the boundary it is only ever held in
    a form that does not render itself.
    """
    package = str(Path(gantry_sftp.__file__).parent)
    rendered = []
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.startswith(package):
            rendered += [f"{name}={value!r}" for name, value in frame.f_locals.items()]
        traceback = traceback.tb_next
    return "\n".join(rendered)


def show_what_the_password_path_changes() -> None:
    """Print the option deltas, read from the library rather than retyped."""
    print("the shipped default makes password auth impossible:")
    print(f"  BatchMode={DEFAULT_SSH_OPTIONS['BatchMode']}   <- suppresses ssh's askpass helper")
    print()
    print("what password= sends instead:")
    for name, value in PASSWORD_AUTH_OPTIONS.items():
        print(f"  {name}={value}")
    print()


async def refused_by_open_ssh_transport(secret: str, port: int) -> ConnectError:
    """Fail a connection through the two-call spelling, and hand back its error."""
    connected = None
    try:
        async with (
            open_ssh_transport(
                "127.0.0.1",
                port=port,
                config_file=os.devnull,
                password=secret,
            ) as transport,
            open_session(transport) as sftp,
        ):
            connected = repr(sftp)
    except ConnectError as error:
        return error
    raise SystemExit(f"unexpectedly connected: {connected}")


async def refused_by_connect(secret: str, port: int) -> ConnectError:
    """The same failure through ``connect()``, which binds the password in a frame of its own.

    **Running both is the point, not thoroughness.** ``password=`` is a parameter of each entry
    point, and each holds its own binding for as long as the caller's block lasts -- so a
    version of this example that exercised only the inner one checked the frame claim on the
    single path where it was already true, and the path the README opens with rendered the
    plaintext. Wrapping in one function protects that function's local and no other.
    """
    connected = None
    try:
        async with gantry_sftp.connect(
            "127.0.0.1",
            port=port,
            config_file=os.devnull,
            password=secret,
        ) as sftp:
            connected = repr(sftp)
    except ConnectError as error:
        return error
    raise SystemExit(f"unexpectedly connected: {connected}")


def report_where_the_secret_went(label: str, secret: str, error: ConnectError) -> None:
    """The three checks this example exists to make, for one entry point.

    ``ps`` shows argv to every user on the machine; it never shows the password, because the
    password was never there. The third line is the one nobody looks at, and it is the one that
    needs a per-entry-point answer rather than a single global one.
    """
    print(f"  via {label}")
    print(f"    password anywhere in argv:      {secret in ' '.join(error.argv)}")
    print(f"    password anywhere in the error: {secret in str(error)}")
    print(f"    password in any dumped frame:   {secret in dumped_frames(error)}")


async def against_a_closed_port() -> None:
    """Spawn a real ssh with a real password and show where the secret ended up.

    Nothing listens on the port, so this fails at the connection rather than at
    authentication -- which is all this needs. The question being answered is what was on the
    command line, and that is decided before a single packet is sent.
    """
    secret = "hunter2-not-a-real-password"
    port = closed_port()
    show_what_the_password_path_changes()

    through_transport = await refused_by_open_ssh_transport(secret, port)
    through_connect = await refused_by_connect(secret, port)

    print("the command that actually ran:")
    print(f"  {' '.join(through_transport.argv)}")
    print()
    report_where_the_secret_went("open_ssh_transport()", secret, through_transport)
    report_where_the_secret_went("connect()", secret, through_connect)
    print()
    print(f"and the connection failed for its own reason: {type(through_transport).__name__}")
    for line in (through_transport.stderr or "(nothing)").strip().splitlines():
        print(f"    | {line}")


async def against_a_real_server(destination: str) -> None:
    """Authenticate to a real endpoint and list its working directory."""
    user, _, host = destination.rpartition("@")
    password = read_password()

    try:
        async with (
            open_ssh_transport(host, user=user or None, password=password) as transport,
            open_session(transport) as sftp,
        ):
            print(f"connected: {sftp!r}")
            cwd = await sftp.realpath(b".")
            print(f"realpath('.'): {cwd.decode('utf-8', 'replace')}")
            print(f"entries:       {len(await sftp.listdir(cwd))}")
    except AuthenticationError as error:
        print(f"authentication was refused: {error.stderr.strip()}")
        # Empty whenever we did answer the prompt -- which means the password was simply
        # wrong, and saying anything more would be a guess.
        if error.hint:
            print(f"hint: {error.hint}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    if destination is None:
        print("no host given -- showing what password= does with the secret\n")
        await against_a_closed_port()
    else:
        await against_a_real_server(destination)


if __name__ == "__main__":
    anyio.run(main)

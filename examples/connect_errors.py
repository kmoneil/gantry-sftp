"""Why the connection failed, answered by an exception class instead of a substring search.

    python examples/connect_errors.py                  # a refused connection and a missing
                                                       # ssh client -- no network either way
    python examples/connect_errors.py user@host        # against a real server over ssh

paramiko answers this question with ``Error reading SSH protocol banner``. OpenSSH knew exactly
what went wrong and said so on stderr; this library passes that through untouched *and* types
the common cases, so the two questions people actually ask -- "was that my key?" and "has the
host changed?" -- are answered by ``except`` rather than by string matching in your own code.

The ladder below is the whole API. Order it most-specific-first, as always:

    AuthenticationError   -- credentials refused
    HostKeyError          -- the server's identity was not accepted
    ConnectError          -- everything else, with OpenSSH's stderr verbatim

``ConnectError`` is not a fallback that means "we gave up". It is the honest answer whenever
the stderr does not positively establish one of the other two -- a refused connection, a name
that will not resolve, a cipher mismatch. A class that sometimes means "we guessed" would be
worth less than one that always means what it says.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import textwrap
from pathlib import Path

import anyio

from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError
from gantry_sftp.session import open_session
from gantry_sftp.transport import open_ssh_transport


def closed_port() -> int:
    """A port with nothing listening on it, so the no-arguments run has something to fail on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def report(error: ConnectError) -> None:
    """Print the diagnosis the way a caller would branch on it."""
    if isinstance(error, AuthenticationError):
        headline = "authentication was refused -- check the key or the username"
    elif isinstance(error, HostKeyError):
        # Worth its own branch even in an example: this is the one that may be interception,
        # and "just retry" is the wrong reflex.
        headline = "the host's identity was NOT accepted -- do not retry blindly"
    else:
        headline = "the connection failed for a reason we do not classify"

    print(f"  class:    {type(error).__name__}")
    print(f"  meaning:  {headline}")
    print(f"  exit:     {error.returncode}")
    print("  ssh said:")
    for line in (error.stderr or "(nothing)").strip().splitlines():
        print(f"    | {line}")

    # The hint is ours rather than OpenSSH's, and it is empty for most failures -- it is set
    # only where our own configuration or environment made the failure inevitable. Printing it
    # unconditionally would teach the wrong shape, so branch on it the way a caller should.
    if error.hint:
        print("  and we can add:")
        for line in textwrap.wrap(error.hint, width=76):
            print(f"    > {line}")


async def missing_ssh_client() -> None:
    """Show the failure that needs no network, no server and no credentials.

    This is the one most likely to be somebody's first experience of the library, because the
    requirement is satisfied on every developer machine and absent from most slim container
    images: it passes locally and fails on first deploy. ``could not run ...`` on its own is
    diagnosable only by a reader who already knows the answer, so the hint is the whole fix.
    """
    print("pointing ssh_executable at something that does not exist")
    nowhere = Path(tempfile.gettempdir()) / "gantry-sftp-no-such-ssh"
    try:
        async with open_ssh_transport("example.com", ssh_executable=str(nowhere)):
            print("  unexpectedly connected")
    except ConnectError as error:
        report(error)


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None

    if destination is None:
        # No host given: connect to a port with nothing on it. Real ssh, real failure, no
        # network and no credentials -- and it demonstrates the ConnectError case, which is
        # the one people hit most and understand least.
        print("connecting to a closed port on 127.0.0.1")
        opener = open_ssh_transport(
            "127.0.0.1",
            port=closed_port(),
            config_file=os.devnull,
            options={"BatchMode": "yes", "StrictHostKeyChecking": "yes"},
        )
    else:
        user, _, host = destination.rpartition("@")
        print(f"connecting to {host}")
        opener = open_ssh_transport(host, user=user or None)

    try:
        async with opener as transport, open_session(transport) as sftp:
            print(f"connected: {sftp!r}")
    except ConnectError as error:
        report(error)
    else:
        print("no error to report")

    if destination is None:
        # Second case, and the one worth showing even though it looks trivial: it is the
        # failure a reader is most likely to meet first, and the only one where the hint is
        # the entire diagnosis because there is no stderr to read.
        print()
        await missing_ssh_client()


if __name__ == "__main__":
    anyio.run(main)

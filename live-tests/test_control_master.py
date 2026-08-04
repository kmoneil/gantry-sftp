"""`ControlMaster=no` ships, and what that costs a reader is the whole point of this file.

`DEFAULT_SSH_OPTIONS` puts `ControlMaster=no` on every command line, and a command-line `-o`
beats the user's `ssh_config`. That is one option and two separate consequences, and until this
file existed only the first was measured -- `ssh -G` shows the resolution, and nothing showed
what the connection then did.

The claim `docs/connecting.md` makes has three parts, so there are three tests. An existing
master **is** used, because `ControlPath` is untouched. This library will **not** create one, so
a config line on its own buys nothing. And `options={"ControlMaster": "auto"}` opts back in.

`ssh -G` cannot answer any of those: it prints what the options resolve to and never opens a
connection, so "controlmaster false" is consistent both with reuse working and with it being
broken. What separates them is whether `sshd` saw a second authentication, which is why these
tests read the server's log rather than the client's opinion of itself.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import anyio
import pytest
from sshd import SSHServer, scrubbed_ssh_env

from conftest import connect
from gantry_sftp.session import open_session

pytestmark = pytest.mark.anyio


def authentications(server: SSHServer) -> int:
    """How many times `sshd` has accepted a login since it started.

    The server runs at ``LogLevel VERBOSE`` and logs one ``Accepted publickey`` per *network*
    connection. A session reaching it down an existing master's socket is not a new network
    connection and produces no such line, which is what makes this the instrument: it counts the
    thing multiplexing is supposed to avoid, from the far side, rather than asking the client
    whether it thinks it multiplexed.
    """
    log = (server.root / "sshd.log").read_text(encoding="utf-8", errors="replace")
    return log.count("Accepted publickey")


def control_path(tmp_path: Path) -> Path:
    """A socket path for one test.

    Short by construction. A `ControlPath` is a Unix socket path and therefore bounded by
    ``sun_path`` -- 108 bytes on Linux -- and pytest's ``tmp_path`` under a long temp root plus
    the ``%r@%h:%p`` expansion gets close enough that a test named for something else starts
    failing on path length. `ssh` reports that as a plain refusal to multiplex, which reads as
    this library's fault.
    """
    return tmp_path / "cm"


def start_master(server: SSHServer, socket_path: Path) -> subprocess.Popen[bytes]:
    """A backgrounded `ssh` master holding a connection open at `socket_path`.

    ``-N`` runs no command and ``-M`` makes it the master. It is *not* ``-f``: staying in the
    foreground as a child of this process is what lets the test kill it deterministically
    instead of hunting a pid, and a leaked master would be seen by every later test in the
    session through the shared ``ssh_server``.
    """
    return subprocess.Popen(
        [
            "ssh",
            "-N",
            "-M",
            "-S",
            str(socket_path),
            "-F",
            os.devnull,
            "-p",
            str(server.port),
            "-i",
            str(server.identity_file),
            "-o",
            f"UserKnownHostsFile={server.known_hosts}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"GlobalKnownHostsFile={os.devnull}",
            "--",
            "127.0.0.1",
        ],
        env=scrubbed_ssh_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_for_socket(socket_path: Path, process: subprocess.Popen[bytes]) -> None:
    """Block until the master is listening, or fail saying which way it went wrong.

    Polling the path rather than sleeping, because the two failures are different: a master that
    died has an exit code and a master that is slow has not created the socket yet. Sleeping a
    fixed interval reports both as "no multiplexing", which is the same symptom as the bug these
    tests exist to catch.
    """
    for _ in range(200):
        if socket_path.exists():
            return
        assert process.poll() is None, (
            f"the ssh master exited {process.returncode} before it began listening"
        )
        # A plain blocking sleep: this runs before any transfer starts and waits on another
        # process, so there is nothing for an event loop to do meanwhile.
        time.sleep(0.05)
    raise AssertionError(f"the ssh master never created {socket_path}")


async def test_an_existing_master_is_reused_because_controlpath_is_untouched(
    ssh_server: SSHServer, tmp_path: Path
) -> None:
    """The half of the claim that `ssh -G` cannot reach.

    `ControlMaster=no` declines to *become* a master and says nothing about using one. If the
    shipped default also suppressed reuse -- which is what a reader would reasonably fear on
    seeing it -- then every connection here would authenticate again and the count would climb.
    """
    socket_path = control_path(tmp_path)
    master = start_master(ssh_server, socket_path)
    try:
        wait_for_socket(socket_path, master)
        after_master = authentications(ssh_server)
        assert after_master >= 1, "the master itself did not authenticate; the fixture is broken"

        for _ in range(3):
            async with (
                connect(ssh_server, options={"ControlPath": str(socket_path)}) as transport,
                open_session(transport) as sftp,
            ):
                await sftp.realpath(b".")

        assert authentications(ssh_server) == after_master, (
            "sshd saw a new authentication, so the transfers did not go down the existing "
            "master -- docs/connecting.md claims ControlPath is untouched by ControlMaster=no"
        )
    finally:
        master.terminate()
        master.wait(timeout=10)


async def test_this_library_does_not_start_a_master_of_its_own(
    ssh_server: SSHServer, tmp_path: Path
) -> None:
    """The consequence a reader pays for, and the reason the docs had to change.

    A `ControlPath` with no master behind it is exactly the state somebody is in after setting
    `ControlMaster auto` in their `ssh_config` and running only this library: the socket is
    never created, so connection two has nothing to reuse and the config line bought nothing.
    """
    socket_path = control_path(tmp_path)
    before = authentications(ssh_server)

    for _ in range(2):
        async with (
            connect(ssh_server, options={"ControlPath": str(socket_path)}) as transport,
            open_session(transport) as sftp,
        ):
            await sftp.realpath(b".")

    assert not socket_path.exists(), (
        f"{socket_path} exists, so this library became a multiplexing master -- "
        "DEFAULT_SSH_OPTIONS ships ControlMaster=no precisely so it does not"
    )
    assert authentications(ssh_server) == before + 2, (
        "two connections should be two authentications when no master exists"
    )


async def test_asking_for_a_master_gets_one(ssh_server: SSHServer, tmp_path: Path) -> None:
    """The third state, and the one that makes the other two a decision rather than a limit.

    Without this the pair above is equally consistent with multiplexing being unreachable from
    this library, which would be a defect rather than a default. `options=` overrides by name, so
    the shipped value is *replaced* rather than joined -- there is no repeated `-o` here for
    `ssh`'s first-wins rule to resolve.
    """
    socket_path = control_path(tmp_path)
    before = authentications(ssh_server)

    async with (
        connect(
            ssh_server,
            options={
                "ControlPath": str(socket_path),
                "ControlMaster": "auto",
                "ControlPersist": "5",
            },
        ) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.realpath(b".")

    try:
        assert socket_path.exists(), (
            "options={'ControlMaster': 'auto'} did not produce a master, so the documented "
            "opt-in does not work"
        )
        async with (
            connect(ssh_server, options={"ControlPath": str(socket_path)}) as transport,
            open_session(transport) as sftp,
        ):
            await sftp.realpath(b".")
        assert authentications(ssh_server) == before + 1, (
            "the second connection authenticated, so it did not reuse the master this test made"
        )
    finally:
        # `anyio.run_process` rather than `subprocess.run`: this is an async test, and a blocking
        # wait here stalls the whole event loop for however long the master takes to go.
        await anyio.run_process(
            ["ssh", "-O", "exit", "-S", str(socket_path), "-F", os.devnull, "--", "127.0.0.1"],
            env=scrubbed_ssh_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

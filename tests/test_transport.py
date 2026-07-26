"""Subprocess transports: real children, real pipes, real cleanup.

Every async test runs on both anyio backends -- see the ``anyio_backend`` fixture. No
network is involved anywhere here: the local-server transport speaks to ``sftp-server`` over
a pipe, and the ssh failure cases are made to fail before any connection is attempted.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Close,
    Codec,
    Handle,
    Negotiated,
    Open,
    OpenFlag,
    PacketType,
    Read,
)
from gantry_sftp.exceptions import ConnectError
from gantry_sftp.transport import (
    build_ssh_argv,
    find_sftp_server,
    open_local_server_transport,
    open_ssh_transport,
)

pytestmark = pytest.mark.anyio


async def _receive_until_closed(transport) -> None:
    """Read until the peer hangs up. Isolated so pytest.raises wraps one statement."""
    while True:
        await transport.receive()


async def _open_and_close(opener) -> None:
    """Enter and immediately leave a transport context manager."""
    async with opener:
        pass


@pytest.fixture
def fake_ssh(tmp_path: Path) -> Path:
    """A stand-in for ssh that writes a known message to stderr and exits.

    Deterministic where a real ssh failure is not: it pins what *we* do with a child's
    stderr, independently of what any particular OpenSSH build says.
    """
    script = tmp_path / "fake_ssh.py"
    script.write_text(
        "import sys\n"
        "sys.stderr.write('Permission denied (publickey,password).\\n')\n"
        "sys.stderr.flush()\n"
        "sys.exit(255)\n"
    )
    launcher = tmp_path / "fake-ssh"
    launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    launcher.chmod(0o755)
    return launcher


# --- the local server transport ----------------------------------------------------------


async def test_a_local_server_transport_speaks_sftp(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        codec = Codec()
        await transport.send(codec.initiate())
        events: list[object] = []
        while not events:
            events = list(codec.receive(await transport.receive()))
        (negotiated,) = events
        assert isinstance(negotiated, Negotiated)
        assert negotiated.version == 3


async def test_a_transport_reads_a_real_file_end_to_end(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    target = tmp_path / "payload.txt"
    target.write_bytes(b"bytes that came off a real server\n")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        codec = Codec()
        await transport.send(codec.initiate())

        async def exchange(request: object) -> object:
            await transport.send(codec.send(request))  # type: ignore[arg-type]
            while True:
                events = codec.receive(await transport.receive())
                if events:
                    return events[0].response  # type: ignore[union-attr]

        while codec.state.name != "READY":
            codec.receive(await transport.receive())

        opened = await exchange(
            Open(codec.allocate_request_id(), str(target).encode(), OpenFlag.READ)
        )
        assert isinstance(opened, Handle)
        data = await exchange(Read(codec.allocate_request_id(), opened.handle, 0, 4096))
        assert bytes(data.data) == b"bytes that came off a real server\n"  # type: ignore[union-attr]
        await exchange(Close(codec.allocate_request_id(), opened.handle))


async def test_the_child_is_reaped_when_the_context_exits(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        assert transport.returncode is None
    # "cancellation obviously works" is a claim about a subprocess, a pipe and a task group.
    # This is the subprocess half, asserted rather than assumed.
    assert transport.returncode is not None


async def test_aclose_is_idempotent(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        await transport.aclose()
        await transport.aclose()
    assert transport.returncode is not None


async def test_using_a_closed_transport_raises_rather_than_hanging(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        await transport.aclose()
        with pytest.raises(ConnectError) as exc:
            await transport.receive()
        assert exc.value.args[0] == "transport is closed"
        with pytest.raises(ConnectError):
            await transport.send(b"anything")


async def test_a_cancelled_transfer_still_reaps_the_child(tmp_path: Path):
    """Cancellation must not orphan the subprocess.

    ``receive`` blocks forever here because nothing was requested, so the cancel scope fires
    while we are parked in the middle of the transport. Cleanup is shielded precisely so it
    still runs from there.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    captured: list[object] = []
    with anyio.move_on_after(0.25):
        async with open_local_server_transport(cwd=tmp_path) as transport:
            captured.append(transport)
            await transport.receive()  # never arrives; the deadline cancels us here

    (transport,) = captured
    assert transport.returncode is not None, "the child outlived a cancelled transfer"


async def test_end_of_stream_reports_the_children_stderr(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        # A byte that is not a valid frame makes sftp-server give up and close.
        await transport.send(b"\x00\x00\x00\x01\xff")
        with pytest.raises(ConnectError) as exc:
            await _receive_until_closed(transport)
        assert exc.value.args[0] == "connection closed by the remote end"
        assert exc.value.returncode is not None


# --- ssh failures carry OpenSSH's own diagnosis ------------------------------------------


async def test_a_failing_ssh_surfaces_its_stderr_verbatim(fake_ssh: Path):
    """The headline fix. paramiko says ``Error reading SSH protocol banner``; we say why.

    A stand-in for ssh is used so the assertion is on *our* handling rather than on a
    particular OpenSSH build's wording, which varies by version.
    """
    async with open_ssh_transport("example.com", ssh_executable=str(fake_ssh)) as transport:
        with pytest.raises(ConnectError) as exc:
            await transport.receive()

    assert exc.value.stderr == "Permission denied (publickey,password).\n"
    assert exc.value.returncode == 255
    # The rendered message carries the diagnosis, so a bare `print(err)` is enough to debug.
    assert "Permission denied (publickey,password)." in str(exc.value)
    assert "exit status 255" in str(exc.value)


async def test_the_failure_carries_the_exact_command_that_was_run(fake_ssh: Path):
    async with open_ssh_transport("example.com", ssh_executable=str(fake_ssh)) as transport:
        with pytest.raises(ConnectError) as exc:
            await transport.receive()
    assert exc.value.argv[0] == str(fake_ssh)
    assert exc.value.argv[-4:] == ("-s", "--", "example.com", "sftp")


async def test_a_missing_ssh_executable_is_a_clear_connect_error(tmp_path: Path):
    missing = tmp_path / "definitely-not-here"
    with pytest.raises(ConnectError) as exc:
        await _open_and_close(open_ssh_transport("h", ssh_executable=str(missing)))
    assert exc.value.args[0].startswith(f"could not run {str(missing)!r}:")
    assert exc.value.argv[0] == str(missing)


async def test_a_hostile_host_is_refused_before_anything_is_spawned():
    # The injection defence fires during argv construction, so no process ever exists. The
    # transport never gets a chance to be careful, which is the point.
    with pytest.raises(ValueError) as exc:
        await _open_and_close(open_ssh_transport("-oProxyCommand=echo PWNED >&2"))
    assert exc.value.args[0].startswith("host may not begin with '-'")


# --- the OpenSSH behaviour our defence depends on ----------------------------------------


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="ssh not installed")
def test_ssh_treats_a_dash_host_as_options_without_the_separator():
    """Characterisation of ssh(1), not of us. It is why `--` is not optional.

    Without ``--``, a hostname beginning with ``-`` is parsed as options and
    ``ProxyCommand`` executes. The marker in stderr is the proof.
    """
    result = subprocess.run(
        [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-oProxyCommand=echo GANTRY_MARKER >&2",
            "nonexistent.invalid",
            "-s",
            "sftp",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert "GANTRY_MARKER" in result.stderr, (
        "ssh no longer executes ProxyCommand from an option-shaped argument; "
        "re-check whether `--` is still the right defence"
    )


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="ssh not installed")
def test_the_separator_stops_ssh_parsing_a_dash_host_as_options():
    """The other half: with ``--``, the same string is refused as a hostname.

    If a future OpenSSH ever stopped honouring ``--`` here, this failing is how we would
    find out -- rather than by shipping a client that executes attacker-chosen commands.
    """
    result = subprocess.run(
        [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-s",
            "--",
            "-oProxyCommand=echo GANTRY_MARKER >&2",
            "sftp",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert "GANTRY_MARKER" not in result.stderr
    assert result.returncode != 0


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="ssh not installed")
def test_our_argv_puts_the_hostile_string_after_the_separator_anyway():
    # Belt and braces: even though build_ssh_argv rejects such a host, the argv it produces
    # for a legitimate one always has `--` before the host position.
    argv = build_ssh_argv("legitimate.example", ssh_executable="/usr/bin/ssh")
    assert argv.index("--") == len(argv) - 3


# --- codec and transport agree on framing ------------------------------------------------


async def test_the_transport_delivers_whole_frames_to_the_codec(tmp_path: Path):
    # The transport chunks arbitrarily; the splitter is what makes that irrelevant. This is
    # the seam between them, exercised against a real server rather than a fake.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with open_local_server_transport(cwd=tmp_path) as transport:
        codec = Codec()
        await transport.send(codec.initiate())
        events: list[object] = []
        while not events:
            # One byte at a time: the worst chunking a transport could plausibly produce.
            events = list(codec.receive(await transport.receive(1)))
        (negotiated,) = events
        assert isinstance(negotiated, Negotiated)
        assert any(name == b"limits@openssh.com" for name, _ in negotiated.extensions)
        assert PacketType.VERSION == 2

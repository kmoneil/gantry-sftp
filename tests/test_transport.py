"""Subprocess transports: real children, real pipes, real cleanup.

Every async test runs on both anyio backends -- see the ``anyio_backend`` fixture. No
network is involved anywhere here: the local-server transport speaks to ``sftp-server`` over
a pipe, and the ssh failure cases are made to fail before any connection is attempted.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import anyio
import pytest

import gantry_sftp
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
from gantry_sftp.exceptions import ConnectError, flatten_exception_group
from gantry_sftp.transport import (
    ASKPASS_ARMING_VARIABLES,
    StderrBuffer,
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


# --- stderr is captured, but not without limit -------------------------------------------


def test_stderr_under_the_cap_is_kept_exactly():
    buffer = StderrBuffer(head_limit=16, tail_limit=16)
    buffer.extend(b"Permission denied\n")
    assert buffer.text() == "Permission denied\n"
    assert buffer.dropped == 0


def test_stderr_beyond_the_cap_keeps_both_ends():
    # OpenSSH puts the decisive line last and the banner first, so a buffer that keeps only
    # one end throws away either the answer or the context.
    buffer = StderrBuffer(head_limit=10, tail_limit=10)
    buffer.extend(b"HEAD______" + b"x" * 500 + b"______TAIL")
    text = buffer.text()
    assert text.startswith("HEAD______")
    assert text.endswith("______TAIL")
    assert buffer.dropped == 500


def test_the_omission_is_announced_rather_than_silent():
    # Silently truncated diagnostics are how people conclude the tool is lying to them.
    buffer = StderrBuffer(head_limit=4, tail_limit=4)
    buffer.extend(b"AAAA" + b"m" * 20 + b"ZZZZ")
    assert "[20 bytes of stderr omitted]" in buffer.text()


def test_stderr_stays_bounded_however_much_arrives():
    # `ssh -vvv` on a transfer that runs for hours is the trigger this exists for.
    buffer = StderrBuffer(head_limit=1024, tail_limit=1024)
    for _ in range(2000):
        buffer.extend(b"debug1: a line of quite verbose ssh debugging output\n")
    assert len(buffer.text()) < 4096
    assert buffer.dropped > 0


def test_stderr_arriving_one_byte_at_a_time_is_reassembled():
    buffer = StderrBuffer(head_limit=8, tail_limit=8)
    for byte in b"0123456789ABCDEF":
        buffer.extend(bytes([byte]))
    assert buffer.text() == "0123456789ABCDEF"


def test_stderr_that_is_not_utf8_does_not_raise():
    # A stray byte in a banner must not turn an authentication failure into a
    # UnicodeDecodeError about the message that was explaining it.
    buffer = StderrBuffer()
    buffer.extend(b"Permission denied \xff\xfe\n")
    assert "Permission denied" in buffer.text()


async def test_a_chatty_child_does_not_grow_the_transport_without_bound(tmp_path: Path):
    noisy = tmp_path / "noisy.py"
    noisy.write_text(
        "import sys\n"
        "for n in range(20000):\n"
        "    sys.stderr.write('debug1: chatter %d\\n' % n)\n"
        "sys.stderr.flush()\n"
        "sys.exit(3)\n"
    )
    launcher = tmp_path / "noisy-ssh"
    launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{noisy}" "$@"\n')
    launcher.chmod(0o755)

    async with open_ssh_transport("example.com", ssh_executable=str(launcher)) as transport:
        with pytest.raises(ConnectError) as exc:
            await _receive_until_closed(transport)

    # Well under what the child actually wrote, and still containing both ends.
    assert len(exc.value.stderr) < 128 * 1024
    assert "debug1: chatter 0\n" in exc.value.stderr
    assert "debug1: chatter 19999" in exc.value.stderr
    assert "bytes of stderr omitted" in exc.value.stderr


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


async def test_the_password_never_reaches_a_dumped_stack_frame(tmp_path: Path):
    """A traceback reporter that captures locals must not capture the secret.

    Keeping the password out of argv is two thirds of the job. ``open_ssh_transport`` and
    ``_open_process_transport`` are ``@asynccontextmanager`` generators, so their frames --
    and the environment dictionary in them -- stay alive for the whole connection, and a
    reporter that walks frame locals renders every one of them with ``repr``. Sentry does
    that by default; so do ``pytest --showlocals``, ``rich`` and IPython.

    The walk below is exactly what those reporters do.
    """
    canary = "hunter2-CANARY-must-not-appear"
    missing = tmp_path / "definitely-not-here"

    with pytest.raises(ConnectError) as exc:
        await _open_and_close(open_ssh_transport("h", ssh_executable=str(missing), password=canary))

    # The surfaces a caller sees directly.
    assert canary not in str(exc.value)
    assert canary not in repr(exc.value)
    assert not any(canary in argument for argument in exc.value.argv)

    # And the one they see through a reporter. Only *this library's* frames are asserted on:
    # the caller's own frame holds the plaintext they passed in and always will, which is
    # their boundary to draw, not ours.
    # Taken from the package, not from `open_ssh_transport.__globals__`: the name is the
    # wrapper `asynccontextmanager` built, so its globals are contextlib's and a filter built
    # from them silently matches nothing -- a test that passes because it looked nowhere.
    package = str(Path(gantry_sftp.__file__).parent)
    leaks: list[str] = []
    traceback = exc.value.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.startswith(package):
            leaks += [
                f"{Path(frame.f_code.co_filename).name}:{traceback.tb_lineno} "
                f"in {frame.f_code.co_name}() local {name!r}"
                for name, value in frame.f_locals.items()
                if canary in repr(value)
            ]
        traceback = traceback.tb_next
    assert leaks == [], "password rendered by a frame-locals dump: " + "; ".join(leaks)


async def test_the_child_still_receives_the_real_secret(tmp_path: Path):
    """The redaction must not have redacted it on the way to ``ssh`` as well.

    A guard on the fix rather than on the bug: a ``repr`` that hides the password is only
    correct while the password still arrives intact, and a mistake in that direction would
    look exactly like a server rejecting the credential.
    """
    canary = "hunter2-CANARY-must-arrive"
    recorder = tmp_path / "recorder"
    seen = tmp_path / "seen.txt"
    recorder.write_text(
        f'#!/bin/sh\nprintf "%s" "${{GANTRY_SFTP_ASKPASS_ANSWER}}" > "{seen}"\nexit 255\n'
    )
    recorder.chmod(0o700)

    async with open_ssh_transport("h", ssh_executable=str(recorder), password=canary) as transport:
        with pytest.raises(ConnectError):
            await transport.receive()

    assert seen.read_text() == canary


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


# --- the transport must not leak an ExceptionGroup ----------------------------------------
#
# Regression tests for the exception-group leak found while writing examples/connect_errors.py:
# the stderr drain runs in an anyio task group, and anyio wraps *even a single* exception on
# the way out of one. So anything the caller's body raised came back as an ExceptionGroup, and
# `except ConnectError` placed outside the `async with` -- the natural spelling, and the one
# the README and every example use -- silently never matched. Both tests below fail without
# the unwrap in `_open_process_transport`.


class MarkerError(Exception):
    """A caller's own exception, to prove the unwrap is not specific to our hierarchy."""


async def test_an_exception_from_the_body_escapes_the_transport_unwrapped(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    with pytest.raises(MarkerError) as exc:
        async with open_local_server_transport(cwd=tmp_path):
            raise MarkerError("from the body")

    assert not isinstance(exc.value, BaseExceptionGroup)
    assert exc.value.args[0] == "from the body"


async def test_a_connect_error_is_catchable_outside_the_async_with(tmp_path: Path):
    """The shape users actually write, and the one that was broken.

    `pytest.raises` *inside* the `async with` passed the whole time, which is why the live
    tests never caught this -- they all had it inside.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async def receive_after_closing() -> None:
        async with open_local_server_transport(cwd=tmp_path) as transport:
            await transport.aclose()
            # The transport is now closed, so this raises ConnectError from inside the body
            # and has to cross the task-group boundary to reach the handler below.
            _ = await transport.receive()

    with pytest.raises(ConnectError) as exc:
        await receive_after_closing()

    assert not isinstance(exc.value, BaseExceptionGroup)
    assert exc.value.args[0] == "transport is closed"


async def test_the_group_is_flattened_all_the_way_down():
    # A task group inside a task group nests the groups, so one level of unwrapping is not
    # enough. Asserted on the helper directly: constructing the nesting through real
    # transports would be theatre, and the property is about the unwrapper.
    inner = ConnectError("the real one")
    nested = BaseExceptionGroup("outer", [BaseExceptionGroup("inner", [inner])])
    assert flatten_exception_group(nested) is inner


def test_flattening_leaves_a_plain_exception_alone():
    error = ConnectError("not a group")
    assert flatten_exception_group(error) is error


# --- passwords: where the secret goes, and what a refusal says ----------------------------

SECRET = "correct-horse-battery-staple"


def askpass_directories() -> set[Path]:
    """Temporary directories the askpass helper has left behind, if any."""
    return set(Path(tempfile.gettempdir()).glob("gantry-sftp-askpass-*"))


@pytest.fixture
def no_askpass_in_the_environment(monkeypatch):
    """Unset everything that would arm an askpass helper, and prove it is unset.

    A developer with `DISPLAY` set inherits a machine on which ssh *would* run a helper, and
    the hint below is deliberately suppressed in that case -- so without this fixture these
    tests pass or fail according to whose laptop they run on.
    """
    for name in ASKPASS_ARMING_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name in ASKPASS_ARMING_VARIABLES:
        assert name not in os.environ, f"{name} is still set"


async def test_a_password_never_reaches_argv(fake_ssh: Path):
    """The reason this feature exists at all.

    ``sshpass -p secret`` puts the credential in argv, where ``/proc/<pid>/cmdline`` makes it
    readable by every user on the machine. Nothing this library spawns may do that, and argv
    is captured on the exception, so the assertion covers the bug report too.
    """
    async with open_ssh_transport(
        "example.com", ssh_executable=str(fake_ssh), password=SECRET
    ) as transport:
        assert SECRET not in repr(transport)
        assert SECRET not in " ".join(transport.argv)
        with pytest.raises(ConnectError) as exc:
            await transport.receive()

    assert SECRET not in " ".join(exc.value.argv)
    assert SECRET not in str(exc.value)
    assert SECRET not in exc.value.stderr
    assert SECRET not in exc.value.hint


async def test_the_password_path_relaxes_batchmode_in_the_command_it_actually_runs(
    fake_ssh: Path,
):
    async with open_ssh_transport(
        "example.com", ssh_executable=str(fake_ssh), password=SECRET
    ) as transport:
        assert "BatchMode=no" in transport.argv
        assert "BatchMode=yes" not in transport.argv


async def test_the_helper_does_not_outlive_the_connection(fake_ssh: Path):
    # A credential-adjacent temporary file surviving a failed connection is the leak this
    # design exists to avoid, and the failure path is the one nobody watches.
    before = askpass_directories()
    async with open_ssh_transport(
        "example.com", ssh_executable=str(fake_ssh), password=SECRET
    ) as transport:
        with pytest.raises(ConnectError):
            await transport.receive()
    assert askpass_directories() == before


async def test_a_password_that_could_answer_two_prompts_is_refused_before_spawning():
    # Validation happens before any process exists, so a rejected password cannot leave a
    # child, a helper or a directory behind.
    before = askpass_directories()
    with pytest.raises(ValueError) as exc:
        await _open_and_close(open_ssh_transport("example.com", password="two\nlines"))
    assert exc.value.args[0].startswith("password may not contain '\\n';")
    assert askpass_directories() == before


async def test_a_password_with_an_explicit_batchmode_yes_is_refused_before_spawning():
    with pytest.raises(ValueError) as exc:
        await _open_and_close(
            open_ssh_transport("example.com", password=SECRET, options={"BatchMode": "yes"})
        )
    assert exc.value.args[0].startswith("password= needs BatchMode=no,")


async def test_a_refusal_under_the_shipped_defaults_says_which_option_disabled_the_password(
    fake_ssh: Path, no_askpass_in_the_environment
):
    """The gap D-78 was filed for, end to end.

    The stderr names the methods the *server* offers and says nothing about the one this
    client switched off. Without the hint the reader is sent to check their password, which
    was never sent.
    """
    async with open_ssh_transport("example.com", ssh_executable=str(fake_ssh)) as transport:
        with pytest.raises(ConnectError) as exc:
            await transport.receive()

    assert "BatchMode=yes suppresses the askpass helper outright" in exc.value.hint
    # Rendered too: a bare `print(err)` has to be enough, which is the whole standard the
    # stderr passthrough set.
    assert "hint: " in str(exc.value)
    assert exc.value.hint in str(exc.value)


async def test_a_password_connection_that_is_refused_gets_no_hint(
    fake_ssh: Path, no_askpass_in_the_environment
):
    # We answered the prompt. Why the server still said no is not something this client
    # knows, and a hint that guesses is worse than none.
    async with open_ssh_transport(
        "example.com", ssh_executable=str(fake_ssh), password=SECRET
    ) as transport:
        with pytest.raises(ConnectError) as exc:
            await transport.receive()
    assert exc.value.hint == ""
    assert "hint: " not in str(exc.value)


async def test_a_caller_supplied_askpass_suppresses_the_hint(fake_ssh: Path, monkeypatch):
    # Arming it by hand is the documented pre-`password=` recipe and still works. Telling
    # somebody who did that they had "no way to answer the prompt" would be a wrong answer.
    monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")
    async with open_ssh_transport("example.com", ssh_executable=str(fake_ssh)) as transport:
        with pytest.raises(ConnectError) as exc:
            await transport.receive()
    assert exc.value.hint == ""


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="ssh not installed")
def test_ssh_matches_option_names_case_insensitively_and_takes_the_first():
    """Characterisation of ssh(1), not of us. It is why option merging folds case.

    Two facts, and the bug needed both: keyword names are case-insensitive, and a repeated
    keyword resolves to the *first* ``-o`` on the command line. ``build_ssh_argv`` sorts its
    options, and in ASCII every uppercase letter sorts before every lowercase one -- so before
    the fold, ``STRICTHOSTKEYCHECKING=no`` from a caller arrived ahead of our
    ``StrictHostKeyChecking=yes`` and won, silently.

    If a future OpenSSH ever changed either fact, this failing is how we would find out.
    """

    def resolved(*options: str) -> str:
        result = subprocess.run(
            ["/usr/bin/ssh", "-G", "-F", "/dev/null", *options, "example.com"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        line = next(
            line for line in result.stdout.splitlines() if line.startswith("stricthostkeychecking")
        )
        return line.split()[1]

    # Case-insensitive: a spelling we never emit still sets the same keyword.
    assert resolved("-o", "STRICTHOSTKEYCHECKING=no") == "false"
    # First wins, in both orders -- so argv position decides, which is what made the sort
    # order load-bearing and the bug silent.
    assert resolved("-o", "STRICTHOSTKEYCHECKING=no", "-o", "StrictHostKeyChecking=yes") == "false"
    assert resolved("-o", "StrictHostKeyChecking=yes", "-o", "STRICTHOSTKEYCHECKING=no") == "true"


CONFIG_FILE_COMMAND_EXECUTION = [
    pytest.param(
        "Host *\n    ProxyCommand /bin/sh -c 'echo GANTRY_PROXY >&2; exit 1'\n",
        "GANTRY_PROXY",
        id="proxycommand",
    ),
    pytest.param(
        'Match exec "echo GANTRY_MATCH >&2"\n    ProxyCommand /bin/false\n',
        "GANTRY_MATCH",
        id="match-exec",
    ),
]
"""Two ``ssh_config`` directives that run a program on *this* machine at connection setup.

``ProxyCommand`` is executed to obtain the connection; ``Match exec`` is executed during config
*parsing*, before a connection is attempted at all. Neither needs the network, which is why
these run as unit tests.
"""


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="ssh not installed")
@pytest.mark.parametrize(("directive", "marker"), CONFIG_FILE_COMMAND_EXECUTION)
def test_the_shipped_defaults_do_not_neutralise_an_untrusted_config(
    tmp_path: Path, directive: str, marker: str
):
    """Characterisation of ssh(1), and a boundary this library deliberately does not claim.

    ``PermitLocalCommand=no`` and ``ClearAllForwardings=yes`` ship because ``LocalCommand`` and
    forwardings in an ``ssh_config`` are things an SFTP client has no business doing. They are
    worth having and they are **not** a defence against a config file you do not trust: the two
    directives that actually execute a program still execute one, with the full default set
    applied. Asserted rather than described, because a comment claiming a boundary that is not
    there is worse than no comment.

    The defence is :func:`test_devnull_is_what_actually_ignores_a_config_file`.
    """
    config = tmp_path / "ssh_config"
    config.write_text(directive)
    # `.invalid` is reserved and never resolves, so neither case can reach the network: the
    # ProxyCommand one never looks the host up, and the Match exec one fails DNS immediately.
    result = subprocess.run(
        build_ssh_argv("nonexistent.invalid", config_file=config),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert marker in result.stderr, (
        "ssh no longer runs this directive from a config file with our defaults applied; "
        "re-check what the defaults are documented to cover"
    )


@pytest.mark.skipif(not Path("/usr/bin/ssh").exists(), reason="ssh not installed")
@pytest.mark.parametrize(("directive", "marker"), CONFIG_FILE_COMMAND_EXECUTION)
def test_devnull_is_what_actually_ignores_a_config_file(
    tmp_path: Path, directive: str, marker: str
):
    """``config_file=os.devnull`` is the control, and it covers the system config too.

    ``-F`` replaces the per-user config *and* suppresses ``/etc/ssh/ssh_config``, so it is a
    real "no config at all" rather than a half of one. Measured on this box: the system config
    sets ``HashKnownHosts yes`` and ``GSSAPIAuthentication yes``, and under ``-F /dev/null``
    ``ssh -G`` reports ``no`` for both.
    """
    config = tmp_path / "ssh_config"
    config.write_text(directive)
    # The config exists and says the same thing; the only difference is that we do not read it.
    result = subprocess.run(
        build_ssh_argv("nonexistent.invalid", config_file=os.devnull),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert marker not in result.stderr

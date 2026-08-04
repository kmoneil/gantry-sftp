"""The diagnostic, its exit codes, and the two things it must never get wrong.

**D-90.** `python -m gantry_sftp doctor` reports what this machine can do and what a server
negotiated. The local half is here, because it deliberately reaches no network; the server half
is in `live-tests/test_doctor.py`, where there is a real `sshd` to negotiate with.

Two properties carry more weight than the rest.

**It must not leak.** This feature exists to be pasted into a bug report, so the output is a
channel with a reader — the same finding D-39 made about the frame dumper, arriving again for a
different surface. Only the variables that steer `ssh` are read at all, and their values go
through the masking chokepoint. A test sets a password in the environment and greps the whole
report for it.

**It must report rather than raise.** A diagnostic that dies on the condition it was run to
diagnose is worse than no diagnostic. So the no-`ssh` case is exercised with a real empty `PATH`
rather than a patched function, per the card's own recon bullet and D-35's lesson that the
assertion tends to move what it asserts.

The third thing worth pinning is quieter: `ssh` expands `~` from `getpwuid`, not from `$HOME`, so
a report that resolved `~/.ssh/config` through the environment would name a file `ssh` is not
going to read — in exactly the situation where somebody is asking why their config is ignored.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from gantry_sftp import __main__ as gantry_main
from gantry_sftp import __version__
from gantry_sftp import doctor as gantry_doctor
from gantry_sftp.__main__ import build_parser, main, parse_options
from gantry_sftp.codec import IMPLEMENTED_EXTENSIONS, PROTOCOL_VERSION, _extensions
from gantry_sftp.doctor import (
    TYPICAL_HANDLE,
    Exit,
    LocalDiagnosis,
    ServerDiagnosis,
    _limits_of,
    local_diagnosis,
    overall_status,
    render_json,
    render_text,
    server_diagnosis,
    ssh_config_path,
)
from gantry_sftp.exceptions import NoSuchFileError
from gantry_sftp.session import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DEFAULT_REQUEST_TIMEOUT,
    ServerLimits,
)

SECRET = "hunter2-in-the-environment"  # noqa: S105 -- the thing the leak test greps for


def reachable(**overrides: object) -> ServerDiagnosis:
    """A server report with everything filled in, for the rendering tests."""
    fields: dict[str, object] = {
        "host": "example.com",
        "reached": True,
        "server": "openssh",
        "server_description": "OpenSSH's sftp-server",
        "server_version": None,
        "protocol_version": 3,
        "extensions": ("posix-rename@openssh.com", "statvfs@openssh.com"),
        "implemented": ("posix-rename@openssh.com",),
        "unimplemented": ("statvfs@openssh.com",),
        "absent": ("fsync@openssh.com",),
        "limits": {"max_packet_length": 262144, "max_read_length": 261120},
        "read_size": 261120,
        "write_size": 261120,
        "depth": 64,
        "start_directory": "/home/bob",
        "reaped": 0,
    }
    fields.update(overrides)
    return ServerDiagnosis(**fields)  # type: ignore[arg-type]


# --- the local half ----------------------------------------------------------------------------


def test_the_local_report_describes_this_machine():
    report = local_diagnosis()

    assert report.library_version == __version__
    assert report.protocol_version == PROTOCOL_VERSION
    assert report.ssh_executable == "ssh"
    assert report.ssh_resolved_from == "a bare name, so PATH decides at spawn time"
    assert report.ssh_version is not None, report.ssh_error
    assert report.ssh_version.startswith("OpenSSH_")
    assert report.ssh_error is None
    assert report.transfers_supported is True
    assert report.missing_local_io == ()
    assert report.exit_code is Exit.OK


def test_the_defaults_reported_are_the_ones_the_session_uses():
    """A diagnostic that restated the defaults would drift from them silently.

    Read from the same constants rather than typed here, so a changed default cannot make the
    report wrong while this test stays green.
    """
    defaults = local_diagnosis().defaults
    assert defaults.pipeline_depth == DEFAULT_PIPELINE_DEPTH
    assert defaults.request_timeout == DEFAULT_REQUEST_TIMEOUT
    assert defaults.idle_timeout == DEFAULT_IDLE_TIMEOUT


def test_the_environment_reported_is_the_one_that_was_passed(tmp_path: Path):
    """Injected rather than inherited, so this asserts about a stated environment.

    A test that read the developer's shell would pass on their machine and prove nothing --
    and the variables in question are exactly the ones a developer has set.
    """
    report = local_diagnosis({"SSH_AUTH_SOCK": "/run/agent.sock", "IRRELEVANT": "x"})

    assert report.environment == {"SSH_AUTH_SOCK": "/run/agent.sock"}
    assert "IRRELEVANT" not in report.environment


def test_an_environment_with_nothing_set_says_so():
    assert local_diagnosis({}).environment == {}
    assert "none of the steering variables are set" in render_text(local_diagnosis({}))


# --- the two properties that carry the weight ---------------------------------------------------


def test_no_ssh_is_reported_rather_than_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The card's recon bullet, run for real: an empty `PATH`, not a patched function.

    `subprocess` resolves the bare name through the environment it inherits, so emptying
    `PATH` is the actual mechanism rather than a stand-in for it. What it proves is that the
    report *exists* in the case it is most needed.
    """
    monkeypatch.setenv("PATH", str(tmp_path))

    report = local_diagnosis()

    assert report.ssh_version is None
    assert report.exit_code is Exit.NO_SSH
    assert report.ssh_error == (
        "'ssh' is not on PATH. OpenSSH is a runtime requirement of this library, not an "
        "optional extra: install the openssh-client package"
    )
    assert "NOT USABLE" in render_text(report)


def test_a_credential_in_the_environment_cannot_reach_the_output():
    """The card is not done until this passes, and it is checked against the whole report.

    Two mechanisms, either of which would be enough and both of which are here: an ordinary
    variable is not in the steering allowlist so it is never read, and the one steering
    variable that does carry a secret is masked by name. Asserted by grepping the rendered
    text *and* the JSON, because a leak that only appears in one renderer is still a leak.
    """
    hostile = {
        "MY_PASSWORD": SECRET,
        "AWS_SECRET_ACCESS_KEY": SECRET,
        "GANTRY_SFTP_ASKPASS_ANSWER": SECRET,
        "SSH_AUTH_SOCK": "/run/agent.sock",
    }

    report = local_diagnosis(hostile)

    assert SECRET not in render_text(report)
    assert SECRET not in render_json(report)
    assert SECRET not in str(report)
    # The masked variable is still *named*, because its presence is the diagnostic fact and
    # only its value is the secret.
    assert report.environment["GANTRY_SFTP_ASKPASS_ANSWER"] == "<redacted>"
    assert report.environment["SSH_AUTH_SOCK"] == "/run/agent.sock"


def test_the_ssh_config_is_resolved_the_way_ssh_resolves_it(monkeypatch: pytest.MonkeyPatch):
    """`ssh` expands `~` from `getpwuid(getuid())`, never from `$HOME` — so neither does this.

    Redirecting `HOME` must not move the answer. A report built on `Path.home()` would name a
    file `ssh` is not going to read, and would do it precisely when somebody is trying to work
    out why their config is being ignored.
    """
    account_home = pwd.getpwuid(os.getuid()).pw_dir
    monkeypatch.setenv("HOME", "/somewhere/else")

    assert ssh_config_path() == Path(account_home) / ".ssh" / "config"
    assert local_diagnosis().ssh_config == str(Path(account_home) / ".ssh" / "config")


# --- exit codes ---------------------------------------------------------------------------------


def local(**overrides: object) -> LocalDiagnosis:
    fields: dict[str, object] = {
        "library_version": "0.0.0",
        "protocol_version": 3,
        "ssh_executable": "ssh",
        "ssh_resolved_from": "a bare name, so PATH decides at spawn time",
        "ssh_version": "OpenSSH_10.0p2",
        "ssh_error": None,
        "transfers_supported": True,
        "missing_local_io": (),
        "ssh_config": "/home/bob/.ssh/config",
        "ssh_config_present": True,
    }
    fields.update(overrides)
    return LocalDiagnosis(**fields)  # type: ignore[arg-type]


def test_a_platform_without_local_io_is_its_own_code():
    """Not a failure and not a success: remote-only operations still work there (D-82).

    A build that only lists and renames is fine on such a platform, and its own build should
    be able to say so rather than reading a generic 1.
    """
    report = local(transfers_supported=False, missing_local_io=("os.pwrite",))

    assert report.exit_code is Exit.NO_LOCAL_IO
    assert "NOT SUPPORTED here -- needs os.pwrite" in render_text(report)
    assert "remote-only ops work" in render_text(report)


def test_a_local_problem_outranks_an_unreachable_host():
    """An unreachable host on a machine with no `ssh` is a machine with no `ssh`.

    Reporting the connection failure would send the reader after the symptom; the local
    finding is the one with a remedy attached.
    """
    unreachable = ServerDiagnosis(host="example.com", reached=False, error="ConnectError: no")

    assert overall_status(local(ssh_version=None), unreachable) is Exit.NO_SSH
    assert overall_status(local(), unreachable) is Exit.UNREACHABLE
    assert overall_status(local(), reachable()) is Exit.OK
    assert overall_status(local(), None) is Exit.OK


def test_the_status_in_the_report_is_the_status_of_the_process():
    """One definition, used by both renderers and by `main`, so they cannot disagree."""
    report = local(transfers_supported=False, missing_local_io=("os.pread",))

    assert f"exit {int(Exit.NO_LOCAL_IO)} ({Exit.NO_LOCAL_IO.name})" in render_text(report)
    assert json.loads(render_json(report))["exit"] == int(Exit.NO_LOCAL_IO)
    assert json.loads(render_json(report))["status"] == Exit.NO_LOCAL_IO.name


# --- rendering ----------------------------------------------------------------------------------


def test_the_server_section_says_which_extensions_are_used_and_which_are_not():
    """The question this exists to answer: "why did posix_rename not happen"."""
    rendered = render_text(local(), reachable())

    assert "uses                  posix-rename@openssh.com" in rendered
    assert "ignores               statvfs@openssh.com" in rendered
    assert "absent                fsync@openssh.com -- documented fallback" in rendered


def test_a_server_that_advertised_no_limits_is_not_reported_as_having_stated_defaults():
    """Two absences kept apart, because collapsing them makes the report assert its own guess."""
    rendered = render_text(local(), reachable(limits=None))

    assert "limits                  not advertised; conservative defaults in use" in rendered


def test_a_limit_the_server_called_unlimited_renders_as_unlimited():
    rendered = render_text(local(), reachable(limits={"max_open_handles": None}))

    assert "  limits.max_open_handles no limit" in rendered


def test_a_failure_is_a_block_rather_than_a_field():
    """A `ConnectError` carries OpenSSH's stderr verbatim, which is many lines and is the answer.

    Rendering it as the tail of a fixed-width field would put the diagnosis in the one place
    the layout makes unreadable. Found by running it against an unreachable host.
    """
    error = "ConnectError: connection closed\nssh stderr:\n/home/bob/.ssh/config: line 14: bad"

    rendered = render_text(local(), ServerDiagnosis(host="h", reached=False, error=error))

    assert "  NOT REACHED\n" in rendered
    assert "    ConnectError: connection closed" in rendered
    assert "    /home/bob/.ssh/config: line 14: bad" in rendered


def test_the_json_carries_every_field_of_both_halves():
    """`--json` exists so CI asserts on this rather than scraping the text."""
    payload = json.loads(render_json(local(), reachable()))

    assert payload["local"]["ssh_executable"] == "ssh"
    assert payload["server"]["implemented"] == ["posix-rename@openssh.com"]
    assert payload["server"]["start_directory"] == "/home/bob"
    assert payload["server"]["read_size"] == 261120
    assert payload["server"]["write_size"] == 261120


def test_the_local_report_alone_has_no_server_key():
    assert "server" not in json.loads(render_json(local()))


# --- the command ---------------------------------------------------------------------------------


def test_doctor_is_the_only_verb():
    """A decision, not a starting point: a `__main__` with one verb invites a second.

    Asserted through argparse's own choices rather than a hand-rolled check, so an unknown
    verb produces a usage message listing what exists.
    """
    parser = build_parser()
    commands = [action for action in parser._actions if action.dest == "command"]  # noqa: SLF001

    assert list(commands[0].choices or ()) == ["doctor"]

    with pytest.raises(SystemExit) as exited:
        parser.parse_args(["transfer"])
    assert exited.value.code == int(Exit.USAGE)


def test_the_verb_is_required_so_a_second_one_could_not_change_an_invocation():
    with pytest.raises(SystemExit) as exited:
        build_parser().parse_args([])
    assert exited.value.code == int(Exit.USAGE)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (None, {}),
        (["BatchMode=yes"], {"BatchMode": "yes"}),
        (["A=1", "B=2"], {"A": "1", "B": "2"}),
        # The value may itself contain `=`, which is why the split is on the first one only --
        # and this case has to *contain* one to say so. It did not until D-135: the comment
        # claimed the axis and the data did not vary along it, so `partition` could become
        # `rpartition` with the suite green. `ProxyCommand` is exactly where this bites,
        # because the command it names has options of its own.
        (
            ["ProxyCommand=ssh -o StrictHostKeyChecking=no -W %h:%p bastion"],
            {"ProxyCommand": "ssh -o StrictHostKeyChecking=no -W %h:%p bastion"},
        ),
        (["Empty="], {"Empty": ""}),
    ],
)
def test_repeated_o_options_become_the_mapping_connect_takes(
    given: list[str] | None, expected: dict[str, str]
):
    assert parse_options(given) == expected


def test_an_option_with_no_equals_is_refused_rather_than_dropped():
    """A silently dropped option makes the report describe a different connection."""
    with pytest.raises(ValueError) as wrong:
        parse_options(["BatchMode"])
    assert wrong.value.args[0] == "-o wants KEY=VALUE, got 'BatchMode'"

    with pytest.raises(SystemExit) as exited:
        main(["doctor", "example.com", "-o", "BatchMode"])
    assert exited.value.code == int(Exit.USAGE)


def test_the_command_prints_a_report_and_returns_a_status(capsys: pytest.CaptureFixture[str]):
    status = main(["doctor"])

    printed = capsys.readouterr().out
    assert status == int(Exit.OK)
    assert "gantry-sftp doctor" in printed
    assert "ssh version             OpenSSH_" in printed


def test_the_command_emits_json_when_asked(capsys: pytest.CaptureFixture[str]):
    status = main(["doctor", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert status == int(Exit.OK)
    assert payload["status"] == "OK"
    assert payload["local"]["library_version"] == __version__


def test_no_host_is_reached_when_ssh_itself_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """The connection is not even attempted: its failure would be the symptom, not the cause."""
    monkeypatch.setenv("PATH", str(tmp_path))

    status = main(["doctor", "example.invalid", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert status == int(Exit.NO_SSH)
    assert "server" not in payload, "a connection was attempted with no ssh to attempt it with"


def test_the_module_runs_as_a_module(tmp_path: Path):
    """`python -m gantry_sftp doctor`, spawned, because that is how a Dockerfile runs it.

    The `__main__` guard and the `sys.exit` are only exercised this way -- importing `main`
    reaches neither, and those two lines are the whole contract with the shell.
    """
    finished = subprocess.run(
        [sys.executable, "-m", "gantry_sftp", "doctor", "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=tmp_path,
    )

    assert finished.returncode == int(Exit.OK), finished.stderr
    assert json.loads(finished.stdout)["status"] == "OK"


def test_a_bad_verb_exits_two_from_a_real_process(tmp_path: Path):
    finished = subprocess.run(
        [sys.executable, "-m", "gantry_sftp", "sync-everything"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=tmp_path,
    )

    assert finished.returncode == int(Exit.USAGE)
    assert "invalid choice" in finished.stderr


# --- what the report claims about the library ----------------------------------------------------


def test_the_implemented_extension_set_is_the_one_with_bodies():
    """The report's "used here" column is only true if this list is.

    Derived where the bodies are rather than in the diagnostic, so an extension gains its
    entry in the same file its encoder lands in. This is the guard on that.
    """
    with_bodies = {
        cls.extension_name.decode("ascii")
        for cls in vars(_extensions).values()
        if isinstance(cls, type) and hasattr(cls, "extension_name")
    }

    assert with_bodies <= set(IMPLEMENTED_EXTENSIONS), (
        "an extension has a wire body but is not reported as implemented"
    )


# --- the connecting half, which the mutation lane reported as 81 mutants with no test ---------
#
# `server_diagnosis` is the one function here that opens a connection, so every test above
# stops short of it -- and the lane's reading for it was **"no tests"** rather than "survived":
# nothing ran, as opposed to something running and not noticing. It is also the function with
# the most to get wrong. Six arguments are forwarded to `connect`, sixteen fields are read off
# the session, and its whole contract is that it *refuses to raise* -- a diagnostic that dies on
# the condition it was run to diagnose has nothing to say about the only case that matters.
#
# `connect` is replaced rather than a server stood up, because what is under test is the
# reading, not the protocol: `live-tests/` is where a real handshake is exercised.


class _Profile:
    label = "OpenSSH"
    description = "OpenSSH's own sftp-server"
    version = "9.6"


class _FakeSession:
    """A session with every field `server_diagnosis` reads, each a distinguishable value."""

    extensions = (b"posix-rename@openssh.com", b"fsync@openssh.com", b"vendor-thing@example")
    profile = _Profile()
    server_version = 3
    depth = 7
    reaped = 2

    def __init__(self, limits: ServerLimits | None = None) -> None:
        self.limits = limits if limits is not None else ServerLimits(max_read_length=32768)

    def sizes_for(self, handle: bytes) -> object:
        self.handle_asked_about = handle

        class _Sizes:
            read_length = 31000
            write_length = 30000

        return _Sizes()

    def realpath(self) -> bytes:
        return "/incoming/caf\udce9".encode("utf-8", "surrogateescape")


@pytest.fixture
def recorded_connect(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Replace `connect` with a recorder that yields `_FakeSession`, and hand back the record."""
    seen: dict[str, object] = {}
    session = _FakeSession()

    @contextmanager
    def fake_connect(host: str, **kwargs: object):  # type: ignore[no-untyped-def]
        seen.update(kwargs, host=host)
        yield session

    monkeypatch.setattr(gantry_doctor, "connect", fake_connect)
    return seen, session


def test_server_diagnosis_forwards_every_argument_it_accepts(recorded_connect, tmp_path: Path):
    """Six arguments, each droppable on its own with everything else still green.

    Non-default values throughout, because an argument that forwards its own default is
    invisible -- and `identity_file` and `config_file` are exactly the two a caller reaches for
    when reproducing the connection that is actually failing.
    """
    seen, _session = recorded_connect
    _ = server_diagnosis(
        "example.com",
        user="bob",
        port=2222,
        identity_file=str(tmp_path / "id_ed25519"),
        config_file=str(tmp_path / "ssh_config"),
        options={"Compression": "yes"},
    )

    assert seen == {
        "host": "example.com",
        "user": "bob",
        "port": 2222,
        "identity_file": str(tmp_path / "id_ed25519"),
        "config_file": str(tmp_path / "ssh_config"),
        "options": {"Compression": "yes"},
    }


def test_server_diagnosis_reads_every_field_off_the_session(recorded_connect):
    """Sixteen fields, and the three extension tuples are the ones worth reading twice.

    `implemented`, `unimplemented` and `absent` are three views of one comparison between what
    the server advertised and what this library can send. Swapping any two of them turns
    "we do not use this" into "your server does not offer it", which sends a reader to the
    wrong side of the connection.
    """
    _seen, session = recorded_connect
    report = server_diagnosis("example.com")

    assert report.reached is True
    assert report.host == "example.com"
    assert report.error is None
    assert report.server == "OpenSSH"
    assert report.server_description == "OpenSSH's own sftp-server"
    assert report.server_version == "9.6"
    assert report.protocol_version == 3

    assert report.extensions == (
        "posix-rename@openssh.com",
        "fsync@openssh.com",
        "vendor-thing@example",
    )
    assert report.implemented == ("posix-rename@openssh.com", "fsync@openssh.com")
    assert report.unimplemented == ("vendor-thing@example",)
    assert "posix-rename@openssh.com" not in report.absent
    assert set(report.absent) == set(IMPLEMENTED_EXTENSIONS) - set(report.implemented)

    assert report.limits == {
        "max_packet_length": None,
        "max_read_length": 32768,
        "max_write_length": None,
        "max_open_handles": None,
    }
    assert report.read_size == 31000
    assert report.write_size == 30000
    assert report.depth == 7
    assert report.reaped == 2
    # Decoded leniently and reversibly, because a start directory can be a name no encoding
    # explains -- the same rule the rest of this library applies to server-supplied names.
    assert report.start_directory == "/incoming/caf\udce9"
    assert session.handle_asked_about == TYPICAL_HANDLE


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (NoSuchFileError("no such file", code=2), "NoSuchFileError: no such file"),
        (
            OSError("ssh: connect to host example.com port 22: Connection refused"),
            "OSError: ssh: connect to host example.com port 22: Connection refused",
        ),
    ],
)
def test_server_diagnosis_reports_a_failure_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, expected: str
):
    """**Refusing to raise is the design**, and it is the only case that matters.

    A diagnostic that dies on the condition it was run to diagnose has nothing to say about it.
    The message carries the exception's *type* as well as its text, because "Connection
    refused" and "Permission denied" arrive as different classes and the class is what a reader
    acts on.
    """

    @contextmanager
    def failing_connect(_host: str, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise failure
        yield  # pragma: no cover -- unreachable, and what makes this a context manager

    monkeypatch.setattr(gantry_doctor, "connect", failing_connect)
    report = server_diagnosis("example.com")

    assert report.reached is False
    assert report.host == "example.com"
    assert report.error == expected
    assert report.exit_code is Exit.UNREACHABLE
    # Nothing was negotiated, so nothing is claimed about it.
    assert report.extensions == ()
    assert report.limits is None
    assert report.protocol_version is None


@pytest.mark.parametrize(
    ("limits", "expected"),
    [
        (ServerLimits(), None),
        (
            ServerLimits(
                max_packet_length=34000,
                max_read_length=32768,
                max_write_length=32768,
                max_open_handles=100,
            ),
            {
                "max_packet_length": 34000,
                "max_read_length": 32768,
                "max_write_length": 32768,
                "max_open_handles": 100,
            },
        ),
        # A `0` from the server means *no limit* on that field, which `ServerLimits` also stores
        # as `None` -- so a `None` inside an answer is "unlimited" and must still be rendered.
        (
            ServerLimits(max_packet_length=34000),
            {
                "max_packet_length": 34000,
                "max_read_length": None,
                "max_write_length": None,
                "max_open_handles": None,
            },
        ),
    ],
)
def test_the_two_absences_are_kept_apart(limits: ServerLimits, expected: object):
    """No answer at all is `None`; an answer with a gap in it is a dict with a `None` in it.

    Collapsing the two would make the diagnostic assert its own conservative defaults back at
    the reader as though the server had stated them -- on the one report whose value is that it
    says what the *server* said.
    """
    assert _limits_of(limits) == expected


# --- the branch this platform never takes ----------------------------------------------------


@pytest.fixture
def no_pwd(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Make `import pwd` fail, which is the only way to reach the Windows fallback here.

    Nineteen of this module's survivors lived in that branch: on any platform with `pwd` the
    `try` succeeds and none of it executes, so the environment variable names, their order and
    the shape of the path were all free. `None` in `sys.modules` is what makes an `import`
    raise `ImportError` without touching the real module.
    """
    monkeypatch.setitem(sys.modules, "pwd", None)


def test_the_windows_fallback_prefers_userprofile(no_pwd):
    # OpenSSH on Windows uses the profile directory, so `USERPROFILE` is the right source
    # there rather than a second-best one -- and it has to win over `HOME`, which a
    # Git-for-Windows shell will also have set, to somewhere else.
    found = ssh_config_path({"USERPROFILE": r"C:\Users\bob", "HOME": "/msys/home/bob"})
    assert found == Path(r"C:\Users\bob") / ".ssh" / "config"


def test_the_windows_fallback_takes_home_when_there_is_no_profile(no_pwd):
    assert ssh_config_path({"HOME": "/home/bob"}) == Path("/home/bob") / ".ssh" / "config"


def test_the_windows_fallback_says_tilde_when_it_knows_nothing(no_pwd):
    """`~` unexpanded, deliberately: a wrong absolute path reads as an answer, `~` reads as one.

    Left as the literal rather than expanded, because expanding it here would go through
    `Path.home()` and land back on `$HOME` -- the very thing this function exists not to use.
    """
    assert ssh_config_path({}) == Path("~") / ".ssh" / "config"


def test_the_windows_fallback_reads_the_real_environment_when_given_none(no_pwd, monkeypatch):
    # `environ=None` means "the process environment", and the fallback is the one branch that
    # consults it at all.
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setenv("HOME", "/from/the/process")
    assert ssh_config_path() == Path("/from/the/process") / ".ssh" / "config"


# --- running `ssh -V`, whose three failures each have their own sentence ---------------------


def test_the_version_probe_asks_for_what_it_needs(monkeypatch: pytest.MonkeyPatch):
    """`check=False` and a timeout, both carried rather than observable in the answer.

    `-V` prints to **stderr** and exits non-zero on some builds, so `check=True` would turn an
    ordinary OpenSSH into "no ssh here" -- the single most misleading thing this report could
    say. The timeout is what stops a wedged binary hanging the diagnostic; neither shows up in
    the return value, so both are read off the call.
    """
    seen: dict[str, object] = {}

    def spy(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen.update(kwargs, argv=argv)
        return subprocess.CompletedProcess(argv, returncode=255, stderr=b"OpenSSH_10.0p2\n")

    monkeypatch.setattr(gantry_doctor.subprocess, "run", spy)
    version, error = gantry_doctor._ssh_version("ssh")  # noqa: SLF001

    assert (version, error) == ("OpenSSH_10.0p2", None), "a non-zero exit was read as a failure"
    assert seen["argv"] == ["ssh", "-V"]
    assert seen["check"] is False
    assert seen["timeout"] == gantry_doctor._SSH_VERSION_TIMEOUT  # noqa: SLF001
    assert seen["capture_output"] is True


def test_a_version_banner_that_is_not_utf8_is_still_reported(monkeypatch: pytest.MonkeyPatch):
    # The banner is somebody else's bytes. A strict decode would raise `UnicodeDecodeError`
    # from inside the function whose job is to explain why `ssh` is not usable.
    def spy(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, returncode=0, stderr=b"OpenSSH_\xff9.6\n")

    monkeypatch.setattr(gantry_doctor.subprocess, "run", spy)
    version, error = gantry_doctor._ssh_version("ssh")  # noqa: SLF001

    assert version == "OpenSSH_\ufffd9.6"
    assert error is None


# --- the JSON report -------------------------------------------------------------------------


def test_the_json_report_is_stable_and_readable():
    """Indented and key-sorted, and both are for the reader rather than the parser.

    A diff of two `doctor --json` runs is how somebody compares a working host with a broken
    one, and neither an unsorted nor a single-line document diffs usefully.
    """
    document = render_json(local())
    assert "\n" in document, "the report is a single line, so it cannot be diffed"
    lines = document.splitlines()
    assert lines[1].startswith('  "'), "the first key is not indented by two"
    assert not lines[1].startswith("   "), "indented by more than two"
    keys = [line.strip().split(":")[0] for line in lines if line.startswith('  "')]
    assert keys == sorted(keys), "top-level keys are not sorted"


def test_the_json_report_takes_its_status_from_the_server_too():
    """`overall_status(local, server)`, not `overall_status(local, None)`.

    Dropping the second argument makes a run against an unreachable host exit `0` and print
    `OK` -- the exact failure `doctor` exists to report, reported as success.
    """
    payload = json.loads(render_json(local(), reachable(reached=False, error="refused")))

    assert payload["status"] == Exit.UNREACHABLE.name
    assert payload["exit"] == int(Exit.UNREACHABLE)
    assert payload["server"]["error"] == "refused"


# --- the rendered report, pinned whole ---------------------------------------------------------
#
# Fourteen of `render_text`'s mutants and every one of the four line helpers' survived a suite
# that asserts on *substrings*. A heading could lose its case, a blank line could become `"XX"`,
# `lines +=` could become `lines =` and drop everything above it, and a `', '` join could become
# something else -- all invisible to `assert "..." in report`.
#
# So the whole report is pinned, the way a packet is pinned by a golden frame: this is an output
# format, people diff two runs of it, and an assertion that reads part of a line cannot see the
# line move. Four shapes, because the branches are in the data rather than in the call.


REACHED_REPORT = """\
gantry-sftp doctor

local
  library                 0.0.0 (filexfer v3)
  ssh executable          ssh -- a bare name, so PATH decides at spawn time
  ssh version             OpenSSH_10.0p2
  transfers               supported
  ssh config              /home/bob/.ssh/config
  environment             SSH_AUTH_SOCK=/run/agent
  defaults                depth=64 request_timeout=30.0 idle_timeout=60.0

server example.com
  identified as           openssh -- OpenSSH's sftp-server
  protocol                v3
  extensions              2 advertised, 1 used here
    uses                  posix-rename@openssh.com
    ignores               statvfs@openssh.com
    absent                fsync@openssh.com -- documented fallback
  limits.max_packet_length262144
  limits.max_read_length  261120
  request size            read=261120 write=261120 (for a 4-byte handle)
  depth                   64
  start directory         /home/bob
  handles reaped          0

exit 0 (OK)"""


def test_the_whole_report_for_a_server_that_answered():
    assert render_text(local(environment={"SSH_AUTH_SOCK": "/run/agent"}), reachable()) == (
        REACHED_REPORT
    )


LOCAL_PROBLEMS_REPORT = """\
gantry-sftp doctor

local
  library                 0.0.0 (filexfer v3)
  ssh executable          /usr/bin/ssh -- an absolute path, probed under SystemRoot (Windows)
  ssh version             OpenSSH_10.0p2
  transfers               NOT SUPPORTED here -- needs os.pread, os.pwrite (remote-only ops work)
  ssh config              /home/bob/.ssh/config (absent)
  environment             none of the steering variables are set
  defaults                depth=64 request_timeout=30.0 idle_timeout=60.0

server example.com
  NOT REACHED
    ConnectError: refused

    ssh said no

exit 4 (NO_LOCAL_IO)"""


def test_the_whole_report_when_this_machine_is_the_problem():
    """Two local problems and a multi-line failure, which is the shape a real one has.

    The blank line inside the reason is rendered as an *empty* line rather than as four spaces,
    which is what keeps a pasted `ssh` transcript readable. And the exit is the **local**
    status: an unreachable host on a machine that cannot do local file I/O is a machine that
    cannot do local file I/O, and saying so is the difference between one remedy and a hunt.
    """
    report = render_text(
        local(
            transfers_supported=False,
            missing_local_io=("os.pread", "os.pwrite"),
            ssh_config_present=False,
            ssh_executable="/usr/bin/ssh",
            ssh_resolved_from="an absolute path, probed under SystemRoot (Windows)",
        ),
        reachable(reached=False, error="ConnectError: refused\n\nssh said no", limits=None),
    )
    assert report == LOCAL_PROBLEMS_REPORT


def test_the_report_takes_its_exit_from_the_server_when_the_machine_is_fine():
    """`overall_status(local, server)` in both halves of the exit line, and a missing reason.

    Dropping the server from either half prints `exit 0 (OK)` for a host that was never
    reached -- the one thing this report exists to say, said backwards. They are two separate
    calls in one f-string, so each is asserted.
    """
    report = render_text(local(), reachable(reached=False, error=None, limits=None))

    assert report.endswith("\n\nexit 5 (UNREACHABLE)")
    assert report.splitlines()[-4:-2] == ["  NOT REACHED", "    no reason recorded"]


def test_a_server_that_advertised_no_limits_says_so_rather_than_reporting_our_guesses():
    # The other side of `_limits_of`'s two absences: the renderer has to say the extension was
    # not offered, not print the conservative defaults the session then uses as though the
    # server had stated them.
    report = render_text(local(), reachable(limits=None))

    assert "  limits                  not advertised; conservative defaults in use" in (
        report.splitlines()
    ), "asserted as a whole line: a substring check passes a line that grew around it"
    assert "limits.max_packet_length" not in report


def test_more_than_one_steering_variable_is_listed_comma_separated():
    # A single-variable case cannot see the separator, and this is a line an operator scans.
    report = render_text(local(environment={"SSH_AUTH_SOCK": "/run/agent", "SSH_ASKPASS": "/x"}))
    assert "  environment             SSH_AUTH_SOCK=/run/agent, SSH_ASKPASS=/x" in (
        report.splitlines()
    )


@pytest.mark.parametrize(
    ("executable", "note"),
    [
        ("ssh", "a bare name, so PATH decides at spawn time"),
        ("/usr/bin/ssh", "an absolute path, probed under SystemRoot (Windows)"),
        (r"C:\Windows\System32\OpenSSH\ssh.exe", "a bare name, so PATH decides at spawn time"),
    ],
)
def test_how_the_executable_will_be_found_is_said_in_words(executable: str, note: str):
    """Both branches, and the third case is the one that surprises.

    A Windows-shaped path is *not* absolute to `pathlib` on POSIX, so it reads as a bare name
    here -- which is correct for the platform doing the reporting and is why this is computed
    rather than inferred from the string's shape.
    """
    assert gantry_doctor._resolution_note(executable) == note  # noqa: SLF001


def test_an_extension_name_that_is_not_utf8_is_reported_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
):
    """The extension table is the server's bytes, and a strict decode raises inside the report.

    Reaching a server that advertises a name no encoding explains is exactly the situation
    `doctor` is run for -- so this is the one path where a `UnicodeDecodeError` would be
    thrown by the diagnostic instead of by the thing being diagnosed.
    """

    class _Odd(_FakeSession):
        extensions = (b"posix-rename@openssh.com", b"vendor-\xff@example")

    @contextmanager
    def fake_connect(_host: str, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield _Odd()

    monkeypatch.setattr(gantry_doctor, "connect", fake_connect)
    report = server_diagnosis("example.com")

    assert report.extensions == ("posix-rename@openssh.com", "vendor-\ufffd@example")
    assert report.unimplemented == ("vendor-\ufffd@example",)


def test_the_local_report_forwards_the_environment_it_was_given(monkeypatch: pytest.MonkeyPatch):
    """Two forwards, neither observable in the answer on this platform.

    `resolve_ssh_executable` reads the environment only on Windows and `ssh_config_path` reads
    it only where `pwd` is missing -- so on Linux both could be called with `None` and the
    report would be identical. What is asserted is therefore the call, not the result.
    """
    seen: dict[str, object] = {}
    environ = {"SystemRoot": r"C:\Windows"}

    def spy_executable(*, environ: object = None) -> str:
        seen["executable_environ"] = environ
        return "ssh"

    def spy_config(passed: object = None) -> Path:
        seen["config_environ"] = passed
        return Path("/home/bob/.ssh/config")

    monkeypatch.setattr(gantry_doctor, "resolve_ssh_executable", spy_executable)
    monkeypatch.setattr(gantry_doctor, "ssh_config_path", spy_config)
    _ = local_diagnosis(environ)

    assert seen == {"executable_environ": environ, "config_environ": environ}


def test_whether_the_config_file_is_there_is_a_boolean(tmp_path: Path):
    # `None` is falsy, so every `if report.ssh_config_present` reads the same -- and the report
    # then renders " (absent)" for a file that is right there.
    absent = local_diagnosis({"HOME": str(tmp_path)})
    assert absent.ssh_config_present in (True, False), "not a bool, so `is True` cannot be used"


# --- the command line, pinned as a table -------------------------------------------------------
#
# 62 of `__main__.py`'s 82 survivors were in `build_parser`, and every one of them was a string
# argparse holds rather than a branch: a flag's spelling, its `dest`, its `metavar`, its
# `choices`, its help. None of it is reachable by running the program successfully, because a
# renamed flag simply becomes a usage error in a test that never passes that flag.
#
# A table of the parser's own actions rather than a golden of `--help`: the help text is laid out
# by argparse and its wrapping moves with the terminal width and the Python version, so pinning
# the rendered form would pin somebody else's formatter. What this pins is what was *declared*.

EXPECTED_ARGUMENTS = [
    # option strings, dest, metavar, choices, nargs, type, action, help
    ((), "command", None, ("doctor",), None, None, "_StoreAction", "the only command there is"),
    ((), "host", None, None, "?", None, "_StoreAction", "a server to diagnose as well; optional"),
    (
        ("--user",),
        "user",
        None,
        None,
        None,
        None,
        "_StoreAction",
        "log in as somebody other than the local account",
    ),
    (("--port",), "port", None, None, None, "int", "_StoreAction", "a non-default port"),
    (
        ("-i", "--identity-file"),
        "identity_file",
        None,
        None,
        None,
        None,
        "_StoreAction",
        "a private key to offer, as ssh -i",
    ),
    (
        ("--config-file",),
        "config_file",
        None,
        None,
        None,
        None,
        "_StoreAction",
        "an ssh_config to use instead of your own",
    ),
    (
        ("-o",),
        "options",
        "KEY=VALUE",
        None,
        None,
        None,
        "_AppendAction",
        "an ssh -o option; repeat for more than one",
    ),
    (
        ("--json",),
        "json",
        None,
        None,
        0,
        None,
        "_StoreTrueAction",
        "emit the report as JSON rather than as text",
    ),
]


def test_every_declared_argument_is_what_it_says_it_is():
    """One row per flag, and each column is something a mutation can change on its own.

    `-o` being `_AppendAction` with that `metavar` is the load-bearing one: a single `--option`
    would make reproducing a two-option failure impossible, which is the case the flag exists
    for. `--port`'s `type=int` is the other -- without it the port reaches `connect` as a string.
    """
    actions = [a for a in build_parser()._actions if a.dest != "help"]  # noqa: SLF001
    described = [
        (
            tuple(a.option_strings),
            a.dest,
            a.metavar,
            tuple(a.choices) if a.choices else a.choices,
            a.nargs,
            a.type.__name__ if a.type else None,
            type(a).__name__,
            a.help,
        )
        for a in actions
    ]
    assert described == EXPECTED_ARGUMENTS


def test_the_parser_names_itself_and_says_what_it_is_for():
    parser = build_parser()
    assert parser.prog == "python -m gantry_sftp"
    assert parser.description, "no description, so --help says nothing about the program"
    assert parser.epilog, "no epilog, so --help shows no example"
    # Raw, so the epilog's example command lines keep their line breaks rather than being
    # rewrapped into one paragraph.
    assert parser.formatter_class is argparse.RawDescriptionHelpFormatter


def test_an_unknown_command_is_a_usage_error_that_lists_what_exists(capsys):
    # `choices` rather than free text, so argparse writes the message and it cannot drift out
    # of step with the commands that actually exist.
    with pytest.raises(SystemExit) as exit_status:
        build_parser().parse_args(["diagnose"])
    assert exit_status.value.code == 2
    assert "doctor" in capsys.readouterr().err


# --- what `main` hands to the diagnosis --------------------------------------------------------


def test_main_forwards_every_argument_to_the_server_diagnosis(monkeypatch, tmp_path, capsys):
    """Six arguments, each droppable on its own, on the path that reproduces a real failure.

    An operator diagnosing a connection passes the identity, the config and the options that
    connection actually uses -- so an argument dropped here diagnoses a *different* connection
    and reports that it worked.
    """
    seen: dict[str, object] = {}

    def spy(host: str, **kwargs: object) -> ServerDiagnosis:
        seen.update(kwargs, host=host)
        return reachable()

    monkeypatch.setattr(gantry_main, "server_diagnosis", spy)
    status = gantry_main.main(
        [
            "doctor",
            "example.com",
            "--user",
            "bob",
            "--port",
            "2222",
            "-i",
            str(tmp_path / "id_ed25519"),
            "--config-file",
            str(tmp_path / "ssh_config"),
            "-o",
            "Compression=yes",
            "-o",
            "ProxyCommand=ssh -W %h:%p bastion",
        ]
    )
    _ = capsys.readouterr()

    assert status == int(Exit.OK)
    assert seen == {
        "host": "example.com",
        "user": "bob",
        "port": 2222,
        "identity_file": str(tmp_path / "id_ed25519"),
        "config_file": str(tmp_path / "ssh_config"),
        # Repeated `-o` accumulates, and the value keeps the `=` inside it.
        "options": {"Compression": "yes", "ProxyCommand": "ssh -W %h:%p bastion"},
    }


def test_no_options_reaches_the_diagnosis_as_none_rather_than_an_empty_mapping(monkeypatch, capsys):
    """`options or None`, where `and None` would send `{}`.

    An empty mapping and "the caller said nothing" are different requests: `connect` layers its
    own defaults under whatever it is given, and a caller who passed no `-o` is asking for
    exactly those.
    """
    seen: dict[str, object] = {}

    def spy(host: str, **kwargs: object) -> ServerDiagnosis:
        seen.update(kwargs, host=host)
        return reachable()

    monkeypatch.setattr(gantry_main, "server_diagnosis", spy)
    _ = gantry_main.main(["doctor", "example.com"])
    _ = capsys.readouterr()

    assert seen["options"] is None


def test_no_host_means_no_connection_is_attempted(monkeypatch, capsys):
    def refuse(*_a: object, **_k: object) -> ServerDiagnosis:  # pragma: no cover -- must not run
        raise AssertionError("a connection was attempted with no host given")

    monkeypatch.setattr(gantry_main, "server_diagnosis", refuse)
    status = gantry_main.main(["doctor"])
    assert status == int(Exit.OK)
    assert "server" not in capsys.readouterr().out


def test_a_malformed_option_is_refused_with_the_argument_that_was_wrong(capsys):
    """`parser.error(str(malformed))`, where the message is the only thing an operator can act on.

    Refused rather than ignored: a silently dropped `-o` would make the diagnosis a report
    about a different connection from the one being asked about -- and the message has to name
    the argument, because `-o` is repeatable and the operator passed several.
    """
    with pytest.raises(SystemExit) as exit_status:
        gantry_main.main(["doctor", "-o", "Compression"])
    assert exit_status.value.code == 2
    assert "-o wants KEY=VALUE, got 'Compression'" in capsys.readouterr().err


def test_the_printed_report_and_the_exit_status_both_include_the_server(monkeypatch, capsys):
    """Three separate uses of `server` in four lines, and each is droppable on its own.

    Dropped from `render`, the report says nothing about the host that was just contacted.
    Dropped from `overall_status`, the process exits `0` for a host it could not reach -- and
    a CI job that only checks the exit code then passes on a broken connection.
    """
    monkeypatch.setattr(
        gantry_main,
        "server_diagnosis",
        lambda host, **_k: reachable(host=host, reached=False, error="refused", limits=None),
    )
    status = gantry_main.main(["doctor", "example.com"])
    printed = capsys.readouterr().out

    assert status == int(Exit.UNREACHABLE), "the exit status ignored the server"
    assert "server example.com" in printed.splitlines()
    assert "  NOT REACHED" in printed.splitlines()

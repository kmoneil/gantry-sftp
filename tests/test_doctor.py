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

import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

from gantry_sftp import __version__
from gantry_sftp.__main__ import build_parser, main, parse_options
from gantry_sftp.codec import IMPLEMENTED_EXTENSIONS, PROTOCOL_VERSION, _extensions
from gantry_sftp.doctor import (
    Exit,
    LocalDiagnosis,
    ServerDiagnosis,
    local_diagnosis,
    overall_status,
    render_json,
    render_text,
    ssh_config_path,
)
from gantry_sftp.session import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DEFAULT_REQUEST_TIMEOUT,
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
        # The value may itself contain `=`, which is why the split is on the first one only.
        (["ProxyCommand=ssh -W %h:%p bastion"], {"ProxyCommand": "ssh -W %h:%p bastion"}),
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

"""Building the ssh command line: ordering, defaults, and refusing injection.

This is the security-critical part of the transport and it is pure, so it is tested
exhaustively without spawning anything. The injection cases are not hypothetical -- the
strings below execute commands when passed to a real ssh without `--`.
"""

from __future__ import annotations

import itertools

import pytest

from gantry_sftp.exceptions import InsecureOptionWarning
from gantry_sftp.transport import (
    DEFAULT_SSH_OPTIONS,
    PASSWORD_AUTH_OPTIONS,
    build_ssh_argv,
    options_for_password_auth,
    resolve_ssh_executable,
)


def options_in(argv: list[str]) -> dict[str, str]:
    """Extract every -o option from an argv."""
    found = {}
    for flag, value in itertools.pairwise(argv):
        if flag == "-o":
            name, _, setting = value.partition("=")
            found[name] = setting
    return found


# --- ordering, which comes from OpenSSH's own sftp.c ------------------------------------


def test_the_tail_is_dash_s_then_dash_dash_then_host_then_subsystem():
    # `-s` is an ssh option meaning "the command is a subsystem name", so it must be parsed
    # as an option -- which means before `--`. Putting it after would make it part of the
    # remote command and the subsystem request would never happen. This ordering is copied
    # from sftp.c, not guessed.
    argv = build_ssh_argv("example.com")
    assert argv[-4:] == ["-s", "--", "example.com", "sftp"]


def test_the_executable_is_first():
    assert build_ssh_argv("h", ssh_executable="/usr/bin/ssh")[0] == "/usr/bin/ssh"


def test_a_custom_subsystem_replaces_the_trailing_name():
    argv = build_ssh_argv("h", subsystem="/usr/libexec/sftp-server")
    assert argv[-4:] == ["-s", "--", "h", "/usr/libexec/sftp-server"]


def test_everything_the_caller_asked_for_appears_before_the_separator():
    argv = build_ssh_argv("h", user="bob", port=2222, config_file="/dev/null", identity_file="/k")
    separator = argv.index("--")
    for expected in ("-l", "bob", "-p", "2222", "-F", "/dev/null", "-i", "/k"):
        assert expected in argv[:separator]


def test_argv_is_a_list_of_separate_arguments_never_a_string():
    # `shell=True` does not appear anywhere in this library, and argv being a list is what
    # makes that true rather than aspirational.
    argv = build_ssh_argv("h", user="bob")
    assert isinstance(argv, list)
    assert all(isinstance(item, str) for item in argv)
    assert "-l bob" not in argv
    assert argv[argv.index("-l") : argv.index("-l") + 2] == ["-l", "bob"]


# --- defaults ----------------------------------------------------------------------------


def test_batch_mode_and_strict_host_key_checking_are_on_by_default():
    options = options_in(build_ssh_argv("h"))
    assert options["BatchMode"] == "yes"
    assert options["StrictHostKeyChecking"] == "yes"


def test_local_command_and_forwarding_are_disabled_by_default():
    # A hostile or merely careless ssh_config can specify LocalCommand, which runs a program
    # on *this* machine at connection setup. OpenSSH's own sftp turns it off; so do we.
    options = options_in(build_ssh_argv("h"))
    assert options["PermitLocalCommand"] == "no"
    assert options["ClearAllForwardings"] == "yes"
    assert options["ForwardX11"] == "no"
    assert options["ForwardAgent"] == "no"


def test_control_master_no_means_do_not_host_multiplexing_not_do_not_use_it():
    # "no" declines to *become* a master. An existing master is still reused when
    # ControlPath points at one, which is where the connection-setup win comes from.
    assert options_in(build_ssh_argv("h"))["ControlMaster"] == "no"


def test_every_documented_default_actually_reaches_the_command_line():
    options = options_in(build_ssh_argv("h"))
    assert options == dict(DEFAULT_SSH_OPTIONS)


def test_caller_options_override_defaults_by_name():
    options = options_in(build_ssh_argv("h", options={"BatchMode": "no", "Compression": "yes"}))
    assert options["BatchMode"] == "no"
    assert options["Compression"] == "yes"
    assert options["StrictHostKeyChecking"] == "yes"


def test_options_are_emitted_in_a_stable_order():
    # Two identical calls must produce identical argv, or a recorded command line is not
    # comparable and a cache key built from one is unstable.
    assert build_ssh_argv("h", options={"B": "1", "A": "2"}) == build_ssh_argv(
        "h", options={"A": "2", "B": "1"}
    )


# --- weakening a security default is loud ------------------------------------------------


@pytest.mark.parametrize("setting", ["no", "accept-new", "off"])
def test_weakening_strict_host_key_checking_warns(setting: str):
    with pytest.warns(InsecureOptionWarning) as record:
        build_ssh_argv("h", options={"StrictHostKeyChecking": setting})
    assert f"set to {setting!r}" in str(record[0].message)
    assert "may be intercepted" in str(record[0].message)


def test_restating_the_default_does_not_warn():
    # Passing the same value explicitly is not a downgrade, and warning about it would
    # train people to silence the category.
    build_ssh_argv("h", options={"StrictHostKeyChecking": "yes"})


def test_overriding_an_unrelated_option_does_not_warn():
    build_ssh_argv("h", options={"Compression": "yes"})


# --- argument injection ------------------------------------------------------------------


INJECTION_ATTEMPTS = [
    pytest.param("-oProxyCommand=echo PWNED >&2", id="proxycommand"),
    pytest.param("-oPermitLocalCommand=yes", id="permitlocalcommand"),
    pytest.param("-E/tmp/pwned.log", id="logfile"),
    pytest.param("-i/tmp/attacker-key", id="identity"),
    pytest.param("--", id="bare-separator"),
    pytest.param("-", id="lone-dash"),
]


@pytest.mark.parametrize("host", INJECTION_ATTEMPTS)
def test_a_host_that_looks_like_an_option_is_refused(host: str):
    # `--` should already neutralise these. Rejecting them as well is the second,
    # independent defence: `--` handling is an OpenSSH behaviour we do not control across
    # the versions people actually run, and two defences fail independently.
    with pytest.raises(ValueError) as exc:
        build_ssh_argv(host)
    assert exc.value.args[0] == (
        f"host may not begin with '-': {host!r}; a leading dash makes a hostname "
        f"indistinguishable from an ssh option"
    )


@pytest.mark.parametrize("user", ["-oProxyCommand=id", "-l root"])
def test_a_username_that_looks_like_an_option_is_refused(user: str):
    with pytest.raises(ValueError):
        build_ssh_argv("h", user=user)


@pytest.mark.parametrize("char", ["\x00", "\n", "\r"])
def test_control_characters_are_refused_in_a_host(char: str):
    with pytest.raises(ValueError) as exc:
        build_ssh_argv(f"host{char}evil")
    assert exc.value.args[0].startswith("host may not contain")


@pytest.mark.parametrize("char", ["\x00", "\n", "\r"])
def test_a_newline_in_an_option_value_is_refused(char: str):
    # `-o` is parsed as a line of ssh_config. A newline inside it is a second directive we
    # did not intend to send -- the config-file equivalent of SQL injection.
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("h", options={"Compression": f"yes{char}ProxyCommand id"})
    assert exc.value.args[0].startswith("value of ssh option 'Compression' may not contain")


@pytest.mark.parametrize("char", ["\x00", "\n", "\r"])
def test_a_newline_in_an_option_name_is_refused(char: str):
    with pytest.raises(ValueError):
        build_ssh_argv("h", options={f"Compression{char}ProxyCommand id": "yes"})


def test_an_option_name_containing_equals_is_refused():
    # Otherwise "A=B" as a name produces `-oA=B=value`, which is not the option anyone meant.
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("h", options={"Proxy=Command": "id"})
    assert exc.value.args[0] == "ssh option name may not contain '=': 'Proxy=Command'"


def test_whitespace_in_a_host_is_refused():
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("host name")
    assert exc.value.args[0] == "host may not contain whitespace: 'host name'"


def test_an_at_sign_in_a_host_is_refused_with_a_pointer_to_the_right_parameter():
    # Splitting user@host here would mean validating a string we already decided is one
    # thing. Making the caller split it means both halves get checked.
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("bob@example.com")
    assert exc.value.args[0] == (
        "host may not contain '@': 'bob@example.com'; pass the username as user=... "
        "so both halves are validated separately"
    )


def test_an_empty_host_is_refused():
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("")
    assert exc.value.args[0] == "host may not be empty"


def test_an_empty_user_is_refused():
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("h", user="")
    assert exc.value.args[0] == "user may not be empty"


def test_an_empty_subsystem_is_refused():
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("h", subsystem="")
    assert exc.value.args[0] == "subsystem may not be empty"


@pytest.mark.parametrize("port", [0, -1, 65536, 1_000_000])
def test_an_out_of_range_port_is_refused(port: int):
    with pytest.raises(ValueError) as exc:
        build_ssh_argv("h", port=port)
    assert exc.value.args[0] == f"port must be between 1 and 65535, got {port}"


@pytest.mark.parametrize("port", [1, 22, 65535])
def test_a_valid_port_is_accepted(port: int):
    assert str(port) in build_ssh_argv("h", port=port)


# --- hosts that are legal but look unusual ----------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "192.0.2.1",
        "::1",
        "[2001:db8::1]",
        "my-ssh-config-alias",
        "host_with_underscores",
        "xn--bcher-kva.example",
    ],
)
def test_legitimate_hosts_are_accepted(host: str):
    # Rejecting an option-looking host must not turn into rejecting IPv6 literals or
    # ssh_config aliases, which are what a lot of real deployments actually use.
    assert build_ssh_argv(host)[-2] == host


# --- the password path's options ------------------------------------------------------------


def test_the_password_path_relaxes_batchmode_because_the_default_disables_askpass():
    # The finding D-78 was filed for, pinned as a test. `BatchMode=yes` does not discourage a
    # password prompt, it suppresses the askpass helper outright -- so without this line the
    # `password=` parameter would silently do nothing at all.
    assert DEFAULT_SSH_OPTIONS["BatchMode"] == "yes"
    assert options_for_password_auth(None)["BatchMode"] == "no"


def test_the_password_path_asks_for_the_interactive_methods_in_a_fixed_order():
    # Without this, ssh tries publickey first and offers every identity it can find; against
    # a server with a low MaxAuthTries the attempts run out before password is reached, and
    # the failure names nothing that is actually wrong.
    options = options_for_password_auth(None)
    assert options["PreferredAuthentications"] == "password,keyboard-interactive"
    # keyboard-interactive is not padding: appliances routinely offer only that one.
    assert "keyboard-interactive" in options["PreferredAuthentications"]


def test_the_password_path_asks_once_so_a_wrong_secret_is_not_offered_three_times():
    # OpenSSH's default is three prompts, each re-running the helper with the same wrong
    # secret. On a 9.8+ server that is three failures, which earns this source address a
    # PerSourcePenalties timeout that then breaks the *next* connection from this host.
    assert options_for_password_auth(None)["NumberOfPasswordPrompts"] == "1"


def test_every_password_option_except_batchmode_can_still_be_overridden():
    overridden = options_for_password_auth(
        {"PreferredAuthentications": "keyboard-interactive", "NumberOfPasswordPrompts": "3"}
    )
    assert overridden["PreferredAuthentications"] == "keyboard-interactive"
    assert overridden["NumberOfPasswordPrompts"] == "3"
    assert overridden["BatchMode"] == "no"


@pytest.mark.parametrize("spelling", ["yes", "YES", "Yes", " yes "])
def test_a_password_with_batchmode_yes_is_refused_as_the_contradiction_it_is(spelling):
    # Silently winning this argument in either direction is worse than refusing it: honouring
    # BatchMode would make password= a no-op, and honouring password= would override an
    # explicit security-shaped setting the caller wrote down.
    with pytest.raises(ValueError) as exc:
        options_for_password_auth({"BatchMode": spelling})
    assert exc.value.args[0] == (
        f"password= needs BatchMode=no, but options set BatchMode={spelling!r}; "
        f"BatchMode=yes suppresses the askpass helper outright, so ssh would never ask "
        f"for the password and the connection would fail with 'Permission denied'"
    )


def test_saying_batchmode_no_alongside_a_password_is_agreement_not_contradiction():
    assert options_for_password_auth({"BatchMode": "no"})["BatchMode"] == "no"


def test_the_password_options_layer_over_the_security_defaults_rather_than_replacing_them():
    # The layering is the part that could quietly go wrong: password auth must not cost the
    # host-key check or the LocalCommand defence.
    argv = build_ssh_argv("example.com", options=options_for_password_auth(None))
    options = options_in(argv)
    assert options["BatchMode"] == "no"
    assert options["StrictHostKeyChecking"] == "yes"
    assert options["PermitLocalCommand"] == "no"
    assert options["ClearAllForwardings"] == "yes"


def test_the_password_options_are_only_the_three_that_have_a_reason():
    # A guard on scope. Every entry here changes how authentication behaves, and the next
    # person to add one should have to change this test and say why.
    assert set(PASSWORD_AUTH_OPTIONS) == {
        "BatchMode",
        "PreferredAuthentications",
        "NumberOfPasswordPrompts",
    }


# --- executable resolution ----------------------------------------------------------------


def test_posix_resolution_defers_to_path():
    assert resolve_ssh_executable(platform="linux") == "ssh"
    assert resolve_ssh_executable(platform="darwin") == "ssh"


def test_windows_prefers_sysnative_when_it_exists(tmp_path):
    # A 32-bit Python on 64-bit Windows has System32 redirected to SysWOW64, where OpenSSH
    # is not. SysNative is the alias that reaches the real directory.
    sysnative = tmp_path / "SysNative" / "OpenSSH"
    sysnative.mkdir(parents=True)
    (sysnative / "ssh.exe").write_text("")
    system32 = tmp_path / "System32" / "OpenSSH"
    system32.mkdir(parents=True)
    (system32 / "ssh.exe").write_text("")

    resolved = resolve_ssh_executable(platform="win32", environ={"SystemRoot": str(tmp_path)})
    assert resolved == str(sysnative / "ssh.exe")


def test_windows_falls_back_to_system32_when_there_is_no_sysnative(tmp_path):
    # A 64-bit process has no SysNative at all, so assuming it would break the common case.
    system32 = tmp_path / "System32" / "OpenSSH"
    system32.mkdir(parents=True)
    (system32 / "ssh.exe").write_text("")

    resolved = resolve_ssh_executable(platform="win32", environ={"SystemRoot": str(tmp_path)})
    assert resolved == str(system32 / "ssh.exe")


def test_windows_falls_back_to_a_bare_name_when_nothing_is_found(tmp_path):
    assert (
        resolve_ssh_executable(platform="win32", environ={"SystemRoot": str(tmp_path)}) == "ssh.exe"
    )


def test_windows_without_systemroot_falls_back_to_a_bare_name():
    assert resolve_ssh_executable(platform="win32", environ={}) == "ssh.exe"

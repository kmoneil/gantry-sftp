"""The askpass helper: where the secret goes, and everywhere it must not.

The module under test exists to keep a password out of argv. That is a claim about a file, an
environment and a shell script, so the tests here run the helper for real rather than reading
its source and believing it -- ``printf '%s\\n' "$VAR"`` is safe and
``printf "$VAR\\n"`` is a format-string injection, and only executing the thing tells them
apart.

The end-to-end proof that a real ``ssh`` authenticates through it is in
``live-tests/test_password_auth.py``; this file is the fast lane over what gets written.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from gantry_sftp.transport import (
    ASKPASS_ANSWER_VARIABLE,
    ASKPASS_ARMING_VARIABLES,
    askpass_environment,
)

# Every one of these is a password a shell could mangle if the helper interpolated instead of
# quoting. `%s%d%n` is the format-string case, backticks and `$(...)` are command substitution,
# `-n` is the one printf itself could eat as an option, and the backslash is what `echo`
# expands and `printf '%s'` does not.
HOSTILE_PASSWORDS = [
    pytest.param("plain", id="plain"),
    pytest.param("with spaces", id="spaces"),
    pytest.param("$(touch /tmp/gantry-pwned)", id="command-substitution"),
    pytest.param("`touch /tmp/gantry-pwned`", id="backticks"),
    pytest.param("semi;colon && echo pwned", id="shell-operators"),
    pytest.param("%s%d%n", id="format-string"),
    pytest.param("-n", id="printf-option"),
    pytest.param("back\\slash", id="backslash"),
    pytest.param("quote'and\"quote", id="quotes"),
    pytest.param("glob*star?", id="glob"),
    pytest.param("unicode-ø-π", id="unicode"),
    pytest.param("$HOME$PATH${IFS}", id="variable-expansion"),
]


def run_helper(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the helper exactly as ``ssh`` would: exec it, read one line of stdout."""
    return subprocess.run(
        [env["SSH_ASKPASS"]],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )


# --- what reaches the helper, and in what form --------------------------------------------


@pytest.mark.parametrize("password", HOSTILE_PASSWORDS)
def test_the_helper_prints_the_password_unchanged(password):
    # The whole contract in one assertion: whatever ssh asked for, it gets back byte for
    # byte, followed by exactly one newline.
    with askpass_environment(password) as env:
        finished = run_helper(env)
    assert finished.stdout == f"{password}\n"


@pytest.mark.parametrize("password", HOSTILE_PASSWORDS)
def test_the_password_is_never_written_into_the_helper(password):
    # The file is disposable and world-legible in principle; the secret must not be in it.
    with askpass_environment(password) as env:
        source = Path(env["SSH_ASKPASS"]).read_text()
    assert password not in source
    assert ASKPASS_ANSWER_VARIABLE in source


def test_the_helper_answers_only_one_prompt():
    # ssh reads a line per prompt. One line out means the helper cannot accidentally answer
    # the *next* question -- which is what makes rejecting an embedded newline sufficient.
    with askpass_environment("secret") as env:
        finished = run_helper(env)
    assert finished.stdout.count("\n") == 1


def test_the_environment_carries_the_secret_and_arms_the_helper():
    with askpass_environment("secret") as env:
        assert env[ASKPASS_ANSWER_VARIABLE] == "secret"
        assert env["SSH_ASKPASS"] == str(Path(env["SSH_ASKPASS"]))
        # Measured against OpenSSH 10.0p2: SSH_ASKPASS alone does *not* arm the helper. This
        # is the variable that does it without requiring a display.
        assert env["SSH_ASKPASS_REQUIRE"] == "force"


@pytest.mark.parametrize("password", HOSTILE_PASSWORDS)
def test_the_environment_does_not_render_the_secret(password):
    # The environment dictionary is a live local for the whole connection, and a frame-locals
    # dumper renders every local with `repr`. So `repr` is the boundary, and it is the one
    # that was open: Sentry captures locals by default, and so do `pytest --showlocals`,
    # `rich` tracebacks and IPython's verbose mode.
    with askpass_environment(password) as env:
        assert password not in repr(env[ASKPASS_ANSWER_VARIABLE])


def test_rendering_the_whole_environment_does_not_disclose_the_secret():
    # The value-level assertion above cannot be written over the hostile set as a whole-dict
    # check: `-n` and `plain` occur inside inherited variables like LS_COLORS, so a substring
    # search would fail on the environment rather than on us. A canary settles it instead.
    canary = "hunter2-CANARY-must-not-appear"
    with askpass_environment(canary) as env:
        assert canary not in repr(env)
        assert "'<redacted>'" in repr(env)


def test_the_redacted_secret_is_still_a_string_everywhere_it_must_be():
    # The redaction is a `repr` that lies; everything else about the value has to keep telling
    # the truth, or `ssh` gets the wrong password and the failure looks like a bad credential.
    with askpass_environment("secret") as env:
        answer = env[ASKPASS_ANSWER_VARIABLE]
        assert isinstance(answer, str)
        assert answer == "secret"
        assert f"{answer}" == "secret"
        assert dict(env)[ASKPASS_ANSWER_VARIABLE] == "secret"
        # And the child -- the only consumer that matters -- reads it back intact.
        assert run_helper(env).stdout == "secret\n"


def test_the_helper_is_executable_by_its_owner_and_nobody_else():
    with askpass_environment("secret") as env:
        helper = Path(env["SSH_ASKPASS"])
        mode = stat.S_IMODE(helper.stat().st_mode)
        directory_mode = stat.S_IMODE(helper.parent.stat().st_mode)
    assert mode == 0o700, f"helper mode is {mode:o}"
    assert directory_mode == 0o700, f"helper directory mode is {directory_mode:o}"


# --- lifetime ------------------------------------------------------------------------------


def test_the_helper_is_removed_when_the_connection_ends():
    with askpass_environment("secret") as env:
        helper = Path(env["SSH_ASKPASS"])
        assert helper.exists()
    assert not helper.exists()
    assert not helper.parent.exists()


def test_the_directory_is_named_after_this_library_so_a_leak_can_be_attributed():
    # The removal above is what stops a leak; this is what makes one *attributable* if the
    # process is killed between the mkdtemp and the rmtree. A directory in `/tmp` called
    # `tmpab12cd` tells an operator nothing, and this is a directory that briefly holds the
    # helper `ssh` runs to answer a password prompt.
    with askpass_environment("secret") as env:
        directory = Path(env["SSH_ASKPASS"]).parent
        assert directory.name.startswith("gantry-sftp-askpass-")


def test_the_helper_is_removed_even_when_the_body_raises():
    # The failure path is the one that matters: a connection that fails is exactly when a
    # credential-adjacent temporary file would be left behind.
    captured: list[Path] = []

    def fail_inside_the_block() -> None:
        with askpass_environment("secret") as env:
            captured.append(Path(env["SSH_ASKPASS"]))
            raise RuntimeError("connection failed")

    with pytest.raises(RuntimeError):
        fail_inside_the_block()

    helper = captured[0]
    assert not helper.exists()
    assert not helper.parent.exists()


def test_a_cleanup_that_cannot_finish_does_not_replace_the_connection_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The reason the removal passes ``ignore_errors=True``, asserted rather than commented.

    A connection that fails is the case this whole path exists for, and the caller needs the
    exception that says *why* -- not a ``PermissionError`` from tidying up after it. The
    failure is made with real filesystem permissions rather than a stubbed ``rmtree``: a
    read-only parent is what actually stops the final ``rmdir``, and stubbing the function
    under test would only confirm which argument was passed to it.
    """
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def fail_with_an_undeletable_directory() -> None:
        with askpass_environment("secret") as env:
            # Read-only *parent*: the helper can still be unlinked, the `rmdir` of the
            # directory itself cannot.
            tmp_path.chmod(0o500)
            assert Path(env["SSH_ASKPASS"]).exists()
            raise RuntimeError("connection failed")

    try:
        with pytest.raises(RuntimeError) as refused:
            fail_with_an_undeletable_directory()
        assert refused.value.args[0] == "connection failed"
    finally:
        tmp_path.chmod(0o700)


# --- the base environment ------------------------------------------------------------------


def test_the_callers_environment_is_copied_rather_than_mutated():
    supplied = {"PATH": "/usr/bin"}
    with askpass_environment("secret", env=supplied) as env:
        assert env["PATH"] == "/usr/bin"
        assert env is not supplied
    assert supplied == {"PATH": "/usr/bin"}, "the caller's mapping was modified"


def test_no_env_inherits_this_process_because_a_child_with_an_env_inherits_nothing(monkeypatch):
    # Materialising os.environ is load-bearing rather than tidy: passing `env=` to a child
    # *replaces* its environment, so a password path that built the dict from scratch would
    # silently drop PATH, HOME and everything else the caller expects ssh to see.
    monkeypatch.setenv("GANTRY_TEST_MARKER", "inherited")
    with askpass_environment("secret") as env:
        assert env["GANTRY_TEST_MARKER"] == "inherited"


def test_an_explicit_environment_does_not_inherit():
    with askpass_environment("secret", env={"ONLY": "this"}) as env:
        assert set(env) == {"ONLY", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", ASKPASS_ANSWER_VARIABLE}


# --- refusals ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("password", "shown"),
    [
        pytest.param("first\nsecond", "'\\n'", id="newline"),
        pytest.param("first\rsecond", "'\\r'", id="carriage-return"),
        pytest.param("nul\x00byte", "'\\x00'", id="nul"),
    ],
)
def test_a_password_that_could_answer_two_prompts_is_refused(password, shown):
    # Not a style rule. The helper prints one line per prompt, so a password containing a
    # newline would put its tail in front of whatever ssh asks next.
    with pytest.raises(ValueError) as exc, askpass_environment(password):
        pytest.fail("should not have yielded an environment")
    assert exc.value.args[0] == (
        f"password may not contain {shown}; the askpass helper answers one prompt with one "
        f"line, and an embedded newline would answer the next prompt too"
    )


def test_windows_refuses_rather_than_writing_a_script_it_cannot_run(monkeypatch):
    # The helper is a POSIX shell script and Windows OpenSSH's prompting path has never been
    # run here. Refusing beats shipping an untested claim -- and beats leaving a file behind.
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(NotImplementedError) as exc, askpass_environment("secret"):
        pytest.fail("should not have yielded an environment")
    assert exc.value.args[0] == (
        "password= is not supported on Windows: the askpass helper is a POSIX shell "
        "script and Windows OpenSSH's prompting path has never been exercised here. "
        "Use key-based authentication, or supply your own SSH_ASKPASS via env="
    )


def test_the_password_is_validated_before_anything_is_written(tmp_path, monkeypatch):
    # Order matters: validation after mkdtemp would leave a directory behind on every
    # rejected password, and the rejection path is one nobody watches.
    monkeypatch.setattr("tempfile.mkdtemp", lambda **kwargs: pytest.fail("should not be reached"))
    with pytest.raises(ValueError), askpass_environment("two\nlines"):
        pytest.fail("should not have yielded an environment")


# --- the arming variables ------------------------------------------------------------------


def test_the_arming_variables_are_the_measured_set():
    # Sourced from a measurement against OpenSSH 10.0p2, not from ssh(1): WAYLAND_DISPLAY is
    # in the binary and documented nowhere. If this list shrinks, a connection that *could*
    # answer a prompt starts being told it could not.
    assert ASKPASS_ARMING_VARIABLES == ("SSH_ASKPASS_REQUIRE", "DISPLAY", "WAYLAND_DISPLAY")
    assert "SSH_ASKPASS" not in ASKPASS_ARMING_VARIABLES


def test_the_answer_variable_is_not_a_name_an_inherited_environment_would_collide_with():
    assert ASKPASS_ANSWER_VARIABLE.startswith("GANTRY_SFTP_")
    assert ASKPASS_ANSWER_VARIABLE not in os.environ

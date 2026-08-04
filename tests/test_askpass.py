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

import ast
import os
import stat
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

import anyio
import pytest
from anyio.from_thread import start_blocking_portal

import gantry_sftp
import gantry_sftp.sync
import gantry_sftp.transport
from gantry_sftp.sync import BoundPortal
from gantry_sftp.transport import (
    ASKPASS_ANSWER_VARIABLE,
    ASKPASS_ARMING_VARIABLES,
    Secret,
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


# --- Secret: the boundary a frame-locals dumper meets ---------------------------------------
#
# `Secret` existed and was applied at exactly one of the seven functions that take a
# `password`: `transport.open_ssh_transport`. The other six -- every entry point a caller
# actually reaches for -- held the plaintext in a decorated-generator frame or on a cached
# instance for the life of the connection, which is precisely the hazard `Secret`'s own
# docstring describes. Rebinding inside `open_ssh_transport` protects *its* local; a caller's
# frame is a different frame.
#
# Two tests, because they fail on different mistakes. The first catches a site that rebinds
# too late (after a `partial` has already captured the plaintext); the second catches a site
# that does not rebind at all, including one added next year.

REDACTED_PASSWORD = "correct-horse-battery-staple"

UNROUTABLE_PORT = 0
"""A port `build_ssh_argv` refuses, so the failure happens before anything is spawned.

The traceback still crosses every frame between the caller and the refusal, which is the whole
surface under test -- and no `ssh` child, no temporary directory and no network are involved,
so this stays in the fast lane the module docstring promises.
"""


def gantry_frames_rendering(exc: BaseException, needle: str) -> list[str]:
    """Every `gantry_sftp` frame local whose `repr` carries `needle`.

    `capture_locals=True` is not a contrivance: it is what Sentry does by default, and what
    `pytest --showlocals`, `rich` tracebacks and IPython's verbose mode all do. Each renders a
    local with `repr`, which is why `repr` is the boundary `Secret` defends.
    """
    rendered = traceback.TracebackException.from_exception(exc, capture_locals=True)
    return [
        f"{Path(frame.filename).name}:{frame.lineno} {frame.name}() -> {name}"
        for frame in rendered.stack
        if "gantry_sftp" in (frame.filename or "")
        for name, value in (frame.locals or {}).items()
        if needle in value
    ]


def refuse_through_async_connect() -> None:
    async def attempt() -> None:
        async with gantry_sftp.connect(
            "example.com",
            port=UNROUTABLE_PORT,
            password=REDACTED_PASSWORD,
            config_file=os.devnull,
        ):
            pytest.fail("the port should have been refused")

    anyio.run(attempt)


def refuse_through_async_open_ssh_transport() -> None:
    async def attempt() -> None:
        async with gantry_sftp.transport.open_ssh_transport(
            "example.com",
            port=UNROUTABLE_PORT,
            password=REDACTED_PASSWORD,
            config_file=os.devnull,
        ):
            pytest.fail("the port should have been refused")

    anyio.run(attempt)


def refuse_through_sync_connect() -> None:
    with gantry_sftp.sync.connect(
        "example.com", port=UNROUTABLE_PORT, password=REDACTED_PASSWORD, config_file=os.devnull
    ):
        pytest.fail("the port should have been refused")


def refuse_through_sync_open_ssh_transport() -> None:
    with gantry_sftp.sync.open_ssh_transport(
        "example.com", port=UNROUTABLE_PORT, password=REDACTED_PASSWORD, config_file=os.devnull
    ):
        pytest.fail("the port should have been refused")


def refuse_through_bound_portal_connect() -> None:
    with (
        start_blocking_portal() as portal,
        BoundPortal(portal).connect(
            "example.com", port=UNROUTABLE_PORT, password=REDACTED_PASSWORD, config_file=os.devnull
        ),
    ):
        pytest.fail("the port should have been refused")


def refuse_through_bound_portal_open_ssh_transport() -> None:
    with (
        start_blocking_portal() as portal,
        BoundPortal(portal).open_ssh_transport(
            "example.com", port=UNROUTABLE_PORT, password=REDACTED_PASSWORD, config_file=os.devnull
        ),
    ):
        pytest.fail("the port should have been refused")


@pytest.mark.parametrize(
    "reach_the_refusal",
    [
        pytest.param(refuse_through_async_connect, id="connect"),
        pytest.param(refuse_through_async_open_ssh_transport, id="open_ssh_transport"),
        pytest.param(refuse_through_sync_connect, id="sync.connect"),
        pytest.param(refuse_through_sync_open_ssh_transport, id="sync.open_ssh_transport"),
        pytest.param(refuse_through_bound_portal_connect, id="BoundPortal.connect"),
        pytest.param(
            refuse_through_bound_portal_open_ssh_transport, id="BoundPortal.open_ssh_transport"
        ),
    ],
)
def test_a_failed_connection_shows_no_frame_holding_the_plaintext_password(reach_the_refusal):
    # The regression test for the finding. Before the fix this failed on four of the six ids,
    # and `BoundPortal.connect` reported the secret *twice* in one frame -- once as the local
    # and once inside the `functools.partial` repr, which renders every argument bound into it.
    with pytest.raises(ValueError) as refusal:
        reach_the_refusal()

    showing = gantry_frames_rendering(refusal.value, REDACTED_PASSWORD)
    assert not showing, (
        f"the password is readable in {len(showing)} frame local(s) that a traceback reporter "
        f"would capture: {showing}"
    )


def test_the_redacted_password_is_still_the_password_everywhere_it_has_to_be():
    # `Secret` defends `repr` and nothing else on purpose: `ssh` receives the real value
    # through the child's environment. A wrapper that broke equality or `str` would break
    # authentication rather than protect it.
    secret = Secret(REDACTED_PASSWORD)
    assert repr(secret) == "'<redacted>'"
    assert str(secret) == REDACTED_PASSWORD
    assert secret == REDACTED_PASSWORD
    assert f"{secret}" == REDACTED_PASSWORD
    assert repr({"GANTRY_SFTP_ASKPASS_ANSWER": secret}) == (
        "{'GANTRY_SFTP_ASKPASS_ANSWER': '<redacted>'}"
    )


def test_secret_is_importable_from_the_package_the_docstrings_name():
    # `_logging.py` cited `gantry_sftp.transport.Secret` while `Secret` was reachable only
    # through the private `transport._askpass`, so both references were dead -- and every
    # entry point that has to wrap lives outside that package.
    assert gantry_sftp.transport.Secret is Secret
    assert "Secret" in gantry_sftp.transport.__all__


# --- the same rule, derived rather than restated ---------------------------------------------


def functions_taking_a_password() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Every function in the shipped source that declares a `password` parameter.

    Read off the package that is actually imported rather than off a path resolved from this
    file, so a mutation run reads its own copy of the source instead of the pristine tree.
    """
    root = Path(gantry_sftp.__file__).parent
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for module in sorted(root.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        owners = {
            child: node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
            if isinstance(node, ast.ClassDef)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            arguments = node.args
            declared = arguments.posonlyargs + arguments.args + arguments.kwonlyargs
            if not any(argument.arg == "password" for argument in declared):
                continue
            owner = owners.get(node)
            qualified = f"{owner.name}.{node.name}" if owner is not None else node.name
            found[f"{module.relative_to(root).as_posix()}:{qualified}"] = node
    return found


MUST_WRAP_THE_PASSWORD = frozenset(
    {
        "_connect.py:connect",
        "fsspec.py:GantrySFTPFileSystem.__init__",
        "sync.py:connect",
        "sync.py:open_ssh_transport",
        "sync.py:BoundPortal.connect",
        "sync.py:BoundPortal.open_ssh_transport",
        "transport/_askpass.py:_askpass_environment",
        "transport/_askpass.py:askpass_environment",
        "transport/_subprocess.py:open_ssh_transport",
    }
)
"""Every function whose `password` outlives the call, and must therefore become a `Secret`.

Six of these are decorated generators, so the frame holding the parameter stays alive for as
long as the `with` block does. The seventh, `GantrySFTPFileSystem.__init__`, is not a generator
at all -- fsspec's registry caches the instance for the life of the process, so `self._password`
is what an object dump renders instead.
"""

EXEMPT_FROM_WRAPPING = {
    "transport/_askpass.py:_validate_password": (
        "a private predicate with one caller, which wraps *before* calling it -- deliberately, "
        "because this is the function that raises, so its frame is the one guaranteed to be in "
        "a traceback. It receives a Secret and holds nothing else; wrapping again here would "
        "redact an already-redacted value and hide that the ordering above is load-bearing"
    ),
    "transport/_subprocess.py:_askpass_is_armed": (
        "reads `password is not None` and nothing else; the value is never bound or rendered"
    ),
}
"""Functions that take a `password` and legitimately do not wrap it, each with its reason.

A reason rather than a bare list, because the next person to add one has to write down why --
which is the step that would have caught the six sites this section exists for.
"""


def wraps_its_password(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether the body ever builds a `Secret` out of the `password` parameter."""
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "Secret"
        and any(
            isinstance(argument, ast.Name) and argument.id == "password" for argument in call.args
        )
        for call in ast.walk(node)
    )


def test_every_function_taking_a_password_has_been_decided_about():
    # The half a per-site fix cannot cover: a *new* entry point. This is the same technique
    # `tests/test_sync_facade.py` uses on the async surface -- derive the set from the code, so
    # an addition fails by name here rather than by nobody noticing.
    assert set(functions_taking_a_password()) == MUST_WRAP_THE_PASSWORD | set(EXEMPT_FROM_WRAPPING)


@pytest.mark.parametrize("where", sorted(MUST_WRAP_THE_PASSWORD))
def test_it_rebinds_the_password_to_a_secret(where):
    assert wraps_its_password(functions_taking_a_password()[where]), (
        f"{where} takes a password that outlives the call and never wraps it in Secret(), so "
        f"the plaintext is what a frame-locals dumper renders"
    )


# --- D-144: the mechanism's own two frames -----------------------------------------------------
#
# `askpass_environment` is public, is a @contextmanager, and holds `password` for the caller's
# whole block -- and so does the `_askpass_environment` body D-107 split out for the mutation
# lane. Neither rebound until D-144. Both were safe only because `open_ssh_transport` wrapped
# before calling in, which is not a property a *public* function may lean on: this one is
# exported for a caller supplying their own helper through `env=`.

D144_CANARY = "canary-D144-must-not-appear"


def test_the_public_helpers_live_frames_do_not_hold_the_plaintext():
    # Reached directly rather than through `open_ssh_transport`, so nothing wrapped on the way
    # in -- the case the exemption used to cover.
    #
    # Inspects the *live* generator frames rather than a traceback, and the difference is the
    # whole reason this test is written the way it is. Raising inside the caller's block does
    # not put these frames in that exception's traceback, so the obvious version of this test
    # passes with the fix and without it. What `Secret`'s docstring actually claims is that
    # these frames "stay alive for the whole connection" -- so the honest check is to open the
    # block and read them while they are, which is what a live-stack dumper walks.
    manager = askpass_environment(D144_CANARY)
    with manager as env:
        assert env[ASKPASS_ANSWER_VARIABLE] == D144_CANARY
        # The wrapper's own frame, and the split body it is delegating into via `yield from`.
        # Both are suspended at their yield and both are alive for as long as this block is.
        wrapper = manager.gen
        body = wrapper.gi_yieldfrom
        frames = [wrapper.gi_frame, body.gi_frame]
        assert all(frames), "both generators should be suspended, not finished"

        showing = [
            f"{Path(frame.f_code.co_filename).name}:{frame.f_code.co_name}() -> {name}"
            for frame in frames
            for name, value in frame.f_locals.items()
            if D144_CANARY in repr(value)
        ]
        assert not showing, f"a live frame renders the password: {showing}"


def test_a_refused_password_does_not_disclose_itself_in_the_refusal():
    # The ordering `_askpass_environment` documents. `_validate_password` is the function that
    # raises, so its frame is the one *guaranteed* to reach a traceback -- which makes "wrap
    # before validating" load-bearing rather than tidy. Wrapping afterwards would leave the one
    # path that always produces a traceback as the one path that discloses.
    refused = f"{D144_CANARY}\nsecond-line"
    with pytest.raises(ValueError) as failure, askpass_environment(refused):
        pytest.fail("should not have yielded an environment")

    assert D144_CANARY not in failure.value.args[0]
    showing = gantry_frames_rendering(failure.value, D144_CANARY)
    assert not showing, f"the refused password is readable in {showing}"


def test_wrapping_an_already_wrapped_secret_changes_nothing():
    # After D-144 double wrapping is the normal case rather than an accident: open_ssh_transport
    # wraps, then askpass_environment wraps what it was handed, then the body wraps again. Assert
    # it rather than rely on `str` subclassing behaving.
    once = Secret(D144_CANARY)
    twice = Secret(once)
    assert twice == D144_CANARY
    assert str(twice) == D144_CANARY
    assert repr(twice) == "'<redacted>'"
    assert isinstance(twice, str)


def test_the_secret_still_reaches_the_child_intact_through_both_wrappings():
    # The half that must not break: `ssh` needs the real bytes. This runs the helper for real,
    # which is what the rest of this module does and why it is the check that matters.
    with askpass_environment(D144_CANARY) as env:
        assert run_helper(env).stdout == f"{D144_CANARY}\n"

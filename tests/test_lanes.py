"""The lane runner, and the enumerators that have to agree with it.

`scripts/lanes.py` exists so that "how this project runs its proofs" has one spelling. That
only holds if adding a lane is *forced* to update the places that list lanes -- the CI
workflow and the README -- so most of this module is the sweep that DoD 2 asks for, applied to
lanes instead of to packet types.

The runner is loaded by path rather than imported. `scripts/` is not a package and giving it
an `__init__.py` to suit a test would make a shipping decision on a test's behalf.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LANES_PATH = REPO_ROOT / "scripts" / "lanes.py"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _load_runner():
    spec = importlib.util.spec_from_file_location("gantry_lane_runner", LANES_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution, not after: the runner uses `from __future__ import
    # annotations`, so @dataclass resolves its field types as strings through
    # `sys.modules[cls.__module__].__dict__`, and a module that is not there yet gives an
    # AttributeError on None several frames inside dataclasses.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lanes = _load_runner()

WORKFLOW_TEXT = WORKFLOW_PATH.read_text(encoding="utf-8")
DEVELOPMENT_TEXT = (REPO_ROOT / "docs" / "development.md").read_text(encoding="utf-8")
"""Where the lane table lives since D-125 split the README into `docs/`.

It moved with the rest of the contributor prose, and this assertion moved with it rather than
being dropped: a lane that exists and is documented nowhere is a lane nobody runs.
"""
PRECOMMIT_TEXT = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")


def path_arguments(lane) -> list[str]:
    """Every argument of a lane that names something on disk."""
    return [arg for arg in lane.args if "/" in arg or arg.endswith(".py")]


# ---------------------------------------------------------------------------
# The sweep: everything that enumerates lanes has to know about all of them
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lane", lanes.LANES, ids=lambda lane: lane.name)
def test_every_lane_is_invoked_by_name_in_the_ci_workflow(lane) -> None:
    assert f"lanes.py {lane.name}" in WORKFLOW_TEXT


@pytest.mark.parametrize("lane", lanes.LANES, ids=lambda lane: lane.name)
def test_every_lane_is_named_in_the_development_docs(lane) -> None:
    assert f"lanes.py {lane.name}" in DEVELOPMENT_TEXT


def test_the_workflow_spells_out_no_test_command_of_its_own() -> None:
    # Two spellings of "run the tests" is how CI ends up with one set of flags and the
    # developer with another. Everything the workflow runs goes through the lane runner.
    # Asserted over the `run:` steps rather than the whole file, so the comments above them
    # are still free to explain what a lane is.
    commands = re.findall(r"^\s*- run:\s*(.+)$", WORKFLOW_TEXT, flags=re.MULTILINE)
    assert commands
    assert [command for command in commands if "pytest" in command] == []


def test_the_pre_push_hook_runs_the_fast_lane_and_not_a_second_spelling_of_it() -> None:
    fast = lanes.LANES_BY_NAME["fast"]
    assert " ".join(fast.args) in PRECOMMIT_TEXT


# ---------------------------------------------------------------------------
# The deprecation lane
# ---------------------------------------------------------------------------


def test_the_deprecation_hook_is_wired_to_a_config_that_exists() -> None:
    """The hook and its config are two files, and only one of them fails loudly when deleted.

    `basedpyright -p <missing file>` is an error, but a config that has quietly lost
    `reportDeprecated` is a hook that runs, prints `0 errors` and checks nothing -- which is
    the failure mode this asserts against, because it looks exactly like passing.
    """
    assert "-p pyrightconfig.deprecations.json" in PRECOMMIT_TEXT
    config = json.loads((REPO_ROOT / "pyrightconfig.deprecations.json").read_text(encoding="utf-8"))
    assert config["reportDeprecated"] == "error"
    # Type checking is off on purpose: `[tool.pyright]` is the IDE's config and is not a gate,
    # and this lane must not become a third one by accident.
    assert config["typeCheckingMode"] == "off"


def test_the_deprecation_lane_covers_every_directory_of_python_in_the_repository() -> None:
    """Scope is the whole repository, not `src`, unlike mypy and ty.

    An example is documentation people copy and a test is the pattern the next test is written
    from, so a deprecated spelling in either is on its way into shipped code.
    """
    config = json.loads((REPO_ROOT / "pyrightconfig.deprecations.json").read_text(encoding="utf-8"))
    assert {"src", "tests", "examples", "live-tests", "benchmarks", "scripts"} <= set(
        config["include"]
    )
    # mutants/ is a generated copy of src/ and would double every finding in it.
    assert "mutants" in config["exclude"]


# ---------------------------------------------------------------------------
# The parked-worktree warning
# ---------------------------------------------------------------------------

PARKED_SCRIPT = REPO_ROOT / "scripts" / "warn_parked_worktrees.sh"

GIT_ENV = {
    # `~/.gitconfig` is a read-only host mount here and a developer's own config anywhere else,
    # so a repository built for a test resolves its identity, its default branch and whether it
    # signs commits from the machine it happens to run on. DoD 1: control the environment.
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def _hook_block(hook_id: str) -> str:
    """The one hook's settings, so a key asserted here cannot be satisfied by another hook.

    Comments are dropped rather than kept. A stanza runs to the start of the next `- id:`, so
    the prose introducing the *following* hook lands at the end of this one -- and every key
    here is also a word somebody explains in a comment, which is a control test that fails for
    a reason unrelated to what it controls.
    """
    blocks = re.split(r"^\s*- id: ", PRECOMMIT_TEXT, flags=re.MULTILINE)
    matching = [block for block in blocks if block.startswith(f"{hook_id}\n")]
    assert len(matching) == 1
    settings = [line for line in matching[0].splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(settings)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        env={**os.environ, **GIT_ENV},
        capture_output=True,
        text=True,
        check=True,
    )


def _repository(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "file.txt").write_text("first\n", encoding="utf-8")
    _git(repo, "add", "file.txt")
    _git(repo, "commit", "--quiet", "-m", "first")
    return repo


def _warn(cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PARKED_SCRIPT)],
        cwd=cwd,
        env={**os.environ, **GIT_ENV},
        capture_output=True,
        text=True,
        # The return code is the assertion in every test below -- it is what proves the hook
        # warns rather than gates -- so raising on it here would delete the thing under test.
        check=False,
    )


def test_the_parked_worktree_hook_runs_a_script_that_exists() -> None:
    assert "bash scripts/warn_parked_worktrees.sh" in PRECOMMIT_TEXT
    assert PARKED_SCRIPT.is_file()


def test_the_parked_worktree_hook_is_verbose_or_it_reports_into_a_void() -> None:
    """`verbose` is the difference between this hook working and this hook existing.

    pre-commit prints the stdout of a hook that *fails*. This one never fails -- that is its
    design, argued in the script's header -- so without `verbose: true` every warning it writes
    is discarded, the hook passes, and the commit looks checked. It is the failure mode that
    looks exactly like the success one, so it is asserted rather than remembered.
    """
    block = _hook_block("parked-worktrees")
    assert "verbose: true" in block
    # It reads the worktree list rather than the staged files, so file filters would gate it on
    # something unrelated to what it checks.
    assert "always_run: true" in block
    assert "pass_filenames: false" in block


def test_no_other_hook_was_made_verbose_by_this_one() -> None:
    # The control for the assertion above: if `_hook_block` returned the whole file, every hook
    # would appear verbose and the test above would pass without wiring anything.
    assert "verbose" not in _hook_block("forbid-exec-bit")


def test_a_repository_with_nothing_parked_says_nothing(tmp_path: Path) -> None:
    done = _warn(_repository(tmp_path))
    assert done.returncode == 0
    assert done.stdout == ""


def test_a_parked_worktree_is_named_with_its_branch(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    _git(repo, "worktree", "add", "--quiet", "-b", "worktree-parked", ".claude/worktrees/parked")

    done = _warn(repo)

    # Exit 0 is the point, not an oversight: working in a worktree is supported, so a gate here
    # would fail the normal case and get itself removed. See the script's header.
    assert done.returncode == 0
    assert "1 parked worktree(s)" in done.stdout
    assert ".claude/worktrees/parked" in done.stdout
    assert "[worktree-parked]" in done.stdout
    assert "git worktree remove --force" in done.stdout


def test_a_worktree_outside_the_sessions_directory_is_not_reported(tmp_path: Path) -> None:
    # The decoy. A hook that warned about every worktree would be right about this one too, and
    # would be noise on the deliberate, hand-made kind that is nobody's forgotten session.
    repo = _repository(tmp_path)
    _git(repo, "worktree", "add", "--quiet", "-b", "feature", str(tmp_path / "elsewhere"))

    done = _warn(repo)

    assert done.returncode == 0
    assert done.stdout == ""


def test_the_worktree_being_committed_from_does_not_report_itself(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    parked = repo / ".claude" / "worktrees" / "parked"
    _git(repo, "worktree", "add", "--quiet", "-b", "worktree-parked", str(parked))

    done = _warn(parked)

    assert done.returncode == 0
    assert done.stdout == ""


def test_a_registration_whose_directory_is_gone_is_still_reported(tmp_path: Path) -> None:
    """The cheapest way to lose one is to delete the directory and leave the registration.

    It is also the case that breaks the obvious implementation: reading the tip with
    `git -C <path>` errors on exactly the worktree most worth reporting, which under `set -e`
    is a hook that dies instead of warning.
    """
    repo = _repository(tmp_path)
    parked = repo / ".claude" / "worktrees" / "parked"
    _git(repo, "worktree", "add", "--quiet", "-b", "worktree-parked", str(parked))
    shutil.rmtree(parked)

    done = _warn(repo)

    assert done.returncode == 0
    assert ".claude/worktrees/parked" in done.stdout
    assert "directory is gone" in done.stdout


def test_the_ide_checker_treats_an_untyped_dependency_as_untyped() -> None:
    """Three checkers, one dependency, one answer about whether it is typed.

    pyright's default is to infer types from an untyped package's source, which for fsspec reads
    each parameter's *default value* as its declared type -- `callback=NoOpCallback()` becomes
    `callback: NoOpCallback`, `block_size="default"` becomes `block_size: str`. That produced
    seven errors in `fsspec.py`, every one of them a contract fsspec does not have (D-109). PEP
    561 and the mypy override beside it both say a package with no `py.typed` is not typed; this
    is that same answer in the third checker's spelling, and flipping it back would reintroduce
    the seven as if they were findings.
    """
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        pyright = tomllib.load(handle)["tool"]["pyright"]
    assert pyright["useLibraryCodeForTypes"] is False


def test_both_in_venv_checkers_have_the_deprecation_rule_on() -> None:
    """The lane above is a stopgap, and a stopgap nobody revisits is a permanent dependency.

    mypy's and ty's bundled typeshed still declare `contextmanager` as a single un-deprecated
    overload, so neither sees the `-> Iterator[T]` form that D-108 removed; both start seeing it
    the moment they vendor a newer snapshot, and only if the rule is enabled by then.
    """
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)["tool"]
    assert "deprecated" in config["mypy"]["enable_error_code"]
    # ty reports deprecation as a warning, and `ty check` exits 0 on warnings.
    assert config["ty"]["rules"]["deprecated"] == "error"


@pytest.mark.parametrize("lane", lanes.LANES, ids=lambda lane: lane.name)
def test_a_lane_that_does_not_gate_has_to_say_why(lane) -> None:
    # `reports_only` is prose, not a flag, so opting a lane out of gating is a written act
    # that a reader can disagree with.
    assert lane.gates or len(lane.reports_only) > 40


@pytest.mark.parametrize("lane", lanes.LANES, ids=lambda lane: lane.name)
def test_every_lane_says_what_it_needs(lane) -> None:
    assert len(lane.needs) > 10


@pytest.mark.parametrize("lane", lanes.LANES, ids=lambda lane: lane.name)
def test_every_path_a_lane_names_exists(lane) -> None:
    for argument in path_arguments(lane):
        assert (REPO_ROOT / argument).exists(), argument


def test_every_directory_of_tests_is_reachable_from_some_lane() -> None:
    # A new test root that no lane runs is a suite nothing executes. `tests` and `examples`
    # arrive through pytest's own `testpaths`; the rest have to be named by a lane.
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        testpaths = tomllib.load(handle)["tool"]["pytest"]["ini_options"]["testpaths"]
    reached = {*testpaths}
    for lane in lanes.LANES:
        reached.update(argument.split("/", 1)[0] for argument in path_arguments(lane))
    assert {"tests", "examples", "live-tests", "benchmarks"} <= reached


# ---------------------------------------------------------------------------
# The workflow's own properties
# ---------------------------------------------------------------------------


def test_every_third_party_action_is_pinned_to_a_commit_sha() -> None:
    # A floating tag is a mutable reference to somebody else's code running with a token in
    # scope. This project spawns `ssh` and handles credentials; it does not get to be
    # relaxed about that. The trailing comment is what makes the pin re-readable.
    uses = re.findall(r"uses:\s*(\S+)(.*)$", WORKFLOW_TEXT, flags=re.MULTILINE)
    assert uses
    for reference, trailer in uses:
        owner_repo, _, pin = reference.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", pin), f"{owner_repo} is not pinned to a SHA"
        assert re.search(r"#\s*v\d", trailer), f"{owner_repo} has no version comment"


def test_no_run_step_interpolates_a_workflow_context() -> None:
    # The Actions analogue of this project's argv-injection rule. `${{ ... }}` inside a `run:`
    # block is substituted into the shell *before* it executes, so a branch name or PR title
    # containing a metacharacter runs as code. Nothing here needs one.
    commands = re.findall(r"^\s*- run:\s*(.+)$", WORKFLOW_TEXT, flags=re.MULTILINE)
    assert [command for command in commands if "${{" in command] == []


def test_the_workflow_never_triggers_on_pull_request_target() -> None:
    # `pull_request_target` runs the *base* workflow with secrets in scope against a fork's
    # code. `pull_request` is the one that does not.
    assert "pull_request_target" not in WORKFLOW_TEXT
    assert "pull_request:" in WORKFLOW_TEXT


def test_the_workflow_asks_for_no_more_than_read_access() -> None:
    assert "permissions:\n  contents: read\n" in WORKFLOW_TEXT


def test_the_windows_job_reports_rather_than_gates() -> None:
    # Transfers are POSIX-only by decision, not by omission (see session/_platform.py), so
    # every row that moves bytes fails on Windows. When the out-of-scope rows are marked --
    # or a fallback lands -- this assertion is the thing that says the job may now block a
    # change, and it has to be edited deliberately for that to happen.
    assert "continue-on-error: ${{ matrix.os == 'windows-latest' }}" in WORKFLOW_TEXT


# ---------------------------------------------------------------------------
# Resolving the tools
# ---------------------------------------------------------------------------


def test_a_tool_resolves_under_bin_on_posix() -> None:
    resolved = lanes.venv_executable("pytest", platform="linux", venv=Path("/v"))
    assert resolved == Path("/v/bin/pytest")


def test_a_tool_resolves_under_scripts_with_an_exe_suffix_on_windows() -> None:
    resolved = lanes.venv_executable("pytest", platform="win32", venv=Path("/v"))
    assert resolved == Path("/v/Scripts/pytest.exe")


def test_a_lanes_argv_names_the_venv_tool_and_never_a_bare_command() -> None:
    argv = lanes.lane_argv(lanes.LANES_BY_NAME["fast"])
    assert argv[0] == str(REPO_ROOT / ".venv" / "bin" / "python")
    assert argv[1:] == ["-m", "pytest"]


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def test_no_lane_is_run_through_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(lanes, "lane_argv", lambda lane: [sys.executable, lane.name])
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert lanes.main(["fast"]) == 0
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert "shell" not in kwargs


def test_a_lanes_environment_is_layered_over_the_callers_rather_than_replacing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D-115. The `leaks` lane is only a lane because of its variable, so it has to arrive.

    And the layering is the part worth pinning: replacing the environment rather than adding
    to it would take PATH and HOME away from the subprocess, which fails in a way that blames
    the tests rather than the runner.
    """
    calls: list[dict[str, object]] = []

    def fake_run(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setenv("SOMETHING_THE_CALLER_SET", "kept")
    monkeypatch.setattr(lanes, "lane_argv", lambda lane: [sys.executable, lane.name])
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert lanes.main(["leaks"]) == 0
    environment = calls[0]["env"]
    assert isinstance(environment, dict)
    assert environment["GANTRY_SFTP_LEAK_CHECK"] == "1"
    assert environment["SOMETHING_THE_CALLER_SET"] == "kept"


def test_a_lane_with_no_environment_of_its_own_inherits_rather_than_being_handed_a_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`env=None` is inheritance. Every lane but one wants exactly that."""
    calls: list[dict[str, object]] = []

    def fake_run(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(lanes, "lane_argv", lambda lane: [sys.executable, lane.name])
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert lanes.main(["fast"]) == 0
    assert calls[0]["env"] is None


def test_the_table_shows_a_lanes_environment_so_the_runs_line_can_be_copied() -> None:
    """A `runs:` line that omits the variable is a line that does something else when pasted."""
    table = lanes.describe()
    assert "GANTRY_SFTP_LEAK_CHECK=1 .venv/bin/python -m pytest" in table


def test_lanes_run_in_the_order_given(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[str] = []

    def fake_run(argv, **kwargs):
        ran.append(argv[1])
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(lanes, "lane_argv", lambda lane: [sys.executable, lane.name])
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert lanes.main(["live", "fast", "matrix"]) == 0
    assert ran == ["live", "fast", "matrix"]


def test_a_failing_lane_stops_the_ones_after_it(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[str] = []

    def fake_run(argv, **kwargs):
        ran.append(argv[1])
        return subprocess.CompletedProcess(argv, 3 if argv[1] == "gates" else 0)

    monkeypatch.setattr(lanes, "lane_argv", lambda lane: [sys.executable, lane.name])
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert lanes.main(["gates", "fast"]) == 3
    assert ran == ["gates"]


def test_a_dry_run_prints_the_argv_and_spawns_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("a dry run must not spawn anything")

    monkeypatch.setattr(subprocess, "run", explode)

    assert lanes.main(["-n", "netem"]) == 0
    out = capsys.readouterr().out
    assert ">>> netem: " in out
    assert "live-tests/test_netem_pipelining.py" in out


def test_a_missing_tool_is_reported_as_a_missing_sync(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(lanes, "REPO_ROOT", tmp_path)

    assert lanes.main(["fast"]) == 127
    missing = tmp_path / ".venv" / "bin" / "python"
    assert capsys.readouterr().err == (
        f"error: {missing} is not there -- run `uv sync` first "
        f"(and `uv sync --group bench` for the lanes whose prerequisites say so)\n"
    )


def test_an_unknown_lane_names_the_ones_that_exist(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert lanes.main(["fats"]) == 2
    assert capsys.readouterr().err == (
        "error: unknown lane 'fats'; known lanes are "
        "gates, fast, leaks, live, matrix, netem, benchmarks, cost, mutation\n"
    )


# ---------------------------------------------------------------------------
# The table, which is the discovery path
# ---------------------------------------------------------------------------


def test_with_no_arguments_it_prints_the_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert lanes.main([]) == 0
    assert capsys.readouterr().out == lanes.describe() + "\n"


@pytest.mark.parametrize("lane", lanes.LANES, ids=lambda lane: lane.name)
def test_the_table_carries_what_a_lane_is_for_and_what_it_needs(lane) -> None:
    # Whitespace-normalised on both sides: the table wraps its prose, so an exact substring
    # match would be asserting the wrap column rather than the content.
    table = " ".join(lanes.describe().split())
    assert lane.name in table
    assert " ".join(lane.summary.split()) in table
    assert " ".join(lane.needs.split()) in table
    assert lane.takes in table
    assert ("gates" if lane.gates else "reports only") in table
    if lane.reports_only:
        assert " ".join(lane.reports_only.split()) in table

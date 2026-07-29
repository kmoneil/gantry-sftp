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
import re
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
README_TEXT = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
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
def test_every_lane_is_named_in_the_readme(lane) -> None:
    assert f"lanes.py {lane.name}" in README_TEXT


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
    # os.pread and os.pwrite are documented Unix-only and the data path calls both, so the
    # transfer rows cannot pass on Windows. When that changes, this assertion is the thing
    # that says the job may now block a change.
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
        "gates, fast, live, matrix, netem, benchmarks, mutation\n"
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

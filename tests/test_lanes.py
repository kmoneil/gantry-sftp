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
RELEASE_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"
RELEASE_TEXT = RELEASE_PATH.read_text(encoding="utf-8")
WORKFLOWS = {"ci.yml": WORKFLOW_TEXT, "release.yml": RELEASE_TEXT}
"""Both workflows, because the properties below are about all of them and only one was read.

The action-pinning and context-interpolation rules were written for `ci.yml` and asserted only
there, while `release.yml` -- the one that runs with permission to publish -- was covered by a
comment saying it followed the same rule. A rule enforced on the less dangerous of two files is
a rule with its exception in the right place to hurt.
"""
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
# The API-consumer type gate (D-152)
# ---------------------------------------------------------------------------

CONSUMER_CONFIG = REPO_ROOT / "mypy.consumers.ini"

CONSUMER_LANES = {"benchmarks": "live-tests", "live-tests": "tests"}
"""Each API-consuming directory and the `MYPYPATH` its own imports need.

`benchmarks/` imports `sshd` and `netem` out of `live-tests/`; `live-tests/` imports
`server_contract` out of `tests/`. Without the path mypy reports `import-not-found` on a
sibling helper instead of checking the file, which is a gate failing for the wrong reason.
"""


@pytest.mark.parametrize("directory", sorted(CONSUMER_LANES))
def test_each_api_consuming_directory_has_a_type_gate(directory: str) -> None:
    """`benchmarks/` and `live-tests/` call the public API the way a user does.

    Until D-152 neither was inside any type gate, and a `DownloadResult` appended to a
    `list[int]` sat in `benchmarks/` for two releases -- reachable only by a 25-minute job that
    three consecutive pushes had cancelled before it could report. mypy names it in two
    seconds. A hook per directory rather than one over both, because each has a `conftest.py`
    and two files claiming that module name is an error before any checking starts.
    """
    block = _hook_block(f"mypy-{directory}")
    entry = next(line for line in block.splitlines() if line.lstrip().startswith("entry:"))
    assert f"--config-file={CONSUMER_CONFIG.name}" in entry
    # The directory is the last argument, so a hook checking a *different* one -- or checking
    # nothing, which is what mypy does with no path and no `files` -- fails here.
    assert entry.split()[-1] == directory
    assert f"MYPYPATH={CONSUMER_LANES[directory]}" in entry


def test_the_consumer_gate_cannot_weaken_the_gate_over_shipped_code() -> None:
    """The whole reason this is a second config file rather than more keys in pyproject.

    The settings for the consumer lanes are deliberately weaker than `src`'s -- no `strict`,
    so `no-untyped-def` on a test function is not a failure. One table holding both is one
    edit away from that weakening reaching shipped code, and nothing would look wrong.
    """
    assert CONSUMER_CONFIG.is_file()
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    mypy_table = pyproject.split("[tool.mypy]", 1)[1].split("\n[", 1)[0]
    assert "strict = true" in mypy_table
    assert 'files = ["src"]' in mypy_table
    assert "strict" not in CONSUMER_CONFIG.read_text(encoding="utf-8").split("[mypy]", 1)[1]


def test_each_waived_package_is_waived_hard_enough_to_survive_a_bench_sync() -> None:
    """The gate must answer the same with and without `--group bench`, and one flag is not enough.

    `ignore_missing_imports` speaks only to the *import statement*. A package that is installed
    **and ships `py.typed`** is still read for real types, so everything downstream is checked
    against them -- and asyncssh ships one while paramiko does not. `matrix.py`'s `asyncssh = None`
    fallback was therefore a genuine `assignment` error on a machine with the bench group and an
    *unused* ignore on a runner without it. It passed here, failed `release.yml`'s verify job, and
    stopped the 0.1.1 publish before anything irreversible ran.

    `follow_imports = skip` is what makes the module `Any` either way. Asserted per section rather
    than per file, because the next package added to this list will have the same two halves and
    only one of them is obvious.

    **Comments are stripped first, and the first version of this test was vacuous without that.**
    The prose above each section quotes the settings it argues about, so a section's text carries
    the words `follow_imports = skip` whether or not the section *sets* it -- and the run that was
    supposed to prove this test works passed against the exact config that had just failed a
    release. Same reason `_uncommented` exists for the workflows, found the same way.
    """
    text = CONSUMER_CONFIG.read_text(encoding="utf-8")
    settings = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    sections = re.split(r"^\[mypy-", settings, flags=re.M)[1:]
    assert sections, "the waiver sections are gone, not merely weakened"
    for section in sections:
        name = section.split(",", 1)[0]
        assert "ignore_missing_imports = True" in section, name
        assert "follow_imports = skip" in section, (
            f"{name} is waived for its import and then read for real types wherever it happens "
            "to be installed, which is a gate whose verdict depends on the last `uv sync`"
        )


def test_the_consumer_gate_waives_exactly_the_three_packages_it_documents() -> None:
    """An `ignore_missing_imports` section is a hole, and a fourth one added quietly is how
    this gate stops being one.

    paramiko and asyncssh are the competitor stack, present only under `--group bench`, so
    without a waiver the gate's verdict would depend on which group somebody last synced --
    `import-not-found` when absent, `import-untyped` when present, neither about our code.
    fsspec is the same call already taken for `src` in pyproject, for the same reason: no
    `py.typed`, and the fix is upstream.
    """
    sections = re.findall(r"^\[mypy-([a-z_]+),", CONSUMER_CONFIG.read_text(encoding="utf-8"), re.M)
    assert set(sections) == {"paramiko", "asyncssh", "fsspec"}


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


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS), ids=lambda name: name)
def test_every_third_party_action_is_pinned_to_a_commit_sha(workflow: str) -> None:
    # A floating tag is a mutable reference to somebody else's code running with a token in
    # scope. This project spawns `ssh` and handles credentials; it does not get to be
    # relaxed about that. The trailing comment is what makes the pin re-readable.
    uses = re.findall(r"uses:\s*(\S+)(.*)$", WORKFLOWS[workflow], flags=re.MULTILINE)
    assert uses
    for reference, trailer in uses:
        owner_repo, _, pin = reference.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", pin), f"{owner_repo} is not pinned to a SHA"
        assert re.search(r"#\s*v\d", trailer), f"{owner_repo} has no version comment"


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS), ids=lambda name: name)
def test_no_run_step_interpolates_a_workflow_context(workflow: str) -> None:
    # The Actions analogue of this project's argv-injection rule. `${{ ... }}` inside a `run:`
    # block is substituted into the shell *before* it executes, so a branch name or PR title
    # containing a metacharacter runs as code. Nothing here needs one -- release.yml reads the
    # tag through the `GITHUB_REF_NAME` environment variable instead, which is inert.
    commands = re.findall(r"^\s*- run:\s*(.+)$", WORKFLOWS[workflow], flags=re.MULTILINE)
    assert [command for command in commands if "${{" in command] == []


def test_the_workflow_never_triggers_on_pull_request_target() -> None:
    # `pull_request_target` runs the *base* workflow with secrets in scope against a fork's
    # code. `pull_request` is the one that does not.
    assert "pull_request_target" not in WORKFLOW_TEXT
    assert "pull_request:" in WORKFLOW_TEXT


def test_the_workflow_asks_for_no_more_than_read_access() -> None:
    assert "permissions:\n  contents: read\n" in WORKFLOW_TEXT


def test_the_windows_job_is_weekly_and_reports_rather_than_gates() -> None:
    """D-158. Windows is not a supported platform today, and the workflow has to say so.

    Transfers are POSIX-only by decision rather than by omission (`session/_platform.py`), so
    what works on Windows is the codec, the transport and the remote-only operations -- for a
    file-transfer library, the product minus the product. The job therefore runs on the weekly
    `schedule:` rather than per change: the evidence is worth having (the first completed
    Windows run produced the out-of-scope list, and both raised D-156 and, once its log was
    read row by row, refuted it) and a red row on every commit is D-152's pathology.

    Three assertions because the arrangement has three parts and any one of them silently
    reverting would put a permanently-red job back in front of every push. Read from the
    *uncommented* workflow: the block above the job quotes these spellings to argue about them.
    """
    runs = _uncommented(WORKFLOW_TEXT)
    assert "os: [ubuntu-latest, macos-latest]" in runs, "Windows is back in the gating matrix"
    assert "fast-windows:" in runs, "the weekly Windows job is gone rather than deferred"
    # Asserted on what the guard *admits* rather than on its spelling. This pinned the exact
    # string until the dispatch input made all four guards longer, and a literal that has to be
    # retyped every time the condition is edited is a literal somebody retypes wrongly.
    guard = job_guard(job_blocks()["fast-windows"])
    assert "schedule" in guard, "the Windows job no longer runs weekly"
    assert "pull_request" not in guard, "the Windows job runs per change again"
    # Flipping this is D-158's closure condition, not a tidy-up: it says Windows may block a
    # change, which is a claim about the platform being supported.
    assert "continue-on-error: true" in runs


# ---------------------------------------------------------------------------
# The release path, which is the one that cannot be undone
# ---------------------------------------------------------------------------


def _uncommented(text: str) -> str:
    """The workflow with its comment lines dropped.

    Every assertion below is about what the file *runs*, and the comments explaining these
    rules quote the spellings they argue against -- so a search over the raw text finds the
    prose and fails on the explanation rather than on the command.
    """
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


@pytest.mark.parametrize("subcommand", ["sync", "run"], ids=lambda name: f"uv {name}")
def test_every_uv_invocation_in_the_release_path_is_frozen(subcommand: str) -> None:
    """The publish path was the only one allowed to install something the lock does not name.

    `uv sync` without `--frozen` re-resolves when the lock and `pyproject.toml` disagree, and
    `uv.lock`'s 687 hashes are worth exactly what the flag insisting on them is worth. Every
    job in `ci.yml` already passed it; the job that ends in an irreversible upload did not.
    """
    invocations = re.findall(rf"\buv {subcommand}\b[^\n|]*", _uncommented(RELEASE_TEXT))
    assert invocations
    unfrozen = [command for command in invocations if "--frozen" not in command]
    assert unfrozen == []


def test_the_release_builds_with_the_locked_backend_rather_than_a_fresh_resolve() -> None:
    """PEP 517 build requirements are the one dependency declaration `uv.lock` does not cover.

    Left isolated, the backend that produces the artifact is fetched unpinned and unhashed at
    build time -- so the last unverified link in the release path was the code doing the
    packaging. `--no-build-isolation` over a synced `build` group closes it; the group
    agreeing with `[build-system] requires` is asserted in `tests/test_audit_deps.py`.
    """
    commands = re.findall(r"^\s*- run:\s*(.+)$", _uncommented(RELEASE_TEXT), flags=re.MULTILINE)
    builds = [command for command in commands if "uv build" in command]
    assert builds
    for command in builds:
        assert "--no-build-isolation" in command
    assert "uv sync --frozen --group build" in _uncommented(RELEASE_TEXT)


def test_the_release_is_gated_on_the_audit_lane() -> None:
    # A published version cannot be withdrawn, and the audit's gating scope is exactly the set
    # a user of that artifact installs. This is the moment it is worth the most.
    assert "lanes.py audit" in RELEASE_TEXT


def test_the_attestation_the_sbom_decision_rests_on_is_asked_for_explicitly() -> None:
    """`docs/security.md` declines to ship an SBOM, and this is what it declines in favour of.

    The argument there is that for "was this artifact built by the project it claims to come
    from" a signed PEP 740 attestation beats an unsigned inventory -- which holds only while one
    is actually produced.

    D-149 gave two reasons the action's default was too thin to rest a documented decision on,
    and **one of them expired** (D-174): it labelled the input `[EXPERIMENTAL]`, and at v1.14.2
    it no longer does -- upstream stopped implying PEP 740 might be experimental. The reason
    that never depended on upstream is the one this assertion rests on now: a default nobody
    wrote down is one an edit can turn off with nothing reading as changed.

    Asserted over the uncommented text, because the comment above that line quotes the spelling
    it is arguing about.
    """
    runs = _uncommented(RELEASE_TEXT)
    assert "pypa/gh-action-pypi-publish@" in runs
    assert "attestations: true" in runs, (
        "docs/security.md declines an SBOM on the grounds that a signed attestation is uploaded "
        "instead; without this line that argument rests on a third-party default"
    )


def test_only_the_publishing_job_may_mint_a_token() -> None:
    """`id-token: write` is what trusted publishing exchanges for an upload credential.

    Granted at workflow level it would be in scope for every job, including the ones that run
    the test suite. It is granted to `publish` alone, and the file says so in a comment -- this
    is the assertion that makes the comment true.
    """
    assert "permissions:\n  contents: read\n" in RELEASE_TEXT
    grants = re.findall(r"^\s*id-token: write", RELEASE_TEXT, flags=re.MULTILINE)
    assert len(grants) == 1
    _, _, after = RELEASE_TEXT.partition("  publish:")
    assert "id-token: write" in after


def _job_body(job: str) -> str:
    """One job's YAML, from its `<job>:` line to the next job at the same indentation.

    Read from the uncommented file. Every comment block in `release.yml` quotes the spelling
    it argues about -- the `publish` guard's own comment names `refs/tags/v` three times -- so
    a search over the raw text finds the prose and passes while the job runs unguarded.
    """
    body = _uncommented(RELEASE_TEXT).partition(f"\n  {job}:\n")[2]
    return re.split(r"^  \w+:$", body, maxsplit=1, flags=re.MULTILINE)[0]


@pytest.mark.parametrize("job", ["publish", "announce"], ids=lambda name: name)
def test_only_a_version_tag_may_reach_an_irreversible_job(job: str) -> None:
    """D-198. The ref condition on the publish path is stated in the file, not only in Settings.

    `test_only_the_publishing_job_may_mint_a_token` proves *which job* may mint the upload
    credential. This is the neighbouring question nothing asked: *which ref may reach that
    job*. It went unasserted because the answer was correct for a reason no test can see --
    the `pypi` environment's deployment branch policy allows one pattern, `v*`, of type tag,
    and refuses a branch `workflow_dispatch` at the gate. That rule lives in repository
    settings: `git` does not track it, review cannot see it, and nothing fails if it changes.

    So this does not assert the enforcement, which is not reachable from here. It asserts the
    *restatement* -- that the file says what the environment enforces -- which is the only half
    a test can hold, and is what makes the header's description of the environment checkable
    prose rather than a claim about a system nobody can query from a test run.

    `announce` is parametrized alongside deliberately: it has carried this condition since it
    was written, so it is the control proving the assertion matches the spelling already in
    use, and it would fail if a refactor changed the spelling in one job and not the other.
    """
    body = _job_body(job)
    assert body, f"no {job} job in release.yml"
    assert "if: startsWith(github.ref, 'refs/tags/v')" in body, (
        f"`{job}` has no ref guard; a workflow_dispatch against a branch would enter it with "
        f"the `pypi` environment's tag policy as the only thing in the way -- and that policy "
        f"is in repository settings, where no review and no test can see it"
    )


def test_the_release_holds_no_long_lived_credential() -> None:
    # Trusted publishing (OIDC) is the whole point: a `PYPI_API_TOKEN` in repository secrets
    # is exfiltrable by any workflow that runs untrusted code. Read over the uncommented file,
    # because the comment arguing for OIDC names the thing it is arguing against.
    settings = _uncommented(RELEASE_TEXT)
    assert "PYPI_API_TOKEN" not in settings
    assert "secrets." not in settings
    assert "password:" not in settings


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
        "gates, audit, fast, leaks, live, matrix, netem, benchmarks, cost, mutation\n"
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


# ---------------------------------------------------------------------------
# The branch ruleset, and the workflow it has to agree with
# ---------------------------------------------------------------------------

RULESET_PATH = REPO_ROOT / ".github" / "rulesets" / "main.json"
RULESET = json.loads(RULESET_PATH.read_text(encoding="utf-8"))
"""The `main` ruleset as it is meant to be, committed so a change to it is reviewable.

**What this file is not is a mirror of the live one.** GitHub holds the enforced copy and
nothing here can read it -- a test that reached the API would need the network and would fail on
an outage rather than on a defect. So the assertions below prove that *this* configuration and
`ci.yml` agree with each other, which is the half that goes wrong silently. Drift between this
file and the repository setting is found by re-exporting it, and `docs/development.md` says how.
"""


def _rule(rule_type: str) -> dict:
    """The one rule of that type, so an assertion cannot be satisfied by a sibling."""
    matches = [rule for rule in RULESET["rules"] if rule["type"] == rule_type]
    assert len(matches) == 1, f"{rule_type} appears {len(matches)} times, expected once"
    return matches[0]


def job_blocks() -> dict[str, str]:
    """Every job in the workflow, mapped to its own text.

    One walk, because two readers of the same structure drift. A block runs to the start of
    the next job, so nothing below can be read as belonging to the one above -- which matters
    here for exactly one reason: `fast` carries the only matrix, and a slice that overran would
    hand its two images to whichever job was asked about first.
    """
    body = _uncommented(WORKFLOW_TEXT).split("\njobs:\n", 1)[1]
    starts = [
        (match.group(1), match.start())
        for match in re.finditer(r"^  ([a-z][a-z0-9-]*):$", body, flags=re.MULTILINE)
    ]
    assert starts, "no jobs found in the workflow, so every sweep below would pass while empty"
    return {
        job: body[start : (starts[index + 1][1] if index + 1 < len(starts) else len(body))]
        for index, (job, start) in enumerate(starts)
    }


def job_guard(block: str) -> str:
    """A job's `if:` text, whitespace-normalised, or `""` when it has none.

    Returned whole rather than matched against, because it folds over several lines with `>-`
    and a caller wants to ask what it mentions.
    """
    guard = re.search(r"^    if:(.*?)(?=^    [a-z-]+:)", block, flags=re.MULTILINE | re.DOTALL)
    return " ".join(guard.group(1).split()) if guard else ""


def job_contexts(job: str, block: str) -> set[str]:
    """What a job reports as, which is not its id when it carries a matrix."""
    matrix = re.search(r"^        os: \[(.+)\]$", block, flags=re.MULTILINE)
    if matrix is None:
        return {job}
    return {f"{job} ({image.strip()})" for image in matrix.group(1).split(",")}


def contexts_a_pull_request_reports() -> set[str]:
    """Every check a pull request will actually produce, read from the workflow.

    **A job with no `if:` runs on every event this workflow takes, which includes
    `pull_request`; a job with one does not.** That is the whole rule, and it is deliberately
    not "matches the weekly guard": the guards are not written the same way -- three name
    `schedule` and `workflow_dispatch`, `netem` names `push` as well -- and a test matching one
    spelling would classify the others as gating.

    Contexts rather than job ids, because `fast` is one job and two checks -- a ruleset can
    only name what the check reports, so the matrix has to be expanded the way GitHub expands
    it.
    """
    return {
        context
        for job, block in job_blocks().items()
        if not job_guard(block)
        for context in job_contexts(job, block)
    }


def dispatchable_lanes() -> set[str]:
    """The `weekly_lane` choice, minus the two that are not lane names."""
    options = re.search(r"^        options: \[(.+)\]$", WORKFLOW_TEXT, flags=re.MULTILINE)
    assert options is not None, "the weekly_lane input has no options list"
    return {name.strip() for name in options.group(1).split(",")} - {"all", "none"}


def test_every_lane_that_does_not_run_per_change_can_be_dispatched_on_its_own() -> None:
    """Both directions, and they fail differently.

    A guarded lane missing from the choice cannot be reached without running all four, which
    is the two hours of runner time this input exists to stop paying. An option naming no job
    is a dropdown entry that silently does nothing -- worse than absent, because somebody picks
    it and reads the resulting green as an answer.
    """
    guarded = {job for job, block in job_blocks().items() if job_guard(block)}
    assert guarded == dispatchable_lanes()


@pytest.mark.parametrize("lane", sorted(dispatchable_lanes()))
def test_a_dispatched_lane_names_itself_in_its_own_guard(lane: str) -> None:
    # The failure this catches is a copy-paste: four guards with the same shape, and the one
    # that still names its neighbour runs whenever the neighbour is asked for.
    guard = job_guard(job_blocks()[lane])
    assert f"inputs.weekly_lane == '{lane}'" in guard
    assert "inputs.weekly_lane == 'all'" in guard


def required_contexts() -> set[str]:
    parameters = _rule("required_status_checks")["parameters"]
    return {check["context"] for check in parameters["required_status_checks"]}


def test_every_check_a_pull_request_reports_is_required_to_merge() -> None:
    """A gating lane the ruleset does not name is a lane that does not gate.

    It still runs, still goes red, and still merges -- which is the failure this sweep exists
    for, because nothing about the pull request looks different.
    """
    assert contexts_a_pull_request_reports() - required_contexts() == set()


def test_no_required_check_is_one_a_pull_request_never_reports() -> None:
    """The other direction, and it is the one that stops the repository dead.

    `fast-windows`, `mutation`, `benchmarks` and `netem` are skipped on a pull request. A
    required check that never reports leaves every pull request waiting for it, so moving a
    lane to the weekly schedule without taking it out of the ruleset blocks all merges rather
    than relaxing one.
    """
    assert required_contexts() - contexts_a_pull_request_reports() == set()


def test_main_cannot_be_force_pushed_or_deleted() -> None:
    """The two irreversible ones, and the reason they outrank the rest.

    A wheel on PyPI carries an attestation naming a workflow, a repository and a commit. A
    force-push to `main` invalidates what that attestation points at, and no green lane
    anywhere would notice.
    """
    assert {rule["type"] for rule in RULESET["rules"]} >= {"deletion", "non_fast_forward"}


def test_nothing_may_bypass_the_ruleset() -> None:
    # An empty bypass list is what makes "must pass CI" true rather than customary -- with an
    # actor in it the rule describes what everybody else has to do.
    assert RULESET["bypass_actors"] == []
    assert RULESET["enforcement"] == "active"


def test_a_change_reaches_main_only_through_a_pull_request_that_rebases() -> None:
    """Both halves of how a commit is allowed to land.

    `rebase` alone, because `main` is linear and the merge button is where that is decided.
    Squash is excluded on purpose and it is not a style preference: a pull request here can be
    three commits where the third corrects the first, and collapsing them keeps the conclusion
    while deleting the correction.
    """
    parameters = _rule("pull_request")["parameters"]
    assert parameters["allowed_merge_methods"] == ["rebase"]
    # Zero approvals required, and that is not an oversight: a solo maintainer cannot approve
    # their own pull request, so any positive number blocks every merge permanently.
    assert parameters["required_approving_review_count"] == 0

"""The dependency audit, and the three states it has to keep apart.

`scripts/audit_deps.py` exists because "clean" and "could not check" had been the same answer:
pip-audit exits 1 for a finding *and* for an unreachable service, so a lane reading the exit
code alone would have reported an outage as a pass. Most of this module is that distinction,
asserted from both sides.

Nothing here reaches the network or spawns `uv`. The subprocess seam is injected the way
`tests/test_lanes.py` does it -- `subprocess.run` monkeypatched for the paths that go through
`main`, an explicit `runner=` for the ones that do not -- so the answers are the ones a test
chose rather than the ones today's advisory database happens to hold. A test whose result moves
when somebody publishes a CVE is a test that proves nothing about this code.

The script is loaded by path. `scripts/` is not a package and giving it an `__init__.py` to
suit a test would make a shipping decision on a test's behalf.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "audit_deps.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("gantry_audit_deps", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution, not after. The script uses `from __future__ import
    # annotations`, so @dataclass resolves its field types as strings through
    # `sys.modules[cls.__module__].__dict__`, and a module that is not there yet fails several
    # frames inside dataclasses with an AttributeError on None.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


audit_deps = _load_script()

SHIPPED = audit_deps.SCOPES[0]
TOOLCHAIN = audit_deps.SCOPES[1]

CLEAN_REPORT = {
    "dependencies": [
        {"name": "anyio", "version": "4.14.2", "vulns": []},
        {"name": "idna", "version": "3.18", "vulns": []},
    ],
    "fixes": [],
}

# The shape of a real finding, copied off pip-audit 2.10.1 rather than invented: the advisory
# that was sitting in this lock when the lane was built. The description is cut because only
# the fields the script reads matter here, and the full text is four paragraphs.
VULNERABLE_REPORT = {
    "dependencies": [
        {"name": "anyio", "version": "4.14.2", "vulns": []},
        {
            "name": "cryptography",
            "version": "49.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2026-3552",
                    "fix_versions": ["50.0.0"],
                    "aliases": ["CVE-2026-69247", "GHSA-g6cj-pr64-35w5"],
                    "description": "Bleichenbacher oracle in pkcs7_decrypt_*.",
                }
            ],
        },
    ],
    "fixes": [],
}

SKIPPED_REPORT = {
    "dependencies": [
        {"name": "anyio", "version": "4.14.2", "vulns": []},
        {"name": "idna", "version": "3.18", "skip_reason": "Dependency not found on PyPI"},
    ],
    "fixes": [],
}

# What an unreachable service actually looks like: empty stdout, a traceback on stderr, exit
# 1 -- the same exit code as a finding, which is the whole reason this script parses stdout.
UNREACHABLE_STDERR = """\
Traceback (most recent call last):
  File "requests/adapters.py", line 723, in send
    raise ProxyError(e, request=request)
requests.exceptions.ProxyError: HTTPSConnectionPool(host='pypi.org', port=443): Max retries \
exceeded with url: /pypi/anyio/4.14.2/json
"""


class Runs:
    """A subprocess seam that answers from a script instead of running anything.

    Attributes:
        calls: Every argv it was handed, so a test can assert on the command as well as on
            what came back from it.
    """

    def __init__(
        self,
        *,
        reports: dict[str, object] | None = None,
        export_failures: dict[str, str] | None = None,
        audit_failures: dict[str, str] | None = None,
    ) -> None:
        self.reports = reports or {}
        self.export_failures = export_failures or {}
        self.audit_failures = audit_failures or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        if "export" in argv:
            return self._export(argv)
        return self._audit(argv)

    def _scope_of(self, argv: list[str], flag: str) -> str:
        # The scope is recoverable from the requirements filename, which `audit_scope` names
        # after it. Reading it back here is what lets one runner answer differently per scope
        # without the test having to know the call order.
        return Path(argv[argv.index(flag) + 1]).stem

    def _export(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        scope = self._scope_of(argv, "--output-file")
        if scope in self.export_failures:
            return subprocess.CompletedProcess(argv, 2, "", self.export_failures[scope])
        Path(argv[argv.index("--output-file") + 1]).write_text(
            "anyio==4.14.2 \\\n    --hash=sha256:9f505dda\n", encoding="utf-8"
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    def _audit(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        scope = self._scope_of(argv, "--requirement")
        if scope in self.audit_failures:
            return subprocess.CompletedProcess(argv, 1, "", self.audit_failures[scope])
        report = self.reports.get(scope, CLEAN_REPORT)
        vulnerable = any(dependency.get("vulns") for dependency in report["dependencies"])
        return subprocess.CompletedProcess(argv, int(vulnerable), json.dumps(report), "")


@pytest.fixture
def with_audit_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin both prerequisites so no test depends on the developer's PATH or synced groups.

    `uv`'s location was the original reason (DoD 1). **`pip-audit`'s presence is the second and
    it was found by the first CI run this project ever had**: `pip-audit` lives in the `audit`
    group, which is deliberately *not* installed by a default `uv sync` -- it costs 18 packages
    for something one lane runs -- so on any machine that had not synced that group, `main()`
    returned `EXIT_NO_TOOL` before building a single argument vector and twelve tests here
    failed with `assert 0 == 2` and `assert 127 == 0`.

    Faked rather than skipped, and the distinction matters. Nothing in this file runs the real
    `pip-audit`: `subprocess.run` is a scripted seam in every test. What they assert is how the
    argument vector is *built* -- `--frozen` on the export, `python -m pip_audit` rather than a
    console script, no `shell=`. Those are the security-relevant claims in this lane, and
    skipping them wherever the `audit` group is absent would have retired them from the default
    lane on every machine and in CI, which is where they most need to run.

    The one test that wants the real check -- `test_the_missing_tool_is_named_...` -- patches
    `find_spec` back to `None` itself, and its own `monkeypatch` is applied after this one.
    """
    monkeypatch.setattr(audit_deps.shutil, "which", lambda tool: f"/usr/local/bin/{tool}")
    # Truthy and not a real `ModuleSpec`: nothing reads it, the script only asks `is None`.
    monkeypatch.setattr(audit_deps.importlib.util, "find_spec", lambda name: object())


def drive(runs: Runs, monkeypatch: pytest.MonkeyPatch, argv: list[str] | None = None) -> int:
    """Run `main` with a scripted seam, the way `tests/test_lanes.py` drives the runner."""
    monkeypatch.setattr(subprocess, "run", lambda a, **kwargs: runs(a))
    return audit_deps.main(argv or [])


# ---------------------------------------------------------------------------
# The two scopes, and which one is allowed to fail a change
# ---------------------------------------------------------------------------


def test_the_shipped_scope_gates_and_the_toolchain_scope_does_not() -> None:
    assert [scope.name for scope in audit_deps.SCOPES] == ["shipped", "toolchain"]
    assert SHIPPED.gates is True
    assert TOOLCHAIN.gates is False


def test_the_shipped_scope_excludes_every_group_rather_than_just_dev() -> None:
    """`--no-dev` would keep exporting `bench`, and `bench` is where `cryptography` is.

    The distinction is not academic: the advisory this lane found on its first run was against
    a package no user of this library installs, and a shipped scope spelled `--no-dev` would
    have reported it as shipped and gated on it.
    """
    assert SHIPPED.export_args == ("--no-default-groups", "--all-extras")
    assert "--no-dev" not in SHIPPED.export_args


def test_the_toolchain_scope_covers_every_group() -> None:
    assert TOOLCHAIN.export_args == ("--all-groups", "--all-extras")


# ---------------------------------------------------------------------------
# What gets run, and how
# ---------------------------------------------------------------------------


def test_the_export_is_frozen_so_the_audit_cannot_be_of_a_resolution_nobody_installed(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without `--frozen`, `uv export` may re-resolve when the lock and pyproject disagree.

    That is the one way this lane could report on versions nobody has installed and look
    entirely healthy doing it, so the flag is asserted rather than assumed.
    """
    runs = Runs()
    drive(runs, monkeypatch)

    exports = [call for call in runs.calls if "export" in call]
    assert len(exports) == 2
    for call in exports:
        assert "--frozen" in call


def test_pip_audit_runs_through_this_interpreter_and_not_a_console_script(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`python -m pip_audit` is what makes the answering pip-audit provably the locked one."""
    runs = Runs()
    drive(runs, monkeypatch)

    audits = [call for call in runs.calls if "pip_audit" in call]
    assert len(audits) == 2
    for call in audits:
        assert call[:3] == [sys.executable, "-m", "pip_audit"]
        assert "--format" in call
        assert call[call.index("--format") + 1] == "json"


def test_nothing_is_run_through_a_shell(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, object]] = []

    def fake_run(argv, **kwargs):
        seen.append(kwargs)
        assert isinstance(argv, list)
        return Runs()(argv)

    monkeypatch.setattr(subprocess, "run", fake_run)
    audit_deps.main([])

    assert seen
    for kwargs in seen:
        assert "shell" not in kwargs


# ---------------------------------------------------------------------------
# Clean, vulnerable, and the decoy in between
# ---------------------------------------------------------------------------


def test_a_clean_lock_exits_zero(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert drive(Runs(), monkeypatch) == 0
    out = capsys.readouterr().out
    assert "shipped     gates" in out
    assert "clean" in out


def test_an_advisory_in_the_shipped_scope_fails_and_names_what_to_do(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = Runs(reports={"shipped": VULNERABLE_REPORT})

    assert drive(runs, monkeypatch) == audit_deps.EXIT_VULNERABLE

    out = capsys.readouterr().out
    assert "cryptography 49.0.0" in out
    assert "PYSEC-2026-3552" in out
    # The aliases are carried because a CVE number is what a reader will search for, and the
    # fix version because "there is a fix" and "there is not yet" are different situations.
    assert "CVE-2026-69247" in out
    assert "fixed in 50.0.0" in out


def test_an_advisory_in_only_the_toolchain_scope_is_reported_and_changes_nothing(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The decoy, and the case that actually happened.

    `cryptography` arrives through `bench`, which exists to run paramiko and asyncssh and is
    excluded from the sdist. A lane that gated on it would fail a release of a library that
    does not ship it, for a defect in a benchmark dependency. It still has to be *printed* --
    a reporting scope that stayed silent would be the same lane with extra steps.
    """
    runs = Runs(reports={"toolchain": VULNERABLE_REPORT})

    assert drive(runs, monkeypatch) == audit_deps.EXIT_CLEAN

    out = capsys.readouterr().out
    assert "PYSEC-2026-3552" in out
    assert "toolchain   reports" in out


def test_a_finding_with_no_fix_yet_says_so_rather_than_printing_an_empty_list() -> None:
    report = {
        "dependencies": [
            {
                "name": "somepkg",
                "version": "1.0",
                "vulns": [{"id": "GHSA-xxxx", "fix_versions": [], "aliases": []}],
            }
        ]
    }
    rendered = audit_deps.render([audit_deps.read_report(SHIPPED, report)])
    assert "fixed in no fix yet" in rendered


# ---------------------------------------------------------------------------
# The third state: checked, and not checked
# ---------------------------------------------------------------------------


def test_a_package_pip_audit_skipped_is_not_counted_as_clean(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A skip is the service answering and one package going unchecked. In the gate that fails."""
    runs = Runs(reports={"shipped": SKIPPED_REPORT})

    assert drive(runs, monkeypatch) == audit_deps.EXIT_VULNERABLE

    out = capsys.readouterr().out
    assert "idna was not checked: Dependency not found on PyPI" in out
    # One of the two was checked, and the count says one rather than two -- a skipped package
    # counted as audited would make the table overstate what it looked at.
    assert re.search(r"shipped\s+gates\s+1 packages", out)


def test_a_skipped_package_in_the_reporting_scope_does_not_fail(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert drive(Runs(reports={"toolchain": SKIPPED_REPORT}), monkeypatch) == 0


def test_an_unreachable_service_is_never_reported_as_clean(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The defect this whole script exists for.

    pip-audit exits 1 for a finding and 1 for a network failure, and on failure stdout is
    empty. A lane reading the exit code would call an outage a finding; a lane reading
    "no vulns in the report" would call it clean. Neither is true and the third answer needs
    its own exit code.
    """
    runs = Runs(audit_failures={"shipped": UNREACHABLE_STDERR})

    assert drive(runs, monkeypatch) == audit_deps.EXIT_NOT_CHECKED

    out = capsys.readouterr().out
    assert "NOT CHECKED" in out
    assert "no answer was obtained, so nothing here was checked:" in out
    # The reason is the exception line, not the first line of a traceback: "Traceback (most
    # recent call last):" names nothing.
    assert "requests.exceptions.ProxyError" in out
    assert "Traceback" not in out


def test_an_unreachable_service_in_the_reporting_scope_alone_does_not_fail(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = Runs(audit_failures={"toolchain": UNREACHABLE_STDERR})

    assert drive(runs, monkeypatch) == audit_deps.EXIT_CLEAN
    assert "NOT CHECKED" in capsys.readouterr().out


def test_a_failure_that_said_nothing_still_gets_a_reason() -> None:
    """`unavailable` is treated as truthy everywhere, so it must never come back empty."""
    done = subprocess.CompletedProcess(["pip-audit"], 9, "not json", "   \n\n")
    _, reason = audit_deps.audit_requirements(Path("x.txt"), runner=lambda argv: done)
    assert reason == "pip-audit exited 9 and said nothing"


def test_a_report_that_is_not_an_object_is_a_failure_rather_than_an_empty_result() -> None:
    done = subprocess.CompletedProcess(["pip-audit"], 0, "[]", "")
    report, reason = audit_deps.audit_requirements(Path("x.txt"), runner=lambda argv: done)
    assert report == {}
    assert reason == "pip-audit returned list, not a report"


# ---------------------------------------------------------------------------
# Failing to even ask
# ---------------------------------------------------------------------------


def test_a_failed_export_carries_uvs_own_error(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = Runs(export_failures={"shipped": "error: the lock file is not up to date"})

    assert drive(runs, monkeypatch) == audit_deps.EXIT_NOT_CHECKED
    assert "error: the lock file is not up to date" in capsys.readouterr().out


def test_a_missing_uv_says_what_it_was_needed_for(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit_deps.shutil, "which", lambda tool: None)

    reason = audit_deps.export_requirements(SHIPPED, Path("out.txt"), runner=lambda argv: None)

    assert reason == "uv is not on PATH, and uv.lock is the only thing that knows these versions"


def test_an_export_that_failed_silently_is_still_a_reason() -> None:
    done = subprocess.CompletedProcess(["uv"], 3, "", "")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(audit_deps.shutil, "which", lambda tool: "/usr/bin/uv")
        reason = audit_deps.export_requirements(SHIPPED, Path("out.txt"), runner=lambda a: done)
    assert reason == "uv export exited 3"


def test_a_missing_pip_audit_asks_for_the_group_by_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(audit_deps.importlib.util, "find_spec", lambda name: None)

    assert audit_deps.main([]) == audit_deps.EXIT_NO_TOOL
    assert capsys.readouterr().err == (
        "error: pip-audit is not installed -- run `uv sync --group audit`\n"
    )


def test_the_missing_tool_code_is_the_one_the_lane_runner_uses() -> None:
    # Two scripts, one meaning for 127. Pinned because the lane runner's message and this
    # one's are what a reader compares when a lane will not start.
    assert audit_deps.EXIT_NO_TOOL == 127


# ---------------------------------------------------------------------------
# Reading a report
# ---------------------------------------------------------------------------


def test_a_report_is_read_into_findings_with_every_field_carried() -> None:
    result = audit_deps.read_report(SHIPPED, VULNERABLE_REPORT)

    assert result.audited == 2
    assert result.skipped == ()
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.package == "cryptography"
    assert finding.version == "49.0.0"
    assert finding.vulnerability == "PYSEC-2026-3552"
    assert finding.aliases == ("CVE-2026-69247", "GHSA-g6cj-pr64-35w5")
    assert finding.fix_versions == ("50.0.0",)


def test_a_dependency_with_neither_vulns_nor_a_skip_reason_is_simply_clean() -> None:
    result = audit_deps.read_report(SHIPPED, CLEAN_REPORT)
    assert result.audited == 2
    assert result.findings == ()
    assert result.blocks is False


def test_an_empty_report_is_not_an_error_but_audits_nothing() -> None:
    result = audit_deps.read_report(SHIPPED, {})
    assert result.audited == 0
    assert result.blocks is False


def test_a_scope_that_could_not_be_reached_is_unchecked_rather_than_blocking() -> None:
    unreachable = audit_deps.Result(SHIPPED, 0, (), (), "connection refused")
    assert unreachable.blocks is False
    assert unreachable.unchecked is True


def test_a_reporting_scope_is_never_unchecked_because_it_never_gates() -> None:
    unreachable = audit_deps.Result(TOOLCHAIN, 0, (), (), "connection refused")
    assert unreachable.blocks is False
    assert unreachable.unchecked is False


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (audit_deps.Result(SHIPPED, 3, (), (), ""), "clean"),
        (audit_deps.Result(SHIPPED, 0, (), (), "boom"), "NOT CHECKED"),
        (audit_deps.Result(SHIPPED, 3, (), (("x", "why"),), ""), "1 not checked"),
    ],
    ids=["clean", "unreachable", "skipped"],
)
def test_the_verdict_words_keep_clean_and_unchecked_apart(result, expected: str) -> None:
    assert audit_deps.verdict(result) == expected


def test_one_advisory_is_singular_and_two_are_not() -> None:
    one = audit_deps.read_report(SHIPPED, VULNERABLE_REPORT)
    assert audit_deps.verdict(one) == "1 advisory"

    both = dict(VULNERABLE_REPORT)
    both["dependencies"] = [
        VULNERABLE_REPORT["dependencies"][1],
        {**VULNERABLE_REPORT["dependencies"][1], "name": "other"},
    ]
    assert audit_deps.verdict(audit_deps.read_report(SHIPPED, both)) == "2 advisories"


def test_the_table_says_which_scope_gates_so_a_reader_need_not_read_the_source() -> None:
    rendered = audit_deps.render(
        [audit_deps.Result(SHIPPED, 3, (), (), ""), audit_deps.Result(TOOLCHAIN, 78, (), (), "")]
    )
    assert "shipped" in rendered
    assert "gates" in rendered
    assert "toolchain" in rendered
    assert "reports" in rendered
    assert SHIPPED.summary in rendered
    assert TOOLCHAIN.summary in rendered


def test_a_single_scope_can_be_audited(
    with_audit_tools: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = Runs()
    assert drive(runs, monkeypatch, ["--scope", "shipped"]) == 0

    assert [call for call in runs.calls if "export" in call] != []
    assert "toolchain" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# The lock this all reads from
# ---------------------------------------------------------------------------


def test_every_artifact_in_the_lock_carries_a_hash() -> None:
    """The property `--frozen` enforces at install time, asserted at rest.

    `uv sync --frozen` refuses an artifact whose sha256 does not match, on a cold cache and a
    warm one alike -- measured. That is only worth anything if every artifact has one, and a
    source that recorded none would install without complaint.
    """
    text = (REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
    urls = re.findall(r'url = "https://[^"]+"', text)
    hashes = re.findall(r'hash = "sha256:[0-9a-f]{64}"', text)
    assert urls
    assert len(urls) == len(hashes)


def test_the_build_group_names_the_real_build_requirement() -> None:
    """`--no-build-isolation` builds with what the group installed, not with `requires`.

    If the two disagree the build either fails or silently resolves something else, and the
    second one is indistinguishable from this working. One assertion is cheaper than finding
    out during a release.
    """
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    required = {re.split(r"[<>=!~ ]", name)[0] for name in config["build-system"]["requires"]}
    grouped = {re.split(r"[<>=!~ ]", name)[0] for name in config["dependency-groups"]["build"]}
    assert required <= grouped

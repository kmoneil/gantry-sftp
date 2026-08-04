"""Known advisories against what this lock installs, in two scopes with two verdicts.

`uv.lock` records a sha256 for every artifact and `uv sync --frozen` refuses one that does not
match, so what gets installed is pinned and its integrity is checked. Neither of those says
anything about whether the pinned thing is *known to be broken*, and nothing in this repository
asked until this lane existed. The first run of it found one advisory that had been sitting in
the lock.

**The two scopes are the point, and they are not the same question.**

`shipped` is what `pip install gantry-sftp[fsspec]` puts on a production machine: three
packages, because the runtime dependency is `anyio` and nothing else (DESIGN.md 4.1). An
advisory there is about what users run, so it **gates**.

`toolchain` is everything the lock can install -- `dev`, `bench` and `audit` as well. `bench`
alone brings `cryptography`, `pynacl` and `bcrypt`, which is the Python cryptography this
project exists not to need and installs only to measure against. An advisory there is worth
knowing and is not a reason to fail somebody's change, so it **reports**. Gating on it would
mean paramiko's transitive dependencies could block a release of a library that does not ship
them, and a gate that fails for reasons the change cannot fix is a gate that gets skipped.

**An unreachable advisory service fails the lane, and fails it with its own exit code.** This
is the one place the repository's usual "skip with a reason rather than fail" rule is
deliberately not applied, so the reasoning is here rather than assumed. That rule exists for a
prerequisite a developer has not installed -- Docker for `live-tests/`, `CAP_NET_ADMIN` for
`netem` -- where the lane genuinely cannot apply and saying so is the honest answer. A security
scan is the opposite shape: "could not check" and "checked, found nothing" are the two states
it exists to keep apart, and reporting the first as the second is the exact defect this lane
was built after finding. So an unreachable service exits **2** rather than 0 or 1 -- the lane
could not run, which is neither a pass nor a finding, and the table says so in those words.
CI has network, so 2 there means something is actually wrong and is worth a red tick over a
green one taken on trust.

**Distinguishing "nothing is wrong" from "nothing was checked" is most of this file.** Measured
against pip-audit 2.10.1 rather than assumed:

  - It exits **1** both when it finds an advisory and when it cannot reach the service, so the
    exit code alone cannot tell those apart.
  - On a real answer it writes JSON to stdout; on a failure stdout is **empty** and the
    traceback goes to stderr. So stdout parsing is the discriminator, and it is the reason
    this script asks for `--format json` even though nothing here needs a machine-readable
    report.
  - With a warm HTTP cache it answers from the cache without contacting anything, which is
    correct and is also why a cached "clean" is not evidence the service was reachable.

A package pip-audit **skipped** is a third state and is treated as one: the service answered,
and that package was not checked. In the gating scope that fails, because "not checked" is
exactly what this lane exists to stop being invisible.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]
"""How a subprocess gets run. Injectable so the tests never spawn `uv` or reach the network."""

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_NOT_CHECKED = 2
EXIT_NO_TOOL = 127
"""Four codes, because three of them are things a caller would otherwise conflate.

`1` is "the shipped surface carries an advisory". `2` is "the shipped surface could not be
checked" -- a different fact, and the one worth having a code of its own, since the failure
this lane was built after finding is a scan that could not see reporting itself as clean.
`127` is `scripts/lanes.py`'s code for a tool that is not installed and means the same here.
"""


@dataclass(frozen=True)
class Scope:
    """One half of the lock, and what a finding in it means.

    Attributes:
        name: What it is called in the table.
        summary: Who installs this set, in one line.
        export_args: The `uv export` arguments that select it.
        gates: Whether a finding here should stop a change.
    """

    name: str
    summary: str
    export_args: tuple[str, ...]
    gates: bool


SCOPES: tuple[Scope, ...] = (
    Scope(
        name="shipped",
        summary="what `pip install gantry-sftp[fsspec]` puts on a production machine",
        # `--no-default-groups` rather than `--no-dev`: `dev` is only a default group by uv's
        # own default, and naming the narrower flag would keep exporting any group added later.
        export_args=("--no-default-groups", "--all-extras"),
        gates=True,
    ),
    Scope(
        name="toolchain",
        summary="everything this lock can install -- dev, bench and audit as well",
        export_args=("--all-groups", "--all-extras"),
        gates=False,
    ),
)


@dataclass(frozen=True)
class Finding:
    """One advisory against one pinned package.

    Attributes:
        package: Distribution name as the lock spells it.
        version: The pinned version, which is the one the advisory was matched against.
        vulnerability: Advisory id -- `PYSEC-…`, `GHSA-…`.
        aliases: Other ids for the same advisory, so a CVE number can be searched for.
        fix_versions: Versions that carry the fix, empty when there is no fix yet.
    """

    package: str
    version: str
    vulnerability: str
    aliases: tuple[str, ...]
    fix_versions: tuple[str, ...]


@dataclass(frozen=True)
class Result:
    """What one scope's audit came back with.

    Attributes:
        scope: The scope audited.
        audited: How many packages were checked. Zero with no reason is itself a finding.
        findings: The advisories, in the order pip-audit reported them.
        skipped: Packages pip-audit could not check, each with its reason.
        unavailable: Why no answer was obtained, or `""` when one was. Never both this and
            findings: an unreachable service produces no report to have findings in.
    """

    scope: Scope
    audited: int
    findings: tuple[Finding, ...]
    skipped: tuple[tuple[str, str], ...]
    unavailable: str

    @property
    def blocks(self) -> bool:
        """Whether this result is a finding that should fail the lane.

        A package pip-audit skipped counts, and that is the deliberate part: the service
        answered and that package was not checked, which is unchecked rather than clean. A
        scope that could not be reached at all is not a finding and is reported through
        `unavailable` instead -- the two get different exit codes.
        """
        if not self.scope.gates or self.unavailable:
            return False
        return bool(self.findings) or bool(self.skipped)

    @property
    def unchecked(self) -> bool:
        """Whether this result means the lane could not run rather than that it passed."""
        return self.scope.gates and bool(self.unavailable)


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run a command from the repository root, capturing both streams.

    Args:
        argv: The command, always a list and never a string -- there is no shell anywhere in
            this project and an audit script is not where the first one arrives.

    Returns:
        The completed process, never raising on a non-zero exit: every caller here routes on
        the code rather than on an exception.
    """
    return subprocess.run(
        list(argv),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _failure_reason(done: subprocess.CompletedProcess[str]) -> str:
    """Read the cause off a run whose output could not be parsed.

    Args:
        done: The completed process.

    Returns:
        The last non-empty line of stderr, which for pip-audit is the exception line of a
        traceback and names the actual cause -- a proxy error, a DNS failure, a 503. Falls
        back to the exit code, so this never returns an empty reason and lets a caller treat
        `unavailable` as a truthy field.
    """
    for line in reversed(done.stderr.splitlines()):
        if line.strip():
            return line.strip()
    return f"pip-audit exited {done.returncode} and said nothing"


def export_requirements(scope: Scope, destination: Path, *, runner: Runner = _run) -> str:
    """Write one scope's pinned, hashed requirements out of the lock.

    Args:
        scope: Which half of the lock to export.
        destination: File to write, overwritten if it exists.
        runner: Subprocess seam.

    Returns:
        Empty on success, or the reason it failed. `--frozen` is not optional: an export
        allowed to re-lock would audit a resolution nobody has installed, which is the one
        way this lane could report on the wrong versions and look right doing it.
    """
    uv = shutil.which("uv")
    if uv is None:
        return "uv is not on PATH, and uv.lock is the only thing that knows these versions"
    done = runner(
        [
            uv,
            "export",
            "--frozen",
            "--no-emit-project",
            *scope.export_args,
            "--output-file",
            str(destination),
        ]
    )
    if done.returncode != 0:
        return done.stderr.strip() or f"uv export exited {done.returncode}"
    return ""


def audit_requirements(requirements: Path, *, runner: Runner = _run) -> tuple[dict[str, Any], str]:
    """Ask pip-audit about an exported requirements file.

    Args:
        requirements: The file `export_requirements` wrote.
        runner: Subprocess seam.

    Returns:
        The parsed report and an empty reason, or an empty report and the reason there is
        none. pip-audit is invoked as `python -m pip_audit` through this interpreter rather
        than by resolving a console script: the lane runs `.venv/bin/python`, so this is what
        makes the pip-audit that answers provably the one `uv.lock` pinned.
    """
    done = runner(
        [
            sys.executable,
            "-m",
            "pip_audit",
            # The file is fully pinned and hashed, so there is nothing to resolve; without
            # this pip-audit shells out to pip to do it anyway.
            "--disable-pip",
            "--format",
            "json",
            "--requirement",
            str(requirements),
        ]
    )
    try:
        report = json.loads(done.stdout)
    except json.JSONDecodeError:
        return {}, _failure_reason(done)
    if not isinstance(report, dict):
        return {}, f"pip-audit returned {type(report).__name__}, not a report"
    return report, ""


def read_report(scope: Scope, report: dict[str, Any]) -> Result:
    """Turn one pip-audit JSON report into a result.

    Args:
        scope: The scope it came from.
        report: The parsed `--format json` output.

    Returns:
        The result. A dependency carrying a `skip_reason` is counted as skipped rather than
        as clean, and is deliberately not counted in `audited` -- the two numbers are "what
        was checked" and "what was not", and a package in both would make the table lie.
    """
    findings: list[Finding] = []
    skipped: list[tuple[str, str]] = []
    audited = 0
    for dependency in report.get("dependencies", ()):
        name = str(dependency.get("name", "?"))
        reason = dependency.get("skip_reason")
        if reason:
            skipped.append((name, str(reason)))
            continue
        audited += 1
        version = str(dependency.get("version", "?"))
        findings.extend(
            Finding(
                package=name,
                version=version,
                vulnerability=str(vulnerability.get("id", "?")),
                aliases=tuple(str(alias) for alias in vulnerability.get("aliases", ())),
                fix_versions=tuple(str(fixed) for fixed in vulnerability.get("fix_versions", ())),
            )
            for vulnerability in dependency.get("vulns", ())
        )
    return Result(
        scope=scope,
        audited=audited,
        findings=tuple(findings),
        skipped=tuple(skipped),
        unavailable="",
    )


def audit_scope(scope: Scope, workdir: Path, *, runner: Runner = _run) -> Result:
    """Export one scope out of the lock and audit it.

    Args:
        scope: The scope.
        workdir: Directory to write the exported requirements into.
        runner: Subprocess seam.

    Returns:
        The result, with `unavailable` carrying the reason when either step could not answer.
    """
    requirements = workdir / f"{scope.name}.txt"
    failed = export_requirements(scope, requirements, runner=runner)
    if failed:
        return Result(scope, 0, (), (), failed)
    report, unavailable = audit_requirements(requirements, runner=runner)
    if unavailable:
        return Result(scope, 0, (), (), unavailable)
    return read_report(scope, report)


def verdict(result: Result) -> str:
    """The one-word state of a scope, for the right-hand column.

    Args:
        result: The result.

    Returns:
        A short phrase. "not checked" is deliberately not "clean": the whole reason this
        script parses stdout rather than reading an exit code is that those two had been
        indistinguishable.
    """
    if result.unavailable:
        return "NOT CHECKED"
    if result.findings:
        count = len(result.findings)
        return f"{count} advisor{'y' if count == 1 else 'ies'}"
    if result.skipped:
        return f"{len(result.skipped)} not checked"
    return "clean"


def _detail_lines(result: Result) -> list[str]:
    """The indented lines under one scope's heading.

    Args:
        result: The result.

    Returns:
        Either why no answer was obtained, or every advisory and every skipped package. Never
        both: a scope that could not be reached has no report to have findings in, which is
        why this returns early rather than falling through.
    """
    if result.unavailable:
        return [
            "    no answer was obtained, so nothing here was checked:",
            f"      {result.unavailable}",
        ]
    lines: list[str] = []
    for finding in result.findings:
        fix = ", ".join(finding.fix_versions) if finding.fix_versions else "no fix yet"
        aliases = f"  ({', '.join(finding.aliases)})" if finding.aliases else ""
        lines.append(
            f"      {finding.package} {finding.version}  "
            f"{finding.vulnerability}{aliases}  fixed in {fix}"
        )
    lines.extend(f"      {package} was not checked: {reason}" for package, reason in result.skipped)
    return lines


def render(results: Sequence[Result]) -> str:
    """Render the whole audit as one table.

    Args:
        results: One per scope, in scope order.

    Returns:
        The table as a string, so a caller can print it or assert on it.
    """
    lines = ["gantry-sftp dependency audit -- advisories against what uv.lock pins", ""]
    for result in results:
        role = "gates" if result.scope.gates else "reports"
        heading = f"  {result.scope.name:<11} {role:<9} {result.audited:>3} packages"
        lines.append(f"{heading}   {verdict(result)}")
        lines.append(f"    {result.scope.summary}")
        lines.extend(_detail_lines(result))
        lines.append("")
    return "\n".join(lines)


def audit(*, runner: Runner = _run, scopes: Sequence[Scope] = SCOPES) -> tuple[Result, ...]:
    """Audit every scope.

    Args:
        runner: Subprocess seam.
        scopes: The scopes, injectable so a test can drive one.

    Returns:
        One result per scope, in the order given. The exported requirements live in a
        temporary directory and are deleted: they are a derived view of `uv.lock` and a
        committed copy would be a second place for the same versions to be stated.
    """
    with tempfile.TemporaryDirectory(prefix="gantry-audit-") as directory:
        workdir = Path(directory)
        return tuple(audit_scope(scope, workdir, runner=runner) for scope in scopes)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command line without the program name. Defaults to `sys.argv[1:]`.

    Returns:
        A code decided entirely by the gating scope: 1 when it carries an advisory or a
        package that was skipped, 2 when it could not be checked at all, 127 when pip-audit
        is not installed, and 0 otherwise. Whatever the reporting scope found is printed and
        changes nothing -- that is what makes it a reporting scope.
    """
    parser = argparse.ArgumentParser(
        prog="audit_deps.py",
        description="Check uv.lock's pinned versions against known advisories.",
    )
    parser.add_argument(
        "--scope",
        choices=[scope.name for scope in SCOPES],
        help="audit one scope instead of all of them",
    )
    parsed = parser.parse_args(argv)

    if importlib.util.find_spec("pip_audit") is None:
        print(
            "error: pip-audit is not installed -- run `uv sync --group audit`",
            file=sys.stderr,
        )
        return EXIT_NO_TOOL

    chosen = [scope for scope in SCOPES if parsed.scope in (None, scope.name)]
    results = audit(scopes=chosen)
    print(render(results))

    if any(result.blocks for result in results):
        return EXIT_VULNERABLE
    if any(result.unchecked for result in results):
        return EXIT_NOT_CHECKED
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())

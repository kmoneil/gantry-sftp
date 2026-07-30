"""Every lane this repository has, named in one place.

DESIGN.md 10 calls six lanes load-bearing and the Definition of Done cites four of them by
name. Until this file each one existed only as a command somebody had to remember, which is a
lane in the sense that a footpath is a road: it works for exactly as long as the person who
wore it in is still walking it.

A lane here is a name, the argv it runs, what has to be installed before it will do anything,
and **whether it gates**. That last field is the one worth writing down. ``netem``,
``benchmarks`` and ``mutation`` measure rather than assert, or assert against a baseline that
is not in this tree, so they report and do not fail -- and a lane list that called them gates
would make every other lane's word worth less. Each non-gating lane therefore has to say why,
in the field next to it; there is no way to add a quiet one. ``benchmarks`` is the one whose
reason now has an exception inside it, and the exception is what the field has to carry: a
*figure* there has nothing to be compared against, but the size sweep's *shape* is internal to
one run, so it asserts. Measurement and assertion are not the same axis as absolute and
relative, and the field says which is which rather than implying a lane is all one thing.

Nothing here installs anything, and that is deliberate rather than lazy. A lane that ran
``uv sync --group bench`` on your behalf would make "the comparison libraries are deliberately
not installed by default" false whenever somebody ran the wrong lane -- and that default is
how the no-cryptography claim stays checkable. The prerequisite is stated; the caller installs
it. Lanes whose dependencies are absent skip with a reason of their own, which is their
contract and not this file's.

Usage::

    python scripts/lanes.py                 # the table
    python scripts/lanes.py fast live       # run those lanes, in that order
    python scripts/lanes.py -n benchmarks   # print the argv, run nothing

The tools are resolved inside ``.venv`` rather than taken from ``PATH``, for the same reason
``.pre-commit-config.yaml`` uses local hooks: the versions that gate have to be the ones
``uv.lock`` pins, not whatever a shell happens to find first.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Lane:
    """One named way of running this project's proofs.

    Attributes:
        name: What you type after ``lanes.py``.
        summary: What the lane proves, in one line.
        tool: Executable inside ``.venv``, without a platform suffix.
        args: Arguments after the tool.
        needs: Prerequisites, in prose, as the thing a reader would have to install or
            enable. Stated rather than probed: the lanes do their own probing and skip
            with the line that would fix them.
        reports_only: Why this lane reports instead of gating, or ``""`` if it gates. A
            non-gating lane with no reason is not allowed, so opting out is a written act.
        takes: Rough wall clock, so nobody starts the four-minute one by accident.
    """

    name: str
    summary: str
    tool: str
    args: tuple[str, ...]
    needs: str
    reports_only: str
    takes: str

    @property
    def gates(self) -> bool:
        """Whether a failure here should stop the change."""
        return not self.reports_only


# Every pytest lane runs `python -m pytest`, never the `pytest` console script, and that is
# not a stylistic preference: the console script does not put the repository root on
# `sys.path`, so `tests/test_benchmark_harness.py` and `tests/test_lanes.py` fail collection
# with an error that blames pytest rather than the invocation. Same spelling as the pre-push
# hook, for the same reason.
LANES: tuple[Lane, ...] = (
    Lane(
        name="gates",
        summary="ruff, mypy, ty, complexipy, the uv.lock check and the exec-bit check",
        tool="pre-commit",
        args=("run", "--all-files"),
        needs=(
            "uv sync. POSIX only -- the local hooks name .venv/bin/* by path, which does "
            "not exist on Windows, so this lane runs on one platform and the things it "
            "checks are platform-independent anyway"
        ),
        reports_only="",
        takes="seconds",
    ),
    Lane(
        name="fast",
        summary="unit tests, the real sftp-server rows, and every example run as a subprocess",
        tool="python",
        args=("-m", "pytest"),
        needs=(
            "uv sync. openssh-server for the real-server rows, which skip with a reason "
            "without it. This is the pre-push hook's lane"
        ),
        reports_only="",
        takes="under a minute",
    ),
    Lane(
        name="live",
        summary="a real sshd on localhost: transport, ssh environment, cancellation, handles",
        tool="python",
        args=("-m", "pytest", "live-tests/"),
        needs=(
            "openssh-server. Superset of matrix and netem: inside this lane those rows "
            "skip silently unless their own prerequisites happen to be present, which is "
            "why they are also lanes of their own"
        ),
        reports_only="",
        takes="a couple of minutes",
    ),
    Lane(
        name="matrix",
        summary="one client against three servers -- OpenSSH, asyncssh and paramiko",
        tool="python",
        args=("-m", "pytest", "live-tests/test_matrix.py"),
        needs=(
            "uv sync --group bench, plus openssh-server. Two of the three servers are the "
            "comparison libraries, which are not installed by default"
        ),
        reports_only="",
        takes="under a minute",
    ),
    Lane(
        name="netem",
        summary="every pipelining claim, measured on a tc-shaped link at 5/50/200 ms RTT",
        tool="python",
        args=("-m", "pytest", "live-tests/test_netem_pipelining.py"),
        needs=(
            "CAP_NET_ADMIN (docker run --cap-add=NET_ADMIN) and a way for this user to "
            "exercise it, plus openssh-server. It shapes lo, so it slows down everything "
            "else running on the machine for as long as it holds a profile -- and two "
            "copies of this lane at once measure each other's link, which its first row "
            "catches by measuring the RTT rather than restating it"
        ),
        reports_only=(
            "its rows compare measured throughput, so they are only ever as steady as the "
            "machine underneath them; each compared leg is now the fastest of a few over a "
            "warmed connection (D-81), which took the flakes out, but a shared CI runner "
            "still measures whoever else is on it, so this reports weekly rather than "
            "gating a pull request"
        ),
        takes="about 80 seconds",
    ),
    Lane(
        name="benchmarks",
        summary="wall clock and CPU against paramiko and asyncssh over the same shaped link",
        tool="python",
        args=("-m", "pytest", "benchmarks/", "-s"),
        needs="uv sync --group bench, openssh-server, and CAP_NET_ADMIN as netem",
        reports_only=(
            "there is no committed baseline to compare a run's *figures* against, so it can "
            "print a throughput regression but not fail on one (D-63). One thing in it does "
            "assert, and needs no baseline to: the size sweep fails when our own throughput "
            "falls as the file grows, which is a claim about a single run's shape rather than "
            "about a number (D-92)"
        ),
        takes="minutes",
    ),
    Lane(
        name="mutation",
        summary="mutmut over codec/ -- whether an assertion would notice the line being wrong",
        tool="mutmut",
        args=("run",),
        needs=(
            "uv sync. Writes a mutants/ copy of src/ and a generated setup.cfg, both "
            "gitignored. Follow it with `mutmut results` to see the survivors"
        ),
        reports_only=(
            "`mutmut run` exits 0 whether or not mutants survive, and the register of "
            "known-equivalent survivors lives in the gitignored _plans/ tree, so there is "
            "nothing in this repository for a machine to compare a run against"
        ),
        takes="about four minutes",
    ),
)

LANES_BY_NAME: dict[str, Lane] = {lane.name: lane for lane in LANES}


def venv_executable(
    tool: str,
    *,
    platform: str | None = None,
    venv: Path | None = None,
) -> Path:
    """Locate a tool inside the project's virtualenv.

    Args:
        tool: Executable name with no suffix, as ``uv`` installs it.
        platform: ``sys.platform`` value to resolve for. Injectable so the Windows branch
            is testable from anywhere, the same reason ``resolve_ssh_executable`` takes it.
        venv: Virtualenv root. Defaults to ``.venv`` beside ``pyproject.toml``.

    Returns:
        The path the tool would have if ``uv sync`` has been run. Existence is the
        caller's problem, because "not there" and "wrong one" want different messages.
    """
    platform = sys.platform if platform is None else platform
    venv = REPO_ROOT / ".venv" if venv is None else venv
    if platform.startswith("win"):
        return venv / "Scripts" / f"{tool}.exe"
    return venv / "bin" / tool


def lane_argv(lane: Lane) -> list[str]:
    """The full argv a lane runs.

    Args:
        lane: The lane.

    Returns:
        A list, never a string and never for a shell -- there is no shell anywhere in this
        project, and a lane runner is not where the first one gets introduced.
    """
    return [str(venv_executable(lane.tool)), *lane.args]


def _wrapped(text: str, width: int) -> list[str]:
    """Wrap one field of the table, indented under its lane.

    Args:
        text: The prose.
        width: Column to wrap at.

    Returns:
        The lines, ready to append. Hyphens and long words are never broken: "platform-
        independent" split across two lines is a different string from the one the lane
        actually carries, and this table is asserted against those strings.
    """
    return textwrap.wrap(
        text,
        width=width,
        initial_indent="    ",
        subsequent_indent="      ",
        break_on_hyphens=False,
        break_long_words=False,
    )


def describe(width: int = 96) -> str:
    """Render the lane table.

    Args:
        width: Column to wrap prose at. The reasons a lane does not gate are sentences
            rather than labels, and an unwrapped one is a sentence nobody reads.

    Returns:
        The whole table as one string, so a caller can print it or assert on it.
    """
    lines = ["gantry-sftp lanes -- python scripts/lanes.py <name>...", ""]
    for lane in LANES:
        verdict = "gates" if lane.gates else "reports only"
        tool = venv_executable(lane.tool)
        shown = tool.relative_to(REPO_ROOT) if tool.is_relative_to(REPO_ROOT) else tool
        lines.append(f"  {lane.name:<11} {verdict:<13} {lane.takes}")
        lines.extend(_wrapped(lane.summary, width))
        lines.append(f"    runs:  {shown} {' '.join(lane.args)}")
        lines.extend(_wrapped(f"needs: {lane.needs}", width))
        if lane.reports_only:
            lines.extend(_wrapped(f"why it does not gate: {lane.reports_only}", width))
        lines.append("")
    return "\n".join(lines)


def run_lane(lane: Lane, *, dry_run: bool = False) -> int:
    """Run one lane.

    Args:
        lane: The lane to run.
        dry_run: Print the argv and return 0 without spawning anything.

    Returns:
        The tool's exit code, 0 for a dry run, or 127 when the tool is not installed --
        which is a missing ``uv sync`` rather than a failing lane, and says so.
    """
    argv = lane_argv(lane)
    print(f">>> {lane.name}: {' '.join(argv)}")
    if dry_run:
        return 0
    if not Path(argv[0]).exists():
        print(
            f"error: {argv[0]} is not there -- run `uv sync` first "
            f"(and `uv sync --group bench` for the lanes whose prerequisites say so)",
            file=sys.stderr,
        )
        return 127
    return subprocess.run(argv, cwd=REPO_ROOT, check=False).returncode


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command line, without the program name. Defaults to ``sys.argv[1:]``.

    Returns:
        The first non-zero lane exit code, or 0. Lanes run in the order given and stop at
        the first failure: a lane list is a sequence of proofs, and the ones after a broken
        gate are answering a question nobody should be asking yet.
    """
    parser = argparse.ArgumentParser(
        prog="lanes.py",
        description="Run one of this project's test lanes. With no lane, print the table.",
    )
    parser.add_argument("lanes", nargs="*", metavar="LANE", help="lane names, in order")
    parser.add_argument("-l", "--list", action="store_true", help="print the lane table and exit")
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="print the argv each lane would run, and run nothing",
    )
    parsed = parser.parse_args(argv)

    if parsed.list or not parsed.lanes:
        print(describe())
        return 0

    unknown = [name for name in parsed.lanes if name not in LANES_BY_NAME]
    if unknown:
        known = ", ".join(lane.name for lane in LANES)
        print(
            f"error: unknown lane {unknown[0]!r}; known lanes are {known}",
            file=sys.stderr,
        )
        return 2

    for name in parsed.lanes:
        code = run_lane(LANES_BY_NAME[name], dry_run=parsed.dry_run)
        if code != 0:
            return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

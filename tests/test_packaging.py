"""What a user actually receives, asserted against a real build.

Every other test in this suite runs against the source tree. None of them can see a packaging
defect, and packaging defects are silent by construction: the wheel built fine, imported fine
and shipped `License-Expression: Apache-2.0` with **no licence text in it at all** -- measured,
which is how it was found. Apache-2.0 section 4(a) requires the copy to travel with the
distribution, so that is a legal defect on the release surface that every green test agreed with.

So this module builds the distribution and looks inside it. It is the slowest test here by some
margin and it earns that: the alternative is finding out from the first person to run a
compliance scan.
"""

from __future__ import annotations

import errno
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

import gantry_sftp
from gantry_sftp.session import (
    DEFAULT_PIPELINE_DEPTH,
    PREFERRED_READ_LENGTH,
    PREFERRED_WRITE_LENGTH,
)
from gantry_sftp.transport import missing_executable_hint

ROOT = Path(__file__).resolve().parent.parent
LICENCE = ROOT / "LICENSE"


def test_the_licence_text_ships_in_the_repository():
    """The identifier is not the grant. `license = "Apache-2.0"` in `pyproject.toml` is an SPDX
    expression; the text is a separate obligation and it is this file."""
    assert LICENCE.is_file(), "LICENSE is missing; the SPDX identifier alone grants nothing"
    text = LICENCE.read_text(encoding="utf-8")
    assert text.startswith("\n                                 Apache License\n")
    assert "Version 2.0, January 2004" in text
    # The patent grant is the clause this licence was chosen for -- see DESIGN.md 12.3 -- so it
    # is named rather than assumed present in a file nobody reads.
    assert "3. Grant of Patent License." in text


def test_pyproject_declares_the_licence_file():
    """A `license-files` entry is what puts `License-File:` in METADATA. Without it the build
    is happy, the metadata is wrong, and nothing fails."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license-files = ["LICENSE"]' in pyproject
    assert 'license = "Apache-2.0"' in pyproject


def test_the_version_is_written_in_exactly_one_place():
    """`pyproject.toml` reads the version from the package rather than restating it.

    Two hand-maintained copies drift, and the way they announce it is a bug report naming a
    release the reporter did not install.
    """
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in pyproject
    assert '[tool.hatch.version]\npath = "src/gantry_sftp/__init__.py"' in pyproject
    assert f'version = "{gantry_sftp.__version__}"' not in pyproject


@pytest.fixture(scope="session")
def distribution(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Build both artifacts once, or skip with the reason the build could not run.

    Session-scoped because a build is seconds and the three tests below inspect the same two
    files. `UV_CACHE_DIR` is passed through rather than left to chance: the default
    `~/.cache/uv` is root-owned in this sandbox, and a test that skips because of *that* reports
    the machine rather than the package.
    """
    if shutil.which("uv") is None:
        pytest.skip("uv is not on PATH; this lane builds the distribution to inspect it")

    destination = tmp_path_factory.mktemp("dist")
    environment = dict(os.environ)
    environment.setdefault("UV_CACHE_DIR", str(tmp_path_factory.mktemp("uv-cache")))
    finished = subprocess.run(
        ["uv", "build", "--out-dir", str(destination)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    if finished.returncode != 0:
        # A build needs the backend, which means the network on a cold cache. That is a missing
        # dependency rather than a failure of this project -- skip with what it actually said.
        pytest.skip(f"uv build failed, so there is nothing to inspect:\n{finished.stderr[-500:]}")

    wheels = sorted(destination.glob("*.whl"))
    sdists = sorted(destination.glob("*.tar.gz"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"
    assert len(sdists) == 1, f"expected one sdist, got {sdists}"
    return wheels[0], sdists[0]


@pytest.mark.slow
def test_the_built_wheel_carries_the_licence_and_names_it_in_the_metadata(
    distribution: tuple[Path, Path],
):
    wheel, _ = distribution
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata = next(name for name in names if name.endswith(".dist-info/METADATA"))
        text = archive.read(metadata).decode("utf-8")
        licences = [name for name in names if name.endswith("dist-info/licenses/LICENSE")]
        assert licences, f"no licence text in the wheel: {sorted(names)[:20]}"
        assert archive.read(licences[0]).decode("utf-8") == LICENCE.read_text(encoding="utf-8")

    assert "License-Expression: Apache-2.0" in text
    assert "License-File: LICENSE" in text
    assert f"Version: {gantry_sftp.__version__}" in text


@pytest.mark.slow
def test_the_sdist_carries_the_licence_too(distribution: tuple[Path, Path]):
    """Both artifacts, because they are built by different code paths and a source
    distribution is what a downstream packager rebuilds from."""
    _, sdist = distribution
    with tarfile.open(sdist) as archive:
        members = archive.getnames()
        assert any(name.endswith("/LICENSE") for name in members), members[:20]


@pytest.mark.slow
def test_the_built_version_comes_from_the_package(distribution: tuple[Path, Path]):
    """The single-sourcing, proven at the one moment it matters: what the artifact is called."""
    wheel, sdist = distribution
    assert wheel.name.startswith(f"gantry_sftp-{gantry_sftp.__version__}-")
    assert sdist.name == f"gantry_sftp-{gantry_sftp.__version__}.tar.gz"


# --- The README is a shipped artifact, so its facts are asserted too (D-89) ----------------


def test_the_readme_and_pyproject_agree_on_the_python_floor():
    """Two hand-maintained copies of the same number, and one of them is the first thing a
    reader sees. `requires-python` is what actually refuses an install; the README line is what
    somebody plans around, and a reader who plans around the wrong one finds out from pip.
    """
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.13"' in pyproject
    assert "**Python 3.13+**" in readme
    assert "- Python 3.13+" in readme


def test_the_readme_quotes_the_missing_ssh_hint_exactly_as_the_code_produces_it():
    """The hint is quoted verbatim in the README, which makes it a two-place fact.

    It is the highest-value sentence in the document -- the one a reader in a broken container
    acts on -- so a reworded hint that leaves the README behind is the drift worth catching.
    Whitespace is normalised because the README reflows it to the page width; wording is not.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    produced = " ".join(missing_executable_hint("ssh", errno_value=errno.ENOENT).split())
    quoted = " ".join(readme.split())
    assert f"hint: {produced}" in quoted


def test_the_documented_memory_bound_is_derived_from_the_shipped_constants():
    """D-101. The README states an expression and a number; both come from two constants.

    A platform team sizes a container on this figure, and the failure mode if it drifts is the
    worst kind: the limit is exceeded in production and Cloud Run and Lambda kill the container
    with no Python traceback at all. So the number is not allowed to be a number somebody typed
    once -- if either constant moves, this fails and names the new arithmetic.

    Two constants, and neither is a parameter a caller sets: ``DEFAULT_PIPELINE_DEPTH`` is what
    ``depth`` defaults to, and ``PREFERRED_READ_LENGTH`` is what the request size is *before*
    the per-connection clamp, which can only make it smaller. So the documented figure is the
    ceiling rather than an estimate.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    peak = DEFAULT_PIPELINE_DEPTH * PREFERRED_READ_LENGTH
    mebibytes = round(peak / 2**20)

    # Whitespace-normalised, as the ssh-hint test is and for the same reason: the README aligns
    # the expression to read as arithmetic, and a reflow is not a drift in the fact.
    times = "\u00d7"  # written as an escape; RUF001 is right that the glyph reads as an `x`
    spelled = " ".join(readme.split())
    assert f"= 1 {times} {DEFAULT_PIPELINE_DEPTH} {times} {PREFERRED_READ_LENGTH} bytes" in spelled
    assert f"concurrent transfers {times} depth {times} request size" in spelled
    assert f"{mebibytes} MiB per transfer" in readme
    # And the same figure on the deployment screen, which is the one a reader meets first.
    assert f"About {mebibytes} MiB of memory per concurrent transfer" in readme
    # The write side shares the bound, so a divergence between the two preferred lengths would
    # make one of the two directions cost more than the document says.
    assert PREFERRED_WRITE_LENGTH == PREFERRED_READ_LENGTH


def test_the_lowered_depth_example_still_arrives_at_the_number_it_claims():
    """The README offers `depth=8` as the way into a smaller container and states the result.

    Worth its own assertion because it is the actionable half: a reader who copies the setting
    is trusting the figure beside it, and that figure is a second place the arithmetic lives.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    lowered = 8
    assert f"SessionOptions(depth={lowered})" in readme
    assert f"about {round(lowered * PREFERRED_READ_LENGTH / 2**20)} MiB" in readme


# --- No shipped document states a throughput figure (D-88) ----------------------------------

# The multiplication sign is written as an escape rather than pasted: ruff's RUF001 is right
# that the glyph is ambiguous with an `x` in source, and `re` reads the escape itself.
THROUGHPUT_CLAIM_SHAPES = (
    # "1.35x faster", "1.6-3.2 times slower", "1.2-1.6x worse"
    r"\d+(?:\.\d+)?\s*(?:[\u00d7x]|times)\s*(?:faster|slower|better|worse)",
    # an unquantified cross-library speed claim, which is the same marketing minus the number
    r"(?:faster|slower)\s+than\s+(?:paramiko|asyncssh|scp|rsync|`?sftp\(1\)`?)",
    # an absolute rate: "24.8 MiB/s", "100 Mbit/s"
    r"\d+(?:\.\d+)?\s*(?:[MKG]i?B|[MKG]bit)\s*/\s*s",
    # "3.2x paramiko"
    r"\d+(?:\.\d+)?\s*[\u00d7x]\s*(?:paramiko|asyncssh)",
)

# A figure describing a *defect in someone else's* throughput, carrying the tracker item it was
# read from, is evidence about a failure mode rather than a claim about our rate -- and it is the
# form D-91's inventory asked for, since nobody complains in ratios: they report a cliff, a stall
# or a hang. So a match is excused by a citation next to it, and by nothing else.
CITATION = re.compile(r"(?:paramiko|asyncssh|fsspec)#\d+")


def shipped_prose() -> list[Path]:
    """Every document a user reads to learn what this library is. Three deliberate absences.

    `benchmarks/` is the sanctioned home, so it is not scanned. Neither is `live-tests/`, for the
    same reason one layer down: it is the lane that *produces* the pipelining figures, and a proof
    may state what it measured -- both are excluded as measurement lanes rather than as documents.
    CLAUDE.md is out because it is addressed to whoever changes the library rather than to whoever
    uses it, and it quotes the banned shape on purpose, inside the rule that bans it.
    """
    return [
        ROOT / "README.md",
        *sorted((ROOT / "examples").rglob("*.md")),
        *sorted((ROOT / "examples").rglob("*.py")),
        *sorted((ROOT / "src").rglob("*.py")),
    ]


@pytest.mark.parametrize("document", shipped_prose(), ids=lambda path: path.name)
def test_no_shipped_document_states_a_throughput_figure(document: Path):
    """The rule this project could not follow while it was only about sourcing (D-88).

    The old Docs Rule -- "performance claims are dated and sourced or they are not made" -- was
    satisfied by every sentence that broke it: the README's longest section was throughput, and
    the front screen led with ratios against both competitors, all of it correctly dated and
    sourced. DESIGN 2.1 ranks a correctness gap above a throughput feature, so a shipped document
    that leads with ratios argues against the thesis it opens with.

    Relocation is the fix rather than deletion, and the other half of it is
    `test_the_benchmark_report_keeps_the_rows_that_do_not_flatter_us`: a rule that only removed
    figures would take the two that go the wrong way with them.
    """
    text = document.read_text(encoding="utf-8")
    lines = text.splitlines()
    offences = []
    for shape in THROUGHPUT_CLAIM_SHAPES:
        for match in re.finditer(shape, text, re.IGNORECASE):
            number = text[: match.start()].count("\n")
            window = "\n".join(lines[max(0, number - 1) : number + 2])
            if not CITATION.search(window):
                offences.append(f"{document.name}:{number + 1}: {match.group(0)!r}")
    assert not offences, (
        "throughput figures belong in benchmarks/README.md and nowhere else (D-88): "
        + "; ".join(offences)
    )


def test_the_benchmark_lane_still_names_the_costs_it_measured():
    """The honesty property, which outlived the form it was written in (D-88, then D-94).

    D-88 relocated the ratio tables into `benchmarks/README.md` on the argument that deleting
    them would take the two rows that do not flatter us -- the connect cost and the CPU column
    -- down with the wins, and that a selectively positive record is worse than the
    front-loading it replaced. D-94 then moved the *figures* out of the committed tree
    entirely, into the report the suite generates, which is gitignored.

    That is a deliberate change and not a quiet reversal of the first one, because the property
    D-88 was protecting is not "the tables exist" -- it is that **a reader who never runs the
    lane still learns where this architecture costs something**. So the losses are still named,
    in prose instead of in a column, and they are pinned here: a future edit can rewrite the
    sentence and cannot silently drop the admission.
    """
    lane = (ROOT / "benchmarks" / "README.md").read_text(encoding="utf-8")
    admissions = (
        "slower to connect",
        "wins nothing on CPU",
    )
    missing = [phrase for phrase in admissions if phrase not in lane]
    assert not missing, f"benchmarks/README.md stopped naming what this costs: {missing}"


def test_the_committed_tree_holds_no_benchmark_figures():
    """The other half of D-94: the numbers went to a generated report, not to a nicer table.

    `benchmarks/README.md` is excluded from the prose sweep above because it is the lane's
    method document and quotes the banned shape inside the rule that bans it. That exclusion
    would be a hole if nothing checked the file itself, so this is the check: the results
    tables are gone, and what a reader is pointed at is the generated report.
    """
    lane = without_typography((ROOT / "benchmarks" / "README.md").read_text(encoding="utf-8"))
    for shape in THROUGHPUT_CLAIM_SHAPES:
        for match in re.finditer(shape, lane, re.IGNORECASE):
            if match.group(0).endswith("Mbit/s"):
                # A `tc` rate limit, which names a profile rather than reporting a result. A
                # number the harness *sets* is not a number it *found*, and nothing this
                # library does is measured in bits per second -- the report uses MiB/s.
                continue
            number = lane[: match.start()].count("\n")
            window = "\n".join(lane.splitlines()[max(0, number - 1) : number + 2])
            assert CITATION.search(window) or "unattributed" in window, (
                f"benchmarks/README.md:{number + 1} carries a figure again: {match.group(0)!r}"
            )
    assert "_reports/benchmarks.md" in lane, "the lane must say where its figures actually go"


def without_typography(text: str) -> str:
    """An `x` and a `-` for the glyphs, so this module's own source carries neither.

    Normalising both sides is also the right strictness: the subject of the assertion below is
    the claim, not its punctuation, and an en dash relaxing into a hyphen should not fail it.
    """
    return text.replace("\u00d7", "x").replace("\u2013", "-")


def test_the_readme_sends_a_reader_who_wants_numbers_somewhere_real():
    """The pointer is the other half of the relocation, and a dangling one is worse than a ratio.

    A reader who wants to know how fast this is has to be told where the figures went, by name,
    or the effect of D-88 is that the question stopped being answered.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "benchmarks/README.md" in readme
    assert (ROOT / "benchmarks" / "README.md").is_file()


# --- What the distribution carries, decided rather than defaulted (D-94) --------------------

SHIPPED = ("src", "tests", "examples", "live-tests", "scripts", "README.md", "LICENSE")
"""Top-level entries an sdist must carry.

`tests/` and `examples/` are in for a reason worth stating, because "why ship tests?" gets asked
every few years: Debian, Fedora and conda-forge rebuild from the sdist and run the suite to
validate their build, and `examples/` is tested documentation with a README of its own.
"""

WITHHELD = (
    "benchmarks",
    ".github",
    ".pre-commit-config.yaml",
    "pyrightconfig.deprecations.json",
    ".complexipy_cache",
)
"""Top-level entries an sdist must **not** carry, and each one is a decision.

`benchmarks/` needs paramiko and asyncssh -- the Python cryptography this library exists not to
need -- plus `openssh-server` and `CAP_NET_ADMIN`, and it is not self-contained anyway, since it
imports `sshd` from `live-tests/`. A shipped directory that cannot run is worse than an absent
one. It stays in the repository, in CI and gating; it is simply not part of what a user receives.

`.complexipy_cache` is in this list because it **was shipping**, unnoticed, until the tarball was
opened and looked at -- the same class of silent packaging defect as the missing licence text
this module was written for. A lint cache in a distribution is not a style question.

`pyrightconfig.deprecations.json` goes with `.pre-commit-config.yaml` for the same reason it sits
beside it: it is the config for a hook, and the hook is not shipped either. A user who receives
the sdist gets no `basedpyright` to read it.

`.gitignore` is deliberately absent from both lists: hatchling force-includes it whatever the
excludes say, measured on a real build, so asserting either way would be asserting about
hatchling rather than about a decision of ours.
"""


@pytest.mark.slow
def test_the_sdist_carries_what_was_decided_and_nothing_else(distribution: tuple[Path, Path]):
    """Hatchling's default is "the whole working tree", which is not a decision.

    A packaging exclusion is invisible from the source tree by construction: every test passes,
    the build succeeds, and the only way to see what a user receives is to open the artifact.
    That is why this asserts both directions -- a `WITHHELD` entry creeping back in would look
    exactly like nothing having happened.
    """
    _, sdist = distribution
    with tarfile.open(sdist) as archive:
        top = {name.split("/")[1] for name in archive.getnames() if "/" in name}

    missing = sorted(entry for entry in SHIPPED if entry not in top)
    assert missing == [], f"the sdist stopped carrying: {missing}"
    leaked = sorted(entry for entry in WITHHELD if entry in top)
    assert leaked == [], f"the sdist is carrying what it was told not to: {leaked}"


@pytest.mark.slow
def test_the_wheel_carries_only_the_package(distribution: tuple[Path, Path]):
    """The wheel is what `pip install` unpacks into site-packages, so anything beyond the
    package itself lands in a user's environment under a name they did not choose."""
    wheel, _ = distribution
    with zipfile.ZipFile(wheel) as archive:
        top = {name.split("/")[0] for name in archive.namelist()}
    unexpected = sorted(name for name in top if not name.startswith("gantry_sftp"))
    assert unexpected == [], f"the wheel carries more than the package: {unexpected}"

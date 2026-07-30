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


def without_typography(text: str) -> str:
    """An `x` and a `-` for the glyphs, so this module's own source carries neither.

    Normalising both sides is also the right strictness: the subject of the assertion below is
    the claim, not its punctuation, and an en dash relaxing into a hyphen should not fail it.
    """
    return text.replace("\u00d7", "x").replace("\u2013", "-")


def test_the_benchmark_report_keeps_the_rows_that_do_not_flatter_us():
    """Relocated, not deleted -- and this is the half that decays quietly.

    Moving the numbers out of the README could have been done by deleting them, and the result
    would read better: what leaves with them is the connect cost, the CPU column, the small-file
    upload loss and the clause forbidding an unattributed "10x faster than paramiko". A record
    with only the wins in it is worse than the front-loading D-88 set out to fix, because the
    honesty artifact and the wins are the same artifact. So the losses are pinned by content.
    """
    report = without_typography((ROOT / "benchmarks" / "README.md").read_text(encoding="utf-8"))
    losses = (
        "| connect and close | **1.2-1.4x slower** | **1.2-2.1x slower** |",
        "**1.7-1.8x slower unshaped**",
        "| CPU per MiB, download | about the same | **1.2-1.6x worse** |",
        "**Connecting is our weak spot, and it is structural.**",
        '"No cryptography in Python" does not become a CPU win.',
        'Nothing here is an unattributed "10x faster than paramiko"',
    )
    missing = [row for row in losses if row not in report]
    assert not missing, f"benchmarks/README.md dropped the rows that do not flatter us: {missing}"


def test_the_readme_sends_a_reader_who_wants_numbers_somewhere_real():
    """The pointer is the other half of the relocation, and a dangling one is worse than a ratio.

    A reader who wants to know how fast this is has to be told where the figures went, by name,
    or the effect of D-88 is that the question stopped being answered.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "benchmarks/README.md" in readme
    assert (ROOT / "benchmarks" / "README.md").is_file()

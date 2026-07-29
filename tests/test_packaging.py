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

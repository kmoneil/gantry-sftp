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
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import pytest

import gantry_sftp
from gantry_sftp.session import (
    DEFAULT_PIPELINE_DEPTH,
    PREFERRED_READ_LENGTH,
    PREFERRED_WRITE_LENGTH,
    Session,
)
from gantry_sftp.transport import DEFAULT_SSH_OPTIONS, missing_executable_hint

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


def test_the_changelog_describes_the_code_as_it_stands():
    """D-124. A release whose changelog does not mention it is a changelog nobody can use.

    The version is single-sourced from ``__init__.py``, so this is the one place the two are
    compared: a bump that forgets the entry ships METADATA pointing at a `Changelog` URL whose
    top section describes the release before it.

    **Two states are legal and the second one is not laxity.** A section named for
    ``__version__`` is one. An ``## Unreleased`` section is the other, and it is what is true
    before a version is tagged -- which for a repository with no ``v*`` tag and nothing on PyPI
    is every commit so far. Requiring the numbered heading unconditionally is what produced the
    thing this test exists to prevent, in the opposite direction: a dated
    ``## 0.1.0 (2026-08-03)`` for a release nobody could install, which read to its own author as
    proof that a version was already out.

    What is *not* legal is neither: a tree whose changelog names no version and admits to no
    pending work has stopped describing the code. And the stronger requirement -- that a tagged
    release carries the numbered heading rather than ``Unreleased`` -- is enforced at the only
    moment it can be, in ``release.yml``, beside the check that the tag matches the version.
    """
    changelog = ROOT / "CHANGELOG.md"
    assert changelog.is_file(), "CHANGELOG.md is missing"
    text = changelog.read_text(encoding="utf-8")
    named = f"## {gantry_sftp.__version__}" in text
    pending = "## Unreleased" in text
    assert named or pending, (
        f"CHANGELOG.md has neither a section for {gantry_sftp.__version__} nor an "
        f"'## Unreleased' section, so it describes neither a release nor the work since one"
    )


def test_the_changelog_states_the_limitations_rather_than_only_the_features():
    """The honesty property, in the one document a user reads at upgrade time.

    D-88 established that the costs stay stated even when the figures go, and pinned that for
    `benchmarks/README.md`. A release note is where the same rule bites hardest: a list of
    features with no limitations reads as a complete description and is not one. These four are
    decided, tested positions rather than defects to fix -- what would be dishonest is letting a
    user discover them.
    """
    text = ROOT / "CHANGELOG.md"
    changelog = " ".join(text.read_text(encoding="utf-8").split())
    for admission in (
        "Transfers refuse on Windows",
        "`ssh` is a system dependency",
        "transient `FAILURE`",
        "Connecting is slower",
    ):
        assert admission in changelog, (
            f"the changelog stopped naming a known limitation: {admission}"
        )


def test_the_project_urls_are_declared_absolute_and_share_one_host():
    """They were absent until 0.1.0 and the reason was written into `pyproject.toml`.

    METADATA advertising a Homepage that 404s is the same defect as a docstring pointing at a
    gitignored file, so the field came back with the repository rather than before it. Asserted
    now so it cannot quietly go missing in a build config edit -- PyPI renders each of these as a
    link on the project page, and a release with none is one a reader cannot get behind.

    **This test used to be called ``..._point_at_something_a_reader_can_reach`` and checked that
    four keys appeared in the file.** It could not have failed for a URL that 404s, was a typo,
    or pointed at ``example.com`` -- the exact defect its own docstring says it exists to
    prevent, which is the shape this repository keeps finding: a guard named for a claim it
    does not make. The name now says what it checks.

    **Reachability is deliberately not asserted, and cannot be here**: a test that fetched these
    would need the network, which this suite does not use, and would then fail on an outage
    rather than on a defect. What is checkable offline is checked -- that each field exists,
    that each is an absolute ``https`` URL rather than a path or a placeholder, that all four
    name one host so a typo in any single one stands out against its siblings, and that the
    ``Changelog`` link names a file this repository actually has. That last one is the only
    end-of-link that lives in the tree, so it is the only one whose target can be proven.
    """
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    urls = pyproject["project"].get("urls", {})

    wanted = ("Homepage", "Source", "Issues", "Changelog")
    missing = [field for field in wanted if field not in urls]
    assert not missing, f"[project.urls] lost {missing}"

    hosts = set()
    for field, url in urls.items():
        parsed = urlparse(url)
        assert parsed.scheme == "https", f"{field} is not https: {url!r}"
        assert parsed.netloc, f"{field} names no host, so it is not an absolute URL: {url!r}"
        hosts.add(parsed.netloc)
    assert len(hosts) == 1, f"[project.urls] spans several hosts, which is usually a typo: {hosts}"

    # The one link whose far end is in this tree. A renamed changelog leaves the URL pointing at
    # a file that stopped existing, and nothing else here would notice.
    changelog = PurePosixPath(urlparse(urls["Changelog"]).path).name
    assert (ROOT / changelog).is_file(), (
        f"[project.urls] Changelog points at {changelog!r}, which this repository does not have"
    )


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


# --- The docs are shipped artifacts, so their facts are asserted too (D-89) ----------------

DOCS = ROOT / "docs"
"""Where the reference prose lives, since D-125 split it out of one 3000-line README.

Each assertion below reads the file that now *holds* the fact rather than the README, and the
distinction is the point of the split: a fact belongs on the page a reader is on when they need
it, and a test that kept pointing at the front page would quietly stop checking anything the day
the sentence moved.
"""


def doc(name: str) -> str:
    """One documentation page, read by name, failing loudly if it has been renamed.

    A missing page would otherwise make an `in` assertion below fail with "not found in ''",
    which reads as a reworded sentence rather than as a deleted file.
    """
    page = DOCS / name
    assert page.is_file(), f"docs/{name} is gone; the fact it holds needs a new home"
    return page.read_text(encoding="utf-8")


def test_every_guide_the_readme_advertises_exists():
    """The front page is now a table of contents, and a dead row in it is worse than no row.

    D-125 moved the reference prose into `docs/`, which makes the README's job pointing at it.
    A link that 404s on the day somebody renames a page is the failure this catches, and it is
    derived from the README's own links rather than from a list kept beside them.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    linked = sorted(set(re.findall(r"\]\(docs/([a-z-]+\.md)[)#]", readme)))
    assert len(linked) > 8, f"the README stopped linking the guides: {linked}"
    missing = [name for name in linked if not (DOCS / name).is_file()]
    assert not missing, f"README links documentation that does not exist: {missing}"


def test_the_documentation_index_and_the_readme_offer_the_same_guides():
    """Two tables of contents, so two places to forget a page.

    `docs/README.md` is what a reader browsing the directory sees and the README table is what
    everyone else sees. They are hand-maintained on purpose -- each has its own wording -- so
    the property asserted is that they name the same set of files, not that they read alike.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = doc("README.md")
    from_readme = set(re.findall(r"\]\(docs/([a-z-]+\.md)[)#]", readme))
    from_index = set(re.findall(r"\]\(([a-z-]+\.md)[)#]", index))
    assert from_readme - from_index == set(), "the docs index is missing a guide the README has"
    assert from_index - from_readme == set(), "the docs index has a guide the README does not"


def heading_slugs(page: Path) -> set[str]:
    """Every anchor a Markdown page defines, spelled the way GitHub spells them.

    Lowercase, drop anything that is not a word character, a space or a hyphen, then spaces to
    hyphens. Two details are easy to get wrong and both invent broken links that are not broken:
    an underscore is a word character and survives, and a heading ending in a stripped character
    -- ``rooted at `/` `` -- keeps the trailing hyphen.
    """
    slugs: set[str] = set()
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            text = re.sub(r"[^\w\s-]", "", line.lstrip("#").strip().lower())
            slugs.add(re.sub(r"\s+", "-", text))
    return slugs


def markdown_documents() -> list[Path]:
    return [ROOT / "README.md", *sorted(DOCS.glob("*.md")), ROOT / "examples" / "README.md"]


@pytest.mark.parametrize("page", markdown_documents(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_internal_link_resolves(page: Path):
    """D-125. Splitting one file into thirteen makes a dead link the new drift.

    Every cross-reference used to be an anchor inside the same document, where a rename broke
    something visible immediately. They are now file-plus-anchor across a tree, and a stale one
    is invisible to every other test here: the prose still reads correctly and the link still
    looks like a link. So both halves are checked -- the file exists, and the anchor is a heading
    that file actually defines.
    """
    broken: list[str] = []
    for match in re.finditer(r"\]\(([^)]+)\)", page.read_text(encoding="utf-8")):
        target = match.group(1)
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        relative, _, anchor = target.partition("#")
        destination = (page.parent / relative).resolve() if relative else page
        if relative and not destination.exists():
            broken.append(f"{target} (no such file)")
        elif anchor and destination.suffix == ".md" and anchor not in heading_slugs(destination):
            broken.append(f"{target} (no such heading)")
    assert not broken, f"{page.name} links nowhere: " + "; ".join(broken)


def test_the_link_check_is_not_vacuous():
    """Guards the guard, in both directions.

    A regex that matched no links, or a slugger that returned no headings, would make every page
    above pass while checking nothing -- and the slugger is the half that can fail quietly, since
    it only has to be *wrong* rather than empty to start excusing dead anchors.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert len(re.findall(r"\]\(([^)]+)\)", readme)) > 12
    # Two headings whose slugs exercise the rules the docstring above calls easy to get wrong:
    # an underscore survives, and a heading ending in a stripped character keeps its hyphen.
    assert "when-the-ssh_config-is-not-yours" in heading_slugs(DOCS / "connecting.md")
    assert "servers-whose-namespace-is-not-rooted-at-" in heading_slugs(DOCS / "transfers.md")


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


def test_the_docs_quote_the_missing_ssh_hint_exactly_as_the_code_produces_it():
    """The hint is quoted verbatim in the docs, which makes it a two-place fact.

    It is the highest-value sentence in the documentation -- the one a reader in a broken
    container acts on -- so a reworded hint that leaves the prose behind is the drift worth
    catching. Whitespace is normalised because the page reflows it to the width; wording is not.
    """
    produced = " ".join(missing_executable_hint("ssh", errno_value=errno.ENOENT).split())
    quoted = " ".join(doc("connecting.md").split())
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
    tuning = doc("tuning.md")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    peak = DEFAULT_PIPELINE_DEPTH * PREFERRED_READ_LENGTH
    mebibytes = round(peak / 2**20)

    # Whitespace-normalised, as the ssh-hint test is and for the same reason: the page aligns
    # the expression to read as arithmetic, and a reflow is not a drift in the fact.
    times = "\u00d7"  # written as an escape; RUF001 is right that the glyph reads as an `x`
    spelled = " ".join(tuning.split())
    assert f"= 1 {times} {DEFAULT_PIPELINE_DEPTH} {times} {PREFERRED_READ_LENGTH} bytes" in spelled
    assert f"concurrent transfers {times} depth {times} request size" in spelled
    assert f"{mebibytes} MiB per transfer" in tuning
    # And the same figure on the deployment screen, which is the one a reader meets first --
    # still the README, because sizing a container is a decision taken before installing.
    assert f"About {mebibytes} MiB of memory per concurrent transfer" in readme
    # The write side shares the bound, so a divergence between the two preferred lengths would
    # make one of the two directions cost more than the document says.
    assert PREFERRED_WRITE_LENGTH == PREFERRED_READ_LENGTH


def test_the_lowered_depth_example_still_arrives_at_the_number_it_claims():
    """The docs offer `depth=8` as the way into a smaller container and state the result.

    Worth its own assertion because it is the actionable half: a reader who copies the setting
    is trusting the figure beside it, and that figure is a second place the arithmetic lives.
    """
    tuning = doc("tuning.md")
    lowered = 8
    assert f"SessionOptions(depth={lowered})" in tuning
    assert f"about {round(lowered * PREFERRED_READ_LENGTH / 2**20)} MiB" in tuning


def test_the_docs_say_who_owns_the_total_concurrency_and_the_tree_methods_point_at_it():
    """D-116. Two layers bound the concurrency and the caller owns the product.

    A fact stated in four places is four places to update, so one section is the anchor and the
    two `concurrency=` docstrings defer to it rather than restate it. That arrangement is only
    safe if something notices when a pointer stops pointing anywhere -- a docstring naming a
    section that has been renamed is worse than one that said nothing, because it reads as a
    citation.

    The measurement behind it is in DESIGN 5.2 and is deliberately not asserted here: it is a
    throughput result, it belongs to the machine it was taken on, and `benchmarks/` is the only
    place figures live (D-94).
    """
    concurrency = doc("concurrency.md")
    # The code span is spelled with one backtick in Markdown and two in the docstrings' RST, so
    # the assertion is on the words. Asserting the punctuation would fail on a correct citation.
    anchor = "bounds one call, and you own the product"
    assert f"### `concurrency=` {anchor}" in concurrency
    # The memory section states the same product for a different cost, and the two halves
    # drifting apart is exactly what D-101 and this card each fixed one side of. It now lives on
    # another page, so the link that joins them crosses a file and is checked as one.
    assert "concurrency.md#concurrency-bounds-one-call-and-you-own-the-product" in doc("tuning.md")

    downloads = Session.get_tree.__doc__
    uploads = Session.put_tree.__doc__
    assert downloads is not None
    assert uploads is not None
    assert anchor in " ".join(downloads.split())
    # `put_tree` defers to `get_tree` for the whole of what `concurrency=` means, so what it owes
    # is the referral, not the sentence.
    assert "the total across several calls is the caller's" in " ".join(uploads.split())


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

    **`docs/` is in, and adding it was the whole risk of D-125.** The ban below was written when
    the documentation was one file; moving 2700 lines of prose out of that file without widening
    the sweep would have left the rule intact and pointed at a README with nothing left in it --
    a green test over an empty subject, which is the failure mode this repository keeps finding
    in its own guards.
    """
    return [
        ROOT / "README.md",
        *sorted((ROOT / "docs").rglob("*.md")),
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


def test_every_shipped_ssh_option_is_documented_with_the_value_it_ships():
    """A `-o` on the command line beats the user's `ssh_config`, so every entry here is a setting
    somebody may have written down and will not get. That makes the set a documentation
    obligation rather than an implementation detail.

    Found by `ControlMaster=no`, which shipped in `DEFAULT_SSH_OPTIONS` and appeared in no page
    under `docs/` -- while `README.md`, `docs/architecture.md` and `benchmarks/README.md` each
    described `ControlMaster` as something OpenSSH gives you for free. Measured against OpenSSH
    10.0p2: a config asking for `ControlMaster auto` resolves to `controlmaster false` once our
    `-o` is on the line, so a reader following those pages got no multiplexing and no way to find
    out why. The only place the option was written down was `_plans/DESIGN.md`, which is
    gitignored and ships nowhere.

    The direction this fails in is the point (D-132's argument, one layer out): an allowlist of
    documented options omits silently, so the check is driven from the constant. A default added
    without a row fails here by name, and a row whose value drifts from the code fails with both
    values quoted.
    """
    section = _section(doc("connecting.md"), "### What the shipped defaults are")
    assert section, "docs/connecting.md lost the section listing the shipped ssh options"

    wrong = []
    for name, value in DEFAULT_SSH_OPTIONS.items():
        row = next((r for r in section.splitlines() if r.startswith(f"| `{name}`")), "")
        if not row:
            wrong.append(f"{name}: shipped as {value!r} and the page has no row for it")
        elif f"`{value}`" not in row:
            wrong.append(f"{name}: code ships {value!r}, page row says something else")
    assert not wrong, "docs/connecting.md disagrees with DEFAULT_SSH_OPTIONS: " + "; ".join(wrong)


def _section(page: str, heading: str) -> str:
    """The text under ``heading``, stopping at the next heading of the same depth or shallower.

    Scoped rather than page-wide because this page carries **two** option tables -- the shipped
    defaults and the password-auth overrides -- and ``BatchMode`` is in both, with `yes` in one
    and `no` in the other. A page-wide row match takes whichever comes first, so the check would
    have read the password table and passed while saying nothing about the defaults.
    """
    depth = len(heading) - len(heading.lstrip("#"))
    lines = page.splitlines()
    try:
        start = lines.index(heading)
    except ValueError:
        return ""
    body = []
    for line in lines[start + 1 :]:
        if line.startswith("#") and len(line) - len(line.lstrip("#")) <= depth:
            break
        body.append(line)
    return "\n".join(body)


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


def test_the_adapter_page_still_names_the_cache_as_an_authentication_cost():
    """D-126, pinned the same way and for the same reason as the admissions above.

    Keeping ``password`` out of the fsspec cache token is right and stays -- it is what makes
    the credential un-picklable. Its price is that the second caller's password is never checked
    against anything, so a wrong one still connects on the first caller's session.

    That was already documented, accurately, **as a caching cost**, and the wording is the whole
    finding: a reader told they may get a stale connection budgets for a stale connection, while
    a reader told a wrong password silently succeeds reaches for ``skip_instance_cache=True``.
    So the consequence is pinned rather than the mechanism -- an edit may rewrite the sentence
    and may not quietly demote it back to a caching note.

    Note the spelling of the first phrase: the page emphasises *wrong* in that sentence, so a
    pin reading "wrong for the account" is broken by the asterisks and fails against a page
    that says exactly what it should. Pin a span with no markup inside it, or the test reports
    a missing admission when what changed was the typography.
    """
    page = (ROOT / "docs" / "integrations.md").read_text(encoding="utf-8")
    admissions = (
        "for the account still gives a working session",
        "skip_instance_cache=True",
    )
    missing = [phrase for phrase in admissions if phrase not in page]
    assert not missing, (
        f"docs/integrations.md stopped naming the cache's authentication cost: {missing}"
    )


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

SHIPPED = (
    "src",
    "tests",
    "examples",
    "live-tests",
    "scripts",
    "docs",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
)
"""Top-level entries an sdist must carry.

`tests/` and `examples/` are in for a reason worth stating, because "why ship tests?" gets asked
every few years: Debian, Fedora and conda-forge rebuild from the sdist and run the suite to
validate their build, and `examples/` is tested documentation with a README of its own.

`docs/` joined them in D-125, and the reason is the same one that put the README here. The
documentation used to *be* the README, so shipping it was automatic; splitting it out would have
silently reduced what a user receives to a table of contents whose every row is a dead link. An
sdist is what a distribution packager builds from and what an air-gapped user reads.
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

"""Invariants asserted by parsing the shipped source, rather than by importing it.

Mostly the codec's purity, which is what this file was built for. CLAUDE.md states that
invariant: ``codec/`` imports nothing async, no sockets, no subprocess, no clock, no
randomness. Bytes in, events out. Convention is not enforcement, so it is asserted here by
parsing rather than importing -- an import-based check would pass for a module that imports
``time`` lazily inside a function, which is exactly the shape the rule exists to catch.

The last section is a different kind of rule with the same enforcement problem: a call that
must always carry one keyword argument. Nothing about layering, and it lives here because
parsing every shipped module is what both need and a second file to do it twice is worse than
a docstring saying so.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "src" / "gantry_sftp"
CODEC_ROOT = PACKAGE_ROOT / "codec"

FORBIDDEN_IMPORTS = frozenset(
    {
        # I/O and concurrency
        "anyio",
        "asyncio",
        "concurrent",
        "multiprocessing",
        "queue",
        "select",
        "selectors",
        "socket",
        "socketserver",
        "ssl",
        "subprocess",
        "threading",
        # the clock -- a codec that needs the wall clock is a codec with a bug
        "datetime",
        "sched",
        "time",
        # `logging` is here for the same reason rather than as an I/O rule: every log record
        # is stamped with `time.time()` at construction, so a codec that logs is a codec that
        # reads the clock. It is why the frame dumper is split -- `codec.describe()` renders a
        # packet and returns a string, and the session seam is what emits it.
        "logging",
        # nondeterminism -- request-id allocation is deterministic and owned by the codec
        "random",
        "secrets",
        "uuid",
        # the filesystem and the process
        "io",
        "os",
        "pathlib",
        "shutil",
        "signal",
        "tempfile",
        # cryptography has no business anywhere outside transport/native/
        "cryptography",
        "hashlib",
        "hmac",
        # the network
        "http",
        "urllib",
    }
)


def codec_modules() -> list[Path]:
    return sorted(CODEC_ROOT.rglob("*.py"))


def test_codec_root_exists() -> None:
    # Guards the guard: a renamed package would otherwise make every test below vacuous
    # by iterating an empty list.
    assert CODEC_ROOT.is_dir(), f"codec package not found at {CODEC_ROOT}"
    assert codec_modules(), "no modules found in codec/ -- this test would prove nothing"


@pytest.mark.parametrize("module", codec_modules(), ids=lambda p: p.name)
def test_codec_module_imports_nothing_impure(module: Path) -> None:
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))

    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORTS:
                    offenders.append((node.lineno, root))
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            root = node.module.split(".")[0]
            if root in FORBIDDEN_IMPORTS:
                offenders.append((node.lineno, root))

    assert not offenders, (
        f"{module.name} imports modules the codec layer may not touch: "
        + ", ".join(f"{name} (line {line})" for line, name in offenders)
    )


@pytest.mark.parametrize("module", codec_modules(), ids=lambda p: p.name)
def test_codec_module_has_no_async(module: Path) -> None:
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))

    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            offenders.append((node.lineno, f"async def {node.name}"))
        elif isinstance(node, ast.Await):
            offenders.append((node.lineno, "await"))
        elif isinstance(node, ast.AsyncFor):
            offenders.append((node.lineno, "async for"))
        elif isinstance(node, ast.AsyncWith):
            offenders.append((node.lineno, "async with"))

    assert not offenders, (
        f"{module.name} contains async constructs; the codec is synchronous and pure: "
        + ", ".join(f"{what} (line {line})" for line, what in offenders)
    )


def package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def imported_roots(module: Path) -> list[tuple[int, str]]:
    """Every top-level module name imported by ``module``, with its line number."""
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name.split(".")[0]) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            found.append((node.lineno, node.module.split(".")[0]))
    return found


@pytest.mark.parametrize("module", package_modules(), ids=lambda p: str(p.name))
def test_no_shipped_module_imports_asyncio_directly(module: Path) -> None:
    """Async is anyio, everywhere, with no exceptions.

    ``asyncio.Queue``, ``asyncio.wait_for`` and ``loop.*`` are not merely unidiomatic here:
    each one silently costs trio support, which is the entire reason for the anyio
    dependency. The rule is worth nothing unless something checks it, because a single
    convenient ``import asyncio`` in a hurry is all it takes.

    Note ``subprocess`` is deliberately *not* banned -- ``subprocess.PIPE`` is a plain
    integer constant that anyio's process API expects, and it involves no event loop.
    """
    offenders = [(line, name) for line, name in imported_roots(module) if name == "asyncio"]
    assert not offenders, (
        f"{module.name} imports asyncio directly; use anyio so trio keeps working: "
        + ", ".join(f"line {line}" for line, _ in offenders)
    )


def test_the_package_root_scan_is_not_vacuous() -> None:
    modules = package_modules()
    assert len(modules) > len(codec_modules()), "package scan found no modules outside codec/"


def test_codec_imports_only_itself_and_the_exception_module() -> None:
    """The dependency direction is one-way, and the codec sits at the bottom of it.

    ``session`` may import ``codec``. ``codec`` importing ``session`` or ``transport``
    would make the layering a circle and the purity above unenforceable.
    """
    allowed_prefixes = ("gantry_sftp.codec", "gantry_sftp.exceptions")
    offenders: list[str] = []

    for module in codec_modules():
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                names = [node.module]
            for name in names:
                if name.startswith("gantry_sftp") and not name.startswith(allowed_prefixes):
                    offenders.append(f"{module.name}:{node.lineno} imports {name}")

    assert not offenders, "codec may only import from codec/ and exceptions: " + "; ".join(
        offenders
    )


# --- the top of the stack, which is a layer too (D-90) ------------------------------------------

ERGONOMICS = (
    "gantry_sftp.doctor",
    "gantry_sftp.__main__",
    "gantry_sftp.path",
    "gantry_sftp.sync",
    "gantry_sftp.fsspec",
)
"""Modules that sit *above* session and transport, and are imported by nothing below them.

The command line and the diagnostic are the top of the dependency order — they may reach down
through the whole library, and nothing in the library may reach up to them. Stated as a list
because there are five of them; the assertion below is what keeps the list from becoming a
description of what happened rather than a rule.

**The last three were added by D-61 and the first of them is the one with teeth.** CLAUDE.md's
layout puts `path.py` beside the fsspec adapter at the ergonomics level, and the tempting
spelling of its entry point — `session.path("/incoming")` — inverts that: `session/` would
import the path type, which imports `Session`, and the direction stops being one-way. So the
binding is `SFTPPath(path, session=...)` and this list is why. `sync` and `fsspec` came with it
rather than as scope: `sync` has to import `path` for `SyncSFTPPath`, and `fsspec` imports
`sync`, so leaving either out would report a legitimate downward import as a violation.
"""


def test_nothing_below_the_ergonomics_layer_imports_it() -> None:
    """One import of ``doctor`` from ``session`` would invert the dependency order.

    It would also, quietly, make a ``python -m`` entry point part of the library's import
    graph: ``__main__`` runs an ``argparse`` at import time in some shapes, and every consumer
    would pay for a command they never invoke. The direction is one-way and this is the
    assertion, in the same file and for the same reason the codec's purity is asserted rather
    than documented.
    """
    # The package root is the top of the stack by definition -- re-exporting the public API is
    # what it is for, and `from gantry_sftp import SFTPPath` is the spelling every doc uses. It
    # is excluded by *path* rather than by stem, because `session/__init__.py` and its two
    # siblings have the same stem and are emphatically not exempt.
    root = PACKAGE_ROOT / "__init__.py"
    below = [
        module
        for module in package_modules()
        if f"gantry_sftp.{module.stem}" not in ERGONOMICS
        and module.stem != "__main__"
        and module != root
    ]
    offenders = [
        f"{module.name}:{line} imports {name}"
        for module in below
        for line, name in imported_paths(module)
        if name in ERGONOMICS
    ]

    assert not offenders, "the ergonomics layer is imported from below it: " + "; ".join(offenders)


def test_the_ergonomics_layer_is_not_empty() -> None:
    """Guards the guard: a renamed module would make the test above vacuous rather than red."""
    present = {f"gantry_sftp.{module.stem}" for module in package_modules()}
    missing = [name for name in ERGONOMICS if name not in present]
    assert missing == [], f"named in ERGONOMICS but no longer a module: {missing}"


def imported_paths(module: Path) -> list[tuple[int, str]]:
    """Every fully-qualified module name imported by ``module``, with its line number.

    Distinct from :func:`imported_roots`, which truncates to the top-level package: this rule
    is about a *submodule* of ``gantry_sftp``, and the root of every one of those is
    ``gantry_sftp``.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            found.append((node.lineno, node.module))
    return found


# --- one keyword that has to be on every call (D-118) -------------------------------------------


def hashlib_calls(module: Path) -> list[tuple[int, str, bool]]:
    """Every ``hashlib.<constructor>(...)`` call, with whether it passed the keyword.

    Attribute calls on the ``hashlib`` name only, which is how all of them are spelled here.
    ``from hashlib import new`` would slip past, so the test below refuses that import outright
    rather than growing a second matcher for a spelling nothing uses.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    found: list[tuple[int, str, bool]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            continue
        if func.value.id != "hashlib":
            continue
        opted_out = any(
            keyword.arg == "usedforsecurity"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )
        found.append((node.lineno, f"hashlib.{func.attr}", opted_out))
    return found


@pytest.mark.skipif(
    "MUTANT_UNDER_TEST" in os.environ,
    reason="mutmut mutates the keyword this asserts on, in a shadow tree this then reads",
)
@pytest.mark.parametrize("module", package_modules(), ids=lambda p: str(p.name))
def test_every_hashlib_constructor_opts_out_of_the_security_policy(module: Path) -> None:
    """``usedforsecurity=False`` on every one, and the site that lacked it is why (D-118).

    A FIPS-enabled build refuses ``hashlib.new("md5")`` outright, and paramiko -- the only
    server implementing ``check-file`` that this project can reach -- offers md5 and sha1 and
    nothing else. So the flag is what makes rung 1 reachable at all on such a build.

    **The failure it caused was a wrong diagnosis rather than a missing feature**, which is why
    a rule beats a fix. Three of the four call sites had the keyword; the fourth sized the
    digest the server named, inside a ``try`` that turns any ``ValueError`` into "server hashed
    with b'md5', which this Python cannot size". That sentence blames the algorithm for a
    policy, and it is the shape CLAUDE.md's "error messages name what failed" exists to stop.

    It is also true on the merits at every site: these digests check that a transfer arrived
    intact, which is not an authentication use and was never claimed to be.

    **Skipped under mutmut, and it is the assertion rather than the rule that cannot run
    there.** ``PACKAGE_ROOT`` resolves into ``mutants/``, which holds a *mutated* copy of every
    module -- one variant per mutation, so ``_session.py`` grows past 36,000 lines -- and
    flipping ``usedforsecurity=False`` to ``True`` is an ordinary keyword mutation mutmut
    generates. So this reads real mutations of a fake tree and reports them as offenders,
    against source nobody ships. Without the skip the lane cannot start at all: stats collection
    stops on the first failure, which is the same symptom ``test_sync_facade.py`` has and the
    same one ``test_argv.py``'s ``stacklevel`` assertion has, both recorded in ``pyproject.toml``.
    Skipping kills nothing -- mutmut mutates function *bodies*, and this asserts on source text.
    """
    offenders = [(line, name) for line, name, opted_out in hashlib_calls(module) if not opted_out]
    assert not offenders, (
        f"{module.name} calls a hashlib constructor without usedforsecurity=False, which a "
        f"FIPS build refuses for md5 and sha1: "
        + ", ".join(f"{name} (line {line})" for line, name in offenders)
    )


def test_no_shipped_module_imports_a_hashlib_constructor_by_name() -> None:
    """The matcher above reads ``hashlib.x(...)``, so a bare ``new(...)`` would be invisible.

    Refused rather than matched: one spelling is what makes the rule checkable, and nothing in
    the package wants the other.
    """
    offenders: list[str] = []
    for module in package_modules():
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        offenders += [
            f"{module.name}:{node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "hashlib"
        ]
    assert not offenders, (
        "import hashlib and call hashlib.new(...); a name imported from it escapes the "
        "usedforsecurity check above: " + ", ".join(offenders)
    )


def test_the_hashlib_scan_finds_the_calls_it_is_meant_to_guard() -> None:
    """Guards the guard. A moved call would otherwise make every assertion above vacuous."""
    total = sum(len(hashlib_calls(module)) for module in package_modules())
    assert total >= 3, f"expected the verification ladder's hashlib calls, found {total}"


# --- how much may live in one class (D-128) ---------------------------------------------------


SESSION_METHOD_CEILING = 109
"""What `Session` measures today, which is the whole of the rule.

**A ratchet, not a target, and not a round number.** D-128's finding was that `Session` holds the
orchestration half of all seven responsibilities `session/` has a module for, while every gate
this repository runs says nothing is wrong: each function passes complexipy and mccabe, both type
checkers are clean, the suite is green. A class grows because absorbing the next orchestration is
always the cheapest single edit, and every one of those edits is individually defensible.

Set at the measurement of the day it lands so it cannot be met by doing nothing and cannot be
raised without saying so out loud. A round number would either exempt the current state or fail on
arrival, and both teach the next reader to edit the constant instead of the class.

**The direction of travel is down.** Each further cut lowers this line; the glob cut that landed
with D-128 took it from 114. If a change genuinely needs a new method here, the question the
failure asks is whether the method belongs on `Session` at all -- six of the seven that left did
not.

The sync twin needs no ceiling of its own: `tests/test_sync_facade.py` derives `SyncSession` from
`Session` by name, so a method that cannot be added here cannot appear there either.
"""


def _class_named(module: Path, name: str) -> ast.ClassDef:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    pytest.fail(f"{name} is not defined in {module.name}")


_SHADOW_TREE = pytest.mark.skipif(
    "MUTANT_UNDER_TEST" in os.environ,
    reason="mutmut rewrites Session into one trampoline per mutant, in a shadow tree this reads",
)
"""Both ceilings count methods on the *shipped* class, and under the lane they would not.

mutmut copies `source_paths` into `mutants/` and rewrites each function into a trampoline plus
one variant per mutation, so `Session` measures in the thousands there -- and `PACKAGE_ROOT` is
derived from `__file__`, which under the lane is inside that copy. Without this the ceiling
fails on arrival, `--exitfirst` stops the run, and mutmut reports "failed to collect stats"
rather than anything about the ceiling.

Found by the first `session/_glob` run after D-128, which is the fourth entry in this
repository's list of tests that read what mutmut rewrote. A per-test `skipif` rather than an
`--ignore`, because every *other* test in this module is a real kill under the lane.
"""


@_SHADOW_TREE
def test_the_session_class_does_not_grow() -> None:
    """The one structural claim this repository had no mechanical statement for (D-128).

    Layering is proved by parsing the shipped source, the sync facade's parity is proved by
    deriving it from `Session`, and every doc link is proved by resolving it. How much may live
    in this class was held only by attention, which is what let it become both the largest class
    in the library and the file with the most churn.
    """
    session = _class_named(PACKAGE_ROOT / "session" / "_session.py", "Session")
    methods = [
        node.name
        for node in session.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    assert len(methods) <= SESSION_METHOD_CEILING, (
        f"Session has grown to {len(methods)} methods, above the {SESSION_METHOD_CEILING} it "
        f"measured when D-128 pinned this. Ask whether the new method belongs on Session at "
        f"all: session/ has a module per responsibility and each holds that responsibility's "
        f"pure half, so an orchestration usually belongs beside its own half. Raising this "
        f"line is a decision to record, not a step in adding a method"
    )


@_SHADOW_TREE
def test_the_session_ceiling_is_not_slack() -> None:
    """A ratchet that drifts above what it measures has stopped being one.

    Without this, a cut that removes ten methods leaves the line ten too high and the next ten
    additions pass unnoticed -- which is how a ceiling set once becomes a ceiling that never
    fires. Failing here is the reminder to lower the constant in the same change as the cut.
    """
    session = _class_named(PACKAGE_ROOT / "session" / "_session.py", "Session")
    methods = [
        node.name
        for node in session.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    assert len(methods) == SESSION_METHOD_CEILING, (
        f"Session now has {len(methods)} methods and the ceiling still says "
        f"{SESSION_METHOD_CEILING}. Lower SESSION_METHOD_CEILING to {len(methods)} in this same "
        f"change, so the next addition is measured against what the class actually is"
    )

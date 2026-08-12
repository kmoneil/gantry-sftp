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
from collections.abc import Iterator
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
    "gantry_sftp.compatibility",
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


SESSION_METHOD_CEILING = 39
"""What `Session` measures today, which is the whole of the rule.

**38 to 39 by D-166**, the upload journal, and the ratchet's question was asked rather than
waved through. `discard_staged` removes the staging files a killed run left behind, so it needs
a session -- `remove` is a round trip and the whole operation is a sequence of them against a
record. The pure half *did* leave and is the larger half: `session/_journal.py` holds the log
format, the fold, the durability discipline and the identity comparison, all of it testable with
a directory and no server. What is left here is the part that cannot be: iterate, remove, clear.

**36 to 38 by D-164**, the mirror, and the ratchet's question was asked rather than waved
through. `sync_tree` is an orchestration over the walk, the comparison and `put`, which is what
`put_tree` and `get_tree` beside it already are, so it belongs here for the same reason they do.
`_listing_by_name` awaits `scandir` and could not be a pure function. **The pure half did leave**
-- the comparison, the manifest and the per-directory decision are `session/_sync.py`, which is
where the thing that can lose data is testable with two dictionaries and no server. Two methods
is what was left once that was taken out.

**Lowered from 109 to 59 by D-143**, which split the class into three layers: `_SessionCore`
(state, the properties, and `request`), `_SessionOperations` (one round trip each), and this,
the compositions. The ratchet did its job on contact -- it failed the split with a message
naming the new number, so tightening it was not something anybody had to remember.

**59 to 35 by D-146**, which cut on the other axis. First the verification ladder left as
functions taking a session (`session/_verify.py`) and `_already_complete` joined
`session/_policy.py`, which it had qualified for since the day it was written. Then the whole of
`put` below its public entry point left for `session/_put.py`. D-143's cut was by depth and
reached what depth could; this one is by concern, and it is the axis the mass was actually on.

**What unblocked the second half was a layer finding, not a concern one.** Four members could not
leave because they built requests by hand and needed `_expect_status` / `_next` /
`_attempt_extension`. Each turned out to be one round trip misfiled one layer up, and naming the
operation it wanted -- `fchmod`, `futime`, `fsync_if_supported`, `posix_rename_if_supported` --
retired the whole blocker. Reading them as a concern to extract had the diagnosis backwards.

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

**35 to 36 by D-163**, and this is the raise the rule asks to be recorded rather than taken. The
tree preview's branches put `_walk_for_download` at 21 against a cognitive-complexity ceiling of
15, and the split falls where the two ceilings agree: `_settle_file` appends to the report and
never walks, `_walk_for_download` walks and never decides what a refusal means. It is a method on
`Session` because it needs `_claim_download`, which needs the session -- the membership test the
docstring above describes, answered honestly rather than in the convenient direction.

The count itself was corrected in the same change; see `_methods_of`. An `@overload` stub is a
signature and not a method, and D-163 added six of them.

The sync twin needs no ceiling of its own: `tests/test_sync_facade.py` derives `SyncSession` from
`Session` by name, so a method that cannot be added here cannot appear there either.
"""


def _class_named(module: Path, name: str) -> ast.ClassDef:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    pytest.fail(f"{name} is not defined in {module.name}")


def _is_overload(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether this ``def`` is a ``@typing.overload`` stub rather than a method.

    Both spellings, because either resolves to the same decorator and a ceiling that could be
    walked past by writing ``@typing.overload`` would be measuring the import style.
    """
    return any(
        (isinstance(decorator, ast.Name) and decorator.id == "overload")
        or (isinstance(decorator, ast.Attribute) and decorator.attr == "overload")
        for decorator in node.decorator_list
    )


def _methods_of(module: Path, name: str) -> list[str]:
    """The methods a class defines, counting an overloaded one once (D-163).

    **An ``@overload`` stub is a signature, not a method**, and counting it makes the ceiling
    measure typing sugar: `get_tree` gained three ``def``\\ s and no responsibility when
    ``dry_run`` was overloaded to pick its own return type, which read as +3 against a limit
    whose whole subject is how much this class does. Left uncorrected, the next real addition
    would have been measured against a number six too high -- a ratchet that has stopped
    tracking the thing it ratchets, which is what `test_the_session_ceiling_is_not_slack`
    exists to prevent from the other direction.
    """
    body = _class_named(module, name).body
    return [
        node.name
        for node in body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and not _is_overload(node)
    ]


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
    methods = _methods_of(PACKAGE_ROOT / "session" / "_session.py", "Session")
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
    methods = _methods_of(PACKAGE_ROOT / "session" / "_session.py", "Session")
    assert len(methods) == SESSION_METHOD_CEILING, (
        f"Session now has {len(methods)} methods and the ceiling still says "
        f"{SESSION_METHOD_CEILING}. Lower SESSION_METHOD_CEILING to {len(methods)} in this same "
        f"change, so the next addition is measured against what the class actually is"
    )


# --- what the mutation lane cannot see (D-129) ------------------------------------------------


MUTATED_PACKAGES = ("codec", "session", "transport")
"""The three packages `[tool.mutmut] only_mutate` covers. The rule below applies to those only."""

_MUTABLE_NODES = (ast.BinOp, ast.Compare, ast.BoolOp, ast.UnaryOp, ast.Subscript, ast.IfExp)
"""Node kinds that mean a body has something for mutmut to change.

mutmut rewrites *expressions* -- an operator, a comparison, a slice, a literal. A body with none
of these generates nothing whatever it is attached to, so a one-line delegation or a bare
``return self.x`` is not a finding.
"""


def mutated_modules() -> list[Path]:
    return sorted(
        module for package in MUTATED_PACKAGES for module in (PACKAGE_ROOT / package).rglob("*.py")
    )


def walk_executable(node: ast.AST) -> Iterator[ast.AST]:
    """Walk ``node``, skipping type annotations.

    **The first draft of this rule walked the whole function and reported two false positives**,
    both of them signatures rather than logic: ``-> tuple[bytes, ...]`` is a ``Subscript`` and
    ``data: bytes | memoryview`` is a ``BinOp``. An annotation is not something mutmut changes
    into different behaviour, so counting one as "a body worth mutating" would have flagged every
    method with a generic return type -- a sweep failing in the direction that over-applies, which
    is the half that gets the rule deleted rather than the half that gets it noticed.
    """
    skip: set[ast.AST] = set()
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        # A nested `def` inside a body brings its own signature with it.
        skip = {node.args} | ({node.returns} if node.returns is not None else set())
    elif isinstance(node, ast.Lambda):
        skip = {node.args}
    elif isinstance(node, ast.AnnAssign):
        skip = {node.annotation}

    for child in ast.iter_child_nodes(node):
        if child in skip:
            continue
        yield child
        yield from walk_executable(child)


def method_body_nodes(member: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Every node in a method's body, with its signature and its annotations left out."""
    for statement in member.body:
        yield statement
        yield from walk_executable(statement)


def hidden_methods(module: Path) -> list[str]:
    """Undecorated methods with mutable bodies that sit inside a decorated class.

    Every clause is load-bearing. A method with its *own* decorator is already invisible for the
    reason D-107 recorded and is not this rule's business; a method with nothing mutable in it
    would generate no mutants anywhere; and only the *body* counts, never the signature -- see
    :func:`walk_executable`.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or not node.decorator_list:
            continue
        for member in node.body:
            if not isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if member.decorator_list:
                continue
            if any(isinstance(inner, _MUTABLE_NODES) for inner in method_body_nodes(member)):
                decorators = "+".join(ast.unparse(d).split("(")[0] for d in node.decorator_list)
                found.append(f"{module.name}:{node.name}.{member.name} (@{decorators})")
    return found


@pytest.mark.parametrize("module", mutated_modules(), ids=lambda p: str(p.name))
def test_no_decorated_class_hides_a_method_from_the_mutation_lane(module: Path) -> None:
    """The statement that would have failed the day `GlobRunner` was written (D-129).

    **mutmut declines to instrument the methods of a decorated class**, for the same reason it
    declines a decorated function: building the trampoline re-runs the decorator, and
    `@dataclass(slots=True)` does not merely add methods -- it returns a new class object. So a
    `@dataclass` wrapped around a class whose methods carry logic silently removes all of them
    from the lane.

    **Nothing else can see it.** Such a class passes both type checkers, the complexity gate and
    the whole suite, and `mutmut results` is silent too -- it lists survivors and timeouts, and a
    function with *no* mutants appears in neither. D-128 found it only because the module-level
    matcher in the same file produced 48 trampolines while the whole class produced 0, which is
    legible only next to a healthy neighbour.

    Six methods were hidden when this was written, and the Definition of Done names two of them
    by category: `DescriptorSink.write_at` is the offset arithmetic of every download, and
    `CheckFileReply.split` parses attacker-supplied bytes. *"A surviving mutant in frame parsing
    or offset arithmetic is a missing test, not a curiosity"* -- and there was no mutant to
    survive.

    **Two ways to satisfy this**, and equality decides which. Drop the decorator and write
    `__init__` by hand where nothing compares instances; keep it and move the body to a
    module-level function where something does. `CheckFileReply` is the second case:
    `tests/test_extensions.py` asserts `parsed == CheckFileReply(...)`, which is dataclass
    equality doing golden-frame work.
    """
    hidden = hidden_methods(module)
    assert not hidden, (
        "these methods are invisible to the mutation lane because their class is decorated: "
        + "; ".join(hidden)
        + ". Either drop the class decorator and write __init__ by hand, or move the body to a "
        "module-level function and delegate to it -- see D-129. If the body genuinely has "
        "nothing worth mutating, it will not reach this rule."
    )


def test_the_hidden_method_scan_finds_the_shape_it_guards() -> None:
    """The rule above passes when it finds nothing, which is also what a broken scan does.

    D-116's lesson, applied here: a guard whose subject has been removed reports clean forever.
    So the scanner is pointed at a decorated class with a comparison in an undecorated method
    and has to see it.
    """
    sample = Path(__file__).parent / "_d129_sample.py"
    sample.write_text(
        "from dataclasses import dataclass\n"
        "@dataclass\n"
        "class Hidden:\n"
        "    n: int\n"
        "    def check(self) -> bool:\n"
        "        return self.n < 1\n"
        "    @property\n"
        "    def already_invisible(self) -> bool:\n"
        "        return self.n > 1\n"
        "class Plain:\n"
        "    def fine(self, n: int) -> bool:\n"
        "        return n < 1\n"
        "@dataclass\n"
        "class SignatureOnly:\n"
        "    n: int\n"
        "    def annotated(self, data: bytes | memoryview) -> tuple[bytes, ...]:\n"
        "        return helper(data)\n",
        encoding="utf-8",
    )
    try:
        found = hidden_methods(sample)
    finally:
        sample.unlink()
    # `Hidden.check` only, and each exclusion is a case this scan got wrong at some point or
    # would have: the property is out of scope (D-107 covers it), `Plain` is undecorated so its
    # method is instrumented normally, and `SignatureOnly` carries a `|` and a `[...]` in its
    # *annotations* with a one-line delegation for a body -- which is what the first draft of
    # this rule reported as a finding, twice.
    assert found == ["_d129_sample.py:Hidden.check (@dataclass)"]


# --- the session's three layers (D-143) -------------------------------------------------------


SESSION_LAYERS = ("_core.py", "_operations.py", "_session.py")
"""Bottom to top. `_SessionCore` owns the state and `request`; `_SessionOperations` is one round
trip per method; `Session` composes them into transfers."""


def _class_in(module: str, name: str) -> ast.ClassDef:
    source = (PACKAGE_ROOT / "session" / module).read_text(encoding="utf-8")
    return next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef) and node.name == name
    )


def _defines(node: ast.ClassDef) -> set[str]:
    return {
        member.name
        for member in node.body
        if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _self_calls(node: ast.ClassDef) -> dict[str, set[str]]:
    return {
        member.name: {
            attribute.attr
            for attribute in ast.walk(member)
            if isinstance(attribute, ast.Attribute)
            and isinstance(attribute.value, ast.Name)
            and attribute.value.id == "self"
        }
        for member in node.body
        if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def test_the_session_layers_only_ever_call_downwards():
    """Everything may call down. Nothing may call up.

    The reason to assert it rather than intend it is that calling up always *works*: Python
    resolves it through the MRO at runtime and no checker complains, because the attribute really
    is there on the instance. A layer boundary that exists only in a docstring is one the next
    feature crosses without noticing, which is the same argument `codec/` has an import rule for.

    Parsed rather than imported, like everything else in this file: `dir()` on a subclass returns
    what it inherited, so an import-based version of this check would be vacuous by construction.
    """
    core = _class_in("_core.py", "_SessionCore")
    operations = _class_in("_operations.py", "_SessionOperations")
    compositions = _class_in("_session.py", "Session")

    upwards = _defines(operations) | _defines(compositions)
    offending = {
        method: sorted(used & upwards)
        for method, used in _self_calls(core).items()
        if used & upwards
    }
    assert not offending, f"_SessionCore calls upwards, so it is not the bottom layer: {offending}"

    upwards = _defines(compositions)
    offending = {
        method: sorted(used & upwards)
        for method, used in _self_calls(operations).items()
        if used & upwards
    }
    assert not offending, (
        f"_SessionOperations reaches into the compositions, so it is no longer one round trip "
        f"per method: {offending}"
    )


def test_the_layers_partition_the_session_rather_than_overlapping_it():
    # An override would be silent: the subclass wins and the base's version becomes dead code
    # that still reads as live. Nothing in this hierarchy should be overriding anything.
    core = _defines(_class_in("_core.py", "_SessionCore")) - {"__init__", "__repr__"}
    operations = _defines(_class_in("_operations.py", "_SessionOperations"))
    compositions = _defines(_class_in("_session.py", "Session"))
    assert not core & operations, f"redefined in _SessionOperations: {sorted(core & operations)}"
    assert not core & compositions, f"redefined in Session: {sorted(core & compositions)}"
    assert not operations & compositions, (
        f"redefined in Session: {sorted(operations & compositions)}"
    )


# --- one way to the transfer scheduler (D-146) ------------------------------------------------


SESSION_ROOT = PACKAGE_ROOT / "session"

TRANSFER_SCHEDULERS = ("download_handle", "upload_handle", "read_range_into", "write_range_from")
"""The four entry points into `_download.py` / `_upload.py` that move bytes over a handle."""

SCHEDULER_HOME = {"_download.py", "_upload.py", "_operations.py"}
"""Where a call to one may appear: the two modules that define them, and the one layer that owns
the state they need -- the dispatcher, the pipeline depth, the idle timeout, and the request size
`sizes_for` derives from the handle."""


def test_only_the_operations_layer_reaches_the_transfer_schedulers() -> None:
    """The decision D-146 turned on, asserted rather than remembered.

    Every one of these takes a `Dispatcher` and a pacing triple, so a caller outside the class
    that owns them has to reach for `session._dispatcher`, `session._depth` and
    `session._idle_timeout` -- which is what stopped the verification ladder moving out of
    `Session` when it was first tried. `download_into` and `upload_from` exist so the answer is
    "ask the session to schedule" rather than "hand the session's wire state around", and a
    fifth call site assembled by hand would quietly restore the coupling.

    Ruff's `SLF001` catches the private access itself. What it cannot see is the shape one step
    earlier: a *method* on `Session` doing this is perfectly legal to it, and that is exactly
    where the three duplicated argument lists lived.
    """
    offending: dict[str, list[str]] = {}
    for module in sorted(SESSION_ROOT.glob("*.py")):
        if module.name in SCHEDULER_HOME:
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        called = sorted(
            {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in TRANSFER_SCHEDULERS
            }
        )
        if called:
            offending[module.name] = called
    assert not offending, (
        f"a transfer scheduler is called outside {sorted(SCHEDULER_HOME)}: {offending}. Reach it "
        f"through Session.download_into / upload_from / readinto_at / write_at, which supply the "
        f"dispatcher and this session's pacing from inside the class that owns them"
    )


def test_the_scheduler_scan_finds_the_calls_it_guards() -> None:
    """A scan that matched nothing would pass on an empty package.

    The positive half is that `_operations.py` really does call all four -- if a rename made the
    names above stale, the guard above would go quiet rather than fail, which is the failure mode
    every structural test in this file is written against.
    """
    tree = ast.parse((SESSION_ROOT / "_operations.py").read_text(encoding="utf-8"))
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert set(TRANSFER_SCHEDULERS) <= called, (
        f"the operations layer no longer calls {sorted(set(TRANSFER_SCHEDULERS) - called)}, so "
        f"the guard above is scanning for a name that has moved"
    )

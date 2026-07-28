"""The codec is pure, and this is what makes that true rather than aspirational.

CLAUDE.md states the invariant: ``codec/`` imports nothing async, no sockets, no
subprocess, no clock, no randomness. Bytes in, events out. Convention is not enforcement,
so the invariant is asserted here by parsing the source rather than by importing it -- an
import-based check would pass for a module that imports ``time`` lazily inside a function,
which is exactly the shape this rule exists to catch.
"""

from __future__ import annotations

import ast
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

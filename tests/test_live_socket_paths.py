"""No row in `live-tests/` may build a Unix socket under pytest's ``tmp_path``.

**This guard exists because the bug it names is invisible on the platform CI runs the lane on.**
A `ControlPath` and an ``ssh-agent`` socket are bound, so the *path* is bounded by ``sun_path``:
108 bytes on Linux, **104 on macOS and the BSDs**. pytest's ``tmp_path`` is short enough on Linux
and, on macOS, is
``/private/var/folders/<20 chars>/T/pytest-of-<user>/pytest-<n>/<test-name-cut-to-30>/`` -- past
104 before a filename is appended.

So the first time `live-tests/` ran off Linux, fourteen rows failed at once: all six of
`test_control_master.py` (`ControlPath too long ('...' >= 104 bytes)`, exit 255, surfacing as a
`ConnectError`) and all eight `agent_holding_the_right_key` rows of `test_ssh_environment.py`
(`unix_listener: path "..." too long for Unix domain socket`, exit 1, erroring at setup). That is
the entire ControlMaster guarantee and the entire agent-defence truth table, and both read as
this library refusing to multiplex rather than as a path-length bug -- which is the harm
`control_path`'s own docstring predicted while sizing itself against Linux's bound alone.

The fix is the `short_socket_dir` fixture. This is what stops the next one, and it lives in
`tests/` rather than beside the fixture on purpose: the `live` job is `ubuntu-latest` only, so a
guard inside `live-tests/` would run exactly where the mistake cannot be observed. Here it runs
in `fast`, on both platforms, whether or not anyone has a server.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

LIVE_TESTS = Path(__file__).resolve().parent.parent / "live-tests"

SOCKET_FILENAMES = frozenset({"cm"})
"""Whole filenames that mean "this is a socket path" but carry no suffix to recognise it by.

`cm` is what `control_path` builds. Matching the literal rather than the variable name because the
name is the part that varies -- `socket_path`, `control_path`, `agent.sock` -- while the thing
that has to be short is the string that reaches `bind`.
"""


def _is_socket_literal(value: object) -> bool:
    """Whether a constant in the tree names a Unix socket.

    A named predicate rather than an inline boolean chain: complexipy and SonarLint disagree about
    what a sequence of `and`/`or` costs, and naming the question settles it for both.
    """
    return isinstance(value, str) and (value.endswith(".sock") or value in SOCKET_FILENAMES)


def _functions_taking_tmp_path(module: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Every function in `module` that asks pytest for a `tmp_path`."""
    found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        names = {argument.arg for argument in node.args.args}
        if "tmp_path" in names:
            found.append(node)
    return found


def _socket_literals(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """The socket-path literals `function` builds, if any."""
    return [
        node.value
        for node in ast.walk(function)
        if isinstance(node, ast.Constant) and _is_socket_literal(node.value)
    ]


@pytest.mark.parametrize(
    "module_path",
    sorted(LIVE_TESTS.glob("*.py")),
    ids=lambda path: path.name,
)
def test_no_live_row_builds_a_unix_socket_under_pytests_tmp_path(module_path: Path) -> None:
    """A socket path from `tmp_path` passes on Linux and fails on macOS. Fail here instead.

    `short_socket_dir` is the fixture to take. It roots the directory at `/tmp` rather than at the
    platform temporary directory -- which is the thing that is long -- and it proves the result by
    binding a socket to it rather than by comparing against a constant, because the constant
    differs per platform and Python does not expose it.
    """
    parsed = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))

    offenders = {
        function.name: literals
        for function in _functions_taking_tmp_path(parsed)
        if (literals := _socket_literals(function))
    }

    assert not offenders, (
        f"{module_path.name} builds a unix socket under pytest's tmp_path: "
        f"{offenders} -- that fits sun_path on Linux and does not on macOS (104 bytes). "
        "Take the `short_socket_dir` fixture instead."
    )


def test_the_guard_sees_an_offending_function() -> None:
    """The guard's own control, because a scanner that matches nothing is silently green.

    Both halves are asserted: a `tmp_path` function that builds a socket is caught, and one that
    builds something else is not. Without the second half the check would pass by flagging
    everything, which reads the same from the outside as a correct scan.
    """
    offending = ast.parse(
        "def sock(tmp_path):\n"
        "    return tmp_path / 'agent.sock'\n"
        "def control(tmp_path):\n"
        "    return tmp_path / 'cm'\n"
        "def innocent(tmp_path):\n"
        "    return tmp_path / 'events.csv'\n"
    )
    caught = {
        function.name
        for function in _functions_taking_tmp_path(offending)
        if _socket_literals(function)
    }
    assert caught == {"sock", "control"}

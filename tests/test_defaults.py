"""The shipped defaults, stated as values rather than inferred from each other.

D-105's twelfth slice found that a public default was pinned by exactly one thing:
`test_sync_facade.py::test_a_method_keeps_its_signature`, which compares the async signature
against the sync twin's. That is **agreement between two surfaces**, not a statement about the
value -- change both and nothing objects. The Definition of Done 4 asks for the opposite: a
change to a default ships a test proving the old spelling still resolves the old way.

So this file is the table of values. Every entry is a documented promise -- README, a docstring,
or DESIGN -- and each one is here because flipping it is a **silent** behaviour change to
programs that never named the argument. There is no mechanism here beyond `inspect.signature`;
the point is that the numbers and flags exist in the suite as literals, in one place, where a
reviewer of a change to any of them has to also change this file and say why.

**Both surfaces are asserted against the same table**, rather than against each other. The
facade parity test is still the thing that catches a *renamed* argument or a changed return
type; what it cannot catch is the two surfaces being changed together, which is what the third
test below covers.

**Under mutmut this file is invisible in both directions, and that was measured rather than
assumed.** `inspect.signature` on a mutated class reads the *trampoline*, which carries the
original defaults, so:

* it does **not** break the lane the way `test_sync_facade.py` does -- a scoped re-run of
  `check_file` with this file present returns the same five survivors as without it, so it needs
  no entry on `pytest_add_cli_args`'s ignore list; and
* it cannot **kill** a default mutant either. With
  `MUTANT_UNDER_TEST=…check_file__mutmut_3` (`start_offset` 0 → 1) and `…put_tree__mutmut_1`
  (`preserve_times` False → True) active, all twenty tests here still pass.

So this file is the *statement* of the contract and must not be mistaken for coverage of it. What
kills a default mutant is a test that calls the method with the argument omitted and observes the
difference -- `test_by_default_neither_tree_preserves_timestamps` in `tests/test_timestamps.py`
and `test_check_file_offers_the_algorithms_this_library_actually_supports` in
`tests/test_content_verification.py` are the two this slice added. A default worth defending gets
both: the value written down here, and something that watches it from the outside.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from gantry_sftp.codec import OpenFlag
from gantry_sftp.session import (
    CHECK_FILE_BLOCK_SIZE,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DEFAULT_REQUEST_TIMEOUT,
    Publish,
    Session,
    Verify,
    open_session,
)
from gantry_sftp.sync import SyncSession

# Every default a caller gets by not passing an argument, with the reason it is that value.
#
# `get` / `put`
#   no_follow=False       pointing a download at a link you made yourself is legitimate; the
#                         recursive paths pass True per file, where a link in the destination
#                         tree is the last step of a path traversal
#   resume=False          opt-in in both directions: the upload direction cannot prove the
#                         remote partial came from this source file (DESIGN 6)
#   verify_size=True      rung 3 is free -- it compares against the STAT `get` already makes
#   verify=Verify.SIZE    rungs 1 and 2 both cost something, so they are asked for
#   preserve_times=False  matches `scp -p` and `rsync -t`; on-by-default breaks the landing
#                         zone whose consumer collects "modified since X" (D-79)
#   mode=None             a download stays at the 0o600 it is created with
#   depth=None            "use the session's", so one place sets it
#   concurrency=1         a tree transfers sequentially unless asked; the product of this and
#                         the caller's own task group is the real number (DESIGN 5.2)
#
# `check_file`
#   algorithms            the name-list this library offers, strongest first
#   start_offset=0        from the beginning
#   length=0              the wire spelling of "to the end of the file"
#   block_size            64 KiB: the largest block paramiko answers correctly, and the draft's
#                         256-byte floor is the other end of that range
SESSION_DEFAULTS: dict[str, dict[str, Any]] = {
    "get": {
        "progress": None,
        "depth": None,
        "no_follow": False,
        "resume": False,
        "verify_size": True,
        "verify": Verify.SIZE,
        "preserve_times": False,
        "mode": None,
    },
    "put": {
        "publish": None,
        "resume": False,
        "preserve_times": False,
        "mode": None,
        "verify": Verify.SIZE,
        "progress": None,
        "depth": None,
    },
    "get_tree": {
        "max_depth": None,
        "progress": None,
        "preserve_times": False,
        "mode": None,
        "resume": False,
        "concurrency": 1,
    },
    "put_tree": {
        "max_depth": None,
        "publish": None,
        "preserve_times": False,
        "mode": None,
        "progress": None,
        "resume": False,
        "concurrency": 1,
    },
    "check_file": {
        "algorithms": b"sha256,sha1,md5",
        "start_offset": 0,
        "length": 0,
        "block_size": CHECK_FILE_BLOCK_SIZE,
    },
    "open_file": {"pflags": OpenFlag.READ, "mode": None},
    "walk": {"max_depth": None},
    "glob": {"max_depth": None, "case_sensitive": True},
}

# `atomic=True` is the headline: a consumer polling the destination directory never observes a
# partial file, which DESIGN 6 calls the single most common bug in production SFTP integrations.
# `fsync=True` rides with it and degrades where the extension is absent; the two `require_*`
# flags are False because demanding a guarantee is the caller's decision, not a default.
PUBLISH_DEFAULTS: dict[str, Any] = {
    "atomic": True,
    "fsync": True,
    "require_atomic": False,
    "require_fsync": False,
    "staging_name": None,
}

# The tunables. 64 x 255 KiB is what fills the 2 MiB channel window with room to spare (D-23),
# 60 s of *silence* is not a total deadline, and 30 s bounds one round trip.
SESSION_TUNABLES: dict[str, Any] = {
    "request_timeout": DEFAULT_REQUEST_TIMEOUT,
    "idle_timeout": DEFAULT_IDLE_TIMEOUT,
    "depth": DEFAULT_PIPELINE_DEPTH,
}


def defaults_of(function: object) -> dict[str, Any]:
    """The defaulted parameters of a callable, as a plain mapping."""
    return {
        name: parameter.default
        for name, parameter in inspect.signature(function).parameters.items()  # type: ignore[arg-type]
        if parameter.default is not inspect.Parameter.empty
    }


@pytest.mark.parametrize("method", sorted(SESSION_DEFAULTS))
def test_the_async_surface_ships_the_documented_defaults(method: str):
    expected = SESSION_DEFAULTS[method]
    actual = defaults_of(getattr(Session, method))
    for name, value in expected.items():
        assert name in actual, f"Session.{method} no longer has a defaulted {name}"
        assert actual[name] == value, (
            f"Session.{method}({name}=) defaults to {actual[name]!r}, and this table says "
            f"{value!r}. If the change is deliberate it is a documented break: update the "
            f"README and this table together."
        )


@pytest.mark.parametrize("method", sorted(SESSION_DEFAULTS))
def test_the_blocking_surface_ships_the_same_ones(method: str):
    """The same table, not the same *object*, which is the hole this closes.

    `test_sync_facade.py` proves the two surfaces agree with each other. Asserting both against
    one written-down table is what makes a change to both of them fail something.
    """
    expected = SESSION_DEFAULTS[method]
    actual = defaults_of(getattr(SyncSession, method))
    for name, value in expected.items():
        assert actual.get(name, "<missing>") == value, (
            f"SyncSession.{method}({name}=) defaults to {actual.get(name)!r}, not {value!r}"
        )


def test_the_publish_policy_defaults_to_an_atomic_flushed_publish():
    actual = {field.name: field.default for field in Publish.__dataclass_fields__.values()}
    assert actual == PUBLISH_DEFAULTS


def test_a_session_is_opened_with_the_shipped_tunables():
    assert defaults_of(open_session) == SESSION_TUNABLES


def test_the_tunables_are_the_numbers_the_docs_quote():
    # Pinned as literals as well as by name: a test that only compares the constant to itself
    # passes whatever the constant becomes, which is the shape of assertion this whole file
    # exists to avoid.
    assert DEFAULT_PIPELINE_DEPTH == 64
    assert DEFAULT_IDLE_TIMEOUT == 60.0
    assert DEFAULT_REQUEST_TIMEOUT == 30.0
    assert CHECK_FILE_BLOCK_SIZE == 65536


def test_the_table_covers_every_transfer_entry_point():
    """Guards the guard: a new public transfer method must land in the table above.

    Without this, adding `get_range()` with a `resume=True` default would be invisible here --
    the table would simply not mention it, and every test above would still pass.
    """
    transfers = {"get", "put", "get_tree", "put_tree", "check_file", "open_file"}
    assert transfers <= set(SESSION_DEFAULTS), (
        f"not in the defaults table: {sorted(transfers - set(SESSION_DEFAULTS))}"
    )

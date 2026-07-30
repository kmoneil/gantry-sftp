"""The top-level namespace, and the single call that opens a connection and a session.

**D-58**: `from gantry_sftp import X` reached only exceptions. `Session.open(path, pflags)` is
typed on `OpenFlag` and `stat()` returns `Attrs`, and both lived only in `gantry_sftp.codec` --
the layer DESIGN calls pure internals. So a user following the README to open a file for writing
had to import from it, and the next refactor of that layer would break them. The tests below
assert the property rather than a list: **a program using this library needs no import from
`gantry_sftp.codec`.**

**D-57**: there was no single-call entry point, and DESIGN 8 documented one that did not exist
-- `connect("host", config="~/.ssh/config")`, with the note "`connect()` is still
`open_session`", which is false of the signature in both arity and argument names.

**The scoped signature is the interesting decision.** `open_ssh_transport` already takes ten
arguments, `pyproject.toml` sets `max-args = 10` as policy and refuses to exempt it, and the
same note refuses parameter objects *for connection entry points* because `host` and
`identity_file` really are unrelated. The union would be thirteen. So the ssh half stays flat
and the three session tunables -- one scheduling policy, the argument that made `Publish` a
type -- become `SessionOptions`. Ten exactly, and the test below is what stops the two halves
drifting apart.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

import gantry_sftp
from gantry_sftp import connect
from gantry_sftp.codec import Attrs as CodecAttrs
from gantry_sftp.session import DEFAULT_SESSION_OPTIONS, SessionOptions, open_session
from gantry_sftp.session import Session as SessionFromSession
from gantry_sftp.session import open_session as open_session_from_session
from gantry_sftp.transport import (
    Transport,
    find_sftp_server,
    open_local_server_transport,
    open_ssh_transport,
)

pytestmark = pytest.mark.anyio

ROOT = Path(__file__).resolve().parent.parent


# --- the namespace ------------------------------------------------------------------------------


def test_every_name_in_all_resolves():
    """A typo in ``__all__`` is invisible until a ``from gantry_sftp import *`` somewhere.

    Nothing in this repository does that, which is exactly why the list needs its own check --
    an entry naming something that does not exist would otherwise never be executed.
    """
    missing = sorted(name for name in gantry_sftp.__all__ if not hasattr(gantry_sftp, name))
    assert missing == [], f"in __all__ but not importable: {missing}"


def test_all_is_sorted_so_a_new_name_lands_somewhere_predictable():
    assert list(gantry_sftp.__all__) == sorted(gantry_sftp.__all__)


def test_the_namespace_is_not_vacuous():
    # Guards the guards: the two tests above pass on an empty list.
    assert len(gantry_sftp.__all__) > 20


def test_nothing_public_is_private_by_spelling():
    """A leading underscore in ``__all__`` would be a contradiction in two directions.

    ``_flatten_exception_group`` used to be the other way round -- public by spelling, absent
    from every ``__all__`` -- and D-58 asked for that to be decided rather than left. It was
    decided *private*, because `examples/concurrent_transfers.py` already teaches the right
    answer for a caller's own task group and it is `except*`, not a helper of ours. The library
    flattens the groups it opens itself so that one `get` keeps matching `except NoSuchFileError`;
    a group the caller opened is theirs, and anyio's wrapping there is a contract rather than
    something to paper over.
    """
    assert [name for name in gantry_sftp.__all__ if name.startswith("_")] == ["__version__"]
    assert not hasattr(gantry_sftp, "flatten_exception_group")


def test_a_program_needs_no_import_from_the_codec():
    """The D-58 property, stated as a property rather than as a list of names.

    Every type a caller *receives* from or *passes to* the session API is reachable from the
    top level. The check is on the things a README program touches: the flag enum an ``open``
    needs, the attributes a ``stat`` returns, and the pieces of those attributes.
    """
    needed = [
        "OpenFlag",  # Session.open's second argument
        "Attrs",  # what stat/lstat/fstat return
        "Owner",  # Attrs.owner
        "Times",  # Attrs.times
        "DirEntry",  # what listdir/scandir yield
        "EntryKind",  # DirEntry.kind
        "GlobMatch",  # what glob yields
        "WalkEntry",  # what walk yields
        "Skipped",  # TreeResult.skipped
        "SkipReason",  # Skipped.reason
        "TreeResult",  # what get_tree/put_tree return
        "UploadResult",  # what put returns
        "Publish",  # what put takes
        "Verify",  # what put takes
        "Mode",  # what get/put take
        "SessionOptions",  # what connect takes
        "Session",  # for a type annotation
    ]
    missing = [name for name in needed if not hasattr(gantry_sftp, name)]
    assert missing == [], f"a caller would have to import these from a subpackage: {missing}"


def test_the_entry_points_are_all_reachable_from_the_top():
    for name in ("connect", "open_session", "open_ssh_transport", "with_reconnect", "is_retryable"):
        assert hasattr(gantry_sftp, name), name


def test_the_safe_join_a_caller_has_to_write_is_reachable_from_the_top():
    """D-97, and it is the same property as D-58's rather than a second rule.

    A filter that is not a pattern -- a regex, a watermark, a manifest lookup -- cannot come
    through ``glob``, so that caller performs the join themselves. The functions ``glob``
    calls internally are what they should call, and a security primitive reachable only from
    a subpackage is one only its author finds: the README teaches this loop, so the README's
    own import has to work from the top level.
    """
    for name in ("check_listed_name", "join_remote", "local_child"):
        assert hasattr(gantry_sftp, name), name
        assert name in gantry_sftp.__all__, name


def test_the_predicates_under_them_stay_in_the_session_namespace():
    """The other half of the same decision, written down so it is not read as an omission.

    ``remote_component_reason`` and ``unsafe_reason`` answer *why* a name is unusable instead
    of refusing it, which is the shape of a caller who wants to skip one entry and carry on.
    This library does not do that -- a hostile name fails the whole operation, in ``walk``,
    ``glob`` and both tree transfers -- so promoting the skip primitive to the top level would
    advertise a policy the library declines to take. They stay public, one import away, for a
    caller who has decided otherwise on purpose.
    """
    for name in ("remote_component_reason", "unsafe_reason", "check_component", "check_contained"):
        assert hasattr(gantry_sftp.session, name), name
        assert name not in gantry_sftp.__all__, name


def test_a_listing_entry_carries_no_path_and_that_is_the_decision():
    """D-97 costed ``DirEntry.path`` and declined it; this is the decline, enforced.

    :class:`~gantry_sftp.DirEntry` is also what the *upload* walk reports, via
    ``local_dir_entry``, where there is no remote directory to carry. A field that one
    direction fills and the other cannot makes ``.path`` a property that reads as total and
    raises on half its instances -- a third state discovered at a call site rather than
    decided here. The directory is the one the caller passed to ``listdir``/``scandir``.
    """
    assert not hasattr(gantry_sftp.DirEntry, "path")
    assert not hasattr(gantry_sftp.DirEntry, "directory")
    # And the reason it cannot be filled: this is the same type, built from a local stat.
    local = gantry_sftp.session.local_dir_entry(b"report.csv", (ROOT / "README.md").stat())
    assert isinstance(local, gantry_sftp.DirEntry)
    assert local.filename == b"report.csv"


DEMONSTRATES_THE_CODEC = {
    "observability.py": "builds NAME/STATUS packets to show the frame dumper rendering them",
    "server_capabilities.py": "names an extension by its wire constant",
}
"""Examples whose subject *is* the codec, so importing it is the point rather than a leak.

Not an exemption list. ``gantry_sftp.codec`` is public on purpose -- the package docstring says
so, "because a frame dumper and a fuzz harness need it" -- and these two are the frame dumper
and the capability probe. What D-58 was about is the *other* kind of import: an ordinary program
reaching into the codec because a type it needs to pass lives only there.
``server_capabilities.py`` was doing exactly that with ``OpenFlag`` until 0.10, which is the
card's headline case, and it now takes it from the top level while still naming
``EXTENSION_CHECK_FILE`` from the codec, where wire vocabulary belongs.
"""


def codec_importers() -> dict[str, list[str]]:
    """Which examples import from ``gantry_sftp.codec``, and what they name.

    Parsed rather than grepped, so a mention inside a docstring or a comment does not count.
    """
    found: dict[str, list[str]] = {}
    for example in sorted((ROOT / "examples").glob("*.py")):
        tree = ast.parse(example.read_text(encoding="utf-8"))
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "gantry_sftp.codec"
            ):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                names.extend(
                    alias.name for alias in node.names if alias.name.startswith("gantry_sftp.codec")
                )
        if names:
            found[example.name] = names
    return found


def test_no_ordinary_example_imports_from_the_codec():
    """The claim above, checked against the programs a reader actually copies.

    An example importing from ``gantry_sftp.codec`` for an ordinary transfer would be this
    library teaching users to depend on the layer boundary the whole architecture rests on.
    """
    offenders = sorted(set(codec_importers()) - set(DEMONSTRATES_THE_CODEC))
    assert offenders == [], f"examples reaching into the codec: {offenders}"


def test_the_codec_allowlist_has_no_stale_entries():
    """The other direction, so the list cannot quietly outlive its reason.

    An entry naming an example that no longer imports the codec is a permission nobody needs,
    and it is exactly how an allowlist becomes a place to put things.
    """
    stale = sorted(set(DEMONSTRATES_THE_CODEC) - set(codec_importers()))
    assert stale == [], f"allowlisted but no longer importing the codec: {stale}"


def test_no_example_takes_open_flag_from_the_codec():
    """D-58's headline, pinned on the name that made the case.

    ``Session.open(path, pflags)`` is typed on ``OpenFlag``. A user opening a file for writing
    had no top-level spelling for it and had to import from the internal layer -- and the
    library's own example did.
    """
    reaching = {
        example: names for example, names in codec_importers().items() if "OpenFlag" in names
    }
    assert reaching == {}, f"OpenFlag still imported from the codec by: {sorted(reaching)}"


def test_the_old_spellings_still_resolve_the_old_way():
    """CLAUDE.md's public-API rule: adding a namespace must not move anything.

    Re-exporting is additive, and this is what proves it stayed additive -- the subpackage
    paths every existing program imports are the same objects the new top-level names are.
    """
    assert gantry_sftp.Attrs is CodecAttrs
    assert gantry_sftp.Session is SessionFromSession
    assert gantry_sftp.open_session is open_session_from_session
    assert gantry_sftp.open_ssh_transport is open_ssh_transport


def test_every_exception_the_package_defines_is_exported():
    """A new exception joining the library without joining the namespace is D-58's other half.

    Derived from the module rather than listed, so the check covers the next one too.
    """
    exceptions = importlib.import_module("gantry_sftp.exceptions")
    public = {
        name
        for name in dir(exceptions)
        if not name.startswith("_")
        and isinstance(getattr(exceptions, name), type)
        and issubclass(getattr(exceptions, name), BaseException)
        and getattr(exceptions, name).__module__ == "gantry_sftp.exceptions"
    }
    missing = sorted(public - set(gantry_sftp.__all__))
    assert missing == [], f"defined in exceptions.py but not exported from the package: {missing}"


# --- connect ------------------------------------------------------------------------------------


def test_connect_stays_inside_the_argument_ceiling():
    """Ten, and the reason it is exactly ten is written down rather than discovered later.

    ``pyproject.toml``'s ``max-args`` is a project-wide policy with no exemption list, and
    ruff enforces it. This asserts the *reason* the signature is shaped the way it is: the
    ssh arguments are flat because grouping unrelated connection fields is what that policy
    argues against, and the session tunables are one object because they are one policy and
    because the ssh half already spends the budget.
    """
    parameters = inspect.signature(connect).parameters
    assert len(parameters) == 10
    assert "session" in parameters


def test_connect_forwards_every_ssh_argument_under_its_own_name():
    """Signature-derived, so the two cannot drift into disagreeing about a spelling.

    A hand-written list here would be a second enumeration of ``open_ssh_transport``'s
    parameters -- the failure D-52 is in this repository to memorialise. If a future argument
    is added there and not here, this says so; if one is renamed, this says that too.
    """
    ours = set(inspect.signature(connect).parameters) - {"session"}
    theirs = set(inspect.signature(open_ssh_transport).parameters)
    assert ours <= theirs, f"connect() names ssh arguments that do not exist: {ours - theirs}"
    # And the ones deliberately not forwarded, named so the omission is a decision on the
    # record rather than an oversight somebody has to reconstruct.
    assert theirs - ours == {"subsystem"}


def test_session_options_covers_open_sessions_tunables_exactly():
    """The other half of the same anti-drift check.

    A tunable added to ``open_session`` and not to ``SessionOptions`` would be unreachable
    through ``connect()``, silently, with the default quietly winning.
    """
    theirs = set(inspect.signature(open_session).parameters) - {"transport"}
    ours = set(SessionOptions.__dataclass_fields__)
    assert ours == theirs


def test_the_session_defaults_are_the_same_defaults():
    """``connect()`` must not be a second place the defaults are written."""
    defaults = {
        name: parameter.default
        for name, parameter in inspect.signature(open_session).parameters.items()
        if name != "transport"
    }
    assert defaults == {
        "request_timeout": DEFAULT_SESSION_OPTIONS.request_timeout,
        "idle_timeout": DEFAULT_SESSION_OPTIONS.idle_timeout,
        "depth": DEFAULT_SESSION_OPTIONS.depth,
    }


def test_session_options_is_frozen_so_the_module_default_cannot_be_mutated():
    """A shared mutable default would let one caller's tuning leak into every later connect()."""
    with pytest.raises((AttributeError, TypeError)):
        DEFAULT_SESSION_OPTIONS.depth = 1  # type: ignore[misc]


async def test_connect_applies_the_session_options_it_is_given(monkeypatch: pytest.MonkeyPatch):
    """Driven rather than inspected: the forwarding is what a wrong wiring would break.

    ``open_ssh_transport`` is replaced, because what is under test is the composition rather
    than ``ssh`` -- and a real connection here would need a host. The session half is real.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    seen: dict[str, object] = {}

    @asynccontextmanager
    async def fake_transport(host: str, **kwargs: object) -> AsyncIterator[Transport]:
        seen.update(kwargs, host=host)
        async with open_local_server_transport() as transport:
            yield transport

    monkeypatch.setattr("gantry_sftp._connect.open_ssh_transport", fake_transport)

    async with connect(
        "example.invalid",
        user="bob",
        port=2222,
        session=SessionOptions(request_timeout=7.5, idle_timeout=8.5, depth=3),
    ) as sftp:
        assert sftp.depth == 3
        assert sftp.server_version == 3

    assert seen["host"] == "example.invalid"
    assert seen["user"] == "bob"
    assert seen["port"] == 2222


async def test_connect_defaults_match_the_two_call_spelling(monkeypatch: pytest.MonkeyPatch):
    """With no ``session=``, the fused call must produce the session the long form does."""
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    @asynccontextmanager
    async def fake_transport(host: str, **kwargs: object) -> AsyncIterator[Transport]:
        async with open_local_server_transport() as transport:
            yield transport

    monkeypatch.setattr("gantry_sftp._connect.open_ssh_transport", fake_transport)

    async with connect("example.invalid") as fused:
        fused_depth = fused.depth
    async with (
        open_local_server_transport() as transport,
        open_session(transport) as long_form,
    ):
        assert fused_depth == long_form.depth

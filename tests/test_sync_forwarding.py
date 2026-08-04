"""Every blocking method forwards what it was given, asserted where it crosses the boundary.

**D-135, and the reason this is a separate file from `test_sync_facade.py` is the finding that
produced it.** That file derives every name, signature and return annotation of the blocking API
from the async one, so a method added to `Session` and forgotten here fails by name. It is a good
test and it is why D-8's facade was affordable at all. It asserts on *names, signatures and return
annotations* and never on behaviour -- so it can kill no mutant, and the first mutation run over
`sync.py` found **390 mutants across ~50 methods that no test executed at all**.

**The danger was not the gap, it was that the gap looked filled.** A file called
`test_sync_facade.py` with 262 passing tests in it is where somebody would go to check whether the
blocking surface is covered, and the answer it gave was yes. Two files rather than one section,
because the distinction is structural: a derivation test proves a method *exists*, this one proves
it *forwards*, and neither is progress toward the other.

## How this works, and why the values are sentinels

Each method is called with one distinct, freshly-made object per parameter, with the async
counterpart replaced by a recorder that binds whatever arrives against that method's own
signature. Sentinels rather than realistic values, deliberately:

* **Nothing equals a default**, so an argument that restates its default is not invisible here --
  the shape recorded in `a-forwarded-argument-that-restates-a-default-is-invisible`, which is
  precisely what makes a forwarding facade untestable by ordinary use.
* **Every sentinel is distinct**, so an argument *shifted onto its neighbour* fails as loudly as
  one dropped. "Every field nullable or shiftable" is the register's phrase for the defect this
  catches.
* **No value is ever validated**, because the callee is a recorder, so no test here needs to know
  what a legal `mode` or `Publish` looks like. That is what keeps this table derived rather than
  hand-maintained: it is generated from the signature the parity test already governs.

The recorder sits at the **immediately** delegated-to method rather than further down. That is the
boundary `sync.py` crosses and the only one its mutants live on; proving a `SyncSFTPPath` call
reaches `Session.get` two layers below is a different claim and a different test.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from gantry_sftp.path import SFTPPath
from gantry_sftp.session import DirectoryScan, RemoteFile, Session
from gantry_sftp.sync import (
    SyncRemoteFile,
    SyncSession,
    SyncSFTPPath,
    open_local_server_transport,
    open_session,
)
from gantry_sftp.transport import find_sftp_server

pytestmark = pytest.mark.skipif(
    find_sftp_server() is None, reason="no sftp-server binary on this machine"
)

MUTMUT_MARKER = "__mutmut_"
"""See `test_sync_facade.py`'s note of the same name -- this file enumerates the same classes."""


def is_streaming(member: Any) -> bool:
    """Whether the async member is a generator, so the blocking form is lazy too.

    Derived rather than listed, which matters here: `SyncSFTPPath.iterdir` returns a *generator*
    and forwards nothing until something iterates it, so a table-driven call proves only that
    the generator was built. A hand-written exclusion list got `walk`, `glob` and `rglob` and
    missed `iterdir`, which is the shape a rule catches and a list does not. Their forwarding is
    proven by driving them, at the bottom of this file.
    """
    return inspect.isasyncgenfunction(member)


# Members that read a value off the object underneath rather than calling it. Nothing is
# forwarded, so there is nothing here to drop.
PROPERTIES_AND_PASSTHROUGHS = frozenset({"close"})

# `bind` shares a name with `SFTPPath.bind` and is **not** a forward: it constructs a new
# `SyncSFTPPath` around this one's bytes and the given session, because binding a blocking path
# to a blocking session cannot go through the async one. Covered by its own test below rather
# than excluded silently -- an exclusion with no successor is how the 390 got there.
CONSTRUCTS_RATHER_THAN_FORWARDS = frozenset({"bind"})


class _Sentinel:
    """A value that equals nothing else, and says which parameter it stands for when it fails."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<{self.name}>"

    def __fspath__(self) -> str:
        # Some facades call `os.fspath` on the way past. Answering keeps the sentinel usable
        # there without making it equal to anything.
        return f"/sentinel/{self.name}"


def forwarding_call(target: Any) -> tuple[list[Any], dict[str, Any], dict[str, Any]]:
    """Arguments for ``target``, one distinct sentinel each, plus what must come out the far side.

    Derived from the signature rather than listed, so a parameter added to the async surface
    arrives here automatically -- the same reason the parity test derives rather than lists.
    The expected mapping is built here rather than reconstructed by the caller, because the two
    variadic kinds arrive *collected* under their own parameter name and getting that wrong in
    two places is how a sweep starts agreeing with itself.
    """
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    expected: dict[str, Any] = {}
    for name, parameter in inspect.signature(target).parameters.items():
        if name == "self":
            continue
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            # Two, so `*names` forwarded as `names[0]` is as visible as `*names` dropped.
            spread = [_Sentinel(f"{name}0"), _Sentinel(f"{name}1")]
            args.extend(spread)
            expected[name] = tuple(spread)
        elif parameter.kind is inspect.Parameter.VAR_KEYWORD:
            # One entry, so dropping `**legacy` from the forwarding call is visible.
            sentinel = _Sentinel(f"legacy_{name}")
            kwargs[f"legacy_{name}"] = sentinel
            expected[name] = {f"legacy_{name}": sentinel}
        elif parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            kwargs[name] = expected[name] = _Sentinel(name)
        else:
            sentinel = _Sentinel(name)
            args.append(sentinel)
            expected[name] = sentinel
    return args, kwargs, expected


def record_into(store: dict[str, Any], original: Any) -> Any:
    """An async stand-in for ``original`` that records the call, bound to its own signature.

    Binding rather than storing ``(args, kwargs)`` raw is what makes the assertion indifferent
    to whether the facade forwards a value positionally or by name -- which is a spelling, not
    a behaviour -- while still failing on a value that was dropped or landed on the wrong
    parameter.
    """
    signature = inspect.signature(original)

    def capture(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        bound = signature.bind(*args, **kwargs)
        store.clear()
        # `arrived` marks that the call happened at all, separately from what it carried. A
        # method whose only parameter is `self` records nothing, and reading "no arguments" as
        # "never called" would have made every one of those pass for the wrong reason.
        store["arrived"] = {k: v for k, v in bound.arguments.items() if k != "self"}
        return _Sentinel("returned")

    # Matching the original's async-ness matters rather than being tidy: a coroutine handed to
    # a facade that expects a plain value is never awaited, which surfaces as a `RuntimeWarning`
    # from the garbage collector at whatever unrelated moment it runs.
    if is_streaming(original):

        async def generator_recorder(*args: Any, **kwargs: Any) -> Any:
            capture(args, kwargs)
            return
            yield  # unreachable, and what makes this an async generator rather than a coroutine

        return generator_recorder

    if inspect.iscoroutinefunction(original):

        async def async_recorder(*args: Any, **kwargs: Any) -> Any:
            return capture(args, kwargs)

        return async_recorder

    def sync_recorder(*args: Any, **kwargs: Any) -> Any:
        return capture(args, kwargs)

    return sync_recorder


def public_names(cls: type) -> list[str]:
    """Every public member name of ``cls``, with mutmut's synthetic ones removed.

    **In one place on purpose**, and the reason is that this file already got it wrong. The
    filter lived inline in `forwarding_names` and the streaming table below enumerated `dir()`
    on its own, so under the lane it collected `xǁSessionǁ_walk_for_download__mutmut_1` and
    tried to call it on a `SyncSession`. The mangled names begin with `x`, so
    `startswith("_")` does not exclude them -- which is the same trap D-131 fixed in
    `test_sync_facade.py`, met again one file over by a second enumeration of the same thing.
    """
    return [name for name in dir(cls) if not name.startswith("_") and MUTMUT_MARKER not in name]


def forwarding_names(blocking: type, target: type) -> list[str]:
    """Every method of ``blocking`` that plainly forwards to a same-named one on ``target``."""
    found = []
    for name in public_names(blocking):
        if name in PROPERTIES_AND_PASSTHROUGHS or name in CONSTRUCTS_RATHER_THAN_FORWARDS:
            continue
        ours = inspect.getattr_static(blocking, name)
        theirs = inspect.getattr_static(target, name, None)
        if isinstance(ours, property) or theirs is None or isinstance(theirs, property):
            continue
        if is_streaming(theirs):
            continue
        if not inspect.iscoroutinefunction(theirs) and not inspect.isfunction(theirs):
            continue
        found.append(name)
    return sorted(found)


SESSION_FORWARDS = forwarding_names(SyncSession, Session)
PATH_FORWARDS = forwarding_names(SyncSFTPPath, SFTPPath)
FILE_FORWARDS = forwarding_names(SyncRemoteFile, RemoteFile)


def test_the_derivation_is_not_vacuous():
    """Guards the guards, exactly as the parity file's own does.

    Every test below is a loop over these lists, and an empty one would make the whole file
    pass while proving nothing -- which is the failure mode this file exists because of.
    """
    assert len(SESSION_FORWARDS) > 30, SESSION_FORWARDS
    assert len(PATH_FORWARDS) > 20, PATH_FORWARDS
    assert len(FILE_FORWARDS) > 4, FILE_FORWARDS


def assert_forwards(blocking: Any, target: type, name: str, monkeypatch: Any) -> None:
    """Call one blocking method with sentinels and assert they all arrived, unshifted."""
    original = inspect.getattr_static(target, name)
    record: dict[str, Any] = {}
    monkeypatch.setattr(target, name, record_into(record, original))

    args, kwargs, expected = forwarding_call(original)
    try:
        getattr(blocking, name)(*args, **kwargs)
    except Exception:
        # **What this test claims is that the arguments arrive, and nothing about the return.**
        # Several facades wrap what they get back -- `SyncSFTPPath._wrap` rebuilds an `SFTPPath`
        # from it -- and a sentinel is not something to wrap. Swallowing that is safe rather
        # than lax: if the facade raised *before* forwarding, nothing was recorded and the
        # failure is re-raised here, so a facade that breaks on the way in is never read as one
        # that forwards.
        if "arrived" not in record:
            raise

    assert "arrived" in record, (
        f"{type(blocking).__name__}.{name} never reached {target.__name__}.{name}"
    )
    seen = record["arrived"]
    assert seen == expected, (
        f"{type(blocking).__name__}.{name} did not forward what it was given. "
        f"Missing: {sorted(set(expected) - set(seen))}; "
        f"wrong: {sorted(k for k in set(seen) & set(expected) if seen[k] is not expected[k])}"
    )


@pytest.fixture
def live(tmp_path: Path):  # type: ignore[no-untyped-def]
    """A real blocking session over a real ``sftp-server``, and the two objects hanging off it.

    A real portal rather than a fake one, because what is under test includes `_run` reaching
    the loop's thread at all -- a recorder wired to a stub portal would prove the arguments
    and not the crossing.
    """
    (tmp_path / "payload.bin").write_bytes(b"0123456789")
    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert transport is not None
        with sftp.open_file(str(tmp_path / "payload.bin").encode()) as handle:
            yield sftp, SyncSFTPPath(b"/incoming/report.csv", session=sftp), handle


@pytest.mark.parametrize("name", SESSION_FORWARDS)
def test_a_session_method_forwards_every_argument(name: str, live, monkeypatch):
    """`SyncSession`, which is 228 of the 390 mutants nothing executed."""
    sftp, _path, _handle = live
    assert_forwards(sftp, Session, name, monkeypatch)


@pytest.mark.parametrize("name", PATH_FORWARDS)
def test_a_path_method_forwards_every_argument(name: str, live, monkeypatch):
    """`SyncSFTPPath`, the newest of the three and the one with the most arguments per method."""
    _sftp, path, _handle = live
    assert_forwards(path, SFTPPath, name, monkeypatch)


@pytest.mark.parametrize("name", FILE_FORWARDS)
def test_a_file_method_forwards_every_argument(name: str, live, monkeypatch):
    """`SyncRemoteFile`, whose every method was unexercised behind the parity test."""
    _sftp, _path, handle = live
    assert_forwards(handle, RemoteFile, name, monkeypatch)


def test_a_dropped_argument_is_actually_caught(live, monkeypatch):
    """The control: this whole file is one assertion, so that assertion has to be able to fail.

    A decoy facade that forwards everything except one keyword must fail `assert_forwards`. A
    sweep that cannot fail in the direction it is written for is the failure this repository
    refuses everywhere else -- and the mutation lane is not available as the control here,
    because these tests exist precisely where the lane reported *no tests*.
    """
    sftp, _path, _handle = live

    class Forgetful:
        def chmod(self, path, mode, *, follow_symlinks=True):
            return sftp.chmod(path, mode)  # drops follow_symlinks

    with pytest.raises(AssertionError, match="did not forward"):
        assert_forwards(Forgetful(), Session, "chmod", monkeypatch)


# --- the streaming shapes, which forward nothing until something drives them -----------------

STREAMING = [
    pytest.param(SyncSession, Session, name, id=f"SyncSession.{name}")
    for name in sorted(public_names(Session))
    if is_streaming(inspect.getattr_static(Session, name, None))
] + [
    pytest.param(SyncSFTPPath, SFTPPath, name, id=f"SyncSFTPPath.{name}")
    for name in sorted(public_names(SFTPPath))
    if is_streaming(inspect.getattr_static(SFTPPath, name, None))
]


def test_the_streaming_derivation_is_not_vacuous():
    # Five: `Session.walk`, `Session.glob`, and the path's `glob`, `rglob` and `iterdir`.
    assert len(STREAMING) >= 5, STREAMING


@pytest.mark.parametrize(("blocking_type", "target", "name"), STREAMING)
def test_a_streaming_method_forwards_every_argument(blocking_type, target, name, live, monkeypatch):
    """Driven rather than called, because building the generator forwards nothing.

    `_iterate` calls the factory *through the portal* and only then starts pulling, so a test
    that stops at the return value proves the generator was constructed and not one argument
    reached the far side. Consuming it is the whole difference.
    """
    sftp, path, _handle = live
    blocking = sftp if blocking_type is SyncSession else path

    original = inspect.getattr_static(target, name)
    record: dict[str, Any] = {}
    monkeypatch.setattr(target, name, record_into(record, original))

    args, kwargs, expected = forwarding_call(original)
    assert list(getattr(blocking, name)(*args, **kwargs)) == []

    assert record.get("arrived") == expected, (
        f"{blocking_type.__name__}.{name} did not forward what it was given: "
        f"{record.get('arrived')}"
    )


def test_bind_carries_the_bytes_and_the_new_session(live):
    """`bind` is the one member sharing a name with the async surface that does not forward.

    It builds a new blocking path around this one's bytes and the given session, because
    binding a *blocking* path to a *blocking* session cannot go through the async one. Excluded
    from the table above by name, so it gets its test here rather than an exclusion nobody
    revisits.
    """
    sftp, path, _handle = live
    unbound = SyncSFTPPath(b"/incoming/report.csv")

    bound = unbound.bind(sftp)
    assert bytes(bound) == b"/incoming/report.csv"
    assert bound.session is sftp
    assert unbound.session is None, "bind mutated the path it was called on"
    assert bytes(path.bind(sftp)) == bytes(path)


# --- the default half, which neither table above nor the parity test can see -----------------
#
# The sentinel table passes a value for *every* parameter, so a facade's own default is never
# used and a mutated one is invisible there. `test_sync_facade.py` compares the two signatures
# and cannot see it either, for the reason `test_defaults.py` records: under mutmut
# `inspect.signature` reads the *trampoline*, which carries the original defaults. So a
# blocking `get` could default `verify_size` to `False`, or `no_follow` to `True`, with the
# whole suite green -- the transfer silently skipping its size check, or refusing to follow a
# symlink nobody asked it not to follow.
#
# The oracle is the async signature, which is where the contract lives and which the parity
# test already holds equal. Omitting an argument and watching what arrives is the only thing
# that reads a default, which is the same conclusion `test_defaults.py` reached one layer down.


def has_defaults(target: Any) -> bool:
    return any(
        parameter.default is not inspect.Parameter.empty
        and parameter.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        for name, parameter in inspect.signature(target).parameters.items()
        if name != "self"
    )


DEFAULTED = [
    pytest.param(SyncSession, Session, name, id=f"SyncSession.{name}")
    for name in SESSION_FORWARDS
    if has_defaults(inspect.getattr_static(Session, name))
] + [
    pytest.param(SyncSFTPPath, SFTPPath, name, id=f"SyncSFTPPath.{name}")
    for name in PATH_FORWARDS
    if has_defaults(inspect.getattr_static(SFTPPath, name))
]


def test_the_defaults_derivation_is_not_vacuous():
    assert len(DEFAULTED) > 15, DEFAULTED


@pytest.mark.parametrize(("blocking_type", "target", "name"), DEFAULTED)
def test_an_omitted_argument_arrives_as_the_async_default(
    blocking_type, target, name, live, monkeypatch
):
    """Call with every optional argument omitted; each must arrive as the async one's default."""
    sftp, path, _handle = live
    blocking = sftp if blocking_type is SyncSession else path

    original = inspect.getattr_static(target, name)
    record: dict[str, Any] = {}
    monkeypatch.setattr(target, name, record_into(record, original))

    args: list[Any] = []
    expected: dict[str, Any] = {}
    for parameter_name, parameter in inspect.signature(original).parameters.items():
        if parameter_name == "self":
            continue
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if parameter.default is inspect.Parameter.empty:
            sentinel = _Sentinel(parameter_name)
            args.append(sentinel)
            expected[parameter_name] = sentinel
        else:
            expected[parameter_name] = parameter.default

    try:
        getattr(blocking, name)(*args)
    except Exception:
        if "arrived" not in record:
            raise

    assert record.get("arrived") == expected, (
        f"{blocking_type.__name__}.{name} defaulted differently from {target.__name__}.{name}: "
        f"{ {k: v for k, v in record.get('arrived', {}).items() if expected.get(k) != v} }"
    )


# --- the shapes with no counterpart to derive from -------------------------------------------


@pytest.mark.parametrize(
    ("blocking_attr", "async_type"),
    [("scandir", DirectoryScan), ("open_file", RemoteFile)],
)
def test_leaving_a_block_forwards_all_three_exception_arguments(
    blocking_attr, async_type, live, monkeypatch, tmp_path
):
    """`__exit__` hands three values across and each was droppable on its own.

    A context manager that reports `exc_type=None` to the object underneath is telling it the
    block ended cleanly when it did not -- so a `DirectoryScan` closing a handle, or a
    `RemoteFile` deciding whether to flush, would take the success path out of a failure.
    """
    sftp, _path, _handle = live
    record: dict[str, Any] = {}
    monkeypatch.setattr(async_type, "__aexit__", record_into(record, async_type.__aexit__))

    target = b"." if blocking_attr == "scandir" else str(tmp_path / "payload.bin").encode()
    boom = ValueError("the block did not end cleanly")
    with pytest.raises(ValueError), getattr(sftp, blocking_attr)(target):
        raise boom

    arrived = record["arrived"]
    assert arrived["exc_type"] is ValueError
    assert arrived["exc"] is boom
    assert arrived["traceback"] is boom.__traceback__


@pytest.mark.parametrize("operator", ["__lt__", "__le__", "__gt__", "__ge__"])
def test_the_ordering_operators_cross_the_boundary(operator: str):
    """`dir()` skips dunders, so every table in this file is blind to these four.

    Two mutations each and they need different cases: inverting the `isinstance` guard makes
    two paths uncomparable, and loosening `<` to `<=` shows up only on paths that are equal.
    Sorting a list of remote paths is the ordinary use, and it silently reorders under either.
    """
    lower, higher, twin = (
        SyncSFTPPath(b"/incoming/a"),
        SyncSFTPPath(b"/incoming/b"),
        SyncSFTPPath(b"/incoming/a"),
    )
    strict = operator in ("__lt__", "__gt__")
    ascending = operator in ("__lt__", "__le__")

    assert getattr(lower, operator)(higher) is ascending
    assert getattr(higher, operator)(lower) is not ascending
    # Equal paths are what separate `<` from `<=`.
    assert getattr(lower, operator)(twin) is not strict
    # And a thing that is not a path is not ordered against one.
    assert getattr(lower, operator)("/incoming/b") is NotImplemented


def test_a_path_built_from_another_inherits_its_bytes_and_its_session(live):
    """The copy constructor, which is the only way a bound path is derived from a bound one.

    Losing the inherited session turns every later call into the `StateError` that tells the
    caller to bind one -- on a path that already had one.
    """
    sftp, path, _handle = live
    derived = SyncSFTPPath(path)

    assert bytes(derived) == bytes(path)
    assert derived.session is sftp
    # An explicit session still wins over the inherited one.
    assert SyncSFTPPath(SyncSFTPPath(b"/other"), session=sftp).session is sftp

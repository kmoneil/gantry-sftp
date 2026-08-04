"""Every `SFTPPath` operation forwards its arguments, its own path, and in the right order.

**D-135's second slice**, and the same finding as `sync.py`'s one layer along: `SFTPPath` is
mostly a *binding* — it holds a path and a session and hands both to the session's method — and
114 of its mutants survived because nothing read what came out the far side.

The four transfer methods are 61 of the 114 on their own, and they are the ones where a mistake
is not merely wrong but *inverted*: `download` calls `Session.get(remote, local)` while `upload`
calls `Session.put(local, remote)`, so the operand order flips between the two directions. Which
argument the path itself lands on is therefore load-bearing, and it is asserted here rather than
read off the source.

## The recorder is the whole session, not one method

`sync.py`'s tables patch the delegated-to method by name. That works there because the blocking
surface and the async one share every name. Here they do not -- `download` is `get`, `upload` is
`put`, `is_file` is `isfile` -- so patching by name would mean writing the mapping down and then
asserting the code matches what I wrote, which proves only that I copied it correctly.

Instead the whole session is a stub that records *whatever* is called on it. The mapping is then
**derived**: `RENAMED` below lists only the methods whose forwarded name differs from their own,
and a test asserts that list is exactly the set the code actually produces. A rename that appears
without being argued fails by name, and a method forwarding to the *wrong* session call fails the
same way.
"""

from __future__ import annotations

import inspect
from contextlib import suppress
from typing import Any

import pytest

from gantry_sftp.path import SFTPPath, match_components, match_path

pytestmark = pytest.mark.anyio

PATH = b"/incoming/report.csv"

RENAMED = {
    "download": "get",
    "upload": "put",
    "download_tree": "get_tree",
    "upload_tree": "put_tree",
    "is_dir": "isdir",
    "is_file": "isfile",
    "is_symlink": "islink",
    "size": "getsize",
    "mtime": "getmtime",
    "resolve": "realpath",
}
"""Path methods whose session call has a different name, and what it is.

Derived rather than trusted: `test_the_rename_table_is_exactly_the_set_of_renames` asserts this
is precisely the set of methods whose forwarded name differs from their own, so a new rename
cannot arrive unargued and a method forwarding to the wrong call fails here first.
"""

LOCAL_PATH_COMES_FIRST = frozenset({"upload", "upload_tree"})
"""The two methods where the path is the *second* positional argument, not the first.

`Session.get(remote, local)` and `Session.put(local, remote)` read in transfer order -- source
then destination -- so the operands flip between the directions. Swapping them on the upload side
is the mistake this set exists to catch, and it is the one that would be silent: both arguments
are paths.
"""

FORWARDS_VERBATIM = frozenset(
    {
        "chmod",
        "download",
        "download_tree",
        "exists",
        "is_dir",
        "is_file",
        "is_symlink",
        "lstat",
        "mtime",
        "readlink",
        "resolve",
        "rmdir",
        "rmtree",
        "size",
        "stat",
        "upload",
        "upload_tree",
    }
)
"""The members that are *only* a binding: this path, the caller's arguments, one session call.

**`SFTPPath` is not a forwarding facade the way `gantry_sftp.sync` is**, which is the thing to
know before reading the tables below. Nine of its async members do work of their own -- `mkdir`
chooses between `mkdir` and `makedirs`, `unlink` consumes `missing_ok` rather than passing it,
`read_text` decodes what `read_bytes` returned, `symlink_to` *reverses* its operands, and
`rename`/`replace` coerce a target and re-derive a path from the answer. Driving those with
sentinels proves nothing, because a sentinel cannot be encoded, coerced or opened.

So the split is declared here and **checked against the code** by
`test_the_classification_is_exactly_what_the_code_does`, rather than assumed in either
direction. A method that stops being a plain binding fails there rather than silently getting
weaker coverage from a table that no longer suits it.
"""


class _Sentinel:
    """A value that equals nothing else and names the parameter it stands for when it fails."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<{self.name}>"

    def __fspath__(self) -> str:
        return f"/sentinel/{self.name}"


class _Reply:
    """What every stub call hands back: awaitable *and* an async context manager.

    Both, because `SFTPPath` uses the session both ways -- `await session.stat(...)` and
    `async with self.open() as remote`. A plain coroutine covers only the first, and the second
    then leaves it un-awaited, which surfaces as a `RuntimeWarning` from the garbage collector
    at whatever unrelated moment it runs and which pytest promotes to an error.

    Entering yields the session itself, so the object inside a `with` records too: `read_bytes`
    opens a file and then reads it, and both calls land in the same list.
    """

    def __init__(self, session: _RecordingSession, value: Any) -> None:
        self._session = session
        self._value = value

    def __await__(self) -> Any:
        async def answer() -> Any:
            return self._value

        return answer().__await__()

    async def __aenter__(self) -> _RecordingSession:
        return self._session

    async def __aexit__(self, *_exc: object) -> None:
        return None

    def __aiter__(self) -> _Reply:
        # And iterable, for `glob`/`rglob`/`iterdir`, which forward nothing until driven.
        return self

    async def __anext__(self) -> Any:
        raise StopAsyncIteration


class _RecordingSession:
    """Stands in for a whole `Session`, recording whatever is asked of it.

    `SFTPPath._bound` is a property over `_session` with no runtime type check, so a stub goes
    in through the ordinary constructor. Recording rather than asserting is what lets the
    name mapping be derived instead of restated.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def recorder(*args: Any, **kwargs: Any) -> _Reply:
            self.calls.append((name, args, kwargs))
            return _Reply(self, _Sentinel(f"{name}()"))

        return recorder


def forwarding_call(target: Any) -> tuple[list[Any], dict[str, Any], dict[str, Any]]:
    """Sentinel arguments for every parameter, and the keywords that must come out the far side."""
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    for name, parameter in inspect.signature(target).parameters.items():
        if name == "self":
            continue
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            kwargs[name] = _Sentinel(name)
        elif parameter.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            args.append(_Sentinel(name))
    return args, kwargs, dict(kwargs)


def async_members(cls: type) -> list[str]:
    """Every public coroutine method, with mutmut's synthetic ones removed (see D-131)."""
    return sorted(
        name
        for name in dir(cls)
        if not name.startswith("_")
        and "__mutmut_" not in name
        and inspect.iscoroutinefunction(inspect.getattr_static(cls, name))
    )


ASYNC_MEMBERS = async_members(SFTPPath)


def test_the_derivation_is_not_vacuous():
    # Every test below loops over this; an empty list would pass the file while proving nothing.
    assert len(ASYNC_MEMBERS) > 20, ASYNC_MEMBERS


async def call_and_record(
    name: str, args: list[Any], keywords: dict[str, Any]
) -> _RecordingSession:
    """Call one member against a stub session and hand back what it saw.

    A failure *after* the call is not this file's business. `resolve` and `readlink` re-derive
    an `SFTPPath` from what came back, and a sentinel is not a path -- so they raise on the way
    out having forwarded perfectly. What separates that from a member which never forwarded at
    all is whether anything was recorded, which is checked rather than inferred, and the
    exception is re-raised in exactly the case where it carries the answer.
    """
    session = _RecordingSession()
    path = SFTPPath(PATH, session=session)
    try:
        _ = await getattr(path, name)(*args, **keywords)
    except Exception:
        if not session.calls:
            raise
    return session


async def drive(name: str) -> tuple[_RecordingSession, list[Any], dict[str, Any]]:
    """Call one binding with sentinels and hand back what the session saw."""
    args, keywords, expected = forwarding_call(inspect.getattr_static(SFTPPath, name))
    session = await call_and_record(name, args, keywords)
    assert session.calls, f"{name} answered without asking the session"
    return session, args, expected


@pytest.mark.parametrize("name", sorted(FORWARDS_VERBATIM))
async def test_a_binding_forwards_every_argument_and_its_own_path(name: str):
    """One distinct sentinel per parameter, so a dropped *or shifted* argument fails.

    The path itself is asserted in its documented position, because the two transfer directions
    disagree about where that is and nothing else in the suite reads it.
    """
    session, args, expected_keywords = await drive(name)
    called, positional, keywords = session.calls[-1]

    assert called == RENAMED.get(name, name), f"{name} forwarded to {called}"
    assert keywords == expected_keywords, f"{name} lost or shifted a keyword argument"

    ours = tuple(args)
    expected = (*ours, PATH) if name in LOCAL_PATH_COMES_FIRST else (PATH, *ours)
    assert positional == expected, (
        f"{name} passed its operands in the wrong order: {positional} rather than {expected}"
    )


@pytest.mark.parametrize("name", sorted(FORWARDS_VERBATIM))
async def test_an_omitted_argument_arrives_as_this_surface_s_default(name: str):
    """The default half. Passing a value for everything means no default is ever read.

    `SFTPPath` restates each default rather than letting the session supply it -- every argument
    is forwarded explicitly -- so a wrong one here is a wrong one on the wire, and neither the
    sentinel table above nor a signature comparison can see it.
    """
    signature = inspect.signature(inspect.getattr_static(SFTPPath, name))

    args: list[Any] = []
    expected: dict[str, Any] = {}
    for parameter_name, parameter in signature.parameters.items():
        if parameter_name == "self":
            continue
        if parameter.default is inspect.Parameter.empty:
            args.append(_Sentinel(parameter_name))
        elif parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            expected[parameter_name] = parameter.default

    session = await call_and_record(name, args, {})
    _called, _positional, keywords = session.calls[-1]
    assert keywords == expected, f"{name} did not forward its own documented defaults"


async def test_the_classification_is_exactly_what_the_code_does():
    """Both directions, because a table that only over-claims is half a check.

    A member that stops being a plain binding must leave `FORWARDS_VERBATIM`, and one that
    becomes a plain binding must join it -- otherwise it keeps the weaker coverage of whichever
    named test it has, and nobody notices that the named test no longer describes it.
    """
    measured: set[str] = set()
    for name in ASYNC_MEMBERS:
        args, keywords, expected = forwarding_call(inspect.getattr_static(SFTPPath, name))
        # A sentinel it cannot coerce on the way *in* means it is not a plain binding; one it
        # cannot coerce on the way *out* still forwarded. `session.calls` tells them apart.
        session = _RecordingSession()
        with suppress(Exception):
            session = await call_and_record(name, args, keywords)
        if not session.calls:
            continue
        _called, positional, seen = session.calls[-1]
        verbatim = seen == expected and set(positional) == {PATH, *args}
        if verbatim:
            measured.add(name)

    assert measured == FORWARDS_VERBATIM, (
        f"newly plain: {sorted(measured - FORWARDS_VERBATIM)}; "
        f"no longer plain: {sorted(FORWARDS_VERBATIM - measured)}"
    )


async def test_the_rename_table_is_exactly_the_set_of_renames():
    """`RENAMED` states intent; this derives reality and fails on the difference.

    A member that starts forwarding to a differently-named session call -- or to the *wrong*
    one -- shows up as an entry nobody argued for, rather than passing because somebody updated
    the table to match whatever the code now does.
    """
    observed = {}
    for name in sorted(FORWARDS_VERBATIM):
        session, _args, _keywords = await drive(name)
        called, _positional, _seen = session.calls[-1]
        if called != name:
            observed[name] = called

    assert observed == RENAMED, (
        f"unargued: {sorted(set(observed) - set(RENAMED))}; "
        f"stale: {sorted(set(RENAMED) - set(observed))}; "
        f"changed: {sorted(k for k in set(observed) & set(RENAMED) if observed[k] != RENAMED[k])}"
    )


# --- the members that are not a plain binding, each proven for what it actually does ---------


async def test_mkdir_chooses_between_the_two_session_calls():
    """`parents=` picks the call; `exist_ok=` is forwarded to whichever was picked.

    Four combinations and all four matter: `parents` decides `makedirs` against `mkdir`, and
    `exist_ok` has to survive the choice rather than being dropped by one branch.
    """
    for parents, expected_call in ((True, "makedirs"), (False, "mkdir")):
        for exist_ok in (True, False):
            session = await call_and_record("mkdir", [], {"parents": parents, "exist_ok": exist_ok})
            called, positional, keywords = session.calls[-1]
            assert called == expected_call, f"parents={parents} chose {called}"
            assert positional == (PATH,)
            assert keywords == {"exist_ok": exist_ok}, f"exist_ok lost on the {called} branch"


async def test_unlink_consumes_missing_ok_rather_than_forwarding_it():
    # `Session.remove` has no such argument, so the flag is this surface's own -- which is why
    # it does not appear in the forwarded call and why the table above excludes `unlink`.
    for missing_ok in (True, False):
        session = await call_and_record("unlink", [], {"missing_ok": missing_ok})
        called, positional, keywords = session.calls[-1]
        assert called == "remove"
        assert positional == (PATH,)
        assert keywords == {}


async def test_symlink_to_reverses_its_operands():
    """The trap this repository has already paid for once, asserted at the surface that hides it.

    `SYMLINK`'s wire order is the reverse of what the draft says, so `Session.symlink` takes
    ``(target, link)``. `SFTPPath.symlink_to` reads the other way round -- *this path* becomes a
    link *to* the target -- so it must swap them. Getting it wrong creates the link under the
    target's name, which is a real file appearing where the caller expected a symlink.
    """
    session = await call_and_record("symlink_to", [b"/elsewhere/real.csv"], {})
    called, positional, _keywords = session.calls[-1]

    assert called == "symlink"
    assert positional == (b"/elsewhere/real.csv", PATH), "the link and its target were swapped"


@pytest.mark.parametrize(("name", "call"), [("rename", "rename"), ("replace", "posix_rename")])
async def test_a_rename_coerces_its_target_and_keeps_this_path_first(name: str, call: str):
    # `replace` is the POSIX-atomic spelling and a *different* request, not a flag on the same
    # one -- so the pair is parametrized rather than tested once.
    session = await call_and_record(name, [SFTPPath(b"/incoming/renamed.csv")], {})
    called, positional, _keywords = session.calls[-1]

    assert called == call
    assert positional == (PATH, b"/incoming/renamed.csv"), "an SFTPPath target reached the wire"


@pytest.mark.parametrize("target", [b"/a/b", "/a/b", SFTPPath(b"/a/b")])
async def test_every_accepted_spelling_of_a_target_arrives_as_the_same_bytes(target: Any):
    """The axis to vary is the argument's own type, which a sentinel table cannot reach.

    Three spellings are accepted and all three have to become the same bytes on the wire -- a
    `str` encoded with `surrogateescape`, an `SFTPPath` unwrapped, `bytes` untouched.
    """
    session = await call_and_record("rename", [target], {})
    _called, positional, _keywords = session.calls[-1]
    assert positional == (PATH, b"/a/b")


async def test_read_text_decodes_what_read_bytes_returned():
    """`encoding` and `errors` are this surface's own: they never reach the session at all.

    Every mutant of those two defaults survived because no test read a byte back through them.
    A latin-1 byte is the case that separates `utf-8` from a permissive codec, and `replace`
    from `strict`.
    """
    session = _RecordingSession()
    path = SFTPPath(PATH, session=session)

    class _Bytes(_RecordingSession):
        async def read(self, *_a: object, **_k: object) -> bytes:
            return b"caf\xe9"

    session.__dict__["read"] = _Bytes().read
    assert await path.read_text(encoding="latin-1") == "café"
    assert await path.read_text(errors="replace") == "caf�"


async def test_write_text_encodes_before_it_writes():
    """The encoding is applied here and the bytes go down through `write_bytes`.

    `write_bytes` opens the file and calls `write` on the handle, so what the wire sees is the
    argument of that `write` -- which is where the encoding either happened or did not.
    """
    session = await call_and_record("write_text", ["café"], {"encoding": "latin-1"})
    calls = {name: args for name, args, _ in session.calls}

    assert "write" in calls, f"nothing was written; the session saw {sorted(calls)}"
    assert calls["write"] == (b"caf\xe9",), "the text reached the wire in the wrong encoding"


async def test_write_text_carries_the_mode_that_creates_the_file():
    # `mode=` is a security argument on this path (D-56a): omitting it lets the server apply
    # `0666 & ~umask`, and no later `chmod` closes the window. It has to survive two hops --
    # `write_text` to `write_bytes` to the `open`.
    session = await call_and_record("write_text", ["x"], {"mode": 0o640})
    opened = [args_kwargs for name, *args_kwargs in session.calls if name == "open_file"]

    assert opened, f"nothing was opened; the session saw {sorted(n for n, *_ in session.calls)}"
    assert opened[-1][1]["mode"] == 0o640, "the creating mode was lost between the two hops"


# --- the shapes no table reaches ------------------------------------------------------------


@pytest.mark.parametrize("name", ["glob", "rglob"])
async def test_a_glob_forwards_its_pattern_joined_onto_this_path(name: str):
    """Driven, because an async generator forwards nothing until something iterates it.

    The pattern is joined onto this path rather than sent as given -- a `glob` on a path is
    relative to that path -- so what reaches the session is one absolute pattern, and both
    tunables have to survive the join.

    **Both spellings reach `Session.glob`**, because `rglob(p)` is exactly `glob("**/" + p)` and
    is built as that rather than as a second kind of request. What separates them here is the
    pattern, which is the only thing that differs on the wire.
    """
    session = _RecordingSession()
    path = SFTPPath(PATH, session=session)
    depth = _Sentinel("max_depth")
    folding = _Sentinel("case_sensitive")

    assert [
        found
        async for found in getattr(path, name)(b"*.csv", max_depth=depth, case_sensitive=folding)
    ] == []

    expected = PATH + (b"/**/*.csv" if name == "rglob" else b"/*.csv")
    called, positional, keywords = session.calls[-1]
    assert called == "glob"
    assert positional == (expected,), "the pattern was not joined onto this path"
    assert keywords == {"max_depth": depth, "case_sensitive": folding}


@pytest.mark.parametrize("name", ["glob", "rglob"])
async def test_a_glob_defaults_to_matching_case_sensitively(name: str):
    # The default half. `case_sensitive=False` folds names, so a pattern starts matching files
    # it should not -- and every case that passes the argument is blind to it.
    session = _RecordingSession()
    path = SFTPPath(PATH, session=session)

    assert [found async for found in getattr(path, name)(b"*.csv")] == []

    _called, _positional, keywords = session.calls[-1]
    assert keywords == {"max_depth": None, "case_sensitive": True}


@pytest.mark.parametrize("name", ["read_text", "write_text"])
async def test_text_defaults_to_strict_utf8(name: str):
    """`encoding` and `errors` never reach the session, so only a byte round trip reads them.

    Strict is the right default and it is the one that can be wrong quietly: `replace` would
    turn a file this library could not decode into one full of replacement characters, which is
    data loss that looks like data.
    """
    session = _RecordingSession()
    path = SFTPPath(PATH, session=session)

    if name == "read_text":
        session.__dict__["read"] = _returning(b"\xff\xfe")
        with pytest.raises(UnicodeDecodeError):
            _ = await path.read_text()
    else:
        with pytest.raises(UnicodeEncodeError):
            _ = await path.write_text("\udce9")
        # And the default encoding is utf-8, proven by a character the two candidates disagree on.
        session.calls.clear()
        _ = await path.write_text("café")
        assert {n: a for n, a, _ in session.calls}["write"] == (b"caf\xc3\xa9",)


def _returning(value: object) -> Any:
    async def answer(*_a: object, **_k: object) -> object:
        return value

    return answer


@pytest.mark.parametrize("operator", ["__lt__", "__le__", "__gt__", "__ge__"])
def test_the_ordering_operators_refuse_what_is_not_a_path(operator: str):
    """`dir()` skips dunders, so every table in this file is blind to these four.

    Sorting a list of remote paths is the ordinary use. With the `isinstance` guard inverted
    two paths become uncomparable and `sorted()` raises; with the comparison loosened, equal
    paths reorder. Both cases are here.
    """
    lower, higher, twin = SFTPPath(b"/a"), SFTPPath(b"/b"), SFTPPath(b"/a")
    ascending = operator in ("__lt__", "__le__")
    strict = operator in ("__lt__", "__gt__")

    assert getattr(lower, operator)(higher) is ascending
    assert getattr(higher, operator)(lower) is not ascending
    assert getattr(lower, operator)(twin) is not strict
    assert getattr(lower, operator)("/b") is NotImplemented


@pytest.mark.parametrize("other", [b"/incoming", "/incoming", SFTPPath(b"/incoming")])
def test_is_relative_to_accepts_all_three_spellings(other: Any):
    # The same "vary the argument's own type" axis as `rename`'s target, on the predicate that
    # decides whether a path is confined to a directory -- so getting the coercion backwards
    # answers the containment question about the wrong bytes.
    assert SFTPPath(PATH).is_relative_to(other) is True
    assert SFTPPath(b"/elsewhere/x").is_relative_to(other) is False


def test_a_path_built_from_another_inherits_its_session():
    session = _RecordingSession()
    original = SFTPPath(PATH, session=session)

    assert SFTPPath(original).session is session
    assert bytes(SFTPPath(original)) == PATH
    # An explicit session still wins over the inherited one.
    other = _RecordingSession()
    assert SFTPPath(original, session=other).session is other


def test_a_double_star_is_reachable_only_once_something_reaches_it():
    """`_spread` is what lets `**` stand for zero or more names, and it is pure.

    Seeded `True` rather than `False`, every position reads as reachable and `**` matches from
    the start regardless of what came before it -- so a pattern anchored to a directory would
    match outside it. Asserted directly, because through `match_path` the difference is one
    boolean at the end of a longer computation.
    """
    from gantry_sftp.path import _spread  # noqa: PLC0415  # private and pure, tested in place

    assert _spread([False, False]) == [False, False]
    assert _spread([False, True, False]) == [False, True, True]
    assert _spread([]) == []


# --- the pure algebra, whose edges the operations above never reach --------------------------


@pytest.mark.parametrize(
    ("name", "stem", "suffix"),
    [
        # The dot at index 1 -- a one-character stem, which `0 < dot` admits and `1 < dot` does
        # not. `a.txt` is not exotic: it is what a per-key or per-shard file is called.
        (b"a.txt", b"a", b".txt"),
        # A one-character suffix, where `len(name) - 1` and `len(name) - 2` part company.
        (b"file.c", b"file", b".c"),
        # A dotfile has no suffix, and a trailing dot is not the start of one.
        (b".hidden", b".hidden", b""),
        (b"trailing.", b"trailing.", b""),
        (b"no-dot", b"no-dot", b""),
        (b"two.dots.gz", b"two.dots", b".gz"),
    ],
)
def test_the_stem_and_suffix_boundaries(name: bytes, stem: bytes, suffix: bytes):
    """Both halves of one comparison, and each end of it has its own case.

    `stem` and `suffix` split on `0 < dot < len(name) - 1`, and every existing case sits well
    inside that range -- so both boundaries could move by one with nothing failing. They are the
    same expression twice, so a case that pins one has to pin the other or half of it stays
    free.
    """
    path = SFTPPath(b"/incoming/" + name)
    assert path.stem == stem
    assert path.suffix == suffix


def test_match_path_defaults_to_matching_case_sensitively():
    # The default on a *public* function, so a caller who never passes the argument gets it.
    # Folded, a pattern starts matching names that differ only in case -- which on a
    # case-sensitive server is a different file.
    assert match_path(b"*.CSV", b"/incoming/report.csv") is False
    assert match_path(b"*.CSV", b"/incoming/report.csv", case_sensitive=False) is True
    assert match_path(b"*.csv", b"/incoming/report.csv") is True


def test_a_pattern_component_is_matched_where_it_stands():
    """`match_components` asked directly, because `match_path` is a filter over it.

    A *relative* pattern is matched from the right by `match_path`, so through that door a
    one-component pattern is supposed to match the last name of a longer path -- which is
    exactly what an over-permissive reachability seed also does. The two are indistinguishable
    from outside, and the security-shaped half is this one: the sweep must not treat every
    position as a place the pattern could have started.
    """
    assert match_components([b"b"], (b"a", b"b"), case_sensitive=True) is False
    assert match_components([b"a", b"b"], (b"a", b"b"), case_sensitive=True) is True
    assert match_components([b"b"], (b"b",), case_sensitive=True) is True
    # `**` is what makes a shorter pattern reach a longer path, and it has to be asked for.
    assert match_components([b"**", b"b"], (b"a", b"b"), case_sensitive=True) is True
    assert match_components([b"**", b"c"], (b"a", b"b"), case_sensitive=True) is False


def test_a_pattern_longer_than_the_path_matches_nothing():
    # The `index > 0` guard. Loosened to `>= 0`, index 0 reads `reachable[-1]` and
    # `components[-1]` -- Python's negative indexing quietly wrapping to the *last* name -- so
    # the sweep can start accounting for the pattern from off the end of the path.
    assert match_components([b"a", b"b", b"c"], (b"a", b"b"), case_sensitive=True) is False
    assert match_components([b"a"], (), case_sensitive=True) is False


async def test_mkdir_defaults_to_this_directory_only_and_to_refusing_an_existing_one():
    """Both of `mkdir`'s own defaults, which the four-combination test above cannot read.

    That one passes `parents` and `exist_ok` explicitly, so neither default is ever used.
    Defaulted the other way, `path.mkdir()` would create every missing ancestor and succeed on
    a directory that is already there -- which is `makedirs`, a different call with a different
    contract, reached by a caller who asked for neither.
    """
    session = await call_and_record("mkdir", [], {})
    called, positional, keywords = session.calls[-1]

    assert called == "mkdir", "the bare call created ancestors it was not asked for"
    assert positional == (PATH,)
    assert keywords == {"exist_ok": False}


async def test_write_text_forwards_the_error_handler_it_was_given():
    """`errors=` is dropped as easily as it is passed, and `strict` is the default it falls to.

    So the mutation only shows on a string the two handlers disagree about. A lone surrogate is
    that string, and it is not hypothetical here: it is what `surrogateescape` produces when a
    name or a body came off the wire as bytes no encoding explains.
    """
    session = await call_and_record("write_text", ["\udce9"], {"errors": "surrogateescape"})
    written = {name: args for name, args, _ in session.calls}

    assert written["write"] == (b"\xe9",), "the error handler was dropped on the way to encode"

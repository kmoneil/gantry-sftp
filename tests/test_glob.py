"""Glob: the dialect, and a matcher that must not be fuzzable to a hang.

Two halves, and the split is the layering. The pattern matcher is **pure** -- bytes in, a bool
out, no I/O and no clock -- so it is tested and fuzzed directly. The traversal is tested
against the scripted :class:`TreeServer`, because the interesting cases are the ones a real
server will not produce on request: a listing entry containing ``/``, a name that is not valid
UTF-8, a server whose namespace is not rooted at ``/``.

The dialect table below is the specification. It is written as a table on purpose: every row is
a decision that could have gone the other way, and three of them differ from :mod:`fnmatch`,
which is the module a reader would otherwise assume was under this.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from contextlib import aclosing
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    PermissionDeniedError,
    ServerError,
    UnsafePathError,
)
from gantry_sftp.session import open_session
from gantry_sftp.session._glob import (
    RECURSIVE,
    has_magic,
    match_component,
    split_pattern,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from test_recursive import DIRECTORY, REGULAR, SYMLINK, TreeServer, named

pytestmark = pytest.mark.anyio


# --- the dialect, which is `glob(3)`'s and not fnmatch's -------------------------------------

DIALECT: list[tuple[str, bytes, bytes, bool]] = [
    ("star-matches-suffix", b"*.csv", b"report.csv", True),
    ("star-rejects-other-suffix", b"*.csv", b"report.txt", False),
    ("star-matches-empty", b"*", b"", True),
    ("star-alone-matches-anything", b"*", b"whatever", True),
    ("question-is-exactly-one", b"a?c", b"abc", True),
    ("question-is-not-zero", b"a?c", b"ac", False),
    ("question-is-not-two", b"a?c", b"abbc", False),
    ("class-range", b"log[0-9]", b"log7", True),
    ("class-range-misses", b"log[0-9]", b"logx", False),
    ("class-set", b"log[abc]", b"logb", True),
    ("class-negated-with-bang", b"log[!0-9]", b"logx", True),
    ("class-negated-with-bang-misses", b"log[!0-9]", b"log7", False),
    ("class-negated-with-caret", b"log[^0-9]", b"logx", True),
    ("class-negated-with-caret-misses", b"log[^0-9]", b"log7", False),
    ("close-bracket-first-is-literal", b"a[]]b", b"a]b", True),
    ("unterminated-bracket-is-literal", b"a[b", b"a[b", True),
    ("escaped-star-is-literal", b"a\\*b", b"a*b", True),
    ("escaped-star-does-not-wildcard", b"a\\*b", b"axb", False),
    ("escaped-question-is-literal", b"a\\?b", b"a?b", True),
    ("trailing-backslash-is-literal", b"ab\\", b"ab\\", True),
    ("leading-dot-not-matched-by-star", b"*", b".hidden", False),
    ("leading-dot-not-matched-by-question", b"?hidden", b".hidden", False),
    ("leading-dot-not-matched-by-class", b"[.]hidden", b".hidden", False),
    ("leading-dot-matched-by-literal-dot", b".*", b".hidden", True),
    ("leading-dot-matched-by-escaped-dot", b"\\.hidden", b".hidden", True),
    ("interior-dot-is-ordinary", b"a*", b"a.hidden", True),
    ("non-utf8-name-matches", b"*.csv", b"\xff\xfe.csv", True),
    ("non-utf8-pattern-matches", b"\xff*", b"\xff\xfe.csv", True),
    ("multiple-stars-collapse", b"**.csv", b"a.csv", True),
    ("star-does-not-match-across-nothing", b"a*b*c", b"axbyc", True),
    # --- bracket expressions, every row checked against libc's own `fnmatch(3)` -------------
    #
    # `glob(3)` matches each component with the same matcher `fnmatch(3)` exposes, so libc is
    # the reference this dialect claims to follow rather than a second opinion about it. The
    # differential test below re-derives all of these from libc at run time; they are written
    # out here as well because this table *is* the specification, and a row a reader can see
    # is worth more than one a fuzzer regenerates.
    #
    # 23 of `_glob.py`'s 36 mutation survivors were in this handful of branches, and the
    # matcher was **right about every one** -- what was missing was anything pinning it.
    ("class-escape-closes-bracket", b"[\\]]", b"]", True),
    ("class-escape-is-not-the-backslash", b"[\\]]", b"\\", False),
    ("class-escape-makes-a-dash-literal", b"a[\\-]b", b"a-b", True),
    ("class-escape-does-not-match-the-slash", b"a[\\-]b", b"a\\b", False),
    ("class-escaped-ordinary-is-itself", b"[\\a]", b"a", True),
    ("class-escape-consumes-the-backslash", b"[\\a]", b"\\", False),
    # A dash with nothing after it is a literal dash, not a half-open range.
    ("trailing-dash-is-literal-low", b"[a-]", b"a", True),
    ("trailing-dash-is-literal-dash", b"[a-]", b"-", True),
    ("trailing-dash-spans-nothing", b"[a-]", b"b", False),
    ("leading-dash-is-literal", b"[-a]", b"-", True),
    ("leading-dash-keeps-the-rest", b"[-a]", b"a", True),
    # `]` directly after `-` ends the class, so `[a-]]` is the class `[a-]` then a literal `]`.
    ("dash-before-close-is-literal", b"[a-]]", b"a", False),
    ("dash-before-close-needs-the-bracket", b"[a-]]", b"]", False),
    ("close-first-then-dash", b"[]-]", b"]", True),
    ("close-first-then-dash-matches-dash", b"[]-]", b"-", True),
    # An escaped dash cannot open a range, so `[a\-c]` is three literals and not `a` to `c`.
    ("escaped-dash-does-not-open-a-range", b"[a\\-c]", b"b", False),
    ("escaped-dash-is-a-member", b"[a\\-c]", b"-", True),
    # Negation still loses to the leading-period rule, which `glob(3)` applies and bare
    # `fnmatch(3)` does not -- the flag is `FNM_PERIOD`, and forgetting it makes libc look
    # like it disagrees with us when it is being asked a different question.
    ("negated-class-does-not-reach-a-dotfile", b"[!-/]", b".", False),
    ("negated-class-matches-otherwise", b"[!-/]", b"e", True),
]


@pytest.mark.parametrize(
    ("pattern", "name", "expected"),
    [(pattern, name, expected) for _, pattern, name, expected in DIALECT],
    ids=[name for name, *_ in DIALECT],
)
def test_the_dialect_is_glob3_rather_than_fnmatch(pattern: bytes, name: bytes, expected: bool):
    # `sftp(1)` globs client-side through POSIX glob(3) (sftp-glob.c, GLOB_ALTDIRFUNC), so the
    # reference implementation's dialect is glob(3)'s. Three rows here are where fnmatch would
    # answer differently: the leading-dot rules and the escaping ones.
    assert match_component(pattern, name) is expected


# --- the same question, asked of libc rather than of this file -------------------------------


def _libc_fnmatch():
    """libc's own ``fnmatch(3)``, or ``None`` where it cannot be reached.

    ``glob(3)`` matches each path component with this matcher, so it is not a second opinion
    about the dialect -- it is the thing the dialect is defined as. Loaded through ``ctypes``
    rather than shelled out to, because the answer wanted is a bool per call and there are
    thousands of calls.
    """
    name = ctypes.util.find_library("c")
    if name is None and not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(name or "libc.so.6")
        libc.fnmatch.restype = ctypes.c_int
        libc.fnmatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    except (OSError, AttributeError):  # pragma: no cover -- platform without it
        return None
    return libc.fnmatch


_FNM_PERIOD = 4
"""glibc ``fnmatch.h``: ``FNM_PATHNAME`` 1, ``FNM_NOESCAPE`` 2, ``FNM_PERIOD`` 4.

``FNM_PERIOD`` is the flag that makes a leading period need matching explicitly, which is
``glob(3)``'s behaviour and therefore ours. Omitting it is not a smaller test, it is a
different question -- and it makes libc appear to disagree with us on ``[!-/]`` against
``.``, which is how this constant came to be written down rather than assumed.
"""

# The alphabet is every byte that means something to the matcher, plus two ordinary ones and a
# byte above 127. `/` is excluded because a component never contains one -- `split_pattern`
# removes them before the matcher is ever called -- and NUL because it cannot cross `c_char_p`.
_INTERESTING = st.sampled_from([bytes([b]) for b in b"*?[]!^-\\.aA0\xff"])
_FRAGMENT = st.lists(_INTERESTING, max_size=6).map(b"".join)


def _every_class_is_terminated(pattern: bytes) -> bool:
    """Whether every ``[`` in ``pattern`` opens a class that is closed.

    This encodes the POSIX *termination* rule, not this library's matching logic -- a `]`
    immediately after the `[` (or after a leading `!`/`^`) is a literal member and does not
    close the class, which is the only way to put one in a class at all. It exists solely to
    keep POSIX-undefined input out of the differential below; nothing about matching is
    decided here, and getting it slightly conservative costs coverage rather than soundness.
    """
    i = 0
    while i < len(pattern):
        if pattern[i : i + 1] == b"\\":
            i += 2
            continue
        if pattern[i : i + 1] != b"[":
            i += 1
            continue
        p = i + 1
        if pattern[p : p + 1] in (b"!", b"^"):
            p += 1
        if pattern[p : p + 1] == b"]":  # literal first member
            p += 1
        close = pattern.find(b"]", p)
        if close == -1:
            return False
        i = close + 1
    return True


@pytest.mark.skipif(_libc_fnmatch() is None, reason="libc fnmatch(3) is not reachable here")
@settings(max_examples=500, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(pattern=_FRAGMENT, name=_FRAGMENT)
def test_the_matcher_agrees_with_libc_on_arbitrary_patterns(pattern: bytes, name: bytes):
    """Differential fuzz against the implementation this dialect is *defined* as.

    The dialect table above is the specification and this is its proof: every row there is a
    decision someone wrote down, and this asks libc the same question several hundred more
    ways per run. It is the strongest form the module's central claim can take -- "the dialect
    is `glob(3)`, because that is what the reference client uses" is either true against libc
    or it is not.

    Case-sensitive only. `FNM_CASEFOLD` is a GNU extension whose folding is locale-dependent,
    while ours is ASCII-only by decision (a remote name is bytes of unstated encoding), so the
    two are answering different questions there and a disagreement would prove nothing.
    """
    # The one divergence, excluded here and pinned by `trailing-backslash-is-literal` above so
    # that excluding it costs no coverage of it. A pattern ending in an *unpaired* backslash --
    # an escape with nothing left to escape -- is undefined in POSIX; glibc answers no-match and
    # this library answers "a literal backslash", which is what a user who globbed a filename
    # containing one expects. That is the whole of it: the fuzz found this case within a few
    # hundred examples and no other, over `* ? [ ] ! ^ - \\ . a A 0 \xff`.
    trailing = len(pattern) - len(pattern.rstrip(b"\\"))
    assume(trailing % 2 == 0)

    # The second divergence, and it is a **gap rather than a decision** -- D-106. `glob(3)`
    # supports POSIX bracket sub-expressions inside a class: character classes
    # `[[:digit:]]`, equivalence classes `[[=a=]]` and collating symbols `[[.a.]]`. This
    # matcher implements none of them, so `glob("*.[[:digit:]]")` matches nothing at all
    # rather than every digit -- a silent wrong answer, and against a spelling that works in
    # `sftp(1)` today. Excluded here so the rest of the differential can run; **not** excluded
    # because it is acceptable. The module's "deliberately not supported" list names brace
    # expansion, tilde expansion and non-ASCII folding, and this is not on it.
    assume(not any(marker in pattern for marker in (b"[:", b"[=", b"[.")))

    # The third divergence, and the only one where *libc* is the inconsistent party. An
    # unterminated `[` is undefined in POSIX. This matcher answers "a literal `[`" uniformly;
    # glibc answers that for `[abc` and no-match for `[*-`, so there is no single glob(3)
    # behaviour here to match. Ours is the documented choice and the one a caller who globbed
    # a filename containing a bracket expects. Terminated classes -- where the 23 survivors
    # this slice was about actually live -- are still fuzzed.
    assume(_every_class_is_terminated(pattern))

    fnmatch = _libc_fnmatch()
    assert fnmatch is not None  # narrowed by the skipif above
    assert match_component(pattern, name) is (fnmatch(pattern, name, _FNM_PERIOD) == 0), (
        f"pattern={pattern!r} name={name!r}"
    )


def test_a_component_never_sees_a_separator_so_star_cannot_cross_one():
    # The fnmatch trap: `fnmatch.fnmatchcase(b"a/b.csv", b"*.csv")` is True, which would make
    # `*.csv` match into subdirectories. Patterns are split into components before they ever
    # reach the matcher, so the matcher is only ever asked about one level.
    assert split_pattern(b"/incoming/*.csv") == (b"/incoming", (b"*.csv",), False)
    assert split_pattern(b"/incoming/*/*.csv") == (b"/incoming", (b"*", b"*.csv"), False)


@pytest.mark.parametrize(
    ("pattern", "name", "expected"),
    [
        (b"*.CSV", b"report.csv", True),
        (b"REPORT.*", b"report.csv", True),
        (b"[A-Z]og", b"log", True),
        (b"[a-z]og", b"Log", True),
        # Above 127 nothing is folded: the bytes are of an encoding the protocol never states,
        # so folding one would be folding a fragment of some character in a guessed encoding.
        (b"\xc3\x89", b"\xc3\xa9", False),
    ],
    ids=["suffix", "stem", "upper-range", "lower-range", "non-ascii-is-never-folded"],
)
def test_case_insensitive_matching_folds_ascii_and_nothing_else(
    pattern: bytes, name: bytes, expected: bool
):
    assert match_component(pattern, name, case_sensitive=False) is expected
    assert match_component(pattern, name) is (pattern == name)


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (b"/incoming/2026/*.csv", (b"/incoming/2026", (b"*.csv",), False)),
        (b"*.csv", (b"", (b"*.csv",), False)),
        (b"/incoming/**/*.csv", (b"/incoming", (RECURSIVE, b"*.csv"), False)),
        (b"/incoming/", (b"/incoming", (), True)),
        (b"/a/b/c", (b"/a/b/c", (), False)),
        (b"/", (b"/", (), False)),
        (b"**", (b"", (RECURSIVE,), False)),
        (b"/*", (b"/", (b"*",), False)),
        (b"/incoming//sub/*", (b"/incoming/sub", (b"*",), False)),
        (b"/incoming/*/", (b"/incoming", (b"*",), True)),
    ],
    ids=[
        "literal-prefix",
        "relative",
        "recursive-in-the-middle",
        "trailing-slash-is-directories-only",
        "no-magic-at-all",
        "root",
        "recursive-alone",
        "magic-directly-under-root",
        "empty-components-collapse",
        "trailing-slash-with-magic",
    ],
)
def test_the_literal_prefix_is_split_off_so_no_directory_is_listed_needlessly(
    pattern: bytes, expected: tuple[bytes, tuple[bytes, ...], bool]
):
    # Not only an optimisation: listing directories a pattern was never going to match is an
    # observable side effect on a server that logs, and on one that charges.
    assert split_pattern(pattern) == expected


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (b"/x/report.csv", (b"/x", (b"report.csv",), False)),
        (b"/incoming/*.csv", (b"/incoming", (b"*.csv",), False)),
        (b"/a/b/c", (b"/a/b", (b"c",), False)),
        (b"report.csv", (b"", (b"report.csv",), False)),
        (b"/", (b"/", (), False)),
    ],
    ids=["literal-file", "magic-is-unchanged", "literal-path", "relative-literal", "root"],
)
def test_case_insensitive_matching_never_folds_the_last_component_into_the_prefix(
    pattern: bytes, expected: tuple[bytes, tuple[bytes, ...], bool]
):
    # Found by the live test. A wholly literal pattern has nothing left to match once the
    # prefix is split off, so `case_sensitive=False` was accepted and silently did nothing --
    # naming the path to the server resolves it the *server's* way, which is the one thing the
    # argument says not to rely on. The directory part is still used as typed: folding that too
    # would mean listing `/` to answer a question the caller did not ask.
    assert split_pattern(pattern, case_sensitive=False) == expected


def test_a_backslash_does_not_make_a_component_magic():
    # It only escapes, so `a\b` still names exactly one file and can take the literal path.
    assert not has_magic(b"a\\b")
    assert has_magic(b"a*b")
    assert has_magic(b"a?b")
    assert has_magic(b"a[b")


# --- the matcher must not be fuzzable to a hang ----------------------------------------------


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(pattern=st.binary(max_size=40), name=st.binary(max_size=200))
def test_matching_arbitrary_bytes_terminates_and_never_raises(pattern: bytes, name: bytes):
    # A file-transfer library matching hostile server names against a caller's pattern must not
    # be reducible to a crash or a hang. The matcher is deliberately not a compiled regular
    # expression: `*a*a*a*a*b` translated to `.*a.*a.*a.*a.*b` backtracks catastrophically on a
    # long name, and the name is the half the *peer* chooses.
    assert match_component(pattern, name) in (True, False)


def test_the_pathological_backtracking_pattern_is_not_pathological_here():
    # The shape that kills a regex-backed glob. Asserted as a result rather than a timing, so
    # it cannot flake on a busy machine -- a matcher that backtracked would not finish at all.
    assert not match_component(b"*a" * 40 + b"b", b"a" * 4000)


@settings(max_examples=200, deadline=None)
@given(name=st.binary(min_size=1, max_size=60))
def test_a_name_with_no_magic_in_it_matches_itself(name: bytes):
    # The round-trip property a matcher has: escaping a name turns it into the pattern that
    # matches exactly that name and nothing else.
    escaped = bytes(name).replace(b"\\", b"\\\\")
    for byte in b"*?[":
        escaped = escaped.replace(bytes([byte]), b"\\" + bytes([byte]))
    assert match_component(escaped, name)


# --- the traversal, against a server that may be lying ----------------------------------------

GLOB_TREE = {
    b"/root": (
        named(b"a.csv", REGULAR, 3),
        named(b"b.txt", REGULAR, 3),
        named(b".hidden.csv", REGULAR, 3),
        named(b"sub", DIRECTORY),
        named(b"link", SYMLINK),
    ),
    b"/root/sub": (named(b"c.csv", REGULAR, 5), named(b"deeper", DIRECTORY)),
    b"/root/sub/deeper": (named(b"d.csv", REGULAR, 7),),
}


async def matches(sftp, pattern: bytes | str, **kwargs) -> list[bytes]:
    """Every path a pattern matches, in order.

    `aclosing` rather than dropping the generator: a suspended async generator left to the
    garbage collector is not finalised by trio, and surfaces as an ignored exception at some
    unrelated point later. The library documents this idiom, so the tests use it.
    """
    async with aclosing(sftp.glob(pattern, **kwargs)) as found:
        return [match.path async for match in found]


async def test_a_glob_matches_one_directory_and_does_not_descend():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.csv") == [b"/root/a.csv"]


async def test_a_leading_dot_is_matched_only_when_asked_for():
    # The rule that keeps a glob over a drop directory from picking up half-written staging
    # files -- including the dot-prefixed ones this library's own atomic publish creates.
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.csv") == [b"/root/a.csv"]
        assert await matches(sftp, b"/root/.*.csv") == [b"/root/.hidden.csv"]


async def test_one_wildcard_component_descends_exactly_one_level():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*/*.csv") == [b"/root/sub/c.csv"]


async def test_a_recursive_component_crosses_every_level():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        found = await matches(sftp, b"/root/**/*.csv")

    # `**` is zero or more levels, so the directory it starts from is included.
    assert found == [b"/root/a.csv", b"/root/sub/c.csv", b"/root/sub/deeper/d.csv"]


async def test_max_depth_bounds_how_far_a_recursive_component_descends():
    # An infinite tree is something a hostile server can simply answer with, which is why the
    # bound exists at all -- and it is the walk's bound, reused rather than reimplemented.
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/**/*.csv", max_depth=0) == [b"/root/a.csv"]
        assert await matches(sftp, b"/root/**/*.csv", max_depth=1) == [
            b"/root/a.csv",
            b"/root/sub/c.csv",
        ]


async def test_a_trailing_recursive_component_means_everything_below():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        found = await matches(sftp, b"/root/sub/**")

    assert found == [b"/root/sub/c.csv", b"/root/sub/deeper", b"/root/sub/deeper/d.csv"]


async def test_a_trailing_slash_restricts_the_match_to_directories():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*/") == [b"/root/sub"]
        assert await matches(sftp, b"/root/*") == [
            b"/root/a.csv",
            b"/root/b.txt",
            b"/root/sub",
            b"/root/link",
        ]


async def test_a_symlink_matches_and_is_never_descended_into():
    # Consistent with `walk`, and for the same reason: following one needs loop detection this
    # library deliberately does not have. So it can match a pattern and cannot be searched.
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert b"/root/link" in await matches(sftp, b"/root/*")
        assert await matches(sftp, b"/root/link/*") == []


async def test_a_pattern_with_no_magic_is_a_path_and_answers_at_most_once():
    server = TreeServer(tree=GLOB_TREE, files={b"/root/a.csv": b"aaa"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/a.csv") == [b"/root/a.csv"]
        assert await matches(sftp, b"/root/absent.csv") == []
        # A literal pattern with a trailing slash still means "and it must be a directory".
        assert await matches(sftp, b"/root/a.csv/") == []
        assert await matches(sftp, b"/root/sub/") == [b"/root/sub"]


async def test_a_match_carries_the_entry_so_the_kind_costs_no_extra_round_trip():
    server = TreeServer(tree=GLOB_TREE, files={b"/root/a.csv": b"aaa"})
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        aclosing(sftp.glob(b"/root/a.csv")) as found,
    ):
        match = await anext(aiter(found))

    assert match.path == b"/root/a.csv"
    assert match.name == b"a.csv"
    assert match.entry.size == 3


async def test_a_pattern_may_be_given_as_str():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, "/root/*.csv") == [b"/root/a.csv"]


async def test_a_non_utf8_name_is_matched_as_bytes_rather_than_decoded():
    # A lossy decode makes two distinct names match one pattern, and `surrogateescape` makes
    # the pattern unwritable as a str. Matching is on the bytes the server actually sent.
    tree = {b"/root": (named(b"\xff\xfe.csv", REGULAR, 3), named(b"plain.csv", REGULAR, 3))}
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.csv") == [b"/root/\xff\xfe.csv", b"/root/plain.csv"]
        assert await matches(sftp, b"/root/\xff*") == [b"/root/\xff\xfe.csv"]


async def test_case_insensitivity_is_the_callers_decision_because_it_is_the_servers_property():
    # This library cannot detect a case-folding server, and guessing means either missing files
    # on one that folds or inventing matches on one that does not.
    tree = {b"/root": (named(b"REPORT.CSV", REGULAR, 3),)}
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.csv") == []
        assert await matches(sftp, b"/root/*.csv", case_sensitive=False) == [b"/root/REPORT.CSV"]
        # And a wholly literal pattern folds too, rather than accepting the argument and
        # quietly naming the path to the server instead of matching it.
        assert await matches(sftp, b"/root/report.csv") == []
        assert await matches(sftp, b"/root/report.csv", case_sensitive=False) == [
            b"/root/REPORT.CSV"
        ]


async def test_a_server_supplied_name_containing_a_separator_is_refused():
    # The whole reason to use `glob` rather than a hand-rolled listdir plus match: the join from
    # a name the server chose to a path the caller will feed to `get` happens once, here, and
    # the component is checked first. A real sftp-server will not do this however you ask it,
    # which is exactly why it is scripted.
    tree = {b"/root": (named(b"../../etc/passwd", REGULAR, 3),)}
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsafePathError) as excinfo:
            await matches(sftp, b"/root/*")

    assert excinfo.value.args[0] == (
        "refusing the server-supplied name b'../../etc/passwd' in the listing of b'/root': "
        "it contains a path separator, so it is not one path component and this server is "
        "not describing its own directory truthfully"
    )
    assert excinfo.value.name == b"../../etc/passwd"
    assert excinfo.value.reason == "a path separator"


async def test_a_relative_pattern_is_refused_on_a_server_whose_root_is_not_a_slash():
    # D-77's gate, reached through a new door. `/`-arithmetic on a namespace the draft defines
    # no syntax for builds paths the server does not mean, so it refuses rather than guesses.
    server = TreeServer(tree={b"/root": ()}, root=b"DISK$USER:[HOME]")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as excinfo:
            await matches(sftp, b"*.csv")

    assert excinfo.value.feature == "globbing"


async def test_an_absolute_pattern_asks_the_server_nothing_about_its_root():
    # §6.2: a path starting with `/` is absolute, so the caller has already asserted the
    # namespace. No REALPATH probe is sent, which is visible as the root staying unasked-for.
    server = TreeServer(tree=GLOB_TREE, root=b"DISK$USER:[HOME]")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.csv") == [b"/root/a.csv"]
        assert sftp.server_root is None


async def test_a_relative_pattern_answers_in_relative_paths_with_and_without_a_star_star():
    # One pattern must not answer in two spellings depending on whether it contained `**`: the
    # recursive branch walks `.` and would otherwise prefix every path with `./`.
    tree = {
        b"/home/user": (named(b"a.csv", REGULAR, 3), named(b"sub", DIRECTORY)),
        b"/home/user/sub": (named(b"b.csv", REGULAR, 3),),
    }
    server = TreeServer(tree=tree, root=b"/home/user")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"*.csv") == [b"a.csv"]
        assert await matches(sftp, b"**/*.csv") == [b"a.csv", b"sub/b.csv"]


# --- against a real sftp-server, because a fake only confirms what its author believed --------


def build_glob_tree(root: Path) -> None:
    """A tree with the names that make the dialect observable on a real filesystem."""
    (root / "a.csv").write_bytes(b"aaa")
    (root / "b.txt").write_bytes(b"bbb")
    (root / ".hidden.csv").write_bytes(b"hhh")
    (root / "REPORT.CSV").write_bytes(b"rrr")
    # Not valid UTF-8, and legal on ext4. The axis the card named: a lossy decode makes two
    # distinct names match one pattern, so the match has to run on the bytes.
    (root / os.fsdecode(b"odd-\xff\xfe.csv")).write_bytes(b"ooo")
    sub = root / "sub"
    sub.mkdir()
    (sub / "c.csv").write_bytes(b"ccc")
    deeper = sub / "deeper"
    deeper.mkdir()
    (deeper / "d.csv").write_bytes(b"ddd")


async def test_globbing_a_real_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    root = tmp_path / "remote"
    root.mkdir()
    build_glob_tree(root)
    prefix = os.fsencode(str(root))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        top = await matches(sftp, prefix + b"/*.csv")
        hidden = await matches(sftp, prefix + b"/.*.csv")
        one_level = await matches(sftp, prefix + b"/*/*.csv")
        every_level = await matches(sftp, prefix + b"/**/*.csv")
        directories = await matches(sftp, prefix + b"/*/")
        folded = await matches(sftp, prefix + b"/report.csv", case_sensitive=False)

    # Sorted, because a real server's READDIR order is its own business -- the fake's order is
    # the only place this suite may assert on sequence.
    assert sorted(top) == [prefix + b"/a.csv", prefix + b"/odd-\xff\xfe.csv"]
    assert hidden == [prefix + b"/.hidden.csv"]
    assert one_level == [prefix + b"/sub/c.csv"]
    assert sorted(every_level) == [
        prefix + b"/a.csv",
        prefix + b"/odd-\xff\xfe.csv",
        prefix + b"/sub/c.csv",
        prefix + b"/sub/deeper/d.csv",
    ]
    assert directories == [prefix + b"/sub"]
    # A genuinely case-folding *server* is not in any lane here -- ext4 does not fold -- so
    # what this proves is our folding against a real listing, which is the half we own. The
    # server-side half is the argument for `case_sensitive` being a parameter at all.
    assert folded == [prefix + b"/REPORT.CSV"]


async def test_a_real_server_listing_feeds_get_without_the_caller_joining_anything(
    tmp_path: Path,
):
    # The end-to-end shape the card was filed for: "fetch /incoming/*.csv" with no hand-rolled
    # listdir and no path arithmetic at the call site, which is where the `..`-in-a-name
    # mistake gets made.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    root = tmp_path / "remote"
    root.mkdir()
    build_glob_tree(root)
    destination = tmp_path / "local"
    destination.mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        aclosing(sftp.glob(os.fsencode(str(root)) + b"/**/*.csv")) as found,
    ):
        async for match in found:
            _ = await sftp.get(match.path, destination / os.fsdecode(match.name))

    assert sorted(p.name for p in destination.iterdir()) == [
        "a.csv",
        "c.csv",
        "d.csv",
        os.fsdecode(b"odd-\xff\xfe.csv"),
    ]
    assert (destination / "d.csv").read_bytes() == b"ddd"


async def test_nothing_matching_is_an_empty_result_rather_than_an_error():
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.parquet") == []
        # A directory in the middle of the pattern that does not exist matches nothing too.
        assert await matches(sftp, b"/root/absent/*.csv") == []


# --- the third state, for the half of the feature that has no wildcard in it -------------------
#
# D-102. `_glob_literal` caught `(NoSuchFileError, ServerError)` -- and `NoSuchFileError` *is* a
# `ServerError`, so the second element swallowed every other status. Both tests below passed
# vacuously before the fix, returning `[]`, and both fail against the code as it stood.
#
# The asymmetry that made it invisible: the wildcard branch (`_glob_listing`) has always been
# correct and documents refusing exactly this, so `glob("/closed/*.txt")` raised while
# `glob("/closed/secret.txt")` answered "no matches". Whether the caller's pattern happened to
# contain a `*` decided which answer they got, which is why both spellings are asserted here.


async def test_a_literal_pattern_does_not_report_permission_denied_as_no_match(tmp_path: Path):
    """A refusal to answer must not arrive as an answer of "there is nothing there".

    The consequence is the one `test_permission_denied_is_not_false` names for the predicates:
    a caller that reads an empty glob as absence creates over a file it could not see. For a
    mirror or a sync built on `glob`, it is a silently incomplete copy reported as a complete
    one -- the shape this library refuses everywhere else.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    closed = tmp_path / "closed"
    closed.mkdir()
    (closed / "secret.txt").write_bytes(b"payload")
    closed.chmod(0o000)
    try:
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            inside = os.fsencode(str(closed / "secret.txt"))

            with pytest.raises(PermissionDeniedError) as denied:
                _ = await matches(sftp, inside)
            assert denied.value.args[0] == "server returned PERMISSION_DENIED: Permission denied"
            assert denied.value.path == inside

            # The wildcard branch has always been right. Asserted beside it so the two halves
            # of one feature cannot drift apart again without a test noticing.
            with pytest.raises(PermissionDeniedError):
                _ = await matches(sftp, os.fsencode(str(closed)) + b"/*.txt")
    finally:
        closed.chmod(0o755)


async def test_a_literal_pattern_does_not_report_an_overlong_name_as_no_match(tmp_path: Path):
    """`ENAMETOOLONG` arrives as `BAD_MESSAGE`, which is a bare `ServerError`.

    The second status the old catch swallowed, and the one that shows the width of it: a
    `ServerError` that is *not* about existence at all reads as "matches nothing". `glob` has
    no `Skipped` channel, so nothing anywhere recorded that the question went unanswered.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    too_long = os.fsencode(str(tmp_path / ("n" * 4096)))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refused:
            _ = await matches(sftp, too_long)
        assert refused.value.args[0] == "server returned BAD_MESSAGE: Bad message"
        assert not isinstance(refused.value, NoSuchFileError)


async def test_a_literal_pattern_that_is_merely_absent_still_matches_nothing(tmp_path: Path):
    """The state the catch was right about, kept from being fixed away.

    `NO_SUCH_FILE` stays an empty result: a pattern matching nothing is the ordinary case, and
    a literal pattern is still a pattern. Narrowing the `except` must not turn that into an
    error -- which is the regression a fix for the two tests above would most plausibly cause.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await matches(sftp, os.fsencode(str(tmp_path / "absent.csv"))) == []

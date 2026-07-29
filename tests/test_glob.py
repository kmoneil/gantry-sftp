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

import os
from contextlib import aclosing
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gantry_sftp.exceptions import CapabilityError, UnsafePathError
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

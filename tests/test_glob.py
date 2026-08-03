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

from gantry_sftp.codec import OpenDir
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    PermissionDeniedError,
    ServerError,
    UnsafePathError,
)
from gantry_sftp.session import EntryKind, entry_kind, open_session
from gantry_sftp.session._glob import (
    _NAMED_CLASSES,
    RECURSIVE,
    has_magic,
    match_component,
    split_pattern,
    validate_pattern,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from test_recursive import DIRECTORY, REGULAR, SYMLINK, SparseAndRefusing, TreeServer, named

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
    # Both ends of a range are members. Every other row here matches something *inside* one,
    # which cannot tell an inclusive bound from an exclusive one.
    ("range-includes-its-low-end", b"[a-c]", b"a", True),
    ("range-includes-its-high-end", b"[a-c]", b"c", True),
    ("range-excludes-what-is-past-it", b"[a-c]", b"d", False),
    # Case is only folded when the caller asks. Three sites take that flag and each one is a
    # separate row, because a member, an escaped member and an escaped byte outside a bracket
    # are three calls.
    ("class-member-is-case-sensitive", b"[A]", b"a", False),
    ("class-escaped-member-is-case-sensitive", b"[\\A]", b"a", False),
    ("escaped-byte-is-case-sensitive", b"a\\Bc", b"abc", False),
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
    # The same trailing dash with something in front of the bracket. Whether the byte after the
    # `-` is the terminator has to be read *forward* from the member, and a bracket at offset 0
    # is the one position where reading backwards lands on the same answer by coincidence.
    ("trailing-dash-is-literal-after-a-prefix", b"x[a-]", b"xa", True),
    ("trailing-dash-after-a-prefix-still-matches-the-dash", b"x[a-]", b"x-", True),
    # A range whose high byte is missing entirely: an unterminated bracket, so a literal `[` by
    # this library's rule. Excluded from the differential below with the rest of divergence 3.
    ("unterminated-range-is-a-literal-bracket", b"[a-", b"[a-", True),
    # An escaped dash cannot open a range, so `[a\-c]` is three literals and not `a` to `c`.
    ("escaped-dash-does-not-open-a-range", b"[a\\-c]", b"b", False),
    ("escaped-dash-is-a-member", b"[a\\-c]", b"-", True),
    # An escape immediately before the `]` consumes it, so `[a\]` has no terminator and is a
    # literal `[` -- the backslash is not a member of anything. libc answers no-match here too.
    ("escape-at-the-end-of-a-bracket-consumes-the-close", b"[a\\]", b"\\", False),
    ("and-leaves-the-bracket-unterminated", b"[a\\]", b"a", False),
    # A backslash that ends the pattern *inside* a bracket: nothing left to escape, so it is
    # an ordinary member, and the bracket is unterminated -- the whole thing is a literal.
    # Both undefined divergences at once (unpaired trailing backslash, unterminated bracket),
    # so the fuzz excludes it twice over and this row is where the answer is written down.
    ("trailing-backslash-inside-a-bracket-is-literal", b"[a\\", b"[a\\", True),
    ("and-matches-neither-of-its-would-be-members", b"[a\\", b"a", False),
    # Negation still loses to the leading-period rule, which `glob(3)` applies and bare
    # `fnmatch(3)` does not -- the flag is `FNM_PERIOD`, and forgetting it makes libc look
    # like it disagrees with us when it is being asked a different question.
    ("negated-class-does-not-reach-a-dotfile", b"[!-/]", b".", False),
    ("negated-class-matches-otherwise", b"[!-/]", b"e", True),
    # The negation marker is consumed, and so is the `[` before it. Both rows are about a
    # bracket that does **not** start at offset 0, which is what makes "advance past the `!`"
    # distinguishable from "start the members at offset 1" -- they agree for `[!x]` and
    # disagree for everything after a prefix.
    ("negated-class-does-not-swallow-its-own-bang", b"log[!0-9]", b"log!", True),
    ("negated-class-does-not-swallow-its-own-bracket", b"log[!0-9]", b"log[", True),
    ("negated-class-does-not-swallow-the-prefix", b"log[!0-9]", b"logo", True),
    # --- POSIX character classes (D-106), every row checked against libc ---------------------
    #
    # One member and one non-member per name, which is what pins the *set* rather than the
    # recognizer; `test_every_character_class_is_the_set_libc_says_it_is` re-derives all twelve
    # byte for byte. `[[:digit:]]` is here because it is the spelling D-106 was filed over: it
    # works in `sftp(1)`, which globs through POSIX glob(3), and matched nothing here.
    ("class-alnum", b"[[:alnum:]]", b"7", True),
    ("class-alnum-misses", b"[[:alnum:]]", b"_", False),
    ("class-alpha", b"[[:alpha:]]", b"q", True),
    ("class-alpha-misses", b"[[:alpha:]]", b"7", False),
    ("class-blank", b"[[:blank:]]", b"\t", True),
    ("class-blank-misses-newline", b"[[:blank:]]", b"\n", False),
    ("class-cntrl", b"[[:cntrl:]]", b"\x7f", True),
    ("class-cntrl-misses", b"[[:cntrl:]]", b"a", False),
    ("class-digit", b"[[:digit:]]", b"7", True),
    ("class-digit-misses", b"[[:digit:]]", b"a", False),
    ("class-graph", b"[[:graph:]]", b"a", True),
    ("class-graph-misses-space", b"[[:graph:]]", b" ", False),
    ("class-lower", b"[[:lower:]]", b"a", True),
    ("class-lower-misses-upper", b"[[:lower:]]", b"A", False),
    ("class-print", b"[[:print:]]", b" ", True),
    ("class-print-misses-control", b"[[:print:]]", b"\x01", False),
    ("class-punct", b"[[:punct:]]", b"!", True),
    ("class-punct-misses-letter", b"[[:punct:]]", b"a", False),
    ("class-space", b"[[:space:]]", b"\n", True),
    ("class-space-misses", b"[[:space:]]", b"a", False),
    ("class-upper", b"[[:upper:]]", b"A", True),
    ("class-upper-misses-lower", b"[[:upper:]]", b"a", False),
    ("class-xdigit-upper-hex", b"[[:xdigit:]]", b"F", True),
    ("class-xdigit-misses", b"[[:xdigit:]]", b"g", False),
    # Nothing above 127 is in any class. That is the C locale's answer and it is also this
    # library's decision: a remote name is bytes of unstated encoding, so "is this byte a
    # letter" has no answer here -- glibc under Latin-1 says yes and under C says no.
    ("class-alpha-stops-at-ascii", b"[[:alpha:]]", b"\xff", False),
    ("class-print-stops-at-ascii", b"[[:print:]]", b"\xff", False),
    # A class is one member of a bracket expression, not the whole of it.
    ("class-beside-ordinary-members", b"[a[:digit:]z]", b"7", True),
    ("class-does-not-eat-its-neighbours", b"[a[:digit:]z]", b"a", True),
    ("class-neighbours-do-not-widen-it", b"[a[:digit:]z]", b"q", False),
    ("two-classes-in-one-bracket", b"[[:digit:][:upper:]]", b"A", True),
    ("two-classes-miss-together", b"[[:digit:][:upper:]]", b"a", False),
    ("class-is-negated-with-the-bracket", b"[![:digit:]]", b"a", True),
    ("class-negated-still-excludes", b"[![:digit:]]", b"7", False),
    ("class-negated-with-caret", b"[^[:digit:]]", b"a", True),
    # A class cannot be a range endpoint, so a `-` next to one is a literal member.
    ("dash-after-a-class-is-literal", b"[[:digit:]-z]", b"-", True),
    ("member-after-that-dash-still-counts", b"[[:digit:]-z]", b"z", True),
    ("that-dash-opens-no-range", b"[[:digit:]-z]", b"y", False),
    # The leading-period rule outranks a class, exactly as it outranks a range.
    ("class-does-not-reach-a-dotfile", b"[[:punct:]]", b".", False),
    ("negated-class-does-not-reach-one-either", b"[![:digit:]]", b".", False),
    # --- and the shapes that are *not* a class, which glibc decides by backing off -----------
    ("no-outer-bracket-is-an-ordinary-set", b"[:digit:]", b"d", True),
    ("no-outer-bracket-matches-no-digit", b"[:digit:]", b"7", False),
    ("unclosed-class-name-is-ordinary", b"[[:digit]", b"d", True),
    ("unclosed-class-name-matches-no-digit", b"[[:digit]", b"7", False),
    ("a-name-with-a-digit-in-it-is-not-a-name", b"[[:dig1t:]", b"1", True),
    ("an-uppercase-name-is-not-a-name", b"[[:DIGIT:]", b"D", True),
    ("an-escape-inside-the-name-breaks-it", b"[[:digit\\:]]", b"7", False),
    ("an-escaped-open-bracket-opens-nothing", b"[\\[:digit:]]", b"7", False),
    ("the-bracket-before-a-class-is-a-member", b"[[[:digit:]]", b"[", True),
    ("and-the-class-after-it-still-works", b"[[[:digit:]]", b"7", True),
    ("a-leading-close-bracket-precedes-a-class", b"[][:digit:]]", b"]", True),
    ("and-the-class-after-that-works-too", b"[][:digit:]]", b"7", True),
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

_LC_CTYPE = 0
"""glibc ``locale.h``. Not :mod:`locale`'s ``LC_CTYPE``, which is Python's own numbering."""


@pytest.fixture
def c_locale():
    """Ask libc its questions in the C locale, whatever the developer's environment is.

    Everything below compares against ``fnmatch(3)``, and **a character class is the one part
    of that comparison the locale can move**: ``[[:alpha:]]`` matches ``\\xff`` under an
    ISO-8859-1 locale and does not under C or C.UTF-8. This library's classes are ASCII-only by
    decision, so a suite that inherited ``LANG`` from the shell would pass here and fail on a
    machine set to Latin-1 -- the same shape as a test that reads the developer's real ssh
    config. Pinned rather than skipped, because the C locale is exactly the one whose answer
    this library implements.
    """
    fnmatch = _libc_fnmatch()
    if fnmatch is None:  # pragma: no cover -- platform without libc
        pytest.skip("libc fnmatch(3) is not reachable here")
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
    libc.setlocale.restype = ctypes.c_char_p
    libc.setlocale.argtypes = [ctypes.c_int, ctypes.c_char_p]
    # `restype = c_char_p` copies into a `bytes`, so this survives the call that replaces it.
    previous = libc.setlocale(_LC_CTYPE, None)
    libc.setlocale(_LC_CTYPE, b"C")
    try:
        yield fnmatch
    finally:
        libc.setlocale(_LC_CTYPE, previous)


# The alphabet is every byte that means something to the matcher, plus two ordinary ones and a
# byte above 127. `/` is excluded because a component never contains one -- `split_pattern`
# removes them before the matcher is ever called -- and NUL because it cannot cross `c_char_p`.
# `:` is in it so that `[:`-shaped patterns are reachable without a class ever being spelled --
# the back-off cases, which are where a recognizer written from the standard rather than from
# the implementation goes wrong.
_INTERESTING = st.sampled_from([bytes([b]) for b in b"*?[]!^-\\.:aA0\t \x01\xff"])
_FRAGMENT = st.lists(_INTERESTING, max_size=6).map(b"".join)

CLASS_NAMES = (
    b"alnum",
    b"alpha",
    b"blank",
    b"cntrl",
    b"digit",
    b"graph",
    b"lower",
    b"print",
    b"punct",
    b"space",
    b"upper",
    b"xdigit",
)
"""The twelve, written out here rather than imported, so the module under test cannot define
its own specification. A thirteenth name appearing in ``_glob.py`` and not here fails
``test_the_supported_class_names_are_exactly_the_posix_twelve``."""

# Patterns that can contain a whole class sub-expression. Assembling them from fragments rather
# than hoping arbitrary bytes spell `[[:digit:]]` -- which they will not, in any number of
# examples -- while still letting the fragments wrap, negate and neighbour them.
_SUB_EXPRESSION = st.sampled_from([b"[:" + name + b":]" for name in CLASS_NAMES])
_CLASS_FRAGMENT = st.lists(st.one_of(_INTERESTING, _SUB_EXPRESSION), max_size=6).map(b"".join)


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
        close = _bracket_close(pattern, i)
        if close == -1:
            return False
        i = close + 1
    return True


def _bracket_close(pattern: bytes, start: int) -> int:
    """Index of the ``]`` closing the bracket expression at ``start``, or ``-1``.

    A ``[:name:]`` sub-expression is stepped over whole, because **the ``]`` that ends the name
    is not the one that ends the bracket** -- without this, ``[[:digit:]`` looks terminated and
    an unterminated-bracket divergence reaches the differential as a spurious failure.
    """
    p = start + 1
    if pattern[p : p + 1] in (b"!", b"^"):
        p += 1
    if pattern[p : p + 1] == b"]":  # literal first member
        p += 1
    while p < len(pattern):
        if pattern[p : p + 2] == b"[:":
            end = pattern.find(b":]", p + 2)
            if end >= 0:
                p = end + 2
                continue
        if pattern[p : p + 1] == b"]":
            return p
        p += 1
    return -1


@settings(max_examples=500, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(pattern=_CLASS_FRAGMENT, name=_FRAGMENT)
def test_the_matcher_agrees_with_libc_on_arbitrary_patterns(c_locale, pattern: bytes, name: bytes):
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

    # The second divergence, and the only one where *libc* is the inconsistent party. An
    # unterminated `[` is undefined in POSIX. This matcher answers "a literal `[`" uniformly;
    # glibc answers that for `[abc` and no-match for `[*-`, so there is no single glob(3)
    # behaviour here to match. Ours is the documented choice and the one a caller who globbed
    # a filename containing a bracket expects. Terminated classes -- where the 23 survivors
    # this slice was about actually live -- are still fuzzed.
    assume(_every_class_is_terminated(pattern))

    # The third: a sub-expression this library refuses rather than answers -- see D-106 and
    # `test_a_class_name_that_does_not_exist_is_refused_rather_than_matching_nothing`. libc
    # answers "no match" to all of them, which is the silence being replaced. Caught rather
    # than excluded up front, because the *predicate* for "would this be refused" is the
    # parser under test; asserting the message keeps a matcher that refused everything from
    # passing this vacuously, and `class-digit` and its eleven siblings above would fail first.
    ours: bool | None = None
    refusal: str | None = None
    try:
        ours = match_component(pattern, name)
    except ValueError as exc:
        refusal = exc.args[0]
    if refusal is not None:
        assert "character class" in refusal or "are not supported" in refusal
        return

    assert ours is (c_locale(pattern, name, _FNM_PERIOD) == 0), f"pattern={pattern!r} name={name!r}"


def test_every_character_class_is_the_set_libc_says_it_is(c_locale):
    """All twelve classes, every byte, against ``fnmatch(3)`` rather than against a memory.

    The table in ``_glob.py`` is written out by hand -- ``bytes.isalpha`` and :mod:`string` are
    both statements about text, and ``"\\xff".isalpha()`` is ``True`` where this must be
    ``False`` -- so the table is exactly the kind of thing that is right when it is written and
    wrong after an edit. This re-derives all twelve from libc at run time.

    The subject is prefixed so that no row is decided by the leading-period rule instead: a
    bare ``.`` is punct, print and graph, and ``FNM_PERIOD`` would answer no-match for all
    three and make the comparison agree for the wrong reason.
    """
    for name in CLASS_NAMES:
        pattern = b"x[[:" + name + b":]]"
        for value in range(1, 256):  # NUL cannot cross `c_char_p`; asserted separately below
            subject = b"x" + bytes([value])
            expected = c_locale(pattern, subject, _FNM_PERIOD) == 0
            assert match_component(pattern, subject) is expected, (
                f"class {name!r} disagrees about byte {value:#04x}"
            )


def test_nul_is_a_control_character_and_is_in_no_other_class():
    # The one byte the differential above cannot ask libc about, since `c_char_p` terminates on
    # it -- and a byte a server can absolutely put in a name.
    for name in CLASS_NAMES:
        expected = name in (b"cntrl",)
        assert match_component(b"[[:" + name + b":]]", b"\x00") is expected


def test_the_supported_class_names_are_exactly_the_posix_twelve():
    # A thirteenth name is not a bug in itself, but it is a specification change, and the
    # dialect table, this list and `_NAMED_CLASSES` all have to learn about it together.
    assert sorted(_NAMED_CLASSES) == sorted(CLASS_NAMES)
    assert len(CLASS_NAMES) == 12


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
        # The first letter of each case, folded on its own rather than inside a range -- the
        # one byte an off-by-one at the bottom of the fold window would silently stop folding.
        (b"A", b"a", True),
        # Both ends of a range that only the *folded* comparison can satisfy: `a` and `z` are
        # outside `A`..`Z` as raw bytes, so these two rows are decided entirely by the second
        # half of the rule and pin its bounds.
        (b"[A-Z]", b"a", True),
        (b"[A-Z]", b"z", True),
        # Above 127 nothing is folded: the bytes are of an encoding the protocol never states,
        # so folding one would be folding a fragment of some character in a guessed encoding.
        (b"\xc3\x89", b"\xc3\xa9", False),
    ],
    ids=[
        "suffix",
        "stem",
        "upper-range",
        "lower-range",
        "single-letter",
        "folded-range-low-end",
        "folded-range-high-end",
        "non-ascii-is-never-folded",
    ],
)
def test_case_insensitive_matching_folds_ascii_and_nothing_else(
    pattern: bytes, name: bytes, expected: bool
):
    assert match_component(pattern, name, case_sensitive=False) is expected
    assert match_component(pattern, name) is (pattern == name)


@pytest.mark.parametrize("name", [b"A", b"_"], ids=["low-end", "high-end"])
def test_a_range_that_folds_backwards_is_still_matched_as_written(name: bytes):
    """Why the case-insensitive rule is two comparisons joined by ``or`` and not one.

    ``[A-_]`` spans ``A`` to ``_`` -- the uppercase letters plus five punctuation bytes -- and
    it **reverses when folded**, because ``A`` lowercases to ``a`` (0x61) while ``_`` (0x5f)
    has no other case. So the folded comparison answers no for every byte in it, and the
    pattern only keeps working because the range is *also* tried exactly as the caller wrote
    it. Both endpoints, since one comparison being inclusive is what is being asserted.
    """
    assert match_component(b"[A-_]", name, case_sensitive=False) is True
    assert match_component(b"[A-_]", name) is True


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
        # A trailing slash contributes an empty component and nothing else. The final `X` is
        # there because a trailing separator used to be removed with `rstrip(b"/")`, and a
        # strip set is a set of bytes rather than a suffix -- so a strip written with any other
        # byte in it ate part of the name it was meant to leave alone.
        (b"/logX/", (b"/logX", (), True)),
        # A pattern that is nothing but separator is still absolute, and the server agrees: it
        # answers `lstat("//")` with the root directory. Deciding this after the trailing
        # separators were trimmed decided it about `b""`, which is relative -- so `glob("//")`
        # resolved the root against the working directory and then matched nothing at all.
        (b"//", (b"/", (), True)),
        (b"///", (b"/", (), True)),
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
        "trailing-slash-strips-only-slashes",
        "two-separators-are-absolute",
        "three-separators-are-absolute",
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
        # No component to hold back, so the "never fold the last one into the prefix" rule has
        # nothing to do here and must not turn an empty split into a negative index.
        (b"//", (b"/", (), True)),
    ],
    ids=[
        "literal-file",
        "magic-is-unchanged",
        "literal-path",
        "relative-literal",
        "root",
        "two-separators-are-absolute",
    ],
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


# --- what this dialect refuses, and refuses out loud (D-106) ---------------------------------


def test_a_class_name_that_does_not_exist_is_refused_rather_than_matching_nothing():
    # The plural typo, which is the realistic way to write this wrong. `glob(3)` answers "no
    # match" here, and a nightly job that switched to this library would then transfer zero
    # files and report success -- the same partial-success shape `glob` already refuses when a
    # directory cannot be read. The message carries what was named, where, and the twelve names
    # to choose from, because "unknown character class" alone does not tell anyone what to type.
    with pytest.raises(ValueError) as excinfo:
        match_component(b"*.[[:digits:]]", b"report.7")
    assert excinfo.value.args[0] == (
        "unknown character class '[:digits:]' at offset 3 in glob pattern b'*.[[:digits:]]'; "
        "the POSIX character classes are: alnum, alpha, blank, cntrl, digit, graph, lower, "
        "print, punct, space, upper, xdigit"
    )


def test_an_empty_class_name_is_refused_as_an_unknown_one():
    # `[[::]]` reads as a sub-expression whose name is the empty string. glibc treats it as a
    # class it does not know and answers no-match; there is one rule here rather than two.
    with pytest.raises(ValueError) as excinfo:
        match_component(b"[[::]]", b":")
    assert excinfo.value.args[0].startswith("unknown character class '[::]' at offset 1")


def test_a_class_name_containing_z_is_read_as_a_name_rather_than_backed_off():
    """glibc's own recognizer stops at ``z``, and this deliberately does not.

    ``fnmatch_loop.c`` abandons the sub-expression on any name byte outside ``a`` to ``y`` --
    the condition is ``c < 'a' || c >= 'z'`` -- so glibc reads ``[[:zzz:]]`` as the ordinary
    set ``{[, :, z}`` and matches ``z``. None of the twelve POSIX names contains a ``z``, so
    the quirk is invisible for every valid pattern, and copying it would mean a *misspelled*
    class silently becoming a set whenever the typo happened to contain one letter.
    """
    with pytest.raises(ValueError) as excinfo:
        match_component(b"[[:zzz:]]", b"z")
    assert excinfo.value.args[0].startswith("unknown character class '[:zzz:]' at offset 1")


def test_an_equivalence_class_is_refused_with_the_reason_and_a_remedy():
    # Not implemented and not silently mismatched. `[[=a=]]` *works* in `sftp(1)` -- it matches
    # `a` -- and here it would otherwise be read as the ordinary set `{[, =, a}` followed by a
    # literal `]`, which is a different pattern that happens to parse.
    with pytest.raises(ValueError) as excinfo:
        match_component(b"[[=a=]]", b"a")
    assert excinfo.value.args[0] == (
        "equivalence classes are not supported in a glob pattern: '[=a=]' at offset 1 in "
        "b'[[=a=]]'. They are defined by the locale's collation table, and a remote name is "
        "bytes of unstated encoding -- this library will not choose a locale for it. "
        "Instead, spell the members out, as in [aA]."
    )


def test_an_equivalence_class_is_delimited_by_its_first_close_and_may_be_empty():
    # Two properties of the scan, in the two spellings that separate it from the plausible
    # wrong ones: it must stop at the *first* `=]` rather than the last, and it must accept a
    # close that lands immediately after the marker. The message is what carries both, since
    # the refusal itself is the same either way.
    with pytest.raises(ValueError) as first:
        match_component(b"[[=a=]x=]]", b"a")
    assert first.value.args[0].startswith("equivalence classes are not supported")
    assert "'[=a=]'" in first.value.args[0]

    with pytest.raises(ValueError) as empty:
        match_component(b"[[==]]", b"=")
    assert empty.value.args[0].startswith("equivalence classes are not supported")
    assert "'[==]'" in empty.value.args[0]


def test_a_collating_symbol_is_refused_the_same_way():
    with pytest.raises(ValueError) as excinfo:
        match_component(b"[[.a.]]", b"a")
    assert excinfo.value.args[0] == (
        "collating symbols are not supported in a glob pattern: '[.a.]' at offset 1 in "
        "b'[[.a.]]'. They are defined by the locale's collation table, and a remote name is "
        "bytes of unstated encoding -- this library will not choose a locale for it. "
        "Instead, write the character itself, as in [a]."
    )


@pytest.mark.parametrize(
    "pattern",
    [b"[[=]", b"[[.]", b"[[=a]", b"[[.a]", b"[a[=b]"],
    ids=["equals-alone", "dot-alone", "unclosed-equals", "unclosed-dot", "equals-mid-set"],
)
def test_an_unclosed_locale_sub_expression_is_an_ordinary_set_rather_than_a_refusal(
    pattern: bytes,
):
    # The refusal is for the sub-expression, not for the two bytes that could start one. `[[=]`
    # is the perfectly ordinary set `{[, =}`, and refusing it would turn a working pattern into
    # an error -- the failure mode the "refuse them loudly" option was rejected for. Every row
    # has `[` as a member, which is the byte the back-off puts there.
    assert match_component(pattern, b"[") is True
    validate_pattern(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        b"/incoming/*.[[:digits:]]",
        b"/incoming/[[=a=]]",
        b"/incoming/[[.a.]]",
        b"[[:digits:]]",
        b"\\*[[=a=]]",
        b"x[[:digits:]]",
        b"[abc][[:digits:]]",
        b"[a-z][[:digits:]]",
    ],
    ids=[
        "unknown-class",
        "equivalence",
        "collating",
        "relative",
        "after-an-escape",
        # The walk must inspect *every* byte, not every other one: a bad class one byte in is
        # missed by a scan that strides.
        "at-an-odd-offset",
        # And it must keep walking after a bracket expression that was fine, rather than
        # stopping at the first one it understood.
        "after-a-good-bracket",
        # Same, with a range in the good bracket -- the member shape that needs a real byte to
        # compare against, so a walk that passes something that is not one raises here first.
        "after-a-range",
    ],
)
def test_validate_pattern_finds_a_refusal_with_no_name_to_match_it_against(pattern: bytes):
    # The reason `glob` cannot rely on the matcher raising: a refusal reached through matching
    # needs an entry to be raised against, so the same broken pattern would raise over a
    # directory with files in it and answer "no matches" over an empty one.
    with pytest.raises(ValueError):
        validate_pattern(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        b"",
        b"*",
        b"/incoming/*.[[:digit:]]",
        b"[:digit:]",
        b"[[:digit]",
        b"[",
        b"[[",
        b"[[:",
        b"[[:digit:]",
        b"\\[[:zzz:]]",
        b"a\\",
        b"[]]",
        b"[!]a]",
        b"[a-z]",
        b"x[a-z]y[0-9]z",
    ],
    ids=[
        "empty",
        "star",
        "a-real-class",
        "no-outer-bracket",
        "unclosed-class-name",
        "lone-bracket",
        "two-brackets",
        "bracket-colon",
        "class-with-no-closing-bracket",
        "escaped-bracket-hides-the-class",
        "trailing-backslash",
        "close-bracket-first",
        "negated-close-bracket-first",
        # A range: the one member shape whose comparison is arithmetic rather than equality,
        # so a walk that hands the parser something that is not a byte fails here and nowhere
        # else. Without this row the validator could be walking with `None` and nothing says so.
        "a-range",
        "two-ranges-and-ordinary-bytes",
    ],
)
def test_validate_pattern_accepts_everything_the_matcher_will_answer(pattern: bytes):
    # The validator drives the matcher's own bracket parser, so this is the property that keeps
    # the two from drifting: anything it accepts, the matcher answers without raising. The
    # `\[[:zzz:]]` row is the one that would break under a naive `pattern.find(b"[[:")` scan --
    # the `[` is escaped, so what follows is the ordinary set `{[, :, z}` and not a class.
    validate_pattern(pattern)
    assert match_component(pattern, b"x") in (True, False)
    assert match_component(pattern, b"") in (True, False)


@settings(max_examples=400, deadline=None)
@given(pattern=_CLASS_FRAGMENT)
def test_validate_pattern_and_the_matcher_refuse_exactly_the_same_patterns(pattern: bytes):
    # Both walk `_scan_class`, and this is what says so. A pattern the validator passes must
    # never raise from matching -- that direction is the one with a user behind it, because the
    # refusal would then arrive mid-iteration, after entries had already been yielded.
    try:
        validate_pattern(pattern)
    except ValueError:
        return
    for name in (b"", b"x", b"7", b".hidden", b"\xff"):
        assert match_component(pattern, name) in (True, False)


@pytest.mark.parametrize(
    ("pattern", "name", "expected"),
    [
        (b"[[:upper:]]", b"a", True),
        (b"[[:lower:]]", b"A", True),
        (b"[[:alpha:]]", b"A", True),
        (b"[[:digit:]]", b"7", True),
        (b"[[:digit:]]", b"a", False),
        (b"[![:upper:]]", b"a", False),
        (b"[[:punct:]]", b"!", True),
        # The *last* letter of each range. The first two rows already cover `A` and `a`; `Z`
        # and `z` are where an exclusive bound hides, and swapping case for `A`..`Y` and
        # `a`..`y` only passes every test written with `a` in it -- which is every obvious one.
        (b"[[:lower:]]", b"Z", True),
        (b"[[:upper:]]", b"z", True),
    ],
    ids=[
        "upper-reaches-lower",
        "lower-reaches-upper",
        "alpha",
        "digit",
        "digit-misses",
        "negated",
        "caseless-punct",
        "lower-reaches-the-last-upper",
        "upper-reaches-the-last-lower",
    ],
)
def test_a_character_class_folds_case_the_way_a_range_does(
    pattern: bytes, name: bytes, expected: bool
):
    # `[A-Z]` matches `a` under `case_sensitive=False` because `_in_range` folds both ends. A
    # class is a set rather than a pair of endpoints, so the same rule has to be spelled the
    # other way -- ask whether *either* case of the subject is in the set. Folding only the
    # subject gets `[[:lower:]]` against `A` right and `[[:upper:]]` against `a` wrong, which
    # is a bug that half the obvious tests would miss.
    assert match_component(pattern, name, case_sensitive=False) is expected


def test_a_backslash_does_not_make_a_component_magic():
    # It only escapes, so `a\b` still names exactly one file and can take the literal path.
    assert not has_magic(b"a\\b")
    assert has_magic(b"a*b")
    assert has_magic(b"a?b")
    assert has_magic(b"a[b")


# --- the matcher must not be fuzzable to a hang ----------------------------------------------


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(pattern=st.binary(max_size=40), name=st.binary(max_size=200))
def test_matching_arbitrary_bytes_terminates_and_answers_or_refuses(pattern: bytes, name: bytes):
    # A file-transfer library matching hostile server names against a caller's pattern must not
    # be reducible to a crash or a hang. The matcher is deliberately not a compiled regular
    # expression: `*a*a*a*a*b` translated to `.*a.*a.*a.*a.*b` backtracks catastrophically on a
    # long name, and the name is the half the *peer* chooses.
    #
    # This said "never raises" until D-106, and the rename is the honest half of that change:
    # a pattern naming a character class that does not exist is now refused rather than
    # silently matching nothing. `ValueError` is the only exception in the total function's
    # range, and the test below proves the *name* can never be what puts it there.
    answer: object = None
    refusal: str | None = None
    try:
        answer = match_component(pattern, name)
    except ValueError as exc:
        refusal = exc.args[0]
    assert answer in (True, False) or (refusal is not None and "glob pattern" in refusal)


@settings(max_examples=300, deadline=None)
@given(name=st.binary(max_size=200))
def test_no_name_can_make_a_valid_pattern_refuse(name: bytes):
    # The half that matters for a hostile peer: refusals are a property of the *pattern*, so a
    # server cannot reach one by choosing a name. If it could, a single malicious entry would
    # take down a `glob` over a directory rather than simply not matching.
    for pattern in (b"*", b"[[:digit:]]", b"*[[:alpha:]]*", b"[![:space:]]", b"[a[:punct:]-]"):
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


async def test_a_character_class_matches_through_a_real_traversal():
    # The spelling D-106 was filed over, end to end: `sftp(1)` globs client-side through POSIX
    # `glob(3)`, so `get *.[[:digit:]]` works there, and until this change it matched nothing
    # here -- silently, and indistinguishably from the directory being empty.
    tree = {
        b"/root": (
            named(b"log.1", REGULAR, 3),
            named(b"log.2", REGULAR, 3),
            named(b"log.old", REGULAR, 3),
            named(b"LOG.3", REGULAR, 3),
        )
    }
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*.[[:digit:]]") == [
            b"/root/log.1",
            b"/root/log.2",
            b"/root/LOG.3",
        ]
        assert await matches(sftp, b"/root/[[:upper:]]*") == [b"/root/LOG.3"]
        assert await matches(sftp, b"/root/*.[![:digit:]]*") == [b"/root/log.old"]


async def test_an_unknown_class_is_refused_over_an_empty_directory_too():
    # The whole argument for validating up front. A refusal that needed an entry to be raised
    # against would answer "no matches" here and raise over the same pattern one file later:
    # two opposite answers to one broken pattern, decided by what the server happens to hold,
    # and the silent one arriving exactly when there is least evidence anything is wrong.
    server = TreeServer(tree={b"/root": ()})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        before = len(server.seen)
        with pytest.raises(ValueError) as excinfo:
            await matches(sftp, b"/root/*.[[:digits:]]")
        assert excinfo.value.args[0].startswith("unknown character class '[:digits:]'")
        # And it costs no round trip: nothing was asked of the server between the two lines.
        assert len(server.seen) == before


async def test_a_refused_pattern_is_refused_before_the_directory_is_opened():
    # The same over a directory that *does* have entries, which is where a matcher-level
    # refusal would raise -- but only after `OPENDIR` and a `READDIR`, so a server that logs
    # would have recorded a listing for a pattern this library was never going to honour.
    server = TreeServer(tree=GLOB_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        for pattern in (b"/root/[[=a=]]", b"/root/[[.a.]]", b"/root/[[:alphabet:]]"):
            with pytest.raises(ValueError):
                await matches(sftp, pattern)
        assert not [packet for packet in server.seen if isinstance(packet, OpenDir)]


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


async def test_a_literal_pattern_synthesises_an_entry_with_no_longname():
    """There was no listing to take one from, and `DirEntry.longname` is `bytes` (D-105 s28).

    `None` would be a type the rest of the surface does not expect, and any other placeholder
    would look like something the server said. The wildcard half carries the server's real
    `longname`, which is what makes the two distinguishable at all.
    """
    server = TreeServer(tree=GLOB_TREE, files={b"/root/a.csv": b"aaa"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        async with aclosing(sftp.glob(b"/root/a.csv")) as found:
            literal = [match async for match in found]
        async with aclosing(sftp.glob(b"/root/*.csv")) as found:
            listed = [match async for match in found]

    assert [match.entry.longname for match in literal] == [b""]
    assert [match.entry.filename for match in literal] == [b"a.csv"]
    # The same file through the matching path does carry one, so `b""` is a decision here
    # rather than what this server happens to send.
    assert listed[0].entry.longname != b""


async def test_a_literal_pattern_reports_a_symlink_as_a_symlink(tmp_path: Path):
    """The literal path uses `LSTAT`, matching what every other component does.

    Following it would make a link answer as whatever it points at, so the two halves of
    `glob` would disagree about what a link is -- decided by whether the caller's pattern
    happened to contain a `*`. That is the divergence D-102 was filed for, one field over.

    Against the real server because the scripted one answers `LSTAT` for entries it holds
    rather than for every name it listed, so the literal route cannot reach a link there.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    target = tmp_path / "data.csv"
    target.write_bytes(b"aaa")
    (tmp_path / "alias").symlink_to(target)
    prefix = os.fsencode(str(tmp_path))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        aclosing(sftp.glob(prefix + b"/alias")) as found,
    ):
        got = [match async for match in found]

    assert [match.path for match in got] == [prefix + b"/alias"]
    assert entry_kind(got[0].entry.attrs) is EntryKind.SYMLINK


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


async def test_case_folding_survives_the_descent_into_a_subdirectory():
    """Every option test above matches at the *top* level, which never forwards anything.

    `GlobRunner.match_in`, `GlobRunner.descend` and `GlobRunner.recursive` each hand the three
    options to the next level down, and each forward could be dropped or nulled with every
    existing test green --
    because a pattern with one component never gets there. `case_sensitive=None` is falsy, so
    the mutation makes the *nested* level fold when the caller asked it not to (D-105 slice 26).
    """
    tree = {
        b"/root": (named(b"SUB", DIRECTORY),),
        b"/root/SUB": (named(b"REPORT.CSV", REGULAR, 3),),
    }
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        # Both components matched against a listing, one level apart, and both folded.
        assert await matches(sftp, b"/root/*/*.csv", case_sensitive=False) == [
            b"/root/SUB/REPORT.CSV"
        ]
        # And the default reaches the nested level too, which is the half a dropped forward
        # would silently satisfy: nothing here may match when the caller did not ask to fold.
        assert await matches(sftp, b"/root/*/*.csv") == []

        # Not a gap: `case_sensitive=False` folds the *names it matches*, and the literal
        # directory prefix is used as typed -- `split_pattern` says so and the live test that
        # found it is cited there. So a nested literal stays unfolded, deliberately.
        assert await matches(sftp, b"/root/sub/*.csv", case_sensitive=False) == []
        assert await matches(sftp, b"/root/SUB/*.csv", case_sensitive=False) == [
            b"/root/SUB/REPORT.CSV"
        ]


async def test_a_directory_only_pattern_stays_directory_only_after_descending():
    """The trailing `/` is decided once, at the top, and has to reach every level below it."""
    tree = {
        b"/root": (named(b"sub", DIRECTORY),),
        b"/root/sub": (named(b"inner", DIRECTORY), named(b"c.csv", REGULAR, 5)),
    }
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        # `inner` is a directory and `c.csv` is not, one level below where the flag was read.
        assert await matches(sftp, b"/root/*/*/") == [b"/root/sub/inner"]
        assert await matches(sftp, b"/root/*/*") == [b"/root/sub/inner", b"/root/sub/c.csv"]


async def test_max_depth_survives_a_descent_before_the_recursive_component():
    """`max_depth` is forwarded twice over and every existing case starts `**` at the root.

    With the bound dropped on the way down, a pattern whose `**` begins *below* a literal
    component descends without limit -- which is the hostile-server case the bound exists for,
    reachable only after at least one descent.
    """
    tree = {
        b"/root": (named(b"sub", DIRECTORY),),
        b"/root/sub": (named(b"a.csv", REGULAR, 3), named(b"deeper", DIRECTORY)),
        b"/root/sub/deeper": (named(b"b.csv", REGULAR, 3), named(b"deepest", DIRECTORY)),
        b"/root/sub/deeper/deepest": (named(b"c.csv", REGULAR, 3),),
    }
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/sub/**/*.csv", max_depth=0) == [b"/root/sub/a.csv"]
        assert await matches(sftp, b"/root/sub/**/*.csv", max_depth=1) == [
            b"/root/sub/a.csv",
            b"/root/sub/deeper/b.csv",
        ]
        assert await matches(sftp, b"/root/sub/**/*.csv") == [
            b"/root/sub/a.csv",
            b"/root/sub/deeper/b.csv",
            b"/root/sub/deeper/deepest/c.csv",
        ]

        # And again with a *wildcard* before the `**`, which is a different route through the
        # same forwards: a literal prefix enters `GlobRunner.match_in` with `**` already at
        # the head, so `GlobRunner.descend` is never on the path and its own forward of the
        # bound goes untested.
        assert await matches(sftp, b"/root/*/**/*.csv", max_depth=0) == [b"/root/sub/a.csv"]
        assert await matches(sftp, b"/root/*/**/*.csv", max_depth=1) == [
            b"/root/sub/a.csv",
            b"/root/sub/deeper/b.csv",
        ]


async def test_the_bound_reaches_a_second_recursive_component():
    """`GlobRunner.recursive` consumes `max_depth` in its own `walk` *and* forwards it (D-105 s28).

    The forwarded copy only matters when what is left contains another `**`, so a pattern with
    two of them is the only shape that can see it. Dropped, the inner one descends without
    limit while the outer one is bounded -- which is the bound not holding, in the one pattern
    where a hostile server has two chances to be infinite.

    The duplicates are real and are pinned rather than glossed: two recursive components each
    expand, so a path reachable both ways is reported both ways. Observed, not fixed -- `**/**`
    is a pathological spelling of `**` and no caller has asked for it.
    """
    tree = {
        b"/root": (named(b"a.csv", REGULAR, 3), named(b"sub", DIRECTORY)),
        b"/root/sub": (named(b"b.csv", REGULAR, 3), named(b"deeper", DIRECTORY)),
        b"/root/sub/deeper": (named(b"c.csv", REGULAR, 3), named(b"deepest", DIRECTORY)),
        b"/root/sub/deeper/deepest": (named(b"d.csv", REGULAR, 3),),
    }
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/**/**/*.csv", max_depth=0) == [b"/root/a.csv"]
        # One level from the root for the outer `**`, and one more from each place it reached
        # for the inner one -- so `deeper/c.csv` appears and `deepest/d.csv` does not.
        assert await matches(sftp, b"/root/**/**/*.csv", max_depth=1) == [
            b"/root/a.csv",
            b"/root/sub/b.csv",
            b"/root/sub/b.csv",
            b"/root/sub/deeper/c.csv",
        ]


async def test_a_directory_only_pattern_stays_directory_only_through_a_recursive_component():
    """The third route for the same flag, and the one `**` takes.

    `GlobRunner.match_in` hands `directories_only` to `GlobRunner.recursive`, which hands it
    back to `GlobRunner.match_in` for the components below -- two more forwards, neither
    reachable by a pattern whose only
    magic is a plain wildcard.
    """
    tree = {
        b"/root": (named(b"sub", DIRECTORY),),
        b"/root/sub": (named(b"a.csv", REGULAR, 3), named(b"deeper", DIRECTORY)),
        b"/root/sub/deeper": (named(b"b.csv", REGULAR, 3), named(b"deepest", DIRECTORY)),
        b"/root/sub/deeper/deepest": (named(b"c.csv", REGULAR, 3),),
    }
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        # Directories at every level and no files anywhere, which is the whole difference.
        assert await matches(sftp, b"/root/**/") == [
            b"/root/sub",
            b"/root/sub/deeper",
            b"/root/sub/deeper/deepest",
        ]
        assert await matches(sftp, b"/root/**") == [
            b"/root/sub",
            b"/root/sub/a.csv",
            b"/root/sub/deeper",
            b"/root/sub/deeper/b.csv",
            b"/root/sub/deeper/deepest",
            b"/root/sub/deeper/deepest/c.csv",
        ]
        # Through a wildcard first, so the flag crosses `GlobRunner.descend` as well.
        assert await matches(sftp, b"/root/*/**/") == [
            b"/root/sub/deeper",
            b"/root/sub/deeper/deepest",
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


async def test_a_pattern_that_is_all_separator_names_the_root_the_way_the_server_does(
    tmp_path: Path,
):
    # The bug the mutation lane's `rstrip(b"/")` -> `rstrip(None)` survivor pointed at, and it
    # needed a real server to be worth anything: the claim is that `//` and `///` name the same
    # directory to `sftp-server` as `/` does, which no fake of ours can establish. Absoluteness
    # used to be decided about the pattern *after* its trailing separators were trimmed, so a
    # pattern that is nothing but separator trimmed down to `b""`, was called relative, and was
    # resolved against the working directory -- `glob("/")` answered the root and `glob("//")`
    # answered nothing, which is this module's own "no matches when I mean I could not look"
    # in the one place it was not looking for it.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        # The server's own answer first, so the assertions below are pinned to what it holds
        # rather than to what this file believes about POSIX pathname resolution.
        root = await sftp.lstat(b"/")
        assert (await sftp.lstat(b"//")).permissions == root.permissions
        assert (await sftp.lstat(b"///")).permissions == root.permissions

        assert await matches(sftp, b"/") == [b"/"]
        assert await matches(sftp, b"//") == [b"/"]
        assert await matches(sftp, b"///") == [b"/"]
        assert await matches(sftp, b"//", case_sensitive=False) == [b"/"]


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
# D-102. `GlobRunner.literal` caught `(NoSuchFileError, ServerError)` -- and `NoSuchFileError`
# *is* a `ServerError`, so the second element swallowed every other status. Both tests below passed
# vacuously before the fix, returning `[]`, and both fail against the code as it stood.
#
# The asymmetry that made it invisible: the wildcard branch (`GlobRunner.listing`) has always been
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


def build_class_tree(root: Path) -> None:
    """Three one-character stems: a letter, a digit, and a byte in no class at all.

    A plain function rather than inline, so the async test below does no filesystem work in an
    async frame -- which is what ASYNC240 is for.
    """
    (root / "a.log").write_bytes(b"ascii")
    (root / "7.log").write_bytes(b"digit")
    # Not valid UTF-8, legal on ext4, and the byte whose membership a locale would decide.
    (root / os.fsdecode(b"\xff.log")).write_bytes(b"not utf-8")


async def test_a_character_class_is_ascii_only_against_names_a_real_server_listed(
    tmp_path: Path,
):
    """The ASCII-only decision where it can actually be observed: names off a real ``READDIR``.

    `TreeServer` returns the names its author typed, so a class that quietly folded a
    high byte into ``[[:alpha:]]`` would look the same there. Here the filenames exist on
    disk, the server enumerated them, and ``\\xff.log`` is a name a drop directory really can
    hold -- if the matcher asked a locale rather than answering ASCII-only, that entry would
    move in and out of the result set with the machine's ``LANG``.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    root = os.fsencode(str(tmp_path))
    build_class_tree(tmp_path)

    # Sorted, because `READDIR` order is the server's and this is not a test about ordering.
    async def found(pattern: bytes) -> list[bytes]:
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            return sorted(await matches(sftp, pattern))

    assert await found(root + b"/[[:alpha:]].log") == [root + b"/a.log"]
    assert await found(root + b"/[[:digit:]].log") == [root + b"/7.log"]
    # `\xff` is in no class at all, so only a pattern that does not ask the question reaches it.
    assert await found(root + b"/[[:print:]].log") == sorted([root + b"/a.log", root + b"/7.log"])
    assert await found(root + b"/?.log") == sorted(
        [root + b"/a.log", root + b"/7.log", root + b"/\xff.log"]
    )


# --- D-103: the fourth way a glob can be told nothing --------------------------------------
#
# The three above are the literal stat, the listing, and the pattern validator, and each one
# documents the same rule: only `NO_SUCH_FILE` is swallowed, because a glob answering "no
# matches" when it means "I was not allowed to look" is a partial success wearing a complete
# one's clothes. The fourth is the `LSTAT` that settles an entry's *kind*, and it swallowed
# every `ServerError` into `EntryKind.UNKNOWN`, which `GlobRunner.is_directory` then read as "not a
# directory".
#
# Why no test caught it and no lane could: OpenSSH always sends permission bits, so a real
# `sftp-server` never reaches the settling stat at all. It is reachable only on a server that
# omits them -- DESIGN §7's appliance class -- which is why these two are the only tests in this
# file below the real-server line that use a fake, and why that is stated rather than papered
# over.


SPARSE_TREE = {
    # `None` is a listing entry with no attributes: the server said the name and nothing else.
    b"/root": (named(b"mystery", None), named(b"sub", DIRECTORY)),
    b"/root/sub": (named(b"c.csv", REGULAR, 5),),
    # A real directory with a real match under it, so what the swallow loses is a loss.
    b"/root/mystery": (named(b"secret.csv", REGULAR, 9),),
}

VANISHING_TREE = {
    # Same listing, and `/root/mystery` is not a path this server has: the name was in the
    # listing and the settling LSTAT answers NO_SUCH_FILE, which is the race rather than a
    # refusal.
    b"/root": (named(b"mystery", None), named(b"sub", DIRECTORY)),
    b"/root/sub": (named(b"c.csv", REGULAR, 5),),
}


async def test_a_refused_settling_stat_does_not_silently_shorten_a_glob():
    """The descend site. Without the fix this returns `/root/sub/c.csv` and stops.

    Nothing is raised, nothing is logged as a skip, and the caller gets a shorter list that is
    indistinguishable from `/root/mystery` having held no matching files -- while the entry that
    was not searched is the one the server declined to describe, which on a real endpoint is
    exactly where the interesting files are.
    """
    server = SparseAndRefusing(tree=SPARSE_TREE, denied=b"/root/mystery")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(PermissionDeniedError) as denied:
            _ = await matches(sftp, b"/root/*/*.csv")

    assert denied.value.args[0] == "server returned PERMISSION_DENIED: Permission denied"
    assert denied.value.path == b"/root/mystery"


async def test_a_refused_settling_stat_does_not_silently_drop_a_directory_only_match():
    """The second site, and the one that loses the *match* rather than what is under it.

    A trailing `/` restricts a pattern to directories, so it asks about kind for every entry it
    matched -- which makes it the spelling most likely to reach this. Without the fix
    `/root/mystery` is absent from the result and the result reports success.
    """
    server = SparseAndRefusing(tree=SPARSE_TREE, denied=b"/root/mystery")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(PermissionDeniedError) as denied:
            _ = await matches(sftp, b"/root/*/")

    assert denied.value.args[0] == "server returned PERMISSION_DENIED: Permission denied"
    assert denied.value.path == b"/root/mystery"


async def test_a_stat_that_answers_without_a_type_is_refused_rather_than_read_as_no():
    """The fifth state, and the likelier one on the servers that reach any of this.

    A server that omits permission bits from a *listing* probably omits them from a `STAT` too,
    so the entry arrives settled to `UNKNOWN` rather than refused -- narrowing the `except`
    alone would have fixed the rarer half and left this one silent. `isdir` reached the same
    fork and refuses, and `_kind_is`'s docstring names this consequence by name: "the reason
    recursive downloads silently skip directories on some servers".
    """
    server = TreeServer(tree=SPARSE_TREE, opaque={b"/root/mystery"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        for pattern in (b"/root/*/*.csv", b"/root/*/"):
            with pytest.raises(CapabilityError) as refused:
                _ = await matches(sftp, pattern)
            assert refused.value.args[0] == (
                "glob() cannot be answered for b'/root/mystery': the server returned "
                "attributes with no permission bits, and filexfer v3 carries the file type "
                "in those bits, so there is nothing here to classify. Returning False would "
                "report a definite 'no' for a question the server did not answer. Call "
                "stat() or lstat() and decide from Attrs.permissions, or use walk(), which "
                "reports an entry it cannot settle as skipped rather than guessing"
            )
            assert refused.value.path == b"/root/mystery"


async def test_an_entry_that_vanished_between_the_listing_and_the_stat_matches_nothing():
    """The state the swallow was right about, kept from being fixed away.

    `NO_SUCH_FILE` from the settling stat is a race with whoever else writes that directory, and
    a path that is not there matches nothing -- the same answer a name that does not match gets.
    This is the regression the narrowing would most plausibly cause, and it is asserted at both
    sites: the plain `TreeServer` answers `NO_SUCH_FILE` for a name it never had.
    """
    server = TreeServer(tree=VANISHING_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await matches(sftp, b"/root/*/*.csv") == [b"/root/sub/c.csv"]
        assert await matches(sftp, b"/root/*/") == [b"/root/sub"]


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

"""Glob pattern matching over remote names, and the traversal that drives it.

**Two halves, and the split between them is the point.** Everything above
:class:`GlobRunner` is pure: bytes in, a verdict out, no I/O and no session. :class:`GlobRunner`
is the traversal, and it reaches a server only through five callables it is handed, so it too
runs with no transport and no server behind it. The matcher was always the easy half to test;
D-128 moved the traversal here so it is the easy half as well, and so a change to globbing is
made in the file that is only about globbing.

The matcher is **deliberately not ``fnmatch``**.

**The dialect is `glob(3)`, because that is what the reference client uses.** `sftp(1)` globs
*client-side*: `sftp-glob.c` hands POSIX ``glob(3)`` its own ``opendir``/``readdir``/``lstat``
through ``GLOB_ALTDIRFUNC`` and lets libc do the matching. So the pattern language a user
already has in their fingers is ``glob(3)``'s, and matching this library to it is not a
preference -- it is the same rule that decided the zero-count ``NAME`` question: where the
written spec and the reference implementation disagree, the one that was *run* binds.

That rules out reaching for :mod:`fnmatch`, which differs in three ways that each produce a
wrong answer rather than a different style:

- **``*`` crosses ``/`` in fnmatch.** ``fnmatch.fnmatchcase(b"a/b.csv", b"*.csv")`` is ``True``.
  A pattern is therefore split into components here and each is matched on its own; a component
  never sees a separator.
- **fnmatch matches a leading dot.** ``glob(3)`` requires a period at the start of a name to be
  matched *explicitly*, which is why ``ls *`` does not list your dotfiles. Getting this wrong
  means ``glob("/incoming/*")`` silently sweeps up ``.hidden`` and any half-written
  ``.staging`` file -- including the ones this library's own atomic publish creates.
- **fnmatch has no escaping.** `sftp(1)` passes no ``GLOB_NOESCAPE``, so a backslash escapes the
  next character there and must here.

**No regular expression is built, and that is a security decision rather than a style one.**
Translating a glob to a regex turns ``*a*a*a*a*b`` into a pattern that backtracks
catastrophically, and the strings being matched are **server-supplied names of
attacker-chosen length**. The matcher below is the classic two-pointer algorithm with a single
backtrack point: O(len(pattern) x len(name)) worst case, constant memory, no recursion, and
nothing to blow up.

**Character classes are supported and are ASCII-only** (D-106). ``[[:digit:]]``,
``[[:alpha:]]`` and the other ten POSIX names match what ``glob(3)`` matches *in the C locale*,
and nothing above 127 is in any of them. That limit is the same decision as ASCII-only case
folding and it is taken for the same reason: a remote name is bytes whose encoding the protocol
does not state, so asking whether byte ``0xff`` is a letter is asking a question that has no
answer here. glibc in a Latin-1 locale says it is; glibc in the C locale says it is not; the
server never said which one it meant. Declining to guess is the only answer that is the same on
every machine this library runs on.

**What is deliberately not supported**, each with its reason:

- **Brace expansion** (``{a,b}``). `sftp(1)` passes ``GLOB_BRACE`` for ``ls`` and *not* for
  ``get`` or ``put``, so the reference client is inconsistent with itself; it is a BSD/glibc
  extension rather than POSIX. Supporting it would mean picking which half of `sftp(1)` to
  agree with.
- **Tilde expansion** (``~``, ``~user``). That is a server-side operation
  (``expand-path@openssh.com``) and a different feature. Note for anyone tempted to reach for
  that extension here: it does **not** glob. Its reply is REALPATH-shaped -- one name -- so it
  could not return a match set even in principle. See :mod:`gantry_sftp.session._session`.
- **Case-insensitive matching of non-ASCII bytes.** Folding is ASCII-only, because a remote
  name is bytes of unknown encoding and folding UTF-8 by byte is simply wrong.
- **Equivalence classes** (``[[=a=]]``) **and collating symbols** (``[[.a.]]``), which are the
  other two POSIX bracket sub-expressions and are declined together. Both are *defined* by the
  locale's collation table -- ``[[=a=]]`` means "every character that collates equal to ``a``",
  which is ``{a}`` in the C locale and ``{a, á, à, â, ä, …}`` in several others -- so honouring
  them means choosing a locale on the caller's behalf for bytes whose encoding is unstated.
  That is the same refusal as the line above it, applied to a construct rather than to a byte.
  A character class is different in exactly the way that matters: ASCII ``[[:digit:]]`` is the
  same ten bytes in every locale a caller could have meant.

**A construct this module will not honour is refused, never quietly matched as something
else.** A pattern naming a character class that does not exist (``[[:digits:]]``, plural), or
using either declined sub-expression, raises :exc:`ValueError` -- from :func:`match_component`,
and from :func:`validate_pattern` before :meth:`Session.glob` has listed anything. That is a
deliberate divergence from ``glob(3)``, which answers "no matches" to all three, and it is the
same divergence :meth:`Session.glob` already takes over a directory it was not allowed to read:
answering "nothing matched" when the truth is "I did not understand the pattern" is the shape
of partial success this library refuses everywhere else. Where glibc *backs off* rather than
refusing -- ``[[:digit]`` has no ``:]`` to close the name, ``[[:dig1t:]`` has a digit in it --
so does this, and the ``[`` is an ordinary member.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import aclosing
from types import TracebackType
from typing import Protocol

from gantry_sftp.codec import Attrs
from gantry_sftp.exceptions import CapabilityError, NoSuchFileError
from gantry_sftp.session._listing import DirEntry, EntryKind, entry_kind
from gantry_sftp.session._recursive import GlobMatch, WalkEntry, check_listed_name, join_remote

__all__ = [
    "MAGIC_BYTES",
    "RECURSIVE",
    "GlobRunner",
    "has_magic",
    "match_component",
    "split_pattern",
    "validate_pattern",
]

MAGIC_BYTES = b"*?["
"""Bytes that make a component a pattern rather than a literal name.

``\\`` is absent on purpose: a backslash only *escapes*, so a component containing one but no
other magic -- ``a\\b`` -- still matches exactly one literal name and can take the fast path.
"""

RECURSIVE = b"**"
"""The component that crosses directory levels.

Not in ``glob(3)`` and not in `sftp(1)`: this is an addition, because every neighbouring
ecosystem a caller arrives from has it (``pathlib``, ``fsspec``, bash's ``globstar``) and
because :meth:`Session.walk` already provides exactly the bounded traversal it needs. A pattern
that uses it is not portable back to `sftp(1)`, which is said out loud in the public docstring.
"""

_STAR = ord("*")
_QUESTION = ord("?")
_OPEN_CLASS = ord("[")
_CLOSE_CLASS = ord("]")
_ESCAPE = ord("\\")
_NEGATE = (ord("!"), ord("^"))
_DOT = ord(".")
_DASH = ord("-")
_COLON = ord(":")
_EQUALS = ord("=")
_UPPER_A = ord("A")
_UPPER_Z = ord("Z")
_LOWER_A = ord("a")
_LOWER_Z = ord("z")
_CASE_SHIFT = ord("a") - ord("A")

_CLASS_CLOSE = b":]"
"""What closes a ``[:name:]`` character class."""

_LOCALE_MARKERS = (_EQUALS, _DOT)
"""The two bracket sub-expressions this module refuses: ``[[=a=]]`` and ``[[.a.]]``.

Named by the byte that both opens and closes them, since ``[=`` is closed by ``=]`` and ``[.``
by ``.]``. See the module docstring for why they are declined rather than implemented.
"""

_NO_BYTE = -1
"""A subject that is not a byte, for a walk taken to parse rather than to match.

:func:`validate_pattern` drives the matcher's own bracket parser and discards its answer, so it
needs something to pass that cannot be equal to any byte in a pattern. ``-1`` is that, and it is
not a sentinel anyone must check for: every comparison it takes part in is simply false.
"""

_ASCII_UPPER = frozenset(range(_UPPER_A, _UPPER_Z + 1))
_ASCII_LOWER = frozenset(range(_LOWER_A, _LOWER_Z + 1))
_ASCII_DIGIT = frozenset(range(ord("0"), ord("9") + 1))
_ASCII_ALPHA = _ASCII_UPPER | _ASCII_LOWER
_ASCII_PRINT = frozenset(range(0x20, 0x7F))
_ASCII_GRAPH = frozenset(range(0x21, 0x7F))

_NAMED_CLASSES: dict[bytes, frozenset[int]] = {
    b"alnum": _ASCII_ALPHA | _ASCII_DIGIT,
    b"alpha": _ASCII_ALPHA,
    b"blank": frozenset(b"\t "),
    b"cntrl": frozenset(range(0x00, 0x20)) | frozenset({0x7F}),
    b"digit": _ASCII_DIGIT,
    b"graph": _ASCII_GRAPH,
    b"lower": _ASCII_LOWER,
    b"print": _ASCII_PRINT,
    b"punct": _ASCII_GRAPH - _ASCII_ALPHA - _ASCII_DIGIT,
    b"space": frozenset(b"\t\n\v\f\r "),
    b"upper": _ASCII_UPPER,
    b"xdigit": _ASCII_DIGIT | frozenset(b"abcdefABCDEF"),
}
"""The twelve POSIX character classes, as the exact byte sets they match.

Written out rather than derived from :mod:`string` or from ``bytes.isalpha``, because every
one of those is a statement about *text* and these are statements about *bytes*: ``b"\\xff"``
is not alphabetic here and ``"ÿ".isalpha()`` is ``True``. Each set was checked byte for byte
against glibc's own ``fnmatch(3)`` in the C locale, which is the matcher ``glob(3)`` uses, and
``tests/test_glob.py`` re-derives all twelve from libc at run time rather than trusting this
table.
"""

_CLASS_NAMES = ", ".join(sorted(name.decode("ascii") for name in _NAMED_CLASSES))
"""The twelve names, for the message a caller who mistyped one has to act on."""


def _fold(byte: int) -> int:
    """Lowercase one ASCII byte, leaving every other byte alone.

    ASCII only, and the limit is honest rather than lazy: a remote name is bytes whose encoding
    the protocol does not state, so folding a byte above 127 would be folding a fragment of
    some character in an encoding nobody has established.
    """
    return byte + _CASE_SHIFT if _UPPER_A <= byte <= _UPPER_Z else byte


def has_magic(component: bytes) -> bool:
    """Whether a pattern component contains anything that needs matching rather than comparing.

    Args:
        component: One component of a pattern, with no ``/``.

    Returns:
        ``True`` if the component must be matched, ``False`` if it is a literal name.
    """
    return any(byte in component for byte in MAGIC_BYTES)


def split_pattern(
    pattern: bytes, *, case_sensitive: bool = True
) -> tuple[bytes, tuple[bytes, ...], bool]:
    """Split a pattern into the directory it can start from and the parts that must be matched.

    The leading run of components with no magic in them is a path that can be walked to
    directly, so ``/incoming/2026/*.csv`` opens ``/incoming/2026`` and never lists ``/``. That
    is not only an optimisation: listing directories a pattern was never going to match is an
    observable side effect on a server that logs, and on one that charges.

    **Under ``case_sensitive=False`` the last component is never folded into the prefix**, even
    when it has no magic in it. A wholly literal pattern otherwise has nothing left to match,
    so the argument would be accepted and silently do nothing -- which the live test caught:
    ``glob("/x/report.csv", case_sensitive=False)`` matched nothing against a real server
    holding ``REPORT.CSV``. Naming the final component to the server resolves it the server's
    way; matching it against a listing resolves it the caller's.

    The *directory* part is still used as the caller typed it. Folding that too would mean
    listing ``/`` to discover whether ``/Incoming`` is ``/incoming``, which is a round trip per
    level for a question the caller did not ask -- they typed the directory and know it. So
    this argument means "match the names case-insensitively", not "resolve the whole path
    case-insensitively", and the public docstring says so in those words.

    **Whether the pattern is absolute is read from the pattern itself, not from what survives
    trimming its trailing separators.** ``//`` and ``///`` are nothing but separator, so a
    version that asked after trimming asked an empty string and was told "relative" --
    ``glob("/")`` answered ``/`` and ``glob("//")`` answered *nothing*, having resolved the
    root of the server against the working directory and then stat'd ``b""``. Both spellings
    name the root to the server itself, measured against OpenSSH 10.0p2: POSIX leaves two
    leading separators implementation-defined and collapses three or more, and either way the
    path is absolute. Trailing separators need no trimming here in any case, since splitting on
    ``/`` yields empty components and those are dropped.

    Args:
        pattern: The whole pattern, absolute or relative.
        case_sensitive: What the caller asked for; see above.

    Returns:
        ``(base, components, directories_only)``. ``base`` is the literal prefix, which is
        ``b"/"`` for an absolute pattern with magic in its first component and ``b""`` for a
        relative one. ``components`` are what remains to match, in order. ``directories_only``
        is set when the pattern ended in ``/``, which asks for directories exactly as it does
        in a shell.
    """
    directories_only = pattern.endswith(b"/") and pattern != b"/"
    absolute = pattern.startswith(b"/")
    parts = [part for part in pattern.split(b"/") if part]

    index = next(
        (i for i, part in enumerate(parts) if has_magic(part) or part == RECURSIVE),
        len(parts),
    )
    if not case_sensitive and parts:
        index = min(index, len(parts) - 1)
    joined = b"/".join(parts[:index])
    return (b"/" + joined if absolute else joined), tuple(parts[index:]), directories_only


def match_component(pattern: bytes, name: bytes, *, case_sensitive: bool = True) -> bool:
    """Match one server-supplied name against one pattern component.

    Neither argument may contain ``/``; the caller has already split on it. See the module
    docstring for the dialect and for why this is not a regular expression.

    Args:
        pattern: One pattern component.
        name: One name, exactly as the server sent it.
        case_sensitive: Fold ASCII case when ``False``. Non-ASCII bytes are never folded.

    Returns:
        Whether the name matches.

    Raises:
        ValueError: If the pattern contains a bracket sub-expression this module refuses -- an
            unknown character class, an equivalence class or a collating symbol. **A name never
            causes this**, however hostile: the three are properties of the caller's pattern,
            which is why :func:`validate_pattern` can find all of them before a name exists.
    """
    if name.startswith(b".") and not _matches_leading_dot(pattern):
        # `glob(3)`'s rule, and the one fnmatch does not have: a leading period is matched only
        # by a literal period. A bracket expression does not count as explicit, so `[.]x` does
        # not match `.x` -- which is what every shell does and what a caller globbing a drop
        # directory is relying on to not pick up this library's own staging files.
        return False
    return _match_here(pattern, name, case_sensitive=case_sensitive)


def validate_pattern(pattern: bytes) -> None:
    """Refuse a pattern this module will not honour, before anything has been listed.

    :meth:`Session.glob` calls this once, up front, and the reason it cannot rely on
    :func:`match_component` raising instead is that **a refusal reached through matching needs
    a name to be raised against**. A pattern naming a character class that does not exist would
    then raise on the first entry of a directory that has entries, and answer "no matches" for
    a directory that is empty or whose first component matched nothing -- two opposite answers
    to one broken pattern, decided by what the server happens to hold, and the quiet one
    reached exactly when there is least evidence anything went wrong.

    Args:
        pattern: The whole pattern, separators and all. It is not split first: a ``/`` means
            nothing to a bracket expression, and no character class name can straddle one.

    Raises:
        ValueError: If any bracket expression contains a sub-expression this module refuses.
            The message names the sub-expression, its offset, the whole pattern, and either the
            twelve class names or what to write instead.
    """
    p = 0
    while p < len(pattern):
        if pattern[p] == _ESCAPE:
            p += 2
            continue
        if pattern[p] == _OPEN_CLASS:
            # The matcher's own parser, driven for its refusals and asked about a subject that
            # is not a byte. `_scan_class` always returns an index past `p`, so this terminates.
            p, _ = _scan_class(pattern, p, _NO_BYTE, case_sensitive=True)
            continue
        p += 1


def _matches_leading_dot(pattern: bytes) -> bool:
    """Whether a pattern begins with a literal period, escaped or not."""
    if pattern.startswith(b"."):
        return True
    return pattern.startswith(b"\\.")


def _match_here(pattern: bytes, name: bytes, *, case_sensitive: bool) -> bool:
    """Two-pointer glob match with one backtrack point.

    ``star_pattern`` remembers where the most recent ``*`` was and ``star_name`` how much it has
    already consumed, so a failure rewinds to "that ``*`` swallows one more byte" rather than
    exploring every split. That is what keeps this linear-ish and unbackrackable, which matters
    because ``name`` comes from the peer.
    """
    p = n = 0
    star_pattern = -1
    star_name = 0
    while n < len(name):
        if p < len(pattern) and pattern[p] == _STAR:
            star_pattern = p
            star_name = n
            p += 1
            continue
        consumed = _match_single(pattern, p, name, n, case_sensitive=case_sensitive)
        if consumed is not None:
            p = consumed
            n += 1
            continue
        if star_pattern < 0:
            return False
        star_name += 1
        n = star_name
        p = star_pattern + 1
    return all(byte == _STAR for byte in pattern[p:])


def _match_single(
    pattern: bytes, p: int, name: bytes, n: int, *, case_sensitive: bool
) -> int | None:
    """Match one name byte at ``n`` against the pattern element at ``p``.

    Returns:
        The pattern index just past the element consumed, or ``None`` if it did not match.
    """
    if p >= len(pattern):
        return None
    element = pattern[p]
    if element == _QUESTION:
        return p + 1
    if element == _OPEN_CLASS:
        return _match_class(pattern, p, name[n], case_sensitive=case_sensitive)
    if element == _ESCAPE and p + 1 < len(pattern):
        # A trailing lone backslash is *not* an escape -- there is nothing to escape -- so it
        # falls through and is compared as an ordinary byte, which is what `glob(3)` does.
        return p + 2 if _equal(pattern[p + 1], name[n], case_sensitive) else None
    return p + 1 if _equal(element, name[n], case_sensitive) else None


def _equal(left: int, right: int, case_sensitive: bool) -> bool:
    return left == right if case_sensitive else _fold(left) == _fold(right)


def _match_class(pattern: bytes, start: int, byte: int, *, case_sensitive: bool) -> int | None:
    """Match one byte against a ``[...]`` bracket expression beginning at ``start``.

    Returns:
        The index just past the closing ``]``, or ``None`` if the byte did not match. An
        unterminated ``[`` is not an error: it is a literal ``[``, which is what any caller who
        globbed a filename containing a bracket expects.

    Raises:
        ValueError: If the expression contains a sub-expression this module refuses; see
            :func:`_read_sub_expression`.

    Note:
        That used to read "which is what ``glob(3)`` does", and **glibc has no single answer to
        match**: an unterminated ``[`` is undefined in POSIX, and measured against glibc's
        ``fnmatch(3)``, ``[abc`` matches ``[abc`` literally while ``[*-`` matches nothing. So
        this is our decision, taken because it is the predictable one, rather than the
        reference's behaviour copied. The differential fuzz in ``tests/test_glob.py`` excludes
        unterminated classes for exactly this reason and says so.
    """
    end, matched = _scan_class(pattern, start, byte, case_sensitive=case_sensitive)
    return end if matched else None


def _scan_class(pattern: bytes, start: int, byte: int, *, case_sensitive: bool) -> tuple[int, bool]:
    """Walk the bracket expression at ``start``, saying where it ends and whether it matched.

    Split out of :func:`_match_class` so that :func:`validate_pattern` can walk a pattern's
    bracket expressions with the *matcher's* parser rather than a second one written to agree
    with it. Two parsers over the same syntax is two places for a sub-expression rule to live,
    and the one that is not exercised by matching is the one that drifts.

    Returns:
        ``(index just past the expression, whether the byte is in it)``. The index is past the
        closing ``]``, or ``start + 1`` when there is no closing ``]`` and the ``[`` was an
        ordinary member; it is always greater than ``start``, so a caller may loop on it.
    """
    p = start + 1
    negated = p < len(pattern) and pattern[p] in _NEGATE
    if negated:
        p += 1
    # A `]` in the first position is the literal character, not the terminator -- POSIX, and the
    # only way to put one in a class at all.
    first = p
    matched = False
    while p < len(pattern):
        if pattern[p] == _CLOSE_CLASS and p > first:
            return p + 1, matched != negated
        consumed, hit = _match_class_item(pattern, p, byte, case_sensitive=case_sensitive)
        matched = matched or hit
        p = consumed
    return start + 1, _equal(_OPEN_CLASS, byte, case_sensitive)


def _match_class_item(
    pattern: bytes, p: int, byte: int, *, case_sensitive: bool
) -> tuple[int, bool]:
    """Consume one class member and say whether it matched.

    A member is a POSIX sub-expression (``[:digit:]``), an escaped byte, a range, or a single
    byte, tried in that order -- the first two are mutually exclusive, since a member cannot
    begin with both a bracket and a backslash.
    """
    low = pattern[p]
    if low == _OPEN_CLASS and p + 1 < len(pattern):
        sub = _read_sub_expression(pattern, p, byte, case_sensitive=case_sensitive)
        if sub is not None:
            return sub
    if low == _ESCAPE and p + 1 < len(pattern):
        return p + 2, _equal(pattern[p + 1], byte, case_sensitive)
    is_range = p + 2 < len(pattern) and pattern[p + 1] == _DASH and pattern[p + 2] != _CLOSE_CLASS
    if is_range:
        high = pattern[p + 2]
        return p + 3, _in_range(low, high, byte, case_sensitive=case_sensitive)
    return p + 1, _equal(low, byte, case_sensitive)


def _read_sub_expression(
    pattern: bytes, p: int, byte: int, *, case_sensitive: bool
) -> tuple[int, bool] | None:
    """Read the POSIX sub-expression opening at ``p``, if that is what opens there.

    Args:
        pattern: The whole pattern component.
        p: The index of a ``[`` that is a *member* of a bracket expression, so ``p + 1`` is
            readable and is what decides which of the three sub-expressions this could be.
        byte: The subject byte.
        case_sensitive: Fold ASCII case when ``False``, matching :func:`_in_range`'s rule --
            ``[[:upper:]]`` matches ``a`` under a case-insensitive match for the same reason
            ``[A-Z]`` does, and neither happens if only the subject is folded.

    Returns:
        ``(index just past the sub-expression, whether the byte is in it)``, or ``None`` when
        the ``[`` opens no sub-expression at all and is an ordinary member.

    Raises:
        ValueError: If the sub-expression is well formed and this module will not honour it:
            an unknown character class, or either locale-dependent form.
    """
    marker = pattern[p + 1]
    if marker == _COLON:
        return _read_named_class(pattern, p, byte, case_sensitive=case_sensitive)
    if marker in _LOCALE_MARKERS:
        end = pattern.find(bytes([marker, _CLOSE_CLASS]), p + 2)
        if end >= 0:
            raise ValueError(_locale_refusal(pattern, p, marker, pattern[p + 2 : end]))
    return None


def _read_named_class(
    pattern: bytes, p: int, byte: int, *, case_sensitive: bool
) -> tuple[int, bool] | None:
    """Read a ``[:name:]`` character class at ``p``, or ``None`` if there is not one there.

    **The back-off rule is glibc's**, measured rather than recalled: a ``[:`` with no ``:]`` to
    close it (``[[:digit]``) and one whose name is not all lowercase ASCII letters
    (``[[:dig1t:]``, ``[[:DIGIT:]``) are both *not* sub-expressions, and the ``[`` reverts to an
    ordinary member. This is what makes ``[:digit:]`` -- the same spelling with the outer
    bracket forgotten -- stay the ordinary set ``{:, d, i, g, t}`` that ``glob(3)`` makes it,
    rather than becoming a refusal for a pattern that is not wrong.

    Where it diverges is the *terminated* name that is not one of the twelve. glibc answers no
    match, for that name and for every other byte; this raises. Both are outside POSIX, which
    calls an unknown class undefined -- so there is no reference behaviour to copy here, only a
    choice between two ways of being wrong about ``[[:digits:]]``, and the loud one is this
    library's rule.
    """
    end = pattern.find(_CLASS_CLOSE, p + 2)
    if end < 0:
        return None
    name = pattern[p + 2 : end]
    if any(letter < _LOWER_A or letter > _LOWER_Z for letter in name):
        return None
    members = _NAMED_CLASSES.get(name)
    if members is None:
        raise ValueError(_unknown_class_refusal(pattern, p, name))
    if case_sensitive:
        return end + 2, byte in members
    return end + 2, byte in members or _swap_case(byte) in members


def _unknown_class_refusal(pattern: bytes, p: int, name: bytes) -> str:
    """The message for ``[[:digits:]]`` -- what was named, where, and what the names are."""
    spelling = f"[:{name.decode('ascii')}:]"
    return (
        f"unknown character class {spelling!r} at offset {p} in glob pattern {pattern!r}; "
        f"the POSIX character classes are: {_CLASS_NAMES}"
    )


def _locale_refusal(pattern: bytes, p: int, marker: int, content: bytes) -> str:
    """The message for the two sub-expressions this module declines to implement."""
    delimiter = chr(marker)
    spelling = f"[{delimiter}{content.decode('latin-1')}{delimiter}]"
    kind, remedy = (
        ("equivalence classes", "spell the members out, as in [aA]")
        if marker == _EQUALS
        else ("collating symbols", "write the character itself, as in [a]")
    )
    return (
        f"{kind} are not supported in a glob pattern: {spelling!r} at offset {p} in "
        f"{pattern!r}. They are defined by the locale's collation table, and a remote name is "
        f"bytes of unstated encoding -- this library will not choose a locale for it. "
        f"Instead, {remedy}."
    )


def _swap_case(byte: int) -> int:
    """The other ASCII case of one byte, or the byte itself where it has no other case.

    :func:`_fold` cannot serve here. A character class is a *set*, not a pair of endpoints, so
    the question is whether either case of the subject is in it -- and folding alone answers
    that for ``[[:lower:]]`` against ``A`` while getting ``[[:upper:]]`` against ``a`` wrong.
    """
    if _UPPER_A <= byte <= _UPPER_Z:
        return byte + _CASE_SHIFT
    if _LOWER_A <= byte <= _LOWER_Z:
        return byte - _CASE_SHIFT
    return byte


def _in_range(low: int, high: int, byte: int, *, case_sensitive: bool) -> bool:
    """Whether a byte falls in an inclusive range, folding both ends when asked.

    Folded both ways rather than once: ``[A-Z]`` must match ``a`` under a case-insensitive
    match, and so must ``[a-z]`` match ``A``, and neither happens if only the subject is folded.
    """
    if case_sensitive:
        return low <= byte <= high
    return (low <= byte <= high) or (_fold(low) <= _fold(byte) <= _fold(high))


# --- driving a session with the matcher above -------------------------------------------------


class _AttrsOrAbsent(Protocol):
    """``Session._attrs_or_absent``: attributes, or ``None`` when the path is not there."""

    async def __call__(self, path: bytes, *, follow_symlinks: bool) -> Attrs | None: ...


class _EntryScan(Protocol):
    """As much of ``DirectoryScan`` as globbing uses.

    Named structurally rather than imported: ``DirectoryScan`` lives in ``_session``, which
    imports *this* module, so naming the class here would be the cycle the layering forbids.
    """

    async def __aenter__(self) -> AsyncIterator[DirEntry]: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


class _Scandir(Protocol):
    """``Session.scandir``: one directory, streamed, with the handle held across the yield."""

    def __call__(self, path: bytes | str) -> _EntryScan: ...


class _Walk(Protocol):
    """``Session.walk``: the bounded traversal, which owns the symlink and depth policy."""

    def __call__(
        self, path: bytes | str, *, max_depth: int | None = None
    ) -> AsyncGenerator[WalkEntry]: ...


class _SettleKind(Protocol):
    """``Session._settle_kind``: the entry's kind, paying an ``LSTAT`` only when it must."""

    async def __call__(self, path: bytes, entry: DirEntry) -> EntryKind | None: ...


class _Unclassifiable(Protocol):
    """``Session._unclassifiable``: the refusal shared with :meth:`Session.isdir`."""

    def __call__(self, path: bytes, *, caller: str) -> CapabilityError: ...


def _strip_dot_prefix(path: bytes) -> bytes:
    """Drop the ``./`` a walk rooted at ``.`` prefixes onto every path below it.

    Only the prefix a walk this library started is responsible for -- a server that genuinely
    returns a name beginning with a dot keeps it, because ``.hidden`` is an ordinary filename
    and ``..`` never reaches here (a listing excludes it and
    :func:`~gantry_sftp.session.check_listed_name` refuses it).
    """
    if path == b".":
        return b""
    return path[2:] if path.startswith(b"./") else path


class GlobRunner:
    """The traversal half of :meth:`Session.glob`, holding no session and no state.

    **A plain class with a written-out ``__init__``, and not a dataclass** -- which looks like a
    step backwards and is the opposite (D-128, found by the first run of the lane after the
    extraction). mutmut does not instrument the methods of a **decorated class**, for the same
    reason it declines a decorated function: building the trampoline means re-running the
    decorator, and ``@dataclass(slots=True)`` does not merely add methods, it returns a *new
    class object*. Measured in the shadow tree rather than reasoned about — as a dataclass this
    class produced **zero** mutants while the module-level matcher above it produced 48, so the
    six methods below moved out of `Session`, which is instrumented, into a class which is not.
    The extraction would have silently traded the traversal's mutation coverage for tidier
    construction.

    So the five fields are assigned by hand. `frozen` and `slots` bought a defensive guarantee
    and a micro-optimisation on an object built once per `glob()` call; the lane's view of six
    methods full of comparisons, slices and `or` defaults is worth more than both. This is
    CLAUDE.md's D-107 rule applied to a class rather than to a function: decide by reading the
    body for something mutable, and these bodies are almost entirely that.

    **Built from bound methods rather than from a session**, and that is a layering decision
    rather than a style one (D-128). Three of the five things a glob needs are private members
    of ``Session``; reaching them from this module would be ``obj._private`` at seven call
    sites, which ``SLF001`` refuses and which seven ``noqa``s would not fix so much as record.
    Binding happens in :meth:`Session._glob_runner`, where ``self._settle_kind`` is an ordinary
    attribute access, and this module never names a private member of anything.

    What that buys beyond the lint: the traversal is exercisable with five callables and no
    session, no transport and no server -- which is the property the extraction was for, and
    the reason the pattern matcher above has always been the easy half to test.

    The methods keep the names they had as ``Session`` methods. They are redundant here, where
    everything is glob, and they are kept because ``tests/test_glob.py`` names them in its
    docstrings when it explains which forwarding path a case covers: renaming them would make
    that file's prose wrong, and an untouched test file passing over moved code is what proves
    the move changed no behaviour.
    """

    def __init__(
        self,
        *,
        attrs_or_absent: _AttrsOrAbsent,
        scandir: _Scandir,
        walk: _Walk,
        settle_kind: _SettleKind,
        unclassifiable: _Unclassifiable,
    ) -> None:
        self.attrs_or_absent = attrs_or_absent
        self.scandir = scandir
        self.walk = walk
        self.settle_kind = settle_kind
        self.unclassifiable = unclassifiable

    async def literal(self, path: bytes, *, directories_only: bool) -> GlobMatch | None:
        """Resolve a pattern that turned out to have no magic in it.

        One ``LSTAT``. ``LSTAT`` rather than ``STAT`` so a symlink stays a symlink, matching
        what the matching path does for every other component; and a missing path is ``None``
        rather than an error, because a pattern matching nothing is the ordinary case and a
        literal pattern is still a pattern.

        **Through ``attrs_or_absent`` rather than round its own ``except``**, which is the
        whole of the fix for D-102. This used to catch ``(NoSuchFileError, ServerError)`` -- and
        ``NoSuchFileError`` *is* a ``ServerError``, so the second element swallowed every other
        status too. A file the caller was not allowed to stat came back as "matches nothing",
        and so did a name that was merely too long. That is the divergence from ``glob(3)``
        that :meth:`listing` documents refusing, three methods below, for the wildcard
        half of the same feature: a glob answering "no matches" when it means "I was not
        allowed to look" is a partial success wearing a complete one's clothes. Whether the
        caller's pattern happened to contain a ``*`` decided which answer they got.
        """
        attributes = await self.attrs_or_absent(path, follow_symlinks=False)
        if attributes is None:
            return None
        entry = DirEntry(filename=path.rpartition(b"/")[2], longname=b"", attrs=attributes)
        if directories_only and entry_kind(attributes) is not EntryKind.DIRECTORY:
            return None
        return GlobMatch(path, entry)

    async def match_in(
        self,
        directory: bytes,
        components: tuple[bytes, ...],
        *,
        max_depth: int | None,
        case_sensitive: bool,
        directories_only: bool,
    ) -> AsyncGenerator[GlobMatch]:
        """Match ``components`` against the contents of one directory, descending as needed.

        Recursive, and the recursion depth is the number of pattern components rather than the
        depth of the tree -- so it is bounded by something the caller wrote, not by something
        the server can answer with. One directory handle is open per level for the same reason.

        **Every inner generator is wrapped in ``aclosing``, including this module's own.** An
        ``async for`` does not close the generator it iterates, so a chain of them abandoned
        part-way -- by a caller that stopped early, or by
        :func:`~gantry_sftp.session.check_listed_name` refusing a name mid-listing -- leaves
        each link to the garbage collector. trio does not finalise those, and it surfaces as
        ``Exception ignored in: <async_generator object ...>`` at some unrelated later point.
        This is the idiom :meth:`Session.walk` tells *callers* to use, applied to the callers
        inside this class; it was not theoretical, and the test that refuses a hostile name is
        what found it.
        """
        head, rest = components[0], components[1:]
        if head == RECURSIVE:
            async with aclosing(
                self.recursive(
                    directory,
                    rest,
                    max_depth=max_depth,
                    case_sensitive=case_sensitive,
                    directories_only=directories_only,
                )
            ) as found:
                async for match in found:
                    yield match
            return

        async with aclosing(self.listing(directory)) as entries:
            async for entry in entries:
                name = check_listed_name(entry.filename, directory=directory)
                if not match_component(head, name, case_sensitive=case_sensitive):
                    continue
                path = join_remote(directory, name)
                if rest:
                    async with aclosing(
                        self.descend(
                            path,
                            entry,
                            rest,
                            max_depth=max_depth,
                            case_sensitive=case_sensitive,
                            directories_only=directories_only,
                        )
                    ) as deeper:
                        async for match in deeper:
                            yield match
                elif not directories_only or await self.is_directory(path, entry):
                    yield GlobMatch(path, entry)

    async def listing(self, directory: bytes) -> AsyncGenerator[DirEntry]:
        """List one directory for a glob, where "not there" means "matches nothing".

        A pattern naming a directory that does not exist matches nothing, exactly as a name
        that does not match matches nothing -- ``/root/absent/*.csv`` is not an error, it is an
        empty result. **And the same is true of a path component that exists and is not a
        directory**, which falls out of the protocol rather than needing a second case:
        ``OPENDIR`` on a plain file answers ``NO_SUCH_FILE`` because ``ENOTDIR`` is remapped.

        Only that status is swallowed. ``PERMISSION_DENIED`` on a directory the pattern reached
        is raised, because a glob that answers "no matches" when it means "I was not allowed to
        look" is a partial success wearing a complete one's clothes -- which is the shape this
        library refuses everywhere else, and is where it diverges from ``glob(3)``.

        The ``NO_SUCH_FILE`` can only come from the ``OPENDIR`` this opens: a ``READDIR`` past
        the end answers ``EOF``, which :meth:`Session.scandir` turns into the end of the
        iteration.
        """
        try:
            async with self.scandir(directory or b".") as entries:
                async for entry in entries:
                    yield entry
        except NoSuchFileError:
            return

    async def descend(
        self,
        path: bytes,
        entry: DirEntry,
        rest: tuple[bytes, ...],
        *,
        max_depth: int | None,
        case_sensitive: bool,
        directories_only: bool,
    ) -> AsyncGenerator[GlobMatch]:
        """Continue matching inside a matched entry, if it is a directory we may enter."""
        if not await self.is_directory(path, entry):
            return
        async with aclosing(
            self.match_in(
                path,
                rest,
                max_depth=max_depth,
                case_sensitive=case_sensitive,
                directories_only=directories_only,
            )
        ) as found:
            async for match in found:
                yield match

    async def recursive(
        self,
        directory: bytes,
        rest: tuple[bytes, ...],
        *,
        max_depth: int | None,
        case_sensitive: bool,
        directories_only: bool,
    ) -> AsyncGenerator[GlobMatch]:
        """Match the components after a ``**`` at this directory and at every descendant.

        Driven by :meth:`Session.walk`, which is where the bounded traversal, the symlink
        policy and the ``max_depth`` refusal already live -- reimplementing the descent here
        would be a second place for those three decisions to be made differently.

        A trailing ``**`` is ``**/*``: it matches everything below its position, at every
        level, which is what a shell with ``globstar`` does and what the alternative -- a
        pattern that matches only directories, or only the root -- would surprise a caller
        with.
        """
        remaining = rest or (b"*",)
        async with aclosing(self.walk(directory or b".", max_depth=max_depth)) as walker:
            async for visited in walker:
                # `walk(b".")` reports `.` and `./sub`; a relative pattern's other components
                # join onto `b""` and produce `sub`. Left alone, one pattern would answer in
                # two spellings depending on whether it happened to contain `**`.
                reached = visited.path if directory else _strip_dot_prefix(visited.path)
                async with aclosing(
                    self.match_in(
                        reached,
                        remaining,
                        max_depth=max_depth,
                        case_sensitive=case_sensitive,
                        directories_only=directories_only,
                    )
                ) as found:
                    async for match in found:
                        yield match

    async def is_directory(self, path: bytes, entry: DirEntry) -> bool:
        """Whether a matched entry is a directory this glob may look inside.

        ``settle_kind`` rather than a bare attribute read, so an entry the server sent no
        permissions for costs one ``LSTAT`` instead of being guessed at -- and ``LSTAT`` is
        what keeps a symlink a symlink, which is what makes "matched but never descended into"
        true rather than aspirational.

        **Absent is ``False``; a refusal and an answer with no type in it both raise, which is
        D-103.** That is the same rule :meth:`listing` and :meth:`literal` state for
        the other two ways a glob can be told nothing. An entry that is no longer there matches
        nothing, exactly as a name that does not match matches nothing. But a server that
        *refuses* the stat, or answers it without the permission bits v3 carries the file type
        in, has said nothing about the kind -- and `glob` has no ``Skipped`` channel to record
        that in, so answering "not a directory" would drop the entry, or everything beneath it,
        into a result that looks complete.

        **The second of those two is the likelier one in the field**, and it is why this method
        does not stop at narrowing the ``except``: a server that omits permission bits from a
        *listing* is a server that probably omits them from a ``STAT`` as well, so the entry
        arrives here settled to ``UNKNOWN`` rather than refused. :meth:`Session._kind_is`
        reached the same fork for :meth:`Session.isdir` and answered it the same way, and its
        docstring names this exact consequence -- *"the reason recursive downloads silently
        skip directories on some servers"*. Sharing ``unclassifiable`` is what keeps the two
        refusals one decision instead of two wordings.
        """
        settled = await self.settle_kind(path, entry)
        if settled is EntryKind.UNKNOWN:
            raise self.unclassifiable(path, caller="glob")
        return settled is EntryKind.DIRECTORY

"""Glob pattern matching over remote names -- pure, and deliberately not ``fnmatch``.

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

__all__ = [
    "MAGIC_BYTES",
    "RECURSIVE",
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
    trimmed = pattern.rstrip(b"/") if directories_only else pattern
    absolute = trimmed.startswith(b"/")
    parts = [part for part in trimmed.split(b"/") if part]

    index = next(
        (i for i, part in enumerate(parts) if has_magic(part) or part == RECURSIVE),
        len(parts),
    )
    if not case_sensitive and parts:
        index = min(index, len(parts) - 1)
    joined = b"/".join(parts[:index])
    base = b"/" + joined if absolute else joined
    return base or (b"/" if absolute else b""), tuple(parts[index:]), directories_only


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

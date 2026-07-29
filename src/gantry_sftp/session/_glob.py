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
"""

from __future__ import annotations

__all__ = [
    "MAGIC_BYTES",
    "RECURSIVE",
    "has_magic",
    "match_component",
    "split_pattern",
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
_UPPER_A = ord("A")
_UPPER_Z = ord("Z")
_CASE_SHIFT = ord("a") - ord("A")


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
    """
    if name.startswith(b".") and not _matches_leading_dot(pattern):
        # `glob(3)`'s rule, and the one fnmatch does not have: a leading period is matched only
        # by a literal period. A bracket expression does not count as explicit, so `[.]x` does
        # not match `.x` -- which is what every shell does and what a caller globbing a drop
        # directory is relying on to not pick up this library's own staging files.
        return False
    return _match_here(pattern, name, case_sensitive=case_sensitive)


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
        unterminated ``[`` is not an error: it is a literal ``[``, which is what ``glob(3)``
        does and what any caller who globbed a filename containing a bracket expects.
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
            return (p + 1) if matched != negated else None
        consumed, hit = _match_class_item(pattern, p, byte, case_sensitive=case_sensitive)
        matched = matched or hit
        p = consumed
    return start + 1 if _equal(_OPEN_CLASS, byte, case_sensitive) else None


def _match_class_item(
    pattern: bytes, p: int, byte: int, *, case_sensitive: bool
) -> tuple[int, bool]:
    """Consume one class member -- a range or a single byte -- and say whether it matched."""
    low = pattern[p]
    if low == _ESCAPE and p + 1 < len(pattern):
        return p + 2, _equal(pattern[p + 1], byte, case_sensitive)
    is_range = p + 2 < len(pattern) and pattern[p + 1] == _DASH and pattern[p + 2] != _CLOSE_CLASS
    if is_range:
        high = pattern[p + 2]
        return p + 3, _in_range(low, high, byte, case_sensitive=case_sensitive)
    return p + 1, _equal(low, byte, case_sensitive)


def _in_range(low: int, high: int, byte: int, *, case_sensitive: bool) -> bool:
    """Whether a byte falls in an inclusive range, folding both ends when asked.

    Folded both ways rather than once: ``[A-Z]`` must match ``a`` under a case-insensitive
    match, and so must ``[a-z]`` match ``A``, and neither happens if only the subject is folded.
    """
    if case_sensitive:
        return low <= byte <= high
    return (low <= byte <= high) or (_fold(low) <= _fold(byte) <= _fold(high))

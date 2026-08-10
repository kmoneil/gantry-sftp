"""A path object for a remote namespace, shaped like ``pathlib`` and made of bytes.

    from gantry_sftp import SFTPPath, connect

    async with connect("example.com", user="bob") as sftp:
        incoming = SFTPPath("/incoming", session=sftp)
        async for csv in incoming.glob("*.csv"):
            await csv.download(local_dir / os.fsdecode(csv.name))

**Strings go in, bytes come out.** That is the whole type rule and it is
:class:`~gantry_sftp.session.Session`'s rule, not a new one: every method there takes
``bytes | str`` and every one hands back ``bytes``. A remote name is bytes whose encoding the
protocol never states, and the files whose names are the reason you needed a listing are
exactly the ones that are not valid UTF-8 -- so :meth:`SFTPPath.name`, like
:attr:`~gantry_sftp.session.DirEntry.filename` and :meth:`~gantry_sftp.session.Session.realpath`
before it, is ``bytes``. ``str(path)`` and ``bytes(path)`` are both round-trippable views of the
same name: ``str`` decodes with ``surrogateescape``, so re-encoding it recovers the original
bytes for any input at all. Nothing here is ever normalised. A trailing slash stays, ``//``
stays, ``..`` stays, and a backslash is an ordinary character in a name rather than a separator.

**Two different trust levels, and the split is what makes this safe to hand a listing to.**

*The constructor is a caller-written path.* ``SFTPPath("/a/../b")`` is accepted verbatim,
because the argument's trust comes from whoever wrote it and because
:meth:`~gantry_sftp.session.Session.stat` accepts exactly that string today. Refusing it here
would make this type weaker than the API it wraps and buy nothing.

*Joining is a server-supplied name.* ``path / name`` is overwhelmingly ``path / entry.filename``,
which is attacker-controlled, so ``/`` takes **one validated component** and nothing else --
:func:`~gantry_sftp.session.remote_component_reason` decides, and a separator, a NUL, ``.``,
``..`` or an empty name raises :class:`~gantry_sftp.exceptions.UnsafePathError`. It is the same
predicate :meth:`~gantry_sftp.session.Session.glob` and the recursive operations use, called from
one more place rather than reimplemented -- which is the point of the class existing at all,
since the alternative is every caller rediscovering the ``..`` check by hand. Go up with
:attr:`~SFTPPath.parent`, which needs no string.

**The binding is explicit or there is none.** ``session=`` is how a path reaches a server, and a
path derived from a bound one stays bound. An unbound path is pure arithmetic and every method
that would touch the wire raises :class:`~gantry_sftp.exceptions.StateError` naming the fix.
There is no ambient session and no URL constructor: ``SFTPPath("sftp://host/incoming")`` --
which is what DESIGN.md sketched from draft 0.1 until this shipped -- needs a global default
client to mean anything, and DESIGN.md 8's own "no global state, no module-level default
client" forbids one.

**Three shapes this deliberately is not**, each because the convenient version has a hole:

- **Not a ``str`` subclass.** It reads elegantly and it inherits ``+``, ``%`` and ``.replace()``
  -- none of which route through the joining check above. A type that lets a caller rebuild the
  zip-slip hazard with ``path + name`` is the defence with a hole in it.
- **Not** :class:`os.PathLike`. Defining ``__fspath__`` would admit this into :func:`open`,
  :func:`os.stat` and every stdlib function that takes a path, all of which would operate on the
  **local** filesystem with a remote name. That confusion already cost four different endings for
  one wrong argument (D-96), which is why the two sides have different declared types.
- **Not case-folding, and not because it would be hard.** Two paths differing in case are two
  paths here, and equality is byte equality. Which names a filesystem folds into one file is that
  filesystem's own table -- three different tables -- and D-37 established that the reachable
  hazard is a case-folding *local* disk rather than a folding server. That check is
  :class:`~gantry_sftp.session.DestinationLedger`, it asks ``lstat`` after the write because the
  filesystem is the only authority, and a recursive download already runs one.

**The arithmetic is ``/``-shaped, which is a claim about the server** (D-77). A namespace that is
not rooted at ``/`` -- a mainframe dataset name, a VMS-style path -- gives ``/`` arithmetic
nothing to be right about, and the refusal for that lives where D-77 put it: on the operations
that do the arithmetic against a real server. The I/O methods here inherit it by delegation
rather than re-deriving it, because the answer needs a round trip and the arithmetic does not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, overload, override

from gantry_sftp.codec import OpenFlag
from gantry_sftp.exceptions import NoSuchFileError, StateError, UnsafePathError
from gantry_sftp.session import Verify, join_remote, remote_component_reason
from gantry_sftp.session._glob import RECURSIVE, match_component, validate_pattern

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Iterable
    from datetime import datetime
    from pathlib import Path

    from gantry_sftp.codec import Attrs
    from gantry_sftp.session import (
        DownloadResult,
        Mode,
        ProgressCallback,
        Publish,
        RemoteFile,
        Session,
        TreePlan,
        TreeResult,
        UploadResult,
    )

__all__ = ["DEFAULT_WRITE_MODE", "SFTPPath"]

DEFAULT_WRITE_MODE = 0o600
"""Permission bits :meth:`SFTPPath.write_bytes` gives a file it creates.

``open(2)``'s ``0666`` is the wrong default across a network and the reason is measured rather
than cautious: OpenSSH's ``process_open`` reads the ``ATTRS`` on an ``OPEN`` for ``PERMISSIONS``
and nothing else, defaulting to ``0666`` when the flag is absent, so a file created without one
arrives world-readable under the usual umask -- and a later ``chmod`` leaves a window in which
it was readable. There is no umask of ours on the far side to narrow it. ``0600`` is the same
answer :meth:`~gantry_sftp.session.Session.get` gives on the local side, and a caller who wants
the file group-readable passes ``mode=``.
"""

_DOT = b"."
_ROOT = b"/"
_SEPARATOR = b"/"


def _encode(path: bytes | str) -> bytes:
    """Take a caller's path to the bytes that go on the wire.

    ``surrogateescape`` matching :class:`~gantry_sftp.session.Session`'s own encoder, so a name
    that came back from the server as invalid UTF-8, was decoded leniently and is now being sent
    again survives the round trip unchanged.

    Raises:
        TypeError: If ``path`` is neither ``bytes`` nor ``str``.
    """
    if isinstance(path, bytes):
        return path
    if isinstance(path, str):
        return path.encode("utf-8", "surrogateescape")
    raise TypeError(_wrong_type(path))


def _wrong_type(path: object) -> str:
    """Explain a path argument that is neither ``bytes``, ``str`` nor an :class:`SFTPPath`.

    A ``pathlib`` path gets its own sentence for the reason
    :func:`gantry_sftp.session._policy._wrong_path_type` gives: it is the type callers actually
    reach for, and ``pathlib``'s job is to normalise a name this one has to preserve.
    """
    kind = type(path).__name__
    if hasattr(path, "__fspath__"):
        return (
            f"a remote path must be bytes, str or SFTPPath, not {kind}: pathlib normalises and "
            f"a remote name has to survive byte for byte -- a trailing slash goes on "
            f"construction, and str(Path(...)) on Windows renders separators as backslashes, "
            f"which a server takes as part of the filename. Pass str(path) if it really is "
            f"posix-shaped, or the bytes the server gave you"
        )
    return f"a remote path must be bytes, str or SFTPPath, not {kind}"


def check_component(name: bytes) -> bytes:
    """Refuse a name that may not be one component of a remote path, and return it if it may.

    The joining check, in the one place :class:`SFTPPath` calls it. It is
    :func:`~gantry_sftp.session.remote_component_reason` -- the same predicate the recursive
    walk and ``glob`` ask of every name a server sends -- rather than a fourth copy of the
    ``..`` test.

    Args:
        name: One component, exactly as it arrived.

    Returns:
        ``name`` unchanged, so this reads as a pass-through at the call site.

    Raises:
        UnsafePathError: If the name could not be one path component.
    """
    reason = remote_component_reason(name)
    if reason is None:
        return name
    raise UnsafePathError(
        f"refusing to join {name!r} onto a remote path: it contains {reason}, so it is not one "
        f"path component -- use .parent to go up, or build the path you mean with SFTPPath()",
        name=name,
        reason=reason,
    )


def split_components(path: bytes) -> tuple[bytes, ...]:
    """The non-empty components of a path, with no root marker.

    Empty components are dropped, which is what makes a trailing slash, a doubled separator and
    a bare ``/`` all describe the same sequence of names without anything being rewritten: the
    stored bytes are untouched and this is a *view* of them.
    """
    return tuple(part for part in path.split(_SEPARATOR) if part)


def path_parts(path: bytes) -> tuple[bytes, ...]:
    """The components, preceded by ``b"/"`` when the path is absolute.

    ``pathlib``'s ``parts``, minus the drive and anchor machinery there is nothing here to put
    in it.
    """
    components = split_components(path)
    return (_ROOT, *components) if path.startswith(_ROOT) else components


def parent_of(path: bytes) -> bytes:
    """The directory holding ``path``, as bytes.

    The root is its own parent, and a relative path with one component has ``b"."`` -- which is
    ``pathlib``'s answer and also the path the protocol itself uses for "where I am"
    (:meth:`~gantry_sftp.session.Session.realpath` defaults to it).
    """
    components = split_components(path)
    absolute = path.startswith(_ROOT)
    if len(components) <= 1:
        return _ROOT if absolute else _DOT
    joined = _SEPARATOR.join(components[:-1])
    return _ROOT + joined if absolute else joined


def name_of(path: bytes) -> bytes:
    """The last component, or ``b""`` for a path that has none."""
    components = split_components(path)
    return components[-1] if components else b""


def suffix_of(name: bytes) -> bytes:
    """The final extension of one name, including its dot, or ``b""``.

    ``pathlib``'s rule exactly: a dot at the start does not begin a suffix, so ``.bashrc`` has
    none, and neither does a name ending in one.
    """
    dot = name.rfind(_DOT)
    return name[dot:] if 0 < dot < len(name) - 1 else b""


def stem_of(name: bytes) -> bytes:
    """The name without its final suffix."""
    dot = name.rfind(_DOT)
    return name[:dot] if 0 < dot < len(name) - 1 else name


def suffixes_of(name: bytes) -> tuple[bytes, ...]:
    """Every extension of one name, so ``archive.tar.gz`` is ``(b'.tar', b'.gz')``."""
    if name.endswith(_DOT):
        return ()
    return tuple(_DOT + part for part in name.lstrip(_DOT).split(_DOT)[1:])


def with_name(path: bytes, name: bytes) -> bytes:
    """Replace the last component of ``path`` with ``name``.

    Raises:
        UnsafePathError: If ``name`` could not be one path component.
        ValueError: If ``path`` has no component to replace.
    """
    components = split_components(path)
    if not components:
        raise ValueError(f"{path!r} has an empty name, so there is nothing to replace")
    check_component(name)
    joined = _SEPARATOR.join([*components[:-1], name])
    return _ROOT + joined if path.startswith(_ROOT) else joined


def relative_components(path: bytes, other: bytes) -> tuple[bytes, ...] | None:
    """The components of ``path`` below ``other``, or ``None`` if it is not below it.

    Byte comparison per component, with no folding and no symlink resolution -- this is
    arithmetic on names, and what the server's namespace does with those names is a question
    only the server can answer.
    """
    if path.startswith(_ROOT) != other.startswith(_ROOT):
        return None
    ours = split_components(path)
    theirs = split_components(other)
    if ours[: len(theirs)] != theirs:
        return None
    return ours[len(theirs) :]


def match_components(
    pattern: Iterable[bytes], components: tuple[bytes, ...], *, case_sensitive: bool
) -> bool:
    """Match a sequence of pattern components against a sequence of names.

    A width-first sweep rather than recursion, and that is a security decision of the same kind
    :mod:`~gantry_sftp.session._glob` makes about not building a regular expression: the names
    are server-supplied and of attacker-chosen length, so the cost has to be a product of the
    two lengths rather than a search over where each ``**`` stops. ``reachable[j]`` is "the
    pattern so far can account for the first ``j`` names", which every component updates once.
    """
    reachable = [False] * (len(components) + 1)
    reachable[0] = True
    for element in pattern:
        if element == RECURSIVE:
            reachable = _spread(reachable)
            continue
        reachable = [
            index > 0
            and reachable[index - 1]
            and match_component(element, components[index - 1], case_sensitive=case_sensitive)
            for index in range(len(components) + 1)
        ]
    return reachable[len(components)]


def _spread(reachable: list[bool]) -> list[bool]:
    """Let ``**`` account for zero or more names: once reachable, reachable from there on."""
    seen = False
    spread: list[bool] = []
    for value in reachable:
        seen = seen or value
        spread.append(seen)
    return spread


def match_path(pattern: bytes, path: bytes, *, case_sensitive: bool = True) -> bool:
    """Whether ``path`` matches ``pattern`` under this library's ``glob(3)`` dialect.

    An **absolute** pattern must account for the whole path. A **relative** one is matched from
    the right, as ``pathlib``'s ``match`` is, which is the same thing as prefixing it with
    ``**``. ``**`` is honoured in either, so there is no second method for the full-path
    question -- an absolute pattern already is it.

    Args:
        pattern: The pattern, absolute or relative.
        path: The path to test.
        case_sensitive: Fold ASCII case when ``False``. Non-ASCII bytes are never folded.

    Returns:
        Whether it matches.

    Raises:
        ValueError: If the pattern is empty, or names a bracket sub-expression this library
            refuses -- an unknown character class, an equivalence class, a collating symbol.
    """
    if not pattern:
        raise ValueError("an empty pattern matches nothing, so it is refused rather than answered")
    validate_pattern(pattern)
    if pattern.startswith(_ROOT) and not path.startswith(_ROOT):
        return False
    components = split_components(pattern)
    wanted = components if pattern.startswith(_ROOT) else (RECURSIVE, *components)
    return match_components(wanted, split_components(path), case_sensitive=case_sensitive)


class SFTPPath:
    """One path in a remote namespace, with the algebra and -- once bound -- the operations.

    See the module docstring for the type rule, the two trust levels and what this deliberately
    is not. Construction never talks to a server and never normalises::

        SFTPPath("/incoming/")             # unbound: arithmetic only
        SFTPPath("/incoming/", session=s)  # bound: every method below works

    Args:
        path: The path. ``bytes`` goes on the wire verbatim; ``str`` is encoded with
            ``surrogateescape``; another :class:`SFTPPath` is copied, keeping its session unless
            ``session=`` overrides it.
        session: The session this path operates through, or ``None`` for a pure path.

    Raises:
        TypeError: If ``path`` is not ``bytes``, ``str`` or :class:`SFTPPath`.
    """

    __slots__ = ("_path", "_session")

    def __init__(self, path: bytes | str | SFTPPath, *, session: Session | None = None) -> None:
        inherited = path.session if isinstance(path, SFTPPath) else None
        self._path: bytes = bytes(path) if isinstance(path, SFTPPath) else _encode(path)
        self._session: Session | None = session if session is not None else inherited

    # --- what it is ------------------------------------------------------------------------

    def __bytes__(self) -> bytes:
        """The path exactly as it will go on the wire."""
        return self._path

    @override
    def __str__(self) -> str:
        """The path decoded for display, reversibly.

        ``surrogateescape``, so re-encoding this recovers :meth:`__bytes__` for any name at all
        -- including one no encoding explains. It is a view, not the value: the value is bytes.
        """
        return self._path.decode("utf-8", "surrogateescape")

    @override
    def __repr__(self) -> str:
        """Name the path and say whether it can reach a server.

        The binding is in here because "why did that raise ``StateError``" is the question this
        type invites, and the session itself is not: a session's ``repr`` is a paragraph of
        tunables, and a path is frequently printed inside a listing.
        """
        return f"SFTPPath({self._path!r}, {'bound' if self._session else 'unbound'})"

    @override
    def __eq__(self, other: object) -> bool:
        """Byte equality of the path. The session takes no part.

        Two paths naming the same file through two sessions are the same path, and two spellings
        of one file -- ``/a/b`` and ``/a/./b``, ``README`` and ``readme`` on a folding server --
        are not. Nothing here can resolve either question without a round trip, so it does not
        pretend to.
        """
        return isinstance(other, SFTPPath) and self._path == other._path

    @override
    def __hash__(self) -> int:
        """Hash the bytes, matching :meth:`__eq__`."""
        return hash(self._path)

    def __lt__(self, other: SFTPPath) -> bool:
        """Order by bytes, so a list of paths sorts. Undefined across types."""
        if not isinstance(other, SFTPPath):
            return NotImplemented
        return self._path < other._path

    def __le__(self, other: SFTPPath) -> bool:
        """Order by bytes; see :meth:`__lt__`."""
        if not isinstance(other, SFTPPath):
            return NotImplemented
        return self._path <= other._path

    def __gt__(self, other: SFTPPath) -> bool:
        """Order by bytes; see :meth:`__lt__`."""
        if not isinstance(other, SFTPPath):
            return NotImplemented
        return self._path > other._path

    def __ge__(self, other: SFTPPath) -> bool:
        """Order by bytes; see :meth:`__lt__`."""
        if not isinstance(other, SFTPPath):
            return NotImplemented
        return self._path >= other._path

    # --- pure algebra ----------------------------------------------------------------------

    @property
    def name(self) -> bytes:
        """The last component, or ``b""``. Bytes, like every other name in this library."""
        return name_of(self._path)

    @property
    def parts(self) -> tuple[bytes, ...]:
        """The components, with ``b"/"`` first when the path is absolute."""
        return path_parts(self._path)

    @property
    def parent(self) -> SFTPPath:
        """The directory holding this path, keeping the binding.

        The way up, and the reason ``/`` does not need to accept ``..``.
        """
        return self._derive(parent_of(self._path))

    @property
    def parents(self) -> tuple[SFTPPath, ...]:
        """Every ancestor, nearest first, ending at the root or at ``b"."``."""
        return tuple(self._ancestors())

    @property
    def stem(self) -> bytes:
        """:attr:`name` without its final suffix."""
        return stem_of(name_of(self._path))

    @property
    def suffix(self) -> bytes:
        """The final extension of :attr:`name`, including its dot, or ``b""``."""
        return suffix_of(name_of(self._path))

    @property
    def suffixes(self) -> tuple[bytes, ...]:
        """Every extension of :attr:`name`, so ``archive.tar.gz`` gives two."""
        return suffixes_of(name_of(self._path))

    def _ancestors(self) -> list[SFTPPath]:
        """Walk up until the path stops changing, which is the root or ``b"."``."""
        found: list[SFTPPath] = []
        current = self._path
        while True:
            above = parent_of(current)
            if above == current:
                return found
            found.append(self._derive(above))
            current = above

    def _derive(self, path: bytes) -> SFTPPath:
        """A new path of this class, carrying this one's session."""
        return SFTPPath(path, session=self._session)

    def is_absolute(self) -> bool:
        """Whether the path starts at the server's root.

        The only rootedness question this type answers on its own. Whether the *server* has a
        ``/``-rooted namespace at all is :attr:`~gantry_sftp.session.Session.server_root`'s, and
        it costs a round trip.
        """
        return self._path.startswith(_ROOT)

    def joinpath(self, *names: bytes | str) -> SFTPPath:
        """Append one or more validated components.

        Each name is checked with :func:`check_component` -- one component, no separator, no
        ``..`` -- because the usual right-hand side is a name a server chose.

        Args:
            *names: Components to append, in order.

        Returns:
            A new path, keeping this one's session.

        Raises:
            UnsafePathError: If any name is not one safe path component.
            TypeError: If any name is neither ``bytes`` nor ``str``.
        """
        joined = self._path
        for name in names:
            joined = join_remote(joined, check_component(_encode(name)))
        return self._derive(joined)

    def __truediv__(self, name: bytes | str) -> SFTPPath:
        """``path / name`` -- one validated component. See :meth:`joinpath`."""
        return self.joinpath(name)

    def with_name(self, name: bytes | str) -> SFTPPath:
        """Replace the last component.

        Raises:
            UnsafePathError: If ``name`` is not one safe path component.
            ValueError: If this path has no component to replace.
        """
        return self._derive(with_name(self._path, _encode(name)))

    def with_stem(self, stem: bytes | str) -> SFTPPath:
        """Replace the last component's stem, keeping its suffix.

        Raises:
            UnsafePathError: If the resulting name is not one safe path component.
            ValueError: If this path has no component to replace.
        """
        return self.with_name(_encode(stem) + self.suffix)

    def with_suffix(self, suffix: bytes | str) -> SFTPPath:
        """Replace the last component's final suffix. An empty suffix removes it.

        Raises:
            UnsafePathError: If the resulting name is not one safe path component.
            ValueError: If this path has no component to replace, or if ``suffix`` is
                non-empty and does not begin with a dot.
        """
        encoded = _encode(suffix)
        if encoded and not encoded.startswith(_DOT):
            raise ValueError(f"an extension has to begin with a dot, and {encoded!r} does not")
        return self.with_name(stem_of(self.name) + encoded)

    def relative_to(self, other: bytes | str | SFTPPath) -> SFTPPath:
        """This path expressed below ``other``.

        Byte comparison per component: no folding, no symlink resolution, and no round trip.
        **The result is still a remote name**, so turning it into a local one goes through
        :func:`~gantry_sftp.session.local_child` per component rather than through
        ``os.fsdecode`` -- that check is the zip-slip defence and this method is not it.

        Raises:
            ValueError: If this path is not below ``other``.
        """
        target = _encode(other) if not isinstance(other, SFTPPath) else bytes(other)
        rest = relative_components(self._path, target)
        if rest is None:
            raise ValueError(f"{self._path!r} is not below {target!r}")
        return self._derive(_SEPARATOR.join(rest) if rest else _DOT)

    def is_relative_to(self, other: bytes | str | SFTPPath) -> bool:
        """Whether :meth:`relative_to` would answer rather than raise."""
        target = _encode(other) if not isinstance(other, SFTPPath) else bytes(other)
        return relative_components(self._path, target) is not None

    def match(self, pattern: bytes | str, *, case_sensitive: bool = True) -> bool:
        """Whether this path matches a pattern, without asking the server anything.

        The dialect is :meth:`~gantry_sftp.session.Session.glob`'s and so is the leading-dot
        rule: ``*`` does not match a name beginning with a period, which is what keeps a filter
        over a drop directory from picking up half-written staging files. An absolute pattern
        must account for the whole path; a relative one is matched from the right. ``**``
        crosses levels in both, which is why there is no separate full-path method.

        Args:
            pattern: The pattern.
            case_sensitive: Fold ASCII case when ``False``. Non-ASCII bytes are never folded,
                because which bytes are letters is a property of a locale the protocol never
                states.

        Returns:
            Whether it matches.

        Raises:
            ValueError: If the pattern is empty or names a bracket sub-expression this library
                refuses.
        """
        return match_path(_encode(pattern), self._path, case_sensitive=case_sensitive)

    # --- the session -----------------------------------------------------------------------

    @property
    def session(self) -> Session | None:
        """The session this path operates through, or ``None`` for a pure path.

        Readable so that "is this bound, and to what" is answerable without reaching inside --
        a path is frequently passed around, and the alternative is callers guessing from
        whether a method raised.
        """
        return self._session

    def bind(self, session: Session) -> SFTPPath:
        """The same path, operating through ``session``.

        Returns a new path rather than mutating this one, so a path handed to something else
        cannot acquire a connection behind the caller's back.
        """
        return SFTPPath(self._path, session=session)

    @property
    def _bound(self) -> Session:
        """The session, or a refusal naming how to get one.

        Raises:
            StateError: If this path was constructed without a session.
        """
        if self._session is None:
            raise StateError(
                f"SFTPPath({self._path!r}) has no session, so it can do path arithmetic and "
                f"nothing else -- construct it with SFTPPath(path, session=...) or call "
                f".bind(session)"
            )
        return self._session

    # --- asking the server -----------------------------------------------------------------

    async def stat(self) -> Attrs:
        """Attributes of the file, following symlinks."""
        return await self._bound.stat(self._path)

    async def lstat(self) -> Attrs:
        """Attributes of the file, not following a final symlink."""
        return await self._bound.lstat(self._path)

    async def exists(self, *, follow_symlinks: bool = True) -> bool:
        """Whether the path is there.

        ``False`` means ``NO_SUCH_FILE`` and nothing else -- a refusal raises, because reporting
        a path as free when something you cannot see is on it is answered by the line after,
        which is almost always a create.
        """
        return await self._bound.exists(self._path, follow_symlinks=follow_symlinks)

    async def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        """Whether it is a directory.

        Raises:
            CapabilityError: If the server sent no permission bits, so the type is unknown --
                a definite "not a directory" would be a guess about a question it declined.
        """
        return await self._bound.isdir(self._path, follow_symlinks=follow_symlinks)

    async def is_file(self, *, follow_symlinks: bool = True) -> bool:
        """Whether it is a regular file. See :meth:`is_dir` for the unknown-type case."""
        return await self._bound.isfile(self._path, follow_symlinks=follow_symlinks)

    async def is_symlink(self) -> bool:
        """Whether it is a symbolic link. See :meth:`is_dir` for the unknown-type case."""
        return await self._bound.islink(self._path)

    async def size(self) -> int | None:
        """The size in bytes, or ``None`` if the server reported no size for a file that exists."""
        return await self._bound.getsize(self._path)

    async def mtime(self) -> datetime | None:
        """Last modification as an aware UTC :class:`~datetime.datetime`, or ``None``.

        Aware and UTC rather than a float, because a bare epoch number at a call site becomes
        ``datetime.fromtimestamp(x)`` and then silently the client's local wall clock.
        """
        return await self._bound.getmtime(self._path)

    async def resolve(self) -> SFTPPath:
        """The canonical path, with ``..`` and symlinks resolved by the server.

        ``REALPATH``, so the answer is the server's. Note that it checks nothing: canonicalising
        a path that does not exist succeeds on OpenSSH.
        """
        return self._derive(await self._bound.realpath(self._path))

    async def readlink(self) -> SFTPPath:
        """Where this symlink points, as the server stored it.

        The result is **attacker-controlled** and may be relative, absolute, or a name that
        escapes anything you were confining to -- it is returned rather than resolved for
        exactly that reason.
        """
        return self._derive(await self._bound.readlink(self._path))

    async def symlink_to(self, target: bytes | str | SFTPPath) -> None:
        """Create this path as a symlink pointing at ``target``.

        ``target`` is stored inside the link and interpreted by the server relative to the
        link's own directory, so it is not resolved against the session's working directory --
        the one path argument in this library that is deliberately exempt.
        """
        await self._bound.symlink(_as_bytes(target), self._path)

    async def chmod(self, mode: int, *, follow_symlinks: bool = True) -> None:
        """Set permission bits.

        Args:
            mode: The bits, as :func:`os.chmod` takes them.
            follow_symlinks: Act on the link's target rather than on the link. Setting a
                *link's* own mode needs ``lsetstat@openssh.com`` and fails on Linux regardless,
                which has no ``lchmod``.
        """
        await self._bound.chmod(self._path, mode, follow_symlinks=follow_symlinks)

    # --- directories -----------------------------------------------------------------------

    async def iterdir(self) -> AsyncGenerator[SFTPPath]:
        """Yield each entry of this directory as a path, streaming.

        Every name is checked before it is joined, so an entry the server named ``../x`` is an
        :class:`~gantry_sftp.exceptions.UnsafePathError` rather than a path somewhere else.
        ``.`` and ``..`` are excluded, as they are from every listing here.

        The attributes the listing carried are dropped, because a path is a name. Where they
        matter -- a size, a type, a timestamp per entry -- use
        :meth:`~gantry_sftp.session.Session.scandir`, which hands back the whole
        :class:`~gantry_sftp.session.DirEntry` and costs no extra round trip.

        Breaking out of the loop finalises the directory handle only if the generator is closed;
        wrap it in :func:`~contextlib.aclosing` on trio, where dropping it does not.

        Yields:
            One bound path per entry.
        """
        session = self._bound
        async with session.scandir(self._path) as scan:
            async for entry in scan:
                yield self / entry.filename

    async def glob(
        self, pattern: bytes | str, *, max_depth: int | None = None, case_sensitive: bool = True
    ) -> AsyncGenerator[SFTPPath]:
        """Match a pattern below this path, streaming each match as it is found.

        The pattern is relative to this path and is the caller's, so it may contain separators
        and ``**``; the *names* it matches are the server's, and each one is validated before it
        becomes a path. An absolute pattern is refused rather than silently ignoring the path it
        was called on.

        Args:
            pattern: Relative pattern, in :meth:`~gantry_sftp.session.Session.glob`'s dialect.
            max_depth: Levels of ``**`` to descend, or ``None`` for no limit.
            case_sensitive: Fold ASCII case in the matched names when ``False``.

        Yields:
            One bound path per match. Where the entry's attributes matter, use
            :meth:`~gantry_sftp.session.Session.glob`, which yields
            :class:`~gantry_sftp.session.GlobMatch` carrying them.

        Raises:
            ValueError: If the pattern is absolute, empty, or refused by the dialect.
        """
        encoded = _encode(pattern)
        if encoded.startswith(_ROOT):
            raise ValueError(
                f"glob() takes a pattern relative to {self._path!r}, and {encoded!r} is "
                f"absolute -- call Session.glob for a pattern that names its own root"
            )
        session = self._bound
        matches = session.glob(
            join_remote(self._path, encoded), max_depth=max_depth, case_sensitive=case_sensitive
        )
        async for match in matches:
            yield self._derive(match.path)

    async def rglob(
        self, pattern: bytes | str, *, max_depth: int | None = None, case_sensitive: bool = True
    ) -> AsyncGenerator[SFTPPath]:
        """:meth:`glob`, applied at every level below this path.

        ``rglob(p)`` is exactly ``glob("**/" + p)``.

        Yields:
            One bound path per match.
        """
        encoded = _encode(pattern)
        prefixed = RECURSIVE + _SEPARATOR + encoded
        async for found in self.glob(prefixed, max_depth=max_depth, case_sensitive=case_sensitive):
            yield found

    async def mkdir(self, *, parents: bool = False, exist_ok: bool = False) -> None:
        """Create this directory.

        Args:
            parents: Create missing ancestors too. An existing *ancestor* is never an error
                either way; ``exist_ok`` governs this path only, matching :func:`os.makedirs`.
            exist_ok: Do not raise if this path is already a directory. A **file** in the way
                still raises, and the message says which of the two it was -- v3's ``FAILURE``
                carries no reason, so that costs one ``LSTAT`` on the already-failing path.
        """
        session = self._bound
        if parents:
            await session.makedirs(self._path, exist_ok=exist_ok)
            return
        await session.mkdir(self._path, exist_ok=exist_ok)

    async def rmdir(self) -> None:
        """Remove this directory, which must be empty."""
        await self._bound.rmdir(self._path)

    async def rmtree(self) -> TreeResult:
        """Remove this directory and everything below it.

        Symlinks are removed rather than followed. The result names what was skipped and why,
        so a partial removal is readable rather than silent.
        """
        return await self._bound.rmtree(self._path)

    async def unlink(self, *, missing_ok: bool = False) -> None:
        """Remove this file.

        Args:
            missing_ok: Return quietly if it is not there. Off by default, as
                :meth:`pathlib.Path.unlink`'s is.

        Raises:
            NoSuchFileError: If it is not there and ``missing_ok`` is false.
        """
        if not missing_ok:
            await self._bound.remove(self._path)
            return
        try:
            await self._bound.remove(self._path)
        except NoSuchFileError:
            return

    async def rename(self, target: bytes | str | SFTPPath) -> SFTPPath:
        """Rename to ``target``, which must not already exist.

        v3's ``RENAME`` refuses an existing destination, which is the one guarantee it has and
        the reason it is not :meth:`replace`.

        Returns:
            A bound path naming the destination.
        """
        destination = _as_bytes(target)
        await self._bound.rename(self._path, destination)
        return self._derive(destination)

    async def replace(self, target: bytes | str | SFTPPath) -> SFTPPath:
        """Rename to ``target``, replacing it atomically if it exists.

        ``posix-rename@openssh.com``, which is an **optional** extension: a server that does not
        advertise it raises :class:`~gantry_sftp.exceptions.CapabilityError` rather than falling
        back to a remove-then-rename, because that fallback has a window in which the
        destination does not exist and callers reach for this method precisely to avoid one.
        :meth:`~gantry_sftp.session.Session.put`'s atomic publish is the shape that degrades
        deliberately and reports which mechanism it got.

        Returns:
            A bound path naming the destination.
        """
        destination = _as_bytes(target)
        await self._bound.posix_rename(self._path, destination)
        return self._derive(destination)

    # --- bytes ------------------------------------------------------------------------------

    def open(self, pflags: OpenFlag = OpenFlag.READ, *, mode: int | None = None) -> RemoteFile:
        """Open this file as a cursor-bearing object, for ranges and streaming.

        A context manager, because it holds a server-side handle open. **One file object is one
        task**: the cursor is mutable shared state, so concurrent access goes through
        :meth:`~gantry_sftp.session.Session.readinto_at` and
        :meth:`~gantry_sftp.session.Session.write_at`, which take the offset as an argument.

        Args:
            pflags: Access and creation flags.
            mode: Permission bits for a file this call **creates**. Omitting it means the server
                applies ``0666 & ~umask`` -- see :data:`DEFAULT_WRITE_MODE`.

        Returns:
            An unopened :class:`~gantry_sftp.session.RemoteFile`. Nothing is sent until it is
            entered.
        """
        return self._bound.open_file(self._path, pflags, mode=mode)

    async def read_bytes(self) -> bytes:
        """The whole file.

        Pipelined, so this is not a request per block; but it is also the whole file in memory,
        which for anything large is what :meth:`download` and :meth:`open` are for.
        """
        async with self.open() as remote:
            return await remote.read()

    async def write_bytes(self, data: bytes | memoryview, *, mode: int = DEFAULT_WRITE_MODE) -> int:
        """Replace the file's contents with ``data``, creating it if needed.

        **This is not an atomic publish.** The file is truncated and then written, so a reader
        polling the directory can see it empty or half-written --
        :meth:`~gantry_sftp.session.Session.put` is the method that stages and renames, and
        DESIGN.md 6 calls that partial read the single most common bug in production SFTP
        integrations. This one is here for the small-file case where the caller knows nobody is
        watching.

        Args:
            data: The bytes.
            mode: Permission bits for a file this call creates, defaulting to
                :data:`DEFAULT_WRITE_MODE` rather than to the server's world-readable ``0666``.

        Returns:
            The number of bytes written.
        """
        flags = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
        async with self.open(flags, mode=mode) as remote:
            return await remote.write(data)

    async def read_text(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        """The whole file, decoded.

        Args:
            encoding: Text encoding. The protocol states none, so this is the caller's claim
                about the file rather than something discovered.
            errors: As :meth:`bytes.decode` takes it.
        """
        return (await self.read_bytes()).decode(encoding, errors)

    async def write_text(
        self,
        data: str,
        encoding: str = "utf-8",
        errors: str = "strict",
        *,
        mode: int = DEFAULT_WRITE_MODE,
    ) -> int:
        """Encode ``data`` and write it. See :meth:`write_bytes` for what this is not.

        Returns:
            The number of **bytes** written, which is not ``len(data)`` unless the text is ASCII.
        """
        return await self.write_bytes(data.encode(encoding, errors), mode=mode)

    # --- transfers ---------------------------------------------------------------------------

    async def download(
        self,
        local_path: Path | str,
        *,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
        no_follow: bool = False,
        resume: bool = False,
        verify_size: bool = True,
        verify: Verify = Verify.SIZE,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
    ) -> DownloadResult:
        """Download this file to ``local_path``.

        Every argument is :meth:`~gantry_sftp.session.Session.get`'s and means what it means
        there, including that the local path is a :class:`~pathlib.Path` or a ``str`` while this
        one is bytes -- the two sides of a transfer have different types on purpose.

        Returns:
            What the download did, including whether a resume or a verification ran.
        """
        return await self._bound.get(
            self._path,
            local_path,
            progress=progress,
            depth=depth,
            no_follow=no_follow,
            resume=resume,
            verify_size=verify_size,
            verify=verify,
            preserve_times=preserve_times,
            mode=mode,
        )

    async def upload(
        self,
        local_path: Path | str,
        *,
        publish: Publish | None = None,
        resume: bool = False,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        verify: Verify = Verify.SIZE,
        progress: ProgressCallback | None = None,
        depth: int | None = None,
    ) -> UploadResult:
        """Upload ``local_path`` to this path, publishing it atomically by default.

        Every argument is :meth:`~gantry_sftp.session.Session.put`'s. The deprecated spellings
        of the publish flags are **not** forwarded: this surface is new, so it has no old
        callers to keep working, and ``publish=Publish(...)`` is the one spelling here.

        Returns:
            What the upload did, including which publish mechanism actually ran.
        """
        return await self._bound.put(
            local_path,
            self._path,
            publish=publish,
            resume=resume,
            preserve_times=preserve_times,
            mode=mode,
            verify=verify,
            progress=progress,
            depth=depth,
        )

    @overload
    async def download_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        progress: ProgressCallback | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[False] = ...,
    ) -> TreeResult: ...

    @overload
    async def download_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        progress: ProgressCallback | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[True],
    ) -> TreePlan: ...

    @overload
    async def download_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        progress: ProgressCallback | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: bool,
    ) -> TreeResult | TreePlan: ...

    async def download_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = None,
        progress: ProgressCallback | None = None,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        resume: bool = False,
        concurrency: int = 1,
        dry_run: bool = False,
    ) -> TreeResult | TreePlan:
        """Download this directory into ``local_path``, refusing to escape it.

        Every argument is :meth:`~gantry_sftp.session.Session.get_tree`'s, and so is the
        zip-slip defence: each server-supplied name is validated, and the finished local path is
        re-checked against the destination after symlinks are resolved. ``dry_run=True`` reports
        what the download would do and writes nothing, returning a
        :class:`~gantry_sftp.session.TreePlan`; what a preview cannot determine is
        :meth:`~gantry_sftp.session.Session.get_tree`'s to explain and is listed there.

        Returns:
            What was transferred and what was skipped, with a reason for each skip -- or a
            :class:`~gantry_sftp.session.TreePlan` when ``dry_run`` is set.
        """
        return await self._bound.get_tree(
            self._path,
            local_path,
            max_depth=max_depth,
            progress=progress,
            preserve_times=preserve_times,
            mode=mode,
            resume=resume,
            concurrency=concurrency,
            dry_run=dry_run,
        )

    @overload
    async def upload_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        publish: Publish | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        progress: ProgressCallback | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[False] = ...,
    ) -> TreeResult: ...

    @overload
    async def upload_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        publish: Publish | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        progress: ProgressCallback | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: Literal[True],
    ) -> TreePlan: ...

    @overload
    async def upload_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = ...,
        publish: Publish | None = ...,
        preserve_times: bool = ...,
        mode: int | Mode | str | None = ...,
        progress: ProgressCallback | None = ...,
        resume: bool = ...,
        concurrency: int = ...,
        dry_run: bool,
    ) -> TreeResult | TreePlan: ...

    async def upload_tree(
        self,
        local_path: Path | str,
        *,
        max_depth: int | None = None,
        publish: Publish | None = None,
        preserve_times: bool = False,
        mode: int | Mode | str | None = None,
        progress: ProgressCallback | None = None,
        resume: bool = False,
        concurrency: int = 1,
        dry_run: bool = False,
    ) -> TreeResult | TreePlan:
        """Upload the local tree at ``local_path`` into this directory.

        Every argument is :meth:`~gantry_sftp.session.Session.put_tree`'s. Local symlinks are
        reported and never followed, which is this direction's hazard rather than the download's.
        ``dry_run=True`` reports what the upload would do and sends nothing that writes; an
        upload preview is silent about the destination, and
        :meth:`~gantry_sftp.session.Session.put_tree` explains why.

        Returns:
            What was transferred and what was skipped, with a reason for each skip -- or a
            :class:`~gantry_sftp.session.TreePlan` when ``dry_run`` is set.
        """
        return await self._bound.put_tree(
            local_path,
            self._path,
            max_depth=max_depth,
            publish=publish,
            preserve_times=preserve_times,
            mode=mode,
            progress=progress,
            resume=resume,
            concurrency=concurrency,
            dry_run=dry_run,
        )


def _as_bytes(path: bytes | str | SFTPPath) -> bytes:
    """A path argument of any accepted spelling, as the bytes that go on the wire."""
    return bytes(path) if isinstance(path, SFTPPath) else _encode(path)

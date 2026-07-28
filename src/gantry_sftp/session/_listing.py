"""Directory entries, and the two things a listing must not pretend to know.

READDIR hands back a filename, a display string, and an ATTRS the server was free to make
up. Turning that into something usable is where clients quietly lie:

**A missing attribute is not a false one.** v3 ATTRS fields are all optional and DESIGN.md 7
lists attribute honesty among the things real endpoints differ on. If a server does not send
permissions, ``is_dir`` cannot be ``False`` -- that answer makes a recursive walk skip every
directory on that server, silently, and the walk still looks like it worked. So the type is
:class:`EntryKind` with an ``UNKNOWN`` member and the caller decides, exactly as a limits
field of ``0`` is normalised to ``None`` rather than believed.

**``longname`` is a display string with no format.** From READDIR it is an ``ls -l``-style
line, from REALPATH it is the bare path -- measured, same server, same session. It is
surfaced verbatim and never parsed here. Scraping it for an owner name is reading somebody's
idea of a column layout; ``users-groups-by-id@openssh.com`` is the structured answer.

**And it is not a timestamp either**, which is the trap most worth naming because the string
looks like it carries one. OpenSSH's ``ls_file`` prints ``%b %e %H:%M`` for a file modified
within the last half year and ``%b %e  %Y`` for anything else -- so a recent file has no year,
an older one has no time, and neither has both. A *future* mtime falls to the year branch too,
because the guard is ``now >= st_mtime``. If ``localtime()`` returns ``NULL`` the field is
emitted empty. And it is rendered in the **server's** timezone: the same instant reads as
``Jun 23  2025`` under ``TZ=UTC`` and ``Jun 24  2025`` under ``TZ=Asia/Tokyo`` -- a different
calendar day, with nothing in the reply saying which offset to undo. All four measured against
OpenSSH 10.0p2. :func:`modified_at` reads the structured field instead, which is exact.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from gantry_sftp.codec import Attrs, NameEntry

__all__ = [
    "DOT_ENTRIES",
    "DirEntry",
    "EntryKind",
    "accessed_at",
    "decode_name",
    "entry_kind",
    "modified_at",
]

DOT_ENTRIES = (b".", b"..")
"""Names a directory listing must not hand back.

OpenSSH's READDIR includes both -- measured, not assumed. Passing them on makes any
recursion that follows directories loop forever, and it is the caller who pays, so they are
filtered here rather than documented as the caller's job. A server that omits them is equally
legal and needs no special case.
"""


class EntryKind(StrEnum):
    """What a directory entry is, including "the server did not say"."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"
    """A socket, fifo, or device node. Real, and not something to transfer."""

    UNKNOWN = "unknown"
    """The server sent no permissions, so there is nothing to derive this from.

    Not a synonym for ``FILE``. Code that must know asks with ``stat``; code that guesses
    here is the reason recursive downloads silently skip directories on some servers."""


def entry_kind(attrs: Attrs) -> EntryKind:
    """Classify an entry from its mode bits.

    v3 sends the full ``st_mode``, so the file-type bits are in ``permissions`` alongside the
    permission bits -- ``0o40755`` is a directory, not a permission of 40755.

    Args:
        attrs: Attributes from a NAME entry or a STAT.

    Returns:
        The kind, or :attr:`EntryKind.UNKNOWN` when the server sent no permissions at all.
    """
    mode = attrs.permissions
    if mode is None:
        return EntryKind.UNKNOWN
    if stat.S_ISDIR(mode):
        return EntryKind.DIRECTORY
    if stat.S_ISLNK(mode):
        return EntryKind.SYMLINK
    if stat.S_ISREG(mode):
        return EntryKind.FILE
    return EntryKind.OTHER


def modified_at(attrs: Attrs) -> datetime | None:
    """When the file was last modified, as an aware UTC datetime, or ``None`` if unstated.

    ``None`` is the load-bearing half of the return type. ``times`` is absent whenever a server
    did not set ``ACMODTIME``, and the obvious coercion -- treat absent as ``0`` -- dates the
    file to 1970, which reads as "very old" to every ``if remote > local`` in the world. A sync
    built on that either re-transfers everything or skips everything, depending on which way
    the comparison runs, and looks correct while doing it.

    **Aware, and UTC.** v3 timestamps are seconds since the epoch, which name an instant rather
    than a wall-clock reading, so there is nothing to interpret and no timezone to guess. The
    reason to return an aware value anyway is the one mistake this function exists to remove:
    ``datetime.fromtimestamp(ts)`` with no ``tz`` yields the *client's* local wall clock, which
    then silently disagrees with anything rendered server-side.

    Two limits it cannot lift. v3 has no sub-second field, so this is second-granular and mtime
    alone is not a change detector. And the field is a ``uint32``: usable to 2106-02-07 read as
    unsigned, while a server that treats it as signed wraps at 2038-01-19 instead.

    Args:
        attrs: Attributes from a NAME entry or a STAT.

    Returns:
        The modification time, or ``None`` where the server reported no times at all.
    """
    if attrs.times is None:
        return None
    return datetime.fromtimestamp(attrs.times.mtime, UTC)


def accessed_at(attrs: Attrs) -> datetime | None:
    """When the file was last accessed, as an aware UTC datetime, or ``None`` if unstated.

    The companion to :func:`modified_at`, and worth less than it looks: atime is updated by
    *reading*, so downloading a file changes the source's, and most filesystems mount
    ``relatime`` and barely maintain it at all. It is surfaced because v3 sends it and because
    the pair is set together -- see :class:`~gantry_sftp.codec.Times` -- not because it is
    evidence of much.

    Args:
        attrs: Attributes from a NAME entry or a STAT.

    Returns:
        The access time, or ``None`` where the server reported no times at all.
    """
    if attrs.times is None:
        return None
    return datetime.fromtimestamp(attrs.times.atime, UTC)


def decode_name(filename: bytes) -> str:
    """Decode a server-supplied name for display, reversibly.

    ``surrogateescape``, matching how :func:`~gantry_sftp.session.Session.put` encodes a
    ``str`` path on the way out: a name that is not valid UTF-8 survives the round trip and
    can be sent back byte-for-byte. Without that, the files whose names are the reason you
    needed a listing are exactly the files you cannot then open.
    """
    return filename.decode("utf-8", "surrogateescape")


@dataclass(frozen=True, slots=True)
class DirEntry:
    """One entry from a directory listing, with the attributes the server volunteered.

    Attributes come *with* the listing in v3, so they are kept rather than discarded. A
    client that returns names alone forces a STAT per entry, which is a round trip per file
    and the reason listing a large directory is slow in every paramiko-based tool.

    Attributes:
        filename: The name, exactly as the server sent it. Bytes, because it is not
            guaranteed to be text and is attacker-controlled either way.
        longname: A display string with no guaranteed format. Never parsed.
        attrs: What the server said about the entry, any field of which may be absent.
    """

    filename: bytes
    longname: bytes
    attrs: Attrs

    @classmethod
    def from_name_entry(cls, entry: NameEntry) -> DirEntry:
        """Adapt a codec NAME entry, which is a wire record rather than an ergonomic one."""
        return cls(filename=entry.filename, longname=entry.longname, attrs=entry.attrs)

    @property
    def name(self) -> str:
        """:attr:`filename` decoded for display, and reversibly -- see :func:`decode_name`."""
        return decode_name(self.filename)

    @property
    def kind(self) -> EntryKind:
        """What this is, or :attr:`EntryKind.UNKNOWN` if the server did not say."""
        return entry_kind(self.attrs)

    @property
    def is_dir(self) -> bool:
        """Whether this is *known* to be a directory.

        ``False`` covers both "a file" and "the server did not say", which is the safe way
        round for a recursive walk -- it under-recurses rather than looping -- but it is a
        conflation. Read :attr:`kind` where the difference matters.
        """
        return self.kind is EntryKind.DIRECTORY

    @property
    def is_file(self) -> bool:
        """Whether this is *known* to be a regular file. See :attr:`is_dir` on the ``False``."""
        return self.kind is EntryKind.FILE

    @property
    def is_symlink(self) -> bool:
        """Whether this is *known* to be a symlink, which READDIR reports without following."""
        return self.kind is EntryKind.SYMLINK

    @property
    def size(self) -> int | None:
        """Size in bytes, or ``None`` where the server did not report one."""
        return self.attrs.size

    @property
    def modified(self) -> datetime | None:
        """Modification time as an aware UTC datetime, or ``None`` if the server said nothing.

        Read this rather than :attr:`longname`, which cannot carry a usable timestamp -- see
        the module docstring for the four separate ways it fails. See :func:`modified_at` for
        why the ``None`` matters and what second-granularity costs.
        """
        return modified_at(self.attrs)

    @property
    def accessed(self) -> datetime | None:
        """Access time as an aware UTC datetime, or ``None`` if the server said nothing."""
        return accessed_at(self.attrs)

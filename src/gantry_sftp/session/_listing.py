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
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from enum import StrEnum

from gantry_sftp.codec import Attrs, NameEntry

__all__ = ["DOT_ENTRIES", "DirEntry", "EntryKind", "decode_name", "entry_kind"]

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

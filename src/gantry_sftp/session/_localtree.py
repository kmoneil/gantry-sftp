"""Walking a *local* tree, for the direction where the names are ours.

The mirror image of :meth:`~gantry_sftp.session.Session.walk`, and the asymmetry is the whole
point of having a separate module for it. Downloading a tree means every name arrives from
the far end and has to be refused before it becomes a path -- that is
:mod:`gantry_sftp.session._localpath`, and it is the zip-slip defence. Uploading one reverses
that: the names come from the local filesystem, so the attacker-controlled input is simply
gone, and none of that machinery applies.

What replaces it is smaller but not nothing:

**Symlinks are not followed, in either direction.** A link in the upload tree pointing at
``/etc/shadow`` would otherwise copy it to the server under an innocent name -- an exfiltration
primitive built out of a mirroring tool. So this walk never follows one, which matches what
:meth:`Session.walk` does going the other way and for a comparable reason.

**A name still has to survive becoming a remote path component.** On both POSIX and Windows a
filename cannot contain the separator, so the reversal really does hold -- but
:func:`remote_component` asserts it rather than trusting it. It is one comparison per name and
it is the check that would catch a bug in our own joining, which is the failure mode left once
the hostile input is gone.

**Everything is classified with the same function the remote side uses.** A local
``st_mode`` and a v3 ``ATTRS`` ``permissions`` field are the same bits, so
:func:`~gantry_sftp.session.entry_kind` classifies both and a skipped entry reports
identically whichever direction it was skipped in. One report type, one vocabulary.

Blocking on purpose
-------------------
Nothing here is ``async``. ``os.scandir`` and ``os.stat`` are blocking calls, and ASYNC240 is
right to say so -- but they are local metadata operations rather than transfers, so they are
not worth a thread. Keeping them in plain functions puts them where the lint rule can see
them, and has the side benefit that this whole module is testable against a ``tmp_path`` with
no event loop, no transport and no server.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from gantry_sftp.codec import Attrs, Times
from gantry_sftp.exceptions import UnsafePathError
from gantry_sftp.session._listing import DirEntry, EntryKind, entry_kind
from gantry_sftp.session._recursive import Skipped, SkipReason, remote_component_reason

__all__ = [
    "LocalWalkEntry",
    "local_dir_entry",
    "remote_component",
    "times_from_stat",
    "walk_local",
]


def remote_component(name: bytes) -> bytes:
    """Refuse a local filename that must not become a single remote path component.

    The reverse of :func:`~gantry_sftp.session.check_component`, and deliberately not the same
    list: the Windows device names and forbidden characters are rules about what may be
    *written locally*, and applying them here would refuse to upload files that exist and are
    perfectly legal on the machine they are being read from.

    Args:
        name: One local filename, already encoded with :func:`os.fsencode`.

    Returns:
        ``name`` unchanged, so this reads as a pass-through at the call site.

    Raises:
        UnsafePathError: If the name could not be one remote path component.
    """
    reason = remote_component_reason(name)
    if reason is None:
        return name
    raise UnsafePathError(
        f"refusing to send the local name {name!r} as a remote path component: "
        f"it contains {reason}",
        name=name,
        reason=reason,
    )


def times_from_stat(stat_result: os.stat_result) -> Times:
    """A local ``stat``'s atime and mtime, truncated to the seconds filexfer v3 can carry.

    ``int()`` rather than ``round()``: rounding a timestamp *up* invents a modification that
    has not happened yet, and a file dated one second into the future is exactly what makes a
    "modified since" sweep behave differently between two runs of the same upload.

    Here rather than beside its other caller because this module is imported by that one and
    not the reverse, and the rule is worth having once. :func:`~gantry_sftp.session.sync_tree`
    compares against these values, so the truncation is part of a comparison rather than only
    of a ``preserve_times`` write: a mirror that compared a float against a wire timestamp
    would find every file changed, every run (D-164).
    """
    return Times(atime=int(stat_result.st_atime), mtime=int(stat_result.st_mtime))


def local_dir_entry(name: bytes, stat_result: os.stat_result) -> DirEntry:
    """Adapt a local name and ``stat`` into the entry type a report is written in.

    Not a pretence that a local file came off the wire: :class:`DirEntry` is a name plus
    whatever attributes are known, and ``st_mode`` carries exactly the file-type bits v3 puts
    in ``permissions``. Sharing it means a :class:`~gantry_sftp.session.Skipped` reads the same
    whichever direction produced it, instead of two parallel report types that drift.

    ``longname`` is empty because there is no display string to have: it is an ``ls -l`` line
    the *server* composed, and inventing one locally would be inventing a format nobody asked
    for.

    **Times are carried as of D-164**, and they were not before. A mirror compares a local
    entry against what it recorded sending, so an entry that dropped its modification time made
    the comparison unbuildable from this type -- and this is the type both directions already
    share. Truncated on the way in by :func:`times_from_stat`, so what is compared is what the
    protocol can carry rather than what the local filesystem happens to store.
    """
    return DirEntry(
        filename=name,
        longname=b"",
        attrs=Attrs(
            size=stat_result.st_size,
            permissions=stat_result.st_mode,
            times=times_from_stat(stat_result),
        ),
    )


@dataclass(frozen=True, slots=True)
class LocalWalkEntry:
    """One local directory, as the upload walk reports it.

    The local counterpart of :class:`~gantry_sftp.session.WalkEntry`, and a separate type
    rather than a reused one because ``path`` here is a real :class:`~pathlib.Path` on this
    machine, not a remote path the server owns. Conflating those two is how a local path ends
    up sent to a server.

    Attributes:
        path: This directory, locally.
        relative: The names descended through to reach it, from the walk root. Empty for the
            root itself. Carried as *components* so the remote path is built one validated
            piece at a time rather than by re-parsing a joined string.
        directories: Subdirectory names this walk will descend into.
        files: Regular file names to upload.
        skipped: Everything else, with a reason.
    """

    path: Path
    relative: tuple[bytes, ...]
    directories: tuple[bytes, ...]
    files: tuple[bytes, ...]
    skipped: tuple[Skipped, ...] = ()


def walk_local(root: Path, *, max_depth: int | None = None) -> Iterator[LocalWalkEntry]:
    """Walk a local tree, top down, yielding one entry per directory.

    Top down because the remote side needs it that way: a directory has to exist before
    anything can be written into it, and descending in this order means every parent has
    already been created by the time its children are reached.

    Entries are sorted by name. ``os.scandir`` returns them in whatever order the filesystem
    stores them, which is stable for nobody -- and an upload whose order changes between runs
    makes a report impossible to diff and a test impossible to pin.

    Args:
        root: Directory to walk. Followed if it is itself a symlink, because the caller named
            it explicitly; nothing *inside* it is.
        max_depth: Levels below the root to descend, or ``None`` for no limit. ``0`` yields the
            root and nothing else, matching :meth:`~gantry_sftp.session.Session.walk`.

    Yields:
        One :class:`LocalWalkEntry` per directory visited.

    Raises:
        OSError: If a directory cannot be read. Deliberately not swallowed into a skip: the
            download direction fails the whole transfer when it cannot read the far end, and a
            mirroring tool that silently omits the files it could not open has produced a
            wrong copy while reporting a right one.
    """
    pending: list[tuple[Path, tuple[bytes, ...]]] = [(root, ())]
    while pending:
        directory, relative = pending.pop()
        entry = _walk_one(directory, relative, max_depth=max_depth)
        yield entry
        # Reversed, so a stack pops them back into sorted order rather than mirrored.
        pending.extend(
            (directory / os.fsdecode(name), (*relative, name))
            for name in reversed(entry.directories)
        )


def _walk_one(
    directory: Path, relative: tuple[bytes, ...], *, max_depth: int | None
) -> LocalWalkEntry:
    """List one local directory and sort its entries into descend / upload / skip."""
    directories: list[bytes] = []
    files: list[bytes] = []
    skipped: list[Skipped] = []
    at_limit = max_depth is not None and len(relative) >= max_depth

    for name, stat_result in _scan(directory):
        kind = entry_kind(Attrs(permissions=stat_result.st_mode))
        if kind is EntryKind.DIRECTORY and at_limit:
            skipped.append(_skip(directory, name, stat_result, SkipReason.TOO_DEEP))
        elif kind is EntryKind.DIRECTORY:
            directories.append(name)
        elif kind is EntryKind.FILE:
            files.append(name)
        elif kind is EntryKind.SYMLINK:
            skipped.append(_skip(directory, name, stat_result, SkipReason.SYMLINK))
        else:
            skipped.append(_skip(directory, name, stat_result, SkipReason.NOT_A_FILE))

    return LocalWalkEntry(directory, relative, tuple(directories), tuple(files), tuple(skipped))


def _scan(directory: Path) -> list[tuple[bytes, os.stat_result]]:
    """Every name in ``directory`` with its own ``lstat``, sorted, symlinks unfollowed.

    ``follow_symlinks=False`` throughout. ``os.DirEntry.is_dir()`` follows by default, and a
    walk that used it would descend through a link and copy whatever it points at.
    """
    with os.scandir(directory) as scan:
        entries = [(os.fsencode(item.name), item.stat(follow_symlinks=False)) for item in scan]
    entries.sort(key=lambda item: item[0])
    return entries


def _skip(directory: Path, name: bytes, stat_result: os.stat_result, reason: str) -> Skipped:
    """Record one local entry the walk passed over."""
    return Skipped(
        path=os.fsencode(directory / os.fsdecode(name)),
        entry=local_dir_entry(name, stat_result),
        reason=reason,
    )

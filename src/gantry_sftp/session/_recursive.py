"""Walking a remote tree, and what a walk is allowed to assume.

Three facts decide the shape of everything here, and all three were measured rather than
reasoned about:

**A batch is not a directory.** ``READDIR`` returns what the server feels like returning --
100 entries on OpenSSH -- so every listing is a loop. That is :meth:`Session.listdir`'s
problem, not this module's, but a walk built on a client that forgot it would silently visit
the first hundred files of each directory and report success.

**``OPENDIR`` on a plain file answers ``NO_SUCH_FILE``, not ``FAILURE``.** ``ENOTDIR`` is
remapped, so a walk that treats that status as proof a path is gone is wrong about every file
it meets. Nothing here descends into something it has not established is a directory.

**The kind can be unknown, and unknown is not "file".** A server that sends no permissions
gives :attr:`DirEntry.is_dir` nothing to derive from. Guessing "file" makes a recursive
download silently skip every directory on that server; guessing "directory" makes it try to
list every file. So an unknown entry gets one ``LSTAT``, and if that settles nothing it is
*skipped with a reason* rather than silently sorted into a bucket.

Symlinks are reported and never followed. Following them needs loop detection, which needs
``REALPATH`` per directory, which is a round trip per directory to defend against something
that only a hostile or misconfigured server does -- so it is deliberately absent rather than
half-built, and the entries are surfaced so a caller can do it themselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gantry_sftp.session._listing import DirEntry

__all__ = [
    "SkipReason",
    "Skipped",
    "TreeResult",
    "WalkEntry",
    "join_remote",
]


def join_remote(parent: bytes, name: bytes) -> bytes:
    """Join a remote directory path and a single name.

    ``/`` always, and never ``os.path.join``: on a Windows *client* that would join with a
    backslash and produce a path no SFTP server understands. The separator belongs to the
    protocol, not to the machine running the client.
    """
    if not parent or parent.endswith(b"/"):
        return parent + name
    return parent + b"/" + name


class SkipReason:
    """Why a walk did not descend into, or count, an entry.

    Strings rather than an enum because these are for a human reading a report, and the set
    grows with what servers do rather than with what the protocol defines.
    """

    SYMLINK = "symlink, and symlinks are not followed"
    UNKNOWN_KIND = "the server reported no attributes, and a stat did not settle it"
    NOT_A_FILE = "not a regular file or directory"
    TOO_DEEP = "deeper than max_depth"
    DESTINATION_COLLISION = "the destination filesystem does not tell it apart from an earlier name"


@dataclass(frozen=True, slots=True)
class Skipped:
    """One entry a walk passed over, and why.

    Kept rather than dropped because "it worked, and here is what it did not do" is a
    different report from "it worked", and a recursive download that quietly ignores every
    symlink is one that quietly loses data.
    """

    path: bytes
    entry: DirEntry
    reason: str


@dataclass(frozen=True, slots=True)
class WalkEntry:
    """One directory, as a walk reports it.

    Attributes:
        path: Full remote path of this directory.
        relative: The names descended through to reach it, from the walk root. Empty for the
            root itself. Carried as *components* rather than as a joined path so a consumer
            building a local path validates each one, instead of re-parsing a string the
            server had a hand in.
        directories: Entries this walk will descend into.
        files: Regular files.
        skipped: Everything else, with a reason.
    """

    path: bytes
    relative: tuple[bytes, ...]
    directories: tuple[DirEntry, ...]
    files: tuple[DirEntry, ...]
    skipped: tuple[Skipped, ...] = ()


@dataclass(frozen=True, slots=True)
class TreeResult:
    """What a recursive transfer actually did.

    Attributes:
        files: Files transferred.
        directories: Directories created.
        transferred: Bytes moved, summed over the files.
        skipped: Entries that were not transferred, each with a reason. Present in full
            rather than counted, because "which ones" is the question anyone asks next.
    """

    files: int = 0
    directories: int = 0
    transferred: int = 0
    skipped: tuple[Skipped, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        """Whether everything encountered was transferred.

        ``False`` is not failure -- a skipped symlink is normal and expected. It is the flag
        that says the report is worth reading before treating the copy as a copy.
        """
        return not self.skipped

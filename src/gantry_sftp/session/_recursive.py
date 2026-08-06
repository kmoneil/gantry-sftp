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

from gantry_sftp.exceptions import UnsafePathError
from gantry_sftp.session._listing import DirEntry

__all__ = [
    "GlobMatch",
    "SkipReason",
    "Skipped",
    "TreeResult",
    "WalkEntry",
    "check_listed_name",
    "join_remote",
    "remote_component_reason",
]

_DOT_NAMES = (b".", b"..")


def join_remote(parent: bytes, name: bytes) -> bytes:
    """Join a remote directory path and a single name.

    ``/`` always, and never ``os.path.join``: on a Windows *client* that would join with a
    backslash and produce a path no SFTP server understands. The separator belongs to the
    protocol, not to the machine running the client.
    """
    if not parent or parent.endswith(b"/"):
        return parent + name
    return parent + b"/" + name


def remote_component_reason(name: bytes) -> str | None:
    """Why ``name`` cannot be one remote path component, or ``None`` if it can.

    Shared by both directions, which is the point of it living here beside
    :func:`join_remote` rather than in either side's module: the upload path asks it of a
    *local* filename before sending it, and a listing asks it of a name the *server* sent
    before joining it. Same predicate, opposite threat models, and two copies of it would
    have drifted.
    """
    if not name:
        return "an empty name"
    if name in _DOT_NAMES:
        return "a relative directory entry"
    if b"/" in name:
        return "a path separator"
    if b"\x00" in name:
        return "a NUL byte"
    return None


def check_listed_name(name: bytes, *, directory: bytes) -> bytes:
    """Refuse a name a *server* sent that must not be joined onto a remote path.

    The direction that matters: everything out of ``READDIR`` is chosen by the far end, and a
    name carrying ``/`` or ``..`` would silently turn one directory's listing into a path
    somewhere else in the namespace. On an honest server this never fires -- POSIX filenames
    cannot contain ``/`` -- so it costs one comparison per entry and refuses only a server that
    is lying about its own directory.

    It is not the zip-slip defence, which is :func:`~gantry_sftp.session.check_component` and
    guards the *local* destination. This one guards the remote path arithmetic, so that a path
    handed back to a caller is one this library built out of validated parts rather than one
    the server steered.

    Args:
        name: One entry name, exactly as the server sent it.
        directory: The listing it came from, for the error message.

    Returns:
        ``name`` unchanged, so this reads as a pass-through at the call site.

    Raises:
        UnsafePathError: If the name could not be one remote path component.
    """
    reason = remote_component_reason(name)
    if reason is None:
        return name
    raise UnsafePathError(
        f"refusing the server-supplied name {name!r} in the listing of {directory!r}: "
        f"it contains {reason}, so it is not one path component and this server is not "
        f"describing its own directory truthfully",
        name=name,
        reason=reason,
    )


class SkipReason:
    """Why a walk did not descend into, or count, an entry.

    Strings rather than an enum because these are for a human reading a report, and the set
    grows with what servers do rather than with what the protocol defines.
    """

    SYMLINK = "symlink, and symlinks are not followed"
    UNKNOWN_KIND = "the server reported no attributes, and a stat did not settle it"
    KIND_REFUSED = "the server reported no attributes, and refused the stat that would settle it"
    """Distinct from ``UNKNOWN_KIND`` since D-103, because they are different facts.

    That one is a server *answering* unhelpfully -- attributes with no type bits in them. This
    one is a server declining to answer at all, which is the condition ``glob`` raises on rather
    than skipping, because it has nowhere to record a skip. Which status the refusal carried is
    in the log record rather than here: this field is a sentence for a human reading a report,
    and the frame dump is where a diagnosis is done.
    """

    VANISHED = "listed, and then not there when it was stat'd"
    """A race with whoever else writes to that directory, not a refusal.

    The listing named it and the settling ``LSTAT`` answered ``NO_SUCH_FILE``. Reported rather
    than dropped for the same reason as everything else here: a walk that silently omits a name
    it *saw* is a walk whose output cannot be compared with the directory.
    """

    NOT_A_FILE = "not a regular file or directory"
    TOO_DEEP = "deeper than max_depth"
    DESTINATION_COLLISION = "the destination filesystem does not tell it apart from an earlier name"

    DESTINATION_REFUSED_THE_NAME = "the destination filesystem will not accept these name bytes"
    """A local rule the remote name breaks, which no test over remote names can see (D-150).

    APFS and HFS+ validate that a filename is UTF-8 and reject one that is not, so a name this
    library carries byte-exactly on Linux **cannot be placed on a Mac's disk at all**. The sibling
    above is the same class of fact -- the destination filesystem's rules, not the server's -- and
    both are reported rather than raised for the reason the whole of this class exists: one
    unlucky filename in a two-hundred-file tree must not cost the other hundred and ninety-nine.
    """


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
class GlobMatch:
    """One entry a pattern matched.

    Carries the **path** rather than only the name, and that is the security half of
    :meth:`Session.glob` rather than a convenience: the join from a server-supplied name to a
    path the caller will feed to ``get`` happens here, once, against a component that has
    already been checked, so a hand-rolled ``listdir`` plus match does not have to get it
    right.

    **This is not the only safe place to join, and saying otherwise sent readers back to the
    hazard** (D-97). A predicate that is not a pattern -- a regular expression, a watermark
    comparison, a size test, a manifest lookup -- cannot come through ``glob`` at all, and
    that caller is not stuck: :func:`check_listed_name` and :func:`join_remote` are public and
    are exactly what this class calls. Two lines at the call site build the same path this
    one carries.

    Attributes:
        path: Full remote path, built by joining validated components onto the pattern's own
            literal prefix. Safe to pass straight to :meth:`Session.get`.
        entry: The listing entry, so the kind and any attributes the server volunteered are
            available without a second round trip.
    """

    path: bytes
    entry: DirEntry

    @property
    def name(self) -> bytes:
        """The matched entry's own name, without its directory."""
        return self.entry.filename


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

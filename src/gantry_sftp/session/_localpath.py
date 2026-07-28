"""Turning a server-supplied name into a local path, or refusing to.

This is the zip-slip defence, and it is the reason a recursive download is not just a loop
around ``get``. A name from ``READDIR`` is chosen by the far end. A malicious or compromised
server that answers with ``../../etc/cron.d/x`` must not be able to write there, and this is a
genuine, exploited vulnerability class in file-transfer clients rather than a theoretical one.

**Two independent layers, because either one alone has a hole.**

*Component validation* rejects the name itself: separators, ``..``, the empty name, NUL, and
on Windows a longer list that includes things POSIX does not care about at all. It cannot see
anything about the destination.

*Containment* re-checks the finished path against the destination root after resolving
symlinks. This is what catches the escape the first layer cannot: every component is
individually innocent, but ``downloads/reports`` is already a symlink to ``/etc`` on the local
machine, put there by a local attacker or by an earlier download. `Path.resolve()` follows it;
``is_relative_to`` then says no.

**The rules are platform-dependent and the platform is injectable.** A backslash is a perfectly
ordinary character in a POSIX filename and a path separator on Windows; ``COM1`` is a file on
Linux and a device on Windows. Applying the union everywhere would refuse to download files
that are legal where they are being written, and applying the wrong set is a vulnerability. So
the rules follow the destination platform, and ``windows=`` exists so the Windows rules are
tested on Linux -- the same arrangement ``resolve_ssh_executable`` uses, and for the same
reason: the environment that matters is not the one CI runs on.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import override

from gantry_sftp.exceptions import UnsafePathError

__all__ = [
    "WINDOWS_FORBIDDEN_CHARACTERS",
    "WINDOWS_RESERVED_NAMES",
    "DestinationLedger",
    "check_component",
    "check_contained",
    "identity",
    "local_child",
    "unsafe_reason",
]

_DOT_NAMES = (b".", b"..")

WINDOWS_FORBIDDEN_CHARACTERS = b'\\:*?"<>|'
"""Characters Windows will not accept in a filename, beyond the POSIX separator.

``:`` is the one that matters most: ``file.txt:stream`` writes an alternate data stream, and
``C:evil`` is a drive-relative path. Both look like ordinary filenames.
"""

WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{digit}" for digit in range(1, 10)}
    | {f"lpt{digit}" for digit in range(1, 10)}
)
"""Device names Windows resolves *before* looking at the directory.

Opening ``CON`` writes to the console and ``LPT1`` to a printer port, from any directory, with
or without an extension -- ``con.txt`` is still the console. A server can therefore aim a
recursive download at a device by naming a file.
"""


def _windows_reason(name: bytes) -> str | None:
    """Why this name is unusable on Windows specifically, or ``None``."""
    if any(byte in name for byte in WINDOWS_FORBIDDEN_CHARACTERS):
        return "a character Windows does not allow in a filename"
    if any(byte < 32 for byte in name):  # noqa: PLR2004 -- ASCII control range
        return "a control character"
    if name.endswith((b".", b" ")):
        # Windows silently strips these, so `evil.txt.` and `evil.txt` are the same file --
        # which turns a name that passed validation into one that did not.
        return "a trailing dot or space, which Windows strips"
    stem = name.split(b".", 1)[0].decode("ascii", "replace").lower()
    if stem in WINDOWS_RESERVED_NAMES:
        return f"the reserved device name {stem!r}"
    return None


def unsafe_reason(name: bytes, *, windows: bool | None = None) -> str | None:
    """Why ``name`` may not be used as a single local filename, or ``None`` if it may.

    Args:
        name: One component, exactly as the server sent it.
        windows: Apply the Windows rules. Defaults to the platform this is running on.

    Returns:
        A short phrase naming the problem, suitable for an error message, or ``None``.
    """
    if not name:
        return "an empty name"
    if name in _DOT_NAMES:
        return "a relative directory entry"
    if b"/" in name:
        return "a path separator"
    if b"\x00" in name:
        return "a NUL byte"
    if windows if windows is not None else os.name == "nt":
        return _windows_reason(name)
    return None


def check_component(name: bytes, *, windows: bool | None = None) -> None:
    """Refuse a server-supplied name that must not become a local filename.

    Raises:
        UnsafePathError: If the name is not a safe single component.
    """
    reason = unsafe_reason(name, windows=windows)
    if reason is None:
        return
    raise UnsafePathError(
        f"refusing to use the server-supplied name {name!r}: it contains {reason}",
        name=name,
        reason=reason,
    )


def local_child(parent: Path, name: bytes, *, windows: bool | None = None) -> Path:
    """Join one validated server-supplied name onto a local directory.

    The name is decoded with :func:`os.fsdecode`, which is ``surrogateescape`` on POSIX, so a
    filename that is not valid UTF-8 is written back out as the same bytes it arrived as.

    Raises:
        UnsafePathError: If the name is not a safe single component.
    """
    check_component(name, windows=windows)
    return parent / os.fsdecode(name)


def check_contained(root: Path, candidate: Path) -> Path:
    """Refuse a path that resolves outside ``root``, and return it if it does not.

    The second layer, and the one component validation cannot replace: it resolves symlinks,
    so it catches a destination directory that is *already* a link somewhere else. Note what
    it cannot promise on its own -- between this check and the ``open`` that follows, a local
    attacker can still swap a component for a symlink, which is why the download opens with
    ``O_NOFOLLOW`` where the platform has it.

    Raises:
        UnsafePathError: If ``candidate`` is not inside ``root`` once symlinks are resolved.
    """
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved == resolved_root or resolved.is_relative_to(resolved_root):
        return candidate
    raise UnsafePathError(
        f"refusing to write outside the destination: {candidate} resolves to {resolved}, "
        f"which is not inside {resolved_root}",
        name=os.fsencode(candidate.name),
        reason="a path that escapes the destination directory",
        destination=str(root),
    )


def identity(path: Path) -> tuple[int, int]:
    """The filesystem's own name for a file: ``(st_dev, st_ino)``.

    ``lstat`` rather than ``stat``, and the difference is load-bearing twice. A symlink is its
    own file here rather than the one it points at, so a link somebody planted in the
    destination reports its own identity instead of reading as a collision with its target --
    and the link itself is already refused by the ``O_NOFOLLOW`` the download opens with. Two
    *names* that the filesystem folds into one file still share an inode, which is the case
    this exists to see.

    Raises:
        OSError: Whatever ``lstat`` raises. ``FileNotFoundError`` is the ordinary one and
            means the path is free.
    """
    status = path.lstat()
    return (status.st_dev, status.st_ino)


class DestinationLedger:
    """Which remote path each local file of a recursive download belongs to.

    **The filesystem decides what "the same file" means, and nothing in Python can.** A tree
    holding ``README.md`` and ``readme.md`` is legal on ext4 and is one file on APFS and NTFS;
    so is ``report.`` beside ``report`` on Windows, and an NFC/NFD pair on HFS+. Folding the
    names here would mean reimplementing that filesystem's own table -- three different tables
    -- and a wrong guess either refuses a legitimate pair or misses a real collision. Asking
    ``lstat`` after the write is authoritative on every filesystem and needs no table, because
    it never asks *why* two names became one file.

    That is also why this is stateful and lives beside the walk rather than in
    :func:`check_component`: a collision is a property of a *set* of names, and a per-name
    predicate has nothing to compare against.

    What it prevents: the second write truncating the first while ``get_tree`` reports
    success. :func:`check_contained` cannot catch that one -- both paths are legitimately
    inside the destination.
    """

    def __init__(self) -> None:
        self._claims: dict[tuple[int, int], bytes] = {}

    @override
    def __repr__(self) -> str:
        """Name how many local files have been claimed so far."""
        return f"<DestinationLedger {len(self._claims)} claimed>"

    def collides_with(self, local: Path) -> bytes | None:
        """The remote path this run already wrote to ``local``, or ``None`` if it is free.

        Three states, and the third is the one worth naming: the path is claimed, the path is
        absent, or ``lstat`` failed for some other reason. Absent answers ``None`` because a
        file that is not there cannot be overwritten. Anything else propagates -- the open
        that follows will fail on it too, and with a better message than this could give.
        """
        try:
            claimed = identity(local)
        except FileNotFoundError:
            return None
        return self._claims.get(claimed)

    def claim(self, local: Path, remote: bytes) -> None:
        """Record that ``remote`` is what is on disk at ``local``.

        Called after the write rather than before it: the file has to exist for the
        filesystem to have an opinion about its identity.
        """
        self._claims[identity(local)] = remote

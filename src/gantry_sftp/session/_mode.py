"""How a transferred file's permission bits are decided.

Until 0.10 they were not decided at all, and the asymmetry between the two directions is what
gave it away. The **download** side already opens its destination ``0o600`` "so a file is never
briefly world-readable while it is being written" -- see :meth:`Session._download_into` -- and
then leaves it there. The **upload** side sent an empty ATTRS on every ``OPEN``, and OpenSSH's
``process_open`` reads that ATTRS for ``PERMISSIONS`` and nothing else::

    mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
    fd = open(name, flags, mode);

So every file this library uploaded was created ``0666 & ~umask``, including the staging file an
atomic publish writes first, and there was no argument anywhere that could change it. That is a
wrong outcome rather than a missing convenience: a caller delivering a key, a credential file or
anything else with a ``0600`` requirement had no spelling for it, and a ``chmod`` issued after the
publish rename leaves the file readable in the window between the two.

**One parameter, not two.** ``mode=0o600`` and ``preserve_mode=True`` are mutually exclusive by
nature, so a single ``mode=`` taking either an integer or :data:`Mode.PRESERVE` makes the
contradiction unrepresentable rather than refused at runtime. It also gives the three states the
problem actually has -- leave it alone, set it to this, copy it from the source -- where
``preserve_times``' bool has only the two it needs.

**Why a refused mode fails the transfer when a refused timestamp does not.** A file published
with the wrong times is cosmetically wrong; a file published world-readable when ``0600`` was
asked for is the failure the argument exists to prevent, reported as success. See
:class:`~gantry_sftp.session.TimePreservation` for the other side of that trade, which is
deliberate and points the other way.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

__all__ = [
    "CREATE_BITS",
    "PERMISSION_BITS",
    "Mode",
    "create_bits",
    "local_mode",
    "resolve_mode",
]


PERMISSION_BITS = 0o7777
"""Every bit ``chmod(2)`` takes: the nine rwx bits, plus setuid, setgid and the sticky bit.

The same mask OpenSSH applies -- ``chmod(name, a.perm & 07777)`` in ``process_setstat`` -- so a
mode this library sends is a mode the reference server will use unchanged rather than one it
quietly narrows.
"""

CREATE_BITS = 0o0777
"""What a file is *created* with: :data:`PERMISSION_BITS` without setuid, setgid or sticky.

Those three are applied afterwards, by the ``FSETSTAT`` that sets the exact mode once the content
is complete. Creating a setuid file and *then* filling it would leave a window in which a
partially written file is already privileged, which is the same class of mistake as publishing a
half-written file and the reason atomic publish exists.

``umask`` only ever clears bits, so a file created with these is never **more** permissive than
the caller asked for -- which is what makes the create-then-set order safe in the direction that
matters. It can be less permissive, which the ``FSETSTAT`` then corrects.
"""


class Mode(StrEnum):
    """A permission policy that is not a literal mode.

    A :class:`~enum.StrEnum` for the same reason :class:`~gantry_sftp.session.Verify` is one:
    ``mode="preserve"`` from a caller who is not running a type checker reaches us as a plain
    ``str``, and normalising at the boundary means ``mode is Mode.PRESERVE`` downstream is not
    quietly ``False`` while ``==`` is ``True``.
    """

    PRESERVE = "preserve"
    """Carry the source file's own permission bits onto the destination.

    On an upload that is the local file's ``st_mode``; on a download it is what the server
    reported in ATTRS. A server is not obliged to report permissions at all, and a download that
    was asked to preserve them and was told nothing raises rather than silently leaving the
    destination at its ``0o600`` creation mode -- see :meth:`Session.get`.
    """


def resolve_mode(mode: int | Mode | str | None, *, caller: str) -> int | Mode | None:
    """Validate and normalise a ``mode=`` argument.

    Args:
        mode: What the caller passed: ``None`` to leave permissions to the destination's
            default, an integer to set exactly, or :data:`Mode.PRESERVE` (or the string
            ``"preserve"``) to copy them from the source.
        caller: The method name, for the message -- ``"put()"``, ``"get_tree()"``.

    Returns:
        ``None``, an ``int`` already masked to :data:`PERMISSION_BITS`, or
        :data:`Mode.PRESERVE`.

    Raises:
        TypeError: If ``mode`` is a ``bool``, or is neither an integer nor a string. ``bool`` is
            rejected explicitly *because* it is an ``int`` subclass: ``mode=True`` would
            otherwise mean ``0o1``, a file executable by others and readable by nobody, which is
            nothing any caller intends and is a plausible reflex from ``preserve_times=True``.
        ValueError: If ``mode`` is an integer outside ``0o0`` to ``0o7777``, or a string that is
            not a member of :class:`Mode`. A mode above the mask is usually a full ``st_mode``
            with its file-type bits still attached, so the message says so rather than silently
            masking them off -- silently accepting it would make ``mode=0o100644`` and
            ``mode=0o644`` the same call, and only one of them was meant.
    """
    if mode is None:
        return None
    if isinstance(mode, bool):
        raise TypeError(
            f"{caller} mode= must be an octal permission mode or Mode.PRESERVE, not a bool. "
            f"Pass mode=Mode.PRESERVE to carry the source file's own permissions across, or an "
            f"integer such as 0o600 to set them explicitly."
        )
    if isinstance(mode, str):
        # `Mode` is a StrEnum, so a `Mode` member lands here too and round-trips unchanged.
        try:
            return Mode(mode)
        except ValueError:
            raise ValueError(
                f"{caller} mode= must be an octal permission mode or one of "
                f"{[member.value for member in Mode]}, not {mode!r}"
            ) from None
    if not isinstance(mode, int):
        raise TypeError(
            f"{caller} mode= must be an octal permission mode or Mode.PRESERVE, not "
            f"{type(mode).__name__}"
        )
    if not 0 <= mode <= PERMISSION_BITS:
        raise ValueError(
            f"{caller} mode= must be between 0o0 and 0o7777, not {mode:#o}. A larger value is "
            f"usually a whole st_mode with its file-type bits still attached -- mask it with "
            f"0o7777, or pass Mode.PRESERVE and let the transfer read it from the source."
        )
    return mode


def create_bits(mode: int | Mode | None) -> int | None:
    """The mode a file should be *created* with, given the mode it should end up with.

    Returns:
        ``None`` where the caller asked for nothing and the destination's default stands, or the
        requested mode narrowed to :data:`CREATE_BITS`.

    Note:
        :data:`Mode.PRESERVE` answers ``None`` rather than a number, because at the moment a file
        is created the source's mode is either not yet known (a download resolves it from the
        ATTRS it has already fetched, but a tree resolves per file) or not worth a second
        ``stat``. The exact mode lands before the file is published either way, and the creation
        default is never *more* permissive than what follows it on any path here: an upload
        creates ``0666 & ~umask`` and a download creates ``0o600``.
    """
    if mode is None or mode is Mode.PRESERVE:
        return None
    return mode & CREATE_BITS


def local_mode(path: Path | str) -> int:
    """A local file's permission bits, with the file-type bits masked off.

    ``st_mode`` carries both -- v3 ATTRS ``permissions`` is the same field, which is exactly why
    :func:`~gantry_sftp.session.entry_kind` can read a listing's file type out of it -- and
    ``chmod(2)`` takes only the low twelve. Sending the type bits to a server would set the mode
    from a number that is mostly not a mode.
    """
    return Path(path).stat().st_mode & PERMISSION_BITS

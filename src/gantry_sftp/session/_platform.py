"""What this machine can do, as distinct from what the far end will do.

Every other module in ``session/`` asks the *server* what it supports. This one asks the local
platform, and it exists because two of the answers are load-bearing and neither is universal.

**Offset-addressed local I/O is Unix-only, and the data path is built on it.** ``get`` places
every payload with :func:`os.pwrite` at the offset the matching request asked for, ``put``
reads with :func:`os.pread` from a worker thread, and both are documented Unix-only in
CPython. That is not an implementation detail waiting to be swapped: writing at an explicit
offset is *why* writes need no ordering, why a short ``READ`` can be re-queued instead of
restarting the transfer, and why the upload side can read concurrently with no seek position
to serialise on. Stamping metadata has the same shape -- ``os.utime`` and ``os.fchmod`` on a
**descriptor** rather than a path, which is deliberate because re-opening the path to stamp it
would hand a second chance to whatever ``O_NOFOLLOW`` refused. Each is probed the way it can
be: ``os.utime`` is universal and takes a descriptor only where :data:`os.supports_fd` says so,
while ``os.fchmod`` either exists or does not.

So the four transfer operations refuse on such a platform, in one place, naming what is
missing -- rather than raising ``AttributeError: module 'os' has no attribute 'pwrite'`` four
frames inside a download loop, which is what happened before 0.9 and reads like a library bug.
The refusal is at ``get`` / ``get_tree`` / ``put`` / ``put_tree`` rather than deeper, because
that is where the operation still has the name the caller used; the helpers underneath are
reachable only through them.

Nothing else degrades. The ``ssh`` transport, the whole codec, and every operation that
touches only the remote side -- listing, stat, rename, remove, mkdir, rmtree, ``check-file``
-- are platform-independent and keep working. Windows is the platform this is about today, and
it is a scope statement rather than a bug: see the README's Requirements section.
"""

from __future__ import annotations

import os

__all__ = [
    "NO_FOLLOW",
    "missing_local_io",
    "require_local_io",
]

NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)
"""``O_NOFOLLOW`` where the platform has it, and ``0`` where it does not.

Windows has no equivalent, so the flag silently becomes nothing there rather than the open
failing. That is a documented weakness rather than a hidden one: on Windows the containment
check in ``_localpath`` is the whole defence, and it is checked before the open rather than
enforced by it. It is also, since 0.9, unreachable there in practice -- a download on a
platform without ``O_NOFOLLOW`` is a download on a platform without :func:`os.pwrite`, and
:func:`require_local_io` refuses before any of this is consulted.
"""

_OFFSET_IO = ("pread", "pwrite")


def missing_local_io() -> tuple[str, ...]:
    """Which offset-addressed local primitives this Python does not have.

    Returns:
        Their names, spelled as an error message should spell them, or an empty tuple where
        the platform has all of them.

    Note:
        Probed, never inferred from ``sys.platform``. The obstacle is the primitive being
        absent; a platform check would be a guess about *which* platforms those are, and it
        would go stale the day one of them grows a ``pwrite``. The same instinct as
        ``NO_FOLLOW`` above, which asks ``os`` rather than asking what system it is on.
    """
    missing = [f"os.{name}" for name in _OFFSET_IO if not hasattr(os, name)]
    if os.utime not in os.supports_fd:
        missing.append("os.utime on a descriptor")
    if not hasattr(os, "fchmod"):
        missing.append("os.fchmod")
    return tuple(missing)


def require_local_io(operation: str) -> None:
    """Refuse an operation that needs local I/O this platform cannot do.

    Args:
        operation: What the caller asked for, in their spelling -- ``"get()"``,
            ``"put_tree()"`` -- so the message names the call rather than the primitive
            underneath it, which the caller never chose.

    Raises:
        NotImplementedError: On a platform without offset-addressed local I/O, which today
            means Windows. The same class the askpass helper raises for the same kind of
            reason: our own refusal about *this machine*, as opposed to
            :class:`~gantry_sftp.exceptions.CapabilityError`, which is a refusal about the
            server.
    """
    missing = missing_local_io()
    if not missing:
        return
    raise NotImplementedError(
        f"{operation} is not supported on this platform: it needs "
        f"{', '.join(missing)}, which CPython provides on Unix only. The ssh transport "
        f"and every remote-only operation -- listdir, scandir, walk, stat, realpath, "
        f"rename, remove, mkdir, rmdir, rmtree, check_file -- work normally here; only "
        f"transfers between the remote side and a local file do not, and there is no "
        f"fallback. Use a POSIX host for transfers."
    )

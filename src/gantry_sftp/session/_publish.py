"""Atomic publish: what mechanism was used, and where the file was staged.

DESIGN.md 6 calls a half-written file visible to a consumer "the single most common bug in
production SFTP integrations", and the fix is old and well known: write to a sibling temp
name, flush it, then rename it over the target in one step. The part that is usually got
wrong is not the sequence, it is the *reporting*, because every step of it is an OpenSSH
extension that most of the field does not advertise.

So ``atomic=True`` is not a boolean promise here. It selects the strongest mechanism the
server actually supports and says which one that was, and a caller who needs the real thing
can demand it and get an error instead of a downgrade. Three mechanisms, measured against
OpenSSH 10.0p2 rather than assumed:

* ``posix-rename@openssh.com`` -- one step, overwrites, atomic. Confirmed on the wire: the
  target's contents afterwards are the source's, and the reply is ``OK``.
* plain v3 ``RENAME`` -- atomic **only because the target does not exist**. Confirmed on the
  wire that this is a real constraint and not pessimism: renaming onto an existing target
  answers ``FAILURE`` and changes nothing.
* ``REMOVE`` then ``RENAME`` -- the documented fallback, and the failure mode inverts rather
  than disappearing: instead of a consumer reading a partial file, a consumer reads *no*
  file. Usually better. Not always, and never silently.

This module is pure apart from the token generator: policy, names and arithmetic, so the
part that decides where a file gets staged is testable without a server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "MAX_STAGED_NAME_LENGTH",
    "Durability",
    "PublishMechanism",
    "UploadResult",
    "split_parent",
    "staged_path",
    "staging_token",
]

MAX_STAGED_NAME_LENGTH = 255
"""Longest staging *filename* we will construct, in bytes.

``NAME_MAX`` is 255 on every common filesystem, and the derived name is longer than the one
the caller asked for. A target whose name is already near the limit would otherwise produce a
staging name the server refuses -- an upload that fails only for long filenames, which is a
bug that hides until the day someone uses one. Servers with a shorter limit exist; the escape
hatch is to pass the staging name explicitly.
"""

_TOKEN_BYTES = 4


class PublishMechanism(StrEnum):
    """How the uploaded bytes became the file at the destination path.

    Ordered strongest to weakest. :attr:`IN_PLACE` is not weaker than the others by accident
    -- it is what every SFTP client does by default, and it is the one that lets a consumer
    read a half-written file.
    """

    POSIX_RENAME = "posix-rename"
    """Staged, then renamed over the target with ``posix-rename@openssh.com``. Atomic, and
    atomic even when the target already existed."""

    RENAME = "rename"
    """Staged, then renamed with plain v3 ``RENAME``. Atomic **because the target was not
    there**: v3 RENAME cannot overwrite, so a success proves the destination appeared whole."""

    REMOVE_RENAME = "remove-rename"
    """Staged, then the existing target was removed and the staged file renamed into place.
    **Not atomic**: between the two there is a window in which the path does not exist."""

    IN_PLACE = "in-place"
    """Written directly to the destination path. Not atomic, and a consumer polling the
    directory can read it half-written. Requested explicitly with ``atomic=False``."""


class Durability(StrEnum):
    """Whether the bytes were flushed to stable storage before being published.

    Three values because the errored case is a different fact from the refused one, and a
    caller that cares about durability needs to tell them apart. Note what none of these can
    promise: ``fsync@openssh.com`` covers the *file*, and SFTP has no way to flush the
    directory entry, so the rename that publishes it is never itself durable.
    """

    FSYNCED = "fsynced"
    """``fsync@openssh.com`` was sent and answered ``OK``."""

    UNAVAILABLE = "unavailable"
    """No durability barrier: the extension was not advertised, or the server refused it.
    Both collapse here because the consequence is identical -- the bytes may still be in a
    cache. ``require_fsync=True`` turns this into an error instead."""

    SKIPPED = "skipped"
    """Not attempted, because the caller passed ``fsync=False``."""


@dataclass(frozen=True, slots=True)
class UploadResult:
    """What one ``put`` actually did.

    Returned rather than an ``int`` precisely because the byte count is the least interesting
    thing about an upload that may or may not have been atomic. A caller that only wants the
    count reads :attr:`transferred`; a caller that promised its consumers a whole file reads
    :attr:`atomic` and finds out whether that promise was kept.

    Attributes:
        transferred: Bytes the server acknowledged.
        remote_path: Where the file ended up.
        mechanism: How it got there.
        durability: Whether it was flushed before being published.
        staged_at: The temp path the bytes were written to first, or ``None`` when they were
            written straight to :attr:`remote_path`. Kept because a failure leaves it behind
            and something has to be able to name it.
    """

    transferred: int
    remote_path: bytes
    mechanism: PublishMechanism
    durability: Durability
    staged_at: bytes | None = None

    @property
    def atomic(self) -> bool:
        """Whether a consumer could ever have observed the path in a partial state.

        ``True`` for both rename mechanisms: with ``posix-rename`` the replacement is one
        step, and with plain ``RENAME`` the target provably did not exist beforehand, since
        v3 RENAME fails when it does. ``False`` for ``REMOVE``-then-``RENAME`` -- which has a
        window with no file at all -- and for an in-place write.
        """
        return self.mechanism in (PublishMechanism.POSIX_RENAME, PublishMechanism.RENAME)

    @property
    def durable(self) -> bool:
        """Whether the file's bytes reached stable storage before it was published.

        Never a claim about the directory entry: SFTP cannot flush one.
        """
        return self.durability is Durability.FSYNCED


def staging_token() -> str:
    """A short random suffix, so two publishers of one target do not collide.

    Random rather than derived from the pid: the point is uniqueness across *machines*, and
    two hosts writing the same file at the same time is the exact case the collision would
    corrupt. Only the session layer may do this -- the codec is deterministic by rule.
    """
    return os.urandom(_TOKEN_BYTES).hex()


def split_parent(path: bytes) -> tuple[bytes, bytes]:
    """Split a remote path into ``(parent-with-separator, name)``.

    POSIX arithmetic on bytes, deliberately not ``os.path``: on a Windows *client* that
    would join with a backslash and produce a path no SFTP server understands. Remote paths
    are the server's business and ``/`` is what the protocol uses.

    Args:
        path: A remote path.

    Returns:
        The parent including its trailing separator (empty for a bare name), and the final
        component.
    """
    head, separator, name = path.rpartition(b"/")
    return head + separator, name


def staged_path(target: bytes, token: str, *, name: bytes | None = None) -> bytes:
    """Where to write the bytes before publishing them at ``target``.

    Defaults to a hidden sibling -- ``.name.<token>.part`` -- for two reasons. A sibling is
    required, because a rename that crosses a filesystem is not atomic and frequently not
    even permitted. The leading dot is because a consumer globbing ``*.csv`` must not match
    the staging file; that consumer is the reason any of this exists.

    Args:
        target: Final remote path.
        token: Uniqueness suffix, from :func:`staging_token`.
        name: Override. A bare name is resolved as a sibling of ``target``; a value
            containing ``/`` is used as the staging path verbatim, which is how a server with
            a mandated staging directory is handled -- it must still be on the same
            filesystem or the publish step will fail.

    Returns:
        The staging path.

    Raises:
        ValueError: If ``target`` has no final component, which means it names a directory
            and no upload could have succeeded anyway.
    """
    parent, base = split_parent(target)
    if not base:
        raise ValueError(f"remote path has no filename to publish: {target!r}")
    if name is not None:
        return name if b"/" in name else parent + name

    suffix = f".{token}.part".encode("ascii")
    overhead = 1 + len(suffix)
    return parent + b"." + base[: MAX_STAGED_NAME_LENGTH - overhead] + suffix

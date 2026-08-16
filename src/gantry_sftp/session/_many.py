"""Deriving one destination name per entry of a caller-supplied list.

The part of ``get_many`` / ``put_many`` that is not a loop. A tree transfer takes its names from
a walk and keeps the structure it found; a **list** flattens, and flattening is where the two
hazards live:

**The name has to be built, and the two checks are not one check.** A remote path's basename
becomes a local filename and a local path's basename becomes a remote path component, and
:func:`~gantry_sftp.session.check_component` and :func:`._localtree.remote_component` share four
rules before the local one adds a Windows superset -- a backslash, a colon, the wildcard and
redirection characters, control bytes, a trailing dot or space, and the reserved device names
such as ``CON``. Passing one is not passing the other, which is
why the derivation happens here once rather than at each call site: this repository printed the
one-join spelling in its own README and in ``examples/glob_patterns.py`` before D-97 removed it.

**Flattening can collide, and a tree cannot.** ``a/x.txt`` and ``b/x.txt`` are two files in a
tree and one name in a list. Unchecked, the second transfer overwrites the first and the call
reports success -- the same silent loss :class:`~gantry_sftp.exceptions.DestinationCollisionError`
exists for, arrived at from the caller's list instead of from the destination's filesystem.

**So the duplicate check is exact, up front, and refuses rather than reports.** It compares the
derived names as bytes, which is a fact about the caller's own list: no filesystem is consulted
and none has to be, so it is knowable before anything is transferred and is refused there --
unlike a *folding* collision, which is the destination's answer and can only be had by writing
the file and asking. A download keeps that second check too, at the end, exactly as ``get_tree``
does; this one runs first and costs nothing.

Both halves raise :exc:`ValueError` rather than
:exc:`~gantry_sftp.exceptions.DestinationCollisionError`, and the distinction is the one
:class:`~gantry_sftp.session.TreePlan` draws against
:class:`~gantry_sftp.session.TreeResult`: that exception means *the filesystem merged two names*,
established by asking it. This means *the request cannot be satisfied as written*, established by
arithmetic on the caller's own arguments before contact. One is a result and the other is a
mistake in the call, and a single type cannot honestly carry both.
"""

from __future__ import annotations

import os
import posixpath
from collections.abc import Iterable
from pathlib import Path

from gantry_sftp.session._localpath import check_contained, local_child
from gantry_sftp.session._localtree import remote_component
from gantry_sftp.session._policy import _SettledDownload, _SettledUpload
from gantry_sftp.session._recursive import join_remote

__all__ = ["settle_downloads", "settle_uploads"]


def _refuse_duplicates(derived: list[tuple[bytes, str]], *, destination: str, caller: str) -> None:
    """Refuse a list whose entries flatten onto one destination name.

    Args:
        derived: ``(name, source)`` per entry, in the caller's order, where ``source`` is the
            path they supplied rendered for the message.
        destination: The directory everything is being placed in, for the message.
        caller: The method name, so the message names the call that has to change.

    Raises:
        ValueError: If two entries derived the same name. Names the **first** pair found in the
            caller's order, so the message is reproducible: a set of three colliding entries
            reports one pair, the caller fixes it, and the next run reports the next.
    """
    claimed: dict[bytes, str] = {}
    for name, source in derived:
        first = claimed.get(name)
        if first is not None:
            raise ValueError(
                f"{caller}() cannot transfer {source} and {first} into {destination}: both are "
                f"named {name!r} there, so the second would overwrite the first. A list "
                f"flattens, where a tree keeps the directories that told these two apart -- "
                f"transfer them one at a time to destinations you name, or use the tree form"
            )
        claimed[name] = source


def settle_downloads(
    remotes: Iterable[bytes | str], *, destination: Path, caller: str = "get_many"
) -> list[_SettledDownload]:
    """Name the local file each remote path will be downloaded to.

    The input is materialised, which is the premise rather than an implementation detail: an
    explicit list is the caller's and is already in memory, and that is exactly what separates
    this from a walk over a tree whose size the server chooses.

    Args:
        remotes: Remote paths, in the order the caller gave them.
        destination: Local directory each file is placed in.
        caller: Method name for the messages.

    Returns:
        One settled item per input, in input order.

    Raises:
        UnsafePathError: If a remote path's basename could not be a local filename -- empty,
            ``.``, ``..``, a separator, or anything the destination platform refuses.
        ValueError: If two remote paths share a basename.
    """
    settled: list[_SettledDownload] = []
    derived: list[tuple[bytes, str]] = []
    for remote in remotes:
        path = os.fsencode(remote) if isinstance(remote, str) else remote
        # `posixpath` and not `PurePosixPath`: pathlib swallows a trailing `/.` and answers with
        # the parent's name, so `/a/.` would derive `a` and be transferred as a file. The bytes
        # function answers `.`, which `local_child` then refuses -- which is the honest end for
        # a path naming a directory entry rather than a file.
        name = posixpath.basename(path)
        target = check_contained(destination, local_child(destination, name))
        settled.append(_SettledDownload(path, target))
        derived.append((name, repr(path)))
    _refuse_duplicates(derived, destination=str(destination), caller=caller)
    return settled


def settle_uploads(
    sources: Iterable[Path | str], *, remote_directory: bytes, caller: str = "put_many"
) -> list[_SettledUpload]:
    """Name the remote path each local file will be uploaded to.

    **This is what makes :func:`._localtree.remote_component`'s refusal reachable** (D-184). Every
    other caller takes its names from ``os.scandir``, which cannot produce ``.``, ``..``, a
    separator or an empty name -- so that function's docstring recorded, correctly, that no
    caller could reach the refusal. A caller-supplied ``Path("dir/..")`` has the basename ``..``
    and reaches it, which is why ``put_many`` documents ``UnsafePathError`` where ``put_tree``
    stopped documenting it.

    Args:
        sources: Local paths, in the order the caller gave them.
        remote_directory: Remote directory each file is placed in.
        caller: Method name for the messages.

    Returns:
        One settled item per input, in input order.

    Raises:
        UnsafePathError: If a local path's basename could not be one remote path component.
        ValueError: If two local paths share a basename.
    """
    settled: list[_SettledUpload] = []
    derived: list[tuple[bytes, str]] = []
    for source in sources:
        path = Path(source)
        name = os.fsencode(path.name)
        settled.append(_SettledUpload(path, join_remote(remote_directory, remote_component(name))))
        derived.append((name, str(path)))
    _refuse_duplicates(derived, destination=repr(remote_directory), caller=caller)
    return settled

"""The decisions a transfer makes without the wire, and the local effects they produce.

Everything here was in ``_session.py``, and the reason it is not any more is that it never
needed to be: not one of these functions takes a :class:`~gantry_sftp.session.Session`, awaits
anything, or sends a byte. They are the synchronous half of a transfer -- which local mode to
create a file with, whether a resume may adopt the bytes already on disk, whether a size that
arrived matches the size that was announced, which entries a tree walk skips and why -- plus the
local-side effects those decisions produce, like stamping timestamps onto a descriptor.

**The split is by what the code needs, not by what it is about.** Anything holding a session or
awaiting a reply stays out: ``close_quietly`` takes one and lives in
:mod:`gantry_sftp.session._handles`, and ``_unexpected`` belongs beside
:func:`~gantry_sftp.session.raise_for_status` because both turn a *reply* into an exception
rather than deciding anything about a transfer.

**That rule is a membership test and D-146 used it as one.** Splitting `Session` by concern
asks of each member "what does this need?", and `_already_complete` needed nothing -- it awaits
nothing and never referenced the session it was declared on, so it belonged here from the day it
was written and nobody had asked.

What it buys is a testable seam: these can be exercised with a ``Path`` and an
:class:`~gantry_sftp.codec.Attrs` and no server, no subprocess and no event loop, which is what
the module they came from could not offer.

The names keep their leading underscore because they stay package-private -- the module is the
boundary, not the name. ``exceptions._flatten_exception_group`` is the same arrangement.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from gantry_sftp.codec import Attrs, Times
from gantry_sftp.exceptions import DestinationCollisionError, PathCollision, TransferError
from gantry_sftp.session._download import DownloadResult, ProgressCallback
from gantry_sftp.session._listing import EntryKind
from gantry_sftp.session._localpath import DestinationLedger, check_contained, local_child
from gantry_sftp.session._localtree import LocalWalkEntry, remote_component
from gantry_sftp.session._mode import PERMISSION_BITS, Mode, local_mode
from gantry_sftp.session._platform import NO_FOLLOW
from gantry_sftp.session._publish import Publish, SizeCheck, TimePreservation
from gantry_sftp.session._recursive import Skipped, SkipReason, TreeResult, WalkEntry, join_remote
from gantry_sftp.session._verify import ContentCheck, ResumeCheck, Verify

__all__ = [
    "_DownloadState",
    "_TreeDownload",
    "_TreeUpload",
    "_already_complete",
    "_check_local_path",
    "_check_publish_flags",
    "_check_tree_concurrency",
    "_check_tree_publish",
    "_chmod_local",
    "_chmod_local_directories",
    "_claim_directory",
    "_collision_error",
    "_confirm_download_size",
    "_download_mode",
    "_download_resume_offset",
    "_encode_path",
    "_ensure_directory",
    "_gate_as_content_check",
    "_local_directory",
    "_local_size",
    "_local_times",
    "_name_the_local_file",
    "_optional_path",
    "_preservation",
    "_remote_directory",
    "_settle_directory",
    "_settle_remote_directory",
    "_skip_reason",
    "_stamp_local",
    "_stamp_local_directories",
    "_touch_destination",
    "_wrong_path_type",
]


def _ensure_directory(path: Path, *, parents: bool = False) -> Path:
    """Create a local directory if it is not there, from outside an async frame.

    A plain function because ASYNC240 is right: filesystem calls block the event loop. These
    are metadata operations on a local disk rather than a transfer, so they are not worth a
    thread -- but they are worth keeping out of the coroutine where the rule can see them.
    """
    path.mkdir(parents=parents, exist_ok=True)
    return path


def _remote_directory(root: bytes, relative: tuple[bytes, ...]) -> bytes:
    """Build the remote directory for a walked local position, validating every component.

    The counterpart of :func:`_local_directory`, and it checks each name for the same reason
    even though the names are ours: one component at a time is what catches a bug in our own
    joining, and a joined path has already lost which name was the problem.
    """
    remote = root
    for name in relative:
        remote = join_remote(remote, remote_component(name))
    return remote


def _local_directory(destination: Path, relative: tuple[bytes, ...]) -> Path:
    """Build the local directory for a walked position, validating every component.

    Each name is checked and joined one at a time rather than joined and then checked: a
    single ``..`` in the middle of an otherwise innocent chain is exactly the shape of the
    attack, and a joined path has already lost which component was the problem.
    """
    local = destination
    for name in relative:
        local = local_child(local, name)
    return check_contained(destination, local)


def _claim_directory(
    ledger: DestinationLedger, local_directory: Path, entry: WalkEntry
) -> tuple[PathCollision, ...]:
    """Claim a walked directory's local path, reporting a collision rather than merging.

    Directories collapse the same way files do -- ``Docs`` and ``docs`` are one directory on a
    case-folding filesystem -- and the consequence is quieter: the two remote directories'
    contents merge, so the *structure* is wrong even where no individual file is lost. Returns
    a one-element tuple on collision and an empty one otherwise, so the caller stays flat.

    **The identity is the resolved path's, and that is the difference from the file case**
    (D-123). A *file* is opened ``O_NOFOLLOW``, so a symlink at that name is refused and its own
    inode is the honest answer. A directory is created with ``mkdir(exist_ok=True)``, whose
    ``FileExistsError`` branch asks ``is_dir()`` -- which follows -- so a link to a directory is
    written *through*, and the link's own inode would report a name this run had not claimed.
    Two remote directories then merged into one local one with nothing said. Resolving here
    keeps the legitimate use of a pre-created link (one remote directory pointed somewhere the
    caller chose) and catches only the shape that merges two.

    Both calls take the resolved path so the pair cannot be split; the *collision* still names
    the path the caller would go and look at rather than what it resolved to.
    """
    created = local_directory.resolve()
    first = ledger.collides_with(created)
    if first is None:
        ledger.claim(created, entry.path)
        return ()
    return (PathCollision(str(local_directory), entry.path, first),)


def _collision_error(
    collisions: list[PathCollision], destination: Path, result: TreeResult
) -> DestinationCollisionError:
    """Build the error that ends a tree the destination could not keep the names apart in."""
    noun, verb = ("path", "was") if len(collisions) == 1 else ("paths", "were")
    return DestinationCollisionError(
        f"{len(collisions)} remote {noun} resolved onto a local file this download had "
        f"already written, and {verb} refused rather than overwriting it",
        collisions=tuple(collisions),
        destination=str(destination),
        files=result.files,
        transferred=result.transferred,
    )


def _skip_reason(kind: EntryKind) -> str:
    """Name why a walk passed over an entry of this kind."""
    if kind is EntryKind.SYMLINK:
        return SkipReason.SYMLINK
    if kind is EntryKind.UNKNOWN:
        return SkipReason.UNKNOWN_KIND
    return SkipReason.NOT_A_FILE


def _check_publish_flags(
    *,
    atomic: bool,
    fsync: bool,
    require_atomic: bool,
    require_fsync: bool,
    resume: bool,
    staging_name: bytes | str | None = None,
) -> None:
    """Refuse a combination of flags that contradict each other.

    ``require_atomic=True, atomic=False`` is not a policy this can satisfy by picking one --
    it is two opposite instructions, and honouring either silently would be guessing about
    the guarantee the caller cares most about.

    ``resume=True, atomic=True`` with no ``staging_name`` is the same shape for a subtler
    reason. The default staging name carries fresh randomness per call, so the file a
    previous run left behind has a name this run cannot reconstruct: there is nothing to
    resume *into*. Falling back to a full upload would be the silent downgrade this library
    refuses everywhere else, so it is refused here and the message names the fix.

    Deriving the staging name from the target instead -- making it findable -- was rejected
    rather than overlooked: a predictable staging name is what
    :func:`~gantry_sftp.session.staging_token` exists to avoid, and two publishers resuming
    into one would interleave into a single file.

    Raises:
        ValueError: If a ``require_*`` flag strengthens a flag that is switched off, or if
            ``resume`` is asked for where nothing could be resumed.
    """
    if require_atomic and not atomic:
        raise ValueError("require_atomic=True contradicts atomic=False")
    if require_fsync and not fsync:
        raise ValueError("require_fsync=True contradicts fsync=False")
    if resume and atomic and staging_name is None:
        raise ValueError(
            "resume=True needs staging_name= when atomic=True: the default staging file is "
            "named with fresh randomness each call, so a previous run's partial upload "
            "cannot be found. Pass staging_name= to fix the name, or atomic=False to resume "
            "the destination itself"
        )


def _local_size(path: Path | str) -> int:
    """Size of a local file, or ``0`` if it is not there.

    A plain function because ASYNC240 is right that a filesystem call blocks the event loop,
    and a single ``stat`` is not worth a thread. Absent is ``0`` rather than an error: a
    first ``resume=True`` attempt with no local file is a caller mistake the ``open`` will
    report far more clearly than this could.
    """
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


def _local_times(path: Path | str) -> Times:
    """A local file's atime and mtime, truncated to the seconds filexfer v3 can carry.

    ``int()`` rather than ``round()``: rounding a timestamp *up* invents a modification that
    has not happened yet, and a file dated one second into the future is exactly what makes a
    "modified since" sweep behave differently between two runs of the same upload.
    """
    stat_result = Path(path).stat()
    return Times(atime=int(stat_result.st_atime), mtime=int(stat_result.st_mtime))


def _download_mode(mode: int | Mode | None, attributes: Attrs, remote_path: bytes) -> int | None:
    """What permission bits a download should end up with, or ``None`` to leave 0o600 alone.

    Raises:
        TransferError: If :data:`Mode.PRESERVE` was asked for and the server reported no
            permissions at all. **Absent is not zero and it is not a default**: v3 ATTRS makes
            every field optional and a server is entitled to send none of them, so there is
            genuinely nothing to preserve. Leaving the file at its 0o600 creation mode and
            returning success would be indistinguishable from having preserved a 0o600 file,
            which is the shape of wrong answer this whole argument exists to remove. Raised
            before the first ``READ``, so a terse server costs no transfer.
    """
    if mode is None:
        return None
    if mode is not Mode.PRESERVE:
        return mode
    if attributes.permissions is None:
        raise TransferError(
            f"mode=Mode.PRESERVE was asked for but the server sent no permissions for "
            f"{remote_path!r}, so there is nothing to preserve; pass an explicit mode= or "
            f"leave it unset to keep the 0o600 a download creates",
            transferred=0,
            offset=0,
            remote_path=remote_path,
        )
    return attributes.permissions & PERMISSION_BITS


def _chmod_local(path: Path | str, mode: int, *, no_follow: bool) -> None:
    """Apply a mode to a local file that is already complete, without following a link to it.

    Used only where there is no open descriptor to hand -- a resumed download that finds the
    file already whole. Everywhere else the mode goes onto the descriptor the transfer is
    already holding, which is stronger; here the ``O_NOFOLLOW`` is re-applied on a fresh
    read-only open so that a symlink swapped in since the containment check still cannot
    redirect the ``chmod`` onto whatever it points at.
    """
    fd = os.open(path, os.O_RDONLY | (NO_FOLLOW if no_follow else 0))
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _stamp_local(path: Path | str, times: Times, *, no_follow: bool = True) -> None:
    """Apply times to a local path that is already complete, without following a link to it.

    The mirror of :func:`_chmod_local`, and it exists for the same reason: the tree pass runs
    *after* the walk that containment-checked the path, so the check is old by the time the
    stamp lands and a local attacker has had the whole transfer to swap the directory for a
    symlink. ``os.utime`` on a path follows one; on a descriptor opened ``O_NOFOLLOW`` there
    is nothing left to follow.

    The descriptor form rather than ``follow_symlinks=False`` because that is what
    :func:`~gantry_sftp.session.require_local_io` already guarantees -- it probes
    ``os.utime in os.supports_fd`` -- and it is the shape ``session/_platform.py`` describes
    for stamping metadata generally. ``os.supports_follow_symlinks`` is a separate probe this
    library does not make, so relying on it would be a third capability to degrade.

    Args:
        path: What to stamp.
        times: The atime and mtime to apply.
        no_follow: Refuse to stamp through a symlink. Defaults to ``True`` because every
            recursive call site is inside a destination tree that must not be escaped. A
            single ``get`` passes its own ``no_follow``, which is off by default: pointing a
            download at a link you made yourself is legitimate, and stamping it would
            otherwise fail where writing to it succeeded.
    """
    fd = os.open(path, os.O_RDONLY | (NO_FOLLOW if no_follow else 0))
    try:
        os.utime(fd, (times.atime, times.mtime))
    finally:
        os.close(fd)


def _preservation(asked: bool, times: Times | None) -> TimePreservation:
    """Which of the three outcomes a ``preserve_times`` request reached.

    ``UNAVAILABLE`` is the one worth having: a server that answers ``STAT`` with no times
    leaves the local file stamped with the moment it was downloaded, which looks entirely
    plausible and is wrong. Nothing said so before D-99.
    """
    if not asked:
        return TimePreservation.SKIPPED
    return TimePreservation.PRESERVED if times is not None else TimePreservation.UNAVAILABLE


def _gate_as_content_check(resume_check: ResumeCheck, verify: Verify) -> ContentCheck:
    """Report a whole-file resume gate as the content check it already performed.

    Only correct where the adopted prefix *is* the whole file, which is the one caller. The
    gate compared every byte against the remote file at the rung ``verify`` names, so the
    answer is not inferred from it -- it is it.

    ``Verify.SIZE`` still reports ``SKIPPED`` even though the gate opportunistically tries
    rung 1, matching ``put``: this field answers "which content check did you ask for and what
    did it find", and the gate's own answer is on
    :attr:`~gantry_sftp.session.DownloadResult.resume_check`.
    """
    if verify is Verify.SIZE:
        return ContentCheck.SKIPPED
    if resume_check is ResumeCheck.MATCHED:
        return ContentCheck.HASHED if verify is Verify.HASH else ContentCheck.REREAD
    return ContentCheck.UNAVAILABLE


def _already_complete(
    remote_path: bytes,
    local_path: Path | str,
    record: dict[str, object],
    *,
    adopted: int,
    mode: int | None,
    no_follow: bool,
    times: Times | None,
    times_result: TimePreservation,
    resume_check: ResumeCheck,
    verify: Verify,
) -> DownloadResult:
    """Finish a resume that found the local file already whole, without opening anything.

    A function rather than a method since D-146, and it always could have been: it awaits
    nothing, sends nothing and never touched the session it was declared on -- which is this
    module's whole membership rule, and is why the move cost no argument.

    **The metadata is still applied, and skipping it is the silent wrong answer this whole
    path exists to avoid**: the destination the caller named exists, they said what
    permissions and timestamps it should have, and "it was already there" is not an answer
    to that. The partial was not necessarily left by this library, so neither its mode nor
    its times are necessarily anything in particular -- its mtime is the moment the
    *interrupted* run last wrote to it, which is exactly the fabricated-but-plausible
    timestamp D-79 is about.

    The times half of that was missing until D-99, and it was missing invisibly: ``get``
    returned a byte count, so a caller who passed ``preserve_times=True`` and resumed a
    complete file got a plausible wrong mtime and no way to notice. Building the result
    type is what surfaced it, which is the argument for result types.

    Both go on a fresh ``O_NOFOLLOW`` descriptor rather than on the path, for the reason
    :func:`_chmod_local` gives: the containment check is old by now.

    Returns:
        The result, with ``content_check`` derived from the gate rather than from a second
        comparison. A resume that adopts the whole file has just had the whole file
        compared against the remote one at the rung ``verify`` names, so re-running it
        would be a duplicate -- and for
        :data:`~gantry_sftp.session.Verify.REREAD` a duplicate is a second full download.
    """
    if mode is not None:
        _chmod_local(local_path, mode, no_follow=no_follow)
    if times is not None:
        _stamp_local(local_path, times, no_follow=no_follow)
    record["bytes"] = 0
    record["adopted"] = adopted
    return DownloadResult(
        0,
        remote_path,
        Path(local_path),
        SizeCheck.MATCHED,
        times=times_result,
        content_check=_gate_as_content_check(resume_check, verify),
        resume_check=resume_check,
        adopted=adopted,
        mode=mode,
    )


def _name_the_local_file(failure: TransferError, local_path: Path | str) -> None:
    """Fill in the local half of a transfer error, at the boundary that knows it.

    DoD 3 states the contract in as many words -- a ``TransferError`` carries bytes
    transferred, offset **and both paths** -- and the download's scheduler was passing three of
    the four (D-117). The missing one is the only thing that names the artefact a failed
    ``get`` leaves on disk, so it was absent exactly where it mattered most.

    **It is filled here rather than threaded through every raise site, because the schedulers
    genuinely do not have it.** :func:`~gantry_sftp.session.download_handle` is handed a
    *descriptor* and :func:`~gantry_sftp.session.upload_handle` reads through one, deliberately:
    the open flags are a safety decision belonging to the layer that knows where the file is
    allowed to be, and a scheduler with an fd can just as well write into a pipe, which has no
    path at all. Passing a name down to be quoted in an error would buy that name back at the
    cost of the seam. So :meth:`Session.get` and :meth:`Session.put` name it on the way out --
    which is also what makes the claim exhaustive rather than per-site: a raise site added
    inside either of them carries the field without anybody remembering to pass it.

    **A site that knows better keeps its answer.** The resume gates and the verification
    failures build the error with the path already on it, so this fills a blank and never
    overwrites one -- which is what keeps the innermost, most specific name from being replaced
    by the outermost.
    """
    if failure.local_path is None:
        failure.local_path = str(local_path)


def _confirm_download_size(
    remote_path: bytes,
    local_path: Path | str,
    *,
    arrived: int,
    announced: int | None,
    asked: bool,
) -> SizeCheck:
    """Rung 3 on the download, which costs no round trip -- ``get`` already made that ``STAT``.

    Args:
        remote_path: What was read, for the error.
        local_path: What was written, for the error.
        arrived: ``adopted + transferred``, not what this call moved: a resume returns only
            the remainder and comparing that against the whole file would fail every resume.
        announced: The size the server reported, or ``None`` if it reported none.
        asked: ``verify_size``. ``False`` reports ``SKIPPED`` and compares nothing.

    Returns:
        Which of the three answerable outcomes happened. A *mismatch* is not among them.
        ``SKIPPED`` wins over ``UNAVAILABLE`` when both apply, because a caller who turned the
        check off is told that rather than told the server was quiet -- they did not ask, so
        whether it could have been answered never came up.

    Raises:
        TransferError: If fewer bytes arrived than the server said there were.
    """
    if not asked:
        return SizeCheck.SKIPPED
    if announced is None:
        return SizeCheck.UNAVAILABLE
    if arrived != announced:
        raise TransferError(
            f"{remote_path!r} is {announced} bytes but the download ended after "
            f"{arrived}; it was truncated or the file shrank underneath it",
            transferred=arrived,
            offset=arrived,
            remote_path=remote_path,
            local_path=str(local_path),
        )
    return SizeCheck.MATCHED


def _stamp_local_directories(entries: Sequence[tuple[Path, Times]]) -> None:
    """Apply remote directory times locally, once everything inside them has been written.

    **After, necessarily**, for the reason :meth:`Session._set_directory_times` gives: writing
    a file into a directory updates that directory's mtime, so stamping it earlier is undone
    by the next transfer. Touching a nested directory does not dirty its parent, so no order is
    imposed within this pass.

    A failure is swallowed per directory. The files are the payload and they have all arrived;
    a directory whose timestamp could not be set -- because the destination is read-only to us,
    or on a filesystem that will not take one -- is not a reason to fail a completed download.
    **A directory that is now a symlink lands in that same swallow** (``O_NOFOLLOW`` answers
    ``ELOOP``, an ``OSError``), which is the right end for it: the timestamp is metadata on a
    tree whose files have all arrived, so refusing to stamp costs nothing, while following the
    link would put the transfer's mtime on a file outside the destination.
    """
    for path, times in entries:
        with suppress(OSError):
            _stamp_local(path, times)


def _chmod_local_directories(entries: Sequence[tuple[Path, int]]) -> None:
    """Apply remote directory modes locally, once everything inside them has been written.

    **After, necessarily**, and for a stronger reason than the timestamps have: a directory
    created ``0o500`` cannot have a file written into it, so applying a source mode on the way
    down would fail the transfers underneath it. Deepest-last is not required either -- changing
    a nested directory's mode does not affect its parent's -- so no order is imposed.

    A failure is swallowed per directory, for the reason :func:`_stamp_local_directories` gives:
    the files are the payload and they have all arrived. That is the opposite of what a *file*'s
    mode does, which fails the transfer, and the difference is that a file's mode is what the
    caller asked to control while a directory's is carried along with it.

    Through :func:`_chmod_local` rather than ``Path.chmod``, which follows a symlink -- the same
    correction :func:`_stamp_local` carries and for the same reason, and the more dangerous half
    of the pair: a followed link puts the remote tree's permission bits on a file outside the
    destination, where ``0o777`` on the wrong target is a durable change rather than a cosmetic
    one. ``_chmod_local`` is the function the *file* path has always used for this; only the
    directory pass was reaching for the path-based call.
    """
    for path, mode in entries:
        with suppress(OSError):
            _chmod_local(path, mode, no_follow=True)


def _download_resume_offset(local_path: Path | str, size: int | None, remote_path: bytes) -> int:
    """Where a resumed download should continue from.

    The mirror of :meth:`Session._upload_resume_offset`, and the *stronger* of the two: the
    partial is on local disk, so its length is a fact rather than a report, and a read at an
    explicit offset is idempotent. The refusals are the same two, for the same reasons -- no
    remote size means nothing to check against, and a local partial longer than the remote
    file is not a prefix of it.

    Raises:
        TransferError: If no safe offset can be established.
    """
    have = _local_size(local_path)
    if size is None:
        raise TransferError(
            f"resume needs a size for {remote_path!r} and this server did not report one, "
            f"so a local partial cannot be checked against it",
            remote_path=remote_path,
            local_path=str(local_path),
        )
    if have > size:
        raise TransferError(
            f"cannot resume: {local_path} already holds {have} bytes and {remote_path!r} is "
            f"only {size}, so what is on disk is not a prefix of what is being downloaded",
            transferred=0,
            offset=have,
            remote_path=remote_path,
            local_path=str(local_path),
        )
    return have


def _check_local_path(local_path: object, *, method: str) -> None:
    """Refuse a local path that is not a ``Path`` or a ``str``, naming the argument (D-96).

    **The mirror of the remote-path rule, and the two disagreed before this existed.** A
    transfer takes one path of each kind, and passing ``bytes`` for the local one used to
    reach four different endings: ``get`` accepted it and wrote the file, because POSIX
    ``open`` takes bytes; ``put``, ``get_tree`` and ``put_tree`` raised ``pathlib``'s own
    ``TypeError``, which names neither the method nor the argument. Accepted-here and
    refused-there is the per-site decision nobody re-reads, so it is decided once: the
    declared type is the accepted type.

    ``bytes`` is called out specifically, since it is not a typo -- it is the *remote* rule
    applied one argument over, and the fix is to say which side is which rather than which
    type is wrong.

    Raises:
        TypeError: If ``local_path`` is neither ``Path`` nor ``str``.
    """
    if isinstance(local_path, Path | str):
        return
    kind = type(local_path).__name__
    detail = (
        "bytes is the rule for the *remote* path, which goes on the wire; a local path is "
        "opened by this process"
        if isinstance(local_path, bytes)
        else "it is opened by this process, so it has to be something pathlib accepts"
    )
    raise TypeError(f"{method} needs a Path or str for its local path, not {kind}: {detail}")


def _optional_path(path: bytes | str | None) -> bytes | None:
    """Encode a path that may be absent, keeping ``None`` distinct from an empty name."""
    return None if path is None else _encode_path(path)


def _encode_path(path: bytes | str) -> bytes:
    """Paths go on the wire as bytes.

    ``str`` is encoded with ``surrogateescape`` so a name that came back from the server as
    invalid UTF-8, was decoded leniently, and is now being sent again survives the round
    trip unchanged. Server-supplied names are frequently not valid UTF-8, and a client that
    cannot re-send what it was just given cannot operate on those files at all.

    Anything else is refused here rather than by whatever it fails inside (D-96).

    Raises:
        TypeError: If ``path`` is neither ``bytes`` nor ``str``.
    """
    if isinstance(path, bytes | str):
        return path if isinstance(path, bytes) else path.encode("utf-8", "surrogateescape")
    raise TypeError(_wrong_path_type(path))


def _wrong_path_type(path: object) -> str:
    r"""Explain a remote path that is not ``bytes`` or ``str``, and say why not a ``Path``.

    **A ``Path`` gets its own sentence because it is the type callers actually pass**, and
    because "unsupported" would be the wrong reason. ``pathlib`` is a type whose job is to
    normalise, and a remote name has to survive byte for byte: ``PurePosixPath`` drops a
    trailing slash on construction, and on Windows ``str(Path("/incoming/x"))`` is
    ``'\\incoming\\x'`` -- which the server does not refuse, because a backslash is a legal
    character in a POSIX filename. It would create a file *named* ``\\incoming\\x``. So a
    silent ``os.fsencode`` here would be a data-placement bug wearing a convenience's clothes.

    The asymmetry is named too. ``get``/``put`` take a ``Path`` for their **local** side, so a
    caller who has just written one is not confused about ``pathlib`` -- they are one argument
    out on a rule nothing had ever stated.
    """
    kind = type(path).__name__
    if isinstance(path, PurePath):
        return (
            f"a remote path must be bytes or str, not {kind}: pathlib normalises and a remote "
            f"name has to survive byte for byte -- a trailing slash goes on construction, and "
            f"str(Path(...)) on Windows renders separators as backslashes, which a server takes "
            f"as part of the filename rather than as separators. Pass str(path) if it really is "
            f"posix-shaped, or the bytes the server gave you. The local side of get()/put() is "
            f"the argument that takes a Path"
        )
    return (
        f"a remote path must be bytes or str, not {kind}: it goes on the wire as bytes, and "
        f"str is encoded with surrogateescape so a name the server sent can be sent back "
        f"unchanged"
    )


@dataclass(slots=True)
class _DownloadState:
    """What a tree download accumulates while its producer walks and its workers transfer.

    A mutable object rather than a pile of ``nonlocal`` bindings, so the producer can be a
    method instead of a closure -- which is what keeps :meth:`Session.get_tree` under the
    cognitive-complexity ceiling without an exemption.

    Everything here except ``moved`` is written **only by the producer**, which runs in one
    task; ``moved`` is appended to by the workers, and appending is the point -- see
    :meth:`Session.get_tree`.
    """

    ledger: DestinationLedger = field(default_factory=DestinationLedger)
    directories: int = 0
    moved: list[int] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    collisions: list[PathCollision] = field(default_factory=list)
    # Collected during the walk and applied after it -- see _stamp_local_directories. A
    # directory's times come from its *parent's* listing, which READDIR already returned, so
    # this costs no round trip.
    directory_times: list[tuple[Path, Times]] = field(default_factory=list)
    # Same collection, same listing, same after-the-walk pass -- and for a second reason on top
    # of the timestamps': a directory created 0o500 cannot have files written into it, so its
    # real mode has to wait until everything inside it has arrived.
    directory_modes: list[tuple[Path, int]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _TreeDownload:
    """One file a tree download has settled a destination for, waiting to be transferred."""

    remote: bytes
    target: Path


@dataclass(frozen=True, slots=True)
class _TreeUpload:
    """One file a tree upload has settled a destination for, waiting to be transferred."""

    source: Path
    remote: bytes


def _settle_remote_directory(
    entry: LocalWalkEntry,
    remote_directory: bytes,
    *,
    preserve_times: bool,
    mode: int | Mode | None,
    times: list[tuple[bytes, Times]],
    modes: list[tuple[bytes, int]],
) -> None:
    """Record what a just-created remote directory contributes to the final metadata pass.

    The upload-side twin of :func:`_settle_directory`, and it is deliberately the same shape:
    collect during the walk, apply after it. See :meth:`Session._set_directory_times` for why
    the pass is deferred -- a directory's mtime is changed again by every file written into it,
    so stamping it during the walk stamps it with the walk.

    **Only ``Mode.PRESERVE`` reaches directories**, the same rule the download side states: an
    explicit integer is a *file* mode, and ``mode=0o600`` applied here would build a tree that
    nothing can descend into.

    Called only where ``entry.relative`` is non-empty, which is the difference from the
    download twin: this stamps the directory it was just handed, so the root -- named by the
    caller, not created by us -- is not ours to modify. The entry is a
    :class:`~gantry_sftp.session.LocalWalkEntry` and not a
    :class:`~gantry_sftp.session.WalkEntry` for the reason that type exists: ``path`` here is a
    real local path, and the two are kept apart so a local one cannot be sent to a server.

    Args:
        entry: The walked local directory, whose ``path`` is the source of both values.
        remote_directory: Where it was just created on the server.
        preserve_times: Whether to carry the local mtime/atime across.
        mode: The resolved mode request; only ``Mode.PRESERVE`` is a directory instruction.
        times: Collected ``(remote path, times)`` pairs, appended to in place.
        modes: Collected ``(remote path, permission bits)`` pairs, appended to in place.
    """
    if preserve_times:
        times.append((remote_directory, _local_times(entry.path)))
    if mode is Mode.PRESERVE:
        modes.append((remote_directory, local_mode(entry.path)))


def _settle_directory(
    entry: WalkEntry,
    *,
    local_directory: Path,
    preserve_times: bool,
    mode: int | Mode | None,
    state: _DownloadState,
) -> None:
    """Create one walked directory locally and record what it contributes to the report.

    The root is deliberately not counted, stamped or chmodded: the caller named it, so creating
    it is :meth:`Session.get_tree`'s own ``_ensure_directory`` and modifying it would be a side
    effect on something they did not ask to have modified.

    **Only ``Mode.PRESERVE`` reaches directories.** An explicit integer is a *file* mode, and
    applying it here would make ``mode=0o600`` produce a tree nothing can descend into. A
    directory the server declined to report permissions for is skipped rather than raising, which
    is the opposite of what a *file* does under ``PRESERVE`` -- the file is the payload and a
    silently wrong mode on it is the failure being prevented, while a directory whose mode could
    not be carried leaves a readable tree and a listing that says what was skipped.
    """
    if entry.relative:
        _ = _ensure_directory(local_directory)
        state.directories += 1
        state.collisions.extend(_claim_directory(state.ledger, local_directory, entry))
    if preserve_times:
        state.directory_times.extend(
            (local_child(local_directory, child.filename), child.attrs.times)
            for child in entry.directories
            if child.attrs.times is not None
        )
    if mode is Mode.PRESERVE:
        state.directory_modes.extend(
            (
                local_child(local_directory, child.filename),
                child.attrs.permissions & PERMISSION_BITS,
            )
            for child in entry.directories
            if child.attrs.permissions is not None
        )
    state.skipped.extend(entry.skipped)


def _touch_destination(target: Path) -> None:
    """Create ``target`` empty if it is not there, without truncating it if it is.

    See :meth:`Session._claim_download` for why this runs before the collision check rather
    than being left to the transfer's own ``open``.
    """
    os.close(os.open(target, os.O_CREAT | os.O_WRONLY | NO_FOLLOW, 0o600))


def refuses_the_name(error: OSError) -> bool:
    """Is this the local filesystem saying the *name* cannot exist here, rather than an I/O error?

    ``EILSEQ`` is APFS and HFS+ rejecting a filename that is not valid UTF-8 (D-150). A remote
    name is bytes -- any bytes but ``/`` and NUL -- and Linux stores it happily, so a file this
    library downloads correctly here **cannot be placed on a Mac's disk at all**. It is the same
    shape as the case folding D-37 refuses: a property of the destination filesystem, invisible
    to every test that varies the *remote* name.

    **Narrow on purpose, and this is the whole care in it.** The two callers turn a true answer
    into a skip or a named refusal, and a wide ``except OSError`` there would report a full disk
    or a denied directory as "bad name" -- the failure mode a predicate that swallows a
    superclass always has. Every other errno keeps propagating exactly as it did.

    Args:
        error: The error the local ``open`` raised.

    Returns:
        Whether the filesystem refused the name itself.
    """
    return error.errno == errno.EILSEQ


def _check_tree_concurrency(
    concurrency: int, *, progress: ProgressCallback | None, caller: str
) -> None:
    """Refuse a concurrency argument that cannot mean what the caller wants.

    ``progress`` is the interesting half. :class:`~gantry_sftp.session.ProgressCallback` is
    ``(transferred, total)`` and carries **no file identity** -- deliberately, so one reporter
    works everywhere -- and a tree calls it per file, so ``total`` resets at each one. With a
    single worker that is a sequence a reporter can follow. With several it is several files'
    counters interleaved into one stream with nothing to tell them apart, and a progress bar
    built on it would jump backwards at random. Passing it through anyway would be a silent
    wrong answer, which this library refuses everywhere else, so it is refused here and the
    message names both fixes.

    Tree-wide progress, or a second callback shape carrying identity, is a real feature and a
    real decision (D-55) -- it is not made here by accident.

    Raises:
        ValueError: If ``concurrency`` is below 1, or if it is above 1 with a ``progress``
            callback that could not be interpreted.
    """
    if concurrency < 1:
        raise ValueError(
            f"{caller}() concurrency must be at least 1, got {concurrency}; "
            f"1 transfers the tree one file at a time"
        )
    if concurrency > 1 and progress is not None:
        raise ValueError(
            f"{caller}() cannot take progress= with concurrency={concurrency}: the callback is "
            f"(transferred, total) per file and carries no file identity, so several workers "
            f"reporting at once produce one stream of counters that reset unpredictably. Use "
            f"concurrency=1 to keep per-file progress, or drop progress= to keep the "
            f"concurrency and read the counts from the returned TreeResult"
        )


def _check_tree_publish(policy: Publish, *, resume: bool, caller: str) -> None:
    """Refuse a publish policy that one name cannot serve a whole tree with.

    Both refusals are about the **staging name**, which is per file for a reason, and both are
    raised here rather than at the first transfer: the fault is in the request, so a report
    blaming a file chosen by walk order would name the wrong thing.

    Split out of :meth:`Session.put_tree` in the same shape as
    :func:`_check_tree_concurrency`, which validates the argument beside these two. Nothing
    downstream of it moved -- these guards read ``policy`` and ``resume`` and nothing the walk
    builds, which is why they were already the first thing after the policy was resolved.

    Args:
        policy: The resolved publish policy.
        resume: Whether the caller asked to resume.
        caller: The public method name, without parentheses, for the messages.

    Raises:
        ValueError: If ``resume`` is asked for with atomic publishing, or if the policy
            carries a ``staging_name``.
    """
    if resume and policy.atomic:
        # The decision D-54 had to make, and it is `put`'s rule reaching a tree rather than a
        # new one. `put(resume=True, atomic=True)` needs an explicit staging_name, because the
        # generated one carries fresh randomness per call and last run's partial cannot be
        # found again -- and `put_tree` cannot take a staging_name at all, since one name
        # cannot serve a tree's many files. Deriving one per file from the target was rejected
        # rather than overlooked: a predictable staging name is exactly what `staging_token`
        # exists to avoid, and here it would be predictable for every file in the tree at once,
        # so two mirrors resuming into one destination would interleave file by file. So tree
        # resume means resuming the destination itself, which is `atomic=False`, and the caller
        # is told rather than downgraded.
        raise ValueError(
            f"{caller}() cannot resume with atomic publishing: each file stages under a "
            f"name generated fresh per call, so a previous run's partial cannot be found, "
            f"and a staging_name cannot be fixed for a whole tree. Pass "
            f"publish=Publish(atomic=False) to resume the destination files themselves, "
            f"or drop resume=True to re-upload the tree atomically"
        )
    if policy.staging_name is not None:
        raise ValueError(
            f"{caller}() cannot take a staging_name: it applies to every file in the tree, "
            f"so they would all stage under one name and overwrite each other. Leave it "
            f"unset to get a generated hidden sibling per file."
        )

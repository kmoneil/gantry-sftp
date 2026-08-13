"""Uploading a file, in its two shapes, and publishing the result.

`put` is the only public name in this concern and it stays on
:class:`~gantry_sftp.session.Session`, because it is the API. Everything under it is here, as
functions taking a session, for the reason :mod:`gantry_sftp.session._policy` gives for its own
membership: the module is the boundary rather than the name, and a concern nobody can read in one
place is a concern that grows by absorbing the next thing (D-128, D-146).

**Three modules serve this direction and they divide by what they need.**
:mod:`gantry_sftp.session._upload` is the scheduler -- a dispatcher, a handle and an fd, no
session. :mod:`gantry_sftp.session._publish` is the vocabulary and the pure arithmetic --
`Publish`, `UploadResult`, `staged_path` -- testable with no server at all. This is the
orchestration between them: it holds a session, awaits replies, and decides in what order.

**What made the split possible is that none of it reaches for private state any more** (D-146).
The four members that did were sending requests by hand -- `FSETSTAT` twice, an `fsync` attempt
and a `posix-rename` attempt -- and each is now one call to an operation the session names:
`fchmod`, `futime`, `fsync_if_supported`, `posix_rename_if_supported`. That was the finding
rather than the plan: they were misfiled by *layer*, one above where they belonged, and reading
them as a concern to extract had the diagnosis backwards.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import anyio
from anyio.to_thread import run_sync

from gantry_sftp.codec import (
    EXTENSION_FSYNC,
    EXTENSION_POSIX_RENAME,
    OpenFlag,
    Times,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    ServerError,
    SFTPError,
    TransferError,
)
from gantry_sftp.session._download import ProgressCallback
from gantry_sftp.session._handles import close_quietly
from gantry_sftp.session._journal import SourceIdentity, UploadJournal
from gantry_sftp.session._mode import CREATE_BITS, create_bits
from gantry_sftp.session._policy import _local_size, _local_times
from gantry_sftp.session._publish import (
    Durability,
    PublishMechanism,
    SizeCheck,
    TimePreservation,
    UploadResult,
)
from gantry_sftp.session._quirks import server_note
from gantry_sftp.session._verify import Verify, gate_resume, verify_content

if TYPE_CHECKING:
    from gantry_sftp.session._operations import _SessionOperations


_TRUNCATE_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
"""Open flags for writing a file in place: create it, or replace what is there."""

_RESUME_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT
"""Open flags for a resumed upload: adopt what is there, and do not truncate it.

No ``TRUNC``, obviously, and no ``EXCL`` -- adopting an existing file is the whole point, and
``EXCL`` is the flag that refuses to. Losing it loses the collision check with it, which is
why a resumed atomic publish demands a caller-chosen staging name."""

_STAGE_FLAGS = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL
"""Open flags for a staging file, and ``EXCL`` is the load-bearing one.

Without it, a name collision means two publishers writing into one file at different offsets,
producing a result that is the wrong length or interleaved -- plausible, and wrong, which is
the failure class this whole module exists to prevent. With it, a collision is an error.

Measured cost: OpenSSH answers ``FAILURE`` for ``CREAT|EXCL`` on an existing file, which is
the v3 catch-all, so a server that does not implement ``EXCL`` and one whose staging name is
taken are indistinguishable from the status code alone. The escape hatch for such a server is
``atomic=False``, and the error says so.
"""

_FEATURE_DURABLE_UPLOAD = "durable upload"
"""``CapabilityError.feature`` for every refusal ``require_fsync=True`` can produce.

A constant rather than a literal per site because ``feature`` is the half of that exception a
caller **branches on** -- it exists so a handler can ask *what* was unavailable without reading
prose -- and the three sites that raise it are hundreds of lines apart: the pre-flight check
against a server already known to refuse ``fsync``, the probe on the staging handle, and the
in-place path. One of them drifting to "durable uploads" would break a caller's branch while
every message still read correctly. The tests pin the value as a literal, on purpose: an
assertion importing this name would move with it and prove nothing."""

_FEATURE_ATOMIC_PUBLISH = "atomic publish"
"""``CapabilityError.feature`` for every refusal ``require_atomic=True`` can produce.

Same argument as :data:`_FEATURE_DURABLE_UPLOAD`, over the rootedness check and the two
``posix-rename`` refusals."""


class _StagedIsTheOnlyCopyError(Exception):
    """Internal signal: the destination may be gone and the staging file is all that is left.

    Raised only from the ``REMOVE``-then-``RENAME`` fallback. The normal cleanup would delete
    the staging file, which in this window holds the *only* copy of the data, turning a
    recoverable failure into an unrecoverable one.

    Never escapes the session: it is unwrapped at the boundary and the original failure is what
    the caller sees, with a note saying where the file is.

    Args:
        failure: What went wrong, re-raised unchanged at the boundary. May be a cancellation.
        destination_removed: Whether the ``REMOVE`` is *known* to have succeeded. False when
            the remove itself failed in a way that does not say -- a timeout, a lost
            connection, cancellation -- because the request may well have been executed with
            only the answer going missing. The two cases get different notes: telling somebody
            their file was deleted when it may still be there sends them to restore a backup
            they did not need.
    """

    def __init__(self, failure: BaseException, *, destination_removed: bool) -> None:
        super().__init__("the destination was removed and the staged file could not replace it")
        self.failure = failure
        self.destination_removed = destination_removed


@dataclass(frozen=True, slots=True)
class _Upload:
    """The knobs one ``put`` carries through its helpers.

    A parameter object rather than eight more positional arguments threaded through four
    methods: the staging path and the destination differ between them, everything here does
    not.
    """

    local_path: Path | str
    fsync: bool
    require_fsync: bool
    progress: ProgressCallback | None
    depth: int | None
    resume: bool = False
    preserve_times: bool = False
    verify: Verify = Verify.SIZE
    # Already resolved to a number by `put`: `Mode.PRESERVE` needs the local file, and reading
    # it once at the top beats every helper below deciding again whether to stat.
    mode: int | None = None


async def _confirm_size(session: _SessionOperations, path: bytes, expected: int) -> SizeCheck:
    """Rung 3 of DESIGN.md 6's ladder: does the remote file have the length it should?

    Args:
        session: The session to ask.
        path: Remote file to measure. On the atomic path this is the *staging* file, so
            the answer arrives before anything is published.
        expected: Length it should have -- the local file's size, not the byte count this
            run moved, which differs under ``resume``.

    Returns:
        Which of the two answerable outcomes happened. A *mismatch* is not among them.

    Raises:
        TransferError: If the server reports a length and it is not ``expected``. Raised
            rather than reported, because there is no useful thing a caller does with a
            published file of the wrong size, and returning it as a value is how a
            truncation gets logged and ignored.
    """
    # Three states, and the errored one decided explicitly. A server that refuses to STAT
    # the file it just accepted has told us nothing about its length -- it has not told us
    # the upload failed. Propagating would replace the diagnosis with an unrelated one on
    # the very path where the diagnosis matters most: `_publish`'s fallback needs the
    # rename's refusal to be the error the caller sees. This is the same call
    # `_confirmed_present` makes for the same reason, and the same one the `limits` probe
    # makes -- an optional measurement that fails degrades, it does not fail the operation
    # it was measuring.
    try:
        size = (await session.stat(path)).size
    except ServerError:
        return SizeCheck.UNAVAILABLE
    if size is None:
        # Not a failure either. Every server in the matrix reports one, so this branch
        # keeps a server we have not met from being refused over a tuning fact -- and it
        # reports unavailable rather than passed, because a check that could not run did
        # not run.
        return SizeCheck.UNAVAILABLE
    if size != expected:
        raise TransferError(
            f"uploaded {expected} bytes but {path!r} is {size} bytes on the server; "
            f"the transfer was truncated or the file changed underneath it",
            transferred=size,
            offset=size,
            remote_path=path,
        )
    return SizeCheck.MATCHED


async def _put_in_place(
    session: _SessionOperations, upload: _Upload, target: bytes
) -> UploadResult:
    """Write the destination directly, which a consumer can observe half-written.

    Nothing is cleaned up on failure, and that is not an oversight: the destination *is*
    the file being written, so there is nothing to remove that would not be deleting the
    caller's data. A failed in-place write leaves a truncated destination, which is what
    ``atomic=False`` means.

    Resuming here reads the destination's own length and continues into it. That is the
    one place the two flags cooperate without an extra name: in-place has already given
    up on the consumer never seeing a partial file, which is the same thing a resumable
    upload leaves lying around between runs.
    """
    start = await _upload_resume_offset(session, upload, target)
    # Before the OPEN, so a refused prefix leaves the destination exactly as it was found.
    # The sibling refusals in `_upload_resume_offset` are at this same point for the same
    # reason, and a gate that first truncates what it is about to reject is not a gate.
    resume_check = await gate_resume(session, target, upload.local_path, start, upload.verify)
    handle = await session.open(
        target,
        _RESUME_FLAGS if upload.resume else _TRUNCATE_FLAGS,
        mode=create_bits(upload.mode),
    )
    if upload.mode is not None:
        # **Before the first byte, and only on this path.** `open(2)` applies its mode
        # argument to a file it *creates* and ignores it for one that already exists, so
        # writing in place over an existing destination would otherwise fill it while it
        # still wore whatever permissions it had before -- the window `mode=` exists to
        # close, in the one case where the OPEN cannot close it. The staged path has no
        # equivalent: its file is always new, `EXCL` proves it, and nothing can open the
        # destination by name until the rename.
        await session.fchmod(handle, upload.mode & CREATE_BITS, path=target)
    transferred, durability, times, published_mode = await _fill_and_close(
        session, upload, handle, target, start_offset=start
    )
    # After the fact, necessarily: in place, the destination *is* the file being written,
    # so there is no earlier moment at which a short write could have been caught. That is
    # the same trade `atomic=False` already makes, and it is why the atomic path checks
    # the staging file instead.
    expected = _local_size(upload.local_path)
    size_check = await _confirm_size(session, target, expected)
    content_check = await verify_content(
        session, target, upload.local_path, expected, upload.verify
    )
    return UploadResult(
        transferred,
        target,
        PublishMechanism.IN_PLACE,
        durability,
        size_check,
        times,
        content_check,
        resume_check,
        mode=published_mode,
    )


async def _put_atomically(
    session: _SessionOperations,
    upload: _Upload,
    target: bytes,
    staged: bytes,
    *,
    require_atomic: bool,
    journal: UploadJournal | None = None,
    source: SourceIdentity | None = None,
) -> UploadResult:
    """Stage, flush, then publish -- and clean the staging file up on any failure.

    ``require_atomic`` is answered from what the server *advertised*, deliberately, even
    though :meth:`posix_rename_if_supported` will attempt the extension regardless. A demand
    for a guarantee should not be answered by an experiment that costs a nine-gigabyte upload
    first. The opportunistic attempt belongs on the path where the fallback is acceptable;
    the strict path gets a cheap, deterministic answer, and the cost of that choice is a
    false refusal against a server that both under-advertises *and* has a destination
    already in place. Such a caller drops ``require_atomic`` and reads
    :attr:`~gantry_sftp.session.UploadResult.mechanism` instead.
    """
    if require_atomic and not session.supports(EXTENSION_POSIX_RENAME):
        await _refuse_unpublishable(session, target)

    # **Before the OPEN, and before the refusals below, which is the ordering that matters**
    # (D-166). An unanswered request must be assumed to have been performed, so the note that
    # says where the bytes are going has to be durable before anything could create the file.
    # Written even on the paths that then refuse: a record pointing at a file that was never
    # opened costs one wasted `STAT` next run, and a file with no record is one nobody can ever
    # find again.
    #
    # In a worker thread (D-176), which does not weaken that ordering by a byte: the `await`
    # returns only once the record is written *and* `fsync`ed, so nothing below it can run
    # before the note is durable. What moves is which thread waits for the disk -- and this
    # one waits for an `fsync`, so on the loop thread it is the longest stall the journal has.
    if journal is not None and source is not None:
        await run_sync(journal.staging, staged, target, source)

    start = await _upload_resume_offset(session, upload, staged)
    # Outside the try, with the sibling refusals, and that placement is the decision. A
    # rejected prefix inside it would reach `_discard` and delete the staging file -- which
    # is the caller's named file under `resume=`, is possibly another publisher's, and is
    # the only evidence of what went wrong. Refusing must not also destroy.
    resume_check = await gate_resume(session, staged, upload.local_path, start, upload.verify)
    handle = await _open_staging_file(
        session, staged, target, resume=upload.resume, mode=create_bits(upload.mode)
    )
    try:
        if upload.require_fsync:
            # Inside the try, so a refusal takes the staging file with it. One round trip,
            # paid only by a caller who demanded durability against a server that did not
            # claim it -- and it saves that caller a whole upload when the answer is no.
            await _probe_durability(session, handle, staged)
        # The times and the mode land on the *staging* handle, inside `_fill_and_close`,
        # which is the only place they can: `rename(2)` alters neither, so setting them
        # before the publish is what makes the published file carry them. Setting them
        # after the rename would need a second round trip to a path that a consumer can
        # already see, and would briefly publish a file with the wrong timestamps -- or,
        # for the mode, with permissions the caller explicitly asked it not to have.
        transferred, durability, times, published_mode = await _fill_and_close(
            session, upload, handle, staged, start_offset=start
        )
        # Before the rename, deliberately. Checking the *destination* afterwards would
        # report a truncation that consumers can already see, which is the failure atomic
        # publish exists to prevent; checking the staging file means a short upload never
        # becomes the destination at all. A mismatch raises into the cleanup path below,
        # so the staging file goes and the destination is left alone.
        expected = _local_size(upload.local_path)
        size_check = await _confirm_size(session, staged, expected)
        # Same moment and the same argument, one rung up: corrupt content that never
        # becomes the destination is a failed upload, and corrupt content that does is a
        # consumer reading it. This one is inside the try on purpose -- unlike the resume
        # gate, the staging file it would discard is one we just wrote and know is wrong.
        content_check = await verify_content(
            session, staged, upload.local_path, expected, upload.verify
        )
        mechanism = await _publish(session, staged, target, require_atomic=require_atomic)
    except _StagedIsTheOnlyCopyError as lost:
        # Do NOT clean up. The destination has already been removed, or may have been, and
        # this file is the only copy of the data; deleting it here would turn a failure
        # someone can undo by hand into one nobody can. The original failure is re-raised
        # unchanged -- which matters when it is a cancellation, because converting one into
        # an ordinary exception would break the structured concurrency it belongs to.
        lost.failure.add_note(
            (
                f"the destination {target!r} was removed and the rename that should have "
                f"replaced it failed; the uploaded file is intact at {staged!r} and is now "
                f"the only copy of it"
            )
            if lost.destination_removed
            else (
                f"the destination {target!r} may already have been removed and was not "
                f"replaced; the uploaded file is intact at {staged!r} and may now be the "
                f"only copy of it"
            )
        )
        raise lost.failure from None
    except BaseException as error:
        await _discard(session, staged, error)
        # After the discard and only when it was reached: the staging file is gone, so the
        # record pointing at it would send the next run looking for something gone. The
        # `_StagedIsTheOnlyCopyError` branch above deliberately does not reach here, because
        # there the file is the only copy of the data and the record is how anybody finds it.
        #
        # Shielded for the reason `_discard` above it is (D-176). Moving this write to a
        # worker made it an `await`, and an `await` in the cleanup path of a *cancelled*
        # upload is one that raises instead of running -- which is exactly the failure this
        # clears the record for, and the one place a plain `await` would have silently
        # stopped clearing it.
        if journal is not None:
            with anyio.CancelScope(shield=True):
                await run_sync(journal.published, target)
        raise
    if journal is not None:
        await run_sync(journal.published, target)
    return UploadResult(
        transferred,
        target,
        mechanism,
        durability,
        size_check,
        times,
        content_check,
        resume_check,
        staged_at=staged,
        mode=published_mode,
    )


async def _open_staging_file(
    session: _SessionOperations,
    staged: bytes,
    target: bytes,
    *,
    resume: bool,
    mode: int | None = None,
) -> bytes:
    """Create the staging file, or fail in a way that names what to do about it.

    Kept separate because **a failed OPEN must not reach the cleanup path**: nothing of
    ours exists yet, and the most likely reason for `EXCL` to refuse is that somebody else
    is publishing to the same destination. Removing the file in the way would destroy the
    upload they are in the middle of.

    The note matters more than it looks. This is the first failure a user meets when the
    new default does not suit their server, and without it the message names a dot-file
    they never typed, in answer to a call about a path they did.

    ``resume`` drops ``EXCL``, because adopting the previous run's staging file is the
    entire point and ``EXCL`` exists to refuse exactly that. What is lost with it is the
    collision check, and **there are two ways to arrive here, not one** -- this said only
    the first until D-180 found it stale.

    A caller who passed ``staging_name`` chose the name, so its predictability is their
    decision and they were told. A caller who passed a ``journal`` did not: D-166 amended
    :func:`_check_publish_flags` to accept one as the alternative, and
    :func:`~gantry_sftp.session.resume_target` then hands back the path recorded for this
    target -- which is the **only** resume a tree has, since
    :func:`~gantry_sftp.session._policy._check_tree_publish` refuses a ``staging_name``
    outright. So the pre-journal reading of this paragraph missed the common case.

    What makes that safe is a different argument and a stronger one. The name is still
    :func:`~gantry_sftp.session.staging_token`'s ``os.urandom``, generated fresh when the
    interrupted run staged the file; the journal makes this run's own name *recoverable*
    rather than making any name guessable, and it is written by
    :func:`~gantry_sftp.session._journal.replace_atomically` to a ``0600`` file at a path
    nobody can derive. Unpredictable to anybody without read access to the caller's own disk,
    which is the same line D-175 drew around those two files.

    ``mode`` is the *creation* mode, so the staging file is never briefly more permissive
    than the destination it is going to become. On a resume it does nothing, which is
    correct rather than a gap: the file already exists, ``open(2)`` ignores the mode for
    one that does, and the exact bits land on the handle before the publish either way.
    """
    try:
        return await session.open(staged, _RESUME_FLAGS if resume else _STAGE_FLAGS, mode=mode)
    except SFTPError as refusal:
        refusal.add_note(
            f"{staged!r} is the staging file for {target!r}. Publishing atomically needs "
            f"the right to create and rename a second name in that directory, and a name "
            f"that is not already taken -- pass atomic=False to write the destination "
            f"directly instead, or staging_name= to put the staging file elsewhere."
        )
        raise


async def _probe_durability(session: _SessionOperations, handle: bytes, path: bytes) -> None:
    """Settle whether this server can flush, before the upload rather than after it.

    DESIGN.md 4.2 says capability detection is advertisement **plus an optional probe**,
    and this is the one probe the library sends. It is here because this is the one place
    a probe is both safe and free: an ``fsync`` on a staging file that was created moments
    ago and holds nothing is idempotent, touches nobody else's data, and answers the
    question a ``require_fsync`` caller asked for a definite answer to.

    **Only on the atomic path**, and the asymmetry is deliberate rather than an oversight.
    In place, the destination has already been opened -- truncated, usually -- by the time
    a handle exists, so refusing here would destroy the caller's file to report a
    capability that was never going to be used. There the honest moment is after the
    bytes: the data is written and complete, and only the guarantee is missing, which is
    what :meth:`_flush` raises.

    Skipped when the server advertises the extension: the claim is enough to proceed on,
    and a server that then answers ``OP_UNSUPPORTED`` is caught by :meth:`_flush` with the
    upload already discarded by the staging path's cleanup.

    Raises:
        CapabilityError: If the server did not perform it.
    """
    if session.supports(EXTENSION_FSYNC):
        return
    if not await session.fsync_if_supported(handle):
        refusal = CapabilityError(
            f"require_fsync=True and this server did not perform {EXTENSION_FSYNC} when "
            f"asked, so nothing can promise the bytes reached stable storage",
            feature=_FEATURE_DURABLE_UPLOAD,
            missing=(EXTENSION_FSYNC,),
            path=path,
        )
        refusal.add_note(server_note(session.profile, len(session.extensions)))
        raise refusal


async def _fill_and_close(
    session: _SessionOperations, upload: _Upload, handle: bytes, path: bytes, *, start_offset: int
) -> tuple[int, Durability, TimePreservation, int | None]:
    """Push the file through an open handle, set its metadata, flush it, and close it.

    Everything except the write happens while the handle is still open, because that is
    the only time it can: ``fsync@openssh.com`` on a closed handle answers
    ``NO_SUCH_FILE``, and a handle is the only thing ``FSETSTAT`` can address.

    **Mode, then times, then the flush**, so the metadata the caller asked for is inside the
    durability barrier rather than outside it. Getting this order backwards would flush the
    bytes and then modify the inode, which is a narrower window than the one ``fsync``
    exists to close but is the same class of mistake.

    **The mode lands only now, after the content is complete**, and that is what the
    ``0o777`` narrowing on the creating ``OPEN`` is for: setuid, setgid and sticky are
    deliberately withheld until there is a finished file to apply them to, because a setuid
    file that exists half-written is privileged before it is finished. The ordinary bits are
    already correct from birth -- ``umask`` can only clear them, so a file created with the
    requested mode is never *more* permissive than what lands here.

    Both publish paths route through here, which is what makes one insertion cover them
    both -- and on the atomic path the handle is the *staging* file's, so the mode and the
    times are set before the rename that publishes it.
    """
    try:
        transferred = await session.upload_from(
            handle,
            upload.local_path,
            depth=upload.depth,
            progress=upload.progress,
            remote_path=path,
            start_offset=start_offset,
        )
        if upload.mode is not None:
            await session.fchmod(handle, upload.mode, path=path)
        times = await _set_times(session, upload, handle)
        durability = await _flush(session, upload, handle)
    except BaseException:
        # Closing is not optional -- a leaked handle counts against max-open-handles and
        # is invisible from this side until the server refuses to open anything. But it
        # must not replace the error that got us here with one about the close.
        await close_quietly(session, handle)
        raise
    await session.close(handle)
    return transferred, durability, times, upload.mode


async def _upload_resume_offset(session: _SessionOperations, upload: _Upload, path: bytes) -> int:
    """How much of ``path`` the server already holds, if we are allowed to trust it.

    ``0`` for a fresh upload, and ``0`` when the file is not there yet -- which is the
    ordinary case for a first attempt with ``resume=True`` and is not an error.

    Two refusals, both in the direction that raises:

    * **The server will not report a size.** Then there is no offset to continue from and
      nothing to check, and guessing zero would silently re-send a nine-gigabyte file
      while the caller believes they asked not to.
    * **The remote is longer than the local file.** Whatever is there, it is not a prefix
      of what we are sending. Continuing would leave a file that is part one upload and
      part another, of the right length, and wrong.

    What it cannot check is the case that matters most: a remote partial of the *right*
    length from the *wrong* source. A size match proves the byte count agrees. That is
    why this is opt-in and documented as the weaker claim rather than presented as
    "resume support".
    """
    if not upload.resume:
        return 0
    local_size = _local_size(upload.local_path)
    try:
        attributes = await session.stat(path)
    except NoSuchFileError:
        return 0
    if attributes.size is None:
        raise TransferError(
            f"resume needs a size for {path!r} and this server did not report one, "
            f"so there is no offset to continue from and nothing to check it against",
            remote_path=path,
            local_path=str(upload.local_path),
        )
    if attributes.size > local_size:
        raise TransferError(
            f"cannot resume: {path!r} is {attributes.size} bytes on the server and the "
            f"local file is only {local_size}, so what is there is not a prefix of what "
            f"we are sending",
            transferred=0,
            offset=attributes.size,
            remote_path=path,
            local_path=str(upload.local_path),
        )
    return attributes.size


async def _set_directory_times(
    session: _SessionOperations, entries: Sequence[tuple[bytes, Times]]
) -> None:
    """Stamp remote directories, once every file inside them has been written.

    **After, necessarily.** Creating or renaming a file inside a directory updates *that
    directory's* mtime, so stamping one before its contents exist is undone by the very
    next transfer. Setting the times of a nested directory does **not** dirty its parent --
    that only tracks changes to its own entries -- so the order within this pass does not
    matter and none is imposed.

    ``SETSTAT`` on the path rather than ``FSETSTAT``, because no handle is held: a
    directory handle comes from ``OPENDIR`` and exists to be read, not written through.

    A refusal is swallowed per directory. The tree's *files* are the payload and they are
    already published; failing a completed upload because a server would not restamp a
    directory would be the wrong trade, and it is the same one :meth:`_set_times` makes for
    a file.
    """
    for path, times in entries:
        with suppress(ServerError):
            await session.utime(path, times.atime, times.mtime)


async def _set_directory_modes(
    session: _SessionOperations, entries: Sequence[tuple[bytes, int]]
) -> None:
    """Set remote directory modes, once every file inside them has been written.

    **After, necessarily**, and for a stronger reason than :meth:`_set_directory_times`
    has: a directory created ``0o500`` would refuse the uploads that belong in it, so its
    source mode cannot be applied on the way down. Nothing here depends on order --
    changing a nested directory's mode does not touch its parent's.

    ``SETSTAT`` on the path rather than ``FSETSTAT``, because no handle is held: a directory
    handle comes from ``OPENDIR`` and exists to be read. One flag per call, for the reason
    :meth:`chmod` gives.

    A refusal is swallowed per directory, matching the timestamps and *not* matching a
    file's mode, which fails the upload. The difference is what the caller asked for: a file
    mode is the thing ``mode=`` controls, and a directory mode is carried along beside it.
    The tree's files are the payload and they are already published.
    """
    for path, mode in entries:
        with suppress(ServerError):
            await session.chmod(path, mode)


async def _set_times(
    session: _SessionOperations, upload: _Upload, handle: bytes
) -> TimePreservation:
    """Stamp the open handle with the local file's times, or report why not.

    ``FSETSTAT`` rather than ``SETSTAT`` on the path, for two reasons. On the atomic path
    the file's name is the staging name and it is about to change, so addressing it by
    handle is addressing the thing rather than a name for it. And a path-based call between
    the write and the publish is a second chance for something else to swap what that name
    refers to.

    The times cannot ride along on the ``OPEN`` that created the handle. OpenSSH's
    ``process_open`` reads only ``PERMISSIONS`` out of that request's ATTRS, to pass as
    ``open(2)``'s mode, and ignores ``ACMODTIME`` entirely -- verified in ``sftp-server.c``,
    not assumed from the draft, which describes the field as settable there.
    """
    if not upload.preserve_times:
        return TimePreservation.SKIPPED
    times = _local_times(upload.local_path)
    try:
        await session.futime(handle, times.atime, times.mtime)
    except ServerError:
        # Not fatal, and deliberately so: the bytes are the payload. A server that will
        # not set times has still stored the file correctly, and discarding a completed
        # upload over its metadata would be the wrong trade. The result says which
        # happened -- see TimePreservation.UNAVAILABLE.
        return TimePreservation.UNAVAILABLE
    return TimePreservation.PRESERVED


async def _flush(session: _SessionOperations, upload: _Upload, handle: bytes) -> Durability:
    """Flush the handle, reporting what was possible rather than promising what was not.

    **Attempted rather than pre-judged on advertisement** (D-51). This used to return
    ``UNAVAILABLE`` without sending anything when ``fsync@openssh.com`` was not in the
    server's list -- which under-reports durability on exactly the population this library
    is aimed at, since the enterprise endpoints of DESIGN.md 7 advertise nothing and
    implement some of it. The cost of asking is one round trip, once per session: an
    ``OP_UNSUPPORTED`` is cached, so the second upload does not ask again.

    It is also what makes the policy consistent. ``posix-rename`` has always been
    attempted regardless of advertisement, on the argument that advertisement is a claim
    and the answer is a fact; there was never a reason for ``fsync`` to be judged
    differently, only an asymmetry nobody had noticed.
    """
    if not upload.fsync:
        return Durability.SKIPPED
    try:
        flushed = await session.fsync_if_supported(handle)
    except ServerError:
        # Advertised and then refused. The bytes may still be in a cache, which the
        # result says; a caller who cannot accept that asked for require_fsync.
        if upload.require_fsync:
            raise
        return Durability.UNAVAILABLE
    if flushed:
        return Durability.FSYNCED
    if upload.require_fsync:
        # Two ways here, and neither is the atomic path's ordinary one. An in-place upload
        # never probes -- opening the destination has already truncated it, so there is no
        # cheap moment left to refuse at, and the honest report is that the bytes are
        # written and the guarantee is not. Or a server that *advertised* the extension
        # answered OP_UNSUPPORTED when asked, in which case the claim was false and the
        # staging file is about to be discarded. See `_probe_durability`.
        refusal = CapabilityError(
            f"require_fsync=True and this server did not perform {EXTENSION_FSYNC}, "
            f"so nothing can promise the bytes reached stable storage",
            feature=_FEATURE_DURABLE_UPLOAD,
            missing=(EXTENSION_FSYNC,),
        )
        refusal.add_note(server_note(session.profile, len(session.extensions)))
        raise refusal
    return Durability.UNAVAILABLE


async def _publish(
    session: _SessionOperations, staged: bytes, target: bytes, *, require_atomic: bool
) -> PublishMechanism:
    """Move the staged file onto the destination by the strongest available mechanism."""
    if await session.posix_rename_if_supported(staged, target):
        return PublishMechanism.POSIX_RENAME
    return await _publish_by_plain_rename(session, staged, target, require_atomic=require_atomic)


async def _publish_by_plain_rename(
    session: _SessionOperations, staged: bytes, target: bytes, *, require_atomic: bool
) -> PublishMechanism:
    """Plain ``RENAME``, and the documented non-atomic fallback when that will not do.

    A plain rename onto an absent target *is* atomic -- v3 RENAME cannot overwrite, so a
    success proves the destination appeared whole. The refusal is the interesting case,
    and ``FAILURE`` is a v3 catch-all that names nothing: it could be the target being in
    the way, or the directory being read-only. So the target is STATed before anything is
    deleted. Removing a good file on the strength of a guess about an error string is a
    worse outcome than the failure it was trying to recover from.

    Raises:
        _StagedIsTheOnlyCopyError: If the destination was removed and the rename after it
            failed, so that the caller knows not to clean the staging file up.
    """
    try:
        await session.rename(staged, target)
    except ServerError as refusal:
        if not await _confirmed_present(session, target):
            raise
        if require_atomic:
            raise CapabilityError(
                f"require_atomic=True but {target!r} already exists and this server does "
                f"not advertise {EXTENSION_POSIX_RENAME}; replacing it would mean "
                f"removing it first, leaving a window with no file at all",
                feature=_FEATURE_ATOMIC_PUBLISH,
                missing=(EXTENSION_POSIX_RENAME,),
                path=target,
            ) from refusal
    else:
        return PublishMechanism.RENAME

    # The window this rung is named for. Everything from the REMOVE onwards is unwindable
    # only by hand, so *any* failure from here must leave the staged file where it is --
    # including a failure of the REMOVE itself. That was the D-74 bug: this call sat
    # outside the guard, so a REMOVE the server performed but never acknowledged fell
    # through to the ordinary cleanup, which deleted the staging file with the destination
    # already gone. Both copies, and a message saying only that a request timed out.
    try:
        await session.remove(target)
    except BaseException as removal_failure:
        if isinstance(removal_failure, ServerError):
            # Definitive: the server answered and said no, so nothing was removed and the
            # destination is intact. The staging file is litter, not the only copy, and
            # leaving it behind would trade one silent failure for another.
            raise
        # Anything else -- a timeout, a lost connection, cancellation -- leaves us unable
        # to say whether the REMOVE ran, and very often it did: the request goes out, the
        # server performs it, and only the answer is missing. Assuming it ran costs a
        # staging file left behind; assuming it did not costs the only remaining copy.
        raise _StagedIsTheOnlyCopyError(
            removal_failure, destination_removed=False
        ) from removal_failure

    try:
        await session.rename(staged, target)
    except BaseException as second_failure:
        # `BaseException`, not `Exception`: anyio's cancellation is a `BaseException`, and
        # concurrent transfers are the whole point of this library -- a sibling task
        # failing inside a task group cancels this one, in the one window where the
        # staging file is the only copy of the data. The cancellation itself is re-raised
        # unchanged at the boundary, so structured concurrency is preserved; all this
        # suppresses is the cleanup.
        raise _StagedIsTheOnlyCopyError(
            second_failure, destination_removed=True
        ) from second_failure
    return PublishMechanism.REMOVE_RENAME


async def _refuse_unpublishable(session: _SessionOperations, target: bytes) -> None:
    """Refuse before the transfer if the destination cannot be replaced atomically.

    Raises:
        CapabilityError: If the destination exists and there is no atomic overwrite.
    """
    if not await _confirmed_present(session, target):
        return
    refusal = CapabilityError(
        f"require_atomic=True but {target!r} already exists and this server does not "
        f"advertise {EXTENSION_POSIX_RENAME}, so it cannot be replaced in one step",
        feature=_FEATURE_ATOMIC_PUBLISH,
        missing=(EXTENSION_POSIX_RENAME,),
        path=target,
    )
    refusal.add_note(server_note(session.profile, len(session.extensions)))
    raise refusal


async def _confirmed_present(session: _SessionOperations, path: bytes) -> bool:
    """Whether the server *positively reported* that the name ``path`` is taken.

    Three states, and the third one is why this is not called ``_exists``: the request can
    succeed, report ``NO_SUCH_FILE``, or fail for some third reason -- permissions, a
    server that refuses to stat that path, a ``FAILURE`` meaning who knows what. Only the
    first is evidence. Anything else answers ``False``, because this predicate's callers
    use it to decide whether to *delete* something, and "the server would not tell us" is
    not a licence to do that.

    ``LSTAT`` rather than ``STAT``, because the question is whether the *name* is in the
    way. A destination that is a symlink whose target has been rotated away is still a
    name a rename cannot land on, and ``STAT`` would call it absent -- leaving the publish
    to fail with the rename's uninformative ``FAILURE`` and no fallback attempted.
    """
    try:
        _ = await session.lstat(path)
    except ServerError:
        return False
    return True


async def _discard(session: _SessionOperations, staged: bytes, error: BaseException) -> None:
    """Remove a staging file after a failure, and say so if that did not work.

    Shielded from cancellation, because a cancelled nine-gigabyte upload is precisely
    when a staging file gets left behind, and it is still bounded: every request carries
    ``request_timeout``, so a dead connection cannot make cleanup hang. That bound only
    means anything because the reader outlives the cancellation as well -- a ``REMOVE``
    whose reply nobody can route waits out the whole timeout and then leaves the file
    behind anyway. See :meth:`~gantry_sftp.session.Dispatcher.run`.

    The failure is recorded as a note on the original exception rather than swallowed or
    raised. Swallowing it means the caller never learns a file was left on the server;
    raising it means replacing the real error with a housekeeping one.
    """
    with anyio.CancelScope(shield=True):
        try:
            await session.remove(staged)
        except Exception as cleanup_failure:  # see close_quietly on the breadth
            error.add_note(
                f"the staging file {staged!r} was left on the server: "
                f"removing it also failed ({cleanup_failure!r})"
            )

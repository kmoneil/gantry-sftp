"""Making a random staging name findable again after the process that chose it died (D-166).

An interrupted upload already survives the *connection* failing: the offsets are tracked, the
partial is adopted, and nothing is blindly replayed. It does not survive the **process** failing
-- a killed container, an OOM, a deploy, a laptop lid -- and for a tree of thousands of files
over a bad link that is the difference between continuing and starting again.

**Downloads already survive it and need nothing here.** A download's partial is a file on our own
disk, so its length is a fact rather than a report;
:func:`~gantry_sftp.session._policy._download_resume_offset` reads it, refuses when it exceeds
the remote size, and ``gate_resume`` proves the prefix where the server can. Measured across two
separate interpreter processes before this module was written. So this is an **upload-side**
feature, which is also what makes it tractable: the two directions never needed the same journal.

## What this is, and the objection it dissolves

``put(resume=True)`` with the default ``atomic=True`` is refused today, and
:func:`~gantry_sftp.session._policy._check_publish_flags` records why the obvious fix was
*rejected rather than overlooked*: a staging name derived from the target is predictable, which
is exactly what :func:`~gantry_sftp.session.staging_token` exists to avoid, and two publishers
resuming into one name would interleave into a single file.

**A journal dissolves that without weakening it.** The staging name stays random. The journal --
local, private to the run that wrote it -- is what makes *its own* token findable again. A second
publisher on another machine has a different journal and a different token, so the hazard the
policy refuses is untouched. This is not a workaround for that refusal; it is what makes the
refusal unnecessary in the single-publisher case, which is the case everybody is actually in.

## The one decision that keeps it safe: no offsets

**Nothing here records how many bytes were sent.** A journal that recorded intent and replayed it
would be a corruption engine, because after a crash the process knows what it *intended* and not
what the far end accepted -- and an upload's remote partial is a report from a server that may
have buffered, may have been killed mid-write, and is under no obligation to have flushed.

So this records a **name**, which is a fact about a decision we made locally, and never a
**quantity**, which would be a claim about somebody else's disk. Where to resume from is still
read off the server by ``_upload_resume_offset``, and how well that was proven is still labelled
by :class:`~gantry_sftp.session.ResumeCheck`. **This module adds no trust.** A journal that is
stale, truncated or lying costs a wasted ``STAT`` and a full re-upload; it cannot cost a wrong
file, and ``tests/test_journal.py`` asserts that rather than arguing it.

## Append-only, because a tree uploads concurrently

``put_tree(concurrency=N)`` runs N uploads against one journal, so a read-modify-write of a whole
document would need a lock and would lose records to interleaving. That sentence described a
capability the tree API refused for a day -- ``_check_tree_publish`` did not read the journal, so
``put_tree(resume=True)`` still raised the pre-journal argument at a caller who had answered it,
which D-172 fixed. Each event is instead one line, appended to a file opened ``O_APPEND`` and
``fsync``ed, and the state is folded on read:
a target with a ``staged`` line and no ``published`` line is one that may have a partial. The
append is a single :func:`os.write` of a short buffer, which is the assumption every append-only
log makes; :func:`compact` is how the file stops growing, and it is explicit rather than
automatic because it is the one operation here that rewrites.

**This is deliberately not** :class:`~gantry_sftp.session.SyncManifest`, whose entry shape was
the obvious thing to reuse. That type is a *cache*: its loader degrades every failure to "we know
nothing", because under-reporting costs a re-send and loses no data, and it is written once at
the end of a run. Both properties are wrong here. A journal must be written *as* progress
happens, and while under-reporting is merely slow, over-reporting is corruption -- so the
manifest's most carefully argued property is the one this must not have.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from gantry_sftp.session._listing import decode_name

__all__ = [
    "JOURNAL_VERSION",
    "JournalEntry",
    "SourceIdentity",
    "UploadJournal",
    "append_record",
    "compact",
    "entry_matches",
    "fold",
    "fsync_directory",
    "source_identity",
    "staged_for",
]

JOURNAL_VERSION = 1
"""Schema version on every line, so a future format can be recognised rather than misread.

Per line rather than per file, because the file is appended to by runs that may not share a
version -- an upgrade mid-tree is a deploy, which is one of the things this feature exists to
survive. A line whose version is not this one is dropped by :func:`fold`, which degrades to
"nothing is in flight for that target" and therefore to a full upload.
"""

_STAGED = "staged"
_PUBLISHED = "published"


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Which local file, and which version of it, an upload is sending.

    **Read once and passed down, rather than read at each place that wants it.** The lookup that
    finds a previous run's staging file and the record that notes this run's must describe the
    same bytes: a file edited between those two moments would otherwise be resumed as the old
    version and recorded as the new one, which is the splice this type exists to make
    impossible.

    Attributes:
        path: The source as the caller named it.
        size: Its size in bytes.
        mtime: Its modification time in whole seconds -- v3's resolution, so a record cannot
            hold more precision than any comparison could use.
    """

    path: str
    size: int
    mtime: int


def source_identity(local_path: Path | str) -> SourceIdentity:
    """Describe a local file for the journal, or as absent when it cannot be read.

    A missing or unreadable source records as zeroes rather than raising: this runs on the way
    into an upload that is about to open the file anyway, and ``open`` reports a missing source
    far better than this could. What matters is that the zeroes cannot match a real file's
    identity, so a resume is refused rather than attempted.
    """
    try:
        status = Path(local_path).stat()
    except OSError:
        return SourceIdentity(path=str(local_path), size=0, mtime=0)
    return SourceIdentity(path=str(local_path), size=status.st_size, mtime=int(status.st_mtime))


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One upload that had begun staging and had not yet been published.

    Attributes:
        staged: The remote path the bytes were being written to, as recorded before the first
            of them was sent. **The whole point of the file**: this name carries fresh
            randomness per call and is otherwise unrecoverable.
        target: The remote path it was to be published at.
        local_path: The source, as the caller named it. Recorded so a resume can refuse when it
            is being asked to continue a partial from a *different* file.
        local_size: The source's size when staging began.
        local_mtime: The source's modification time then, in whole seconds -- v3's resolution,
            so a record cannot hold more precision than a comparison could use.
    """

    staged: bytes
    target: bytes
    local_path: str
    local_size: int
    local_mtime: int

    def matches(self, source: SourceIdentity) -> bool:
        """Whether this entry describes an upload of the file the caller is asking about.

        Delegates to :func:`entry_matches` because ``@dataclass`` hides a method from the
        mutation lane (D-107), and this body is three comparisons joined by ``and`` -- which is
        exactly the shape a dropped conjunct makes silently wrong.
        """
        return entry_matches(self, source)


def _line(event: str, fields: dict[str, object]) -> bytes:
    """One record, as the bytes appended to the file.

    ``sort_keys`` so two runs writing the same facts produce the same bytes, which makes a
    journal diffable and a test able to assert on content rather than on a parse.
    """
    document: dict[str, object] = {"version": JOURNAL_VERSION, "event": event, **fields}
    return (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")


def append_record(path: Path | str, event: str, fields: dict[str, object]) -> None:
    """Append one record and make it durable before returning.

    **The ``fsync`` is the point and it is per record.** A journal that loses its tail in the
    same crash is worse than no journal, because it claims less progress than happened for a
    ``published`` line -- costing a re-upload, which is safe -- but *more* than happened for a
    ``staged`` line, which is the direction that leaves a caller resuming into a file that was
    never opened. Both are survivable only because nothing here records an offset; the ``fsync``
    is what keeps the cost at a wasted round trip.

    The directory entry is flushed too, and separately: a file's contents reaching stable
    storage says nothing about whether the *name* did, so a journal created for the first time
    in the run that crashes could otherwise vanish entirely.

    Args:
        path: The journal file. Created if it is not there, along with nothing else -- a
            missing parent directory is the caller's mistake and is reported as one.
        event: ``"staged"`` or ``"published"``.
        fields: The rest of the record.
    """
    destination = Path(path)
    first_time = not destination.exists()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        # One `write` of a short buffer, which is what makes the append atomic against the
        # other workers in a concurrent tree upload -- the kernel updates the offset and
        # writes under the same lock for an `O_APPEND` descriptor.
        _ = os.write(descriptor, _line(event, fields))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if first_time:
        fsync_directory(destination.parent)


def fsync_directory(directory: Path) -> None:
    """Flush a directory entry, ignoring a platform that will not let us.

    Shared with :mod:`gantry_sftp.session._sync`, which compacts its manifest the same way and
    needs the same guarantee once per run (D-173). One copy rather than two, because two guards
    stating one rule is what D-172 had just finished removing one module along.

    Windows refuses ``O_RDONLY`` on a directory and has no equivalent call; there the file's own
    flush is all that is available. Swallowed rather than raised because the alternative is an
    upload that fails on Windows for a reason that has nothing to do with the upload -- and the
    data path already refuses on Windows for a different and louder reason (D-82).
    """
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def fold(path: Path | str) -> dict[str, JournalEntry]:
    """Read the log and return what is still in flight, keyed by decoded target path.

    A target with a ``staged`` line and no later ``published`` line may have a partial on the
    server. Later lines win, so a target staged, published, and staged again reads as in flight,
    which is what it is.

    **Every failure degrades to "nothing is in flight"**, which costs a full upload and cannot
    cost a wrong file -- an unreadable file, an unparseable line, a record from a schema this
    version does not know. That is the same direction :class:`SyncManifest`'s loader takes and
    it is safe here for a different reason: the manifest degrades towards re-sending, and so
    does this, because the only thing a lost record can do is fail to point at a partial.

    Args:
        path: The journal file.

    Returns:
        Decoded target path to the entry describing its in-flight staging file.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return {}
    # Bytes and a replacing decode, not `read_text`. **Found by fuzzing this function**: the
    # file sits on disk between two runs of somebody's job, so it is not trusted input, and a
    # single stray byte made `read_text` raise `UnicodeDecodeError` -- which is a `ValueError`,
    # not an `OSError`, so it escaped the guard above and took down the upload it was supposed
    # to help. A replaced character makes its line unparseable as JSON, which folds to nothing,
    # which is the honest answer to garbage.
    entries: dict[str, JournalEntry] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        _apply(entries, line)
    return entries


def _apply(entries: dict[str, JournalEntry], line: str) -> None:
    """Fold one line into the state, ignoring anything that is not a record we wrote."""
    try:
        record: object = json.loads(line)
    except json.JSONDecodeError:
        return
    if not isinstance(record, dict):
        return
    # Rebuilt rather than passed along, and ty is why: `isinstance(x, dict)` narrows to
    # `dict[Unknown, Unknown]`, `dict` is invariant in both parameters, so the narrowed value is
    # not a `dict[str, object]` however obviously JSON keys are strings. mypy accepted it. The
    # comprehension states the fact the checker cannot infer instead of casting past it.
    fields: dict[str, object] = {str(key): value for key, value in record.items()}
    if fields.get("version") != JOURNAL_VERSION:
        return
    target = fields.get("target")
    if not isinstance(target, str):
        return
    if fields.get("event") == _PUBLISHED:
        _ = entries.pop(target, None)
        return
    if fields.get("event") != _STAGED:
        return
    entry = _entry_from(fields)
    if entry is not None:
        entries[target] = entry


def _entry_from(record: dict[str, object]) -> JournalEntry | None:
    """Rebuild a ``staged`` record, or ``None`` if it is not one this version understands."""
    staged, target, local_path = record.get("staged"), record.get("target"), record.get("local")
    size, mtime = record.get("local_size"), record.get("local_mtime")
    if not isinstance(staged, str) or not isinstance(target, str):
        return None
    if not isinstance(local_path, str) or not isinstance(size, int) or not isinstance(mtime, int):
        return None
    return JournalEntry(
        staged=staged.encode("utf-8", "surrogateescape"),
        target=target.encode("utf-8", "surrogateescape"),
        local_path=local_path,
        local_size=size,
        local_mtime=mtime,
    )


def compact(path: Path | str) -> int:
    """Rewrite the log holding only what is still in flight, and say how many that was.

    **Explicit rather than automatic**, because it is the one operation here that rewrites, and
    a rewrite is where an append-only file can lose records. It is safe to call while nothing
    else is using this journal and unsafe while something is: a concurrent worker appending
    between the fold and the replace has its record dropped. The sweep calls it; a transfer
    never does.

    Written to a sibling and renamed, so an interrupted compaction leaves the original log
    rather than half of one.

    Returns:
        How many entries survived, which is how many staging files may still be out there.
    """
    destination = Path(path)
    surviving = fold(destination)
    staging = destination.with_name(f"{destination.name}.compacting")
    lines = b"".join(_line(_STAGED, _fields_of(entry)) for entry in surviving.values())
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        _ = os.write(descriptor, lines)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    staging.replace(destination)
    fsync_directory(destination.parent)
    return len(surviving)


def entry_matches(entry: JournalEntry, source: SourceIdentity) -> bool:
    """Whether ``entry`` describes an upload of exactly the bytes ``source`` names.

    **Three fields rather than the path alone**, because the hazard is not a different name --
    it is the same name holding different bytes. A file edited between the killed run and this
    one has a partial on the server that is a prefix of something else, and resuming into it
    produces a plausible file that is a splice of two versions. Size and mtime are the same
    evidence ``sync_tree`` compares on, and they are what the protocol can carry.

    A module-level function so the mutation lane can see it: a dropped conjunct here would
    resume across a change the comparison exists to catch, and every other test would pass.
    """
    return (
        entry.local_path == source.path
        and entry.local_size == source.size
        and entry.local_mtime == source.mtime
    )


def staged_for(path: Path | str, target: bytes, source: SourceIdentity) -> bytes | None:
    """The staging path a previous run left for ``target``, or ``None``.

    Module-level for the reason :func:`entry_matches` is: the negation and the ``None`` check
    below decide whether a resume happens at all, and inverting either would either resume
    across a changed file or never resume anything.
    """
    entry = fold(path).get(decode_name(target))
    if entry is None or not entry_matches(entry, source):
        return None
    return entry.staged


def _fields_of(entry: JournalEntry) -> dict[str, object]:
    """The ``staged`` record for an entry. One place, so a rewrite cannot drift from a write."""
    return {
        "staged": decode_name(entry.staged),
        "target": decode_name(entry.target),
        "local": entry.local_path,
        "local_size": entry.local_size,
        "local_mtime": entry.local_mtime,
    }


@dataclass(frozen=True, slots=True)
class UploadJournal:
    """A durable note of which staging files an interrupted run may have left behind.

    ::

        from gantry_sftp.session import Publish, UploadJournal

        journal = UploadJournal(Path("/var/lib/myjob/uploads.journal"))
        await sftp.put(source, target, resume=True, publish=Publish(journal=journal))

    Passing one is what makes ``resume=True`` legal alongside ``atomic=True``: without it there
    is no way to find the previous run's staging file, and this library refuses rather than
    silently re-uploading. See this module's docstring for why that refusal was right and why
    this is not a way around it.

    **The file is the caller's to place and to keep.** There is no default location and there
    will not be one -- it has to outlive the process to be worth anything, so it cannot go
    anywhere this library would clean up, and choosing a directory on somebody's disk is not a
    decision a library gets to make.

    Attributes:
        path: Where the log lives. Its parent directory must exist.
    """

    path: Path

    def __post_init__(self) -> None:
        """Normalise a ``str``, so a caller need not care which this takes."""
        object.__setattr__(self, "path", Path(self.path))

    def staged_for(self, target: bytes, source: SourceIdentity) -> bytes | None:
        """The staging path a previous run left for ``target``, or ``None``.

        ``None`` for every reason: no journal file, no record, a record for a different source,
        or a source that has changed since. Each of those means "start a fresh upload", which is
        always safe, and none of them means "resume anyway". See :func:`staged_for`, which holds
        the body for the reason :meth:`JournalEntry.matches` gives.
        """
        return staged_for(self.path, target, source)

    def staging(self, staged: bytes, target: bytes, source: SourceIdentity) -> None:
        """Record that bytes are about to be written to ``staged``.

        **Called before the OPEN, never after it.** A record written afterwards would be missing
        for exactly the crash that happens during the transfer, which is the one this exists
        for: an unanswered request must be assumed to have been performed, so the note has to be
        durable before the request that could create the file.
        """
        append_record(
            self.path,
            _STAGED,
            _fields_of(
                JournalEntry(
                    staged=staged,
                    target=target,
                    local_path=source.path,
                    local_size=source.size,
                    local_mtime=source.mtime,
                )
            ),
        )

    def published(self, target: bytes) -> None:
        """Record that ``target`` was published, so nothing is in flight for it any more.

        A failure to write this line costs a stale entry, which costs one ``STAT`` of a staging
        file that is no longer there on the next run -- the cheap direction, and why the two
        events are not one record updated in place.
        """
        append_record(self.path, _PUBLISHED, {"target": decode_name(target)})

    def in_flight(self) -> dict[str, JournalEntry]:
        """Every target with a staging file that may still exist. See :func:`fold`."""
        return fold(self.path)

    def compact(self) -> int:
        """Drop the published records. See :func:`compact`."""
        return compact(self.path)

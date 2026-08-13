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

## Read once, then tailed -- because append-only is what makes that safe (D-176)

An append-only log read whole on every lookup is quadratic in the tree it is describing, and
``put`` performs exactly one lookup per file. Folding the log from byte zero once per file, in a
tree that appends two records per file to it, was measured at about fifteen minutes of CPU for
20,000 files -- **on the event-loop thread**, so every concurrent sibling was frozen for each of
them. The lookup now remembers how far into the file it has folded and reads only what was
appended since; :func:`_fold_tail` is that, and :class:`_Folded` is where it remembers.

**The freshness argument is the whole of why this is allowed**, because ``staged_for`` decides
whether bytes are appended to a file that already exists on a server. Three things carry it.
Every writer here appends to the *file* and none of them updates the folded state, so there is no
path on which the two can disagree about a record this process wrote. Every lookup re-opens the
file and reads to its current end, so a record **another** process appended is folded on the next
lookup rather than missed -- the property a fold-at-open cache would have lost, and the reason
this is incremental rather than cached. And the fold is keyed to the file it read: a log that was
replaced (:func:`compact` renames a new one over it) or truncated is a different file, is
detected as one, and is folded again from its first byte.

Two shapes fall out of that and are load-bearing rather than incidental. The state advances only
to the **last complete line**, so a torn write at the tail is re-read until the bytes that finish
it arrive, instead of being consumed as garbage and skipped forever. And a log with no newline in
it at all never advances, so it is re-read whole every time -- the cost this section exists to
remove, kept for a file that is not one this module wrote, which is the direction that cannot
produce a wrong answer.

**And the fold re-reads the byte it stopped at, which is what makes the argument a check.**
Identity and length between them cannot see a log truncated and rewritten *in place* back to at
least the length it had: same inode, no shrink to catch. Requiring the byte before the offset to
still be the newline the fold ended on is what notices, and it costs one byte of a read that was
already happening. Worth stating that even the undetected version of this could not have cost a
wrong file -- a misframed read yields lines that do not parse and records that are still checked
against :func:`entry_matches` -- but "it would have been safe anyway" is the argument this module
makes about a *lying* journal, and it should not have to make it about our own reader.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import mkstemp

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
    "replace_atomically",
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


def replace_atomically(destination: Path, payload: bytes) -> None:
    """Put ``payload`` at ``destination`` through a temporary sibling nobody else can name.

    **The name is the security decision** (D-175). Both rewrites here used to derive the
    temporary from the real file -- ``<journal>.compacting``, ``<manifest>.partial`` -- and open
    it ``O_CREAT|O_TRUNC``, which is a name a caller never asked for, in a directory this library
    does not own, that anybody able to write there could predict. A symlink planted at it was
    followed: the file it pointed at was truncated and overwritten, and the ``replace`` below
    then renamed the *link* over the real path, so every later append went there too.

    This is the argument :func:`~gantry_sftp.session._publish.staging_token` already makes about
    the file we create on the *server* -- a predictable staging name is what the randomness is
    for -- arriving at the two we create on the local disk. :func:`tempfile.mkstemp` is the
    whole mechanism: ``O_CREAT | O_EXCL``, plus ``O_NOFOLLOW`` where the platform has it, at a
    name that is not derivable. ``O_EXCL`` is doing work ``O_NOFOLLOW`` cannot, because a *hard*
    link at the name is not a symlink and would be written through.

    **The refusal stops at the name we chose.** The path the caller named is opened the way
    ``get`` opens a caller's download destination -- following a link, because a state file that
    is a symlink to somewhere else is a deployment rather than an attack, and ``no_follow`` is a
    parameter there and off by default. Where the journal may be placed is a documented rule
    instead: see :class:`UploadJournal` and ``docs/reliability.md``.

    Cleans up on any failure, which the predictable name did not do either -- a temporary left
    behind under a random name is litter nobody can identify, so the cost of the unpredictable
    name is paid here rather than by whoever finds it.

    Args:
        destination: The file to end up holding ``payload``. Its parent directory must exist.
        payload: The whole new contents.
    """
    descriptor, name = mkstemp(dir=destination.parent, prefix=f"{destination.name}.")
    staging = Path(name)
    try:
        try:
            _ = os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _ = staging.replace(destination)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    fsync_directory(destination.parent)


@dataclass(slots=True)
class _Folded:
    """How much of one log has been folded, into what, and which file it was (D-176).

    Pure state and no methods, for the reason :meth:`JournalEntry.matches` gives: a
    ``@dataclass`` hides its methods from the mutation lane, and every decision here -- which
    file this describes, whether to keep it, how far it got -- is one a dropped comparison
    would get silently wrong. The functions that read and advance it are module-level.

    Attributes:
        lock: Held across a read-and-advance. The lookup runs in a worker thread and a
            concurrent tree has one per file, so two of them advancing ``offset`` from the same
            starting value would consume one region twice and skip the next.
        device: ``st_dev`` of the file this was folded from, or ``-1`` before anything was.
        inode: ``st_ino`` of the same, and the pair is what makes a replaced log detectable.
        offset: How many bytes have been folded, always ending at a newline.
        entries: What those bytes said is still in flight, keyed by decoded target path.
    """

    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    device: int = -1
    inode: int = -1
    offset: int = 0
    entries: dict[str, JournalEntry] = field(default_factory=dict)


def _restart(state: _Folded, device: int, inode: int) -> None:
    """Forget a fold that cannot describe this file, so the next read starts at byte zero.

    Called for a log that was replaced or truncated, and for one that could not be read at all
    -- the second because a cache kept across a failure would answer from bytes nobody can
    still see. Both land on "nothing is in flight", which is a full upload and never a wrong
    file.
    """
    state.device, state.inode, state.offset, state.entries = device, inode, 0, {}


def _read_tail(state: _Folded, descriptor: int) -> bytes:
    """The bytes after the fold, having proved the fold still describes this file.

    Three things have to hold before a byte range can be read as "what was appended since", and
    a log that fails any of them is read whole from the start instead. One ``_restart`` rather
    than one per condition, because resetting the fold sets the offset to zero and every
    condition then routes to the same full read -- an earlier version had a second call above
    and the mutation lane is what showed it could not change an answer.

    **It is the same file.** ``(st_dev, st_ino)``, which is what :func:`compact` breaks: it
    renames a new log over this one, so the fold of the old one describes an inode nothing can
    reach any more.

    **The fold ended where a record ends.** The byte before the offset is read back and must
    be the newline the fold stopped at. That is the one check that can notice a log truncated
    and rewritten *in place* -- a rotation, a shell redirect, an operator -- which keeps the
    inode and can come back longer than it was, so neither the identity nor the length has
    anything to say about it. Costing one byte on a read that was happening anyway.

    The length condition is doing a second job worth naming: it is what keeps ``st_size -
    offset`` from going negative on a log that shrank, which ``os.pread`` reports as ``EINVAL``
    -- an answer of the right shape, arrived at by accident, which is the kind that stops being
    right when the arithmetic moves.
    """
    status = os.fstat(descriptor)
    same_file = (status.st_dev, status.st_ino) == (state.device, state.inode)
    if same_file and 0 < state.offset <= status.st_size:
        chunk = os.pread(descriptor, status.st_size - state.offset + 1, state.offset - 1)
        if chunk.startswith(b"\n"):
            return chunk[1:]
    _restart(state, status.st_dev, status.st_ino)
    return os.pread(descriptor, status.st_size, 0)


def _fold_tail(state: _Folded, path: Path | str) -> str:
    """Fold whatever was appended since last time, and hand back the unterminated tail.

    Opened once and measured through that descriptor rather than stat-then-open, so the file
    whose size and identity decide what to read is provably the file the bytes come from --
    a :func:`compact` renaming a new log over this one in between would otherwise have us
    reading the new file at the old file's offset.

    Returns:
        The bytes after the last newline, decoded. Empty for a log that ends the way this
        module writes them.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        _restart(state, -1, -1)
        return ""
    try:
        chunk = _read_tail(state, descriptor)
    except OSError:
        # Reached by a path that is a directory, which `os.open` accepts and `os.pread` does
        # not, and by a read that fails after the open. Both are "nothing is in flight".
        _restart(state, -1, -1)
        return ""
    finally:
        os.close(descriptor)
    boundary = chunk.rfind(b"\n") + 1
    # Bytes and a replacing decode, not `read_text`. **Found by fuzzing this function**: the
    # file sits on disk between two runs of somebody's job, so it is not trusted input, and a
    # single stray byte made `read_text` raise `UnicodeDecodeError` -- which is a `ValueError`,
    # not an `OSError`, so it escaped the guard above and took down the upload it was supposed
    # to help. A replaced character makes its line unparseable as JSON, which folds to nothing,
    # which is the honest answer to garbage.
    for line in chunk[:boundary].decode("utf-8", "replace").splitlines():
        _apply(state.entries, line)
    state.offset += boundary
    return chunk[boundary:].decode("utf-8", "replace")


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

    Reads the whole file every time, deliberately: this is what :meth:`UploadJournal.in_flight`
    and :func:`compact` call, both of them once per run against a log nothing else is using.
    The per-file lookup is :func:`staged_for`, and it is the one that tails.

    Args:
        path: The journal file.

    Returns:
        Decoded target path to the entry describing its in-flight staging file.
    """
    state = _Folded()
    # The unterminated tail is folded here and not in `staged_for`'s cached state, which is the
    # one difference between the two readers and it is not a difference in what they see: a
    # fold that keeps nothing can consume a half-written line, because there is no next call
    # for the rest of it to arrive before.
    for line in _fold_tail(state, path).splitlines():
        _apply(state.entries, line)
    return state.entries


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

    Written to a temporary sibling and renamed, so an interrupted compaction leaves the original
    log rather than half of one. That sibling's *name* is :func:`replace_atomically`'s subject
    and is not derived from this file's (D-175).

    Returns:
        How many entries survived, which is how many staging files may still be out there.
    """
    destination = Path(path)
    surviving = fold(destination)
    replace_atomically(
        destination, b"".join(_line(_STAGED, _fields_of(entry)) for entry in surviving.values())
    )
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


def _tail_says(entry: JournalEntry | None, key: str, tail: str) -> JournalEntry | None:
    """What an unterminated tail says about one target, without committing it to the fold.

    A line the log does not yet end with is folded for this answer only: the bytes finishing it
    may still be on their way, and a state that had already consumed it would fold the
    remainder as garbage and lose the record for good.

    One entry is the whole overlay because one line can only reach the target it names --
    :func:`_apply` either replaces that key or removes it -- so seeding a scratch dictionary
    with just the key being asked about gives the same answer as folding into a copy of the
    whole state, at no cost that grows with it.
    """
    scratch = {} if entry is None else {key: entry}
    for line in tail.splitlines():
        _apply(scratch, line)
    return scratch.get(key)


def staged_for(
    path: Path | str, target: bytes, source: SourceIdentity, folded: _Folded
) -> bytes | None:
    """The staging path a previous run left for ``target``, or ``None``.

    Module-level for the reason :func:`entry_matches` is: the negation and the ``None`` check
    below decide whether a resume happens at all, and inverting either would either resume
    across a changed file or never resume anything.

    Args:
        path: The journal file.
        target: The remote path being uploaded to.
        source: The bytes being sent, so a record for a different or changed file is refused.
        folded: How far this journal has been read. Advanced in place, under its own lock, and
            the module docstring is where the argument that it cannot go stale lives.
    """
    key = decode_name(target)
    with folded.lock:
        tail = _fold_tail(folded, path)
        entry = folded.entries.get(key)
        if tail:
            entry = _tail_says(entry, key, tail)
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

    **Put it somewhere only this job can write.** This path is opened following a symlink, the
    way ``get`` opens a download destination and for the same reason -- a state file that is a
    link to somewhere else is a deployment rather than an attack -- so in a shared directory the
    records can be appended into a file somebody else chose. The temporary that :meth:`compact`
    writes is the half this library owns, and it is unpredictable and ``O_EXCL | O_NOFOLLOW``
    (D-175). ``docs/reliability.md`` has the rule under "Where to put the journal".

    Attributes:
        path: Where the log lives. Its parent directory must exist.
    """

    path: Path
    _folded: _Folded = field(default_factory=_Folded, init=False, repr=False, compare=False)
    """How far :meth:`staged_for` has read this log, so a tree pays for it once (D-176).

    **On the journal rather than on the run**, because the log is what it describes and two of
    these over one file would each miss what the other appended. It is state with a lifetime,
    so the lifetime is stated: nothing here is remembered across a *file*, only across reads of
    the same one, and every read re-opens it and checks that it is still the file the fold came
    from. Held across runs by a caller who holds the journal, which costs nothing and is
    already the case for a repeated job.

    Excluded from ``repr`` and from comparison, so two journals over one path stay equal and
    ``repr()`` keeps naming the one thing a caller chose.
    """

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
        return staged_for(self.path, target, source, self._folded)

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

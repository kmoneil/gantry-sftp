"""The comparison a mirror makes, and the record it makes it against (D-164).

**A mirror's defining operation is deciding not to transfer something**, and getting that wrong
leaves a changed file wearing its old contents on the far end while the run reports success.
That is data loss with a green result object, so the decision is the feature and the saved
bytes are the side effect. Everything in this module exists to make the decision auditable.

Why the comparison is against a *record* rather than against the destination's clock
------------------------------------------------------------------------------------
The obvious rule -- compare the local modification time against the remote one -- does not work
here, and the reason is not subtle. ``preserve_times`` is off by default on
:meth:`~gantry_sftp.session.Session.put_tree` (DESIGN 6, deliberately: a landing zone whose
consumer collects "modified since X" never picks up a file wearing last year's date), so the
remote mtime is normally *the time of the upload*. Measured against a real ``sftp-server``: a
file with a local mtime of 1700000000 arrived carrying 1786470831. Comparing those two finds
every file changed, every run, forever.

Turning ``preserve_times`` on to fix that would force the flag DESIGN turns off, and push the
breakage it prevents onto the caller. So the comparison is against **what this library recorded
sending**, which is immune to both that flag and to a server whose clock disagrees with ours.

What a record alone cannot see, and why both sides are stored
-------------------------------------------------------------
A manifest describes what *we* did. It cannot see a change made **on the server** -- truncate
the remote file and the record still says we wrote 28 bytes, the local file is unchanged, and a
comparison against the record alone skips while the destination stays wrong. That is the same
wrong-skip this module exists to prevent, reintroduced by the fix for it.

It costs nothing to close: v3 returns attributes *with* a listing, so the walk a mirror already
performs hands back the remote size and mtime with no extra round trip. The record therefore
stores **both sides** as of the moment of writing, and the comparison checks both.

The three states, and which way the undecidable one falls
----------------------------------------------------------
Every field of :class:`~gantry_sftp.codec.Attrs` is optional -- a server sends what it feels
like sending -- so "the comparison could not run" is a real answer and not a defensive
hypothetical. It is reported as :attr:`SyncDecision.UNDECIDABLE` and it **transfers**.

That is a correction to D-164 as filed, which described the third state as a kind of *skip*.
Skipping on undecidable is precisely the data-loss direction the card is about: it means a file
we could not prove identical keeps its old contents on the far end. So the three states describe
the **evidence**, and the two actions are transfer or skip, with skip reserved for the case that
was proven. An undecidable entry is transferred and named in the report, so a caller who cares
which files could not be checked can see them without having lost anything to find out.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from gantry_sftp.codec import Attrs
from gantry_sftp.session._listing import decode_name
from gantry_sftp.session._localtree import (
    LocalWalkEntry,
    local_dir_entry,
    remote_component,
    times_from_stat,
)
from gantry_sftp.session._recursive import Skipped, join_remote

__all__ = [
    "MANIFEST_VERSION",
    "Comparison",
    "ManifestEntry",
    "SyncDecision",
    "SyncManifest",
    "SyncOutcome",
    "SyncReason",
    "SyncResult",
    "candidates_in",
    "compare_for_sync",
    "manifest_entry_for",
    "record_entry",
    "summarise",
    "write_manifest",
]

MANIFEST_VERSION = 1
"""What :meth:`SyncManifest.load` will read.

A manifest from a future version is refused rather than parsed on a best-effort basis: the whole
value of the file is that a comparison can trust it, and a field this version does not know
about is a comparison this version cannot make correctly. Refusing costs one full re-send, which
is the safe failure.
"""


class SyncDecision(StrEnum):
    """What a comparison concluded about one file, as *evidence* rather than as an action.

    Two of these transfer. That is not a redundancy -- :attr:`TRANSFER` means the file is known
    to need sending, :attr:`UNDECIDABLE` means it could not be shown not to, and a report that
    called both "transferred" would hide exactly the entries a careful operator wants to look
    at.
    """

    TRANSFER = "transfer"
    """Positive evidence of a difference, or nothing on record for this path."""

    SKIPPED = "skipped"
    """Proven identical on both sides against the record. The only state that does not send."""

    UNDECIDABLE = "undecidable"
    """The comparison could not run. **Sent anyway**, and reported under this name.

    Reached when the server volunteered no size or no times for the entry, which v3 permits at
    any time and for any reason.
    """


class SyncReason:
    """Why a comparison decided what it did.

    Strings rather than an enum for the same reason :class:`~gantry_sftp.session.SkipReason` is:
    they are sentences for a human reading a report, and the set grows with what servers do
    rather than with what the protocol defines.
    """

    NO_RECORD = "no record of this path having been sent"
    LOCAL_SIZE_CHANGED = "the local file's size differs from what was recorded"
    LOCAL_MTIME_CHANGED = "the local file's modification time differs from what was recorded"
    REMOTE_GONE = "the file recorded as sent is not in the destination listing"
    REMOTE_SIZE_CHANGED = "the remote file's size differs from what was recorded"
    REMOTE_MTIME_CHANGED = "the remote file's modification time differs from what was recorded"
    IDENTICAL = "size and modification time match the record on both sides"

    REMOTE_SIZE_UNREPORTED = "this server volunteered no size for the remote entry"
    """Not folded into "same", which is the entire point of the third state.

    ``TreePlan.UNREPORTED_SIZES`` names the same server behaviour on the preview side. Same
    fact, second consumer.
    """

    REMOTE_TIMES_UNREPORTED = "this server volunteered no modification time for the remote entry"
    LOCAL_ATTRS_UNREPORTED = "the local entry carried no size or modification time"
    """Not reachable from :func:`~gantry_sftp.session.local_dir_entry`, which always fills both.

    Handled rather than asserted because :class:`~gantry_sftp.codec.Attrs` is a shared type whose
    every field is optional, and a caller may build one by hand. A comparison that assumed the
    local half was total would fold that case into "identical" -- which is the wrong direction.
    """


@dataclass(frozen=True, slots=True)
class Comparison:
    """One file's decision and the evidence for it.

    Attributes:
        decision: What the comparison concluded.
        reason: Why, as a sentence fit for a report.
    """

    decision: SyncDecision
    reason: str

    @property
    def transfers(self) -> bool:
        """Whether this decision sends the file. True for all but :attr:`SyncDecision.SKIPPED`."""
        return self.decision is not SyncDecision.SKIPPED


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """What one file looked like on both sides at the moment it was last sent.

    Both sides, because a record of the local half alone cannot see a change made on the server
    -- see this module's docstring. All four values are what the *protocol* can carry: sizes in
    bytes, times as whole seconds, because v3's ``ACMODTIME`` is a ``uint32`` of seconds and a
    record holding more precision than the wire would compare unequal against itself.

    Attributes:
        local_size: The local file's size when it was sent.
        local_mtime: The local file's modification time, truncated to seconds.
        remote_size: The size the destination reported afterwards.
        remote_mtime: The modification time the destination reported afterwards.
    """

    local_size: int
    local_mtime: int
    remote_size: int
    remote_mtime: int

    def as_json(self) -> dict[str, int]:
        """This entry as the object written to disk. Long field names on purpose: it is read."""
        return {
            "local_size": self.local_size,
            "local_mtime": self.local_mtime,
            "remote_size": self.remote_size,
            "remote_mtime": self.remote_mtime,
        }

    @classmethod
    def from_json(cls, record: object) -> ManifestEntry | None:
        """Rebuild one entry, or ``None`` if the object on disk is not one.

        ``None`` rather than an exception, and the caller drops the entry: a manifest is a cache
        of evidence, so an unreadable record means "we do not know about this path", which is
        already a state the comparison has and already resolves by transferring. Raising would
        turn a corrupt line into a failed run.
        """
        if not isinstance(record, dict):
            return None
        values: list[int] = []
        for field_name in ("local_size", "local_mtime", "remote_size", "remote_mtime"):
            value = record.get(field_name)
            # `bool` is an `int` subclass and would pass this test wearing the wrong type, which
            # is the shape that survives a round trip and compares unequal later.
            if not isinstance(value, int) or isinstance(value, bool):
                return None
            values.append(value)
        return cls(*values)


@dataclass(frozen=True, slots=True)
class SyncManifest:
    r"""What a mirror recorded sending, keyed by remote path.

    Keys are the remote path decoded with :func:`~gantry_sftp.session.decode_name`, which is
    ``surrogateescape`` and therefore reversible: a remote name that is not valid UTF-8 survives
    being written to JSON and read back byte-for-byte. Verified rather than assumed --
    ``json.dumps`` escapes a lone surrogate as ``\udcXX`` and ``json.loads`` returns it.

    Attributes:
        entries: Remote path to what was recorded about it.
    """

    entries: dict[str, ManifestEntry]

    @classmethod
    def empty(cls) -> SyncManifest:
        """A manifest that knows nothing, which is what a first run compares against."""
        return cls(entries={})

    @classmethod
    def load(cls, path: Path | str) -> SyncManifest:
        """Read a manifest, or return an empty one if it is absent or unusable.

        **Every failure here degrades to "we know nothing"**, which costs a full re-send and
        loses no data. The alternative -- raising -- turns a truncated file, a version bump or a
        stray byte into a failed mirror run, and the thing the file protects is a cost rather
        than a correctness property. The comparison never trusts it further than the record it
        actually parsed.
        """
        try:
            blob = Path(path).read_text(encoding="utf-8")
        except OSError:
            return cls.empty()
        try:
            document: object = json.loads(blob)
        except json.JSONDecodeError:
            return cls.empty()
        if not isinstance(document, dict) or document.get("version") != MANIFEST_VERSION:
            return cls.empty()
        raw = document.get("entries")
        if not isinstance(raw, dict):
            return cls.empty()
        entries = {
            key: parsed
            for key, value in raw.items()
            if isinstance(key, str) and (parsed := ManifestEntry.from_json(value)) is not None
        }
        return cls(entries=entries)

    def save(self, path: Path | str) -> None:
        """Write this manifest, replacing whatever was there. See :func:`write_manifest`."""
        write_manifest(self.entries, path)

    def record(self, remote_path: bytes, entry: ManifestEntry) -> None:
        """Note what one file looked like on both sides. See :func:`record_entry`."""
        record_entry(self.entries, remote_path, entry)

    def recorded(self, remote_path: bytes) -> ManifestEntry | None:
        """What was recorded for one remote path, or ``None`` if nothing was."""
        return self.entries.get(decode_name(remote_path))


@dataclass(frozen=True, slots=True)
class SyncOutcome:
    """What a mirror decided about one file, and did.

    Every file the walk offered gets one of these, including the ones that were sent. A report
    listing only the skips would answer "what did this run avoid" and not "why did it re-send
    that", which is the question an operator actually arrives with.

    Attributes:
        remote_path: Where the file lives, or would live, on the server.
        decision: What the comparison concluded.
        reason: Why, as a sentence.
        transferred: Bytes sent for this entry. Zero for a skip.
    """

    remote_path: bytes
    decision: SyncDecision
    reason: str
    transferred: int = 0


@dataclass(frozen=True, slots=True)
class SyncResult:
    """What one :meth:`~gantry_sftp.session.Session.sync_tree` did.

    **The three counts do not collapse into two.** ``undecidable`` files were sent, exactly as
    ``transferred`` ones were, and adding them together would destroy the only signal that says
    which entries this run could not actually check. A mirror against a server that volunteers
    no sizes is a mirror that transfers everything and says so, and that has to be visible
    without reading every outcome.

    Attributes:
        transferred: Files sent because something was known to differ.
        skipped: Files proven identical on both sides and not sent.
        undecidable: Files sent because they could not be proven identical.
        directories: Remote directories created or confirmed.
        bytes_transferred: Total bytes sent.
        outcomes: One record per file considered, in completion order.
        walk_skipped: Entries the *walk* passed over -- symlinks and the rest. A different kind
            of skip from :attr:`skipped`, kept in its own field for that reason: one means "not
            looked at", the other means "looked at and identical", and a report that merged them
            would be unreadable in exactly the case that matters.
    """

    transferred: int
    skipped: int
    undecidable: int
    directories: int
    bytes_transferred: int
    outcomes: tuple[SyncOutcome, ...] = ()
    walk_skipped: tuple[Skipped, ...] = ()

    @property
    def considered(self) -> int:
        """Files the comparison looked at, which is every file the walk offered."""
        return self.transferred + self.skipped + self.undecidable

    @property
    def complete(self) -> bool:
        """Whether every file was decided one way or the other, with none left unprovable."""
        return self.undecidable == 0


def summarise(
    outcomes: Sequence[SyncOutcome], *, directories: int, walk_skipped: Sequence[Skipped]
) -> SyncResult:
    """Fold per-file outcomes into the run's report.

    Counted here rather than incremented as the run goes, because a mirror fans out and an
    augmented assignment across several workers finishing inside one another's awaits is the
    lost-update bug ``get_tree`` documents. The outcomes list is appended to, which is safe, and
    the arithmetic happens once at the end over a list nobody is still writing to.
    """
    by_decision = Counter(outcome.decision for outcome in outcomes)
    return SyncResult(
        transferred=by_decision[SyncDecision.TRANSFER],
        skipped=by_decision[SyncDecision.SKIPPED],
        undecidable=by_decision[SyncDecision.UNDECIDABLE],
        directories=directories,
        bytes_transferred=sum(outcome.transferred for outcome in outcomes),
        outcomes=tuple(outcomes),
        walk_skipped=tuple(walk_skipped),
    )


def write_manifest(entries: Mapping[str, ManifestEntry], path: Path | str) -> None:
    """Write a manifest, replacing whatever was there.

    Written to a sibling temporary file and renamed, because the failure this avoids is the one
    the library refuses to inflict on a *remote* destination: a run interrupted mid-write leaves
    a truncated manifest, which the loader would then discard entirely and re-send the whole
    tree. ``os.replace`` semantics via :meth:`~pathlib.Path.replace`.

    A module-level function with :meth:`SyncManifest.save` delegating to it, because
    :class:`SyncManifest` is a ``@dataclass`` and **mutmut generates no mutants for a method of a
    decorated class** (D-107). The sort order, the version field and the trailing newline are all
    things a mutation would change silently, so this body is worth having the lane look at.
    """
    destination = Path(path)
    document: dict[str, Any] = {
        "version": MANIFEST_VERSION,
        "entries": {key: entry.as_json() for key, entry in sorted(entries.items())},
    }
    staging = destination.with_name(f"{destination.name}.partial")
    _ = staging.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    staging.replace(destination)


def record_entry(
    entries: dict[str, ManifestEntry], remote_path: bytes, entry: ManifestEntry
) -> None:
    """Note what one file looked like on both sides, replacing any earlier record.

    Split from the method for the same reason as :func:`write_manifest`: the key is the *decoded*
    remote path, and a mutation that keyed it on something else would make every subsequent run
    re-send every file while the suite stayed green.
    """
    entries[decode_name(remote_path)] = entry


@dataclass(frozen=True, slots=True)
class _SyncCandidate:
    """One file the comparison decided to send, on its way to a worker.

    Carries the verdict rather than re-deriving it after the transfer: the reason a file was
    sent is decided in the producer, where the directory listing is in hand, and a worker that
    recomputed it would be answering from a listing that is one transfer out of date.

    Attributes:
        source: The local file.
        remote: Where it is going.
        verdict: Why it is going, for the report.
    """

    source: Path
    remote: bytes
    verdict: Comparison


def candidates_in(
    entry: LocalWalkEntry,
    remote_directory: bytes,
    present: Mapping[bytes, Attrs],
    manifest: SyncManifest,
    decided: list[SyncOutcome],
) -> Iterator[_SyncCandidate]:
    """Decide about every file in one walked directory, yielding the ones that need sending.

    A plain generator, and deliberately not a method on the session: it performs no I/O beyond
    the local ``stat`` the walk would do anyway, so the decision that can lose data is testable
    with two dictionaries and no server.

    Skips are appended to ``decided`` rather than yielded, because they are the outcome -- there
    is nothing left to do with them. The transfers come back as candidates carrying the verdict
    that sent them, so the report can say *why* without recomputing it against a listing that
    the transfer itself has since invalidated.

    Args:
        entry: The walked local directory.
        remote_directory: Where its contents go, already created.
        present: That remote directory's listing, by filename.
        manifest: What was recorded about earlier runs.
        decided: Appended to for every file that needs no transfer.

    Yields:
        One candidate per file that will be sent.
    """
    for name in entry.files:
        source = entry.path / os.fsdecode(name)
        target = join_remote(remote_directory, remote_component(name))
        verdict = compare_for_sync(
            local_dir_entry(name, source.stat()).attrs,
            present.get(name),
            manifest.recorded(target),
        )
        if verdict.transfers:
            yield _SyncCandidate(source, target, verdict)
        else:
            decided.append(SyncOutcome(target, verdict.decision, verdict.reason))


def manifest_entry_for(source: Path, landed: Attrs) -> ManifestEntry | None:
    """What to record about a file that was just sent, or ``None`` if it cannot be recorded.

    ``None`` when the server volunteered no size or no times for what it just accepted. That is
    the honest answer -- there is nothing to compare against next time -- and it makes the next
    run treat the path as unrecorded, which transfers. A record with a guessed field in it would
    make the next run *skip* on evidence this one invented.

    The local half is re-``stat``ed here rather than carried from the walk, because the walk's
    reading is from before the transfer and a file that changed while it was being sent must not
    be recorded as though it had not.
    """
    if landed.size is None or landed.times is None:
        return None
    local = source.stat()
    return ManifestEntry(
        local_size=local.st_size,
        local_mtime=times_from_stat(local).mtime,
        remote_size=landed.size,
        remote_mtime=landed.times.mtime,
    )


def compare_for_sync(
    local: Attrs, remote: Attrs | None, recorded: ManifestEntry | None
) -> Comparison:
    """Decide whether one file needs sending, and say what the decision rests on.

    The ladder is ordered by what it can prove, and the order is the load-bearing part:

    1. Nothing on record, or the local file differs from what was recorded -- **transfer**.
       Local evidence alone is sufficient and is always available, so it is asked first and no
       server answer can override it.
    2. The recorded file is not in the destination listing -- **transfer**. Something removed it.
    3. The server volunteered no size or no times -- **undecidable**, and transferred. The local
       half matched, so there is no positive evidence of change; there is also no proof of
       identity, and this module's docstring says which way that falls.
    4. The remote differs from what was recorded -- **transfer**. Somebody changed it on the
       server behind us.
    5. Everything matches -- **skipped**, and this is the only branch that does not send.

    Args:
        local: The local file's attributes, as :func:`~gantry_sftp.session.local_dir_entry`
            builds them -- size and a modification time already truncated to whole seconds.
        remote: What the destination listing said about the same path, or ``None`` if the
            listing did not contain it.
        recorded: What was recorded the last time this path was sent, or ``None``.

    Returns:
        The decision and the sentence explaining it.
    """
    if recorded is None:
        return Comparison(SyncDecision.TRANSFER, SyncReason.NO_RECORD)
    # `is not None` rather than truthiness: a `Comparison` is a dataclass and is always truthy
    # today, so `or` would work and would silently stop working the day one grows a `__bool__`.
    local_verdict = _local_side(local, recorded)
    if local_verdict is not None:
        return local_verdict
    return _remote_side(remote, recorded)


def _local_side(local: Attrs, recorded: ManifestEntry) -> Comparison | None:
    """Rungs 1 and 3 of the ladder, or ``None`` if the local half matches the record.

    Split from :func:`compare_for_sync` rather than inlined because the two halves rest on
    different evidence: this one needs no server and cannot be wrong about availability, while
    the remote half is entirely at the mercy of what was volunteered. Keeping them apart also
    keeps each under the return-count ceiling without a suppression.
    """
    if local.size is None or local.times is None:
        return Comparison(SyncDecision.UNDECIDABLE, SyncReason.LOCAL_ATTRS_UNREPORTED)
    if local.size != recorded.local_size:
        return Comparison(SyncDecision.TRANSFER, SyncReason.LOCAL_SIZE_CHANGED)
    if local.times.mtime != recorded.local_mtime:
        return Comparison(SyncDecision.TRANSFER, SyncReason.LOCAL_MTIME_CHANGED)
    return None


def _remote_side(remote: Attrs | None, recorded: ManifestEntry) -> Comparison:
    """Rungs 2, 3 and 4, and the only branch that concludes :attr:`SyncDecision.SKIPPED`.

    Reached only once the local half has matched the record, so every answer here is about
    whether the destination still holds what was put there.
    """
    if remote is None:
        return Comparison(SyncDecision.TRANSFER, SyncReason.REMOTE_GONE)
    if remote.size is None:
        return Comparison(SyncDecision.UNDECIDABLE, SyncReason.REMOTE_SIZE_UNREPORTED)
    if remote.times is None:
        return Comparison(SyncDecision.UNDECIDABLE, SyncReason.REMOTE_TIMES_UNREPORTED)
    if remote.size != recorded.remote_size:
        return Comparison(SyncDecision.TRANSFER, SyncReason.REMOTE_SIZE_CHANGED)
    if remote.times.mtime != recorded.remote_mtime:
        return Comparison(SyncDecision.TRANSFER, SyncReason.REMOTE_MTIME_CHANGED)
    return Comparison(SyncDecision.SKIPPED, SyncReason.IDENTICAL)

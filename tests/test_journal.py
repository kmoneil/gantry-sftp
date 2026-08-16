"""The upload journal: what it records, what it refuses to trust, and what a crash leaves.

**D-166.** An interrupted upload already survives the connection failing. It did not survive the
*process* failing, and the reason was narrow and precise: the staging name carries fresh
randomness per call, so a killed run leaves a file whose name nothing can reconstruct. The
journal makes that name recoverable **without making it predictable**, which is the objection
`_policy._check_publish_flags` recorded when it refused the combination outright.

Three properties carry the weight here, and the third is the one that makes the feature safe.

**Downloads must keep needing nothing.** Measured before any of this was written: a download
resumes across two separate interpreter processes, because its partial is a file on our own disk
and its length is a fact rather than a report. A row below re-proves it, because the day somebody
"unifies" the two directions is the day the upload's weaker evidence gets applied to the one that
never needed it.

**The record must be durable before the request it describes.** An unanswered request must be
assumed to have been performed, so the note saying where the bytes are going is written and
`fsync`ed before anything could create the file. The subprocess row below kills a real upload with
a real `SIGKILL` and then resumes it from a different process, because that is the only way to
prove this rather than assert it.

**Nothing here records an offset, and that is what keeps it from being a corruption engine.**
After a crash the process knows what it *intended*, not what the far end accepted. So the journal
records a name — a fact about a decision made locally — and never a quantity, which would be a
claim about somebody else's disk. Where to resume from is still read off the server. The rows
under "a lying journal costs a round trip, never a file" are the proof that a stale, truncated or
hostile journal cannot produce a wrong file.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gantry_sftp.exceptions import SFTPError
from gantry_sftp.session import (
    JournalEntry,
    Publish,
    SourceIdentity,
    UploadJournal,
    _journal,
)
from gantry_sftp.session import open_session as open_async_session
from gantry_sftp.session._journal import (
    append_record,
    compact,
    fold,
    source_identity,
)
from gantry_sftp.session._policy import _check_publish_flags
from gantry_sftp.session._publish import resume_target
from gantry_sftp.sync import open_local_server_transport, open_session
from gantry_sftp.transport import find_sftp_server
from gantry_sftp.transport import open_local_server_transport as open_async_local_transport

TARGET = b"/incoming/data.csv"
STAGED = b"/incoming/.data.csv.0a1b2c3d.part"


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def identity(path: str = "/local/data.csv", size: int = 4096, mtime: int = 1_700_000_000):
    return SourceIdentity(path=path, size=size, mtime=mtime)


def journal_at(tmp_path: Path) -> UploadJournal:
    return UploadJournal(tmp_path / "uploads.journal")


# --- what the log records ------------------------------------------------------------------


def test_a_staged_record_survives_a_fold(tmp_path: Path):
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert journal.staged_for(TARGET, identity()) == STAGED


def test_publishing_clears_the_record(tmp_path: Path):
    """Two events rather than one record updated in place, which is what makes it append-only."""
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    journal.published(TARGET)

    assert journal.staged_for(TARGET, identity()) is None
    assert journal.in_flight() == {}


def test_a_target_staged_again_after_publishing_reads_as_in_flight(tmp_path: Path):
    """Later lines win, which is the whole of the fold rule."""
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    journal.published(TARGET)
    journal.staging(b"/incoming/.data.csv.ffff.part", TARGET, identity())

    assert journal.staged_for(TARGET, identity()) == b"/incoming/.data.csv.ffff.part"


def test_nothing_is_in_flight_before_anything_is_recorded(tmp_path: Path):
    assert journal_at(tmp_path).in_flight() == {}
    assert journal_at(tmp_path).staged_for(TARGET, identity()) is None


def test_a_record_carries_no_offset_and_no_byte_count(tmp_path: Path):
    """The design decision, asserted on the bytes rather than trusted to the docstring.

    A journal that recorded how much had been sent would be replaying intent, and after a crash
    the process knows what it intended rather than what the far end accepted. If a field like
    that is ever added, this fails and whoever added it has to argue with the module docstring.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    record = json.loads(journal.path.read_text().splitlines()[0])
    assert set(record) == {
        "version",
        "event",
        "staged",
        "target",
        "local",
        "local_size",
        "local_mtime",
    }
    assert not any("offset" in key or "transferred" in key or "sent" in key for key in record)


def test_the_file_is_created_private(tmp_path: Path):
    """It names paths inside somebody's infrastructure, so it is not world-readable."""
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert journal.path.stat().st_mode & 0o777 == 0o600


def test_a_non_utf8_remote_name_survives_the_round_trip(tmp_path: Path):
    """Remote names are bytes and need not be UTF-8, and the file they name is JSON.

    `surrogateescape` both ways, the same rule `SyncManifest` uses -- and the files whose names
    are the reason you needed a journal are exactly the ones a lossy encoding would lose.
    """
    awkward_target = b"/incoming/\xff\xfe.csv"
    awkward_staged = b"/incoming/.\xff\xfe.csv.0a1b.part"
    journal = journal_at(tmp_path)
    journal.staging(awkward_staged, awkward_target, identity())

    assert journal.staged_for(awkward_target, identity()) == awkward_staged


# --- durability ------------------------------------------------------------------------------


def test_each_record_is_flushed_before_the_call_returns(tmp_path: Path, monkeypatch):
    """The `fsync` is per record, because a journal that loses its tail claims more than happened.

    Asserted by counting the calls rather than by trusting the source: an `fsync` moved outside
    the loop, or dropped for speed, is exactly the change that passes every other test here.
    """
    flushed: list[int] = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (flushed.append(fd), real_fsync(fd))[1])

    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    first = len(flushed)
    journal.published(TARGET)

    # Two flushes for the first record -- the file and, because it was created by this call,
    # the directory entry that names it. One for the second, whose file already existed.
    assert first == 2
    assert len(flushed) == first + 1


def test_the_directory_entry_is_flushed_only_when_the_file_is_new(tmp_path: Path, monkeypatch):
    """A file's contents reaching disk says nothing about whether its *name* did.

    Flushing the parent on every append would be a syscall per upload for a fact that cannot
    change after the first one, so it is conditional -- and the condition is what this pins.
    """
    flushed: list[int] = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (flushed.append(fd), real_fsync(fd))[1])

    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    journal.staging(STAGED, b"/incoming/other.csv", identity())

    assert len(flushed) == 3


def test_a_missing_parent_directory_is_reported_rather_than_created(tmp_path: Path):
    """Creating it would be this library picking a place on somebody's disk. It refuses to."""
    journal = UploadJournal(tmp_path / "not-there" / "uploads.journal")

    with pytest.raises(OSError) as raised:
        journal.staging(STAGED, TARGET, identity())

    assert raised.value.errno == 2


# --- a lying journal costs a round trip, never a file -----------------------------------------


@pytest.mark.parametrize(
    ("content", "why"),
    [
        ("", "an empty file"),
        ("not json at all\n", "a line that is not JSON"),
        ('{"event": "staged"}\n', "a record with no target"),
        ("[1, 2, 3]\n", "a JSON document that is not an object"),
        ('{"version": 99, "event": "staged", "target": "/incoming/data.csv"}\n', "a newer schema"),
        ('{"version": 1, "event": "staged", "target": "/incoming/data.csv"}\n', "missing fields"),
        (
            '{"version": 1, "event": "elephant", "target": "/incoming/data.csv"}\n',
            "an event we do not write",
        ),
    ],
)
def test_an_unreadable_record_degrades_to_nothing_in_flight(tmp_path: Path, content: str, why: str):
    """Every failure means "start a fresh upload", which is always safe.

    The direction is what matters. Under-reporting progress costs a re-upload; over-reporting it
    is a caller resuming into a file that was never what they think. So every ambiguity resolves
    towards the first, and none of these inputs can produce an entry.
    """
    path = tmp_path / "uploads.journal"
    _ = path.write_text(content, encoding="utf-8")

    assert fold(path) == {}, why


def test_a_truncated_tail_costs_only_the_records_after_it(tmp_path: Path):
    """A crash mid-append leaves half a line, and the lines before it are still good.

    This is the property append-only buys and a rewritten document would not: a torn write at
    the end of the file cannot corrupt what was already there.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    with journal.path.open("a", encoding="utf-8") as handle:
        _ = handle.write('{"version": 1, "event": "staged", "targ')

    assert journal.staged_for(TARGET, identity()) == STAGED


def test_a_record_for_a_different_source_is_not_offered(tmp_path: Path):
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity(path="/local/data.csv"))

    assert journal.staged_for(TARGET, identity(path="/local/other.csv")) is None


@pytest.mark.parametrize(
    ("changed", "why"),
    [
        ({"size": 8192}, "the file grew since the killed run"),
        ({"size": 0}, "the file was truncated since"),
        ({"mtime": 1_700_000_001}, "the file was rewritten with the same length"),
    ],
)
def test_a_source_that_changed_since_the_crash_is_not_resumed(tmp_path: Path, changed, why: str):
    """The splice this prevents: a partial that is a prefix of *different* bytes.

    The mtime row is the one that matters most, because a same-length rewrite is invisible to
    every other check -- the offset still looks legal and the finished file is a plausible
    mixture of two versions.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert journal.staged_for(TARGET, identity(**changed)) is None, why


def test_an_entry_matches_only_when_all_three_fields_do():
    entry = JournalEntry(
        staged=STAGED, target=TARGET, local_path="/local/data.csv", local_size=4096, local_mtime=7
    )

    assert entry.matches(SourceIdentity(path="/local/data.csv", size=4096, mtime=7)) is True
    assert entry.matches(SourceIdentity(path="/local/data.csv", size=4096, mtime=8)) is False


def test_a_source_that_cannot_be_read_records_as_absent(tmp_path: Path):
    """Zeroes rather than an exception, and zeroes cannot match a real file's identity.

    This runs on the way into an upload that is about to open the file anyway, and `open`
    reports a missing source far better than a stat could.
    """
    missing = source_identity(tmp_path / "not-there.csv")

    assert missing.size == 0
    assert missing.mtime == 0
    assert missing.path.endswith("not-there.csv")


# --- compaction --------------------------------------------------------------------------------


def test_compaction_keeps_what_is_in_flight_and_drops_the_rest(tmp_path: Path):
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    journal.staging(b"/incoming/.b.csv.ffff.part", b"/incoming/b.csv", identity())
    journal.published(TARGET)

    surviving = journal.compact()

    assert surviving == 1
    assert journal.path.read_text().count("\n") == 1
    assert journal.staged_for(b"/incoming/b.csv", identity()) == b"/incoming/.b.csv.ffff.part"
    assert journal.staged_for(TARGET, identity()) is None


def test_compacting_an_empty_journal_leaves_an_empty_one(tmp_path: Path):
    path = tmp_path / "uploads.journal"

    assert compact(path) == 0
    assert path.read_text() == ""


def test_compaction_leaves_no_partial_file_behind(tmp_path: Path):
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    _ = journal.compact()

    assert sorted(p.name for p in tmp_path.iterdir()) == ["uploads.journal"]


# --- the name of the file compaction writes (D-175) --------------------------------------------


def test_compaction_does_not_write_through_a_link_planted_at_the_derived_name(tmp_path: Path):
    """The bug, and it is about a name rather than about the journal's contents.

    Compaction used to write `<journal>.compacting` -- a name derived from the caller's, in a
    directory this library does not own -- and open it `O_CREAT|O_TRUNC` with no `O_NOFOLLOW`.
    Anybody able to write there could predict it, so a symlink planted at it was followed: the
    file it pointed at was truncated and overwritten with the compacted log, and the rename that
    followed moved the *link* onto the journal path, sending every later append there too.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    victim = tmp_path / "victim.conf"
    _ = victim.write_text("important\n" * 20)
    planted = tmp_path / "uploads.journal.compacting"
    planted.symlink_to(victim)

    assert journal.compact() == 1

    assert victim.read_text() == "important\n" * 20, "written through the planted link"
    assert planted.is_symlink(), "the planted link was itself replaced"
    assert not journal.path.is_symlink(), "the link was renamed over the journal"
    assert journal.staged_for(TARGET, identity()) == STAGED


def test_the_file_compaction_writes_is_private_and_named_unpredictably(tmp_path: Path, monkeypatch):
    """`0o600` and a name a second run does not repeat, asserted while the file still exists.

    `mkstemp` supplies both, along with the `O_EXCL | O_NOFOLLOW` no test can observe from
    outside -- `O_EXCL` because a *hard* link planted at the name is not a symlink and would be
    written through. What is pinned here is therefore the pair of properties a rewrite would
    have to keep, not the call that currently provides them.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    observed: list[tuple[str, int]] = []
    replace = os.replace

    def watch(source, destination):
        observed.append((Path(source).name, stat.S_IMODE(Path(source).stat().st_mode)))
        replace(source, destination)

    monkeypatch.setattr(os, "replace", watch)
    _ = journal.compact()
    _ = journal.compact()

    assert [mode for _, mode in observed] == [0o600, 0o600]
    first, second = (name for name, _ in observed)
    assert first != second, "a name a second run repeats is a name somebody can plant at"
    assert not first.endswith(".compacting")
    assert first.startswith("uploads.journal."), "still recognisable to whoever sweeps this"


def test_a_compaction_that_cannot_rename_leaves_the_log_and_no_temporary(
    tmp_path: Path, monkeypatch
):
    """The cost of an unpredictable name is paid here rather than by whoever finds the litter.

    The derived name left its file behind on this path too; a random one nobody can identify
    would be worse, so the failure cleans up after itself.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    before = journal.path.read_bytes()

    def refuse(source, destination):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError) as failure:
        _ = journal.compact()

    assert failure.value.errno == errno.EXDEV
    assert journal.path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["uploads.journal"]


# --- read once, then tailed (D-176) -------------------------------------------------------------


def counting_preads(monkeypatch) -> list[tuple[int, int]]:
    """Record every journal read this process performs, as ``(length asked for, offset)``.

    ``os.pread`` rather than a spy on the parse, because bytes read off the disk is the
    quantity D-176 is about and the one a regression would grow. Nothing else in these rows
    reads through it: no transfer runs, so the only ``pread`` in the process is the fold's.

    **Asked for, not returned.** ``pread`` clamps at end of file, so a length computed wrong in
    the direction of *too large* comes back with the right bytes and costs a buffer nobody
    needed -- invisible to a counter of what arrived. The mutation lane is what said so.
    """
    reads: list[tuple[int, int]] = []
    real_pread = os.pread

    def counting(fd: int, length: int, offset: int) -> bytes:
        reads.append((length, offset))
        return real_pread(fd, length, offset)

    monkeypatch.setattr(os, "pread", counting)
    return reads


def test_a_tree_reads_its_journal_once_rather_than_once_per_file(tmp_path: Path, monkeypatch):
    """**The whole of D-176**, asserted as a shape rather than as a duration.

    A tree performs one lookup per file against a log it appends two records to per file, so a
    lookup that folds from byte zero reads the whole log once per file -- quadratic in the tree,
    in the case this module's docstring names. Reading only what was appended since makes the
    run's total what the file ends up holding, which is the definition of paying for it once.

    Bytes rather than seconds, because a timing threshold on a shared runner is a flake and
    this is not a claim about speed: it is a claim about how many times each byte is read.
    """
    files = 200
    journal = journal_at(tmp_path)
    read = counting_preads(monkeypatch)

    for index in range(files):
        target = f"/incoming/file{index}.dat".encode()
        source = identity(path=f"/local/file{index}.dat")
        _ = journal.staged_for(target, source)
        journal.staging(target + b".part", target, source)
        journal.published(target)

    log = journal.path.stat().st_size
    asked = sum(length for length, _ in read)
    # Every byte of the log asked for at most once across the whole tree, plus the one byte
    # per lookup that re-reads the newline the fold stopped at. The old shape read the log at
    # every lookup, so it moved about `files / 2` times this much -- two orders of magnitude
    # here, which is why the bound can be this tight without being brittle.
    assert asked <= log + files, (
        f"{asked} bytes read from a {log}-byte log over {files} files: a lookup is folding "
        f"more than the tail it has not seen"
    )
    assert len(read) == files - 1, "one read per lookup, less the one before the file existed"


def test_a_lookup_asks_for_exactly_the_tail_and_the_newline_before_it(tmp_path: Path, monkeypatch):
    """The read arithmetic, pinned to the byte rather than bounded.

    A length computed too large is invisible to any assertion about what came back, because
    ``pread`` clamps at end of file -- so the bound in the row above cannot see it and the
    mutation lane can. Spelling out both numbers is what makes the off-by-one deliberate: the
    extra byte is the newline the fold ended on, re-read to prove the bytes under the offset
    have not moved.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"
    folded_to = journal.path.stat().st_size

    read = counting_preads(monkeypatch)
    journal.staging(b"/incoming/.next.part", b"/incoming/next", identity())
    grown = journal.path.stat().st_size

    assert journal.staged_for(b"/incoming/next", identity()) == b"/incoming/.next.part"
    assert read == [(grown - folded_to + 1, folded_to - 1)]


def test_a_second_lookup_with_nothing_appended_reads_no_further(tmp_path: Path, monkeypatch):
    """A fold that has reached the end of the log is at the end of it, not one byte short.

    The common shape in a tree that skips files: two lookups with no record written between
    them. Reading the whole log again because the offset happens to equal the length is the
    defect this card is about, arriving through an off-by-one instead of through a design.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"
    log = journal.path.stat().st_size

    read = counting_preads(monkeypatch)
    for _ in range(3):
        assert journal.staged_for(TARGET, identity()) == STAGED

    assert [length for length, _ in read] == [1, 1, 1], (
        f"three lookups against an unchanged {log}-byte log should re-read only the newline "
        f"the fold stopped at"
    )


def test_a_journal_path_that_is_a_directory_folds_to_nothing(tmp_path: Path):
    """A read that fails *after* the open, which is the other half of the failure path.

    ``os.open`` accepts a directory and ``os.pread`` refuses it, so this is the one ordinary
    way to reach the second guard -- and without a row for it that whole branch is unexecuted,
    which the mutation lane reports as an arity error nobody can trigger rather than as a gap.
    """
    misplaced = tmp_path / "uploads.journal"
    misplaced.mkdir()
    journal = UploadJournal(misplaced)

    assert fold(misplaced) == {}
    assert journal.staged_for(TARGET, identity()) is None


def test_a_record_another_process_appended_is_found_by_a_primed_lookup(tmp_path: Path):
    """The property a fold-at-open cache would have lost, and the reason this one tails.

    The journal exists to survive a killed run, so a second process appending to the same log
    is the case it is for -- and a lookup answering from a snapshot taken at construction would
    be reading a file that has since moved on.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"

    elsewhere = UploadJournal(journal.path)  # another run, sharing only the file
    elsewhere.staging(b"/incoming/.later.part", b"/incoming/later", identity(path="/local/later"))

    assert journal.staged_for(b"/incoming/later", identity(path="/local/later")) == (
        b"/incoming/.later.part"
    )


def test_a_publish_by_another_process_clears_a_primed_entry(tmp_path: Path):
    """Later lines win **through** the fold, not only within one read of it.

    The other direction of the row above, and the one that decides whether a lookup can go
    stale in the way that costs: an entry this process folded and another process has since
    published must stop being offered.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"

    UploadJournal(journal.path).published(TARGET)

    assert journal.staged_for(TARGET, identity()) is None


def replacement_log(tmp_path: Path, records: list[tuple[bytes, bytes]]) -> Path:
    """A whole log built elsewhere, ready to be moved or written over a journal.

    Takes ``(staged, target)`` spelled out rather than deriving one from the other, because
    the rows below turn on a record's **width** to the byte.
    """
    built = tmp_path / "replacement"
    writer = UploadJournal(built)
    for staged, target in records:
        writer.staging(staged, target, identity())
    return built


def test_a_log_replaced_by_one_that_lines_up_is_folded_again(tmp_path: Path):
    """The identity check, on a case no other guard here can see.

    Constructed so every cheaper check says "carry on": the replacement is **longer**, so a
    length test finds nothing, and its records are the same width as the original's, so the
    byte before the fold is still a newline and the framing test finds nothing either. Only
    ``(st_dev, st_ino)`` can tell that the file the fold describes has been renamed away.

    Written this way deliberately. Against an arbitrary replacement all three guards fire, and
    a row like that passes with any two of them deleted.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"
    folded_to = journal.path.stat().st_size

    # Names chosen the same width as the originals, so the replacement's first record ends
    # exactly where the fold stopped. The assertions are what make that a fact, not a hope.
    built = replacement_log(
        tmp_path,
        [
            (b"/incoming/.aaaa.csv.0a1b2c3d.part", b"/incoming/aaaa.csv"),
            (b"/incoming/.bbbb.csv.0a1b2c3d.part", b"/incoming/bbbb.csv"),
        ],
    )
    assert built.stat().st_size > folded_to, "longer, so the length check cannot fire"
    assert built.read_bytes()[folded_to - 1 : folded_to] == b"\n", (
        "aligned, so the framing check cannot fire either"
    )
    _ = built.replace(journal.path)

    assert journal.staged_for(b"/incoming/aaaa.csv", identity()) == (
        b"/incoming/.aaaa.csv.0a1b2c3d.part"
    )
    assert journal.staged_for(TARGET, identity()) is None, "the old log's records are gone"


def test_a_log_rewritten_in_place_is_folded_again(tmp_path: Path):
    """The framing check, on the case neither of the other two can see.

    A rotation, a shell redirect or an operator truncating this file keeps the **inode**, and
    if the log comes back at least as long as it was there is no shrink to notice either. What
    is left is that the fold claims to have stopped at a newline, so reading that byte back is
    what says the bytes underneath it moved.

    The recovery is what the row asserts: fold the whole file again and answer from it. Reading
    on at the old offset would skip the records before it and mis-frame the ones after.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"
    folded_to = journal.path.stat().st_size

    rewritten = replacement_log(
        tmp_path,
        [
            (b"/incoming/.a.csv.part", b"/incoming/a.csv"),
            (b"/incoming/.bb.csv.part", b"/incoming/bb.csv"),
        ],
    ).read_bytes()
    assert len(rewritten) >= folded_to, "at least as long, so the length check cannot fire"
    assert rewritten[folded_to - 1 : folded_to] != b"\n", "misaligned, which is what is noticed"
    with journal.path.open("r+b") as handle:
        _ = handle.truncate(0)
        _ = handle.write(rewritten)

    assert journal.staged_for(b"/incoming/a.csv", identity()) == b"/incoming/.a.csv.part"
    assert journal.staged_for(TARGET, identity()) is None, "the old log's records are gone"


def test_a_log_truncated_to_nothing_is_never_read_at_a_negative_length(tmp_path: Path, monkeypatch):
    """The length condition, pinned on what it prevents rather than on the answer.

    A fold that has read further than the file now reaches would ask ``os.pread`` for a
    negative number of bytes. The answer would still come out right -- the kernel says
    ``EINVAL``, which lands in the same "nothing is in flight" restart as every other read
    failure -- and that is exactly why it needs its own row: an outcome reached through an
    errno nobody intended is one that stops being right the moment the arithmetic moves.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"
    real_pread = os.pread

    def refusing_negative(fd: int, length: int, offset: int) -> bytes:
        assert length >= 0, (
            f"asked for {length} bytes at {offset}: a fold that has read past the end of its "
            f"log must be restarted, not handed to the kernel to reject"
        )
        return real_pread(fd, length, offset)

    monkeypatch.setattr(os, "pread", refusing_negative)
    with journal.path.open("r+b") as handle:
        handle.truncate(0)

    assert journal.staged_for(TARGET, identity()) is None
    journal.staging(b"/incoming/.fresh.part", b"/incoming/fresh", identity())
    assert journal.staged_for(b"/incoming/fresh", identity()) == b"/incoming/.fresh.part"


def test_a_compacted_log_is_still_read_correctly(tmp_path: Path):
    """The rewrite this module actually performs, end to end through a primed fold."""
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    journal.staging(b"/incoming/.gone.part", b"/incoming/gone", identity())
    journal.published(b"/incoming/gone")
    assert journal.staged_for(TARGET, identity()) == STAGED, "prime the fold"

    assert journal.compact() == 1

    assert journal.staged_for(TARGET, identity()) == STAGED
    assert journal.staged_for(b"/incoming/gone", identity()) is None


def test_a_record_whose_newline_never_arrived_is_still_offered(tmp_path: Path):
    """Two readers of one log that disagree would be the bug this row exists to prevent.

    ``fold`` reads every line including a final one the file does not terminate, so the lookup
    has to see it too. It is answered from without being consumed -- see the row below for the
    half that decides.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    _ = journal.path.write_bytes(journal.path.read_bytes().rstrip(b"\n"))

    assert UploadJournal(journal.path).staged_for(TARGET, identity()) == STAGED
    assert list(fold(journal.path)) == [TARGET.decode()]


def test_a_line_completed_after_it_was_read_is_not_lost(tmp_path: Path):
    """Why the unterminated tail is answered from and never folded into the state.

    A state that had consumed the half-written line would resume from after it, fold the bytes
    that finish it as a fragment, and drop the record for good -- the direction a crash mid-
    append makes real, since ``append_record`` is what leaves one.

    **The offset is the assertion, not the answer.** Both spellings end up returning the entry,
    because a fold that over-advanced is noticed by the framing check on the next read and
    recovers by re-reading the whole log -- which is correct and is also this card's defect
    coming back for any journal with a torn tail. What must hold is that nothing past the last
    complete line was ever consumed.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    torn = journal.path.read_bytes().rstrip(b"\n")
    _ = journal.path.write_bytes(torn)
    assert journal.staged_for(TARGET, identity()) == STAGED, "answered from the tail"
    # The offset is the assertion here and it has no public spelling -- adding one would be
    # publishing an implementation detail to make a test look tidier.
    assert journal._folded.offset == 0, (  # noqa: SLF001  # see the comment above
        "an unterminated line is not a line the fold has read"
    )

    with journal.path.open("ab") as handle:
        _ = handle.write(b"\n")

    assert journal.staged_for(TARGET, identity()) == STAGED, "the completed line was still folded"
    assert journal._folded.offset == len(torn) + 1, (  # noqa: SLF001  # as above
        "and now the whole of it has been"
    )


def test_the_fold_advances_under_its_own_lock(tmp_path: Path, monkeypatch):
    """What keeps a concurrent tree from consuming one region twice and skipping the next.

    The lookup runs in a worker thread and ``put_tree(concurrency=N)`` has N of them against
    one journal. Two reads starting from the same ``offset`` fold the same records and then
    advance past the ones neither of them read.

    Asserted by watching the lock at the moment of the read rather than by racing threads: a
    race that usually passes is not a proof, and this is the exact instant that must be
    exclusive.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    held: list[bool] = []
    real_pread = os.pread

    def watching(fd: int, length: int, offset: int) -> bytes:
        # Whether the lock is held at the instant of the read *is* the property, and it is not
        # observable from outside the object that owns it.
        held.append(journal._folded.lock.locked())  # noqa: SLF001  # see the comment above
        return real_pread(fd, length, offset)

    monkeypatch.setattr(os, "pread", watching)

    assert journal.staged_for(TARGET, identity()) == STAGED
    assert held == [True]


@pytest.mark.anyio
async def test_the_lookup_does_not_read_the_journal_on_the_event_loop(tmp_path: Path, monkeypatch):
    """The other half of D-176: what the loop was doing while it folded.

    A 20 000-file tree stalled the loop for longer than a 200 ms round trip on every file, with
    every concurrent sibling frozen for it -- which is the same argument
    :class:`~gantry_sftp.session.DescriptorSource` makes one module over about ``os.pread``,
    arriving at the module that had not taken it.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    loop_thread = threading.get_ident()
    reading_threads: list[int] = []
    real_pread = os.pread

    def recording(fd: int, length: int, offset: int) -> bytes:
        reading_threads.append(threading.get_ident())
        return real_pread(fd, length, offset)

    monkeypatch.setattr(os, "pread", recording)

    assert (await resume_target(journal, TARGET, identity(), resume=True, name=None)) == STAGED
    assert reading_threads, "the lookup did not read the journal at all"
    assert loop_thread not in reading_threads


@pytest.mark.anyio
async def test_the_refusals_reach_no_thread_at_all(tmp_path: Path, monkeypatch):
    """The three cases that answer from arguments must not pay for a worker.

    Most uploads pass no journal, and an upload that does mostly is not resuming. Sending those
    to a thread pool would make D-176's fix cost something on the path it was not about.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())
    read = counting_preads(monkeypatch)

    assert (await resume_target(None, TARGET, identity(), resume=True, name=None)) is None
    assert (await resume_target(journal, TARGET, identity(), resume=False, name=None)) is None
    assert (await resume_target(journal, TARGET, identity(), resume=True, name=b"x.part")) is None

    assert read == []


# --- the policy the journal changes ------------------------------------------------------------


def test_resume_with_atomic_is_still_refused_without_a_journal():
    """The old spelling still raises the old way, which is the public-API rule.

    A caller who was relying on that refusal to catch a mistake keeps getting it; what changed
    is that there is now a third way to satisfy it rather than two.
    """
    with pytest.raises(ValueError) as raised:
        _check_publish_flags(
            atomic=True, fsync=True, require_atomic=False, require_fsync=False, resume=True
        )

    assert raised.value.args[0] == (
        "resume=True needs journal= or staging_name= when atomic=True: the default staging "
        "file is named with fresh randomness each call, so a previous run's partial upload "
        "cannot be found. Pass journal= to record the name durably, staging_name= to fix it "
        "yourself, or atomic=False to resume the destination itself"
    )


def test_a_journal_satisfies_the_check_that_a_staging_name_used_to(tmp_path: Path):
    _check_publish_flags(
        atomic=True,
        fsync=True,
        require_atomic=False,
        require_fsync=False,
        resume=True,
        journal=journal_at(tmp_path),
    )


@pytest.mark.anyio
async def test_a_named_staging_file_outranks_the_journal(tmp_path: Path):
    """Nothing to look up when the caller named the file, so nothing that could disagree."""
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert (
        await resume_target(journal, TARGET, identity(), resume=True, name=b"chosen.part")
    ) is None


@pytest.mark.anyio
async def test_nothing_is_continued_when_resume_was_not_asked_for(tmp_path: Path):
    """A journal on a non-resuming upload records where the bytes went and adopts nothing.

    Worth pinning because the opposite would be a silent behaviour change: passing a journal
    for the cleanup it buys would start resuming uploads the caller did not ask to resume.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert (await resume_target(journal, TARGET, identity(), resume=False, name=None)) is None


@pytest.mark.anyio
async def test_without_a_journal_nothing_is_continued():
    assert (await resume_target(None, TARGET, identity(), resume=True, name=None)) is None


@pytest.mark.anyio
async def test_the_journal_is_adopted_when_every_refusal_declines(tmp_path: Path):
    """The one case that reaches the disk, so the three refusals above are not vacuous.

    Without this row each of them could be asserting on a predicate that never says yes -- a
    guard needs the values it admits as well as the ones it turns away.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert (await resume_target(journal, TARGET, identity(), resume=True, name=None)) == STAGED


# --- against a real server ---------------------------------------------------------------------


def test_a_journal_records_where_the_bytes_went_and_clears_it_after(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "data.csv"
    _ = source.write_bytes(b"id,total\n" + b"7,42\n" * 500)
    journal = journal_at(tmp_path)

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = sftp.put(
            source, str(tmp_path / "out.csv").encode(), publish=Publish(journal=journal)
        )

    assert result.staged_at is not None
    # Two lines: staged, then published. The staging file is gone and so is the record.
    assert journal.in_flight() == {}
    assert journal.path.read_text().count("\n") == 2
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "data.csv",
        "out.csv",
        "uploads.journal",
    ]


@pytest.mark.anyio
async def test_a_real_upload_writes_its_journal_off_the_event_loop(tmp_path: Path, monkeypatch):
    """The whole path, against a real server, with the loop watching what runs on it (D-176).

    The rows above prove the *lookup* went to a worker. This one covers the two writes -- and
    they are the half that carries an ``fsync``, which is the longest stall the journal has and
    the one this ``fakeowner`` mount cannot even measure. A fake could not answer this: what is
    being asserted is which thread ran, through the real ``put`` that arranges it.
    """
    needs_real_server()
    source = tmp_path / "data.csv"
    _ = source.write_bytes(b"id,total\n" + b"7,42\n" * 500)
    journal = journal_at(tmp_path)
    loop_thread = threading.get_ident()
    writing_threads: list[int] = []
    real_append = _journal.append_record

    def recording(path, event: str, fields: dict[str, object]) -> None:
        writing_threads.append(threading.get_ident())
        real_append(path, event, fields)

    monkeypatch.setattr(_journal, "append_record", recording)

    async with (
        open_async_local_transport(cwd=tmp_path) as transport,
        open_async_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(tmp_path / "out.csv").encode(), publish=Publish(journal=journal)
        )

    assert result.staged_at is not None
    assert len(writing_threads) == 2, "one `staged` record and one `published` record"
    assert loop_thread not in writing_threads


def test_an_upload_that_fails_before_the_open_leaves_a_stale_record(tmp_path: Path):
    """A record whose file was never created stays, and **that is the safe direction**.

    The note is written before the OPEN because an unanswered request must be assumed to have
    been performed -- so an OPEN that fails outright is indistinguishable, from here, from one
    whose reply was lost after the server created the file. Clearing the record on a refusal
    would be asserting the difference we do not have.

    What a stale record costs is one `STAT` on the next run, which answers `NO_SUCH_FILE`, which
    resumes from zero. What it buys is that a file which *was* created is never unfindable.
    `discard_staged` is how it goes away.
    """
    needs_real_server()
    source = tmp_path / "data.csv"
    _ = source.write_bytes(b"id\n1\n")
    journal = journal_at(tmp_path)
    target = str(tmp_path / "no-such-dir" / "out.csv").encode()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        pytest.raises(SFTPError),
    ):
        sftp.put(source, target, publish=Publish(journal=journal))

    assert list(journal.in_flight()) == [target.decode()]

    # And the next run is unharmed by it: the staging file is not there, so the resume starts
    # from zero and the upload completes normally.
    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        (tmp_path / "no-such-dir").mkdir()
        result = sftp.put(source, target, resume=True, publish=Publish(journal=journal))

    assert result.transferred == source.stat().st_size
    assert Path(target.decode()).read_bytes() == source.read_bytes()
    assert journal.in_flight() == {}


def test_discard_staged_removes_what_a_killed_run_left(tmp_path: Path):
    """The half a user notices first: a directory that fills with `.part` files nobody owns."""
    needs_real_server()
    orphan = tmp_path / ".out.csv.deadbeef.part"
    _ = orphan.write_bytes(b"half a file")
    journal = journal_at(tmp_path)
    journal.staging(str(orphan).encode(), str(tmp_path / "out.csv").encode(), identity())

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        removed = sftp.discard_staged(journal)

    assert removed == (str(orphan).encode(),)
    assert not orphan.exists()
    assert journal.in_flight() == {}


def test_discard_staged_clears_a_record_whose_file_had_already_gone(tmp_path: Path):
    """Cleared but not reported as removed: "removed" is a claim about what happened."""
    needs_real_server()
    journal = journal_at(tmp_path)
    journal.staging(str(tmp_path / ".gone.part").encode(), b"/incoming/out.csv", identity())

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        removed = sftp.discard_staged(journal)

    assert removed == ()
    assert journal.in_flight() == {}


def test_discard_staged_removes_only_what_the_journal_recorded(tmp_path: Path):
    """A sweep that globbed for `.*.part` would delete another publisher's in-flight upload."""
    needs_real_server()
    ours = tmp_path / ".out.csv.aaaa.part"
    _ = ours.write_bytes(b"ours")
    theirs = tmp_path / ".out.csv.bbbb.part"
    _ = theirs.write_bytes(b"somebody else's, still being written")
    journal = journal_at(tmp_path)
    journal.staging(str(ours).encode(), str(tmp_path / "out.csv").encode(), identity())

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        _ = sftp.discard_staged(journal)

    assert not ours.exists()
    assert theirs.read_bytes() == b"somebody else's, still being written"


# --- the crash, for real -------------------------------------------------------------------------


KILLED_UPLOAD = """
import os, signal, sys
from pathlib import Path
from gantry_sftp.session import Publish, UploadJournal
from gantry_sftp.sync import open_local_server_transport, open_session

root, source, journal = Path(sys.argv[1]), Path(sys.argv[2]), UploadJournal(Path(sys.argv[3]))

def die(transferred, total):
    if transferred > 200_000:
        os.kill(os.getpid(), signal.SIGKILL)

# `depth=2` is what makes the kill land *mid-file* rather than after it. At the shipped depth of
# 64 x 255 KiB, well over a megabyte is in flight before the first progress callback crosses the
# threshold, so against a fast server the whole payload is already staged by the time SIGKILL is
# delivered and there is nothing partial to resume. Found by this row failing about half the time
# against paramiko. A smaller window is the honest fix: the subject is the crash, not the
# scheduler.
with open_local_server_transport(cwd=root) as t, open_session(t, depth=2) as s:
    s.put(source, str(root / "out.bin").encode(), publish=Publish(journal=journal), progress=die)
"""


def _first_difference(actual: bytes, expected: bytes) -> str | None:
    """Describe how two payloads differ, or `None` when they do not.

    D-188. The published file is a megabyte, and asserting `actual == expected` on it hands
    pytest two megabyte-long `bytes` to render when it fails -- which is a second way to lose a
    failure that has nothing to do with anybody piping the run into `tail`. Comparing here and
    asserting on this string keeps the payload out of the assertion's repr entirely.
    """
    if actual == expected:
        return None
    if len(actual) != len(expected):
        return f"published {len(actual)} bytes, the source is {len(expected)}"
    offset = next(i for i, (a, b) in enumerate(zip(actual, expected, strict=True)) if a != b)
    window = slice(max(0, offset - 8), offset + 8)
    return (
        f"same length ({len(actual)}) and the bytes differ from offset {offset}: "
        f"published {actual[window]!r}, source {expected[window]!r}"
    )


def test_the_payload_comparison_names_the_difference_without_rendering_the_payload():
    """D-188. This helper runs only when the row below fails, and a path that runs only on a
    failure is the shape that hides defects -- the `lsetstat` swallow this project reported
    upstream sat under a `# pragma: no cover` for exactly that reason. So its three answers are
    pinned now rather than read for the first time on the day it fires.
    """
    assert _first_difference(b"abc", b"abc") is None
    assert _first_difference(b"abc", b"abcdef") == "published 3 bytes, the source is 6"
    assert _first_difference(b"abcX", b"abcY") == (
        "same length (4) and the bytes differ from offset 3: published b'abcX', source b'abcY'"
    )


def test_an_upload_killed_mid_transfer_is_resumed_by_a_different_process(tmp_path: Path):
    """The card, proved rather than described: a real SIGKILL and a real second process.

    **Not a simulated crash.** The point of the feature is that nothing runs on the way out --
    no `finally`, no context manager, no shielded cleanup -- so a test that raised an exception
    instead would exercise the one path that already worked. `SIGKILL` cannot be caught, which
    is what makes it the right instrument.
    """
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    source = tmp_path / "src.bin"
    _ = source.write_bytes(bytes(range(256)) * 4000)
    journal = journal_at(tmp_path)
    script = tmp_path / "killed.py"
    _ = script.write_text(KILLED_UPLOAD, encoding="utf-8")

    killed = subprocess.run(
        [sys.executable, str(script), str(root), str(source), str(journal.path)],
        capture_output=True,
        timeout=120,
        check=False,
    )

    assert killed.returncode == -9, (
        f"the child exited {killed.returncode} instead of dying of SIGKILL"
        + (
            " -- the upload finished before the progress callback crossed the threshold, so "
            "there was nothing left to kill"
            if killed.returncode == 0
            else " -- it failed on its own before reaching the kill"
        )
        + f"\nstderr:\n{killed.stderr.decode('utf-8', 'replace')}"
    )
    staged = [p for p in root.iterdir() if p.name.endswith(".part")]
    assert len(staged) == 1, (
        f"expected one .part file to resume from and found {len(staged)}; the directory holds "
        f"{sorted(p.name for p in root.iterdir())}"
    )
    partial = staged[0].stat().st_size
    complete = source.stat().st_size
    assert 0 < partial < complete, (
        f"the staging file is {partial} bytes of {complete}, which leaves nothing partial to "
        "resume: 0 means the kill landed before any write was on disk, and the whole size means "
        "it landed after the last one"
    )
    # The record is on disk because it was written before the OPEN, which is the whole design.
    recorded = journal.staged_for(str(root / "out.bin").encode(), source_identity(source))
    assert recorded == str(staged[0]).encode(), (
        f"the journal names {recorded!r} as the staging file and the one on disk is "
        f"{str(staged[0]).encode()!r}"
    )

    with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        result = sftp.put(
            source, str(root / "out.bin").encode(), resume=True, publish=Publish(journal=journal)
        )

    # D-188: every message below carries the numbers rather than a diagnosis. "It did not
    # resume, it restarted" was one reading of this failing, and a resume from an offset other
    # than the one measured above is another, which the same assertion cannot tell apart.
    assert result.transferred == complete - partial, (
        f"the resuming run moved {result.transferred} bytes; {complete - partial} was what "
        f"remained after {partial} of {complete} had been staged. {complete} would mean it "
        "restarted, and anything else means it resumed from a different offset"
    )
    difference = _first_difference((root / "out.bin").read_bytes(), source.read_bytes())
    assert difference is None, f"the published file is not the source: {difference}"
    names = sorted(p.name for p in root.iterdir())
    assert names == ["out.bin"], (
        f"publishing should leave the destination and nothing beside it, and the directory "
        f"holds {names}"
    )
    in_flight = journal.in_flight()
    assert in_flight == {}, (
        f"the journal still lists {len(in_flight)} upload(s) in flight after a successful "
        f"publish: {in_flight}"
    )


RESUMED_DOWNLOAD = """
import sys
from pathlib import Path
from gantry_sftp.sync import open_local_server_transport, open_session

root, local = Path(sys.argv[1]), Path(sys.argv[2])
with open_local_server_transport(cwd=root) as t, open_session(t) as s:
    result = s.get(str(root / "big.bin").encode(), local, resume=True)
print(result.transferred)
"""


def test_a_download_still_needs_no_journal_at_all(tmp_path: Path):
    """The recon finding, kept as a regression guard rather than as a note in a card.

    A download's partial is a file on our own disk, so its length is a fact rather than a
    report -- which is why this direction already survived a process death and why the journal
    is upload-side. The day somebody unifies the two, this fails, and the thing it protects is
    that the upload's weaker evidence never gets applied to the direction that never needed it.
    """
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    _ = (root / "big.bin").write_bytes(bytes(range(256)) * 400)
    local = tmp_path / "partial.bin"
    _ = local.write_bytes((root / "big.bin").read_bytes()[:40000])
    script = tmp_path / "resumed.py"
    _ = script.write_text(RESUMED_DOWNLOAD, encoding="utf-8")

    finished = subprocess.run(
        [sys.executable, str(script), str(root), str(local)],
        capture_output=True,
        timeout=120,
        check=False,
    )

    assert finished.returncode == 0, finished.stderr.decode("utf-8", "replace")
    assert finished.stdout.strip() == b"62400"
    assert local.read_bytes() == (root / "big.bin").read_bytes()


# --- fuzzing the fold ----------------------------------------------------------------------------


# No deadline, because every example here makes a directory and writes and reads a real file,
# so hypothesis's per-example clock is measuring the machine rather than this code. It is a tail
# and not a mean: typical examples run a few tens of milliseconds against a 200 ms default, and a
# contended run produced one at 262.88 ms which took 36.63 ms on the retry -- reported as
# `FlakyFailure`, on `fast`, which is a required check. Nothing is given up by dropping it. The
# pathology a deadline would have caught here is a record costing more than one write, and
# `test_an_appended_record_is_one_write` asserts that by counting, which no amount of load moves.
@given(
    staged=st.binary(min_size=1, max_size=60),
    target=st.binary(min_size=1, max_size=60),
    local=st.text(max_size=60),
    size=st.integers(min_value=0, max_value=2**40),
    mtime=st.integers(min_value=0, max_value=2**32 - 1),
)
@settings(deadline=None)
def test_a_record_survives_being_written_and_folded_back(
    tmp_path_factory, staged: bytes, target: bytes, local: str, size: int, mtime: int
):
    """The round trip, over names and values nobody would think to type.

    Remote paths are generated as raw bytes because that is what they are -- a name that was
    never valid UTF-8 is ordinary, and it is exactly the name a lossy journal would lose.
    """
    path = tmp_path_factory.mktemp("journal") / "uploads.journal"
    journal = UploadJournal(path)
    source = SourceIdentity(path=local, size=size, mtime=mtime)

    journal.staging(staged, target, source)

    assert journal.staged_for(target, source) == staged


# No deadline, for the reason given on the row above: the per-example work is a real file.
@given(blob=st.binary(max_size=400))
@settings(deadline=None)
def test_folding_arbitrary_bytes_never_raises(tmp_path_factory, blob: bytes):
    """The file is on disk between two runs of somebody's job, so it is not trusted input.

    It must not be possible to make a diagnostic-shaped crash out of whatever is in it, and
    the honest answer to garbage is "nothing is in flight".
    """
    path = tmp_path_factory.mktemp("journal") / "uploads.journal"
    _ = path.write_bytes(blob)

    assert isinstance(fold(path), dict)


def test_an_appended_record_is_one_write(tmp_path: Path, monkeypatch):
    """What makes a concurrent tree upload safe without a lock.

    `put_tree(concurrency=N)` runs N uploads against one journal. Interleaved partial writes
    would corrupt lines; one `write` per record under `O_APPEND` cannot. Asserted by counting,
    because "it is one call" is a property of this code rather than of the filesystem.
    """
    writes: list[int] = []
    real_write = os.write

    def counted(fd: int, data: bytes) -> int:
        writes.append(len(data))
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", counted)
    append_record(tmp_path / "uploads.journal", "staged", {"target": "/incoming/x"})

    assert len(writes) == 1

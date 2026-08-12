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

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.exceptions import SFTPError
from gantry_sftp.session import (
    JournalEntry,
    Publish,
    SourceIdentity,
    UploadJournal,
)
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


def test_a_named_staging_file_outranks_the_journal(tmp_path: Path):
    """Nothing to look up when the caller named the file, so nothing that could disagree."""
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert resume_target(journal, TARGET, identity(), resume=True, name=b"chosen.part") is None


def test_nothing_is_continued_when_resume_was_not_asked_for(tmp_path: Path):
    """A journal on a non-resuming upload records where the bytes went and adopts nothing.

    Worth pinning because the opposite would be a silent behaviour change: passing a journal
    for the cleanup it buys would start resuming uploads the caller did not ask to resume.
    """
    journal = journal_at(tmp_path)
    journal.staging(STAGED, TARGET, identity())

    assert resume_target(journal, TARGET, identity(), resume=False, name=None) is None


def test_without_a_journal_nothing_is_continued():
    assert resume_target(None, TARGET, identity(), resume=True, name=None) is None


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

    assert killed.returncode == -9, killed.stderr.decode("utf-8", "replace")
    staged = [p for p in root.iterdir() if p.name.endswith(".part")]
    assert len(staged) == 1, "the killed run left no staging file, so there is nothing to resume"
    partial = staged[0].stat().st_size
    assert 0 < partial < source.stat().st_size
    # The record is on disk because it was written before the OPEN, which is the whole design.
    assert (
        journal.staged_for(str(root / "out.bin").encode(), source_identity(source))
        == str(staged[0]).encode()
    )

    with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        result = sftp.put(
            source, str(root / "out.bin").encode(), resume=True, publish=Publish(journal=journal)
        )

    assert result.transferred == source.stat().st_size - partial, "it did not resume, it restarted"
    assert (root / "out.bin").read_bytes() == source.read_bytes()
    assert sorted(p.name for p in root.iterdir()) == ["out.bin"]
    assert journal.in_flight() == {}


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


@given(
    staged=st.binary(min_size=1, max_size=60),
    target=st.binary(min_size=1, max_size=60),
    local=st.text(max_size=60),
    size=st.integers(min_value=0, max_value=2**40),
    mtime=st.integers(min_value=0, max_value=2**32 - 1),
)
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


@given(blob=st.binary(max_size=400))
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

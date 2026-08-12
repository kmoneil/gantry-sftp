"""An upload that is killed outright, and finished by a second process.

    python examples/crash_resume.py                  # local sftp-server, no network
    python examples/crash_resume.py user@host        # a real server over ssh

**This example kills itself.** It forks a child that starts a large upload and sends itself
`SIGKILL` partway through -- not an exception, not a cancellation, not a context manager exiting.
`SIGKILL` cannot be caught, so nothing runs on the way out: no ``finally``, no shielded cleanup,
no chance to record anything. That is the point. A demonstration that raised an exception instead
would be exercising the path that already worked before any of this existed.

**What the parent then does is the whole feature.** It opens a fresh session, passes the same
journal, and continues from the partial the dead child left -- a file whose name carries fresh
randomness and which nothing could have found otherwise.

The three things worth copying out of here:

**The journal records a name, never an offset.** After a crash a process knows what it *intended*
to send, not what the far end accepted, so a journal of byte counts would be a corruption engine.
Where to resume from is read off the server, exactly as it was before.

**The record is written before the OPEN.** An unanswered request must be assumed to have been
performed, so the note saying where the bytes are going has to be durable before anything could
create the file.

**Cleanup is the half you notice first.** The third section leaves an orphan on purpose and sweeps
it, because a directory that slowly fills with ``.part`` files nobody owns is what an operator
actually complains about.

**And then the same crash one level up.** The last section kills a ``put_tree`` inside one of its
files and resumes the whole tree on one journal -- the combination that was refused outright until
D-172, because each file stages under a name generated fresh per call and nothing could find them
again. Note what it does *not* do: ``put_tree`` re-sends the files that already landed, because it
is not a mirror. ``sync_tree`` is the operation that decides not to send something.
"""

from __future__ import annotations

import os
import signal
import sys
import tempfile
from pathlib import Path

from gantry_sftp.session import Publish, UploadJournal
from gantry_sftp.session._journal import source_identity
from gantry_sftp.sync import SyncSession, connect, open_local_server_transport, open_session

PAYLOAD = bytes(range(256)) * 8000
"""Two megabytes, so there is time to be killed in the middle of sending it."""

KILL_AFTER = 400_000
"""Bytes to let through before the child kills itself. Any value inside the file will do."""


def upload_and_die(root: Path, source: Path, target: bytes, journal: UploadJournal) -> None:
    """Start an upload and SIGKILL this process partway through. Never returns."""

    def die(transferred: int, total: int | None) -> None:
        if transferred > KILL_AFTER:
            print(f"  child: {transferred} bytes in, killing myself with SIGKILL")
            sys.stdout.flush()
            os.kill(os.getpid(), signal.SIGKILL)

    with open_local_server_transport(cwd=root) as transport, open_session(transport) as sftp:
        _ = sftp.put(source, target, publish=Publish(journal=journal), progress=die)


def show_what_the_crash_left(root: Path, journal: UploadJournal) -> Path:
    """Print the staging file and the record that is the only way to find it again."""
    staged = [p for p in root.iterdir() if p.name.endswith(".part")]
    print(f"\nafter the crash, the server holds: {sorted(p.name for p in root.iterdir())}")
    print(f"  the staging file is {staged[0].stat().st_size} bytes of a {len(PAYLOAD)}-byte file")
    print(f"  its name carries randomness nothing could reconstruct: {staged[0].name}")
    print("\nthe journal, which is the only thing that can find it:")
    for line in journal.path.read_text().splitlines():
        print(f"  {line}")
    return staged[0]


def finish_it(sftp: SyncSession, source: Path, target: bytes, journal: UploadJournal) -> None:
    """Resume into the dead child's staging file and publish it."""
    result = sftp.put(source, target, resume=True, publish=Publish(journal=journal))
    print("\nsecond process, same journal:")
    print(
        f"  transferred {result.transferred} of {len(PAYLOAD)} bytes -- the rest was already there"
    )
    print(f"  published with mechanism={result.mechanism.name}")
    print(f"  resume_check={result.resume_check.name}")


def sweep(sftp: SyncSession, root: Path, target: bytes, journal: UploadJournal) -> None:
    """Leave an orphan the way a crash would, then remove it through the journal."""
    orphan = root / ".orphan.bin.deadbeef.part"
    _ = orphan.write_bytes(b"half of something nobody will ever finish")
    journal.staging(
        str(orphan).encode(), str(root / "orphan.bin").encode(), source_identity(orphan)
    )
    stranger = root / ".orphan.bin.cafebabe.part"
    _ = stranger.write_bytes(b"another publisher, still writing")

    print("\na crash also leaves files nothing else can clean up:")
    print(f"  before: {sorted(p.name for p in root.iterdir() if p.name.endswith('.part'))}")
    removed = sftp.discard_staged(journal)
    print(f"  discard_staged removed {[p.decode() for p in removed]}")
    print(f"  after:  {sorted(p.name for p in root.iterdir() if p.name.endswith('.part'))}")
    print("  the one left is another publisher's -- the sweep removes only what it recorded")
    _ = target


def run_locally(workdir: Path) -> None:
    """The whole demonstration against a local sftp-server, including the fork."""
    root = workdir / "srv"
    root.mkdir()
    source = workdir / "big.bin"
    _ = source.write_bytes(PAYLOAD)
    target = str(root / "big.bin").encode()
    journal = UploadJournal(workdir / "uploads.journal")

    print(f"uploading {len(PAYLOAD)} bytes, and dying after {KILL_AFTER}:")
    child = os.fork()
    if child == 0:  # pragma: no cover -- the child never returns, it is killed
        upload_and_die(root, source, target, journal)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    print(f"  parent: child exited on signal {os.WTERMSIG(status)} (9 = SIGKILL)")

    _ = show_what_the_crash_left(root, journal)

    with open_local_server_transport(cwd=root) as transport, open_session(transport) as sftp:
        finish_it(sftp, source, target, journal)
        published = Path(target.decode()).read_bytes()
        print(f"\n  bytes match the source: {published == PAYLOAD}")
        print(f"  nothing left staged:    {[p.name for p in root.iterdir()] == ['big.bin']}")
        print(f"  journal is clear:       {journal.in_flight() == {}}")
        sweep(sftp, root, target, journal)

    run_tree_demonstration(workdir)


def upload_tree_and_die(root: Path, source: Path, target: bytes, journal: UploadJournal) -> None:
    """Start a whole tree and SIGKILL this process inside one of its files. Never returns."""

    def die(transferred: int, total: int | None) -> None:
        # Only inside the large file: the small ones ahead of it have to reach their
        # destinations, because what the resume then demonstrates is that it continues the one
        # that was interrupted and re-sends the others from scratch.
        if total is not None and total > KILL_AFTER and transferred > KILL_AFTER:
            print(f"  child: {transferred} bytes into the big file, killing myself")
            sys.stdout.flush()
            os.kill(os.getpid(), signal.SIGKILL)

    with open_local_server_transport(cwd=root) as transport, open_session(transport) as sftp:
        _ = sftp.put_tree(
            source,
            target,
            resume=True,
            publish=Publish(journal=journal),
            progress=die,
            concurrency=1,
        )


def run_tree_demonstration(workdir: Path) -> None:
    """The same crash one level up: a tree, killed inside one file, resumed on one journal.

    `put_tree(resume=True)` used to be refused outright with atomic publishing, because a
    staging name generated fresh per call cannot be found again. The journal is what makes each
    of them findable, so the tree keeps atomic publishing *and* resumes.

    **`put_tree` is not a mirror.** The files that already landed are uploaded again in full --
    only the interrupted one continues. `sync_tree` is the operation that decides not to send
    something, and it decides that against a manifest rather than a journal.
    """
    root = workdir / "tree-srv"
    root.mkdir()
    source = workdir / "outgoing"
    source.mkdir()
    _ = (source / "small-a.bin").write_bytes(b"a" * 4096)
    _ = (source / "small-b.bin").write_bytes(b"b" * 4096)
    # Named to sort last: `walk_local` yields entries sorted by name, so the two small files
    # are published before the kill lands inside this one.
    _ = (source / "zz-big.bin").write_bytes(PAYLOAD)
    total = sum(path.stat().st_size for path in source.iterdir())
    destination = root / "incoming"
    journal = UploadJournal(workdir / "tree.journal")

    print(f"\nuploading a {total}-byte tree, and dying inside the big file:")
    child = os.fork()
    if child == 0:  # pragma: no cover -- the child never returns, it is killed
        upload_tree_and_die(root, source, str(destination).encode(), journal)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    print(f"  parent: child exited on signal {os.WTERMSIG(status)} (9 = SIGKILL)")

    staged = [path for path in destination.iterdir() if path.name.endswith(".part")]
    landed = sorted(p.name for p in destination.iterdir() if not p.name.endswith(".part"))
    partial = staged[0].stat().st_size
    print(f"  published before the crash: {landed}")
    print(f"  one file was in flight:     {staged[0].name} ({partial} bytes)")
    print(f"  the journal has {len(journal.in_flight())} record still in flight")

    with open_local_server_transport(cwd=root) as transport, open_session(transport) as sftp:
        result = sftp.put_tree(
            source, str(destination).encode(), resume=True, publish=Publish(journal=journal)
        )

    # The whole tree less the prefix already staged: the small files go again, the big one
    # continues. A run that restarted the big file would move `total` and read identically.
    print(f"\nsecond process, same journal: moved {result.transferred} of {total} bytes")
    print(f"  resumed rather than restarted: {result.transferred == total - partial}")
    matches = all((destination / p.name).read_bytes() == p.read_bytes() for p in source.iterdir())
    print(f"  every file matches its source: {matches}")
    print(f"  nothing left staged:           {not list(destination.glob('*.part'))}")
    print(f"  journal is clear:              {journal.in_flight() == {}}")


def run_remotely(destination: str, workdir: Path) -> None:
    """The same three points against a real server, without forking a killed child.

    A remote run stages the crash rather than causing one: killing a process mid-upload against
    somebody's real server would leave a partial file there if anything about this example were
    wrong, and an example is not the place to find that out.
    """
    user, _, host = destination.rpartition("@")
    source = workdir / "big.bin"
    _ = source.write_bytes(PAYLOAD)

    with connect(host, user=user or None) as sftp:
        home = sftp.realpath(b".").rstrip(b"/")
        target = home + b"/gantry-crash-resume-example.bin"
        journal = UploadJournal(workdir / "uploads.journal")
        try:
            result = sftp.put(source, target, publish=Publish(journal=journal))
            print(f"uploaded {result.transferred} bytes, mechanism={result.mechanism.name}")
            print(f"journal after a clean publish: {journal.in_flight()}")
            print("\nthe crash path needs a process to kill; run with no arguments to see it.")
        finally:
            sftp.remove(target)


def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        if destination is None:
            run_locally(workdir)
        else:
            run_remotely(destination, workdir)


if __name__ == "__main__":
    main()

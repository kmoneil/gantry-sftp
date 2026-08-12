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

**Cleanup is the half you notice first.** The last section leaves an orphan on purpose and sweeps
it, because a directory that slowly fills with ``.part`` files nobody owns is what an operator
actually complains about.
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

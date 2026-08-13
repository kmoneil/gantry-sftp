"""The upload journal against three real servers, and across a real process death.

**D-166.** `tests/test_journal.py` proves the mechanism against OpenSSH's `sftp-server` on a pipe,
including a `SIGKILL` mid-transfer. This is the other axis: the same crash and the same recovery
against the three implementations in the matrix, over real `ssh` connections.

**Why the matrix matters for this feature specifically.** Resuming an atomic publish depends on
two things the servers disagree about. Adopting a partial needs an `OPEN` with `CREAT` and no
`TRUNC` to keep what is there, and publishing over the destination needs a rename that can replace
one -- which is `posix-rename@openssh.com` where it exists and something weaker where it does not.
paramiko's server advertises no `posix-rename`, so it takes a different route to the same place,
and a feature tested against one implementation is tested against one implementation.

Blocking, through `gantry_sftp.sync`, because the subprocess that gets killed has to be an
ordinary program rather than something inside an event loop this test owns.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from matrix import SERVER_NAMES, MatrixServer, running_server, unavailable_reason

from gantry_sftp.session import Publish, PublishMechanism, UploadJournal
from gantry_sftp.session._journal import source_identity
from gantry_sftp.sync import open_session, open_ssh_transport

PAYLOAD = bytes(range(256)) * 4000


def settled_size(path: Path, *, quiet_for: float = 0.5, timeout: float = 30.0) -> int:
    """The staging file's size once it has stopped growing, which is not the size it is now.

    **The client is SIGKILLed; the server is not** (D-181). A ``WRITE`` already on the wire is
    applied by the far end after the process that sent it is gone, so a ``stat`` taken the moment
    ``subprocess.run`` returns can be short by up to ``depth`` requests. The rows below then
    compare a resume against a number that was already stale when it was read.

    That is measured rather than feared. On 2026-08-13 the tree row failed on a macOS runner with
    the staging file **261120 bytes larger at resume than when it was measured** -- exactly
    ``PREFERRED_WRITE_LENGTH``, one request, to the byte -- and the transfer it reported was
    correct for the file's real size. The library resumed properly and the expectation was wrong.

    Args:
        path: The staging file, which the far end may still be extending.
        quiet_for: How long the size must hold still to count as settled. Generous against a
            local ``sftp-server`` writing 255 KiB at a time; the timeout is what bounds the
            pathological case rather than this.
        timeout: Give up after this long. **A bound rather than a sleep**: a file that never
            settles is a server that never stopped, which is a finding and must fail loudly
            instead of hanging the lane until the job's own timeout kills it.

    Returns:
        The size, once two reads ``quiet_for`` apart agree.

    Raises:
        AssertionError: If it is still changing when ``timeout`` expires.
    """
    deadline = time.monotonic() + timeout
    size = path.stat().st_size
    unchanged_since = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(0.05)
        current = path.stat().st_size
        if current != size:
            size, unchanged_since = current, time.monotonic()
        elif time.monotonic() - unchanged_since >= quiet_for:
            return size
    raise AssertionError(
        f"{path} was still growing {timeout:g}s after the writer was killed (now {size} "
        f"bytes); the far end never stopped applying requests, which is a finding rather than "
        f"a slow runner"
    )


KILLED_UPLOAD = """
import json, os, signal, sys
from pathlib import Path
from gantry_sftp.session import Publish, UploadJournal
from gantry_sftp.sync import open_ssh_transport, open_session

# The whole connect mapping, forwarded rather than reconstructed from the parts this script
# happens to need. Rebuilding it from `port` and `options` alone dropped `config_file`, and the
# subprocess then read the developer's real `~/.ssh/config` -- which on this machine is a macOS
# config OpenSSH 10 refuses outright, so every run died at the handshake with an error naming
# the config rather than the test.
plan = json.loads(sys.argv[1])
source, journal, target = Path(sys.argv[2]), UploadJournal(Path(sys.argv[3])), sys.argv[4]
host = plan.pop("host")

def die(transferred, total):
    if transferred > 200_000:
        os.kill(os.getpid(), signal.SIGKILL)

# `depth=2` is what makes the kill land *mid-file* rather than after it. At the shipped depth of
# 64 x 255 KiB, well over a megabyte is in flight before the first progress callback crosses the
# threshold, so against a fast server the whole payload is already staged by the time SIGKILL is
# delivered and there is nothing partial to resume. Found by this row failing about half the time
# against paramiko. A smaller window is the honest fix: the subject is the crash, not the
# scheduler.
with open_ssh_transport(host, **plan) as t, open_session(t, depth=2) as s:
    s.put(source, target.encode(), publish=Publish(journal=journal), progress=die)
"""


KILLED_TREE_UPLOAD = """
import json, os, signal, sys
from pathlib import Path
from gantry_sftp.session import Publish, UploadJournal
from gantry_sftp.sync import open_ssh_transport, open_session

plan = json.loads(sys.argv[1])
source, journal, target = Path(sys.argv[2]), UploadJournal(Path(sys.argv[3])), sys.argv[4]
host = plan.pop("host")

def die(transferred, total):
    # Only on the one file large enough to leave a partial worth resuming: the small files
    # ahead of it must reach their destinations, because what this row proves is that the
    # restart continues *one* file and does not care about the others.
    if total is not None and total > 500_000 and transferred > 200_000:
        os.kill(os.getpid(), signal.SIGKILL)

# `depth=2` for the reason the single-file script gives: at the shipped depth the whole payload
# is in flight before the first callback crosses the threshold, and there is nothing partial.
with open_ssh_transport(host, **plan) as t, open_session(t, depth=2) as s:
    s.put_tree(
        source, target.encode(),
        resume=True, publish=Publish(journal=journal), progress=die, concurrency=1,
    )
"""


@pytest.fixture(params=SERVER_NAMES)
def server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MatrixServer]:
    """One running server per implementation, skipping with a reason when it cannot start."""
    name = str(request.param)
    reason = unavailable_reason(name)
    if reason is not None:
        pytest.skip(reason)
    with running_server(name, tmp_path) as running:
        yield running


def connected(server: MatrixServer):
    """A blocking session against ``server``, over a real ``ssh`` connection."""
    connect = dict(server.connect)
    host = str(connect.pop("host"))
    return open_ssh_transport(host, **connect)


def _jsonable(value: object) -> object:
    """A connect value the subprocess can be handed as JSON.

    Paths arrive as `Path` and options as a mapping; everything else is already a scalar. Kept
    deliberately shallow -- a general encoder here would quietly accept a value the child then
    could not use.
    """
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    return value


def test_an_upload_killed_mid_transfer_resumes_against_this_server(
    server: MatrixServer, tmp_path: Path
):
    """The card, against each implementation in turn.

    The kill is a real `SIGKILL` in a real subprocess, so nothing runs on the way out -- no
    `finally`, no context manager, no shielded cleanup. That is the whole point: the record has
    to be on disk *because it was written before the OPEN*, not because anything tidied up.
    """
    source = tmp_path / "src.bin"
    _ = source.write_bytes(PAYLOAD)
    journal = UploadJournal(tmp_path / "uploads.journal")
    target = str(server.root / "out.bin")
    script = tmp_path / "killed.py"
    _ = script.write_text(KILLED_UPLOAD, encoding="utf-8")

    plan = {key: _jsonable(value) for key, value in server.connect.items()}
    killed = subprocess.run(
        [sys.executable, str(script), json.dumps(plan), str(source), str(journal.path), target],
        capture_output=True,
        timeout=180,
        check=False,
    )

    assert killed.returncode == -9, killed.stderr.decode("utf-8", "replace")
    staged = [p for p in server.root.iterdir() if p.name.endswith(".part")]
    assert len(staged) == 1, f"{server.name} left no staging file to resume"
    # Settled, not snapshotted: see `settled_size` for the request that lands after the kill.
    partial = settled_size(staged[0])
    assert 0 < partial < len(PAYLOAD)
    assert journal.staged_for(target.encode(), source_identity(source)) == str(staged[0]).encode()

    with connected(server) as transport, open_session(transport) as sftp:
        result = sftp.put(source, target.encode(), resume=True, publish=Publish(journal=journal))

    assert result.transferred == len(PAYLOAD) - partial, (
        f"resume moved {result.transferred} bytes, expected {len(PAYLOAD) - partial} "
        f"({len(PAYLOAD)} payload minus the {partial} already staged). **More** means it "
        f"restarted the file it should have continued. **Fewer** means it adopted more than "
        f"was measured, which before D-181 was a race rather than a finding -- `settled_size` "
        f"is what rules that out, so fewer now means the resume offset is wrong"
    )
    assert Path(target).read_bytes() == PAYLOAD
    # No exact listing: `server.root` is the test's own `tmp_path` for this fixture, so it also
    # holds the script, the keys and the journal. The claim is about staging files.
    assert [p.name for p in server.root.iterdir() if p.name.endswith(".part")] == []
    assert journal.in_flight() == {}


def test_a_tree_killed_mid_file_resumes_against_this_server(server: MatrixServer, tmp_path: Path):
    """D-172, and the row the lifted guard exists for.

    `tests/` proves the *request* is accepted and that each file records a name of its own. What
    only a real crash can show is the rest of it: that the record on disk survives a process
    that ran no cleanup, that the restart finds the one file that was in flight, and that it
    continues that file while re-sending the others from scratch -- `put_tree` is not a mirror
    and does not skip what is already there.

    Against all three implementations for the reason this module's docstring gives: adopting a
    partial and publishing over a destination are the two things they disagree about, and a tree
    does both once per file.
    """
    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.bin").write_bytes(b"a" * 4096)
    _ = (source / "b.bin").write_bytes(b"b" * 4096)
    _ = (source / "big.bin").write_bytes(PAYLOAD)
    total = sum(path.stat().st_size for path in source.iterdir())
    # A directory of its own under the server's root, which for this fixture is also the test's
    # `tmp_path` and holds the keys, the script and the journal.
    destination = server.root / "incoming"
    journal = UploadJournal(tmp_path / "uploads.journal")
    script = tmp_path / "killed_tree.py"
    _ = script.write_text(KILLED_TREE_UPLOAD, encoding="utf-8")

    plan = {key: _jsonable(value) for key, value in server.connect.items()}
    killed = subprocess.run(
        [
            sys.executable,
            str(script),
            json.dumps(plan),
            str(source),
            str(journal.path),
            str(destination),
        ],
        capture_output=True,
        timeout=180,
        check=False,
    )

    assert killed.returncode == -9, killed.stderr.decode("utf-8", "replace")
    staged = [path for path in destination.iterdir() if path.name.endswith(".part")]
    assert len(staged) == 1, f"{server.name} left {len(staged)} staging files, expected one"
    # `walk_local` yields entries sorted by name, so the two small files are published before
    # the kill lands inside `big.bin`. Asserted rather than assumed: with the order the other
    # way the row would still pass its arithmetic while proving nothing about the others.
    assert sorted(p.name for p in destination.iterdir() if not p.name.endswith(".part")) == [
        "a.bin",
        "b.bin",
    ]
    # Settled, not snapshotted. This is the row D-181 was filed for: it failed on a macOS
    # runner with the file exactly one `PREFERRED_WRITE_LENGTH` larger at resume than here.
    partial = settled_size(staged[0])
    assert 0 < partial < len(PAYLOAD)
    in_flight = journal.in_flight()
    assert len(in_flight) == 1, "the killed file is the only one that should still be in flight"
    assert (
        journal.staged_for(
            str(destination / "big.bin").encode(), source_identity(source / "big.bin")
        )
        == str(staged[0]).encode()
    )

    with connected(server) as transport, open_session(transport) as sftp:
        result = sftp.put_tree(
            source, str(destination).encode(), resume=True, publish=Publish(journal=journal)
        )

    assert result.files == 3
    # The small files are sent again in full and the big one continues, so the difference from
    # the whole tree is exactly the prefix that was already staged. Anything else means it
    # restarted the file it was supposed to resume.
    assert result.transferred == total - partial, (
        f"resume moved {result.transferred} bytes, expected {total - partial} (tree total "
        f"{total} minus the {partial} already staged). **More** means it restarted the file it "
        f"should have continued. **Fewer** means it adopted more than was measured, which "
        f"before D-181 was a race rather than a finding -- `settled_size` is what rules that "
        f"out, so fewer now means the resume offset is wrong"
    )
    for name in ("a.bin", "b.bin", "big.bin"):
        assert (destination / name).read_bytes() == (source / name).read_bytes()
    assert [path.name for path in destination.iterdir() if path.name.endswith(".part")] == []
    assert journal.in_flight() == {}


def test_the_recovery_uses_the_strongest_publish_this_server_offers(
    server: MatrixServer, tmp_path: Path
):
    """The mechanism is not the same on all three, and a resumed publish is still a publish.

    paramiko's server advertises no `posix-rename@openssh.com`, so it publishes through plain v3
    `RENAME` -- and **that succeeds over an existing target here, which the draft says it must
    not**. That is `_ParamikoHandler.rename` using `Path.rename`, recorded in `matrix.py` as the
    harness's own choice, and it is the same behaviour D-165's compatibility battery measures as
    `RENAME replaces an existing target = yes` for this server. Two features agreeing about one
    server is worth more than either asserting it alone.

    So the row is a measurement rather than an assertion that all three behave alike, and what
    it pins is that a journalled publish still selects the strongest mechanism *this* server
    offers rather than silently degrading further.
    """
    source = tmp_path / "src.bin"
    _ = source.write_bytes(b"id,total\n" + b"7,42\n" * 200)
    journal = UploadJournal(tmp_path / "uploads.journal")
    target = str(server.root / "out.csv")
    # A destination already in place, which is what separates the three mechanisms.
    _ = Path(target).write_bytes(b"stale\n")

    with connected(server) as transport, open_session(transport) as sftp:
        result = sftp.put(source, target.encode(), publish=Publish(journal=journal))

    assert Path(target).read_bytes() == source.read_bytes()
    if server.name == "paramiko":
        assert result.mechanism is PublishMechanism.RENAME
    else:
        assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert journal.in_flight() == {}


def test_the_sweep_removes_what_a_killed_run_left_on_this_server(
    server: MatrixServer, tmp_path: Path
):
    """`discard_staged` over a real connection, and only over what the journal recorded."""
    journal = UploadJournal(tmp_path / "uploads.journal")
    ours = server.root / ".out.bin.aaaa.part"
    _ = ours.write_bytes(b"half of ours")
    theirs = server.root / ".out.bin.bbbb.part"
    _ = theirs.write_bytes(b"another publisher, still writing")
    journal.staging(
        str(ours).encode(), str(server.root / "out.bin").encode(), source_identity(ours)
    )

    with connected(server) as transport, open_session(transport) as sftp:
        removed = sftp.discard_staged(journal)

    assert removed == (str(ours).encode(),)
    assert not ours.exists()
    assert theirs.read_bytes() == b"another publisher, still writing"
    assert journal.in_flight() == {}

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
from collections.abc import Iterator
from pathlib import Path

import pytest
from matrix import SERVER_NAMES, MatrixServer, running_server, unavailable_reason

from gantry_sftp.session import Publish, PublishMechanism, UploadJournal
from gantry_sftp.session._journal import source_identity
from gantry_sftp.sync import open_session, open_ssh_transport

PAYLOAD = bytes(range(256)) * 4000

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
    partial = staged[0].stat().st_size
    assert 0 < partial < len(PAYLOAD)
    assert journal.staged_for(target.encode(), source_identity(source)) == str(staged[0]).encode()

    with connected(server) as transport, open_session(transport) as sftp:
        result = sftp.put(source, target.encode(), resume=True, publish=Publish(journal=journal))

    assert result.transferred == len(PAYLOAD) - partial, "it restarted rather than resuming"
    assert Path(target).read_bytes() == PAYLOAD
    # No exact listing: `server.root` is the test's own `tmp_path` for this fixture, so it also
    # holds the script, the keys and the journal. The claim is about staging files.
    assert [p.name for p in server.root.iterdir() if p.name.endswith(".part")] == []
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

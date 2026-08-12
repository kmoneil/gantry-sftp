"""The mirror across a real process death, against three real servers (D-173).

`tests/test_sync_tree.py` proves the record exists before the run ends, and proves an
*exception* mid-run leaves it readable. Neither is a crash: an exception unwinds, and a process
that unwinds is a process that could have written its record on the way out. This is the other
axis -- a real `SIGKILL`, so nothing runs on the way out, and the record is on disk because it
was appended as each file landed rather than because anything tidied up.

**Why the matrix matters for this feature specifically.** The manifest is a file on our own disk
and its durability is nothing to do with the server. What the *next run* does with it is: the
comparison reads the remote size and modification time out of a `READDIR` listing, and what a
server volunteers there is exactly the thing three implementations disagree about. A mirror that
kept a perfect record and then found every entry `UNDECIDABLE` would re-send the tree anyway, so
the row asserts the skip and not just the file.

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

from gantry_sftp.session import SyncManifest
from gantry_sftp.sync import open_session, open_ssh_transport

FILES = 5
KILL_AFTER_RECORDS = 2

KILLED_MIRROR = """
import json, os, signal, sys
from pathlib import Path
from gantry_sftp.session import SyncManifest
from gantry_sftp.sync import open_ssh_transport, open_session

plan = json.loads(sys.argv[1])
source, manifest = Path(sys.argv[2]), Path(sys.argv[3])
target, kill_after = sys.argv[4], int(sys.argv[5])
host = plan.pop("host")

def die(transferred, total):
    # Read from disk rather than counted in memory: what this row is about is what a *separate
    # process* can see, so the trigger has to be the same evidence the next run will read.
    if len(SyncManifest.load(manifest).entries) >= kill_after:
        os.kill(os.getpid(), signal.SIGKILL)

with open_ssh_transport(host, **plan) as t, open_session(t) as s:
    s.sync_tree(source, target.encode(), manifest=manifest, concurrency=1, progress=die)
print("child finished without dying", file=sys.stderr)
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
    """A connect value the subprocess can be handed as JSON."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    return value


def test_a_mirror_killed_mid_tree_keeps_what_it_sent(server: MatrixServer, tmp_path: Path) -> None:
    """The card. A killed mirror used to keep nothing and re-send the whole tree next run."""
    source = tmp_path / "outgoing"
    source.mkdir()
    for index in range(FILES):
        _ = (source / f"file-{index}.csv").write_bytes(f"id,total\n{index},{index * 10}\n".encode())
    destination = server.root / "mirror"
    manifest = tmp_path / "state.json"
    script = tmp_path / "killed_mirror.py"
    _ = script.write_text(KILLED_MIRROR, encoding="utf-8")

    plan = {key: _jsonable(value) for key, value in server.connect.items()}
    killed = subprocess.run(
        [
            sys.executable,
            str(script),
            json.dumps(plan),
            str(source),
            str(manifest),
            str(destination),
            str(KILL_AFTER_RECORDS),
        ],
        capture_output=True,
        timeout=180,
        check=False,
    )

    assert killed.returncode == -9, killed.stderr.decode("utf-8", "replace")
    kept = SyncManifest.load(manifest).entries
    assert len(kept) == KILL_AFTER_RECORDS, (
        f"{server.name} left {len(kept)} records; the run was killed once it had written "
        f"{KILL_AFTER_RECORDS}, and nothing after that point should have reached the file"
    )
    # Not compacted: the run never got to its `save`, so what survived is the appended log.
    assert len(manifest.read_bytes().splitlines()) == KILL_AFTER_RECORDS

    with connected(server) as transport, open_session(transport) as sftp:
        result = sftp.sync_tree(source, str(destination).encode(), manifest=manifest)

    assert result.skipped == KILL_AFTER_RECORDS, (
        f"{server.name}: the record survived but the comparison did not use it "
        f"({result.transferred} sent, {result.skipped} skipped, {result.undecidable} unproven)"
    )
    assert result.transferred + result.undecidable == FILES - KILL_AFTER_RECORDS
    for index in range(FILES):
        name = f"file-{index}.csv"
        assert (destination / name).read_bytes() == (source / name).read_bytes()
    # Compacted by the run that finished, so the file holds one line per file and no duplicates.
    assert len(manifest.read_bytes().splitlines()) == FILES
    assert len(SyncManifest.load(manifest).entries) == FILES

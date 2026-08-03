"""The scheduled ingest loop, and the two ways it loses data without telling you.

    python examples/incremental_ingest.py                  # a local sftp-server, no network
    python examples/incremental_ingest.py user@host /dir   # a real server over ssh

The job shape most SFTP deployments actually run:

    list a drop directory -> take what is newer than a stored watermark and matches a
    pattern -> transfer it -> publish it -> advance the watermark

The library has every piece. This is the assembly, and the two warnings that go with it --
because both traps below are one line of caller code away from silent data loss, and silent
data loss on an ingest is found weeks later by a missing row.

**Trap 1: v3's modification time is whole seconds, so `mtime > watermark` loses files.**
Not "is imprecise" -- loses them, permanently, on every subsequent run, while the job reports
success. A file written 0.9 s into the same second as your stored watermark reports the *same*
timestamp as the file that set it, so `>` excludes it today and every day after. Demonstrated
below against a real `sftp-server` with mtimes set explicitly, so it is not a race that happens
to reproduce.

The fix is not `>=` on its own, because that re-takes the file that set the watermark every
run. It is `>=` **plus a record of what was already taken**, which is what this example does.
The alternative -- hold the watermark one second behind and accept re-taking a second's worth
each run -- is also correct and is cheaper to store; it is named here so the choice is visible
rather than made for you.

**Trap 2: what the watermark advances *to*.** Advancing it to "now" silently drops anything
that lands while the run is in progress, permanently, because the next run starts after it.
Advancing to the largest modification time actually *seen* cannot do that. The difference is
one line and shows up only under load, which is the worst combination.

**And one thing worth seeing in the same place: per-endpoint `ssh_config`.** Full config
fidelity is the largest thing this library gets for free by spawning `ssh`, and the
multi-endpoint case is the one anybody with more than a handful of trading partners has. A
legacy partner needing an old `HostKeyAlgorithms` is a `Match host` block, not a global
weakening applied to every connection you make. The last section prints such a config and shows
`ssh -G` resolving two endpoints out of it differently.

None of this is an API. `sftp.since(path, when)` would be this library deciding retention,
dedupe and clock-trust policy on your behalf, and those three are exactly what differs between
one deployment and the next. The pieces stay pieces; what was missing was the worked assembly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import anyio

from gantry_sftp.session import DirEntry, Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

# A fixed instant, so the printed output is the same on every run and the same-second
# collision is a property of the protocol rather than of how fast this machine is.
#
# Deliberately in the **past**. An earlier draft used a future timestamp and trap 2 printed
# backwards: "now" came out *earlier* than the newest file, so advancing to it would have
# moved the watermark backwards rather than skipping ahead, which is the opposite of the
# lesson. A demonstration has to be able to fail the way it describes.
BASE = 1_700_000_000  # 2023-11-14T22:13:20Z


def populate(directory: Path) -> None:
    """A drop directory with a same-second pair in it, mtimes set rather than raced."""
    plan = {
        # Already ingested by an earlier run.
        "orders-001.csv": BASE - 10 + 0.0,
        # The run that stored the watermark saw this one, and the watermark is its mtime.
        "orders-002.csv": BASE + 0.10,
        # Landed 0.8 s later. A *different* file, the same whole second -- this is trap 1.
        "orders-003.csv": BASE + 0.90,
        # Comfortably later, and picked up by any implementation.
        "orders-004.csv": BASE + 5.0,
        # Matches no pattern: an ingest takes what it recognises, not what is there.
        "README.txt": BASE + 5.0,
    }
    for name, when in plan.items():
        path = directory / name
        _ = path.write_bytes(f"id,total\n1,{name}\n".encode())
        os.utime(path, (when, when))


@asynccontextmanager
async def connect(destination: str | None, workdir: Path) -> AsyncGenerator[Session]:
    """A session, either to a local `sftp-server` or over `ssh` to a real host."""
    if destination is None:
        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp
    else:
        user, _, host = destination.rpartition("@")
        async with (
            open_ssh_transport(host, user=user or None) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp


# --- the watermark, which is the whole state a scheduled job carries -------------------------


class Watermark:
    """A timestamp plus the names already taken *at* that timestamp.

    The names are the part people leave out, and leaving them out is what forces the choice
    between losing a file (`>`) and re-taking one every run (`>=`). Only the names sharing the
    watermark's exact second need keeping, so this does not grow with the directory -- it grows
    with how many files landed in the busiest single second, and it is reset every time the
    watermark advances.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self.taken_at: datetime | None = None
        self.names: set[str] = set()
        if path.exists():
            stored = json.loads(path.read_text())
            self.taken_at = datetime.fromisoformat(stored["taken_at"])
            self.names = set(stored["names"])

    def wants(self, entry: DirEntry) -> bool:
        """Whether this entry is new work.

        ``>=`` rather than ``>``, because a file sharing the watermark's second is *not* older
        than it -- the protocol simply cannot say which came first. The name check is what
        stops that admitting the same file twice.
        """
        if entry.modified is None:
            # The server sent no ACMODTIME. Legal in v3. Treating it as 1970 would make the
            # file look ancient and it would never be ingested; treating it as new re-takes it
            # every run. Neither is right for everyone, so this example says so and takes it.
            return True
        if self.taken_at is None:
            return True
        if entry.modified > self.taken_at:
            return True
        return entry.modified == self.taken_at and entry.name not in self.names

    def advance(self, taken: list[DirEntry]) -> None:
        """Move to the largest modification time actually seen, never to "now".

        "Now" is later than the newest file this run observed, so anything that lands between
        the listing and the write is skipped by the *next* run as well -- gone, with no error
        anywhere. The largest mtime seen cannot skip a file, because a file the next run has
        not seen yet is by definition not in this maximum.
        """
        stamps = [entry.modified for entry in taken if entry.modified is not None]
        if not stamps:
            return
        newest = max(stamps)
        if self.taken_at is not None and newest < self.taken_at:
            return
        if newest != self.taken_at:
            self.names = set()
            self.taken_at = newest
        self.names.update(entry.name for entry in taken if entry.modified == newest)
        self._path.write_text(
            json.dumps({"taken_at": self.taken_at.isoformat(), "names": sorted(self.names)})
        )


async def sweep(sftp: Session, remote_dir: str, watermark: Watermark, into: Path) -> list[str]:
    """One run of the loop. Returns the names taken."""
    taken: list[DirEntry] = []
    for entry in sorted(await sftp.listdir(remote_dir), key=lambda item: item.name):
        # `entry.modified` comes free with the listing -- v3 sends attributes with every
        # READDIR entry. `sftp.getmtime(path)` answers the same question for a path you were
        # handed rather than listed, and costs a round trip per file.
        if not entry.is_file or not entry.name.endswith(".csv"):
            continue
        if not watermark.wants(entry):
            continue
        _ = await sftp.get(f"{remote_dir.rstrip('/')}/{entry.name}", into / entry.name)
        taken.append(entry)
    watermark.advance(taken)
    return [entry.name for entry in taken]


def show_per_endpoint_config(scratch: Path) -> None:
    """Two endpoints, one config file, different requirements -- and no global weakening."""
    config = scratch / "ssh_config"
    _ = config.write_text(
        "Host sftp.partner-a.example\n"
        "  User ingest\n"
        "  IdentityFile ~/.ssh/partner_a_ed25519\n"
        "\n"
        "# A legacy appliance that still needs an old host-key type. Scoped to this one host,\n"
        "# rather than weakening HostKeyAlgorithms for every connection this process makes.\n"
        "Match host sftp.partner-b.example\n"
        "  HostKeyAlgorithms +ssh-rsa\n"
        "  User legacy-drop\n"
    )
    print("\nper-endpoint ssh_config -- what `ssh` resolves for each host:")
    for host in ("sftp.partner-a.example", "sftp.partner-b.example"):
        resolved = subprocess.run(
            ["ssh", "-F", str(config), "-G", "--", host],
            capture_output=True,
            text=True,
            check=False,
        )
        wanted = {"user", "hostkeyalgorithms", "identityfile"}
        fields = {}
        for line in resolved.stdout.splitlines():
            keyword, _, value = line.partition(" ")
            if keyword.lower() in wanted and keyword.lower() not in fields:
                fields[keyword.lower()] = value
        print(f"    {host}")
        print(f"        user               {fields.get('user', '(default)')}")
        print(f"        identityfile       {fields.get('identityfile', '(default)')}")
        # Whether the legacy type is *accepted*, not the first 60 characters of the list --
        # `+ssh-rsa` appends, so the difference between these two hosts is at the end, and
        # truncating would print two identical-looking lines under a claim that they differ.
        algorithms = fields.get("hostkeyalgorithms", "").split(",")
        print(f"        accepts ssh-rsa    {'ssh-rsa' in algorithms}")
    print("    -- the legacy requirement is on one host, and this library passed no -o at all")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/incremental_ingest.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        drop = workdir / "drop"
        drop.mkdir()
        landing = workdir / "landing"
        landing.mkdir()
        if destination is None:
            populate(drop)
        target = remote_dir if remote_dir is not None else str(drop)

        watermark = Watermark(workdir / "watermark.json")

        async with connect(destination, workdir) as sftp:
            print("run 1 -- nothing stored yet, so everything matching is new:")
            first = await sweep(sftp, target, watermark, landing)
            for name in first:
                print(f"    took {name}")
            print(f"    watermark now {watermark.taken_at}  names={sorted(watermark.names)}")

            print("\nrun 2 -- nothing has changed, so nothing is taken:")
            second = await sweep(sftp, target, watermark, landing)
            print(f"    took {second or 'nothing'}")

        if destination is not None:
            return

        # --- the trap, shown rather than described -----------------------------------------
        listed = {}
        async with connect(None, workdir) as sftp:
            for entry in await sftp.listdir(str(drop)):
                if entry.modified is not None:
                    listed[entry.name] = entry.modified

        pair = ("orders-002.csv", "orders-003.csv")
        print("\ntrap 1 -- two different files, one second, as the protocol reports them:")
        for name in pair:
            print(
                f"    {name:<16} local {(drop / name).stat().st_mtime:<16} "
                f"over SFTP {listed[name].isoformat()}"
            )
        print(f"    equal over SFTP: {listed[pair[0]] == listed[pair[1]]}")
        print(
            f"    a watermark of {listed[pair[0]].isoformat()} with '>' would exclude "
            f"{pair[1]} forever;\n"
            f"    with '>=' and no name record it would re-take {pair[0]} every run."
        )
        assert listed[pair[0]] == listed[pair[1]], "the same-second pair should collide"
        assert set(pair) <= set(first), "run 1 must take both halves of the pair"

        print("\ntrap 2 -- what the watermark advanced to:")
        newest = max(listed[name] for name in first)
        print(f"    largest mtime actually seen  {newest.isoformat()}   <- what this uses")
        print(f"    'now' would have been        {datetime.now(UTC).isoformat()}")
        print("    ...and everything landing between those two would never be ingested")
        assert watermark.taken_at == newest, "the watermark must not advance past what it saw"

        show_per_endpoint_config(workdir)

    print(
        "\nThe pattern is yours to own: retention, dedupe and clock-trust policy differ between\n"
        "deployments, so this library ships the pieces and this example, not a `since()` method."
    )


if __name__ == "__main__":
    anyio.run(main)

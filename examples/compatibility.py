"""Does this library work against *your* server, and where does it not.

    python examples/compatibility.py                  # local sftp-server, no network
    python examples/compatibility.py user@host        # a real server over ssh

The command is ``python -m gantry_sftp doctor <host>``, which runs the read-only battery by
default and ``--probe-writes DIR`` for the rest. This example is the other half: **the report is
data before it is text**, so a deployment check can assert on it rather than scrape it, and a
maintainer can be sent an object rather than a paragraph.

**Why it exists at all.** The endpoints this library is for -- MOVEit, GoAnywhere, Cleo,
Sterling -- belong to somebody's employer and sit behind a VPN, so no maintainer can start one.
``live-tests/matrix.py`` covers the three servers that fit in a test suite and the interesting
ones are permanently outside it. The evidence has to come from the person who can reach the
server, which means it has to be producible by them.

**The one lesson worth copying out of here** is the reason every extension probe checks the
*result* instead of the status. ``lsetstat@openssh.com`` is advertised by OpenSSH's server and
by asyncssh's; on Linux it works on neither, and the two fail differently -- OpenSSH refuses,
asyncssh answers ``OK`` and moves nothing. A report that believed the status would call the
second one working, which is the confident-and-wrong answer this whole feature exists to avoid.

This example runs **both** batteries, because it owns the directory it is pointed at. Against a
real server that directory is a scratch directory under your home, and every file it creates is
named ``gantry-probe-*`` and removed before it exits.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from gantry_sftp.compatibility import CompatibilityReport, Verdict, compatibility_report
from gantry_sftp.sync import SyncSession, connect, open_local_server_transport, open_session

TYPICAL_HANDLE = b"\x00\x00\x00\x00"
"""What the request size is asked for. OpenSSH issues four-byte handles; nothing promises that.

A handle travels in every READ and WRITE header, so it comes out of the payload budget and the
answer is genuinely per-handle. `doctor` names the length it assumed for the same reason.
"""


def render(report: CompatibilityReport) -> None:
    """Print the report the way a person reads it: fact, verdict, then the round trips."""
    for finding in report.findings:
        print(f"\n[{finding.verdict.value:>12}] {finding.fact}")
        print(f"               {finding.answer}")
        for line in finding.evidence:
            print(f"                 . {line}")

    print("\nnot determined -- what this run did not ask, and why:")
    for limit in report.undetermined:
        print(f"  - {limit}")


def summarise(report: CompatibilityReport) -> None:
    """The same report read as data, which is what a deployment check would do."""
    print("\n--- as data ---")
    answered = [f for f in report.findings if f.verdict is not Verdict.UNDETERMINED]
    print(f"probed:          {len(report.findings)}")
    print(f"answered:        {len(answered)}")
    print(f"complete:        {report.complete}")
    print(f"wrote into:      {report.wrote_into}")
    print(f"left behind:     {list(report.left_behind) or 'nothing'}")

    # Every fact that came back `no`, named rather than counted. **A `no` is not a fault and
    # this heading is careful not to say it is**: "this server does not fold case" is the
    # POSIX answer and the desirable one, while "lsetstat does not work" is a limitation. The
    # report deliberately does not rank them -- which of these matters depends on what you are
    # about to do with the server, and a tool that decided that for you would be guessing.
    negative = [f.fact for f in report.findings if f.verdict is Verdict.NO]
    print(f"\nfacts that came back `no` ({len(negative)}) -- answers, not faults:")
    for fact in negative:
        print(f"  - {fact}")

    # `left_behind` empty is a claim, so it is worth asserting rather than printing: every name
    # is registered before the request that could create it, so a create whose answer was lost
    # is still cleaned up -- and anything that could not be removed is named with its reason.
    assert not report.left_behind, report.left_behind


def run(sftp: SyncSession, scratch: bytes) -> None:
    report = compatibility_report(
        sftp,
        request_bytes=sftp.sizes_for(TYPICAL_HANDLE).write_length,
        write_directory=scratch,
    )
    render(report)
    summarise(report)


def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None

    if destination is None:
        with tempfile.TemporaryDirectory(prefix="gantry-example-") as workdir:
            probe_dir = Path(workdir) / "scratch"
            probe_dir.mkdir()
            with (
                open_local_server_transport(cwd=Path(workdir)) as transport,
                open_session(transport) as sftp,
            ):
                run(sftp, str(probe_dir).encode())
            # The battery said it cleaned up; this is the filesystem agreeing. Against a local
            # server that check is free, and it is the one an operator most wants made.
            print(f"\nscratch directory afterwards: {sorted(p.name for p in probe_dir.iterdir())}")
        return

    user, _, host = destination.rpartition("@")
    with connect(host, user=user or None) as sftp:
        # Asked rather than assumed: a nominated directory is the whole safety property, and
        # picking one for the caller is exactly what this feature refuses to do. Here the
        # example nominates its own, under wherever the session starts.
        home = sftp.realpath(b".")
        scratch = home.rstrip(b"/") + b"/gantry-compatibility-example"
        sftp.mkdir(scratch, exist_ok=True)
        try:
            run(sftp, scratch)
        finally:
            sftp.rmdir(scratch)


if __name__ == "__main__":
    main()

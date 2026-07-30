"""Ask the library what this machine can do -- as a command, and as data.

    python examples/doctor.py                   # the report, and what a health check reads
    python examples/doctor.py user@host         # and what that server negotiated

The command is `python -m gantry_sftp doctor [host]`, and it is the thing to run first when
something does not work. This example is the other half: **the report is data before it is
text**, so a deployment check does not have to scrape output. `local_diagnosis()` reaches no
network and answers the question a container image actually has -- is `ssh` here, can this
platform transfer, what is set in the environment -- and `server_diagnosis()` performs the same
handshake a transfer performs and reports what came back.

Why this exists at all: paramiko and asyncssh *are* the SSH environment, so they have nothing to
introspect. This library spawns OpenSSH, which is a deployment dependency -- and the price of
that dependency is also the only reason a report like this can be produced.

Two things worth copying out of here. The exit codes are distinct on purpose, so a `RUN` line in
a Dockerfile can tell "no ssh binary" from "host unreachable" without a human reading the output.
And the report is safe to paste into a bug report: only the variables that steer `ssh` are read,
and anything credential-shaped is masked before it can be rendered.
"""

from __future__ import annotations

import sys

from gantry_sftp.doctor import (
    Exit,
    local_diagnosis,
    overall_status,
    render_text,
    server_diagnosis,
)


def health_check() -> bool:
    """What a container's start-up probe would actually ask, using the report as data.

    No parsing, no subprocess, no scraping: the same values the command prints are fields.
    """
    report = local_diagnosis()
    return report.ssh_version is not None and report.transfers_supported


def main() -> int:
    destination = sys.argv[1] if len(sys.argv) > 1 else None

    local = local_diagnosis()
    server = None
    if destination is not None:
        user, _, host = destination.rpartition("@")
        server = server_diagnosis(host, user=user or None)

    print(render_text(local, server))

    # The same report, read as data rather than as text.
    print()
    print(f"usable for transfers: {health_check()}")
    print(f"ssh reported as:      {local.ssh_version or 'absent -- ' + str(local.ssh_error)}")
    print(f"steering variables:   {sorted(local.environment) or 'none set'}")
    if server is not None and server.reached:
        print(f"extensions used:      {list(server.implemented)}")
        print(f"extensions ignored:   {list(server.unimplemented)}")

    status = overall_status(local, server)
    print(f"\nexit status would be {int(status)} ({status.name})")

    # An example must exit clean to be a runnable example, so a local finding is reported
    # rather than propagated -- the *command* is what returns the status, and that is the
    # difference worth showing rather than hiding.
    if status is not Exit.OK:
        print("(the command would exit non-zero here; this example does not)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

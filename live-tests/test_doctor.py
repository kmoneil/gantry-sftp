"""The doctor's server half, against a real `sshd` reached through a real `ssh`.

**D-90.** `tests/test_doctor.py` covers everything answerable without a network. This is the
other half, and it belongs here rather than there for the reason DESIGN 4.3 gives: the value of
this command is that it reports a *negotiation*, and a negotiation with a fake confirms only what
its author already believed.

What it pins is the card's claim about the feature — that this is a better answer to "why did
`posix_rename` not happen" than any log line, because it is the same handshake a transfer
performs. So the assertions are that the extension table came from the server, that the limits
are the server's rather than our defaults, and that the request size is the one the scheduler
derived from them.

It is also the first thing in this repository to use `gantry_sftp.sync` for real work rather than
to test the facade. A blocking call, from a synchronous test, over a portal, against a live
server, is D-84's claim exercised end to end.

**The environment is scrubbed here rather than passed in**, and that is a consequence of a
decision on the shipped side: `server_diagnosis` takes no `env=`, because the process environment
is part of what is being diagnosed and a flag that replaced it would let the report state which
steering variables are set while connecting with different ones. So the suite scrubs its own
process, which is what a `-F /dev/null` plus `IdentitiesOnly` already backstops.
"""

from __future__ import annotations

import json
import os

import pytest
from sshd import STEERING, SSHServer

from gantry_sftp.codec import IMPLEMENTED_EXTENSIONS
from gantry_sftp.doctor import (
    Exit,
    ServerDiagnosis,
    local_diagnosis,
    overall_status,
    render_json,
    render_text,
    server_diagnosis,
)

# Deliberately no `pytestmark = pytest.mark.anyio`: the command is blocking, and driving it from
# an event loop would exercise something the shipped code never does.


@pytest.fixture
def scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every variable that steers `ssh` from this process, for this test.

    The same list `sshd.scrubbed_ssh_env` filters on, applied to `os.environ` instead of to a
    copy — because the copy is what a caller passes as `env=`, and this command deliberately
    has none. Without this, a developer's agent could authenticate a connection the test
    believes it made with `-i`.
    """
    for name in STEERING:
        monkeypatch.delenv(name, raising=False)
    assert [name for name in STEERING if name in os.environ] == []


def diagnose(server: SSHServer, **overrides: object) -> ServerDiagnosis:
    """The server half against the suite's `sshd`, with the connection arguments it pins."""
    options = server.connect_options()
    options.setdefault("IdentitiesOnly", "yes")
    arguments: dict[str, object] = {
        "port": server.port,
        "identity_file": str(server.identity_file),
        "config_file": os.devnull,
        "options": options,
    }
    arguments.update(overrides)
    return server_diagnosis("127.0.0.1", **arguments)  # type: ignore[arg-type]


def test_the_report_is_the_negotiation_a_transfer_would_have_made(
    ssh_server: SSHServer, scrubbed: None
):
    report = diagnose(ssh_server)

    assert report.reached is True, report.error
    assert report.error is None
    assert report.protocol_version == 3
    assert report.server == "openssh"
    assert report.exit_code is Exit.OK


def test_the_extension_table_is_the_servers_and_the_used_column_is_ours(
    ssh_server: SSHServer, scrubbed: None
):
    """The card's headline question, answered as data.

    `implemented` has to be the intersection of what this server advertised and what this
    library can send, so it is asserted as a partition rather than by listing names: no
    advertised name may fall out of both columns, and none may appear in both.
    """
    report = diagnose(ssh_server)

    advertised = set(report.extensions)
    assert advertised, "the reference server advertised nothing, which would break the premise"
    assert "posix-rename@openssh.com" in advertised

    used = set(report.implemented)
    ignored = set(report.unimplemented)
    assert used | ignored == advertised
    assert used & ignored == set()
    assert used <= set(IMPLEMENTED_EXTENSIONS)
    # `check-file` is paramiko's spelling and OpenSSH does not advertise it, so it is the one
    # implemented name that has to land in `absent` here.
    assert "check-file" in set(report.absent)


def test_the_limits_reported_are_the_servers_rather_than_our_defaults(
    ssh_server: SSHServer, scrubbed: None
):
    """`limits@openssh.com` is advertised here, so a `None` would mean we failed to read it.

    The numbers vary by OpenSSH build, so what is asserted is the relationship the protocol
    guarantees — a read fits inside a packet — rather than a constant that would pin this test
    to one server version.
    """
    report = diagnose(ssh_server)

    limits = report.limits
    assert limits is not None, "limits@openssh.com is advertised by this server and was not read"
    assert limits["max_read_length"] is not None
    assert limits["max_packet_length"] is not None
    assert limits["max_read_length"] < limits["max_packet_length"]

    assert report.read_size is not None
    assert report.read_size <= limits["max_read_length"]


def test_the_start_directory_is_canonical(ssh_server: SSHServer, scrubbed: None):
    """A `REALPATH` of `.` — the first thing an operator wants to know about a new host."""
    report = diagnose(ssh_server)

    assert report.start_directory is not None
    assert report.start_directory.startswith("/")


def test_the_diagnosis_leaves_nothing_behind(ssh_server: SSHServer, scrubbed: None):
    """`reaped` counts handles nobody claimed, and a command reporting on cleanliness must be it."""
    report = diagnose(ssh_server)

    assert report.reaped == 0


def test_the_rendered_report_names_the_server_and_survives_json(
    ssh_server: SSHServer, scrubbed: None
):
    """Both renderers over a real report, because a field that formats in only one is a bug."""
    local = local_diagnosis()
    report = diagnose(ssh_server)

    text = render_text(local, report)
    assert "server 127.0.0.1" in text
    assert "identified as           openssh" in text
    assert "uses                  posix-rename@openssh.com" in text

    payload = json.loads(render_json(local, report))
    assert payload["server"]["reached"] is True
    assert payload["status"] == "OK"
    assert overall_status(local, report) is Exit.OK


def test_a_refused_connection_is_reported_rather_than_raised(ssh_server: SSHServer, scrubbed: None):
    """The case the command exists for: it comes back with a report, not a traceback.

    A port nothing is listening on, on a host that is definitely there, so the failure is a
    refusal rather than a timeout — and OpenSSH's stderr, which is the actual diagnosis, has to
    survive into the report and then into the renderer. That stderr reaching the operator is
    the headline of this library's error handling; here it has to reach a *layout* as well.
    """
    report = diagnose(ssh_server, port=ssh_server.port + 1)

    assert report.reached is False
    assert report.error is not None
    assert "ConnectError" in report.error
    assert report.exit_code is Exit.UNREACHABLE

    rendered = render_text(local_diagnosis(), report)
    assert "  NOT REACHED\n" in rendered
    failure_block = rendered.split("  NOT REACHED\n")[1].split("\nexit ")[0]
    assert all(line.startswith("    ") or not line for line in failure_block.splitlines())

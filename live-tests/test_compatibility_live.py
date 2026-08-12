"""The compatibility battery against three real servers, which is the fixture it needs.

**D-165.** The report exists because the endpoints this library is for cannot be started by
anybody who could write a test for them, so what can be started has to carry the proof. Three
implementations that disagree with each other is exactly right for that: a battery written
against OpenSSH alone measures OpenSSH and calls it SFTP.

The table below is the payoff and it is a *measurement*, so a failure here is usually a finding
rather than a bug — a server changed, or a probe stopped working. Both are worth a person
looking. What it pins is the card's central claim, in a form somebody can check: **advertised
and working are different questions**, and `lsetstat@openssh.com` is the row that proves it —
advertised by two of the three, working on neither, and failing differently on each.

**Two rows measure the harness rather than the implementation, and both stay.** `matrix.py`
implements paramiko's filesystem half itself, because paramiko ships the interface and leaves
the implementation to the caller: its `rename` replaces silently and its `chattr` answers `OK`
to a field it discards, and both facts are recorded there as the handler's choices. They are
not evidence about paramiko. They are the best evidence in this file about *the battery*: a
server that accepts a `SETSTAT` and drops it is the failure the matrix's own docstring calls
worse than `OP_UNSUPPORTED`, no test of the client can see it, and the timestamp probe catches
it here.

Nothing here is `pytest.mark.anyio`. The battery is blocking, driven through `gantry_sftp.sync`
over a real `ssh` connection, which is what `doctor` does — running it from an event loop would
exercise something the shipped path never does.
"""

from __future__ import annotations

import json
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from matrix import SERVER_NAMES, MatrixServer, running_server, unavailable_reason

from gantry_sftp.compatibility import (
    PROBE_PREFIX,
    CompatibilityReport,
    ProbeLimit,
    Verdict,
    compatibility_report,
)
from gantry_sftp.doctor import local_diagnosis, render_json, render_text, server_diagnosis
from gantry_sftp.sync import open_session, open_ssh_transport
from local_filesystem import FILESYSTEM_FOLDS_CASE, SERVER_CAN_CHMOD_A_SYMLINK

TYPICAL_HANDLE = b"\x00\x00\x00\x00"

REALPATH_MISSING = "REALPATH canonicalises a path that does not exist"
ROOT_IS_SLASH = "the root of this server's namespace is /"
MESSAGES_INFORMATIVE = "a refusal carries a message that says more than its status code"
LIMITS_USABLE = "limits@openssh.com answers with a usable maximum"
CASE_FOLDS = "this server folds case in names"
RENAME_REPLACES = "RENAME replaces an existing target"
TIMES_SURVIVE = "a file's timestamps survive being set"
POSIX_RENAME = "posix-rename@openssh.com actually renames"
FSYNC = "fsync@openssh.com actually flushes"
LSETSTAT = "lsetstat@openssh.com actually changes a symlink's own mode"
LARGEST_REQUEST = "a request as large as this session would send is accepted"
CHECK_FILE = "check-file actually hashes the bytes the server has"

NOT_ASKED = None
"""What a fact is worth when the extension it is about was never advertised.

Distinct from every verdict on purpose. "This server did not offer the extension" and "this
server offered it and it does not work" are different answers, and the report keeps them apart
by not producing a finding at all for the first.
"""

FOLDS = Verdict.YES if FILESYSTEM_FOLDS_CASE else Verdict.NO
LCHMOD = Verdict.YES if SERVER_CAN_CHMOD_A_SYMLINK else Verdict.NO
"""The two facts below that belong to the *machine* rather than to the server implementation.

**This distinction cost two red macOS lanes to learn, and the audit is written down here so the
next reader does not redo it.** Every server in this matrix is served from the local filesystem
by a process on this kernel, so a fact the battery reports is about the server *only* when the
server is what decides it. Of the twelve:

* ``CASE_FOLDS`` is the **filesystem's** -- APFS folds, ext4 does not.
* ``LSETSTAT`` is the **kernel's** -- macOS has ``lchmod``, Linux does not, so OpenSSH's
  permissions branch succeeds on one and answers ``ENOTSUP`` on the other.
* Every other row is decided in the server's own code -- how it canonicalises, what its message
  table says, whether it refuses a ``RENAME`` onto an existing name, which extensions it
  implements -- and does not move with the host.

A row that turns out to be in the wrong group shows up as one red lane and gains a line here
with its reason. That is the process; guessing which rows were portable is what produced the two.
"""

# Measured 2026-08-12 against OpenSSH 10.0p2, asyncssh 2.24.0 and paramiko's SFTPServer, on Linux
# except where a value is derived above. A change here is a finding first and a broken test second.
MEASURED: dict[str, dict[str, Verdict | None]] = {
    "openssh": {
        REALPATH_MISSING: Verdict.YES,
        ROOT_IS_SLASH: Verdict.YES,
        # 'No such file' and 'Bad message' -- each is its own status code spelled out.
        MESSAGES_INFORMATIVE: Verdict.NO,
        LIMITS_USABLE: Verdict.YES,
        CASE_FOLDS: FOLDS,
        RENAME_REPLACES: Verdict.NO,
        TIMES_SURVIVE: Verdict.YES,
        POSIX_RENAME: Verdict.YES,
        FSYNC: Verdict.YES,
        LSETSTAT: LCHMOD,
        LARGEST_REQUEST: Verdict.YES,
        CHECK_FILE: NOT_ASKED,
    },
    "asyncssh": {
        REALPATH_MISSING: Verdict.YES,
        ROOT_IS_SLASH: Verdict.YES,
        # 'File already exists' under FAILURE says what the code cannot, and the fingerprint
        # already recorded `informative_messages=True` for this server.
        MESSAGES_INFORMATIVE: Verdict.YES,
        LIMITS_USABLE: Verdict.YES,
        CASE_FOLDS: FOLDS,
        RENAME_REPLACES: Verdict.NO,
        TIMES_SURVIVE: Verdict.YES,
        POSIX_RENAME: Verdict.YES,
        FSYNC: Verdict.YES,
        # Advertised, answers OK, and moves nothing -- on the same kernel where OpenSSH
        # refuses. Believing the status would have reported the one server that silently
        # discards the request as the one where the extension works. Pinned rather than
        # derived: asyncssh needs the `bench` group, which only the ubuntu-only
        # `server-matrix` job installs, so this row never runs on a kernel with lchmod.
        LSETSTAT: Verdict.NO,
        LARGEST_REQUEST: Verdict.YES,
        CHECK_FILE: NOT_ASKED,
    },
    "paramiko": {
        REALPATH_MISSING: Verdict.YES,
        ROOT_IS_SLASH: Verdict.YES,
        # 'No such file' and 'Operation unsupported', both of which are their codes.
        MESSAGES_INFORMATIVE: Verdict.NO,
        LIMITS_USABLE: NOT_ASKED,
        CASE_FOLDS: FOLDS,
        # `_ParamikoHandler.rename` -- the harness's choice, recorded as such in matrix.py.
        RENAME_REPLACES: Verdict.YES,
        # `_ParamikoHandler.chattr` answers OK to an ACMODTIME it discards. See this module's
        # docstring: it is the harness's behaviour and the battery's best demonstration.
        TIMES_SURVIVE: Verdict.NO,
        POSIX_RENAME: NOT_ASKED,
        FSYNC: NOT_ASKED,
        LSETSTAT: NOT_ASKED,
        LARGEST_REQUEST: Verdict.YES,
        CHECK_FILE: Verdict.YES,
    },
}

FACTS = tuple(MEASURED["openssh"])


@pytest.fixture(params=SERVER_NAMES)
def server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MatrixServer]:
    """One running server per implementation, skipping with a reason when it cannot start."""
    name = str(request.param)
    reason = unavailable_reason(name)
    if reason is not None:
        pytest.skip(reason)
    with running_server(name, tmp_path) as running:
        yield running


@contextmanager
def probed(server: MatrixServer, scratch: Path | None) -> Generator[CompatibilityReport]:
    """Run the battery against ``server`` and yield the report, connection already closed.

    The write directory is a real path on the machine running the test, so a caller can list
    it afterwards and assert about what is there rather than about what the report claims.
    """
    connect = dict(server.connect)
    host = str(connect.pop("host"))
    with open_ssh_transport(host, **connect) as transport, open_session(transport) as sftp:
        yield compatibility_report(
            sftp,
            request_bytes=sftp.sizes_for(TYPICAL_HANDLE).write_length,
            write_directory=None if scratch is None else str(scratch).encode(),
            run_id="live",
        )


# --- what holds on every implementation --------------------------------------------------------


def test_every_server_answers_every_question_the_battery_asks(server: MatrixServer, tmp_path: Path):
    """`complete` on all three, which is the claim that no probe has quietly stopped working.

    An undetermined finding against a server this suite starts is a probe that broke, not a
    server that is unusual -- there is nothing unusual about any of these three.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    with probed(server, scratch) as report:
        unanswered = [f.fact for f in report.findings if f.verdict is Verdict.UNDETERMINED]

    assert unanswered == [], f"{server.name}: {unanswered}"
    assert report.complete is True


def test_every_finding_carries_the_exchange_that_produced_it(server: MatrixServer, tmp_path: Path):
    """Constraint three of the card, against a real server rather than against a stub."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    with probed(server, scratch) as report:
        pass

    for finding in report.findings:
        assert finding.evidence, f"{server.name}: {finding.fact} has a verdict and no workings"
        assert finding.answer != finding.fact


def test_the_read_only_battery_changes_nothing_on_disk(server: MatrixServer, tmp_path: Path):
    """The safety property, measured on the filesystem the server is actually writing to.

    Two instruments, because neither alone is enough. A control directory is compared down to
    the modification times, which catches a probe that rewrites something already there; and
    the whole of `server.root` is swept for probe names, which catches one that writes
    somewhere this test did not think to look.

    **The control directory is not `server.root` itself**, and that is not a convenience: the
    OpenSSH harness writes `sshd.log` there while the connection is open, so a whole-tree mtime
    comparison fails on the server's own logging and says nothing about the battery.
    """
    control = server.root / "control"
    control.mkdir()
    (control / "existing.csv").write_bytes(b"id\n1\n")
    before = {p: p.stat().st_mtime_ns for p in sorted(control.rglob("*"))}

    with probed(server, None) as report:
        pass

    assert {p: p.stat().st_mtime_ns for p in sorted(control.rglob("*"))} == before
    assert list(server.root.rglob(f"{PROBE_PREFIX}*")) == []
    assert report.wrote_into is None
    assert report.left_behind == ()


def test_the_write_battery_removes_everything_it_created(server: MatrixServer, tmp_path: Path):
    """Asserted by listing the directory, not by counting the removals the battery made."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "not-ours.csv").write_bytes(b"id\n1\n")

    with probed(server, scratch) as report:
        pass

    assert sorted(p.name for p in scratch.iterdir()) == ["not-ours.csv"]
    assert report.left_behind == ()
    assert report.wrote_into == str(scratch)


def test_no_probe_name_escapes_the_directory_it_was_given(server: MatrixServer, tmp_path: Path):
    """A nominated directory is a promise, and a probe file one level up is it broken."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    with probed(server, scratch) as report:
        pass

    strays = [p for p in tmp_path.rglob(f"{PROBE_PREFIX}*") if p.parent != scratch]
    assert strays == []
    assert report.findings


def test_a_read_only_run_names_what_it_declined_to_ask(server: MatrixServer):
    """The list has to shrink when a run asks more, or it is decoration rather than a record."""
    with probed(server, None) as read_only:
        pass

    assert ProbeLimit.WRITE_PROBES_NOT_REQUESTED in read_only.undetermined
    assert ProbeLimit.LARGEST_REQUEST_NEEDS_A_WRITE in read_only.undetermined


# --- what each one actually does ---------------------------------------------------------------


@pytest.mark.parametrize("fact", FACTS)
def test_what_this_server_actually_does(server: MatrixServer, tmp_path: Path, fact: str):
    """One row per server per fact, pinned against a measurement.

    Parametrised over the facts rather than asserted as one dict comparison so that a server
    that changed one answer names the answer it changed, instead of printing a twelve-line
    diff of a mapping.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    with probed(server, scratch) as report:
        pass

    found = next((f for f in report.findings if f.fact == fact), None)
    expected = MEASURED[server.name][fact]
    if expected is NOT_ASKED:
        assert found is None, f"{server.name} now advertises this: {found}"
        return
    assert found is not None, f"{server.name} no longer produces a finding for {fact!r}"
    assert found.verdict is expected, f"{server.name}: {found.answer} -- {found.evidence}"


def test_advertised_is_not_the_same_question_as_working(server: MatrixServer, tmp_path: Path):
    """The card's central claim, on the row that proves it.

    `lsetstat@openssh.com` is advertised by OpenSSH and by asyncssh, and on a Linux server it
    works on neither -- **failing differently on each**, which is the part no advertisement
    could have told anybody. OpenSSH refuses with a contentless FAILURE; asyncssh answers OK and
    moves nothing. A report that believed the status would have called the second one working.

    **On macOS the OpenSSH row is a success, and that is the same claim rather than an exception
    to it.** `lchmod` exists there, so the extension does what it says; what stays true is that
    the answer is a property of the *server's operating system* and cannot be read off the
    advertisement. So the assertion is on the pair -- verdict and evidence agreeing about which
    outcome happened -- rather than on a fixed verdict, because pinning one platform's answer as
    SFTP's is exactly the mistake this feature exists to stop.

    The asyncssh row is Linux-only in practice: the `bench` group it needs is installed on the
    `server-matrix` job, which is `ubuntu-latest`.
    """
    if server.name == "paramiko":
        pytest.skip("paramiko advertises no lsetstat@openssh.com, so there is nothing to verify")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    with probed(server, scratch) as report:
        pass

    found = next(f for f in report.findings if f.fact == LSETSTAT)
    if server.name == "openssh" and SERVER_CAN_CHMOD_A_SYMLINK:
        assert found.verdict is Verdict.YES
        assert "this server's platform has lchmod" in found.answer
        return
    assert found.verdict is Verdict.NO
    if server.name == "openssh":
        assert "FAILURE" in found.evidence[-1]
    else:
        assert "lsetstat PERMISSIONS -> OK" in found.evidence
        assert "neither mode changed" in found.answer


def test_the_three_servers_do_not_agree_with_each_other(tmp_path: Path):
    """The reason this file exists, asserted rather than asserted about.

    A battery written against one implementation measures that implementation. This runs all
    three in one test — which is what makes it the expensive one here — and requires that they
    genuinely disagree, so a future change that quietly narrowed the battery to facts every
    server shares would fail rather than pass more easily.
    """
    verdicts: dict[str, dict[str, Verdict | None]] = {}
    for name in SERVER_NAMES:
        reason = unavailable_reason(name)
        if reason is not None:
            pytest.skip(reason)
        root = tmp_path / name
        scratch = root / "scratch"
        scratch.mkdir(parents=True)
        with running_server(name, root) as running, probed(running, scratch) as report:
            verdicts[name] = {f.fact: f.verdict for f in report.findings}

    contested = [fact for fact in FACTS if len({verdicts[name].get(fact) for name in verdicts}) > 1]
    assert MESSAGES_INFORMATIVE in contested
    assert TIMES_SURVIVE in contested
    assert RENAME_REPLACES in contested
    assert len(contested) >= 5, contested


# --- through the command, which is how anybody will actually run it -----------------------------


def test_doctor_runs_the_battery_and_renders_it(server: MatrixServer, tmp_path: Path):
    """The shipped path end to end: `server_diagnosis` opens one session and does both halves.

    OpenSSH only. The other two are reached by `open_ssh_transport` in this file rather than by
    `connect`, and what is under test here is that the negotiation and the battery come back
    from one connection and survive both renderers -- not a third measurement of the servers.
    """
    if server.name != "openssh":
        pytest.skip("the command path is exercised once; the servers are covered above")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    connect = dict(server.connect)
    host = str(connect.pop("host"))

    report = server_diagnosis(
        host,
        port=connect["port"],
        identity_file=connect["identity_file"],
        config_file=connect["config_file"],
        options=connect["options"],
        write_directory=str(scratch).encode(),
    )

    assert report.reached is True, report.error
    assert report.compatibility is not None
    assert report.compatibility.wrote_into == str(scratch)
    assert report.compatibility.left_behind == ()
    # The negotiation half is still whole: reading it before the battery is what keeps a probe
    # that ends the session from costing the facts already established.
    assert report.protocol_version == 3
    assert report.start_directory is not None
    # Nothing the battery opened outlived it.
    assert report.reaped == 0

    text = render_text(local_diagnosis(), report)
    assert "  compatibility           " in text
    assert LSETSTAT in text
    assert "  not determined" in text

    payload = json.loads(render_json(local_diagnosis(), report))
    findings = payload["server"]["compatibility"]["findings"]
    assert [f["fact"] for f in findings] == [f.fact for f in report.compatibility.findings]
    assert all(f["verdict"] in {"yes", "no", "undetermined"} for f in findings)
    assert all(f["evidence"] for f in findings)


def test_doctor_without_the_flag_still_probes_read_only(server: MatrixServer):
    """`doctor <host>` is a diagnostic, so the battery is on -- and writes nothing.

    The library function defaults the other way, which is the deliberate half of the split:
    an existing caller of `server_diagnosis` asked for a negotiation report and still gets one.
    """
    if server.name != "openssh":
        pytest.skip("the command path is exercised once; the servers are covered above")
    connect = dict(server.connect)
    host = str(connect.pop("host"))
    arguments = {
        "port": connect["port"],
        "identity_file": connect["identity_file"],
        "config_file": connect["config_file"],
        "options": connect["options"],
    }

    with_probes = server_diagnosis(host, probes=True, **arguments)
    without = server_diagnosis(host, **arguments)

    assert with_probes.compatibility is not None
    assert with_probes.compatibility.wrote_into is None
    assert without.compatibility is None

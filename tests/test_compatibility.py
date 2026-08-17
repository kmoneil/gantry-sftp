"""The compatibility battery: what it asks, what it refuses to guess, and what it cleans up.

**D-165.** The battery exists because the endpoints this library is for are the ones no
maintainer can start, so a user has to be able to produce the evidence instead. That makes
*this* file's job narrower than usual and one part of it unusually load-bearing: the happy
paths are proved against a real `sftp-server` on a pipe further down, and against the matrix's
three servers in `live-tests/test_compatibility_live.py`. What is left here is the half no real
server will produce on demand — a probe that fails, a directory that will not let go of a file,
a server that answers where a refusal was expected — and those need a stub.

Three things carry more weight than the rest.

**Undetermined has to stay a third answer.** The card's whole reason for existing is that "this
server does not fold case" and "I could not find out" are different, and a report that collapsed
them would be the confident-and-wrong artifact it was written to prevent. So every probe has a
row for its failure, and the two mechanisms — a `Verdict.UNDETERMINED` finding and a
`ProbeLimit` in `report.undetermined` — are asserted to mean different things.

**Nothing may be left behind.** Every name is registered before the request that could create
it, so a create whose answer never arrived is still removed. The stub proves the registration
happens at claim time by failing the create and then asserting the removal was still attempted.

**The verdict must not be flattering.** Two probes were wrong in the first draft and both were
wrong in the direction of a pleasant answer: the message-quality probe called OpenSSH's
`'No such file'` informative because it differed from `'Bad message'`, and the large-request
probe reported `no` against the reference server because a 261 KB path hits `PATH_MAX` rather
than a packet limit. Both are pinned below against the values that caught them.
"""

from __future__ import annotations

import re
from functools import partial
from hashlib import sha256
from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from gantry_sftp.codec import (
    EXTENSION_CHECK_FILE,
    EXTENSION_FSYNC,
    EXTENSION_LIMITS,
    EXTENSION_LSETSTAT,
    EXTENSION_POSIX_RENAME,
    IMPLEMENTED_EXTENSIONS,
    Attrs,
    OpenFlag,
    Status,
    StatusCode,
    Times,
)
from gantry_sftp.compatibility import (
    _CHECK_FILE_PAYLOAD,
    _EXTENSION_PROBES,
    _LSETSTAT_PROBE_MODE,
    PROBE_MODE,
    PROBE_PREFIX,
    PROBE_TIMESTAMP,
    CompatibilityReport,
    Finding,
    ProbeLimit,
    Verdict,
    _clean_up,
    _guarded,
    _join,
    _probe_case_folding,
    _probe_largest_request,
    _probe_message_quality,
    _probe_posix_rename,
    _probe_rename_replaces,
    _probe_timestamps,
    _Scratch,
    _upper_name,
    compatibility_report,
    read_only_probes,
    restates_the_code,
    write_probes,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    ConnectError,
    NoSuchFileError,
    PermissionDeniedError,
    ServerError,
)
from gantry_sftp.session import ServerLimits, raise_for_status
from gantry_sftp.session._quirks import PROFILES, UNKNOWN
from gantry_sftp.sync import open_local_server_transport, open_session
from gantry_sftp.transport import find_sftp_server
from local_filesystem import FILESYSTEM_FOLDS_CASE, SERVER_CAN_CHMOD_A_SYMLINK

CASE_FOLDS = "this server folds case in names"
ROOT_IS_SLASH = "the root of this server's namespace is /"
"""Two fact strings this file names more than once.

Spelled here rather than in the module under test, deliberately: a test that imported the
constant would assert the code equals itself, and the string is a user-facing sentence whose
wording is part of what is being pinned.
"""


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def refusal(code: StatusCode, message: bytes = b"") -> ServerError:
    """A server refusal, built the way the session builds one.

    **Through `raise_for_status` rather than by constructing `ServerError` directly**, and the
    difference is not cosmetic: several probes catch a *subclass* — `NoSuchFileError` is how
    "this name is not there" arrives, and swallowing the base class instead would report a
    permission failure as a case-sensitive server. A hand-built base-class instance makes those
    probes look broken and, worse, would make a probe that *did* over-swallow look correct.
    """
    with pytest.raises(ServerError) as raised:
        raise_for_status(Status(request_id=1, code=code, message=message))
    return raised.value


# --- the constants other things are derived from ----------------------------------------------


def test_the_probe_prefix_is_not_its_own_uppercase():
    """The case-folding probe is only an instrument if the two names it uses differ.

    It creates a name and asks for that name uppercased. A prefix with no letters in it —
    digits, or a token alone — would be its own uppercase, the stat would find the file it just
    made, and every server on earth would be reported as folding case. Asserted here rather
    than guarded for at run time, because the property belongs to the constant.
    """
    assert PROBE_PREFIX.upper() != PROBE_PREFIX


def test_probe_files_are_created_private():
    """`0o600`, because OPEN with no ATTRS leaves the server applying `0666 & ~umask`.

    The files are removed either way; the window between creation and removal is the part that
    would have been world-readable, in a directory somebody's employer depends on.
    """
    assert PROBE_MODE == 0o600


def test_the_probe_timestamp_is_in_the_past_and_fits_the_wire():
    """A `now` would be indistinguishable from a creation time a server never updated."""
    assert PROBE_TIMESTAMP < 2**32
    assert PROBE_TIMESTAMP != 0


def test_every_implemented_extension_a_write_can_verify_is_in_the_table():
    """The sweep CLAUDE.md's rule is about, derived rather than listed.

    Adding an extension to `IMPLEMENTED_EXTENSIONS` and not to `_EXTENSION_PROBES` leaves the
    report silently narrower than it claims to be — it would say "which advertised extensions
    actually work" and quietly not ask about the new one. `limits@openssh.com` is the single
    exclusion because it is the only one answered without a write, and it has its own probe in
    the read-only battery.
    """
    verified = {extension for extension, _, _ in _EXTENSION_PROBES}
    assert verified == set(IMPLEMENTED_EXTENSIONS) - {EXTENSION_LIMITS}


def test_every_probe_limit_says_both_what_and_why():
    """A limit that named the gap without the reason would be re-asked every six months."""
    limits = [
        value
        for name, value in vars(ProbeLimit).items()
        if not name.startswith("_") and isinstance(value, str)
    ]
    assert limits
    for limit in limits:
        assert "not probed" in limit, limit
        assert "because" in limit, limit


# --- the two helpers that decide a verdict ----------------------------------------------------


@pytest.mark.parametrize(
    ("code", "message", "restates"),
    [
        # Measured against OpenSSH 10.0p2: every one of these is the code's own name, and the
        # first draft of the probe called the pair informative because they differ from each
        # other. They differ because the codes differ.
        (StatusCode.NO_SUCH_FILE, b"No such file", True),
        (StatusCode.BAD_MESSAGE, b"Bad message", True),
        (StatusCode.FAILURE, b"Failure", True),
        (StatusCode.PERMISSION_DENIED, b"Permission denied", True),
        # Punctuation and case are noise, so a server that ends its sentences still restates.
        (StatusCode.FAILURE, b"failure.", True),
        (StatusCode.NO_SUCH_FILE, b"NO_SUCH_FILE", True),
        # asyncssh, measured: a FAILURE that names the actual condition.
        (StatusCode.FAILURE, b"File already exists", False),
        (StatusCode.FAILURE, b"Directory not empty", False),
        # An empty message says nothing, and "says nothing" is what this predicate reports.
        (StatusCode.FAILURE, b"", False),
    ],
)
def test_a_message_that_only_spells_out_its_own_code_says_nothing(code, message, restates):
    assert restates_the_code(int(code), message) is restates


def test_an_empty_message_is_judged_by_the_probe_rather_than_by_the_predicate():
    """`restates_the_code(code, b"")` is False, and the probe still calls it uninformative.

    Worth pinning because the two look like they disagree. The predicate answers "is this text
    the code's name", and an empty string is not; the probe answers "is there anything worth
    reading", and checks for emptiness first. Collapsing them would make a silent server report
    as informative.
    """
    assert restates_the_code(int(StatusCode.FAILURE), b"") is False


def test_joining_does_not_double_a_separator_the_caller_supplied():
    assert _join(b"/incoming", "probe") == b"/incoming/probe"
    assert _join(b"/incoming/", "probe") == b"/incoming/probe"
    assert _join(b"/", "probe") == b"/probe"


def test_only_the_last_component_is_uppercased():
    """Folding the directory would ask whether the whole path folds and report it as a name."""
    folded = b"/Incoming/scratch/GANTRY-PROBE-X"  # pragma: allowlist secret  # a path, not a key
    assert _upper_name(b"/Incoming/scratch/gantry-probe-x") == folded


# --- the report object ------------------------------------------------------------------------


def test_a_report_is_complete_when_every_probe_answered():
    answered = Finding(fact="f", verdict=Verdict.YES, answer="a")
    assert CompatibilityReport(findings=(answered,)).complete is True
    assert CompatibilityReport(findings=(answered, answered)).complete is True


def test_one_undetermined_finding_makes_a_report_incomplete():
    answered = Finding(fact="f", verdict=Verdict.YES, answer="a")
    unknown = Finding(fact="g", verdict=Verdict.UNDETERMINED, answer="could not tell")
    assert CompatibilityReport(findings=(answered, unknown)).complete is False


def test_a_no_is_an_answer_and_does_not_make_a_report_incomplete():
    """The card's whole point: a server that differs from the reference is not a broken one."""
    negative = Finding(fact="f", verdict=Verdict.NO, answer="it does not")
    assert CompatibilityReport(findings=(negative,)).complete is True


def test_an_empty_report_is_not_complete():
    """Nothing asked is not everything answered, and `all(())` is True."""
    assert CompatibilityReport().complete is False


def test_completeness_ignores_the_undetermined_list_because_it_is_never_empty():
    """`undetermined` records what was not *asked*; `complete` is about what was.

    Folding the list in would make `complete` constantly False — a read-only run always has
    questions it declined — which is the same as not having the property at all.
    """
    answered = Finding(fact="f", verdict=Verdict.YES, answer="a")
    report = CompatibilityReport(findings=(answered,), undetermined=("something was not asked",))
    assert report.complete is True


# --- a stub session, for the answers no real server gives on demand ---------------------------


class StubSession:
    """The handful of calls the battery makes, with each one's answer scripted.

    Deliberately not a `SyncSession` subclass and deliberately tiny. It exists for the shapes
    `tests/server_contract.py` says a contract cannot cover — a probe that raises, a removal
    that is refused, a server that answers where a refusal was expected — and every behaviour
    it *can* be asked of a real server is asserted against one further down instead.
    """

    def __init__(self, **scripted: object) -> None:
        self.scripted = scripted
        self.calls: list[tuple[str, object]] = []
        self.limits = ServerLimits()
        self.profile = UNKNOWN
        self.advertised: set[str] = set()
        self.files: set[bytes] = set()
        self.removed: list[bytes] = []

    # Each of these records the call, then either raises what it was told to raise or returns
    # what it was told to return. `_answer` is the one place that decision is made, so a stub
    # method cannot grow its own opinion about it.
    def _answer(self, name: str, default: object = None) -> object:
        answer = self.scripted.get(name, default)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def supports(self, extension: bytes | str) -> bool:
        name = extension.decode() if isinstance(extension, bytes) else extension
        return name in self.advertised

    def realpath(self, path: bytes | str = b".") -> bytes:
        self.calls.append(("realpath", path))
        answer = self._answer("realpath", b"/home/probe")
        assert isinstance(answer, bytes)
        return answer

    def stat(self, path: bytes | str) -> object:
        self.calls.append(("stat", path))
        # The default answers with the times and the mode the probes just set, not `None`: a
        # stub whose `stat` answered nothing would make the timestamp probe raise
        # `AttributeError`, which `_guarded` does not catch and should not -- that is a bug in
        # the probe rather than a server behaviour, and the two must not look alike.
        return self._answer("stat", attrs())

    def lstat(self, path: bytes | str) -> object:
        self.calls.append(("lstat", path))
        # `0o777` is what a symlink's own mode reads as on Linux, where it cannot be changed --
        # so the default here is the answer that means "lsetstat did nothing", which is the
        # case a stub is most likely to be asked to reproduce.
        return self._answer("lstat", attrs(mode=0o777))

    def readlink(self, path: bytes | str) -> bytes:
        self.calls.append(("readlink", path))
        answer = self._answer("readlink")
        assert isinstance(answer, bytes)
        return answer

    def open(self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ, *, mode=None) -> bytes:
        self.calls.append(("open", (path, pflags, mode)))
        assert isinstance(path, bytes)
        self.files.add(path)
        answer = self._answer("open", b"handle")
        assert isinstance(answer, bytes)
        return answer

    def write_at(self, handle: bytes, offset: int, data: bytes | memoryview) -> int:
        self.calls.append(("write_at", (offset, len(data))))
        answer = self._answer("write_at", len(data))
        assert isinstance(answer, int)
        return answer

    def close(self, handle: bytes) -> None:
        self.calls.append(("close", handle))

    def rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        self.calls.append(("rename", (old_path, new_path)))
        _ = self._answer("rename")

    def posix_rename_if_supported(self, old_path: bytes | str, new_path: bytes | str) -> bool:
        self.calls.append(("posix_rename", (old_path, new_path)))
        answer = self._answer("posix_rename", True)
        assert isinstance(answer, bool)
        return answer

    def exists(self, path: bytes | str, *, follow_symlinks: bool = True) -> bool:
        self.calls.append(("exists", path))
        answer = self._answer("exists", False)
        assert isinstance(answer, bool)
        return answer

    def utime(self, path: bytes | str, atime: int, mtime: int, *, follow_symlinks=True) -> None:
        self.calls.append(("utime", (path, atime, mtime)))
        _ = self._answer("utime")

    def remove(self, path: bytes | str) -> None:
        self.calls.append(("remove", path))
        assert isinstance(path, bytes)
        self.removed.append(path)
        _ = self._answer("remove")

    def fsync_if_supported(self, handle: bytes) -> bool:
        self.calls.append(("fsync", handle))
        answer = self._answer("fsync", True)
        assert isinstance(answer, bool)
        return answer

    def symlink(self, target: bytes | str, link_path: bytes | str) -> None:
        self.calls.append(("symlink", (target, link_path)))
        _ = self._answer("symlink")

    def chmod(self, path: bytes | str, mode: int, *, follow_symlinks: bool = True) -> None:
        self.calls.append(("chmod", (path, mode, follow_symlinks)))
        _ = self._answer("chmod")

    def check_file(self, handle: bytes, **_kwargs: object) -> tuple[bytes, tuple[bytes, ...]]:
        self.calls.append(("check_file", handle))
        default = (b"sha256", (sha256(_CHECK_FILE_PAYLOAD).digest(),))
        answer = self._answer("check_file", default)
        assert isinstance(answer, tuple)
        return answer


def scratch(directory: bytes = b"/incoming/scratch") -> _Scratch:
    return _Scratch(directory, "t0ken")


def attrs(*, mtime: int = PROBE_TIMESTAMP, mode: int = PROBE_MODE) -> Attrs:
    """The real `Attrs` a session hands back, rather than a class with the two fields on it.

    A hand-rolled stand-in would let a probe read a field `Attrs` does not have and pass, which
    is the class of bug `tests/server_contract.py` exists for one layer down.
    """
    return Attrs(times=Times(atime=mtime, mtime=mtime), permissions=mode)


# --- a probe that fails is undetermined, never a no -------------------------------------------


def test_a_probe_that_raises_becomes_an_undetermined_finding_carrying_the_failure():
    """The guard, which is what lets fifteen probes run against an unfamiliar endpoint."""

    def explode() -> Finding:
        raise PermissionDeniedError("nope", code=int(StatusCode.PERMISSION_DENIED))

    found = _guarded("some fact", explode)

    assert found.fact == "some fact"
    assert found.verdict is Verdict.UNDETERMINED
    assert found.answer == "the probe itself failed, so this server's behaviour is not established"
    assert found.evidence == ("PermissionDeniedError: nope",)


def test_a_dead_connection_is_caught_by_the_guard_as_well():
    """`OSError` alongside `SFTPError`: a channel that has gone away arrives as one."""

    def explode() -> Finding:
        raise OSError("broken pipe")

    found = _guarded("some fact", explode)

    assert found.verdict is Verdict.UNDETERMINED
    assert found.evidence == ("OSError: broken pipe",)


def test_a_guarded_probe_that_succeeds_is_returned_untouched():
    """The guard must not be able to launder a real verdict into an undetermined one."""
    answered = Finding(fact="f", verdict=Verdict.NO, answer="it does not", evidence=("x",))
    assert _guarded("f", lambda: answered) is answered


def test_a_session_that_cannot_name_its_own_start_reports_that_and_does_not_raise():
    """The one failure that stops the battery before it begins, and it is still a report.

    Every probe builds a name under the start directory. A `compatibility_report` that let this
    escape would take down `doctor`'s whole server half — including the negotiation, which had
    already succeeded — on the one server most worth reporting on.
    """
    session = StubSession(realpath=ConnectError("the channel closed"))

    report = compatibility_report(session, request_bytes=32768)  # type: ignore[arg-type]

    assert len(report.findings) == 1
    only = report.findings[0]
    assert only.fact == "the session can name its own starting directory"
    assert only.verdict is Verdict.UNDETERMINED
    assert only.answer == (
        "REALPATH of '.' failed, so there was nowhere to build a probe name and no fact below "
        "could be established"
    )
    assert only.evidence == ("REALPATH b'.' -> ConnectError: the channel closed",)
    assert report.complete is False
    assert report.wrote_into is None


# --- the read-only battery --------------------------------------------------------------------


def test_a_server_that_answers_where_a_refusal_was_expected_is_undetermined():
    """Not a `no`: a server that canonicalises a directory as a symlink target told us nothing.

    Reported as undetermined with the accepted exchange in the evidence, so a reader can see
    which of the two probes went the wrong way rather than being handed a verdict about the
    other one.
    """
    session = StubSession(stat=refusal(StatusCode.NO_SUCH_FILE, b"gone"), readlink=b"/elsewhere")

    found = _probe_message_quality(session, b"/home/probe", "t0ken")  # type: ignore[arg-type]

    assert found.verdict is Verdict.UNDETERMINED
    assert found.answer == (
        "this server accepted a request where a refusal was expected, so there was no pair of "
        "refusals to read"
    )
    assert found.evidence[-1] == "READLINK b'/home/probe' -> accepted"


def test_a_silent_refusal_is_reported_as_carrying_nothing():
    """Some servers send no message at all, which is different from sending the code's name."""
    session = StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE), readlink=refusal(StatusCode.BAD_MESSAGE)
    )

    found = _probe_message_quality(session, b"/home/probe", "t0ken")  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert found.answer == (
        "at least one refusal carried no message at all, so the status code is all there is "
        "to route on"
    )
    assert "NO_SUCH_FILE, no message" in found.evidence[0]


def test_one_message_worth_reading_is_enough_for_a_yes():
    """`any`, not `all`: a server that explains one refusal has text worth quoting."""
    session = StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"),
        readlink=refusal(StatusCode.FAILURE, b"that is a directory, not a link"),
    )

    found = _probe_message_quality(session, b"/home/probe", "t0ken")  # type: ignore[arg-type]

    assert found.verdict is Verdict.YES


def test_the_fingerprints_claim_about_messages_is_in_the_evidence():
    """The report measures the one non-identity field a `ServerProfile` carries.

    `informative_messages` is the only thing in the quirks fingerprint that is a claim about
    behaviour rather than identity, and it was set by measurement. Putting it beside the
    measurement lets a reviewer see the two agree — or notice that they do not.
    """
    session = StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"),
        readlink=refusal(StatusCode.BAD_MESSAGE, b"Bad message"),
    )
    session.profile = PROFILES["openssh"]

    found = _probe_message_quality(session, b"/home/probe", "t0ken")  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert found.evidence[-1] == (
        "this library's fingerprint for openssh claims informative_messages=False"
    )


def test_the_read_only_battery_asks_about_limits_only_where_it_was_advertised():
    """Probing an extension the server never offered would report a fallback as a failure."""
    session = StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"),
        readlink=refusal(StatusCode.BAD_MESSAGE, b"Bad message"),
    )

    without = read_only_probes(session, directory=b"/home/probe", run_id="t0ken")  # type: ignore[arg-type]
    session.advertised.add(EXTENSION_LIMITS)
    session.limits = ServerLimits(max_packet_length=262144)
    with_it = read_only_probes(session, directory=b"/home/probe", run_id="t0ken")  # type: ignore[arg-type]

    facts = {finding.fact for finding in without}
    assert "limits@openssh.com answers with a usable maximum" not in facts
    assert "limits@openssh.com answers with a usable maximum" in {f.fact for f in with_it}


def test_an_advertised_limits_that_states_no_maximum_is_a_no():
    """A returned `0` means "no limit", which this library stores as `None`.

    That is worth saying out loud, because from the outside it is indistinguishable from a
    negotiated maximum — and the session is running on its own conservative default.
    """
    session = StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"),
        readlink=refusal(StatusCode.BAD_MESSAGE, b"Bad message"),
    )
    session.advertised.add(EXTENSION_LIMITS)

    findings = read_only_probes(session, directory=b"/home/probe", run_id="t0ken")  # type: ignore[arg-type]

    limits = next(f for f in findings if f.fact.startswith("limits@openssh.com"))
    assert limits.verdict is Verdict.NO
    assert "conservative default" in limits.answer
    assert "limits@openssh.com max_packet_length -> no limit stated" in limits.evidence


# --- the write battery ------------------------------------------------------------------------


def test_the_case_probe_asks_for_the_uppercase_of_the_name_it_created():
    """The instrument, pinned: a stat of the same name would report every server as folding."""
    session = StubSession(stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"))
    board = scratch()

    found = _probe_case_folding(session, board)  # type: ignore[arg-type]

    created = board.claimed[0]
    asked = next(path for name, path in session.calls if name == "stat")
    assert asked != created
    assert asked == created.upper() or asked.endswith(b"/" + created.rpartition(b"/")[2].upper())
    assert found.verdict is Verdict.NO


def test_a_folding_server_is_reported_as_an_upload_hazard():
    """The `yes` branch names the consequence, because the verdict alone is not actionable.

    **D-193: it named the wrong one, and this test's previous name and assertion carried the
    error rather than catching it.** It asserted the substring "overwrite its own output" and
    was called `..._is_reported_as_a_download_hazard`, so the direction -- the part that was
    wrong -- was the one thing not being checked.

    The reasoning, written out so a reader can check it rather than trust it. `verdict=YES`
    means **this server folds case**, established by creating `…-case-aA` and finding
    `…-CASE-AA`. A server that folds cannot hold two names differing only in case, so it can
    never present two such names in a listing -- which means a download cannot merge two remote
    names into one local file *because of this server*. The direction that does bite is the
    mirror: two local files differing only in case land as one file on the way up, the second
    overwriting the first.

    The download hazard is real and belongs to the **other** branch -- it needs a
    case-*sensitive* server, so both names can exist, plus a local filesystem that folds, as
    macOS and Windows do by default. `_probe_case_folding`'s own docstring names both directions
    correctly; only the prose a user reads had them swapped.
    """
    session = StubSession()  # stat returns None rather than raising: the name was found

    found = _probe_case_folding(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.YES
    assert "an upload of two local names differing only in case" in found.answer
    # Both directions, because the defect was a true sentence about the wrong case: asserting
    # only the new clause would still pass with the old one left beside it.
    assert "download" not in found.answer


def test_a_case_sensitive_server_is_reported_as_the_download_hazard():
    """The other half of the same correction, and the reason it is a move rather than a cut.

    The clause deleted above is true and worth telling a user -- of a server that does *not*
    fold. Dropping it would have traded a misplaced warning for a missing one.
    """
    session = StubSession(stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"))

    found = _probe_case_folding(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert "recursive download onto a filesystem that folds case" in found.answer
    assert "overwrite its own output" in found.answer


def test_the_case_probe_only_swallows_no_such_file():
    """A wide `except` would report "permission denied" as "does not fold case".

    The same rule the rest of the library follows: a predicate may only swallow the subclass
    that means the answer is no, and everything else is an unanswered question.
    """
    session = StubSession(stat=refusal(StatusCode.PERMISSION_DENIED, b"nope"))

    probe = partial(_probe_case_folding, session, scratch())  # type: ignore[arg-type]
    found = _guarded(CASE_FOLDS, probe)

    assert found.verdict is Verdict.UNDETERMINED


def test_a_rename_that_is_refused_is_the_draft_conformant_answer():
    session = StubSession(rename=refusal(StatusCode.FAILURE, b"Failure"))

    found = _probe_rename_replaces(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert "as the draft requires" in found.answer
    assert found.evidence[-1] == "RENAME -> FAILURE, server said 'Failure'"


def test_a_rename_that_clobbers_is_reported_as_destructive():
    """POSIX `rename(2)` replaces; the draft says it must not. Real servers do both."""
    session = StubSession()

    found = _probe_rename_replaces(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.YES
    assert "Treat any rename here as destructive" in found.answer


def test_a_posix_rename_that_answers_ok_and_moves_nothing_is_a_no():
    """The reason the probe confirms the source is gone rather than trusting the status.

    Atomic publish rests on this extension, so a server that answers OK and does nothing would
    otherwise read as a working one — which is the failure mode that costs a file.
    """
    session = StubSession(exists=True)

    found = _probe_posix_rename(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert found.answer == (
        "the server answered OK and the source is still there, so nothing was renamed"
    )
    assert found.evidence[-1].endswith("-> still present")


def test_an_advertised_posix_rename_that_answers_unsupported_is_a_no_not_a_failure():
    session = StubSession(posix_rename=False)

    found = _probe_posix_rename(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert "OP_UNSUPPORTED" in found.evidence[-1]


def test_a_server_that_reports_no_times_leaves_the_timestamp_question_open():
    """Undetermined rather than `no`: nothing came back to compare against.

    A `no` here would accuse a server of dropping a timestamp it may have stored perfectly
    well and simply not volunteered.
    """
    session = StubSession(stat=Attrs())

    found = _probe_timestamps(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.UNDETERMINED
    assert found.answer == "this server reported no times at all, so there was nothing to compare"
    assert found.evidence[-1] == "STAT -> no times reported"


def test_a_server_that_kept_a_different_mtime_is_reported_as_such():
    session = StubSession(stat=attrs(mtime=PROBE_TIMESTAMP + 5))

    found = _probe_timestamps(session, scratch())  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert "preserve_times cannot be relied on here" in found.answer
    assert found.evidence[-1] == f"STAT -> mtime={PROBE_TIMESTAMP + 5}"


def test_an_lsetstat_that_answers_ok_and_moves_nothing_is_a_no():
    """asyncssh on Linux, measured. Believing the status would report it as the one that works.

    OpenSSH refuses on this kernel and asyncssh answers `OK`, so a probe that read the status
    would say the extension works on exactly the server that silently discards the request.
    """
    session = StubSession(lstat=attrs(mode=0o777), stat=attrs(mode=PROBE_MODE))
    session.advertised.add("lsetstat@openssh.com")

    findings, _ = write_probes(session, directory=b"/s", request_bytes=64, run_id="ls")  # type: ignore[arg-type]

    found = next(f for f in findings if f.fact.startswith("lsetstat@openssh.com"))
    assert found.verdict is Verdict.NO
    assert "accepted and discarded" in found.answer
    assert "LSTAT of the link -> 0o777" in found.evidence


def test_an_lsetstat_that_changed_the_target_is_reported_as_a_hazard():
    """The dangerous outcome: the caller asked not to follow a link and was followed.

    Nothing in the matrix does this, which is exactly why it needs a stub — it is the failure
    that reverses a security decision without telling anybody, and a probe that only knew the
    two outcomes real servers produce would let it through as a success.
    """
    session = StubSession(lstat=attrs(mode=0o777), stat=attrs(mode=0o640))
    session.advertised.add("lsetstat@openssh.com")

    findings, _ = write_probes(session, directory=b"/s", request_bytes=64, run_id="ls")  # type: ignore[arg-type]

    found = next(f for f in findings if f.fact.startswith("lsetstat@openssh.com"))
    assert found.verdict is Verdict.NO
    assert "changed the mode of what the link points at" in found.answer
    assert "STAT of the target -> 0o640" in found.evidence


def test_an_lsetstat_that_changed_the_links_own_mode_is_the_only_yes():
    """What a macOS or BSD server does, where `lchmod` exists and the mode is real."""
    session = StubSession(lstat=attrs(mode=0o640), stat=attrs(mode=PROBE_MODE))
    session.advertised.add("lsetstat@openssh.com")

    findings, _ = write_probes(session, directory=b"/s", request_bytes=64, run_id="ls")  # type: ignore[arg-type]

    found = next(f for f in findings if f.fact.startswith("lsetstat@openssh.com"))
    assert found.verdict is Verdict.YES
    assert "this server's platform has lchmod" in found.answer


def test_the_mode_the_lsetstat_probe_sets_differs_from_the_one_it_creates_with():
    """Two equal values would make a followed link and an untouched one look identical.

    The probe creates the target at `PROBE_MODE` and asks for the link to become something
    else; if they matched, "the server followed the link" and "the server did nothing" would
    both read as the target still wearing the mode it was created with.
    """
    assert _LSETSTAT_PROBE_MODE != PROBE_MODE


def test_a_short_write_is_a_no_that_no_exception_would_have_reported():
    """The failure a bare try/except would miss: accepted, stored short, counted honestly."""
    session = StubSession(write_at=1024)

    found = _probe_largest_request(session, scratch(), 262144)  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert "stored fewer bytes than it was sent" in found.answer
    assert found.evidence == ("WRITE of 262144 bytes -> 1024 bytes written",)


def test_a_refused_large_write_names_the_knob_that_fixes_it():
    session = StubSession(write_at=refusal(StatusCode.FAILURE, b"Failure"))

    found = _probe_largest_request(session, scratch(), 262144)  # type: ignore[arg-type]

    assert found.verdict is Verdict.NO
    assert "lower request_size until this passes" in found.answer


def test_the_large_write_probe_closes_its_handle_even_when_the_write_is_refused():
    """A diagnostic that leaked a handle per run would be the thing it reports on."""
    session = StubSession(write_at=refusal(StatusCode.FAILURE, b"Failure"))

    _ = _probe_largest_request(session, scratch(), 4096)  # type: ignore[arg-type]

    assert ("close", b"handle") in session.calls


# --- cleanup ----------------------------------------------------------------------------------


def test_a_name_is_registered_before_the_request_that_would_create_it():
    """The rule that makes cleanup honest when an answer never arrives.

    A create whose reply was lost may still have happened, so a cleanup list built from
    *successful* creates misses exactly the files nobody wanted left behind. Proved by failing
    the create and asserting the name is still on the list.
    """
    board = scratch()
    session = StubSession(open=ConnectError("the channel closed"))

    found = _guarded("f", lambda: _probe_case_folding(session, board))  # type: ignore[arg-type]

    assert found.verdict is Verdict.UNDETERMINED
    assert len(board.claimed) == 1
    assert _clean_up(session, board) == []  # type: ignore[arg-type]
    assert session.removed == board.claimed


def test_cleanup_removes_in_reverse_so_a_replaced_name_is_attempted_last():
    board = scratch()
    first, second = board.claim("a"), board.claim("b")
    session = StubSession()

    _ = _clean_up(session, board)  # type: ignore[arg-type]

    assert session.removed == [second, first]


def test_a_name_that_was_never_created_is_not_reported_as_left_behind():
    """`NoSuchFileError` alone is swallowed: a rename consumes one of its two names."""
    board = scratch()
    _ = board.claim("a")
    session = StubSession(remove=NoSuchFileError("gone", code=int(StatusCode.NO_SUCH_FILE)))

    assert _clean_up(session, board) == []  # type: ignore[arg-type]


def test_anything_else_that_refuses_a_removal_is_reported_with_its_reason():
    """A wide `except` here would turn "the directory is read-only" into "cleaned up fine"."""
    board = scratch()
    path = board.claim("a")
    session = StubSession(
        remove=PermissionDeniedError("read-only", code=int(StatusCode.PERMISSION_DENIED))
    )

    left = _clean_up(session, board)  # type: ignore[arg-type]

    assert left == [f"{path!r}: PermissionDeniedError: read-only"]


def test_a_report_carries_what_it_could_not_clean_up():
    """Silence about a litter of probe files in production would be worse than not running."""
    session = StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"),
        readlink=refusal(StatusCode.BAD_MESSAGE, b"Bad message"),
        remove=PermissionDeniedError("read-only", code=int(StatusCode.PERMISSION_DENIED)),
    )

    report = compatibility_report(  # type: ignore[arg-type]
        session, request_bytes=4096, write_directory="/incoming/scratch", run_id="t0ken"
    )

    assert report.wrote_into == "/incoming/scratch"
    assert report.left_behind
    assert all("PermissionDeniedError: read-only" in item for item in report.left_behind)


# --- what a run declines to ask ---------------------------------------------------------------


def readable_stub() -> StubSession:
    return StubSession(
        stat=refusal(StatusCode.NO_SUCH_FILE, b"No such file"),
        readlink=refusal(StatusCode.BAD_MESSAGE, b"Bad message"),
    )


def test_a_read_only_run_says_which_questions_needed_a_write():
    session = readable_stub()

    report = compatibility_report(session, request_bytes=4096, run_id="t0ken")  # type: ignore[arg-type]

    assert ProbeLimit.WRITE_PROBES_NOT_REQUESTED in report.undetermined
    assert ProbeLimit.LARGEST_REQUEST_NEEDS_A_WRITE in report.undetermined
    assert report.wrote_into is None


def test_a_write_run_drops_the_limits_its_writes_answered():
    """The list must shrink when the run asks more, or it is decoration rather than a record."""
    session = readable_stub()

    report = compatibility_report(  # type: ignore[arg-type]
        session, request_bytes=4096, write_directory=b"/incoming/scratch", run_id="t0ken"
    )

    assert ProbeLimit.WRITE_PROBES_NOT_REQUESTED not in report.undetermined
    assert ProbeLimit.LARGEST_REQUEST_NEEDS_A_WRITE not in report.undetermined


def test_the_unverified_extensions_are_named_rather_than_counted():
    """ "Some extensions were not verified" sends a reader to work out which."""
    session = readable_stub()
    session.advertised.update({"posix-rename@openssh.com", "fsync@openssh.com"})

    report = compatibility_report(session, request_bytes=4096, run_id="t0ken")  # type: ignore[arg-type]

    named = [line for line in report.undetermined if "posix-rename@openssh.com" in line]
    assert len(named) == 1
    assert "fsync@openssh.com" in named[0]


def test_a_run_against_a_server_advertising_everything_drops_the_unadvertised_limit():
    session = readable_stub()
    session.advertised.update(IMPLEMENTED_EXTENSIONS)
    session.limits = ServerLimits(max_packet_length=262144)

    report = compatibility_report(  # type: ignore[arg-type]
        session, request_bytes=4096, write_directory=b"/incoming/scratch", run_id="t0ken"
    )

    assert ProbeLimit.UNADVERTISED_EXTENSIONS not in report.undetermined


def test_two_limits_are_permanent_because_neither_can_be_asked_safely():
    """Whatever the run does, these two stay: both mean "not without moving your data"."""
    session = readable_stub()
    session.advertised.update(IMPLEMENTED_EXTENSIONS)

    report = compatibility_report(  # type: ignore[arg-type]
        session, request_bytes=4096, write_directory=b"/incoming/scratch", run_id="t0ken"
    )

    assert ProbeLimit.CEILING_ABOVE_THIS_SESSION in report.undetermined
    assert ProbeLimit.BEHAVIOUR_UNDER_LOAD in report.undetermined


def test_a_write_directory_given_as_text_is_encoded_and_echoed_back():
    """Remote paths are bytes; the command line hands over `str`. One conversion, one place."""
    session = readable_stub()

    report = compatibility_report(  # type: ignore[arg-type]
        session, request_bytes=4096, write_directory="/incoming/scratch", run_id="t0ken"
    )

    assert report.wrote_into == "/incoming/scratch"
    created = [path for name, path in session.calls if name == "open"]
    assert created
    assert all(path[0].startswith(b"/incoming/scratch/") for path in created)


def test_every_name_created_carries_the_prefix_and_the_token():
    """So an operator who finds one after a killed run can tell what made it, and when."""
    session = readable_stub()

    _ = compatibility_report(  # type: ignore[arg-type]
        session, request_bytes=4096, write_directory=b"/incoming/scratch", run_id="t0ken"
    )

    for path in session.removed:
        assert path.rpartition(b"/")[2].startswith(f"{PROBE_PREFIX}-t0ken-".encode())


def test_two_runs_get_different_names_without_being_told_to():
    """A shared scratch directory must survive two people diagnosing at once."""
    first, second = readable_stub(), readable_stub()

    _ = compatibility_report(first, request_bytes=4096, write_directory=b"/s")  # type: ignore[arg-type]
    _ = compatibility_report(second, request_bytes=4096, write_directory=b"/s")  # type: ignore[arg-type]

    assert first.removed
    assert second.removed
    assert set(first.removed) & set(second.removed) == set()


# --- against a real sftp-server, over a pipe --------------------------------------------------


def test_the_read_only_battery_makes_no_writes_at_all(tmp_path: Path):
    """The safety property this whole feature rests on, asserted against a real filesystem.

    Not "no probe calls a write method" — that is a claim about our own code. This runs the
    read-only battery against a real `sftp-server` in a directory whose contents are compared
    before and after, which is a claim about what reached the disk.
    """
    needs_real_server()
    (tmp_path / "existing.csv").write_bytes(b"id\n1\n")
    before = {p.name: p.stat().st_mtime_ns for p in tmp_path.iterdir()}

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(sftp, request_bytes=4096, run_id="readonly")

    assert {p.name: p.stat().st_mtime_ns for p in tmp_path.iterdir()} == before
    assert report.wrote_into is None
    assert report.left_behind == ()
    assert report.findings


def test_the_write_battery_leaves_the_directory_as_it_found_it(tmp_path: Path):
    """Every file it creates is removed, proved by listing rather than by counting removals."""
    needs_real_server()
    (tmp_path / "existing.csv").write_bytes(b"id\n1\n")
    before = sorted(p.name for p in tmp_path.iterdir())

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=sftp.sizes_for(b"\x00\x00\x00\x00").write_length,
            write_directory=str(tmp_path).encode(),
            run_id="writes",
        )

    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert report.left_behind == ()
    assert report.wrote_into == str(tmp_path)


def test_the_reference_server_answers_every_question_the_battery_asks(tmp_path: Path):
    """`complete` against the one server whose behaviour this project knows in full.

    An undetermined finding here is a probe that has stopped working, not a server that is
    unusual — which is exactly what this assertion is for.
    """
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=sftp.sizes_for(b"\x00\x00\x00\x00").write_length,
            write_directory=str(tmp_path).encode(),
            run_id="complete",
        )

    unanswered = [f.fact for f in report.findings if f.verdict is Verdict.UNDETERMINED]
    assert unanswered == []
    assert report.complete is True


@pytest.mark.parametrize(
    ("fact", "verdict"),
    [
        # Measured against OpenSSH 10.0p2 on Linux. Each is a fact about the reference server,
        # and a change here is a finding rather than a broken test.
        ("REALPATH canonicalises a path that does not exist", Verdict.YES),
        ("the root of this server's namespace is /", Verdict.YES),
        # The one the first draft of the probe got backwards: 'No such file' and 'Bad message'
        # differ from each other and are both the code's own name.
        ("a refusal carries a message that says more than its status code", Verdict.NO),
        ("limits@openssh.com answers with a usable maximum", Verdict.YES),
        # A property of the disk this server is serving, not of the server. macOS's APFS
        # folds and ext4 does not, so this row is derived -- and the battery reporting `yes`
        # on a Mac is the battery *working*.
        ("this server folds case in names", Verdict.YES if FILESYSTEM_FOLDS_CASE else Verdict.NO),
        ("RENAME replaces an existing target", Verdict.NO),
        ("a file's timestamps survive being set", Verdict.YES),
        ("posix-rename@openssh.com actually renames", Verdict.YES),
        ("fsync@openssh.com actually flushes", Verdict.YES),
        # The headline: advertised by OpenSSH, and whether it *works* is a property of the
        # server's operating system rather than of the extension. Linux has no `lchmod`, so the
        # permissions branch cannot succeed; macOS has one, so it does. **Both answers are the
        # battery working** -- this row is the proof that advertised and working are different
        # questions, and pinning either verdict unconditionally would assert one platform's
        # answer as SFTP's, which is the mistake the whole report exists to stop.
        (
            "lsetstat@openssh.com actually changes a symlink's own mode",
            Verdict.YES if SERVER_CAN_CHMOD_A_SYMLINK else Verdict.NO,
        ),
        # The one the first draft reported as `no` because a 261 KB path hits PATH_MAX.
        ("a request as large as this session would send is accepted", Verdict.YES),
    ],
)
def test_what_the_reference_server_actually_does(tmp_path: Path, fact: str, verdict: Verdict):
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=sftp.sizes_for(b"\x00\x00\x00\x00").write_length,
            write_directory=str(tmp_path).encode(),
            run_id="reference",
        )

    found = next((f for f in report.findings if f.fact == fact), None)
    assert found is not None, f"the battery no longer asks {fact!r}"
    assert found.verdict is verdict, f"{found.answer} -- {found.evidence}"


def test_every_finding_carries_the_exchange_that_produced_it(tmp_path: Path):
    """Constraint three of the card: a bare verdict is a rumour with better formatting."""
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=sftp.sizes_for(b"\x00\x00\x00\x00").write_length,
            write_directory=str(tmp_path).encode(),
            run_id="evidence",
        )

    for finding in report.findings:
        assert finding.evidence, f"{finding.fact} has a verdict and no workings"
        assert finding.answer
        assert finding.answer != finding.fact


def test_check_file_is_absent_from_openssh_so_its_probe_does_not_run(tmp_path: Path):
    """`check-file` is paramiko's spelling and OpenSSH advertises nothing like it.

    An extension probe that ran anyway would report the documented fallback as a failure, which
    is the confident-and-wrong answer the report exists to avoid.
    """
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=4096,
            write_directory=str(tmp_path).encode(),
            run_id="checkfile",
        )

    assert "check-file actually hashes the bytes the server has" not in {
        f.fact for f in report.findings
    }
    assert ProbeLimit.UNADVERTISED_EXTENSIONS in report.undetermined


def test_the_report_carries_no_credential_shaped_material(tmp_path: Path):
    """The same rule the frame dumper and `doctor`'s environment block follow.

    This report is written to be pasted into a message read by a stranger. Nothing it collects
    is a secret today — paths, status codes, extension names, byte counts — and this is what
    notices if something that is ever gets added to a probe's evidence.
    """
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=4096,
            write_directory=str(tmp_path).encode(),
            run_id="redaction",
        )

    rendered = "\n".join(
        [*(f.answer for f in report.findings), *(e for f in report.findings for e in f.evidence)]
    )
    credential_shaped = r"(?i)password|passphrase|secret|token=|BEGIN [A-Z ]*PRIVATE KEY"
    assert not re.search(credential_shaped, rendered)


def test_the_battery_leaves_no_handle_behind(tmp_path: Path):
    """`reaped` counts handles the router closed because nobody claimed them.

    The battery opens several — a write handle per probe, a read handle for `check-file` — and
    a diagnostic that leaked one per run would be reporting on a condition it was causing.
    """
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        _ = compatibility_report(
            sftp,
            request_bytes=4096,
            write_directory=str(tmp_path).encode(),
            run_id="handles",
        )
        assert sftp.reaped == 0


def test_the_write_battery_creates_its_files_private(tmp_path: Path):
    """`0o600` on the wire, checked on the filesystem the server is writing to.

    Asserted by holding the run still: a probe file's mode is only observable while it exists,
    so the battery is driven one probe at a time rather than through the whole report.
    """
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        board = _Scratch(str(tmp_path).encode(), "modes")
        _ = _probe_case_folding(sftp, board)
        created = Path(board.claimed[0].decode())
        mode = created.stat().st_mode & 0o777
        _ = _clean_up(sftp, board)

    assert mode == PROBE_MODE


def test_a_write_battery_pointed_at_a_directory_that_is_not_there_reports_rather_than_raises(
    tmp_path: Path,
):
    """The commonest operator mistake, and it must not cost the read-only half of the report."""
    needs_real_server()

    with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        report = compatibility_report(
            sftp,
            request_bytes=4096,
            write_directory=str(tmp_path / "not-there").encode(),
            run_id="missing",
        )

    write_side = next(f for f in report.findings if f.fact == CASE_FOLDS)
    assert write_side.verdict is Verdict.UNDETERMINED
    read_side = next(f for f in report.findings if f.fact == ROOT_IS_SLASH)
    assert read_side.verdict is Verdict.YES
    assert report.left_behind == ()


def test_a_capability_refusal_is_a_no_rather_than_an_undetermined(tmp_path: Path):
    """`lsetstat` on a server that does not advertise it raises `CapabilityError`, not a status.

    Two exception types mean the same thing to this probe — the extension did not perform —
    and only one of them is a `ServerError`. Catching just that one would report a client-side
    refusal as a probe failure.
    """
    session = StubSession(
        chmod=CapabilityError("this server will not", feature="chmod without following")
    )
    session.advertised.add("lsetstat@openssh.com")

    findings, _ = write_probes(session, directory=b"/s", request_bytes=64, run_id="cap")  # type: ignore[arg-type]

    lsetstat = next(f for f in findings if f.fact.startswith("lsetstat@openssh.com"))
    assert lsetstat.verdict is Verdict.NO
    assert lsetstat.evidence[-1] == "lsetstat PERMISSIONS -> refused by this client"


# --- fuzzing the two pure helpers ---------------------------------------------------------------


@given(
    code=st.sampled_from(list(StatusCode)),
    noise=st.text(alphabet=" _-.:,;()'\"", max_size=12),
    upper=st.booleans(),
)
def test_decorating_a_codes_own_name_still_restates_it(code: StatusCode, noise: str, upper: bool):
    """Punctuation and case are noise, and the normalisation has to keep saying so.

    A server writing `Failure.` or `no_such_file` or `Permission denied (publickey)` -- minus the
    parenthetical, which is content -- is still telling you the status code. This generates the
    decorations rather than listing four of them, because the ones that bite are the spellings
    nobody thought to type.
    """
    spelling = noise.join(code.name.split("_"))
    message = (spelling.upper() if upper else spelling.lower()).encode()
    assume(any(character.isalnum() for character in message.decode()))

    assert restates_the_code(int(code), message) is True


@given(code=st.sampled_from(list(StatusCode)), message=st.binary(max_size=200))
def test_the_message_predicate_survives_arbitrary_server_bytes(code: StatusCode, message: bytes):
    """A `STATUS` message is attacker-controlled input, so this must not be fuzzable to a crash.

    It is also not UTF-8 by requirement -- v3 says the field is a string and says nothing about
    the encoding -- so a decode that raised would take down a diagnostic on exactly the server
    worth diagnosing.
    """
    assert isinstance(restates_the_code(int(code), message), bool)


@given(directory=st.binary(max_size=40), name=st.binary(min_size=1, max_size=40))
def test_uppercasing_a_name_never_touches_the_directory(directory: bytes, name: bytes):
    """The property, over names nobody would think to type: only the last component moves.

    Remote names are bytes and need not be UTF-8, so this generates raw bytes rather than text.
    """
    assume(b"/" not in name)
    path = directory + b"/" + name

    folded = _upper_name(path)

    assert folded.startswith(directory + b"/")
    assert folded[len(directory) + 1 :] == name.upper()


@given(directory=st.binary(max_size=40), name=st.text(alphabet=st.characters(codec="ascii")))
def test_joining_never_produces_a_doubled_separator(directory: bytes, name: str):
    """A trailing slash on the caller's directory is ordinary, and `//` is a different path."""
    joined = _join(directory, name)

    assert b"//" not in joined[: len(directory.rstrip(b"/")) + 1]
    assert joined.endswith(name.encode("ascii"))


# --- the golden report ------------------------------------------------------------------------
#
# **Every test above runs all twelve probes and asserts on one finding** (D-193). They select it
# with `next(f for f in findings if ...)` and let the other eleven be computed and discarded, so a
# mutation in probe X survives unless some row happens to pick X's finding *and* assert the aspect
# the mutation touched. That single shape produced the largest survivor cluster in the repository
# -- 287, more than `session/_session.py` -- and better than half of it is the report's own prose,
# which is the one thing this module exists to emit.
#
# So this is the report pinned whole: every fact, verdict, answer and evidence line for one known
# server, in both directions. It is `tests/fixtures/`'s golden-frame discipline applied to the
# report instead of to packets, and it is the only artifact here that fails when a probe's wording
# drifts.
#
# **The golden was generated and then read, which is not the same as generated.** An expectation
# computed with the code under test encodes whatever that code does, including its bugs -- and
# this one did: reviewing the twelve lines found `_probe_case_folding`'s YES branch naming the
# hazard of the NO case, fixed in the same change and regression-tested below. Generating without
# reading would have made the defect the expected value and locked it in permanently.


PROBE_DIRECTORY = b"/incoming/scratch"


def capable_stub() -> StubSession:
    """A server that advertises every extension this library implements, and answers.

    Chosen over a refusing stub because it reaches the most probes: a refusal short-circuits a
    probe into one line of evidence, and what needs pinning is the prose each one emits when it
    has something to say. `readlink` answers with the lsetstat probe's own target so that probe
    reaches its judgement rather than failing on the link.
    """
    session = StubSession(
        readlink=PROBE_DIRECTORY + b"/" + PROBE_PREFIX.encode() + b"t0ken-lsetstat-target"
    )
    session.advertised.update(
        {
            EXTENSION_POSIX_RENAME,
            EXTENSION_FSYNC,
            EXTENSION_LSETSTAT,
            EXTENSION_CHECK_FILE,
            EXTENSION_LIMITS,
        }
    )
    return session


GOLDEN_WRITE_BATTERY: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=("REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe'",),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a path "
            "built by joining strings will not mean what it looks like"
        ),
        evidence=("REALPATH b'/' -> b'/home/probe'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.UNDETERMINED,
        answer=(
            "this server accepted a request where a refusal was expected, so there was no pair of "
            "refusals to read"
        ),
        evidence=("STAT b'/home/probe/gantry-probe-t0ken-absent' -> accepted",),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than anything "
            "the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.YES,
        answer=(
            "the same file answered to a different case, so remote names that differ only in case "
            "will collide here -- and an upload of two local names differing only in case lands "
            "as one file, the second overwriting the first"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> found",
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. Treat any "
            "rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.YES,
        answer="the mtime that was set is the mtime that came back",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-times'",
            "SETSTAT ACMODTIME=1000000000 -> OK",
            "STAT -> mtime=1000000000",
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.YES,
        answer="the target was replaced in one step, which is what atomic publish needs",
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OK",
            "STAT b'/incoming/scratch/gantry-probe-t0ken-posix-source' -> gone",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.YES,
        answer="the server flushed the handle, so a durable upload can be asked for here",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> OK",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.NO,
        answer=(
            "the server answered OK and neither mode changed, so the request was accepted and "
            "discarded. That is worse than the refusal OpenSSH gives on the same kernel: a caller "
            "is told their permission change happened when it did not"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-lsetstat-target' at 0o600 and "
                "symlink b'/incoming/scratch/gantry-probe-t0ken-lsetstat-link' -> it"
            ),
            "lsetstat PERMISSIONS -> OK",
            "LSTAT of the link -> 0o777",
            "STAT of the target -> 0o600",
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed here, so "
            "content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)


def golden_report() -> CompatibilityReport:
    """The report `GOLDEN_WRITE_BATTERY` describes, built the way a caller would build one."""
    return compatibility_report(
        capable_stub(),  # type: ignore[arg-type]
        request_bytes=4096,
        write_directory=PROBE_DIRECTORY,
        run_id="t0ken",
    )


def fact_id(finding: Finding) -> str:
    """A pytest id that is ASCII and has no spaces.

    The facts are sentences with apostrophes, slashes and `@` in them, and mutmut aborts the
    whole lane on an exotic parametrize id rather than skipping the row -- so the ids are
    slugged here instead of being the facts themselves.
    """
    return "".join(c if c.isalnum() else "-" for c in finding.fact.lower()).strip("-")[:44]


def test_the_golden_names_exactly_the_findings_the_battery_produces():
    """Both directions and the order, because a golden that only checks its own rows is blind.

    A probe added to `_EXTENSION_PROBES` and not here would leave every row below passing, and a
    probe deleted would leave a row here asserting about a finding nobody produces.
    """
    produced = [finding.fact for finding in golden_report().findings]

    assert produced == [finding.fact for finding in GOLDEN_WRITE_BATTERY]


@pytest.mark.parametrize("expected", GOLDEN_WRITE_BATTERY, ids=fact_id)
def test_the_report_matches_the_golden_finding_for_finding(expected: Finding):
    """Compared whole rather than field by field, so evidence order and count are pinned too."""
    produced = {finding.fact: finding for finding in golden_report().findings}

    assert produced[expected.fact] == expected

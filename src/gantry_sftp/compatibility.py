"""Does this library work against *your* server, and where does it not (D-165).

    python -m gantry_sftp doctor sftp.example.com
    python -m gantry_sftp doctor sftp.example.com --probe-writes /incoming/scratch

**The endpoints this library exists for are the ones it can never measure.** MOVEit,
GoAnywhere, Cleo, Sterling and the mainframe middleware behind them belong to somebody's
employer, sit behind a VPN, and advertise none of the extensions the reference implementation
does. No maintainer can start one, so ``live-tests/matrix.py`` covers the three servers that
can be started in a container and the interesting ones are permanently outside it. The people
who *can* reach them have had no way to produce evidence in a form this project accepts.

This module is that form. It runs a battery against a live endpoint and returns, per fact, a
verdict and **the exchange that produced it** -- so what comes back is an argument somebody
who was not there can review, rather than a claim.

**This is not a quirks registry, and nothing it emits changes what the library does.** The
card it comes from began as one; the recon found there is no registry to contribute to and
that a profile was never the artifact anybody wanted --
:mod:`gantry_sftp.session._quirks` is a fingerprint on purpose, because the matrix measured
the behavioural overrides DESIGN §7 proposed and none of them had a case to fix. What a user
with an unreachable endpoint needs is an answer to "does this work against my server"; what
the maintainer needs back is the same answer with its workings attached. Neither needs a
registry. If a behavioural override ever earns its place it arrives the way CLAUDE.md says,
with the fixture that proves it -- and this report is what would produce that fixture.

Three constraints shaped every decision below, because the people who can run this will run it
against a system their employer depends on.

**Safe to point at production, by default.** The read-only battery makes no writes at all: it
canonicalises paths that cannot exist, reads two refusals, and sends one request no larger than
this session's own transfers already send. Everything that creates, renames or removes is
behind :func:`write_probes` and a directory the caller nominates by name. A probe that needs a
maintenance window will not be run, and a probe that surprises somebody is run once.

**It reports what it could not determine.** "This server does not fold case" and "I could not
find out whether this server folds case" are different answers, and collapsing them produces
exactly the confident-and-wrong artifact this exists to prevent. So there are two mechanisms
and they mean different things: a :attr:`Verdict.UNDETERMINED` finding is *we asked and could
not tell*, and :attr:`CompatibilityReport.undetermined` is *we did not ask, and here is why*.
The second copies :class:`~gantry_sftp.session.TreePlan`'s shape, which D-163 built for a dry
run and which now has two consumers rather than one.

**Reviewable by someone who was not there.** Every :class:`Finding` carries the exchange. A
bare verdict is a rumour with better formatting.

Nothing here can carry a credential: the evidence lines are paths, status codes, the server's
own message text, extension names and byte counts. No argument to this module is a secret and
none of it reads the environment -- the connection was made before it was called.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from typing import TYPE_CHECKING

from gantry_sftp.codec import (
    EXTENSION_CHECK_FILE,
    EXTENSION_FSYNC,
    EXTENSION_LIMITS,
    EXTENSION_LSETSTAT,
    EXTENSION_POSIX_RENAME,
    IMPLEMENTED_EXTENSIONS,
    OpenFlag,
    StatusCode,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    ServerError,
    SFTPError,
)

if TYPE_CHECKING:
    # Typing only, and the direction is what makes that safe rather than an economy: this
    # module and `sync` are both in the ergonomics layer, so a real import would be legal --
    # it is just a portal, a thread and an event loop imported by anything that wanted the
    # type. The battery is handed a live session; it never makes one.
    from gantry_sftp.sync import SyncSession

__all__ = [
    "CODE_IN_PROSE",
    "PROBE_MODE",
    "PROBE_PREFIX",
    "PROBE_TIMESTAMP",
    "CompatibilityReport",
    "Finding",
    "ProbeLimit",
    "Verdict",
    "compatibility_report",
    "read_only_probes",
    "restates_the_code",
    "write_probes",
]

PROBE_PREFIX = "gantry-probe"
"""First component of every name the write battery creates.

Deliberately a word rather than a dot-file: an operator who finds one of these left behind
after a killed run should be able to tell what made it from the name alone, and a hidden file
is the opposite of that. It is also why the prefix has letters in it -- the case-folding probe
uppercases a name it created and asks for it back, so a name that were all digits would be its
own uppercase and would report folding on a server that does not fold. That property is
asserted in ``tests/test_compatibility.py`` rather than guarded for at run time.
"""

PROBE_MODE = 0o600
"""Permission bits every file the write battery creates is opened with.

**Never omitted, and that is a security fact rather than tidiness.** OPEN's ATTRS are how a
file's mode is set at creation; sending none leaves the server applying its own default, which
for OpenSSH is ``0666 & ~umask`` -- so a probe that skipped this would scatter world-readable
files through a directory somebody's employer depends on. The files are removed either way;
the window between creation and removal is the part that would not have been.
"""

_LSETSTAT_PROBE_MODE = 0o640
"""What the ``lsetstat`` probe sets, and it must differ from :data:`PROBE_MODE`.

The probe creates a file at ``PROBE_MODE``, points a symlink at it, and asks for the *link's*
mode to become this. If the target comes back wearing it, the server followed the link. Two
equal values would make a followed link and an untouched one look identical -- and the
followed one is the hazard.
"""

PROBE_TIMESTAMP = 1_000_000_000
"""The mtime the timestamp probe sets, in seconds since the epoch (2001-09-09).

A fixed value in the past rather than "now", for two reasons. A server that ignores
``SETSTAT``'s ``ACMODTIME`` entirely leaves the file's creation time in place, and a creation
time is indistinguishable from a *just now* that was honoured -- so "now" cannot tell the two
apart. And it fits filexfer v3's ``uint32`` seconds with two decades to spare, which
a value derived from the clock will stop doing in 2106.
"""

CODE_IN_PROSE: Mapping[StatusCode, tuple[str, ...]] = {
    StatusCode.NO_SUCH_FILE: ("nosuchfileordirectory",),
    StatusCode.OP_UNSUPPORTED: ("operationunsupported",),
}
"""Other ways a server spells a status code out, normalised the way `restates_the_code` is.

**Every entry was read off a running server**, which is what keeps this from being a list of
things that felt like synonyms. Without it the probe reports paramiko as having informative
messages on the strength of ``'Operation unsupported'`` for ``OP_UNSUPPORTED`` -- which is the
code with its abbreviation expanded and nothing else -- and contradicts the fingerprint that
was set by measuring the same server.

* ``'No such file or directory'`` is ``strerror(ENOENT)``, sent by asyncssh.
* ``'Operation unsupported'`` is sent by paramiko.

The code's own name is matched without being listed, so this holds only the spellings that
are *not* mechanical. It is small on purpose: a long list here would be the probe deciding in
advance what servers are allowed to say, which is the opposite of measuring them.
"""

_CHECK_FILE_PAYLOAD = b"gantry-sftp check-file probe\n"
"""What the ``check-file`` probe writes, so the digest can be computed on this side too.

Short on purpose: it has to fit inside one ``check-file`` block, and the block size this
library uses is bounded by paramiko's, which wedges permanently above 64 KiB.
"""


class Verdict(StrEnum):
    """What a probe established.

    Three states, and the third is the point. A predicate here has the same three the rest of
    this library insists on -- true, false, and *could not find out* -- and a report that
    offered only the first two would answer every question it failed to ask.
    """

    YES = "yes"
    """The fact holds, and :attr:`Finding.evidence` is the exchange that showed it."""

    NO = "no"
    """The fact does not hold. Also an answer, and frequently the useful one."""

    UNDETERMINED = "undetermined"
    """The probe ran and could not tell. Never a stand-in for a probe that was not run."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One fact, its verdict, and the exchange that produced it.

    Attributes:
        fact: The question, phrased so that ``yes`` and ``no`` are both unambiguous. "REALPATH
            canonicalises a path that does not exist" can be answered either way; "REALPATH
            behaviour" cannot.
        verdict: What was established.
        answer: The verdict in words, including what it means for a caller.
        evidence: The exchange, one line per round trip -- request, then what came back. This
            is what makes the report reviewable by somebody who was not there, and it is why
            a refusal records the status code *and* the server's own message rather than the
            rendered exception alone.
    """

    fact: str
    verdict: Verdict
    answer: str
    evidence: tuple[str, ...] = field(default_factory=tuple)


class ProbeLimit:
    """What a run did not find out, and why.

    Strings rather than an enum, copying :class:`~gantry_sftp.session.PlanLimit`: these are for
    a human reading a report, and the set grows with what a battery declines to do rather than
    with anything the protocol defines.

    **Every member here exists because a diagnostic is pointed at production.** A report that
    stated these as facts would be guessing; a report that omitted them would read as though it
    had checked.
    """

    WRITE_PROBES_NOT_REQUESTED = (
        "whether names fold case, whether RENAME replaces an existing target and whether a "
        "file's timestamps survive: not probed, because each of them is established by "
        "writing and no directory was nominated. Re-run with a directory you are content to "
        "have files created and removed in"
    )
    EXTENSIONS_NEEDING_A_WRITE = (
        "whether these advertised extensions actually perform, as opposed to being "
        "advertised: not probed, because the only way to find out is to do the thing. They "
        "are {names}"
    )
    LARGEST_REQUEST_NEEDS_A_WRITE = (
        "whether a request the size this session derived is accepted whole: not probed, "
        "because there is no read-only instrument for it. Every request that is not a WRITE "
        "carries its size in a path, and a path hits the server's name limit long before its "
        "packet limit -- so a read-only version of this measures PATH_MAX and reports it as a "
        "packet ceiling"
    )
    UNADVERTISED_EXTENSIONS = (
        "whether an extension this server did not advertise would nevertheless work: not "
        "probed, because the advertisement is taken at its word and every one of them has a "
        "documented fallback -- so a server implementing one silently costs a slower path "
        "rather than a wrong answer"
    )
    CEILING_ABOVE_THIS_SESSION = (
        "the largest request this server would accept, as opposed to whether it accepts the "
        "largest one this session would send: not probed, because finding the true ceiling "
        "means sending packets bigger than any transfer would, and a diagnostic must not be "
        "the thing that trips an appliance"
    )
    BEHAVIOUR_UNDER_LOAD = (
        "how this server behaves at pipeline depth, on a shaped link, or against a file big "
        "enough to matter: not probed, because that means moving somebody's data. "
        "`benchmarks/` and the netem lane are where those questions are asked, and both need "
        "a server the person asking controls"
    )


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    """What a battery established about one server.

    Attributes:
        findings: Every fact probed, in the order probed, each with its evidence.
        undetermined: What this run did not ask about, in :class:`ProbeLimit`'s words. Distinct
            from a :attr:`Verdict.UNDETERMINED` finding, which is a question that *was* asked
            and could not be answered.
        wrote_into: The directory the write battery was pointed at, or ``None`` when it did not
            run. Recorded rather than inferred from the findings, so a report says plainly
            whether anything was created and where.
        left_behind: Paths the battery created and could not remove, with the reason. Empty is
            a claim -- every name is registered before the request that would create it, so a
            create whose answer was lost is still cleaned up and still reported here if the
            removal fails too.
    """

    findings: tuple[Finding, ...] = field(default_factory=tuple)
    undetermined: tuple[str, ...] = field(default_factory=tuple)
    wrote_into: str | None = None
    left_behind: tuple[str, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        """Whether every fact this run probed came back with a yes or a no.

        **About the findings alone**, deliberately, the same way
        :attr:`~gantry_sftp.session.TreePlan.complete` is about what a plan would skip rather
        than about what it declined to look at. :attr:`undetermined` is never empty -- a
        read-only run always has questions it did not ask -- so folding it in here would make
        this constant and useless.
        """
        return bool(self.findings) and all(
            finding.verdict is not Verdict.UNDETERMINED for finding in self.findings
        )


def _join(directory: bytes, name: str) -> bytes:
    """A child of ``directory``, without doubling a separator the caller already supplied."""
    return directory.rstrip(b"/") + b"/" + name.encode("ascii")


def _upper_name(path: bytes) -> bytes:
    """``path`` with its **last component only** uppercased.

    The directory is left alone on purpose. It is the caller's own path, it may sit under a
    parent whose case matters, and folding it would ask a different question -- whether the
    whole path folds -- while reporting the answer as though it were about the name.
    """
    directory, separator, name = path.rpartition(b"/")
    return directory + separator + name.upper()


def _refusal(failure: ServerError) -> str:
    """A refusal as one evidence line: the code, and the server's own words where it sent any.

    The message is quoted verbatim and separately from the code, because whether there is
    anything in it is itself one of the facts this report probes -- most servers send a
    constant, and a rendered exception hides that behind our own summary text.
    """
    code = StatusCode(failure.code).name
    if not failure.message:
        return f"{code}, no message"
    return f"{code}, server said {failure.message.decode('utf-8', 'replace')!r}"


def _guarded(fact: str, probe: Callable[[], Finding]) -> Finding:
    """Run one probe, turning a failure of the probe itself into an honest non-answer.

    **The single most important function here.** A diagnostic that dies on the condition it was
    run to diagnose has nothing to say about the only case that matters, and a battery of
    fifteen probes against an unfamiliar endpoint is fifteen chances to find that condition.
    So a probe that raises costs one undetermined finding and the rest of the battery still
    runs.

    ``OSError`` is caught alongside ``SFTPError`` because a dead connection arrives as one:
    everything after such a probe will be undetermined too, which is itself the finding.

    Args:
        fact: The question, for the finding this returns on a failure.
        probe: The probe. Called once.

    Returns:
        Whatever the probe returned, or an :attr:`Verdict.UNDETERMINED` finding carrying the
        failure as its evidence.
    """
    try:
        return probe()
    except (SFTPError, OSError) as failure:
        return Finding(
            fact=fact,
            verdict=Verdict.UNDETERMINED,
            answer="the probe itself failed, so this server's behaviour is not established",
            evidence=(f"{type(failure).__name__}: {failure}",),
        )


# --- the read-only battery ----------------------------------------------------------------


_REALPATH_MISSING = "REALPATH canonicalises a path that does not exist"
_ROOT_IS_SLASH = "the root of this server's namespace is /"
_MESSAGES_INFORMATIVE = "a refusal carries a message that says more than its status code"
_LIMITS_USABLE = "limits@openssh.com answers with a usable maximum"
_LARGEST_REQUEST = "a request as large as this session would send is accepted"


def _probe_realpath_of_a_missing_path(sftp: SyncSession, directory: bytes, run_id: str) -> Finding:
    """Whether a name that is not there can still be canonicalised.

    The answer decides whether a caller can resolve a path *before* creating it, which is what
    an upload wants to do. OpenSSH canonicalises and answers with a name; other servers refuse,
    and a client that assumed the first has no way to ask "where would this end up".
    """
    missing = _join(directory, f"{PROBE_PREFIX}-{run_id}-absent")
    try:
        canonical = sftp.realpath(missing)
    except ServerError as refusal:
        return Finding(
            fact=_REALPATH_MISSING,
            verdict=Verdict.NO,
            answer=(
                "this server refuses to canonicalise a name that does not exist, so a path "
                "has to be created before it can be resolved"
            ),
            evidence=(f"REALPATH {missing!r} -> {_refusal(refusal)}",),
        )
    return Finding(
        fact=_REALPATH_MISSING,
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=(f"REALPATH {missing!r} -> {canonical!r}",),
    )


def _probe_root_shape(sftp: SyncSession) -> Finding:
    """Whether ``/`` is a path on this server at all.

    Not universal, and the exceptions are exactly the endpoints this report exists for:
    a mainframe gateway may root its namespace at a dataset qualifier, and a virtualised
    appliance may expose a list of shares where a filesystem would have a root.
    """
    try:
        canonical = sftp.realpath(b"/")
    except ServerError as refusal:
        return Finding(
            fact=_ROOT_IS_SLASH,
            verdict=Verdict.NO,
            answer="this server refuses / outright, so absolute paths here are not POSIX paths",
            evidence=(f"REALPATH b'/' -> {_refusal(refusal)}",),
        )
    if canonical == b"/":
        return Finding(
            fact=_ROOT_IS_SLASH,
            verdict=Verdict.YES,
            answer="/ canonicalises to itself, as on a POSIX filesystem",
            evidence=("REALPATH b'/' -> b'/'",),
        )
    return Finding(
        fact=_ROOT_IS_SLASH,
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a "
            "path built by joining strings will not mean what it looks like"
        ),
        evidence=(f"REALPATH b'/' -> {canonical!r}",),
    )


def _probe_message_quality(sftp: SyncSession, directory: bytes, run_id: str) -> Finding:
    """Whether this server's refusals say anything the status code did not.

    The answer decides whether an operator can route on the text or has only the status code,
    and v3's ``FAILURE`` is a catch-all -- so on a server whose messages say nothing, five
    unrelated conditions are indistinguishable from each other.

    **Two refusals rather than one, because one is a sample of size one.** Both are read-only
    and harmless: a ``STAT`` of a name that cannot exist, and a ``READLINK`` of a directory,
    which is not a link. The verdict comes from :func:`restates_the_code` rather than from
    comparing the two against each other -- see there for the wrong answer that produced.
    """
    missing = _join(directory, f"{PROBE_PREFIX}-{run_id}-absent")
    asks = (
        (f"STAT {missing!r}", partial(sftp.stat, missing)),
        (f"READLINK {directory!r}", partial(sftp.readlink, directory)),
    )
    exchanges: list[str] = []
    refusals: list[tuple[int, bytes]] = []
    for description, ask in asks:
        try:
            _ = ask()
        except ServerError as refusal:
            exchanges.append(f"{description} -> {_refusal(refusal)}")
            refusals.append((refusal.code, refusal.message))
        else:
            return Finding(
                fact=_MESSAGES_INFORMATIVE,
                verdict=Verdict.UNDETERMINED,
                answer=(
                    "this server accepted a request where a refusal was expected, so there "
                    "was no pair of refusals to read"
                ),
                evidence=(*exchanges, f"{description} -> accepted"),
            )
    exchanges.append(
        f"this library's fingerprint for {sftp.profile.label} claims "
        f"informative_messages={sftp.profile.informative_messages}"
    )
    return _judge_messages(refusals, tuple(exchanges))


def restates_the_code(code: int, message: bytes) -> bool:
    """Whether a ``STATUS`` message is the code's own name spelled out in prose.

    **The measurement this probe turns on, and it took a wrong answer against the reference to
    arrive at.** The first version compared two refusals with *different* codes and called them
    informative when the text differed -- against OpenSSH that reads ``'No such file'`` and
    ``'Bad message'``, calls them different, and reports the most famously contentless error
    text in the ecosystem as worth reading. They differ because the *codes* differ. What makes
    a message worth reading is saying something the code did not, and that is answerable from
    one refusal.

    Compared with punctuation and case removed, so ``NO_SUCH_FILE`` matches ``No such file``
    and ``no such file.`` alike, plus the spellings in :data:`CODE_IN_PROSE`. asyncssh's
    ``'File already exists'`` under ``FAILURE`` does not match, which is the case this exists
    to find.

    Args:
        code: The ``SSH_FX_*`` status, which is always a defined one by the time an error
            carries it -- the decoder degrades anything else and records the raw value.
        message: The server's own text, verbatim and undecoded.

    Returns:
        ``True`` when the text adds nothing, including when there is no text at all.
    """
    text = message.decode("utf-8", "replace")
    normalised = "".join(character for character in text.lower() if character.isalnum())
    status = StatusCode(code)
    return normalised == status.name.lower().replace("_", "") or normalised in CODE_IN_PROSE.get(
        status, ()
    )


def _judge_messages(refusals: list[tuple[int, bytes]], evidence: tuple[str, ...]) -> Finding:
    """Turn the captured refusals into the verdict, kept apart from the round trips."""
    silent = [code for code, message in refusals if not message]
    if silent:
        return Finding(
            fact=_MESSAGES_INFORMATIVE,
            verdict=Verdict.NO,
            answer=(
                "at least one refusal carried no message at all, so the status code is all "
                "there is to route on"
            ),
            evidence=evidence,
        )
    if all(restates_the_code(code, message) for code, message in refusals):
        return Finding(
            fact=_MESSAGES_INFORMATIVE,
            verdict=Verdict.NO,
            answer=(
                "every refusal spelled out its own status code and nothing else, so the text "
                "is a constant function of the code and reading it is reading the code twice"
            ),
            evidence=evidence,
        )
    return Finding(
        fact=_MESSAGES_INFORMATIVE,
        verdict=Verdict.YES,
        answer=(
            "a refusal said something its status code did not, so this server's message text "
            "is worth reading and worth quoting in a bug report"
        ),
        evidence=evidence,
    )


def _probe_limits(sftp: SyncSession) -> Finding:
    """Whether an advertised ``limits@openssh.com`` answered with a number anybody can use.

    A returned ``0`` means *no limit stated*, which this library stores as ``None`` and
    replaces with a conservative default -- so a server that advertises the extension and
    answers zero for everything has told us nothing, and the session is running on its own
    guess. That is worth saying out loud, because it looks identical to a negotiated limit
    from the outside.
    """
    limits = sftp.limits
    stated = {
        "max_packet_length": limits.max_packet_length,
        "max_read_length": limits.max_read_length,
        "max_write_length": limits.max_write_length,
        "max_open_handles": limits.max_open_handles,
    }
    evidence = tuple(
        f"limits@openssh.com {name} -> {'no limit stated' if value is None else value}"
        for name, value in stated.items()
    )
    if any(value is not None for value in stated.values()):
        return Finding(
            fact=_LIMITS_USABLE,
            verdict=Verdict.YES,
            answer="the extension was advertised, was answered, and named at least one maximum",
            evidence=evidence,
        )
    return Finding(
        fact=_LIMITS_USABLE,
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than "
            "anything the server agreed to"
        ),
        evidence=evidence,
    )


def read_only_probes(sftp: SyncSession, *, directory: bytes, run_id: str) -> list[Finding]:
    """The battery that makes no writes.

    **It takes no request size, and that absence is a measurement.** The obvious read-only way
    to ask whether this session's request size is accepted is a ``REALPATH`` of a name that
    long -- and against the reference server it answers ``BAD_MESSAGE`` for a reason that has
    nothing to do with packets: Linux caps a path at 4096 bytes, two orders of magnitude below
    the packet ceiling, so *every* read-only request is bounded by a name limit long before it
    is bounded by a message limit. A probe reporting "no" against OpenSSH for that reason is
    noise wearing a finding's clothes. The question lives in :func:`write_probes`, where a
    ``WRITE`` carries data rather than a name, and
    :data:`ProbeLimit.LARGEST_REQUEST_NEEDS_A_WRITE` says so when that battery is off.

    Args:
        sftp: A live session. Nothing here changes it: no ``chdir``, no handles left open.
        directory: Where the harmless non-existent names are built. The session's own start
            directory when the caller has not nominated somewhere else.
        run_id: Distinguishes one run's scratch names from another's.

    Returns:
        One finding per fact.
    """
    findings = [
        _guarded(
            _REALPATH_MISSING,
            partial(_probe_realpath_of_a_missing_path, sftp, directory, run_id),
        ),
        _guarded(_ROOT_IS_SLASH, partial(_probe_root_shape, sftp)),
        _guarded(_MESSAGES_INFORMATIVE, partial(_probe_message_quality, sftp, directory, run_id)),
    ]
    if sftp.supports(EXTENSION_LIMITS):
        findings.append(_guarded(_LIMITS_USABLE, partial(_probe_limits, sftp)))
    return findings


# --- the write battery, which is opt-in and nominated -------------------------------------


_CASE_FOLDS = "this server folds case in names"
_RENAME_REPLACES = "RENAME replaces an existing target"
_POSIX_RENAME_HONOURED = "posix-rename@openssh.com actually renames"
_TIMES_SURVIVE = "a file's timestamps survive being set"
_FSYNC_HONOURED = "fsync@openssh.com actually flushes"
_LSETSTAT_HONOURED = "lsetstat@openssh.com actually changes a symlink's own mode"
_CHECK_FILE_HONOURED = "check-file actually hashes the bytes the server has"


class _Scratch:
    """The names a write battery may create, registered before anything creates them.

    **The registration happens at :meth:`claim`, not after a successful create, and that is
    the point.** A request whose answer never arrives -- a killed connection, a timeout -- may
    still have been performed, so a cleanup list built from *successful* creates is a cleanup
    list that misses exactly the files nobody wanted left behind. Every name is on the list
    from the moment it might exist.
    """

    def __init__(self, directory: bytes, run_id: str) -> None:
        self._directory = directory
        self._run_id = run_id
        self.claimed: list[bytes] = []

    def claim(self, suffix: str) -> bytes:
        """Register a name and return it. Call this *before* the request that creates it."""
        path = _join(self._directory, f"{PROBE_PREFIX}-{self._run_id}-{suffix}")
        self.claimed.append(path)
        return path


def _create(sftp: SyncSession, path: bytes, contents: bytes = b"") -> None:
    """Create a file that must not already exist, with the mode :data:`PROBE_MODE` names."""
    handle = sftp.open(path, OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL, mode=PROBE_MODE)
    try:
        if contents:
            _ = sftp.write_at(handle, 0, contents)
    finally:
        sftp.close(handle)


def _probe_case_folding(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether the server hands back a file asked for in a different case.

    The hazard this answers is a download that merges two remote names into one local file, and
    the mirror of it on the way up. It cannot be answered by looking: it is a property of the
    server's filesystem, not of the protocol, and the only instrument is to create a name and
    ask for its uppercase.
    """
    path = scratch.claim("case-aA")
    _create(sftp, path)
    folded = _upper_name(path)
    try:
        _ = sftp.stat(folded)
    except NoSuchFileError as refusal:
        return Finding(
            fact=_CASE_FOLDS,
            verdict=Verdict.NO,
            answer=(
                "names are case-sensitive here, so two names differing only in case are two "
                "separate files"
            ),
            evidence=(f"created {path!r}", f"STAT {folded!r} -> {_refusal(refusal)}"),
        )
    return Finding(
        fact=_CASE_FOLDS,
        verdict=Verdict.YES,
        answer=(
            "the same file answered to a different case, so remote names that differ only in "
            "case will collide here -- and a recursive download from a case-sensitive server "
            "can overwrite its own output"
        ),
        evidence=(f"created {path!r}", f"STAT {folded!r} -> found"),
    )


def _probe_rename_replaces(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether plain ``RENAME`` clobbers a target that is already there.

    The draft says it must not, POSIX ``rename(2)`` says it must, and real servers do both --
    which is why atomic publish uses ``posix-rename@openssh.com`` where it exists and refuses
    to pretend otherwise where it does not.
    """
    source = scratch.claim("rename-source")
    target = scratch.claim("rename-target")
    _create(sftp, source)
    _create(sftp, target)
    try:
        sftp.rename(source, target)
    except ServerError as refusal:
        return Finding(
            fact=_RENAME_REPLACES,
            verdict=Verdict.NO,
            answer=(
                "RENAME onto an existing name is refused, as the draft requires. Publishing "
                "over an existing file here needs posix-rename@openssh.com, or a remove first "
                "with the window that opens"
            ),
            evidence=(f"created {source!r} and {target!r}", f"RENAME -> {_refusal(refusal)}"),
        )
    return Finding(
        fact=_RENAME_REPLACES,
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. "
            "Treat any rename here as destructive"
        ),
        evidence=(f"created {source!r} and {target!r}", "RENAME -> OK, the target was replaced"),
    )


def _probe_posix_rename(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether an advertised ``posix-rename@openssh.com`` does what it says.

    Atomic publish rests on this one, so "advertised" is not good enough: the probe renames
    onto an existing target and then confirms the source is gone, because a server that
    answered OK and did nothing would otherwise read as a success.
    """
    source = scratch.claim("posix-source")
    target = scratch.claim("posix-target")
    _create(sftp, source)
    _create(sftp, target)
    try:
        performed = sftp.posix_rename_if_supported(source, target)
    except ServerError as refusal:
        return Finding(
            fact=_POSIX_RENAME_HONOURED,
            verdict=Verdict.NO,
            answer="the extension is advertised and this server refused the request",
            evidence=(f"created {source!r} and {target!r}", f"posix-rename -> {_refusal(refusal)}"),
        )
    if not performed:
        return Finding(
            fact=_POSIX_RENAME_HONOURED,
            verdict=Verdict.NO,
            answer=(
                "the extension is advertised and the server answered OP_UNSUPPORTED, so "
                "atomic publish falls back and says so rather than pretending"
            ),
            evidence=(f"created {source!r} and {target!r}", "posix-rename -> OP_UNSUPPORTED"),
        )
    moved = not sftp.exists(source)
    return Finding(
        fact=_POSIX_RENAME_HONOURED,
        verdict=Verdict.YES if moved else Verdict.NO,
        answer=(
            "the target was replaced in one step, which is what atomic publish needs"
            if moved
            else "the server answered OK and the source is still there, so nothing was renamed"
        ),
        evidence=(
            f"created {source!r} and {target!r}",
            "posix-rename -> OK",
            f"STAT {source!r} -> {'gone' if moved else 'still present'}",
        ),
    )


def _probe_timestamps(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether ``SETSTAT``'s ``ACMODTIME`` is honoured or quietly dropped.

    Kevin has hit this in production and it is why transfers preserve times explicitly rather
    than trusting a server to carry them: a server that ignores the flag answers ``OK`` and
    leaves the file's own creation time, which looks exactly like success.
    """
    path = scratch.claim("times")
    _create(sftp, path)
    sftp.utime(path, PROBE_TIMESTAMP, PROBE_TIMESTAMP)
    times = sftp.stat(path).times
    if times is None:
        return Finding(
            fact=_TIMES_SURVIVE,
            verdict=Verdict.UNDETERMINED,
            answer="this server reported no times at all, so there was nothing to compare",
            evidence=(
                f"created {path!r}",
                f"SETSTAT ACMODTIME={PROBE_TIMESTAMP} -> OK",
                "STAT -> no times reported",
            ),
        )
    survived = times.mtime == PROBE_TIMESTAMP
    return Finding(
        fact=_TIMES_SURVIVE,
        verdict=Verdict.YES if survived else Verdict.NO,
        answer=(
            "the mtime that was set is the mtime that came back"
            if survived
            else "the server accepted the request and kept a different mtime, so preserve_times "
            "cannot be relied on here and a mirror must compare on size or content"
        ),
        evidence=(
            f"created {path!r}",
            f"SETSTAT ACMODTIME={PROBE_TIMESTAMP} -> OK",
            f"STAT -> mtime={times.mtime}",
        ),
    )


def _probe_fsync(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether an advertised ``fsync@openssh.com`` reaches the server's disk."""
    path = scratch.claim("fsync")
    handle = sftp.open(path, OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL, mode=PROBE_MODE)
    try:
        _ = sftp.write_at(handle, 0, _CHECK_FILE_PAYLOAD)
        performed = sftp.fsync_if_supported(handle)
    finally:
        sftp.close(handle)
    return Finding(
        fact=_FSYNC_HONOURED,
        verdict=Verdict.YES if performed else Verdict.NO,
        answer=(
            "the server flushed the handle, so a durable upload can be asked for here"
            if performed
            else "the extension is advertised and the server would not perform it, so a "
            "transfer that asked for durability gets the documented refusal instead"
        ),
        evidence=(f"created {path!r}", f"fsync -> {'OK' if performed else 'not performed'}"),
    )


def _probe_lsetstat(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether an advertised ``lsetstat@openssh.com`` can change a symlink's own mode.

    **The headline case for this whole report.** OpenSSH advertises the extension and, on
    Linux, its permissions branch cannot succeed at all: there is no ``lchmod``, so
    ``fchmodat(AT_SYMLINK_NOFOLLOW)`` answers ``ENOTSUP`` and the server maps that to a
    contentless ``FAILURE``. Advertised and working are different questions, and this is the
    one already proved to have different answers.

    **An ``OK`` is not taken at its word, and the matrix is why.** asyncssh's server answers
    ``OK`` here on the same Linux kernel where OpenSSH's refuses -- and measuring what
    actually moved found that *nothing* did. Believing the status would have reported the one
    server that silently discards the request as the one server where the extension works.
    :func:`_judge_lsetstat` is the check.
    """
    target = scratch.claim("lsetstat-target")
    link = scratch.claim("lsetstat-link")
    _create(sftp, target)
    sftp.symlink(target, link)
    made = (f"created {target!r} at {PROBE_MODE:#o} and symlink {link!r} -> it",)
    try:
        sftp.chmod(link, _LSETSTAT_PROBE_MODE, follow_symlinks=False)
    except (CapabilityError, ServerError) as refusal:
        detail = _refusal(refusal) if isinstance(refusal, ServerError) else "refused by this client"
        return Finding(
            fact=_LSETSTAT_HONOURED,
            verdict=Verdict.NO,
            answer=(
                "advertised and refused. On a Linux server this is unconditional and is not a "
                "misconfiguration: the kernel has no lchmod, a symlink's own mode is ignored "
                "there, and the times and owner of a link can still be set"
            ),
            evidence=(*made, f"lsetstat PERMISSIONS -> {detail}"),
        )
    return _judge_lsetstat(sftp, target, link, made)


def _judge_lsetstat(
    sftp: SyncSession, target: bytes, link: bytes, made: tuple[str, ...]
) -> Finding:
    """Decide what an ``OK`` from ``lsetstat`` actually did, by looking at both files.

    **Three outcomes, and only one of them is the extension working.** An ``OK`` on its own
    distinguishes none of them, which is why this looks: the link may have taken the mode
    (the extension works), the *target* may have taken it (the link was followed, which is
    what the caller asked not to happen), or neither may have changed (the server accepted the
    request and did nothing). asyncssh on Linux is the third, measured -- and reported as a
    ``no``, because a caller who cannot tell that apart from success has no way to know their
    permission change never happened.
    """
    on_link = (sftp.lstat(link).permissions or 0) & 0o7777
    on_target = (sftp.stat(target).permissions or 0) & 0o7777
    evidence = (
        *made,
        "lsetstat PERMISSIONS -> OK",
        f"LSTAT of the link -> {on_link:#o}",
        f"STAT of the target -> {on_target:#o}",
    )
    if on_link == _LSETSTAT_PROBE_MODE:
        return Finding(
            fact=_LSETSTAT_HONOURED,
            verdict=Verdict.YES,
            answer=(
                "the link's own mode is what was asked for, so this server's platform has "
                "lchmod and follow_symlinks=False means what it says here"
            ),
            evidence=evidence,
        )
    if on_target == _LSETSTAT_PROBE_MODE:
        return Finding(
            fact=_LSETSTAT_HONOURED,
            verdict=Verdict.NO,
            answer=(
                "the server answered OK and changed the mode of what the link points at. That "
                "is the operation follow_symlinks=False exists to refuse, so a chmod aimed at "
                "a link somebody else planted lands on their target here"
            ),
            evidence=evidence,
        )
    return Finding(
        fact=_LSETSTAT_HONOURED,
        verdict=Verdict.NO,
        answer=(
            "the server answered OK and neither mode changed, so the request was accepted and "
            "discarded. That is worse than the refusal OpenSSH gives on the same kernel: a "
            "caller is told their permission change happened when it did not"
        ),
        evidence=evidence,
    )


def _probe_check_file(sftp: SyncSession, scratch: _Scratch) -> Finding:
    """Whether an advertised ``check-file`` hashes the bytes the server actually holds.

    Compared against a digest computed here rather than merely checked for a well-formed
    reply: the failure this catches is a server that hashes the wrong range, which answers
    with the right *shape* and the wrong bytes.
    """
    path = scratch.claim("check-file")
    _create(sftp, path, _CHECK_FILE_PAYLOAD)
    # Deliberately NOT `open_for_read` (D-182, and the same answer at the public spelling in
    # D-185). Every other read-open on a path a caller named retries a refusal the server's
    # profile calls transient; this one must not. A battery exists to report what the server
    # did, and retrying until it succeeds would paper over exactly the behaviour being
    # measured -- a server that refuses one open in three would be reported as healthy.
    # Stated here because a missing retry is invisible, and it survives by construction: the
    # retry lives in a different method, so nothing has to remember an opt-out here.
    handle = sftp.open(path, OpenFlag.READ)
    try:
        algorithm, digests = sftp.check_file(handle)
    finally:
        sftp.close(handle)
    name = algorithm.decode("ascii", "replace")
    # `usedforsecurity=False` because the server chooses the algorithm and may choose md5 or
    # sha1, which a FIPS build refuses to construct at all -- and this is a comparison against
    # what that server just computed, not a security decision of ours.
    expected = hashlib.new(name, _CHECK_FILE_PAYLOAD, usedforsecurity=False).digest()
    matched = len(digests) == 1 and digests[0] == expected
    return Finding(
        fact=_CHECK_FILE_HONOURED,
        verdict=Verdict.YES if matched else Verdict.NO,
        answer=(
            f"the server's {name} digest of the bytes it holds matches the one computed here, "
            f"so content verification can be done without moving the file back"
            if matched
            else f"the server answered with {len(digests)} {name} digest(s) that do not match "
            f"the bytes that were uploaded, so this extension must not be trusted here"
        ),
        evidence=(
            f"created {path!r} with {len(_CHECK_FILE_PAYLOAD)} bytes",
            f"check-file -> algorithm {name!r}, {len(digests)} digest(s)",
            f"first digest {'matches' if matched else 'differs from'} the locally computed one",
        ),
    )


def _probe_largest_request(sftp: SyncSession, scratch: _Scratch, request_bytes: int) -> Finding:
    """Whether one ``WRITE`` the size this session's transfers use is accepted whole.

    **Bounded by what a transfer would send, and that bound is the safety property.** Finding a
    server's true ceiling means walking upwards until something breaks, against a machine
    somebody's payroll runs on. This asks the only question that changes what the library does
    -- is the size already derived actually usable -- and sends exactly one request no bigger
    than a ``put`` sends continuously. What stays unanswered is
    :data:`ProbeLimit.CEILING_ABOVE_THIS_SESSION`.

    A ``WRITE`` rather than anything read-only because the size has to be carried by *data*:
    every other request is bounded by a path, and a path is bounded by the server's name limit
    far below its packet limit. See :func:`read_only_probes`.

    **A short write is its own answer**, and it is the one this catches that a bare "did it
    refuse" would not: a server may accept the message, write part of it and report the count,
    which looks like success to anything that only checks for an exception.
    """
    path = scratch.claim("largest-request")
    payload = b"\0" * request_bytes
    handle = sftp.open(path, OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL, mode=PROBE_MODE)
    try:
        written = sftp.write_at(handle, 0, payload)
    except ServerError as refusal:
        return Finding(
            fact=_LARGEST_REQUEST,
            verdict=Verdict.NO,
            answer=(
                "the server refused a request of the size this session derived, so transfers "
                "here need a smaller one -- lower request_size until this passes"
            ),
            evidence=(f"WRITE of {request_bytes} bytes -> {_refusal(refusal)}",),
        )
    finally:
        sftp.close(handle)
    if written != request_bytes:
        return Finding(
            fact=_LARGEST_REQUEST,
            verdict=Verdict.NO,
            answer=(
                "the server accepted the request and stored fewer bytes than it was sent, "
                "which no exception would have reported"
            ),
            evidence=(f"WRITE of {request_bytes} bytes -> {written} bytes written",),
        )
    return Finding(
        fact=_LARGEST_REQUEST,
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            f"WRITE of {request_bytes} bytes -> {written} bytes written",
            f"the size was derived from this server's own limits, for {path!r}",
        ),
    )


_EXTENSION_PROBES: tuple[tuple[str, str, Callable[[SyncSession, _Scratch], Finding]], ...] = (
    (EXTENSION_POSIX_RENAME, _POSIX_RENAME_HONOURED, _probe_posix_rename),
    (EXTENSION_FSYNC, _FSYNC_HONOURED, _probe_fsync),
    (EXTENSION_LSETSTAT, _LSETSTAT_HONOURED, _probe_lsetstat),
    (EXTENSION_CHECK_FILE, _CHECK_FILE_HONOURED, _probe_check_file),
)
"""Which advertised extension each write probe verifies.

A table rather than four ``if sftp.supports(...)`` blocks, because this is one of the lists
CLAUDE.md's sweep rule is about: adding an extension to
:data:`~gantry_sftp.codec.IMPLEMENTED_EXTENSIONS` and not to this one leaves the report
silently narrower than it claims. ``tests/test_compatibility.py`` asserts the two agree, minus
``limits@openssh.com``, which is the only one that answers without a write.
"""


def write_probes(
    sftp: SyncSession, *, directory: bytes, request_bytes: int, run_id: str
) -> tuple[list[Finding], list[str]]:
    """The battery that creates files, in a directory the caller nominated by name.

    Every name it creates begins with :data:`PROBE_PREFIX`, carries ``run_id``, and is removed
    before this returns. Nothing outside ``directory`` is touched and no existing file is read,
    renamed or removed -- the only files it renames over are two it made itself. All of it
    together writes a few hundred bytes plus one request of ``request_bytes``.

    **The large-request probe is last, and the ordering is load-bearing.** It is the one probe
    a server may answer by closing the channel rather than by refusing, so everything cheap
    happens first and a session that dies costs one finding instead of the whole battery.

    Args:
        sftp: A live session.
        directory: Where to work. **Nominated rather than defaulted**: the caller has to name a
            place they are content to have files created and removed in, and there is no
            spelling of this call that picks one for them.
        request_bytes: The largest payload this session would put in one request, from
            :meth:`~gantry_sftp.sync.SyncSession.sizes_for`. Passed in rather than derived
            here, because it is a property of the handle a transfer holds and this battery
            holds none of a transfer's.
        run_id: Distinguishes this run's names from a concurrent one's.

    Returns:
        The findings, and anything that could not be cleaned up -- each with the reason,
        because a probe that litters somebody's production directory and says nothing is worse
        than one that did not run.
    """
    scratch = _Scratch(directory, run_id)
    findings = [
        _guarded(_CASE_FOLDS, partial(_probe_case_folding, sftp, scratch)),
        _guarded(_RENAME_REPLACES, partial(_probe_rename_replaces, sftp, scratch)),
        _guarded(_TIMES_SURVIVE, partial(_probe_timestamps, sftp, scratch)),
    ]
    findings += [
        _guarded(fact, partial(probe, sftp, scratch))
        for extension, fact, probe in _EXTENSION_PROBES
        if sftp.supports(extension)
    ]
    findings.append(
        _guarded(_LARGEST_REQUEST, partial(_probe_largest_request, sftp, scratch, request_bytes))
    )
    return findings, _clean_up(sftp, scratch)


def _clean_up(sftp: SyncSession, scratch: _Scratch) -> list[str]:
    """Remove everything the battery claimed, and report what would not go.

    Reverse order, so a name that was renamed over is attempted after the one that replaced
    it. ``NoSuchFileError`` alone is swallowed -- a claimed name that was never created, or one
    a rename consumed, is the expected case -- and every other refusal is reported: a wide
    ``except`` here would turn "the directory is read-only" into "cleaned up fine".
    """
    left_behind: list[str] = []
    for path in reversed(scratch.claimed):
        try:
            sftp.remove(path)
        except NoSuchFileError:
            continue
        except (SFTPError, OSError) as failure:
            left_behind.append(f"{path!r}: {type(failure).__name__}: {failure}")
    return left_behind


# --- the report -----------------------------------------------------------------------------


def compatibility_report(
    sftp: SyncSession,
    *,
    request_bytes: int,
    write_directory: bytes | str | None = None,
    run_id: str | None = None,
) -> CompatibilityReport:
    """Run the battery against a live session and return the evidence.

    ::

        with connect("sftp.example.com") as sftp:
            report = compatibility_report(sftp, request_bytes=sftp.sizes_for(handle).write_length)

    Read-only unless ``write_directory`` is given. What the run did not ask about is in
    :attr:`CompatibilityReport.undetermined` rather than left for the reader to notice.

    Args:
        sftp: A live session. The battery leaves it as it found it: no working directory
            changed, no handle still open, and -- with a write directory -- no file it created
            still there.
        request_bytes: The largest payload this session would put in one request. From
            :meth:`~gantry_sftp.sync.SyncSession.sizes_for`, which needs a handle length;
            passed in rather than guessed here.
        write_directory: Where the write battery may create files, or ``None`` to skip it
            entirely. There is no default and there will not be one.
        run_id: Fixes this run's scratch names, for a test that wants to assert on them.
            Defaults to a fresh random value so two runs cannot collide.

    Returns:
        The report. **Refusing to raise is the design**, the same as
        :func:`~gantry_sftp.doctor.server_diagnosis`: a probe that dies on the condition it was
        run to diagnose has nothing to say about the only case that matters. That extends to
        the one call made before any probe -- a session whose ``REALPATH .`` fails has nowhere
        to build a scratch name, and comes back as a report saying so rather than as an
        exception thrown through a diagnostic.
    """
    run_id = secrets.token_hex(4) if run_id is None else run_id
    try:
        start = sftp.realpath(b".")
    except (SFTPError, OSError) as failure:
        return _nowhere_to_probe(failure)
    findings = read_only_probes(sftp, directory=start, run_id=run_id)
    left_behind: list[str] = []
    if write_directory is None:
        wrote_into = None
    else:
        nominated = (
            write_directory
            if isinstance(write_directory, bytes)
            else write_directory.encode("utf-8", "surrogateescape")
        )
        wrote_into = nominated.decode("utf-8", "replace")
        written, left_behind = write_probes(
            sftp, directory=nominated, request_bytes=request_bytes, run_id=run_id
        )
        findings += written
    return CompatibilityReport(
        findings=tuple(findings),
        undetermined=_undetermined(sftp, probed_writes=write_directory is not None),
        wrote_into=wrote_into,
        left_behind=tuple(left_behind),
    )


def _nowhere_to_probe(failure: SFTPError | OSError) -> CompatibilityReport:
    """The report for a session that could not name its own starting point.

    Every probe builds a scratch name under the start directory, so this is the one failure
    that stops the battery before it begins. It comes back as a report rather than an
    exception for the reason the whole module exists: a diagnostic that dies on a broken
    server has nothing to say about the case worth reporting.
    """
    return CompatibilityReport(
        findings=(
            Finding(
                fact="the session can name its own starting directory",
                verdict=Verdict.UNDETERMINED,
                answer=(
                    "REALPATH of '.' failed, so there was nowhere to build a probe name and "
                    "no fact below could be established"
                ),
                evidence=(f"REALPATH b'.' -> {type(failure).__name__}: {failure}",),
            ),
        )
    )


def _undetermined(sftp: SyncSession, *, probed_writes: bool) -> tuple[str, ...]:
    """What this run did not ask about, assembled from what it was asked to do.

    Never padded and never silently short: an entry appears when the run genuinely declined
    something, so a report with a short list is one that asked more rather than one that
    admitted less.
    """
    limits: list[str] = []
    if not probed_writes:
        limits.append(ProbeLimit.WRITE_PROBES_NOT_REQUESTED)
        limits.append(ProbeLimit.LARGEST_REQUEST_NEEDS_A_WRITE)
        unverified = [
            extension for extension, _, _ in _EXTENSION_PROBES if sftp.supports(extension)
        ]
        if unverified:
            limits.append(ProbeLimit.EXTENSIONS_NEEDING_A_WRITE.format(names=", ".join(unverified)))
    limits += [ProbeLimit.CEILING_ABOVE_THIS_SESSION, ProbeLimit.BEHAVIOUR_UNDER_LOAD]
    if any(not sftp.supports(name) for name in IMPLEMENTED_EXTENSIONS):
        limits.append(ProbeLimit.UNADVERTISED_EXTENSIONS)
    return tuple(limits)

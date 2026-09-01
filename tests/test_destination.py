"""The destination allowlist: what it matches, how layers compose, and what it does when asked.

**D-121.** Nothing restricted where a connection went until 0.11. The card's own recon is what
shaped these tests, and the finding that shaped them most is that matching the hostname *string
the caller passed* does not work: an ``ssh_config`` rewrites the destination after that name,
so a string allowlist is checkable-but-not-binding the moment a config file is in play. The
test named for that is
:func:`test_a_config_rewrite_is_caught_because_the_effective_host_is_what_is_checked`, and it
fails against any implementation that checks the input.

The probe is driven with a real ``ssh`` throughout, and the failure paths with a real script
that exits the way a broken ``ssh`` would, rather than by monkeypatching ``anyio.run_process``
-- a fake here would only confirm what its author believed about subprocess failure, which is
DoD 1's whole objection.

**That script is a ``#!/bin/sh`` file, and Windows cannot execute one** -- see
:func:`broken_ssh`, which is where the skip and its reason live. It is worth knowing here
because reading those rows' failures as the library's is how D-156 came to be filed.

``config_file=os.devnull`` is passed everywhere a probe runs. ``ssh`` reads the developer's own
``~/.ssh/config`` otherwise, and a test whose policy answer depends on the machine it runs on
proves nothing -- DoD 1 again, and ``ssh`` resolves ``~`` from ``getpwuid`` rather than
``$HOME``, so ``-F`` is the only defence.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import anyio
import pytest

from gantry_sftp import connect
from gantry_sftp.exceptions import ConnectError, DestinationNotAllowedError
from gantry_sftp.transport import _destination, build_ssh_argv, resolve_ssh_executable
from gantry_sftp.transport._destination import (
    ALLOWED_HOSTS_ENV,
    _environment_layer,
    _normalize_patterns,
    _probe_argv,
    _reported_hostname,
    _reported_keyword,
    active_layers,
    allowed_hosts,
    check_destination,
    host_matches,
    normalize_host,
)

pytestmark = pytest.mark.anyio


def argv_for(host: str, **kwargs: object) -> list[str]:
    """A connection argv with the developer's ssh_config fenced off."""
    kwargs.setdefault("config_file", os.devnull)
    return build_ssh_argv(host, **kwargs)  # type: ignore[arg-type]


def broken_ssh(tmp_path: Path, name: str, body: str) -> Path:
    r"""A real program that misbehaves the way a broken ``ssh`` would.

    Four of the probe's failure paths cannot be reached with a working ``ssh``: exiting
    non-zero, answering with no ``hostname``, hanging past the bound, and writing bytes that
    are not UTF-8. A shell script reaches all four for the cost of one file, and driving a real
    process is the point -- monkeypatching ``anyio.run_process`` would assert what its author
    believes about subprocess failure rather than what one does.

    **It is POSIX-only, and mistaking that for a library defect is what D-156 was.** Windows
    cannot execute a ``#!/bin/sh`` text file: ``CreateProcess`` refuses it with
    ``ERROR_BAD_EXE_FORMAT``, which arrives as ``OSError(..., 193)``. So on Windows every one
    of these rows refuses through the *spawn failed* path instead of the path it was written
    for, and the resulting `'%1 is not a valid Win32 application'` was read as evidence that
    ``allowed_hosts()``'s probe cannot run there at all. It can: on the same runners
    ``resolve_ssh_executable()`` returns ``C:\Windows\System32\OpenSSH\ssh.exe``, and every row
    that drives that -- the allowed host, the refused host, both config rewrites -- passed on
    Windows in both of the runs the card was written from.

    So these skip rather than being ported. A ``.cmd`` stand-in would be a second fixture to
    keep in step, and it would put ``cmd.exe``'s argument re-parsing underneath a security
    test, which is a poor trade for four platform-independent branches that Linux and macOS
    already cover.
    """
    if sys.platform.startswith("win"):
        pytest.skip(
            "the stand-in is a '#!/bin/sh' script and Windows cannot execute one -- it fails "
            "with ERROR_BAD_EXE_FORMAT before reaching the branch under test, which is what "
            "D-156 mistook for allowed_hosts() being unusable there. The real probe is covered "
            "on Windows by the rows that drive resolve_ssh_executable()'s answer"
        )
    fake = tmp_path / name
    _ = fake.write_text(f"#!/bin/sh\n{body}")
    fake.chmod(0o700)
    return fake


# --- folding and matching, which are pure ---------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("Example.COM", "example.com"),
        # The explicit root. `example.com.` and `example.com` are the same name, and a policy
        # that answered differently for the two would be defeated by one character.
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("EXAMPLE.com.", "example.com"),
        # `rstrip` takes a character *set*, not a suffix, so the argument has to be exactly the
        # one character meant. A name ending in any other character keeps it -- the case that
        # catches a set that grew. Same shape as `_mkdir_parents`' `rstrip(b"/")`.
        ("exampleX", "examplex"),
        ("example.com..", "example.com"),
    ],
)
def test_a_host_folds_to_one_form(given: str, expected: str):
    assert normalize_host(given) == expected


@pytest.mark.parametrize(
    ("host", "pattern", "allowed"),
    [
        ("sftp.corp.example.com", "*.corp.example.com", True),
        # `*` matches a dot, so a wildcard spans labels. Documented, and asserted so the
        # documentation cannot drift from fnmatch's behaviour.
        ("a.b.corp.example.com", "*.corp.example.com", True),
        # ...and it does not match the bare domain, which has no leading label. This is the
        # edge an operator gets wrong, so it is pinned rather than left to the reader.
        ("example.com", "*.example.com", False),
        ("example.com", "example.com", True),
        # The two ways a lookalike tries to pass an exact pattern.
        ("evil-example.com", "example.com", False),
        ("example.com.evil.net", "example.com", False),
        # Case and the trailing root are folded on both sides.
        ("SFTP.Example.COM.", "sftp.example.com", True),
        ("sftp.example.com", "SFTP.EXAMPLE.COM", True),
        ("anything.at.all", "*", True),
    ],
)
def test_which_hosts_a_pattern_admits(host: str, pattern: str, allowed: bool):
    assert host_matches(host, (pattern,)) is allowed


def test_a_layer_admits_a_host_any_of_its_patterns_matches():
    layer = ("a.example.com", "*.b.example.com")
    assert host_matches("a.example.com", layer)
    assert host_matches("x.b.example.com", layer)
    assert not host_matches("c.example.com", layer)


# --- building a layer, including the states that must not read as "no policy" ---------------


def test_an_empty_allowlist_is_refused_rather_than_read_as_unrestricted():
    """The failure mode this prevents is an unset variable becoming an open door."""
    with pytest.raises(ValueError) as exc:
        _ = _normalize_patterns([])
    assert exc.value.args[0] == (
        "allowed_hosts needs at least one pattern; an empty allowlist would refuse every "
        "host, which is a bug in how the list was built rather than a policy"
    )


def test_a_blank_pattern_is_refused():
    with pytest.raises(ValueError) as exc:
        _ = _normalize_patterns(["example.com", "   "])
    assert exc.value.args[0] == "allowed_hosts patterns may not be blank: ('example.com', '')"


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_an_unset_or_empty_environment_variable_sets_no_policy(raw: str | None):
    environ = {} if raw is None else {ALLOWED_HOSTS_ENV: raw}
    assert _environment_layer(environ) is None


def test_an_environment_variable_of_separators_alone_raises():
    """The third state of the predicate: not "policy" and not "no policy", but malformed.

    Reading ``GANTRY_SFTP_ALLOWED_HOSTS=","`` as unrestricted would turn a typo into an open
    door, which is precisely the shape of failure the card exists to prevent.
    """
    with pytest.raises(ValueError) as exc:
        _ = _environment_layer({ALLOWED_HOSTS_ENV: " , , "})
    assert exc.value.args[0] == (
        "GANTRY_SFTP_ALLOWED_HOSTS is set to ' , , ', which names no host patterns; unset it "
        "to apply no policy, rather than setting it to separators alone"
    )


def test_the_environment_layer_is_split_and_folded():
    layer = _environment_layer({ALLOWED_HOSTS_ENV: " *.Corp.Example.COM , sftp.partner.net. "})
    assert layer == ("*.corp.example.com", "sftp.partner.net")


# --- layering, which is the composition rule that makes this safe to nest -------------------


def test_no_policy_is_the_default():
    assert active_layers({}) == ()


def test_the_environment_is_the_outermost_layer():
    with allowed_hosts(["*.inner.example.com"]):
        assert active_layers({ALLOWED_HOSTS_ENV: "*.outer.example.com"}) == (
            ("*.outer.example.com",),
            ("*.inner.example.com",),
        )


def test_a_scope_does_not_leak_out_of_its_block():
    with allowed_hosts(["*.example.com"]):
        assert active_layers({}) == (("*.example.com",),)
    assert active_layers({}) == ()


async def test_layers_narrow_and_never_widen():
    """The rule that makes an ambient control safe: an inner scope cannot re-admit a host.

    The alternative -- an inner scope *replacing* an outer one -- is a control that any library
    running inside the policy can switch off, which is worth no more than no control at all.
    """
    probe = argv_for("evil.net")
    # The inner scope names the host explicitly and it is still refused, because the outer
    # layer is also consulted and does not admit it.
    with (
        allowed_hosts(["*.corp.example.com"]),
        allowed_hosts(["evil.net"]),
        pytest.raises(DestinationNotAllowedError) as exc,
    ):
        await check_destination(probe, "evil.net", environ={})
    assert exc.value.layers == (("*.corp.example.com",), ("evil.net",))
    assert "1 of the 2 active allowlist layers" in exc.value.args[0]


async def test_the_environment_layer_cannot_be_widened_by_a_scope():
    probe = argv_for("evil.net")
    environ = {ALLOWED_HOSTS_ENV: "*.corp.example.com"}
    with allowed_hosts(["evil.net"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "evil.net", environ=environ)
    assert exc.value.layers == (("*.corp.example.com",), ("evil.net",))


# --- the probe, and the finding the whole card turns on -------------------------------------


async def test_no_policy_runs_no_probe(monkeypatch: pytest.MonkeyPatch):
    """An unrestricted caller pays nothing: no process, no round trip, no latency.

    Asserted by making a probe impossible rather than by timing it -- ``run_process`` is
    replaced with something that fails loudly, so a probe that happens cannot be missed.
    """

    async def refuse_to_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a probe was spawned with no policy active")

    monkeypatch.setattr(anyio, "run_process", refuse_to_run)
    await check_destination(argv_for("anywhere.example.com"), "anywhere.example.com", environ={})


async def test_an_allowed_host_passes_the_check():
    with allowed_hosts(["*.corp.example.com"]):
        await check_destination(
            argv_for("sftp.corp.example.com"), "sftp.corp.example.com", environ={}
        )


async def test_a_disallowed_host_is_refused_and_the_error_carries_the_policy():
    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(argv_for("evil.net"), "evil.net", environ={})
    assert exc.value.host == "evil.net"
    assert exc.value.effective_host == "evil.net"
    assert exc.value.layers == (("*.corp.example.com",),)
    assert exc.value.control_path is None
    assert exc.value.args[0] == (
        "'evil.net' is not an allowed destination; it matches no pattern in 1 of the 1 active "
        "allowlist layers ('*.corp.example.com'). Layers narrow and never widen, so a host "
        "must satisfy every one of them"
    )


async def test_a_config_rewrite_is_caught_because_the_effective_host_is_what_is_checked(
    tmp_path: Path,
):
    """D-121's recon finding, named for it. An allowlisted name is not an allowed destination.

    ``Hostname`` rewrites the destination after the name the caller passed, so an allowlist
    matching the caller's string would approve this connection to the cloud metadata endpoint.
    Checking what ``ssh -G`` reports is what catches it, and this test fails against any
    implementation that matches the input instead.
    """
    config = tmp_path / "rewrite.conf"
    _ = config.write_text("Host allowed.example.com\n  Hostname 169.254.169.254\n")
    probe = argv_for("allowed.example.com", config_file=str(config))

    with allowed_hosts(["allowed.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "allowed.example.com", environ={})
    assert exc.value.host == "allowed.example.com"
    assert exc.value.effective_host == "169.254.169.254"
    assert "which ssh_config rewrites to '169.254.169.254'" in exc.value.args[0]


async def test_a_match_host_rewrite_is_caught_too(tmp_path: Path):
    """``Match host`` is evaluated later than ``Host`` and rewrites just as effectively."""
    config = tmp_path / "match.conf"
    _ = config.write_text("Match host allowed.example.com\n  Hostname internal.corp.local\n")
    probe = argv_for("allowed.example.com", config_file=str(config))

    with allowed_hosts(["allowed.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "allowed.example.com", environ={})
    assert exc.value.effective_host == "internal.corp.local"


async def test_an_option_override_is_carried_into_the_probe(tmp_path: Path):
    """``-o Hostname=`` changes the destination and ``ssh -G`` honours it.

    So the probe has to be given the connection's own options. A probe built from the host
    alone would describe a connection nobody is about to make -- and would approve this one.
    """
    probe = argv_for("allowed.example.com", options={"Hostname": "169.254.169.254"})
    with allowed_hosts(["allowed.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "allowed.example.com", environ={})
    assert exc.value.effective_host == "169.254.169.254"


async def test_the_probe_runs_the_ssh_this_platform_resolved_and_reaches_an_answer(
    tmp_path: Path,
):
    r"""D-156, refuted -- by evidence that was in the log the card was written from.

    The card says ``allowed_hosts()`` refuses every connection on Windows because its
    ``ssh -G`` probe cannot execute there, and it is wrong in a specific way worth pinning:
    every ``ERROR_BAD_EXE_FORMAT`` in that run and in the one five days later belongs to a row
    that hands the probe a ``#!/bin/sh`` stand-in (see :func:`broken_ssh`), and every row that
    drives the *real* ``ssh`` passed on Windows both times.

    Two things are asserted, because the card's open question was which executable runs.
    ``build_ssh_argv`` takes it from :func:`resolve_ssh_executable`, so this fails if a bare
    name ever goes back there -- on Windows that resolves to
    ``C:\Windows\System32\OpenSSH\ssh.exe``, and ``gantry-sftp doctor`` reads
    ``OpenSSH_for_Windows_9.5p2`` out of the same path. Then the check runs and **allows**,
    which is the direct negation of the card's headline: the probe spawned, ``ssh -G``
    answered, and the rewritten name is what got matched.
    """
    config = tmp_path / "resolved.conf"
    _ = config.write_text("Host probe.example.com\n  Hostname resolved.example.com\n")
    probe = argv_for("probe.example.com", config_file=str(config))

    assert probe[0] == resolve_ssh_executable()
    with allowed_hosts(["resolved.example.com"]):
        await check_destination(probe, "probe.example.com", environ={})


def test_the_probe_argv_replaces_the_subsystem_request_and_keeps_the_options():
    argv = argv_for("example.com", options={"ServerAliveInterval": "30"})
    probe = _probe_argv(argv, "example.com")
    assert probe[-3:] == ["-G", "--", "example.com"]
    assert "-s" not in probe
    assert "sftp" not in probe
    assert "-o" in probe
    assert "ServerAliveInterval=30" in probe


def test_an_argv_that_does_not_end_in_a_subsystem_request_names_the_coupling():
    """D-127. The probe rebuilds argv by position, and the layout belongs to another module.

    It already failed closed -- a malformed probe exits non-zero and `effective_host` refuses --
    so this is about the *diagnosis*, not about a hole. Without the check the symptom is "the
    allowlist refuses every host", which reads as a policy bug and sends the reader to the
    patterns, the layers and the environment variable, none of which are where it is.
    """
    argv = [*argv_for("example.com"), "-o", "ProxyJump=bastion"]
    with pytest.raises(ValueError) as exc:
        _ = _probe_argv(argv, "example.com")
    assert exc.value.args[0] == (
        "cannot build an 'ssh -G' probe from this argv: it must end with "
        "['-s', '--', 'example.com', <subsystem>] as build_ssh_argv writes it, and it ends "
        "with ['example.com', 'sftp', '-o', 'ProxyJump=bastion']. The allowlist probe "
        "reconstructs the connection's argv by position, so a change to that tail belongs in "
        "transport/_argv.py and here together"
    )


def test_a_truncated_argv_is_refused_rather_than_silently_shortened():
    """The other side of the same guard: too short must not slice into nothing and proceed."""
    with pytest.raises(ValueError) as exc:
        _ = _probe_argv(["ssh", "-s", "--"], "example.com")
    assert exc.value.args[0].startswith("cannot build an 'ssh -G' probe from this argv")


# --- the errored third state: a probe that cannot answer must refuse ------------------------


async def test_a_probe_that_cannot_run_refuses_rather_than_allowing(tmp_path: Path):
    """Treating an unreadable answer as "allowed" would make any breakage a bypass."""
    missing = tmp_path / "no-such-ssh"
    probe = argv_for("example.com", ssh_executable=str(missing))
    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.effective_host is None
    assert exc.value.args[0].startswith(
        "cannot check whether 'example.com' is an allowed destination: the 'ssh -G' probe failed"
    )
    assert (
        "refusing the connection rather than allowing an unverified destination"
        in (exc.value.args[0])
    )
    # The state, not only the sentence. Every field here could be dropped or nulled with the
    # message unchanged, and an operator reading a refusal needs the policy that produced it
    # and the argv that failed -- this is the site where they have nothing else to go on.
    assert exc.value.host == "example.com"
    assert exc.value.layers == (("*.corp.example.com",),)
    assert exc.value.argv == (*probe[:-4], "-G", "--", "example.com")
    assert exc.value.argv[0] == str(missing)


async def test_a_probe_that_exits_non_zero_refuses_and_keeps_stderr_verbatim(tmp_path: Path):
    """The stderr goes through :class:`ConnectError`'s own field, not into the message.

    A subclass that formatted its own copy would be the one place OpenSSH's stderr arrived
    differently from every other connection failure, which is the base class's whole point.
    """
    fake = broken_ssh(tmp_path, "broken-ssh", "echo 'ssh: something went wrong' >&2\nexit 255\n")
    probe = argv_for("example.com", ssh_executable=str(fake))

    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.returncode == 255
    assert exc.value.stderr.strip() == "ssh: something went wrong"
    assert exc.value.effective_host is None
    assert exc.value.argv[0] == str(fake)
    # Rendered by ConnectError.__str__, so it reaches an operator without being re-formatted.
    assert "ssh: something went wrong" in str(exc.value)
    # This site's message was the one the other two had and it did not: `stderr` being asserted
    # is what made it look covered, and the whole sentence could be replaced with `None`.
    assert exc.value.args[0] == (
        "cannot check whether 'example.com' is an allowed destination: 'ssh -G' exited 255; "
        "refusing the connection rather than allowing an unverified destination"
    )
    assert exc.value.host == "example.com"
    assert exc.value.layers == (("*.corp.example.com",),)


async def test_a_probe_that_reports_no_hostname_refuses(tmp_path: Path):
    """A zero exit with nothing usable in it is still an answer we do not have."""
    fake = broken_ssh(tmp_path, "quiet-ssh", "echo 'user bob'\nexit 0\n")
    probe = argv_for("example.com", ssh_executable=str(fake))

    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.effective_host is None
    assert exc.value.args[0] == (
        "cannot check whether 'example.com' is an allowed destination: 'ssh -G' reported no "
        "hostname; refusing the connection rather than allowing an unverified destination"
    )
    assert exc.value.host == "example.com"
    assert exc.value.layers == (("*.corp.example.com",),)
    assert exc.value.argv == (*probe[:-4], "-G", "--", "example.com")


async def test_a_probe_that_hangs_is_bounded_rather_than_hanging_the_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """``ALLOWED_HOSTS_PROBE_TIMEOUT`` is documented as bounding the probe; nothing read it.

    The outer ``fail_after`` is the point: without it, dropping the inner bound makes this test
    *hang* rather than fail, which is a proof that reports the wrong thing when it breaks.
    ``CanonicalizeHostname`` makes the probe do DNS, so this is not a theoretical wait.

    Three numbers, spread so neither answer is a race: the probe is bounded at 0.5 s, the outer
    net catches at 3 s -- six times the margin, on a machine the benchmark lane can be loading
    -- and the fake sleeps past both. The outer one is also what keeps this cheap when it does
    fire, since a mutant that removes the bound costs 3 s per backend rather than the sleep.
    """
    fake = broken_ssh(tmp_path, "hanging-ssh", "sleep 5\n")
    probe = argv_for("example.com", ssh_executable=str(fake))
    monkeypatch.setattr(_destination, "ALLOWED_HOSTS_PROBE_TIMEOUT", 0.5)

    with anyio.fail_after(3):
        with (
            allowed_hosts(["*.corp.example.com"]),
            pytest.raises(DestinationNotAllowedError) as exc,
        ):
            await check_destination(probe, "example.com", environ={})

    # It refuses through the probe-failed path, carrying the TimeoutError that produced it.
    assert exc.value.args[0].startswith(
        "cannot check whether 'example.com' is an allowed destination: the 'ssh -G' probe failed"
    )
    assert "TimeoutError()" in exc.value.args[0]
    assert exc.value.effective_host is None


async def test_a_probe_whose_stderr_is_not_utf8_still_produces_a_refusal(tmp_path: Path):
    """A strict decode would raise ``UnicodeDecodeError`` from inside the error path.

    ``ssh``'s stderr is bytes from a program in another locale, so it is not ours to assume
    well-formed -- and the one place it is read is while building the refusal, where an
    exception replaces a security decision with a crash.
    """
    fake = broken_ssh(tmp_path, "noisy-ssh", "printf 'ssh: \\377 broke\\n' >&2\nexit 255\n")
    probe = argv_for("example.com", ssh_executable=str(fake))

    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.returncode == 255
    assert exc.value.stderr.strip() == "ssh: � broke"


async def test_a_probe_whose_stdout_is_not_utf8_still_reports_the_hostname(tmp_path: Path):
    """Same byte on the channel the *answer* arrives on, where a crash loses the answer.

    The hostname line is well-formed and a different line is not, which is the shape a locale
    or a rewritten banner produces. The check has to survive it and still read the hostname.
    """
    fake = broken_ssh(
        tmp_path, "mixed-ssh", "printf 'user \\377\\nhostname evil.example.com\\n'\nexit 0\n"
    )
    probe = argv_for("example.com", ssh_executable=str(fake))

    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.effective_host == "evil.example.com"


async def test_a_refusal_names_every_pattern_in_the_layer_that_refused():
    """A one-element join puts nothing between anything, so the separator was unasserted.

    Read while deciding which pattern to add, so a list rendered without separators sends the
    reader to fix the wrong thing. The patterns are also reversed against the order they were
    written in, which is what makes "the layer's own order is kept" observable.
    """
    with (
        allowed_hosts(["sftp.corp.example.com", "backup.corp.example.com"]),
        pytest.raises(DestinationNotAllowedError) as exc,
    ):
        await check_destination(argv_for("evil.net"), "evil.net", environ={})
    assert exc.value.args[0] == (
        "'evil.net' is not an allowed destination; it matches no pattern in 1 of the 1 active "
        "allowlist layers ('sftp.corp.example.com', 'backup.corp.example.com'). Layers narrow "
        "and never widen, so a host must satisfy every one of them"
    )


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("user bob\nhostname real.example.com\nport 22\n", "real.example.com"),
        ("hostname Example.COM.\n", "example.com"),
        ("HOSTNAME upper.example.com\n", "upper.example.com"),
        ("user bob\nport 22\n", None),
        ("", None),
        ("hostname\n", None),
        ("hostname   \n", None),
        # The format promises no uniqueness, so the last wins: a control must not be
        # shadowable by an earlier line.
        ("hostname first.example.com\nhostname second.example.com\n", "second.example.com"),
        # The value is everything after the *first* space, so a value carrying one is kept
        # whole and matches no pattern. Splitting on the last space instead would read this
        # line's keyword as `hostname real.example.com` and find no hostname at all -- and the
        # difference is only visible on a line with more than two fields.
        ("hostname real.example.com evil.example.com\n", "real.example.com evil.example.com"),
    ],
)
def test_which_hostname_the_probe_output_yields(output: str, expected: str | None):
    assert _reported_hostname(output) == expected


# --- a ControlPath the destination cannot bind (D-202) --------------------------------------


async def test_a_controlpath_that_does_not_change_with_the_destination_is_refused(
    tmp_path: Path,
):
    """D-202. ``ControlMaster=no`` still *uses* a master, so a fixed socket carries the session
    to whichever host that master was opened to, and ``ssh -G`` reports the named destination
    regardless. The allowlist would approve a host the session never reaches; it refuses.

    A real ``ssh`` throughout: ``-G`` expands the tokens, so the check is a second probe with a
    different destination rather than a read of the path, and a fake would only confirm what
    its author believed ``-G`` prints.
    """
    fixed = tmp_path / "cm"
    probe = argv_for("sftp.corp.example.com", options={"ControlPath": str(fixed)})
    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "sftp.corp.example.com", environ={})
    assert exc.value.args[0] == (
        f"cannot check whether 'sftp.corp.example.com' is an allowed destination: ControlPath "
        f"{str(fixed)!r} does not change when the destination does, so an existing multiplexing "
        f"master at that socket would carry this session to whichever host it was opened to, "
        f"and the allowlist cannot bind it. Key the path on the destination "
        f"(ControlPath=~/.ssh/cm-%C) or set ControlPath=none; refusing the connection rather "
        f"than allowing an unverified destination"
    )
    assert exc.value.host == "sftp.corp.example.com"
    assert exc.value.effective_host == "sftp.corp.example.com"
    assert exc.value.control_path == str(fixed)
    assert exc.value.layers == (("*.corp.example.com",),)


@pytest.mark.parametrize("token", ["%C", "%r@%h:%p", "%h"])
async def test_a_controlpath_keyed_on_the_destination_passes(token: str, tmp_path: Path):
    """The two spellings ssh_config(5) recommends, and the bare token they share."""
    probe = argv_for(
        "sftp.corp.example.com", options={"ControlPath": str(tmp_path / f"cm-{token}")}
    )
    with allowed_hosts(["*.corp.example.com"]):
        await check_destination(probe, "sftp.corp.example.com", environ={})


@pytest.mark.parametrize("token", ["%p", "%r", "%n", "%k"])
async def test_a_controlpath_keyed_on_anything_but_the_host_is_refused(token: str, tmp_path: Path):
    """Port and user are not the destination; ``%n`` and ``%k`` are, and are refused anyway.

    The last two are the documented limit: they key on the name as typed rather than on the
    resolved host, which the sentinel ``Hostname`` cannot move, so the instrument reports them
    as fixed. Pinned so the docs' statement of the limit stays true rather than aspirational --
    and so an instrument that one day *can* see them changes this test by name.
    """
    probe = argv_for(
        "sftp.corp.example.com", options={"ControlPath": str(tmp_path / f"cm-{token}")}
    )
    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "sftp.corp.example.com", environ={})
    assert "does not change when the destination does" in exc.value.args[0]


async def test_a_controlpath_from_the_config_file_is_seen(tmp_path: Path):
    """The check reads what ``ssh -G`` resolved, not the ``options=`` the caller passed.

    A path set in the config is the common case -- it is how a master run by hand is found --
    and a check over ``options=`` alone would miss every one of them.
    """
    config = tmp_path / "cm.conf"
    _ = config.write_text(f"Host allowed.example.com\n  ControlPath {tmp_path / 'cm'}\n")
    probe = argv_for("allowed.example.com", config_file=str(config))
    with allowed_hosts(["allowed.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "allowed.example.com", environ={})
    assert exc.value.control_path == str(tmp_path / "cm")


async def test_a_controlpath_the_config_scopes_to_the_destination_passes(tmp_path: Path):
    """``Match host`` is evaluated against the resolved host, so the sentinel un-matches it.

    The second probe then reports no ``controlpath`` at all, and that counts as changing: in
    this configuration no other destination reaches the socket. The question the check asks is
    whether the socket moves with the destination, and here it does -- by disappearing.
    """
    config = tmp_path / "scoped.conf"
    _ = config.write_text(f"Match host allowed.example.com\n  ControlPath {tmp_path / 'cm'}\n")
    probe = argv_for("allowed.example.com", config_file=str(config))
    with allowed_hosts(["allowed.example.com"]):
        await check_destination(probe, "allowed.example.com", environ={})


async def test_controlpath_none_is_no_controlpath():
    """``ssh -G`` prints no ``controlpath`` line for ``none``, so there is nothing to bind."""
    probe = argv_for("sftp.corp.example.com", options={"ControlPath": "none"})
    with allowed_hosts(["*.corp.example.com"]):
        await check_destination(probe, "sftp.corp.example.com", environ={})


async def test_a_disallowed_host_is_refused_for_its_pattern_before_its_controlpath(
    tmp_path: Path,
):
    """The pattern refusal is the more useful message and costs no second probe.

    The path is still carried, because an operator fixing the first problem should not have
    to rediscover the second.
    """
    probe = argv_for("evil.net", options={"ControlPath": str(tmp_path / "cm")})
    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "evil.net", environ={})
    assert exc.value.args[0].startswith("'evil.net' is not an allowed destination")
    assert exc.value.control_path == str(tmp_path / "cm")


async def test_a_second_probe_that_fails_refuses_and_carries_what_the_first_read(tmp_path: Path):
    """The errored third state of the second predicate, driven with a real process.

    The stand-in answers the first probe like a healthy ``ssh`` and refuses the second -- the
    one carrying the sentinel -- so this reaches the branch a working ``ssh`` cannot. The
    refusal names the exit code and keeps stderr verbatim, and it carries the hostname and
    path the first probe established rather than nulling them.
    """
    fake = broken_ssh(
        tmp_path,
        "second-probe-fails",
        'case "$*" in *gantry-sftp-controlpath-probe.invalid*)'
        " echo 'the second probe was refused' >&2; exit 7;; esac\n"
        f"echo hostname example.com\necho controlpath {tmp_path / 'cm'}\n",
    )
    probe = argv_for(
        "example.com", ssh_executable=str(fake), options={"ControlPath": str(tmp_path / "cm")}
    )
    with allowed_hosts(["example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.args[0] == (
        "cannot check whether 'example.com' is an allowed destination: 'ssh -G' exited 7; "
        "refusing the connection rather than allowing an unverified destination"
    )
    assert exc.value.returncode == 7
    assert exc.value.stderr == "the second probe was refused\n"
    assert exc.value.effective_host == "example.com"
    assert exc.value.control_path == str(tmp_path / "cm")
    assert exc.value.argv[:3] == (
        str(fake),
        "-o",
        "Hostname=gantry-sftp-controlpath-probe.invalid",
    )


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("hostname a.example.com\ncontrolpath /run/ssh/cm\n", "/run/ssh/cm"),
        ("hostname a.example.com\n", None),
        ("CONTROLPATH /run/ssh/cm\n", "/run/ssh/cm"),
        ("controlpath\n", None),
        ("controlpath   \n", None),
        ("controlpath /run/ssh/first\ncontrolpath /run/ssh/second\n", "/run/ssh/second"),
        # Unlike the hostname, the path is compared rather than matched, so it is not folded:
        # a socket path is case-sensitive and `/run/ssh/CM` is not `/run/ssh/cm`.
        ("controlpath /run/ssh/CM\n", "/run/ssh/CM"),
        ("controlpath /run/ssh/with space\n", "/run/ssh/with space"),
    ],
)
def test_which_controlpath_the_probe_output_yields(output: str, expected: str | None):
    assert _reported_keyword(output, "controlpath") == expected


# --- the class, and where it sits in the ladder ---------------------------------------------


def test_a_refusal_is_a_connect_error():
    """``except ConnectError`` must not start missing failures because a policy was enabled."""
    assert issubclass(DestinationNotAllowedError, ConnectError)


async def test_the_refusal_reaches_a_caller_through_connect(tmp_path: Path):
    """The policy is enforced at the transport, so it applies to every entry point above it.

    Nothing is spawned: the refusal happens before the connection, which is what makes this a
    control rather than a report.
    """
    config = tmp_path / "empty.conf"
    _ = config.write_text("")
    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        async with connect("evil.net", config_file=str(config)):
            pass  # pragma: no cover -- the refusal is the feature
    assert exc.value.host == "evil.net"

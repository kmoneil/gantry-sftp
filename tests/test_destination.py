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

``config_file=os.devnull`` is passed everywhere a probe runs. ``ssh`` reads the developer's own
``~/.ssh/config`` otherwise, and a test whose policy answer depends on the machine it runs on
proves nothing -- DoD 1 again, and ``ssh`` resolves ``~`` from ``getpwuid`` rather than
``$HOME``, so ``-F`` is the only defence.
"""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest

from gantry_sftp import connect
from gantry_sftp.exceptions import ConnectError, DestinationNotAllowedError
from gantry_sftp.transport import build_ssh_argv
from gantry_sftp.transport._destination import (
    ALLOWED_HOSTS_ENV,
    _environment_layer,
    _normalize_patterns,
    _probe_argv,
    _reported_hostname,
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


def test_the_probe_argv_replaces_the_subsystem_request_and_keeps_the_options():
    argv = argv_for("example.com", options={"ServerAliveInterval": "30"})
    probe = _probe_argv(argv, "example.com")
    assert probe[-3:] == ["-G", "--", "example.com"]
    assert "-s" not in probe
    assert "sftp" not in probe
    assert "-o" in probe
    assert "ServerAliveInterval=30" in probe


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


async def test_a_probe_that_exits_non_zero_refuses_and_keeps_stderr_verbatim(tmp_path: Path):
    """The stderr goes through :class:`ConnectError`'s own field, not into the message.

    A subclass that formatted its own copy would be the one place OpenSSH's stderr arrived
    differently from every other connection failure, which is the base class's whole point.
    """
    fake = tmp_path / "broken-ssh"
    _ = fake.write_text("#!/bin/sh\necho 'ssh: something went wrong' >&2\nexit 255\n")
    fake.chmod(0o700)
    probe = argv_for("example.com", ssh_executable=str(fake))

    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.returncode == 255
    assert exc.value.stderr.strip() == "ssh: something went wrong"
    assert exc.value.effective_host is None
    assert exc.value.argv[0] == str(fake)
    # Rendered by ConnectError.__str__, so it reaches an operator without being re-formatted.
    assert "ssh: something went wrong" in str(exc.value)


async def test_a_probe_that_reports_no_hostname_refuses(tmp_path: Path):
    """A zero exit with nothing usable in it is still an answer we do not have."""
    fake = tmp_path / "quiet-ssh"
    _ = fake.write_text("#!/bin/sh\necho 'user bob'\nexit 0\n")
    fake.chmod(0o700)
    probe = argv_for("example.com", ssh_executable=str(fake))

    with allowed_hosts(["*.corp.example.com"]), pytest.raises(DestinationNotAllowedError) as exc:
        await check_destination(probe, "example.com", environ={})
    assert exc.value.effective_host is None
    assert "reported no hostname" in exc.value.args[0]


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
    ],
)
def test_which_hostname_the_probe_output_yields(output: str, expected: str | None):
    assert _reported_hostname(output) == expected


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

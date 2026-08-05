"""What the ``ssh`` child can actually see, and why every other live proof depends on it.

DESIGN.md §10 promises a *"Controlled ``ssh`` environment, **asserted**"* -- the steering
variables cleared, ``-F`` passed explicitly, "with the unset case asserted unset". The
clearing was real and applied everywhere. The asserting did not exist: until this file, those
names appeared in exactly one place in the whole test tree, which was the scrubber's own body.

**That gap is not bookkeeping.** Every security assertion in ``test_ssh_transport.py`` -- the
wrong key, the unknown host key, the changed host key -- is meaningful only if the child could
not have authenticated some other way. On a developer's machine with an agent running, a
leaked ``SSH_AUTH_SOCK`` lets that agent supply a working key, and the test asserting we
surface ``Permission denied`` verifies nothing while staying green.

Writing the proofs found that two of the things the scrubber was believed to do, it does not.

**``HOME`` does not fence off ``~/.ssh``.** ``ssh`` resolves ``~`` from the password database,
not from ``$HOME``: with ``HOME`` redirected it still reads the developer's real
``~/.ssh/config`` and still loads their real default identities. ``-F`` is the defence, and
until now nothing asserted it either. :func:`test_openssh_ignores_home_when_it_looks_for_a_config`
pins that behaviour rather than assuming it, because the whole reason the redirect was here
was a belief about a program's behaviour that nobody had run.

**And clearing ``SSH_ASKPASS`` does not disarm the askpass helper.** This ``ssh`` has
``/usr/bin/ssh-askpass`` compiled in as its default, and the variables that *arm* it are
``DISPLAY`` and ``WAYLAND_DISPLAY`` -- either alone is sufficient. Both were missing from the
set, and ``WAYLAND_DISPLAY`` appears nowhere in ``ssh(1)``. See :data:`sshd.STEERING`.

Three proofs, in increasing order of how little they assume:

1. The helper's contract, as a dictionary, plus the contract of the connection arguments every
   suite here is built from. Cheap, and between them they catch a name being renamed out of
   the set or a defence being deleted from a constructor.
2. **What the child process really got.** ``ProxyCommand`` is executed by the ``ssh`` client
   and inherits its environment verbatim, so a proxy that writes its own ``os.environ`` to a
   file is a direct reading of the child's environment rather than an inference from
   behaviour. That is DESIGN's phrasing honoured literally: not "we called the scrubber" but
   "the child's environment does not contain this name".
3. **The hazard itself, reproduced.** A real ``ssh-agent`` holding the *correct* key while the
   connection is made with the *wrong* one. Four rows, and the fourth authenticates -- which
   is the bug this whole mechanism exists to prevent, demonstrated rather than described. A
   proof must be run against the broken version once or it is a claim about the proof; here
   the broken version is a parametrisation, so it runs every time.

**What is deliberately not proven behaviourally, and why that is not laziness.**
``SSH_ASKPASS``, ``SSH_ASKPASS_REQUIRE``, ``DISPLAY`` and ``WAYLAND_DISPLAY`` cannot be proved
by watching a marker script fail to run -- which is what this card originally proposed --
because ``BatchMode=yes`` is in ``DEFAULT_SSH_OPTIONS`` and reaches every connection this
library makes. Measured against a real server with an encrypted key it accepts:

===========================  ==============  =============================
environment                  ``BatchMode``   helper runs?
===========================  ==============  =============================
``DISPLAY=:0``               ``no``          **yes**, and it authenticates
``WAYLAND_DISPLAY=...``      ``no``          **yes**, and it authenticates
``SSH_ASKPASS_REQUIRE=...``  ``no``          **yes**, and it authenticates
none of the three            ``no``          no
``DISPLAY=:0``               ``yes``         no
===========================  ==============  =============================

So a "poison ``SSH_ASKPASS``, assert the marker never ran" test passes identically against a
completely unscrubbed environment: ``BatchMode`` already suppressed it. It is a test that
could not fail. Removing those four names is defence in depth against a caller who overrides
``BatchMode``, and proof 1's dictionary assertion plus proof 2's child-side assertion are the
whole of their proof, on purpose.
"""

from __future__ import annotations

import json
import os
import pwd
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import anyio
import pytest
from sshd import (
    OPTIONAL_DIRECTIVES,
    REDIRECTED_HOME,
    SSHServer,
    client_kwargs,
    connect_kwargs,
    scrubbed_ssh_env,
)

from conftest import negotiate
from gantry_sftp.codec import Codec
from gantry_sftp.exceptions import AuthenticationError, ConnectError
from gantry_sftp.transport import open_ssh_transport

pytestmark = pytest.mark.anyio

STEERING_VARIABLES = (
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "SHELL",
    "SSH_SK_HELPER",
)
"""The names the scrubber promises to remove, spelled out again on purpose.

Importing :data:`sshd.STEERING` would make this file assert a constant against itself: rename
a name there and the assertion renames with it, green throughout, protecting nothing. The
duplication *is* the test, and it is why this list must be edited by hand whenever the
scrubber's is. :data:`sshd.STEERING` carries the evidence for each entry; this one carries
none deliberately, so that the two lists are independent statements rather than one.
"""

_AGENT_TIMEOUT = 30.0
_CONNECT_TIMEOUT = 60.0
_MARKER_CONNECT_TIMEOUT = "77"
_READING_CONFIG = "Reading configuration data"

_ENV_DUMPER = """\
# Run by ssh as a ProxyCommand, so it inherits the ssh client's environment exactly.
# It must never write to stdout: that pipe is the transport ssh is about to speak SSH over.
import json
import os
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(dict(os.environ), handle)
"""


# --- 1a. the helper's contract --------------------------------------------------------------


def test_the_scrubber_removes_every_variable_that_steers_ssh(monkeypatch: pytest.MonkeyPatch):
    """Each name gone, from an environment that demonstrably had it.

    The poison is asserted present first. Without that this passes on any machine where the
    developer simply had no agent and no display -- a test whose subject was never there. On
    this container that is the *default* state: ``env | grep ^SSH_`` returns nothing.
    """
    for name in STEERING_VARIABLES:
        monkeypatch.setenv(name, f"poison-{name}")
    assert [name for name in STEERING_VARIABLES if name not in os.environ] == []

    env = scrubbed_ssh_env()

    assert [name for name in STEERING_VARIABLES if name in env] == []


def test_the_scrubber_keeps_everything_it_does_not_name(monkeypatch: pytest.MonkeyPatch):
    """Otherwise an empty dict would satisfy every absence assertion in this file.

    It also matters in its own right: ``ssh`` is spawned with exactly what this returns, so a
    scrubber that dropped ``PATH`` would produce a child that cannot find the helpers it
    execs, diagnosed as anything but the environment.
    """
    monkeypatch.setenv("GANTRY_UNRELATED_VARIABLE", "kept")

    env = scrubbed_ssh_env()

    assert env["GANTRY_UNRELATED_VARIABLE"] == "kept"
    assert env["PATH"] == os.environ["PATH"]


def test_the_scrubbed_home_is_redirected_to_a_pinned_nonexistent_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """``HOME`` is replaced, and with a value chosen here rather than found here.

    The parent value is set first so "it was redirected" is a comparison between two known
    strings. Written the obvious way -- ``env["HOME"] != os.environ.get("HOME")`` -- this
    passes for free whenever ``HOME`` is unset in the parent, because nothing equals ``None``;
    that is a scrubbed CI container, which is exactly where it would matter most.

    What this does **not** claim is that the redirect protects ``~/.ssh`` --
    :func:`test_openssh_ignores_home_when_it_looks_for_a_config` is the measurement that says
    it does not.
    """
    monkeypatch.setenv("HOME", str(tmp_path))

    env = scrubbed_ssh_env()

    assert env["HOME"] != str(tmp_path)
    assert env["HOME"] == REDIRECTED_HOME
    assert not Path(env["HOME"]).exists()


def test_the_scrubber_does_not_disturb_the_environment_of_this_process(
    monkeypatch: pytest.MonkeyPatch,
):
    # It returns a filtered copy. A version that mutated os.environ would scrub the agent out
    # from under the developer's own shell -- and every later test in the run, silently.
    monkeypatch.setenv("SSH_AUTH_SOCK", "poison-SSH_AUTH_SOCK")

    scrubbed_ssh_env()

    assert os.environ["SSH_AUTH_SOCK"] == "poison-SSH_AUTH_SOCK"


# --- 1b. the contract of the connection arguments every suite is built from ------------------


def test_the_connection_arguments_carry_both_defences_and_the_config_that_matters(
    ssh_server: SSHServer, monkeypatch: pytest.MonkeyPatch
):
    """Assert the production constructor, not just the helper underneath it.

    Every one of these lines is here because deleting the thing it asserts used to leave the
    entire live suite green. ``IdentitiesOnly`` in particular: remove it from
    :meth:`sshd.SSHServer.connect_options` and nothing goes red, because the scrubbed
    environment silently covers for it -- which is the single point of failure this card was
    written to remove, reappearing one layer up.

    ``config_file`` is the one that turned out to matter most, and nothing asserted it at all.
    It is not a second-best version of the ``HOME`` redirect; per
    :func:`test_openssh_ignores_home_when_it_looks_for_a_config` it is the *only* thing that
    keeps the developer's ``ssh_config`` out of a test run.

    The environment is poisoned first, and the redirect asserted as well as the absences,
    because absence alone is not evidence: this container ambiently sets exactly one of the
    eight names, so seven of the eight assertions would be about something that was never
    there, and on a bare runner all eight would be.
    """
    for name in STEERING_VARIABLES:
        monkeypatch.setenv(name, f"poison-{name}")

    kwargs = connect_kwargs(ssh_server)

    assert kwargs["config_file"] == os.devnull
    assert kwargs["options"]["IdentitiesOnly"] == "yes"
    assert kwargs["env"]["HOME"] == REDIRECTED_HOME
    assert [name for name in STEERING_VARIABLES if name in kwargs["env"]] == []


def test_an_override_cannot_quietly_drop_a_defence(ssh_server: SSHServer):
    # `connect_kwargs` merges caller options over the pinned ones, which is what lets a test
    # say `options={"ProxyCommand": ...}`. The merge must not be a way to lose IdentitiesOnly
    # by naming something else.
    kwargs = connect_kwargs(ssh_server, options={"ConnectTimeout": "5"})

    assert kwargs["options"]["IdentitiesOnly"] == "yes"
    assert kwargs["options"]["ConnectTimeout"] == "5"


# --- 1c. what -F does, and what HOME does not ------------------------------------------------


def _ssh_probe(*args: str, home: str) -> tuple[dict[str, str], list[str]]:
    """Ask ``ssh -vG`` what it resolved and which files it read, without connecting.

    Returns:
        The effective settings from stdout, and the config paths ``ssh`` reported reading on
        stderr. Both halves are needed: the settings say whether a directive took effect, and
        the paths say whether a file was consulted at all -- which still answers the question
        when a config is bad enough that ``ssh`` refuses to continue and prints no settings.
    """
    finished = subprocess.run(
        ["ssh", "-v", "-G", *args, "--", "probe.invalid"],
        env={**os.environ, "HOME": home},
        capture_output=True,
        text=True,
        timeout=_AGENT_TIMEOUT,
        check=False,
    )
    settings: dict[str, str] = {}
    for line in finished.stdout.splitlines():
        name, _, value = line.partition(" ")
        settings.setdefault(name, value)
    read = [
        line.partition(_READING_CONFIG)[2].strip()
        for line in finished.stderr.splitlines()
        if _READING_CONFIG in line
    ]
    return settings, read


def _password_database_home() -> Path:
    """The home directory ``ssh`` will use, which is not necessarily ``$HOME``."""
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def test_openssh_ignores_home_when_it_looks_for_a_config(tmp_path: Path):
    """Characterisation of ``ssh(1)``, not of us -- and it overturns why ``HOME`` is scrubbed.

    ``ssh`` resolves ``~`` from the password database rather than from ``$HOME``, so pointing
    ``HOME`` at a directory containing an ``ssh_config`` does not make ``ssh`` read it. That
    matters because this repository redirected ``HOME`` *specifically* to keep the developer's
    ``~/.ssh/config`` out of test runs, and it never could. The redirect stayed, with a
    narrower and truthful justification; see :func:`sshd.scrubbed_ssh_env`.

    **The positive control is the whole test.** Asserting "the marker is absent" against a
    config ``ssh`` was never going to read proves nothing about ``HOME`` -- it would pass just
    as well if the file were empty, unreadable, or syntactically ignored. So the same file is
    fed to the same ``ssh`` through ``-F``, where the marker does appear.

    Where a real ``~/.ssh/config`` exists, the negative is upgraded to a positive: ``ssh`` is
    asserted to have read *that* one while ``HOME`` pointed elsewhere. That is the difference
    between "our file was not used" and "the password-database home was used instead", and it
    is the sentence the docstring this test corrects got wrong.
    """
    if shutil.which("ssh") is None:  # pragma: no cover -- ssh is a project requirement
        pytest.skip("ssh not installed")

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    marker_config = home / ".ssh" / "config"
    marker_config.write_text(f"Host *\n    ConnectTimeout {_MARKER_CONNECT_TIMEOUT}\n")

    # The control: this file is readable and this marker is detectable.
    settings, read = _ssh_probe("-F", str(marker_config), home=str(home))
    assert settings["connecttimeout"] == _MARKER_CONNECT_TIMEOUT
    assert str(marker_config) in read

    # And yet HOME does not lead ssh to it.
    settings, read = _ssh_probe(home=str(home))
    assert str(marker_config) not in read
    assert settings.get("connecttimeout") != _MARKER_CONNECT_TIMEOUT

    real_config = _password_database_home() / ".ssh" / "config"
    if not real_config.is_file():  # pragma: no cover -- depends on the developer's machine
        pytest.skip(f"no {real_config} to demonstrate the positive half against")
    assert str(real_config) in read


def test_devnull_is_what_keeps_a_config_out_of_a_test_run(tmp_path: Path):
    """The defence that does work, asserted for the first time.

    ``-F /dev/null`` also suppresses the system-wide ``/etc/ssh/ssh_config``, which is the
    other file nobody running the suite controls. Asserted on the list of files read rather
    than on a setting, because "no directive took effect" is also what a broken probe looks
    like.
    """
    if shutil.which("ssh") is None:  # pragma: no cover -- ssh is a project requirement
        pytest.skip("ssh not installed")

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "config").write_text(f"Host *\n    ConnectTimeout {_MARKER_CONNECT_TIMEOUT}\n")

    settings, read = _ssh_probe("-F", os.devnull, home=str(home))

    assert read == [os.devnull]
    assert settings.get("connecttimeout") != _MARKER_CONNECT_TIMEOUT


# --- 2. what the child process really got ----------------------------------------------------


def _poison(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """Values to poison the parent environment with, and the marker one of them writes.

    Every name gets a distinctive string except ``SHELL``, which has to be a working shell:
    ``ssh`` execs ``$SHELL -c`` to run ``ProxyCommand``, so poisoning it with a non-path made
    the observer vanish entirely -- ``poison-SHELL: No such file or directory``, no dump, and
    an "the four names are absent" assertion that would have been satisfied by a file nobody
    wrote. That is the exact vacuity this file exists to rule out, met while writing it.

    The wrapper is therefore a real shell that records having run and then hands off. It turns
    the accident into a second, *behavioural* proof: under the unscrubbed environment the
    marker appears, so ``SHELL`` demonstrably steered ``ssh``; under the scrubbed one it does
    not, so removing the name demonstrably took the steering away.

    Returns:
        The poison values by name, and the path the ``SHELL`` wrapper writes when used.
    """
    marker = tmp_path / "poisoned-shell-was-used"
    wrapper = tmp_path / "poisoned-shell.sh"
    wrapper.write_text(f'#!/bin/sh\necho used > {marker}\nexec /bin/sh "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    values = {name: f"poison-{name}" for name in STEERING_VARIABLES}
    values["SHELL"] = str(wrapper)
    return values, marker


@pytest.mark.parametrize("scrubbed", [True, False], ids=["scrubbed", "unscrubbed"])
async def test_what_the_spawned_ssh_child_can_see_in_its_own_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, scrubbed: bool
):
    """Read the child's environment directly, instead of inferring it from behaviour.

    ``ssh`` runs ``ProxyCommand`` itself, before any connection exists, with its own
    environment -- so a proxy that dumps ``os.environ`` and exits reports exactly what ``ssh``
    was handed. No server is involved: the proxy dies, ``ssh`` gets a broken pipe, and the
    dump is already on disk.

    The ``unscrubbed`` parametrisation is the control, and it is what stops the ``scrubbed``
    one being a test that could not fail: it asserts the poison values are *present*, so an
    observer that could never have seen them fails here rather than quietly making the other
    half look like a pass. The scrubbed half asserts a survivor reaches the child for the same
    reason in the other direction -- an over-aggressive scrubber returning almost nothing
    would satisfy every absence assertion here.
    """
    if shutil.which("ssh") is None:  # pragma: no cover -- ssh is a project requirement
        pytest.skip("ssh not installed")

    poison, shell_marker = _poison(tmp_path)
    for name, value in poison.items():
        monkeypatch.setenv(name, value)
    poisoned_home = tmp_path / "poisoned-home"
    poisoned_home.mkdir()
    monkeypatch.setenv("HOME", str(poisoned_home))
    monkeypatch.setenv("GANTRY_CHILD_SENTINEL", "reached the child")

    dump = tmp_path / "child-environment.json"
    dumper = tmp_path / "dump_environment.py"
    dumper.write_text(_ENV_DUMPER, encoding="utf-8")
    # ssh execs `$SHELL -c "exec <this>"`, falling back to /bin/sh only when SHELL is unset --
    # which is one of the things the scrubber removes, so under a scrubbed environment this is
    # POSIX sh and `shlex` is the right quoting. Under the unscrubbed one it is whatever the
    # developer's login shell is, which is a reason to remove SHELL rather than to quote
    # differently.
    proxy = shlex.join([sys.executable, str(dumper), str(dump)])

    opener = open_ssh_transport(
        "127.0.0.1",
        config_file=os.devnull,
        env=scrubbed_ssh_env() if scrubbed else dict(os.environ),
        options={"ProxyCommand": proxy},
    )
    with anyio.fail_after(_CONNECT_TIMEOUT):
        async with opener as transport:
            # Not a race guard, and an earlier version of this comment claimed it was. The
            # dump is safe either way: `ssh` blocks reading the SSH banner from the proxy's
            # stdout so it cannot outrun it, and our own teardown waits for the child rather
            # than pre-empting it -- measured, a proxy that sleeps a full second before
            # writing still gets there under `async with opener: pass`. What the drain buys is
            # the diagnosis: it pins the failure to a `ConnectError` rather than to whatever
            # else a dead proxy might raise, and it populates `stderr_text` so the assertion
            # below can say *why* nothing was observed.
            with pytest.raises(ConnectError):
                await transport.receive()

    assert dump.is_file(), (
        f"ProxyCommand never ran, so this test observed nothing. ssh said: "
        f"{transport.stderr_text!r}"
    )
    seen = json.loads(dump.read_text(encoding="utf-8"))

    if scrubbed:
        assert [name for name in STEERING_VARIABLES if name in seen] == []
        assert seen["HOME"] != str(poisoned_home)
        assert not await anyio.Path(seen["HOME"]).exists()
        assert seen["GANTRY_CHILD_SENTINEL"] == "reached the child"
        assert seen["PATH"] == os.environ["PATH"]
        assert not shell_marker.exists()
    else:
        assert {name: seen.get(name) for name in STEERING_VARIABLES} == poison
        assert seen["HOME"] == str(poisoned_home)
        assert shell_marker.is_file()


# --- 3. the hazard itself --------------------------------------------------------------------


def _agent_pid(announcement: str) -> str:
    """Pull the pid out of ``ssh-agent``'s shell-shaped announcement.

    Under ``-s`` it prints ``SSH_AGENT_PID=1234; export SSH_AGENT_PID;`` for a shell to
    ``eval``. Parsed rather than eval'd, and asserted rather than defaulted -- an agent we
    cannot later kill would outlive the test run.

    ``-s`` is not decoration. Without it ``ssh-agent`` picks its output syntax from ``$SHELL``,
    and a csh-family shell makes it print ``setenv SSH_AGENT_PID 1234;`` instead, which this
    parser does not match -- so on a developer running csh or tcsh every parametrisation would
    fail *and* leak a running agent. ``SHELL`` catching this file out for the second time is
    the reason it is in :data:`sshd.STEERING`.
    """
    for line in announcement.splitlines():
        name, _, rest = line.partition("=")
        if name == "SSH_AGENT_PID":
            return rest.split(";")[0]
    raise AssertionError(f"ssh-agent did not announce a pid: {announcement!r}")


def _fingerprint(key: Path) -> str:
    """``SHA256:...`` for a private key, via ``ssh-keygen``, for comparing against the agent."""
    finished = subprocess.run(
        ["ssh-keygen", "-lf", str(key)],
        capture_output=True,
        text=True,
        timeout=_AGENT_TIMEOUT,
        check=True,
    )
    return finished.stdout.split()[1]


@pytest.fixture
def agent_holding_the_right_key(ssh_server: SSHServer, tmp_path: Path) -> Iterator[dict[str, str]]:
    """A real ``ssh-agent`` loaded with the key that *would* authenticate.

    Real rather than faked, because the thing under test is whether ``ssh`` consults it, and a
    fake socket proves only that our fake was not consulted. The key is the server's genuine
    identity -- the same one every passing test in this suite uses -- so the agent holds
    exactly the credential that makes a wrong-key connection succeed.

    **It fails rather than skips once the binaries are present, and that is the whole design
    of this fixture.** A ``pytest.skip`` on a failing ``ssh-add`` would disarm every row of
    the truth table below and report green; the row that authenticates is the only one in this
    file that can fail for the right reason, and it is the first thing a flake would be
    tempted to skip. Missing binaries are a skip; a broken agent is a failure.

    Yields:
        The two variables a shell would have exported, for a test to poison with.
    """
    for binary in ("ssh-agent", "ssh-add"):
        if shutil.which(binary) is None:  # pragma: no cover -- ships with the ssh client
            pytest.skip(f"{binary} not installed; the agent-rescue proof needs a real agent")

    socket_path = tmp_path / "agent.sock"
    started = subprocess.run(
        ["ssh-agent", "-s", "-a", str(socket_path)],
        capture_output=True,
        text=True,
        timeout=_AGENT_TIMEOUT,
        check=True,
    )
    # The pid is parsed *inside* the try, so that a parse failure is still followed by the
    # kill. Read the other way round -- as it was first written -- a failure here happens
    # after the agent is running and before anything can stop it, and every parametrisation
    # leaves a live ssh-agent behind holding a usable key.
    agent_env = {"SSH_AUTH_SOCK": str(socket_path)}
    try:
        agent_env["SSH_AGENT_PID"] = _agent_pid(started.stdout)
        subprocess.run(
            ["ssh-add", str(ssh_server.identity_file)],
            env={**os.environ, **agent_env},
            capture_output=True,
            text=True,
            timeout=_AGENT_TIMEOUT,
            check=True,
        )
        listed = subprocess.run(
            ["ssh-add", "-l"],
            env={**os.environ, **agent_env},
            capture_output=True,
            text=True,
            timeout=_AGENT_TIMEOUT,
            check=True,
        )
        # `ssh-add` exiting 0 says the request was accepted, not that the agent kept the key.
        # The credential being present is the precondition every row below depends on.
        assert _fingerprint(ssh_server.identity_file) in listed.stdout, listed.stdout
        yield agent_env
    finally:
        if "SSH_AGENT_PID" in agent_env:
            subprocess.run(
                ["ssh-agent", "-k"],
                env={**os.environ, **agent_env},
                capture_output=True,
                timeout=_AGENT_TIMEOUT,
                check=False,
            )


@pytest.mark.parametrize(
    ("scrubbed", "identities_only", "authenticates"),
    [
        pytest.param(True, True, False, id="both-defences"),
        pytest.param(True, False, False, id="scrubbed-environment-alone"),
        pytest.param(False, True, False, id="identities-only-alone"),
        pytest.param(False, False, True, id="neither-and-the-agent-rescues-it"),
    ],
)
async def test_an_agent_holding_the_right_key_cannot_rescue_the_wrong_one(
    ssh_server: SSHServer,
    agent_holding_the_right_key: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    scrubbed: bool,
    identities_only: bool,
    authenticates: bool,
):
    """The failure the scrubber exists to prevent, and the two defences against it.

    Connecting with ``wrong_identity_file`` while an agent holds the right key. Three rows are
    refused; the fourth -- neither defence -- **authenticates**, which is the whole argument.
    Without that row this table would be four ways of saying "the connection failed", and a
    connection can fail for reasons that have nothing to do with the subject.

    Read as a truth table it says something stronger than the card asked for: each defence is
    independently sufficient, so neither is decoration and neither may be dropped as redundant
    on the grounds that the other covers it.

    The only difference between the two environments is ``SSH_AUTH_SOCK`` and
    ``SSH_AGENT_PID``: the unscrubbed one is the scrubbed one with those put back, not the
    developer's real environment. One variable at a time, and it keeps the row that succeeds
    from succeeding through some key in a real ``~/.ssh`` -- which ``ssh`` would otherwise
    reach regardless of ``HOME``.
    """
    # PerSourcePenalties is probed and silently dropped when an sshd will not take it, and this
    # lane spends six deliberate authentication failures per run. Checked here rather than
    # assumed, because its absence does not surface here: it surfaces as a connection reset
    # during key exchange in whatever unrelated test happens to run next.
    #
    # **Dropped is not a failure, and reading it as one is what broke the first CI run.** The
    # directive arrived in OpenSSH 9.8 and `sshd -t` is what drops it, so an sshd that refused
    # it is an sshd older than 9.8 -- which has no penalty feature to suppress. The hazard and
    # the directive are absent for the same reason and by the same version boundary, so the
    # lane is safe either way and the subject of this test still runs. What must not happen is
    # the third state: sshd took the directive and then did not apply it.
    penalties = ssh_server.applied_directives
    assert penalties in (OPTIONAL_DIRECTIVES, ()), (
        f"sshd applied a directive set this suite does not know how to reason about: "
        f"{penalties}. Expected either the full optional set or nothing at all"
    )

    monkeypatch.setenv("SSH_AUTH_SOCK", agent_holding_the_right_key["SSH_AUTH_SOCK"])
    monkeypatch.setenv("SSH_AGENT_PID", agent_holding_the_right_key["SSH_AGENT_PID"])

    options = {
        "UserKnownHostsFile": str(ssh_server.known_hosts),
        "GlobalKnownHostsFile": os.devnull,
    }
    if identities_only:
        options["IdentitiesOnly"] = "yes"

    # Built here rather than through `connect_kwargs` because two of its pinned values are the
    # parametrised subject. `test_the_connection_arguments_carry_both_defences...` is what
    # holds the production constructor to the same standard.
    kwargs = client_kwargs(
        port=ssh_server.port,
        identity_file=ssh_server.wrong_identity_file,
        options=options,
    )
    # The A/B is only meaningful if the agent was visible at the moment the environment was
    # built. Asserting the output alone -- "SSH_AUTH_SOCK is absent" -- is satisfied just as
    # well by a poison that was never there, which is this container's default state.
    assert os.environ["SSH_AUTH_SOCK"] == agent_holding_the_right_key["SSH_AUTH_SOCK"]
    assert "SSH_AUTH_SOCK" not in kwargs["env"]
    if not scrubbed:
        kwargs["env"] = {**kwargs["env"], **agent_holding_the_right_key}

    codec = Codec()
    with anyio.fail_after(_CONNECT_TIMEOUT):
        async with open_ssh_transport("127.0.0.1", **kwargs) as transport:
            if authenticates:
                await negotiate(transport, codec)
            else:
                with pytest.raises(AuthenticationError) as exc:
                    await negotiate(transport, codec)

    if authenticates:
        assert codec.server_version == 3
    else:
        assert "Permission denied" in exc.value.stderr, exc.value.stderr


def test_the_optional_sshd_directives_are_reported_rather_than_assumed(ssh_server: SSHServer):
    """``applied_directives`` exists so the assertion above can be written at all.

    ``_write_config`` tries the whole set and then nothing, so the report is all-or-nothing by
    construction, and that shape is what is pinned here. A partial value would mean someone
    made the fallback per-directive without giving a caller any way to tell which half
    survived -- which is the state this field was added to end.

    Which directives actually applied is asserted where it matters, by the lane that depends
    on one. A test here saying "``PerSourcePenalties`` is present" would fail on an sshd older
    than 9.8 that is otherwise perfectly able to run this suite.
    """
    assert ssh_server.applied_directives in (OPTIONAL_DIRECTIVES, ())

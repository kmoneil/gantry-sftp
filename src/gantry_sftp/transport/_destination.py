"""Which hosts this process is allowed to dial.

D-121. Nothing in this library restricted the *destination* before the first release:
:func:`~gantry_sftp.transport.build_ssh_argv` refuses a host that could be reparsed as an
``ssh`` flag, which is argument-injection defence and a different vulnerability class. An
application that takes a hostname -- or a ``gantry-sftp://`` URL -- from user input and hands
it to :func:`~gantry_sftp.connect` dials whatever it names.

Why this is ambient rather than an argument
-------------------------------------------
An allowlist is a *deployment's* policy, not a call's. The audience the fsspec adapter exists
for makes that concrete: ``pd.read_parquet(url)`` has no per-call surface at all, so a
parameter on :func:`~gantry_sftp.connect` would not reach the place untrusted hosts actually
arrive. A context variable does, and it costs no signature -- which also keeps
``open_ssh_transport`` inside the project-wide ``max-args = 10`` that DESIGN refuses to exempt.

**Layers narrow and never widen.** :data:`ALLOWED_HOSTS_ENV` is one layer if set, each
:func:`allowed_hosts` scope is another, and a host must satisfy **every** active layer. So a
deployment's floor cannot be raised by code running inside it, and nesting two scopes is an
intersection rather than a replacement. This is the one composition rule that makes an ambient
security control safe to nest; the alternative -- an inner scope replacing an outer one -- is a
control that any library in the process can switch off.

What is matched, and why it is not the string the caller passed
---------------------------------------------------------------
**The effective host, read back from** ``ssh -G``. An ``ssh_config`` rewrites the destination
after the name the caller supplied, measured against OpenSSH 10.0p2::

    Host allowed.example.com
      Hostname 169.254.169.254

    $ ssh -G allowed.example.com | grep '^host'
    host allowed.example.com
    hostname 169.254.169.254        <-- what it actually dials

``Match host`` does the same, later still. So an allowlist checking the caller's string is
checkable-but-not-binding the moment a config file is in play, and one is in play by default
because ``-F`` is passed only when asked. Checking the string would also break every legitimate
``ssh_config`` alias, since an alias is by construction not the name of the destination.

``ssh -G`` is given the **same argv** as the real connection, minus the subsystem request,
because ``-o`` overrides change its answer -- ``-o Hostname=10.1.2.3`` is honoured by ``-G``
exactly as it is by the connection.

The assumption this makes, stated rather than implied
------------------------------------------------------
``ssh -G`` **evaluates** ``Match exec``, which runs a program -- verified, not assumed. So this
check assumes the ``ssh_config`` is trusted. That is not a weakening: a config you do not trust
is already arbitrary code execution through ``ProxyCommand`` or ``Match exec`` whether or not
an allowlist exists, which ``_argv.py`` has documented from the start, and the control for it is
``config_file=os.devnull``. An allowlist is a defence against an untrusted *host*, not an
untrusted *config*, and it does not pretend to be one.

Two more non-goals, in the API's own docstring rather than only here: this does not defeat DNS
rebinding, because the name is resolved by ``ssh`` inside the subprocess and this library
resolves nothing (see D-121 for why pinning an address is not available to us); and it is not a
substitute for network egress control, which is the only thing that binds the socket.

A ``ControlPath`` the destination cannot bind
---------------------------------------------
D-202. ``ControlMaster=no`` ships, and an existing master at the resolved ``ControlPath`` is
still used -- so a path that does not change with the destination carries the session to
whichever host that master was opened to, and ``port=``, ``identity_file=`` and the destination
itself are all ignored on the way. Reproduced end to end against two ``sshd``s: the second
server's ``Accepted publickey`` count never moved. ``ssh -G`` reports the *named* destination
regardless, so the allowlist approved a host the session never reached.

The card proposed reading the tokens off the ``controlpath`` line, and that instrument does not
exist: ``-G`` **expands** them, measured against OpenSSH 10.0p2 -- ``%C`` comes back as a hash
and ``%h`` as the name, so a literal ``/tmp/cm`` and a keyed ``/tmp/cm-%h`` are
indistinguishable by inspection. What can be measured is whether the path *changes when the
destination does*: the probe is run a second time with ``-o Hostname=<sentinel>`` placed first
on the command line, where ``ssh``'s first-wins rule makes it beat any ``Hostname`` the caller
or the config supplied, and the two ``controlpath`` lines are compared. ``%h`` and ``%C``
change; a literal path, ``%p`` and ``%r`` do not; and a path the config scopes to the
destination with ``Match host`` is absent from the second answer, which counts as changing,
because in that configuration no other destination reaches the socket.

**Two limits, stated.** ``%n`` and ``%k`` key on the name as typed rather than on the resolved
host, which the sentinel cannot move, so a path keyed on either alone is refused with the same
message -- fail closed, and the message names ``%C``. And the check runs only when a policy is
active, because no policy means no probe, a documented and tested property; without one the
hazard is documented in ``docs/connecting.md`` and nothing measures it.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Generator, Iterable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Final, NamedTuple

import anyio

from gantry_sftp.exceptions import DestinationNotAllowedError

__all__ = [
    "ALLOWED_HOSTS_ENV",
    "ALLOWED_HOSTS_PROBE_TIMEOUT",
    "active_layers",
    "allowed_hosts",
    "check_destination",
    "effective_host",
    "host_matches",
    "normalize_host",
]

ALLOWED_HOSTS_ENV: Final = "GANTRY_SFTP_ALLOWED_HOSTS"
"""Environment variable holding a comma-separated allowlist, applied as the outermost layer."""

ALLOWED_HOSTS_PROBE_TIMEOUT: Final = 10.0
"""Seconds to wait for ``ssh -G``.

Bounded because ``CanonicalizeHostname`` makes the probe do DNS lookups, so it is not
guaranteed to be the ~3 ms a config-only evaluation costs. A probe that hangs must fail the
connection rather than hang it.
"""

_layers: ContextVar[tuple[tuple[str, ...], ...]] = ContextVar("gantry_sftp_allowed_hosts")

_PROBE_HOSTNAME: Final = "gantry-sftp-controlpath-probe.invalid"
"""The destination the second probe substitutes, to see whether ``ControlPath`` moves with it.

Under ``.invalid`` (RFC 2606) so nothing resolves it -- and nothing is dialled either way, since
``-G`` prints configuration and exits.
"""

_SUBSYSTEM_REQUEST_LENGTH: Final = 4
"""How many trailing argv entries ``build_ssh_argv`` spends on the subsystem request.

``["-s", "--", host, subsystem]``. Named rather than spelled as a literal at the one call site,
because it is the length of somebody else's tuple and the reader has to be sent to the module
that decides it.
"""


def normalize_host(host: str) -> str:
    """Fold a hostname to the form patterns are matched against.

    Lowercased because DNS is case-insensitive, and a trailing dot -- the explicit root of a
    fully-qualified name -- is stripped so ``example.com.`` and ``example.com`` cannot be two
    different answers to the same question.

    Args:
        host: A hostname, as given or as ``ssh -G`` reported it.

    Returns:
        The folded form. Not punycode-encoded: an internationalized name is matched as the
        bytes it arrived as, and a pattern must be written the same way.
    """
    return host.strip().rstrip(".").lower()


def _normalize_patterns(patterns: Iterable[str]) -> tuple[str, ...]:
    """Fold and validate an allowlist layer.

    Raises:
        ValueError: If the layer is empty, or a pattern is blank. An empty allowlist would
            refuse every host, which is never what a caller means and is always a bug in how
            the list was built -- an unset variable, a bad split. Refusing it here makes that
            fail where it is written rather than at the next connection.
    """
    folded = tuple(normalize_host(pattern) for pattern in patterns)
    if not folded:
        raise ValueError(
            "allowed_hosts needs at least one pattern; an empty allowlist would refuse every "
            "host, which is a bug in how the list was built rather than a policy"
        )
    if any(not pattern for pattern in folded):
        raise ValueError(f"allowed_hosts patterns may not be blank: {folded!r}")
    return folded


def host_matches(host: str, patterns: Sequence[str]) -> bool:
    """Whether ``host`` satisfies one layer.

    Matching is :func:`fnmatch.fnmatchcase` over the folded forms, so ``*`` and ``?`` and
    ``[seq]`` all work. Case folding is done by :func:`normalize_host` rather than left to
    :func:`fnmatch.fnmatch`, whose case handling is the *filesystem's* and therefore differs
    between platforms -- a policy that depends on the OS is not a policy.

    Note:
        ``*`` matches a dot, so ``*.example.com`` matches ``a.b.example.com``. And it does not
        match ``example.com`` itself, which has no leading label -- list both when both are
        meant. Both are asserted in the tests rather than left to the reader.

    Args:
        host: Hostname to test.
        patterns: One layer's patterns.

    Returns:
        True if any pattern in the layer matches.
    """
    # Both sides are folded. The patterns reaching here through `allowed_hosts` or the
    # environment are folded already, so this is redundant on every shipped path -- but a
    # function whose answer depends on which path called it is one nobody can reason about,
    # and an unfolded `SFTP.EXAMPLE.COM` silently matching nothing reads as a broken policy.
    folded = normalize_host(host)
    return any(fnmatch.fnmatchcase(folded, normalize_host(pattern)) for pattern in patterns)


def _environment_layer(environ: Mapping[str, str]) -> tuple[str, ...] | None:
    """The layer :data:`ALLOWED_HOSTS_ENV` contributes, or ``None`` when it sets no policy.

    An unset variable and an empty one both mean "no policy from the environment". A variable
    holding only separators is a *malformed* policy and raises, because silently reading
    ``GANTRY_SFTP_ALLOWED_HOSTS=","`` as "unrestricted" would turn a typo into an open door.
    """
    raw = environ.get(ALLOWED_HOSTS_ENV)
    if raw is None or not raw.strip():
        return None
    patterns = [piece.strip() for piece in raw.split(",") if piece.strip()]
    if not patterns:
        raise ValueError(
            f"{ALLOWED_HOSTS_ENV} is set to {raw!r}, which names no host patterns; unset it to "
            f"apply no policy, rather than setting it to separators alone"
        )
    return _normalize_patterns(patterns)


def active_layers(environ: Mapping[str, str] | None = None) -> tuple[tuple[str, ...], ...]:
    """Every allowlist layer in force, outermost first.

    Args:
        environ: Environment to read :data:`ALLOWED_HOSTS_ENV` from. Injectable so a test never
            depends on the developer's own environment, which the Definition of Done requires
            of anything that steers a connection.

    Returns:
        A layer per active policy. Empty when nothing restricts destinations, which is the
        default and costs the connection nothing at all -- no probe is run.
    """
    environ = os.environ if environ is None else environ
    from_environment = _environment_layer(environ)
    scopes = _layers.get(())
    if from_environment is None:
        return scopes
    return (from_environment, *scopes)


@contextmanager
def allowed_hosts(patterns: Iterable[str]) -> Generator[None]:
    """Restrict the hosts this library may dial, for the duration of the block.

    Layers narrow and never widen: this scope is applied *in addition to*
    :data:`ALLOWED_HOSTS_ENV` and any enclosing scope, and a host must satisfy all of them. So
    an inner scope cannot re-admit a host an outer one refused.

    ::

        with allowed_hosts(["*.corp.example.com"]):
            async with connect(host_from_user) as sftp:
                ...

    The scope is a :class:`~contextvars.ContextVar`, so it follows the task that entered it and
    does not leak to siblings. Note that it therefore does **not** cross into a thread that
    ``anyio`` did not start with the context -- set :data:`ALLOWED_HOSTS_ENV` when the policy
    has to hold process-wide regardless of who spawns what.

    A ``ControlPath`` that does not change when the destination does is refused while a policy
    is active: an existing master at that socket would carry the session to whichever host it
    was opened to, and the allowlist could not see it. Key the path on the destination
    (``ControlPath=~/.ssh/cm-%C``) or set ``ControlPath=none``.

    Args:
        patterns: Host patterns, matched by :func:`host_matches`. At least one.

    Yields:
        Nothing. The policy is ambient for the block.

    Raises:
        ValueError: If no patterns are given, or one is blank.
    """
    token = _layers.set((*_layers.get(()), _normalize_patterns(patterns)))
    try:
        yield
    finally:
        _layers.reset(token)


def _probe_argv(argv: Sequence[str], host: str) -> list[str]:
    """Turn the connection's argv into the ``ssh -G`` argv that describes it.

    The options have to be carried across verbatim, because ``-G`` honours them -- ``-o
    Hostname=10.1.2.3`` changes its answer exactly as it changes the connection's destination.
    Dropping them would describe a connection nobody is about to make.

    :func:`~gantry_sftp.transport.build_ssh_argv` ends every command with
    ``["-s", "--", host, subsystem]``; ``-s`` and the subsystem are the request to run one, and
    ``-G`` prints configuration instead of connecting, so those four are replaced rather than
    appended to.

    **The tail is checked rather than assumed, and D-127 is about the difference.** That layout
    belongs to ``_argv.py`` and the assumption lives here, so an option appended after the
    subsystem -- a jump host, a second subsystem argument -- would silently make this probe
    describe a different command. It already failed *closed*: a malformed probe exits non-zero
    and :func:`effective_host` refuses, which is the errored-third-state rule doing its job. What
    it did not do is say why. The symptom was "the allowlist refuses every host", which reads as
    a policy bug, and every candidate for that is in another file.

    Raises:
        ValueError: If ``argv`` does not end the way ``build_ssh_argv`` ends. Not an
            ``assert``: this guards a security control and ``python -O`` removes asserts.
    """
    tail = tuple(argv[-_SUBSYSTEM_REQUEST_LENGTH:])
    if len(tail) != _SUBSYSTEM_REQUEST_LENGTH or tail[:3] != ("-s", "--", host):
        raise ValueError(
            f"cannot build an 'ssh -G' probe from this argv: it must end with "
            f"['-s', '--', {host!r}, <subsystem>] as build_ssh_argv writes it, and it ends "
            f"with {list(tail)!r}. The allowlist probe reconstructs the connection's argv by "
            f"position, so a change to that tail belongs in transport/_argv.py and here "
            f"together"
        )
    head = list(argv[:-_SUBSYSTEM_REQUEST_LENGTH])
    return [*head, "-G", "--", host]


class _Resolution(NamedTuple):
    """What one ``ssh -G`` probe says about the connection an argv describes."""

    hostname: str
    """The destination, folded by :func:`normalize_host`."""
    control_path: str | None
    """The ``ControlPath`` with its tokens expanded, or ``None`` when ``ssh`` printed no line --
    which is what it does for an unset path and for ``ControlPath=none`` alike."""


def _unverified(
    reason: str,
    *,
    host: str,
    probe: Sequence[str],
    resolved: _Resolution | None,
    stderr: str = "",
    returncode: int | None = None,
) -> DestinationNotAllowedError:
    """The refusal for a probe whose answer cannot be read.

    One constructor for every way a probe fails, so the message family and the state carried
    with it cannot drift apart between the sites. ``resolved`` is what an earlier probe already
    established: a second probe that fails still tells the operator what the first one read.
    """
    return DestinationNotAllowedError(
        f"cannot check whether {host!r} is an allowed destination: {reason}; refusing the "
        f"connection rather than allowing an unverified destination",
        host=host,
        effective_host=None if resolved is None else resolved.hostname,
        layers=active_layers(),
        control_path=None if resolved is None else resolved.control_path,
        stderr=stderr,
        argv=tuple(probe),
        returncode=returncode,
    )


async def _probe_output(
    probe: Sequence[str], host: str, *, resolved: _Resolution | None = None
) -> str:
    """Run one ``ssh -G`` probe and return what it printed.

    Args:
        probe: The probe argv, from :func:`_probe_argv`.
        host: The host as the caller gave it, for the message.
        resolved: What an earlier probe established, carried into any refusal raised here.

    Returns:
        The probe's standard output, decoded with replacement so a stray byte cannot turn a
        readable answer into an exception of a different class.

    Raises:
        DestinationNotAllowedError: If the probe cannot be spawned, times out, or exits
            non-zero. **Refusing on an unreadable answer is deliberate**: the third state of
            this predicate is "errored", and treating it as "allowed" would make any way of
            breaking the probe into a way of defeating the allowlist.
    """
    try:
        with anyio.fail_after(ALLOWED_HOSTS_PROBE_TIMEOUT):
            completed = await anyio.run_process(probe, check=False)
    except OSError as failure:
        # Both failures of this probe arrive as an `OSError`, and the timeout is the one that
        # does not look like it: `fail_after` raises the builtin `TimeoutError`, which **is**
        # an `OSError` subclass, so naming it alongside would be redundant rather than
        # documentary. Do not narrow this to a spawn error -- the timeout has to keep landing
        # here, because the whole point of the branch is that a probe nobody can read refuses.
        raise _unverified(
            f"the 'ssh -G' probe failed ({failure!r})", host=host, probe=probe, resolved=resolved
        ) from failure

    if completed.returncode != 0:
        raise _unverified(
            f"'ssh -G' exited {completed.returncode}",
            host=host,
            probe=probe,
            resolved=resolved,
            stderr=completed.stderr.decode("utf-8", "replace"),
            returncode=completed.returncode,
        )
    return completed.stdout.decode("utf-8", "replace")


async def _resolve(argv: Sequence[str], host: str) -> _Resolution:
    """Ask ``ssh -G`` where this argv dials and which ``ControlPath`` it would use."""
    probe = _probe_argv(argv, host)
    output = await _probe_output(probe, host)
    reported = _reported_hostname(output)
    if reported is None:
        raise _unverified("'ssh -G' reported no hostname", host=host, probe=probe, resolved=None)
    return _Resolution(reported, _reported_keyword(output, "controlpath"))


async def effective_host(argv: Sequence[str], host: str) -> str:
    """Ask ``ssh`` which host this argv actually dials.

    Args:
        argv: The connection's own argv, from
            :func:`~gantry_sftp.transport.build_ssh_argv`.
        host: The host as the caller gave it, which is the last thing on that argv before the
            subsystem name.

    Returns:
        The ``hostname`` ``ssh -G`` reports, folded by :func:`normalize_host`. Equal to ``host``
        when no config rewrites it, so the check degrades to the obvious one rather than to
        nothing.

    Raises:
        DestinationNotAllowedError: If the probe fails, times out, or reports no ``hostname``.
            **Refusing on an unreadable answer is deliberate**: the third state of this
            predicate is "errored", and treating it as "allowed" would make any way of breaking
            the probe into a way of defeating the allowlist.
    """
    return (await _resolve(argv, host)).hostname


async def _control_path_binds(argv: Sequence[str], host: str, resolved: _Resolution) -> bool:
    """Whether the resolved ``ControlPath`` changes when the destination does.

    ``ssh -G`` expands the tokens, so the path cannot be read for a ``%h`` or ``%C``; what can
    be read is the *answer to a different destination*. The probe is repeated with
    ``-o Hostname=<sentinel>`` inserted **first**, because ``ssh`` resolves a repeated keyword to
    the first ``-o`` on the line and the caller's own ``Hostname`` override, if any, must lose
    to it. A path that comes back unchanged is one every destination shares.

    A second answer with **no** ``controlpath`` line counts as changed: that is a path the config
    scopes to this destination with ``Match host``, and in that configuration no other
    destination reaches the socket.

    Args:
        argv: The connection's own argv.
        host: The host as the caller gave it, kept on the command line so ``Host`` blocks
            still match exactly as they will for the connection.
        resolved: The first probe's answer.

    Returns:
        True if the path moved with the destination.

    Raises:
        DestinationNotAllowedError: If the second probe fails, exactly as for the first.
    """
    probe = _probe_argv(argv, host)
    probe[1:1] = ["-o", f"Hostname={_PROBE_HOSTNAME}"]
    output = await _probe_output(probe, host, resolved=resolved)
    return _reported_keyword(output, "controlpath") != resolved.control_path


def _reported_keyword(output: str, keyword: str) -> str | None:
    """The value of one keyword in ``ssh -G`` output, or ``None`` if it printed no such line.

    ``ssh`` prints ``keyword value`` a line at a time with the keyword lowercased. The **last**
    occurrence is taken rather than the first: the format does not promise uniqueness, and for
    a control the conservative reading is the one that cannot be shadowed by an earlier line.
    The value is everything after the first space, so one carrying a space is kept whole.
    """
    found: str | None = None
    for line in output.splitlines():
        name, separator, value = line.partition(" ")
        if separator and name.strip().lower() == keyword and value.strip():
            found = value.strip()
    return found


def _reported_hostname(output: str) -> str | None:
    """The ``hostname`` line of ``ssh -G`` output, folded."""
    reported = _reported_keyword(output, "hostname")
    return None if reported is None else normalize_host(reported)


def _not_allowed(
    host: str,
    resolved: _Resolution,
    layers: tuple[tuple[str, ...], ...],
    refusing: Sequence[tuple[str, ...]],
) -> DestinationNotAllowedError:
    """The refusal for a destination some layer does not admit."""
    rewritten = (
        ""
        if resolved.hostname == normalize_host(host)
        else f" (which ssh_config rewrites to {resolved.hostname!r})"
    )
    return DestinationNotAllowedError(
        f"{host!r}{rewritten} is not an allowed destination; it matches no pattern in "
        f"{len(refusing)} of the {len(layers)} active allowlist layers "
        f"({', '.join(repr(pattern) for layer in refusing for pattern in layer)}). Layers "
        f"narrow and never widen, so a host must satisfy every one of them",
        host=host,
        effective_host=resolved.hostname,
        layers=layers,
        control_path=resolved.control_path,
    )


def _cannot_bind(
    host: str, resolved: _Resolution, layers: tuple[tuple[str, ...], ...]
) -> DestinationNotAllowedError:
    """The refusal for a ``ControlPath`` every destination would share."""
    return DestinationNotAllowedError(
        f"cannot check whether {host!r} is an allowed destination: ControlPath "
        f"{resolved.control_path!r} does not change when the destination does, so an existing "
        f"multiplexing master at that socket would carry this session to whichever host it was "
        f"opened to, and the allowlist cannot bind it. Key the path on the destination "
        f"(ControlPath=~/.ssh/cm-%C) or set ControlPath=none; refusing the connection rather "
        f"than allowing an unverified destination",
        host=host,
        effective_host=resolved.hostname,
        layers=layers,
        control_path=resolved.control_path,
    )


async def check_destination(
    argv: Sequence[str], host: str, *, environ: Mapping[str, str] | None = None
) -> None:
    """Refuse the connection unless every active layer allows where it is going.

    Does nothing at all -- and spawns nothing -- when no policy is active, which is the default
    and is why this costs an unrestricted caller no round trip and no process.

    Two questions, in this order: does every layer admit the destination ``ssh -G`` reports,
    and -- only when a ``ControlPath`` is in play -- does that path change when the destination
    does. The second costs one more probe, so it is asked only of a connection the first has
    already allowed, and it is asked at all because the answer to the first is not binding
    without it (see the module docstring).

    Args:
        argv: The connection's argv, used verbatim for the probe.
        host: The host as the caller gave it, for the message.
        environ: Environment to read the policy layer from. Injectable for tests.

    Raises:
        DestinationNotAllowedError: If any layer refuses, if the destination cannot be
            determined, or if the ``ControlPath`` is one every destination would share.
    """
    layers = active_layers(environ)
    if not layers:
        return

    resolved = await _resolve(argv, host)
    refusing = [layer for layer in layers if not host_matches(resolved.hostname, layer)]
    if refusing:
        raise _not_allowed(host, resolved, layers, refusing)
    if resolved.control_path is not None and not await _control_path_binds(argv, host, resolved):
        raise _cannot_bind(host, resolved, layers)

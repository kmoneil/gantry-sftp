"""Which hosts this process is allowed to dial.

D-121. Nothing in this library restricted the *destination* until 0.11:
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
an allowlist exists, which ``_argv.py`` has documented since 0.9, and the control for it is
``config_file=os.devnull``. An allowlist is a defence against an untrusted *host*, not an
untrusted *config*, and it does not pretend to be one.

Two more non-goals, in the API's own docstring rather than only here: this does not defeat DNS
rebinding, because the name is resolved by ``ssh`` inside the subprocess and this library
resolves nothing (see D-121 for why pinning an address is not available to us); and it is not a
substitute for network egress control, which is the only thing that binds the socket.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Generator, Iterable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Final

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
    probe = _probe_argv(argv, host)
    try:
        with anyio.fail_after(ALLOWED_HOSTS_PROBE_TIMEOUT):
            completed = await anyio.run_process(probe, check=False)
    except (OSError, TimeoutError) as failure:
        raise DestinationNotAllowedError(
            f"cannot check whether {host!r} is an allowed destination: the 'ssh -G' probe "
            f"failed ({failure!r}); refusing the connection rather than allowing an "
            f"unverified destination",
            host=host,
            effective_host=None,
            layers=active_layers(),
            argv=tuple(probe),
        ) from failure

    if completed.returncode != 0:
        raise DestinationNotAllowedError(
            f"cannot check whether {host!r} is an allowed destination: 'ssh -G' exited "
            f"{completed.returncode}; refusing the connection rather than allowing an "
            f"unverified destination",
            host=host,
            effective_host=None,
            layers=active_layers(),
            stderr=completed.stderr.decode("utf-8", "replace"),
            argv=tuple(probe),
            returncode=completed.returncode,
        )

    reported = _reported_hostname(completed.stdout.decode("utf-8", "replace"))
    if reported is None:
        raise DestinationNotAllowedError(
            f"cannot check whether {host!r} is an allowed destination: 'ssh -G' reported no "
            f"hostname; refusing the connection rather than allowing an unverified destination",
            host=host,
            effective_host=None,
            layers=active_layers(),
            argv=tuple(probe),
        )
    return reported


def _reported_hostname(output: str) -> str | None:
    """The ``hostname`` line of ``ssh -G`` output, folded.

    ``ssh`` prints ``keyword value`` a line at a time with the keyword lowercased. The **last**
    occurrence is taken rather than the first: the format does not promise uniqueness, and for
    a control the conservative reading is the one that cannot be shadowed by an earlier line.
    """
    found: str | None = None
    for line in output.splitlines():
        keyword, separator, value = line.partition(" ")
        if separator and keyword.strip().lower() == "hostname" and value.strip():
            found = normalize_host(value)
    return found


async def check_destination(
    argv: Sequence[str], host: str, *, environ: Mapping[str, str] | None = None
) -> None:
    """Refuse the connection unless every active layer allows where it is going.

    Does nothing at all -- and spawns nothing -- when no policy is active, which is the default
    and is why this costs an unrestricted caller no round trip and no process.

    Args:
        argv: The connection's argv, used verbatim for the probe.
        host: The host as the caller gave it, for the message.
        environ: Environment to read the policy layer from. Injectable for tests.

    Raises:
        DestinationNotAllowedError: If any layer refuses, or the destination cannot be
            determined.
    """
    layers = active_layers(environ)
    if not layers:
        return

    destination = await effective_host(argv, host)
    refusing = [layer for layer in layers if not host_matches(destination, layer)]
    if not refusing:
        return

    rewritten = (
        ""
        if destination == normalize_host(host)
        else f" (which ssh_config rewrites to {destination!r})"
    )
    raise DestinationNotAllowedError(
        f"{host!r}{rewritten} is not an allowed destination; it matches no pattern in "
        f"{len(refusing)} of the {len(layers)} active allowlist layers "
        f"({', '.join(repr(pattern) for layer in refusing for pattern in layer)}). Layers "
        f"narrow and never widen, so a host must satisfy every one of them",
        host=host,
        effective_host=destination,
        layers=layers,
    )

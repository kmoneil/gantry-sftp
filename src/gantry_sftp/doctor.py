"""What this machine can do, and what the far end actually negotiated.

    python -m gantry_sftp doctor                # local only, no network
    python -m gantry_sftp doctor example.com    # and what that server negotiated
    python -m gantry_sftp doctor --json         # the same report, for CI

**There is something here to report only because this library does not implement SSH** (D-90).
A client that *is* the SSH environment has nothing to diagnose: no external binary it did not
run, no ``ssh_config`` somebody else wrote, no agent socket resolved by a program it does not
own. This one spawns OpenSSH, which is the deployment dependency D-89 documents as a liability —
and the same fact is what makes a report possible. What is printed is the same resolution and
the same negotiation a real session performs, printed instead of used.

Three decisions worth stating, because each could have gone the other way.

**It is a diagnostic, not a CLI.** ``doctor`` is the only verb and is meant to stay that way. A
``__main__`` with one verb invites a second, and a library that grows a command surface by
accident ends up maintaining an interface nobody designed. Anything else prints usage and exits
non-zero.

**It is blocking, and that is a test of D-84's facade.** A command has no event loop to inherit,
and :mod:`gantry_sftp.sync` exists so that user-facing code never has to write ``anyio.run``.
This is its first real consumer.

**The output is a channel with a reader.** This feature's whole purpose is to be pasted into a
bug report, so every environment value goes through :func:`~gantry_sftp._logging.mask_environment`
and only the variables that steer ``ssh`` are read at all — the same allowlist a failed
connection logs. A report that leaked a token would be worse than no report, because the reader
would be the internet.

The report is data before it is text: :func:`local_diagnosis` and :func:`server_diagnosis` return
dataclasses, ``--json`` renders them, and a program that wants to assert on its own deployment can
import them rather than scrape the output.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path

from gantry_sftp import __version__
from gantry_sftp._logging import mask_environment
from gantry_sftp.codec import IMPLEMENTED_EXTENSIONS, PROTOCOL_VERSION
from gantry_sftp.exceptions import SFTPError
from gantry_sftp.session import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DEFAULT_REQUEST_TIMEOUT,
    ServerLimits,
)
from gantry_sftp.session._platform import missing_local_io
from gantry_sftp.sync import connect
from gantry_sftp.transport import LOGGED_ENVIRONMENT_VARIABLES, resolve_ssh_executable

__all__ = [
    "TYPICAL_HANDLE",
    "Defaults",
    "Exit",
    "LocalDiagnosis",
    "ServerDiagnosis",
    "local_diagnosis",
    "overall_status",
    "render_json",
    "render_text",
    "server_diagnosis",
    "ssh_config_path",
]

_SSH_VERSION_TIMEOUT = 10.0
"""Seconds to wait for ``ssh -V``. Generous: it prints and exits, so reaching this is a finding."""

TYPICAL_HANDLE = b"\x00\x00\x00\x00"
"""A four-byte handle, which is what the request-size arithmetic is reported against.

A handle travels in every ``READ`` and ``WRITE`` header, so its length comes out of the payload
budget and the answer is genuinely per-handle. Nothing is open during a diagnosis, so the report
names the length it assumed rather than quietly picking one: OpenSSH issues four bytes, and
nothing in the protocol promises another server does.
"""


class Exit(IntEnum):
    """What the command's exit status means.

    Distinct codes rather than a bare 1, because the case this exists for is a ``RUN`` line in
    a Dockerfile: "there is no ssh here" and "the host would not answer" want different
    remedies, and a build that cannot tell them apart has to print and be read by a human,
    which is the thing being automated away.
    """

    OK = 0
    """Everything checked is usable."""

    USAGE = 2
    """Not a question this command answers. Matches ``argparse``'s own convention."""

    NO_SSH = 3
    """No ``ssh`` binary. Nothing else can work; see the README's Requirements section."""

    NO_LOCAL_IO = 4
    """The platform has no offset-addressed local I/O, so transfers refuse (D-82).

    Remote-only operations still work, which is why this is its own code rather than a
    failure: an image that only lists and renames is fine, and its build should be able to
    say so.
    """

    UNREACHABLE = 5
    """The host did not answer, or the session could not be established."""


@dataclass(frozen=True, slots=True)
class Defaults:
    """The tunables a slow transfer makes you want to check, as this build ships them.

    A dataclass rather than a dict, and the reason is that a report is a thing other people
    construct: the renderer indexes these, and a free-form mapping made "a report missing a
    key" a crash in the renderer rather than an error at the boundary. Read from the session's
    own constants, never restated, so a changed default cannot leave the diagnostic confidently
    reporting the old one.
    """

    pipeline_depth: int = DEFAULT_PIPELINE_DEPTH
    request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT


@dataclass(frozen=True, slots=True)
class LocalDiagnosis:
    """What this machine brings, with no network involved.

    Attributes:
        library_version: This package's version.
        protocol_version: The filexfer revision it speaks.
        ssh_executable: What would be spawned, as resolved rather than as configured.
        ssh_resolved_from: How that was arrived at, in words.
        ssh_version: OpenSSH's own version string, or ``None`` if it could not be run.
        ssh_error: Why it could not be run, where it could not.
        transfers_supported: Whether the data path's local primitives exist here.
        missing_local_io: Their names, when they do not.
        ssh_config: The config file ``ssh`` would read, whether or not it exists.
        ssh_config_present: Whether that file is there.
        environment: The variables that steer ``ssh``, masked.
        defaults: The tunables a slow transfer would make you want to check.
    """

    library_version: str
    protocol_version: int
    ssh_executable: str
    ssh_resolved_from: str
    ssh_version: str | None
    ssh_error: str | None
    transfers_supported: bool
    missing_local_io: tuple[str, ...]
    ssh_config: str
    ssh_config_present: bool
    environment: dict[str, str] = field(default_factory=dict)
    defaults: Defaults = field(default_factory=Defaults)

    @property
    def exit_code(self) -> Exit:
        """The worst thing found, as a status. ``ssh`` first: without it nothing else matters."""
        if self.ssh_version is None:
            return Exit.NO_SSH
        if not self.transfers_supported:
            return Exit.NO_LOCAL_IO
        return Exit.OK


@dataclass(frozen=True, slots=True)
class ServerDiagnosis:
    """What one server negotiated, or why it did not.

    Attributes:
        host: The destination as the caller spelled it.
        reached: Whether a session was established.
        error: The failure, rendered, when it was not.
        server: The identified implementation's label.
        server_description: What the quirks profile says it is.
        server_version: The vendor's own version string, where it sends one.
        protocol_version: What the handshake settled on, which is 3 whenever ``reached`` is
            true -- the handshake refuses any other version. A server that negotiates another
            one shows up as ``reached=False`` with the refusal in ``error``, which is the
            report a ``doctor`` run against such a server is for.
        extensions: Every advertised name, in the order the server sent them.
        implemented: Which of those this library can actually send.
        unimplemented: Advertised names nothing here uses.
        absent: Names this library implements that this server did not advertise.
        limits: The ``limits@openssh.com`` answers, or ``None`` where it was not offered. A
            field that is ``None`` inside an answer means the server stated no limit there.
        read_size: Payload bytes per READ, as derived from those limits.
        write_size: Payload bytes per WRITE, likewise.
        depth: Requests kept in flight.
        start_directory: The canonical path of the session's starting point.
        reaped: Handles the router closed because nobody claimed them.
    """

    host: str
    reached: bool
    error: str | None = None
    server: str | None = None
    server_description: str | None = None
    server_version: str | None = None
    protocol_version: int | None = None
    extensions: tuple[str, ...] = ()
    implemented: tuple[str, ...] = ()
    unimplemented: tuple[str, ...] = ()
    absent: tuple[str, ...] = ()
    limits: dict[str, int | None] | None = None
    read_size: int | None = None
    write_size: int | None = None
    depth: int | None = None
    start_directory: str | None = None
    reaped: int | None = None

    @property
    def exit_code(self) -> Exit:
        """Reached or not. Nothing a server says makes a session that happened a failure."""
        return Exit.OK if self.reached else Exit.UNREACHABLE


def ssh_config_path(environ: Mapping[str, str] | None = None) -> Path:
    """The per-user config file ``ssh`` will read, resolved the way ``ssh`` resolves it.

    **Not** :meth:`pathlib.Path.home`, and the difference is the whole reason this is a
    function. ``ssh`` expands ``~`` from ``getpwuid(getuid())``, not from ``$HOME`` — measured
    while building the transport's environment handling — so a process with ``HOME`` redirected
    still reads the *account's* ``~/.ssh/config``. A diagnostic that resolved it through
    ``$HOME`` would report a file ``ssh`` is not going to read, and would do it precisely in the
    situation where somebody is trying to work out why their config is being ignored.

    Args:
        environ: Consulted only for the fallback below. Defaults to the real environment.

    Returns:
        The path, whether or not it exists.
    """
    try:
        import pwd  # noqa: PLC0415 -- Unix-only, and this function is where that is handled
    except ImportError:
        # Windows has no `pwd` and no getpwuid; there, OpenSSH does use the profile directory,
        # so the environment is the right source rather than a second-best one.
        environ = os.environ if environ is None else environ
        home = environ.get("USERPROFILE") or environ.get("HOME") or "~"
        return Path(home) / ".ssh" / "config"
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".ssh" / "config"


def _ssh_version(executable: str) -> tuple[str | None, str | None]:
    """Run ``ssh -V`` and return its output, or the reason there is none.

    ``-V`` prints to **stderr** and exits non-zero on some builds, so neither the stream nor the
    return code is the signal — the presence of output is. A list argv and no shell, as
    everywhere else that spawns anything here.

    Returns:
        ``(version, None)`` or ``(None, why not)``.
    """
    try:
        finished = subprocess.run(  # noqa: S603 -- resolved executable, list argv, no shell
            [executable, "-V"],
            capture_output=True,
            timeout=_SSH_VERSION_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return None, (
            f"{executable!r} is not on PATH. OpenSSH is a runtime requirement of this library, "
            f"not an optional extra: install the openssh-client package"
        )
    except PermissionError:
        return None, f"{executable!r} exists but could not be executed; check its mode"
    except subprocess.TimeoutExpired:
        return None, f"{executable!r} did not answer -V within {_SSH_VERSION_TIMEOUT:.0f}s"
    banner = (finished.stderr or finished.stdout).decode("utf-8", "replace").strip()
    if not banner:
        return None, f"{executable!r} ran but printed no version"
    return banner.splitlines()[0], None


def _resolution_note(executable: str) -> str:
    """How the resolved name will actually be found, in a sentence an operator can act on."""
    if Path(executable).is_absolute():
        return "an absolute path, probed under SystemRoot (Windows)"
    return "a bare name, so PATH decides at spawn time"


def local_diagnosis(environ: Mapping[str, str] | None = None) -> LocalDiagnosis:
    """Everything answerable without a network.

    This is the mode a Dockerfile runs, so it reaches no host and its exit code is the whole
    point: an image that cannot spawn ``ssh`` should fail its own build rather than a customer's
    first transfer.

    Args:
        environ: Environment to read. Defaults to the real one. Injectable so a test can state
            what it is asserting about instead of inheriting the developer's shell.

    Returns:
        The report.
    """
    environ = os.environ if environ is None else environ
    executable = resolve_ssh_executable(environ=environ)
    version, error = _ssh_version(executable)
    missing = missing_local_io()
    config = ssh_config_path(environ)
    steering = {name: environ[name] for name in LOGGED_ENVIRONMENT_VARIABLES if name in environ}
    return LocalDiagnosis(
        library_version=__version__,
        protocol_version=PROTOCOL_VERSION,
        ssh_executable=executable,
        ssh_resolved_from=_resolution_note(executable),
        ssh_version=version,
        ssh_error=error,
        transfers_supported=not missing,
        missing_local_io=missing,
        ssh_config=str(config),
        ssh_config_present=config.exists(),
        environment=mask_environment(steering),
        defaults=Defaults(),
    )


def server_diagnosis(
    host: str,
    *,
    user: str | None = None,
    port: int | None = None,
    identity_file: str | os.PathLike[str] | None = None,
    config_file: str | os.PathLike[str] | None = None,
    options: Mapping[str, str] | None = None,
) -> ServerDiagnosis:
    """Connect once, report what was negotiated, and close.

    Every value here is read from the same session a transfer would use, which is what makes it
    a better answer to "why did ``posix_rename`` not happen" than any log line: the extension
    table is the server's own advertisement, and the request size is the number the scheduler
    would actually use rather than the default it started from.

    Args:
        host: Destination, as :func:`~gantry_sftp.connect` takes it.
        user: Log in as somebody other than the local account.
        port: A non-default port.
        identity_file: A private key to offer, as ``ssh -i``.
        config_file: An ``ssh_config`` to use instead of the account's own.
        options: ``-o`` options, which is how a diagnosis reproduces the connection that is
            actually failing rather than a simplified one that works.

    Named parameters rather than a ``**kwargs`` passed through, and the reason is worth
    keeping: a splat is untypeable at the ``connect`` call below, and silencing that would
    have hidden a real question — which of ``connect``'s ten arguments a *diagnostic* should
    offer. Three are deliberately absent. **``password``**, because a secret does not belong
    on the command line this exists to serve. **``env``**, because the process environment is
    part of what is being diagnosed, and a flag that replaced it would be diagnosing a fiction
    while the report above still claimed to say which steering variables are set. And
    **``session``**, because a tunable changes how fast a transfer goes, not what a handshake
    settles on.

    Returns:
        The report, including the failure where there was one. **Refusing to raise is the
        design**: a diagnostic that dies on the condition it was run to diagnose has nothing to
        say about the only case that matters.
    """
    try:
        with connect(
            host,
            user=user,
            port=port,
            identity_file=identity_file,
            config_file=config_file,
            options=options,
        ) as sftp:
            advertised = tuple(name.decode("utf-8", "replace") for name in sftp.extensions)
            implemented = tuple(name for name in advertised if name in IMPLEMENTED_EXTENSIONS)
            sizes = sftp.sizes_for(TYPICAL_HANDLE)
            return ServerDiagnosis(
                host=host,
                reached=True,
                server=sftp.profile.label,
                server_description=sftp.profile.description,
                server_version=sftp.profile.version,
                protocol_version=sftp.server_version,
                extensions=advertised,
                implemented=implemented,
                unimplemented=tuple(name for name in advertised if name not in implemented),
                absent=tuple(name for name in IMPLEMENTED_EXTENSIONS if name not in advertised),
                limits=_limits_of(sftp.limits),
                read_size=sizes.read_length,
                write_size=sizes.write_length,
                depth=sftp.depth,
                start_directory=sftp.realpath().decode("utf-8", "surrogateescape"),
                reaped=sftp.reaped,
            )
    except (SFTPError, OSError) as failure:
        return ServerDiagnosis(
            host=host, reached=False, error=f"{type(failure).__name__}: {failure}"
        )


def _limits_of(limits: ServerLimits) -> dict[str, int | None] | None:
    """The four ``limits@openssh.com`` numbers, or ``None`` where the server offered none.

    Two absences, kept apart. A server that never answered the extension leaves every field
    ``None``, and reporting the conservative defaults the session then uses would be the
    diagnostic asserting its own guess back at the reader as though the server had said it. A
    server that answered with a ``0`` in one field is saying *no limit* on that one, which
    :class:`~gantry_sftp.session.ServerLimits` also stores as ``None`` -- so a field that is
    ``None`` inside an otherwise-populated answer means "unlimited", and that is why the
    fields are rendered rather than dropped.
    """
    values = {
        "max_packet_length": limits.max_packet_length,
        "max_read_length": limits.max_read_length,
        "max_write_length": limits.max_write_length,
        "max_open_handles": limits.max_open_handles,
    }
    return None if all(value is None for value in values.values()) else values


def render_text(local: LocalDiagnosis, server: ServerDiagnosis | None = None) -> str:
    """The human report. Fixed-width labels, one fact per line, nothing that needs a terminal."""
    lines = [
        "gantry-sftp doctor",
        "",
        "local",
        f"  library                 {local.library_version} (filexfer v{local.protocol_version})",
        f"  ssh executable          {local.ssh_executable} -- {local.ssh_resolved_from}",
        f"  ssh version             {local.ssh_version or f'NOT USABLE: {local.ssh_error}'}",
        f"  transfers               {_transfers_line(local)}",
        f"  ssh config              {local.ssh_config}{_absent(local.ssh_config_present)}",
    ]
    lines.append("  environment             " + (_environment_line(local.environment)))
    lines.append(
        f"  defaults                depth={local.defaults.pipeline_depth} "
        f"request_timeout={local.defaults.request_timeout} "
        f"idle_timeout={local.defaults.idle_timeout}"
    )
    if server is not None:
        lines += ["", f"server {server.host}"]
        lines += _server_lines(server)
    lines += [
        "",
        f"exit {overall_status(local, server).value} ({overall_status(local, server).name})",
    ]
    return "\n".join(lines)


def _absent(present: bool) -> str:
    """Mark a path that is not there. A config file `ssh` will not read is the finding."""
    return "" if present else " (absent)"


def _transfers_line(local: LocalDiagnosis) -> str:
    if local.transfers_supported:
        return "supported"
    return f"NOT SUPPORTED here -- needs {', '.join(local.missing_local_io)} (remote-only ops work)"


def _environment_line(environment: Mapping[str, str]) -> str:
    if not environment:
        return "none of the steering variables are set"
    return ", ".join(f"{name}={value}" for name, value in environment.items())


def _server_lines(server: ServerDiagnosis) -> list[str]:
    """The negotiated half, or the reason there is none.

    **A failure gets its own indented block rather than a field**, because the most valuable
    thing this command can print is a multi-line one: a ``ConnectError`` carries OpenSSH's
    stderr verbatim, and that stderr is usually the entire diagnosis. Rendering it as the tail
    of a fixed-width field puts the answer in the one place the layout makes unreadable --
    found by running it against an unreachable host, where a local ``ssh_config`` full of
    options this OpenSSH build rejects turned out to be why nothing on this machine could
    connect at all.
    """
    if not server.reached:
        reason = (server.error or "no reason recorded").splitlines()
        return ["  NOT REACHED", *(f"    {line}" if line else "" for line in reason)]
    lines = [
        f"  identified as           {server.server} -- {server.server_description}",
        f"  protocol                v{server.protocol_version}",
        f"  extensions              {len(server.extensions)} advertised, "
        f"{len(server.implemented)} used here",
    ]
    lines += [f"    uses                  {name}" for name in server.implemented]
    lines += [f"    ignores               {name}" for name in server.unimplemented]
    lines += [f"    absent                {name} -- documented fallback" for name in server.absent]
    if server.limits is None:
        lines.append("  limits                  not advertised; conservative defaults in use")
    else:
        lines += [
            f"  limits.{name:<17}{'no limit' if value is None else value}"
            for name, value in server.limits.items()
        ]
    lines += [
        f"  request size            read={server.read_size} write={server.write_size} "
        f"(for a {len(TYPICAL_HANDLE)}-byte handle)",
        f"  depth                   {server.depth}",
        f"  start directory         {server.start_directory}",
        f"  handles reaped          {server.reaped}",
    ]
    return lines


def render_json(local: LocalDiagnosis, server: ServerDiagnosis | None = None) -> str:
    """The same report as JSON, so CI asserts on it instead of scraping the text."""
    payload: dict[str, object] = {
        "local": asdict(local),
        "exit": int(overall_status(local, server)),
        "status": overall_status(local, server).name,
    }
    if server is not None:
        payload["server"] = asdict(server)
    return json.dumps(payload, indent=2, sort_keys=True)


def overall_status(local: LocalDiagnosis, server: ServerDiagnosis | None) -> Exit:
    """The status of the whole run: local problems outrank a server that did not answer.

    An unreachable host on a machine with no ``ssh`` is a machine with no ``ssh``, and saying
    so is the difference between one remedy and a wild goose chase.

    Public, and used by both the renderers and ``__main__``, so the number printed in the
    report and the number the process exits with cannot disagree -- which they would the first
    time somebody changed one of two copies.

    Args:
        local: The local half, which is always present.
        server: The server half, where a host was given.

    Returns:
        The status to exit with.
    """
    if local.exit_code is not Exit.OK:
        return local.exit_code
    if server is not None:
        return server.exit_code
    return Exit.OK

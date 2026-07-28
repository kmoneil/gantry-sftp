"""Building the ``ssh`` command line, safely.

Pure and synchronous on purpose. Argument injection into ``ssh`` is a real, exploited
vulnerability class, and the defence against it should be testable without spawning
anything -- so every decision about what ends up in argv is made here, by a function that
takes strings and returns a list of strings.

The shape comes from OpenSSH's own ``sftp.c``, not from guesswork::

    ssh <options> -s -- <host> sftp

``-s`` comes **before** ``--``. It is an ``ssh`` flag meaning "the command is a subsystem
name", so it has to be parsed as an option; putting it after ``--`` would make it part of
the remote command and the subsystem request would never happen.

Why any of this matters
-----------------------
A hostname is often attacker-influenced -- read from a config file, a database row, a URL.
Passed to ``ssh`` without ``--``, a hostname that begins with ``-`` is parsed as options.
Against OpenSSH 10.0p2::

    $ ssh -F /dev/null -o BatchMode=yes '-oProxyCommand=echo PWNED >&2' host -s sftp
    PWNED

That is arbitrary command execution from a string that looked like a hostname. With ``--``
the same string is refused as a hostname instead. We pass ``--`` *and* reject hosts
beginning with ``-`` before argv is built, because ``--`` handling is an OpenSSH behaviour
we do not control across the versions people actually run, and the two defences fail
independently.
"""

from __future__ import annotations

import os
import sys
import warnings
from collections.abc import Mapping
from pathlib import Path

from gantry_sftp.exceptions import InsecureOptionWarning

__all__ = [
    "DEFAULT_SSH_OPTIONS",
    "DEFAULT_SUBSYSTEM",
    "PASSWORD_AUTH_OPTIONS",
    "build_ssh_argv",
    "options_for_password_auth",
    "resolve_ssh_executable",
]

DEFAULT_SUBSYSTEM = "sftp"

# The bare Windows executable name, used both as the PATH-resolved fallback and as the leaf
# of the absolute candidates below.
_WINDOWS_SSH_EXE = "ssh.exe"

DEFAULT_SSH_OPTIONS: Mapping[str, str] = {
    # No prompting. A hung transfer waiting on an invisible password prompt is the single
    # most common way an automated SFTP job fails silently.
    "BatchMode": "yes",
    # Refuse unknown host keys rather than trusting on first use.
    "StrictHostKeyChecking": "yes",
    # The next four mirror what OpenSSH's own sftp(1) always passes, and they are not
    # cosmetic: `LocalCommand` in a user's ssh_config runs an arbitrary program on *this*
    # machine when a connection is set up. `PermitLocalCommand no` disables it, and
    # `ClearAllForwardings yes` drops any forwardings a config tries to establish. An SFTP
    # client has no business doing either, and a config file is not always trusted input.
    "PermitLocalCommand": "no",
    "ClearAllForwardings": "yes",
    "ForwardX11": "no",
    "ForwardAgent": "no",
    # "no" means "do not *become* a multiplexing master". An existing master is still used
    # when ControlPath points at one, which is where the connection-setup win comes from --
    # this does not opt out of multiplexing, only out of hosting it.
    "ControlMaster": "no",
}
"""Options applied unless the caller overrides them by name."""

PASSWORD_AUTH_OPTIONS: Mapping[str, str] = {
    # The finding D-78 was filed for. `BatchMode=yes` does not merely discourage a password
    # prompt, it suppresses the askpass helper *outright* -- measured against OpenSSH 10.0p2,
    # with a correct `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force` present and ignored. So
    # password authentication is not awkward under the shipped default, it is impossible, and
    # relaxing this on the password path is what makes the feature exist at all.
    "BatchMode": "no",
    # Deterministic method order, which matters more than it looks. Without it `ssh` tries
    # publickey first and offers every identity it can find; against a server with a low
    # `MaxAuthTries` the attempts are exhausted before password is ever reached, and the
    # failure -- "Too many authentication failures" -- names nothing that is actually wrong.
    # `keyboard-interactive` is included because appliances routinely offer *only* that, and
    # OpenSSH answers its prompts through the same askpass helper.
    "PreferredAuthentications": "password,keyboard-interactive",
    # One attempt. The default is three, and each one re-runs the helper with the same wrong
    # secret -- three guaranteed failures, which on an OpenSSH 9.8+ server earns the source
    # address a `PerSourcePenalties` timeout that then breaks the *next*, unrelated
    # connection from this host.
    "NumberOfPasswordPrompts": "1",
}
"""Options layered over :data:`DEFAULT_SSH_OPTIONS` when a password is supplied.

Applied *under* the caller's own ``options``, so every one of them can still be overridden by
name -- except ``BatchMode``, where an explicit ``yes`` contradicts the request rather than
refining it and is refused. See :func:`options_for_password_auth`.
"""

_FORBIDDEN_IN_ARGUMENTS = ("\x00", "\n", "\r")

_MIN_PORT = 1
_MAX_PORT = 65535


def _reject_control_characters(value: str, *, what: str) -> None:
    for bad in _FORBIDDEN_IN_ARGUMENTS:
        if bad in value:
            raise ValueError(f"{what} may not contain {bad!r}: {value!r}")


def _validate_host(host: str) -> None:
    if not host:
        raise ValueError("host may not be empty")
    _reject_control_characters(host, what="host")
    if host.startswith("-"):
        # `--` should already make this harmless. This is the second, independent defence:
        # see the module docstring for what it costs to get wrong.
        raise ValueError(
            f"host may not begin with '-': {host!r}; a leading dash makes a hostname "
            f"indistinguishable from an ssh option"
        )
    if "@" in host:
        raise ValueError(
            f"host may not contain '@': {host!r}; pass the username as user=... so both "
            f"halves are validated separately"
        )
    if any(char.isspace() for char in host):
        raise ValueError(f"host may not contain whitespace: {host!r}")


def _validate_user(user: str) -> None:
    if not user:
        raise ValueError("user may not be empty")
    _reject_control_characters(user, what="user")
    if user.startswith("-"):
        raise ValueError(f"user may not begin with '-': {user!r}")
    if any(char.isspace() for char in user):
        raise ValueError(f"user may not contain whitespace: {user!r}")


def _validate_option(name: str, value: str) -> None:
    if not name:
        raise ValueError("ssh option name may not be empty")
    # A newline would end the config line ssh parses out of `-o`, so anything after it is
    # a directive we did not intend to send.
    _reject_control_characters(name, what="ssh option name")
    _reject_control_characters(value, what=f"value of ssh option {name!r}")
    if "=" in name:
        raise ValueError(f"ssh option name may not contain '=': {name!r}")
    if any(char.isspace() for char in name):
        raise ValueError(f"ssh option name may not contain whitespace: {name!r}")


def _merged_options(overrides: Mapping[str, str] | None) -> dict[str, str]:
    """Apply caller overrides over the defaults, warning about the dangerous ones."""
    options = dict(DEFAULT_SSH_OPTIONS)
    if not overrides:
        return options

    for name, value in overrides.items():
        _validate_option(name, value)
        options[name] = value

    strictness = options["StrictHostKeyChecking"]
    if strictness != DEFAULT_SSH_OPTIONS["StrictHostKeyChecking"]:
        # Overridable, but never quietly: this is the check that stops a machine-in-the-
        # middle from reading every byte of the transfer.
        warnings.warn(
            f"StrictHostKeyChecking is set to {strictness!r} rather than 'yes'; "
            f"host keys will not be verified as strictly and the connection may be "
            f"intercepted without error",
            InsecureOptionWarning,
            stacklevel=3,
        )
    return options


def options_for_password_auth(options: Mapping[str, str] | None) -> dict[str, str]:
    """Layer :data:`PASSWORD_AUTH_OPTIONS` under the caller's own options.

    Pure, so what the password path does to the command line is testable without spawning
    anything -- which is the same reason the rest of this module exists.

    Args:
        options: The caller's ``-o`` overrides, or ``None``. Takes precedence over
            :data:`PASSWORD_AUTH_OPTIONS` for every name except ``BatchMode``.

    Returns:
        Options to hand to :func:`build_ssh_argv`, which still layers them over
        :data:`DEFAULT_SSH_OPTIONS`.

    Raises:
        ValueError: If the caller asks for password authentication and ``BatchMode=yes`` in
            the same call. That is a contradiction rather than a preference: the connection
            would fail with ``Permission denied`` and nothing in the message would say why.
    """
    merged = dict(PASSWORD_AUTH_OPTIONS)
    if options:
        merged.update(options)
    batch_mode = merged["BatchMode"]
    if batch_mode.strip().lower() != "no":
        raise ValueError(
            f"password= needs BatchMode=no, but options set BatchMode={batch_mode!r}; "
            f"BatchMode=yes suppresses the askpass helper outright, so ssh would never ask "
            f"for the password and the connection would fail with 'Permission denied'"
        )
    return merged


def resolve_ssh_executable(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Work out which ``ssh`` to run.

    On POSIX this is just ``ssh`` and ``PATH`` decides. On Windows it is the OpenSSH that
    ships with the OS, which needs care: a 32-bit Python on 64-bit Windows has its
    ``System32`` requests redirected to ``SysWOW64``, where OpenSSH is not, so the real
    directory has to be reached through the ``SysNative`` alias instead.

    Args:
        platform: ``sys.platform`` value to resolve for. Injectable so the Windows branch
            is testable from anywhere.
        environ: Environment to read ``SystemRoot`` from. Injectable for the same reason.

    Returns:
        An executable name or absolute path. A bare name is resolved by ``PATH`` at spawn
        time, which is what we want on POSIX.

    Note:
        The Windows branch is exercised by unit tests with injected inputs. It has not been
        run on Windows, and this docstring will say so until it has.
    """
    platform = sys.platform if platform is None else platform
    if not platform.startswith("win"):
        return "ssh"

    environ = os.environ if environ is None else environ
    system_root = environ.get("SystemRoot") or environ.get("SYSTEMROOT")
    if not system_root:
        return _WINDOWS_SSH_EXE

    # A 32-bit process gets SysWOW64 when it asks for System32; SysNative is the alias that
    # reaches the real one. A 64-bit process has no SysNative, so it is not a valid guess
    # there -- hence checking rather than assuming.
    for directory in ("SysNative", "System32"):
        candidate = Path(system_root) / directory / "OpenSSH" / _WINDOWS_SSH_EXE
        if candidate.exists():
            return str(candidate)
    return _WINDOWS_SSH_EXE


def build_ssh_argv(
    host: str,
    *,
    user: str | None = None,
    port: int | None = None,
    config_file: str | os.PathLike[str] | None = None,
    identity_file: str | os.PathLike[str] | None = None,
    options: Mapping[str, str] | None = None,
    subsystem: str = DEFAULT_SUBSYSTEM,
    ssh_executable: str | None = None,
) -> list[str]:
    """Build the argv for ``ssh -s sftp``.

    Args:
        host: Hostname or ssh_config alias. May not begin with ``-``, contain ``@``,
            whitespace, or control characters.
        user: Remote username, passed as ``-l``. Put it here rather than in ``host`` so
            both halves get validated.
        port: Remote port, passed as ``-p``.
        config_file: Passed as ``-F``. Pass ``os.devnull`` to ignore the user's config
            entirely, which is what a test should do.
        identity_file: Passed as ``-i``.
        options: ``-o`` options, overriding :data:`DEFAULT_SSH_OPTIONS` by name. Weakening
            ``StrictHostKeyChecking`` warns.
        subsystem: Subsystem name, or a path to an sftp server binary for a server with no
            subsystem configured.
        ssh_executable: Override which ``ssh`` to run. Defaults to
            :func:`resolve_ssh_executable`.

    Returns:
        A complete argv list. Never a string, and never for a shell -- there is no shell
        involved anywhere in this library.

    Raises:
        ValueError: If any argument could be misread as an ``ssh`` option, or contains a
            character that would let it mean something other than it says.

    Warns:
        InsecureOptionWarning: If ``StrictHostKeyChecking`` is weakened.
    """
    _validate_host(host)
    if user is not None:
        _validate_user(user)
    if port is not None and not _MIN_PORT <= port <= _MAX_PORT:
        raise ValueError(f"port must be between {_MIN_PORT} and {_MAX_PORT}, got {port}")
    if not subsystem:
        raise ValueError("subsystem may not be empty")
    _reject_control_characters(subsystem, what="subsystem")

    argv = [ssh_executable if ssh_executable is not None else resolve_ssh_executable()]

    if config_file is not None:
        config = os.fspath(config_file)
        _reject_control_characters(config, what="config_file")
        argv += ["-F", config]
    if identity_file is not None:
        identity = os.fspath(identity_file)
        _reject_control_characters(identity, what="identity_file")
        argv += ["-i", identity]
    if port is not None:
        argv += ["-p", str(port)]
    if user is not None:
        argv += ["-l", user]

    for name, value in sorted(_merged_options(options).items()):
        argv += ["-o", f"{name}={value}"]

    # Order is load-bearing and comes from sftp.c: -s is an option and must be parsed as
    # one, then -- ends option parsing, then the host, then the subsystem name.
    argv += ["-s", "--", host, subsystem]
    return argv

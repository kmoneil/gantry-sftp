"""Transports: the byte pipe underneath the codec.

This is the layer that is allowed to touch the operating system, and the only one that
spawns anything. It is also the first async layer -- and async here means **anyio**, never
bare ``asyncio``. ``asyncio.Queue``, ``asyncio.wait_for`` and ``loop.*`` are bugs in this
package: they cost trio support and buy nothing that anyio does not already provide.
``tests/test_layer_discipline.py`` enforces that.

Available transports:

* :func:`open_ssh_transport` -- ``ssh -s sftp``. The default, and the reason the library
  contains no cryptography.
* :func:`open_local_server_transport` -- ``sftp-server`` on a pipe, no ``ssh`` at all.
"""

from __future__ import annotations

from gantry_sftp.transport._argv import (
    DEFAULT_SSH_OPTIONS,
    DEFAULT_SUBSYSTEM,
    PASSWORD_AUTH_OPTIONS,
    build_ssh_argv,
    options_for_password_auth,
    resolve_ssh_executable,
)
from gantry_sftp.transport._askpass import (
    ASKPASS_ANSWER_VARIABLE,
    ASKPASS_ARMING_VARIABLES,
    askpass_environment,
)
from gantry_sftp.transport._base import DEFAULT_RECEIVE_SIZE, Transport
from gantry_sftp.transport._diagnosis import (
    AUTH_MARKERS,
    HOST_KEY_MARKERS,
    INTERACTIVE_AUTH_METHODS,
    classify_failure,
    password_auth_hint,
)
from gantry_sftp.transport._subprocess import (
    SFTP_SERVER_CANDIDATES,
    StderrBuffer,
    SubprocessTransport,
    find_sftp_server,
    open_local_server_transport,
    open_ssh_transport,
)

__all__ = [
    "ASKPASS_ANSWER_VARIABLE",
    "ASKPASS_ARMING_VARIABLES",
    "AUTH_MARKERS",
    "DEFAULT_RECEIVE_SIZE",
    "DEFAULT_SSH_OPTIONS",
    "DEFAULT_SUBSYSTEM",
    "HOST_KEY_MARKERS",
    "INTERACTIVE_AUTH_METHODS",
    "PASSWORD_AUTH_OPTIONS",
    "SFTP_SERVER_CANDIDATES",
    "StderrBuffer",
    "SubprocessTransport",
    "Transport",
    "askpass_environment",
    "build_ssh_argv",
    "classify_failure",
    "find_sftp_server",
    "open_local_server_transport",
    "open_ssh_transport",
    "options_for_password_auth",
    "password_auth_hint",
    "resolve_ssh_executable",
]

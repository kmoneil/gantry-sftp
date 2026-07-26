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
    build_ssh_argv,
    resolve_ssh_executable,
)
from gantry_sftp.transport._base import DEFAULT_RECEIVE_SIZE, Transport
from gantry_sftp.transport._subprocess import (
    SFTP_SERVER_CANDIDATES,
    StderrBuffer,
    SubprocessTransport,
    find_sftp_server,
    open_local_server_transport,
    open_ssh_transport,
)

__all__ = [
    "DEFAULT_RECEIVE_SIZE",
    "DEFAULT_SSH_OPTIONS",
    "DEFAULT_SUBSYSTEM",
    "SFTP_SERVER_CANDIDATES",
    "StderrBuffer",
    "SubprocessTransport",
    "Transport",
    "build_ssh_argv",
    "find_sftp_server",
    "open_local_server_transport",
    "open_ssh_transport",
    "resolve_ssh_executable",
]

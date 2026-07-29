"""gantry-sftp -- a modern Python SFTP library that does not implement SSH at all.

OpenSSH is spawned as a subprocess and hands us a plaintext, framed SFTP byte stream, so
there is zero cryptography in this package. What is left is a protocol codec, a scheduler,
and an ergonomics layer.

What exists today, from a distribution a user actually installed::

    from gantry_sftp.transport import open_ssh_transport
    from gantry_sftp.session import open_session

    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        await sftp.get("/incoming/data.parquet", "data.parquet")

:mod:`gantry_sftp.transport` opens the connection, :mod:`gantry_sftp.session` is the API --
``get`` / ``put`` (atomic by default, resumable, verifiable), ``listdir`` / ``scandir`` /
``walk``, ``get_tree`` / ``put_tree`` / ``rmtree``, ``with_reconnect``, and several transfers
at once over one connection. :mod:`gantry_sftp.codec` is the sans-I/O protocol layer
underneath, public because a frame dumper and a fuzz harness need it. Typed errors are
re-exported here; every one carries state rather than a string.

This module used to point at ``_plans/DESIGN.md`` and ``_plans/progress.md``. Neither is in
any distribution -- they are gitignored working documents -- so ``help(gantry_sftp)`` was
sending readers to files they could not obtain (D-47). The README is what ships.
"""

from __future__ import annotations

from gantry_sftp.exceptions import (
    AuthenticationError,
    CapabilityError,
    ConnectError,
    DestinationCollisionError,
    HostKeyError,
    InsecureOptionWarning,
    NoSuchFileError,
    PathCollision,
    PermissionDeniedError,
    ProtocolError,
    ServerError,
    SFTPError,
    SFTPWarning,
    StateError,
    TransferError,
    TransferTimeoutError,
    UnsafePathError,
    UnsupportedError,
)

__all__ = [
    "AuthenticationError",
    "CapabilityError",
    "ConnectError",
    "DestinationCollisionError",
    "HostKeyError",
    "InsecureOptionWarning",
    "NoSuchFileError",
    "PathCollision",
    "PermissionDeniedError",
    "ProtocolError",
    "SFTPError",
    "SFTPWarning",
    "ServerError",
    "StateError",
    "TransferError",
    "TransferTimeoutError",
    "UnsafePathError",
    "UnsupportedError",
    "__version__",
]

__version__ = "0.0.0"
"""The one place the version is written.

``pyproject.toml`` reads it from here through ``[tool.hatch.version]`` rather than restating
it, because two hand-maintained copies means a bug report can name a release the reporter did
not install. ``tests/test_packaging.py`` asserts the built distribution agrees with this."""

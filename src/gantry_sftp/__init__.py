"""gantry-sftp -- a modern Python SFTP library that does not implement SSH at all.

OpenSSH is spawned as a subprocess and hands us a plaintext, framed SFTP byte stream, so
there is zero cryptography in this package. What is left is a protocol codec, a scheduler,
and an ergonomics layer.

The public surface is still being built. See ``_plans/DESIGN.md`` for what is coming and
``_plans/progress.md`` for what actually exists today.
"""

from __future__ import annotations

from gantry_sftp.exceptions import (
    AuthenticationError,
    ConnectError,
    HostKeyError,
    InsecureOptionWarning,
    NoSuchFileError,
    PermissionDeniedError,
    ProtocolError,
    ServerError,
    SFTPError,
    SFTPWarning,
    StateError,
    TransferError,
    TransferTimeoutError,
    UnsupportedError,
)

__all__ = [
    "AuthenticationError",
    "ConnectError",
    "HostKeyError",
    "InsecureOptionWarning",
    "NoSuchFileError",
    "PermissionDeniedError",
    "ProtocolError",
    "SFTPError",
    "SFTPWarning",
    "ServerError",
    "StateError",
    "TransferError",
    "TransferTimeoutError",
    "UnsupportedError",
    "__version__",
]

__version__ = "0.0.0"

"""gantry-sftp -- a modern Python SFTP library that does not implement SSH at all.

OpenSSH is spawned as a subprocess and hands us a plaintext, framed SFTP byte stream, so
there is zero cryptography in this package. What is left is a protocol codec, a scheduler,
and an ergonomics layer.

What exists today, from a distribution a user actually installed::

    from gantry_sftp import connect

    async with connect("example.com", user="bob") as sftp:
        await sftp.get("/incoming/data.parquet", "data.parquet")

:func:`~gantry_sftp.connect` opens the connection and the session together. The two-call
spelling is unchanged and is what to use when their lifetimes differ::

    from gantry_sftp import open_session, open_ssh_transport

    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        ...

:mod:`gantry_sftp.transport` opens the connection, :mod:`gantry_sftp.session` is the API --
``get`` / ``put`` (atomic by default, resumable, verifiable, and able to carry a file's mode
and timestamps rather than inventing new ones), ``listdir`` / ``scandir`` / ``walk``,
``get_tree`` / ``put_tree`` / ``rmtree``, ``chmod`` / ``chown`` / ``utime`` / ``truncate``,
``readlink`` / ``symlink``, ``with_reconnect``, and several transfers at once over one
connection. :mod:`gantry_sftp.codec` is the sans-I/O protocol layer
underneath, public because a frame dumper and a fuzz harness need it. Typed errors are
re-exported here; every one carries state rather than a string.

Three surfaces sit beside the session rather than under it. :mod:`gantry_sftp.sync` is the same
API without an event loop -- a facade over the async code, not a second implementation.
:class:`~gantry_sftp.SFTPPath` is a ``pathlib``-shaped object bound to a session, made of bytes
because remote names are, and with a joining operator that validates every component rather than
concatenating. :mod:`gantry_sftp.fsspec` is an fsspec filesystem, so pandas, pyarrow and dask
reach a remote file through a URL; it needs the ``fsspec`` extra and **registers nothing on
import**, because ``sftp://`` already belongs to somebody else.

**Names a server sent are attacker-controlled, and building a path out of one is not the
caller's problem to solve from scratch.** ``glob`` and the recursive operations do it
internally; a caller whose filter is a regular expression or a watermark rather than a
pattern gets the same primitives -- :func:`~gantry_sftp.session.check_listed_name` and
:func:`~gantry_sftp.session.join_remote` for the remote path,
:func:`~gantry_sftp.session.local_child` for the local one -- from here rather than from a
submodule (D-97).

This module used to point at ``_plans/DESIGN.md`` and ``_plans/progress.md``. Neither is in
any distribution -- they are gitignored working documents -- so ``help(gantry_sftp)`` was
sending readers to files they could not obtain (D-47). The README is what ships.
"""

from __future__ import annotations

from gantry_sftp._connect import connect
from gantry_sftp._logging import LOG_FIELDS, record_fields
from gantry_sftp.codec import Attrs, OpenFlag, Owner, Times
from gantry_sftp.exceptions import (
    AuthenticationError,
    CapabilityError,
    ConnectError,
    DestinationCollisionError,
    DestinationNotAllowedError,
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
from gantry_sftp.path import SFTPPath
from gantry_sftp.session import (
    DirEntry,
    DownloadResult,
    EntryKind,
    GlobMatch,
    Mode,
    PlanLimit,
    PotentialCollision,
    Publish,
    RemoteFile,
    Session,
    SessionOptions,
    Skipped,
    SkipReason,
    TreePlan,
    TreeResult,
    UploadJournal,
    UploadResult,
    Verify,
    WalkEntry,
    check_listed_name,
    is_retryable,
    join_remote,
    local_child,
    open_session,
    with_reconnect,
)
from gantry_sftp.transport import allowed_hosts, open_ssh_transport

__all__ = [
    "LOG_FIELDS",
    "Attrs",
    "AuthenticationError",
    "CapabilityError",
    "ConnectError",
    "DestinationCollisionError",
    "DestinationNotAllowedError",
    "DirEntry",
    "DownloadResult",
    "EntryKind",
    "GlobMatch",
    "HostKeyError",
    "InsecureOptionWarning",
    "Mode",
    "NoSuchFileError",
    "OpenFlag",
    "Owner",
    "PathCollision",
    "PermissionDeniedError",
    "PlanLimit",
    "PotentialCollision",
    "ProtocolError",
    "Publish",
    "RemoteFile",
    "SFTPError",
    "SFTPPath",
    "SFTPWarning",
    "ServerError",
    "Session",
    "SessionOptions",
    "SkipReason",
    "Skipped",
    "StateError",
    "Times",
    "TransferError",
    "TransferTimeoutError",
    "TreePlan",
    "TreeResult",
    "UnsafePathError",
    "UnsupportedError",
    "UploadJournal",
    "UploadResult",
    "Verify",
    "WalkEntry",
    "__version__",
    "allowed_hosts",
    "check_listed_name",
    "connect",
    "is_retryable",
    "join_remote",
    "local_child",
    "open_session",
    "open_ssh_transport",
    "record_fields",
    "with_reconnect",
]

__version__ = "0.2.0"
"""The one place the version is written.

``pyproject.toml`` reads it from here through ``[tool.hatch.version]`` rather than restating
it, because two hand-maintained copies means a bug report can name a release the reporter did
not install. ``tests/test_packaging.py`` asserts the built distribution agrees with this."""

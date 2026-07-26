"""Typed bodies for the OpenSSH ``EXTENDED`` requests this library sends.

An extension request is an ordinary ``EXTENDED`` packet whose body is defined by the
extension rather than by the specification, so these are **not** new packet types: each one
builds and reads the payload of an :class:`~gantry_sftp.codec.Extended`, and the packet
tables, the decode registry and the event union stay untouched. That is deliberate -- a
per-extension packet type would put the completeness sweep in DESIGN.md's way for every new
extension, and the wire has exactly one type byte here.

Every layout in this module was read off a real ``sftp-server`` (OpenSSH 10.0p2) on
2026-07-26, not recalled and not taken from documentation alone. ``SYMLINK`` is why: its
field order contradicts the draft, and a layout written from memory passes every unit test
while corrupting every real operation. The probe output is in DESIGN.md 13.

Measured, and each one changed the code above this layer:

* ``posix-rename@openssh.com`` really does overwrite an existing target -- ``OK``, and the
  target's contents are the source's afterwards.
* Its field order is *distinguishable*: with only the source present, ``(oldpath, newpath)``
  answers ``OK`` and the reverse answers ``NO_SUCH_FILE``. So this is a test, not a belief.
* ``fsync@openssh.com`` on a handle that has already been closed answers ``NO_SUCH_FILE``,
  not ``FAILURE``. Ordering matters: the flush has to happen before the ``CLOSE``.
* A *truncated* extension body is not answered with ``BAD_MESSAGE`` -- the reference server
  calls ``fatal()`` and hangs up. An encoder bug here presents as a dead connection rather
  than as an error, which is the argument for building these bodies in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Self

from gantry_sftp.codec._constants import (
    EXTENSION_FSYNC,
    EXTENSION_LIMITS,
    EXTENSION_POSIX_RENAME,
)
from gantry_sftp.codec._packets import Extended
from gantry_sftp.codec._wire import WireReader, WireWriter
from gantry_sftp.exceptions import ProtocolError

__all__ = [
    "FSYNC_NAME",
    "LIMITS_NAME",
    "POSIX_RENAME_NAME",
    "Fsync",
    "PosixRename",
]

POSIX_RENAME_NAME = EXTENSION_POSIX_RENAME.encode("ascii")
"""``posix-rename@openssh.com`` as it appears on the wire."""

FSYNC_NAME = EXTENSION_FSYNC.encode("ascii")
"""``fsync@openssh.com`` as it appears on the wire."""

LIMITS_NAME = EXTENSION_LIMITS.encode("ascii")
"""``limits@openssh.com`` as it appears on the wire.

Derived from the same string constant the advertisement table uses rather than typed again
as a bytes literal. Two spellings of one wire string is how ``copy-data@openssh.com``
happened: a name that never matches degrades to the fallback forever and passes every test
written against the same wrong constant.
"""


def _payload_of(request: Extended, expected: bytes) -> WireReader:
    """Return a reader over an ``EXTENDED`` body, checking the name first.

    Raises:
        ProtocolError: If the request names a different extension.
    """
    if request.name != expected:
        raise ProtocolError(
            f"expected extension {expected.decode('ascii')!r}, got {bytes(request.name)!r}",
            packet_type=int(Extended.packet_type),
            request_id=request.request_id,
            raw_frame=request.data,
        )
    return WireReader(
        request.data,
        packet_type=int(Extended.packet_type),
        request_id=request.request_id,
    )


@dataclass(frozen=True, slots=True)
class PosixRename:
    """``posix-rename@openssh.com``: rename that overwrites the target.

    The reason atomic publish needs this: plain v3 ``RENAME`` **fails** when the target
    exists, measured on OpenSSH 10.0p2 as ``FAILURE`` with the target left untouched. So
    without this extension there is no way to replace a file in one step, and the fallback
    has a window where the target does not exist at all.

    Body layout, verified on the wire::

        string  "posix-rename@openssh.com"
        string  oldpath
        string  newpath

    Attributes:
        request_id: Correlates the reply.
        oldpath: The existing path, which stops existing.
        newpath: The path it takes over, overwritten if it is already there.
    """

    extension_name: ClassVar[bytes] = POSIX_RENAME_NAME

    request_id: int
    oldpath: bytes
    newpath: bytes

    def to_extended(self) -> Extended:
        """Build the ``EXTENDED`` request that carries this rename."""
        writer = WireWriter()
        writer.write_string(self.oldpath)
        writer.write_string(self.newpath)
        return Extended(self.request_id, self.extension_name, writer.getvalue())

    @classmethod
    def from_extended(cls, request: Extended) -> Self:
        """Read one back out of an ``EXTENDED`` request.

        Trailing bytes are ignored rather than rejected, matching how the rest of the codec
        decodes a tail it did not expect: a future revision of the extension may append a
        field, and refusing to parse the part we do understand gains nothing.

        Raises:
            ProtocolError: If the name does not match, or the body is truncated.
        """
        reader = _payload_of(request, cls.extension_name)
        return cls(
            request_id=request.request_id,
            oldpath=bytes(reader.read_string()),
            newpath=bytes(reader.read_string()),
        )


@dataclass(frozen=True, slots=True)
class Fsync:
    """``fsync@openssh.com``: flush an open handle to stable storage.

    The only durability barrier SFTP has, and it covers the *file*, not the directory entry.
    A rename that publishes the file is therefore not itself durable -- nothing in the
    protocol can make it so -- which is a limit to state rather than to imply.

    Body layout, verified on the wire::

        string  "fsync@openssh.com"
        string  handle

    Attributes:
        request_id: Correlates the reply.
        handle: An open handle. Measured: after ``CLOSE`` the same handle answers
            ``NO_SUCH_FILE``, so the flush belongs before the close, not after it.
    """

    extension_name: ClassVar[bytes] = FSYNC_NAME

    request_id: int
    handle: bytes

    def to_extended(self) -> Extended:
        """Build the ``EXTENDED`` request that carries this flush."""
        writer = WireWriter()
        writer.write_string(self.handle)
        return Extended(self.request_id, self.extension_name, writer.getvalue())

    @classmethod
    def from_extended(cls, request: Extended) -> Self:
        """Read one back out of an ``EXTENDED`` request.

        Raises:
            ProtocolError: If the name does not match, or the body is truncated.
        """
        reader = _payload_of(request, cls.extension_name)
        return cls(request_id=request.request_id, handle=bytes(reader.read_string()))

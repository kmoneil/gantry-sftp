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

from gantry_sftp.codec._attrs import EMPTY_ATTRS, Attrs, decode_attrs, encode_attrs
from gantry_sftp.codec._constants import (
    EXTENSION_CHECK_FILE,
    EXTENSION_FSYNC,
    EXTENSION_LIMITS,
    EXTENSION_LSETSTAT,
    EXTENSION_POSIX_RENAME,
)
from gantry_sftp.codec._packets import Extended, ExtendedReply
from gantry_sftp.codec._wire import WireReader, WireWriter
from gantry_sftp.exceptions import ProtocolError

__all__ = [
    "CHECK_FILE_NAME",
    "FSYNC_NAME",
    "IMPLEMENTED_EXTENSIONS",
    "LIMITS_NAME",
    "LSETSTAT_NAME",
    "POSIX_RENAME_NAME",
    "CheckFile",
    "CheckFileReply",
    "Fsync",
    "LSetStat",
    "PosixRename",
]

POSIX_RENAME_NAME = EXTENSION_POSIX_RENAME.encode("ascii")
"""``posix-rename@openssh.com`` as it appears on the wire."""

FSYNC_NAME = EXTENSION_FSYNC.encode("ascii")
"""``fsync@openssh.com`` as it appears on the wire."""

LSETSTAT_NAME = EXTENSION_LSETSTAT.encode("ascii")
"""``lsetstat@openssh.com`` as it appears on the wire."""

CHECK_FILE_NAME = EXTENSION_CHECK_FILE.encode("ascii")
"""``check-file`` as it appears on the wire -- unsuffixed, which is paramiko's spelling."""

LIMITS_NAME = EXTENSION_LIMITS.encode("ascii")
"""``limits@openssh.com`` as it appears on the wire.

Derived from the same string constant the advertisement table uses rather than typed again
as a bytes literal. Two spellings of one wire string is how ``copy-data@openssh.com``
happened: a name that never matches degrades to the fallback forever and passes every test
written against the same wrong constant.
"""

IMPLEMENTED_EXTENSIONS: tuple[str, ...] = (
    EXTENSION_POSIX_RENAME,
    EXTENSION_FSYNC,
    EXTENSION_LSETSTAT,
    EXTENSION_LIMITS,
    EXTENSION_CHECK_FILE,
)
"""The extensions this library can actually *send*, as distinct from the ones it can name.

There is an ``EXTENSION_*`` constant for every name OpenSSH is known to advertise, including
the ones nothing here implements -- so ``supports()`` can answer about a server's whole
advertisement without anybody typing a wire string by hand. That makes the constants a list
of what exists, and leaves "what do we do with it" unanswered, which is the question an
operator staring at an advertisement actually has.

This is that answer, and it lives beside the bodies rather than in the diagnostic that prints
it: an extension is implemented when it has a body in this module, so the set is derived from
the same place the code is. :mod:`tests.test_extensions` asserts the two cannot drift.
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
class LSetStat:
    """``lsetstat@openssh.com``: ``SETSTAT`` that does not follow a symlink.

    The reason it is needed: plain ``SETSTAT`` is ``chmod(2)``/``chown(2)``/``utimes(2)`` on a
    path, and all three follow. Where the path may be a symlink somebody else planted, that is
    an operation on whatever it points at. **v3 offers no non-following spelling at all**, so
    this extension is not an optimisation with a fallback -- its absence means the operation
    cannot be performed, and the caller has to be told rather than quietly given the following
    version.

    Body layout, from ``PROTOCOL`` 4.7 and matching ``process_extended_lsetstat``::

        string  "lsetstat@openssh.com"
        string  path
        ATTRS   attrs

    **It refuses ``SIZE`` outright**, with ``BAD_MESSAGE`` and the comment
    ``/* nonsensical for links */`` -- so this cannot carry a truncation and is not a drop-in
    ``SETSTAT``. Mode, times and owner only. Read from the 10.0p2 source rather than inferred
    from "it is like setstat", which is what ``PROTOCOL`` says and is not the whole truth.

    Attributes:
        request_id: Correlates the reply.
        path: What to modify. Not followed if it is a symlink -- the point of the extension.
        attrs: The fields to set. One flag per request, for the reason
            :meth:`~gantry_sftp.session.Session.chmod` gives: the server applies them in
            sequence and reports one status.
    """

    extension_name: ClassVar[bytes] = LSETSTAT_NAME

    request_id: int
    path: bytes
    attrs: Attrs = EMPTY_ATTRS

    def to_extended(self) -> Extended:
        """Build the ``EXTENDED`` request that carries this attribute change."""
        writer = WireWriter()
        writer.write_string(self.path)
        encode_attrs(writer, self.attrs)
        return Extended(self.request_id, self.extension_name, writer.getvalue())

    @classmethod
    def from_extended(cls, request: Extended) -> Self:
        """Read one back out of an ``EXTENDED`` request.

        Raises:
            ProtocolError: If the name does not match, or the body is truncated.
        """
        reader = _payload_of(request, cls.extension_name)
        return cls(
            request_id=request.request_id,
            path=bytes(reader.read_string()),
            attrs=decode_attrs(reader),
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


@dataclass(frozen=True, slots=True)
class CheckFile:
    """``check-file``: ask the server to hash a file it already has.

    Rung 1 of DESIGN.md 6's verification ladder, and the only rung that verifies *content*
    without moving the bytes a second time. **OpenSSH does not implement it** -- all three
    spellings answer ``OP_UNSUPPORTED``, measured -- so every use of this degrades to a size
    check or a full re-read.

    **Sourced from paramiko's ``SFTPServer._check_file``**, which is the implementation this
    library has actually spoken to, and from the frames that exchange produced. It is in no
    secsh draft: ``draft-ietf-secsh-filexfer-05``, ``-09`` and ``-13`` were each fetched and
    searched, and the string does not appear in any of them. Paramiko's own comment says it
    "comes from v6 protocol"; whatever document that refers to, it is not one of those three,
    so the layout below cites code rather than a specification.

    Two spellings exist in the wild and this is the paramiko one. The extension it advertises
    is ``check-file``, unsuffixed, taking a **handle**; other documents describe separate
    ``check-file-handle`` and ``check-file-name`` requests. A server advertising those needs
    its own type, not a flag on this one.

    Body layout::

        string  "check-file"
        string  handle
        string  algorithms      -- a name-list: "md5,sha1"
        uint64  start_offset
        uint64  length          -- 0 means "to the end of the file"
        uint32  block_size      -- 0 means "one digest over the whole range"

    Attributes:
        request_id: Correlates the reply.
        handle: An **open** file handle. Paramiko answers ``BAD_MESSAGE`` for one it does not
            know, which is a different failure from the request being malformed and is worth
            not confusing with it.
        algorithms: Preference order. The server picks the first it supports and says which
            in the reply; if it supports none it answers ``FAILURE``.
        start_offset: First byte to hash.
        length: Bytes to hash, or ``0`` for the rest of the file.
        block_size: Bytes per digest, or ``0`` for a single digest over the whole range.
            Paramiko refuses anything below 256 with ``FAILURE``, so this is not a free
            parameter -- it is 0 or at least 256.
    """

    extension_name: ClassVar[bytes] = CHECK_FILE_NAME

    request_id: int
    handle: bytes
    algorithms: bytes = b"sha256,sha1,md5"
    start_offset: int = 0
    length: int = 0
    block_size: int = 0

    def to_extended(self) -> Extended:
        """Build the ``EXTENDED`` request that carries this check."""
        writer = WireWriter()
        writer.write_string(self.handle)
        writer.write_string(self.algorithms)
        writer.write_uint64(self.start_offset)
        writer.write_uint64(self.length)
        writer.write_uint32(self.block_size)
        return Extended(self.request_id, self.extension_name, writer.getvalue())

    @classmethod
    def from_extended(cls, request: Extended) -> Self:
        """Read one back out of an ``EXTENDED`` request.

        Raises:
            ProtocolError: If the name does not match, or the body is truncated.
        """
        reader = _payload_of(request, cls.extension_name)
        return cls(
            request_id=request.request_id,
            handle=bytes(reader.read_string()),
            algorithms=bytes(reader.read_string()),
            start_offset=reader.read_uint64(),
            length=reader.read_uint64(),
            block_size=reader.read_uint32(),
        )


@dataclass(frozen=True, slots=True)
class CheckFileReply:
    """The ``EXTENDED_REPLY`` to a :class:`CheckFile`, and its last field is the trap.

    Body layout, after the ``uint32`` request id the packet already carries::

        string  "check-file"    -- the extension name, echoed back
        string  algorithm       -- which one the server chose
        bytes   digests         -- **raw, not length-prefixed**, to the end of the packet

    Two things a layout written from memory gets wrong. The reply **echoes the extension
    name**, which an ``EXTENDED_REPLY`` is under no general obligation to do -- most carry
    only the extension's own data. And the digest field is *not* a ``string``: paramiko emits
    it with ``Message.add_bytes``, so there is no length prefix and the digests run to the end
    of the frame. Reading it as a ``string`` consumes four bytes of the first digest as a
    length and then overruns.

    One digest per block, concatenated, so the count follows from the request's ``block_size``
    and the digest size of the chosen algorithm rather than being stated anywhere.

    Attributes:
        request_id: The request this answers.
        algorithm: The algorithm the server chose, as it named it.
        digests: The raw concatenated digest bytes, exactly as sent.
    """

    request_id: int
    algorithm: bytes
    digests: bytes

    @classmethod
    def from_reply(cls, reply: ExtendedReply) -> Self:
        """Parse an ``EXTENDED_REPLY`` body as a check-file answer.

        Raises:
            ProtocolError: If the echoed name is not ``check-file``, or the body is truncated
                before the algorithm.
        """
        reader = WireReader(reply.data)
        try:
            name = bytes(reader.read_string())
            algorithm = bytes(reader.read_string())
        except ProtocolError as truncated:
            raise ProtocolError(
                "check-file reply is truncated before the algorithm name",
                request_id=reply.request_id,
                raw_frame=reply.data,
            ) from truncated
        if name != CHECK_FILE_NAME:
            raise ProtocolError(
                f"check-file reply echoed {name!r} where {CHECK_FILE_NAME!r} was expected",
                request_id=reply.request_id,
                raw_frame=reply.data,
            )
        return cls(
            request_id=reply.request_id,
            algorithm=algorithm,
            digests=bytes(reader.read_bytes(reader.remaining)),
        )

    def split(self, digest_size: int) -> tuple[bytes, ...]:
        """Split the concatenated digests into one per block.

        The wire says nothing about how many there are, so the caller supplies the digest
        size -- from ``hashlib`` for the algorithm the server named.

        Raises:
            ValueError: If ``digest_size`` is not positive, or does not divide the payload.
                A remainder means the algorithm we sized against is not the one that produced
                these bytes, and splitting anyway would hand back digests that are silently
                misaligned.
        """
        if digest_size < 1:
            raise ValueError(f"digest_size must be at least 1, got {digest_size}")
        if len(self.digests) % digest_size:
            raise ValueError(
                f"{len(self.digests)} digest bytes do not divide into {digest_size}-byte "
                f"digests, so this is not {self.algorithm!r} output"
            )
        return tuple(
            self.digests[start : start + digest_size]
            for start in range(0, len(self.digests), digest_size)
        )

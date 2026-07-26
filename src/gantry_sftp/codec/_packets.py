"""Packet types for filexfer v3, and the encode/decode pair for each.

Every packet is a frozen dataclass carrying exactly the fields on the wire, so
``decode(encode(p)) == p`` is a property that means something. Packet identity is part of
equality: ``Stat(1, b"/a")`` does not equal ``Remove(1, b"/a")`` even though their bodies
are byte-identical, because dataclass equality checks the class first.

Two things here are not derivable from the specification and were established by asking a
real server. Both are recorded at their definitions:

* ``SYMLINK`` takes its arguments in the **opposite order** to the draft.
* ``STATUS`` has a tail the draft requires and servers omit.

Lifetimes
---------
Path-like fields are ``bytes`` -- copied out of the frame, safe to keep. :class:`Data` is
the exception: its payload is a ``memoryview`` aliasing the frame, valid only until the
next :meth:`~gantry_sftp.codec.FrameSplitter.feed`, because copying a quarter-megabyte read
payload in the hot path is the allocation this library exists to avoid. Write it out with
``os.pwrite`` and move on, or copy it deliberately.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar, NamedTuple, Self

from gantry_sftp.codec._attrs import EMPTY_ATTRS, Attrs, decode_attrs, encode_attrs
from gantry_sftp.codec._constants import PROTOCOL_VERSION, OpenFlag, PacketType, StatusCode
from gantry_sftp.codec._wire import WireReader, WireWriter
from gantry_sftp.exceptions import ProtocolError

__all__ = [
    "AttrsReply",
    "Close",
    "Data",
    "Extended",
    "ExtendedReply",
    "FSetStat",
    "FStat",
    "Handle",
    "Init",
    "LStat",
    "MkDir",
    "Name",
    "NameEntry",
    "Open",
    "OpenDir",
    "Packet",
    "Read",
    "ReadDir",
    "ReadLink",
    "RealPath",
    "Remove",
    "Rename",
    "RmDir",
    "SetStat",
    "Stat",
    "Status",
    "SymLink",
    "Version",
    "Write",
    "decode",
    "encode",
]


# --- shared body shapes -----------------------------------------------------------------
#
# Seven request types are `uint32 id, string path` and three are `uint32 id, string handle`.
# The bodies are shared so that a fix to one is a fix to all of them; the packet type stays
# on the subclass, where it is the only thing that differs.


@dataclass(frozen=True, slots=True)
class _PathRequest:
    """A request carrying a single path."""

    request_id: int
    path: bytes

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.path)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(request_id=reader.read_uint32(), path=bytes(reader.read_string()))


@dataclass(frozen=True, slots=True)
class _HandleRequest:
    """A request carrying a single open handle."""

    request_id: int
    handle: bytes

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.handle)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(request_id=reader.read_uint32(), handle=bytes(reader.read_string()))


@dataclass(frozen=True, slots=True)
class _PathAttrsRequest:
    """A request carrying a path and an attribute set."""

    request_id: int
    path: bytes
    attrs: Attrs = EMPTY_ATTRS

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.path)
        encode_attrs(writer, self.attrs)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            path=bytes(reader.read_string()),
            attrs=decode_attrs(reader),
        )


# --- INIT and VERSION -------------------------------------------------------------------
#
# The framing exception. These two carry `uint32 version` where every other packet carries
# `uint32 request-id`, and they are the first packets on any connection -- so a codec that
# models the id slot as universal breaks before it has done anything else.


@dataclass(frozen=True, slots=True)
class Init:
    """Client hello. Body is a version and optional extensions -- **no request id**."""

    packet_type: ClassVar[PacketType] = PacketType.INIT

    version: int = PROTOCOL_VERSION
    extensions: tuple[tuple[bytes, bytes], ...] = field(default_factory=tuple)

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.version)
        for name, value in self.extensions:
            writer.write_string(name)
            writer.write_string(value)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        version = reader.read_uint32()
        return cls(version=version, extensions=_decode_extension_pairs(reader))


@dataclass(frozen=True, slots=True)
class Version:
    """Server hello. Body is a version and the extensions it supports -- **no request id**.

    Extension versions are strings on the wire (``b"1"``, ``b"2"``), not integers, and two
    of the names OpenSSH advertises carry no ``@openssh.com`` suffix. See
    :data:`~gantry_sftp.codec.OPENSSH_ADVERTISED_EXTENSIONS`.
    """

    packet_type: ClassVar[PacketType] = PacketType.VERSION

    version: int = PROTOCOL_VERSION
    extensions: tuple[tuple[bytes, bytes], ...] = field(default_factory=tuple)

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.version)
        for name, value in self.extensions:
            writer.write_string(name)
            writer.write_string(value)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        version = reader.read_uint32()
        return cls(version=version, extensions=_decode_extension_pairs(reader))


def _decode_extension_pairs(reader: WireReader) -> tuple[tuple[bytes, bytes], ...]:
    """Read ``string name / string value`` pairs until the frame runs out.

    There is no count -- the pair list is terminated by the end of the frame, which is why
    this needs the frame boundary to be exact and not merely an upper bound.
    """
    pairs = []
    while not reader.at_end:
        name = bytes(reader.read_string())
        pairs.append((name, bytes(reader.read_string())))
    return tuple(pairs)


# --- file requests ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Open:
    """Open a file. ``pflags`` selects the access mode; ``attrs`` is usually empty."""

    packet_type: ClassVar[PacketType] = PacketType.OPEN

    request_id: int
    filename: bytes
    pflags: OpenFlag
    attrs: Attrs = EMPTY_ATTRS

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.filename)
        writer.write_uint32(self.pflags)
        encode_attrs(writer, self.attrs)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            filename=bytes(reader.read_string()),
            pflags=OpenFlag(reader.read_uint32()),
            attrs=decode_attrs(reader),
        )


@dataclass(frozen=True, slots=True)
class Close(_HandleRequest):
    """Close an open handle."""

    packet_type: ClassVar[PacketType] = PacketType.CLOSE


@dataclass(frozen=True, slots=True)
class Read:
    """Read ``length`` bytes at an explicit ``offset``.

    Reads at an explicit offset are idempotent, which is what makes them safe to retry and
    safe to issue out of order. Writes are not, and are not treated the same way.
    """

    packet_type: ClassVar[PacketType] = PacketType.READ

    request_id: int
    handle: bytes
    offset: int
    length: int

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.handle)
        writer.write_uint64(self.offset)
        writer.write_uint32(self.length)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            handle=bytes(reader.read_string()),
            offset=reader.read_uint64(),
            length=reader.read_uint32(),
        )


@dataclass(frozen=True, slots=True)
class Write:
    """Write ``data`` at an explicit ``offset``.

    The offset is explicit so writes need no ordering, but a write is **not** idempotent
    the way a read is: replaying one blindly after a connection loss can duplicate or
    interleave bytes. Retry policy lives above the codec and must know the difference.
    """

    packet_type: ClassVar[PacketType] = PacketType.WRITE

    request_id: int
    handle: bytes
    offset: int
    data: bytes

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.handle)
        writer.write_uint64(self.offset)
        writer.write_string(self.data)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            handle=bytes(reader.read_string()),
            offset=reader.read_uint64(),
            data=bytes(reader.read_string()),
        )


@dataclass(frozen=True, slots=True)
class LStat(_PathRequest):
    """Stat a path without following a final symlink."""

    packet_type: ClassVar[PacketType] = PacketType.LSTAT


@dataclass(frozen=True, slots=True)
class FStat(_HandleRequest):
    """Stat an open handle."""

    packet_type: ClassVar[PacketType] = PacketType.FSTAT


@dataclass(frozen=True, slots=True)
class SetStat(_PathAttrsRequest):
    """Set attributes on a path."""

    packet_type: ClassVar[PacketType] = PacketType.SETSTAT


@dataclass(frozen=True, slots=True)
class FSetStat:
    """Set attributes on an open handle."""

    packet_type: ClassVar[PacketType] = PacketType.FSETSTAT

    request_id: int
    handle: bytes
    attrs: Attrs = EMPTY_ATTRS

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.handle)
        encode_attrs(writer, self.attrs)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            handle=bytes(reader.read_string()),
            attrs=decode_attrs(reader),
        )


@dataclass(frozen=True, slots=True)
class OpenDir(_PathRequest):
    """Open a directory for reading."""

    packet_type: ClassVar[PacketType] = PacketType.OPENDIR


@dataclass(frozen=True, slots=True)
class ReadDir(_HandleRequest):
    """Read the next batch of directory entries.

    Returns a NAME with one or more entries, or a STATUS of ``EOF`` when the directory is
    exhausted. ``EOF`` here is the normal terminating condition, not an error.
    """

    packet_type: ClassVar[PacketType] = PacketType.READDIR


@dataclass(frozen=True, slots=True)
class Remove(_PathRequest):
    """Delete a file. Not a directory -- that is RMDIR."""

    packet_type: ClassVar[PacketType] = PacketType.REMOVE


@dataclass(frozen=True, slots=True)
class MkDir(_PathAttrsRequest):
    """Create a directory."""

    packet_type: ClassVar[PacketType] = PacketType.MKDIR


@dataclass(frozen=True, slots=True)
class RmDir(_PathRequest):
    """Remove an empty directory."""

    packet_type: ClassVar[PacketType] = PacketType.RMDIR


@dataclass(frozen=True, slots=True)
class RealPath(_PathRequest):
    """Canonicalise a path.

    Servers disagree about what this does for a path that does not exist: some canonicalise
    it anyway, some return an error. That disagreement is a quirks-layer concern, not
    something to paper over here.
    """

    packet_type: ClassVar[PacketType] = PacketType.REALPATH


@dataclass(frozen=True, slots=True)
class Stat(_PathRequest):
    """Stat a path, following symlinks."""

    packet_type: ClassVar[PacketType] = PacketType.STAT


@dataclass(frozen=True, slots=True)
class Rename:
    """Rename ``oldpath`` to ``newpath``.

    Plain v3 RENAME must **fail** if the target exists, which is precisely why
    ``posix-rename@openssh.com`` exists and why publish-by-rename needs it. Servers
    disagree here too: some overwrite, some error, some silently do nothing.
    """

    packet_type: ClassVar[PacketType] = PacketType.RENAME

    request_id: int
    oldpath: bytes
    newpath: bytes

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.oldpath)
        writer.write_string(self.newpath)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            oldpath=bytes(reader.read_string()),
            newpath=bytes(reader.read_string()),
        )


@dataclass(frozen=True, slots=True)
class ReadLink(_PathRequest):
    """Read the destination of a symlink."""

    packet_type: ClassVar[PacketType] = PacketType.READLINK


@dataclass(frozen=True, slots=True)
class SymLink:
    """Create a symlink at ``linkpath`` pointing to ``targetpath``.

    **The wire order is the reverse of the specification, and this is not a typo.**
    ``draft-ietf-secsh-filexfer-02`` says the body is ``string linkpath, string
    targetpath``. OpenSSH sends and expects ``string targetpath, string linkpath``, and
    since OpenSSH is the de-facto specification here, so do we.

    Verified by experiment against a real ``sftp-server``, not read off a mailing list:
    sending the draft order returns ``FAILURE`` and creates nothing, while sending this
    order returns ``OK`` and creates the link. ``tests/test_real_sftp_server.py`` runs both
    directions, so if a server ever disagrees the test says which one.

    The field *names* here follow the semantics, not the wire position -- ``linkpath`` is
    the link being created in both readings. Only the order differs, and the order lives in
    :meth:`encode_body` where it is checked against a server.
    """

    packet_type: ClassVar[PacketType] = PacketType.SYMLINK

    request_id: int
    targetpath: bytes
    linkpath: bytes

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.targetpath)
        writer.write_string(self.linkpath)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            targetpath=bytes(reader.read_string()),
            linkpath=bytes(reader.read_string()),
        )


@dataclass(frozen=True, slots=True)
class Extended:
    """A vendor extension request.

    ``data`` is whatever the named extension defines; the codec does not interpret it.
    Sending one whose name the server does not know is safe -- it answers
    ``OP_UNSUPPORTED`` and the session stays usable -- which is what makes probe-based
    capability detection viable for servers that under-advertise.
    """

    packet_type: ClassVar[PacketType] = PacketType.EXTENDED

    request_id: int
    name: bytes
    data: bytes = b""

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.name)
        writer.write_bytes(self.data)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(
            request_id=reader.read_uint32(),
            name=bytes(reader.read_string()),
            data=bytes(reader.read_remaining()),
        )


# --- responses --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Status:
    """The universal reply: success, failure, or EOF.

    ``message`` and ``language`` are a tail that v3 added and that servers omit. OpenSSH
    sends a message and an **empty** language tag -- not ``"en"`` -- so a decoder demanding
    a well-formed RFC-1766 tag rejects every error the reference server sends. A frame that
    simply ends after the code decodes to empty strings rather than to an error, because a
    truncated tail is a server being terse, not a server being broken.

    ``FAILURE`` is a v3 catch-all meaning nothing more than "no". Making it actionable
    means reading ``message``, which is exactly the field a server is free not to send.
    """

    packet_type: ClassVar[PacketType] = PacketType.STATUS

    request_id: int
    code: StatusCode
    message: bytes = b""
    language: bytes = b""

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_uint32(self.code)
        writer.write_string(self.message)
        writer.write_string(self.language)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        request_id = reader.read_uint32()
        reader.set_request_id(request_id)
        raw_code = reader.read_uint32()
        try:
            code = StatusCode(raw_code)
        except ValueError as exc:
            raise ProtocolError(
                f"STATUS carries undefined status code {raw_code}; filexfer v3 defines 0-8",
                packet_type=int(PacketType.STATUS),
                request_id=request_id,
            ) from exc

        # The tail is optional in practice. Absent means terse, not malformed.
        message = bytes(reader.read_string()) if not reader.at_end else b""
        language = bytes(reader.read_string()) if not reader.at_end else b""
        return cls(request_id=request_id, code=code, message=message, language=language)


@dataclass(frozen=True, slots=True)
class Handle(_HandleRequest):
    """A handle for a newly opened file or directory.

    Opaque binary, not text. OpenSSH's first handle is four NUL bytes -- a packed integer.
    Decoding one as a string corrupts it.
    """

    packet_type: ClassVar[PacketType] = PacketType.HANDLE


@dataclass(frozen=True, slots=True)
class Data:
    """Payload from a READ.

    A short DATA is legal and is **not** EOF: asking for 100 bytes at offset 8 of a
    ten-byte file returns two bytes in a DATA frame, and only a read starting at or past
    the end returns a STATUS of ``EOF``. Treating a short DATA as end-of-file truncates
    every pipelined transfer at its first partial response -- silently, producing a file
    that is plausible and wrong.

    ``data`` aliases the frame buffer and is valid only until the next
    :meth:`~gantry_sftp.codec.FrameSplitter.feed`. That is the point: a quarter-megabyte
    payload should reach the destination file without being copied through Python first.
    Use it or copy it, but do not keep it.
    """

    packet_type: ClassVar[PacketType] = PacketType.DATA

    request_id: int
    data: memoryview

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_string(self.data)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(request_id=reader.read_uint32(), data=reader.read_string())


class NameEntry(NamedTuple):
    """One entry of a NAME reply.

    ``longname`` has no guaranteed format and its shape depends on the request that
    produced it: an ``ls -l``-style line from READDIR, the bare path from REALPATH. It is
    surfaced verbatim and never parsed -- scraping it for an owner name is reading a
    display string, and ``users-groups-by-id@openssh.com`` is the structured answer.
    """

    filename: bytes
    longname: bytes
    attrs: Attrs


@dataclass(frozen=True, slots=True)
class Name:
    """One or more filenames with attributes -- the reply to READDIR and REALPATH."""

    packet_type: ClassVar[PacketType] = PacketType.NAME

    request_id: int
    entries: tuple[NameEntry, ...] = field(default_factory=tuple)

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_uint32(len(self.entries))
        for entry in self.entries:
            writer.write_string(entry.filename)
            writer.write_string(entry.longname)
            encode_attrs(writer, entry.attrs)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        request_id = reader.read_uint32()
        count = reader.read_uint32()
        # Not pre-allocated on `count`: a hostile count is bounded by the frame, since the
        # first read past the end raises rather than spinning.
        entries = []
        for _ in range(count):
            filename = bytes(reader.read_string())
            longname = bytes(reader.read_string())
            entries.append(NameEntry(filename, longname, decode_attrs(reader)))
        return cls(request_id=request_id, entries=tuple(entries))


@dataclass(frozen=True, slots=True)
class AttrsReply:
    """Attributes for a STAT, LSTAT or FSTAT.

    Named ``AttrsReply`` rather than ``Attrs`` because :class:`~gantry_sftp.codec.Attrs` is
    the structure it carries, and one of them has to give.
    """

    packet_type: ClassVar[PacketType] = PacketType.ATTRS

    request_id: int
    attrs: Attrs = EMPTY_ATTRS

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        encode_attrs(writer, self.attrs)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(request_id=reader.read_uint32(), attrs=decode_attrs(reader))


@dataclass(frozen=True, slots=True)
class ExtendedReply:
    """The reply to an EXTENDED request whose extension defines a non-STATUS answer.

    The body is extension-specific and is surfaced as raw bytes: only the caller knows what
    it asked for, so only the caller can say what came back.
    """

    packet_type: ClassVar[PacketType] = PacketType.EXTENDED_REPLY

    request_id: int
    data: bytes = b""

    def encode_body(self, writer: WireWriter) -> None:
        """Append this packet's body, excluding the type byte."""
        writer.write_uint32(self.request_id)
        writer.write_bytes(self.data)

    @classmethod
    def decode_body(cls, reader: WireReader) -> Self:
        """Read this packet's body, with the type byte already consumed."""
        return cls(request_id=reader.read_uint32(), data=bytes(reader.read_remaining()))


# --- the union and the dispatch table ----------------------------------------------------

Packet = (
    Init
    | Version
    | Open
    | Close
    | Read
    | Write
    | LStat
    | FStat
    | SetStat
    | FSetStat
    | OpenDir
    | ReadDir
    | Remove
    | MkDir
    | RmDir
    | RealPath
    | Stat
    | Rename
    | ReadLink
    | SymLink
    | Extended
    | Status
    | Handle
    | Data
    | Name
    | AttrsReply
    | ExtendedReply
)
"""Every filexfer v3 packet.

Both directions, deliberately. A client never receives an OPEN, but being able to decode
one is what makes the debug frame dumper possible and what will make server mode cheap --
and a decoder that only handles what it expects is a decoder that has not decided what to
do about the rest.
"""

_DECODERS: dict[PacketType, Callable[[WireReader], Packet]] = {
    PacketType.INIT: Init.decode_body,
    PacketType.VERSION: Version.decode_body,
    PacketType.OPEN: Open.decode_body,
    PacketType.CLOSE: Close.decode_body,
    PacketType.READ: Read.decode_body,
    PacketType.WRITE: Write.decode_body,
    PacketType.LSTAT: LStat.decode_body,
    PacketType.FSTAT: FStat.decode_body,
    PacketType.SETSTAT: SetStat.decode_body,
    PacketType.FSETSTAT: FSetStat.decode_body,
    PacketType.OPENDIR: OpenDir.decode_body,
    PacketType.READDIR: ReadDir.decode_body,
    PacketType.REMOVE: Remove.decode_body,
    PacketType.MKDIR: MkDir.decode_body,
    PacketType.RMDIR: RmDir.decode_body,
    PacketType.REALPATH: RealPath.decode_body,
    PacketType.STAT: Stat.decode_body,
    PacketType.RENAME: Rename.decode_body,
    PacketType.READLINK: ReadLink.decode_body,
    PacketType.SYMLINK: SymLink.decode_body,
    PacketType.EXTENDED: Extended.decode_body,
    PacketType.STATUS: Status.decode_body,
    PacketType.HANDLE: Handle.decode_body,
    PacketType.DATA: Data.decode_body,
    PacketType.NAME: Name.decode_body,
    PacketType.ATTRS: AttrsReply.decode_body,
    PacketType.EXTENDED_REPLY: ExtendedReply.decode_body,
}


def encode(packet: Packet) -> bytes:
    """Encode a packet into a complete wire frame, length prefix included.

    Args:
        packet: The packet to encode.

    Returns:
        Bytes ready to hand to a transport. The result of feeding these to a
        :class:`~gantry_sftp.codec.FrameSplitter` is a frame that :func:`decode` turns back
        into an equal packet.
    """
    writer = WireWriter()
    writer.write_uint8(packet.packet_type)
    packet.encode_body(writer)
    body = writer.getvalue()
    return len(body).to_bytes(4, "big") + body


def decode(frame: memoryview | bytes) -> Packet:
    """Decode one frame body into a packet.

    Args:
        frame: A frame body as produced by :meth:`FrameSplitter.feed` -- the type byte and
            everything after it, without the length prefix.

    Returns:
        The decoded packet.

    Raises:
        ProtocolError: If the type byte is not a v3 packet type, if the body is truncated,
            or if the body has bytes left over once the packet is decoded. Trailing bytes
            mean our idea of the layout disagrees with the server's, which is worth hearing
            about at the packet that caused it rather than at the next one.
    """
    reader = WireReader(frame)
    raw_type = reader.read_uint8()
    try:
        packet_type = PacketType(raw_type)
    except ValueError as exc:
        raise ProtocolError(
            f"unknown packet type {raw_type}; filexfer v3 defines "
            f"{sorted(int(p) for p in PacketType)}",
            packet_type=raw_type,
            raw_frame=frame,
        ) from exc

    reader = WireReader(frame, packet_type=int(packet_type))
    reader.read_uint8()
    packet = _DECODERS[packet_type](reader)

    if not reader.at_end:
        raise ProtocolError(
            f"{packet_type.name} frame has {reader.remaining} trailing bytes after a "
            f"complete packet",
            packet_type=int(packet_type),
            raw_frame=frame,
        )
    return packet

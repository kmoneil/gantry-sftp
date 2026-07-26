"""The v3 ATTRS structure.

``uint32 flags`` followed by the fields whose bits are set, strictly in wire order. Two of
those bits govern *two* fields each, and that is the whole reason this module exists as
something other than a five-field record: ``UIDGID`` covers uid and gid, ``ACMODTIME``
covers atime and mtime. Modelling them as four independent optional fields would admit
"uid set, gid missing", which has no wire representation -- there is no bit that means it.
A decoder written against that shape reads one field, desynchronises, and misparses
everything after the ATTRS in the packet.

So the pairs are single values of type :class:`Owner` and :class:`Times`. The illegal state
is not validated against; it cannot be written down.

Timestamps are ``uint32`` seconds. That is the v3 wire format, and it is Y2038-bounded no
matter what Python holds -- :class:`Times` is what a caller sets, the range check happens on
encode, and nothing here silently truncates a larger value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

from gantry_sftp.codec._constants import AttrFlag
from gantry_sftp.codec._wire import WireReader, WireWriter
from gantry_sftp.exceptions import ProtocolError

__all__ = ["Attrs", "Owner", "Times", "decode_attrs", "encode_attrs"]

_KNOWN_FLAGS = (
    AttrFlag.SIZE | AttrFlag.UIDGID | AttrFlag.PERMISSIONS | AttrFlag.ACMODTIME | AttrFlag.EXTENDED
)


class Owner(NamedTuple):
    """A uid/gid pair, present or absent together under ``SSH_FILEXFER_ATTR_UIDGID``.

    Both are raw numeric ids. Turning them into names needs
    ``users-groups-by-id@openssh.com``; without it we report the numbers rather than
    guessing, and never by scraping the ``longname`` display string.
    """

    uid: int
    gid: int


class Times(NamedTuple):
    """An atime/mtime pair, present or absent together under ``SSH_FILEXFER_ATTR_ACMODTIME``.

    Seconds since the epoch, as ``uint32`` on the wire.
    """

    atime: int
    mtime: int


@dataclass(frozen=True, slots=True)
class Attrs:
    """File attributes. Every field is optional; a server sends what it feels like sending.

    Absent is not zero. A server that does not report a size is saying "I did not tell
    you", which is different from "the file is empty" -- so the fields are ``None`` rather
    than defaulted, and code that needs a value has to decide what to do about not having
    one.

    Attributes:
        size: File size in bytes.
        owner: uid and gid, together or not at all.
        permissions: POSIX mode bits, including the file-type bits.
        times: atime and mtime, together or not at all.
        extended: Vendor ``type``/``data`` pairs, in wire order.
    """

    size: int | None = None
    owner: Owner | None = None
    permissions: int | None = None
    times: Times | None = None
    extended: tuple[tuple[bytes, bytes], ...] = field(default_factory=tuple)

    @property
    def flags(self) -> AttrFlag:
        """The flags word this instance encodes to."""
        flags = AttrFlag(0)
        if self.size is not None:
            flags |= AttrFlag.SIZE
        if self.owner is not None:
            flags |= AttrFlag.UIDGID
        if self.permissions is not None:
            flags |= AttrFlag.PERMISSIONS
        if self.times is not None:
            flags |= AttrFlag.ACMODTIME
        if self.extended:
            flags |= AttrFlag.EXTENDED
        return flags


EMPTY_ATTRS = Attrs()
"""No attributes at all -- a flags word of zero and nothing after it.

This is what a request sends when it has nothing to say, which is most of them: OPEN
carries an ATTRS it almost never uses.
"""


def encode_attrs(writer: WireWriter, attrs: Attrs) -> None:
    """Append an ATTRS structure to ``writer``."""
    writer.write_uint32(attrs.flags)
    if attrs.size is not None:
        writer.write_uint64(attrs.size)
    if attrs.owner is not None:
        writer.write_uint32(attrs.owner.uid)
        writer.write_uint32(attrs.owner.gid)
    if attrs.permissions is not None:
        writer.write_uint32(attrs.permissions)
    if attrs.times is not None:
        writer.write_uint32(attrs.times.atime)
        writer.write_uint32(attrs.times.mtime)
    if attrs.extended:
        writer.write_uint32(len(attrs.extended))
        for ext_type, ext_data in attrs.extended:
            writer.write_string(ext_type)
            writer.write_string(ext_data)


def decode_attrs(reader: WireReader) -> Attrs:
    """Read an ATTRS structure from ``reader``.

    Raises:
        ProtocolError: If the flags word sets a bit v3 does not define. An unknown bit is
            unrecoverable rather than ignorable: it announces a field of unknown width, so
            there is no way to skip past it and no way to trust anything decoded after it.
            Ignoring it would desynchronise the rest of the packet silently, which is worse
            than failing.
    """
    flags = reader.read_uint32()
    unknown = flags & ~_KNOWN_FLAGS
    if unknown:
        raise ProtocolError(
            f"ATTRS sets undefined flag bits 0x{unknown:08x}; filexfer v3 defines only "
            f"0x{int(_KNOWN_FLAGS):08x}, and an unknown bit means a field of unknown width"
        )

    size = reader.read_uint64() if flags & AttrFlag.SIZE else None
    owner = Owner(reader.read_uint32(), reader.read_uint32()) if flags & AttrFlag.UIDGID else None
    permissions = reader.read_uint32() if flags & AttrFlag.PERMISSIONS else None
    times = (
        Times(reader.read_uint32(), reader.read_uint32()) if flags & AttrFlag.ACMODTIME else None
    )

    extended: tuple[tuple[bytes, bytes], ...] = ()
    if flags & AttrFlag.EXTENDED:
        count = reader.read_uint32()
        # Not pre-allocated on `count`: a hostile count is bounded by the frame, because
        # the first read past the end raises rather than looping.
        pairs = []
        for _ in range(count):
            ext_type = bytes(reader.read_string())
            pairs.append((ext_type, bytes(reader.read_string())))
        extended = tuple(pairs)

    return Attrs(size=size, owner=owner, permissions=permissions, times=times, extended=extended)

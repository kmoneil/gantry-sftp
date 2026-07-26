"""Sans-I/O filexfer v3 codec. Bytes in, events out.

This layer is **pure**: no I/O, no ``async``, no threads, no timers, no clock, no
randomness. It cannot open a socket and it cannot tell you what time it is.

That purity is what makes the protocol testable without a server, fuzzable without a
network, and reusable for a server implementation later. It is enforced by
``tests/test_layer_discipline.py``, not by everyone remembering -- a codec that needs the
wall clock is a codec with a bug, and the test says so out loud.

Typical use is through :class:`Codec`, which owns the handshake, request-id allocation and
request/response correlation together::

    codec = Codec()
    transport.send(codec.initiate())

    request_id = codec.allocate_request_id()
    transport.send(codec.send(RealPath(request_id, b".")))

    for event in codec.receive(transport.recv()):
        ...

:class:`FrameSplitter`, :func:`encode` and :func:`decode` are the layer underneath and stay
public: they are what a debug frame dumper, a fuzz harness, or a future server
implementation needs, and none of those want a client's state machine attached.
"""

from __future__ import annotations

from gantry_sftp.codec._attrs import EMPTY_ATTRS, Attrs, Owner, Times, decode_attrs, encode_attrs
from gantry_sftp.codec._codec import Codec, CodecState, Completed, Event, Negotiated
from gantry_sftp.codec._constants import (
    EXTENSION_FSYNC,
    EXTENSION_LIMITS,
    EXTENSION_POSIX_RENAME,
    MAX_STATUS_CODE,
    NO_REQUEST_ID,
    OPENSSH_ADVERTISED_EXTENSIONS,
    PROTOCOL_VERSION,
    AttrFlag,
    OpenFlag,
    PacketType,
    StatusCode,
)
from gantry_sftp.codec._extensions import (
    FSYNC_NAME,
    LIMITS_NAME,
    POSIX_RENAME_NAME,
    Fsync,
    PosixRename,
)
from gantry_sftp.codec._framing import DEFAULT_MAX_FRAME_LENGTH, FrameSplitter
from gantry_sftp.codec._packets import (
    AttrsReply,
    Close,
    Data,
    Extended,
    ExtendedReply,
    FSetStat,
    FStat,
    Handle,
    Init,
    LStat,
    MkDir,
    Name,
    NameEntry,
    Open,
    OpenDir,
    Packet,
    Read,
    ReadDir,
    ReadLink,
    RealPath,
    Remove,
    Rename,
    Request,
    Response,
    RmDir,
    SetStat,
    Stat,
    Status,
    SymLink,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.codec._wire import WireReader, WireWriter

__all__ = [
    "DEFAULT_MAX_FRAME_LENGTH",
    "EMPTY_ATTRS",
    "EXTENSION_FSYNC",
    "EXTENSION_LIMITS",
    "EXTENSION_POSIX_RENAME",
    "FSYNC_NAME",
    "LIMITS_NAME",
    "MAX_STATUS_CODE",
    "NO_REQUEST_ID",
    "OPENSSH_ADVERTISED_EXTENSIONS",
    "POSIX_RENAME_NAME",
    "PROTOCOL_VERSION",
    "AttrFlag",
    "Attrs",
    "AttrsReply",
    "Close",
    "Codec",
    "CodecState",
    "Completed",
    "Data",
    "Event",
    "Extended",
    "ExtendedReply",
    "FSetStat",
    "FStat",
    "FrameSplitter",
    "Fsync",
    "Handle",
    "Init",
    "LStat",
    "MkDir",
    "Name",
    "NameEntry",
    "Negotiated",
    "Open",
    "OpenDir",
    "OpenFlag",
    "Owner",
    "Packet",
    "PacketType",
    "PosixRename",
    "Read",
    "ReadDir",
    "ReadLink",
    "RealPath",
    "Remove",
    "Rename",
    "Request",
    "Response",
    "RmDir",
    "SetStat",
    "Stat",
    "Status",
    "StatusCode",
    "SymLink",
    "Times",
    "Version",
    "WireReader",
    "WireWriter",
    "Write",
    "decode",
    "decode_attrs",
    "encode",
    "encode_attrs",
]

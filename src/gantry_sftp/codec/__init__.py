"""Sans-I/O filexfer v3 codec. Bytes in, events out.

This layer is **pure**: no I/O, no ``async``, no threads, no timers, no clock, no
randomness. It cannot open a socket and it cannot tell you what time it is.

That purity is what makes the protocol testable without a server, fuzzable without a
network, and reusable for a server implementation later. It is enforced by
``tests/test_layer_discipline.py``, not by everyone remembering -- a codec that needs the
wall clock is a codec with a bug, and the test says so out loud.

Typical use::

    splitter = FrameSplitter()
    transport.send(encode(Init()))
    for frame in splitter.feed(transport.recv()):
        packet = decode(frame)

Request-id allocation and request/response correlation are not here yet. They arrive with
the state machine that owns both together; a counter designed in isolation from the
correlation table it feeds is a counter with the wrong interface.
"""

from __future__ import annotations

from gantry_sftp.codec._attrs import EMPTY_ATTRS, Attrs, Owner, Times, decode_attrs, encode_attrs
from gantry_sftp.codec._constants import (
    MAX_STATUS_CODE,
    NO_REQUEST_ID,
    OPENSSH_ADVERTISED_EXTENSIONS,
    PROTOCOL_VERSION,
    AttrFlag,
    OpenFlag,
    PacketType,
    StatusCode,
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
    "MAX_STATUS_CODE",
    "NO_REQUEST_ID",
    "OPENSSH_ADVERTISED_EXTENSIONS",
    "PROTOCOL_VERSION",
    "AttrFlag",
    "Attrs",
    "AttrsReply",
    "Close",
    "Data",
    "Extended",
    "ExtendedReply",
    "FSetStat",
    "FStat",
    "FrameSplitter",
    "Handle",
    "Init",
    "LStat",
    "MkDir",
    "Name",
    "NameEntry",
    "Open",
    "OpenDir",
    "OpenFlag",
    "Owner",
    "Packet",
    "PacketType",
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

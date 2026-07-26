"""Sans-I/O filexfer v3 codec. Bytes in, events out.

This layer is **pure**: no I/O, no ``async``, no threads, no timers, no clock, no
randomness. It cannot open a socket and it cannot tell you what time it is. Request-id
allocation is deterministic and owned here.

That purity is what makes the protocol testable without a server, fuzzable without a
network, and reusable for a server implementation later. It is enforced by
``tests/test_layer_discipline.py``, not by everyone remembering -- a codec that needs the
wall clock is a codec with a bug, and the test says so out loud.
"""

from __future__ import annotations

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
from gantry_sftp.codec._wire import WireReader, WireWriter

__all__ = [
    "DEFAULT_MAX_FRAME_LENGTH",
    "MAX_STATUS_CODE",
    "NO_REQUEST_ID",
    "OPENSSH_ADVERTISED_EXTENSIONS",
    "PROTOCOL_VERSION",
    "AttrFlag",
    "FrameSplitter",
    "OpenFlag",
    "PacketType",
    "StatusCode",
    "WireReader",
    "WireWriter",
]

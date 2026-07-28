r"""One line per packet, for a frame dump. Pure, and deliberately not ``repr``.

Two shipped docstrings in this package justify their public surface with "what a debug frame
dumper needs" -- :mod:`gantry_sftp.codec` on ``encode``/``decode``/``FrameSplitter``, and the
:data:`~gantry_sftp.codec.Packet` union on decoding packets a client never receives. This is that
dumper's rendering half. The *emitting* half is at the session/transport seam, in
:mod:`gantry_sftp._logging`, because a log record carries a timestamp and the codec does not read
the clock.

Three rules, and each one is a decision rather than a formatting preference.

**Untrusted bytes are rendered with ``repr``, never decoded.** Every filename, path and server
message here is attacker-controlled -- it came from ``READDIR``, ``READLINK``, ``REALPATH`` or a
``STATUS``. Writing those into a log stream raw is log injection: a ``\n`` forges a second log
record, and an ``\x1b[`` sequence drives the terminal of whoever tails the file. Python's ``repr``
escapes both, and every non-printable Unicode codepoint besides -- including U+2028, which is a
line break to a JavaScript log viewer and invisible to ``str.isprintable``'s casual reader. So the
raw bytes go through ``repr`` and no ``decode`` appears in this module.

**Every rendered field is truncated.** A hostile server can answer with a 64 KiB filename, and a
dumper that prints one per frame is a log bomb aimed at the operator's disk. The cap is
:data:`MAX_FIELD_BYTES` and it is applied at the single place bytes become text.

**``DATA`` and ``WRITE`` payloads are never rendered.** Not for privacy -- for the two reasons that
would make it useless anyway: a quarter-megabyte payload in a log line is unreadable, and rendering
a ``memoryview`` copies it, which is the allocation this library's data path exists to avoid. They
show as ``len=N``, which is the diagnostic content either way.
"""

from __future__ import annotations

from typing import assert_never

from gantry_sftp.codec._attrs import Attrs
from gantry_sftp.codec._packets import (
    AttrsReply,
    Data,
    Extended,
    ExtendedReply,
    FSetStat,
    Init,
    Name,
    Open,
    Packet,
    Read,
    Rename,
    Request,
    Response,
    Status,
    SymLink,
    Version,
    Write,
    _HandleRequest,
    _PathAttrsRequest,
    _PathRequest,
)

__all__ = ["MAX_FIELD_BYTES", "describe", "render_field"]

MAX_FIELD_BYTES = 96
"""Bytes of any one field a dump will render before it says how many it dropped.

Long enough for a realistic path, short enough that a frame stays one line and a server cannot
choose how much of the operator's disk a transfer fills.
"""

_Correlated = Request | Response
"""Every packet that carries a request id -- which is every packet but ``INIT`` and ``VERSION``."""

_ShapedRequest = Open | Read | Write | FSetStat | Rename | SymLink | Extended
"""Requests whose body is not one of the three shapes ``_packets`` factors out.

Spelled out rather than derived, because the residue *is* the list of packets with a body of
their own -- and because a new request type that does not fit an existing shape then fails to
typecheck at the one call site, which is the reminder to render it.
"""

_ShapedResponse = Status | Data | Name | AttrsReply | ExtendedReply
"""Replies with a body of their own. ``HANDLE`` is absent because it shares the handle shape."""


def describe(packet: Packet) -> str:
    r"""Render one packet as a single line, safe to put in a log.

    The line is the packet type followed by the fields that matter for diagnosis -- what was
    asked, of which handle, at which offset, and how big the answer was. A ``READ`` comes out as
    ``READ id=7 handle=b'\x00...' offset=1024 len=32768``. It is a *diagnostic* rendering, not
    a serialisation: it is lossy by design, and nothing should parse it.

    Args:
        packet: Any filexfer v3 packet, in either direction. A client never receives an
            ``OPEN``, and this renders one anyway; a dumper that can only show what it expects
            is no use on the frame that surprised you.

    Returns:
        One line, with no trailing newline. Contains no unescaped control characters whatever
        the server sent, and no payload bytes from a ``DATA`` or a ``WRITE``.
    """
    return f"{packet.packet_type.name} {_body(packet)}"


def _body(packet: Packet) -> str:
    """The fields, without the type name every packet shares.

    ``INIT`` and ``VERSION`` are the framing exception here exactly as they are on the wire:
    they carry a version where every other packet carries a request id.
    """
    if isinstance(packet, Init | Version):
        return f"version={packet.version} extensions={len(packet.extensions)}"
    return f"id={packet.request_id} {_fields(packet)}"


def _fields(packet: _Correlated) -> str:
    """Fields of a packet that carries a request id.

    Structured the way :mod:`gantry_sftp.codec._packets` structures the packets themselves: ten
    requests share three body shapes -- a path, a handle, or a path and an attribute set -- and
    are rendered by shape rather than one case per type. A dumper that enumerated all
    twenty-seven would be a second enumeration to keep in step with the first.
    """
    if isinstance(packet, _PathAttrsRequest):
        return f"path={render_field(packet.path)} attrs={_attrs(packet.attrs)}"
    if isinstance(packet, _PathRequest):
        return f"path={render_field(packet.path)}"
    if isinstance(packet, _HandleRequest):
        # `Handle`, the reply, shares this shape and lands here too, which is right: the
        # handle is the whole content of both.
        return f"handle={render_field(packet.handle)}"
    if isinstance(packet, Request):
        return _request_fields(packet)
    return _response_fields(packet)


def _request_fields(packet: _ShapedRequest) -> str:
    """Fields of a request whose body is its own shape.

    ``assert_never`` is what makes adding a packet type a *type* error rather than a silent gap
    -- the completeness sweep CLAUDE.md's Definition of Done 2 asks for, enforced at check time.
    A new request type also has to be added to :data:`_ShapedRequest` or the call above stops
    typechecking, so neither half can be forgotten quietly.
    """
    match packet:
        case Open():
            fields = (
                f"filename={render_field(packet.filename)} "
                f"pflags={packet.pflags.name or '0'} attrs={_attrs(packet.attrs)}"
            )
        case Read():
            fields = (
                f"handle={render_field(packet.handle)} offset={packet.offset} len={packet.length}"
            )
        case Write():
            fields = (
                f"handle={render_field(packet.handle)} offset={packet.offset} "
                f"len={len(packet.data)}"
            )
        case FSetStat():
            fields = f"handle={render_field(packet.handle)} attrs={_attrs(packet.attrs)}"
        case Rename():
            fields = f"old={render_field(packet.oldpath)} new={render_field(packet.newpath)}"
        case SymLink():
            # Named by semantics, not by wire order -- which is reversed. See `SymLink`.
            fields = (
                f"link={render_field(packet.linkpath)} target={render_field(packet.targetpath)}"
            )
        case Extended():
            fields = f"name={render_field(packet.name)} len={len(packet.data)}"
        case _:  # pragma: no cover -- unreachable while the match above is exhaustive
            assert_never(packet)
    return fields


def _response_fields(packet: _ShapedResponse) -> str:
    """Fields of a reply. Exhaustive for the same reason, and by the same mechanism."""
    match packet:
        case Status():
            return f"code={packet.code.name}{_message(packet.message)}"
        case Data() | ExtendedReply():
            return f"len={len(packet.data)}"
        case Name():
            return f"entries={len(packet.entries)}{_first(packet)}"
        case AttrsReply():
            return f"attrs={_attrs(packet.attrs)}"
        case _:  # pragma: no cover -- unreachable while the match above is exhaustive
            assert_never(packet)


def render_field(raw: bytes | memoryview) -> str:
    """Render untrusted bytes: escaped by ``repr``, truncated, and honest about the truncation.

    Public because the dumper is not the only place server-supplied bytes become text -- the
    session's handshake record names the extensions a server advertised, and it needs the same
    rule rather than a second, kinder one. The dropped-byte count is part of the output rather
    than an ellipsis, because "this path was long" and "this path was 64 KiB of the same
    character" call for different responses.

    Args:
        raw: Bytes from the wire. A ``memoryview`` is not copied beyond the cap.

    Returns:
        A ``repr``-escaped literal, carrying at most :data:`MAX_FIELD_BYTES` bytes of content
        and a ``+NB`` suffix naming what was dropped.
    """
    if len(raw) <= MAX_FIELD_BYTES:
        return repr(bytes(raw))
    return f"{bytes(raw[:MAX_FIELD_BYTES])!r}+{len(raw) - MAX_FIELD_BYTES}B"


def _message(message: bytes) -> str:
    """A STATUS message, or nothing at all when the server sent none -- which is usual.

    The language tag is deliberately dropped. OpenSSH sends it empty, the draft's own tail is
    optional, and a field that is empty on every real server is noise on every line.
    """
    return f" message={render_field(message)}" if message else ""


def _first(name: Name) -> str:
    """The first filename of a NAME, as a sample of a listing that may hold thousands.

    A zero-entry NAME is legal and is how a listing ends, so it renders as the count alone.
    """
    return f" first={render_field(name.entries[0].filename)}" if name.entries else ""


def _attrs(attrs: Attrs) -> str:
    """Attributes as the fields that are actually present.

    Absent is not zero -- a server that reports no size has told you nothing about the size --
    so an omitted field is omitted here too, and an ATTRS with no flags set renders as ``-``
    rather than as five defaults it never sent.
    """
    parts: list[str] = []
    if attrs.size is not None:
        parts.append(f"size={attrs.size}")
    if attrs.permissions is not None:
        parts.append(f"mode={attrs.permissions:#o}")
    if attrs.owner is not None:
        parts.append(f"uid={attrs.owner.uid} gid={attrs.owner.gid}")
    if attrs.times is not None:
        parts.append(f"atime={attrs.times.atime} mtime={attrs.times.mtime}")
    if attrs.extended:
        parts.append(f"extended={len(attrs.extended)}")
    return f"({' '.join(parts)})" if parts else "-"

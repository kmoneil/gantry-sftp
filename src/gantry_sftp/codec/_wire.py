"""Primitive field codecs for the filexfer wire format.

The wire types are the SSH architecture ones (RFC 4251 section 5): fixed-width big-endian
unsigned integers, and ``string`` as a ``uint32`` length followed by that many bytes. A
``string`` is *binary*: filenames, handles and error messages all use it, and none of them
are guaranteed to be valid UTF-8. So reads return raw bytes and decoding policy lives
above this layer, where it can be wrong in a way the user can see and configure.

Reads never copy the payload -- :meth:`WireReader.read_string` returns a view into the
caller's buffer. Fixed-width integer fields do copy, because copying eight bytes is cheaper
than the memoryview object that would avoid it.
"""

from __future__ import annotations

from gantry_sftp.exceptions import ProtocolError

__all__ = ["WireReader", "WireWriter"]

_UINT8_MAX = 0xFF
_UINT32_MAX = 0xFFFFFFFF
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF


class WireReader:
    """Sequential reader over a single decoded frame.

    The reader does not own its buffer and never mutates it. Every read is bounds-checked
    against the end of the frame, so a truncated or hostile frame raises
    :class:`~gantry_sftp.exceptions.ProtocolError` rather than raising ``IndexError``,
    reading adjacent memory, or over-allocating.

    Args:
        buf: The frame body to read from, excluding the outer length prefix.
        packet_type: Attached to any error raised, so a failure names the packet it
            happened in rather than just an offset.
        request_id: Likewise, once it is known.
    """

    __slots__ = ("_buf", "_packet_type", "_pos", "_request_id")

    def __init__(
        self,
        buf: memoryview | bytes,
        *,
        packet_type: int | None = None,
        request_id: int | None = None,
    ) -> None:
        self._buf = memoryview(buf) if not isinstance(buf, memoryview) else buf
        self._pos = 0
        self._packet_type = packet_type
        self._request_id = request_id

    @property
    def position(self) -> int:
        """Bytes consumed so far."""
        return self._pos

    @property
    def remaining(self) -> int:
        """Bytes left unread in the frame."""
        return len(self._buf) - self._pos

    @property
    def at_end(self) -> bool:
        """Whether every byte of the frame has been consumed.

        Worth asserting after decoding a packet: trailing bytes mean the layout we used
        disagrees with the layout the server used, which is a bug worth hearing about
        early rather than at the next packet boundary.
        """
        return self._pos >= len(self._buf)

    def set_request_id(self, request_id: int) -> None:
        """Record the request id for error reporting, once it has been read."""
        self._request_id = request_id

    def _fail(self, message: str) -> ProtocolError:
        return ProtocolError(
            message,
            packet_type=self._packet_type,
            request_id=self._request_id,
            raw_frame=self._buf,
        )

    def _take(self, n: int) -> memoryview:
        if n > self.remaining:
            raise self._fail(
                f"truncated frame: need {n} more bytes at offset {self._pos}, "
                f"{self.remaining} available"
            )
        chunk = self._buf[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def read_uint8(self) -> int:
        """Read a single unsigned byte."""
        return self._take(1)[0]

    def read_uint32(self) -> int:
        """Read a big-endian 32-bit unsigned integer."""
        return int.from_bytes(self._take(4), "big")

    def read_uint64(self) -> int:
        """Read a big-endian 64-bit unsigned integer."""
        return int.from_bytes(self._take(8), "big")

    def read_bytes(self, n: int) -> memoryview:
        """Read exactly ``n`` raw bytes as a view, without copying."""
        return self._take(n)

    def read_string(self) -> memoryview:
        """Read a length-prefixed binary string as a view, without copying.

        The length is bounds-checked against the remaining frame, so a server claiming a
        four-gigabyte string inside a small frame is rejected on the claim rather than on
        the allocation.
        """
        length = self.read_uint32()
        return self._take(length)

    def read_remaining(self) -> memoryview:
        """Read everything left in the frame as a view, without copying."""
        return self._take(self.remaining)


class WireWriter:
    """Incremental builder for a frame body.

    The writer keeps the pieces it is given and joins them once, into a buffer of exactly
    the right size, when the caller asks for the result. Nothing is copied on the way in.
    That is what makes the ``memoryview``-end-to-end rule true on the *send* side as well
    as the receive side: a WRITE's payload is copied exactly once, straight into the frame
    that goes to the transport (D-112). Building into a ``bytearray`` instead copied every
    uploaded byte three times -- into the builder, again to materialise it, and again to
    put the length prefix in front.

    One copy is the floor without handing the transport a header and a payload as two
    separate buffers, which is an interface change this does not need; see D-112 for the
    measurement that decided against it.

    **The writer does not own what it is handed.** A buffer written here is referenced,
    not copied, until :meth:`getvalue` or :meth:`frame` materialises it, so a caller must
    not mutate a buffer in between. Encoding is synchronous and materialises immediately,
    so the window is one function call wide -- but it is a window, and it did not exist
    when this copied on the way in.
    """

    __slots__ = ("_chunks", "_size")

    def __init__(self) -> None:
        self._chunks: list[bytes | memoryview] = []
        self._size = 0

    def __len__(self) -> int:
        """Bytes written so far."""
        return self._size

    def write_uint8(self, value: int) -> None:
        """Append an unsigned byte.

        Raises:
            ValueError: If ``value`` does not fit in eight unsigned bits.
        """
        if not 0 <= value <= _UINT8_MAX:
            raise ValueError(f"uint8 out of range: {value}")
        self._chunks.append(value.to_bytes(1, "big"))
        self._size += 1

    def write_uint32(self, value: int) -> None:
        """Append a big-endian 32-bit unsigned integer.

        Raises:
            ValueError: If ``value`` does not fit in thirty-two unsigned bits.
        """
        if not 0 <= value <= _UINT32_MAX:
            raise ValueError(f"uint32 out of range: {value}")
        self._chunks.append(value.to_bytes(4, "big"))
        self._size += 4

    def write_uint64(self, value: int) -> None:
        """Append a big-endian 64-bit unsigned integer.

        Raises:
            ValueError: If ``value`` does not fit in sixty-four unsigned bits.
        """
        if not 0 <= value <= _UINT64_MAX:
            raise ValueError(f"uint64 out of range: {value}")
        self._chunks.append(value.to_bytes(8, "big"))
        self._size += 8

    def write_bytes(self, value: bytes | memoryview) -> None:
        """Append raw bytes with no length prefix."""
        self._chunks.append(value)
        self._size += len(value)

    def write_string(self, value: bytes | memoryview) -> None:
        """Append a length-prefixed binary string.

        Raises:
            ValueError: If ``value`` is longer than a ``uint32`` length can describe.
        """
        self.write_uint32(len(value))
        self._chunks.append(value)
        self._size += len(value)

    def getvalue(self) -> bytes:
        """Return the accumulated body, in a single allocation."""
        return b"".join(self._chunks)

    def frame(self) -> bytes:
        """Return the body behind its ``uint32`` length prefix, in a single allocation.

        The prefix is the body's length, which the writer already knows -- so a frame needs
        no size calculation per packet type and no second pass over what has been written.

        Raises:
            OverflowError: If the body is longer than a ``uint32`` length can describe. No
                single field can reach that -- :meth:`write_string` refuses first -- so it
                takes a packet built from billions of fields to get here.
        """
        return b"".join([self._size.to_bytes(4, "big"), *self._chunks])

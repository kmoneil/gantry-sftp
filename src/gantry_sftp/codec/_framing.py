"""Incremental frame splitting for the length-prefixed filexfer stream.

The stream is ``uint32 length`` followed by that many bytes of frame body. The transport
hands us whatever the pipe gave it -- a partial header, three frames and a fragment, a
single byte -- so splitting is a resumable state machine and never a parse of a whole
message.

Zero-copy, without a lifetime rule to remember
----------------------------------------------
:meth:`FrameSplitter.feed` returns views into an internal buffer. A frame stays valid for
as long as you hold it, and holding one never corrupts anything or stalls the stream.

That is a stronger guarantee than it first looks, and getting to it took two attempts.
Requiring frames to be dropped before the next ``feed`` is unworkable in practice: the most
natural loop in the language, ``for frame in splitter.feed(data):``, leaves the name bound
after the loop, and a decoded ``DATA`` packet holds a *slice* of its frame, which nothing
here can reach to release. Either of those turns a correct program into a usage error.

So the buffer is never mutated while views into it are alive. CPython refuses to resize a
``bytearray`` with live exports, and that refusal is the signal: when it happens, the
splitter moves the unparsed remainder into a fresh buffer and carries on, leaving the old
one to the caller for as long as they want it. Safety is structural rather than
contractual -- a held view cannot see recycled bytes, because bytes are never recycled
underneath it.

That path is the common one, not an exceptional one: the loop above leaves a view alive, so
most feeds take it. It is cheap on purpose. Both paths copy the incoming ``data`` into the
buffer and both move the unparsed remainder -- compaction relocates it just as a fresh
buffer does -- so the difference is an allocation, not a copy of anything large. **No frame
payload is ever copied by this module**, which is the property that actually matters: a
quarter-megabyte READ arrives once and is handed onward as a view.
"""

from __future__ import annotations

from gantry_sftp.exceptions import ProtocolError

__all__ = ["DEFAULT_MAX_FRAME_LENGTH", "FrameSplitter"]

_LENGTH_PREFIX_SIZE = 4

DEFAULT_MAX_FRAME_LENGTH = 4 * 1024 * 1024
"""Hard ceiling on a single frame, well above any real packet.

A real server's limit is far lower -- OpenSSH reports a ``max-packet-length`` of 256 KiB --
but this is not a tuning knob. It is the guard that stops a hostile or corrupted stream
claiming a four-gigabyte frame and getting a four-gigabyte allocation for the cost of four
bytes. The claim is rejected before anything is reserved for it.
"""

_COMPACT_THRESHOLD = 64 * 1024
"""Consumed-prefix size at which the buffer is compacted.

Compaction is O(n) in what is left, so doing it every feed would make a byte-at-a-time
stream quadratic. Deferring it trades a bounded amount of dead memory for linear
behaviour.
"""


class FrameSplitter:
    """Splits a byte stream into frame bodies.

    The returned bodies include the packet type byte and everything after it, and exclude
    the length prefix -- the prefix is framing, not content, and nothing above this layer
    should see it.

    Args:
        max_frame_length: Reject any frame claiming to be longer than this. Defaults to
            :data:`DEFAULT_MAX_FRAME_LENGTH`.
    """

    __slots__ = ("_buf", "_max_frame_length", "_start")

    def __init__(self, *, max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH) -> None:
        if max_frame_length < 1:
            raise ValueError(f"max_frame_length must be at least 1, got {max_frame_length}")
        self._buf = bytearray()
        self._start = 0
        self._max_frame_length = max_frame_length

    @property
    def buffered(self) -> int:
        """Bytes held that do not yet form a complete frame."""
        return len(self._buf) - self._start

    @property
    def max_frame_length(self) -> int:
        """The configured per-frame ceiling."""
        return self._max_frame_length

    def feed(self, data: bytes | memoryview) -> list[memoryview]:
        """Add received bytes and return every complete frame body they finished.

        Args:
            data: Bytes as received from the transport. May be empty, may be a fragment of
                a frame, may contain several frames.

        Returns:
            Frame bodies in wire order, each a view into the splitter's buffer that stays
            valid for as long as it is referenced. Empty if ``data`` did not complete a
            frame.

        Raises:
            ProtocolError: If a frame claims a length of zero, or a length above
                ``max_frame_length``. Both mean the stream is not filexfer, and neither is
                recoverable by reading more bytes.
        """
        self._absorb(data)

        frames: list[memoryview] = []
        view = memoryview(self._buf)
        try:
            while (frame := self._next_frame(view)) is not None:
                frames.append(frame)
        finally:
            # Release our own export so it is not the thing blocking the next reclaim.
            # Slices survive their parent's release.
            view.release()
        return frames

    def _absorb(self, data: bytes | memoryview) -> None:
        """Take ``data`` into the buffer, without ever mutating one that is still in use."""
        try:
            self._reclaim()
            self._buf += data
        except BufferError:
            # Frames from an earlier feed are still referenced, so this buffer belongs to
            # the caller now. Move the unparsed remainder into a fresh one and leave theirs
            # intact -- their views keep working, and the stream keeps moving.
            self._buf = bytearray(self._buf[self._start :])
            self._start = 0
            self._buf += data

    def _next_frame(self, view: memoryview) -> memoryview | None:
        """Pull one complete frame from the buffer, or ``None`` if none is complete."""
        available = len(self._buf) - self._start
        if available < _LENGTH_PREFIX_SIZE:
            return None

        header = self._start
        length = int.from_bytes(self._buf[header : header + _LENGTH_PREFIX_SIZE], "big")

        if length == 0:
            raise ProtocolError("frame declares zero length; every frame has a type byte")
        if length > self._max_frame_length:
            raise ProtocolError(
                f"frame declares length {length}, above the {self._max_frame_length}-byte "
                f"ceiling; refusing to buffer it"
            )
        if available - _LENGTH_PREFIX_SIZE < length:
            return None

        body = header + _LENGTH_PREFIX_SIZE
        self._start = body + length
        return view[body : body + length]

    def _reclaim(self) -> None:
        """Drop consumed bytes, if enough have accumulated to be worth the move.

        Raises:
            BufferError: If a previously returned frame is still referenced. Handled by
                :meth:`_absorb`, which starts a fresh buffer rather than disturbing one the
                caller is still reading.
        """
        if self._start == 0:
            return
        if self._start >= _COMPACT_THRESHOLD or self._start == len(self._buf):
            del self._buf[: self._start]
            self._start = 0

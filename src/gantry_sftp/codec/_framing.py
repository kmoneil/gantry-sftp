"""Incremental frame splitting for the length-prefixed filexfer stream.

The stream is ``uint32 length`` followed by that many bytes of frame body. The transport
hands us whatever the pipe gave it -- a partial header, three frames and a fragment, a
single byte -- so splitting is a resumable state machine and never a parse of a whole
message.

Zero-copy contract
------------------
:meth:`FrameSplitter.feed` returns views into an internal buffer, and those views stay
valid **until the next call to feed**, which explicitly releases them.

Explicitly, rather than by relying on the caller to drop their reference, because the
obvious loop does not drop it::

    for frame in splitter.feed(data):   # `frame` is still bound out here
        handle(frame)

Leaving that dangling reference to block the next feed would make the most natural spelling
in the language a usage error. So the splitter releases what it issued, and a caller who
kept one gets ``ValueError: operation forbidden on released memoryview object`` at the
point of use -- naming the mistake where it happens, instead of surfacing it as a stalled
stream one call later. Callers that need a frame to outlive the next feed copy it, and pay
for the copy where it is visible.
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

    __slots__ = ("_buf", "_issued", "_max_frame_length", "_start")

    def __init__(self, *, max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH) -> None:
        if max_frame_length < 1:
            raise ValueError(f"max_frame_length must be at least 1, got {max_frame_length}")
        self._buf = bytearray()
        self._start = 0
        self._max_frame_length = max_frame_length
        self._issued: list[memoryview] = []

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
            Frame bodies in wire order, each a view valid until the next call to this
            method. Empty if ``data`` did not complete a frame.

        Raises:
            ProtocolError: If a frame claims a length of zero, or a length above
                ``max_frame_length``. Both mean the stream is not filexfer, and neither is
                recoverable by reading more bytes.
            RuntimeError: If a view *derived* from a previous frame -- a slice of it, say --
                is still alive. Releasing the frames we issued cannot reach those.
        """
        # Frames from the previous call are invalidated here, before anything resizes the
        # buffer. Order matters: a live export makes both the compaction and the append
        # raise BufferError.
        for issued in self._issued:
            issued.release()
        self._issued.clear()

        try:
            self._reclaim()
            self._buf += data
        except BufferError as exc:
            raise RuntimeError(
                "a view derived from a previous frame is still alive, so the buffer "
                "cannot be reused; copy any frame data you need to keep beyond the next "
                "feed()"
            ) from exc

        view = memoryview(self._buf)
        try:
            while (frame := self._next_frame(view)) is not None:
                self._issued.append(frame)
        finally:
            # Release our own export so the issued frames are the only thing holding the
            # buffer. Slices survive their parent's release.
            view.release()
        return list(self._issued)

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
            BufferError: If a previously returned frame is still referenced. Translated by
                the caller into an explanation of the zero-copy contract.
        """
        if self._start == 0:
            return
        if self._start >= _COMPACT_THRESHOLD or self._start == len(self._buf):
            del self._buf[: self._start]
            self._start = 0

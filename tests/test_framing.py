"""Frame splitting: partial frames, hostile lengths, and the zero-copy contract."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import DEFAULT_MAX_FRAME_LENGTH, FrameSplitter
from gantry_sftp.codec._framing import _COMPACT_THRESHOLD
from gantry_sftp.exceptions import ProtocolError


def framed(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def test_single_complete_frame():
    s = FrameSplitter()
    assert [bytes(f) for f in s.feed(framed(b"\x02hello"))] == [b"\x02hello"]
    assert s.buffered == 0


def test_several_frames_in_one_feed():
    s = FrameSplitter()
    data = framed(b"\x01") + framed(b"\x02ab") + framed(b"\x65xyz")
    assert [bytes(f) for f in s.feed(data)] == [b"\x01", b"\x02ab", b"\x65xyz"]


def test_frame_split_across_feeds():
    s = FrameSplitter()
    body = b"\x68" + b"payload"
    wire = framed(body)
    for byte in wire[:-1]:
        assert s.feed(bytes([byte])) == []
    assert [bytes(f) for f in s.feed(wire[-1:])] == [body]


def test_header_split_across_feeds():
    # The length prefix itself arriving in pieces is the case a non-resumable parser gets
    # wrong, because there is nothing to parse yet and it is tempting to assume otherwise.
    s = FrameSplitter()
    wire = framed(b"\x02ok")
    assert s.feed(wire[:1]) == []
    assert s.feed(wire[1:3]) == []
    assert s.feed(wire[3:4]) == []
    assert [bytes(f) for f in s.feed(wire[4:])] == [b"\x02ok"]


def test_empty_feed_is_a_no_op():
    s = FrameSplitter()
    assert s.feed(b"") == []
    assert s.buffered == 0


def test_trailing_partial_frame_is_buffered_not_lost():
    s = FrameSplitter()
    frames = s.feed(framed(b"\x02done") + b"\x00\x00\x00\x09par")
    assert [bytes(f) for f in frames] == [b"\x02done"]
    assert s.buffered == 7


def test_accepts_memoryview_input():
    s = FrameSplitter()
    assert [bytes(f) for f in s.feed(memoryview(framed(b"\x02mv")))] == [b"\x02mv"]


# --- rejections ------------------------------------------------------------------------


def test_zero_length_frame_is_rejected():
    s = FrameSplitter()
    with pytest.raises(ProtocolError) as exc:
        s.feed(b"\x00\x00\x00\x00")
    assert exc.value.args[0] == "frame declares zero length; every frame has a type byte"


def test_oversize_frame_is_rejected_on_the_claim_not_the_allocation():
    # 0xFFFFFFFF is four gigabytes. It must be refused after reading four bytes, without
    # reserving anything, or a hostile server gets to exhaust memory for the price of a
    # length prefix.
    s = FrameSplitter(max_frame_length=1024)
    with pytest.raises(ProtocolError) as exc:
        s.feed(b"\xff\xff\xff\xff")
    assert exc.value.args[0] == (
        "frame declares length 4294967295, above the 1024-byte ceiling; refusing to buffer it"
    )
    assert s.buffered == 4


def test_frame_exactly_at_the_ceiling_is_accepted():
    s = FrameSplitter(max_frame_length=16)
    body = bytes(16)
    assert [bytes(f) for f in s.feed(framed(body))] == [body]


def test_frame_one_over_the_ceiling_is_rejected():
    s = FrameSplitter(max_frame_length=16)
    with pytest.raises(ProtocolError):
        s.feed(framed(bytes(17)))


def test_max_frame_length_must_be_positive():
    with pytest.raises(ValueError) as exc:
        FrameSplitter(max_frame_length=0)
    assert exc.value.args[0] == "max_frame_length must be at least 1, got 0"


def test_default_ceiling_is_exposed_and_generous():
    s = FrameSplitter()
    assert s.max_frame_length == DEFAULT_MAX_FRAME_LENGTH
    # Comfortably above OpenSSH's 256 KiB max-packet-length, so the guard never fires on a
    # legitimate server. It is a DoS bound, not a tuning knob.
    assert s.max_frame_length > 262144


# --- the zero-copy contract ------------------------------------------------------------


def test_frames_are_views_into_the_splitters_own_buffer_not_copies():
    s = FrameSplitter()
    (frame,) = s.feed(framed(b"\x02abc"))
    assert isinstance(frame, memoryview)
    assert bytes(frame) == b"\x02abc"
    # `.obj` is the object the view borrows from. If this were a copy it would be some
    # fresh bytes object instead, and the whole memoryview-end-to-end claim would be
    # decoration.
    assert frame.obj is s._buf  # noqa: SLF001


def test_using_a_frame_after_the_next_feed_raises_at_the_point_of_use():
    # The failure mode this prevents is silent: a retained frame would otherwise quietly
    # start pointing at unrelated later bytes. Releasing it means the mistake is reported
    # where it is made, rather than as a stalled stream one call later.
    s = FrameSplitter()
    (frame,) = s.feed(framed(b"\x02keepme"))
    assert bytes(frame) == b"\x02keepme"

    s.feed(framed(b"\x02next"))

    with pytest.raises(ValueError) as exc:
        bytes(frame)
    assert exc.value.args[0] == "operation forbidden on released memoryview object"


def test_the_idiomatic_loop_leaves_a_binding_and_still_works():
    # `for frame in ...` leaves `frame` bound after the loop. That is the most natural
    # spelling in the language, so it must not be a usage error -- this is the exact case
    # that made the splitter release issued frames instead of waiting for the caller to.
    s = FrameSplitter()
    for frame in s.feed(framed(b"\x02first")):
        assert bytes(frame) == b"\x02first"
    assert [bytes(f) for f in s.feed(framed(b"\x02second"))] == [b"\x02second"]


def test_a_slice_of_a_frame_kept_alive_is_reported_rather_than_corrupted():
    # Releasing what we issued cannot reach a view the caller derived from it. That case
    # still has to fail loudly rather than hand back recycled bytes.
    s = FrameSplitter()
    (frame,) = s.feed(framed(b"\x02" + bytes(_COMPACT_THRESHOLD)))
    derived = frame[1:]
    with pytest.raises(RuntimeError) as exc:
        s.feed(framed(b"\x02next"))
    assert exc.value.args[0] == (
        "a view derived from a previous frame is still alive, so the buffer cannot be "
        "reused; copy any frame data you need to keep beyond the next feed()"
    )
    derived.release()


def test_copying_a_frame_lets_it_outlive_the_next_feed():
    s = FrameSplitter()
    kept = bytes(s.feed(framed(b"\x02keep"))[0])
    assert [bytes(f) for f in s.feed(framed(b"\x02more"))] == [b"\x02more"]
    assert kept == b"\x02keep"


# --- properties ------------------------------------------------------------------------


@given(bodies=st.lists(st.binary(min_size=1, max_size=64), max_size=20))
def test_every_frame_comes_back_in_order_whatever_the_chunking(bodies: list[bytes]):
    s = FrameSplitter()
    wire = b"".join(framed(b) for b in bodies)
    out: list[bytes] = []
    for i in range(0, len(wire), 3):
        out.extend(bytes(f) for f in s.feed(wire[i : i + 3]))
    assert out == bodies
    assert s.buffered == 0


@given(
    bodies=st.lists(st.binary(min_size=1, max_size=32), min_size=1, max_size=10),
    split=st.integers(min_value=0, max_value=200),
)
def test_arbitrary_split_point_preserves_the_stream(bodies: list[bytes], split: int):
    s = FrameSplitter()
    wire = b"".join(framed(b) for b in bodies)
    point = min(split, len(wire))
    out = [bytes(f) for f in s.feed(wire[:point])]
    out.extend(bytes(f) for f in s.feed(wire[point:]))
    assert out == bodies


@given(data=st.binary(max_size=512))
def test_arbitrary_bytes_never_crash_the_splitter(data: bytes):
    # A file-transfer library parsing hostile server input must fail predictably or not at
    # all. ProtocolError is a decision; anything else is a bug.
    s = FrameSplitter(max_frame_length=4096)
    try:
        for frame in s.feed(data):
            bytes(frame)
    except ProtocolError:
        pass


@given(chunk=st.integers(min_value=1, max_value=8))
def test_streaming_reclaims_consumed_bytes(chunk: int):
    # Compaction is deferred for throughput -- doing it every feed makes a byte-at-a-time
    # stream quadratic -- but deferred must not mean never. Reaching into `_buf` is the
    # point: `buffered` reports unparsed bytes and would read 0 even if the consumed
    # prefix grew without limit.
    s = FrameSplitter()
    wire = b"".join(framed(bytes([2]) + bytes(n % 251)) for n in range(60))
    high_water = 0
    for i in range(0, len(wire), chunk):
        for frame in s.feed(wire[i : i + chunk]):
            bytes(frame)
        high_water = max(high_water, len(s._buf))  # noqa: SLF001
    assert s.buffered == 0

    # Reclaim is deferred to the *start* of the next feed, so a trailing consumed frame is
    # expected here -- what must not happen is the whole stream accumulating.
    assert high_water < _COMPACT_THRESHOLD + 512
    assert s.feed(b"") == []
    assert len(s._buf) == 0, "the deferred reclaim never ran"  # noqa: SLF001


def test_a_trailing_partial_frame_bounds_the_buffer_rather_than_leaking():
    # The awkward case for deferred compaction: a stream that always has an incomplete
    # frame at the tail never hits the "everything consumed" fast path, so growth is held
    # by the size threshold alone.
    s = FrameSplitter()
    body = bytes([2]) + bytes(200)  # 205 bytes on the wire, coprime-ish with the chunk
    stream = framed(body) * 400  # 82000 bytes, comfortably past the 64 KiB threshold
    for i in range(0, len(stream), 512):
        assert (i + 512) % 205 != 0, "chunking must not align with frame boundaries"
        for frame in s.feed(stream[i : i + 512]):
            bytes(frame)
    assert len(s._buf) < 128 * 1024, "buffer grew past the compaction threshold"  # noqa: SLF001


def test_a_rejected_stream_stays_rejected():
    # A length violation is not a bad packet to skip past -- it means the byte stream is
    # not filexfer, so resynchronising would be guessing. Every later feed must fail too.
    s = FrameSplitter(max_frame_length=64)
    with pytest.raises(ProtocolError):
        s.feed(b"\xff\xff\xff\xff")
    with pytest.raises(ProtocolError):
        s.feed(framed(b"\x02perfectly-valid"))

"""Wire primitives: round-trips, bounds, and what happens on a truncated frame."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import WireReader, WireWriter
from gantry_sftp.exceptions import ProtocolError

UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


# --- round trips -----------------------------------------------------------------------


@given(value=st.integers(min_value=0, max_value=0xFF))
def test_uint8_round_trip(value: int):
    w = WireWriter()
    w.write_uint8(value)
    assert WireReader(w.getvalue()).read_uint8() == value


@given(value=st.integers(min_value=0, max_value=UINT32_MAX))
def test_uint32_round_trip(value: int):
    w = WireWriter()
    w.write_uint32(value)
    assert WireReader(w.getvalue()).read_uint32() == value


@given(value=st.integers(min_value=0, max_value=UINT64_MAX))
def test_uint64_round_trip(value: int):
    w = WireWriter()
    w.write_uint64(value)
    assert WireReader(w.getvalue()).read_uint64() == value


@given(value=st.binary(max_size=512))
def test_string_round_trip(value: bytes):
    w = WireWriter()
    w.write_string(value)
    assert bytes(WireReader(w.getvalue()).read_string()) == value


# Field kind -> (write, read-and-normalise). Table-driven rather than a pair of match
# statements so the test stays under the complexity ceiling and so adding a field type
# means adding one row instead of editing two ladders that can drift apart.
FIELD_CODECS = {
    "u8": (WireWriter.write_uint8, WireReader.read_uint8),
    "u32": (WireWriter.write_uint32, WireReader.read_uint32),
    "u64": (WireWriter.write_uint64, WireReader.read_uint64),
    "str": (WireWriter.write_string, lambda r: bytes(r.read_string())),
}

field_values = st.one_of(
    st.tuples(st.just("u8"), st.integers(min_value=0, max_value=0xFF)),
    st.tuples(st.just("u32"), st.integers(min_value=0, max_value=UINT32_MAX)),
    st.tuples(st.just("u64"), st.integers(min_value=0, max_value=UINT64_MAX)),
    st.tuples(st.just("str"), st.binary(max_size=64)),
)


@given(values=st.lists(field_values, max_size=30))
def test_mixed_sequence_round_trips_in_order(values: list[tuple[str, int | bytes]]):
    w = WireWriter()
    for kind, value in values:
        FIELD_CODECS[kind][0](w, value)

    r = WireReader(w.getvalue())
    for kind, value in values:
        assert FIELD_CODECS[kind][1](r) == value
    assert r.at_end


# --- the running size, and the frame derived from it -------------------------------------


@given(values=st.lists(field_values, max_size=30))
def test_the_running_size_is_the_length_of_what_was_written(
    values: list[tuple[str, int | bytes]],
):
    # `frame()` takes its length prefix from this counter rather than from the joined bytes,
    # so a field that adds the wrong amount writes a legal frame with a wrong prefix -- which
    # is a desynchronised stream rather than a parse error, and shows up at the *next* packet.
    w = WireWriter()
    for kind, value in values:
        FIELD_CODECS[kind][0](w, value)
    assert len(w) == len(w.getvalue())


@given(values=st.lists(field_values, max_size=30))
def test_a_frame_is_its_body_behind_a_uint32_length(values: list[tuple[str, int | bytes]]):
    w = WireWriter()
    for kind, value in values:
        FIELD_CODECS[kind][0](w, value)
    body = w.getvalue()
    assert w.frame() == len(body).to_bytes(4, "big") + body


def test_an_empty_frame_is_a_zero_length_and_nothing_else():
    assert WireWriter().frame() == b"\x00\x00\x00\x00"
    assert WireWriter().getvalue() == b""
    assert len(WireWriter()) == 0


def test_write_bytes_appends_without_a_length_prefix():
    # Used by DATA and EXTENDED_REPLY, whose payload runs to the end of the frame and
    # therefore carries no length of its own.
    w = WireWriter()
    w.write_uint8(1)
    w.write_bytes(b"tail")
    assert w.getvalue() == b"\x01tail"
    assert len(w) == 5


# --- what "no copy on the way in" means, stated as behaviour -----------------------------


def test_the_writer_references_a_buffer_rather_than_copying_it():
    # This is the observable form of the memoryview-end-to-end rule on the send side, not a
    # feature: a payload handed to the writer is not copied until the frame is materialised,
    # which is what makes an upload cost one copy per byte instead of three (D-112). It is
    # pinned because the cheap "fix" for the aliasing it implies is to copy on the way in,
    # which would silently put the two extra passes back.
    buffer = bytearray(b"before")
    w = WireWriter()
    w.write_string(buffer)
    buffer[0:6] = b"after!"
    assert bytes(WireReader(w.getvalue()).read_string()) == b"after!"


def test_materialising_twice_gives_the_same_bytes():
    # The join is not destructive: `getvalue()` and `frame()` can each be called more than
    # once, and calling one does not consume what the other would return.
    w = WireWriter()
    w.write_uint32(7)
    w.write_string(b"path")
    assert w.getvalue() == w.getvalue()
    assert w.frame() == w.frame()
    assert w.frame()[4:] == w.getvalue()


@given(value=st.binary(max_size=512))
def test_a_memoryview_field_encodes_exactly_as_the_bytes_spelling(value: bytes):
    # A caller's buffer reaches the wire as a view; that must not change a single byte of
    # what the wire sees.
    as_bytes, as_view = WireWriter(), WireWriter()
    as_bytes.write_string(value)
    as_view.write_string(memoryview(value))
    assert as_view.frame() == as_bytes.frame()


# --- non-UTF-8 is normal, not exceptional ----------------------------------------------


@given(value=st.binary(max_size=128))
def test_strings_are_binary_and_never_decoded(value: bytes):
    # Server-supplied filenames are attacker-controlled bytes and are frequently not valid
    # UTF-8. A codec that decodes them here would raise on a legal directory listing.
    w = WireWriter()
    w.write_string(value)
    out = WireReader(w.getvalue()).read_string()
    assert isinstance(out, memoryview)
    assert bytes(out) == value


def test_a_lone_surrogate_and_invalid_utf8_survive_the_round_trip():
    hostile = b"\xed\xa0\x80\xff\xfe/etc/passwd\x00"
    w = WireWriter()
    w.write_string(hostile)
    assert bytes(WireReader(w.getvalue()).read_string()) == hostile


# --- ranges ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "value", "message"),
    [
        ("write_uint8", -1, "uint8 out of range: -1"),
        ("write_uint8", 256, "uint8 out of range: 256"),
        ("write_uint32", -1, "uint32 out of range: -1"),
        ("write_uint32", UINT32_MAX + 1, f"uint32 out of range: {UINT32_MAX + 1}"),
        ("write_uint64", -1, "uint64 out of range: -1"),
        ("write_uint64", UINT64_MAX + 1, f"uint64 out of range: {UINT64_MAX + 1}"),
    ],
)
def test_out_of_range_writes_are_refused(method: str, value: int, message: str):
    w = WireWriter()
    with pytest.raises(ValueError) as exc:
        getattr(w, method)(value)
    assert exc.value.args[0] == message


def test_boundary_values_are_accepted():
    w = WireWriter()
    w.write_uint8(0)
    w.write_uint8(0xFF)
    w.write_uint32(0)
    w.write_uint32(UINT32_MAX)
    w.write_uint64(0)
    w.write_uint64(UINT64_MAX)
    r = WireReader(w.getvalue())
    assert (r.read_uint8(), r.read_uint8()) == (0, 0xFF)
    assert (r.read_uint32(), r.read_uint32()) == (0, UINT32_MAX)
    assert (r.read_uint64(), r.read_uint64()) == (0, UINT64_MAX)
    assert r.at_end


# --- truncation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("buf", "reader_call", "message"),
    [
        (b"", "read_uint8", "truncated frame: need 1 more bytes at offset 0, 0 available"),
        (b"\x01\x02", "read_uint32", "truncated frame: need 4 more bytes at offset 0, 2 available"),
        (
            b"\x01\x02\x03\x04",
            "read_uint64",
            "truncated frame: need 8 more bytes at offset 0, 4 available",
        ),
    ],
)
def test_reading_past_the_end_raises_protocol_error(buf: bytes, reader_call: str, message: str):
    r = WireReader(buf)
    with pytest.raises(ProtocolError) as exc:
        getattr(r, reader_call)()
    assert exc.value.args[0] == message


def test_a_string_longer_than_its_frame_is_rejected_on_the_length():
    # The claim is checked before anything is reserved for it, so a server announcing a
    # four-gigabyte filename inside a twenty-byte frame costs us nothing.
    r = WireReader(b"\xff\xff\xff\xff" + b"short")
    with pytest.raises(ProtocolError) as exc:
        r.read_string()
    assert exc.value.args[0] == (
        "truncated frame: need 4294967295 more bytes at offset 4, 5 available"
    )


def test_errors_carry_the_packet_context_they_were_given():
    r = WireReader(b"\x00", packet_type=103, request_id=42)
    with pytest.raises(ProtocolError) as exc:
        r.read_uint32()
    assert exc.value.packet_type == 103
    assert exc.value.request_id == 42
    assert exc.value.raw_frame == b"\x00"
    assert "packet_type=103" in str(exc.value)
    assert "request_id=42" in str(exc.value)


def test_request_id_can_be_attached_after_it_is_read():
    r = WireReader(b"\x00\x00\x00\x07", packet_type=101)
    r.set_request_id(r.read_uint32())
    with pytest.raises(ProtocolError) as exc:
        r.read_uint32()
    assert exc.value.request_id == 7


def test_a_failed_read_does_not_advance_the_position():
    r = WireReader(b"\x01\x02")
    with pytest.raises(ProtocolError):
        r.read_uint32()
    assert r.position == 0
    assert r.read_uint8() == 1


# --- cursor ----------------------------------------------------------------------------


def test_position_remaining_and_at_end_track_consumption():
    r = WireReader(b"\x01\x02\x03\x04\x05")
    assert (r.position, r.remaining, r.at_end) == (0, 5, False)
    r.read_uint32()
    assert (r.position, r.remaining, r.at_end) == (4, 1, False)
    r.read_uint8()
    assert (r.position, r.remaining, r.at_end) == (5, 0, True)


def test_read_remaining_consumes_the_rest_without_copying():
    r = WireReader(b"\x01tail-bytes")
    assert r.read_uint8() == 1
    rest = r.read_remaining()
    assert isinstance(rest, memoryview)
    assert bytes(rest) == b"tail-bytes"
    assert r.at_end


def test_read_remaining_on_an_exhausted_reader_is_empty_not_an_error():
    r = WireReader(b"\x01")
    r.read_uint8()
    assert bytes(r.read_remaining()) == b""


def test_read_bytes_takes_exactly_n_as_a_view_without_copying():
    # `read_bytes` has no caller inside the library yet -- the fixed-width payloads that
    # want it are the `check-file*@openssh.com` digests -- but it is a method on a public
    # class, and an untested one is a promise nobody has checked.
    r = WireReader(b"\x01\xde\xad\xbe\xeftail")
    assert r.read_uint8() == 1
    chunk = r.read_bytes(4)
    assert isinstance(chunk, memoryview)
    assert bytes(chunk) == b"\xde\xad\xbe\xef"
    assert (r.position, r.remaining) == (5, 4)


def test_read_bytes_past_the_end_is_a_protocol_error_not_a_short_read():
    # A short read that returns fewer bytes than asked for is how a truncated frame becomes
    # silently wrong data one layer up. The bound is checked before anything is handed back.
    r = WireReader(b"\x00\x01\x02")
    with pytest.raises(ProtocolError) as exc:
        r.read_bytes(4)
    assert exc.value.args[0] == "truncated frame: need 4 more bytes at offset 0, 3 available"
    assert r.position == 0, "a refused read must not consume anything"


def test_reader_accepts_a_memoryview_without_rewrapping_it():
    mv = memoryview(b"\x00\x00\x00\x09")
    assert WireReader(mv).read_uint32() == 9


@given(data=st.binary(max_size=256))
def test_arbitrary_bytes_decode_or_raise_protocol_error_but_never_crash(data: bytes):
    r = WireReader(data)
    try:
        while not r.at_end:
            r.read_string()
    except ProtocolError:
        pass

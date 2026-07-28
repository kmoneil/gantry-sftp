"""The ATTRS structure: paired bits, field order, and unknown flags."""

from __future__ import annotations

import contextlib
import datetime as dt

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import (
    MAX_V3_TIMESTAMP,
    AttrFlag,
    Attrs,
    Owner,
    Times,
    WireReader,
    WireWriter,
    decode_attrs,
    encode_attrs,
)
from gantry_sftp.exceptions import ProtocolError


def roundtrip(attrs: Attrs) -> Attrs:
    w = WireWriter()
    encode_attrs(w, attrs)
    return decode_attrs(WireReader(w.getvalue()))


def encoded(attrs: Attrs) -> bytes:
    w = WireWriter()
    encode_attrs(w, attrs)
    return w.getvalue()


# --- the paired bits --------------------------------------------------------------------


def test_uid_and_gid_cannot_be_separated():
    # There is no flag bit meaning "uid but not gid", so the type does not offer one. This
    # is the illegal state being unrepresentable rather than validated -- there is no
    # ValueError to test for, because there is no way to ask for it.
    assert not hasattr(Attrs(), "uid")
    assert not hasattr(Attrs(), "gid")
    attrs = Attrs(owner=Owner(uid=1000, gid=100))
    assert attrs.owner is not None
    assert (attrs.owner.uid, attrs.owner.gid) == (1000, 100)


def test_atime_and_mtime_cannot_be_separated():
    assert not hasattr(Attrs(), "atime")
    assert not hasattr(Attrs(), "mtime")
    attrs = Attrs(times=Times(atime=1, mtime=2))
    assert attrs.times is not None
    assert (attrs.times.atime, attrs.times.mtime) == (1, 2)


def test_uidgid_is_one_flag_bit_governing_two_fields():
    wire = encoded(Attrs(owner=Owner(0x01020304, 0x05060708)))
    assert wire == (
        b"\x00\x00\x00\x02"  # flags: UIDGID only
        b"\x01\x02\x03\x04"  # uid
        b"\x05\x06\x07\x08"  # gid
    )


def test_acmodtime_is_one_flag_bit_governing_two_fields():
    wire = encoded(Attrs(times=Times(0x01020304, 0x05060708)))
    assert wire == b"\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08"


# --- flags derivation -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        (Attrs(), AttrFlag(0)),
        (Attrs(size=0), AttrFlag.SIZE),
        (Attrs(owner=Owner(0, 0)), AttrFlag.UIDGID),
        (Attrs(permissions=0), AttrFlag.PERMISSIONS),
        (Attrs(times=Times(0, 0)), AttrFlag.ACMODTIME),
        (Attrs(extended=((b"a", b"b"),)), AttrFlag.EXTENDED),
        (
            Attrs(size=1, owner=Owner(0, 0), permissions=0o644, times=Times(1, 2)),
            AttrFlag.SIZE | AttrFlag.UIDGID | AttrFlag.PERMISSIONS | AttrFlag.ACMODTIME,
        ),
    ],
)
def test_flags_are_derived_from_which_fields_are_set(attrs: Attrs, expected: AttrFlag):
    assert attrs.flags == expected


def test_zero_is_a_value_and_absent_is_not_zero():
    # A server that does not report a size is saying "I did not tell you", which is not the
    # same as "the file is empty". Both must be expressible and must encode differently.
    assert Attrs(size=0).flags == AttrFlag.SIZE
    assert Attrs(size=None).flags == AttrFlag(0)
    assert encoded(Attrs(size=0)) != encoded(Attrs(size=None))
    assert roundtrip(Attrs(size=0)).size == 0
    assert roundtrip(Attrs(size=None)).size is None


def test_empty_extended_does_not_set_the_extended_bit():
    assert Attrs(extended=()).flags == AttrFlag(0)
    assert encoded(Attrs(extended=())) == b"\x00\x00\x00\x00"


def test_empty_attrs_is_four_zero_bytes():
    assert encoded(Attrs()) == b"\x00\x00\x00\x00"


# --- field order ------------------------------------------------------------------------


def test_fields_appear_in_wire_order_not_declaration_convenience():
    # size, uid, gid, permissions, atime, mtime -- getting this wrong desynchronises
    # everything after the ATTRS in the containing packet, which is the failure mode with
    # no local symptom.
    wire = encoded(
        Attrs(
            size=0xAAAAAAAAAAAAAAAA,
            owner=Owner(0xBBBBBBBB, 0xCCCCCCCC),
            permissions=0xDDDDDDDD,
            times=Times(0xEEEEEEEE, 0xFFFFFFFF),
        )
    )
    assert wire == (
        b"\x00\x00\x00\x0f"
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        b"\xbb\xbb\xbb\xbb"
        b"\xcc\xcc\xcc\xcc"
        b"\xdd\xdd\xdd\xdd"
        b"\xee\xee\xee\xee"
        b"\xff\xff\xff\xff"
    )


def test_decoding_consumes_exactly_the_bytes_the_flags_describe():
    w = WireWriter()
    encode_attrs(w, Attrs(size=7, permissions=0o600))
    w.write_uint32(0xDEADBEEF)  # a field belonging to the enclosing packet

    r = WireReader(w.getvalue())
    attrs = decode_attrs(r)
    assert attrs == Attrs(size=7, permissions=0o600)
    assert r.read_uint32() == 0xDEADBEEF
    assert r.at_end


# --- extended pairs ---------------------------------------------------------------------


def test_extended_pairs_round_trip_in_order():
    attrs = Attrs(extended=((b"x@example.com", b"1"), (b"y@example.com", b"")))
    assert roundtrip(attrs) == attrs


def test_extended_count_is_the_number_of_pairs():
    wire = encoded(Attrs(extended=((b"a", b"b"), (b"c", b"d"))))
    assert wire.startswith(b"\x80\x00\x00\x00\x00\x00\x00\x02")


def test_a_hostile_extended_count_is_bounded_by_the_frame():
    # A count of four billion must fail on the first read past the end, not spin.
    wire = b"\x80\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x01a"
    with pytest.raises(ProtocolError):
        decode_attrs(WireReader(wire))


# --- unknown flags ----------------------------------------------------------------------


def test_an_undefined_flag_bit_is_rejected_rather_than_ignored():
    # An unknown bit announces a field of unknown width. Skipping it is impossible and
    # ignoring it desynchronises everything after -- silently, which is worse than failing.
    with pytest.raises(ProtocolError) as exc:
        decode_attrs(WireReader(b"\x00\x00\x00\x10"))
    assert exc.value.args[0] == (
        "ATTRS sets undefined flag bits 0x00000010; filexfer v3 defines only 0x8000000f, "
        "and an unknown bit means a field of unknown width"
    )


def test_the_extended_high_bit_is_not_treated_as_unknown():
    # 0x80000000 is the one legitimately-set high bit; a signed read or a careless mask
    # turns it into an error.
    attrs = Attrs(extended=((b"k", b"v"),))
    assert roundtrip(attrs) == attrs


@pytest.mark.parametrize("bit", [0x10, 0x20, 0x100, 0x40000000])
def test_each_undefined_bit_is_rejected(bit: int):
    with pytest.raises(ProtocolError):
        decode_attrs(WireReader(bit.to_bytes(4, "big")))


# --- ranges -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("times", "field"),
    [
        (Times(atime=2**32, mtime=0), "atime"),
        (Times(atime=0, mtime=2**32), "mtime"),
        (Times(atime=0, mtime=-1), "mtime"),
    ],
    ids=["atime-too-large", "mtime-too-large", "mtime-negative"],
)
def test_a_timestamp_outside_the_v3_field_is_refused_rather_than_truncated(times, field):
    # Refusing beats wrapping, and the dates that reach this are deliberate rather than
    # accidental: retention and legal-hold systems set mtimes decades out, so a 2039 hold
    # that silently became 1970 would read as expired instead of protected.
    #
    # The message names which field, the span, and both ceilings -- 2106 unsigned and the
    # 2038 a signed server stops at. "uint32 out of range: 4294967296" named the type and
    # not the problem, and the problem here has a date attached to it.
    with pytest.raises(ValueError) as exc:
        encoded(Attrs(times=times))
    assert exc.value.args[0] == (
        f"{field} {getattr(times, field)} does not fit filexfer v3's uint32 seconds field, "
        f"which spans 0 to 4294967295 (1970-01-01T00:00:00Z to 2106-02-07T06:28:15Z); a "
        f"server reading it as signed stops even earlier, at 2038-01-19T03:14:07Z"
    )


def test_the_last_representable_timestamp_is_accepted():
    # The other side of the boundary, so the refusal above is a ceiling rather than pessimism.
    attrs = Attrs(times=Times(atime=MAX_V3_TIMESTAMP, mtime=MAX_V3_TIMESTAMP))
    assert roundtrip(attrs) == attrs


def test_the_documented_ceiling_is_the_instant_the_docstring_names():
    # MAX_V3_TIMESTAMP is quoted as a date in three docstrings and one error message. This is
    # what stops those dates drifting from the number they describe.
    assert MAX_V3_TIMESTAMP == 0xFFFFFFFF
    assert dt.datetime.fromtimestamp(MAX_V3_TIMESTAMP, dt.UTC).isoformat() == (
        "2106-02-07T06:28:15+00:00"
    )
    # And the earlier ceiling a signed server stops at, which is the one to design against.
    assert dt.datetime.fromtimestamp(2**31 - 1, dt.UTC).isoformat() == "2038-01-19T03:14:07+00:00"


def test_a_size_beyond_uint64_is_refused():
    with pytest.raises(ValueError):
        encoded(Attrs(size=2**64))


# --- properties -------------------------------------------------------------------------

u32 = st.integers(min_value=0, max_value=0xFFFFFFFF)
u64 = st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF)

attrs_strategy = st.builds(
    Attrs,
    size=st.one_of(st.none(), u64),
    owner=st.one_of(st.none(), st.builds(Owner, u32, u32)),
    permissions=st.one_of(st.none(), u32),
    times=st.one_of(st.none(), st.builds(Times, u32, u32)),
    extended=st.lists(st.tuples(st.binary(max_size=8), st.binary(max_size=8)), max_size=3).map(
        tuple
    ),
)


@given(attrs=attrs_strategy)
def test_attrs_round_trip(attrs: Attrs):
    assert roundtrip(attrs) == attrs


@given(attrs=attrs_strategy)
def test_the_encoded_flags_word_matches_the_flags_property(attrs: Attrs):
    assert int.from_bytes(encoded(attrs)[:4], "big") == attrs.flags


@given(data=st.binary(max_size=64))
def test_arbitrary_bytes_decode_or_raise_protocol_error(data: bytes):
    with contextlib.suppress(ProtocolError):
        decode_attrs(WireReader(data))

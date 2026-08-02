"""Server limits and derived request sizes -- the two traps from _plans/deferred.md.

D-1: a reported limit of 0 means "no limit", not zero.
D-2: the payload ceiling sits below the packet ceiling, so a round 256 KiB is never
achievable and would be clamped on every request, forever.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import Read, WireWriter, Write, encode
from gantry_sftp.exceptions import ProtocolError
from gantry_sftp.session import (
    DEFAULT_MAX_PACKET_LENGTH,
    PREFERRED_READ_LENGTH,
    ServerLimits,
    TransferSizes,
    negotiate_transfer_sizes,
    read_request_overhead,
    write_request_overhead,
)

OPENSSH_HANDLE_LENGTH = 4


def limits_reply(packet: int, read: int, write: int, handles: int) -> bytes:
    w = WireWriter()
    for value in (packet, read, write, handles):
        w.write_uint64(value)
    return w.getvalue()


# --- D-1: zero means unlimited ------------------------------------------------------------


def test_a_zero_limit_becomes_none_not_zero():
    # The trap, disarmed at the boundary: after this, `min(size, limit)` cannot silently
    # yield 0, because the field is not an int.
    limits = ServerLimits.from_extended_reply(limits_reply(0, 0, 0, 0))
    assert limits.max_packet_length is None
    assert limits.max_read_length is None
    assert limits.max_write_length is None
    assert limits.max_open_handles is None


def test_a_server_reporting_zero_read_length_does_not_produce_a_zero_length_read():
    # The failure this prevents makes no progress and reads as a hang, not a crash -- which
    # is why it would survive a long time in production before anyone diagnosed it.
    limits = ServerLimits.from_extended_reply(limits_reply(0, 0, 0, 0))
    sizes = negotiate_transfer_sizes(limits, handle_length=OPENSSH_HANDLE_LENGTH)
    assert sizes.read_length > 0
    assert sizes.write_length > 0


@pytest.mark.parametrize("field", ["max_packet_length", "max_read_length", "max_write_length"])
def test_each_field_independently_treats_zero_as_unlimited(field: str):
    values = {"packet": 262144, "read": 100, "write": 100, "handles": 10}
    key = field.removeprefix("max_").removesuffix("_length")
    values[key] = 0
    limits = ServerLimits.from_extended_reply(
        limits_reply(values["packet"], values["read"], values["write"], values["handles"])
    )
    assert getattr(limits, field) is None


def test_a_nonzero_limit_is_kept_as_reported():
    limits = ServerLimits.from_extended_reply(limits_reply(262144, 261120, 261120, 1048571))
    assert limits.max_packet_length == 262144
    assert limits.max_read_length == 261120
    assert limits.max_write_length == 261120
    assert limits.max_open_handles == 1048571


def test_transfer_sizes_refuse_to_exist_at_zero():
    # Belt and braces: even constructed directly, a size that makes no progress is refused.
    with pytest.raises(ValueError) as exc:
        TransferSizes(read_length=0, write_length=1)
    assert exc.value.args[0] == "read_length must be at least 1, got 0"

    with pytest.raises(ValueError) as exc:
        TransferSizes(read_length=1, write_length=0)
    assert exc.value.args[0] == "write_length must be at least 1, got 0"


# --- D-2: framing headroom ----------------------------------------------------------------


def test_the_default_read_preference_is_not_the_round_number():
    # 262144 is exactly wrong: 1024 above what a real OpenSSH server permits as a payload,
    # so it would be clamped on every single request and the knob would never mean what it
    # says.
    assert PREFERRED_READ_LENGTH == 261120
    assert PREFERRED_READ_LENGTH < DEFAULT_MAX_PACKET_LENGTH


def test_a_read_request_always_fits_inside_the_packet_ceiling():
    limits = ServerLimits.from_extended_reply(limits_reply(262144, 261120, 261120, 1048571))
    sizes = negotiate_transfer_sizes(limits, handle_length=OPENSSH_HANDLE_LENGTH)
    encoded = read_request_overhead(OPENSSH_HANDLE_LENGTH) + sizes.read_length
    assert encoded <= limits.effective_max_packet_length


def test_a_write_request_and_its_payload_fit_inside_the_packet_ceiling():
    limits = ServerLimits.from_extended_reply(limits_reply(262144, 261120, 261120, 1048571))
    sizes = negotiate_transfer_sizes(limits, handle_length=OPENSSH_HANDLE_LENGTH)
    encoded = write_request_overhead(OPENSSH_HANDLE_LENGTH) + sizes.write_length
    assert encoded <= limits.effective_max_packet_length


def test_a_longer_handle_eats_into_the_payload_budget():
    # OpenSSH's handles are four bytes. Nothing says another server's are, and the handle is
    # part of every request header -- so it is part of the budget.
    limits = ServerLimits(max_packet_length=4096)
    short = negotiate_transfer_sizes(limits, handle_length=4, preferred_read=1 << 30)
    long = negotiate_transfer_sizes(limits, handle_length=256, preferred_read=1 << 30)
    assert long.read_length == short.read_length - 252


def test_the_server_payload_limit_wins_when_it_is_the_smallest():
    limits = ServerLimits(max_packet_length=262144, max_read_length=32768)
    sizes = negotiate_transfer_sizes(limits, handle_length=OPENSSH_HANDLE_LENGTH)
    assert sizes.read_length == 32768


def test_our_preference_wins_when_it_is_the_smallest():
    limits = ServerLimits(max_packet_length=262144, max_read_length=261120)
    sizes = negotiate_transfer_sizes(limits, handle_length=4, preferred_read=8192)
    assert sizes.read_length == 8192


def test_the_packet_ceiling_wins_when_it_is_the_smallest():
    # A server advertising a generous payload limit but a small packet limit is
    # self-contradictory; the packet limit is the one that governs what fits on the wire.
    limits = ServerLimits(max_packet_length=4096, max_read_length=1 << 20)
    sizes = negotiate_transfer_sizes(limits, handle_length=4, preferred_read=1 << 20)
    assert sizes.read_length == 4096 - read_request_overhead(4)


def test_a_server_advertising_nothing_still_gets_a_workable_size():
    # The normal case for enterprise endpoints, which advertise no extensions at all.
    sizes = negotiate_transfer_sizes(ServerLimits.unknown(), handle_length=4)
    assert sizes.read_length == PREFERRED_READ_LENGTH
    assert read_request_overhead(4) + sizes.read_length <= DEFAULT_MAX_PACKET_LENGTH


def test_unknown_is_distinguishable_from_unlimited_even_though_they_compute_the_same():
    # Same arithmetic, different claim. The quirks layer will care which one it is.
    assert ServerLimits.unknown().max_read_length is None
    assert ServerLimits.from_extended_reply(limits_reply(0, 0, 0, 0)).max_read_length is None
    assert ServerLimits.unknown() == ServerLimits.from_extended_reply(limits_reply(0, 0, 0, 0))


# --- pathological servers -----------------------------------------------------------------


def test_a_tiny_packet_ceiling_still_yields_a_size_that_makes_progress():
    # A handle longer than the whole packet budget drives the arithmetic negative. Refusing
    # to make progress is worse than sending a request the server may reject -- a rejection
    # at least says something.
    sizes = negotiate_transfer_sizes(ServerLimits(max_packet_length=8), handle_length=64)
    assert sizes.read_length >= 1
    assert sizes.write_length >= 1


def test_a_malformed_limits_reply_is_a_protocol_error():
    with pytest.raises(ProtocolError):
        ServerLimits.from_extended_reply(b"\x00\x00\x00\x01")


def test_a_limits_reply_with_trailing_bytes_still_decodes_the_four_fields():
    # Being strict about trailing bytes is decode()'s job at the frame level; here we read
    # the four fields the extension defines and leave forward-compatibility room.
    limits = ServerLimits.from_extended_reply(limits_reply(262144, 261120, 261120, 10) + b"junk")
    assert limits.max_packet_length == 262144


# --- properties ---------------------------------------------------------------------------


@given(
    packet=st.integers(min_value=0, max_value=1 << 22),
    read=st.integers(min_value=0, max_value=1 << 22),
    write=st.integers(min_value=0, max_value=1 << 22),
    handle=st.integers(min_value=0, max_value=512),
)
def test_derived_sizes_are_always_usable(packet: int, read: int, write: int, handle: int):
    limits = ServerLimits.from_extended_reply(limits_reply(packet, read, write, 0))
    sizes = negotiate_transfer_sizes(limits, handle_length=handle)
    assert sizes.read_length >= 1
    assert sizes.write_length >= 1


@given(
    packet=st.integers(min_value=1024, max_value=1 << 22),
    read=st.integers(min_value=1, max_value=1 << 22),
    handle=st.integers(min_value=0, max_value=64),
)
def test_a_read_never_exceeds_what_the_server_said_it_would_accept(
    packet: int, read: int, handle: int
):
    limits = ServerLimits.from_extended_reply(limits_reply(packet, read, read, 0))
    sizes = negotiate_transfer_sizes(limits, handle_length=handle)
    assert sizes.read_length <= read
    # And the whole request still fits, unless the ceiling was too small for any payload at
    # all -- in which case the minimum-progress floor is what we deliberately chose.
    encoded = read_request_overhead(handle) + sizes.read_length
    assert encoded <= packet or sizes.read_length == 1


# --- the overhead, measured rather than restated ------------------------------------------------
#
# D-105's nineteenth slice. Every test above computes the encoded size *with the same function
# it is testing*, so the two sides move together: `1 + 4 + (4 + handle) + 8 + 4` could become any
# other sum and every assertion here would still hold. That is the golden-frame argument applied
# to arithmetic -- an encoder checked against itself is checked against nothing -- and the fix is
# an independent oracle, which is the codec that has to put the bytes on the wire.


def test_the_read_overhead_is_what_a_real_empty_read_frame_measures():
    """The oracle is the encoder, because it is the thing the server actually counts.

    A zero-length READ *is* its own overhead, so encoding one and measuring it settles the sum
    without restating it. The four-byte length prefix comes off because it is framing: OpenSSH
    counts `max-packet-length` against the body, which is why its `max-read-length` sits 1024
    below its `max-packet-length` rather than at it.
    """
    handle = b"\x00" * OPENSSH_HANDLE_LENGTH
    frame = encode(Read(1, handle, offset=0, length=0))
    assert len(frame) - 4 == read_request_overhead(OPENSSH_HANDLE_LENGTH)


def test_the_write_overhead_is_what_a_real_empty_write_frame_measures():
    """The same oracle for the other direction, whose payload is in the *request*.

    A WRITE's data string carries its own four-byte length prefix inside the body, which is the
    term that makes this sum equal the read's by coincidence rather than by construction -- so
    the two are measured separately.
    """
    handle = b"\x00" * OPENSSH_HANDLE_LENGTH
    frame = encode(Write(1, handle, offset=0, data=b""))
    assert len(frame) - 4 == write_request_overhead(OPENSSH_HANDLE_LENGTH)


@pytest.mark.parametrize("handle_length", [0, 4, 64, 255], ids=["empty", "openssh", "long", "255"])
def test_the_overhead_tracks_the_handle_at_every_length(handle_length: int):
    """The handle is the only variable term, and it is the one another server can change.

    OpenSSH's handles are four bytes; nothing says another server's are, and a formula that
    dropped the handle entirely would still pass every fixed-handle test above.
    """
    handle = b"\x00" * handle_length
    assert len(encode(Read(1, handle, offset=0, length=0))) - 4 == read_request_overhead(
        handle_length
    )
    assert len(encode(Write(1, handle, offset=0, data=b""))) - 4 == write_request_overhead(
        handle_length
    )


def test_a_negotiated_request_fills_the_packet_ceiling_without_exceeding_it():
    """The property the arithmetic exists for, asserted on the bytes rather than on the sum.

    OpenSSH's real numbers, and a real frame at the negotiated size: the encoded body must fit
    `max-packet-length`, because the consequence of exceeding it is not an error but a clamp --
    on every request, forever, which is the failure this whole module is here to avoid.
    """
    limits = ServerLimits.from_extended_reply(limits_reply(262144, 261120, 261120, 1048571))
    sizes = negotiate_transfer_sizes(limits, handle_length=OPENSSH_HANDLE_LENGTH)
    handle = b"\x00" * OPENSSH_HANDLE_LENGTH

    read_frame = encode(Read(1, handle, offset=0, length=sizes.read_length))
    write_frame = encode(Write(2, handle, offset=0, data=b"\x00" * sizes.write_length))

    assert len(read_frame) - 4 <= limits.effective_max_packet_length
    assert len(write_frame) - 4 <= limits.effective_max_packet_length


def test_the_packet_ceiling_wins_for_a_write_as_well_as_a_read():
    """The read half of this is asserted above; the write budget is a separate subtraction.

    Spelled as a literal rather than as `4096 - write_request_overhead(4)`, because computing
    the expectation from the function under test is what let every term of it drift. The
    overhead is 25 bytes with a four-byte handle: a type byte, a request id, a string handle
    (four of length and four of handle), a `uint64` offset and a `uint32` length.
    """
    limits = ServerLimits(max_packet_length=4096)
    sizes = negotiate_transfer_sizes(limits, handle_length=4, preferred_write=1 << 30)
    assert sizes.write_length == 4096 - 25

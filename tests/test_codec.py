"""The client state machine: handshake, id allocation, correlation, and failure."""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    Close,
    Codec,
    CodecState,
    Completed,
    Data,
    Handle,
    Init,
    Name,
    NameEntry,
    Negotiated,
    Open,
    OpenFlag,
    PacketType,
    Read,
    RealPath,
    Stat,
    Status,
    StatusCode,
    Version,
    _codec,
    encode,
)
from gantry_sftp.codec._codec import _MAX_REQUEST_ID
from gantry_sftp.exceptions import ProtocolError, SFTPError, StateError


def negotiated_codec(extensions: tuple[tuple[bytes, bytes], ...] = ()) -> Codec:
    codec = Codec()
    codec.initiate()
    codec.receive(encode(Version(3, extensions)))
    return codec


# --- handshake --------------------------------------------------------------------------


def test_a_fresh_codec_is_new_and_knows_nothing():
    codec = Codec()
    assert codec.state is CodecState.NEW
    assert codec.server_version is None
    assert codec.extensions == {}
    assert codec.outstanding == 0


def test_initiate_emits_init_and_awaits_version():
    codec = Codec()
    assert codec.initiate() == encode(Init(version=3))
    assert codec.state is CodecState.AWAITING_VERSION


def test_initiate_can_request_a_non_default_version():
    assert Codec().initiate(version=6) == encode(Init(version=6))


def test_initiate_twice_is_refused():
    codec = Codec()
    codec.initiate()
    with pytest.raises(StateError) as exc:
        codec.initiate()
    assert exc.value.args[0] == "cannot send INIT while AWAITING_VERSION"


def test_version_negotiates_and_reports_extensions():
    codec = Codec()
    codec.initiate()
    (event,) = codec.receive(encode(Version(3, ((b"copy-data", b"1"), (b"statvfs@x", b"2")))))
    assert event == Negotiated(version=3, extensions=((b"copy-data", b"1"), (b"statvfs@x", b"2")))
    assert codec.state is CodecState.READY
    assert codec.server_version == 3
    assert dict(codec.extensions) == {b"copy-data": b"1", b"statvfs@x": b"2"}


def test_a_server_advertising_nothing_is_normal_not_an_error():
    # Most enterprise endpoints advertise no extensions at all.
    codec = negotiated_codec()
    assert codec.state is CodecState.READY
    assert codec.extensions == {}


def test_extensions_are_read_only():
    codec = negotiated_codec(((b"fsync@openssh.com", b"1"),))
    with pytest.raises(TypeError):
        codec.extensions[b"x"] = b"1"  # type: ignore[index]


def test_a_second_version_is_refused():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Version(3)))
    assert exc.value.args[0] == "server sent VERSION while READY; the handshake happens once"


def test_a_version_below_ours_is_refused():
    # The *legal* case, and the one that went unnoticed: draft 4 has the server answer with the
    # lower of the two versions, so a v2-only server answering 2 is behaving correctly. Nothing
    # checked this before 0.12, and the codec went to READY and spoke v3 at it.
    codec = Codec()
    codec.initiate()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Version(2)))
    assert exc.value.args[0] == (
        "server negotiated filexfer v2 and this client implements only v3; "
        "draft-ietf-secsh-filexfer-02 4 has the server answer with the lower of its own "
        "version and ours, so this server is behaving correctly and simply cannot speak v3 -- "
        "10.1 lists READLINK, SYMLINK and EXTENDED as v3 additions, and nothing tells a v3 "
        "client which of its requests this server knows"
    )


def test_a_version_above_ours_is_refused():
    # The violation. v4 ATTRS puts a `byte type` before every optional field, so a v3 decoder
    # reads the type byte as the first byte of the size and every field after it is shifted.
    codec = Codec()
    codec.initiate()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Version(4)))
    assert exc.value.args[0] == (
        "server negotiated filexfer v4, above the v3 this client implements; "
        "draft-ietf-secsh-filexfer-02 4 requires the answer to be the lower of the two "
        "versions, so a version above ours is a protocol violation -- and v4 ATTRS puts a "
        "'byte type' ahead of every optional field (draft-04 5), which a v3 decoder reads as "
        "the leading byte of whatever comes next"
    )


@pytest.mark.parametrize("version", [0, 1, 2, 4, 6, 0xFFFFFFFF])
def test_a_refused_version_is_terminal(version: int):
    # Not merely reported: the stream after it is not v3, so reading on would mean guessing at
    # a layout. The latch is what stops the next `receive` carrying on.
    codec = Codec()
    codec.initiate()
    with pytest.raises(ProtocolError):
        codec.receive(encode(Version(version)))

    assert codec.state is CodecState.FAILED
    assert codec.server_version is None
    assert codec.extensions == {}
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Version(3)))
    assert exc.value.args[0] == "codec is in a failed state; the connection is not recoverable"


def test_a_refused_version_does_not_adopt_the_extensions_it_advertised():
    # The advertisement arrives on the same frame as the version. Recording it would leave
    # `supports()` answering about a server we have just refused to speak to.
    codec = Codec()
    codec.initiate()
    with pytest.raises(ProtocolError):
        codec.receive(encode(Version(4, ((b"posix-rename@openssh.com", b"1"),))))
    assert codec.extensions == {}


def test_a_response_before_version_is_refused():
    codec = Codec()
    codec.initiate()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Status(1, StatusCode.OK)))
    assert exc.value.args[0] == (
        "server sent Status while AWAITING_VERSION; nothing is answerable before VERSION"
    )


def test_sending_a_request_before_negotiation_is_refused():
    codec = Codec()
    codec.initiate()
    with pytest.raises(StateError) as exc:
        codec.send(Stat(1, b"/tmp"))
    assert exc.value.args[0] == "cannot send Stat while AWAITING_VERSION"


def test_sending_a_request_before_initiate_is_refused():
    with pytest.raises(StateError) as exc:
        Codec().send(Stat(1, b"/tmp"))
    assert exc.value.args[0] == "cannot send Stat while NEW"


def test_a_premature_send_leaves_the_connection_usable():
    # A caller mistake never reached the wire, so the connection is fine. Failing it would
    # turn a fixable programming error into a dropped session.
    codec = Codec()
    codec.initiate()
    with pytest.raises(StateError):
        codec.send(Stat(1, b"/tmp"))

    assert codec.state is CodecState.AWAITING_VERSION
    codec.receive(encode(Version(3)))
    codec.send(Stat(1, b"/tmp"))
    (event,) = codec.receive(encode(AttrsReply(1, Attrs(size=5))))
    assert event.response.attrs.size == 5


def test_a_state_error_is_not_a_protocol_error():
    # The distinction is the whole point: one means fix the call, the other means the
    # connection is finished. Catching ProtocolError must not swallow a caller mistake.
    assert not issubclass(StateError, ProtocolError)
    assert not issubclass(ProtocolError, StateError)
    assert issubclass(StateError, SFTPError)
    assert issubclass(ProtocolError, SFTPError)


# --- what a client may not receive ------------------------------------------------------


def test_a_server_sending_init_is_refused():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Init()))
    assert exc.value.args[0] == "server sent INIT; INIT is a client-to-server packet"


def test_a_server_sending_a_request_is_refused():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Open(1, b"/etc/passwd", OpenFlag.READ)))
    assert exc.value.args[0] == (
        "server sent Open, which is a request; a client never receives requests"
    )


# --- id allocation ----------------------------------------------------------------------


def test_allocation_is_deterministic_from_one():
    codec = Codec()
    assert [codec.allocate_request_id() for _ in range(5)] == [1, 2, 3, 4, 5]


def test_two_fresh_codecs_allocate_identically():
    # Deterministic means reproducible: a recorded session replays.
    assert [Codec().allocate_request_id() for _ in range(3)] == [1, 1, 1]


def test_zero_is_never_issued():
    codec = Codec()
    codec._next_id = _MAX_REQUEST_ID  # noqa: SLF001
    assert codec.allocate_request_id() == _MAX_REQUEST_ID
    assert codec.allocate_request_id() == 1


def test_ids_wrap_at_uint32():
    codec = Codec()
    codec._next_id = _MAX_REQUEST_ID - 1  # noqa: SLF001
    assert [codec.allocate_request_id() for _ in range(4)] == [
        _MAX_REQUEST_ID - 1,
        _MAX_REQUEST_ID,
        1,
        2,
    ]


def test_wrapping_skips_ids_still_in_flight():
    # Reusing an in-flight id correlates a reply to the wrong request, which looks exactly
    # like data corruption from every layer above. The wrap has to step over them.
    codec = negotiated_codec()
    codec.send(Stat(1, b"/a"))
    codec.send(Stat(2, b"/b"))
    codec._next_id = _MAX_REQUEST_ID  # noqa: SLF001

    assert codec.allocate_request_id() == _MAX_REQUEST_ID
    assert codec.allocate_request_id() == 3, "wrap handed back an id already in flight"


def test_exhaustion_is_refused_rather_than_spun_on(monkeypatch: pytest.MonkeyPatch):
    # Four billion concurrent requests is not reachable in a test, and the guard is not
    # decoration: it is the only thing standing between a full table and the wrap loop
    # below spinning forever. Shrinking the id space is the only way to make the exhausted
    # case a fact rather than a comment, so the constants are patched before the codec is
    # built -- `__init__` reads `_MIN_REQUEST_ID` to seed the counter.
    monkeypatch.setattr(_codec, "_MIN_REQUEST_ID", 1)
    monkeypatch.setattr(_codec, "_MAX_REQUEST_ID", 4)
    codec = negotiated_codec()

    for _ in range(3):
        codec.send(Stat(codec.allocate_request_id(), b"/a"))

    # Three of the four in flight is not exhaustion. The comparison is `>`, not `>=`: the
    # last free id must still be handed out, or the usable space is one short of the space.
    last = codec.allocate_request_id()
    assert last == 4
    codec.send(Stat(last, b"/a"))

    with pytest.raises(StateError) as exc:
        codec.allocate_request_id()
    assert exc.value.args[0] == "every request id is in flight; cannot allocate another"
    assert codec.state is CodecState.READY, "a caller-side refusal must not fail the codec"


def test_an_id_is_reusable_once_its_reply_arrives():
    codec = negotiated_codec()
    codec.send(Stat(1, b"/a"))
    assert codec.outstanding == 1
    codec.receive(encode(AttrsReply(1, Attrs(size=0))))
    assert codec.outstanding == 0
    codec.send(Stat(1, b"/again"))  # no complaint


# --- sending ----------------------------------------------------------------------------


def test_send_encodes_and_records_the_request():
    codec = negotiated_codec()
    request = RealPath(1, b".")
    assert codec.send(request) == encode(request)
    assert codec.outstanding == 1


def test_sending_a_duplicate_in_flight_id_is_refused():
    codec = negotiated_codec()
    codec.send(Stat(7, b"/a"))
    with pytest.raises(StateError) as exc:
        codec.send(Close(7, b"h"))
    assert exc.value.args[0] == (
        "request id 7 is already in flight for a Stat; ids come from "
        "allocate_request_id() and are free again once answered"
    )


def test_a_refused_duplicate_leaves_the_original_request_and_the_connection_intact():
    # A silent overwrite would strand the first request forever, waiting for a reply that
    # gets attributed to the second. And since nothing was encoded, the session continues.
    codec = negotiated_codec()
    original = Stat(7, b"/original")
    codec.send(original)
    with pytest.raises(StateError):
        codec.send(Close(7, b"h"))

    assert codec.outstanding == 1
    assert codec.state is CodecState.READY
    (event,) = codec.receive(encode(AttrsReply(7, Attrs())))
    assert event.request is original


# --- correlation ------------------------------------------------------------------------


def test_a_reply_completes_its_request_and_carries_it_back():
    codec = negotiated_codec()
    request = Open(1, b"/tmp/f", OpenFlag.READ)
    codec.send(request)
    (event,) = codec.receive(encode(Handle(1, b"\x00\x00\x00\x00")))
    assert event == Completed(request=request, response=Handle(1, b"\x00\x00\x00\x00"))
    assert codec.outstanding == 0


def test_replies_may_arrive_out_of_order():
    # Out-of-order completion is normal, not exceptional: it is the entire point of
    # pipelining, and a scheduler that assumed FIFO would corrupt every deep transfer.
    codec = negotiated_codec()
    requests = [Read(codec.allocate_request_id(), b"h", offset=n * 10, length=10) for n in range(4)]
    for request in requests:
        codec.send(request)

    wire = b"".join(
        encode(Data(request_id=rid, data=memoryview(bytes([rid]) * 4))) for rid in (3, 1, 4, 2)
    )
    events = codec.receive(wire)

    assert [e.request.offset for e in events] == [20, 0, 30, 10]
    assert [bytes(e.response.data) for e in events] == [bytes([n]) * 4 for n in (3, 1, 4, 2)]
    assert codec.outstanding == 0


def test_a_reply_to_an_unknown_id_is_refused():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Status(42, StatusCode.OK)))
    assert exc.value.args[0] == (
        "server sent Status for request id 42, which is not outstanding; "
        "it was never sent, or it was already answered"
    )
    assert exc.value.request_id == 42


def test_a_duplicate_reply_is_refused():
    codec = negotiated_codec()
    codec.send(Stat(1, b"/a"))
    codec.receive(encode(AttrsReply(1, Attrs())))
    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(AttrsReply(1, Attrs())))
    assert exc.value.request_id == 1


def test_several_replies_in_one_chunk_are_all_reported():
    codec = negotiated_codec()
    for rid in (1, 2, 3):
        codec.send(Stat(rid, b"/x"))
    wire = b"".join(encode(AttrsReply(rid, Attrs(size=rid))) for rid in (1, 2, 3))
    events = codec.receive(wire)
    assert [e.response.attrs.size for e in events] == [1, 2, 3]


def test_a_reply_split_across_chunks_completes_once_whole():
    codec = negotiated_codec()
    codec.send(Stat(1, b"/x"))
    wire = encode(AttrsReply(1, Attrs(size=99)))
    for byte in wire[:-1]:
        assert codec.receive(bytes([byte])) == []
    (event,) = codec.receive(wire[-1:])
    assert event.response.attrs.size == 99


def test_a_status_completes_a_request_that_expected_a_handle():
    # Any response with a matching id completes the request. Whether the *kind* of reply
    # makes sense for the request is a judgement about server behaviour and is not made
    # here -- OPEN legitimately answers with either HANDLE or STATUS.
    codec = negotiated_codec()
    codec.send(Open(1, b"/nope", OpenFlag.READ))
    (event,) = codec.receive(encode(Status(1, StatusCode.NO_SUCH_FILE, b"No such file")))
    assert isinstance(event.request, Open)
    assert isinstance(event.response, Status)


# --- failure is terminal ----------------------------------------------------------------


def test_the_codec_is_terminal_after_a_protocol_error():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError):
        codec.receive(encode(Status(99, StatusCode.OK)))
    assert codec.state is CodecState.FAILED

    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Status(1, StatusCode.OK)))
    assert exc.value.args[0] == "codec is in a failed state; the connection is not recoverable"


# Each entry is a chunk the codec must refuse *and* be finished by. The four cover both
# sources that were missed until 0.8 -- the splitter's own length rejections and the
# decoder's -- because `_handle` was the only path that ever reached `_fail`.
MALFORMED_CHUNKS = [
    pytest.param(b"\x00\x00\x00\x02\x7f\x00", id="unknown-packet-type"),
    pytest.param(b"\x00\x00\x00\x04\x65\x00\x00\x00", id="truncated-status-body"),
    pytest.param(b"\x00\x00\x00\x00", id="zero-length-frame"),
    pytest.param((_codec.DEFAULT_MAX_FRAME_LENGTH + 1).to_bytes(4, "big"), id="over-ceiling"),
]


@pytest.mark.parametrize("chunk", MALFORMED_CHUNKS)
def test_a_malformed_frame_fails_the_codec_permanently(chunk: bytes):
    # The previous version of this test asserted only that two calls raised, and its second
    # `pytest.raises` caught "server sent Status for request id 1, which is not outstanding"
    # -- request 1 was never sent, so it raised for a reason that has nothing to do with the
    # malformed frame. It passed identically with the bug present and with it fixed. The
    # request is now genuinely outstanding, so a failed state is the only thing left to
    # refuse it, and the message is pinned.
    codec = negotiated_codec()
    codec.send(Stat(1, b"/x"))

    with pytest.raises(ProtocolError):
        codec.receive(chunk)
    assert codec.state is CodecState.FAILED

    with pytest.raises(ProtocolError) as exc:
        codec.receive(encode(Status(1, StatusCode.OK)))
    assert exc.value.args[0] == "codec is in a failed state; the connection is not recoverable"


@pytest.mark.parametrize("chunk", MALFORMED_CHUNKS)
def test_sending_after_a_malformed_frame_is_refused(chunk: bytes):
    codec = negotiated_codec()
    with pytest.raises(ProtocolError):
        codec.receive(chunk)
    with pytest.raises(ProtocolError) as exc:
        codec.send(Stat(1, b"/a"))
    assert exc.value.args[0] == "codec is in a failed state; the connection is not recoverable"


def test_a_good_frame_ahead_of_a_bad_one_is_discarded_with_the_error():
    # The documented decision, pinned so it is a decision rather than an accident. One call
    # cannot both return a value and raise; the connection is terminal either way; and
    # discarding costs a completed operation being reported as failed, which is the safe
    # direction. The dangerous direction -- reporting a failed operation as done -- is what
    # the FAILED latch exists to prevent, and it is asserted on the next line.
    codec = negotiated_codec()
    codec.send(Stat(1, b"/x"))
    codec.send(Stat(2, b"/y"))

    good = encode(AttrsReply(1, Attrs(size=7)))
    with pytest.raises(ProtocolError) as exc:
        codec.receive(good + b"\x00\x00\x00\x02\x7f\x00")
    # Prefix rather than the whole string, matching tests/test_packets.py's convention for
    # this one message: its tail is generated from the packet-type enum, so pinning it here
    # would break every time a type is added and would assert the enum rather than the
    # error. The offending value is in the prefix, which is what identifies *which* frame
    # failed -- the second one, not the first.
    assert exc.value.args[0].startswith("unknown packet type 127; filexfer v3 defines")
    assert codec.state is CodecState.FAILED

    # Request 1 was retired on the way past, so it is gone from the outstanding table even
    # though nobody was told it completed. That is visible rather than hidden: the codec is
    # FAILED, so no caller can act on the table again.
    assert codec.outstanding == 1


def test_sending_after_failure_is_refused():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError):
        codec.receive(encode(Status(99, StatusCode.OK)))
    # ProtocolError, not StateError: this connection is finished, and no correction to the
    # call would help.
    with pytest.raises(ProtocolError) as exc:
        codec.send(Stat(1, b"/a"))
    assert exc.value.args[0] == "codec is in a failed state; the connection is not recoverable"


# --- introspection ----------------------------------------------------------------------


def test_repr_reports_the_state_a_debugging_session_needs():
    codec = Codec()
    assert repr(codec) == "<Codec NEW version=- extensions=0 outstanding=0>"

    codec.initiate()
    codec.receive(encode(Version(3, ((b"fsync@openssh.com", b"1"),))))
    codec.send(Stat(1, b"/a"))
    assert repr(codec) == "<Codec READY version=3 extensions=1 outstanding=1>"


# --- payload lifetime -------------------------------------------------------------------


def test_a_data_payload_from_an_event_survives_later_receives():
    codec = negotiated_codec()
    codec.send(Read(1, b"h", 0, 4))
    codec.send(Read(2, b"h", 4, 4))
    (first,) = codec.receive(encode(Data(1, memoryview(b"AAAA"))))
    (second,) = codec.receive(encode(Data(2, memoryview(b"BBBB"))))
    assert bytes(first.response.data) == b"AAAA"
    assert bytes(second.response.data) == b"BBBB"


# --- properties -------------------------------------------------------------------------


@given(order=st.permutations(range(1, 9)))
def test_every_request_completes_exactly_once_whatever_the_reply_order(order):
    codec = negotiated_codec()
    sent = {}
    for _ in range(8):
        rid = codec.allocate_request_id()
        request = Stat(rid, f"/path/{rid}".encode())
        sent[rid] = request
        codec.send(request)

    completed = {}
    for rid in order:
        (event,) = codec.receive(encode(AttrsReply(rid, Attrs(size=rid))))
        completed[event.request.request_id] = event

    assert codec.outstanding == 0
    assert set(completed) == set(sent)
    for rid, event in completed.items():
        assert event.request is sent[rid]
        assert event.response.attrs.size == rid


@given(chunk_size=st.integers(min_value=1, max_value=32))
def test_replies_are_reassembled_whatever_the_chunking(chunk_size: int):
    codec = negotiated_codec()
    for rid in range(1, 6):
        codec.send(Stat(rid, b"/x"))
    wire = b"".join(
        encode(Name(rid, (NameEntry(b"f", b"lf", Attrs(size=rid)),))) for rid in range(1, 6)
    )

    events = []
    for i in range(0, len(wire), chunk_size):
        events.extend(codec.receive(wire[i : i + chunk_size]))

    assert [e.request.request_id for e in events] == [1, 2, 3, 4, 5]
    assert codec.outstanding == 0


def test_a_conformant_v6_era_status_over_v3_no_longer_kills_the_connection():
    """D-145, decided: degrade to the catch-all, keep the number, stay connected.

    24 is `SSH_FX_FILE_IS_A_DIRECTORY` from filexfer-13 9.1, and
    `draft-ietf-secsh-filexfer-extensions-00` 3 says a hashing request naming a directory SHOULD
    be answered with exactly it. So this is a *conformant* server answering a v6-era extension
    inside the v3 envelope we negotiated -- not a broken one.

    This test was committed one commit earlier asserting the opposite, which is what the card
    asked for: pin the behaviour so whichever answer is chosen shows up as a change. It did.

    Distinct from `test_the_codec_is_terminal_after_a_protocol_error`, which asks whether a
    genuinely malformed frame latches. That one still must, and still does: the latch is for a
    desynchronised stream, and a value with no name in an enum desynchronises nothing.
    """
    v6_era_but_real = 24
    codec = negotiated_codec()
    request = Stat(codec.allocate_request_id(), b"/some/directory")
    codec.send(request)

    frame = (
        struct.pack(">B", int(PacketType.STATUS))
        + struct.pack(">I", request.request_id)
        + struct.pack(">I", v6_era_but_real)
        + struct.pack(">I", len(b"is a directory"))
        + b"is a directory"
        + struct.pack(">I", 0)
    )
    (event,) = codec.receive(struct.pack(">I", len(frame)) + frame)

    assert codec.state is not CodecState.FAILED, "an unnameable status must not be terminal"
    assert isinstance(event, Completed)
    assert event.response.code is StatusCode.FAILURE
    assert event.response.raw_code == v6_era_but_real
    assert event.response.message == b"is a directory"

    # And the session stays usable, which is the entire point.
    second = Stat(codec.allocate_request_id(), b"/x")
    codec.send(second)
    codec.receive(encode(Status(second.request_id, StatusCode.OK)))
    assert codec.state is CodecState.READY

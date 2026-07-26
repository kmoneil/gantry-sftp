"""The client state machine: handshake, id allocation, correlation, and failure."""

from __future__ import annotations

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
    Read,
    RealPath,
    Stat,
    Status,
    StatusCode,
    Version,
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


def test_a_malformed_frame_fails_the_codec_permanently():
    codec = negotiated_codec()
    with pytest.raises(ProtocolError):
        codec.receive(b"\x00\x00\x00\x02\x7f\x00")  # unknown packet type
    with pytest.raises(ProtocolError):
        codec.receive(encode(Status(1, StatusCode.OK)))


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

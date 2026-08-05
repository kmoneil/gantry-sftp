"""Byte-range reads and writes, and the cursor object over them (D-86).

Three kinds of coverage, and the split is the same one `test_download.py` draws for the same
reasons. A scripted server produces shapes a real one will not make on demand -- a short
`DATA` at a chosen offset, a `DATA` *longer* than its request. Hypothesis covers the offset
arithmetic, because reassembling a range from arbitrary shortfalls is exactly the shape that
looks right in the two cases anybody writes by hand. And a real `sftp-server` answers the
questions this surface newly exposes: a public `read_at` lets a caller aim at end of file,
past it, at a zero-length range and at a range longer than `max-read-length`, none of which
`get` can reach because it clamps every range to a size it got from a `STAT`.

Those four edges were probed against the real server before any of this was written
(`_plans/probes/read_edges_probe.py`) and three of them decided the design:

* A `READ` at or past end of file answers `STATUS EOF`, so a read there is `b""` and not an
  error.
* A **zero-length** `READ` answers an empty `DATA` -- which is also precisely how a server
  making no progress looks. The transfer scheduler tolerates one empty `DATA` and fails on the
  second, correctly, so `read_at` answers a zero-length read locally rather than teaching the
  scheduler an exception for a case whose answer is already known.
* A `READ` longer than `max-read-length` is **clamped, not refused**, so a large read is a
  short `DATA` and a re-queue rather than an error a caller has to know how to avoid.

The fourth is a diagnosis rather than a decision: reading a write-only handle answers
`NO_SUCH_FILE`, for a file that plainly exists.
"""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import negotiate, running_dispatcher

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    Close,
    Data,
    FStat,
    Handle,
    Init,
    Open,
    OpenFlag,
    Read,
    Status,
    StatusCode,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.codec import (
    FrameSplitter as Splitter,
)
from gantry_sftp.exceptions import (
    ProtocolError,
    ServerError,
    StateError,
    TransferError,
    TransferTimeoutError,
)
from gantry_sftp.session import open_session, read_range_into, write_range_from
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

HANDLE = b"\x00\x00\x00\x00"


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


# --- a scripted server, for the shapes a real one will not make ---------------------------


class RangeServer:
    """Answers READs from a byte string and collects WRITEs into one, however we choose.

    `test_download.py`'s scripted server refuses anything that is not a `READ`, which was
    right when the only scheduler ran one direction. This one has to answer both, because the
    range surface writes as well as reads.
    """

    def __init__(
        self,
        content: bytes = b"",
        *,
        short_at: set[int] | None = None,
        overlong_at: int | None = None,
    ) -> None:
        self.content = bytearray(content)
        self.short_at = short_at or set()
        self.overlong_at = overlong_at
        """Offset whose READ is answered with more bytes than it asked for. A real server does
        not do this; a hostile one is not obliged to be a real one."""

        self.reads: list[tuple[int, int]] = []
        self.writes: list[tuple[int, int]] = []
        self._splitter = Splitter()
        self._pending: list[bytes] = []
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._handle(decode(frame))

    def _queue(self, frame: bytes) -> None:
        self._pending.append(frame)
        self._has_output.set()

    def _handle(self, packet: object) -> None:
        if isinstance(packet, Init):
            self._queue(encode(Version(3)))
        elif isinstance(packet, Read):
            self._answer_read(packet)
        elif isinstance(packet, Write):
            self._answer_write(packet)
        else:
            raise TypeError(f"scripted server got an unexpected {type(packet).__name__}")

    def _answer_read(self, packet: Read) -> None:
        self.reads.append((packet.offset, packet.length))
        if packet.offset >= len(self.content) and packet.length:
            self._queue(encode(Status(packet.request_id, StatusCode.EOF)))
            return
        if packet.offset == self.overlong_at:
            payload = bytes(self.content[packet.offset :])[: packet.length + 1]
            self._queue(encode(Data(packet.request_id, memoryview(payload))))
            return
        available = bytes(self.content[packet.offset : packet.offset + packet.length])
        if packet.offset in self.short_at and len(available) > 1:
            available = available[: len(available) // 2]
        self._queue(encode(Data(packet.request_id, memoryview(available))))

    def _answer_write(self, packet: Write) -> None:
        self.writes.append((packet.offset, len(packet.data)))
        end = packet.offset + len(packet.data)
        if len(self.content) < end:
            self.content.extend(bytes(end - len(self.content)))
        self.content[packet.offset : end] = bytes(packet.data)
        self._queue(encode(Status(packet.request_id, StatusCode.OK)))

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._outbox:
            await self._has_output.wait()
            batch, self._pending = self._pending, []
            self._has_output = anyio.Event()
            for frame in batch:
                self._outbox += frame
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        return chunk

    async def aclose(self) -> None:
        return


class CursorServer:
    """A whole session, for the two answers a real server will not give.

    ``RangeServer`` above speaks only ``READ`` and ``WRITE``, which is right for the scheduler
    and not enough for :class:`RemoteFile` -- the cursor object opens, fstats and closes. Two
    behaviours here are the reason it exists at all and neither is reachable against
    ``sftp-server``: **an ``ATTRS`` with no size in it**, which is legal (the size flag is
    optional, ``draft-ietf-secsh-filexfer-02`` 5) and is what ``read()`` and ``seek(SEEK_END)``
    refuse on, and **a ``CLOSE`` that fails**, which decides whether leaving the block reports
    or stays quiet.

    It also records every ``READ`` it is asked for, which is the only oracle for a length
    computed one way rather than another: the *bytes* come back the same either way once EOF
    clamps them, so the request is where the difference lives (D-105 slice 25).
    """

    def __init__(
        self, content: bytes = b"", *, report_size: bool = True, close_fails: bool = False
    ):
        self.content = bytearray(content)
        self.report_size = report_size
        self.close_fails = close_fails
        self.reads: list[tuple[int, int]] = []
        self.writes: list[tuple[int, int]] = []
        self.closes: list[bytes] = []
        self._splitter = Splitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._handle(decode(frame))

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

    def _handle(self, packet: object) -> None:
        if isinstance(packet, Init):
            self._reply(Version(3))
            return
        rid = packet.request_id  # type: ignore[union-attr]
        if isinstance(packet, Open):
            self._reply(Handle(rid, HANDLE))
        elif isinstance(packet, FStat):
            size = len(self.content) if self.report_size else None
            self._reply(AttrsReply(rid, Attrs(size=size)))
        elif isinstance(packet, Read):
            self.reads.append((packet.offset, packet.length))
            chunk = bytes(self.content[packet.offset : packet.offset + packet.length])
            if chunk:
                self._reply(Data(rid, memoryview(chunk)))
            else:
                self._reply(Status(rid, StatusCode.EOF))
        elif isinstance(packet, Write):
            self.writes.append((packet.offset, len(packet.data)))
            end = packet.offset + len(packet.data)
            if len(self.content) < end:
                self.content.extend(bytes(end - len(self.content)))
            self.content[packet.offset : end] = bytes(packet.data)
            self._reply(Status(rid, StatusCode.OK))
        elif isinstance(packet, Close):
            self.closes.append(packet.handle)
            if self.close_fails:
                self._reply(Status(rid, StatusCode.FAILURE, b"close refused"))
            else:
                self._reply(Status(rid, StatusCode.OK))
        else:
            self._reply(Status(rid, StatusCode.FAILURE, b"unscripted"))

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if not self._outbox:
            await self._has_output.wait()
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        if not self._outbox:
            self._has_output = anyio.Event()
        return chunk

    async def aclose(self) -> None:
        return


async def read_range(server: RangeServer, offset: int, length: int, **kwargs: object) -> bytes:
    codec = await negotiate(server)  # type: ignore[arg-type]
    buffer = bytearray(length)
    async with running_dispatcher(server, codec) as dispatcher:  # type: ignore[arg-type]
        filled = await read_range_into(
            dispatcher,
            HANDLE,
            memoryview(buffer),
            offset=offset,
            read_length=kwargs.pop("read_length", 64),  # type: ignore[arg-type]
            **kwargs,  # type: ignore[arg-type]
        )
    return bytes(buffer[:filled])


async def write_range(server: RangeServer, offset: int, payload: bytes, **kwargs: object) -> int:
    codec = await negotiate(server)  # type: ignore[arg-type]
    async with running_dispatcher(server, codec) as dispatcher:  # type: ignore[arg-type]
        return await write_range_from(
            dispatcher,
            HANDLE,
            memoryview(payload),
            offset=offset,
            write_length=kwargs.pop("write_length", 64),  # type: ignore[arg-type]
            **kwargs,  # type: ignore[arg-type]
        )


# --- the scheduler, with the destination in memory ----------------------------------------


async def test_a_range_inside_one_request():
    server = RangeServer(bytes(range(256)))
    assert await read_range(server, 10, 20) == bytes(range(10, 30))
    assert server.reads == [(10, 20)]


async def test_a_range_spanning_many_requests_is_pipelined_not_serialised():
    """The acceptance criterion this card was given, in its cheapest observable form.

    A read of 400 bytes at a 64-byte request size is seven requests. What matters is that they
    are issued *before* the replies are waited on -- one request per call, awaited, is the
    shape that makes the incumbent's file object 25x slower than its own whole-file download
    (`paramiko#2453`), and it would pass every correctness test in this file.
    """
    server = RangeServer(bytes(range(256)) * 4)
    assert await read_range(server, 0, 400) == bytes(range(256))[:256] + bytes(range(256))[:144]
    assert len(server.reads) == 7
    # Every request was in flight at once: the scheduler filled its window before the first
    # reply could be handled, so the offsets come out in issue order with no gaps.
    assert [offset for offset, _ in server.reads] == [0, 64, 128, 192, 256, 320, 384]


async def test_a_short_data_is_refilled_rather_than_returned():
    """A short `DATA` is legal mid-file and is **not** end of file.

    Returning it would make every caller loop, and the ones that forgot would silently get a
    prefix. The scheduler re-queues the shortfall, so a caller sees a short read only at the
    real end of the file.
    """
    server = RangeServer(bytes(range(256)), short_at={0})
    assert await read_range(server, 0, 64) == bytes(range(64))
    assert server.reads == [(0, 64), (32, 32)]


async def test_a_range_that_runs_past_the_end_returns_what_exists():
    server = RangeServer(b"0123456789")
    assert await read_range(server, 5, 100) == b"56789"


async def test_a_range_starting_at_the_end_is_empty():
    server = RangeServer(b"0123456789")
    assert await read_range(server, 10, 8) == b""


async def test_an_empty_buffer_asks_the_server_nothing():
    """Nothing on the wire, because the answer is already known.

    Not an optimisation: OpenSSH answers a zero-length READ with an empty DATA, which is the
    exact shape the scheduler treats as a server making no progress. Asking would be asking
    for the one reply we refuse to accept twice.
    """
    server = RangeServer(b"0123456789")
    assert await read_range(server, 0, 0) == b""
    assert server.reads == []


async def test_a_data_longer_than_its_request_is_refused():
    """The bug the memory sink surfaced, and it was reachable before it (D-86).

    A `DATA` carrying more bytes than the `READ` asked for used to be written out in full: a
    descriptor sink scribbled over the range the *next* request owns, silently, and `get`
    returned a byte count larger than the file. With a caller's buffer as the destination the
    same frame is a `ValueError` from a slice assignment several frames from its cause.

    Server-supplied lengths are attacker-controlled, so this is refused by the scheduler with
    the request it belongs to rather than absorbed.
    """
    server = RangeServer(bytes(range(256)), overlong_at=0)
    with pytest.raises(ProtocolError) as exc:
        await read_range(server, 0, 64)
    assert exc.value.args[0] == (
        "server answered a 64-byte READ at offset 0 with 65 bytes; "
        "a DATA may be short but never long"
    )
    # The frame it came on, which is the half a reader needs to report this upstream and the
    # half the sentence reads perfectly without.
    assert exc.value.request_id is not None


async def test_the_unfilled_tail_of_a_buffer_is_left_alone():
    """A caller's buffer is a caller's buffer: zeroing what we did not fill is a write nobody
    asked for, and it destroys whatever was being reused there."""
    server = RangeServer(b"0123456789")
    codec = await negotiate(server)  # type: ignore[arg-type]
    buffer = bytearray(b"x" * 20)
    async with running_dispatcher(server, codec) as dispatcher:  # type: ignore[arg-type]
        filled = await read_range_into(
            dispatcher, HANDLE, memoryview(buffer), offset=0, read_length=64
        )
    assert filled == 10
    assert bytes(buffer) == b"0123456789" + b"x" * 10


async def test_a_write_longer_than_one_request_is_split():
    server = RangeServer()
    assert await write_range(server, 0, bytes(range(200))[:200], write_length=64) == 200
    assert [offset for offset, _ in server.writes] == [0, 64, 128, 192]
    assert bytes(server.content) == bytes(range(200))[:200]


async def test_a_write_lands_at_the_offset_it_was_given():
    server = RangeServer(b"0123456789")
    assert await write_range(server, 4, b"AB") == 2
    assert bytes(server.content) == b"0123AB6789"


async def test_an_empty_write_asks_the_server_nothing():
    server = RangeServer(b"0123456789")
    assert await write_range(server, 0, b"") == 0
    assert server.writes == []


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"depth": 0}, "depth must be at least 1, got 0"),
        ({"read_length": 0}, "read_length must be at least 1, got 0"),
    ],
    ids=["depth", "read_length"],
)
async def test_a_range_read_that_could_not_progress_is_refused(
    kwargs: dict[str, int], message: str
):
    server = RangeServer(b"0123456789")
    with pytest.raises(ValueError) as exc:
        await read_range(server, 0, 4, **kwargs)
    assert exc.value.args[0] == message


# --- the offset arithmetic, fuzzed --------------------------------------------------------


@settings(deadline=None, max_examples=60)
@given(
    content=st.binary(min_size=1, max_size=600),
    offset=st.integers(min_value=0, max_value=600),
    length=st.integers(min_value=0, max_value=600),
    read_length=st.integers(min_value=1, max_value=97),
    short_at=st.sets(st.integers(min_value=0, max_value=600), max_size=8),
)
async def test_any_range_reassembles_to_the_slice_it_names(
    content: bytes, offset: int, length: int, read_length: int, short_at: set[int]
):
    """`read_range_into(offset, n) == content[offset:offset + n]`, for any split.

    The property the whole surface rests on, and the one a pair of hand-written cases cannot
    establish: the request size, the shortfalls and the end of the file all interact, and the
    interesting cases are the ones where a re-queued range is itself answered short.
    """
    server = RangeServer(content, short_at=short_at)
    assert (
        await read_range(server, offset, length, read_length=read_length)
        == (content[offset : offset + length])
    )


@settings(deadline=None, max_examples=40)
@given(
    payload=st.binary(min_size=0, max_size=400),
    offset=st.integers(min_value=0, max_value=200),
    write_length=st.integers(min_value=1, max_value=61),
)
async def test_any_write_lands_where_it_says(payload: bytes, offset: int, write_length: int):
    server = RangeServer(b"\x00" * 200)
    written = await write_range(server, offset, payload, write_length=write_length)
    assert written == len(payload)
    assert bytes(server.content[offset : offset + len(payload)]) == payload


# --- the session surface, against a real sftp-server --------------------------------------


async def test_read_at_returns_the_range_a_real_server_holds(tmp_path: Path):
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(bytes(range(256)) * 8)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(tmp_path / "data.bin").encode())
        try:
            assert await sftp.read_at(handle, 300, 12) == (bytes(range(256)) * 8)[300:312]
        finally:
            await sftp.close(handle)


async def test_a_read_past_the_end_of_a_real_file_is_empty_rather_than_an_error(tmp_path: Path):
    """`STATUS EOF`, probed, and it must not surface as a `ServerError`.

    This is the edge `get` never reaches -- it clamps to the size a `STAT` reported -- and it
    is the first thing a caller does by accident: read a fixed block size until the answer is
    short.
    """
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(tmp_path / "data.bin").encode())
        try:
            assert await sftp.read_at(handle, 10, 4) == b""
            assert await sftp.read_at(handle, 5000, 4) == b""
            assert await sftp.read_at(handle, 8, 4) == b"89"
        finally:
            await sftp.close(handle)


async def test_a_read_longer_than_max_read_length_is_served_by_several_requests(tmp_path: Path):
    """The server clamps rather than refusing, so the ceiling is not a caller's problem.

    Probed: a 1 MiB `READ` against OpenSSH comes back with `max-read-length` bytes and no
    error. That makes a large `read_at` a sequence of short `DATA`s to the scheduler, which is
    a case it already handles -- and it means no caller has to discover a per-request maximum.
    """
    needs_real_server()
    content = os.urandom(600_000)
    (tmp_path / "big.bin").write_bytes(content)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(tmp_path / "big.bin").encode())
        try:
            assert await sftp.read_at(handle, 0, len(content)) == content
        finally:
            await sftp.close(handle)


async def test_writing_past_the_end_leaves_a_hole_that_reads_back_as_zeroes(tmp_path: Path):
    """Legal, and worth pinning because it is the one way this surface can create bytes
    nobody wrote. Verified against the real server rather than assumed from POSIX."""
    needs_real_server()
    target = tmp_path / "sparse.bin"
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(target).encode(), OpenFlag.WRITE | OpenFlag.CREAT, mode=0o600)
        try:
            assert await sftp.write_at(handle, 4096, b"x") == 1
        finally:
            await sftp.close(handle)
    assert target.stat().st_size == 4097
    assert target.read_bytes()[:16] == b"\x00" * 16


async def test_reading_a_write_only_handle_says_no_such_file(tmp_path: Path):
    """The misdiagnosis, pinned so it cannot be mistaken for our own bug later.

    OpenSSH's handle lookup checks the direction, so a `READ` on a handle opened write-only
    answers `NO_SUCH_FILE` -- for a file that exists, by a path nobody mistyped. It is the same
    trap `check_file` hits, and the reason it is a test rather than a note is that the next
    person to see "No such file" from a successful `open()` will otherwise go looking in the
    wrong place.

    The exception is a `TransferError` and not the typed `NoSuchFileError` that `open()` would
    raise for the same status, because this goes through the transfer scheduler -- which is
    the same choice `get` makes, for the same reason: what a caller needs from a failed range
    is how far it got. Pinned here so the two cannot drift apart quietly.

    It is also the **non-`FAILURE`** half of D-117's first-read message: the sentence says the
    handle opened and nothing could be read, and stops there. The directory hint is withheld
    because `NO_SUCH_FILE` carries its own meaning and no server answers it for a directory, so
    offering one here would be a guess printed as a lead. And `local_path` stays `None`: a
    range read has no local file, which is the case that keeps "carry both paths" from
    becoming "invent the second one".
    """
    needs_real_server()
    target = tmp_path / "out.bin"
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(target).encode(), OpenFlag.WRITE | OpenFlag.CREAT, mode=0o600)
        try:
            with pytest.raises(TransferError) as exc:
                await sftp.read_at(handle, 0, 4)
            assert exc.value.args[0] == (
                "server refused the first read, at offset 0: NO_SUCH_FILE No such file -- the "
                "handle opened and then not one byte could be read, so nothing arrived and "
                "nothing was truncated"
            )
            assert exc.value.transferred == 0
            assert exc.value.offset == 0
            assert exc.value.local_path is None
            assert not hasattr(exc.value, "__notes__")
        finally:
            await sftp.close(handle)


async def test_ranges_of_one_file_can_be_read_concurrently(tmp_path: Path):
    """The reason the offset form exists beside the cursor form.

    Four tasks, one handle, four ranges, no shared position -- so this is the shape to fan out
    with. Doing the same with one `RemoteFile` would interleave the cursor and give each task
    a subset of what it asked for, which is why that object is documented as one-task.
    """
    needs_real_server()
    content = bytes(range(256)) * 40
    (tmp_path / "data.bin").write_bytes(content)
    got: dict[int, bytes] = {}

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(tmp_path / "data.bin").encode())

        async def fetch(index: int) -> None:
            got[index] = await sftp.read_at(handle, index * 1000, 1000)

        try:
            async with anyio.create_task_group() as tasks:
                for index in range(4):
                    tasks.start_soon(fetch, index)
        finally:
            await sftp.close(handle)

    assert got == {index: content[index * 1000 : (index + 1) * 1000] for index in range(4)}


@pytest.mark.parametrize(
    ("offset", "length", "message"),
    [
        (-1, 4, "offset must not be negative, got -1"),
        (0, -4, "length must not be negative, got -4"),
    ],
    ids=["offset", "length"],
)
async def test_read_at_refuses_a_negative_argument(
    tmp_path: Path, offset: int, length: int, message: str
):
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(tmp_path / "data.bin").encode())
        try:
            with pytest.raises(ValueError) as exc:
                await sftp.read_at(handle, offset, length)
            assert exc.value.args[0] == message
        finally:
            await sftp.close(handle)


# --- the cursor object --------------------------------------------------------------------


async def test_the_file_object_reads_seeks_and_tells(tmp_path: Path):
    needs_real_server()
    content = bytes(range(256)) * 4
    (tmp_path / "data.bin").write_bytes(content)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        sftp.open_file(str(tmp_path / "data.bin").encode()) as remote,
    ):
        assert remote.tell() == 0
        assert await remote.read(16) == content[:16]
        assert remote.tell() == 16
        assert await remote.seek(100) == 100
        assert await remote.read(4) == content[100:104]
        assert await remote.seek(-8, os.SEEK_END) == len(content) - 8
        assert await remote.read() == content[-8:]
        assert await remote.read(4) == b""
        assert await remote.seek(-4, os.SEEK_CUR) == len(content) - 4
        assert await remote.read() == content[-4:]


async def test_the_file_object_reads_the_rest_when_given_no_length(tmp_path: Path):
    needs_real_server()
    content = os.urandom(300_000)
    (tmp_path / "data.bin").write_bytes(content)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        sftp.open_file(str(tmp_path / "data.bin").encode()) as remote,
    ):
        await remote.seek(1000)
        assert await remote.read() == content[1000:]


async def test_the_file_object_writes_at_the_cursor_and_truncates(tmp_path: Path):
    needs_real_server()
    target = tmp_path / "out.bin"
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        flags = OpenFlag.WRITE | OpenFlag.READ | OpenFlag.CREAT
        async with sftp.open_file(str(target).encode(), flags, mode=0o600) as remote:
            assert await remote.write(b"0123456789") == 10
            assert remote.tell() == 10
            assert (await remote.stat()).size == 10
            await remote.seek(4)
            assert await remote.write(b"AB") == 2
            await remote.truncate(8)
    assert target.read_bytes() == b"0123AB67"
    assert target.stat().st_mode & 0o777 == 0o600


async def test_the_file_object_reads_into_a_buffer(tmp_path: Path):
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        sftp.open_file(str(tmp_path / "data.bin").encode()) as remote,
    ):
        buffer = bytearray(4)
        assert await remote.readinto(buffer) == 4
        assert bytes(buffer) == b"0123"
        assert remote.tell() == 4


async def test_the_handle_is_gone_after_the_block_even_on_a_break(tmp_path: Path):
    """A leak probe rather than an inference: `close()` of an unknown handle answers
    `NO_SUCH_FILE`, so asking twice is how we know the first one landed."""
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        remote = sftp.open_file(str(tmp_path / "data.bin").encode())
        async with remote:
            handle = remote._open_handle()  # noqa: SLF001
            assert await remote.read(2) == b"01"
        with pytest.raises(ServerError):
            await sftp.close(handle)


async def test_using_a_file_object_outside_its_block_is_refused(tmp_path: Path):
    """Both halves of the lifetime, and they say different things -- "not open yet" and
    "closed" are different mistakes and a caller fixes them differently."""
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        remote = sftp.open_file(str(tmp_path / "data.bin").encode())
        with pytest.raises(StateError) as before:
            await remote.read(2)
        assert before.value.args[0] == (
            "this open_file() is not open; use it in an `async with` block"
        )

        async with remote:
            pass

        with pytest.raises(StateError) as after:
            await remote.read(2)
        assert after.value.args[0] == (
            "this open_file() is closed; its `async with` block has ended"
        )

        with pytest.raises(StateError) as again:
            async with remote:
                pass
        assert again.value.args[0] == (
            "this open_file() has already been used; call open_file() again"
        )


async def test_a_seek_to_exactly_the_start_is_allowed(tmp_path: Path):
    """The value the guard exists to admit, which nothing had ever passed through it.

    ``if target < 0`` reads as obviously right and becomes ``<= 0`` or ``< 1`` without any
    test objecting: every existing case seeks to -1 (refused) or forward (never near the
    boundary). Rewinding to the start is the ordinary thing a caller does, and it is exactly
    the value the two mutations reject. Third instance of this shape after both schedulers.
    """
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        sftp.open_file(str(tmp_path / "data.bin").encode()) as remote,
    ):
        assert await remote.seek(4) == 4
        assert await remote.seek(0) == 0
        assert remote.tell() == 0
        assert await remote.read(2) == b"01"
        # ...and by the other two routes to the same position, since each computes `target`
        # with different arithmetic and only `SEEK_SET` passes the value through untouched.
        assert await remote.seek(-2, os.SEEK_CUR) == 0
        assert await remote.seek(-10, os.SEEK_END) == 0


async def test_reading_the_rest_asks_for_what_remains_and_no_more(tmp_path: Path):
    """The bytes cannot see this and the request can (D-105 slice 25).

    ``length = max(0, attrs.size - self._position)`` returns the same *data* whether the
    subtraction is a subtraction or an addition, because EOF clamps an over-long read to what
    exists. What differs is what went on the wire -- an over-long request, or none at all.
    """
    server = CursorServer(b"0123456789")
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.open_file(b"/data.bin") as remote,
    ):
        _ = await remote.seek(4)
        assert await remote.read() == b"456789"
    # Six remaining, so six asked for. `size + position` would ask for fourteen and get the
    # same six back; `max(1, ...)` would ask for one.
    assert server.reads == [(4, 6)]


async def test_reading_at_the_end_asks_the_server_nothing(tmp_path: Path):
    """A zero-length range is answered locally, so the cursor at EOF costs one FSTAT and no READ.

    `max(0, ...)` becoming `max(1, ...)` is invisible in the returned bytes -- a one-byte read
    at EOF is `b""` as well -- and visible here as a round trip that should not have happened.
    """
    server = CursorServer(b"0123456789")
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.open_file(b"/data.bin") as remote,
    ):
        _ = await remote.seek(0, os.SEEK_END)
        assert await remote.read() == b""
    assert server.reads == []


async def test_a_server_that_reports_no_size_is_refused_by_name(tmp_path: Path):
    """Legal, unreachable against `sftp-server`, and the two refusals it produces.

    The size flag is optional, so an ``ATTRS`` without one is a conformant answer that neither
    ``read()`` with no length nor ``SEEK_END`` can work from. Both messages were unasserted, so
    either could have been emptied or case-mangled.
    """
    server = CursorServer(b"0123456789", report_size=False)
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.open_file(b"/data.bin") as remote,
    ):
        with pytest.raises(ValueError) as read_refusal:
            _ = await remote.read()
        assert read_refusal.value.args[0] == (
            "the server did not report a size, so read() cannot tell where the file "
            "ends; pass a length"
        )
        with pytest.raises(ValueError) as seek_refusal:
            _ = await remote.seek(0, os.SEEK_END)
        assert seek_refusal.value.args[0] == (
            "the server did not report a size, so SEEK_END has nothing to seek from"
        )
        # A read with an explicit length still works: only the "where does it end"
        # question needs the size, and the refusal must not disable the rest.
        assert await remote.read(4) == b"0123"


async def test_the_cursor_advances_across_successive_readintos(tmp_path: Path):
    """`self._position += filled` against `= filled`, which agree on the first call only."""
    server = CursorServer(b"0123456789")
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.open_file(b"/data.bin") as remote,
    ):
        first = bytearray(4)
        assert await remote.readinto(first) == 4
        assert remote.tell() == 4
        second = bytearray(4)
        assert await remote.readinto(second) == 4
        assert bytes(second) == b"4567"
        # 8, not 4. Assignment would put the cursor back where the first call left it and
        # re-read the same bytes for ever.
        assert remote.tell() == 8


async def test_a_close_that_fails_on_the_way_out_is_reported(tmp_path: Path):
    """Leaving a clean block reports the failure; leaving a failing one must not replace it.

    Both halves of `__aexit__`'s documented contract, and neither had a test -- so the branch
    could be inverted, which swaps "report" and "stay quiet" without changing either message.
    """
    server = CursorServer(b"0123456789", close_fails=True)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            async with sftp.open_file(b"/data.bin"):
                pass
        assert exc.value.args[0] == "server returned FAILURE: close refused"

    # And the other way: the caller's exception is the one that explains what happened, so a
    # CLOSE failing underneath it is swallowed rather than allowed to take its place.
    server = CursorServer(b"0123456789", close_fails=True)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ZeroDivisionError):
            async with sftp.open_file(b"/data.bin"):
                _ = 1 / 0
    # Swallowed is not the same as skipped. `_close_quietly` suppresses everything, so a
    # handle or a session lost on the way in would look identical from out here -- the
    # server having been asked is the only thing that says the handle was released.
    assert server.closes == [HANDLE]


async def test_the_cursor_advances_across_successive_writes():
    """`self._position += written` against `= written`, the write-side twin of readinto's.

    They agree on the first call and diverge on every one after it: assignment parks the
    cursor at the length of the last write, so a third write lands on top of the second.
    """
    server = CursorServer()
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.open_file(b"/data.bin", OpenFlag.WRITE | OpenFlag.CREAT) as remote,
    ):
        assert await remote.write(b"abcd") == 4
        assert remote.tell() == 4
        assert await remote.write(b"ef") == 2
        assert remote.tell() == 6
    assert bytes(server.content) == b"abcdef"


async def test_the_file_object_flushes_through_fsync(tmp_path: Path):
    """`RemoteFile.fsync` had no test at all -- the lane reported "no tests", not a survivor.

    One line forwarding an open handle, and the handle is the whole content of it: passing
    `None` instead reaches the session with nothing to flush. Driven against the real server
    because `fsync@openssh.com` is an extension and whether it is *there* is half the answer.
    """
    needs_real_server()
    path = tmp_path / "data.bin"
    path.write_bytes(b"")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        async with sftp.open_file(str(path).encode(), OpenFlag.WRITE | OpenFlag.CREAT) as remote:
            _ = await remote.write(b"durable")
            await remote.fsync()
        assert path.read_bytes() == b"durable"

    # And the refusal, which is the other half: a file that is not open has no handle to
    # flush, and that must say so rather than reaching the server with nothing.
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        spent = sftp.open_file(str(path).encode())
        async with spent:
            pass
        with pytest.raises(StateError):
            await spent.fsync()


async def test_a_seek_before_the_start_is_refused(tmp_path: Path):
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
        sftp.open_file(str(tmp_path / "data.bin").encode()) as remote,
    ):
        with pytest.raises(ValueError) as exc:
            await remote.seek(-1)
        assert exc.value.args[0] == "seek would put the position at -1, before the start"
        with pytest.raises(ValueError) as whence:
            await remote.seek(0, 99)
        assert whence.value.args[0] == ("whence must be os.SEEK_SET, SEEK_CUR or SEEK_END, got 99")
        assert remote.tell() == 0


async def test_the_file_object_repr_says_where_it_is(tmp_path: Path):
    """The `repr` is a debugging surface and the position is the thing being debugged."""
    needs_real_server()
    (tmp_path / "data.bin").write_bytes(b"0123456789")
    path = str(tmp_path / "data.bin").encode()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        remote = sftp.open_file(path)
        assert repr(remote) == f"<RemoteFile {path!r} unopened at 0>"
        async with remote:
            await remote.read(4)
            assert repr(remote) == f"<RemoteFile {path!r} open at 4>"
        assert repr(remote) == f"<RemoteFile {path!r} closed at 4>"


# --- the range functions' own guards, and what they forward ------------------------------------
#
# D-105's sixteenth slice. Both take the same three guards as the whole-file schedulers and had
# none of their messages asserted -- and neither had ever been passed the smallest value its
# guard admits, so `< 1` could become `<= 1` with every existing test still green.


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"depth": 0}, "depth must be at least 1, got 0"),
        ({"write_length": 0}, "write_length must be at least 1, got 0"),
    ],
    ids=["depth", "write-length"],
)
async def test_a_range_write_refuses_a_setting_that_cannot_make_progress(
    kwargs: dict[str, int], message: str
):
    server = RangeServer(b"")
    with pytest.raises(ValueError) as refusal:
        _ = await write_range(server, 0, b"payload", **{"write_length": 64, **kwargs})
    assert refusal.value.args[0] == message


async def test_a_range_write_refuses_a_negative_offset():
    server = RangeServer(b"")
    with pytest.raises(ValueError) as refusal:
        _ = await write_range(server, -1, b"payload")
    assert refusal.value.args[0] == "offset must not be negative, got -1"


async def test_readinto_at_hands_the_sessions_tunables_to_the_scheduler(
    monkeypatch: pytest.MonkeyPatch,
):
    """The read side of the same forward `write_at` has, and it was untested for the same reason.

    Every caller passes the callee's own defaults, so dropping `depth` or `idle_timeout` on the
    way in restates what was going to happen anyway. A session opened with non-default values
    is the only thing that can tell.
    """
    captured: dict[str, object] = {}

    async def recording_read_range_into(*args: object, **kwargs: object) -> int:
        captured.update(kwargs)
        return 3

    monkeypatch.setattr(
        "gantry_sftp.session._operations.read_range_into", recording_read_range_into
    )
    server = CursorServer(b"0123456789")
    async with open_session(server, depth=2, idle_timeout=9.5) as sftp:  # type: ignore[arg-type]
        buffer = bytearray(4)
        assert await sftp.readinto_at(HANDLE, buffer, 1) == 3

    assert captured["depth"] == 2
    assert captured["idle_timeout"] == 9.5
    assert captured["offset"] == 1


async def test_write_at_refuses_a_negative_offset_by_name():
    """The session-level guard, which is a different one from `write_range_from`'s.

    Both exist and only the inner one had its message pinned, so the outer could raise
    `ValueError(None)` -- an exception with nothing in it, at the layer a caller actually
    calls.
    """
    server = CursorServer(b"0123456789")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as refusal:
            _ = await sftp.write_at(HANDLE, -1, b"payload")
    assert refusal.value.args[0] == "offset must not be negative, got -1"
    assert server.writes == []


async def test_write_at_of_nothing_returns_zero_and_asks_the_server_nothing():
    """`return 0` and `return 1` both look like "an empty write wrote nothing".

    The return value is the byte count a caller adds to a running total, so the difference is
    a transfer that reports one byte more than it sent, per empty write.
    """
    server = CursorServer(b"0123456789")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.write_at(HANDLE, 0, b"") == 0
        assert await sftp.write_at(HANDLE, 0, memoryview(b"")) == 0
    assert server.writes == []


async def test_write_at_hands_the_sessions_tunables_to_the_scheduler(
    monkeypatch: pytest.MonkeyPatch,
):
    """Two arguments whose only job is to arrive, and which every caller passes by default.

    `depth` and `idle_timeout` are session tunables forwarded into `write_range_from`. Dropped,
    the callee's own defaults apply -- so a session opened with a shallow pipeline or a short
    idle timeout would silently get neither, and no test asserting on *bytes* can see it. The
    non-default values are the whole point: with the defaults passed, the mutation restates
    what was already going to happen.
    """
    captured: dict[str, object] = {}

    async def recording_write_range_from(*args: object, **kwargs: object) -> int:
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(
        "gantry_sftp.session._operations.write_range_from", recording_write_range_from
    )
    server = CursorServer(b"0123456789")
    async with open_session(server, depth=3, idle_timeout=11.5) as sftp:  # type: ignore[arg-type]
        assert await sftp.write_at(HANDLE, 4, b"payload") == 7

    assert captured["depth"] == 3
    assert captured["idle_timeout"] == 11.5
    assert captured["offset"] == 4


async def test_a_range_read_refuses_a_negative_offset():
    server = RangeServer(b"0123456789")
    with pytest.raises(ValueError) as refusal:
        _ = await read_range(server, -1, 4)
    assert refusal.value.args[0] == "offset must not be negative, got -1"


@pytest.mark.parametrize("depth", [0, -1], ids=["zero", "negative"])
async def test_a_range_read_refuses_a_depth_that_cannot_make_progress(depth: int):
    server = RangeServer(b"0123456789")
    with pytest.raises(ValueError) as refusal:
        _ = await read_range(server, 0, 4, depth=depth)
    assert refusal.value.args[0] == f"depth must be at least 1, got {depth}"


async def test_the_smallest_legal_settings_still_move_a_range():
    """`depth=1` and one byte per request: the value each guard is written to admit.

    Every other test of those guards passes 0 or -1, which cannot separate `< 1` from `<= 1`.
    A caller reaches for this shape to find out which byte a broken endpoint mangles, so it has
    to work rather than merely not be refused.
    """
    server = RangeServer(b"0123456789")
    assert await read_range(server, 2, 4, depth=1, read_length=1) == b"2345"
    assert server.reads == [(2, 1), (3, 1), (4, 1), (5, 1)]


async def test_an_empty_range_read_moves_nothing_and_reports_zero():
    """Zero is the answer, and it is one character from being one.

    An empty buffer is what a caller passes at EOF, and a range read that reported `1` for it
    would have the caller advance an offset past a byte nothing wrote -- silently, since there
    is no request on the wire to disagree with.
    """
    server = RangeServer(b"0123456789")
    codec = await negotiate(server)  # type: ignore[arg-type]
    async with running_dispatcher(server, codec) as dispatcher:  # type: ignore[arg-type]
        # The returned count is the assertion, not the buffer: `bytes(buffer[:1])` of an empty
        # buffer is still empty, so reading through the helper cannot see a wrong answer here.
        filled = await read_range_into(
            dispatcher, HANDLE, memoryview(bytearray(0)), offset=4, read_length=64
        )

    assert filled == 0
    assert server.reads == []


async def test_a_refused_range_write_names_the_file_it_was_writing():
    """`remote_path` is forwarded to the scheduler, which holds a handle and no name.

    A byte-range write is what a file object does on `flush`, so the caller is several frames
    away from the path by the time this fails -- and the error is all they get.
    """

    class RefusesWrites(RangeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Write):
                self._queue(encode(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"no")))
                return
            super()._handle(packet)

    server = RefusesWrites(b"")
    with pytest.raises(TransferError) as refusal:
        _ = await write_range(server, 0, b"payload", remote_path=b"/incoming/report.csv")

    assert refusal.value.remote_path == b"/incoming/report.csv"


async def test_a_stalled_range_read_is_bounded_by_the_idle_timeout_it_was_given():
    """The forwarded watchdog, and the outer deadline is the assertion.

    A dropped `idle_timeout=` falls back to the shipped 60 s default, which raises the same
    error a minute later -- so a test with no ceiling of its own cannot tell the two apart and
    is merely slow.
    """

    class NeverAnswersARead(RangeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read):
                return
            super()._handle(packet)

    server = NeverAnswersARead(b"0123456789")
    with anyio.fail_after(5):
        with pytest.raises(TransferTimeoutError):
            _ = await read_range(server, 0, 4, idle_timeout=0.05)


async def test_the_smallest_legal_settings_still_write_a_range():
    """`depth=1` on the sending side, which its own guard admits and nothing had passed."""
    server = RangeServer(b"")
    assert await write_range(server, 0, b"payload", depth=1, write_length=1) == 7
    assert server.writes == [(offset, 1) for offset in range(7)]


async def test_a_refused_range_read_names_the_file_it_was_reading():
    """The read side's `remote_path`, forwarded to a scheduler that holds a handle and no name.

    Asserted separately from the write side's because they are separate call sites: the two
    functions each build their own scheduler and each pass this argument themselves.
    """

    class RefusesReads(RangeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read):
                self._queue(encode(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"no")))
                return
            super()._handle(packet)

    server = RefusesReads(b"0123456789")
    with pytest.raises(TransferError) as refusal:
        _ = await read_range(server, 0, 4, remote_path=b"/incoming/report.csv")

    assert refusal.value.remote_path == b"/incoming/report.csv"


async def test_a_stalled_range_write_is_bounded_by_the_idle_timeout_it_was_given():
    """The write side's watchdog, with the same outer ceiling as the read side's.

    Separate call sites again, and the failure mode is worse here: a `flush` that never
    returns holds bytes the caller believes are on their way.
    """

    class NeverAnswersAWrite(RangeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Write):
                return
            super()._handle(packet)

    server = NeverAnswersAWrite(b"")
    with anyio.fail_after(5):
        with pytest.raises(TransferTimeoutError):
            _ = await write_range(server, 0, b"payload", idle_timeout=0.05)

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
    Data,
    Init,
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
from gantry_sftp.exceptions import ProtocolError, ServerError, StateError, TransferError
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
                "server refused a read at offset 0: NO_SUCH_FILE No such file"
            )
            assert exc.value.transferred == 0
            assert exc.value.offset == 0
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

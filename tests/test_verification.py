"""Rung 3 of DESIGN.md 6's ladder: the size check that section says runs *always*.

Until 0.8 it ran nowhere. ``get`` STATted the file, used the size to bound which ranges the
scheduler issued, and returned whatever arrived; ``put`` never STATted the destination at
all. So a server that ended a download early -- a truncating appliance, a file being rewritten
underneath us -- produced a short local file and a *successful* call, while README and
DESIGN.md both said a size check had happened.

The lying server is the whole point of this module. A conformant server cannot be asked to
truncate a transfer on demand, so a lane built only on one proves the check never *fires* --
which is why almost everything here is scripted. The last test is the other half, against a
real ``sftp-server``: every scripted case above would also pass against an implementation
that raised unconditionally, so a check that never misfires needs an honest server to say so.
Neither half is evidence without the other.

What this does *not* test is content, because the check does not verify content. It is a
length comparison: it catches truncation and nothing else, and the docstrings say so in those
words rather than letting "verified" be read into it.

``get_tree`` and ``put_tree`` get the same treatment as of D-71, for the reason the tree
section below states: they inherit the check by *delegation*, which is a property of the
current call graph rather than a guarantee, and nothing here would have noticed it breaking.
The matching does-it-not-misfire half for trees is in ``live-tests/test_matrix.py``, against
all three server implementations rather than one -- whether an endpoint reports a size at all
is exactly the sort of thing that differs between them.
"""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    Close,
    Data,
    Extended,
    FrameSplitter,
    Handle,
    Init,
    LStat,
    Name,
    NameEntry,
    Open,
    OpenDir,
    Read,
    ReadDir,
    Stat,
    Status,
    StatusCode,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import Publish, PublishMechanism, SizeCheck, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio


class LyingServer:
    """A server whose STAT disagrees with what it will actually store or serve.

    One fake for both directions, because the failure is symmetrical: the server states a
    length and the bytes do not match it. ``stated_size`` is what every STAT reports;
    ``content`` is what a READ will actually yield, and writes are counted rather than kept so
    an upload's stated size can be made to disagree with the local file's.

    ``entries`` makes it serve a single flat directory, which is what the ``get_tree`` cases
    need: one batch of NAME entries then EOF. ``opened`` records every OPEN filename in order,
    so a test can assert a tree *stopped* rather than merely that it raised -- the difference
    between an error propagating and an error being collected into ``skipped``.
    """

    def __init__(
        self,
        *,
        content: bytes = b"",
        stated_size: int | None = None,
        no_size: bool = False,
        refuse_stat: bool = False,
        entries: tuple[bytes, ...] = (),
    ) -> None:
        self.content = content
        self.stated_size = len(content) if stated_size is None else stated_size
        self.no_size = no_size
        self.refuse_stat = refuse_stat
        self.entries = entries
        self.written = bytearray()
        self.kinds: list[str] = []
        self.opened: list[bytes] = []
        self._drained: set[bytes] = set()
        self._splitter = FrameSplitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._dispatch(decode(frame))

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

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

    def _dispatch(self, packet: object) -> None:
        if isinstance(packet, Init):
            self._reply(Version(3))
            return
        self.kinds.append(
            packet.name.decode() if isinstance(packet, Extended) else type(packet).__name__
        )
        self._handle(packet)

    def _stat(self, rid: int) -> None:
        if self.refuse_stat:
            self._reply(Status(rid, StatusCode.PERMISSION_DENIED, b"no stat for you"))
        elif self.no_size:
            self._reply(AttrsReply(rid, Attrs()))
        else:
            self._reply(AttrsReply(rid, Attrs(size=self.stated_size)))

    def _readdir(self, rid: int, handle: bytes) -> None:
        """One batch of :attr:`entries` then EOF, keyed on the handle.

        A NAME with no entries would also mean end-of-directory, but sending EOF is what the
        reference server does and the zero-count NAME has its own test elsewhere.
        """
        if handle in self._drained:
            self._reply(Status(rid, StatusCode.EOF))
            return
        self._drained.add(handle)
        self._reply(
            Name(
                rid,
                tuple(
                    NameEntry(
                        name,
                        b"-rw-r--r-- 1 u g " + name,
                        # 0o100644 -- the file-*type* bits are what matter, not the permission
                        # bits: `entry_kind` reads S_ISREG off this same field, and a bare
                        # 0o644 would classify every entry as OTHER and make the walk skip the
                        # whole directory rather than descend into it.
                        Attrs(size=self.stated_size, permissions=0o100644),
                    )
                    for name in self.entries
                ),
            )
        )

    def _handle(self, packet: object) -> None:
        rid = packet.request_id  # type: ignore[union-attr]
        if isinstance(packet, Stat | LStat):
            self._stat(rid)
        elif isinstance(packet, Open):
            self.opened.append(packet.filename)
            self._reply(Handle(rid, b"h"))
        elif isinstance(packet, OpenDir):
            self._reply(Handle(rid, b"d"))
        elif isinstance(packet, ReadDir):
            self._readdir(rid, packet.handle)
        elif isinstance(packet, Read):
            chunk = self.content[packet.offset : packet.offset + packet.length]
            if chunk:
                self._reply(Data(rid, memoryview(chunk)))
            else:
                self._reply(Status(rid, StatusCode.EOF))
        elif isinstance(packet, Write):
            self.written += packet.data
            self._reply(Status(rid, StatusCode.OK))
        elif isinstance(packet, Extended):
            # posix-rename answers a STATUS, not an EXTENDED_REPLY -- OpenSSH's PROTOCOL, and
            # confirmed on the wire in 0.3. Everything else here is refused, so the upload
            # takes the no-fsync path and Durability comes back UNAVAILABLE.
            self._reply(
                Status(rid, StatusCode.OK)
                if packet.name.startswith(b"posix-rename")
                else Status(rid, StatusCode.OP_UNSUPPORTED, b"no")
            )
        elif isinstance(packet, Close):
            self._reply(Status(rid, StatusCode.OK))
        else:
            self._reply(Status(rid, StatusCode.OK))


# --- downloading ------------------------------------------------------------------------------


async def test_a_download_that_ends_short_of_the_stated_size_is_refused(tmp_path: Path):
    """The headline. Without the check this call returns 10 and reports success.

    The server states 100 bytes and serves 10, then answers EOF -- which is *legal*, and is
    why the scheduler treats it as "stop issuing" rather than as an error. Nothing below
    ``get`` is in a position to complain: a short DATA is legal, an early EOF is legal, and
    only the caller who asked for a named file knows how big it was supposed to be.
    """
    server = LyingServer(content=b"x" * 10, stated_size=100)
    local = tmp_path / "short.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(b"/remote.bin", local)

    assert exc.value.args[0] == (
        "b'/remote.bin' is 100 bytes but the download ended after 10; "
        "it was truncated or the file shrank underneath it"
    )
    # State, not just a string: DESIGN.md 9 says TransferError carries the progress and both
    # paths, and a mutation run found these unasserted everywhere once already.
    assert exc.value.transferred == 10
    assert exc.value.offset == 10
    assert exc.value.remote_path == b"/remote.bin"
    assert exc.value.local_path == str(local)
    # The partial is left on disk rather than deleted. It is the caller's file, it is what a
    # subsequent resume=True continues from, and deleting a user's bytes to tidy up an error
    # is a worse failure than the one being reported.
    assert local.read_bytes() == b"x" * 10


async def test_verify_size_false_accepts_the_short_download(tmp_path: Path):
    # The escape hatch for a file that is genuinely changing size underneath -- and the proof
    # that the refusal above comes from the check rather than from anything else in the path.
    server = LyingServer(content=b"x" * 10, stated_size=100)
    local = tmp_path / "short.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        moved = await sftp.get(b"/remote.bin", local, verify_size=False)

    assert moved.transferred == 10
    # Turning the check off is reported rather than being silent. The download is a snapshot
    # of unknown completeness and the result is where that is written down -- an `int` had
    # nowhere to say it, which is the half of D-99 the verification ladder cared about.
    assert moved.size_check is SizeCheck.SKIPPED
    assert local.read_bytes() == b"x" * 10


async def test_a_server_that_reports_no_size_cannot_be_size_checked(tmp_path: Path):
    # Rung 3 is unavailable rather than passed, and unavailable must not mean refused: there
    # is no size to compare against, the download reads to EOF, and failing here would refuse
    # a server over a tuning fact. The same call the `limits` probe makes.
    server = LyingServer(content=b"x" * 10, no_size=True)
    local = tmp_path / "unknown.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        moved = await sftp.get(b"/remote.bin", local)

    assert moved.transferred == 10
    assert moved.size_check is SizeCheck.UNAVAILABLE, "not passed, and not refused"
    assert local.read_bytes() == b"x" * 10


async def test_a_full_download_passes_the_check(tmp_path: Path):
    server = LyingServer(content=b"y" * 64)
    local = tmp_path / "whole.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        moved = await sftp.get(b"/remote.bin", local)

    assert moved.transferred == 64
    assert moved.size_check is SizeCheck.MATCHED
    assert local.read_bytes() == b"y" * 64


async def test_a_resumed_download_compares_the_whole_file_not_the_remainder(tmp_path: Path):
    """The off-by-one that would break every resume, pinned.

    ``get`` returns bytes written *by this call*, so on a resume that is the remainder.
    Comparing the remainder against the file's size would fail every resume that ever
    succeeded -- so the comparison is ``start + transferred``, and this is the test that says
    so. It fails against the naive spelling and passes against the shipped one.
    """
    server = LyingServer(content=b"z" * 100)
    local = tmp_path / "partial.bin"
    local.write_bytes(b"z" * 40)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        moved = await sftp.get(b"/remote.bin", local, resume=True)

    assert moved.transferred == 60, "the remainder, not the whole file"
    assert moved.size == 100, "and `size` is the whole file, which is why it exists"
    assert moved.size_check is SizeCheck.MATCHED
    assert local.read_bytes() == b"z" * 100


# --- uploading --------------------------------------------------------------------------------


async def test_a_truncated_upload_is_refused_before_it_can_be_published(tmp_path: Path):
    """The check runs on the staging file, so the destination is never renamed into place.

    Checking the destination *afterwards* would report a truncation a consumer can already
    read, which is the exact failure atomic publish exists to prevent. This asserts the
    ordering by asserting the outcome: no rename was ever attempted.
    """
    source = tmp_path / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")  # 14 bytes
    server = LyingServer(stated_size=9)  # accepts the writes, then claims it holds 9

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(
                source, b"/incoming/report.csv", publish=Publish(staging_name=b".staged")
            )

    # The error names the *staging* path, resolved as a sibling of the destination, because
    # that is the file whose length was measured and the one an operator would go looking for.
    assert exc.value.args[0] == (
        "uploaded 14 bytes but b'/incoming/.staged' is 9 bytes on the server; "
        "the transfer was truncated or the file changed underneath it"
    )
    assert exc.value.remote_path == b"/incoming/.staged"
    # The state, and it is the *server's* count on both fields rather than what was sent: the
    # message already says how many bytes went out, and what a caller needs from the fields is
    # where the file actually ends. Neither was asserted anywhere, so both could be nulled.
    assert exc.value.transferred == 9
    assert exc.value.offset == 9
    assert "posix-rename@openssh.com" not in server.kinds, "a short upload was published"
    assert "Rename" not in server.kinds
    # The staging file goes, because on this path the destination was never touched and the
    # staged bytes are known-bad. That is the ordinary cleanup path, not the one that keeps
    # the file -- which exists only for the window where the destination has already been
    # removed and the staged copy is the only one.
    assert "Remove" in server.kinds


async def test_a_whole_upload_reports_the_length_as_matched(tmp_path: Path):
    source = tmp_path / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")
    server = LyingServer(stated_size=14)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/report.csv", publish=Publish(staging_name=b".staged")
        )

    assert result.size_check is SizeCheck.MATCHED
    assert result.mechanism is PublishMechanism.POSIX_RENAME


async def test_an_upload_to_a_server_that_reports_no_size_is_unavailable_not_failed(
    tmp_path: Path,
):
    # "The server would not say" is not "the upload failed". It is reported rather than
    # swallowed, which is the difference between this and having no check at all.
    source = tmp_path / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")
    server = LyingServer(no_size=True)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/report.csv", publish=Publish(staging_name=b".staged")
        )

    assert result.size_check is SizeCheck.UNAVAILABLE
    assert result.mechanism is PublishMechanism.POSIX_RENAME


async def test_an_upload_whose_stat_is_refused_is_unavailable_not_failed(tmp_path: Path):
    """The errored state of the predicate, decided explicitly and tested.

    A server that refuses to STAT the file it just accepted has told us nothing about its
    length -- it has not told us the write failed. Propagating would also replace the
    diagnosis on the publish fallback path, where the rename's refusal is the error the caller
    needs to see.
    """
    source = tmp_path / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")
    server = LyingServer(refuse_stat=True)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/report.csv", publish=Publish(staging_name=b".staged")
        )

    assert result.size_check is SizeCheck.UNAVAILABLE
    assert result.mechanism is PublishMechanism.POSIX_RENAME


async def test_an_in_place_upload_is_checked_too(tmp_path: Path):
    # It can only be checked afterwards -- the destination is the file being written -- but it
    # is still checked, and a caller who chose atomic=False did not thereby ask for a
    # truncation to go unreported.
    source = tmp_path / "report.csv"
    source.write_bytes(b"id,total\n1,42\n")
    server = LyingServer(stated_size=3)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, b"/incoming/report.csv", publish=Publish(atomic=False))

    assert exc.value.args[0] == (
        "uploaded 14 bytes but b'/incoming/report.csv' is 3 bytes on the server; "
        "the transfer was truncated or the file changed underneath it"
    )


# --- whole trees --------------------------------------------------------------------------
#
# D-71. `get_tree` and `put_tree` inherit rung 3 by delegation -- they call `get` and `put` per
# file -- and until 0.8 that inheritance was established by reading the code rather than by a
# test. A later change giving either its own inner transfer loop would drop the check silently
# and every test above would still pass. These are the tests that would go red.
#
# Note what shape the proof has to take: `TreeResult` carries no `size_check`, so a tree cannot
# *report* the verdict, only fail on it. Both cases therefore assert the raise -- and assert the
# tree stopped, because an error that gets swallowed into `skipped` would satisfy a bare
# `pytest.raises` on the wrong grounds.


async def test_a_truncated_file_fails_put_tree_and_stops_it(tmp_path: Path):
    source = tmp_path / "outgoing"
    source.mkdir()
    (source / "a.csv").write_bytes(b"id,total\n1,42\n")  # 14 bytes
    (source / "b.csv").write_bytes(b"id,total\n2,17\n")  # 14 bytes
    server = LyingServer(stated_size=9)  # accepts the writes, then claims it holds 9

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put_tree(source, b"/incoming", publish=Publish(atomic=False))

    assert exc.value.args[0] == (
        "uploaded 14 bytes but b'/incoming/a.csv' is 9 bytes on the server; "
        "the transfer was truncated or the file changed underneath it"
    )
    # The second file was never opened. That is the assertion that separates "the check ran and
    # the error propagated" from "the check ran and put_tree carried on to the next file".
    assert server.opened == [b"/incoming/a.csv"]


async def test_a_short_file_fails_get_tree_and_stops_it(tmp_path: Path):
    # The server lists two files and claims 14 bytes for each, then serves 9. The first one is
    # short, so the tree must fail on it rather than write a truncated file and continue.
    server = LyingServer(content=b"id,total\n", stated_size=14, entries=(b"a.csv", b"b.csv"))

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get_tree(b"/outgoing", tmp_path / "landing")

    assert exc.value.args[0] == (
        "b'/outgoing/a.csv' is 14 bytes but the download ended after 9; "
        "it was truncated or the file shrank underneath it"
    )
    assert server.opened == [b"/outgoing/a.csv"]


async def test_a_tree_whose_server_will_not_stat_is_not_reported_as_unverified(
    tmp_path: Path,
):
    """The decision D-71 asked for, recorded as a test so it cannot drift into an accident.

    ``put`` distinguishes "the lengths agreed" from "the server would not say" -- that is why
    :class:`SizeCheck` is an enum rather than a boolean. ``put_tree`` **discards that**: it
    keeps ``result.transferred`` from each :class:`UploadResult` and drops ``size_check``, so a
    tree of ten thousand files onto a server that refuses every ``STAT`` completes with
    ``complete is True`` and no indication that rung 3 never happened.

    That is a real loss of information and it is deliberate. **The reason it used to be
    deliberate has expired and the decision was re-taken rather than inherited** (D-99): the
    old argument was that only ``put_tree`` has a per-file verdict to aggregate, because
    ``get`` returned an ``int``; ``get`` now returns a
    :class:`~gantry_sftp.session.DownloadResult` and ``get_tree`` drops it in exactly the same
    way. What holds the line now is memory: ``TreeResult.skipped`` is bounded by the number of
    *problems* and is worth carrying in full, per-file results are bounded by the number of
    *files*, and a tree of a hundred thousand of them should not cost a hundred thousand
    objects for a report almost nobody reads.

    What would change it: a caller who needs the distinction, for whom the answer today is to
    call ``get`` or ``put`` per file and keep the results -- which is what the consumer behind
    D-99 does. Until then this test pins the behaviour so the gap is visible in the suite
    rather than only in a card.
    """
    source = tmp_path / "outgoing"
    source.mkdir()
    (source / "a.csv").write_bytes(b"id,total\n1,42\n")
    server = LyingServer(refuse_stat=True)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put_tree(source, b"/incoming", publish=Publish(atomic=False))

    assert result.files == 1
    assert result.transferred == 14
    assert result.complete, "a refused STAT is not a skipped file"
    assert not hasattr(result, "size_check"), (
        "TreeResult grew a size-check field -- update this test and the reasoning above"
    )


# --- against a real server ----------------------------------------------------------------


async def test_an_honest_round_trip_passes_the_check_on_a_real_server(tmp_path: Path):
    """The half a lying fake cannot prove: that the check does not *mis*fire.

    Every test above drives a server built to disagree with itself, so all of them would pass
    against an implementation that raised unconditionally. This one moves a real file through
    a real ``sftp-server`` in both directions and asserts the check is satisfied -- including
    a size that is not a round number and spans several requests, since a check that only
    works when the file fits one READ is a check with an off-by-one waiting in it.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(300_001)
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    destination = tmp_path / "downloaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(tmp_path / "uploaded.bin"))
        moved = await sftp.get(str(tmp_path / "uploaded.bin"), destination)

    assert result.size_check is SizeCheck.MATCHED
    assert moved.size_check is SizeCheck.MATCHED
    assert moved.transferred == len(content)
    assert destination.read_bytes() == content

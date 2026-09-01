"""Rungs 1 and 2 of DESIGN.md 6's ladder, and the resume gate that section asks for by name.

``tests/test_verification.py`` covers rung 3, the length comparison. This module covers the
two rungs that check **content**, and the reason they are a separate concern is the failure
they catch: a file of exactly the right length whose bytes are wrong passes rung 3 every time.

Two things are proved here that nothing else in the suite could.

**The resume gate.** ``put(resume=True)`` establishes its offset from the size the server
reports, which proves the byte *count* agrees and nothing else. What it could not refuse was a
remote partial of the right length from the wrong source -- a previous run against a different
file, a truncated staging file, a concurrent writer. That upload completed, published, and
passed rung 3, because the finished length was correct. DESIGN.md 6 said in as many words to
gate resume on a content rung where one is available; until D-38 nothing consulted one, even on
the server where it existed.

**The fallback, as the tested path rather than the theoretical one.** CLAUDE.md's rule for
every extension is that its absence gets a documented degrade and a test that exercises it.
``check-file`` is absent from nearly every endpoint in the field -- OpenSSH answers
``OP_UNSUPPORTED`` under all three spellings -- so the case where the gate cannot run is the
*common* one and it is scripted here both ways round.

The scripted server is what makes the mismatch case reachable at all. A conformant server
cannot be asked to hold bytes that disagree with the ones it was sent, so an honest-server lane
proves only that the check does not misfire; that half is in ``tests/test_real_sftp_server.py``
and ``live-tests/test_matrix.py``, against a real ``sftp-server`` and against paramiko, which is
the only implementation of ``check-file`` this project can reach.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    CheckFile,
    Close,
    Data,
    Extended,
    ExtendedReply,
    FrameSplitter,
    Handle,
    Init,
    LStat,
    Open,
    OpenFlag,
    Read,
    Stat,
    Status,
    StatusCode,
    Version,
    WireWriter,
    Write,
    decode,
    encode,
)
from gantry_sftp.exceptions import (
    ProtocolError,
    TransferError,
    TransferTimeoutError,
    UnsupportedError,
)
from gantry_sftp.session import (
    CHECK_FILE_BLOCK_SIZE,
    ContentCheck,
    Publish,
    ResumeCheck,
    SizeCheck,
    Verify,
    open_session,
)
from gantry_sftp.session._verify import (
    block_bounds,
    hashes_agree,
    local_block_digests,
    ranges_equal,
    reread_agrees,
    verify_downloaded_content,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

CHECK_FILE = b"check-file"


def sha1(data: bytes) -> bytes:
    """The algorithm paramiko actually offers, so the fake offers the same one."""
    return hashlib.sha1(data, usedforsecurity=False).digest()


class HashingServer:
    """A server that answers ``check-file``, and can hold bytes it was never sent.

    The second half is the point. Everything about a wrong-source resume is invisible from
    lengths alone, so a fake that stores what it receives could not stage the failure: it needs
    to *already hold* content of the right size and the wrong bytes, which is what ``holds``
    is. ``advertises`` turns the extension off to exercise the fallback, which is the field's
    common case rather than an edge one.

    ``refuses_check`` is the third state of the predicate -- advertised and then declined,
    which is what a server with no algorithm in common does. It must degrade to "unavailable",
    never to "verified" and never to a failed transfer.

    ``advertises`` and ``implements`` are separate because D-51 turns on the difference. This
    library now *asks* rather than reading the advertisement, so "does not list it" and "does
    not have it" produce different exchanges and must be modelled separately -- a fake that
    conflated them would agree with a client that skipped the question.

    Writes land in :attr:`holds` at their offset, so the file grows the way a real one does and
    rung 3 keeps passing -- which is the point, since every failure here has to be one rung 3
    cannot see. ``corrupts`` breaks that link: the bytes are counted and discarded, so the
    server keeps whatever it was given to hold. Set its length to the local file's and you have
    the only failure that matters -- the right number of the wrong bytes.

    ``serves`` is the same trick pointed the other way, for the download side: READ answers
    from it while ``check-file`` still hashes ``holds``. Same length, different bytes, and a
    ``get`` lands a file that passes rung 3 and fails rung 1 -- which is the failure a download
    could not report at all until ``get`` returned something with a field for it (D-99).
    """

    def __init__(
        self,
        *,
        holds: bytes = b"",
        advertises: bool = True,
        implements: bool | None = None,
        refuses_check: bool = False,
        corrupts: bool = False,
        serves: bytes | None = None,
    ) -> None:
        self.holds = bytearray(holds)
        self.serves = bytearray(holds if serves is None else serves)
        self.advertises = advertises
        self.implements = advertises if implements is None else implements
        self.refuses_check = refuses_check
        self.corrupts = corrupts
        self.written = bytearray()
        self.kinds: list[str] = []
        self.opened: list[bytes] = []
        self.checks: list[CheckFile] = []
        self.renamed = False
        self.removed: list[bytes] = []
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
            extensions = ((CHECK_FILE, b"2"),) if self.advertises else ()
            self._reply(Version(3, extensions))
            return
        self.kinds.append(
            packet.name.decode() if isinstance(packet, Extended) else type(packet).__name__
        )
        self._handle(packet)

    def _check_file(self, packet: Extended) -> None:
        """Hash what this server *holds*, blocked exactly the way paramiko blocks it."""
        request = CheckFile.from_extended(packet)
        self.checks.append(request)
        if not self.implements:
            self._reply(Status(request.request_id, StatusCode.OP_UNSUPPORTED, b"Unsupported"))
            return
        if self.refuses_check:
            self._reply(Status(request.request_id, StatusCode.FAILURE, b"No supported hash types"))
            return
        end = len(self.holds) if request.length == 0 else request.start_offset + request.length
        size = request.block_size or (end - request.start_offset)
        digests = b"".join(
            sha1(bytes(self.holds[offset : min(offset + size, end)]))
            for offset in range(request.start_offset, end, size)
        )
        writer = WireWriter()
        writer.write_string(CHECK_FILE)
        writer.write_string(b"sha1")
        writer.write_bytes(digests)
        self._reply(ExtendedReply(request.request_id, writer.getvalue()))

    def _handle(self, packet: object) -> None:
        rid = packet.request_id  # type: ignore[union-attr]
        if isinstance(packet, Stat | LStat):
            self._reply(AttrsReply(rid, Attrs(size=len(self.holds))))
        elif isinstance(packet, Open):
            self.opened.append(packet.filename)
            self._reply(Handle(rid, b"h"))
        elif isinstance(packet, Read):
            chunk = bytes(self.serves[packet.offset : packet.offset + packet.length])
            self._reply(Data(rid, memoryview(chunk)) if chunk else Status(rid, StatusCode.EOF))
        elif isinstance(packet, Write):
            self.written += packet.data
            if not self.corrupts:
                # At the offset, not appended: writes arrive out of order under pipelining, and
                # a fake that appends would make a scrambled upload look correct.
                end = packet.offset + len(packet.data)
                self.holds.extend(bytes(end - len(self.holds)) if end > len(self.holds) else b"")
                self.holds[packet.offset : end] = packet.data
                self.serves = self.holds
            self._reply(Status(rid, StatusCode.OK))
        elif isinstance(packet, Extended) and packet.name == CHECK_FILE:
            self._check_file(packet)
        elif isinstance(packet, Extended):
            # posix-rename answers a STATUS rather than an EXTENDED_REPLY. Everything else is
            # refused, so the upload takes the no-fsync path.
            if packet.name.startswith(b"posix-rename"):
                self.renamed = True
                self._reply(Status(rid, StatusCode.OK))
            else:
                self._reply(Status(rid, StatusCode.OP_UNSUPPORTED, b"no"))
        elif isinstance(packet, Close):
            self._reply(Status(rid, StatusCode.OK))
        else:
            self._reply(Status(rid, StatusCode.OK))


# --- the arithmetic both rungs share ------------------------------------------------------------


def test_block_bounds_starts_every_block_and_stops_at_the_range_end():
    # The last block is short, and getting that wrong is the whole failure mode: a digest over
    # a padded final block matches nothing the server sent.
    assert block_bounds(0, 10, 4) == [0, 4, 8]
    assert block_bounds(100, 8, 4) == [100, 104]
    assert block_bounds(0, 4, 4) == [0]


def test_block_bounds_of_an_empty_range_is_no_blocks_at_all():
    # Not one empty block. An empty range must produce no request and no digest, because
    # `length=0` on the wire means "to the end of the file" -- the opposite of "nothing".
    assert block_bounds(0, 0, 4) == []
    assert block_bounds(500, 0) == []


def test_block_bounds_refuses_a_block_size_that_would_not_terminate():
    with pytest.raises(ValueError) as exc:
        _ = block_bounds(0, 10, 0)
    assert exc.value.args[0] == "block_size must be at least 1, got 0"


async def test_local_block_digests_match_hashlib_block_for_block(tmp_path: Path):
    # Every 1 KiB block distinct. A repeating pattern would hash identically block for
    # block, and the ordering assertion below could not then have failed.
    payload = b"".join(bytes([n]) * 1024 for n in range(10))
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)

    digests = await local_block_digests(
        source, b"sha1", start=0, length=len(payload), block_size=1024
    )

    assert digests == tuple(
        sha1(payload[offset : offset + 1024]) for offset in range(0, len(payload), 1024)
    )
    # Distinct blocks, or an ordering bug could not have failed the assertion above.
    assert len(set(digests)) == len(digests)


async def test_local_block_digests_hash_only_the_range_they_were_given(tmp_path: Path):
    payload = bytes(range(256)) * 8
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)

    assert await local_block_digests(source, b"sha1", start=300, length=500, block_size=4096) == (
        sha1(payload[300:800]),
    )


async def test_local_block_digests_refuse_an_algorithm_this_python_cannot_compute(tmp_path: Path):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"x" * 16)

    with pytest.raises(ValueError):
        _ = await local_block_digests(source, b"blake3-not-real", start=0, length=16)


async def test_ranges_equal_compares_and_stops_at_the_first_difference(tmp_path: Path):
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"a" * 4096)
    right.write_bytes(b"a" * 4096)
    fd = os.open(left, os.O_RDONLY)
    try:
        assert await ranges_equal(fd, right, start=0, length=4096, block_size=1024) is True
        right.write_bytes(b"a" * 4095 + b"b")
        assert await ranges_equal(fd, right, start=0, length=4096, block_size=1024) is False
        # The difference is outside the compared range, so the range still agrees.
        assert await ranges_equal(fd, right, start=0, length=1024, block_size=1024) is True
    finally:
        os.close(fd)


# --- the resume gate --------------------------------------------------------------------------


async def test_a_resumed_upload_onto_a_wrong_source_partial_is_refused(tmp_path: Path):
    """The headline. Without the gate this publishes a file of the right length and wrong bytes.

    The server holds 64 bytes that are *not* a prefix of the local file. Resume adopts them on
    the strength of the size alone, sends the remaining bytes, and the size check at the end
    passes -- because the finished length is correct. Nothing anywhere reports a problem.
    """
    server = HashingServer(holds=b"WRONG!! " * 8)
    source = tmp_path / "right.bin"
    source.write_bytes(b"correct " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(
                source, b"/incoming/file.bin", publish=Publish(atomic=False), resume=True
            )

    assert exc.value.args[0] == (
        "cannot resume: the 64 bytes already at b'/incoming/file.bin' are not a prefix of "
        f"{source} -- the partial is from a different source file or a different run, and "
        "continuing would publish a file of the right length and the wrong contents. Upload "
        "without resume=True to replace it"
    )
    assert exc.value.transferred == 0
    assert exc.value.offset == 64
    assert exc.value.remote_path == b"/incoming/file.bin"
    assert exc.value.local_path == str(source)
    # Refused *before* anything was opened for writing, which is the placement decision: a gate
    # that first truncates what it is about to reject is not a gate.
    assert server.written == b""
    assert server.opened == [b"/incoming/file.bin"], "only the read-only probe should have opened"


async def test_a_resumed_upload_onto_a_matching_prefix_proceeds_and_says_so(tmp_path: Path):
    payload = b"correct " * 16
    server = HashingServer(holds=payload[:64])
    source = tmp_path / "right.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), resume=True
        )

    assert result.resume_check is ResumeCheck.MATCHED
    assert bytes(server.written) == payload[64:], "only the remainder should have been sent"
    # The request the gate sent: the whole adopted prefix, blocked at the only size paramiko
    # answers correctly, and never `block_size=0`.
    assert len(server.checks) == 1
    assert server.checks[0].start_offset == 0
    assert server.checks[0].length == 64
    assert server.checks[0].block_size == CHECK_FILE_BLOCK_SIZE


async def test_a_resume_degrades_to_unavailable_where_the_server_has_no_check_file(tmp_path: Path):
    """CLAUDE.md's rule for every extension: the absent case is the *tested* path.

    This is also the common case in the field, not the edge one -- OpenSSH answers
    ``OP_UNSUPPORTED`` to ``check-file`` under all three spellings, and it is the reference
    server. The resume must still work, on the size match alone, and must report that the
    stronger claim was not made.
    """
    payload = b"correct " * 16
    server = HashingServer(holds=payload[:64], advertises=False, implements=False)
    source = tmp_path / "right.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), resume=True
        )

    assert result.resume_check is ResumeCheck.UNAVAILABLE
    assert bytes(server.written) == payload[64:]
    # Asked once and refused, rather than not asked (D-51). The old assertion here was that
    # nothing reached the wire, which is the same answer for this server and the wrong one for
    # a server that implements the extension and does not list it.
    assert len(server.checks) == 1


async def test_a_server_that_advertises_and_then_refuses_is_unavailable_not_a_failure(
    tmp_path: Path,
):
    # The errored third state of the predicate, decided explicitly. A server with no algorithm
    # in common has told us nothing about the bytes; it has not told us they are wrong.
    payload = b"correct " * 16
    server = HashingServer(holds=payload[:64], refuses_check=True)
    source = tmp_path / "right.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), resume=True
        )

    assert result.resume_check is ResumeCheck.UNAVAILABLE
    assert bytes(server.written) == payload[64:]


async def test_a_resume_with_nothing_on_the_server_yet_checks_nothing(tmp_path: Path):
    """A zero-length prefix must never reach the wire: ``length=0`` there means "to EOF".

    Sending it would ask the server to hash the entire file and compare that against no local
    blocks at all -- a check that cannot pass, on the ordinary first attempt of a resumable
    upload.
    """
    payload = b"correct " * 16
    server = HashingServer(holds=b"")
    source = tmp_path / "right.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), resume=True
        )

    assert result.resume_check is ResumeCheck.SKIPPED
    assert server.checks == []
    assert bytes(server.written) == payload


async def test_an_upload_that_does_not_resume_reports_a_skipped_gate(tmp_path: Path):
    server = HashingServer(holds=b"")
    source = tmp_path / "right.bin"
    source.write_bytes(b"correct " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, b"/incoming/file.bin", publish=Publish(atomic=False))

    assert result.resume_check is ResumeCheck.SKIPPED
    assert result.content_check is ContentCheck.SKIPPED
    assert server.checks == []


async def test_a_refused_resume_leaves_the_staging_file_alone(tmp_path: Path):
    """The atomic path's placement decision, asserted rather than assumed.

    The gate runs outside the ``try`` that discards the staging file. Inside it, a rejected
    prefix would delete the very file the caller named under ``resume=`` -- which may be
    another publisher's, and is the only evidence of what went wrong. Refusing must not also
    destroy.
    """
    server = HashingServer(holds=b"WRONG!! " * 8)
    source = tmp_path / "right.bin"
    source.write_bytes(b"correct " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError):
            _ = await sftp.put(
                source,
                b"/incoming/file.bin",
                publish=Publish(staging_name=b"/incoming/.partial"),
                resume=True,
            )

    assert "Remove" not in server.kinds, "the staging file must survive a refusal"
    assert server.written == b""


async def test_a_download_resuming_onto_a_wrong_local_partial_is_refused(tmp_path: Path):
    """The same gate on the direction that is usually assumed safe.

    The local partial being *ours* makes its length trustworthy. It does not make its contents
    a prefix of this remote file, and a partial left by a previous run against a different
    source is the same corruption with the arrow reversed.
    """
    remote = b"correct " * 16
    server = HashingServer(holds=remote)
    local = tmp_path / "partial.bin"
    local.write_bytes(b"WRONG!! " * 8)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(b"/remote.bin", local, resume=True)

    assert exc.value.args[0] == (
        f"cannot resume: the 64 bytes already at b'/remote.bin' are not a prefix of {local} -- "
        "the partial is from a different source file or a different run, and continuing would "
        "publish a file of the right length and the wrong contents. Upload without resume=True "
        "to replace it"
    )
    # The bad partial is left exactly as it was: it is the caller's file and the only evidence.
    assert local.read_bytes() == b"WRONG!! " * 8


async def test_a_download_that_is_already_complete_is_still_gated(tmp_path: Path):
    """The case that adopts the *entire* file and returns success having moved nothing.

    That makes it the one most worth gating rather than the one to skip for a round trip, and
    it is the shape a retry loop hits every time it re-runs a finished transfer.
    """
    remote = b"correct " * 16
    server = HashingServer(holds=remote)
    local = tmp_path / "complete.bin"
    local.write_bytes(b"WRONG!! " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(b"/remote.bin", local, resume=True)

    assert exc.value.offset == 128


# --- rung 1 and rung 2 as a content check ------------------------------------------------------


async def test_verify_hash_reports_the_rung_it_reached(tmp_path: Path):
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.HASH
        )

    assert result.content_check is ContentCheck.HASHED


async def test_verify_hash_is_unavailable_rather_than_passed_without_the_extension(tmp_path: Path):
    # The distinction the whole ladder exists for: "not checked" must never come back looking
    # like "checked and fine". This is what almost every real endpoint answers.
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.HASH
        )

    assert result.content_check is ContentCheck.UNAVAILABLE


async def test_verify_hash_reaches_a_server_that_implements_it_without_advertising(
    tmp_path: Path,
):
    """Rung 1 against the population it is most likely to be available on and least likely to
    be advertised by (D-51).

    Gating on the advertisement meant a server that would have hashed the file was reported
    as unable to -- the caller asked for content verification, the server could do it, and the
    answer came back "unavailable" without anyone asking.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False, implements=True)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.HASH
        )

    assert result.content_check is ContentCheck.HASHED
    assert len(server.checks) == 1


async def test_a_refused_check_file_is_asked_once_for_the_whole_session(tmp_path: Path):
    """Two uploads, one question. The cache is what makes attempting affordable.

    Verification asks per file, so without this every upload in a batch spends an OPEN, an
    EXTENDED and a CLOSE to be told the same thing -- three round trips per file, 200 ms each
    on the profile the netem lane measures, for an answer that cannot have changed.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False, implements=False)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        first = await sftp.put(
            source, b"/incoming/one.bin", publish=Publish(atomic=False), verify=Verify.HASH
        )
        second = await sftp.put(
            source, b"/incoming/two.bin", publish=Publish(atomic=False), verify=Verify.HASH
        )

    assert first.content_check is ContentCheck.UNAVAILABLE
    assert second.content_check is ContentCheck.UNAVAILABLE
    assert len(server.checks) == 1, "the second upload re-asked a settled question"


async def test_verify_reread_reads_the_bytes_back_and_compares_them(tmp_path: Path):
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.REREAD
        )

    assert result.content_check is ContentCheck.REREAD


async def test_verify_reread_needs_no_extension_at_all(tmp_path: Path):
    """Rung 2's whole reason for existing: it works where rung 1 does not, which is everywhere.

    Nothing is advertised here and the check still runs, because it asks for nothing but READ.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.REREAD
        )

    assert result.content_check is ContentCheck.REREAD
    assert server.checks == []


async def test_content_of_the_right_length_and_the_wrong_bytes_is_refused(tmp_path: Path):
    """The failure rung 3 cannot see, and the reason these are separate fields.

    The server holds the right number of bytes and the wrong ones. The size check passes.
    """
    server = HashingServer(holds=b"WRONG!! " * 16, corrupts=True)
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(
                source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.HASH
            )

    assert exc.value.args[0] == (
        f"b'/incoming/file.bin' does not hold the contents of {source}: it is 128 bytes long, "
        "as it should be, and the bytes differ. The upload is corrupt rather than short, which "
        "is the failure a size check cannot see"
    )
    assert exc.value.transferred == 128
    assert exc.value.remote_path == b"/incoming/file.bin"


async def test_corrupt_content_never_becomes_the_destination(tmp_path: Path):
    """Same argument as rung 3's, one rung up: the check runs against the staging file.

    Publishing and *then* reporting corruption would report it to a consumer who can already
    read it, which is the failure atomic publish exists to prevent.
    """
    server = HashingServer(holds=b"WRONG!! " * 16, corrupts=True)
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError):
            _ = await sftp.put(source, b"/incoming/file.bin", verify=Verify.HASH)

    assert not server.renamed, "the rename must not have happened"
    assert b"Remove" in b"".join(k.encode() for k in server.kinds), "the staging file is discarded"


# --- the same two rungs, on the download ------------------------------------------------------
#
# `get(verify=)` did not exist until D-99, and the blocker was the return type rather than the
# machinery: both rungs compare a remote range against a local one and have always been
# direction-agnostic. What `get` had nowhere to report was `unavailable`, and a content check
# that silently passes when it did not happen is the outcome DESIGN.md 6 exists to prevent.


async def test_a_download_verify_hash_reports_the_rung_it_reached(tmp_path: Path):
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get(b"/remote.bin", local, verify=Verify.HASH)

    assert result.content_check is ContentCheck.HASHED
    assert result.size_check is SizeCheck.MATCHED
    assert local.read_bytes() == payload


async def test_a_download_verify_hash_is_unavailable_without_the_extension(tmp_path: Path):
    """The answer nearly every real endpoint gives, and the reason the field is not a bool.

    Nothing here fails: the file arrives, its length is checked, and the content check reports
    that it could not run. Returning ``True`` would be a lie and raising would refuse a working
    server over a missing optional extension.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False, implements=False)
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get(b"/remote.bin", local, verify=Verify.HASH)

    assert result.content_check is ContentCheck.UNAVAILABLE
    assert result.size_check is SizeCheck.MATCHED, "rung 3 still ran; only rung 1 was missing"
    assert local.read_bytes() == payload


async def test_a_download_of_the_right_length_and_the_wrong_bytes_is_refused(tmp_path: Path):
    """The failure a download could not previously report, staged the only way it can be.

    The server serves one thing and hashes another, both the same length, so rung 3 passes on
    the way past and rung 1 is the only thing between the caller and a plausible wrong file.
    """
    server = HashingServer(holds=b"correct " * 16, serves=b"WRONG!! " * 16)
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(b"/remote.bin", local, verify=Verify.HASH)

    assert exc.value.args[0] == (
        f"{local} does not hold the contents of b'/remote.bin': it is 128 bytes long, as it "
        "should be, and the bytes differ. The download is corrupt rather than short, which is "
        "the failure a size check cannot see"
    )
    assert exc.value.transferred == 128
    assert exc.value.remote_path == b"/remote.bin"
    assert exc.value.local_path == str(local)
    # Left on disk: it is the caller's file and the only evidence of what arrived.
    assert local.read_bytes() == b"WRONG!! " * 16


async def test_a_download_verify_reread_needs_no_extension_at_all(tmp_path: Path):
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False, implements=False)
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get(b"/remote.bin", local, verify=Verify.REREAD)

    assert result.content_check is ContentCheck.REREAD
    assert server.checks == []
    assert local.read_bytes() == payload


async def test_a_download_verifies_nothing_by_default(tmp_path: Path):
    # The default is the behaviour every release before 0.11 had. What is new is that it says
    # so instead of being indistinguishable from a check that passed.
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get(b"/remote.bin", local)

    assert result.content_check is ContentCheck.SKIPPED
    assert server.checks == [], "the default must not cost a round trip"


async def test_a_download_verify_selects_the_rung_the_resume_gate_uses(tmp_path: Path):
    """``verify=`` steers the resume gate too, which is what ``put``'s has always done.

    Rung 2 needs no extension, so a server with no ``check-file`` gates on ``REREAD`` rather
    than degrading to ``UNAVAILABLE`` -- the one case where asking for the more expensive rung
    buys a stronger claim about the bytes already on disk.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False, implements=False)
    local = tmp_path / "partial.bin"
    local.write_bytes(payload[:64])

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        degraded = await sftp.get(b"/remote.bin", tmp_path / "a.bin", resume=True)
        result = await sftp.get(b"/remote.bin", local, resume=True, verify=Verify.REREAD)

    assert degraded.resume_check is ResumeCheck.SKIPPED, "nothing was on disk to adopt"
    assert result.resume_check is ResumeCheck.MATCHED
    assert result.adopted == 64
    assert local.read_bytes() == payload


async def test_a_resume_that_adopts_the_whole_file_reports_the_gate_as_the_content_check(
    tmp_path: Path,
):
    """The one place the two fields are the same measurement, and it is not an inference.

    A resume of an already-complete file compares every byte against the remote one at the rung
    ``verify`` names, and then returns without opening anything. Re-running that comparison to
    populate ``content_check`` separately would be a duplicate -- and under ``REREAD`` a
    duplicate is a second full download.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    local = tmp_path / "complete.bin"
    local.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        hashed = await sftp.get(b"/remote.bin", local, resume=True, verify=Verify.HASH)
        default = await sftp.get(b"/remote.bin", local, resume=True)

    assert hashed.transferred == 0
    assert hashed.resume_check is ResumeCheck.MATCHED
    assert hashed.content_check is ContentCheck.HASHED

    # `Verify.SIZE` still reports SKIPPED even though the gate opportunistically hashes,
    # matching `put`: this field answers what the *caller asked for* and found.
    assert default.resume_check is ResumeCheck.MATCHED
    assert default.content_check is ContentCheck.SKIPPED


# --- the knob itself ---------------------------------------------------------------------------


async def test_verify_accepts_the_string_spelling(tmp_path: Path):
    # `Verify` is a StrEnum, so `verify="reread"` arrives as a plain `str` from anyone not
    # running a type checker. It is normalised rather than compared loosely, because
    # `verify is Verify.REREAD` would otherwise be False while `==` was True.
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source,
            b"/incoming/file.bin",
            publish=Publish(atomic=False),
            verify="reread",  # type: ignore[arg-type]
        )

    assert result.content_check is ContentCheck.REREAD


async def test_a_download_verify_accepts_the_string_spelling(tmp_path: Path):
    """The same normalisation on the download, where getting it wrong is worse than on `put`.

    ``get``'s rung ladder falls through to rung 2 if neither named rung matches, so an
    un-normalised ``verify="size"`` -- the *default*, spelled as a string -- would silently
    download the file a second time. Both spellings are asserted here rather than only the
    interesting one, because the failure lands on the boring one.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        reread = await sftp.get(b"/remote.bin", tmp_path / "a.bin", verify="reread")  # type: ignore[arg-type]
        default = await sftp.get(b"/remote.bin", tmp_path / "b.bin", verify="size")  # type: ignore[arg-type]

    assert reread.content_check is ContentCheck.REREAD
    assert default.content_check is ContentCheck.SKIPPED


async def test_an_unknown_verify_name_on_a_download_is_refused_rather_than_ignored(
    tmp_path: Path,
):
    # A silently ignored `verify="hsah"` is a download the caller believes was verified, and
    # here it would also cost a full second transfer while being wrong about it.
    server = HashingServer(holds=b"payload " * 16)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as exc:
            _ = await sftp.get(b"/remote.bin", tmp_path / "out.bin", verify="hsah")  # type: ignore[arg-type]

    assert exc.value.args[0] == "'hsah' is not a valid Verify"


async def test_an_unknown_verify_name_is_refused_rather_than_ignored(tmp_path: Path):
    # A silently ignored `verify="rerad"` is an upload the caller believes was verified. The
    # same argument the publish arguments make about a misspelled `atmoic`.
    server = HashingServer(holds=b"")
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as exc:
            _ = await sftp.put(
                source,
                b"/incoming/file.bin",
                verify="rerad",  # type: ignore[arg-type]
            )

    assert "'rerad' is not a valid Verify" in exc.value.args[0]


# --- against a real server ----------------------------------------------------------------


async def test_rung_2_verifies_an_honest_upload_through_a_real_server(tmp_path: Path):
    """The half a scripted server cannot prove: that the check does not *mis*fire.

    Every case above drives a fake built to disagree with itself, so all of them would pass
    against an implementation that raised unconditionally. This moves a real file through a
    real ``sftp-server`` -- which advertises no ``check-file`` at all, so it is also the
    documented degrade path running end to end -- and asserts rung 2 is satisfied.

    The size is deliberately not a round number and spans several requests. A re-read that
    only works when the file fits one READ has an off-by-one waiting in it, and the comparison
    is blocked at 64 KiB while the transfer is blocked at whatever the server negotiated, so
    the two blockings are not the same and must not be assumed to line up.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(300_001)
    source = tmp_path / "source.bin"
    source.write_bytes(content)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert not sftp.supports(b"check-file"), "OpenSSH must not have grown the extension"
        hashed = await sftp.put(source, str(tmp_path / "hashed.bin"), verify=Verify.HASH)
        reread = await sftp.put(source, str(tmp_path / "reread.bin"), verify=Verify.REREAD)

    # Rung 1 asked for and absent: unavailable, never "passed". That is the whole distinction.
    assert hashed.content_check is ContentCheck.UNAVAILABLE
    assert reread.content_check is ContentCheck.REREAD
    assert (tmp_path / "reread.bin").read_bytes() == content


async def test_a_real_server_resume_degrades_and_still_finishes_the_file(tmp_path: Path):
    """CLAUDE.md's every-extension rule, end to end: absent extension, documented fallback.

    The reference server has no ``check-file``, so the gate cannot run. What must not happen
    is the resume failing, or reporting that it verified something.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(200_003)
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    partial = tmp_path / "partial.bin"
    partial.write_bytes(content[:70_000])

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(partial), publish=Publish(atomic=False), resume=True)

    assert result.resume_check is ResumeCheck.UNAVAILABLE
    assert result.transferred == len(content) - 70_000, "only the remainder should have moved"
    assert partial.read_bytes() == content


# --- what `check_file` puts on the wire, and what it says when the answer is wrong ------------
#
# D-105's twelfth slice. `Session.check_file` carried 30 survivors, and they are this register's
# established theme for the fifth time: the *arguments* and the *carried state* of the errors,
# where the messages were already pinned. Two of them are the sharpest kind -- the offered
# algorithm name-list could be uppercased or emptied and nothing looked, and a server that
# supports none of what we offer answers FAILURE, which this library degrades to
# `ContentCheck.UNAVAILABLE`. So a mutation there turns rung 1 off everywhere while every test
# still passes, which is the silent downgrade DESIGN.md 6 exists to make impossible.


class ChoosesTheAlgorithm(HashingServer):
    """Answers `check-file` with an algorithm and digests of our choosing.

    `HashingServer` always answers `sha1` over the bytes it holds, which is what makes it a
    *conformant* fake. The two failures below are ones a conformant server cannot be asked for:
    an algorithm this Python cannot size, and a digest run that does not divide by the size of
    the algorithm the server named.
    """

    def __init__(self, *, holds: bytes, algorithm: bytes, digests: bytes) -> None:
        super().__init__(holds=holds)
        self.algorithm = algorithm
        self.digests = digests

    def _check_file(self, packet: Extended) -> None:
        request = CheckFile.from_extended(packet)
        self.checks.append(request)
        writer = WireWriter()
        writer.write_string(CHECK_FILE)
        writer.write_string(self.algorithm)
        writer.write_bytes(self.digests)
        self._reply(ExtendedReply(request.request_id, writer.getvalue()))


class AnswersWithTheWrongPacket(HashingServer):
    """Answers `check-file` with a STATUS of OK -- well-formed, and not an `EXTENDED_REPLY`."""

    def _check_file(self, packet: Extended) -> None:
        self.checks.append(CheckFile.from_extended(packet))
        self._reply(Status(packet.request_id, StatusCode.OK))


async def test_check_file_offers_the_algorithms_this_library_actually_supports():
    """The name-list on the wire, pinned as a value rather than as "some list".

    Uppercasing it is a legal string and an illegal name-list: the server matches the names it
    knows, finds none, and answers `FAILURE` -- which this library reports as
    `ContentCheck.UNAVAILABLE`, the same answer a server with no `check-file` at all gives. So
    rung 1 would stop running everywhere and every existing test would still pass.

    The three defaults beside it are pinned in the same call because they are what the
    *extension* means: `0` length is "to the end of the file" and `0` offset is "from the
    start", and either one becoming `1` silently hashes a different range than the caller asked
    about -- which a digest comparison then reports as corruption.
    """
    payload = b"payload " * 64
    server = HashingServer(holds=payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        _ = await sftp.check_file(handle)

    assert len(server.checks) == 1
    asked = server.checks[0]
    assert asked.algorithms == b"sha256,sha1,md5", "the offered name-list is a wire value"
    assert asked.start_offset == 0
    assert asked.length == 0, "0 is the wire spelling of 'to the end of the file'"
    assert asked.block_size == CHECK_FILE_BLOCK_SIZE


async def test_check_file_forwards_every_argument_it_was_given():
    """Each argument proven to *arrive*, which is not what pinning the defaults proves.

    `CheckFile` carries the same defaults this method does, so dropping any one of these from
    the request would send the right value anyway whenever the caller wanted the default. It is
    the caller who asked for something else that loses -- the fifth time this card has found a
    forwarded argument nobody proved arrives, after `_retry`'s tunables and `put_tree`'s
    `max_depth`. Four distinct values, so a *shift* onto the neighbouring field cannot pass
    either.
    """
    payload = b"payload " * 64
    server = HashingServer(holds=payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        _ = await sftp.check_file(
            handle, algorithms=b"sha1", start_offset=8, length=256, block_size=512
        )

    asked = server.checks[0]
    assert asked.algorithms == b"sha1"
    assert asked.start_offset == 8
    assert asked.length == 256
    assert asked.block_size == 512


async def test_a_settled_unsupported_refuses_the_next_call_without_asking_again():
    """The cache, asserted on the exception it raises rather than only on the round trip saved.

    `test_a_refused_check_file_is_asked_once_for_the_whole_session` already pins the round trip.
    What nothing pinned is what the caller is handed the second time: the message, and the
    `code` that makes `except UnsupportedError` mean `OP_UNSUPPORTED` rather than "some
    refusal". Both could be nulled or deleted with the round-trip assertion still passing.

    `advertises=False` since D-205: the answer is settled only when it came from a server that
    never claimed the extension. The advertising case is the next test.
    """
    server = HashingServer(holds=b"payload", advertises=False, implements=False)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        with pytest.raises(UnsupportedError) as first:
            _ = await sftp.check_file(handle)
        with pytest.raises(UnsupportedError) as second:
            _ = await sftp.check_file(handle)

    assert len(server.checks) == 1, "the second call re-asked a settled question"
    assert second.value.args[0] == (
        "this server has already answered OP_UNSUPPORTED for check-file"
    )
    assert second.value.code == StatusCode.OP_UNSUPPORTED
    # The first came from the server's own STATUS and the second from the cache, so they are
    # different code paths reaching the same class -- and only the second is this method's own.
    assert first.value.code == StatusCode.OP_UNSUPPORTED


async def test_an_advertised_check_file_that_declines_is_asked_again():
    """D-205. A server that advertised `check-file` and answers `OP_UNSUPPORTED` is declining
    this request, so nothing is settled: the second call is a second round trip, both refusals
    are the server's own, and `refuses()` never becomes true.
    """
    server = HashingServer(holds=b"payload", advertises=True, implements=False)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        for _ in range(2):
            with pytest.raises(UnsupportedError) as declined:
                _ = await sftp.check_file(handle)
            assert declined.value.args[0] != (
                "this server has already answered OP_UNSUPPORTED for check-file"
            )
        assert not sftp.refuses("check-file")

    assert len(server.checks) == 2, "the second call was answered from a cache"


async def test_a_check_file_answered_with_the_wrong_packet_names_what_was_expected():
    payload = b"payload " * 64
    server = AnswersWithTheWrongPacket(holds=payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        with pytest.raises(ProtocolError) as exc:
            _ = await sftp.check_file(handle)

    assert exc.value.args[0] == ("server answered with STATUS OK where EXTENDED_REPLY was expected")


async def test_an_algorithm_this_python_cannot_size_is_reported_with_the_frame_it_came_on():
    """The reply names an algorithm `hashlib` does not know, so the digests cannot be split.

    A `ProtocolError` rather than a `ServerError`: the server answered, and what it said cannot
    be read. The state matters more than the sentence -- `request_id` is what ties this to a
    frame in a dump, and it could be nulled with the message still reading perfectly.
    """
    server = ChoosesTheAlgorithm(holds=b"payload " * 64, algorithm=b"whirlpool9", digests=b"x" * 8)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        with pytest.raises(ProtocolError) as exc:
            _ = await sftp.check_file(handle)

    assert exc.value.args[0] == (
        "server hashed with b'whirlpool9', which this Python cannot size, so its 8 digest "
        "bytes cannot be split"
    )
    assert exc.value.request_id == server.checks[0].request_id


async def test_digests_that_do_not_divide_by_the_algorithm_carry_the_frame_that_proves_it():
    """sha1 is 20 bytes; 30 is not a whole number of them, so the reply is malformed.

    `raw_frame` is the field that makes this reportable to whoever wrote the server, and it is
    the one most easily dropped: the message is complete without it and nothing else looks.
    """
    server = ChoosesTheAlgorithm(holds=b"payload " * 64, algorithm=b"sha1", digests=b"z" * 30)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open(b"/incoming/file.bin", OpenFlag.READ)
        with pytest.raises(ProtocolError) as exc:
            _ = await sftp.check_file(handle)

    assert exc.value.args[0] == (
        "30 digest bytes do not divide into 20-byte digests, so this is not b'sha1' output"
    )
    assert exc.value.request_id == server.checks[0].request_id
    assert exc.value.raw_frame is not None
    assert exc.value.raw_frame.endswith(b"z" * 30)


# --- the arithmetic's edges, and what the rungs forward ------------------------------------------
#
# D-105's thirteenth slice found the carried state of every refusal untested; this is the same
# question asked of the verification ladder, and the answer came back in three parts. The state
# again (an offset and a path nothing read), the *forwarded arguments* -- a range, a depth, an
# idle timeout and a size, each handed to something else by a method whose whole job is to hand
# them over -- and three edges of the block arithmetic that only a degenerate size reaches.


def test_block_bounds_accepts_the_smallest_legal_block():
    """`block_size=1` is the boundary the guard names, and nothing had ever passed it.

    `if block_size < 1` is one character from `<= 1`, and a suite that only ever passes 0 (the
    refusal, tested above) and 1024 (the ordinary case) cannot separate the two. One byte per
    block is what a caller reaches for to localise a corruption, and the guard exists to refuse
    only the value that would not terminate.
    """
    assert block_bounds(0, 3, 1) == [0, 1, 2]
    assert block_bounds(7, 2, 1) == [7, 8]


async def test_local_block_digests_refuse_a_non_ascii_algorithm_as_an_algorithm(tmp_path: Path):
    """The algorithm name is the *server's* bytes, so the decode has to survive hostile ones.

    `check-file`'s reply names the algorithm it hashed with and this library hashes with
    whatever it says -- so those bytes are attacker-controlled, and the decode is deliberately
    lenient (`errors="replace"`) so the refusal that follows is about the **algorithm**, raised
    by `hashlib`, rather than about the decode. Strict decoding reports the wrong failure for
    the same input, and an unknown error-handler name raises `LookupError` from inside the codec
    machinery, which is neither.

    The type is asserted exactly rather than through `pytest.raises(ValueError)`, because
    `UnicodeDecodeError` **is** a `ValueError` -- the assertion that looks sufficient passes for
    precisely the failure this test exists to tell apart.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"x" * 16)

    with pytest.raises(ValueError) as refusal:
        _ = await local_block_digests(source, b"sha1\xff", start=0, length=16)

    assert type(refusal.value) is ValueError
    assert "sha1�" in refusal.value.args[0]


async def test_local_block_digests_hash_what_is_there_when_the_file_ends_early(tmp_path: Path):
    """A short read means the local file shrank, and the digest covers what was found.

    `_digest_block` breaks out of its read loop on the first empty `pread`; it does not retry
    and it does not abandon the block. The difference is what the caller sees: a digest over the
    bytes that *are* there fails the comparison, which is the correct answer to "the file
    changed underneath us", while returning nothing for the block is a `TypeError` in the
    comparison instead of a mismatch.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"short")

    assert await local_block_digests(source, b"sha1", start=0, length=64) == (sha1(b"short"),)


async def test_local_block_digests_hash_a_final_block_of_one_byte(tmp_path: Path):
    """The one-byte tail, which `while remaining > 0` is one character from never hashing.

    Every ordinary block survives `> 1`, because a full `pread` takes `remaining` from the
    block's length straight to zero in one pass. Only a block of exactly one byte enters the
    loop already at its last byte, so a range whose final block is a single byte is the only
    input that separates the two.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abc")

    assert await local_block_digests(source, b"sha1", start=0, length=3, block_size=2) == (
        sha1(b"ab"),
        sha1(b"c"),
    )


async def test_ranges_equal_sizes_its_last_block_to_the_range_and_not_past_it(tmp_path: Path):
    """Two blocks, a short second one, and a difference beyond the range being compared.

    The existing test above cannot see this: with a single block starting at zero the
    short-final-block arithmetic and its mutations agree. A second block is what makes the
    remainder visible, and the difference *past* the range is what turns an overrun into a wrong
    answer -- which is not hypothetical, because the resume gate compares exactly the adopted
    prefix and nothing else. Reading past it fails a resume that should have proceeded.
    """
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    shared = b"a" * 1500
    left.write_bytes(shared + b"L" * 548)
    right.write_bytes(shared + b"R" * 548)

    fd = os.open(left, os.O_RDONLY)
    try:
        assert await ranges_equal(fd, right, start=0, length=1500, block_size=1024) is True
    finally:
        os.close(fd)


# --- the rungs' own edges ---------------------------------------------------------------------


@pytest.mark.parametrize("rung", [Verify.HASH, Verify.REREAD], ids=["hash", "reread"])
async def test_an_empty_file_is_verified_without_asking_the_server_anything(
    tmp_path: Path, rung: Verify
):
    """`length=0` short-circuits, and that is a wire fact rather than an optimisation.

    `length=0` in a `check-file` request means "to the end of the file" -- the opposite of
    "nothing" -- so sending one would hash the whole file and compare it against no local blocks
    at all. The early return answers **True**: an empty file matches an empty file, and
    answering anything else refuses every zero-byte upload, which is a real thing to send.
    """
    server = HashingServer(holds=b"")
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/empty.bin", publish=Publish(atomic=False), verify=rung
        )

    expected = ContentCheck.HASHED if rung is Verify.HASH else ContentCheck.REREAD
    assert result.content_check is expected
    assert server.checks == []
    assert "Read" not in server.kinds


@pytest.mark.parametrize("rung", [Verify.HASH, Verify.REREAD], ids=["hash", "reread"])
async def test_a_one_byte_file_is_compared_rather_than_waved_through(tmp_path: Path, rung: Verify):
    """One byte is not zero bytes, and the short-circuit is one character from saying it is.

    `if length == 0` mutates to `== 1`, which passes every single-byte file unverified. A
    one-byte upload is not a curiosity -- a sentinel, a flag file, a marker a downstream job
    polls for -- and the whole point of a content check is that the file is the *right* byte.
    """
    server = HashingServer(holds=b"X", corrupts=True)
    source = tmp_path / "one.bin"
    source.write_bytes(b"Y")

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as refusal:
            _ = await sftp.put(
                source, b"/incoming/one.bin", publish=Publish(atomic=False), verify=rung
            )

    assert refusal.value.transferred == 1
    assert refusal.value.offset == 0


@pytest.mark.parametrize("rung", [Verify.HASH, Verify.REREAD], ids=["hash", "reread"])
async def test_the_first_byte_of_an_upload_is_inside_the_verified_range(
    tmp_path: Path, rung: Verify
):
    """The range starts at 0, and `start=0` is one character from `start=1`.

    A verification that begins at the second byte reads correctly, reports the rung it reached,
    and cannot see a corruption in the first byte -- which is where a truncated header, a
    byte-order mark eaten by a middlebox, or an off-by-one in a reassembler puts it. Every other
    content test here corrupts the whole payload, so all of them pass with the first byte
    excluded.
    """
    server = HashingServer(holds=b"B" + b"x" * 15, corrupts=True)
    source = tmp_path / "source.bin"
    source.write_bytes(b"A" + b"x" * 15)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as refusal:
            _ = await sftp.put(
                source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=rung
            )

    assert refusal.value.offset == 0
    assert refusal.value.local_path == str(source)


async def test_the_first_byte_of_a_download_is_inside_the_verified_range(tmp_path: Path):
    """The same off-by-one on the other side, where only rung 1 can see it at all.

    Rung 2 on a download compares the file against a second read of the same remote bytes, so a
    server serving something other than what it hashes is invisible to it -- which is why this
    is the hash rung and why the docstring for `Verify.REREAD` says what it proves on each side.
    """
    server = HashingServer(holds=b"A" + b"x" * 15, serves=b"B" + b"x" * 15)
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as refusal:
            _ = await sftp.get(b"/remote.bin", local, verify=Verify.HASH)

    assert refusal.value.offset == 0
    assert local.read_bytes() == b"B" + b"x" * 15


# --- what the two rungs hand to the layers under them ----------------------------------------


async def test_a_settled_refusal_saves_the_open_and_the_close_as_well_as_the_question(
    tmp_path: Path,
):
    """The cache is checked *before* the OPEN, and the OPEN is two of the three round trips.

    The test above this one counts `check-file` requests, which is the question itself. It
    cannot see the other two: rung 1 opens the file to ask, because `check-file` hashes through
    a handle and an upload's is WRITE-only. A cache consulted after the open would save one trip
    of three and the count of questions would still read as one.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload, advertises=False, implements=False)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        for name in (b"/incoming/one.bin", b"/incoming/two.bin"):
            result = await sftp.put(source, name, publish=Publish(atomic=False), verify=Verify.HASH)
            assert result.content_check is ContentCheck.UNAVAILABLE

    assert len(server.checks) == 1
    # Two uploads, three opens: each destination, plus the one file rung 1 opened to ask about.
    assert len(server.opened) == 3


async def test_hashing_a_range_asks_the_server_about_the_range_it_was_given(tmp_path: Path):
    """`start_offset` is forwarded, and both public callers pass zero, so nothing proved it.

    An argument that is only ever handed the value it defaults to is invisible from the API --
    and this one is the method's whole contract, which is documented as "rung 1 over one range".
    A resume gate hashing from zero on the server while this side hashed from the offset would
    report every partial as a mismatch and refuse every resume the gate exists to allow.
    """
    payload = b"".join(bytes([n]) * 32 for n in range(8))
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        agreed = await hashes_agree(sftp, b"/remote.bin", source, start=64, length=64)

    assert agreed is True
    assert server.checks[0].start_offset == 64
    assert server.checks[0].length == 64


async def test_a_reread_asks_for_the_range_and_does_not_read_on_to_find_the_end(tmp_path: Path):
    """`size=` is what lets the re-read stop without a trailing round trip to see EOF.

    `download_handle` documents it: `None` reads until EOF and costs one extra request at the
    end. Rung 2 already knows how long the range is, so passing it is the difference between one
    READ and two -- per verified file, which on a `put_tree` is per file in the tree, and on the
    200 ms profile the netem lane measures is the whole cost of the rung on small files.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.REREAD
        )

    assert result.content_check is ContentCheck.REREAD
    assert server.kinds.count("Read") == 1


async def test_a_reread_that_is_refused_names_the_file_it_was_reading(tmp_path: Path):
    """The re-read is a download, and a download's errors carry the remote path they were given.

    Rung 2 hands `remote_path` to the scheduler, which has a handle and no name -- so an error
    raised in there says `None` unless this call site passes it. The upload has already
    succeeded at this point, which is exactly when a nameless error is hardest to place: the
    bytes are on the server and the failure is in the verification of a file the message does
    not identify.
    """

    class RefusesTheReread(HashingServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read):
                self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"no"))
                return
            super()._handle(packet)

    payload = b"payload " * 16
    server = RefusesTheReread(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as refusal:
            _ = await sftp.put(
                source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.REREAD
            )

    assert refusal.value.remote_path == b"/incoming/file.bin"
    assert refusal.value.local_path == str(source)


async def test_a_reread_runs_at_the_session_s_pipeline_depth(tmp_path: Path):
    """The depth is forwarded, and what it bounds is memory rather than speed.

    D-101 states the cost of a transfer as `concurrent transfers x depth x request size`, so a
    re-read that quietly ran at the default depth would break that arithmetic for anybody who
    turned the depth down to fit it. Proven with a depth the scheduler refuses: an invalid value
    is the cheapest thing that tells "the session's depth arrived" apart from "the default did",
    and the refusal is the scheduler's own.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server, depth=0) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as refusal:
            _ = await reread_agrees(sftp, b"/remote.bin", source, start=0, length=len(payload))

    assert refusal.value.args[0] == "depth must be at least 1, got 0"


async def test_a_stalled_reread_is_bounded_by_the_session_s_idle_timeout(tmp_path: Path):
    """A server that answers the OPEN and then stops is the case the idle timeout is for.

    The forwarded `idle_timeout` is the only thing between a hung verification and a transfer
    that never returns -- and the upload has already completed, so the caller is blocked on a
    check rather than on the work. Set short here; the shipped default is 60 s, which is the
    difference between this test taking a moment and taking a minute.
    """

    class StopsAfterTheOpen(HashingServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read):
                return
            super()._handle(packet)

    payload = b"payload " * 16
    server = StopsAfterTheOpen(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server, idle_timeout=0.05) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferTimeoutError):
            _ = await reread_agrees(sftp, b"/remote.bin", source, start=0, length=len(payload))


async def test_the_scratch_file_a_reread_writes_is_named_after_this_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The prefix is what makes a leaked temporary attributable, and nothing read it.

    Rung 2's cost is temporary local disk equal to the range, in `$TMPDIR` -- which on a busy
    host holds files from everything running on it. A stray `gantry-verify-*` names both the
    library and the operation that left it; an unnamed one is somebody else's problem to
    diagnose. Same argument D-107 recorded for the askpass helper's directory prefix, and the
    same reason it needs an assertion: a prefix nothing reads can be renamed or dropped without
    anything noticing.
    """
    prefixes: list[object] = []
    real = tempfile.NamedTemporaryFile

    def recording(*args: object, **kwargs: object):
        prefixes.append(kwargs.get("prefix"))
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", recording)

    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=Verify.REREAD
        )

    assert prefixes == ["gantry-verify-"]


@pytest.mark.parametrize("rung", [Verify.HASH, Verify.REREAD], ids=["hash", "reread"])
async def test_a_verification_closes_the_handle_it_opened(tmp_path: Path, rung: Verify):
    """Both rungs open the file a second time to ask their question, and both must close it.

    A handle leaked by the *verification* is invisible from this side and counts against the
    server's open-handle limit exactly like a leaked transfer handle -- and it is leaked on the
    success path, so nothing anywhere is failing when it happens. `_close_quietly` swallows
    every exception by design, which is what makes this untestable by any route except counting
    what reached the server.
    """
    payload = b"payload " * 16
    server = HashingServer(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(
            source, b"/incoming/file.bin", publish=Publish(atomic=False), verify=rung
        )

    assert server.kinds.count("Open") == 2, "the destination, and the file the rung re-opened"
    assert server.kinds.count("Close") == server.kinds.count("Open")


async def test_a_reread_reads_back_the_range_and_not_the_file_under_it(tmp_path: Path):
    """`start_offset` is rung 2's other forwarded argument, and dropping it is silently correct.

    A re-read that started at zero would still answer correctly -- it would fetch the bytes
    below the range, ignore them, and compare the right ones -- so the only visible difference
    is what crossed the link. That difference is the rung's entire cost argument: gating a
    resume on rung 2 is worth it when reading back is cheaper than sending again, and a gate
    that re-read the whole file every time would be the bandwidth cost resume exists to avoid.
    """

    class RecordsReads(HashingServer):
        reads: list[tuple[int, int]] = []  # noqa: RUF012

        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read):
                self.reads = [*self.reads, (packet.offset, packet.length)]
            super()._handle(packet)

    payload = b"".join(bytes([n]) * 32 for n in range(8))
    server = RecordsReads(holds=payload)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        agreed = await reread_agrees(sftp, b"/remote.bin", source, start=64, length=64)

    assert agreed is True
    assert server.reads, "the rung read nothing at all"
    assert min(offset for offset, _ in server.reads) == 64


async def test_the_first_byte_of_a_downloaded_file_is_inside_a_reread_too(tmp_path: Path):
    """The mirror of the upload's first-byte test, on the rung the public path cannot stage.

    Rung 2 on a download compares the local file against a second read of the same remote
    bytes, so an honest server makes the two agree by construction and no `get` can produce a
    disagreement to test with. What *can* differ is a local file that changed after it
    arrived -- a concurrent writer, a half-restored backup -- which is what this stages by
    calling the check against a file the server never sent.
    """
    served = b"B" + b"x" * 15
    server = HashingServer(holds=served)
    local = tmp_path / "downloaded.bin"
    local.write_bytes(b"A" + b"x" * 15)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as refusal:
            _ = await verify_downloaded_content(
                sftp, b"/remote.bin", local, len(served), Verify.REREAD
            )

    assert refusal.value.offset == 0
    assert refusal.value.transferred == 16


@pytest.mark.parametrize("atomic", [True, False], ids=["atomic", "in-place"])
async def test_the_resume_gate_runs_the_rung_the_upload_asked_for(tmp_path: Path, atomic: bool):
    """`verify=` reaches the gate from both publish paths, and each builds the call itself.

    A gate handed nothing falls through to rung 1, which is absent from nearly every endpoint
    -- so an upload that asked for `REREAD`, the rung that works everywhere, would report the
    adopted prefix as `UNAVAILABLE` and complete on the size match alone. That is the exact
    failure the gate exists to prevent, arrived at by dropping one argument, and the two paths
    are separate construction sites: proving one proves nothing about the other.
    """
    payload = b"correct " * 16
    server = HashingServer(holds=payload[:64], advertises=False, implements=False)
    source = tmp_path / "right.bin"
    source.write_bytes(payload)
    policy = Publish(atomic=atomic, staging_name=b".staged") if atomic else Publish(atomic=False)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"/incoming/file.bin", publish=policy, resume=True, verify=Verify.REREAD
        )

    assert result.resume_check is ResumeCheck.MATCHED
    assert server.checks == [], "rung 2 was asked for and rung 1 was attempted"

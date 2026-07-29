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
from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import (
    CHECK_FILE_BLOCK_SIZE,
    ContentCheck,
    Publish,
    ResumeCheck,
    Verify,
    open_session,
)
from gantry_sftp.session._verify import block_bounds, local_block_digests, ranges_equal
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
    """

    def __init__(
        self,
        *,
        holds: bytes = b"",
        advertises: bool = True,
        implements: bool | None = None,
        refuses_check: bool = False,
        corrupts: bool = False,
    ) -> None:
        self.holds = bytearray(holds)
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
            chunk = bytes(self.holds[packet.offset : packet.offset + packet.length])
            self._reply(Data(rid, memoryview(chunk)) if chunk else Status(rid, StatusCode.EOF))
        elif isinstance(packet, Write):
            self.written += packet.data
            if not self.corrupts:
                # At the offset, not appended: writes arrive out of order under pipelining, and
                # a fake that appends would make a scrambled upload look correct.
                end = packet.offset + len(packet.data)
                self.holds.extend(bytes(end - len(self.holds)) if end > len(self.holds) else b"")
                self.holds[packet.offset : end] = packet.data
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

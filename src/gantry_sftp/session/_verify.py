"""The verification ladder of DESIGN.md 6: the rungs, and the arithmetic they share.

Three rungs, strongest first: a server-side hash (``check-file``, rung 1), a full re-read of
what we just wrote (rung 2), and a length comparison (rung 3, which always runs and has no
flag). Rung 3 is not here -- it is a length against a length, and it lives in
:mod:`gantry_sftp.session._policy` with the rest of what a transfer decides without the wire.

**The ladder itself moved here under D-146**, out of `Session`, as functions taking a session
rather than methods on one. Nothing about the split is inheritance: these are one of the seven
concerns that class composes, not a layer beneath it, and the module is the boundary in the
same way :mod:`gantry_sftp.session._policy` is. What made it possible is that a caller no
longer needs the session's wire state to re-read a range --
:meth:`~gantry_sftp.session.Session.download_into` schedules it from inside the class that owns
the dispatcher, so nothing here reaches for a private.

**Everything here is blocked out at 64 KiB and that number is not a tuning choice.** It is the
largest block paramiko's ``check-file`` answers correctly, and paramiko is the only
implementation of that extension this project can reach. See :data:`CHECK_FILE_BLOCK_SIZE`.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from anyio.to_thread import run_sync

from gantry_sftp.codec import EXTENSION_CHECK_FILE
from gantry_sftp.exceptions import ServerError, TransferError
from gantry_sftp.session._handles import close_quietly
from gantry_sftp.session._transient import open_for_read

if TYPE_CHECKING:
    from gantry_sftp.session._operations import _SessionOperations

__all__ = [
    "CHECK_FILE_BLOCK_SIZE",
    "ContentCheck",
    "ResumeCheck",
    "Verify",
    "block_bounds",
    "gate_resume",
    "hashes_agree",
    "local_block_digests",
    "ranges_equal",
    "reread_agrees",
    "verify_content",
    "verify_downloaded_content",
]

CHECK_FILE_BLOCK_SIZE = 65536
"""Bytes per digest in every ``check-file`` this library sends, and never ``0``.

``0`` is the wire value for "one digest over the whole range" and it is what
:meth:`~gantry_sftp.session.Session.check_file` used to default to. Against paramiko -- the
only server implementing this extension that the matrix can start -- it is a **hang** for any
range over 64 KiB, and a ``FAILURE`` for any range under 256 bytes. Both were measured, and
both come out of ``SFTPServer._check_file``:

* it turns ``block_size=0`` into ``block_size=length``, then refuses anything below 256 with
  ``"Block size too small"``. So a 100-byte prefix is unhashable in that spelling. **That
  floor is the specification's**, not paramiko's -- ``draft-ietf-secsh-filexfer-extensions-00``
  3 says the block size "MUST NOT be smaller than 256 bytes" -- so every server implementing
  this extension refuses it and the ``0`` spelling is unusable for a short range anywhere
  (D-118).
* its inner read loop is ``count += len(data)`` followed by ``offset += count`` -- cumulative,
  where it means ``offset += len(data)``. While a block fits in one read the two are equal, and
  ``chunklen`` is capped at 64 KiB, so **64 KiB is exactly the boundary where the two stop
  agreeing.** Past it the offsets run away, the digest covers the wrong bytes, and once they
  run past EOF ``readfile.read()`` returns ``b""`` -- which ``count`` does not grow on, so the
  ``while count < blocklen`` loop never terminates. paramiko's own
  :meth:`SFTPHandle.read` documents returning ``b""`` at EOF, so the two halves disagree in
  stock code rather than in anything a handler does.

The consequence for a caller is worth stating plainly: a ``check-file`` with a block over
64 KiB wedges a paramiko server thread permanently. Our side recovers on ``request_timeout``;
the server's does not recover at all. A fixed 64 KiB block avoids every one of these cases,
costs one extra digest per 64 KiB of payload, and is the largest block that is correct.
"""


class Verify(StrEnum):
    """Which rung of DESIGN.md 6's ladder a transfer should try to reach.

    Names what the caller *wants*. What they got is reported back on
    :attr:`~gantry_sftp.session.UploadResult.content_check` or
    :attr:`~gantry_sftp.session.DownloadResult.content_check`, because a rung can be asked for
    and be unavailable -- rung 1 is absent from almost every server in the field -- and
    silently settling for a weaker check than the one that was requested is the exact failure
    this ladder is documented to prevent.

    **Both directions accept it** (D-99). ``get`` could not at first, and the
    blocker was its return type rather than any missing machinery: an ``int`` had nowhere to
    report ``UNAVAILABLE``. On a resume it also selects the rung the adopted prefix is gated
    on, in either direction.
    """

    SIZE = "size"
    """Rung 3 only, and the default. The length is compared and nothing else is -- which
    catches truncation, the common failure, and no form of corruption at all. It is not a
    hash, and no amount of it adds up to one."""

    HASH = "hash"
    """Rung 1: ask the server to hash what it holds and compare against the same bytes here.
    Verifies content without moving it a second time, and costs one round trip per 64 KiB
    of digests. **Most servers do not have it** -- OpenSSH answers ``OP_UNSUPPORTED`` under
    all three spellings -- so this frequently reports ``UNAVAILABLE`` rather than failing."""

    REREAD = "reread"
    """Rung 2: read the bytes back and compare them. Works against **any** server, because it
    asks for nothing but ``READ``, and costs a second transfer plus temporary local disk equal
    to the file. That is the price of the only content check available on an endpoint with no
    ``check-file``, which is nearly all of them.

    **It proves less on a download than on an upload.** Uploading, it proves the server holds
    what was sent. Downloading, both copies come from the same place, so what it checks is the
    local half -- this library's reassembly, its offsets, and the disk they were written to.
    Worth asking for; not the same claim, and rung 1 is the end-to-end one on that side."""


class ContentCheck(StrEnum):
    """Whether the uploaded *content* was verified, and by which rung.

    Distinct from :class:`SizeCheck`, which is about length. A file of the right length and
    the wrong bytes passes rung 3 every time, and calling that a verified transfer is what
    DESIGN.md 6 exists to stop.

    A **mismatch** is not one of these values -- it raises
    :class:`~gantry_sftp.exceptions.TransferError`, for the same reason a size mismatch does:
    there is nothing useful a caller does with a published file of the wrong content, and
    returning it as a value is how a corruption gets logged and ignored.
    """

    SKIPPED = "skipped"
    """``verify=Verify.SIZE``, the default. Only the length was checked."""

    HASHED = "hashed"
    """Rung 1 ran: the server hashed what it holds, and every digest matched ours."""

    REREAD = "reread"
    """Rung 2 ran: the bytes were read back and compared, and they were equal."""

    UNAVAILABLE = "unavailable"
    """A rung was asked for and could not run. In practice that is ``Verify.HASH`` against a
    server with no ``check-file``, or one that advertises it and then refuses -- no algorithm
    in common, or a handle it will not read. The upload succeeded and its length was checked;
    what did not happen is the content check, and this says so rather than passing."""


class ResumeCheck(StrEnum):
    """Whether the partial a resume adopted was proven to be a prefix of the local file.

    Resume's weak point is not the offset, it is the bytes below it. A remote partial of the
    *right length* from the *wrong source* -- a previous run against a different file, a
    truncated staging file, a concurrent writer -- is completed and reported successful, and
    the size check at the end passes, because the length is right. This is the answer to
    "was that ruled out", and DESIGN.md 6 asks for the gate in as many words.

    A **mismatch** raises :class:`~gantry_sftp.exceptions.TransferError` before a single byte
    is sent.
    """

    SKIPPED = "skipped"
    """Nothing was adopted: not a resume, or a resume that found nothing on the server and is
    starting from zero. There is no prefix to have an opinion about."""

    MATCHED = "matched"
    """A prefix was adopted and proven: hashed on both sides, or read back and compared."""

    UNAVAILABLE = "unavailable"
    """A prefix was adopted and could not be proven -- the default case, because rung 1 needs
    ``check-file`` and rung 2 has to be asked for. The resume proceeded on the size match
    alone, which is the weaker claim DESIGN.md 6 requires be labelled one."""


def block_bounds(start: int, length: int, block_size: int = CHECK_FILE_BLOCK_SIZE) -> list[int]:
    """Where each digest's block begins, for a range hashed at ``block_size``.

    Mirrors paramiko's blocking exactly -- fixed-size blocks from ``start``, a short final one
    -- because the digests it returns have to line up with the ones computed here, and nothing
    on the wire says how many there are or where they start.

    Args:
        start: First byte of the range.
        length: Bytes in the range. ``0`` yields no blocks at all.
        block_size: Bytes per block.

    Returns:
        The offset of each block, in order.

    Raises:
        ValueError: If ``block_size`` is not positive, which would not terminate.
    """
    if block_size < 1:
        raise ValueError(f"block_size must be at least 1, got {block_size}")
    return list(range(start, start + length, block_size))


async def local_block_digests(
    path: Path | str,
    algorithm: bytes,
    *,
    start: int,
    length: int,
    block_size: int = CHECK_FILE_BLOCK_SIZE,
) -> tuple[bytes, ...]:
    """Hash a range of a local file the way the server hashed the remote one.

    One digest per block, blocked identically to :func:`block_bounds`, so the two tuples can be
    compared element by element. The algorithm is whichever one the *server* named in its
    reply, not a preference of ours -- comparing against a digest computed with a different
    function is a check that cannot pass.

    Each block is read and hashed in a worker thread. A 9 GB prefix is real work, and doing it
    on the event loop would stall every other transfer sharing the connection; one call per
    block also leaves a cancellation checkpoint between them, so a cancelled verification stops
    at the next block rather than at the end of the file.

    Args:
        path: Local file to read.
        algorithm: Digest name as the server spelled it, e.g. ``b"sha1"``.
        start: First byte to hash.
        length: Bytes to hash.
        block_size: Bytes per digest.

    Returns:
        One digest per block, in order.

    Raises:
        ValueError: If ``algorithm`` is not a name this Python's ``hashlib`` knows, or if
            ``block_size`` is not positive.
        OSError: If the file cannot be read.
    """
    name = algorithm.decode("ascii", "replace")
    # Rejected here rather than at the first block, so an unusable algorithm is one error
    # about the algorithm instead of one about a file we then half-read.
    hashlib.new(name, usedforsecurity=False)
    fd = os.open(path, os.O_RDONLY)
    try:
        digests = []
        for offset in block_bounds(start, length, block_size):
            span = min(block_size, start + length - offset)
            digests.append(await run_sync(_digest_block, fd, name, offset, span))
        return tuple(digests)
    finally:
        os.close(fd)


async def ranges_equal(
    fd: int,
    path: Path | str,
    *,
    start: int,
    length: int,
    block_size: int = CHECK_FILE_BLOCK_SIZE,
) -> bool:
    """Whether the same byte range of an open descriptor and a local file is identical.

    Rung 2's comparison, once the bytes are back on this side. Compared rather than hashed:
    two digests are only a cheaper way of saying "not equal" and there is nothing to be saved
    here, since both operands are already on local disk.

    Block by block with an explicit offset on each, so peak memory is one block whatever the
    file's size, and so a mismatch stops at the first block that differs instead of reading
    the rest of a file already known to be wrong.

    Args:
        fd: Readable descriptor holding what the server sent back. Not closed here.
        path: Local file to compare it against.
        start: First byte of the range, in both.
        length: Bytes to compare.
        block_size: Bytes per comparison.

    Returns:
        Whether every byte of the range agrees.

    Raises:
        OSError: If either side cannot be read.
    """
    mine = os.open(path, os.O_RDONLY)
    try:
        for offset in block_bounds(start, length, block_size):
            span = min(block_size, start + length - offset)
            if not await run_sync(_blocks_equal, fd, mine, offset, span):
                return False
    finally:
        os.close(mine)
    return True


def _blocks_equal(left: int, right: int, offset: int, length: int) -> bool:
    """Read one block from each descriptor at the same offset and compare. In a thread.

    A short read on either side leaves the two byte strings different lengths, which compares
    unequal -- the right answer, because a file that ends early is not the file we wrote.
    """
    return os.pread(left, length, offset) == os.pread(right, length, offset)


def _digest_block(fd: int, name: str, offset: int, length: int) -> bytes:
    """Read one block at an explicit offset and hash it. Runs in a worker thread.

    ``os.pread`` rather than a seek and a read: the fd is shared with nothing here, but an
    explicit offset is what makes this safe to call in any order and is the same rule the
    transfer paths follow.

    A short ``pread`` is not an error to retry -- it means the local file ends inside this
    block, which happens when the file shrank underneath us. The digest is then over fewer
    bytes than the server hashed and the comparison fails, which is the correct outcome.
    """
    digest = hashlib.new(name, usedforsecurity=False)
    remaining = length
    while remaining > 0:
        chunk = os.pread(fd, remaining, offset + length - remaining)
        if not chunk:
            break
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.digest()


# --- the rungs, which are the only things here that reach the wire ----------------------------


async def hashes_agree(
    session: _SessionOperations, path: bytes, local_path: Path | str, *, start: int, length: int
) -> bool | None:
    """Rung 1 over one range: does the server's hash of it match the local file's?

    ``None`` is the third state and it is the *common* one -- the extension is absent, or
    advertised and then refused. It says the question could not be asked, which is a
    different fact from the answer being "no" and must never collapse into it: one is
    "unverified", the other is "corrupt".

    Costs its own ``OPEN`` and ``CLOSE``. ``check-file`` hashes by reading through the
    handle, so the WRITE-only one an upload is holding answers ``FAILURE`` -- measured
    against paramiko, which is the only server that implements this at all.

    An **empty range short-circuits and never reaches the wire**, because ``length=0`` on
    the wire means "to the end of the file" rather than "nothing". Sending it would hash
    the whole file and compare it against no local blocks at all.
    """
    if session.refuses(EXTENSION_CHECK_FILE):
        # Asked once per session, not once per file. Advertisement is not consulted here
        # any more (D-51): the endpoints most likely to under-advertise are the ones where
        # rung 1 is worth having, and the cost of finding out is one exchange for the whole
        # session -- against the OPEN and CLOSE below, which this pays per file anyway.
        return None
    if length == 0:
        return True
    handle = await open_for_read(session.open, path, session.profile, what="verify")
    try:
        algorithm, theirs = await session.check_file(
            handle, start_offset=start, length=length, block_size=CHECK_FILE_BLOCK_SIZE
        )
    except ServerError:
        # Advertised and unusable -- no algorithm in common, a handle it will not read,
        # a range it will not hash. Rung 1 is unavailable here, which is exactly what an
        # unadvertised extension also means, so the two collapse to the same answer.
        return None
    finally:
        # Quietly, and on the success path too: this handle exists only to ask a question,
        # and failing a transfer because the *probe's* CLOSE was refused would be
        # housekeeping replacing the diagnosis.
        await close_quietly(session, handle)
    try:
        mine = await local_block_digests(local_path, algorithm, start=start, length=length)
    except ValueError:
        # The server hashed with something this Python cannot compute. There is nothing to
        # compare against, so the rung is unavailable rather than failed.
        return None
    return theirs == mine


async def reread_agrees(
    session: _SessionOperations, path: bytes, local_path: Path | str, *, start: int, length: int
) -> bool:
    """Rung 2 over one range: read the bytes back off the server and compare them.

    Works against **any** server, because it asks for nothing but ``READ``. That is the
    whole point of the rung: ``check-file`` is absent from nearly every endpoint in the
    field, so without this there is no content verification available at all off a
    paramiko-backed server.

    The bytes land in a temporary file and are compared from there, rather than being
    compared as they arrive. Two reasons, and the second is the load-bearing one: replies
    arrive out of order, so a streaming comparison would have to reassemble them, which is
    the scheduler this library already has exactly one of; and writing to a descriptor is
    what :meth:`~gantry_sftp.session.Session.download_into` does, so the re-read runs at the
    pipelined speed of an ordinary download instead of one round trip per block. **The cost is
    temporary local disk equal to the range**, in ``$TMPDIR``, and that is stated rather than
    hidden -- it is the reason this rung is opt-in.
    """
    if length == 0:
        return True
    handle = await open_for_read(session.open, path, session.profile, what="verify")
    try:
        with tempfile.NamedTemporaryFile(prefix="gantry-verify-") as scratch:
            _ = await session.download_into(
                handle,
                scratch.fileno(),
                size=start + length,
                remote_path=path,
                start_offset=start,
            )
            return await ranges_equal(scratch.fileno(), local_path, start=start, length=length)
    finally:
        await close_quietly(session, handle)


async def gate_resume(
    session: _SessionOperations,
    path: bytes,
    local_path: Path | str,
    adopted: int,
    verify: Verify,
) -> ResumeCheck:
    """Gate the adopted prefix on a rung, which is what DESIGN.md 6 asks for in as many words.

    The offset was established from the size the server reported, and a size match proves
    only that the byte count agrees. What it cannot refuse is the case that matters most --
    a remote partial of the *right* length from the *wrong* source, which this completes,
    publishes, and passes rung 3 on, because the finished length is correct.

    **Rung 1 runs by default and rung 2 does not**, and the asymmetry is the decision.
    Rung 1 moves no bytes, so gating on it where it exists is free correctness and there
    is no case for making a caller ask. Rung 2 re-reads the whole adopted prefix, which is
    most of what resume set out to avoid; making *that* automatic would silently turn a
    bandwidth optimisation into a bandwidth cost. It is worth asking for on an asymmetric
    link, where reading back is cheaper than sending again -- but that is the caller's fact
    about their link, not ours.

    Raises:
        TransferError: If the adopted prefix is provably not a prefix of the local file.
            Before a single byte is sent, so nothing is published and the partial is left
            exactly as it was found -- it may be somebody else's, and it is the only
            evidence of what went wrong.
    """
    if adopted == 0:
        return ResumeCheck.SKIPPED
    if verify is Verify.REREAD:
        agreed: bool | None = await reread_agrees(
            session, path, local_path, start=0, length=adopted
        )
    else:
        agreed = await hashes_agree(session, path, local_path, start=0, length=adopted)
    if agreed is None:
        return ResumeCheck.UNAVAILABLE
    if not agreed:
        raise TransferError(
            f"cannot resume: the {adopted} bytes already at {path!r} are not a prefix of "
            f"{local_path} -- the partial is from a different source file or a different "
            f"run, and continuing would publish a file of the right length and the wrong "
            f"contents. Upload without resume=True to replace it",
            transferred=0,
            offset=adopted,
            remote_path=path,
            local_path=str(local_path),
        )
    return ResumeCheck.MATCHED


async def verify_content(
    session: _SessionOperations,
    path: bytes,
    local_path: Path | str,
    expected: int,
    verify: Verify,
) -> ContentCheck:
    """Check what the server now holds against the local file, at the rung asked for.

    Args:
        session: The session to ask.
        path: What to read back. On the atomic path this is the **staging file**, checked
            before the rename, for the same reason rung 3 is: content that fails belongs
            to a file no consumer has ever been able to see.
        local_path: The source of truth.
        expected: Bytes the file should hold -- the local file's length, not what this run
            moved, which differs under ``resume``.
        verify: Which rung to try.

    Raises:
        TransferError: If the content disagrees.
    """
    if verify is Verify.SIZE:
        return ContentCheck.SKIPPED
    if verify is Verify.HASH:
        agreed = await hashes_agree(session, path, local_path, start=0, length=expected)
        if agreed is None:
            return ContentCheck.UNAVAILABLE
        reached = ContentCheck.HASHED
    else:
        agreed = await reread_agrees(session, path, local_path, start=0, length=expected)
        reached = ContentCheck.REREAD
    if not agreed:
        raise TransferError(
            f"{path!r} does not hold the contents of {local_path}: it is {expected} bytes "
            f"long, as it should be, and the bytes differ. The upload is corrupt rather "
            f"than short, which is the failure a size check cannot see",
            transferred=expected,
            offset=0,
            remote_path=path,
            local_path=str(local_path),
        )
    return reached


async def verify_downloaded_content(
    session: _SessionOperations,
    path: bytes,
    local_path: Path | str,
    expected: int,
    verify: Verify,
) -> ContentCheck:
    """Check the file that was just written against what the server holds, at ``verify``.

    The mirror of :func:`verify_content`, and separate from it only for the message: the
    comparison is identical -- a remote range against a local one -- but "the upload is
    corrupt" is the wrong sentence to hand somebody whose download it was.

    Args:
        session: The session to ask.
        path: What was read.
        local_path: What was written, and what is being checked.
        expected: Bytes the local file should hold. ``adopted + transferred``, not what
            this call moved, which differs under ``resume``.
        verify: Which rung to try.

    Raises:
        TransferError: If the content disagrees.
    """
    if verify is Verify.SIZE:
        return ContentCheck.SKIPPED
    if verify is Verify.HASH:
        agreed = await hashes_agree(session, path, local_path, start=0, length=expected)
        if agreed is None:
            return ContentCheck.UNAVAILABLE
        reached = ContentCheck.HASHED
    else:
        agreed = await reread_agrees(session, path, local_path, start=0, length=expected)
        reached = ContentCheck.REREAD
    if not agreed:
        raise TransferError(
            f"{local_path} does not hold the contents of {path!r}: it is {expected} bytes "
            f"long, as it should be, and the bytes differ. The download is corrupt rather "
            f"than short, which is the failure a size check cannot see",
            transferred=expected,
            offset=0,
            remote_path=path,
            local_path=str(local_path),
        )
    return reached

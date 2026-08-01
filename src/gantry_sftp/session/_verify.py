"""The verification ladder of DESIGN.md 6, and the arithmetic its rungs share.

Three rungs, strongest first: a server-side hash (``check-file``, rung 1), a full re-read of
what we just wrote (rung 2), and a length comparison (rung 3, which always runs and has no
flag). This module holds the vocabulary and the pure part; the round trips live in
:mod:`gantry_sftp.session._session`, which is the layer allowed to make them.

**Everything here is blocked out at 64 KiB and that number is not a tuning choice.** It is the
largest block paramiko's ``check-file`` answers correctly, and paramiko is the only
implementation of that extension this project can reach. See :data:`CHECK_FILE_BLOCK_SIZE`.
"""

from __future__ import annotations

import hashlib
import os
from enum import StrEnum
from pathlib import Path

from anyio.to_thread import run_sync

__all__ = [
    "CHECK_FILE_BLOCK_SIZE",
    "ContentCheck",
    "ResumeCheck",
    "Verify",
    "block_bounds",
    "local_block_digests",
    "ranges_equal",
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

    **Both directions accept it as of 0.11** (D-99). ``get`` could not until then, and the
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

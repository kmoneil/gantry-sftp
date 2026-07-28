"""Resume, in both directions, and the two claims are not the same strength.

Downloading, the partial is on local disk: its length is a fact, and a READ at an explicit
offset is idempotent. Uploading, the length is whatever the server *says*, and a size match
proves the byte count agrees and nothing else -- the remote partial may be from a different
run, a different source file, or a concurrent writer. Both are opt-in for that reason, and
the tests below are mostly about the refusals rather than the happy path, because the happy
path is the easy half.

Most of these run against the real ``sftp-server``: resume is exactly the feature where a
fake proves what its author already believed, since the whole question is whether the size
the *server* reports can be continued from. The scripted server appears only for the shape a
real one will not produce on demand -- a STAT with no size in it.
"""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    FrameSplitter,
    Init,
    LStat,
    Stat,
    Status,
    StatusCode,
    Version,
    decode,
    encode,
)
from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import Publish, PublishMechanism, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

CONTENT = bytes(range(256)) * 400  # 102400 bytes, several requests at any sane read length


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


# --- downloading ------------------------------------------------------------------------------


async def test_a_resumed_download_completes_a_partial_file(tmp_path: Path):
    """The headline, and the assertion that catches the obvious way to get it wrong.

    Dropping ``O_TRUNC`` is the whole local-side change. If it were left in, the partial would
    be deleted and the transfer would write from the resume offset into an empty file, leaving
    a hole of zeros where the first half was -- a file of exactly the right *length*, and
    wrong. So this compares content, not size.
    """
    needs_real_server()
    remote = tmp_path / "source.bin"
    remote.write_bytes(CONTENT)
    local = tmp_path / "partial.bin"
    local.write_bytes(CONTENT[:40_000])

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        written = await sftp.get(str(remote), local, resume=True)

    assert written == len(CONTENT) - 40_000, "it re-sent bytes it already had"
    assert local.read_bytes() == CONTENT


async def test_a_resumed_download_with_no_partial_transfers_the_whole_file(tmp_path: Path):
    # resume=True on a first attempt is the ordinary case, not an error: there is simply
    # nothing to continue from.
    needs_real_server()
    remote = tmp_path / "source.bin"
    remote.write_bytes(CONTENT)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        written = await sftp.get(str(remote), tmp_path / "fresh.bin", resume=True)

    assert written == len(CONTENT)
    assert (tmp_path / "fresh.bin").read_bytes() == CONTENT


async def test_a_resumed_download_of_an_already_complete_file_moves_nothing(tmp_path: Path):
    # Zero is the honest answer -- `get` returns what this call moved -- and it costs one
    # STAT rather than opening a file to transfer nothing out of it.
    needs_real_server()
    remote = tmp_path / "source.bin"
    remote.write_bytes(CONTENT)
    local = tmp_path / "done.bin"
    local.write_bytes(CONTENT)
    before = local.stat().st_mtime_ns

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.get(str(remote), local, resume=True) == 0

    assert local.read_bytes() == CONTENT
    assert local.stat().st_mtime_ns == before, "the file was rewritten to transfer nothing"


async def test_a_local_partial_longer_than_the_remote_is_refused(tmp_path: Path):
    """The check that stops resume being a corruption primitive.

    A local file longer than the remote one cannot be a prefix of it, so it is from a
    different source -- or the remote was replaced. Continuing would leave a file that is part
    one download and part another, and the length would look right.
    """
    needs_real_server()
    remote = tmp_path / "source.bin"
    remote.write_bytes(CONTENT[:1000])
    local = tmp_path / "too-long.bin"
    local.write_bytes(CONTENT[:5000])

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(str(remote), local, resume=True)

    assert exc.value.args[0] == (
        f"cannot resume: {local} already holds 5000 bytes and "
        f"{str(remote).encode()!r} is only 1000, so what is on disk is not a prefix of "
        f"what is being downloaded"
    )
    assert exc.value.offset == 5000
    assert local.read_bytes() == CONTENT[:5000], "the local file was touched despite the refusal"


async def test_a_download_without_resume_still_truncates(tmp_path: Path):
    # The default has not changed. A partial left over from a previous run is replaced, which
    # is what every caller who did not ask for resume expects.
    needs_real_server()
    remote = tmp_path / "source.bin"
    remote.write_bytes(CONTENT[:1000])
    local = tmp_path / "stale.bin"
    local.write_bytes(b"x" * 9999)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        written = await sftp.get(str(remote), local)

    assert written == 1000
    assert local.read_bytes() == CONTENT[:1000]


async def test_resumed_download_progress_starts_where_the_file_left_off(tmp_path: Path):
    # "0 of 100 MB" after resuming at 90 MB is a lie about how much is left, and a progress
    # bar that jumps backwards is the visible symptom of an offset bug underneath.
    needs_real_server()
    remote = tmp_path / "source.bin"
    remote.write_bytes(CONTENT)
    local = tmp_path / "partial.bin"
    local.write_bytes(CONTENT[:40_000])
    seen: list[tuple[int, int | None]] = []

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        _ = await sftp.get(
            str(remote), local, resume=True, progress=lambda t, n: seen.append((t, n))
        )

    assert seen[0] == (40_000, len(CONTENT)), "progress restarted the count"
    assert seen[-1] == (len(CONTENT), len(CONTENT))
    assert seen == sorted(seen), "progress went backwards"


# --- uploading --------------------------------------------------------------------------------


async def test_resume_with_the_default_staging_name_is_refused(tmp_path: Path):
    """The interaction the card predicted wrongly, pinned in the shape it actually has.

    Not "EXCL refuses to adopt the staging file" -- EXCL never meets it, because the staging
    name carries fresh randomness on every call. The previous run's file has a name this run
    cannot reconstruct, so there is nothing to resume into and no honest answer but to say so.
    """
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError) as exc:
            _ = await sftp.put(source, str(tmp_path / "dest.bin"), resume=True)

    assert exc.value.args[0] == (
        "resume=True needs staging_name= when atomic=True: the default staging file is "
        "named with fresh randomness each call, so a previous run's partial upload cannot "
        "be found. Pass staging_name= to fix the name, or atomic=False to resume the "
        "destination itself"
    )


async def test_a_resumed_in_place_upload_completes_the_destination(tmp_path: Path):
    # atomic=False has already given up on a consumer never seeing a partial file, which is
    # the same thing a resumable upload leaves lying around between runs -- so this is the
    # combination that needs no extra name.
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT)
    destination = tmp_path / "dest.bin"
    destination.write_bytes(CONTENT[:30_000])

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(destination), publish=Publish(atomic=False), resume=True
        )

    assert result.transferred == len(CONTENT) - 30_000
    assert result.mechanism is PublishMechanism.IN_PLACE
    assert destination.read_bytes() == CONTENT


async def test_a_resumed_atomic_upload_adopts_the_named_staging_file(tmp_path: Path):
    """The one path where resume and atomic publish both hold.

    The staging file is the caller's name, so it is findable; ``EXCL`` is dropped so it can be
    adopted; and the publish step is unchanged, so the destination still appears in one move.
    """
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT)
    staging = tmp_path / "dest.bin.partial"
    staging.write_bytes(CONTENT[:30_000])
    destination = tmp_path / "dest.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(destination), publish=Publish(staging_name=b"dest.bin.partial"), resume=True
        )

    assert result.transferred == len(CONTENT) - 30_000
    assert destination.read_bytes() == CONTENT
    assert not staging.exists(), "the staging file should have been renamed, not copied"


async def test_a_resumed_upload_of_an_already_complete_staging_file_still_publishes(tmp_path: Path):
    # The case a naive "nothing to do" shortcut gets wrong: no bytes need moving, and the
    # file still has to be renamed into place or the upload never happened.
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT)
    staging = tmp_path / "dest.bin.partial"
    staging.write_bytes(CONTENT)
    destination = tmp_path / "dest.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(destination), publish=Publish(staging_name=b"dest.bin.partial"), resume=True
        )

    assert result.transferred == 0
    assert destination.read_bytes() == CONTENT
    assert not staging.exists()


async def test_a_remote_partial_longer_than_the_local_file_is_refused(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT[:1000])
    destination = tmp_path / "dest.bin"
    destination.write_bytes(CONTENT[:5000])

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, str(destination), publish=Publish(atomic=False), resume=True)

    assert exc.value.args[0] == (
        f"cannot resume: {str(destination).encode()!r} is 5000 bytes on the server and the "
        f"local file is only 1000, so what is there is not a prefix of what we are sending"
    )
    assert destination.read_bytes() == CONTENT[:5000], "the destination was touched anyway"


async def test_a_resumed_upload_with_nothing_on_the_server_sends_the_whole_file(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT)
    destination = tmp_path / "dest.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(destination), publish=Publish(atomic=False), resume=True
        )

    assert result.transferred == len(CONTENT)
    assert destination.read_bytes() == CONTENT


async def test_resumed_upload_progress_starts_where_the_server_left_off(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "payload.bin"
    source.write_bytes(CONTENT)
    destination = tmp_path / "dest.bin"
    destination.write_bytes(CONTENT[:30_000])
    seen: list[tuple[int, int | None]] = []

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        _ = await sftp.put(
            source,
            str(destination),
            publish=Publish(atomic=False),
            resume=True,
            progress=lambda t, n: seen.append((t, n)),
        )

    assert seen[0] == (30_000, len(CONTENT))
    assert seen[-1] == (len(CONTENT), len(CONTENT))
    assert seen == sorted(seen), "progress went backwards"


# --- a server that will not say how big anything is --------------------------------------------


class SizelessServer:
    """Answers every STAT with attributes carrying no size at all.

    DESIGN.md 7 lists attribute honesty among the things real endpoints differ on, and this is
    the shape the real ``sftp-server`` will never produce on demand. Both resume directions
    need a size to check a partial against, so both have to refuse rather than guess zero and
    silently re-send the file.
    """

    def __init__(self) -> None:
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

    def _reply(self, packet) -> None:
        self._outbox += encode(packet)
        self._has_output.set()

    def _dispatch(self, packet) -> None:
        if isinstance(packet, Init):
            self._reply(Version(3))
        elif isinstance(packet, Stat | LStat):
            self._reply(AttrsReply(packet.request_id, Attrs()))
        else:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))


async def test_a_download_cannot_resume_from_a_server_that_reports_no_size(tmp_path: Path):
    local = tmp_path / "partial.bin"
    local.write_bytes(b"abc")

    async with open_session(SizelessServer()) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(b"/remote.bin", local, resume=True)

    assert exc.value.args[0] == (
        "resume needs a size for b'/remote.bin' and this server did not report one, "
        "so a local partial cannot be checked against it"
    )


async def test_an_upload_cannot_resume_onto_a_server_that_reports_no_size(tmp_path: Path):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abcdef")

    async with open_session(SizelessServer()) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, b"/remote.bin", publish=Publish(atomic=False), resume=True)

    assert exc.value.args[0] == (
        "resume needs a size for b'/remote.bin' and this server did not report one, "
        "so there is no offset to continue from and nothing to check it against"
    )


# --- interrupted for real, then resumed --------------------------------------------------------


class StopPartwayError(Exception):
    """Raised from a progress callback to cut a transfer off at a known point.

    Deterministic where a timeout is not. An earlier version of these two tests used
    ``move_on_after(0.001)`` and passed whether or not the transfer was ever interrupted --
    if it finished in time, the "resume" resumed nothing and the arithmetic still balanced.
    A test that passes when the scenario did not happen is not a test.
    """


INTERRUPTIBLE_SIZE = 2_000_000
"""Big enough that one request cannot carry it, with room for a few more to slip out.

Sized rather than guessed. The upload side releases its send window inside ``_acknowledge``
and calls the progress callback *after* -- so between the callback raising and the task group
unwinding, another chunk or two can legitimately go out. At 400 KB and a ~255 KB request that
was the difference between "interrupted" and "finished", and the test failed on the upload
side only. The fixture is now several requests long, so a couple of extra ones in flight
cannot complete the file."""


def stop_once_something_has_moved(transferred: int, total: int | None) -> None:
    """Abort at the first reply that carried bytes but did not finish the file."""
    if total is not None and 0 < transferred < total:
        raise StopPartwayError


async def test_a_download_killed_partway_resumes_to_a_byte_identical_file(tmp_path: Path):
    """The scenario the feature exists for, driven end to end rather than simulated.

    The first attempt dies after one reply, leaving whatever the scheduler had written. The
    second picks up from there. That the two halves join correctly is the claim, and random
    content is what makes comparing bytes mean something -- a hole of zeros in the middle of
    a file of zeros proves nothing.
    """
    needs_real_server()
    big = os.urandom(INTERRUPTIBLE_SIZE)
    remote = tmp_path / "big.bin"
    remote.write_bytes(big)
    local = tmp_path / "copy.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(StopPartwayError):
            _ = await sftp.get(str(remote), local, depth=1, progress=stop_once_something_has_moved)

        partial = local.stat().st_size
        assert 0 < partial < len(big), "the transfer was not actually interrupted"

        written = await sftp.get(str(remote), local, resume=True)

    assert local.read_bytes() == big
    assert written == len(big) - partial


async def test_an_upload_killed_partway_resumes_to_a_byte_identical_file(tmp_path: Path):
    # The upload side runs its send and receive halves in a task group, so an exception from
    # the progress callback arrives wrapped -- this also checks it is unwrapped before a
    # caller's `except` ladder ever sees it.
    needs_real_server()
    big = os.urandom(INTERRUPTIBLE_SIZE)
    source = tmp_path / "big.bin"
    source.write_bytes(big)
    destination = tmp_path / "dest.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(StopPartwayError):
            _ = await sftp.put(
                source,
                str(destination),
                publish=Publish(atomic=False),
                depth=1,
                progress=stop_once_something_has_moved,
            )

        partial = destination.stat().st_size
        assert 0 < partial < len(big), "the transfer was not actually interrupted"

        result = await sftp.put(
            source, str(destination), publish=Publish(atomic=False), resume=True
        )

    assert destination.read_bytes() == big
    assert result.transferred == len(big) - partial

"""What a failed transfer leaves behind, and whether its error can name it.

D-117. A `get` of a *directory* raised `TransferError` with `local_path=None` and left a
zero-byte local file with the right name -- so the exception could not name the artefact it
had just created, on the one path that creates one. DoD 3 states the contract in as many
words: `TransferError` carries bytes transferred, offset **and both paths**.

Two separable claims are proven here and they are not the same claim.

* **Every** transfer error that has a local file names it, in both directions, across every
  failure shape a `get` or a `put` can reach -- not only the one that prompted the card. The
  field is filled at the `get`/`put` boundary rather than at each raise site, so this is also
  the test that the boundary catches the shapes nobody thought about.
* **The file is left where it is, deliberately**, and the error says so in a note. That is the
  decision the card asked to have made out loud rather than inherited: the destination is the
  caller's own file rather than a staging name of ours, `resume=True` continues from exactly
  this partial, and `no_follow` is off by default so the path may be a symlink they made.

The fakes are imported rather than rewritten, for the reason `test_cancellation.py` gives.
`TreeServer` already answers a directory read the way OpenSSH does -- which it did *not* until
`tests/server_contract.py` asked it and the reference the same question (D-114) -- and
`PublishingServer` already implements the upload ladder.
"""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import Attrs, Data, Read, Status, StatusCode
from gantry_sftp.exceptions import TransferError
from gantry_sftp.session import Mode, Publish, open_session
from gantry_sftp.session._session import _name_the_local_file
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from test_publish import PublishingServer
from test_recursive import DIRECTORY, REGULAR, TreeServer, named

pytestmark = pytest.mark.anyio

CONTENT = bytes(range(256)) * 8
"""2048 bytes, so a transfer can fail with some of it on disk and some of it not."""

CHUNK = 512
"""Bytes a chunking fake serves per read, and therefore where a part-way failure lands."""

TREE = {
    b"/root": (named(b"data.bin", REGULAR, len(CONTENT)), named(b"sub", DIRECTORY)),
    b"/root/sub": (),
}
FILES = {b"/root/data.bin": CONTENT}
REMOTE = b"/root/data.bin"
DIRECTORY_PATH = b"/root/sub"


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


# --- the reproduction, asked of a real server and of the fake ---------------------------------


async def test_a_get_of_a_directory_names_the_file_it_left_on_disk(tmp_path: Path):
    """The card's case, against the server it was measured on.

    OpenSSH permits `open(2)` on a directory, so the refusal arrives at the `READ` -- by which
    time `get` has created the destination. The zero-byte file with the right name is the whole
    hazard: `if os.path.exists` reads it as a download that happened.
    """
    needs_real_server()
    (tmp_path / "sub").mkdir()
    local = tmp_path / "landed.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(str(tmp_path / "sub"), local)

    assert exc.value.local_path == str(local)
    assert exc.value.remote_path == str(tmp_path / "sub").encode()
    assert exc.value.transferred == 0
    assert exc.value.offset == 0
    assert exc.value.args[0] == (
        "server refused the first read, at offset 0: FAILURE Failure -- the handle opened and "
        "then not one byte could be read, so nothing arrived and nothing was truncated. v3's "
        "FAILURE says no more than 'no', and one thing that reaches here looking exactly like "
        "this is a directory: a server that lets one be opened refuses at the read instead"
    )
    # The decision, stated as an assertion: it is still there, and the error said so.
    assert local.exists()
    assert local.stat().st_size == 0
    assert str(local) in "".join(exc.value.__notes__)
    # And `str()` carries both paths, which is what an operator actually reads.
    assert f"local='{local}'" in str(exc.value)


async def test_the_fake_answers_a_directory_download_the_same_way(tmp_path: Path):
    """The same question of the fake, because the two lanes prove different things.

    The real-server test above proves the client against the reference; it cannot prove the
    fake, which is a different test over different code. `TreeServer` answered this wrongly --
    it refused the `OPEN` -- until the contract suite asked both, and nothing failed either
    before or after the correction (D-114). So this pins the pair rather than one of them.
    """
    local = tmp_path / "landed.bin"
    server = TreeServer(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(DIRECTORY_PATH, local)

    assert exc.value.local_path == str(local)
    assert exc.value.args[0].startswith("server refused the first read, at offset 0: FAILURE")
    assert local.exists()
    assert local.stat().st_size == 0


# --- the sweep: every shape, not the one that prompted the card -------------------------------


class RefusesReadsFrom(TreeServer):
    """Serves ``CHUNK`` bytes per read, and refuses every read at or past ``after``.

    The chunking is what makes "part way through" reachable at all against a fake: `get`
    derives its read length from the negotiated limits, so one request would otherwise cover
    this whole file and there would be no second read to refuse. A short `DATA` is legal and is
    re-queued as a read of the remainder, which is exactly the machinery being leaned on.
    """

    after = 0

    def _on_read(self, packet: Read) -> None:
        if packet.offset >= self.after:
            self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"no"))
            return
        content = self.files[self._handles[packet.handle]]
        chunk = content[packet.offset : packet.offset + min(packet.length, CHUNK)]
        self._reply(Data(packet.request_id, memoryview(chunk)))


class AlwaysZeroLength(TreeServer):
    """Answers every read with a `DATA` carrying nothing, which makes no progress."""

    def _on_read(self, packet: Read) -> None:
        self._reply(Data(packet.request_id, memoryview(b"")))


class Silent(TreeServer):
    """Opens the file and then never answers a read: the idle timeout's shape."""

    def _on_read(self, packet: Read) -> None:
        return


class OverstatesTheSize(TreeServer):
    """Reports a file longer than it will serve, so the download ends short of the stat."""

    def _attrs_for(self, path: bytes) -> Attrs | None:
        attrs = super()._attrs_for(path)
        if attrs is not None and attrs.size == len(CONTENT):
            return Attrs(len(CONTENT) * 2, None, attrs.permissions)
        return attrs


class NoPermissions(TreeServer):
    """Describes a file that exists with no attributes at all -- no size, no mode.

    Legal: v3 ATTRS makes every field optional. It is the shape that makes `Mode.PRESERVE`
    unanswerable and a resume uncheckable, and both are refusals rather than defaults.
    """

    def _attrs_for(self, path: bytes) -> Attrs | None:
        attrs = super()._attrs_for(path)
        return Attrs() if attrs is not None else None


def _seed(local: Path, content: bytes) -> None:
    """Write a local partial for a resume to find.

    A plain function rather than a line in the async helper below, because ASYNC240 is right
    that a blocking filesystem call does not belong in a coroutine -- and silencing it per line
    is how a real one gets waved through later.
    """
    local.write_bytes(content)


async def _refused_first_read(local: Path) -> TransferError:
    server = TreeServer(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(DIRECTORY_PATH, local)
    return exc.value


async def _refused_part_way(local: Path) -> TransferError:
    server = RefusesReadsFrom(tree=TREE, files=FILES)
    server.after = CHUNK
    async with open_session(server, depth=1) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(REMOTE, local, depth=1)
    return exc.value


async def _spun_by_zero_length_data(local: Path) -> TransferError:
    server = AlwaysZeroLength(tree=TREE, files=FILES)
    async with open_session(server, depth=1) as sftp:  # type: ignore[arg-type]
        with anyio.fail_after(30):
            with pytest.raises(TransferError) as exc:
                _ = await sftp.get(REMOTE, local, depth=1)
    return exc.value


async def _timed_out(local: Path) -> TransferError:
    server = Silent(tree=TREE, files=FILES)
    async with open_session(server, idle_timeout=0.25) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(REMOTE, local)
    return exc.value


async def _ended_short_of_the_stated_size(local: Path) -> TransferError:
    server = OverstatesTheSize(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(REMOTE, local)
    return exc.value


async def _nothing_to_preserve(local: Path) -> TransferError:
    server = NoPermissions(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(REMOTE, local, mode=Mode.PRESERVE)
    return exc.value


async def _resume_with_no_remote_size(local: Path) -> TransferError:
    _seed(local, CONTENT[:64])
    server = NoPermissions(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(REMOTE, local, resume=True)
    return exc.value


async def _resume_from_a_partial_that_is_too_long(local: Path) -> TransferError:
    _seed(local, CONTENT * 2)
    server = TreeServer(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(REMOTE, local, resume=True)
    return exc.value


DOWNLOAD_FAILURES = {
    "refused first read": _refused_first_read,
    "refused part way": _refused_part_way,
    "zero-length data": _spun_by_zero_length_data,
    "idle timeout": _timed_out,
    "short of the stated size": _ended_short_of_the_stated_size,
    "nothing to preserve": _nothing_to_preserve,
    "resume with no size": _resume_with_no_remote_size,
    "resume from too long a partial": _resume_from_a_partial_that_is_too_long,
}


@pytest.mark.parametrize("shape", list(DOWNLOAD_FAILURES), ids=lambda name: name.replace(" ", "-"))
async def test_every_download_failure_names_the_local_file(tmp_path: Path, shape: str):
    """The completeness half, and the reason the field is filled at the boundary.

    Four of these shapes build the error somewhere that already knew both paths and four do
    not, and a reader cannot tell which from the outside -- which is the argument. A raise site
    added inside `get` carries the field without anybody remembering to pass it.
    """
    local = tmp_path / "landed.bin"
    failure = await DOWNLOAD_FAILURES[shape](local)
    assert failure.local_path == str(local)
    assert failure.remote_path is not None


async def test_a_refused_upload_names_the_local_source(tmp_path: Path):
    """The other direction, asserted rather than assumed from this one.

    The two have disagreed before on exactly this kind of symmetry -- D-96 on which types a
    path argument takes, D-103 on which refusals a predicate swallows -- so `put` gets its own
    boundary and its own proof.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(CONTENT)
    server = PublishingServer(refuse={"write": StatusCode.PERMISSION_DENIED})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, b"/incoming/report.csv", publish=Publish(atomic=False))

    assert exc.value.local_path == str(source)
    assert exc.value.remote_path == b"/incoming/report.csv"
    assert exc.value.args[0] == (
        "server refused a write at offset 0: PERMISSION_DENIED PERMISSION_DENIED"
    )


async def test_an_upload_error_keeps_the_local_path_the_raise_site_chose(tmp_path: Path):
    """A staged upload names the *source*, not the staging file it was writing.

    Worth pinning because the two names are both plausible here and only one is the caller's.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(CONTENT)
    server = PublishingServer(refuse={"write": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, b"/incoming/report.csv")

    assert exc.value.local_path == str(source)


# --- the decision: the file stays, and the error says where it is -----------------------------


async def test_a_download_that_fails_part_way_leaves_exactly_what_arrived(tmp_path: Path):
    """Not deleted, and not zeroed: the bytes that landed are still there.

    This is the fact `resume=True` is built on, and it is what makes deleting on failure the
    expensive choice rather than the tidy one.
    """
    local = tmp_path / "landed.bin"
    failure = await _refused_part_way(local)

    assert failure.transferred == 512
    assert local.exists()
    assert local.read_bytes() == CONTENT[:512]
    assert str(local) in "".join(failure.__notes__)
    assert "resume=True continues from exactly this partial" in "".join(failure.__notes__)


async def test_a_resume_continues_from_the_partial_a_failure_left(tmp_path: Path):
    """End to end: the artefact of one call is the input to the next.

    The point of running both halves rather than writing a partial by hand -- which
    `test_resume.py` already does -- is that this proves the *same file* a failure left is a
    valid resume input, which is the whole argument for keeping it.
    """
    local = tmp_path / "landed.bin"
    _ = await _refused_part_way(local)
    assert local.read_bytes() == CONTENT[:512]

    server = TreeServer(tree=TREE, files=FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get(REMOTE, local, resume=True)

    assert result.adopted == 512
    assert result.transferred == len(CONTENT) - 512
    assert local.read_bytes() == CONTENT


async def test_a_failure_before_the_local_file_is_opened_leaves_nothing_and_says_nothing(
    tmp_path: Path,
):
    """The note is not attached where it would be false, which a mechanical sweep gets wrong.

    `mode=Mode.PRESERVE` against a server that reports no permissions is refused before the
    first `READ` -- and therefore before the destination is opened. There is no artefact, so
    there is no sentence about one; the local path is still carried, because that is the file
    the caller asked for.
    """
    local = tmp_path / "landed.bin"
    failure = await _nothing_to_preserve(local)

    assert failure.local_path == str(local)
    assert not local.exists(), "a refusal before the first READ created a file"
    assert not hasattr(failure, "__notes__")


def test_a_local_path_the_raise_site_supplied_is_never_overwritten():
    """The boundary fills a blank; it does not correct anybody.

    The innermost site is the most specific one, and a boundary that overwrote would replace a
    name chosen with more information by one chosen with less.
    """
    already_named = TransferError("refused", local_path="/data/the-one-that-failed")
    _name_the_local_file(already_named, "/data/the-boundary-argument")
    assert already_named.local_path == "/data/the-one-that-failed"

    unnamed = TransferError("refused")
    _name_the_local_file(unnamed, Path("/data/the-boundary-argument"))
    assert unnamed.local_path == "/data/the-boundary-argument"

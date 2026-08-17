"""Transferring an explicit list, where the caller chose the files and the library names them.

Split the way the operation is: the derivation is pure and is exercised with no server at all,
and everything that has to be true of a real transfer -- input-ordered results under concurrency,
the collision raised at the end, the refusals that fire before anything moves -- is run against a
real ``sftp-server``.

**A list flattens and a tree does not**, so two hazards exist here that no tree test can reach:
two paths whose basenames are equal, and a basename that is legal where it came from and illegal
where it is going. Both are asserted in both directions.
"""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest

from gantry_sftp.exceptions import DestinationCollisionError, UnsafePathError
from gantry_sftp.session import open_session
from gantry_sftp.session._many import settle_downloads, settle_uploads
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from local_filesystem import give_one_file_a_second_name

pytestmark = pytest.mark.anyio


def needs_real_server() -> None:
    """These move real bytes, which the scripted servers here do not implement."""
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


# --- deriving the name, which is pure -----------------------------------------------------


def test_a_downloads_destination_is_the_remote_basename(tmp_path: Path):
    settled = settle_downloads([b"/incoming/a.csv", "/other/b.csv"], destination=tmp_path)

    assert [item.remote for item in settled] == [b"/incoming/a.csv", b"/other/b.csv"]
    assert [item.target for item in settled] == [tmp_path / "a.csv", tmp_path / "b.csv"]


def test_an_uploads_destination_is_the_local_basename(tmp_path: Path):
    settled = settle_uploads([tmp_path / "a.csv", "sub/b.csv"], remote_directory=b"/drop")

    assert [item.source for item in settled] == [tmp_path / "a.csv", Path("sub/b.csv")]
    assert [item.remote for item in settled] == [b"/drop/a.csv", b"/drop/b.csv"]


def test_the_settled_order_is_the_callers_order(tmp_path: Path):
    """The whole reason the results can be returned in input order is that this list is."""
    names = [f"/incoming/{index}.csv".encode() for index in range(20)]

    assert [item.remote for item in settle_downloads(names, destination=tmp_path)] == names


@pytest.mark.parametrize(
    ("remote", "reason"),
    [
        (b"/incoming/..", "a relative directory entry"),
        (b"/incoming/.", "a relative directory entry"),
        (b"/incoming/", "an empty name"),
        (b"/", "an empty name"),
    ],
)
def test_a_remote_path_with_no_usable_basename_is_refused(
    tmp_path: Path, remote: bytes, reason: str
):
    """The derived name goes through the *local* check, which is not the remote one."""
    with pytest.raises(UnsafePathError) as caught:
        _ = settle_downloads([remote], destination=tmp_path)

    assert caught.value.reason == reason


def test_a_trailing_dot_is_not_swallowed_into_the_parents_name(tmp_path: Path):
    """`posixpath.basename` and not `PurePosixPath.name`, and the difference is a wrong answer.

    `PurePosixPath("/a/.").name` is `"a"`, so pathlib would derive the *parent's* name and
    transfer a directory entry as though it were the file beside it. The bytes function answers
    `b"."`, which the component check then refuses -- which is the honest end for a path that
    names a directory entry rather than a file.
    """
    with pytest.raises(UnsafePathError) as caught:
        _ = settle_downloads([b"/incoming/."], destination=tmp_path)

    assert caught.value.reason == "a relative directory entry"


def test_an_uploads_basename_can_reach_the_refusal_no_walk_can(tmp_path: Path):
    """D-184's claim was true of every caller that existed, and this is the one that changes it.

    `remote_component`'s docstring records that no caller can reach its refusal, because every
    name it is asked about comes from `os.scandir`, which cannot produce `.`, `..`, a separator
    or an empty name. A caller-supplied path can: `Path("dir/..")` has the basename `..`.
    """
    with pytest.raises(UnsafePathError) as caught:
        _ = settle_uploads([tmp_path / "dir" / ".."], remote_directory=b"/drop")

    assert caught.value.reason == "a relative directory entry"


def test_two_remote_paths_with_one_basename_are_refused(tmp_path: Path):
    with pytest.raises(ValueError) as caught:
        _ = settle_downloads([b"/a/x.csv", b"/b/x.csv"], destination=tmp_path)

    assert caught.value.args[0] == (
        f"get_many() cannot transfer b'/b/x.csv' and b'/a/x.csv' into {tmp_path}: both are "
        f"named b'x.csv' there, so the second would overwrite the first. A list flattens, "
        f"where a tree keeps the directories that told these two apart -- transfer them one "
        f"at a time to destinations you name, or use the tree form"
    )


def test_two_local_paths_with_one_basename_are_refused(tmp_path: Path):
    with pytest.raises(ValueError) as caught:
        _ = settle_uploads([Path("a/x.csv"), Path("b/x.csv")], remote_directory=b"/drop")

    assert caught.value.args[0] == (
        "put_many() cannot transfer b/x.csv and a/x.csv into b'/drop': both are named "
        "b'x.csv' there, so the second would overwrite the first. A list flattens, where a "
        "tree keeps the directories that told these two apart -- transfer them one at a time "
        "to destinations you name, or use the tree form"
    )


def test_the_duplicate_reported_is_the_first_pair_in_the_callers_order(tmp_path: Path):
    """Three colliding entries report one pair, and which one has to be reproducible.

    A set would report whichever the hash order surfaced, and the same call would name a
    different pair on a different run -- which is a message nobody can act on twice.
    """
    for _ in range(4):
        with pytest.raises(ValueError) as caught:
            _ = settle_downloads([b"/a/x.csv", b"/b/x.csv", b"/c/x.csv"], destination=tmp_path)

        assert "b'/b/x.csv' and b'/a/x.csv'" in caught.value.args[0]


def test_an_unusable_name_is_refused_before_a_duplicate_is(tmp_path: Path):
    """Both are refusals before anything moves, so the order is only about the message.

    The unsafe name is the more serious of the two and is what the caller should see first;
    pinned so a reordering of the two passes is a visible decision rather than a silent one.
    """
    with pytest.raises(UnsafePathError):
        _ = settle_downloads([b"/a/x.csv", b"/b/x.csv", b"/c/.."], destination=tmp_path)


def test_an_empty_list_settles_to_nothing(tmp_path: Path):
    assert settle_downloads([], destination=tmp_path) == []
    assert settle_uploads([], remote_directory=b"/drop") == []


# --- against a real server ----------------------------------------------------------------


def _remote_files(root: Path, sizes: dict[str, int]) -> list[bytes]:
    """Build files in separate directories, so only the basenames collide if anything does."""
    made: list[bytes] = []
    for index, (name, size) in enumerate(sizes.items()):
        directory = root / f"d{index}"
        directory.mkdir()
        _ = (directory / name).write_bytes(bytes([index % 256]) * size)
        made.append(os.fsencode(directory / name))
    return made


async def test_a_list_of_remote_files_lands_in_one_directory(tmp_path: Path):
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    remotes = _remote_files(root, {"a.csv": 10, "b.csv": 20, "c.csv": 30})
    destination = tmp_path / "dest"

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        results = await sftp.get_many(remotes, destination)

    assert [result.transferred for result in results] == [10, 20, 30]
    assert sorted(path.name for path in destination.iterdir()) == ["a.csv", "b.csv", "c.csv"]
    assert (destination / "b.csv").read_bytes() == bytes([1]) * 20


@pytest.mark.parametrize(
    ("options", "sequential"),
    [
        pytest.param({}, True, id="default"),
        pytest.param({"concurrency": 1}, True, id="one"),
        pytest.param({"concurrency": 4}, False, id="four"),
    ],
)
async def test_the_results_come_back_in_the_order_they_were_asked_for(
    tmp_path: Path, options: dict[str, int], sequential: bool
):
    """The claim `get_many` makes that a fan-out of `get` does not.

    **The completion order is forced rather than hoped for.** Writing this against file *sizes*
    and letting the scheduler decide produced a row that failed under trio and passed under
    asyncio on the same broken build -- the two orders happened to coincide on one backend, so
    half the matrix was asserting nothing. A descending delay per input position makes the
    completion order the exact reverse of the caller's on any backend, and `completed` is
    asserted too: if the two orders ever agreed, this row would pass without the sort existing.

    **The `default` case is the point of the parametrisation** (D-191). This test passed
    `concurrency=` on every row, so `concurrency: int = 1` was pinned by nothing and a mutant
    raising it survived a full lane. Omitting the argument and asserting the *sequential* order
    is what makes the shipped default a tested one -- and the `four` row is what stops that
    assertion being satisfiable by a method that ignores the argument.
    """
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    sizes = {"first.bin": 30, "second.bin": 20, "third.bin": 10}
    remotes = _remote_files(root, sizes)
    completed: list[bytes] = []

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        downloaded = sftp.get

        async def delayed_get(remote, local, **kwargs):  # type: ignore[no-untyped-def]
            await anyio.sleep(0.05 * (len(remotes) - remotes.index(remote)))
            result = await downloaded(remote, local, **kwargs)
            completed.append(remote)
            return result

        sftp.get = delayed_get  # type: ignore[method-assign]
        try:
            results = await sftp.get_many(remotes, tmp_path / "dest", **options)
        finally:
            sftp.get = downloaded  # type: ignore[method-assign]

    assert [result.transferred for result in results] == list(sizes.values())
    # The other half: prove the orders differed, so the assertion above is doing work.
    assert completed == (remotes if sequential else list(reversed(remotes)))


async def test_a_list_of_local_files_is_uploaded_into_one_directory(tmp_path: Path):
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    sources = []
    for index, name in enumerate(["a.csv", "b.csv"]):
        directory = tmp_path / f"src{index}"
        directory.mkdir()
        _ = (directory / name).write_bytes(b"x" * (index + 1))
        sources.append(directory / name)

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        results = await sftp.put_many(sources, os.fsencode(root / "drop"))

    assert [result.transferred for result in results] == [1, 2]
    assert sorted(path.name for path in (root / "drop").iterdir()) == ["a.csv", "b.csv"]


async def test_an_upload_list_returns_what_each_file_published_with(tmp_path: Path):
    """The per-file result is the reason this returns them rather than a summary count."""
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    source = tmp_path / "one.csv"
    _ = source.write_bytes(b"hello")

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        results = await sftp.put_many([source], os.fsencode(root))

    assert len(results) == 1
    assert results[0].transferred == 5
    assert results[0].remote_path == os.fsencode(root / "one.csv")
    # The half a summary count cannot carry: this one was published by a rename, not written
    # into place, and only the per-file result says so.
    assert results[0].atomic


@pytest.mark.parametrize("concurrency", [1, 4])
async def test_two_names_the_destination_merges_are_refused_at_the_end(
    tmp_path: Path, concurrency: int
):
    """The folding collision, which the up-front duplicate check cannot see.

    `README.md` and `readme.md` are different bytes, so nothing about the caller's list is
    wrong -- it is the destination that makes them one file. A hard link produces exactly that
    condition on a case-sensitive filesystem: two names, one inode, which is what `lstat`
    reports on APFS for the pair.

    **Which name is refused is the assertion, and it is the second in the caller's list at
    both concurrencies** -- the scheduler does not get a say in what the error names.

    Two limits, recorded because they are easy to mistake for coverage. Moving the claim out
    of the producer and into the worker was tried and this row does not catch it: the pool's
    stream has a zero buffer, so claim order follows list order either way. And the
    *reservation* -- the empty file `_claim_local_destination` creates before asking -- cannot
    be exercised here at all, because the hard-link stand-in for case folding needs the inode
    to exist before the download starts. On a genuinely folding destination the reservation is
    what makes the second name detectable; on ext4 nothing distinguishes it.
    """
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    remotes = _remote_files(root, {"README.md": 4, "readme.md": 6, "other.txt": 8})
    destination = tmp_path / "dest"
    destination.mkdir()
    (destination / "README.md").touch()
    give_one_file_a_second_name(destination / "README.md", destination / "readme.md")

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(DestinationCollisionError) as caught:
            _ = await sftp.get_many(remotes, destination, concurrency=concurrency)

    # Everything transferable still transferred: the refusal is only the write that would have
    # destroyed an earlier one. And it is the *second* name in the caller's list, at both
    # concurrencies -- the scheduler does not get a say.
    assert [collision.remote for collision in caught.value.collisions] == [remotes[1]]
    assert caught.value.files == 2
    assert caught.value.transferred == 12


async def test_a_duplicate_basename_refuses_before_anything_is_transferred(tmp_path: Path):
    """The up-front half, and the assertion is what is *not* on disk afterwards."""
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    remotes = _remote_files(root, {"x.csv": 5})
    remotes = [*remotes, remotes[0].replace(b"/d0/", b"/d0/")]
    destination = tmp_path / "dest"

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError):
            _ = await sftp.get_many(remotes, destination)

    assert list(destination.iterdir()) == []


async def test_an_upload_duplicate_refuses_before_the_directory_is_even_made(tmp_path: Path):
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    first, second = tmp_path / "a" / "x.csv", tmp_path / "b" / "x.csv"
    for path in (first, second):
        path.parent.mkdir()
        _ = path.write_bytes(b"z")

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError):
            _ = await sftp.put_many([first, second], os.fsencode(root / "drop"))

    assert not (root / "drop").exists()


# --- the refusals the arguments themselves earn -------------------------------------------


async def test_progress_is_refused_above_one_worker(tmp_path: Path):
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError) as caught:
            _ = await sftp.get_many(
                [b"/a.csv"], tmp_path, progress=lambda a, b: None, concurrency=2
            )

    assert caught.value.args[0] == (
        "get_many() cannot take progress= with concurrency=2: the callback is (transferred, "
        "total) per file and carries no file identity, so several workers reporting at once "
        "produce one stream of counters that reset unpredictably. Use concurrency=1 to keep "
        "per-file progress, or drop progress= to keep the concurrency and read the counts "
        "from the returned results"
    )


async def test_the_refusal_says_list_where_a_tree_says_tree(tmp_path: Path):
    """The message's noun is the one thing a shared helper gets wrong by default."""
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError) as caught:
            _ = await sftp.put_many([], b"/drop", concurrency=0)

    assert caught.value.args[0] == (
        "put_many() concurrency must be at least 1, got 0; 1 transfers the list one file at a time"
    )


async def test_an_empty_list_transfers_nothing_and_says_so(tmp_path: Path):
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.get_many([], tmp_path / "dest") == ()
        assert await sftp.put_many([], os.fsencode(root / "drop")) == ()


# --- the defaults, which are only tested by omitting them (D-191) -----------------------------


@pytest.mark.parametrize(
    ("options", "resumes"),
    [pytest.param({}, False, id="default"), pytest.param({"resume": True}, True, id="asked")],
)
async def test_a_list_download_resumes_only_when_asked(
    tmp_path: Path, options: dict[str, bool], resumes: bool
):
    """`resume: bool = False` was pinned by nothing, so a mutant flipping it survived a lane.

    **Observed through the file's content rather than by counting `READ`s**, which is what lets
    this run against a real server instead of a scripted one. The destination is pre-filled with
    the right *length* and the wrong *bytes*: resumption decides it is complete on size alone and
    leaves the lie in place, and a download that does not resume overwrites it with the truth.
    `test_a_resumed_download_does_not_re_read_a_file_it_already_has` asserts the same behaviour
    from the packet side for a tree.

    The `asked` row is not decoration -- without it the default row passes against a `get_many`
    that has no working `resume=` at all.
    """
    needs_real_server()
    root = tmp_path / "srv"
    root.mkdir()
    remotes = _remote_files(root, {"a.csv": 10, "b.csv": 20})
    destination = tmp_path / "dest"
    destination.mkdir()
    # Same length as the remote, so a size check calls it complete; different bytes, so
    # whether it was re-read is readable afterwards.
    _ = (destination / "a.csv").write_bytes(b"?" * 10)

    async with (
        open_local_server_transport(cwd=root) as transport,
        open_session(transport) as sftp,
    ):
        _ = await sftp.get_many(remotes, destination, **options)

    landed = (destination / "a.csv").read_bytes()
    if resumes:
        assert landed == b"?" * 10, "resume=True re-read a file it had already downloaded"
    else:
        assert landed == bytes([0]) * 10, (
            "the default re-used a partial local file: get_many() resumed without being asked"
        )

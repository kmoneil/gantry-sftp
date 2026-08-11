"""Resuming a tree and overlapping its files -- and the defence that concurrency nearly broke.

The two cards were sequenced together because they share a parameter surface, and building
them together found the thing neither would have found alone: **`get_tree`'s destination-
collision check was only correct because the transfers were sequential.** It asks the
filesystem whether two remote names resolved to one local file, which the filesystem can only
answer once an inode exists -- so with workers running concurrently the second name could be
checked before the first name's transfer had created anything, and both would open the same
file with `O_TRUNC`. The test for that is here rather than beside the original D-37 tests,
because what it exercises is the concurrency.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from gantry_sftp._logging import record_fields
from gantry_sftp.codec import Read
from gantry_sftp.exceptions import DestinationCollisionError
from gantry_sftp.session import Publish, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from local_filesystem import give_one_file_a_second_name
from test_observability import names_path
from test_recursive import (
    DIRECTORY,
    REGULAR,
    TreeServer,
    build_tree,
    named,
)

pytestmark = pytest.mark.anyio


WIDE_TREE = {
    b"/root": (
        *(named(f"file{index}.bin".encode(), REGULAR, 4) for index in range(6)),
        named(b"sub", DIRECTORY),
    ),
    b"/root/sub": tuple(named(f"nested{index}.bin".encode(), REGULAR, 4) for index in range(4)),
}
WIDE_FILES = {
    **{f"/root/file{index}.bin".encode(): b"aaaa" for index in range(6)},
    **{f"/root/sub/nested{index}.bin".encode(): b"bbbb" for index in range(4)},
}


# --- the argument surface, which both methods share --------------------------------------------


@pytest.mark.parametrize("concurrency", [0, -3])
async def test_a_concurrency_below_one_is_refused_on_both_trees(tmp_path: Path, concurrency: int):
    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    source = tmp_path / "outgoing"
    source.mkdir()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as caught:
            _ = await sftp.get_tree(b"/root", tmp_path / "out", concurrency=concurrency)
        assert caught.value.args[0] == (
            f"get_tree() concurrency must be at least 1, got {concurrency}; "
            f"1 transfers the tree one file at a time"
        )
        with pytest.raises(ValueError) as caught:
            _ = await sftp.put_tree(source, b"/root", concurrency=concurrency)
        assert caught.value.args[0] == (
            f"put_tree() concurrency must be at least 1, got {concurrency}; "
            f"1 transfers the tree one file at a time"
        )


async def test_progress_with_concurrency_is_refused_rather_than_interleaved(tmp_path: Path):
    """The D-55 decision, made once and enforced in both directions.

    `ProgressCallback` is `(transferred, total)` and carries no file identity -- deliberately,
    so one reporter works everywhere. A tree calls it per file, so several workers reporting at
    once is several counters interleaved into one stream with nothing to tell them apart, and a
    bar built on it jumps backwards. Passing it through anyway is a wrong answer with no
    symptom, so it is refused and the message names both fixes.
    """
    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    source = tmp_path / "outgoing"
    source.mkdir()

    def reporter(_transferred: int, _total: int | None) -> None:
        return

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as caught:
            _ = await sftp.get_tree(b"/root", tmp_path / "out", progress=reporter, concurrency=4)

    assert caught.value.args[0] == (
        "get_tree() cannot take progress= with concurrency=4: the callback is (transferred, "
        "total) per file and carries no file identity, so several workers reporting at once "
        "produce one stream of counters that reset unpredictably. Use concurrency=1 to keep "
        "per-file progress, or drop progress= to keep the concurrency and read the counts "
        "from the returned TreeResult"
    )


async def test_progress_still_works_at_the_default_concurrency(tmp_path: Path):
    # The refusal above must not have cost the feature it is protecting.
    seen: list[tuple[int, int | None]] = []

    def reporter(transferred: int, total: int | None) -> None:
        seen.append((transferred, total))

    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", tmp_path / "out", progress=reporter)

    assert result.files == 10
    assert seen, "the progress callback was never called at concurrency=1"
    # Per file, so `total` is one file's size and not the tree's.
    assert {total for _transferred, total in seen} == {4}


# --- concurrency ------------------------------------------------------------------------------


async def test_a_concurrent_download_moves_the_same_bytes_as_a_sequential_one(tmp_path: Path):
    sequential = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(sequential) as sftp:  # type: ignore[arg-type]
        one = await sftp.get_tree(b"/root", tmp_path / "one")

    concurrent = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(concurrent) as sftp:  # type: ignore[arg-type]
        many = await sftp.get_tree(b"/root", tmp_path / "many", concurrency=4)

    assert (many.files, many.directories, many.transferred) == (
        one.files,
        one.directories,
        one.transferred,
    )
    assert sorted(p.name for p in (tmp_path / "many").rglob("*")) == sorted(
        p.name for p in (tmp_path / "one").rglob("*")
    )
    assert (tmp_path / "many" / "sub" / "nested0.bin").read_bytes() == b"bbbb"


async def test_the_byte_count_is_not_lost_to_an_augmented_assignment(tmp_path: Path):
    # `transferred += await ...` loads the target before evaluating the right-hand side, so
    # with several workers finishing inside one another's awaits every one of them adds to a
    # value it read before the others finished. The count comes out short and MiB/s derived
    # from it reports the fastest run as the slowest.
    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", tmp_path / "out", concurrency=8)

    assert result.files == 10
    assert result.transferred == sum(len(body) for body in WIDE_FILES.values())


async def test_a_failure_under_concurrency_arrives_flat_not_as_a_group(tmp_path: Path):
    # An anyio task group wraps even one failure, so `except TransferError` around a
    # `get_tree(concurrency=...)` would stop matching. Concurrent fan-out is the default case
    # for this hazard in this library, not an edge one.
    tree = {b"/root": (named(b"gone.bin", REGULAR, 4),)}
    server = TreeServer(tree=tree, files={})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(Exception) as caught:
            _ = await sftp.get_tree(b"/root", tmp_path / "out", concurrency=4)

    assert not isinstance(caught.value, BaseExceptionGroup)


# --- the collision defence, under concurrency ---------------------------------------------------

COLLIDING_TREE = {
    b"/root": (
        named(b"README.md", REGULAR, 3),
        named(b"readme.md", REGULAR, 5),
        *(named(f"pad{index}.bin".encode(), REGULAR, 4) for index in range(6)),
    )
}
COLLIDING_FILES = {
    b"/root/README.md": b"AAA",
    b"/root/readme.md": b"bbbbb",
    **{f"/root/pad{index}.bin".encode(): b"pppp" for index in range(6)},
}


async def test_two_names_for_one_local_file_are_still_caught_when_workers_overlap(
    tmp_path: Path,
):
    """The bug this slice nearly shipped.

    The ledger asks the filesystem for a local file's identity, which only exists once the
    file does. Until 0.10 the check ran before the transfer that created it and was correct
    only because the *previous* file's transfer had already finished -- a sequential accident.
    With four workers, `readme.md` is checked while `README.md` is still in flight, both pass,
    and the second truncates the first while `get_tree` reports success.

    A hard link is the faithful stand-in for a case-folding filesystem: two directory entries,
    one inode, which is exactly what APFS and NTFS hand back for this pair.
    """
    destination = tmp_path / "out"
    destination.mkdir()
    first = destination / "README.md"
    first.write_text("placeholder")
    give_one_file_a_second_name(first, destination / "readme.md")

    server = TreeServer(tree=COLLIDING_TREE, files=COLLIDING_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(DestinationCollisionError) as caught:
            _ = await sftp.get_tree(b"/root", destination, concurrency=4)

    # The first file is intact. Without the pre-creation it holds b"bbbbb" and nothing says so.
    assert first.read_bytes() == b"AAA"
    assert [(item.remote, item.first) for item in caught.value.collisions] == [
        (b"/root/readme.md", b"/root/README.md")
    ]


# --- resume -------------------------------------------------------------------------------------


async def test_a_resumed_download_does_not_re_read_a_file_it_already_has(tmp_path: Path):
    # The nine-gigabyte mirror interrupted at 95%. An already-complete file costs one STAT and
    # moves nothing, which is visible as the absence of a READ for it.
    destination = tmp_path / "out"
    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        first = await sftp.get_tree(b"/root", destination)

    assert first.transferred == 40

    resumed_server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(resumed_server) as sftp:  # type: ignore[arg-type]
        second = await sftp.get_tree(b"/root", destination, resume=True)

    assert second.files == 10
    assert second.transferred == 0, "a complete tree re-transferred its own bytes"
    assert not [packet for packet in resumed_server.seen if isinstance(packet, Read)]


async def test_a_resumed_download_continues_a_partial_file(tmp_path: Path):
    destination = tmp_path / "out"
    destination.mkdir()
    _ = (destination / "file0.bin").write_bytes(b"aa")

    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", destination, resume=True)

    # Two bytes of file0 were already there, so only the remainder moved.
    assert result.transferred == 38
    assert (destination / "file0.bin").read_bytes() == b"aaaa"


async def test_resume_and_concurrency_compose(tmp_path: Path):
    destination = tmp_path / "out"
    server = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.get_tree(b"/root", destination, concurrency=4)

    again = TreeServer(tree=WIDE_TREE, files=WIDE_FILES)
    async with open_session(again) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", destination, resume=True, concurrency=4)

    assert result.transferred == 0
    assert not [packet for packet in again.seen if isinstance(packet, Read)]


async def test_an_uploaded_tree_cannot_resume_atomically(tmp_path: Path):
    """The decision D-54 had to make, and it is `put`'s rule reaching a tree.

    Each file stages under a name generated fresh per call, so last run's partial cannot be
    found; and a `staging_name` cannot be fixed for a whole tree. Deriving one per file from
    the target would make it predictable for every file at once -- which is what
    `staging_token` exists to prevent -- so the combination is refused, not downgraded.
    """
    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.csv").write_bytes(b"aaa")

    server = TreeServer(tree={b"/dest": ()}, root=b"/dest")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as caught:
            _ = await sftp.put_tree(source, b"/dest/tree", resume=True)

    assert caught.value.args[0] == (
        "put_tree() cannot resume with atomic publishing: each file stages under a name "
        "generated fresh per call, so a previous run's partial cannot be found, and a "
        "staging_name cannot be fixed for a whole tree. Pass publish=Publish(atomic=False) "
        "to resume the destination files themselves, or drop resume=True to re-upload the "
        "tree atomically"
    )


# --- against a real server ----------------------------------------------------------------------


async def test_a_real_tree_resumes_and_overlaps(tmp_path: Path):
    """A fake only confirms what its author believed.

    Concurrency in particular: the fake answers instantly and in order, so it cannot show that
    several transfers really do overlap on one connection, nor that the reassembler keeps each
    file's bytes to itself when they do.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    remote = tmp_path / "remote"
    remote.mkdir()
    build_tree(remote)
    destination = tmp_path / "local"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        first = await sftp.get_tree(str(remote), destination, concurrency=4)
        # Everything is already there, so a resume moves nothing and reads nothing.
        second = await sftp.get_tree(str(remote), destination, resume=True, concurrency=4)

    assert first.files > 0
    assert first.transferred > 0
    assert second.files == first.files
    assert second.transferred == 0
    assert (destination / "top.csv").read_bytes() == (remote / "top.csv").read_bytes()
    assert (destination / "sub" / "nested.bin").read_bytes() == (
        remote / "sub" / "nested.bin"
    ).read_bytes()


async def test_a_real_tree_uploads_concurrently_and_resumes_in_place(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "outgoing"
    source.mkdir()
    build_tree(source)
    destination = tmp_path / "uploaded"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        first = await sftp.put_tree(source, str(destination), concurrency=4)
        second = await sftp.put_tree(
            source,
            str(destination),
            resume=True,
            concurrency=4,
            publish=Publish(atomic=False, fsync=False),
        )

    assert first.files > 0
    assert second.files == first.files
    assert second.transferred == 0, "a complete tree re-uploaded its own bytes"
    assert (destination / "top.csv").read_bytes() == (source / "top.csv").read_bytes()
    # The ordering constraint a pool could have broken: `walk_local` is top-down and the
    # `mkdir` is awaited in the *producer*, before any of that directory's files are queued, so
    # a worker never writes into a directory that does not exist yet. A nested file arriving
    # intact is what proves it -- queueing directories as work items would race here.
    assert (destination / "sub" / "deeper" / "leaf.txt").read_bytes() == (
        source / "sub" / "deeper" / "leaf.txt"
    ).read_bytes()


async def test_a_real_concurrent_upload_writes_each_file_only_where_it_belongs(tmp_path: Path):
    # Distinct contents per file, so an interleaving bug in the writer shows up as bytes in the
    # wrong file rather than as a count that happens to add up.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "outgoing"
    source.mkdir()
    bodies = {f"f{index}.bin": bytes([index]) * (1024 * (index + 1)) for index in range(12)}
    for name, body in bodies.items():
        _ = (source / name).write_bytes(body)
    destination = tmp_path / "uploaded"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put_tree(source, str(destination), concurrency=6)

    assert result.files == len(bodies)
    for name, body in bodies.items():
        assert (destination / name).read_bytes() == body, f"{name} holds the wrong bytes"


# --- what the survivors found: a forwarded bound, and a record nobody read (D-105) -----------


async def test_put_trees_max_depth_reaches_the_local_walk(tmp_path: Path):
    """``max_depth`` is forwarded to ``walk_local`` and nothing proved it arrived.

    The remote side of this is covered -- ``test_max_depth_stops_the_descent_and_says_so`` and
    its zero-depth sibling pin ``walk``. The *upload* side forwards the same argument to a
    different walker and had no test at all, so nulling it or dropping it from the call both
    survived the suite. The consequence is not a wrong number: a caller who bounds a recursive
    upload to one level gets the **whole tree** sent, which on a drop directory is every byte
    below it going somewhere it was deliberately not asked to go.

    Asserted by depth rather than by file count, because a count is satisfied by any tree of
    the right size and the thing under test is *where* the walk stopped.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "outgoing"
    source.mkdir()
    build_tree(source)
    shallow = tmp_path / "shallow"
    unbounded = tmp_path / "unbounded"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        bounded = await sftp.put_tree(source, str(shallow), max_depth=1)
        whole = await sftp.put_tree(source, str(unbounded))

    # `build_tree` puts `leaf.txt` two levels down, which is what `max_depth=1` must exclude.
    assert (shallow / "top.csv").exists(), "the root's own files are inside a depth of one"
    assert (shallow / "sub").is_dir(), "one level down is inside a depth of one"
    assert not (shallow / "sub" / "deeper").exists(), (
        "max_depth=1 descended two levels, so it did not reach walk_local"
    )
    # And the unbounded run is the control: without it, a put_tree that silently uploaded
    # nothing at all would satisfy every assertion above.
    assert (unbounded / "sub" / "deeper" / "leaf.txt").exists()
    assert whole.files > bounded.files


async def test_the_put_tree_record_carries_its_fields_as_data(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The operation record's structured half, which is the fourth site of one pattern.

    D-105's three previous slices each found the machine-readable half of something whose
    human-readable half was tested well: an invariant two docstrings assert, an exception's
    carried fields beside a message pinned to the character, and a log record's fields beside a
    pinned sentence. This is the same shape again -- the ``operation`` name could be nulled,
    case-mangled or replaced with ``XXput_treeXX``, and ``local`` and ``remote`` could each be
    nulled or deleted, with nothing failing.

    It matters here for the reason D-98 exists: these fields are what an operator's tooling
    filters and joins on. A dashboard that groups transfers by ``operation`` silently loses
    every tree upload if the name changes, and the message still reads correctly.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "outgoing"
    source.mkdir()
    (source / "only.csv").write_bytes(b"id\n1\n")
    destination = tmp_path / "uploaded"

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.put_tree(source, str(destination))

    records = [r for r in caplog.records if record_fields(r).get("operation") == "put_tree"]
    assert records, "the tree upload emitted no record naming itself put_tree"
    start = record_fields(records[0])
    assert start["operation"] == "put_tree"
    assert start["event"] == "start"
    assert names_path(start["local"], source)
    assert names_path(start["remote"], destination)

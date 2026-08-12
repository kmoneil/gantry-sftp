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
from dataclasses import fields
from itertools import product
from pathlib import Path

import pytest

from gantry_sftp._logging import record_fields
from gantry_sftp.codec import Read
from gantry_sftp.exceptions import DestinationCollisionError
from gantry_sftp.session import Publish, UploadJournal, open_session
from gantry_sftp.session._policy import _check_publish_flags, _check_tree_publish
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


async def test_an_uploaded_tree_cannot_resume_atomically_without_a_journal(tmp_path: Path):
    """The decision D-54 had to make, and it is `put`'s rule reaching a tree.

    Each file stages under a name generated fresh per call, so last run's partials cannot be
    found unless something wrote them down; and a `staging_name` cannot be fixed for a whole
    tree. Deriving one per file from the target would make it predictable for every file at
    once -- which is what `staging_token` exists to prevent -- so that stays refused.

    Renamed by D-172, which added the second way out. The refusal is still the default answer
    and the message now names both.
    """
    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.csv").write_bytes(b"aaa")

    server = TreeServer(tree={b"/dest": ()}, root=b"/dest")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as caught:
            _ = await sftp.put_tree(source, b"/dest/tree", resume=True)

    assert caught.value.args[0] == (
        "put_tree() needs a journal to resume with atomic publishing: each file stages under "
        "a name generated fresh per call, so a previous run's partials cannot be found "
        "without a record of them, and a staging_name cannot be fixed for a whole tree. Pass "
        "publish=Publish(journal=UploadJournal(path)) to record each name durably, or "
        "publish=Publish(atomic=False) to resume the destination files themselves"
    )


def test_the_tree_guard_refuses_everything_the_one_file_guard_would(tmp_path: Path):
    """The parity D-172 was a near-miss on, asserted rather than remembered.

    Two guards restating one rule drift, and the drift is invisible: `_check_publish_flags` was
    amended by D-166 and `_check_tree_publish` was not, both stayed correct in isolation, the
    suite stayed green, and the stale message was *well written* -- which is what made it read
    as current.

    **The fix is the delegation and this is what pins what delegation cannot.** A tree must
    refuse a superset of what one file refuses, because every file goes through `put` anyway and
    a rule reached per file is reached *inside the walk* -- after `put_tree` has created the
    destination and its parents for a transfer that will not happen. The one legitimate extra is
    `staging_name`, which a tree cannot have at all.

    Driven from `Publish`'s own fields, so a new flag on it fails here by name instead of
    joining the untested set silently.
    """
    flags = [field.name for field in fields(Publish) if isinstance(field.default, bool)]
    assert flags == ["atomic", "fsync", "require_atomic", "require_fsync"], (
        f"Publish grew or lost a boolean: {flags}. Each one is a rule, and this check has to "
        f"be read again rather than extended blindly -- a tree's answer is not always one "
        f"file's, which is why `resume` and `staging_name` are handled separately below"
    )
    journal = UploadJournal(tmp_path / "uploads.journal")

    tree_only: list[tuple[Publish, bool, str]] = []
    for values in product([True, False], repeat=len(flags)):
        for resume, has_journal, has_name in product([True, False], repeat=3):
            policy = Publish(
                **dict(zip(flags, values, strict=True)),
                journal=journal if has_journal else None,
                staging_name=b"/dest/one.part" if has_name else None,
            )
            one_file = _one_file_refusal(policy, resume=resume)
            tree = _tree_refusal(policy, resume=resume)
            assert not (one_file and not tree), (
                f"a tree accepts what one file refuses: {policy}, resume={resume}, "
                f"put said {one_file!r}"
            )
            if tree is not None and one_file is None:
                tree_only.append((policy, resume, tree))

    assert tree_only, "the check found no difference at all, so it is asserting nothing"
    unexplained = [case for case in tree_only if case[0].staging_name is None]
    assert not unexplained, (
        f"a tree refuses something one file allows, for a reason that is not staging_name: "
        f"{unexplained}"
    )


def _one_file_refusal(policy: Publish, *, resume: bool) -> str | None:
    """What `put`'s guard says about this policy, or ``None`` if it accepts it."""
    try:
        _check_publish_flags(
            atomic=policy.atomic,
            fsync=policy.fsync,
            require_atomic=policy.require_atomic,
            require_fsync=policy.require_fsync,
            resume=resume,
            staging_name=policy.staging_name,
            journal=policy.journal,
        )
    except ValueError as refused:
        return str(refused.args[0])
    return None


def _tree_refusal(policy: Publish, *, resume: bool) -> str | None:
    """What the tree's guard says about it, or ``None`` if it accepts it."""
    try:
        _check_tree_publish(policy, resume=resume, caller="put_tree")
    except ValueError as refused:
        return str(refused.args[0])
    return None


async def test_a_tree_still_refuses_a_staging_name_even_with_a_journal(tmp_path: Path):
    """The second clause of the old message was a different guard, and D-172 did not touch it.

    One name cannot serve a tree whatever else is passed, so a journal must not read as
    permission for the thing that was never about findability.
    """
    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.csv").write_bytes(b"aaa")
    journal = UploadJournal(tmp_path / "uploads.journal")

    server = TreeServer(tree={b"/dest": ()}, root=b"/dest")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as caught:
            _ = await sftp.put_tree(
                source,
                b"/dest/tree",
                resume=True,
                publish=Publish(journal=journal, staging_name=b"/dest/one.part"),
            )

    assert caught.value.args[0] == (
        "put_tree() cannot take a staging_name: it applies to every file in the tree, so they "
        "would all stage under one name and overwrite each other. Leave it unset to get a "
        "generated hidden sibling per file."
    )


# --- the walk's own ordering, which nothing else checks -------------------------------------------


def _local_tree(root: Path) -> None:
    """Three levels, so the ordering below is exercised at depth rather than once."""
    (root / "one" / "two").mkdir(parents=True)
    _ = (root / "top.bin").write_bytes(b"t")
    _ = (root / "one" / "middle.bin").write_bytes(b"m")
    _ = (root / "one" / "two" / "deep.bin").write_bytes(b"d")


def _parent_of(remote: bytes) -> bytes:
    head, _, _ = remote.rpartition(b"/")
    return head


def needs_real_server() -> None:
    """`TreeServer` implements no `mkdir` and no `write`, so this half needs the real one."""
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


@pytest.mark.parametrize("concurrency", [1, 4])
@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "already-there"])
async def test_an_uploaded_directory_is_created_before_any_of_its_files(
    tmp_path: Path, concurrency: int, existing: bool
):
    """D-179's characterization test, written before the extraction it exists to guard.

    `put_tree`'s producer awaits the `mkdir` **in the producer**, before any of that
    directory's files is yielded, and its own comment says why: *"so a worker never writes into
    a directory that does not exist yet. `walk_local` is top-down, which is what makes that
    sufficient rather than merely usual."*

    That is an ordering invariant between two `await`s in one generator, and **nothing checked
    it**. It is implied by the shape of the loop, which is exactly the kind of guarantee an
    extraction can lose without any existing test noticing: every tree test asserts on what
    landed, and a `mkdir` issued late still lands before the assertions run. What would break
    is a tree against a server slow enough, or a worker scheduled early enough, for the write
    to arrive first -- which is a flake somewhere else, on somebody else's machine.

    Recorded at `Session.mkdir` and `Session.put` rather than at the wire, because those two
    are what the producer calls and what the extraction moves. Run at both concurrencies: the
    invariant is not "the operations are ordered" -- with four workers they interleave, and
    they are supposed to -- it is that *each file's own parent* precedes it.

    **`existing` is what makes the assertion do any work, and it was added after watching the
    break.** Deferring the `mkdir` against a *fresh* destination fails on its own, loudly, with
    `NO_SUCH_FILE` on the staging file -- so on that row the ordering assertion never speaks and
    could be wrong without anybody knowing. Against a destination whose directories are already
    there, a late `mkdir(exist_ok=True)` succeeds, every file lands, the result object is
    correct, and the **only** thing that can report the regression is the order recorded here.
    That is also the case a real deployment is most likely to be in: a re-run, a mirror, a tree
    dropped into a directory somebody already made.
    """
    needs_real_server()
    source = tmp_path / "src"
    source.mkdir()
    _local_tree(source)
    destination = tmp_path / "dest"
    if existing:
        # The "remote" here is this same filesystem, so pre-creating the destination tree is
        # what a second run of the same upload would find.
        (destination / "one" / "two").mkdir(parents=True)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        order: list[tuple[str, bytes]] = []
        made, sent = sftp.mkdir, sftp.put

        async def recording_mkdir(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            order.append(("mkdir", sftp._resolve(path)))  # noqa: SLF001
            return await made(path, *args, **kwargs)

        async def recording_put(local, remote, *args, **kwargs):  # type: ignore[no-untyped-def]
            order.append(("put", sftp._resolve(remote)))  # noqa: SLF001
            return await sent(local, remote, *args, **kwargs)

        sftp.mkdir, sftp.put = recording_mkdir, recording_put
        try:
            result = await sftp.put_tree(source, str(destination).encode(), concurrency=concurrency)
        finally:
            sftp.mkdir, sftp.put = made, sent

    assert result.files == 3, "the tree did not upload, so the ordering below proves nothing"
    assert result.directories == 2

    made_at = {path: index for index, (kind, path) in enumerate(order) if kind == "mkdir"}
    puts = [(index, path) for index, (kind, path) in enumerate(order) if kind == "put"]
    assert len(puts) == 3, f"expected three uploads, recorded {order!r}"

    for index, remote in puts:
        parent = _parent_of(remote)
        assert parent in made_at, (
            f"{remote!r} was uploaded into {parent!r}, which this run never created: {order!r}"
        )
        assert made_at[parent] < index, (
            f"{remote!r} was uploaded at step {index} but its directory {parent!r} was only "
            f"created at step {made_at[parent]} -- a worker wrote into a directory that did "
            f"not exist yet. Order was {order!r}"
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


async def test_a_contradictory_policy_is_refused_before_the_tree_creates_anything(tmp_path: Path):
    """What the delegation buys, stated as the thing a caller can see.

    `require_atomic=True, atomic=False` was reached one *file* late, because the tree guard
    restated three of `put`'s rules and not these two. The exception was identical, so the only
    visible difference was this: `put_tree` had already created the destination and its missing
    parents on the server for a transfer that was never going to happen.

    A real server rather than `TreeServer`, because the claim is about directories that exist.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.csv").write_bytes(b"aaa")
    destination = tmp_path / "deep" / "dest"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError) as caught:
            _ = await sftp.put_tree(
                source,
                str(destination).encode(),
                publish=Publish(require_atomic=True, atomic=False),
            )

    assert caught.value.args[0] == "require_atomic=True contradicts atomic=False"
    assert not destination.exists(), "a refused request created its destination"
    assert not destination.parent.exists(), "a refused request created a parent directory"


async def test_a_real_tree_resumes_atomically_with_a_journal(tmp_path: Path):
    """D-172: what the lifted guard actually permits, against a server that stages for real.

    Not against `TreeServer`: the acceptance is only interesting if the upload then goes
    through the staged path, and a fake that answers every `OPEN` cannot show that each file
    chose a name of its own. Four journal records for two files -- a `staged` and a
    `published` each -- is what says the tree did not share one.

    That a *killed* run resumes from those names needs a real crash in a real process and
    lives in `live-tests/test_journal_live.py`.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.csv").write_bytes(b"aaa")
    _ = (source / "b.csv").write_bytes(b"bbbb")
    destination = tmp_path / "uploaded"
    journal = UploadJournal(tmp_path / "uploads.journal")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put_tree(
            source,
            str(destination),
            resume=True,
            publish=Publish(journal=journal, fsync=False),
        )

    assert result.files == 2
    assert (destination / "a.csv").read_bytes() == b"aaa"
    assert (destination / "b.csv").read_bytes() == b"bbbb"
    # Published, so nothing is in flight and no staging file survived the run.
    assert journal.in_flight() == {}
    assert not [path for path in destination.iterdir() if ".part" in path.name]
    staged = [line for line in journal.path.read_text().splitlines() if '"event": "staged"' in line]
    assert len(staged) == 2, "each file needs its own recorded staging name"
    assert len({line.split('"staged": ')[1].split(",")[0] for line in staged}) == 2


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

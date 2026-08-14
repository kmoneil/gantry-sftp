"""The local half of a recursive upload: what the walk descends into, and what it refuses.

Everything here runs against a `tmp_path` with no event loop, no transport and no server,
which is the point of `walk_local` being a plain generator: the direction where the names are
ours is also the direction that can be proven without a connection.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gantry_sftp.exceptions import UnsafePathError
from gantry_sftp.session import (
    EntryKind,
    LocalWalkEntry,
    SkipReason,
    local_dir_entry,
    remote_component,
    walk_local,
)
from local_filesystem import HOLDS_NON_UTF8_NAMES


def build(root: Path) -> None:
    """A tree with one of everything the walk has to have an opinion about."""
    (root / "b.txt").write_bytes(b"bbb")
    (root / "a.txt").write_bytes(b"a")
    (root / "sub").mkdir()
    (root / "sub" / "nested.bin").write_bytes(b"nested")
    (root / "sub" / "deeper").mkdir()
    (root / "sub" / "deeper" / "leaf.txt").write_bytes(b"leaf")
    (root / "link.txt").symlink_to(root / "a.txt")
    (root / "dirlink").symlink_to(root / "sub", target_is_directory=True)
    # Not valid UTF-8, and perfectly ordinary on Linux -- conditional because macOS refuses
    # to hold such a name at all. See `conftest.HOLDS_NON_UTF8_NAMES`.
    if HOLDS_NON_UTF8_NAMES:
        (root / os.fsdecode(b"caf\xe9.bin")).write_bytes(b"\xe9\xe9")


ODD_NAME: tuple[bytes, ...] = (b"caf\xe9.bin",) if HOLDS_NON_UTF8_NAMES else ()
"""Spliced into the expected listings, empty where the filesystem will not hold it."""


def entries(root: Path, **kwargs) -> dict[tuple[bytes, ...], LocalWalkEntry]:
    return {entry.relative: entry for entry in walk_local(root, **kwargs)}


# --- what a name may become on the far end -------------------------------------------------


def test_an_ordinary_name_passes_through_unchanged():
    assert remote_component(b"report.csv") == b"report.csv"
    assert remote_component(b"caf\xe9.bin") == b"caf\xe9.bin"


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        (b"", "an empty name"),
        (b".", "a relative directory entry"),
        (b"..", "a relative directory entry"),
        (b"a/b", "a path separator"),
        (b"/absolute", "a path separator"),
        (b"nul\x00byte", "a NUL byte"),
    ],
)
def test_a_name_that_could_not_be_one_remote_component_is_refused(name: bytes, reason: str):
    with pytest.raises(UnsafePathError) as exc:
        remote_component(name)
    assert exc.value.args[0] == (
        f"refusing to send the local name {name!r} as a remote path component: it contains {reason}"
    )
    assert exc.value.name == name
    assert exc.value.reason == reason


def test_the_windows_rules_do_not_apply_in_this_direction():
    # `CON`, `a:b` and a trailing dot are rules about what may be *written locally*. A file
    # named that way exists on the machine being read from, and refusing to upload it would
    # refuse a file that is legal where it lives.
    for name in (b"CON", b"a:b", b"trailing.", b"back\\slash", b'quote"'):
        assert remote_component(name) == name


# --- and no walk can reach that refusal (D-184) ---------------------------------------------
#
# The rows above call `remote_component` directly, which is the only way to reach it: every
# name it is asked about in production comes out of `os.scandir`, and none of the four refusals
# is producible from there. These three pin that finding from the side that can regress -- a
# future name source that is *not* `os.scandir` would fail one of them. `put_tree` and
# `sync_tree` dropped `UnsafePathError` from their **Raises** on the strength of it.


def test_a_separator_becomes_structure_rather_than_a_name(tmp_path: Path):
    """The refusal that looks reachable and is not.

    Creating ``a/b`` with the parent missing fails for the wrong reason -- the path did not
    exist, which says nothing about names. With the parent present the call *succeeds*: it
    makes a directory ``a`` holding a file ``b``, so the separator became structure the walk
    descends through, and neither name carries it.
    """
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").touch()

    seen = [name for entry in walk_local(tmp_path) for name in (*entry.directories, *entry.files)]

    assert seen == [b"a", b"b"], "the separator is a directory boundary, never part of a name"
    for name in seen:
        assert remote_component(name) == name


def test_scandir_is_what_keeps_the_dot_names_out_rather_than_the_filesystem(tmp_path: Path):
    """The arm of the argument that rests on CPython rather than on POSIX.

    Every POSIX directory contains `.` and `..` as real entries and `readdir(2)` returns both;
    what keeps them out of the walk is `os.scandir`'s documented contract. Asserted here
    because the docstring on `remote_component` reasons from it -- if this ever changed, a
    guard we describe as unreachable would become reachable with nothing else failing.
    """
    (tmp_path / "child").mkdir()
    (tmp_path / "file").touch()

    listed = {os.fsencode(item.name) for item in os.scandir(tmp_path)}

    assert listed == {b"child", b"file"}
    assert b"." not in listed
    assert b".." not in listed


def test_a_walk_over_the_nastiest_legal_names_never_refuses_one(tmp_path: Path):
    """The admitted side of the guard, which is the half a `return False` would pass.

    Names chosen to sit next to each refusal without being one: a client-side separator, one
    dot more than `..`, `..` with a space and with a non-UTF-8 byte, and a name that is not
    valid UTF-8 at all.
    """
    hostile = [rb"a\b", b"...", b" ..", b"-rf", b"name with spaces"]
    if HOLDS_NON_UTF8_NAMES:
        hostile += [b"..\xff", b"\xff\xfe"]
    for name in hostile:
        (tmp_path / os.fsdecode(name)).touch()

    walked = [name for entry in walk_local(tmp_path) for name in (*entry.directories, *entry.files)]

    assert sorted(walked) == sorted(hostile), "every name was held by the filesystem and walked"
    for name in walked:
        assert remote_component(name) == name, f"{name!r} must upload, not be refused"


# --- the walk ------------------------------------------------------------------------------


def test_the_root_is_reported_first_with_an_empty_relative(tmp_path: Path):
    build(tmp_path)
    walked = list(walk_local(tmp_path))
    assert walked[0].relative == ()
    assert walked[0].path == tmp_path


def test_files_and_directories_are_sorted_by_name(tmp_path: Path):
    # scandir returns filesystem order, which is stable for nobody. An upload whose order
    # changes between runs makes a report impossible to diff.
    build(tmp_path)
    root = entries(tmp_path)[()]
    assert root.files == (b"a.txt", b"b.txt", *ODD_NAME)
    assert root.directories == (b"sub",)


def test_directories_are_visited_in_sorted_order_not_mirrored(tmp_path: Path):
    for name in ("c", "a", "b"):
        (tmp_path / name).mkdir()
    assert [entry.relative for entry in walk_local(tmp_path)] == [
        (),
        (b"a",),
        (b"b",),
        (b"c",),
    ]


def test_relative_is_components_rather_than_a_joined_path(tmp_path: Path):
    build(tmp_path)
    assert set(entries(tmp_path)) == {(), (b"sub",), (b"sub", b"deeper")}


def test_a_symlink_to_a_file_is_reported_and_not_uploaded(tmp_path: Path):
    # The exfiltration shape: a link in the upload tree pointing at /etc/shadow would
    # otherwise copy it to the server under an innocent name.
    build(tmp_path)
    root = entries(tmp_path)[()]
    assert b"link.txt" not in root.files
    skip = next(item for item in root.skipped if item.entry.filename == b"link.txt")
    assert skip.reason == SkipReason.SYMLINK
    assert skip.path == os.fsencode(tmp_path / "link.txt")


def test_a_symlink_to_a_directory_is_not_descended_into(tmp_path: Path):
    # The one that would loop, and the one `os.DirEntry.is_dir()` gets wrong by default:
    # it follows links, so a walk built on it descends through them.
    build(tmp_path)
    root = entries(tmp_path)[()]
    assert b"dirlink" not in root.directories
    skip = next(item for item in root.skipped if item.entry.filename == b"dirlink")
    assert skip.reason == SkipReason.SYMLINK
    assert (b"dirlink",) not in entries(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no mkfifo on this platform")
def test_something_that_is_neither_a_file_nor_a_directory_is_skipped_with_a_reason(
    tmp_path: Path,
):
    os.mkfifo(tmp_path / "pipe")
    root = entries(tmp_path)[()]
    assert root.files == ()
    assert [item.reason for item in root.skipped] == [SkipReason.NOT_A_FILE]


def test_an_empty_directory_walks_to_one_empty_entry(tmp_path: Path):
    (walked,) = list(walk_local(tmp_path))
    assert (walked.files, walked.directories, walked.skipped) == ((), (), ())


# --- max_depth -----------------------------------------------------------------------------


def test_max_depth_zero_lists_the_root_and_nothing_else(tmp_path: Path):
    build(tmp_path)
    (root,) = list(walk_local(tmp_path, max_depth=0))
    assert root.directories == ()
    assert root.files == (b"a.txt", b"b.txt", *ODD_NAME)
    assert [item.reason for item in root.skipped].count(SkipReason.TOO_DEEP) == 1


def test_max_depth_one_descends_one_level(tmp_path: Path):
    build(tmp_path)
    walked = entries(tmp_path, max_depth=1)
    assert set(walked) == {(), (b"sub",)}
    deep = next(item for item in walked[(b"sub",)].skipped if item.entry.filename == b"deeper")
    assert deep.reason == SkipReason.TOO_DEEP


def test_max_depth_none_descends_all_the_way(tmp_path: Path):
    build(tmp_path)
    assert (b"sub", b"deeper") in entries(tmp_path, max_depth=None)


# --- the report shape ----------------------------------------------------------------------


def test_a_local_entry_is_classified_by_the_same_function_the_remote_side_uses(tmp_path: Path):
    # st_mode and a v3 ATTRS `permissions` field are the same bits, so one classifier serves
    # both directions and a skipped entry reads identically whichever produced it.
    target = tmp_path / "a.txt"
    target.write_bytes(b"abc")
    entry = local_dir_entry(b"a.txt", target.lstat())
    assert entry.kind is EntryKind.FILE
    assert entry.size == 3
    assert entry.filename == b"a.txt"
    assert entry.longname == b"", "there is no display string to have locally"


def test_a_skipped_symlink_carries_the_link_rather_than_its_target(tmp_path: Path):
    build(tmp_path)
    skip = next(
        item for item in entries(tmp_path)[()].skipped if item.entry.filename == b"link.txt"
    )
    assert skip.entry.kind is EntryKind.SYMLINK


# --- failures are not swallowed ------------------------------------------------------------


def test_a_missing_root_raises_rather_than_walking_nothing(tmp_path: Path):
    # A mirroring tool that silently omits what it could not read has produced a wrong copy
    # while reporting a right one, so local OS errors propagate rather than becoming skips.
    with pytest.raises(FileNotFoundError):
        list(walk_local(tmp_path / "absent"))


def test_a_root_that_is_a_file_raises(tmp_path: Path):
    target = tmp_path / "a.txt"
    target.write_bytes(b"x")
    with pytest.raises(NotADirectoryError):
        list(walk_local(target))

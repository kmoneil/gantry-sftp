"""`SFTPPath`: the algebra, the refusals, and the axes a canonical spelling would hide.

Three groups, and the middle one is what the card was actually about.

**The algebra is pure and is tested without a server**, because that is what it is: bytes in,
bytes out, no round trip. The interesting cases are the ones a test written in the canonical
spelling cannot reach -- a component that is not valid UTF-8, a trailing slash, a backslash that
is a *character* here and a separator on Windows, `.` and `..` in a path the caller wrote versus
in a name a server sent, and a namespace with no leading `/` at all.

**The joining check is the security half.** `path / name` is overwhelmingly
`path / entry.filename`, and that name is chosen by the far end. The refusal is asserted on its
whole message rather than its type, because the message is what tells a caller to reach for
`.parent` instead of the string they were about to build.

**The behaviour runs against a real `sftp-server` on a pipe**, no container and no network, for
the reason the rest of this suite does: a fake proves the code agrees with our idea of a server.
The one thing a real server will not do on demand is *lie about its own directory*, so the
listing that answers with `../etc` is scripted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import anyio
import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp import (
    NoSuchFileError,
    OpenFlag,
    SFTPPath,
    StateError,
    UnsafePathError,
)
from gantry_sftp.codec import (
    Attrs,
    Close,
    FrameSplitter,
    Handle,
    Init,
    Name,
    NameEntry,
    OpenDir,
    ReadDir,
    Status,
    StatusCode,
    Version,
    decode,
    encode,
)
from gantry_sftp.path import (
    DEFAULT_WRITE_MODE,
    match_path,
    name_of,
    parent_of,
    path_parts,
    relative_components,
    split_components,
    stem_of,
    suffix_of,
    suffixes_of,
)
from gantry_sftp.session import open_session
from gantry_sftp.sync import SyncSFTPPath
from gantry_sftp.sync import open_local_server_transport as sync_open_local_server_transport
from gantry_sftp.sync import open_session as sync_open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

REGULAR = 0o100644

NOT_UTF8 = b"\xff\xfe\x80"
"""A name no encoding explains, which is the ordinary case rather than the exotic one.

Latin-1 filenames on a Windows or a mainframe endpoint decode to exactly this, and they are the
files a caller most needs to be able to name back to the server.
"""


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def remote(path: Path) -> bytes:
    """A local temporary directory, spelled the way it goes on the wire."""
    return os.fsencode(path)


# --- what it is ------------------------------------------------------------------------------


def test_a_path_keeps_its_bytes_exactly():
    """No normalisation, at all. Every one of these is a different path to a server."""
    for spelling in (b"/incoming", b"/incoming/", b"//incoming", b"/incoming/./x", b"/a/../b"):
        assert bytes(SFTPPath(spelling)) == spelling


def test_a_str_is_encoded_the_way_the_session_encodes_one():
    """`surrogateescape`, so a name that came back undecodable can be sent again."""
    decoded = NOT_UTF8.decode("utf-8", "surrogateescape")
    assert bytes(SFTPPath(decoded)) == NOT_UTF8


def test_str_is_a_view_and_bytes_is_the_value():
    path = SFTPPath(b"/incoming/" + NOT_UTF8)
    assert str(path).encode("utf-8", "surrogateescape") == bytes(path)


def test_a_path_copies_another_and_keeps_its_binding():
    original = SFTPPath(b"/incoming", session=None)
    assert bytes(SFTPPath(original)) == b"/incoming"
    assert SFTPPath(original) == original


@pytest.mark.parametrize("wrong", [Path("/incoming"), 3, None, ["/incoming"]])
def test_a_wrong_type_is_refused_by_name(wrong: object):
    with pytest.raises(TypeError) as exc:
        SFTPPath(wrong)  # type: ignore[arg-type]
    assert exc.value.args[0].startswith(
        f"a remote path must be bytes, str or SFTPPath, not {type(wrong).__name__}"
    )


def test_a_pathlib_path_is_told_why_rather_than_merely_refused():
    """The type callers actually reach for, so "unsupported" would be the wrong reason.

    `pathlib` normalises -- it drops a trailing slash on construction and renders separators as
    backslashes on Windows -- and a remote name has to survive byte for byte.
    """
    with pytest.raises(TypeError) as exc:
        SFTPPath(Path("/incoming"))  # type: ignore[arg-type]
    assert "pathlib normalises and a remote name has to survive byte for byte" in exc.value.args[0]


def test_it_is_not_os_pathlike():
    """Defining `__fspath__` would admit a *remote* name into `open()` and `os.stat()`."""
    assert not hasattr(SFTPPath(b"/incoming"), "__fspath__")
    with pytest.raises(TypeError):
        os.fspath(SFTPPath(b"/incoming"))  # type: ignore[arg-type]


def test_it_is_not_a_str_subclass():
    """A `str` subclass inherits `+`, `%` and `.replace()`, none of which check a component."""
    assert not isinstance(SFTPPath(b"/incoming"), str)
    with pytest.raises(TypeError):
        SFTPPath(b"/incoming") + "../etc"  # type: ignore[operator]


def test_equality_is_bytes_and_the_session_takes_no_part():
    assert SFTPPath(b"/a") == SFTPPath(b"/a")
    assert SFTPPath(b"/a") != SFTPPath(b"/a/")
    assert SFTPPath(b"/a") != b"/a"
    assert len({SFTPPath(b"/a"), SFTPPath(b"/a")}) == 1


def test_case_is_never_folded():
    """Two paths differing in case are two paths (D-37).

    Which names a filesystem folds into one file is that filesystem's own table, and the
    reachable hazard is a folding *local* disk rather than a folding server -- `DestinationLedger`
    asks `lstat` after the write, which is the only authority there is.
    """
    assert SFTPPath(b"/README") != SFTPPath(b"/readme")


def test_paths_sort_by_bytes():
    unsorted = [SFTPPath(b"/b"), SFTPPath(b"/a"), SFTPPath(b"/c")]
    assert [bytes(p) for p in sorted(unsorted)] == [b"/a", b"/b", b"/c"]
    assert SFTPPath(b"/a") < SFTPPath(b"/b")
    assert SFTPPath(b"/b") >= SFTPPath(b"/b")


def test_ordering_across_types_is_undefined_rather_than_wrong():
    with pytest.raises(TypeError):
        _ = SFTPPath(b"/a") < b"/b"  # type: ignore[operator]


def test_repr_says_whether_it_can_reach_a_server():
    """ "Why did that raise StateError" is the question this type invites."""
    assert repr(SFTPPath(b"/incoming")) == "SFTPPath(b'/incoming', unbound)"


async def test_repr_names_the_binding_without_embedding_the_session(tmp_path: Path):
    """The bound half, which is the half worth asserting.

    An unbound path obviously has no session in its `repr`; the claim is about a path that *has*
    one. A session's own `repr` is a paragraph of tunables and a path is frequently printed
    inside a listing, so the binding appears as one word.
    """
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        rendered = repr(SFTPPath(b"/incoming", session=sftp))
    assert rendered == "SFTPPath(b'/incoming', bound)"
    assert "Session" not in rendered
    assert "depth=" not in rendered


# --- the algebra, on the axes that bite -------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (b"/incoming/report.csv", (b"/", b"incoming", b"report.csv")),
        (b"incoming/report.csv", (b"incoming", b"report.csv")),
        (b"/incoming/", (b"/", b"incoming")),
        (b"//incoming//x", (b"/", b"incoming", b"x")),
        (b"/", (b"/",)),
        (b"", ()),
        (b"/a/../b", (b"/", b"a", b"..", b"b")),
    ],
)
def test_parts_reads_the_bytes_without_rewriting_them(path: bytes, expected: tuple[bytes, ...]):
    """A trailing slash and a doubled separator are dropped from the *view*, not from the value."""
    assert path_parts(path) == expected
    assert SFTPPath(path).parts == expected
    assert bytes(SFTPPath(path)) == path


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (b"/incoming/report.csv", b"/incoming"),
        (b"/incoming", b"/"),
        (b"/", b"/"),
        (b"incoming/report.csv", b"incoming"),
        (b"report.csv", b"."),
        (b"", b"."),
        (b"/incoming/", b"/"),
    ],
)
def test_parent_of(path: bytes, expected: bytes):
    """`b"."` for a relative path with one component -- pathlib's answer, and the protocol's."""
    assert parent_of(path) == expected
    assert bytes(SFTPPath(path).parent) == expected


def test_parents_climbs_to_the_root_and_stops():
    path = SFTPPath(b"/incoming/2026/q1/report.csv")
    assert [bytes(p) for p in path.parents] == [
        b"/incoming/2026/q1",
        b"/incoming/2026",
        b"/incoming",
        b"/",
    ]


def test_parents_of_a_relative_path_ends_at_dot():
    assert [bytes(p) for p in SFTPPath(b"a/b").parents] == [b"a", b"."]
    assert SFTPPath(b"report.csv").parents == (SFTPPath(b"."),)


@pytest.mark.parametrize(
    ("path", "name", "stem", "suffix", "suffixes"),
    [
        (b"/a/report.csv", b"report.csv", b"report", b".csv", (b".csv",)),
        (b"/a/archive.tar.gz", b"archive.tar.gz", b"archive.tar", b".gz", (b".tar", b".gz")),
        (b"/a/.bashrc", b".bashrc", b".bashrc", b"", ()),
        (b"/a/report.", b"report.", b"report.", b"", ()),
        (b"/a/report", b"report", b"report", b"", ()),
        (b"/", b"", b"", b"", ()),
        (b"/a/" + NOT_UTF8 + b".csv", NOT_UTF8 + b".csv", NOT_UTF8, b".csv", (b".csv",)),
    ],
)
def test_name_stem_and_suffix(
    path: bytes, name: bytes, stem: bytes, suffix: bytes, suffixes: tuple[bytes, ...]
):
    """A leading dot does not begin a suffix and a trailing one does not end a name."""
    assert name_of(path) == name
    assert stem_of(name) == stem
    assert suffix_of(name) == suffix
    assert suffixes_of(name) == suffixes
    subject = SFTPPath(path)
    assert (subject.name, subject.stem, subject.suffix, subject.suffixes) == (
        name,
        stem,
        suffix,
        suffixes,
    )


def test_names_are_bytes_because_every_other_name_here_is():
    """The type rule: strings go in, bytes come out. `DirEntry.filename` is bytes, so is this."""
    assert isinstance(SFTPPath("/incoming/report.csv").name, bytes)
    assert SFTPPath("/incoming/report.csv").name == b"report.csv"


def test_a_backslash_is_a_character_and_not_a_separator():
    """POSIX filenames may contain a backslash; a Windows *client* must not split on one."""
    path = SFTPPath(rb"/incoming/a\b")
    assert path.parts == (b"/", b"incoming", rb"a\b")
    assert path.name == rb"a\b"
    assert bytes(path.parent) == b"/incoming"


def test_a_trailing_slash_survives_a_join():
    """The stored bytes are untouched, and `join_remote` does not double the separator."""
    assert bytes(SFTPPath(b"/incoming/") / b"x") == b"/incoming/x"
    assert bytes(SFTPPath(b"/incoming") / b"x") == b"/incoming/x"


def test_a_relative_path_joins_without_growing_a_root():
    assert bytes(SFTPPath(b"incoming") / b"x") == b"incoming/x"
    assert bytes(SFTPPath(b"") / b"x") == b"x"


def test_is_absolute_is_the_only_rootedness_question_this_answers():
    """Whether the *server* is `/`-rooted costs a round trip and lives on the session (D-77)."""
    assert SFTPPath(b"/incoming").is_absolute()
    assert not SFTPPath(b"incoming").is_absolute()
    assert not SFTPPath(b"SYS1.PROCLIB").is_absolute()


def test_a_rootless_name_still_does_arithmetic_it_can_justify():
    """`/` arithmetic on a namespace that is not `/`-rooted is the caller's claim, not ours."""
    path = SFTPPath(b"SYS1.PROCLIB")
    assert path.name == b"SYS1.PROCLIB"
    assert bytes(path.parent) == b"."
    assert path.suffix == b".PROCLIB"


# --- joining, which is the security half ------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        (b"..", "a relative directory entry"),
        (b".", "a relative directory entry"),
        (b"../etc", "a path separator"),
        (b"a/b", "a path separator"),
        (b"", "an empty name"),
        (b"a\x00b", "a NUL byte"),
    ],
)
def test_joining_refuses_a_name_that_is_not_one_component(name: bytes, reason: str):
    """The whole message, because it is what sends a caller to `.parent` instead of a string."""
    with pytest.raises(UnsafePathError) as exc:
        SFTPPath(b"/incoming") / name
    assert exc.value.args[0] == (
        f"refusing to join {name!r} onto a remote path: it contains {reason}, so it is not one "
        f"path component -- use .parent to go up, or build the path you mean with SFTPPath()"
    )
    assert exc.value.name == name
    assert exc.value.reason == reason


def test_the_constructor_accepts_what_joining_refuses():
    """Trust comes from who wrote it. A caller's `..` is a path; a server's is an escape.

    Refusing it in the constructor too would make this type weaker than `Session.stat`, which
    accepts exactly that string, and would buy nothing -- the hazard is the *join*.
    """
    assert bytes(SFTPPath(b"/a/../b")) == b"/a/../b"
    assert bytes(SFTPPath(b"..")) == b".."


def test_joining_a_non_utf8_name_is_ordinary():
    """The common case, not the exotic one: a name is bytes and these bytes are legal."""
    assert bytes(SFTPPath(b"/incoming") / NOT_UTF8) == b"/incoming/" + NOT_UTF8


def test_joinpath_checks_every_component():
    assert bytes(SFTPPath(b"/a").joinpath(b"b", "c")) == b"/a/b/c"
    with pytest.raises(UnsafePathError):
        SFTPPath(b"/a").joinpath(b"b", b"..")


def test_there_is_no_reflected_join():
    """`b"/a" / path` would take a whole path on the right, which the one-component rule forbids."""
    assert not hasattr(SFTPPath(b"/a"), "__rtruediv__")


def test_with_name_and_friends_check_the_component_too():
    """The other three ways to produce a name, all of which route through the same predicate."""
    for build in (
        lambda p: p.with_name(b"../etc"),
        lambda p: p.with_stem(b"../etc"),
        lambda p: p.with_suffix(b"./x"),
    ):
        with pytest.raises(UnsafePathError):
            build(SFTPPath(b"/incoming/report.csv"))


def test_with_name_replaces_only_the_last_component():
    path = SFTPPath(b"/incoming/report.csv")
    assert bytes(path.with_name(b"other.txt")) == b"/incoming/other.txt"
    assert bytes(path.with_stem(b"other")) == b"/incoming/other.csv"
    assert bytes(path.with_suffix(b".txt")) == b"/incoming/report.txt"
    assert bytes(path.with_suffix(b"")) == b"/incoming/report"


def test_with_name_on_a_path_that_has_none():
    with pytest.raises(ValueError) as exc:
        SFTPPath(b"/").with_name(b"x")
    assert exc.value.args[0] == "b'/' has an empty name, so there is nothing to replace"


def test_with_suffix_refuses_an_extension_that_is_not_one():
    with pytest.raises(ValueError) as exc:
        SFTPPath(b"/a/report.csv").with_suffix(b"txt")
    assert exc.value.args[0] == "an extension has to begin with a dot, and b'txt' does not"


def test_a_relative_path_of_one_component_can_be_renamed():
    """`with_name` must not grow a `./` prefix out of `parent` being `b"."`."""
    assert bytes(SFTPPath(b"report.csv").with_name(b"other.csv")) == b"other.csv"


# --- relative_to ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        (b"/incoming/2026/x.csv", b"/incoming", (b"2026", b"x.csv")),
        (b"/incoming/", b"/incoming", ()),
        (b"/incoming/x", b"/incoming/", (b"x",)),
        (b"a/b/c", b"a", (b"b", b"c")),
    ],
)
def test_relative_components(path: bytes, root: bytes, expected: tuple[bytes, ...]):
    assert relative_components(path, root) == expected


@pytest.mark.parametrize(
    ("path", "root"),
    [
        (b"/incoming/x", b"/outgoing"),
        (b"/incoming/x", b"incoming"),
        (b"incoming/x", b"/incoming"),
        (b"/incomingx/y", b"/incoming"),
    ],
)
def test_relative_to_refuses_what_is_not_below(path: bytes, root: bytes):
    """Absoluteness has to agree, and a prefix of the *bytes* is not a prefix of the path."""
    assert relative_components(path, root) is None
    assert not SFTPPath(path).is_relative_to(root)
    with pytest.raises(ValueError) as exc:
        SFTPPath(path).relative_to(root)
    assert exc.value.args[0] == f"{path!r} is not below {root!r}"


def test_relative_to_a_path_is_dot():
    assert bytes(SFTPPath(b"/incoming").relative_to(b"/incoming")) == b"."


def test_relative_to_takes_another_path():
    root = SFTPPath(b"/incoming")
    assert bytes(SFTPPath(b"/incoming/x").relative_to(root)) == b"x"


def test_relative_to_does_not_fold_case():
    assert not SFTPPath(b"/Incoming/x").is_relative_to(b"/incoming")


# --- matching ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        (b"*.csv", b"/incoming/2026/report.csv", True),
        (b"2026/*.csv", b"/incoming/2026/report.csv", True),
        (b"/incoming/*.csv", b"/incoming/2026/report.csv", False),
        (b"/incoming/**/*.csv", b"/incoming/2026/report.csv", True),
        (b"/incoming/**", b"/incoming/2026/report.csv", True),
        (b"/**/*.csv", b"/incoming/2026/report.csv", True),
        (b"/incoming/2026/report.csv", b"/incoming/2026/report.csv", True),
        (b"*.csv", b"incoming/report.csv", True),
        (b"/*.csv", b"report.csv", False),
        (b"report.[cd]sv", b"/a/report.csv", True),
        (b"*.[[:alpha:]]sv", b"/a/report.csv", True),
    ],
)
def test_match_dialect(pattern: bytes, path: bytes, matches: bool):
    """An absolute pattern accounts for the whole path; a relative one is matched from the right."""
    assert match_path(pattern, path) is matches
    assert SFTPPath(path).match(pattern) is matches


def test_match_keeps_the_leading_dot_rule():
    """`glob(3)`'s rule, and what keeps a filter off this library's own staging files."""
    assert not SFTPPath(b"/incoming/.staging").match(b"*")
    assert SFTPPath(b"/incoming/.staging").match(b".*")


def test_match_folds_ascii_case_on_request_and_nothing_else():
    assert not SFTPPath(b"/a/REPORT.CSV").match(b"*.csv")
    assert SFTPPath(b"/a/REPORT.CSV").match(b"*.csv", case_sensitive=False)
    high = b"/a/" + NOT_UTF8
    assert SFTPPath(high).match(NOT_UTF8, case_sensitive=False)


def test_match_refuses_an_empty_pattern():
    with pytest.raises(ValueError) as exc:
        SFTPPath(b"/a").match(b"")
    assert exc.value.args[0] == (
        "an empty pattern matches nothing, so it is refused rather than answered"
    )


def test_match_refuses_a_class_that_does_not_exist():
    """Refused rather than answered "no", which is the same divergence `Session.glob` takes."""
    with pytest.raises(ValueError):
        SFTPPath(b"/a/report.csv").match(b"*.[[:digits:]]sv")


def test_match_never_recurses_on_a_hostile_name():
    """The names are server-supplied and of attacker-chosen length, so the cost has to be a
    product of the two lengths rather than a search over where each `**` stops."""
    path = SFTPPath(b"/" + b"/".join([b"a"] * 40) + b"/x.csv")
    assert path.match(b"/" + b"**/" * 12 + b"*.csv")


# --- the binding ------------------------------------------------------------------------------


async def test_an_unbound_path_refuses_io_and_names_the_fix():
    path = SFTPPath(b"/incoming/report.csv")
    with pytest.raises(StateError) as exc:
        await path.stat()
    assert exc.value.args[0] == (
        "SFTPPath(b'/incoming/report.csv') has no session, so it can do path arithmetic and "
        "nothing else -- construct it with SFTPPath(path, session=...) or call .bind(session)"
    )


def test_an_unbound_path_refuses_open_immediately():
    """`open` is not a coroutine, so its refusal arrives at the call rather than at an await."""
    with pytest.raises(StateError):
        SFTPPath(b"/incoming/report.csv").open()


async def test_a_derived_path_keeps_the_binding(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        for derived in (root / b"child", root.parent, root.with_name(b"other"), *root.parents):
            assert derived.session is sftp


async def test_bind_returns_a_new_path_rather_than_mutating(tmp_path: Path):
    """A path handed to something else must not acquire a connection behind the caller's back."""
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        pure = SFTPPath(remote(tmp_path))
        bound = pure.bind(sftp)
        assert bound is not pure
        assert pure.session is None
        assert bound.session is sftp


# --- against a real sftp-server ----------------------------------------------------------------


async def test_the_ordinary_shapes_against_a_real_server(tmp_path: Path):
    """Predicates, attributes and the two byte methods, in one session.

    Batched deliberately: each of these is one delegation, so a test apiece would be a test of
    `pytest` rather than of the class, and the shared session is what a caller actually has.
    """
    needs_real_server()
    (tmp_path / "report.csv").write_bytes(b"a,b\n1,2\n")
    (tmp_path / "sub").mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        report = root / b"report.csv"

        assert await report.exists()
        assert await report.is_file()
        assert not await report.is_dir()
        assert not await report.is_symlink()
        assert await (root / b"sub").is_dir()
        assert not await (root / b"absent").exists()

        assert await report.size() == 8
        assert (await report.stat()).size == 8
        assert (await report.mtime()) is not None
        assert await report.read_bytes() == b"a,b\n1,2\n"
        assert await report.read_text() == "a,b\n1,2\n"


async def test_write_bytes_creates_a_file_that_is_not_world_readable(tmp_path: Path):
    """`OPEN` with no PERMISSIONS arrives `0666 & ~umask`, and no later chmod closes the window."""
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        target = SFTPPath(remote(tmp_path), session=sftp) / b"new.txt"
        assert await target.write_bytes(b"payload") == 7

    written = tmp_path / "new.txt"
    assert written.read_bytes() == b"payload"
    assert written.stat().st_mode & 0o777 == DEFAULT_WRITE_MODE


async def test_write_bytes_truncates_rather_than_appending(tmp_path: Path):
    needs_real_server()
    (tmp_path / "log.txt").write_bytes(b"old and long")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await (SFTPPath(remote(tmp_path), session=sftp) / b"log.txt").write_bytes(b"new")
    assert (tmp_path / "log.txt").read_bytes() == b"new"


async def test_write_text_reports_bytes_rather_than_characters(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        target = SFTPPath(remote(tmp_path), session=sftp) / b"unicode.txt"
        written = await target.write_text("héllo")
    assert written == 6
    assert (tmp_path / "unicode.txt").read_text(encoding="utf-8") == "héllo"


async def test_open_hands_back_a_cursor(tmp_path: Path):
    needs_real_server()
    (tmp_path / "log.jsonl").write_bytes(b"0123456789")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        path = SFTPPath(remote(tmp_path), session=sftp) / b"log.jsonl"
        async with path.open() as remote_file:
            assert await remote_file.read(4) == b"0123"
            assert remote_file.tell() == 4


async def test_open_for_writing_takes_a_mode(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        path = SFTPPath(remote(tmp_path), session=sftp) / b"made.txt"
        flags = OpenFlag.WRITE | OpenFlag.CREAT
        async with path.open(flags, mode=0o640) as remote_file:
            await remote_file.write(b"x")
    assert (tmp_path / "made.txt").stat().st_mode & 0o777 == 0o640


async def test_iterdir_streams_the_directory_as_paths(tmp_path: Path):
    needs_real_server()
    for name in ("a.csv", "b.csv"):
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / "sub").mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        found = sorted([bytes(entry) async for entry in root.iterdir()])

    assert found == [remote(tmp_path / name) for name in ("a.csv", "b.csv", "sub")]


async def test_iterdir_excludes_the_dot_entries(tmp_path: Path):
    """`.` and `..` would each be refused by the joining check, so they must never reach it."""
    needs_real_server()
    (tmp_path / "only.txt").write_bytes(b"x")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        names = [entry.name async for entry in root.iterdir()]
    assert names == [b"only.txt"]


async def test_glob_matches_below_the_path(tmp_path: Path):
    needs_real_server()
    (tmp_path / "2026").mkdir()
    (tmp_path / "2026" / "report.csv").write_bytes(b"x")
    (tmp_path / "2026" / "notes.txt").write_bytes(b"x")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        matched = [bytes(found) async for found in root.glob(b"2026/*.csv")]
        recursed = [bytes(found) async for found in root.rglob(b"*.csv")]

    assert matched == [remote(tmp_path / "2026" / "report.csv")]
    assert recursed == matched


async def test_glob_refuses_an_absolute_pattern(tmp_path: Path):
    """Silently ignoring the path it was called on is the wrong answer, not a convenience."""
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        with pytest.raises(ValueError) as exc:
            _ = [found async for found in root.glob(b"/etc/*")]
    assert exc.value.args[0] == (
        f"glob() takes a pattern relative to {remote(tmp_path)!r}, and b'/etc/*' is absolute "
        f"-- call Session.glob for a pattern that names its own root"
    )


async def test_mkdir_rmdir_and_unlink(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        made = root / b"made"
        await made.mkdir()
        assert (tmp_path / "made").is_dir()

        await made.mkdir(exist_ok=True)
        await made.rmdir()
        assert not (tmp_path / "made").exists()

        deep = root / b"a" / b"b" / b"c"
        await deep.mkdir(parents=True)
        assert (tmp_path / "a" / "b" / "c").is_dir()


async def test_unlink_missing_ok_is_the_only_thing_that_swallows(tmp_path: Path):
    needs_real_server()
    (tmp_path / "gone.txt").write_bytes(b"x")
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        target = SFTPPath(remote(tmp_path), session=sftp) / b"gone.txt"
        await target.unlink()
        assert not (tmp_path / "gone.txt").exists()

        with pytest.raises(NoSuchFileError):
            await target.unlink()
        await target.unlink(missing_ok=True)


async def test_rename_and_replace(tmp_path: Path):
    """`rename` refuses an existing destination; `replace` is `posix-rename@openssh.com`."""
    needs_real_server()
    (tmp_path / "from.txt").write_bytes(b"payload")
    (tmp_path / "occupied.txt").write_bytes(b"older")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        moved = await (root / b"from.txt").rename(root / b"to.txt")
        assert bytes(moved) == remote(tmp_path / "to.txt")
        assert moved.session is sftp

        replaced = await moved.replace(root / b"occupied.txt")
        assert bytes(replaced) == remote(tmp_path / "occupied.txt")

    assert (tmp_path / "occupied.txt").read_bytes() == b"payload"
    assert not (tmp_path / "to.txt").exists()


async def test_resolve_readlink_symlink_to_and_chmod(tmp_path: Path):
    needs_real_server()
    (tmp_path / "real.txt").write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(tmp_path), session=sftp)
        link = root / b"alias.txt"
        await link.symlink_to(root / b"real.txt")
        assert await link.is_symlink()
        assert bytes(await link.readlink()) == remote(tmp_path / "real.txt")

        dotted = SFTPPath(remote(tmp_path) + b"/./real.txt", session=sftp)
        assert bytes(await dotted.resolve()) == remote(tmp_path / "real.txt")

        await (root / b"real.txt").chmod(0o640)

    assert (tmp_path / "alias.txt").is_symlink()
    assert (tmp_path / "real.txt").stat().st_mode & 0o777 == 0o640


async def test_download_and_upload(tmp_path: Path):
    needs_real_server()
    server_root = tmp_path / "server"
    server_root.mkdir()
    (server_root / "data.bin").write_bytes(b"payload" * 100)
    local = tmp_path / "local.bin"

    async with (
        open_local_server_transport(cwd=server_root) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(server_root), session=sftp)
        result = await (root / b"data.bin").download(local)
        assert result.transferred == 700

        uploaded = await (root / b"copy.bin").upload(local)
        assert uploaded.transferred == 700

    assert local.read_bytes() == b"payload" * 100
    assert (server_root / "copy.bin").read_bytes() == b"payload" * 100


async def test_download_tree_and_upload_tree(tmp_path: Path):
    needs_real_server()
    server_root = tmp_path / "server"
    (server_root / "sub").mkdir(parents=True)
    (server_root / "sub" / "a.txt").write_bytes(b"a")
    (server_root / "b.txt").write_bytes(b"b")
    destination = tmp_path / "down"

    async with (
        open_local_server_transport(cwd=server_root) as transport,
        open_session(transport) as sftp,
    ):
        root = SFTPPath(remote(server_root), session=sftp)
        pulled = await root.download_tree(destination)
        assert pulled.files == 2

        pushed = await (root / b"again").upload_tree(destination)
        assert pushed.files == 2

    assert (destination / "sub" / "a.txt").read_bytes() == b"a"
    assert (server_root / "again" / "sub" / "a.txt").read_bytes() == b"a"


async def test_rmtree(tmp_path: Path):
    needs_real_server()
    (tmp_path / "tree" / "sub").mkdir(parents=True)
    (tmp_path / "tree" / "sub" / "a.txt").write_bytes(b"a")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await (SFTPPath(remote(tmp_path), session=sftp) / b"tree").rmtree()

    assert result.complete
    assert not (tmp_path / "tree").exists()


# --- a server that lies about its own directory -------------------------------------------------


class LyingListingServer:
    """A server whose `READDIR` answers with names that are not one component.

    The one thing a real `sftp-server` will not do on demand, and the reason `iterdir` joins
    through the check rather than concatenating: POSIX filenames cannot contain `/`, so this
    never fires against an honest server and refuses only one that is lying about its own
    directory.
    """

    def __init__(self, *, entries: tuple[NameEntry, ...]) -> None:
        self.entries = entries
        self.position = 0
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

    def _reply(self, packet: Any) -> None:
        self._outbox += encode(packet)
        self._has_output.set()

    def _dispatch(self, packet: Any) -> None:
        if isinstance(packet, Init):
            self._reply(Version(3))
        elif isinstance(packet, OpenDir):
            self._reply(Handle(packet.request_id, b"d\x00\x00\x00"))
        elif isinstance(packet, ReadDir):
            self._on_readdir(packet)
        elif isinstance(packet, Close):
            self._reply(Status(packet.request_id, StatusCode.OK))
        else:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))

    def _on_readdir(self, packet: ReadDir) -> None:
        if self.position:
            self._reply(Status(packet.request_id, StatusCode.EOF))
            return
        self.position = 1
        self._reply(Name(packet.request_id, self.entries))


def listed(name: bytes, mode: int = REGULAR) -> NameEntry:
    return NameEntry(name, b"-rw-r--r-- 1 me me 0 Jul 26 12:00 " + name, Attrs(0, None, mode))


@pytest.mark.parametrize("hostile", [b"../etc", b"a/b", b"", b"a\x00b"])
async def test_iterdir_refuses_a_listing_that_is_not_a_listing(hostile: bytes):
    """Names out of `READDIR` are chosen by the far end, and this is where they become paths."""
    server = LyingListingServer(entries=(listed(b"honest.csv"), listed(hostile)))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        root = SFTPPath(b"/incoming", session=sftp)
        with pytest.raises(UnsafePathError) as exc:
            _ = [entry async for entry in root.iterdir()]
    assert exc.value.name == hostile


async def test_iterdir_yields_what_precedes_the_refusal():
    """The refusal is per name, so an honest entry before a hostile one still arrives.

    Worth pinning rather than assuming: a version that validated the whole batch up front would
    look identical from the outside until a caller streamed a large directory and lost the
    entries it had already been given.
    """
    server = LyingListingServer(entries=(listed(b"honest.csv"), listed(b"../etc")))
    seen: list[bytes] = []

    async def drain(root: SFTPPath) -> None:
        async for entry in root.iterdir():
            seen.append(bytes(entry))

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsafePathError):
            await drain(SFTPPath(b"/incoming", session=sftp))
    assert seen == [b"/incoming/honest.csv"]


# --- the blocking form --------------------------------------------------------------------------


def test_the_blocking_path_does_the_same_algebra():
    """Same class of answers, no portal involved: the arithmetic never crosses a thread."""
    path = SyncSFTPPath(b"/incoming/archive.tar.gz")
    assert path.name == b"archive.tar.gz"
    assert path.suffixes == (b".tar", b".gz")
    assert bytes(path.parent / b"other") == b"/incoming/other"
    assert path.match(b"*.gz")
    with pytest.raises(UnsafePathError):
        _ = path / b".."


def test_the_blocking_path_against_a_real_server(tmp_path: Path):
    """One session, exercising a predicate, a listing, a glob and the two byte methods."""
    needs_real_server()
    (tmp_path / "report.csv").write_bytes(b"a,b\n")
    (tmp_path / "notes.txt").write_bytes(b"x")

    with (
        sync_open_local_server_transport(cwd=tmp_path) as transport,
        sync_open_session(transport) as sftp,
    ):
        root = SyncSFTPPath(remote(tmp_path), session=sftp)
        report = root / b"report.csv"

        assert report.exists()
        assert report.is_file()
        assert report.read_bytes() == b"a,b\n"
        assert report.size() == 4

        assert sorted(bytes(entry) for entry in root.iterdir()) == [
            remote(tmp_path / "notes.txt"),
            remote(tmp_path / "report.csv"),
        ]
        assert [bytes(found) for found in root.glob(b"*.csv")] == [remote(tmp_path / "report.csv")]

        created = root / b"made.txt"
        assert created.write_bytes(b"payload") == 7
        assert created.read_text() == "payload"
        created.unlink()
        assert not created.exists()


def test_breaking_out_of_a_blocking_glob_finalises_it(tmp_path: Path):
    """An ordinary Python generator, so CPython closes it and the `finally` reaches the portal."""
    needs_real_server()
    for index in range(4):
        (tmp_path / f"f{index}.csv").write_bytes(b"x")

    with (
        sync_open_local_server_transport(cwd=tmp_path) as transport,
        sync_open_session(transport) as sftp,
    ):
        root = SyncSFTPPath(remote(tmp_path), session=sftp)
        for found in root.glob(b"*.csv"):
            assert found.suffix == b".csv"
            break
        assert sftp.listdir(remote(tmp_path))


def test_the_blocking_path_refuses_io_without_a_session():
    with pytest.raises(StateError) as exc:
        SyncSFTPPath(b"/incoming/x").stat()
    assert exc.value.args[0] == (
        "SyncSFTPPath(b'/incoming/x') has no session, so it can do path arithmetic and nothing "
        "else -- construct it with SyncSFTPPath(path, session=...) or call .bind(session)"
    )


# --- properties ---------------------------------------------------------------------------------

SAFE_BYTE_NAMES = st.binary(min_size=1, max_size=6).map(
    lambda raw: bytes(ord("_") if byte in b"/\x00*?[\\" else byte for byte in raw)
)
"""One component that is legal on the wire and literal as a pattern.

Mapped rather than filtered so hypothesis is not rejecting most of what it generates, and the
bytes above 127 are left alone on purpose -- an undecodable name is the case this library exists
to keep working.
"""

COMPONENTS = st.lists(
    SAFE_BYTE_NAMES.filter(lambda name: name not in (b".", b"..")), min_size=1, max_size=4
)


@given(st.binary(max_size=40))
def test_any_bytes_survive_the_round_trip(raw: bytes):
    """A path is its bytes. Nothing is normalised, so nothing can be lost."""
    assert bytes(SFTPPath(raw)) == raw
    assert str(SFTPPath(raw)).encode("utf-8", "surrogateescape") == raw
    assert SFTPPath(str(SFTPPath(raw))) == SFTPPath(raw)


@given(COMPONENTS)
def test_joining_components_is_reversible(components: list[bytes]):
    """`parent` and `name` invert `/`, and `parts` reads back what was put in."""
    path = SFTPPath(b"/")
    for component in components:
        path = path / component
    assert path.parts == (b"/", *components)
    assert path.name == components[-1]
    assert bytes(path.parent) == (
        b"/" + b"/".join(components[:-1]) if len(components) > 1 else b"/"
    )
    assert path.relative_to(b"/").parts == tuple(components)


@given(COMPONENTS)
def test_a_literal_path_matches_itself(components: list[bytes]):
    path = SFTPPath(b"/" + b"/".join(components))
    assert path.match(bytes(path))
    assert path.match(b"/" + b"**/" * len(components) + components[-1])


@given(st.binary(max_size=30))
def test_the_view_functions_never_raise_on_arbitrary_bytes(raw: bytes):
    """These read server-supplied bytes, so "no answer" is an answer rather than a crash."""
    assert isinstance(split_components(raw), tuple)
    assert isinstance(path_parts(raw), tuple)
    assert isinstance(parent_of(raw), bytes)
    assert isinstance(suffixes_of(name_of(raw)), tuple)
    assert stem_of(name_of(raw)) + suffix_of(name_of(raw)) == name_of(raw)

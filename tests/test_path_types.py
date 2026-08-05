r"""What a path argument may be, on each side of a transfer, and what it says when it is not.

**D-96.** A remote path is `bytes` or `str`; a local path is a `Path` or a `str`. One call takes
one of each, which is the trap: `sftp.get("/incoming/data.csv", Path("downloads/data.csv"))` is
correct, and `sftp.stat(Path("/incoming/data.csv"))` used to raise

    AttributeError: 'PosixPath' object has no attribute 'encode'

from inside a private helper, naming neither the argument nor the rule. That is what this file
pins, and the messages are asserted in full because the messages are the whole feature.

**The tempting fix is the wrong one and that is the correctness half.** Accepting `PathLike` via
`os.fsencode` looks like a convenience:

- `str(PureWindowsPath("/incoming/data.csv"))` is `'\\incoming\\data.csv'`, and a backslash is a
  legal character in a POSIX filename -- so a Windows caller would not get an error, they would
  get a file *named* `\incoming\data.csv` in whatever directory the server started in;
- `PurePosixPath("/incoming/")` is `PurePosixPath('/incoming')`, so the trailing slash is gone
  before the library ever sees it.

Both are asserted below rather than described, because they are the argument for refusing.

The local side is here too, and it was inconsistent: `get` accepted `bytes` and wrote the file
(POSIX `open` takes bytes), while `put`, `get_tree` and `put_tree` raised `pathlib`'s own
`TypeError`. Accepted here and refused there is the per-site decision nobody re-reads.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from conftest import needs_non_utf8_names
from gantry_sftp.session import open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

REMOTE_RULE = (
    "a remote path must be bytes or str, not {kind}: it goes on the wire as bytes, and str is "
    "encoded with surrogateescape so a name the server sent can be sent back unchanged"
)

PATHLIB_RULE = (
    "a remote path must be bytes or str, not {kind}: pathlib normalises and a remote name has "
    "to survive byte for byte -- a trailing slash goes on construction, and str(Path(...)) on "
    "Windows renders separators as backslashes, which a server takes as part of the filename "
    "rather than as separators. Pass str(path) if it really is posix-shaped, or the bytes the "
    "server gave you. The local side of get()/put() is the argument that takes a Path"
)

LOCAL_RULE = (
    "{method} needs a Path or str for its local path, not bytes: bytes is the rule for the "
    "*remote* path, which goes on the wire; a local path is opened by this process"
)


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


# --- why a Path is refused rather than coerced -------------------------------------------------


def test_a_windows_path_would_put_backslashes_on_the_wire():
    """The reason `os.fsencode` is not the fix, stated as an assertion rather than a worry.

    A server does not refuse this. `\\` is an ordinary character in a POSIX filename, so the
    file is created -- with the separators as part of its name, in whatever directory the
    session started in. Silent, and in the data-placement class.
    """
    assert str(PureWindowsPath("/incoming/data.csv")) == "\\incoming\\data.csv"
    assert os.fsencode(str(PureWindowsPath("/incoming/data.csv"))) == b"\\incoming\\data.csv"


def test_pathlib_drops_a_trailing_slash_before_the_library_sees_it():
    """The other half, and it bites on posix paths too -- so this is not only a Windows rule.

    "Vary the axis under test" names trailing slashes as an axis that bites, and a type whose
    job is to normalise cannot carry one.
    """
    assert str(PurePosixPath("/incoming/")) == "/incoming"


# --- the remote side ---------------------------------------------------------------------------


async def test_a_path_as_a_remote_path_is_refused_by_name(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TypeError) as wrong:
            await sftp.stat(tmp_path / "data.txt")
        assert wrong.value.args[0] == PATHLIB_RULE.format(kind="PosixPath")


async def test_a_pure_path_gets_the_same_answer(tmp_path: Path):
    """`PurePosixPath` has no Windows problem and still normalises, so it is refused too.

    Named in the message rather than special-cased: the remedy `str(path)` is the same one.
    """
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TypeError) as wrong:
            await sftp.exists(PurePosixPath("/incoming"))
        assert wrong.value.args[0] == PATHLIB_RULE.format(kind="PurePosixPath")


@pytest.mark.parametrize(
    ("value", "kind"), [(3, "int"), (None, "NoneType"), (["/incoming"], "list")]
)
async def test_anything_else_is_refused_with_the_rule(value: object, kind: str, tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TypeError) as wrong:
            await sftp.stat(value)  # type: ignore[arg-type]
        assert wrong.value.args[0] == REMOTE_RULE.format(kind=kind)


async def test_every_path_taking_method_refuses_it(tmp_path: Path):
    """The sweep. One chokepoint is only worth having if everything really goes through it.

    Enumerated by calling them rather than by trusting that they share a helper -- a method
    that encoded a path itself would pass a test that only checked the helper.
    """
    needs_real_server()
    bad = tmp_path / "data.txt"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        calls = (
            ("stat", lambda: sftp.stat(bad)),
            ("lstat", lambda: sftp.lstat(bad)),
            ("exists", lambda: sftp.exists(bad)),
            ("isdir", lambda: sftp.isdir(bad)),
            ("isfile", lambda: sftp.isfile(bad)),
            ("islink", lambda: sftp.islink(bad)),
            ("getsize", lambda: sftp.getsize(bad)),
            ("getmtime", lambda: sftp.getmtime(bad)),
            ("realpath", lambda: sftp.realpath(bad)),
            ("readlink", lambda: sftp.readlink(bad)),
            ("chmod", lambda: sftp.chmod(bad, 0o644)),
            ("truncate", lambda: sftp.truncate(bad, 0)),
            ("mkdir", lambda: sftp.mkdir(bad)),
            ("makedirs", lambda: sftp.makedirs(bad)),
            ("rmdir", lambda: sftp.rmdir(bad)),
            ("remove", lambda: sftp.remove(bad)),
            ("rmtree", lambda: sftp.rmtree(bad)),
            ("rename", lambda: sftp.rename(bad, b"/elsewhere")),
            ("posix_rename", lambda: sftp.posix_rename(bad, b"/elsewhere")),
            ("symlink", lambda: sftp.symlink(bad, b"/elsewhere")),
            ("opendir", lambda: sftp.opendir(bad)),
            ("listdir", lambda: sftp.listdir(bad)),
            ("open", lambda: sftp.open(bad)),
        )
        for name, call in calls:
            with pytest.raises(TypeError) as wrong:
                await call()
            assert wrong.value.args[0] == PATHLIB_RULE.format(kind="PosixPath"), name


async def test_the_streaming_shapes_refuse_it_too(tmp_path: Path):
    """`scandir`, `open_file`, `walk` and `glob` hand back an object before doing any work.

    So the refusal has to survive the extra hop -- entering the context manager, or taking the
    first item -- rather than being raised at a call nobody awaited.
    """
    needs_real_server()
    bad = tmp_path / "data.txt"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TypeError) as wrong:
            async with sftp.scandir(bad):
                pass
        assert wrong.value.args[0] == PATHLIB_RULE.format(kind="PosixPath")

        with pytest.raises(TypeError):
            async with sftp.open_file(bad):
                pass

        with pytest.raises(TypeError):
            async for _ in sftp.walk(bad):
                pass

        with pytest.raises(TypeError):
            async for _ in sftp.glob(bad):
                pass


# --- the local side, which disagreed with itself -----------------------------------------------


async def test_a_bytes_local_path_is_refused_by_every_transfer(tmp_path: Path):
    """`get` used to accept it and write the file; the other three raised pathlib's TypeError.

    The declared type is now the accepted type on all four, and the message says which side
    `bytes` is the rule for -- because a caller passing it here is not confused about types,
    they are one argument out on a rule nothing had stated.
    """
    needs_real_server()
    source = tmp_path / "data.txt"
    source.write_bytes(b"payload")
    remote_source = os.fsencode(source)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        calls = (
            ("get()", lambda: sftp.get(remote_source, os.fsencode(tmp_path / "out.txt"))),
            ("put()", lambda: sftp.put(os.fsencode(source), os.fsencode(tmp_path / "up.txt"))),
            ("get_tree()", lambda: sftp.get_tree(os.fsencode(tmp_path), os.fsencode(tmp_path))),
            ("put_tree()", lambda: sftp.put_tree(os.fsencode(tmp_path), os.fsencode(tmp_path))),
        )
        for method, call in calls:
            with pytest.raises(TypeError) as wrong:
                await call()  # type: ignore[arg-type]
            assert wrong.value.args[0] == LOCAL_RULE.format(method=method), method

    assert not (tmp_path / "out.txt").exists(), "get() wrote a file it should have refused"


async def test_a_local_path_that_is_not_bytes_either_gets_the_other_half_of_the_message(
    tmp_path: Path,
):
    """`bytes` is the interesting wrong type and it is not the only one (D-105 slice 27).

    The refusal picks its second sentence from whether the value was `bytes` -- the "you are
    one argument out" case -- or anything else, and only the first branch had a test. The
    other could have been emptied or case-mangled, which is the sentence a caller gets when
    they hand over an `int` from a config file or a `list` from an `argparse` mistake.
    """
    needs_real_server()
    source = tmp_path / "data.txt"
    source.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(TypeError) as wrong:
            await sftp.get(os.fsencode(source), 7)  # type: ignore[arg-type]
        assert wrong.value.args[0] == (
            "get() needs a Path or str for its local path, not int: it is opened by this "
            "process, so it has to be something pathlib accepts"
        )


async def test_the_local_path_still_takes_both_of_the_types_it_declares(tmp_path: Path):
    """Guards the guard: a check that refused everything would pass every test above."""
    needs_real_server()
    source = tmp_path / "data.txt"
    source.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        as_path = await sftp.get(os.fsencode(source), tmp_path / "as-path.txt")
        as_str = await sftp.get(os.fsencode(source), str(tmp_path / "as-str.txt"))

    assert (as_path.transferred, as_str.transferred) == (len(b"payload"), len(b"payload"))
    # Both spellings come back normalised: the result carries the destination as a `Path`
    # whichever of the two the caller passed in, so a consumer writing a manifest does not
    # have to normalise it a second time.
    assert as_path.local_path == tmp_path / "as-path.txt"
    assert as_str.local_path == tmp_path / "as-str.txt"

    assert (tmp_path / "as-path.txt").read_bytes() == b"payload"
    assert (tmp_path / "as-str.txt").read_bytes() == b"payload"


@needs_non_utf8_names
async def test_a_str_remote_path_still_round_trips_a_hostile_name(tmp_path: Path):
    """The other guard: the `str` branch is what carries a surrogateescaped name back.

    Refusing the wrong types must not disturb the one thing `_encode_path` exists for -- a
    name that was not valid UTF-8, decoded leniently, and sent again unchanged.
    """
    needs_real_server()
    hostile = tmp_path / "caf\udce9.csv"
    hostile.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.exists(str(hostile)) is True
        assert await sftp.getsize(os.fsencode(hostile)) == len(b"payload")

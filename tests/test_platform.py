"""The local platform's capabilities, and the refusal when it lacks one.

`session/_platform.py` is the only place in `session/` that asks the *near* end a question.
Two things it claims have to be true or the refusal is worse than the crash it replaced: it
must probe rather than infer a platform, and everything it says still works must still work.
Both are asserted below.

The transfer methods are driven against `FakeServer`, whose `seen` list is every packet it was
handed -- so "refuses before touching the wire" is a count rather than an impression.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from tests.test_session import FakeServer

from gantry_sftp.session import open_session
from gantry_sftp.session._platform import NO_FOLLOW, missing_local_io, require_local_io

pytestmark = pytest.mark.anyio

REFUSAL_TAIL = (
    "which CPython provides on Unix only. The ssh transport and every remote-only "
    "operation -- listdir, scandir, walk, stat, realpath, rename, remove, mkdir, rmdir, "
    "rmtree, check_file -- work normally here; only transfers between the remote side and "
    "a local file do not, and there is no fallback. Use a POSIX host for transfers."
)


# ---------------------------------------------------------------------------
# The probe
# ---------------------------------------------------------------------------


def test_this_platform_has_offset_addressed_local_io() -> None:
    # Written to fail on a platform that does not, which is the point: the CI matrix runs it
    # on Windows and this row is the one that says why that job cannot gate.
    assert missing_local_io() == ()


def test_a_python_without_pwrite_reports_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "pwrite")
    assert missing_local_io() == ("os.pwrite",)


def test_a_python_without_pread_reports_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "pread")
    assert missing_local_io() == ("os.pread",)


def test_both_halves_of_the_data_path_are_reported_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reported in one list rather than whichever is checked first: a Windows reader who
    # implements only `pwrite` should be told the upload side is still missing.
    monkeypatch.delattr(os, "pread")
    monkeypatch.delattr(os, "pwrite")
    assert missing_local_io() == ("os.pread", "os.pwrite")


def test_a_platform_that_cannot_stamp_a_descriptor_reports_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `os.utime` exists everywhere; what varies is whether it takes a descriptor, which is
    # what `preserve_times` needs and what `os.supports_fd` is the portable way to ask.
    monkeypatch.setattr(os, "supports_fd", frozenset())
    assert missing_local_io() == ("os.utime on a descriptor",)


def test_the_probe_asks_os_rather_than_which_platform_this_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A `sys.platform` check would be a guess about which platforms have `pwrite`, and it
    # would be wrong the day one of them grows it. The obstacle is the primitive.
    monkeypatch.setattr(sys, "platform", "win32")
    assert missing_local_io() == ()


def test_no_follow_is_the_real_flag_where_the_platform_has_one() -> None:
    assert NO_FOLLOW == os.O_NOFOLLOW


# ---------------------------------------------------------------------------
# The refusal
# ---------------------------------------------------------------------------


def test_a_platform_with_everything_is_not_refused() -> None:
    assert require_local_io("get()") is None


def test_the_refusal_names_the_call_and_what_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(os, "pwrite")
    with pytest.raises(NotImplementedError) as exc:
        require_local_io("get()")
    assert exc.value.args[0] == (
        f"get() is not supported on this platform: it needs os.pwrite, {REFUSAL_TAIL}"
    )


def test_the_refusal_lists_every_missing_primitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "pread")
    monkeypatch.delattr(os, "pwrite")
    monkeypatch.setattr(os, "supports_fd", frozenset())
    with pytest.raises(NotImplementedError) as exc:
        require_local_io("put_tree()")
    assert exc.value.args[0] == (
        f"put_tree() is not supported on this platform: it needs os.pread, os.pwrite, "
        f"os.utime on a descriptor, {REFUSAL_TAIL}"
    )


# ---------------------------------------------------------------------------
# The four entry points, against a server that would have answered
# ---------------------------------------------------------------------------


TRANSFERS = ("get", "get_tree", "put", "put_tree")


async def call_transfer(sftp: object, name: str, tmp_path: Path) -> None:
    if name == "get":
        await sftp.get(b"/remote/file.bin", tmp_path / "file.bin")  # type: ignore[attr-defined]
    elif name == "get_tree":
        await sftp.get_tree(b"/remote", tmp_path / "tree")  # type: ignore[attr-defined]
    elif name == "put":
        source = tmp_path / "source.bin"
        _ = source.write_bytes(b"payload")
        await sftp.put(source, b"/remote/file.bin")  # type: ignore[attr-defined]
    else:
        (tmp_path / "tree").mkdir()
        await sftp.put_tree(tmp_path / "tree", b"/remote")  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", TRANSFERS)
async def test_a_transfer_refuses_before_touching_the_wire(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer(content=b"payload")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        monkeypatch.delattr(os, "pwrite")
        before = len(server.seen)
        with pytest.raises(NotImplementedError) as exc:
            await call_transfer(sftp, name, tmp_path)
        assert exc.value.args[0].startswith(f"{name}() is not supported on this platform")
        assert len(server.seen) == before


@pytest.mark.parametrize("name", ["get", "get_tree"])
async def test_a_refused_download_does_not_truncate_its_destination(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A download opens its destination with O_TRUNC, so a refusal raised after that open
    # would destroy the caller's file in order to report that it could not replace it. The
    # upload side has no equivalent -- it never writes locally -- so it is not parametrised
    # here rather than added as a row that cannot fail.
    existing = tmp_path / "file.bin"
    _ = existing.write_bytes(b"do not touch")
    server = FakeServer(content=b"payload")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        monkeypatch.delattr(os, "pwrite")
        with pytest.raises(NotImplementedError):
            await call_transfer(sftp, name, tmp_path)
    assert existing.read_bytes() == b"do not touch"
    assert not (tmp_path / "tree").exists()


async def test_the_remote_only_operations_keep_working_without_offset_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The refusal message claims these still work. A claim in an error message is a claim.
    server = FakeServer(content=b"payload")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        monkeypatch.delattr(os, "pread")
        monkeypatch.delattr(os, "pwrite")
        assert (await sftp.stat(b"/remote/file.bin")).size == len(b"payload")
        assert await sftp.realpath(b".") == b"/canonical"
        handle = await sftp.open(b"/remote/file.bin")
        await sftp.close(handle)


def test_a_python_without_fchmod_reports_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The third probe, and the only one whose name is spelled out rather than derived.

    The two offset primitives come from a list comprehension over `_OFFSET_IO`, so their names
    are the list's; `os.fchmod` is appended as a literal and nothing had removed it to see what
    the refusal says. It is the primitive `mode=` needs on the download side -- without it a
    delivered file cannot be given the permissions the caller asked for, which is D-56a's whole
    subject on the local half.
    """
    monkeypatch.delattr(os, "fchmod", raising=False)
    assert missing_local_io() == ("os.fchmod",)

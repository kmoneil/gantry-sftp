"""Timestamps: preserved when asked, discarded by default, and never read off ``longname``.

**The bug this file exists for (D-79).** Until 0.9 a transfer discarded the file's times in
both directions, so every file this library moved arrived stamped with the moment it was
moved. Nothing errored, the size check passed, the result reported success -- only a field
nobody inspects was wrong, and the value replacing the truth was a plausible one. Every
downstream decision keyed on mtime was then made on a fabrication: incremental sync, retention
windows, dedup, "newer than" sweeps.

The first two tests below are the regression. Each fails against the code as it stood.

Two things are deliberately *not* preserved, and each has a test saying so rather than a
comment: the default leaves the destination stamped with now, and neither tree stamps the root
the caller named.
"""

from __future__ import annotations

import datetime as dt
import os
import time
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    Attrs,
    AttrsReply,
    Close,
    Data,
    FrameSplitter,
    Handle,
    Init,
    LStat,
    Open,
    Read,
    Stat,
    Status,
    StatusCode,
    Times,
    Version,
    decode,
    encode,
)
from gantry_sftp.session import (
    DirEntry,
    Publish,
    TimePreservation,
    accessed_at,
    modified_at,
    open_session,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

# Deliberately unequal, and atime the larger, so a swapped pair is visible rather than
# symmetrical. 2020-09-13, comfortably outside the six months that would make `ls -l` print a
# time instead of a year -- see the longname section below.
KNOWN_MTIME = 1_600_000_000
KNOWN_ATIME = 1_600_000_007


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


class TimelessServer:
    """A server whose ``STAT`` carries a size and no times.

    Legal, and not rare: filexfer v3 attributes are a flags word, so ``ACMODTIME`` being
    absent is a server saying it has no opinion rather than a server misbehaving. There is no
    way to make a real ``sftp-server`` do it, which is why this is a fake -- and the case it
    stages is the one ``preserve_times`` cannot satisfy and used to pass over in silence.
    """

    def __init__(self, *, content: bytes = b"") -> None:
        self.content = content
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

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

    def _dispatch(self, packet: object) -> None:
        if isinstance(packet, Init):
            self._reply(Version(3, ()))
            return
        rid = packet.request_id  # type: ignore[union-attr]
        if isinstance(packet, Stat | LStat):
            self._reply(AttrsReply(rid, Attrs(size=len(self.content))))
        elif isinstance(packet, Open):
            self._reply(Handle(rid, b"h"))
        elif isinstance(packet, Read):
            chunk = self.content[packet.offset : packet.offset + packet.length]
            self._reply(Data(rid, memoryview(chunk)) if chunk else Status(rid, StatusCode.EOF))
        elif isinstance(packet, Close):
            self._reply(Status(rid, StatusCode.OK))
        else:
            self._reply(Status(rid, StatusCode.OK))


def stamped(path: Path, payload: bytes = b"payload") -> Path:
    path.write_bytes(payload)
    os.utime(path, (KNOWN_ATIME, KNOWN_MTIME))
    return path


# --- the regression ---------------------------------------------------------------------


async def test_a_download_preserves_the_remote_mtime_when_asked(tmp_path: Path):
    """D-79, download half. Fails against 0.8: the local copy was stamped with now.

    Compares the whole timestamp rather than asserting "not now", because "not now" would
    also pass for a wrong-but-stable value -- the failure mode that made this expensive to
    find in the first place is a plausible number, not an obviously absent one.
    """
    needs_real_server()
    source = stamped(tmp_path / "source.bin")
    destination = tmp_path / "downloaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.get(str(source).encode(), destination, preserve_times=True)

    assert int(destination.stat().st_mtime) == KNOWN_MTIME
    assert int(destination.stat().st_atime) == KNOWN_ATIME


async def test_an_upload_preserves_the_local_mtime_when_asked(tmp_path: Path):
    """D-79, upload half. Fails against 0.8 for the same reason, in the other direction."""
    needs_real_server()
    source = stamped(tmp_path / "source.bin")
    destination = tmp_path / "uploaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination).encode(), preserve_times=True)

    assert result.times is TimePreservation.PRESERVED
    assert int(destination.stat().st_mtime) == KNOWN_MTIME


# --- the default is a decision, not an omission -------------------------------------------


async def test_by_default_a_transfer_stamps_the_destination_with_now(tmp_path: Path):
    """Both directions, asserted, because the default is the load-bearing half of D-79.

    Off matches ``scp -p`` and ``rsync -t``, and on-by-default would break the landing zone
    whose consumer collects "files modified since X" -- a file arriving with last year's date
    is never picked up. That failure is as silent as the one preserving fixes and points the
    other way, which is why this is pinned rather than left to whichever way the code drifts.
    """
    needs_real_server()
    source = stamped(tmp_path / "source.bin")
    downloaded = tmp_path / "downloaded.bin"
    uploaded = tmp_path / "uploaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.get(str(source).encode(), downloaded)
        result = await sftp.put(source, str(uploaded).encode())

    assert result.times is TimePreservation.SKIPPED
    assert int(downloaded.stat().st_mtime) != KNOWN_MTIME
    assert int(uploaded.stat().st_mtime) != KNOWN_MTIME
    # The source is untouched either way -- preserving is about the copy, not the original.
    assert int(source.stat().st_mtime) == KNOWN_MTIME


# --- the publish paths ---------------------------------------------------------------------


@pytest.mark.parametrize("atomic", [True, False], ids=["atomic", "in-place"])
async def test_both_publish_paths_preserve(tmp_path: Path, atomic: bool):
    """Atomic is the one that could plausibly lose them, so it is the one worth pinning.

    The times are set on the *staging* handle, before the rename. ``rename(2)`` does not alter
    a file's mtime, so they survive the publish -- but setting them after the rename instead
    would have needed a second round trip to a path a consumer can already see, and would
    briefly publish the file wearing the wrong date.
    """
    needs_real_server()
    source = stamped(tmp_path / "source.bin")
    destination = tmp_path / "published.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source,
            str(destination).encode(),
            publish=Publish(atomic=atomic),
            preserve_times=True,
        )

    assert result.times is TimePreservation.PRESERVED
    assert int(destination.stat().st_mtime) == KNOWN_MTIME


async def test_a_resumed_download_that_is_already_complete_is_still_stamped(tmp_path: Path):
    """D-99's bug: the early return applied the mode and silently skipped the timestamps.

    A resume that finds the local file already whole returns without opening anything, and
    until 0.11 that path stamped nothing -- so ``preserve_times=True`` left the file carrying
    the moment the *interrupted* run last wrote to it. That is D-79's failure exactly: a
    fabricated timestamp that looks entirely plausible, on a call that reported success.

    It was invisible because ``get`` returned a byte count. Building
    :class:`~gantry_sftp.session.DownloadResult` is what surfaced it -- the field had to say
    ``PRESERVED`` or ``SKIPPED`` on a path where the caller had asked and neither was true.

    The mode half was already right and is asserted alongside, because the argument the code
    makes for one is the argument for the other: the destination exists, the caller said what
    metadata it should carry, and "it was already there" is not an answer to that.
    """
    needs_real_server()
    payload = b"payload"
    complete = tmp_path / "complete.bin"
    complete.write_bytes(payload)
    os.utime(complete, (KNOWN_ATIME - 500_000, KNOWN_MTIME - 500_000))
    # Stamped *after* the copy: reading a file updates its atime, so building the destination
    # from `source.read_bytes()` would move the very timestamp this test is about.
    source = stamped(tmp_path / "source.bin", payload)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.get(
            str(source).encode(), complete, resume=True, preserve_times=True, mode=0o640
        )

    assert result.transferred == 0, "nothing was moved, which is what makes this the early path"
    assert result.times is TimePreservation.PRESERVED
    assert int(complete.stat().st_mtime) == KNOWN_MTIME
    assert int(complete.stat().st_atime) == KNOWN_ATIME
    assert complete.stat().st_mode & 0o777 == 0o640


async def test_a_download_from_a_server_that_reports_no_times_says_so(tmp_path: Path):
    """The third state, which used to be a paragraph of apology in ``get``'s docstring.

    A server that answers ``STAT`` with no times leaves the local file stamped with now. That
    is a wrong answer rather than a missing one, and before D-99 ``get`` had nowhere to say it
    had happened -- the docstring told the caller to go and ``stat()`` the file first instead.
    """
    server = TimelessServer(content=b"payload")
    local = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get(b"/remote.bin", local, preserve_times=True)

    assert result.times is TimePreservation.UNAVAILABLE
    assert local.read_bytes() == b"payload"


async def test_a_resumed_download_is_stamped_once_it_is_whole(tmp_path: Path):
    # Applied after the last write, not during: a write updates mtime, so stamping a partial
    # file would be undone by the bytes that finish it.
    needs_real_server()
    payload = bytes(range(256)) * 200
    source = stamped(tmp_path / "source.bin", payload)
    partial = tmp_path / "partial.bin"
    partial.write_bytes(payload[:10_000])

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.get(str(source).encode(), partial, resume=True, preserve_times=True)

    assert result.transferred == len(payload) - 10_000
    assert result.times is TimePreservation.PRESERVED
    assert partial.read_bytes() == payload
    assert int(partial.stat().st_mtime) == KNOWN_MTIME


# --- trees ----------------------------------------------------------------------------------


def build_tree(root: Path) -> None:
    (root / "sub").mkdir(parents=True)
    stamped(root / "a.txt", b"a")
    stamped(root / "sub" / "b.txt", b"b")
    # Directories last: creating a file inside one updates its mtime, so stamping the
    # directories first would be undone by the files.
    os.utime(root / "sub", (KNOWN_ATIME, KNOWN_MTIME))
    os.utime(root, (KNOWN_ATIME, KNOWN_MTIME))


async def test_put_tree_and_get_tree_preserve_files_and_the_directories_they_create(
    tmp_path: Path,
):
    needs_real_server()
    source = tmp_path / "src"
    build_tree(source)
    uploaded = tmp_path / "up"
    downloaded = tmp_path / "down"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put_tree(source, str(uploaded).encode(), preserve_times=True)
        await sftp.get_tree(str(uploaded).encode(), downloaded, preserve_times=True)

    for base in (uploaded, downloaded):
        for relative in ("a.txt", "sub", "sub/b.txt"):
            assert int((base / relative).stat().st_mtime) == KNOWN_MTIME, (
                f"{base.name}/{relative} lost its timestamp"
            )


async def test_by_default_neither_tree_preserves_timestamps(tmp_path: Path):
    """The tree half of the default, which only the single-file half had (D-105, twelfth slice).

    `preserve_times=False` on `get_tree` and `put_tree` was held in place by exactly one thing:
    `test_sync_facade.py` comparing the async signature against the sync twin. That is agreement
    between two surfaces rather than a statement about the value, so changing both would have
    gone unnoticed -- and mutmut cannot see that file at all, which is how a documented public
    default came to have no lane-visible test.

    The consequence is the one `test_by_default_a_transfer_stamps_the_destination_with_now`
    states for a single file, multiplied by a tree: a landing zone whose consumer collects
    "modified since X" never picks up a file wearing last year's date.
    """
    needs_real_server()
    source = tmp_path / "src"
    build_tree(source)
    uploaded = tmp_path / "up"
    downloaded = tmp_path / "down"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put_tree(source, str(uploaded).encode())
        # **Downloaded from the stamped source, not from what the upload just landed.** The
        # first version of this read `uploaded`, which `put_tree` had already re-stamped with
        # now -- so a `get_tree` that preserved would have copied *that*, and "not the known
        # time" was true either way. The mutation survived and the test could not have failed.
        await sftp.get_tree(str(source).encode(), downloaded)

    for base in (uploaded, downloaded):
        for relative in ("a.txt", "sub/b.txt"):
            assert int((base / relative).stat().st_mtime) != KNOWN_MTIME, (
                f"{base.name}/{relative} was stamped with the source's time without being asked"
            )
    # And the sources are untouched, so this is a fact about the copies rather than about
    # something the walk did on the way past.
    assert int((source / "a.txt").stat().st_mtime) == KNOWN_MTIME


async def test_neither_tree_stamps_the_root_the_caller_named(tmp_path: Path):
    # Restamping a directory the caller already had is a side effect on something they did
    # not ask to have modified. Stated as a test because "we only touch what we create" is
    # the kind of boundary that erodes silently.
    needs_real_server()
    source = tmp_path / "src"
    build_tree(source)
    uploaded = tmp_path / "up"
    downloaded = tmp_path / "down"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put_tree(source, str(uploaded).encode(), preserve_times=True)
        await sftp.get_tree(str(uploaded).encode(), downloaded, preserve_times=True)

    assert int(uploaded.stat().st_mtime) != KNOWN_MTIME
    assert int(downloaded.stat().st_mtime) != KNOWN_MTIME


# --- absent is not epoch ---------------------------------------------------------------------


def test_a_server_that_reports_no_times_yields_none_rather_than_1970():
    # The coercion this type exists to refuse. Absent treated as 0 dates the file to 1970,
    # which reads as "very old" to every `if remote > local`, so a sync built on it either
    # re-transfers everything or skips everything -- and looks correct doing it.
    assert modified_at(Attrs(size=10)) is None
    assert accessed_at(Attrs(size=10)) is None
    assert DirEntry(b"f", b"f", Attrs(size=10)).modified is None


def test_a_reported_time_decodes_to_an_aware_utc_instant():
    entry = DirEntry(b"f", b"f", Attrs(times=Times(atime=KNOWN_ATIME, mtime=KNOWN_MTIME)))
    modified = entry.modified
    assert modified is not None
    assert modified.tzinfo is dt.UTC, "a naive datetime is the client's wall clock, not the file's"
    assert modified.isoformat() == "2020-09-13T12:26:40+00:00"
    accessed = entry.accessed
    assert accessed is not None
    assert accessed.isoformat() == "2020-09-13T12:26:47+00:00"


# --- longname carries no usable timestamp ----------------------------------------------------


@pytest.mark.parametrize(
    ("age_seconds", "expect_year"),
    [
        (60 * 60 * 24 * 30, False),  # a month old: month, day, time -- and no year
        (60 * 60 * 24 * 400, True),  # over a year: month, day, year -- and no time
        (-60 * 60 * 24 * 30, True),  # in the *future*: the year branch too
    ],
    ids=["recent-has-no-year", "old-has-no-time", "future-has-no-time"],
)
async def test_longname_never_carries_both_a_year_and_a_time(
    tmp_path: Path, age_seconds: int, expect_year: bool
):
    """Measured against the real server, because this is the trap the accessors exist for.

    OpenSSH's ``ls_file`` prints ``%b %e %H:%M`` within the last half year and ``%b %e  %Y``
    otherwise, so no entry ever carries both. Scraping the string therefore loses the year on
    exactly the files a sync cares about most -- the recent ones.
    """
    needs_real_server()
    target = tmp_path / "aged.txt"
    target.write_bytes(b"x")
    stamp = int(time.time()) - age_seconds
    os.utime(target, (stamp, stamp))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        (entry,) = [e for e in await sftp.listdir(str(tmp_path).encode()) if e.name == "aged.txt"]

    rendered = entry.longname.decode()
    year = str(dt.datetime.fromtimestamp(stamp, dt.UTC).year)
    has_time = ":" in rendered.rsplit(maxsplit=1)[0]
    assert (year in rendered) is expect_year
    assert has_time is not expect_year, "longname carried a year and a time at once"

    # And the structured field is exact regardless of which branch was printed.
    modified = entry.modified
    assert modified is not None
    assert int(modified.timestamp()) == stamp

"""Path predicates, and the third state each of them has.

**D-87.** `exists`, `isdir`, `isfile`, `islink`, `getsize`, `getmtime` and a public `makedirs`.
Seven methods over `stat`, and the reason they are a card rather than seven one-liners is the
rule in CLAUDE.md's Definition of Done §2: *every predicate has three states -- true, false, and
errored -- decide the errored one explicitly and test it.* Nothing in this library was a
predicate until now, so that rule had never been applied to anything.

The decision under test is that **`False` means the server said `NO_SUCH_FILE`, and nothing
else**. A predicate that answers `False` for a refusal reports a path as free when it is
occupied by something the caller may not see, and the caller then creates on top of it.

Which conditions the far end folds *into* `NO_SUCH_FILE` is a property of the server rather
than something to reason out, so it was measured first
(`_plans/probes/predicate_third_state_probe.py`, OpenSSH 10.0p2) and the findings are asserted
here against a real `sftp-server`:

- `ENOTDIR` (a path under a file) and `ELOOP` (a symlink loop) are `NO_SUCH_FILE`, so both are
  an ordinary `False`;
- `EACCES` on a traversal is `PERMISSION_DENIED` -- the third state, one `chmod` away;
- `ENAMETOOLONG` is `BAD_MESSAGE`, a code that reads as *your frame was malformed* and means
  nothing of the kind. It arrives as a plain `ServerError`, so anything catching wider than
  `NoSuchFileError` would answer "not there" for a path that was merely long.

The one state a real server cannot produce is an `ATTRS` with fields missing -- OpenSSH always
sends `SIZE|UIDGID|PERMISSIONS|ACMODTIME` -- and that is what the fake at the bottom is for. It
is the legitimate use of a fake: the question is what *our* code decides when a legal answer
carries nothing, not whether we agree with a real server about anything.
"""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    Attrs,
    AttrsReply,
    FrameSplitter,
    Init,
    LStat,
    Name,
    NameEntry,
    RealPath,
    Stat,
    Status,
    StatusCode,
    Times,
    Version,
    decode,
    encode,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    PermissionDeniedError,
    ServerError,
)
from gantry_sftp.session import open_session
from gantry_sftp.sync import open_local_server_transport as sync_open_local_server_transport
from gantry_sftp.sync import open_session as sync_open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

KNOWN_MTIME = 1_600_000_000
KNOWN_ATIME = 1_600_000_007


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def remote(path: Path) -> bytes:
    """A local path as the bytes a request carries."""
    return os.fsencode(path)


# --- true and false, against a real server ---------------------------------------------------


async def test_the_predicates_agree_with_the_filesystem(tmp_path: Path):
    """Every predicate's true and false answer, in one pass over four real kinds of entry.

    A fifo is in here because "not a directory" is not "a file": `isfile` is `S_ISREG` and
    something that is neither has to answer `False` to both, not `True` to one by elimination.
    """
    needs_real_server()
    (tmp_path / "data.txt").write_bytes(b"payload")
    (tmp_path / "folder").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "data.txt")
    os.mkfifo(tmp_path / "pipe")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        file_path = remote(tmp_path / "data.txt")
        folder = remote(tmp_path / "folder")
        alias = remote(tmp_path / "alias")
        pipe = remote(tmp_path / "pipe")
        absent = remote(tmp_path / "nothing")

        assert await sftp.exists(file_path) is True
        assert await sftp.exists(folder) is True
        assert await sftp.exists(absent) is False

        assert await sftp.isdir(folder) is True
        assert await sftp.isdir(file_path) is False
        assert await sftp.isdir(absent) is False

        assert await sftp.isfile(file_path) is True
        assert await sftp.isfile(folder) is False
        assert await sftp.isfile(pipe) is False
        assert await sftp.isfile(absent) is False

        assert await sftp.islink(alias) is True
        assert await sftp.islink(file_path) is False
        assert await sftp.islink(absent) is False


async def test_a_symlink_is_followed_by_default_and_not_when_asked(tmp_path: Path):
    """`follow_symlinks` decides which of two different questions is being asked.

    A link to a directory *is* a directory to `isdir`, matching `os.path.isdir`, and is a
    symlink to `isdir(follow_symlinks=False)`. `islink` takes no such argument at all: following
    the link first is what makes its question unanswerable.
    """
    needs_real_server()
    (tmp_path / "folder").mkdir()
    (tmp_path / "to-folder").symlink_to(tmp_path / "folder")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        link = remote(tmp_path / "to-folder")
        assert await sftp.isdir(link) is True
        assert await sftp.isdir(link, follow_symlinks=False) is False
        assert await sftp.islink(link) is True


async def test_a_broken_symlink_separates_the_two_spellings_of_exists(tmp_path: Path):
    """The shape that makes `follow_symlinks` on `exists` worth having.

    `exists` follows, so a link whose target is gone is `False` -- there is no file at the end
    of the name. `exists(follow_symlinks=False)` answers the question publishing actually asks,
    *is this name taken*, and a name occupied by a broken link is taken: creating there fails.
    """
    needs_real_server()
    (tmp_path / "dangling").symlink_to(tmp_path / "never-existed")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        dangling = remote(tmp_path / "dangling")
        assert await sftp.exists(dangling) is False
        assert await sftp.exists(dangling, follow_symlinks=False) is True
        assert await sftp.islink(dangling) is True
        assert await sftp.isfile(dangling) is False
        assert await sftp.isdir(dangling) is False


async def test_a_symlink_loop_reads_as_absent(tmp_path: Path):
    """Measured, not assumed: OpenSSH maps `ELOOP` to `NO_SUCH_FILE`, so this is a plain `False`.

    Documented rather than corrected. `os.path.exists` answers `False` for a loop locally too,
    and the alternative -- raising for a condition the status code does not distinguish -- would
    mean inventing a difference the wire does not carry.
    """
    needs_real_server()
    (tmp_path / "ouroboros").symlink_to(tmp_path / "ouroboros")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        loop = remote(tmp_path / "ouroboros")
        assert await sftp.exists(loop) is False
        assert await sftp.exists(loop, follow_symlinks=False) is True
        assert await sftp.islink(loop) is True


async def test_a_path_under_a_file_is_false_rather_than_an_error(tmp_path: Path):
    """`ENOTDIR` is folded into `NO_SUCH_FILE` by the server, so nothing here has to fold it."""
    needs_real_server()
    (tmp_path / "data.txt").write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        under_a_file = remote(tmp_path / "data.txt" / "child")
        assert await sftp.exists(under_a_file) is False
        assert await sftp.isdir(under_a_file) is False


# --- the third state -------------------------------------------------------------------------


async def test_permission_denied_is_not_false(tmp_path: Path):
    """The headline. Every predicate raises rather than reporting a path it cannot reach.

    The setup is one `chmod`: a directory with no execute bit cannot be traversed, so the
    server answers `PERMISSION_DENIED` for anything inside it while the directory itself stats
    fine. Collapsing that into `False` is how a caller decides to create something that is
    already there -- and, where the caller is a publisher, overwrites it.
    """
    needs_real_server()
    closed = tmp_path / "closed"
    closed.mkdir()
    (closed / "secret.txt").write_bytes(b"payload")
    closed.chmod(0o000)
    try:
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            inside = remote(closed / "secret.txt")

            for predicate in (sftp.exists, sftp.isdir, sftp.isfile, sftp.islink):
                with pytest.raises(PermissionDeniedError) as denied:
                    await predicate(inside)
                assert (
                    denied.value.args[0] == "server returned PERMISSION_DENIED: Permission denied"
                )
                assert denied.value.path == inside

            # The directory itself is readable metadata, so the refusal really is about
            # traversal rather than about the whole subtree being unmentionable.
            assert await sftp.isdir(remote(closed)) is True
    finally:
        closed.chmod(0o755)


async def test_an_overlong_name_is_not_false_either(tmp_path: Path):
    """`ENAMETOOLONG` arrives as `BAD_MESSAGE`, which is a `ServerError` and not a subclass.

    The trap this pins: `BAD_MESSAGE` reads as *the frame you sent was malformed*, and a
    predicate written to catch `ServerError` broadly -- rather than `NoSuchFileError`
    specifically -- would report "not there" for a path whose only problem was its length.
    """
    needs_real_server()
    too_long = remote(tmp_path / ("n" * 4096))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refused:
            await sftp.exists(too_long)
        assert refused.value.args[0] == "server returned BAD_MESSAGE: Bad message"
        assert refused.value.code == int(StatusCode.BAD_MESSAGE)
        assert not isinstance(refused.value, NoSuchFileError)

        with pytest.raises(ServerError):
            await sftp.isdir(too_long)


# --- reading one attribute ---------------------------------------------------------------------


async def test_getsize_and_getmtime_read_what_the_server_sent(tmp_path: Path):
    """Both against a real file, with `getmtime` aware and in UTC rather than a bare float."""
    needs_real_server()
    payload = b"seven!!"
    target = tmp_path / "data.txt"
    target.write_bytes(payload)
    os.utime(target, (KNOWN_ATIME, KNOWN_MTIME))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        path = remote(target)
        assert await sftp.getsize(path) == len(payload)

        when = await sftp.getmtime(path)
        assert when == datetime.fromtimestamp(KNOWN_MTIME, UTC)
        assert when is not None
        assert when.tzinfo is UTC


async def test_getsize_of_a_link_measures_what_was_asked_for(tmp_path: Path):
    """Following gives the target's size; not following gives the length of the target string.

    `os.lstat` reports a symlink's size the same way, so the surprising number is the correct
    one -- and it is only reachable by asking for it.
    """
    needs_real_server()
    target = tmp_path / "data.txt"
    target.write_bytes(b"payload")
    link = tmp_path / "alias"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.getsize(remote(link)) == len(b"payload")
        assert await sftp.getsize(remote(link), follow_symlinks=False) == len(remote(target))


async def test_isfile_and_getmtime_follow_by_default_and_stop_when_asked(tmp_path: Path):
    """The two accessors whose `follow_symlinks` default and forward were both free.

    `isdir` and `getsize` had this pair; `isfile` and `getmtime` did not, so their default
    could flip to `False` and their forward could be nulled -- and `None` is falsy, which is
    the same as asking for `lstat`. Every existing call passed the default, so the two spelled
    the same answer (D-105 slice 27).
    """
    needs_real_server()
    target = tmp_path / "data.csv"
    target.write_bytes(b"payload")
    os.utime(target, (1_600_000_007, 1_600_000_000))
    link = tmp_path / "alias"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        # A link to a file is a file when followed and a symlink when not.
        assert await sftp.isfile(remote(link)) is True
        assert await sftp.isfile(remote(link), follow_symlinks=False) is False

        followed = await sftp.getmtime(remote(link))
        assert followed is not None
        assert int(followed.timestamp()) == 1_600_000_000
        # The link has an mtime of its own -- its creation -- so the two differ, which is what
        # makes the argument observable at all.
        unfollowed = await sftp.getmtime(remote(link), follow_symlinks=False)
        assert unfollowed is not None
        assert int(unfollowed.timestamp()) != 1_600_000_000


async def test_reading_an_attribute_of_an_absent_path_raises(tmp_path: Path):
    """`getsize` and `getmtime` are accessors, not predicates: absent is an error, not a value.

    This is what keeps their `None` unambiguous. `None` can then mean exactly one thing --
    the server sent no such field -- rather than doubling as "no such file", which is a
    distinction `os.path.getsize` makes by raising and which callers would otherwise have to
    make with a second round trip.
    """
    needs_real_server()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        absent = remote(tmp_path / "nothing")
        with pytest.raises(NoSuchFileError) as missing:
            await sftp.getsize(absent)
        assert missing.value.args[0] == "server returned NO_SUCH_FILE: No such file"

        with pytest.raises(NoSuchFileError):
            await sftp.getmtime(absent)


# --- makedirs ----------------------------------------------------------------------------------


async def test_makedirs_creates_every_missing_level(tmp_path: Path):
    needs_real_server()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.makedirs(remote(tmp_path / "a" / "b" / "c"))

    assert (tmp_path / "a" / "b" / "c").is_dir()


async def test_makedirs_on_a_directory_that_exists_costs_one_request(tmp_path: Path):
    """`exist_ok` has to reach the *first* `MKDIR`, and the recovery path hides it if it does not.

    Dropped there, the first attempt is strict, fails, and the missing-parents recovery runs --
    which re-tries with the real `exist_ok` and succeeds. Same end state, extra round trips per
    call, and no assertion about the *result* can see it. The counter can (D-105 slice 27).
    """
    needs_real_server()
    (tmp_path / "already").mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        before = sftp.requests_sent
        await sftp.makedirs(remote(tmp_path / "already"), exist_ok=True)
        # Two, and both are named: the `MKDIR` that fails, and the `STAT` that decides the
        # failure was "already a directory" -- v3 answers a refused MKDIR with a bare FAILURE,
        # so `exist_ok` costs a round trip when it fires and `mkdir`'s docstring says so.
        # Dropped from the first call the recovery walk runs instead and this is five.
        assert sftp.requests_sent - before == 2


async def test_makedirs_governs_the_last_component_only(tmp_path: Path):
    """`os.makedirs`'s asymmetry, which is the half that is easy to get wrong.

    An existing *ancestor* is never an error, whatever `exist_ok` says; `exist_ok` decides only
    what happens when the destination itself is already there. The private `_mkdir_parents`
    this is built on tolerated everything, because `put_tree` -- its only caller until now --
    always wanted `exist_ok=True`.
    """
    needs_real_server()
    (tmp_path / "existing").mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        # An ancestor that is already there: fine, with exist_ok at its default.
        await sftp.makedirs(remote(tmp_path / "existing" / "fresh"))

        # The destination itself already there: refused by default...
        with pytest.raises(ServerError) as refused:
            await sftp.makedirs(remote(tmp_path / "existing"))
        assert refused.value.args[0] == "server returned FAILURE: Failure"
        assert any("already a directory" in note for note in refused.value.__notes__)
        assert any("exist_ok=True" in note for note in refused.value.__notes__)

        # ...and accepted when asked for.
        await sftp.makedirs(remote(tmp_path / "existing"), exist_ok=True)

    assert (tmp_path / "existing" / "fresh").is_dir()


async def test_makedirs_says_what_is_in_the_way(tmp_path: Path):
    """A file where a directory should go, which v3 reports as the contentless `FAILURE`.

    OpenSSH answers the single word `Failure` for an occupied name, a full disk and a read-only
    mount alike, so the status code cannot be the diagnosis. The note is the diagnosis, and it
    costs one `LSTAT` on a path that has already failed.
    """
    needs_real_server()
    (tmp_path / "occupied").write_bytes(b"i am a file")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refused:
            await sftp.makedirs(remote(tmp_path / "occupied"), exist_ok=True)
        assert refused.value.args[0] == "server returned FAILURE: Failure"
        assert any("is a file, not a directory" in note for note in refused.value.__notes__)


async def test_makedirs_blames_the_ancestor_that_is_in_the_way(tmp_path: Path):
    """The error names the level that has to be fixed, not the path that was asked for.

    Creating `/occupied/under/here` where `occupied` is a file fails on `occupied`, and saying
    so is the difference between a fixable message and one that sends the reader to the leaf.
    """
    needs_real_server()
    (tmp_path / "occupied").write_bytes(b"i am a file")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refused:
            await sftp.makedirs(remote(tmp_path / "occupied" / "under" / "here"))
        assert refused.value.path == remote(tmp_path / "occupied")
        assert any("is a file, not a directory" in note for note in refused.value.__notes__)


async def test_makedirs_propagates_a_refusal_it_cannot_excuse(tmp_path: Path):
    """A directory that may not be written to is an error at the level that refused."""
    needs_real_server()
    closed = tmp_path / "closed"
    closed.mkdir()
    closed.chmod(0o500)
    try:
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            with pytest.raises(PermissionDeniedError) as denied:
                await sftp.makedirs(remote(closed / "nope" / "deeper"))
            assert denied.value.args[0] == "server returned PERMISSION_DENIED: Permission denied"
            assert denied.value.path == remote(closed / "nope")
    finally:
        closed.chmod(0o755)


async def test_put_tree_still_tolerates_an_existing_root(tmp_path: Path):
    """The seam `makedirs` was carved out of, proven not to have changed underneath it.

    `_mkdir_parents` grew an `exist_ok` argument and `put_tree` is the caller that was there
    first: uploading into a destination that already exists must stay ordinary.
    """
    needs_real_server()
    source = tmp_path / "src"
    source.mkdir()
    (source / "one.txt").write_bytes(b"first")
    destination = tmp_path / "dst"
    destination.mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put_tree(source, remote(destination))

    assert result.files == 1
    assert (destination / "one.txt").read_bytes() == b"first"


# --- what a server volunteers, and what it does not --------------------------------------------


class SparseServer:
    """A server that answers `STAT`/`LSTAT` with exactly the attributes a test names.

    Every field of a v3 `ATTRS` is optional and a real `sftp-server` never exercises that: it
    sends `SIZE|UIDGID|PERMISSIONS|ACMODTIME` on every reply, measured. So the legal answer
    that carries nothing is unreachable against a real one, and what is under test here is our
    own decision rather than agreement with anybody -- which is the case a fake is for.
    """

    def __init__(self, attrs: Attrs) -> None:
        self.attrs = attrs
        self._splitter = FrameSplitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            packet = decode(frame)
            if isinstance(packet, Init):
                self._reply(Version(3, ()))
            elif isinstance(packet, Stat | LStat):
                self._reply(AttrsReply(packet.request_id, self.attrs))
            elif isinstance(packet, RealPath):
                # Echoed rather than rewritten: `chdir` shares `_classify` with the
                # predicates and has to canonicalise before it can classify, so reaching the
                # shared refusal at all needs this answered (D-105 slice 25).
                self._reply(
                    Name(
                        packet.request_id,
                        (NameEntry(packet.path, packet.path, EMPTY_ATTRS),),
                    )
                )
            else:
                self._reply(Status(packet.request_id, StatusCode.OP_UNSUPPORTED, b"not scripted"))

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

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


async def test_a_missing_size_is_none_rather_than_zero():
    """`None` is the answer, because `0` is a lie that looks like a measurement.

    Absent is not zero -- the rule `Attrs` already states and `modified_at` already honours.
    A `getsize` returning `0` for "the server did not say" reports an empty file, and every
    `if size == 0` in the caller then agrees with it.
    """
    server = SparseServer(Attrs(permissions=stat.S_IFREG | 0o644))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.getsize(b"/anything") is None
        assert await sftp.getmtime(b"/anything") is None


async def test_the_times_still_arrive_when_only_they_are_sent():
    """The other half, so the test above is proving absence rather than a broken reader."""
    server = SparseServer(Attrs(size=11, times=Times(KNOWN_ATIME, KNOWN_MTIME)))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.getsize(b"/anything") == 11
        assert await sftp.getmtime(b"/anything") == datetime.fromtimestamp(KNOWN_MTIME, UTC)


async def test_a_kind_that_cannot_be_classified_raises_rather_than_guessing():
    """No permission bits means no file type, because v3 carries the type inside them.

    `False` would be a definite answer to a question the server did not answer, and it is the
    same guess `EntryKind.UNKNOWN` exists to refuse -- the one that makes a recursive download
    silently skip directories. `exists` is unaffected: something is there, and that much *was*
    answered.
    """
    server = SparseServer(Attrs(size=11))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.exists(b"/anything") is True

        for predicate, name in (
            (sftp.isdir, "isdir"),
            (sftp.isfile, "isfile"),
            (sftp.islink, "islink"),
        ):
            with pytest.raises(CapabilityError) as unclassifiable:
                await predicate(b"/anything")
            assert unclassifiable.value.args[0] == (
                f"{name}() cannot be answered for b'/anything': the server returned attributes "
                f"with no permission bits, and filexfer v3 carries the file type in those bits, "
                f"so there is nothing here to classify. Returning False would report a definite "
                f"'no' for a question the server did not answer. Call stat() or lstat() and "
                f"decide from Attrs.permissions, or use walk(), which reports an entry it cannot "
                f"settle as skipped rather than guessing"
            )
            assert unclassifiable.value.path == b"/anything"
            assert unclassifiable.value.missing == ()
            assert unclassifiable.value.feature == (
                f"{name}() against a server that sends no permission bits"
            )


async def test_chdir_shares_the_predicates_refusal_rather_than_wording_its_own():
    """`_classify` is shared by the predicates and by `chdir`, and D-103 is why.

    One decision, one wording. `chdir` differs only in what it does with a *missing* path --
    a predicate answers `False`, `chdir` raises -- so the unclassifiable case has to arrive
    identically or there are two messages describing one refusal. Lives here rather than in
    `test_working_directory.py` because what is being asserted is the sharing, and the
    argument the two `_classify` arguments carry is only observable through this message.
    """
    server = SparseServer(Attrs(size=11))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as unclassifiable:
            await sftp.chdir(b"/somewhere")

    # Names `chdir` and names the path, both of which `chdir` forwards and nothing read.
    assert unclassifiable.value.args[0].startswith(
        "chdir() cannot be answered for b'/somewhere': the server returned attributes "
        "with no permission bits"
    )
    assert unclassifiable.value.path == b"/somewhere"
    assert unclassifiable.value.feature == (
        "chdir() against a server that sends no permission bits"
    )


# --- the blocking form -------------------------------------------------------------------------


def test_the_predicates_cross_the_thread_boundary(tmp_path: Path):
    """Scalars over the portal, which is the cheap case -- confirmed rather than assumed.

    `tests/test_sync_facade.py` derives the *signatures*, so a predicate missing from
    `SyncSession` fails there by name. What it cannot show is a value coming back, and a
    `bool` returning from a portal call is worth one assertion.
    """
    needs_real_server()
    (tmp_path / "data.txt").write_bytes(b"payload")

    with (
        sync_open_local_server_transport(cwd=tmp_path) as transport,
        sync_open_session(transport) as sftp,
    ):
        assert sftp.exists(remote(tmp_path / "data.txt")) is True
        assert sftp.isfile(remote(tmp_path / "data.txt")) is True
        assert sftp.isdir(remote(tmp_path / "data.txt")) is False
        assert sftp.exists(remote(tmp_path / "nothing")) is False
        assert sftp.getsize(remote(tmp_path / "data.txt")) == len(b"payload")

        sftp.makedirs(remote(tmp_path / "made" / "here"))
        assert sftp.isdir(remote(tmp_path / "made" / "here")) is True

        with pytest.raises(NoSuchFileError) as missing:
            sftp.getsize(remote(tmp_path / "nothing"))
        assert missing.value.args[0] == "server returned NO_SUCH_FILE: No such file"


def test_a_denied_predicate_arrives_flat_on_the_blocking_surface(tmp_path: Path):
    """The third state through the portal: still `PermissionDeniedError`, still not a group."""
    needs_real_server()
    closed = tmp_path / "closed"
    closed.mkdir()
    (closed / "secret.txt").write_bytes(b"payload")
    closed.chmod(0o000)
    try:
        with (
            sync_open_local_server_transport(cwd=tmp_path) as transport,
            sync_open_session(transport) as sftp,
        ):
            with pytest.raises(PermissionDeniedError) as denied:
                sftp.exists(remote(closed / "secret.txt"))
            assert denied.value.args[0] == "server returned PERMISSION_DENIED: Permission denied"
    finally:
        closed.chmod(0o755)


async def test_makedirs_walks_up_to_the_ancestor_it_actually_needs(tmp_path: Path):
    """The walk strips a trailing separator and nothing else, which a name can be mistaken for.

    `parent.rstrip(b"/")` takes a *set* of characters, so widening it by one letter silently
    truncates any ancestor whose name ends in that letter -- and the failure is a second
    `MKDIR` of the original path against a parent that still is not there. A directory called
    `dataX` is not a contrived name; the point is that the strip is about the separator and
    must not be about the name.
    """
    needs_real_server()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.makedirs(remote(tmp_path / "dataX" / "inner"))

    assert (tmp_path / "dataX" / "inner").is_dir()
    assert not (tmp_path / "data").exists(), "the ancestor's name was truncated"


async def test_makedirs_stops_at_the_root_rather_than_walking_past_it(tmp_path: Path):
    """The recursion's terminating condition, and the one that is not about `exist_ok`.

    A refusal one level under `/` leaves nothing to recurse into: the parent strips to the
    empty string, and the guard re-raises the server's own answer. Getting the condition wrong
    turns a clean `PERMISSION_DENIED` into a walk toward an empty path -- an error about a name
    the caller never used, or no termination at all.
    """
    needs_real_server()
    if os.geteuid() == 0:
        pytest.skip("running as root, where creating a directory at / succeeds")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refused:
            await sftp.makedirs(b"/gantry-sftp-should-not-be-able-to-create-this")

    # **Which refusal the server gives is the server platform's, and this test is not about
    # that.** Linux answers `EACCES` and OpenSSH maps it to `PERMISSION_DENIED`; macOS keeps `/`
    # read-only under System Integrity Protection, so the errno differs and the same `mkdir`
    # arrives as the catch-all `FAILURE` -- which is what the first macOS CI run reported, as
    # `assert 4 == 3`. What this test exists to prove is the *terminating condition*: the guard
    # re-raises the server's own answer, naming the path the caller actually used, rather than
    # recursing toward an empty one. Both codes satisfy that; neither is a walk past the root.
    assert refused.value.code in {
        int(StatusCode.PERMISSION_DENIED),
        int(StatusCode.FAILURE),
    }, f"expected the server's own refusal, got {refused.value.code}"
    assert refused.value.path == b"/gantry-sftp-should-not-be-able-to-create-this"

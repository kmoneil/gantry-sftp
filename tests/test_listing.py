"""Directory listing: batches, dot entries, attribute honesty, and untrusted names.

The scripted server here exists to produce the things a real one will not on demand -- a
server that reports no permissions at all, a name that is not valid UTF-8, a READDIR that
stops with an error halfway through a listing. The real-``sftp-server`` tests at the bottom
supply what no fake can: what an actual server sends, in what batches, and with ``.`` and
``..`` in it.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import anyio
import pytest

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
from gantry_sftp.exceptions import NoSuchFileError, ProtocolError, ServerError
from gantry_sftp.session import (
    DirEntry,
    EntryKind,
    decode_name,
    entry_kind,
    open_session,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

DIRECTORY = 0o040755
REGULAR = 0o100644
SYMLINK = 0o120777
FIFO = 0o010644


# --- classifying an entry, which is pure --------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (DIRECTORY, EntryKind.DIRECTORY),
        (REGULAR, EntryKind.FILE),
        (SYMLINK, EntryKind.SYMLINK),
        (FIFO, EntryKind.OTHER),
    ],
)
def test_the_mode_bits_classify_the_entry(mode: int, expected: EntryKind):
    # v3 sends the whole st_mode, so the file-type bits arrive in `permissions` next to the
    # permission bits. 0o40755 is a directory, not a permission of 40755.
    assert entry_kind(Attrs(permissions=mode)) is expected


def test_an_entry_with_no_permissions_is_unknown_rather_than_a_file():
    """The trap this type exists to make unrepresentable.

    If a server sends no permissions -- and DESIGN.md 7 lists attribute honesty among the
    things real endpoints differ on -- then ``is_dir`` cannot be ``False``. That answer makes
    a recursive walk skip every directory on that server, silently, while still looking like
    it worked.
    """
    entry = DirEntry(b"mystery", b"mystery", Attrs())
    assert entry.kind is EntryKind.UNKNOWN
    assert not entry.is_dir
    assert not entry.is_file
    assert entry.size is None


@pytest.mark.parametrize(
    ("mode", "is_dir", "is_file", "is_symlink"),
    [
        (DIRECTORY, True, False, False),
        (REGULAR, False, True, False),
        (SYMLINK, False, False, True),
        (FIFO, False, False, False),
    ],
)
def test_the_convenience_predicates_agree_with_the_kind(
    mode: int, is_dir: bool, is_file: bool, is_symlink: bool
):
    entry = DirEntry(b"x", b"x", Attrs(permissions=mode))
    assert entry.is_dir is is_dir
    assert entry.is_file is is_file
    assert entry.is_symlink is is_symlink


def test_a_name_that_is_not_utf8_survives_being_decoded_and_re_encoded():
    # The files whose names are the reason you needed a listing are exactly the files you
    # must still be able to open afterwards.
    raw = b"caf\xe9-\xff.csv"
    entry = DirEntry(raw, b"", Attrs())
    assert entry.name == decode_name(raw)
    assert entry.name.encode("utf-8", "surrogateescape") == raw


def test_the_kinds_render_as_the_names_a_log_line_wants():
    assert str(EntryKind.DIRECTORY) == "directory"
    assert str(EntryKind.UNKNOWN) == "unknown"


# --- a server that serves directories ------------------------------------------------------


class ListingServer:
    """Scriptable in-process server with directories, batches, and misbehaviour.

    Batches matter more than anything else here: one READDIR is not a directory, and a server
    is free to answer with as many entries as it likes. A fake that returned everything at
    once would agree with a client that stops after the first reply.
    """

    def __init__(
        self,
        *,
        entries: tuple[NameEntry, ...] = (),
        batch: int = 2,
        refuse: dict[str, StatusCode] | None = None,
        fail_after: int | None = None,
    ) -> None:
        self.entries = entries
        self.batch = batch
        self.refuse = dict(refuse or {})
        self.fail_after = fail_after

        self.seen: list[object] = []
        self.position = 0
        self.batches_sent = 0
        self.open_handles: set[bytes] = set()
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

    def _reply(self, packet) -> None:
        self._outbox += encode(packet)
        self._has_output.set()

    def _refuse(self, packet, code: StatusCode) -> None:
        self._reply(Status(packet.request_id, code, code.name.encode("ascii")))

    def _dispatch(self, packet) -> None:
        self.seen.append(packet)
        if isinstance(packet, Init):
            self._reply(Version(3))
        elif isinstance(packet, OpenDir):
            self._on_opendir(packet)
        elif isinstance(packet, ReadDir):
            self._on_readdir(packet)
        elif isinstance(packet, Close):
            self.open_handles.discard(packet.handle)
            self._reply(Status(packet.request_id, StatusCode.OK))
        else:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))

    def _on_opendir(self, packet: OpenDir) -> None:
        if (refusal := self.refuse.get("opendir")) is not None:
            self._refuse(packet, refusal)
            return
        handle = b"d\x00\x00\x00"
        self.open_handles.add(handle)
        self._reply(Handle(packet.request_id, handle))

    def _on_readdir(self, packet: ReadDir) -> None:
        if (refusal := self.refuse.get("readdir")) is not None:
            self._refuse(packet, refusal)
            return
        if self.fail_after is not None and self.batches_sent >= self.fail_after:
            self._refuse(packet, StatusCode.FAILURE)
            return
        chunk = self.entries[self.position : self.position + self.batch]
        if not chunk:
            self._reply(Status(packet.request_id, StatusCode.EOF))
            return
        self.position += len(chunk)
        self.batches_sent += 1
        self._reply(Name(packet.request_id, chunk))


def entry(name: bytes, mode: int | None = REGULAR, size: int | None = 0) -> NameEntry:
    return NameEntry(name, b"-rw-r--r-- 1 me me 0 Jul 26 12:00 " + name, Attrs(size, None, mode))


# --- listing ---------------------------------------------------------------------------------


async def test_a_listing_follows_every_batch_to_the_end():
    """One READDIR is not a directory.

    OpenSSH caps a batch at 100 entries. A client that treats the first reply as the listing
    silently loses everything after the hundredth file -- and reports success.
    """
    names = [f"file{i:02d}.csv".encode() for i in range(7)]
    server = ListingServer(entries=tuple(entry(name) for name in names), batch=2)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        listing = await sftp.listdir("/incoming")

    assert [item.filename for item in listing] == names
    assert server.batches_sent == 4, "the batches were not all followed"


async def test_dot_and_dotdot_are_filtered_out():
    # Passing them on makes any recursion that follows directories loop forever, and it is
    # the caller who pays.
    server = ListingServer(
        entries=(
            entry(b".", DIRECTORY),
            entry(b"..", DIRECTORY),
            entry(b"real.csv"),
        ),
        batch=3,
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        listing = await sftp.listdir("/incoming")

    assert [item.filename for item in listing] == [b"real.csv"]


async def test_the_raw_batch_still_shows_what_the_server_sent():
    # readdir() is the escape hatch and the instrument: the filtering above is only testable
    # because one place shows the unfiltered truth.
    server = ListingServer(entries=(entry(b".", DIRECTORY), entry(b"x.csv")), batch=9)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.opendir("/incoming")
        batch = await sftp.readdir(handle)
        assert batch is not None
        assert [item.filename for item in batch] == [b".", b"x.csv"]
        assert await sftp.readdir(handle) is None, "EOF should end the iteration"
        await sftp.close(handle)


async def test_an_empty_directory_lists_as_nothing_rather_than_failing():
    # EOF on the very first READDIR is a normal empty directory, not an error.
    server = ListingServer(entries=())
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.listdir("/empty") == []


async def test_a_directory_of_only_dot_entries_lists_as_nothing():
    server = ListingServer(entries=(entry(b".", DIRECTORY), entry(b"..", DIRECTORY)))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.listdir("/empty") == []


async def test_attributes_come_with_the_listing_rather_than_a_stat_each():
    # v3 sends ATTRS with every entry. Discarding them forces a round trip per file, which is
    # why listing a large directory is slow in every paramiko-based tool.
    server = ListingServer(
        entries=(entry(b"a.csv", REGULAR, 1234), entry(b"sub", DIRECTORY, 4096)), batch=9
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        listing = await sftp.listdir("/incoming")

    assert [item.kind for item in listing] == [EntryKind.FILE, EntryKind.DIRECTORY]
    assert listing[0].size == 1234
    assert not any(isinstance(packet, Name) for packet in server.seen), "no STAT per entry"


async def test_a_listing_closes_the_handle_when_a_batch_fails():
    # A leaked directory handle counts against max-open-handles exactly like a file one, and
    # is just as invisible from this side.
    server = ListingServer(entries=tuple(entry(f"f{i}".encode()) for i in range(9)), fail_after=2)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.listdir("/incoming")

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"
    assert not server.open_handles, "the directory handle was leaked"


async def test_a_missing_directory_reports_no_such_file():
    server = ListingServer(refuse={"opendir": StatusCode.NO_SUCH_FILE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(NoSuchFileError) as exc:
            _ = await sftp.listdir("/absent")
    assert exc.value.path == b"/absent"


async def test_a_reply_of_the_wrong_type_to_readdir_is_a_protocol_error():
    class Confused(ListingServer):
        def _on_readdir(self, packet: ReadDir) -> None:
            self._reply(Handle(packet.request_id, b"nonsense"))

    server = Confused()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ProtocolError) as exc:
            _ = await sftp.listdir("/incoming")
    assert exc.value.args[0] == "server answered with Handle where NAME was expected"


async def test_names_are_carried_as_bytes_and_never_decoded_on_the_wire():
    # Server-supplied names are attacker-controlled and frequently not UTF-8. A listing that
    # decodes strictly cannot even report those files, let alone open them.
    raw = b"caf\xe9-\xff.csv"
    server = ListingServer(entries=(entry(raw),))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        listing = await sftp.listdir("/incoming")

    assert listing[0].filename == raw
    assert listing[0].name.encode("utf-8", "surrogateescape") == raw


async def test_a_hostile_name_is_surfaced_verbatim_rather_than_sanitised_here():
    """A server can put anything in a name, and the listing is not where that is decided.

    ``../../etc/cron.d/x`` is the zip-slip shape and it is a real, exploited pattern in
    file-transfer clients. Listing reports what the server said; the defence belongs where a
    remote name becomes a local path, which is recursive download, and it does not exist yet.
    Sanitising here would hide the attack from the layer that has to handle it.
    """
    hostile = (b"../../etc/passwd", b"a/b", b"", b"..\\..\\windows")
    server = ListingServer(entries=tuple(entry(name) for name in hostile), batch=9)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        listing = await sftp.listdir("/incoming")

    assert [item.filename for item in listing] == list(hostile)


# --- against a real server ---------------------------------------------------------------------


async def test_listing_a_real_directory(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    (tmp_path / "a.csv").write_bytes(b"one")
    (tmp_path / "b.csv").write_bytes(b"two hundred")
    (tmp_path / "sub").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "a.csv")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        listing = await sftp.listdir(str(tmp_path))

    by_name = {item.name: item for item in listing}
    assert set(by_name) == {"a.csv", "b.csv", "sub", "link"}
    assert by_name["a.csv"].kind is EntryKind.FILE
    assert by_name["a.csv"].size == 3
    assert by_name["sub"].kind is EntryKind.DIRECTORY
    # READDIR reports the link itself, not what it points at -- it is an LSTAT, not a STAT.
    assert by_name["link"].kind is EntryKind.SYMLINK


async def test_a_real_server_does_send_dot_and_dotdot(tmp_path: Path):
    """The filtering is not defensive programming: the reference server really sends both.

    Measured rather than assumed, because if it did not, the filter would be untested code
    protecting against nothing.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    (tmp_path / "only.csv").write_bytes(b"x")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.opendir(str(tmp_path))
        raw: list[bytes] = []
        while (batch := await sftp.readdir(handle)) is not None:
            raw.extend(item.filename for item in batch)
        await sftp.close(handle)

        filtered = await sftp.listdir(str(tmp_path))

    assert b"." in raw
    assert b".." in raw
    assert [item.filename for item in filtered] == [b"only.csv"]


async def test_a_real_directory_larger_than_one_batch(tmp_path: Path):
    """OpenSSH answers at most 100 entries per READDIR, so this needs several.

    The number is not asserted -- it is the server's business and it may change. What is
    asserted is that more than one batch was needed and every entry arrived, which is the
    property a client gets wrong.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    expected = {f"file{i:03d}.bin" for i in range(250)}
    for name in expected:
        (tmp_path / name).write_bytes(b"")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.opendir(str(tmp_path))
        batches = 0
        while await sftp.readdir(handle) is not None:
            batches += 1
        await sftp.close(handle)

        listing = await sftp.listdir(str(tmp_path))

    assert batches > 1, "the fixture is too small to prove batching"
    assert {item.name for item in listing} == expected


async def test_a_real_server_reports_a_name_that_is_not_valid_utf8(tmp_path: Path):
    """The axis that actually bites, varied rather than assumed away.

    A filename on Linux is bytes, not text. A client that decodes strictly cannot list this
    directory at all, and one that decodes lossily cannot open the file it just listed.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    raw_name = b"caf\xe9-\xff.bin"
    (tmp_path / os.fsdecode(raw_name)).write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        listing = await sftp.listdir(str(tmp_path))
        assert [item.filename for item in listing] == [raw_name]

        # And the name we got back is usable: sent as `str`, it must reach the same file.
        attributes = await sftp.stat(str(tmp_path).encode() + b"/" + listing[0].filename)
        assert attributes.size == 7
        by_decoded_name = await sftp.stat(f"{tmp_path}/{listing[0].name}")
        assert by_decoded_name.size == 7


async def test_opening_a_file_as_a_directory_reports_no_such_file_not_failure(tmp_path: Path):
    """Measured, and not what you would guess: ``ENOTDIR`` comes back as ``NO_SUCH_FILE``.

    So a path that plainly exists is reported as missing, and "not a directory" cannot be
    told from "not there" by status code alone. That is the server's mapping and it is
    carried through rather than second-guessed here -- inventing a friendlier error would
    mean asserting something we did not measure. It is a fact for the quirks layer, and the
    reason a recursive walk must not treat NO_SUCH_FILE from OPENDIR as proof of absence.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    target = tmp_path / "not-a-directory.txt"
    target.write_bytes(b"x")
    assert target.exists()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(NoSuchFileError) as exc:
            _ = await sftp.listdir(str(target))

    # OpenSSH's own words for it, carried through rather than replaced by ours.
    assert exc.value.code == int(StatusCode.NO_SUCH_FILE)
    assert exc.value.message == b"No such file"


async def test_the_permissions_a_real_server_sends_classify_correctly(tmp_path: Path):
    # Guards the mapping against the real bit layout rather than against our own constants:
    # the test above uses 0o040755 because that is what st_mode looks like, and this proves
    # the server agrees.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    (tmp_path / "sub").mkdir()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        listing = await sftp.listdir(str(tmp_path))

    entry_for_sub = next(item for item in listing if item.name == "sub")
    assert entry_for_sub.attrs.permissions is not None
    assert stat.S_ISDIR(entry_for_sub.attrs.permissions)

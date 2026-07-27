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
from gantry_sftp.exceptions import NoSuchFileError, ProtocolError, ServerError, StateError
from gantry_sftp.session import (
    DirEntry,
    EntryKind,
    Session,
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
        empty_name_after: int | None = None,
    ) -> None:
        self.entries = entries
        self.batch = batch
        self.refuse = dict(refuse or {})
        self.fail_after = fail_after
        # Answer with a NAME carrying zero names once this many batches have gone out, and
        # keep doing it. The draft says one or more; OpenSSH's server never sends one. A
        # client that reads it as "an empty batch, ask again" spins here forever.
        self.empty_name_after = empty_name_after

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
            if (refusal := self.refuse.get("close")) is not None:
                self._refuse(packet, refusal)
            else:
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
        if self.empty_name_after is not None and self.batches_sent >= self.empty_name_after:
            self.batches_sent += 1
            self._reply(Name(packet.request_id, ()))
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


# --- a NAME with no names in it -----------------------------------------------------------------
#
# The draft answers READDIR with "one or more names" and signals end of directory with a
# STATUS of EOF; OpenSSH's server never sends a zero-count NAME (`if (count > 0) send_names()
# else send_status(id, SSH2_FX_EOF)`). So one is a server bug either way, and the only
# question is how to fail on it. Reading it as "an empty batch, ask again" is a livelock --
# 100% CPU forever, in the operation every recursive transfer starts with. Refusing it would
# make this library stricter than `sftp(1)`, whose client does `if (count == 0) break;`.
# It ends the listing, matching the reference client.
#
# Every test here is wrapped in `fail_after`, because without the fix they do not fail --
# they hang, and a hanging test is a test nobody runs twice.

EMPTY_NAME_TIMEOUT = 10.0


async def test_a_name_with_no_names_in_it_ends_the_listing_rather_than_spinning():
    server = ListingServer(
        entries=tuple(entry(f"f{i}".encode()) for i in range(4)), batch=2, empty_name_after=2
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with anyio.fail_after(EMPTY_NAME_TIMEOUT):
            listing = await sftp.listdir("/incoming")

    assert [item.filename for item in listing] == [b"f0", b"f1", b"f2", b"f3"]
    assert not server.open_handles, "the directory handle was leaked"


async def test_an_empty_name_ends_a_stream_too():
    server = ListingServer(
        entries=tuple(entry(f"f{i}".encode()) for i in range(4)), batch=2, empty_name_after=2
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with anyio.fail_after(EMPTY_NAME_TIMEOUT):
            async with sftp.scandir("/incoming") as entries:
                streamed = [item async for item in entries]

    assert [item.filename for item in streamed] == [b"f0", b"f1", b"f2", b"f3"]


async def test_an_empty_name_on_the_very_first_readdir_is_an_empty_directory():
    # The shape a lazy server would produce for a directory with nothing in it: a NAME with
    # no names, where the draft wants an EOF status. Not an error, and not a hang.
    server = ListingServer(entries=(entry(b"unreachable"),), empty_name_after=0)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with anyio.fail_after(EMPTY_NAME_TIMEOUT):
            assert await sftp.listdir("/incoming") == []


async def test_readdir_reports_an_empty_name_as_the_end_rather_than_as_a_batch():
    # The raw surface makes the same call, because it is the one place that translates a
    # reply into "a batch, or the end" -- `Status(EOF)` already goes through it.
    server = ListingServer(entries=(entry(b"a.csv"),), empty_name_after=0)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.opendir("/incoming")
        assert await sftp.readdir(handle) is None
        await sftp.close(handle)


# --- streaming a directory ----------------------------------------------------------------------
#
# The point of scandir is a bound the *server* cannot choose. listdir follows every batch to
# the end, so a server willing to answer READDIR with new names forever makes the client
# allocate forever -- peer-driven memory exhaustion in a client that parses hostile input.
# These tests are about that bound and about the handle, not about the entries: the entries
# are listdir's tests above, and the two must agree.


async def test_scandir_asks_for_a_batch_only_when_the_last_one_is_used_up():
    """The whole claim, asserted rather than described.

    A client that read the directory up front and then handed out entries would pass every
    other test in this file and have exactly the memory shape scandir exists to remove. So
    the assertion is on the *server*: after one entry, one batch has been sent.
    """
    names = [f"file{i:02d}.csv".encode() for i in range(7)]
    server = ListingServer(entries=tuple(entry(name) for name in names), batch=2)
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.scandir("/incoming") as entries,
    ):
        iterator = aiter(entries)
        first = await anext(iterator)
        assert first.filename == names[0]
        assert server.batches_sent == 1, "the whole directory was read up front"

        # Second entry is already in hand: same batch, no round trip.
        _ = await anext(iterator)
        assert server.batches_sent == 1

        _ = await anext(iterator)
        assert server.batches_sent == 2, "the next batch was not fetched on demand"

    assert not server.open_handles


async def test_scandir_and_listdir_agree_on_what_a_directory_contains():
    # listdir is implemented on scandir, so this is the equivalence that lets there be one
    # batch-following loop in the library instead of two that drift.
    names = [f"file{i:02d}.csv".encode() for i in range(7)]
    server = ListingServer(
        entries=(entry(b".", DIRECTORY), *[entry(name) for name in names], entry(b"..", DIRECTORY)),
        batch=3,
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        listed = await sftp.listdir("/incoming")

    server.position = 0
    server.batches_sent = 0
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.scandir("/incoming") as entries,
    ):
        streamed = [item async for item in entries]

    assert [item.filename for item in streamed] == [item.filename for item in listed] == names


async def test_stopping_a_scan_early_closes_the_directory_handle():
    """Finding the first match and leaving is the reason to stream at all.

    A directory handle counts against the server's open-handle limit exactly like a file one
    and is just as invisible from this side, so the ``async with`` has to close it on the
    ``break`` -- which is why this is a context manager and not a bare async generator.
    """
    names = [f"file{i:02d}.csv".encode() for i in range(20)]
    server = ListingServer(entries=tuple(entry(name) for name in names), batch=2)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        async with sftp.scandir("/incoming") as entries:
            async for item in entries:
                if item.filename == b"file01.csv":
                    break

        assert not server.open_handles, "the directory handle was leaked on an early exit"
        assert server.batches_sent == 1, "the rest of the directory was read anyway"


async def test_an_exception_inside_the_loop_closes_the_handle_and_keeps_the_error():
    # The cleanup must not replace the diagnosis that is already on its way up: a caller
    # debugging their own error should not be handed a housekeeping complaint instead.
    async def fail_inside_the_loop(sftp: Session) -> None:
        async with sftp.scandir("/incoming") as entries:
            async for _item in entries:
                _ = 1 / 0

    server = ListingServer(entries=tuple(entry(f"f{i}".encode()) for i in range(9)), batch=2)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ZeroDivisionError) as exc:
            await fail_inside_the_loop(sftp)

        assert exc.value.args[0] == "division by zero"
        assert not server.open_handles


async def test_a_scan_that_fails_midway_closes_the_handle_and_reports_the_server_error():
    server = ListingServer(entries=tuple(entry(f"f{i}".encode()) for i in range(9)), fail_after=2)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            async with sftp.scandir("/incoming") as entries:
                _ = [item async for item in entries]

        assert exc.value.args[0] == "server returned FAILURE: FAILURE"
        assert not server.open_handles, "the directory handle was leaked"


async def test_a_close_that_fails_at_the_end_of_a_clean_scan_is_reported():
    # Not swallowed. Some servers report a failure on CLOSE rather than on the operation that
    # caused it, and a scan that ended cleanly has no other error to protect.
    server = ListingServer(entries=(entry(b"a.csv"),), refuse={"close": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            async with sftp.scandir("/incoming") as entries:
                _ = [item async for item in entries]

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"


async def test_dot_entries_are_filtered_out_of_a_stream_too():
    # Including the case where they are the only thing in a batch: the buffered-entry loop
    # has to ask for another batch rather than report end of directory.
    server = ListingServer(
        entries=(entry(b".", DIRECTORY), entry(b"..", DIRECTORY), entry(b"real.csv")), batch=2
    )
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.scandir("/incoming") as entries,
    ):
        streamed = [item async for item in entries]

    assert [item.filename for item in streamed] == [b"real.csv"]


async def test_an_empty_directory_streams_as_nothing():
    server = ListingServer(entries=())
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.scandir("/empty") as entries,
    ):
        assert [item async for item in entries] == []


async def test_a_directory_of_only_dot_entries_streams_as_nothing():
    server = ListingServer(entries=(entry(b".", DIRECTORY), entry(b"..", DIRECTORY)))
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.scandir("/empty") as entries,
    ):
        assert [item async for item in entries] == []


async def test_the_end_of_a_directory_is_latched_rather_than_re_asked():
    # An iterator driven past its end must not spend a round trip asking a server that has
    # already said EOF -- and a server that answered EOF once is not obliged to again.
    server = ListingServer(entries=(entry(b"a.csv"),), batch=9)
    async with (
        open_session(server) as sftp,  # type: ignore[arg-type]
        sftp.scandir("/incoming") as entries,
    ):
        iterator = aiter(entries)
        _ = await anext(iterator)
        with pytest.raises(StopAsyncIteration):
            _ = await anext(iterator)
        readdirs = sum(1 for packet in server.seen if isinstance(packet, ReadDir))

        with pytest.raises(StopAsyncIteration):
            _ = await anext(iterator)
        assert sum(1 for packet in server.seen if isinstance(packet, ReadDir)) == readdirs


async def test_a_missing_directory_is_reported_when_the_scan_is_entered():
    # The OPENDIR happens in __aenter__, so the error arrives at the `async with` rather than
    # at the first `async for` -- which is where a caller's try/except will be.
    server = ListingServer(refuse={"opendir": StatusCode.NO_SUCH_FILE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(NoSuchFileError) as exc:
            async with sftp.scandir("/absent"):
                pytest.fail("the body must not run")

    assert exc.value.path == b"/absent"


# --- misusing a scan, which has to fail loudly rather than leak --------------------------------


async def test_iterating_a_scan_that_was_never_entered_is_refused():
    """The misuse the context manager exists to prevent, made an error rather than a leak.

    ``async for entry in sftp.scandir(p)`` without the ``async with`` is the spelling a
    caller will try first, and supporting it would hold a directory handle open with nothing
    responsible for closing it.
    """

    async def iterate_without_entering(sftp: Session) -> None:
        async for _item in sftp.scandir("/incoming"):
            pytest.fail("iteration must not start")

    server = ListingServer(entries=(entry(b"a.csv"),))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(StateError) as exc:
            await iterate_without_entering(sftp)

    assert exc.value.args[0] == "scandir() must be entered with `async with` before iterating"
    assert not server.open_handles


async def test_iterating_a_scan_after_its_block_has_ended_is_refused():
    # The handle is gone, so the honest answer is an error rather than the entries that
    # happened to be buffered when the block exited.
    server = ListingServer(entries=tuple(entry(f"f{i}".encode()) for i in range(9)), batch=4)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        async with sftp.scandir("/incoming") as entries:
            iterator = aiter(entries)
            _ = await anext(iterator)

        with pytest.raises(StateError) as exc:
            _ = await anext(iterator)

    assert exc.value.args[0] == "this scandir() is closed; its `async with` block has ended"


async def test_a_scan_cannot_be_entered_twice():
    # One scan is one handle. Re-entering would silently restart the listing, which reads as
    # a duplicate-entries bug somewhere else entirely.
    server = ListingServer(entries=(entry(b"a.csv"),))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        scan = sftp.scandir("/incoming")
        async with scan:
            pass

        with pytest.raises(StateError) as exc:
            async with scan:
                pytest.fail("the body must not run")

    assert exc.value.args[0] == "this scandir() has already been used; call scandir() again"
    assert not server.open_handles


async def test_a_scan_says_which_state_it_is_in():
    # The library has to keep telling the truth about itself: a scan in a debugger or a log
    # line should say whether it is holding a handle.
    server = ListingServer(entries=(entry(b"a.csv"),))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        scan = sftp.scandir(b"/incoming")
        assert repr(scan) == "<DirectoryScan b'/incoming' unopened>"
        async with scan:
            assert repr(scan) == "<DirectoryScan b'/incoming' open>"
        assert repr(scan) == "<DirectoryScan b'/incoming' spent>"


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


async def test_streaming_a_real_directory_larger_than_one_batch(tmp_path: Path):
    """What no fake can prove: a real server's batching, streamed.

    The fake chooses its batch size; OpenSSH chooses its own, and this is the only place the
    two are made to agree. The count is not asserted -- it is the server's business -- only
    that more than one batch was needed and that nothing was lost between them.
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
        async with sftp.scandir(str(tmp_path)) as entries:
            streamed = {item.name async for item in entries}

        # And the same directory the accumulating way, which must not disagree.
        assert {item.name for item in await sftp.listdir(str(tmp_path))} == streamed

    assert streamed == expected


async def test_a_real_server_answers_a_stat_from_inside_an_open_directory_scan(tmp_path: Path):
    """The constraint that shaped this API, and the one that turned out to be void.

    A streaming listing that held the session while suspended would deadlock any caller who
    used it the obvious way -- ``stat`` each entry as it arrives, which is what a walk does.
    The session lock that would have caused it is gone, so this is a proof that the hazard
    stayed gone: interleaving STAT with READDIR on one connection, against a real server that
    has to be willing to answer that way.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    for index in range(120):  # more than one OpenSSH batch, so the interleave spans READDIRs
        (tmp_path / f"file{index:03d}.bin").write_bytes(b"x" * index)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        sizes: dict[str, int | None] = {}
        with anyio.fail_after(60):  # a deadlock must fail this test, not hang the suite
            async with sftp.scandir(str(tmp_path)) as entries:
                async for item in entries:
                    attributes = await sftp.stat(f"{tmp_path}/{item.name}")
                    sizes[item.name] = attributes.size

    assert len(sizes) == 120
    assert sizes["file042.bin"] == 42


async def test_a_real_server_tolerates_a_scan_abandoned_mid_directory(tmp_path: Path):
    """Stopping mid-listing, repeatedly, against a server that keeps real state.

    The *leak* is caught upstairs by the fake, which can see its own handle table; nothing
    here can observe `sftp-server`'s. What this proves is the half a fake cannot: that closing
    a directory handle with batches still unread is something the reference server accepts,
    over and over, and that the connection is unaffected afterwards. A CLOSE mid-READDIR is
    not obviously fine -- it is fine because OpenSSH says so, which is why it is measured.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    for index in range(150):  # several real batches, so every scan leaves some unread
        (tmp_path / f"file{index:03d}.bin").write_bytes(b"")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        for _attempt in range(50):
            async with sftp.scandir(str(tmp_path)) as entries:
                async for item in entries:
                    assert item.name.startswith("file")
                    break

        assert len(await sftp.listdir(str(tmp_path))) == 150


async def test_a_real_server_reports_a_non_utf8_name_through_a_scan_too(tmp_path: Path):
    # The axis that bites, varied on the streaming path as well: a name is bytes on both.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    raw_name = b"caf\xe9-\xff.bin"
    (tmp_path / os.fsdecode(raw_name)).write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        async with sftp.scandir(str(tmp_path)) as entries:
            streamed = [item async for item in entries]

        assert [item.filename for item in streamed] == [raw_name]
        attributes = await sftp.stat(str(tmp_path).encode() + b"/" + streamed[0].filename)

    assert attributes.size == 7


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

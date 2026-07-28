"""Walking a tree, and downloading one from a server that may be lying.

The scripted server here is the point. A real ``sftp-server`` will not hand back
``../../etc/passwd`` as a filename however you ask it, and that is exactly the case the
recursive download exists to survive -- so the hostile cases are scripted and the honest ones
are run against a real server, and neither substitutes for the other.
"""

from __future__ import annotations

import os
from contextlib import aclosing
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
    MkDir,
    Name,
    NameEntry,
    Open,
    OpenDir,
    Read,
    ReadDir,
    RealPath,
    Remove,
    RmDir,
    Stat,
    Status,
    StatusCode,
    Version,
    decode,
    encode,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    DestinationCollisionError,
    NoSuchFileError,
    ServerError,
    UnsafePathError,
)
from gantry_sftp.session import (
    EntryKind,
    SkipReason,
    TreeResult,
    join_remote,
    open_session,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

DIRECTORY = 0o040755
REGULAR = 0o100644
SYMLINK = 0o120777
FIFO = 0o010644


# --- remote path joining, which is pure ----------------------------------------------------


@pytest.mark.parametrize(
    ("parent", "name", "expected"),
    [
        (b"/incoming", b"a.csv", b"/incoming/a.csv"),
        (b"/incoming/", b"a.csv", b"/incoming/a.csv"),
        (b"/", b"a.csv", b"/a.csv"),
        (b"", b"a.csv", b"a.csv"),
        (b"relative/dir", b"a.csv", b"relative/dir/a.csv"),
    ],
)
def test_remote_paths_join_with_a_slash(parent: bytes, name: bytes, expected: bytes):
    # Never os.path.join: on a Windows *client* that joins with a backslash and produces a
    # path no SFTP server understands. The separator belongs to the protocol.
    assert join_remote(parent, name) == expected


def test_a_tree_result_says_whether_anything_was_skipped():
    assert TreeResult(files=3, directories=1, transferred=99).complete
    assert not TreeResult(skipped=("something",)).complete  # type: ignore[arg-type]


# --- a server with a tree ---------------------------------------------------------------------


class TreeServer:
    """Scriptable server holding a whole directory tree, including dishonest ones.

    ``tree`` maps a directory path to its entries; ``files`` maps a file path to its content.
    Anything not in either is absent. Entries are returned in one batch because batching is
    :mod:`tests.test_listing`'s subject -- here the interesting variable is what the names
    *are*.
    """

    def __init__(
        self,
        *,
        tree: dict[bytes, tuple[NameEntry, ...]],
        files: dict[bytes, bytes] | None = None,
        refuse: dict[str, StatusCode] | None = None,
        others: set[bytes] | None = None,
        opaque: set[bytes] | None = None,
        root: bytes = b"/home/user",
    ) -> None:
        self.tree = dict(tree)
        # What REALPATH of b"." answers. A value not starting with b"/" is a server whose
        # namespace is not the one this library's path arithmetic assumes -- VMS, an MVS
        # dataset name -- which is the axis D-77 exists to vary.
        self.root = root
        self.files = dict(files or {})
        self.refuse = dict(refuse or {})
        # Paths that exist and are not regular files: symlinks, fifos, and entries the
        # server declines to describe. REMOVE unlinks them; nothing may descend into one.
        self.others = set(others or ())
        # Paths this server will not describe: STAT and LSTAT answer with no permissions at
        # all, whatever the entry really is. The shape that makes UNKNOWN more than a
        # theoretical member of the enum.
        self.opaque = set(opaque or ())

        self.seen: list[object] = []
        self.open_handles: set[bytes] = set()
        self._next_handle = 0
        self._handles: dict[bytes, bytes] = {}
        self._exhausted: set[bytes] = set()
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

    def _handle_for(self, path: bytes) -> bytes:
        handle = self._next_handle.to_bytes(4, "big")
        self._next_handle += 1
        self._handles[handle] = path
        self.open_handles.add(handle)
        return handle

    def _attrs_for(self, path: bytes) -> Attrs | None:
        if path in self.opaque:
            return Attrs()
        if path in self.tree:
            return Attrs(size=4096, permissions=DIRECTORY)
        if path in self.files:
            return Attrs(size=len(self.files[path]), permissions=REGULAR)
        return None

    def _forget(self, path: bytes) -> None:
        """Drop ``path`` from its parent's listing, so a later READDIR agrees it is gone.

        Without this the fake could not falsify anything: a removal in the wrong order would
        still leave every parent reporting itself empty, and the bottom-up guarantee would be
        asserted only against the client's own idea of what it did.
        """
        parent, _, name = path.rpartition(b"/")
        parent = parent or b"/"
        if parent in self.tree:
            self.tree[parent] = tuple(e for e in self.tree[parent] if e.filename != name)

    def _dispatch(self, packet) -> None:
        self.seen.append(packet)
        handlers = {
            Init: self._on_init,
            OpenDir: self._on_opendir,
            ReadDir: self._on_readdir,
            Open: self._on_open,
            Read: self._on_read,
            Close: self._on_close,
            Stat: self._on_stat,
            LStat: self._on_stat,
            Remove: self._on_remove,
            RmDir: self._on_rmdir,
            RealPath: self._on_realpath,
        }
        handler = handlers.get(type(packet))
        if handler is None:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))
            return
        handler(packet)

    def _on_init(self, packet: Init) -> None:
        self._reply(Version(3))

    def _on_realpath(self, packet: RealPath) -> None:
        self._reply(Name(packet.request_id, (NameEntry(self.root, self.root, Attrs()),)))

    def _on_opendir(self, packet: OpenDir) -> None:
        if (refusal := self.refuse.get("opendir")) is not None:
            self._reply(Status(packet.request_id, refusal, refusal.name.encode("ascii")))
        elif packet.path in self.tree:
            self._reply(Handle(packet.request_id, self._handle_for(packet.path)))
        else:
            # What a real server answers for a plain file too: ENOTDIR is remapped.
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))

    def _on_readdir(self, packet: ReadDir) -> None:
        path = self._handles[packet.handle]
        if packet.handle in self._exhausted:
            self._reply(Status(packet.request_id, StatusCode.EOF))
            return
        self._exhausted.add(packet.handle)
        self._reply(Name(packet.request_id, self.tree[path]))

    def _on_open(self, packet: Open) -> None:
        if packet.filename not in self.files:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
            return
        self._reply(Handle(packet.request_id, self._handle_for(packet.filename)))

    def _on_read(self, packet: Read) -> None:
        content = self.files[self._handles[packet.handle]]
        chunk = content[packet.offset : packet.offset + packet.length]
        if chunk:
            self._reply(Data(packet.request_id, memoryview(chunk)))
        else:
            self._reply(Status(packet.request_id, StatusCode.EOF))

    def _on_close(self, packet: Close) -> None:
        self.open_handles.discard(packet.handle)
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_stat(self, packet) -> None:
        attrs = self._attrs_for(packet.path)
        if attrs is None:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        else:
            self._reply(AttrsReply(packet.request_id, attrs))

    def _on_remove(self, packet: Remove) -> None:
        """``unlink(2)``: deletes a name, and refuses a directory.

        The refusal is the behaviour ``rmtree``'s safety argument rests on, so the fake
        implements it rather than accepting everything.
        """
        if packet.path in self.tree:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"Is a directory"))
            return
        if packet.path in self.files:
            del self.files[packet.path]
        elif packet.path in self.others:
            self.others.discard(packet.path)
        else:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
            return
        self._forget(packet.path)
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_rmdir(self, packet: RmDir) -> None:
        """``rmdir(2)``: refuses anything still holding entries."""
        if packet.path not in self.tree:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
            return
        if self.tree[packet.path]:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"Directory not empty"))
            return
        del self.tree[packet.path]
        self._forget(packet.path)
        self._reply(Status(packet.request_id, StatusCode.OK))


async def first_entry(sftp, root: bytes = b"/root"):
    """The first directory a walk reports, with the generator closed properly.

    `aclosing` rather than dropping the generator: a suspended async generator left to the
    garbage collector is not finalised by trio, and surfaces as an ignored exception at some
    unrelated point later. The library documents this idiom, so the tests use it.
    """
    async with aclosing(sftp.walk(root)) as walker:
        return await anext(aiter(walker))


def named(name: bytes, mode: int | None = REGULAR, size: int = 0) -> NameEntry:
    return NameEntry(name, b"longname " + name, Attrs(size, None, mode))


SIMPLE_TREE = {
    b"/root": (named(b"a.csv", REGULAR, 3), named(b"sub", DIRECTORY), named(b"link", SYMLINK)),
    b"/root/sub": (named(b"b.csv", REGULAR, 5), named(b"deeper", DIRECTORY)),
    b"/root/sub/deeper": (named(b"c.csv", REGULAR, 7),),
}
SIMPLE_FILES = {
    b"/root/a.csv": b"aaa",
    b"/root/sub/b.csv": b"bbbbb",
    b"/root/sub/deeper/c.csv": b"ccccccc",
}


# --- walking ------------------------------------------------------------------------------------


async def test_a_walk_visits_every_directory_top_down():
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        visited = [entry async for entry in sftp.walk(b"/root")]

    assert [entry.path for entry in visited] == [b"/root", b"/root/sub", b"/root/sub/deeper"]
    assert [entry.relative for entry in visited] == [(), (b"sub",), (b"sub", b"deeper")]
    assert [item.filename for item in visited[0].files] == [b"a.csv"]
    assert [item.filename for item in visited[0].directories] == [b"sub"]


async def test_a_symlink_is_reported_and_not_followed():
    # Following one needs loop detection, which needs a REALPATH per directory to defend
    # against something only a hostile or misconfigured server does. Absent rather than
    # half-built -- and surfaced, so a caller can decide for themselves.
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        root = await first_entry(sftp)

    assert [skip.entry.filename for skip in root.skipped] == [b"link"]
    assert root.skipped[0].reason == SkipReason.SYMLINK
    assert root.skipped[0].path == b"/root/link"


async def test_an_entry_that_is_neither_a_file_nor_a_directory_is_skipped_with_a_reason():
    server = TreeServer(tree={b"/root": (named(b"pipe", FIFO),)})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        root = await first_entry(sftp)

    assert root.files == ()
    assert root.skipped[0].reason == SkipReason.NOT_A_FILE


async def test_an_entry_with_no_attributes_costs_one_lstat_and_is_then_correct():
    """The server that sends no permissions, which is why ``UNKNOWN`` exists.

    Guessing "file" here makes the walk skip a real directory silently; guessing "directory"
    makes it try to list a file. One LSTAT settles it, and only for the entries that need it,
    so a server that sends attributes pays nothing.
    """
    tree = {
        b"/root": (named(b"sub", None), named(b"a.csv", None)),
        b"/root/sub": (named(b"inner.csv", REGULAR, 2),),
    }
    server = TreeServer(tree=tree, files={b"/root/a.csv": b"aa", b"/root/sub/inner.csv": b"ii"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        visited = [entry async for entry in sftp.walk(b"/root")]

    assert [entry.path for entry in visited] == [b"/root", b"/root/sub"]
    assert [item.filename for item in visited[0].files] == [b"a.csv"]
    assert sum(isinstance(packet, LStat) for packet in server.seen) == 2


async def test_the_settling_lstat_is_issued_while_the_directory_is_still_open():
    """The seam that changed when the walk started streaming, pinned.

    ``_walk_one`` used to accumulate the whole directory with ``listdir`` and *then* classify
    it, so every LSTAT arrived after the CLOSE. It now classifies as entries stream in, which
    puts a second operation on the connection inside an open directory handle -- legal only
    because a session multiplexes, and a deadlock again the moment anything reintroduces a
    lock. Ordering is asserted rather than described, since the fake cannot deadlock.
    """
    tree = {b"/root": (named(b"mystery", None), named(b"a.csv", REGULAR, 2))}
    server = TreeServer(tree=tree, files={b"/root/a.csv": b"aa"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await first_entry(sftp)

    kinds = [type(packet) for packet in server.seen]
    assert kinds.index(LStat) < kinds.index(Close), "the directory was closed before the LSTAT"


async def test_an_entry_the_server_will_not_describe_at_all_is_skipped_rather_than_guessed():
    # Attributes absent *and* the LSTAT refused. Two failures to answer is not evidence of
    # anything, so it is skipped with a reason rather than sorted into a bucket by guess.
    tree = {b"/root": (named(b"mystery", None),)}
    server = TreeServer(tree=tree)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        root = await first_entry(sftp)

    assert root.files == ()
    assert root.directories == ()
    assert root.skipped[0].reason == SkipReason.UNKNOWN_KIND


async def test_max_depth_stops_the_descent_and_says_so():
    # The only defence against a tree that is infinite because the server says it is.
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        visited = [entry async for entry in sftp.walk(b"/root", max_depth=1)]

    assert [entry.path for entry in visited] == [b"/root", b"/root/sub"]
    assert [skip.reason for skip in visited[1].skipped] == [SkipReason.TOO_DEEP]


async def test_max_depth_zero_lists_the_root_and_nothing_else():
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        visited = [entry async for entry in sftp.walk(b"/root", max_depth=0)]

    assert [entry.path for entry in visited] == [b"/root"]
    assert [item.filename for item in visited[0].files] == [b"a.csv"]


async def test_abandoning_a_walk_early_leaks_no_handles():
    """Stopping as soon as you find what you wanted is the natural way to use a walk.

    Nothing server-side is held between yields -- each directory's handle is opened and closed
    inside one scandir -- so an abandoned iterator needs no ``aclosing`` and leaks nothing.
    """
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        walker = sftp.walk(b"/root")
        _ = await anext(aiter(walker))
        await walker.aclose()

    assert not server.open_handles


async def test_walking_a_missing_directory_reports_no_such_file():
    server = TreeServer(tree=SIMPLE_TREE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(NoSuchFileError):
            _ = [entry async for entry in sftp.walk(b"/absent")]


# --- recursive download -------------------------------------------------------------------------


async def test_a_tree_is_downloaded_with_its_shape_intact(tmp_path: Path):
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", tmp_path / "out")

    root = tmp_path / "out"
    assert (root / "a.csv").read_bytes() == b"aaa"
    assert (root / "sub" / "b.csv").read_bytes() == b"bbbbb"
    assert (root / "sub" / "deeper" / "c.csv").read_bytes() == b"ccccccc"
    assert result.files == 3
    assert result.directories == 2
    assert result.transferred == 15


async def test_the_result_names_what_it_skipped_rather_than_counting_it(tmp_path: Path):
    # "It worked" and "it worked, and here is what it did not do" are different reports, and
    # a recursive download that quietly ignores every symlink quietly loses data.
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", tmp_path / "out")

    assert not result.complete
    assert [skip.path for skip in result.skipped] == [b"/root/link"]
    assert result.skipped[0].reason == SkipReason.SYMLINK
    assert not (tmp_path / "out" / "link").exists()


async def test_an_empty_tree_still_creates_the_destination(tmp_path: Path):
    server = TreeServer(tree={b"/root": ()})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", tmp_path / "out")

    assert (tmp_path / "out").is_dir()
    assert result == TreeResult(files=0, directories=0, transferred=0, skipped=())
    assert result.complete


# --- the attack ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [b"../../etc/cron.d/x", b"/etc/passwd", b"sub/../../escape", b"", b"a/b"],
)
async def test_a_traversing_filename_is_refused_and_nothing_is_written(
    tmp_path: Path, hostile: bytes
):
    """The zip-slip, at the layer that has to survive it.

    A malicious or compromised server chooses these names. Nothing is written -- not the
    escaping file, and not the sibling that would have followed it -- and the error names the
    file rather than failing somewhere confusing later.
    """
    tree = {b"/root": (named(hostile, REGULAR, 4),)}
    server = TreeServer(tree=tree, files={join_remote(b"/root", hostile): b"evil"})
    destination = tmp_path / "out"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsafePathError) as exc:
            _ = await sftp.get_tree(b"/root", destination)

    assert exc.value.name == hostile
    assert list(destination.iterdir()) == [], "something was written despite the refusal"
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path.parent / "escape").exists()


async def test_a_traversing_directory_name_is_refused_before_it_is_created(tmp_path: Path):
    # The same attack one level up: the escaping name is a directory, so the mkdir is what
    # would have escaped rather than the write.
    tree = {
        b"/root": (named(b"../escape", DIRECTORY),),
        b"/root/../escape": (named(b"loot.csv", REGULAR, 4),),
    }
    server = TreeServer(tree=tree, files={b"/root/../escape/loot.csv": b"evil"})
    destination = tmp_path / "out"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsafePathError) as exc:
            _ = await sftp.get_tree(b"/root", destination)

    assert exc.value.name == b"../escape"
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "loot.csv").exists()


@pytest.mark.parametrize("dotted", [b"..", b"."])
async def test_a_dot_entry_never_reaches_the_path_check_at_all(tmp_path: Path, dotted: bytes):
    """Two layers, and this is the outer one -- which is there for a different reason.

    ``.`` and ``..`` are filtered by the listing so that recursion terminates, not as a
    security measure. But they are also the most obvious traversal names, so a server sending
    one as an ordinary entry finds it dropped before the path check ever sees it. The check
    still refuses them (:mod:`tests.test_localpath`); neither layer is relied on alone.
    """
    tree = {b"/root": (named(dotted, DIRECTORY),), b"/root/" + dotted: ()}
    server = TreeServer(tree=tree)
    destination = tmp_path / "out"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", destination)

    assert result == TreeResult(), "a dot entry was treated as a real entry"
    assert list(destination.iterdir()) == []


async def test_a_symlinked_destination_directory_cannot_be_written_through(tmp_path: Path):
    """Every name innocent, and the escape happens anyway.

    ``sub`` is already a symlink out of the destination -- planted locally, or left by an
    earlier download. Component validation cannot see it; resolving the finished path can.
    """
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    destination = tmp_path / "out"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "sub").symlink_to(outside)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsafePathError) as exc:
            _ = await sftp.get_tree(b"/root", destination)

    assert exc.value.reason == "a path that escapes the destination directory"
    assert list(outside.iterdir()) == [], "the download escaped into the link's target"


async def test_a_file_that_is_a_symlink_out_is_not_written_through(tmp_path: Path):
    # The narrow version: the destination *file* is the link. The containment check catches
    # it before the open, and O_NOFOLLOW is the second lock on the same door.
    server = TreeServer(tree={b"/root": (named(b"a.csv", REGULAR, 3),)}, files=SIMPLE_FILES)
    destination = tmp_path / "out"
    destination.mkdir()
    secret = tmp_path / "secret"
    secret.write_bytes(b"original")
    (destination / "a.csv").symlink_to(secret)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsafePathError):
            _ = await sftp.get_tree(b"/root", destination)

    assert secret.read_bytes() == b"original"


async def test_no_follow_refuses_a_single_get_through_a_local_symlink(tmp_path: Path):
    # The flag on its own, without the tree: proof that O_NOFOLLOW is actually applied and
    # not merely passed around.
    server = TreeServer(tree={b"/root": ()}, files={b"/root/a.csv": b"aaa"})
    secret = tmp_path / "secret"
    secret.write_bytes(b"original")
    link = tmp_path / "link.csv"
    link.symlink_to(secret)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(OSError):
            _ = await sftp.get(b"/root/a.csv", link, no_follow=True)
        assert secret.read_bytes() == b"original"

        # And without the flag the same call goes through, which is what makes it a flag.
        _ = await sftp.get(b"/root/a.csv", link)
    assert secret.read_bytes() == b"aaa"


# --- recursive removal -----------------------------------------------------------------------


def removals(server: TreeServer) -> list[tuple[str, bytes]]:
    """Every removal the server was asked for, in order and with its kind."""
    return [
        (type(packet).__name__, packet.path)
        for packet in server.seen
        if isinstance(packet, (Remove, RmDir))
    ]


async def test_rmtree_removes_children_before_their_parents():
    # The whole ordering requirement, and the fake can falsify it: RMDIR on a directory that
    # still holds entries is refused, exactly as rmdir(2) refuses one.
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES, others={b"/root/link"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.rmtree(b"/root")

    assert removals(server) == [
        ("Remove", b"/root/sub/deeper/c.csv"),
        ("RmDir", b"/root/sub/deeper"),
        ("Remove", b"/root/sub/b.csv"),
        ("RmDir", b"/root/sub"),
        ("Remove", b"/root/a.csv"),
        ("Remove", b"/root/link"),
        ("RmDir", b"/root"),
    ]
    assert server.tree == {}
    assert result.files == 4
    assert result.directories == 3
    assert result.transferred == 0
    assert result.complete


async def test_rmtree_unlinks_a_symlink_rather_than_descending_into_it():
    # A symlink is what a walk *skips*; a removal has to delete it or the parent will not go.
    # Deleting the link and not what it points at is REMOVE's semantics, and it is why a
    # recursive delete cannot reach outside the tree it was given.
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES, others={b"/root/link"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.rmtree(b"/root")

    assert ("Remove", b"/root/link") in removals(server)
    assert not any(
        isinstance(packet, OpenDir) and packet.path == b"/root/link" for packet in server.seen
    )


async def test_rmtree_unlinks_an_entry_the_server_would_not_describe():
    # Attributes absent and the LSTAT refused. The walk refuses to call it a directory, so
    # nothing descends into it -- and REMOVE is safe on it precisely because unlink refuses a
    # directory, so the guess can only fail in the direction that raises.
    tree = {b"/root": (named(b"a.csv", REGULAR, 3), named(b"mystery", None))}
    server = TreeServer(tree=tree, files={b"/root/a.csv": b"aaa"}, others={b"/root/mystery"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.rmtree(b"/root")

    assert removals(server) == [
        ("Remove", b"/root/a.csv"),
        ("Remove", b"/root/mystery"),
        ("RmDir", b"/root"),
    ]
    assert result.files == 2


async def test_an_unknown_entry_that_is_really_a_directory_stops_the_removal():
    # The safety net stated as a test: a server that will not describe an entry which is in
    # fact a directory gets a REMOVE, and unlink refuses it. Nothing was descended into and
    # nothing below it was touched -- the failure names the exact path.
    tree = {
        b"/root": (named(b"liar", None),),
        b"/root/liar": (named(b"hidden.csv", REGULAR, 1),),
    }
    server = TreeServer(tree=tree, files={b"/root/liar/hidden.csv": b"h"}, opaque={b"/root/liar"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            await sftp.rmtree(b"/root")

    assert exc.value.path == b"/root/liar"
    assert not any(
        isinstance(packet, OpenDir) and packet.path == b"/root/liar" for packet in server.seen
    ), "nothing descended into an entry the server would not call a directory"
    assert exc.value.args[0] == "server returned FAILURE: Is a directory"
    assert server.files == {b"/root/liar/hidden.csv": b"h"}, "nothing below it was touched"


async def test_rmtree_removes_a_single_empty_directory():
    server = TreeServer(tree={b"/root": ()})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.rmtree(b"/root")

    assert removals(server) == [("RmDir", b"/root")]
    assert (result.files, result.directories) == (0, 1)


async def test_rmtree_on_a_missing_tree_raises_rather_than_reporting_nothing():
    server = TreeServer(tree={b"/root": ()})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(NoSuchFileError):
            await sftp.rmtree(b"/absent")


async def test_rmdir_refuses_a_directory_that_is_not_empty():
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            await sftp.rmdir(b"/root")
    assert exc.value.args[0] == "server returned FAILURE: Directory not empty"
    assert exc.value.path == b"/root"


# --- against a real server -----------------------------------------------------------------------


def build_tree(root: Path) -> None:
    """A tree with the shapes that make a recursive download interesting."""
    (root / "top.csv").write_bytes(b"top")
    (root / "sub").mkdir()
    (root / "sub" / "nested.bin").write_bytes(os.urandom(200_000))
    (root / "sub" / "deeper").mkdir()
    (root / "sub" / "deeper" / "leaf.txt").write_bytes(b"leaf")
    (root / "sub" / "link.csv").symlink_to(root / "top.csv")
    # A name that is not valid UTF-8, which is ordinary on Linux.
    (root / os.fsdecode(b"caf\xe9.bin")).write_bytes(b"\xe9\xe9")


async def test_downloading_a_real_tree(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "remote"
    source.mkdir()
    build_tree(source)
    destination = tmp_path / "local"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.get_tree(str(source), destination)

    assert (destination / "top.csv").read_bytes() == b"top"
    assert (destination / "sub" / "nested.bin").read_bytes() == (
        source / "sub" / "nested.bin"
    ).read_bytes()
    assert (destination / "sub" / "deeper" / "leaf.txt").read_bytes() == b"leaf"
    assert (destination / os.fsdecode(b"caf\xe9.bin")).read_bytes() == b"\xe9\xe9"

    assert result.files == 4
    assert result.directories == 2
    # The symlink is reported rather than copied or followed.
    assert [Path(os.fsdecode(skip.path)).name for skip in result.skipped] == ["link.csv"]
    assert not (destination / "sub" / "link.csv").exists()


async def test_a_real_walk_reports_the_kinds_the_server_gave_it(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "remote"
    source.mkdir()
    build_tree(source)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        visited = [entry async for entry in sftp.walk(str(source))]

    directories = {Path(os.fsdecode(entry.path)).name for entry in visited}
    assert directories == {"remote", "sub", "deeper"}
    root = next(entry for entry in visited if entry.relative == ())
    assert {item.kind for item in root.files} == {EntryKind.FILE}


async def test_a_real_tree_download_is_byte_identical_and_repeatable(tmp_path: Path):
    # Running it twice over the same destination must converge rather than accumulate: the
    # second pass rewrites the same files, and mkdir must not fail on what is already there.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "remote"
    source.mkdir()
    build_tree(source)
    destination = tmp_path / "local"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        first = await sftp.get_tree(str(source), destination)
        second = await sftp.get_tree(str(source), destination)

    assert first.files == second.files
    assert first.transferred == second.transferred
    assert (destination / "sub" / "deeper" / "leaf.txt").read_bytes() == b"leaf"


async def test_mkdir_on_a_real_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.mkdir(str(tmp_path / "fresh"))
        assert (tmp_path / "fresh").is_dir()

        # v3 answers a repeat with the catch-all FAILURE, so "already there" can only be
        # told from "refused" by looking -- which is what exist_ok does.
        with pytest.raises(Exception) as exc:
            await sftp.mkdir(str(tmp_path / "fresh"))
        assert exc.value.code == int(StatusCode.FAILURE)  # type: ignore[attr-defined]

        await sftp.mkdir(str(tmp_path / "fresh"), exist_ok=True)

        # And exist_ok does not excuse a *file* of the same name, which is a different
        # problem wearing the same status.
        (tmp_path / "afile").write_bytes(b"x")
        with pytest.raises(Exception):  # noqa: B017 -- any refusal, and it must refuse
            await sftp.mkdir(str(tmp_path / "afile"), exist_ok=True)


async def test_uploading_a_real_tree(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "local"
    source.mkdir()
    build_tree(source)
    destination = tmp_path / "remote"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put_tree(source, str(destination))

    assert (destination / "top.csv").read_bytes() == b"top"
    assert (destination / "sub" / "nested.bin").read_bytes() == (
        source / "sub" / "nested.bin"
    ).read_bytes()
    assert (destination / "sub" / "deeper" / "leaf.txt").read_bytes() == b"leaf"
    assert (destination / os.fsdecode(b"caf\xe9.bin")).read_bytes() == b"\xe9\xe9"

    assert result.files == 4
    assert result.directories == 2
    assert result.transferred == 200_000 + len(b"top") + len(b"leaf") + 2
    # The symlink is reported rather than followed and copied -- the exfiltration shape,
    # going this way: a link to /etc/shadow would otherwise arrive under an innocent name.
    assert [Path(os.fsdecode(skip.path)).name for skip in result.skipped] == ["link.csv"]
    assert not (destination / "sub" / "link.csv").exists()
    assert not result.complete


async def test_uploading_creates_missing_parents_of_the_destination(tmp_path: Path):
    # v3 answers a MKDIR whose parent is absent with the same catch-all FAILURE it answers
    # everything else with, so "create the missing levels" cannot be told from "refused"
    # without looking. Three levels, none of which exist.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "local"
    source.mkdir()
    (source / "only.txt").write_bytes(b"only")
    destination = tmp_path / "a" / "b" / "c"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put_tree(source, str(destination))

    assert (destination / "only.txt").read_bytes() == b"only"
    assert result.files == 1


async def test_uploading_a_real_tree_twice_converges_rather_than_accumulating(tmp_path: Path):
    # The mirroring case. The second pass rewrites the same files over the top, and mkdir
    # must not fail on directories that are already there.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "local"
    source.mkdir()
    build_tree(source)
    destination = tmp_path / "remote"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        first = await sftp.put_tree(source, str(destination))
        second = await sftp.put_tree(source, str(destination))

    assert (first.files, first.transferred) == (second.files, second.transferred)
    assert (destination / "sub" / "deeper" / "leaf.txt").read_bytes() == b"leaf"
    # No staging file survived either pass: every one was renamed onto its destination.
    assert not list(destination.glob(".*.part"))


async def test_uploading_without_atomic_leaves_no_staging_file_either(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "local"
    source.mkdir()
    (source / "plain.txt").write_bytes(b"plain")
    destination = tmp_path / "remote"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put_tree(source, str(destination), atomic=False)

    assert (destination / "plain.txt").read_bytes() == b"plain"
    assert sorted(item.name for item in destination.iterdir()) == ["plain.txt"]
    assert result.files == 1


async def test_a_real_round_trip_up_then_down_is_byte_identical(tmp_path: Path):
    # The mirroring workload end to end, and the only test that proves the two directions
    # agree with each other rather than each agreeing with its own idea of the tree.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "local"
    source.mkdir()
    build_tree(source)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put_tree(source, str(tmp_path / "remote"))
        await sftp.get_tree(str(tmp_path / "remote"), tmp_path / "back")

    # The non-UTF-8 name spelled the way the filesystem holds it, not as a str literal:
    # "caf\xe9.bin" is U+00E9 and encodes to two bytes, which is a different file.
    for relative in (
        "top.csv",
        "sub/nested.bin",
        "sub/deeper/leaf.txt",
        os.fsdecode(b"caf\xe9.bin"),
    ):
        assert (tmp_path / "back" / relative).read_bytes() == (source / relative).read_bytes()


async def test_removing_a_real_tree(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    doomed = tmp_path / "doomed"
    doomed.mkdir()
    build_tree(doomed)
    # A file outside the tree that the symlink inside it points at: rmtree must unlink the
    # link and leave the target alone, which is the difference between REMOVE and following.
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"untouched")
    (doomed / "sub" / "escape").symlink_to(outside)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.rmtree(str(doomed))

    assert not doomed.exists()
    assert outside.read_bytes() == b"untouched", "rmtree followed a link out of the tree"
    assert result.directories == 3
    assert result.files == 6
    assert result.transferred == 0


async def test_rmtree_of_a_real_empty_directory(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    (tmp_path / "empty").mkdir()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.rmtree(str(tmp_path / "empty"))

    assert not (tmp_path / "empty").exists()
    assert (result.files, result.directories) == (0, 1)


async def test_rmdir_on_a_real_server_refuses_a_populated_directory(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    root = tmp_path / "populated"
    root.mkdir()
    (root / "a.txt").write_bytes(b"a")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as exc:
            await sftp.rmdir(str(root))
        assert exc.value.code == int(StatusCode.FAILURE)
        assert root.is_dir(), "a refused rmdir must have changed nothing"

        (root / "a.txt").unlink()
        await sftp.rmdir(str(root))
    assert not root.exists()


# --- two remote names, one local file ----------------------------------------------------------
#
# The axis CLAUDE.md's Definition of Done names and this repository had never varied. It needs
# no hostile server and no exotic endpoint: a case-sensitive server holding README.md beside
# readme.md is entirely legal, and APFS and NTFS -- the defaults on macOS and Windows -- make
# them one file. Without a check the second write truncates the first and the walk reports
# success, which is silent data loss that check_contained cannot see, because both paths are
# legitimately inside the destination.

COLLIDING_TREE = {
    b"/root": (named(b"README.md", REGULAR, 3), named(b"readme.md", REGULAR, 5)),
}
COLLIDING_FILES = {b"/root/README.md": b"AAA", b"/root/readme.md": b"bbbbb"}


def fold_case(path: Path) -> tuple[int, int]:
    """Stand in for a case-folding filesystem, for the cases a hard link cannot reach.

    Directories are one of those: Linux refuses to hard-link them, so the only way to give
    ``Docs`` and ``docs`` one identity here is to say so. The file-level proof below uses a
    real hard link and no stub, so at least one of these does not depend on this function
    being an honest model.
    """
    return (0, hash(str(path).lower()))


async def test_a_second_name_for_one_local_file_is_refused_not_overwritten(tmp_path: Path):
    # A hard link is the faithful stand-in: two directory entries, one inode, which is
    # exactly what a case-folding filesystem hands back for README.md and readme.md.
    destination = tmp_path / "out"
    destination.mkdir()
    first = destination / "README.md"
    first.write_text("placeholder")
    os.link(first, destination / "readme.md")

    server = TreeServer(tree=COLLIDING_TREE, files=COLLIDING_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(DestinationCollisionError) as caught:
            _ = await sftp.get_tree(b"/root", destination)

    # The first file is intact. Without the check it holds b"bbbbb" and nothing says so.
    assert first.read_bytes() == b"AAA"
    assert caught.value.args[0] == (
        "1 remote path resolved onto a local file this download had already written, "
        "and was refused rather than overwriting it"
    )
    assert [(item.remote, item.first) for item in caught.value.collisions] == [
        (b"/root/readme.md", b"/root/README.md")
    ]
    assert caught.value.destination == str(destination)


async def test_everything_transferable_still_transfers_before_the_error(tmp_path: Path):
    # Refusing the write that would destroy an earlier one is not a reason to abandon the
    # files that have nothing wrong with them.
    destination = tmp_path / "out"
    destination.mkdir()
    first = destination / "README.md"
    first.write_text("placeholder")
    os.link(first, destination / "readme.md")

    tree = {
        b"/root": (
            named(b"README.md", REGULAR, 3),
            named(b"readme.md", REGULAR, 5),
            named(b"other.csv", REGULAR, 4),
        ),
    }
    files = {**COLLIDING_FILES, b"/root/other.csv": b"cccc"}
    server = TreeServer(tree=tree, files=files)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(DestinationCollisionError) as caught:
            _ = await sftp.get_tree(b"/root", destination)

    assert (destination / "other.csv").read_bytes() == b"cccc"
    assert caught.value.files == 2
    assert caught.value.transferred == 7
    assert "transferred 2 files, 7 bytes" in str(caught.value)


async def test_a_case_folding_destination_refuses_the_second_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr("gantry_sftp.session._localpath.identity", fold_case)
    server = TreeServer(tree=COLLIDING_TREE, files=COLLIDING_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(DestinationCollisionError) as caught:
            _ = await sftp.get_tree(b"/root", tmp_path / "out")

    assert (tmp_path / "out" / "README.md").read_bytes() == b"AAA"
    assert caught.value.collisions[0].remote == b"/root/readme.md"


async def test_two_directories_that_fold_together_are_reported_not_merged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # Quieter than the file case and still wrong: the two directories' contents merge, so the
    # structure is unfaithful even where no individual file is lost.
    monkeypatch.setattr("gantry_sftp.session._localpath.identity", fold_case)
    tree = {
        b"/root": (named(b"Docs", DIRECTORY), named(b"docs", DIRECTORY)),
        b"/root/Docs": (named(b"a.csv", REGULAR, 3),),
        b"/root/docs": (named(b"b.csv", REGULAR, 5),),
    }
    files = {b"/root/Docs/a.csv": b"aaa", b"/root/docs/b.csv": b"bbbbb"}
    server = TreeServer(tree=tree, files=files)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(DestinationCollisionError) as caught:
            _ = await sftp.get_tree(b"/root", tmp_path / "out")

    assert [(item.remote, item.first) for item in caught.value.collisions] == [
        (b"/root/docs", b"/root/Docs")
    ]
    assert caught.value.files == 2


async def test_the_refused_entry_is_reported_in_the_skip_list(tmp_path: Path):
    destination = tmp_path / "out"
    destination.mkdir()
    first = destination / "README.md"
    first.write_text("placeholder")
    os.link(first, destination / "readme.md")

    server = TreeServer(tree=COLLIDING_TREE, files=COLLIDING_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(DestinationCollisionError):
            _ = await sftp.get_tree(b"/root", destination)

    # The reason string is the one a human reads in a report, so it is pinned like the rest.
    assert SkipReason.DESTINATION_COLLISION == (
        "the destination filesystem does not tell it apart from an earlier name"
    )


async def test_a_file_left_by_an_earlier_run_is_overwritten_not_refused(tmp_path: Path):
    # The guard against the check firing on the ordinary case. A destination holding last
    # week's copy is the normal state of every scheduled transfer, and re-downloading onto it
    # is the point -- only a file *this* run wrote is protected.
    destination = tmp_path / "out"
    destination.mkdir()
    (destination / "a.csv").write_text("from last week")

    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", destination)

    assert (destination / "a.csv").read_bytes() == b"aaa"
    assert result.files == 3


# --- a namespace that is not rooted at "/" -----------------------------------------------------
#
# D-77, split out of D-37. Every remote path this library builds is "/" arithmetic on bytes,
# which is what draft-ietf-secsh-filexfer-02 6.2 says to assume -- "File names are assumed to
# use the slash ('/') character as a directory separator", and "otherwise, no syntax is defined
# for file names by this specification". So on a server whose namespace is not "/"-shaped there
# is no correct join to perform, and the answer is to refuse rather than build a path the server
# does not mean.

VMS_ROOT = b"DISK$USER:[SMITH]"

RELATIVE_TREE = {
    b"incoming": (named(b"a.csv", REGULAR, 3),),
}
RELATIVE_FILES = {b"incoming/a.csv": b"aaa"}


async def test_an_absolute_path_never_asks_the_server_where_it_is(tmp_path: Path):
    # The cheap half, and the reason this costs nothing in the common case. 6.2: a name
    # starting with "/" is absolute and relative to the root of the filesystem, so the caller
    # has already asserted the namespace the arithmetic assumes. No REALPATH is sent at all --
    # even on a server that would have answered with a foreign one.
    server = TreeServer(tree=SIMPLE_TREE, files=SIMPLE_FILES, root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"/root", tmp_path / "out")

    assert result.files == 3
    assert not [packet for packet in server.seen if isinstance(packet, RealPath)]
    assert sftp.server_root is None


async def test_a_relative_path_on_a_rooted_server_is_fine(tmp_path: Path):
    server = TreeServer(tree=RELATIVE_TREE, files=RELATIVE_FILES, root=b"/home/smith")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.get_tree(b"incoming", tmp_path / "out")

    assert result.files == 1
    assert (tmp_path / "out" / "a.csv").read_bytes() == b"aaa"
    assert sftp.server_root == b"/home/smith"


async def test_a_relative_walk_on_a_rootless_server_is_refused(tmp_path: Path):
    server = TreeServer(tree=RELATIVE_TREE, files=RELATIVE_FILES, root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as caught:
            _ = await sftp.get_tree(b"incoming", tmp_path / "out")

    assert caught.value.args[0] == (
        "walking a tree builds remote paths by '/' arithmetic and this server's default "
        "directory is not rooted at '/': REALPATH of b'.' answered b'DISK$USER:[SMITH]'. "
        "draft-ietf-secsh-filexfer-02 6.2 defines no other filename syntax, so joining or "
        "splitting b'incoming' would produce a path this server does not mean. Pass an "
        "absolute '/'-rooted path, or drive the per-file operations yourself with paths you "
        "build"
    )
    assert caught.value.feature == "walking a tree"
    assert caught.value.path == b"incoming"
    assert not caught.value.missing
    # Nothing was attempted: the refusal is ours, before any listing was asked for.
    assert not [packet for packet in server.seen if isinstance(packet, OpenDir)]


async def test_the_root_is_probed_once_and_remembered(tmp_path: Path):
    # One REALPATH for the life of the session, however many relative operations run. A probe
    # per operation would be a round trip per tree on the servers least able to spare one.
    server = TreeServer(tree=RELATIVE_TREE, files=RELATIVE_FILES, root=b"/home/smith")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.get_tree(b"incoming", tmp_path / "one")
        _ = await sftp.get_tree(b"incoming", tmp_path / "two")
        _ = [entry async for entry in sftp.walk(b"incoming")]

    assert len([packet for packet in server.seen if isinstance(packet, RealPath)]) == 1


async def test_a_relative_upload_tree_on_a_rootless_server_is_refused(tmp_path: Path):
    source = tmp_path / "outgoing"
    source.mkdir()
    _ = (source / "a.csv").write_bytes(b"aaa")

    server = TreeServer(tree={}, root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as caught:
            _ = await sftp.put_tree(source, b"incoming")

    assert caught.value.feature == "uploading a tree"
    # MKDIR of the parents is the first thing put_tree would have sent, and it did not.
    assert not [packet for packet in server.seen if isinstance(packet, MkDir)]

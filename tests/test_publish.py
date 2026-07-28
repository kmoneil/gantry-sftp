"""Atomic publish: the ladder, the refusals, and what the result claims.

Two halves, and neither substitutes for the other. The scripted server below produces shapes
a real one will not make on demand -- an extension advertised and then refused, a rename that
fails for a reason that is *not* the target being in the way, a staging name already taken.
The real-``sftp-server`` tests at the bottom prove the thing itself: that a consumer watching
the directory never sees the destination in a partial state, and that with ``atomic=False`` it
does.
"""

from __future__ import annotations

import os
import re
import warnings
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    EXTENSION_FSYNC,
    EXTENSION_POSIX_RENAME,
    FSYNC_NAME,
    POSIX_RENAME_NAME,
    Attrs,
    AttrsReply,
    Close,
    Extended,
    FrameSplitter,
    Fsync,
    Handle,
    Init,
    LStat,
    Name,
    NameEntry,
    Open,
    OpenFlag,
    PosixRename,
    RealPath,
    Remove,
    Rename,
    Stat,
    Status,
    StatusCode,
    Version,
    Write,
    decode,
    encode,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    PermissionDeniedError,
    ServerError,
    TransferError,
    TransferTimeoutError,
)
from gantry_sftp.session import (
    DEFAULT_PUBLISH,
    MAX_STAGED_NAME_LENGTH,
    Durability,
    Publish,
    PublishMechanism,
    SizeCheck,
    UploadResult,
    open_session,
    split_parent,
    staged_path,
    staging_token,
)
from gantry_sftp.session._publish import publish_from_legacy
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

TARGET = b"/incoming/report.csv"
STAGED = b"/incoming/.report.csv.deadbeef.part"


# --- the naming arithmetic, which is pure -------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (b"/incoming/report.csv", (b"/incoming/", b"report.csv")),
        (b"/report.csv", (b"/", b"report.csv")),
        (b"report.csv", (b"", b"report.csv")),
        (b"/a/b/c/d.bin", (b"/a/b/c/", b"d.bin")),
        (b"/trailing/", (b"/trailing/", b"")),
        (b"/\xff\xfe/caf\xe9.csv", (b"/\xff\xfe/", b"caf\xe9.csv")),
    ],
)
def test_split_parent_is_posix_arithmetic_on_bytes(path: bytes, expected: tuple[bytes, bytes]):
    # Deliberately not os.path: on a Windows *client* that joins with a backslash and
    # produces a remote path no SFTP server understands. And the name is never decoded, so a
    # filename that is not valid UTF-8 splits like any other.
    assert split_parent(path) == expected


def test_the_staging_file_is_a_hidden_sibling():
    # A sibling because a rename across filesystems is not atomic and often not permitted.
    # Hidden because a consumer globbing `*.csv` must not match the staging file, and that
    # consumer is the reason any of this exists.
    assert staged_path(TARGET, "deadbeef") == STAGED


def test_a_bare_target_stages_in_the_same_implicit_directory():
    assert staged_path(b"report.csv", "abc12345") == b".report.csv.abc12345.part"


def test_a_target_in_the_root_stages_in_the_root():
    assert staged_path(b"/report.csv", "abc12345") == b"/.report.csv.abc12345.part"


def test_two_publishers_of_one_target_do_not_collide():
    first, second = staging_token(), staging_token()
    assert first != second
    assert re.fullmatch(r"[0-9a-f]{8}", first), first


def test_a_long_filename_still_produces_a_name_a_server_will_accept():
    # NAME_MAX is 255 on every common filesystem and the staging name is longer than the one
    # the caller asked for. Without the cap this is an upload that fails only for long
    # filenames -- which hides until the day somebody uses one.
    target = b"/incoming/" + b"n" * 250 + b".csv"
    _, name = split_parent(staged_path(target, "deadbeef"))
    assert len(name) == MAX_STAGED_NAME_LENGTH
    assert name.startswith(b".nnn")
    assert name.endswith(b".deadbeef.part")


def test_a_short_filename_is_not_padded_or_truncated():
    _, name = split_parent(staged_path(b"/a/b.c", "deadbeef"))
    assert name == b".b.c.deadbeef.part"


def test_an_explicit_bare_staging_name_is_resolved_as_a_sibling():
    assert staged_path(TARGET, "deadbeef", name=b"upload.tmp") == b"/incoming/upload.tmp"


def test_an_explicit_staging_path_is_used_verbatim():
    # For a server that mandates a staging directory. Same filesystem is the caller's problem
    # and the publish step is where they find out.
    staging = b"/var/spool/staging/report.csv"
    assert staged_path(TARGET, "deadbeef", name=staging) == staging


def test_a_target_with_no_filename_is_refused():
    with pytest.raises(ValueError) as exc:
        _ = staged_path(b"/incoming/", "deadbeef")
    assert exc.value.args[0] == "remote path has no filename to publish: b'/incoming/'"


# --- what the result claims ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("mechanism", "atomic"),
    [
        (PublishMechanism.POSIX_RENAME, True),
        (PublishMechanism.RENAME, True),
        (PublishMechanism.REMOVE_RENAME, False),
        (PublishMechanism.IN_PLACE, False),
    ],
)
def test_every_mechanism_decides_whether_it_was_atomic(mechanism: PublishMechanism, atomic: bool):
    # Parametrised over the whole enum on purpose: a mechanism added later without a decision
    # here is a mechanism whose atomicity nobody stated.
    result = UploadResult(1, TARGET, mechanism, Durability.FSYNCED, SizeCheck.MATCHED)
    assert result.atomic is atomic


@pytest.mark.parametrize(
    ("durability", "durable"),
    [
        (Durability.FSYNCED, True),
        (Durability.UNAVAILABLE, False),
        (Durability.SKIPPED, False),
    ],
)
def test_every_durability_decides_whether_it_was_durable(durability: Durability, durable: bool):
    result = UploadResult(1, TARGET, PublishMechanism.RENAME, durability, SizeCheck.MATCHED)
    assert result.durable is durable


def test_the_mechanisms_render_as_the_names_a_log_line_wants():
    assert str(PublishMechanism.POSIX_RENAME) == "posix-rename"
    assert str(PublishMechanism.REMOVE_RENAME) == "remove-rename"
    assert str(Durability.UNAVAILABLE) == "unavailable"


# --- a server with just enough filesystem to publish onto ---------------------------------


class PublishingServer:
    """Scriptable in-process server: names, bytes, handles, and rename semantics.

    v3 ``RENAME`` refuses an existing target here, because that is what a real server does --
    measured on OpenSSH 10.0p2, ``FAILURE`` with nothing changed. A fake that let it overwrite
    would make the whole fallback ladder untested and would agree with a client that skipped
    it.
    """

    def __init__(
        self,
        *,
        extensions: tuple[bytes, ...] = (POSIX_RENAME_NAME, FSYNC_NAME),
        implements: tuple[bytes, ...] | None = None,
        files: dict[bytes, bytes] | None = None,
        dangling: tuple[bytes, ...] = (),
        refuse: dict[str, StatusCode] | None = None,
        root: bytes = b"/home/user",
    ) -> None:
        # What REALPATH of b"." answers. A value not starting with b"/" is a namespace this
        # library's path arithmetic cannot join in -- see D-77 and the tests at the bottom.
        self.root = root
        self.files: dict[bytes, bytearray] = {
            name: bytearray(content) for name, content in (files or {}).items()
        }
        # Symlinks whose target is gone: the name is taken, and STAT still says NO_SUCH_FILE.
        self.dangling: set[bytes] = set(dangling)
        self.extensions = extensions
        # Advertising and implementing are different things in both directions, and the
        # publish ladder now depends on that: a server can implement an extension it never
        # lists. Default is the honest majority case -- it implements exactly what it says.
        self.implements = extensions if implements is None else implements
        # One mapping rather than eight flags: every operation refuses the same way, and a
        # ninth operation should not mean a ninth constructor argument.
        self.refuse = dict(refuse or {})

        self.seen: list[object] = []
        self.handles: dict[bytes, bytes] = {}
        self.fsynced: list[bytes] = []
        self._next_handle = 0
        self._splitter = FrameSplitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    # --- transport surface ---------------------------------------------------------------

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

    # --- dispatch ------------------------------------------------------------------------

    def _reply(self, packet) -> None:
        self._outbox += encode(packet)
        self._has_output.set()

    def _dispatch(self, packet) -> None:
        self.seen.append(packet)
        if isinstance(packet, Init):
            self._reply(Version(3, tuple((name, b"1") for name in self.extensions)))
            return
        handlers = {
            Open: self._on_open,
            Write: self._on_write,
            Close: self._on_close,
            Stat: self._on_stat,
            LStat: self._on_lstat,
            Remove: self._on_remove,
            Rename: self._on_rename,
            Extended: self._on_extended,
            RealPath: self._on_realpath,
        }
        handler = handlers.get(type(packet))
        if handler is None:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))
            return
        handler(packet)

    def _refuse(self, packet, code: StatusCode) -> None:
        self._reply(Status(packet.request_id, code, code.name.encode("ascii")))

    # --- operations ----------------------------------------------------------------------

    def _on_open(self, packet: Open) -> None:
        if (refusal := self.refuse.get("open")) is not None:
            self._refuse(packet, refusal)
            return
        if packet.pflags & OpenFlag.EXCL and packet.filename in self.files:
            self._refuse(packet, StatusCode.FAILURE)
            return
        if packet.pflags & OpenFlag.TRUNC or packet.filename not in self.files:
            self.files[packet.filename] = bytearray()
        handle = self._next_handle.to_bytes(4, "big")
        self._next_handle += 1
        self.handles[handle] = packet.filename
        self._reply(Handle(packet.request_id, handle))

    def _on_write(self, packet: Write) -> None:
        if (refusal := self.refuse.get("write")) is not None:
            self._refuse(packet, refusal)
            return
        stored = self.files[self.handles[packet.handle]]
        end = packet.offset + len(packet.data)
        if len(stored) < end:
            stored.extend(bytes(end - len(stored)))
        stored[packet.offset : end] = packet.data
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_close(self, packet: Close) -> None:
        _ = self.handles.pop(packet.handle, None)
        if (refusal := self.refuse.get("close")) is not None:
            self._refuse(packet, refusal)
            return
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_stat(self, packet) -> None:
        # Follows symlinks, so a dangling one is NO_SUCH_FILE here and present under LSTAT.
        # That difference is the whole reason the publish path asks with LSTAT.
        if (refusal := self.refuse.get("stat")) is not None:
            self._refuse(packet, refusal)
        elif packet.path in self.files:
            self._reply(AttrsReply(packet.request_id, Attrs(size=len(self.files[packet.path]))))
        else:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))

    def _on_lstat(self, packet) -> None:
        if (refusal := self.refuse.get("stat")) is not None:
            self._refuse(packet, refusal)
        elif packet.path in self.files or packet.path in self.dangling:
            self._reply(AttrsReply(packet.request_id, Attrs(size=0)))
        else:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))

    def _taken(self, path: bytes) -> bool:
        """Whether the name is occupied, symlink or not -- what a rename collides with."""
        return path in self.files or path in self.dangling

    def _on_remove(self, packet: Remove) -> None:
        if (refusal := self.refuse.get("remove")) is not None:
            self._refuse(packet, refusal)
        elif not self._taken(packet.path):
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        else:
            _ = self.files.pop(packet.path, None)
            self.dangling.discard(packet.path)
            self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_rename(self, packet: Rename) -> None:
        if (refusal := self.refuse.get("rename")) is not None:
            self._refuse(packet, refusal)
        elif self._taken(packet.newpath):
            # v3 RENAME cannot overwrite, and this is the measured behaviour of a real server.
            self._refuse(packet, StatusCode.FAILURE)
        elif packet.oldpath not in self.files:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        else:
            self.files[packet.newpath] = self.files.pop(packet.oldpath)
            self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_realpath(self, packet: RealPath) -> None:
        self._reply(Name(packet.request_id, (NameEntry(self.root, self.root, Attrs()),)))

    def _on_extended(self, packet: Extended) -> None:
        if packet.name not in self.implements:
            self._refuse(packet, StatusCode.OP_UNSUPPORTED)
        elif packet.name == POSIX_RENAME_NAME:
            self._on_posix_rename(PosixRename.from_extended(packet))
        elif packet.name == FSYNC_NAME:
            self._on_fsync(Fsync.from_extended(packet))
        else:
            self._refuse(packet, StatusCode.OP_UNSUPPORTED)

    def _on_posix_rename(self, packet: PosixRename) -> None:
        if (refusal := self.refuse.get("posix-rename")) is not None:
            self._refuse(packet, refusal)
        elif packet.oldpath not in self.files:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        else:
            self.files[packet.newpath] = self.files.pop(packet.oldpath)
            self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_fsync(self, packet: Fsync) -> None:
        if packet.handle not in self.handles:
            # What a real server answers for a handle it has already closed, which is what
            # makes flush-before-close a tested ordering rather than a comment.
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        elif (refusal := self.refuse.get("fsync")) is not None:
            self._refuse(packet, refusal)
        else:
            self.fsynced.append(self.handles[packet.handle])
            self._reply(Status(packet.request_id, StatusCode.OK))

    # --- inspection ----------------------------------------------------------------------

    def kinds(self) -> list[str]:
        """The conversation, as a list of packet names plus extension names."""
        names = []
        for packet in self.seen:
            if isinstance(packet, Extended):
                names.append(packet.name.decode("ascii"))
            else:
                names.append(type(packet).__name__)
        return names

    def opened(self, pflags: OpenFlag) -> list[bytes]:
        return [p.filename for p in self.seen if isinstance(p, Open) and p.pflags == pflags]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "report.csv"
    path.write_bytes(b"id,total\n1,42\n")
    return path


def staging_files(directory: Path, stem: str) -> list[Path]:
    """Staging files for ``stem`` in ``directory``, as a consumer's glob would see them.

    A plain function rather than inline, so the async tests below do not do filesystem work
    that ASYNC240 rightly objects to in an async frame.
    """
    return list(directory.glob(f".{stem}.*.part"))


# --- the happy path ------------------------------------------------------------------------


async def test_a_default_put_stages_flushes_and_renames(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result == UploadResult(
        transferred=14,
        remote_path=TARGET,
        mechanism=PublishMechanism.POSIX_RENAME,
        durability=Durability.FSYNCED,
        size_check=SizeCheck.MATCHED,
        staged_at=STAGED,
    )
    assert result.atomic
    assert result.durable
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"
    assert STAGED not in server.files, "the staging file outlived the publish"


async def test_the_order_is_stage_write_flush_close_rename(source: Path):
    """The sequence, asserted as a sequence.

    Every one of these has to be where it is. The flush is before the CLOSE because a closed
    handle answers ``NO_SUCH_FILE`` -- measured. The rename is after the CLOSE because a
    server is entitled to report a write failure at close time, and publishing a file we then
    learn was not written is the failure this feature exists to prevent.
    """
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    # The Stat is rung 3, and it sits between the Close and the rename deliberately: the
    # length is confirmed on the staging file, so a truncated upload is refused before it can
    # become the destination rather than reported after a consumer could already read it.
    assert server.kinds() == [
        "Init",
        "Open",
        "Write",
        "fsync@openssh.com",
        "Close",
        "Stat",
        "posix-rename@openssh.com",
    ]


async def test_the_bytes_go_to_the_staging_name_and_never_to_the_destination(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    written = {server.handles.get(p.handle, STAGED) for p in server.seen if isinstance(p, Write)}
    assert server.opened(OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL) == [STAGED]
    assert TARGET not in written


async def test_the_staging_file_is_opened_exclusively(source: Path):
    # Without EXCL a name collision is two publishers writing into one file at different
    # offsets, which produces a result that is the wrong length or interleaved -- plausible,
    # and wrong.
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    opens = [p for p in server.seen if isinstance(p, Open)]
    assert opens[0].pflags & OpenFlag.EXCL
    assert not opens[0].pflags & OpenFlag.TRUNC, "EXCL and TRUNC together is a contradiction"


async def test_the_default_staging_name_is_a_hidden_sibling_with_a_token(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET)

    assert result.staged_at is not None
    assert re.fullmatch(rb"/incoming/\.report\.csv\.[0-9a-f]{8}\.part", result.staged_at)


async def test_publishing_over_an_existing_file_is_still_atomic(source: Path):
    server = PublishingServer(files={TARGET: b"yesterday's numbers"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert result.atomic
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


# --- the fallback ladder -------------------------------------------------------------------


async def test_a_server_without_posix_rename_uses_a_plain_rename(source: Path):
    # Atomic none the less, and that is not a hedge: v3 RENAME cannot overwrite, so a success
    # proves the destination appeared whole.
    server = PublishingServer(extensions=(FSYNC_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.mechanism is PublishMechanism.RENAME
    assert result.atomic
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


async def test_posix_rename_is_attempted_even_when_it_was_never_advertised(source: Path):
    """Endpoints under-advertise, and the cost of asking is one round trip.

    This is not the probe DESIGN.md 4.2 forbids for mutating extensions -- it is the operation
    we came here to perform. A server that implements ``posix-rename`` and never lists it would
    otherwise be pushed onto the remove-then-rename path, and lose the guarantee, for no reason
    but its own reticence.
    """

    # Implements it, advertises nothing.
    server = PublishingServer(
        extensions=(), implements=(POSIX_RENAME_NAME,), files={TARGET: b"yesterday"}
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert not sftp.supports(EXTENSION_POSIX_RENAME)
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert result.atomic
    assert "Remove" not in server.kinds()
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


async def test_an_unsupported_answer_is_remembered_for_the_session(source: Path):
    # OP_UNSUPPORTED is a definitive answer, so asking twice is a wasted round trip on every
    # subsequent publish -- and publishing is something jobs do in a loop.
    server = PublishingServer(extensions=())
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))
        _ = await sftp.put(
            source, b"/incoming/second.csv", publish=Publish(staging_name=b"/incoming/.second.part")
        )

    assert server.kinds().count("posix-rename@openssh.com") == 1


async def test_a_refusal_that_is_not_unsupported_is_not_remembered(source: Path):
    """Only a definitive answer is cached.

    A server that refused one rename has told us about that request, not about its
    capabilities -- and an unadvertised extension refusing for some other reason leaves us
    knowing nothing at all, so the fallback stands and the question stays open.
    """
    server = PublishingServer(
        extensions=(),
        implements=(POSIX_RENAME_NAME,),
        refuse={"posix-rename": StatusCode.FAILURE},
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))
        assert result.mechanism is PublishMechanism.RENAME
        result = await sftp.put(
            source, b"/incoming/second.csv", publish=Publish(staging_name=b"/incoming/.two")
        )

    assert result.mechanism is PublishMechanism.RENAME
    assert server.kinds().count("posix-rename@openssh.com") == 2


async def test_an_advertised_extension_refusing_for_another_reason_propagates(source: Path):
    """Advertised and then refused with something that is not OP_UNSUPPORTED.

    The server said it has this and then declined *this operation* -- permissions, a read-only
    directory. Falling through to a fallback that will fail the same way only replaces a
    precise error with a vaguer one.
    """
    server = PublishingServer(refuse={"posix-rename": StatusCode.PERMISSION_DENIED})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(PermissionDeniedError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert exc.value.path == TARGET
    assert "Rename" not in server.kinds(), "fell through to a fallback that cannot help"
    assert STAGED not in server.files, "the staging file was left behind"


async def test_an_advertised_extension_that_answers_unsupported_falls_through(source: Path):
    # Advertising and then refusing is a server contradicting itself, and it happens. The
    # fallback must be the tested path, not the theoretical one.
    server = PublishingServer(refuse={"posix-rename": StatusCode.OP_UNSUPPORTED})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.mechanism is PublishMechanism.RENAME
    assert server.kinds().count("posix-rename@openssh.com") == 1
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


async def test_without_posix_rename_an_existing_target_costs_a_remove_first(source: Path):
    """The documented non-atomic fallback, and the failure mode inverts rather than vanishing.

    Instead of a consumer reading a partial file, a consumer reads *no* file. Usually better.
    Not always, and never silently -- which is why the mechanism is in the result.
    """
    server = PublishingServer(extensions=(), files={TARGET: b"yesterday"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.mechanism is PublishMechanism.REMOVE_RENAME
    assert not result.atomic
    assert result.durability is Durability.UNAVAILABLE
    assert server.kinds() == [
        "Init",
        "Open",
        "Write",
        "Close",
        "Stat",
        "posix-rename@openssh.com",
        "Rename",
        "LStat",
        "Remove",
        "Rename",
    ]
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


async def test_a_rename_that_fails_for_another_reason_deletes_nothing(source: Path):
    """The dangerous shape: ``FAILURE`` is a v3 catch-all and names nothing.

    A rename can be refused because the directory is read-only, not because the target is in
    the way. Removing the target on the strength of a guess about an error string would
    destroy a good file to recover from a failure that was never about it -- so the target is
    STATed first, and its absence means the original refusal stands.
    """
    server = PublishingServer(extensions=(), refuse={"rename": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"
    assert "Remove" not in server.kinds()[:-1], "something was deleted on a guess"
    # The staging file is cleaned up, and it is the only thing that is.
    assert STAGED not in server.files
    assert server.kinds()[-1] == "Remove", "the staging file was not cleaned up"


async def test_losing_the_race_inside_the_window_keeps_the_only_copy_of_the_data(source: Path):
    """The window this fallback is named for, and what must survive it.

    A concurrent writer recreating the destination between our REMOVE and our RENAME is enough
    to fail the second rename, because v3 RENAME refuses an existing target. At that instant
    the staging file is the *only* copy of what we uploaded -- the destination we removed is
    already gone. The normal cleanup would delete it and turn a failure someone can undo by
    hand into one nobody can.
    """

    class LosesTheRace(PublishingServer):
        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self.renames = 0

        def _on_rename(self, packet: Rename) -> None:
            self.renames += 1
            if self.renames == 2:
                # Somebody else got there in the window.
                self.files[TARGET] = bytearray(b"a concurrent writer's file")
            super()._on_rename(packet)

    server = LosesTheRace(extensions=(), implements=(), files={TARGET: b"yesterday"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert bytes(server.files[STAGED]) == b"id,total\n1,42\n", "the only copy was deleted"
    assert "Remove" in server.kinds()[:-1], "the destination was removed, so this is the case"
    assert exc.value.__notes__[0] == (
        "the destination b'/incoming/report.csv' was removed and the rename that should have "
        "replaced it failed; the uploaded file is intact at "
        "b'/incoming/.report.csv.deadbeef.part' and is now the only copy of it"
    )


class _SwallowsTheRemoveReply(PublishingServer):
    """Performs the ``REMOVE`` and withholds only the answer.

    This is what a stalled link looks like from the client, and it is the case the client
    genuinely cannot distinguish: the request went out, the server did the work, and the
    acknowledgement never came back. Deleting the file for real is the whole point -- a fake
    that refused instead would be a *definitive* answer, which is the safe case rather than
    this one.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.swallowed = 0

    def _on_remove(self, packet: Remove) -> None:
        if self.swallowed == 0 and self._taken(packet.path):
            self.swallowed += 1
            _ = self.files.pop(packet.path, None)
            return
        super()._on_remove(packet)


async def test_a_remove_whose_reply_never_arrives_does_not_delete_the_only_copy(source: Path):
    """D-74. The same window as the race above, entered by a timeout instead.

    The rung's own comment says everything past the ``REMOVE`` is unwindable only by hand, so
    a failure there must leave the staged file where it is. It did not: the ``REMOVE`` was
    *outside* the ``try`` that raises :class:`_StagedIsTheOnlyCopyError`, so a failure of the
    remove itself fell through to the ordinary cleanup -- which deleted the staging file with
    the destination already gone. Both copies, and an error message saying only that a request
    timed out.

    **No cancellation is needed to reach it**, which is what makes it ordinary rather than
    exotic: a request timeout is a slow server or a link that hiccuped. And this rung runs only
    where ``posix-rename@openssh.com`` is absent, which CLAUDE.md already names as most real
    endpoints.
    """
    server = _SwallowsTheRemoveReply(extensions=(), implements=(), files={TARGET: b"yesterday"})
    async with open_session(server, request_timeout=0.5) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferTimeoutError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert bytes(server.files[STAGED]) == b"id,total\n1,42\n", "the only copy was deleted"
    assert server.swallowed == 1, "the destination really was removed, so this is the case"
    # "may": the REMOVE went unanswered, so whether it ran is exactly what we cannot say.
    # Telling somebody their file was deleted when it may still be there sends them to restore
    # a backup they did not need.
    assert exc.value.__notes__[0] == (
        "the destination b'/incoming/report.csv' may already have been removed and was not "
        "replaced; the uploaded file is intact at b'/incoming/.report.csv.deadbeef.part' and "
        "may now be the only copy of it"
    )


async def test_a_cancellation_inside_the_remove_rename_window_does_not_delete_the_only_copy(
    source: Path,
):
    """The same hole, reached the other way, and it needed a second fix rather than the same one.

    A timeout is an ``Exception``; anyio's cancellation is a ``BaseException``, so even once
    the ``REMOVE`` was inside the guarded region an ``except Exception`` there would still have
    let a cancelled publish through to the cleanup. Concurrent transfers are the whole point of
    this library, and a sibling task failing inside a task group cancels its siblings -- so
    this is the default case, not an edge one.

    The cancellation itself must still propagate: it is re-raised unchanged, which is why the
    assertion is on the scope having been cancelled rather than on an exception type.
    """
    server = _SwallowsTheRemoveReply(extensions=(), implements=(), files={TARGET: b"yesterday"})
    async with open_session(server, request_timeout=None) as sftp:  # type: ignore[arg-type]
        with anyio.move_on_after(0.25) as scope:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert scope.cancelled_caught, "the publish was never actually cancelled"
    assert bytes(server.files[STAGED]) == b"id,total\n1,42\n", "the only copy was deleted"
    assert server.swallowed == 1, "the destination really was removed, so this is the case"


async def test_a_cancellation_during_the_second_rename_does_not_delete_the_only_copy(
    source: Path,
):
    """The other half of the window, and it needs its own case.

    The two guards fail independently: one covers a REMOVE that goes unanswered, this one
    covers a cancellation arriving once the destination is definitely gone. A test that only
    cancelled during the REMOVE would leave the rename's guard a mutation survivor -- turning
    it back into ``except Exception`` would change nothing red.

    Here the note is the *confirmed* wording, because the remove was answered: the destination
    is known to be gone rather than merely possibly gone. That distinction is the difference
    between telling somebody to restore a backup and telling them they might not need to.
    """

    class SwallowsTheSecondRenameReply(PublishingServer):
        """Lets the REMOVE through and withholds the answer to the rename after it."""

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self.renames = 0

        def _on_rename(self, packet: Rename) -> None:
            self.renames += 1
            if self.renames == 2:
                return
            super()._on_rename(packet)

    server = SwallowsTheSecondRenameReply(
        extensions=(), implements=(), files={TARGET: b"yesterday"}
    )
    async with open_session(server, request_timeout=None) as sftp:  # type: ignore[arg-type]
        with anyio.move_on_after(0.25) as scope:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert scope.cancelled_caught, "the publish was never actually cancelled"
    assert server.renames == 2, "the cancellation landed on the second rename, so this is the case"
    assert TARGET not in server.files, "the destination really was removed, so this is the window"
    assert bytes(server.files[STAGED]) == b"id,total\n1,42\n", "the only copy was deleted"


async def test_a_refused_remove_is_definitive_so_the_staging_file_is_still_cleaned_up(
    source: Path,
):
    """The other half, and the reason the fix is not "never clean up after a REMOVE".

    A ``ServerError`` means the server answered and said no: nothing was removed, the
    destination is intact, and the staging file is litter rather than the only copy. Leaving it
    behind would trade one silent failure for another -- the directory a consumer is watching
    slowly filling with dot-files nobody owns.
    """

    class RefusesToRemoveTheDestination(PublishingServer):
        """Refuses only the destination's removal.

        ``refuse={"remove": ...}`` would refuse the *cleanup* remove as well, and the staging
        file would survive for that reason instead of the one under test -- a test that could
        not have failed, in the direction that makes the fix look right.
        """

        def _on_remove(self, packet: Remove) -> None:
            if packet.path == TARGET:
                self._refuse(packet, StatusCode.PERMISSION_DENIED)
                return
            super()._on_remove(packet)

    server = RefusesToRemoveTheDestination(
        extensions=(), implements=(), files={TARGET: b"yesterday"}
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(PermissionDeniedError):
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert bytes(server.files[TARGET]) == b"yesterday", "the destination was never removed"
    assert STAGED not in server.files, "a definitive refusal leaves no reason to keep it"


async def test_a_destination_that_is_a_dangling_symlink_still_counts_as_in_the_way(source: Path):
    """The question is whether the *name* is taken, which is LSTAT's question, not STAT's.

    A ``latest.csv`` symlink whose target was rotated away is a name a rename cannot land on
    and a file STAT calls absent. Asking with STAT would conclude the destination is free,
    take the rename's uninformative FAILURE as final, and never try the fallback -- so the
    publish would fail on a case the fallback handles perfectly well.
    """
    server = PublishingServer(extensions=(), implements=(), dangling=(TARGET,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.mechanism is PublishMechanism.REMOVE_RENAME
    assert "LStat" in server.kinds()
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"
    assert TARGET not in server.dangling, "the symlink should have been replaced"


async def test_a_stat_that_errors_is_not_evidence_the_target_is_absent(source: Path):
    # Three states, and the third one decided explicitly: a STAT that fails for some reason
    # other than NO_SUCH_FILE tells us nothing, and "the server would not say" is not a
    # licence to delete anything.
    server = PublishingServer(
        extensions=(),
        refuse={"rename": StatusCode.FAILURE, "stat": StatusCode.PERMISSION_DENIED},
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert exc.value.code == int(StatusCode.FAILURE), "the rename's refusal is the diagnosis"
    assert "Remove" not in server.kinds()[:-1]


# --- refusing to downgrade -----------------------------------------------------------------


async def test_require_atomic_refuses_before_moving_any_bytes(source: Path):
    # The pre-flight exists so a nine-gigabyte upload is not transferred and then refused.
    server = PublishingServer(extensions=(), files={TARGET: b"yesterday"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as exc:
            _ = await sftp.put(
                source, TARGET, publish=Publish(staging_name=STAGED, require_atomic=True)
            )

    assert exc.value.args[0] == (
        "require_atomic=True but b'/incoming/report.csv' already exists and this server does "
        "not advertise posix-rename@openssh.com, so it cannot be replaced in one step"
    )
    assert exc.value.feature == "atomic publish"
    assert exc.value.missing == (EXTENSION_POSIX_RENAME,)
    assert exc.value.path == TARGET
    assert "Write" not in server.kinds(), "bytes were moved before the refusal"
    assert bytes(server.files[TARGET]) == b"yesterday"


async def test_require_atomic_is_satisfied_by_a_plain_rename_onto_a_free_name(source: Path):
    # Refusing here would be wrong. Most enterprise endpoints advertise no extensions at all,
    # and a rename onto a name that is free is atomic on every one of them.
    server = PublishingServer(extensions=())
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, TARGET, publish=Publish(staging_name=STAGED, require_atomic=True)
        )

    assert result.mechanism is PublishMechanism.RENAME
    assert result.atomic


async def test_require_atomic_refuses_a_target_that_appears_during_the_transfer(source: Path):
    """The race the pre-flight cannot close, closed at the other end.

    Another writer creating the destination while we upload turns an atomic publish into a
    remove-and-rename. A strict caller must get an error rather than that, even though the
    bytes have already been moved.
    """
    server = PublishingServer(extensions=())

    class Racing(PublishingServer):
        def _on_close(self, packet: Close) -> None:
            self.files[TARGET] = bytearray(b"somebody else got there first")
            super()._on_close(packet)

    server = Racing(extensions=())
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as exc:
            _ = await sftp.put(
                source, TARGET, publish=Publish(staging_name=STAGED, require_atomic=True)
            )

    assert exc.value.args[0] == (
        "require_atomic=True but b'/incoming/report.csv' already exists and this server does "
        "not advertise posix-rename@openssh.com; replacing it would mean removing it first, "
        "leaving a window with no file at all"
    )
    assert isinstance(exc.value.__cause__, ServerError), "the refusal that triggered it is kept"
    assert bytes(server.files[TARGET]) == b"somebody else got there first"
    assert STAGED not in server.files, "the staging file was left behind"


@pytest.mark.parametrize(
    ("flags", "message"),
    [
        ({"atomic": False, "require_atomic": True}, "require_atomic=True contradicts atomic=False"),
        ({"fsync": False, "require_fsync": True}, "require_fsync=True contradicts fsync=False"),
    ],
)
async def test_contradictory_flags_are_refused_rather_than_reconciled(
    source: Path, flags: dict[str, bool], message: str
):
    # Honouring either half silently would be guessing about the guarantee the caller cares
    # most about.
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(**flags))
    assert exc.value.args[0] == message
    assert "Open" not in server.kinds()


# --- durability -----------------------------------------------------------------------------


async def test_a_server_without_fsync_reports_no_durability_rather_than_claiming_it(
    source: Path,
):
    server = PublishingServer(extensions=(POSIX_RENAME_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.durability is Durability.UNAVAILABLE
    assert not result.durable
    assert result.atomic, "atomicity and durability are separate claims"
    assert "fsync@openssh.com" not in server.kinds()


async def test_fsync_can_be_switched_off_and_says_it_was_skipped(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED, fsync=False))

    assert result.durability is Durability.SKIPPED
    assert "fsync@openssh.com" not in server.kinds()


async def test_a_refused_flush_is_recorded_rather_than_fatal(source: Path):
    # fsync defaults to on, so a server whose filesystem cannot flush must not fail every
    # upload. The caller who cannot accept that has require_fsync.
    server = PublishingServer(refuse={"fsync": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert result.durability is Durability.UNAVAILABLE
    assert result.mechanism is PublishMechanism.POSIX_RENAME


async def test_require_fsync_turns_a_refused_flush_into_a_failure(source: Path):
    server = PublishingServer(refuse={"fsync": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(
                source, TARGET, publish=Publish(staging_name=STAGED, require_fsync=True)
            )

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"
    assert TARGET not in server.files, "an unflushed file was published anyway"
    assert STAGED not in server.files, "the staging file was left behind"


async def test_require_fsync_refuses_a_server_that_does_not_advertise_it(source: Path):
    server = PublishingServer(extensions=(POSIX_RENAME_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(require_fsync=True))

    assert exc.value.args[0] == (
        "require_fsync=True but this server does not advertise fsync@openssh.com, so nothing "
        "can promise the bytes reached stable storage"
    )
    assert exc.value.feature == "durable upload"
    assert exc.value.missing == (EXTENSION_FSYNC,)
    assert "Open" not in server.kinds(), "bytes were moved before the refusal"


async def test_the_flush_reaches_the_staging_file_not_the_destination(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))
    assert server.fsynced == [STAGED]


# --- in place, on request --------------------------------------------------------------------


async def test_atomic_false_writes_the_destination_directly(source: Path):
    # What every other SFTP client does by default, and what a write-only drop directory may
    # require: staging needs the right to create *and* rename a second name.
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, publish=Publish(atomic=False))

    assert result.mechanism is PublishMechanism.IN_PLACE
    assert not result.atomic
    assert result.staged_at is None
    assert result.durability is Durability.FSYNCED
    # In place the Stat is last and can only be last: the destination *is* the file being
    # written, so there is no earlier moment at which a short write could have been caught.
    assert server.kinds() == ["Init", "Open", "Write", "fsync@openssh.com", "Close", "Stat"]
    assert server.opened(OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC) == [TARGET]


async def test_an_in_place_write_truncates_what_was_there(source: Path):
    server = PublishingServer(files={TARGET: b"a much longer previous version"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, publish=Publish(atomic=False))
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


# --- cleanup ----------------------------------------------------------------------------------


async def test_a_failed_transfer_removes_the_staging_file(source: Path):
    # Otherwise every failed run leaves litter in the directory a consumer is watching, which
    # is how people end up writing the cleanup cron job that deletes the wrong thing.
    server = PublishingServer(refuse={"write": StatusCode.PERMISSION_DENIED})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert not isinstance(exc.value, BaseExceptionGroup)
    assert exc.value.remote_path == STAGED, "the error names the file that has bytes in it"
    assert STAGED not in server.files
    assert TARGET not in server.files
    assert server.kinds()[-1] == "Remove"


async def test_a_staging_name_already_taken_deletes_nothing(source: Path):
    """EXCL's whole point, and the trap in cleaning up after it.

    A collision means somebody else is publishing to the same destination. Their staging file
    must survive our failure -- deleting it would corrupt *their* upload, which is a strictly
    worse outcome than ours failing.
    """
    server = PublishingServer(files={STAGED: b"another publisher's work in progress"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert bytes(server.files[STAGED]) == b"another publisher's work in progress"
    assert "Remove" not in server.kinds()
    # And the error names a dot-file the caller never typed, so it says whose it is and what
    # to do instead. This is the first failure anyone meets when the new default does not suit
    # their server.
    assert exc.value.__notes__[0] == (
        "b'/incoming/.report.csv.deadbeef.part' is the staging file for "
        "b'/incoming/report.csv'. Publishing atomically needs the right to create and rename "
        "a second name in that directory, and a name that is not already taken -- pass "
        "atomic=False to write the destination directly instead, or staging_name= to put the "
        "staging file elsewhere."
    )


async def test_a_cleanup_that_also_fails_is_reported_on_the_original_error(source: Path):
    # Swallowing it means the caller never learns a file was left on the server. Raising it
    # means replacing the real error with a housekeeping one.
    server = PublishingServer(
        refuse={"write": StatusCode.PERMISSION_DENIED, "remove": StatusCode.PERMISSION_DENIED}
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert exc.value.__notes__
    assert exc.value.__notes__[0].startswith(
        "the staging file b'/incoming/.report.csv.deadbeef.part' was left on the server: "
        "removing it also failed ("
    )


async def test_a_failing_close_does_not_replace_the_error_that_caused_it(source: Path):
    """Closing on the failure path is housekeeping and must never become the diagnosis.

    With the close in a ``finally``, a server that refuses both the write and the close
    reports the close -- so the caller is told about a handle instead of about the write that
    was denied, and the offset and byte count that would let them resume are gone with it.
    """
    server = PublishingServer(
        refuse={"write": StatusCode.PERMISSION_DENIED, "close": StatusCode.FAILURE}
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert "PERMISSION_DENIED" in exc.value.args[0]
    assert exc.value.transferred == 0
    # And the handle really was closed anyway.
    assert any(isinstance(packet, Close) for packet in server.seen)


async def test_a_close_that_fails_on_the_success_path_fails_the_transfer(source: Path):
    # Some servers only discover a write failed when the file is closed -- NFS-backed ones
    # especially. A CLOSE that returns an error is the transfer failing, so it must not be
    # swallowed, and nothing may be published on the strength of it.
    server = PublishingServer(refuse={"close": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"
    assert TARGET not in server.files, "published a file the server would not close"
    assert "posix-rename@openssh.com" not in server.kinds()


async def test_a_failing_close_on_a_download_does_not_replace_the_error_either(
    source: Path, tmp_path: Path
):
    # Same shape on the read side, which had the same `finally`.
    server = PublishingServer(files={TARGET: b"content"}, refuse={"close": StatusCode.FAILURE})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.get(TARGET, tmp_path / "out.bin")

    # This scripted server has no READ handler, so the read is refused; the point is that the
    # surviving error is the read's -- which carries the offset and the byte count a resume
    # would need -- rather than the close's, which carries neither.
    assert exc.value.args[0] == "server refused a read at offset 0: FAILURE unscripted"
    assert exc.value.transferred == 0
    assert any(isinstance(packet, Close) for packet in server.seen)


async def test_a_refused_open_of_the_destination_is_not_dressed_up(source: Path):
    server = PublishingServer(refuse={"open": StatusCode.PERMISSION_DENIED})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(PermissionDeniedError) as exc:
            _ = await sftp.put(source, TARGET, publish=Publish(staging_name=STAGED))
    assert exc.value.path == STAGED


# --- capability reporting ----------------------------------------------------------------------


async def test_supports_answers_for_both_spellings_of_a_name(source: Path):
    server = PublishingServer(extensions=(POSIX_RENAME_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert sftp.supports(EXTENSION_POSIX_RENAME)
        assert sftp.supports(POSIX_RENAME_NAME)
        assert not sftp.supports(EXTENSION_FSYNC)
        assert not sftp.supports(b"nothing-like-this")


# --- against a real server -----------------------------------------------------------------------


async def test_a_consumer_never_sees_the_destination_partially_written(tmp_path: Path):
    """The promise, proven against a real server rather than asserted.

    The local-server transport runs the genuine ``sftp-server`` against this directory, so the
    test can watch the directory *while* the upload is in flight -- which is exactly what the
    consumer this feature exists for does.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(3_000_000)
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    destination = tmp_path / "published.bin"

    observations: list[tuple[int, bool, bool]] = []

    def watch(transferred: int, total: int | None) -> None:
        observations.append(
            (transferred, destination.exists(), bool(staging_files(tmp_path, "published.bin")))
        )

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination), progress=watch)

    assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert result.durability is Durability.FSYNCED
    assert destination.read_bytes() == content
    assert not staging_files(tmp_path, "published.bin"), "the staging file was left behind"

    # Nothing observed the destination while bytes were still moving, and the staging file was
    # observed, which is what makes the first half mean something rather than being vacuous.
    assert len(observations) > 2, "too few progress ticks to prove anything"
    assert not any(seen for _, seen, _ in observations), "the destination appeared mid-transfer"
    assert any(staged for _, _, staged in observations), "nothing was ever staged"


async def test_with_atomic_false_the_destination_does_appear_mid_transfer(tmp_path: Path):
    # The differential that makes the test above mean something: the same observation, the
    # opposite result, and the default is the safe one.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "source.bin"
    source.write_bytes(os.urandom(3_000_000))
    destination = tmp_path / "in-place.bin"

    seen_early: list[bool] = []

    def watch(transferred: int, total: int | None) -> None:
        seen_early.append(destination.exists())

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(destination), publish=Publish(atomic=False), progress=watch
        )

    assert result.mechanism is PublishMechanism.IN_PLACE
    assert any(seen_early[:-1]), "an in-place write should be visible while it happens"


async def test_publishing_over_an_existing_file_on_a_real_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    source = tmp_path / "source.bin"
    source.write_bytes(b"the new contents")
    destination = tmp_path / "published.bin"
    destination.write_bytes(b"the previous contents, which are longer")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(
            source, str(destination), publish=Publish(require_atomic=True, require_fsync=True)
        )

    assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert result.durable
    assert destination.read_bytes() == b"the new contents"


async def test_a_real_round_trip_through_an_atomic_publish_is_byte_identical(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(1_500_000)
    source = tmp_path / "source.bin"
    source.write_bytes(content)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(tmp_path / "remote.bin"))
        _ = await sftp.get(str(tmp_path / "remote.bin"), tmp_path / "back.bin")

    assert result.transferred == len(content)
    assert (tmp_path / "back.bin").read_bytes() == content


# --- publishing into a namespace that is not rooted at "/" -------------------------------------
#
# D-77. An atomic publish derives the staging file's directory from the target's, by splitting
# on "/". On a server whose namespace is not "/"-shaped that split finds nothing, the staging
# file lands in the default directory instead of beside the target, and the rename that was
# supposed to be atomic crosses directories -- silently, because a rename that is not atomic
# still looks like one from the return value.

VMS_ROOT = b"DISK$USER:[SMITH]"


async def test_a_relative_atomic_publish_on_a_rootless_server_is_refused(tmp_path: Path):
    source = tmp_path / "report.csv"
    _ = source.write_bytes(b"id,total\n")

    server = PublishingServer(root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as caught:
            _ = await sftp.put(source, b"report.csv")

    assert caught.value.feature == "atomic publish"
    assert caught.value.path == b"report.csv"
    # Ours, not the server's: nothing was opened, so no staging file was left anywhere.
    assert not [packet for packet in server.seen if isinstance(packet, Open)]
    assert not server.files


async def test_an_absolute_atomic_publish_never_probes(tmp_path: Path):
    source = tmp_path / "report.csv"
    _ = source.write_bytes(b"id,total\n")

    server = PublishingServer(root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, b"/incoming/report.csv")

    assert result.atomic
    assert not [packet for packet in server.seen if isinstance(packet, RealPath)]


async def test_an_explicit_staging_path_is_the_documented_escape(tmp_path: Path):
    # A staging name carrying a separator is used verbatim, so no parent is derived from the
    # target and there is nothing for a foreign namespace to break. The error tells callers to
    # build their own paths; this is that, and it has to actually work.
    source = tmp_path / "report.csv"
    _ = source.write_bytes(b"id,total\n")

    server = PublishingServer(root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(
            source, b"report.csv", publish=Publish(staging_name=b"staging/report.part")
        )

    assert result.staged_at == b"staging/report.part"
    assert result.atomic
    assert not [packet for packet in server.seen if isinstance(packet, RealPath)]


async def test_a_relative_in_place_put_is_untouched(tmp_path: Path):
    # atomic=False derives no parent and does no arithmetic, so it has no reason to be gated.
    # The whole point of narrowing the refusal is that a rootless server stays usable.
    source = tmp_path / "report.csv"
    _ = source.write_bytes(b"id,total\n")

    server = PublishingServer(root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, b"report.csv", publish=Publish(atomic=False))

    assert result.transferred == 9
    assert bytes(server.files[b"report.csv"]) == b"id,total\n"
    assert not [packet for packet in server.seen if isinstance(packet, RealPath)]


# --- the old spelling still resolves the old way --------------------------------------------
#
# CLAUDE.md's public-API rule, honoured literally. D-68 moved five arguments into `Publish`;
# these prove the move cost nobody anything, and that the ways it can go wrong are refusals
# rather than silent reinterpretations. `publish_from_legacy` is pure, so most of this needs
# no server -- which is the point of having put the decision in a function.


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ({"atomic": False}, Publish(atomic=False)),
        ({"fsync": False}, Publish(fsync=False)),
        ({"require_atomic": True}, Publish(require_atomic=True)),
        ({"require_fsync": True}, Publish(require_fsync=True)),
        ({"staging_name": b".part"}, Publish(staging_name=b".part")),
        (
            {"atomic": False, "fsync": False, "require_atomic": False},
            Publish(atomic=False, fsync=False),
        ),
    ],
    ids=lambda v: "|".join(sorted(v)) if isinstance(v, dict) else "",
)
def test_every_legacy_publish_argument_still_means_what_it_meant(legacy, expected):
    with pytest.deprecated_call():
        assert publish_from_legacy(None, legacy, caller="put") == expected


def test_no_arguments_at_all_is_the_default_policy_and_warns_about_nothing():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert publish_from_legacy(None, {}, caller="put") is DEFAULT_PUBLISH


def test_the_new_spelling_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert publish_from_legacy(Publish(atomic=False), {}, caller="put") == Publish(atomic=False)


def test_the_deprecation_names_the_arguments_it_is_about_and_the_replacement():
    with pytest.warns(DeprecationWarning) as caught:
        publish_from_legacy(None, {"atomic": False, "fsync": False}, caller="put")
    assert str(caught[0].message) == (
        "put(): atomic, fsync moved into the Publish object -- pass "
        "publish=Publish(atomic=..., fsync=...) instead. The old names still work and still "
        "mean the same thing."
    )


def test_both_spellings_at_once_is_refused_rather_than_merged():
    # There is no correct merge: either side silently overrides something the caller wrote.
    with pytest.raises(TypeError) as exc:
        publish_from_legacy(Publish(atomic=True), {"atomic": False}, caller="put")
    assert exc.value.args[0] == (
        "put() got both publish= and the legacy argument(s) atomic; use one spelling or the "
        "other, because there is no correct way to merge them -- either would silently "
        "override something you wrote"
    )


def test_a_misspelled_argument_is_refused_and_the_message_lists_the_real_ones():
    # The regression that absorbing these into **legacy would otherwise introduce: Python no
    # longer rejects a typo for us, and `atmoic=False` would publish atomically while the
    # caller believed the opposite.
    with pytest.raises(TypeError) as exc:
        publish_from_legacy(None, {"atmoic": False}, caller="put")
    assert exc.value.args[0] == (
        "put() got unexpected keyword argument(s) atmoic; publish policy is now a Publish "
        "object passed as publish=, and the accepted legacy names are atomic, fsync, "
        "require_atomic, require_fsync, staging_name"
    )


@pytest.mark.parametrize("name", ["atomic", "fsync", "require_atomic", "require_fsync"])
def test_a_legacy_flag_that_is_not_a_bool_is_refused(name):
    # `atomic="no"` is truthy. Under the old signature an annotation described it; absorbing
    # the name into **legacy threw that away, so the check is explicit or it is absent.
    with pytest.raises(TypeError) as exc:
        publish_from_legacy(None, {name: "no"}, caller="put")
    assert exc.value.args[0] == (
        f"put(): {name} must be a bool, got str; a truthy value that is not True would "
        f"publish differently than it reads"
    )


def test_a_legacy_staging_name_that_is_not_a_path_is_refused():
    with pytest.raises(TypeError) as exc:
        publish_from_legacy(None, {"staging_name": 7}, caller="put")
    assert exc.value.args[0] == "put(): staging_name must be bytes or str, got int"


async def test_the_old_spelling_still_publishes_the_way_it_used_to(source: Path):
    # The end-to-end half. The pure function above proves the translation; this proves the
    # translated policy still reaches the server as the same sequence of requests.
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.deprecated_call():
            old = await sftp.put(source, TARGET, atomic=False)
    assert old.mechanism is PublishMechanism.IN_PLACE

    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        new = await sftp.put(source, TARGET, publish=Publish(atomic=False))
    assert new.mechanism is PublishMechanism.IN_PLACE
    assert old.transferred == new.transferred


async def test_put_tree_refuses_a_staging_name_rather_than_colliding_every_file(tmp_path: Path):
    # One name cannot serve many files: the second would collide with the first, and the
    # report would blame whichever file the walk reached second.
    (tmp_path / "tree").mkdir()
    (tmp_path / "tree" / "a.txt").write_bytes(b"a")
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ValueError) as exc:
            _ = await sftp.put_tree(
                tmp_path / "tree", b"/incoming", publish=Publish(staging_name=b".part")
            )
    assert exc.value.args[0] == (
        "put_tree() cannot take a staging_name: it applies to every file in the tree, so they "
        "would all stage under one name and overwrite each other. Leave it unset to get a "
        "generated hidden sibling per file."
    )

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
    Open,
    OpenFlag,
    PosixRename,
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
)
from gantry_sftp.session import (
    MAX_STAGED_NAME_LENGTH,
    Durability,
    PublishMechanism,
    UploadResult,
    open_session,
    split_parent,
    staged_path,
    staging_token,
)
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
    result = UploadResult(1, TARGET, mechanism, Durability.FSYNCED)
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
    assert UploadResult(1, TARGET, PublishMechanism.RENAME, durability).durable is durable


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
        files: dict[bytes, bytes] | None = None,
        open_status: StatusCode | None = None,
        write_status: StatusCode | None = None,
        close_status: StatusCode | None = None,
        rename_status: StatusCode | None = None,
        posix_rename_status: StatusCode | None = None,
        remove_status: StatusCode | None = None,
        stat_status: StatusCode | None = None,
        fsync_status: StatusCode | None = None,
    ) -> None:
        self.files: dict[bytes, bytearray] = {
            name: bytearray(content) for name, content in (files or {}).items()
        }
        self.extensions = extensions
        self.open_status = open_status
        self.write_status = write_status
        self.close_status = close_status
        self.rename_status = rename_status
        self.posix_rename_status = posix_rename_status
        self.remove_status = remove_status
        self.stat_status = stat_status
        self.fsync_status = fsync_status

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
            Remove: self._on_remove,
            Rename: self._on_rename,
            Extended: self._on_extended,
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
        if self.open_status is not None:
            self._refuse(packet, self.open_status)
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
        if self.write_status is not None:
            self._refuse(packet, self.write_status)
            return
        stored = self.files[self.handles[packet.handle]]
        end = packet.offset + len(packet.data)
        if len(stored) < end:
            stored.extend(bytes(end - len(stored)))
        stored[packet.offset : end] = packet.data
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_close(self, packet: Close) -> None:
        _ = self.handles.pop(packet.handle, None)
        if self.close_status is not None:
            self._refuse(packet, self.close_status)
            return
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_stat(self, packet) -> None:
        if self.stat_status is not None:
            self._refuse(packet, self.stat_status)
        elif packet.path in self.files:
            self._reply(AttrsReply(packet.request_id, Attrs(size=len(self.files[packet.path]))))
        else:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))

    def _on_remove(self, packet: Remove) -> None:
        if self.remove_status is not None:
            self._refuse(packet, self.remove_status)
        elif self.files.pop(packet.path, None) is None:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        else:
            self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_rename(self, packet: Rename) -> None:
        if self.rename_status is not None:
            self._refuse(packet, self.rename_status)
        elif packet.newpath in self.files:
            # v3 RENAME cannot overwrite, and this is the measured behaviour of a real server.
            self._refuse(packet, StatusCode.FAILURE)
        elif packet.oldpath not in self.files:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
        else:
            self.files[packet.newpath] = self.files.pop(packet.oldpath)
            self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_extended(self, packet: Extended) -> None:
        if packet.name == POSIX_RENAME_NAME:
            self._on_posix_rename(PosixRename.from_extended(packet))
        elif packet.name == FSYNC_NAME:
            self._on_fsync(Fsync.from_extended(packet))
        else:
            self._refuse(packet, StatusCode.OP_UNSUPPORTED)

    def _on_posix_rename(self, packet: PosixRename) -> None:
        if self.posix_rename_status is not None:
            self._refuse(packet, self.posix_rename_status)
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
        elif self.fsync_status is not None:
            self._refuse(packet, self.fsync_status)
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
        result = await sftp.put(source, TARGET, staging_name=STAGED)

    assert result == UploadResult(
        transferred=14,
        remote_path=TARGET,
        mechanism=PublishMechanism.POSIX_RENAME,
        durability=Durability.FSYNCED,
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
        _ = await sftp.put(source, TARGET, staging_name=STAGED)

    assert server.kinds() == [
        "Init",
        "Open",
        "Write",
        "fsync@openssh.com",
        "Close",
        "posix-rename@openssh.com",
    ]


async def test_the_bytes_go_to_the_staging_name_and_never_to_the_destination(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, staging_name=STAGED)

    written = {server.handles.get(p.handle, STAGED) for p in server.seen if isinstance(p, Write)}
    assert server.opened(OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL) == [STAGED]
    assert TARGET not in written


async def test_the_staging_file_is_opened_exclusively(source: Path):
    # Without EXCL a name collision is two publishers writing into one file at different
    # offsets, which produces a result that is the wrong length or interleaved -- plausible,
    # and wrong.
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, staging_name=STAGED)

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
        result = await sftp.put(source, TARGET, staging_name=STAGED)

    assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert result.atomic
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


# --- the fallback ladder -------------------------------------------------------------------


async def test_a_server_without_posix_rename_uses_a_plain_rename(source: Path):
    # Atomic none the less, and that is not a hedge: v3 RENAME cannot overwrite, so a success
    # proves the destination appeared whole.
    server = PublishingServer(extensions=(FSYNC_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, staging_name=STAGED)

    assert result.mechanism is PublishMechanism.RENAME
    assert result.atomic
    assert "posix-rename@openssh.com" not in server.kinds()
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


async def test_an_advertised_extension_that_answers_unsupported_falls_through(source: Path):
    # Advertising and then refusing is a server contradicting itself, and it happens. The
    # fallback must be the tested path, not the theoretical one.
    server = PublishingServer(posix_rename_status=StatusCode.OP_UNSUPPORTED)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, staging_name=STAGED)

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
        result = await sftp.put(source, TARGET, staging_name=STAGED)

    assert result.mechanism is PublishMechanism.REMOVE_RENAME
    assert not result.atomic
    assert result.durability is Durability.UNAVAILABLE
    assert server.kinds() == [
        "Init",
        "Open",
        "Write",
        "Close",
        "Rename",
        "Stat",
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
    server = PublishingServer(extensions=(), rename_status=StatusCode.FAILURE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

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
        renames = 0

        def _on_rename(self, packet: Rename) -> None:
            LosesTheRace.renames += 1
            if LosesTheRace.renames == 2:
                # Somebody else got there in the window.
                self.files[TARGET] = bytearray(b"a concurrent writer's file")
            super()._on_rename(packet)

    LosesTheRace.renames = 0
    server = LosesTheRace(extensions=(), files={TARGET: b"yesterday"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

    assert bytes(server.files[STAGED]) == b"id,total\n1,42\n", "the only copy was deleted"
    assert "Remove" in server.kinds()[:-1], "the destination was removed, so this is the case"
    assert exc.value.__notes__[0] == (
        "the destination b'/incoming/report.csv' was removed and the rename that should have "
        "replaced it failed; the uploaded file is intact at "
        "b'/incoming/.report.csv.deadbeef.part' and is now the only copy of it"
    )


async def test_a_stat_that_errors_is_not_evidence_the_target_is_absent(source: Path):
    # Three states, and the third one decided explicitly: a STAT that fails for some reason
    # other than NO_SUCH_FILE tells us nothing, and "the server would not say" is not a
    # licence to delete anything.
    server = PublishingServer(
        extensions=(),
        rename_status=StatusCode.FAILURE,
        stat_status=StatusCode.PERMISSION_DENIED,
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

    assert exc.value.code == int(StatusCode.FAILURE), "the rename's refusal is the diagnosis"
    assert "Remove" not in server.kinds()[:-1]


# --- refusing to downgrade -----------------------------------------------------------------


async def test_require_atomic_refuses_before_moving_any_bytes(source: Path):
    # The pre-flight exists so a nine-gigabyte upload is not transferred and then refused.
    server = PublishingServer(extensions=(), files={TARGET: b"yesterday"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED, require_atomic=True)

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
        result = await sftp.put(source, TARGET, staging_name=STAGED, require_atomic=True)

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
            _ = await sftp.put(source, TARGET, staging_name=STAGED, require_atomic=True)

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
            _ = await sftp.put(source, TARGET, **flags)
    assert exc.value.args[0] == message
    assert "Open" not in server.kinds()


# --- durability -----------------------------------------------------------------------------


async def test_a_server_without_fsync_reports_no_durability_rather_than_claiming_it(
    source: Path,
):
    server = PublishingServer(extensions=(POSIX_RENAME_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, staging_name=STAGED)

    assert result.durability is Durability.UNAVAILABLE
    assert not result.durable
    assert result.atomic, "atomicity and durability are separate claims"
    assert "fsync@openssh.com" not in server.kinds()


async def test_fsync_can_be_switched_off_and_says_it_was_skipped(source: Path):
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, staging_name=STAGED, fsync=False)

    assert result.durability is Durability.SKIPPED
    assert "fsync@openssh.com" not in server.kinds()


async def test_a_refused_flush_is_recorded_rather_than_fatal(source: Path):
    # fsync defaults to on, so a server whose filesystem cannot flush must not fail every
    # upload. The caller who cannot accept that has require_fsync.
    server = PublishingServer(fsync_status=StatusCode.FAILURE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, staging_name=STAGED)

    assert result.durability is Durability.UNAVAILABLE
    assert result.mechanism is PublishMechanism.POSIX_RENAME


async def test_require_fsync_turns_a_refused_flush_into_a_failure(source: Path):
    server = PublishingServer(fsync_status=StatusCode.FAILURE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED, require_fsync=True)

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"
    assert TARGET not in server.files, "an unflushed file was published anyway"
    assert STAGED not in server.files, "the staging file was left behind"


async def test_require_fsync_refuses_a_server_that_does_not_advertise_it(source: Path):
    server = PublishingServer(extensions=(POSIX_RENAME_NAME,))
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as exc:
            _ = await sftp.put(source, TARGET, require_fsync=True)

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
        _ = await sftp.put(source, TARGET, staging_name=STAGED)
    assert server.fsynced == [STAGED]


# --- in place, on request --------------------------------------------------------------------


async def test_atomic_false_writes_the_destination_directly(source: Path):
    # What every other SFTP client does by default, and what a write-only drop directory may
    # require: staging needs the right to create *and* rename a second name.
    server = PublishingServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, TARGET, atomic=False)

    assert result.mechanism is PublishMechanism.IN_PLACE
    assert not result.atomic
    assert result.staged_at is None
    assert result.durability is Durability.FSYNCED
    assert server.kinds() == ["Init", "Open", "Write", "fsync@openssh.com", "Close"]
    assert server.opened(OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC) == [TARGET]


async def test_an_in_place_write_truncates_what_was_there(source: Path):
    server = PublishingServer(files={TARGET: b"a much longer previous version"})
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        _ = await sftp.put(source, TARGET, atomic=False)
    assert bytes(server.files[TARGET]) == b"id,total\n1,42\n"


# --- cleanup ----------------------------------------------------------------------------------


async def test_a_failed_transfer_removes_the_staging_file(source: Path):
    # Otherwise every failed run leaves litter in the directory a consumer is watching, which
    # is how people end up writing the cleanup cron job that deletes the wrong thing.
    server = PublishingServer(write_status=StatusCode.PERMISSION_DENIED)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

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
        with pytest.raises(ServerError):
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

    assert bytes(server.files[STAGED]) == b"another publisher's work in progress"
    assert "Remove" not in server.kinds()


async def test_a_cleanup_that_also_fails_is_reported_on_the_original_error(source: Path):
    # Swallowing it means the caller never learns a file was left on the server. Raising it
    # means replacing the real error with a housekeeping one.
    server = PublishingServer(
        write_status=StatusCode.PERMISSION_DENIED, remove_status=StatusCode.PERMISSION_DENIED
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

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
        write_status=StatusCode.PERMISSION_DENIED, close_status=StatusCode.FAILURE
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

    assert "PERMISSION_DENIED" in exc.value.args[0]
    assert exc.value.transferred == 0
    # And the handle really was closed anyway.
    assert any(isinstance(packet, Close) for packet in server.seen)


async def test_a_close_that_fails_on_the_success_path_fails_the_transfer(source: Path):
    # Some servers only discover a write failed when the file is closed -- NFS-backed ones
    # especially. A CLOSE that returns an error is the transfer failing, so it must not be
    # swallowed, and nothing may be published on the strength of it.
    server = PublishingServer(close_status=StatusCode.FAILURE)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)

    assert exc.value.args[0] == "server returned FAILURE: FAILURE"
    assert TARGET not in server.files, "published a file the server would not close"
    assert "posix-rename@openssh.com" not in server.kinds()


async def test_a_failing_close_on_a_download_does_not_replace_the_error_either(
    source: Path, tmp_path: Path
):
    # Same shape on the read side, which had the same `finally`.
    server = PublishingServer(files={TARGET: b"content"}, close_status=StatusCode.FAILURE)
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
    server = PublishingServer(open_status=StatusCode.PERMISSION_DENIED)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(PermissionDeniedError) as exc:
            _ = await sftp.put(source, TARGET, staging_name=STAGED)
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
        result = await sftp.put(source, str(destination), atomic=False, progress=watch)

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
        result = await sftp.put(source, str(destination), require_atomic=True, require_fsync=True)

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

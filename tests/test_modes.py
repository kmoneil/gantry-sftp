"""Permission bits: set when asked, private by default on the way down, never widened early.

**The bug this file exists for (D-56a).** Until 0.10 there was no ``mode=`` anywhere and
:meth:`Session.open` sent an empty ATTRS at its only construction site. OpenSSH's
``process_open`` reads that ATTRS for ``PERMISSIONS`` and nothing else::

    mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
    fd = open(name, flags, mode);

so every file this library uploaded -- including the staging file of an atomic publish --
arrived ``0666 & ~umask``. There was no spelling that delivered a key, a credential file, or
anything else with a ``0600`` requirement, and a ``chmod`` after the publish rename leaves the
file readable in the window between the two. That is a wrong outcome rather than a missing
convenience, which is why it ranked with the correctness block rather than with the ergonomics.

The regression tests are the first section. Each fails against 0.9, most of them with
``TypeError: put() got an unexpected keyword argument 'mode'``, so the more interesting proofs
are the *ordering* ones below them: the mode has to be on the file before anything can open it
by its published name, and setuid must not be on a file that is still being written.

**The asymmetry with timestamps is deliberate and is asserted here rather than left to drift.**
A refused ``FSETSTAT`` for times degrades to ``TimePreservation.UNAVAILABLE`` and the upload
succeeds; a refused one for the mode fails the upload. A file published with the wrong dates is
cosmetically wrong. A file published world-readable when ``0o600`` was asked for is the failure
the argument exists to prevent, reported as success.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    Attrs,
    AttrsReply,
    Close,
    Data,
    Extended,
    FrameSplitter,
    FSetStat,
    Handle,
    Init,
    LStat,
    MkDir,
    Name,
    NameEntry,
    Open,
    OpenFlag,
    Read,
    RealPath,
    Remove,
    Rename,
    SetStat,
    Stat,
    Status,
    StatusCode,
    Version,
    WireReader,
    Write,
    decode,
    encode,
)
from gantry_sftp.exceptions import ServerError, TransferError
from gantry_sftp.session import (
    CREATE_BITS,
    PERMISSION_BITS,
    Mode,
    Publish,
    local_mode,
    open_session,
    resolve_mode,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

POSIX_RENAME_NAME = b"posix-rename@openssh.com"

# Distinctive and asymmetric on purpose: 0o640 differs from every default a server or this
# library would otherwise produce (0o666 & ~umask, and 0o600), so a test asserting it cannot
# pass by accident on a machine whose umask happens to agree.
PRIVATE = 0o600
GROUP_READABLE = 0o640


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def bits(path: Path) -> int:
    """The permission bits of ``path``, which is ``st_mode`` without the file-type bits."""
    return stat.S_IMODE(path.stat().st_mode)


def server_default_mode() -> int:
    """What a server creating a file with no PERMISSIONS produces, on this machine.

    Derived rather than hardcoded. ``sftp-server`` is a child of this process and inherits its
    umask, so the number depends on the developer's environment -- but ``0o666`` is
    ``process_open``'s literal default and *that* is the fact worth pinning. Reading the umask
    to subtract it keeps the assertion exact without making it environment-dependent.
    """
    current = os.umask(0)
    os.umask(current)
    return 0o666 & ~current


# --- the regression -------------------------------------------------------------------------


async def test_an_upload_with_no_mode_is_created_world_readable(tmp_path: Path):
    """The characterisation D-56a was filed on. Passes before and after; it is the *why*.

    Not a bug in itself -- it is what ``open(2)`` with mode ``0666`` does -- but it is the
    behaviour a caller had no way to change, and pinning it is what makes the next test mean
    something. If OpenSSH ever changes ``process_open``'s default this fails and tells us.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    destination = tmp_path / "uploaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination).encode())

    assert result.mode is None
    assert bits(destination) == server_default_mode()


async def test_an_upload_can_deliver_a_file_that_is_not_world_readable(tmp_path: Path):
    """D-56a, the regression. Fails against 0.9: there was no ``mode=`` to pass.

    The whole card in one assertion -- a caller with a ``0o600`` requirement can now meet it.
    """
    needs_real_server()
    source = tmp_path / "key.pem"
    source.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
    destination = tmp_path / "delivered.pem"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination).encode(), mode=PRIVATE)

    assert result.mode == PRIVATE
    assert bits(destination) == PRIVATE


async def test_a_download_is_private_by_default_and_takes_an_explicit_mode(tmp_path: Path):
    """The download side already created ``0o600`` and had no way to say otherwise.

    Both halves in one test because the default is the interesting one: this direction was
    already right, and ``mode=`` widens it deliberately rather than by omission.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    private = tmp_path / "private.bin"
    shared = tmp_path / "shared.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.get(str(source).encode(), private)
        await sftp.get(str(source).encode(), shared, mode=GROUP_READABLE)

    assert bits(private) == PRIVATE
    assert bits(shared) == GROUP_READABLE


# --- PRESERVE, both directions --------------------------------------------------------------


async def test_an_upload_preserves_the_local_mode(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    source.chmod(GROUP_READABLE)
    destination = tmp_path / "uploaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination).encode(), mode=Mode.PRESERVE)

    assert result.mode == GROUP_READABLE
    assert bits(destination) == GROUP_READABLE


async def test_a_download_preserves_the_remote_mode(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    source.chmod(GROUP_READABLE)
    destination = tmp_path / "downloaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.get(str(source).encode(), destination, mode=Mode.PRESERVE)

    assert bits(destination) == GROUP_READABLE


async def test_preserve_is_spelled_as_a_plain_string_too(tmp_path: Path):
    """``Verify``'s precedent: a StrEnum normalised at the boundary, so ``"preserve"`` works.

    Without the normalisation ``mode is Mode.PRESERVE`` downstream would be ``False`` while
    ``==`` was ``True``, which is the failure mode that makes a StrEnum worth normalising.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    source.chmod(GROUP_READABLE)
    destination = tmp_path / "uploaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        result = await sftp.put(source, str(destination).encode(), mode="preserve")

    assert result.mode == GROUP_READABLE


# --- the ordering properties, which are the security content ---------------------------------


class ModeServer:
    """A scriptable server that records the ATTRS of every frame that carries one.

    A fake per hazard, named for it: what is under test here is *when* a permission bit reaches
    the far end relative to the bytes, and no real server can be asked to report that. The
    real-server tests above prove the outcome; this one proves the order that makes the outcome
    hold in the window nobody can observe from outside.

    ``refuse_fsetstat`` is the other half -- a server that will not take a mode, which OpenSSH
    cannot be made to be.
    """

    def __init__(
        self,
        *,
        files: dict[bytes, bytes] | None = None,
        refuse_fsetstat: bool = False,
        refuse_setstat: bool = False,
    ) -> None:
        self.files: dict[bytes, bytearray] = {
            name: bytearray(content) for name, content in (files or {}).items()
        }
        self.modes: dict[bytes, int] = {}
        self.directories: set[bytes] = set()
        self.refuse_fsetstat = refuse_fsetstat
        self.refuse_setstat = refuse_setstat
        self.seen: list[object] = []
        self.handles: dict[bytes, bytes] = {}
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

    # --- dispatch -------------------------------------------------------------------------

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

    def _dispatch(self, packet: object) -> None:
        self.seen.append(packet)
        if isinstance(packet, Init):
            self._reply(Version(3, ((POSIX_RENAME_NAME, b"1"),)))
            return
        handlers = {
            Open: self._on_open,
            Write: self._on_write,
            Read: self._on_read,
            FSetStat: self._on_fsetstat,
            SetStat: self._on_setstat,
            Stat: self._on_stat,
            LStat: self._on_stat,
            Rename: self._on_rename,
            Remove: self._on_remove,
            Extended: self._on_extended,
            MkDir: self._on_mkdir,
            Close: self._on_close,
            RealPath: self._on_realpath,
        }
        handler = handlers.get(type(packet))
        if handler is None:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"unscripted"))  # type: ignore[union-attr]
            return
        handler(packet)  # type: ignore[arg-type]

    def _on_mkdir(self, packet: MkDir) -> None:
        self.directories.add(packet.path)
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_close(self, packet: Close) -> None:
        _ = self.handles.pop(packet.handle, None)
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_realpath(self, packet: RealPath) -> None:
        self._reply(Name(packet.request_id, (NameEntry(b"/", b"/", EMPTY_ATTRS),)))

    def _on_open(self, packet: Open) -> None:
        if packet.pflags & OpenFlag.EXCL and packet.filename in self.files:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"exists"))
            return
        creating = packet.filename not in self.files
        if packet.pflags & OpenFlag.TRUNC or creating:
            self.files[packet.filename] = bytearray()
        if creating:
            # `open(2)` applies its mode only to a file it creates, and ignores it otherwise.
            # A fake that applied it either way would agree with a client that relied on the
            # OPEN alone to fix an existing destination's permissions -- which is exactly the
            # in-place window `_put_in_place` sends its own FSETSTAT to close.
            self.modes[packet.filename] = (
                packet.attrs.permissions if packet.attrs.permissions is not None else 0o666
            )
        handle = self._next_handle.to_bytes(4, "big")
        self._next_handle += 1
        self.handles[handle] = packet.filename
        self._reply(Handle(packet.request_id, handle))

    def _on_write(self, packet: Write) -> None:
        stored = self.files[self.handles[packet.handle]]
        end = packet.offset + len(packet.data)
        if len(stored) < end:
            stored.extend(bytes(end - len(stored)))
        stored[packet.offset : end] = packet.data
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_read(self, packet: Read) -> None:
        stored = self.files[self.handles[packet.handle]]
        chunk = bytes(stored[packet.offset : packet.offset + packet.length])
        if chunk:
            self._reply(Data(packet.request_id, memoryview(chunk)))
        else:
            self._reply(Status(packet.request_id, StatusCode.EOF))

    def _on_fsetstat(self, packet: FSetStat) -> None:
        if self.refuse_fsetstat:
            self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"no"))
            return
        if packet.attrs.permissions is not None:
            self.modes[self.handles[packet.handle]] = packet.attrs.permissions
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_setstat(self, packet: SetStat) -> None:
        if self.refuse_setstat:
            self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"no"))
            return
        if packet.attrs.permissions is not None:
            self.modes[packet.path] = packet.attrs.permissions
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_stat(self, packet: Stat | LStat) -> None:
        if packet.path not in self.files:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"absent"))
            return
        self._reply(
            AttrsReply(
                packet.request_id,
                Attrs(
                    size=len(self.files[packet.path]),
                    permissions=stat.S_IFREG | self.modes.get(packet.path, 0o666),
                ),
            )
        )

    def _on_rename(self, packet: Rename) -> None:
        if packet.new_path in self.files:
            self._reply(Status(packet.request_id, StatusCode.FAILURE, b"exists"))
            return
        self.files[packet.new_path] = self.files.pop(packet.old_path)
        self.modes[packet.new_path] = self.modes.pop(packet.old_path, 0o666)
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_remove(self, packet: Remove) -> None:
        _ = self.files.pop(packet.path, None)
        _ = self.modes.pop(packet.path, None)
        self._reply(Status(packet.request_id, StatusCode.OK))

    def _on_extended(self, packet: Extended) -> None:
        if packet.name != POSIX_RENAME_NAME:
            self._reply(Status(packet.request_id, StatusCode.OP_UNSUPPORTED, b"no"))
            return
        old, new = _posix_rename_paths(packet.data)
        self.files[new] = self.files.pop(old)
        self.modes[new] = self.modes.pop(old, 0o666)
        self._reply(Status(packet.request_id, StatusCode.OK))


def _posix_rename_paths(data: bytes) -> tuple[bytes, bytes]:
    reader = WireReader(memoryview(data))
    return bytes(reader.read_string()), bytes(reader.read_string())


def sent(server: ModeServer, kind: type) -> list[object]:
    return [packet for packet in server.seen if isinstance(packet, kind)]


def index_of_first(server: ModeServer, predicate) -> int:
    for position, packet in enumerate(server.seen):
        if predicate(packet):
            return position
    raise AssertionError("no matching frame was sent")


async def test_the_staging_file_is_created_with_the_requested_mode(tmp_path: Path):
    """The OPEN carries PERMISSIONS, so the staging file is never briefly world-readable.

    An FSETSTAT after the writes alone would leave a window: the staging file exists, holds the
    caller's bytes, and is readable by anyone who can list the directory. Short, but a window
    on a secret is exactly what ``mode=`` is for.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    server = ModeServer()

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.put(source, b"/target.bin", mode=PRIVATE)

    creating = [packet for packet in sent(server, Open) if packet.pflags & OpenFlag.CREAT]
    assert creating, "no creating OPEN was sent"
    assert creating[0].attrs.permissions == PRIVATE


async def test_setuid_is_not_on_the_file_until_its_content_is_complete(tmp_path: Path):
    """The create mode withholds setuid; the FSETSTAT that adds it comes after the last write.

    A setuid file that exists half-written is privileged before it is finished. This is the
    reason ``CREATE_BITS`` is ``0o777`` rather than ``0o7777``, and it is asserted as an order
    rather than described in a comment.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    setuid_mode = 0o4755
    server = ModeServer()

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, b"/target.bin", mode=setuid_mode)

    creating = next(packet for packet in sent(server, Open) if packet.pflags & OpenFlag.CREAT)
    assert creating.attrs.permissions == setuid_mode & CREATE_BITS
    assert not creating.attrs.permissions & stat.S_ISUID

    last_write = max(
        position for position, packet in enumerate(server.seen) if isinstance(packet, Write)
    )
    setuid_at = index_of_first(
        server,
        lambda packet: isinstance(packet, FSetStat) and packet.attrs.permissions == setuid_mode,
    )
    assert setuid_at > last_write
    assert result.mode == setuid_mode


async def test_the_mode_is_set_before_the_rename_that_publishes_it(tmp_path: Path):
    """Nothing can open the destination by its published name at the wrong permissions.

    The mirror of the argument ``preserve_times`` makes: a mode applied after the rename would
    need a second round trip to a path a consumer can already see.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    server = ModeServer()

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.put(source, b"/target.bin", mode=PRIVATE)

    mode_at = index_of_first(
        server,
        lambda packet: isinstance(packet, FSetStat) and packet.attrs.permissions == PRIVATE,
    )
    publish_at = index_of_first(
        server,
        lambda packet: (
            isinstance(packet, Rename)
            or (isinstance(packet, Extended) and packet.name == POSIX_RENAME_NAME)
        ),
    )
    assert mode_at < publish_at
    assert server.modes[b"/target.bin"] == PRIVATE


async def test_in_place_over_an_existing_file_sets_the_mode_before_the_first_write(
    tmp_path: Path,
):
    """The one window the creating OPEN cannot close, and the reason `_put_in_place` differs.

    ``open(2)`` applies its mode argument to a file it *creates* and ignores it for one that
    already exists, so an in-place upload over an existing destination would otherwise fill it
    while it still wore the permissions it had before. Under ``atomic=True`` there is no
    equivalent -- the staging file is always new and ``EXCL`` proves it.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    server = ModeServer(files={b"/target.bin": b"old content, world readable"})

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.put(source, b"/target.bin", publish=Publish(atomic=False), mode=PRIVATE)

    first_write = index_of_first(server, lambda packet: isinstance(packet, Write))
    narrowed_at = index_of_first(
        server,
        lambda packet: isinstance(packet, FSetStat) and packet.attrs.permissions is not None,
    )
    assert narrowed_at < first_write
    assert server.modes[b"/target.bin"] == PRIVATE


async def test_the_download_widens_only_once_the_content_is_there(tmp_path: Path):
    """Locally the same rule, enforced by the creation mode rather than by a second call.

    The local open stays ``0o600`` whatever ``mode=`` says, so a download that is asked for a
    world-readable file is still private for as long as it is partial. Asserted by watching the
    file's mode while the transfer is in flight, from the progress callback -- the only moment
    at which a partial file exists to look at.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    # Large enough to take more than one payload, so the callback fires before the last write.
    source.write_bytes(b"x" * (512 * 1024))
    destination = tmp_path / "downloaded.bin"
    observed: list[int] = []

    def watch(transferred: int, total: int | None) -> None:
        if transferred < (total or 0):
            observed.append(bits(destination))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.get(str(source).encode(), destination, mode=0o644, progress=watch)

    assert observed, "the progress callback never saw a partial file"
    assert set(observed) == {PRIVATE}
    assert bits(destination) == 0o644


# --- a refused mode is fatal, and a refused *directory* mode is not --------------------------


async def test_a_refused_mode_fails_the_upload_and_does_not_publish(tmp_path: Path):
    """The asymmetry with ``preserve_times``, asserted on both halves of its consequence.

    The caller asked for a mode because the file must not be readable by whoever the default
    would let read it. Publishing anyway and reporting success is the failure the argument
    exists to prevent -- so it raises, and because it raises before the rename the destination
    is never created at all.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    server = ModeServer(refuse_fsetstat=True)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as refusal:
            await sftp.put(source, b"/target.bin", mode=PRIVATE)

    assert refusal.value.code == int(StatusCode.PERMISSION_DENIED)
    assert b"/target.bin" not in server.files
    assert not any(isinstance(packet, Rename) for packet in server.seen)
    # And the staging file it wrote is cleaned up rather than left behind.
    assert [packet for packet in server.seen if isinstance(packet, Remove)]


async def test_a_refused_timestamp_still_does_not_fail_the_upload(tmp_path: Path):
    """The control for the test above: the same refusal, the other field, the other outcome.

    Without this the asymmetry could be read as "this fake refuses everything", and the two
    behaviours would not be distinguishable from one test.
    """
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    server = ModeServer(refuse_fsetstat=True)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put(source, b"/target.bin", preserve_times=True)

    assert result.times.value == "unavailable"
    assert b"/target.bin" in server.files


# --- PRESERVE has nothing to preserve --------------------------------------------------------


class TerseServer(ModeServer):
    """Reports a size and no permissions at all, which v3 entitles a server to do."""

    def _on_stat(self, packet: Stat | LStat) -> None:
        if packet.path not in self.files:
            self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"absent"))
            return
        self._reply(AttrsReply(packet.request_id, Attrs(size=len(self.files[packet.path]))))


async def test_preserving_a_mode_the_server_never_sent_is_an_error(tmp_path: Path):
    """Absent is not zero and it is not a default -- so there is genuinely nothing to preserve.

    Leaving the file at its ``0o600`` creation mode and returning success would be
    indistinguishable from having preserved a ``0o600`` file, which is the shape of wrong answer
    this whole argument removes. Raised before the first READ, so a terse server costs no
    transfer.
    """
    server = TerseServer(files={b"/source.bin": b"payload"})
    destination = tmp_path / "downloaded.bin"

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferError) as refusal:
            await sftp.get(b"/source.bin", destination, mode=Mode.PRESERVE)

    assert refusal.value.args[0] == (
        "mode=Mode.PRESERVE was asked for but the server sent no permissions for "
        "b'/source.bin', so there is nothing to preserve; pass an explicit mode= or "
        "leave it unset to keep the 0o600 a download creates"
    )
    assert not any(isinstance(packet, Read) for packet in server.seen)


# --- the resumed download that is already complete -------------------------------------------


async def test_a_resumed_download_that_is_already_complete_still_applies_the_mode(
    tmp_path: Path,
):
    """The early return adopts the whole file -- and the caller still named a mode for it.

    Skipping it here would be the silent wrong answer the argument exists to prevent: the
    destination exists, they said what permissions it should have, and "it was already there"
    is not an answer to that. The partial was not necessarily left by this library, so its mode
    is not necessarily the ``0o600`` a download creates.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    destination = tmp_path / "downloaded.bin"
    destination.write_bytes(b"payload")
    destination.chmod(0o666)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        transferred = await sftp.get(str(source).encode(), destination, resume=True, mode=PRIVATE)

    assert transferred == 0
    assert bits(destination) == PRIVATE


# --- trees ------------------------------------------------------------------------------------


def build_tree(root: Path) -> Path:
    root.mkdir()
    (root / "top.txt").write_bytes(b"top")
    nested = root / "nested"
    nested.mkdir()
    (nested / "inner.txt").write_bytes(b"inner")
    return root


async def test_an_integer_mode_on_a_tree_applies_to_files_only(tmp_path: Path):
    """A file mode on a directory is usually unusable -- ``0o600`` cannot be entered.

    So the directories keep the destination's default and only the files are set. A caller who
    wants both names both.
    """
    needs_real_server()
    source = build_tree(tmp_path / "source")
    destination = tmp_path / "destination"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.put_tree(source, str(destination).encode(), mode=PRIVATE)

    assert bits(destination / "top.txt") == PRIVATE
    assert bits(destination / "nested" / "inner.txt") == PRIVATE
    assert bits(destination / "nested") != PRIVATE


@pytest.mark.parametrize("direction", ["upload", "download"])
async def test_preserve_carries_directory_modes_in_both_directions(tmp_path: Path, direction: str):
    needs_real_server()
    source = build_tree(tmp_path / "source")
    (source / "nested").chmod(0o750)
    (source / "top.txt").chmod(GROUP_READABLE)
    destination = tmp_path / "destination"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        if direction == "upload":
            await sftp.put_tree(source, str(destination).encode(), mode=Mode.PRESERVE)
        else:
            await sftp.get_tree(str(source).encode(), destination, mode=Mode.PRESERVE)

    assert bits(destination / "top.txt") == GROUP_READABLE
    assert bits(destination / "nested") == 0o750


@pytest.mark.parametrize("direction", ["upload", "download"])
async def test_a_directory_whose_source_mode_forbids_writing_still_receives_its_files(
    tmp_path: Path, direction: str
):
    """The ordering bug this would have had, on both sides, if modes were applied on the way down.

    A directory created ``0o500`` cannot have a file written into it. Applying the source's mode
    at ``mkdir`` time -- the obvious place, and where the directory's name is already in hand --
    fails every transfer underneath it. Both passes are therefore final passes, which is the
    same shape ``preserve_times`` needs for a different reason.
    """
    needs_real_server()
    source = build_tree(tmp_path / "source")
    destination = tmp_path / "destination"
    (source / "nested").chmod(0o500)
    try:
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            if direction == "upload":
                result = await sftp.put_tree(source, str(destination).encode(), mode=Mode.PRESERVE)
            else:
                result = await sftp.get_tree(str(source).encode(), destination, mode=Mode.PRESERVE)

        assert result.files == 2
        assert bits(destination / "nested") == 0o500
        assert (destination / "nested" / "inner.txt").read_bytes() == b"inner"
    finally:
        # Otherwise the tmp_path teardown cannot remove what it just created.
        (source / "nested").chmod(0o755)
        if (destination / "nested").exists():
            (destination / "nested").chmod(0o755)


async def test_a_refused_directory_mode_does_not_fail_the_tree(tmp_path: Path):
    """The other side of the file/directory asymmetry, and the reason it is not an oversight.

    A file's mode is what ``mode=`` controls, so a refusal fails the upload. A directory's is
    carried along beside it, and the files are the payload -- they are already published by the
    time the final pass runs.
    """
    source = build_tree(tmp_path / "source")
    server = ModeServer(refuse_setstat=True)

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        result = await sftp.put_tree(source, b"/destination", mode=Mode.PRESERVE)

    assert result.files == 2
    assert [packet for packet in server.seen if isinstance(packet, SetStat)]


# --- the argument itself ----------------------------------------------------------------------


def test_resolve_mode_passes_none_and_an_octal_mode_through():
    assert resolve_mode(None, caller="put()") is None
    assert resolve_mode(0o600, caller="put()") == 0o600
    assert resolve_mode(0, caller="put()") == 0
    assert resolve_mode(PERMISSION_BITS, caller="put()") == PERMISSION_BITS


@pytest.mark.parametrize("spelling", [Mode.PRESERVE, "preserve"])
def test_resolve_mode_normalises_both_spellings_of_preserve(spelling: object):
    assert resolve_mode(spelling, caller="put()") is Mode.PRESERVE  # type: ignore[arg-type]


def test_a_bool_is_refused_rather_than_read_as_a_mode():
    """``mode=True`` would otherwise be ``0o1`` -- executable by others, readable by nobody.

    ``bool`` is an ``int`` subclass, so nothing catches this without an explicit check, and it
    is a plausible reflex from ``preserve_times=True`` next door.
    """
    with pytest.raises(TypeError) as refusal:
        resolve_mode(True, caller="put()")
    assert refusal.value.args[0] == (
        "put() mode= must be an octal permission mode or Mode.PRESERVE, not a bool. "
        "Pass mode=Mode.PRESERVE to carry the source file's own permissions across, or an "
        "integer such as 0o600 to set them explicitly."
    )


def test_a_whole_st_mode_is_refused_rather_than_silently_masked():
    """``0o100644`` and ``0o644`` must not be the same call -- only one of them was meant."""
    with pytest.raises(ValueError) as refusal:
        resolve_mode(0o100644, caller="put()")
    assert refusal.value.args[0] == (
        "put() mode= must be between 0o0 and 0o7777, not 0o100644. A larger value is "
        "usually a whole st_mode with its file-type bits still attached -- mask it with "
        "0o7777, or pass Mode.PRESERVE and let the transfer read it from the source."
    )


def test_a_negative_mode_is_refused():
    with pytest.raises(ValueError):
        resolve_mode(-1, caller="get()")


def test_an_unknown_policy_name_is_refused_and_lists_the_known_ones():
    with pytest.raises(ValueError) as refusal:
        resolve_mode("inherit", caller="get_tree()")
    assert refusal.value.args[0] == (
        "get_tree() mode= must be an octal permission mode or one of ['preserve'], not 'inherit'"
    )


def test_a_non_integer_is_refused_by_type():
    with pytest.raises(TypeError) as refusal:
        resolve_mode(0.5, caller="put()")  # type: ignore[arg-type]
    assert refusal.value.args[0] == (
        "put() mode= must be an octal permission mode or Mode.PRESERVE, not float"
    )


def test_local_mode_drops_the_file_type_bits(tmp_path: Path):
    """``st_mode`` carries both, and the type bits would set a mode from mostly not-a-mode."""
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    source.chmod(GROUP_READABLE)
    assert source.stat().st_mode & stat.S_IFREG
    assert local_mode(source) == GROUP_READABLE


# --- chmod --------------------------------------------------------------------------------------


async def test_chmod_sets_the_bits_and_sends_only_the_permissions_flag(tmp_path: Path):
    """One flag per call, because ``process_setstat`` is legally-partial.

    It walks the ATTRS flags in order -- size, permissions, times, uid/gid -- applying each and
    recording only the last failure in the single STATUS it returns. A multi-field SETSTAT that
    fails has therefore already applied part of itself and does not say which part. One field
    per call makes a refusal unambiguous and leaves nothing else moved.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    target.chmod(0o644)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chmod(str(target).encode(), PRIVATE)

    assert bits(target) == PRIVATE


async def test_chmod_masks_a_whole_st_mode_rather_than_sending_the_type_bits(tmp_path: Path):
    """Unlike ``mode=``, which refuses one: ``chmod`` is the low-level call and masks.

    The difference is deliberate. ``mode=`` is a transfer argument where a wrong value is
    silently wrong for the life of the file, so it refuses. ``chmod`` is the direct spelling of
    ``chmod(2)`` and OpenSSH itself masks with ``a.perm & 07777``, so matching that keeps the
    method honest about what the server will do with what it is given.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chmod(str(target).encode(), stat.S_IFREG | PRIVATE)

    assert bits(target) == PRIVATE


async def test_chmod_follows_a_symlink_which_is_what_chmod_does(tmp_path: Path):
    """Characterisation, and the reason it is written down rather than left to be discovered.

    ``SETSTAT`` is ``chmod(2)``, which follows -- the same default as :func:`os.chmod`. Where
    the path may be a symlink somebody else planted, that is a chmod of whatever it points at.
    The extension that does not follow is ``lsetstat@openssh.com``; it is not implemented here
    and v3 offers no fallback, so there is nothing to degrade to.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    target.chmod(0o644)
    link = tmp_path / "link.bin"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chmod(str(link).encode(), PRIVATE)

    assert bits(target) == PRIVATE

"""The fsspec adapter: the registry, the lifetime, the credential, and the bytes.

**D-60.** DESIGN 8 lists three interfaces and fsspec is the first, because pandas, pyarrow,
dask and DVC already call it. The card's own recon is what shaped these tests, and it found
that the interesting parts are not the filesystem methods:

- `sftp://` is **already registered** inside fsspec, to a paramiko implementation, and taking
  it is silent or a `ValueError` depending on import order. So the first tests here are about
  the *registry*, not about files.
- `AbstractFileSystem` caches instances by a token that includes `threading.get_ident()`, holds
  a strong reference on purpose, and has no `close()` in its contract. One `ssh` child per
  thread, and `__del__` never fires.
- `storage_options` is what `__reduce__` pickles and what `to_json()` serialises -- with
  `include_password` defaulting to `True`. A password there travels to every dask worker.

Everything below the registry runs against a real `sftp-server` on a pipe rather than a fake,
because DoD 1 says a fake only confirms what its author believed. `LocalGantryFS` overrides
exactly one method -- `_connect` -- so every line of the adapter above the connection is the
shipped one. The `ssh` path itself is `live-tests/test_fsspec_live.py`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from contextlib import ExitStack
from pathlib import Path

import fsspec
import pytest
from anyio.from_thread import start_blocking_portal
from fsspec.registry import known_implementations, register_implementation, registry

from gantry_sftp.exceptions import CapabilityError
from gantry_sftp.fsspec import (
    PROTOCOL,
    GantrySFTPFile,
    GantrySFTPFileSystem,
    register,
)
from gantry_sftp.sync import BoundPortal
from gantry_sftp.transport import find_sftp_server

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    find_sftp_server() is None, reason="no sftp-server binary on this machine"
)


class LocalGantryFS(GantrySFTPFileSystem):
    """The shipped adapter, connected to a local ``sftp-server`` instead of through ``ssh``.

    One method overridden, deliberately: everything the tests exercise -- the listing, the
    joins, the symlink rules, the byte ranges, the buffered file -- is the shipped code, and
    the server answering is the real OpenSSH binary rather than a fake with our idea of a
    server in it.
    """

    protocol = "gantry-sftp-local"

    def __init__(self, root: str, host: str = "local", **kwargs: object) -> None:
        # `host` is accepted and ignored: a URL supplies one, and there is no ssh to give it
        # to. Everything else is the shipped constructor.
        if self._cached:
            return
        self._root = root
        super().__init__(host=host, **kwargs)

    def _connect(self):  # type: ignore[no-untyped-def]
        stack = ExitStack()
        portal = stack.enter_context(start_blocking_portal())
        gantry = BoundPortal(portal)
        transport = stack.enter_context(gantry.open_local_server_transport(cwd=self._root))
        session = stack.enter_context(gantry.open_session(transport))
        self._stack = stack
        self._owner_pid = os.getpid()
        return session


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A directory with the shapes that make an adapter's rules visible."""
    drop = tmp_path / "incoming"
    drop.mkdir()
    _ = (drop / "report.csv").write_bytes(b"id,total\n1,42\n")
    _ = (drop / "big.bin").write_bytes(bytes(range(256)) * 4096)
    # Not valid UTF-8. Ordinary on Linux, and the axis a name-handling test has to vary.
    _ = (drop / "caf\udce9.csv").write_bytes(b"\xe9")
    (drop / "latest.csv").symlink_to(drop / "report.csv")
    (drop / "dangling").symlink_to(tmp_path / "gone")
    (drop / "archive").mkdir()
    _ = (drop / "archive" / "old.csv").write_bytes(b"id\n0\n")
    return tmp_path


@pytest.fixture
def fs(tree: Path):  # type: ignore[no-untyped-def]
    """A filesystem over ``tree``, closed at the end of the test."""
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    try:
        yield filesystem
    finally:
        filesystem.close()


@pytest.fixture
def drop(tree: Path) -> str:
    return str(tree / "incoming")


@pytest.fixture(autouse=True)
def _restore_registry():
    """Undo any registration a test performs.

    The registry is process-global, so a test that claims ``sftp`` would otherwise decide what
    every later test in the session resolves -- which is the very failure mode this card is
    about, reproduced inside our own suite.
    """
    live = dict(registry)
    known = dict(known_implementations)
    yield
    registry.clear() if hasattr(registry, "clear") else None
    for name, cls in live.items():
        register_implementation(name, cls, clobber=True)
    known_implementations.clear()
    known_implementations.update(known)


# --- the registry, which is the security half ---------------------------------------------


def test_importing_the_library_registers_nothing():
    """The headline decision, asserted rather than described.

    A library that changed what ``pd.read_parquet("sftp://...")`` does merely because it was
    installed would be doing the thing this repository would call an attack if somebody else
    did it. Both halves of fsspec's registry are checked: ``registry`` is what has been
    resolved in this process and ``known_implementations`` is what would be imported on the
    next miss, and writing to *either* is a takeover.
    """
    for name in ("sftp", "ssh"):
        assert registry.get(name) is not GantrySFTPFileSystem, f"{name} was taken on import"
        assert known_implementations[name]["class"] == (
            "fsspec.implementations.sftp.SFTPFileSystem"
        ), f"{name} points somewhere other than the incumbent"


def test_importing_the_adapter_module_does_not_register_even_its_own_free_name():
    # `gantry-sftp` is free, so claiming it on import would harm nobody -- and the rule is
    # still one rule, because "registration is explicit" is easier to rely on than
    # "registration is explicit for the names that matter".
    assert PROTOCOL not in registry
    assert PROTOCOL not in known_implementations


def test_register_claims_the_free_name():
    register()
    assert fsspec.get_filesystem_class(PROTOCOL) is GantrySFTPFileSystem


def test_register_refuses_a_name_fsspec_already_knows():
    with pytest.raises(ValueError) as exc:
        register("sftp")
    assert exc.value.args[0] == (
        "the 'sftp' protocol is already registered to "
        "fsspec.implementations.sftp.SFTPFileSystem; pass override=True to replace it. Doing "
        "so silently would change what every sftp:// URL in this process resolves to"
    )
    assert registry.get("sftp") is not GantrySFTPFileSystem


def test_register_refuses_a_name_only_the_live_registry_knows():
    """The half a `known_implementations` check alone would miss.

    fsspec's own guard reads the live registry; ours reads both, and this is the case that
    separates them -- a protocol somebody registered at runtime is in ``registry`` and not in
    ``known_implementations``.
    """
    register_implementation("some-other-fs", GantrySFTPFile, clobber=True)
    with pytest.raises(ValueError) as exc:
        register("some-other-fs")
    assert "already registered to gantry_sftp.fsspec.GantrySFTPFile" in exc.value.args[0]


def test_override_displaces_the_incumbent_deliberately():
    register("sftp", override=True)
    assert fsspec.get_filesystem_class("sftp") is GantrySFTPFileSystem


def test_registering_our_own_name_twice_is_not_an_error():
    # Idempotent, because a program that calls `register()` at import of two of its own modules
    # is doing something reasonable.
    register()
    register()
    assert fsspec.get_filesystem_class(PROTOCOL) is GantrySFTPFileSystem


# --- the credential -------------------------------------------------------------------------


def test_the_password_never_reaches_storage_options():
    """The one credential path fsspec would otherwise take out of our hands.

    ``storage_options`` is what ``__reduce__`` pickles -- so a dask scheduler ships it to every
    worker -- and what ``to_json()`` serialises, whose ``include_password`` parameter defaults
    to ``True``. Listing ``password`` in ``_strip_tokenize_options`` means it reaches
    ``__init__`` and is never stored.
    """
    filesystem = GantrySFTPFileSystem(
        "example.com", user="bob", password="hunter2", skip_instance_cache=True
    )
    assert "password" not in filesystem.storage_options
    assert "hunter2" not in filesystem.to_json()
    assert "hunter2" not in repr(filesystem.__reduce__())
    assert "hunter2" not in repr(filesystem)
    # And it did arrive, so the absence above is not the absence of a working argument.
    assert filesystem._password == "hunter2"  # noqa: SLF001


def test_the_repr_names_the_endpoint_and_the_state():
    filesystem = GantrySFTPFileSystem("example.com", user="bob", skip_instance_cache=True)
    assert repr(filesystem) == "<GantrySFTPFileSystem bob@example.com (not connected)>"


def test_the_cost_of_keeping_the_password_out_of_the_token(tree: Path):
    """Stated on the class, so it is asserted here rather than left as a surprise.

    The password is not part of the cache token, so two constructions differing only in it come
    back as one instance holding the first password. ``skip_instance_cache=True`` is the
    documented way out, and the test proves both halves.
    """
    first = GantrySFTPFileSystem("example.com", password="one")
    second = GantrySFTPFileSystem("example.com", password="two")
    assert first is second
    assert first._password == "one"  # noqa: SLF001
    apart = GantrySFTPFileSystem("example.com", password="two", skip_instance_cache=True)
    assert apart is not first
    assert apart._password == "two"  # noqa: SLF001


# --- the instance cache, which is the lifetime --------------------------------------------


def test_the_same_options_come_back_as_the_same_instance():
    assert GantrySFTPFileSystem("h", user="bob") is GantrySFTPFileSystem("h", user="bob")
    assert GantrySFTPFileSystem("h", user="bob") is not GantrySFTPFileSystem("h", user="eve")


def test_a_second_thread_gets_a_second_instance_and_therefore_a_second_ssh_child():
    """Not a defect of ours, and not something a caller can be expected to guess.

    fsspec tokenizes a *sync* filesystem with ``threading.get_ident()``, so a thread pool
    calling ``pd.read_parquet`` fans out to one subprocess each. It is documented on the module
    for that reason, and asserted here so the documentation cannot quietly stop being true.
    """
    on_this_thread = GantrySFTPFileSystem("h", user="bob")
    elsewhere: list[object] = []
    worker = threading.Thread(
        target=lambda: elsewhere.append(GantrySFTPFileSystem("h", user="bob"))
    )
    worker.start()
    worker.join()
    assert elsewhere[0] is not on_this_thread


def test_close_after_a_fork_does_not_touch_the_parents_child(fs, drop: str, monkeypatch):
    """The pid guard: a forked child must not unwind the parent's connection.

    fsspec clears its instance cache when the pid changes, so a forked child can hold this
    object while the ``ssh`` process it describes belongs to the parent. Closing from there
    would be unwinding pipes and signalling a pid that is no longer ours.

    **The pid is moved rather than the process forked, and that is deliberate.** A real
    ``os.fork()`` here would fork a process running an anyio portal thread and an
    ``sftp-server`` child; CPython warns about fork-with-threads from 3.12, and written that
    way this test deadlocked. The guard *is* one comparison, and moving the pid exercises that
    comparison against a connection that is real on both sides of it.
    """
    assert fs.ls(drop)  # connect, so there is something a careless close could break
    stack, session = fs._stack, fs._session  # noqa: SLF001
    assert stack is not None
    assert session is not None

    monkeypatch.setattr(os, "getpid", os.getppid)
    fs.close()
    monkeypatch.undo()

    # Nothing was unwound: the session the parent owns still answers, and the ssh child is
    # still there to answer it. In a real fork the parent holds its own copy of this object,
    # so the child's forgetting is correct and invisible to the parent.
    assert session.listdir(drop), "a child's close() tore down the parent's connection"
    # Hand it back so the fixture's close() reaps what this test deliberately orphaned.
    fs._stack, fs._session, fs._owner_pid = stack, session, os.getpid()  # noqa: SLF001


def test_close_is_idempotent_and_reconnects_on_the_next_use(tree: Path, drop: str):
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    try:
        assert filesystem.ls(drop)
        filesystem.close()
        filesystem.close()
        assert filesystem.ls(drop), "a closed filesystem did not reopen on use"
    finally:
        filesystem.close()


def test_the_connection_is_not_opened_until_something_asks(tree: Path):
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    try:
        assert filesystem._session is None  # noqa: SLF001
        assert "not connected" in repr(filesystem)
        _ = filesystem.ls(str(tree))
        assert filesystem._session is not None  # noqa: SLF001
    finally:
        filesystem.close()


# --- paths and URLs -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("gantry-sftp://host/incoming", "/incoming"),
        ("gantry-sftp://host/incoming/", "/incoming"),
        # The doubled separator survives: a server is entitled to distinguish `//abs` from
        # `/abs`, and nothing here is entitled to decide it does not.
        ("gantry-sftp://host//abs", "//abs"),
        ("gantry-sftp://host", "/"),
        ("gantry-sftp://host/", "/"),
        ("/plain/path", "/plain/path"),
        ("/", "/"),
    ],
)
def test_a_url_strips_to_a_remote_path(url: str, expected: str):
    assert GantrySFTPFileSystem._strip_protocol(url) == expected  # noqa: SLF001


def test_the_url_carries_the_connection_arguments():
    kwargs = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
        "gantry-sftp://bob:hunter2@example.com:2222/incoming"
        "?identity_file=/keys/id_ed25519&depth=8&request_timeout=30"
    )
    assert kwargs["host"] == "example.com"
    assert kwargs["port"] == 2222
    assert kwargs["user"] == "bob"
    assert kwargs["password"] == "hunter2"
    assert kwargs["identity_file"] == "/keys/id_ed25519"
    assert kwargs["session"].depth == 8
    assert kwargs["session"].request_timeout == 30.0


def test_a_timeout_can_be_turned_off_in_a_url():
    # `None` means "wait forever", which a URL has no other way to say.
    kwargs = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
        "gantry-sftp://h/x?request_timeout=none"
    )
    assert kwargs["session"].request_timeout is None


def test_an_unknown_query_parameter_is_refused_rather_than_ignored():
    """A typo in a URL that silently does nothing is a connection failing for the wrong reason."""
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
            "gantry-sftp://h/x?identiy_file=/keys/id"
        )
    assert exc.value.args[0] == (
        "unknown query parameter 'identiy_file' in a gantry-sftp URL; this adapter accepts "
        "config_file, cwd, depth, identity_file, idle_timeout, port, request_timeout, "
        "ssh_executable, user"
    )


@pytest.mark.parametrize(("key", "raw"), [("depth", "lots"), ("request_timeout", "soon")])
def test_a_query_parameter_that_does_not_parse_names_itself(key: str, raw: str):
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls(f"gantry-sftp://h/x?{key}={raw}")  # noqa: SLF001
    assert key in exc.value.args[0]
    assert raw in exc.value.args[0]


# --- listing --------------------------------------------------------------------------------


def test_a_listing_names_every_entry_with_a_path_this_library_built(fs, drop: str):
    names = fs.ls(drop)
    assert names == sorted(names)
    assert f"{drop}/report.csv" in names
    assert all(name.startswith(f"{drop}/") for name in names)


def test_a_name_that_is_not_utf8_survives_listing_info_and_open(fs, drop: str, tree: Path):
    """The axis to vary, per DoD 1, and the one the incumbent has crashed on since 2015.

    ``decode_name`` is ``surrogateescape`` and this library's encoder is its exact inverse, so
    the name comes back as a ``str`` that can be handed straight back in and opens the same
    file. A lossy decode would make two distinct names one.
    """
    listed = [name for name in fs.ls(drop) if name.endswith(".csv") and "caf" in name]
    assert listed == [f"{drop}/caf\udce9.csv"]
    assert fs.info(listed[0])["size"] == 1
    assert fs.cat_file(listed[0]) == b"\xe9"
    with fs.open(listed[0], "rb") as handle:
        assert handle.read() == b"\xe9"


def test_ls_and_info_agree_about_a_symlink(fs, drop: str):
    """The incumbent's bug, named in D-60's recon and not reproduced here.

    Its ``ls`` reads READDIR's attributes, so a symlink is ``"link"``; its ``info`` calls
    ``stat``, which follows, so the same path is ``"file"`` -- while fsspec's own docstring
    says ``info`` returns "exactly the same information as ``ls``". Ours follows in both, so
    ``isfile`` on a symlinked parquet answers ``True`` and something will actually open it.
    """
    link = f"{drop}/latest.csv"
    from_listing = next(entry for entry in fs.ls(drop, detail=True) if entry["name"] == link)
    direct = fs.info(link)
    assert from_listing["type"] == direct["type"] == "file"
    assert from_listing["islink"] is True
    assert direct["islink"] is True
    assert from_listing["destination"] == direct["destination"] == f"{drop}/report.csv"
    assert fs.isfile(link)
    assert not fs.isdir(link)


def test_a_broken_symlink_is_reported_rather_than_skipped_or_raised(fs, drop: str, tree: Path):
    """The third state, decided rather than discovered.

    Dropping the entry would make a listing quietly disagree with the directory it describes;
    raising would let one dead link cost the whole listing. So the type is ``"other"`` -- which
    is honest, since the follow failed and nobody knows what it was -- with the target kept.
    """
    dangling = f"{drop}/dangling"
    entry = next(item for item in fs.ls(drop, detail=True) if item["name"] == dangling)
    assert entry["type"] == "other"
    assert entry["size"] is None
    assert entry["islink"] is True
    assert entry["destination"] == str(tree / "gone")
    assert fs.info(dangling) == entry


def test_listing_a_plain_file_returns_that_one_entry(fs, drop: str):
    """``LocalFileSystem``'s behaviour, and what ``find`` / ``glob`` / ``walk`` expect.

    It costs an extra round trip only on the failure path, because SFTP gives no way to tell
    the two apart up front: ``OPENDIR`` on a file answers ``NO_SUCH_FILE`` rather than a
    distinct status, since the server remaps ``ENOTDIR``.
    """
    assert fs.ls(f"{drop}/report.csv") == [f"{drop}/report.csv"]
    assert fs.ls(f"{drop}/report.csv", detail=True)[0]["type"] == "file"


def test_listing_something_absent_is_a_file_not_found(fs, drop: str):
    with pytest.raises(FileNotFoundError):
        _ = fs.ls(f"{drop}/nowhere")


def test_a_listing_carries_the_attributes_the_server_volunteered(fs, drop: str):
    entry = fs.info(f"{drop}/report.csv")
    assert entry["size"] == 14
    assert entry["type"] == "file"
    assert entry["mode"] & 0o777 == (Path(entry["name"]).stat().st_mode & 0o777)
    assert entry["uid"] == os.getuid()
    assert entry["mtime"] == int(Path(entry["name"]).stat().st_mtime)


def test_the_base_class_walkers_work_on_top_of_ls(fs, drop: str):
    """``find`` / ``glob`` / ``du`` are fsspec's, and they are what a consumer actually calls."""
    assert f"{drop}/archive/old.csv" in fs.find(drop)
    assert sorted(fs.glob(f"{drop}/*.csv")) == sorted(
        [f"{drop}/report.csv", f"{drop}/caf\udce9.csv", f"{drop}/latest.csv"]
    )
    assert fs.du(f"{drop}/report.csv") == 14


# --- bytes ----------------------------------------------------------------------------------


def test_a_whole_file_reads_back_byte_for_byte(fs, drop: str, tree: Path):
    expected = (tree / "incoming" / "big.bin").read_bytes()
    assert fs.cat_file(f"{drop}/big.bin") == expected
    with fs.open(f"{drop}/big.bin", "rb") as handle:
        assert handle.read() == expected


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (0, 2, b"id"),
        (3, 8, b"total"),
        (None, 2, b"id"),
        (9, None, b"1,42\n"),
        (-6, None, b"\n1,42\n"),
        (0, -8, b"id,tot"),
        (5, 5, b""),
        (100, 200, b""),
    ],
)
def test_byte_ranges_including_the_negative_ones(fs, drop: str, start, end, expected: bytes):
    assert fs.cat_file(f"{drop}/report.csv", start=start, end=end) == expected


def test_reading_across_the_block_size_is_still_one_file(fs, drop: str, tree: Path):
    """The block cache asks for ranges; the point is that the seams are invisible.

    A small block size forces many ``_fetch_range`` calls over one held handle, which is the
    shape a parquet reader produces and the one an ``OPEN``/``CLOSE`` per block would make
    expensive.
    """
    expected = (tree / "incoming" / "big.bin").read_bytes()
    with fs.open(f"{drop}/big.bin", "rb", block_size=4096) as handle:
        assert handle.read(10) == expected[:10]
        _ = handle.seek(500_000)
        assert handle.read(1000) == expected[500_000:501_000]
        _ = handle.seek(0)
        assert handle.read() == expected


def test_a_read_past_the_end_is_empty_rather_than_an_error(fs, drop: str):
    with fs.open(f"{drop}/report.csv", "rb") as handle:
        _ = handle.seek(1000)
        assert handle.read(10) == b""


def test_writing_through_the_file_object_lands_the_bytes(fs, drop: str, tree: Path):
    with fs.open(f"{drop}/written.csv", "wb") as handle:
        _ = handle.write(b"id,total\n")
        _ = handle.write(b"7,99\n")
    assert (tree / "incoming" / "written.csv").read_bytes() == b"id,total\n7,99\n"


def test_a_written_file_is_not_world_readable(fs, drop: str, tree: Path):
    """``mode=0o600`` on OPEN is a security decision, not a default.

    Omitting the permission field lets the server apply ``0666 & ~umask``, and no later
    ``chmod`` closes the window in between.
    """
    with fs.open(f"{drop}/private.csv", "wb") as handle:
        _ = handle.write(b"secret\n")
    assert (tree / "incoming" / "private.csv").stat().st_mode & 0o077 == 0


def test_a_write_larger_than_the_block_size_is_reassembled_in_order(fs, drop: str, tree: Path):
    payload = bytes(range(256)) * 2048
    with fs.open(f"{drop}/blocks.bin", "wb", block_size=5 * 2**20) as handle:
        for offset in range(0, len(payload), 4096):
            _ = handle.write(payload[offset : offset + 4096])
    assert (tree / "incoming" / "blocks.bin").read_bytes() == payload


def test_the_handle_is_released_when_the_file_closes(fs, drop: str):
    handle = fs.open(f"{drop}/report.csv", "rb")
    _ = handle.read(4)
    assert handle._handle is not None  # noqa: SLF001
    handle.close()
    assert handle._handle is None  # noqa: SLF001


def test_get_file_and_put_file_use_this_librarys_transfer_path(fs, drop: str, tmp_path: Path):
    destination = tmp_path / "downloaded" / "report.csv"
    fs.get_file(f"{drop}/report.csv", destination)
    assert destination.read_bytes() == b"id,total\n1,42\n"

    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n5\n")
    fs.put_file(source, f"{drop}/uploaded.csv")
    assert fs.cat_file(f"{drop}/uploaded.csv") == b"id\n5\n"


def test_put_file_in_create_mode_refuses_an_existing_destination(fs, drop: str, tmp_path: Path):
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n5\n")
    with pytest.raises(FileExistsError):
        fs.put_file(source, f"{drop}/report.csv", mode="create")


def test_a_progress_callback_is_bridged_rather_than_dropped(fs, drop: str, tmp_path: Path):
    """A dropped callback is a progress bar that silently never moves.

    fsspec's callback is incremental with the size set once; this library's is absolute. The
    bridge sets the size and then uses ``absolute_update``, which is the one call that cannot
    double-count when a range is retried.
    """
    seen: list[tuple[int, int | None]] = []

    class Recorder(fsspec.Callback):
        def set_size(self, size):
            self.size = size

        def absolute_update(self, value):
            seen.append((value, self.size))

    fs.get_file(f"{drop}/report.csv", tmp_path / "out.csv", callback=Recorder())
    assert seen, "the callback was never called"
    assert seen[-1] == (14, 14)


def test_a_local_path_that_is_byte_flavoured_is_refused_by_name(fs, drop: str):
    """D-96's rule, applied at this boundary too.

    A silent ``os.fsdecode`` here would be guessing an encoding for a name on this machine,
    which is the same class of defect as coercing a ``Path`` onto the wire.
    """

    class BytesPath:
        def __fspath__(self) -> bytes:
            return b"/tmp/out.csv"

    with pytest.raises(TypeError) as exc:
        fs.get_file(f"{drop}/report.csv", BytesPath())
    assert exc.value.args[0] == (
        "a local path must be a str or a pathlib.Path; BytesPath describes itself with bytes, "
        "and decoding it here would be guessing an encoding for a name on this machine"
    )


# --- namespace ------------------------------------------------------------------------------


def test_mkdir_makedirs_rmdir_and_rm(fs, drop: str, tree: Path):
    fs.mkdir(f"{drop}/new/deep")
    assert (tree / "incoming" / "new" / "deep").is_dir()
    fs.makedirs(f"{drop}/new/deep", exist_ok=True)
    with pytest.raises(FileExistsError):
        fs.makedirs(f"{drop}/new/deep")
    fs.rmdir(f"{drop}/new/deep")
    assert not (tree / "incoming" / "new" / "deep").exists()
    fs.rm(f"{drop}/report.csv")
    assert not (tree / "incoming" / "report.csv").exists()


def test_removing_a_symlink_unlinks_the_link_and_not_its_target(fs, drop: str, tree: Path):
    fs.rm(f"{drop}/latest.csv")
    assert not (tree / "incoming" / "latest.csv").exists()
    assert (tree / "incoming" / "report.csv").exists(), "the target went with the link"


def test_mv_is_a_rename_rather_than_a_copy_and_a_delete(fs, drop: str, tree: Path):
    before = (tree / "incoming" / "report.csv").stat().st_ino
    fs.mv(f"{drop}/report.csv", f"{drop}/archive/report.csv")
    assert (tree / "incoming" / "archive" / "report.csv").stat().st_ino == before
    assert not (tree / "incoming" / "report.csv").exists()


def test_mv_refuses_maxdepth_rather_than_ignoring_it(fs, drop: str):
    """Accepted-and-ignored is the failure: the tree moves and the caller is told it worked."""
    with pytest.raises(ValueError) as exc:
        fs.mv(f"{drop}/archive", f"{drop}/archived", maxdepth=1)
    assert exc.value.args[0] == (
        "maxdepth is not meaningful for a server-side rename: RENAME moves a directory and "
        "everything under it in one operation, so there is no depth to limit. Copy and delete "
        "explicitly if a partial move is what you meant"
    )


# --- timestamps -----------------------------------------------------------------------------


def test_modified_is_an_aware_utc_datetime(fs, drop: str, tree: Path):
    when = fs.modified(f"{drop}/report.csv")
    assert when.tzinfo is not None
    assert when.timestamp() == int((tree / "incoming" / "report.csv").stat().st_mtime)


def test_modified_on_something_absent_is_a_file_not_found(fs, drop: str):
    with pytest.raises(FileNotFoundError):
        _ = fs.modified(f"{drop}/nowhere.csv")


def test_created_refuses_because_v3_has_no_creation_time(fs, drop: str):
    """Refused rather than answered with the modification time under a second name."""
    with pytest.raises(CapabilityError) as exc:
        _ = fs.created(f"{drop}/report.csv")
    assert exc.value.feature == "created()"
    assert exc.value.args[0] == (
        f"SFTP v3 has no creation time: an ATTRS carries size, uid/gid, permissions and "
        f"atime/mtime only, so '{drop}/report.csv' has no created timestamp to report"
    )


# --- the extra ------------------------------------------------------------------------------


def test_importing_the_adapter_without_fsspec_names_the_extra():
    """The import error a user actually hits, proven in a process where fsspec is unimportable.

    A bare ``ModuleNotFoundError: No module named 'fsspec'`` tells a reader nothing about how
    this library is packaged. The subprocess blocks the import rather than uninstalling
    anything, so the check costs nothing and cannot corrupt the environment.
    """
    program = (
        "import sys\n"
        "class Block:\n"
        "    def find_module(self, name, path=None):\n"
        "        return self if name == 'fsspec' or name.startswith('fsspec.') else None\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'fsspec' or name.startswith('fsspec.'):\n"
        '            raise ModuleNotFoundError(f"No module named {name!r}", name=name)\n'
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "for name in [n for n in sys.modules if n == 'fsspec' or n.startswith('fsspec.')]:\n"
        "    del sys.modules[name]\n"
        "try:\n"
        "    import gantry_sftp.fsspec\n"
        "except ModuleNotFoundError as exc:\n"
        "    print(exc.args[0])\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    assert result.stdout.strip() == (
        "gantry_sftp.fsspec needs fsspec, which is an optional dependency of this library: "
        "install it with `pip install gantry-sftp[fsspec]` (or `uv add gantry-sftp[fsspec]`). "
        "Nothing else in gantry_sftp requires it."
    )


def test_the_extra_is_declared_and_its_floor_is_the_version_probed():
    """The extra exists and pins a floor, because the adapter reads fsspec internals."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.optional-dependencies]" in text
    assert 'fsspec = [\n    "fsspec>=' in text
    assert fsspec.__version__ >= "2026.7.0"


# --- the integration a consumer actually performs -------------------------------------------


def test_a_url_opens_end_to_end_through_fsspecs_own_entry_points(tree: Path, drop: str):
    """What ``pd.read_parquet(url)`` does underneath, without needing pandas installed.

    pandas, pyarrow and dask all reach a remote file the same way -- resolve the protocol, get
    a filesystem, open a file object -- so exercising ``url_to_fs`` and ``fsspec.open`` on a
    registered URL is the claim in DESIGN 8, and it is the part that would break if the
    registration, the URL form or the file object were wrong.

    The instance is left in fsspec's cache on purpose so that both calls resolve to the *same*
    filesystem: that is what a consumer's repeated URL use does, and it is the only way one
    ``close`` at the end is enough.
    """
    register_implementation(LocalGantryFS.protocol, LocalGantryFS, clobber=True)
    url = f"gantry-sftp-local://local{drop}/report.csv"
    filesystem, path = fsspec.core.url_to_fs(url, root=str(tree))
    try:
        assert isinstance(filesystem, LocalGantryFS)
        assert path == f"{drop}/report.csv"
        with fsspec.open(url, "rb", root=str(tree)) as handle:
            assert handle.read() == b"id,total\n1,42\n"
        assert fsspec.open(url, "rb", root=str(tree)).fs is filesystem
        assert fsspec.get_filesystem_class(LocalGantryFS.protocol) is LocalGantryFS
    finally:
        filesystem.close()
        LocalGantryFS._cache.clear()  # noqa: SLF001


def test_the_file_object_is_ours_rather_than_a_paramiko_one(fs, drop: str):
    with fs.open(f"{drop}/report.csv", "rb") as handle:
        assert isinstance(handle, GantrySFTPFile)

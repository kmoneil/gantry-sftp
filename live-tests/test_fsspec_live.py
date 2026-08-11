"""The fsspec adapter over a real ``ssh`` connection.

``tests/test_fsspec.py`` drives every rule in the adapter against a real ``sftp-server`` on a
pipe, which is a real server but not a real *connection*. This lane is the other boundary: a
URL goes in, ``ssh`` is spawned, a host key is verified, and bytes come back. DoD 1 is
explicit that anything crossing the ``ssh`` subprocess needs a proof here rather than only in
the unit suite.

**Registration is process-global, so every test here restores it.** A lane that left
``gantry-sftp`` -- or worse, ``sftp`` -- pointing at us would be doing to the rest of the
session exactly what D-60 exists to stop this library doing to somebody's program.

The backend is not parametrised. These are assertions about ``ssh``, a server and fsspec;
running each twice would prove nothing about anyio, and the adapter is blocking anyway --
:mod:`gantry_sftp.sync` is what it stands on, and that has its own backend coverage.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

fsspec = pytest.importorskip("fsspec", reason="the fsspec extra is not installed")

from fsspec.registry import known_implementations, register_implementation, registry  # noqa: E402
from sshd import scrubbed_ssh_env  # noqa: E402

from gantry_sftp.exceptions import HostKeyError  # noqa: E402
from gantry_sftp.fsspec import (  # noqa: E402
    PROTOCOL,
    GantrySFTPFile,
    GantrySFTPFileSystem,
    register,
)
from local_filesystem import HOLDS_NON_UTF8_NAMES, needs_non_utf8_names  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    """Put fsspec's registry back exactly as it was found."""
    live = dict(registry)
    known = dict(known_implementations)
    yield
    for name, cls in live.items():
        register_implementation(name, cls, clobber=True)
    known_implementations.clear()
    known_implementations.update(known)


@pytest.fixture
def remote(ssh_server, tmp_path: Path) -> Path:
    """A drop directory on the server's filesystem, with the shapes worth crossing ssh for."""
    drop = tmp_path / "incoming"
    drop.mkdir()
    _ = (drop / "events.csv").write_bytes(b"id,total\n1,42\n2,7\n")
    _ = (drop / "big.bin").write_bytes(bytes(range(256)) * 8192)
    # Not valid UTF-8, and the whole point of carrying names as bytes: this one has crashed
    # paramiko's listdir since 2015 (`paramiko#546`, open, 47 comments).
    #
    # Guarded, because the *server's* filesystem is this machine's and APFS refuses the name
    # outright -- `OSError: [Errno 92] Illegal byte sequence`, at setup, for all nine rows in
    # this module. The unit twin has guarded the identical line since the first macOS CI run
    # (`tests/test_fsspec.py`); this one could not reach the probe until it moved out of a
    # conftest, and so asked nothing. See `local_filesystem.HOLDS_NON_UTF8_NAMES`.
    if HOLDS_NON_UTF8_NAMES:
        _ = (drop / "caf\udce9.csv").write_bytes(b"\xe9")
    (drop / "latest.csv").symlink_to(drop / "events.csv")
    return drop


@pytest.fixture
def filesystem(ssh_server, remote: Path) -> Iterator[GantrySFTPFileSystem]:
    """The shipped adapter, connected over ``ssh`` to the live server.

    Nothing is overridden here -- unlike the unit lane, this is the real constructor, the real
    ``ssh`` subprocess and the real host-key check. The options are the suite's own, which
    pin this server and scrub the environment so no agent key or developer ``ssh_config``
    can decide the outcome.
    """
    adapter = GantrySFTPFileSystem(
        "127.0.0.1",
        port=ssh_server.port,
        identity_file=str(ssh_server.identity_file),
        config_file=os.devnull,
        options=ssh_server.connect_options(),
        skip_instance_cache=True,
    )
    # `env` is not a constructor argument, so the scrubbed environment is applied the way a
    # deployment would: to this process, for the life of the fixture.
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update(scrubbed_ssh_env())
    try:
        yield adapter
    finally:
        adapter.close()
        os.environ.clear()
        os.environ.update(previous)


def test_a_listing_crosses_a_real_ssh_connection(filesystem, remote: Path):
    names = filesystem.ls(str(remote))
    assert f"{remote}/events.csv" in names
    assert names == sorted(names)


@needs_non_utf8_names
def test_a_name_that_is_not_utf8_survives_a_real_connection(filesystem, remote: Path):
    """The unit lane proves the encoding round trip; this proves it through ``ssh``.

    Nothing between here and the wire is allowed to normalise the name: not the subprocess
    pipe, not the codec, not the adapter's decode. A lossy step anywhere would make this file
    unnameable, which is the decade-old open bug in the incumbent.

    The only row here whose *subject* is the odd name, so the only one that skips where the
    filesystem refuses it. The other eight merely stood in a directory that contained one, and
    they now run on a Mac.
    """
    listed = [name for name in filesystem.ls(str(remote)) if "caf" in name]
    assert listed == [f"{remote}/caf\udce9.csv"]
    assert filesystem.cat_file(listed[0]) == b"\xe9"


def test_a_symlink_reads_the_same_from_ls_and_info(filesystem, remote: Path):
    link = f"{remote}/latest.csv"
    listed = next(item for item in filesystem.ls(str(remote), detail=True) if item["name"] == link)
    assert listed == filesystem.info(link)
    assert listed["type"] == "file"
    assert listed["islink"] is True


def test_a_file_object_reads_a_whole_file_back_over_ssh(filesystem, remote: Path):
    expected = (remote / "big.bin").read_bytes()
    with filesystem.open(f"{remote}/big.bin", "rb", block_size=64 * 1024) as handle:
        assert isinstance(handle, GantrySFTPFile)
        assert handle.read() == expected


def test_a_byte_range_reads_over_ssh_without_staging_the_file(filesystem, remote: Path):
    assert filesystem.cat_file(f"{remote}/events.csv", start=3, end=8) == b"total"
    assert filesystem.cat_file(f"{remote}/events.csv", start=-4) == b"2,7\n"


def test_a_write_lands_on_the_server_and_is_not_world_readable(filesystem, remote: Path):
    with filesystem.open(f"{remote}/written.csv", "wb") as handle:
        _ = handle.write(b"id,total\n9,1\n")
    written = remote / "written.csv"
    assert written.read_bytes() == b"id,total\n9,1\n"
    assert written.stat().st_mode & 0o077 == 0


def test_the_connection_is_not_opened_until_something_is_asked(ssh_server, remote: Path):
    """Lazy connect, proven where it costs something: no ``ssh`` child for an unused URL."""
    adapter = GantrySFTPFileSystem(
        "127.0.0.1",
        port=ssh_server.port,
        identity_file=str(ssh_server.identity_file),
        config_file=os.devnull,
        options=ssh_server.connect_options(),
        skip_instance_cache=True,
    )
    try:
        assert adapter._session is None  # noqa: SLF001
        assert "not connected" in repr(adapter)
    finally:
        adapter.close()


def test_a_url_reaches_the_server_through_fsspecs_own_entry_points(ssh_server, remote: Path):
    """The claim in DESIGN 8, over a real connection: a URL is the whole integration.

    ``url_to_fs`` and ``fsspec.open`` are what pandas, pyarrow and dask reach a remote file
    through, so this is the path a consumer actually takes -- including the query parameters,
    which fsspec hands back unparsed and this adapter defines.
    """
    register()
    options = ssh_server.connect_options()
    url = f"{PROTOCOL}://127.0.0.1:{ssh_server.port}{remote}/events.csv?depth=4"
    adapter, path = fsspec.core.url_to_fs(
        url,
        identity_file=str(ssh_server.identity_file),
        config_file=os.devnull,
        options=options,
        skip_instance_cache=True,
    )
    try:
        assert path == f"{remote}/events.csv"
        assert adapter.session_options.depth == 4
        with adapter.open(path, "rb") as handle:
            assert handle.read() == b"id,total\n1,42\n2,7\n"
    finally:
        adapter.close()


def test_a_bad_host_key_reaches_the_caller_as_a_host_key_error(ssh_server, remote: Path):
    """The reason to displace the incumbent, over a real connection.

    fsspec's own ``sftp://`` sets ``paramiko.AutoAddPolicy()`` unconditionally, so this
    connection would succeed there and the caller would never learn the key was unknown. Here
    ``ssh`` reads a ``known_hosts`` that does not name this server and refuses, and the refusal
    survives the adapter rather than being flattened into "could not connect".
    """
    options = ssh_server.connect_options()
    options["UserKnownHostsFile"] = str(ssh_server.empty_known_hosts)
    options["StrictHostKeyChecking"] = "yes"
    adapter = GantrySFTPFileSystem(
        "127.0.0.1",
        port=ssh_server.port,
        identity_file=str(ssh_server.identity_file),
        config_file=os.devnull,
        options=options,
        skip_instance_cache=True,
    )
    try:
        with pytest.raises(HostKeyError) as exc:
            _ = adapter.ls(str(remote))
        assert exc.value.stderr, "OpenSSH's own diagnosis did not reach the caller"
    finally:
        adapter.close()

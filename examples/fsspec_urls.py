"""Read over SFTP from anything that speaks fsspec -- pandas, pyarrow, dask, DVC.

    python examples/fsspec_urls.py                  # a local sftp-server, no network
    python examples/fsspec_urls.py user@host /dir   # a real server over ssh

The integration is a URL. `pd.read_parquet("gantry-sftp://host/incoming/events.parquet")`
resolves the protocol, gets a filesystem, opens a file object -- and that is the whole of it,
which is why DESIGN.md lists fsspec first among the three interfaces: it costs a user nothing
to adopt.

Three things this example exists to make visible, and all three are decisions rather than
details.

**Registration never happens on import.** `sftp://` and `ssh://` are *already* registered
inside fsspec, to an implementation that wraps paramiko. Claiming one costs a single line, and
fsspec's own guard does not stop it: `register_implementation("sftp", cls)` with the default
`clobber=False` succeeds *silently* when nothing has resolved `sftp://` yet, and raises only
once something has -- so which of those two happens is decided by import order. A library that
changed what `pd.read_parquet("sftp://...")` does merely because it was installed would be
doing the thing this project would call an attack if somebody else did it. So you say which
name you want, and `register("sftp")` without `override=True` refuses and names the incumbent.

**A symlink reads the same from `ls` and from `info`.** The output below shows it. The
incumbent's `ls` reads the listing's attributes, so a symlink is `"link"`, while its `info`
calls `stat`, which follows, so the same path is `"file"` -- and fsspec's own docstring for
`info` says it returns "exactly the same information as `ls` would". A symlinked parquet file
that answers `isfile() == False` is a file nothing will open.

**The password never reaches `storage_options`.** For every other fsspec filesystem it does,
and `storage_options` is what `__reduce__` pickles -- a dask scheduler ships it to every
worker -- and what `to_json()` serialises, whose `include_password` argument defaults to
`True`. The last section prints both and finds nothing.
"""

from __future__ import annotations

import os
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

from anyio.from_thread import start_blocking_portal
from fsspec.registry import known_implementations, registry

from gantry_sftp.fsspec import PROTOCOL, GantrySFTPFileSystem, register
from gantry_sftp.sync import BoundPortal


def populate(directory: Path) -> None:
    """A drop directory with the shapes an adapter has to get right."""
    _ = (directory / "events.csv").write_bytes(b"id,total\n1,42\n2,7\n")
    _ = (directory / "notes.txt").write_bytes(b"not a csv\n")
    # A symlink to a real file: `ls` and `info` must agree that this is a file.
    (directory / "latest.csv").symlink_to(directory / "events.csv")
    # A name that is not valid UTF-8. Ordinary on Linux, and the reason remote names are
    # carried as bytes and decoded reversibly.
    _ = (directory / "caf\udce9.csv").write_bytes(b"\xe9")


class LocalServerFileSystem(GantrySFTPFileSystem):
    """The shipped adapter, pointed at a local `sftp-server` so this runs with no network.

    Exactly one method is replaced -- the one that opens the connection. Everything the
    example prints comes from the shipped code. Against a real host the script uses
    `GantrySFTPFileSystem` itself, unchanged; see `main()`.
    """

    protocol = "gantry-sftp-local"

    def __init__(self, root: str, host: str = "local", **kwargs: object) -> None:
        if self._cached:
            return
        self._root = root
        super().__init__(host=host, **kwargs)

    def _connect(self):
        stack = ExitStack()
        portal = stack.enter_context(start_blocking_portal())
        gantry = BoundPortal(portal)
        transport = stack.enter_context(gantry.open_local_server_transport(cwd=self._root))
        session = stack.enter_context(gantry.open_session(transport))
        self._stack = stack
        self._owner_pid = os.getpid()
        return session


def show_the_registry() -> None:
    """What fsspec thinks `sftp://` is, before and after we ask for a name."""
    print("before importing anything of ours, fsspec already knows:")
    for name in ("sftp", "ssh"):
        print(f"    {name}:// -> {known_implementations[name]['class']}")

    print(f"\nimporting gantry_sftp.fsspec registered: {PROTOCOL in registry or 'nothing'}")

    register()
    print(f"after register(), {PROTOCOL}:// -> {registry[PROTOCOL].__name__}")

    try:
        register("sftp")
    except ValueError as refusal:
        print(f"\nregister('sftp') refused, as it should:\n    {refusal}")
    print("    (register('sftp', override=True) is how you mean it)")


def describe(filesystem: GantrySFTPFileSystem, directory: str) -> None:
    """One listing, and the symlink that the incumbent reports two different ways."""
    print(f"\nls({directory}, detail=True):")
    for entry in filesystem.ls(directory, detail=True):
        link = "  ->  " + entry["destination"] if entry.get("islink") else ""
        size = "?" if entry["size"] is None else entry["size"]
        print(f"    {entry['type']:<9} {size:>8}  {PurePosixPath(entry['name']).name}{link}")

    link = f"{directory}/latest.csv"
    from_listing = next(e for e in filesystem.ls(directory, detail=True) if e["name"] == link)
    print("\nls and info agree about the symlink:")
    print(f"    from ls():   type={from_listing['type']}  islink={from_listing['islink']}")
    direct = filesystem.info(link)
    print(f"    from info(): type={direct['type']}  islink={direct['islink']}")
    print(f"    isfile(latest.csv) = {filesystem.isfile(link)}")
    assert from_listing == direct, "ls and info disagreed, which is the bug this one does not have"


def read_bytes(filesystem: GantrySFTPFileSystem, directory: str) -> None:
    """A whole file, a byte range, and a file object -- none of which stages anything."""
    events = f"{directory}/events.csv"
    print("\nreading:")
    print(f"    cat_file()                 {filesystem.cat_file(events)!r}")
    print(f"    cat_file(start=3, end=8)   {filesystem.cat_file(events, start=3, end=8)!r}")
    print(f"    cat_file(start=-4)         {filesystem.cat_file(events, start=-4)!r}")
    with filesystem.open(events, "rb") as handle:
        _ = handle.seek(9)
        print(f"    open() + seek + read       {handle.read(5)!r}")

    # The non-UTF-8 name survives the round trip and opens the same file.
    odd = next(name for name in filesystem.ls(directory) if "caf" in name)
    print(f"    a name that is not UTF-8   {filesystem.cat_file(odd)!r}  ({odd!r})")


def show_the_credential() -> None:
    """Where a password would be, in every other fsspec filesystem, and is not here."""
    filesystem = GantrySFTPFileSystem(
        "example.com", user="bob", password="hunter2", skip_instance_cache=True
    )
    print("\na filesystem built with password='hunter2':")
    print(f"    storage_options   {filesystem.storage_options}")
    print(f"    to_json()         {filesystem.to_json()}")
    print(f"    repr()            {filesystem!r}")
    for surface, text in (
        ("storage_options", repr(filesystem.storage_options)),
        ("to_json()", filesystem.to_json()),
        ("__reduce__()", repr(filesystem.__reduce__())),
        ("repr()", repr(filesystem)),
    ):
        assert "hunter2" not in text, f"the password reached {surface}"
    print("    -- and none of those four carries it, so a pickle to a dask worker cannot")


def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/fsspec_urls.py user@host /remote/dir")

    show_the_registry()

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "incoming"
        source.mkdir()
        if destination is None:
            populate(source)
        directory = remote_dir if remote_dir is not None else str(source)

        if destination is None:
            filesystem = LocalServerFileSystem(str(workdir), skip_instance_cache=True)
        else:
            user, _, host = destination.rpartition("@")
            filesystem = GantrySFTPFileSystem(host, user=user or None, skip_instance_cache=True)

        # `close()` is ours: fsspec has no close in its contract, and its instance cache holds
        # a strong reference on purpose, so nothing else will ever end this connection.
        with filesystem:
            describe(filesystem, directory)
            read_bytes(filesystem, directory)

    show_the_credential()

    print(
        "\nWith a real host, the same thing through pandas is one line:\n"
        f"    pd.read_parquet('{PROTOCOL}://user@host/incoming/events.parquet')"
    )


if __name__ == "__main__":
    main()

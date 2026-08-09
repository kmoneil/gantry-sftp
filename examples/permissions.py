"""Deliver a file that is not world-readable, and mirror a tree's permissions.

    python examples/permissions.py                 # against a local sftp-server, no network
    python examples/permissions.py user@host /dir  # against a real server over ssh

**An uploaded file is created world-readable unless you say otherwise.** That is the server's
default rather than a choice this library makes -- OpenSSH's `process_open` reads the OPEN's
attributes for PERMISSIONS and nothing else, defaulting to 0666, so with the usual `umask 022`
a delivered file lands 0644. Until 0.10 there was no argument that changed it, which meant
there was no way to deliver a key or a credential file correctly.

A `chmod` afterwards is not the same thing and this example shows why: the bits ride on the
OPEN that creates the staging file, and the exact mode lands on the open handle *before* the
rename that publishes it. There is no instant at which the destination exists at the wrong
permissions.

The download direction was already right and had no way to say otherwise: every local file is
created 0600, so nothing is briefly readable while it is being written.
"""

from __future__ import annotations

import stat
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp import OpenFlag
from gantry_sftp.session import Mode, Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


@asynccontextmanager
async def connect(destination: str | None, workdir: Path):
    """Either a real ssh connection, or the genuine sftp-server on a pipe."""
    if destination is None:
        async with open_local_server_transport(cwd=workdir) as transport:
            yield transport
        return
    user, _, host = destination.rpartition("@")
    async with open_ssh_transport(host, user=user or None) as transport:
        yield transport


def show(label: str, path: Path) -> None:
    bits = stat.S_IMODE(path.stat().st_mode)
    others = "world-readable" if bits & stat.S_IROTH else "not readable by others"
    print(f"  {label:<36} {bits:04o}  ({others})")


async def demonstrate_chmod(sftp: Session, default: Path) -> None:
    """Setting a mode on a file that is already there, by name and by handle."""
    print("\nchmod, for a file that is already there:\n")
    await sftp.chmod(str(default).encode(), 0o600)
    show("after chmod(0o600)", default)
    print(
        "\n  It follows symlinks, because SETSTAT is chmod(2). Where the path may be a\n"
        "  link somebody else planted, that is a chmod of whatever it points at. The\n"
        "  extension that does not follow is lsetstat@openssh.com; it is not\n"
        "  implemented here and v3 has no fallback for it, so this is said rather than\n"
        "  quietly assumed."
    )

    print("\nfchmod, for a file you are holding open:\n")
    handle = await sftp.open(str(default).encode(), OpenFlag.WRITE)
    try:
        # By handle rather than by name, and the difference is not convenience: the path can
        # be replaced between the OPEN and the SETSTAT, and on a staging-and-rename publish it
        # is *about* to be -- which is why `put()` sets a mode this way.
        await sftp.fchmod(handle, 0o640)
    finally:
        await sftp.close(handle)
    show("after fchmod(0o640)", default)
    print(
        "\n  A handle refers to the file this session opened; a name refers to whatever it\n"
        "  points at now. That is the whole of the difference, and it is a correctness one."
    )


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        source = workdir / "key.pem"
        source.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
        source.chmod(0o600)
        base = Path(remote_dir) if remote_dir else workdir

        async with connect(destination, workdir) as transport, open_session(transport) as sftp:
            print("the local file is 0600. uploading it:\n")

            default = base / "default.pem"
            result = await sftp.put(source, str(default).encode())
            print(f"  UploadResult.mode = {result.mode}")
            show("put() with no mode=", default)

            private = base / "private.pem"
            result = await sftp.put(source, str(private).encode(), mode=0o600)
            print(f"  UploadResult.mode = {result.mode:#o}")
            show("put(mode=0o600)", private)

            carried = base / "carried.pem"
            result = await sftp.put(source, str(carried).encode(), mode=Mode.PRESERVE)
            show("put(mode=Mode.PRESERVE)", carried)

            # A server that refuses the mode *fails* the upload, unlike a refused timestamp,
            # and on the atomic path it fails before the rename so nothing is published. A
            # file delivered world-readable when 0600 was asked for is the failure this
            # argument exists to prevent -- reporting it as success would be the worst outcome
            # available. Measured against OpenSSH, asyncssh and paramiko: all three honour it.

            print("\ndownload -- already private by default, and widened deliberately:\n")
            plain = workdir / "downloaded-default.pem"
            await sftp.get(str(private).encode(), plain)
            show("get() with no mode=", plain)

            shared = workdir / "downloaded-shared.pem"
            await sftp.get(str(private).encode(), shared, mode=0o644)
            show("get(mode=0o644)", shared)

            print("\na tree -- an integer is a *file* mode, PRESERVE carries directories too:\n")
            tree = workdir / "site"
            (tree / "assets").mkdir(parents=True)
            (tree / "index.html").write_bytes(b"<h1>hi</h1>")
            (tree / "assets" / "app.css").write_bytes(b"body{}")
            (tree / "index.html").chmod(0o644)
            (tree / "assets").chmod(0o750)

            files_only = base / "files-only"
            await sftp.put_tree(tree, str(files_only).encode(), mode=0o640)
            show("put_tree(mode=0o640)  index.html", files_only / "index.html")
            show("  ...and its directory", files_only / "assets")

            mirrored = base / "mirrored"
            await sftp.put_tree(tree, str(mirrored).encode(), mode=Mode.PRESERVE)
            show("put_tree(PRESERVE)    index.html", mirrored / "index.html")
            show("  ...and its directory", mirrored / "assets")

            print(
                "\n  0o600 on a directory cannot be entered, so an integer mode is not applied\n"
                "  to one -- it would leave a complete tree nothing could read. And directory\n"
                "  modes are set in a pass *after* every file: a directory created 0o500 will\n"
                "  not accept the files that belong in it."
            )

            await demonstrate_chmod(sftp, default)


if __name__ == "__main__":
    anyio.run(main)

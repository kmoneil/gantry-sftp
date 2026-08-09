"""Symlinks and attribute changes: `symlink`, `readlink`, `chown`, `utime`, `truncate`, `fstat`.

    python examples/links.py                 # against a local sftp-server, no network
    python examples/links.py user@host /dir  # against a real server over ssh

Two things here are worth more than the method list.

**Every one of these follows a symlink by default**, because `SETSTAT` is `chmod(2)` /
`chown(2)` / `utimes(2)` on a path and all three follow. Point one at a link somebody else
planted and you have operated on whatever it points at. `follow_symlinks=False` uses
`lsetstat@openssh.com` and *refuses* where the server will not do it, rather than quietly doing
the following version -- v3 has no other spelling, so there is nothing to degrade to.

**And `readlink` hands you bytes an attacker chose.** A link target can be absolute, can climb
with `..`, and need not be valid UTF-8. Nothing is validated because every one of those is a
legal symlink; the defence belongs at the point you *use* it.
"""

from __future__ import annotations

import datetime as dt
import stat
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp.exceptions import CapabilityError, ServerError
from gantry_sftp.session import open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

KNOWN_ATIME = 1_600_000_007
KNOWN_MTIME = 1_600_000_000


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


async def show_links(sftp, base: Path, release: Path, current: Path) -> None:
    """`symlink`, `readlink`, and the two things about a link target worth knowing."""
    print("symlink and readlink:\n")
    # Target first, name second -- os.symlink's order, and the *reverse* of the wire's.
    # OpenSSH sends targetpath then linkpath where the draft specifies the opposite; the
    # reversal lives in the codec, checked against a real server.
    await sftp.symlink(str(release).encode(), str(current).encode())
    target = await sftp.readlink(str(current).encode())
    print(f"  {current.name} -> {target.decode()}")

    print("\n  a target is whatever the person who made the link chose:")
    hostile = base / "escape"
    await sftp.symlink(b"../../../../etc/shadow", str(hostile).encode())
    print(f"    {hostile.name} -> {(await sftp.readlink(str(hostile).encode())).decode()}")
    print(
        "    Nothing rejected that, because a climbing relative target is a perfectly\n"
        "    legal symlink. Do not join one onto a local path without a containment\n"
        "    check -- that is the zip-slip class, and readlink is the shortest route."
    )

    print("\n  and a path that is not a link answers BAD_MESSAGE, not FAILURE:")
    try:
        await sftp.readlink(str(release).encode())
    except ServerError as refusal:
        print(f"    {type(refusal).__name__}: code={refusal.code} (BAD_MESSAGE is 5)")
        print("    It reads as 'your frame was malformed'. It means EINVAL.")


async def show_attributes(sftp, release: Path) -> None:
    """`truncate`, `utime`, `chown`, `fstat` -- and why each carries one flag."""
    print("\nattributes -- one flag per call:\n")
    attrs = await sftp.stat(str(release).encode())
    print(f"  before   size={attrs.size} mode={stat.S_IMODE(attrs.permissions or 0):04o}")

    # Truncate *before* utime, and the order is not arbitrary: changing a file's content
    # updates its mtime, so doing these the other way round silently undoes the timestamp
    # you just set. Same shape as stamping a directory only after its contents are written.
    await sftp.truncate(str(release).encode(), 4)
    await sftp.utime(str(release).encode(), KNOWN_ATIME, KNOWN_MTIME)
    attrs = await sftp.stat(str(release).encode())
    when = dt.datetime.fromtimestamp(attrs.times.mtime, dt.UTC) if attrs.times else None
    print(f"  after    size={attrs.size} mtime={when:%Y-%m-%d}")
    print("  (truncate first: changing the content would have re-stamped the mtime)")
    print(
        "\n  One ATTRS flag per request, deliberately: OpenSSH applies the flags in\n"
        "  sequence and reports a single status, so a multi-field SETSTAT that fails\n"
        "  has already applied part of itself and will not say which part."
    )

    # chown to the ids the file already has: the only one an unprivileged client can make,
    # and it exercises the same UIDGID flag. Changing a file's owner for real is root's
    # privilege on every ordinary Unix server.
    if attrs.owner is not None:
        await sftp.chown(str(release).encode(), attrs.owner.uid, attrs.owner.gid)
        print(f"\n  chown to the current owner {attrs.owner} succeeded")

    print("\nfstat -- the file you hold, not the name:\n")
    handle = await sftp.open(str(release).encode())
    try:
        print(f"  fstat(handle).size = {(await sftp.fstat(handle)).size}")
        print(
            "  A path can be replaced between the OPEN and a STAT, which is the shape\n"
            "  of a swap attack. A handle cannot: it is the file this session opened."
        )
    finally:
        await sftp.close(handle)


async def show_symlink_policy(sftp, release: Path, current: Path) -> None:
    """`follow_symlinks=False`, where it works and the two ways it does not.

    The `chmod` branch is the one that depends on the **server's** operating system, and both
    outcomes are printed. On Linux it is refused whatever the server is configured to do; on
    macOS and the BSDs it succeeds and changes the link's own mode. An example that only ever
    narrated the refusal ran on a Mac and said nothing at all about the call.
    """
    print("\nnot following the link -- and where that is refused:\n")
    try:
        await sftp.utime(str(current).encode(), 1, 2, follow_symlinks=False)
    except CapabilityError as refusal:
        print(f"  utime(follow_symlinks=False) refused: missing {refusal.missing}")
    else:
        after = await sftp.stat(str(release).encode())
        unchanged = dt.datetime.fromtimestamp(after.times.mtime, dt.UTC)
        print("  utime(follow_symlinks=False) set the link's own times, via lsetstat")
        print(f"  and the target it points at still reads {unchanged:%Y-%m-%d}")

    try:
        await sftp.chmod(str(current).encode(), 0o600, follow_symlinks=False)
    except (CapabilityError, ServerError) as refusal:
        print(f"\n  chmod(follow_symlinks=False) refused: {type(refusal).__name__}")
        if any("lchmod" in note for note in getattr(refusal, "__notes__", [])):
            print("    ...and the reason is not the server's configuration:")
            print("    Linux has no lchmod, so fchmodat(AT_SYMLINK_NOFOLLOW) answers ENOTSUP.")
            print("    A symlink's own mode is meaningless there and always reads 0o777.")
            print("    utime and chown on a link do work -- the limit is the mode's.")
    else:
        link_mode = stat.S_IMODE((await sftp.lstat(str(current).encode())).permissions or 0)
        target_mode = stat.S_IMODE((await sftp.stat(str(release).encode())).permissions or 0)
        print("\n  chmod(follow_symlinks=False) succeeded: this server's OS has lchmod")
        print(f"    the link's own mode is now {link_mode:04o}")
        print(f"    and the target it points at still reads {target_mode:04o}")
        print("    macOS and the BSDs do this; Linux refuses. It is the *server's*")
        print("    platform that decides, and a client cannot infer it from its own.")
    print(
        "\n  Where it is refused, that is a refusal rather than a downgrade, because\n"
        "  'degrading' here would mean operating on the link's target -- exactly what\n"
        "  the caller asked to avoid."
    )


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        base = Path(remote_dir) if remote_dir else workdir
        release = base / "v2"
        release.write_bytes(b"the payload\n")
        current = base / "current"

        async with connect(destination, workdir) as transport, open_session(transport) as sftp:
            await show_links(sftp, base, release, current)
            await show_attributes(sftp, release)
            await show_symlink_policy(sftp, release, current)


if __name__ == "__main__":
    anyio.run(main)

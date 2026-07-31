"""Ask whether a path is there -- and handle the answer that is neither yes nor no.

    python examples/predicates.py                   # against a local sftp-server, no network
    python examples/predicates.py user@host /dir    # against a real server over ssh

`exists`, `isdir`, `isfile`, `islink`, `getsize`, `getmtime` and `makedirs`, which between
them replace the `try: await sftp.stat(p) except NoSuchFileError:` block every caller would
otherwise write. The reason to read this example rather than the method list is the part of
that block most people get wrong.

**A predicate has three states, not two.** `False` here means the server answered
`NO_SUCH_FILE` and nothing else. A directory you are not allowed to traverse answers
`PERMISSION_DENIED`; a name longer than the far end's limit answers `BAD_MESSAGE`; v3's
`FAILURE` is a catch-all that covers a full disk and a read-only mount. None of those is "no",
and a predicate that reported them as `False` would tell you a path is free when something you
cannot see is sitting on it -- after which the obvious next line creates over the top.

So the shape below is `if not await sftp.exists(p): create it`, wrapped in nothing at all, with
the refusal left to propagate. That is the whole lesson: the `try` you do not write is the bug
you do not ship.

Two other decisions show up in the output. `getsize` and `getmtime` return `None` when the
server sent no such field -- absent is not zero, and not 1970 -- while a path that is not there
raises, so the `None` means exactly one thing. And a broken symlink is `False` to `exists` and
`True` to `islink`: between them they separate "there is a file at the end of this name" from
"this name is taken", and publishing needs the second question.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp import PermissionDeniedError
from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def populate(directory: Path) -> None:
    """The four kinds of entry a predicate has to tell apart."""
    _ = (directory / "report.csv").write_bytes(b"id,total\n1,42\n")
    (directory / "incoming").mkdir()
    (directory / "latest.csv").symlink_to(directory / "report.csv")
    # A link whose target was deleted: still a name, with no file at the end of it.
    (directory / "yesterday.csv").symlink_to(directory / "deleted.csv")


@asynccontextmanager
async def connect(destination: str | None, workdir: Path) -> AsyncGenerator[Session]:
    """A session, either to a local `sftp-server` or over `ssh` to a real host."""
    if destination is None:
        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp
    else:
        user, _, host = destination.rpartition("@")
        async with (
            open_ssh_transport(host, user=user or None) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp


async def describe(sftp: Session, path: bytes, label: str) -> None:
    """Every predicate against one path, in one line."""
    marks = []
    if await sftp.exists(path):
        marks.append("exists")
    if await sftp.isdir(path):
        marks.append("isdir")
    if await sftp.isfile(path):
        marks.append("isfile")
    if await sftp.islink(path):
        marks.append("islink")
    print(f"  {label:<16} {', '.join(marks) or '(nothing)'}")


async def ensure_directory(sftp: Session, path: bytes) -> None:
    """The branching case, written the way it should be written.

    No `try`. If the server will not say whether the path is there, that is not a reason to
    create something -- it is a reason to stop, with a typed error naming the path and the
    refusal. `makedirs(exist_ok=True)` would also be correct here and is one round trip
    cheaper; this spelling is the one that shows what the predicate is for.
    """
    if await sftp.exists(path):
        print(f"  {path.decode()} is already there")
        return
    await sftp.makedirs(path)
    print(f"  created {path.decode()}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/predicates.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        if destination is None:
            populate(workdir)
        base = os.fsencode(remote_dir) if remote_dir is not None else os.fsencode(workdir)

        async with connect(destination, workdir) as sftp:
            print(f"in {base.decode()}:")
            await describe(sftp, base + b"/report.csv", "report.csv")
            await describe(sftp, base + b"/incoming", "incoming/")
            await describe(sftp, base + b"/latest.csv", "latest.csv")
            await describe(sftp, base + b"/yesterday.csv", "yesterday.csv")
            await describe(sftp, base + b"/nothing-here", "nothing-here")

            # A broken symlink is the shape that makes the two questions visibly different.
            dangling = base + b"/yesterday.csv"
            print(
                f"\n{dangling.decode()} is a name with no file at the end of it:\n"
                f"  exists()                      -> {await sftp.exists(dangling)}"
                f"   (is there a file there?)\n"
                f"  exists(follow_symlinks=False) -> "
                f"{await sftp.exists(dangling, follow_symlinks=False)}"
                f"   (is this name taken?)"
            )

            # One attribute at a time, and the absent case says so rather than reporting zero.
            report = base + b"/report.csv"
            size = await sftp.getsize(report)
            when = await sftp.getmtime(report)
            print(
                f"\nreport.csv is {size if size is not None else 'a size the server did not send'}"
                f" bytes, modified "
                f"{when.isoformat() if when is not None else 'at a time the server did not send'}"
            )

            print("\nmaking sure a destination exists:")
            await ensure_directory(sftp, base + b"/incoming")
            await ensure_directory(sftp, base + b"/outgoing/2026/q3")

            # The third state, which is the reason none of the above is wrapped in a `try`.
            # Only demonstrable where the process cannot simply read everything, so it is
            # skipped rather than faked for a run as root.
            if destination is None and os.geteuid() != 0:
                closed = workdir / "closed"
                closed.mkdir(exist_ok=True)
                _ = (closed / "invoice.pdf").write_bytes(b"%PDF-1.4")
                closed.chmod(0o000)
                try:
                    print("\nand a directory this process may not traverse:")
                    try:
                        await sftp.exists(os.fsencode(closed / "invoice.pdf"))
                    except PermissionDeniedError as denied:
                        print(f"  exists() raised {type(denied).__name__}: {denied}")
                        print("  -- which is why False can only ever mean NO_SUCH_FILE.")
                        print("     Reported as False, the next line would overwrite the file.")
                    else:
                        raise AssertionError("a path inside a mode-000 directory answered")
                finally:
                    closed.chmod(0o755)


if __name__ == "__main__":
    anyio.run(main)

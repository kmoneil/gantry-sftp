"""Work from a directory, without the protocol having one.

    python examples/working_directory.py                  # against a local sftp-server
    python examples/working_directory.py user@host /dir   # against a real server over ssh

SFTP v3 has **no** working directory: nothing on the wire sets one and nothing asks. `chdir` is
therefore a prefix this library prepends to relative paths, and everything interesting about it
follows from that one sentence.

- Before you call it, a relative path is left alone and the *server* resolves it against its own
  default directory. `getcwd()` reports that; `sftp.server_root` is the same value and never
  moves, whatever you do afterwards.
- Absolute paths are never prefixed. That is what makes the prefix safe to apply everywhere: a
  path this library hands back — from `glob`, `walk`, `realpath` — goes straight back in.
- `chdir` canonicalises and checks. A prefix holding `..` is one a symlink can redirect out from
  under you, and `REALPATH` alone would happily accept a path that is not there.
- `symlink()`'s target is deliberately *not* prefixed: it is a string stored inside the link,
  interpreted relative to the link's own directory, so a relative link stays relative.

The last section is the one that costs people a production incident: a working directory does
not survive a reconnect, because nothing does.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

import anyio

from gantry_sftp.session import Session, open_session, with_reconnect
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def populate(directory: Path) -> None:
    """Two directories, so moving between them is visible."""
    (directory / "incoming").mkdir()
    _ = (directory / "incoming" / "report.csv").write_bytes(b"id,total\n1,42\n")
    (directory / "incoming" / "archive").mkdir()
    _ = (directory / "incoming" / "archive" / "old.csv").write_bytes(b"id,total\n0,0\n")
    (directory / "outgoing").mkdir()
    # A decoy: the same name one level up. Anything that failed to apply the prefix would
    # silently read this instead, which is why the example asserts on content.
    _ = (directory / "report.csv").write_bytes(b"WRONG FILE\n")


@asynccontextmanager
async def connect(destination: str | None, workdir: Path) -> AsyncIterator[Session]:
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


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/working_directory.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        if destination is None:
            populate(workdir)
        base = remote_dir if remote_dir is not None else str(workdir)

        async with connect(destination, workdir) as sftp:
            print(f"the server starts us in {(await sftp.getcwd()).decode()}")

            await sftp.chdir(f"{base}/incoming")
            print(f"after chdir:             {(await sftp.getcwd()).decode()}")

            # Relative now means "under the working directory". The decoy one level up has
            # the same name and different content, so this is a real assertion.
            content = await sftp.read_at(await sftp.open("report.csv"), 0, 64)
            print(f"  report.csv           -> {content!r}")
            if destination is None and content != b"id,total\n1,42\n":
                raise AssertionError("a relative path escaped the working directory")

            # Relative chdirs compose, and `..` is canonicalised by the server rather than
            # trimmed with string arithmetic.
            await sftp.chdir("archive")
            print(f"  chdir('archive')     -> {(await sftp.getcwd()).decode()}")
            await sftp.chdir("..")
            print(f"  chdir('..')          -> {(await sftp.getcwd()).decode()}")

            # Every method takes the prefix, including the streaming ones -- and what they
            # yield is absolute, so it feeds straight back in with no double prefix.
            matches = [match.path async for match in sftp.glob("**/*.csv")]
            print(f"  glob('**/*.csv')     -> {[path.decode() for path in matches]}")
            for path in matches:
                _ = await sftp.getsize(path)

            # The server's own default directory is a different question and still answers it.
            print(f"  server_root          -> {(sftp.server_root or b'').decode()}")

            # An absolute path is never prefixed, so the two spellings coexist.
            print(f"  absolute still works -> {await sftp.exists(f'{base}/outgoing')}")

        # And the part that costs an incident. `with_reconnect` builds a NEW session per
        # attempt, so a chdir made outside the operation is not there when it runs. Set it
        # inside, exactly as you would re-establish anything else.
        if destination is None:
            recipe = partial(open_local_server_transport, cwd=workdir)

            async def where(session: Session) -> bytes:
                return await session.getcwd()

            async def move_then_work(session: Session) -> bytes:
                await session.chdir(f"{base}/incoming")
                return await session.realpath("report.csv")

            print("\nacross a reconnect, which builds a new session per attempt:")
            print(f"  a chdir made outside -> {(await with_reconnect(recipe, where)).decode()}")
            inside = await with_reconnect(recipe, move_then_work)
            print(f"  a chdir made inside  -> {inside.decode()}")


if __name__ == "__main__":
    anyio.run(main)

"""Fetch `/incoming/*.csv` -- the one-line task a transfer script is usually written for.

    python examples/glob_patterns.py                  # a local sftp-server, no network
    python examples/glob_patterns.py user@host /dir   # a real server over ssh

(Named `glob_patterns` rather than `glob` because a script's own directory goes first on
`sys.path`, so a file called `glob.py` shadows the stdlib module -- and `pathlib` imports it,
so the failure is an unrelated-looking circular import from `pathlib`.)

The reason to use `glob()` rather than a `listdir()` and a `fnmatch` is not brevity. It is
that the join from a name the *server* chose to a path you will hand to `get()` happens once,
inside the library, against a component that has been checked for separators and dot entries.
Written by hand, that join is at your call site, and a server answering with `../../etc/x` is
a path traversal you wrote yourself.

Three things in the output are worth knowing before you tune anything:

**The dialect is `glob(3)`'s, not `fnmatch`'s.** `sftp(1)` globs client-side through POSIX
`glob(3)`, so this matches the pattern language you already have. The visible consequence is
the dotfile: `*.csv` does **not** match `.hidden.csv`, and `fnmatch` would have matched it.
That rule is what stops a glob over a drop directory from picking up half-written staging
files -- including the dot-prefixed ones this library's own atomic publish creates.

**`**` crosses directories and `*` does not.** `*` never matches a `/`, so `/dir/*.csv` is one
level. `**` is an addition to what `sftp(1)` understands, so a pattern using it is not
portable back to that client -- it is here because pathlib, fsspec and bash all have it.

**Matching is on bytes.** A remote name need not be valid UTF-8, and decoding leniently makes
two distinct names match one pattern. The example directory contains such a name on purpose.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import AsyncIterator
from contextlib import aclosing, asynccontextmanager
from pathlib import Path

import anyio

from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport


def populate(directory: Path) -> None:
    """A directory with the names that make the dialect visible."""
    _ = (directory / "report.csv").write_bytes(b"id,total\n1,42\n")
    _ = (directory / "summary.csv").write_bytes(b"id,total\n2,7\n")
    _ = (directory / "notes.txt").write_bytes(b"not a csv\n")
    # Dot-prefixed, and deliberately ending in .csv: `*.csv` must not match it. This is the
    # shape of a staging file, which is exactly what must not be picked up mid-write.
    _ = (directory / ".hidden.csv").write_bytes(b"still being written\n")
    # Not valid UTF-8. Ordinary on Linux, and the reason matching runs on bytes.
    _ = (directory / "caf\udce9.csv").write_bytes(b"\xe9")
    nested = directory / "2026"
    nested.mkdir()
    _ = (nested / "january.csv").write_bytes(b"id,total\n3,99\n")


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


async def show(sftp: Session, pattern: str, note: str) -> list[bytes]:
    """Run one pattern and print what it matched.

    `aclosing` rather than dropping the generator: `glob()` streams, so it is suspended
    between matches and holds a directory handle open at each level of the pattern. An
    abandoned async generator is not finalised by trio, and the handles would sit on the
    server until the garbage collector felt like it, if ever.
    """
    async with aclosing(sftp.glob(pattern)) as found:
        matched = [match.path async for match in found]
    print(f"\n{pattern}\n  {note}")
    for path in sorted(matched):
        print(f"    {os.fsdecode(path)}")
    if not matched:
        print("    (nothing)")
    return matched


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if destination is not None and remote_dir is None:
        sys.exit("usage: python examples/glob_patterns.py user@host /remote/dir")

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        source = workdir / "incoming"
        source.mkdir()
        if destination is None:
            populate(source)
        target = remote_dir if remote_dir is not None else str(source)
        # Deliberately a *sibling* of the globbed tree, not a child of it. Downloading into
        # the directory you are globbing means `**` finds the files you have just written and
        # asks the server for them -- the first version of this example did exactly that, and
        # the symptom was `get` truncating a file onto itself.
        into = workdir / "downloaded"
        into.mkdir()

        async with connect(destination, workdir) as sftp:
            top = await show(sftp, f"{target}/*.csv", "one level, and no dotfile")
            hidden = await show(sftp, f"{target}/.*.csv", "the dotfile, asked for explicitly")
            everything = await show(sftp, f"{target}/**/*.csv", "every level")
            directories = await show(sftp, f"{target}/*/", "a trailing slash means directories")

            # The point of the whole thing: a match carries a path this library built, so it
            # goes straight to `get` with no joining at the call site.
            print("\nfetching every match of **/*.csv:")
            async with aclosing(sftp.glob(f"{target}/**/*.csv")) as found:
                async for match in found:
                    written = await sftp.get(match.path, into / os.fsdecode(match.name))
                    print(f"    {os.fsdecode(match.name)}  ({written} bytes)")

    # `*.csv` matched neither the .txt nor the dotfile, and did not descend.
    assert all(path.endswith(b".csv") for path in top)
    assert not any(path.rpartition(b"/")[2].startswith(b".") for path in top)
    assert len(hidden) == 1
    # `**` reached the nested directory that `*` could not.
    assert len(everything) > len(top)
    assert any(b"/2026/" in path for path in everything)
    # And the trailing slash matched the directory rather than anything in it.
    assert all(path.endswith(b"2026") for path in directories)

    print(f"\n{len(top)} at the top level, {len(everything)} at every level")


if __name__ == "__main__":
    anyio.run(main)

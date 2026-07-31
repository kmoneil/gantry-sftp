"""Turn on the logs, read a frame dump, and watch the counters move.

    python examples/observability.py                        # local sftp-server, no network
    python examples/observability.py user@host /remote/dir  # a real server over ssh

Three loggers, and the point of the split is that they answer different questions:

* ``gantry_sftp.session`` -- what the library was asked to do and what it moved. One record per
  operation, which is what you want running in production.
* ``gantry_sftp.transport`` -- what child process was spawned, with which authentication-steering
  variables, and how it exited.
* ``gantry_sftp.frames`` -- every packet, both directions. Per *packet*: the tiny transfer below
  produces a readable amount, a 16 MiB download produces a few hundred lines and a recursive tree
  produces thousands. This is the one to reach for with a protocol question, and the one to leave
  off otherwise.

Nothing is emitted until an application configures ``logging``: the package logger carries a
``NullHandler``, so a library that is merely imported stays silent.

Named ``observability.py`` rather than ``logging.py`` because a script's own directory is
``sys.path[0]``: a file called ``logging.py`` next to it shadows the standard library module for
everything the process imports afterwards, and the traceback blames ``anyio``.

**Every field is on the record as data, not only inside the message.** That is what the JSON
section below is: a formatter of about ten lines turns these records into one object per line,
with `operation`, `bytes` and `elapsed` as keys a sink can index -- which is what Cloud Logging,
CloudWatch and Datadog all want. Without it a deployment ends up writing a parser for our
sentences, and the first time one is reworded somebody's alerting stops firing silently.

The last section is the part worth reading twice. Every path and message in a dump was chosen by
the server, and this prints one that is trying to forge a log record and clear your terminal.
"""

from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path

import anyio

from gantry_sftp import record_fields
from gantry_sftp.codec import Attrs as PacketAttrs
from gantry_sftp.codec import Name, NameEntry, Status, StatusCode, describe
from gantry_sftp.session import open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

HOSTILE_NAME = b"\x1b[2Jgotcha\nFATAL: your transfer was cancelled\r"
"""What a filename looks like when the server would rather write in your log than be logged."""


def configure(frames: bool) -> None:
    """Send this library's records to stderr, and decide how loud the frame dump is."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)-7s %(name)-24s %(message)s",
        stream=sys.stderr,
    )
    # Everything else in the process stays at whatever it was; only this library is turned up.
    logging.getLogger("gantry_sftp").setLevel(logging.DEBUG)
    logging.getLogger("gantry_sftp.frames").setLevel(logging.DEBUG if frames else logging.INFO)


async def transfer(workdir: Path, destination: str | None, remote_dir: str | None) -> None:
    """Do enough work to be worth logging: one upload, one download, one listing."""
    source = workdir / "source.csv"
    _ = source.write_bytes(b"id,value\n" + b"1,x\n" * 200)

    if destination is None:
        # No host: the genuine OpenSSH sftp-server on a pipe, serving this directory.
        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.put(source, str(workdir / "published.csv"))
            _ = await sftp.get(str(workdir / "published.csv"), workdir / "roundtrip.csv")
            _ = await sftp.listdir(str(workdir))
            print(f"\n{sftp!r}\n")
            print(
                f"{sftp.requests_sent} requests, {sftp.replies_received} replies, "
                f"{sftp.bytes_sent} bytes out, {sftp.bytes_received} bytes in"
            )
        return

    if remote_dir is None:
        sys.exit("usage: python examples/observability.py user@host /remote/dir")
    user, _, host = destination.rpartition("@")
    async with (
        open_ssh_transport(host, user=user or None) as transport,
        open_session(transport) as sftp,
    ):
        remote = f"{remote_dir.rstrip('/')}/published.csv"
        _ = await sftp.put(source, remote)
        _ = await sftp.get(remote, workdir / "roundtrip.csv")
        _ = await sftp.listdir(remote_dir)
        print(f"\n{sftp!r}\n")
        print(
            f"{sftp.requests_sent} requests, {sftp.replies_received} replies, "
            f"{sftp.bytes_sent} bytes out, {sftp.bytes_received} bytes in"
        )


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with this library's fields as indexable keys.

    The whole recipe. `record_fields()` returns the fields the library attached, or `{}` for a
    record from anywhere else -- including another library's, since a formatter installed on the
    root logger sees everything.

    Two things it does *not* have to do, and both are the library's decisions rather than this
    formatter's luck. It does not have to guess types: `bytes` and `elapsed` arrive as numbers,
    so `bytes > 1e9` is a query rather than a substring match. And it does not have to sanitise:
    a remote path is escaped before it is attached, so a name the server chose cannot forge a
    record, and it is pure ASCII, so `json.dumps(...).encode()` cannot fail on a filename that
    was never valid UTF-8 in the first place.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **record_fields(record),
        }
        return json.dumps(payload)


async def show_json_records(workdir: Path) -> None:
    """The same operations again, through the formatter above."""
    print("\nthe same records as JSON, which is what a container's log sink wants:\n")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    session = logging.getLogger("gantry_sftp.session")
    session.addHandler(handler)
    session.propagate = False
    source = workdir / "for-json.csv"
    _ = source.write_bytes(b"id,value\n7,x\n")
    try:
        async with (
            open_local_server_transport(cwd=workdir) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.put(source, str(workdir / "json-published.csv"))
    finally:
        session.removeHandler(handler)
        session.propagate = True


def show_the_renderer_is_pure() -> None:
    """`describe` needs no session, no server and no logging configured -- it is a function."""
    print("\nthe renderer on its own, with nothing running:")
    print("  " + describe(Status(7, StatusCode.NO_SUCH_FILE, message=b"No such file")))
    entry = NameEntry(HOSTILE_NAME, b"-rw-r--r-- 1 u g 0 Jul 28 12:00 ?", PacketAttrs(size=0))
    rendered = describe(Name(9, (entry,)))
    print("  " + rendered)

    # Computed rather than written into the f-strings: `"\\x1b"` inside one is the *text*
    # backslash-x-1-b, not the escape character, so the obvious spelling asks a different
    # question and cheerfully answers it.
    clears_the_screen = b"\x1b[2J" in HOSTILE_NAME
    forges_a_record = b"\n" in HOSTILE_NAME
    survived = any(character in rendered for character in "\x1b\n\r")
    print("\nthat filename really contains:")
    print(f"  a screen-clearing escape sequence: {clears_the_screen}")
    print(f"  a newline that would forge a second log record: {forges_a_record}")
    print(f"  and any of it reached the rendered line: {survived}")
    print(f"  ...because it is escaped instead: {r'\x1b' in rendered}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    configure(frames=True)
    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)
        await transfer(workdir, destination, remote_dir)
        if destination is None:
            # Frames off for this part: the point is the shape of a session record, and a
            # per-packet dump beside it would bury the four lines worth reading.
            logging.getLogger("gantry_sftp.frames").setLevel(logging.INFO)
            await show_json_records(workdir)

    show_the_renderer_is_pure()


if __name__ == "__main__":
    anyio.run(main)

"""Move several files at once over one connection.

    python examples/concurrent_transfers.py                 # against a local sftp-server
    python examples/concurrent_transfers.py user@host /dir  # against a real server over ssh

One session, many transfers. SFTP correlates replies by request id, so a single channel can
carry several operations at once; this library reads that channel in one task and hands each
reply to whichever transfer asked for it.

Three shapes, and picking the wrong one is the point of this file:

* **A list of files into one directory** -- `get_many` / `put_many`. The library derives each
  destination name and refuses a list that flattens onto one of them.
* **Anything else you can enumerate** -- your own `anyio` task group, where the concurrency
  limit is the group and the two path joins are yours to make.
* **A tree** -- `get_tree(concurrency=)`, because you do not have the list; the server does,
  and its size is the server's choice.

That argument bounds **one call** and nothing adds the calls up, so the total across a program
is the caller's either way: three `get_tree(concurrency=8)` in your task group is twenty-four
transfers in flight. The README section *"`concurrency=` bounds one call, and you own the
product"* is what that costs, and the short version is that it is close to free on one session
and the thing that actually costs is how many sessions you open.

Two reasons to want it, and they are different:

* **Round trips.** A thousand small files cost `OPEN`/`READ`/`CLOSE` each. Sequentially that
  is three round trips per file with the link idle in between.
* **Reaching the window.** Bytes in flight are capped at 2 MiB by OpenSSH's per-channel flow
  control, measured. A 64 KiB file has 64 KiB to put in flight; a hundred of them have more.
  Concurrency gets you *to* that ceiling -- it does not lift it, because `ssh -s sftp` runs on
  one channel and everything on this session shares its window. Past 2 MiB needs a second
  connection.

Nothing here is a performance claim: a local pipe has no round-trip time, which is precisely
the thing concurrency buys back. `benchmarks/` measures that on a shaped link and names the
versions it measured against.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import anyio

from gantry_sftp.exceptions import NoSuchFileError
from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import open_local_server_transport, open_ssh_transport

FILE_COUNT = 12
FILE_SIZE = 64 * 1024


async def sequentially(sftp: Session, remotes: list[str], into: Path) -> float:
    started = time.perf_counter()
    for remote in remotes:
        _ = await sftp.get(remote, into / Path(remote).name)
    return time.perf_counter() - started


async def concurrently(
    sftp: Session, remotes: list[str], into: Path, spans: list[tuple[float, float]]
) -> float:
    async def fetch(remote: str) -> None:
        opened = time.perf_counter()
        _ = await sftp.get(remote, into / Path(remote).name)
        spans.append((opened, time.perf_counter()))

    started = time.perf_counter()
    # The task group is the concurrency limit. There is no `concurrency=` knob on the session
    # because the session does not need one: it multiplexes, and how many transfers to have in
    # flight is a decision about the far end, not about this library.
    async with anyio.create_task_group() as group:
        for remote in remotes:
            group.start_soon(fetch, remote)
    return time.perf_counter() - started


def peak_overlap(spans: list[tuple[float, float]]) -> int:
    """The most transfers that were open at the same instant.

    Completion *order* proves nothing -- twelve small files over a local pipe finish in the
    order they started, and would do so on a library that had no concurrency at all. What
    demonstrates overlap is that their intervals intersect, so that is what is counted.
    """
    edges = sorted([(start, 1) for start, _ in spans] + [(end, -1) for _, end in spans])
    open_now = peak = 0
    for _, delta in edges:
        open_now += delta
        peak = max(peak, open_now)
    return peak


async def show_how_a_failure_arrives(sftp: Session, good: str, into: Path) -> None:
    """Where the exception lands, which changes when you fan out -- and where it does not.

    One `get` raises flat: the library unwraps the task groups it runs internally, because
    `except NoSuchFileError` around a single call has to keep matching. But a task group *you*
    open is yours, and anyio wraps whatever its children raise -- even one exception, even
    when only one child ran. That is anyio's contract rather than something to paper over, so
    a fan-out is caught with `except*`.
    """
    try:
        _ = await sftp.get("/definitely/not/there", into / "doomed.bin")
    except NoSuchFileError as error:
        print(f"  one call, on its own:  {type(error).__name__}: {error}")

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(sftp.get, good, into / "fine.bin")
            group.start_soon(sftp.get, "/definitely/not/there", into / "doomed.bin")
    except* NoSuchFileError as group_error:
        for error in group_error.exceptions:
            print(f"  inside your task group: {type(error).__name__}: {error}")
            print("  (your group wraps it -- catch with `except*`, or fan out one level down)")


async def show_what_several_failures_at_once_report(sftp: Session, into: Path) -> None:
    """A concurrent transfer raises one exception, and it tells you about the others.

    The pool cancels the remaining workers on the first failure, but transfers already in
    flight can fail before that reaches them -- so more than one failure is genuinely real.
    The raised exception is still **flat**, which is what keeps `except NoSuchFileError`
    matching; the others are named in a note, and notes print in every traceback, so
    `logging.exception` and any crash reporter show them without being asked.

    **Which one is raised is not meaningful** -- it is whichever the task group listed first,
    not the earliest or the worst. Branching on it as though it were the primary cause is the
    mistake this demonstration exists to prevent.
    """
    try:
        _ = await sftp.get_many(
            [f"/definitely/not/there/{n}.bin" for n in range(4)], into, concurrency=4
        )
    except NoSuchFileError as error:
        print(f"  four at once, one raised:  {type(error).__name__}: {error}")
        notes = getattr(error, "__notes__", [])
        # Asserted rather than printed and hoped for: an example that cannot fail the way it
        # describes is a paragraph with a shebang. The *count* is deliberately not asserted --
        # how many workers get their refusal before the cancellation reaches them is the
        # scheduler's business, and pinning it here would make this file flaky by design.
        assert notes, "the other concurrent failures were not reported"
        for note in notes:
            print(f"  and the rest, on a note:   {note}")


async def run(sftp: Session, remotes: list[str], workdir: Path) -> None:
    one_at_a_time = workdir / "sequential"
    all_at_once = workdir / "concurrent"
    one_at_a_time.mkdir()
    all_at_once.mkdir()

    sequential_seconds = await sequentially(sftp, remotes, one_at_a_time)
    spans: list[tuple[float, float]] = []
    concurrent_seconds = await concurrently(sftp, remotes, all_at_once, spans)

    print(f"\n{len(remotes)} files x {FILE_SIZE} bytes, one session")
    print(f"  sequential: {sequential_seconds:.3f}s")
    print(f"  concurrent: {concurrent_seconds:.3f}s")
    print("  (a local pipe has no RTT -- see benchmarks/ for numbers that mean something)")

    print(f"\n  transfers open at once, at the peak: {peak_overlap(spans)} of {len(remotes)}")
    print("  on a serialised session that number is 1, whatever the wall clock says")

    for remote in remotes:
        name = Path(remote).name
        assert (all_at_once / name).read_bytes() == (one_at_a_time / name).read_bytes(), (
            f"{name} differs between the sequential and concurrent runs"
        )
    print("  every file byte-identical to its sequential download")

    print("\nand when one of them fails:")
    await show_how_a_failure_arrives(sftp, remotes[0], workdir)

    print("\nand when several fail at once:")
    several = workdir / "several"
    several.mkdir()
    await show_what_several_failures_at_once_report(sftp, several)


async def show_list_transfers(sftp: Session, remotes: list[str], workdir: Path) -> None:
    """A list of files into one directory, where the library owns the destination name.

    This is the shape the task group above is *not* the best answer to. Two things happen here
    that a hand-written fan-out has to get right itself:

    * **The destination name is derived and checked.** A remote path's basename becomes a local
      filename, and the remote and local name rules are not the same rule -- a name that
      cleared the remote check can still be `..\\evil` or `C:evil` or `CON`.
    * **A list that flattens onto one name is refused.** `a/x.csv` and `b/x.csv` are two files
      in a tree and one file in a flat directory, so the second would overwrite the first with
      the call reporting success.

    And the results come back in the order they were asked for, whatever the concurrency, which
    is what lets you zip them against your own list.
    """
    into = workdir / "list"
    results = await sftp.get_many(remotes, into, concurrency=4)

    print(f"\n{len(results)} files by list, concurrency=4")
    print(f"  {sum(result.transferred for result in results)} bytes")
    assert [result.transferred for result in results] == [FILE_SIZE] * len(remotes), (
        "get_many returned its results out of the order they were asked for"
    )
    print("  results in the order they were asked for, one per input")

    # The refusal, which is the half worth demonstrating: two different files whose basenames
    # are equal cannot both land in one directory. Refused before anything is transferred.
    first = workdir / "a" / "same.csv"
    second = workdir / "b" / "same.csv"
    for path in (first, second):
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(b"x")
    try:
        _ = await sftp.put_many([first, second], str(workdir / "drop").encode())
    except ValueError as error:
        print(f"\n  two sources, one name -- refused before anything moved:\n    {error}")
    assert not (workdir / "drop").exists(), (
        "put_many created the destination directory for a list it then refused"
    )


async def show_tree_concurrency(sftp: Session, source: str, workdir: Path) -> None:
    """The same idea for a whole tree, where the fan-out is not yours to write.

    `get_many` is right for a list of files you already have. A tree is different in one way
    that matters: **you do not have the list**, the server does, and its size is the
    server's choice. `group.start_soon(...)` inside the walk creates a task per entry, so a peer
    answering with a million names creates a million tasks -- which is why `concurrency=` feeds a
    bounded worker pool from the walk instead, and the walk blocks while every worker is busy.

    Two things it refuses, both on purpose:

    * `progress=` above `concurrency=1`. The callback carries no file identity, so several
      workers reporting at once is several counters interleaved into one stream.
    * Resuming an upload atomically. Each file stages under a name generated fresh per call,
      so a previous run's partial cannot be found again.
    """
    sequential_into = workdir / "tree-sequential"
    concurrent_into = workdir / "tree-concurrent"

    started = time.perf_counter()
    one = await sftp.get_tree(source, sequential_into)
    sequential_seconds = time.perf_counter() - started

    started = time.perf_counter()
    many = await sftp.get_tree(source, concurrent_into, concurrency=8)
    concurrent_seconds = time.perf_counter() - started

    print(f"\n{one.files} files as a tree")
    print(f"  concurrency=1: {sequential_seconds:.3f}s")
    print(f"  concurrency=8: {concurrent_seconds:.3f}s")
    assert (many.files, many.transferred) == (one.files, one.transferred), (
        "the concurrent tree moved a different number of bytes, which is the lost-update bug "
        "`transferred += await ...` produces once workers finish inside one another's awaits"
    )
    print(f"  same {many.files} files, same {many.transferred} bytes")

    # Resume: everything is already there, so the second pass moves nothing at all. This is the
    # nine-gigabyte mirror interrupted at 95%, which used to re-transfer all of it.
    again = await sftp.get_tree(source, concurrent_into, resume=True, concurrency=8)
    print(f"  resumed over the finished copy: {again.files} files, {again.transferred} bytes moved")
    assert again.transferred == 0, "a complete tree re-transferred its own bytes"

    try:
        _ = await sftp.get_tree(
            source, workdir / "nope", progress=lambda _t, _n: None, concurrency=4
        )
    except ValueError as error:
        print(f"\n  progress= with concurrency>1 is refused:\n    {error}")


async def main() -> None:
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    remote_dir = sys.argv[2] if len(sys.argv) > 2 else None

    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        workdir = Path(scratch)

        if destination is None:
            source_dir = workdir / "remote"
            source_dir.mkdir()
            remotes = []
            for index in range(FILE_COUNT):
                source = source_dir / f"part-{index:02d}.bin"
                _ = source.write_bytes(bytes([index]) * FILE_SIZE)
                remotes.append(str(source))
            async with (
                open_local_server_transport(cwd=workdir) as transport,
                open_session(transport) as sftp,
            ):
                await run(sftp, remotes, workdir)
                await show_list_transfers(sftp, remotes, workdir)
                await show_tree_concurrency(sftp, str(source_dir), workdir)
        else:
            if remote_dir is None:
                sys.exit("usage: python examples/concurrent_transfers.py user@host /remote/dir")
            user, _, host = destination.rpartition("@")
            async with (
                open_ssh_transport(host, user=user or None) as transport,
                open_session(transport) as sftp,
            ):
                entries = await sftp.listdir(remote_dir)
                remotes = [f"{remote_dir.rstrip('/')}/{entry.name}" for entry in entries][
                    :FILE_COUNT
                ]
                if not remotes:
                    sys.exit(f"{remote_dir} is empty; nothing to fetch")
                await run(sftp, remotes, workdir)


if __name__ == "__main__":
    anyio.run(main)

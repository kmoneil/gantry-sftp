# Concurrency, and byte ranges

One connection carries many transfers at once. This is also where the async core is the
point rather than an implementation detail.

## Many transfers, one connection

```python
async with anyio.create_task_group() as group:
    for name in names:
        group.start_soon(sftp.get, f"/incoming/{name}", local / name)
```

SFTP correlates replies by request id, so one channel carries as many operations as you care
to start. This library reads that channel in exactly one task and hands each reply to the
operation that asked for it, which is what makes the above safe. There is no `concurrency=`
knob: how many transfers to have in flight is a decision about the far end, about its handle
limits, its patience and its disks, and a task group already expresses it.

Three things worth knowing before you fan out:

- **It reaches the window; it does not lift it.** `ssh -s sftp` runs the subsystem on one SSH
  channel, so one session is one 2 MiB window (measured, below) shared by everything on it.
  What concurrency buys is getting _to_ that ceiling: a 64 KiB file has 64 KiB to put in
  flight and a hundred of them have more, and the round trips of a sequential
  `OPEN`/`READ`/`CLOSE` per file are time the link spends idle. Going past 2 MiB needs a
  second transport, meaning another `ssh` child and another channel, which is not built.
- **A task group you open wraps its errors, and that is anyio's contract, not a bug.** One
  `await sftp.get(...)` raises `NoSuchFileError` flat, because the library unwraps the groups
  it runs internally. Fan out with your own group and you catch with `except*`. `examples/`
  shows both.
- **One operation is one consumer.** Two tasks may each run a `get`; two tasks driving _the
  same_ `get` is not a thing.

`get_tree()` and `put_tree()` take `concurrency=` as of 0.10, defaulting to `1`:

```python
result = await sftp.get_tree("/incoming", "downloads/", concurrency=8)
```

The walk feeds a **bounded** worker pool, not a task per file. That matters because a tree's
size is the server's choice: `start_soon` inside the walk would let a peer answering with a
million entries create a million pending tasks. The producer blocks while every worker is
busy, so peak memory is the worker count and not the tree.

Two things it will not do, both deliberate:

- **`progress=` is refused above `concurrency=1`** rather than passed through. The callback is
  `(transferred, total)` and carries no file identity, so several workers reporting at once is
  several counters interleaved into one stream, and a bar built on it jumps backwards. Use
  `concurrency=1` to keep per-file progress, or read the counts off the returned `TreeResult`.
- **It does not lift the 2 MiB ceiling.** One session is one channel is one window, so
  concurrency _reaches_ the ceiling on a tree of small files rather than exceeding it. Above
  `1` the transfer order is not the walk's, so a failure part-way leaves an unpredictable
  subset transferred.

### `concurrency=` bounds one call, and you own the product

`concurrency=` is the bound for _that call_. It does not compose, and nothing anywhere adds the
calls up for you: three `get_tree(concurrency=8)` running in your task group is twenty-four
transfers in flight, not eight. **The total is yours to own**, in the same way and for the same
reason the concurrent-`get` fan-out above is.

Two things follow, and only the second is a surprise:

- **On one session the total is close to free.** Measured over a real server, how the product
  is split makes no difference, and raising it well past the point where the link is busy
  changes nothing either. Extra workers queue behind one channel, one reader task and one
  window — there is one of everything to contend over, so there is nothing to thrash.
- **Across sessions it is not free, and the number that costs is the session count.** A second
  connection is the only route past the 2 MiB ceiling, and a second one measured faster than
  one. The third and the fourth give the gain back: each `ssh` child is another channel we have
  to frame, decode and place bytes for, and all of that is one Python process on one GIL. On a
  tree of small files a second session buys nothing at all. So if you are reaching for a
  connection pool, keep the number very small and measure it on your own machine — where it
  stops paying is a property of your CPU, not of your link.

To bound the work this library does across a whole program, bound the thing that actually costs:
**how many sessions you open**. A limiter over transfers would bound the number that was already
free.

## Byte ranges, and a file object

`get` and `put` move a whole file between a remote path and a local path. When that is not the
shape you need, whether a header, a range, a tail, an append, or a remote file streamed into a
parser without staging it on disk, `open_file()` is the cursor form:

```python
import os

async with sftp.open_file("/logs/today.jsonl") as remote:
    header = await remote.read(512)
    await remote.seek(-4096, os.SEEK_END)
    tail = await remote.read()
```

It is a context manager because it holds a server-side handle, exactly like
[`scandir`](listing-and-matching.md#streaming-a-directory-you-did-not-size). `read` / `readinto` / `write` / `seek` /
`tell` / `stat` / `truncate` / `fsync` are the surface; `os.SEEK_END` costs one `FSTAT` and the
other two whences send nothing. Writing is a flag rather than a seek: `OpenFlag.APPEND` has the
server place every write at its own idea of the end, so the cursor stops describing where the
bytes landed, which is what the flag means.

**A short read is only ever end of file.** A `DATA` shorter than its `READ` is legal mid-file and
is re-requested underneath you, so `read(n)` returns `n` bytes unless the file ended, and no
caller has to loop. At or past the end you get `b""` rather than an exception, because end of
file is a status the server sends and turning it into an exception would make every loop a `try`.

**This is how a file larger than your memory limit gets processed.** `get` writes to local disk,
which on Cloud Run, Lambda and Fly is a tmpfs and therefore your memory limit again — so a 40 GB
file cannot be staged in a 256 MiB container at all. Reading it in blocks can: nothing here holds
more than the block you ask for, so the ceiling is a number you choose rather than the size of
the file.

```python
async with sftp.open_file("/incoming/huge.jsonl") as remote:
    while block := await remote.read(1 << 20):
        parse(block)  # 1 MiB at a time, whatever the file weighs
```

Use `readinto()` into a buffer you allocated once if you want the copy gone too. See
[What a transfer costs in memory](tuning.md#what-a-transfer-costs-in-memory) for what the whole-file
path costs by comparison, which is `depth × request size` and also independent of file size.

### One file object is one task

The cursor is mutable shared state. Two tasks reading the same object interleave their positions
and each gets a subset of what it asked for, which is a correctness bug that reads as a scheduling
one. That is not a limitation of the session, which multiplexes happily; it is what a cursor is.

For concurrent access to one file, the offset is an argument instead:

```python
handle = await sftp.open("/data/big.parquet")
try:
    async with anyio.create_task_group() as tasks:
        for index in range(4):
            tasks.start_soon(fetch_chunk, handle, index)  # each calls read_at
finally:
    await sftp.close(handle)
```

`read_at(handle, offset, length)` returns `bytes`; `readinto_at(handle, buffer, offset)` fills a
buffer you already own and is the zero-copy form; `write_at(handle, offset, data)` is the other
direction, and takes a `memoryview` without materialising it — the payload is copied once, into
the outgoing frame, which is the floor for a send. Reads at an explicit offset are idempotent
and safe to fan out. Writes are not
retried and never will be blindly, because two tasks writing the same range is a race no client can
arbitrate, exactly as with two processes and `pwrite`.

### Read in big blocks

**This is the one performance decision the surface hands you, and it is arithmetic rather than
advice.** A `read(n)` fills the window, drains it, and only then issues the next block, where a
`get` keeps the window full from its first request to its last. So a cursor read costs **one
round trip per block**, `file_size / block_size` of them, and no block size removes it.

The lever is making that count small: **read in blocks of at least 2 MiB**, the SSH channel
window, which is the same ceiling [Tunables](tuning.md#tunables-and-what-they-default-to) explains
for `depth`. An 8 KiB block is one round trip per 8 KiB, which on any link with latency is the
whole transfer. What each block size costs on each link profile is what the
[benchmark lane](../benchmarks/README.md) measures; run it rather than trusting a number quoted
here, which is why none is.

**If you want `get`'s throughput without `get`'s destination, fan out `read_at`.** Independent
ranges in flight have no bubble to amortise. Closing the gap inside the cursor would take
read-ahead, and that is deliberately not here: implicit prefetching is a policy the caller cannot
see and cannot switch off.

**This one is gated rather than asserted in prose.** `benchmarks/` carries a
`read 16 MiB: file object vs whole file` row, and the run **fails** if our file object at a
window-sized block drops below half our own `get`. The gate exists because the obvious
implementation of a byte-range read — one `READ` per call, awaited — is dramatically slower than
a pipelined whole-file read, and it is slow in a way no unit test notices. Shipping that under a
new name is the failure the row exists to catch.

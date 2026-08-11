# Tunables, and what things cost

Every knob, its default, and the two costs worth sizing before you deploy: round trips per
operation, and memory per concurrent transfer.

## Tunables, and what they default to

Every knob this library has, with the number it ships as. There are four, and three of them
you should not need.

| Setting           | Default        | What it bounds                                                                                                               | When to change it                                                                                                 |
| ----------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `request_timeout` | `30.0` s       | One round trip (the handshake, a `STAT`, an `OPEN`, a `CLOSE`) **and one write**, including the wait for the send lock       | Raise for an appliance that thinks slowly; `None` for no bound at all                                             |
| `idle_timeout`    | `60.0` s       | A bulk transfer's _silence_, not its duration. A nine-hour download never trips it; sixty seconds with nothing arriving does | Raise if the far end legitimately pauses for minutes mid-transfer                                                 |
| `depth`           | `64`           | Requests in flight per transfer, and therefore the memory one costs                                                          | Lower it to fit a smaller container, as below; raising it does not raise throughput, also below                   |
| request size      | `261120` bytes | Payload per `READ`/`WRITE`                                                                                                   | Not a parameter. Derived per connection from `limits@openssh.com`, clamped to what the server says it will accept |

All three parameters are keyword arguments to `open_session()` (and to `with_reconnect()`,
which forwards them); `connect()` takes the same three as one `SessionOptions`, because the
`ssh` arguments already spend this project's argument budget. The blocking surface spells both
exactly the same way. `None` for either timeout means no bound; it is a legitimate thing to ask
for and it is never the default.

**Why the request size is not 256 KiB.** It is the round number, and it is unachievable: the
reference server reports `max-packet-length` 262144 and `max-read-length` 261120, because the
packet also carries the type byte, the request id, the handle and the offset. Asking for the
round number means being clamped on every single request forever. Worse, a frame _over_ the
packet limit is not refused. Measured: `sftp-server` exits with no `STATUS` and an empty
stderr, and the connection dies mid-write. So the size is derived, not defaulted.

**Why raising `depth` past 64 does nothing.** 64 × 255 KiB is what the client _issues_; what
the connection can hold is the SSH channel window, which is 2 MiB: OpenSSH's
`CHAN_SES_WINDOW_DEFAULT`, measured to be the plateau by the benchmark lane.
Issuing past the ceiling is deliberate, so that a server which clamps the request size still
reaches it, but the bytes in flight are the window's business. More depth buys memory
pressure. The thing that would buy throughput is a second connection.

### What an operation costs in round trips

The table above bounds bytes in flight, which is the right lever for a big file and the wrong
one for a directory of small ones. On a link with latency, what a small transfer costs is round
trips, and this is the number to multiply by your RTT:

**Requests and round trips are not the same number**, and the difference is the whole of what
`depth` buys. A request that waits for its own reply before the next one is sent costs a round
trip; requests in flight together cost one between them. Both columns are here because a reader
sizing a WAN transfer needs the second and a reader reading a frame dump sees the first.

| Operation                                         | Requests                                                                   | Round trips             | Which ones                                             |
| ------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------------ |
| `stat` / `lstat` / `realpath` / `getsize`         | 1                                                                          | 1                       | itself                                                 |
| `get`                                             | 3 + `ceil(size / request size)`                                            | **2** + 1 for the reads | `STAT` **and** `OPEN` together, the `READ`s, `CLOSE`   |
| `put(publish=Publish(atomic=False, fsync=False))` | 3 + `ceil(size / request size)`                                            | 3 + 1 for the writes    | `OPEN`, the `WRITE`s, `CLOSE`, `STAT`                  |
| `put` (the default, atomic and flushed)           | 5 + `ceil(size / request size)`                                            | 5 + 1 for the writes    | the four above plus `fsync@openssh.com` and the rename |
| `listdir` / `scandir`                             | 2 + one `READDIR` per reply the server chooses to split the directory into | the same                | `OPENDIR`, the `READDIR`s, `CLOSE`                     |
| `sync_tree`, per directory                        | one `MKDIR` + one `listdir`                                                | the same                | the directory, then its listing                        |
| `sync_tree`, per file **skipped**                 | 0                                                                          | **0**                   | nothing — the listing already answered                 |
| `sync_tree`, per file **sent**                    | one `put` + 1                                                              | `put` + 1               | the transfer, then a `STAT` to record what landed      |

The `READ`s and `WRITE`s pipeline — that is what `depth` is for — so they cost one round trip
in total rather than one each, provided the file is smaller than `depth × request size`.

**A skipped file in `sync_tree` costs nothing at all**, and that is the whole reason the
comparison is affordable. v3 returns attributes *with* a listing, so one `READDIR` sequence per
directory carries every size and modification time the comparison reads — there is no `STAT` per
candidate. Only a file actually sent pays the extra round trip, to record what the destination
ended up holding. So a mirror of an unchanged tree costs two round trips per *directory* and none
per file, which is what makes running it on a schedule over a slow link reasonable.

**`get`'s `STAT` and `OPEN` go out together**, which is why it makes four requests and waits
three times. Neither reads the other's answer on the default path, so the ordering between them
was costing a round trip for nothing. Resuming is the exception and keeps them sequential: the
offset is derived from the size, the safety gate refuses on it, and a resume of an
already-complete file returns without opening anything at all.

The metadata waits are what dominate a small transfer and round to nothing on a large one. On a
200 ms link a 1 KiB `get` is three round trips and the bytes are a rounding error; a 16 MiB one
is the same three plus however long the pipeline takes to move the file.

**The atomic publish costs more on the endpoints that advertise no extensions**, and that is the
MOVEit / GoAnywhere / Cleo / Sterling class this library was written for. `posix-rename` is one
request and can overwrite; without it, v3 `RENAME` has to be _tried and allowed to fail_ when the
destination already exists, because the protocol gives no way to ask whether it would — so
publishing over an existing name becomes `RENAME`, `LSTAT`, `REMOVE`, `RENAME`. Eight round
trips against the reference server's five, and the extra ones buy a _weaker_ guarantee, because
that ladder has a window in which the destination does not exist. If your consumer polls a drop
directory and your server has no `posix-rename@openssh.com`, `atomic=False` is not the reckless
choice it looks like — read the [atomic publish](transfers.md#atomic-publish) section before deciding.

The extension is probed once per session and the refusal is remembered, so only the first upload
on a connection pays for finding out. That is another argument for reusing a session.

These counts are asserted, not documented: `tests/test_round_trips.py` pins every row against a
real `sftp-server`, so a change that adds a round trip fails a test rather than showing up as a
slow WAN transfer six months later.

### What a transfer costs in memory

Every serverless and container runtime makes you pick a limit before anything runs, and the
good ones tell you nothing when it is exceeded — Cloud Run and Lambda kill the container with
no Python traceback at all. So here is the bound, as an expression rather than an anecdote:

```
peak ≈ concurrent transfers × depth × request size
     =                    1 ×    64 × 261120 bytes  ≈ 16 MiB per transfer
```

That is the payload buffering, which is the part that scales. Add a few hundred KiB per
connection for the frame splitter and the transport's read buffer, and whatever your own
program holds.

**This is measured, not just asserted.** `scripts/lanes.py cost` sweeps peak resident set across
16 → 256 MiB in both directions and fails the run if it grows with the file or if a transfer costs
more over an empty session than the expression above allows. Measured on that lane, a transfer
costs about 1.2 MiB over an idle session and the curve is flat to ~1% across the whole range —
so the "independent of the file's size" half is a check rather than a promise.

**`depth` is what you lower**, and it is the whole of the knob — `SessionOptions(depth=8)`
brings a transfer to about 2 MiB, at the cost of throughput on a high-latency link, where the
requests in flight are what hides the round trip. The request size is not a parameter: it is
derived per connection from `limits@openssh.com` and clamped to what the server accepts, which
is the part nobody guesses when sizing a container.

**What multiplies it is concurrency, and you own that number.** One transfer is one `depth`
worth of buffers. `get_tree(concurrency=8)` is eight. Your own task group over `get` is however
many you started — `asyncio.gather` over a hundred files is a hundred, which is where a
comfortable limit stops being comfortable. Two `get_tree(concurrency=8)` calls at once is
sixteen, because the argument bounds one call and not the program: see
[`concurrency=` bounds one call](concurrency.md#concurrency-bounds-one-call-and-you-own-the-product) for what
that costs in throughput, which is a different answer from what it costs in memory.

The bound is the same in both directions and the reason differs, which matters if you are
reading the code to check us: **uploading**, the codec holds each `WRITE` — payload included —
until the server acknowledges it, so `depth` unacknowledged writes are `depth` payloads;
**downloading**, replies queue in the transfer's own deque until its loop drains them, and at
most `depth` reads are outstanding, so at most `depth` payloads can be waiting. Neither
direction accumulates a _file_: a download places each payload with `os.pwrite` at the offset
its request asked for and drops it, and an upload reads each one with `os.pread` as it goes.
Transferring a 40 GB file costs the same as transferring a 40 MB one.

**On Cloud Run, Lambda and Fly, `/tmp` is memory.** It is a tmpfs and it counts against the
same limit as your heap, so a staged download is charged twice — once as the buffers above and
once as the file. Delete each file when you are done with it inside the loop, or do not stage
it at all:

**A file larger than the container is still readable, without staging it anywhere.** That is
what the byte-range surface buys you and it is the reason it exists:

```python
async with sftp.open_file("/incoming/huge.jsonl") as remote:
    async for line in stream_lines(remote):  # your parser, fed a block at a time
        ...
```

`open_file()` and `read_at` never hold more than the block you ask for, so a 40 GB file goes
through a 256 MiB container. See [Byte ranges, and a file object](concurrency.md#byte-ranges-and-a-file-object).

None of this is a _measurement_ — peak RSS against paramiko and asyncssh is not measured, and
this section would be true whatever such a comparison said. It is the bound the design
guarantees, derived from two constants you can read.

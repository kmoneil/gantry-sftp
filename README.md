# gantry-sftp

A modern Python SFTP library that **does not implement SSH at all**.

## Why

The Python SFTP ecosystem is one library deep. pysftp, sftpretty, `fs.sshfs` and
`smart_open` all wrap paramiko, so they all inherit its engine — a general-purpose SSHv2
implementation from 2003 in which SFTP is one feature among many. The familiar complaints
are downstream of that one architectural fact: slow WAN transfers, no async, no
`ProxyJump`, no connection multiplexing, and `Error reading SSH protocol banner`.

So don't write an SSH library. OpenSSH already exists, it is already installed, and one
subprocess hands you a plaintext, framed SFTP byte stream:

```
ssh -o BatchMode=yes -- host -s sftp
```

Everything hard about SSH becomes somebody else's problem, permanently: full `ssh_config`
fidelity, `ControlMaster` multiplexing, post-quantum key exchange, FIDO keys, host
certificates, and every CVE fix without shipping a release. **There is zero cryptography in
this package.** What remains is a protocol codec, a scheduler, and an ergonomics layer.

**The goal is a better SFTP library — safer, more maintainable, more honest about what it is
doing. Being faster is a consequence of being purpose-built for SFTP scheduling, not the
point.** That distinction decides real trade-offs here: a security or correctness gap outranks
a throughput feature, and a performance win is never a reason to ship something less safe. What
the architecture actually buys is surface area nobody here has to own — no crypto to get wrong,
no `ssh_config` to reimplement badly, no SSHv2 stack to maintain — plus the correctness features
the field genuinely needs and no existing option ships: atomic publish, a zip-slip defence,
errors that carry state, and extension fallbacks that are tested rather than assumed.

## Status

**Pre-alpha, and honest about it.** Nothing is published and the API will change. What
exists today:

- a complete filexfer v3 codec: all 27 packet types plus ATTRS, encoding and decoding,
  checked against `draft-ietf-secsh-filexfer-02`, OpenSSH's `sftp.h`, and frames captured
  from a real server — every one of the 27 carries a byte-level fixture asserted in both
  directions, which is a stronger claim than a round trip, because a round trip agrees with
  any consistently wrong layout
- wire primitives and an incremental frame splitter — no frame payload is ever copied
- the client state machine: handshake, deterministic request-id allocation, and
  request/response correlation that survives out-of-order replies
- transports: `ssh -s sftp` as a subprocess, and `sftp-server` on a bare pipe
- a session with `stat`, `lstat`, `fstat`, `realpath`, `open`/`close`, `mkdir`, `rmdir`,
  `remove`, `rename`, `posix_rename`, `fsync`, `chmod` / `chown` / `utime` / `truncate`,
  `readlink` / `symlink`, `supports()`, `listdir()` / streaming `scandir()`, and
  pipelined `get()` / `put()`, with typed errors, timeouts on every wait, and a progress
  callback
- **permissions that survive the transfer**: `mode=` and `Mode.PRESERVE` both directions, set
  on the file before anything can open it by its published name — without it every upload
  arrives `0666 & ~umask`, which is the server's default and used to be unchangeable
- **recursive transfer both ways**: `walk()` and `get_tree()`, with the zip-slip defence that
  makes a hostile server's filenames safe to write, plus `put_tree()` and `rmtree()` — trees
  go up as well as down, and come back off again
- **destination collisions are refused, not overwritten**: two legal remote names that a
  case-folding local filesystem makes one file — `README.md` and `readme.md` downloaded onto
  macOS or Windows — used to lose one silently. The check is filesystem identity rather than
  name folding, so it covers Unicode normalisation and Windows trailing dots for free
- **atomic publish**: `put()` stages, flushes and renames, and tells you which mechanism it
  actually used
- **resume**, both directions, opt-in and labelled with what it actually proves — on single
  files and, as of 0.10, on whole trees
- **trees transfer concurrently on request**: `get_tree(concurrency=8)` feeds a bounded worker
  pool from the walk, so the peak task count is the worker count rather than the tree's size
- **reconnect and retry**: `with_reconnect()` runs an operation against a fresh session when
  the link drops, with a classification that refuses to retry a failed authentication
- **server identification**: the session names which SFTP implementation it is talking to,
  from what the handshake already carried — measured against three real servers
- **server-side hashing** where a server has it: `check_file()` verifies content without
  moving the bytes again, with its layout read off the wire because no draft defines it
- **one session, many transfers at once**: a single reader task routes each reply to whichever
  operation asked for it, so `get`/`put` overlap over one channel instead of queueing behind
  a lock
- **password authentication** for the endpoint class that needs it, with the secret travelling
  through the child's environment and never through argv, where `ps` would show it to every
  user on the machine
- a test lane that drives the genuine OpenSSH `sftp-server` over a pipe — no ssh, no keys,
  no network, no containers — and a `live-tests/` lane that runs a real `sshd`, including a
  `tc netem`-shaped link where the pipelining claims are actually measured
- a `benchmarks/` lane that runs this library, paramiko and asyncssh against the same server
  over that shaped link, reporting wall clock **and** CPU — the source of truth for every
  performance number here, including the two that do not flatter us
- runnable `examples/`, each of which works with no arguments and is executed by the suite

The thesis is proven end to end: SFTP runs over a real SSH connection, with key exchange,
host-key verification and authentication — by key or by password — all done by OpenSSH, and no
cryptography in this package. It is also now measured against the alternatives — on a shaped link it downloads
1.6–3.2× faster than paramiko and 1.1–1.4× faster than asyncssh, it is *slower* to connect, and
it wins nothing on CPU. All three of those are below, including the two that do not flatter it.
It moves files:

```python
import anyio
from gantry_sftp.session import open_session
from gantry_sftp.transport import open_ssh_transport


async def main():
    async with (
        open_ssh_transport("example.com", user="bob") as transport,
        open_session(transport) as sftp,
    ):
        await sftp.get("/remote/data.parquet", "data.parquet")
        result = await sftp.put("report.csv", "/remote/report.csv")
        print(result.mechanism, result.atomic)  # posix-rename True


anyio.run(main)
```

Not yet: the fsspec adapter, `SFTPPath`, or the generated sync API. The
names in DESIGN.md's §8 sketch (`connect()`, `put_many()`) do not exist yet — `open_session` is
the current spelling, and concurrency is spelled with your own task group rather than a
`concurrency=` argument.

## Matching names: `glob`

```python
from contextlib import aclosing

async with aclosing(sftp.glob("/incoming/*.csv")) as matches:
    async for match in matches:
        await sftp.get(match.path, local_dir / os.fsdecode(match.name))
```

`match.path` is a path **this library** built, by joining a name that was checked for
separators and dot entries onto the prefix you typed. That is the reason to use `glob` rather
than a `listdir` and an `fnmatch`: written by hand, that join is at your call site, and a
server answering with `../../etc/x` is a path traversal you wrote yourself.

**The dialect is `glob(3)`'s, because that is what `sftp(1)` uses** — it globs client-side
through POSIX `glob(3)`, so this is the pattern language you already have. Three consequences
differ from Python's `fnmatch`, which is what a reader would otherwise assume is underneath:

- **`*` and `?` never cross `/`.** `fnmatch` matches `a/b.csv` against `*.csv`; this does not.
- **A leading period must be matched explicitly.** `*.csv` does not match `.hidden.csv`; `.*.csv`
  does. This is what keeps a glob over a drop directory from picking up half-written staging
  files — including the dot-prefixed ones this library's own atomic publish creates.
- **A backslash escapes**, as it does in `sftp(1)`, which passes no `GLOB_NOESCAPE`.

`[abc]`, `[a-z]` and `[!a-z]` (also spelled `[^a-z]`) work. Brace expansion does not: `sftp(1)`
applies it to `ls` and not to `get`, so there is no consistent behaviour to copy.

| | |
| --- | --- |
| `**` | zero or more directory levels. An **addition** to what `sftp(1)` understands, so a pattern using it is not portable back to that client. Bounded by `max_depth=` |
| trailing `/` | match directories only, as in a shell |
| `case_sensitive=False` | fold ASCII case in the names being matched. Not the directory you typed — folding that would mean listing `/` to find out whether `/Incoming` is `/incoming`. Non-ASCII bytes are never folded: a remote name is bytes of unstated encoding |

Matching runs on **bytes**, because a remote name need not be valid UTF-8 and a lossy decode
makes two distinct names match one pattern. Symlinks match but are never descended into, the
same as in `walk`. Nothing is accumulated — matches are yielded as they are found — so it is an
async generator and you close it, exactly as with `walk`. A directory in the pattern's path that
does not exist matches nothing; one that exists and **cannot be read** raises, which is a
deliberate divergence from `glob(3)`: answering "no matches" when the truth is "I was not
allowed to look" is a partial success wearing a complete one's clothes.

Runnable: `examples/glob_patterns.py`.

## Many transfers, one connection

```python
async with anyio.create_task_group() as group:
    for name in names:
        group.start_soon(sftp.get, f"/incoming/{name}", local / name)
```

SFTP correlates replies by request id, so one channel carries as many operations as you care
to start. This library reads that channel in exactly one task and hands each reply to the
operation that asked for it, which is what makes the above safe. There is no `concurrency=`
knob: how many transfers to have in flight is a decision about the far end — its handle
limits, its patience, its disks — and a task group already expresses it.

Three things worth knowing before you fan out:

- **It reaches the window; it does not lift it.** `ssh -s sftp` runs the subsystem on one SSH
  channel, so one session is one 2 MiB window (measured — below) shared by everything on it.
  What concurrency buys is getting *to* that ceiling: a 64 KiB file has 64 KiB to put in
  flight and a hundred of them have more, and the round trips of a sequential
  `OPEN`/`READ`/`CLOSE` per file are time the link spends idle. Going past 2 MiB needs a
  second transport — another `ssh` child, another channel — which is not built.
- **A task group you open wraps its errors, and that is anyio's contract, not a bug.** One
  `await sftp.get(...)` raises `NoSuchFileError` flat, because the library unwraps the groups
  it runs internally. Fan out with your own group and you catch with `except*`. `examples/`
  shows both.
- **One operation is one consumer.** Two tasks may each run a `get`; two tasks driving *the
  same* `get` is not a thing.

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
  several counters interleaved into one stream — a bar built on it jumps backwards. Use
  `concurrency=1` to keep per-file progress, or read the counts off the returned `TreeResult`.
- **It does not lift the 2 MiB ceiling.** One session is one channel is one window, so
  concurrency *reaches* the ceiling on a tree of small files rather than exceeding it. Above
  `1` the transfer order is not the walk's, so a failure part-way leaves an unpredictable
  subset transferred.

## Resuming a tree

```python
result = await sftp.get_tree("/incoming", "downloads/", resume=True)
```

The nine-gigabyte mirror interrupted at 95%. `resume=` forwards to `get` / `put` per file, so
it inherits their guarantees exactly: an already-complete file costs one `STAT` and moves
nothing, a partial one continues from where it stopped, and a local partial *longer* than the
remote file is refused rather than truncated. It composes with `concurrency=`.

**Uploading a tree with `resume=True` requires `publish=Publish(atomic=False)`**, and raises
otherwise. Each file stages under a name generated fresh per call, so a previous run's partial
cannot be found again — and a `staging_name` cannot be fixed for a whole tree. Deriving one per
file from the target would make it predictable for every file at once, which is exactly what
the generated name exists to prevent, so the combination is refused rather than quietly
downgraded. Resuming an upload therefore means resuming the destination files themselves, and a
consumer polling the directory can see a partial file while it happens.

## Listing

```python
for entry in await sftp.listdir("/incoming"):
    print(entry.kind, entry.size, entry.name)  # directory 4096 archive
```

Three things this does differently from the tools you have used:

- **The attributes come with the listing.** v3 sends ATTRS per entry, so `entry.size` and
  `entry.kind` cost nothing. Returning bare names forces a `stat` per file, which is a round
  trip each, and is why listing a large directory is slow in most SFTP tooling.
- **`entry.kind` can be `unknown`.** A server is not obliged to send permissions, and
  answering "file" when it did not say is how a recursive walk silently skips every
  directory on that server. `is_dir` is `False` for `unknown` — the safe way round for a
  walk — so read `kind` where the difference matters.
- **`entry.filename` is bytes and `entry.name` is `str` via `surrogateescape`.** A filename
  on Linux is bytes; a name decoded lossily is a file you can list and cannot open. The two
  round-trip, so the name you display is the name you can send back.

`.` and `..` are filtered out. `readdir()` gives you the raw batches if you want to see
exactly what the server sent — one READDIR is not a directory, and the server decides how
many entries a batch holds (OpenSSH: 100). It reports the end of a directory as `None`, for
an `EOF` status **and** for a NAME carrying zero names: the draft says a READDIR is answered
with "one or more names" and OpenSSH's server never sends an empty one, but OpenSSH's client
stops on one, and being stricter than `sftp(1)` against real-world servers buys nothing.

### Streaming a directory you did not size

`listdir()` follows every batch to the end, so **how much memory it takes is the server's
decision, not yours** — a directory with millions of entries, or a server willing to answer
READDIR with new names forever, is unbounded allocation driven by the peer. Nothing is
capped, because a silent cap breaks the legitimate large directory *and* reports success.
`scandir()` is the form that holds one batch:

```python
async with sftp.scandir("/incoming") as entries:
    async for entry in entries:
        if entry.is_file and entry.name.endswith(".csv"):
            break  # the directory handle goes back here
```

It is a context manager rather than a bare generator because it holds a directory handle
open across the yield, and a suspended async generator that is merely dropped is not
finalised by trio — the handle would sit on the server until the garbage collector felt like
it, if ever. Iterating one without the `async with` raises `StateError` instead of leaking.

Other work on the session is fine inside the loop — a `stat` per entry, or a `get` — because
a session multiplexes and a scan holds no lock.

`listdir()` is `scandir()` collected, so the two cannot disagree about what a directory
contains. `walk()` uses it too, which means the raw listing and the classified one are never
both in memory; one directory still is, and that bound is structural — a top-down walk cannot
know where to descend until it has seen every name.

## Walking and recursive download

```python
result = await sftp.get_tree("/incoming", "downloads/")
result.files, result.directories, result.transferred  # 3 2 2520
result.complete  # False -- read result.skipped
```

**Every name the server supplies is validated before it becomes a local path**, and the
finished path is re-checked against the destination once symlinks are resolved. A server
answering `../../etc/cron.d/x` gets an `UnsafePathError` and nothing is written. This is the
zip-slip class, and it is a genuine, exploited vulnerability pattern in file-transfer clients
rather than a theoretical one. Two layers, because either alone has a hole:

| Layer                | Catches                                                                |
| -------------------- | ---------------------------------------------------------------------- |
| Component validation | `..`, separators, the empty name, NUL — and on Windows `:` streams, `C:` drive-relative names, `CON`/`LPT1` devices, trailing dots |
| Containment          | a destination subdirectory that is *already* a local symlink pointing elsewhere — every component innocent, the finished path outside |

The rules follow the platform being written to, because a backslash is an ordinary character
in a POSIX filename and a separator on Windows. Refusing the union everywhere would refuse
files that are legal where they live.

`walk()` yields one entry per directory and **never follows symlinks** — they are reported so
you can decide. Nothing server-side is held between yields, so stopping early leaks nothing;
close the generator with `aclosing` rather than dropping it:

```python
from contextlib import aclosing

async with aclosing(sftp.walk("/incoming")) as walker:
    async for entry in walker:
        print(entry.path, len(entry.files), [s.reason for s in entry.skipped])
```

`max_depth` bounds the descent, which is the only defence against a tree that is infinite
because the server says it is.

### Two remote names, one local file

A third refusal, and it is the one that needs no hostile server at all:

```python
try:
    result = await sftp.get_tree("/incoming", "downloads/")
except DestinationCollisionError as error:
    for collision in error.collisions:
        print(collision.remote, "would overwrite", collision.first, "at", collision.local)
    print(error.files, "files and", error.transferred, "bytes did transfer")
```

A server holding `README.md` beside `readme.md` is doing nothing wrong — both names are legal
on any case-sensitive filesystem. Download them onto **APFS or NTFS, the defaults on macOS and
Windows**, and they are one file: the second write truncates the first and the walk reports
success, with one file's contents gone and nothing saying so. Containment cannot catch it,
because both paths are legitimately inside the destination. Nothing escaped anywhere.

**The check asks the filesystem, not the name.** Every file a tree download writes is
remembered by `(st_dev, st_ino)`, and a name landing on an inode this run already wrote is
refused. That never asks *why* two names became one file, so one check covers case folding,
`report.` beside `report` on Windows, and NFC/NFD pairs on HFS+ — reimplementing three
filesystems' folding tables in Python would get all three subtly wrong instead.

Everything transferable still transfers; only the write that would destroy an earlier one is
refused, recorded in `result.skipped`, and reported at the end. A file left by a *previous*
run is not a collision — overwriting that is the point of re-running a download, and it is
what `resume=` depends on. Which member of a colliding pair survives is `READDIR` order, so it
is the server's choice and not reproducible; the error names both.

`examples/destination_collision.py` runs it.

### Servers whose namespace is not rooted at `/`

Every remote path this library *builds* — joining a child onto a directory, splitting a staging
file's parent off its target — is `/` arithmetic on bytes. That is what the protocol says to
assume: `draft-ietf-secsh-filexfer-02` §6.2, *"File names are assumed to use the slash ('/')
character as a directory separator"*, and *"otherwise, no syntax is defined for file names by
this specification."*

So on an endpoint whose namespace is not `/`-shaped — VMS `DISK$USER:[DIR]FILE.TXT`, an MVS
dataset name — there is no correct join to perform, and guessing per vendor is a different
project. `walk()`, `get_tree()`, `put_tree()`, `rmtree()` and an atomic `put()` raise
`CapabilityError` rather than building a path the server does not mean.

**An absolute path asks nothing and costs nothing.** §6.2 also says a name starting with `/` is
absolute and relative to the root of the filesystem, so a caller who passed one has already
asserted the namespace the arithmetic assumes — no probe is sent at all. Only a *relative* path
is in question, because that one is relative to the user's default directory, and whether that
namespace uses `/` is the thing we cannot know without asking. The probe is one `REALPATH` of
`.`, cached for the life of the session and readable as `sftp.server_root`.

What still works on such a server is everything that does no arithmetic: `get()`, `stat()`,
`open()`, `remove()`, `rename()` and `put(..., publish=Publish(atomic=False))` pass your bytes
through untouched.
An atomic `put()` works too if you name the staging path yourself —
`put(..., publish=Publish(staging_name=b"staging/report.part"))` — because a staging name with a separator
is used verbatim and no parent is derived from the target.

## Recursive upload, and removal

```python
result = await sftp.put_tree("outgoing/", "/incoming/batch-1")
result.files, result.directories, result.transferred

removed = await sftp.rmtree("/incoming/batch-1")
```

**The upload direction is not the download direction with the arrows reversed.** Every name
here comes from the local filesystem, so the zip-slip machinery does not apply — the
attacker-controlled input is gone. What replaces it is specific: **symlinks are still not
followed**, in this direction because a link in the tree pointing at `/etc/shadow` would
otherwise copy it to the server under an innocent name. Links are reported in `skipped`,
exactly as the download reports them. `walk_local()` is the walk on its own, and it needs no
connection at all.

Missing parents of the destination are created, and that costs an extra round trip only when
a level is genuinely absent: v3 answers a failed `MKDIR` with the catch-all `FAILURE`, so
"already there" and "the parent is missing" can only be told apart by looking.

**`atomic` is per file, not per tree, and the distinction is the honest part.** Each file is
staged and renamed, so no consumer ever sees a partial *file*. Nothing makes the *tree* appear
in one step — that would mean renaming a staging directory over the destination, and `rename`
onto a non-empty directory fails on every POSIX server, so it could only ever work for a
destination that does not exist yet. A flag that delivered the guarantee sometimes would be
worse than not having it.

`rmtree()` goes bottom up and **descends only into what the walk positively established is a
directory**. Everything else — files, symlinks, fifos, and entries the server declines to
describe — is removed with `REMOVE`, which is `unlink(2)`: it deletes the *name*, so a symlink
goes and what it points at does not, and a directory is refused rather than emptied. That
refusal is the safety net, and it means a wrong guess can only fail in the direction that
raises. There is no `max_depth`, because a depth-limited recursive delete leaves the deepest
directories populated and their parents unremovable.

## Reconnect and retry

A session cannot reconnect itself, and that is deliberate: `open_session()` is handed a
transport whose lifetime is the caller's. Reconnection lives one level up and needs a
*recipe* — any zero-argument callable that produces a new transport:

```python
from functools import partial
from gantry_sftp.session import with_reconnect

recipe = partial(open_ssh_transport, "example.com", user="bob")

moved = await with_reconnect(
    recipe,
    lambda sftp: sftp.get("/incoming/big.iso", "big.iso", resume=True),
    attempts=3,
)
```

**The operation is re-run from the beginning against a session that did not exist before.**
Nothing survives a reconnect — not the remote handles, not the request ids, not the
negotiated limits. So it has to be *resumable* (`get`/`put` with `resume=True`, which
re-establishes the offset from what is actually there) or *idempotent* (`listdir`,
`get_tree`). A `rename` is neither: v3 `RENAME` refuses an existing target, so a lost reply
makes the second attempt fail. Nothing here can tell the difference for you, so it is stated
rather than guessed at.

That is also why "writes are never blindly replayed" needs no machinery: it is `resume`'s
own check, and its weaker claim on the upload side is made once per attempt.

`is_retryable()` is the classification, and it is public because you may want to disagree
with it:

| Retryable | Terminal |
| --- | --- |
| `ConnectError` — the transport died | `AuthenticationError`, `HostKeyError` |
| `TransferTimeoutError` — the far end went quiet | `NoSuchFileError`, `PermissionDeniedError`, `UnsupportedError` |
| `ServerError` with `NO_CONNECTION` / `CONNECTION_LOST` | `ServerError` with `FAILURE`, `ProtocolError`, `UnsafePathError` |

Two of those deserve their reasons. **A failed authentication is never retried**, and not just
because credentials do not become correct by being offered again: OpenSSH 9.8+ applies
`PerSourcePenalties`, so repeated failed auth from one address gets that address
progressively locked out — a retry loop turns one wrong key into a host that stops answering
for everything behind that IP. And **`FAILURE` is terminal**, even though it is sometimes
transient: v3's catch-all is what a permission problem, a full disk, a name collision and a
momentary appliance hiccup all arrive as, so retrying it would turn every fast clear failure
into three slow ones. That changes when the quirks layer can match a server's message text.

**`BAD_MESSAGE` is terminal too, and it does not mean what its name says.** It reads as "the
frame you sent was malformed", which would make it a bug in this library rather than an answer
about your file. On OpenSSH it is also where `EINVAL` and `ENAMETOOLONG` land, so a `readlink`
of a path that is not a symlink, or an operation on an over-long name, arrives under it —
measured, and the reason it is in the terminal column rather than raising as a protocol error.
A genuinely unparseable frame does not produce this code at all: `sftp-server` exits without
answering.

`examples/retry.py` drops a link mid-download and finishes it on the next connection.

## Atomic publish

`put()` writes the bytes to a hidden sibling staging file, flushes them, and renames that
file over the destination. A consumer polling the directory sees the old file or the new one
and never a half-written one — the single most common bug in production SFTP integrations,
and the reason this is the **default** rather than an option.

Every step of it is an optional OpenSSH extension, and most enterprise endpoints advertise
none of them. So `atomic=True` is not a boolean promise: the result says what actually
happened.

```python
result = await sftp.put("report.csv", "/incoming/report.csv")

result.transferred  # 41310
result.mechanism  # posix-rename | rename | remove-rename | in-place
result.durability  # fsynced | unavailable | skipped
result.size_check  # matched | unavailable — rung 3, below
result.content_check  # hashed | reread | unavailable | skipped — rungs 1 and 2, below
result.resume_check  # matched | unavailable | skipped — what the adopted prefix proved
result.atomic  # True — no consumer could observe a partial destination
result.durable  # True — the bytes reached stable storage before the rename
result.staged_at  # b'/incoming/.report.csv.20b59c88.part'
```

| Mechanism       | When                                                      | Atomic                          |
| --------------- | --------------------------------------------------------- | ------------------------------- |
| `posix-rename`  | The server implements `posix-rename@openssh.com`          | Yes, even over an existing file |
| `rename`        | No extension, and the destination did not exist           | Yes — v3 `RENAME` cannot overwrite, so success means it appeared whole |
| `remove-rename` | No extension, and the destination existed                 | **No** — a window with no file  |
| `in-place`      | You passed `Publish(atomic=False)`                        | **No** — the classic behaviour  |

**Every extension is attempted rather than assumed absent**, because endpoints under-advertise
and the answer is worth more than the claim. The cost of asking is one round trip and it is paid
once: `OP_UNSUPPORTED` is a definitive answer and is remembered for the session, so the second
upload does not ask again. `sftp.refuses(name)` is that memory, next to `sftp.supports(name)`,
which is still only what the server *said*.

`require_atomic` is the exception, and the reason is that `posix-rename` cannot be probed — you
do not discover rename support by renaming something, so a demand for that guarantee is answered
from the advertisement rather than by an experiment that costs a nine-gigabyte upload first.
`require_fsync` **can** be probed, and is: an `fsync` on the staging file the moment it is
opened and before it holds anything is idempotent and touches nothing else, so the refusal
still costs no upload while being right about a server that flushes and never said so.

Refusing to downgrade is one flag, and it fails before moving any bytes where it can:

```python
await sftp.put(src, dst, publish=Publish(require_atomic=True))  # rather than remove-rename
await sftp.put(src, dst, publish=Publish(require_fsync=True))  # rather than no durability
await sftp.put(src, dst, publish=Publish(atomic=False))  # in place, for a write-only drop dir
await sftp.put(
    src, dst, publish=Publish(staging_name=b"x.tmp")
)  # servers that forbid dot-files, or mandate a
# staging directory (same filesystem, or the
# rename fails)
```

Three limits stated rather than implied. `fsync@openssh.com` flushes the *file*; SFTP has no
way to flush a directory entry, so the rename that publishes it is never itself durable.
Staging needs the right to create *and* rename a second name in the destination directory — a
drop directory that only permits creation needs `Publish(atomic=False)`. And a failed publish removes
the staging file, with one deliberate exception: once the `remove-rename` fallback has issued
the `REMOVE`, the staging file may be the only copy of your data, so it is left where it is and
the error says where that is.

That exception starts at the `REMOVE` rather than after it, which is not the obvious place. A
`REMOVE` the server performed but never acknowledged — a request timeout is enough — is
indistinguishable from one that never ran, so it is assumed to have run. A `REMOVE` the server
*refused* is a different thing: nothing was removed, and the staging file is cleaned up
normally. The two cases produce different error notes, one saying the destination was removed
and the other that it may have been.

`examples/atomic_publish.py` runs all of this against a real server with no arguments.

## Resume

Off by default in both directions, and the two are not equally trustworthy:

```python
await sftp.get("/remote/big.iso", "big.iso", resume=True)  # continue from what is on disk
await sftp.put("big.iso", "/remote/big.iso", publish=Publish(atomic=False), resume=True)
```

**Downloading is the stronger claim.** The partial is on your disk, so its length is a fact
rather than a report, and a `READ` at an explicit offset is idempotent. **Uploading is the
weaker one**, and the docs say so in those words: the offset comes from the size the *server*
reports, and a size match proves the byte count agrees and nothing else — the remote partial
may be from a different run, a different source file, or a concurrent writer.

Both refuse rather than guess in two cases. A partial *longer* than the file it is supposed
to be a prefix of is a `TransferError`, not a truncation. And a server that will not report a
size makes the check impossible, so the resume is refused instead of silently starting over.

**And where a content check is available, the adopted prefix is gated on it.** The failure a
size match cannot refuse is a partial of the *right* length from the *wrong* source — a
previous run against a different file, a truncated staging file, a concurrent writer. That
upload completes, publishes, and passes the size check, because the finished length is
correct. The gate hashes the prefix on both sides and refuses before a byte is sent:

```python
result = await sftp.put(src, dst, publish=Publish(atomic=False), resume=True)
result.resume_check  # matched | unavailable | skipped
```

| | when it runs | what it costs |
| --- | --- | --- |
| rung 1 | automatically, where the server *performs* `check-file` — asked, not assumed from the advertisement | one `OPEN`/`EXTENDED`/`CLOSE`, no payload; a refusal is remembered for the session |
| rung 2 | only under `verify=Verify.REREAD` | re-reads the whole adopted prefix |
| neither | the default case — `resume_check` is `unavailable` | nothing, and the claim stays the weak one |

Rung 1 is automatic because it moves no bytes, so gating on it where it exists is free.
Rung 2 is not, because re-reading the prefix is most of what resume set out to avoid — worth
asking for on an asymmetric link, where reading back is cheaper than sending again, and that
is a fact about your link rather than ours. A refusal leaves the partial exactly as it was
found: it may be another publisher's, and it is the only evidence of what went wrong.

The download side is gated too, including the case where the local file is *already complete* —
that one adopts the whole file and returns success having moved nothing, which makes it the
one most worth checking rather than the one to skip. `get` returns an `int`, so it can refuse
but has nothing to report `unavailable` on.

**`resume=True` with `atomic=True` needs an explicit `staging_name`**, and raises `ValueError`
without one. Not because `CREAT|EXCL` refuses to adopt a leftover staging file — it never
meets one. The staging name carries fresh randomness on every call, which is what stops two
publishers colliding, and it also means the previous run's staging file has a name this run
cannot reconstruct. Making that name predictable instead would reintroduce exactly the
collision `EXCL` exists to catch, so the choice is handed to the caller:

```python
await sftp.put(
    src, dst, resume=True, publish=Publish(staging_name=b".big.iso.part")
)  # atomic + resumable
```

With a fixed staging name, `EXCL` is dropped so the file can be adopted — which is also the
collision risk moving to whoever named it.

`examples/resume.py` interrupts a transfer in each direction and finishes it, and catches
both refusals so you can see what they say.

One thing worth knowing if you are reading the codec: **`SYMLINK`'s arguments are in the
opposite order to the specification.** draft-02 says `linkpath, targetpath`; OpenSSH sends
and expects `targetpath, linkpath`. We follow OpenSSH, because OpenSSH is what is deployed.
Both orders are run against a live server in the test suite so the claim stays measured
rather than remembered.

(The design and status documents this repository works from are deliberately not committed and
are in no distribution, so nothing here sends you to them. What ships is this file, the
docstrings, and `examples/`.)

## Verifying a transfer

Three rungs, and the library is explicit about which one you actually got:

1. **Server-side hash** — `verify=Verify.HASH`, where the server has it. Verifies *content*
   without moving the bytes again.
2. **Full re-read** — `verify=Verify.REREAD`. Reads back what you uploaded and compares it.
   Works anywhere, costs a second transfer, so it is opt-in paranoid mode.
3. **Size check** — always, no flag. Catches truncation, which is the common failure, and
   nothing else.

```python
result = await sftp.put("report.csv", "/incoming/report.csv", verify=Verify.REREAD)
result.content_check  # hashed | reread | unavailable | skipped
result.size_check  # matched | unavailable — rung 3, always
```

**Rung 3 is what you get by default, everywhere**, because OpenSSH does not implement
`check-file` — it answers `OP_UNSUPPORTED` under all three spellings. Calling a size
comparison a "verified transfer" is the sort of thing this library exists to stop doing.

Which is also why **rung 2 is the one that matters in the field**: it asks for nothing but
`READ`, so it is the only content check most endpoints can offer. It costs a second transfer
*and* temporary local disk equal to the file, in `$TMPDIR` — the bytes come back at full
pipelined speed into a scratch file and are compared from there, rather than one round trip
per block. Asking for rung 1 where the server has no `check-file` reports `unavailable`, never
success:

| `verify=` | rung | works against | cost |
| --- | --- | --- | --- |
| `Verify.SIZE` *(default)* | 3 only | everything | nothing beyond the `STAT` every `put` makes |
| `Verify.HASH` | 1, else `unavailable` | `check-file` servers — paramiko, ProFTPD, some appliances | one round trip, no payload |
| `Verify.REREAD` | 2 | everything | a second transfer + scratch disk |

A **mismatch** never appears as a value: it raises `TransferError`, and under `atomic` it
raises *before the rename*, so corrupt content never becomes the destination.

`verify=` is on `put` and not on `get`. The download side has the local file already, so
"read it back" means downloading twice, and rung 1 there is reachable through `check_file()`
directly; the blocker on a `get(verify=)` is that `get` returns an `int` and so has nowhere to
report `unavailable` — a silent degrade being the one outcome this ladder exists to prevent.

If you call `check_file()` yourself, leave `block_size` alone. It defaults to
`CHECK_FILE_BLOCK_SIZE` (64 KiB) because that is the largest block paramiko answers correctly:
above it the digests cover the wrong bytes and the server thread ends up in a loop it never
leaves, and `block_size=0` — "one digest over the whole range" — is that same loop for any
file over 64 KiB, and a `FAILURE` for any range under 256 bytes. Measured, not inferred.

Rung 3 is not free of decisions, so here is what it actually does:

| | `get()` | `put()` |
| --- | --- | --- |
| what it compares | bytes that arrived vs. the size the `STAT` reported | the local file's length vs. what the server says it holds |
| when | after the transfer | **before the rename**, against the staging file, so a short upload never becomes the destination — in place, necessarily after |
| cost | nothing; `get` already makes that `STAT` | one extra `STAT` — measured, and level with paramiko and asyncssh on every shaped profile |
| on mismatch | `TransferError` carrying both paths and the offset | `TransferError`; the staging file is removed and the destination is left alone |
| server won't report a size | check skipped, download still succeeds | `result.size_check` is `unavailable` |
| turning it off | `get(..., verify_size=False)` | no flag — see below |

```python
result = await sftp.put("report.csv", "/incoming/report.csv")
result.size_check  # matched | unavailable
```

An early `EOF` and a short `DATA` are both *legal*, so nothing below `get()` is entitled to
treat one as an error — which is exactly why a truncating server used to produce a short file
and a successful call. `verify_size=False` exists for reading something that is genuinely
changing size underneath you, and makes the result a snapshot of unknown completeness.

There is no matching flag on `put()`: we control the source there, so a length disagreement is
wrong every time, and `SizeCheck` has no `skipped` value as a result. The cost is one `STAT`
per upload, and it was benchmarked rather than assumed — on every shaped profile the small-file
upload row ties with paramiko and asyncssh to within 5%, because one round trip is invisible
beside the ones a transfer already spends. paramiko's `put` has done the same
`STAT`-and-compare by default since 1.7.7 — its `confirm` parameter — so the benchmark's paramiko
column pays it too and still ties. An earlier draft promised an opt-out flag here; the measurement
withdrew it.

```python
handle = await sftp.open("/incoming/big.iso")
algorithm, digests = await sftp.check_file(handle, algorithms=b"sha256,sha1", block_size=1 << 20)
await sftp.close(handle)
```

You get one digest per block and the algorithm the server chose — it picks the first from your
list that it supports, and answers `FAILURE` if it supports none rather than quietly hashing
with something else. The digest *count* is nowhere on the wire; it follows from the block size
and the width of the chosen algorithm, so a payload that does not divide evenly is a
`ProtocolError` rather than a set of silently misaligned digests.

`check-file` is in no published SFTP draft — 05, 09 and 13 were each checked. The layout here
was read off paramiko's implementation and off a captured frame, and it is committed as a
golden fixture in both directions with a live test that re-runs the capture, because there is
no document to notice a disagreement against.

`examples/server_capabilities.py` runs this with no arguments, and shows the path you will
almost certainly take: OpenSSH answers `OP_UNSUPPORTED`, and the example falls to the size
check rather than pretending the question was answered.

## Timestamps

**A transfer stamps its destination with the time of the transfer unless you ask otherwise.**
That is the default here and in `scp`, `rsync` and every other SFTP client, and it is worth
saying out loud because the alternative failure is silent: bytes correct, size check passed,
result reporting success, and only a field nobody inspects quietly rewritten.

```python
await sftp.get("/remote/data.parquet", "data.parquet", preserve_times=True)
await sftp.put("report.csv", "/remote/report.csv", preserve_times=True)
await sftp.get_tree("/remote/archive", "archive", preserve_times=True)
```

It costs no round trip on download — the times come from the `STAT` `get` already makes — and
one `FSETSTAT` on upload, sent on the open handle so it pipelines with the writes. On the
atomic path it lands on the *staging* file before the rename, because `rename(2)` does not
alter mtime. On a tree it also stamps the directories the call creates, in a pass after every
file, since writing into a directory updates that directory's own mtime. **The root you named
is never stamped** — only what the call creates under it.

A server that refuses does not fail the upload. `UploadResult.times` says which happened:

| | |
| --- | --- |
| `preserved` | `FSETSTAT` sent and accepted |
| `unavailable` | asked for, and the server refused or ignored it |
| `skipped` | not asked for — the default |

**Why off by default.** On-by-default breaks a real deployment: the SFTP landing zone whose
consumer collects "files modified since X" never picks up a file that arrived wearing last
year's date. That is as silent as the failure preserving fixes, pointing the other way, so the
choice belongs to whoever knows which pipeline they are in.

### Reading a timestamp

```python
for entry in await sftp.listdir("/incoming"):
    print(entry.name, entry.modified)  # aware UTC datetime, or None
```

`entry.modified` is `datetime | None`, and the `None` is the point: `times` is absent whenever
a server did not set `ACMODTIME`, and coercing that to `0` dates the file to 1970 — which
reads as "very old" to every `if remote > local`, so a sync built on it either re-transfers
everything or skips everything, and looks correct doing it.

**Do not read the date off `longname`.** It looks like it carries one and it does not. Measured
against OpenSSH 10.0p2, all four:

- Modified within the last **half year**: month, day, time — **no year**.
- Anything else: month, day, year — **no time**. Never both.
- A *future* mtime falls into the year branch too, because the guard is `now >= st_mtime`.
- It is rendered in the **server's** timezone. The same instant reads `Jun 23  2025` under
  `TZ=UTC` and `Jun 24  2025` under `TZ=Asia/Tokyo` — a different calendar **day**, with
  nothing in the reply saying which offset to undo.

So scraping it gives a wrong date rather than a coarse one. `entry.modified` reads the
structured field, which is exact.

### What this cannot promise

- **One-second granularity.** v3 has no sub-second field, so two files written in the same
  second are indistinguishable by mtime and mtime alone is not a change detector.
- **Clock skew is not ours to correct.** Comparing a local mtime against a remote one compares
  two machines' clocks.
- **2038 or 2106.** The wire field is `uint32` seconds: usable to 2106-02-07 read as unsigned,
  which is what the draft says and what OpenSSH stores, but a server treating it as signed
  wraps at 2038-01-19 and nothing distinguishes the two. We refuse a value that does not fit
  rather than truncating it, which matters most for retention and legal-hold systems that set
  far-future dates deliberately.

`examples/preserve_times.py` runs all of this.

## Permissions

**An uploaded file is created world-readable unless you say otherwise, and that is the
server's default rather than a choice this library makes.** OpenSSH's `process_open` reads the
`OPEN`'s attributes for `PERMISSIONS` and nothing else, defaulting to `0666` when the flag is
absent — so with the usual `umask 022` a delivered file lands `0644`. A download is the other
way round: this library creates every local file `0600`, so a file is never briefly readable
while it is being written.

```python
await sftp.put("key.pem", "/remote/key.pem", mode=0o600)  # exactly these bits
await sftp.put_tree("build", "/srv/app", mode=Mode.PRESERVE)  # each file's own bits
await sftp.get("/remote/key.pem", "key.pem", mode=0o600)  # and on the way down
```

`mode=` takes an octal mode, `Mode.PRESERVE` (or the string `"preserve"`) to carry the source
file's own bits across, or `None` — the default — to leave them alone.
`UploadResult.mode` reports what was set.

**One argument rather than two**, because `mode=0o600` and a `preserve_mode=True` would be
mutually exclusive by nature: one parameter makes the contradiction unrepresentable instead of
refusing it at runtime.

### The mode is on the file before anything can open it by name

This is the part worth knowing, because a `chmod` after the fact does not give you it. The
bits ride on the `OPEN` that creates the staging file, and the exact mode lands via `FSETSTAT`
on the open handle **before** the rename that publishes it — so there is no instant at which
the destination exists at the wrong permissions. Writing in place needs one extra step, since
`open(2)` applies its mode argument only to a file it *creates*: there the mode is set after
the open and before the first byte.

setuid, setgid and sticky are withheld from the creating `OPEN` and applied only once the
content is complete. A setuid file that exists half-written is privileged before it is
finished.

### A refused mode fails the transfer

Unlike `preserve_times`, which degrades and reports. The asymmetry is deliberate: a file
published with the wrong dates is cosmetically wrong, and one published world-readable when
`0o600` was asked for is the failure the argument exists to prevent, reported as success. On
the atomic path the refusal arrives before the rename, so the destination is never replaced.

Measured against OpenSSH 10.0p2, asyncssh 2.24.0 and paramiko 5.0.0: **all three honour it**,
so no fallback path exists to document.

### On a tree

An integer `mode=` applies to **files only**. `Mode.PRESERVE` carries directories too, in a
pass after every file has been transferred.

```python
await sftp.put_tree("build", "/srv/app", mode=0o640)  # files 0640, dirs untouched
await sftp.get_tree("/srv/app", "build", mode=Mode.PRESERVE)  # files and dirs both mirrored
```

A file mode on a directory is usually unusable — `0o600` on a directory cannot be entered — so
applying one there would leave a complete tree nothing can read. And the final pass is not
tidiness: a directory created `0o500` cannot have files written into it, so applying a source
mode on the way down fails every transfer underneath it. A refused *directory* mode does not
fail the tree; the files are the payload and are already published.

`examples/permissions.py` runs all of this.

## Changing attributes, and links

```python
await sftp.chmod("/remote/report.csv", 0o640)
await sftp.chown("/remote/report.csv", uid=1000, gid=1000)
await sftp.utime("/remote/report.csv", atime, mtime)  # whole seconds
await sftp.truncate("/remote/report.csv", 0)

attrs = await sftp.fstat(handle)  # the file you hold, not the name
target = await sftp.readlink("/remote/current")
await sftp.symlink("/remote/v2", "/remote/current")  # target first, like os.symlink
```

**Each sends exactly one attribute flag, and that is a correctness decision rather than an
economy.** OpenSSH's `process_setstat` walks the flags in sequence — size, permissions, times,
owner — applying each and recording only the last failure in the single status it returns. So a
multi-field `SETSTAT` that fails has *already applied* the fields before the failing one and
does not say which. One field per call makes a refusal unambiguous and leaves nothing else
moved.

`chown` and `utime` set two values each because the wire pairs them: `UIDGID` and `ACMODTIME`
are one flag apiece. To change a uid alone, read the gid back with `stat()` and send it
unchanged.

### These follow symlinks by default

`SETSTAT` is `chmod(2)`/`chown(2)`/`utimes(2)` on a path, and all three follow — the same
default as `os.chmod`. Where the path may be a symlink somebody else planted, that is an
operation on whatever it points at.

```python
await sftp.utime("/remote/current", atime, mtime, follow_symlinks=False)
```

`follow_symlinks=False` uses `lsetstat@openssh.com`, and **where the server will not do it the
call is refused** with a `CapabilityError` rather than quietly doing the following version.
That is the opposite of how every other extension here degrades, and the reason is that there
is nothing to degrade *to*: v3 has no non-following spelling, so the fallback would be to
perform a different operation, on the target the caller was trying to avoid. OpenSSH and
asyncssh advertise it; paramiko does not.

**`chmod(follow_symlinks=False)` cannot work against a Linux server**, and the extension being
present does not change that. Linux has no `lchmod`: `fchmodat(AT_SYMLINK_NOFOLLOW)` answers
`ENOTSUP` — measured at the syscall level — because a symlink's own permission bits are
meaningless to that kernel and always read `0o777`. It arrives as OpenSSH's contentless
`Failure`, so the exception carries a note saying why. `utime` and `chown` on a link *do* work
there: `utimensat` and `fchownat` both accept the flag. The limit is the mode's, not the
extension's.

`truncate` has no `follow_symlinks=` at all, for a related reason: `lsetstat` rejects a `SIZE`
field outright with `BAD_MESSAGE` (`/* nonsensical for links */`), so a parameter there could
only ever fail.

### `readlink` returns attacker-controlled bytes

A link target is whatever the person who made the link chose. It may be absolute, may climb
with `..`, may not be valid UTF-8, and may point at nothing. None of that is validated, because
every one of those is a legal symlink — so **do not join the result onto a local path** without
the containment check `get_tree` uses. That is the zip-slip class, and `readlink` is the
shortest route to it.

A path that is *not* a symlink answers `BAD_MESSAGE`, which reads as "your frame was malformed"
and here means `EINVAL`. See the status-code notes above.

`examples/permissions.py` covers `chmod`; `examples/links.py` covers the rest.

## Which server is at the other end

```python
sftp.profile.name  # "openssh" | "asyncssh" | "paramiko" | "unknown"
sftp.profile.version  # "2.24.0", where the server volunteers one
repr(sftp)  # <Session server=asyncssh/2.24.0 version=3 extensions=11 ...>
```

Worked out from the extension list the handshake already carried, so it costs no round trip,
and attached to capability refusals so "this server does not advertise `posix-rename`" names
the server it is complaining about.

**It is diagnostic only.** Nothing in the library changes behaviour because of it, and that
bound is deliberate rather than a stage not yet reached: a fingerprint is a guess about an
opaque peer, so a wrong guess should cost a wrong name in a log line, never a wrong answer in
a file. `unknown` is a real answer — many endpoints advertise nothing at all — and it is what
you get rather than the nearest match.

Three profiles ship, not ten, because three is how many `live-tests/matrix.py` can actually
start: OpenSSH, asyncssh and paramiko all serve SFTP and the last two were already installed
as benchmark dependencies. A profile without a test against that server is a rumour.

One measurement from that matrix is worth repeating here, because it decides what any
"quirks" layer can ever do. Five distinct failure conditions — `MKDIR` on an existing
directory, `RENAME` onto an existing target, `CREAT|EXCL` on an existing file, `RMDIR` of a
non-empty directory, `REMOVE` of a directory — produce this:

| | OpenSSH | asyncssh | paramiko |
| --- | --- | --- | --- |
| all five | `Failure` | `File exists` / `File already exists` / `Directory not empty` / `Is a directory` | `Failure` |

**On OpenSSH the error message is a constant function of the error code.** So telling a
transient failure from a permanent one by reading the message — the standard proposal, and
the thing v3's catch-all `FAILURE` would need — cannot work on the reference server at all.
That is why retry classifies on exception type rather than on message text.

`examples/server_capabilities.py` prints the profile, the advertised extension list and the
session `repr` against whatever you point it at.

## Authenticating

There is no authentication code in this library, and that is the thesis working. `ssh` is the
client, so every method it supports works here with no adapter: keys from the agent,
`IdentityFile`, `ProxyJump`, host certificates, FIDO tokens, `Match` blocks, `ControlMaster`.
Point it at a host in your `ssh_config` and it connects the way `ssh` would.

```python
async with open_ssh_transport("prod-sftp", user="bob") as t, open_session(t) as sftp:
    ...
```

### When the `ssh_config` is not yours

"It connects the way `ssh` would" cuts both ways. An `ssh_config` is executable: `ProxyCommand`
runs a program to obtain the connection, and `Match exec` runs one during config *parsing*,
before a connection is attempted at all. If the config file is trusted — yours, or your
organisation's — that is the feature that makes `ProxyJump` and bastion hosts work for free. If
it is not, it is arbitrary command execution on the machine running the transfer.

The shipped defaults do **not** close that. `PermitLocalCommand=no` and `ClearAllForwardings=yes`
ship because an SFTP client has no business running `LocalCommand` or establishing forwardings,
and they are worth having — but neither touches `ProxyCommand` or `Match exec`, both of which
still execute with the full default set applied. Verified against OpenSSH 10.0p2 and pinned by
`tests/test_transport.py::test_the_shipped_defaults_do_not_neutralise_an_untrusted_config`.

The control is to not read the file:

```python
async with open_ssh_transport("host", user="bob", config_file=os.devnull) as t:
    ...
```

`-F` suppresses `/etc/ssh/ssh_config` as well as the per-user file, so this is a real "no
config" rather than half of one. Everything the config would have supplied — port, identity
file, username — has an explicit parameter, so the trade is verbosity rather than capability.

### Passwords

A large fraction of enterprise SFTP endpoints — MOVEit, GoAnywhere, Cleo, Sterling — are
password-first. Pass one:

```python
async with (
    open_ssh_transport("host", user="bob", password=os.environ["SFTP_PASSWORD"]) as t,
    open_session(t) as sftp,
):
    ...
```

**The secret never reaches argv.** `ssh` refuses to take a password as an argument, and the two
workarounds people reach for — `sshpass -p secret` and stuffing it into an `-o` value — both put
the credential where `/proc/<pid>/cmdline` makes it readable by every user on the machine, for
as long as the process lives. Instead, `password=` writes a throwaway `SSH_ASKPASS` helper to a
`0700` temporary directory and hands `ssh` the secret in the child's *environment*, which on
Linux only this user and root can read. The helper contains no secret — it is a `printf` of an
environment variable — and it is deleted when the connection ends, whether or not it succeeded.

Three `ssh` options change on that path, and the first of them is the reason the parameter
exists at all:

| option | value | why |
| --- | --- | --- |
| `BatchMode` | `no` | The shipped default is `yes`, and it does not merely discourage a prompt — it **suppresses the askpass helper outright**, regardless of `SSH_ASKPASS` or `SSH_ASKPASS_REQUIRE`. Password authentication was not awkward under the default; it was impossible. |
| `PreferredAuthentications` | `password,keyboard-interactive` | Deterministic order. Otherwise `ssh` offers every key it can find first, and against a server with a low `MaxAuthTries` the attempts run out before password is reached — failing with `Too many authentication failures`, which names nothing that is wrong. Appliances routinely offer only `keyboard-interactive`, and OpenSSH answers it through the same helper. |
| `NumberOfPasswordPrompts` | `1` | OpenSSH's default is three, each re-running the helper with the same wrong secret. Against an OpenSSH 9.8+ server that is three failed attempts, which earns your source address a `PerSourcePenalties` timeout that then breaks the *next* connection from that host. |

All three are overridable by name through `options=`, except that `password=` together with an
explicit `BatchMode=yes` is refused as the contradiction it is — with a `ValueError` naming
both halves, rather than a `Permission denied` twenty seconds later.

`password=` is POSIX-only: the helper is a shell script, and Windows OpenSSH's prompting path
has never been run here, so it raises `NotImplementedError` rather than shipping an untested
guess.

**What the library will not do**: write your password to a file, put it on a command line, read
it from one, or log it. Anything that can carry it is checked — `repr()` of the transport, the
captured stderr, `ConnectError.argv`, the rendered exception, and the **frame locals** a
traceback reporter captures — and `tests/test_askpass.py` runs the helper against passwords
built to break a shell (`$(...)`, backticks, `%s%n`, `-n`, embedded quotes) to prove what comes
back out is what went in.

That last surface is the least obvious one. The environment dictionary carrying the secret is a
local variable in an `@asynccontextmanager` generator, so its frame stays alive for the whole
connection — and Sentry captures frame locals by default, as do `pytest --showlocals`, `rich`
tracebacks and IPython's verbose mode. Every one of them renders a local with `repr()`, so the
secret is held in a `str` subclass whose `repr()` is `'<redacted>'`. It is still an ordinary
string everywhere it has to be one, so `ssh` receives it intact. What that does **not** cover,
stated plainly: a reporter that calls `str()` rather than `repr()`, a core dump, and
`/proc/<pid>/environ` — the last being the deliberate trade that buys not being in argv.

### `options=` matches names the way `ssh` does

Option names are matched **case-insensitively**, because that is how `ssh` reads them. An
override spelled `stricthostkeychecking` or `STRICTHOSTKEYCHECKING` replaces the shipped
`StrictHostKeyChecking` rather than joining it on the command line, and warns exactly as the
canonical spelling does.

This is not cosmetic. `ssh` resolves a repeated keyword to the **first** `-o` on the line, and
this library emits its options sorted — where ASCII puts every uppercase letter before every
lowercase one. Matching on exact case therefore let `STRICTHOSTKEYCHECKING=no` land ahead of
the default and silently win, with no `InsecureOptionWarning`, because the warning was reading
the default under its own spelling. The same shape defeated `PermitLocalCommand=no` and the
`BatchMode` contradiction check above. Measured against OpenSSH 10.0p2; pinned by
`tests/test_transport.py::test_ssh_matches_option_names_case_insensitively_and_takes_the_first`,
which characterises `ssh` rather than us, so a change in that behaviour fails loudly.

### Arming your own askpass helper

`password=` is a convenience over a mechanism that is still fully available: set `SSH_ASKPASS`
to any program of yours and `SSH_ASKPASS_REQUIRE=force` through `env=`, and override
`BatchMode`. `SSH_ASKPASS_REQUIRE=force` is what arms the helper on a headless machine —
measured, `SSH_ASKPASS` alone does not, and `DISPLAY` or `WAYLAND_DISPLAY` each arm it on their
own. This is also the path for a *passphrase* on an encrypted private key.

## When the connection fails

```python
from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError

try:
    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        ...
except AuthenticationError as e:
    ...  # credentials refused
except HostKeyError as e:
    ...  # the server's identity was not accepted -- do not retry blindly
except ConnectError as e:
    print(e.stderr)  # OpenSSH's own words, verbatim
```

paramiko answers this question with `Error reading SSH protocol banner`. OpenSSH knew exactly
what went wrong and said so; `ConnectError.stderr` carries that text unparsed, and the two
questions people actually ask — "was that my key?" and "has the host changed?" — are answered
by `except` rather than by string matching in your own code.

It is **bounded**, which "untouched" used to imply it was not: the first 8 KiB and the last
56 KiB, with `... [N bytes of stderr omitted] ...` marking the gap. Both ends, because the
first lines say what was attempted and the last say how it ended — and `ssh -vvv` is precisely
the case that overflows it. A hostile server also writes to that stream, so it is a buffer with
a cap rather than a string with a promise.

Three things about that ladder are deliberate:

- **Unrecognised failures stay `ConnectError`.** A refused connection, a name that will not
  resolve, a cipher mismatch — none of them are guessed into a more specific class. One that
  sometimes means "we guessed" is worth less than one that always means what it says.
- **Host keys are checked before credentials.** Of the two possible misclassifications only one
  costs anything: reporting a *changed* host key as a bad password tells you to check your
  credentials when what happened may be interception. OpenSSH prints a server-supplied banner to
  stderr, so a hostile server can put `Permission denied` in it — it cannot remove the host-key
  line `ssh` itself writes.
- **Every marker was captured from a real server**, not written from memory. A marker that is
  subtly wrong does not fail loudly; it silently stops matching and the class quietly goes back
  to being decorative.

`ConnectError.hint` is the one thing on these errors that is *ours* rather than OpenSSH's, and
it is separate from `stderr` for that reason — merging them would put words in the server's
mouth. It is set only where this client's own configuration made the failure inevitable, and
the case it exists for is the one the stderr cannot explain:

```
AuthenticationError: connection closed by the remote end (exit status 255)
ssh stderr:
bob@host: Permission denied (keyboard-interactive,password).
hint: the server offered password authentication and this client had it switched off:
BatchMode=yes suppresses the askpass helper outright, so no password was ever sent.
Pass password=... to open_ssh_transport()
```

That line names the methods the *server* offers and says nothing about the one we disabled.
Reading it is how people conclude the library is publickey-only. Note that it cannot be
produced from the text alone: `BatchMode=yes` with a working helper, and `BatchMode=no` with no
helper at all, are byte-identical on stderr, so the hint reads back the argv that was actually
spawned to tell them apart — and stays empty when a password *was* offered and refused, because
why the server said no is not something this client knows.

`examples/connect_errors.py` runs this with no arguments, and `examples/password_auth.py`
covers the password half.

## Timeouts, and stopping a transfer

```python
with anyio.move_on_after(30):
    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        await sftp.get("/incoming/big.iso", "big.iso")
```

Two timeouts ship, and they bound different things:

- **`request_timeout=30.0`** covers one round trip — the handshake, a `STAT`, an `OPEN`, a
  `CLOSE`. A server that accepts the connection and then says nothing trips it. It also bounds
  every **write**, including the wait for the connection's send lock.
- **`idle_timeout=60.0`** covers a bulk transfer's *silence*, not its duration. A nine-hour
  download over a slow link never trips it; sixty seconds with nothing arriving does.

`None` for either means no bound at all. It is a legitimate thing to ask for, and it is never
the default. It covers *teardown* as well, which is the half worth knowing: cleanup after a
cancelled transfer is shielded so that it survives the cancellation that triggered it, and a
shield is not cancellable from outside — so with `request_timeout=None` and a peer that has
stopped reading its socket, leaving the `async with` block waits forever on the cleanup
`CLOSE`. `request_timeout` is the only thing that bounds it.

**The write half was unbounded until 0.9, and "in practice it cannot block" is why** (D-40).
A request is around thirty bytes and a pipe holds 64 KiB, so a sender could not fill it — while
a session ran one transfer at a time. Once transfers share a connection, one upload's 255 KiB
`WRITE` fills the pipe and every other task's write queues behind it, so an ordinary concurrent
`get` against a peer that stopped draining hung forever with nothing to report it. Measured, not
argued: a probe drove every sending path against a server that stops reading, and two of them
never came back.

**A write that times out ends the connection**, rather than just the transfer, and that is
deliberate. A write puts a whole frame on the wire; abandoning one part-way leaves the peer
parsing a length prefix out of the middle of your payload. So the failure reaches every operation
on that session, and `with_reconnect()` treats it as retryable — a fresh connection rather than a
poisoned one.

Cancelling from outside — the `move_on_after` above, a task group whose sibling failed, Ctrl-C
— stops the transfer, and then cleans up **before** the block finishes unwinding:

- the remote handle is closed, and that is asserted against the server rather than against our
  intention to send a `CLOSE`;
- an interrupted `put` removes its staging file, so nothing is left in the directory a consumer
  is watching;
- the partial local file from a cancelled `get` stays, because that is what `resume=True`
  continues from.

**An `OPEN` that was abandoned is cleaned up too, and that one is not about cancellation.** A
request that timed out or was cancelled is still outstanding on the server, and if it was an
`OPEN` the server answers it by allocating a handle — which arrives with nobody waiting for it.
Nothing at the call site can catch that: there is no moment between the reply and the variable
in which to put a `try`. The session notices the unclaimed reply instead and closes the handle,
and `sftp.reaped` counts how often it has had to. A number that climbs is not a leak; it is a
server slow enough that callers are giving up on it.

Cleanup is shielded so it survives the cancellation that triggered it, and **the session's
reader is shielded for the same reason** — cleanup sends requests, and something has to read
the replies. When it was not, a cancelled transfer took a full `request_timeout` to unwind and,
with `request_timeout=None`, never finished at all (fixed in 0.8, D-34). The reader stops when
the `async with open_session(...)` block ends and at no other time; cancelling the task group
it happens to run in deliberately does not stop it.

`examples/cancellation.py` runs this with no arguments.

## Seeing what it is doing

Nothing is printed unless you ask. The package logger carries a `NullHandler`, so an
application that never configures `logging` sees nothing at all from this library — including
on stderr, which is where an unhandled warning would otherwise go.

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("gantry_sftp.session").setLevel(logging.DEBUG)  # one record per operation
logging.getLogger("gantry_sftp.transport").setLevel(logging.DEBUG)  # spawn and teardown
logging.getLogger("gantry_sftp.frames").setLevel(logging.DEBUG)  # every packet, both ways
```

| Logger                    | Level   | Carries                                                                        |
| ------------------------- | ------- | ------------------------------------------------------------------------------ |
| `gantry_sftp.session`     | DEBUG   | Handshake, and one record each when an operation starts and finishes            |
| `gantry_sftp.session`     | WARNING | A retryable failure `with_reconnect()` swallowed — the only warning in the tree |
| `gantry_sftp.transport`   | DEBUG   | The `ssh` child: pid, argv, the variables that steer authentication, exit status |
| `gantry_sftp.frames`      | DEBUG   | Every packet sent and received, decoded                                         |

```
DEBUG gantry_sftp.session   negotiated version=3 extensions=6 [b'posix-rename@openssh.com' ...]
DEBUG gantry_sftp.session   get start remote=b'/incoming/data.parquet' local='data.parquet'
DEBUG gantry_sftp.frames    -> STAT id=1 path=b'/incoming/data.parquet'
DEBUG gantry_sftp.frames    <- ATTRS id=1 attrs=(size=16777216 mode=0o100644)
DEBUG gantry_sftp.frames    -> READ id=3 handle=b'\x00\x00\x00\x00' offset=0 len=261120
DEBUG gantry_sftp.frames    <- DATA id=3 len=261120
DEBUG gantry_sftp.session   get ok remote=b'/incoming/data.parquet' bytes=16777216 elapsed=1.284s
```

**The frame dump is per packet and it means it** — a 16 MiB download is a few hundred lines and
a recursive tree is thousands. Turn it on for a protocol question. When it is off it costs one
`isEnabledFor` check per packet and nothing is rendered, which is asserted rather than assumed.

**Payloads are never in it.** `DATA` and `WRITE` show as `len=N offset=M`. That is not
squeamishness: a quarter-megabyte payload per line is unreadable, and rendering it would copy
the `memoryview` that the copy-free data path exists to avoid.

**Every server-supplied name is escaped and truncated.** A filename, a path and a `STATUS`
message are all chosen by the far end, and written raw into a log stream a `\n` forges a second
record while an `\x1b[` sequence drives the terminal of whoever is tailing the file. They are
rendered with `repr` — which escapes both, and every non-printable codepoint besides — and
capped at 96 bytes with the dropped count stated, because a 64 KiB filename is legal and a log
line per frame is a disk to fill.

`gantry_sftp.codec.describe(packet)` is the renderer, and it is public and pure: pass it any
packet and get the same line back, with no logging configured and no session running.

### Counters

`Session` carries cumulative totals beside the instantaneous gauges, and both are in its `repr`:

```python
sftp.requests_sent  # requests written to this connection, handshake excluded
sftp.replies_received  # replies routed, including ones nobody was waiting for
sftp.bytes_sent  # bytes handed to the transport, framing included
sftp.bytes_received  # bytes read from it
sftp.reaped  # handles closed on behalf of an abandoned OPEN

repr(sftp)
# <Session server=OpenSSH version=3 extensions=6 depth=64 outstanding=17
#  requests=142/125 bytes=4321/16783104 request_timeout=30.0 idle_timeout=60.0>
```

Two `repr`s a second apart is the cheapest diagnosis there is: same `outstanding` and moving
totals is a slow link, and same totals is a stall. `requests_sent` climbing while
`replies_received` does not is a server that has stopped answering.

There is deliberately **no retry counter**. `with_reconnect()` builds a new session per attempt,
so a counter would reset exactly when it became interesting — the WARNING above is where retry
visibility lives, and it names the attempt, the error and the backoff.

### Credentials

A password never reaches argv, a file, or a log record. It travels in the child's environment
via an `SSH_ASKPASS` helper, and:

- the value renders as `'<redacted>'` in any frame-locals dump — Sentry, `pytest --showlocals`,
  `rich`, IPython all render locals with `repr`, and that is the boundary it defends;
- the environment is masked by name before it can reach a log record, so the record says
  `'GANTRY_SFTP_ASKPASS_ANSWER': '<redacted>'` — the *presence* of an askpass answer is exactly
  what a failed password authentication needs to know, and the value is not;
- the mask also covers any variable whose name contains `PASSWORD`, `PASSPHRASE`, `SECRET`,
  `TOKEN` or `CREDENTIAL`, including ones this library never sets, so a caller's own `env=`
  overlay is covered too.

What that does **not** cover, stated because a half-understood guarantee is worse than none: a
reporter that calls `str()` rather than `repr()` on a local, a core dump, and
`/proc/<pid>/environ`. The last is the deliberate trade — owner-and-root readable beats `ps`
output readable by every user on the machine.

`examples/logging.py` runs all of this with no arguments.

## Why it is faster, and where it is not

Speed is not the objective — see above — but it is measurable, and a claim about it should
either be evidenced or dropped. This section is the evidence, including the parts that go the
wrong way.

Sustained SFTP throughput is bounded by bytes in flight, not by cryptography:

```
throughput ~= (outstanding_requests * request_size) / RTT
```

OpenSSH's own `sftp(1)` defaults to 64 outstanding requests of 32768 bytes — exactly 2 MiB
in flight, which caps a 100 ms transatlantic link at roughly 21 MB/s regardless of how fast
the machine is. That is a scheduling bug, not a crypto bug, and it is invisible on
localhost, which is why it went unnoticed for two decades.

That formula is now measured rather than argued. On a `tc netem`-shaped loopback link
against OpenSSH 10.0p2, raising pipeline depth from 1 to 64 at a fixed 32768-byte request
size transfers the same file **50.7× faster at 5 ms RTT, 36.8× at 50 ms and 24.8× at 200 ms**
(2026-07-29) — and on an unshaped link the same comparison is noise. At depth 1 the elapsed
time *is* one round trip per request, within 3%. The lane is
`live-tests/test_netem_pipelining.py` and it re-measures on every run.

**Those figures are for a connection that has already moved something**, and the difference
is worth knowing because it is not ours. The same three comparisons on a connection's *first*
transfer come out at 13.0×, 7.6× and 5.0×: a deep pipeline puts about a megabyte in flight
immediately, which is more than an initial TCP congestion window, so its opening round trips
are spent waiting for that window to open rather than for the server. Measured at six round
trips for a 768 KiB transfer as a connection's first, and **one** as its fourth. The practical
form of this: a session that transfers several files pays it once, and `ControlMaster` — which
this README recommends for the connect cost — pays it once for every session that shares the
control socket.

The benchmark's own headline scenario says the same thing in throughput. A 16 MiB download,
same file and same connection, timed as that connection's first transfer and as its second:

| RTT | first transfer | second transfer | |
| --- | -------------- | --------------- | --- |
| 50 ms | 18.4 MiB/s | 24.8 MiB/s | **1.35× faster** |
| 200 ms | 4.7 MiB/s | 6.3 MiB/s | **1.35× faster** |

(`benchmarks/`, `tc netem`-shaped loopback against OpenSSH 10.0p2, 2026-07-29.) The warm figure
is about 82% of what the 2 MiB channel window implies, once the three round trips `get` spends
on `STAT`, `OPEN` and `CLOSE` are subtracted — so **the ceiling is reachable, and reaching it is
a property of reusing the connection** rather than of tuning anything. Every cross-library row
below is a first transfer, for all three libraries, because the benchmark opens a fresh
connection per sample so that the cost of connecting is not hidden.

### The ceiling, which is not ours

The same lane found where the formula stops. Throughput follows **bytes in flight** rather
than depth or request size individually — three different (depth × size) pairs multiplying to
the same product perform within 4% of each other — and it stops improving at **2 MiB**.
Going from 0.5 MiB to 2 MiB in flight roughly doubles throughput; going from 2 MiB to 8 MiB
changes it by about 1%, whether the 8 MiB is reached with deep small requests or shallow
large ones.

2 MiB is OpenSSH's per-channel flow-control window. It is enforced by the SSH transport, one
layer below anything this library does, so no amount of pipelining lifts it. Three things
follow, and they are worth knowing before you tune anything:

- **`sftp(1)`'s defaults are not timid.** `-R 64 -B 32768` is exactly the channel window.
  What this library fixes is clients that never reach 2 MiB, not `sftp(1)`'s inability to
  exceed it.
- **Past 2 MiB the lever is more channels, not more depth.** Raising depth beyond the window
  buys memory consumption and nothing else. Concurrent transfers over one session now work,
  and they help by *reaching* the window rather than exceeding it — one `ssh` child is one
  channel is one window. A second connection is what gets a second window, and this library
  does not manage a pool of them yet.
- **It is not OpenSSH's idiosyncrasy — it is the ecosystem's default.** Read off the sources
  while building the benchmark: `paramiko.transport.DEFAULT_WINDOW_SIZE` is 2097152 with a
  32768 max packet, and `asyncssh.connection._DEFAULT_WINDOW` is `2*1024*1024` with the same
  packet size. The same two constants three times. Nobody is past 2 MiB today — but paramiko
  and asyncssh implement SSH and could raise their own window, and we cannot raise OpenSSH's,
  because not implementing SSH is the whole point. That is a real cost of this architecture and
  it is written down here rather than left for someone to discover with a tuned paramiko.

### Measured against paramiko and asyncssh

`benchmarks/` now exists, so the comparison is a measurement rather than a promise. Three
libraries, one uniform interface, the same `sshd`, five link profiles, every scenario verifying
the bytes it moved. Against **paramiko 5.0.0** and **asyncssh 2.24.0** on OpenSSH 10.0p2 over
`tc netem`-shaped loopback:

| scenario | vs paramiko | vs asyncssh |
| -------- | ----------- | ----------- |
| download 16 MiB | **1.6–3.2× faster** | 1.1–1.4× faster |
| upload 16 MiB | 1.2–1.5× faster | up to 1.5×, level on the rate-limited profile |
| N × 8 KiB download, sequential | ~1.5× faster | **a tie** |
| N × 8 KiB upload, sequential | level shaped (≤1.05×); **1.7–1.8× slower unshaped** | level shaped (≤1.07×); 1.1–1.2× slower unshaped |
| connect and close | **1.2–1.4× slower** | **1.2–2.1× slower** |
| CPU per MiB, download | about the same | **1.2–1.6× worse** |
| CPU per MiB, upload | 1.1–1.6× better | mixed, 0.7–1.4× |

Ratios across 5, 50 and 200 ms RTT plus a 100 Mbit/s rate-limited profile, taken as the
**union of three full runs** rather than the best one. That widening is not padding: the runs
put the download range at 1.9–2.6×, then 1.6–2.3×, then 1.6–3.2×, because paramiko's 200 ms row
is genuinely noisy — its spread column has reached 3.67 across those runs while ours stayed near
1.1. A range that only one run reproduces is a number with an expiry date on it, and the widest
ratio in that table is drawn from the least stable row. Absolute figures, the exact host and the
full caveats are in the report the suite writes; re-run it with
`python scripts/lanes.py benchmarks` and it re-derives all of them.

The **small-file upload row is newer and its range comes from two runs, not three** — it was
added in 0.8 when the size check gave every `put` an extra `STAT` and it emerged that the matrix
could not see a per-file cost at all: every small-file row was a download, and both 16 MiB
upload rows move one file. Those two 16 MiB rows were re-measured in the same pair of runs and
did not move outside the ranges above; at 200 ms RTT the added round trip shows up as roughly
+0.15 s on a 3.3 s transfer, which is the one `STAT` and nothing else.

**Concurrency, measured against ourselves.** The same small-file corpus over one connection,
eight transfers at a time against one at a time: **3.1× on unshaped loopback, 9.1× at 5 ms RTT
and 8.0× at 50 ms**, with CPU per MiB *lower* rather than higher. Us against us, deliberately —
paramiko and asyncssh can be driven concurrently too, so racing our task group against their
`for` loop would measure a feature gap while looking like a speed gap, and the cross-library row
above stays sequential for all three. The gain is round trips, which is why it grows with
latency and why the unshaped number is the smallest one here.

Three of those rows are not the ones a pitch would choose, and they are the interesting ones.

**We lose small-file upload on a fast link, and we win small-file download on the same one.**
Unshaped, 200 × 8 KiB: 3.0–3.2× *faster* than paramiko downloading, 1.7–1.8× *slower* uploading,
same files, same count, same connection. With the round trips nearly free the difference is
per-operation work in Python, and the CPU column says so. It disappears the moment the link has
any latency, where all three tie, so it costs nothing on the networks this library is for and
everything on loopback. It is not the size check — paramiko performs the same one.

**Measured 2026-07-28, and the swing between those two rows is mostly not ours.** Ranging each
library against *itself* on the same corpus and connection: our upload is **1.25×** our own
download, while paramiko's upload is **0.23×** theirs — paramiko's small-file `get` is over four
times its own `put`, and disabling its prefetch does not change that. So the cross-library rows
above are two facts, not one. Our own direction asymmetry is modest and its largest single
component is that `put` reads the local file in a worker thread while `get` calls `os.pwrite`
inline — worth 75–130 µs per file, about a third of the gap. The anyio primitives in that path
are innocent: a task group, a semaphore acquire and an event wait total ~17 µs per file, measured
directly.

**Read the download row with that in mind.** It is an honest measurement of both libraries'
default APIs, which is the benchmark's fairness rule — but a good part of the 3× is paramiko's
`get`, not our scheduler. The row that demonstrates what the scheduling actually buys is the
`one connection` one below, which is this library against itself.

The upload gap is **measured, understood and deliberately not fixed** (D-72). Restoring the
symmetry means reading small payloads inline, which trades away the property that a slow local
disk cannot stall the receive side — to win back tens of milliseconds on a link with no latency,
which is the one case nobody ships.

**"No cryptography in Python" does not become a CPU win.** `cryptography` is OpenSSL and
OpenSSL uses the CPU's AES instructions, so the expensive part was never interpreted in either
design. What moves out of Python is per-packet framing work, and we pay a pipe copy for it. The
thesis in §5 was always that this is a *scheduling* win rather than a crypto one — the wall
clock column says that is right, and the CPU column is what stops the softer claim being
written down.

**Connecting is our weak spot, and it is structural.** Spawning `ssh` costs a fork, an exec and
OpenSSH's own configuration parsing before a packet moves — 0.5–0.9 s extra per connection at
200 ms RTT, and 1.5–3.9× the CPU of an in-process handshake. The gap is widest where latency is
lowest (2.1× against asyncssh at 5 ms, 1.2× at 200 ms), which is the signature of a fixed
process-startup cost rather than an extra round trip. For connection-heavy workloads
`ControlMaster` is not an optimisation, it is the fix.

The ratios in the section above are this library measured against *itself*, which is a weaker
kind of claim and is labelled as one. Nothing here is an unattributed "10× faster than
paramiko": every figure names its link, its server, its versions and the benchmark that
produced it, and that benchmark re-runs.

## Tunables, and what they default to

Every knob this library has, with the number it ships as. There are four, and three of them
you should not need.

| Setting | Default | What it bounds | When to change it |
| --- | --- | --- | --- |
| `request_timeout` | `30.0` s | One round trip — the handshake, a `STAT`, an `OPEN`, a `CLOSE` — **and one write**, including the wait for the send lock | Raise for an appliance that thinks slowly; `None` for no bound at all |
| `idle_timeout` | `60.0` s | A bulk transfer's *silence*, not its duration. A nine-hour download never trips it; sixty seconds with nothing arriving does | Raise if the far end legitimately pauses for minutes mid-transfer |
| `depth` | `64` | Requests in flight per transfer | Lower it to bound memory on an upload (each in-flight request holds a payload); raising it does not raise throughput — see below |
| request size | `261120` bytes | Payload per `READ`/`WRITE` | Not a parameter. Derived per connection from `limits@openssh.com`, clamped to what the server says it will accept |

All three parameters are keyword arguments to `open_session()` (and to `with_reconnect()`,
which forwards them). `None` for either timeout means no bound; it is a legitimate thing to
ask for and it is never the default.

**Why the request size is not 256 KiB.** It is the round number, and it is unachievable: the
reference server reports `max-packet-length` 262144 and `max-read-length` 261120, because the
packet also carries the type byte, the request id, the handle and the offset. Asking for the
round number means being clamped on every single request forever. Worse, a frame *over* the
packet limit is not refused — measured, `sftp-server` exits with no `STATUS` and an empty
stderr, and the connection dies mid-write. So the size is derived, not defaulted.

**Why raising `depth` past 64 does nothing.** 64 × 255 KiB is what the client *issues*; what
the connection can hold is the SSH channel window, which is 2 MiB (measured — see below).
Issuing past the ceiling is deliberate, so that a server which clamps the request size still
reaches it, but the bytes in flight are the window's business. More depth buys memory
pressure. The thing that would buy throughput is a second connection.

## Requirements

- Python 3.13+
- **A POSIX host.** Transfers need offset-addressed local I/O — `get` places every payload
  with `os.pwrite` at the offset its request asked for, `put` reads with `os.pread` from a
  worker thread, and `preserve_times` stamps a descriptor rather than a path. All three are
  Unix-only in CPython, and they are not incidental: writing at an explicit offset is why
  writes need no ordering and why a short `READ` is re-queued rather than restarting the
  transfer. On Windows `get` / `get_tree` / `put` / `put_tree` raise `NotImplementedError`
  naming what is missing, before anything is sent and before any local file is touched.
  Everything that talks only to the far end — connecting, `listdir`, `scandir`, `walk`,
  `stat`, `realpath`, `rename`, `remove`, `mkdir`, `rmdir`, `rmtree`, `check_file` — is
  platform-independent and works there. A Windows fallback is open work, not a decision
  against it.
- An `ssh` binary on `PATH` (`openssh-client`). Windows ships one at
  `%SystemRoot%\System32\OpenSSH\ssh.exe`; slim Docker images frequently do not.
- `openssh-server` — **only** to run the real-server test lane, never at runtime.

## Development

```bash
export UV_CACHE_DIR=/workspace/.uv-cache   # the default cache is root-owned here
uv sync
.venv/bin/pre-commit install               # sets up pre-commit and pre-push
```

Every proof this project has is a **lane**, and `scripts/lanes.py` is the one place they are
named. Run it with no arguments for the table — what each lane proves, what it needs installed
first, roughly how long it takes, and whether it gates:

```bash
python scripts/lanes.py                 # the table
python scripts/lanes.py gates fast      # what has to pass before anything lands
python scripts/lanes.py -n benchmarks   # print the argv it would run, run nothing
```

| lane | what it proves | needs, beyond `uv sync` |
| --- | --- | --- |
| `lanes.py gates` | ruff, mypy `--strict`, ty, complexipy, the `uv.lock` check, the exec bit | nothing; POSIX only |
| `lanes.py fast` | unit tests, the real `sftp-server` rows, every example as a subprocess | `openssh-server` for some rows |
| `lanes.py live` | a real `sshd` on localhost: transport, `ssh` environment, cancellation, handles | `openssh-server` |
| `lanes.py matrix` | one client against three servers — OpenSSH, asyncssh, paramiko | `uv sync --group bench` |
| `lanes.py netem` | every pipelining claim, on a `tc`-shaped link at 5/50/200 ms RTT | `CAP_NET_ADMIN` |
| `lanes.py benchmarks` | wall clock and CPU against paramiko and asyncssh | both of the two above |
| `lanes.py mutation` | whether an assertion would notice the line being wrong | nothing |

The first four **gate**: a failure stops the change. The last three **report** — they measure,
or they assert against a baseline that is not in this tree — and `scripts/lanes.py` carries the
reason next to each one, so opting a lane out of gating is a written act rather than a habit.

Type checking is deliberately two-tool: mypy is stricter and catches gaps ty misses. A
finding gets fixed at the source, never silenced with an ignore.

`tests/` and `examples/` need no network and are what `fast` runs — every example is executed
as a subprocess, because an example that has drifted out of sync with the library is a
confident, wrong answer somebody will copy. `live-tests/` starts a real `sshd` on localhost;
`benchmarks/` needs that plus a shaped link and the comparison libraries. Both are excluded
from the default `pytest` run, and every lane skips with a reason rather than failing when the
thing it needs is absent.

The comparison libraries are a separate dependency group and are deliberately not installed by
default. They pull in `cryptography`, `pynacl` and `bcrypt` — Python cryptography is precisely
what this project exists not to need, and a `uv sync` that installed it would make that claim
harder to check than it should be. No lane installs them on your behalf, for the same reason.

### CI

`.github/workflows/ci.yml` runs those lanes on Linux, macOS and Windows. It invokes them
through `scripts/lanes.py` rather than spelling out a `pytest` command of its own, so CI and a
developer cannot drift into running different things; `tests/test_lanes.py` asserts both that
and that every lane the runner knows about is named in the workflow.

**It has never run.** There is no git remote yet, so GitHub has never seen this repository.
The file is committed anyway, because deciding which lane runs where and what it needs is most
of the work and none of it needs a remote — and because a Windows job is the only thing that
can settle whether `resolve_ssh_executable`'s `SysNative`-before-`System32` probe is right. It
is unit-tested with injected inputs and has never executed on Windows.

That Windows job **reports rather than gates**, and not out of caution. Transfers are
POSIX-only (see Requirements) and refuse there, so every test that moves bytes fails on
Windows by design. Making that job gate needs the out-of-scope rows marked as such, and
marking them before a single Windows run has happened would be guessing at which ones they
are. The job stays in the matrix because what is wanted from it is exactly that list, and no
amount of reading the code produces it.

### The controlled `ssh` environment

Every `ssh` these suites spawn gets `-F /dev/null` and an environment with `SSH_AUTH_SOCK`,
`SSH_AGENT_PID`, `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE`, `DISPLAY`, `WAYLAND_DISPLAY`, `SHELL` and
`SSH_SK_HELPER` removed. That is not hygiene for its own sake. Without it, a developer with an
agent running has that agent supply a working key to the test that means to fail with the
*wrong* one — and the assertion that we surface `Permission denied` verifies nothing while
staying green.

`live-tests/test_ssh_environment.py` proves it, and the interesting half is *how*. It reads the
child's environment directly rather than inferring it from behaviour: `ProxyCommand` is executed
by the `ssh` client and inherits its environment verbatim, so a proxy that dumps its own
`os.environ` reports what `ssh` was handed rather than what we meant to hand it. Then it
reproduces the hazard, with a real `ssh-agent` holding the *right* key while the connection is
made with the *wrong* one:

| parent environment | `IdentitiesOnly` | result |
| --- | --- | --- |
| scrubbed | `yes` | `Permission denied (publickey)` |
| scrubbed | absent | `Permission denied (publickey)` |
| agent visible | `yes` | `Permission denied (publickey)` |
| agent visible | absent | **authenticates** |

Two independent defences, each sufficient on its own. The bottom row is what stops the other
three being four ways of saying "the connection failed for some reason".

Writing those proofs corrected two beliefs this repository had been running on, both measured
against OpenSSH 10.0p2:

- **Redirecting `HOME` does not keep your `~/.ssh` out of a test run.** `ssh` resolves `~` from
  the password database, not from `$HOME` — with `HOME` pointed at an empty directory it still
  reads the real `~/.ssh/config` and still loads the real default identities. **`-F` is the
  defence**, and nothing asserted it either. The redirect stays for its real and narrower scope:
  it is inherited by the children `ssh` spawns, and it expands inside `-o` values such as
  `ControlPath=${HOME}/…`.
- **Clearing `SSH_ASKPASS` does not disarm the askpass helper.** `/usr/bin/ssh-askpass` is
  compiled in as the default, and the variables that *arm* it are `DISPLAY` and
  `WAYLAND_DISPLAY` — either alone is enough to make a passphrase-protected key authenticate
  through a helper. Both were missing from the set; `WAYLAND_DISPLAY` appears nowhere in
  `ssh(1)`.

### The netem lane

`live-tests/test_netem_pipelining.py` is where every claim about pipelining is made, because
it is the only place a pipelining bug is visible: on an unshaped link a lockstep client and a
deeply pipelined one finish at the same time. It shapes loopback with `tc netem` at 5, 50 and
200 ms round-trip times, with packet loss, and it takes about 70 seconds.

Shaping needs `CAP_NET_ADMIN`. In a container that means starting it with
`--cap-add=NET_ADMIN` — capabilities cannot be added to a running container — and, if the
tests do not run as root, a way for the test user to exercise it (passwordless `sudo`, or
`setcap cap_net_admin+ep` on the `tc` binary). The lane probes for this by adding a real qdisc
and removing it again, rather than by reading `/proc/self/status`: a capability can sit in the
bounding set and be unusable, and be perfectly usable through `sudo` while `CapEff` reads all
zeros. When it cannot shape, every test in the file skips with the line that would fix it.

Two things to know if you read the numbers it prints. `netem`'s delay applies **per traversal**
of the interface, so a 200 ms round trip is configured as `delay 100ms` — the module halves it
for you and then *measures* what the kernel actually did, because a benchmark that reports its
own configuration has checked nothing. And the profile is held only for the duration of one
test: shaping `lo` slows down everything else in the container, including the rest of the
suite.

Every async test runs on both anyio backends, asyncio and trio. That is deliberate: the
reason for depending on anyio at all is that it costs nothing and buys trio support, and a
codebase that has only ever run on asyncio is one accidental `asyncio.Queue` away from not
having it.

It **reports rather than gates**, and the reason is written next to the lane rather than only
here: two of its rows compare ratios of measured throughput and have each failed once under load
and passed on every re-run since. A lane that fails for reasons unrelated to the code is a lane
whose failures get re-run instead of read, which is exactly how the regression it exists to
catch would get waved through. Widening the thresholds without the measurement that justifies
them would be the same mistake in the other direction, so it is open work rather than a fix.

### The benchmark lane

`benchmarks/` is the source of truth for every performance number in this repository. It reuses
the netem shaping and the `sshd` harness from `live-tests/` rather than copying them — two
spellings of "how this suite connects" is how the scrubbed `ssh` environment ends up applied in
one of them and not the other, and a benchmark that quietly read your `ssh_config` would report
your `Compression yes` as a change in the library.

It reports **wall clock and CPU side by side**, because on a latency-bound link all three
clients hit the same 2 MiB channel window and wall clock alone cannot see the architecture. CPU
comes from `getrusage(RUSAGE_SELF) + RUSAGE_CHILDREN`, which is the only counter that can see
an `ssh` subprocess at all — and because `RUSAGE_CHILDREN` accounts only for children that have
been *reaped*, the CPU window necessarily spans connect through close rather than the transfer
alone. The `connect` scenario measures that half separately so it can be subtracted, and every
client is measured through the same wider window. That mechanism has its own test in `tests/`,
because a counter silently returning only this process's time would fail nothing and publish a
number saying the thesis is free.

Repeats are few, so every row carries a **spread** (slowest ÷ fastest) and a ratio drawn from
overlapping sample ranges is printed with `(overlapping)` beside it. With three samples a
*p*-value would be theatre; non-overlapping ranges is something you can check by eye.

The fairness rules — best default API per library, host keys verified by all three, no agent or
`ssh_config` for any of them, our own atomic publish switched off in the comparison row and
measured separately — are in `benchmarks/README.md`, one written line per decision that could
have gone the other way.

### The mutation lane

Coverage says a line ran. It does not say an assertion would have noticed the line being
wrong. For frame parsing and offset arithmetic that distinction is the whole game, so the
codec carries a `mutmut` run:

```bash
python scripts/lanes.py mutation   # ~4 minutes; scoped to codec/ by pyproject.toml
.venv/bin/mutmut browse            # inspect survivors
.venv/bin/mutmut results           # non-interactive list
```

It is a lane, not a pre-commit gate — it takes minutes, not seconds. A surviving mutant in
`codec/` is a missing test, not a curiosity, and the survivors that are genuinely
*equivalent* (no test can distinguish them) are listed with their reasons in
a register rather than suppressed, so a future run has a baseline to diff against
instead of a triage to redo.

It reports rather than gates, and the reason is mechanical: `mutmut run` exits 0 whether or
not mutants survive, and the register of known-equivalent survivors is not in this repository,
so there is nothing here for a machine to diff a run against. Comparing the two is a human
step until that changes.

`mutmut` mutates only functions the tests call, and it mutates the copy of the library it
writes into `mutants/`. Test selection is `tests/` alone: `examples/` runs each example as a
subprocess, which imports the *installed* library rather than the mutated copy, so those
tests cannot kill a mutant and would only add wall-clock.

## License

Apache-2.0.

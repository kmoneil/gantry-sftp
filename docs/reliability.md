# Reconnecting, timeouts and cancellation

What happens when the link drops, when the far end stops answering, and when you stop the
transfer yourself.

## Reconnect and retry

A session cannot reconnect itself, and that is deliberate: `open_session()` is handed a
transport whose lifetime is the caller's. Reconnection lives one level up and needs a
_recipe_: any zero-argument callable that produces a new transport:

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
Nothing survives a reconnect: not the remote handles, not the request ids, not the
negotiated limits. So it has to be _resumable_ (`get`/`put` with `resume=True`, which
re-establishes the offset from what is actually there) or _idempotent_ (`listdir`,
`get_tree`). A `rename` is neither: v3 `RENAME` refuses an existing target, so a lost reply
makes the second attempt fail. Nothing here can tell the difference for you, so it is stated
rather than guessed at.

That is also why "writes are never blindly replayed" needs no machinery: it is `resume`'s
own check, and its weaker claim on the upload side is made once per attempt.

`is_retryable()` is the classification, and it is public because you may want to disagree
with it:

| Retryable                                              | Terminal                                                         |
| ------------------------------------------------------ | ---------------------------------------------------------------- |
| `ConnectError`, the transport died                     | `AuthenticationError`, `HostKeyError`                            |
| `TransferTimeoutError`, the far end went quiet         | `NoSuchFileError`, `PermissionDeniedError`, `UnsupportedError`   |
| `ServerError` with `NO_CONNECTION` / `CONNECTION_LOST` | `ServerError` with `FAILURE`, `ProtocolError`, `UnsafePathError` |

Two of those deserve their reasons. **A failed authentication is never retried**, and not just
because credentials do not become correct by being offered again: OpenSSH 9.8+ applies
`PerSourcePenalties`, so repeated failed auth from one address gets that address
progressively locked out, so a retry loop turns one wrong key into a host that stops answering
for everything behind that IP. And **`FAILURE` is terminal**, even though it is sometimes
transient: v3's catch-all is what a permission problem, a full disk, a name collision and a
momentary appliance hiccup all arrive as, so retrying it would turn every fast clear failure
into three slow ones. That is still true of `is_retryable()` and of `with_reconnect`, which
reconnect a whole operation; a narrower rule that repeats a *single request* on the session you
already have is described under [A refusal that clears](#a-refusal-that-clears) below.

**A status code v3 has no name for also arrives as `FAILURE`**, and that is a decision rather
than a coincidence. A server answering an extension from the v6-era draft may legally reply with
a v6-era code — `SSH_FX_FILE_IS_A_DIRECTORY` is 24, and filexfer v3 stops at 8. Some servers map
those down themselves and keep the detail in the message; asyncssh is one. Others send the number
as-is. This client now produces the same thing either way: `FAILURE`, with the number kept on
`Status.raw_code` and named in the error text, so you never have to know which kind of server you
are talking to. It used to raise instead, and because a protocol error is terminal, a conformant
server answering conformantly dropped the connection.

## A refusal that clears

Some refusals are about a resource rather than about your file, and they pass on their own. The
one this library has measured is descriptor exhaustion: a server that has run out of file
descriptors refuses the next `OPEN`, and answers the identical request once another transfer
closes one. That is what DESIGN §7 means about appliance servers degrading rather than erroring
under deep pipelining.

**`get` retries such a refusal, up to three attempts, with a short doubling delay** — and it does
so on the session you already have, without reconnecting. `get_tree` inherits it, because it
transfers by calling `get` per file. **Both verification rungs retry too**, which matters more than
it sounds: without it a busy server could let the transfer succeed and then fail the check on the
file it just delivered, which reads exactly like a corrupt transfer of a file that is correct.
Nothing is switched on: there is no parameter, and there is nothing to configure.

One read-open deliberately never retries — the compatibility battery's. A report that says what a
server does must not retry until the server behaves, or a server refusing one open in three is
reported as healthy.

**It is a per-server capability, and it is off wherever the server does not explain itself.** The
retry fires only when the profile in `session.profile` says this server's `STATUS` text carries
information (`informative_messages`) *and* the message matches a condition measured against that
server. Of the three implementations in the test matrix, asyncssh is the only one that qualifies.
A server this library has no fingerprint for gets the conservative answer and is never retried.

Three limits, each deliberate:

- **Downloads only.** A `WRITE` whose reply was lost may or may not have landed, so re-sending
  the same bytes at the same offset is idempotent only on a server that behaves like a
  filesystem. Uploads are not retried this way, and `resume=True` remains the answer there.
- **The open, not the transfer.** The refusal lands on the request that acquires the descriptor.
  A `READ` runs against one the server already holds, so a mid-transfer `READ` failure is a
  different condition, and this does not claim to cover it.
- **Bounded, on purpose.** Resource exhaustion is exactly the failure where every client
  retrying without limit is what keeps the resource exhausted. Three attempts, then the server's
  own error reaches you unchanged.

Each retry is logged at `WARNING` — the same reasoning as `with_reconnect`'s, in
[observability](observability.md): a swallowed failure that nothing records makes a server that
refuses every second open indistinguishable from a healthy one.

**Against OpenSSH none of this applies, and it cannot at any layer.** OpenSSH's `STATUS` message
is a constant function of the status code: five distinct conditions, from a full disk to a name
collision, all send the single word `Failure`. That was already measured for those five, and it
has now been measured for a *transient* condition too — the reference server reaches the same
descriptor ceiling, recovers the same way, and still says only `Failure`, so there is nothing in
the reply to classify on. The claim is closed rather than merely well-supported. Against
`sftp-server`, a transient `FAILURE` mid-transfer still kills the transfer, and what you get is
`with_reconnect` re-running the whole operation when the _link_ drops — from the top, or with
`resume=True`, from where it got to.

**`BAD_MESSAGE` is terminal too, and it does not mean what its name says.** It reads as "the
frame you sent was malformed", which would make it a bug in this library rather than an answer
about your file. On OpenSSH it is also where `EINVAL` and `ENAMETOOLONG` land, so a `readlink`
of a path that is not a symlink, or an operation on an over-long name, arrives under it. That is
measured, and it is the reason it sits in the terminal column rather than raising as a protocol
error. A genuinely unparseable frame does not produce this code at all: `sftp-server` exits without
answering.

`examples/retry.py` drops a link mid-download and finishes it on the next connection.

## Timeouts, and stopping a transfer

```python
with anyio.move_on_after(30):
    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        await sftp.get("/incoming/big.iso", "big.iso")
```

Two timeouts ship, and they bound different things:

- **`request_timeout=30.0`** covers one round trip: the handshake, a `STAT`, an `OPEN`, a
  `CLOSE`. A server that accepts the connection and then says nothing trips it. It also bounds
  every **write**, including the wait for the connection's send lock.
- **`idle_timeout=60.0`** covers a bulk transfer's _silence_, not its duration. A nine-hour
  download over a slow link never trips it; sixty seconds with nothing arriving does.

`None` for either means no bound at all. It is a legitimate thing to ask for, and it is never
the default. It covers _teardown_ as well, which is the half worth knowing: cleanup after a
cancelled transfer is shielded so that it survives the cancellation that triggered it, and a
shield is not cancellable from outside, so with `request_timeout=None` and a peer that has
stopped reading its socket, leaving the `async with` block waits forever on the cleanup
`CLOSE`. `request_timeout` is the only thing that bounds it.

**The write half was originally unbounded, and "in practice it cannot block" is why** (D-40).
A request is around thirty bytes and a pipe holds 64 KiB, so a sender could not fill it, while
a session ran one transfer at a time. Once transfers share a connection, one upload's 255 KiB
`WRITE` fills the pipe and every other task's write queues behind it, so an ordinary concurrent
`get` against a peer that stopped draining hung forever with nothing to report it. Measured, not
argued: a probe drove every sending path against a server that stops reading, and two of them
never came back.

**A write that times out ends the connection**, rather than just the transfer, and that is
deliberate. A write puts a whole frame on the wire; abandoning one part-way leaves the peer
parsing a length prefix out of the middle of your payload. So the failure reaches every operation
on that session, and `with_reconnect()` treats it as retryable, giving a fresh connection rather
than a poisoned one.

Cancelling from outside, whether by the `move_on_after` above, a task group whose sibling failed
or Ctrl-C, stops the transfer, and then cleans up **before** the block finishes unwinding:

- the remote handle is closed, and that is asserted against the server rather than against our
  intention to send a `CLOSE`;
- an interrupted `put` removes its staging file, so nothing is left in the directory a consumer
  is watching;
- the partial local file from a cancelled `get` stays, because that is what `resume=True`
  continues from.

**An `OPEN` that was abandoned is cleaned up too, and that one is not about cancellation.** A
request that timed out or was cancelled is still outstanding on the server, and if it was an
`OPEN` the server answers it by allocating a handle, which arrives with nobody waiting for it.
Nothing at the call site can catch that: there is no moment between the reply and the variable
in which to put a `try`. The session notices the unclaimed reply instead and closes the handle,
and `sftp.reaped` counts how often it has had to. A number that climbs is not a leak; it is a
server slow enough that callers are giving up on it.

Cleanup is shielded so it survives the cancellation that triggered it, and **the session's
reader is shielded for the same reason**: cleanup sends requests, and something has to read
the replies. When it was not, a cancelled transfer took a full `request_timeout` to unwind and,
with `request_timeout=None`, never finished at all (fixed by D-34). The reader stops when
the `async with open_session(...)` block ends and at no other time; cancelling the task group
it happens to run in deliberately does not stop it.

`examples/cancellation.py` runs this with no arguments.

## Surviving the process, not just the connection

Everything above survives the *connection* failing. A killed container, an OOM, a deploy or a
laptop lid is a different failure, and until D-166 an upload did not survive it:

```python
from gantry_sftp import Publish, UploadJournal

journal = UploadJournal(Path("/var/lib/myjob/uploads.journal"))

await sftp.put(source, "/incoming/big.iso", resume=True, publish=Publish(journal=journal))
```

Run that again after a crash and it continues from where the killed run stopped. Without the
journal, the same call is **refused** — and understanding why is the whole of this feature.

An atomic publish writes to a hidden sibling whose name carries fresh randomness per call, so a
killed run leaves `.big.iso.7f3a1c22.part` with a name the next run cannot reconstruct. There is
nothing to resume *into*, and re-uploading silently would be the downgrade this library refuses
everywhere. The obvious fix — deriving the staging name from the target so it is findable — is
worse: a predictable name is what the randomness is *for*, and two publishers resuming into one
would interleave into a single file.

**The journal makes this run's own name recoverable without making any name predictable.** It is
local and private to whoever wrote it, so a second publisher on another machine has a different
journal and a different token, and the hazard is untouched.

### A whole tree, not just one file

`put_tree(resume=True)` takes the same journal and needs nothing else (D-172):

```python
await sftp.put_tree("outgoing/", "/incoming", resume=True, publish=Publish(journal=journal))
```

Each file records its own random staging name under its own target, so a run killed partway
through a tree resumes the file that was in flight and re-sends nothing that was already
published. This is the case the append-only format was chosen for — see
[Durability](#durability-and-the-shape-that-follows-from-it) — and one journal serves any
`concurrency=`.

Without a journal, `put_tree(resume=True)` still requires `publish=Publish(atomic=False)` and
raises with neither, for the reason above: there is nothing to resume *into* when no record of
the staging names exists. [Resuming a tree](transfers.md#resuming-a-tree) has the comparison
table.

### Downloads need none of this

`get(..., resume=True)` already survived a process death and still does. Its partial is a file on
your own disk, so its length is a fact rather than a report — which is the same asymmetry
[Resume](transfers.md#resume) describes, one level up. There is no download journal and there is
no plan for one.

### What it records, and what it deliberately does not

**No offsets.** After a crash the process knows what it *intended*, not what the far end accepted,
and an upload's remote partial is a report from a server that may have buffered and is under no
obligation to have flushed. So the journal records a **name** — a fact about a decision made
locally — and never a byte count. Where to resume from is still read off the server, and
`result.resume_check` still labels how well that was proven. **The journal adds no trust**: one
that is stale, truncated or hostile costs a wasted round trip and a full re-upload, never a wrong
file.

| it records                       | it never records                        |
| -------------------------------- | ---------------------------------------- |
| the staging path this run chose  | how many bytes were sent                 |
| the target it will be published at | what the server acknowledged           |
| the source's path, size and mtime | anything about the destination's state  |

The source's size and mtime are what refuse the dangerous case: a file edited between the killed
run and this one has a partial on the server that is a prefix of *different* bytes, and finishing
it produces a plausible file that is a splice of two versions. A same-length rewrite is invisible
to every other check, which is why the mtime is there.

### Durability, and the shape that follows from it

Each record is one line, appended and `fsync`ed before the request it describes — because an
unanswered request must be assumed to have been performed, so the note has to be durable before
anything could create the file. The directory entry is flushed too the first time, since a file's
contents reaching disk says nothing about whether its *name* did.

Append-only rather than a rewritten document, because `put_tree(concurrency=N)` runs N uploads
against one journal and a read-modify-write would need a lock and would lose records. `compact()`
is how it stops growing, and it is explicit: it is the one operation that rewrites.

### What a big journal costs, and what it does not

**A tree reads its journal once, not once per file.** Each upload needs one lookup — which staging
file, if any, a previous run left for this target — and that lookup reads only what has been
appended since the last one. So the cost of the log over a run is the cost of reading it once,
however many files the tree has and however long the log has grown. It does not become a reason to
split a tree up, and it does not make `compact()` something you have to schedule.

Nothing is cached across the *file*, only across reads of the same one: every lookup re-opens the
journal, reads to its current end, and checks it is still looking at the file it read before. A
record another process appended is seen. A journal that was compacted, rotated or truncated
underneath a running job is noticed and read again from the start.

**None of that reading or writing happens on the event loop.** The lookup, the two records and
their `fsync`s all run on a worker thread, for the same reason local file reads in the data path
do: a transfer's job is to keep the link busy, and time spent waiting for a local disk on the loop
thread is time every *other* file in a concurrent tree is stopped too.

`compact()` is still worth calling, and its reasons are unchanged: a log nobody compacts grows
without limit on disk, and [`discard_staged`](#cleaning-up-after-a-crash) compacts as it sweeps.

### Where to put the journal

**In a directory only your job can write to.** There is no default location and there will not be
one — the file has to outlive the process to be worth anything, so it cannot go anywhere this
library would clean up, and choosing a directory on your disk is not a decision a library gets to
make. `/var/lib/<job>/` is the shape; `/tmp` and `/var/tmp` are not, and neither is a spool other
accounts share.

That is a real boundary rather than tidiness, and the line runs between the name you chose and the
names this library derives:

- **The path you name is opened the way `get` opens a download destination** — following a
  symlink, because `/var/lib/myjob/uploads.journal → /mnt/state/uploads.journal` is a deployment
  and not an attack. In a directory somebody else can write to, that means your records can be
  appended into a file of their choosing, without the `0600` a fresh journal would have been
  created with.
- **The temporary file `compact()` writes is not derivable from your path** and is created with
  `O_EXCL` and `O_NOFOLLOW` (D-175). That one is this library's to get right: you never asked for
  it to exist. It used to be `<journal>.compacting`, opened `O_CREAT|O_TRUNC`, which anybody able
  to write to the directory could plant a link at and have an arbitrary file truncated and
  overwritten.

The same two rules apply to `sync_tree`'s `manifest`, which is written the same way.

### Cleaning up after a crash

The half you notice first is not the resume — it is the `.part` files. Every in-process failure
path cleans up after itself, but a killed process reaches none of them:

```python
removed = await sftp.discard_staged(journal)   # returns the paths it actually deleted
```

Safe at the start of a run, and it removes **only what this journal recorded staging**. A sweep
that globbed for `.*.part` would delete another publisher's in-flight upload.

A record whose file has already gone is cleared and not reported as removed, because "removed" is
a claim about what happened. A removal refused for any other reason propagates, and the records
already cleared stay cleared — so a later sweep retries only what is left, which is what an
append-only log buys.

`examples/crash_resume.py` kills a real upload with a real `SIGKILL` and finishes it from a second
process.

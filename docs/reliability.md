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
into three slow ones. That changes when the quirks layer can match a server's message text.

**A status code v3 has no name for also arrives as `FAILURE`**, and that is a decision rather
than a coincidence. A server answering an extension from the v6-era draft may legally reply with
a v6-era code — `SSH_FX_FILE_IS_A_DIRECTORY` is 24, and filexfer v3 stops at 8. Some servers map
those down themselves and keep the detail in the message; asyncssh is one. Others send the number
as-is. This client now produces the same thing either way: `FAILURE`, with the number kept on
`Status.raw_code` and named in the error text, so you never have to know which kind of server you
are talking to. It used to raise instead, and because a protocol error is terminal, a conformant
server answering conformantly dropped the connection.

**And against OpenSSH it cannot change, at any layer.** That is worth stating plainly rather
than reading as a to-do: a transient `FAILURE` mid-transfer kills the transfer, and no amount
of work here fixes it for the reference server. OpenSSH's `STATUS` message is a constant
function of the status code. Five distinct conditions, from a full disk to a name collision,
all send the single word `Failure`, measured, so there is nothing in the reply to classify on.
Retrying an individual request inside a live connection therefore needs a server whose message
text carries information (asyncssh's does; OpenSSH's does not), and until one is in the test
matrix this stays unbuilt rather than half-built. What you get today is `with_reconnect`, which
re-runs the whole operation when the _link_ drops. An eight-hour transfer to an appliance that
hiccups once still starts again from the top, or with `resume=True`, from where it got to.

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

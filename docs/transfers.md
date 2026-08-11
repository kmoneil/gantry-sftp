# Transferring files

`get` and `put`, the guarantees around them, and the four things that go wrong in
production: a half-written file picked up by a consumer, a truncated transfer reported as
success, an interrupted transfer restarted from zero, and metadata silently replaced.

## Atomic publish

`put()` writes the bytes to a hidden sibling staging file, flushes them, and renames that
file over the destination. A consumer polling the directory sees the old file or the new one
and never a half-written one. That is the single most common bug in production SFTP
integrations, and the reason this is the **default** rather than an option.

Every step of it is an optional OpenSSH extension, and most enterprise endpoints advertise
none of them. So `atomic=True` is not a boolean promise: the result says what actually
happened.

```python
result = await sftp.put("report.csv", "/incoming/report.csv")

result.transferred  # 41310
result.mechanism  # posix-rename | rename | remove-rename | in-place
result.durability  # fsynced | unavailable | skipped
result.size_check  # matched | unavailable (rung 3, below)
result.content_check  # hashed | reread | unavailable | skipped (rungs 1 and 2, below)
result.resume_check  # matched | unavailable | skipped (what the adopted prefix proved)
result.atomic  # True: no consumer could observe a partial destination
result.durable  # True: the bytes reached stable storage before the rename
result.staged_at  # b'/incoming/.report.csv.20b59c88.part'
```

**`get` returns the same shape for the other direction**, and originally did not — it returned
a byte count, which is why the verification ladder below reached only one way:

```python
result = await sftp.get("/incoming/report.csv", "report.csv")

result.transferred  # 41310 — what *this call* moved; on a resume, the remainder
result.adopted  # 0 — what was already on disk and was kept
result.size  # 41310 — adopted + transferred: what the local file holds now
result.local_path  # PosixPath('report.csv'), whichever spelling you passed in
result.remote_path  # b'/incoming/report.csv', as it went on the wire
result.size_check  # matched | unavailable | skipped (rung 3, below)
result.content_check  # hashed | reread | unavailable | skipped (rungs 1 and 2, below)
result.resume_check  # matched | unavailable | skipped (what the adopted prefix proved)
result.times  # preserved | unavailable | skipped
result.mode  # 0o600, or None when the mode was left where a download creates it
```

`transferred` is the field the old `int` was, so `bytes = await sftp.get(...)` becomes
`bytes = (await sftp.get(...)).transferred`. There is deliberately **no `int` subclass** to
keep the old spelling working: a type that lies about what it is turns every downstream
`isinstance` and every arithmetic use into an accident that happens to work.

| Mechanism       | When                                             | Atomic                                                                |
| --------------- | ------------------------------------------------ | --------------------------------------------------------------------- |
| `posix-rename`  | The server implements `posix-rename@openssh.com` | Yes, even over an existing file                                       |
| `rename`        | No extension, and the destination did not exist  | Yes. v3 `RENAME` cannot overwrite, so success means it appeared whole |
| `remove-rename` | No extension, and the destination existed        | **No**, there is a window with no file                                |
| `in-place`      | You passed `Publish(atomic=False)`               | **No**, the classic behaviour                                         |

**Every extension is attempted rather than assumed absent**, because endpoints under-advertise
and the answer is worth more than the claim. The cost of asking is one round trip and it is paid
once: `OP_UNSUPPORTED` is a definitive answer and is remembered for the session, so the second
upload does not ask again. `sftp.refuses(name)` is that memory, next to `sftp.supports(name)`,
which is still only what the server _said_.

`require_atomic` is the exception, and the reason is that `posix-rename` cannot be probed. You
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

Three limits stated rather than implied. `fsync@openssh.com` flushes the _file_; SFTP has no
way to flush a directory entry, so the rename that publishes it is never itself durable.
Staging needs the right to create _and_ rename a second name in the destination directory, so a
drop directory that only permits creation needs `Publish(atomic=False)`. And a failed publish removes
the staging file, with one deliberate exception: once the `remove-rename` fallback has issued
the `REMOVE`, the staging file may be the only copy of your data, so it is left where it is and
the error says where that is.

That exception starts at the `REMOVE` rather than after it, which is not the obvious place. A
`REMOVE` the server performed but never acknowledged, and a request timeout is enough, is
indistinguishable from one that never ran, so it is assumed to have run. A `REMOVE` the server
_refused_ is a different thing: nothing was removed, and the staging file is cleaned up
normally. The two cases produce different error notes, one saying the destination was removed
and the other that it may have been. What the _other_ two transfer paths leave behind — an
in-place upload and any download — is in **What a failed transfer leaves behind** below, and
they do not clean up at all.

`examples/atomic_publish.py` runs all of this against a real server with no arguments.

## Resume

Off by default in both directions, and the two are not equally trustworthy:

```python
await sftp.get("/remote/big.iso", "big.iso", resume=True)  # continue from what is on disk
await sftp.put("big.iso", "/remote/big.iso", publish=Publish(atomic=False), resume=True)
```

**Downloading is the stronger claim.** The partial is on your disk, so its length is a fact
rather than a report, and a `READ` at an explicit offset is idempotent. **Uploading is the
weaker one**, and the docs say so in those words: the offset comes from the size the _server_
reports, and a size match proves the byte count agrees and nothing else. The remote partial
may be from a different run, a different source file, or a concurrent writer.

Both refuse rather than guess in two cases. A partial _longer_ than the file it is supposed
to be a prefix of is a `TransferError`, not a truncation. And a server that will not report a
size makes the check impossible, so the resume is refused instead of silently starting over.

**And where a content check is available, the adopted prefix is gated on it.** The failure a
size match cannot refuse is a partial of the _right_ length from the _wrong_ source: a
previous run against a different file, a truncated staging file, a concurrent writer. That
upload completes, publishes, and passes the size check, because the finished length is
correct. The gate hashes the prefix on both sides and refuses before a byte is sent:

```python
result = await sftp.put(src, dst, publish=Publish(atomic=False), resume=True)
result.resume_check  # matched | unavailable | skipped
```

|         | when it runs                                                                                              | what it costs                                                                      |
| ------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| rung 1  | automatically, where the server _performs_ `check-file`, asked rather than assumed from the advertisement | one `OPEN`/`EXTENDED`/`CLOSE`, no payload; a refusal is remembered for the session |
| rung 2  | only under `verify=Verify.REREAD`                                                                         | re-reads the whole adopted prefix                                                  |
| neither | the default case, where `resume_check` is `unavailable`                                                   | nothing, and the claim stays the weak one                                          |

Rung 1 is automatic because it moves no bytes, so gating on it where it exists is free.
Rung 2 is not, because re-reading the prefix is most of what resume set out to avoid. It is worth
asking for on an asymmetric link, where reading back is cheaper than sending again, and that
is a fact about your link rather than ours. A refusal leaves the partial exactly as it was
found: it may be another publisher's, and it is the only evidence of what went wrong.

The download side is gated too, including the case where the local file is _already complete_.
That one adopts the whole file and returns success having moved nothing, which makes it the
one most worth checking rather than the one to skip — and it reports as well as
refuses: `get` returns a `DownloadResult` whose `resume_check` says which of the three
happened. A resume that adopts the _whole_ file has compared the whole file, so that same
answer is its `content_check` rather than being measured twice.

**`resume=True` with `atomic=True` needs an explicit `staging_name`**, and raises `ValueError`
without one. Not because `CREAT|EXCL` refuses to adopt a leftover staging file; it never
meets one. The staging name carries fresh randomness on every call, which is what stops two
publishers colliding, and it also means the previous run's staging file has a name this run
cannot reconstruct. Making that name predictable instead would reintroduce exactly the
collision `EXCL` exists to catch, so the choice is handed to the caller:

```python
await sftp.put(
    src, dst, resume=True, publish=Publish(staging_name=b".big.iso.part")
)  # atomic + resumable
```

With a fixed staging name, `EXCL` is dropped so the file can be adopted, which is also the
collision risk moving to whoever named it.

`examples/resume.py` interrupts a transfer in each direction and finishes it, and catches
both refusals so you can see what they say.

### What a failed transfer leaves behind

Three rules, one per path, and each one is a decision rather than whatever the code happened to
do:

|                             | what is left on failure                                               | why                                                                                                                        |
| --------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `get`                       | the local destination, holding whatever arrived                       | it is _your_ file, not a staging name of ours — and it is what `resume=True` continues from                                |
| `put`, `atomic=False`       | a truncated remote destination                                        | in place, the destination _is_ the file being written; that is what `atomic=False` means                                   |
| `put`, atomic (the default) | nothing: the staging file is removed and the destination is untouched | except once the `remove-rename` fallback has issued its `REMOVE`, where the staging file may be the only copy of your data |

The download's rule has a cost, and it is worth stating plainly: **a `get` that fails before its
first byte leaves a zero-byte file with the right name**, which `if os.path.exists(...)` reads as
a download that happened. Deleting it instead would break resume, and would delete a path that
may be a symlink you made — `no_follow` is off by default — so the file stays and the error
names it:

```python
try:
    await sftp.get("/incoming/report.csv", "report.csv")
except TransferError as failure:
    failure.local_path  # 'report.csv' — the file that is still there
    failure.remote_path  # b'/incoming/report.csv'
    failure.transferred  # 0
    print(failure.__notes__[0])  # says it was left, and to delete it if you are not resuming
```

`local_path` is filled for every failure either direction can raise, not only the transfer
itself: a refused resume, a mode that could not be preserved, a size that did not match.

**And the first read being refused says so**, rather than describing the request. Downloading a
directory is the case that produces it against a real OpenSSH server — `open(2)` on a directory
succeeds, `read(2)` does not — and v3's `FAILURE` carries no detail to distinguish it, so the
message names a directory as something that arrives looking exactly like this without claiming
it is one:

```
server refused the first read, at offset 0: FAILURE Failure -- the handle opened and then not
one byte could be read, so nothing arrived and nothing was truncated. v3's FAILURE says no more
than 'no', and one thing that reaches here looking exactly like this is a directory: a server
that lets one be opened refuses at the read instead
```

Settling it properly would cost a `STAT` on every download to improve one error message, which
is the wrong trade for a path that had a round trip removed from it deliberately.

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

1. **Server-side hash**, `verify=Verify.HASH`, where the server has it. Verifies _content_
   without moving the bytes again.
2. **Full re-read**, `verify=Verify.REREAD`. Reads back what you uploaded and compares it.
   Works anywhere, costs a second transfer, so it is opt-in paranoid mode.
3. **Size check**, always, no flag. Catches truncation, which is the common failure, and
   nothing else.

```python
result = await sftp.put("report.csv", "/incoming/report.csv", verify=Verify.REREAD)
result.content_check  # hashed | reread | unavailable | skipped
result.size_check  # matched | unavailable (rung 3, always)
```

**Rung 3 is what you get by default, everywhere**, because OpenSSH does not implement
`check-file`; it answers `OP_UNSUPPORTED` under all three spellings. Calling a size
comparison a "verified transfer" is the sort of thing this library exists to stop doing.

Which is also why **rung 2 is the one that matters in the field**: it asks for nothing but
`READ`, so it is the only content check most endpoints can offer. It costs a second transfer
_and_ temporary local disk equal to the file, in `$TMPDIR`, since the bytes come back at full
pipelined speed into a scratch file and are compared from there, rather than one round trip
per block. Asking for rung 1 where the server has no `check-file` reports `unavailable`, never
success:

| `verify=`                 | rung                  | works against                                            | cost                                        |
| ------------------------- | --------------------- | -------------------------------------------------------- | ------------------------------------------- |
| `Verify.SIZE` _(default)_ | 3 only                | everything                                               | nothing beyond the `STAT` every `put` makes |
| `Verify.HASH`             | 1, else `unavailable` | `check-file` servers: paramiko, ProFTPD, some appliances | one round trip, no payload                  |
| `Verify.REREAD`           | 2                     | everything                                               | a second transfer + scratch disk            |

A **mismatch** never appears as a value: it raises `TransferError`, and under `atomic` it
raises _before the rename_, so corrupt content never becomes the destination.

**`verify=` is on both directions**, and originally it was on `put` only — the
blocker was the return type rather than the machinery. `get` returned an `int`, so a rung that
could not run had nowhere to report `unavailable` and the only options left were to pass
silently or fail the transfer, a silent degrade being the one outcome this ladder exists to
prevent. `get` returns a `DownloadResult` now (D-99) and both rungs are reachable:

```python
result = await sftp.get("/incoming/big.iso", "big.iso", verify=Verify.HASH)
result.content_check  # hashed | reread | unavailable | skipped
```

**Rung 2 proves something narrower downloading than it does uploading**, which is worth knowing
rather than assuming. Uploading, it proves the server holds what you sent. Downloading, both
copies come from the same place, so what it checks is the _local_ half — this library's
reassembly, its offsets, and the disk they were written to. Rung 1 is the end-to-end check on
this side, when the server can answer it, and `unavailable` is what it answers on nearly every
endpoint.

If you call `check_file()` yourself, leave `block_size` alone. It defaults to
`CHECK_FILE_BLOCK_SIZE` (64 KiB) because that is the largest block paramiko answers correctly:
above it the digests cover the wrong bytes and the server thread ends up in a loop it never
leaves, and `block_size=0`, meaning "one digest over the whole range", is that same loop for any
file over 64 KiB, and a `FAILURE` for any range under 256 bytes. Measured, not inferred — except
the 256, which is the draft's own rule and therefore holds against every server, not just this
one.

Rung 3 is not free of decisions, so here is what it actually does:

|                            | `get()`                                                       | `put()`                                                                                                                       |
| -------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| what it compares           | bytes that arrived vs. the size the `STAT` reported           | the local file's length vs. what the server says it holds                                                                     |
| when                       | after the transfer                                            | **before the rename**, against the staging file, so a short upload never becomes the destination. In place, necessarily after |
| cost                       | nothing; `get` already makes that `STAT`                      | one extra `STAT`, measured rather than assumed, and it ties on every shaped profile (`benchmarks/`)                           |
| on mismatch                | `TransferError` carrying both paths and the offset            | `TransferError`; the staging file is removed and the destination is left alone                                                |
| server won't report a size | `result.size_check` is `unavailable`, download still succeeds | `result.size_check` is `unavailable`                                                                                          |
| turning it off             | `get(..., verify_size=False)`, reported as `skipped`          | no flag; see below                                                                                                            |

```python
result = await sftp.put("report.csv", "/incoming/report.csv")
result.size_check  # matched | unavailable
```

An early `EOF` and a short `DATA` are both _legal_, so nothing below `get()` is entitled to
treat one as an error, which is exactly why a truncating server used to produce a short file
and a successful call. `verify_size=False` exists for reading something that is genuinely
changing size underneath you, and makes the result a snapshot of unknown completeness.

There is no matching flag on `put()`: we control the source there, so a length disagreement is
wrong every time, and `skipped` is a value only a download ever reports. The cost is one `STAT` per
upload, and it was measured rather than assumed — on every shaped link profile it is invisible
beside the round trips a transfer already spends. An earlier draft promised an opt-out flag here;
the measurement withdrew it.

```python
handle = await sftp.open("/incoming/big.iso")
algorithm, digests = await sftp.check_file(handle, algorithms=b"sha256,sha1", block_size=1 << 20)
await sftp.close(handle)
```

You get one digest per block and the algorithm the server chose. It picks the first from your
list that it supports, and answers `FAILURE` if it supports none rather than quietly hashing
with something else. The digest _count_ is nowhere on the wire; it follows from the block size
and the width of the chosen algorithm, so a payload that does not divide evenly is a
`ProtocolError` rather than a set of silently misaligned digests.

`check-file` **is** specified, in `draft-ietf-secsh-filexfer-extensions-00` §3 — a separate
draft from the filexfer series, which is why searching filexfer 05, 09 and 13 for the name finds
nothing. This paragraph used to say the extension had no document at all. It is the same draft
OpenSSH's `PROTOCOL` links from §4.10 and §4.11 for `copy-data` and `home-directory`.

The _request_ here matches that draft field for field, and so does paramiko's. The **reply does
not**: the draft sends `string hash-algo-used` and then the digests, while paramiko echoes
`check-file` in front of the algorithm, and this library implements paramiko's — the only
implementation of this extension it can actually reach. A server sending the draft's reply is
refused with a message naming both shapes, rather than parsed on a guess. Both directions are
committed as golden fixtures with a live test that re-runs the capture.

One more thing the draft settles that this page previously credited to paramiko: the 256-byte
floor under `block_size` is the specification's (`MUST NOT be smaller than 256 bytes`), so every
implementation refuses below it.

The draft also defines a path-taking sibling that would remove the extra `OPEN` an upload's
verification costs. It is permanently not built — the decision and the measurements behind it are
in `gantry_sftp.codec.CheckFile`'s docstring, which is the one place that carries them.

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

It costs no round trip on download, since the times come from the `STAT` `get` already makes, and
one `FSETSTAT` on upload, sent on the open handle so it pipelines with the writes. On the
atomic path it lands on the _staging_ file before the rename, because `rename(2)` does not
alter mtime. On a tree it also stamps the directories the call creates, in a pass after every
file, since writing into a directory updates that directory's own mtime. **The root you named
is never stamped**, only what the call creates under it.

A server that refuses does not fail the upload. `UploadResult.times` says which happened:

|               |                                                 |
| ------------- | ----------------------------------------------- |
| `preserved`   | `FSETSTAT` sent and accepted                    |
| `unavailable` | asked for, and the server refused or ignored it |
| `skipped`     | not asked for, which is the default             |

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
a server did not set `ACMODTIME`, and coercing that to `0` dates the file to 1970, which
reads as "very old" to every `if remote > local`, so a sync built on it either re-transfers
everything or skips everything, and looks correct doing it.

**Do not read the date off `longname`.** It looks like it carries one and it does not. Measured
against OpenSSH 10.0p2, all four:

- Modified within the last **half year**: month, day, time, and **no year**.
- Anything else: month, day, year, and **no time**. Never both.
- A _future_ mtime falls into the year branch too, because the guard is `now >= st_mtime`.
- It is rendered in the **server's** timezone. The same instant reads `Jun 23  2025` under
  `TZ=UTC` and `Jun 24  2025` under `TZ=Asia/Tokyo`, a different calendar **day**, with
  nothing in the reply saying which offset to undo.

So scraping it gives a wrong date rather than a coarse one. `entry.modified` reads the
structured field, which is exact.

### What this cannot promise

- **One-second granularity.** v3 has no sub-second field, so two files written in the same
  second are indistinguishable by mtime and mtime alone is not a change detector. This is not
  a rounding inconvenience — it is the reason a `mtime > watermark` ingest loop **loses files
  permanently and reports success**. See [Incremental ingest](#incremental-ingest-and-the-two-ways-it-loses-data),
  which is the only pattern where this bites and the one everybody writes first.
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
absent, so with the usual `umask 022` a delivered file lands `0644`. A download is the other
way round: this library creates every local file `0600`, so a file is never briefly readable
while it is being written.

```python
await sftp.put("key.pem", "/remote/key.pem", mode=0o600)  # exactly these bits
await sftp.put_tree("build", "/srv/app", mode=Mode.PRESERVE)  # each file's own bits
await sftp.get("/remote/key.pem", "key.pem", mode=0o600)  # and on the way down
```

`mode=` takes an octal mode, `Mode.PRESERVE` (or the string `"preserve"`) to carry the source
file's own bits across, or `None`, the default, to leave them alone.
`UploadResult.mode` reports what was set.

**One argument rather than two**, because `mode=0o600` and a `preserve_mode=True` would be
mutually exclusive by nature: one parameter makes the contradiction unrepresentable instead of
refusing it at runtime.

### The mode is on the file before anything can open it by name

This is the part worth knowing, because a `chmod` after the fact does not give you it. The
bits ride on the `OPEN` that creates the staging file, and the exact mode lands via `FSETSTAT`
on the open handle **before** the rename that publishes it, so there is no instant at which
the destination exists at the wrong permissions. Writing in place needs one extra step, since
`open(2)` applies its mode argument only to a file it _creates_: there the mode is set after
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

A file mode on a directory is usually unusable, since `0o600` on a directory cannot be entered,
so applying one there would leave a complete tree nothing can read. And the final pass is not
tidiness: a directory created `0o500` cannot have files written into it, so applying a source
mode on the way down fails every transfer underneath it. A refused _directory_ mode does not
fail the tree; the files are the payload and are already published.

`examples/permissions.py` runs all of this.

## Walking and recursive download

```python
result = await sftp.get_tree("/incoming", "downloads/")
result.files, result.directories, result.transferred  # 3 2 2520
result.complete  # False -- read result.skipped
```

**A tree returns a summary, not a result per file**, in both directions: `get_tree` keeps each
`DownloadResult.transferred` and drops the rest, exactly as `put_tree` does with its
`UploadResult`s. `skipped` is carried in full because it is bounded by the number of
_problems_; per-file results are bounded by the number of _files_, and a tree of a hundred
thousand of them should not cost a hundred thousand objects for a report almost nobody reads.
If you need the per-file verdicts, call `get` or `put` yourself over a `walk` or a `glob`.

**Every name the server supplies is validated before it becomes a local path**, and the
finished path is re-checked against the destination once symlinks are resolved. A server
answering `../../etc/cron.d/x` gets an `UnsafePathError` and nothing is written. This is the
zip-slip class, and it is a genuine, exploited vulnerability pattern in file-transfer clients
rather than a theoretical one. Two layers, because either alone has a hole:

| Layer                | Catches                                                                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Component validation | `..`, separators, the empty name, NUL, and on Windows `:` streams, `C:` drive-relative names, `CON`/`LPT1` devices, trailing dots                |
| Containment          | a destination subdirectory that is _already_ a local symlink pointing elsewhere, so every component is innocent and the finished path is outside |

The rules follow the platform being written to, because a backslash is an ordinary character
in a POSIX filename and a separator on Windows. Refusing the union everywhere would refuse
files that are legal where they live.

`walk()` yields one entry per directory and **never follows symlinks**; they are reported so
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

A server holding `README.md` beside `readme.md` is doing nothing wrong, since both names are legal
on any case-sensitive filesystem. Download them onto **APFS or NTFS, the defaults on macOS and
Windows**, and they are one file: the second write truncates the first and the walk reports
success, with one file's contents gone and nothing saying so. Containment cannot catch it,
because both paths are legitimately inside the destination. Nothing escaped anywhere.

**The check asks the filesystem, not the name.** Every file a tree download writes is
remembered by `(st_dev, st_ino)`, and a name landing on an inode this run already wrote is
refused. That never asks _why_ two names became one file, so one check covers case folding,
`report.` beside `report` on Windows, and NFC/NFD pairs on HFS+. Reimplementing three
filesystems' folding tables in Python would get all three subtly wrong instead.

Everything transferable still transfers; only the write that would destroy an earlier one is
refused, recorded in `result.skipped`, and reported at the end. A file left by a _previous_
run is not a collision, since overwriting that is the point of re-running a download, and it is
what `resume=` depends on. Which member of a colliding pair survives is `READDIR` order, so it
is the server's choice and not reproducible; the error names both.

**Directories are remembered by what they open, not by what they are.** A file is opened
`O_NOFOLLOW`, so a symlink sitting at that name is refused outright and its own inode is the
honest identity. A directory is created with `mkdir(exist_ok=True)`, which succeeds _through_ a
link to a directory — so a directory's claim is recorded against the resolved path. Without
that, a destination holding `mirror -> Docs` would take two remote directories into one local
one and report success. A link pointing **out** of the destination never gets that far: the
containment check resolves symlinks and refuses it. A link you created yourself, pointing at one
directory you meant, still works — what is reported is the second remote directory arriving on
a local one this run already claimed. Directory collisions are reported rather than prevented:
the contents transfer and the report says the structure is not faithful.

`examples/destination_collision.py` runs it.

### A name the local filesystem will not accept at all

The sibling of the refusal above, and the same shape: a rule belonging to the **destination**
filesystem that no amount of care with the remote name can satisfy.

A remote name is bytes — any bytes but `/` and NUL — and this library carries them byte for byte.
Linux stores them just as happily. **APFS and HFS+ do not**: they validate that a filename is
valid UTF-8 and reject one that is not, with `Illegal byte sequence`. So a file that downloads
correctly on Linux cannot be placed on a Mac's disk under its own name, and no flag changes that.

The two entry points answer differently, on purpose:

```python
# One file: a refusal that names both paths.
try:
    await sftp.get(b"/incoming/caf\xe9.csv", "downloads/caf\xe9.csv")
except TransferError as error:
    print(error.remote_path, error.local_path)

# A tree: the other files still transfer, and the report says which one did not.
result = await sftp.get_tree("/incoming", "downloads/")
result.complete                       # False
[(s.path, s.reason) for s in result.skipped]
```

A single `get` names one file the caller chose, so refusing is the whole answer. A `get_tree` of
two hundred files must not lose a hundred and ninety-nine to one unlucky name, so the entry is
recorded in `result.skipped` and the walk continues — the same call `walk()` makes for a symlink
and `get_tree` makes for a collision.

**The refusal is by errno, not by name inspection**, which matters in both directions. This
library does not try to predict which names a filesystem will take — that would be
reimplementing three filesystems' rules in Python and getting them subtly wrong, the same
argument the collision check above makes. It asks, and the answer is the `open` failing. And it
is narrow: a full disk or a denied directory still aborts the tree, because reporting either of
those as "bad name" would let a real failure look like a quirk of one entry.

**Renaming the file is not on the table.** Transliterating `caf\xe9.csv` to `cafe.csv` would let
two distinct remote names become one local file, which is exactly the silent data loss the
collision check exists to prevent. If you need these files on a Mac, download them somewhere
that will hold them, or fetch them by an explicit local name of your own.

### Servers whose namespace is not rooted at `/`

Every remote path this library _builds_, whether joining a child onto a directory or splitting a
staging file's parent off its target, is `/` arithmetic on bytes. That is what the protocol says to
assume: `draft-ietf-secsh-filexfer-02` §6.2, _"File names are assumed to use the slash ('/')
character as a directory separator"_, and _"otherwise, no syntax is defined for file names by
this specification."_

So on an endpoint whose namespace is not `/`-shaped, such as VMS `DISK$USER:[DIR]FILE.TXT` or an
MVS dataset name, there is no correct join to perform, and guessing per vendor is a different
project. `walk()`, `get_tree()`, `put_tree()`, `rmtree()` and an atomic `put()` raise
`CapabilityError` rather than building a path the server does not mean.

**An absolute path asks nothing and costs nothing.** §6.2 also says a name starting with `/` is
absolute and relative to the root of the filesystem, so a caller who passed one has already
asserted the namespace the arithmetic assumes, so no probe is sent at all. Only a _relative_ path
is in question, because that one is relative to the user's default directory, and whether that
namespace uses `/` is the thing we cannot know without asking. The probe is one `REALPATH` of
`.`, cached for the life of the session and readable as `sftp.server_root`.

What still works on such a server is everything that does no arithmetic: `get()`, `stat()`,
`open()`, `remove()`, `rename()` and `put(..., publish=Publish(atomic=False))` pass your bytes
through untouched.
An atomic `put()` works too if you name the staging path yourself, as in
`put(..., publish=Publish(staging_name=b"staging/report.part"))`, because a staging name with a
separator is used verbatim and no parent is derived from the target.

## Recursive upload, and removal

```python
result = await sftp.put_tree("outgoing/", "/incoming/batch-1")
result.files, result.directories, result.transferred

removed = await sftp.rmtree("/incoming/batch-1")
```

**The upload direction is not the download direction with the arrows reversed.** Every name
here comes from the local filesystem, so the zip-slip machinery does not apply and the
attacker-controlled input is gone. What replaces it is specific: **symlinks are still not
followed**, in this direction because a link in the tree pointing at `/etc/shadow` would
otherwise copy it to the server under an innocent name. Links are reported in `skipped`,
exactly as the download reports them. `walk_local()` is the walk on its own, and it needs no
connection at all.

Missing parents of the destination are created, and that costs an extra round trip only when
a level is genuinely absent: v3 answers a failed `MKDIR` with the catch-all `FAILURE`, so
"already there" and "the parent is missing" can only be told apart by looking.

**`atomic` is per file, not per tree, and the distinction is the honest part.** Each file is
staged and renamed, so no consumer ever sees a partial _file_. Nothing makes the _tree_ appear
in one step. That would mean renaming a staging directory over the destination, and `rename`
onto a non-empty directory fails on every POSIX server, so it could only ever work for a
destination that does not exist yet. A flag that delivered the guarantee sometimes would be
worse than not having it.

`rmtree()` goes bottom up and **descends only into what the walk positively established is a
directory**. Everything else, meaning files, symlinks, fifos, and entries the server declines to
describe, is removed with `REMOVE`, which is `unlink(2)`: it deletes the _name_, so a symlink
goes and what it points at does not, and a directory is refused rather than emptied. That
refusal is the safety net, and it means a wrong guess can only fail in the direction that
raises. There is no `max_depth`, because a depth-limited recursive delete leaves the deepest
directories populated and their parents unremovable.

## Previewing a tree, and the one thing a preview cannot know

`dry_run=True` runs the same walk and makes the same decisions, then hands them back instead of
acting on them. Both directions take it, and both return a `TreePlan` rather than a `TreeResult`:

```python
plan = await sftp.get_tree("/incoming", "downloads/", dry_run=True)

print(plan.files, "files,", plan.bytes_to_transfer, "bytes,", plan.directories, "directories")
for skip in plan.skipped:
    print("would skip", skip.path, "--", skip.reason)
for limit in plan.undetermined:
    print("not determined:", limit)

if plan.complete:
    result = await sftp.get_tree("/incoming", "downloads/")
```

A different type rather than a `TreeResult` with its counters zeroed. `TreeResult.transferred ==
0` means "nothing needed moving"; a preview's zero would mean "nothing was attempted", and one
field cannot carry both. `dry_run` is overloaded on its literal value, so `get_tree(...)` still
types as `TreeResult` and `get_tree(..., dry_run=True)` as `TreePlan` with nothing to narrow.

**The contract is one sentence: a dry run makes no writes.** No `MKDIR`, no `OPEN`, no `SETSTAT`,
no local directory — not even the destination root — and none of the empty files a download
reserves for its collision check. It reads only what the operation would read anyway.

That is why the two directions preview so differently, and the asymmetry is stated rather than
hidden. Walking a remote tree **is** reading, so a download previews nearly completely. An
upload's walk is local, so its plan is complete about every local fact and silent about the
destination: whether those directories exist, and which files are already there, would cost a
round trip per entry — on a large tree over a slow link, a "preview" that stats every target is
a half-hour operation — and it is a mirror's question rather than a preview's.

Whatever a plan did not find out is in `plan.undetermined`, in `PlanLimit`'s words. An empty
list is a claim, so it is never padded and never silently short.

### The collision check degrades, and says so

The one decision a preview cannot reproduce. A real `get_tree` establishes that two remote names
are one local file by creating the file and asking `lstat` for its inode — authoritative on every
filesystem, and a write. A dry run has promised not to, so it folds names instead: Unicode NFC
normalisation and `str.lower()`, reported as `PotentialCollision` and never raised.

```python
for maybe in plan.potential_collisions:
    print(maybe.remote, "and", maybe.first, "fold together at", maybe.local)
```

It is wrong in **both** directions and neither is hidden:

- On a case-sensitive destination — ext4, XFS, most Linux — every pair it lists is a non-event.
  `README.md` and `readme.md` are two files there and the real download transfers both. They stay
  in `plan.files` and `plan.bytes_to_transfer` for exactly that reason.
- A hard link or symlink already sitting in the destination has no name to fold, so it is missed
  entirely. That is precisely the case the inode check exists for.

`PlanLimit.DESTINATION_FILESYSTEM_RULES` is in `plan.undetermined` on every download plan,
collisions or not — the caveat is about what was not asked, so a clean plan needs it just as
much. `plan.complete` is `False` when either the skip list or the collision list is non-empty.

`examples/dry_run.py` runs both directions.

## Resuming a tree

```python
result = await sftp.get_tree("/incoming", "downloads/", resume=True)
```

The nine-gigabyte mirror interrupted at 95%. `resume=` forwards to `get` / `put` per file, so
it inherits their guarantees exactly: an already-complete file costs one `STAT` and moves
nothing, a partial one continues from where it stopped, and a local partial _longer_ than the
remote file is refused rather than truncated. It composes with `concurrency=`.

**Uploading a tree with `resume=True` requires `publish=Publish(atomic=False)`**, and raises
otherwise. Each file stages under a name generated fresh per call, so a previous run's partial
cannot be found again, and a `staging_name` cannot be fixed for a whole tree. Deriving one per
file from the target would make it predictable for every file at once, which is exactly what
the generated name exists to prevent, so the combination is refused rather than quietly
downgraded. Resuming an upload therefore means resuming the destination files themselves, and a
consumer polling the directory can see a partial file while it happens.

## Mirroring a tree

`sync_tree` makes a remote directory match a local one, sending only what is not already there:

```python
result = await sftp.sync_tree("build/", "/deploy", manifest="state.json")

print(result.transferred, "sent,", result.skipped, "unchanged,", result.undecidable, "unproven")
for outcome in result.outcomes:
    print(outcome.remote_path, outcome.decision, "--", outcome.reason)
```

**The feature is the decision not to transfer, not the bytes it saves.** Get that wrong and a
changed file keeps its old contents on the server while the run returns a successful result —
data loss with a green report, which this project ranks above any throughput win. So every file
comes back with the reason it was or was not sent.

### What it compares against, and why it is not the remote timestamp

The obvious rule — local mtime against remote mtime — does not work, and it fails in the
direction that looks like it is working. `preserve_times` is [off by
default](#timestamps), so a file uploaded by `put_tree` carries the _time of the upload_.
Measured against a real `sftp-server`:

```
                 local mtime         remote mtime after put
report.csv       1700000000      →   1786470831        ← the upload, not the file
```

Comparing those finds every file changed, on every run, forever. Turning `preserve_times` on to
fix it would force on a flag that exists to be off — a landing zone whose consumer collects
"modified since X" never picks up a file wearing last year's date — so the mirror compares
against **its own record of what it sent**. That is the `manifest` argument: a JSON file this
library reads at the start and writes at the end.

Losing it costs one full re-send and loses nothing. Absent, unreadable, or written by a future
version all mean the same thing — nothing is known — because a record a comparison cannot trust
is worse than no record.

### The record stores both sides

A record of what _we_ sent cannot see a change made **on the server**. Truncate the remote file
and the local one still matches the record exactly, so a record-only mirror skips and the
destination stays truncated — the same wrong skip, reintroduced by the fix for it.

Closing that costs nothing, because v3 returns attributes _with_ a listing: the walk already
reads every remote size and modification time it needs. So the record holds both sides, and a
file changed on the server is re-sent with `REMOTE_SIZE_CHANGED` or `REMOTE_MTIME_CHANGED` as
the reason. Only a file actually sent costs an extra round trip, to record what the destination
ended up holding.

### Three outcomes, and the third one sends

| `decision`    | what it means                                     | sends |
| ------------- | ------------------------------------------------- | ----- |
| `TRANSFER`    | something differs, or nothing is on record         | yes   |
| `SKIPPED`     | proven identical on both sides against the record  | no    |
| `UNDECIDABLE` | the server volunteered no size or no modification time for it | yes |

`UNDECIDABLE` is counted separately rather than folded into either neighbour. Skipping on it
would lose the file; calling it `TRANSFER` would hide which entries this run could not actually
check. `result.complete` is `True` when there were none.

### It does not delete

A file on the server that is no longer in the local tree is left alone. Deletion is the one
mirror operation whose mistakes are unrecoverable, and nothing on this side can tell an
extraneous file from somebody else's.

## Incremental ingest, and the two ways it loses data

The loop nearly every scheduled SFTP job runs:

> list a drop directory → take what is newer than a stored watermark and matches a pattern →
> transfer it → publish it → advance the watermark

This library ships every piece and **not** a `since()` method, because retention, dedupe and
clock-trust policy are exactly what differs between deployments. What it ships instead is
`examples/incremental_ingest.py` and these two warnings, both of which are one line of caller
code away from silent data loss.

**Why this is pieces and [`sync_tree`](#mirroring-a-tree) is a method**, given that both are
"decide what to move by looking at timestamps". The mirror's comparison is not policy: size
against a recorded modification time, with an explicit third state, is the same rule in every
deployment, and it is the part callers get wrong. An ingest's rule is not — how long to remember
what was taken, whether a re-appearing name is a new file, and whether the server's clock can be
trusted at all are answers that differ per trading partner. So the mirror ships the comparison
and no deletion policy, and the ingest ships the assembly and no comparison. Where a decision is
yours, this library declines to make it quietly.

**1. `mtime > watermark` loses files.** v3 carries whole seconds. A file that lands 0.9 s into
the same second as the file that set your watermark reports the _same_ timestamp, so `>`
excludes it — today, and on every run after. Measured against a real `sftp-server`:

```
                 local mtime      over SFTP
orders-002.csv   ...000.1     →   22:13:20Z     ← set the watermark
orders-003.csv   ...000.9     →   22:13:20Z     ← different file, identical timestamp
```

`>=` on its own is not the fix either: it re-transfers the file that set the watermark on every
run. The fix is `>=` **plus a record of which names were already taken at that exact second** —
a set that resets whenever the watermark moves, so it grows with the busiest single second
rather than with the directory. Holding the watermark one second behind and accepting a
second's worth of re-transfers is also correct and cheaper to store; pick one deliberately.

**2. Advancing the watermark to "now" drops whatever landed mid-run.** "Now" is later than the
newest file the run actually saw, so anything that arrived between the listing and the write is
already behind the watermark when the next run starts — gone, with no error anywhere. Advance
to the **largest modification time actually seen** instead, which cannot skip a file because a
file nobody has listed yet is not in that maximum.

Read `entry.modified` from the [listing](listing-and-matching.md#listing) rather than calling `getmtime` per file: v3
sends attributes with every `READDIR` entry, so the timestamp is already in your hand and
`getmtime` is a round trip you do not need. `getmtime` is for a path you were handed rather
than one you listed.

A third state to decide rather than discover: `entry.modified` is `None` when the server sent
no `ACMODTIME`, which is legal. Treating that as 1970 makes the file look ancient and it is
never ingested — silent loss by a different route.

`tests/test_incremental_ingest.py` fails if either trap is reintroduced.

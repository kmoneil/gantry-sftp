# gantry-sftp

A modern Python SFTP library that **does not implement SSH at all**.

## Why

The Python SFTP ecosystem is one library deep. pysftp, sftpretty, `fs.sshfs` and
`smart_open` all wrap paramiko, so they all inherit its engine: a general-purpose SSHv2
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

**The goal is a better SFTP library: safer, more maintainable, more honest about what it is
doing. Being faster is a consequence of being purpose-built for SFTP scheduling, not the
point.** That distinction decides real trade-offs here. A security or correctness gap outranks
a throughput feature, and a performance win is never a reason to ship something less safe. What
the architecture actually buys is surface area nobody here has to own (no crypto to get wrong,
no `ssh_config` to reimplement badly, no SSHv2 stack to maintain) plus the correctness features
the field genuinely needs and no existing option ships: atomic publish, a zip-slip defence,
errors that carry state, and extension fallbacks that are tested rather than assumed.

## What it needs: read this before you install it

That architecture has a price and it is a single sentence: **this library does not implement
SSH, so it needs an SSH client.** `pip install gantry-sftp` does not put one there. It is the
same sentence as the reason to use it, so it is here rather than at the bottom.

- **Python 3.13+**
- **An `ssh` binary on `PATH`**, meaning `openssh-client`. Not a soft dependency, not vendored,
  and not optional.
- **A POSIX host, for transfers.** `get` / `put` / `get_tree` / `put_tree` need
  offset-addressed local I/O and raise `NotImplementedError` on Windows, before anything is
  sent. Everything that only talks to the far end works there. See
  [Requirements](#requirements) for why, and for the full list.
- **About 16 MiB of memory per concurrent transfer**, which is `depth × request size` and is
  independent of the file's size — a 40 GB download costs what a 40 MB one does. Lower `depth`
  for a smaller container. If you are on Cloud Run, Lambda or Fly, note also that **`/tmp` is
  memory there**, so a staged download counts against your limit twice. See
  [What a transfer costs in memory](#what-a-transfer-costs-in-memory), which gives the
  expression and the way to process a file bigger than the container without staging it.

**Your machine already satisfies this and your container probably does not**, which is the
failure worth pre-empting: it passes locally, then fails on first deploy. Check the image you
actually deploy rather than trusting a table. The library will check itself, and needs no
server to do it:

```console
$ python -m gantry_sftp doctor
gantry-sftp doctor

local
  library                 0.0.0 (filexfer v3)
  ssh executable          ssh -- a bare name, so PATH decides at spawn time
  ssh version             OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026
  transfers               supported
  ssh config              /home/bob/.ssh/config
  environment             none of the steering variables are set
  defaults                depth=64 request_timeout=30.0 idle_timeout=60.0

exit 0 (OK)
```

Put it in the build and the image that cannot work fails its own build instead of a
customer's first transfer. The exit codes are distinct so a `RUN` can tell the cases apart:
**0** usable · **3** no `ssh` binary · **4** platform cannot transfer · **5** host unreachable.

```dockerfile
RUN python -m gantry_sftp doctor
```

Add it in a Dockerfile with whichever your base image uses:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client  # Debian/Ubuntu
RUN apk add --no-cache openssh-client                                            # Alpine
RUN dnf install -y openssh-clients                                               # RHEL/Fedora
```

`python:3.13-slim` and Alpine images generally need one of those; full `python:3.13` and the
Airflow images generally already have `ssh`. Those are guidance, not guarantees. No CI job
here verifies a base image's contents, so the `ssh -V` check above is the authoritative
answer for your image and the sentence you should trust.

**Where this library cannot run at all:** `scratch`, distroless images, and managed runtimes
with no package manager, such as the AWS Lambda Python runtime. There is no `ssh` to install
and no way to install one, so the answer is a different base image. A Lambda *container*
image can install `openssh-client` and works fine. This is stated plainly rather than
hedged, because finding it out after adopting a library is worse than finding it out now.

If `ssh` is missing, you get a `ConnectError` whose `hint` says all of the above. See
[When the connection fails](#when-the-connection-fails).

## The failures this prevents

The reason to switch is not a ratio. It is this list, and every row names the mechanism *and* the
test that proves it, because a prevention claim without a test is a rumour.

| The failure | What stops it | What proves it |
| --- | --- | --- |
| A consumer picks up a file that is real, plausible and a quarter written | `put()` stages under a temporary name, flushes, then renames, and the result says which mechanism it actually got | `tests/test_publish.py`, `examples/atomic_publish.py` |
| A truncated transfer reported as success | a size check on every transfer, and on the way up it runs *before* the rename, so a short upload never becomes the destination | `tests/test_verification.py` |
| An upload that arrives world-readable | `mode=` is set in the `OPEN` that creates the file, before anything can open it by its published name. Omitting it means `0666 & ~umask`, and a `chmod` afterwards leaves a window | `tests/test_modes.py` |
| Timestamps replaced by the time of the transfer | `preserve_times=` in both directions, stamping a descriptor rather than a path | `tests/test_timestamps.py` |
| A hostile filename escaping the destination directory | every server-supplied name is checked before it reaches the filesystem: absolute paths, `..`, and a parent directory that is a symlink pointing out of the tree | `tests/test_localpath.py`, `tests/test_recursive.py` |
| Two legal remote names silently becoming one local file | the collision check asks the filesystem for identity rather than folding the name, so Unicode normalisation and Windows trailing dots come free | `tests/test_localpath.py` |
| A resume that adopts the wrong bytes | a partial that cannot be a prefix is refused, and `resume_check` reports what was actually proven rather than that something was | `tests/test_resume.py`, `tests/test_content_verification.py` |
| A `UnicodeDecodeError` on somebody else's filename | bytes end to end: `DirEntry.filename` is bytes, every `Session` method takes `bytes` or `str`, `realpath` returns bytes, and the decode question is decided once on the download side | `tests/test_listing.py` |
| A `Path` silently becoming `\incoming\data.csv` on the server | a remote path is `bytes` or `str` and a `Path` is refused by name. `pathlib` drops a trailing slash and renders separators as backslashes on Windows, and a backslash is a legal character in a POSIX filename, so the server would create it rather than refuse it | `tests/test_path_types.py` |
| A transfer that hangs with nothing to escape it | a deadline on every wait, including the send and including the wait for the send lock | `tests/test_send_deadline.py`, `tests/test_cancellation.py` |

**Two of those are the incumbent's open bugs rather than hypotheticals** (counts read from the
trackers on 2026-07-29). `paramiko#546`, *Crashes on filenames that are not UTF-8*, has been open
since 2015 with 47 comments; `#707` is the same crash on a single filename byte, and seven issues
carry that shape in their title. Hanging with no timeout to
escape is `paramiko#520` (54 comments, open since 2015), `#926` (*Downloading Large Files Hangs /
Stalls*, 27 comments), `#515` and `#331`.

**And this is where the performance claim belongs, because nobody complains in ratios.** What
people report against an SFTP client is a *pathology*: it hangs, it stalls, it cliffs at a byte
count (`paramiko#2438`, where writing more than 32675 bytes costs 99% of the throughput), or one
of its own APIs runs 25× slower than another (`paramiko#2453`). Those are failure modes, not
benchmark rows. So the claim worth having is that **throughput rises with file size and then
plateaus, and never falls**, and it is asserted rather than reported: ten sizes bracketing every
boundary the design has, both directions, and a fall fails the run. Its limits, stated because they
matter: it covers `get` and `put` on two of the five link profiles, and the read path a file object
would use is not swept, because there is no file object yet.

## The bug class this library cannot have

**The loudest thing in paramiko's tracker is not a bug, it is a treadmill.** Four issues, 252
reactions between them, and they are the same issue four times over eight years: Blowfish
deprecated in `cryptography` 37 (`#2038`, 99 reactions), `CryptographyDeprecationWarning`s on
`cryptography` 2.5 (`#1369`, 86), TripleDES (`#2419`, 46), and one more of the same (`#1386`, 21).
Beside them, a `bcrypt` dependency that produced `GLIBC_2.28 not found` at runtime (`#2108`) and a
`DSSKey` removal that broke `pysftp` downstream for people who never used those keys (`#2537`).
None of it is anybody's mistake. An SSH implementation in Python must track a crypto library's
deprecation schedule forever, and every turn of that schedule reaches every user as a warning or a
break.

**There is no cryptography in this package and no cryptographic dependency**, so it cannot produce
any of that: `pip install gantry-sftp` pulls `anyio` and nothing else. There is one optional
extra, `[fsspec]`, and it does not change that sentence — fsspec has no required dependencies
of its own, and it is fsspec's *own* `sftp` extra that installs paramiko. Algorithm currency is the
same fact from the other side: this library cannot lag on a key type, cannot mis-parse
`known_hosts` and cannot diverge from the `ssh_config` you already tested with `ssh`, because it
implements none of them. The episode where OpenSSH 8.8 disabled SHA-1 `ssh-rsa` signatures and a
Python client had to grow `rsa-sha2-*` (`paramiko#1643`, 61 comments, then `#2017`, where the fix
broke compatibility in the other direction) is a shape there is no way to reproduce from here.

**`Error reading SSH protocol banner` appears in 55 issues in that repository.** What you get here
instead is OpenSSH's own stderr, verbatim, on a typed exception, with a `hint` when there is
something to do about it. See [When the connection fails](#when-the-connection-fails).

**asyncssh deserves a different sentence, so it gets one.** The argument above is not an argument
against it: its loudest issue has 7 reactions to paramiko's 99, most of its tracker is questions
that were answered, and against asyncssh this library is *behind* on surface (no `statvfs`, no
`hardlink`, no `copy-data`) and on Windows, where its transfers work and ours refuse. Three things
stand against it and they are the honest three: no cryptography in Python, the table above, and
trio.

## What is free because OpenSSH does it

Every item here is an open feature request in the incumbent's tracker with no path forward inside a
Python SSH implementation, and none of it is implemented here, which is why none of it can rot
here:

- **`ssh_config`, in full**: `Match`, `Include`, `ProxyJump`, `ProxyCommand`, `IdentityFile`.
  (`fsspec#516` is the same wish one layer up.)
- **`ControlMaster` / `ControlPath` multiplexing** (`paramiko#852`, open since 2016). If your
  `ssh_config` sets it, you have it, and for connection-heavy work it is the fix rather than an
  optimisation, because connecting is this library's weak spot.
- **Host keys signed by a CA** (`paramiko#771`), and the agent with more than one key in it
  (`paramiko#1390`).
- **Reaching a host through a proxy or a bastion**: `ProxyJump`, and `ProxyCommand` for SOCKS
  (`paramiko#955`, 24 reactions). Port *forwardings* are a different feature and this library
  switches them off on purpose: an SFTP client has no business opening one.
- **FIDO `sk-*` keys, GSSAPI, post-quantum key exchange**, and every CVE fix, which arrives with
  your OS package rather than with a release from us.

See [Authenticating](#authenticating), which is a short section for exactly this reason.

## asyncio, trio, or no event loop at all

The core is async and it is written against `anyio`, so it runs on **asyncio and on trio**, and
every async test in the suite runs on both backends, which is what makes that a property rather
than a dependency choice. asyncssh's implementation depends on asyncio primitives directly, so
trio is not available there; it was asked for in 2019 (`asyncssh#208`) and still is not. paramiko
is threads.

If you have no event loop at all, `gantry_sftp.sync` is a blocking facade over the same code
rather than a second implementation of it. See [No event loop](#no-event-loop).

## Status

**Pre-alpha, and honest about it.** Nothing is published and the API will change. What
exists today:

- a complete filexfer v3 codec: all 27 packet types plus ATTRS, encoding and decoding,
  checked against `draft-ietf-secsh-filexfer-02`, OpenSSH's `sftp.h`, and frames captured
  from a real server. Every one of the 27 carries a byte-level fixture asserted in both
  directions, which is a stronger claim than a round trip, because a round trip agrees with
  any consistently wrong layout
- wire primitives and an incremental frame splitter, so no frame payload is ever copied
- the client state machine: handshake, deterministic request-id allocation, and
  request/response correlation that survives out-of-order replies
- transports: `ssh -s sftp` as a subprocess, and `sftp-server` on a bare pipe
- **one call to connect**: `connect(host, ...)` opens the `ssh` connection and a session over
  it, and `from gantry_sftp import ...` reaches every entry point and value type, so no
  program needs an import from `gantry_sftp.codec`, the layer the design calls internal
- a session with `stat`, `lstat`, `fstat`, `realpath`, `chdir` / `getcwd`, `open`/`close`, `mkdir`, `rmdir`,
  `remove`, `rename`, `posix_rename`, `fsync`, `chmod` / `chown` / `utime` / `truncate`,
  `readlink` / `symlink`, `supports()`, `listdir()` / streaming `scandir()`, and
  pipelined `get()` / `put()`, with typed errors, timeouts on every wait, and a progress
  callback
- **path predicates that have three states**: `exists` / `isdir` / `isfile` / `islink` /
  `getsize` / `getmtime` / `makedirs`, where `False` means the server said `NO_SUCH_FILE` and
  every other refusal is raised. A `PERMISSION_DENIED` reported as "not there" is how a
  publisher overwrites a file it was never allowed to see
- **byte ranges and a file object**: `open_file()` for a cursor, giving `read` / `readinto` /
  `write` / `seek` / `truncate`, and `read_at` / `readinto_at` / `write_at` for explicit offsets,
  which are safe to fan out over one handle. Every read is pipelined through the same scheduler
  `get` uses rather than one request per call
- **permissions that survive the transfer**: `mode=` and `Mode.PRESERVE` both directions, set
  on the file before anything can open it by its published name. Without it every upload
  arrives `0666 & ~umask`, which is the server's default and used to be unchangeable
- **recursive transfer both ways**: `walk()` and `get_tree()`, with the zip-slip defence that
  makes a hostile server's filenames safe to write, plus `put_tree()` and `rmtree()`, so trees
  go up as well as down, and come back off again
- **destination collisions are refused, not overwritten**: two legal remote names that a
  case-folding local filesystem makes one file, such as `README.md` and `readme.md` downloaded
  onto macOS or Windows, used to lose one silently. The check is filesystem identity rather than
  name folding, so it covers Unicode normalisation and Windows trailing dots for free
- **atomic publish**: `put()` stages, flushes and renames, and tells you which mechanism it
  actually used
- **resume**, both directions, opt-in and labelled with what it actually proves, on single
  files and, as of 0.10, on whole trees
- **trees transfer concurrently on request**: `get_tree(concurrency=8)` feeds a bounded worker
  pool from the walk, so the peak task count is the worker count rather than the tree's size
- **reconnect and retry**: `with_reconnect()` runs an operation against a fresh session when
  the link drops, with a classification that refuses to retry a failed authentication
- **server identification**: the session names which SFTP implementation it is talking to,
  from what the handshake already carried, and measured against three real servers
- **server-side hashing** where a server has it: `check_file()` verifies content without
  moving the bytes again, with its layout read off the wire because no draft defines it
- **one session, many transfers at once**: a single reader task routes each reply to whichever
  operation asked for it, so `get`/`put` overlap over one channel instead of queueing behind
  a lock
- **password authentication** for the endpoint class that needs it, with the secret travelling
  through the child's environment and never through argv, where `ps` would show it to every
  user on the machine
- **a blocking surface**: `gantry_sftp.sync` gives every one of the above to a program with no
  event loop, as a facade over the async code rather than a second implementation of it, with
  the parity between the two derived from the async signatures by a test, not maintained by
  hand
- **name matching**: `glob()` in `sftp(1)`'s own `glob(3)` dialect rather than `fnmatch`'s, so
  the dotfile rule that keeps a drop directory's half-written staging files out of a match is
  the one the reference client has. A match carries a path this library built out of validated
  parts — and for a filter no pattern can express, the same two calls are public
- **an fsspec filesystem**: `gantry_sftp.fsspec` makes `pd.read_parquet("gantry-sftp://…")`
  work, over the blocking surface rather than a second concurrency runtime. It registers
  **nothing** on import, because `sftp://` is already claimed inside fsspec by an
  implementation that sets `AutoAddPolicy` — taking a protocol from another library is a
  decision the caller makes in writing, not a side effect of installing this one
- a test lane that drives the genuine OpenSSH `sftp-server` over a pipe, with no ssh, no keys,
  no network and no containers, and a `live-tests/` lane that runs a real `sshd`, including a
  `tc netem`-shaped link where the pipelining claims are actually measured
- a `benchmarks/` lane that runs this library, paramiko and asyncssh against the same server
  over that shaped link, reporting wall clock **and** CPU, and in the two scenarios there
  that assert rather than report, throughput swept against file size so that a cliff at a byte
  count fails a run, and the file object measured against our own `get` so that a read which
  stopped pipelining does too. It is a lane rather than a published result: the figures it
  produces are written to a report that is not committed, because a number in a repository ages
  and a lane re-runs
- runnable `examples/`, each of which works with no arguments and is executed by the suite

The thesis is proven end to end: SFTP runs over a real SSH connection, with key exchange,
host-key verification and authentication (by key or by password) all done by OpenSSH, and no
cryptography in this package. It is also measured against both alternatives, in both directions,
on five link profiles, including the scenarios where we lose, which are connecting and CPU. The
figures are not in this repository at all, for the reason in [Why](#why): a document that ranks
correctness above throughput and then leads with ratios is arguing against itself. The lane is
[`benchmarks/`](benchmarks/README.md) and it writes its report when you run it. It moves files:

```python
import anyio
from gantry_sftp import connect


async def main():
    async with connect("example.com", user="bob") as sftp:
        await sftp.get("/remote/data.parquet", "data.parquet")
        result = await sftp.put("report.csv", "/remote/report.csv")
        print(result.mechanism, result.atomic)  # posix-rename True


anyio.run(main)
```

One import, one call. `connect()` opens the `ssh` connection and the session together and
closes both when the block exits.

**The two-call spelling is not deprecated and is what to reach for when the connection's
lifetime differs from the session's**, such as running two sessions over one connection, or
handing a transport to something else:

```python
from gantry_sftp import open_session, open_ssh_transport

async with (
    open_ssh_transport("example.com", user="bob") as transport,
    open_session(transport) as sftp,
):
    ...
```

Session tunables go through `SessionOptions`, because `connect()` is already at this
project's argument ceiling with the `ssh` arguments alone:

```python
from gantry_sftp import SessionOptions, connect

async with connect("host", user="bob", session=SessionOptions(depth=16)) as sftp:
    ...
```

`connect()` is **not** a reconnect recipe. See [Reconnect and retry](#reconnect-and-retry), where
`with_reconnect` takes a callable producing a *transport*, because a retry rebuilds the session
over a new connection.

**There is a blocking surface, and it is a facade rather than a generated twin**; see
[No event loop](#no-event-loop). There is an **fsspec filesystem**; see
[pandas, dask and anything else that speaks fsspec](#pandas-dask-and-anything-else-that-speaks-fsspec).
Not yet: `SFTPPath`. `put_many()` from DESIGN.md's §8 sketch does not exist. Concurrency is
spelled with your own task group, or with `get_tree(concurrency=)`, rather than a
`concurrency=` argument on a `*_many` call.

**What is still missing.** `SFTPPath` does not exist — `Path.open` / `read_bytes` /
`write_bytes` are most of what a path is for, and the byte-range surface they needed landed in
0.11 ([Byte ranges, and a file object](#byte-ranges-and-a-file-object)), so what remains is the
path algebra rather than a missing primitive. The other things it was waiting on have all
landed: the predicates ([Is it there?](#is-it-there)), relative paths with `chdir` / `getcwd`
([A working directory](#a-working-directory-which-this-protocol-does-not-have)), and the
blocking surface.

Against **asyncssh** specifically, this library is still behind on surface, with no `statvfs`,
no `hardlink` and no `copy-data`, and its transfers work on Windows where ours refuse.

## No event loop

```python
from gantry_sftp.sync import connect

with connect("example.com", user="bob") as sftp:
    sftp.get("/remote/data.parquet", "data.parquet")
    result = sftp.put("report.csv", "/remote/report.csv")
    print(result.mechanism, result.atomic)  # posix-rename True
```

Same library, same `Session` methods, same arguments, same errors. `gantry_sftp.sync` is a
facade over the async code, not a second implementation of it. The event loop runs on a
background thread for the length of the block
([`anyio.from_thread.start_blocking_portal`](https://anyio.readthedocs.io/en/stable/threads.html)),
and every call is the identically named coroutine sent across the boundary.

This is why that matters: **the alternative was generating the blocking API from the async one
with `unasync`, and that mechanism cannot work here.** Token substitution has no sync
`create_task_group`, so honouring it meant hand-writing a second concurrency runtime: threads
for the reader and the reaper, `threading` locks, a selector transport, and a re-derivation of
cancellation. `httpx` gets away with it because `httpcore` ships hand-written parallel backends
under matching names; that seam does not exist here. So there is one scheduler, one reader, one
set of retry rules, and a **parity test that derives the blocking signatures from the async
ones**, so a method added to `Session` and not to `SyncSession` fails the suite by name.

Everything keeps its shape, including the parts that could not survive the boundary unchanged:

| async | blocking |
| --- | --- |
| `async with connect(...) as sftp` | `with connect(...) as sftp` |
| `await sftp.get(...)` | `sftp.get(...)`, returning the same `int` |
| `async for entry in sftp.walk(...)` | `for entry in sftp.walk(...)`, an ordinary iterator |
| `async with sftp.scandir(p) as entries` | `with sftp.scandir(p) as entries`, still a context manager, because it still holds a directory handle |
| `async with sftp.open_file(p) as f` | `with sftp.open_file(p) as f`, the same, for the same reason: it holds a file handle |
| `except NoSuchFileError` | `except NoSuchFileError`, arriving flat rather than in an `ExceptionGroup` |

Breaking out of a `walk`, a `glob`, a `scandir` or an `open_file` closes the handle **on the
server**, not
merely in Python: the suite asserts it by calling `close()` on the handle afterwards and
requiring `NO_SUCH_FILE`, because "no complaint appeared" is the absence of evidence rather
than evidence.

The two-call spelling works the same way, and the transport carries the portal so both halves
share one loop rather than starting two:

```python
from gantry_sftp.sync import open_session, open_ssh_transport

with open_ssh_transport("example.com", user="bob") as transport:
    with open_session(transport) as sftp:
        ...
```

**Several connections, or a backend other than asyncio: own the portal.** The module-level
entry points start one and stop it with the block, which is right for a script and wasteful for
a job with ten connections, which pays for a thread and a loop apiece for loops that are idle
between calls.

```python
from anyio.from_thread import start_blocking_portal
from gantry_sftp.sync import BoundPortal

with start_blocking_portal(backend="trio") as portal:   # or asyncio, the default
    gantry = BoundPortal(portal)
    with gantry.connect("a.example.com") as one, gantry.connect("b.example.com") as two:
        one.get("/data.csv", "a.csv")
        two.get("/data.csv", "b.csv")
```

**Many transfers over one connection is spelled with threads here.** A blocking caller has no
task group, and a `SyncSession` is safe to share across one. Each call posts to the same loop,
so the fan-out lands on the one reader that already routes replies by request id:

```python
from concurrent.futures import ThreadPoolExecutor

with connect("example.com", user="bob") as sftp, ThreadPoolExecutor(8) as pool:
    pool.map(lambda name: sftp.get(f"/incoming/{name}", local / name), names)
```

Four things to know about the thread boundary:

- **A `progress` callback runs on the portal's thread**, which is the one thread that cannot
  wait on the portal. Calling back into the session from inside a callback is refused by anyio
  with `RuntimeError: This method cannot be called from the event loop thread`, loudly rather
  than as a deadlock. Count bytes and return.
- **The session is shareable across threads; one `walk` or `glob` is not.** They come back as
  ordinary Python generators, and a generator driven from two threads at once raises
  `ValueError: generator already executing`. Iterate one per thread, or list it first.
- **Using a session after its block has ended** raises `StateError` naming the block, rather
  than anyio's complaint about a portal you never asked for.
- **`with_reconnect` has no blocking form yet.** It takes a callable that receives a session,
  so a blocking version has to run *your* function on the portal's thread and therefore needs a
  third thread to re-enter from. That is a mechanism decision rather than a wrapper, and not one
  to half-build. The async form is unaffected.

Runnable: `examples/blocking.py`.

## pandas, dask and anything else that speaks fsspec

```python
from gantry_sftp.fsspec import register

register()  # once, at startup -- never on import, and the reason is below

import pandas as pd
frame = pd.read_parquet("gantry-sftp://bob@example.com/incoming/events.parquet")
```

Install it with the extra: `pip install gantry-sftp[fsspec]`. Nothing else in the library
needs fsspec, and importing `gantry_sftp` does not import it.

**Registration is explicit, and that is a security decision.** `sftp://` and `ssh://` are
*already* registered inside fsspec itself, to an implementation that wraps paramiko —
and fsspec's `register_implementation(..., clobber=False)` **succeeds silently** when nothing
has resolved `sftp://` yet, raising only once something has. Which of the two you get is
decided by import order. So this library claims nothing on import; you say which name you
want:

```python
register()                       # `gantry-sftp://`, a name nothing else claims
register("sftp", override=True)  # take `sftp://`, deliberately and in writing
```

`register("sftp")` without `override=True` raises and names the incumbent. A library that
changed what `pd.read_parquet("sftp://…")` does merely because it was installed would be
doing the thing this README's [bug class](#the-bug-class-this-library-cannot-have) section is
about.

**What taking `sftp://` buys you.** The incumbent calls
`set_missing_host_key_policy(paramiko.AutoAddPolicy())` unconditionally, so every `sftp://`
URL in the pandas and dask ecosystem today accepts whatever host key it is offered. Ours
spawns `ssh`, which reads your real `known_hosts` and refuses. Three more differences, each
a defect on the other side rather than a preference:

- **`ls` and `info` agree about a symlink.** The incumbent's `ls` reads the listing's
  attributes, so a symlink is `"link"`; its `info` calls `stat`, which follows, so the same
  path is `"file"` — while fsspec's own docstring says `info` returns "exactly the same
  information as `ls`". Here both follow, so `isfile` on a symlinked parquet is `True` and
  something will actually open it. `islink` is a separate key, as it is in fsspec's own
  `LocalFileSystem`.
- **A file object that does not cost a round trip per read.** `_fetch_range` goes through the
  same scheduler a whole-file `get` uses, over one handle held for the object's lifetime.
- **A server that omits attributes does not crash the listing.** `S_ISDIR(None)` is a
  `TypeError` on the other side; here an entry the server did not describe is `"other"`, and
  a broken symlink is reported rather than dropped or raised.

**Errors change shape at this boundary, deliberately.** fsspec's contract is `FileNotFoundError`
— `AbstractFileSystem.info` is documented to raise it, `exists` is written around it, and pandas
tests for it by name — so the adapter translates: `NoSuchFileError` becomes `FileNotFoundError`
and `PermissionDeniedError` becomes `PermissionError`, with the original on `__cause__` so the
status code and the server's message survive. Everywhere else in this library an
[`SFTPError` is not an `OSError`](#when-the-connection-fails), and it stays that way; the
translation happens here and nowhere else. The predicates you get through `fs` are fsspec's too,
which means they swallow every exception including a refusal — reach for
[`Session.exists`](#is-it-there) when "not there" and "not allowed to look" have to differ.

### The URL form

```
gantry-sftp://[user[:password]@]host[:port]/absolute/path[?parameters]
```

The path is always absolute — fsspec has no way to express a relative one — so `cwd=` is how
you name a relative root. fsspec parses the authority and hands the **query string back
unparsed**, so these parameters are this library's own, and they are the arguments
[`connect()`](#status) already takes:

| | |
| --- | --- |
| `user`, `identity_file`, `config_file`, `ssh_executable` | as on `connect()` |
| `port` | as on `connect()`, and also expressible as `host:port` |
| `cwd` | a remote working directory relative paths resolve against |
| `depth`, `request_timeout`, `idle_timeout` | the [tunables](#tunables-and-what-they-default-to). `request_timeout=none` means "wait forever" |

An unknown parameter **raises** rather than being ignored: a misspelled `identiy_file` that
silently does nothing is a connection that fails for a reason the message will not name.

### Two things about fsspec's own design to know before you deploy this

Neither is a defect of this adapter, and both will surprise you if nobody says them.

- **One connection per thread, not per host.** fsspec caches filesystem instances by a token
  that includes the thread id, and the cache holds a strong reference on purpose, so
  `__del__` never fires and there is no `close()` in fsspec's contract. A thread pool calling
  `pd.read_parquet` therefore opens one `ssh` child per thread. The connection is opened
  lazily — resolving a URL costs nothing — and `close()` plus a context manager are provided
  for when you want to decide; `skip_instance_cache=True` is the spelling for "a connection I
  control".
- **A password in a URL is a password in `storage_options`** for every other fsspec
  filesystem, which is what `__reduce__` pickles — so a dask scheduler ships it to every
  worker — and what `to_json()` serialises, with `include_password` defaulting to `True`.
  **Not here**: the password reaches the constructor and is never stored on the instance, so
  none of those carry it. The cost is stated rather than hidden — the password is not part of
  the cache token either, so two filesystems differing only in password come back as one
  instance holding the first. `skip_instance_cache=True` when that is not what you want.

Runnable: `examples/fsspec_urls.py`.

## Matching names: `glob`

```python
from contextlib import aclosing

from gantry_sftp import local_child

async with aclosing(sftp.glob("/incoming/*.csv")) as matches:
    async for match in matches:
        await sftp.get(match.path, local_child(local_dir, match.name))
```

`match.path` is a path **this library** built, by joining a name that was checked for
separators and dot entries onto the prefix you typed. That is the reason to use `glob` rather
than a `listdir` and an `fnmatch`: written by hand, that join is at your call site, and a
server answering with `../../etc/x` is a path traversal you wrote yourself.

### When the filter is not a pattern

A regular expression, a modification-time watermark, a size threshold, a lookup in a
manifest — none of those can come through `glob`, and none of them means writing the join
unsafely. The two functions `glob` itself calls are public, and the whole answer is two lines:

```python
from gantry_sftp import check_listed_name, join_remote, local_child

drop = b"/incoming"
for entry in await sftp.listdir(drop):
    if entry.is_file and pattern.match(entry.name):
        remote = join_remote(drop, check_listed_name(entry.filename, directory=drop))
        await sftp.get(remote, local_child(local_dir, entry.filename))
```

- **`check_listed_name(name, directory=...)`** returns the name unchanged, so it reads as a
  pass-through, and raises `UnsafePathError` for a name that is not one path component —
  empty, `.` or `..`, or carrying a `/` or a NUL. On an honest server it never fires: a POSIX
  filename cannot contain a `/`.
- **`join_remote(parent, name)`** joins with `/` always, never `os.path.join`, which on a
  Windows *client* would produce a path no server understands. Both arguments are bytes,
  because `entry.filename` is bytes — `entry.name` is the same name decoded for display, and
  decoding is not reversible for every server that will ever answer you.
- **`local_child(directory, name)`** is the destination side, and it is the one that is easy
  to forget: `local_dir / os.fsdecode(entry.filename)` is the zip-slip. It validates against
  the **local** rules and then decodes with `os.fsdecode`, so a filename that is not valid
  UTF-8 lands on disk as the bytes it arrived as. The local rules are a strict superset of the
  remote ones — a name that cleared `check_listed_name` can still be `..\evil` or `C:evil` or
  `CON`, none of which contains a `/` and all of which mean something on Windows — so passing
  the remote check is not a reason to skip this one.

The same three are what `glob`, `walk`, `get_tree` and `put_tree` use internally, so a
hand-written loop and a library one refuse the same names for the same reasons. `entry` here
is a `DirEntry`, which deliberately does **not** carry a `.path`: it is also what the upload
walk reports, where a remote directory does not exist, and a property that worked in one
direction and raised in the other would be worse than the two lines above.

**The dialect is `glob(3)`'s, because that is what `sftp(1)` uses.** It globs client-side
through POSIX `glob(3)`, so this is the pattern language you already have. Three consequences
differ from Python's `fnmatch`, which is what a reader would otherwise assume is underneath:

- **`*` and `?` never cross `/`.** `fnmatch` matches `a/b.csv` against `*.csv`; this does not.
- **A leading period must be matched explicitly.** `*.csv` does not match `.hidden.csv`; `.*.csv`
  does. This is what keeps a glob over a drop directory from picking up half-written staging
  files, including the dot-prefixed ones this library's own atomic publish creates.
- **A backslash escapes**, as it does in `sftp(1)`, which passes no `GLOB_NOESCAPE`.

`[abc]`, `[a-z]` and `[!a-z]` (also spelled `[^a-z]`) work, and so do POSIX **character
classes** — `*.[[:digit:]]`, `[[:upper:]]*`, `[![:space:]]`, and the other names below. Brace
expansion does not: `sftp(1)` applies it to `ls` and not to `get`, so there is no consistent
behaviour to copy.

| | |
| --- | --- |
| `**` | zero or more directory levels. An **addition** to what `sftp(1)` understands, so a pattern using it is not portable back to that client. Bounded by `max_depth=` |
| trailing `/` | match directories only, as in a shell |
| `[[:name:]]` | a POSIX character class inside a bracket expression: `alnum`, `alpha`, `blank`, `cntrl`, `digit`, `graph`, `lower`, `print`, `punct`, `space`, `upper`, `xdigit`. **ASCII-only** — no byte above 127 is in any of them |
| `case_sensitive=False` | fold ASCII case in the names being matched. Not the directory you typed, since folding that would mean listing `/` to find out whether `/Incoming` is `/incoming`. Non-ASCII bytes are never folded: a remote name is bytes of unstated encoding |

**Character classes stop at ASCII, and a class name that does not exist is an error.** Which
bytes are letters is a property of a locale — glibc under ISO-8859-1 says `0xff` is one and
under C says it is not — and a remote name is bytes whose encoding the protocol never states,
so this library answers the question the same way on every machine instead of guessing. The
other two POSIX sub-expressions, equivalence classes `[[=a=]]` and collating symbols `[[.a.]]`,
are *defined* by a locale's collation table and are refused for the same reason. So is a
misspelled class name: `glob("*.[[:digits:]]")` raises `ValueError` — before anything is
listed — where `glob(3)` would have quietly matched nothing and let a nightly job transfer zero
files and report success.

Matching runs on **bytes**, because a remote name need not be valid UTF-8 and a lossy decode
makes two distinct names match one pattern. Symlinks match but are never descended into, the
same as in `walk`. Nothing is accumulated, since matches are yielded as they are found, so it is an
async generator and you close it, exactly as with `walk`. A path in the pattern that does not
exist matches nothing; one that exists and **cannot be read** raises, which is a deliberate
divergence from `glob(3)`: answering "no matches" when the truth is "I was not allowed to look"
is a partial success wearing a complete one's clothes. That holds for a directory the pattern
descends through *and* for a pattern with no wildcard in it at all — only `NO_SUCH_FILE` is an
empty result, and a refusal to answer never is.

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
knob: how many transfers to have in flight is a decision about the far end, about its handle
limits, its patience and its disks, and a task group already expresses it.

Three things worth knowing before you fan out:

- **It reaches the window; it does not lift it.** `ssh -s sftp` runs the subsystem on one SSH
  channel, so one session is one 2 MiB window (measured, below) shared by everything on it.
  What concurrency buys is getting *to* that ceiling: a 64 KiB file has 64 KiB to put in
  flight and a hundred of them have more, and the round trips of a sequential
  `OPEN`/`READ`/`CLOSE` per file are time the link spends idle. Going past 2 MiB needs a
  second transport, meaning another `ssh` child and another channel, which is not built.
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
  several counters interleaved into one stream, and a bar built on it jumps backwards. Use
  `concurrency=1` to keep per-file progress, or read the counts off the returned `TreeResult`.
- **It does not lift the 2 MiB ceiling.** One session is one channel is one window, so
  concurrency *reaches* the ceiling on a tree of small files rather than exceeding it. Above
  `1` the transfer order is not the walk's, so a failure part-way leaves an unpredictable
  subset transferred.

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
[`scandir`](#streaming-a-directory-you-did-not-size). `read` / `readinto` / `write` / `seek` /
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
[What a transfer costs in memory](#what-a-transfer-costs-in-memory) for what the whole-file
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
direction. Reads at an explicit offset are idempotent and safe to fan out. Writes are not
retried and never will be blindly, because two tasks writing the same range is a race no client can
arbitrate, exactly as with two processes and `pwrite`.

### Read in big blocks

**This is the one performance decision the surface hands you, and it is arithmetic rather than
advice.** A `read(n)` fills the window, drains it, and only then issues the next block, where a
`get` keeps the window full from its first request to its last. So a cursor read costs **one
round trip per block**, `file_size / block_size` of them, and no block size removes it.

The lever is making that count small: **read in blocks of at least 2 MiB**, the SSH channel
window, which is the same ceiling [Tunables](#tunables-and-what-they-default-to) explains for
`depth`. An
8 KiB block is one round trip per 8 KiB, which on any link with latency is the whole transfer.
What each block size costs on each link profile is what the
[benchmark lane](benchmarks/README.md) measures; run it rather than trusting a number quoted
here, which is why none is.

**If you want `get`'s throughput without `get`'s destination, fan out `read_at`.** Independent
ranges in flight have no bubble to amortise. Closing the gap inside the cursor would take
read-ahead, and that is deliberately not here: implicit prefetching is a policy the caller cannot
see, and `paramiko#2454` is an open request for an API to switch theirs off.

This is measured rather than asserted, and against the incumbent: `benchmarks/` carries a
`read 16 MiB: file object vs whole file` row, and the run **fails** if our file object at a
window-sized block drops below half our own `get`. That gate exists because the obvious
implementation, one `READ` per call, awaited, is what makes `paramiko#2453`'s file object
slower than its own `get` by more than an order of magnitude, and shipping it under a new name
would have shipped the same complaint.

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
cannot be found again, and a `staging_name` cannot be fixed for a whole tree. Deriving one per
file from the target would make it predictable for every file at once, which is exactly what
the generated name exists to prevent, so the combination is refused rather than quietly
downgraded. Resuming an upload therefore means resuming the destination files themselves, and a
consumer polling the directory can see a partial file while it happens.

## A working directory, which this protocol does not have

```python
await sftp.chdir("/incoming/2026")
await sftp.get("data.csv", "data.csv")     # /incoming/2026/data.csv
await sftp.getcwd()                        # b'/incoming/2026'
```

**SFTP v3 has no working directory.** There is nothing on the wire to set and nothing to ask, so
`chdir` is a prefix *this library* prepends to relative paths. Every method takes it, including
`stat`, `glob`, `walk`, `get_tree` and `open_file`, because they share one resolver rather
than each remembering to apply it.

Before any `chdir`, relative paths are left alone and the **server** resolves them against its
own default directory. `getcwd()` reports that until you move; `session.server_root` is the same
value and never moves.

Four things worth knowing:

- **`chdir` costs two round trips and checks two things.** A `REALPATH`, so what is stored is
  canonical, since a prefix holding `..` is one a symlink can redirect between the `chdir` and
  the operation. Then a `STAT`, because `REALPATH` checks nothing: canonicalising a path that does
  not exist *succeeds* on OpenSSH, so without it a `chdir` to a typo would be accepted and every
  later call would fail somewhere else, naming a path you never typed.
- **Absolute paths are never prefixed**, so mixing the two is safe and a path this library hands
  you back from `walk`, `glob` or `realpath` can be passed straight back in.
- **`symlink()`'s target is not prefixed.** It is a string stored *inside* the link and
  interpreted by the server relative to the link's own directory, so
  `symlink("data.csv", "alias.csv")` stays the relative link a shell would make.
- **It does not survive a reconnect.** `with_reconnect` builds a new session per attempt and
  nothing survives one: not the handles, not the request ids, not the limits. Call `chdir`
  *inside* the operation, the same way you re-establish everything else.

On a server whose namespace is not rooted at `/`, `chdir` refuses with `CapabilityError`: a
prefix is `/` arithmetic, and the draft defines no other filename syntax. `getcwd` still answers,
because reporting where you are asks no arithmetic. See
[Servers whose namespace is not rooted at `/`](#servers-whose-namespace-is-not-rooted-at-).

## Two kinds of path

One transfer takes one of each, and the rule is different on each side:

```python
await sftp.get("/incoming/data.csv", Path("downloads/data.csv"))
#              ^ remote: bytes or str              ^ local: Path or str
```

A **remote** path is `bytes` or `str`. It goes on the wire as bytes, and a `str` is encoded with
`surrogateescape` so a name the server sent, which is frequently not valid UTF-8, can be sent
straight back. A **local** path is a `Path` or a `str`, because it is opened by this process.

**A `Path` for the remote side is refused, and that is deliberate rather than unimplemented.**
`pathlib` normalises, and a remote name has to survive byte for byte:

- `PurePosixPath("/incoming/")` is `PurePosixPath('/incoming')`, so the trailing slash is gone
  before the library ever sees it;
- `str(Path("/incoming/data.csv"))` on **Windows** is `'\incoming\data.csv'`, and a backslash is
  a perfectly legal character in a POSIX filename. The server would not refuse it. You would get
  a file *named* `\incoming\data.csv`, in whatever directory the session started in.

So the refusal is a `TypeError` naming the rule, not an `os.fsencode` that looks like a
convenience. Pass `str(path)` when the path really is posix-shaped, or the bytes the server gave
you.

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
  directory on that server. `is_dir` is `False` for `unknown`, which is the safe way round for
  a walk, so read `kind` where the difference matters.
- **`entry.filename` is bytes and `entry.name` is `str` via `surrogateescape`.** A filename
  on Linux is bytes; a name decoded lossily is a file you can list and cannot open. The two
  round-trip, so the name you display is the name you can send back.

`.` and `..` are filtered out. `readdir()` gives you the raw batches if you want to see
exactly what the server sent: one READDIR is not a directory, and the server decides how
many entries a batch holds (OpenSSH: 100). It reports the end of a directory as `None`, for
an `EOF` status **and** for a NAME carrying zero names: the draft says a READDIR is answered
with "one or more names" and OpenSSH's server never sends an empty one, but OpenSSH's client
stops on one, and being stricter than `sftp(1)` against real-world servers buys nothing.

### Streaming a directory you did not size

`listdir()` follows every batch to the end, so **how much memory it takes is the server's
decision, not yours.** A directory with millions of entries, or a server willing to answer
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
finalised by trio, so the handle would sit on the server until the garbage collector felt like
it, if ever. Iterating one without the `async with` raises `StateError` instead of leaking.

Other work on the session is fine inside the loop, such as a `stat` per entry or a `get`,
because a session multiplexes and a scan holds no lock.

`listdir()` is `scandir()` collected, so the two cannot disagree about what a directory
contains. `walk()` uses it too, which means the raw listing and the classified one are never
both in memory; one directory still is, and that bound is structural, because a top-down walk
cannot know where to descend until it has seen every name.

## Is it there?

```python
if not await sftp.exists("/incoming/2026"):
    await sftp.makedirs("/incoming/2026/q3")
```

`exists`, `isdir`, `isfile`, `islink`, `getsize`, `getmtime` and `makedirs`, each of them
taking bytes or `str`, like everything else on the session.

**`False` means the server said `NO_SUCH_FILE`, and only that.** Every other refusal is
raised. This is the one decision in this section worth reading, because the obvious
implementation gets it wrong:

| The server answers | Because | `exists()` |
| ------------------ | ------- | ---------- |
| `NO_SUCH_FILE` | it is not there, and also `ENOTDIR`, a path under a file, and `ELOOP`, a symlink loop | `False` |
| `PERMISSION_DENIED` | a directory on the way may not be traversed | **raises** |
| `BAD_MESSAGE` | the name is longer than the far end's `NAME_MAX`. The code reads as *your frame was malformed*; it is `ENAMETOOLONG` | **raises** |
| `FAILURE` | v3's catch-all: a full disk, a read-only mount, whatever the server felt like | **raises** |

A predicate that collapsed those into `False` would report a path as free when something you
cannot see is sitting on it, and the next line in almost every program that calls `exists()`
creates something there. So `if not await sftp.exists(p)` needs no `try` around it: the
answer is either an answer or an exception that names the path and the refusal.

`isdir`, `isfile` and `islink` add one more state. v3 carries the file type inside the
permission bits, and a server is not obliged to send any, which is the same `EntryKind.UNKNOWN`
a listing can report. They raise `CapabilityError` there rather than answering `False`, because
"not a directory" is a definite answer to a question the server did not answer.

### Following the link, or not

`exists`, `isdir`, `isfile`, `getsize` and `getmtime` take `follow_symlinks=` and default to
`True`, matching `os.path`. `islink` does not take it: resolving the link first is what makes
its question unanswerable.

A **broken** symlink is where the two spellings separate, and the difference is the one
publishing cares about:

```python
await sftp.exists("/incoming/yesterday.csv")                        # False -- no file there
await sftp.exists("/incoming/yesterday.csv", follow_symlinks=False) # True  -- name is taken
await sftp.islink("/incoming/yesterday.csv")                        # True
```

### One attribute, and the answer that is missing

```python
size = await sftp.getsize("/incoming/data.parquet")   # int | None
when = await sftp.getmtime("/incoming/data.parquet")  # datetime | None, aware, UTC
```

`None` means the server sent an ATTRS with no such field, which is legal in v3 and not the same
as zero or as 1970. A file that is not there **raises** instead, so the `None` means exactly one
thing. `getmtime` returns an aware UTC `datetime` rather than `os.path.getmtime`'s float, for
the reason `modified_at` exists: `datetime.fromtimestamp(seconds)` with no timezone gives the
*client's* local wall clock and then disagrees with everything rendered server-side. It is
second-granular, because v3 has no sub-second field.

### `makedirs`

`os.makedirs` semantics, including the asymmetry: an existing **ancestor** is never an error,
and `exist_ok` governs the last component only. It costs one round trip when the parent is
already there, and walks up a level at a time only where one is genuinely absent.

Where something is in the way, the error says what. v3 answers a failed `MKDIR` with the
contentless `FAILURE`, and OpenSSH sends the single word `Failure` for an occupied name, a
full disk and a read-only mount alike, so the note is the diagnosis:

```
ServerError: server returned FAILURE: Failure path=b'/incoming/2026'
  b'/incoming/2026' already exists and is a file, not a directory, so nothing can be
  created at that name until it is moved or removed
```

The path named is the deepest level that actually failed, which is not always the one you
asked for: `makedirs("/locked/a/b")` against a directory you may not write reports
`/locked/a`, because that is the one to fix.

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
| Component validation | `..`, separators, the empty name, NUL, and on Windows `:` streams, `C:` drive-relative names, `CON`/`LPT1` devices, trailing dots |
| Containment          | a destination subdirectory that is *already* a local symlink pointing elsewhere, so every component is innocent and the finished path is outside |

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
refused. That never asks *why* two names became one file, so one check covers case folding,
`report.` beside `report` on Windows, and NFC/NFD pairs on HFS+. Reimplementing three
filesystems' folding tables in Python would get all three subtly wrong instead.

Everything transferable still transfers; only the write that would destroy an earlier one is
refused, recorded in `result.skipped`, and reported at the end. A file left by a *previous*
run is not a collision, since overwriting that is the point of re-running a download, and it is
what `resume=` depends on. Which member of a colliding pair survives is `READDIR` order, so it
is the server's choice and not reproducible; the error names both.

`examples/destination_collision.py` runs it.

### Servers whose namespace is not rooted at `/`

Every remote path this library *builds*, whether joining a child onto a directory or splitting a
staging file's parent off its target, is `/` arithmetic on bytes. That is what the protocol says to
assume: `draft-ietf-secsh-filexfer-02` §6.2, *"File names are assumed to use the slash ('/')
character as a directory separator"*, and *"otherwise, no syntax is defined for file names by
this specification."*

So on an endpoint whose namespace is not `/`-shaped, such as VMS `DISK$USER:[DIR]FILE.TXT` or an
MVS dataset name, there is no correct join to perform, and guessing per vendor is a different
project. `walk()`, `get_tree()`, `put_tree()`, `rmtree()` and an atomic `put()` raise
`CapabilityError` rather than building a path the server does not mean.

**An absolute path asks nothing and costs nothing.** §6.2 also says a name starting with `/` is
absolute and relative to the root of the filesystem, so a caller who passed one has already
asserted the namespace the arithmetic assumes, so no probe is sent at all. Only a *relative* path
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
staged and renamed, so no consumer ever sees a partial *file*. Nothing makes the *tree* appear
in one step. That would mean renaming a staging directory over the destination, and `rename`
onto a non-empty directory fails on every POSIX server, so it could only ever work for a
destination that does not exist yet. A flag that delivered the guarantee sometimes would be
worse than not having it.

`rmtree()` goes bottom up and **descends only into what the walk positively established is a
directory**. Everything else, meaning files, symlinks, fifos, and entries the server declines to
describe, is removed with `REMOVE`, which is `unlink(2)`: it deletes the *name*, so a symlink
goes and what it points at does not, and a directory is refused rather than emptied. That
refusal is the safety net, and it means a wrong guess can only fail in the direction that
raises. There is no `max_depth`, because a depth-limited recursive delete leaves the deepest
directories populated and their parents unremovable.

## Reconnect and retry

A session cannot reconnect itself, and that is deliberate: `open_session()` is handed a
transport whose lifetime is the caller's. Reconnection lives one level up and needs a
*recipe*: any zero-argument callable that produces a new transport:

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
| `ConnectError`, the transport died | `AuthenticationError`, `HostKeyError` |
| `TransferTimeoutError`, the far end went quiet | `NoSuchFileError`, `PermissionDeniedError`, `UnsupportedError` |
| `ServerError` with `NO_CONNECTION` / `CONNECTION_LOST` | `ServerError` with `FAILURE`, `ProtocolError`, `UnsafePathError` |

Two of those deserve their reasons. **A failed authentication is never retried**, and not just
because credentials do not become correct by being offered again: OpenSSH 9.8+ applies
`PerSourcePenalties`, so repeated failed auth from one address gets that address
progressively locked out, so a retry loop turns one wrong key into a host that stops answering
for everything behind that IP. And **`FAILURE` is terminal**, even though it is sometimes
transient: v3's catch-all is what a permission problem, a full disk, a name collision and a
momentary appliance hiccup all arrive as, so retrying it would turn every fast clear failure
into three slow ones. That changes when the quirks layer can match a server's message text.

**And against OpenSSH it cannot change, at any layer.** That is worth stating plainly rather
than reading as a to-do: a transient `FAILURE` mid-transfer kills the transfer, and no amount
of work here fixes it for the reference server. OpenSSH's `STATUS` message is a constant
function of the status code. Five distinct conditions, from a full disk to a name collision,
all send the single word `Failure`, measured, so there is nothing in the reply to classify on.
Retrying an individual request inside a live connection therefore needs a server whose message
text carries information (asyncssh's does; OpenSSH's does not), and until one is in the test
matrix this stays unbuilt rather than half-built. What you get today is `with_reconnect`, which
re-runs the whole operation when the *link* drops. An eight-hour transfer to an appliance that
hiccups once still starts again from the top, or with `resume=True`, from where it got to.

**`BAD_MESSAGE` is terminal too, and it does not mean what its name says.** It reads as "the
frame you sent was malformed", which would make it a bug in this library rather than an answer
about your file. On OpenSSH it is also where `EINVAL` and `ENAMETOOLONG` land, so a `readlink`
of a path that is not a symlink, or an operation on an over-long name, arrives under it. That is
measured, and it is the reason it sits in the terminal column rather than raising as a protocol
error. A genuinely unparseable frame does not produce this code at all: `sftp-server` exits without
answering.

`examples/retry.py` drops a link mid-download and finishes it on the next connection.

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

| Mechanism       | When                                                      | Atomic                          |
| --------------- | --------------------------------------------------------- | ------------------------------- |
| `posix-rename`  | The server implements `posix-rename@openssh.com`          | Yes, even over an existing file |
| `rename`        | No extension, and the destination did not exist           | Yes. v3 `RENAME` cannot overwrite, so success means it appeared whole |
| `remove-rename` | No extension, and the destination existed                 | **No**, there is a window with no file |
| `in-place`      | You passed `Publish(atomic=False)`                        | **No**, the classic behaviour   |

**Every extension is attempted rather than assumed absent**, because endpoints under-advertise
and the answer is worth more than the claim. The cost of asking is one round trip and it is paid
once: `OP_UNSUPPORTED` is a definitive answer and is remembered for the session, so the second
upload does not ask again. `sftp.refuses(name)` is that memory, next to `sftp.supports(name)`,
which is still only what the server *said*.

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

Three limits stated rather than implied. `fsync@openssh.com` flushes the *file*; SFTP has no
way to flush a directory entry, so the rename that publishes it is never itself durable.
Staging needs the right to create *and* rename a second name in the destination directory, so a
drop directory that only permits creation needs `Publish(atomic=False)`. And a failed publish removes
the staging file, with one deliberate exception: once the `remove-rename` fallback has issued
the `REMOVE`, the staging file may be the only copy of your data, so it is left where it is and
the error says where that is.

That exception starts at the `REMOVE` rather than after it, which is not the obvious place. A
`REMOVE` the server performed but never acknowledged, and a request timeout is enough, is
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
reports, and a size match proves the byte count agrees and nothing else. The remote partial
may be from a different run, a different source file, or a concurrent writer.

Both refuse rather than guess in two cases. A partial *longer* than the file it is supposed
to be a prefix of is a `TransferError`, not a truncation. And a server that will not report a
size makes the check impossible, so the resume is refused instead of silently starting over.

**And where a content check is available, the adopted prefix is gated on it.** The failure a
size match cannot refuse is a partial of the *right* length from the *wrong* source: a
previous run against a different file, a truncated staging file, a concurrent writer. That
upload completes, publishes, and passes the size check, because the finished length is
correct. The gate hashes the prefix on both sides and refuses before a byte is sent:

```python
result = await sftp.put(src, dst, publish=Publish(atomic=False), resume=True)
result.resume_check  # matched | unavailable | skipped
```

| | when it runs | what it costs |
| --- | --- | --- |
| rung 1 | automatically, where the server *performs* `check-file`, asked rather than assumed from the advertisement | one `OPEN`/`EXTENDED`/`CLOSE`, no payload; a refusal is remembered for the session |
| rung 2 | only under `verify=Verify.REREAD` | re-reads the whole adopted prefix |
| neither | the default case, where `resume_check` is `unavailable` | nothing, and the claim stays the weak one |

Rung 1 is automatic because it moves no bytes, so gating on it where it exists is free.
Rung 2 is not, because re-reading the prefix is most of what resume set out to avoid. It is worth
asking for on an asymmetric link, where reading back is cheaper than sending again, and that
is a fact about your link rather than ours. A refusal leaves the partial exactly as it was
found: it may be another publisher's, and it is the only evidence of what went wrong.

The download side is gated too, including the case where the local file is *already complete*.
That one adopts the whole file and returns success having moved nothing, which makes it the
one most worth checking rather than the one to skip. `get` returns an `int`, so it can refuse
but has nothing to report `unavailable` on.

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

1. **Server-side hash**, `verify=Verify.HASH`, where the server has it. Verifies *content*
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
*and* temporary local disk equal to the file, in `$TMPDIR`, since the bytes come back at full
pipelined speed into a scratch file and are compared from there, rather than one round trip
per block. Asking for rung 1 where the server has no `check-file` reports `unavailable`, never
success:

| `verify=` | rung | works against | cost |
| --- | --- | --- | --- |
| `Verify.SIZE` *(default)* | 3 only | everything | nothing beyond the `STAT` every `put` makes |
| `Verify.HASH` | 1, else `unavailable` | `check-file` servers: paramiko, ProFTPD, some appliances | one round trip, no payload |
| `Verify.REREAD` | 2 | everything | a second transfer + scratch disk |

A **mismatch** never appears as a value: it raises `TransferError`, and under `atomic` it
raises *before the rename*, so corrupt content never becomes the destination.

`verify=` is on `put` and not on `get`. The download side has the local file already, so
"read it back" means downloading twice, and rung 1 there is reachable through `check_file()`
directly; the blocker on a `get(verify=)` is that `get` returns an `int` and so has nowhere to
report `unavailable`, a silent degrade being the one outcome this ladder exists to prevent.

If you call `check_file()` yourself, leave `block_size` alone. It defaults to
`CHECK_FILE_BLOCK_SIZE` (64 KiB) because that is the largest block paramiko answers correctly:
above it the digests cover the wrong bytes and the server thread ends up in a loop it never
leaves, and `block_size=0`, meaning "one digest over the whole range", is that same loop for any
file over 64 KiB, and a `FAILURE` for any range under 256 bytes. Measured, not inferred.

Rung 3 is not free of decisions, so here is what it actually does:

| | `get()` | `put()` |
| --- | --- | --- |
| what it compares | bytes that arrived vs. the size the `STAT` reported | the local file's length vs. what the server says it holds |
| when | after the transfer | **before the rename**, against the staging file, so a short upload never becomes the destination. In place, necessarily after |
| cost | nothing; `get` already makes that `STAT` | one extra `STAT`, measured rather than assumed, and it ties on every shaped profile (`benchmarks/`) |
| on mismatch | `TransferError` carrying both paths and the offset | `TransferError`; the staging file is removed and the destination is left alone |
| server won't report a size | check skipped, download still succeeds | `result.size_check` is `unavailable` |
| turning it off | `get(..., verify_size=False)` | no flag; see below |

```python
result = await sftp.put("report.csv", "/incoming/report.csv")
result.size_check  # matched | unavailable
```

An early `EOF` and a short `DATA` are both *legal*, so nothing below `get()` is entitled to
treat one as an error, which is exactly why a truncating server used to produce a short file
and a successful call. `verify_size=False` exists for reading something that is genuinely
changing size underneath you, and makes the result a snapshot of unknown completeness.

There is no matching flag on `put()`: we control the source there, so a length disagreement is
wrong every time, and `SizeCheck` has no `skipped` value as a result. The cost is one `STAT`
per upload, and it was benchmarked rather than assumed. On every shaped profile the small-file
upload row ties with paramiko and asyncssh, because one round trip is invisible beside the ones a
transfer already spends. paramiko's `put` has done the same
`STAT`-and-compare by default since 1.7.7, through its `confirm` parameter, so the benchmark's
paramiko column pays it too and still ties. An earlier draft promised an opt-out flag here; the
measurement withdrew it.

```python
handle = await sftp.open("/incoming/big.iso")
algorithm, digests = await sftp.check_file(handle, algorithms=b"sha256,sha1", block_size=1 << 20)
await sftp.close(handle)
```

You get one digest per block and the algorithm the server chose. It picks the first from your
list that it supports, and answers `FAILURE` if it supports none rather than quietly hashing
with something else. The digest *count* is nowhere on the wire; it follows from the block size
and the width of the chosen algorithm, so a payload that does not divide evenly is a
`ProtocolError` rather than a set of silently misaligned digests.

`check-file` is in no published SFTP draft: 05, 09 and 13 were each checked. The layout here
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

It costs no round trip on download, since the times come from the `STAT` `get` already makes, and
one `FSETSTAT` on upload, sent on the open handle so it pipelines with the writes. On the
atomic path it lands on the *staging* file before the rename, because `rename(2)` does not
alter mtime. On a tree it also stamps the directories the call creates, in a pass after every
file, since writing into a directory updates that directory's own mtime. **The root you named
is never stamped**, only what the call creates under it.

A server that refuses does not fail the upload. `UploadResult.times` says which happened:

| | |
| --- | --- |
| `preserved` | `FSETSTAT` sent and accepted |
| `unavailable` | asked for, and the server refused or ignored it |
| `skipped` | not asked for, which is the default |

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
- A *future* mtime falls into the year branch too, because the guard is `now >= st_mtime`.
- It is rendered in the **server's** timezone. The same instant reads `Jun 23  2025` under
  `TZ=UTC` and `Jun 24  2025` under `TZ=Asia/Tokyo`, a different calendar **day**, with
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

A file mode on a directory is usually unusable, since `0o600` on a directory cannot be entered,
so applying one there would leave a complete tree nothing can read. And the final pass is not
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
economy.** OpenSSH's `process_setstat` walks the flags in sequence (size, permissions, times,
owner) applying each and recording only the last failure in the single status it returns. So a
multi-field `SETSTAT` that fails has *already applied* the fields before the failing one and
does not say which. One field per call makes a refusal unambiguous and leaves nothing else
moved.

`chown` and `utime` set two values each because the wire pairs them: `UIDGID` and `ACMODTIME`
are one flag apiece. To change a uid alone, read the gid back with `stat()` and send it
unchanged.

### These follow symlinks by default

`SETSTAT` is `chmod(2)`/`chown(2)`/`utimes(2)` on a path, and all three follow, the same
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
`ENOTSUP`, measured at the syscall level, because a symlink's own permission bits are
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
every one of those is a legal symlink, so **do not join the result onto a local path** without
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
a file. `unknown` is a real answer, since many endpoints advertise nothing at all, and it is what
you get rather than the nearest match.

Three profiles ship, not ten, because three is how many `live-tests/matrix.py` can actually
start: OpenSSH, asyncssh and paramiko all serve SFTP and the last two were already installed
as benchmark dependencies. A profile without a test against that server is a rumour.

One measurement from that matrix is worth repeating here, because it decides what any
"quirks" layer can ever do. Five distinct failure conditions (`MKDIR` on an existing
directory, `RENAME` onto an existing target, `CREAT|EXCL` on an existing file, `RMDIR` of a
non-empty directory, and `REMOVE` of a directory) produce this:

| | OpenSSH | asyncssh | paramiko |
| --- | --- | --- | --- |
| all five | `Failure` | `File exists` / `File already exists` / `Directory not empty` / `Is a directory` | `Failure` |

**On OpenSSH the error message is a constant function of the error code.** So telling a
transient failure from a permanent one by reading the message, which is the standard proposal
and the thing v3's catch-all `FAILURE` would need, cannot work on the reference server at all.
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
before a connection is attempted at all. If the config file is trusted, yours or your
organisation's, that is the feature that makes `ProxyJump` and bastion hosts work for free. If
it is not, it is arbitrary command execution on the machine running the transfer.

The shipped defaults do **not** close that. `PermitLocalCommand=no` and `ClearAllForwardings=yes`
ship because an SFTP client has no business running `LocalCommand` or establishing forwardings,
and they are worth having, but neither touches `ProxyCommand` or `Match exec`, both of which
still execute with the full default set applied. Verified against OpenSSH 10.0p2 and pinned by
`tests/test_transport.py::test_the_shipped_defaults_do_not_neutralise_an_untrusted_config`.

The control is to not read the file:

```python
async with open_ssh_transport("host", user="bob", config_file=os.devnull) as t:
    ...
```

`-F` suppresses `/etc/ssh/ssh_config` as well as the per-user file, so this is a real "no
config" rather than half of one. Everything the config would have supplied, meaning port,
identity file and username, has an explicit parameter, so the trade is verbosity rather than
capability.

### Passwords

A large fraction of enterprise SFTP endpoints, including MOVEit, GoAnywhere, Cleo and Sterling,
are password-first. Pass one:

```python
async with (
    open_ssh_transport("host", user="bob", password=os.environ["SFTP_PASSWORD"]) as t,
    open_session(t) as sftp,
):
    ...
```

**The secret never reaches argv.** `ssh` refuses to take a password as an argument, and the two
workarounds people reach for, `sshpass -p secret` and stuffing it into an `-o` value, both put
the credential where `/proc/<pid>/cmdline` makes it readable by every user on the machine, for
as long as the process lives. Instead, `password=` writes a throwaway `SSH_ASKPASS` helper to a
`0700` temporary directory and hands `ssh` the secret in the child's *environment*, which on
Linux only this user and root can read. The helper contains no secret, being a `printf` of an
environment variable, and it is deleted when the connection ends, whether or not it succeeded.

Three `ssh` options change on that path, and the first of them is the reason the parameter
exists at all:

| option | value | why |
| --- | --- | --- |
| `BatchMode` | `no` | The shipped default is `yes`, and it does not merely discourage a prompt: it **suppresses the askpass helper outright**, regardless of `SSH_ASKPASS` or `SSH_ASKPASS_REQUIRE`. Password authentication was not awkward under the default; it was impossible. |
| `PreferredAuthentications` | `password,keyboard-interactive` | Deterministic order. Otherwise `ssh` offers every key it can find first, and against a server with a low `MaxAuthTries` the attempts run out before password is reached, failing with `Too many authentication failures`, which names nothing that is wrong. Appliances routinely offer only `keyboard-interactive`, and OpenSSH answers it through the same helper. |
| `NumberOfPasswordPrompts` | `1` | OpenSSH's default is three, each re-running the helper with the same wrong secret. Against an OpenSSH 9.8+ server that is three failed attempts, which earns your source address a `PerSourcePenalties` timeout that then breaks the *next* connection from that host. |

All three are overridable by name through `options=`, except that `password=` together with an
explicit `BatchMode=yes` is refused as the contradiction it is, with a `ValueError` naming
both halves, rather than a `Permission denied` twenty seconds later.

`password=` is POSIX-only: the helper is a shell script, and Windows OpenSSH's prompting path
has never been run here, so it raises `NotImplementedError` rather than shipping an untested
guess.

**What the library will not do**: write your password to a file, put it on a command line, read
it from one, or log it. Anything that can carry it is checked, including `repr()` of the
transport, the captured stderr, `ConnectError.argv`, the rendered exception, and the **frame
locals** a traceback reporter captures, and `tests/test_askpass.py` runs the helper against
passwords built to break a shell (`$(...)`, backticks, `%s%n`, `-n`, embedded quotes) to prove
what comes back out is what went in.

That last surface is the least obvious one. The environment dictionary carrying the secret is a
local variable in an `@asynccontextmanager` generator, so its frame stays alive for the whole
connection, and Sentry captures frame locals by default, as do `pytest --showlocals`, `rich`
tracebacks and IPython's verbose mode. Every one of them renders a local with `repr()`, so the
secret is held in a `str` subclass whose `repr()` is `'<redacted>'`. It is still an ordinary
string everywhere it has to be one, so `ssh` receives it intact. What that does **not** cover,
stated plainly: a reporter that calls `str()` rather than `repr()`, a core dump, and
`/proc/<pid>/environ`, the last being the deliberate trade that buys not being in argv.

### `options=` matches names the way `ssh` does

Option names are matched **case-insensitively**, because that is how `ssh` reads them. An
override spelled `stricthostkeychecking` or `STRICTHOSTKEYCHECKING` replaces the shipped
`StrictHostKeyChecking` rather than joining it on the command line, and warns exactly as the
canonical spelling does.

This is not cosmetic. `ssh` resolves a repeated keyword to the **first** `-o` on the line, and
this library emits its options sorted, where ASCII puts every uppercase letter before every
lowercase one. Matching on exact case therefore let `STRICTHOSTKEYCHECKING=no` land ahead of
the default and silently win, with no `InsecureOptionWarning`, because the warning was reading
the default under its own spelling. The same shape defeated `PermitLocalCommand=no` and the
`BatchMode` contradiction check above. Measured against OpenSSH 10.0p2; pinned by
`tests/test_transport.py::test_ssh_matches_option_names_case_insensitively_and_takes_the_first`,
which characterises `ssh` rather than us, so a change in that behaviour fails loudly.

### Arming your own askpass helper

`password=` is a convenience over a mechanism that is still fully available: set `SSH_ASKPASS`
to any program of yours and `SSH_ASKPASS_REQUIRE=force` through `env=`, and override
`BatchMode`. `SSH_ASKPASS_REQUIRE=force` is what arms the helper on a headless machine.
Measured: `SSH_ASKPASS` alone does not, and `DISPLAY` or `WAYLAND_DISPLAY` each arm it on their
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
questions people actually ask, "was that my key?" and "has the host changed?", are answered
by `except` rather than by string matching in your own code.

It is **bounded**, which "untouched" used to imply it was not: the first 8 KiB and the last
56 KiB, with `... [N bytes of stderr omitted] ...` marking the gap. Both ends, because the
first lines say what was attempted and the last say how it ended, and `ssh -vvv` is precisely
the case that overflows it. A hostile server also writes to that stream, so it is a buffer with
a cap rather than a string with a promise.

Three things about that ladder are deliberate:

- **Unrecognised failures stay `ConnectError`.** A refused connection, a name that will not
  resolve, a cipher mismatch: none of them are guessed into a more specific class. One that
  sometimes means "we guessed" is worth less than one that always means what it says.
- **Host keys are checked before credentials.** Of the two possible misclassifications only one
  costs anything: reporting a *changed* host key as a bad password tells you to check your
  credentials when what happened may be interception. OpenSSH prints a server-supplied banner to
  stderr, so a hostile server can put `Permission denied` in it. What it cannot do is remove the
  host-key line `ssh` itself writes.
- **Every marker was captured from a real server**, not written from memory. A marker that is
  subtly wrong does not fail loudly; it silently stops matching and the class quietly goes back
  to being decorative.

`ConnectError.hint` is the one thing on these errors that is *ours* rather than OpenSSH's, and
it is separate from `stderr` for that reason, since merging them would put words in the server's
mouth. It is set only where this client's own configuration or environment made the failure
inevitable, and **there are exactly two such cases: the ones OpenSSH cannot explain itself.**

The first is when there is no stderr at all, because `ssh` never ran:

```
ConnectError: could not run 'ssh': No such file or directory
hint: 'ssh' was not found. This library does not implement SSH -- it runs the OpenSSH client
as a subprocess -- so an ssh client is a hard requirement. Install it (Debian/Ubuntu:
apt-get install openssh-client; Alpine: apk add openssh-client; RHEL/Fedora: dnf install
openssh-clients), or pass ssh_executable=... if it is installed somewhere PATH does not
reach. A distroless or scratch image has no package manager and cannot run this transport
at all.
```

`could not run 'ssh': No such file or directory` is diagnosable only by a reader who already
knows the answer, and this is the failure most likely to be somebody's *first* experience of
the library; see [What it needs](#what-it-needs-read-this-before-you-install-it). A binary
that exists but will not execute gets a different hint, and a spawn that failed for a reason
that is nothing to do with the binary, such as out of memory or out of file descriptors, gets
none, because installing a package would not fix it.

The second is when the stderr is real and says the wrong thing:

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
spawned to tell them apart, and stays empty when a password *was* offered and refused, because
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

- **`request_timeout=30.0`** covers one round trip: the handshake, a `STAT`, an `OPEN`, a
  `CLOSE`. A server that accepts the connection and then says nothing trips it. It also bounds
  every **write**, including the wait for the connection's send lock.
- **`idle_timeout=60.0`** covers a bulk transfer's *silence*, not its duration. A nine-hour
  download over a slow link never trips it; sixty seconds with nothing arriving does.

`None` for either means no bound at all. It is a legitimate thing to ask for, and it is never
the default. It covers *teardown* as well, which is the half worth knowing: cleanup after a
cancelled transfer is shielded so that it survives the cancellation that triggered it, and a
shield is not cancellable from outside, so with `request_timeout=None` and a peer that has
stopped reading its socket, leaving the `async with` block waits forever on the cleanup
`CLOSE`. `request_timeout` is the only thing that bounds it.

**The write half was unbounded until 0.9, and "in practice it cannot block" is why** (D-40).
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
with `request_timeout=None`, never finished at all (fixed in 0.8, D-34). The reader stops when
the `async with open_session(...)` block ends and at no other time; cancelling the task group
it happens to run in deliberately does not stop it.

`examples/cancellation.py` runs this with no arguments.

## Seeing what it is doing

Nothing is printed unless you ask. The package logger carries a `NullHandler`, so an
application that never configures `logging` sees nothing at all from this library, including
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
| `gantry_sftp.session`     | WARNING | A retryable failure `with_reconnect()` swallowed, the only warning in the tree |
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

**The frame dump is per packet and it means it.** A 16 MiB download is a few hundred lines and
a recursive tree is thousands. Turn it on for a protocol question. When it is off it costs one
`isEnabledFor` check per packet and nothing is rendered, which is asserted rather than assumed.

**Payloads are never in it.** `DATA` and `WRITE` show as `len=N offset=M`. That is not
squeamishness: a quarter-megabyte payload per line is unreadable, and rendering it would copy
the `memoryview` that the copy-free data path exists to avoid.

**Every server-supplied name is escaped and truncated.** A filename, a path and a `STATUS`
message are all chosen by the far end, and written raw into a log stream a `\n` forges a second
record while an `\x1b[` sequence drives the terminal of whoever is tailing the file. They are
rendered with `repr`, which escapes both and every non-printable codepoint besides, and
capped at 96 bytes with the dropped count stated, because a 64 KiB filename is legal and a log
line per frame is a disk to fill.

`gantry_sftp.codec.describe(packet)` is the renderer, and it is public and pure: pass it any
packet and get the same line back, with no logging configured and no session running.

### Structured output: the fields are on the record, not only in the message

Every record the `session` and `transport` loggers emit carries its fields **as data** as well
as in the sentence, under one `LogRecord` attribute. So a JSON sink indexes them instead of
re-parsing text this library formatted:

```python
import json, logging
from gantry_sftp import record_fields

class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "severity": record.levelname,
            "message": record.getMessage(),
            **record_fields(record),
        })
```

```json
{"severity": "DEBUG", "message": "put ok local='data.csv' remote=b'/incoming/data.csv' bytes=13 mechanism='POSIX_RENAME' elapsed=0.002s",
 "operation": "put", "event": "ok", "local": "data.csv", "remote": "/incoming/data.csv",
 "bytes": 13, "mechanism": "POSIX_RENAME", "elapsed": 0.0018}
```

`record_fields(record)` returns `{}` for a record from anywhere else, so the formatter is safe
on the root logger. The attribute name is `LOG_FIELDS` if you would rather read it directly.

**Three keys are on every record**, and they are what a query selects on before any of the rest:

| | |
| --- | --- |
| `operation` | `get`, `put`, `get_tree`, `put_tree`, `rmtree`, `spawn`, `close`, `reconnect` |
| `event` | `start`, `ok`, `failed`, `retrying` — the field a "started but never finished" query needs |
| `elapsed` | seconds, on the closing record. `error` joins it on a failure, carrying the exception's class name |

The rest are per operation: `remote` and `local`; `bytes`; `files`, `directories` and `skipped`
on a tree; `mechanism` on a `put`; `pid`, `argv`, `returncode` and `steering` on the transport;
`attempt`, `attempts` and `delay` on the retry warning.

Three properties worth knowing, because they are decisions rather than accidents:

- **Numbers stay numbers.** `bytes` and `elapsed` arrive as an int and a float, so `bytes > 1e9`
  is a query rather than a substring match that also catches 10240.
- **Names are escaped, and not wrapped in quotes.** A remote name is chosen by the server, so it
  gets the same `repr` escaping the frame dump uses — a `\n` cannot forge a record and the value
  is pure ASCII, which matters because a filename that was never valid UTF-8 would otherwise
  break `json.dumps(...).encode()` in the sink. What it does *not* get is `repr`'s surrounding
  quotes, since those would become part of the value you filter on.
- **A list stays a list and a mapping stays a mapping.** `argv` is an array and `steering` an
  object, each scalar inside escaped and capped, rather than one long truncated string.

**The frame dump carries no fields, deliberately.** `gantry_sftp.frames` renders through
`codec.describe(packet)`, which returns a string by design — the codec renders, the session seam
emits, and a test enforces the split. A frame dump is text and stays text.

Runnable: `examples/observability.py`.

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
so a counter would reset exactly when it became interesting. The WARNING above is where retry
visibility lives, and it names the attempt, the error and the backoff.

### Credentials

A password never reaches argv, a file, or a log record. It travels in the child's environment
via an `SSH_ASKPASS` helper, and:

- the value renders as `'<redacted>'` in any frame-locals dump. Sentry, `pytest --showlocals`,
  `rich` and IPython all render locals with `repr`, and that is the boundary it defends;
- the environment is masked by name before it can reach a log record, so the record says
  `'GANTRY_SFTP_ASKPASS_ANSWER': '<redacted>'`, since the *presence* of an askpass answer is exactly
  what a failed password authentication needs to know, and the value is not;
- the mask also covers any variable whose name contains `PASSWORD`, `PASSPHRASE`, `SECRET`,
  `TOKEN` or `CREDENTIAL`, including ones this library never sets, so a caller's own `env=`
  overlay is covered too.

What that does **not** cover, stated because a half-understood guarantee is worse than none: a
reporter that calls `str()` rather than `repr()` on a local, a core dump, and
`/proc/<pid>/environ`. The last is the deliberate trade: owner-and-root readable beats `ps`
output readable by every user on the machine.

`examples/logging.py` runs all of this with no arguments.

### `doctor`, the diagnostic no other Python SFTP library can ship

```console
$ python -m gantry_sftp doctor sftp.example.com
```

paramiko and asyncssh **are** the SSH environment, with no external binary, no `ssh_config`
somebody else wrote and no agent socket resolved by a program they do not own, so they have
nothing to introspect. This library spawns OpenSSH, and the price of that dependency is also
the only reason a report like this can exist.

Without a host it reaches no network and answers what a container image needs to know: which
`ssh` would be spawned and how that was resolved, its version, whether this platform supports
transfers, which config file `ssh` will read, which steering variables are set, and the
tunables this build ships. That is the
[Dockerfile check](#what-it-needs-read-this-before-you-install-it).

With a host it connects once and reports **the same negotiation a transfer performs**: the
protocol version, the identified implementation, every advertised extension split into the ones
this library uses and the ones it ignores, the `limits@openssh.com` answers, the request size
derived from them, the pipeline depth, and where the session starts. That is a better answer to
*why did `posix_rename` not happen* or *why is this slow* than any log line, because it is not a
description of the handshake; it is the handshake.

| flag | |
| --- | --- |
| `--json` | the same report as JSON, so CI asserts on fields rather than scraping text |
| `--user`, `--port`, `-i`, `--config-file` | as `ssh` takes them |
| `-o KEY=VALUE` | repeatable, so the connection you diagnose is the one that is failing |

It is safe to paste into a bug report, which is the point of it: only the variables that steer
`ssh` are read at all, and their values go through the same masking chokepoint as everything
above. There is no `--password`, because a secret does not belong on a command line, and no flag to
replace the environment, because the environment is part of what is being diagnosed.

Exit codes are distinct rather than 0/1: **0** usable · **2** usage · **3** no `ssh` binary ·
**4** platform cannot transfer · **5** host unreachable.

The report is data before it is text. `gantry_sftp.doctor.local_diagnosis()` and
`server_diagnosis()` return dataclasses, so a health check reads fields instead of parsing, and
`examples/doctor.py` does exactly that.

## Speed, and where its numbers are

Not here, and not anywhere in this repository. [`benchmarks/`](benchmarks/README.md) measures
this library against paramiko and asyncssh across five link profiles, in both directions, and
writes its tables to a report that is **not committed**. Run `python scripts/lanes.py
benchmarks` and it re-derives them in about ten minutes.

That is a decision rather than an omission. A figure in a document is an observation of one
machine on one afternoon and it ages without anybody noticing; a lane fails. What the committed
tree does say is where this architecture *costs* something: it is slower to connect than either
alternative, and it wins nothing on CPU. A cost is worth knowing whether or not you trust the
person reporting it.

Two things about speed are mechanism rather than measurement, so they are worth stating where you
are reading:

- **Sustained SFTP throughput is bounded by bytes in flight, not by cryptography.** Outstanding
  requests times request size, divided by the round-trip time. That is why this library pipelines
  by default and why `sftp(1)`'s 64 requests of 32 KiB is the number the whole design argues with.
- **The ceiling is OpenSSH's per-channel flow-control window, 2 MiB, and it is not ours to lift.**
  It is enforced by the SSH transport one layer below anything here, so no amount of pipelining
  exceeds it. See [Tunables](#tunables-and-what-they-default-to) for what that means for `depth`.
  paramiko and asyncssh default to the same 2 MiB and *could* raise it; we cannot, and that is a
  real cost of not implementing SSH rather than a detail.

## Tunables, and what they default to

Every knob this library has, with the number it ships as. There are four, and three of them
you should not need.

| Setting | Default | What it bounds | When to change it |
| --- | --- | --- | --- |
| `request_timeout` | `30.0` s | One round trip (the handshake, a `STAT`, an `OPEN`, a `CLOSE`) **and one write**, including the wait for the send lock | Raise for an appliance that thinks slowly; `None` for no bound at all |
| `idle_timeout` | `60.0` s | A bulk transfer's *silence*, not its duration. A nine-hour download never trips it; sixty seconds with nothing arriving does | Raise if the far end legitimately pauses for minutes mid-transfer |
| `depth` | `64` | Requests in flight per transfer, and therefore the memory one costs | Lower it to fit a smaller container, as below; raising it does not raise throughput, also below |
| request size | `261120` bytes | Payload per `READ`/`WRITE` | Not a parameter. Derived per connection from `limits@openssh.com`, clamped to what the server says it will accept |

All three parameters are keyword arguments to `open_session()` (and to `with_reconnect()`,
which forwards them); `connect()` takes the same three as one `SessionOptions`, because the
`ssh` arguments already spend this project's argument budget. The blocking surface spells both
exactly the same way. `None` for either timeout means no bound; it is a legitimate thing to ask
for and it is never the default.

**Why the request size is not 256 KiB.** It is the round number, and it is unachievable: the
reference server reports `max-packet-length` 262144 and `max-read-length` 261120, because the
packet also carries the type byte, the request id, the handle and the offset. Asking for the
round number means being clamped on every single request forever. Worse, a frame *over* the
packet limit is not refused. Measured: `sftp-server` exits with no `STATUS` and an empty
stderr, and the connection dies mid-write. So the size is derived, not defaulted.

**Why raising `depth` past 64 does nothing.** 64 × 255 KiB is what the client *issues*; what
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

| Operation | Requests | Round trips | Which ones |
| --- | --- | --- | --- |
| `stat` / `lstat` / `realpath` / `getsize` | 1 | 1 | itself |
| `get` | 3 + `ceil(size / request size)` | **2** + 1 for the reads | `STAT` **and** `OPEN` together, the `READ`s, `CLOSE` |
| `put(publish=Publish(atomic=False, fsync=False))` | 3 + `ceil(size / request size)` | 3 + 1 for the writes | `OPEN`, the `WRITE`s, `CLOSE`, `STAT` |
| `put` (the default, atomic and flushed) | 5 + `ceil(size / request size)` | 5 + 1 for the writes | the four above plus `fsync@openssh.com` and the rename |
| `listdir` / `scandir` | 2 + one `READDIR` per reply the server chooses to split the directory into | the same | `OPENDIR`, the `READDIR`s, `CLOSE` |

The `READ`s and `WRITE`s pipeline — that is what `depth` is for — so they cost one round trip
in total rather than one each, provided the file is smaller than `depth × request size`.

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
request and can overwrite; without it, v3 `RENAME` has to be *tried and allowed to fail* when the
destination already exists, because the protocol gives no way to ask whether it would — so
publishing over an existing name becomes `RENAME`, `LSTAT`, `REMOVE`, `RENAME`. Eight round
trips against the reference server's five, and the extra ones buy a *weaker* guarantee, because
that ladder has a window in which the destination does not exist. If your consumer polls a drop
directory and your server has no `posix-rename@openssh.com`, `atomic=False` is not the reckless
choice it looks like — read the [atomic publish](#atomic-publish) section before deciding.

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

**`depth` is what you lower**, and it is the whole of the knob — `SessionOptions(depth=8)`
brings a transfer to about 2 MiB, at the cost of throughput on a high-latency link, where the
requests in flight are what hides the round trip. The request size is not a parameter: it is
derived per connection from `limits@openssh.com` and clamped to what the server accepts, which
is the part nobody guesses when sizing a container.

**What multiplies it is concurrency, and you own that number.** One transfer is one `depth`
worth of buffers. `get_tree(concurrency=8)` is eight. Your own task group over `get` is however
many you started — `asyncio.gather` over a hundred files is a hundred, which is where a
comfortable limit stops being comfortable.

The bound is the same in both directions and the reason differs, which matters if you are
reading the code to check us: **uploading**, the codec holds each `WRITE` — payload included —
until the server acknowledges it, so `depth` unacknowledged writes are `depth` payloads;
**downloading**, replies queue in the transfer's own deque until its loop drains them, and at
most `depth` reads are outstanding, so at most `depth` payloads can be waiting. Neither
direction accumulates a *file*: a download places each payload with `os.pwrite` at the offset
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
through a 256 MiB container. See [Byte ranges, and a file object](#byte-ranges-and-a-file-object).

None of this is a *measurement* — peak RSS against paramiko and asyncssh is not measured, and
this section would be true whatever such a comparison said. It is the bound the design
guarantees, derived from two constants you can read.

## Requirements

- Python 3.13+
- **A POSIX host.** Transfers need offset-addressed local I/O: `get` places every payload
  with `os.pwrite` at the offset its request asked for, `put` reads with `os.pread` from a
  worker thread, and `preserve_times` stamps a descriptor rather than a path. All three are
  Unix-only in CPython, and they are not incidental: writing at an explicit offset is why
  writes need no ordering and why a short `READ` is re-queued rather than restarting the
  transfer. On Windows `get` / `get_tree` / `put` / `put_tree` raise `NotImplementedError`
  naming what is missing, before anything is sent and before any local file is touched.
  Everything that talks only to the far end (connecting, `listdir`, `scandir`, `walk`,
  `stat`, `realpath`, `rename`, `remove`, `mkdir`, `rmdir`, `rmtree` and `check_file`) is
  platform-independent and works there. A Windows fallback is open work, not a decision
  against it.
- An `ssh` binary on `PATH` (`openssh-client`). Windows ships one at
  `%SystemRoot%\System32\OpenSSH\ssh.exe`. **The container story, the install commands and
  the platforms where this cannot run are on the first screen**, under
  [What it needs](#what-it-needs-read-this-before-you-install-it), rather than repeated here.
  One copy, so the two cannot drift.
- `openssh-server`, **only** to run the real-server test lane, never at runtime.

## Development

```bash
export UV_CACHE_DIR=/workspace/.uv-cache   # the default cache is root-owned here
uv sync
.venv/bin/pre-commit install               # sets up pre-commit and pre-push
```

Every proof this project has is a **lane**, and `scripts/lanes.py` is the one place they are
named. Run it with no arguments for the table: what each lane proves, what it needs installed
first, roughly how long it takes, and whether it gates.

```bash
python scripts/lanes.py                 # the table
python scripts/lanes.py gates fast      # what has to pass before anything lands
python scripts/lanes.py -n benchmarks   # print the argv it would run, run nothing
```

| lane | what it proves | needs, beyond `uv sync` |
| --- | --- | --- |
| `lanes.py gates` | ruff, mypy `--strict`, ty, complexipy, the deprecation check, the `uv.lock` check, the exec bit | nothing; POSIX only |
| `lanes.py fast` | unit tests, the real `sftp-server` rows, every example as a subprocess | `openssh-server` for some rows |
| `lanes.py live` | a real `sshd` on localhost: transport, `ssh` environment, cancellation, handles | `openssh-server` |
| `lanes.py matrix` | one client against three servers: OpenSSH, asyncssh, paramiko | `uv sync --group bench` |
| `lanes.py netem` | every pipelining claim, on a `tc`-shaped link at 5/50/200 ms RTT | `CAP_NET_ADMIN` |
| `lanes.py benchmarks` | wall clock and CPU against paramiko and asyncssh | both of the two above |
| `lanes.py mutation` | whether an assertion would notice the line being wrong | nothing |

The first four **gate**: a failure stops the change. The last three **report**, meaning they
measure, or assert against a baseline that is not in this tree, and `scripts/lanes.py` carries the
reason next to each one, so opting a lane out of gating is a written act rather than a habit.

Type checking is deliberately two-tool: mypy is stricter and catches gaps ty misses. A
finding gets fixed at the source, never silenced with an ignore.

Calling a deprecated API is a gate of its own, over the whole repository rather than over `src`
alone — a deprecated spelling taught in an example is one that gets copied into shipped code.
mypy's `deprecated` error code and ty's `deprecated` rule both run, and a third hook runs
`basedpyright` with type checking switched off and `reportDeprecated` switched on, because the
three checkers vendor different typeshed snapshots and the one that already carries a
deprecation is not always the one you were going to run.

`tests/` and `examples/` need no network and are what `fast` runs. Every example is executed
as a subprocess, because an example that has drifted out of sync with the library is a
confident, wrong answer somebody will copy. `live-tests/` starts a real `sshd` on localhost;
`benchmarks/` needs that plus a shaped link and the comparison libraries. Both are excluded
from the default `pytest` run, and every lane skips with a reason rather than failing when the
thing it needs is absent.

The comparison libraries are a separate dependency group and are deliberately not installed by
default. They pull in `cryptography`, `pynacl` and `bcrypt`, and Python cryptography is precisely
what this project exists not to need, and a `uv sync` that installed it would make that claim
harder to check than it should be. No lane installs them on your behalf, for the same reason.

### CI

`.github/workflows/ci.yml` runs those lanes on Linux, macOS and Windows. It invokes them
through `scripts/lanes.py` rather than spelling out a `pytest` command of its own, so CI and a
developer cannot drift into running different things; `tests/test_lanes.py` asserts both that
and that every lane the runner knows about is named in the workflow.

**It has never run.** There is no git remote yet, so GitHub has never seen this repository.
The file is committed anyway, because deciding which lane runs where and what it needs is most
of the work and none of it needs a remote, and because a Windows job is the only thing that
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
*wrong* one, and the assertion that we surface `Permission denied` verifies nothing while
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
  the password database, not from `$HOME`. With `HOME` pointed at an empty directory it still
  reads the real `~/.ssh/config` and still loads the real default identities. **`-F` is the
  defence**, and nothing asserted it either. The redirect stays for its real and narrower scope:
  it is inherited by the children `ssh` spawns, and it expands inside `-o` values such as
  `ControlPath=${HOME}/…`.
- **Clearing `SSH_ASKPASS` does not disarm the askpass helper.** `/usr/bin/ssh-askpass` is
  compiled in as the default, and the variables that *arm* it are `DISPLAY` and
  `WAYLAND_DISPLAY`, either alone being enough to make a passphrase-protected key authenticate
  through a helper. Both were missing from the set; `WAYLAND_DISPLAY` appears nowhere in
  `ssh(1)`.

### The netem lane

`live-tests/test_netem_pipelining.py` is where every claim about pipelining is made, because
it is the only place a pipelining bug is visible: on an unshaped link a lockstep client and a
deeply pipelined one finish at the same time. It shapes loopback with `tc netem` at 5, 50 and
200 ms round-trip times, with packet loss, and it takes about 70 seconds.

Shaping needs `CAP_NET_ADMIN`. In a container that means starting it with
`--cap-add=NET_ADMIN`, since capabilities cannot be added to a running container, and, if the
tests do not run as root, a way for the test user to exercise it (passwordless `sudo`, or
`setcap cap_net_admin+ep` on the `tc` binary). The lane probes for this by adding a real qdisc
and removing it again, rather than by reading `/proc/self/status`: a capability can sit in the
bounding set and be unusable, and be perfectly usable through `sudo` while `CapEff` reads all
zeros. When it cannot shape, every test in the file skips with the line that would fix it.

Two things to know if you read the numbers it prints. `netem`'s delay applies **per traversal**
of the interface, so a 200 ms round trip is configured as `delay 100ms`; the module halves it
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

`benchmarks/` is where every performance number this project has comes from, and none of them is
committed: the suite writes `_reports/benchmarks.md`, which is gitignored, and the directory is
excluded from the built distribution because no packager runs a benchmark and it needs paramiko
and asyncssh to do anything. It reuses
the netem shaping and the `sshd` harness from `live-tests/` rather than copying them, because two
spellings of "how this suite connects" is how the scrubbed `ssh` environment ends up applied in
one of them and not the other, and a benchmark that quietly read your `ssh_config` would report
your `Compression yes` as a change in the library.

It reports **wall clock and CPU side by side**, because on a latency-bound link all three
clients hit the same 2 MiB channel window and wall clock alone cannot see the architecture. CPU
comes from `getrusage(RUSAGE_SELF) + RUSAGE_CHILDREN`, which is the only counter that can see
an `ssh` subprocess at all, and because `RUSAGE_CHILDREN` accounts only for children that have
been *reaped*, the CPU window necessarily spans connect through close rather than the transfer
alone. The `connect` scenario measures that half separately so it can be subtracted, and every
client is measured through the same wider window. That mechanism has its own test in `tests/`,
because a counter silently returning only this process's time would fail nothing and publish a
number saying the thesis is free.

Repeats are few, so every row carries a **spread** (slowest ÷ fastest) and a ratio drawn from
overlapping sample ranges is printed with `(overlapping)` beside it. With three samples a
*p*-value would be theatre; non-overlapping ranges is something you can check by eye.

The fairness rules are in `benchmarks/README.md`, one written line per decision that could have
gone the other way: best default API per library, host keys verified by all three, no agent or
`ssh_config` for any of them, and our own atomic publish switched off in the comparison row and
measured separately.

One scenario in it is not a comparison and is the only thing in the lane that **fails a run**:
throughput swept against file size, ten sizes from 4 KiB to 16 MiB, both directions. Nobody
reports a library's speed as a ratio; they report a *pathology*, a cliff at a byte count, and
those are what the incumbent's tracker is full of. So the claim worth being able to make is that
throughput rises and then plateaus and **never falls as the file grows**, and it is worth
nothing unless something sweeps the axis a cliff would hide on. Every rung is a boundary rather
than a round number, including the crossing from one 261120-byte request to two, and each one
reuses a connection with a warm-up discarded so that TCP slow start is not mistaken for a cliff
at the small end. paramiko and asyncssh are swept beside us as controls, reported and never
asserted, because an incumbent's pathology must not be able to fail our lane. This says nothing
about a *regression* between runs; comparing figures against a committed baseline is separate,
unbuilt work.

### The mutation lane

Coverage says a line ran. It does not say an assertion would have noticed the line being
wrong. For frame parsing and offset arithmetic that distinction is the whole game, so the
codec carries a `mutmut` run:

```bash
python scripts/lanes.py mutation   # ~4 minutes; scoped to codec/ by pyproject.toml
.venv/bin/mutmut browse            # inspect survivors
.venv/bin/mutmut results           # non-interactive list
```

It is a lane, not a pre-commit gate, because it takes minutes rather than seconds. A surviving
mutant in `codec/` is a missing test, not a curiosity, and the survivors that are genuinely
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

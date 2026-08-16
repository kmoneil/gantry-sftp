# Getting started

Install it, check the one thing it needs, and move a file.

## Install

```console
pip install gantry-sftp
```

It has one dependency, `anyio`, and **no cryptography** — because it does not implement SSH. It
runs the `ssh` you already have. That means one prerequisite `pip` will not install for you:

```console
python -m gantry_sftp doctor
```

If that says `exit 3 (no ssh binary)`, install `openssh-client` and run it again. The full story,
including the container images where this cannot work at all, is on the
[front page](../README.md#what-it-needs-read-this-before-you-install-it) — worth two minutes now
rather than on your first deploy.

## Your first transfer

No event loop, no `async`, no framework:

```python
from gantry_sftp.sync import connect

with connect("example.com", user="bob") as sftp:
    sftp.get("/remote/data.parquet", "data.parquet")
    result = sftp.put("report.csv", "/remote/report.csv")
    print(result.mechanism, result.atomic)  # posix-rename True
```

Authentication is OpenSSH's, so if `ssh example.com` works from your shell — key, agent, `Host`
alias, `ProxyJump`, whatever your `ssh_config` says — this works too, with nothing configured
twice. [Connecting and authenticating](connecting.md) covers the seams.

Three things happened in those four lines that are worth knowing about:

- **The upload was atomic.** It staged, flushed and renamed, so nothing could observe a partial
  file at the destination. `result.mechanism` says which of four mechanisms actually ran, because
  every step is an optional server extension. See [Atomic publish](transfers.md#atomic-publish).
- **Both transfers were verified.** What arrived was checked against the size the far end
  reported. See [Verifying a transfer](transfers.md#verifying-a-transfer).
- **Both were pipelined.** Neither was one request at a time waiting for a reply, which is what
  makes this quick on a link with any latency. See [Tunables](tuning.md#tunables-and-what-they-default-to).

## The same thing with an event loop

The core is async, written against `anyio`, so it runs on **asyncio and on trio** — every async
test in the suite runs on both backends, which is what makes that a property rather than a claim.
Drop the `.sync` and add the keywords:

```python
import anyio
from gantry_sftp import connect

async def main():
    async with connect("example.com", user="bob") as sftp:
        await sftp.get("/remote/data.parquet", "data.parquet")

anyio.run(main)
```

Reach for this when you are inside something that already has a loop, or when you want many
transfers over one connection — see [Concurrency](concurrency.md).

## Where to go next

- **[`examples/`](../examples/README.md)** — one runnable example per feature, each working with
  no arguments against a real `sftp-server`, and all of them executed by the test suite. The
  fastest way in if you would rather read code.
- **[Transferring files](transfers.md)** — the guarantees around `get` and `put`, and the four
  things that go wrong in production.
- **[Paths, predicates and attributes](paths.md)** — `SFTPPath`, and the one type rule worth
  reading before the rest.

## How the blocking surface works

Worth knowing if you are choosing between the two, and skippable otherwise.

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

| async                                   | blocking                                                                                              |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `async with connect(...) as sftp`       | `with connect(...) as sftp`                                                                           |
| `await sftp.get(...)`                   | `sftp.get(...)`, returning the same `DownloadResult`                                                  |
| `async for entry in sftp.walk(...)`     | `for entry in sftp.walk(...)`, an ordinary iterator                                                   |
| `async with sftp.scandir(p) as entries` | `with sftp.scandir(p) as entries`, still a context manager, because it still holds a directory handle |
| `async with sftp.open_file(p) as f`     | `with sftp.open_file(p) as f`, the same, for the same reason: it holds a file handle                  |
| `except NoSuchFileError`                | `except NoSuchFileError`, arriving flat rather than in an `ExceptionGroup`                            |
| `SFTPPath(p, session=sftp)`             | `SyncSFTPPath(p, session=sftp)`, whose `iterdir` / `glob` / `rglob` are ordinary iterators            |

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

with start_blocking_portal(backend="trio") as portal:  # or asyncio, the default
    gantry = BoundPortal(portal)
    with gantry.connect("a.example.com") as one, gantry.connect("b.example.com") as two:
        one.get("/data.csv", "a.csv")
        two.get("/data.csv", "b.csv")
```

**For a list of files, there is no pool to stand up.** `get_many` and `put_many` overlap the
transfers on the portal's own loop, derive each destination name for you and hand the results
back in the order you asked for them:

```python
with connect("example.com", user="bob") as sftp:
    results = sftp.get_many(paths, "downloads/", concurrency=8)
```

That is the shape worth reaching for first, and it is a bigger difference here than on the
async surface — see [A list of files](concurrency.md#a-list-of-files-get_many-and-put_many).

**Anything else is spelled with threads.** A blocking caller has no task group, and a
`SyncSession` is safe to share across one. Each call posts to the same loop, so the fan-out
lands on the one reader that already routes replies by request id:

```python
from concurrent.futures import ThreadPoolExecutor

from gantry_sftp import check_listed_name, join_remote, local_child

with connect("example.com", user="bob") as sftp, ThreadPoolExecutor(8) as pool:
    pool.map(
        lambda name: sftp.get(
            join_remote(b"/incoming", check_listed_name(name, directory=b"/incoming")),
            local_child(local, name),
        ),
        names,
    )
```

Both joins, always, if `names` came from the server — a name that cleared the remote check has
not cleared the local one, and `local / name` is the spelling this project has had to remove
from its own documentation more than once.

Four things to know about the thread boundary:

- **A `progress` callback runs on the portal's thread**, which is the one thread that cannot
  wait on the portal. Calling back into the session from inside a callback is refused by anyio
  with `RuntimeError: This method cannot be called from the event loop thread`, loudly rather
  than as a deadlock. Count bytes and return.
- **The session is shareable across threads; one `walk` or `glob` is not.** They come back as
  ordinary Python generators, and a generator driven from two threads at once raises
  `ValueError: generator already executing`. Iterate one per thread, or list it first.
- **Using a session after its block has ended** raises `StateError` naming the block, rather
  than anyio's complaint about a portal you never asked for. **So do the objects it hands
  out** — a file from `open_file()` or a scan from `scandir()` that outlives the session says
  the same thing when you enter it, read from it or advance it. Leaving one's `with` block is
  the exception and is quiet: the handle went with the connection, so there is nothing to
  release, and raising on the way out would replace whatever error you were already handling.
- **`with_reconnect` runs your function on a third thread.** It has to: it hands you a session,
  and the portal's own thread is the one thread that cannot use one. That thread is borrowed
  from anyio's pool rather than started per call, and an exception you raise there comes back
  as itself. Its `connect` argument is the **async** transport recipe, because a transport is
  opened per attempt on the portal's loop — passing the blocking twin of the same name is
  refused with a `TypeError` that says so. See
  [Reconnecting and timeouts](reliability.md#the-blocking-form).

Runnable: `examples/blocking.py`.

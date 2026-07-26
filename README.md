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

## Status

**Pre-alpha, and honest about it.** Nothing is published and the API will change. What
exists today:

- a complete filexfer v3 codec: all 27 packet types plus ATTRS, encoding and decoding,
  checked against `draft-ietf-secsh-filexfer-02`, OpenSSH's `sftp.h`, and frames captured
  from a real server
- wire primitives and an incremental frame splitter — no frame payload is ever copied
- the client state machine: handshake, deterministic request-id allocation, and
  request/response correlation that survives out-of-order replies
- transports: `ssh -s sftp` as a subprocess, and `sftp-server` on a bare pipe
- a session with `stat`, `lstat`, `realpath`, `open`/`close`, `remove`, `rename`,
  `posix_rename`, `fsync`, `supports()`, `listdir()`, and pipelined `get()` / `put()`, with
  typed errors, timeouts on every wait, and a progress callback
- **atomic publish**: `put()` stages, flushes and renames, and tells you which mechanism it
  actually used
- a test lane that drives the genuine OpenSSH `sftp-server` over a pipe — no ssh, no keys,
  no network, no containers — and a `live-tests/` lane that runs a real `sshd`
- runnable `examples/`, each of which works with no arguments and is executed by the suite

The thesis is proven end to end: SFTP runs over a real SSH connection, with key exchange,
host-key verification and public-key authentication all done by OpenSSH, and no
cryptography in this package. It moves files:

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
        print(result.mechanism, result.atomic)   # posix-rename True

anyio.run(main)
```

Not yet: recursive operations, resume, retry, the fsspec adapter, `SFTPPath`, or the
generated sync API. The names in DESIGN.md's §8 sketch (`connect()`, `put_many()`) do not
exist yet — `open_session` is the current spelling.

## Listing

```python
for entry in await sftp.listdir("/incoming"):
    print(entry.kind, entry.size, entry.name)   # directory 4096 archive
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
many entries a batch holds (OpenSSH: 100).

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

result.transferred   # 41310
result.mechanism     # posix-rename | rename | remove-rename | in-place
result.durability    # fsynced | unavailable | skipped
result.atomic        # True — no consumer could observe a partial destination
result.durable       # True — the bytes reached stable storage before the rename
result.staged_at     # b'/incoming/.report.csv.20b59c88.part'
```

| Mechanism       | When                                                      | Atomic                          |
| --------------- | --------------------------------------------------------- | ------------------------------- |
| `posix-rename`  | The server implements `posix-rename@openssh.com`          | Yes, even over an existing file |
| `rename`        | No extension, and the destination did not exist           | Yes — v3 `RENAME` cannot overwrite, so success means it appeared whole |
| `remove-rename` | No extension, and the destination existed                 | **No** — a window with no file  |
| `in-place`      | You passed `atomic=False`                                 | **No** — the classic behaviour  |

`posix-rename` is attempted whether or not the server advertised it, because endpoints
under-advertise and the cost of asking is one round trip — `OP_UNSUPPORTED` is a definitive
answer and is remembered for the session. `require_atomic` is the exception: it is answered
from what the server advertised, because a demand for a guarantee should not be answered by an
experiment that costs a nine-gigabyte upload first.

Refusing to downgrade is one flag, and it fails before moving any bytes where it can:

```python
await sftp.put(src, dst, require_atomic=True)   # CapabilityError rather than remove-rename
await sftp.put(src, dst, require_fsync=True)    # CapabilityError rather than no durability
await sftp.put(src, dst, atomic=False)          # in place, for a write-only drop directory
await sftp.put(src, dst, staging_name=b"x.tmp") # servers that forbid dot-files, or mandate a
                                                # staging directory (same filesystem, or the
                                                # rename fails)
```

Three limits stated rather than implied. `fsync@openssh.com` flushes the *file*; SFTP has no
way to flush a directory entry, so the rename that publishes it is never itself durable.
Staging needs the right to create *and* rename a second name in the destination directory — a
drop directory that only permits creation needs `atomic=False`. And a failed publish removes
the staging file, with one deliberate exception: if the `remove-rename` fallback removed the
destination and the rename after it failed, the staging file is the only copy of your data, so
it is left where it is and the error says where that is.

`examples/atomic_publish.py` runs all of this against a real server with no arguments.

One thing worth knowing if you are reading the codec: **`SYMLINK`'s arguments are in the
opposite order to the specification.** draft-02 says `linkpath, targetpath`; OpenSSH sends
and expects `targetpath, linkpath`. We follow OpenSSH, because OpenSSH is what is deployed.
Both orders are run against a live server in the test suite so the claim stays measured
rather than remembered.

`_plans/DESIGN.md` is canonical for intent and `_plans/progress.md` for what is actually
built. Neither is committed.

## Why it should be faster

Sustained SFTP throughput is bounded by bytes in flight, not by cryptography:

```
throughput ~= (outstanding_requests * request_size) / RTT
```

OpenSSH's own `sftp(1)` defaults to 64 outstanding requests of 32768 bytes — exactly 2 MiB
in flight, which caps a 100 ms transatlantic link at roughly 21 MB/s regardless of how fast
the machine is. That is a scheduling bug, not a crypto bug, and it is invisible on
localhost, which is why it went unnoticed for two decades.

No throughput claim appears in this README until the benchmark suite produces one, with its
link profile and server named. An unattributed "10x faster than paramiko" is marketing.

## Requirements

- Python 3.13+
- An `ssh` binary on `PATH` (`openssh-client`). Windows ships one at
  `%SystemRoot%\System32\OpenSSH\ssh.exe`; slim Docker images frequently do not.
- `openssh-server` — **only** to run the real-server test lane, never at runtime.

## Development

```bash
export UV_CACHE_DIR=/workspace/.uv-cache   # the default cache is root-owned here
uv sync
.venv/bin/pre-commit install               # sets up pre-commit and pre-push
```

The gates, all of which must pass before anything lands:

```bash
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
.venv/bin/mypy                      # --strict, scoped to src
.venv/bin/ty check                  # second type gate, same scope
.venv/bin/complexipy src            # cognitive complexity, ceiling 15
.venv/bin/python -m pytest          # unit + real-server lane
```

Type checking is deliberately two-tool: mypy is stricter and catches gaps ty misses. A
finding gets fixed at the source, never silenced with an ignore.

`tests/` and `examples/` need no network and are what the gates above run — every example is
executed as a subprocess, because an example that has drifted out of sync with the library is
a confident, wrong answer somebody will copy. `live-tests/` starts a real `sshd` on localhost
and will later need containers and `tc netem` link shaping; `benchmarks/` needs a shaped link.
Both are excluded from the default run and skip with a reason rather than failing when their
dependencies are absent:

```bash
.venv/bin/python -m pytest live-tests/       # needs openssh-server
```

Every async test runs on both anyio backends, asyncio and trio. That is deliberate: the
reason for depending on anyio at all is that it costs nothing and buys trio support, and a
codebase that has only ever run on asyncio is one accidental `asyncio.Queue` away from not
having it.

## License

Apache-2.0.

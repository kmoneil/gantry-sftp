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
  from a real server
- wire primitives and an incremental frame splitter — no frame payload is ever copied
- the client state machine: handshake, deterministic request-id allocation, and
  request/response correlation that survives out-of-order replies
- transports: `ssh -s sftp` as a subprocess, and `sftp-server` on a bare pipe
- a session with `stat`, `lstat`, `realpath`, `open`/`close`, `mkdir`, `rmdir`, `remove`,
  `rename`, `posix_rename`, `fsync`, `supports()`, `listdir()`, and pipelined `get()` /
  `put()`, with typed errors, timeouts on every wait, and a progress callback
- **recursive transfer both ways**: `walk()` and `get_tree()`, with the zip-slip defence that
  makes a hostile server's filenames safe to write, plus `put_tree()` and `rmtree()` — trees
  go up as well as down, and come back off again
- **atomic publish**: `put()` stages, flushes and renames, and tells you which mechanism it
  actually used
- a test lane that drives the genuine OpenSSH `sftp-server` over a pipe — no ssh, no keys,
  no network, no containers — and a `live-tests/` lane that runs a real `sshd`, including a
  `tc netem`-shaped link where the pipelining claims are actually measured
- a `benchmarks/` lane that runs this library, paramiko and asyncssh against the same server
  over that shaped link, reporting wall clock **and** CPU — the source of truth for every
  performance number here, including the two that do not flatter us
- runnable `examples/`, each of which works with no arguments and is executed by the suite

The thesis is proven end to end: SFTP runs over a real SSH connection, with key exchange,
host-key verification and public-key authentication all done by OpenSSH, and no cryptography in
this package. It is also now measured against the alternatives — on a shaped link it downloads
1.6–2.6× faster than paramiko and 1.1–1.4× faster than asyncssh, it is *slower* to connect, and
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
        print(result.mechanism, result.atomic)   # posix-rename True

anyio.run(main)
```

Not yet: `glob`, resume, retry, the fsspec adapter, `SFTPPath`, or the generated sync API. The
names in DESIGN.md's §8 sketch (`connect()`, `put_many()`) do not exist yet — `open_session` is
the current spelling.

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

## Walking and recursive download

```python
result = await sftp.get_tree("/incoming", "downloads/")
result.files, result.directories, result.transferred   # 3 2 2520
result.complete                                        # False -- read result.skipped
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

## When the connection fails

```python
from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError

try:
    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        ...
except AuthenticationError as e:
    ...   # credentials refused
except HostKeyError as e:
    ...   # the server's identity was not accepted -- do not retry blindly
except ConnectError as e:
    print(e.stderr)   # OpenSSH's own words, verbatim
```

paramiko answers this question with `Error reading SSH protocol banner`. OpenSSH knew exactly
what went wrong and said so; `ConnectError.stderr` carries that text untouched, and the two
questions people actually ask — "was that my key?" and "has the host changed?" — are answered
by `except` rather than by string matching in your own code.

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

`examples/connect_errors.py` runs this with no arguments.

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
size transfers the same file **14.7× faster at 5 ms RTT, 18.5× at 50 ms and 10.6× at
200 ms** — and on an unshaped link the same comparison is noise. At depth 1 the elapsed time
*is* one round trip per request, within 3%. The lane is `live-tests/test_netem_pipelining.py`
and it re-measures on every run.

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
- **Past 2 MiB the lever is concurrency, not depth.** One window per channel, so moving
  several files at once is a throughput feature and not only a small-file one. Raising depth
  beyond the window buys memory consumption and nothing else.
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
| download 16 MiB | **1.6–2.6× faster** | 1.1–1.4× faster |
| upload 16 MiB | 1.2–1.5× faster | up to 1.2×, level on the rate-limited profile |
| 100 × 8 KiB sequential | ~1.5× faster | **a tie** |
| connect and close | **1.2–1.4× slower** | **1.2–2.1× slower** |
| CPU per MiB, download | about the same | **1.2–1.6× worse** |
| CPU per MiB, upload | 1.1–1.6× better | mixed, 0.7–1.4× |

Ratios across 5, 50 and 200 ms RTT plus a 100 Mbit/s rate-limited profile, taken as the
**union of two full runs** rather than the best one. That widening is not padding: the first
run put the download range at 1.9–2.6× and the second at 1.6–2.3×, because paramiko's 200 ms
row is genuinely noisy (its spread column reached 2.06 while ours stayed near 1.1). A range
that only one run reproduces is a number with an expiry date on it. Absolute figures, the exact
host and the full caveats are in the report the suite writes; re-run it with
`pytest benchmarks/ -s` and it re-derives all of them.

Two of those rows are not the ones a pitch would choose, and they are the interesting ones.

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
a confident, wrong answer somebody will copy. `live-tests/` starts a real `sshd` on localhost;
`benchmarks/` needs that plus a shaped link and the comparison libraries. Both are excluded
from the default run and skip with a reason rather than failing when their dependencies are
absent:

```bash
.venv/bin/python -m pytest live-tests/       # needs openssh-server
uv sync --group bench                        # paramiko and asyncssh
.venv/bin/python -m pytest benchmarks/ -s    # needs the above plus tc netem
```

The comparison libraries are a separate dependency group and are deliberately not installed by
default. They pull in `cryptography`, `pynacl` and `bcrypt` — Python cryptography is precisely
what this project exists not to need, and a `uv sync` that installed it would make that claim
harder to check than it should be.

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
.venv/bin/mutmut run          # ~4 minutes; scoped to codec/ by pyproject.toml
.venv/bin/mutmut browse       # inspect survivors
.venv/bin/mutmut results      # non-interactive list
```

It is a lane, not a pre-commit gate — it takes minutes, not seconds. A surviving mutant in
`codec/` is a missing test, not a curiosity, and the survivors that are genuinely
*equivalent* (no test can distinguish them) are listed with their reasons in
`_plans/deferred.md` rather than suppressed, so a future run has a baseline to diff against
instead of a triage to redo.

`mutmut` mutates only functions the tests call, and it mutates the copy of the library it
writes into `mutants/`. Test selection is `tests/` alone: `examples/` runs each example as a
subprocess, which imports the *installed* library rather than the mutated copy, so those
tests cannot kill a mutant and would only add wall-clock.

## License

Apache-2.0.

# gantry-sftp

A modern Python SFTP library that **does not implement SSH at all**.

OpenSSH already exists and is already installed. `gantry-sftp` runs it as a subprocess, which
hands back a plaintext, framed SFTP byte stream, so there is **zero cryptography in this
package**, and key exchange, host-key verification, `ssh_config` and `ProxyJump` are all things
you already have rather than things this library reimplements.

What is left is the part that is actually about SFTP: a protocol codec, a request scheduler, and
an ergonomics layer.

```console
pip install gantry-sftp
```

[![PyPI](https://img.shields.io/pypi/v/gantry-sftp)](https://pypi.org/project/gantry-sftp/)
[![Python](https://img.shields.io/pypi/pyversions/gantry-sftp)](https://pypi.org/project/gantry-sftp/)
[![License](https://img.shields.io/pypi/l/gantry-sftp)](LICENSE)

```python
from gantry_sftp.sync import connect

with connect("example.com", user="bob") as sftp:
    sftp.get("/incoming/data.parquet", "data.parquet")

    result = sftp.put("report.csv", "/outgoing/report.csv")
    print(result.mechanism, result.atomic)   # posix-rename True
```

That upload is **atomic by default**: the bytes go to a hidden staging file, are flushed, and are
renamed over the destination, so a consumer polling that directory sees the old file or the new
one and never a half-written one. `result` says which mechanism it actually got, because every
step of it is an optional server extension.

**No event loop is needed for any of that.** The core is async, written against `anyio` so it runs
on asyncio *and* trio, and `gantry_sftp.sync` is a blocking facade over the same code rather than
a second implementation of it. If you are writing a script, stay here. If you are writing a
service, drop the `.sync` and add `async` / `await`:

```python
import anyio
from gantry_sftp import connect

async def main():
    async with connect("example.com", user="bob") as sftp:
        await sftp.get("/incoming/data.parquet", "data.parquet")

anyio.run(main)
```

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
  independent of the file's size: a 40 GB download costs what a 40 MB one does. Lower `depth`
  for a smaller container. If you are on Cloud Run, Lambda or Fly, note also that **`/tmp` is
  memory there**, so a staged download counts against your limit twice. See
  [what a transfer costs in memory](docs/tuning.md#what-a-transfer-costs-in-memory), which gives
  the expression and the way to process a file bigger than the container without staging it.

**Your machine already satisfies this and your container probably does not**, which is the
failure worth pre-empting: it passes locally, then fails on first deploy. Check the image you
actually deploy rather than trusting a table. The library will check itself, and needs no
server to do it:

```console
$ python -m gantry_sftp doctor
gantry-sftp doctor

local
  library                 0.1.0 (filexfer v3)
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
and no way to install one, so the answer is a different base image. A Lambda _container_
image can install `openssh-client` and works fine. This is stated plainly rather than
hedged, because finding it out after adopting a library is worse than finding it out now.

If `ssh` is missing, you get a `ConnectError` whose `hint` says all of the above. See
[when the connection fails](docs/connecting.md#when-the-connection-fails).

## Documentation

Start with **[Getting started](docs/getting-started.md)**. After that the guides are shaped by
task rather than by module:

| Guide | What is in it |
| --- | --- |
| [Getting started](docs/getting-started.md) | Install, the `ssh` prerequisite, your first transfer, and the same code with and without an event loop |
| [Transferring files](docs/transfers.md) | `get` / `put`, atomic publish, resume, content verification, timestamps, permissions, whole trees, and the incremental-ingest loop |
| [Paths, predicates and attributes](docs/paths.md) | `SFTPPath`, the bytes-versus-`Path` rule, `exists` / `is_dir` / `is_file`, a working directory, symlinks and `chmod` |
| [Listing and matching](docs/listing-and-matching.md) | `listdir` / `scandir`, streaming a directory you did not size, and the `glob` dialect |
| [Concurrency and byte ranges](docs/concurrency.md) | Many transfers over one connection, `concurrency=`, `open_file`, and reading part of a file |
| [Connecting and authenticating](docs/connecting.md) | Keys, agents, `ssh_config`, passwords, restricting where a connection may go, which `ssh_config` settings this library overrides, and what a failure tells you |
| [Reconnecting and timeouts](docs/reliability.md) | `with_reconnect`, deadlines on every wait, and stopping a transfer cleanly |
| [Seeing what it is doing](docs/observability.md) | Structured logs, session counters, the frame dump, credential redaction, and `doctor` |
| [fsspec, pandas and dask](docs/integrations.md) | `pd.read_parquet("gantry-sftp://…")`, and the two things to know before deploying it |
| [Tunables, and what things cost](docs/tuning.md) | Every knob and its default, round trips per operation, memory per transfer |
| [Why this exists](docs/architecture.md) | The design argument, the failures it prevents, and where this library is behind |
| [Development](docs/development.md) | The suite, the lanes, and what each one exists to catch |
| [The security model](docs/security.md) | The trust boundary, what is deliberately not defended, and where each control is proved |

**[`examples/`](examples/README.md) is the other half of the documentation**, and it is executed
rather than described: one runnable example per user-facing feature, each of which works with **no
arguments** by spawning a real `sftp-server` on a pipe, and every one of them is run by the test
suite. If you would rather read code than prose, start there.

## What it does

- **Transfers that tell you what happened.** `get` and `put` return a result object rather than a
  byte count: which checks ran, which could not, what a resume adopted, whether the timestamps
  survived.
- **Atomic publish by default**, with the mechanism named in the result, because every step of it
  is an optional extension and a downgrade you were not told about is worse than a refusal.
- **Resume in both directions**, opt-in, and labelled with what it actually proves rather than
  with a claim that something was proven.
- **Content verification** on a ladder: server-side hashing where it exists, a re-read where it
  does not, and a size check that is always available. It reports `unavailable` rather than
  success when a rung could not run.
- **A zip-slip defence on every recursive download.** Server-supplied names are attacker-supplied
  names, and every one is validated before it reaches your filesystem.
- **Bytes end to end**, so a filename that is not valid UTF-8 is an ordinary filename rather than
  a `UnicodeDecodeError`.
- **Typed errors carrying state, not strings**. A `ConnectError` holds OpenSSH's own stderr
  verbatim, a `TransferError` holds both paths and the offset it stopped at.
- **Timeouts on every wait**, including the send, so a transfer cannot hang with nothing to
  escape it.
- **One connection, many transfers**, multiplexed over a single `ssh` child.
- **A `pathlib`-shaped path object**, an **fsspec filesystem**, and a **blocking facade**: three
  ways in besides the async session.

Full detail is in the guides above. `python -m gantry_sftp doctor` reports what your machine can
actually do; **[`benchmarks/README.md`](benchmarks/README.md)** is the lane that measures
performance, and it writes its figures to a report rather than to this file.

## Status

**0.1.0, the first public release, and beta rather than alpha: the feature set is complete and
the API can still change.** While the major version is `0` a breaking change lands in the minor
version. Two already have, deliberately, in the releases leading to this one.

The protocol layer is complete: all 27 filexfer v3 packet types, encoded and decoded, each with a
byte-level fixture asserted in **both** directions, checked against `draft-ietf-secsh-filexfer-02`
and OpenSSH's own source. The thesis is proven end to end against a real `sshd` over a
`tc netem`-shaped link, and against three different server implementations.

[`CHANGELOG.md`](CHANGELOG.md) has what is in this release **and what its known limitations are**:
Windows transfers refuse by design, `ssh` is a system dependency, and two more. Where this library
is behind is also in [Why this exists](docs/architecture.md#where-this-library-is-behind). Both are
written down rather than left for you to find.

## How this was built

**This library was built with AI assistance.** Most of the code and prose here was written by a
language model, directed, reviewed and accepted by a human author who is responsible for the
result. It is stated because you would reasonably want to know, not because it is an excuse or a
selling point.

**Humans and models produce slop in roughly equal measure.** Neither one is the reason software is
good or bad. What decides that is the verification: what is actually tested, what is measured
against a real system instead of recalled, and which claims something would catch if they stopped
being true. A careful human and a careful model with the same test suite land in the same place,
and so do a careless one of each.

So the rules for this repository are aimed at that, and they are enforced rather than professed.
The specific failure mode worth designing against is **confident plausibility**: a packet layout
recalled from memory looks exactly like one read off a wire, and a fallback described in a
docstring reads exactly like a fallback somebody tested.

- **Byte layouts are validated against the source, never from memory:**
  `draft-ietf-secsh-filexfer-02` and OpenSSH's own `PROTOCOL` and `sftp.h`. Every one of the 27
  packet types carries a byte-level fixture asserted on encode *and* decode, because a codec
  tested only against its own encoder is tested against nothing.
- **Claims about servers are measured, not remembered.** Extension behaviour, status codes, and
  the argument order of `SYMLINK` (which the reference server reverses relative to the draft) were
  each settled by asking a real server and keeping the answer. The suite drives the genuine
  OpenSSH `sftp-server`, and a matrix lane drives three different implementations, because a fake
  only ever confirms what its author already believed.
- **A prevention claim without a test is a rumour.** The table in
  [Why this exists](docs/architecture.md#the-failures-this-prevents) names the test for each row.
  Documentation facts are pinned the same way: the memory figure is derived from the shipped
  constants rather than typed, the `ssh` hint is quoted from the code that produces it, and every
  link in these documents is checked to resolve.
- **Mutation testing on the codec**, because a passing suite proves the tests ran, not that they
  would have noticed.

None of that makes the code correct. It makes the *claims* checkable, which is the part you cannot
verify by reading a diff, and it is the standard this project should be held to no matter who or
what typed it.

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

The suite runs with no network, no containers and no keys. It drives the genuine OpenSSH
`sftp-server` over a pipe:

```console
uv sync --all-extras
.venv/bin/python -m pytest
```

[Development](docs/development.md) covers the rest: the CI matrix, the controlled `ssh`
environment every security assertion depends on, and the four lanes that run longer than a commit
hook: leak detection, `tc netem` link shaping, benchmarks, and mutation testing.

## Security

**Found something? Please report it privately** — [open a security
advisory](https://github.com/kmoneil/gantry-sftp/security/advisories/new), or email
kevin@oneil.xyz if you would rather not use GitHub.

[`SECURITY.md`](SECURITY.md) has the reporting scope and
[the security model](docs/security.md) has the trust boundary in full. The scope is worth
reading before you start: this
library contains no cryptography and does not implement SSH, so a finding about ciphers or
host-key algorithms belongs to OpenSSH rather than here. What *is* ours is everything a hostile
server can send us, how we build the `ssh` argument vector, and where a credential can end up.

## License

Apache-2.0.

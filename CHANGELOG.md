# Changelog

Notable changes, newest first. This project follows [semantic versioning](https://semver.org),
and while the major version is `0` the minor version is where a breaking change lands.

## Unreleased

**Nothing has been released yet.** No `v*` tag exists, `git describe --tags` returns a bare sha,
and the distribution is not on PyPI — so there is no version out there to diff against and every
entry below is part of what the first release will say. The heading gets a number and a date when
a tag is cut, not before: a dated heading for a release nobody can install is the kind of claim
this project asks its own docs not to make.

### What it is

A Python SFTP library that does not implement SSH. OpenSSH is spawned as a subprocess and hands
back a plaintext, framed SFTP byte stream, so there is **no cryptography in this package and no
cryptographic dependency**. `pip install gantry-sftp` pulls `anyio` and nothing else. What ships
is a protocol codec, a request scheduler and an ergonomics layer.

### Ways in

- `gantry_sftp.connect()`: async session, one call.
- `gantry_sftp.sync.connect()`: the same API with no event loop, as a facade over the async code
  rather than a second implementation of it.
- `gantry_sftp.SFTPPath`: a `pathlib`-shaped remote path, made of bytes because remote names are.
- `gantry_sftp.fsspec`: an fsspec filesystem, so `pd.read_parquet("gantry-sftp://…")` works. It
  **registers nothing on import**; you choose the protocol name in writing.

### What it does

- **Atomic publish by default.** `put()` stages, flushes and renames, and the result names which
  of four mechanisms actually ran, because every step is an optional server extension and most
  enterprise endpoints advertise none of them.
- **Transfers report what happened.** `get()` and `put()` return a result object: which checks
  ran, which could not, what a resume adopted, whether timestamps survived.
- **Content verification on a ladder**: server-side hashing where it exists, a re-read where it
  does not, a size check that is always available. It reports `unavailable` rather than success
  when a rung could not run.
- **Resume in both directions**, opt-in, labelled with what it actually proves.
- **A zip-slip defence** on every recursive download: server-supplied names are attacker-supplied
  names, validated before they reach your filesystem, with the finished path re-checked against
  the destination after symlinks resolve.
- **A password never reaches argv, a file, a log record, or a frame-locals dump.** It travels in
  the `ssh` child's environment through a throwaway `SSH_ASKPASS` helper, and it is held in
  `gantry_sftp.transport.Secret`, a `str` whose `repr()` is `'<redacted>'` — which is the form
  Sentry, `pytest --showlocals`, `rich` and IPython all render a captured local with. Every entry
  point taking a `password` wraps its own binding, and `tests/test_askpass.py` derives that list
  from the source so a new one cannot be added without deciding.
- **Bytes end to end**, so a filename that is not valid UTF-8 is an ordinary filename.
- **Typed errors carrying state**. `ConnectError` holds OpenSSH's stderr verbatim, `TransferError`
  holds both paths and the offset it stopped at.
- **Timeouts on every wait**, including the send and the wait for the send lock.
- **One connection, many transfers**, multiplexed over a single `ssh` child.
- **Pipelining by default**, with the depth, request timeout and idle timeout as tunables.
- `walk` / `get_tree` / `put_tree` / `rmtree`, `glob` in `sftp(1)`'s own dialect, `listdir` /
  `scandir`, path predicates, a working directory, byte ranges and a file object, permissions and
  timestamps preserved on request, reconnect-and-resume, server identification, and
  `python -m gantry_sftp doctor`.

### Known limitations, stated rather than left to be discovered

- **Transfers refuse on Windows, by design.** The data path uses `os.pread` / `os.pwrite`, which
  is a POSIX constraint rather than an unfinished port; `get` / `put` / `get_tree` / `put_tree`
  raise `NotImplementedError` before anything is sent. Everything that only talks to the far end
  works there, including the byte-range surface.
- **`ssh` is a system dependency.** `pip` will not install it. `python -m gantry_sftp doctor`
  exits `3` when it is missing, so a container build can fail instead of a first transfer.
  There are runtimes where this cannot work at all: `scratch`, distroless, and managed runtimes
  with no package manager.
- **A transient `FAILURE` mid-transfer ends the transfer.** OpenSSH answers five distinct
  conditions with the constant word `Failure`, so there is nothing to classify on; this improves
  only for servers that surface `strerror`.
- **`check-file` reaches one server of the three tested.** Rung 1 of the verification ladder is
  real and absent from nearly every endpoint. Rung 3 is available everywhere.
- **`ls()` through the fsspec adapter holds the whole directory**, because fsspec's contract is
  that it returns a list. A directory the server can grow without bound is unbounded allocation
  driven by the peer; `Session.scandir` is the streaming form, and nothing is capped because a
  silent cap breaks the legitimate large directory *and* reports success.
- **Connecting is slower** than a library that implements SSH in-process, because spawning `ssh`
  costs a fork, an exec and OpenSSH's own config parsing. For connection-heavy work,
  `ControlMaster` is the fix, and it has to be asked for: this library ships `ControlMaster=no`,
  so it uses a master you already have and will not start one. See
  [Connection reuse](docs/connecting.md#connection-reuse-and-why-the-master-is-not-ours-to-start).
- **The benchmark lane reports and does not gate**, apart from two scenarios that assert a shape
  rather than a ratio. No published figure has a regression test behind it, which is why no
  committed file carries one.

### Reporting a vulnerability

[`SECURITY.md`](SECURITY.md) carries the disclosure policy: a private advisory channel, an email
fallback for reporters who will not use GitHub, the supported-version window, and the scope. The
scope is the part worth reading before reporting — this package contains no cryptography and does
not implement SSH, so a finding about ciphers, key exchange or host-key algorithms belongs to
OpenSSH. What is in scope is everything a hostile server can send us, how the `ssh` argument
vector is built, and where a credential can end up.

### Requirements

Python 3.13+, an `ssh` binary on `PATH`, and a POSIX host for transfers.

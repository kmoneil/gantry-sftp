# Changelog

Notable changes, newest first. This project follows [semantic versioning](https://semver.org),
and while the major version is `0` the minor version is where a breaking change lands.

## Unreleased

### Changed

- **No SBOM ships, and `docs/security.md` now says so with the reasoning.** OWASP 2025 moved
  supply-chain failures to A03 and names an SBOM as prevention, so the absence is recorded as a
  decision rather than left to be rediscovered. The declared runtime dependency is `anyio` alone
  and installs as three packages, so an inventory restates one `pip install` in a second format
  and becomes a second thing to keep current — and for the question that rescope is about, a
  signed PEP 740 attestation is a stronger answer than an unsigned self-report. The release
  workflow now asks for that attestation explicitly rather than inheriting a default the page's
  argument depends on. **If a procurement process needs an SBOM regardless, open an issue** —
  that is the evidence that would change the answer.
- **The maturity claim moves from alpha to beta**, in the three places that state it: the
  `Development Status` classifier, README's Status section and `SECURITY.md`'s support window.
  PyPI's rungs are about feature completeness rather than release count — the protocol layer
  covers all 27 filexfer v3 packet types, the ergonomics and fsspec surfaces are built, and what
  is left open is scope decided against rather than work half-done. Not `5 - Production/Stable`:
  that claims a settled API, and a `0` major version says the opposite.

### Fixed

- **`get_tree` no longer abandons the rest of a tree when the local filesystem refuses one
  name.** A remote name is bytes; APFS and HFS+ require valid UTF-8 and reject anything else. One
  such name used to raise a bare `OSError` out of the walk, so every file after it in walk order
  was never fetched and the caller got an errno with no remote path. The entry is now recorded in
  `result.skipped` with the new `SkipReason.DESTINATION_REFUSED_THE_NAME` and the walk continues,
  which is what the sibling refusal for colliding names already did.
- **`get` of such a name raises `TransferError` instead of a bare `OSError`.** It carries the
  remote path and the local path, so `except SFTPError` catches it and the message says which
  file and why. Both changes are narrow by errno: a full disk or a denied directory still aborts,
  because reporting either as "bad name" would make a real failure look like a quirk of one entry.

## 0.1.0 — 2026-08-05

**The first public release**, so there is nothing to diff against and everything below is new.
Read [Known limitations](#known-limitations-stated-rather-than-left-to-be-discovered) before the
feature list: `ssh` is a system dependency this package cannot install for you, and transfers
refuse on Windows by design.

This heading carried `## Unreleased` until the tag was cut, which is what
`tests/test_packaging.py` and `release.yml` between them insist on — a dated heading for a
release nobody can install is the kind of claim this project asks its own docs not to make, and
tagging is the only moment that stops being true.

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

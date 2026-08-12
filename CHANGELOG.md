# Changelog

Notable changes, newest first. This project follows [semantic versioning](https://semver.org),
and while the major version is `0` the minor version is where a breaking change lands.

## Unreleased

**`Unreleased` rather than a version heading, and that distinction is enforced rather than
observed.** `tests/test_packaging.py` accepts this heading *or* one naming the packaged version;
`release.yml` refuses this one on a tag. Writing a version heading before the tag exists is how a
changelog comes to describe a release that does not exist.

### Added

- **An upload survives the process dying, not just the connection** (D-166). `UploadJournal` is a
  durable, local, append-only note of which staging file an in-flight atomic upload chose, passed
  as `Publish(journal=...)`. New public names: `UploadJournal`, `JournalEntry`, `SourceIdentity`,
  `JOURNAL_VERSION`, a `journal` field on `Publish`, and `Session.discard_staged()` with its
  blocking twin.

  **What it unblocks is one specific refusal.** `put(resume=True)` with the default `atomic=True`
  raised, because the staging name carries fresh randomness per call and a killed run leaves a
  file nothing can find. Deriving the name from the target was rejected then and is still
  rejected: a predictable staging name is what the randomness is *for*, and two publishers
  resuming into one would interleave into a single file. **The journal makes this run's own name
  recoverable without making any name predictable** — it is local and private to whoever wrote it,
  so a second publisher elsewhere has a different journal and a different token. The old spelling
  still raises when neither a journal nor a `staging_name` is given.

  **A whole tree resumes on the same journal** (D-172):
  `put_tree(resume=True, publish=Publish(journal=...))`. Each file records its own random staging
  name under its own target, so a run killed partway through continues the file that was in
  flight. Without a journal that call still requires `publish=Publish(atomic=False)`, and a
  `staging_name` is still refused for a tree whatever else is passed — one name cannot serve many
  files, which was never the clause the journal answered.

  **Downloads were already fine and get nothing.** Measured across two separate interpreter
  processes before any of this was written: a download's partial is a file on your own disk, so
  its length is a fact rather than a report. There is no download journal and no plan for one.

  **It records a name and never an offset**, which is what keeps it from being a corruption
  engine: after a crash a process knows what it *intended*, not what the far end accepted. Where
  to resume from is still read off the server and `resume_check` still labels how well it was
  proven. A journal that is stale, truncated or hostile costs a wasted round trip and a full
  re-upload, never a wrong file. The source's size and mtime are recorded so a file edited between
  the crash and the retry is refused rather than spliced.

  Each record is appended and `fsync`ed **before** the request it describes, because an unanswered
  request must be assumed to have been performed. Append-only rather than a rewritten document,
  because `put_tree(concurrency=N)` writes to one journal from N workers.

  `discard_staged()` removes the staging files a killed run left — which nothing could do before,
  and which is the half a user notices first. It removes only what that journal recorded, never
  what a glob for `.*.part` would find. `docs/reliability.md` and `examples/crash_resume.py`, which
  kills a real upload with a real `SIGKILL` and finishes it from a second process.
- **A compatibility report, for the endpoints nobody here can reach.** `gantry_sftp.compatibility`
  runs a battery against a live server and returns, per fact, a verdict and **the exchange that
  produced it**. Reached as `python -m gantry_sftp doctor <host>`, which now runs the read-only
  half by default; `--no-probes` turns it off and `--probe-writes DIR` adds the questions that can
  only be answered by writing. New public names: `CompatibilityReport`, `Finding`, `Verdict`,
  `ProbeLimit`, `compatibility_report`, `read_only_probes`, `write_probes`, `restates_the_code`,
  `CODE_IN_PROSE`, `PROBE_PREFIX`, `PROBE_MODE`, `PROBE_TIMESTAMP`, plus a `compatibility` field on
  `ServerDiagnosis` and `probes` / `write_directory` arguments on `server_diagnosis`.

  **The reason it exists is arithmetic, not modesty.** MOVEit, GoAnywhere, Cleo and Sterling belong
  to somebody's employer and sit behind a VPN, so no maintainer can start one and the endpoints
  this library is *for* are the ones it can never measure. The evidence has to be producible by the
  person who can reach the server, and reviewable by somebody who was not there.

  **Advertised and working are different questions**, and every extension probe checks the result
  rather than the status. `lsetstat@openssh.com` is the row that proves it: advertised by both
  OpenSSH's server and asyncssh's, working on neither under Linux, and failing *differently* on
  each — OpenSSH refuses with a contentless `FAILURE`, asyncssh answers `OK` and moves nothing.
  A report that believed the status would have called the second one working.

  **Safe to point at production, by default.** The read-only battery creates, renames and removes
  nothing. The write battery runs only into a directory the caller nominates by name — there is no
  default and there will not be one — creates every file `0600` under a `gantry-probe` prefix,
  removes them before returning, and names anything it could not remove. `undetermined` stays a
  third answer throughout: a finding that could not be established and a question the run declined
  to ask are recorded by different mechanisms, copying `TreePlan.undetermined`'s shape.

  Not a registry: nothing it emits changes what the library does. DESIGN §7's declarative quirks
  registry stays struck. `docs/compatibility.md` and `examples/compatibility.py`.

- **`Session.sync_tree(local, remote, manifest=...)`**, with a blocking form on `SyncSession`.
  Makes a remote tree match a local one, sending only what changed, and returns a `SyncResult`
  carrying a decision *and the reason for it* per file. New public names alongside it:
  `SyncResult`, `SyncOutcome`, `SyncDecision`, `SyncReason`, `SyncManifest`, `ManifestEntry`,
  `Comparison`, `compare_for_sync`, `MANIFEST_VERSION` and `times_from_stat`.

  **The comparison is against a manifest this library writes, not against the remote timestamp**,
  and that is not a preference. `preserve_times` is off by default, so a file uploaded by
  `put_tree` carries the time of the *upload* — measured against a real `sftp-server` at
  86,470,831 seconds away from the local mtime. A mirror comparing those two finds every file
  changed on every run, forever. Turning `preserve_times` on to compensate would force on a flag
  that exists to be off, so the comparison is against a record instead.

  **The record stores both sides.** A record of what we sent cannot see a file truncated *on the
  server*: the local half still matches, so a record-only mirror skips and leaves the destination
  broken. A v3 listing carries the remote size and modification time already, so closing this
  costs no round trips.

  **Three decisions, and the third one transfers.** `TRANSFER`, `SKIPPED`, and `UNDECIDABLE` for a
  server that volunteered no size or no modification time. Undecidable files are **sent** — a file
  that could not be proven identical is not a file to leave alone — and counted separately, so a
  run that could check nothing is visible without reading every outcome.

  **It does not delete**, and there is no delta transfer: filexfer v3 has no rolling checksum and
  no extension provides one, so an rsync-shaped algorithm is not implementable over this protocol.

- **`DirEntry` from a local walk now carries modification times.** `local_dir_entry` filled
  `size` and `permissions` and dropped `times`; it fills all three. Visible on `Skipped.entry` for
  an upload, where the field was previously always `None`.

### Fixed

- **`live-tests/` had never run off Linux and did not survive contact.** 23 rows failed on macOS
  at once: a Unix socket path is bounded by `sun_path`, which is 108 bytes on Linux and **104 on
  macOS and the BSDs**, and pytest's `tmp_path` is past that on a Mac before a filename is
  appended. That took out the whole `ControlMaster` guarantee and the whole agent-defence truth
  table, and both failed looking like this library refusing to multiplex. A separate nine failed
  because the non-UTF-8 filesystem probe lived in `tests/conftest.py`, which `live-tests/` cannot
  import — two files cannot both be the module named `conftest` — so that lane asked the
  filesystem nothing. No library code changed; this is the suite, and it is listed because the
  guarantees it had stopped proving are ones this project advertises.

### Changed

- **CI runs the `live` lane on macOS as well as Linux**, so the above stays fixed. Required
  status checks are now `live (ubuntu-latest)` and `live (macos-latest)` in place of `live`.
  Nothing a user installs is affected.
- **A tree refuses a contradictory `publish` before it creates anything** (D-172 follow-on).
  `put_tree` and `sync_tree` restated three of `put`'s rules and not the two `require_*` ones, so
  `Publish(require_atomic=True, atomic=False)` was caught one *file* late — same exception, same
  message, but the destination and its missing parents had already been created on the server for
  a transfer that was never going to happen. The tree guard now asks `put`'s guard instead of
  restating it, so the two cannot drift again, and a test derives the leftover difference from
  `Publish`'s own fields.
- **`put_tree(resume=True)` accepts atomic publishing when given a journal**, and its refusal
  message changed (D-172). Since 0.1.0 the combination raised unconditionally, on the argument
  that a staging name generated fresh per call cannot be found again — which is exactly what the
  journal above dissolves, and which `put`'s own guard was amended to say. Nothing that worked
  before stops working: with no journal the call still raises, and the code that catches the
  `ValueError` still catches it. Only callers matching on the message text see a difference.

## 0.1.2 — 2026-08-10

**Six new methods and no breaking change, which under this project's `0.x` rule makes it a patch.**
That rule — the minor version is where a break lands — is doing real work here rather than being
recited: `download_into`, `upload_from`, `fchmod`, `futime`, `fsync_if_supported` and
`posix_rename_if_supported` are additions, each with a blocking twin on `SyncSession`, and no
existing signature, default or resolution order moved. Nothing written against 0.1.1 needs
changing.

**One reason to take this release even if none of those methods is interesting to you.** The
source distribution ships `docs/`, and 0.1.1's copy states that `allowed_hosts()` refuses every
connection on Windows because its `ssh -G` probe cannot execute there. That is wrong — the probe
runs, and the failure the claim was read from belonged to five tests that hand it a `#!/bin/sh`
script Windows cannot execute. The wheel never carried the claim and neither did the README, so
this reaches you only if you rebuild from source; if you avoided a destination policy on Windows
on our advice, you did not need to.

### Added

- **`Session.download_into(handle, fd, size=...)` and `Session.upload_from(handle, path)`**, with
  blocking forms on `SyncSession`. They move a whole file through a handle you opened, into or out
  of a *descriptor* rather than a path, at this session's pipeline depth — the same scheduler
  `get()` and `put()` use. Neither opens or closes either end, both write at explicit offsets so
  `start_offset=` resumes rather than restarts, and `depth=` overrides the session's for one
  transfer. Reach for them when the destination is not something `get()` can open for you: a pipe,
  an unnamed temporary file, a descriptor you already hold. `get()` and `put()` remain the ordinary
  way in and add what these deliberately do not — `O_NOFOLLOW`, the creation mode, size and content
  verification, resume gating and the atomic publish. Documented under
  [Concurrency](docs/concurrency.md) and demonstrated in `examples/file_object.py`.

  They exist because the alternative was worse. Before this, the only pipelined path to a
  descriptor was `get()`, which insists on opening the destination itself — so the verification
  ladder's re-read rung reached into the session for its dispatcher, its depth and its idle
  timeout, and three call sites assembled the same eight-argument scheduler call by hand.

- **`Session.fchmod(handle, mode)` and `Session.futime(handle, atime, mtime)`**, the `f` twins of
  `chmod` and `utime`, beside the `fstat` and `ftruncate` that already existed. Setting a mode by
  *name* on a file you hold open sets it on whatever the name refers to now — the shape of a swap
  attack — and on a staging-and-rename publish the name is about to change, so there is a moment
  when no correct name exists. Both take an optional `path=` carried on the error, because a
  handle is meaningless in a message.

- **`Session.fsync_if_supported(handle)` and `Session.posix_rename_if_supported(old, new)`**,
  which answer `bool` where `fsync` and `posix_rename` raise. Reach for these when you have a
  fallback and want it. Both are attempted whether or not the server advertised the extension,
  and an `OP_UNSUPPORTED` is remembered for the session, so a tree of a thousand files asks once.
  Documented under [Paths, predicates and attributes](docs/paths.md).

  All four carry blocking forms on `SyncSession`. They exist because the upload path was building
  those four requests by hand and could not be read anywhere but inside `Session`; naming the
  operation each one wanted is what let the whole of `put` below its public entry point move to a
  module of its own. Nothing about `get()`, `put()` or their results changed.

### Fixed

- **`chmod(..., follow_symlinks=False)` no longer attaches its `lchmod` explanation to a refusal
  that already explains itself.** The note exists because OpenSSH's `FAILURE` carries no message —
  five distinct conditions all render as `Failure` — and the common cause for this one flag is that
  Linux has no `lchmod`. It was being attached to *every* `ServerError` from that branch, so a
  `NO_SUCH_FILE` that had already said `No such file` arrived with a paragraph about a syscall that
  was never reached, naming a kernel the server may not be running. It now travels with the
  contentless `FAILURE` alone. If you branch on `__notes__` to tell an unexplained refusal from an
  explained one, that distinction is now real. Documented under
  [Paths, predicates and attributes](docs/paths.md).

  Found by running the suite on macOS, where `lsetstat`'s permissions branch *succeeds* — so a
  missing path is the only refusal that branch can produce there, and every one of them carried the
  wrong diagnosis.

- **`allowed_hosts()` works on Windows, and the documentation saying it does not is withdrawn.**
  From 2026-08-05 to 2026-08-10, [Connecting](docs/connecting.md) carried a "known defect" note
  and [Security](docs/security.md) listed Windows under what is not defended, both stating that
  the `ssh -G` probe cannot execute there so every connection is refused while a policy is
  active. **It can, and they are not.** The Windows job resolves
  `C:\Windows\System32\OpenSSH\ssh.exe`, `ssh -G` answers, and a config rewrite is caught exactly
  as on Linux — proven by rows that passed on Windows in the two runs the note was written from.

  The `ERROR_BAD_EXE_FORMAT` behind the note belongs to five tests that hand the probe a
  `#!/bin/sh` script to make it misbehave on purpose. Windows cannot execute that file, so those
  rows failed in the spawn path instead of the path they were written for, and the failure was
  read as the library's. They skip there now with the reason. **If you avoided a destination
  policy on Windows because of that note, you do not need to.**

A patch rather than a minor, and the one judgement call in that is stated rather than left to be
inferred. `get` of a name the local filesystem refuses used to raise a bare `OSError` and now
raises `TransferError`, which is **not** an `OSError` subclass — so an `except OSError` around
`get` written for it would stop matching. That is treated as the fix it is filed as rather than as
a break: the behaviour was undocumented, unreachable on Linux, and the leak of an errno with no
path out of an API whose whole claim is that its errors say what failed and where. The new
`SkipReason` member is an addition, which under this project's `0.x` rule — the minor version is
where a breaking change lands — belongs in a patch.

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

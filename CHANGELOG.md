# Changelog

Notable changes, newest first. This project follows [semantic versioning](https://semver.org),
and while the major version is `0` the minor version is where a breaking change lands.

## 0.5.0 — 2026-08-17

**A minor bump because it adds API, and for no other reason — nothing here breaks.** Two public
surfaces arrive: transferring an explicit list of files, on both the async and the blocking side,
and a blocking form of `with_reconnect`. Under this project's `0.x` rule the minor version is
also where a break would land, and this release has none: nothing was removed, no signature
changed, and no default moved. Calling it `0.4.1` would understate it, since a bug-fix release
does not grow the API.

**The rest of what landed since 0.4.0 does not appear below, and that is deliberate.** Four of
the seven changes are tests — mutation-lane work that pinned defaults nothing was asserting and
pinned the compatibility report finding for finding. They changed no behaviour a program can
observe, so they are not notable changes to a *user*; the one defect that work uncovered is under
Fixed.

### Added

- **`Session.get_many(paths, directory)` and `Session.put_many(paths, directory)`, with the
  blocking twins `SyncSession.get_many` / `SyncSession.put_many`** (D-26). Transfer an explicit
  list of files into one directory, with `concurrency=` and per-file results returned **in the
  order you asked for them** rather than in completion order.

  **The reason this is a method and not three lines of task group is the local name.** Each
  destination is *derived* from a path you supplied, and the remote and local name rules are not
  the same rule — `..\evil`, `C:evil` and `CON` all clear a remote check while containing no `/`
  at all. Deriving the name here means one place checks it instead of every call site.

  **A list flattens where a tree does not**, so `a/x.csv` and `b/x.csv` are two files in a tree
  and one name here. Byte-identical basenames are refused **up front, from the arguments, before
  anything moves** — deliberately unlike `get_tree`, which cannot know the set until it has
  walked. The remote direction cannot have that check at all, because a server's folding rules
  are its own, so `put_many` refuses only what it can prove and the asymmetry is documented.

- **`gantry_sftp.sync.with_reconnect`** (D-85). The blocking form of the reconnect-and-retry
  helper, which the async surface has had and the blocking one had not. It hands your function a
  session, and the portal's own thread is the one thread that cannot use one — so the blocking
  form runs it on a borrowed pool worker rather than a thread per call. An exception raised there
  comes back as itself and flat, so the retry classifier still sees it.

  The invariant this closes is *anything added to the async surface is not done until the
  blocking one has it*, and the gate asserting it could not see this function: the parity check
  derived from classes, and `with_reconnect` is a module-level callable. It now covers those too,
  and discriminates by whether a function is a coroutine rather than by whether its name appears
  on both surfaces.

### Fixed

- **`doctor` told you the wrong hazard about a case-folding server** (D-193). The compatibility
  battery's case finding, when it establishes that **the server folds case**, described the
  consequence as "a recursive download from a case-sensitive server can overwrite its own
  output". That sentence is true and it is about the opposite server: one that folds cannot hold
  two names differing only in case, so it can never present both in a listing and cannot make a
  download merge them. What follows from a folding server is the mirror — **an upload of two
  local names differing only in case lands as one file, the second overwriting the first**.

  Both branches now carry the hazard that belongs to them; the download warning moved to the
  case-*sensitive* finding, where it is what bites a `get_tree` onto macOS or Windows. Only the
  prose a reader acts on was wrong, so no verdict changed and no exit code moved.

## 0.4.0 — 2026-08-14

**A minor bump, and it would be one for either half of what follows.** Under this project's `0.x`
rule — the minor version is where a break lands — one behaviour a caller could have written against
changed: a `SyncRemoteFile` or `SyncDirectoryScan` used after its session's `with` block has ended
now raises this library's `StateError` where it raised anyio's `RuntimeError`, so a handler catching
`RuntimeError` around one stops catching. And the release adds a subsystem rather than fixing one,
which is the argument 0.2.0 made for not being `0.1.3`: every `OPEN` this library chooses the flags
for now survives a refusal the server says will clear. Calling this `0.3.1` would have described a
bug-fix release.

Written with the date because the tag follows immediately; before that it read `## Unreleased`, and
that distinction is enforced rather than observed. `tests/test_packaging.py` accepts either heading;
`release.yml` refuses `Unreleased` on a tag and refuses a tag that disagrees with `__version__`.

### Added

- **A refusal that clears is now retried, on the session you already have** (D-30, D-182, D-185,
  D-187). Some refusals are about a resource rather than about your file and pass on their own. The
  measured one is descriptor exhaustion: a server out of file descriptors refuses the next `OPEN`
  and answers the identical request once another transfer closes one. Before this release that
  ended your transfer.

  **Every `OPEN` this library chooses the flags for is covered**, in both directions — `get` and
  `get_tree`, both rungs of `get(verify=...)`, `open_file` and `SFTPPath.open` / `read_bytes` when
  the flags you passed mutate nothing, the fsspec adapter's `cat_file` and `fs.open(…, "rb")`, and
  every upload path including the default atomic publish. Three attempts, a short doubling delay,
  and then the server's own error unchanged. There is no parameter and nothing to configure.

  **It is a per-server capability and it is off wherever the server does not explain itself.**
  `ServerProfile` gains `transient_messages` and `classifies_transient()`, read only together with
  the existing `informative_messages`, so a server this library has no fingerprint for is never
  retried however its text reads. Of the three implementations in the test matrix only asyncssh
  qualifies; OpenSSH's `STATUS` message is the constant word `Failure` for every condition
  including this one, which is measured rather than assumed.

  **Two limits are deliberate and documented.** The open rather than the transfer — a `READ` runs
  against a descriptor the server already holds, so it cannot reach this condition — and bounded at
  three attempts, because resource exhaustion is exactly the failure where a client retrying
  without limit is what keeps the resource exhausted. The one read-open that deliberately never
  retries is the compatibility battery's: a report of what a server does must not retry until it
  behaves. `docs/reliability.md` carries the whole table under "A refusal that clears".

- **`Session.open_for_read(path)`, with the blocking twin `SyncSession.open_for_read(path)`**
  (D-185). The plain read-open for when you want the handle yourself, on the same ladder `get()`
  uses. It takes no `pflags`, and that is the design rather than an omission: there is no flag
  whose retry it would be willing to make. An open that changes something is still spelled
  `open()` and is still issued exactly once, whatever the server says about why it refused.

### Changed

- **A `SyncRemoteFile` or `SyncDirectoryScan` used after its session's block has ended now names
  the block rather than the portal** (D-186). Every `SyncSession` method already went through a
  readiness check raising `StateError("this session is closed; its `with` block has ended")`; these
  two classes held the raw `BlockingPortal` and called it directly, so not one of their methods
  passed through it and a caller got anyio's `RuntimeError: This portal is not running` — a message
  about a thread they never asked for.

  **This is the release's one break, and it is on a path a caller has already got wrong.** If you
  catch `RuntimeError` around a file object or a directory scan used past its session, catch
  `StateError` (or its base `SFTPError`) instead. `__exit__` is the deliberate exception and still
  returns quietly: the handle went with the connection, so there is nothing to release, and raising
  from an exit would replace whatever exception was already propagating.

### Fixed

- **`get(verify=...)` could report a verification failure on a file that was byte-correct**
  (D-182). Both verification rungs open a handle for reading, and neither open had the retry the
  transfer's own had. Against a server momentarily out of descriptors the file transferred and then
  failed its check — which is exactly how a corrupt transfer reads, and so the most misleading shape
  this library can produce.

- **The default `put()` failed where `put(atomic=False)` recovered** (D-187). The atomic publish's
  staging file is opened `CREAT|EXCL`, and an exclusive create was held out of the ladder on the
  argument that a first attempt which created the file and then refused would leave the retry
  colliding with our own leftover. It cannot: a name genuinely in the way is refused with a message
  this library does not classify as transient, so it is terminal on the first sight of it and you
  get the same error you would have got without the ladder. Measured too — under the condition that
  *is* classified, the server answers before creating anything. The staging name does not change
  between attempts, so nothing about `UploadJournal` or `discard_staged()` changes with it.

- **`put_tree` and `sync_tree` documented an `UnsafePathError` neither can raise** (D-184). Every
  name the guard is asked about comes from `os.scandir` plus `os.fsencode`, and each of its five
  refusals is unreachable from there — built rather than reasoned about. `put_tree(dry_run=True)`
  also claimed the refusal happens "exactly as it would in a real run", which was a positive claim
  about an impossible behaviour used to argue a dry run is complete. The guard stays, documented as
  the assertion it is.

- **`docs/compatibility.md` now cites `ronf/asyncssh#827`** for the row recording that asyncssh
  answers `OK` to an `lsetstat` chmod and changes nothing. The citation narrows the claim in a way
  the table has no room for: only the permissions flag is discarded, and the timestamp flag over
  the same request works.

## 0.3.0 — 2026-08-13

**A minor bump because one documented default changed, and that is the whole of why it is not
`0.2.1`.** While the major version is `0` a breaking change lands in the minor version, so a patch
release is always safe to take — and this one is not a patch: a `gantry-sftp` filesystem built with
a `password=` is no longer shared out of fsspec's instance cache. Nothing was added and no
signature moved; everything else below is a fix. But a caller relying on that instance being reused
gets a different object and an `ssh` child per resolution, and a release that delivers that under a
patch number delivers it silently.

Written with the date because the tag follows immediately; before that it read `## Unreleased`, and
that distinction is enforced rather than observed. `tests/test_packaging.py` accepts either heading;
`release.yml` refuses `Unreleased` on a tag and refuses a tag that disagrees with `__version__`.

### Changed

- **A `gantry-sftp` filesystem built with a `password=` is no longer shared out of fsspec's
  instance cache** (D-178). The cache token deliberately omits the password — that is what keeps
  the credential out of a pickle — so two filesystems differing *only* in password used to come
  back as one, holding the first. 0.2.0 documented that and named the control; this makes the
  control the default, because the consequence is an authentication one: the second caller's
  password is never checked against anything, so one that is *wrong* for the account still
  connected, on a session somebody else authenticated. Where several principals share a process —
  a dask worker, a notebook server, a shared ETL job — knowing a username was enough to inherit a
  colleague's session, and no log distinguished it.

  **What it costs, and who pays.** A program resolving the same password-bearing URL repeatedly
  now spawns an `ssh` child per resolution instead of reusing one. Key-based authentication is
  untouched and still caches per thread. Pass `skip_instance_cache=False` explicitly to share
  anyway, in a process you know holds one principal — the old spelling still resolves the old way,
  and there is a test that says so.

### Fixed

- **An upload journal was re-read from the start once per file, on the event loop** (D-176).
  `put` performs one lookup per file — which staging file, if any, a previous run left for this
  target — and a tree appends two records per file to that same journal, so the cost of reading it
  grew with the tree in the exact case the feature exists for: thousands of files over a bad link.
  The lookup now reads only what has been appended since the last one, so a run pays for its log
  once however long the log has grown, and the shape no longer depends on tree size. Nothing is
  cached across the *file*: every lookup re-opens the journal, reads to its current end and checks
  it is still the file it read before, so a record another process appended is still seen and a
  log that was compacted, rotated or truncated underneath a running job is read again from the
  start.

  **The reading and writing also left the event-loop thread.** The lookup, both records and their
  `fsync`s now run on a worker, which is what `put` already did with local file reads: a transfer's
  job is to keep the link busy, and a wait on the local disk stopped every *other* file in a
  concurrent tree as well. No API changed; `compact()` keeps the reasons it already had, which are
  disk space and the sweep.

- **The password's absence from `storage_options` rested on a private attribute of fsspec**
  (D-177). `_strip_tokenize_options = ("password",)` is our whole contribution to that guarantee;
  the pop that acts on it lives in fsspec's `_Cached.__call__`, and `storage_options` is the one
  mapping `__reduce__` returns verbatim and `to_json()` serialises with `include_password`
  defaulting to `True`. With `fsspec` declared `>=2026.7.0` and no upper bound, and every CI lane
  resolving `--frozen`, a release that stopped honouring the attribute would have put the
  credential into every dask worker's pickle with nothing raised anywhere. The mapping is now
  scrubbed by `gantry_sftp.fsspec`'s own metaclass as well, so the guarantee holds whatever fsspec
  does; `_strip_tokenize_options` stays, because it is also what keeps the password out of the
  cache *token*, which a scrub cannot reach. No upper bound was added — with the belt in place the
  adapter no longer needs one for this, and a cap would restrict you to buy nothing.

- **A local file this library creates beside one you named could be planted at first** (D-175,
  CWE-59). `UploadJournal.compact()` wrote `<journal>.compacting` and `sync_tree`'s manifest
  compaction wrote `<manifest>.partial`, each opened `O_CREAT|O_TRUNC` with no `O_NOFOLLOW`. Both
  names are derived from a path **you** named, in a directory this library does not own, so
  anybody able to write there could predict one and plant a symlink at it: the file it pointed at
  was truncated and overwritten, and the rename that followed moved the *link* onto your journal,
  sending every later record there too. Both now go through one helper using `tempfile.mkstemp`
  semantics — `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`, and a name that is not derivable.
  `O_EXCL` is load-bearing beside `O_NOFOLLOW`: a *hard* link planted at the name is not a
  symlink. A failed compaction now also removes its temporary instead of leaving it.

  **What deliberately did not change**: the journal and manifest paths *you* name are still
  opened following a symlink, exactly as `get` opens a download destination — `no_follow` is a
  parameter there and off by default, because a state file that is a link to somewhere else is a
  deployment rather than an attack. The line is who chose the name. The consequence is that these
  files belong in a directory only your job can write to, which is now stated in
  [Where to put the journal](docs/reliability.md#where-to-put-the-journal), on `UploadJournal`,
  on `sync_tree`'s `manifest` argument, and as a row in the security table.

## 0.2.0 — 2026-08-12

**A minor bump that breaks nothing.** While the major version is `0` a breaking change lands in the
minor version, so a patch release is always safe to take — but the reverse does not follow, and
this one adds three subsystems rather than fixing anything. Calling it `0.1.3` would have described
a bug-fix release. Everything below is additive except one refusal that became *less* strict and
one on-disk format belonging to a feature that had not been released.

Written with the date because the tag follows immediately; before that it read `## Unreleased`, and
that distinction is enforced rather than observed. `tests/test_packaging.py` accepts either heading;
`release.yml` refuses `Unreleased` on a tag and refuses a tag that disagrees with `__version__`.

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
- **An interrupted mirror keeps what it sent** (D-173). `sync_tree` wrote its manifest once, after
  the transfer loop returned, so a run killed partway through recorded nothing and the next one
  re-sent the whole tree — and on a tree large enough to be interrupted, that is every run. The
  record is now appended as each file lands and compacted when the run ends.

  **The file format changed** and `MANIFEST_VERSION` is `2`: one JSON record per line, with the
  version carried per record so an upgrade between two runs costs only the records the new version
  cannot read. Nothing needed migrating, since `sync_tree` had not been released. A manifest
  written by the earlier code reads as "nothing is known" and costs one full re-send.

  **No `fsync` per record, and that is the decision rather than an omission.** The upload journal
  flushes every line because over-reporting there is corruption; a manifest record is written only
  after the transfer returned *and* the destination was checked, so a lost tail is a record fewer —
  a re-send. There is one `fsync`, at the compaction. Measured before it was argued: rewriting the
  whole document per file is quadratic in a run and costs more than the transfers do over a fast
  link, while an append is orders of magnitude below one transferred file even on localhost.

  The manifest path is opened before the walk starts, so a directory that does not exist raises
  `OSError` immediately instead of from inside the walk.
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

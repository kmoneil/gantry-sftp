# Development

How to run the suite and the lanes, and what each lane exists to catch.

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

| lane                  | what it proves                                                                                  | needs, beyond `uv sync`        |
| --------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------ |
| `lanes.py gates`      | ruff, mypy `--strict` over `src` and a weaker mypy over the two API-consuming directories, ty, complexipy, the deprecation check, the `uv.lock` check, the exec bit, the secrets scan | nothing; POSIX only            |
| `lanes.py audit`      | known advisories against the versions `uv.lock` pins                                           | `uv sync --group audit`, network |
| `lanes.py fast`       | unit tests, the real `sftp-server` rows, every example as a subprocess                          | `openssh-server` for some rows |
| `lanes.py leaks`      | the unit tests again, failing the one that left a transport, session or child process alive     | `openssh-server` for some rows |
| `lanes.py live`       | a real `sshd` on localhost: transport, `ssh` environment, cancellation, handles                 | `openssh-server`               |
| `lanes.py matrix`     | one client against three servers: OpenSSH, asyncssh, paramiko                                   | `uv sync --group bench`        |
| `lanes.py netem`      | every pipelining claim, on a `tc`-shaped link at 5/50/200 ms RTT                                | `CAP_NET_ADMIN`                |
| `lanes.py benchmarks` | wall clock and CPU against paramiko and asyncssh                                                | both of the two above          |
| `lanes.py cost`       | what a transfer costs this process: instructions retired and peak memory                        | `valgrind`, `openssh-server`   |
| `lanes.py mutation`   | whether an assertion would notice the line being wrong                                          | nothing                        |

Every lane **gates** — a failure stops the change — except `netem`, `benchmarks` and
`mutation`, which **report**, meaning they measure, or assert against a baseline that is not in
this tree. `scripts/lanes.py` carries the reason next to each one, so opting a lane out of
gating is a written act rather than a habit.

`cost` is the one performance lane that gates, and the reason is worth reading before adding
another. It measures a transfer as **counts of work** rather than as a rate — instructions
retired, and peak resident set — so it comes out the same on a busy machine and on an idle one,
which is what lets a baseline for it be committed where a baseline of MiB/s could not be. Four
things fail a run.

**Instructions**, under `cachegrind`: cost per byte drifting more than 8% from
`benchmarks/instructions-<arch>.json`, and cost per byte *growing with the file*, which is a
superlinear cost and is invisible to the wall-clock sweep for as long as throughput is still
rising. Eight percent is twice the measured run-to-run spread, so what it catches is a change of
roughly a tenth or more — the class D-112's 11× belongs to, and not a single extra copy on the
data path. Regenerate the baseline with `GANTRY_SFTP_INSTRUCTION_BASELINE=write` and commit the
diff; it is never rewritten on your behalf. A count only reproduces against one instruction set
and one CPython patch release, both of which the file records — on a machine matching neither,
the shape half still gates and the report says in one line why the other did not.

**Peak memory**, from `/proc/self/status`: the peak growing with the file across a 16× range of
sizes, or a transfer costing more over an empty session than `docs/tuning.md`'s expression allows.
This is the first measurement behind that page's bound — before it, the only thing checking
"about 16 MiB per transfer, independent of the file's size" was arithmetic over the two constants
the sentence quotes. Needs no baseline; both assertions are internal to one run. Linux only, and
it skips elsewhere with the reason: `getrusage`'s `ru_maxrss` is **not** a portable substitute,
because across `posix_spawn` it reports the *parent's* peak (D-138).

Type checking is deliberately two-tool: mypy is stricter and catches gaps ty misses. A
finding gets fixed at the source, never silenced with an ignore.

It runs at **two strengths over three scopes**. `src/` gets mypy `--strict` and ty, configured in
`pyproject.toml`. `benchmarks/` and `live-tests/` get a second, weaker mypy pass configured in
`mypy.consumers.ini` — they are consumers of the public API, calling `get`, `put`, `open_session`
and `connect` exactly as a downstream program does, so a signature change that breaks them is one
that breaks users. `tests/` is outside both, deliberately: it asserts against internals and is a
different argument. The weaker level is measured rather than assumed — `--strict` reports
hundreds of `no-untyped-def` and missing-`@override` findings on test functions, which is house
style for assertion code and not a contract break, while the default level plus a few error codes
reports the ones that matter. It is a separate file rather than more keys in `pyproject.toml` so
that the weakening cannot reach shipped code by one edit, and it runs once per directory because
each has a `conftest.py` and two files cannot both claim that module name.

Calling a deprecated API is a gate of its own, over the whole repository rather than over `src`
alone — a deprecated spelling taught in an example is one that gets copied into shipped code.
mypy's `deprecated` error code and ty's `deprecated` rule both run, and a third hook runs
`basedpyright` with type checking switched off and `reportDeprecated` switched on, because the
three checkers vendor different typeshed snapshots and the one that already carries a
deprecation is not always the one you were going to run.

`detect-secrets` runs over **every** file type rather than over Python, because a credential
lands in a YAML, a TOML or a Markdown snippet at least as easily as in a module. It carries a
committed `.secrets.baseline`, and the thing to understand about that file before trusting it is
that it is **not a list of excused files**: an entry is keyed by file, hashed secret and line, so
a real credential added to an already-listed file still fails. That was verified rather than
assumed, by dropping an AWS key into `tests/test_fsspec.py` — a file with four baselined entries
— and watching the hook refuse it.

The 22 entries it starts with were each read before they were written down, and none is a
credential: fixture passwords the suite greps for on purpose (`hunter2`,
`correct-horse-battery-staple`, `s3cret-that-must-not-be-in-argv`), bare `-----BEGIN PRIVATE
KEY-----` header lines with no key material behind them, an environment variable's *name*, and an
OpenSSH `Permission denied (password)` message. Regenerate with

```console
$ .venv/bin/detect-secrets scan $(git ls-files) > .secrets.baseline
```

when a fixture moves, and **read the diff** — a baseline regenerated without being read is the
one way this check becomes decoration. A single false positive is better marked in place with a
`pragma: allowlist secret` comment than by growing the file.

One hook **reports instead of gating**, and it is the only one: `parked-worktrees` lists any
worktree left behind under `.claude/worktrees/` and always exits 0. Working in a worktree is
supported, so failing the commit would be wrong every time somebody legitimately has two going —
what it guards against is not knowing one is there. A session that ends a turn and a session
sitting idle waiting for an answer look identical from outside, the worktree it leaves stays
`locked` because the keep-or-remove prompt never runs for it, and nothing else in the repository
mentions it: `git status` in the main checkout is clean whatever is parked next door. It says
nothing when nothing is parked. It is marked `verbose` in `.pre-commit-config.yaml` because
pre-commit shows the output of a *failing* hook only, and this one never fails.

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

There are four groups in all and the reason each is separate is on it in `pyproject.toml`.
`dev` is the default and holds everything the gating lanes need. `bench` is the comparison
libraries above. `audit` is `pip-audit`, which costs 18 packages over a default `uv sync` for
something one lane runs. `build` is `hatchling`, and it exists so that `release.yml` can build
with `--no-build-isolation` and have the backend come from `uv.lock` like everything else —
PEP 517 build requirements are otherwise resolved fresh from PyPI, unpinned and unhashed, by
whatever is doing the packaging.

### CI

`.github/workflows/ci.yml` runs those lanes on Linux, macOS and Windows. It invokes them
through `scripts/lanes.py` rather than spelling out a `pytest` command of its own, so CI and a
developer cannot drift into running different things; `tests/test_lanes.py` asserts both that
and that every lane the runner knows about is named in the workflow.

**It first ran on 2026-08-05**, and what that run found is listed in the workflow's own header
rather than repeated here. This paragraph used to say the file had never run, because there was
no remote for GitHub to see the repository through; the sentence outlived the remote by four
days, which is the argument for keeping this section next to the file it describes.

Linux and macOS gate on every push and pull request. **Windows runs on the weekly schedule
only**, as `fast-windows`, and it **reports rather than gates** — not out of caution. Transfers
are POSIX-only (see Requirements) and refuse there, so every test that moves bytes fails on
Windows by design. Making that job gate needs the out-of-scope rows marked as such, and marking
them before a Windows run has happened would be guessing at which ones they are. The job exists
because that list is exactly what is wanted from it, and no amount of reading the code produces
it.

**It has still never produced the list, and the reason is worth writing down.** The first
scheduled run ended in 27 seconds with `ModuleNotFoundError: No module named 'resource'` while
importing `tests/conftest.py` — zero tests collected, so the job reported nothing about the
library at all, and `continue-on-error: true` made that indistinguishable from a lane with
nothing to say. A `conftest.py` that fails to import ends the session; there is nowhere to
attribute the error to. The same collision had already taken three test modules on the first
Windows run ever and was answered in each of them with `pytest.importorskip`, which a conftest
cannot use. The rule now lives in `tests/test_platform.py`, which walks every module the
default run imports and fails on a module-scope import of anything CPython does not build on
Windows. So `resolve_ssh_executable`'s `SysNative`-before-`System32` probe is still unit-tested
with injected inputs and has still never executed on Windows.

### The controlled `ssh` environment

Every `ssh` these suites spawn gets `-F /dev/null` and an environment with `SSH_AUTH_SOCK`,
`SSH_AGENT_PID`, `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE`, `DISPLAY`, `WAYLAND_DISPLAY`, `SHELL` and
`SSH_SK_HELPER` removed. That is not hygiene for its own sake. Without it, a developer with an
agent running has that agent supply a working key to the test that means to fail with the
_wrong_ one, and the assertion that we surface `Permission denied` verifies nothing while
staying green.

`live-tests/test_ssh_environment.py` proves it, and the interesting half is _how_. It reads the
child's environment directly rather than inferring it from behaviour: `ProxyCommand` is executed
by the `ssh` client and inherits its environment verbatim, so a proxy that dumps its own
`os.environ` reports what `ssh` was handed rather than what we meant to hand it. Then it
reproduces the hazard, with a real `ssh-agent` holding the _right_ key while the connection is
made with the _wrong_ one:

| parent environment | `IdentitiesOnly` | result                          |
| ------------------ | ---------------- | ------------------------------- |
| scrubbed           | `yes`            | `Permission denied (publickey)` |
| scrubbed           | absent           | `Permission denied (publickey)` |
| agent visible      | `yes`            | `Permission denied (publickey)` |
| agent visible      | absent           | **authenticates**               |

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
  compiled in as the default, and the variables that _arm_ it are `DISPLAY` and
  `WAYLAND_DISPLAY`, either alone being enough to make a passphrase-protected key authenticate
  through a helper. Both were missing from the set; `WAYLAND_DISPLAY` appears nowhere in
  `ssh(1)`.

### The audit lane

```bash
uv sync --group audit
python scripts/lanes.py audit
```

`uv.lock` records a sha256 for every artifact it names, and `uv sync --frozen` refuses one whose
bytes do not match — on a cold cache and a warm one alike. That is integrity, and it says nothing
about whether the pinned version is *known to be broken*. This lane is the part that asks, and
the first run of it found an advisory that had been sitting in the lock.

It audits **two scopes and gives them two different verdicts**, which is the design decision
worth knowing before reading the output:

- **`shipped`** is what `pip install gantry-sftp[fsspec]` puts on a production machine — three
  packages, because the runtime dependency is `anyio` and nothing else. An advisory here is
  about what users run, so it **gates**.
- **`toolchain`** is everything the lock can install, `bench` included. That is where
  `cryptography` lives, and it is there to be measured against rather than shipped. An advisory
  here is worth knowing and is not a reason to fail somebody's change, so it **reports** —
  gating on it would let paramiko's dependencies block a release of a library that does not
  ship them.

**A run that could not reach the advisory service exits `2`, not `0`.** This is the one place
the "skip with a reason rather than fail" rule used everywhere else here is deliberately not
applied, and the reason is that a security scan has three states rather than two: `1` is "found
something", `2` is "checked nothing", and only `0` means clean. pip-audit itself exits `1` for
both a finding and a network failure, which is exactly the conflation this lane was built to
undo — `scripts/audit_deps.py` tells them apart by whether stdout parsed as a report, and its
header records why.

It is also the one lane whose value is mostly in running on a **schedule**. An advisory is
published against code that has not changed, so a lane that only ran per change would find it
whenever somebody next happened to edit something. It runs per change *and* weekly, and again in
`release.yml` before anything is uploaded — a published version cannot be withdrawn, and its
gating scope is exactly the set a user of that artifact installs.

### The leak lane

```bash
python scripts/lanes.py leaks
```

The same unit tests as `fast`, with an autouse fixture that fails **the test that leaked** a
transport, a session, a dispatcher or a child process. It is armed by `GANTRY_SFTP_LEAK_CHECK`
and off otherwise, because it makes two full passes over `gc.get_objects()` per test — a cost
that scales with the live heap, and lands about an order of magnitude above `fast` on the whole
suite. The gating lane should stay under a minute.

Which test fails is the entire point. The last leak of this shape — `Process.aclose()` never
called, leaving the pipe transports open for the garbage collector — surfaced as failures in
_unrelated later tests_, which is indistinguishable from flakiness while it is happening and
costs an afternoon of reading the wrong module.

**It counts live instances of a few named types, not bytes and not total objects**, and the
reason is measured rather than assumed. All three were compared against the two leak shapes
this project has actually had:

| case                      | fds | total objects | watched types                                             |
| ------------------------- | --- | ------------- | --------------------------------------------------------- |
| clean transfer, ×3        | +0  | +1            | none                                                      |
| a plain file left open    | +1  | +3            | none                                                      |
| `Process` never closed    | +0  | +29           | `Process` +2                                              |
| async generator abandoned | +0  | +100          | `Dispatcher`, `Process`, `Session`, `SubprocessTransport` |

`tracemalloc` bytes and the total object count both see the leaks, and neither can be
thresholded: across 294 real tests, 22% grow the total object count and one reaches **146
objects** — an fsspec test whose subject is a `storage_options` dict. The real leaks are +29
and +100, so a threshold clearing the noise misses the leak. Counting the resource-bearing
types instead needs no threshold at all — one survivor is a failure — and across those same
294 tests it grew zero times. It also names what leaked, which is what the last one needed.

**The descriptor column needs a directory listing this process's own fds**, and it tries
`/proc/self/fd` then `/dev/fd` — the second is what makes the count work on macOS, which has no
`/proc` at all and reported every fd reading as unmeasured until then. When neither can be listed
the count is `None` and no descriptor growth is reported: a zero from a counter that cannot see is
proof of absence manufactured from an absence of proof.

`tests/test_leakcheck.py` leaks on purpose in both shapes and asserts the detector reports
them, because a detector nobody has watched fail is a decoration. Adding a new transport means
adding it to `WATCHED_TYPES`; a test asserts that list covers every `Transport` the package
exports, so a new one cannot go unwatched silently.

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
for you and then _measures_ what the kernel actually did, because a benchmark that reports its
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
_equivalent_ (no test can distinguish them) are listed with their reasons in
a register rather than suppressed, so a future run has a baseline to diff against
instead of a triage to redo.

It reports rather than gates, and the reason is mechanical: `mutmut run` exits 0 whether or
not mutants survive, and the register of known-equivalent survivors is not in this repository,
so there is nothing here for a machine to diff a run against. Comparing the two is a human
step until that changes.

`mutmut` mutates only functions the tests call, and it mutates the copy of the library it
writes into `mutants/`. Test selection is `tests/` alone: `examples/` runs each example as a
subprocess, which imports the _installed_ library rather than the mutated copy, so those
tests cannot kill a mutant and would only add wall-clock.

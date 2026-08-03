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
| `lanes.py gates`      | ruff, mypy `--strict`, ty, complexipy, the deprecation check, the `uv.lock` check, the exec bit | nothing; POSIX only            |
| `lanes.py fast`       | unit tests, the real `sftp-server` rows, every example as a subprocess                          | `openssh-server` for some rows |
| `lanes.py leaks`      | the unit tests again, failing the one that left a transport, session or child process alive     | `openssh-server` for some rows |
| `lanes.py live`       | a real `sshd` on localhost: transport, `ssh` environment, cancellation, handles                 | `openssh-server`               |
| `lanes.py matrix`     | one client against three servers: OpenSSH, asyncssh, paramiko                                   | `uv sync --group bench`        |
| `lanes.py netem`      | every pipelining claim, on a `tc`-shaped link at 5/50/200 ms RTT                                | `CAP_NET_ADMIN`                |
| `lanes.py benchmarks` | wall clock and CPU against paramiko and asyncssh                                                | both of the two above          |
| `lanes.py mutation`   | whether an assertion would notice the line being wrong                                          | nothing                        |

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

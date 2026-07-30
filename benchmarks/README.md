# benchmarks

The source of truth for every performance claim this project makes, and since 0.10 the only
place one lives. Nothing shipped outside this directory states a throughput figure — not the
README, not an example, not a docstring — because the ranking rule this project is built on puts
a correctness gap above a throughput feature, and a document that says so and then leads with
ratios is arguing against itself (D-88). The older half of that rule still governs here: an
unattributed "10× faster than paramiko" is marketing, and a number without its link profile, its
server and its benchmark is an anecdote.

```bash
uv sync --group bench                        # paramiko and asyncssh
python scripts/lanes.py benchmarks           # about ten minutes
```

That lane is `pytest benchmarks/ -s`, and `scripts/lanes.py` is where it is spelled out — one
place, so what CI runs and what you run cannot drift apart. `-s` because the report is printed
as well as written. The written copy lands in
`_reports/benchmarks.md`, which is gitignored: a generated table is evidence for a claim, not a
source file.

A run that covers only part of the matrix — a `-k` selection, or a profile that skipped because
the link could not be shaped — writes `_reports/benchmarks-partial.md` instead, and says
`PARTIAL` in its header. Overwriting the full report with a subset would be worse than writing
nothing: `benchmarks.md` is what the README and DESIGN.md cite, and a ten-second
`-k unshaped` run would silently replace every shaped number with the one profile that proves
least.

Everything here skips with a fix-it message rather than failing — no `openssh-server`, no `tc`,
or no comparison libraries installed, and you still get the rows that can be measured. The
unshaped profile needs no `tc` at all and runs in a plain checkout.

## What is measured

| scenario | what it is for |
| -------- | -------------- |
| connect and close | the handshake alone. Two of the three libraries do key exchange in Python; this is the row that isolates it, and it is what you subtract from the CPU column of the others |
| download 16 MiB | the latency-bound case. 16 MiB is eight times the 2 MiB channel window, so a client that fills the window is distinguishable from one that does not |
| upload 16 MiB (in place) | the other direction, with our atomic publish and fsync **off**, because that is the work the other two libraries do |
| download 16 MiB, one connection | not a comparison. The same download timed as a connection's first transfer and as its second, because every other row here opens a fresh connection per sample and therefore times TCP slow start along with the transfer (D-23) |
| download N × 8 KiB, sequential | the round-trip-bound case. Sequential for all three — see below |
| upload N × 8 KiB, sequential | the same case in the direction the matrix used to miss entirely. Both 16 MiB upload rows move one file, so a per-file round trip rounds to nothing in them; this is the only row a cost paid *per file* can appear in, and `put_tree` over a drop directory is the workload it stands for |
| download N × 8 KiB, one connection | not a comparison. Our own sequential path against our own overlapped one, same files, same connection |
| atomic publish 16 MiB | not a comparison. What *our own* default costs against our own in-place path |
| read 16 MiB: file object vs whole file | not a comparison, and the one row besides the sweep that **gates**. Our own `open_file().read()` in fixed blocks against our own `get`, plus paramiko's file object as a control. `paramiko#2453` reports their `SFTPFile.read()` at 25x their own `get`; the obvious implementation of a byte-range read reproduces it, so this row is how we know which one we shipped (D-86) |
| download / upload: throughput against size | the **shape**, on two profiles. Ten sizes bracketing every boundary the design has, so a cliff at a byte count is visible as a curve rather than inferred from two points. This is the only scenario that **gates** — see below |

Across five link profiles: unshaped, 5 ms, 50 ms, 200 ms, and 50 ms rate-limited to 100 Mbit/s.
The rated one exists because loopback has no bandwidth ceiling unless you configure one, so
every other profile measures latency-bound behaviour only.

## The size sweep: the one scenario that asserts

Nobody complains in ratios. What people report against the incumbent is a *pathology* — a cliff
at a byte count (`paramiko#2438`: writing more than 32675 bytes costs 99% of the throughput),
one API of a library running 25× another (`paramiko#2453`), a stall, a hang. So the claim worth
having is not "faster than X", it is **throughput never falls as the file grows**, and the only
way to have it is to sweep the axis a cliff would hide on.

The ladder is in `conftest.py` as `SWEEP_LADDER`, and every rung is a boundary rather than a
round number: one request, the SSH packet size, two SSH packets, the derived `max-read-length`
of 255 KiB, **one kibibyte past it** so the crossing from one request to two is measured, the
2 MiB channel window, and past `pipeline depth × request size` where depth rather than file size
becomes the limit. Both directions, because `#2438` is a *write* pathology and reads get most of
the tuning attention.

Three things about it are decisions rather than defaults:

- **Each rung runs on one connection with a same-size warmup discarded first.** This is the only
  place the no-connection-reuse rule above is suspended, identically for all three clients. A
  fresh connection per rung would time TCP slow start at the small end (D-81) and publish
  congestion control as a cliff. The consequence: **these numbers are not comparable with any
  other table in the report**, which are all deliberately cold. There is no CPU column for the
  same reason — one connection is one reaped child, so per-sample CPU does not exist.
- **paramiko and asyncssh are swept as controls, reported and never asserted.** The strongest
  form of "we have no cliff" is the same ladder showing someone else's, and an incumbent's
  pathology must not be able to fail this lane. Their falls land in the report's caveats as
  `Control finding`, read off medians without the separability requirement, because an
  incumbent's stall is bimodal and its fast mode would hide it.
- **Our own curve gates, and that is not the gate D-63 is about.** D-63 is the missing
  *regression* gate: it needs a committed baseline to compare a run's figures against, and it is
  blocked on not having one. This assertion needs no baseline and quotes no figure — it compares
  rungs of a single run's curve against each other, and fails when throughput falls below half
  the best measured at any smaller size *by a margin that run's own samples separate*. Whether a
  number moving between runs should fail CI is still D-63's question.

**What this gate cannot catch, measured rather than guessed.** A *fixed* per-transfer cost is
invisible to a monotonicity test wherever the curve is still climbing steeply, because doubling the
size outruns a constant. paramiko is the demonstration: its 32 KiB and 64 KiB uploads stall on a
~42 ms floor, which unshaped is a 99% collapse and fires every detector here — and at 50 ms RTT the
same +32 ms and +39 ms appear on the same two rungs while throughput keeps rising, so the shaped
curve reads as clean. That is why the unshaped profile stays in the sweep: it is the one where a
fixed cost dwarfs the transfer instead of hiding inside a round trip.

Sample counts are per profile (`Profile.sweep_repeats`) because a rung costs about 2 ms unshaped
and 220 ms at 50 ms RTT. The unshaped profile takes 25 samples per small rung and needs them:
three samples there reported 262144 bytes downloading at 0.47× the throughput of 261120, which
read as a real cost for crossing the request boundary. `_plans/probes/size_boundary_probe.py`
took that crossing 25 times and found the opposite — a **one-byte** step from 261120 to 261121
*raises* the median from 2.41 ms to 1.73 ms, because the second request pipelines behind the
first while a single-request transfer has nothing to overlap a scheduler hiccup with. Its p90 is
7.1 ms against a 1.7 ms floor. The fat tail is real; the fall was not.

## The file-object row: having one was never the deliverable

D-86 added a byte-range surface, and D-91's tracker gather attached an acceptance criterion to
it that parity alone would have missed. The incumbent *has* a file object. It is also
`paramiko#2453`: `SFTPFile.read()` reported at 25x slower than the same library's
`SFTPClient.get()`, plus `paramiko#2454`, an open request for an API to turn its prefetching
off. Shipping a file object that reads one `READ` per call and awaits it would have shipped
that complaint under a new name -- and that is the *obvious* implementation, which is why the
criterion is a benchmark row rather than a code review.

So the row measures our file object against **our own `get`**, on the same file over the same
link, and fails the run below half of it. Like the size sweep, it compares two rows of a single
run rather than a figure against a baseline, so it needs no committed baseline and is not the
regression gate D-63 is about.

Block size is on the ladder because it is the one performance decision the surface hands a
caller, and **the shaped profile is what turned that from a caveat into an arithmetic.** A
`get` keeps its window full from the first request to the last. A `read(n)` fills the window,
drains it, and only then issues the next block -- so a cursor read pays **one round trip per
block**, `file_size / block_size` of them, and no block size removes it.

Measured on the 100 Mbit/s 50 ms profile, 16 MiB, against our own `get` at 1.868 s:

| block | wall | vs `get` |
| ----- | ---- | -------- |
| 261120 (one request) | 5.165 s | 0.36x |
| 1 MiB | 2.570 s | 0.73x |
| 2 MiB (the channel window) | 2.309 s | 0.81x |

The 2 MiB row is the arithmetic showing its work: eight blocks, and 2.309 - 1.868 = 0.441 s
against eight round trips of the measured 52.5 ms, which is 0.42 s. The gap is the bubbles and
nothing else, which is why closing it needs read-ahead rather than tuning -- and read-ahead is
deliberately not built (`paramiko#2454` is an open request for an API to switch theirs off).

Unshaped the same ladder reads differently, and both are worth having: with no latency to hide,
1 MiB blocks run at 1.19x `get` -- *faster*, because no local file is written -- and 8 KiB
blocks at 0.10x. A gate written only against the unshaped profile would have concluded the file
object was free.

**Two things in this row are bounded by cost, and both are stated rather than left to a reader
to notice.** The 8 KiB rung runs on the unshaped profile only -- 16 MiB in 8 KiB blocks is 2048
round trips, which at 50 ms RTT is a hundred seconds *per sample* to re-learn what the unshaped
rung already shows. And **paramiko is swept as a control on the unshaped profile only**, for the
same arithmetic one layer over: its file object is round-trip-bound by construction, so a shaped
profile turns each sample into minutes. What the control demonstrates it demonstrates unshaped,
where it is already tens of times its own `get` with no latency to blame for it.

## Two columns, because wall clock alone cannot see the thesis

The claim this library makes is not that it moves bytes faster than `cryptography` can decrypt
them. It is that the SSH work happens in OpenSSH rather than in Python. On a link fast enough
for that to matter, **all three clients hit the same 2 MiB channel window** — that is not a
coincidence, it is the same constant three times:

| implementation | channel window | max packet |
| -------------- | -------------- | ---------- |
| OpenSSH | `CHAN_SES_WINDOW_DEFAULT`, 2 MiB | 32768 |
| paramiko | `transport.DEFAULT_WINDOW_SIZE` = 2097152 | 32768 |
| asyncssh | `connection._DEFAULT_WINDOW` = 2 MiB | 32768 |

So wall clock on a latency-bound profile largely measures a ceiling all three share, and the
CPU column is where the architectures differ. Both are reported, per scenario, with a spread.

**CPU is counted over connect through close, not over the transfer**, and that is forced rather
than chosen: `getrusage(RUSAGE_CHILDREN)` only accounts for children that have been *waited
for*, so the `ssh` subprocess contributes nothing until it has exited and been reaped. Sampling
it mid-transfer means reading `/proc`, which would make the harness Linux-only for a number
that is still an estimate. The `connect` scenario measures the connect half on its own so a
reader can subtract it, and every client is measured through the same window — which is what
makes the comparison fair even though the window is wider than the operation.

That mechanism has its own test, in `tests/test_benchmark_harness.py`: a counter that silently
returned only this process's time would not fail anything, it would just publish a number
saying the thesis is free.

## Fairness rules

Each one could have gone the other way, so each one is written down:

- **Each library uses its own best default API.** `paramiko.SFTPClient.get` prefetches;
  `asyncssh` negotiates `limits@openssh.com` and picks its own block size. Reimplementing
  either to "match" ours would benchmark our idea of them.
- **Everything that steers a client is turned off identically** — no agent, no `~/.ssh/config`,
  no key search. A benchmark that reads the developer's ssh config measures the developer's ssh
  config, and a stray `Compression yes` would move every number without moving any code.
- **All three verify host keys.** `AutoAddPolicy` and `known_hosts=None` would have been
  simpler and would have handed the other two a head start on a check we perform.
- **The small-file scenarios are sequential for all three.** Not because we cannot overlap —
  the multiplexing change closed D-12 and a task group over `get` now overlaps files — but
  because the other two can be driven concurrently as well, paramiko with a thread per
  transfer and asyncssh with a task group. Racing our overlapped path against their `for` loop
  would measure a feature gap while looking like a speed gap. The comparison rows stay
  sequential; what overlapping is worth is its own row, against ourselves.
- **Our upload row has `atomic=False, fsync=False`.** What our default costs is its own
  scenario rather than a penalty silently applied to the comparison.
- **Connections are not reused between samples.** Connecting once and looping hides the cost of
  connecting, which for two of these three libraries is a key exchange performed in Python.
  **The consequence is worth stating, because it went four drafts unnoticed** (D-23): every
  cross-library row here is therefore a connection's *first* transfer, and a deep pipeline spends
  its opening round trips in TCP slow start rather than waiting on the server. That is fair —
  all three pay it — but it is not what a pipeline sustains, and reading these rows as a
  sustained rate is how D-23 came to be filed against our own scheduler for a cost belonging to
  the transport. `download 16 MiB, one connection` is the row that separates the two.
- **Every scenario verifies the bytes it moved.** A client that returns fast and wrong fails;
  it does not win.

## Reading a ratio

Repeats are few — three samples after one discarded warm-up — because a 200 ms profile is slow.
So every row carries a **spread** (slowest run ÷ fastest run), and a ratio drawn from
overlapping sample ranges is printed with `(overlapping)` beside it. That is deliberately not a
significance test: with three samples a *p*-value would be theatre, whereas non-overlapping
ranges is something you can check by eye against the spread column.

A spread near 1.0 means the median means something. A spread near 2 means the profile is noisy
and you should distrust a 1.3× difference in it — which is the usual state of the unshaped
profile, where a 16 MiB transfer takes tens of milliseconds and the run-to-run variation is
larger than anything being compared.

## What the lane has found

Everything below moved here from the README in 0.10, unchanged (D-88). It is kept in one place
rather than summarised in two, and it is kept *whole* — including the rows that go the wrong way,
which are not separable from the ones that go the right way. A version of this section with only
the wins in it would be marketing, and it would be a worse document than the front-loading it
replaced.

Re-derive all of it with `python scripts/lanes.py benchmarks`.

### Bytes in flight, and the ceiling that is not ours

Sustained SFTP throughput is bounded by bytes in flight, not by cryptography:

```
throughput ~= (outstanding_requests * request_size) / RTT
```

OpenSSH's own `sftp(1)` defaults to 64 outstanding requests of 32768 bytes — exactly 2 MiB in
flight, which caps a 100 ms transatlantic link at roughly 21 MB/s regardless of how fast the
machine is. That is a scheduling bug, not a crypto bug, and it is invisible on localhost, which
is why it went unnoticed for two decades.

That formula is measured rather than argued. On a `tc netem`-shaped loopback link against
OpenSSH 10.0p2, raising pipeline depth from 1 to 64 at a fixed 32768-byte request size transfers
the same file **50.7× faster at 5 ms RTT, 36.8× at 50 ms and 24.8× at 200 ms** (2026-07-29) —
and on an unshaped link the same comparison is noise. At depth 1 the elapsed time *is* one round
trip per request, within 3%. That lane is `live-tests/test_netem_pipelining.py` rather than this
directory, and it re-measures on every run.

**Those figures are for a connection that has already moved something**, and the difference is
worth knowing because it is not ours. The same three comparisons on a connection's *first*
transfer come out at 13.0×, 7.6× and 5.0×: a deep pipeline puts about a megabyte in flight
immediately, which is more than an initial TCP congestion window, so its opening round trips are
spent waiting for that window to open rather than for the server. Measured at six round trips
for a 768 KiB transfer as a connection's first, and **one** as its fourth (D-81).

**Throughput follows the product, not either factor.** Three different (depth × size) pairs
multiplying to the same bytes-in-flight figure perform within 4% of each other, and improvement
stops at **2 MiB**: going from 0.5 MiB to 2 MiB in flight roughly doubles throughput, going from
2 MiB to 8 MiB changes it by about 1%, whether the 8 MiB is reached with deep small requests or
shallow large ones. 2 MiB is the channel window in the table above — enforced by the SSH
transport, one layer below anything this library does, so no amount of pipelining lifts it. Two
consequences worth having before tuning anything:

- **`sftp(1)`'s defaults are not timid.** `-R 64 -B 32768` is exactly the channel window. What
  this library fixes is clients that never *reach* 2 MiB, not `sftp(1)`'s inability to exceed it.
- **Past 2 MiB the lever is more channels, not more depth.** One `ssh` child is one channel is
  one window, so concurrent transfers help by reaching the window rather than by exceeding it,
  and a second connection is what gets a second window. Raising depth past the window buys
  memory consumption and nothing else. Neither paramiko nor asyncssh is past 2 MiB today either —
  but both implement SSH and *could* raise their own window, and we cannot raise OpenSSH's,
  because not implementing SSH is the whole point. That is a real cost of this architecture and
  it is written here rather than left for someone to find with a tuned paramiko.

### The same download, cold and warm

`download 16 MiB, one connection` is not a comparison: it is the same file over the same
connection, timed as that connection's first transfer and as its second (D-23).

| RTT | first transfer | second transfer | |
| --- | -------------- | --------------- | --- |
| 50 ms | 18.4 MiB/s | 24.8 MiB/s | **1.35× faster** |
| 200 ms | 4.7 MiB/s | 6.3 MiB/s | **1.35× faster** |

(`tc netem`-shaped loopback against OpenSSH 10.0p2, 2026-07-29.) The warm figure is about 82% of
what the 2 MiB channel window implies, once the three round trips `get` spends on `STAT`, `OPEN`
and `CLOSE` are subtracted — so **the ceiling is reachable, and reaching it is a property of
reusing the connection** rather than of tuning anything. Every cross-library row below is a first
transfer, for all three libraries, because connections are not reused between samples.

### Measured against paramiko and asyncssh

Against **paramiko 5.0.0** and **asyncssh 2.24.0** on OpenSSH 10.0p2 over `tc netem`-shaped
loopback:

| scenario | vs paramiko | vs asyncssh |
| -------- | ----------- | ----------- |
| download 16 MiB | **1.6–3.2× faster** | 1.1–1.4× faster |
| upload 16 MiB | 1.2–1.5× faster | up to 1.5×, level on the rate-limited profile |
| N × 8 KiB download, sequential | ~1.5× faster | **a tie** |
| N × 8 KiB upload, sequential | level shaped (≤1.05×); **1.7–1.8× slower unshaped** | level shaped (≤1.07×); 1.1–1.2× slower unshaped |
| connect and close | **1.2–1.4× slower** | **1.2–2.1× slower** |
| CPU per MiB, download | about the same | **1.2–1.6× worse** |
| CPU per MiB, upload | 1.1–1.6× better | mixed, 0.7–1.4× |

Ratios across 5, 50 and 200 ms RTT plus a 100 Mbit/s rate-limited profile, taken as the **union
of three full runs** rather than the best one. That widening is not padding: the runs put the
download range at 1.9–2.6×, then 1.6–2.3×, then 1.6–3.2×, because paramiko's 200 ms row is
genuinely noisy — its spread column has reached 3.67 across those runs while ours stayed near
1.1. A range that only one run reproduces is a number with an expiry date on it, and the widest
ratio in that table is drawn from the least stable row. Absolute figures, the exact host and the
full caveats are in the report the suite writes.

The **small-file upload row is newer and its range comes from two runs, not three** — it was
added in 0.8 when the size check gave every `put` an extra `STAT` and it emerged that the matrix
could not see a per-file cost at all: every small-file row was a download, and both 16 MiB upload
rows move one file. Those two 16 MiB rows were re-measured in the same pair of runs and did not
move outside the ranges above; at 200 ms RTT the added round trip shows up as roughly +0.15 s on
a 3.3 s transfer, which is the one `STAT` and nothing else.

**Concurrency, measured against ourselves.** The same small-file corpus over one connection,
eight transfers at a time against one at a time: **3.1× on unshaped loopback, 9.1× at 5 ms RTT
and 8.0× at 50 ms**, with CPU per MiB *lower* rather than higher. Us against us, deliberately —
paramiko and asyncssh can be driven concurrently too, so racing our task group against their
`for` loop would measure a feature gap while looking like a speed gap, which is the fairness rule
above. The gain is round trips, which is why it grows with latency and why the unshaped number is
the smallest one here.

### The rows a pitch would not choose, which are the interesting ones

**We lose small-file upload on a fast link, and we win small-file download on the same one.**
Unshaped, 200 × 8 KiB: 3.0–3.2× *faster* than paramiko downloading, 1.7–1.8× *slower* uploading,
same files, same count, same connection. With the round trips nearly free the difference is
per-operation work in Python, and the CPU column says so. It disappears the moment the link has
any latency, where all three tie, so it costs nothing on the networks this library is for and
everything on loopback. It is not the size check — paramiko performs the same one.

**Measured 2026-07-28, and the swing between those two rows is mostly not ours.** Ranging each
library against *itself* on the same corpus and connection: our upload is **1.25×** our own
download, while paramiko's upload is **0.23×** theirs — paramiko's small-file `get` is over four
times its own `put`, and disabling its prefetch does not change that. So the cross-library rows
above are two facts, not one. Our own direction asymmetry is modest and its largest single
component is that `put` reads the local file in a worker thread while `get` calls `os.pwrite`
inline — worth 75–130 µs per file, about a third of the gap. The anyio primitives in that path
are innocent: a task group, a semaphore acquire and an event wait total ~17 µs per file, measured
directly.

**Read the download row with that in mind.** It is an honest measurement of both libraries'
default APIs, which is the fairness rule above — but a good part of the 3× is paramiko's `get`,
not our scheduler. The row that demonstrates what the scheduling actually buys is the
`one connection` one, which is this library against itself.

The upload gap is **measured, understood and deliberately not fixed** (D-72). Restoring the
symmetry means reading small payloads inline, which trades away the property that a slow local
disk cannot stall the receive side — to win back tens of milliseconds on a link with no latency,
which is the one case nobody ships.

**"No cryptography in Python" does not become a CPU win.** `cryptography` is OpenSSL and OpenSSL
uses the CPU's AES instructions, so the expensive part was never interpreted in either design.
What moves out of Python is per-packet framing work, and we pay a pipe copy for it. The thesis
was always that this is a *scheduling* win rather than a crypto one — the wall clock column says
that is right, and the CPU column is what stops the softer claim being written down.

**Connecting is our weak spot, and it is structural.** Spawning `ssh` costs a fork, an exec and
OpenSSH's own configuration parsing before a packet moves — 0.5–0.9 s extra per connection at
200 ms RTT, and 1.5–3.9× the CPU of an in-process handshake. The gap is widest where latency is
lowest (2.1× against asyncssh at 5 ms, 1.2× at 200 ms), which is the signature of a fixed
process-startup cost rather than an extra round trip. For connection-heavy workloads
`ControlMaster` is not an optimisation, it is the fix — and it is the first thing to reach for,
because it is also what pays the cold-transfer cost above once per control socket rather than
once per session.

Nothing here is an unattributed "10× faster than paramiko": every figure names its link, its
server, its versions and the benchmark that produced it, and that benchmark re-runs.

## What these numbers do not say

- Shaped **loopback**, not a network. No competing traffic, no middlebox, and no real bandwidth
  ceiling unless the profile names one.
- **One server implementation**, OpenSSH's `sftp-server`. Nothing here says anything about
  SFTPGo, ProFTPD, MOVEit, GoAnywhere, Cleo or an appliance. That is the server matrix's job and
  it does not exist yet.
- **One machine, one CPU architecture.** The ratios travel better than the absolute numbers.
- Nothing about **memory**, which for a library whose pitch includes bounded buffers is a real
  gap and not a measured result.
- The size sweep runs on **two of the five profiles** and covers `get` and `put`. The file-object
  read path is where `paramiko#2453`'s 25× gap lives and it is not swept, because there is no file
  object yet — D-86 builds one and the sweep is what has to catch a `read(n)` that issues one
  `READ` and awaits it.

## Why paramiko and asyncssh are a separate dependency group

They carry Python cryptography, which is the thing this library exists not to need. Putting
them in `[dependency-groups] bench` rather than in the project's dependencies keeps that true:
nothing shipped gains a crypto dependency, and a checkout that skips the group skips those rows
with a reason instead of failing.

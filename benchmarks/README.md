# benchmarks

Where every performance number this project has comes from, and **no throughput figure is
committed**. A run writes `_reports/benchmarks.md`, which git ignores; this directory keeps the
method, the fairness rules and the scenarios that gate. It is also excluded from the built
distribution, because no packager runs a benchmark and it needs paramiko and asyncssh — the
Python cryptography this library exists not to need — to do anything at all (D-88, D-94).

**One file here is committed and holds numbers, and the distinction it rests on is the point of
this paragraph.** `instructions-<arch>.json` records how many machine instructions this process
retires moving a file. That is a count of **work**, not a rate: it comes out the same on a busy
machine and an idle one, so it says something about this code rather than about a host. A
throughput figure cannot be committed because it is a claim about a machine the reader does not
have; an instruction count can, for the same reason a golden frame can. It is the whole of
D-63's answer, and [the lane it feeds](#the-cost-lane-the-one-that-gates-a-figure) is
below.

The reason is the ranking rule the project is built on: a correctness gap outranks a throughput
feature, and a repository that says so and then carries a table of ratios against its
competitors is arguing against itself. The older half of the rule still governs whatever a run
prints: an unattributed "10× faster than paramiko" is marketing, and a number without its link
profile, its server and its benchmark is an anecdote.

```bash
uv sync --group bench                        # paramiko and asyncssh
python scripts/lanes.py benchmarks           # about ten minutes
python scripts/lanes.py cost                 # about two minutes; needs valgrind, not the group
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
| our own CPU per byte | not a comparison, and **unshaped only**. This process's CPU per MiB in both directions, net of connecting, and the MiB/s ceiling that implies. DESIGN §5.1's route past the 2 MiB channel window is more transports — and one process is one GIL however many `ssh` children it spawns, so this is the ceiling underneath that one (D-113). A link constraint is exactly what it must not measure, which is why it runs on the one profile that is not constraining anything |
| read 16 MiB: file object vs whole file | not a comparison, and the one row besides the sweep that **gates**. Our own `open_file().read()` in fixed blocks against our own `get`, plus paramiko's file object as a control. `paramiko#2453` reports their `SFTPFile.read()` at 25x their own `get`; the obvious implementation of a byte-range read reproduces it, so this row is how we know which one we shipped (D-86) |
| download / upload: throughput against size | the **shape**, on two profiles. Ten sizes bracketing every boundary the design has, so a cliff at a byte count is visible as a curve rather than inferred from two points. It **gates** — see below |
| download / upload: instructions and peak memory against size | **not in this lane, and not wall clock at all.** `scripts/lanes.py cost` counts the instructions this process retires moving a file, which is the one performance number here that may be committed and the one that gates a *figure* (D-63). Its own section is below |

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
- **Our own curve gates, and that is not the gate D-63 was about.** D-63 was the missing
  *regression* gate, blocked on having no baseline it was allowed to commit. This assertion needs
  no baseline and quotes no figure — it compares rungs of a single run's curve against each
  other, and fails when throughput falls below half the best measured at any smaller size *by a
  margin that run's own samples separate*. Whether a number moving between runs should fail CI is
  answered by the instruction lane below, on a different instrument.

**What this gate cannot catch, measured rather than guessed.** Two things, and neither is a
tuning problem.

A *fixed* per-transfer cost is invisible to a monotonicity test wherever the curve is still
climbing steeply, because doubling the size outruns a constant. paramiko is the demonstration:
its 32 KiB and 64 KiB uploads stall on a ~42 ms floor, which unshaped is a 99% collapse and fires
every detector here — and at 50 ms RTT the same +32 ms and +39 ms appear on the same two rungs
while throughput keeps rising, so the shaped curve reads as clean. That is why the unshaped
profile stays in the sweep: it is the one where a fixed cost dwarfs the transfer instead of hiding
inside a round trip.

And a **superlinear** cost passes for as long as throughput is still rising, which can be the
whole ladder. An O(n²) reassembler — one that walks everything it already holds once per arriving
chunk — costs 32% of the wall clock at 16 MiB and produces **no cliff and no dip, in either
direction**, measured in `_plans/probes/superlinear_blind_spot_probe.py`. Nor can the tolerance be
tightened into catching it: the marginal-cost ratio it produces (1.11–1.50 across runs) sits
inside the *same statistic's* range on a healthy run (0.71–1.11). The signal and the noise are the
same size, so this is a limit of the instrument rather than of the threshold — which is what the
instruction lane exists to get past.

## The cost lane: the one that gates a figure

```bash
python scripts/lanes.py cost
```

Everything above times a transfer. This counts one, under `cachegrind`, over a real
`sftp-server` on a pipe — no `ssh`, no network, no comparison libraries. What it reports is
**instructions this process retired**, which is our own CPU per byte: DESIGN §5.2's second
ceiling, and the axis D-112's ~11× improvement in `encode(WRITE)` moved without any clock here
being able to see it.

**Why it may gate when nothing else here may.** Two independent reasons, and both had to hold.
An instruction count is a count of work rather than a rate, so committing a baseline for it does
not breach the rule that keeps throughput figures out of this tree. And it does not move with the
machine: with `PYTHONHASHSEED` pinned a pure-compute workload is **bit-identical** run to run, and
a real 16 MiB download — subprocess, scheduler, `pwrite` and all — reproduces to about 0.06%,
against a wall-clock spread that reaches 10 on the same rungs. That is why this is the only
performance lane that runs on a pull request.

Two assertions, needing different things:

- **The shape.** Marginal instructions per MiB — what the bytes one rung adds over the rung below
  cost — is one number under work that is linear in the file size, whatever the fixed cost per
  transfer is. A rung more than 1.25× the cheapest step below it fails. This needs **no baseline**
  and runs on any machine. Measured margin: a healthy run's steps agree to 1.005, and the O(n²)
  reassembler the wall-clock sweep cannot see comes out at 1.53.
- **The figures**, against `instructions-<arch>.json`, at an 8% band. A rung that got *costlier*
  fails; one that got cheaper is a note asking for the baseline to be refreshed, because a
  baseline left pessimistic stops being able to see the next regression.

The band is the one number here that took three tries, and the wrong answers are worth knowing
about. Two runs of one rung agreed to 0.06%, and a second pair to 0.5% — both of which are what a
sample of two looks like, not what the instrument does. A **24-run pool** of one rung spans 2.6%,
minimum-of-three groups inside it span 2.1%, and a group taken an hour earlier fell below that
pool's floor entirely; across a session the honest figure is about 4%. The variation is not the
interpreter — with the hash seed pinned that part is bit-identical — it is how much of the stream
each `read` returns, which is the operating system's call and moves with what else is running.

So the gate catches a change of roughly a tenth or more, which is where D-112's 11× lives, and it
does **not** catch a single extra copy of the payload on the data path — about 2.6% here. Getting
that would mean holding the read granularity still, which means a deterministic in-process
transport instead of a real pipe. Every run prints its own widest spread next to the verdict, so a
band that has quietly stopped meaning anything is visible in the report rather than inferred.

A count only reproduces against one instruction set and one CPython patch release, and the
baseline records both. Against a machine matching neither, the shape half still gates and the
report states in one line why the other did not — a lane that cannot compare has to say so,
rather than passing because it looked at nothing.

Regenerate with `GANTRY_SFTP_INSTRUCTION_BASELINE=write python scripts/lanes.py instructions`,
then read the diff and commit it. It is never rewritten on your behalf: a baseline that refreshed
itself whenever a run disagreed with it would agree with every run, including the one that made
everything twice as expensive.

### Peak memory, in the same lane and on the same argument

`docs/tuning.md` puts a bound on the deployment screen, where a Cloud Run reader meets it: peak
memory is `concurrent transfers × depth × request size`, about 16 MiB per transfer at the shipped
defaults, and **independent of the file's size in both directions**. Until D-138 the only thing
behind that was `tests/test_packaging.py` checking the sentence against `DEFAULT_PIPELINE_DEPTH`
and `PREFERRED_READ_LENGTH` — arithmetic over the documented values, which cannot say whether a
transfer stays inside them.

Two more assertions, both internal to one run: the peak must not grow with the file across
16 → 256 MiB, and the most a transfer costs over an empty session must stay under the documented
expression plus slack. Measured, the claim holds — the ladder is flat to about 1% in both
directions, and a transfer costs roughly 1.2 MiB over an empty session against a 16 MiB bound.

**The instrument is `VmHWM` from `/proc/self/status`, and `ru_maxrss` is not a portable
alternative to it.** Across `posix_spawn` the child inherits the parent's high-water mark through
the `vfork` window, so `getrusage` in a subprocess-per-rung harness reports whatever the *parent*
did. A first pass using it said this library buffers whole files in both directions, byte-identical
between them — which was the harness, and the tell was that two unrelated code paths agreed to the
kilobyte. One process per rung is required for the same family of reason: a high-water mark can
only ever report the largest transfer the process has already done. Linux only, stated rather than
worked around.

**The gate has been watched failing**, which is the only thing that separates a check from a
claim: the same download with one `read_bytes()` added peaks at 45,800 / 94,504 / 291,228 KiB
against the bounded path's flat ~30,000, and the numbers are pinned in
`tests/test_memory_harness.py`.

**What this lane does not gate**, since its name would suggest otherwise: nothing about
pipelining, round trips or the link. Round-trip counts are asserted elsewhere (D-111), by the same
reasoning — a count is variance-free and is a shape rather than a figure.

Three environment facts, each cheap to get wrong. `cachegrind` is used rather than a perf-counter
tool because `perf_event_open` needs a privilege this project's container does not have, and
cachegrind is userspace simulation that needs none. `setarch --addr-no-randomize`, which the
method this was drawn from recommends, **also** needs a privilege the container lacks
(`Operation not permitted`) — and is unnecessary here, because valgrind lays out the address space
itself. And cachegrind is roughly a two-orders-of-magnitude slowdown, which is why this is a lane
and never a hook — the same reason `mutation` is one.

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

So the ladder climbs towards `get` as the block grows, and the gate sits on the window-sized
rung because that is where the remaining gap stops being a choice: at the window, the shortfall
against `get` is the per-block bubbles and nothing else -- checked on a shaped run by subtracting
the block count times the measured RTT from the difference, which accounts for it. Closing it
needs read-ahead rather than tuning, and read-ahead is deliberately not built (`paramiko#2454`
is an open request for an API to switch theirs off).

**Run both profiles before believing either.** Unshaped, with no latency to hide, the file
object is *faster* than `get` at large blocks -- there is no local file to write -- so a gate
written only against that profile would have concluded the feature was free. The shaped profile
is where the per-block cost exists at all. The figures for each are in the generated report.

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

## Where the figures are

**No throughput figure is here or anywhere committed.** The suite writes its full report to
`_reports/benchmarks.md`, which is gitignored, and that is the only place an absolute rate or a
cross-library ratio lives. Re-derive them with `python scripts/lanes.py benchmarks`; the run
takes about ten minutes and prints the same tables it writes.

The one committed file that holds numbers is `instructions-<arch>.json`, and the rule it obeys
is this section's rather than an exception to it: it carries **counts of work**, which are
properties of this code, not rates, which are properties of a machine and an afternoon. Read the
[cost lane](#the-cost-lane-the-one-that-gates-a-figure) for why that distinction is
the thing that made a regression gate possible at all.

The reason is the ranking rule this project is built on: a correctness gap outranks a throughput
feature, and a repository that says so and then carries a table of ratios against its
competitors is arguing against itself (D-88). The tables lived in this file for exactly one day,
which was long enough to make the point that they had to leave the README and not long enough to
pretend they belonged here instead (D-94).

What survives in the committed tree is this document -- the method, the fairness rules and the
gates -- because those are decisions and they are worth reviewing. A rate is an observation of
one machine on one afternoon, and it ages whether or not anybody re-reads it.

**The line to apply when adding one**, because "no numbers" is not quite the rule and pretending
it is invites the next person to delete something load-bearing: a figure that is *evidence for a
decision in this file* stays -- three samples reading a tail as a cliff is why the unshaped
profile takes twenty-five, and paramiko's stall floor is why the unshaped profile stays in the
sweep at all. A figure that *reports how fast this library is* goes to the report. If a number
would still be true of a rewritten scheduler, it is probably a decision's evidence; if it moves
when the scheduler does, it is a result.

**What is stated here is the half that is a disclosure rather than a claim.** This library is
*slower to connect* than either alternative -- spawning `ssh` costs a fork, an exec and
OpenSSH's own configuration parsing before a packet moves, and for connection-heavy work
`ControlMaster` is the fix rather than an optimisation. And it **wins nothing on CPU**, because
`cryptography` is OpenSSL and the expensive part was never interpreted in either design; what
moves out of Python is per-packet framing, and a pipe copy is paid for it.

Where it is *faster* is in the generated report and not in this sentence, and the asymmetry is
the point rather than modesty: a cost is worth knowing whether or not you trust the person
reporting it, and a win is worth exactly as much as the evidence attached to it. The evidence
does not live in the committed tree.

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

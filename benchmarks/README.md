# benchmarks

The source of truth for every performance claim this project makes. Until this directory had
something in it, no absolute throughput number and no cross-library comparison was allowed to
appear in any document — the rule is in the Docs Rules and it is not decoration: an
unattributed "10× faster than paramiko" is marketing, and a number without its link profile,
its server and its benchmark is an anecdote.

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

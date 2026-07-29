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

Across five link profiles: unshaped, 5 ms, 50 ms, 200 ms, and 50 ms rate-limited to 100 Mbit/s.
The rated one exists because loopback has no bandwidth ceiling unless you configure one, so
every other profile measures latency-bound behaviour only.

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

## Why paramiko and asyncssh are a separate dependency group

They carry Python cryptography, which is the thing this library exists not to need. Putting
them in `[dependency-groups] bench` rather than in the project's dependencies keeps that true:
nothing shipped gains a crypto dependency, and a checkout that skips the group skips those rows
with a reason instead of failing.

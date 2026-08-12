# Why this exists, and what the architecture buys

The design argument, the failures it prevents, and where it costs something.

## Why

**The Python SFTP ecosystem is one library deep.** pysftp, sftpretty, `fs.sshfs` and `smart_open`
are wrappers over a single underlying engine — a general-purpose SSHv2 implementation in which SFTP
is one feature among many. That is an observation about the shape of the ecosystem rather than a
complaint about anyone's code: when SFTP is a feature of an SSH library, SFTP's own problems — how
many requests to keep in flight, what a short read means, how a file becomes visible at its
destination — are nobody's main subject.

So don't write an SSH library. OpenSSH already exists, it is already installed, and one
subprocess hands you a plaintext, framed SFTP byte stream:

```
ssh -o BatchMode=yes -- host -s sftp
```

Everything hard about SSH becomes somebody else's problem, permanently: full `ssh_config`
fidelity, `ControlMaster` multiplexing, post-quantum key exchange, FIDO keys, host
certificates, and every CVE fix without shipping a release. **There is zero cryptography in
this package.** What remains is a protocol codec, a scheduler, and an ergonomics layer.

**The goal is a better SFTP library: safer, more maintainable, more honest about what it is
doing. Being faster is a consequence of being purpose-built for SFTP scheduling, not the
point.** That distinction decides real trade-offs here. A security or correctness gap outranks
a throughput feature, and a performance win is never a reason to ship something less safe. What
the architecture actually buys is surface area nobody here has to own (no crypto to get wrong,
no `ssh_config` to reimplement badly, no SSHv2 stack to maintain) plus the correctness features
the field genuinely needs and no existing option ships: atomic publish, a zip-slip defence,
errors that carry state, and extension fallbacks that are tested rather than assumed.

## The failures this prevents

The reason to switch is not a ratio. It is this list, and every row names the mechanism _and_ the
test that proves it, because a prevention claim without a test is a rumour.

| The failure                                                              | What stops it                                                                                                                                                                                                                                                       | What proves it                                               |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| A consumer picks up a file that is real, plausible and a quarter written | `put()` stages under a temporary name, flushes, then renames, and the result says which mechanism it actually got                                                                                                                                                   | `tests/test_publish.py`, `examples/atomic_publish.py`        |
| A truncated transfer reported as success                                 | a size check on every transfer, and on the way up it runs _before_ the rename, so a short upload never becomes the destination                                                                                                                                      | `tests/test_verification.py`                                 |
| An upload that arrives world-readable                                    | `mode=` is set in the `OPEN` that creates the file, before anything can open it by its published name. Omitting it means `0666 & ~umask`, and a `chmod` afterwards leaves a window                                                                                  | `tests/test_modes.py`                                        |
| Timestamps replaced by the time of the transfer                          | `preserve_times=` in both directions, stamping a descriptor rather than a path                                                                                                                                                                                      | `tests/test_timestamps.py`                                   |
| A hostile filename escaping the destination directory                    | every server-supplied name is checked before it reaches the filesystem: absolute paths, `..`, and a parent directory that is a symlink pointing out of the tree                                                                                                     | `tests/test_localpath.py`, `tests/test_recursive.py`         |
| Two legal remote names silently becoming one local file                  | the collision check asks the filesystem for identity rather than folding the name, so Unicode normalisation and Windows trailing dots come free                                                                                                                     | `tests/test_localpath.py`                                    |
| Two remote _directories_ silently merging into one local one             | a directory is created with `mkdir(exist_ok=True)`, which succeeds through a symlink, so a directory's claim is recorded against the resolved path rather than the link's own inode                                                                                 | `tests/test_recursive.py`                                    |
| A resume that adopts the wrong bytes                                     | a partial that cannot be a prefix is refused, and `resume_check` reports what was actually proven rather than that something was                                                                                                                                    | `tests/test_resume.py`, `tests/test_content_verification.py` |
| A `UnicodeDecodeError` on somebody else's filename                       | bytes end to end: `DirEntry.filename` is bytes, every `Session` method takes `bytes` or `str`, `realpath` returns bytes, and the decode question is decided once on the download side                                                                               | `tests/test_listing.py`                                      |
| A `Path` silently becoming `\incoming\data.csv` on the server            | a remote path is `bytes` or `str` and a `Path` is refused by name. `pathlib` drops a trailing slash and renders separators as backslashes on Windows, and a backslash is a legal character in a POSIX filename, so the server would create it rather than refuse it | `tests/test_path_types.py`                                   |
| A transfer that hangs with nothing to escape it                          | a deadline on every wait, including the send and including the wait for the send lock                                                                                                                                                                               | `tests/test_send_deadline.py`, `tests/test_cancellation.py`  |

**The claim worth making about speed is a shape rather than a ratio**, and it belongs here with the
failures rather than in a table of its own. Nobody experiences a client as a ratio; they experience
it as a pathology — it hangs, it stalls, it slows down at one particular size. So the claim is that
**throughput rises with file size and then plateaus, and never falls**, and it is asserted rather
than reported: ten sizes bracketing every boundary the design has, both directions, and a fall
fails the run. Its limits, stated because they matter: it covers `get` and `put` on two of the five
link profiles. The file object has a gating row of its own, measured against our own `get`.

## No cryptography, and the class of problem that removes

**There is no cryptography of this library's own and no cryptographic dependency.** No cipher,
no key exchange, no signature, no host-key handling, no `known_hosts` parsing — none of it is
here, and none of it is installed. `pip install gantry-sftp` pulls `anyio` and nothing else.
There is one optional extra, `[fsspec]`, and it does not change that sentence — fsspec has no
required dependencies of its own.

**One exception, named because a page you read to rule something out should not need a second
source.** The standard library's `hashlib` is called in three places, all of them the
[`check-file` verification ladder](transfers.md#verifying-a-transfer): the local digest has to be
computed locally to be compared with the server's. Every call passes `usedforsecurity=False`, and
that flag is load-bearing rather than decorative — the server chooses the algorithm, paramiko is
the only implementation of the extension and offers nothing but `md5` and `sha1`, and a FIPS
build refuses to construct `md5` at all. So a FIPS-constrained deployment meets this library's
one crypto interaction at `check_file`, and nowhere else. It is a hash over bytes you already
have, not a primitive protecting anything, which is why the argument below is unaffected.

That is the load-bearing consequence of the architecture, and what it does is *remove* a class of
problem rather than solve it. An SSH implementation written in Python has to track a cryptography
library's deprecation schedule forever, and every turn of that schedule reaches every user
eventually: an algorithm retired upstream, a warning nobody can silence, a binary wheel that will
not load against an older libc, a key type removed in a major version. None of that is anybody's
mistake — it is the standing cost of owning an SSHv2 stack, and it is paid by every library that
owns one. This package owns none of it.

The same fact from the other side: this library cannot lag on a key type, cannot mis-parse
`known_hosts`, and cannot diverge from the `ssh_config` you have already tested with `ssh`, because
it implements none of them. When OpenSSH gains an algorithm or retires one, you get the change from
your OS package rather than from a release here.

**And when a connection fails you get OpenSSH's own stderr, verbatim**, on a typed exception,
carrying a `hint` when there is something to do about it — rather than a message produced by a
Python reimplementation of the handshake, about a handshake it was performing itself. See
[When the connection fails](connecting.md#when-the-connection-fails).

## Where this library is behind

Stated here rather than left for you to discover, because choosing a library on an incomplete
picture is worse than choosing a different one.

- **asyncssh implements SSH in Python and therefore ships things this design cannot reach**:
  `statvfs`, `hardlink` and `copy-data` are on its surface and not on ours. If you need one of
  them, it is the better fit.
- **Transfers refuse on Windows, by design.** The data path uses `os.pread`/`os.pwrite`, which is
  a POSIX constraint rather than an unfinished port. The byte-range surface and everything that
  does not place bytes in a local file work there.
- **Connecting is slower than either alternative**, because spawning `ssh` costs a fork, an exec
  and OpenSSH's own config parsing before a packet moves. For connection-heavy work `ControlMaster`
  is the answer, and it takes one `ssh_config` line **plus** asking for it — this library ships
  `ControlMaster=no` and so declines to host the master. See
  [Connection reuse](connecting.md#connection-reuse-and-why-the-master-is-not-ours-to-start).
- **It wins nothing on CPU.** Moving the cryptography out of Python does not make it free; it makes
  it somebody else's, and the cycles are still spent.

## What is free because OpenSSH does it

None of this is implemented here, which is why none of it can rot here. It is OpenSSH's, and if
your `ssh` can do it, so can this:

- **`ssh_config`, in full**: `Match`, `Include`, `ProxyJump`, `ProxyCommand`, `IdentityFile`.
- **`ControlMaster` / `ControlPath` multiplexing** — the one entry on this list with a caveat, and
  it is ours rather than OpenSSH's. An **existing** master is used with no argument at all, because
  `ControlPath` is untouched. Hosting one is opt-in: this library ships `ControlMaster=no`, so a
  config line alone buys nothing when the only `ssh` on the machine is this one. For
  connection-heavy work it is still the fix rather than an optimisation, because connecting is this
  library's weak spot — it just needs to be asked for. See
  [Connection reuse](connecting.md#connection-reuse-and-why-the-master-is-not-ours-to-start).
- **Host keys signed by a CA**, and an agent with more than one key in it.
- **Reaching a host through a proxy or a bastion**: `ProxyJump`, and `ProxyCommand` for SOCKS. Port
  _forwardings_ are a different feature and this library switches them off on purpose: an SFTP
  client has no business opening one.
- **FIDO `sk-*` keys, GSSAPI, post-quantum key exchange**, and every CVE fix, which arrives with
  your OS package rather than with a release from us.

See [Connecting and authenticating](connecting.md), which is a short page for exactly this reason.

## Speed, and where its numbers are

**Not here, and nowhere else in this repository.** [`benchmarks/`](../benchmarks/README.md) is the
lane, it writes its tables to a report that is **not committed**, and `python scripts/lanes.py
benchmarks` re-derives them in about ten minutes.

That is a decision rather than an omission, and it follows from the ranking above. A figure in a
document is an observation of one machine on one afternoon; it ages without anybody noticing, and a
document that ranks correctness above throughput and then opens with ratios is arguing against
itself. A lane, unlike a paragraph, can fail.

Two things about speed are mechanism rather than measurement, so they are worth stating where you
are reading:

- **Sustained SFTP throughput is bounded by bytes in flight, not by cryptography.** Outstanding
  requests times request size, divided by the round-trip time. That is why this library pipelines
  by default, and why `sftp(1)`'s 64 requests of 32 KiB is the number the whole design argues with.
- **The ceiling is OpenSSH's per-channel flow-control window, 2 MiB, and it is not ours to lift.**
  It is enforced by the SSH transport one layer below anything here, so no amount of pipelining
  exceeds it. See [Tunables](tuning.md#tunables-and-what-they-default-to) for what that means for
  `depth`. It is a real cost of not implementing SSH rather than a detail: a library that owns its
  own transport can raise that window, and this one cannot.

# Does this work against my server?

Nothing in this library has ever been tested against your server. That is not modesty — it is
arithmetic. The endpoints this library exists for are MOVEit, GoAnywhere, Cleo, Sterling and the
mainframe middleware behind them, and every one of them belongs to somebody's employer, sits
behind a VPN, and advertises none of the extensions the reference implementation does. No
maintainer can start one.

So the evidence has to come from you.

```console
$ python -m gantry_sftp doctor sftp.example.com
```

That connects once, reports the negotiation, and then runs a **read-only compatibility
battery**: a list of facts, each with a verdict and the exchange that produced it. It makes no
writes, and it is meant to be pasted into an issue.

## What the report is for

Two questions, one artifact.

**Yours:** does this library work against this endpoint, and where does it not. A `no` in the
report is an answer, not a fault — real endpoints differ from OpenSSH in a dozen ways and work
perfectly well. What matters is knowing *which* dozen before a transfer surprises you.

**Ours:** the same answer, in a form somebody who was not there can review. Every finding
carries the round trips behind it, so what arrives is an argument rather than a claim.

**It is not a plugin.** Nothing the report emits changes what the library does. There is no
profile to install and no registry to contribute to — see
[Which server is at the other end](observability.md#which-server-is-at-the-other-end) for why
the fingerprint deliberately stops at identity. The report is evidence for a human: a bug report
with its workings attached, or the fixture that would justify a behavioural change if one ever
earns its place.

## Reading a finding

```text
  compatibility           5 probed, 5 answered
    no            lsetstat@openssh.com actually changes a symlink's own mode
      the server answered OK and neither mode changed, so the request was accepted and
      discarded. That is worse than the refusal OpenSSH gives on the same kernel: a caller is
      told their permission change happened when it did not
        created b'/incoming/scratch/gantry-probe-4f1c-lsetstat-target' at 0o600 and symlink ...
        lsetstat PERMISSIONS -> OK
        LSTAT of the link -> 0o777
        STAT of the target -> 0o600
```

Four parts, and the last one is why the report exists:

| part         | what it is                                                                    |
| ------------ | ----------------------------------------------------------------------------- |
| **fact**     | a question phrased so `yes` and `no` are both unambiguous                     |
| **verdict**  | `yes`, `no`, or `undetermined`                                                |
| **answer**   | what the verdict means for you, not a restatement of the fact                 |
| **evidence** | the exchange, one line per round trip — request, then what came back          |

### `undetermined` is a real answer

_"This server does not fold case"_ and _"I could not find out whether this server folds case"_
are different, and a report that collapsed them would be exactly the confident-and-wrong artifact
this exists to prevent. So there are two mechanisms and they mean different things:

- an **`undetermined` verdict** means the probe ran and could not tell;
- the **`not determined`** list at the end of the report means the run did not ask, and says why.

The second list is never empty, because a read-only run always declines something. That is
deliberate: a report claiming to have checked everything would be the more dangerous document.

## Advertised is not the same question as working

This is the finding the battery is built around, and it is not hypothetical.
`lsetstat@openssh.com` is advertised by OpenSSH's server and by asyncssh's. On Linux it works on
neither, and the two fail *differently*:

|                                | advertises it | what it actually does                                     |
| ------------------------------ | ------------- | --------------------------------------------------------- |
| OpenSSH `sftp-server` on Linux | yes           | refuses with a contentless `FAILURE`                      |
| asyncssh's server on Linux     | yes           | answers `OK` and changes nothing                          |
| paramiko's `SFTPServer`        | no            | —                                                          |

No advertisement could have told you that, and the second row is the one that costs something: a
caller is told a permission change happened when it did not. Every extension probe therefore
checks the *result*, not the status — the `posix-rename` probe confirms the source is gone, the
`check-file` probe compares the digest against one computed locally, and the `lsetstat` probe
looks at both the link and its target.

## Safe to point at production

The people who can run this will run it against a system their employer depends on, so the
default does nothing a listing does not.

**The read-only battery** canonicalises names that cannot exist, reads two refusals, and asks
`limits@openssh.com` what it already answered at the handshake. It creates nothing, renames
nothing and removes nothing. `--no-probes` turns even that off and leaves you the negotiation
report alone.

**The write battery is opt-in and takes a directory by name.** There is no default and there
will not be one:

```console
$ python -m gantry_sftp doctor sftp.example.com --probe-writes /incoming/scratch
```

Everything it creates begins with `gantry-probe`, carries a random tag for that run, lives in the
directory you named, and is removed before the command exits. Files are created `0600`, so the
window between creation and removal is not a window in which they are world-readable. It writes a
few hundred bytes plus one request of the session's own request size — the same size a `put`
sends continuously, and never larger.

Anything it could not remove is named in the report under `LEFT BEHIND`, with the reason. A probe
that litters a production directory and says nothing would be worse than one that never ran.

## What it asks

**Read-only, on by default with a host:**

| fact                                             | why it matters                                                              |
| ------------------------------------------------ | --------------------------------------------------------------------------- |
| `REALPATH` canonicalises a path that does not exist | whether a path can be resolved before it is created, which uploads want   |
| the root of the namespace is `/`                 | not universal — a gateway may root at a dataset qualifier or a share list   |
| a refusal says more than its status code         | whether anything can be routed on the message, or only on the code          |
| `limits@openssh.com` answers with a usable maximum  | a server can advertise it and answer "no limit" for everything, which leaves the session on this library's conservative default |

**Writes, only with `--probe-writes DIR`:**

| fact                                          | why it matters                                                        |
| --------------------------------------------- | ---------------------------------------------------------------------- |
| names fold case                               | two remote names can become one local file on a folding destination    |
| `RENAME` replaces an existing target          | the draft says it must not; POSIX `rename(2)` says it must             |
| a file's timestamps survive being set         | a server can accept `ACMODTIME` and discard it, which looks like success |
| a request the size of this session's is accepted whole | including a short write, which no exception would report        |
| each advertised extension actually performs   | `posix-rename`, `fsync`, `lsetstat`, `check-file` — the table above     |

Extensions the server did not advertise are not probed. Each has a documented fallback, so a
server that implements one silently costs a slower path rather than a wrong answer.

## Getting the report to us

Paste the text output into an issue. It carries no credential: the evidence is paths, status
codes, the server's own message text, extension names and byte counts, and the environment block
above it goes through the same masking chokepoint as everything else in
[Seeing what it is doing](observability.md). Redact the paths if they are sensitive — the
verdicts stand without them.

For a machine, `--json` renders the same report with the compatibility block under
`server.compatibility`.

## As data

The report is a dataclass before it is text, so a deployment check can assert on it rather than
scrape it:

```python
from gantry_sftp.compatibility import Verdict, compatibility_report
from gantry_sftp.sync import connect

with connect("sftp.example.com") as sftp:
    report = compatibility_report(
        sftp,
        request_bytes=sftp.sizes_for(b"\x00\x00\x00\x00").write_length,
    )

for finding in report.findings:
    print(finding.verdict.value, finding.fact)
    for line in finding.evidence:
        print("   ", line)

for limit in report.undetermined:
    print("not asked:", limit)

assert report.complete  # every fact probed came back with a yes or a no
```

`request_bytes` is passed in rather than derived, because the largest request a session sends
depends on the handle a transfer is holding and this report holds none. `sizes_for` takes a
handle length; four bytes is what OpenSSH issues and what
[`doctor`](observability.md#doctor-the-diagnostic-no-other-python-sftp-library-can-ship) reports
against.

Pass `write_directory=` to add the write battery. `examples/compatibility.py` runs all of it
against a real server with no arguments.

## Where the answers came from

`live-tests/test_compatibility_live.py` runs the whole battery against OpenSSH's `sftp-server`,
asyncssh's server and paramiko's `SFTPServer`, and pins what each one answers. Three
implementations that disagree with each other is the fixture this needs — a battery written
against OpenSSH alone measures OpenSSH and calls it SFTP. A failure there is usually a finding
rather than a bug, which is the same rule [the matrix](development.md) runs under.

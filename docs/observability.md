# Seeing what it is doing

Logs whose fields are data rather than a formatted sentence, counters on the session, a
frame dump, and a diagnostic that tells you what this machine can actually do.

## Seeing what it is doing

Nothing is printed unless you ask. The package logger carries a `NullHandler`, so an
application that never configures `logging` sees nothing at all from this library, including
on stderr, which is where an unhandled warning would otherwise go.

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("gantry_sftp.session").setLevel(logging.DEBUG)  # one record per operation
logging.getLogger("gantry_sftp.transport").setLevel(logging.DEBUG)  # spawn and teardown
logging.getLogger("gantry_sftp.frames").setLevel(logging.DEBUG)  # every packet, both ways
```

| Logger                  | Level   | Carries                                                                          |
| ----------------------- | ------- | -------------------------------------------------------------------------------- |
| `gantry_sftp.session`   | DEBUG   | Handshake, and one record each when an operation starts and finishes             |
| `gantry_sftp.session`   | WARNING | A retryable failure `with_reconnect()` swallowed, the only warning in the tree   |
| `gantry_sftp.transport` | DEBUG   | The `ssh` child: pid, argv, the variables that steer authentication, exit status |
| `gantry_sftp.frames`    | DEBUG   | Every packet sent and received, decoded                                          |

```
DEBUG gantry_sftp.session   negotiated version=3 extensions=6 [b'posix-rename@openssh.com' ...]
DEBUG gantry_sftp.session   get start remote=b'/incoming/data.parquet' local='data.parquet'
DEBUG gantry_sftp.frames    -> STAT id=1 path=b'/incoming/data.parquet'
DEBUG gantry_sftp.frames    <- ATTRS id=1 attrs=(size=16777216 mode=0o100644)
DEBUG gantry_sftp.frames    -> READ id=3 handle=b'\x00\x00\x00\x00' offset=0 len=261120
DEBUG gantry_sftp.frames    <- DATA id=3 len=261120
DEBUG gantry_sftp.session   get ok remote=b'/incoming/data.parquet' bytes=16777216 elapsed=1.284s
```

**The frame dump is per packet and it means it.** A 16 MiB download is a few hundred lines and
a recursive tree is thousands. Turn it on for a protocol question. When it is off it costs one
`isEnabledFor` check per packet and nothing is rendered, which is asserted rather than assumed.

**Payloads are never in it.** `DATA` and `WRITE` show as `len=N offset=M`. That is not
squeamishness: a quarter-megabyte payload per line is unreadable, and rendering it would copy
the `memoryview` that the copy-free data path exists to avoid.

**Every server-supplied name is escaped and truncated.** A filename, a path and a `STATUS`
message are all chosen by the far end, and written raw into a log stream a `\n` forges a second
record while an `\x1b[` sequence drives the terminal of whoever is tailing the file. They are
rendered with `repr`, which escapes both and every non-printable codepoint besides, and
capped at 96 bytes with the dropped count stated, because a 64 KiB filename is legal and a log
line per frame is a disk to fill.

**The cut is in the middle**, so a long value keeps both ends:
`/private/var/folders/df/…+28…/data.csv`. The bound applies to *local* paths as well as remote
ones, and taking the head dropped the filename — the part that identifies the record — while
keeping the prefix every path in the run shares. That is not a remote-name problem: any deep
local tree reaches 96 characters, and a macOS temporary directory does so before the filename
begins.

`gantry_sftp.codec.describe(packet)` is the renderer, and it is public and pure: pass it any
packet and get the same line back, with no logging configured and no session running.

### Structured output: the fields are on the record, not only in the message

Every record the `session` and `transport` loggers emit carries its fields **as data** as well
as in the sentence, under one `LogRecord` attribute. So a JSON sink indexes them instead of
re-parsing text this library formatted:

```python
import json, logging
from gantry_sftp import record_fields


class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps(
            {
                "severity": record.levelname,
                "message": record.getMessage(),
                **record_fields(record),
            }
        )
```

```json
{
  "severity": "DEBUG",
  "message": "put ok local='data.csv' remote=b'/incoming/data.csv' bytes=13 mechanism='POSIX_RENAME' elapsed=0.002s",
  "operation": "put",
  "event": "ok",
  "local": "data.csv",
  "remote": "/incoming/data.csv",
  "bytes": 13,
  "mechanism": "POSIX_RENAME",
  "elapsed": 0.0018
}
```

`record_fields(record)` returns `{}` for a record from anywhere else, so the formatter is safe
on the root logger. The attribute name is `LOG_FIELDS` if you would rather read it directly.

**Three keys are on every record**, and they are what a query selects on before any of the rest:

|             |                                                                                                    |
| ----------- | -------------------------------------------------------------------------------------------------- |
| `operation` | `get`, `put`, `get_tree`, `put_tree`, `sync_tree`, `rmtree`, `spawn`, `close`, `reconnect`         |
| `event`     | `start`, `ok`, `failed`, `retrying` — the field a "started but never finished" query needs         |
| `elapsed`   | seconds, on the closing record. `error` joins it on a failure, carrying the exception's class name |

The rest are per operation: `remote` and `local`; `bytes`; `files`, `directories` and `skipped`
on a tree; `mechanism` on a `put`; `pid`, `argv`, `returncode` and `steering` on the transport;
`attempt`, `attempts` and `delay` on the retry warning.

Four properties worth knowing, because they are decisions rather than accidents:

- **Numbers stay numbers.** `bytes` and `elapsed` arrive as an int and a float, so `bytes > 1e9`
  is a query rather than a substring match that also catches 10240.
- **Names are escaped, and not wrapped in quotes.** A remote name is chosen by the server, so it
  gets the same `repr` escaping the frame dump uses — a `\n` cannot forge a record and the value
  is pure ASCII, which matters because a filename that was never valid UTF-8 would otherwise
  break `json.dumps(...).encode()` in the sink. What it does _not_ get is `repr`'s surrounding
  quotes, since those would become part of the value you filter on. **No key is exempt**, which
  is worth stating because four of them used to be: `operation`, `event`, `error` and `mechanism`
  skipped escaping on the grounds that this library picks them from a closed set. It bought
  nothing — escaping an identifier and taking the quotes back off returns the identifier — and
  `error` is `type(exc).__name__`, which is whatever the class was built with rather than a set
  anybody enumerates.
- **`elapsed` is measured across the operation, including a failed or cancelled one.** A record
  is closed on the way out whichever way the body left, so "started and never finished" means a
  hang rather than an error you did not see.
- **A list stays a list and a mapping stays a mapping.** `argv` is an array and `steering` an
  object, each scalar inside escaped and capped, rather than one long truncated string.

**The frame dump carries no fields, deliberately.** `gantry_sftp.frames` renders through
`codec.describe(packet)`, which returns a string by design — the codec renders, the session seam
emits, and a test enforces the split. A frame dump is text and stays text.

Runnable: `examples/observability.py`.

### Counters

`Session` carries cumulative totals beside the instantaneous gauges, and both are in its `repr`:

```python
sftp.requests_sent  # requests written to this connection, handshake excluded
sftp.replies_received  # replies routed, including ones nobody was waiting for
sftp.bytes_sent  # bytes handed to the transport, framing included
sftp.bytes_received  # bytes read from it
sftp.reaped  # handles closed on behalf of an abandoned OPEN

repr(sftp)
# <Session server=OpenSSH version=3 extensions=6 depth=64 outstanding=17
#  requests=142/125 bytes=4321/16783104 request_timeout=30.0 idle_timeout=60.0>
```

Two `repr`s a second apart is the cheapest diagnosis there is: same `outstanding` and moving
totals is a slow link, and same totals is a stall. `requests_sent` climbing while
`replies_received` does not is a server that has stopped answering.

There is deliberately **no retry counter**. `with_reconnect()` builds a new session per attempt,
so a counter would reset exactly when it became interesting. The WARNING above is where retry
visibility lives, and it names the attempt, the error and the backoff.

### Credentials

A password never reaches argv, a file, or a log record. It travels in the child's environment
via an `SSH_ASKPASS` helper, and:

- the value renders as `'<redacted>'` in any frame-locals dump. Sentry, `pytest --showlocals`,
  `rich` and IPython all render locals with `repr`, and that is the boundary
  `gantry_sftp.transport.Secret` defends. Every entry point taking a `password` wraps its own
  binding, because each holds one in its own frame for the life of the block — see
  [Passwords](connecting.md#passwords) for why that is a list rather than a single site;
- the environment is masked by name before it can reach a log record, so the record says
  `'GANTRY_SFTP_ASKPASS_ANSWER': '<redacted>'`, since the _presence_ of an askpass answer is exactly
  what a failed password authentication needs to know, and the value is not;
- the mask also covers any variable whose name contains `PASSWORD`, `PASSPHRASE`, `SECRET`,
  `TOKEN` or `CREDENTIAL`, including ones this library never sets, so a caller's own `env=`
  overlay is covered too.

What that does **not** cover, stated because a half-understood guarantee is worse than none: a
reporter that calls `str()` rather than `repr()` on a local, a core dump, and
`/proc/<pid>/environ`. The last is the deliberate trade: owner-and-root readable beats `ps`
output readable by every user on the machine.

`examples/observability.py` runs all of this with no arguments.

### `doctor`, the diagnostic no other Python SFTP library can ship

```console
$ python -m gantry_sftp doctor sftp.example.com
```

paramiko and asyncssh **are** the SSH environment, with no external binary, no `ssh_config`
somebody else wrote and no agent socket resolved by a program they do not own, so they have
nothing to introspect. This library spawns OpenSSH, and the price of that dependency is also
the only reason a report like this can exist.

Without a host it reaches no network and answers what a container image needs to know: which
`ssh` would be spawned and how that was resolved, its version, whether this platform supports
transfers, which config file `ssh` will read, which steering variables are set, and the
tunables this build ships. That is the
[Dockerfile check](../README.md#what-it-needs-read-this-before-you-install-it).

With a host it connects once and reports **the same negotiation a transfer performs**: the
protocol version, the identified implementation, every advertised extension split into the ones
this library uses and the ones it ignores, the `limits@openssh.com` answers, the request size
derived from them, the pipeline depth, and where the session starts. That is a better answer to
_why did `posix_rename` not happen_ or _why is this slow_ than any log line, because it is not a
description of the handshake; it is the handshake.

With a host it also runs a read-only **compatibility battery**, which asks what the server
*does* rather than what it advertised and prints the exchange behind every answer. That has a
page of its own — [Does this work against my server?](compatibility.md) — because it is the
report to send when the answer is _it does not_.

| flag                                      |                                                                            |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| `--json`                                  | the same report as JSON, so CI asserts on fields rather than scraping text |
| `--user`, `--port`, `-i`, `--config-file` | as `ssh` takes them                                                        |
| `-o KEY=VALUE`                            | repeatable, so the connection you diagnose is the one that is failing      |
| `--no-probes`                             | skip the battery and report the negotiation alone                          |
| `--probe-writes DIR`                      | also run the probes that create files, in `DIR`, removing them afterwards  |

It is safe to paste into a bug report, which is the point of it: only the variables that steer
`ssh` are read at all, and their values go through the same masking chokepoint as everything
above. There is no `--password`, because a secret does not belong on a command line, and no flag to
replace the environment, because the environment is part of what is being diagnosed.

Exit codes are distinct rather than 0/1: **0** usable · **2** usage · **3** no `ssh` binary ·
**4** platform cannot transfer · **5** host unreachable.

The report is data before it is text. `gantry_sftp.doctor.local_diagnosis()` and
`server_diagnosis()` return dataclasses, so a health check reads fields instead of parsing, and
`examples/doctor.py` does exactly that.

## Which server is at the other end

```python
sftp.profile.name  # "openssh" | "asyncssh" | "paramiko" | "unknown"
sftp.profile.version  # "2.24.0", where the server volunteers one
repr(sftp)  # <Session server=asyncssh/2.24.0 version=3 extensions=11 ...>
```

Worked out from the extension list the handshake already carried, so it costs no round trip,
and attached to capability refusals so "this server does not advertise `posix-rename`" names
the server it is complaining about.

**It is diagnostic only.** Nothing in the library changes behaviour because of it, and that
bound is deliberate rather than a stage not yet reached: a fingerprint is a guess about an
opaque peer, so a wrong guess should cost a wrong name in a log line, never a wrong answer in
a file. `unknown` is a real answer, since many endpoints advertise nothing at all, and it is what
you get rather than the nearest match.

Three profiles ship, not ten, because three is how many `live-tests/matrix.py` can actually
start: OpenSSH, asyncssh and paramiko all serve SFTP and the last two were already installed
as benchmark dependencies. A profile without a test against that server is a rumour.

**There is no registry to contribute a fourth to, and that is deliberate rather than unfinished.**
A profile carries identity and nothing else, so what a user with a MOVEit endpoint could
contribute is a name, a description and one boolean — none of which changes anything. What they
can produce instead is evidence: [Does this work against my server?](compatibility.md) is the
report, and it is the artifact that would justify a behavioural rule if one ever earned its place.

One measurement from that matrix is worth repeating here, because it decides what any
"quirks" layer can ever do. Five distinct failure conditions (`MKDIR` on an existing
directory, `RENAME` onto an existing target, `CREAT|EXCL` on an existing file, `RMDIR` of a
non-empty directory, and `REMOVE` of a directory) produce this:

|          | OpenSSH   | asyncssh                                                                         | paramiko  |
| -------- | --------- | -------------------------------------------------------------------------------- | --------- |
| all five | `Failure` | `File exists` / `File already exists` / `Directory not empty` / `Is a directory` | `Failure` |

**On OpenSSH the error message is a constant function of the error code.** So telling a
transient failure from a permanent one by reading the message, which is the standard proposal
and the thing v3's catch-all `FAILURE` would need, cannot work on the reference server at all.
That is why retry classifies on exception type rather than on message text.

`examples/server_capabilities.py` prints the profile, the advertised extension list and the
session `repr` against whatever you point it at.

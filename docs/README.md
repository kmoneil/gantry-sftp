# gantry-sftp documentation

Start with **[Getting started](getting-started.md)** — install, the one prerequisite `pip` does
not handle, and a first transfer with no event loop involved.

The rest is shaped by task rather than by module.

| Guide | What is in it |
| --- | --- |
| [Getting started](getting-started.md) | Install, the `ssh` prerequisite, your first transfer, and the same code with and without an event loop |
| [Transferring files](transfers.md) | `get` / `put`, atomic publish, resume, content verification, timestamps, permissions, whole trees, and the incremental-ingest loop |
| [Paths, predicates and attributes](paths.md) | `SFTPPath`, the bytes-versus-`Path` rule, `exists` / `is_dir` / `is_file`, a working directory, symlinks and `chmod` |
| [Listing and matching](listing-and-matching.md) | `listdir` / `scandir`, streaming a directory you did not size, and the `glob` dialect |
| [Concurrency and byte ranges](concurrency.md) | Many transfers over one connection, `concurrency=`, `open_file`, and reading part of a file |
| [Connecting and authenticating](connecting.md) | Keys, agents, `ssh_config`, passwords, restricting where a connection may go, and what a failure tells you |
| [Reconnecting and timeouts](reliability.md) | `with_reconnect`, deadlines on every wait, and stopping a transfer cleanly |
| [Seeing what it is doing](observability.md) | Structured logs, session counters, the frame dump, credential redaction, and `doctor` |
| [fsspec, pandas and dask](integrations.md) | `pd.read_parquet("gantry-sftp://…")`, and the two things to know before deploying it |
| [Tunables, and what things cost](tuning.md) | Every knob and its default, round trips per operation, memory per transfer |
| [Why this exists](architecture.md) | The design argument, the failures it prevents, and where this library is behind |
| [Development](development.md) | The suite, the lanes, and what each one exists to catch |

## The other half is runnable

[`examples/`](../examples/README.md) is documentation that executes. One example per user-facing
feature, each works with **no arguments** by spawning a real OpenSSH `sftp-server` on a pipe, and
every one of them is run by the test suite — so an example that has drifted out of step with the
library fails a build rather than misleading a reader.

## Two conventions worth knowing before you read anything else

**A remote path is `bytes` or `str`; a local path is a `Path` or a `str`.** One transfer takes one
of each, and passing the wrong one is refused by name rather than silently converted. The reason
is in [Paths](paths.md#two-kinds-of-path), and it is not pedantry: `pathlib` normalises, a remote
name has to survive byte for byte, and on Windows `str(Path("/incoming/x"))` is `'\incoming\x'`,
which a server would happily create as a *filename*.

**Nothing that could not run reports success.** Every optional server extension has a documented
fallback, and the result object says which one it got — `unavailable` rather than a quiet
downgrade. That shows up in `put`'s `mechanism`, in `content_check`, in `resume_check`, and in
`times`. When a guarantee could not be delivered, you are told, and where you asked for it
explicitly you get an exception instead.

# Examples

One runnable example per user-facing feature. Every one of them runs with **no arguments** —
they fall back to spawning the genuine OpenSSH `sftp-server` on a pipe, serving a temporary
directory, so there is no host to arrange, no key to install and no network involved. It is a
real server either way; the only thing the local mode skips is `ssh`.

```bash
python examples/download.py                       # pipelined get(), with progress
python examples/atomic_publish.py                 # put(), and what "atomic" actually resolved to
python examples/listing.py                        # listdir() and scandir(), and what a listing can't know
python examples/recursive_download.py             # walk() + get_tree(), and the zip-slip refusal
python examples/destination_collision.py          # two remote names, one local file, and the refusal
python examples/recursive_upload.py               # walk_local() + put_tree() + rmtree()
python examples/resume.py                         # interrupt a transfer, then finish it
python examples/retry.py                          # a link that drops, reconnected and resumed
python examples/concurrent_transfers.py           # many transfers over one session
python examples/cancellation.py                   # stop a transfer, and what it leaves behind
python examples/connect_errors.py                 # why the connection failed, as a class
python examples/password_auth.py                  # password= , and where the secret does not go
python examples/observability.py                  # the logs, a frame dump, and the counters
```

Pass a destination to run the same code against a real server:

```bash
python examples/download.py user@host /remote/data.parquet
python examples/atomic_publish.py user@host /remote/incoming
python examples/listing.py user@host /remote/dir
python examples/recursive_download.py user@host /remote/dir
python examples/recursive_upload.py user@host /remote/dir
python examples/resume.py user@host /remote/dir
python examples/retry.py user@host /remote/dir
python examples/concurrent_transfers.py user@host /remote/dir
python examples/cancellation.py user@host /remote/dir
python examples/connect_errors.py user@host
GANTRY_SFTP_PASSWORD=... python examples/password_auth.py user@host
python examples/observability.py user@host /remote/dir
```

`password_auth.py` is the one example that takes its input from the environment rather than
the command line, and that is the lesson rather than an inconvenience: a password passed as an
argument is in the reader's shell history and in `ps` output for every user on the machine.

`test_examples.py` executes each one as a subprocess and fails if it does not exit clean. An
example that has drifted out of sync with the library is a confident, wrong answer somebody
will copy, so they are tested rather than trusted. They skip with a reason when
`openssh-server` is not installed.

| Example                   | Shows                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `download.py`             | `get()`, the progress callback, and where the pipelining happens                                       |
| `atomic_publish.py`       | `put()`, the publish mechanisms, `require_atomic`, and what `atomic=False` costs                       |
| `listing.py`              | `listdir()` vs streaming `scandir()`, attributes that arrive with the listing, and `EntryKind.UNKNOWN` |
| `recursive_download.py`   | `walk()`, `get_tree()`, skipped entries, the names a hostile server gets refused, and `server_root` — why an absolute path costs no probe |
| `destination_collision.py` | `DestinationCollisionError`: two legal remote names that a case-folding destination makes one file, and why the check asks the filesystem rather than the name |
| `recursive_upload.py`     | `walk_local()`, `put_tree()`, `rmtree()`, and the symlink that is neither followed nor deleted through |
| `resume.py`               | `get(resume=)`, `put(resume=)`, and the two refusals — a partial that cannot be a prefix, and atomic without a staging name |
| `preserve_times.py`       | `preserve_times=` both directions, `UploadResult.times`, `entry.modified` — and why `longname` cannot carry a usable date |
| `verify_content.py`       | `verify=Verify.HASH` / `Verify.REREAD`, `content_check`, `resume_check` — and a resume that passes the size check while publishing a corrupt file |
| `retry.py`                | `with_reconnect()`, `is_retryable()`, and why a failed authentication is never retried |
| `concurrent_transfers.py` | many `get()`s over one session, measured overlap, and where an error lands once you fan out            |
| `cancellation.py`         | cancelling a `get()` and a `put()` mid-flight, what the unwind costs, and the staging file that is not left behind |
| `connect_errors.py`       | `AuthenticationError` / `HostKeyError` / `ConnectError`, and OpenSSH's stderr verbatim                 |
| `password_auth.py`        | `password=`, the `SSH_ASKPASS` helper it writes, why `BatchMode` has to be relaxed, and the proof that the secret reaches neither argv nor the exception |
| `observability.py`        | the three loggers, a frame dump of a real transfer, the session counters, and a filename that tries to forge a log record |

## What `atomic_publish.py` is actually showing

The last section uploads the same file twice, once with the default and once with
`atomic=False`, and watches the destination while the bytes move. Against a local
`sftp-server` the output looks like this:

```
in place    1013024 bytes -> /tmp/…/report-in-place.csv  mechanism=in-place  atomic=False
            a watcher saw sizes [0, 261120, 522240, 783360, 1013024, 1013024]...
```

Those intermediate sizes are the bug this library exists to fix: a consumer polling that
directory reads a file that is real, plausible, and a quarter written. With the default the
watcher never sees the destination at all until it is complete, because the bytes were
somewhere else the entire time.

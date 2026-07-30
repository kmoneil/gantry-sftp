# Examples

One runnable example per user-facing feature. Every one of them runs with **no arguments** —
they fall back to spawning the genuine OpenSSH `sftp-server` on a pipe, serving a temporary
directory, so there is no host to arrange, no key to install and no network involved. It is a
real server either way; the only thing the local mode skips is `ssh`.

```bash
python examples/blocking.py                       # the same library from a program with no event loop
python examples/download.py                       # pipelined get(), with progress
python examples/file_object.py                    # byte ranges, a tail, an append, no staging
python examples/atomic_publish.py                 # put(), and what "atomic" actually resolved to
python examples/listing.py                        # listdir() and scandir(), and what a listing can't know
python examples/working_directory.py              # chdir() as a prefix, and what a reconnect does to it
python examples/predicates.py                     # exists()/isdir()/..., and the answer that is neither yes nor no
python examples/recursive_download.py             # walk() + get_tree(), and the zip-slip refusal
python examples/destination_collision.py          # two remote names, one local file, and the refusal
python examples/recursive_upload.py               # walk_local() + put_tree() + rmtree()
python examples/resume.py                         # interrupt a transfer, then finish it
python examples/retry.py                          # a link that drops, reconnected and resumed
python examples/concurrent_transfers.py           # many transfers over one session
python examples/cancellation.py                   # stop a transfer, and what it leaves behind
python examples/connect_errors.py                 # why the connection failed, as a class
python examples/doctor.py                         # what this machine can do, as a report and as data
python examples/password_auth.py                  # password= , and where the secret does not go
python examples/observability.py                  # the logs, a frame dump, and the counters
python examples/server_capabilities.py            # who is at the other end, and what they refuse
```

Pass a destination to run the same code against a real server:

```bash
python examples/blocking.py user@host /remote/dir
python examples/download.py user@host /remote/data.parquet
python examples/file_object.py user@host /remote/dir
python examples/atomic_publish.py user@host /remote/incoming
python examples/listing.py user@host /remote/dir
python examples/working_directory.py user@host /remote/dir
python examples/predicates.py user@host /remote/dir
python examples/recursive_download.py user@host /remote/dir
python examples/recursive_upload.py user@host /remote/dir
python examples/resume.py user@host /remote/dir
python examples/retry.py user@host /remote/dir
python examples/concurrent_transfers.py user@host /remote/dir
python examples/cancellation.py user@host /remote/dir
python examples/connect_errors.py user@host
python examples/doctor.py user@host
GANTRY_SFTP_PASSWORD=... python examples/password_auth.py user@host
python examples/observability.py user@host /remote/dir
python examples/server_capabilities.py user@host
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
| `quickstart.py`           | the shortest program that moves a file: `connect()` in one call, and a whole session's worth of types imported from `gantry_sftp` with nothing reaching into `gantry_sftp.codec` |
| `blocking.py`             | `gantry_sftp.sync`: a `with` instead of an `async with`, `walk` / `glob` as ordinary iterators, `scandir` still a context manager because it still holds a handle, a typed error crossing the thread flat — and `BoundPortal`, for several sessions on one loop or a backend other than asyncio |
| `download.py`             | `get()`, the progress callback, and where the pipelining happens                                       |
| `file_object.py`          | `open_file()`: a header, a tail, a range and an append without staging the file -- plus `read_at` / `readinto_at` fanned out over one handle, which is what the cursor form cannot do, and why block size is the one performance decision this surface hands you |
| `atomic_publish.py`       | `put()`, the publish mechanisms, `require_atomic`, and what `atomic=False` costs                       |
| `listing.py`              | `listdir()` vs streaming `scandir()`, attributes that arrive with the listing, and `EntryKind.UNKNOWN` |
| `working_directory.py`    | `chdir()` / `getcwd()`: a prefix this library prepends because v3 has no working directory, why absolute paths are never touched, why `symlink`'s target is not either, and the reconnect that silently starts you somewhere else |
| `predicates.py`           | `exists()` / `isdir()` / `isfile()` / `islink()` / `getsize()` / `getmtime()` / `makedirs()`, the third state a predicate has — a refusal is not `False` — and the two questions a broken symlink separates |
| `doctor.py`               | `python -m gantry_sftp doctor` as data: `local_diagnosis()` for a container health check with no network, `server_diagnosis()` for the handshake a transfer would make, and the exit codes that let a Dockerfile tell "no ssh" from "host unreachable" |
| `glob_patterns.py`        | `glob()`: the `glob(3)` dialect and where it differs from `fnmatch`, the dotfile rule, `**`, a trailing `/`, and a match whose path goes straight to `get()` — then the same job with a **regex**, which no pattern can express, over `check_listed_name` / `join_remote` / `local_child` |
| `fsspec_urls.py`          | `gantry_sftp.fsspec`: why registration is explicit and what `sftp://` already resolves to, `ls` and `info` agreeing about a symlink where the incumbent's disagree, byte ranges through a URL, and a password that reaches the constructor and none of the four surfaces fsspec would serialise it into |
| `recursive_download.py`   | `walk()`, `get_tree()`, skipped entries, the names a hostile server gets refused, and `server_root` — why an absolute path costs no probe |
| `destination_collision.py` | `DestinationCollisionError`: two legal remote names that a case-folding destination makes one file, and why the check asks the filesystem rather than the name |
| `recursive_upload.py`     | `walk_local()`, `put_tree()`, `rmtree()`, and the symlink that is neither followed nor deleted through |
| `resume.py`               | `get(resume=)`, `put(resume=)`, and the two refusals — a partial that cannot be a prefix, and atomic without a staging name |
| `preserve_times.py`       | `preserve_times=` both directions, `UploadResult.times`, `entry.modified` — and why `longname` cannot carry a usable date |
| `permissions.py`          | `mode=` and `Mode.PRESERVE` both directions, `chmod()`, `UploadResult.mode` — why an upload is world-readable without it, and why a `chmod` afterwards is not the same thing |
| `links.py`                | `symlink()` / `readlink()` / `chown()` / `utime()` / `truncate()` / `fstat()`, one ATTRS flag per call, and `follow_symlinks=False` — where it works, where it is refused, and the one place Linux itself makes it impossible |
| `verify_content.py`       | `verify=Verify.HASH` / `Verify.REREAD`, `content_check`, `resume_check` — and a resume that passes the size check while publishing a corrupt file |
| `retry.py`                | `with_reconnect()`, `is_retryable()`, and why a failed authentication is never retried |
| `concurrent_transfers.py` | many `get()`s over one session, measured overlap, where an error lands once you fan out — and `get_tree(concurrency=)`, which is a bounded pool rather than the same thing with a loop, plus `resume=` over a finished tree |
| `cancellation.py`         | cancelling a `get()` and a `put()` mid-flight, what the unwind costs, and the staging file that is not left behind |
| `connect_errors.py`       | `AuthenticationError` / `HostKeyError` / `ConnectError`, OpenSSH's stderr verbatim, and the two cases where `hint` says what to do -- including a missing `ssh` client, where there is no stderr at all |
| `password_auth.py`        | `password=`, the `SSH_ASKPASS` helper it writes, why `BatchMode` has to be relaxed, and the proof that the secret reaches neither argv nor the exception |
| `observability.py`        | the three loggers, a frame dump of a real transfer, the session counters, and a filename that tries to forge a log record |
| `server_capabilities.py`  | `session.profile`, the advertised extension list, and `check_file()` refusing — with the rung-3 fallback that every real endpoint takes |

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

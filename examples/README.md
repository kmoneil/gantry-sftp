# Examples

One runnable example per user-facing feature. Every one of them runs with **no arguments** —
they fall back to spawning the genuine OpenSSH `sftp-server` on a pipe, serving a temporary
directory, so there is no host to arrange, no key to install and no network involved. It is a
real server either way; the only thing the local mode skips is `ssh`.

```bash
python examples/download.py                       # pipelined get(), with progress
python examples/atomic_publish.py                 # put(), and what "atomic" actually resolved to
python examples/listing.py                        # listdir(), and what a listing can't know
python examples/recursive_download.py             # walk() + get_tree(), and the zip-slip refusal
python examples/recursive_upload.py               # walk_local() + put_tree() + rmtree()
python examples/connect_errors.py                  # why the connection failed, as a class
```

Pass a destination to run the same code against a real server:

```bash
python examples/download.py user@host /remote/data.parquet
python examples/atomic_publish.py user@host /remote/incoming
python examples/listing.py user@host /remote/dir
python examples/recursive_download.py user@host /remote/dir
python examples/recursive_upload.py user@host /remote/dir
python examples/connect_errors.py user@host
```

`test_examples.py` executes each one as a subprocess and fails if it does not exit clean. An
example that has drifted out of sync with the library is a confident, wrong answer somebody
will copy, so they are tested rather than trusted. They skip with a reason when
`openssh-server` is not installed.

| Example             | Shows                                                                        |
| ------------------- | ---------------------------------------------------------------------------- |
| `download.py`       | `get()`, the progress callback, and where the pipelining happens              |
| `atomic_publish.py` | `put()`, the publish mechanisms, `require_atomic`, and what `atomic=False` costs |
| `listing.py`        | `listdir()`, attributes that arrive with the listing, and `EntryKind.UNKNOWN`  |
| `recursive_download.py` | `walk()`, `get_tree()`, skipped entries, and the names a hostile server gets refused |
| `recursive_upload.py` | `walk_local()`, `put_tree()`, `rmtree()`, and the symlink that is neither followed nor deleted through |
| `connect_errors.py` | `AuthenticationError` / `HostKeyError` / `ConnectError`, and OpenSSH's stderr verbatim |

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

# fsspec, pandas and dask

A remote file behind a URL, for the ecosystem that expects one.

## pandas, dask and anything else that speaks fsspec

```python
from gantry_sftp.fsspec import register

register()  # once, at startup -- never on import, and the reason is below

import pandas as pd

frame = pd.read_parquet("gantry-sftp://bob@example.com/incoming/events.parquet")
```

Install it with the extra: `pip install gantry-sftp[fsspec]`. Nothing else in the library
needs fsspec, and importing `gantry_sftp` does not import it.

**Registration is explicit, and that is a security decision.** `sftp://` and `ssh://` are
_already_ registered inside fsspec itself, to an implementation that wraps paramiko —
and fsspec's `register_implementation(..., clobber=False)` **succeeds silently** when nothing
has resolved `sftp://` yet, raising only once something has. Which of the two you get is
decided by import order. So this library claims nothing on import; you say which name you
want:

```python
register()  # `gantry-sftp://`, a name nothing else claims
register("sftp", override=True)  # take `sftp://`, deliberately and in writing
```

`register("sftp")` without `override=True` raises and names what already holds the protocol. A
library that changed what `pd.read_parquet("sftp://…")` does merely because it was installed
would be making a decision that belongs to the person writing the program.

**What taking `sftp://` buys you, and it is worth knowing before you decide.** The
implementation that ships inside fsspec and currently answers `sftp://` calls
`set_missing_host_key_policy(AutoAddPolicy())` unconditionally — so an `sftp://` URL in the
pandas and dask ecosystem today accepts whatever host key it is offered, which is
trust-on-first-use with the trust part removed. Ours spawns `ssh`, which reads your real
`known_hosts` and refuses. Three more differences:

- **`ls` and `info` agree about a symlink.** An `ls` that reads the listing's attributes
  reports a symlink as `"link"`, while an `info` that calls `stat` follows it and reports the
  same path as `"file"` — and fsspec's own docstring says `info` returns "exactly the same
  information as `ls`". Here both follow, so `isfile` on a symlinked parquet is `True` and
  something will actually open it. `islink` is a separate key, as it is in fsspec's own
  `LocalFileSystem`.
- **A file object that does not cost a round trip per read.** `_fetch_range` goes through the
  same scheduler a whole-file `get` uses, over one handle held for the object's lifetime.
- **A server that omits attributes does not crash the listing.** `S_ISDIR(None)` is a
  `TypeError` on the other side; here an entry the server did not describe is `"other"`, and
  a broken symlink is reported rather than dropped or raised.

**Downloading into a stream works; uploading out of one is refused.** `fs.get_file(url, sink)`
with an open binary file — or the equivalent `outfile=` — writes into it, and the stream is
left open for you to keep writing to. `fs.put_file(sink, url)` raises `TypeError` naming what
to do instead.

The asymmetry is fsspec's rather than ours, and both halves of it are worth knowing. On the
download side, `AbstractFileSystem.get_file` accepts a file-like destination and then calls
`_parent()` on the same object, so every backend that has not overridden it — `MemoryFileSystem`
among them — raises `AttributeError` from inside fsspec instead. `LocalFileSystem` overrides it
and works, so this adapter matches `LocalFileSystem`. On the upload side *nothing* accepts one,
and the reason is not an oversight: a stream you write to needs no offsets, while a stream you
read from has no size, no seek and no second read — which is
[verification](transfers.md#verifying-a-transfer), [resume](transfers.md#resume) and retry
respectively. An upload from
a stream would be a second transfer path with none of the guarantees `put` exists for. Write the
bytes to a file, or use fsspec's `pipe_file(path, value)` for a value already in memory.

**Errors change shape at this boundary, deliberately.** fsspec's contract is `FileNotFoundError`
— `AbstractFileSystem.info` is documented to raise it, `exists` is written around it, and pandas
tests for it by name — so the adapter translates: `NoSuchFileError` becomes `FileNotFoundError`
and `PermissionDeniedError` becomes `PermissionError`, with the original on `__cause__` so the
status code and the server's message survive. Everywhere else in this library an
[`SFTPError` is not an `OSError`](connecting.md#when-the-connection-fails), and it stays that way; the
translation happens here and nowhere else. The predicates you get through `fs` are fsspec's too,
which means they swallow every exception including a refusal — reach for
[`Session.exists`](paths.md#is-it-there) when "not there" and "not allowed to look" have to differ.

### The URL form

```
gantry-sftp://[user[:password]@]host[:port]/absolute/path[?parameters]
```

The path is always absolute — fsspec has no way to express a relative one — so `cwd=` is how
you name a relative root. fsspec parses the authority and hands the **query string back
unparsed**, so these parameters are this library's own, and they are the arguments
[`connect()`](../README.md#status) already takes:

|                                            |                                                                                                 |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `user`                                     | as on `connect()`                                                                               |
| `port`                                     | as on `connect()`, and also expressible as `host:port`                                          |
| `cwd`                                      | a remote working directory relative paths resolve against                                       |
| `depth`, `request_timeout`, `idle_timeout` | the [tunables](tuning.md#tunables-and-what-they-default-to). `request_timeout=none` means "wait forever" |

An unknown parameter **raises** rather than being ignored: a misspelled `identiy_file` that
silently does nothing is a connection that fails for a reason the message will not name. And
`?password=` raises too, naming the two spellings that work — the authority form
`user:password@host`, or `storage_options`, which keeps it out of the URL string altogether.
That one is not a security boundary; a query spelling would grant nothing the authority does
not already grant. It is there because calling `password` "unknown" would be false.

**Four arguments `connect()` takes cannot come from a URL**, and this is a security boundary
rather than an omission. `identity_file`, `config_file` and `ssh_executable` each name a
**local** path, and before the first release all three were accepted as query parameters. Two of them were
remote code execution from a URL string:

- `?ssh_executable=` is `argv[0]`. The URL chose which program this library spawned.
- `?config_file=` is `ssh -F`. An `ssh_config` may carry a `ProxyCommand`, which runs a program
  to obtain the connection, and a `Match exec`, which runs one during config _parsing_ before
  any connection is attempted. No `-o` default neutralises either. So a URL plus one
  attacker-writable file anywhere on disk — an uploads directory, `/tmp` — was arbitrary
  command execution.

Both were measured against OpenSSH 10.0p2, not reasoned about, and
`tests/test_fsspec.py` carries the proof for each. The asymmetry is the whole of the argument:
a constructor argument is written by the author of the program, while a URL arrives from a job
config, a notebook parameter, a database row or an API request — which is precisely the
population this adapter exists to serve, since `pd.read_parquet` of a URL somebody else chose
is the reason it is here at all.

`options` is the fourth and it was never accepted — it is named here because before the first release that
was true only because nobody had added it, which is not a rule and cannot fail a test. It is
also the most dangerous of the four: `-o ProxyCommand=…` is the same execution payload, and
`-o StrictHostKeyChecking=no` silently removes the defence that makes an attacker-chosen
destination survivable. **A safe-subset allowlist was considered and refused**: the directives
that execute or load code are neither short nor stable — `ProxyCommand`, `LocalCommand`,
`KnownHostsCommand` and `Match exec` run programs, `PKCS11Provider` loads a shared library,
`Include` pulls in another config file whole — and a new OpenSSH release can add one more, with
arbitrary execution as the price of missing it.

A test reads the constructor's signature and requires every argument to be classified as
URL-settable or not, so the next one added cannot reach a release without that decision being
made.

Pass them to the filesystem instead, where they are unchanged:

```python
fs = fsspec.filesystem("gantry-sftp", host="example.com", identity_file="~/.ssh/id_ed25519")

# or, through storage_options
pd.read_parquet(
    "gantry-sftp://example.com/incoming/events.parquet",
    storage_options={"config_file": "/etc/gantry/ssh_config"},
)
```

### Three things about fsspec's own design to know before you deploy this

None is a defect of this adapter, and each will surprise you if nobody says it.

- **One connection per thread, not per host.** fsspec caches filesystem instances by a token
  that includes the thread id, and the cache holds a strong reference on purpose, so
  `__del__` never fires and there is no `close()` in fsspec's contract. A thread pool calling
  `pd.read_parquet` therefore opens one `ssh` child per thread. The connection is opened
  lazily — resolving a URL costs nothing — and `close()` plus a context manager are provided
  for when you want to decide; `skip_instance_cache=True` is the spelling for "a connection I
  control".
- **A password in a URL is a password in `storage_options`** for every other fsspec
  filesystem, which is what `__reduce__` pickles — so a dask scheduler ships it to every
  worker — and what `to_json()` serialises, with `include_password` defaulting to `True`.
  **Not here**: `_strip_tokenize_options` means the password reaches the constructor and never
  reaches `storage_options`, so none of those carry it. It is held on the instance, because the
  connection is opened lazily and something has to remember it — as a `Secret`, whose `repr()`
  is `'<redacted>'`, so an object dump of a cached filesystem does not disclose it either. The
  cost is stated rather than hidden — the password is not part of the cache token either, so two
  filesystems differing only in password come back as one instance holding the first.
- **That cost is an authentication one.** The second caller's password is never checked against
  anything, so a password that is *wrong* for the account still gives a working session,
  authenticated by whoever constructed first. With one principal in the process that is a stale
  connection. With several — a dask worker, a notebook server, a shared ETL job — knowing a
  username is enough to inherit a colleague's session, and no log distinguishes it, because it
  is a legitimate connection that simply is not theirs. **Pass `skip_instance_cache=True`
  whenever more than one principal can reach the process.** Keeping the password out of the
  token stays right regardless; this is what its price is.
- **`ls()` holds the whole directory, and the server decides how big that is.** fsspec's
  contract is that `ls` returns a list, so there is no streaming form of it to reach for and no
  override that could add one. A directory with millions of entries — or a hostile server
  answering `READDIR` with new names forever — is unbounded allocation driven by the peer.
  Nothing is capped, because a silent cap breaks the legitimate large directory *and* reports
  success. When the directory is untrusted or merely enormous, drop to
  [`Session.scandir`](listing-and-matching.md#streaming-a-directory-you-did-not-size), which
  holds one batch.

Runnable: `examples/fsspec_urls.py`.

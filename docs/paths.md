# Paths, predicates and attributes

A remote path is bytes and a local path is not, which is the one rule worth reading before
the rest. `SFTPPath` gives the remote side `pathlib`'s shape over that rule.

## Two kinds of path

One transfer takes one of each, and the rule is different on each side:

```python
await sftp.get("/incoming/data.csv", Path("downloads/data.csv"))
#              ^ remote: bytes or str              ^ local: Path or str
```

A **remote** path is `bytes` or `str`. It goes on the wire as bytes, and a `str` is encoded with
`surrogateescape` so a name the server sent, which is frequently not valid UTF-8, can be sent
straight back. A **local** path is a `Path` or a `str`, because it is opened by this process.

**A `Path` for the remote side is refused, and that is deliberate rather than unimplemented.**
`pathlib` normalises, and a remote name has to survive byte for byte:

- `PurePosixPath("/incoming/")` is `PurePosixPath('/incoming')`, so the trailing slash is gone
  before the library ever sees it;
- `str(Path("/incoming/data.csv"))` on **Windows** is `'\incoming\data.csv'`, and a backslash is
  a perfectly legal character in a POSIX filename. The server would not refuse it. You would get
  a file _named_ `\incoming\data.csv`, in whatever directory the session started in.

So the refusal is a `TypeError` naming the rule, not an `os.fsencode` that looks like a
convenience. Pass `str(path)` when the path really is posix-shaped, or the bytes the server gave
you.

## `SFTPPath`, which is the remote side with the arithmetic attached

`pathlib`'s shape over a remote name, bound to a session:

```python
from gantry_sftp import SFTPPath, connect

async with connect("example.com", user="bob") as sftp:
    incoming = SFTPPath("/incoming", session=sftp)

    async for csv in incoming.glob("2026/*.csv"):
        await csv.download(local_dir / os.fsdecode(csv.name))

    receipt = incoming / "receipt.txt"          # one validated component
    await receipt.write_text("done\n")          # created 0600, not 0666
```

`name` / `parent` / `parts` / `stem` / `suffix` / `suffixes` / `parents`, `/` and `joinpath`,
`with_name` / `with_stem` / `with_suffix`, `relative_to` / `is_relative_to`, `match`,
`is_absolute` — none of which need a connection — and then `stat` / `lstat`, `exists` / `is_dir` /
`is_file` / `is_symlink`, `size` / `mtime`, `iterdir` / `glob` / `rglob`, `mkdir` / `rmdir` /
`rmtree` / `unlink`, `rename` / `replace`, `resolve` / `readlink` / `symlink_to` / `chmod`,
`open` / `read_bytes` / `write_bytes` / `read_text` / `write_text`, and `download` / `upload` /
`download_tree` / `upload_tree`. `gantry_sftp.sync.SyncSFTPPath` is the same thing without the
`await`s.

Four decisions in it are worth knowing before you use it, because each one could have gone the
other way.

**Strings go in, bytes come out.** `path.name` is `bytes`, like `DirEntry.filename` and
`realpath` and everything else here, because a remote name is bytes whose encoding the protocol
never states. `str(path)` is a view — it decodes with `surrogateescape`, so re-encoding it gives
back `bytes(path)` for any name at all — and `bytes(path)` is the value. Nothing is ever
normalised: a trailing slash stays, `//` stays, and a backslash is a character in a name rather
than a separator.

**`/` takes one component and checks it; the constructor does not.** The right-hand side of a
join is almost always `entry.filename`, which the _server_ chose, so `path / name` refuses a
separator, a NUL, an empty name, `.` and `..` with `UnsafePathError` — the same predicate `glob`
and the recursive operations use. Go up with `.parent`, which needs no string. The constructor
takes `SFTPPath("/a/../b")` without complaint, because that argument was written by you and
`sftp.stat("/a/../b")` accepts it too. Trust comes from who wrote it.

**The binding is explicit, and there is no URL constructor.** `SFTPPath("/incoming")` is pure
arithmetic and raises `StateError` — naming `session=` and `.bind()` — if you ask it to touch the
wire. A path derived from a bound one stays bound. `SFTPPath("sftp://host/incoming")` would need
a module-level default client, and this library does not have one.

**It is not a `str` subclass and not `os.PathLike`.** A `str` subclass inherits `+`, `%` and
`.replace()`, none of which route through the joining check — a type that lets you rebuild the
hazard with `path + name` is the defence with a hole in it. And defining `__fspath__` would admit
a _remote_ name into `open()`, `os.stat()` and every other stdlib function that takes a path, all
of which would then operate on the local filesystem.

Two things it deliberately does not do. It never folds case: two paths differing in case are two
paths, and the collision that actually bites is a case-folding _local_ disk, which
[`get_tree` already checks](transfers.md#two-remote-names-one-local-file) by asking `lstat` after the write.
And `glob` / `iterdir` yield paths rather than entries, so where you need the size or the type
the listing already carried, `sftp.scandir` and `sftp.glob` hand you the whole `DirEntry` and
cost no extra round trip.

`examples/paths.py` runs all of it.

## Is it there?

```python
if not await sftp.exists("/incoming/2026"):
    await sftp.makedirs("/incoming/2026/q3")
```

`exists`, `isdir`, `isfile`, `islink`, `getsize`, `getmtime` and `makedirs`, each of them
taking bytes or `str`, like everything else on the session.

**`False` means the server said `NO_SUCH_FILE`, and only that.** Every other refusal is
raised. This is the one decision in this section worth reading, because the obvious
implementation gets it wrong:

| The server answers  | Because                                                                                                              | `exists()` |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------- |
| `NO_SUCH_FILE`      | it is not there, and also `ENOTDIR`, a path under a file, and `ELOOP`, a symlink loop                                | `False`    |
| `PERMISSION_DENIED` | a directory on the way may not be traversed                                                                          | **raises** |
| `BAD_MESSAGE`       | the name is longer than the far end's `NAME_MAX`. The code reads as _your frame was malformed_; it is `ENAMETOOLONG` | **raises** |
| `FAILURE`           | v3's catch-all: a full disk, a read-only mount, whatever the server felt like                                        | **raises** |

A predicate that collapsed those into `False` would report a path as free when something you
cannot see is sitting on it, and the next line in almost every program that calls `exists()`
creates something there. So `if not await sftp.exists(p)` needs no `try` around it: the
answer is either an answer or an exception that names the path and the refusal.

`isdir`, `isfile` and `islink` add one more state. v3 carries the file type inside the
permission bits, and a server is not obliged to send any, which is the same `EntryKind.UNKNOWN`
a listing can report. They raise `CapabilityError` there rather than answering `False`, because
"not a directory" is a definite answer to a question the server did not answer.

### Following the link, or not

`exists`, `isdir`, `isfile`, `getsize` and `getmtime` take `follow_symlinks=` and default to
`True`, matching `os.path`. `islink` does not take it: resolving the link first is what makes
its question unanswerable.

A **broken** symlink is where the two spellings separate, and the difference is the one
publishing cares about:

```python
await sftp.exists("/incoming/yesterday.csv")  # False -- no file there
await sftp.exists("/incoming/yesterday.csv", follow_symlinks=False)  # True  -- name is taken
await sftp.islink("/incoming/yesterday.csv")  # True
```

### One attribute, and the answer that is missing

```python
size = await sftp.getsize("/incoming/data.parquet")  # int | None
when = await sftp.getmtime("/incoming/data.parquet")  # datetime | None, aware, UTC
```

`None` means the server sent an ATTRS with no such field, which is legal in v3 and not the same
as zero or as 1970. A file that is not there **raises** instead, so the `None` means exactly one
thing. `getmtime` returns an aware UTC `datetime` rather than `os.path.getmtime`'s float, for
the reason `modified_at` exists: `datetime.fromtimestamp(seconds)` with no timezone gives the
_client's_ local wall clock and then disagrees with everything rendered server-side. It is
second-granular, because v3 has no sub-second field.

### `makedirs`

`os.makedirs` semantics, including the asymmetry: an existing **ancestor** is never an error,
and `exist_ok` governs the last component only. It costs one round trip when the parent is
already there, and walks up a level at a time only where one is genuinely absent.

Where something is in the way, the error says what. v3 answers a failed `MKDIR` with the
contentless `FAILURE`, and OpenSSH sends the single word `Failure` for an occupied name, a
full disk and a read-only mount alike, so the note is the diagnosis:

```
ServerError: server returned FAILURE: Failure path=b'/incoming/2026'
  b'/incoming/2026' already exists and is a file, not a directory, so nothing can be
  created at that name until it is moved or removed
```

The path named is the deepest level that actually failed, which is not always the one you
asked for: `makedirs("/locked/a/b")` against a directory you may not write reports
`/locked/a`, because that is the one to fix.

Planning a scheduled ingest on top of `entry.modified`? Read
[Incremental ingest](transfers.md#incremental-ingest-and-the-two-ways-it-loses-data) first — the
one-second granularity turns the obvious loop into silent data loss.

## A working directory, which this protocol does not have

```python
await sftp.chdir("/incoming/2026")
await sftp.get("data.csv", "data.csv")  # /incoming/2026/data.csv
await sftp.getcwd()  # b'/incoming/2026'
```

**SFTP v3 has no working directory.** There is nothing on the wire to set and nothing to ask, so
`chdir` is a prefix _this library_ prepends to relative paths. Every method takes it, including
`stat`, `glob`, `walk`, `get_tree` and `open_file`, because they share one resolver rather
than each remembering to apply it.

Before any `chdir`, relative paths are left alone and the **server** resolves them against its
own default directory. `getcwd()` reports that until you move; `session.server_root` is the same
value and never moves.

Four things worth knowing:

- **`chdir` costs two round trips and checks two things.** A `REALPATH`, so what is stored is
  canonical, since a prefix holding `..` is one a symlink can redirect between the `chdir` and
  the operation. Then a `STAT`, because `REALPATH` checks nothing: canonicalising a path that does
  not exist _succeeds_ on OpenSSH, so without it a `chdir` to a typo would be accepted and every
  later call would fail somewhere else, naming a path you never typed.
- **Absolute paths are never prefixed**, so mixing the two is safe and a path this library hands
  you back from `walk`, `glob` or `realpath` can be passed straight back in.
- **`symlink()`'s target is not prefixed.** It is a string stored _inside_ the link and
  interpreted by the server relative to the link's own directory, so
  `symlink("data.csv", "alias.csv")` stays the relative link a shell would make.
- **It does not survive a reconnect.** `with_reconnect` builds a new session per attempt and
  nothing survives one: not the handles, not the request ids, not the limits. Call `chdir`
  _inside_ the operation, the same way you re-establish everything else.

On a server whose namespace is not rooted at `/`, `chdir` refuses with `CapabilityError`: a
prefix is `/` arithmetic, and the draft defines no other filename syntax. `getcwd` still answers,
because reporting where you are asks no arithmetic. See
[Servers whose namespace is not rooted at `/`](transfers.md#servers-whose-namespace-is-not-rooted-at-).

## Changing attributes, and links

```python
await sftp.chmod("/remote/report.csv", 0o640)
await sftp.chown("/remote/report.csv", uid=1000, gid=1000)
await sftp.utime("/remote/report.csv", atime, mtime)  # whole seconds
await sftp.truncate("/remote/report.csv", 0)

attrs = await sftp.fstat(handle)  # the file you hold, not the name
target = await sftp.readlink("/remote/current")
await sftp.symlink("/remote/v2", "/remote/current")  # target first, like os.symlink
```

**Each sends exactly one attribute flag, and that is a correctness decision rather than an
economy.** OpenSSH's `process_setstat` walks the flags in sequence (size, permissions, times,
owner) applying each and recording only the last failure in the single status it returns. So a
multi-field `SETSTAT` that fails has _already applied_ the fields before the failing one and
does not say which. One field per call makes a refusal unambiguous and leaves nothing else
moved.

`chown` and `utime` set two values each because the wire pairs them: `UIDGID` and `ACMODTIME`
are one flag apiece. To change a uid alone, read the gid back with `stat()` and send it
unchanged.

### These follow symlinks by default

`SETSTAT` is `chmod(2)`/`chown(2)`/`utimes(2)` on a path, and all three follow, the same
default as `os.chmod`. Where the path may be a symlink somebody else planted, that is an
operation on whatever it points at.

```python
await sftp.utime("/remote/current", atime, mtime, follow_symlinks=False)
```

`follow_symlinks=False` uses `lsetstat@openssh.com`, and **where the server will not do it the
call is refused** with a `CapabilityError` rather than quietly doing the following version.
That is the opposite of how every other extension here degrades, and the reason is that there
is nothing to degrade _to_: v3 has no non-following spelling, so the fallback would be to
perform a different operation, on the target the caller was trying to avoid. OpenSSH and
asyncssh advertise it; paramiko does not.

**`chmod(follow_symlinks=False)` cannot work against a Linux server**, and the extension being
present does not change that. Linux has no `lchmod`: `fchmodat(AT_SYMLINK_NOFOLLOW)` answers
`ENOTSUP`, measured at the syscall level, because a symlink's own permission bits are
meaningless to that kernel and always read `0o777`. It arrives as OpenSSH's contentless
`Failure`, so the exception carries a note saying why. `utime` and `chown` on a link _do_ work
there: `utimensat` and `fchownat` both accept the flag. The limit is the mode's, not the
extension's.
On a server whose operating system *does* have `lchmod` — macOS and the BSDs — the same call succeeds, because a symlink's mode is a real thing there. So this is a property of the **server's** platform rather than of SFTP or of this library, and a client on one cannot infer it from its own: a Linux client against a macOS server gets the success, not the refusal.

`truncate` has no `follow_symlinks=` at all, for a related reason: `lsetstat` rejects a `SIZE`
field outright with `BAD_MESSAGE` (`/* nonsensical for links */`), so a parameter there could
only ever fail.

### `readlink` returns attacker-controlled bytes

A link target is whatever the person who made the link chose. It may be absolute, may climb
with `..`, may not be valid UTF-8, and may point at nothing. None of that is validated, because
every one of those is a legal symlink, so **do not join the result onto a local path** without
the containment check `get_tree` uses. That is the zip-slip class, and `readlink` is the
shortest route to it.

A path that is _not_ a symlink answers `BAD_MESSAGE`, which reads as "your frame was malformed"
and here means `EINVAL`. See the status-code notes above.

`examples/permissions.py` covers `chmod`; `examples/links.py` covers the rest.

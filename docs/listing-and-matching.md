# Listing a directory, and matching names

What a listing carries, how to stream one you did not size, and the `glob` dialect --
which is `sftp(1)`'s rather than `fnmatch`'s, and the difference is not cosmetic.

## Listing

```python
for entry in await sftp.listdir("/incoming"):
    print(entry.kind, entry.size, entry.name)  # directory 4096 archive
```

Three things this does differently from the tools you have used:

- **The attributes come with the listing.** v3 sends ATTRS per entry, so `entry.size` and
  `entry.kind` cost nothing. Returning bare names forces a `stat` per file, which is a round
  trip each, and is why listing a large directory is slow in most SFTP tooling.
- **`entry.kind` can be `unknown`.** A server is not obliged to send permissions, and
  answering "file" when it did not say is how a recursive walk silently skips every
  directory on that server. `is_dir` is `False` for `unknown`, which is the safe way round for
  a walk, so read `kind` where the difference matters.
- **`entry.filename` is bytes and `entry.name` is `str` via `surrogateescape`.** A filename
  on Linux is bytes; a name decoded lossily is a file you can list and cannot open. The two
  round-trip, so the name you display is the name you can send back.

`.` and `..` are filtered out. `readdir()` gives you the raw batches if you want to see
exactly what the server sent: one READDIR is not a directory, and the server decides how
many entries a batch holds (OpenSSH: 100). It reports the end of a directory as `None`, for
an `EOF` status **and** for a NAME carrying zero names: the draft says a READDIR is answered
with "one or more names" and OpenSSH's server never sends an empty one, but OpenSSH's client
stops on one, and being stricter than `sftp(1)` against real-world servers buys nothing.

### Streaming a directory you did not size

`listdir()` follows every batch to the end, so **how much memory it takes is the server's
decision, not yours.** A directory with millions of entries, or a server willing to answer
READDIR with new names forever, is unbounded allocation driven by the peer. Nothing is
capped, because a silent cap breaks the legitimate large directory _and_ reports success.
`scandir()` is the form that holds one batch:

```python
async with sftp.scandir("/incoming") as entries:
    async for entry in entries:
        if entry.is_file and entry.name.endswith(".csv"):
            break  # the directory handle goes back here
```

It is a context manager rather than a bare generator because it holds a directory handle
open across the yield, and a suspended async generator that is merely dropped is not
finalised by trio, so the handle would sit on the server until the garbage collector felt like
it, if ever. Iterating one without the `async with` raises `StateError` instead of leaking.

Other work on the session is fine inside the loop, such as a `stat` per entry or a `get`,
because a session multiplexes and a scan holds no lock.

`listdir()` is `scandir()` collected, so the two cannot disagree about what a directory
contains. `walk()` uses it too, which means the raw listing and the classified one are never
both in memory; one directory still is, and that bound is structural, because a top-down walk
cannot know where to descend until it has seen every name.

## Matching names: `glob`

```python
from contextlib import aclosing

from gantry_sftp import local_child

async with aclosing(sftp.glob("/incoming/*.csv")) as matches:
    async for match in matches:
        await sftp.get(match.path, local_child(local_dir, match.name))
```

`match.path` is a path **this library** built, by joining a name that was checked for
separators and dot entries onto the prefix you typed. That is the reason to use `glob` rather
than a `listdir` and an `fnmatch`: written by hand, that join is at your call site, and a
server answering with `../../etc/x` is a path traversal you wrote yourself.

### When the filter is not a pattern

A regular expression, a modification-time watermark, a size threshold, a lookup in a
manifest — none of those can come through `glob`, and none of them means writing the join
unsafely. The two functions `glob` itself calls are public, and the whole answer is two lines:

```python
from gantry_sftp import check_listed_name, join_remote, local_child

drop = b"/incoming"
for entry in await sftp.listdir(drop):
    if entry.is_file and pattern.match(entry.name):
        remote = join_remote(drop, check_listed_name(entry.filename, directory=drop))
        await sftp.get(remote, local_child(local_dir, entry.filename))
```

- **`check_listed_name(name, directory=...)`** returns the name unchanged, so it reads as a
  pass-through, and raises `UnsafePathError` for a name that is not one path component —
  empty, `.` or `..`, or carrying a `/` or a NUL. On an honest server it never fires: a POSIX
  filename cannot contain a `/`.
- **`join_remote(parent, name)`** joins with `/` always, never `os.path.join`, which on a
  Windows _client_ would produce a path no server understands. Both arguments are bytes,
  because `entry.filename` is bytes — `entry.name` is the same name decoded for display, and
  decoding is not reversible for every server that will ever answer you.
- **`local_child(directory, name)`** is the destination side, and it is the one that is easy
  to forget: `local_dir / os.fsdecode(entry.filename)` is the zip-slip. It validates against
  the **local** rules and then decodes with `os.fsdecode`, so a filename that is not valid
  UTF-8 lands on disk as the bytes it arrived as. The local rules are a strict superset of the
  remote ones — a name that cleared `check_listed_name` can still be `..\evil` or `C:evil` or
  `CON`, none of which contains a `/` and all of which mean something on Windows — so passing
  the remote check is not a reason to skip this one.

The same three are what `glob`, `walk`, `get_tree` and `put_tree` use internally, so a
hand-written loop and a library one refuse the same names for the same reasons. `entry` here
is a `DirEntry`, which deliberately does **not** carry a `.path`: it is also what the upload
walk reports, where a remote directory does not exist, and a property that worked in one
direction and raised in the other would be worse than the two lines above.

**The dialect is `glob(3)`'s, because that is what `sftp(1)` uses.** It globs client-side
through POSIX `glob(3)`, so this is the pattern language you already have. Three consequences
differ from Python's `fnmatch`, which is what a reader would otherwise assume is underneath:

- **`*` and `?` never cross `/`.** `fnmatch` matches `a/b.csv` against `*.csv`; this does not.
- **A leading period must be matched explicitly.** `*.csv` does not match `.hidden.csv`; `.*.csv`
  does. This is what keeps a glob over a drop directory from picking up half-written staging
  files, including the dot-prefixed ones this library's own atomic publish creates.
- **A backslash escapes**, as it does in `sftp(1)`, which passes no `GLOB_NOESCAPE`.

`[abc]`, `[a-z]` and `[!a-z]` (also spelled `[^a-z]`) work, and so do POSIX **character
classes** — `*.[[:digit:]]`, `[[:upper:]]*`, `[![:space:]]`, and the other names below. Brace
expansion does not: `sftp(1)` applies it to `ls` and not to `get`, so there is no consistent
behaviour to copy.

|                        |                                                                                                                                                                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `**`                   | zero or more directory levels. An **addition** to what `sftp(1)` understands, so a pattern using it is not portable back to that client. Bounded by `max_depth=`                                                                                 |
| trailing `/`           | match directories only, as in a shell                                                                                                                                                                                                            |
| `[[:name:]]`           | a POSIX character class inside a bracket expression: `alnum`, `alpha`, `blank`, `cntrl`, `digit`, `graph`, `lower`, `print`, `punct`, `space`, `upper`, `xdigit`. **ASCII-only** — no byte above 127 is in any of them                           |
| `case_sensitive=False` | fold ASCII case in the names being matched. Not the directory you typed, since folding that would mean listing `/` to find out whether `/Incoming` is `/incoming`. Non-ASCII bytes are never folded: a remote name is bytes of unstated encoding |

**Character classes stop at ASCII, and a class name that does not exist is an error.** Which
bytes are letters is a property of a locale — glibc under ISO-8859-1 says `0xff` is one and
under C says it is not — and a remote name is bytes whose encoding the protocol never states,
so this library answers the question the same way on every machine instead of guessing. The
other two POSIX sub-expressions, equivalence classes `[[=a=]]` and collating symbols `[[.a.]]`,
are _defined_ by a locale's collation table and are refused for the same reason. So is a
misspelled class name: `glob("*.[[:digits:]]")` raises `ValueError` — before anything is
listed — where `glob(3)` would have quietly matched nothing and let a nightly job transfer zero
files and report success.

Matching runs on **bytes**, because a remote name need not be valid UTF-8 and a lossy decode
makes two distinct names match one pattern. Symlinks match but are never descended into, the
same as in `walk`. Nothing is accumulated, since matches are yielded as they are found, so it is an
async generator and you close it, exactly as with `walk`. A path in the pattern that does not
exist matches nothing; one that exists and **cannot be read** raises, which is a deliberate
divergence from `glob(3)`: answering "no matches" when the truth is "I was not allowed to look"
is a partial success wearing a complete one's clothes. That holds for all three ways a server
can decline: a directory the pattern descends through, a pattern with no wildcard in it at all,
and the `stat` that settles an entry's _kind_ on a server whose listing does not report it —
only `NO_SUCH_FILE` is an empty result, and a refusal to answer never is. The third case is
reachable only on a server that omits permission bits from a listing, which is why it outlived
the other two.

Runnable: `examples/glob_patterns.py`.

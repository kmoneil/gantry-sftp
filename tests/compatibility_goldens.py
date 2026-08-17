"""The reports four known servers produce, pinned finding for finding (D-193).

**Why seven and not one.** The first golden depicted a server that advertises every extension and
answers yes to everything, which is the report a reader most wants to see and the one that
reaches the fewest branches: a probe only emits its refusal prose when something refuses. Measured
rather than guessed -- the first four produce **27 distinct findings between them**, where the
capable server alone produces twelve, and no three of them reach all twenty-seven. What remained
after the first golden was not a shortage of assertions but a shortage of *servers*.

**And the four were themselves one axis.** They vary what a server does when it *refuses* and
share everything else -- the same `realpath`, the same all-`None` `ServerLimits`, the same
symlink mode, the same `check-file`, the same short-write-free `write_at`. So six probes saw an
identical server four times, and 88 of the 136 survivors after that slice were in them. `ROOTED`
and `MISMATCHING` vary those answers instead. Same rule as before: the axis was measured -- one
scripted answer at a time, diffed against the baseline -- before either was written.

**Why the duplication is deliberate.** Several findings are byte-identical across two portraits --
a case-sensitive server says the same thing about case whether its refusals are informative or
silent -- and they are written out in each rather than shared through a registry of named
findings. A portrait is meant to be read top to bottom as one server's whole report, which is
exactly what `compatibility_report` hands a user; keying the shared ones through constants would
save lines and lose the only property that makes a golden readable. The duplication is data, and
it is regenerated rather than edited.

**Regenerating.** These come from the code under test, so they can only ever pin behaviour rather
than prove it -- and that is not a formality here. Reviewing the first twelve found
`_probe_case_folding` naming the hazard of the other branch, a defect no mutation could reach
because every mutant of a sentence is still a sentence. So: regenerate, then **read every line
against the probe's docstring and ask whether it follows from the verdict above it**. A golden
pasted without that step freezes whatever was wrong.

The servers, and what each is for:

* `CAPABLE` -- advertises everything and answers yes. The happy path, and the only one that
  reaches the `YES` prose of the four extension probes.
* `RESTATING` -- refuses, with messages that spell out their own status code (`'No such file'`
  for `NO_SUCH_FILE`). This is OpenSSH, and it is what drives `_judge_messages` to *no*.
* `INFORMATIVE` -- refuses with a message that says something its code did not, which is the
  only way to reach that judgement's `yes`.
* `SILENT` -- refuses with no message at all, `_judge_messages`'s third branch. Legal and common:
  v3 `FAILURE` frequently carries nothing.
* `ROOTED` -- a namespace whose root really is `/`, a symlink whose own mode the server *did*
  change, and a `limits@openssh.com` answer with real maxima. The macOS/BSD shape: those
  platforms have `lchmod`, so `lsetstat`'s permissions branch succeeds where Linux refuses it.
  The only portrait reaching the `YES` branch of the root, limits and lsetstat probes.
* `MISMATCHING` -- answers everything, and its answers are wrong: a `check-file` digest of bytes
  it does not hold, and a `write_at` reporting fewer bytes stored than it was sent. The hazard a
  refusing server cannot depict, because a refusal at least says so.
* `STRICT` -- an appliance that refuses what it is not obliged to do: `REALPATH` of a name that
  does not exist, and `lsetstat`'s permission change. The second is what OpenSSH on Linux does
  *unconditionally* -- no `lchmod` in the kernel -- so it is the report a reader is most likely
  to meet in the field, and it had no portrait until the survivor count said so.

`run_id` is fixed at `t0ken` in every one, because the probe names are derived from it and a
generated id would make every path here a fresh string.
"""

from __future__ import annotations

from gantry_sftp.compatibility import Finding, Verdict

CAPABLE: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=("REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe'",),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a path "
            "built by joining strings will not mean what it looks like"
        ),
        evidence=("REALPATH b'/' -> b'/home/probe'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.UNDETERMINED,
        answer=(
            "this server accepted a request where a refusal was expected, so there was no pair of "
            "refusals to read"
        ),
        evidence=("STAT b'/home/probe/gantry-probe-t0ken-absent' -> accepted",),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than anything "
            "the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.YES,
        answer=(
            "the same file answered to a different case, so remote names that differ only in case "
            "will collide here -- and an upload of two local names differing only in case lands "
            "as one file, the second overwriting the first"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> found",
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. Treat any "
            "rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.YES,
        answer="the mtime that was set is the mtime that came back",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-times'",
            "SETSTAT ACMODTIME=1000000000 -> OK",
            "STAT -> mtime=1000000000",
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.YES,
        answer="the target was replaced in one step, which is what atomic publish needs",
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OK",
            "STAT b'/incoming/scratch/gantry-probe-t0ken-posix-source' -> gone",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.YES,
        answer="the server flushed the handle, so a durable upload can be asked for here",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> OK",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.NO,
        answer=(
            "the server answered OK and neither mode changed, so the request was accepted and "
            "discarded. That is worse than the refusal OpenSSH gives on the same kernel: a caller "
            "is told their permission change happened when it did not"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-lsetstat-target' at 0o600 and "
                "symlink b'/incoming/scratch/gantry-probe-t0ken-lsetstat-link' -> it"
            ),
            "lsetstat PERMISSIONS -> OK",
            "LSTAT of the link -> 0o777",
            "STAT of the target -> 0o600",
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed here, so "
            "content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)

RESTATING: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=("REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe'",),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a path "
            "built by joining strings will not mean what it looks like"
        ),
        evidence=("REALPATH b'/' -> b'/home/probe'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.NO,
        answer=(
            "every refusal spelled out its own status code and nothing else, so the text is a "
            "constant function of the code and reading it is reading the code twice"
        ),
        evidence=(
            (
                "STAT b'/home/probe/gantry-probe-t0ken-absent' -> NO_SUCH_FILE, server said 'No "
                "such file'"
            ),
            "READLINK b'/home/probe' -> BAD_MESSAGE, server said 'Bad message'",
            "this library's fingerprint for unknown claims informative_messages=False",
        ),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than anything "
            "the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.NO,
        answer=(
            "names are case-sensitive here, so two names differing only in case are two separate "
            "files -- and a recursive download onto a filesystem that folds case, as macOS and "
            "Windows do by default, can overwrite its own output"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            (
                "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> NO_SUCH_FILE, server "
                "said 'No such file'"
            ),
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.NO,
        answer=(
            "RENAME onto an existing name is refused, as the draft requires. Publishing over an "
            "existing file here needs posix-rename@openssh.com, or a remove first with the window "
            "that opens"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> FAILURE, server said 'Failure'",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=(
            (
                "NoSuchFileError: server returned NO_SUCH_FILE: No such file server said: 'No "
                "such file'"
            ),
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.NO,
        answer=(
            "the extension is advertised and the server answered OP_UNSUPPORTED, so atomic "
            "publish falls back and says so rather than pretending"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OP_UNSUPPORTED",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.NO,
        answer=(
            "the extension is advertised and the server would not perform it, so a transfer that "
            "asked for durability gets the documented refusal instead"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> not performed",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=(
            (
                "NoSuchFileError: server returned NO_SUCH_FILE: No such file server said: 'No "
                "such file'"
            ),
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed here, so "
            "content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)

INFORMATIVE: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=("REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe'",),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a path "
            "built by joining strings will not mean what it looks like"
        ),
        evidence=("REALPATH b'/' -> b'/home/probe'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.YES,
        answer=(
            "a refusal said something its status code did not, so this server's message text is "
            "worth reading and worth quoting in a bug report"
        ),
        evidence=(
            (
                "STAT b'/home/probe/gantry-probe-t0ken-absent' -> PERMISSION_DENIED, server said "
                "'quota exceeded on /vol1, contact ops'"
            ),
            "READLINK b'/home/probe' -> BAD_MESSAGE, server said 'Bad message'",
            "this library's fingerprint for unknown claims informative_messages=False",
        ),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than anything "
            "the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=(
            (
                "PermissionDeniedError: server returned PERMISSION_DENIED: quota exceeded on "
                "/vol1, contact ops server said: 'quota exceeded on /vol1, contact ops'"
            ),
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. Treat any "
            "rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=(
            (
                "PermissionDeniedError: server returned PERMISSION_DENIED: quota exceeded on "
                "/vol1, contact ops server said: 'quota exceeded on /vol1, contact ops'"
            ),
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.NO,
        answer=(
            "the extension is advertised and the server answered OP_UNSUPPORTED, so atomic "
            "publish falls back and says so rather than pretending"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OP_UNSUPPORTED",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.NO,
        answer=(
            "the extension is advertised and the server would not perform it, so a transfer that "
            "asked for durability gets the documented refusal instead"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> not performed",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=(
            (
                "PermissionDeniedError: server returned PERMISSION_DENIED: quota exceeded on "
                "/vol1, contact ops server said: 'quota exceeded on /vol1, contact ops'"
            ),
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed here, so "
            "content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)

SILENT: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=("REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe'",),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a path "
            "built by joining strings will not mean what it looks like"
        ),
        evidence=("REALPATH b'/' -> b'/home/probe'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.NO,
        answer=(
            "at least one refusal carried no message at all, so the status code is all there is "
            "to route on"
        ),
        evidence=(
            "STAT b'/home/probe/gantry-probe-t0ken-absent' -> NO_SUCH_FILE, no message",
            "READLINK b'/home/probe' -> BAD_MESSAGE, no message",
            "this library's fingerprint for unknown claims informative_messages=False",
        ),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than anything "
            "the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.NO,
        answer=(
            "names are case-sensitive here, so two names differing only in case are two separate "
            "files -- and a recursive download onto a filesystem that folds case, as macOS and "
            "Windows do by default, can overwrite its own output"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> NO_SUCH_FILE, no message",
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. Treat any "
            "rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=("NoSuchFileError: server returned NO_SUCH_FILE",),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.YES,
        answer="the target was replaced in one step, which is what atomic publish needs",
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OK",
            "STAT b'/incoming/scratch/gantry-probe-t0ken-posix-source' -> gone",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.YES,
        answer="the server flushed the handle, so a durable upload can be asked for here",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> OK",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.UNDETERMINED,
        answer="the probe itself failed, so this server's behaviour is not established",
        evidence=("NoSuchFileError: server returned NO_SUCH_FILE",),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed here, so "
            "content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)


ROOTED: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=(
            (
                "REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe/gantry-"
                "probe-t0ken-absent'"
            ),
        ),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.YES,
        answer="/ canonicalises to itself, as on a POSIX filesystem",
        evidence=("REALPATH b'/' -> b'/'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.UNDETERMINED,
        answer=(
            "this server accepted a request where a refusal was expected, so there was no "
            "pair of refusals to read"
        ),
        evidence=("STAT b'/home/probe/gantry-probe-t0ken-absent' -> accepted",),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.YES,
        answer="the extension was advertised, was answered, and named at least one maximum",
        evidence=(
            "limits@openssh.com max_packet_length -> 32768",
            "limits@openssh.com max_read_length -> 16384",
            "limits@openssh.com max_write_length -> 16384",
            "limits@openssh.com max_open_handles -> 64",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.YES,
        answer=(
            "the same file answered to a different case, so remote names that differ only "
            "in case will collide here -- and an upload of two local names differing only "
            "in case lands as one file, the second overwriting the first"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> found",
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. "
            "Treat any rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.YES,
        answer="the mtime that was set is the mtime that came back",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-times'",
            "SETSTAT ACMODTIME=1000000000 -> OK",
            "STAT -> mtime=1000000000",
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.YES,
        answer="the target was replaced in one step, which is what atomic publish needs",
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OK",
            "STAT b'/incoming/scratch/gantry-probe-t0ken-posix-source' -> gone",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.YES,
        answer="the server flushed the handle, so a durable upload can be asked for here",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> OK",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.YES,
        answer=(
            "the link's own mode is what was asked for, so this server's platform has "
            "lchmod and follow_symlinks=False means what it says here"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-lsetstat-target' at 0o600 and "
                "symlink b'/incoming/scratch/gantry-probe-t0ken-lsetstat-link' -> it"
            ),
            "lsetstat PERMISSIONS -> OK",
            "LSTAT of the link -> 0o640",
            "STAT of the target -> 0o600",
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed "
            "here, so content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)

MISMATCHING: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.YES,
        answer="a name that does not exist can be resolved to where it would be",
        evidence=("REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> b'/home/probe'",),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.NO,
        answer=(
            "/ resolves to something else, so this server rewrites absolute paths and a "
            "path built by joining strings will not mean what it looks like"
        ),
        evidence=("REALPATH b'/' -> b'/home/probe'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.UNDETERMINED,
        answer=(
            "this server accepted a request where a refusal was expected, so there was no "
            "pair of refusals to read"
        ),
        evidence=("STAT b'/home/probe/gantry-probe-t0ken-absent' -> accepted",),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than "
            "anything the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.YES,
        answer=(
            "the same file answered to a different case, so remote names that differ only "
            "in case will collide here -- and an upload of two local names differing only "
            "in case lands as one file, the second overwriting the first"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> found",
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. "
            "Treat any rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.YES,
        answer="the mtime that was set is the mtime that came back",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-times'",
            "SETSTAT ACMODTIME=1000000000 -> OK",
            "STAT -> mtime=1000000000",
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.YES,
        answer="the target was replaced in one step, which is what atomic publish needs",
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OK",
            "STAT b'/incoming/scratch/gantry-probe-t0ken-posix-source' -> gone",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.YES,
        answer="the server flushed the handle, so a durable upload can be asked for here",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> OK",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.NO,
        answer=(
            "the server answered OK and neither mode changed, so the request was accepted "
            "and discarded. That is worse than the refusal OpenSSH gives on the same "
            "kernel: a caller is told their permission change happened when it did not"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-lsetstat-target' at 0o600 and "
                "symlink b'/incoming/scratch/gantry-probe-t0ken-lsetstat-link' -> it"
            ),
            "lsetstat PERMISSIONS -> OK",
            "LSTAT of the link -> 0o777",
            "STAT of the target -> 0o600",
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.NO,
        answer=(
            "the server answered with 1 sha256 digest(s) that do not match the bytes that "
            "were uploaded, so this extension must not be trusted here"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest differs from the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.NO,
        answer=(
            "the server accepted the request and stored fewer bytes than it was sent, which"
            " no exception would have reported"
        ),
        evidence=("WRITE of 4096 bytes -> 1024 bytes written",),
    ),
)

STRICT: tuple[Finding, ...] = (
    Finding(
        fact="REALPATH canonicalises a path that does not exist",
        verdict=Verdict.NO,
        answer=(
            "this server refuses to canonicalise a name that does not exist, so a path has "
            "to be created before it can be resolved"
        ),
        evidence=(
            (
                "REALPATH b'/home/probe/gantry-probe-t0ken-absent' -> NO_SUCH_FILE, server said "
                "'No such file'"
            ),
        ),
    ),
    Finding(
        fact="the root of this server's namespace is /",
        verdict=Verdict.YES,
        answer="/ canonicalises to itself, as on a POSIX filesystem",
        evidence=("REALPATH b'/' -> b'/'",),
    ),
    Finding(
        fact="a refusal carries a message that says more than its status code",
        verdict=Verdict.UNDETERMINED,
        answer=(
            "this server accepted a request where a refusal was expected, so there was no "
            "pair of refusals to read"
        ),
        evidence=("STAT b'/home/probe/gantry-probe-t0ken-absent' -> accepted",),
    ),
    Finding(
        fact="limits@openssh.com answers with a usable maximum",
        verdict=Verdict.NO,
        answer=(
            "the extension was advertised and answered every field with no limit, so this "
            "session's request size is this library's conservative default rather than "
            "anything the server agreed to"
        ),
        evidence=(
            "limits@openssh.com max_packet_length -> no limit stated",
            "limits@openssh.com max_read_length -> no limit stated",
            "limits@openssh.com max_write_length -> no limit stated",
            "limits@openssh.com max_open_handles -> no limit stated",
        ),
    ),
    Finding(
        fact="this server folds case in names",
        verdict=Verdict.YES,
        answer=(
            "the same file answered to a different case, so remote names that differ only "
            "in case will collide here -- and an upload of two local names differing only "
            "in case lands as one file, the second overwriting the first"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-case-aA'",
            "STAT b'/incoming/scratch/GANTRY-PROBE-T0KEN-CASE-AA' -> found",
        ),
    ),
    Finding(
        fact="RENAME replaces an existing target",
        verdict=Verdict.YES,
        answer=(
            "RENAME silently replaced an existing file, which the draft does not allow. "
            "Treat any rename here as destructive"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-rename-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-rename-target'"
            ),
            "RENAME -> OK, the target was replaced",
        ),
    ),
    Finding(
        fact="a file's timestamps survive being set",
        verdict=Verdict.YES,
        answer="the mtime that was set is the mtime that came back",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-times'",
            "SETSTAT ACMODTIME=1000000000 -> OK",
            "STAT -> mtime=1000000000",
        ),
    ),
    Finding(
        fact="posix-rename@openssh.com actually renames",
        verdict=Verdict.YES,
        answer="the target was replaced in one step, which is what atomic publish needs",
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-posix-source' and "
                "b'/incoming/scratch/gantry-probe-t0ken-posix-target'"
            ),
            "posix-rename -> OK",
            "STAT b'/incoming/scratch/gantry-probe-t0ken-posix-source' -> gone",
        ),
    ),
    Finding(
        fact="fsync@openssh.com actually flushes",
        verdict=Verdict.YES,
        answer="the server flushed the handle, so a durable upload can be asked for here",
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-fsync'",
            "fsync -> OK",
        ),
    ),
    Finding(
        fact="lsetstat@openssh.com actually changes a symlink's own mode",
        verdict=Verdict.NO,
        answer=(
            "advertised and refused. On a Linux server this is unconditional and is not a "
            "misconfiguration: the kernel has no lchmod, a symlink's own mode is ignored "
            "there, and the times and owner of a link can still be set"
        ),
        evidence=(
            (
                "created b'/incoming/scratch/gantry-probe-t0ken-lsetstat-target' at 0o600 and "
                "symlink b'/incoming/scratch/gantry-probe-t0ken-lsetstat-link' -> it"
            ),
            "lsetstat PERMISSIONS -> FAILURE, server said 'Failure'",
        ),
    ),
    Finding(
        fact="check-file actually hashes the bytes the server has",
        verdict=Verdict.YES,
        answer=(
            "the server's sha256 digest of the bytes it holds matches the one computed "
            "here, so content verification can be done without moving the file back"
        ),
        evidence=(
            "created b'/incoming/scratch/gantry-probe-t0ken-check-file' with 29 bytes",
            "check-file -> algorithm 'sha256', 1 digest(s)",
            "first digest matches the locally computed one",
        ),
    ),
    Finding(
        fact="a request as large as this session would send is accepted",
        verdict=Verdict.YES,
        answer="a request of the size this session's transfers use was accepted whole",
        evidence=(
            "WRITE of 4096 bytes -> 4096 bytes written",
            (
                "the size was derived from this server's own limits, for "
                "b'/incoming/scratch/gantry-probe-t0ken-largest-request'"
            ),
        ),
    ),
)


REPORTS: dict[str, tuple[Finding, ...]] = {
    "capable": CAPABLE,
    "restating": RESTATING,
    "informative": INFORMATIVE,
    "silent": SILENT,
    "rooted": ROOTED,
    "mismatching": MISMATCHING,
    "strict": STRICT,
}
"""Every portrait, so the test file iterates rather than naming them one at a time.

A server added here without a matching stub in `tests/test_compatibility.py` fails the pairing
test there rather than being silently skipped -- which is the failure mode a dict of goldens
invites, and the same shape as the defaults table's own guard.
"""

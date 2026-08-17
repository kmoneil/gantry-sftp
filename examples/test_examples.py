"""Every example runs, as a subprocess, exactly as a reader would run it.

An example that has drifted out of sync with the library is worse than no example: it is a
confident, wrong answer that somebody will copy. So these are executed rather than imported
-- the `__main__` block, the argument handling and the imports are all part of what is being
checked.

They need a real `sftp-server`, because that is what makes them runnable with no arguments,
so they skip with a reason where it is absent rather than failing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from gantry_sftp.transport import find_sftp_server

sys.path.append(str(Path(__file__).resolve().parent.parent / "tests"))
from local_filesystem import (  # one probe and one marker, shared with tests/ and live-tests/
    HOLDS_NON_UTF8_NAMES,
    needs_non_utf8_names,
)

# The examples that put a non-UTF-8 filename on disk to demonstrate this library handling one.
# macOS refuses such a name outright (`OSError: [Errno 92] Illegal byte sequence`), so these
# cannot run there -- the *example* is correct and the filesystem will not hold its subject.
NEEDS_NON_UTF8_NAMES = frozenset({"listing", "glob_patterns", "fsspec_urls", "paths"})

EXAMPLES = sorted(p for p in Path(__file__).parent.glob("*.py") if p.name != Path(__file__).name)


def test_there_are_examples_to_run():
    # Guards the guard: an empty directory would make the parametrised test below vacuous.
    assert EXAMPLES, "no examples found -- this file would prove nothing"


def tabled_examples() -> set[str]:
    """Every example named in a table row of `examples/README.md`.

    Rows only, not the whole file: the *how to run* lists near the top already name every
    example as a command line, so matching anywhere would report an example as documented on
    the strength of a line that says how to start it and not what it shows.
    """
    readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\|\s*`([a-z_]+\.py)`", readme, re.MULTILINE))


def test_every_example_has_a_row_saying_what_it_demonstrates():
    """The table is an index of work, and an index cannot be audited by reading it.

    `compatibility.py` and `crash_resume.py` were shipped, runnable, driven by
    `test_an_example_runs_clean`, and named in this README's *how to run* list -- and neither had
    a row in the table saying what it shows. Nothing noticed, because the way to notice is to
    resolve the table against the directory, which no check did.

    Both directions, and the second is not decoration: a row for a file that was renamed or
    deleted is an index pointing at nothing, which is the same defect from the other side and
    the one D-196 found in `docs/security.md`.
    """
    present = {p.name for p in EXAMPLES}
    tabled = tabled_examples()
    assert not (present - tabled), (
        f"examples with no row in examples/README.md: {sorted(present - tabled)}"
    )
    assert not (tabled - present), (
        f"examples/README.md has rows for files that do not exist: {sorted(tabled - present)}"
    )


def test_the_example_table_check_is_not_vacuous():
    # A regex that matched no rows would make the test above pass while comparing two empty
    # sets against each other, which is how a derived check goes quiet.
    assert len(tabled_examples()) > 25


def run_example(example: Path) -> tuple[int, str, str]:
    """Run an example and decode its output leniently.

    **Not** ``text=True``. `listing.py` prints a filename that is not valid UTF-8, because
    that is an ordinary thing for a filename to be and the whole point of the example -- and
    strict decoding here turns the demonstration into a harness crash. The library's own rule,
    applied to the library's own test: names are bytes, and something else decides how to show
    them.
    """
    finished = subprocess.run(
        [sys.executable, str(example)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    return (
        finished.returncode,
        finished.stdout.decode("utf-8", "replace"),
        finished.stderr.decode("utf-8", "replace"),
    )


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.stem)
def test_an_example_runs_clean(example: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")
    if example.stem in NEEDS_NON_UTF8_NAMES and not HOLDS_NON_UTF8_NAMES:
        pytest.skip(f"{example.stem} writes a non-UTF-8 filename; this filesystem refuses one")

    returncode, stdout, stderr = run_example(example)
    assert returncode == 0, f"{example.name} failed:\n{stderr}"
    assert stdout.strip(), f"{example.name} printed nothing"
    assert "Traceback" not in stderr


def test_the_publish_example_reports_the_mechanism_it_used():
    # The example exists to show that the result names its mechanism. If that line stops
    # appearing, the example has stopped demonstrating the thing it is here to demonstrate.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "atomic_publish.py")
    assert returncode == 0
    assert "mechanism=posix-rename" in stdout
    assert "durability=fsynced" in stdout
    # Rung 3 of DESIGN.md 6's ladder, against a real sftp-server: the published length was
    # confirmed against the local file's before the rename ran.
    assert "size=matched" in stdout
    assert "mechanism=in-place" in stdout


@needs_non_utf8_names
def test_the_listing_example_shows_a_name_that_is_not_valid_utf8():
    # The example is only worth having if it demonstrates the awkward case. A directory of
    # tidy ASCII names would prove nothing that a docstring could not claim.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "listing.py")
    assert returncode == 0
    assert "�" in stdout, "the non-UTF-8 name did not survive to the output"
    assert "directory" in stdout
    assert "symlink" in stdout


def test_the_links_example_narrates_the_chmod_outcome_whichever_one_it_gets():
    """The one branch in `examples/` whose outcome is the *server's* operating system.

    `chmod(follow_symlinks=False)` is refused on a Linux server -- it has no `lchmod` -- and
    succeeds on macOS and the BSDs, where a symlink's mode is real. The example printed only
    the refusal, so on a Mac it ran clean, exited 0, and said **nothing whatever** about the
    call before printing a paragraph about refusals (D-161). `test_an_example_runs_clean`
    cannot see that: silence is not a failure.

    Asserted as "one of the two, and the paragraph after it either way", which is what makes
    this row platform-free rather than a second skip.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "links.py")
    assert returncode == 0
    refused = "chmod(follow_symlinks=False) refused" in stdout
    succeeded = "chmod(follow_symlinks=False) succeeded" in stdout
    assert refused != succeeded, (
        "the example must narrate exactly one of the two outcomes; it narrated "
        f"{'both' if refused else 'neither'}"
    )
    if succeeded:
        assert "the link's own mode is now 0600" in stdout
        assert "still reads 0644" in stdout, "a success that left the target alone is the claim"
    assert "utime(follow_symlinks=False) set the link's own times" in stdout
    assert "refusal rather than a downgrade" in stdout


def test_the_concurrency_example_shows_transfers_actually_overlapping():
    # The example is only worth having if it demonstrates overlap rather than asserting it,
    # and wall clock over a local pipe demonstrates nothing -- there is no round-trip time to
    # win back. What must appear is the peak number of transfers open at the same instant,
    # which is 1 on a session that serialises no matter how fast it is.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "concurrent_transfers.py")
    assert returncode == 0
    assert "transfers open at once, at the peak: 12 of 12" in stdout
    assert "byte-identical" in stdout
    # And the error section has to keep telling the truth about where the exception lands.
    assert "one call, on its own:  NoSuchFileError" in stdout
    assert "inside your task group: NoSuchFileError" in stdout
    # D-194: and about the failures that are *not* the one raised. The example asserts the note
    # exists; this asserts it reached stdout carrying a path, because a note that named no file
    # would satisfy the example's own assertion and tell a reader nothing.
    assert "and the rest, on a note:" in stdout
    assert "other failure(s) happened concurrently" in stdout
    assert "/definitely/not/there/" in stdout.split("and the rest, on a note:")[1]


def test_the_cancellation_example_shows_a_prompt_unwind_and_no_litter():
    # Two claims, and the example is only worth having if it keeps demonstrating both: that
    # the cancel landed while bytes were moving, and that unwinding did not cost the
    # `request_timeout` it used to. A cancelled publish leaving its staging file behind is
    # the other half -- invisible from the client, and exactly what the shield exists for.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "cancellation.py")
    assert returncode == 0
    assert "cancelled mid-transfer" in stdout
    assert "cancelled mid-upload" in stdout
    assert "left behind: none" in stdout
    assert "the session still works" in stdout


def test_the_retry_example_says_why_it_stopped_and_not_only_how_often():
    # D-195. The two exits from the retry loop need different sentences, and until they had
    # them the mixed path -- a link that drops, then a refusal no reconnect can fix -- claimed
    # the attempts were spent and that every failure was retryable. Both were false, and both
    # send a reader to look at the link for a permission problem.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "retry.py")
    assert returncode == 0
    assert "Retryable, then terminal: NoSuchFileError" in stdout
    assert "attempts run: 2 of 3" in stdout
    # The note itself, not just its presence: "stopped after" and "not retryable" are the two
    # halves the old sentence got wrong, and "gave up after" survives in the *other* branch, so
    # asserting that alone would pass against the defect.
    assert "stopped after 2 of 3 attempt(s): this failure is not retryable" in stdout


def test_the_connect_errors_example_classifies_rather_than_guesses():
    # The example exists to show that the failure reaches you as a *class*. With no arguments
    # it connects to a closed port, which is deliberately one of the cases we refuse to
    # classify -- so what it must demonstrate is the honest base class plus OpenSSH's own
    # words, not a guess dressed up as a diagnosis.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "connect_errors.py")
    assert returncode == 0
    assert "class:    ConnectError" in stdout
    assert "Connection refused" in stdout, "OpenSSH's own diagnosis did not reach the output"
    # And it must not have claimed to know more than it does.
    assert "AuthenticationError" not in stdout
    assert "HostKeyError" not in stdout

    # D-89's half: the missing-client case, where there is no stderr at all and the hint is
    # therefore the entire diagnosis. Both halves of that pairing are asserted, because
    # "(nothing)" next to actionable advice is the whole point the output makes.
    assert "ssh said:" in stdout
    assert "(nothing)" in stdout

    # The hint is wrapped for the terminal, so it is reassembled before matching rather than
    # asserted line by line -- otherwise a reworded sentence moves the wrap and fails a test
    # that has nothing to say about wrapping.
    hint = " ".join(
        line.strip().removeprefix(">").strip()
        for line in stdout.splitlines()
        if line.strip().startswith(">")
    )
    assert "does not implement SSH" in hint
    assert "apt-get install openssh-client" in hint
    assert "cannot run this transport at all" in hint


def test_the_password_example_proves_the_secret_is_not_on_the_command_line():
    """The example's claim is a security property, so the property is what gets pinned.

    ``sshpass -p`` puts a credential in argv, where ``ps`` shows it to every user on the
    machine. If these two lines ever print ``True``, the example is demonstrating the bug
    rather than the fix -- and unlike most drift, nobody would notice by reading it.

    No ``sftp-server`` needed: the example connects to a closed port, because what it is
    asserting is decided before a packet is sent.
    """
    returncode, stdout, _ = run_example(Path(__file__).parent / "password_auth.py")
    assert returncode == 0
    assert "password anywhere in argv:      False" in stdout
    assert "password anywhere in the error: False" in stdout
    # Pinned per entry point rather than once. The frame line was printed and never asserted,
    # and the example only ever ran the two-call spelling -- the one site that already wrapped
    # its parameter -- so the claim held on the single path it exercised while `connect()`,
    # which the README opens with, put the plaintext in a frame any reporter would capture.
    assert "via open_ssh_transport()" in stdout
    assert "via connect()" in stdout
    assert stdout.count("password in any dumped frame:   False") == 2
    # And it must still be showing *why* the parameter has to exist: the shipped default is
    # not a preference here, it is what makes the feature impossible without it.
    assert "BatchMode=yes   <- suppresses ssh's askpass helper" in stdout
    assert "BatchMode=no" in stdout


def test_the_verification_example_shows_corruption_slipping_past_the_size_check():
    """The example's whole argument is one line of its output, so that line is pinned.

    It uploads onto a partial from the wrong source with no ``check-file`` available, and the
    call *succeeds* with ``size_check=matched`` over a file that is half one upload and half
    another. If that stops appearing, the example has stopped demonstrating why rungs 1 and 2
    exist and has become a tour of an API.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "verify_content.py")
    assert returncode == 0
    # Rung 1 asked for and absent: reported, never passed off as success.
    assert "verify=hash        content_check=unavailable" in stdout
    # Rung 2 needs no extension, which is the point of having it.
    assert "verify=reread      content_check=reread" in stdout
    # The failure itself: rung 3 satisfied, contents wrong.
    assert "size_check=matched -- passed, and the published file is corrupt" in stdout
    assert "matches the source: False" in stdout
    # And rung 2 refusing the same prefix on a server that cannot hash anything.
    assert "cannot resume:" in stdout


@needs_non_utf8_names
def test_the_paths_example_demonstrates_both_refusals_and_the_awkward_name():
    """Three claims, and each is a decision the class could have made the other way.

    An example of a `pathlib`-shaped API is a tour of an API unless it shows what the shape
    costs and buys. So what is pinned is the joining refusal on a name a *server* chose, the
    constructor accepting the same characters because a caller wrote them, and a name that is
    not valid UTF-8 surviving to the output -- a directory of tidy ASCII would prove nothing a
    docstring could not claim.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "paths.py")
    assert returncode == 0
    # The zip-slip join, refused, with the reason and the alternative in the message.
    assert "refusing to join b'../../etc/cron.d/x'" in stdout
    assert "use .parent to go up" in stdout
    # The other side of the same line: the constructor is a path the caller wrote.
    assert "the constructor takes what the join refuses: b'/a/../b'" in stdout
    # A path with no session does arithmetic and nothing else.
    assert "has no session, so it can do path arithmetic and nothing else" in stdout
    # The name that breaks clients which decode strictly, listed and then downloaded.
    assert r"caf\xe9.csv" in stdout
    # `glob(3)`'s leading-dot rule, which is what keeps a sweep off half-written files.
    assert "and .staging.csv was not matched" in stdout
    # And the mode a file created through a path arrives with, which is not the server's.
    assert "mode 600" in stdout


def test_the_dry_run_example_shows_a_preview_that_wrote_nothing():
    """The claim is a negative, so the example has to be able to fail it.

    "Makes no writes" is the whole contract, and a docstring stating it proves nothing -- the
    example checks the destination is absent *after* previewing and prints the answer, so a
    preview that started creating directories again would flip a line of output rather than
    pass quietly. The three writes it has to miss are in three different places: `get_tree`'s
    own root `mkdir`, the one inside `_settle_directory` for every walked directory, and
    `_touch_destination`'s empty file per remote name.

    **The collision half is branched, and the branch is the platform finding.** The example
    stages its own hazard by writing `README.md` beside `readme.md` into the directory the
    server serves -- which on APFS is one file, written twice, listed once. So on macOS there is
    no pair to preview and asserting one is asserting that the filesystem under CI is the one
    the author had. That is what failed the first `fast (macos-latest)` run of this example, and
    it is the same shape as the stand-in in `destination_collision.py` breaking on the only
    platform where the hazard is real.

    Branched on the example's **own** statement rather than on a probe here: `run_example`
    spawns a subprocess with its own temporary directory, which need not be the filesystem
    `tmp_path` is on, so a second probe could disagree with the first about the same machine.
    The example is the only honest authority on where it ran.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "dry_run.py")
    assert returncode == 0
    # Both directions preview, and neither leaves anything behind.
    assert stdout.count("destination untouched: True") == 2
    # The download previews nearly completely; the upload is silent about the far end and
    # says which question it declined to ask.
    assert "whether each remote directory already exists: not checked" in stdout
    assert "what the destination filesystem does with these names: not consulted" in stdout
    # The skip a preview exists to surface before anything moves.
    assert "symlink, and symlinks are not followed" in stdout

    if "remote tree holds both names: yes" in stdout:
        # A fold, reported rather than raised -- and then both files transfer for real, which
        # is the whole demonstration: the preview flagged a pair the real run does not refuse.
        assert "would fold together" in stdout
        assert "README.md -> b'the first file\\n'" in stdout
        assert "readme.md -> b'a different file entirely\\n'" in stdout
    else:
        # The other branch has to be pinned too, or "no pair reported" passes on a machine
        # where the pair was staged and the preview simply stopped noticing it.
        assert "remote tree holds both names: no" in stdout
        assert "would fold together" not in stdout
        assert "the fold happened when" in stdout


def test_the_compatibility_example_shows_a_verdict_that_disagrees_with_the_advertisement():
    """The example is only worth having if it demonstrates the gap the report exists for.

    "Which extensions are advertised" and "which extensions work" are different questions, and
    against the OpenSSH server this example spawns there is exactly one row where they give
    different answers: `lsetstat@openssh.com` is advertised and cannot succeed on Linux. An
    example that printed only agreeing rows would be demonstrating the easy half.

    The cleanup claim is asserted twice on purpose, because the two are different statements.
    `left behind: nothing` is what the *report* says; the scratch listing is what the
    *filesystem* says, and a battery that lost track of a name it created would pass the first
    and fail the second.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "compatibility.py")
    assert returncode == 0
    assert "lsetstat@openssh.com actually changes a symlink's own mode" in stdout
    # **One outcome or the other, and the exchange that matches it.** Which one is a property of
    # the machine the example spawns its server on -- Linux refuses for want of `lchmod`, macOS
    # succeeds -- and asserting the Linux line alone made this row a claim about the host. The
    # portable claim, and the example's actual subject, is that the verdict carries its workings.
    refused = "lsetstat PERMISSIONS -> FAILURE" in stdout
    worked = "lsetstat PERMISSIONS -> OK" in stdout
    assert refused != worked, (
        "the example must show exactly one lsetstat outcome with its exchange; it showed "
        f"{'both' if refused else 'neither'}"
    )
    if worked:
        assert "LSTAT of the link ->" in stdout, "an OK is only evidence with the check after it"
    # Every finding carries its workings, and the run answered everything it asked.
    assert "complete:        True" in stdout
    assert "answers, not faults" in stdout
    # Both cleanup claims.
    assert "left behind:     nothing" in stdout
    assert "scratch directory afterwards: []" in stdout
    # And what it declined to ask is named rather than implied.
    assert "not determined -- what this run did not ask, and why:" in stdout
    assert "not probed, because that means moving somebody's data" in stdout


def test_the_crash_resume_example_actually_dies_and_actually_resumes():
    """Two claims, and the example is only worth having if it keeps demonstrating both.

    **That the child was killed rather than unwound** -- signal 9, not an exception -- because a
    demonstration that raised instead would exercise the path that already worked. And that the
    second process sent only the remainder, since an upload that silently restarted would print
    the same "bytes match the source: True" and prove nothing.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    returncode, stdout, _ = run_example(Path(__file__).parent / "crash_resume.py")
    assert returncode == 0
    assert "child exited on signal 9 (9 = SIGKILL)" in stdout
    # The staging file exists and the journal is the only thing that names it.
    assert "its name carries randomness nothing could reconstruct: .big.bin." in stdout
    assert '"event": "staged"' in stdout
    # It resumed rather than restarting: the remainder is less than the whole file.
    remainder = next(line for line in stdout.splitlines() if "the rest was already there" in line)
    transferred = int(remainder.split("transferred ")[1].split(" of ")[0])
    total = int(remainder.split(" of ")[1].split(" bytes")[0])
    assert 0 < transferred < total, remainder
    assert "bytes match the source: True" in stdout
    assert "nothing left staged:    True" in stdout
    assert "journal is clear:       True" in stdout
    # And the sweep removed only what the journal recorded.
    assert "after:  ['.orphan.bin.cafebabe.part']" in stdout

    # The tree section (D-172), which has to fail the same two ways the single file can: a run
    # that was never killed, and a resume that quietly restarted the interrupted file.
    assert "into the big file, killing myself" in stdout
    assert "published before the crash: ['small-a.bin', 'small-b.bin']" in stdout
    assert "one file was in flight:     .zz-big.bin." in stdout
    moved = next(line for line in stdout.splitlines() if "same journal: moved" in line)
    tree_transferred = int(moved.split("moved ")[1].split(" of ")[0])
    tree_total = int(moved.split(" of ")[1].split(" bytes")[0])
    assert 0 < tree_transferred < tree_total, moved
    assert "resumed rather than restarted: True" in stdout
    assert "every file matches its source: True" in stdout
    assert "nothing left staged:           True" in stdout
    assert "journal is clear:              True" in stdout

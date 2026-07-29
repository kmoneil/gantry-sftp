"""Every example runs, as a subprocess, exactly as a reader would run it.

An example that has drifted out of sync with the library is worse than no example: it is a
confident, wrong answer that somebody will copy. So these are executed rather than imported
-- the `__main__` block, the argument handling and the imports are all part of what is being
checked.

They need a real `sftp-server`, because that is what makes them runnable with no arguments,
so they skip with a reason where it is absent rather than failing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from gantry_sftp.transport import find_sftp_server

EXAMPLES = sorted(p for p in Path(__file__).parent.glob("*.py") if p.name != Path(__file__).name)


def test_there_are_examples_to_run():
    # Guards the guard: an empty directory would make the parametrised test below vacuous.
    assert EXAMPLES, "no examples found -- this file would prove nothing"


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

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

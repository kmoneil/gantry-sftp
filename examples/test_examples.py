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


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.stem)
def test_an_example_runs_clean(example: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    finished = subprocess.run(
        [sys.executable, str(example)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert finished.returncode == 0, f"{example.name} failed:\n{finished.stderr}"
    assert finished.stdout.strip(), f"{example.name} printed nothing"
    assert "Traceback" not in finished.stderr


def test_the_publish_example_reports_the_mechanism_it_used():
    # The example exists to show that the result names its mechanism. If that line stops
    # appearing, the example has stopped demonstrating the thing it is here to demonstrate.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    finished = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "atomic_publish.py")],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert "mechanism=posix-rename" in finished.stdout
    assert "durability=fsynced" in finished.stdout
    assert "mechanism=in-place" in finished.stdout

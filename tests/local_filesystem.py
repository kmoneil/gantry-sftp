"""What the local filesystem will actually hold, asked once and shared by every lane.

**This is a plain module rather than part of `conftest.py`, and the reason is mechanical.**
`live-tests/` has a `conftest.py` of its own, so `from conftest import ...` there resolves to
that one -- two files cannot both be the module named `conftest`. The live fsspec lane needs the
same answer as the unit lane and could not reach it, so it asked the filesystem *nothing* and
wrote the name unconditionally: nine tests errored at setup on the first run of that lane on
macOS, while its unit twin skipped cleanly.

`pythonpath = ["tests"]` in `pyproject.toml` already exists for exactly this shape --
`live-tests/test_contract_matrix.py` imports `server_contract` from here, so one contract is
asked of the fake and of the matrix's three servers rather than each lane keeping its own copy
(D-114). A probe is the same argument: answered once, or it is not one probe.

Everything here is **probed, never keyed to `sys.platform`**, which is this repository's rule
wherever it asks what the environment can do -- netem, Docker, `sftp-server`. These properties
belong to the *filesystem*: a UTF-8-enforcing mount can appear under Linux, and a Mac with a
suitable mount would be wrongly skipped by a platform check.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


def _filesystem_holds_non_utf8_names() -> bool:
    """Whether this machine's temporary filesystem can hold a name that is not valid UTF-8.

    **Linux can; macOS cannot, and it is the filesystem refusing rather than Python.** APFS and
    HFS+ validate that a name is UTF-8 and answer `OSError: [Errno 92] Illegal byte sequence`,
    so a fixture building such a name errors every test that takes it -- 98 in `test_fsspec.py`
    and the whole real-server row in `test_glob.py`, on the first CI run with a macOS job, and
    all nine rows of `live-tests/test_fsspec_live.py` on the first run of that lane off Linux.

    `D-150` covers the half this does not: what the *library* does when a legal remote name
    cannot be written locally.
    """
    with tempfile.TemporaryDirectory() as probe:
        try:
            (Path(probe) / "\udce9").touch()
        except OSError:
            return False
        return True


HOLDS_NON_UTF8_NAMES = _filesystem_holds_non_utf8_names()
"""Set once: probing per test would ask the filesystem hundreds of times."""

needs_non_utf8_names = pytest.mark.skipif(
    not HOLDS_NON_UTF8_NAMES,
    reason="this filesystem rejects names that are not valid UTF-8 (macOS APFS/HFS+ does)",
)
"""For tests asserting *on* such a name, as opposed to those that merely tolerate one.

Imported rather than re-spelled. `examples/test_examples.py` used to carry a second copy of this
marker with the same reason string, which is the shape D-157 was closed on -- one rule in `src/`
with three transcriptions in `tests/`, and the branch carrying the stale one unreachable on the
machine the change was made on.
"""


def give_one_file_a_second_name(first: Path, second: Path) -> None:
    """Make ``second`` another name for ``first``, however this filesystem gets there.

    **A hard link is the stand-in for case folding, and the stand-in breaks where the real thing
    lives.** On a case-sensitive filesystem `README.md` and `readme.md` are two entries, so a
    link is what produces the two-names-one-inode condition the destination-collision checks are
    about. On APFS or NTFS the filesystem already folds them together -- `second` *is* `first` --
    and `os.link` answers `FileExistsError` rather than obliging.

    That is not hypothetical: seven call sites and one example failed exactly this way on the
    first macOS CI run, with `[Errno 17] File exists: '.../README.md' -> '.../readme.md'`. The
    hazard was present and the simulation of it was what broke.

    So the fold is used where it exists and reproduced where it does not, and neither branch is
    a skip: the property under test -- two names, one file -- holds on both, which is the whole
    reason these tests can run anywhere.
    """
    if second.exists():
        return
    os.link(first, second)

"""The zip-slip defence, tested as an attacker would probe it.

A name from ``READDIR`` is chosen by the far end, and this is the code that stands between
``../../etc/cron.d/x`` and a file being written there. DESIGN.md 6 calls it a genuine,
exploited vulnerability class in file-transfer clients rather than a theoretical one, so the
tests here are adversarial rather than illustrative: every case is a thing a server could
actually send.

The Windows rules are exercised on Linux with ``windows=True``, because the environment that
matters is not the one CI runs on -- the same arrangement ``resolve_ssh_executable`` uses.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp.exceptions import UnsafePathError
from gantry_sftp.session import (
    WINDOWS_RESERVED_NAMES,
    DestinationLedger,
    check_component,
    check_contained,
    identity,
    local_child,
    unsafe_reason,
)

# --- names that must never become a filename ----------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        (b"..", "a relative directory entry"),
        (b".", "a relative directory entry"),
        (b"", "an empty name"),
        (b"../etc/passwd", "a path separator"),
        (b"../../etc/cron.d/x", "a path separator"),
        (b"/etc/passwd", "a path separator"),
        (b"sub/file", "a path separator"),
        (b"trailing/", "a path separator"),
        (b"nul\x00byte", "a NUL byte"),
    ],
)
def test_a_name_that_could_escape_is_refused_everywhere(name: bytes, reason: str):
    # Separator-and-dots cases are refused on every platform: they are the attack, not a
    # platform quirk.
    assert unsafe_reason(name, windows=False) == reason
    assert unsafe_reason(name, windows=True) == reason


@pytest.mark.parametrize(
    "name",
    [
        b"report.csv",
        b"a-file_with.many.dots",
        b"caf\xe9-\xff.bin",  # not valid UTF-8, and perfectly legal
        b"..hidden",  # starts with dots but is not `..`
        b"...",
        b"file..name",
        b" leading-space",
    ],
)
def test_an_ordinary_name_is_allowed_on_posix(name: bytes):
    # The other half of the test above. A validator that refuses everything is safe and
    # useless, and these are all names a POSIX server can legitimately hand back.
    assert unsafe_reason(name, windows=False) is None


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        (b"back\\slash", "a character Windows does not allow in a filename"),
        (b"C:evil", "a character Windows does not allow in a filename"),
        (b"stream.txt:hidden", "a character Windows does not allow in a filename"),
        (b"star*", "a character Windows does not allow in a filename"),
        (b"question?", "a character Windows does not allow in a filename"),
        (b'quote"', "a character Windows does not allow in a filename"),
        (b"pipe|", "a character Windows does not allow in a filename"),
        (b"bell\x07", "a control character"),
        (b"trailing.", "a trailing dot or space, which Windows strips"),
        (b"trailing ", "a trailing dot or space, which Windows strips"),
        (b"CON", "the reserved device name 'con'"),
        (b"con.txt", "the reserved device name 'con'"),
        (b"LPT1", "the reserved device name 'lpt1'"),
        (b"NUL.log", "the reserved device name 'nul'"),
    ],
)
def test_windows_rules_refuse_what_windows_treats_specially(name: bytes, reason: str):
    """Each of these is a name that is ordinary on Linux and dangerous on Windows.

    ``file.txt:stream`` writes an alternate data stream. ``C:evil`` is drive-relative.
    ``con.txt`` is the console from any directory. ``trailing.`` is silently stripped, so a
    name that passed validation becomes a different one on disk.
    """
    assert unsafe_reason(name, windows=True) == reason
    # And each is fine on POSIX, which is why the rules cannot simply be unioned: refusing
    # them everywhere would mean refusing to download files that are legal where they live.
    assert unsafe_reason(name, windows=False) is None


def test_every_reserved_device_name_is_covered():
    # The list is the point: missing one is a hole, and they are easy to half-remember.
    assert "con" in WINDOWS_RESERVED_NAMES
    assert {f"com{n}" for n in range(1, 10)} <= WINDOWS_RESERVED_NAMES
    assert {f"lpt{n}" for n in range(1, 10)} <= WINDOWS_RESERVED_NAMES
    for name in WINDOWS_RESERVED_NAMES:
        assert unsafe_reason(name.upper().encode(), windows=True) is not None
        assert unsafe_reason(name.encode() + b".txt", windows=True) is not None


def test_the_platform_decides_when_it_is_not_stated():
    # Injectable for the tests, and correct by default: the rules follow the machine the
    # file is being written to.
    assert unsafe_reason(b"CON") == (None if os.name != "nt" else "the reserved device name 'con'")


def test_the_refusal_carries_the_name_and_the_reason():
    with pytest.raises(UnsafePathError) as exc:
        check_component(b"../../etc/passwd")
    assert exc.value.args[0] == (
        "refusing to use the server-supplied name b'../../etc/passwd': it contains a path separator"
    )
    assert exc.value.name == b"../../etc/passwd"
    assert exc.value.reason == "a path separator"


@given(name=st.binary(max_size=40))
def test_an_allowed_name_never_contains_a_separator_or_a_dot_entry(name: bytes):
    # The property that actually matters, over arbitrary bytes: whatever else the validator
    # permits, it never permits something that can traverse.
    if unsafe_reason(name, windows=False) is None:
        assert b"/" not in name
        assert name not in (b".", b"..")
        assert name


@given(name=st.binary(max_size=40))
def test_an_allowed_name_stays_one_component_when_joined(name: bytes):
    # No tmp_path: this is path arithmetic and touches no filesystem, and a function-scoped
    # fixture is not reset between hypothesis examples anyway.
    parent = Path("/destination")
    if unsafe_reason(name, windows=False) is not None:
        return
    child = local_child(parent, name)
    assert child.parent == parent
    # And it survives the round trip back to the bytes the server sent.
    assert os.fsencode(child.name) == name


# --- containment, which catches what the name check cannot ---------------------------------


def test_a_path_inside_the_destination_is_returned_unchanged(tmp_path: Path):
    candidate = tmp_path / "sub" / "file.csv"
    assert check_contained(tmp_path, candidate) == candidate


def test_the_destination_itself_is_contained(tmp_path: Path):
    assert check_contained(tmp_path, tmp_path) == tmp_path


def test_a_symlinked_destination_directory_is_caught(tmp_path: Path):
    """The escape component validation cannot see.

    Every name is innocent: ``reports``, then ``passwd``. But ``reports`` is already a symlink
    to somewhere else on the local machine -- planted by a local attacker, or by an earlier
    download of a link. Only resolving the finished path catches it.
    """
    destination = tmp_path / "downloads"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "reports").symlink_to(outside)

    with pytest.raises(UnsafePathError) as exc:
        _ = check_contained(destination, destination / "reports" / "passwd")

    assert exc.value.reason == "a path that escapes the destination directory"
    assert exc.value.destination == str(destination)
    assert "which is not inside" in exc.value.args[0]


def test_a_file_that_is_itself_a_symlink_out_is_caught(tmp_path: Path):
    # The narrower version of the same thing: not a directory in the chain, but the target
    # file itself -- which is what an ordinary `get` would happily write through.
    destination = tmp_path / "downloads"
    destination.mkdir()
    (tmp_path / "secret.txt").write_text("original")
    (destination / "innocent.txt").symlink_to(tmp_path / "secret.txt")

    with pytest.raises(UnsafePathError):
        _ = check_contained(destination, destination / "innocent.txt")

    assert (tmp_path / "secret.txt").read_text() == "original"


def test_a_sibling_directory_with_a_shared_prefix_is_not_contained(tmp_path: Path):
    # The classic off-by-one in a containment check written with startswith: /tmp/downloads
    # and /tmp/downloads-evil share a prefix and are unrelated directories.
    destination = tmp_path / "downloads"
    destination.mkdir()
    (tmp_path / "downloads-evil").mkdir()

    with pytest.raises(UnsafePathError):
        _ = check_contained(destination, tmp_path / "downloads-evil" / "file.csv")


# --- destination collisions -------------------------------------------------------------------
#
# The second defence with a data-loss consequence, and unlike zip-slip it needs no hostile
# server at all: a case-sensitive server holding README.md beside readme.md, downloaded onto
# APFS or NTFS, is two legal remote names and one local file. Containment cannot see it --
# both paths are legitimately inside the destination.


def test_identity_uses_lstat_so_a_symlink_is_its_own_file(tmp_path: Path):
    # stat() would report the target's inode here, so a link planted in the destination would
    # read as a collision with whatever it points at. It is not one: O_NOFOLLOW refuses it.
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert identity(link) != identity(target)


def test_two_names_for_one_file_share_an_identity(tmp_path: Path):
    # A hard link is the honest stand-in for case folding on a case-sensitive filesystem:
    # two directory entries, one inode, which is exactly what APFS gives README.md/readme.md.
    first = tmp_path / "README.md"
    first.write_text("first")
    second = tmp_path / "readme.md"
    os.link(first, second)

    assert identity(first) == identity(second)


def test_an_absent_path_is_free(tmp_path: Path):
    assert DestinationLedger().collides_with(tmp_path / "nothing-here") is None


def test_a_file_this_run_did_not_write_is_not_a_collision(tmp_path: Path):
    # The ordinary re-download and the whole resume path. A file left by a previous run is
    # there to be overwritten; only a file *this* run wrote must not be.
    existing = tmp_path / "a.csv"
    existing.write_text("from last time")

    assert DestinationLedger().collides_with(existing) is None


def test_a_claimed_file_names_the_remote_path_that_holds_it(tmp_path: Path):
    written = tmp_path / "README.md"
    written.write_text("first")
    ledger = DestinationLedger()
    ledger.claim(written, b"/root/README.md")

    other_name = tmp_path / "readme.md"
    os.link(written, other_name)

    assert ledger.collides_with(other_name) == b"/root/README.md"


def test_a_failure_that_is_not_absence_propagates(tmp_path: Path):
    # Three states, and this is the third. Absent means free; anything else is a real error
    # and belongs to the open that follows, which reports it better than a bool could.
    not_a_directory = tmp_path / "file.txt"
    not_a_directory.write_text("x")

    with pytest.raises(NotADirectoryError):
        _ = DestinationLedger().collides_with(not_a_directory / "child")


def test_the_ledger_says_how_much_it_is_holding(tmp_path: Path):
    written = tmp_path / "a.csv"
    written.write_text("x")
    ledger = DestinationLedger()

    assert repr(ledger) == "<DestinationLedger 0 claimed>"
    ledger.claim(written, b"/root/a.csv")
    assert repr(ledger) == "<DestinationLedger 1 claimed>"

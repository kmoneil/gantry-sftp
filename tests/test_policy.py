"""The transfer decisions, exercised with no server, no subprocess and no event loop.

These functions lived in `_session.py` until the split, and every one of them was already
covered — through `Session.get`, `Session.put` and `get_tree`, which means through a real
`sftp-server` on a pipe. That coverage is not what this file adds. What it adds is the proof of
the claim `_policy.py`'s own docstring makes: that the split bought a seam, and these can be
driven with a `Path` and an `Attrs` and nothing else.

That claim is worth checking rather than asserting. A module can be moved out of an async file
and still be untestable without one — if it takes a session, if it awaits, if it reaches for a
handle. `tests/test_layer_discipline.py` proves `codec/` imports no clock and no socket; nothing
proved the same shape one layer up, and this is the cheapest demonstration of it: no fixture, no
`anyio`, no `conftest` server. If a decision function ever needs a session again, this file stops
compiling long before anybody notices the seam has closed.

Deliberately a thin sample rather than a second suite over 31 functions. Duplicating the
behavioural coverage would be two places to update and one of them would rot.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import gantry_sftp.session._policy as policy
from gantry_sftp.codec import Attrs, Times
from gantry_sftp.exceptions import TransferError
from gantry_sftp.session._listing import EntryKind
from gantry_sftp.session._mode import Mode
from gantry_sftp.session._policy import (
    _confirm_download_size,
    _download_mode,
    _download_resume_offset,
    _ensure_directory,
    _local_times,
    _optional_path,
    _preservation,
    _skip_reason,
    _wrong_path_type,
)
from gantry_sftp.session._publish import SizeCheck, TimePreservation


def test_the_module_is_the_synchronous_half_it_says_it_is():
    # The seam itself, and the reason the module-level import above is the assertion rather than
    # setup: this file imports `_policy` with no anyio, no transport and no conftest fixture, so
    # collecting it at all is the first half of the proof. The rest reads the source, because a
    # decision function that acquires a session or an await is how the seam closes again, and
    # neither shows up in a passing behavioural test.
    assert "Session" not in dir(policy), "a decision function has acquired a session again"
    source = Path(policy.__file__).read_text(encoding="utf-8")
    assert "await " not in source, "_policy.py has grown an await; it is the synchronous half"
    assert "import anyio" not in source


# --- mode ------------------------------------------------------------------------------------


def test_an_explicit_mode_is_what_the_download_lands_with():
    assert _download_mode(0o640, Attrs(), b"/remote/f") == 0o640


def test_no_mode_asked_leaves_the_download_at_its_creation_bits():
    # `None` rather than 0o600: the caller is not asking, so nothing chmods afterwards and the
    # descriptor keeps what it was opened with.
    assert _download_mode(None, Attrs(), b"/remote/f") is None


def test_preserve_takes_the_servers_bits_when_the_server_sent_any():
    assert _download_mode(Mode.PRESERVE, Attrs(permissions=0o100644), b"/remote/f") == 0o644


def test_preserve_with_no_permissions_reported_refuses_rather_than_returning_none():
    # Worth stating why this is a refusal and not a `None`, because `None` is what the two
    # cases above return and it is the obvious guess. Returning it here would leave the file at
    # the 0o600 a download creates and report success -- indistinguishable from having
    # genuinely preserved a 0o600 file, which is the class of silent wrong answer the whole
    # result-object design exists to remove. v3 makes every ATTRS field optional, so a server
    # sending none is entitled rather than broken; there is simply nothing to preserve.
    with pytest.raises(TransferError) as refusal:
        _download_mode(Mode.PRESERVE, Attrs(), b"/remote/f")
    assert refusal.value.args[0] == (
        "mode=Mode.PRESERVE was asked for but the server sent no permissions for "
        "b'/remote/f', so there is nothing to preserve; pass an explicit mode= or "
        "leave it unset to keep the 0o600 a download creates"
    )
    # And it refuses before a byte moves, so a terse server costs no transfer.
    assert refusal.value.transferred == 0


# --- timestamps ------------------------------------------------------------------------------


def test_preservation_reports_which_of_the_three_outcomes_was_reached():
    assert _preservation(asked=False, times=Times(1, 2)) is TimePreservation.SKIPPED
    assert _preservation(asked=True, times=None) is TimePreservation.UNAVAILABLE
    assert _preservation(asked=True, times=Times(1, 2)) is TimePreservation.PRESERVED


def test_local_times_reads_a_real_file_and_truncates_to_v3_seconds(tmp_path):
    # The one function here that touches a disk, which is the point: local I/O is synchronous
    # and belongs on this side of the split. v3 carries seconds, so a float mtime truncates.
    target = tmp_path / "f"
    target.write_bytes(b"x")
    times = _local_times(target)
    assert isinstance(times.atime, int)
    assert isinstance(times.mtime, int)
    assert times.mtime == int(target.stat().st_mtime)


# --- the size gate ----------------------------------------------------------------------------


def test_a_download_that_matched_the_announced_size_passes_rung_three(tmp_path):
    assert (
        _confirm_download_size(b"/remote/f", tmp_path / "f", arrived=10, announced=10, asked=True)
        is SizeCheck.MATCHED
    )


def test_a_server_that_announced_no_size_reports_unavailable_rather_than_success(tmp_path):
    # The distinction DESIGN 6's ladder exists for: "the check could not run" is not "the check
    # passed", and reporting the second would be the silent-success bug the ladder is against.
    assert (
        _confirm_download_size(b"/remote/f", tmp_path / "f", arrived=10, announced=None, asked=True)
        is SizeCheck.UNAVAILABLE
    )


def test_turning_the_size_check_off_is_reported_rather_than_silent(tmp_path):
    assert (
        _confirm_download_size(b"/remote/f", tmp_path / "f", arrived=3, announced=10, asked=False)
        is SizeCheck.SKIPPED
    )


def test_a_short_download_raises_and_the_error_names_both_paths_and_the_counts(tmp_path):
    # **This name was true of the message and false of the error.** It asserted three substrings
    # and nothing about the state the exception carries, so blanking `local_path` -- the file
    # left on disk, which is the one fact deciding between resuming and deleting -- changed
    # nothing here. Two mutants survived behind a test whose name says otherwise, which is the
    # shape where a name stops anybody reading the body. D-162's triage of the first CI run.
    local = tmp_path / "f"
    with pytest.raises(TransferError) as failure:
        _confirm_download_size(b"/remote/f", local, arrived=3, announced=10, asked=True)
    message = failure.value.args[0]
    assert "3" in message
    assert "10" in message
    assert "/remote/f" in message
    assert failure.value.local_path == str(local)
    assert failure.value.remote_path == b"/remote/f"
    # `arrived` rather than 0: rung three runs after bytes have moved, and reporting none of
    # them would make a truncation look like a failure that happened before the transfer began.
    assert failure.value.transferred == 3
    assert failure.value.offset == 3


# --- the small predicates ----------------------------------------------------------------------


def test_a_skip_reason_is_a_sentence_a_human_reads_in_a_report():
    assert _skip_reason(EntryKind.SYMLINK)
    assert _skip_reason(EntryKind.UNKNOWN)
    assert _skip_reason(EntryKind.OTHER)


def test_an_absent_path_stays_absent_rather_than_becoming_an_empty_name():
    # `None` and `b""` are different requests, and collapsing them would send an empty path.
    assert _optional_path(None) is None
    assert _optional_path("") == b""
    assert _optional_path("/incoming") == b"/incoming"
    assert _optional_path(b"/incoming") == b"/incoming"


def test_a_local_path_passed_as_a_remote_one_is_explained_rather_than_coerced():
    # The mistake this repo expects: `Path` is a *local* path type, and a remote name is bytes.
    explanation = _wrong_path_type(Path("/incoming"))
    assert "Path" in explanation
    assert _wrong_path_type(42)


# --- the state these errors carry, which is not the message ------------------------------------
#
# D-162's triage of the first CI mutation run. Six survivors across these three raise sites were
# all one shape: blank the `local_path` the error carries and every assertion still passes,
# because the assertions stopped at the message. DoD 3 says these errors carry state rather than
# strings -- `local_path` on a failed `get` is *the file left on disk*, which is the one fact a
# caller needs to decide between resuming and deleting.
#
# Two mutants in the same cluster are **not** here and that is deliberate: dropping `transferred=0`
# from `_download_mode` and from the too-long-partial refusal restates `TransferError`'s own
# default, so no assertion can distinguish them. They are argued in the register instead.


def test_a_resume_with_no_remote_size_names_the_partial_it_could_not_check(tmp_path):
    target = tmp_path / "partial.bin"
    target.write_bytes(b"already here")
    with pytest.raises(TransferError) as exc:
        _download_resume_offset(target, None, b"/remote/f")
    assert exc.value.local_path == str(target)
    assert exc.value.remote_path == b"/remote/f"


def test_a_partial_longer_than_the_remote_file_names_both_and_where_it_stopped(tmp_path):
    target = tmp_path / "partial.bin"
    target.write_bytes(b"0123456789")
    with pytest.raises(TransferError) as exc:
        _download_resume_offset(target, 4, b"/remote/f")
    assert exc.value.local_path == str(target)
    assert exc.value.remote_path == b"/remote/f"
    # The offset is what is on disk, not the remote size: it says where the disagreement is.
    assert exc.value.offset == 10


def test_creating_a_walked_directory_refuses_when_its_parent_is_missing(tmp_path):
    """`parents=False` is a guard whose whole worth is that it never fires.

    The tree walk creates parents before children, so `parents=True` would behave identically
    for every input the walk produces -- which is why the mutation survived. What the default
    buys is the case the walk is not supposed to produce: a child emitted before its parent
    becomes a loud `FileNotFoundError` here instead of a silently invented directory chain,
    under a destination the caller never asked us to create.
    """
    orphan = tmp_path / "never-created" / "child"
    with pytest.raises(FileNotFoundError):
        _ = _ensure_directory(orphan)
    assert not orphan.exists()
    assert not orphan.parent.exists()
    # And the other half, so this pins the argument rather than only the refusal.
    assert _ensure_directory(orphan, parents=True) == orphan
    assert orphan.is_dir()

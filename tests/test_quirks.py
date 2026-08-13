"""Fingerprinting a server from what it advertised, and the bound on what that may cost.

The identification here was **diagnostic only** for four releases, and these tests exist as much
to pin the bound as to pin the matching. A fingerprint is a guess about an opaque peer, so a
wrong guess has to cost a wrong name in a log line rather than a wrong answer in a file.

**One behavioural rule now reads a profile** -- D-30's bounded retry, gated on
``transient_messages`` and on ``informative_messages`` together. It does not weaken the bound
above: the worst a wrong fingerprint can do through it is repeat an ``OPEN`` that was going to
fail anyway. The rule and its gate are tested in ``tests/test_transient.py``, against the server
that produced the message in ``live-tests/test_transient_live.py``.

The extension sets below are the ones ``live-tests/matrix.py`` actually measured. They are
duplicated here rather than imported, on purpose: ``live-tests/`` needs real servers and this
file must run in the ordinary suite. If the two drift, the live matrix is the one that is
right, and it fails loudly when a server changes.
"""

from __future__ import annotations

import pytest

from gantry_sftp.session import PROFILES, UNKNOWN, ServerProfile, identify, parse_vendor_id
from gantry_sftp.session._quirks import _from_vendor_id


def vendor_id(vendor: bytes, product: bytes, version: bytes, build: int = 0) -> bytes:
    """Build a ``vendor-id`` body: three strings and a uint64."""
    parts = [
        len(vendor).to_bytes(4, "big"),
        vendor,
        len(product).to_bytes(4, "big"),
        product,
        len(version).to_bytes(4, "big"),
        version,
        build.to_bytes(8, "big"),
    ]
    return b"".join(parts)


ASYNCSSH_VENDOR_ID = vendor_id(b"Ron Frederick", b"AsyncSSH", b"2.24.0")
"""Captured off asyncssh 2.24.0 on 2026-07-27, reconstructed field for field.

The layout -- ``string vendor, string product, string version, uint64 build`` -- is sourced
from asyncssh's own ``_parse_vendor_id`` and from the bytes on the wire. It is in neither
``draft-ietf-secsh-filexfer-05`` nor ``-13``; both were checked, because an earlier comment
in this repo cited draft-05 for it and was wrong.
"""

OPENSSH_EXTENSIONS = {
    b"posix-rename@openssh.com": b"1",
    b"statvfs@openssh.com": b"2",
    b"fstatvfs@openssh.com": b"2",
    b"hardlink@openssh.com": b"1",
    b"fsync@openssh.com": b"1",
    b"lsetstat@openssh.com": b"1",
    b"limits@openssh.com": b"1",
    b"expand-path@openssh.com": b"1",
    b"copy-data": b"1",
    b"home-directory": b"1",
    b"users-groups-by-id@openssh.com": b"1",
}

ASYNCSSH_EXTENSIONS = {
    b"newline": b"\n",
    b"vendor-id": ASYNCSSH_VENDOR_ID,
    b"posix-rename@openssh.com": b"1",
    b"hardlink@openssh.com": b"1",
    b"fsync@openssh.com": b"1",
    b"lsetstat@openssh.com": b"1",
    b"limits@openssh.com": b"1",
    b"copy-data": b"1",
    b"ranges@asyncssh.com": b"1",
    b"statvfs@openssh.com": b"2",
    b"fstatvfs@openssh.com": b"2",
}

PARAMIKO_EXTENSIONS = {b"check-file": b"md5,sha1"}


# --- vendor-id, the only structured identity any of them sends ---------------------------------


def test_a_vendor_id_decodes_to_its_four_fields():
    assert parse_vendor_id(ASYNCSSH_VENDOR_ID) == ("Ron Frederick", "AsyncSSH", "2.24.0", 0)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\x00\x00\x00\x04",  # a length with nothing after it
        b"\x00\x00\x00\xff" + b"short",  # a length that overruns the body
        vendor_id(b"v", b"p", b"1")[:-1],  # the uint64 truncated by one byte
        b"\x00" * 3,
    ],
    ids=["empty", "length-only", "overrun", "short-build", "truncated"],
)
def test_a_malformed_vendor_id_is_not_an_error(body: bytes):
    """Three states, and the third is not an exception.

    This is server-supplied input parsed during connection setup. A malformed brag must not
    fail the connection -- the server is still perfectly usable, we just do not know its name.
    """
    assert parse_vendor_id(body) is None


def test_a_vendor_id_that_is_not_utf8_still_decodes():
    # Names are bytes on the wire like everything else. A server with one stray byte in its
    # product name must not turn a fingerprint into a UnicodeDecodeError.
    parsed = parse_vendor_id(vendor_id(b"\xff\xfe", b"Weird\xff", b"1.0"))
    assert parsed is not None
    assert parsed[1].startswith("Weird")


def test_a_stray_byte_in_the_version_does_not_discard_the_whole_identity():
    """Each of the three strings is decoded separately, and each needs the lenient handler.

    The product's is asserted above; the version's was not, and the failure it hides is worse
    than a wrong string. A strict decode raises `UnicodeDecodeError`, the broad `except` here
    catches it, and the *entire* vendor-id is discarded -- so a server with one bad byte in its
    version goes from identified to unknown, and every profile decision made from its name
    silently stops happening.
    """
    parsed = parse_vendor_id(vendor_id(b"Acme", b"Widget", b"2.1\xff"))
    assert parsed is not None
    assert parsed[1] == "Widget"
    assert parsed[2].startswith("2.1")


# --- matching ----------------------------------------------------------------------------------


def test_openssh_is_recognised_from_its_marker_extensions():
    assert identify(OPENSSH_EXTENSIONS) is PROFILES["openssh"]


def test_asyncssh_is_recognised_from_its_vendor_id_and_carries_the_version():
    profile = identify(ASYNCSSH_EXTENSIONS)
    assert profile.name == "asyncssh"
    assert profile.version == "2.24.0"
    assert profile.label == "asyncssh/2.24.0"


@pytest.mark.parametrize(
    "product", [b"asyncssh", b"AsyncSSH", b"ASYNCSSH"], ids=["lower", "mixed", "upper"]
)
def test_a_known_product_is_matched_whatever_case_it_announces_itself_in(product: bytes):
    """The lookup folds the product name, and the table's keys are lowercase.

    A server chooses how to spell its own name and can change that spelling between releases,
    so matching it exactly would make the profile table depend on a cosmetic decision made at
    the other end. Asserted across three spellings because the fold is one method call: `.get`
    on the raw name misses the mixed case, and folding the *wrong* way misses all three.
    """
    profile = _from_vendor_id(vendor_id(b"asyncssh", product, b"2.24.0"))
    assert profile is not None
    assert profile is not UNKNOWN
    assert profile.name == "asyncssh"
    assert profile.description == PROFILES["asyncssh"].description
    assert profile.version == "2.24.0"


def test_paramiko_is_recognised_from_check_file():
    assert identify(PARAMIKO_EXTENSIONS) is PROFILES["paramiko"]


def test_a_server_advertising_nothing_is_unknown_rather_than_guessed():
    # §7 says endpoints often advertise nothing at all. That is an answer, not a failure, and
    # it is the one this library will meet most often in the field.
    assert identify({}) is UNKNOWN


def test_an_old_openssh_without_the_marker_extensions_is_unknown():
    """The documented limitation, pinned so it is not mistaken for a bug.

    The markers all arrived in OpenSSH 8.9-9.0. An older one advertises none of them, and is
    reported as unknown rather than matched by something so weak that asyncssh matches it too.
    """
    old_openssh = {
        b"posix-rename@openssh.com": b"1",
        b"statvfs@openssh.com": b"2",
        b"fsync@openssh.com": b"1",
        b"hardlink@openssh.com": b"1",
    }
    assert identify(old_openssh) is UNKNOWN


def test_a_server_we_have_no_profile_for_is_still_named_if_it_says_who_it_is():
    """Better than unknown by exactly the amount the server volunteered.

    A ``vendor-id`` from something not in the table gives a name and a version and nothing
    else -- no behaviour is assumed, and ``informative_messages`` stays False because a
    stranger's error text is not evidence.
    """
    profile = identify({b"vendor-id": vendor_id(b"Example Corp", b"MOVEit", b"2025.1")})
    assert profile.name == "moveit"
    assert profile.version == "2025.1"
    assert profile.informative_messages is False
    assert "not in this library's profile table" in profile.description


def test_a_malformed_vendor_id_falls_through_to_the_markers():
    # A server that sends both a broken vendor-id and OpenSSH's markers is still OpenSSH.
    # Without the fall-through it would be unknown on the strength of the broken field.
    assert identify({b"vendor-id": b"\xff", **OPENSSH_EXTENSIONS}) is PROFILES["openssh"]


def test_a_vendor_id_with_an_empty_product_name_is_not_an_identity():
    assert identify({b"vendor-id": vendor_id(b"Vendor", b"", b"1.0")}) is UNKNOWN


# --- what a profile is allowed to claim ---------------------------------------------------------


def test_only_asyncssh_claims_its_error_messages_are_worth_reading():
    """The measurement that stopped the behavioural half of the registry being built.

    OpenSSH answers five distinct FAILURE conditions -- MKDIR on an existing directory,
    RENAME onto an existing target, CREAT|EXCL on an existing file, RMDIR of a non-empty
    directory, REMOVE of a directory -- with the single word "Failure". Paramiko does the
    same. The message is a constant function of the status code on both, so a message-based
    rule has nothing to read, which is why D-30 is impossible on the reference server rather
    than merely blocked.
    """
    assert PROFILES["openssh"].informative_messages is False
    assert PROFILES["paramiko"].informative_messages is False
    assert PROFILES["asyncssh"].informative_messages is True
    assert UNKNOWN.informative_messages is False, "a stranger gets the conservative answer"


def test_every_shipped_profile_is_one_the_matrix_can_start():
    """CLAUDE.md: a quirks profile without a passing test against that server is a rumor.

    §7 proposes shipping profiles for the top ten implementations. This ships three, because
    three is how many `live-tests/matrix.py` can actually run. The assertion is deliberately
    the *count* as well as the names: adding a fourth from vendor documentation would pass a
    names-only check and would be exactly the rumour that rule forbids.
    """
    assert set(PROFILES) == {"openssh", "asyncssh", "paramiko"}


def test_a_profile_is_immutable():
    # Profiles are shared module-level singletons handed out to every session. One that could
    # be mutated would let a caller's edit follow the next connection to a different server.
    with pytest.raises(AttributeError):
        PROFILES["openssh"].name = "something else"  # type: ignore[misc]


def test_a_profile_without_a_version_labels_itself_by_name_alone():
    assert ServerProfile("x", "an x").label == "x"
    assert ServerProfile("x", "an x", version="1.2").label == "x/1.2"

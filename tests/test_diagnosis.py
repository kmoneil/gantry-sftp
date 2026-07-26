"""Classifying OpenSSH's stderr, against the text OpenSSH actually produces.

Every stderr fixture in this file was captured from OpenSSH 10.0p2 driven into that exact
failure mode against a real `sshd`, not written from memory. That is the difference between a
classifier that works and one that quietly stops matching after a wording change -- a wrong
marker does not raise, it just returns the base class forever, and `except AuthenticationError`
goes back to never matching.

The live proof that these classes really are raised end to end is in
`live-tests/test_ssh_transport.py`; this file is the fast lane over the pure decision.
"""

from __future__ import annotations

import pytest

from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError
from gantry_sftp.transport import classify_failure

# --- Captured verbatim from OpenSSH 10.0p2 -----------------------------------------------

WRONG_KEY = "dev@127.0.0.1: Permission denied (publickey).\n"

UNKNOWN_HOST_KEY = (
    "No ED25519 host key is known for [127.0.0.1]:45845 and you have requested "
    "strict checking.\n"
    "Host key verification failed.\n"
)

CHANGED_HOST_KEY = """@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:/87pb0pvaC5xmV5+syQ7aswWlhjgAonT2QdcLqKz6Gw.
Please contact your system administrator.
Add correct host key in /tmp/x/bad_known_hosts to get rid of this message.
Offending ED25519 key in /tmp/x/bad_known_hosts:1
  remove with:
  ssh-keygen -f '/tmp/x/bad_known_hosts' -R '[127.0.0.1]:45845'
Host key for [127.0.0.1]:45845 has changed and you have requested strict checking.
Host key verification failed.
"""

TOO_MANY_AUTH_FAILURES = (
    "Received disconnect from 127.0.0.1 port 35937:2: Too many authentication failures\n"
    "Disconnected from 127.0.0.1 port 35937\n"
)

CONNECTION_REFUSED = "ssh: connect to host 127.0.0.1 port 58561: Connection refused\n"

UNRESOLVABLE = "ssh: Could not resolve hostname no-such-host.invalid: Name or service not known\n"

NO_MATCHING_HOST_KEY_TYPE = (
    "Unable to negotiate with 127.0.0.1 port 45845: no matching host key type found. "
    "Their offer: ssh-ed25519\n"
)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        pytest.param(WRONG_KEY, AuthenticationError, id="wrong-key"),
        pytest.param(TOO_MANY_AUTH_FAILURES, AuthenticationError, id="too-many-failures"),
        pytest.param(UNKNOWN_HOST_KEY, HostKeyError, id="host-not-known"),
        pytest.param(CHANGED_HOST_KEY, HostKeyError, id="host-key-changed"),
        pytest.param(CONNECTION_REFUSED, ConnectError, id="refused"),
        pytest.param(UNRESOLVABLE, ConnectError, id="unresolvable"),
        pytest.param(NO_MATCHING_HOST_KEY_TYPE, ConnectError, id="no-matching-host-key-type"),
        pytest.param("", ConnectError, id="empty"),
        pytest.param("something nobody has ever seen\n", ConnectError, id="unknown"),
    ],
)
def test_real_openssh_stderr_is_classified(stderr, expected):
    assert classify_failure(stderr) is expected


def test_too_many_failures_does_not_contain_permission_denied():
    # The reason AUTH_MARKERS needs a second entry. If this ever becomes false, one marker
    # would do -- and if it silently became false the other way round, the second marker
    # would be dead code nobody noticed.
    assert "Permission denied" not in TOO_MANY_AUTH_FAILURES


def test_a_host_key_failure_is_not_reported_as_an_authentication_failure():
    # The dangerous direction. Telling someone to check their password when the host's
    # identity changed is how an interception goes unnoticed, so this is asserted on its own
    # rather than left implied by the table above.
    assert classify_failure(CHANGED_HOST_KEY) is not AuthenticationError
    assert classify_failure(UNKNOWN_HOST_KEY) is not AuthenticationError


def test_host_keys_win_when_both_markers_are_present():
    # OpenSSH prints a *server-supplied* banner to stderr, so a hostile server can put
    # "Permission denied" in there. It cannot remove the host-key line ssh itself writes, and
    # checking host keys first is what makes that harmless.
    hostile_banner = "Permission denied\n" + UNKNOWN_HOST_KEY
    assert classify_failure(hostile_banner) is HostKeyError


def test_a_no_matching_host_key_type_error_is_not_a_host_key_error():
    # It mentions host keys and is not one. The remedy is a HostKeyAlgorithms setting, not a
    # changed identity, and folding it in would make `except HostKeyError` mean two different
    # things -- diluting exactly the signal the class exists to carry.
    assert classify_failure(NO_MATCHING_HOST_KEY_TYPE) is ConnectError


def test_the_specific_classes_are_still_catchable_as_the_base():
    # Anyone who wrote `except ConnectError` before this change must keep working: making an
    # error more specific must not stop the general handler catching it.
    assert issubclass(AuthenticationError, ConnectError)
    assert issubclass(HostKeyError, ConnectError)
    assert not issubclass(AuthenticationError, HostKeyError)
    assert not issubclass(HostKeyError, AuthenticationError)


def test_markers_are_matched_per_line_so_a_truncated_buffer_still_classifies():
    # StderrBuffer drops the middle of a chatty child's output and marks the gap. The decisive
    # line is the last one, which is the half that survives -- but assert it rather than
    # assuming, since head-only truncation would have discarded exactly this.
    truncated = "... [8192 bytes dropped] ...\nHost key verification failed.\n"
    assert classify_failure(truncated) is HostKeyError


def test_leading_and_trailing_whitespace_does_not_defeat_a_marker():
    assert classify_failure("   Host key verification failed.   \n") is HostKeyError
    assert classify_failure("\t dev@h: Permission denied (publickey). \n") is AuthenticationError

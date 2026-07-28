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
from gantry_sftp.transport import (
    INTERACTIVE_AUTH_METHODS,
    build_ssh_argv,
    classify_failure,
    password_auth_hint,
)

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


# --- the password hint, where the text alone cannot answer the question --------------------

# Both captured on 2026-07-28 driving the real `ssh` client at a server that offers password
# authentication. The two spellings are the point: OpenSSH's sshd and asyncssh's server were
# configured to do the same thing and named the methods differently, so a rule matching the
# literal "(password)" would have worked against one and silently missed the other.
PASSWORD_REFUSED_BY_OPENSSH = "dev@127.0.0.1: Permission denied (password).\n"
PASSWORD_REFUSED_BY_ASYNCSSH = "dev@127.0.0.1: Permission denied (keyboard-interactive,password).\n"

BOTH_SPELLINGS = [
    pytest.param(PASSWORD_REFUSED_BY_OPENSSH, id="openssh"),
    pytest.param(PASSWORD_REFUSED_BY_ASYNCSSH, id="asyncssh"),
]


def argv_with(batch_mode: str) -> list[str]:
    return build_ssh_argv("example.com", options={"BatchMode": batch_mode})


@pytest.mark.parametrize("stderr", BOTH_SPELLINGS)
def test_batchmode_yes_against_an_offered_password_names_the_option_that_disabled_it(stderr):
    hint = password_auth_hint(stderr, argv=argv_with("yes"), askpass_armed=False)
    assert hint == (
        "the server offered password authentication and this client had it switched off: "
        "BatchMode=yes suppresses the askpass helper outright, so no password was ever sent. "
        "Pass password=... to open_ssh_transport()"
    )


@pytest.mark.parametrize("stderr", BOTH_SPELLINGS)
def test_no_askpass_at_all_gets_its_own_diagnosis_not_the_batchmode_one(stderr):
    # **The reason this function takes three arguments.** Measured on 2026-07-28: this case
    # and the one above produce byte-identical stderr, so a rule keyed on the message would
    # have to pick one cause and would be wrong half the time.
    hint = password_auth_hint(stderr, argv=argv_with("no"), askpass_armed=False)
    assert hint == (
        "the server offered password authentication and this client had no way to answer the "
        "prompt: no askpass helper was configured, and ssh cannot prompt when its input is a "
        "pipe. Pass password=... to open_ssh_transport()"
    )


def test_one_stderr_produces_two_different_diagnoses_depending_on_what_we_sent():
    # Guards the guard, and states the finding as an assertion: the *same* server output has
    # two different causes here, so anything derived from the text alone cannot tell them
    # apart. A refactor that dropped the argv argument would make these two equal and this is
    # the test that would notice.
    stderr = PASSWORD_REFUSED_BY_ASYNCSSH
    disabled = password_auth_hint(stderr, argv=argv_with("yes"), askpass_armed=False)
    unanswerable = password_auth_hint(stderr, argv=argv_with("no"), askpass_armed=False)
    assert disabled != unanswerable
    assert "BatchMode=yes" in disabled
    assert "no way to answer" in unanswerable


@pytest.mark.parametrize("stderr", BOTH_SPELLINGS)
def test_a_connection_that_did_answer_the_prompt_gets_no_hint(stderr):
    # We supplied a password and it was refused. Why is between the user and the server:
    # a wrong secret, a locked account, a source-address policy. Guessing would be noise.
    assert password_auth_hint(stderr, argv=argv_with("no"), askpass_armed=True) == ""
    assert password_auth_hint(stderr, argv=argv_with("yes"), askpass_armed=True) == ""


def test_a_publickey_only_refusal_gets_no_hint():
    # Nothing about our configuration stood in the way: the server never offered a method a
    # password could satisfy.
    assert password_auth_hint(WRONG_KEY, argv=argv_with("yes"), askpass_armed=False) == ""


@pytest.mark.parametrize(
    "stderr",
    [
        pytest.param("", id="empty"),
        pytest.param(CONNECTION_REFUSED, id="refused"),
        pytest.param(UNKNOWN_HOST_KEY, id="host-key"),
        pytest.param(TOO_MANY_AUTH_FAILURES, id="too-many-failures"),
        pytest.param("Permission denied (unterminated\n", id="unterminated-list"),
        pytest.param("Permission denied\n", id="no-list-at-all"),
    ],
)
def test_nothing_that_is_not_an_offered_password_produces_a_hint(stderr):
    assert password_auth_hint(stderr, argv=argv_with("yes"), askpass_armed=False) == ""


def test_the_word_password_in_a_server_banner_is_not_an_offered_method():
    # The banner is server-supplied text, so it is hostile input. Only the parenthesised list
    # ssh itself writes counts as a statement about methods.
    banner = "Contact the helpdesk to reset your password.\n" + WRONG_KEY
    assert password_auth_hint(banner, argv=argv_with("yes"), askpass_armed=False) == ""


def test_the_joined_option_spelling_is_read_too():
    # build_ssh_argv always emits `-o Name=value`, but argv is not always ours.
    joined = ["ssh", "-oBatchMode=yes", "-s", "--", "example.com", "sftp"]
    hint = password_auth_hint(PASSWORD_REFUSED_BY_OPENSSH, argv=joined, askpass_armed=False)
    assert "BatchMode=yes" in hint


def test_an_argv_with_no_batchmode_at_all_falls_back_to_the_answerable_diagnosis():
    # Absent is not "yes". Claiming BatchMode disabled something it never set would send the
    # reader to look for a line that is not there.
    bare = ["ssh", "-s", "--", "example.com", "sftp"]
    hint = password_auth_hint(PASSWORD_REFUSED_BY_OPENSSH, argv=bare, askpass_armed=False)
    assert "no way to answer" in hint
    assert "BatchMode" not in hint


def test_the_interactive_methods_are_both_of_the_ones_a_helper_can_answer():
    assert set(INTERACTIVE_AUTH_METHODS) == {"password", "keyboard-interactive"}


@pytest.mark.parametrize("stderr", BOTH_SPELLINGS)
def test_a_hinted_failure_is_still_classified_as_an_authentication_error(stderr):
    # The hint is additional state, not a reclassification. `except AuthenticationError` must
    # keep matching.
    assert classify_failure(stderr) is AuthenticationError

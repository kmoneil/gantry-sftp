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

import errno

import pytest

from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError
from gantry_sftp.transport import (
    INTERACTIVE_AUTH_METHODS,
    build_ssh_argv,
    classify_failure,
    missing_executable_hint,
    password_auth_hint,
)
from gantry_sftp.transport._diagnosis import _offered_methods

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


# --- the two parsers, against shapes a well-formed capture never has ------------------------
#
# Both read attacker-influenced input: `_offered_methods` parses text a server had a hand in,
# and `_option_value` reads an argv the caller may have built themselves. Every case above uses
# one tidy refusal line and an argv this library produced, which left thirteen mutants alive in
# the two of them -- all of them about the shapes a real capture eventually has.


def test_every_refusal_line_is_read_not_just_until_the_first_gap():
    """Driven at `_offered_methods` directly, because the hint absorbs the difference.

    Routing these through `password_auth_hint` was the first attempt and it killed none of
    them: the hint only asks whether the offered set *intersects* the interactive methods, so
    a parser that reads too much or too little usually lands on the same yes/no. The parser is
    the unit with the behaviour, so it is the unit under test.

    `ssh` emits more than one `Permission denied (...)` when it tries several identities, and
    `StderrBuffer` glues a head and a tail together, so several of them interleaved with
    ordinary lines is what a real capture looks like.
    """
    # A line with no marker in the middle must not stop the scan.
    interleaved = (
        "dev@a: Permission denied (publickey).\n"
        "debug1: Next authentication method: password\n"
        "dev@b: Permission denied (password).\n"
    )
    assert _offered_methods(interleaved) == frozenset({"publickey", "password"})

    # Nor must a marker line whose list never closes.
    unterminated = "dev@a: Permission denied (publickey\ndev@b: Permission denied (password).\n"
    assert _offered_methods(unterminated) == frozenset({"password"})


def test_the_method_list_ends_at_the_first_close_paren():
    """A bracket later in the line must not extend the list to reach it.

    Server-supplied text lands on these lines, and a banner containing a parenthesis with a
    comma in it would otherwise be read as a method list -- turning a publickey-only refusal
    into one that appears to offer a password, which is a hint pointing at the wrong cause.
    """
    trailing = "dev@h: Permission denied (publickey). (ask an admin,password resets here)\n"
    assert _offered_methods(trailing) == frozenset({"publickey"})

    # The shape that actually distinguishes first-from-last: a bare `password` token after it.
    hostile = "dev@h: Permission denied (publickey). (a,password)\n"
    assert _offered_methods(hostile) == frozenset({"publickey"}), "read to the last bracket"


def test_only_the_first_marker_on_a_line_starts_the_list():
    """Two markers in one line: the first opens the list, not the last."""
    doubled = "Permission denied (password). Permission denied (publickey).\n"
    assert _offered_methods(doubled) == frozenset({"password"})


def test_an_empty_method_name_is_dropped_rather_than_counted():
    """`(publickey,)` names one method and a stray comma.

    Asserted on the set rather than through the hint, where an empty string could never have
    changed the answer -- it is not one of the interactive methods either way.
    """
    assert _offered_methods("dev@h: Permission denied (publickey,).\n") == frozenset({"publickey"})
    assert _offered_methods("dev@h: Permission denied ().\n") == frozenset()
    assert _offered_methods("dev@h: Permission denied (,).\n") == frozenset()


@pytest.mark.parametrize(
    ("argv", "why"),
    [
        pytest.param(["ssh", "-o"], "a bare -o with nothing after it", id="trailing-bare-o"),
        pytest.param(
            ["ssh", "BatchMode=yes", "-s", "--", "h", "sftp"],
            "the value present but not as an option",
            id="value-without-its-o",
        ),
        pytest.param(["ssh", "-s", "--", "h", "sftp", "-o"], "a stray trailing -o", id="stray-o"),
    ],
)
def test_reading_an_option_off_a_ragged_argv_neither_raises_nor_invents(argv, why):
    """`_option_value` indexes past its own element, so the end of argv is where it breaks.

    Every existing case here passes an argv this library built, which is always well-formed.
    The docstring says argv "is not always ours" -- so these are the shapes that follow from
    taking that seriously: an option with no value, an option at the very end, and a value
    that never had an `-o` in front of it. None may raise, and none may be read as `yes`.
    """
    hint = password_auth_hint(PASSWORD_REFUSED_BY_OPENSSH, argv=argv, askpass_armed=False)
    assert "no way to answer" in hint, f"{why} was misread as BatchMode=yes"
    assert "BatchMode" not in hint


def test_an_option_at_the_very_end_of_argv_is_still_read():
    """The complement of the ragged cases: last-pair is well-formed and must be found.

    `-o BatchMode=yes` as the final two elements is an ordinary command line, and a bounds
    check one element too cautious would skip exactly it -- reporting "no way to answer" for a
    connection whose own `BatchMode` is the answer. The ragged cases above cannot catch that,
    because being too cautious gives them the result they want.
    """
    argv = ["ssh", "-s", "--", "h", "sftp", "-o", "BatchMode=yes"]
    hint = password_auth_hint(PASSWORD_REFUSED_BY_OPENSSH, argv=argv, askpass_armed=False)
    assert "BatchMode=yes" in hint


def test_an_argument_that_merely_contains_the_option_name_is_not_an_option():
    """`--BatchMode=yes` is a typo, not an `-o`, and must not be read as one.

    The joined form is matched by checking `[:2] == "-o"` *and* the name at offset 2. Only the
    second half was exercised, so the two could be an `or` -- and then any argument at all
    whose third character onward begins `BatchMode=` is read as the option. `--BatchMode=yes`
    is the realistic instance: a plausible mistake, present in argv, and it would make the
    hint name an option `ssh` never received.
    """
    argv = ["ssh", "--BatchMode=yes", "-s", "--", "h", "sftp"]
    hint = password_auth_hint(PASSWORD_REFUSED_BY_OPENSSH, argv=argv, askpass_armed=False)
    assert "no way to answer" in hint
    assert "BatchMode" not in hint


def test_the_option_value_is_the_one_after_the_dash_o_not_the_one_before():
    """Order matters and off-by-one goes both ways.

    `-o` takes the argument that *follows* it. Reading the one before finds whatever happened
    to precede the flag, which in a real command line is another option's value.
    """
    argv = ["ssh", "BatchMode=no", "-o", "BatchMode=yes", "-s", "--", "h", "sftp"]
    hint = password_auth_hint(PASSWORD_REFUSED_BY_OPENSSH, argv=argv, askpass_armed=False)
    assert "BatchMode=yes" in hint, "the argument before the flag was read instead of after it"


def test_the_interactive_methods_are_both_of_the_ones_a_helper_can_answer():
    assert set(INTERACTIVE_AUTH_METHODS) == {"password", "keyboard-interactive"}


@pytest.mark.parametrize("stderr", BOTH_SPELLINGS)
def test_a_hinted_failure_is_still_classified_as_an_authentication_error(stderr):
    # The hint is additional state, not a reclassification. `except AuthenticationError` must
    # keep matching.
    assert classify_failure(stderr) is AuthenticationError


# --- The failure with no stderr to classify (D-89) ----------------------------------------
#
# Every other hint in this module reads text OpenSSH produced. This one exists because there
# is no text: `exec` failed, so nothing ran, so there is no banner and nothing to match on.
# The only inputs are the executable name and an errno.


def test_a_missing_ssh_names_the_requirement_the_package_and_the_escape_hatch():
    hint = missing_executable_hint("ssh", errno_value=errno.ENOENT)
    # The requirement, stated as what the library is rather than as a caveat -- this is the
    # sentence the reader in a broken container has to be able to act on.
    assert "does not implement SSH" in hint
    assert "runs the OpenSSH client as a subprocess" in hint
    # All three package managers, because sys.platform cannot tell them apart.
    assert "apt-get install openssh-client" in hint
    assert "apk add openssh-client" in hint
    assert "dnf install openssh-clients" in hint
    # The override, for an ssh that exists somewhere PATH does not reach.
    assert "ssh_executable=" in hint
    # And the case where "install it" is not an answer at all.
    assert "distroless or scratch" in hint


def test_the_missing_hint_quotes_the_executable_it_actually_tried():
    # A Windows absolute path from resolve_ssh_executable's branch must appear as itself: the
    # reader needs to know *which* ssh was looked for, not that "ssh" was.
    windows = r"C:\Windows\System32\OpenSSH\ssh.exe"
    assert repr(windows) in missing_executable_hint(windows, errno_value=errno.ENOENT)


def test_a_present_but_unexecutable_ssh_gets_a_different_hint():
    # Distinct from absent: telling somebody to install a binary they already have sends them
    # to fix the wrong thing.
    hint = missing_executable_hint("/usr/bin/ssh", errno_value=errno.EACCES)
    assert "exists but could not be executed" in hint
    assert "apt-get" not in hint
    assert hint == missing_executable_hint("/usr/bin/ssh", errno_value=errno.EPERM)


@pytest.mark.parametrize("errno_value", [errno.ENOMEM, errno.EMFILE, errno.EAGAIN, None])
def test_a_spawn_failure_that_is_not_about_the_binary_gets_no_hint(errno_value):
    # The third state, decided rather than defaulted. Out of memory, out of file descriptors
    # and a platform that supplied no errno are all real, and none of them is fixed by
    # installing openssh-client -- so inventing advice would send the reader somewhere wrong.
    assert missing_executable_hint("ssh", errno_value=errno_value) == ""

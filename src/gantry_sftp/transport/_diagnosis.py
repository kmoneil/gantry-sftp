"""Turning OpenSSH's stderr into a typed error, without guessing.

``ConnectError`` carries OpenSSH's stderr verbatim, and that alone already fixes paramiko's
``Error reading SSH protocol banner`` -- the diagnosis was always there and was thrown away.
But *carrying* the text is not the same as *answering the question*, and the question users
actually ask is "was that my key, or has the host changed?". Answering it with a substring
search in their own code is worse than answering it here, which is why
:class:`~gantry_sftp.exceptions.AuthenticationError` and
:class:`~gantry_sftp.exceptions.HostKeyError` exist. Until this module they were defined and
never raised -- an ``except AuthenticationError`` that silently never matched, which is worse
than not shipping the class at all.

**Every marker below was read off OpenSSH 10.0p2 on the wire**, not recalled: a real ``sshd``
was driven into each failure mode and its stderr captured. That matters more than usual here,
because a marker that is subtly wrong does not fail -- it just quietly stops matching, and the
class goes back to being decorative.

**Host-key markers are checked before authentication markers, and that ordering is a security
property rather than tidiness.** The dangerous misclassification is one direction only:
reporting a host-key failure as a rejected password tells the user to check their credentials
when what actually happened may be interception. The reverse is merely unhelpful. OpenSSH
prints a *server-supplied* banner to stderr, so a hostile server can put any text it likes in
there -- but it cannot make a host-key marker disappear, and checking host keys first means an
injected ``Permission denied`` cannot mask one. (In practice a host-key failure aborts before
any banner is printed, so the two cannot even co-occur; the ordering is defence against the
case we have not thought of.)

**Anything unrecognised stays a plain ``ConnectError``.** A predicate has three states and the
third one is "do not know" -- a connection refused, a name that will not resolve, or a message
from an ``ssh`` we have never seen must not be guessed into a class whose whole value is that
it means something specific.

This lives in ``transport/`` rather than in the quirks layer that DESIGN.md 9 originally
assigned it to, and the reassignment is deliberate: these strings are facts about the OpenSSH
*client we spawn*, and the quirks layer is about the *servers we talk to*. A quirks profile
keyed on a server implementation is the wrong place to record what our own subprocess says.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError

HOST_KEY_MARKERS: Final = (
    "Host key verification failed.",
    "REMOTE HOST IDENTIFICATION HAS CHANGED",
)
"""Lines that mean the server's identity was not accepted.

Both were captured from OpenSSH 10.0p2. The first ends *both* host-key failure modes -- a host
that is not in ``known_hosts`` under ``StrictHostKeyChecking=yes``, and a host whose key has
changed. The second is the first line of the man-in-the-middle warning banner, kept separately
because it is the case that matters most and because a future OpenSSH could reword the summary
line without touching the banner.
"""

AUTH_MARKERS: Final = (
    "Permission denied",
    "Too many authentication failures",
)
"""Lines that mean the server refused our credentials.

``Permission denied`` is the common substring of OpenSSH's refusals -- measured as
``user@host: Permission denied (publickey).``, and the same prefix carries the password and
keyboard-interactive variants. ``Too many authentication failures`` is *not* one of them: it
arrives as ``Received disconnect from host port N:2: Too many authentication failures`` with no
``Permission denied`` anywhere in it, so matching only the first marker would leave the client
that offered too many keys reporting a bare ``ConnectError``. That one was found by probing
rather than by reasoning about it.
"""


INTERACTIVE_AUTH_METHODS: Final = ("password", "keyboard-interactive")
"""Methods OpenSSH answers by asking a human, which is what an askpass helper stands in for.

Both, not just ``password``: an appliance frequently offers *only* ``keyboard-interactive``,
and OpenSSH answers its prompts through the same helper. Matching the literal string
``(password)`` would have missed every one of them -- measured, since asyncssh's server
advertises ``(keyboard-interactive,password)`` where OpenSSH's ``sshd`` advertises
``(password)`` for the same configuration.
"""

_PERMISSION_DENIED = "Permission denied ("


def _offered_methods(stderr: str) -> frozenset[str]:
    """Which authentication methods the server named in its refusal.

    OpenSSH ends a rejected connection with ``user@host: Permission denied (publickey,password).``
    -- the parenthesised list is the *server's* methods, which is why it cannot answer the
    question users actually have. Parsed rather than substring-matched so that ``password``
    appearing in a server banner cannot be read as an offered method.

    Args:
        stderr: OpenSSH's standard error, as captured.

    Returns:
        The method names, lowercased. Empty when no refusal line is present.
    """
    methods: set[str] = set()
    for line in stderr.splitlines():
        start = line.find(_PERMISSION_DENIED)
        if start < 0:
            continue
        inside = line[start + len(_PERMISSION_DENIED) :]
        end = inside.find(")")
        if end < 0:
            continue
        methods.update(name.strip().lower() for name in inside[:end].split(","))
    return frozenset(methods - {""})


def _option_value(argv: Sequence[str], name: str) -> str | None:
    """The value of an ``-o`` option in an already-built argv, or ``None`` if absent.

    Read back off argv rather than taken from the caller's ``options`` mapping, so the
    diagnosis describes what was actually sent to ``ssh`` rather than what we meant to send.
    Both separations are handled -- ``-o Name=value`` and ``-oName=value`` -- because argv is
    not always ours.

    The **name** is matched case-insensitively for the same reason ``ssh`` does it that way:
    :func:`~gantry_sftp.transport.build_ssh_argv` preserves whatever spelling the caller used,
    so a connection built from ``{"BATCHMODE": "no"}`` carries ``-o BATCHMODE=no`` and an
    exact-match lookup would report the option as absent -- turning a hint that names the
    cause into no hint at all.
    """
    prefix = f"{name}=".lower()
    width = len(prefix)
    for index, argument in enumerate(argv):
        if argument == "-o" and index + 1 < len(argv):
            following = argv[index + 1]
            if following[:width].lower() == prefix:
                return following[width:]
        if argument[:2] == "-o" and argument[2 : 2 + width].lower() == prefix:
            return argument[2 + width :]
    return None


def password_auth_hint(stderr: str, *, argv: Sequence[str], askpass_armed: bool) -> str:
    """Explain a refusal that this client's own configuration made inevitable.

    **The text alone cannot answer this, and that is the whole reason the function takes
    three arguments.** Measured against asyncssh's server on 2026-07-28: a connection with
    ``BatchMode=yes`` and a perfectly good askpass helper, and a connection with
    ``BatchMode=no`` and no helper at all, both fail with the byte-identical line
    ``Permission denied (keyboard-interactive,password).`` A rule keyed on the message would
    have to pick one of the two causes and would be wrong half the time, so the client's own
    configuration is read as well.

    Args:
        stderr: OpenSSH's standard error, as captured.
        argv: The command that was actually spawned. Safe to inspect: no credential is ever
            in argv, which is why the askpass helper exists.
        askpass_armed: Whether this connection supplied a way to answer a prompt --
            ``password=``, or an ``SSH_ASKPASS`` the caller armed themselves.

    Returns:
        One sentence naming the cause and the fix, or ``""`` when our configuration is not
        what stood in the way. Silence is the honest answer for a password that was offered
        and refused, or for a server that never offered an interactive method at all.
    """
    if askpass_armed:
        # We did answer the prompt. The refusal is then about the secret or the account, and
        # neither is something this client knows anything about.
        return ""
    if not _offered_methods(stderr) & frozenset(INTERACTIVE_AUTH_METHODS):
        return ""

    if (_option_value(argv, "BatchMode") or "").strip().lower() == "yes":
        return (
            "the server offered password authentication and this client had it switched "
            "off: BatchMode=yes suppresses the askpass helper outright, so no password was "
            "ever sent. Pass password=... to open_ssh_transport()"
        )
    return (
        "the server offered password authentication and this client had no way to answer "
        "the prompt: no askpass helper was configured, and ssh cannot prompt when its "
        "input is a pipe. Pass password=... to open_ssh_transport()"
    )


def classify_failure(stderr: str) -> type[ConnectError]:
    """Choose the most specific ``ConnectError`` subclass justified by ``stderr``.

    Args:
        stderr: OpenSSH's standard error, as captured. May be empty, truncated in the middle
            by :class:`~gantry_sftp.transport.StderrBuffer`, or contain a server banner.

    Returns:
        :class:`~gantry_sftp.exceptions.HostKeyError` if the host's identity was rejected,
        :class:`~gantry_sftp.exceptions.AuthenticationError` if our credentials were, and
        :class:`~gantry_sftp.exceptions.ConnectError` when neither is established. Never
        guesses: the base class is the honest answer for everything else.
    """
    lines = [line.strip() for line in stderr.splitlines()]
    # Host keys first. See the module docstring: this ordering is the mitigation, not a style.
    if any(marker in line for line in lines for marker in HOST_KEY_MARKERS):
        return HostKeyError
    if any(marker in line for line in lines for marker in AUTH_MARKERS):
        return AuthenticationError
    return ConnectError

"""Handing a password to ``ssh`` without putting it anywhere a stranger can read.

``ssh`` never takes a password as an argument, and that is a feature rather than an omission.
The two workarounds people reach for when a library appears not to support passwords --
``sshpass -p secret`` and ``-o`` values -- both put the credential in **argv**, which on Linux
is world-readable through ``/proc/<pid>/cmdline``: every user on the box can read it out of
``ps`` for as long as the process lives. The whole point of this module is that the library
offers a path that is better than the one users would otherwise build for themselves.

The mechanism OpenSSH does support is ``SSH_ASKPASS``: the path of a program ``ssh`` execs when
it needs a secret, whose standard output is the answer. So the secret has to reach *that*
program somehow, and there are three places it could go:

* **argv** -- world-readable. Never.
* **the helper's own file contents** -- a credential written to disk, outliving the connection
  if cleanup is missed, and readable by anything that can read the file.
* **the environment** -- what this module does. On Linux ``/proc/<pid>/environ`` is readable
  only by the owning user, so the secret is exposed to *this* user's other processes and to
  root, and to nobody else. That is strictly better than argv and it is the same trade
  ``ssh-agent`` and OpenSSH's own tooling make.

So the helper written here is a three-line shell script containing **no secret at all** -- it
prints an environment variable. The file is disposable; what matters never touches the disk.

Two things this is deliberately not:

* **Not a shipped executable.** The helper is written to a fresh ``0700`` directory per
  connection and deleted with it. Shipping an executable module would mean a file with the
  exec bit in the distribution -- which is precisely what ``scripts/forbid_exec_bit.sh``
  exists to refuse -- and a fixed path on disk that every process owned by this user could
  find. A per-connection temporary file has neither property.
* **Not available on Windows.** The helper is a POSIX shell script, and Windows OpenSSH's
  prompting path has never been run here. Guessing at it would produce exactly the kind of
  untested claim this repository does not make, so it raises instead.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

__all__ = [
    "ASKPASS_ANSWER_VARIABLE",
    "ASKPASS_ARMING_VARIABLES",
    "askpass_environment",
]

ASKPASS_ANSWER_VARIABLE = "GANTRY_SFTP_ASKPASS_ANSWER"
"""Environment variable the helper reads the secret from.

Named distinctly rather than reusing something conventional so that a redaction key list has
one unambiguous name to mask, and so an inherited environment cannot collide with it.
"""

ASKPASS_ARMING_VARIABLES = ("SSH_ASKPASS_REQUIRE", "DISPLAY", "WAYLAND_DISPLAY")
"""The variables that make ``ssh`` *use* an askpass helper, any one of which is sufficient.

Setting ``SSH_ASKPASS`` alone does not arm the helper -- measured against OpenSSH 10.0p2 -- and
clearing it does not disarm one, because ``/usr/bin/ssh-askpass`` is compiled in as the default.
``WAYLAND_DISPLAY`` appears nowhere in ``ssh(1)``; it is in the binary. This module uses
``SSH_ASKPASS_REQUIRE=force`` because the other two require a display, and a display is not
something a headless transfer job has.
"""

_FORBIDDEN_IN_PASSWORD = ("\x00", "\n", "\r")

_HELPER_SOURCE = f"""#!/bin/sh
# Written by gantry-sftp for a single connection and deleted with it.
#
# The secret is read from this process's environment. It is not in argv, where every user on
# the machine could read it from `ps`, and it is not in this file.
printf '%s\\n' "${ASKPASS_ANSWER_VARIABLE}"
"""

_HELPER_NAME = "gantry-askpass.sh"


def _validate_password(password: str) -> None:
    """Reject a password that could answer more prompts than the one we are answering.

    The helper prints the secret followed by one newline. A password *containing* a newline
    would print two lines, and ``ssh`` reads a line per prompt -- so the tail would silently
    become the answer to whatever it asks next. That is worth a clear error rather than a
    connection that behaves strangely once in a while.

    Args:
        password: The secret to check.

    Raises:
        ValueError: If the password contains NUL, a newline, or a carriage return.
    """
    for bad in _FORBIDDEN_IN_PASSWORD:
        if bad in password:
            raise ValueError(
                f"password may not contain {bad!r}; the askpass helper answers one prompt "
                f"with one line, and an embedded newline would answer the next prompt too"
            )


@contextmanager
def askpass_environment(
    password: str, *, env: Mapping[str, str] | None = None
) -> Iterator[dict[str, str]]:
    """Yield a child environment that can answer ``ssh``'s password prompt.

    The helper is written to a private temporary directory for the life of the ``with`` block
    and removed on the way out, whether or not the connection succeeded.

    Args:
        password: The secret. It is placed in the returned environment under
            :data:`ASKPASS_ANSWER_VARIABLE` and nowhere else -- never in argv, never in a
            file, never in a log.
        env: Base environment for the child. ``None`` means inherit this process's, which is
            what ``open_ssh_transport`` does when no ``env`` is given -- and it has to be
            materialised here, because a child that gets an explicit environment does not
            inherit anything else.

    Yields:
        A new environment dictionary. The caller's mapping is copied, not mutated.

    Raises:
        ValueError: If the password contains a character that would let it answer more than
            the prompt it is for.
        NotImplementedError: On Windows. The helper is a POSIX shell script, and this has
            never been run against Windows OpenSSH.
    """
    _validate_password(password)
    if sys.platform.startswith("win"):
        raise NotImplementedError(
            "password= is not supported on Windows: the askpass helper is a POSIX shell "
            "script and Windows OpenSSH's prompting path has never been exercised here. "
            "Use key-based authentication, or supply your own SSH_ASKPASS via env="
        )

    # mkdtemp is 0700 already; the mode is restated on the file because the helper is the
    # thing `ssh` executes and "who may run this" should be visible at the point it is made.
    directory = Path(tempfile.mkdtemp(prefix="gantry-sftp-askpass-"))
    try:
        helper = directory / _HELPER_NAME
        helper.write_text(_HELPER_SOURCE)
        helper.chmod(stat.S_IRWXU)

        child_env = dict(os.environ if env is None else env)
        child_env["SSH_ASKPASS"] = str(helper)
        child_env["SSH_ASKPASS_REQUIRE"] = "force"
        child_env[ASKPASS_ANSWER_VARIABLE] = password
        yield child_env
    finally:
        # ignore_errors because failing to clean up a temporary file must not replace the
        # exception that explains why the connection failed.
        shutil.rmtree(directory, ignore_errors=True)

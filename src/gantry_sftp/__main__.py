"""``python -m gantry_sftp doctor`` — the command, and deliberately only this one.

The whole of the CLI lives here and it is thin on purpose: argument parsing, one call into
:mod:`gantry_sftp.doctor`, one write, one exit status. Everything worth testing is in that
module and is reachable as data, so nothing here has to be scraped to be asserted.

**One verb, and that is a decision rather than a starting point** (D-90). A ``__main__`` with a
single verb invites a second one, and a library that grows a command surface by accident ends up
maintaining an interface nobody designed — this project ships a *library* and one diagnostic. The
verb is required rather than defaulted so that adding a second one later could not change what
an existing invocation means.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from gantry_sftp.doctor import (
    Exit,
    local_diagnosis,
    overall_status,
    render_json,
    render_text,
    server_diagnosis,
)

__all__ = ["main"]

_DESCRIPTION = """\
Report what this machine can do and what a server negotiated.

With no host, everything answerable without a network -- which ssh would be spawned, its
version, whether this platform supports transfers, and the variables that steer it. This is
the mode to run in a Dockerfile: it needs no server and its exit status is the answer.

With a host, it connects once and reports the same negotiation a transfer performs: the
protocol version, the advertised extensions and which of them this library uses, the limits
and the request size derived from them, and where the session starts. It then runs a
read-only compatibility battery, which asks what the server *does* rather than what it
advertised, and prints the exchange behind every answer. That battery makes no writes and is
safe to point at production; --no-probes turns it off.

--probe-writes DIR adds the questions that can only be answered by writing -- whether names
fold case, whether RENAME replaces an existing target, whether an uploaded file's timestamps
survive. Every file it creates begins with `gantry-probe`, lives in DIR and is removed before
the command exits; anything it could not remove is named in the report. There is no default
directory and there will not be one.
"""

_EPILOG = """\
exit status: 0 usable | 2 usage | 3 no ssh binary | 4 platform cannot transfer |
5 host unreachable

a compatibility finding of "no" is an answer, not a fault, and does not change the status:
real endpoints differ from the reference in a dozen ways and work perfectly well.
"""


def build_parser() -> argparse.ArgumentParser:
    """The command line, built separately so a test can read it without running anything."""
    parser = argparse.ArgumentParser(
        prog="python -m gantry_sftp",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Constrained to one choice rather than accepted as free text: an unknown verb is then a
    # usage error argparse writes, listing what does exist, instead of a message this file
    # would have to keep in step with itself.
    _ = parser.add_argument("command", choices=("doctor",), help="the only command there is")
    _ = parser.add_argument("host", nargs="?", help="a server to diagnose as well; optional")
    _ = parser.add_argument("--user", help="log in as somebody other than the local account")
    _ = parser.add_argument("--port", type=int, help="a non-default port")
    _ = parser.add_argument("-i", "--identity-file", help="a private key to offer, as ssh -i")
    _ = parser.add_argument("--config-file", help="an ssh_config to use instead of your own")
    # Repeatable, and `ssh`'s own spelling, because the connection worth diagnosing is the one
    # that is failing -- which usually has options on it. A single `--option` would mean
    # reproducing a two-option failure is impossible.
    _ = parser.add_argument(
        "-o",
        dest="options",
        action="append",
        metavar="KEY=VALUE",
        help="an ssh -o option; repeat for more than one",
    )
    _ = parser.add_argument(
        "--json", action="store_true", help="emit the report as JSON rather than as text"
    )
    # Mutually exclusive rather than resolved by precedence: "skip the probes, and here is a
    # directory to write probes into" has no reading a user would be glad we guessed, and
    # argparse's own error names both flags without this file owning the sentence.
    battery = parser.add_mutually_exclusive_group()
    _ = battery.add_argument(
        "--no-probes",
        dest="probes",
        action="store_false",
        help="skip the read-only compatibility battery; report the negotiation only",
    )
    _ = battery.add_argument(
        "--probe-writes",
        metavar="DIR",
        help="also run the probes that create files, in DIR, removing them afterwards",
    )
    return parser


def parse_options(pairs: Sequence[str] | None) -> dict[str, str]:
    """Turn repeated ``-o KEY=VALUE`` into the mapping ``connect`` takes.

    Split on the *first* ``=`` only: an option's value may contain one, and
    ``ProxyCommand=ssh -W %h:%p bastion`` is exactly the kind of thing somebody diagnosing a
    connection needs to pass.

    Args:
        pairs: The raw arguments, or ``None`` when none were given.

    Returns:
        The options, in the order they were given.

    Raises:
        ValueError: If an argument has no ``=`` in it at all. Refused rather than ignored: a
            silently dropped option would make the diagnosis a report about a different
            connection from the one the operator asked about.
    """
    options: dict[str, str] = {}
    for pair in pairs or ():
        name, separator, value = pair.partition("=")
        if not separator:
            raise ValueError(f"-o wants KEY=VALUE, got {pair!r}")
        options[name] = value
    return options


def main(argv: Sequence[str] | None = None) -> int:
    """Run the diagnostic and return the process's exit status.

    Returns an ``int`` rather than calling :func:`sys.exit`, so a test runs the real entry
    point rather than a rearrangement of it and catches nothing to do so.

    Args:
        argv: Arguments after the program name. Defaults to the real ones.

    Returns:
        One of :class:`~gantry_sftp.doctor.Exit`.
    """
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        options = parse_options(arguments.options)
    except ValueError as malformed:
        parser.error(str(malformed))  # exits USAGE, which is argparse's 2
    if arguments.probe_writes is not None and arguments.host is None:
        # Refused rather than ignored, and the asymmetry with `--no-probes` is deliberate:
        # skipping a battery that was never going to run is harmless, but a flag that promises
        # to create files somewhere and silently creates none has told the operator something
        # untrue about what just happened.
        parser.error("--probe-writes needs a host to probe")
    local = local_diagnosis()
    server = None
    # Not attempted when ssh is unusable: a connection failure would be the *symptom*, and
    # reporting both makes the reader choose which one to believe. The local finding is the
    # one with a remedy attached.
    if arguments.host is not None and local.exit_code is not Exit.NO_SSH:
        server = server_diagnosis(
            arguments.host,
            user=arguments.user,
            port=arguments.port,
            identity_file=arguments.identity_file,
            config_file=arguments.config_file,
            options=options or None,
            probes=arguments.probes,
            write_directory=arguments.probe_writes,
        )
    render = render_json if arguments.json else render_text
    print(render(local, server))  # noqa: T201  # printing the report is what this program is
    return int(overall_status(local, server))


if __name__ == "__main__":
    sys.exit(main())

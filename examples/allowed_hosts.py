"""Restricting where a connection may go, when the hostname comes from somebody else.

    python examples/allowed_hosts.py

Runs entirely offline: every connection here is refused before an `ssh` is spawned, or fails
to resolve a name that does not exist. Nothing needs a server.

The problem is ordinary. An application takes a hostname from a job config, an API request or a
`gantry-sftp://` URL, and hands it to `connect()`. The application chose to connect; the user
chose where. That is server-side request forgery, and this library did not restrict it before
0.11 -- `build_ssh_argv` refuses a host that could be reparsed as an `ssh` flag, which is
argument injection and a different problem entirely.

Four things this example exists to make visible.

**The policy is ambient, not an argument.** It is set for a block or for a process, because a
deployment knows its policy and a call site does not -- and because `pd.read_parquet(url)` has
no per-call surface at all, so a parameter on `connect()` would never reach the place untrusted
hosts actually arrive.

**Layers narrow and never widen.** The environment variable is one layer, each scope is
another, and a host must satisfy all of them. The third section shows an inner scope naming a
host explicitly and still being refused, which is what stops any library in the process from
switching the policy off.

**It matches the effective host.** An `ssh_config` rewrites the destination after the name you
passed, so an allowlist that checked your string would approve a connection to somewhere else.
The fourth section builds exactly that config and watches the refusal name both halves.

**Off by default, and free when off.** No policy means no probe: nothing is spawned and nothing
is checked.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import anyio

from gantry_sftp import DestinationNotAllowedError, allowed_hosts, connect
from gantry_sftp.transport import ALLOWED_HOSTS_ENV, active_layers


async def refuse(host: str, **kwargs: object) -> str:
    """Attempt a connection and report how the policy answered."""
    try:
        async with connect(host, **kwargs):  # type: ignore[arg-type]
            return "connected"
    except DestinationNotAllowedError as refused:
        rewritten = (
            ""
            if refused.effective_host in {None, refused.host}
            else f" -> {refused.effective_host}"
        )
        return f"REFUSED  {refused.host}{rewritten}"
    except Exception as failure:
        return f"allowed by the policy, then {type(failure).__name__}"


async def show_the_default() -> None:
    print("with no policy set, nothing is restricted and no probe is run:")
    print(f"    active layers          {active_layers()}")


async def show_a_scope() -> None:
    print("\na scope, for a block of code:")
    with allowed_hosts(["*.corp.example.com"]):
        print(f"    active layers          {active_layers()}")
        for host in ("sftp.corp.example.com", "evil.net"):
            print(f"    {host:24} {await refuse(host, config_file=os.devnull)}")


async def show_that_layers_only_narrow() -> None:
    print("\nlayers narrow and never widen -- an inner scope cannot re-admit a host:")
    with allowed_hosts(["*.corp.example.com"]), allowed_hosts(["evil.net"]):
        print(f"    active layers          {active_layers()}")
        print(f"    {'evil.net':24} {await refuse('evil.net', config_file=os.devnull)}")
    print("    -- named explicitly by the inner layer, and the outer one still refuses it")


async def show_the_config_rewrite(scratch: Path) -> None:
    print("\nthe effective host is what is checked, because an ssh_config rewrites it:")
    config = scratch / "rewrite.conf"
    _ = config.write_text("Host allowed.example.com\n  Hostname 169.254.169.254\n")
    print(f"    {config.name}:            Host allowed.example.com / Hostname 169.254.169.254")
    with allowed_hosts(["allowed.example.com"]):
        answer = await refuse("allowed.example.com", config_file=str(config))
        print(f"    {'allowed.example.com':24} {answer}")
    print("    -- the name is allowlisted; the destination is the cloud metadata endpoint")


async def show_the_environment_variable() -> None:
    print("\nfor a whole process, which is the only spelling a URL-driven caller can use:")
    print(f"    export {ALLOWED_HOSTS_ENV}='*.corp.example.com'")
    os.environ[ALLOWED_HOSTS_ENV] = "*.corp.example.com"
    try:
        print(f"    active layers          {active_layers()}")
        print(f"    {'evil.net':24} {await refuse('evil.net', config_file=os.devnull)}")
    finally:
        del os.environ[ALLOWED_HOSTS_ENV]
    print("    -- and it reaches pd.read_parquet('gantry-sftp://...') with no API of its own")


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="gantry-example-") as scratch:
        await show_the_default()
        await show_a_scope()
        await show_that_layers_only_narrow()
        await show_the_config_rewrite(Path(scratch))
        await show_the_environment_variable()

    print(
        "\nThree things it does not do, because a control that overstates itself is worse than\n"
        "an absent one: it does not defeat DNS rebinding (this library resolves no names --\n"
        "ssh does, in the subprocess -- so there is no address to pin); it assumes the\n"
        "ssh_config is trusted, since 'ssh -G' evaluates Match exec, and the control for an\n"
        "untrusted config is config_file=os.devnull; and it is not egress control."
    )


if __name__ == "__main__":
    anyio.run(main)

"""One call that opens a connection and hands back a ready session.

The two-call spelling -- :func:`~gantry_sftp.transport.open_ssh_transport` then
:func:`~gantry_sftp.session.open_session` -- is what this library has always shipped, and it
stays: the transport's lifetime is genuinely separable from the session's, which is what makes
``with_reconnect`` possible at all. What it is not is the first thing a reader should meet, and
DESIGN 8 had documented a ``connect()`` since draft 0.1 that did not exist.

**The signature is scoped rather than a union, and the reason is the project's own arity
ceiling.** ``open_ssh_transport`` already takes ten arguments and ``pyproject.toml`` sets
``max-args = 10`` as a policy it explicitly refuses to exempt, while also refusing parameter
objects *for the connection entry points* on the grounds that ``host`` and ``identity_file``
really are unrelated. Fusing both signatures verbatim would be thirteen. So the ssh arguments
stay flat, where that objection applies, and the three session tunables -- which are one
concept, a scheduling policy, the same argument that made ``Publish`` a type -- become a single
:class:`~gantry_sftp.session.SessionOptions`. Ten exactly.

**What the recon found, recorded because the card said otherwise.** D-57 counted "four places in
this repo already fuse them with a private ``connect()`` helper". Eight of the ten helpers that
now exist are a *local-`sftp-server`-versus-`ssh`* switch driven by ``sys.argv``, so they choose
a transport rather than fusing two calls, and half of them yield a transport rather than a
session. Exactly one site was a real fusion. The case for this function is therefore the
documentation being false and the entry point D-60 and D-61 will need to name -- not repetition.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager

from gantry_sftp.session import DEFAULT_SESSION_OPTIONS, Session, SessionOptions, open_session
from gantry_sftp.transport import open_ssh_transport

__all__ = ["connect"]


@asynccontextmanager
async def connect(
    host: str,
    *,
    user: str | None = None,
    port: int | None = None,
    identity_file: str | os.PathLike[str] | None = None,
    password: str | None = None,
    config_file: str | os.PathLike[str] | None = None,
    options: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    ssh_executable: str | None = None,
    session: SessionOptions = DEFAULT_SESSION_OPTIONS,
) -> AsyncGenerator[Session]:
    """Open an ``ssh`` connection and a session over it, and yield the session.

    ::

        async with connect("example.com", user="bob") as sftp:
            await sftp.get("/incoming/data.parquet", "data.parquet")

    Equivalent to the two-call spelling, which still works and is what to reach for when the
    transport's lifetime differs from the session's::

        async with (
            open_ssh_transport("example.com", user="bob") as transport,
            open_session(transport) as sftp,
        ):
            ...

    **This is not a reconnect recipe, and the distinction is load-bearing.**
    :func:`~gantry_sftp.session.with_reconnect` takes a callable that produces a *transport*,
    because a retry builds a new session over a new connection and the session is what it
    rebuilds. Passing this function to it would nest a session inside a session. The spelling
    stays what it has been since 0.7::

        recipe = functools.partial(open_ssh_transport, "example.com", user="bob")
        await with_reconnect(recipe, lambda sftp: sftp.get("/big.iso", "big.iso"))

    Args:
        host: Hostname or ``user@host``-free hostname. A leading ``-`` is refused rather than
            handed to ``ssh`` as a flag -- see
            :func:`~gantry_sftp.transport.open_ssh_transport`, which validates it.
        user: Remote username. ``None`` lets ``ssh`` decide, from its config or the local user.
        port: Remote port. ``None`` lets ``ssh`` decide.
        identity_file: Private key to offer.
        password: Password to answer an interactive prompt with, via an ``SSH_ASKPASS`` helper
            written to a ``0700`` temporary directory. Never reaches argv or a log line.
        config_file: ``ssh_config`` to use. ``os.devnull`` means *no* config, including the
            system one -- and note that a config file's ``ProxyCommand`` and ``Match exec``
            both execute, which the shipped defaults do not prevent.
        options: Extra ``-o`` settings. Option names are matched case-insensitively and the
            first one wins, so these replace a shipped default rather than landing beside it.
        env: Environment for the ``ssh`` child, replacing the scrubbed default.
        ssh_executable: Which ``ssh`` to run.
        session: Session tunables -- :class:`~gantry_sftp.session.SessionOptions`, holding
            ``request_timeout``, ``idle_timeout`` and ``depth``. One type rather than three
            arguments because they are one policy and because the ssh arguments above already
            spend the project's whole argument budget.

    Yields:
        A ready :class:`~gantry_sftp.session.Session`. Both the session and the connection
        close when the block exits.

    Raises:
        AuthenticationError: If the server rejected every credential offered.
        HostKeyError: If the host key is unknown or has changed.
        ConnectError: For any other failure to connect, carrying OpenSSH's stderr verbatim.
        ProtocolError: If the server negotiates a filexfer version other than 3 -- see
            :func:`~gantry_sftp.session.open_session`, which is where the handshake happens.
    """
    async with (
        open_ssh_transport(
            host,
            user=user,
            port=port,
            identity_file=identity_file,
            password=password,
            config_file=config_file,
            options=options,
            env=env,
            ssh_executable=ssh_executable,
        ) as transport,
        open_session(
            transport,
            request_timeout=session.request_timeout,
            idle_timeout=session.idle_timeout,
            depth=session.depth,
        ) as sftp,
    ):
        yield sftp

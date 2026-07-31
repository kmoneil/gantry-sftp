"""The same contract, asked of the matrix's three servers.

`tests/test_contract.py` asks `server_contract.CONTRACT` of a fake and of `sftp-server` on a
pipe. This asks the identical list of the three implementations in :mod:`matrix`, over a real
`ssh` connection -- so a guarantee is checked against a fake, against the reference, and against
two independent implementations of the same protocol.

**Here rather than in `tests/` because these bind a socket**, which the fast lane is not allowed
to do. Everything skips with a reason when a server cannot be started; `bench` is deliberately
not installed by default, since asyncssh and paramiko drag in the Python cryptography this
project exists not to need.

**Reading a paramiko failure.** Paramiko ships the protocol half and leaves the filesystem to
the caller, so the handler under it is `matrix._ParamikoHandler`, which is ours. A contract row
failing there is a finding about *either* paramiko's framing and error mapping *or* our thirty
lines of `os.stat` -- check which before reporting it, exactly as `matrix.HANDLER_IS_OURS`
requires of every other claim drawn from that server.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import ExitStack, asynccontextmanager
from pathlib import Path
from typing import ClassVar

import pytest
from matrix import SERVER_NAMES, running_server, unavailable_reason
from test_matrix import connected

from gantry_sftp.session import Session
from server_contract import CONTRACT, CONTRACT_TREE, Capability, Guarantee, Tree

pytestmark = pytest.mark.anyio


class MatrixBackend:
    """One matrix implementation, serving a real directory over a real `ssh` connection.

    `connected` comes from `test_matrix` rather than being spelled again here, for the reason
    `conftest.py` gives about itself: two copies of "how this suite connects" is how a setting
    ends up applied in one of them and not the other.
    """

    CAPABILITIES: ClassVar[frozenset[Capability]] = frozenset(Capability)

    def __init__(self, name: str, tmp_path: Path) -> None:
        self.name = name
        self.tmp_path = tmp_path

    def unavailable(self) -> str | None:
        return unavailable_reason(self.name)

    @asynccontextmanager
    async def session(self, tree: Tree) -> AsyncGenerator[tuple[Session, bytes]]:
        # The contract's tree goes in a subdirectory of the server's own root, never in it:
        # `running_server` uses that directory as the harness's scratch space and `sshd` drops
        # its host key, config and log there. A listing of the root is a listing of those.
        served = self.tmp_path / "tree"
        served.mkdir()
        for name in tree.directories:
            (served / os.fsdecode(name)).mkdir()
        for name, content in tree.files.items():
            (served / os.fsdecode(name)).write_bytes(content)
        with ExitStack() as stack:
            server = stack.enter_context(running_server(self.name, self.tmp_path))
            async with connected(server) as sftp:
                yield sftp, os.fsencode(str(served))


@pytest.mark.parametrize("server_name", SERVER_NAMES)
@pytest.mark.parametrize("guarantee", CONTRACT, ids=lambda item: item.name)
async def test_the_contract_against_a_real_server(
    guarantee: Guarantee, server_name: str, tmp_path: Path
) -> None:
    """One guarantee, one implementation. Three servers already disagree; this says where."""
    backend = MatrixBackend(server_name, tmp_path)
    if (reason := backend.unavailable()) is not None:
        pytest.skip(reason)

    async with backend.session(CONTRACT_TREE) as (sftp, root):
        await guarantee.run(sftp, root)

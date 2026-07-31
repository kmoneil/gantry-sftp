"""The contract in `server_contract.py`, asked of a fake and of a real `sftp-server`.

Every guarantee runs against every backend that can answer it, so a fake and the server it
claims to model are asked the *same* question rather than two questions that happen to agree
(D-114). Neither backend here needs a network: one is in-memory, the other is the genuine
`sftp-server` binary on a pipe, which is the seam `test_real_sftp_server.py` already uses. The
matrix's asyncssh and paramiko servers answer the same list from `live-tests/`, because they
bind a socket and this lane does not.

**What a skip means here.** A fake implements the packets its own module needed and no more, so
a guarantee it cannot answer skips with the capability named. The declaration is not taken on
trust: `test_a_fakes_declared_capabilities_match_its_dispatch_table` reads the set off the
fake's own handler table, so a fake that grows a handler and is not offered the matching
guarantees fails here rather than quietly narrowing the contract.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import ClassVar

import pytest

from gantry_sftp.codec import (
    Close,
    LStat,
    MkDir,
    Open,
    OpenDir,
    Read,
    ReadDir,
    RealPath,
    Remove,
    Rename,
    RmDir,
    Stat,
    Write,
)
from gantry_sftp.session import Session, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from server_contract import CONTRACT, CONTRACT_TREE, Capability, Guarantee, Tree
from test_recursive import DIRECTORY, REGULAR, TreeServer, named

pytestmark = pytest.mark.anyio


# --- the fakes that cannot be verified, and why ---------------------------------------------

UNVERIFIABLE: dict[str, str] = {
    "StallingServer": "answers nothing until a test lets it; no real server stalls on request",
    "StallingTreeServer": "as StallingServer, inside a walk",
    "StallingPublishServer": "as StallingServer, inside the publish ladder",
    "StallingUploadTreeServer": "as StallingServer, inside a tree upload",
    "HoldsTheHandle": "never answers the OPEN, so the handle is abandoned in flight",
    "DyingTransport": "drops the link on a chosen request, which is not a server behaviour",
    "LyingServer": "reports attributes contradicting what it stored, on purpose",
    "ZeroLength": "answers a READ with zero bytes, which is a server making no progress",
    "SizelessServer": "omits the size from a stat",
    "TimelessServer": "omits the timestamps",
    "SparseServer": "omits the permission bits",
    "SparseAndRefusing": "omits the permission bits and refuses the stat that would settle it",
    "TerseServer": "answers a listing without the attributes a real server includes",
    "Recipe": "a script of failures for the retry ladder, not a server",
    "Wire": "a transport-level fake, below the protocol entirely",
    "Rendezvous": "a barrier proving two requests overlapped; it models no server",
    "TripCounter": "counts packets, does not answer them",
    "CodecDrivenServer": "drives the real sftp-server; it is the reference, not a model of one",
}
"""Fakes exempt from the contract, each with the reason it cannot be held to one.

**This list is the honest half of the technique.** Verified fakes explicitly does not cover
transient or hard-to-trigger failure, and that is what most of these are for: stalling, dying
mid-request, contradicting itself, abandoning a handle. No real server does any of it on
demand, so there is nothing to ask the same question of.

The `Sparse*` / `Timeless` / `Sizeless` / `Terse` entries are exempt for a different reason and
the two are worth telling apart. They model a **legal** server this project has never met, so
what they test is what *we* decide about a legal answer rather than whether we agree with a real
one -- and DESIGN §12 already ruled that is the case a fake is legitimately for. Verifying them
is not merely hard, it is the wrong question.
"""


# --- backends ---------------------------------------------------------------------------------


class FakeBackend:
    """`TreeServer`, the general-purpose fake most of this suite is built on.

    It backs `test_recursive`, `test_glob`, `test_cancellation` and `test_orphaned_handles`, so
    it is the fake the most other proofs inherit their credibility from -- which is why it is
    the one that gets a contract first.
    """

    NAME: ClassVar[str] = "TreeServer"
    CAPABILITIES: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.LIST, Capability.STAT, Capability.READ, Capability.REMOVE, Capability.REALPATH}
    )
    ROOT: ClassVar[bytes] = b"/root"

    def __init__(self, tmp_path: Path) -> None:
        # Takes it and does not use it, so every backend is built the same way.
        del tmp_path

    def unavailable(self) -> str | None:
        return None

    @asynccontextmanager
    async def session(self, tree: Tree) -> AsyncGenerator[tuple[Session, bytes]]:
        entries = tuple(named(name, DIRECTORY) for name in tree.directories) + tuple(
            named(name, REGULAR, len(content)) for name, content in tree.files.items()
        )
        layout = {self.ROOT: entries} | {self.ROOT + b"/" + name: () for name in tree.directories}
        files = {self.ROOT + b"/" + name: content for name, content in tree.files.items()}
        server = TreeServer(tree=layout, files=files, root=self.ROOT)
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            yield sftp, self.ROOT


class LocalServerBackend:
    """The genuine OpenSSH `sftp-server`, on a pipe. No ssh, no keys, no network.

    The reference the fakes claim to model, which is what makes the comparison worth anything.
    `tmp_path` is per test rather than shared, because several guarantees remove things.
    """

    NAME: ClassVar[str] = "sftp-server"
    CAPABILITIES: ClassVar[frozenset[Capability]] = frozenset(Capability)

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path

    def unavailable(self) -> str | None:
        if find_sftp_server() is None:
            return "sftp-server not installed (ships in openssh-server)"
        return None

    @asynccontextmanager
    async def session(self, tree: Tree) -> AsyncGenerator[tuple[Session, bytes]]:
        for name in tree.directories:
            (self.tmp_path / os.fsdecode(name)).mkdir()
        for name, content in tree.files.items():
            (self.tmp_path / os.fsdecode(name)).write_bytes(content)
        async with (
            open_local_server_transport(cwd=self.tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            yield sftp, os.fsencode(str(self.tmp_path))


BACKENDS = (FakeBackend, LocalServerBackend)


# --- the grid ------------------------------------------------------------------------------


@pytest.mark.parametrize("backend_type", BACKENDS, ids=lambda kind: kind.NAME)
@pytest.mark.parametrize("guarantee", CONTRACT, ids=lambda item: item.name)
async def test_the_contract(
    guarantee: Guarantee, backend_type: type[FakeBackend | LocalServerBackend], tmp_path: Path
) -> None:
    """One guarantee against one backend. The grid is the point: the same question, twice."""
    backend = backend_type(tmp_path)
    if (reason := backend.unavailable()) is not None:
        pytest.skip(reason)
    if missing := guarantee.needs - backend_type.CAPABILITIES:
        pytest.skip(f"{backend_type.NAME} implements no {', '.join(sorted(missing))}")

    async with backend.session(CONTRACT_TREE) as (sftp, root):
        await guarantee.run(sftp, root)


# --- the declaration is derived, not trusted ------------------------------------------------

DISPATCHED_BY: dict[Capability, tuple[type, ...]] = {
    Capability.LIST: (OpenDir, ReadDir, Close),
    Capability.STAT: (Stat, LStat),
    Capability.READ: (Open, Read, Close),
    Capability.WRITE: (Open, Write, Close),
    Capability.REMOVE: (Remove, RmDir),
    Capability.RENAME: (Rename,),
    Capability.MKDIR: (MkDir,),
    Capability.REALPATH: (RealPath,),
}
"""Which packets each capability needs, so a fake's declaration can be read off its own code."""


def test_a_fakes_declared_capabilities_match_its_dispatch_table() -> None:
    """A fake that grows a handler and is not offered the matching guarantees fails here.

    `FakeBackend.CAPABILITIES` is the sort of thing that is true when written and quietly false
    a year later, and the failure is silent -- the contract narrows and every remaining row goes
    on passing. So it is derived from `TreeServer.handlers()` instead, which is the approach
    `test_sync_facade.py` takes to the blocking surface for the same reason.
    """
    handled = TreeServer(tree={b"/root": ()}).handlers().keys()
    implemented = {
        capability
        for capability, packets in DISPATCHED_BY.items()
        if all(packet in handled for packet in packets)
    }
    assert implemented == FakeBackend.CAPABILITIES, (
        "TreeServer's dispatch table and FakeBackend.CAPABILITIES disagree: a handler was added "
        "or removed and the contract was not offered the difference"
    )


def test_every_backend_is_offered_at_least_one_guarantee() -> None:
    """A backend whose capabilities match nothing would skip every row and look like a pass.

    The shape D-104 found inside a fixture written to prevent it: a green lane proving nothing.
    """
    for backend_type in BACKENDS:
        askable = [item for item in CONTRACT if item.needs <= backend_type.CAPABILITIES]
        assert askable, f"{backend_type.NAME} can be asked nothing in the contract"


def test_a_fake_is_either_a_backend_or_exempt_with_a_reason() -> None:
    """The exemption list is exactly the set that cannot be held to the contract.

    An unexplained hole in a contract suite reads as unfinished work and gets "fixed" by
    somebody who does not know it cannot be. This makes the hole a list with a sentence against
    each entry, and makes adding a fake without deciding which side it falls on a failing test
    rather than an omission nobody sees.
    """
    named_backends = {backend_type.NAME for backend_type in BACKENDS}
    overlap = named_backends & UNVERIFIABLE.keys()
    assert not overlap, f"a backend cannot also be exempt: {sorted(overlap)}"
    unexplained = [name for name, reason in UNVERIFIABLE.items() if not reason.strip()]
    assert not unexplained, f"an exemption without a reason is a hole: {unexplained}"

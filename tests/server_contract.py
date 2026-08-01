"""What this library needs a server to do, written once and asked of every server.

**Why this file exists.** The Definition of Done says a fake only confirms what its author
already believed, and answers it with ``live-tests/``: anything crossing a real boundary needs a
proof against a real server. That is a good rule and it does not do what the sentence claims.
``live-tests/`` proves the *client* against real servers. It cannot prove the *fakes*, because
it runs different tests over different code paths -- the fake and the real server are never
asked the same question. This is where they are (D-114).

``live-tests/test_matrix.py`` is the evidence that the gap is real rather than tidy: three real
servers already disagree with each other on extensions, on error text and on path semantics. So
"our idea of an SFTP server" is known to be an idea of at most one of them, and nothing anywhere
says which.

**What belongs here.** A guarantee earns a place if it is something the library *relies on* and
something a fake could plausibly get wrong. Most of the list below is a fact this project
learned from a real server after writing code against a different belief -- ``SYMLINK``'s
argument order, ``NO_SUCH_FILE`` for a closed handle, ``BAD_MESSAGE`` for a name that is merely
too long. Each of those passed every unit test at the time, because the fake agreed with the
encoder that produced it.

**What does not belong here.** Anything a real server will not produce on demand. Most of the
fakes in this suite exist precisely to stall, to die mid-transfer, to lose a rename race or to
lie about attributes, and by construction no real server can be asked to do that on cue --
"verified fakes" is explicit that the technique does not cover them. They are exempt, they are
listed in ``test_contract.py`` with the reason, and a test there asserts the exemption list is
exactly that set. An unexplained hole in a contract suite reads as unfinished work and gets
"fixed" by somebody who does not know it cannot be.

**Layering.** This module imports nothing from either lane. The guarantees are expressed against
the public ``Session`` API, so the same list runs in ``tests/`` against a fake and the real
``sftp-server`` on a pipe, and in ``live-tests/`` against the matrix's three servers. Backends
live with the lane that can build them; only the contract is shared.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Protocol

import pytest

from gantry_sftp.codec import OpenFlag
from gantry_sftp.exceptions import NoSuchFileError, ServerError, SFTPError
from gantry_sftp.session import DOT_ENTRIES, EntryKind, entry_kind

__all__ = [
    "CONTRACT",
    "Backend",
    "Capability",
    "Guarantee",
    "Tree",
]


class Capability(StrEnum):
    """What a backend has to implement for a guarantee to be askable of it.

    Not a statement about SFTP -- every real server does all of this. It exists because a fake
    implements the packets its own module needed and no more, and a guarantee it cannot answer
    must **skip with a reason** rather than fail. A fake growing a handler and nobody extending
    its declared set is caught by ``test_contract.py``, which reads the set off the dispatch
    table rather than trusting the declaration.
    """

    LIST = "list"
    STAT = "stat"
    READ = "read"
    WRITE = "write"
    REMOVE = "remove"
    RENAME = "rename"
    MKDIR = "mkdir"
    REALPATH = "realpath"


@dataclass(frozen=True, slots=True)
class Tree:
    """A layout every backend must be able to produce before a guarantee runs.

    Declarative because the two kinds of backend build it in incompatible ways -- a fake takes a
    dict of listing entries, a real server needs the directories and files to exist on a disk.
    Keys are relative to the backend's root and use ``/`` regardless of the host, because they
    are remote paths rather than local ones.
    """

    directories: tuple[bytes, ...] = ()
    files: Mapping[bytes, bytes] = field(default_factory=dict)


class Backend(Protocol):
    """One server the contract can be asked of.

    Constructed with a ``tmp_path`` whether or not it needs one, so a lane can build every
    backend the same way.

    Attributes:
        NAME: What the parametrised test is identified by. Short: it is read in failures.
        CAPABILITIES: What this backend implements. A guarantee needing more of them skips.
    """

    NAME: ClassVar[str]
    CAPABILITIES: ClassVar[frozenset[Capability]]

    def __init__(self, tmp_path: Any) -> None: ...

    def unavailable(self) -> str | None:
        """Why this backend cannot run here, or ``None``. A missing binary skips, never fails."""
        ...

    def session(self, tree: Tree) -> AbstractAsyncContextManager[tuple[Any, bytes]]:
        """Build ``tree``, connect, and yield the session and the remote root it was built at.

        The root is returned rather than fixed, because a fake's namespace is whatever its
        author chose and a real server's is a temporary directory.
        """
        ...


@dataclass(frozen=True, slots=True)
class Guarantee:
    """One thing every server must do, and what a backend needs to be asked it."""

    name: str
    needs: frozenset[Capability]
    run: Callable[[Any, bytes], Awaitable[None]]

    @property
    def why(self) -> str:
        """The docstring, which is where the reason this is in the contract is written."""
        return (self.run.__doc__ or "").strip()


CONTRACT: list[Guarantee] = []


def guarantee(
    *needs: Capability,
) -> Callable[[Callable[[Any, bytes], Awaitable[None]]], Callable[[Any, bytes], Awaitable[None]]]:
    """Register a contract guarantee and declare what a backend needs to answer it."""

    def register(
        run: Callable[[Any, bytes], Awaitable[None]],
    ) -> Callable[[Any, bytes], Awaitable[None]]:
        CONTRACT.append(Guarantee(name=run.__name__, needs=frozenset(needs), run=run))
        return run

    return register


# --- handshake -----------------------------------------------------------------------------


@guarantee()
async def the_handshake_settles_on_filexfer_v3(sftp, root: bytes) -> None:
    """Every server here answers INIT with 3, which is what makes refusing anything else safe.

    Since 0.12 the codec **refuses** a negotiated version that is not 3 -- v4 ATTRS puts a
    `byte type` ahead of every optional field, so a v3 decoder cannot read one, and a v2 server
    has no READLINK, SYMLINK or EXTENDED to answer with. That refusal is only correct if real
    servers do in fact settle on 3, and a fake asserting it against itself proves nothing: the
    fake is where the number is chosen. asyncssh implements up to v6 and paramiko v3, so this
    is a genuine question of the matrix rather than a formality.

    Needs no capability: the answer is established before the session exists.
    """
    del root
    assert sftp.server_version == 3


# --- listing -------------------------------------------------------------------------------


@guarantee(Capability.LIST)
async def a_listing_names_the_children_and_never_the_dot_entries(sftp, root: bytes) -> None:
    """`.` and `..` are filtered, and the two kinds of backend disagree about sending them.

    The single strongest reason to run one list against both: a real server puts `.` and `..` in
    every `READDIR` and our fakes never have, so the filter is exercised on one side of this
    suite and assumed on the other. A caller who sees `..` in a listing and joins it has left
    the directory.
    """
    entries = await sftp.listdir(root)
    names = [entry.filename for entry in entries]
    assert sorted(names) == [b"a.txt", b"sub"], names
    assert not [name for name in names if name in DOT_ENTRIES]


@guarantee(Capability.LIST)
async def listing_a_plain_file_is_no_such_file_rather_than_some_other_refusal(
    sftp, root: bytes
) -> None:
    """`OPENDIR` on a file answers `NO_SUCH_FILE`, because `ENOTDIR` is remapped into it.

    `_glob_listing` depends on this **by name**: it swallows exactly `NoSuchFileError` so that a
    pattern component naming a file matches nothing instead of raising, and raises everything
    else so a refusal never becomes an empty result. If a server answered `FAILURE` here, a glob
    over a directory containing a file would raise.
    """
    with pytest.raises(NoSuchFileError):
        await sftp.listdir(root + b"/a.txt")


@guarantee(Capability.LIST)
async def listing_a_directory_that_is_not_there_is_no_such_file(sftp, root: bytes) -> None:
    """The ordinary absence, distinguished from the refusals around it."""
    with pytest.raises(NoSuchFileError):
        await sftp.listdir(root + b"/absent")


# --- attributes ----------------------------------------------------------------------------


@guarantee(Capability.STAT)
async def a_stat_tells_a_directory_from_a_file(sftp, root: bytes) -> None:
    """v3 carries the file type in the permission bits, and everything classifying reads them.

    A fake that returns attributes without a mode makes every entry `UNKNOWN`, which the
    predicates refuse to guess from and `glob` refuses to descend past -- so a fake that got
    this wrong would look like a server the library cannot use.
    """
    assert entry_kind(await sftp.stat(root + b"/sub")) is EntryKind.DIRECTORY
    assert entry_kind(await sftp.stat(root + b"/a.txt")) is EntryKind.FILE


@guarantee(Capability.STAT)
async def a_stat_of_something_absent_is_no_such_file_and_not_a_bare_failure(
    sftp, root: bytes
) -> None:
    """The whole three-state rule rests on this being the *specific* code and not the catch-all.

    Every predicate answers `False` for `NO_SUCH_FILE` and raises for anything else. A server
    answering the v3 `FAILURE` catch-all for a missing path would turn `exists()` into a raise.
    """
    with pytest.raises(NoSuchFileError):
        await sftp.stat(root + b"/absent")


@guarantee(Capability.STAT)
async def the_size_a_stat_reports_is_the_length_of_the_file(sftp, root: bytes) -> None:
    """Verification rung 3 is a size comparison, so a wrong size is a wrong verdict."""
    assert await sftp.getsize(root + b"/a.txt") == len(CONTRACT_TREE.files[b"a.txt"])


# --- reading -------------------------------------------------------------------------------


@guarantee(Capability.READ)
async def a_whole_file_reads_back_as_what_it_holds(sftp, root: bytes) -> None:
    """The base case, and the one a fake is most likely to get right."""
    handle = await sftp.open(root + b"/a.txt", OpenFlag.READ)
    try:
        assert await sftp.read_at(handle, 0, 64) == CONTRACT_TREE.files[b"a.txt"]
    finally:
        await sftp.close(handle)


@guarantee(Capability.READ)
async def a_read_that_asks_past_the_end_gets_what_is_there_and_no_error(sftp, root: bytes) -> None:
    """A short `DATA` is legal and is **not** `EOF`, which is the classic bug in this protocol.

    Conflating them truncates every pipelined transfer at the first partial response, silently.
    A fake that answered the full requested length regardless would hide a reassembler that
    cannot handle a short read -- and the reassembler is the part that must.
    """
    content = CONTRACT_TREE.files[b"a.txt"]
    handle = await sftp.open(root + b"/a.txt", OpenFlag.READ)
    try:
        assert await sftp.read_at(handle, 1, len(content) * 4) == content[1:]
        assert await sftp.read_at(handle, len(content), 8) == b""
    finally:
        await sftp.close(handle)


@guarantee(Capability.READ)
async def a_directory_cannot_be_read_as_a_file(sftp, root: bytes) -> None:
    """Refused -- but **where** it is refused is not agreed, so nothing may depend on that.

    Measured 2026-07-31 across the matrix, and the three do three different things:

    * **OpenSSH** allows the `OPEN`. `sftp-server` calls `open(2)`, Linux permits `O_RDONLY` on a
      directory, so a handle comes back and `read(2)` is what fails -- `FAILURE`, message
      `Failure`.
    * **asyncssh** refuses the `OPEN`: `FAILURE`, message `Is a directory`.
    * **paramiko** refuses the `OPEN` too: `FAILURE`, message `Failure`.

    This guarantee was first written as OpenSSH's version, and the matrix is what caught that:
    a contract written against the reference alone is the reference's behaviour with a
    contract's authority. What the library may rely on is only that the pair refuses **somewhere**
    -- which also means an error message for "you asked to download a directory" cannot be
    produced by matching on the request that failed.
    """
    with pytest.raises(SFTPError):
        await _read_as_a_file(sftp, root + b"/sub")


async def _read_as_a_file(sftp, path: bytes) -> None:
    """`OPEN` then `READ`, closing whatever came back.

    One helper rather than both calls inside the `pytest.raises`, because *which* of them
    refuses is the thing the three servers disagree about -- so a block asserting "one of these
    two raised" is exactly what is meant here, and spelling it as one call says so.
    """
    handle = await sftp.open(path, OpenFlag.READ)
    try:
        await sftp.read_at(handle, 0, 16)
    finally:
        await sftp.close(handle)


@guarantee(Capability.READ)
async def closing_a_handle_twice_is_refused_rather_than_accepted(sftp, root: bytes) -> None:
    """Refused, and again the *code* is not agreed, so no caller may narrow on one.

    * **OpenSSH**: `NO_SUCH_FILE`, message `No such file`.
    * **asyncssh** and **paramiko**: `BAD_MESSAGE`, message `Invalid handle`.

    `BAD_MESSAGE` reads as *your frame was malformed* and here means *I do not know that
    handle* -- the same trap `ENAMETOOLONG` sets, one layer along. So a `CLOSE` cleanup written
    as `except NoSuchFileError` would work against the reference and raise against two thirds of
    the matrix. Checked when this was written: both close paths use `suppress(Exception)`, so
    nothing narrows today.

    That it is refused *at all* is what makes an orphan reaper's proof mean anything -- a fake
    answering `OK` to every `CLOSE` cannot tell "closed the handle it was supposed to" from
    "closed something".
    """
    handle = await sftp.open(root + b"/a.txt", OpenFlag.READ)
    await sftp.close(handle)
    with pytest.raises(ServerError):
        await sftp.close(handle)


# --- creating and destroying -----------------------------------------------------------------


@guarantee(Capability.REMOVE)
async def removing_something_that_is_not_there_is_no_such_file(sftp, root: bytes) -> None:
    """The specific code again, because `rmtree` reads it to mean "already gone, carry on"."""
    with pytest.raises(NoSuchFileError):
        await sftp.remove(root + b"/absent")


@guarantee(Capability.REMOVE)
async def remove_refuses_a_directory(sftp, root: bytes) -> None:
    """`unlink(2)` semantics, and `rmtree`'s safety argument is built on them.

    A recursive removal descends and removes bottom-up; the reason it is safe to send `REMOVE`
    for an entry whose kind the server would not describe is that a server refuses to unlink a
    directory. A fake that accepted it would prove a `rmtree` that deletes trees it should not.
    """
    with pytest.raises(ServerError):
        await sftp.remove(root + b"/sub")


@guarantee(Capability.REMOVE)
async def rmdir_refuses_a_directory_that_still_holds_entries(sftp, root: bytes) -> None:
    """The other half of the same argument: bottom-up is enforced by the server, not just by us."""
    with pytest.raises(ServerError):
        await sftp.rmdir(root)


@guarantee(Capability.MKDIR)
async def mkdir_refuses_a_name_that_is_taken(sftp, root: bytes) -> None:
    """What makes `makedirs(exist_ok=False)` mean anything."""
    with pytest.raises(ServerError):
        await sftp.mkdir(root + b"/sub")


@guarantee(Capability.RENAME)
async def rename_refuses_to_replace_an_existing_name(sftp, root: bytes) -> None:
    """v3 `RENAME` does not overwrite, and the whole publish ladder is built on that.

    It is why `posix-rename@openssh.com` exists, why the fallback path removes the destination
    first, and why that removal is the step D-74 found losing both copies of a file. A fake that
    let `RENAME` clobber would make the extension look pointless and the fallback untested.
    """
    with pytest.raises(ServerError):
        await sftp.rename(root + b"/a.txt", root + b"/sub")


@guarantee(Capability.WRITE, Capability.READ)
async def what_was_written_reads_back(sftp, root: bytes) -> None:
    """The round trip, at an explicit offset, which is how the data path writes."""
    payload = b"contract" * 4
    flags = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
    handle = await sftp.open(root + b"/written", flags)
    try:
        assert await sftp.write_at(handle, 0, payload) == len(payload)
    finally:
        await sftp.close(handle)

    handle = await sftp.open(root + b"/written", OpenFlag.READ)
    try:
        assert await sftp.read_at(handle, 0, len(payload) * 2) == payload
    finally:
        await sftp.close(handle)


# --- the namespace -----------------------------------------------------------------------------


@guarantee(Capability.REALPATH)
async def realpath_of_dot_answers_an_absolute_path(sftp, root: bytes) -> None:
    """D-77's assumption, asserted rather than assumed.

    Every relative path this library builds is joined onto whatever `REALPATH(".")` answered, and
    the arithmetic is `/`-shaped. A server whose namespace is not rooted at `/` is refused by
    name rather than guessed at -- so what this pins is that the ordinary case really is the
    ordinary case, and the refusal is for the exception.
    """
    assert (await sftp.realpath(b".")).startswith(b"/")


CONTRACT_TREE = Tree(directories=(b"sub",), files={b"a.txt": b"contract-a"})
"""The layout every guarantee above is written against.

One layout rather than one per guarantee: a backend has to build it, and a fake building six
different trees is six chances for the fake to be the thing under test.
"""

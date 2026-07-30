"""`chdir` / `getcwd`, and the fact that this protocol has neither.

**D-95**, the half D-87 split out on purpose. SFTP v3 has no working directory: there is nothing
on the wire to set and nothing to ask. So `chdir` is a **prefix this library prepends**, which
makes it path algebra rather than two accessors — and it has to agree with everything else that
does path algebra, which is why the interesting tests here are not about `chdir` at all.

Three properties carry it.

**Every path-taking method honours it, and the proof is calling them.** They share one resolver,
and a test that only exercised the resolver would prove nothing about a method that encoded a
path for itself. That is not hypothetical: the mechanical sweep that routed them through it got
two wrong in each direction — `opendir` and `rmdir` were skipped, and the resolver rewrote itself
into infinite recursion — and only calling them found it.

**Resolving is idempotent, which is what the recursive operations need.** `walk` resolves its
root once and then joins child names onto that absolute root, so every child passes the resolver
again on the way back in through `get`. A prefix applied to whatever it was handed would double
on exactly those paths and produce a name that is still perfectly legal, so nothing would fail —
it would just be the wrong file.

**A prefix is `/` arithmetic**, so on a server whose namespace is not `/`-rooted there is nothing
correct to prepend and `chdir` refuses, exactly as `walk` and the tree operations do (D-77). That
is the same predicate, not a second list.
"""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path

import pytest
from tests.test_recursive import VMS_ROOT, TreeServer

from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    ServerError,
)
from gantry_sftp.session import Session, open_session, with_reconnect
from gantry_sftp.sync import open_local_server_transport as sync_open_local_server_transport
from gantry_sftp.sync import open_session as sync_open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def remote(path: Path) -> bytes:
    """A local path as the bytes a request carries, canonical.

    `.resolve()` here rather than at the call sites: `REALPATH` canonicalises, so an expected
    value built from a `tmp_path` with a symlink component would never match -- and calling a
    `pathlib` method inside an `async def` is what `ASYNC240` is for.
    """
    return os.fsencode(path.resolve())


def link_target(link: Path) -> bytes:
    """Where a symlink actually points, canonical, for comparing against a resolved path."""
    return os.fsencode(link.resolve())


def populate(root: Path) -> None:
    """A small tree, so a relative name has somewhere to resolve to."""
    (root / "incoming").mkdir()
    (root / "incoming" / "data.csv").write_bytes(b"id,total\n1,42\n")
    (root / "incoming" / "nested").mkdir()
    (root / "incoming" / "nested" / "deep.txt").write_bytes(b"deep")
    (root / "outgoing").mkdir()


# --- where we are before anybody moves ----------------------------------------------------


async def test_getcwd_before_a_chdir_is_the_servers_own_default(tmp_path: Path):
    """A `REALPATH` of `.`, which is the probe D-77 already had — so half of this is a rename.

    The recon question the card asked, answered: `_require_rooted_paths` has always sent this
    to decide whether path arithmetic is safe here, and cached it. `getcwd` reads the same
    value, and `server_root` is it without the round trip.
    """
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.server_root is None, "nothing should have probed yet"

        where = await sftp.getcwd()

        assert where == remote(tmp_path)
        assert sftp.server_root == where, "the probe should have been cached, not repeated"


async def test_a_relative_path_without_a_chdir_is_left_to_the_server(tmp_path: Path):
    """The behaviour that existed before this card, unchanged: no prefix means no prefix.

    The server has a default directory of its own and a relative path resolves against it
    server-side. Prepending nothing is not the same as prepending `getcwd()` — it costs no
    round trip, and it is what every existing test relies on.
    """
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.getsize(b"incoming/data.csv") == len(b"id,total\n1,42\n")
        assert sftp.server_root is None, "a relative stat sent a REALPATH it did not need"


# --- moving ------------------------------------------------------------------------------


async def test_chdir_makes_relative_paths_resolve_against_it(tmp_path: Path):
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))

        assert await sftp.getcwd() == remote(tmp_path / "incoming")
        assert await sftp.getsize(b"data.csv") == len(b"id,total\n1,42\n")
        assert await sftp.isdir(b"nested") is True
        assert await sftp.exists(b"not-there") is False


async def test_a_relative_chdir_composes_like_a_shells(tmp_path: Path):
    """Two `chdir`s land in the second relative to the first, and `..` comes back out.

    `..` is not string arithmetic here: it is canonicalised by the server through `REALPATH`,
    which is what keeps a prefix from holding a component a symlink can redirect between the
    `chdir` and the operation.
    """
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        await sftp.chdir(b"nested")
        assert await sftp.getcwd() == remote(tmp_path / "incoming" / "nested")
        assert await sftp.getsize(b"deep.txt") == len(b"deep")

        await sftp.chdir(b"..")
        assert await sftp.getcwd() == remote(tmp_path / "incoming")
        assert b".." not in await sftp.getcwd()


async def test_an_absolute_chdir_replaces_the_prefix_outright(tmp_path: Path):
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        await sftp.chdir(remote(tmp_path / "outgoing"))

        assert await sftp.getcwd() == remote(tmp_path / "outgoing")


async def test_an_absolute_path_ignores_the_working_directory(tmp_path: Path):
    """The property that makes resolving idempotent, asserted directly."""
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "outgoing"))

        # Absolute, so the prefix must not apply -- this file is not under `outgoing`.
        assert await sftp.exists(remote(tmp_path / "incoming" / "data.csv")) is True
        assert await sftp.exists(b"data.csv") is False


async def test_the_servers_own_root_is_not_moved_by_a_chdir(tmp_path: Path):
    """`server_root` answers a different question and has to keep answering it.

    The probe behind it deliberately bypasses the client-side prefix. Running it through the
    prefix would cache wherever `chdir` last went and publish that under a name that says
    *server*, which is the failure mode of a value that is nearly right.
    """
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        before = await sftp.getcwd()
        await sftp.chdir(remote(tmp_path / "incoming"))

        assert sftp.server_root == before
        assert await sftp.getcwd() != sftp.server_root


# --- the errored states ------------------------------------------------------------------


async def test_chdir_to_something_that_is_not_a_directory_is_refused(tmp_path: Path):
    """`REALPATH` does not check, so `chdir` does.

    Canonicalising a path that does not exist *succeeds* on OpenSSH, measured — so without an
    explicit check a `chdir` to a typo would be accepted and every later operation would fail
    somewhere else, naming a path the caller never typed.
    """
    needs_real_server()
    populate(tmp_path)
    target = tmp_path / "incoming" / "data.csv"
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refused:
            await sftp.chdir(remote(target))
        assert refused.value.args[0] == (
            f"chdir() needs a directory and {remote(target)!r} is a file"
        )

        # And nothing moved: a failed chdir must not leave the session somewhere new.
        assert await sftp.getcwd() == remote(tmp_path)


async def test_chdir_to_a_path_that_is_not_there_is_refused(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(NoSuchFileError):
            await sftp.chdir(remote(tmp_path / "never-existed"))


async def test_a_failed_chdir_leaves_the_previous_one_in_place(tmp_path: Path):
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        with pytest.raises(NoSuchFileError):
            await sftp.chdir(b"nowhere")

        assert await sftp.getcwd() == remote(tmp_path / "incoming")
        assert await sftp.getsize(b"data.csv") == len(b"id,total\n1,42\n")


# --- the sweep: one resolver, and every method has to be on it ----------------------------


async def test_every_reading_method_resolves_against_the_working_directory(tmp_path: Path):
    """Called rather than inspected, because a method that encoded its own path would pass.

    The mechanical rewrite that routed these through one resolver got `opendir` and `rmdir`
    wrong -- they kept the raw encoder -- and only calling them found it. Each assertion below
    is that the method reached the file *under the prefix* rather than the one beside it.

    Split from the mutating half only because one function reading and writing every path in
    the API is over the statement ceiling; the decoy and the argument are the same in both.
    """
    needs_real_server()
    populate(tmp_path)
    # A decoy beside the working directory: any method that failed to resolve would find this
    # one instead of the real target, and a test that only checked for success would pass.
    (tmp_path / "data.csv").write_bytes(b"decoy")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        under = remote(tmp_path / "incoming")

        assert (await sftp.stat(b"data.csv")).size == len(b"id,total\n1,42\n")
        assert (await sftp.lstat(b"data.csv")).size == len(b"id,total\n1,42\n")
        assert await sftp.getsize(b"data.csv") == len(b"id,total\n1,42\n")
        assert await sftp.getmtime(b"data.csv") is not None
        assert await sftp.exists(b"data.csv") is True
        assert await sftp.isfile(b"data.csv") is True
        assert await sftp.isdir(b"nested") is True
        assert await sftp.islink(b"data.csv") is False
        assert await sftp.realpath(b"data.csv") == under + b"/data.csv"

        assert [entry.filename for entry in await sftp.listdir(b"nested")] == [b"deep.txt"]
        handle = await sftp.opendir(b"nested")
        await sftp.close(handle)
        async with sftp.scandir(b"nested") as entries:
            assert [entry.filename async for entry in entries] == [b"deep.txt"]

        async with sftp.open_file(b"data.csv") as remote_file:
            assert remote_file.path == under + b"/data.csv"
            assert await remote_file.read(7) == b"id,tota"

        assert [entry.path async for entry in sftp.walk(b"nested")] == [under + b"/nested"]
        assert [match.path async for match in sftp.glob(b"*.csv")] == [under + b"/data.csv"]

        assert await sftp.get(b"data.csv", tmp_path / "fetched.csv") == len(b"id,total\n1,42\n")
        assert (tmp_path / "fetched.csv").read_bytes() == b"id,total\n1,42\n"

    # The decoy is untouched: nothing above reached the file beside the working directory.
    assert (tmp_path / "data.csv").read_bytes() == b"decoy"


async def test_every_mutating_method_resolves_against_the_working_directory(tmp_path: Path):
    """The other half of the sweep: the ones that create, move and delete.

    These matter more than the reads, because a method that missed the resolver here would not
    fail -- it would successfully create or delete something one directory up.
    """
    needs_real_server()
    populate(tmp_path)
    (tmp_path / "data.csv").write_bytes(b"decoy")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        _ = await sftp.get(b"data.csv", tmp_path / "fetched.csv")

        await sftp.mkdir(b"made")
        assert (tmp_path / "incoming" / "made").is_dir()
        await sftp.makedirs(b"made/deeper/still")
        assert (tmp_path / "incoming" / "made" / "deeper" / "still").is_dir()
        # `symlink`'s target is a string stored in the link, not a path this client operates
        # on, so the working directory must not reach it: this stays the relative link a
        # shell would make. The link *name* is resolved; the target is not.
        await sftp.symlink(b"data.csv", b"alias.csv")
        assert (tmp_path / "incoming" / "alias.csv").is_symlink()
        assert await sftp.readlink(b"alias.csv") == b"data.csv"
        assert link_target(tmp_path / "incoming" / "alias.csv") == remote(
            tmp_path / "incoming" / "data.csv"
        )
        await sftp.rename(b"alias.csv", b"renamed.csv")
        assert (tmp_path / "incoming" / "renamed.csv").is_symlink()
        await sftp.posix_rename(b"renamed.csv", b"moved.csv")
        assert (tmp_path / "incoming" / "moved.csv").is_symlink()
        await sftp.remove(b"moved.csv")
        assert not (tmp_path / "incoming" / "moved.csv").is_symlink()
        await sftp.rmdir(b"made/deeper/still")
        assert not (tmp_path / "incoming" / "made" / "deeper" / "still").exists()
        await sftp.rmtree(b"made")
        assert not (tmp_path / "incoming" / "made").exists()

        (tmp_path / "incoming" / "chmod-me.txt").write_bytes(b"x")
        await sftp.chmod(b"chmod-me.txt", 0o640)
        assert (tmp_path / "incoming" / "chmod-me.txt").stat().st_mode & 0o777 == 0o640
        await sftp.truncate(b"chmod-me.txt", 0)
        assert (tmp_path / "incoming" / "chmod-me.txt").stat().st_size == 0

        await sftp.put(tmp_path / "fetched.csv", b"uploaded.csv")
        assert (tmp_path / "incoming" / "uploaded.csv").read_bytes() == b"id,total\n1,42\n"


async def test_a_tree_transfer_resolves_its_root_and_then_stops_resolving(tmp_path: Path):
    """The idempotence property, exercised through the operation that would break without it.

    `get_tree` resolves the root once, walks it, and joins child names onto the *absolute*
    result -- so every child passes the resolver again and has to come out unchanged. A prefix
    applied unconditionally would produce `/incoming/incoming/nested`, which is a legal path
    that simply is not there.
    """
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        result = await sftp.get_tree(b"nested", tmp_path / "pulled")

    assert result.files == 1
    assert (tmp_path / "pulled" / "deep.txt").read_bytes() == b"deep"


async def test_a_path_a_walk_yielded_can_be_used_again_unchanged(tmp_path: Path):
    """The round trip a caller actually writes: walk, then act on what it handed back."""
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chdir(remote(tmp_path / "incoming"))
        found = [match.path async for match in sftp.glob(b"**/*.txt")]

        assert found == [remote(tmp_path / "incoming" / "nested" / "deep.txt")]
        for path in found:
            assert await sftp.getsize(path) == len(b"deep")


# --- the namespace question --------------------------------------------------------------


async def test_chdir_is_refused_where_the_namespace_is_not_rooted_at_slash():
    """D-77's predicate, not a second list of gated operations.

    A prefix *is* the `/` arithmetic that rule governs, so `chdir` joins it by being the same
    kind of operation rather than by being added to something. `getcwd` deliberately does not
    refuse: reporting where you are asks no arithmetic.
    """
    server = TreeServer(tree={b"incoming": ()}, root=VMS_ROOT)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(CapabilityError) as refused:
            await sftp.chdir(b"incoming")

        assert refused.value.feature == "chdir()"
        assert refused.value.args[0] == (
            "chdir() builds remote paths by '/' arithmetic and this server's default "
            "directory is not rooted at '/': REALPATH of b'.' answered b'DISK$USER:[SMITH]'. "
            "draft-ietf-secsh-filexfer-02 6.2 defines no other filename syntax, so joining or "
            "splitting b'incoming' would produce a path this server does not mean. Pass an "
            "absolute '/'-rooted path, or drive the per-file operations yourself with paths "
            "you build"
        )

        # And the session stays usable, which is the whole point of narrowing the refusal.
        assert await sftp.getcwd() == VMS_ROOT


# --- what a reconnect does to it ---------------------------------------------------------


async def test_the_working_directory_does_not_survive_a_reconnect(tmp_path: Path):
    """Consistent rather than an oversight, and the reason it has to be tested.

    `with_reconnect` builds a *new session per attempt* and its docstring says nothing
    survives one -- not the handles, not the request ids, not the negotiated limits. A working
    directory is the one of those a caller can set from outside, so it is the one they might
    expect to persist. Carrying it would make it the single exception to a stated invariant,
    and would silently re-establish a directory that may no longer be there.

    So the rule is: set it inside the operation, which is what that function already requires
    for everything else. Both halves are asserted, because "it does not carry over" and "the
    documented remedy works" are different claims.
    """
    needs_real_server()
    populate(tmp_path)
    recipe = partial(open_local_server_transport, cwd=tmp_path)

    async def where_am_i(sftp: Session) -> bytes:
        return await sftp.getcwd()

    async def move_then_read(sftp: Session) -> int:
        await sftp.chdir(remote(tmp_path / "incoming"))
        size = await sftp.getsize(b"data.csv")
        assert size is not None
        return size

    # A chdir performed before the operation cannot reach it: the session it ran on is gone.
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as first,
    ):
        await first.chdir(remote(tmp_path / "incoming"))
        assert await first.getcwd() == remote(tmp_path / "incoming")

    assert await with_reconnect(recipe, where_am_i, backoff=0) == remote(tmp_path)

    # And the documented remedy is what works.
    assert await with_reconnect(recipe, move_then_read, backoff=0) == len(b"id,total\n1,42\n")


# --- what it says about itself -----------------------------------------------------------


async def test_the_repr_shows_a_working_directory_only_once_there_is_one(tmp_path: Path):
    """It changes what every relative path in the caller's program means, so it is in the repr.

    Absent until set, so its absence reads as "no prefix" rather than as a field skimmed past.
    """
    needs_real_server()
    populate(tmp_path)
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert "cwd=" not in repr(sftp)

        await sftp.chdir(remote(tmp_path / "incoming"))

        assert f"cwd={remote(tmp_path / 'incoming')!r}" in repr(sftp)


# --- the blocking form -------------------------------------------------------------------


def test_the_working_directory_crosses_the_thread_boundary(tmp_path: Path):
    needs_real_server()
    populate(tmp_path)

    with (
        sync_open_local_server_transport(cwd=tmp_path) as transport,
        sync_open_session(transport) as sftp,
    ):
        assert sftp.getcwd() == remote(tmp_path)

        sftp.chdir(remote(tmp_path / "incoming"))

        assert sftp.getcwd() == remote(tmp_path / "incoming")
        assert sftp.getsize(b"data.csv") == len(b"id,total\n1,42\n")
        assert [entry.filename for entry in sftp.listdir(b"nested")] == [b"deep.txt"]

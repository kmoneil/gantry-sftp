"""What three real SFTP servers actually do, and where they disagree.

DESIGN.md 7 lists seven things endpoints differ on and, until this file, cited no measurement
for any of them -- one server cannot disagree with itself. These tests drive the same client
against OpenSSH, asyncssh and paramiko over real ``ssh`` connections, and pin the differences
so the table in that section stays a measurement rather than a memory.

**A failure here is usually a finding, not a bug.** If asyncssh adds an extension or paramiko
changes its error text, these fail, and the right response is to re-read the table and update
it -- which is the point. Pinned facts that nobody notices going stale are how a compatibility
document becomes fiction.

The backend is pinned to asyncio rather than parametrised over both. These are assertions
about *servers*; running each one twice would double a lane that starts real ``sshd``
processes to prove nothing about anyio.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import AsyncGenerator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from matrix import SERVER_NAMES, MatrixServer, running_server, unavailable_reason
from sshd import REDIRECTED_HOME, STEERING

from gantry_sftp.codec import (
    EXTENSION_LSETSTAT,
    CheckFileReply,
    Codec,
    Completed,
    Handle,
    Negotiated,
    Open,
    OpenFlag,
    StatusCode,
    Write,
    decode,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    ServerError,
    TransferError,
    TransferTimeoutError,
)
from gantry_sftp.session import (
    CHECK_FILE_BLOCK_SIZE,
    ContentCheck,
    Publish,
    ResumeCheck,
    Session,
    SizeCheck,
    TimePreservation,
    Verify,
    open_session,
    parse_vendor_id,
)
from gantry_sftp.transport import open_ssh_transport

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """Override the two-backend fixture: the subject here is the server, not the loop."""
    return "asyncio"


@pytest.fixture(params=SERVER_NAMES)
def server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MatrixServer]:
    """One running server per implementation, skipping with a reason when it cannot start."""
    name = str(request.param)
    reason = unavailable_reason(name)
    if reason is not None:
        pytest.skip(reason)
    with running_server(name, tmp_path) as running:
        yield running


@asynccontextmanager
async def connected(server: MatrixServer) -> AsyncGenerator[Session]:
    """A session against ``server``, over a real ``ssh`` connection."""
    connect = dict(server.connect)
    host = str(connect.pop("host"))
    async with open_ssh_transport(host, **connect) as transport, open_session(transport) as sftp:
        yield sftp


# --- what every implementation agrees on -------------------------------------------------------


def test_every_server_in_the_matrix_is_reached_with_both_defences(server: MatrixServer):
    """The sweep half of D-35: three constructors, one standard, asserted per server.

    ``matrix.py`` builds its own connection arguments for asyncssh and paramiko, and used to
    spell out ``config_file`` and ``env`` itself. They now go through
    :func:`sshd.client_kwargs`, and this is what keeps them there -- a construction site is a
    per-field decision nobody re-reads, and the failure mode is one server quietly being
    reached with the developer's agent and ``ssh_config`` in play while the other two are not.

    ``live-tests/test_ssh_environment.py`` proves what each of these three settings buys.

    **The ``HOME`` line is the one that does the work, and the absence check alone would be a
    test that could not fail.** On a runner where none of the steering names happens to be set
    -- a bare CI container, which is the default -- "none of these names is present" is equally
    true of ``dict(os.environ)``, so a site reverted to an unscrubbed environment would stay
    green. The redirect is never present by accident, so it is a positive statement that this
    dict came from the scrubber. Measured: with the asyncssh site reverted to
    ``dict(os.environ)`` and ``SHELL`` unset, the whole live suite was 117 passed / 10 skipped.
    """
    assert server.connect["config_file"] == os.devnull
    assert server.connect["options"]["IdentitiesOnly"] == "yes"
    assert server.connect["env"]["HOME"] == REDIRECTED_HOME
    assert [name for name in STEERING if name in server.connect["env"]] == []


async def test_every_server_negotiates_version_3(server: MatrixServer):
    # The floor the whole library is built on. If an implementation answered 4 or 6, every
    # ATTRS layout below it would be wrong and nothing else in this file would mean anything.
    async with connected(server) as sftp:
        assert sftp.server_version == 3


async def test_a_file_round_trips_through_every_server(server: MatrixServer, tmp_path: Path):
    """The interop claim, which is the one that matters more than any table below.

    Byte-identical rather than same-length, and random rather than zeroes, because the
    failure this catches -- an offset or reassembly bug that only shows against a server whose
    batching differs -- produces a file of exactly the right size.
    """
    payload = bytes(range(256)) * 300
    source = server.root / "upload.bin"
    source.write_bytes(payload)
    remote = server.root / "copy.bin"
    local = tmp_path / "back.bin"

    async with connected(server) as sftp:
        result = await sftp.put(source, str(remote))
        assert result.transferred == len(payload)
        assert await sftp.get(str(remote), local) == len(payload)

    assert remote.read_bytes() == payload
    assert local.read_bytes() == payload


async def test_rung_3_is_satisfied_by_every_server(server: MatrixServer, tmp_path: Path):
    """DESIGN.md 6's size check, against three implementations instead of one.

    Whether a `STAT` reply carries a size is per-implementation, and it decides whether rung 3
    reports `MATCHED` or silently degrades to `UNAVAILABLE`. Until 0.8 this had been measured
    against OpenSSH's `sftp-server` and nowhere else, so "the check happens" was a claim about
    one server. `UNAVAILABLE` on any row here would mean uploads through that endpoint are not
    being size-checked at all -- reported, but by a value nobody was asserting.

    **What the paramiko row is and is not.** Its filesystem handler is this repo's
    (`matrix._ParamikoHandler.stat` calls `SFTPAttributes.from_stat`), so the *value* is ours
    and this is not evidence about paramiko's filesystem behaviour. It is still evidence about
    paramiko's `SFTPServer`: whether the size flag survives its ATTRS encoding, and whether our
    client reads it back out. That half is not ours, so the row runs rather than skipping --
    with the line drawn here instead of left for a reader to assume.
    """
    payload = b"id,total\n1,42\n" * 91  # 1274 bytes: not a round number, not one packet
    source = tmp_path / "upload.csv"
    source.write_bytes(payload)
    remote = server.root / "verified.csv"

    async with connected(server) as sftp:
        result = await sftp.put(source, str(remote))

    assert result.size_check is SizeCheck.MATCHED, (
        f"{server.name} did not report a size, so rung 3 degraded to "
        f"{result.size_check.value} -- uploads through it are unchecked"
    )
    assert result.transferred == len(payload)
    assert remote.read_bytes() == payload


async def test_rung_3_reaches_whole_trees_through_every_server(
    server: MatrixServer, tmp_path: Path
):
    """`put_tree` and `get_tree` inherit the check by delegation -- proven here, not read.

    `tests/test_verification.py` proves the tree paths *fail* on a truncation, using a server
    built to lie. It cannot prove they do not misfire, because every scripted case there would
    also pass against an implementation that raised unconditionally. This is that other half,
    and it is run against three servers rather than one because "does this endpoint report a
    size" is exactly the fact that differs between them.

    `TreeResult` carries no `size_check` -- see the decision recorded in
    `tests/test_verification.py` -- so what a tree can assert is that it completed, which it
    cannot do if any file's check fired.
    """
    source = tmp_path / "outgoing"
    source.mkdir()
    for index in range(3):
        (source / f"part-{index}.bin").write_bytes(bytes((index + 7,)) * (500 + index))
    remote_root = server.root / "tree-up"
    landing = tmp_path / "landing"

    async with connected(server) as sftp:
        up = await sftp.put_tree(source, str(remote_root))
        down = await sftp.get_tree(str(remote_root), landing)

    assert up.files == 3, f"{server.name}: {up.skipped}"
    assert up.complete
    assert down.files == 3, f"{server.name}: {down.skipped}"
    assert down.complete
    for index in range(3):
        name = f"part-{index}.bin"
        assert (landing / name).read_bytes() == (source / name).read_bytes()


async def test_a_missing_file_is_reported_as_no_such_file_everywhere(server: MatrixServer):
    # The one status code every implementation maps the same way. The *message* does not
    # agree, which is the next test.
    async with connected(server) as sftp:
        with pytest.raises(NoSuchFileError):
            _ = await sftp.stat(b"/definitely/not/here")


async def test_an_uploaded_file_is_never_world_readable_through_any_server(
    server: MatrixServer, tmp_path: Path
):
    """D-56a's claim, against three implementations rather than one.

    ``mode=`` is the only way to deliver a file that is not ``0666 & ~umask``, and it depends on
    two things a server may or may not do: read ``PERMISSIONS`` out of the ``OPEN``'s ATTRS, and
    honour an ``FSETSTAT`` carrying only that flag. Neither is an extension, so there is no
    advertisement to consult and nothing to degrade to -- a server that ignored both would
    publish the file world-readable and report success, which is exactly what this argument
    exists to prevent. If any row here fails, the answer is a documented refusal on that server,
    not a silent downgrade.

    **What the paramiko row is and is not**, on the same line the rung-3 test draws:
    :class:`matrix._ParamikoHandler` is ours, so ``os.open``'s mode and ``os.fchmod`` are our
    code. What is paramiko's -- and what this measures -- is whether the ``PERMISSIONS`` flag
    survives its ATTRS decode and reaches the handler at all.
    """
    payload = b"-----BEGIN PRIVATE KEY-----\n"
    source = tmp_path / "key.pem"
    source.write_bytes(payload)
    remote = server.root / "delivered.pem"

    async with connected(server) as sftp:
        result = await sftp.put(source, str(remote), mode=0o600)

    assert result.mode == 0o600
    assert stat.S_IMODE(remote.stat().st_mode) == 0o600, (
        f"{server.name} published the file as "
        f"{stat.S_IMODE(remote.stat().st_mode):#o} rather than 0o600 -- an upload through it "
        f"cannot deliver a private file"
    )
    assert remote.read_bytes() == payload


async def test_touching_a_symlink_itself_degrades_where_lsetstat_is_absent(server: MatrixServer):
    """D-56b's degradation path, which is the *opposite* of every other extension here.

    An absent extension normally means a documented fallback. ``lsetstat@openssh.com`` has none
    to fall back to -- v3 offers no non-following ``SETSTAT`` at all, so "degrading" would mean
    operating on the link's target, which is precisely what the caller asked to avoid. So the
    absence is a :class:`CapabilityError` rather than a silent change of operation, and both
    halves of that are asserted here: it works where the extension is, and refuses where it is
    not, with the target unchanged either way.

    ``utime`` rather than ``chmod`` deliberately. Linux has no ``lchmod``, so
    ``lsetstat``'s *permissions* branch cannot succeed on any of these three however they are
    configured -- see ``tests/test_attributes_and_links.py``. ``utimensat`` accepts
    ``AT_SYMLINK_NOFOLLOW``, so the times branch is the one that can distinguish a server that
    has the extension from one that does not.

    Paramiko is the row that pays: it advertises only ``check-file``, and whether it answers an
    unknown ``EXTENDED`` with ``OP_UNSUPPORTED`` rather than dropping the connection is its
    protocol half, not our handler's.
    """
    target = server.root / "real.txt"
    target.write_bytes(b"payload")
    os.utime(target, (1_600_000_007, 1_600_000_000))
    link = server.root / "alias.txt"
    link.symlink_to(target)

    async with connected(server) as sftp:
        if not sftp.supports(EXTENSION_LSETSTAT):
            with pytest.raises(CapabilityError) as refusal:
                await sftp.utime(str(link), 1, 2, follow_symlinks=False)
            assert refusal.value.missing == (EXTENSION_LSETSTAT,)
            assert int(target.stat().st_mtime) == 1_600_000_000
            return
        await sftp.utime(str(link), 1, 2, follow_symlinks=False)

    assert int(os.lstat(link).st_mtime) == 2
    assert int(target.stat().st_mtime) == 1_600_000_000, (
        f"{server.name} followed the symlink despite lsetstat@openssh.com -- the target's "
        f"times were changed, which is the operation follow_symlinks=False exists to avoid"
    )


HANDLER_IS_OURS = frozenset({"paramiko"})
"""Servers whose *filesystem* behaviour is this repo's code rather than the implementation's.

Paramiko ships ``SFTPServer`` -- packet handling, advertised extensions, the mapping from
``errno`` to a status code and its message text -- and leaves the filesystem to the caller,
so :class:`matrix._ParamikoHandler` is ours. Protocol-level facts read off it are paramiko's
and are asserted below. Filesystem-level ones are *our* thirty lines, and reporting those as
findings about paramiko would be the fake-confirms-its-author trap with extra steps.
"""


def skip_where_the_handler_is_ours(server: MatrixServer) -> None:
    if server.name in HANDLER_IS_OURS:
        pytest.skip(
            f"{server.name}'s filesystem behaviour is this repo's handler, not the server's -- "
            f"see matrix.HANDLER_IS_OURS"
        )


# --- where they disagree, which is the point ---------------------------------------------------

EXPECTED_EXTENSIONS = {
    "openssh": {
        "copy-data",
        "expand-path@openssh.com",
        "fstatvfs@openssh.com",
        "fsync@openssh.com",
        "hardlink@openssh.com",
        "home-directory",
        "limits@openssh.com",
        "lsetstat@openssh.com",
        "posix-rename@openssh.com",
        "statvfs@openssh.com",
        "users-groups-by-id@openssh.com",
    },
    "asyncssh": {
        "copy-data",
        "fstatvfs@openssh.com",
        "fsync@openssh.com",
        "hardlink@openssh.com",
        "limits@openssh.com",
        "lsetstat@openssh.com",
        "newline",
        "posix-rename@openssh.com",
        "ranges@asyncssh.com",
        "statvfs@openssh.com",
        "vendor-id",
    },
    "paramiko": {"check-file"},
}
"""Measured 2026-07-27 against OpenSSH 10.0p2, asyncssh 2.24.0, paramiko 5.0.0."""


async def test_the_advertised_extension_set_is_what_was_measured(server: MatrixServer):
    """Eleven, eleven and one -- and the overlap is smaller than the counts suggest.

    §7 says endpoints often advertise none. Paramiko advertises one, and it is not one OpenSSH
    has. This is the fact that makes "absent extension implies a documented fallback path"
    load-bearing rather than defensive.
    """
    async with connected(server) as sftp:
        advertised = {name.decode() for name in sftp.extensions}

    assert advertised == EXPECTED_EXTENSIONS[server.name]


async def test_nothing_can_be_relied_on_beyond_what_all_three_share(server: MatrixServer):
    # The intersection across the matrix is empty: paramiko advertises only `check-file`,
    # which neither of the others has. So there is no extension a client may assume, which is
    # exactly why every use of one has to degrade.
    shared = set.intersection(*(set(names) for names in EXPECTED_EXTENSIONS.values()))
    assert shared == set(), f"the matrix now shares {shared}, and the fallbacks can relax"


async def test_a_real_check_file_digest_matches_what_hashlib_computes(
    server: MatrixServer, tmp_path: Path
):
    """D-5, closed: rung 1 of §6's ladder, read off a server that really speaks it.

    Open since 0.2 on the grounds that no reachable server implemented ``check-file`` --
    OpenSSH answers ``OP_UNSUPPORTED`` under all three spellings, and ProFTPD's ``checkFile``
    was known only from documentation. Paramiko advertises it, so the layout stops being an
    inference.

    **The assertion is the digest, not the shape.** A layout that parses without raising and
    yields the wrong bytes is exactly the failure this had to rule out, and comparing against
    ``hashlib`` over the same content is the only thing that does. The frame is also written
    out as a golden fixture by ``test_check_file_fixture_is_current`` in the ordinary suite.
    """
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    # sha1 because paramiko's server offers only md5 and sha1, and `usedforsecurity=False`
    # because this is a comparison against what the server computed rather than a security
    # decision -- the algorithm is the server's constraint, not our choice.
    #
    # Each 1 KiB block is a distinct byte value, which matters: the first version of this
    # used a repeating pattern, every block hashed identically, and the ordering assertion
    # below could not have failed however scrambled the reply was.
    payload = b"".join(bytes([n]) * 1024 for n in range(10))
    target = server.root / "hashed.bin"
    target.write_bytes(payload)

    async with connected(server) as sftp:
        handle = await sftp.open(str(target))
        try:
            whole = await sftp.check_file(handle, algorithms=b"sha1")
            blocked = await sftp.check_file(handle, algorithms=b"sha1", block_size=1024)
        finally:
            await sftp.close(handle)

    algorithm, digests = whole
    assert algorithm == b"sha1"
    assert digests == (hashlib.sha1(payload, usedforsecurity=False).digest(),)

    _, per_block = blocked
    expected = tuple(
        hashlib.sha1(payload[start : start + 1024], usedforsecurity=False).digest()
        for start in range(0, len(payload), 1024)
    )
    assert per_block == expected, "block boundaries or ordering are wrong"


async def test_check_file_hashes_only_the_range_it_was_given(server: MatrixServer, tmp_path: Path):
    # start_offset and length are the fields a from-memory layout gets in the wrong order,
    # and a whole-file test cannot tell the difference because both are zero.
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    payload = bytes(range(256)) * 8
    target = server.root / "ranged.bin"
    target.write_bytes(payload)

    async with connected(server) as sftp:
        handle = await sftp.open(str(target))
        try:
            algorithm, digests = await sftp.check_file(
                handle, algorithms=b"sha1", start_offset=300, length=500
            )
        finally:
            await sftp.close(handle)

    assert algorithm == b"sha1"
    assert digests == (hashlib.sha1(payload[300:800], usedforsecurity=False).digest(),)


async def test_the_committed_check_file_fixture_still_matches_what_paramiko_sends(
    server: MatrixServer,
):
    """Ties the golden frame in ``tests/fixtures`` to the server it was captured from.

    That fixture is the *only* source for the reply layout -- ``check-file`` is in no secsh
    draft, so if paramiko changes its wire format there is no document to notice the
    disagreement against. This is the notice: it re-runs the exact capture and compares the
    digests, so a stale fixture fails here rather than silently pinning history.
    """
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    fixture = Path(__file__).parent.parent / "tests" / "fixtures" / "paramiko_check_file_reply.bin"
    committed = CheckFileReply.from_reply(decode(memoryview(fixture.read_bytes())[4:]))  # type: ignore[arg-type]

    # The capture hashed ten 1 KiB blocks, block n being the byte n repeated.
    payload = b"".join(bytes([n]) * 1024 for n in range(10))
    target = server.root / "fixture-content.bin"
    target.write_bytes(payload)

    async with connected(server) as sftp:
        handle = await sftp.open(str(target))
        try:
            algorithm, digests = await sftp.check_file(handle, algorithms=b"sha1", block_size=1024)
        finally:
            await sftp.close(handle)

    assert algorithm == committed.algorithm
    assert b"".join(digests) == committed.digests, "the committed fixture is stale"


async def test_check_file_with_no_algorithm_in_common_is_refused(server: MatrixServer):
    # The server picks from our list and answers FAILURE when it can offer none. Worth
    # pinning because the alternative -- silently hashing with something we did not ask for
    # -- would be a verification that verified the wrong thing.
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    target = server.root / "unhashable.bin"
    target.write_bytes(b"x")

    async with connected(server) as sftp:
        handle = await sftp.open(str(target))
        try:
            with pytest.raises(ServerError) as exc:
                _ = await sftp.check_file(handle, algorithms=b"blake3,crc32")
        finally:
            await sftp.close(handle)

    assert exc.value.message == b"No supported hash types found"


async def test_the_default_block_size_hashes_a_file_larger_than_one_read(
    server: MatrixServer, tmp_path: Path
):
    """D-38's regression, and it is bounded so a regression *fails* rather than hangs.

    ``check_file``'s ``block_size`` defaulted to ``0`` -- the wire value for "one digest over
    the whole range" -- until 0.9. Against paramiko that is a **hang** for any range over
    64 KiB, because ``_check_file``'s inner loop advances by a cumulative count where it means
    a per-read length, and once the runaway offsets pass EOF ``readfile.read()`` returns
    ``b""``, which the loop does not count as progress. Its own :meth:`SFTPHandle.read`
    documents returning exactly that at EOF, so the two halves disagree in stock code.

    Every earlier case in this file hashes 10 KiB, which is under the boundary, so none of
    them could have found it. This one is 200 KiB.

    The timeout is the point of the test as much as the assertion. A run that hangs reads as a
    slow machine rather than as a caught regression -- the lesson D-36 left behind -- so this
    bounds itself and fails with a message naming what it was waiting for. **Measured against
    the old default**: it fails, and the `CLOSE` in the teardown times out too, because the
    server thread never leaves that loop and answers nothing else for the rest of the session.
    That second timeout is why the handle is not closed on the failing path -- there is nothing
    left to close it with.
    """
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    payload = b"".join(bytes([n % 251]) * 1024 for n in range(200))
    target = server.root / "over-one-read.bin"
    target.write_bytes(payload)

    async with connected(server) as sftp:
        handle = await sftp.open(str(target))
        try:
            with anyio.fail_after(30):
                algorithm, digests = await sftp.check_file(handle, algorithms=b"sha1")
        except (TimeoutError, TransferTimeoutError):
            pytest.fail(
                "check_file did not answer: block_size reached the server as something over "
                "64 KiB and paramiko is now looping in _check_file, permanently"
            )
        await sftp.close(handle)

    assert algorithm == b"sha1"
    assert digests == tuple(
        hashlib.sha1(payload[start : start + CHECK_FILE_BLOCK_SIZE], usedforsecurity=False).digest()
        for start in range(0, len(payload), CHECK_FILE_BLOCK_SIZE)
    )


async def test_a_resume_onto_a_wrong_prefix_is_refused_by_a_server_that_can_prove_it(
    server: MatrixServer, tmp_path: Path
):
    """D-38's gate, against the one implementation of ``check-file`` this project can reach.

    The scripted half in ``tests/test_content_verification.py`` proves the gate *fires*. This
    proves it fires against a server whose digests we did not compute, over a real ``ssh``
    connection -- the difference between agreeing with our idea of a server and agreeing with
    one.
    """
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    source = tmp_path / "source.bin"
    source.write_bytes(b"correct " * 512)
    destination = server.root / "resumed.bin"
    # A partial of the right length for its offset and the wrong bytes: exactly what a size
    # match cannot refuse, and what the finished upload's size check would have accepted.
    destination.write_bytes(b"WRONG!! " * 128)

    async with connected(server) as sftp:
        with pytest.raises(TransferError) as exc:
            _ = await sftp.put(source, str(destination), publish=Publish(atomic=False), resume=True)

    assert "are not a prefix of" in exc.value.args[0]
    assert exc.value.offset == 1024
    # Refused before a byte was sent, so the partial is exactly as it was found.
    assert destination.read_bytes() == b"WRONG!! " * 128


async def test_a_resume_onto_a_matching_prefix_is_proven_and_completed(
    server: MatrixServer, tmp_path: Path
):
    # The other half: the gate must not misfire on the partial it is supposed to accept, and
    # the upload must still send only the remainder rather than starting over.
    if server.name != "paramiko":
        pytest.skip(f"{server.name} does not advertise check-file")

    payload = b"correct " * 512
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    destination = server.root / "resumable.bin"
    destination.write_bytes(payload[:1024])

    async with connected(server) as sftp:
        result = await sftp.put(
            source, str(destination), publish=Publish(atomic=False), resume=True
        )

    assert result.resume_check is ResumeCheck.MATCHED
    assert result.transferred == len(payload) - 1024
    assert destination.read_bytes() == payload


async def test_rung_2_verifies_content_on_every_server_in_the_matrix(
    server: MatrixServer, tmp_path: Path
):
    """Rung 2's reason for existing: it needs no extension, so it works everywhere.

    Not skipped for any row. ``check-file`` is paramiko-only, which is precisely why the
    library cannot offer content verification through it alone -- and this is the assertion
    that the fallback is genuinely universal rather than merely documented as such.
    """
    payload = os.urandom(300_007)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    destination = server.root / "verified.bin"

    async with connected(server) as sftp:
        result = await sftp.put(source, str(destination), verify=Verify.REREAD)

    assert result.content_check is ContentCheck.REREAD
    assert destination.read_bytes() == payload


async def test_only_paramiko_offers_hash_based_verification(server: MatrixServer):
    """Rung 1 of §6's verification ladder, which had never been seen on a real server.

    D-5 has been open since 0.2 on exactly this: ``check-file`` is absent from OpenSSH, and
    ProFTPD's ``checkFile`` was known only from documentation. Paramiko advertises it -- and
    unsuffixed, matching the draft rather than OpenSSH's ``@openssh.com`` convention -- so the
    request and ``EXTENDED_REPLY`` layouts can now be read off something that really speaks it.
    """
    async with connected(server) as sftp:
        offered = sftp.supports(b"check-file")

    assert offered is (server.name == "paramiko")


EXPECTED_LIMITS = {
    "openssh": (261120, 261120),
    "asyncssh": (4194304, 4194304),
    "paramiko": (None, None),
}
"""Measured read/write maxima. Paramiko advertises no ``limits@openssh.com`` at all."""


async def test_transfer_limits_differ_by_more_than_an_order_of_magnitude(server: MatrixServer):
    """A 16x spread, and one server that will not say.

    This is the tunable the request-size negotiation already consumes, so it is not a curiosity:
    a client that hard-coded OpenSSH's 255 KiB would leave asyncssh sixteen times slower than
    it needs to be, and one that hard-coded asyncssh's 4 MiB would have every request silently
    clamped by OpenSSH. The paramiko row is the *absent* case, which falls back to our defaults
    rather than failing -- the first time that path has been exercised against a real server.
    """
    async with connected(server) as sftp:
        limits = sftp.limits

    assert (limits.max_read_length, limits.max_write_length) == EXPECTED_LIMITS[server.name]


EXPECTED_MISSING_FILE_TEXT = {
    "openssh": b"No such file",
    "asyncssh": b"No such file or directory",
    "paramiko": b"No such file",
}
"""The server's own words for the same condition. Two spellings across three servers."""


async def test_the_words_for_a_missing_file_are_not_the_same(server: MatrixServer):
    """The input a quirks layer would have to match on, and it is already inconsistent.

    D-30 needs to tell a transient ``FAILURE`` from a terminal one, and the only material a
    v3 server offers is this string. Three implementations, two spellings, for the one status
    code they *do* all map identically -- which is the argument for matching message text
    being a per-profile rule rather than a table of substrings that works everywhere.
    """
    async with connected(server) as sftp:
        with pytest.raises(NoSuchFileError) as exc:
            _ = await sftp.stat(b"/definitely/not/here")

    assert exc.value.message == EXPECTED_MISSING_FILE_TEXT[server.name]


async def test_rename_onto_an_existing_target_is_refused(server: MatrixServer):
    """§7 says implementations differ here -- overwrite, error, or silent no-op.

    Both implementations whose filesystem layer is their own refuse, which is the answer
    atomic publish depends on: the ``remove``-then-``rename`` fallback exists precisely
    because plain v3 ``RENAME`` cannot replace. Worth measuring rather than inferring from
    OpenSSH, because a server that overwrote would make that fallback unnecessary *and* make
    the publish step non-atomic in a way nothing would have noticed.

    Paramiko is excluded, and the exclusion is the interesting part. Its handler here is
    ours, and ours uses ``Path.rename``, which replaces silently -- so this test failed
    against it on the first run. Making the handler conformant would have turned a red test
    green by choosing the answer to the question being asked, which is worse than not asking.
    """
    skip_where_the_handler_is_ours(server)
    source = server.root / "rename-source.bin"
    source.write_bytes(b"source")
    target = server.root / "rename-target.bin"
    target.write_bytes(b"target")

    async with connected(server) as sftp:
        with pytest.raises(ServerError):
            await sftp.rename(str(source), str(target))

    assert target.read_bytes() == b"target", "the target was replaced despite the refusal"
    assert source.read_bytes() == b"source", "the source was consumed by a failed rename"


async def test_realpath_of_a_path_that_does_not_exist(server: MatrixServer):
    """§7's open question, answered for the two servers that can answer it.

    Both canonicalise rather than refuse, so the disagreement §7 predicted is not there --
    worth pinning precisely because a non-finding is the kind of thing that gets quietly
    re-litigated. A server that refused would break any client canonicalising a destination
    before writing to it.

    Paramiko is excluded for the same reason as the rename above: ``canonicalize`` is a
    method on the handler, so its answer here would be ours.
    """
    skip_where_the_handler_is_ours(server)
    missing = server.root / "no-such-name.bin"

    async with connected(server) as sftp:
        resolved = await sftp.realpath(str(missing))

    assert resolved == str(missing).encode()


async def test_only_asyncssh_says_who_it_is(server: MatrixServer):
    """``vendor-id`` is a free, structured fingerprint, and §7 does not mention it.

    That section proposes fingerprinting from the SSH banner -- which this architecture does
    not see, because ``ssh`` consumes it, and which costs ``LogLevel=DEBUG1`` and about 3.4 KB
    of stderr per connection to recover. ``vendor-id`` costs nothing and arrives with the
    handshake. It is only worth as much as its coverage, and its coverage here is one server
    in three, so it narrows the fingerprinting problem rather than solving it.
    """
    async with connected(server) as sftp:
        vendor = sftp.extensions.get(b"vendor-id")

    if server.name != "asyncssh":
        assert vendor is None
        return

    assert vendor is not None
    # Layout: string vendor, string product, string version, uint64 build. Sourced from
    # asyncssh's own `_parse_vendor_id` and from these bytes -- it is in neither
    # draft-ietf-secsh-filexfer-05 nor -13, both of which were checked after an earlier
    # version of this comment cited draft-05 for it and was wrong.
    assert parse_vendor_id(vendor) == ("Ron Frederick", "AsyncSSH", "2.24.0", 0)


async def test_every_server_is_identified_from_what_it_advertised(server: MatrixServer):
    """Fingerprinting, against the three implementations it was written from.

    The unit tests match against extension sets copied into the ordinary suite; this is the
    one place the sets themselves are what a server really sent. A server that changes its
    advertisement fails here first, which is the right order -- the copies are downstream.
    """
    async with connected(server) as sftp:
        profile = sftp.profile

    assert profile.name == server.name
    assert profile.name in repr(sftp.profile) or profile.name == profile.label.split("/")[0]


async def test_only_asyncssh_reports_a_version_because_only_it_says_one(server: MatrixServer):
    # No version is inferred from an extension list. OpenSSH's is knowable only from the SSH
    # banner, which this architecture does not see, so the honest answer is None.
    async with connected(server) as sftp:
        profile = sftp.profile

    if server.name == "asyncssh":
        assert profile.version is not None
        assert profile.label == f"asyncssh/{profile.version}"
    else:
        assert profile.version is None
        assert profile.label == server.name


# --- the claim atomic publish rests on: CREAT|EXCL refuses an existing file --------------------


async def test_creat_excl_creates_a_file_that_is_not_there(server: MatrixServer):
    """The control, and without it the refusal below proves nothing.

    A server that refused *every* ``OPEN`` would pass the exclusion test for the wrong reason.
    This is the half that says ``CREAT|EXCL`` is a working way to create a file at all.
    """
    skip_where_the_handler_is_ours(server)
    target = server.root / "excl-fresh.bin"
    async with connected(server) as sftp:
        handle = await sftp.open(str(target), OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL)
        await sftp.close(handle)

    assert target.exists()


async def test_creat_excl_refuses_a_file_that_is_already_there(server: MatrixServer):
    """D-16, and it is the assumption the whole staging design is built on.

    ``put`` writes to ``.name.<token>.part`` and renames it over the target. Two publishers
    that generate the same token must not both open the staging file and interleave their
    writes into it, and ``EXCL`` is the only thing standing between them -- v3 has no
    ``EEXIST``, so a server that ignored ``EXCL`` would produce a file of the wrong length
    with no status code anywhere saying why.

    Until now that claim was backed by a comment in ``session/_quirks.py`` recording that the
    condition had been provoked by hand. A comment is not a test, and the rule this repo
    applies to quirks profiles -- ship the fixture or do not ship the profile -- applies at
    least as hard to a protocol assumption an entire feature rests on.
    """
    skip_where_the_handler_is_ours(server)
    target = server.root / "excl-taken.bin"
    target.write_bytes(b"already here")

    async with connected(server) as sftp:
        with pytest.raises(ServerError) as exc:
            _ = await sftp.open(str(target), OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL)

    # v3 has no EEXIST, so this is the catch-all -- which is exactly why the *message* below
    # is the only thing that could ever distinguish it from any other refusal.
    assert exc.value.code == int(StatusCode.FAILURE)
    assert target.read_bytes() == b"already here"


EXPECTED_EXCL_TEXT = {
    "openssh": b"Failure",
    "asyncssh": b"File exists",
}
"""What each server says when ``EXCL`` refuses. Two of three; paramiko's condition is ours.

The pair that makes ``ServerProfile.informative_messages`` a measurement: OpenSSH's word is
a constant function of the status code and carries nothing, asyncssh's is ``strerror`` text.
"""


async def test_the_words_for_an_existing_file_are_the_profiles_evidence(server: MatrixServer):
    """D-6, asked where it actually matters: on a ``FAILURE``, not on ``NO_SUCH_FILE``.

    The register filed D-6 as "how many servers truncate the ``STATUS`` tail", worried that
    the quirks layer's only input for disambiguating the catch-all might not be there at all.
    Every server here sends it, and the tail is present and non-empty on all three -- so the
    premise the profiles are built on holds for everything this matrix can start.

    **The answer is worse than truncation and less obvious.** OpenSSH's tail is present and
    says ``Failure`` for five distinct conditions, so it is a constant, not information. A
    missing field announces itself; a field that is always the same word does not.
    """
    skip_where_the_handler_is_ours(server)
    target = server.root / "excl-words.bin"
    target.write_bytes(b"already here")

    async with connected(server) as sftp:
        with pytest.raises(ServerError) as exc:
            _ = await sftp.open(str(target), OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.EXCL)

    assert exc.value.message, "the STATUS tail is absent, and D-6's original worry was real"
    assert exc.value.message == EXPECTED_EXCL_TEXT[server.name]


async def test_a_failure_tail_is_present_on_every_server_including_the_wrapped_one(
    server: MatrixServer,
):
    """The half of D-6 that paramiko *can* answer, and the reason it is a separate test.

    Whether the condition arises is our handler's business on paramiko; what text a status
    carries is paramiko's. So the tail question is askable of all three even where the
    filesystem question is not.
    """
    async with connected(server) as sftp:
        with pytest.raises(ServerError) as exc:
            _ = await sftp.stat(b"/definitely/not/here")

    assert exc.value.message, "STATUS arrived with no tail at all"


# --- D-87: a predicate's answers, across three implementations ---------------------------------


async def test_the_predicates_agree_across_every_implementation(server: MatrixServer):
    """`exists`/`isdir`/`isfile` rest on two things a server chooses, so ask all three.

    The first is the status code for a path that is not there, which the matrix already pins
    to `NO_SUCH_FILE` everywhere -- and `False` here means that code and nothing else, so a
    server answering `FAILURE` instead would turn every absent path into a raised error.

    The second is whether a `STAT` reply carries permission bits at all. v3 keeps the file
    type inside them, so a server that omits them makes `isdir` unanswerable -- which this
    library reports as a `CapabilityError` rather than a `False`. That case is unreachable
    against OpenSSH and is proven against a fake in `tests/test_predicates.py`; what this
    test establishes is that the fake is describing a hypothetical rather than any of the
    three implementations here.
    """
    (server.root / "folder").mkdir()
    (server.root / "data.bin").write_bytes(b"payload")

    async with connected(server) as sftp:
        assert await sftp.exists(str(server.root / "data.bin")) is True
        assert await sftp.exists(str(server.root / "folder")) is True
        assert await sftp.exists(str(server.root / "not-here")) is False

        assert await sftp.isdir(str(server.root / "folder")) is True
        assert await sftp.isfile(str(server.root / "data.bin")) is True
        assert await sftp.isdir(str(server.root / "data.bin")) is False

        assert await sftp.getsize(str(server.root / "data.bin")) == len(b"payload")
        assert await sftp.getmtime(str(server.root / "data.bin")) is not None


async def test_makedirs_walks_up_on_every_implementation(server: MatrixServer):
    """The walk-up is driven by a *refusal*, and v3 does not say which refusal it will be.

    `_mkdir_parents` retries after any `ServerError` rather than after `NO_SUCH_FILE`
    specifically, because the status for "the parent is missing" is exactly the kind of thing
    §7 says implementations disagree about. This is that generosity being load-bearing rather
    than defensive: three servers, three error-mapping layers, one chain of directories that
    has to appear.
    """
    destination = server.root / "a" / "b" / "c"

    async with connected(server) as sftp:
        await sftp.makedirs(str(destination))
        assert await sftp.isdir(str(destination)) is True

        # And the second call is the one that has to be refused rather than quietly excused.
        with pytest.raises(ServerError):
            await sftp.makedirs(str(destination))
        await sftp.makedirs(str(destination), exist_ok=True)

    assert destination.is_dir()


async def test_a_path_that_cannot_be_reached_is_not_reported_as_absent(server: MatrixServer):
    """The third state, against three error-mapping layers rather than one.

    `EACCES` has to arrive as something other than `NO_SUCH_FILE` or `exists()` answers
    `False` for a path the caller merely cannot see -- and the next line in most programs that
    ask creates something there. The assertion is deliberately on the *class* rather than on
    `PermissionDeniedError`: what matters is that it is not silently a `False`, and a server
    that mapped `EACCES` to the `FAILURE` catch-all would still be safe.
    """
    closed = server.root / "closed"
    closed.mkdir()
    (closed / "secret.bin").write_bytes(b"payload")
    closed.chmod(0o000)
    try:
        async with connected(server) as sftp:
            with pytest.raises(ServerError) as refused:
                await sftp.exists(str(closed / "secret.bin"))
        assert not isinstance(refused.value, NoSuchFileError), (
            "an unreadable path arrived as NO_SUCH_FILE, which a predicate reports as False"
        )
    finally:
        closed.chmod(0o755)


# --- D-15: does a server whose replies nobody reads stop reading us? --------------------------

CHANNEL_WINDOW = 2 * 1024 * 1024
"""OpenSSH's per-channel window, measured by the netem lane and recorded in DESIGN.md 5.1."""

UNDRAINED_REQUEST_BYTES = 2 * CHANNEL_WINDOW
"""How many bytes of ``WRITE`` to push without reading a single reply.

Twice the window on purpose. The window is the most data that can be in flight unacknowledged,
so pushing twice it and finishing proves the server consumed at least a window's worth **while
its own replies went unread** -- which is the deadlock condition, stated as something a test
can observe rather than as a story about buffering.
"""

UNDRAINED_DEADLINE = 60.0
"""A bound, not a performance assertion. Reaching it *is* the card's other outcome."""

SEND_CHUNK = 64 * 1024


async def receive_until(transport: object, codec: Codec, wanted: type) -> object:
    """Read from ``transport`` until an event of ``wanted`` arrives, and return it.

    ``wanted`` is a codec *event* -- :class:`Negotiated` or :class:`Completed` -- not a packet
    class. VERSION and every reply are absorbed into events rather than surfaced as packets, so
    waiting on ``Version`` or ``Handle`` here waits forever, which is exactly how this helper
    was first written.
    """
    while True:
        for event in codec.receive(await transport.receive()):  # type: ignore[attr-defined]
            if isinstance(event, wanted):
                return event


async def test_a_server_whose_replies_go_unread_keeps_reading_our_requests(
    server: MatrixServer,
):
    """D-15 closes by being dropped with evidence, against all three implementations.

    ``session/_upload.py`` sends and receives concurrently. The textbook justification is
    deadlock -- fill the server's input while the server, blocked writing replies nobody
    drains, stops reading. That was **retracted in 0.4** because it could not be reproduced
    against a real ``sftp-server`` on a pipe, and the card stayed open on the possibility that
    another implementation, or a real SSH channel with its own windowing, would differ.

    Neither does, and there is a reason it cannot for an upload specifically: **a ``WRITE``
    request is always larger on the wire than the ``STATUS`` it produces** -- 33 bytes of
    header plus payload against roughly 21 bytes of reply -- and both directions are bounded by
    the same channel window. So the unread-reply backlog is strictly smaller than the request
    backlog that created it, and the client's own send blocks first, every time. The
    justification was not merely unproven; for this direction it was the wrong mechanism.

    Deliberately driven below the session, because a session **cannot** express the condition:
    :class:`~gantry_sftp.session.Dispatcher` owns ``receive`` and drains continuously. Batched
    into few large sends rather than one ``await`` per packet -- same bytes on the wire, and an
    ``await`` per request made this test slower than the whole rest of the lane put together.

    A timeout here is not a flake and not a bug. It is the finding the card asked for, and it
    would mean restoring the docstring ``_upload.py`` gave up. The concurrent design keeps its
    other justifications regardless: bounded memory on both sides, and a failure surfacing when
    it happens rather than after the whole file is queued.
    """
    connect = dict(server.connect)
    host = str(connect.pop("host"))
    target = server.root / "undrained.bin"
    payload = b"x" * 64

    async with open_ssh_transport(host, **connect) as transport:
        codec = Codec()
        await transport.send(codec.initiate())
        _ = await receive_until(transport, codec, Negotiated)

        open_id = codec.allocate_request_id()
        flags = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
        await transport.send(codec.send(Open(open_id, str(target).encode(), flags)))
        opened = await receive_until(transport, codec, Completed)
        assert isinstance(opened.response, Handle), opened.response  # type: ignore[attr-defined]
        handle: bytes = opened.response.handle  # type: ignore[attr-defined]

        queued = bytearray()
        offset = 0
        while len(queued) < UNDRAINED_REQUEST_BYTES:
            request_id = codec.allocate_request_id()
            queued += codec.send(Write(request_id, handle, offset=offset, data=payload))
            offset += len(payload)

        # From here nothing is read: every STATUS the server sends piles up unread.
        with anyio.fail_after(UNDRAINED_DEADLINE):
            view = memoryview(queued)
            for start in range(0, len(view), SEND_CHUNK):
                await transport.send(view[start : start + SEND_CHUNK])

    assert len(queued) > CHANNEL_WINDOW
    assert codec.outstanding == offset // len(payload)


async def test_preserving_timestamps_works_or_degrades_on_every_server(
    server: MatrixServer, tmp_path: Path
):
    """D-79 against something other than OpenSSH, which is the only way to trust the fallback.

    ``preserve_times`` sends an ``FSETSTAT`` carrying an ATTRS whose ``ACMODTIME`` bit governs
    two positional fields. A server that reads that body differently does not fail: it answers
    ``OK`` and sets the wrong thing, or sets nothing at all. So this asserts the *file*, not
    the status -- and it accepts a documented degrade rather than demanding success, because
    "every extension use degrades" applies to attribute mutation as much as to `posix-rename`.

    Skipped for paramiko: ``SFTPServer`` hands the filesystem to the caller, so an mtime read
    back off it is :class:`matrix._ParamikoHandler` agreeing with the request this repo just
    built. That is the fake-confirms-its-author trap, and it would read as a third data point.
    """
    skip_where_the_handler_is_ours(server)
    known_mtime, known_atime = 1_600_000_000, 1_600_000_007
    source = server.root / "dated.bin"
    source.write_bytes(b"payload")
    os.utime(source, (known_atime, known_mtime))
    remote = server.root / "dated-copy.bin"
    local = tmp_path / "dated-back.bin"

    async with connected(server) as sftp:
        result = await sftp.put(source, str(remote), preserve_times=True)
        await sftp.get(str(remote), local, preserve_times=True)

    if result.times is TimePreservation.UNAVAILABLE:
        # The documented fallback: the file is published and correct, only its timestamps are
        # the time of the upload. Asserted rather than tolerated, so a server that starts
        # refusing shows up as a changed answer instead of a silent one.
        assert remote.read_bytes() == b"payload"
        pytest.skip(f"{server.name} refused FSETSTAT for times; degraded as documented")

    assert result.times is TimePreservation.PRESERVED
    assert int(remote.stat().st_mtime) == known_mtime, (
        f"{server.name} answered OK to the FSETSTAT and did not set the mtime"
    )
    # And the download direction, which needs the server to *report* the times it stored.
    assert int(local.stat().st_mtime) == known_mtime


async def test_every_server_reports_a_modification_time_at_all(server: MatrixServer):
    """The precondition for the test above, and for anything keyed on mtime.

    ``times`` is optional in v3 and :func:`~gantry_sftp.session.modified_at` answers ``None``
    when a server omits it. That branch has unit coverage; this measures how hypothetical the
    omission is in the field, which is a different question and the one a caller planning a
    sync actually needs answered.
    """
    probe = server.root / "has-a-time.txt"
    probe.write_bytes(b"x")

    async with connected(server) as sftp:
        entries = await sftp.listdir(str(server.root))

    (entry,) = [e for e in entries if e.name == "has-a-time.txt"]
    assert entry.modified is not None, (
        f"{server.name} sent no ACMODTIME, so nothing keyed on mtime can work against it"
    )
    assert entry.modified.tzinfo is not None, "a naive datetime is the client's clock"

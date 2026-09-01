"""Attribute mutation and links: `chown`, `utime`, `truncate`, `fstat`, `readlink`, `symlink`.

**D-56b**, the half of D-56 left over once D-56a took `mode=` and `chmod` out as a security
item. These six are ergonomics -- nothing here was producing a wrong answer, they simply did not
exist -- with one exception that is not: **`SETSTAT` follows symlinks**, so every method on this
page had to decide what to do about a path an attacker may have replaced with a link. The answer
is `follow_symlinks=False` backed by `lsetstat@openssh.com`, and a **refusal** where the server
will not do it, because v3 has no non-following spelling to fall back to. Degrading would perform
a different operation, on the target the caller was trying to avoid.

Three of the packets these methods send -- `FSTAT`, `READLINK`, `SYMLINK` -- had golden frames
and a wire proof since 0.8 and **no caller at all**. That is the coverage D-36's card said it
could not buy on its own, and it is why the real-server tests below matter more than usual: the
frames were known to be right, and nothing had ever driven them from the API.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    EXTENSION_LSETSTAT,
    MAX_V3_TIMESTAMP,
    Attrs,
    Extended,
    FSetStat,
    Handle,
    Init,
    LSetStat,
    Name,
    NameEntry,
    OpenFlag,
    Owner,
    Status,
    StatusCode,
    Version,
    decode,
    encode,
)
from gantry_sftp.codec import (
    FrameSplitter as Splitter,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    ProtocolError,
    ServerError,
    UnsupportedError,
)
from gantry_sftp.session import open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from local_filesystem import SERVER_CAN_CHMOD_A_SYMLINK

pytestmark = pytest.mark.anyio

KNOWN_MTIME = 1_600_000_000
KNOWN_ATIME = 1_600_000_007

SERVER_CANNOT_CHMOD_A_SYMLINK = not SERVER_CAN_CHMOD_A_SYMLINK
"""The inverse of the shared probe, kept as a name because both markers below read better for it.

**The probe itself moved to `tests/local_filesystem.py` in D-165**, which gave it a third
consumer: the compatibility battery pins what `lsetstat` does against a local server, and that
answer flips on macOS exactly the way these rows do. Two copies of one probe is the shape D-157
was closed on.
"""

needs_a_server_that_cannot_chmod_a_symlink = pytest.mark.skipif(
    not SERVER_CANNOT_CHMOD_A_SYMLINK,
    reason=(
        "this platform's server can chmod a symlink (macOS has lchmod), so there is no refusal "
        "here to carry a note or a path; what it does instead is asserted rather than skipped "
        "past, by the `..._where_the_server_has_lchmod` rows below"
    ),
)
"""For the two tests whose subject is the *refusal* rather than the operation.

**The reason names the rows that run in their place, and that is the correction D-161 made.**
It used to say the macOS behaviour "is D-151's open question, and skipping is a placeholder for
that answer rather than a decision" -- true when it was written, stale from the moment D-151
closed, and behind it a real hole: on a platform with `lchmod` these two calls *succeed* and
nothing asserted what they did. A skip reason that describes an open question is a skip nobody
revisits, because it reads as work already scheduled.
"""

needs_a_server_that_can_chmod_a_symlink = pytest.mark.skipif(
    SERVER_CANNOT_CHMOD_A_SYMLINK,
    reason=(
        "this platform's server has no lchmod (Linux does not), so the success these assert "
        "cannot happen here -- the refusal it produces instead is asserted by the "
        "`..._on_a_linux_server` rows above"
    ),
)
"""The other half of the same fact, so exactly one of each pair runs and neither platform has a
hole. Written as the inverse of the same probe rather than as its own condition: two
independently-spelled predicates can both be false, and the pair would then silently prove
nothing."""

LCHMOD_NOTE = (
    "the server may be refusing because it cannot do this at all: Linux has no lchmod, so "
    "fchmodat(AT_SYMLINK_NOFOLLOW) answers ENOTSUP and OpenSSH maps that to a contentless "
    "FAILURE. A symlink's own permission bits are ignored by the Linux kernel and are always "
    "0o777, so there is nothing to set. The times and owner of a symlink can be set there; the "
    "mode cannot. Pass follow_symlinks=True to change what the link points at, if that is what "
    "you meant."
)
"""Spelled out here rather than imported, which is the only version of this that proves anything.

A test importing the string it asserts on agrees with whatever the source says, including with a
mutation of it. This is the one place in the suite where a `chmod(follow_symlinks=False)` refusal
gets its whole explanation checked, and that explanation is the entire diagnosis: OpenSSH's
`FAILURE` carries no message, so a caller who does not read this note is told nothing at all.
"""


def needs_real_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


def bits(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# --- links ------------------------------------------------------------------------------------


async def test_symlink_creates_the_link_at_the_second_argument(tmp_path: Path):
    """The argument order, which is the one thing here a unit test cannot catch.

    `os.symlink`'s order -- target first, name second -- and the **reverse** of the wire's.
    OpenSSH sends `targetpath` then `linkpath` where the draft specifies the opposite, so a
    method that passed its arguments straight through in the draft's reading would create the
    link under the *target's* name and point it at the name the caller wanted. Asserted by
    checking which of the two paths ended up being the link, not merely that a link exists.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    link = tmp_path / "alias.txt"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.symlink(str(target).encode(), str(link).encode())

    assert link.is_symlink()
    assert not target.is_symlink()
    assert link.readlink() == target


async def test_readlink_returns_the_target(tmp_path: Path):
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    link = tmp_path / "alias.txt"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.readlink(str(link).encode()) == str(target).encode()


async def test_readlink_returns_a_hostile_target_verbatim(tmp_path: Path):
    """A link target is chosen by whoever made the link, and every shape here is legal.

    Nothing is validated because there is nothing to validate against: absolute, climbing, and
    non-UTF-8 are all things a real symlink can point at. The defence is at the *use* site --
    joining one of these onto a local path without a containment check is the zip-slip class --
    and saying so in the docstring is the honest version of a guarantee this method cannot make.
    """
    needs_real_server()
    hostile = b"../../../../etc/shadow\xff\xfe"
    link = tmp_path / "escape"
    link.symlink_to(os.fsdecode(hostile))

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert await sftp.readlink(str(link).encode()) == hostile


async def test_readlink_of_a_plain_file_is_bad_message(tmp_path: Path):
    """The status that reads like a bug in this library and is not.

    `BAD_MESSAGE` says "the frame you sent was malformed". OpenSSH maps `EINVAL` and
    `ENAMETOOLONG` onto it, so it is also how `readlink` says "that is not a link" -- which
    makes it a *filesystem* answer about the caller's path rather than a protocol complaint
    about ours. Pinned because the natural reaction to seeing it is to go looking in the codec.

    The path is asserted as well as the code, and that is not decoration: `readlink` reaches
    this refusal through `_unexpected`, which forwards `path=` into `raise_for_status` only on
    the STATUS branch. Nothing else in this file drives that branch, so without this line the
    argument could be dropped and every remaining test would still pass.
    """
    needs_real_server()
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refusal:
            _ = await sftp.readlink(str(plain).encode())

    assert refusal.value.code == int(StatusCode.BAD_MESSAGE)
    assert refusal.value.path == str(plain).encode()


async def test_a_dangling_target_is_created_without_complaint(tmp_path: Path):
    """Legal, and deliberate in some deployments -- so it is not ours to refuse."""
    needs_real_server()
    link = tmp_path / "pending"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.symlink(b"/not/here/yet", str(link).encode())
        assert await sftp.readlink(str(link).encode()) == b"/not/here/yet"

    assert link.is_symlink()
    assert not link.exists()


# --- fstat ---------------------------------------------------------------------------------------


async def test_fstat_reports_the_open_handle(tmp_path: Path):
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"x" * 1234)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(source).encode())
        try:
            attributes = await sftp.fstat(handle)
        finally:
            await sftp.close(handle)

    assert attributes.size == 1234
    assert attributes.permissions is not None


async def test_fstat_describes_the_file_we_hold_not_the_name(tmp_path: Path):
    """Why the method is worth having rather than being `stat` with extra steps.

    A path can be replaced between the `OPEN` and a `STAT` -- which is the whole shape of a
    swap attack. The handle cannot: it refers to the file this session opened. Demonstrated by
    replacing the name with a different file and asking both ways.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"x" * 100)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(source).encode())
        try:
            source.unlink()
            source.write_bytes(b"y" * 7)
            by_handle = await sftp.fstat(handle)
            by_name = await sftp.stat(str(source).encode())
        finally:
            await sftp.close(handle)

    assert by_handle.size == 100
    assert by_name.size == 7


async def test_fstat_of_an_unknown_handle_is_refused(tmp_path: Path):
    needs_real_server()
    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError):
            _ = await sftp.fstat(b"\xde\xad\xbe\xef")


# --- truncate ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("size", "expected"),
    [(4, b"payl"), (0, b""), (9, b"payload\x00\x00")],
    ids=["shrink", "empty", "grow"],
)
async def test_truncate_sets_the_length(tmp_path: Path, size: int, expected: bytes):
    """Including the grow case, which zero-fills rather than failing -- `truncate(2)`'s shape."""
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.truncate(str(target).encode(), size)

    assert target.read_bytes() == expected


# --- utime ---------------------------------------------------------------------------------------


async def test_utime_sets_both_times(tmp_path: Path):
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.utime(str(target).encode(), KNOWN_ATIME, KNOWN_MTIME)

    assert int(target.stat().st_mtime) == KNOWN_MTIME
    assert int(target.stat().st_atime) == KNOWN_ATIME


async def test_a_timestamp_that_does_not_fit_is_refused_rather_than_truncated(tmp_path: Path):
    """v3 carries uint32 seconds, and the dates that reach the ceiling are set deliberately.

    Retention and legal-hold systems set far-future mtimes on purpose, so wrapping one is worse
    than refusing it -- the file would come back dated in the past and look entirely plausible.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ValueError):
            await sftp.utime(str(target).encode(), KNOWN_ATIME, MAX_V3_TIMESTAMP + 1)


# --- chown ---------------------------------------------------------------------------------------


async def test_chown_to_the_current_owner_succeeds(tmp_path: Path):
    """The only chown an unprivileged test can make, and it still proves the frame.

    Changing a file's owner is root's privilege on every ordinary Unix server, so a test that
    actually moved a file between users would need a privileged runner. Setting the ids a file
    already has exercises the same `UIDGID` flag and the same `chown(2)` call, and answers `OK`.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    before = target.stat()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chown(str(target).encode(), before.st_uid, before.st_gid)
        attributes = await sftp.stat(str(target).encode())

    assert attributes.owner == Owner(uid=before.st_uid, gid=before.st_gid)


async def test_chown_to_another_user_is_refused(tmp_path: Path):
    """The common answer, and worth pinning so the message is not read as our bug.

    Skipped when running as root, where it would succeed -- a test that cannot fail on the
    runner it is on is worse than one that says why it did not run.
    """
    needs_real_server()
    if os.geteuid() == 0:
        pytest.skip("running as root, where chown to another user succeeds")
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError):
            await sftp.chown(str(target).encode(), 0, 0)


# --- the symlink question, which is the security content ------------------------------------------


async def test_by_default_these_follow_a_symlink(tmp_path: Path):
    """Characterisation, and the reason `follow_symlinks=False` exists.

    `SETSTAT` is `chmod(2)`/`utimes(2)`/`chown(2)` on a path and all three follow, so pointing
    any of them at a link somebody else planted operates on whatever it points at. Pinned rather
    than described, because it is the behaviour a reader is most likely to assume away.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    target.chmod(0o644)
    link = tmp_path / "alias.txt"
    link.symlink_to(target)
    # **Read before, compared after, rather than spelled as a constant.** This used to assert
    # `0o777`, which is a Linux fact stated as a universal one: a symlink's permission bits are
    # meaningless to the Linux kernel and permanently `0o777`, so there was nothing to capture.
    # On macOS they are real -- which is *why* it has `lchmod` and Linux does not -- and a fresh
    # link gets `0o777 & ~umask`, so the first macOS CI run read `0o755` and reported
    # `assert 493 == 511`. The claim being made here is that the operation followed the link and
    # did not touch the link, and that is what a before-and-after comparison says on either.
    before = bits(link)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chmod(str(link).encode(), 0o600)

    assert bits(target) == 0o600
    assert bits(link) == before, "chmod touched the link's own mode instead of its target's"


@needs_a_server_that_cannot_chmod_a_symlink
async def test_chmod_of_a_symlink_is_impossible_on_a_linux_server(tmp_path: Path):
    """Found by writing this test expecting it to pass. **Linux has no `lchmod`.**

    `lsetstat@openssh.com` is advertised, is implemented, and its permissions branch calls
    `fchmodat(AT_FDCWD, name, mode, AT_SYMLINK_NOFOLLOW)` -- which on Linux answers `ENOTSUP`,
    measured here at the syscall level (errno 95) and not inferred. `utimensat` and `fchownat`
    with the same flag both succeed, so this is specific to the mode: a symlink's permission
    bits are meaningless to the Linux kernel, always read `0o777`, and cannot be set.

    So the extension being *present* does not make `chmod(follow_symlinks=False)` work, and the
    answer arrives as OpenSSH's contentless `FAILURE`. It propagates rather than degrading --
    an advertised extension refusing is telling us about this operation -- and it carries a note
    saying why, because "Failure" alone sends a reader to look at the codec.

    **The property that matters is asserted either way**: the target was not touched. Refusing
    to do the thing the caller asked to avoid is the whole point of the argument.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    target.chmod(0o644)
    link = tmp_path / "alias.txt"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.supports(EXTENSION_LSETSTAT)
        with pytest.raises(ServerError) as refusal:
            await sftp.chmod(str(link).encode(), 0o600, follow_symlinks=False)

    assert refusal.value.code == int(StatusCode.FAILURE)
    assert refusal.value.__notes__ == [LCHMOD_NOTE]
    assert refusal.value.path == str(link).encode()
    assert bits(target) == 0o644


@needs_a_server_that_can_chmod_a_symlink
async def test_chmod_of_a_symlink_changes_only_the_link_where_the_server_has_lchmod(
    tmp_path: Path,
):
    """D-151's last open question, asserted on the platform that can answer it.

    The card closed asking one thing it could not settle: on a server whose kernel *has*
    `lchmod`, does `follow_symlinks=False` genuinely change the link's own mode, or does it
    succeed and change nothing? **A success that does nothing is worse than the Linux
    refusal** -- a caller hardening a path against a planted symlink would be told the
    operation happened.

    It happens. Measured on macOS at all three layers before it was written down: the syscall,
    `lsetstat@openssh.com` through this library at a local `sftp-server`, and the neighbouring
    `chown` and `utime` -- so a difference here could be attributed rather than guessed at.

    **Both halves are asserted, and the second is the one with teeth.** The link moved, *and*
    the target did not: an implementation that quietly sent `SETSTAT` instead would satisfy the
    first alone, on exactly the file the caller was avoiding.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    target.chmod(0o644)
    link = tmp_path / "alias.txt"
    link.symlink_to(target)
    # Read rather than spelled, for the reason `test_by_default_these_follow_a_symlink` states:
    # a fresh link's own mode is `0o777 & ~umask` here, and umask is the runner's business.
    before = bits(link)
    assert before != 0o600, "the mode this asks for has to be a change, or nothing is proven"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.supports(EXTENSION_LSETSTAT)
        await sftp.chmod(str(link).encode(), 0o600, follow_symlinks=False)

    assert bits(link) == 0o600, "the extension returned OK and the link's mode did not move"
    assert bits(target) == 0o644, "chmod reached the target the caller was avoiding"


async def test_utime_can_also_leave_the_target_alone(tmp_path: Path):
    """The same routing, a different flag -- so the helper is not proven by `chmod` alone."""
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    os.utime(target, (KNOWN_ATIME, KNOWN_MTIME))
    link = tmp_path / "alias.txt"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.utime(str(link).encode(), 1, 2, follow_symlinks=False)

    assert int(target.stat().st_mtime) == KNOWN_MTIME
    assert int(os.lstat(link).st_mtime) == 2


async def test_lsetstat_refuses_a_size_which_is_why_truncate_has_no_such_parameter(
    tmp_path: Path,
):
    """The premise of a decision, asserted instead of quoted.

    `truncate` has no `follow_symlinks=` because the extension every other method here uses for
    that case rejects `SIZE` outright -- `/* nonsensical for links */` in
    `process_extended_lsetstat`, answered as `BAD_MESSAGE`. A parameter that could only ever
    fail would be worse than not having one, and this is what makes that claim checkable rather
    than a comment citing source somebody would have to go and read.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    link = tmp_path / "alias.txt"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        request = LSetStat(sftp._next(), str(link).encode(), Attrs(size=4))  # noqa: SLF001
        reply = await sftp.request(request.to_extended())

    assert reply.code is StatusCode.BAD_MESSAGE  # type: ignore[union-attr]
    assert target.read_bytes() == b"payload"


async def test_a_server_without_lsetstat_refuses_rather_than_following(tmp_path: Path):
    """The degradation decision, and it is the opposite of every other extension here.

    Everywhere else an absent extension means a documented fallback. Here the fallback would be
    to perform the operation on the link's *target* -- exactly what the caller asked not to do
    -- so there is nothing to degrade to and the answer is a `CapabilityError` naming what is
    missing. Driven by exhausting the session's own refusal cache first, so this is the shape a
    real server without the extension produces rather than a mock of one.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    target.chmod(0o644)
    link = tmp_path / "alias.txt"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        # Poison the cache the way an OP_UNSUPPORTED would, without needing a server that
        # lacks the extension: `refuses()` is the one question `_set_one_attribute` asks.
        sftp._unsupported.add(EXTENSION_LSETSTAT.encode("ascii"))  # noqa: SLF001
        with pytest.raises(CapabilityError) as refusal:
            await sftp.chmod(str(link).encode(), 0o600, follow_symlinks=False)

    assert refusal.value.missing == (EXTENSION_LSETSTAT,)
    assert "filexfer v3 has no other way to chmod a symlink" in refusal.value.args[0]
    # The note names the peer, **including how many extensions it advertised**, and the count
    # was unpinned everywhere until a mutation run replaced it with `None` (D-146). `sftp-server`
    # advertises a known set, so the number is a fact about the server rather than about this
    # test -- read off the session, and compared against the count the fixture list carries.
    note = "\n".join(refusal.value.__notes__)
    assert note == (
        f"the server identifies as openssh (OpenSSH sftp-server) and advertises "
        f"{len(sftp.extensions)} extension(s)"
    )
    assert len(sftp.extensions) >= 6, "a count asserted against zero would pin nothing"
    # And the point of refusing: the target was not touched.
    assert bits(target) == 0o644


# --- one flag per call ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("call", "expected_flag"),
    [
        (lambda sftp, path: sftp.chmod(path, 0o600), "permissions"),
        (lambda sftp, path: sftp.utime(path, 1, 2), "times"),
        (lambda sftp, path: sftp.truncate(path, 0), "size"),
        (lambda sftp, path: sftp.chown(path, os.getuid(), os.getgid()), "owner"),
    ],
    ids=["chmod", "utime", "truncate", "chown"],
)
async def test_each_mutation_sends_exactly_one_attribute_flag(
    tmp_path: Path, call, expected_flag: str
):
    """The rule D-56a established, enforced across every method that inherited it.

    `process_setstat` applies the flags in sequence and reports one status, so a multi-field
    call that fails has already applied part of itself and does not say which part. A test per
    method rather than a comment per method, because the cost of getting it wrong is invisible
    until a server refuses one field of four.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    sent: list[object] = []

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        original = sftp.request

        async def recording(request):
            sent.append(request)
            return await original(request)

        sftp.request = recording  # type: ignore[method-assign]
        await call(sftp, str(target).encode())

    mutations = [packet for packet in sent if hasattr(packet, "attrs")]
    assert len(mutations) == 1
    attrs = mutations[0].attrs  # type: ignore[union-attr]
    present = [
        name
        for name in ("size", "owner", "permissions", "times")
        if getattr(attrs, name) is not None
    ]
    assert present == [expected_flag]


# --- what a refusal carries, which is the half that was not asserted ------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda sftp, path: sftp.chmod(path, 0o600),
        lambda sftp, path: sftp.chown(path, os.getuid(), os.getgid()),
        lambda sftp, path: sftp.utime(path, KNOWN_ATIME, KNOWN_MTIME),
        lambda sftp, path: sftp.truncate(path, 0),
    ],
    ids=["chmod", "chown", "utime", "truncate"],
)
async def test_a_refusal_names_the_path_it_concerned(tmp_path: Path, call):
    """The state rather than the sentence, on every method that raises one.

    `ServerError.path` is what makes a refusal answerable -- a `put_tree` fanning out over a
    thousand names produces a `NO_SUCH_FILE` that means nothing without it. Every method here
    passed it and nothing looked, so dropping the argument left a message that still read
    correctly and an error that no longer said which file. That is the shape D-105 has found in
    five consecutive slices: the prose half tested, the carried half not, and the half that was
    done making the other look finished.
    """
    needs_real_server()
    missing = tmp_path / "not-here.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(NoSuchFileError) as refusal:
            await call(sftp, str(missing).encode())

    assert refusal.value.path == str(missing).encode()


async def test_a_refused_symlink_names_the_link_it_did_not_create(tmp_path: Path):
    """And it names the *link*, not the target, which is the argument this method reverses.

    `symlink(target, link_path)` takes the arguments in `os.symlink`'s order and sends them in
    the opposite one, so "which of the two paths does the error name" is a question this method
    has a real chance of getting wrong. The link is the right answer: the target is a string
    being stored, and the path the server refused is the name it would not create.
    """
    needs_real_server()
    link = tmp_path / "no-such-directory" / "alias.txt"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(NoSuchFileError) as refusal:
            await sftp.symlink(b"/wherever", str(link).encode())

    assert refusal.value.path == str(link).encode()


@pytest.mark.parametrize(
    ("call", "operation"),
    [
        (lambda sftp, path: sftp.chmod(path, 0o600, follow_symlinks=False), "chmod"),
        (
            lambda sftp, path: sftp.chown(path, os.getuid(), os.getgid(), follow_symlinks=False),
            "chown",
        ),
        (lambda sftp, path: sftp.utime(path, 1, 2, follow_symlinks=False), "utime"),
    ],
    ids=["chmod", "chown", "utime"],
)
async def test_the_capability_refusal_names_the_operation_the_caller_asked_for(
    tmp_path: Path, call, operation: str
):
    """One helper serves three methods, and each passes its own name into the message.

    `_set_one_attribute` builds the `CapabilityError` and takes `operation=` from the caller,
    so the sentence a `chown` produces is assembled from a string `chown` alone supplies. Only
    the `chmod` spelling had ever been checked, which left the other two forwarding a value
    nothing read -- they could have passed each other's name, or none.

    The structured fields are asserted beside the message for the reason the message exists:
    `feature` and `path` are what a caller branches on, and neither was pinned anywhere.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    link = tmp_path / "alias.txt"
    link.symlink_to(target)
    encoded = str(link).encode()

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        # The same cache poisoning `test_a_server_without_lsetstat_...` uses: the shape a
        # server without the extension produces, without needing one.
        sftp._unsupported.add(EXTENSION_LSETSTAT.encode("ascii"))  # noqa: SLF001
        with pytest.raises(CapabilityError) as refusal:
            await call(sftp, encoded)

    assert refusal.value.args[0] == (
        f"follow_symlinks=False needs {EXTENSION_LSETSTAT}, which this server will not perform, "
        f"and filexfer v3 has no other way to {operation} a symlink without following it. "
        f"Passing follow_symlinks=True would {operation} whatever {encoded!r} points at, which "
        f"is a different operation"
    )
    assert refusal.value.feature == f"{operation} without following a symlink"
    assert refusal.value.path == encoded
    assert refusal.value.missing == (EXTENSION_LSETSTAT,)


@needs_a_server_that_cannot_chmod_a_symlink
async def test_the_non_following_refusal_also_names_the_path(tmp_path: Path):
    """The other branch of the same helper, and it needs its own test.

    `_set_one_attribute` sends `SETSTAT` or `LSETSTAT` depending on `follow_symlinks`, and each
    passes `path=` separately. A test that only ever follows proves one of the two, so the
    non-following branch could stop naming the path with nothing failing -- on the branch where
    the caller is being careful about *which* file is touched, which is where knowing the name
    matters most.
    """
    needs_real_server()
    target = tmp_path / "real.txt"
    target.write_bytes(b"payload")
    link = tmp_path / "alias.txt"
    link.symlink_to(target)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(ServerError) as refusal:
            await sftp.chmod(str(link).encode(), 0o600, follow_symlinks=False)

    assert refusal.value.path == str(link).encode()


@needs_a_server_that_can_chmod_a_symlink
async def test_the_non_following_refusal_also_names_the_path_where_the_server_has_lchmod(
    tmp_path: Path,
):
    """The same claim as the row above, through the refusal this platform actually produces.

    `_set_one_attribute` passes `path=` into the `LSETSTAT` branch separately from the
    `SETSTAT` one, so the non-following branch can stop naming the path with every following
    test still green. That is worth proving on **both** platforms, and the Linux spelling
    cannot run here: the mode branch succeeds, so a link is the one argument that will not
    produce an error at all.

    A path that is not there is what is left, and it is not a lesser proof -- the missing-file
    refusal is the only one this branch has on a server with `lchmod`, which makes it the one a
    Mac-hosted endpoint's users will actually see.
    """
    needs_real_server()
    missing = tmp_path / "not-here.txt"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.supports(EXTENSION_LSETSTAT), "otherwise this refusal is the capability one"
        with pytest.raises(NoSuchFileError) as refusal:
            await sftp.chmod(str(missing).encode(), 0o600, follow_symlinks=False)

    assert refusal.value.path == str(missing).encode()


# --- ftruncate's boundary -------------------------------------------------------------------------


async def test_ftruncate_to_zero_empties_the_open_file(tmp_path: Path):
    """Zero is the common call and it was the untested one.

    `if size < 0` is one character from `if size <= 0`, and a suite that only truncates to a
    positive length cannot tell the two apart -- while "empty this file" is what a caller
    holding a write handle asks for most often. The refusal it would produce arrives as a
    `ValueError` about a negative size for a size that is not negative.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(target).encode(), OpenFlag.WRITE)
        try:
            await sftp.ftruncate(handle, 0)
        finally:
            await sftp.close(handle)

    assert target.read_bytes() == b""


async def test_ftruncate_refuses_a_negative_size_before_sending_anything(tmp_path: Path):
    """Local, and the message carries the value -- a bare "must not be negative" is unfixable.

    Refused here rather than by the server because `SIZE` is a `uint64` on the wire: a negative
    length has no encoding, so this cannot become a refusal we forward. The server never sees a
    frame, which is asserted rather than assumed.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    sent: list[object] = []

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(target).encode(), OpenFlag.WRITE)
        original = sftp.request

        async def recording(request):
            sent.append(request)
            return await original(request)

        sftp.request = recording  # type: ignore[method-assign]
        try:
            with pytest.raises(ValueError) as refusal:
                await sftp.ftruncate(handle, -1)
        finally:
            sftp.request = original  # type: ignore[method-assign]
            await sftp.close(handle)

    assert refusal.value.args[0] == "size must not be negative, got -1"
    assert not [packet for packet in sent if isinstance(packet, FSetStat)]
    assert target.read_bytes() == b"payload"


# --- a reply of the wrong shape ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (lambda sftp, path, handle: sftp.stat(path), "ATTRS"),
        (lambda sftp, path, handle: sftp.lstat(path), "ATTRS"),
        (lambda sftp, path, handle: sftp.fstat(handle), "ATTRS"),
        (lambda sftp, path, handle: sftp.readlink(path), "NAME"),
    ],
    ids=["stat", "lstat", "fstat", "readlink"],
)
@pytest.mark.parametrize("shape", ["handle", "status"])
async def test_a_reply_of_the_wrong_shape_names_what_was_expected(
    tmp_path: Path, call, expected: str, shape: str
):
    """Four methods, one helper, and the name of the packet they wanted is per-method data.

    A server answering a `STAT` with a `HANDLE` is not refusing, it is unintelligible, and the
    error has to say what was due or a reader cannot tell which end is wrong. Every one of these
    four passes that string as a literal and none of them was checked, so all four could have
    said the same thing, or nothing.

    **Both shapes, because `_unexpected` has two branches.** A `STATUS OK` where a result was due
    is a server claiming success while withholding the answer; any other packet is a server we
    cannot parse. They produce different sentences and both carry the request id, which is the
    only handle an operator has on *which* exchange went wrong when several are in flight.

    Driven by replacing `request` on a session talking to a real server, rather than by a fake:
    everything up to the reply is the shipped path, and a server that answers the wrong packet
    type on demand is not a server anybody can be asked for.
    """
    needs_real_server()
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"payload")
    seen_ids: list[int] = []

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(plain).encode())
        original = sftp.request

        async def wrong_shape(request):
            seen_ids.append(request.request_id)
            if shape == "handle":
                return Handle(request.request_id, b"nonsense")
            return Status(request.request_id, StatusCode.OK)

        sftp.request = wrong_shape  # type: ignore[method-assign]
        try:
            with pytest.raises(ProtocolError) as confusion:
                await call(sftp, str(plain).encode(), handle)
        finally:
            sftp.request = original  # type: ignore[method-assign]
            await sftp.close(handle)

    rendered = "Handle" if shape == "handle" else "STATUS OK"
    assert confusion.value.args[0] == (
        f"server answered with {rendered} where {expected} was expected"
    )
    assert confusion.value.request_id == seen_ids[-1]


async def test_readlink_refuses_a_name_carrying_any_count_but_one(tmp_path: Path):
    """A link has exactly one target, so a count that is not one is a server we do not understand.

    The same strictness `realpath` applies, and for the same reason: `send_names` sends one, and
    where the draft and the reference implementation agree there is nothing to be lenient
    towards. Taking `entries[0]` from a two-name reply would be picking one of the server's
    answers and calling it the target.
    """
    needs_real_server()
    link = tmp_path / "alias.txt"
    link.symlink_to(tmp_path / "real.txt")
    encoded = str(link).encode()
    seen_ids: list[int] = []

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        original = sftp.request

        async def two_names(request):
            seen_ids.append(request.request_id)
            entry = NameEntry(filename=b"first", longname=b"first", attrs=Attrs())
            return Name(request.request_id, (entry, entry))

        sftp.request = two_names  # type: ignore[method-assign]
        try:
            with pytest.raises(ProtocolError) as confusion:
                _ = await sftp.readlink(encoded)
        finally:
            sftp.request = original  # type: ignore[method-assign]

    assert confusion.value.args[0] == (
        f"READLINK of {encoded!r} answered with 2 names, and a link has exactly one target"
    )
    assert confusion.value.request_id == seen_ids[-1]


# --- the `f` twins and the two degrading spellings (D-146) ---------------------------------------


async def test_fchmod_sets_the_mode_of_the_file_we_hold_not_the_name(tmp_path: Path):
    """The argument for the method existing, and it is `fstat`'s argument in the other direction.

    A caller holding an open file who chmods it *by name* is chmodding whatever the name refers
    to now. Staged here the same way `test_fstat_describes_the_file_we_hold_not_the_name` stages
    it: replace the name after opening, then set the mode through the handle and observe that
    the *replacement* is untouched.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"x" * 100)
    source.chmod(0o644)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(source).encode(), OpenFlag.WRITE)
        try:
            held = tmp_path / "moved-away.bin"
            source.rename(held)
            source.write_bytes(b"y")
            source.chmod(0o644)
            await sftp.fchmod(handle, 0o600)
        finally:
            await sftp.close(handle)

    assert bits(held) == 0o600
    assert bits(source) == 0o644


async def test_futime_sets_both_times_of_an_open_handle(tmp_path: Path):
    """`utime`'s twin. The times cannot ride along on the OPEN, which is why this is reached for."""
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(target).encode(), OpenFlag.WRITE)
        try:
            await sftp.futime(handle, KNOWN_ATIME, KNOWN_MTIME)
        finally:
            await sftp.close(handle)

    assert int(target.stat().st_mtime) == KNOWN_MTIME
    assert int(target.stat().st_atime) == KNOWN_ATIME


async def test_a_timestamp_that_does_not_fit_is_refused_by_the_handle_form_too(tmp_path: Path):
    """The same refusal as `utime`'s, at the same place -- the encoder -- and it is worth pinning.

    Both spellings build the ATTRS the same way, so this could only diverge by one of them
    growing a check the other did not. The value is one past the field's ceiling.
    """
    needs_real_server()
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(target).encode(), OpenFlag.WRITE)
        try:
            with pytest.raises(ValueError) as refusal:
                await sftp.futime(handle, KNOWN_ATIME, MAX_V3_TIMESTAMP + 1)
        finally:
            await sftp.close(handle)

    assert refusal.value.args[0].startswith(
        f"mtime {MAX_V3_TIMESTAMP + 1} does not fit filexfer v3's uint32 seconds field"
    )


class _ScriptedServer:
    """A transport that answers each request from one function. Boilerplate, factored once.

    The tests below need shapes a real `sftp-server` will not make on demand -- an `FSETSTAT`
    it refuses, an `OP_UNSUPPORTED` for an extension it implements, and a refusal of
    `lsetstat` under a status the host kernel will not produce -- and the framing around that
    answer is identical every time.

    `extensions` is what the VERSION advertises, and it is not decoration:
    `_attempt_extension` propagates a refusal only from a server that advertised the extension
    and swallows it into the fallback otherwise, so a test about what a *refusal* carries has
    to say the server offered the thing it refused.
    """

    def __init__(self, answer, extensions: tuple[tuple[bytes, bytes], ...] = ()) -> None:
        self._answer = answer
        self._extensions = extensions
        self._splitter = Splitter()
        self._pending: list[bytes] = []
        self._has_output = anyio.Event()
        self._outbox = bytearray()
        self.asked = 0

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            packet = decode(frame)
            if isinstance(packet, Init):
                self._queue(encode(Version(3, self._extensions)))
                continue
            self.asked += 1
            self._queue(self._answer(packet))

    def _queue(self, frame: bytes) -> None:
        self._pending.append(frame)
        self._has_output.set()

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._outbox:
            await self._has_output.wait()
            batch, self._pending = self._pending, []
            self._has_output = anyio.Event()
            for frame in batch:
                self._outbox += frame
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        return chunk

    async def aclose(self) -> None:
        return


@pytest.mark.parametrize(
    ("call", "arguments"),
    [("fchmod", (0o600,)), ("futime", (KNOWN_ATIME, KNOWN_MTIME))],
)
async def test_the_handle_forms_name_the_path_they_were_given_when_the_server_refuses(
    call: str, arguments: tuple[int, ...]
):
    """A handle is meaningless in an error message, so the caller supplies the name for it.

    Load-bearing on the atomic publish path, where the name that *would* be printed by default
    is the destination -- a file nothing was ever published under. Driven against a scripted
    server because a real one accepts the call.

    **Parametrised over both forms because the first version of this covered only `fchmod`**,
    and a mutation run then found `futime`'s `path=` replaceable with `None` with the suite
    green (D-146). The two carry the same argument for the same reason and were written in the
    same change; testing one of a symmetric pair is how the other keeps its hole.
    """
    server = _ScriptedServer(
        lambda packet: encode(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"nope"))
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as refusal:
            await getattr(sftp, call)(b"\x00\x00\x00\x00", *arguments, path=b"/staging.tmp.9f")

    assert refusal.value.path == b"/staging.tmp.9f"


@pytest.mark.parametrize(
    ("code", "message", "explained"),
    [
        (StatusCode.FAILURE, b"", True),
        (StatusCode.NO_SUCH_FILE, b"No such file", False),
        (StatusCode.PERMISSION_DENIED, b"Permission denied", False),
    ],
    ids=["failure", "no-such-file", "permission-denied"],
)
async def test_only_the_contentless_failure_gets_the_lchmod_explanation(
    code: StatusCode, message: bytes, explained: bool
):
    """The note answers "why does this say nothing", so a status that speaks must not carry it.

    **A bug, found by running this suite on a Mac** (D-161). `_set_one_attribute` attached the
    `lchmod` paragraph to *every* `ServerError` from the non-following branch whenever the flag
    was `PERMISSIONS` -- so a `NO_SUCH_FILE` that had already said `No such file` arrived with a
    page about a kernel call that was never reached, naming Linux on a server that may not be
    running it. Nothing caught it because the only row asserting the note asserted the case
    where it belongs.

    Scripted rather than real, and that is the point: the three statuses have to be produced on
    demand, on any platform, because which of them a host *can* produce is precisely the
    platform difference this file is full of. The server advertises `lsetstat@openssh.com`,
    without which `_attempt_extension` would swallow the refusal into the capability fallback
    and this would test the wrong branch.
    """
    server = _ScriptedServer(
        lambda packet: encode(Status(packet.request_id, code, message)),
        extensions=((EXTENSION_LSETSTAT.encode("ascii"), b"1"),),
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as refusal:
            await sftp.chmod(b"/alias.txt", 0o600, follow_symlinks=False)

    assert refusal.value.code == int(code)
    assert refusal.value.path == b"/alias.txt"
    assert getattr(refusal.value, "__notes__", []) == ([LCHMOD_NOTE] if explained else [])


async def test_the_lchmod_explanation_is_for_the_mode_alone_not_every_field():
    """`chown` and `utime` reach the same `except`, and the note would be wrong for both.

    `utimensat` and `fchownat` take `AT_SYMLINK_NOFOLLOW` on Linux and work, so a refusal of
    those is never the missing `lchmod` -- which is why the note is behind
    `attrs.permissions is not None` rather than behind the branch. The two conditions are
    separate and only one of them had a test.
    """
    server = _ScriptedServer(
        lambda packet: encode(Status(packet.request_id, StatusCode.FAILURE, b"")),
        extensions=((EXTENSION_LSETSTAT.encode("ascii"), b"1"),),
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ServerError) as refused_utime:
            await sftp.utime(b"/alias.txt", 1, 2, follow_symlinks=False)
        with pytest.raises(ServerError) as refused_chown:
            await sftp.chown(b"/alias.txt", 0, 0, follow_symlinks=False)

    assert not hasattr(refused_utime.value, "__notes__")
    assert not hasattr(refused_chown.value, "__notes__")


@pytest.mark.parametrize(
    ("call", "advertised"),
    [
        ("fsync_if_supported", b"fsync@openssh.com"),
        ("posix_rename_if_supported", b"posix-rename@openssh.com"),
    ],
)
async def test_the_degrading_spellings_answer_true_against_a_server_that_has_it(
    tmp_path: Path, call: str, advertised: bytes
):
    """`sftp-server` implements both, so the honest answer here is `True` rather than a fallback.

    The pair exists so a caller doing their own publishing can ask "did that happen?" without
    writing the catch-and-remember themselves. A version that always returned `False` would be
    indistinguishable from a server that lacks the extension, and every caller would silently
    take the fallback -- which for the rename means a window with no file at all.
    """
    needs_real_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.supports(advertised), "this server was expected to advertise it"
        if call == "fsync_if_supported":
            handle = await sftp.open(str(source).encode(), OpenFlag.WRITE)
            try:
                assert await sftp.fsync_if_supported(handle) is True
            finally:
                await sftp.close(handle)
        else:
            target = tmp_path / "target.bin"
            target.write_bytes(b"older")
            assert await sftp.posix_rename_if_supported(str(source).encode(), str(target).encode())
            assert target.read_bytes() == b"payload"
            assert not source.exists()


@pytest.mark.parametrize(
    "call", ["fsync_if_supported", "posix_rename_if_supported"], ids=["fsync", "posix-rename"]
)
async def test_the_degrading_spellings_answer_false_and_remember_it(call: str):
    """`False` rather than an exception, once, and then without a round trip.

    The remembering is the half worth sharing and the half a caller would get wrong: an
    `OP_UNSUPPORTED` is a definitive answer about the *server*, so a tree of a thousand files
    asks once. Counted rather than asserted in prose -- a version that did not cache would pass
    every behavioural test and cost a round trip per file.
    """
    server = _ScriptedServer(
        lambda packet: encode(Status(packet.request_id, StatusCode.OP_UNSUPPORTED))
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        arguments = (b"\x00\x00\x00\x00",) if call == "fsync_if_supported" else (b"/a", b"/b")
        assert await getattr(sftp, call)(*arguments) is False
        assert await getattr(sftp, call)(*arguments) is False

    assert server.asked == 1, "the second call asked again rather than reading the cache"


# --- an OP_UNSUPPORTED from a server that advertised the extension (D-205) ------------------


def _answer_unsupported(packet, reason: bytes = b"") -> bytes:
    return encode(Status(packet.request_id, StatusCode.OP_UNSUPPORTED, reason))


@pytest.mark.parametrize(
    "call", ["fsync_if_supported", "posix_rename_if_supported"], ids=["fsync", "posix-rename"]
)
async def test_the_degrading_spellings_ask_again_when_an_advertised_server_declines(call: str):
    """The same answer from a server that *advertised* the extension is not remembered.

    Advertisement is the server saying it implements the extension, so an `OP_UNSUPPORTED`
    from it is about this handle or this rename rather than about the server, and remembering
    it would answer every later call from a cache the server never spoke to. The cost is one
    round trip per declined call, counted so a version that cached it fails here.
    """
    server = _ScriptedServer(
        _answer_unsupported,
        extensions=((b"fsync@openssh.com", b"1"), (b"posix-rename@openssh.com", b"1")),
    )
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        arguments = (b"\x00\x00\x00\x00",) if call == "fsync_if_supported" else (b"/a", b"/b")
        assert await getattr(sftp, call)(*arguments) is False
        assert await getattr(sftp, call)(*arguments) is False
        assert not sftp.refuses("fsync@openssh.com")
        assert not sftp.refuses("posix-rename@openssh.com")

    assert server.asked == 2, "the second call read a cache for an answer about one request"


def _asyncssh_with_its_827_fix() -> _ScriptedServer:
    """asyncssh's server with the #827 patch applied, as measured by hand on 2026-09-01.

    It advertises `lsetstat@openssh.com`. A mode change on the symlink `/link` is declined with
    `OP_UNSUPPORTED` and a reason naming the attribute; the same request on a regular file, and
    the times of the same link, are performed. Nothing on the wire says "extension absent"
    except the code, which is exactly what a client keyed on the code got wrong.
    """

    def answer(packet) -> bytes:
        if isinstance(packet, Extended) and packet.name == EXTENSION_LSETSTAT.encode("ascii"):
            request = LSetStat.from_extended(packet)
            if request.attrs.permissions is not None and request.path == b"/link":
                return _answer_unsupported(packet, b"setting permissions on a symlink")
        return encode(Status(packet.request_id, StatusCode.OK))

    return _ScriptedServer(answer, extensions=((EXTENSION_LSETSTAT.encode("ascii"), b"1"),))


DECLINED_NOTE = (
    "this server advertises lsetstat@openssh.com and declined the chmod of this path without "
    "following it; that is an answer about this request rather than about the server, so it is "
    "not remembered, and the other attribute flags and other paths are still attempted"
)


async def test_a_server_that_advertises_lsetstat_and_declines_the_mode_still_sets_the_times():
    """D-205, the client half. Filed from reviewing the maintainer's patch on asyncssh#827.

    Keyed by extension, the first `chmod` of a link recorded `lsetstat` as refused and every
    later `utime` on a link was refused from the cache with no round trip, though the server
    performs it -- and so was `chmod` on a regular file, which keying by *flag* would not have
    fixed either. The rule that does: an `OP_UNSUPPORTED` from a server that advertised the
    extension is about the request. It propagates as the server's own refusal, carrying the
    reason the server gave and a note saying what kind of answer it is, and nothing is
    remembered. Every request below is a round trip, and the count is the assertion that
    none of them read a cache.
    """
    server = _asyncssh_with_its_827_fix()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(UnsupportedError) as declined:
            await sftp.chmod(b"/link", 0o600, follow_symlinks=False)
        assert declined.value.args[0] == (
            "server returned OP_UNSUPPORTED: setting permissions on a symlink"
        )
        assert declined.value.code == StatusCode.OP_UNSUPPORTED
        assert declined.value.message == b"setting permissions on a symlink"
        assert declined.value.path == b"/link"
        assert declined.value.__notes__ == [DECLINED_NOTE]
        assert not sftp.refuses(EXTENSION_LSETSTAT)

        # The flags the same server performs, on the same link and on a regular file.
        await sftp.utime(b"/link", KNOWN_ATIME, KNOWN_MTIME, follow_symlinks=False)
        await sftp.chmod(b"/regular", 0o600, follow_symlinks=False)
        # And the declined one again: declined again, by the server rather than by a cache.
        with pytest.raises(UnsupportedError):
            await sftp.chmod(b"/link", 0o600, follow_symlinks=False)
        assert not sftp.refuses(EXTENSION_LSETSTAT)

    assert server.asked == 4, "a call was answered from a cache rather than by the server"


async def test_the_outcome_does_not_depend_on_which_flag_was_sent_first():
    """The ordering proof the card asked for: times-then-mode ends where mode-then-times did.

    Before the fix a session that happened to chmod a link first lost `utime` on links for the
    rest of its life, and one that happened to utime first kept it. Same server, both orders,
    same end state: the times are set and the mode is declined, each answered by the server.
    """
    server = _asyncssh_with_its_827_fix()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.utime(b"/link", KNOWN_ATIME, KNOWN_MTIME, follow_symlinks=False)
        with pytest.raises(UnsupportedError):
            await sftp.chmod(b"/link", 0o600, follow_symlinks=False)
        await sftp.utime(b"/link", KNOWN_ATIME, KNOWN_MTIME, follow_symlinks=False)

    assert server.asked == 3


async def test_an_unadvertised_lsetstat_answering_unsupported_is_remembered():
    """The half that must not change: a server without the extension is asked once.

    The control for the rows above. Same code on the wire, no advertisement, and the answer is
    about the server: a `CapabilityError` naming what is missing, and the second call costs no
    round trip. A rule that stopped caching altogether would pass every row above and fail
    here.
    """
    server = _ScriptedServer(_answer_unsupported)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        for _ in range(2):
            with pytest.raises(CapabilityError) as refusal:
                await sftp.chmod(b"/link", 0o600, follow_symlinks=False)
        assert refusal.value.missing == (EXTENSION_LSETSTAT,)
        assert sftp.refuses(EXTENSION_LSETSTAT)

    assert server.asked == 1, "an unadvertised server's OP_UNSUPPORTED was asked twice"

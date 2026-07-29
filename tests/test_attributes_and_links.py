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

import pytest

from gantry_sftp.codec import (
    EXTENSION_LSETSTAT,
    MAX_V3_TIMESTAMP,
    Attrs,
    LSetStat,
    Owner,
    StatusCode,
)
from gantry_sftp.exceptions import CapabilityError, ServerError
from gantry_sftp.session import open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

KNOWN_MTIME = 1_600_000_000
KNOWN_ATIME = 1_600_000_007


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

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.chmod(str(link).encode(), 0o600)

    assert bits(target) == 0o600
    # The link's own mode is untouched, and on Linux it is 0o777 and always was.
    assert bits(link) == 0o777


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
    assert any("Linux has no lchmod" in note for note in refusal.value.__notes__)
    assert bits(target) == 0o644


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

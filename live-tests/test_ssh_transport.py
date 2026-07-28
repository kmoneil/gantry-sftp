"""The thesis, over a real SSH connection.

``ssh -s sftp`` against a real ``sshd``: key exchange, host-key verification, public-key
authentication, the sftp subsystem, and a file actually read. If this passes, OpenSSH is
carrying the protocol and the library is doing what it claims -- being a codec, a scheduler
and an ergonomics layer, with no cryptography of its own.

The failure cases matter as much as the success one. ``Error reading SSH protocol banner``
is what paramiko reports when OpenSSH said something specific and useful; these tests assert
that the specific and useful thing reaches the caller.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from conftest import connect, negotiate
from gantry_sftp.codec import (
    Close,
    Codec,
    Data,
    Handle,
    Open,
    OpenFlag,
    Read,
    RealPath,
    Status,
    StatusCode,
)
from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError
from gantry_sftp.session import Durability, Publish, PublishMechanism, SkipReason, open_session
from gantry_sftp.transport import open_ssh_transport

pytestmark = pytest.mark.anyio


async def exchange(transport, codec: Codec, request):
    await transport.send(codec.send(request))
    while True:
        events = codec.receive(await transport.receive())
        if events:
            return events[0].response


async def _open_and_close(opener) -> None:
    """Enter and immediately leave a transport context manager."""
    async with opener:
        pass


# --- it works -----------------------------------------------------------------------------


async def test_sftp_over_a_real_ssh_connection(ssh_server):
    async with connect(ssh_server) as transport:
        codec = Codec()
        await negotiate(transport, codec)
        assert codec.server_version == 3
        # A real OpenSSH server behind a real SSH transport advertises the same extensions
        # it does on a bare pipe -- the subsystem is the same program either way.
        assert b"limits@openssh.com" in codec.extensions


async def test_reading_a_file_over_a_real_ssh_connection(ssh_server, tmp_path: Path):
    payload = b"bytes that crossed a real SSH connection\n"
    target = tmp_path / "payload.bin"
    target.write_bytes(payload)

    async with connect(ssh_server) as transport:
        codec = Codec()
        await negotiate(transport, codec)

        opened = await exchange(
            transport, codec, Open(codec.allocate_request_id(), str(target).encode(), OpenFlag.READ)
        )
        assert isinstance(opened, Handle), opened

        data = await exchange(
            transport, codec, Read(codec.allocate_request_id(), opened.handle, 0, 65536)
        )
        assert isinstance(data, Data), data
        assert bytes(data.data) == payload

        closed = await exchange(transport, codec, Close(codec.allocate_request_id(), opened.handle))
        assert isinstance(closed, Status)
        assert closed.code == StatusCode.OK


async def test_pipelined_reads_over_a_real_ssh_connection(ssh_server, tmp_path: Path):
    """Every request out before any reply is read, then reassembled by matched offset.

    Still localhost, so this does not prove behaviour under latency -- that is
    ``test_netem_pipelining.py``'s job, and it is a separate file because it needs a shaped
    link and skips without one. What this proves is that pipelining survives a real SSH
    channel, where flow control and packet boundaries are nothing like a pipe's.
    """
    chunk = 4096
    payload = bytes(range(256)) * (chunk * 8 // 256)
    target = tmp_path / "pipelined.bin"
    target.write_bytes(payload)

    async with connect(ssh_server) as transport:
        codec = Codec()
        await negotiate(transport, codec)

        opened = await exchange(
            transport, codec, Open(codec.allocate_request_id(), str(target).encode(), OpenFlag.READ)
        )
        assert isinstance(opened, Handle), opened

        offsets = list(range(0, len(payload), chunk))
        for offset in offsets:
            await transport.send(
                codec.send(Read(codec.allocate_request_id(), opened.handle, offset, chunk))
            )
        assert codec.outstanding == len(offsets)

        reassembled = bytearray(len(payload))
        received = 0
        while received < len(offsets):
            for event in codec.receive(await transport.receive()):
                assert isinstance(event.response, Data), event.response
                start = event.request.offset
                block = bytes(event.response.data)
                reassembled[start : start + len(block)] = block
                received += 1

        assert bytes(reassembled) == payload
        assert codec.outstanding == 0
        await exchange(transport, codec, Close(codec.allocate_request_id(), opened.handle))


async def test_realpath_resolves_over_a_real_connection(ssh_server):
    async with connect(ssh_server) as transport:
        codec = Codec()
        await negotiate(transport, codec)
        reply = await exchange(transport, codec, RealPath(codec.allocate_request_id(), b"."))
        assert reply.entries
        assert reply.entries[0].filename.startswith(b"/")


async def test_streaming_a_directory_over_a_real_ssh_connection(ssh_server, tmp_path: Path):
    """A scan that stops mid-directory, with a real SSH channel underneath it.

    The bare-pipe lane cannot show this one. `scandir` abandons a listing with batches still
    unread and closes the handle underneath them, which over ssh means an OPENDIR, some
    READDIRs and a CLOSE interleaved on a channel that is also carrying a STAT per entry --
    the multiplexed shape, on the transport where a stall would actually cost something.
    """
    source = tmp_path / "remote"
    source.mkdir()
    for index in range(120):  # more than one OpenSSH batch, so a scan really does stop short
        (source / f"file{index:03d}.bin").write_bytes(b"x" * index)

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        seen = 0
        async with sftp.scandir(str(source)) as entries:
            async for item in entries:
                # A second operation from inside an open scan: the interleave that a session
                # lock would deadlock on, over the transport that has its own windowing.
                attributes = await sftp.stat(f"{source}/{item.name}")
                assert attributes.size is not None
                seen += 1
                if seen == 5:
                    break

        # The connection is unaffected by the abandoned scan, and both forms agree.
        assert len({item.name for item in await sftp.listdir(str(source))}) == 120

    assert seen == 5


class StopPartwayError(Exception):
    """Raised from a progress callback to cut a transfer off at a known point."""


def stop_once_something_has_moved(transferred: int, total: int | None) -> None:
    if total is not None and 0 < transferred < total:
        raise StopPartwayError


async def test_resuming_a_transfer_over_a_real_ssh_connection(ssh_server, tmp_path: Path):
    """Both directions, interrupted and resumed, over a real SSH channel.

    The bare-pipe lane cannot show this one. A resume is an offset agreed between two ends
    over a link with its own windowing and its own flow control, and the failure it guards
    against -- a partial that is the right *length* and the wrong *bytes* -- is invisible to
    anything but a full comparison. So both halves are compared byte for byte, with random
    content, because a hole of zeros inside a file of zeros proves nothing.
    """
    payload = os.urandom(2_000_000)
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)
    downloaded = tmp_path / "downloaded.bin"
    uploaded = tmp_path / "uploaded.bin"

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        with pytest.raises(StopPartwayError):
            _ = await sftp.get(
                str(source), downloaded, depth=1, progress=stop_once_something_has_moved
            )
        partial = downloaded.stat().st_size
        assert 0 < partial < len(payload), "the download was not actually interrupted"
        assert await sftp.get(str(source), downloaded, resume=True) == len(payload) - partial

        with pytest.raises(StopPartwayError):
            _ = await sftp.put(
                source,
                str(uploaded),
                publish=Publish(atomic=False),
                depth=1,
                progress=stop_once_something_has_moved,
            )
        sent = uploaded.stat().st_size
        assert 0 < sent < len(payload), "the upload was not actually interrupted"
        result = await sftp.put(source, str(uploaded), publish=Publish(atomic=False), resume=True)
        assert result.transferred == len(payload) - sent

    assert downloaded.read_bytes() == payload
    assert uploaded.read_bytes() == payload


async def test_a_recursive_download_over_a_real_ssh_connection(ssh_server, tmp_path: Path):
    """A tree, over a real SSH channel, with the destination boundary enforced.

    The bare-pipe lane cannot show this: `sshd` spawns the subsystem with its own working
    directory, its own umask, and a HOME that is not this one, so the paths a walk builds are
    resolved by a server in a different place from the client.
    """
    source = tmp_path / "remote"
    (source / "daily" / "archive").mkdir(parents=True)
    (source / "top.csv").write_bytes(b"top")
    (source / "daily" / "today.bin").write_bytes(os.urandom(120_000))
    (source / "daily" / "archive" / "old.csv").write_bytes(b"old")
    (source / "daily" / "latest.csv").symlink_to(source / "top.csv")
    destination = tmp_path / "local"

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        result = await sftp.get_tree(str(source), destination)

    assert result.files == 3
    assert result.directories == 2
    assert (destination / "daily" / "archive" / "old.csv").read_bytes() == b"old"
    assert (destination / "daily" / "today.bin").read_bytes() == (
        source / "daily" / "today.bin"
    ).read_bytes()
    # Symlinks are reported rather than followed or copied, over ssh as over a pipe.
    assert [skip.reason for skip in result.skipped] == [SkipReason.SYMLINK]
    assert not (destination / "daily" / "latest.csv").exists()


def staging_files(directory: Path, stem: str) -> list[Path]:
    """Staging files for ``stem``, as a consumer's glob would see them.

    A plain function so the async test below does no filesystem work in an async frame.
    """
    return list(directory.glob(f".{stem}.*.part"))


async def test_an_atomic_publish_over_a_real_ssh_connection(ssh_server, tmp_path: Path):
    """Atomic publish where the server is a subsystem of a real sshd, not a bare pipe.

    Same program, different environment: spawned by ``sshd`` it has that user's HOME, its own
    working directory and its own umask, so the staging file lands somewhere the bare-pipe
    lane cannot tell us about. The assertion that matters is that the staging file is gone --
    a publish that leaves one behind is one a consumer's glob eventually trips over.
    """
    payload = os.urandom(300_000)
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    destination = tmp_path / "published.bin"
    destination.write_bytes(b"the previous version")

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        result = await sftp.put(
            source, str(destination), publish=Publish(require_atomic=True, require_fsync=True)
        )

    assert result.mechanism is PublishMechanism.POSIX_RENAME
    assert result.durability is Durability.FSYNCED
    assert result.transferred == len(payload)
    assert destination.read_bytes() == payload
    assert not staging_files(tmp_path, "published.bin"), "a staging file was left behind"


# --- it fails usefully ---------------------------------------------------------------------


async def test_authentication_failure_carries_opensshs_own_words(ssh_server):
    """The headline fix, against a real refusal.

    paramiko's answer here is ``Error reading SSH protocol banner``, which says nothing
    about the cause. OpenSSH knew exactly what was wrong and said so; we pass it through
    untouched rather than parsing it into something lossier.
    """
    async with connect(ssh_server, identity_file=str(ssh_server.wrong_identity_file)) as transport:
        codec = Codec()
        # Caught as the *specific* class, which is the whole point of D-11: a user asking
        # "was that my key?" gets an answer instead of a substring search.
        with pytest.raises(AuthenticationError) as exc:
            await negotiate(transport, codec)

    stderr = exc.value.stderr
    assert stderr, "a failed authentication produced no stderr at all"
    assert "Permission denied" in stderr, stderr
    # The rendered exception is enough on its own -- no need to reach for `.stderr`.
    assert "Permission denied" in str(exc.value)
    assert exc.value.returncode == 255
    # The old spelling must still work: making an error more specific must not stop anyone's
    # existing `except ConnectError` from catching it.
    assert isinstance(exc.value, ConnectError)


async def test_host_key_verification_failure_is_reported_not_silently_accepted(ssh_server):
    """An unknown host key must stop the connection, and say why.

    This is the check that stands between the transfer and a machine-in-the-middle, so
    "it failed" is not enough -- the reason has to reach the caller or nobody will ever know
    which of the two things went wrong.
    """
    async with connect(
        ssh_server,
        options={"UserKnownHostsFile": str(ssh_server.empty_known_hosts)},
    ) as transport:
        codec = Codec()
        with pytest.raises(HostKeyError) as exc:
            await negotiate(transport, codec)

    stderr = exc.value.stderr
    assert stderr, "a host-key failure produced no stderr at all"
    assert "Host key verification failed" in stderr, stderr
    assert isinstance(exc.value, ConnectError)
    # Not the other one. Reporting a rejected host identity as a rejected credential is the
    # misclassification that actually costs something.
    assert not isinstance(exc.value, AuthenticationError)


async def test_a_changed_host_key_raises_HostKeyError_with_opensshs_warning(  # noqa: N802
    ssh_server, tmp_path: Path
):
    """The machine-in-the-middle case, which is different from an unknown host.

    An unknown host is a first connection; a *changed* host key means the identity moved under
    a client that had already pinned it, and OpenSSH escalates to a full warning banner rather
    than a one-line refusal. It is the single most security-relevant thing this transport can
    report, and until this test the suite had never produced one -- only the milder unknown-host
    case, whose stderr happens to end in the same summary line.
    """
    wrong_public_key = ssh_server.wrong_identity_file.with_suffix(".pub").read_text().split()
    planted = tmp_path / "known_hosts_with_the_wrong_key"
    planted.write_text(
        f"[127.0.0.1]:{ssh_server.port} {wrong_public_key[0]} {wrong_public_key[1]}\n"
    )

    async with connect(
        ssh_server,
        options={"UserKnownHostsFile": str(planted), "StrictHostKeyChecking": "yes"},
    ) as transport:
        codec = Codec()
        with pytest.raises(HostKeyError) as exc:
            await negotiate(transport, codec)

    stderr = exc.value.stderr
    assert "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr, stderr
    assert "man-in-the-middle attack" in stderr, stderr
    # The banner reaches the user without being summarised into something calmer.
    assert "REMOTE HOST IDENTIFICATION HAS CHANGED" in str(exc.value)


async def test_an_authentication_failure_is_catchable_outside_the_async_with(ssh_server):
    """The spelling users actually write, over a real ssh connection.

    Every other failure test in this file puts `pytest.raises` *inside* the `async with`, and
    that is exactly why none of them caught the exception-group leak: the transport's stderr
    drain runs in an anyio task group, which wraps even a single exception on the way out, so
    a handler placed outside the block never matched. Regression test for that, on the path
    that matters most -- an `except AuthenticationError` that silently never fires is worse
    than not having the class.
    """

    async def connect_with_the_wrong_key() -> None:
        async with connect(
            ssh_server, identity_file=str(ssh_server.wrong_identity_file)
        ) as transport:
            await negotiate(transport, Codec())

    with pytest.raises(AuthenticationError) as exc:
        await connect_with_the_wrong_key()

    assert not isinstance(exc.value, BaseExceptionGroup)
    assert "Permission denied" in exc.value.stderr


async def test_connecting_to_a_closed_port_reports_the_refusal(ssh_server):
    async with connect(ssh_server, port=_closed_port()) as transport:
        codec = Codec()
        with pytest.raises(ConnectError) as exc:
            await negotiate(transport, codec)
    assert "Connection refused" in exc.value.stderr, exc.value.stderr
    # Deliberately *not* classified. A refused connection is neither an authentication failure
    # nor a host-key failure, and guessing it into one would make both classes meaningless.
    assert type(exc.value) is ConnectError


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# --- argument injection, against the real binary --------------------------------------------


async def test_a_hostile_host_never_reaches_ssh(ssh_server):
    # Rejected during argv construction, so no process is spawned at all. The marker would
    # appear in stderr if ProxyCommand had run.
    with pytest.raises(ValueError):
        await _open_and_close(open_ssh_transport("-oProxyCommand=echo GANTRY_MARKER >&2"))


async def test_a_proxycommand_option_is_honoured_when_the_caller_asks_for_it(ssh_server):
    """The defence is against *injection*, not against the option existing.

    A caller who deliberately passes ProxyCommand gets ProxyCommand -- that is a supported
    and necessary feature, and it is how bastion hosts work. What must never happen is a
    hostname turning into one.
    """
    async with connect(
        ssh_server,
        options={"ProxyCommand": f"nc 127.0.0.1 {ssh_server.port}"},
    ) as transport:
        codec = Codec()
        try:
            await negotiate(transport, codec)
        except ConnectError as exc:
            if "nc" in exc.stderr or "not found" in exc.stderr:
                pytest.skip(f"nc unavailable for the ProxyCommand path: {exc.stderr.strip()}")
            raise
        assert codec.server_version == 3

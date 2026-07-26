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

from gantry_sftp.codec import (
    Close,
    Codec,
    CodecState,
    Data,
    Handle,
    Open,
    OpenFlag,
    Read,
    RealPath,
    Status,
    StatusCode,
)
from gantry_sftp.exceptions import ConnectError
from gantry_sftp.transport import open_ssh_transport

pytestmark = pytest.mark.anyio


async def negotiate(transport, codec: Codec) -> None:
    await transport.send(codec.initiate())
    while codec.state is not CodecState.READY:
        codec.receive(await transport.receive())


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


def connect(server, **overrides):
    """Open a transport to the test server, with any argument replaceable.

    Defaults are merged rather than passed alongside the overrides, so a test can say
    ``port=...`` or ``identity_file=...`` without colliding with the value here.
    """
    options = server.connect_options()
    options.update(overrides.pop("options", {}))
    kwargs = {
        "port": server.port,
        "identity_file": str(server.identity_file),
        "config_file": os.devnull,
    }
    kwargs.update(overrides)
    return open_ssh_transport("127.0.0.1", options=options, **kwargs)


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

    Still localhost, so this does not prove behaviour under latency -- that needs the netem
    lane, which does not exist yet. What it proves is that pipelining survives a real SSH
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


# --- it fails usefully ---------------------------------------------------------------------


async def test_authentication_failure_carries_opensshs_own_words(ssh_server):
    """The headline fix, against a real refusal.

    paramiko's answer here is ``Error reading SSH protocol banner``, which says nothing
    about the cause. OpenSSH knew exactly what was wrong and said so; we pass it through
    untouched rather than parsing it into something lossier.
    """
    async with connect(ssh_server, identity_file=str(ssh_server.wrong_identity_file)) as transport:
        codec = Codec()
        with pytest.raises(ConnectError) as exc:
            await negotiate(transport, codec)

    stderr = exc.value.stderr
    assert stderr, "a failed authentication produced no stderr at all"
    assert "Permission denied" in stderr, stderr
    # The rendered exception is enough on its own -- no need to reach for `.stderr`.
    assert "Permission denied" in str(exc.value)
    assert exc.value.returncode == 255


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
        with pytest.raises(ConnectError) as exc:
            await negotiate(transport, codec)

    stderr = exc.value.stderr
    assert stderr, "a host-key failure produced no stderr at all"
    assert "Host key verification failed" in stderr, stderr


async def test_connecting_to_a_closed_port_reports_the_refusal(ssh_server):
    async with connect(ssh_server, port=_closed_port()) as transport:
        codec = Codec()
        with pytest.raises(ConnectError) as exc:
            await negotiate(transport, codec)
    assert "Connection refused" in exc.value.stderr, exc.value.stderr


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

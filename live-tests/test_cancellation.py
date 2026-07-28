"""Cancellation through a real `ssh`, where the fake cannot see what matters.

`tests/test_cancellation.py` proves what a scripted server can prove: that a CLOSE was sent,
that the staging file was removed, that the walk stopped. It cannot prove the server *acted*
on the CLOSE -- the fake's handle table is our own idea of one -- and it has no child process
to leave behind. This lane has both.

**The handle table is read by asking the server, not by reading `/proc`.** That probe is
`conftest.still_open`, shared with the orphaned-handle lane; its docstring says why, and both
directions of it are calibrated in the test below -- "the probe found nothing" and "there is
nothing to find" are the same green test otherwise, which is how a leak passes.

Each test cancels at a rendezvous rather than after a sleep: the progress callback fires once
per reply, so cancelling from inside it lands the cancel mid-transfer on every run.
"""

from __future__ import annotations

import os

import anyio
import pytest

from conftest import connect, still_open
from gantry_sftp.codec import OpenFlag
from gantry_sftp.session import DEFAULT_REQUEST_TIMEOUT, open_session

pytestmark = pytest.mark.anyio

TRANSFER_SIZE = 4 << 20
"""Big enough to take many replies, small enough to cost nothing on loopback."""

BUDGET = 5.0
"""What unwinding a cancelled transfer may take, against a `DEFAULT_REQUEST_TIMEOUT` of 30 s.

Generous by a wide margin over what a local link needs, and still far under the cost of the
bug it guards: shielded cleanup waiting out a `request_timeout` for a reply whose reader the
same cancellation had already stopped (D-34).
"""

PROBED_SLOTS = 4
"""How many handle values to probe.

OpenSSH's `sftp-server` numbers handles from zero and reuses the lowest free slot, so a
handle leaked by the one-and-only transfer in a fresh session is in the first few. Four is
three more than needed and still a bounded, cheap sweep.
"""


def cancel_on_first_reply(scope: anyio.CancelScope):
    """A progress callback that stops the transfer once bytes have actually moved."""

    def watch(transferred: int, total: int | None) -> None:
        if transferred:
            scope.cancel()

    return watch


async def test_a_cancelled_download_leaves_no_handle_open_on_the_server(ssh_server, tmp_path):
    """The clause only a real server can answer: the CLOSE was acted on, not merely sent.

    The session outlives the cancelled transfer -- the scope is inside it -- which is what
    makes the question askable at all. A leaked handle counts against max-open-handles and is
    invisible from this side until the server starts refusing to open anything.
    """
    remote = tmp_path / "big.bin"
    remote.write_bytes(os.urandom(TRANSFER_SIZE))
    local = tmp_path / "copy.bin"

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        caller = anyio.CancelScope()
        with caller:
            _ = await sftp.get(str(remote), local, progress=cancel_on_first_reply(caller))
        assert caller.cancel_called, "the transfer finished before the cancel landed"

        # Nothing else in this session has ever opened anything, so a handle the cancelled
        # transfer left behind is one of these.
        leaked = [
            slot for slot in range(PROBED_SLOTS) if await still_open(sftp, slot.to_bytes(4, "big"))
        ]
        assert leaked == [], f"the server is still holding handle(s) {leaked} from a cancel"

        # And the probe can tell the difference, which the assertion above is worthless
        # without: an open handle closes, and closing it twice is refused.
        handle = await sftp.open(str(remote), OpenFlag.READ)
        assert await still_open(sftp, handle), "an open handle read as closed; the probe is blind"
        assert not await still_open(sftp, handle), "a closed handle read as open"

        # The session is still usable afterwards, which is the other half of "the cancel
        # stopped the transfer": it must not have taken the connection with it.
        assert (await sftp.stat(str(remote))).size == TRANSFER_SIZE


async def test_cancelling_around_the_session_unwinds_promptly_and_reaps_ssh(ssh_server, tmp_path):
    """The spelling a timeout reaches for, at the shipped default, through a real pipe.

    No `request_timeout` is passed: the number under test is the one users get. With the
    reader going down with the caller's cancel this took `DEFAULT_REQUEST_TIMEOUT` to unwind
    -- for the same reason on a real link as on a fake one, but only here is the `ssh` child
    real enough to be left behind.
    """
    remote = tmp_path / "big.bin"
    remote.write_bytes(os.urandom(TRANSFER_SIZE))
    local = tmp_path / "copy.bin"
    captured: list[object] = []

    started = anyio.current_time()
    caller = anyio.CancelScope()
    with caller:
        async with connect(ssh_server) as transport, open_session(transport) as sftp:
            captured.append(transport)
            _ = await sftp.get(str(remote), local, progress=cancel_on_first_reply(caller))
    elapsed = anyio.current_time() - started

    (transport,) = captured
    assert caller.cancel_called, "the transfer finished before the cancel landed"
    assert elapsed < BUDGET, (
        f"unwinding took {elapsed:.2f}s of a {DEFAULT_REQUEST_TIMEOUT}s request_timeout -- "
        f"the shielded cleanup is waiting for a reply the reader is not there to route"
    )
    assert transport.returncode is not None, "the ssh child outlived a cancelled transfer"

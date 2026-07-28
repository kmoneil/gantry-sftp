"""An abandoned `OPEN` against a real server, where the handle table is the server's own.

`tests/test_orphaned_handles.py` proves the reap against a fake that answers when the test
tells it to. Only here is the server free to answer whenever it likes, and only here is the
handle table one we did not write.

The window needs latency to be reachable on purpose: on loopback an `OPEN` is answered in
microseconds, so a test that tried to abandon one would be racing the server and would pass by
accident more often than by design. `tc netem` makes it deterministic — at 200 ms round trip a
50 ms deadline cannot possibly see the reply — which is what this lane exists for. It skips
with a reason when shaping is unavailable rather than pretending.
"""

from __future__ import annotations

import os

import anyio
import pytest

from conftest import connect, still_open
from gantry_sftp.codec import OpenFlag
from gantry_sftp.session import open_session

pytestmark = pytest.mark.anyio

RTT_MS = 200.0
"""Enough latency that the abandonment is a certainty rather than a race."""

TOO_SOON = 0.05
"""A deadline a reply cannot beat: a quarter of one round trip."""

PROBED_SLOTS = 4
"""OpenSSH numbers handles from zero and reuses the lowest free slot, so this is a wide sweep."""


async def test_an_abandoned_open_leaves_no_handle_open_on_a_real_server(
    ssh_server, shape_link, tmp_path
):
    """Abandon an `OPEN` in flight, keep the session, and ask the server what it still holds.

    The session has to survive for the leak to exist at all -- one that ends takes the handle
    with it, because `sftp-server` exits and the kernel closes its files. That is why the cancel
    scope is inside the session here and the assertion comes afterwards, on a connection that is
    still working.
    """
    _ = shape_link(rtt_ms=RTT_MS)
    remote = tmp_path / "target.bin"
    remote.write_bytes(os.urandom(4096))

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        caller = anyio.CancelScope()
        with caller:
            with anyio.move_on_after(TOO_SOON):
                _ = await sftp.open(str(remote), OpenFlag.READ)
        assert caller.cancel_called is False
        assert sftp.reaped == 0, "nothing has been abandoned yet"

        # Two round trips rather than a sleep. The server answers the abandoned OPEN about one
        # RTT after it was sent; the reply is routed, the handle queued, and the CLOSE written
        # from the reaper's task. Anything we send after that is behind it in the server's own
        # order, so by the time the second answer is back the reap has certainly happened --
        # and `reaped` says so rather than a timer claiming it.
        _ = await sftp.realpath(b".")
        _ = await sftp.realpath(b".")
        assert sftp.reaped == 1, "the abandoned OPEN's reply was never reaped"

        leaked = [
            slot for slot in range(PROBED_SLOTS) if await still_open(sftp, slot.to_bytes(4, "big"))
        ]
        assert leaked == [], f"the server is still holding handle(s) {leaked}"

        # The probe has to be able to see an open handle, or the assertion above is a scan that
        # could never have found anything -- which is exactly how this proof failed once before.
        handle = await sftp.open(str(remote), OpenFlag.READ)
        assert await still_open(sftp, handle), "an open handle read as closed; the probe is blind"
        assert not await still_open(sftp, handle), "a closed handle read as open"

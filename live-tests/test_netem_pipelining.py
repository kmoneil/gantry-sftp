"""The scheduler, under latency. The measurements the rest of the suite cannot make.

Every other test in this repository runs on a link with no delay, and on such a link a
lockstep client and a deeply pipelined one are indistinguishable: both finish instantly. That
is not a gap in the coverage, it is *the* gap -- it is precisely why ``sftp(1)``'s defaults
went unquestioned for two decades, and correcting it is the reason this library exists. So
the numbers get made here or they do not get made.

What the lane establishes, in order:

1. The shaped link really has the round-trip time it was asked for. A benchmark that reports
   its own configuration has measured nothing.
2. Depth is what moves throughput. Ten to eighteen times, measured, between depth 1 and
   depth 64 on the same file over the same link.
3. At depth 1 the elapsed time *is* one round trip per request, within a couple of percent.
   That is the formula in DESIGN.md 5 verified rather than asserted.
4. Throughput follows **bytes in flight**, not depth and not request size separately. Three
   different (depth, size) pairs multiplying to the same product transfer at the same rate.
5. And it stops following it at 2 MiB, because that is where OpenSSH's channel window is --
   a ceiling underneath us that no amount of pipelining can lift. See
   :func:`test_the_ceiling_is_opensshs_channel_window_and_not_our_pipeline`, which is the
   most consequential measurement in the file and the one that amended the design.

Backends
--------
The timing tests run on asyncio only. Elapsed time here is a property of the wire -- packets,
a round-trip delay and a flow-control window -- and running each measurement twice to watch
two event loops wait for the same delay doubles the wall clock of the slowest lane in the
project while proving nothing new. The correctness-under-loss test *does* run on both, because
that is where a backend difference could actually hide: retransmits, partial reads and a
timeout that must not fire are exactly the shapes anyio papers over differently.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from netem import measure_rtt_ms, shape

from conftest import connect, negotiate, running_dispatcher
from gantry_sftp.codec import Close, Codec, Handle, Open, OpenFlag
from gantry_sftp.session import (
    DEFAULT_PIPELINE_DEPTH,
    PREFERRED_READ_LENGTH,
    download_handle,
    open_session,
)

pytestmark = pytest.mark.anyio

MEBIBYTE = 1024 * 1024

SFTP1_BUFFER_SIZE = 32768
"""``sftp(1)``'s ``-B`` default, and the SSH channel packet size underneath it.

Measured off ``ssh -vvv`` against the test server: ``open confirm rwindow 0 rmax 32768``. The
two numbers being the same is not a coincidence -- see
:func:`test_the_ceiling_is_opensshs_channel_window_and_not_our_pipeline`.
"""

OPENSSH_CHANNEL_WINDOW = 64 * SFTP1_BUFFER_SIZE
"""2 MiB: the most an OpenSSH session channel will carry unacknowledged.

Not recalled from the source -- derived from the plateau this lane measures, and corroborated
by the ``rmax 32768`` the client prints. It is also exactly ``sftp(1)``'s ``-R 64`` times its
``-B 32768``, which reframes those defaults: they are not timid, they are *matched to the
channel they run over*.
"""


@pytest.fixture
def anyio_backend() -> str:
    """asyncio only for this module. See the module docstring for why."""
    return "asyncio"


@dataclass(frozen=True, slots=True)
class Transfer:
    """One timed download, and enough context to say what the number means."""

    elapsed: float
    size: int
    depth: int
    read_length: int

    @property
    def in_flight(self) -> int:
        """Bytes the scheduler allows outstanding at once. The lever, per DESIGN.md 5."""
        return self.depth * self.read_length

    @property
    def megabytes_per_second(self) -> float:
        return self.size / self.elapsed / 1e6

    def __str__(self) -> str:
        return (
            f"depth={self.depth} x {self.read_length}B = {self.in_flight / MEBIBYTE:.2f} MiB "
            f"in flight -> {self.elapsed:.3f}s, {self.megabytes_per_second:.2f} MB/s"
        )


async def timed_download(
    server, source: Path, target: Path, *, depth: int, read_length: int
) -> Transfer:
    """Download ``source`` to ``target`` at an explicit depth and request size, and time it.

    Drives :func:`~gantry_sftp.session.download_handle` rather than ``Session.get`` because
    the request size is derived from the server's limits there and is deliberately not a
    public knob -- but it is one of the two variables under test, so this lane needs it. The
    scheduler being exercised is the shipped one either way.

    The clock starts after OPEN, so what is timed is the transfer rather than the SSH
    handshake, which at 200 ms costs a second on its own and belongs to no depth.
    """
    async with connect(server) as transport:
        codec = Codec()
        await negotiate(transport, codec)

        request = Open(codec.allocate_request_id(), str(source).encode(), OpenFlag.READ)
        await transport.send(codec.send(request))
        opened = None
        while opened is None:
            for event in codec.receive(await transport.receive()):
                opened = event.response
        assert isinstance(opened, Handle), opened

        size = file_size(source)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        started = time.perf_counter()
        try:
            async with running_dispatcher(transport, codec) as dispatcher:
                written = await download_handle(
                    dispatcher,
                    opened.handle,
                    fd,
                    size=size,
                    read_length=read_length,
                    depth=depth,
                )
        finally:
            os.close(fd)
        elapsed = time.perf_counter() - started
        await transport.send(codec.send(Close(codec.allocate_request_id(), opened.handle)))

    assert written == size
    # Byte identity on every single timed run, not just the correctness tests. A fast wrong
    # answer is the failure mode a benchmark invites, and reassembling by matched offset is
    # exactly what latency makes hard.
    assert_identical(source, target)
    return Transfer(elapsed=elapsed, size=size, depth=depth, read_length=read_length)


# The filesystem helpers below are plain functions rather than inline calls, for the reason
# `staging_files` is one in the transport lane: `os.scandir`, `stat` and `read_bytes` block,
# and keeping them out of an async frame is what lets ruff's ASYNC240 see the difference
# between a deliberate blocking call and an accidental one.


def file_size(path: Path) -> int:
    return path.stat().st_size


def assert_identical(source: Path, target: Path) -> None:
    assert target.read_bytes() == source.read_bytes(), "the shaped transfer corrupted the file"


def random_file(path: Path, size: int) -> Path:
    path.write_bytes(os.urandom(size))
    return path


def build_tree(root: Path) -> Path:
    """Three files across two directory levels -- enough round trips for latency to show."""
    (root / "daily" / "archive").mkdir(parents=True)
    (root / "top.csv").write_bytes(b"top")
    (root / "daily" / "today.bin").write_bytes(os.urandom(300_000))
    (root / "daily" / "archive" / "old.csv").write_bytes(b"old")
    return root


# --- the fixture has to be honest before anything measured under it means anything ---------


@pytest.mark.parametrize("target_rtt", [5.0, 50.0, 200.0])
def test_the_shaped_link_has_the_round_trip_time_it_was_asked_for(shape_link, target_rtt):
    """Measure the link rather than restating the flag that shaped it.

    This is the test the whole lane rests on. ``netem`` applies its delay *per traversal*, so
    a naive ``delay 200ms`` produces a 400 ms round trip -- the model in :mod:`netem` halves
    it, and a model is a belief until something checks it. If this fails, every throughput
    number below is being attributed to the wrong link.

    The tolerance is one-sided in practice: shaping can only add time, and the measured value
    lands 1-6 ms above the request because a round trip also costs two scheduler wakeups and
    a TCP stack. What it must not do is come back at half or double.
    """
    link = shape_link(rtt_ms=target_rtt)

    assert link.baseline_rtt_ms < 1.0, (
        f"unshaped loopback already had a {link.baseline_rtt_ms:.2f} ms round trip; "
        "something else is shaping this interface and the measurements below are not ours"
    )
    assert 0.9 * target_rtt <= link.measured_rtt_ms <= 1.2 * target_rtt + 5.0, link.describe()


def test_removing_the_profile_gives_the_link_back(shape_link):
    """Shaping is scoped, so a lane that fails does not slow the rest of the container.

    ``lo`` carries every server in ``live-tests/``, so a leaked 200 ms qdisc would not fail
    anything -- it would make everything else mysteriously slow, which is worse, because
    nothing points at the cause. The context manager's ``finally`` is what prevents it, and
    an unasserted ``finally`` is a plan rather than a guarantee.

    ``shape_link`` is requested only for its skip: this drives :func:`netem.shape` directly,
    because what is under test is the teardown that the fixture would otherwise perform after
    the test has finished and can no longer look.
    """
    with shape(rtt_ms=200.0) as link:
        assert link.measured_rtt_ms > 100.0, link.describe()
    assert measure_rtt_ms() < 1.0, "the netem qdisc outlived the context manager"


# --- the headline: depth is the knob --------------------------------------------------------

# Chunk counts per RTT, chosen so the depth-1 leg stays under about five seconds. Explicit
# rather than computed: this table *is* the runtime budget of the slowest lane in the project,
# and a reader should be able to see it rather than evaluate a formula.
CHUNKS_AT_RTT = {5.0: 128, 50.0: 48, 200.0: 24}


@pytest.mark.parametrize("target_rtt", [5.0, 50.0, 200.0])
async def test_depth_is_the_knob_that_moves_throughput_under_latency(
    shape_link, ssh_server, tmp_path, target_rtt
):
    """The same file, the same link, the same request size. Only the depth differs.

    This is the entire thesis in one assertion, and it is the assertion localhost cannot
    make: run this without shaping and both legs finish in milliseconds, the ratio collapses
    to noise, and a lockstep client passes.

    Measured on this sandbox (OpenSSH 10.0p2, loopback netem, 32768-byte requests): 14.7x at
    5 ms, 18.5x at 50 ms, 10.6x at 200 ms. The floor asserted here is 4x, which is a wide
    margin on purpose -- the claim is that depth changes the *character* of the transfer, and
    pinning a ratio to two significant figures would be pinning this machine's scheduler.
    """
    chunks = CHUNKS_AT_RTT[target_rtt]
    source = random_file(tmp_path / "source.bin", SFTP1_BUFFER_SIZE * chunks)
    link = shape_link(rtt_ms=target_rtt)

    lockstep = await timed_download(
        ssh_server, source, tmp_path / "lockstep.bin", depth=1, read_length=SFTP1_BUFFER_SIZE
    )
    pipelined = await timed_download(
        ssh_server,
        source,
        tmp_path / "pipelined.bin",
        depth=DEFAULT_PIPELINE_DEPTH,
        read_length=SFTP1_BUFFER_SIZE,
    )

    speedup = lockstep.elapsed / pipelined.elapsed
    assert speedup >= 4.0, (
        f"{link.describe()}: pipelining bought only {speedup:.1f}x. "
        f"lockstep {lockstep}; pipelined {pipelined}"
    )


@pytest.mark.parametrize("target_rtt", [50.0, 200.0])
async def test_at_depth_one_a_transfer_costs_one_round_trip_per_request(
    shape_link, ssh_server, tmp_path, target_rtt
):
    """``throughput = (outstanding x size) / RTT``, with ``outstanding`` pinned to 1.

    DESIGN.md 5 states that formula as the whole argument for the library, and until this
    lane existed it was arithmetic nobody had checked against a wire. At depth 1 it collapses
    to something exactly predictable -- elapsed should equal the number of requests times the
    round-trip time -- so this is the case where the model can be falsified rather than
    merely fitted.

    Measured within 3% at 50 ms and 200 ms. The band below is deliberately wider than that,
    but not wide enough to accommodate the model being wrong: a client issuing two requests
    per round trip would come in at half.
    """
    chunks = CHUNKS_AT_RTT[target_rtt]
    source = random_file(tmp_path / "source.bin", SFTP1_BUFFER_SIZE * chunks)
    link = shape_link(rtt_ms=target_rtt)

    transfer = await timed_download(
        ssh_server, source, tmp_path / "out.bin", depth=1, read_length=SFTP1_BUFFER_SIZE
    )

    predicted = chunks * link.measured_rtt_seconds
    ratio = transfer.elapsed / predicted
    assert 0.85 <= ratio <= 1.25, (
        f"{link.describe()}: {chunks} requests at depth 1 took {transfer.elapsed:.3f}s, "
        f"the one-round-trip-each model predicts {predicted:.3f}s ({ratio:.2f}x)"
    )


# --- what the knob actually is --------------------------------------------------------------


async def test_throughput_follows_bytes_in_flight_not_depth_or_request_size(
    shape_link, ssh_server, tmp_path
):
    """Three ways to put half a mebibyte on the wire, and they perform the same.

    The point is that neither knob matters on its own. A library that tuned depth while
    leaving request size at 32 KiB, or raised request size while leaving depth at 1, would
    each be turning one factor of a product -- and DESIGN.md 5's claim is about the product.
    Deep-and-small, shallow-and-large, and the middle all land within a few percent of each
    other here, which is what makes "bytes in flight" the right thing for the session to
    reason about and report.

    It also rules out an alternative explanation for the depth result above: if the gain came
    from concurrency in *our* code rather than from bytes on the wire, depth 16 would beat
    depth 2 at equal in-flight bytes. It does not.
    """
    source = random_file(tmp_path / "source.bin", 8 * MEBIBYTE)
    link = shape_link(rtt_ms=50.0)

    in_flight = 512 * 1024
    shapes = ((32768, 16), (65536, 8), (261120, 2))
    transfers = [
        await timed_download(
            ssh_server, source, tmp_path / f"out{depth}.bin", depth=depth, read_length=length
        )
        for length, depth in shapes
    ]

    for transfer in transfers:
        assert abs(transfer.in_flight - in_flight) <= in_flight * 0.02, transfer

    rates = [transfer.megabytes_per_second for transfer in transfers]
    spread = max(rates) / min(rates)
    assert spread <= 1.4, (
        f"{link.describe()}: equal bytes in flight gave unequal throughput, "
        f"spread {spread:.2f}x -- " + "; ".join(str(t) for t in transfers)
    )


async def test_the_ceiling_is_opensshs_channel_window_and_not_our_pipeline(
    shape_link, ssh_server, tmp_path
):
    """Past 2 MiB in flight, more depth buys nothing -- and the reason is not ours.

    The most consequential measurement in this file. Quadrupling the bytes in flight from
    2 MiB to 8 MiB changes throughput by about 1%, while quadrupling from 0.5 MiB to 2 MiB
    roughly doubles it. The ceiling sits at a fixed *byte count*, not at a depth: it lands in
    the same place whether it is reached as 64 x 32768 or 8 x 261120, which is what rules out
    an explanation on our side of the pipe.

    2 MiB is ``CHAN_SES_WINDOW_DEFAULT`` -- OpenSSH's per-channel flow-control window, 64
    times the 32768-byte channel packet size that ``ssh -vvv`` reports as ``rmax`` on this
    connection. Nothing the SFTP layer does can lift it, because it is enforced one layer
    down by the transport we deliberately do not implement.

    Three things follow, and all three are now in DESIGN.md 5:

    - ``sftp(1)``'s ``-R 64 -B 32768`` is not a timid default. It is exactly the channel
      window, and the 2 MiB in flight everyone quotes as its ceiling is the *channel's*
      ceiling that it correctly saturates.
    - Adaptive depth ramping must stop at 2 MiB in flight over this transport. Ramping past
      it costs memory and buys nothing, so "grow until throughput plateaus" needs a known
      plateau rather than an open-ended search.
    - The route past 2 MiB is more channels or a native transport, not more depth. That makes
      concurrent transfers a throughput feature and not only a small-file feature.
    """
    source = random_file(tmp_path / "source.bin", 8 * MEBIBYTE)
    link = shape_link(rtt_ms=50.0)

    # Derived rather than written down, because 261120 is not a power of two: `4 * window //
    # length` is 32 requests and lands a hair *under* four windows, which is the sort of
    # off-by-a-rounding that makes a boundary test quietly assert the wrong side.
    past_window_depth = 4 * OPENSSH_CHANNEL_WINDOW // PREFERRED_READ_LENGTH + 1

    quarter_window = await timed_download(
        ssh_server, source, tmp_path / "quarter.bin", depth=16, read_length=SFTP1_BUFFER_SIZE
    )
    at_window = await timed_download(
        ssh_server, source, tmp_path / "at.bin", depth=64, read_length=SFTP1_BUFFER_SIZE
    )
    past_window = await timed_download(
        ssh_server,
        source,
        tmp_path / "past.bin",
        depth=past_window_depth,
        read_length=PREFERRED_READ_LENGTH,
    )

    assert quarter_window.in_flight == OPENSSH_CHANNEL_WINDOW // 4
    assert at_window.in_flight == OPENSSH_CHANNEL_WINDOW
    assert past_window.in_flight >= 4 * OPENSSH_CHANNEL_WINDOW

    # Below the window, bytes in flight still pay. Without this the test would also pass on a
    # link where nothing ever mattered.
    approaching = at_window.megabytes_per_second / quarter_window.megabytes_per_second
    assert approaching >= 1.5, (
        f"{link.describe()}: filling the channel window did not help "
        f"({approaching:.2f}x) -- {quarter_window}; {at_window}"
    )

    # At and past it, they do not.
    beyond = past_window.megabytes_per_second / at_window.megabytes_per_second
    assert beyond <= 1.3, (
        f"{link.describe()}: {past_window.in_flight / MEBIBYTE:.0f} MiB in flight beat "
        f"2 MiB by {beyond:.2f}x, so the ceiling is not where this test says it is -- "
        f"{at_window}; {past_window}"
    )


async def test_the_shipped_defaults_reach_the_channel_window(shape_link, ssh_server, tmp_path):
    """A user who configures nothing gets the plateau.

    The measurements above use hand-picked knobs. This one uses ``open_session`` and
    ``Session.get`` with every default in place, so what it proves is about the *shipped*
    configuration rather than about a configuration that exists only in this file. It has to
    be re-run after any change to :data:`DEFAULT_PIPELINE_DEPTH` or the size negotiation --
    a default that stops reaching the window is a silent regression, since nothing fails and
    every correctness test still passes.
    """
    assert DEFAULT_PIPELINE_DEPTH * PREFERRED_READ_LENGTH >= OPENSSH_CHANNEL_WINDOW, (
        "the shipped defaults no longer allow the channel window to be filled"
    )

    source = random_file(tmp_path / "source.bin", 8 * MEBIBYTE)
    link = shape_link(rtt_ms=50.0)

    at_window = await timed_download(
        ssh_server, source, tmp_path / "at.bin", depth=64, read_length=SFTP1_BUFFER_SIZE
    )

    destination = tmp_path / "defaults.bin"
    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        # The clock starts *inside* the session, after the handshake. Spawning `ssh` and
        # exchanging keys costs about a second at 50 ms and belongs to no pipeline depth;
        # timing it here once produced a 3x "regression" that was entirely key exchange.
        started = time.perf_counter()
        transferred = await sftp.get(str(source), destination)
        elapsed = time.perf_counter() - started

    assert transferred == file_size(source)
    assert_identical(source, destination)
    # The default path pays for STAT, OPEN and CLOSE round trips that `at_window` does not,
    # so it is allowed to be slower -- but not by more than the handful of round trips those
    # cost, which is what the additive term covers.
    budget = file_size(source) / at_window.megabytes_per_second / 1e6 * 1.4
    budget += 6 * link.measured_rtt_seconds
    assert elapsed <= budget, (
        f"{link.describe()}: Session.get at defaults took {elapsed:.3f}s against a "
        f"{budget:.3f}s budget derived from {at_window}"
    )


# --- and it still has to be correct ---------------------------------------------------------


@pytest.mark.parametrize("anyio_backend", ["asyncio", "trio"])
async def test_a_transfer_survives_latency_and_loss_and_is_byte_identical(
    shape_link, ssh_server, tmp_path, anyio_backend
):
    """1% loss at 50 ms, through the public API, on both backends.

    Loss is where a pipelined reader stops being obviously correct. Requests and replies are
    retransmitted underneath us, replies arrive later than the requests that follow them, and
    the idle timeout is sitting there waiting for a gap it must not mistake for a dead
    server. On localhost none of that happens even once.

    Both backends, unlike the timing tests: a retransmit-shaped stall is exactly the kind of
    thing an anyio backend can handle differently, and the whole justification for depending
    on anyio is that trio is supported rather than merely importable.
    """
    source = random_file(tmp_path / "source.bin", 2 * MEBIBYTE)
    destination = tmp_path / "received.bin"
    link = shape_link(rtt_ms=50.0, loss_percent=1.0)

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        transferred = await sftp.get(str(source), destination)

    assert transferred == file_size(source), link.describe()
    assert_identical(source, destination)


@pytest.mark.parametrize("anyio_backend", ["asyncio", "trio"])
async def test_a_tree_transfers_both_ways_over_a_lossy_link(
    shape_link, ssh_server, tmp_path, anyio_backend
):
    """The recursive paths, over a link that actually drops packets.

    ``get_tree`` and ``put_tree`` issue many small transfers rather than one large one, so
    they spend proportionally more of their time in the round trips that latency makes
    expensive -- OPEN, STAT, CLOSE, MKDIR -- and they are where a per-operation timeout
    tuned on localhost would first show up as a spurious failure.
    """
    source = build_tree(tmp_path / "remote")
    fetched = tmp_path / "fetched"
    returned = tmp_path / "returned"

    link = shape_link(rtt_ms=50.0, loss_percent=1.0)

    async with connect(ssh_server) as transport, open_session(transport) as sftp:
        down = await sftp.get_tree(str(source), fetched)
        up = await sftp.put_tree(fetched, str(returned))

    assert down.files == 3, link.describe()
    assert up.files == 3, link.describe()
    assert_identical(source / "daily" / "today.bin", returned / "daily" / "today.bin")
    assert_identical(
        source / "daily" / "archive" / "old.csv", returned / "daily" / "archive" / "old.csv"
    )

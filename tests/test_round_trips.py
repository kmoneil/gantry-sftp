"""What each operation costs in round trips, asserted as equalities.

This library's whole performance argument is about round trips -- DESIGN.md 5 is one formula
over bytes in flight and RTT -- and until this module existed nothing checked how many any
operation makes. ``Session.requests_sent`` has shipped since 0.9, ``repr()`` prints it, and the
suite read it once, as ``>= 4``. An inequality catches a round trip going *missing*, which is
not the direction a regression goes: nobody deletes one by accident.

Why a count rather than a time
------------------------------
A count is RTT-independent, has no run-to-run variance, needs no shaped link and no container,
and runs in milliseconds on a laptop. A latency threshold has none of those properties: it needs
``tc``, it needs samples, and it needs a threshold set above variance or it cries wolf. So the
gate that can exist here is the count, and `live-tests/test_netem_pipelining.py` is where a
number of milliseconds belongs.

It is also inside D-88 and D-94 rather than against them. **A trip count is a shape, not a
throughput figure**: it names no ratio, cites no competitor, and ages only when the code
changes -- which is exactly when someone wants to be told. It sits in the same category as "a
short DATA is not EOF": a description of the protocol conversation this library holds.

Two vehicles, because neither can do the other's job
----------------------------------------------------
**A real ``sftp-server``** for the shipped paths. A fake would only confirm that the client
sends what its author thinks it sends; the claim here is about a conversation with a real
server, including how many READs it takes to satisfy a size and where it decides a directory
has ended. No ``ssh`` and no network -- ``open_local_server_transport`` is ``sftp(1) -D``.

**The in-process :class:`~test_publish.PublishingServer`** for the publish ladder, because a
real OpenSSH cannot be made to refuse ``posix-rename@openssh.com`` and the fallback rungs are
exactly where a trip count changes without anybody choosing it.

The counting is done off the frame dump rather than off a patched encoder, which couples this
module to an observability surface on purpose: a dump that stopped covering a packet type would
be a half-shipped feature under the DoD, and here it fails a test instead. The coupling is
made safe by cross-checking every count against ``requests_sent``, so a dump that under-reports
is a failure of this module rather than a silently smaller number.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import OpenFlag
from gantry_sftp.session import Publish, Session, open_session
from gantry_sftp.transport import find_sftp_server, open_local_server_transport
from test_dispatch import DEADLINE as RENDEZVOUS_DEADLINE
from test_dispatch import Rendezvous
from test_publish import FSYNC_NAME, POSIX_RENAME_NAME, STAGED, TARGET, PublishingServer

pytestmark = pytest.mark.anyio

FRAMES_LOGGER = "gantry_sftp.frames"

DOWNLOAD_METADATA_TRIPS = 3
"""STAT, OPEN, CLOSE. What a download costs before a single byte is asked for.

Three rather than two because the STAT is load-bearing twice over: it bounds the transfer so
the reassembler knows when it is done, and it is what rung 3 of DESIGN.md 6's ladder compares
the arrived byte count against. It is also one more than it needs to be -- see D-110, where the
STAT and the OPEN are shown to have no dependency on each other on the non-resume path.
"""

IN_PLACE_UPLOAD_METADATA_TRIPS = 3
"""OPEN, CLOSE, STAT. The trailing STAT is rung 3 and has to follow the CLOSE."""

ATOMIC_PUBLISH_METADATA_TRIPS = 5
"""The two above plus ``fsync@openssh.com`` and the rename. One rung each."""

LISTING_METADATA_TRIPS = 2
"""OPENDIR and CLOSE. The READDIRs in between are the server's business, not ours."""


def requires_sftp_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


class TripCounter:
    """Outbound requests by packet type, read off the frame dump.

    Cross-checks itself against ``requests_sent`` on every measurement, so this cannot quietly
    become a test of the dumper's coverage instead of a test of the conversation.
    """

    def __init__(self, sftp: Session, caplog: pytest.LogCaptureFixture) -> None:
        self._sftp = sftp
        self._caplog = caplog

    def start(self) -> None:
        self._caplog.clear()
        self._before = self._sftp.requests_sent

    def collect(self) -> Counter[str]:
        counts: Counter[str] = Counter()
        for record in self._caplog.records:
            if record.name != FRAMES_LOGGER:
                continue
            direction, _, rest = record.getMessage().partition(" ")
            if direction == "->":
                counts[rest.split(" ", 1)[0]] += 1
        sent = self._sftp.requests_sent - self._before
        assert sum(counts.values()) == sent, (
            f"the frame dump accounted for {sum(counts.values())} requests and the counter "
            f"says {sent}; one of the two is not seeing every packet type"
        )
        return counts


async def counted(
    sftp: Session,
    caplog: pytest.LogCaptureFixture,
    operation: Callable[[], Awaitable[object]],
) -> Counter[str]:
    """Run ``operation`` and return the requests it sent, by packet type."""
    counter = TripCounter(sftp, caplog)
    counter.start()
    await operation()
    return counter.collect()


@pytest.fixture
def frames(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """The frame dump, on. It is gated on ``isEnabledFor(DEBUG)`` and emits nothing without it."""
    caplog.set_level(logging.DEBUG, logger=FRAMES_LOGGER)
    return caplog


# --- the one-request controls -------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "call"),
    [
        ("stat", lambda sftp, path: sftp.stat(str(path))),
        ("lstat", lambda sftp, path: sftp.lstat(str(path))),
        ("realpath", lambda sftp, path: sftp.realpath(str(path))),
        ("getsize", lambda sftp, path: sftp.getsize(str(path))),
    ],
)
async def test_a_metadata_query_is_exactly_one_round_trip(
    name: str,
    call: Callable[[Session, Path], Awaitable[object]],
    tmp_path: Path,
    frames: pytest.LogCaptureFixture,
) -> None:
    """The controls, and they are not decoration.

    Every count below is a difference against these. If ``stat`` ever costs two -- a REALPATH
    slipped in front of it, a cache probe, a retry that does not say so -- then every other
    number in this module moves for a reason that has nothing to do with the operation being
    measured, and without these it would look like the operation's fault.
    """
    requires_sftp_server()
    target = tmp_path / "probe.txt"
    target.write_bytes(b"x")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        counts = await counted(sftp, frames, lambda: call(sftp, target))

    assert sum(counts.values()) == 1, f"{name} sent {sum(counts.values())} requests: {counts}"


# --- the transfers --------------------------------------------------------------------------


@pytest.mark.parametrize("payloads", [0, 1, 2, 3])
async def test_a_download_costs_three_metadata_trips_and_one_read_per_request_length(
    payloads: int, tmp_path: Path, frames: pytest.LogCaptureFixture
) -> None:
    """``get`` == 3 + ceil(size / read_length), derived rather than spelled.

    The payload half is derived from the negotiated length on purpose: hard-coding it would
    make this a test of :data:`~gantry_sftp.session.PREFERRED_READ_LENGTH` wearing a
    round-trip test's clothes, and it would have to be edited by anyone who changed a constant
    that has nothing to do with how many times we speak to the server.

    Sizes bracket the boundary rather than growing round-number-wise, for the reason
    DESIGN.md 4.2 gives about request sizes generally: a client that asked for one request too
    many at exactly the length, or one too few one byte past it, is wrong in a way no
    round-number ladder can see. Zero is included because a file with nothing in it should
    cost no READ at all, and "we asked for the bytes of an empty file" is the kind of thing
    that is free to be wrong about forever.
    """
    requires_sftp_server()
    source = tmp_path / "payload.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        handle = await sftp.open(str(tmp_path), OpenFlag.READ)
        read_length = sftp.sizes_for(handle).read_length
        await sftp.close(handle)

        size = 0 if payloads == 0 else (payloads - 1) * read_length + 1
        source.write_bytes(b"q" * size)
        counts = await counted(sftp, frames, lambda: sftp.get(str(source), tmp_path / "landed.bin"))

    expected_reads = math.ceil(size / read_length)
    assert counts["READ"] == expected_reads
    assert sum(counts.values()) == DOWNLOAD_METADATA_TRIPS + expected_reads, (
        f"a {size}-byte download sent {counts}"
    )
    assert counts["STAT"] == 1
    assert counts["OPEN"] == 1
    assert counts["CLOSE"] == 1


async def test_an_in_place_upload_costs_three_metadata_trips(
    tmp_path: Path, frames: pytest.LogCaptureFixture
) -> None:
    """``put(atomic=False, fsync=False)`` == OPEN, WRITE(s), CLOSE, STAT.

    The trailing STAT is rung 3 and is the one trip here that could look removable and is not:
    it reads the size the server ended up holding, so it has to follow the CLOSE.
    """
    requires_sftp_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"z" * 1024)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        counts = await counted(
            sftp,
            frames,
            lambda: sftp.put(
                str(source), str(tmp_path / "up.bin"), publish=Publish(atomic=False, fsync=False)
            ),
        )

    assert counts["WRITE"] == 1
    assert sum(counts.values()) == IN_PLACE_UPLOAD_METADATA_TRIPS + 1, f"sent {counts}"
    assert counts["STAT"] == 1


async def test_an_atomic_publish_costs_two_more_than_an_in_place_one(
    tmp_path: Path, frames: pytest.LogCaptureFixture
) -> None:
    """What the default guarantee costs, in the unit this library reasons in.

    Two extra trips: the ``fsync@openssh.com`` barrier and the rename. README states the
    guarantee and `benchmarks/` times it; this is the number that does not need a link to be
    true, and it is the one a reader sizing a WAN drop directory actually needs.
    """
    requires_sftp_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"z" * 1024)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        counts = await counted(
            sftp, frames, lambda: sftp.put(str(source), str(tmp_path / "published.bin"))
        )

    assert counts["WRITE"] == 1
    assert counts["EXTENDED"] == 2, f"expected fsync and posix-rename, sent {counts}"
    assert sum(counts.values()) == ATOMIC_PUBLISH_METADATA_TRIPS + 1, f"sent {counts}"


async def test_a_listing_opens_once_closes_once_and_stops_at_the_first_eof(
    tmp_path: Path, frames: pytest.LogCaptureFixture
) -> None:
    """OPENDIR and CLOSE exactly once; the READDIRs in between are the server's choice.

    How many entries a server packs into one READDIR reply is its business, so the count of
    those is deliberately not pinned -- doing so would make this a test of OpenSSH. What is
    ours is that the directory is opened once and closed once, and that the EOF is believed
    the first time: a client that answered a STATUS/EOF with another READDIR would spin, and
    D-28 is that livelock with a different cause.
    """
    requires_sftp_server()
    listing = tmp_path / "drop"
    listing.mkdir()
    for index in range(4):
        (listing / f"entry-{index}").write_bytes(b"y")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        counts = await counted(sftp, frames, lambda: sftp.listdir(str(listing)))

    assert counts["OPENDIR"] == 1
    assert counts["CLOSE"] == 1
    assert counts["READDIR"] >= 2, "one reply carrying entries and one carrying EOF, at least"
    assert sum(counts.values()) == LISTING_METADATA_TRIPS + counts["READDIR"], f"sent {counts}"


async def test_every_reply_is_accounted_for_when_the_session_is_at_rest(
    tmp_path: Path,
) -> None:
    """A balanced conversation is a different fact from a counted one.

    ``requests_sent`` could be correct while a reply went to the wrong exchange or to none at
    all, and the counter would not notice. This is the cheap assertion that the two halves
    agree once everything has settled, over a mixture of operations rather than one.
    """
    requires_sftp_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"z" * 4096)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        await sftp.stat(str(source))
        await sftp.put(str(source), str(tmp_path / "up.bin"))
        await sftp.get(str(tmp_path / "up.bin"), tmp_path / "back.bin")
        await sftp.listdir(str(tmp_path))

        assert sftp.replies_received == sftp.requests_sent
        assert f"requests={sftp.requests_sent}/{sftp.replies_received}" in repr(sftp)


# --- the publish ladder, where the count changes without anybody choosing it -----------------


async def test_falling_through_a_publish_rung_costs_the_trips_that_rung_would_have_spent(
    tmp_path: Path,
) -> None:
    """The three mechanisms have three different costs, and nothing said what they were.

    This is the case a real OpenSSH cannot produce: it advertises and implements
    ``posix-rename@openssh.com``, so the fallback rungs are only reachable against a server
    that does not. Every endpoint DESIGN.md 7 is written for is such a server, which makes the
    untested rungs the ones the target deployments actually take.

    ``remove-rename`` is the expensive one and it is expensive for a reason worth having a
    number for: it is the rung that is **not atomic**, so a caller paying an extra round trip
    is also the caller getting the weakest guarantee.
    """
    payload = tmp_path / "report.csv"
    payload.write_bytes(b"id,total\n1,42\n")

    async def publish_onto(*, extensions: tuple[bytes, ...], occupied: bool) -> list[str]:
        server = PublishingServer(
            extensions=extensions,
            files={TARGET: b"previous"} if occupied else None,
        )
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            await sftp.put(payload, TARGET, publish=Publish(fsync=False, staging_name=STAGED))
        # `Init` is the handshake rather than an operation, and it is what `requests_sent`
        # excludes on the real-server side of this module. Dropped here so the two halves
        # count the same thing.
        return [kind for kind in server.kinds() if kind != "Init"]

    posix = await publish_onto(extensions=(POSIX_RENAME_NAME, FSYNC_NAME), occupied=True)
    plain = await publish_onto(extensions=(), occupied=False)
    removing = await publish_onto(extensions=(), occupied=True)

    assert posix == ["Open", "Write", "Close", "Stat", POSIX_RENAME_NAME.decode()]

    # One more than the rung above, and the extra one is the *probe*: the extension is tried
    # before it is known to be absent, because an advertisement is a claim and only an answer
    # is definitive (`Session.refuses`). Paid once per session -- asserted below, because an
    # uncached probe would put this round trip back on every file.
    assert plain == ["Open", "Write", "Close", "Stat", POSIX_RENAME_NAME.decode(), "Rename"]

    # Four more than the top rung, and this is the row worth having a number for: it is the
    # endpoint class DESIGN.md 7 is written for -- MOVEit, GoAnywhere, Cleo, Sterling, which
    # advertise none of these extensions -- publishing over a name that already exists. The
    # optimistic RENAME has to be sent and has to fail, because v3 RENAME cannot overwrite and
    # there is no way to ask whether it would; the LSTAT is what distinguishes a taken name
    # from a dangling link; and only then can the REMOVE and the second RENAME run. It is also
    # the rung that is not atomic, so the caller paying the most gets the weakest guarantee.
    assert removing == [
        "Open",
        "Write",
        "Close",
        "Stat",
        POSIX_RENAME_NAME.decode(),
        "Rename",
        "LStat",
        "Remove",
        "Rename",
    ]


async def test_an_extension_is_probed_once_per_session_and_not_once_per_file(
    tmp_path: Path,
) -> None:
    """The refusal cache is a round trip per file on the servers that can least afford one.

    ``Session.refuses`` exists so that an ``OP_UNSUPPORTED`` answer is remembered, and its
    docstring gives the correctness reason -- only that status is definitive, a permission
    error is a fact about one path. This is the *cost* reason, which nothing asserted: on a
    server advertising no extensions, ``put_tree`` over a drop directory would otherwise send
    a doomed ``posix-rename@openssh.com`` before every single file.

    Asserted as "the second upload is strictly shorter than the first, by exactly the probe",
    rather than as a count, so it keeps meaning what it says if a rung is ever added.
    """
    payload = tmp_path / "report.csv"
    payload.write_bytes(b"id,total\n1,42\n")
    server = PublishingServer(extensions=(), files={TARGET: b"previous"})
    conversations: list[list[str]] = []

    async with open_session(server) as sftp:  # type: ignore[arg-type]
        for _ in range(3):
            mark = len(server.seen)
            await sftp.put(payload, TARGET, publish=Publish(fsync=False, staging_name=STAGED))
            conversations.append(server.kinds()[mark:])
        assert sftp.refuses(POSIX_RENAME_NAME), "the refusal was not recorded"

    first, second, third = conversations
    assert POSIX_RENAME_NAME.decode() in first, "the first upload has to find out"
    assert POSIX_RENAME_NAME.decode() not in second, "and no upload after it should ask again"
    assert second == third
    assert len(first) == len(second) + 1, (
        "the probe is exactly one round trip, and it should be the only difference"
    )


# --- and the serial depth, which is what D-110 actually changed ------------------------------


async def test_a_download_puts_its_stat_and_open_in_flight_together(tmp_path: Path) -> None:
    """The count did not move and the *depth* did, so the count cannot be what proves it.

    ``get`` still sends four requests -- the test above pins that -- and D-110 did not remove
    one, it removed a *wait*. The STAT and the OPEN are both addressed by path and neither
    reads the other's answer, so on the default path the ordering between them was incidental.

    Proved with :class:`~test_dispatch.Rendezvous` rather than with a clock. It answers nothing
    until two requests are waiting on it, so a client that sends its STAT and waits for the
    reply before sending its OPEN can never make it respond: this test either passes because
    the two were genuinely in flight together, or it hangs and fails on the deadline. There is
    no threshold to tune and nothing a fast machine can fake, which a latency assertion could
    not manage on any link this suite can shape.
    """
    payload = bytes(range(256)) * 3
    server = Rendezvous({b"/incoming.bin": payload}, release_at=2)

    with anyio.fail_after(RENDEZVOUS_DEADLINE):
        async with open_session(server) as sftp:  # type: ignore[arg-type]
            moved = await sftp.get(b"/incoming.bin", tmp_path / "landed.bin")

    assert moved == len(payload)
    assert (tmp_path / "landed.bin").read_bytes() == payload
    held = [{type(request).__name__ for request in waiting} for waiting in server.rendezvous]
    assert {"Stat", "Open"} in held, f"the barrier was met, but not by the STAT/OPEN pair: {held}"


async def test_a_resumed_download_keeps_its_stat_and_open_sequential(tmp_path: Path) -> None:
    """The exemption, asserted as an exemption rather than left to the ``resume=`` branch.

    Resuming needs the size before anything else happens: the offset is derived from it, the
    D-38 gate refuses on it, and a resume of an already-complete file returns **without opening
    anything at all**. Issuing the OPEN concurrently there would send a request for a transfer
    that is not going to happen, and on the complete-file path would leak the handle it opened.

    Asserted at the seam rather than through ``get``, because what is being pinned is that the
    resume path asks for the sequential form -- a test that only checked a resumed download
    still worked would pass over a version that had quietly made it concurrent.
    """
    requires_sftp_server()
    source = tmp_path / "source.bin"
    source.write_bytes(b"z" * 4096)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        before = sftp.requests_sent
        attributes, handle = await sftp._stat_and_open_for_download(  # noqa: SLF001
            str(source).encode(), together=False
        )
        assert sftp.requests_sent - before == 1, "the sequential form sent more than the STAT"
        assert handle is None, (
            "the sequential form opened a handle the resume path had not asked for"
        )
        assert attributes.size == 4096

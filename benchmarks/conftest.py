"""Fixtures for the benchmark lane: a real server, a shaped link, and a corpus.

The server and the shaping come from ``live-tests/`` rather than from a copy here. That
directory is not a package, so it is put on ``sys.path`` explicitly -- which is ugly and is
still the right trade. The alternative is a second implementation of "start an sshd and scrub
the ssh environment", and the moment there are two, one of them stops being scrubbed and the
benchmark starts quietly measuring the developer's ``ssh_config``.

**These tests run on asyncio only.** ``asyncssh`` is asyncio-native, so a trio parametrisation
could not run two of the three clients; and for the one that could, elapsed time is a property
of the wire rather than of the event loop. The netem lane reached the same conclusion for the
same reason, and the correctness-under-loss tests that genuinely need both backends live
there.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import pytest

_LIVE_TESTS = Path(__file__).resolve().parent.parent / "live-tests"
if str(_LIVE_TESTS) not in sys.path:
    sys.path.insert(0, str(_LIVE_TESTS))

from netem import ShapedLink, release_loopback, shape, unavailable_reason  # noqa: E402
from sshd import ServerUnavailableError, SSHServer, running_sshd  # noqa: E402

LARGE_FILE_BYTES = 16 * 1024 * 1024
"""Big enough that the transfer, not the handshake, is what is being timed.

Sixteen MiB is eight times the 2 MiB channel window of DESIGN.md 5.1, so a client that fills
the window is distinguishable from one that does not; and at 200 ms RTT it still finishes in
under two seconds, which is what keeps the whole matrix inside a few minutes.
"""

SMALL_FILE_BYTES = 8 * 1024
"""Small enough that the cost is round trips rather than bytes -- the small-file case."""

SWEEP_LADDER: tuple[tuple[int, str], ...] = (
    (4 * 1024, "one request, one round trip"),
    (32 * 1024, "SSH max packet; above paramiko#2438's 32675-byte write cliff"),
    (64 * 1024, "two SSH packets -- one per request is no longer enough"),
    (128 * 1024, "half a request"),
    (261120, "exactly one request -- OpenSSH's `max-read-length`"),
    (262144, "1 KiB more: two requests, and the round number DESIGN.md 4.2 forbids"),
    (1024 * 1024, "four requests, inside the 2 MiB channel window"),
    (2 * 1024 * 1024, "the 2 MiB channel window itself"),
    (8 * 1024 * 1024, "32 requests -- window-bound, depth not yet binding"),
    (16 * 1024 * 1024, "past depth x request size (64 x 261120); the matrix's own size"),
)
"""Sizes the throughput-against-size sweep visits, and what each one brackets (D-92).

A geometric ladder rather than round numbers, because **the point of the sweep is the
boundaries**: what people report against the incumbent is a cliff at a byte count -- writing
more than 32675 bytes costing 99% of the throughput (`paramiko#2438`), one API running 25x
another (`paramiko#2453`) -- and a cliff is only visible if a size sits either side of the
boundary it would hide on. Every design boundary this library has is bracketed here: the
single-request case, the SSH packet size, the derived `max-read-length` (255 KiB, *not* 256 --
DESIGN.md 4.2), the crossing from one request to two, the 2 MiB channel window, and the
pipeline depth x request size product past which depth rather than file size is the limit.

The whole ladder is 27.8 MiB on disk, written once per session.
"""


@dataclass(frozen=True, slots=True)
class SweepFile:
    """One rung of :data:`SWEEP_LADDER`, on disk.

    Attributes:
        size_bytes: Its size, which is what the sweep plots against.
        note: What boundary it brackets, carried into the report so a reader does not have to
            recognise the number to know why the row exists.
        path: Where it is. The same file is the download source and the upload source -- the
            server serves this filesystem over loopback, so a second copy would buy nothing
            but a second thing to keep in step.
    """

    size_bytes: int
    note: str
    path: Path


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def ssh_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SSHServer]:
    """A running sshd serving the sftp subsystem, or a skip saying what is missing."""
    root = tmp_path_factory.mktemp("bench-sshd")
    try:
        with running_sshd(root) as server:
            yield server
    except ServerUnavailableError as exc:
        pytest.skip(str(exc))


def _fill(path: Path, size: int, seed: int) -> None:
    """Write ``size`` deterministic bytes.

    Deterministic rather than random so two runs move identical data -- a benchmark whose
    input changes between runs has one more reason for a number to move, and it is the one
    reason that is not the code.
    """
    block = bytes((i * 7 + seed) % 256 for i in range(4096))
    with path.open("wb") as handle:
        written = 0
        while written < size:
            chunk = block[: min(len(block), size - written)]
            handle.write(chunk)
            written += len(chunk)


@dataclass(frozen=True, slots=True)
class Corpus:
    """What every scenario transfers, named rather than looked up by string.

    A dataclass rather than the ``dict[str, object]`` this used to be. That dict cost its one
    consumer four ``assert isinstance`` lines to get typed paths back out, which is the shape of
    boilerplate that grows a statement every time a scenario needs a new file -- and it was
    already enough to push the profile test over ruff's statement ceiling when D-113 added a row.

    Attributes:
        large: The 16 MiB file the download scenarios fetch.
        small: The 8 KiB files, in a fixed order so a ``[:count]`` slice is the same corpus on
            every profile.
        upload_source: A local 16 MiB file, distinct from ``large`` so an upload that silently
            did nothing cannot be verified against the file it was supposed to have sent.
        upload_dir: Where uploads land on the server.
    """

    large: Path
    small: tuple[Path, ...]
    upload_source: Path
    upload_dir: Path


@pytest.fixture(scope="session")
def corpus(ssh_server: SSHServer) -> Corpus:
    """Files on the server for the clients to fetch, and a local file to send.

    Session-scoped: building 16 MiB per profile would put the file system in the measurement.
    """
    root = ssh_server.root / "corpus"
    root.mkdir(exist_ok=True)

    large = root / "large.bin"
    _fill(large, LARGE_FILE_BYTES, seed=1)

    small_dir = root / "small"
    small_dir.mkdir(exist_ok=True)
    small = []
    for index in range(200):
        item = small_dir / f"part-{index:04d}.bin"
        _fill(item, SMALL_FILE_BYTES, seed=index)
        small.append(item)

    upload_source = root / "upload-source.bin"
    _fill(upload_source, LARGE_FILE_BYTES, seed=2)

    destinations = ssh_server.root / "uploads"
    destinations.mkdir(exist_ok=True)

    return Corpus(
        large=large,
        small=tuple(small),
        upload_source=upload_source,
        upload_dir=destinations,
    )


@pytest.fixture(scope="session")
def sweep_corpus(ssh_server: SSHServer) -> tuple[SweepFile, ...]:
    """One file per rung of :data:`SWEEP_LADDER`, ascending.

    Session-scoped and requested lazily by the profiles that sweep, so a ``-k`` selection that
    runs no sweep writes no 27.8 MiB.
    """
    root = ssh_server.root / "sweep"
    root.mkdir(exist_ok=True)
    files = []
    for size, note in SWEEP_LADDER:
        path = root / f"size-{size}.bin"
        # Seeded by size, so two rungs never hold each other's bytes -- a verification that
        # compares the wrong pair of files would pass by accident on identical content.
        _fill(path, size, seed=size % 251)
        files.append(SweepFile(size_bytes=size, note=note, path=path))
    return tuple(files)


ShapeLink = Callable[..., ShapedLink]


@pytest.fixture(scope="session", autouse=True)
def _loopback_is_left_unshaped() -> Iterator[None]:
    """Leave the interface the way we found it, even if a run died holding a profile.

    A 200 ms delay left on loopback does not fail anything. It silently degrades every later
    test and every later benchmark in this container, and the next run would report it as a
    regression in the library.
    """
    yield
    release_loopback()


@pytest.fixture
def shape_link(ssh_server: SSHServer) -> Iterator[ShapeLink]:
    """Shape loopback for one test, or skip saying exactly what would fix it.

    Depends on ``ssh_server`` so the server is listening and its host key scanned before the
    link degrades -- starting a server through a 200 ms link spends the startup budget on key
    exchange and reports it as the server failing to start.
    """
    reason = unavailable_reason()
    if reason is not None:
        pytest.skip(reason)

    with ExitStack() as stack:

        def _shape(
            *, rtt_ms: float, loss_percent: float = 0.0, rate_mbit: float | None = None
        ) -> ShapedLink:
            return stack.enter_context(
                shape(rtt_ms=rtt_ms, loss_percent=loss_percent, rate_mbit=rate_mbit)
            )

        yield _shape

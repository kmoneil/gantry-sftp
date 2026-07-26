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


@pytest.fixture(scope="session")
def corpus(ssh_server: SSHServer) -> dict[str, object]:
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

    return {
        "large": large,
        "small": small,
        "upload_source": upload_source,
        "upload_dir": destinations,
    }


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

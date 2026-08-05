"""Shared fixtures.

Anything that reaches outside the process is located explicitly and skips with a reason
when absent, rather than failing. A test that only passes on a machine with the right
packages installed is a test that reports the machine, not the code.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import Codec
from gantry_sftp.exceptions import _flatten_exception_group
from gantry_sftp.session import Dispatcher
from gantry_sftp.transport import Transport
from leakcheck import leak_check_enabled, settle


@asynccontextmanager
async def running_dispatcher(
    transport: Transport, codec: Codec, *, send_timeout: float | None = None
) -> AsyncGenerator[Dispatcher]:
    """A dispatcher with its reader task running, stopped when the block ends.

    What `open_session` does, minus the handshake, for the tests that drive `download_handle`
    and `upload_handle` directly. The flatten is not decoration: an anyio task group wraps
    even a single failure in an `ExceptionGroup`, so without it every
    `pytest.raises(TransferError)` in this suite would stop matching -- and the ones asserting
    on a message would fail with a group instead of proving anything.

    `close()` is what stops the reader, and cancelling `reader.cancel_scope` would not: the
    reader is shielded (D-34). Mirroring production matters here beyond tidiness -- a helper
    that stopped the reader some other way would prove the fixture, not the library.

    `send_timeout` defaults to none, matching `Dispatcher` itself: the bound arrives from
    `open_session`, and a fixture that supplied one of its own would test the fixture.
    """
    dispatcher = Dispatcher(transport, codec, send_timeout=send_timeout)
    try:
        async with anyio.create_task_group() as reader:
            reader.start_soon(dispatcher.run)
            reader.start_soon(dispatcher.reap_orphans)
            try:
                yield dispatcher
            finally:
                dispatcher.close()
    except BaseExceptionGroup as group:
        raise _flatten_exception_group(group) from None


async def negotiate(transport: Transport) -> Codec:
    """Drive the handshake over an in-process fake and hand back the ready codec."""
    codec = Codec()
    await transport.send(codec.initiate())
    while codec.state.name != "READY":
        codec.receive(await transport.receive())
    return codec


@pytest.fixture(autouse=True)
def _no_leaked_resources(request: pytest.FixtureRequest):
    """Fail the test that leaked a transport, a session or a child process (D-115).

    Armed by ``GANTRY_SFTP_LEAK_CHECK`` and inert otherwise: it makes two full passes over
    ``gc.get_objects()`` per test, a cost that scales with the live heap rather than being a
    flat per-test constant, and lands about an order of magnitude above the default lane over
    the whole suite. `scripts/lanes.py leaks` is the spelling that arms it.

    **The point is which test fails, not that one does.** The last leak of this shape
    (`Process.aclose()` never called) showed up as failures in unrelated *later* tests, so the
    message names the type that survived and the test that left it behind.

    See :mod:`tests.leakcheck` for why this counts a few named types rather than bytes or the
    total object count -- both of which see the leaks and neither of which can be thresholded,
    with the numbers that settled it.
    """
    if not leak_check_enabled():
        yield
        return

    before = settle()
    yield
    # **Drop pytest's own reference to every fixture value before measuring.** A yield-fixture
    # that hands back a session is torn down before this finalizer runs -- its `with` blocks
    # have exited and the session is closed -- but `item.funcargs` still holds the yielded
    # object, and pytest does not clear that until after this fixture is finished. So the
    # object is closed, unreachable by anything that matters, and still counted: every test in
    # `test_sync_forwarding.py` reported `Dispatcher +1, Process +2, Session +1,
    # SubprocessTransport +1`, 140 of them, none of which had leaked anything. Reproduced down
    # to a twelve-line file whose only content was a fixture yielding a session.
    #
    # **Cleared rather than excluded, and the difference is the whole point.** Skipping objects
    # that appear in `funcargs` would also skip a fixture that genuinely failed to close one.
    # Removing only *pytest's* reference leaves every other reference intact, so a real leak --
    # something still holding the object for its own reasons -- still counts. That is what
    # keeps `test_it_catches_an_abandoned_async_generator_chain` working: the chain it abandons
    # holds a *closed* transport, which is exactly the shape this check must keep reporting.
    request.node.funcargs.clear()
    after = settle()

    grown = after.growth_since(before)
    if grown:
        detail = ", ".join(f"{name} +{count}" for name, count in grown.items())
        pytest.fail(
            f"{request.node.nodeid} leaked: {detail}. These objects were still alive after "
            f"two gc.collect() passes, so something still references them. A transport, "
            f"session or process that outlives its test will be blamed on a later one -- see "
            f"tests/leakcheck.py."
        )


@pytest.fixture(params=["asyncio", "trio"])
def anyio_backend(request: pytest.FixtureRequest) -> str:
    """Run every async test on both anyio backends.

    The entire reason this library uses anyio rather than asyncio is that it costs nothing
    and buys trio support. Running the async suite on trio too is what turns that from a
    claim into a fact -- an anyio-shaped codebase that has only ever run on asyncio is one
    accidental ``asyncio.Queue`` away from not supporting trio at all.
    """
    return str(request.param)


# sftp-server ships in openssh-server, not openssh-client, and distributions disagree about
# where it lives. These are the three locations in the wild.
SFTP_SERVER_CANDIDATES = (
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
)


def find_sftp_server() -> Path | None:
    """Locate the OpenSSH sftp-server binary, or return ``None``."""
    for candidate in SFTP_SERVER_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return path
    found = shutil.which("sftp-server")
    return Path(found) if found else None


@pytest.fixture(scope="session")
def sftp_server_binary() -> Path:
    """Path to a real OpenSSH sftp-server, skipping the test if none is installed."""
    path = find_sftp_server()
    if path is None:
        pytest.skip(
            "sftp-server not found; install openssh-server to run the real-server lane "
            f"(looked in {', '.join(SFTP_SERVER_CANDIDATES)} and $PATH)"
        )
    return path


# The environment-scrubbing helper that used to live here now lives in live-tests/sshd.py,
# where something actually spawns ssh against a server that can authenticate it, and where
# live-tests/test_ssh_environment.py asserts what it does. Nothing in tests/ reaches an
# ssh_config: the ssh calls here either pass `config_file=os.devnull`, run a fake ssh that
# is a script and reads no config at all, or fail during argv validation before a process
# exists. So keeping a fixture nobody used was decoration that looked like a safeguard.


# --- what the local filesystem will actually hold -------------------------------------------


def _filesystem_holds_non_utf8_names() -> bool:
    """Whether this machine's temporary filesystem can hold a name that is not valid UTF-8.

    **Linux can; macOS cannot, and it is the filesystem refusing rather than Python.** APFS and
    HFS+ validate that a name is UTF-8 and answer `OSError: [Errno 92] Illegal byte sequence`,
    so a fixture building such a name errors every test that takes it -- 98 in `test_fsspec.py`
    and the whole real-server row in `test_glob.py`, on the first CI run with a macOS job.

    Probed rather than keyed to `sys.platform`, which is this repository's rule everywhere else
    it asks what the environment can do -- netem, Docker, `sftp-server`. The property belongs to
    the *filesystem*: a UTF-8-enforcing mount can appear under Linux too, and a Mac with a
    suitable mount would be wrongly skipped by a platform check.

    Lives here rather than in either test module because both need it and a probe answered two
    different ways in two files is worse than a probe answered once. `D-150` covers the half
    this does not: what the *library* does when a legal remote name cannot be written locally.
    """
    with tempfile.TemporaryDirectory() as probe:
        try:
            (Path(probe) / "\udce9").touch()
        except OSError:
            return False
        return True


HOLDS_NON_UTF8_NAMES = _filesystem_holds_non_utf8_names()
"""Set once: probing per test would ask the filesystem hundreds of times."""

needs_non_utf8_names = pytest.mark.skipif(
    not HOLDS_NON_UTF8_NAMES,
    reason="this filesystem rejects names that are not valid UTF-8 (macOS APFS/HFS+ does)",
)
"""For tests asserting *on* such a name, as opposed to those that merely tolerate one."""


def give_one_file_a_second_name(first: Path, second: Path) -> None:
    """Make ``second`` another name for ``first``, however this filesystem gets there.

    **A hard link is the stand-in for case folding, and the stand-in breaks where the real thing
    lives.** On a case-sensitive filesystem `README.md` and `readme.md` are two entries, so a
    link is what produces the two-names-one-inode condition the destination-collision checks are
    about. On APFS or NTFS the filesystem already folds them together -- `second` *is* `first` --
    and `os.link` answers `FileExistsError` rather than obliging.

    That is not hypothetical: seven call sites and one example failed exactly this way on the
    first macOS CI run, with `[Errno 17] File exists: '.../README.md' -> '.../readme.md'`. The
    hazard was present and the simulation of it was what broke.

    So the fold is used where it exists and reproduced where it does not, and neither branch is
    a skip: the property under test -- two names, one file -- holds on both, which is the whole
    reason these tests can run anywhere.
    """
    if second.exists():
        return
    os.link(first, second)

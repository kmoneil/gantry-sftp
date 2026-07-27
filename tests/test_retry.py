"""Retry: what counts as retryable, and what a reconnect actually re-runs.

The classification is most of the value and all of the danger. Retrying the wrong error is
not merely wasteful -- retrying a failed authentication walks into OpenSSH's
``PerSourcePenalties``, which locks out the *source address*, so a retry loop turns one
rejected key into a host that stops answering for everything behind that IP.

The end-to-end proof at the bottom kills a real connection partway through a real transfer
and finishes it on a new one, because "reconnect and resume" is a claim about two connections
agreeing on an offset and nothing smaller than two connections can test it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

import anyio
import anyio.lowlevel
import pytest

from gantry_sftp.codec import StatusCode
from gantry_sftp.exceptions import (
    AuthenticationError,
    CapabilityError,
    ConnectError,
    HostKeyError,
    NoSuchFileError,
    PermissionDeniedError,
    ProtocolError,
    ServerError,
    StateError,
    TransferError,
    TransferTimeoutError,
    UnsafePathError,
    UnsupportedError,
)
from gantry_sftp.session import Session, is_retryable, with_reconnect
from gantry_sftp.transport import Transport, find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio


def server_error(code: StatusCode) -> ServerError:
    return ServerError(f"server returned {code.name}", code=int(code), message=code.name.encode())


# --- classification ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ConnectError("the link dropped"),
        TransferTimeoutError("the far end went quiet"),
        server_error(StatusCode.CONNECTION_LOST),
        server_error(StatusCode.NO_CONNECTION),
    ],
)
def test_a_broken_link_is_worth_another_attempt(error: BaseException):
    assert is_retryable(error)


@pytest.mark.parametrize(
    "error",
    [
        NoSuchFileError("gone", code=2, message=b"No such file"),
        PermissionDeniedError("no", code=3, message=b"Permission denied"),
        UnsupportedError("no such extension", code=8, message=b"Operation unsupported"),
        server_error(StatusCode.FAILURE),
        ProtocolError("the framing is wrong"),
        TransferError("the server refused a read"),
        UnsafePathError("that name escapes", name=b"../x", reason="traversal"),
        StateError("the session is closed"),
        CapabilityError("cannot publish atomically", feature="atomic upload"),
    ],
)
def test_a_terminal_failure_is_not_retried(error: BaseException):
    assert not is_retryable(error)


def test_a_failed_authentication_is_never_retried():
    """Not merely wasteful -- actively harmful, which is why it is called out separately.

    ``AuthenticationError`` and ``HostKeyError`` are both ``ConnectError`` subclasses, so the
    "a broken link is retryable" rule would sweep them in. OpenSSH 9.8+ applies
    ``PerSourcePenalties``: repeated failed authentication from one address gets that address
    progressively locked out. A retry loop therefore turns one wrong key into an outage for
    everything sharing that IP. Credentials do not become correct by being offered again.
    """
    assert not is_retryable(AuthenticationError("Permission denied (publickey)"))
    assert not is_retryable(HostKeyError("Host key verification failed"))
    # And the base class they derive from still is, so the exclusion is doing real work.
    assert is_retryable(ConnectError("ssh exited while we were writing to it"))


def test_a_catch_all_failure_is_terminal_and_that_is_a_decision():
    """DESIGN.md 6 asks for "transient FAILURE" to be distinguished. It cannot be.

    v3's ``FAILURE`` is the catch-all that a permission problem, a full disk, a name
    collision and a momentary appliance hiccup all arrive as. Retrying it treats every
    terminal error as transient and turns one fast, clear failure into three slow ones with
    the same message. Terminal until the quirks layer can match a server's message text.
    """
    assert not is_retryable(server_error(StatusCode.FAILURE))


def test_several_failures_at_once_are_not_retried():
    # No single answer to classify, and not retrying is the safe direction. It should not
    # arise: the reader task records its failure rather than raising it, so an operation sees
    # one flat error rather than a group.
    group = ExceptionGroup("two at once", [ConnectError("dropped"), ConnectError("also dropped")])
    assert not is_retryable(group)


# --- the driver --------------------------------------------------------------------------------


class Recipe:
    """A connection recipe that counts how many times it was asked for a transport."""

    def __init__(self, make: Callable[[], object]) -> None:
        self._make = make
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self._make()


@asynccontextmanager
async def unusable_transport() -> AsyncIterator[Transport]:
    """A recipe that never yields anything, because the operation never runs."""
    raise ConnectError("could not connect")
    yield  # pragma: no cover -- unreachable, and required to make this a generator


async def unreached(_sftp: Session) -> None:
    """An operation for the tests where connecting fails first, so it never runs."""
    await anyio.lowlevel.checkpoint()


async def test_a_terminal_failure_is_raised_without_reconnecting(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    recipe = Recipe(partial(open_local_server_transport, cwd=tmp_path))

    with pytest.raises(NoSuchFileError):
        _ = await with_reconnect(recipe, lambda sftp: sftp.stat(b"/definitely/not/here"), backoff=0)

    assert recipe.calls == 1, "a terminal error must not spend a second connection"


async def test_a_retryable_failure_from_the_operation_gets_a_fresh_session(tmp_path: Path):
    # The failure need not come from the transport. Anything the operation raises is
    # classified the same way, and a retry means a new session rather than a second go on
    # the old one -- which matters, because nothing survives a reconnect.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    identities: set[int] = set()

    async def flaky(sftp: Session) -> str:
        identities.add(id(sftp))
        if len(identities) < 3:
            raise ConnectError("ssh exited while we were writing to it")
        return "done"

    recipe = Recipe(partial(open_local_server_transport, cwd=tmp_path))

    assert await with_reconnect(recipe, flaky, attempts=3, backoff=0) == "done"
    assert recipe.calls == 3
    # Ids only: holding the Session objects would keep three dead transports alive until the
    # garbage collector felt like running, which surfaces as an unraisable ResourceWarning
    # attributed to whatever unrelated test happens to be running at the time.
    assert len(identities) == 3, "the same session was handed back"


async def test_attempts_below_one_is_refused():
    with pytest.raises(ValueError) as exc:
        _ = await with_reconnect(unusable_transport, unreached, attempts=0)
    assert exc.value.args[0] == "attempts must be at least 1, got 0"


async def test_a_recipe_that_cannot_connect_is_retried_and_then_gives_up():
    recipe = Recipe(unusable_transport)

    with pytest.raises(ConnectError) as exc:
        _ = await with_reconnect(recipe, unreached, attempts=3, backoff=0)

    assert recipe.calls == 3, "it did not use all the attempts it was given"
    assert exc.value.__notes__ == ["gave up after 3 of 3 attempt(s), all retryable"]


async def test_a_single_attempt_carries_no_note_about_attempts():
    # A note on a first-and-only failure is noise on every terminal error, and the common
    # case for this helper is an operation that works immediately.
    recipe = Recipe(unusable_transport)

    with pytest.raises(ConnectError) as exc:
        _ = await with_reconnect(recipe, unreached, attempts=1, backoff=0)

    assert recipe.calls == 1
    assert not hasattr(exc.value, "__notes__")


async def test_the_backoff_doubles_and_is_capped(monkeypatch: pytest.MonkeyPatch):
    slept: list[float] = []

    async def record(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("gantry_sftp.session._retry.anyio.sleep", record)
    recipe = Recipe(unusable_transport)

    with pytest.raises(ConnectError):
        _ = await with_reconnect(recipe, unreached, attempts=6, backoff=1.0, backoff_max=4.0)

    # Five waits for six attempts, doubling until the ceiling holds it.
    assert slept == [1.0, 2.0, 4.0, 4.0, 4.0]


async def test_cancellation_is_not_a_retryable_failure(tmp_path: Path):
    """The line that keeps a cancelled transfer cancelled.

    anyio's cancelled exception derives from ``BaseException`` on both backends, so catching
    ``Exception`` rather than ``BaseException`` is what stops this helper from swallowing a
    caller's cancellation and dutifully reconnecting.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    recipe = Recipe(partial(open_local_server_transport, cwd=tmp_path))

    async def never_finishes(_sftp: Session) -> None:
        await anyio.sleep(60)

    with anyio.move_on_after(0.05):
        await with_reconnect(recipe, never_finishes, attempts=5, backoff=0)

    assert recipe.calls == 1, "a cancelled operation was retried"


async def test_an_operation_that_succeeds_runs_once(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    (tmp_path / "a.csv").write_bytes(b"one")
    recipe = Recipe(partial(open_local_server_transport, cwd=tmp_path))

    listing = await with_reconnect(recipe, lambda sftp: sftp.listdir(str(tmp_path)), backoff=0)

    assert [entry.name for entry in listing] == ["a.csv"]
    assert recipe.calls == 1


# --- reconnect and resume, over a connection that really dies ----------------------------------


class DyingTransport:
    """A real transport that stops working partway, the way a dropped link does.

    Wrapping a real one rather than scripting a fake: the handshake, the limits probe and the
    transfer all have to happen for real up to the point of death, or what is resumed from is
    an offset this test invented rather than one the server and the scheduler agreed on.
    """

    def __init__(self, inner: Transport, *, die_after_bytes: int) -> None:
        self._inner = inner
        self._budget = die_after_bytes
        self.delivered = 0

    async def send(self, data: bytes | memoryview) -> None:
        await self._inner.send(data)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if self.delivered >= self._budget:
            raise ConnectError("connection closed by the remote end", returncode=255)
        chunk = await self._inner.receive(max_bytes)
        self.delivered += len(chunk)
        return chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


async def test_a_connection_that_dies_mid_transfer_reconnects_and_resumes(tmp_path: Path):
    """The card's closure condition, end to end.

    One real connection carries part of a file and then dies. A second one, made by the same
    recipe, finishes it from where the first stopped. The two halves are compared byte for
    byte against random content, because a resume that got the offset wrong produces a file
    of exactly the right length.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    payload = bytes(range(256)) * 8_000  # 2 MB, many receives past the handshake
    source = tmp_path / "big.bin"
    source.write_bytes(payload)
    local = tmp_path / "copy.bin"
    connections = 0

    @asynccontextmanager
    async def dies_once() -> AsyncIterator[Transport]:
        nonlocal connections
        connections += 1
        async with open_local_server_transport(cwd=tmp_path) as transport:
            if connections > 1:  # the second attempt gets a healthy connection
                yield transport
            else:
                yield DyingTransport(transport, die_after_bytes=400_000)

    recipe = Recipe(dies_once)
    moved = await with_reconnect(
        recipe,
        lambda sftp: sftp.get(str(source), local, resume=True),
        attempts=3,
        backoff=0,
    )

    assert recipe.calls == 2, "the first connection did not die, so nothing was resumed"
    partial_size = len(payload) - moved
    assert 0 < partial_size < len(payload), "the first attempt transferred nothing to resume from"
    assert local.read_bytes() == payload


async def test_a_dying_connection_without_resume_still_finishes_it_from_zero(tmp_path: Path):
    # Retry without resume is correct and wasteful, not broken -- worth pinning, because a
    # caller who forgets `resume=True` should get a right answer slowly rather than a wrong
    # one quickly.
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    payload = bytes(range(256)) * 8_000
    source = tmp_path / "big.bin"
    source.write_bytes(payload)
    local = tmp_path / "copy.bin"
    connections = 0

    @asynccontextmanager
    async def dies_once() -> AsyncIterator[Transport]:
        nonlocal connections
        connections += 1
        async with open_local_server_transport(cwd=tmp_path) as transport:
            if connections > 1:
                yield transport
            else:
                yield DyingTransport(transport, die_after_bytes=400_000)

    moved = await with_reconnect(
        Recipe(dies_once), lambda sftp: sftp.get(str(source), local), attempts=3, backoff=0
    )

    assert moved == len(payload), "without resume the second attempt must send the whole file"
    assert local.read_bytes() == payload

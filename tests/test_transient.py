"""Repeating one request on a live session, and the four ways it must refuse to.

D-30's retry is the first behavioural rule the quirks registry has ever carried, so most of
this file is about what it declines to do. The condition it exists for -- a server refusing an
``OPEN`` because it is out of descriptors, and answering the identical request once one is
released -- is proved against a real server in ``live-tests/test_transient_live.py``; what is
proved here is the classification and the bound, which need no server at all.

The mutation-relevant part is that every constant in the ladder is asserted rather than
exercised: an attempt count that is off by one still passes a "it eventually succeeded" test.
"""

from __future__ import annotations

import logging

import anyio
import pytest

from gantry_sftp._logging import LOG_FIELDS
from gantry_sftp.codec import OpenFlag, StatusCode
from gantry_sftp.exceptions import NoSuchFileError, ProtocolError, ServerError
from gantry_sftp.session import PROFILES, UNKNOWN, ServerProfile, identify
from gantry_sftp.session._transient import (
    TRANSIENT_ATTEMPTS,
    TRANSIENT_BACKOFF,
    TRANSIENT_BACKOFF_MAX,
    is_transient_refusal,
    open_for_download,
    with_transient_retry,
)

pytestmark = pytest.mark.anyio

ASYNCSSH = PROFILES["asyncssh"]
OPENSSH = PROFILES["openssh"]
EXHAUSTED = b"Too many open files"


def vendor_id(vendor: bytes, product: bytes, version: bytes, build: int = 0) -> bytes:
    """Build a ``vendor-id`` body: three strings and a uint64."""
    parts = [
        len(vendor).to_bytes(4, "big"),
        vendor,
        len(product).to_bytes(4, "big"),
        product,
        len(version).to_bytes(4, "big"),
        version,
        build.to_bytes(8, "big"),
    ]
    return b"".join(parts)


def refusal(message: bytes, code: int = StatusCode.FAILURE) -> ServerError:
    """A ``ServerError`` shaped like the one a refusing server produces."""
    return ServerError(f"server returned {code}", code=code, message=message)


# --- what counts as transient -------------------------------------------------------------------


def test_the_measured_message_is_classified_on_the_server_it_was_measured_on():
    assert is_transient_refusal(refusal(EXHAUSTED), ASYNCSSH) is True


def test_the_same_message_from_a_server_whose_text_is_a_constant_is_not_classified():
    """The gate, and it is the whole safety argument.

    OpenSSH answers the word ``Failure`` to every condition including this one -- measured, on
    the same kernel, with the server under the same descriptor limit. A server whose message
    carries no information must never be retried on the strength of one, however the bytes
    happen to read.
    """
    assert is_transient_refusal(refusal(EXHAUSTED), OPENSSH) is False
    assert is_transient_refusal(refusal(EXHAUSTED), UNKNOWN) is False


def test_a_profile_with_markers_but_uninformative_messages_matches_nothing():
    """The gate is a rule, not a restatement of the current data.

    Every shipped profile that carries markers also has ``informative_messages=True``, so
    without this row the gate could be deleted and the suite would stay green -- the defect
    would surface only when somebody added a marker to a server whose text is a constant.
    """
    contradictory = ServerProfile(
        name="contradictory",
        description="markers, but its messages are known to be constant",
        informative_messages=False,
        transient_messages=(EXHAUSTED,),
    )
    assert contradictory.classifies_transient(EXHAUSTED) is False
    assert is_transient_refusal(refusal(EXHAUSTED), contradictory) is False


def test_a_terminal_message_from_the_classifying_server_is_not_transient():
    assert is_transient_refusal(refusal(b"No such file"), ASYNCSSH) is False
    assert is_transient_refusal(refusal(b"Permission denied"), ASYNCSSH) is False
    assert is_transient_refusal(refusal(b""), ASYNCSSH) is False


def test_only_failure_is_read_for_a_message():
    """A code that means something specific must not have its message second-guessed.

    ``FAILURE`` is v3's catch-all and is the only status whose meaning is unknown enough to
    need the text read. A ``NO_SUCH_FILE`` carrying the marker -- which no server sends, and
    which is exactly what a confused or hostile one would -- stays terminal.
    """
    assert is_transient_refusal(refusal(EXHAUSTED, StatusCode.NO_SUCH_FILE), ASYNCSSH) is False
    assert is_transient_refusal(refusal(EXHAUSTED, StatusCode.PERMISSION_DENIED), ASYNCSSH) is False


def test_the_marker_matches_inside_a_longer_message():
    assert ASYNCSSH.classifies_transient(b"open failed: Too many open files (24)") is True


def test_something_that_is_not_a_server_refusal_is_never_transient():
    """Only the server refusing counts. A local failure or a broken stream is not a hiccup."""
    assert is_transient_refusal(ProtocolError("framing is wrong"), ASYNCSSH) is False
    assert is_transient_refusal(OSError("disk went away"), ASYNCSSH) is False
    assert is_transient_refusal(NoSuchFileError("gone", code=2, message=EXHAUSTED), ASYNCSSH) is (
        False
    )


def test_only_asyncssh_ships_a_transient_marker():
    """A marker without a server behind it is the rumour CLAUDE.md forbids."""
    assert PROFILES["asyncssh"].transient_messages == (EXHAUSTED,)
    assert PROFILES["openssh"].transient_messages == ()
    assert PROFILES["paramiko"].transient_messages == ()
    assert UNKNOWN.transient_messages == ()


def test_the_marker_survives_the_identification_path_the_real_server_takes():
    """The profile used in production is not the one the tests above reach for.

    asyncssh advertises ``vendor-id``, so ``identify`` routes through ``_from_vendor_id``, which
    returns ``replace(PROFILES["asyncssh"], version=...)`` rather than the table entry itself.
    ``dataclasses.replace`` carries unspecified fields across, so this works -- and **nothing
    asserted it**, which is the gap the Definition of Done's "visit every construction site" rule
    exists for. Rebuild that branch as a fresh ``ServerProfile(...)`` and the feature is dead
    against the only server it works on, with every other row in this file still green.
    """
    identified = identify({b"vendor-id": vendor_id(b"asyncssh", b"asyncssh", b"2.24.0")})
    assert identified.name == "asyncssh"
    assert identified.version == "2.24.0"
    assert identified is not PROFILES["asyncssh"], "the live path really does rebuild it"
    assert identified.transient_messages == (EXHAUSTED,)
    assert is_transient_refusal(refusal(EXHAUSTED), identified) is True


def test_a_server_naming_itself_something_unknown_carries_no_markers():
    """The other construction site in the same function, and it must stay inert."""
    stranger = identify({b"vendor-id": vendor_id(b"Example Corp", b"MOVEit", b"2025.1")})
    assert stranger.transient_messages == ()
    assert is_transient_refusal(refusal(EXHAUSTED), stranger) is False


# --- the ladder ---------------------------------------------------------------------------------


async def test_a_request_that_succeeds_is_issued_once():
    calls = 0

    async def request() -> str:
        nonlocal calls
        calls += 1
        return "handle"

    assert await with_transient_retry(request, profile=ASYNCSSH, what="get") == "handle"
    assert calls == 1


async def test_a_transient_refusal_is_repeated_and_the_second_answer_is_returned():
    calls = 0

    async def request() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise refusal(EXHAUSTED)
        return "handle"

    assert await with_transient_retry(request, profile=ASYNCSSH, what="get", backoff=0) == "handle"
    assert calls == 2


async def test_a_refusal_that_never_clears_raises_the_servers_own_error_unchanged():
    """What the caller sees is the server's error, not a wrapper invented here."""
    calls = 0
    original = refusal(EXHAUSTED)

    async def request() -> str:
        nonlocal calls
        calls += 1
        raise original

    with pytest.raises(ServerError) as raised:
        _ = await with_transient_retry(request, profile=ASYNCSSH, what="get", backoff=0)
    assert raised.value is original
    assert calls == TRANSIENT_ATTEMPTS


async def test_a_terminal_refusal_is_raised_on_the_first_attempt():
    """Being slow to report a permission problem is its own bug -- `_retry.py`'s words."""
    calls = 0

    async def request() -> str:
        nonlocal calls
        calls += 1
        raise refusal(b"Permission denied")

    with pytest.raises(ServerError):
        _ = await with_transient_retry(request, profile=ASYNCSSH, what="get", backoff=0)
    assert calls == 1


async def test_the_bound_is_honoured_exactly():
    """Pinned as a number, because an off-by-one still passes every test above."""
    assert TRANSIENT_ATTEMPTS == 3
    calls = 0

    async def request() -> str:
        nonlocal calls
        calls += 1
        raise refusal(EXHAUSTED)

    for attempts in (1, 2, 5):
        calls = 0
        with pytest.raises(ServerError):
            _ = await with_transient_retry(
                request, profile=ASYNCSSH, what="get", attempts=attempts, backoff=0
            )
        assert calls == attempts


async def test_the_backoff_doubles_and_is_capped(monkeypatch: pytest.MonkeyPatch):
    slept: list[float] = []

    async def record(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("gantry_sftp.session._transient.anyio.sleep", record)

    async def request() -> str:
        raise refusal(EXHAUSTED)

    with pytest.raises(ServerError):
        _ = await with_transient_retry(
            request, profile=ASYNCSSH, what="get", attempts=6, backoff=1.0, backoff_max=4.0
        )
    assert slept == [1.0, 2.0, 4.0, 4.0, 4.0]


async def test_the_swallowed_refusal_is_recorded_with_the_state_it_swallowed(
    caplog: pytest.LogCaptureFixture,
):
    """The record is the only runtime evidence this happened, so its contents are the feature.

    The module's own argument for logging at ``WARNING`` is that a retried refusal reaches
    nobody -- without the record, a server refusing every second open is indistinguishable from
    a healthy one. That makes the *fields* load-bearing rather than decorative, and the mutation
    lane said so: twenty-six survivors in this module, every sampled one inside this call, all
    of them blanking a value nothing asserted.
    """
    calls = 0

    async def request() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise refusal(EXHAUSTED)
        return "handle"

    with caplog.at_level(logging.WARNING, logger="gantry_sftp.session"):
        assert (
            await with_transient_retry(request, profile=ASYNCSSH, what="get", backoff=0) == "handle"
        )

    record = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert record.getMessage() == "get refused as transient (attempt 1 of 3), retrying in 0.00s"
    fields = getattr(record, LOG_FIELDS)
    assert fields["operation"] == "get"
    assert fields["event"] == "retrying_transient"
    assert fields["attempt"] == 1
    assert fields["attempts"] == TRANSIENT_ATTEMPTS
    assert fields["delay"] == 0
    assert fields["profile"] == "asyncssh"
    assert EXHAUSTED.decode() in str(fields["error"]), (
        "the record must carry what the server said, since that is the whole reason this "
        "refusal was treated differently from a terminal one"
    )


async def test_nothing_is_recorded_when_no_retry_happens(caplog: pytest.LogCaptureFixture):
    """A WARNING for every successful download would make the real one unfindable."""

    async def request() -> str:
        return "handle"

    with caplog.at_level(logging.WARNING, logger="gantry_sftp.session"):
        _ = await with_transient_retry(request, profile=ASYNCSSH, what="get")
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


# --- the wiring ---------------------------------------------------------------------------------


async def test_the_download_open_retries_and_asks_for_read(caplog: pytest.LogCaptureFixture):
    """``open_for_download`` itself, which until now only the live lane exercised.

    The mutation lane is what asked for this: blanking the ``profile`` it forwards, and the
    ``what`` it labels the record with, both survived — because every fast-suite test drove
    ``with_transient_retry`` directly and nothing drove the function that wires it to a download.
    """
    seen: list[tuple[bytes, OpenFlag]] = []
    calls = 0

    async def opener(path: bytes, pflags: OpenFlag) -> bytes:
        nonlocal calls
        calls += 1
        seen.append((path, pflags))
        if calls == 1:
            raise refusal(EXHAUSTED)
        return b"handle"

    with caplog.at_level(logging.WARNING, logger="gantry_sftp.session"):
        handle = await open_for_download(opener, b"/remote/file", ASYNCSSH)

    assert handle == b"handle"
    assert calls == 2, "the transient refusal was retried"
    assert seen == [(b"/remote/file", OpenFlag.READ)] * 2, (
        "both attempts ask for the same path, for reading"
    )
    record = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert getattr(record, LOG_FIELDS)["operation"] == "get"


async def test_the_download_open_honours_the_servers_profile():
    """The forwarded profile is what decides, so a server that explains nothing is not retried."""
    calls = 0

    async def opener(path: bytes, pflags: OpenFlag) -> bytes:
        nonlocal calls
        calls += 1
        raise refusal(EXHAUSTED)

    with pytest.raises(ServerError):
        _ = await open_for_download(opener, b"/remote/file", OPENSSH)
    assert calls == 1, "OpenSSH's constant message must not buy a second attempt"


async def test_the_shipped_delays_are_what_the_docstrings_claim():
    assert TRANSIENT_BACKOFF == 0.25
    assert TRANSIENT_BACKOFF_MAX == 2.0


async def test_an_attempt_count_below_one_is_refused_by_name():
    async def request() -> str:
        return "unreached"

    with pytest.raises(ValueError) as raised:
        _ = await with_transient_retry(request, profile=ASYNCSSH, what="get", attempts=0)
    assert raised.value.args[0] == "attempts must be at least 1, got 0"


async def test_cancellation_is_not_retried():
    """A cancelled transfer stops rather than being repeated twice more with delays.

    **This row does not defend the ``except Exception`` spelling, and saying so is the point.**
    Widening it to ``BaseException`` leaves the suite green, because ``is_transient_refusal``
    refuses anything that is not a ``ServerError`` and re-raises it on the spot -- so the
    classifier is what keeps a cancellation cancelled here, not the narrowing. Checked by
    applying that mutation rather than by reading. What this asserts is the behaviour itself,
    which would survive either spelling and must hold under both.
    """
    calls = 0

    async def request() -> str:
        nonlocal calls
        calls += 1
        await anyio.sleep(60)
        return "unreached"

    with anyio.move_on_after(0.05) as scope:
        _ = await with_transient_retry(request, profile=ASYNCSSH, what="get", backoff=0)
    assert scope.cancelled_caught
    assert calls == 1

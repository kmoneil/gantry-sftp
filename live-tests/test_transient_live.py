"""A transient refusal from a real server, and the retry that survives it.

**D-30.** ``tests/test_transient.py`` proves the classification and the bound with no server at
all. This is the half a fake cannot supply: that the condition *exists*, that a real server
produces it, and that the two servers produce it differently in exactly the way the profiles
claim.

The condition is descriptor exhaustion, and it is the server's own resource ceiling rather than
anything this suite implements -- which is what makes it admissible evidence at all. The
objection ``matrix.HANDLER_IS_OURS`` raises against paramiko's row is that its filesystem
handler is code we wrote, so its behaviour is evidence about us. Here no server code is ours: an
``RLIMIT_NOFILE`` is a property of the server *process*, the ``EMFILE`` comes from its own
``os.open``, and the status and message are chosen by asyncssh's and OpenSSH's own error paths.
Constraining the environment is what every real deployment does; an appliance ships with a
descriptor ceiling and this is the same ceiling reached the same way.

**asyncssh runs in a subprocess here, unlike everywhere else in this suite.**
``matrix._listening_asyncssh`` starts it on a thread of the test's own process, and
``RLIMIT_NOFILE`` is per process -- lowering it in-process would starve the client of descriptors
and measure our own exhaustion rather than the server's.

Blocking, through ``gantry_sftp.sync``, because the server has to be an ordinary child process
rather than something inside an event loop this test owns.
"""

from __future__ import annotations

import resource
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
import sshd
from matrix import unavailable_reason

from gantry_sftp.codec import OpenFlag, StatusCode
from gantry_sftp.exceptions import ServerError
from gantry_sftp.session import PROFILES, ContentCheck, Verify
from gantry_sftp.session._transient import is_transient_refusal
from gantry_sftp.sync import open_local_server_transport, open_session, open_ssh_transport

SOFT_LIMIT = 96
"""Small enough to reach in under a hundred opens, large enough for the server's own sockets."""

SERVER_SCRIPT = """
import asyncio, resource, sys
import asyncssh

async def main():
    port, host_key, authorized, soft = sys.argv[1:5]
    resource.setrlimit(resource.RLIMIT_NOFILE, (int(soft), int(soft)))
    await asyncssh.listen(
        "127.0.0.1", port=int(port), server_host_keys=[host_key],
        authorized_client_keys=authorized, sftp_factory=True,
    )
    print("READY", flush=True)
    while True:
        await asyncio.sleep(3600)

asyncio.run(main())
"""


def exhaust(sftp, root: Path, *, limit: int = SOFT_LIMIT * 3) -> tuple[list[bytes], ServerError]:
    """Open files until the server refuses, returning the handles held and the refusal.

    Uses the raw ``open``/``close`` primitives rather than ``get``, because the point is to
    reach the ceiling rather than to transfer anything -- and because the retry under test is
    on ``get``'s open, which must not be in the loop that *creates* the condition.
    """
    handles: list[bytes] = []
    for index in range(limit):
        try:
            handles.append(
                sftp.open(str(root / f"f{index}").encode(), OpenFlag.WRITE | OpenFlag.CREAT)
            )
        except ServerError as refusal:
            return handles, refusal
    for handle in handles:
        sftp.close(handle)
    pytest.skip(f"this server never ran out of descriptors in {limit} opens")


@pytest.fixture
def asyncssh_under_a_descriptor_limit(tmp_path: Path) -> Iterator[tuple[object, Path]]:
    """A real asyncssh server, in a child process, with a small ``RLIMIT_NOFILE``."""
    reason = unavailable_reason("asyncssh")
    if reason is not None:
        pytest.skip(reason)
    from matrix import _client_options, _free_port, _keypair  # noqa: PLC0415  # skip-gated

    host_key, client_key = _keypair(tmp_path, "host"), _keypair(tmp_path, "client")
    port = _free_port()
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {(tmp_path / 'host.pub').read_text().strip()}\n")
    script = tmp_path / "server.py"
    script.write_text(SERVER_SCRIPT)

    # `with`, not a bare Popen: the pipes are what close on exit, and leaving them open makes
    # every test using this fixture error in teardown with an unraisable ResourceWarning --
    # which reads as a broken test rather than as a leaked descriptor, in a file whose whole
    # subject is running out of them.
    with subprocess.Popen(  # resolved interpreter, list argv, no shell
        [
            sys.executable,
            str(script),
            str(port),
            str(host_key),
            str(tmp_path / "client.pub"),
            str(SOFT_LIMIT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as child:
        try:
            assert child.stdout is not None
            if not child.stdout.readline().startswith("READY"):
                assert child.stderr is not None
                pytest.skip(f"asyncssh child did not start: {child.stderr.read()[:200]}")
            kwargs = sshd.client_kwargs(
                port=port, identity_file=client_key, options=_client_options(known)
            )
            with open_ssh_transport("127.0.0.1", **kwargs) as transport:
                yield transport, tmp_path
        finally:
            child.terminate()


def test_a_real_asyncssh_server_refuses_with_a_message_this_library_classifies(
    asyncssh_under_a_descriptor_limit: tuple[object, Path],
):
    """The evidence D-30 was blocked on, asserted rather than described.

    The profile's marker is not a string somebody chose: it is what this server says when it
    runs out of descriptors, and the assertion is on both halves -- the status is the catch-all
    and the message is what distinguishes it from every terminal use of that catch-all.
    """
    transport, root = asyncssh_under_a_descriptor_limit
    with open_session(transport) as sftp:  # type: ignore[arg-type]  # fixture yields a transport
        assert sftp.profile.name == "asyncssh"
        handles, refusal = exhaust(sftp, root)
        try:
            assert refusal.code == StatusCode.FAILURE
            assert refusal.message == b"Too many open files"
            assert is_transient_refusal(refusal, sftp.profile) is True
        finally:
            for handle in handles:
                sftp.close(handle)


def test_the_identical_request_succeeds_once_one_descriptor_is_released(
    asyncssh_under_a_descriptor_limit: tuple[object, Path],
):
    """ "Transient" means this and nothing else: the same request, later, works.

    Without this row the classification is an assertion about a string. With it, the string is
    known to name a condition that clears -- which is the only thing that makes retrying it
    correct rather than merely convenient.
    """
    transport, root = asyncssh_under_a_descriptor_limit
    with open_session(transport) as sftp:  # type: ignore[arg-type]  # fixture yields a transport
        handles, refusal = exhaust(sftp, root)
        refused_path = str(root / f"f{len(handles)}").encode()
        assert refusal.message == b"Too many open files"
        try:
            sftp.close(handles.pop())
            handles.append(sftp.open(refused_path, OpenFlag.WRITE | OpenFlag.CREAT))
        finally:
            for handle in handles:
                sftp.close(handle)


def test_a_download_survives_a_descriptor_shortage_that_would_have_failed_it(
    asyncssh_under_a_descriptor_limit: tuple[object, Path], tmp_path: Path
):
    """The feature, end to end: `get` completes against a server that refused its first OPEN.

    The shortage is made real and then relieved from *outside* the transfer -- the descriptors
    are released between the refusal and the retry, which is what a concurrent sibling
    finishing does on a busy server. Before D-30 this raised and the file was not transferred.
    """
    transport, root = asyncssh_under_a_descriptor_limit
    source = root / "payload"
    source.write_bytes(b"the bytes that must arrive" * 100)

    with open_session(transport) as sftp:  # type: ignore[arg-type]  # fixture yields a transport
        handles, _ = exhaust(sftp, root)

        # Hand back two descriptors on a delay: the retry's first attempt still fails, and the
        # second finds room. `get` needs one for the OPEN it is retrying.
        def release() -> None:
            for handle in handles[-2:]:
                sftp.close(handle)

        timer = threading.Timer(0.4, release)
        timer.start()
        try:
            destination = tmp_path / "arrived"
            result = sftp.get(str(source).encode(), destination)
            assert destination.read_bytes() == source.read_bytes()
            assert result.transferred == source.stat().st_size
        finally:
            timer.cancel()
            timer.join()
            for handle in handles[:-2]:
                sftp.close(handle)


def test_a_verified_download_survives_the_shortage_that_used_to_fail_it_after_transferring(
    asyncssh_under_a_descriptor_limit: tuple[object, Path], tmp_path: Path
):
    """D-182, and it is the row that shows why that card was ranked above the rest of `later`.

    Before it, this sequence *transferred the file* — retrying its own `OPEN` through D-30's
    ladder — and then raised while verifying it, because the verification's own `OPEN` had no
    retry. A caller saw a verification failure on a file that was in fact byte-correct, which is
    the most misleading shape this library can produce: it is the exact reading a corrupt
    transfer would give.

    `Verify.REREAD` rather than `HASH` because asyncssh advertises no `check-file`, so the hash
    rung would report UNAVAILABLE and never open anything.
    """
    transport, root = asyncssh_under_a_descriptor_limit
    source = root / "verified"
    source.write_bytes(b"bytes that must arrive and be checked" * 200)

    with open_session(transport) as sftp:  # type: ignore[arg-type]  # fixture yields a transport
        handles, _ = exhaust(sftp, root)

        def release() -> None:
            for handle in handles[-4:]:
                sftp.close(handle)

        timer = threading.Timer(0.4, release)
        timer.start()
        try:
            destination = tmp_path / "arrived"
            result = sftp.get(str(source).encode(), destination, verify=Verify.REREAD)
            assert destination.read_bytes() == source.read_bytes()
            assert result.content_check is ContentCheck.REREAD, (
                "the verification must have actually run -- an UNAVAILABLE here would make this "
                "row pass without ever opening a handle to verify with"
            )
        finally:
            timer.cancel()
            timer.join()
            for handle in handles[:-4]:
                sftp.close(handle)


def test_the_file_object_survives_the_shortage_that_the_transfers_already_did(
    asyncssh_under_a_descriptor_limit: tuple[object, Path],
):
    """D-185, and the surface D-182's sweep could not see.

    ``open_file`` opens with the flags its *caller* passed, held in a variable whose default is
    ``READ`` -- so the sweep that counted read-opens by their ``OpenFlag.READ`` literal reached
    the five it knew about and not this one. Before this card, ``get()`` recovered from a busy
    server and ``with sftp.open_file(...)`` raised, on the same connection, in the same second.

    The same shape as the two rows above on purpose: the shortage is relieved from outside the
    call, which is what a concurrent sibling finishing does.
    """
    transport, root = asyncssh_under_a_descriptor_limit
    source = root / "streamed"
    source.write_bytes(b"bytes read through the cursor" * 100)

    with open_session(transport) as sftp:  # type: ignore[arg-type]  # fixture yields a transport
        handles, _ = exhaust(sftp, root)

        def release() -> None:
            for handle in handles[-2:]:
                sftp.close(handle)

        timer = threading.Timer(0.4, release)
        timer.start()
        try:
            with sftp.open_file(str(source).encode()) as remote:
                assert remote.read(29) == b"bytes read through the cursor"
        finally:
            timer.cancel()
            timer.join()
            for handle in handles[:-2]:
                sftp.close(handle)


def test_the_public_read_open_survives_the_shortage_through_the_portal(
    asyncssh_under_a_descriptor_limit: tuple[object, Path],
):
    """The spelling the fsspec adapter calls, against a server that is genuinely out (D-185).

    ``sftp`` here *is* a :class:`~gantry_sftp.sync.SyncSession`, so this is the blocking half
    end to end -- the retry, its ``anyio.sleep`` and its log record all run on the portal's
    thread while this one blocks. ``tests/test_fsspec.py`` pins that the adapter asks for this
    spelling; what cannot be shown there is that the spelling survives a real refusal.
    """
    transport, root = asyncssh_under_a_descriptor_limit
    source = root / "read-open"
    source.write_bytes(b"payload")

    with open_session(transport) as sftp:  # type: ignore[arg-type]  # fixture yields a transport
        handles, _ = exhaust(sftp, root)

        def release() -> None:
            for handle in handles[-2:]:
                sftp.close(handle)

        timer = threading.Timer(0.4, release)
        timer.start()
        try:
            opened = sftp.open_for_read(str(source).encode())
            try:
                assert sftp.read_at(opened, 0, 7) == b"payload"
            finally:
                sftp.close(opened)
        finally:
            timer.cancel()
            timer.join()
            for handle in handles[:-2]:
                sftp.close(handle)


def test_the_reference_server_produces_the_same_condition_and_says_nothing_about_it(
    tmp_path: Path,
):
    """D-30's other half, and the row that closes an argument rather than supporting it.

    "Impossible on OpenSSH" rested on five *terminal* conditions all answering the word
    ``Failure``, which left open the objection that a transient one might read differently.
    It does not. The reference server reaches the same ceiling, recovers the same way, and
    says the same contentless word -- so there is nothing for a message rule to match, and
    this library correctly declines to retry it.

    ``RLIMIT_NOFILE`` is inherited across spawn, so it is lowered for the duration of the
    spawn and restored immediately: the child holds the small limit, this process does not,
    and the exhaustion measured is the server's.
    """
    original = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (SOFT_LIMIT, original[1]))
    try:
        with open_local_server_transport(cwd=tmp_path) as transport:
            resource.setrlimit(resource.RLIMIT_NOFILE, original)
            with open_session(transport) as sftp:
                handles, refusal = exhaust(sftp, tmp_path)
                try:
                    assert refusal.code == StatusCode.FAILURE
                    assert refusal.message == b"Failure", (
                        "the reference server's message is a constant; if this changed, D-30's "
                        "impossible-on-OpenSSH half needs revisiting"
                    )
                    assert is_transient_refusal(refusal, PROFILES["openssh"]) is False
                finally:
                    for handle in handles:
                        sftp.close(handle)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, original)

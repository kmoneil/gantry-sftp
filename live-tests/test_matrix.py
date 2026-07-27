"""What three real SFTP servers actually do, and where they disagree.

DESIGN.md 7 lists seven things endpoints differ on and, until this file, cited no measurement
for any of them -- one server cannot disagree with itself. These tests drive the same client
against OpenSSH, asyncssh and paramiko over real ``ssh`` connections, and pin the differences
so the table in that section stays a measurement rather than a memory.

**A failure here is usually a finding, not a bug.** If asyncssh adds an extension or paramiko
changes its error text, these fail, and the right response is to re-read the table and update
it -- which is the point. Pinned facts that nobody notices going stale are how a compatibility
document becomes fiction.

The backend is pinned to asyncio rather than parametrised over both. These are assertions
about *servers*; running each one twice would double a lane that starts real ``sshd``
processes to prove nothing about anyio.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from matrix import SERVER_NAMES, MatrixServer, running_server, unavailable_reason

from gantry_sftp.exceptions import NoSuchFileError, ServerError
from gantry_sftp.session import Session, open_session, parse_vendor_id
from gantry_sftp.transport import open_ssh_transport

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """Override the two-backend fixture: the subject here is the server, not the loop."""
    return "asyncio"


@pytest.fixture(params=SERVER_NAMES)
def server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MatrixServer]:
    """One running server per implementation, skipping with a reason when it cannot start."""
    name = str(request.param)
    reason = unavailable_reason(name)
    if reason is not None:
        pytest.skip(reason)
    with running_server(name, tmp_path) as running:
        yield running


@asynccontextmanager
async def connected(server: MatrixServer) -> AsyncIterator[Session]:
    """A session against ``server``, over a real ``ssh`` connection."""
    connect = dict(server.connect)
    host = str(connect.pop("host"))
    async with open_ssh_transport(host, **connect) as transport, open_session(transport) as sftp:
        yield sftp


# --- what every implementation agrees on -------------------------------------------------------


async def test_every_server_negotiates_version_3(server: MatrixServer):
    # The floor the whole library is built on. If an implementation answered 4 or 6, every
    # ATTRS layout below it would be wrong and nothing else in this file would mean anything.
    async with connected(server) as sftp:
        assert sftp.server_version == 3


async def test_a_file_round_trips_through_every_server(server: MatrixServer, tmp_path: Path):
    """The interop claim, which is the one that matters more than any table below.

    Byte-identical rather than same-length, and random rather than zeroes, because the
    failure this catches -- an offset or reassembly bug that only shows against a server whose
    batching differs -- produces a file of exactly the right size.
    """
    payload = bytes(range(256)) * 300
    source = server.root / "upload.bin"
    source.write_bytes(payload)
    remote = server.root / "copy.bin"
    local = tmp_path / "back.bin"

    async with connected(server) as sftp:
        result = await sftp.put(source, str(remote))
        assert result.transferred == len(payload)
        assert await sftp.get(str(remote), local) == len(payload)

    assert remote.read_bytes() == payload
    assert local.read_bytes() == payload


async def test_a_missing_file_is_reported_as_no_such_file_everywhere(server: MatrixServer):
    # The one status code every implementation maps the same way. The *message* does not
    # agree, which is the next test.
    async with connected(server) as sftp:
        with pytest.raises(NoSuchFileError):
            _ = await sftp.stat(b"/definitely/not/here")


HANDLER_IS_OURS = frozenset({"paramiko"})
"""Servers whose *filesystem* behaviour is this repo's code rather than the implementation's.

Paramiko ships ``SFTPServer`` -- packet handling, advertised extensions, the mapping from
``errno`` to a status code and its message text -- and leaves the filesystem to the caller,
so :class:`matrix._ParamikoHandler` is ours. Protocol-level facts read off it are paramiko's
and are asserted below. Filesystem-level ones are *our* thirty lines, and reporting those as
findings about paramiko would be the fake-confirms-its-author trap with extra steps.
"""


def skip_where_the_handler_is_ours(server: MatrixServer) -> None:
    if server.name in HANDLER_IS_OURS:
        pytest.skip(
            f"{server.name}'s filesystem behaviour is this repo's handler, not the server's -- "
            f"see matrix.HANDLER_IS_OURS"
        )


# --- where they disagree, which is the point ---------------------------------------------------

EXPECTED_EXTENSIONS = {
    "openssh": {
        "copy-data",
        "expand-path@openssh.com",
        "fstatvfs@openssh.com",
        "fsync@openssh.com",
        "hardlink@openssh.com",
        "home-directory",
        "limits@openssh.com",
        "lsetstat@openssh.com",
        "posix-rename@openssh.com",
        "statvfs@openssh.com",
        "users-groups-by-id@openssh.com",
    },
    "asyncssh": {
        "copy-data",
        "fstatvfs@openssh.com",
        "fsync@openssh.com",
        "hardlink@openssh.com",
        "limits@openssh.com",
        "lsetstat@openssh.com",
        "newline",
        "posix-rename@openssh.com",
        "ranges@asyncssh.com",
        "statvfs@openssh.com",
        "vendor-id",
    },
    "paramiko": {"check-file"},
}
"""Measured 2026-07-27 against OpenSSH 10.0p2, asyncssh 2.24.0, paramiko 5.0.0."""


async def test_the_advertised_extension_set_is_what_was_measured(server: MatrixServer):
    """Eleven, eleven and one -- and the overlap is smaller than the counts suggest.

    §7 says endpoints often advertise none. Paramiko advertises one, and it is not one OpenSSH
    has. This is the fact that makes "absent extension implies a documented fallback path"
    load-bearing rather than defensive.
    """
    async with connected(server) as sftp:
        advertised = {name.decode() for name in sftp.extensions}

    assert advertised == EXPECTED_EXTENSIONS[server.name]


async def test_nothing_can_be_relied_on_beyond_what_all_three_share(server: MatrixServer):
    # The intersection across the matrix is empty: paramiko advertises only `check-file`,
    # which neither of the others has. So there is no extension a client may assume, which is
    # exactly why every use of one has to degrade.
    shared = set.intersection(*(set(names) for names in EXPECTED_EXTENSIONS.values()))
    assert shared == set(), f"the matrix now shares {shared}, and the fallbacks can relax"


async def test_only_paramiko_offers_hash_based_verification(server: MatrixServer):
    """Rung 1 of §6's verification ladder, which had never been seen on a real server.

    D-5 has been open since 0.2 on exactly this: ``check-file`` is absent from OpenSSH, and
    ProFTPD's ``checkFile`` was known only from documentation. Paramiko advertises it -- and
    unsuffixed, matching the draft rather than OpenSSH's ``@openssh.com`` convention -- so the
    request and ``EXTENDED_REPLY`` layouts can now be read off something that really speaks it.
    """
    async with connected(server) as sftp:
        offered = sftp.supports(b"check-file")

    assert offered is (server.name == "paramiko")


EXPECTED_LIMITS = {
    "openssh": (261120, 261120),
    "asyncssh": (4194304, 4194304),
    "paramiko": (None, None),
}
"""Measured read/write maxima. Paramiko advertises no ``limits@openssh.com`` at all."""


async def test_transfer_limits_differ_by_more_than_an_order_of_magnitude(server: MatrixServer):
    """A 16x spread, and one server that will not say.

    This is the tunable the request-size negotiation already consumes, so it is not a curiosity:
    a client that hard-coded OpenSSH's 255 KiB would leave asyncssh sixteen times slower than
    it needs to be, and one that hard-coded asyncssh's 4 MiB would have every request silently
    clamped by OpenSSH. The paramiko row is the *absent* case, which falls back to our defaults
    rather than failing -- the first time that path has been exercised against a real server.
    """
    async with connected(server) as sftp:
        limits = sftp.limits

    assert (limits.max_read_length, limits.max_write_length) == EXPECTED_LIMITS[server.name]


EXPECTED_MISSING_FILE_TEXT = {
    "openssh": b"No such file",
    "asyncssh": b"No such file or directory",
    "paramiko": b"No such file",
}
"""The server's own words for the same condition. Two spellings across three servers."""


async def test_the_words_for_a_missing_file_are_not_the_same(server: MatrixServer):
    """The input a quirks layer would have to match on, and it is already inconsistent.

    D-30 needs to tell a transient ``FAILURE`` from a terminal one, and the only material a
    v3 server offers is this string. Three implementations, two spellings, for the one status
    code they *do* all map identically -- which is the argument for matching message text
    being a per-profile rule rather than a table of substrings that works everywhere.
    """
    async with connected(server) as sftp:
        with pytest.raises(NoSuchFileError) as exc:
            _ = await sftp.stat(b"/definitely/not/here")

    assert exc.value.message == EXPECTED_MISSING_FILE_TEXT[server.name]


async def test_rename_onto_an_existing_target_is_refused(server: MatrixServer):
    """§7 says implementations differ here -- overwrite, error, or silent no-op.

    Both implementations whose filesystem layer is their own refuse, which is the answer
    atomic publish depends on: the ``remove``-then-``rename`` fallback exists precisely
    because plain v3 ``RENAME`` cannot replace. Worth measuring rather than inferring from
    OpenSSH, because a server that overwrote would make that fallback unnecessary *and* make
    the publish step non-atomic in a way nothing would have noticed.

    Paramiko is excluded, and the exclusion is the interesting part. Its handler here is
    ours, and ours uses ``Path.rename``, which replaces silently -- so this test failed
    against it on the first run. Making the handler conformant would have turned a red test
    green by choosing the answer to the question being asked, which is worse than not asking.
    """
    skip_where_the_handler_is_ours(server)
    source = server.root / "rename-source.bin"
    source.write_bytes(b"source")
    target = server.root / "rename-target.bin"
    target.write_bytes(b"target")

    async with connected(server) as sftp:
        with pytest.raises(ServerError):
            await sftp.rename(str(source), str(target))

    assert target.read_bytes() == b"target", "the target was replaced despite the refusal"
    assert source.read_bytes() == b"source", "the source was consumed by a failed rename"


async def test_realpath_of_a_path_that_does_not_exist(server: MatrixServer):
    """§7's open question, answered for the two servers that can answer it.

    Both canonicalise rather than refuse, so the disagreement §7 predicted is not there --
    worth pinning precisely because a non-finding is the kind of thing that gets quietly
    re-litigated. A server that refused would break any client canonicalising a destination
    before writing to it.

    Paramiko is excluded for the same reason as the rename above: ``canonicalize`` is a
    method on the handler, so its answer here would be ours.
    """
    skip_where_the_handler_is_ours(server)
    missing = server.root / "no-such-name.bin"

    async with connected(server) as sftp:
        resolved = await sftp.realpath(str(missing))

    assert resolved == str(missing).encode()


async def test_only_asyncssh_says_who_it_is(server: MatrixServer):
    """``vendor-id`` is a free, structured fingerprint, and §7 does not mention it.

    That section proposes fingerprinting from the SSH banner -- which this architecture does
    not see, because ``ssh`` consumes it, and which costs ``LogLevel=DEBUG1`` and about 3.4 KB
    of stderr per connection to recover. ``vendor-id`` costs nothing and arrives with the
    handshake. It is only worth as much as its coverage, and its coverage here is one server
    in three, so it narrows the fingerprinting problem rather than solving it.
    """
    async with connected(server) as sftp:
        vendor = sftp.extensions.get(b"vendor-id")

    if server.name != "asyncssh":
        assert vendor is None
        return

    assert vendor is not None
    # Layout: string vendor, string product, string version, uint64 build. Sourced from
    # asyncssh's own `_parse_vendor_id` and from these bytes -- it is in neither
    # draft-ietf-secsh-filexfer-05 nor -13, both of which were checked after an earlier
    # version of this comment cited draft-05 for it and was wrong.
    assert parse_vendor_id(vendor) == ("Ron Frederick", "AsyncSSH", "2.24.0", 0)


async def test_every_server_is_identified_from_what_it_advertised(server: MatrixServer):
    """Fingerprinting, against the three implementations it was written from.

    The unit tests match against extension sets copied into the ordinary suite; this is the
    one place the sets themselves are what a server really sent. A server that changes its
    advertisement fails here first, which is the right order -- the copies are downstream.
    """
    async with connected(server) as sftp:
        profile = sftp.profile

    assert profile.name == server.name
    assert profile.name in repr(sftp.profile) or profile.name == profile.label.split("/")[0]


async def test_only_asyncssh_reports_a_version_because_only_it_says_one(server: MatrixServer):
    # No version is inferred from an extension list. OpenSSH's is knowable only from the SSH
    # banner, which this architecture does not see, so the honest answer is None.
    async with connected(server) as sftp:
        profile = sftp.profile

    if server.name == "asyncssh":
        assert profile.version is not None
        assert profile.label == f"asyncssh/{profile.version}"
    else:
        assert profile.version is None
        assert profile.label == server.name

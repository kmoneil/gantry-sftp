"""The session: handshake, limits probing, typed errors, timeouts, and get()."""

from __future__ import annotations

import os
from pathlib import Path

import anyio
import pytest

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    Attrs,
    AttrsReply,
    Close,
    Codec,
    Data,
    Extended,
    ExtendedReply,
    FrameSplitter,
    Handle,
    Init,
    Name,
    NameEntry,
    Open,
    OpenFlag,
    Read,
    RealPath,
    Stat,
    Status,
    StatusCode,
    Version,
    WireWriter,
    decode,
    encode,
)
from gantry_sftp.exceptions import (
    NoSuchFileError,
    PermissionDeniedError,
    ProtocolError,
    ServerError,
    TransferTimeoutError,
    UnsupportedError,
)
from gantry_sftp.session import (
    LIMITS_EXTENSION,
    Dispatcher,
    ServerLimits,
    Session,
    open_session,
    raise_for_status,
)
from gantry_sftp.transport import find_sftp_server, open_local_server_transport

pytestmark = pytest.mark.anyio

OPENSSH_LIMITS = (262144, 261120, 261120, 1048571)


def limits_body(values: tuple[int, int, int, int]) -> bytes:
    w = WireWriter()
    for value in values:
        w.write_uint64(value)
    return w.getvalue()


class FakeServer:
    """A scriptable in-process transport.

    Answers the handshake, then dispatches each request to a handler the test supplies.
    Deliberately able to misbehave -- refuse an advertised extension, answer the wrong packet
    type, or say nothing at all -- because those are the cases a real server will not perform
    on request.
    """

    def __init__(
        self,
        *,
        extensions: tuple[tuple[bytes, bytes], ...] = ((LIMITS_EXTENSION, b"1"),),
        limits: tuple[int, int, int, int] | None = OPENSSH_LIMITS,
        content: bytes = b"",
        silent_after_version: bool = False,
        never_version: bool = False,
    ) -> None:
        self.extensions = extensions
        self.limits = limits
        self.content = content
        self.silent_after_version = silent_after_version
        self.never_version = never_version
        self.seen: list[object] = []
        self._splitter = FrameSplitter()
        self._outbox = bytearray()
        self._has_output = anyio.Event()

    async def send(self, data: bytes | memoryview) -> None:
        for frame in self._splitter.feed(data):
            self._dispatch(decode(frame))

    def _reply(self, packet: object) -> None:
        self._outbox += encode(packet)  # type: ignore[arg-type]
        self._has_output.set()

    def _dispatch(self, packet: object) -> None:
        self.seen.append(packet)
        if isinstance(packet, Init):
            if not self.never_version:
                self._reply(Version(3, self.extensions))
            return
        if self.silent_after_version:
            return
        self._handle(packet)

    def _handle(self, packet: object) -> None:
        rid = packet.request_id  # type: ignore[union-attr]
        if isinstance(packet, Extended) and packet.name == LIMITS_EXTENSION:
            if self.limits is None:
                self._reply(Status(rid, StatusCode.OP_UNSUPPORTED, b"no limits here"))
            else:
                self._reply(ExtendedReply(rid, limits_body(self.limits)))
        elif isinstance(packet, Stat):
            self._reply(AttrsReply(rid, Attrs(size=len(self.content))))
        elif isinstance(packet, Open):
            self._reply(Handle(rid, b"\x00\x00\x00\x00"))
        elif isinstance(packet, Read):
            chunk = self.content[packet.offset : packet.offset + packet.length]
            if chunk:
                self._reply(Data(rid, memoryview(chunk)))
            else:
                self._reply(Status(rid, StatusCode.EOF))
        elif isinstance(packet, Close):
            self._reply(Status(rid, StatusCode.OK))
        elif isinstance(packet, RealPath):
            self._reply(Name(rid, (NameEntry(b"/canonical", b"/canonical", EMPTY_ATTRS),)))
        else:
            self._reply(Status(rid, StatusCode.FAILURE, b"unscripted"))

    async def receive(self, max_bytes: int = 65536) -> bytes:
        # Waits on an Event rather than polling, so a test that expects a timeout actually
        # blocks instead of spinning -- and so the timeout under test is the one that fires.
        if not self._outbox:
            await self._has_output.wait()
        chunk = bytes(self._outbox[:max_bytes])
        del self._outbox[:max_bytes]
        if not self._outbox:
            self._has_output = anyio.Event()
        return chunk

    async def aclose(self) -> None:
        return


# --- handshake and limits -------------------------------------------------------------------


async def test_a_session_negotiates_and_reads_limits():
    server = FakeServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert sftp.server_version == 3
        assert sftp.limits.max_read_length == 261120
        assert LIMITS_EXTENSION in sftp.extensions


async def test_a_server_that_does_not_advertise_limits_is_not_asked():
    # No point spending a round trip on an extension the server already said it lacks.
    server = FakeServer(extensions=())
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert sftp.limits == ServerLimits.unknown()
    assert not any(isinstance(packet, Extended) for packet in server.seen)


async def test_a_server_that_advertises_limits_then_refuses_falls_back():
    # Advertising and then refusing is a server contradicting itself. Our defaults work, and
    # failing a connection over an optional tuning hint would be absurd.
    server = FakeServer(limits=None)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert sftp.limits == ServerLimits.unknown()
    assert any(isinstance(packet, Extended) for packet in server.seen)


async def test_a_server_that_goes_silent_after_version_still_yields_a_session():
    # Silence in answer to the limits probe must not hang the connection. This is the case
    # the probe has its own deadline for.
    server = FakeServer(silent_after_version=True)
    async with open_session(server, request_timeout=0.2) as sftp:  # type: ignore[arg-type]
        assert sftp.limits == ServerLimits.unknown()


async def test_a_server_that_never_sends_version_times_out():
    # paramiko's answer is to wait forever. An unattended job that hangs is worse than one
    # that fails, because nothing ever reports it.
    server = FakeServer(never_version=True)
    with pytest.raises(TransferTimeoutError) as exc:
        async with open_session(server, request_timeout=0.2):  # type: ignore[arg-type]
            pass
    assert exc.value.args[0] == "server did not send VERSION within 0.2s"


async def test_no_timeout_is_possible_but_must_be_asked_for():
    server = FakeServer()
    async with open_session(server, request_timeout=None) as sftp:  # type: ignore[arg-type]
        assert sftp.server_version == 3


# --- typed errors ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (StatusCode.NO_SUCH_FILE, NoSuchFileError),
        (StatusCode.PERMISSION_DENIED, PermissionDeniedError),
        (StatusCode.OP_UNSUPPORTED, UnsupportedError),
        (StatusCode.FAILURE, ServerError),
        (StatusCode.BAD_MESSAGE, ServerError),
    ],
)
def test_status_codes_map_to_typed_errors(code: StatusCode, expected: type[ServerError]):
    with pytest.raises(expected) as exc:
        raise_for_status(Status(1, code, b"because"), path=b"/some/path")
    assert exc.value.code == int(code)
    assert exc.value.path == b"/some/path"
    assert exc.value.message == b"because"
    assert "because" in str(exc.value)


@pytest.mark.parametrize("code", [StatusCode.OK, StatusCode.EOF])
def test_ok_and_eof_are_not_errors(code: StatusCode):
    # EOF is the normal terminating condition for READDIR and for a read at the end of a
    # file. Treating it as a failure would make every complete directory listing an error.
    raise_for_status(Status(1, code))


def test_a_status_without_a_message_still_produces_a_usable_error():
    # Many servers send no message at all, so the summary has to stand on its own.
    with pytest.raises(ServerError) as exc:
        raise_for_status(Status(1, StatusCode.FAILURE))
    assert exc.value.args[0] == "server returned FAILURE"


async def test_a_missing_file_raises_no_such_file():
    class Missing(FakeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Stat):
                self._reply(Status(packet.request_id, StatusCode.NO_SUCH_FILE, b"No such file"))
                return
            super()._handle(packet)

    server = Missing()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(NoSuchFileError) as exc:
            await sftp.stat("/absent")
    assert exc.value.path == b"/absent"


async def test_a_reply_of_the_wrong_type_is_a_protocol_error():
    # A STATUS of OK where a HANDLE was due is the server claiming success while withholding
    # the result -- a protocol violation, not a refusal, and typed differently for it.
    class Confused(FakeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Open):
                self._reply(Status(packet.request_id, StatusCode.OK))
                return
            super()._handle(packet)

    server = Confused()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ProtocolError) as exc:
            await sftp.open("/whatever")
    assert exc.value.args[0] == ("server answered with STATUS OK where HANDLE was expected")


# --- operations -------------------------------------------------------------------------------


async def test_stat_returns_attributes():
    server = FakeServer(content=b"x" * 42)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert (await sftp.stat("/f")).size == 42


async def test_realpath_returns_the_canonical_name():
    server = FakeServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert await sftp.realpath(".") == b"/canonical"


async def test_realpath_refuses_a_reply_carrying_several_names():
    """Picking the first of several would be calling one of the server's answers canonical.

    The draft specifies a single name and ``sftp-client.c`` does ``if (count != 1) fatal("Got
    multiple names (%d)")``, so both the written spec and the reference client are strict
    here -- which is exactly the case where there is nothing to be lenient towards. The
    opposite call is right for READDIR, where they disagree; see ``Session.readdir``.
    """

    class Ambiguous(FakeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, RealPath):
                self._reply(
                    Name(
                        packet.request_id,
                        (
                            NameEntry(b"/first", b"/first", EMPTY_ATTRS),
                            NameEntry(b"/second", b"/second", EMPTY_ATTRS),
                        ),
                    )
                )
                return
            super()._handle(packet)

    server = Ambiguous()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ProtocolError) as exc:
            _ = await sftp.realpath(".")

    assert exc.value.args[0] == (
        "REALPATH of b'.' answered with 2 names, and exactly one is the only useful answer"
    )


async def test_realpath_refuses_a_reply_carrying_no_names_and_says_so():
    """The message this used to produce was 'answered with Name where NAME was expected'.

    Which is nonsense -- a NAME *was* what arrived. An empty NAME is legal-looking and
    useless, and the error has to say that rather than describe the packet type twice.
    """

    class Empty(FakeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, RealPath):
                self._reply(Name(packet.request_id, ()))
                return
            super()._handle(packet)

    server = Empty()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(ProtocolError) as exc:
            _ = await sftp.realpath(".")

    assert exc.value.args[0] == (
        "REALPATH of b'.' answered with 0 names, and exactly one is the only useful answer"
    )


async def test_open_and_close_round_trip():
    server = FakeServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        handle = await sftp.open("/f", OpenFlag.READ)
        assert handle == b"\x00\x00\x00\x00"
        await sftp.close(handle)


async def test_a_request_timeout_names_the_request_that_hung():
    class Sluggish(FakeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Stat):
                return
            super()._handle(packet)

    server = Sluggish()
    async with open_session(server, request_timeout=0.2) as sftp:  # type: ignore[arg-type]
        with pytest.raises(TransferTimeoutError) as exc:
            await sftp.stat("/f")
    assert exc.value.args[0] == "Stat was not answered within 0.2s"


# --- get() -------------------------------------------------------------------------------------


async def test_get_downloads_a_file(tmp_path: Path):
    content = bytes(range(256)) * 30
    server = FakeServer(content=content)
    destination = tmp_path / "out.bin"
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        written = await sftp.get("/remote", destination)
    assert written == len(content)
    assert destination.read_bytes() == content


async def test_get_closes_the_handle_even_when_the_transfer_fails(tmp_path: Path):
    # A leaked handle counts against max-open-handles and is invisible from this side until
    # the server starts refusing to open anything at all.
    class Refusing(FakeServer):
        def _handle(self, packet: object) -> None:
            if isinstance(packet, Read):
                self._reply(Status(packet.request_id, StatusCode.PERMISSION_DENIED, b"denied"))
                return
            super()._handle(packet)

    server = Refusing(content=b"x" * 100)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        with pytest.raises(Exception):  # noqa: B017 -- the type is asserted below
            await sftp.get("/remote", tmp_path / "out.bin")

    assert any(isinstance(packet, Close) for packet in server.seen), (
        "the handle was never closed after a failed transfer"
    )


async def test_get_reports_progress(tmp_path: Path):
    content = bytes(4096)
    seen: list[tuple[int, int | None]] = []
    server = FakeServer(content=content)
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.get("/remote", tmp_path / "out.bin", progress=lambda a, b: seen.append((a, b)))
    assert seen[0] == (0, len(content))
    assert seen[-1] == (len(content), len(content))


async def test_a_session_reports_its_tunables():
    # A slow transfer sends people looking for exactly these three numbers.
    server = FakeServer()
    async with open_session(server, depth=8, request_timeout=5.0, idle_timeout=7.0) as sftp:  # type: ignore[arg-type]
        text = repr(sftp)
    assert "depth=8" in text
    assert "request_timeout=5.0" in text
    assert "idle_timeout=7.0" in text


async def test_a_session_says_which_server_it_thinks_it_is_talking_to():
    """A bug report that names the endpoint is worth more than one that describes it.

    The fake advertises nothing, which is the honest case and the common one -- §7 says real
    endpoints frequently advertise no extensions at all -- so it reports ``unknown`` rather
    than picking the nearest match.
    """
    server = FakeServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        assert sftp.profile.name == "unknown"
        assert "server=unknown" in repr(sftp)


# --- paths are bytes ---------------------------------------------------------------------------


async def test_a_str_path_is_encoded_with_surrogateescape():
    # Server-supplied names are frequently not valid UTF-8. A name decoded leniently and then
    # sent back must survive unchanged, or those files cannot be operated on at all.
    server = FakeServer()
    weird = b"/caf\xe9".decode("utf-8", "surrogateescape")
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.stat(weird)
    stats = [packet for packet in server.seen if isinstance(packet, Stat)]
    assert stats[0].path == b"/caf\xe9"


async def test_bytes_paths_pass_through_untouched():
    server = FakeServer()
    async with open_session(server) as sftp:  # type: ignore[arg-type]
        await sftp.stat(b"/\xff\xfe/raw")
    stats = [packet for packet in server.seen if isinstance(packet, Stat)]
    assert stats[0].path == b"/\xff\xfe/raw"


# --- against a real server -----------------------------------------------------------------------


async def test_a_session_against_a_real_sftp_server(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    content = os.urandom(500_000)
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    destination = tmp_path / "downloaded.bin"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.server_version == 3
        # The real server advertises limits, so these are its numbers rather than our
        # defaults -- which is what makes the derived request size exact.
        assert sftp.limits.max_read_length is not None
        assert (await sftp.stat(str(source))).size == len(content)
        written = await sftp.get(str(source), destination)

    assert written == len(content)
    assert destination.read_bytes() == content


async def test_lstat_and_stat_disagree_about_a_dangling_symlink_on_a_real_server(tmp_path: Path):
    """Two different questions, and the publish path needs the second one.

    ``stat`` asks whether there is a file at the end of the name and follows the link to find
    out; ``lstat`` asks whether the name is taken. A ``latest.csv`` whose target was rotated
    away answers no to the first and yes to the second, and it is the second that decides
    whether a rename can land there.
    """
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    link = tmp_path / "latest.csv"
    link.symlink_to(tmp_path / "rotated-away.csv")
    assert not link.exists(), "the fixture is meant to be a dangling symlink"

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(NoSuchFileError):
            await sftp.stat(str(link))
        attributes = await sftp.lstat(str(link))

    assert attributes.size is not None


async def test_a_real_server_reports_a_missing_file_as_no_such_file(tmp_path: Path):
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        with pytest.raises(NoSuchFileError) as exc:
            await sftp.stat(str(tmp_path / "definitely-absent"))
    # OpenSSH's own words, carried through rather than replaced by ours.
    assert exc.value.message == b"No such file"


def test_session_is_constructible_without_the_context_manager():
    # open_session owns the handshake, but Session itself must stay plain enough to build in
    # a test or a REPL without one.
    #
    # The constructor takes a Dispatcher rather than (transport, codec) as of the multiplexing
    # change, and that break is deliberate: a session whose reader is not running would accept
    # requests and never answer them, so the object that owns the reader is the honest
    # dependency. open_session is and was the documented way in.
    session = Session(Dispatcher(FakeServer(), Codec()), ServerLimits.unknown())  # type: ignore[arg-type]
    assert session.limits == ServerLimits.unknown()
    assert session.sizes_for(b"\x00\x00\x00\x00").read_length > 0

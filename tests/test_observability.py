"""The frame dumper, the logger tree, the counters, and the masking chokepoint.

Three things here are security tests wearing diagnostics clothing, and they are the reason this
module exists rather than a handful of assertions spread across the suite.

**A log line is an output channel with a reader.** Every path, filename and status message the
dumper renders was chosen by the server. Written raw, a ``\\n`` forges a log record and an
``\\x1b[`` sequence drives the terminal of whoever tails the file -- so the escaping is asserted
against bytes a hostile server would actually send, and fuzzed over arbitrary ones.

**A dump that prints a payload is a dump nobody can afford**, in two directions: a 255 KiB
``DATA`` per line fills a disk, and rendering a ``memoryview`` copies the very bytes the data
path exists not to copy.

**And the credential must not reach any of it.** The last test drives a real password through
every surface this library has -- log records, exception, ``repr``, argv -- and looks for it in
all of them at once. Checking one surface at a time is how the frame-locals leak survived until
0.9: each individual check passed.
"""

from __future__ import annotations

import io
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any

import anyio
import pytest
from hypothesis import given
from hypothesis import strategies as st

from gantry_sftp._logging import (
    MASKED,
    MAX_VALUE_CHARS,
    fields_of,
    mask_environment,
    operation,
    record_fields,
    summarise,
)
from gantry_sftp.codec import (
    MAX_FIELD_BYTES,
    Attrs,
    AttrsReply,
    Close,
    Data,
    Extended,
    ExtendedReply,
    FSetStat,
    FStat,
    Handle,
    Init,
    LStat,
    MkDir,
    Name,
    NameEntry,
    Open,
    OpenDir,
    OpenFlag,
    Owner,
    Packet,
    PacketType,
    Read,
    ReadDir,
    ReadLink,
    RealPath,
    Remove,
    Rename,
    RmDir,
    SetStat,
    Stat,
    Status,
    StatusCode,
    SymLink,
    Times,
    Version,
    Write,
    describe,
    render_field,
)
from gantry_sftp.codec._describe import _request_fields
from gantry_sftp.exceptions import ConnectError
from gantry_sftp.session import open_session, with_reconnect
from gantry_sftp.transport import find_sftp_server, open_local_server_transport, open_ssh_transport

pytestmark = pytest.mark.anyio

HANDLE = b"\x00\x00\x00\x00"
"""OpenSSH's first handle: four NUL bytes, a packed integer rather than text."""

PASSWORD = "hunter2-CANARY-must-not-appear"  # noqa: S105 -- the credential this module hunts for
"""The secret every surface below is searched for. A test that proves a password does not leak
has to contain one."""

HOSTILE = b"\x1b[2Jevil\nfake log line\r"
"""What a server sends when it would like to write in your log rather than be logged.

Clear-screen, then a newline that would forge a second record, then a carriage return that
would overwrite the line before it on a terminal.
"""

SAMPLES: tuple[tuple[Packet, str], ...] = (
    (Init(version=3), "INIT version=3 extensions=0"),
    (
        Version(version=3, extensions=((b"posix-rename@openssh.com", b"1"),)),
        "VERSION version=3 extensions=1",
    ),
    (
        Open(1, b"/incoming/data.csv", OpenFlag.READ | OpenFlag.CREAT),
        "OPEN id=1 filename=b'/incoming/data.csv' pflags=READ|CREAT attrs=-",
    ),
    (Close(2, HANDLE), r"CLOSE id=2 handle=b'\x00\x00\x00\x00'"),
    (
        Read(3, HANDLE, offset=1024, length=32768),
        r"READ id=3 handle=b'\x00\x00\x00\x00' offset=1024 len=32768",
    ),
    (
        Write(4, HANDLE, offset=2048, data=b"payload-bytes"),
        r"WRITE id=4 handle=b'\x00\x00\x00\x00' offset=2048 len=13",
    ),
    (LStat(5, b"/a"), "LSTAT id=5 path=b'/a'"),
    (FStat(6, HANDLE), r"FSTAT id=6 handle=b'\x00\x00\x00\x00'"),
    (SetStat(7, b"/a", Attrs(permissions=0o644)), "SETSTAT id=7 path=b'/a' attrs=(mode=0o644)"),
    (
        FSetStat(8, HANDLE, Attrs(times=Times(1, 2))),
        r"FSETSTAT id=8 handle=b'\x00\x00\x00\x00' attrs=(atime=1 mtime=2)",
    ),
    (OpenDir(9, b"/dir"), "OPENDIR id=9 path=b'/dir'"),
    (ReadDir(10, HANDLE), r"READDIR id=10 handle=b'\x00\x00\x00\x00'"),
    (Remove(11, b"/a"), "REMOVE id=11 path=b'/a'"),
    (MkDir(12, b"/dir", Attrs(permissions=0o755)), "MKDIR id=12 path=b'/dir' attrs=(mode=0o755)"),
    (RmDir(13, b"/dir"), "RMDIR id=13 path=b'/dir'"),
    (RealPath(14, b"."), "REALPATH id=14 path=b'.'"),
    (Stat(15, b"/a"), "STAT id=15 path=b'/a'"),
    (Rename(16, b"/old", b"/new"), "RENAME id=16 old=b'/old' new=b'/new'"),
    (ReadLink(17, b"/link"), "READLINK id=17 path=b'/link'"),
    (
        SymLink(18, targetpath=b"/target", linkpath=b"/link"),
        "SYMLINK id=18 link=b'/link' target=b'/target'",
    ),
    (
        Status(19, StatusCode.NO_SUCH_FILE, message=b"No such file"),
        "STATUS id=19 code=NO_SUCH_FILE message=b'No such file'",
    ),
    (Handle(20, HANDLE), r"HANDLE id=20 handle=b'\x00\x00\x00\x00'"),
    (Data(21, memoryview(b"x" * 4096)), "DATA id=21 len=4096"),
    (
        Name(22, (NameEntry(b"a.csv", b"-rw-r--r-- 1 u g 3 Jul 28 12:00 a.csv", Attrs(size=3)),)),
        "NAME id=22 entries=1 first=b'a.csv'",
    ),
    (
        AttrsReply(23, Attrs(size=3, permissions=0o100644)),
        "ATTRS id=23 attrs=(size=3 mode=0o100644)",
    ),
    (Extended(24, b"limits@openssh.com"), "EXTENDED id=24 name=b'limits@openssh.com' len=0"),
    (ExtendedReply(25, b"\x00" * 32), "EXTENDED_REPLY id=25 len=32"),
)
"""One instance of every packet type, in wire-number order, with the line it renders as.

The expected string is here rather than in the tests because it *is* the specification of this
format: a dump is read by a person at 3am and a change to any of these lines should be a
deliberate one. It is also what catches a field that stopped being rendered -- an assertion
that a description "contains the request id" passes just as happily when everything after it
has gone.
"""


SAMPLE_IDS = [packet.packet_type.name for packet, _ in SAMPLES]
"""Test ids by packet type -- readable, and free of the quotes and brackets a rendered packet
carries, which is what a tool selecting a single test by id has to put on a command line."""


# --- the dumper renders every packet ------------------------------------------------------


def test_there_is_a_sample_of_every_packet_type():
    """Guards the guard, and is the completeness sweep for this module.

    Definition of Done 2: adding a packet type means visiting every site that enumerates the
    existing ones. ``describe`` is one of those sites, and this is what fails when the new type
    has no sample -- before the parametrised tests below quietly cover 27 of 28.
    """
    assert {packet.packet_type for packet, _ in SAMPLES} == set(PacketType)
    assert len(SAMPLES) == len(PacketType), "two samples of one type would hide a missing one"


@pytest.mark.parametrize(("packet", "expected"), SAMPLES, ids=SAMPLE_IDS)
def test_the_exact_rendering_of_every_packet_type(packet: Packet, expected: str):
    assert describe(packet) == expected


@pytest.mark.parametrize(("packet", "expected"), SAMPLES, ids=SAMPLE_IDS)
def test_no_description_spans_more_than_one_line(packet: Packet, expected: str):
    """One packet, one line -- which is what makes a dump greppable and a log parser possible."""
    assert "\n" not in describe(packet)
    assert "\r" not in describe(packet)


def test_the_handshake_packets_carry_a_version_where_the_rest_carry_an_id():
    """The framing exception on the wire is the framing exception in the dump, deliberately.

    A dumper that printed ``id=3`` for an INIT would be inventing a field the packet does not
    have -- and it is a version, so ``id=3`` and ``version=3`` are the same digit lying.
    """
    for packet, rendered in SAMPLES:
        if packet.packet_type in {PacketType.INIT, PacketType.VERSION}:
            assert "id=" not in rendered
        else:
            assert f"id={packet.request_id}" in rendered


def test_an_unrenderable_packet_fails_loudly_rather_than_printing_half_a_line():
    """What happens when a packet type is added to the union and not to the dumper.

    ``assert_never`` makes that a *type* error first, which is the point of it -- but a type
    error is only checked where someone runs the checker, and this is the runtime half. The
    failure names the object, so the fix is obvious from the traceback alone.
    """

    @dataclass(frozen=True)
    class Invented:
        packet_type: PacketType = PacketType.EXTENDED_REPLY
        request_id: int = 1

    with pytest.raises(AssertionError) as raised:
        _ = describe(Invented())  # type: ignore[arg-type]
    assert "Invented" in str(raised.value)

    # And the request half, which no legal packet can reach: every request shape either matches
    # a case or is not a `Request` at all, so this is the only way to prove the arm is there.
    with pytest.raises(AssertionError) as raised:
        _ = _request_fields(Invented())  # type: ignore[arg-type]
    assert "Invented" in str(raised.value)


# --- the dumper renders untrusted bytes safely --------------------------------------------


@pytest.mark.parametrize(
    "packet",
    [
        Name(1, (NameEntry(HOSTILE, b"longname", Attrs()),)),
        Status(2, StatusCode.FAILURE, message=HOSTILE),
        RealPath(3, HOSTILE),
        Rename(4, HOSTILE, b"/new"),
        SymLink(5, targetpath=HOSTILE, linkpath=b"/link"),
        Open(6, HOSTILE, OpenFlag.READ),
        Handle(7, HOSTILE),
    ],
    ids=["name", "status", "path", "rename", "symlink", "open", "handle"],
)
def test_a_hostile_name_cannot_forge_a_log_record_or_drive_a_terminal(packet: Packet):
    """The escaping is the security property, and it is asserted on each field that carries one.

    Every one of these bytes reaches this library from the far end. Rendered raw into a log
    stream, the ``\\n`` is a second record with whatever content the server chose and the
    ``\\x1b[2J`` clears the screen of anyone tailing it.
    """
    rendered = describe(packet)
    assert "\x1b" not in rendered
    assert "\n" not in rendered
    assert "\r" not in rendered
    # Escaped rather than dropped: a filename that is invisible in the log is its own problem.
    assert r"\x1b[2Jevil\nfake log line\r" in rendered


@given(
    raw=st.binary(min_size=0, max_size=300),
    message=st.binary(min_size=0, max_size=300),
)
def test_no_arbitrary_server_bytes_produce_a_control_character(raw: bytes, message: bytes):
    """Fuzzed, because the hostile sample above only proves the bytes somebody thought of.

    Anything a server can put in a name or a message it can put in a log, so the property is
    over arbitrary bytes rather than over a list of escape sequences.
    """
    for packet in (
        Name(1, (NameEntry(raw, message, Attrs()),)),
        Status(2, StatusCode.FAILURE, message=message),
        RealPath(3, raw),
        Extended(4, raw, message),
    ):
        rendered = describe(packet)
        assert not any(character.isspace() and character != " " for character in rendered)
        assert all(character.isprintable() or character == " " for character in rendered)


def test_a_long_name_is_truncated_and_says_how_many_bytes_it_dropped():
    """A 64 KiB filename is legal, and a dump that prints one per frame is a log bomb.

    The dropped count is in the output rather than an ellipsis: "the path was long" and "the
    path was 64 KiB of the same character" are different findings.
    """
    rendered = describe(RealPath(1, b"a" * (MAX_FIELD_BYTES + 500)))
    assert rendered == f"REALPATH id=1 path={b'a' * MAX_FIELD_BYTES!r}+500B"


def test_a_field_at_exactly_the_cap_is_not_truncated():
    """The boundary, because an off-by-one here mislabels a whole path as truncated."""
    assert render_field(b"a" * MAX_FIELD_BYTES) == repr(b"a" * MAX_FIELD_BYTES)
    assert render_field(b"a" * (MAX_FIELD_BYTES + 1)).endswith("+1B")


def test_a_memoryview_field_renders_as_bytes():
    """`Data` aliases the frame buffer, and a dump must not care which it was handed."""
    assert render_field(memoryview(b"abc")) == "b'abc'"


# --- the dumper renders the fields that answer a question ---------------------------------


def test_open_flags_render_by_name_because_the_number_is_the_question():
    assert "pflags=READ|CREAT" in describe(Open(1, b"/a", OpenFlag.READ | OpenFlag.CREAT))
    assert "pflags=WRITE|CREAT|TRUNC" in describe(
        Open(1, b"/a", OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC)
    )


def test_no_open_flags_renders_as_zero_rather_than_as_none():
    """``OpenFlag(0).name`` is ``None``, and ``pflags=None`` reads as "we do not know"."""
    assert "pflags=0" in describe(Open(1, b"/a", OpenFlag(0)))


def test_attrs_render_only_the_fields_the_server_actually_sent():
    """Absent is not zero -- a server reporting no size has told you nothing about the size."""
    rendered = describe(
        AttrsReply(
            1, Attrs(size=3, permissions=0o100644, owner=Owner(1000, 1000), times=Times(9, 8))
        )
    )
    assert rendered == "ATTRS id=1 attrs=(size=3 mode=0o100644 uid=1000 gid=1000 atime=9 mtime=8)"


def test_an_empty_attrs_renders_as_a_dash_rather_than_as_five_defaults():
    assert describe(AttrsReply(1, Attrs())) == "ATTRS id=1 attrs=-"


def test_vendor_attrs_render_as_a_count_rather_than_as_their_contents():
    """Extended attribute pairs are vendor-defined bytes this library does not interpret.

    The count is the diagnostic fact -- "the server sent some" -- and rendering their contents
    would put another pair of untrusted blobs on a line that is already at its budget.
    """
    rendered = describe(AttrsReply(1, Attrs(size=3, extended=((b"x", b"y"), (b"a", b"b")))))
    assert rendered == "ATTRS id=1 attrs=(size=3 extended=2)"


def test_a_symlink_renders_by_semantics_not_by_the_reversed_wire_order():
    """The wire order is target-then-link; the *meaning* is a link pointing at a target.

    A dump that mirrored the wire would read as though the arguments were swapped, on the one
    packet in this protocol where everybody already suspects they are.
    """
    rendered = describe(SymLink(1, targetpath=b"/target", linkpath=b"/link"))
    assert rendered == "SYMLINK id=1 link=b'/link' target=b'/target'"


def test_a_zero_entry_name_renders_the_count_alone():
    """The end of a listing, and the shape `sftp(1)` binds on. It has no first entry."""
    assert describe(Name(1, ())) == "NAME id=1 entries=0"


def test_a_status_without_a_message_does_not_render_an_empty_one():
    """Most servers send no message, and ``message=b''`` on every line is noise."""
    assert describe(Status(1, StatusCode.EOF)) == "STATUS id=1 code=EOF"
    assert describe(Status(1, StatusCode.EOF, message=b"done")) == (
        "STATUS id=1 code=EOF message=b'done'"
    )


# --- masking ------------------------------------------------------------------------------


def test_the_askpass_answer_is_masked_by_name():
    masked = mask_environment({"GANTRY_SFTP_ASKPASS_ANSWER": "hunter2", "SSH_ASKPASS": "/askpass"})
    assert masked == {"GANTRY_SFTP_ASKPASS_ANSWER": MASKED, "SSH_ASKPASS": "/askpass"}


@pytest.mark.parametrize(
    "name",
    [
        "MY_PASSWORD",
        # D-127. Not a substring of PASSWORD, so it matched nothing until it was its own
        # marker -- and it is the spelling `/etc/passwd` trained everybody to reach for.
        "SSH_PASSWD",
        "sftp_passphrase",
        "APP_SECRET",
        "CI_TOKEN",
        "aws_credential_file",
    ],
)
def test_a_variable_the_library_never_sets_is_masked_by_marker(name: str):
    """Case-insensitive, and deliberately over-broad on a caller's own ``env=``.

    An unhelpful log line is a much better failure than a leaked one. One case per marker, so
    the next marker added without a case fails this parametrize rather than passing quietly.
    """
    assert mask_environment({name: "hunter2"}) == {name: MASKED}


@pytest.mark.parametrize("name", ["PWD", "OLDPWD"])
def test_the_working_directory_is_not_mistaken_for_a_credential(name: str):
    """The reason the markers are spelled out at full length rather than trimmed to a stem.

    ``PWD`` is diagnostic and appears on effectively every environment. A marker short enough
    to catch it would redact a useful field on every record forever -- so this is the assertion
    that stops the list being "simplified" into one that does.
    """
    assert mask_environment({name: "/srv/incoming"}) == {name: "/srv/incoming"}


def test_masking_leaves_the_key_visible():
    """Which variables were set is the entire diagnostic value; the key is not the secret.

    This library has already paid to learn that ``SSH_ASKPASS`` alone arms nothing and
    ``SSH_ASKPASS_REQUIRE`` does -- a masker that hid the names would hide that answer too.
    """
    assert set(mask_environment({"GANTRY_SFTP_ASKPASS_ANSWER": "x"})) == {
        "GANTRY_SFTP_ASKPASS_ANSWER"
    }


def test_masking_does_not_mutate_the_environment_it_was_given():
    """It is frequently the very dictionary about to be handed to the child process."""
    original = {"GANTRY_SFTP_ASKPASS_ANSWER": "hunter2"}
    _ = mask_environment(original)
    assert original == {"GANTRY_SFTP_ASKPASS_ANSWER": "hunter2"}


# --- the operation record -----------------------------------------------------------------


def test_an_operation_records_a_start_and_a_finish(caplog: pytest.LogCaptureFixture):
    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        operation(logger, "get", remote=b"/a.csv") as record,
    ):
        record["bytes"] = 1024

    messages = [record.getMessage() for record in caplog.records]
    assert messages[0] == "get start remote=b'/a.csv'"
    assert messages[1].startswith("get ok remote=b'/a.csv' bytes=1024 elapsed=")
    assert messages[1].endswith("s")


def test_a_failed_operation_records_the_failure_and_re_raises(caplog: pytest.LogCaptureFixture):
    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        pytest.raises(ValueError),
        operation(logger, "put", remote=b"/a.csv"),
    ):
        raise ValueError("no")

    assert caplog.records[-1].getMessage().startswith("put failed remote=b'/a.csv' ValueError")


def test_a_cancelled_operation_still_closes_its_record(caplog: pytest.LogCaptureFixture):
    """The case worth having: "started, and you never heard from it again" is the log of a hang.

    Cancellation is a ``BaseException`` on both anyio backends, so an ``except Exception`` here
    would lose exactly the record that distinguishes a cancelled transfer from a hung one.
    """
    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        # KeyboardInterrupt stands in for anyio's Cancelled: a BaseException, so an
        # `except Exception` in the timer would lose this record rather than close it.
        pytest.raises(KeyboardInterrupt),
        operation(logger, "get", remote=b"/a.csv"),
    ):
        raise KeyboardInterrupt

    assert "get failed remote=b'/a.csv' KeyboardInterrupt" in caplog.records[-1].getMessage()


def test_an_operation_field_renders_a_path_without_its_class_name(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        operation(logger, "get", local=tmp_path / "out.csv"),
    ):
        pass

    assert f"local='{tmp_path / 'out.csv'}'" in caplog.records[0].getMessage()


def test_an_untrusted_field_is_escaped_and_capped(caplog: pytest.LogCaptureFixture):
    """The same two rules as the dumper, applied where a *server-supplied path* becomes a field.

    ``get_tree`` names remote paths in its records, and those names came from ``READDIR``.
    """
    hostile_path = b"a" * 400 + HOSTILE
    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        operation(logger, "get", remote=hostile_path),
    ):
        pass

    message = caplog.records[0].getMessage()
    assert "\n" not in message
    assert "\x1b" not in message
    # The cap is on the *rendered* length, which is what lands in the file -- and escaping
    # grows it, since `\x1b` is four characters once written down.
    assert message.endswith(f"+{len(repr(hostile_path)) - MAX_VALUE_CHARS}")
    assert len(message) < len(repr(hostile_path))


def test_nothing_is_rendered_when_the_logger_is_off(caplog: pytest.LogCaptureFixture):
    """The guard is `isEnabledFor`, and this is what proves it guards.

    A field renderer that raises stands in for the cost: if the record were being built with
    logging off, this test would fail with that error rather than pass.
    """

    class Exploding:
        def __repr__(self) -> str:
            raise AssertionError("a field was rendered with the logger disabled")

    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.CRITICAL, logger="gantry_sftp.session"),
        operation(logger, "get", remote=Exploding()) as record,
    ):
        record["bytes"] = 1

    assert caplog.records == []


# --- the fields as data, not only as a sentence (D-98) ------------------------------------


def emit(logger_name: str, name: str, **fields):
    """Run one operation and return the records it produced."""
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger(logger_name)
    handler = Capture()
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        with operation(logger, name, **fields) as record:
            record["bytes"] = 4096
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
    return records


def test_every_field_arrives_as_data_and_not_only_inside_the_message():
    """The defect D-98 describes, stated as its own test.

    A record that *formats* correctly and carries nothing queryable is exactly what shipped
    before: the fields were assembled, rendered into the message, and discarded. So this
    asserts the attribute rather than the text, which is the half the old tests could not see.
    """
    start, finish = emit("gantry_sftp.session", "get", remote=b"/incoming/a.csv", local="out.csv")

    assert record_fields(start) == {
        "operation": "get",
        "event": "start",
        "remote": "/incoming/a.csv",
        "local": "out.csv",
    }
    fields = record_fields(finish)
    assert fields["event"] == "ok"
    assert fields["bytes"] == 4096
    assert isinstance(fields["elapsed"], float)


def test_the_fields_survive_a_real_formatter_rather_than_only_caplog():
    """``caplog`` keeps the record object, so it cannot tell a working ``extra`` from a broken one.

    A colliding ``extra`` key raises at *emit* time -- inside ``Formatter.format`` or the
    handler -- which is the failure mode that turns a logging call into an application crash.
    So this drives a real ``StreamHandler`` with a real ``Formatter``, and the format string
    names one of our fields so the record has to actually carry it.
    """
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s | op=%(gantry)s"))
    logger = logging.getLogger("gantry_sftp.session")
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        with operation(logger, "put", remote=b"/incoming/a.csv") as record:
            record["bytes"] = 7
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)

    written = stream.getvalue().splitlines()
    assert len(written) == 2
    assert written[0].startswith("DEBUG put start remote=b'/incoming/a.csv' | op={")
    assert "'operation': 'put'" in written[0]
    assert "'bytes': 7" in written[1]


def test_a_json_formatter_can_serialise_every_field_this_library_emits():
    """The sink this card exists for, and the one a `bytes` field would break.

    Cloud Logging, CloudWatch and Datadog all ingest one JSON object per line. A remote path is
    `bytes` on the wire and need not be valid UTF-8, so neither the raw value nor a lenient
    decode survives ``json.dumps(...).encode()`` -- the first is not serialisable and the second
    produces lone surrogates that the encode step refuses. The escaped rendering does.
    """
    records = emit("gantry_sftp.session", "get", remote=b"/incoming/caf\xe9.csv", local="out.csv")
    for record in records:
        line = json.dumps({"message": record.getMessage(), **record_fields(record)})
        # `.encode()` is the step that refuses a lone surrogate, and it is what a sink does to
        # the line before writing it. A field carrying the raw name would fail here.
        assert json.loads(line.encode("utf-8").decode("utf-8"))["message"]
        assert json.loads(line)["remote"] == "/incoming/caf\\xe9.csv"


def test_a_field_is_escaped_but_not_wrapped_in_reprs_quotes():
    """Both halves matter, and they pull in opposite directions.

    Escaped, because a name the server chose can otherwise forge a record or drive a terminal --
    the same rule the frame dumper follows. Unquoted, because ``repr``'s framing becomes part of
    the value a sink indexes, so an operator filtering on the path they know would match nothing
    and would have to learn to write our rendering instead. That is re-parsing our text one
    layer in, which is the defect rather than the fix.
    """
    (start, _) = emit("gantry_sftp.session", "get", remote=b"/incoming/" + HOSTILE)
    remote = record_fields(start)["remote"]
    assert isinstance(remote, str)
    assert remote.startswith("/incoming/")
    assert "\n" not in remote
    assert "\x1b" not in remote
    assert "\\n" in remote
    assert not remote.startswith(("'", "b"))


def test_a_number_stays_a_number_so_a_threshold_alert_can_be_written():
    # The whole point of a field over a sentence: `bytes > 1e9` is a query, `"bytes=1024"` is a
    # substring match that also matches 10240.
    (_, finish) = emit("gantry_sftp.session", "get", remote=b"/a")
    assert record_fields(finish)["bytes"] == 4096
    assert not isinstance(record_fields(finish)["bytes"], str)


def test_the_keys_this_library_chooses_still_read_as_themselves():
    """Escaping every key costs nothing where the value really is an identifier.

    This is what the old ``OUR_OWN_VOCABULARY`` exemption was protecting -- ``operation`` must
    not arrive as ``"'get_tree'"``, because the quotes would become part of the value a sink
    indexes and nobody writes an alert against those. It holds without an exemption:
    ``repr`` of an identifier, with the quotes taken back off, is the identity function.
    """
    (start, _) = emit("gantry_sftp.session", "get_tree", remote=b"/a")
    assert record_fields(start)["operation"] == "get_tree"
    assert record_fields(start)["event"] == "start"


@pytest.mark.parametrize("key", ["operation", "event", "error", "mechanism", "remote"])
def test_no_key_is_exempt_from_escaping(key: str):
    """D-130, and the direction the old exemption failed in.

    ``OUR_OWN_VOCABULARY`` named four keys whose values skipped escaping on the grounds that
    this library picks them from a closed set. Three of them were closed and lost nothing by
    being escaped; ``error`` was not closed at all -- see the test below -- and it was the one
    the list vouched for. The property that replaces the list is that there is no list: a key
    cannot be added to an exemption that does not exist.
    """
    escaped = fields_of(**{key: "forged\nrecord"})["gantry"][key]
    assert escaped == "forged\\nrecord"
    assert "\n" not in escaped


def test_an_exception_class_name_cannot_forge_a_record(caplog: pytest.LogCaptureFixture):
    """The bug the mutation lane found in ``error``'s exemption (D-130).

    A class name reads like a closed set -- everything raised here is declared with ``class``
    and so is named by an identifier -- but ``__name__`` is whatever the type was built with,
    and ``type(...)`` takes any string. So the one key ``OUR_OWN_VOCABULARY`` could not vouch
    for was the one it exempted, and the newline reached the message, the field and
    ``summarise`` alike: three sites, one wrong assumption about who chooses that string.
    """
    forged = type("Forged\nDEBUG fake record", (RuntimeError,), {})

    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        pytest.raises(forged),
        operation(logger, "get", remote=b"/a.csv"),
    ):
        raise forged("boom")

    record = caplog.records[-1]
    assert "\n" not in record.getMessage()
    assert "Forged\\nDEBUG fake record" in record.getMessage()
    assert record_fields(record)["error"] == "Forged\\nDEBUG fake record"
    # And the third site, which renders a class name without going through a field at all.
    assert "\n" not in summarise(forged("boom"))


def test_a_failure_carries_the_exception_class_as_a_field():
    logger = logging.getLogger("gantry_sftp.session")
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        with pytest.raises(ValueError), operation(logger, "put", remote=b"/a"):
            raise ValueError("no")
    finally:
        logger.removeHandler(handler)

    fields = record_fields(records[-1])
    assert fields["event"] == "failed"
    assert fields["error"] == "ValueError"
    assert isinstance(fields["elapsed"], float)
    # The failure record's own `operation` key, which nothing asserted: every test that pins it
    # reads a *successful* record, and the two branches spell the key separately. A record that
    # says which operation failed is the one an alert is written on.
    assert fields["operation"] == "put"


@pytest.mark.parametrize("fail", [False, True], ids=["ok", "failed"])
def test_elapsed_is_a_duration_and_not_merely_a_float(fail: bool):
    """``isinstance(..., float)`` is not an assertion about the number.

    ``monotonic()`` counts from an arbitrary epoch, so ``monotonic() + started`` is a float,
    lands on the record, renders through ``%.3f`` and reads as a plausible time to every
    assertion this suite had -- while being roughly twice the machine's uptime. The oracle has
    to be a *second* measurement rather than the type: the operation cannot have taken longer
    than the wall-clock the test measured around it. Both branches compute this separately.
    """
    logger = logging.getLogger("gantry_sftp.session")
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    before = monotonic()
    try:
        if fail:
            with pytest.raises(ValueError), operation(logger, "put", remote=b"/a"):
                raise ValueError("no")
        else:
            with operation(logger, "get", remote=b"/a"):
                pass
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
    outer = monotonic() - before

    elapsed = record_fields(records[-1])["elapsed"]
    assert isinstance(elapsed, float)
    assert 0.0 <= elapsed <= outer


def test_a_result_key_that_shadows_a_field_does_not_crash_the_log_call():
    """``fields_of(**a, **b)`` raises ``TypeError`` on a shared key -- inside a logging call.

    No call site does it today, which is exactly why it needs a test: the failure would be an
    application crash in whatever path happened to be logging, discovered by a user.
    """
    logger = logging.getLogger("gantry_sftp.session")
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        with operation(logger, "get", remote=b"/first") as record:
            record["remote"] = b"/second"
    finally:
        logger.removeHandler(handler)

    # The later value wins, which is the right answer: what an operation *recorded* is more
    # current than what it was called with.
    assert record_fields(records[-1])["remote"] == "/second"


def test_a_collection_field_keeps_its_shape_instead_of_becoming_one_long_string():
    """The bug this found, kept as its own test.

    ``argv`` and the steering environment render well past the 96-character cap, so capping the
    rendered *collection* truncated the spawn record mid-key -- and that record exists precisely
    to say which variables were set. A list stays a list and a mapping stays a mapping; the cap
    applies to each scalar inside, where it was always meant to.
    """
    (start, _) = emit(
        "gantry_sftp.transport",
        "spawn",
        argv=["ssh", "-o", "StrictHostKeyChecking=yes", "-s", "--", "h", "sftp"],
        steering={"SSH_ASKPASS": "/run/gantry/helper.sh", "SSH_ASKPASS_REQUIRE": "force"},
    )
    fields = record_fields(start)
    assert fields["argv"] == ["ssh", "-o", "StrictHostKeyChecking=yes", "-s", "--", "h", "sftp"]
    assert fields["steering"] == {
        "SSH_ASKPASS": "/run/gantry/helper.sh",
        "SSH_ASKPASS_REQUIRE": "force",
    }


def test_a_scalar_inside_a_collection_is_still_escaped_and_capped():
    # The cap moved, it did not go: a server-chosen name inside a list is still bounded, and a
    # key is escaped as thoroughly as a value because a caller's own env overlay reaches here.
    (start, _) = emit("gantry_sftp.transport", "spawn", argv=[b"x" * 400], steering={"A\nB": "v"})
    fields = record_fields(start)
    # The cap counts the *unquoted* rendering, since that is what the field carries -- the
    # three characters of `b'` and the closing quote are framing this surface does not keep.
    unquoted = repr(b"x" * 400)[2:-1]
    assert fields["argv"][0] == unquoted[:MAX_VALUE_CHARS] + f"+{len(unquoted) - MAX_VALUE_CHARS}"
    assert list(fields["steering"]) == ["A\\nB"]


def test_a_message_with_more_than_one_field_renders_exactly(caplog: pytest.LogCaptureFixture):
    """Every other message assertion here uses one field, ``startswith`` or ``in``.

    None of those can see what joins the pairs together, so the separator between them was
    unasserted -- a mutation putting four characters between every field passed the whole
    suite. A record is read by a person at 3am and parsed by a sink; the exact spelling of
    the line with two fields on it is the specification of both.
    """
    logger = logging.getLogger("gantry_sftp.session")
    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"),
        operation(logger, "get", remote=b"/a.csv", local="out.csv") as record,
    ):
        record["bytes"] = 1024

    start, finish = (record.getMessage() for record in caplog.records)
    assert start == "get start remote=b'/a.csv' local='out.csv'"
    assert finish.startswith("get ok remote=b'/a.csv' local='out.csv' bytes=1024 elapsed=")


def test_a_field_at_exactly_the_cap_is_not_truncated_either():
    """The same boundary the frame dumper has a test for, on the surface that copied its rule.

    ``_capped`` is deliberately a second copy of :data:`gantry_sftp.codec.MAX_FIELD_BYTES`'s
    rule rather than an import of it, so it needs a second copy of the off-by-one test: at
    exactly the cap the value is whole, one past it says how many it dropped. Without this,
    ``<=`` reads as ``<`` and every 96-character name is reported as truncated by zero.
    """
    at_cap = "a" * MAX_VALUE_CHARS
    assert fields_of(remote=at_cap)["gantry"]["remote"] == at_cap
    assert fields_of(remote=at_cap + "a")["gantry"]["remote"] == at_cap + "+1"


@pytest.mark.parametrize("value", ["Kevin's.csv", b"Kevin's.csv"], ids=["str", "bytes"])
def test_a_name_with_an_apostrophe_still_loses_reprs_quotes(value: str | bytes):
    """The axis every other rendering test here holds constant: which quote ``repr`` picks.

    ``repr`` switches to double quotes for a value containing a single one, so ``Kevin's.csv``
    renders as ``"Kevin's.csv"`` and ``b"Kevin's.csv"`` -- a whole branch of the unquoting that
    no test reached, because every sample was a path made of letters and slashes. An apostrophe
    in a filename is not an exotic input; it is Tuesday.
    """
    assert fields_of(remote=value)["gantry"]["remote"] == "Kevin's.csv"


@pytest.mark.parametrize("value", ["", b""], ids=["str", "bytes"])
def test_an_empty_field_arrives_empty_rather_than_as_two_quote_characters(value: str | bytes):
    """``_SHORTEST_LITERAL`` is 2 because ``repr("")`` is two quotes and nothing between.

    The constant's own docstring names this case and nothing exercised it, so the ``>=`` that
    admits it read exactly like a ``>`` that does not -- and under that spelling an empty name
    arrives at the sink as the two characters ``''``, which is a value somebody has to learn
    means "empty" rather than a directory called ``''``.
    """
    assert fields_of(remote=value)["gantry"]["remote"] == ""


def test_a_value_whose_repr_is_not_a_quoted_literal_is_left_whole():
    """The docstring's own carve-out, and it had no test on either side of the branch.

    ``None`` is the reachable case -- ``mechanism`` is ``None`` for an upload that published
    by writing in place -- and its ``repr`` is four characters with no quotes anywhere. Strip
    the outer pair anyway and the field says ``on``.
    """
    assert fields_of(mechanism=None)["gantry"]["mechanism"] == "None"


def test_a_hostile_repr_that_opens_with_a_quote_is_not_trimmed_into_something_else():
    """The other side of that branch: a ``repr`` that *starts* like a literal and is not one.

    Nothing stops a caller's object rendering however it likes, and the unquoting has to decide
    on the pair rather than on the opening character -- otherwise the first and last characters
    of an arbitrary rendering are silently eaten, which is a value nobody can trace back to
    what produced it.
    """

    class Misleading:
        def __repr__(self) -> str:
            return "'oops"

    assert fields_of(remote=Misleading())["gantry"]["remote"] == "'oops"


def test_a_str_field_is_escaped_as_thoroughly_as_a_bytes_one():
    """Same rule, other spelling. ``local`` is a ``str`` on every call site that has one.

    The escaping tests all fed ``bytes``, because that is what ``READDIR`` returns -- so the
    ``str`` half of the same path was covered only by values with nothing in them to escape,
    which cannot tell escaping from a passthrough.
    """
    escaped = fields_of(local="/incoming/" + HOSTILE.decode("latin-1"))["gantry"]["local"]
    assert isinstance(escaped, str)
    assert "\n" not in escaped
    assert "\x1b" not in escaped
    assert escaped.startswith("/incoming/")


def test_record_fields_tolerates_a_record_from_anywhere_else():
    other = logging.LogRecord("other.library", logging.INFO, __file__, 1, "hello", None, None)
    assert record_fields(other) == {}


# --- summarising an exception for a log line ----------------------------------------------


def test_summarise_puts_a_multi_line_error_on_one_line():
    """``ConnectError`` renders ssh's stderr verbatim, newlines and all -- correct for a
    traceback, and a forged record per line in a log."""
    error = ConnectError("could not connect", stderr="Permission denied\nkex_exchange: fail\n")
    rendered = summarise(error)
    assert "\n" not in rendered
    assert rendered.startswith("ConnectError '")


def test_summarise_caps_a_long_message():
    error = ConnectError("x" * 500)
    assert summarise(error).endswith(f"+{500 + 2 - MAX_VALUE_CHARS}")


# --- the library is silent until an application asks -------------------------------------


def test_the_package_logger_has_a_null_handler():
    """A library that logs with no handler configured writes to stderr through
    ``logging.lastResort``. The ``NullHandler`` is what makes the default silence real, and it
    is the one part of this that a user notices only when it is missing."""
    handlers = logging.getLogger("gantry_sftp").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


# --- against a real server ----------------------------------------------------------------


def requires_sftp_server() -> None:
    if find_sftp_server() is None:
        pytest.skip("sftp-server not installed (ships in openssh-server)")


async def test_the_counters_move_over_a_real_session(tmp_path: Path):
    """Cumulative counters, against the server everyone else's client is tested against.

    A fake would only confirm that the two lines incrementing them run. What this adds is that
    they are on the paths a real transfer actually takes, and that both directions are counted
    -- a receive counter fed by a per-frame hook rather than a per-read one would pass every
    unit test and under-report every chunk that did not complete a frame.
    """
    requires_sftp_server()
    (tmp_path / "data.csv").write_bytes(b"x" * 100_000)

    async with (
        open_local_server_transport(cwd=tmp_path) as transport,
        open_session(transport) as sftp,
    ):
        assert sftp.requests_sent == 0
        assert sftp.bytes_received == 0

        moved = await sftp.get(str(tmp_path / "data.csv"), tmp_path / "out.csv")

        assert moved.transferred == 100_000
        assert sftp.requests_sent >= 4  # STAT, OPEN, at least one READ, CLOSE
        assert sftp.replies_received == sftp.requests_sent
        assert sftp.bytes_received > 100_000  # payload plus framing
        assert 0 < sftp.bytes_sent < 100_000  # requests only; nothing was uploaded
        assert f"requests={sftp.requests_sent}/{sftp.replies_received}" in repr(sftp)


async def test_the_frame_dump_shows_both_directions(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    requires_sftp_server()
    (tmp_path / "a.csv").write_bytes(b"xyz")

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.frames"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.stat(str(tmp_path / "a.csv"))

    dumped = [record.getMessage() for record in caplog.records]
    assert any(line.startswith("-> STAT id=") for line in dumped)
    assert any(line.startswith("<- ATTRS id=") for line in dumped)
    assert any("size=3" in line for line in dumped)


async def test_the_dump_is_not_rendered_when_its_logger_is_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """`isEnabledFor` guards every dump site, and this is what proves it on the hot path.

    A download at depth 64 calls this per frame. Rendering unconditionally and letting
    ``logging`` discard the result would cost a formatted string per packet -- invisible in a
    unit test and measurable in the benchmark.
    """
    requires_sftp_server()
    (tmp_path / "a.csv").write_bytes(b"xyz")

    calls: list[object] = []

    def counting_describe(packet: object) -> str:
        calls.append(packet)
        return "unused"

    monkeypatch.setattr("gantry_sftp.session._dispatch.describe", counting_describe)
    logging.getLogger("gantry_sftp.frames").setLevel(logging.CRITICAL)
    try:
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.stat(str(tmp_path / "a.csv"))
    finally:
        logging.getLogger("gantry_sftp.frames").setLevel(logging.NOTSET)

    assert calls == []


async def test_a_download_records_what_it_moved(caplog: pytest.LogCaptureFixture, tmp_path: Path):
    requires_sftp_server()
    (tmp_path / "a.csv").write_bytes(b"x" * 2048)

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.get(str(tmp_path / "a.csv"), tmp_path / "out.csv")

    messages = [record.getMessage() for record in caplog.records]
    assert any(message.startswith("negotiated version=3 extensions=") for message in messages)
    assert any(message.startswith("get start remote=") for message in messages)
    assert any("get ok " in message and "bytes=2048" in message for message in messages)


async def test_an_upload_records_the_publish_mechanism(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    """Which mechanism published the file is the question an atomic upload exists to answer,
    so the record carries it rather than only the byte count."""
    requires_sftp_server()
    source = tmp_path / "source.csv"
    source.write_bytes(b"y" * 512)

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.put(source, str(tmp_path / "published.csv"))

    finished = [m for m in (r.getMessage() for r in caplog.records) if m.startswith("put ok ")]
    assert len(finished) == 1
    assert "bytes=512" in finished[0]
    assert "mechanism=" in finished[0]
    # And as *data*, which is what D-98 was for and what the substring above cannot see: a
    # `mechanism` of `None` renders as `mechanism=None` and still contains "mechanism=". The
    # two identifying fields go the same way -- an upload's record names both ends or a
    # reader has one line per transfer and no way to tell which transfer.
    record = next(r for r in caplog.records if r.getMessage().startswith("put ok "))
    fields = record_fields(record)
    assert fields["operation"] == "put"
    assert fields["local"] == str(source)
    assert fields["remote"] == str(tmp_path / "published.csv")
    assert fields["mechanism"] == "POSIX_RENAME"


async def test_a_tree_download_records_its_counts(caplog: pytest.LogCaptureFixture, tmp_path: Path):
    requires_sftp_server()
    source = tmp_path / "tree"
    (source / "sub").mkdir(parents=True)
    (source / "one.csv").write_bytes(b"a")
    (source / "sub" / "two.csv").write_bytes(b"bb")

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.get_tree(str(source), tmp_path / "copy")

    finished = [m for m in (r.getMessage() for r in caplog.records) if m.startswith("get_tree ok ")]
    assert len(finished) == 1
    assert "files=2" in finished[0]
    assert "directories=1" in finished[0]
    assert "bytes=3" in finished[0]
    assert "skipped=0" in finished[0]
    # And the two identifying fields, which the counts above say nothing about: a record that
    # names neither end is one line per tree with no way to tell which tree.
    fields = record_fields(
        next(r for r in caplog.records if r.getMessage().startswith("get_tree ok "))
    )
    assert fields["remote"] == str(source)
    assert fields["local"] == str(tmp_path / "copy")


# --- the credential, through every surface at once ----------------------------------------


async def test_a_password_reaches_no_surface_this_library_has(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    """The Definition of Done 3 test: one credential, every surface, one assertion.

    Checking surfaces one at a time is how the frame-locals leak survived to 0.9 -- ``str``,
    ``repr`` and ``argv`` were each checked and each clean, while the environment dictionary in
    a live generator frame held the plaintext. So this drives a real connection attempt with a
    real password and searches *everything* the library emitted or exposed.
    """
    if sys.platform.startswith("win"):
        pytest.skip("password= is POSIX only")

    canary = PASSWORD
    failing = tmp_path / "fake-ssh"
    failing.write_text("#!/bin/sh\nexec 1>&2; echo 'Permission denied (password).'; exit 255\n")
    failing.chmod(0o700)

    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp"),
        pytest.raises(ConnectError) as raised,
    ):
        async with open_ssh_transport(
            "example.invalid", ssh_executable=str(failing), password=canary
        ) as transport:
            _ = await transport.receive()

    error = raised.value
    surfaces: dict[str, str] = {
        "str(exc)": str(error),
        "repr(exc)": repr(error),
        "argv": " ".join(error.argv),
        "stderr": error.stderr,
        "log records": "\n".join(record.getMessage() for record in caplog.records),
        "log arguments": "\n".join(repr(record.args) for record in caplog.records),
        # D-98 added a surface, so it is added here rather than tested somewhere else: the
        # structured fields are a second place every value now lands, and this test exists
        # because checking surfaces one at a time is how the last leak survived.
        "structured fields": "\n".join(repr(record_fields(r)) for r in caplog.records),
        # The whole record dictionary, so an `extra` key attached anywhere -- including one
        # added later, outside `fields_of` -- is covered without this list being updated.
        "record attributes": "\n".join(repr(vars(r)) for r in caplog.records),
    }
    leaked = sorted(name for name, rendered in surfaces.items() if canary in rendered)
    assert leaked == [], f"the password reached: {', '.join(leaked)}"

    # And the record that would have carried it says so, rather than omitting the variable --
    # "an askpass answer was configured" is the fact a failed password auth needs.
    spawn = [r for r in caplog.records if r.getMessage().startswith("spawned pid=")]
    assert len(spawn) == 1
    assert f"'GANTRY_SFTP_ASKPASS_ANSWER': '{MASKED}'" in spawn[0].getMessage()
    # The masking reaches the field as well as the sentence, which is the half that would
    # otherwise be a new hole behind an old test.
    assert MASKED in str(record_fields(spawn[0])["steering"])
    assert record_fields(spawn[0])["operation"] == "spawn"


async def test_the_spawn_record_names_the_variables_that_arm_the_helper(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    """`SSH_ASKPASS` alone does not arm anything and `SSH_ASKPASS_REQUIRE` does -- measured
    against OpenSSH 10.0p2. A record that listed neither would leave the one question a failed
    password authentication actually raises unanswerable."""
    if sys.platform.startswith("win"):
        pytest.skip("password= is POSIX only")

    failing = tmp_path / "fake-ssh"
    failing.write_text("#!/bin/sh\nexit 255\n")
    failing.chmod(0o700)

    with (
        caplog.at_level(logging.DEBUG, logger="gantry_sftp.transport"),
        pytest.raises(ConnectError),
    ):
        async with open_ssh_transport(
            "example.invalid", ssh_executable=str(failing), password=PASSWORD
        ) as transport:
            _ = await transport.receive()

    spawned = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("spawned "))
    assert "'SSH_ASKPASS'" in spawned
    assert "'SSH_ASKPASS_REQUIRE': 'force'" in spawned
    assert any(r.getMessage().startswith("closed pid=") for r in caplog.records)


async def test_the_environment_the_record_shows_is_the_childs_not_ours(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """With no explicit ``env=`` the child inherits, so the honest answer is this process's.

    A record that reported "nothing configured" because the caller passed no mapping would be a
    confidently wrong diagnosis of the case where a helper was inherited from the environment.
    """
    requires_sftp_server()
    monkeypatch.setenv("SSH_ASKPASS", "/inherited/askpass")

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.transport"):
        async with open_local_server_transport(cwd=tmp_path):
            pass

    spawned = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("spawned "))
    assert "'SSH_ASKPASS': '/inherited/askpass'" in spawned


async def test_a_reconnect_is_the_one_thing_this_library_warns_about(
    caplog: pytest.LogCaptureFixture,
):
    """A retried failure reaches nobody -- that is what makes it the exception to the rule.

    Every other error here arrives as a typed exception carrying its own state. This one is
    swallowed by design, so without the record a link that drops on every second attempt is
    indistinguishable at runtime from a healthy one.
    """
    attempts = 0

    def connect() -> Any:
        nonlocal attempts
        attempts += 1
        raise ConnectError("the link dropped", stderr="Connection reset\nby peer\n")

    with (
        caplog.at_level(logging.WARNING, logger="gantry_sftp.session"),
        anyio.move_on_after(5),
        pytest.raises(ConnectError),
    ):
        _ = await with_reconnect(connect, lambda sftp: sftp.listdir("/"), attempts=2, backoff=0.01)

    assert attempts == 2
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert message.startswith("attempt 1 of 2 failed (ConnectError ")
    assert "reconnecting in 0.0s" in message
    # The stderr it carries is multi-line and partly server-supplied. Not in the log line.
    assert "\n" not in message

    # And the structured half, which is the whole of D-98 and was asserted nowhere. The
    # sentence above was pinned; `extra=` could be dropped entirely, every field nulled or
    # shifted onto its neighbour, and `"reconnect"` mangled to `"RECONNECT"`, with nothing
    # failing -- 21 mutation survivors on one logging call. A record whose message reads
    # correctly and whose fields are empty is worse than no record, because the sink that
    # was built to key on them silently indexes nothing.
    assert record_fields(warnings[0]) == {
        "operation": "reconnect",
        "event": "retrying",
        "attempt": 1,
        "attempts": 2,
        "error": "ConnectError",
        "delay": 0.01,
    }
    # Numbers stay numbers -- `fields_of` converts everything else, and a threshold alert on
    # `attempt` is the reason the key exists at all.
    fields = record_fields(warnings[0])
    assert isinstance(fields["attempt"], int)
    assert isinstance(fields["attempts"], int)
    assert isinstance(fields["delay"], float)


async def test_a_tree_upload_records_its_counts_as_data(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    """`put_tree` had no record test at all, and `get_tree`'s only read the message.

    Four counters, each of which is a *key* as well as a value -- and a mutated key still
    renders into the sentence, so a substring assertion on "files=2" cannot see `record["FILES"]`
    while a field assertion can. These are the numbers an operator's dashboard groups by, which
    is D-98's whole argument for the record carrying data rather than a formatted line.
    """
    requires_sftp_server()
    source = tmp_path / "tree"
    (source / "sub").mkdir(parents=True)
    (source / "one.csv").write_bytes(b"a")
    (source / "sub" / "two.csv").write_bytes(b"bb")

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.put_tree(source, str(tmp_path / "uploaded").encode())

    record = next(r for r in caplog.records if r.getMessage().startswith("put_tree ok "))
    fields = record_fields(record)
    assert fields["operation"] == "put_tree"
    assert fields["files"] == 2
    assert fields["directories"] == 1
    assert fields["bytes"] == 3
    assert fields["skipped"] == 0


async def test_a_tree_removal_records_what_it_removed(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    """`rmtree` is the operation with the least to show for itself and the most to answer for.

    It returns counts and deletes the evidence, so the record is the only durable account of
    what a run took away -- and it had no test. The operation's own *name* is in the mutation
    set too: `operation(logger, "rmtree", ...)` could be handed anything, and every message
    assertion elsewhere is about some other operation.
    """
    requires_sftp_server()
    victim = tmp_path / "doomed"
    (victim / "sub").mkdir(parents=True)
    (victim / "one.csv").write_bytes(b"a")
    (victim / "sub" / "two.csv").write_bytes(b"bb")

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            result = await sftp.rmtree(str(victim).encode())

    assert not victim.exists()
    # The empty tuple is the answer rather than an absence: `rmtree` reports what it passed
    # over, and "nothing" is what a caller checks before believing the tree is gone.
    assert result.skipped == ()
    record = next(r for r in caplog.records if r.getMessage().startswith("rmtree ok "))
    fields = record_fields(record)
    assert fields["operation"] == "rmtree"
    assert fields["remote"] == str(victim)
    assert fields["files"] == 2
    assert fields["directories"] == 2


async def test_a_download_records_both_ends_and_a_resumed_one_records_what_it_adopted(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
):
    """`get` names both files, and the already-complete resume writes its own two counters.

    D-105's eighteenth slice. The counts a plain `get` reports are asserted elsewhere; the two
    *identifying* fields were not, and a record naming neither end is one line per transfer with
    no way to tell which transfer. The resumed-and-already-complete path is a second record
    site: it returns without opening anything, so it sets `bytes` and `adopted` by hand -- and
    `adopted` is the only thing distinguishing "nothing to do" from "nothing happened".
    """
    requires_sftp_server()
    source = tmp_path / "data.csv"
    source.write_bytes(b"z" * 512)
    destination = tmp_path / "out.csv"

    with caplog.at_level(logging.DEBUG, logger="gantry_sftp.session"):
        async with (
            open_local_server_transport(cwd=tmp_path) as transport,
            open_session(transport) as sftp,
        ):
            _ = await sftp.get(str(source), destination)
            _ = await sftp.get(str(source), destination, resume=True)

    finished = [r for r in caplog.records if r.getMessage().startswith("get ok ")]
    assert len(finished) == 2

    first = record_fields(finished[0])
    assert first["operation"] == "get"
    assert first["remote"] == str(source)
    assert first["local"] == str(destination)
    assert first["bytes"] == 512

    resumed = record_fields(finished[1])
    assert resumed["bytes"] == 0, "the second call moved nothing"
    assert resumed["adopted"] == 512

"""Constants checked against a VERSION frame captured from a real OpenSSH sftp-server.

A constant asserted against itself is asserted against nothing, which is exactly how draft
0.1 of DESIGN.md came to claim ``copy-data@openssh.com`` -- a name that no server has ever
sent. The fixture here is bytes from OpenSSH 10.0p2, so the extension table is checked
against the server rather than against the author's recollection of it.

Regenerate with ``_plans/probes/sftp_server_probe.py`` if OpenSSH changes what it sends; a
mismatch is a real signal, not test noise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gantry_sftp.codec import (
    MAX_STATUS_CODE,
    NO_REQUEST_ID,
    OPENSSH_ADVERTISED_EXTENSIONS,
    PROTOCOL_VERSION,
    AttrFlag,
    OpenFlag,
    PacketType,
    StatusCode,
    WireReader,
)

FIXTURE = Path(__file__).parent / "fixtures" / "openssh_version_frame.bin"


def decode_version_frame(frame: bytes) -> tuple[int, list[tuple[str, str]]]:
    """Decode a VERSION frame body the long way, without the codec's help."""
    r = WireReader(frame)
    packet_type = r.read_uint8()
    assert packet_type == PacketType.VERSION
    version = r.read_uint32()
    extensions: list[tuple[str, str]] = []
    while not r.at_end:
        name = bytes(r.read_string()).decode("ascii")
        value = bytes(r.read_string()).decode("ascii")
        extensions.append((name, value))
    return version, extensions


@pytest.fixture(scope="module")
def version_frame() -> bytes:
    return FIXTURE.read_bytes()


def test_the_fixture_is_a_real_version_frame(version_frame: bytes):
    version, _ = decode_version_frame(version_frame)
    assert version == PROTOCOL_VERSION == 3


def test_version_frame_body_starts_with_a_version_not_a_request_id(version_frame: bytes):
    # The framing exception, in bytes. Offset 1..5 of a VERSION body is the protocol
    # version. A codec that reads it as a request id sees reply id 3 and waits forever for
    # the version that already arrived.
    assert version_frame[0] == PacketType.VERSION
    assert int.from_bytes(version_frame[1:5], "big") == 3
    assert PacketType.VERSION in NO_REQUEST_ID
    assert PacketType.INIT in NO_REQUEST_ID


def test_advertised_extensions_match_the_server_exactly(version_frame: bytes):
    _, extensions = decode_version_frame(version_frame)
    assert tuple(extensions) == OPENSSH_ADVERTISED_EXTENSIONS


def test_copy_data_and_home_directory_carry_no_openssh_suffix(version_frame: bytes):
    # The correction that motivated the fixture. Named so that a regression says what
    # broke rather than "tuples differ".
    _, extensions = decode_version_frame(version_frame)
    by_name = dict(extensions)
    assert "copy-data" in by_name
    assert "home-directory" in by_name
    assert "copy-data@openssh.com" not in by_name
    assert "home-directory@openssh.com" not in by_name


def test_extension_versions_are_strings_not_integers(version_frame: bytes):
    # statvfs is at "2" while everything around it is at "1". Comparing these as integers
    # happens to work until it does not.
    _, extensions = decode_version_frame(version_frame)
    assert all(isinstance(value, str) for _, value in extensions)
    assert dict(extensions)["statvfs@openssh.com"] == "2"
    assert dict(extensions)["fstatvfs@openssh.com"] == "2"


def test_no_extension_is_advertised_twice(version_frame: bytes):
    _, extensions = decode_version_frame(version_frame)
    names = [name for name, _ in extensions]
    assert len(names) == len(set(names))


def test_check_file_is_not_advertised(version_frame: bytes):
    # DESIGN.md 6 rung 1 depends on this being absent from OpenSSH. If a future OpenSSH
    # adds it, this test failing is the notification that the verification ladder changed.
    _, extensions = decode_version_frame(version_frame)
    names = {name for name, _ in extensions}
    assert not any(name.startswith("check-file") for name in names)


# --- the enums themselves --------------------------------------------------------------


# Every ``SSH2_FXP_*`` in OpenSSH's sftp.h, transcribed name by name. Contiguity is not
# identity: a check that 1..20 has no gaps passes just as happily with LSTAT and FSTAT
# transposed, and so does a round trip through our own encoder. Only a table that names each
# number separately can say which name holds which.
#
# sftp.h also defines SSH2_FXP_STAT_VERSION_0 as a second name for 7 -- it is what STAT was
# called in filexfer v0, and v3 spells that request LSTAT. There is no 28th packet type.
SFTP_H_PACKET_NUMBERS = {
    "INIT": 1,
    "VERSION": 2,
    "OPEN": 3,
    "CLOSE": 4,
    "READ": 5,
    "WRITE": 6,
    "LSTAT": 7,
    "FSTAT": 8,
    "SETSTAT": 9,
    "FSETSTAT": 10,
    "OPENDIR": 11,
    "READDIR": 12,
    "REMOVE": 13,
    "MKDIR": 14,
    "RMDIR": 15,
    "REALPATH": 16,
    "STAT": 17,
    "RENAME": 18,
    "READLINK": 19,
    "SYMLINK": 20,
    "STATUS": 101,
    "HANDLE": 102,
    "DATA": 103,
    "NAME": 104,
    "ATTRS": 105,
    "EXTENDED": 200,
    "EXTENDED_REPLY": 201,
}


def test_packet_type_numbers():
    assert {p.name: p.value for p in PacketType} == SFTP_H_PACKET_NUMBERS


def test_no_gaps_in_the_low_request_range():
    # Backs up the table above rather than standing in for it: a number dropped from both
    # this file and the enum in the same edit still leaves a hole here.
    low = {p.value for p in PacketType if p.value <= 20}
    assert low == set(range(1, 21))


def test_status_codes_and_their_ceiling():
    assert [s.value for s in StatusCode] == list(range(9))
    assert MAX_STATUS_CODE == StatusCode.OP_UNSUPPORTED == 8


def test_open_flags():
    assert OpenFlag.READ == 0x1
    assert OpenFlag.WRITE == 0x2
    assert OpenFlag.APPEND == 0x4
    assert OpenFlag.CREAT == 0x8
    assert OpenFlag.TRUNC == 0x10
    assert OpenFlag.EXCL == 0x20
    assert OpenFlag.READ | OpenFlag.WRITE == 0x3


def test_attr_flags_including_the_extended_high_bit():
    assert AttrFlag.SIZE == 0x1
    assert AttrFlag.UIDGID == 0x2
    assert AttrFlag.PERMISSIONS == 0x4
    assert AttrFlag.ACMODTIME == 0x8
    assert AttrFlag.EXTENDED == 0x80000000
    # The high bit is the one that gets mangled by a signed read.
    assert AttrFlag.EXTENDED > 0

"""Protocol constants for SSH filexfer version 3.

Every value here was checked on 2026-07-26 against ``draft-ietf-secsh-filexfer-02`` and
OpenSSH's ``sftp.h``, and the extension names additionally against a live
``sftp-server`` VERSION frame. See DESIGN.md 13 for the provenance table. A constant
recalled from memory is a guess wearing a fact's clothes, so none of these were.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag

__all__ = [
    "EXTENSION_CHECK_FILE",
    "EXTENSION_COPY_DATA",
    "EXTENSION_EXPAND_PATH",
    "EXTENSION_FSTATVFS",
    "EXTENSION_FSYNC",
    "EXTENSION_HARDLINK",
    "EXTENSION_HOME_DIRECTORY",
    "EXTENSION_LIMITS",
    "EXTENSION_LSETSTAT",
    "EXTENSION_POSIX_RENAME",
    "EXTENSION_STATVFS",
    "EXTENSION_USERS_GROUPS_BY_ID",
    "OPENSSH_ADVERTISED_EXTENSIONS",
    "PROTOCOL_VERSION",
    "AttrFlag",
    "OpenFlag",
    "PacketType",
    "StatusCode",
]

PROTOCOL_VERSION = 3
"""The only filexfer revision this library speaks. OpenSSH's ``SSH2_FILEXFER_VERSION``."""


class PacketType(IntEnum):
    """Packet type byte, the first byte of every frame body."""

    INIT = 1
    VERSION = 2
    OPEN = 3
    CLOSE = 4
    READ = 5
    WRITE = 6
    LSTAT = 7
    FSTAT = 8
    SETSTAT = 9
    FSETSTAT = 10
    OPENDIR = 11
    READDIR = 12
    REMOVE = 13
    MKDIR = 14
    RMDIR = 15
    REALPATH = 16
    STAT = 17
    RENAME = 18
    READLINK = 19
    SYMLINK = 20
    STATUS = 101
    HANDLE = 102
    DATA = 103
    NAME = 104
    ATTRS = 105
    EXTENDED = 200
    EXTENDED_REPLY = 201


NO_REQUEST_ID = frozenset({PacketType.INIT, PacketType.VERSION})
"""Packet types whose body starts with ``uint32 version`` instead of ``uint32 request-id``.

This is the framing exception, and it is the first packet on every connection. A codec that
models the request-id slot as universal parses VERSION as a reply to request id 3 and then
waits forever for a version that already arrived. See DESIGN.md 4.1.
"""


class StatusCode(IntEnum):
    """Status codes carried by a STATUS packet.

    ``FAILURE`` is a v3 catch-all: it means "something went wrong" and nothing more. Turning
    it into something actionable is the quirks layer's job, and its only input is the
    human-readable message string -- which some servers omit entirely.
    """

    OK = 0
    EOF = 1
    NO_SUCH_FILE = 2
    PERMISSION_DENIED = 3
    FAILURE = 4
    BAD_MESSAGE = 5
    NO_CONNECTION = 6
    CONNECTION_LOST = 7
    OP_UNSUPPORTED = 8


MAX_STATUS_CODE = StatusCode.OP_UNSUPPORTED
"""OpenSSH's ``SSH2_FX_MAX``. A code above this is a server bug, and must surface as a
``ProtocolError`` rather than as an unnamed enum member."""


class OpenFlag(IntFlag):
    """``pflags`` for OPEN. Combined bitwise; ``CREAT`` is spelled without the ``e``."""

    READ = 0x00000001
    WRITE = 0x00000002
    APPEND = 0x00000004
    CREAT = 0x00000008
    TRUNC = 0x00000010
    EXCL = 0x00000020


class AttrFlag(IntFlag):
    """Which fields are present in an ATTRS structure.

    Two of these bits govern *two* fields each: ``UIDGID`` covers uid and gid, and
    ``ACMODTIME`` covers atime and mtime. Reading either as a single field desynchronises
    the rest of the packet, so the pairing is expressed in the decoder's structure rather
    than left to the reader to remember.
    """

    SIZE = 0x00000001
    UIDGID = 0x00000002
    PERMISSIONS = 0x00000004
    ACMODTIME = 0x00000008
    EXTENDED = 0x80000000


# --- extension names -------------------------------------------------------------------
#
# These are wire strings, and two of them break the naming pattern in a way that is
# invisible until it silently costs you the feature: `copy-data` and `home-directory` carry
# NO @openssh.com suffix. Matching the suffixed spelling never negotiates, degrades to the
# fallback forever, and passes any test written against the same wrong constant.
#
# tests/test_constants.py asserts this tuple against a VERSION frame captured from a real
# sftp-server, so the names are checked against the server rather than against themselves.

# **Every name here is public, including the ones this library does not implement**, and the
# rule is the one D-52 settled: a constant is a fact about what servers *say*, not a build list.
# `Session.supports()` answers a question about the far end's advertisement, so a caller asking
# about `statvfs@openssh.com` should never have to type it -- hand-typing a wire string is
# exactly how `copy-data@openssh.com` happened. Which of these are *implemented* is a separate
# question with a separate answer, in DESIGN.md 4.2's table.
#
# `tests/test_constants.py` asserts that this block, this module's `__all__` and the package's
# exports name the same set, so the next extension cannot land in one of the three.

EXTENSION_POSIX_RENAME = "posix-rename@openssh.com"
EXTENSION_STATVFS = "statvfs@openssh.com"
EXTENSION_FSTATVFS = "fstatvfs@openssh.com"
EXTENSION_HARDLINK = "hardlink@openssh.com"
EXTENSION_FSYNC = "fsync@openssh.com"
EXTENSION_LSETSTAT = "lsetstat@openssh.com"
EXTENSION_LIMITS = "limits@openssh.com"
EXTENSION_EXPAND_PATH = "expand-path@openssh.com"
EXTENSION_COPY_DATA = "copy-data"  # no @openssh.com -- verified on the wire
EXTENSION_HOME_DIRECTORY = "home-directory"  # no @openssh.com -- verified on the wire
EXTENSION_USERS_GROUPS_BY_ID = "users-groups-by-id@openssh.com"

EXTENSION_CHECK_FILE = "check-file"
"""Server-side hashing. **Not an OpenSSH extension** -- it answers ``OP_UNSUPPORTED`` under
all three spellings, measured. Paramiko's server advertises exactly this, unsuffixed, with a
value of ``md5,sha1``; ProFTPD's ``mod_sftp`` implements the same idea as ``checkFile``.

It is rung 1 of DESIGN.md 6's verification ladder and the only rung that verifies *content*
without moving the bytes again."""

OPENSSH_ADVERTISED_EXTENSIONS: tuple[tuple[str, str], ...] = (
    (EXTENSION_POSIX_RENAME, "1"),
    (EXTENSION_STATVFS, "2"),
    (EXTENSION_FSTATVFS, "2"),
    (EXTENSION_HARDLINK, "1"),
    (EXTENSION_FSYNC, "1"),
    (EXTENSION_LSETSTAT, "1"),
    (EXTENSION_LIMITS, "1"),
    (EXTENSION_EXPAND_PATH, "1"),
    (EXTENSION_COPY_DATA, "1"),
    (EXTENSION_HOME_DIRECTORY, "1"),
    (EXTENSION_USERS_GROUPS_BY_ID, "1"),
)
"""What OpenSSH's own sftp-server advertises, in advertisement order.

Versions are *strings* on the wire (``"1"``, ``"2"``), not integers. Comparing them as
integers mis-negotiates ``statvfs``, which is at ``"2"``.

This is a description of one server, not a requirement. Most enterprise endpoints advertise
none of these, which is why every extension needs a tested fallback rather than a
documented one.
"""

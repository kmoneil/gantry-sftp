"""Which server is at the other end, and how much its error messages are worth.

DESIGN.md 7 proposes a declarative quirks registry: fingerprint the server, load a profile,
let the profile set pipeline caps, extension substitutes and error-mapping rules. This module
is the fingerprint and nothing else, and the reason is measurement rather than laziness --
`live-tests/matrix.py` put three implementations side by side and **none of the behavioural
overrides that section proposes has a case to fix**. Advertisement plus a documented fallback
already covers extensions; nothing in the matrix needs a pipeline cap; and the error-mapping
rules turn out to have almost nothing to read (see :attr:`ServerProfile.informative_messages`).

So a profile carries identity, and identity is **diagnostic only**. Nothing here changes what
a request does or how a reply is interpreted. That is a deliberate safety property, not a
stage we have not reached yet: a fingerprint is a guess about an opaque peer, and a wrong
guess must cost a wrong name in a log line rather than a wrong answer in a file. When a
behavioural rule earns its place, it arrives with the fixture that proves it -- CLAUDE.md's
"a quirks profile without a passing test against that server is a rumor", and the matrix is
what makes honouring that possible.

**Fingerprinting does not use the SSH banner**, which §7 assumed it would. We never see it --
``ssh`` consumes it -- and recovering it costs ``LogLevel=DEBUG1`` and about 3.4 KB of stderr
per connection, measured. It is also a string the server chooses, so it could never be a
security input. What is free is the ``VERSION`` reply's extension list, which arrives before
anything else and is what this keys on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from gantry_sftp.codec import WireReader

__all__ = [
    "PROFILES",
    "UNKNOWN",
    "ServerProfile",
    "identify",
    "parse_vendor_id",
]


@dataclass(frozen=True, slots=True)
class ServerProfile:
    """What we believe is at the other end, and what that implies.

    Attributes:
        name: Short identifier -- ``"openssh"``, ``"asyncssh"``, ``"paramiko"`` or
            ``"unknown"``. Stable enough to match on in a caller's own code.
        description: One line for a human reading a log or an exception note.
        version: The server's own version string where it volunteers one, which today means
            a ``vendor-id`` extension. ``None`` otherwise -- and *not* guessed from anything
            else, because a version inferred from an extension list is a rumour with a
            decimal point in it.
        informative_messages: Whether this server's ``STATUS`` message text tells you
            anything the status code does not. **Measured, and mostly false.**
    """

    name: str
    description: str
    version: str | None = None
    informative_messages: bool = False

    @property
    def label(self) -> str:
        """``name/version`` where a version is known, else just the name. For ``repr``."""
        return f"{self.name}/{self.version}" if self.version else self.name


UNKNOWN = ServerProfile(
    name="unknown",
    description="an SFTP server this library has no fingerprint for",
    informative_messages=False,
)
"""The honest answer, and the conservative one.

``informative_messages`` is ``False`` here because assuming a stranger's error text is
meaningful is the assumption that costs something: it would invite reading a status message
as evidence when it may be a constant.
"""

_OPENSSH_MARKERS = frozenset(
    {
        b"users-groups-by-id@openssh.com",
        b"home-directory",
        b"expand-path@openssh.com",
    }
)
"""Extensions only OpenSSH's server advertises, of the three implementations measured.

Any one of them is taken as evidence. All three arrived in OpenSSH 8.9-9.0, so an older
OpenSSH advertises none of them and is reported as ``unknown`` -- which is the right way to
be wrong, since the alternative is a marker so weak that another implementation matches it.
"""

_PARAMIKO_MARKERS = frozenset({b"check-file"})
"""Paramiko's server advertises exactly this one, unsuffixed, with a value of ``md5,sha1``.

Not conclusive: ProFTPD's ``mod_sftp`` implements the same idea, though it spells it
``checkFile``. Being wrong costs a name in a log line -- see this module's docstring on why
that bound is deliberate.
"""

PROFILES: Mapping[str, ServerProfile] = {
    "openssh": ServerProfile(
        name="openssh",
        description="OpenSSH sftp-server",
        # Measured: OpenSSH answers five distinct FAILURE conditions -- MKDIR on an existing
        # directory, RENAME onto an existing target, CREAT|EXCL on an existing file, RMDIR of
        # a non-empty directory, REMOVE of a directory -- with the single word "Failure". The
        # message is a constant function of the status code and carries nothing beyond it.
        informative_messages=False,
    ),
    "asyncssh": ServerProfile(
        name="asyncssh",
        description="asyncssh's built-in SFTP server",
        # Measured: the same five conditions produce "File exists", "File already exists",
        # "Is a directory", "Directory not empty" -- strerror text, genuinely classifiable.
        # The only implementation of the three where a message-based rule could ever work.
        informative_messages=True,
    ),
    "paramiko": ServerProfile(
        name="paramiko",
        description="paramiko's SFTPServer",
        # Measured: "Failure" for every provoked condition, as OpenSSH.
        informative_messages=False,
    ),
}
"""Every implementation with a fixture behind it, and no others.

Ten profiles written from vendor documentation would be ten rumours; §7 proposes shipping
that many and this ships three, because three is how many `live-tests/matrix.py` can start.
"""

_VENDOR_ID = b"vendor-id"

_VENDOR_PRODUCT_TO_PROFILE = {"asyncssh": "asyncssh"}
"""Product names, lowercased, that map onto a profile above."""


def parse_vendor_id(data: bytes | memoryview) -> tuple[str, str, str, int] | None:
    """Decode a ``vendor-id`` extension body, or ``None`` if it is not one.

    Layout is ``string vendor, string product, string version, uint64 build``. **Sourced from
    asyncssh's own ``_parse_vendor_id`` and from bytes captured off its server**, not from the
    specification -- it is in neither ``draft-ietf-secsh-filexfer-05`` nor ``-13``, both of
    which were checked. An earlier comment in this repo cited draft-05 §4.3 for it and was
    wrong, which is the reason this docstring names its sources.

    Returns:
        ``(vendor, product, version, build)``, or ``None`` when the body does not decode --
        a short body, a length that overruns, anything. Server-supplied input gets the
        three-state treatment: yes, no, and unparseable, with the third one not being an
        exception, because a malformed brag is not worth failing a connection over.
    """
    try:
        reader = WireReader(data)
        # `read_string` hands back a view rather than a copy, which is right for the data
        # path and needs materialising here before it can be decoded.
        vendor = bytes(reader.read_string()).decode("utf-8", "replace")
        product = bytes(reader.read_string()).decode("utf-8", "replace")
        version = bytes(reader.read_string()).decode("utf-8", "replace")
        build = reader.read_uint64()
    except Exception:
        # Deliberately broad. Every way this can fail -- a short body, a length that
        # overruns, a type error from something that is not bytes at all -- means the same
        # thing: not a vendor-id we can use. Narrowing it would list the ways a hostile
        # server has thought of so far.
        return None
    return vendor, product, version, build


def identify(extensions: Mapping[bytes, bytes]) -> ServerProfile:
    """Work out which implementation advertised ``extensions``.

    Two sources, in order of how much they are worth:

    1. **``vendor-id``**, where the server sends one. Structured, self-declared and
       unambiguous, and it carries a version nothing else does. §7 does not mention it.
    2. **Marker extensions** otherwise -- names only one implementation in the matrix
       advertises. Weaker, and version-floored: they identify OpenSSH 8.9+ and nothing older.

    A server matching neither is :data:`UNKNOWN`, which is an answer rather than a failure.

    Args:
        extensions: What the server advertised in its ``VERSION`` reply.

    Returns:
        A profile. Never raises: this runs during connection setup, and a fingerprint that
        could fail a connection would be worse than no fingerprint.
    """
    vendor_id = extensions.get(_VENDOR_ID)
    if vendor_id is not None and (identity := _from_vendor_id(vendor_id)) is not None:
        return identity

    names = frozenset(extensions)
    if names & _OPENSSH_MARKERS:
        return PROFILES["openssh"]
    if names & _PARAMIKO_MARKERS:
        return PROFILES["paramiko"]
    return UNKNOWN


def _from_vendor_id(vendor_id: bytes) -> ServerProfile | None:
    """Turn a ``vendor-id`` body into a profile, or ``None`` if it says nothing usable."""
    parsed = parse_vendor_id(vendor_id)
    if parsed is None:
        return None
    _vendor, product, version, _build = parsed
    if not product:
        return None

    known = _VENDOR_PRODUCT_TO_PROFILE.get(product.lower())
    if known is not None:
        return replace(PROFILES[known], version=version or None)
    # A server we have no profile for, that told us who it is. Better than UNKNOWN by
    # exactly the amount it said: the name and version are reported, and nothing is assumed
    # about its behaviour.
    return ServerProfile(
        name=product.lower(),
        description=f"{product}, self-reported and not in this library's profile table",
        version=version or None,
        informative_messages=False,
    )

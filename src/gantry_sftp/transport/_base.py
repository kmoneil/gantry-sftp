"""What the session layer needs from a byte pipe.

Deliberately three methods. A transport moves bytes and reports when it cannot; everything
about SFTP lives above it. That is what lets the same session code run over an ``ssh``
subprocess, a local ``sftp-server``, an in-process fake, or -- later -- a native SSH client,
without any of them knowing about the others.

On copies
---------
:meth:`Transport.receive` returns ``bytes`` rather than filling a caller-supplied buffer.
DESIGN.md originally specified ``read_into(buf) -> int``, on the theory that filling a
preallocated buffer avoids an allocation. Under anyio it does the opposite: the backend
allocates a ``bytes`` object on its way out of the kernel regardless, so ``read_into``
would copy *that* into the caller's buffer and then the frame splitter would copy again --
three copies where there should be one.

So the honest arrangement is: one copy from the transport into the splitter's buffer, and
none after it. Frame payloads reach the caller as views into that buffer and are never
copied again, which is the property that actually matters for a quarter-megabyte READ. The
remaining copy is the one ``os.splice`` removes in phase 3, by keeping payload bytes out of
Python's address space entirely -- and that is a fast path around this interface, not a
change to it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["DEFAULT_RECEIVE_SIZE", "Transport"]

DEFAULT_RECEIVE_SIZE = 65536
"""How much to ask for per read. Not a protocol limit -- just a pipe-sized bite."""


@runtime_checkable
class Transport(Protocol):
    """A bidirectional byte stream carrying a framed SFTP conversation."""

    async def send(self, data: bytes | memoryview) -> None:
        """Write ``data``, in full.

        Raises:
            ConnectError: If the peer is gone. For a subprocess transport the error carries
                the child's stderr, which is usually the actual explanation.
        """
        ...

    async def receive(self, max_bytes: int = DEFAULT_RECEIVE_SIZE) -> bytes:
        """Read up to ``max_bytes``, blocking until at least one byte is available.

        Returns:
            A non-empty chunk. Short reads are normal and mean nothing.

        Raises:
            ConnectError: On end of stream. An SFTP session ends because the client closes
                it, so the peer closing first is a failure, not a tidy finish -- and it is
                exactly the moment when the child's stderr explains why.
        """
        ...

    async def aclose(self) -> None:
        """Shut down and release everything, including any child process.

        Idempotent, and safe to call while being cancelled -- cleanup that only runs on the
        happy path is how processes get orphaned.
        """
        ...

"""Closing a handle when something has already gone wrong.

One function, and it has a module to itself because of where it is called from rather than
because of its size (D-146). Four callers now hold a handle they must give back on a failure
path -- `Session`, `DirectoryScan`, and the two rungs of the verification ladder in
`_verify` -- and the ladder moved out of `_session.py` in the same change, so a copy in each
place would be the second implementation of a cleanup path that the first version of this
function already existed to prevent.

**Why not either neighbour.** `_core.py` is the bottom layer and may not reach an operation;
this calls `close`, which is one. `_operations.py` defines that operation and would be the
obvious home, except that it imports `_verify` for the check-file block size, so `_verify`
importing it back is a cycle. A module that imports neither at runtime is what breaks it, and
the session type is needed for the annotation alone.
"""

from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

import anyio

if TYPE_CHECKING:
    from gantry_sftp.session._operations import _SessionOperations

__all__ = ["close_quietly"]


async def close_quietly(session: _SessionOperations, handle: bytes) -> None:
    """Close a handle during failure handling, shielded and without raising.

    ``Exception`` rather than a precise tuple on purpose. This runs while another error is
    already on its way up, and *anything* raised here replaces the diagnosis with a
    housekeeping complaint. Cancellation is not caught -- it derives from ``BaseException``
    -- and cannot arrive anyway inside the shield.

    The shield is half of what makes this work and the reader outliving the same cancellation
    is the other half: this sends a ``CLOSE`` and waits for its ``STATUS``, so with the reader
    gone it waits out ``request_timeout`` and, with no timeout set, forever. See
    :meth:`~gantry_sftp.session.Dispatcher.run`.

    Args:
        session: Anything that can close a handle, which is the operations layer and up.
        handle: The handle to close. An unknown one answers ``NO_SUCH_FILE`` rather than the
            catch-all, and is suppressed here like any other refusal.
    """
    with anyio.CancelScope(shield=True), suppress(Exception):
        await session.close(handle)

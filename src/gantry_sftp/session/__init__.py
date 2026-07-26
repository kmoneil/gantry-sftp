"""Session: the scheduler and correctness layer between the codec and the user.

The codec knows the protocol and the transport moves bytes; neither of them knows how to
transfer a file quickly or correctly. That is this layer: how many requests to keep in
flight, how large each one may be, what to do when a read comes back short, and what is safe
to retry.

Async here means **anyio**, never bare ``asyncio``.
"""

from __future__ import annotations

from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    ProgressCallback,
    download_handle,
)
from gantry_sftp.session._limits import (
    DEFAULT_MAX_PACKET_LENGTH,
    PREFERRED_READ_LENGTH,
    PREFERRED_WRITE_LENGTH,
    ServerLimits,
    TransferSizes,
    negotiate_transfer_sizes,
    read_request_overhead,
    write_request_overhead,
)
from gantry_sftp.session._publish import (
    MAX_STAGED_NAME_LENGTH,
    Durability,
    PublishMechanism,
    UploadResult,
    split_parent,
    staged_path,
    staging_token,
)
from gantry_sftp.session._session import (
    DEFAULT_REQUEST_TIMEOUT,
    LIMITS_EXTENSION,
    Session,
    open_session,
    raise_for_status,
)
from gantry_sftp.session._upload import upload_handle

__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_PACKET_LENGTH",
    "DEFAULT_PIPELINE_DEPTH",
    "DEFAULT_REQUEST_TIMEOUT",
    "LIMITS_EXTENSION",
    "MAX_STAGED_NAME_LENGTH",
    "PREFERRED_READ_LENGTH",
    "PREFERRED_WRITE_LENGTH",
    "Durability",
    "ProgressCallback",
    "PublishMechanism",
    "ServerLimits",
    "Session",
    "TransferSizes",
    "UploadResult",
    "download_handle",
    "negotiate_transfer_sizes",
    "open_session",
    "raise_for_status",
    "read_request_overhead",
    "split_parent",
    "staged_path",
    "staging_token",
    "upload_handle",
    "write_request_overhead",
]

"""Session: the scheduler and correctness layer between the codec and the user.

The codec knows the protocol and the transport moves bytes; neither of them knows how to
transfer a file quickly or correctly. That is this layer: how many requests to keep in
flight, how large each one may be, what to do when a read comes back short, and what is safe
to retry.

Async here means **anyio**, never bare ``asyncio``.
"""

from __future__ import annotations

from gantry_sftp.session._dispatch import Dispatcher, Exchange
from gantry_sftp.session._download import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PIPELINE_DEPTH,
    DownloadResult,
    ProgressCallback,
    download_handle,
    read_range_into,
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
from gantry_sftp.session._listing import (
    DOT_ENTRIES,
    DirEntry,
    EntryKind,
    accessed_at,
    decode_name,
    entry_kind,
    modified_at,
)
from gantry_sftp.session._localpath import (
    WINDOWS_FORBIDDEN_CHARACTERS,
    WINDOWS_RESERVED_NAMES,
    DestinationLedger,
    check_component,
    check_contained,
    identity,
    local_child,
    unsafe_reason,
)
from gantry_sftp.session._localtree import (
    LocalWalkEntry,
    local_dir_entry,
    remote_component,
    walk_local,
)
from gantry_sftp.session._mode import (
    CREATE_BITS,
    PERMISSION_BITS,
    Mode,
    local_mode,
    resolve_mode,
)
from gantry_sftp.session._publish import (
    DEFAULT_PUBLISH,
    MAX_STAGED_NAME_LENGTH,
    Durability,
    Publish,
    PublishMechanism,
    SizeCheck,
    TimePreservation,
    UploadResult,
    split_parent,
    staged_path,
    staging_token,
)
from gantry_sftp.session._quirks import (
    PROFILES,
    UNKNOWN,
    ServerProfile,
    identify,
    parse_vendor_id,
)
from gantry_sftp.session._recursive import (
    GlobMatch,
    Skipped,
    SkipReason,
    TreeResult,
    WalkEntry,
    check_listed_name,
    join_remote,
    remote_component_reason,
)
from gantry_sftp.session._retry import (
    DEFAULT_ATTEMPTS,
    DEFAULT_BACKOFF,
    DEFAULT_BACKOFF_MAX,
    RETRYABLE_STATUS_CODES,
    is_retryable,
    with_reconnect,
)
from gantry_sftp.session._session import (
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_SESSION_OPTIONS,
    LIMITS_EXTENSION,
    DirectoryScan,
    RemoteFile,
    Session,
    SessionOptions,
    open_session,
    raise_for_status,
)
from gantry_sftp.session._upload import upload_handle, write_range_from
from gantry_sftp.session._verify import (
    CHECK_FILE_BLOCK_SIZE,
    ContentCheck,
    ResumeCheck,
    Verify,
)

__all__ = [
    "CHECK_FILE_BLOCK_SIZE",
    "CREATE_BITS",
    "DEFAULT_ATTEMPTS",
    "DEFAULT_BACKOFF",
    "DEFAULT_BACKOFF_MAX",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_PACKET_LENGTH",
    "DEFAULT_PIPELINE_DEPTH",
    "DEFAULT_PUBLISH",
    "DEFAULT_REQUEST_TIMEOUT",
    "DEFAULT_SESSION_OPTIONS",
    "DOT_ENTRIES",
    "LIMITS_EXTENSION",
    "MAX_STAGED_NAME_LENGTH",
    "PERMISSION_BITS",
    "PREFERRED_READ_LENGTH",
    "PREFERRED_WRITE_LENGTH",
    "PROFILES",
    "RETRYABLE_STATUS_CODES",
    "UNKNOWN",
    "WINDOWS_FORBIDDEN_CHARACTERS",
    "WINDOWS_RESERVED_NAMES",
    "ContentCheck",
    "DestinationLedger",
    "DirEntry",
    "DirectoryScan",
    "Dispatcher",
    "DownloadResult",
    "Durability",
    "EntryKind",
    "Exchange",
    "GlobMatch",
    "LocalWalkEntry",
    "Mode",
    "ProgressCallback",
    "Publish",
    "PublishMechanism",
    "RemoteFile",
    "ResumeCheck",
    "ServerLimits",
    "ServerProfile",
    "Session",
    "SessionOptions",
    "SizeCheck",
    "SkipReason",
    "Skipped",
    "TimePreservation",
    "TransferSizes",
    "TreeResult",
    "UploadResult",
    "Verify",
    "WalkEntry",
    "accessed_at",
    "check_component",
    "check_contained",
    "check_listed_name",
    "decode_name",
    "download_handle",
    "entry_kind",
    "identify",
    "identity",
    "is_retryable",
    "join_remote",
    "local_child",
    "local_dir_entry",
    "local_mode",
    "modified_at",
    "negotiate_transfer_sizes",
    "open_session",
    "parse_vendor_id",
    "raise_for_status",
    "read_range_into",
    "read_request_overhead",
    "remote_component",
    "remote_component_reason",
    "resolve_mode",
    "split_parent",
    "staged_path",
    "staging_token",
    "unsafe_reason",
    "upload_handle",
    "walk_local",
    "with_reconnect",
    "write_range_from",
    "write_request_overhead",
]

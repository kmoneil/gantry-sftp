"""One request, one answer: the protocol operations.

The middle of the three layers `Session` is built from, split out under D-143. Most of what is
here is one round trip -- `STAT`, `OPEN`, `MKDIR`, `RENAME` -- plus the path resolution they
share. Nothing here composes another *operation* into a sequence; that is the layer above, and
`tests/test_layer_discipline.py` asserts the direction.

**The byte movers are the exception and were from the start**, which D-146 made worth stating:
`readinto_at`, `write_at`, `download_into` and `upload_from` each drive the transfer scheduler
over *one handle somebody else opened*, which is many round trips and still no composition --
they open nothing, close nothing, and decide nothing about where a file may live. The line the
layer is really drawn on is that one: a method here needs a handle or a path and produces an
answer, and never sequences two operations to get one.

The split is by **what the code needs**, computed rather than eyeballed: the closure of these
methods over `self.<method>` calls is disjoint from the compositions', and the call graph across
all three layers is a DAG with no back-edges.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from pathlib import Path

from gantry_sftp.codec import (
    EMPTY_ATTRS,
    EXTENSION_CHECK_FILE,
    EXTENSION_FSYNC,
    EXTENSION_LSETSTAT,
    EXTENSION_POSIX_RENAME,
    Attrs,
    AttrsReply,
    CheckFile,
    CheckFileReply,
    Close,
    FSetStat,
    FStat,
    Fsync,
    Handle,
    LSetStat,
    LStat,
    MkDir,
    Name,
    Open,
    OpenDir,
    OpenFlag,
    Owner,
    PosixRename,
    ReadDir,
    ReadLink,
    RealPath,
    Remove,
    Rename,
    Request,
    RmDir,
    SetStat,
    Stat,
    Status,
    StatusCode,
    SymLink,
    Times,
)
from gantry_sftp.codec import (
    ExtendedReply as ExtendedReplyPacket,
)
from gantry_sftp.exceptions import (
    CapabilityError,
    ProtocolError,
    ServerError,
    UnsupportedError,
)
from gantry_sftp.session._core import (
    _SessionCore,
    _unexpected,
    raise_for_status,
)
from gantry_sftp.session._download import (
    ProgressCallback,
    download_handle,
    read_range_into,
)
from gantry_sftp.session._listing import (
    DirEntry,
    EntryKind,
    entry_kind,
)
from gantry_sftp.session._mode import (
    PERMISSION_BITS,
)
from gantry_sftp.session._policy import (
    _encode_path,
)
from gantry_sftp.session._quirks import server_note
from gantry_sftp.session._recursive import (
    join_remote,
)
from gantry_sftp.session._upload import upload_handle, write_range_from
from gantry_sftp.session._verify import (
    CHECK_FILE_BLOCK_SIZE,
)


class _SessionOperations(_SessionCore):
    """The one-round-trip surface. See :class:`~gantry_sftp.session.Session`."""

    def _server_note(self) -> str:
        """One line naming the peer, for a capability refusal to carry.

        The sentence itself lives in :func:`~gantry_sftp.session._quirks.server_note`, because
        the upload orchestration raises capability refusals from outside this class and two
        copies of the format string is two things to update.
        """
        return server_note(self._profile, len(self._codec.extensions))

    def _next(self) -> int:
        return self._codec.allocate_request_id()

    async def _expect_status(self, request: Request, *, path: bytes | None = None) -> None:
        """Send a request whose only useful answer is a STATUS, and raise unless it said OK.

        Raises:
            ServerError: Or the subclass matching the code, for a non-OK STATUS.
            ProtocolError: If the server answered with something other than a STATUS. Both
                ``EXTENDED`` requests this library sends are specified to answer with one and
                a real ``sftp-server`` does; a reply of another shape is a server we cannot
                interpret rather than a refusal we can report.
        """
        reply = await self.request(request)
        if isinstance(reply, Status):
            raise_for_status(reply, path=path)
            return
        # No `path=` here, and its absence is the point: :func:`_unexpected` only reads it on
        # its ``Status`` branch, and this line is reached only when the reply is *not* one --
        # the branch above has already taken that case. Passing it looked like defence in
        # depth and was dead by construction (D-105 slice 25). The call in ``_realpath_raw``
        # does pass it, because a ``Status`` is one of the replies that is not a ``NAME``.
        raise _unexpected(reply, expected="STATUS")

    async def _attempt_extension(
        self, extension: str, attempt: Callable[[], Awaitable[object]]
    ) -> bool:
        """Send an extension request that has a fallback, and say whether it was performed.

        **The one place an ``OP_UNSUPPORTED`` is recorded**, so that "we already asked" is a
        property of the session rather than of whichever call site remembered to check. Before
        this, the cache had exactly one reader and one writer, both inside the posix-rename
        path, and ``fsync`` and ``check-file`` neither consulted nor populated it (D-51).

        ``False`` means the server did not do it, for one of three reasons, and the difference
        matters at the call site rather than here:

        * it already answered ``OP_UNSUPPORTED`` this session -- no round trip is made;
        * it answers ``OP_UNSUPPORTED`` now -- recorded, so the next call is free;
        * it refused for some other reason **while not advertising** the extension -- in which
          case we do not know what we just asked of it, so the fallback stands and nothing is
          cached, because that answer was not definitive.

        A refusal from a server that *did* advertise the extension propagates instead. It is
        telling us about this operation -- the path, the permissions -- and falling through to
        a fallback that will fail the same way only buries the explanation.

        Args:
            extension: Wire name of the extension being attempted.
            attempt: Sends the request. Called at most once.

        Returns:
            Whether the server performed it.

        Raises:
            ServerError: For a non-``OP_UNSUPPORTED`` refusal of an advertised extension.
        """
        if self.refuses(extension):
            return False
        advertised = self.supports(extension)
        try:
            _ = await attempt()
        except UnsupportedError:
            self._unsupported.add(extension.encode("ascii"))
            return False
        except ServerError:
            if advertised:
                raise
            return False
        return True

    async def stat(self, path: bytes | str) -> Attrs:
        """Attributes of ``path``, following symlinks.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        reply = await self.request(Stat(self._next(), encoded))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS", path=encoded)

    async def lstat(self, path: bytes | str) -> Attrs:
        """Attributes of ``path`` itself, **not** following symlinks.

        The difference is not academic where this is used: ``stat`` on a symlink whose target
        is gone reports ``NO_SUCH_FILE``, so it answers "is there a file at the end of this
        name" while ``lstat`` answers "is this name taken". Publishing needs the second
        question.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        reply = await self.request(LStat(self._next(), encoded))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS", path=encoded)

    def _resolve(self, path: bytes | str) -> bytes:
        """Encode a caller's path and apply the working directory, if there is one.

        **Every public path argument goes through here**, which is what makes ``chdir`` mean
        the same thing to ``stat`` and to ``glob`` without either of them knowing it exists.
        The alternative -- each method prepending for itself -- is a per-method decision
        nobody re-reads, and the one that got forgotten would silently operate on a different
        file from the one the caller named.

        **Idempotent by construction, which is the property the recursive operations need.**
        Only a *relative* path is prefixed, and :attr:`_cwd` is always absolute, so a resolved
        path resolves to itself. ``walk`` resolves its root once and then joins child names
        onto that absolute root; every child therefore passes through here again -- from the
        walk, and again from whatever the caller does with it -- and is unchanged both times.
        A prefix applied to whatever it was handed would double on exactly those paths, and
        the resulting name would still be legal, so nothing would have failed.
        """
        encoded = _encode_path(path)
        if self._cwd is None or encoded.startswith(b"/"):
            return encoded
        return join_remote(self._cwd, encoded)

    async def _set_one_attribute(
        self, path: bytes, attrs: Attrs, *, follow_symlinks: bool, operation: str
    ) -> None:
        """Apply one ATTRS field to a path, following the symlink or refusing to.

        **One field per call is the caller's job and this method's assumption.** OpenSSH's
        ``process_setstat`` and ``process_extended_lsetstat`` both walk the flags in sequence,
        applying each and recording only the last failure in the single ``STATUS`` they send
        back -- so a multi-field call that fails has already applied the fields before the
        failing one and does not say which. Every public caller here sends exactly one flag,
        which makes a refusal unambiguous and leaves nothing else moved.

        ``follow_symlinks=False`` needs ``lsetstat@openssh.com`` and **refuses without it**,
        rather than degrading to the following version. That is the opposite of what most
        extension use does here, and the reason is that there is nothing to degrade *to*: v3
        has no non-following spelling, so the fallback would be to perform a different
        operation than the one asked for, on a target the caller was trying to avoid.

        Attempted even where the server did not advertise the extension, since endpoints
        implement extensions they never list -- and an ``OP_UNSUPPORTED`` is cached, so a
        second call in the same session costs no round trip.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        if follow_symlinks:
            await self._expect_status(SetStat(self._next(), path, attrs), path=path)
            return
        try:
            performed = await self._attempt_extension(
                EXTENSION_LSETSTAT,
                lambda: self._expect_status(
                    LSetStat(self._next(), path, attrs).to_extended(), path=path
                ),
            )
        except ServerError as refusal:
            # OpenSSH's FAILURE carries no message worth reading -- five distinct conditions
            # all render as "Failure" -- and for this one flag there is a specific, common and
            # unfixable cause that the bare status sends a reader looking in the wrong place.
            if attrs.permissions is not None:
                refusal.add_note(
                    "the server may be refusing because it cannot do this at all: Linux has "
                    "no lchmod, so fchmodat(AT_SYMLINK_NOFOLLOW) answers ENOTSUP and OpenSSH "
                    "maps that to a contentless FAILURE. A symlink's own permission bits are "
                    "ignored by the Linux kernel and are always 0o777, so there is nothing to "
                    "set. The times and owner of a symlink can be set there; the mode cannot. "
                    "Pass follow_symlinks=True to change what the link points at, if that is "
                    "what you meant."
                )
            raise
        if not performed:
            unavailable = CapabilityError(
                f"follow_symlinks=False needs {EXTENSION_LSETSTAT}, which this server will "
                f"not perform, and filexfer v3 has no other way to {operation} a symlink "
                f"without following it. Passing follow_symlinks=True would {operation} "
                f"whatever {path!r} points at, which is a different operation",
                feature=f"{operation} without following a symlink",
                missing=(EXTENSION_LSETSTAT,),
                path=path,
            )
            unavailable.add_note(self._server_note())
            raise unavailable

    async def chmod(self, path: bytes | str, mode: int, *, follow_symlinks: bool = True) -> None:
        """Set the permission bits of ``path``.

        ``SETSTAT`` carrying **only** ``PERMISSIONS``, and the single flag is the decision
        rather than an economy. OpenSSH's ``process_setstat`` walks the ATTRS flags in order --
        ``SIZE`` to ``truncate``, ``PERMISSIONS`` to ``chmod``, ``ACMODTIME`` to ``utimes``,
        ``UIDGID`` to ``chown`` -- applying each in turn and recording only the *last* failure
        in the single ``STATUS`` it sends back. So a multi-field ``SETSTAT`` that fails has
        already applied the fields before the failing one, and the answer does not say which
        field it was. One field per call makes a refusal unambiguous and leaves nothing else
        moved.

        **It follows symlinks by default**, because ``SETSTAT`` is ``chmod(2)`` and that is what
        ``chmod(2)`` does -- the same default as :func:`os.chmod`. Where the path may be a
        symlink planted by someone else, that is a chmod of whatever it points at.
        ``follow_symlinks=False`` uses ``lsetstat@openssh.com`` and **refuses** where the server
        will not, rather than silently doing the following version: v3 has no other spelling, so
        there is nothing to degrade to.

        **On a Linux server that refusal is unconditional, and the extension being present does
        not change it.** Linux has no ``lchmod``: ``fchmodat(AT_SYMLINK_NOFOLLOW)`` answers
        ``ENOTSUP``, measured, so ``lsetstat``'s permissions branch cannot succeed there however
        the server is configured. A symlink's own mode is meaningless to that kernel and always
        reads ``0o777``. The refusal arrives as OpenSSH's contentless ``FAILURE`` and this
        library attaches a note saying so. :meth:`utime` and :meth:`chown` *do* work on a link
        there -- ``utimensat`` and ``fchownat`` accept the flag -- so this limit is the mode's
        alone, not the extension's.

        Args:
            path: What to modify.
            mode: Permission bits. Masked to ``0o7777``, which is what ``chmod(2)`` takes and
                what OpenSSH applies (``a.perm & 07777``); the file-type bits an ``st_mode``
                carries are not permissions and are dropped rather than sent.
            follow_symlinks: Whether to act on the link's target. ``False`` needs
                ``lsetstat@openssh.com`` -- advertised by OpenSSH and asyncssh, absent from
                paramiko -- **and** a server platform with ``lchmod``, which Linux is not.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        await self._set_one_attribute(
            encoded,
            Attrs(permissions=mode & PERMISSION_BITS),
            follow_symlinks=follow_symlinks,
            operation="chmod",
        )

    async def chown(
        self, path: bytes | str, uid: int, gid: int, *, follow_symlinks: bool = True
    ) -> None:
        """Set the numeric owner and group of ``path``.

        **Both together or neither**, because ``UIDGID`` is one flag covering two fields --
        there is no way to send a uid without a gid, so "leave the group alone" has to be
        spelled by reading the current gid back with :meth:`stat` and sending it unchanged.
        That is the wire's shape rather than ours; :class:`~gantry_sftp.codec.Owner` exists to
        make the pairing visible instead of leaving two loose integers.

        **Numeric ids only.** Turning them into names needs
        ``users-groups-by-id@openssh.com``, which is not implemented here, and the display
        string in ``longname`` is not a source -- it is rendered by the server, in the server's
        name resolution, for a human.

        Args:
            path: What to modify.
            uid: Numeric user id.
            gid: Numeric group id.
            follow_symlinks: Whether to act on the link's target. ``False`` needs
                ``lsetstat@openssh.com``.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it -- which is the common
                answer, since changing a file's owner is root's privilege on every ordinary
                Unix server.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        await self._set_one_attribute(
            encoded,
            Attrs(owner=Owner(uid=uid, gid=gid)),
            follow_symlinks=follow_symlinks,
            operation="chown",
        )

    async def utime(
        self, path: bytes | str, atime: int, mtime: int, *, follow_symlinks: bool = True
    ) -> None:
        """Set the access and modification times of ``path``, in whole seconds.

        **Both together or neither**, for the same reason :meth:`chown` pairs its two: they
        share one ``ACMODTIME`` flag.

        v3 carries ``uint32`` seconds, so sub-second precision does not exist here and a value
        that does not fit is refused rather than truncated -- see
        :data:`~gantry_sftp.codec.MAX_V3_TIMESTAMP`. Whether the *transfer* methods carry times
        across is ``preserve_times=``; this is the standalone call, for a file already there.

        Args:
            path: What to modify.
            atime: Access time, seconds since the epoch.
            mtime: Modification time, seconds since the epoch.
            follow_symlinks: Whether to act on the link's target. ``False`` needs
                ``lsetstat@openssh.com``.

        Raises:
            CapabilityError: If ``follow_symlinks=False`` and the server will not do it.
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
            ValueError: If either value does not fit filexfer v3's ``uint32`` seconds.
        """
        encoded = self._resolve(path)
        await self._set_one_attribute(
            encoded,
            Attrs(times=Times(atime=atime, mtime=mtime)),
            follow_symlinks=follow_symlinks,
            operation="utime",
        )

    async def truncate(self, path: bytes | str, size: int) -> None:
        """Set the length of ``path``, discarding anything past it or zero-filling to reach it.

        ``SETSTAT`` carrying only ``SIZE``, which OpenSSH answers with ``truncate(2)``.

        **There is no ``follow_symlinks=False`` here, and its absence is the server's decision
        rather than an omission.** ``process_extended_lsetstat`` rejects ``SIZE`` outright --
        ``BAD_MESSAGE``, with the comment ``/* nonsensical for links */`` -- so the extension
        every other method on this page uses for the non-following case cannot carry a
        truncation at all. A parameter that could only ever fail would be worse than not having
        one.

        Args:
            path: What to modify. Followed if it is a symlink, necessarily.
            size: The new length in bytes. Growing a file this way makes a hole rather than
                writing zeroes, so the space is not reserved and a later write can still fail
                with ``ENOSPC``.

        Raises:
            NoSuchFileError: If the path does not exist.
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        await self._expect_status(SetStat(self._next(), encoded, Attrs(size=size)), path=encoded)

    async def ftruncate(self, handle: bytes, size: int) -> None:
        """Set the length of an **open file**, by handle rather than by path.

        The handle-addressed :meth:`truncate`, and the difference is the same one :meth:`fstat`
        exists for: a path can be replaced between the ``OPEN`` and the ``SETSTAT``, so a
        writer that truncates by name can truncate a file it is not the one holding open. It
        is also the only form available to a caller who has a handle and no usable path --
        which is every caller of :meth:`open_file`.

        ``FSETSTAT`` carrying only ``SIZE``. Growing a file this way makes a hole rather than
        writing zeroes, so the space is not reserved and a later write can still fail with
        ``ENOSPC``.

        Args:
            handle: An open file handle, opened for writing.
            size: The new length in bytes.

        Raises:
            ValueError: If ``size`` is negative.
            ServerError: If the server refuses. A read-only handle answers ``NO_SUCH_FILE``
                here, the same misdirection a write on one gives.
        """
        if size < 0:
            raise ValueError(f"size must not be negative, got {size}")
        await self._expect_status(FSetStat(self._next(), handle, Attrs(size=size)))

    async def fchmod(self, handle: bytes, mode: int, *, path: bytes | None = None) -> None:
        """Set the permission bits of an **open handle**. The `f` twin of :meth:`chmod`.

        ``FSETSTAT`` carrying only ``PERMISSIONS``, one flag per call for the reason
        :meth:`chmod` gives: OpenSSH's ``process_fsetstat`` walks the flags in sequence and
        reports one ``STATUS``, so a multi-field call that fails has already applied part of
        itself and does not say which part.

        **By handle rather than by path is a correctness property, not an economy** (D-146).
        A caller holding an open file who chmods it by *name* is chmodding whatever that name
        refers to now, which is not necessarily the file they hold — and on a staging-and-rename
        publish the name is about to change, so there is a moment when no correct name exists.
        That is why the upload path sets a mode this way, and why a caller doing their own
        publishing needs the same spelling rather than a close-then-chmod they cannot make safe.

        Args:
            handle: An open file handle.
            mode: Permission bits. Masked to ``0o7777``, as :meth:`chmod` does.
            path: Carried on the error for diagnosis. A handle is meaningless in a message, and
                on a staging path the destination name would be the *wrong* thing to print --
                nothing was ever published under it.

        Raises:
            PermissionDeniedError: If the server will not change it.
            ServerError: For any other refusal.
        """
        await self._expect_status(
            FSetStat(self._next(), handle, Attrs(permissions=mode & PERMISSION_BITS)), path=path
        )

    async def futime(
        self, handle: bytes, atime: int, mtime: int, *, path: bytes | None = None
    ) -> None:
        """Set the times of an **open handle**, in whole seconds. The `f` twin of :meth:`utime`.

        Both together or neither, because they share one ``ACMODTIME`` flag, and v3 carries
        ``uint32`` seconds so a value that does not fit is refused rather than truncated -- see
        :data:`~gantry_sftp.codec.MAX_V3_TIMESTAMP`.

        **The times cannot ride along on the ``OPEN`` that created the handle**, which is the
        reason this is reached for at all: OpenSSH's ``process_open`` reads only ``PERMISSIONS``
        out of that request's ATTRS, to pass as ``open(2)``'s mode, and ignores ``ACMODTIME``
        entirely -- read in ``sftp-server.c`` rather than assumed from the draft, which
        describes the field as settable there.

        Args:
            handle: An open file handle.
            atime: Access time, seconds since the epoch.
            mtime: Modification time, seconds since the epoch.
            path: Carried on the error for diagnosis. See :meth:`fchmod`.

        Raises:
            PermissionDeniedError: If the server will not change them.
            ServerError: For any other refusal.
            ValueError: If either value does not fit filexfer v3's ``uint32`` seconds.
        """
        await self._expect_status(
            FSetStat(self._next(), handle, Attrs(times=Times(atime=atime, mtime=mtime))),
            path=path,
        )

    async def fsync_if_supported(self, handle: bytes) -> bool:
        """Flush an open handle to stable storage, and say whether the server did it.

        The degrading spelling of :meth:`fsync`, which raises instead. ``fsync@openssh.com`` is
        optional in the field and absent from most of the endpoints DESIGN.md 7 lists, so a
        caller who wants durability *where it is available* would otherwise write the
        catch-and-remember themselves — and the remembering is the part worth sharing: an
        ``OP_UNSUPPORTED`` is cached for the session, so the second call costs no round trip.

        **Attempted whether or not the server advertised it** (D-51). Advertisement is a claim
        and an answer is a fact, and the endpoints most likely to under-advertise are exactly
        the ones where this is worth having.

        Returns:
            ``True`` if the server performed it. ``False`` if it will not — which is not an
            error and is the common answer.

        Raises:
            ServerError: If a server that *advertised* the extension refuses for some reason
                other than ``OP_UNSUPPORTED``. That refusal is about this handle rather than
                about the server, so it propagates instead of degrading.
        """
        return await self._attempt_extension(EXTENSION_FSYNC, lambda: self.fsync(handle))

    async def posix_rename_if_supported(self, old_path: bytes | str, new_path: bytes | str) -> bool:
        """Rename, replacing the destination atomically, and say whether the server did it.

        The degrading spelling of :meth:`posix_rename`, and the one an atomic publish is built
        on: v3's own ``RENAME`` is specified to *fail* when the destination exists, so replacing
        a file needs either this extension or a remove-then-rename with a window in it.

        Attempted whether or not it was advertised, and an ``OP_UNSUPPORTED`` is cached, so a
        tree of a thousand files asks once.

        Returns:
            ``True`` if the server performed the atomic rename. ``False`` if it will not, which
            is when a caller has to decide what its fallback is -- and there is no safe one that
            does not briefly leave the destination missing.

        Raises:
            ServerError: If a server that advertised the extension refuses for some reason other
                than ``OP_UNSUPPORTED`` -- a permission, a missing parent, a cross-device move.
        """
        return await self._attempt_extension(
            EXTENSION_POSIX_RENAME, lambda: self.posix_rename(old_path, new_path)
        )

    async def fstat(self, handle: bytes) -> Attrs:
        """Attributes of an open handle.

        The handle-addressed :meth:`stat`, and the difference is worth the method: a path can
        be replaced between the ``OPEN`` and the ``STAT``, so asking the handle is asking about
        the file this session actually has open rather than about whatever currently answers to
        that name.

        Raises:
            ServerError: If the server refuses -- which includes a handle it does not know, and
                a server that does not implement ``FSTAT`` on a directory handle.
        """
        reply = await self.request(FStat(self._next(), handle))
        if isinstance(reply, AttrsReply):
            return reply.attrs
        raise _unexpected(reply, expected="ATTRS")

    async def readlink(self, path: bytes | str) -> bytes:
        """Read the target of a symlink, without following it.

        **The answer is attacker-controlled and is returned raw.** A link target is an
        arbitrary byte string chosen by whoever created the link -- it may be absolute, may
        climb with ``..``, may not be valid UTF-8, and may name something that does not exist.
        Nothing is validated here because there is nothing to validate against: every one of
        those is a legal symlink. **Do not join it onto a local path** without the containment
        check :meth:`get_tree` uses; that is the zip-slip class, and this method is the
        shortest route to it.

        **A path that is not a symlink answers ``BAD_MESSAGE``**, not ``FAILURE`` and not
        ``NO_SUCH_FILE``. That code reads as "the frame you sent was malformed" and here means
        ``EINVAL`` -- OpenSSH maps ``EINVAL`` and ``ENAMETOOLONG`` onto it, so the status that
        looks like a bug in this library is how ``readlink`` says "that is not a link".
        Measured, and in DESIGN 13.

        Returns:
            The link target exactly as the server sent it.

        Raises:
            ProtocolError: If the server answers with something other than a NAME, or with a
                NAME carrying any number of names other than one. Same strictness as
                :meth:`realpath` and for the same reason: ``send_names`` sends exactly one, so
                a different count is a server we do not understand rather than a choice to make.
            NoSuchFileError: If the path does not exist.
            ServerError: If the path is not a symlink (``BAD_MESSAGE``), or for any other
                refusal.
        """
        encoded = self._resolve(path)
        reply = await self.request(ReadLink(self._next(), encoded))
        if not isinstance(reply, Name):
            raise _unexpected(reply, expected="NAME", path=encoded)
        if len(reply.entries) != 1:
            raise ProtocolError(
                f"READLINK of {encoded!r} answered with {len(reply.entries)} names, "
                f"and a link has exactly one target",
                request_id=reply.request_id,
            )
        return reply.entries[0].filename

    async def symlink(self, target: bytes | str, link_path: bytes | str) -> None:
        """Create a symlink at ``link_path`` pointing at ``target``.

        Argument order matches :func:`os.symlink` -- target first, then the name being created
        -- which is **not** the order these fields take on the wire. OpenSSH sends
        ``targetpath`` then ``linkpath`` where ``draft-ietf-secsh-filexfer-02`` specifies the
        reverse, and the reference implementation is what binds: sending the draft order
        against a real ``sftp-server`` returns ``FAILURE`` and creates nothing. That reversal
        lives in :class:`~gantry_sftp.codec.SymLink`'s encoder, checked against a server, and
        not here.

        ``target`` is not resolved, checked, or required to exist. A dangling symlink is a
        legal thing to create and some deployments create one deliberately.

        **That includes not resolving it against :meth:`chdir`'s working directory**, which is
        the one place this library's prefix must not reach: ``target`` is a *string stored
        inside the link*, interpreted by the server relative to the link's own directory, not
        a path this client is about to operate on. Prefixing it would silently turn
        ``symlink(b"data.csv", b"alias.csv")`` -- a relative link, which is what a shell makes
        and what survives the directory being moved -- into an absolute one pointing at
        wherever the session happened to be standing. Caught by the sweep that routed every
        other path through the resolver: this docstring already said the rule, and the sweep
        made it false.

        Args:
            target: What the link should point at.
            link_path: The name to create.

        Raises:
            PermissionDeniedError: If the server will not create it.
            ServerError: For any other refusal, including a name that is already taken.
        """
        encoded = self._resolve(link_path)
        await self._expect_status(
            SymLink(self._next(), targetpath=_encode_path(target), linkpath=encoded),
            path=encoded,
        )

    async def realpath(self, path: bytes | str = b".") -> bytes:
        """Canonicalise ``path`` on the server.

        Servers disagree about what this does for a path that does not exist -- some
        canonicalise anyway, some refuse. That disagreement belongs to the quirks layer and
        is not smoothed over here.

        **Exactly one name, and a count that is not one is an error rather than a guess.**
        Unlike READDIR -- where the draft and OpenSSH's client disagree about strictness and
        the client wins (see :meth:`readdir`) -- here they agree: the draft specifies a single
        name, and ``sftp-client.c`` does ``if (count != 1) fatal("Got multiple names (%d)")``.
        Where both are strict there is nothing for us to be lenient *towards*. Taking the
        first of several would be picking one of the server's answers and calling it the
        canonical path, which is the silently-wrong failure this layer exists to prevent.

        **A relative argument resolves against :meth:`getcwd`**, like every other path this
        session takes, so ``realpath(b".")`` after a :meth:`chdir` canonicalises the directory
        you moved to rather than the one the server started you in. :attr:`server_root` is the
        other question and keeps its own answer.

        Raises:
            ProtocolError: If the server answers with something other than a NAME, or with a
                NAME carrying any number of names other than one.
            NoSuchFileError: If the server refuses because the path does not exist.
            ServerError: For any other refusal.
        """
        return await self._realpath_raw(self._resolve(path))

    async def _realpath_raw(self, encoded: bytes) -> bytes:
        """``REALPATH`` of an already-resolved path, with no working directory applied.

        The split exists for one caller and it is load-bearing: the rootedness probe below
        asks *the server* where its default directory is, and running that through the
        client-side prefix would answer with wherever :meth:`chdir` last went. It would then
        cache that as :attr:`server_root`, which is a different question with a public name.
        """
        reply = await self.request(RealPath(self._next(), encoded))
        if not isinstance(reply, Name):
            raise _unexpected(reply, expected="NAME", path=encoded)
        if len(reply.entries) != 1:
            raise ProtocolError(
                f"REALPATH of {encoded!r} answered with {len(reply.entries)} names, "
                f"and exactly one is the only useful answer",
                request_id=reply.request_id,
            )
        return reply.entries[0].filename

    async def open(
        self, path: bytes | str, pflags: OpenFlag = OpenFlag.READ, *, mode: int | None = None
    ) -> bytes:
        """Open a remote file and return its handle.

        Args:
            path: What to open.
            pflags: Access and creation flags.
            mode: Permission bits for a file this call **creates**, or ``None`` to leave it to
                the server. Ignored by the server when the file already exists, exactly as
                ``open(2)``'s mode argument is, so this is not a way to change an existing
                file's permissions -- :meth:`chmod` is.

                ``None`` is not neutral and it is worth knowing what it means: OpenSSH's
                ``process_open`` reads this ATTRS for ``PERMISSIONS`` and nothing else,
                defaulting to ``0666`` when the flag is absent, so a file created without it
                arrives ``0666 & ~umask`` -- world-readable under the usual umask.

        Raises:
            NoSuchFileError: If the path does not exist and was not to be created.
            PermissionDeniedError: If the server will not open it.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(path)
        attrs = EMPTY_ATTRS if mode is None else Attrs(permissions=mode)
        reply = await self.request(Open(self._next(), encoded, pflags, attrs))
        if isinstance(reply, Handle):
            return reply.handle
        raise _unexpected(reply, expected="HANDLE", path=encoded)

    async def readinto_at(self, handle: bytes, buffer: bytearray | memoryview, offset: int) -> int:
        """Read ``len(buffer)`` bytes from ``offset`` into ``buffer``. The zero-copy primitive.

        Pipelined: a range longer than one request becomes several in flight, exactly as a
        ``get`` does, because a byte-range read that issues one ``READ`` and awaits it costs a
        round trip per call. That is not a hypothetical -- it is the documented behaviour of
        the incumbent's file object, which runs 25x slower than its own whole-file download
        (``paramiko#2453``).

        **Safe to call from several tasks at once**, on the same handle or on different ones:
        the offset is an argument rather than a cursor, so there is no shared position for two
        tasks to interleave. :meth:`open_file` is the cursor-bearing form and is not.

        Args:
            handle: An open remote file handle, opened for reading.
            buffer: Writable destination, filled from its first byte. Its length is the range.
            offset: Absolute offset in the remote file.

        Returns:
            Bytes read. Short of ``len(buffer)`` **only at end of file** -- a short ``DATA`` is
            legal mid-file and is re-requested rather than returned, so a caller never has to
            loop to fill a range. ``0`` means the offset was at or past the end.

            The unfilled tail of ``buffer`` is left as it was rather than zeroed.

        Raises:
            ValueError: If ``offset`` is negative.
            TransferError: If the server refuses the read -- **not** the typed status error
                :meth:`open` would raise, because this is the transfer scheduler and a refusal
                here carries how far the range got. The status name is in the message.

                Two of those messages mislead and it is the server's doing rather than ours: a
                handle opened write-only answers ``NO_SUCH_FILE``, and so does a handle that
                has already been closed. OpenSSH's handle lookup checks the direction, so "No
                such file" is what a perfectly good path reports when the handle is the wrong
                kind.
            TransferTimeoutError: If the server stops responding.
        """
        view = memoryview(buffer) if isinstance(buffer, bytearray) else buffer
        return await read_range_into(
            self._dispatcher,
            handle,
            view,
            offset=offset,
            read_length=self.sizes_for(handle).read_length,
            depth=self._depth,
            idle_timeout=self._idle_timeout,
        )

    async def read_at(self, handle: bytes, offset: int, length: int) -> bytes:
        """Read up to ``length`` bytes from ``offset``, pipelined.

        The ergonomic form of :meth:`readinto_at`, and the one copy in it is the return type:
        handing back immutable ``bytes`` means copying out of the buffer that was filled.
        Reach for ``readinto_at`` when that matters.

        **A zero-length read is answered here rather than on the wire.** OpenSSH replies to a
        zero-length ``READ`` with an empty ``DATA``, which is also exactly how a server making
        no progress looks -- the transfer scheduler tolerates one and fails on the second, and
        it is right to. Rather than teach it an exception for a case whose answer is already
        known, this returns ``b""`` without asking.

        Args:
            handle: An open remote file handle, opened for reading.
            offset: Absolute offset in the remote file.
            length: Bytes to read. May exceed the server's ``max-read-length``; the range is
                split across requests, so there is no ceiling a caller has to know about.

        Returns:
            The bytes read: exactly ``length`` of them unless end of file arrived first, and
            ``b""`` at or past the end.

        Raises:
            ValueError: If ``offset`` or ``length`` is negative.
        """
        if length < 0:
            raise ValueError(f"length must not be negative, got {length}")
        if offset < 0:
            raise ValueError(f"offset must not be negative, got {offset}")
        if length == 0:
            return b""
        buffer = bytearray(length)
        filled = await self.readinto_at(handle, buffer, offset)
        del buffer[filled:]
        return bytes(buffer)

    async def write_at(self, handle: bytes, offset: int, data: bytes | memoryview) -> int:
        """Write ``data`` at ``offset``, pipelined.

        Longer than one request becomes several in flight, and the payload is not copied on
        the way to the wire.

        **Safe to call from several tasks at once on different ranges**; two tasks writing the
        same range is a race this cannot arbitrate, exactly as with two processes and
        ``pwrite``. Unlike a read, a write is **not idempotent** -- nothing here retries one,
        and a caller reissuing a failed write has to know what the server already stored.

        Writing past the end of the file is legal and leaves a hole, which reads back as
        zeroes. Verified against ``sftp-server`` rather than assumed.

        Args:
            handle: An open remote file handle, opened for writing.
            offset: Absolute offset in the remote file.
            data: The bytes to write. Empty writes no bytes and costs no round trip.

        Returns:
            Bytes the server acknowledged, which is ``len(data)`` on success.

        Raises:
            ValueError: If ``offset`` is negative.
            TransferError: If the server refuses the write, carrying how far it got. A handle
                opened read-only answers ``NO_SUCH_FILE`` inside that message, for the same
                reason a read on a write-only handle does.
        """
        if offset < 0:
            raise ValueError(f"offset must not be negative, got {offset}")
        payload = memoryview(data) if isinstance(data, bytes) else data
        if not len(payload):
            return 0
        return await write_range_from(
            self._dispatcher,
            handle,
            payload,
            offset=offset,
            write_length=self.sizes_for(handle).write_length,
            depth=self._depth,
            idle_timeout=self._idle_timeout,
        )

    async def download_into(
        self,
        handle: bytes,
        fd: int,
        *,
        size: int | None,
        depth: int | None = None,
        progress: ProgressCallback | None = None,
        remote_path: bytes | None = None,
        start_offset: int = 0,
    ) -> int:
        """Fill a local descriptor from an open remote handle, pipelined.

        The descriptor-shaped sibling of :meth:`readinto_at`, and the whole file rather than a
        range: a download that has to fit in memory is not a download of a nine-gigabyte file.
        Written at explicit offsets and never seeked, so the destination may be a file, a
        temporary one nobody named, or anything else ``pwrite`` accepts.

        **Why this is a method rather than three attributes a caller assembles** (D-146). The
        scheduler needs the dispatcher, this session's depth, its idle timeout and the request
        size for *this handle* -- and the last of those is only knowable once the handle exists,
        so no caller can build the schedule in advance. Handing those four out would put a
        session's wire state in every caller's hands to reassemble identically; asking the
        session to schedule keeps them where they are owned. That is what lets the verification
        ladder live outside :class:`~gantry_sftp.session.Session` in
        :mod:`gantry_sftp.session._verify` and still re-read at a download's speed.

        Neither end is opened or closed here: the handle is the caller's and so is the
        descriptor. Opening the destination is a *safety* decision -- ``O_NOFOLLOW`` and the
        creation mode -- and it belongs with the layer that knows where the file is allowed to
        be, which is why :meth:`~gantry_sftp.session.Session.get` keeps it.

        Args:
            handle: An open remote file handle, opened for reading.
            fd: Writable file descriptor. Not closed here.
            size: Expected size, from a stat. ``None`` reads until EOF, which costs one extra
                round trip at the end and is the only option when the server will not say.
            depth: Requests in flight, or ``None`` for this session's :attr:`depth`.
            progress: Called with ``(transferred, total)`` as data arrives, reporting the
                *absolute* position so a resumed transfer starts where it left off.
            remote_path: Carried on errors for diagnosis.
            start_offset: Byte to begin at. Non-zero resumes: reads start there and the
                descriptor is written at absolute offsets, so whatever is already below that
                point is left alone. Whether it is *right* is not knowable from here.

        Returns:
            Bytes written by this call, which is the file's size only when ``start_offset``
            is 0.

        Raises:
            TransferError: If the server refuses a read.
            TransferTimeoutError: If the server stops responding.
            ValueError: If ``start_offset`` is negative or past the end of the file.
        """
        return await download_handle(
            self._dispatcher,
            handle,
            fd,
            size=size,
            read_length=self.sizes_for(handle).read_length,
            depth=self._depth if depth is None else depth,
            idle_timeout=self._idle_timeout,
            progress=progress,
            remote_path=remote_path,
            start_offset=start_offset,
        )

    async def upload_from(
        self,
        handle: bytes,
        source: Path | str,
        *,
        depth: int | None = None,
        progress: ProgressCallback | None = None,
        remote_path: bytes | None = None,
        start_offset: int = 0,
    ) -> int:
        """Push a local file through an open remote handle, pipelined.

        The sending half of :meth:`download_into`, with the same argument for being here: the
        request size comes from the handle, so the schedule cannot be built before the handle
        exists. See that method on why the session does the scheduling.

        Takes a path rather than a descriptor because the sending side reads at explicit
        offsets from several requests in flight, and a descriptor with a shared cursor is the
        one thing that cannot serve. Nothing here opens or closes the remote handle.

        Args:
            handle: An open remote file handle, writable.
            source: Local file to read.
            depth: Requests in flight, or ``None`` for this session's :attr:`depth`. Each one
                holds a request's worth of payload, so this multiplies into real memory in a
                way the download side does not.
            progress: Called with ``(transferred, total)`` as writes are acknowledged.
            remote_path: Carried on errors for diagnosis.
            start_offset: Byte of the local file to begin at. Non-zero resumes, and the writes
                go to the same absolute offsets on the server -- so the remote file must
                already hold exactly the first ``start_offset`` bytes of this source. Nothing
                here can check that; it is the caller's claim, made from a stat, and a weak one.

        Returns:
            Bytes the server acknowledged in this call, which is the file's size only when
            ``start_offset`` is 0.

        Raises:
            TransferError: If the server refuses a write.
            TransferTimeoutError: If the server stops responding.
            ValueError: If ``start_offset`` is negative or past the end of the local file.
        """
        return await upload_handle(
            self._dispatcher,
            handle,
            source,
            write_length=self.sizes_for(handle).write_length,
            depth=self._depth if depth is None else depth,
            idle_timeout=self._idle_timeout,
            progress=progress,
            remote_path=remote_path,
            start_offset=start_offset,
        )

    async def opendir(self, path: bytes | str) -> bytes:
        """Open a remote directory and return its handle.

        Raises:
            NoSuchFileError: If the path does not exist.
            ServerError: If it is not a directory, or the server refuses.
        """
        encoded = self._resolve(path)
        reply = await self.request(OpenDir(self._next(), encoded))
        if isinstance(reply, Handle):
            return reply.handle
        raise _unexpected(reply, expected="HANDLE", path=encoded)

    async def readdir(self, handle: bytes) -> tuple[DirEntry, ...] | None:
        """Read one batch of entries, or ``None`` at the end of the directory.

        One READDIR is **not** a whole directory: the server returns as many entries as it
        feels like -- OpenSSH caps a batch at 100 -- and the caller keeps asking until this
        answers ``None``. Treating the first batch as the listing is how a client silently
        loses everything after the hundredth file.

        ``.`` and ``..`` are **not** filtered here. This is the raw batch; the filtering
        belongs to :meth:`listdir`, and keeping one place that shows what the server actually
        sent is what makes that filtering testable.

        **A NAME carrying zero names ends the directory too, and that is a decision.** The
        draft is explicit that it should not happen -- SSH_FXP_READDIR is answered with "one
        or more names", and end of directory is a ``STATUS`` of ``EOF`` -- and OpenSSH's
        server never sends one: ``process_readdir`` is ``if (count > 0) send_names(...) else
        send_status(id, SSH2_FX_EOF)``. So a zero-count NAME is a server bug whichever way we
        read it, and the only question is which way to fail on it.

        Treating it as an empty *batch* and asking again is what a literal reading gives, and
        it is a **livelock**: a server that answers every READDIR that way pins the client at
        100% CPU forever, in the operation every recursive transfer starts with. Refusing it
        with a ``ProtocolError`` would be defensible from the draft alone, but it would make
        this library **stricter than ``sftp(1)``** -- OpenSSH's own client reads the count and
        does ``if (count == 0) break;``, on the line above its ``SSH2_FX_EOF`` check. Every
        server in production has been tested against that client, which is what makes the
        truncation risk here structural rather than merely unlikely: a server that sends an
        empty NAME with entries still to come already silently truncates for every OpenSSH
        user, so it does not survive to ship. A server that sends one *as* its end-of-listing
        marker works fine with ``sftp(1)`` and therefore can and does exist.

        So it ends the listing, matching the reference client. Sourced in DESIGN.md 7.

        Returns:
            The batch, or ``None`` once the directory is finished -- by ``EOF`` or by an empty
            NAME, which are treated alike.

        Raises:
            ServerError: If the server refuses.
        """
        reply = await self.request(ReadDir(self._next(), handle))
        if isinstance(reply, Name):
            # An empty NAME is end of directory, not an empty batch. Returning `()` here is
            # what made every batch-following loop in this file spin forever on one.
            if not reply.entries:
                return None
            return tuple(DirEntry.from_name_entry(entry) for entry in reply.entries)
        if isinstance(reply, Status):
            if reply.code is StatusCode.EOF:
                return None
            raise_for_status(reply)
        raise _unexpected(reply, expected="NAME")

    async def close(self, handle: bytes) -> None:
        """Close a remote handle.

        Not merely bookkeeping: some servers report a write failure here rather than on the
        WRITE that caused it, so a CLOSE that returns an error is the transfer failing.
        """
        await self._expect_status(Close(self._next(), handle))

    async def mkdir(self, path: bytes | str, *, exist_ok: bool = False) -> None:
        """Create a directory.

        ``exist_ok`` costs a round trip when it fires, and it has to: v3 answers a failed
        MKDIR with ``FAILURE``, the catch-all that means nothing, so "it is already there" is
        indistinguishable from "the parent is read-only" by status code. The only honest way
        to tell them apart is to look, which is what this does -- and it checks the path is a
        *directory*, since a file of the same name is a different problem wearing the same
        status.

        Raises:
            ServerError: If the server refuses, and ``exist_ok`` does not excuse it.
        """
        encoded = self._resolve(path)
        try:
            await self._expect_status(MkDir(self._next(), encoded, EMPTY_ATTRS), path=encoded)
        except ServerError:
            if not exist_ok or not await self._is_directory(encoded):
                raise

    async def _is_directory(self, path: bytes) -> bool:
        """Whether the server positively reports ``path`` as a directory.

        ``LSTAT``, so a symlink is not mistaken for what it points at, and every failure --
        including a server that sends no permissions at all -- answers ``False``. Used to
        decide whether a refusal can be excused, and "the server would not say" is not an
        excuse.

        Distinct from :meth:`isdir`, which is the public question and raises where this
        returns ``False``: here the caller is deciding whether to *excuse* a refusal it
        already has, and an unexplained answer must not excuse anything.
        """
        try:
            attributes = await self.lstat(path)
        except ServerError:
            return False
        return entry_kind(attributes) is EntryKind.DIRECTORY

    async def remove(self, path: bytes | str) -> None:
        """Delete a file, a symlink, or any other non-directory entry.

        ``REMOVE`` is ``unlink(2)``: it deletes the *name*, so a symlink is removed rather
        than what it points at, and a directory is refused rather than emptied. That refusal
        is load-bearing for :meth:`rmtree`, which is the only recursive delete here.

        Raises:
            NoSuchFileError: If the path is not there.
            ServerError: For any other refusal, including the path being a directory.
        """
        encoded = self._resolve(path)
        await self._expect_status(Remove(self._next(), encoded), path=encoded)

    async def rmdir(self, path: bytes | str) -> None:
        """Delete an **empty** directory.

        ``RMDIR`` is ``rmdir(2)`` and does not recurse. A directory with anything left in it
        is refused, which is what makes a bottom-up :meth:`rmtree` self-checking: if anything
        was missed, the parent's removal fails rather than the tree quietly half-disappearing.

        Raises:
            NoSuchFileError: If the path is not there.
            ServerError: For any other refusal, including the directory not being empty.
        """
        encoded = self._resolve(path)
        await self._expect_status(RmDir(self._next(), encoded), path=encoded)

    async def rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        """Rename with plain v3 ``RENAME``, which **cannot overwrite**.

        Measured against OpenSSH 10.0p2: renaming onto a path that already exists answers
        ``FAILURE`` and changes nothing. That is the specification's intent and it is why
        :meth:`posix_rename` exists. Servers disagree here -- some overwrite, some silently
        do nothing -- so a caller who needs replacement should ask for it rather than assume
        this does it.

        Raises:
            ServerError: If the server refuses, which includes the target already existing.
        """
        encoded = self._resolve(new_path)
        await self._expect_status(
            Rename(self._next(), self._resolve(old_path), encoded), path=encoded
        )

    async def posix_rename(self, old_path: bytes | str, new_path: bytes | str) -> None:
        """Rename with ``posix-rename@openssh.com``, which **does** overwrite, atomically.

        Sent whether or not the server advertised the extension, because advertisement is
        not the only evidence -- endpoints implement extensions they never list. A server
        that does not have it answers ``OP_UNSUPPORTED`` and stays perfectly usable, which is
        measured, not hoped: three unknown extension names in a row on a real ``sftp-server``
        each returned ``OP_UNSUPPORTED`` and the session survived all three.

        Raises:
            UnsupportedError: If the server does not implement the extension.
            ServerError: For any other refusal.
        """
        encoded = self._resolve(new_path)
        request = PosixRename(self._next(), self._resolve(old_path), encoded)
        await self._expect_status(request.to_extended(), path=encoded)

    async def fsync(self, handle: bytes) -> None:
        """Flush an open handle to stable storage with ``fsync@openssh.com``.

        Must be sent **before** the ``CLOSE``, and that ordering is measured rather than
        assumed: the same handle after a close answers ``NO_SUCH_FILE``.

        This covers the file, not the directory entry. SFTP has no way to flush a directory,
        so a rename that publishes the file is never itself durable -- a limitation to state
        rather than to imply.

        Raises:
            UnsupportedError: If the server does not implement the extension.
            ServerError: For any other refusal, including a handle it does not recognise.
        """
        await self._expect_status(Fsync(self._next(), handle).to_extended())

    async def check_file(
        self,
        handle: bytes,
        *,
        algorithms: bytes = b"sha256,sha1,md5",
        start_offset: int = 0,
        length: int = 0,
        block_size: int = CHECK_FILE_BLOCK_SIZE,
    ) -> tuple[bytes, tuple[bytes, ...]]:
        """Ask the server to hash a file it already has, without moving the bytes again.

        Rung 1 of DESIGN.md 6's verification ladder, and the only rung that verifies
        *content* rather than byte count. **Most servers do not have it** -- OpenSSH answers
        ``OP_UNSUPPORTED`` under all three spellings, measured -- so a caller that needs
        verification everywhere still falls back to rung 3, a size check, and is told so
        rather than left to assume.

        The handle must have been opened for **reading**. Paramiko hashes by reading through
        it, so a WRITE-only handle -- the one an upload is holding -- answers ``FAILURE``
        with ``"Unable to hash file"``. Verifying something being uploaded therefore costs a
        second ``OPEN``, and cannot reuse the handle the bytes are going through.
        The draft's path-taking sibling would remove that second ``OPEN``; it is permanently
        not built, and :class:`~gantry_sftp.codec.CheckFile` is where the decision and its
        evidence live.

        The digest count is not on the wire: the server sends one digest per block,
        concatenated, and how many that is follows from ``block_size`` and the digest size of
        whichever algorithm it picked. That size comes from ``hashlib`` here, so an algorithm
        this Python does not know is an error rather than a silently mis-split answer.

        Args:
            handle: An **open**, readable file handle, from :meth:`open`. Not a path --
                paramiko's spelling of this extension takes a handle, and answers
                ``BAD_MESSAGE`` for one it does not recognise.
            algorithms: Preference order as a name-list. The server picks the first it
                supports and names its choice in the reply.
            start_offset: First byte to hash.
            length: Bytes to hash, or ``0`` for the rest of the file.
            block_size: Bytes per digest. Defaults to
                :data:`~gantry_sftp.session.CHECK_FILE_BLOCK_SIZE`, which is 64 KiB and is the
                largest block paramiko answers correctly.

                ``0`` is the wire value for "one digest over the whole range" and it was this
                parameter's default until 0.9. **Do not send it**, and do not send anything
                above 64 KiB either: measured against paramiko, a block over 64 KiB returns
                digests of the wrong bytes, and once its runaway offsets pass EOF the server
                loops forever and answers nothing -- permanently, from our side as well as
                its own. ``0`` also fails outright below 256 bytes, because paramiko rewrites
                it to the range length and then rejects that as too small. The reasons are in
                :data:`~gantry_sftp.session.CHECK_FILE_BLOCK_SIZE`.

        Returns:
            The algorithm the server chose, and one digest per block.

        Raises:
            UnsupportedError: If the server does not implement the extension. Raised without a
                round trip once this server has answered that in this session -- verification
                asks per file, and re-asking a settled question is a round trip per file for an
                answer that cannot have changed.
            ServerError: If it refuses -- including ``FAILURE`` when it supports none of the
                algorithms offered, and ``BAD_MESSAGE`` for an unknown handle.
            ProtocolError: If the reply is not a well-formed check-file answer, or names an
                algorithm whose digest size does not divide the bytes it sent.
        """
        if self.refuses(EXTENSION_CHECK_FILE):
            raise UnsupportedError(
                f"this server has already answered OP_UNSUPPORTED for {EXTENSION_CHECK_FILE}",
                code=StatusCode.OP_UNSUPPORTED,
            )
        request = CheckFile(
            self._next(),
            handle,
            algorithms=algorithms,
            start_offset=start_offset,
            length=length,
            block_size=block_size,
        )
        reply = await self.request(request.to_extended())
        if isinstance(reply, Status) and reply.code is StatusCode.OP_UNSUPPORTED:
            # Recorded here rather than by catching the exception `_unexpected` raises two
            # lines down: the status is the definitive answer, and reading it where it arrives
            # keeps the recording next to the fact rather than next to the error handling.
            self._unsupported.add(EXTENSION_CHECK_FILE.encode("ascii"))
        if not isinstance(reply, ExtendedReplyPacket):
            raise _unexpected(reply, expected="EXTENDED_REPLY")

        parsed = CheckFileReply.from_reply(reply)
        try:
            # `usedforsecurity=False` for the reason every other hashlib call in this package
            # carries it, and this was the one site that did not: a FIPS-enabled build refuses
            # `hashlib.new("md5")` outright, and paramiko -- the only server implementing this
            # extension -- offers nothing but md5 and sha1. Without the flag, rung 1 against it
            # failed on such a build with "which this Python cannot size", which names the
            # algorithm as the problem when the problem is the policy. It is also true on its
            # own terms: this digest is a transfer check, not an authentication one.
            digest_size = hashlib.new(
                parsed.algorithm.decode("ascii"), usedforsecurity=False
            ).digest_size
        except ValueError as unknown:
            # One `except` for two failures, and the second is why this must not be narrowed to
            # the hashlib one: `algorithm` is the *server's* bytes, so a non-ASCII name raises
            # `UnicodeDecodeError` from the `decode` above -- and that **is** a `ValueError`,
            # which is also why a test written as `pytest.raises(ValueError)` cannot tell the
            # two apart. Both are the same answer to the caller: a name we cannot size.
            raise ProtocolError(
                f"server hashed with {parsed.algorithm!r}, which this Python cannot size, "
                f"so its {len(parsed.digests)} digest bytes cannot be split",
                request_id=reply.request_id,
            ) from unknown
        try:
            return parsed.algorithm, parsed.split(digest_size)
        except ValueError as misaligned:
            raise ProtocolError(
                str(misaligned), request_id=reply.request_id, raw_frame=reply.data
            ) from misaligned

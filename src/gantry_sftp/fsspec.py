"""An fsspec filesystem, so pandas, pyarrow, dask and DVC can read over SFTP through us.

The interface DESIGN 8 lists first, because it is the one that costs a user nothing to
adopt: they already call ``fsspec``, and a URL is the whole of the integration.

**Registration is explicit and never happens on import** (D-60), and that is a security
decision rather than a style one. ``sftp://`` and ``ssh://`` are *already* registered inside
fsspec itself, to a paramiko implementation, and displacing them costs one line:
``register_implementation("sftp", cls)`` with fsspec's default ``clobber=False`` **succeeds
without a word** when nothing has resolved ``sftp://`` yet, and raises ``ValueError`` when
something has -- so which of the two happens is decided by import order. A library that
silently changed what ``pd.read_parquet("sftp://...")`` does merely because it was installed
would be doing the thing this repository would call an attack if somebody else did it. So::

    from gantry_sftp.fsspec import register

    register()                       # our own protocol, `gantry-sftp://`, which is free
    register("sftp", override=True)  # displace the incumbent, deliberately and in writing

**What displacing it buys, and it is not throughput.** The incumbent calls
``set_missing_host_key_policy(paramiko.AutoAddPolicy())`` unconditionally, so every
``sftp://`` URL in the pandas and dask ecosystem today accepts whatever host key it is
offered. We spawn ``ssh``, which reads the real ``known_hosts`` and refuses -- the bug class
this library cannot have, reached by not implementing SSH at all.

**Sync rather than async, and that keeps trio.** ``fsspec.asyn`` is asyncio and only asyncio:
it builds an ``asyncio.new_event_loop()`` on a daemon thread and submits with
``run_coroutine_threadsafe``. Subclassing ``AsyncFileSystem`` would pin this adapter to the
asyncio backend for an audience that does not exist, because an async caller already has
:class:`~gantry_sftp.Session` and needs no filesystem abstraction. This is a sync
``AbstractFileSystem`` over :mod:`gantry_sftp.sync`, which is D-84's portal reused whole
rather than a second concurrency runtime.

**Lifetime is fsspec's design and it is the hard part.** ``AbstractFileSystem`` instances are
cached by the ``_Cached`` metaclass, the cache holds a **strong** reference on purpose, and
there is no ``close()`` in the contract for us to be called through -- so ``__del__`` never
fires. Three consequences, each decided rather than discovered:

- **The connection is opened lazily**, on first use, not in ``__init__`` as the incumbent
  does. Merely resolving a URL constructs an instance; connecting there would spawn an ``ssh``
  child for a filesystem nobody went on to read from.
- **A sync filesystem is tokenized with** ``threading.get_ident()``, so it is one instance --
  and therefore one ``ssh`` child -- **per thread**, not per host. A thread pool calling
  ``pd.read_parquet`` fans out to one subprocess each.
- **The cache is cleared when the pid changes**, which is fork: the Python object is dropped
  while the child it held belongs to the parent. Every path that could signal the child
  compares :func:`os.getpid` first, because killing a pid recorded before a fork is killing
  whatever now holds that number.

:meth:`GantrySFTPFileSystem.close` and the context-manager protocol are provided anyway, for
a caller who wants the connection to end when they say so; ``skip_instance_cache=True`` is
the spelling for "give me one fsspec will not hand to anybody else".

**The password never reaches ``storage_options``**, which is the one credential path fsspec
would otherwise take out of our hands: ``storage_options`` is what ``__reduce__`` pickles --
so a dask scheduler ships it to every worker -- and what ``to_json()`` serialises, whose
``include_password`` parameter defaults to ``True``. Listing it in ``_strip_tokenize_options``
means it reaches ``__init__`` and is never stored there. The measured cost is stated on
:class:`GantrySFTPFileSystem`.
"""

from __future__ import annotations

import os
import threading
from contextlib import ExitStack, contextmanager
from contextlib import suppress as _suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, Self, override
from urllib.parse import parse_qsl

try:
    from fsspec import AbstractFileSystem
    from fsspec.callbacks import DEFAULT_CALLBACK, Callback
    from fsspec.registry import known_implementations, register_implementation, registry
    from fsspec.spec import AbstractBufferedFile
    from fsspec.utils import infer_storage_options
except ModuleNotFoundError as _exc:  # pragma: no cover -- proven by a subprocess test
    raise ModuleNotFoundError(
        "gantry_sftp.fsspec needs fsspec, which is an optional dependency of this library: "
        "install it with `pip install gantry-sftp[fsspec]` (or `uv add gantry-sftp[fsspec]`). "
        "Nothing else in gantry_sftp requires it."
    ) from _exc

from anyio.from_thread import start_blocking_portal

from gantry_sftp.codec import Attrs, OpenFlag
from gantry_sftp.exceptions import (
    CapabilityError,
    NoSuchFileError,
    PermissionDeniedError,
    ServerError,
    SFTPError,
)
from gantry_sftp.session import (
    DEFAULT_SESSION_OPTIONS,
    DirEntry,
    EntryKind,
    ProgressCallback,
    SessionOptions,
    check_listed_name,
    decode_name,
    join_remote,
)
from gantry_sftp.sync import BoundPortal, SyncSession

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping
    from datetime import datetime
    from typing import IO

__all__ = [
    "PROTOCOL",
    "GantrySFTPFile",
    "GantrySFTPFileSystem",
    "register",
]

PROTOCOL: Final = "gantry-sftp"
"""The protocol name this adapter owns.

Free in fsspec's ``known_implementations`` -- checked rather than assumed -- so registering it
displaces nothing and needs no ``override``. ``sftp`` and ``ssh`` are both taken, by
``fsspec.implementations.sftp.SFTPFileSystem``, and taking either is a decision the caller
makes with :func:`register`.
"""

WRITE_FLAGS: Final = OpenFlag.WRITE | OpenFlag.CREAT | OpenFlag.TRUNC
"""How :class:`GantrySFTPFile` opens a destination in write mode.

``mode=0o600`` goes with it at every call site. Omitting the permission field on ``OPEN``
means the server applies its own default, which on OpenSSH is ``0666 & ~umask`` -- a
world-readable file, and no later ``chmod`` closes the window between the two.
"""

_QUERY_FLOATS: Final = frozenset({"request_timeout", "idle_timeout"})
_QUERY_INTS: Final = frozenset({"port", "depth"})
_QUERY_STRINGS: Final = frozenset({"user", "cwd"})
_SESSION_KEYS: Final = frozenset({"request_timeout", "idle_timeout", "depth"})

_NAMES_A_LOCAL_PATH: Final = (
    "it names a local path, and a URL is untrusted input in a way a constructor call is not"
)
_RUNS_A_PROGRAM: Final = (
    "several ssh options run a program of their own -- ProxyCommand, LocalCommand, "
    "KnownHostsCommand and Match exec among them -- and one loads a shared library"
)

_REFUSED_IN_URL: Final[Mapping[str, str]] = {
    "identity_file": _NAMES_A_LOCAL_PATH,
    "config_file": _NAMES_A_LOCAL_PATH,
    "ssh_executable": _NAMES_A_LOCAL_PATH,
    "options": _RUNS_A_PROGRAM,
}
"""Constructor arguments a URL may **not** set, mapped to why. Each is still an argument.

D-120. The first three were accepted as query parameters until 0.11, and two of them were
remote code execution from a URL string -- measured, not reasoned about:

- ``ssh_executable`` is ``argv[0]``. A URL naming it chooses the program this library spawns.
- ``config_file`` is ``-F``. An ``ssh_config`` is allowed a ``ProxyCommand``, which runs a
  program to obtain the connection, and a ``Match exec``, which runs one during config
  *parsing* before any connection is attempted. Neither is neutralised by any option in
  :data:`~gantry_sftp.transport._argv.DEFAULT_SSH_OPTIONS` -- ``PermitLocalCommand=no`` and
  ``ClearAllForwardings=yes`` do not reach either of them, which ``transport/_argv.py`` has
  said in a comment since 0.9. So a URL plus one attacker-writable file anywhere on disk was
  arbitrary command execution.
- ``identity_file`` is ``-i``, which is not execution but is still a URL choosing which local
  file gets read, and it tells the caller whether that file exists.

**The asymmetry is the point, and it is why this is not simply a smaller feature.** A
constructor argument is written by the author of the program; a URL arrives from a job
config, a notebook parameter, a database row or an API request, which is exactly the
population this adapter serves -- ``pd.read_parquet`` of a URL somebody else chose. Its own
docstring calls the incumbent's blanket host-key acceptance "the bug class this library
cannot have"; accepting these three from a URL was a worse one.

``options`` is the fourth and it was **never** accepted -- it is here because until now that
was true by omission rather than by a rule, and it is the most dangerous of the four. ``-o
ProxyCommand=…`` is the argument-injection payload ``transport/_argv.py``'s own module
docstring demonstrates, and ``-o StrictHostKeyChecking=no`` silently removes the defence that
makes an attacker-chosen destination survivable.

**A safe-subset allowlist was considered and refused**, and the reason is recorded so it is
not re-proposed: the directives that execute or load code are neither a short nor a stable
list -- ``ProxyCommand``, ``LocalCommand``, ``KnownHostsCommand`` and ``Match exec`` run
programs, ``PKCS11Provider`` loads a shared library, ``Include`` pulls in another config file
whole -- and a new OpenSSH release can add another, with arbitrary execution as the cost of
missing it. That is D-121's denylist trap in a second costume.

All four remain available as constructor arguments, so ``storage_options`` still carries them
and nothing an author writes in their own source is restricted.
"""

_AUTHORITY_ONLY: Final = frozenset({"password"})
"""Arguments a URL carries somewhere other than the query string.

Not a security boundary -- ``?password=`` grants no authority the ``user:password@host`` form
does not already grant, so this set never protects anything. It is here because the
unknown-parameter message would be **false**: ``password`` is a constructor argument *and* a
real part of the URL, just not of this part of it, and a caller told it was "unknown" would go
looking for a spelling that already works.

The message names ``storage_options`` first anyway, because that is the one place a password
travels in neither the URL string nor the instance cache token -- see
``_strip_tokenize_options``.
"""
_NONE_SPELLINGS: Final = frozenset({"none", "null", ""})
_UNBOUNDED: Final = 1 << 40
"""Length to ask for when the server would not say how big a file is.

``read_at`` stops at end of file and returns what it got, so this bounds the request
arithmetic without claiming to know a size nobody reported. It is a ceiling, not an
allocation.
"""


def _local_path(candidate: object) -> Path | None:
    """The local filename ``candidate`` names, or ``None`` if it is a file-like object.

    ``None`` is the signal to fall back to fsspec's own copy loop, which is the only thing that
    can write into an open stream: this library's transfer path places bytes with ``os.pwrite``
    into a descriptor it opened itself, and there is no filename here for it to open.

    Raises:
        TypeError: If the path is byte-flavoured. D-96's rule applies at this boundary too --
            a local path is a ``str`` or a ``Path``, and the silent ``os.fsdecode`` that would
            make this "just work" is how a Windows caller's separators end up in a filename.
    """
    if isinstance(candidate, Path):
        return candidate
    if isinstance(candidate, str):
        return Path(candidate)
    represent = getattr(candidate, "__fspath__", None)
    if represent is None:
        return None
    resolved = represent()
    if not isinstance(resolved, str):
        raise TypeError(
            f"a local path must be a str or a pathlib.Path; {type(candidate).__name__} "
            f"describes itself with {type(resolved).__name__}, and decoding it here would be "
            f"guessing an encoding for a name on this machine"
        )
    return Path(resolved)


def _or_default(callback: Callback | None) -> Callback:
    """The no-op callback fsspec's base class requires, when the caller supplied none."""
    return DEFAULT_CALLBACK if callback is None else callback


def _bridge(callback: Callback | None) -> ProgressCallback | None:
    """Turn an fsspec ``Callback`` into this library's progress protocol.

    The two disagree about who does the arithmetic and it matters: fsspec's is *incremental*
    (``relative_update(inc)``) with the total set once by ``set_size``, while this library's is
    *absolute* (``transferred, total``) because a resumed or retried transfer has no meaningful
    increment to report. So the bridge sets the size once and then uses ``absolute_update``,
    which is the one call that cannot double-count when a range is retried.

    Returns:
        A callback for ``get``/``put``, or ``None`` when the caller supplied nothing to report
        to -- ``None`` is what this library's transfer path takes for "do not report".
    """
    if callback is None or not isinstance(callback, Callback):
        return None
    sink: Any = callback
    sized: set[int | None] = set()

    def report(transferred: int, total: int | None) -> None:
        if total not in sized:
            sized.add(total)
            sink.set_size(total)
        sink.absolute_update(transferred)

    return report


@contextmanager
def _translated(path: str) -> Generator[None]:
    """Re-raise this library's errors as the ones fsspec's callers catch.

    :class:`~gantry_sftp.SFTPError` is deliberately not an ``OSError`` -- a protocol failure is
    not an operating-system failure, and conflating the two is how an incumbent ends up
    reporting a handshake problem as an ``EOFError``. But ``FileNotFoundError`` **is** fsspec's
    contract: ``AbstractFileSystem.info`` is documented to raise it, ``exists`` is written
    around it, and pandas tests for it by name. So the translation happens here, at the
    adapter boundary, and nowhere else in this library.

    The original is chained rather than discarded, so the state this library's errors carry --
    status code, server message, matched profile -- survives into ``__cause__``.
    """
    try:
        yield
    except NoSuchFileError as exc:
        raise FileNotFoundError(path) from exc
    except PermissionDeniedError as exc:
        raise PermissionError(path) from exc


def _encode(path: str) -> bytes:
    """A remote path as bytes, by the encoder :func:`~gantry_sftp.session.decode_name` inverts.

    ``surrogateescape`` both ways, so a name that came back from the server as invalid UTF-8
    and was decoded leniently can be sent again unchanged. A client that cannot re-send what it
    was just given cannot operate on those files at all -- and a listing full of them is
    ordinary on Linux.
    """
    return path.encode("utf-8", "surrogateescape")


def _kind(attrs: Attrs) -> EntryKind:
    """What the permission bits say this is, without guessing when they are absent."""
    return DirEntry(filename=b"", longname=b"", attrs=attrs).kind


def _fsspec_type(attrs: Attrs) -> Literal["file", "directory", "other"]:
    """The three-word vocabulary fsspec uses, with ``"other"`` carrying "the server did not say".

    ``EntryKind.UNKNOWN`` is a real state -- v3 carries the file type inside the permission
    bits and a server need not send any -- and it maps to ``"other"`` rather than to
    ``"file"``, because answering "file" when nobody said is how a recursive walk silently
    skips every directory on such a server.
    """
    kind = _kind(attrs)
    if kind is EntryKind.DIRECTORY:
        return "directory"
    if kind is EntryKind.FILE:
        return "file"
    return "other"


def _attribute_fields(attrs: Attrs) -> dict[str, Any]:
    """The attribute keys, omitting what the server did not send rather than inventing it.

    ``size`` is present-but-``None`` when unknown, which ``AbstractFileSystem.info``'s own
    docstring names as the spelling for "this filesystem could not measure it". The others are
    absent when absent: a ``uid`` of 0 is root, not "unreported", so a zero default would be a
    lie with a plausible value.
    """
    fields: dict[str, Any] = {"size": attrs.size}
    if attrs.permissions is not None:
        fields["mode"] = attrs.permissions
    if attrs.owner is not None:
        fields["uid"] = attrs.owner.uid
        fields["gid"] = attrs.owner.gid
    if attrs.times is not None:
        fields["time"] = attrs.times.atime
        fields["mtime"] = attrs.times.mtime
    return fields


def _as_int(key: str, raw: str) -> int:
    """Parse an integer query parameter, naming the parameter when it does not parse."""
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"query parameter {key!r} must be an integer, got {raw!r}") from exc


def _as_float(key: str, raw: str) -> float:
    """Parse a float query parameter, naming the parameter when it does not parse."""
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"query parameter {key!r} must be a number, got {raw!r}") from exc


def _query_value(key: str, raw: str) -> str | int | float | None:
    """One query parameter, converted to the type its constructor argument takes."""
    if key in _QUERY_STRINGS:
        return raw
    if key in _QUERY_INTS:
        return _as_int(key, raw)
    if raw.lower() in _NONE_SPELLINGS:
        # `request_timeout=none` is the spelling for "wait forever", which is a value the
        # constructor takes and a URL has no other way to say.
        return None
    return _as_float(key, raw)


def _parse_query(query: str) -> dict[str, Any]:
    """Turn a URL query string into constructor arguments, refusing what we do not know.

    An unknown parameter raises rather than being ignored. A misspelled ``identiy_file`` that
    silently does nothing is a connection that fails for a reason the message will not name,
    and a URL is exactly where a typo lives.

    The three names in :data:`_REFUSED_IN_URL` get their own message rather than falling into
    the unknown-parameter one (D-120). They *are* constructor arguments, so "unknown" would be
    false, and a caller who reads it as a typo would go looking for the correct spelling of a
    parameter that is spelled correctly and refused on purpose.

    Args:
        query: The raw query string, which fsspec hands back unparsed.

    Returns:
        Keyword arguments for :class:`GantrySFTPFileSystem`.

    Raises:
        ValueError: If a parameter names a local path, is not one this adapter accepts, or
            does not parse.
    """
    accepted = _QUERY_STRINGS | _QUERY_INTS | _QUERY_FLOATS
    session: dict[str, Any] = {}
    kwargs: dict[str, Any] = {}
    for key, raw in parse_qsl(query, keep_blank_values=True):
        if key in _REFUSED_IN_URL:
            raise ValueError(
                f"query parameter {key!r} may not be set from a {PROTOCOL} URL because "
                f"{_REFUSED_IN_URL[key]}; pass {key}=... to the filesystem instead, through "
                f"storage_options"
            )
        if key in _AUTHORITY_ONLY:
            raise ValueError(
                f"query parameter {key!r} is not how a {PROTOCOL} URL carries a password; put "
                f"it in the authority as user:password@host, or pass password=... through "
                f"storage_options, which keeps it out of the URL string altogether"
            )
        if key not in accepted:
            raise ValueError(
                f"unknown query parameter {key!r} in a {PROTOCOL} URL; this adapter accepts "
                f"{', '.join(sorted(accepted))}"
            )
        target = session if key in _SESSION_KEYS else kwargs
        target[key] = _query_value(key, raw)
    if session:
        kwargs["session"] = SessionOptions(**session)
    return kwargs


class GantrySFTPFileSystem(AbstractFileSystem):  # type: ignore[misc]  # fsspec ships no py.typed
    """Files over SFTP, with OpenSSH doing the cryptography.

    Not registered on import -- see :func:`register` and this module's docstring.

    ::

        from gantry_sftp.fsspec import register
        register()

        import pandas as pd
        frame = pd.read_parquet("gantry-sftp://user@example.com/incoming/events.parquet")

    **The password is deliberately absent from** ``storage_options``, so it cannot travel in a
    pickle or a ``to_json()``. The measured cost is the instance cache: two constructions
    differing *only* in password return the same instance, holding the first password, because
    the password is not part of the cache token. Pass ``skip_instance_cache=True`` when that is
    not what you want.

    **The predicates here are fsspec's, not this library's.** ``exists`` / ``isdir`` /
    ``isfile`` come from ``AbstractFileSystem`` and swallow every exception, including a
    refusal -- fsspec's documented contract, which pandas and dask are written against.
    :meth:`gantry_sftp.Session.exists` is the one that distinguishes "no such file" from "I was
    not allowed to look"; reach for the session when that difference matters.

    **Three arguments cannot come from a URL** and are constructor-only: ``identity_file``,
    ``config_file`` and ``ssh_executable``, each of which names a local path. Two of them were
    remote code execution from a URL string until 0.11 -- see :data:`_REFUSED_IN_URL` for what
    was measured. Pass them here, or in ``storage_options``, where the author of the program
    is the one writing them.

    Args:
        host: Hostname, or anything ``ssh`` would accept. Never interpreted as a flag.
        user: Remote user. ``ssh`` resolves it from its config when this is ``None``.
        port: Remote port.
        identity_file: Private key to offer. Not settable from a URL.
        password: Sent through ``SSH_ASKPASS``, never argv, never a log line, and never stored
            in ``storage_options``.
        config_file: An ``ssh_config`` to read instead of the default. Not settable from a URL.
        options: Extra ``-o`` options for ``ssh``. Never settable from a URL.
        ssh_executable: Which ``ssh`` to spawn. Not settable from a URL.
        cwd: A remote working directory relative paths resolve against. A URL path is always
            absolute, so this is how a relative root gets expressed.
        session: Scheduling tunables.
        kwargs: Passed to ``AbstractFileSystem``.
    """

    protocol = PROTOCOL
    root_marker = "/"
    _strip_tokenize_options = ("password",)

    def __init__(
        self,
        host: str,
        *,
        user: str | None = None,
        port: int | None = None,
        identity_file: str | os.PathLike[str] | None = None,
        password: str | None = None,
        config_file: str | os.PathLike[str] | None = None,
        options: Mapping[str, str] | None = None,
        ssh_executable: str | None = None,
        cwd: str | None = None,
        session: SessionOptions = DEFAULT_SESSION_OPTIONS,
        **kwargs: object,
    ) -> None:
        # fsspec's re-entry flag: the metaclass calls `__init__` again on a cache hit, and
        # running this body twice would drop a live connection on the floor.
        if self._cached:
            return
        super().__init__(**kwargs)
        self.host = host
        self.user = user
        self.port = port
        self.identity_file = identity_file
        self.config_file = config_file
        self.options = options
        self.ssh_executable = ssh_executable
        self.cwd = cwd
        self.session_options = session
        self._password = password
        self._stack: ExitStack | None = None
        self._session: SyncSession | None = None
        self._owner_pid: int | None = None
        self._lock = threading.Lock()

    @override
    def __repr__(self) -> str:
        """Names the endpoint and its state, and never the credential."""
        where = f"{self.user}@{self.host}" if self.user else self.host
        state = "connected" if self._session is not None else "not connected"
        return f"<{type(self).__name__} {where} ({state})>"

    # --- lifetime -------------------------------------------------------------------------

    @property
    def sftp(self) -> SyncSession:
        """The blocking session, opened on first use.

        Lazy on purpose: an instance exists as soon as a URL is *resolved*, and fsspec caches
        it forever, so connecting in ``__init__`` -- which is what the incumbent does -- would
        spawn an ``ssh`` child per thread per endpoint whether or not anything read a byte.
        """
        with self._lock:
            if self._session is None:
                self._session = self._connect()
            return self._session

    def _connect(self) -> SyncSession:
        """Start a portal and a session on it, owning both through one stack."""
        stack = ExitStack()
        try:
            portal = stack.enter_context(start_blocking_portal())
            session = stack.enter_context(
                BoundPortal(portal).connect(
                    self.host,
                    user=self.user,
                    port=self.port,
                    identity_file=self.identity_file,
                    password=self._password,
                    config_file=self.config_file,
                    options=self.options,
                    ssh_executable=self.ssh_executable,
                    session=self.session_options,
                )
            )
            if self.cwd is not None:
                session.chdir(self.cwd)
        except BaseException:
            stack.close()
            raise
        self._stack = stack
        self._owner_pid = os.getpid()
        return session

    def close(self) -> None:
        """Close the session and reap the ``ssh`` child.

        fsspec will never call this: there is no ``close`` in ``AbstractFileSystem``'s contract
        and the instance cache holds a strong reference, so ``__del__`` does not fire either.
        It is here for a caller who wants the connection to end when they say so, usually
        together with ``skip_instance_cache=True``.

        **After a fork this does nothing**, deliberately. fsspec clears its instance cache when
        the pid changes, so a forked child can hold this object while the ``ssh`` process it
        describes belongs to the parent; unwinding from here would be closing pipes and
        signalling a pid that is no longer ours.
        """
        with self._lock:
            stack, self._stack = self._stack, None
            self._session = None
            owner, self._owner_pid = self._owner_pid, None
        if stack is not None and owner == os.getpid():
            stack.close()

    def __enter__(self) -> Self:
        """Return the filesystem; the connection still opens on first use."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the session, since fsspec's own lifetime rules will not."""
        self.close()

    # --- paths ----------------------------------------------------------------------------

    @classmethod
    def _strip_protocol(cls, path: str) -> str:
        """Turn a URL into the remote path, dropping the scheme *and the host*.

        ``AbstractFileSystem``'s version strips only the scheme, which would leave ``host`` as
        the first path component. ``infer_storage_options`` is what the incumbent uses and it
        is right about this: the host is connection state, not part of the name.

        A doubled separator survives -- ``gantry-sftp://host//abs`` is ``//abs`` -- because a
        server is entitled to distinguish it from ``/abs`` and nothing here is entitled to
        decide it does not.
        """
        text = infer_storage_options(str(path))["path"]
        if not isinstance(text, str) or not text:
            return cls.root_marker
        return text.rstrip("/") or cls.root_marker

    @staticmethod
    def _get_kwargs_from_urls(path: str) -> dict[str, Any]:
        """Turn a URL's authority and query string into constructor arguments.

        fsspec parses neither: ``infer_storage_options`` returns host, port, username and
        password, and hands the query back as an unparsed ``url_query``. So the URL form and
        every parameter in it is this adapter's decision, and the ones accepted are a *subset*
        of the arguments :func:`gantry_sftp.connect` takes -- the three that name a local path
        are refused here and constructor-only, for the reason in :data:`_REFUSED_IN_URL`.

        The argument is named ``path`` because the base class names it that and calls it
        positionally *and* by keyword; ``urlpath`` read better and was a Liskov violation the
        second checker caught.
        """
        options = infer_storage_options(path)
        kwargs: dict[str, Any] = {
            key: options[key] for key in ("host", "port", "password") if key in options
        }
        if "username" in options:
            kwargs["user"] = options["username"]
        query = options.get("url_query")
        if query:
            kwargs.update(_parse_query(str(query)))
        return kwargs

    # --- listing --------------------------------------------------------------------------

    def ls(self, path: str, detail: bool = False, **_kwargs: object) -> list[Any]:
        """List a directory, answering from the listing rather than a STAT per entry.

        v3 sends attributes *with* every ``READDIR`` entry, which is why this library's listing
        keeps them: a client that returns names alone forces a round trip per file, and that is
        why listing a large directory is slow in every paramiko-based tool.

        Every name is joined with :func:`~gantry_sftp.check_listed_name` and
        :func:`~gantry_sftp.join_remote`, because a listing is attacker-controlled input: a
        name carrying ``/`` or ``..`` would turn one directory's listing into a path somewhere
        else in the namespace, and this adapter hands those paths straight back to a caller.

        **Listing a plain file returns that one entry**, which is ``LocalFileSystem``'s
        behaviour and what ``find`` / ``glob`` / ``walk`` are written against. It costs an
        extra round trip only on the failure path, because SFTP gives no way to tell the two
        apart up front: ``OPENDIR`` on a file answers ``NO_SUCH_FILE`` rather than a distinct
        status, since the server remaps ``ENOTDIR``. So the ``LSTAT`` that separates "not a
        directory" from "not there" is asked only once the listing has already failed.
        """
        directory = self._strip_protocol(path)
        parent = _encode(directory)
        try:
            with _translated(directory):
                entries = self.sftp.listdir(directory)
        except FileNotFoundError:
            return self._list_one(directory, detail=detail)
        listing = [self._entry_info(parent, entry) for entry in entries]
        if detail:
            return listing
        return sorted(str(item["name"]) for item in listing)

    def _list_one(self, remote: str, *, detail: bool) -> list[Any]:
        """A listing of something that is not a directory, or the absence that really was one.

        Raises:
            FileNotFoundError: If the path does not exist after all.
        """
        entry = self.info(remote)
        return [entry] if detail else [str(entry["name"])]

    def info(self, path: str, **_kwargs: object) -> dict[str, Any]:
        """Describe one path, with the keys and the rules :meth:`ls` uses.

        fsspec's contract is that ``info`` returns "exactly the same information as ``ls``
        would with ``detail=True``", and the incumbent breaks it in a way worth naming: its
        ``ls`` reads ``READDIR``'s attributes, so a symlink comes back ``"link"``, while its
        ``info`` calls ``stat``, which follows, so the same path comes back ``"file"``. Both go
        through one function here, so they cannot disagree.
        """
        remote = self._strip_protocol(path)
        with _translated(remote):
            attrs = self.sftp.lstat(remote)
            return self._describe(remote, attrs)

    def _entry_info(self, parent: bytes, entry: DirEntry) -> dict[str, Any]:
        """One listing entry, as a path this library built out of validated parts."""
        name = join_remote(parent, check_listed_name(entry.filename, directory=parent))
        return self._describe(decode_name(name), entry.attrs)

    def _describe(self, remote: str, attrs: Attrs) -> dict[str, Any]:
        """Render attributes into fsspec's vocabulary, following a link exactly as it does.

        ``LocalFileSystem`` is the reference for the shape, and it settles the symlink
        question: ``type`` comes from the *followed* attributes, ``islink`` is a separate
        boolean, and ``destination`` carries the target. So a symlink to a parquet file is
        ``"file"`` and ``isfile`` answers ``True`` -- which is the point, because the
        incumbent's ``"link"`` makes it ``False`` and nothing will open it.
        """
        info: dict[str, Any] = {"name": remote, "islink": False}
        if _kind(attrs) is EntryKind.SYMLINK:
            return self._describe_link(remote, info)
        info.update(_attribute_fields(attrs))
        info["type"] = _fsspec_type(attrs)
        return info

    def _describe_link(self, remote: str, info: dict[str, Any]) -> dict[str, Any]:
        """A symlink: read once for its target, follow once for its type.

        **A broken link is reported rather than skipped or raised.** The follow fails, so the
        type is genuinely unknown: it comes back ``"other"`` with ``size: None`` and
        ``islink: True``, keeping ``destination`` so a caller can see what it pointed at.
        Dropping the entry would make a listing quietly disagree with the directory it
        describes, and raising would let one dead link cost the whole listing.
        """
        info["islink"] = True
        with _suppress(SFTPError):
            info["destination"] = decode_name(self.sftp.readlink(remote))
        try:
            followed = self.sftp.stat(remote)
        except SFTPError:
            return {**info, "type": "other", "size": None}
        info.update(_attribute_fields(followed))
        info["type"] = _fsspec_type(followed)
        return info

    def modified(self, path: str) -> datetime:
        """The modification time, as an aware UTC ``datetime``.

        Raises:
            FileNotFoundError: If the path does not exist.
            UnsupportedError: If the server sent no modification time for it.
        """
        remote = self._strip_protocol(path)
        with _translated(remote):
            when = self.sftp.getmtime(remote)
        if when is None:
            raise CapabilityError(
                f"the server sent no modification time for {remote!r}, so there is none to "
                f"report -- every field in an SFTP v3 ATTRS is optional",
                feature="modified()",
                path=_encode(remote),
            )
        return when

    def created(self, path: str) -> datetime:
        """Always raises: SFTP v3 has no creation time.

        An ``ATTRS`` carries size, uid/gid, permissions and an atime/mtime pair, and nothing
        else. There is no field to read and no way to derive one, so this refuses rather than
        returning the modification time under a second name.

        Raises:
            UnsupportedError: Always.
        """
        remote = self._strip_protocol(path)
        raise CapabilityError(
            f"SFTP v3 has no creation time: an ATTRS carries size, uid/gid, permissions and "
            f"atime/mtime only, so {remote!r} has no created timestamp to report",
            feature="created()",
            path=_encode(remote),
        )

    # --- namespace ------------------------------------------------------------------------

    def mkdir(self, path: str, create_parents: bool = True, **_kwargs: object) -> None:
        """Create a directory, letting the server decide whether the name is taken.

        No ``exists()`` first. The incumbent checks and then creates, which is two extra round
        trips *and* a window in which the answer stops being true; ``MKDIR`` already fails when
        the name is taken, and this library turns that contentless v3 ``FAILURE`` into a
        message naming which of "already a directory" and "a file is in the way" it was.
        """
        remote = self._strip_protocol(path)
        with self._creating(remote):
            if create_parents:
                self.sftp.makedirs(remote, exist_ok=True)
            else:
                self.sftp.mkdir(remote)

    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        """Create a directory and any missing parents.

        ``exist_ok`` governs the last component only: an existing *ancestor* is never an error,
        which is ``os.makedirs``'s contract rather than a tree upload's.

        Raises:
            FileExistsError: If the last component exists and ``exist_ok`` is false.
        """
        remote = self._strip_protocol(path)
        with self._creating(remote):
            self.sftp.makedirs(remote, exist_ok=exist_ok)

    @contextmanager
    def _creating(self, remote: str) -> Generator[None]:
        """Translate a refused ``MKDIR`` into the error fsspec's callers expect.

        v3 answers a failed ``MKDIR`` with the contentless ``FAILURE`` -- OpenSSH sends the
        single word ``Failure`` whether the name is occupied by a file, occupied by a
        directory, or the disk is full -- so the status code cannot say whether this is
        ``FileExistsError``. The session attaches a *note* naming the obstacle, which is for a
        human reading a traceback; a program needs a type.

        So the question is asked as a question: one ``LSTAT``, on a path that has already
        failed, and only on the failure path. **Reading our own note text instead would be
        parsing English we formatted ourselves**, which is the shape this library argues
        against everywhere else.
        """
        try:
            with _translated(remote):
                yield
        except ServerError as refusal:
            if self._occupied(remote):
                raise FileExistsError(remote) from refusal
            raise

    def _occupied(self, remote: str) -> bool:
        """Whether something is at ``remote``, where "the server would not say" is not a yes.

        A refusal to answer must not be turned into ``FileExistsError``: that would report
        "it is already there" for a directory nobody is allowed to look at.
        """
        try:
            return self.sftp.exists(remote, follow_symlinks=False)
        except SFTPError:
            return False

    def rmdir(self, path: str) -> None:
        """Remove an empty directory."""
        remote = self._strip_protocol(path)
        with _translated(remote):
            self.sftp.rmdir(remote)

    def _rm(self, path: str) -> None:
        """Remove one file, or one empty directory.

        fsspec's older spelling for ``rm_file``, and the one ``AbstractFileSystem.rm`` still
        reaches through. The kind is asked for rather than assumed, because ``REMOVE`` on a
        directory and ``RMDIR`` on a file both fail on every server. ``follow_symlinks=False``
        so a link to a directory is unlinked rather than followed to an ``RMDIR`` of whatever
        it points at.
        """
        remote = self._strip_protocol(path)
        with _translated(remote):
            if self.sftp.isdir(remote, follow_symlinks=False):
                self.sftp.rmdir(remote)
            else:
                self.sftp.remove(remote)

    def mv(
        self,
        path1: str,
        path2: str,
        recursive: bool = False,
        maxdepth: int | None = None,
        **_kwargs: object,
    ) -> None:
        """Rename, server-side.

        ``AbstractFileSystem.mv`` is a copy followed by a delete, which for a remote filesystem
        means every byte crossing this client twice. A rename is one packet.
        ``posix-rename@openssh.com`` is used where the server advertises it, so the destination
        is replaced atomically; without it this is v3 ``RENAME``, which fails when the
        destination exists rather than silently doing half the job.

        ``recursive`` and ``maxdepth`` are accepted and have no effect, because a ``RENAME``
        moves a directory with everything under it in one operation -- there is no depth for a
        limit to apply to. ``maxdepth`` is therefore refused rather than ignored: a caller who
        asked to move three levels and no more would otherwise get the whole tree moved and be
        told it worked.

        Raises:
            ValueError: If ``maxdepth`` is given, since a rename cannot honour it.
        """
        if maxdepth is not None:
            raise ValueError(
                "maxdepth is not meaningful for a server-side rename: RENAME moves a directory "
                "and everything under it in one operation, so there is no depth to limit. Copy "
                "and delete explicitly if a partial move is what you meant"
            )
        old, new = self._strip_protocol(path1), self._strip_protocol(path2)
        with _translated(old):
            self.sftp.posix_rename(old, new)

    # --- bytes ----------------------------------------------------------------------------

    def cat_file(
        self, path: str, start: int | None = None, end: int | None = None, **_kwargs: object
    ) -> bytes:
        """Read a byte range, pipelined, without staging the file anywhere.

        A range longer than one request becomes several requests in flight rather than a round
        trip per block. The one-``READ``-per-call shape is what ``paramiko#2453`` reports, and
        what makes an incumbent's file object slower than that same library's own whole-file
        download -- a pathology rather than a margin.

        A negative ``start`` or ``end`` is measured back from the end of the file, as in a
        Python slice; resolving one costs the ``FSTAT`` this already performs.
        """
        remote = self._strip_protocol(path)
        with _translated(remote):
            handle = self.sftp.open(remote, OpenFlag.READ)
            try:
                begin, length = _range(self.sftp.fstat(handle), start, end)
                return b"" if length <= 0 else self.sftp.read_at(handle, begin, length)
            finally:
                self.sftp.close(handle)

    def get_file(
        self,
        rpath: str,
        lpath: str | os.PathLike[str] | IO[bytes],
        callback: Callback | None = None,
        outfile: IO[bytes] | None = None,
        **kwargs: object,
    ) -> None:
        """Download, through this library's transfer path rather than fsspec's copy loop.

        The base class opens the remote file and copies it block by block. ``get`` pipelines,
        places every payload with ``os.pwrite`` at an explicit offset so nothing depends on
        arrival order, and checks the bytes it received against the size the server reported.

        ``callback`` is bridged rather than dropped -- a dropped one is a progress bar that
        silently never moves. A file-like ``lpath``, or an explicit ``outfile``, is not this
        path at all, since there is no local filename to write to, so both fall back to the
        base class rather than pretending.
        """
        remote = self._strip_protocol(rpath)
        local = _local_path(lpath)
        if outfile is not None or local is None:
            super().get_file(
                remote, lpath, callback=_or_default(callback), outfile=outfile, **kwargs
            )
            return
        with _translated(remote):
            if self.sftp.isdir(remote):
                local.mkdir(parents=True, exist_ok=True)
                return
            # The local parent, because the base class creates it and a caller writing
            # `fs.get(url, "out/2026/report.csv")` is entitled to the same behaviour here.
            local.parent.mkdir(parents=True, exist_ok=True)
            _ = self.sftp.get(remote, local, progress=_bridge(callback))

    def put_file(
        self,
        lpath: str | os.PathLike[str] | IO[bytes],
        rpath: str,
        callback: Callback | None = None,
        mode: str = "overwrite",
        **kwargs: object,
    ) -> None:
        """Upload, atomically, through this library's transfer path.

        ``put`` writes to a staging name and renames onto the destination, so a reader on the
        far end never sees a half-written file. That is the failure a drop directory is most
        often the scene of, and fsspec's block loop cannot promise it.

        ``mode="create"`` is honoured with an explicit refusal, matching the base class.

        Raises:
            FileExistsError: If ``mode`` is ``"create"`` and the destination exists.
        """
        remote = self._strip_protocol(rpath)
        if mode == "create" and self.exists(remote):
            raise FileExistsError(remote)
        local = _local_path(lpath)
        if local is None:
            super().put_file(lpath, remote, callback=_or_default(callback), mode=mode, **kwargs)
            return
        if local.is_dir():
            self.makedirs(remote, exist_ok=True)
            return
        with _translated(remote):
            parent = self._parent(remote)
            if parent and parent != remote:
                self.sftp.makedirs(parent, exist_ok=True)
            _ = self.sftp.put(local, remote, progress=_bridge(callback))

    def _open(
        self,
        path: str,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: object,
    ) -> GantrySFTPFile:
        """Return a file object backed by byte-range reads, not by a round trip per call."""
        return GantrySFTPFile(
            self,
            path,
            mode=mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_options=cache_options,
            **kwargs,
        )


def _range(attrs: Attrs, start: int | None, end: int | None) -> tuple[int, int]:
    """Turn fsspec's slice-shaped range into an absolute offset and a length.

    Args:
        attrs: What the server said about the file, whose ``size`` may be ``None``.
        start: Inclusive start, negative for "back from the end".
        end: Exclusive end, negative for "back from the end", ``None`` for the whole file.

    Returns:
        The absolute offset to read from, and how many bytes to ask for.

    Raises:
        UnsupportedError: If a negative bound was given and the server reported no size, so
            there is nothing to measure back from.
    """
    size = attrs.size
    if size is None and ((start is not None and start < 0) or (end is not None and end < 0)):
        raise CapabilityError(
            "a negative range is measured back from the end of the file, and this server "
            "reported no size, so there is nothing to measure back from",
            feature="a negative byte range",
        )
    begin = 0 if start is None else start if start >= 0 else max(0, (size or 0) + start)
    if end is None:
        stop = size if size is not None else begin + _UNBOUNDED
    else:
        stop = end if end >= 0 else max(0, (size or 0) + end)
    return begin, max(0, stop - begin)


class GantrySFTPFile(AbstractBufferedFile):  # type: ignore[misc]  # fsspec ships no py.typed
    """An fsspec file object over ``read_at`` / ``write_at``.

    ``AbstractBufferedFile`` provides the block cache, the seek arithmetic and the write
    buffer; what a subclass owes it is the three methods that move bytes. Each one goes through
    the *same* scheduler a whole-file transfer uses, so a block larger than one request becomes
    several requests in flight rather than one round trip per request.

    The shape this deliberately does not have is one ``READ`` per call, awaited: reads then cost
    a round trip each, and pulling a file through the object is slower than downloading the whole
    thing with the same library. That is a pathology rather than a margin, which is why the
    benchmark lane gates on it rather than merely reporting it.

    **One handle, held for the object's lifetime**, rather than an ``OPEN``/``CLOSE`` pair per
    block. That is why :meth:`close` is overridden -- ``AbstractBufferedFile.close`` finalises
    writes and drops the cache, and has no hook for a server-side resource.
    """

    def __init__(
        self, fs: GantrySFTPFileSystem, path: str, *args: object, **kwargs: object
    ) -> None:
        """Record the remote path before the base class asks the filesystem about it."""
        self._fs = fs
        self._remote = fs._strip_protocol(path)  # noqa: SLF001 -- fsspec's own classmethod API
        self._handle: bytes | None = None
        self._written = 0
        super().__init__(fs, path, *args, **kwargs)

    def _read_handle(self) -> bytes:
        """The read handle, opened once and kept."""
        if self._handle is None:
            with _translated(self._remote):
                self._handle = self._fs.sftp.open(self._remote, OpenFlag.READ)
        return self._handle

    def _fetch_range(self, start: int, end: int) -> bytes:
        """Read ``[start, end)``.

        **A short ``READ`` is legal and is already handled underneath.** ``read_at`` reassembles
        a range the server answered in pieces and returns short only at end of file, which is
        exactly this method's contract -- re-requesting the range from scratch here would be
        the bug that reassembler exists to prevent.
        """
        if end <= start:
            return b""
        with _translated(self._remote):
            return self._fs.sftp.read_at(self._read_handle(), start, end - start)

    def _initiate_upload(self) -> None:
        """Open the destination for writing, truncating whatever was there.

        fsspec's write model is a stream of blocks with no size known up front, so there is no
        staging-and-rename to be had here: :meth:`GantrySFTPFileSystem.put_file` is the atomic
        path and this is the one for a caller generating bytes. Said plainly rather than left
        to be discovered by someone who assumed otherwise.

        ``mode=0o600`` is not a default: omitting the permission field on ``OPEN`` lets the
        server apply ``0666 & ~umask``, and no later ``chmod`` closes the window in between.
        """
        with _translated(self._remote):
            self._handle = self._fs.sftp.open(self._remote, WRITE_FLAGS, mode=0o600)
        self._written = 0

    def _upload_chunk(self, final: bool = False) -> bool:
        """Write the buffered block at the offset it belongs at.

        ``write_at`` takes an explicit offset, so ordering is not something this has to
        maintain, and the payload reaches the wire without being copied.
        """
        payload = self.buffer.getbuffer()
        if payload.nbytes and self._handle is not None:
            with _translated(self._remote):
                written = self._fs.sftp.write_at(self._handle, self._written, payload)
            self._written += written
        return not final

    def close(self) -> None:
        """Finish the write, then release the server-side handle.

        The base class is called first so a final buffered block is flushed through
        :meth:`_upload_chunk` while the handle is still open; the ``CLOSE`` follows. A handle
        left open is a resource on somebody else's machine, which is why this is not left to
        the garbage collector.
        """
        already = self.closed
        try:
            super().close()
        finally:
            handle, self._handle = self._handle, None
            if handle is not None and not already:
                with _suppress(SFTPError):
                    self._fs.sftp.close(handle)


def register(protocol: str = PROTOCOL, *, override: bool = False) -> None:
    """Make this adapter resolvable for ``protocol``, deliberately and never on import.

    ::

        register()                       # `gantry-sftp://`, a name nothing else claims
        register("sftp", override=True)  # take `sftp://` from fsspec's paramiko implementation

    **Why this is not done for you.** ``sftp`` and ``ssh`` are already in fsspec's
    ``known_implementations``, pointing at a paramiko implementation shipped inside fsspec
    itself, and ``register_implementation`` with the default ``clobber=False`` **succeeds
    silently** when nothing has resolved that name yet -- its guard reads the live registry,
    which stays empty until the first ``sftp://`` URL is opened. So registering on import would
    change what ``pd.read_parquet("sftp://...")`` does in some processes and raise
    ``ValueError`` in others, decided by import order rather than by anybody's intent.

    Args:
        protocol: The name to claim.
        override: Required to claim a name fsspec already knows. Without it, claiming one
            raises rather than displacing it.

    Raises:
        ValueError: If ``protocol`` is already known to fsspec and ``override`` is false.
    """
    if not override:
        incumbent = _incumbent(protocol)
        if incumbent is not None:
            raise ValueError(
                f"the {protocol!r} protocol is already registered to {incumbent}; pass "
                f"override=True to replace it. Doing so silently would change what every "
                f"{protocol}:// URL in this process resolves to"
            )
    register_implementation(protocol, GantrySFTPFileSystem, clobber=True)


def _incumbent(protocol: str) -> str | None:
    """What already answers for ``protocol``, or ``None`` if the name is free.

    Both halves of fsspec's registry are consulted, because they answer different questions:
    ``registry`` is what has been resolved in *this process*, and ``known_implementations`` is
    what would be imported on the next miss. Checking only the first is precisely the gap that
    makes displacing ``sftp://`` silent.
    """
    live = registry.get(protocol)
    if live is not None and live is not GantrySFTPFileSystem:
        return f"{live.__module__}.{live.__qualname__}"
    known = known_implementations.get(protocol)
    if known is not None and known.get("class") != f"{__name__}.{GantrySFTPFileSystem.__name__}":
        return str(known["class"])
    return None

"""The fsspec adapter: the registry, the lifetime, the credential, and the bytes.

**D-60.** DESIGN 8 lists three interfaces and fsspec is the first, because pandas, pyarrow,
dask and DVC already call it. The card's own recon is what shaped these tests, and it found
that the interesting parts are not the filesystem methods:

- `sftp://` is **already registered** inside fsspec, to a paramiko implementation, and taking
  it is silent or a `ValueError` depending on import order. So the first tests here are about
  the *registry*, not about files.
- `AbstractFileSystem` caches instances by a token that includes `threading.get_ident()`, holds
  a strong reference on purpose, and has no `close()` in its contract. One `ssh` child per
  thread, and `__del__` never fires.
- `storage_options` is what `__reduce__` pickles and what `to_json()` serialises -- with
  `include_password` defaulting to `True`. A password there travels to every dask worker.

Everything below the registry runs against a real `sftp-server` on a pipe rather than a fake,
because DoD 1 says a fake only confirms what its author believed. `LocalGantryFS` overrides
exactly one method -- `_connect` -- so every line of the adapter above the connection is the
shipped one. The `ssh` path itself is `live-tests/test_fsspec_live.py`.
"""

from __future__ import annotations

import inspect
import io
import os
import subprocess
import sys
import threading
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

import fsspec
import pytest
from anyio.from_thread import start_blocking_portal
from fsspec.registry import (
    _registry,
    known_implementations,
    register_implementation,
    registry,
)

from gantry_sftp import fsspec as gantry_fsspec
from gantry_sftp.codec import Attrs
from gantry_sftp.exceptions import CapabilityError, NoSuchFileError, ServerError
from gantry_sftp.fsspec import (
    _AUTHORITY_ONLY,
    _QUERY_FLOATS,
    _QUERY_INTS,
    _QUERY_STRINGS,
    _REFUSED_IN_URL,
    _SESSION_KEYS,
    PROTOCOL,
    GantrySFTPFile,
    GantrySFTPFileSystem,
    _range,
    register,
)
from gantry_sftp.session import SessionOptions
from gantry_sftp.sync import BoundPortal
from gantry_sftp.transport import find_sftp_server

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    find_sftp_server() is None, reason="no sftp-server binary on this machine"
)


class LocalGantryFS(GantrySFTPFileSystem):
    """The shipped adapter, connected to a local ``sftp-server`` instead of through ``ssh``.

    One method overridden, deliberately: everything the tests exercise -- the listing, the
    joins, the symlink rules, the byte ranges, the buffered file -- is the shipped code, and
    the server answering is the real OpenSSH binary rather than a fake with our idea of a
    server in it.
    """

    protocol = "gantry-sftp-local"

    def __init__(self, root: str, host: str = "local", **kwargs: object) -> None:
        # `host` is accepted and ignored: a URL supplies one, and there is no ssh to give it
        # to. Everything else is the shipped constructor.
        if self._cached:
            return
        self._root = root
        super().__init__(host=host, **kwargs)

    def _connect(self):  # type: ignore[no-untyped-def]
        stack = ExitStack()
        portal = stack.enter_context(start_blocking_portal())
        gantry = BoundPortal(portal)
        transport = stack.enter_context(gantry.open_local_server_transport(cwd=self._root))
        session = stack.enter_context(gantry.open_session(transport))
        self._stack = stack
        self._owner_pid = os.getpid()
        return session


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A directory with the shapes that make an adapter's rules visible."""
    drop = tmp_path / "incoming"
    drop.mkdir()
    _ = (drop / "report.csv").write_bytes(b"id,total\n1,42\n")
    _ = (drop / "big.bin").write_bytes(bytes(range(256)) * 4096)
    # Not valid UTF-8. Ordinary on Linux, and the axis a name-handling test has to vary.
    _ = (drop / "caf\udce9.csv").write_bytes(b"\xe9")
    (drop / "latest.csv").symlink_to(drop / "report.csv")
    (drop / "dangling").symlink_to(tmp_path / "gone")
    (drop / "archive").mkdir()
    _ = (drop / "archive" / "old.csv").write_bytes(b"id\n0\n")
    return tmp_path


@pytest.fixture
def fs(tree: Path):  # type: ignore[no-untyped-def]
    """A filesystem over ``tree``, closed at the end of the test."""
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    try:
        yield filesystem
    finally:
        filesystem.close()


@pytest.fixture
def drop(tree: Path) -> str:
    return str(tree / "incoming")


@pytest.fixture(autouse=True)
def _restore_registry():
    """Undo any registration a test performs.

    The registry is process-global, so a test that claims ``sftp`` would otherwise decide what
    every later test in the session resolves -- which is the very failure mode this card is
    about, reproduced inside our own suite.

    **Through ``_registry`` rather than ``registry``, and that is D-104.**
    ``fsspec.registry.registry`` is a ``MappingProxyType`` over ``_registry`` -- read-only, and
    with no ``clear``. So the guarded call this used to make,
    ``registry.clear() if hasattr(registry, "clear") else None``, evaluated to ``None`` on
    every run and the loop underneath it only ever *added* the snapshot back. Anything a test
    registered survived the "restore", and the fixture read as though it worked.

    What that cost: `test_importing_the_library_registers_nothing` passed only because it sits
    above `test_override_displaces_the_incumbent_deliberately` in this file. Reorder them --
    which is what mutmut does, since it runs the tests most relevant to a mutant first -- and
    the assertion fails. It is the ordering dependence the Definition of Done forbids outright,
    hidden behind a fixture written to prevent exactly it.

    Restored by clear-and-update on the real dict rather than by replaying
    ``register_implementation``: a snapshot is only reversible if removals are undone too, and
    that is also what fsspec's own suite does.
    """
    live = dict(_registry)
    known = dict(known_implementations)
    yield
    _registry.clear()
    _registry.update(live)
    known_implementations.clear()
    known_implementations.update(known)


# --- the registry, which is the security half ---------------------------------------------


def test_importing_the_library_registers_nothing():
    """The headline decision, asserted rather than described.

    A library that changed what ``pd.read_parquet("sftp://...")`` does merely because it was
    installed would be doing the thing this repository would call an attack if somebody else
    did it. Both halves of fsspec's registry are checked: ``registry`` is what has been
    resolved in this process and ``known_implementations`` is what would be imported on the
    next miss, and writing to *either* is a takeover.
    """
    for name in ("sftp", "ssh"):
        assert registry.get(name) is not GantrySFTPFileSystem, f"{name} was taken on import"
        assert known_implementations[name]["class"] == (
            "fsspec.implementations.sftp.SFTPFileSystem"
        ), f"{name} points somewhere other than the incumbent"


def test_importing_the_adapter_module_does_not_register_even_its_own_free_name():
    # `gantry-sftp` is free, so claiming it on import would harm nobody -- and the rule is
    # still one rule, because "registration is explicit" is easier to rely on than
    # "registration is explicit for the names that matter".
    assert PROTOCOL not in registry
    assert PROTOCOL not in known_implementations


def test_register_claims_the_free_name():
    register()
    assert fsspec.get_filesystem_class(PROTOCOL) is GantrySFTPFileSystem


def test_register_refuses_a_name_fsspec_already_knows():
    with pytest.raises(ValueError) as exc:
        register("sftp")
    assert exc.value.args[0] == (
        "the 'sftp' protocol is already registered to "
        "fsspec.implementations.sftp.SFTPFileSystem; pass override=True to replace it. Doing "
        "so silently would change what every sftp:// URL in this process resolves to"
    )
    assert registry.get("sftp") is not GantrySFTPFileSystem


def test_register_refuses_a_name_only_the_live_registry_knows():
    """The half a `known_implementations` check alone would miss.

    fsspec's own guard reads the live registry; ours reads both, and this is the case that
    separates them -- a protocol somebody registered at runtime is in ``registry`` and not in
    ``known_implementations``.
    """
    register_implementation("some-other-fs", GantrySFTPFile, clobber=True)
    with pytest.raises(ValueError) as exc:
        register("some-other-fs")
    assert "already registered to gantry_sftp.fsspec.GantrySFTPFile" in exc.value.args[0]


def test_override_displaces_the_incumbent_deliberately():
    register("sftp", override=True)
    assert fsspec.get_filesystem_class("sftp") is GantrySFTPFileSystem


def test_registering_our_own_name_twice_is_not_an_error():
    # Idempotent, because a program that calls `register()` at import of two of its own modules
    # is doing something reasonable.
    register()
    register()
    assert fsspec.get_filesystem_class(PROTOCOL) is GantrySFTPFileSystem


def test_the_registry_is_pristine_after_every_test_that_claimed_a_name():
    """D-104. The same assertion as the first test in this file, from the other side.

    `test_importing_the_library_registers_nothing` sits *above* the four tests that register,
    so it only ever saw a clean registry -- and passed for that reason rather than because
    `_restore_registry` worked. It did not: `registry` is a `MappingProxyType` with no
    `clear`, so the fixture's guarded call evaluated to `None` and nothing was ever removed.

    Placing the same check *below* them pins the invariant from both ends, so the pair cannot
    both pass unless the fixture genuinely restores. That is what makes this file independent
    of collection order, which the Definition of Done requires and which mutmut -- running the
    tests most relevant to a mutant first -- is what actually exposed.
    """
    for name in ("sftp", "ssh"):
        assert registry.get(name) is not GantrySFTPFileSystem, f"{name} outlived its test"
    assert known_implementations[name]["class"] == "fsspec.implementations.sftp.SFTPFileSystem"
    assert "some-other-fs" not in registry


# --- the credential -------------------------------------------------------------------------


def test_the_password_never_reaches_storage_options():
    """The one credential path fsspec would otherwise take out of our hands.

    ``storage_options`` is what ``__reduce__`` pickles -- so a dask scheduler ships it to every
    worker -- and what ``to_json()`` serialises, whose ``include_password`` parameter defaults
    to ``True``. Listing ``password`` in ``_strip_tokenize_options`` means it reaches
    ``__init__`` and is never stored.
    """
    filesystem = GantrySFTPFileSystem(
        "example.com", user="bob", password="hunter2", skip_instance_cache=True
    )
    assert "password" not in filesystem.storage_options
    assert "hunter2" not in filesystem.to_json()
    assert "hunter2" not in repr(filesystem.__reduce__())
    assert "hunter2" not in repr(filesystem)
    # And it did arrive, so the absence above is not the absence of a working argument.
    assert filesystem._password == "hunter2"  # noqa: SLF001


def test_the_repr_names_the_endpoint_and_the_state():
    filesystem = GantrySFTPFileSystem("example.com", user="bob", skip_instance_cache=True)
    assert repr(filesystem) == "<GantrySFTPFileSystem bob@example.com (not connected)>"


def test_a_wrong_password_reuses_the_session_the_right_one_opened():
    """D-126. The price of keeping the password out of the cache token, named as what it is.

    The token omits ``password`` so the credential cannot travel in a pickle or a ``to_json()``,
    and that stays -- but it means the second caller's password is **never checked against
    anything**. A password that is wrong for the account still yields a working session,
    authenticated by whoever constructed first.

    Asserted as the security statement rather than as a caching one, because the two get read by
    different people: this used to be named for the *cost* and a reader budgeting for a stale
    connection does not reach for ``skip_instance_cache=True``, which is the control.
    """
    try:
        right = GantrySFTPFileSystem("example.com", user="bob", password="correct-horse")
        wrong = GantrySFTPFileSystem("example.com", user="bob", password="not-the-password")

        assert wrong is right
        # The whole finding in one line: what `wrong` will authenticate with is not what it
        # was given.
        assert wrong._password == "correct-horse"  # noqa: SLF001

        apart = GantrySFTPFileSystem(
            "example.com", user="bob", password="not-the-password", skip_instance_cache=True
        )
        assert apart is not right
        assert apart._password == "not-the-password"  # noqa: SLF001
    finally:
        # Both cached constructions above are keyed on a token this test invented, and the
        # cache is process-global. Leaving them behind would let this test decide what a later
        # one resolves -- the failure `_restore_registry` exists for, one cache along.
        GantrySFTPFileSystem._cache.clear()  # noqa: SLF001


# --- the instance cache, which is the lifetime --------------------------------------------


def test_the_same_options_come_back_as_the_same_instance():
    assert GantrySFTPFileSystem("h", user="bob") is GantrySFTPFileSystem("h", user="bob")
    assert GantrySFTPFileSystem("h", user="bob") is not GantrySFTPFileSystem("h", user="eve")


def test_a_second_thread_gets_a_second_instance_and_therefore_a_second_ssh_child():
    """Not a defect of ours, and not something a caller can be expected to guess.

    fsspec tokenizes a *sync* filesystem with ``threading.get_ident()``, so a thread pool
    calling ``pd.read_parquet`` fans out to one subprocess each. It is documented on the module
    for that reason, and asserted here so the documentation cannot quietly stop being true.
    """
    on_this_thread = GantrySFTPFileSystem("h", user="bob")
    elsewhere: list[object] = []
    worker = threading.Thread(
        target=lambda: elsewhere.append(GantrySFTPFileSystem("h", user="bob"))
    )
    worker.start()
    worker.join()
    assert elsewhere[0] is not on_this_thread


def test_close_after_a_fork_does_not_touch_the_parents_child(fs, drop: str, monkeypatch):
    """The pid guard: a forked child must not unwind the parent's connection.

    fsspec clears its instance cache when the pid changes, so a forked child can hold this
    object while the ``ssh`` process it describes belongs to the parent. Closing from there
    would be unwinding pipes and signalling a pid that is no longer ours.

    **The pid is moved rather than the process forked, and that is deliberate.** A real
    ``os.fork()`` here would fork a process running an anyio portal thread and an
    ``sftp-server`` child; CPython warns about fork-with-threads from 3.12, and written that
    way this test deadlocked. The guard *is* one comparison, and moving the pid exercises that
    comparison against a connection that is real on both sides of it.
    """
    assert fs.ls(drop)  # connect, so there is something a careless close could break
    stack, session = fs._stack, fs._session  # noqa: SLF001
    assert stack is not None
    assert session is not None

    monkeypatch.setattr(os, "getpid", os.getppid)
    fs.close()
    monkeypatch.undo()

    # Nothing was unwound: the session the parent owns still answers, and the ssh child is
    # still there to answer it. In a real fork the parent holds its own copy of this object,
    # so the child's forgetting is correct and invisible to the parent.
    assert session.listdir(drop), "a child's close() tore down the parent's connection"
    # Hand it back so the fixture's close() reaps what this test deliberately orphaned.
    fs._stack, fs._session, fs._owner_pid = stack, session, os.getpid()  # noqa: SLF001


def test_close_is_idempotent_and_reconnects_on_the_next_use(tree: Path, drop: str):
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    try:
        assert filesystem.ls(drop)
        filesystem.close()
        filesystem.close()
        assert filesystem.ls(drop), "a closed filesystem did not reopen on use"
    finally:
        filesystem.close()


def test_the_connection_is_not_opened_until_something_asks(tree: Path):
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    try:
        assert filesystem._session is None  # noqa: SLF001
        assert "not connected" in repr(filesystem)
        _ = filesystem.ls(str(tree))
        assert filesystem._session is not None  # noqa: SLF001
    finally:
        filesystem.close()


# --- paths and URLs -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("gantry-sftp://host/incoming", "/incoming"),
        ("gantry-sftp://host/incoming/", "/incoming"),
        # The doubled separator survives: a server is entitled to distinguish `//abs` from
        # `/abs`, and nothing here is entitled to decide it does not.
        ("gantry-sftp://host//abs", "//abs"),
        ("gantry-sftp://host", "/"),
        ("gantry-sftp://host/", "/"),
        ("/plain/path", "/plain/path"),
        ("/", "/"),
    ],
)
def test_a_url_strips_to_a_remote_path(url: str, expected: str):
    assert GantrySFTPFileSystem._strip_protocol(url) == expected  # noqa: SLF001


def test_the_url_carries_the_connection_arguments():
    kwargs = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
        "gantry-sftp://bob:hunter2@example.com:2222/incoming"
        "?cwd=/incoming&depth=8&request_timeout=30"
    )
    assert kwargs["host"] == "example.com"
    assert kwargs["port"] == 2222
    assert kwargs["user"] == "bob"
    assert kwargs["password"] == "hunter2"
    assert kwargs["cwd"] == "/incoming"
    assert kwargs["session"].depth == 8
    assert kwargs["session"].request_timeout == 30.0


def test_a_timeout_can_be_turned_off_in_a_url():
    # `None` means "wait forever", which a URL has no other way to say.
    kwargs = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
        "gantry-sftp://h/x?request_timeout=none"
    )
    assert kwargs["session"].request_timeout is None


def test_an_unknown_query_parameter_is_refused_rather_than_ignored():
    """A typo in a URL that silently does nothing is a connection failing for the wrong reason."""
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
            "gantry-sftp://h/x?identiy_file=/keys/id"
        )
    assert exc.value.args[0] == (
        "unknown query parameter 'identiy_file' in a gantry-sftp URL; this adapter accepts "
        "cwd, depth, idle_timeout, port, request_timeout, user"
    )


@pytest.mark.parametrize(("key", "raw"), [("depth", "lots"), ("request_timeout", "soon")])
def test_a_query_parameter_that_does_not_parse_names_itself(key: str, raw: str):
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls(f"gantry-sftp://h/x?{key}={raw}")  # noqa: SLF001
    assert key in exc.value.args[0]
    assert raw in exc.value.args[0]


# --- D-120: a URL may not name a local path -----------------------------------------------


@pytest.mark.parametrize("key", ["identity_file", "config_file", "ssh_executable"])
def test_a_url_may_not_name_a_local_path(key: str):
    """D-120. All three are constructor arguments, so the message may not say "unknown".

    A caller who reads "unknown query parameter 'config_file'" goes looking for the correct
    spelling of a parameter that is spelled correctly and refused on purpose.
    """
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls(f"gantry-sftp://h/x?{key}=/tmp/anything")  # noqa: SLF001
    assert exc.value.args[0] == (
        f"query parameter {key!r} may not be set from a gantry-sftp URL because it names a "
        f"local path, and a URL is untrusted input in a way a constructor call is not; pass "
        f"{key}=... to the filesystem instead, through storage_options"
    )


def test_a_url_naming_an_ssh_executable_does_not_run_it(tmp_path: Path):
    """D-120, named for the bug: ``?ssh_executable=`` was argv[0] and it was spawned.

    Measured before the fix -- the marker file below was written, with the real argv in it.
    The refusal has to happen while resolving the URL, before anything is spawned, which is
    why the assertion is on the marker and not only on the exception.
    """
    register()
    marker = tmp_path / "EXECUTED"
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text(f'#!/bin/sh\necho "argv: $*" > {marker}\nexit 1\n')
    fake_ssh.chmod(0o700)

    with pytest.raises(ValueError) as exc:
        _ = fsspec.open(f"gantry-sftp://user@example.com/x.parquet?ssh_executable={fake_ssh}")
    assert exc.value.args[0].startswith("query parameter 'ssh_executable' may not be set")
    assert not marker.exists(), f"the URL spawned {fake_ssh}"


def test_a_url_naming_a_config_file_does_not_run_its_proxycommand(tmp_path: Path):
    """D-120, named for the bug: ``?config_file=`` was ``-F`` and its ``ProxyCommand`` ran.

    The nastier of the two, because it needs no planted executable -- only a file the attacker
    can write anywhere on disk, which an uploads directory or ``/tmp`` supplies. Measured
    before the fix: the marker below was written by ``ssh`` itself while obtaining the
    connection. No option in ``DEFAULT_SSH_OPTIONS`` prevents it; ``PermitLocalCommand=no``
    governs ``LocalCommand`` and reaches neither ``ProxyCommand`` nor ``Match exec``.
    """
    register()
    marker = tmp_path / "PROXIED"
    config = tmp_path / "evil.conf"
    config.write_text(f'Host *\n  ProxyCommand /bin/sh -c "echo ran > {marker}; exit 1"\n')

    with pytest.raises(ValueError) as exc:
        _ = fsspec.open(f"gantry-sftp://user@example.com/x.parquet?config_file={config}")
    assert exc.value.args[0].startswith("query parameter 'config_file' may not be set")
    assert not marker.exists(), f"the URL ran the ProxyCommand in {config}"


def test_a_url_may_not_set_ssh_options():
    """D-120. ``options`` was never accepted, and until 0.11 that was true by omission.

    It is the most dangerous of the four: ``-o ProxyCommand=…`` is the payload
    ``transport/_argv.py``'s module docstring demonstrates, and ``-o StrictHostKeyChecking=no``
    removes the defence that makes an attacker-chosen destination survivable.
    """
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls(  # noqa: SLF001
            "gantry-sftp://h/x?options=ProxyCommand%3Dtouch+/tmp/pwned"
        )
    assert exc.value.args[0] == (
        "query parameter 'options' may not be set from a gantry-sftp URL because several ssh "
        "options run a program of their own -- ProxyCommand, LocalCommand, KnownHostsCommand "
        "and Match exec among them -- and one loads a shared library; pass options=... to the "
        "filesystem instead, through storage_options"
    )


def test_a_password_query_parameter_names_the_spelling_that_works():
    """Not a security boundary -- ``?password=`` grants nothing the authority does not.

    The refusal exists because "unknown query parameter 'password'" would be false, and a
    caller who read it as one would hunt for a spelling that already works.
    """
    with pytest.raises(ValueError) as exc:
        _ = GantrySFTPFileSystem._get_kwargs_from_urls("gantry-sftp://h/x?password=hunter2")  # noqa: SLF001
    assert exc.value.args[0] == (
        "query parameter 'password' is not how a gantry-sftp URL carries a password; put it "
        "in the authority as user:password@host, or pass password=... through storage_options, "
        "which keeps it out of the URL string altogether"
    )
    # And the spelling the message names does work.
    kwargs = GantrySFTPFileSystem._get_kwargs_from_urls("gantry-sftp://bob:hunter2@h/x")  # noqa: SLF001
    assert kwargs["password"] == "hunter2"


def test_every_constructor_argument_is_classified_for_the_url():
    """The rule, enforced rather than remembered: a new argument must be sorted before it ships.

    ``options`` was safe only because nobody had added it to ``_QUERY_STRINGS`` — an absence,
    which no test can fail on. This is the test that fails: it reads ``__init__``'s signature
    and requires every argument to appear in exactly one bucket, so the next argument added to
    the adapter cannot reach a release without somebody deciding whether a URL may set it.

    The question to answer when this fails is **not** "which set silences it" but the one
    D-120 turned on: does this name something on the *client* machine, or does it carry
    authority the URL's sender should not have? If either, it belongs in ``_REFUSED_IN_URL``.
    """
    accepted = _QUERY_STRINGS | _QUERY_INTS | _QUERY_FLOATS
    refused = frozenset(_REFUSED_IN_URL)
    # `host` is the URL's own; `user` and `port` are in the authority *and* accepted as query
    # parameters, which is deliberate and is why membership below is "at least one" rather
    # than "exactly one". `password` is authority-only.
    from_authority = frozenset({"host", "user", "port"}) | _AUTHORITY_ONLY
    expanded_into_session = frozenset({"session"})
    buckets = {
        "accepted": accepted,
        "refused": refused,
        "from the authority": from_authority,
        "expanded into session": expanded_into_session,
    }

    signature = inspect.signature(GantrySFTPFileSystem.__init__)
    arguments = {
        name
        for name, parameter in signature.parameters.items()
        if name != "self" and parameter.kind is not inspect.Parameter.VAR_KEYWORD
    }

    unclassified = sorted(
        argument
        for argument in arguments
        if not any(argument in bucket for bucket in buckets.values())
    )
    assert not unclassified, (
        f"{unclassified} are constructor arguments of GantrySFTPFileSystem and no set in "
        f"fsspec.py says whether a URL may set them; classify each one -- see _REFUSED_IN_URL"
    )

    # A parameter cannot be both allowed and refused, and a refused one must not be reachable
    # through the authority either -- that would be the same hole with a different spelling.
    assert not accepted & refused
    assert not refused & from_authority

    # Every name the query sets mention is either a constructor argument or a session tunable,
    # so a set cannot name something that quietly does nothing.
    assert (accepted | refused) - arguments == _SESSION_KEYS


def test_the_refused_parameters_are_still_constructor_arguments(tmp_path: Path):
    """The break is deliberate and bounded: refused from a URL, unchanged everywhere else.

    Nothing an author writes in their own source is restricted by D-120, and
    ``storage_options`` is that spelling for an fsspec caller.
    """
    filesystem = GantrySFTPFileSystem(
        "example.com",
        identity_file=str(tmp_path / "id_ed25519"),
        config_file=str(tmp_path / "ssh_config"),
        ssh_executable=str(tmp_path / "ssh"),
        skip_instance_cache=True,
    )
    assert filesystem.identity_file == str(tmp_path / "id_ed25519")
    assert filesystem.config_file == str(tmp_path / "ssh_config")
    assert filesystem.ssh_executable == str(tmp_path / "ssh")


# --- the one method the harness above replaces --------------------------------------------
#
# `LocalGantryFS` overrides `_connect`, which is what makes every other test here run against
# a real `sftp-server` without an `ssh`. The cost is that the shipped `_connect` is the one
# method in this module no test reaches -- the mutation lane reported all 28 of its mutants as
# "no tests", including every one of the nine arguments it forwards. A dropped `password=` or
# `identity_file=` there connects as somebody else, or not at all, and nothing here would have
# noticed. So this section stands the connection up against stand-ins for the two things it
# calls, and reads what it passed.


class _RecordingSession:
    def __init__(self) -> None:
        self.chdir_calls: list[object] = []

    def chdir(self, path: object) -> None:
        self.chdir_calls.append(path)


class _RecordingPortal:
    """Stands in for `BoundPortal`, recording the portal it was handed and the connect call."""

    def __init__(self, portal: object) -> None:
        self.portal = portal
        _recorded["portal_arg"] = portal

    @contextmanager
    def connect(self, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        _recorded["args"] = args
        _recorded["kwargs"] = kwargs
        session = _RecordingSession()
        _recorded["session"] = session
        yield session


_recorded: dict[str, Any] = {}


@pytest.fixture
def recording_connect(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Replace the two things `_connect` calls, so the shipped body runs and spawns nothing."""
    _recorded.clear()
    sentinel = object()

    @contextmanager
    def fake_portal():  # type: ignore[no-untyped-def]
        yield sentinel

    monkeypatch.setattr(gantry_fsspec, "start_blocking_portal", fake_portal)
    monkeypatch.setattr(gantry_fsspec, "BoundPortal", _RecordingPortal)
    return sentinel


def test_connect_forwards_every_constructor_argument_it_was_given(recording_connect, tmp_path):
    """Nine arguments, each droppable on its own with the whole suite green.

    Every value below is deliberately **not** the default, because an argument that forwards a
    value equal to the default is invisible: dropping it changes nothing observable and the
    lane and the test agree for the wrong reason.
    """
    options = SessionOptions(depth=7)
    filesystem = GantrySFTPFileSystem(
        "example.com",
        user="bob",
        port=2222,
        identity_file=str(tmp_path / "id_ed25519"),
        password="hunter2",
        config_file=str(tmp_path / "ssh_config"),
        options={"Compression": "yes"},
        ssh_executable=str(tmp_path / "ssh"),
        session=options,
        skip_instance_cache=True,
    )

    assert filesystem.sftp is _recorded["session"]

    assert _recorded["portal_arg"] is recording_connect, "BoundPortal got the wrong portal"
    assert _recorded["args"] == ("example.com",)
    assert _recorded["kwargs"] == {
        "user": "bob",
        "port": 2222,
        "identity_file": str(tmp_path / "id_ed25519"),
        "password": "hunter2",
        "config_file": str(tmp_path / "ssh_config"),
        "options": {"Compression": "yes"},
        "ssh_executable": str(tmp_path / "ssh"),
        "session": options,
    }


def test_connect_records_the_stack_and_the_pid_that_owns_it(recording_connect):
    """`close()` is a no-op unless both were stored, and after a fork that is the point.

    `_owner_pid` set to `None` makes every `close()` silently do nothing -- the connection
    stays open and the `ssh` child is never reaped -- and `_stack` set to `None` does the same
    from the other side.
    """
    filesystem = GantrySFTPFileSystem("example.com", skip_instance_cache=True)
    _ = filesystem.sftp

    assert filesystem._owner_pid == os.getpid()  # noqa: SLF001
    assert filesystem._stack is not None  # noqa: SLF001

    filesystem.close()
    assert filesystem._stack is None  # noqa: SLF001
    assert filesystem._session is None  # noqa: SLF001


def test_connect_changes_directory_only_when_a_cwd_was_asked_for(recording_connect):
    # Both directions: the guard inverted calls `chdir(None)` on every connection that did not
    # ask for one, and skips it on every connection that did.
    with_cwd = GantrySFTPFileSystem("example.com", cwd="/incoming", skip_instance_cache=True)
    assert with_cwd.sftp.chdir_calls == ["/incoming"]

    without = GantrySFTPFileSystem("example.com", skip_instance_cache=True)
    assert without.sftp.chdir_calls == []


# --- listing --------------------------------------------------------------------------------


def test_a_listing_names_every_entry_with_a_path_this_library_built(fs, drop: str):
    names = fs.ls(drop)
    assert names == sorted(names)
    assert f"{drop}/report.csv" in names
    assert all(name.startswith(f"{drop}/") for name in names)


def test_a_name_that_is_not_utf8_survives_listing_info_and_open(fs, drop: str, tree: Path):
    """The axis to vary, per DoD 1, and the one the incumbent has crashed on since 2015.

    ``decode_name`` is ``surrogateescape`` and this library's encoder is its exact inverse, so
    the name comes back as a ``str`` that can be handed straight back in and opens the same
    file. A lossy decode would make two distinct names one.
    """
    listed = [name for name in fs.ls(drop) if name.endswith(".csv") and "caf" in name]
    assert listed == [f"{drop}/caf\udce9.csv"]
    assert fs.info(listed[0])["size"] == 1
    assert fs.cat_file(listed[0]) == b"\xe9"
    with fs.open(listed[0], "rb") as handle:
        assert handle.read() == b"\xe9"


def test_ls_and_info_agree_about_a_symlink(fs, drop: str):
    """The incumbent's bug, named in D-60's recon and not reproduced here.

    Its ``ls`` reads READDIR's attributes, so a symlink is ``"link"``; its ``info`` calls
    ``stat``, which follows, so the same path is ``"file"`` -- while fsspec's own docstring
    says ``info`` returns "exactly the same information as ``ls``". Ours follows in both, so
    ``isfile`` on a symlinked parquet answers ``True`` and something will actually open it.
    """
    link = f"{drop}/latest.csv"
    from_listing = next(entry for entry in fs.ls(drop, detail=True) if entry["name"] == link)
    direct = fs.info(link)
    assert from_listing["type"] == direct["type"] == "file"
    assert from_listing["islink"] is True
    assert direct["islink"] is True
    assert from_listing["destination"] == direct["destination"] == f"{drop}/report.csv"
    assert fs.isfile(link)
    assert not fs.isdir(link)


def test_a_broken_symlink_is_reported_rather_than_skipped_or_raised(fs, drop: str, tree: Path):
    """The third state, decided rather than discovered.

    Dropping the entry would make a listing quietly disagree with the directory it describes;
    raising would let one dead link cost the whole listing. So the type is ``"other"`` -- which
    is honest, since the follow failed and nobody knows what it was -- with the target kept.
    """
    dangling = f"{drop}/dangling"
    entry = next(item for item in fs.ls(drop, detail=True) if item["name"] == dangling)
    assert entry["type"] == "other"
    assert entry["size"] is None
    assert entry["islink"] is True
    assert entry["destination"] == str(tree / "gone")
    assert fs.info(dangling) == entry


def test_listing_a_plain_file_returns_that_one_entry(fs, drop: str):
    """``LocalFileSystem``'s behaviour, and what ``find`` / ``glob`` / ``walk`` expect.

    It costs an extra round trip only on the failure path, because SFTP gives no way to tell
    the two apart up front: ``OPENDIR`` on a file answers ``NO_SUCH_FILE`` rather than a
    distinct status, since the server remaps ``ENOTDIR``.
    """
    assert fs.ls(f"{drop}/report.csv") == [f"{drop}/report.csv"]
    assert fs.ls(f"{drop}/report.csv", detail=True)[0]["type"] == "file"


def test_listing_something_absent_is_a_file_not_found(fs, drop: str):
    with pytest.raises(FileNotFoundError):
        _ = fs.ls(f"{drop}/nowhere")


def test_a_listing_carries_the_attributes_the_server_volunteered(fs, drop: str):
    entry = fs.info(f"{drop}/report.csv")
    assert entry["size"] == 14
    assert entry["type"] == "file"
    assert entry["mode"] & 0o777 == (Path(entry["name"]).stat().st_mode & 0o777)
    assert entry["uid"] == os.getuid()
    assert entry["mtime"] == int(Path(entry["name"]).stat().st_mtime)


def test_the_base_class_walkers_work_on_top_of_ls(fs, drop: str):
    """``find`` / ``glob`` / ``du`` are fsspec's, and they are what a consumer actually calls."""
    assert f"{drop}/archive/old.csv" in fs.find(drop)
    assert sorted(fs.glob(f"{drop}/*.csv")) == sorted(
        [f"{drop}/report.csv", f"{drop}/caf\udce9.csv", f"{drop}/latest.csv"]
    )
    assert fs.du(f"{drop}/report.csv") == 14


# --- bytes ----------------------------------------------------------------------------------


def test_a_whole_file_reads_back_byte_for_byte(fs, drop: str, tree: Path):
    expected = (tree / "incoming" / "big.bin").read_bytes()
    assert fs.cat_file(f"{drop}/big.bin") == expected
    with fs.open(f"{drop}/big.bin", "rb") as handle:
        assert handle.read() == expected


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (0, 2, b"id"),
        (3, 8, b"total"),
        (None, 2, b"id"),
        (9, None, b"1,42\n"),
        (-6, None, b"\n1,42\n"),
        (0, -8, b"id,tot"),
        (5, 5, b""),
        (100, 200, b""),
    ],
)
def test_byte_ranges_including_the_negative_ones(fs, drop: str, start, end, expected: bytes):
    assert fs.cat_file(f"{drop}/report.csv", start=start, end=end) == expected


# --- the range arithmetic, asked directly rather than through a server ----------------------
#
# `_range` is pure, and every case above reaches it through `cat_file` against a real
# `sftp-server` -- which always reports a size. So its whole sizeless branch, including the
# refusal and every word of that refusal's message, had never executed. Driving a pure function
# through the public name that calls it is also a filter: `cat_file` returns bytes, and two
# different (offset, length) pairs that read the same bytes are indistinguishable there.
#
# These are not hypothetical inputs. A server that answers `STAT` without
# `SSH_FILEXFER_ATTR_SIZE` is exactly what `Attrs`' own docstring is about -- absent is not
# zero -- and this library's rule is that every server response has three shapes.


def _sized(size: int | None) -> Attrs:
    return Attrs(size=size)


@pytest.mark.parametrize(("start", "end"), [(-1, None), (None, -1), (-2, -1)])
def test_a_negative_range_needs_a_size_to_measure_back_from(start, end):
    """The refusal, its message and the feature it carries -- none of which had run.

    `CapabilityError` carries `feature=` so a caller can branch on *what* is unsupported
    rather than on prose, which is the half that goes unread wherever the message is pinned.
    """
    with pytest.raises(CapabilityError) as exc:
        _ = _range(_sized(None), start, end)
    assert exc.value.args[0] == (
        "a negative range is measured back from the end of the file, and this server "
        "reported no size, so there is nothing to measure back from"
    )
    assert exc.value.feature == "a negative byte range"


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (None, None, (0, 1 << 40)),
        (0, None, (0, 1 << 40)),
        (0, 4, (0, 4)),
        (4, 8, (4, 4)),
        # Zero is not negative, and the guard reads `< 0` rather than `<= 0`. A bound of
        # exactly zero from a server that reported no size is an empty read, not a refusal.
        (0, 0, (0, 0)),
        (4, 0, (4, 0)),
    ],
)
def test_a_non_negative_range_does_not_need_a_size(start, end, expected):
    # The other side of the same guard: only a *negative* bound needs a size, so an ordinary
    # read from a server that reported none must still work.
    assert _range(_sized(None), start, end) == expected


def test_no_end_and_no_size_asks_for_everything_from_the_offset():
    # `begin + _UNBOUNDED`, where a minus sign asks for nothing at all and reads zero bytes
    # off a file whose size the server declined to give.
    begin, length = _range(_sized(None), 10, None)
    assert begin == 10
    assert length == 1 << 40


@pytest.mark.parametrize(
    ("size", "start", "end", "expected"),
    [
        # An explicit zero end is empty, not "the whole file measured back from the end".
        (10, 0, 0, (0, 0)),
        (10, 3, 0, (3, 0)),
        # A bound further back than the file is long clamps to the start, not past it.
        (4, -10, None, (0, 4)),
        (4, None, -10, (0, 0)),
        # An empty file the server *did* report the size of, which is not the same as no size.
        (0, -1, None, (0, 0)),
        (0, None, -1, (0, 0)),
    ],
)
def test_the_range_edges_that_a_whole_file_read_never_reaches(size, start, end, expected):
    assert _range(_sized(size), start, end) == expected


def test_reading_across_the_block_size_is_still_one_file(fs, drop: str, tree: Path):
    """The block cache asks for ranges; the point is that the seams are invisible.

    A small block size forces many ``_fetch_range`` calls over one held handle, which is the
    shape a parquet reader produces and the one an ``OPEN``/``CLOSE`` per block would make
    expensive.
    """
    expected = (tree / "incoming" / "big.bin").read_bytes()
    with fs.open(f"{drop}/big.bin", "rb", block_size=4096) as handle:
        assert handle.read(10) == expected[:10]
        _ = handle.seek(500_000)
        assert handle.read(1000) == expected[500_000:501_000]
        _ = handle.seek(0)
        assert handle.read() == expected


def test_a_read_past_the_end_is_empty_rather_than_an_error(fs, drop: str):
    with fs.open(f"{drop}/report.csv", "rb") as handle:
        _ = handle.seek(1000)
        assert handle.read(10) == b""


def test_writing_through_the_file_object_lands_the_bytes(fs, drop: str, tree: Path):
    with fs.open(f"{drop}/written.csv", "wb") as handle:
        _ = handle.write(b"id,total\n")
        _ = handle.write(b"7,99\n")
    assert (tree / "incoming" / "written.csv").read_bytes() == b"id,total\n7,99\n"


def test_a_written_file_is_not_world_readable(fs, drop: str, tree: Path):
    """``mode=0o600`` on OPEN is a security decision, not a default.

    Omitting the permission field lets the server apply ``0666 & ~umask``, and no later
    ``chmod`` closes the window in between.
    """
    with fs.open(f"{drop}/private.csv", "wb") as handle:
        _ = handle.write(b"secret\n")
    assert (tree / "incoming" / "private.csv").stat().st_mode & 0o077 == 0


def test_a_write_larger_than_the_block_size_is_reassembled_in_order(fs, drop: str, tree: Path):
    payload = bytes(range(256)) * 2048
    with fs.open(f"{drop}/blocks.bin", "wb", block_size=5 * 2**20) as handle:
        for offset in range(0, len(payload), 4096):
            _ = handle.write(payload[offset : offset + 4096])
    assert (tree / "incoming" / "blocks.bin").read_bytes() == payload


def test_the_handle_is_released_when_the_file_closes(fs, drop: str):
    handle = fs.open(f"{drop}/report.csv", "rb")
    _ = handle.read(4)
    assert handle._handle is not None  # noqa: SLF001
    handle.close()
    assert handle._handle is None  # noqa: SLF001


def test_get_file_and_put_file_use_this_librarys_transfer_path(fs, drop: str, tmp_path: Path):
    destination = tmp_path / "downloaded" / "report.csv"
    fs.get_file(f"{drop}/report.csv", destination)
    assert destination.read_bytes() == b"id,total\n1,42\n"

    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n5\n")
    fs.put_file(source, f"{drop}/uploaded.csv")
    assert fs.cat_file(f"{drop}/uploaded.csv") == b"id\n5\n"


def test_put_file_in_create_mode_refuses_an_existing_destination(fs, drop: str, tmp_path: Path):
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n5\n")
    with pytest.raises(FileExistsError) as exc:
        fs.put_file(source, f"{drop}/report.csv", mode="create")
    # The path the refusal is about, which is the only thing in it a caller can act on.
    assert exc.value.args[0] == f"{drop}/report.csv"
    assert fs.cat_file(f"{drop}/report.csv") == b"id,total\n1,42\n", "refused and wrote anyway"


# --- the fallback branch, which is a feature and had never run ------------------------------
#
# `get_file` and `put_file` hand back to `AbstractFileSystem` when there is no local *filename*
# to work with -- a file-like `lpath`, or an explicit `outfile`. That is deliberate: this
# library's transfer path places bytes with `os.pwrite` into a descriptor it opened itself, and
# there is nothing there to open. Every test above passes a real path, so the branch never
# executed and each of the six arguments it forwards was droppable in silence.


class _Recorder(fsspec.Callback):
    """An fsspec callback that records what it was told, for both transfer directions."""

    def __init__(self) -> None:
        super().__init__()
        self.size: int | None = None
        self.seen: list[tuple[int, int | None]] = []

    def set_size(self, size):  # type: ignore[no-untyped-def]
        self.size = size

    def absolute_update(self, value):  # type: ignore[no-untyped-def]
        self.seen.append((value, self.size))

    def relative_update(self, inc=1):  # type: ignore[no-untyped-def]
        previous = self.seen[-1][0] if self.seen else 0
        self.seen.append((previous + inc, self.size))


def test_an_explicit_outfile_hands_over_to_the_base_class(fs, drop: str, tmp_path: Path):
    """Every argument in the fallback call, on the one branch of it that a caller can reach.

    Three things are asserted because all three were droppable on their own: the bytes prove
    `rpath` and `outfile` arrived, the untouched `lpath` proves the `or` is an `or`, and the
    callback proves `callback=` survived `_or_default` -- which could hand back the no-op for a
    caller who supplied a real one, leaving a progress bar that silently never moves.

    With `and` in `outfile is not None or local is None`, a caller who passes both a filename
    and an `outfile` gets the *fast* path: the bytes land in the file they named, the stream
    they handed us stays empty, and nothing is raised to say so.
    """
    landing = tmp_path / "explicit-outfile.csv"
    unwanted = tmp_path / "should-not-be-written.csv"
    recorder = _Recorder()

    # A real file rather than a `BytesIO`, because fsspec's copy loop closes the stream it
    # was given and a closed `BytesIO` will not give its value back.
    with landing.open("wb") as sink:
        fs.get_file(f"{drop}/report.csv", str(unwanted), outfile=sink, callback=recorder)

    assert landing.read_bytes() == b"id,total\n1,42\n"
    assert not unwanted.exists(), "outfile was given and the bytes went to lpath anyway"
    assert recorder.seen, "the callback was dropped on the fallback path"


# --- D-134: a file-like local, which the ecosystem answers asymmetrically ------------------
#
# Measured against the pinned fsspec rather than reasoned about. `MemoryFileSystem`, which
# inherits `AbstractFileSystem.get_file`, raises `AttributeError: 'BytesIO' object has no
# attribute 'startswith'` on a file-like `lpath` -- the base class accepts one and then calls
# `_parent(lpath)` on the same object. `LocalFileSystem` overrides the method and works.
# Nothing anywhere accepts a file-like *source* for `put_file`: the base calls
# `os.path.isdir(lpath)` first, and `LocalFileSystem.put_file` hands straight to `cp_file`.
#
# So this adapter supports the download and refuses the upload, which is fsspec's own shape.
# The asymmetry is principled rather than convenient: a stream you write to needs no offsets;
# a stream you read from has no size, no seek and no second read -- verification rung 3,
# resume and retry.


def test_a_file_like_destination_is_written_into_rather_than_refused(fs, drop: str):
    """The spelling `LocalFileSystem` supports, so this adapter supports it too."""
    sink = io.BytesIO()
    recorder = _Recorder()
    fs.get_file(f"{drop}/report.csv", sink, callback=recorder)

    assert sink.getvalue() == b"id,total\n1,42\n"
    assert recorder.seen, "the callback never moved"
    assert recorder.size == len(b"id,total\n1,42\n"), "the size came from the open handle"


def test_a_file_like_destination_is_left_open(fs, drop: str):
    """The one place the two download destinations differ, and it is deliberate.

    fsspec's base class closes an `outfile` it was handed; `LocalFileSystem` does not close a
    file-like `lpath`. Both are matched rather than unified, because a caller writing into
    their own stream expects to keep writing to it -- and finding it closed is the kind of
    thing that surfaces three functions later.
    """
    sink = io.BytesIO()
    fs.get_file(f"{drop}/report.csv", sink)

    assert not sink.closed, "the caller's stream was closed under them"
    sink.write(b"appended\n")
    assert sink.getvalue().endswith(b"appended\n")


def test_a_download_into_a_stream_is_read_in_blocks_rather_than_whole(fs, drop, monkeypatch):
    """Both halves: the seams are invisible in the bytes, and the bound is what matters.

    `big.bin` is 1 MiB and the shipped block size is 4 MiB, so the loop only runs twice if the
    block size is cut. Content alone cannot tell the two apart -- `read(None)` reads to EOF and
    reassembles to exactly the same bytes -- so the *number* of blocks is asserted, through the
    callback, which gets one update per chunk. Reading to EOF here would pull the whole file
    into memory, which is the bound this path exists to keep.
    """
    monkeypatch.setattr(type(fs), "blocksize", 4096)
    expected = bytes(range(256)) * 4096
    sink = io.BytesIO()
    recorder = _Recorder()

    fs.get_file(f"{drop}/big.bin", sink, callback=recorder)

    assert sink.getvalue() == expected
    assert len(recorder.seen) == len(expected) // 4096, "the file was not read a block at a time"


def test_a_download_into_a_stream_names_a_missing_file(fs, drop: str):
    # `_translated(remote)` carries the path into the `FileNotFoundError` fsspec's callers
    # catch. This branch has its own call of it, so the path being nulled there is a separate
    # defect from the same thing on the whole-file path.
    with pytest.raises(FileNotFoundError) as exc:
        fs.get_file(f"{drop}/not-here.csv", io.BytesIO())
    assert exc.value.args[0] == f"{drop}/not-here.csv"


def test_a_download_destination_that_is_neither_a_path_nor_a_file_is_refused_by_name(fs, drop):
    """Refused here rather than handed to the base class to fail two frames down.

    fsspec recognises a file object by `read`, `close` and `tell` -- note `read`, on a write
    destination -- so a hand-rolled write-only object matches neither branch. The message says
    which three attributes and names the escape hatch, because "unsupported type" would send a
    reader looking for a supported one.
    """

    class WriteOnly:
        def write(self, chunk: bytes) -> int:
            return len(chunk)

    with pytest.raises(TypeError) as exc:
        fs.get_file(f"{drop}/report.csv", WriteOnly())
    assert exc.value.args[0] == (
        "a download destination must be a local path or an open binary file; WriteOnly is "
        "neither. fsspec recognises a file object by its read, close and tell attributes, so "
        "a write-only object needs all three -- or pass outfile=... alongside a path"
    )


def test_a_file_like_upload_source_is_refused_with_the_reason(fs, drop: str):
    """The other half, and the refusal has to carry *why* or it reads as an omission.

    No fsspec backend accepts one. What makes it a decision rather than a gap is the
    consequence: an upload from a stream could not be verified, resumed or retried, which is
    three of the guarantees `put` exists for.
    """
    with pytest.raises(TypeError) as exc:
        fs.put_file(io.BytesIO(b"id\n7\n"), f"{drop}/from-a-stream.csv")
    assert exc.value.args[0] == (
        "an upload source must be a local path; BytesIO is not one. A stream has no size, no "
        "seek and no second read, so it cannot be verified, resumed or retried, and no fsspec "
        "backend accepts one here either. Write the bytes to a file and upload that, or use "
        "pipe_file(path, value) for a value already in memory"
    )
    assert not fs.exists(f"{drop}/from-a-stream.csv"), "refused and uploaded anyway"


def test_the_upload_refusal_comes_before_the_server_is_asked_anything(fs, drop: str):
    # A malformed argument is reported as itself rather than as whatever the destination
    # happens to be: `mode="create"` onto an existing file would otherwise win the race to
    # raise, and the caller would fix the wrong thing.
    with pytest.raises(TypeError):
        fs.put_file(io.BytesIO(b"clobber"), f"{drop}/report.csv", mode="create")
    assert fs.cat_file(f"{drop}/report.csv") == b"id,total\n1,42\n"


# --- the local directories a download creates -----------------------------------------------


def test_downloading_a_directory_creates_it_with_its_parents(fs, drop: str, tmp_path: Path):
    # `parents=True` and `exist_ok=True` are both load-bearing and neither had a case: the
    # destination's parents do not exist here, and the second call finds the directory there.
    target = tmp_path / "nested" / "deeper" / "archive"
    fs.get_file(f"{drop}/archive", str(target))
    assert target.is_dir()

    fs.get_file(f"{drop}/archive", str(target))
    assert target.is_dir()


def test_downloading_a_file_creates_the_local_parents(fs, drop: str, tmp_path: Path):
    """A caller writing `fs.get(url, "out/2026/report.csv")` gets the base class's behaviour.

    Two calls, because `exist_ok` only matters on the second: the first creates the tree and
    the second finds it, which is the ordinary shape of a job that runs more than once.
    """
    target = tmp_path / "out" / "2026" / "report.csv"
    fs.get_file(f"{drop}/report.csv", str(target))
    assert target.read_bytes() == b"id,total\n1,42\n"

    fs.get_file(f"{drop}/report.csv", str(target))
    assert target.read_bytes() == b"id,total\n1,42\n"


def test_a_download_of_a_missing_file_names_that_file(fs, drop: str, tmp_path: Path):
    # `_translated(remote)` carries the path into the `FileNotFoundError` fsspec's callers
    # catch; with the argument nulled the error names nothing and the chain is all that is
    # left. fsspec's contract is the exception type; a usable message is ours.
    with pytest.raises(FileNotFoundError) as exc:
        fs.get_file(f"{drop}/not-here.csv", str(tmp_path / "out.csv"))
    assert exc.value.args[0] == f"{drop}/not-here.csv"


def test_a_progress_callback_is_bridged_rather_than_dropped(fs, drop: str, tmp_path: Path):
    """A dropped callback is a progress bar that silently never moves.

    fsspec's callback is incremental with the size set once; this library's is absolute. The
    bridge sets the size and then uses ``absolute_update``, which is the one call that cannot
    double-count when a range is retried.
    """
    seen: list[tuple[int, int | None]] = []

    class Recorder(fsspec.Callback):
        def set_size(self, size):
            self.size = size

        def absolute_update(self, value):
            seen.append((value, self.size))

    fs.get_file(f"{drop}/report.csv", tmp_path / "out.csv", callback=Recorder())
    assert seen, "the callback was never called"
    assert seen[-1] == (14, 14)


def test_a_local_path_that_is_byte_flavoured_is_refused_by_name(fs, drop: str):
    """D-96's rule, applied at this boundary too.

    A silent ``os.fsdecode`` here would be guessing an encoding for a name on this machine,
    which is the same class of defect as coercing a ``Path`` onto the wire.
    """

    class BytesPath:
        def __fspath__(self) -> bytes:
            return b"/tmp/out.csv"

    with pytest.raises(TypeError) as exc:
        fs.get_file(f"{drop}/report.csv", BytesPath())
    assert exc.value.args[0] == (
        "a local path must be a str or a pathlib.Path; BytesPath describes itself with bytes, "
        "and decoding it here would be guessing an encoding for a name on this machine"
    )


# --- namespace ------------------------------------------------------------------------------


def test_mkdir_makedirs_rmdir_and_rm(fs, drop: str, tree: Path):
    fs.mkdir(f"{drop}/new/deep")
    assert (tree / "incoming" / "new" / "deep").is_dir()
    fs.makedirs(f"{drop}/new/deep", exist_ok=True)
    with pytest.raises(FileExistsError):
        fs.makedirs(f"{drop}/new/deep")
    fs.rmdir(f"{drop}/new/deep")
    assert not (tree / "incoming" / "new" / "deep").exists()
    fs.rm(f"{drop}/report.csv")
    assert not (tree / "incoming" / "report.csv").exists()


def test_removing_a_symlink_unlinks_the_link_and_not_its_target(fs, drop: str, tree: Path):
    fs.rm(f"{drop}/latest.csv")
    assert not (tree / "incoming" / "latest.csv").exists()
    assert (tree / "incoming" / "report.csv").exists(), "the target went with the link"


def test_mv_is_a_rename_rather_than_a_copy_and_a_delete(fs, drop: str, tree: Path):
    before = (tree / "incoming" / "report.csv").stat().st_ino
    fs.mv(f"{drop}/report.csv", f"{drop}/archive/report.csv")
    assert (tree / "incoming" / "archive" / "report.csv").stat().st_ino == before
    assert not (tree / "incoming" / "report.csv").exists()


def test_mv_refuses_maxdepth_rather_than_ignoring_it(fs, drop: str):
    """Accepted-and-ignored is the failure: the tree moves and the caller is told it worked."""
    with pytest.raises(ValueError) as exc:
        fs.mv(f"{drop}/archive", f"{drop}/archived", maxdepth=1)
    assert exc.value.args[0] == (
        "maxdepth is not meaningful for a server-side rename: RENAME moves a directory and "
        "everything under it in one operation, so there is no depth to limit. Copy and delete "
        "explicitly if a partial move is what you meant"
    )


# --- timestamps -----------------------------------------------------------------------------


def test_modified_is_an_aware_utc_datetime(fs, drop: str, tree: Path):
    when = fs.modified(f"{drop}/report.csv")
    assert when.tzinfo is not None
    assert when.timestamp() == int((tree / "incoming" / "report.csv").stat().st_mtime)


def test_modified_on_something_absent_is_a_file_not_found(fs, drop: str):
    with pytest.raises(FileNotFoundError):
        _ = fs.modified(f"{drop}/nowhere.csv")


def test_created_refuses_because_v3_has_no_creation_time(fs, drop: str):
    """Refused rather than answered with the modification time under a second name."""
    with pytest.raises(CapabilityError) as exc:
        _ = fs.created(f"{drop}/report.csv")
    assert exc.value.feature == "created()"
    assert exc.value.args[0] == (
        f"SFTP v3 has no creation time: an ATTRS carries size, uid/gid, permissions and "
        f"atime/mtime only, so '{drop}/report.csv' has no created timestamp to report"
    )


# --- the extra ------------------------------------------------------------------------------


def test_importing_the_adapter_without_fsspec_names_the_extra():
    """The import error a user actually hits, proven in a process where fsspec is unimportable.

    A bare ``ModuleNotFoundError: No module named 'fsspec'`` tells a reader nothing about how
    this library is packaged. The subprocess blocks the import rather than uninstalling
    anything, so the check costs nothing and cannot corrupt the environment.
    """
    program = (
        "import sys\n"
        "class Block:\n"
        "    def find_module(self, name, path=None):\n"
        "        return self if name == 'fsspec' or name.startswith('fsspec.') else None\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'fsspec' or name.startswith('fsspec.'):\n"
        '            raise ModuleNotFoundError(f"No module named {name!r}", name=name)\n'
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "for name in [n for n in sys.modules if n == 'fsspec' or n.startswith('fsspec.')]:\n"
        "    del sys.modules[name]\n"
        "try:\n"
        "    import gantry_sftp.fsspec\n"
        "except ModuleNotFoundError as exc:\n"
        "    print(exc.args[0])\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    assert result.stdout.strip() == (
        "gantry_sftp.fsspec needs fsspec, which is an optional dependency of this library: "
        "install it with `pip install gantry-sftp[fsspec]` (or `uv add gantry-sftp[fsspec]`). "
        "Nothing else in gantry_sftp requires it."
    )


def test_the_extra_is_declared_and_its_floor_is_the_version_probed():
    """The extra exists and pins a floor, because the adapter reads fsspec internals."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.optional-dependencies]" in text
    assert 'fsspec = [\n    "fsspec>=' in text
    assert fsspec.__version__ >= "2026.7.0"


# --- the integration a consumer actually performs -------------------------------------------


def test_a_url_opens_end_to_end_through_fsspecs_own_entry_points(tree: Path, drop: str):
    """What ``pd.read_parquet(url)`` does underneath, without needing pandas installed.

    pandas, pyarrow and dask all reach a remote file the same way -- resolve the protocol, get
    a filesystem, open a file object -- so exercising ``url_to_fs`` and ``fsspec.open`` on a
    registered URL is the claim in DESIGN 8, and it is the part that would break if the
    registration, the URL form or the file object were wrong.

    The instance is left in fsspec's cache on purpose so that both calls resolve to the *same*
    filesystem: that is what a consumer's repeated URL use does, and it is the only way one
    ``close`` at the end is enough.
    """
    register_implementation(LocalGantryFS.protocol, LocalGantryFS, clobber=True)
    url = f"gantry-sftp-local://local{drop}/report.csv"
    filesystem, path = fsspec.core.url_to_fs(url, root=str(tree))
    try:
        assert isinstance(filesystem, LocalGantryFS)
        assert path == f"{drop}/report.csv"
        with fsspec.open(url, "rb", root=str(tree)) as handle:
            assert handle.read() == b"id,total\n1,42\n"
        assert fsspec.open(url, "rb", root=str(tree)).fs is filesystem
        assert fsspec.get_filesystem_class(LocalGantryFS.protocol) is LocalGantryFS
    finally:
        filesystem.close()
        LocalGantryFS._cache.clear()  # noqa: SLF001


def test_the_file_object_is_ours_rather_than_a_paramiko_one(fs, drop: str):
    with fs.open(f"{drop}/report.csv", "rb") as handle:
        assert isinstance(handle, GantrySFTPFile)


# --- D-135: the errors name the path, at every site that raises them --------------------------
#
# `_translated(remote)` appears eight times in this module and each one is a separate call with
# its own argument. Nulled, the `FileNotFoundError` fsspec's callers catch names nothing -- and
# fsspec's *contract* is only the exception type, so a usable message is entirely ours.
#
# One case per site rather than one for the helper: "count the sites by what they do, not by
# their name" is this register's own rule, and eight callers of one helper are eight places the
# argument can be dropped.


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        ("cat_file", ()),
        ("_rm", ()),
        ("modified", ()),
        ("info", ()),
        ("ls", ()),
    ],
)
def test_an_operation_on_a_missing_path_names_that_path(fs, drop: str, operation, arguments):
    missing = f"{drop}/not-here.csv"
    with pytest.raises(FileNotFoundError) as exc:
        getattr(fs, operation)(missing, *arguments)
    assert exc.value.args[0] == missing


def test_moving_a_missing_path_names_it(fs, drop: str):
    with pytest.raises(FileNotFoundError) as exc:
        fs.mv(f"{drop}/not-here.csv", f"{drop}/elsewhere.csv")
    assert exc.value.args[0] == f"{drop}/not-here.csv"


# --- the symlink rules, where following one is the whole difference ---------------------------


def test_removing_a_symlink_removes_the_link_and_not_its_target(fs, drop: str, tree: Path):
    """`isdir(follow_symlinks=False)` and `remove`, not `rmdir` on what it points at.

    `latest.csv` points at `report.csv`. Followed, an `rm` of the link would be an `rm` of the
    file -- silent data loss of exactly the shape a drop directory is the scene of.
    """
    fs._rm(f"{drop}/latest.csv")  # noqa: SLF001

    assert not (tree / "incoming" / "latest.csv").is_symlink()
    assert (tree / "incoming" / "report.csv").read_bytes() == b"id,total\n1,42\n"


def test_removing_a_symlink_to_a_directory_unlinks_it_rather_than_removing_the_directory(
    fs, drop: str, tree: Path
):
    # `isdir` following the link would route this to `rmdir`, which refuses a symlink -- and on
    # a server where it did not, would take the directory's contents with it.
    (tree / "incoming" / "to-archive").symlink_to(tree / "incoming" / "archive")

    fs._rm(f"{drop}/to-archive")  # noqa: SLF001

    assert not (tree / "incoming" / "to-archive").exists(follow_symlinks=False)
    assert (tree / "incoming" / "archive" / "old.csv").exists(), "the target directory went too"


def test_a_dangling_symlink_counts_as_occupying_its_name(fs, drop: str):
    """`_occupied` asks with `follow_symlinks=False`, and a dangling link is the case.

    A name holding a broken symlink *is* taken -- `mkdir` there fails -- so a check that
    followed the link would report the name free and turn a `FileExistsError` into whatever
    the server says instead.
    """
    assert fs._occupied(f"{drop}/dangling") is True  # noqa: SLF001
    assert fs._occupied(f"{drop}/report.csv") is True  # noqa: SLF001
    assert fs._occupied(f"{drop}/not-here.csv") is False  # noqa: SLF001


def test_making_a_directory_where_a_dangling_symlink_sits_says_it_exists(fs, drop: str):
    # The two halves of `_creating` together: the server refuses, `_occupied` says the name is
    # taken, and the refusal becomes the `FileExistsError` fsspec's callers expect.
    with pytest.raises(FileExistsError) as exc:
        fs.mkdir(f"{drop}/dangling", create_parents=False)
    assert exc.value.args[0] == f"{drop}/dangling"


# --- directories, and the flags that decide whether an existing one is an error ---------------


def test_mkdir_with_parents_tolerates_a_directory_that_is_already_there(fs, drop: str):
    # `exist_ok=True` on the `makedirs` branch: fsspec's `mkdir(create_parents=True)` is
    # `os.makedirs`-shaped, and a second call must not raise.
    fs.mkdir(f"{drop}/new/deep", create_parents=True)
    fs.mkdir(f"{drop}/new/deep", create_parents=True)
    assert fs.isdir(f"{drop}/new/deep")


def test_mkdir_without_parents_refuses_a_directory_that_is_already_there(fs, drop: str):
    # And the other branch does *not* tolerate it, which is what `create_parents` selects.
    with pytest.raises(FileExistsError):
        fs.mkdir(f"{drop}/archive", create_parents=False)


def test_uploading_a_local_directory_creates_the_remote_one(fs, drop: str, tmp_path: Path):
    """`put_file` on a directory is a `makedirs`, and `exist_ok=True` makes it repeatable.

    An upload loop that walks a tree calls this once per directory, and the second run of the
    same job hits every one of them again.
    """
    (tmp_path / "batch").mkdir()
    fs.put_file(tmp_path / "batch", f"{drop}/batch")
    fs.put_file(tmp_path / "batch", f"{drop}/batch")
    assert fs.isdir(f"{drop}/batch")


def test_uploading_creates_the_remote_parent(fs, drop: str, tmp_path: Path):
    # The parent of the *destination*, so `fs.put_file(x, url + "/2026/report.csv")` works the
    # way the same call does on every other fsspec backend.
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n9\n")
    fs.put_file(source, f"{drop}/2026/q1/report.csv")
    assert fs.cat_file(f"{drop}/2026/q1/report.csv") == b"id\n9\n"


def test_an_upload_reports_progress_through_the_bridge(fs, drop: str, tmp_path: Path):
    # `progress=_bridge(callback)` on the fast path, which is a different call site from
    # `get_file`'s and had nothing reading it.
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n5\n" * 100)
    recorder = _Recorder()

    fs.put_file(source, f"{drop}/watched.csv", callback=recorder)

    assert recorder.seen, "the callback never moved on the upload path"
    assert recorder.seen[-1][0] == source.stat().st_size


# --- the file object, and the fields a listing carries ----------------------------------------


def test_opening_a_file_forwards_the_block_size_and_the_caching_it_was_given(fs, drop: str):
    """Four arguments handed to `GantrySFTPFile`, each droppable on its own.

    `block_size` is the one with teeth: dropped, every read of a parquet footer falls back to
    the class default, and the round-trip count a caller tuned for goes with it.
    """
    handle = fs._open(  # noqa: SLF001
        f"{drop}/big.bin",
        block_size=4096,
        autocommit=False,
        cache_options={"trim": False},
        cache_type="bytes",
    )
    try:
        assert handle.blocksize == 4096
        assert handle.mode == "rb"
        # Non-default throughout: `autocommit` defaults to `True` and `cache_options` to `None`,
        # so an argument dropped here is invisible to any call that passes the default.
        assert handle.autocommit is False
        assert handle.cache.trim is False
        assert handle.read(4) == bytes(range(256))[:4]
    finally:
        handle.close()


def test_a_listing_carries_the_owner_and_the_times_under_the_names_fsspec_uses(fs, drop: str):
    """`uid`/`gid` and `mtime`/`time`, which are four separate assignments to one dict.

    A key that changes case is a key nothing reads, and a value crossed onto its neighbour
    reports the group as the owner. `time` is fsspec's name for the *access* time -- ours is
    `atime` -- and conflating the two is what a swap here looks like.
    """
    entry = fs.info(f"{drop}/report.csv")

    assert entry["uid"] == os.getuid()
    assert entry["gid"] == os.getgid()
    assert entry["mtime"] == pytest.approx(
        (tree_path := Path(entry["name"])).stat().st_mtime, abs=1
    )
    assert entry["time"] == pytest.approx(tree_path.stat().st_atime, abs=1)
    assert entry["size"] == tree_path.stat().st_size


def test_a_buffered_write_accumulates_across_chunks(fs, drop: str):
    """`self._written += written`, where `=` reports only the last chunk and `-=` counts down.

    fsspec's buffered file flushes whenever the buffer fills, so a write larger than the block
    size arrives as several `_upload_chunk` calls -- and the running total is what the last one
    checks against the size it promised.
    """
    chunks = [bytes([ordinal]) * 20_000 for ordinal in b"abc"]
    with fs.open(f"{drop}/streamed.csv", "wb", block_size=4096) as handle:
        for chunk in chunks:
            # One `write` per chunk, because fsspec flushes the *whole* buffer rather than
            # block-sized pieces of it -- a single large write is one `_upload_chunk` call and
            # cannot see an offset that fails to accumulate.
            _ = handle.write(chunk)

    assert fs.cat_file(f"{drop}/streamed.csv") == b"".join(chunks)
    assert fs.info(f"{drop}/streamed.csv")["size"] == sum(len(c) for c in chunks)


def test_a_buffered_write_of_nothing_still_creates_the_file(fs, drop: str):
    # `payload.nbytes and self._handle is not None` -- an `or` there writes an empty payload
    # through a handle that may not exist yet, and the guard is what makes a zero-byte upload
    # land as a zero-byte file rather than as an error.
    with fs.open(f"{drop}/empty.csv", "wb") as handle:
        _ = handle.write(b"")

    assert fs.cat_file(f"{drop}/empty.csv") == b""
    assert fs.info(f"{drop}/empty.csv")["size"] == 0


# --- the last of it: names, ranges, and registration ------------------------------------------


def test_a_path_that_is_not_valid_utf8_survives_the_round_trip(fs, drop: str, tree: Path):
    """`surrogateescape` both ways, which is the only thing that makes such a name operable.

    `_encode` is the inverse of the decode every listing goes through. Strict, it raises on a
    name the server just handed us; any other handler, and the bytes that go back out are not
    the bytes that came in -- so the file cannot be opened, moved or deleted by this client at
    all. Ordinary on Linux, and the axis this suite has to vary along.
    """
    listed = [name for name in fs.ls(drop) if "caf" in name]
    assert listed, "the fixture's non-UTF-8 name did not survive listing"

    (odd,) = listed
    assert fs.cat_file(odd) == b"\xe9"
    # Round-tripped through *our* encoder rather than compared to a literal: what is asserted is
    # that what we send equals what the filesystem holds.
    assert Path(os.fsdecode(gantry_fsspec._encode(odd))).read_bytes() == b"\xe9"  # noqa: SLF001


def test_a_zero_length_range_asks_the_server_for_nothing(fs, drop: str):
    """`end <= start` is empty, and `<` would send a zero-length READ instead of short-circuiting.

    A zero-length READ is legal and answers with empty DATA, so the bytes are right either way
    -- what changes is a round trip per call, on the path a block cache uses most.
    """
    with fs.open(f"{drop}/report.csv", "rb") as handle:
        before = fs.sftp.requests_sent
        assert handle._fetch_range(5, 5) == b""  # noqa: SLF001
        assert fs.sftp.requests_sent == before, "an empty range still went to the server"


def test_a_range_asks_for_the_length_it_was_given(fs, drop: str):
    # `end - start`, where `+` asks for a length that runs past the end of the file -- which a
    # server clamps, so the bytes look right and only the request is wrong.
    with fs.open(f"{drop}/report.csv", "rb") as handle:
        assert handle._fetch_range(3, 8) == b"total"  # noqa: SLF001


def test_registration_replaces_a_protocol_that_is_already_resolved(monkeypatch):
    """`clobber=True`, which is what makes `override=True` mean anything.

    fsspec's `register_implementation` defaults to `clobber=False` and then *raises* when the
    protocol is already in the live registry -- so without this the deliberate override would
    fail with fsspec's error rather than doing what the caller asked, and only after they had
    already read the warning and decided.
    """
    register("gantry-sftp")
    # Registering the same name a second time is what a caller doing `register(override=True)`
    # in a module imported twice looks like, and it must not raise.
    register("gantry-sftp")
    assert registry.get("gantry-sftp") is GantrySFTPFileSystem


def test_the_incumbent_check_reads_the_class_key_fsspec_actually_uses(monkeypatch):
    # `known_implementations` maps a protocol to a dict whose `"class"` entry is the import
    # path. Read under any other key it is always `None`, so every protocol looks unclaimed and
    # the refusal that protects `sftp://` never fires.
    assert known_implementations["sftp"]["class"] == ("fsspec.implementations.sftp.SFTPFileSystem")
    with pytest.raises(ValueError) as exc:
        register("sftp")
    assert "already registered to" in exc.value.args[0]


# --- what a v3 ATTRS cannot carry, and the refusals that say so ------------------------------


def test_a_server_that_sends_no_modification_time_is_refused_with_the_reason(fs, drop, monkeypatch):
    """Every field in a v3 ATTRS is optional, so `getmtime` answering `None` is a real state.

    `sftp-server` always sends one, which is why nothing here had ever reached this branch --
    the whole refusal, its `feature`, its `path` and its message were free. `modified()` is on
    `AbstractFileSystem`'s contract, so the alternative to refusing is returning a timestamp
    nobody sent.
    """
    monkeypatch.setattr(type(fs.sftp), "getmtime", lambda _self, _path: None)

    with pytest.raises(CapabilityError) as exc:
        fs.modified(f"{drop}/report.csv")

    assert exc.value.args[0] == (
        f"the server sent no modification time for '{drop}/report.csv', so there is none to "
        f"report -- every field in an SFTP v3 ATTRS is optional"
    )
    assert exc.value.feature == "modified()"
    assert exc.value.path == f"{drop}/report.csv".encode()


def test_there_is_no_creation_time_in_the_protocol_at_all(fs, drop: str):
    """`created()` refuses unconditionally, and the refusal has to say why rather than how.

    v3's ATTRS carries size, uid/gid, permissions and atime/mtime -- there is no creation time
    to report from any server, so this is a statement about the protocol rather than about this
    one. The `path` is carried anyway, because a caller walking a tree needs to know which
    entry it gave up on.
    """
    with pytest.raises(CapabilityError) as exc:
        fs.created(f"{drop}/report.csv")

    assert exc.value.args[0] == (
        f"SFTP v3 has no creation time: an ATTRS carries size, uid/gid, permissions and "
        f"atime/mtime only, so '{drop}/report.csv' has no created timestamp to report"
    )
    assert exc.value.feature == "created()"
    assert exc.value.path == f"{drop}/report.csv".encode()


def test_an_entry_the_server_did_not_describe_is_other_rather_than_a_guess(fs, drop, monkeypatch):
    """`"other"` is fsspec's third word, and it carries "the server did not say".

    A v3 server need not send permission bits at all, and `S_ISDIR(None)` is a `TypeError` on
    the incumbent. Here the entry is reported, typed as far as it can be, and the type is the
    one fsspec's own vocabulary has for "neither file nor directory".
    """
    monkeypatch.setattr(type(fs.sftp), "lstat", lambda _self, _path: Attrs())

    entry = fs.info(f"{drop}/report.csv")
    assert entry["type"] == "other"
    assert entry["name"] == f"{drop}/report.csv"


def test_uploading_to_a_path_with_no_parent_does_not_try_to_create_one(fs, monkeypatch, tmp_path):
    """`parent and parent != remote`, where an `or` makes a root-level destination self-creating.

    `_parent("/x")` is `"/"`, and `_parent("/")` is `"/"` again -- so the guard's second half is
    what stops a destination at the root asking the server to create the root, and the first
    half is what stops an empty parent doing the same.
    """
    asked: list[str] = []
    monkeypatch.setattr(type(fs.sftp), "makedirs", lambda _self, path, **_k: asked.append(path))
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n1\n")

    fs.put_file(source, str(tmp_path / "at-the-top.csv"))

    assert asked == [str(tmp_path)], f"asked to create something odd: {asked}"


def test_the_default_upload_mode_is_overwrite(fs, drop: str, tmp_path: Path):
    # The default is what a caller who says nothing gets, and it is the *permissive* one -- so
    # a default of anything else turns every ordinary `put_file` into a refusal.
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"replaced\n")
    fs.put_file(source, f"{drop}/report.csv")
    assert fs.cat_file(f"{drop}/report.csv") == b"replaced\n"


def test_an_upload_that_the_server_refuses_names_the_destination(fs, drop, monkeypatch, tmp_path):
    """`put_file`'s own `_translated(remote)`, which is its eighth call site.

    Reached by making the transfer itself fail rather than the directory work above it: an
    ordinary refusal on the way in is a `FAILURE`, which this boundary deliberately does *not*
    translate, so the branch needs a `NoSuchFileError` to travel through it.
    """
    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n1\n")

    def refuse(_self, _local, remote, **_kwargs):  # type: ignore[no-untyped-def]
        raise NoSuchFileError("gone", code=2, path=remote)

    monkeypatch.setattr(type(fs.sftp), "put", refuse)

    with pytest.raises(FileNotFoundError) as exc:
        fs.put_file(source, f"{drop}/vanished.csv")
    assert exc.value.args[0] == f"{drop}/vanished.csv"


def test_uploading_to_the_root_does_not_ask_the_server_to_create_it(fs, monkeypatch, tmp_path):
    """`parent != remote`, which only a destination whose parent is itself can separate.

    `_parent("/x")` is `"/"` and `_parent("/")` is `"/"` again, so at the root the two are
    equal -- and an `or` there turns "skip, there is nothing above this" into `makedirs("/")`,
    which on a strict server is a refusal on every upload to a top-level name.
    """
    asked: list[str] = []
    monkeypatch.setattr(type(fs.sftp), "makedirs", lambda _s, path, **_k: asked.append(path))
    monkeypatch.setattr(type(fs.sftp), "put", lambda _s, *_a, **_k: None)

    fs.put_file(tmp_path / "x.csv", "/")

    assert asked == [], f"asked to create the root: {asked}"


def test_registering_our_own_protocol_twice_is_not_a_takeover(monkeypatch):
    """`known.get("class")`, read under the key fsspec actually uses.

    Under any other key the answer is always `None`, every protocol looks like somebody else's,
    and re-registering our *own* name raises as though it were a takeover -- which is what a
    module imported twice does.
    """
    monkeypatch.setitem(
        known_implementations,
        PROTOCOL,
        {"class": f"gantry_sftp.fsspec.{GantrySFTPFileSystem.__name__}"},
    )
    register(PROTOCOL)
    assert registry.get(PROTOCOL) is GantrySFTPFileSystem


def test_an_override_replaces_a_protocol_that_is_already_resolved():
    """`clobber=True`, without which the deliberate override fails with fsspec's own error.

    `register_implementation` defaults to `clobber=False` and *raises* when the protocol is
    already live in the registry -- so `override=True` would print the warning, get the
    caller's decision, and then not carry it out.

    The incumbent is a stand-in rather than the real one, and that is not a shortcut.
    `fsspec.get_filesystem_class("sftp")` *imports* fsspec's built-in implementation, which
    raises `ImportError: SFTPFileSystem requires "paramiko" to be installed` -- and paramiko is
    in the `bench` group, which the default lane deliberately does not install. So this test
    passed only on a machine where somebody had run `uv sync --group bench` at some point, and
    failed in the lane CI actually runs (DoD 1: control the environment a test depends on).
    Nothing here is about paramiko: what is under test is that a name already live in
    ``registry`` is replaced rather than raising, and any class standing in it proves that.
    """
    register_implementation("sftp", GantrySFTPFile, clobber=True)
    assert registry.get("sftp") is not GantrySFTPFileSystem

    register("sftp", override=True)
    assert registry.get("sftp") is GantrySFTPFileSystem


# --- D-135, the tail: guards, keys and the round trips they decide ---------------------------


@pytest.mark.parametrize("url", ["gantry-sftp://h/x?cwd=", "gantry-sftp://h/x?user="])
def test_a_query_parameter_with_an_empty_value_is_kept_rather_than_dropped(url: str):
    """`keep_blank_values=True`, without which `?cwd=` vanishes instead of meaning something.

    `parse_qsl` drops empty values by default, so the parameter would not appear at all --
    which is not the same as being rejected. An unknown parameter is refused loudly here, so a
    silently *dropped* one is the single shape this module's parsing is written to prevent.
    """
    key = url.rsplit("?", 1)[1].rstrip("=")
    kwargs = GantrySFTPFileSystem._get_kwargs_from_urls(url)  # noqa: SLF001
    assert key in kwargs or key in _SESSION_KEYS
    if key in kwargs:
        assert kwargs[key] == ""


def test_a_listing_says_whether_each_entry_is_a_link(fs, drop: str):
    # `islink` is a separate key from `type`, as it is in fsspec's own LocalFileSystem, and it
    # is seeded `False` and set `True` only on the symlink branch -- so both the key's spelling
    # and its seed matter, and a listing where everything is a link is as wrong as one where
    # nothing is.
    entries = {entry["name"]: entry for entry in fs.ls(drop, detail=True)}

    assert entries[f"{drop}/report.csv"]["islink"] is False
    assert entries[f"{drop}/latest.csv"]["islink"] is True
    assert entries[f"{drop}/archive"]["islink"] is False


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("gantry-sftp://h/incoming/", "/incoming"),
        ("gantry-sftp://h/incoming//", "/incoming"),
        ("gantry-sftp://h/", "/"),
        # `rstrip` takes a character *set*, not a suffix: any other string strips its letters
        # too, and a remote name ending in one of them loses it.
        ("gantry-sftp://h/incomingX", "/incomingX"),
    ],
)
def test_a_url_path_keeps_every_character_that_is_not_a_trailing_slash(given: str, expected: str):
    assert GantrySFTPFileSystem._strip_protocol(given) == expected  # noqa: SLF001


def test_a_path_that_is_not_a_string_is_the_root(fs):
    """`not isinstance(text, str) or not text`, where an `and` needs *both* to be wrong.

    fsspec calls `_strip_protocol` with whatever a caller passed, and `infer_storage_options`
    can hand back something that is not a path at all. With `and`, an empty string falls
    through to `rstrip` and the root marker is never reached.
    """
    assert GantrySFTPFileSystem._strip_protocol("") == "/"  # noqa: SLF001
    assert GantrySFTPFileSystem._strip_protocol("gantry-sftp://h") == "/"  # noqa: SLF001


def test_a_name_the_server_refuses_to_stat_is_not_occupied(fs, drop, monkeypatch):
    """`_occupied`'s `except SFTPError: return False`, which decides what a refusal means.

    Returning `True` there turns every unreadable name into "already exists", so a `mkdir`
    that failed for a reason the server did not explain is reported as a `FileExistsError` --
    sending the caller to delete something that may not be there.
    """

    def refuse(_self, _path, **_kwargs):
        raise ServerError("no", code=4)

    monkeypatch.setattr(type(fs.sftp), "exists", refuse)
    assert fs._occupied(f"{drop}/report.csv") is False  # noqa: SLF001


def test_reading_an_empty_range_costs_no_round_trip(fs, drop: str):
    # `length <= 0` short-circuits; `< 0` sends a zero-length READ, which is legal and answers
    # with empty DATA -- so the bytes agree and only the request count does not.
    before = fs.sftp.requests_sent
    assert fs.cat_file(f"{drop}/report.csv", start=4, end=4) == b""
    # One OPEN, one FSTAT, one CLOSE -- and no READ.
    assert fs.sftp.requests_sent - before == 3


def test_a_progress_bridge_sets_the_size_once_however_many_chunks_arrive(fs, drop, tmp_path):
    """`sized.add(total)`, where adding `None` makes the guard match nothing.

    fsspec's callback is incremental with the size set *once*; this library's is absolute. The
    bridge remembers which totals it has announced, and remembering the wrong thing means
    `set_size` fires on every chunk -- which resets a progress bar to the start each time.
    """
    sizes: list[int | None] = []

    class _CountingSize(_Recorder):
        def set_size(self, size):  # type: ignore[no-untyped-def]
            sizes.append(size)
            super().set_size(size)

    source = tmp_path / "big-upload.bin"
    _ = source.write_bytes(b"x" * 400_000)
    fs.put_file(source, f"{drop}/big-upload.bin", callback=_CountingSize())

    assert len(sizes) == 1, f"the size was announced {len(sizes)} times"


def test_closing_a_filesystem_that_never_connected_does_nothing(tree: Path):
    """`_stack` and `_owner_pid` start as `None`, and `close()` reads both.

    Seeded to anything else that is not `None`, `close()` on an instance nobody used tries to
    unwind a stack that does not exist -- and merely *resolving* a URL constructs one of these,
    so an unused instance is the common case rather than the odd one.
    """
    filesystem = LocalGantryFS(str(tree), skip_instance_cache=True)
    assert filesystem._stack is None  # noqa: SLF001
    assert filesystem._owner_pid is None  # noqa: SLF001
    filesystem.close()  # must not raise


def test_closing_a_file_twice_closes_the_handle_once(fs, drop: str):
    """`already = self.closed`, read *before* the base class closes anything.

    The handle is released in a `finally`, so the second `close()` reaches it too -- and
    `already` is the only thing that stops a second `CLOSE` going out for a handle the server
    has already forgotten. Reading it after `super().close()` would make it always `True` and
    leak the handle instead.
    """
    handle = fs.open(f"{drop}/report.csv", "rb")
    assert handle.read(2) == b"id"

    before = fs.sftp.requests_sent
    handle.close()
    after_first = fs.sftp.requests_sent
    handle.close()

    assert after_first > before, "the handle was never closed"
    assert fs.sftp.requests_sent == after_first, "a second CLOSE went out for a closed handle"


def test_reading_a_file_that_vanished_names_it(fs, drop: str, tree: Path):
    # `_read_handle`'s own `_translated(self._remote)`, which is a different call site from
    # `cat_file`'s: the file object opens lazily, so the failure arrives on the first *read*.
    handle = fs.open(f"{drop}/report.csv", "rb")
    try:
        (tree / "incoming" / "report.csv").unlink()
        with pytest.raises(FileNotFoundError) as exc:
            _ = handle.read(4)
        assert exc.value.args[0] == f"{drop}/report.csv"
    finally:
        handle.close()


def test_a_path_like_local_object_is_accepted_and_becomes_a_path(fs, drop: str, tmp_path: Path):
    """`_local_path` returns `Path(resolved)`, and `__fspath__` is the third accepted spelling.

    A `str` and a `Path` are the obvious two; anything implementing `__fspath__` is the one
    nothing exercised, and it is what a caller passes when they wrap paths in a type of their
    own. `Path(None)` would refuse every one of them.
    """

    class Wrapped:
        def __init__(self, where: Path) -> None:
            self._where = where

        def __fspath__(self) -> str:
            return str(self._where)

    destination = tmp_path / "via-fspath.csv"
    fs.get_file(f"{drop}/report.csv", Wrapped(destination))
    assert destination.read_bytes() == b"id,total\n1,42\n"


def test_a_file_opened_without_saying_so_commits_on_close(fs, drop: str):
    # `autocommit` defaults to `True`, and the test above passes `False` explicitly -- so the
    # default itself is only read by a call that omits it. Defaulted the other way, an ordinary
    # `fs.open(..., "wb")` would never publish what it wrote.
    with fs.open(f"{drop}/committed.csv", "wb") as handle:
        assert handle.autocommit is True
        _ = handle.write(b"id\n1\n")
    assert fs.cat_file(f"{drop}/committed.csv") == b"id\n1\n"


def test_removing_an_empty_directory_removes_that_directory(fs, drop: str, tree: Path):
    # `_rm`'s `rmdir(remote)` branch, which the symlink cases above deliberately avoid: they
    # prove the *link* is unlinked, and this proves a real directory still reaches `rmdir`.
    (tree / "incoming" / "spent").mkdir()
    fs._rm(f"{drop}/spent")  # noqa: SLF001
    assert not (tree / "incoming" / "spent").exists()


def test_a_callback_that_is_not_fsspecs_is_declined_rather_than_called(fs, drop, tmp_path):
    """`callback is None or not isinstance(callback, Callback)`, where `and` needs both.

    fsspec's own `DEFAULT_CALLBACK` is a `Callback`, but the argument is whatever a caller
    passed -- and with `and`, an object that merely looks callback-shaped goes through to
    `set_size` and raises `AttributeError` from inside a transfer that was working.
    """

    class NotACallback:
        pass

    assert gantry_fsspec._bridge(NotACallback()) is None  # noqa: SLF001
    assert gantry_fsspec._bridge(None) is None  # noqa: SLF001

    source = tmp_path / "upload.csv"
    _ = source.write_bytes(b"id\n1\n")
    fs.put_file(source, f"{drop}/unwatched.csv", callback=NotACallback())
    assert fs.cat_file(f"{drop}/unwatched.csv") == b"id\n1\n"


def test_a_write_to_a_destination_that_vanished_names_it(fs, drop, tree, monkeypatch):
    """`_upload_chunk`'s own `_translated(self._remote)` -- the fourth site in this class.

    Each of `_initiate_upload`, `_read_handle`, `_fetch_range` and `_upload_chunk` wraps its
    own call, and the path each carries is its own argument.
    """

    def vanish(_self, _handle, _offset, _data):
        raise NoSuchFileError("gone", code=2)

    monkeypatch.setattr(type(fs.sftp), "write_at", vanish)
    with pytest.raises(FileNotFoundError) as exc, fs.open(f"{drop}/vanishing.csv", "wb") as h:
        _ = h.write(b"id\n1\n")
    assert exc.value.args[0] == f"{drop}/vanishing.csv"


def test_a_file_whose_handle_the_server_forgot_still_closes(fs, drop: str, monkeypatch):
    """`_suppress(SFTPError)` around the final `CLOSE`, which runs in a `finally`.

    A server that has already dropped the handle answers `NO_SUCH_FILE` -- measured, and
    recorded in this repository's notes as OpenSSH's answer to closing an unknown handle. That
    must not turn leaving a `with` block into an error, because there is nothing left to do
    about it and the caller's own exception would be replaced by ours.
    """
    handle = fs.open(f"{drop}/report.csv", "rb")
    assert handle.read(2) == b"id"

    def refuse(_self, _handle):
        raise NoSuchFileError("no such handle", code=2)

    monkeypatch.setattr(type(fs.sftp), "close", refuse)
    handle.close()  # must not raise


def test_opening_through_the_private_entry_point_commits_by_default(fs, drop: str):
    # fsspec's own `open()` passes `autocommit` explicitly, so `_open`'s default is only read
    # by a direct call -- which is what a subclass or an adapter of an adapter makes.
    handle = fs._open(f"{drop}/report.csv")  # noqa: SLF001
    try:
        assert handle.autocommit is True
        assert handle.mode == "rb"
    finally:
        handle.close()


def test_removing_a_missing_directory_names_it(fs, drop: str):
    # `rmdir`'s own `_translated`, which is a different call site from `_rm`'s.
    with pytest.raises(FileNotFoundError) as exc:
        fs.rmdir(f"{drop}/no-such-directory")
    assert exc.value.args[0] == f"{drop}/no-such-directory"


def test_a_range_read_of_a_file_that_vanished_names_it(fs, drop, tree, monkeypatch):
    # `_fetch_range`'s own `_translated`, reached after the handle is already open, which is
    # the state a block cache spends its life in.
    handle = fs.open(f"{drop}/report.csv", "rb")
    try:
        assert handle.read(2) == b"id"

        def vanish(_self, _handle, _offset, _length):
            raise NoSuchFileError("gone", code=2)

        monkeypatch.setattr(type(fs.sftp), "read_at", vanish)
        with pytest.raises(FileNotFoundError) as exc:
            _ = handle._fetch_range(0, 4)  # noqa: SLF001
        assert exc.value.args[0] == f"{drop}/report.csv"
    finally:
        # Closed here rather than left to the collector: the fixture takes the portal down at
        # teardown, and a handle finalised after that raises from inside a generator nobody is
        # driving -- which surfaces as an unraisable warning against whatever test runs next.
        monkeypatch.undo()
        handle.close()


def test_opening_a_destination_that_cannot_be_created_names_it(fs, drop, monkeypatch, tmp_path):
    # `_initiate_upload`'s own `_translated`, which runs before a byte is buffered.
    def refuse(_self, _path, _flags, **_kwargs):
        raise NoSuchFileError("gone", code=2)

    monkeypatch.setattr(type(fs.sftp), "open", refuse)
    with pytest.raises(FileNotFoundError) as exc, fs.open(f"{drop}/nowhere.csv", "wb") as handle:
        _ = handle.write(b"id\n1\n")
    assert exc.value.args[0] == f"{drop}/nowhere.csv"


def test_a_final_flush_with_nothing_buffered_sends_no_write(fs, drop: str):
    """`payload.nbytes and self._handle is not None`, where `or` writes an empty payload.

    fsspec calls `_upload_chunk(final=True)` on close whether or not anything is left in the
    buffer, so the empty case is the common one rather than the odd one -- and an `or` there
    spends a WRITE round trip per closed file to send nothing.
    """
    before = fs.sftp.requests_sent
    with fs.open(f"{drop}/one-block.csv", "wb") as handle:
        _ = handle.write(b"id\n1\n")
    # OPEN, one WRITE for the buffered block, CLOSE -- and no second, empty WRITE on the
    # final flush, which fsspec makes whether or not anything is left to send.
    assert fs.sftp.requests_sent - before == 3
    assert fs.cat_file(f"{drop}/one-block.csv") == b"id\n1\n"

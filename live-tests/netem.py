"""Link shaping with ``tc netem``, and the measurement that has to come with it.

Everything else in this repository runs on a link with no latency, and a pipelining bug is
invisible there: a lockstep client and a deeply pipelined one finish a localhost transfer in
indistinguishable time. That is not a hypothetical -- it is the specific reason ``sftp(1)``'s
defaults were never noticed to be wrong, and correcting it is why this library exists. So the
scheduler gets proven at 5/50/200 ms RTT, with loss, or its numbers are not proven at all.

Two facts about shaping loopback drive the whole design of this module.

**A netem delay is applied per traversal, not per round trip.** A packet from 127.0.0.1 to
127.0.0.1 crosses ``lo``'s root qdisc on the way out and again on the way back, so
``delay 5ms`` produces a ~10 ms RTT. :func:`shape` therefore takes the *round-trip* time the
caller wants and halves it before handing it to ``tc``.

**And then it measures what it actually got.** Halving the number is a model of the kernel's
behaviour, and a benchmark that reports the flag it set rather than the delay it observed is
not a measurement -- it is a restatement of its own configuration, which would survive the
model being wrong. Every :class:`ShapedLink` carries a measured RTT, and there is a test whose
only job is to assert that the measurement agrees with the request.

Nothing here is allowed to *fail* because shaping is unavailable. It reports a reason, and the
fixtures skip with it.
"""

from __future__ import annotations

import functools
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

LOOPBACK = "lo"
"""The interface to shape. Every server in ``live-tests/`` is on 127.0.0.1.

Shaping ``lo`` slows down *everything* in the container, this process included, so a profile
is held for the duration of one test and removed in a ``finally``.
"""

TC_CANDIDATES = ("/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc", "/bin/tc")

_PROBE_DELAY = "1ms"
"""Delay used only to find out whether a qdisc can be added at all. Removed immediately."""

_QUEUE_LIMIT = 200_000
"""Packets netem may hold before it starts dropping them.

netem's default is 1000, which is a *silent* ceiling: a deep pipeline at 200 ms RTT can have
tens of megabytes outstanding, and on loopback -- MTU 65536 -- that is well inside 1000
packets, but the moment a profile is tightened or the MTU differs the default starts dropping
packets that the link profile never asked to drop. A depth experiment whose queue is quietly
discarding its own requests measures the queue, not the depth. This is set high enough that
the shaped loss rate is the only loss rate.
"""

_TC_TIMEOUT = 30.0
_CONNECT_TIMEOUT = 30.0
_JOIN_TIMEOUT = 30.0
_RTT_SAMPLES = 9
"""Round trips per measurement. Nine at 200 ms is under two seconds, and nine is enough that the
fastest of them is a real sample of the link rather than a lucky one -- see
:func:`measure_rtt_ms` for why the fastest is what is reported."""


def _tc_binary() -> str | None:
    """Locate ``tc``, preferring ``PATH`` and falling back to the usual sbin locations.

    ``/usr/sbin`` is frequently off a non-root user's ``PATH`` even where the binary is
    perfectly usable via ``sudo``, so ``shutil.which`` alone under-reports.
    """
    found = shutil.which("tc")
    if found is not None:
        return found
    return next((candidate for candidate in TC_CANDIDATES if Path(candidate).is_file()), None)


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=_TC_TIMEOUT, check=False)


def _root_qdisc_kind(prefix: tuple[str, ...]) -> str | None:
    """The kind of the root qdisc on the loopback interface, or ``None`` if unreadable.

    ``tc qdisc show`` needs no privilege, so this answers before we know whether we are
    allowed to change anything.
    """
    result = _run([*prefix, "qdisc", "show", "dev", LOOPBACK])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        # "qdisc <kind> <handle>: root ..." -- only the root entry, not a child class.
        if len(fields) >= 4 and fields[0] == "qdisc" and "root" in fields:
            return fields[1]
    return None


def _clear(prefix: tuple[str, ...]) -> None:
    """Remove our netem qdisc, and only ours.

    Deleting unconditionally would silently destroy a qdisc somebody set up deliberately --
    on a developer's machine ``lo`` is not necessarily bare. A netem root here is either the
    one this module is holding or one a crashed run left behind, and both should go.
    """
    if _root_qdisc_kind(prefix) == "netem":
        _run([*prefix, "qdisc", "del", "dev", LOOPBACK, "root"])


def _attempt_prefixes(binary: str) -> tuple[tuple[str, ...], ...]:
    """Ways to invoke ``tc``, cheapest first.

    Running as root needs no help. Everywhere else the capability has to come from somewhere:
    this sandbox has ``CAP_NET_ADMIN`` in the container's bounding set but runs tests as an
    unprivileged user, whose effective set is empty -- so ``tc`` works only through ``sudo``.
    Trying the bare binary first means a root container never shells out to ``sudo`` at all.
    """
    direct = ((binary,),)
    if shutil.which("sudo") is None:
        return direct
    return (*direct, ("sudo", "-n", binary))


@functools.cache
def _probe() -> tuple[tuple[str, ...] | None, str]:
    """Find a working way to shape loopback, or the reason there is none.

    Cached, because it is the only honest way to ask: capability introspection lies here.
    ``CapEff`` is all zeros in this container and shaping works anyway, via ``sudo``; a
    bounding set that lists ``cap_net_admin`` says the capability is *available*, not that
    this process can use it. So the probe adds a real qdisc and removes it again, and the
    answer is what the kernel did rather than what ``/proc/self/status`` implies it would.

    Returns:
        The argv prefix that worked and an empty reason, or ``None`` and a reason naming what
        would fix it.
    """
    binary = _tc_binary()
    if binary is None:
        return None, f"tc not found (looked on PATH and in {', '.join(TC_CANDIDATES)})"

    failure = ""
    for prefix in _attempt_prefixes(binary):
        existing = _root_qdisc_kind(prefix)
        if existing not in (None, "noqueue", "pfifo_fast", "netem", "mq"):
            return None, (
                f"{LOOPBACK} already has a {existing!r} root qdisc that is not ours; "
                f"refusing to replace it. Remove it and re-run."
            )
        _clear(prefix)
        result = _run(
            [*prefix, "qdisc", "add", "dev", LOOPBACK, "root", "netem", "delay", _PROBE_DELAY]
        )
        if result.returncode == 0:
            _run([*prefix, "qdisc", "del", "dev", LOOPBACK, "root"])
            return prefix, ""
        failure = (result.stderr or result.stdout).strip()
        if "unknown" in failure.lower():
            # A kernel without sch_netem is a different problem from a missing capability,
            # and the fix is in the VM rather than in the container.
            return None, f"the kernel has no netem qdisc: {failure}"

    return None, (
        f"cannot shape {LOOPBACK}: {failure or 'tc refused'}. The container needs "
        f"CAP_NET_ADMIN (docker run --cap-add=NET_ADMIN) *and* a way for this user to use "
        f"it -- run as root, allow passwordless sudo, or set cap_net_admin+ep on tc."
    )


def unavailable_reason() -> str | None:
    """Why this machine cannot shape its loopback link, or ``None`` if it can."""
    prefix, reason = _probe()
    return None if prefix is not None else reason


def release_loopback() -> None:
    """Best-effort removal of a netem qdisc this process may have left behind.

    A shaped ``lo`` outlives the test run that set it and degrades everything afterwards --
    including the next test run, which would then measure a link it did not configure. The
    context manager's ``finally`` covers every ordinary exit; this covers the one where the
    interpreter does not get one.
    """
    prefix, _ = _probe()
    if prefix is not None:
        _clear(prefix)


def measure_rtt_ms(samples: int = _RTT_SAMPLES) -> float:
    """Fastest round-trip time over a loopback TCP connection, in milliseconds.

    TCP rather than ICMP on purpose: TCP is what carries the transfer, ``ping`` needs a raw
    socket or a permissive ``ping_group_range``, and a shaped link can in principle treat the
    two differently. Measuring the thing under test costs a socket and removes the question.

    Nagle is disabled at both ends, so what is timed is one packet out and one packet back
    rather than the kernel's opinion about when to send a one-byte payload.

    **The fastest rather than the median, changed in 0.9 by D-81.** A round trip's measured
    time is the link's delay plus whatever the machine adds -- two scheduler wakeups, and on a
    busy box a wait for a core. That addition is one-sided: nothing makes a packet arrive
    before the link delivers it. So the minimum is the estimate of the link and the median is
    an estimate of the link *plus the load*, which is exactly the confusion that made this lane
    flake. Measured under a saturating load generator, the median put an unshaped loopback at
    2.15 ms and a 5 ms profile at 31.5 ms; both readings failed rows whose job is to notice a
    *link* that is not what was asked for, and neither was about the link.

    A lossy profile is the case that argued for the median, and it argues for the minimum more
    strongly: a retransmit should perturb the reading rather than define it, and taking the
    fastest of nine is the strongest available version of that.

    Args:
        samples: Round trips to time.

    Returns:
        Fastest RTT in milliseconds.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    def echo() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:  # pragma: no cover - the listener closed before anyone connected
            return
        with connection:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                chunk = connection.recv(64)
                if not chunk:
                    return
                connection.sendall(chunk)

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=_CONNECT_TIMEOUT) as client:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            timings = []
            for _ in range(samples):
                started = time.perf_counter()
                client.sendall(b"!")
                if not client.recv(1):
                    raise RuntimeError("the echo socket closed while the round trip was timed")
                timings.append((time.perf_counter() - started) * 1000.0)
    finally:
        listener.close()
        thread.join(timeout=_JOIN_TIMEOUT)
    return min(timings)


@dataclass(frozen=True, slots=True)
class ShapedLink:
    """A shaped loopback link, described by what was measured on it.

    ``target_rtt_ms`` is what the caller asked for and ``measured_rtt_ms`` is what the link
    turned out to do. They are separate fields rather than one because the entire value of
    this lane rests on the difference being visible: a report that quotes the request has not
    checked that the kernel honoured it, and netem's delay semantics on loopback are exactly
    the kind of thing that is easy to model wrong.
    """

    target_rtt_ms: float
    loss_percent: float
    rate_mbit: float | None
    measured_rtt_ms: float
    baseline_rtt_ms: float

    @property
    def measured_rtt_seconds(self) -> float:
        return self.measured_rtt_ms / 1000.0

    @property
    def bandwidth_delay_product(self) -> int | None:
        """Bytes that fit on the wire at once, or ``None`` on an unrated link.

        This is the number the pipeline window has to beat. A client with fewer bytes
        outstanding than this cannot saturate the link no matter how fast either end is, and
        that -- not cryptography -- is the whole of the "SFTP is slow" experience.
        """
        if self.rate_mbit is None:
            return None
        return int(self.rate_mbit * 1e6 / 8 * self.measured_rtt_seconds)

    def describe(self) -> str:
        """A one-line profile fit to appear beside any number measured under it.

        Every throughput figure this repository publishes has to name its link, and this is
        the string that names it.
        """
        loss = f", {self.loss_percent:g}% loss" if self.loss_percent else ""
        rate = f", {self.rate_mbit:g} Mbit/s" if self.rate_mbit else ", unrated"
        return (
            f"loopback netem: {self.measured_rtt_ms:.1f} ms RTT measured "
            f"(asked for {self.target_rtt_ms:g} ms{loss}{rate}; unshaped baseline "
            f"{self.baseline_rtt_ms:.2f} ms)"
        )


def _netem_arguments(*, rtt_ms: float, loss_percent: float, rate_mbit: float | None) -> list[str]:
    """The netem clause for a profile, with the per-traversal halving applied.

    See the module docstring: ``lo`` applies the delay once outbound and once inbound, so the
    flag carries half of the round-trip time the caller named.

    ``rate`` is halved for the same reason and for a second one: it is applied on each
    traversal, so an unhalved figure would rate-limit the forward and reverse paths
    independently at the full number. Halving keeps the round trip's shared budget honest.
    """
    arguments = ["netem", "limit", str(_QUEUE_LIMIT), "delay", f"{rtt_ms / 2:g}ms"]
    if loss_percent:
        arguments += ["loss", f"{loss_percent:g}%"]
    if rate_mbit is not None:
        arguments += ["rate", f"{rate_mbit:g}mbit"]
    return arguments


@contextmanager
def shape(
    *, rtt_ms: float, loss_percent: float = 0.0, rate_mbit: float | None = None
) -> Iterator[ShapedLink]:
    """Shape loopback for the duration of the block, and measure what that produced.

    Args:
        rtt_ms: Round-trip time wanted, in milliseconds. Halved on the way to ``tc``.
        loss_percent: Packet loss to inject, as a percentage. Applies in both directions,
            since both traverse the shaped interface.
        rate_mbit: Bandwidth ceiling in megabits per second, or ``None`` to leave the link
            unrated. Measured on this sandbox: **without a rate, the SFTP-level request size
            stops being visible past a point** -- 64x32768 and 64x261120 finished a 16 MiB
            transfer at 200 ms RTT within 1% of each other.

            The reason is not TCP, which is what this docstring claimed before the depth
            experiments were run against it. Both of those configurations are clamped to the
            same place by **OpenSSH's 2 MiB per-channel window** (DESIGN.md 5.1): 64x32768 is
            exactly 2 MiB, and 64x261120 asks for 16 MiB and is given 2 MiB. Two settings that
            agree because they hit the same ceiling are not evidence that the knob does
            nothing.

            A rate limit is still what gives the link a bandwidth-delay product, which is what
            the size-clamped-server case in DESIGN.md 5 needs and what ``benchmarks/`` uses to
            measure a bandwidth-bound profile rather than a latency-bound one.

    Yields:
        The link, carrying its measured RTT.

    Raises:
        RuntimeError: If shaping is unavailable, which the fixtures turn into a skip before
            ever getting here, or if ``tc`` refuses the profile.
    """
    prefix, reason = _probe()
    if prefix is None:
        raise RuntimeError(f"cannot shape the link: {reason}")

    baseline = measure_rtt_ms()
    _clear(prefix)
    profile = _netem_arguments(rtt_ms=rtt_ms, loss_percent=loss_percent, rate_mbit=rate_mbit)
    result = _run([*prefix, "qdisc", "add", "dev", LOOPBACK, "root", *profile])
    if result.returncode != 0:
        raise RuntimeError(
            f"tc refused the profile ({' '.join(profile)}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    try:
        yield ShapedLink(
            target_rtt_ms=rtt_ms,
            loss_percent=loss_percent,
            rate_mbit=rate_mbit,
            measured_rtt_ms=measure_rtt_ms(),
            baseline_rtt_ms=baseline,
        )
    finally:
        # Not optional and not best-effort: a 200 ms delay left on loopback breaks every
        # other test in the container, and the next run would silently measure it.
        _clear(prefix)

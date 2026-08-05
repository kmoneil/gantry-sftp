# Security Policy

## Reporting a vulnerability

**Please report security issues privately, not as a public issue.**

- **Preferred:** [open a private security advisory](https://github.com/kmoneil/gantry-sftp/security/advisories/new).
  This gives us a private thread, and it is the channel that can issue a CVE at the end of it.
- **If you cannot use GitHub, or you would rather not:** email **kevin@oneil.xyz**. A reporter who
  will not open a GitHub account is exactly the reporter worth hearing from, so this is a real
  fallback and not a formality.

A proof of concept helps enormously, but do not let its absence stop you from reporting. A clear
description of the mechanism is worth more than a working exploit that arrives three weeks later.

**Please do not test against servers you do not own or have permission to test.** This library talks
to other people's infrastructure by design; a local `sshd`, or the ones the test suite starts, are
enough to demonstrate anything in scope below.

## What is in scope

Everything under `src/gantry_sftp/`. Concretely, the classes of bug this project considers its own:

- **A hostile or compromised server.** Every filename from `READDIR`, `READLINK` and `REALPATH` is
  chosen by the server, as is the `STATUS` message and the banner OpenSSH prints on our standard
  error. If any of those can escape a download directory, forge or inject into a log record, drive a
  terminal through an escape sequence, cause an unbounded allocation, or crash or hang the codec,
  that is a vulnerability here.
- **Argument injection into `ssh`.** The argument vector is always a list and there is never a
  shell, but a hostname, path, or option that `ssh` interprets as a flag is exactly the bug class
  this construction exists to prevent.
- **Credential exposure.** A password or passphrase reaching an argument vector, a log record, a
  frame dump, an exception message, a traceback, or a serialized fsspec `storage_options` is a
  vulnerability, including when it takes a traceback or a pickle to get there.
- **A bypass of a control this library documents.** If `allowed_hosts()` can be evaded, if a
  weakened `ssh` option can be set without the documented warning, or if an atomic publish can leave
  a reader a half-written file, we want to know.
- **The fsspec adapter and the URL form**, which parse a string a user may not have written
  themselves. A URL that changes which program gets spawned, or which host gets contacted, is in
  scope.

## What is not in scope

These are scope decisions with reasons, not deflections. Three of them are unusual enough that a
reviewer who assumes the ordinary answer will get them wrong.

- **Cryptography, key exchange, host-key verification, and the SSH transport itself.** This library
  contains no cryptography and does not implement SSH; it runs OpenSSH as a subprocess and reads a
  plaintext, framed SFTP stream from it. A finding about cipher negotiation, host-key algorithms, or
  the SSH protocol is a finding about OpenSSH and should go to
  [OpenSSH](https://www.openssh.com/report.html). What _is_ ours is how we invoke it — the argument
  vector, the environment, and the options we override.
- **A server you deliberately connected to, behaving badly within its own rights.** Connecting to a
  host is an authorization decision you made. `allowed_hosts()` bounds _which_ hosts a program may
  reach; it does not turn a host you approved into an untrusted one. That a server you chose can
  serve you a file you asked it for is not a vulnerability.
- **`allowed_hosts()` not pinning a resolved address.** This library never resolves DNS — OpenSSH
  does — so the allowlist matches the destination as written and cannot guarantee that the name it
  approved resolves to the same address at connect time. This is documented behavior and a known
  limit of the control, not a defect in it. A way to _bypass the string matching itself_ is in
  scope; DNS rebinding against a name you allowed is not.
- **Deliberately weakening a default.** Passing `StrictHostKeyChecking=no` yourself raises
  `InsecureOptionWarning` and then does what you asked. That is the documented contract.
- **An attacker who already runs code as your user.** They can read the process environment, attach
  a debugger, and replace the `ssh` binary on your `PATH`. Nothing here defends against that and
  nothing can.
- **`NativeTransport`.** It is not implemented and not shipped. Reports about it are premature
  rather than out of scope, and will be held rather than closed.
- **`benchmarks/`, `live-tests/`, and the development tooling**, which are not part of what
  `pip install gantry-sftp` puts on a machine.

## Supported versions

**The latest release, and only the latest release.**

While the major version is `0`, a fix ships in a new minor or patch release and there are no
backports to earlier ones. Stating a support window this narrow is the honest answer for a
single-maintainer alpha project; implying an LTS that does not exist would be worse than saying so.

## What to expect

This is a single-maintainer project, so these are realistic targets rather than a service level
agreement:

- **Acknowledgement within 5 business days.** If you have not heard back, assume the message went
  astray rather than that it was ignored, and try the other channel.
- **An assessment within 10 business days** — whether we agree it is a vulnerability, and if so what
  we think its severity and scope are. Disagreement is possible and we will explain the reasoning
  rather than simply closing the report.
- **A fix, or a written decision not to fix, before any public disclosure.** If we cannot fix
  something, saying so publicly with a workaround is the outcome, not silence.
- **Coordinated disclosure, with 90 days as the default embargo**, negotiable in either direction
  and shorter if the issue is already being exploited.
- **Credit in the advisory and the changelog**, unless you would rather not be named. Tell us which.
- **No bug bounty.** There is no money here. There is a fast, respectful response and public credit.

If a report turns out to be a bug that is not a vulnerability, we will say so and handle it in the
open as an ordinary issue — with your agreement on the timing.

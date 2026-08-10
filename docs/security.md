# The security model

What this library defends against, what it deliberately does not, and where each control is
documented and proved.

**Nothing here is new.** Every fact on this page is stated in full on the task page it belongs to —
this exists because the facts are organised by *what you are doing*, which is right for reference
prose and wrong for the one question a reviewer arrives with: *what is the trust boundary?* That
question has no page, so it gets answered here by pointing at the others.

To report something, see [`SECURITY.md`](../SECURITY.md).

## The trust boundary

**The server is hostile.** Not "might be compromised" — hostile is the assumption every decision is
made under. Everything a server sends is attacker-chosen input:

- Every filename from `READDIR`, `READLINK` and `REALPATH`.
- Every `STATUS` message.
- The banner OpenSSH prints on our standard error, which reaches
  `ConnectError.stderr`.

**The `ssh` child is trusted.** It is the one thing this library does not implement and does not
second-guess: key exchange, host-key verification, `ProxyJump` and `ssh_config` are OpenSSH's, and
that is the whole architecture rather than a convenience.

**The caller is trusted, with one exception.** Arguments you pass are yours. A **URL** is not: it is
the same argument written by a different author, and a `gantry-sftp://` URL that chose which program
to spawn was a reproduced remote-code-execution bug. URLs are validated where constructor arguments
are not — see [the URL form](integrations.md#the-url-form).

## What is defended, and where

| The concern | Where it is documented | CWE |
| --- | --- | --- |
| A server-chosen name escaping the download directory | [Two remote names, one local file](transfers.md#two-remote-names-one-local-file) | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| A hostname or path parsed by `ssh` as an option | [What the shipped defaults are](connecting.md#what-the-shipped-defaults-are) | [CWE-88](https://cwe.mitre.org/data/definitions/88.html) |
| A server-chosen name forging or injecting into a log record | [Credentials](observability.md#credentials) | [CWE-117](https://cwe.mitre.org/data/definitions/117.html) |
| A password reaching argv, a log, a frame dump or a traceback | [Passwords](connecting.md#passwords), [Credentials](observability.md#credentials) | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| An `ssh_config` you do not control rewriting the destination | [When the `ssh_config` is not yours](connecting.md#when-the-ssh_config-is-not-yours) | — |
| A connection going somewhere the program never meant to reach | [Restricting where a connection may go](connecting.md#restricting-where-a-connection-may-go) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| A delivered file being world-readable between creation and `chmod` | [The mode is on the file before anything can open it by name](transfers.md#the-mode-is-on-the-file-before-anything-can-open-it-by-name) | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) |
| An operation following a symlink somebody planted | [Changing attributes, and links](paths.md#changing-attributes-and-links) | [CWE-59](https://cwe.mitre.org/data/definitions/59.html) |
| A predicate answering "no" when it means "I could not tell" | *below* | [CWE-636](https://cwe.mitre.org/data/definitions/636.html) |

### Controls fail closed

A check that cannot reach an answer refuses; it never treats "I could not tell" as approval. Two
places where that is easy to get backwards and is deliberately not:

- A predicate deciding whether something may be **deleted or overwritten** answers `False` only on
  a positive report from the server. A permission error, or a server that will not say, is not a
  licence to proceed.
- The destination allowlist refuses when its `ssh -G` probe cannot run, rather than allowing an
  unverified destination. A probe that fails to spawn, exits non-zero, times out, or reports no
  hostname all land there.

## What is not defended

These are scope decisions with reasons. Three are unusual enough that assuming the ordinary answer
gets them wrong.

**Cryptography, key exchange, host-key verification, and SSH itself.** This package contains none
and implements none; it runs OpenSSH and reads a plaintext, framed SFTP stream from it. A finding
about cipher negotiation or host-key algorithms is a finding about OpenSSH. What *is* ours is how we
invoke it. See [No cryptography, and the class of problem that removes](architecture.md#no-cryptography-and-the-class-of-problem-that-removes).

**A server you chose, behaving badly within its rights.** Connecting is an authorization decision
you made. The allowlist bounds *which* hosts a program may reach; it does not make an approved host
untrusted.

**The allowlist does not pin a resolved address.** This library never resolves DNS — OpenSSH does —
so the allowlist matches the destination as written and cannot guarantee the name it approved still
resolves the same way at connect time. A documented limit of the control rather than a defect in it.

**Deliberately weakening a default.** Setting `StrictHostKeyChecking=no` yourself raises
`InsecureOptionWarning` and then does what you asked.

**An attacker already running code as your user.** They can read your environment, attach a
debugger, and replace `ssh` on your `PATH`.

**Windows transfers**, which refuse by design — see
[Requirements](../README.md#what-it-needs-read-this-before-you-install-it). This entry used to
say `allowed_hosts()` refuses every connection on Windows because its `ssh -G` probe cannot
execute; that was read off five tests whose deliberately-broken `ssh` is a `#!/bin/sh` script,
which is the thing Windows could not execute. The allowlist works there and is tested there.

## Supply chain, and why no SBOM ships

**Deliberate, not an oversight.** OWASP's 2025 list moved Software Supply Chain Failures to A03 and
names maintaining an SBOM as prevention, so the absence of one here is a decision that has to be
written down rather than left to be rediscovered.

What this project does ship, on the three axes an SBOM is not:

| Question | Answer here |
| --- | --- |
| Are the dependencies known-vulnerable? | `scripts/audit_deps.py`, in two scopes — what a user installs gates, what a developer installs reports — with a three-state exit that keeps "could not check" apart from "checked and clean" |
| Is what I install what you locked? | `uv.lock` carries a hash per artifact and every `uv` call in both workflows takes `--frozen`; `uv` verifies those hashes even from a warm cache |
| Did *you* build what I downloaded? | Trusted publishing over OIDC, no long-lived token, third-party actions pinned to commit SHAs, the build backend installed from the lock with `--no-build-isolation`, and a signed **PEP 740 attestation** uploaded with every release |

**The inventory itself is what is missing, and the case for producing one is weak here.** The
declared runtime dependency is `anyio` and nothing else; installed, that resolves to three
packages — `anyio`, `idna`, `typing_extensions` — and `fsspec` only if you asked for the extra.
A CycloneDX document over that restates one `pip install` in a second format, and becomes a second
place to keep in sync. **An SBOM that exists but is stale is worse than none, because it is read as
current.**

**And for the question the 2025 rescope is actually about — was this artifact built by the project
it claims to come from — an attestation is the stronger answer.** It is a signed statement binding
the file to the workflow and repository that produced it, verifiable by the index. An SBOM is an
unsigned self-report of what went in. One can be checked without trusting us; the other cannot.

Two honest caveats, because a decision resting on unstated things is not a decision. PyPI's
attestation support is still labelled experimental by the publishing action that generates it — so
`release.yml` sets `attestations: true` explicitly rather than inheriting the default, and a test
pins that line, since this paragraph depends on it. And if you are here because a procurement
process requires an SBOM regardless of dependency count, that is a fair reason to want one: open an
issue, because "a consumer actually needs this" is the evidence that would change the answer, and
nothing else on this page is waiting for it.

## How each control is proved

Documentation is not evidence, so every control above has a test, and the test is the thing to read
if you doubt the prose:

| Area | Where the proof lives |
| --- | --- |
| Argument construction and `ssh` option handling | `tests/test_argv.py`, `tests/test_transport.py` |
| Destination policy and the URL form | `tests/test_destination.py`, `tests/test_fsspec.py` |
| Local path containment and collisions | `tests/test_localpath.py`, `tests/test_localtree.py` |
| Credential redaction | `tests/test_askpass.py`, `tests/test_observability.py` |
| Escaping of server-chosen names | `tests/test_observability.py`, `tests/test_describe.py` |
| Behaviour against a real server | `live-tests/`, and `tests/server_contract.py` for what a fake is allowed to claim |

The suite runs with no network and no keys against the genuine OpenSSH `sftp-server` over a pipe;
[Development](development.md) covers the lanes and what each one exists to catch.

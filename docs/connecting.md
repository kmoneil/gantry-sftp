# Connecting and authenticating

Authentication is OpenSSH's job, which means your `ssh_config` already works and there is
nothing here to configure twice. What this page covers is the seams: whose config is being
read, where a connection is allowed to go, passwords, which of your `ssh_config`'s settings
this library overrides, and what a failure tells you.

## Authenticating

There is no authentication code in this library, and that is the thesis working. `ssh` is the
client, so every method it supports works here with no adapter: keys from the agent,
`IdentityFile`, `ProxyJump`, host certificates, FIDO tokens, `Match` blocks.
Point it at a host in your `ssh_config` and it connects the way `ssh` would.

```python
async with open_ssh_transport("prod-sftp", user="bob") as t, open_session(t) as sftp:
    ...
```

### When the `ssh_config` is not yours

"It connects the way `ssh` would" cuts both ways. An `ssh_config` is executable: `ProxyCommand`
runs a program to obtain the connection, and `Match exec` runs one during config _parsing_,
before a connection is attempted at all. If the config file is trusted, yours or your
organisation's, that is the feature that makes `ProxyJump` and bastion hosts work for free. If
it is not, it is arbitrary command execution on the machine running the transfer.

The shipped defaults do **not** close that. `PermitLocalCommand=no` and `ClearAllForwardings=yes`
ship because an SFTP client has no business running `LocalCommand` or establishing forwardings,
and they are worth having, but neither touches `ProxyCommand` or `Match exec`, both of which
still execute with the full default set applied. Verified against OpenSSH 10.0p2 and pinned by
`tests/test_transport.py::test_the_shipped_defaults_do_not_neutralise_an_untrusted_config`.

The control is to not read the file:

```python
async with open_ssh_transport("host", user="bob", config_file=os.devnull) as t:
    ...
```

`-F` suppresses `/etc/ssh/ssh_config` as well as the per-user file, so this is a real "no
config" rather than half of one. Everything the config would have supplied, meaning port,
identity file and username, has an explicit parameter, so the trade is verbosity rather than
capability.

### Restricting where a connection may go

If a hostname comes from user input — a job config, an API request, a `gantry-sftp://` URL —
then the application chooses the destination and the user chooses the application's mind. That
is server-side request forgery, and nothing in this library restricted it before 0.11.

The control is an allowlist, and it is **off by default** because only the deployment knows
the policy:

```python
from gantry_sftp import allowed_hosts

with allowed_hosts(["*.corp.example.com", "sftp.partner.net"]):
    async with connect(host_from_user) as sftp:
        ...
```

Or, for a whole process, without touching any code — which is the only spelling that reaches
`pd.read_parquet("gantry-sftp://…")`, since a URL is that adapter's entire interface:

```
export GANTRY_SFTP_ALLOWED_HOSTS='*.corp.example.com,sftp.partner.net'
```

**Layers narrow and never widen.** The environment variable is one layer, each `allowed_hosts`
block is another, and a host must satisfy _every_ active layer. So a deployment's floor cannot
be raised by code running inside it, and nesting two scopes is an intersection rather than a
replacement. An inner scope that could re-admit a host an outer one refused would be a control
that any library in the process could switch off.

**It matches the effective host, not the name you passed.** An `ssh_config` rewrites the
destination _after_ the name reaches it — measured against OpenSSH 10.0p2:

```
Host allowed.example.com
  Hostname 169.254.169.254        # the cloud metadata endpoint
```

An allowlist checking the string would approve that connection. This one asks `ssh -G` what the
command will really dial and checks the answer, so the rewrite is caught and the refusal names
both halves. It also means a legitimate `ssh_config` alias works: you allowlist the destination,
not the nickname.

A refusal is a `DestinationNotAllowedError`, which is a `ConnectError` — so `except ConnectError`
does not start missing failures because a policy was switched on. It carries `host`,
`effective_host` and the layers that refused it.

Three things it deliberately does not do, because a control that overstates itself is worse than
an absent one:

- **It does not defeat DNS rebinding.** This library resolves no names — `ssh` does, inside the
  subprocess — so there is no address for us to pin. A validator that resolved, approved, and
  then let `ssh` resolve again would be reproducing a published bug class rather than fixing one.
- **It assumes the `ssh_config` is trusted**, because `ssh -G` evaluates `Match exec` and that
  runs a program. This is not a weakening: a config you do not trust is already arbitrary code
  execution, and [the control for that](#when-the-ssh_config-is-not-yours) is `config_file=os.devnull`.
  An allowlist defends against an untrusted _host_, not an untrusted _config_.
- **It is not egress control.** Only the network binds the socket.

When no policy is active nothing is spawned and nothing is checked, so an unrestricted caller
pays no process and no latency for the feature existing.

### Passwords

A large fraction of enterprise SFTP endpoints, including MOVEit, GoAnywhere, Cleo and Sterling,
are password-first. Pass one:

```python
async with (
    open_ssh_transport("host", user="bob", password=os.environ["SFTP_PASSWORD"]) as t,
    open_session(t) as sftp,
):
    ...
```

**The secret never reaches argv.** `ssh` refuses to take a password as an argument, and the two
workarounds people reach for, `sshpass -p secret` and stuffing it into an `-o` value, both put
the credential where `/proc/<pid>/cmdline` makes it readable by every user on the machine, for
as long as the process lives. Instead, `password=` writes a throwaway `SSH_ASKPASS` helper to a
`0700` temporary directory and hands `ssh` the secret in the child's _environment_, which on
Linux only this user and root can read. The helper contains no secret, being a `printf` of an
environment variable, and it is deleted when the connection ends, whether or not it succeeded.

Three `ssh` options change on that path, and the first of them is the reason the parameter
exists at all:

| option                     | value                           | why                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BatchMode`                | `no`                            | The shipped default is `yes`, and it does not merely discourage a prompt: it **suppresses the askpass helper outright**, regardless of `SSH_ASKPASS` or `SSH_ASKPASS_REQUIRE`. Password authentication was not awkward under the default; it was impossible.                                                                                                         |
| `PreferredAuthentications` | `password,keyboard-interactive` | Deterministic order. Otherwise `ssh` offers every key it can find first, and against a server with a low `MaxAuthTries` the attempts run out before password is reached, failing with `Too many authentication failures`, which names nothing that is wrong. Appliances routinely offer only `keyboard-interactive`, and OpenSSH answers it through the same helper. |
| `NumberOfPasswordPrompts`  | `1`                             | OpenSSH's default is three, each re-running the helper with the same wrong secret. Against an OpenSSH 9.8+ server that is three failed attempts, which earns your source address a `PerSourcePenalties` timeout that then breaks the _next_ connection from that host.                                                                                               |

All three are overridable by name through `options=`, except that `password=` together with an
explicit `BatchMode=yes` is refused as the contradiction it is, with a `ValueError` naming
both halves, rather than a `Permission denied` twenty seconds later.

`password=` is POSIX-only: the helper is a shell script, and Windows OpenSSH's prompting path
has never been run here, so it raises `NotImplementedError` rather than shipping an untested
guess.

**What the library will not do**: write your password to a file, put it on a command line, read
it from one, or log it. Anything that can carry it is checked, including `repr()` of the
transport, the captured stderr, `ConnectError.argv`, the rendered exception, and the **frame
locals** a traceback reporter captures, and `tests/test_askpass.py` runs the helper against
passwords built to break a shell (`$(...)`, backticks, `%s%n`, `-n`, embedded quotes) to prove
what comes back out is what went in.

That last surface is the least obvious one. The environment dictionary carrying the secret is a
local variable in an `@asynccontextmanager` generator, so its frame stays alive for the whole
connection, and Sentry captures frame locals by default, as do `pytest --showlocals`, `rich`
tracebacks and IPython's verbose mode. Every one of them renders a local with `repr()`, so the
secret is held in a `str` subclass whose `repr()` is `'<redacted>'` —
`gantry_sftp.transport.Secret`, public for the reason below. It is still an ordinary string
everywhere it has to be one, so `ssh` receives it intact. What that does **not** cover, stated
plainly: a reporter that calls `str()` rather than `repr()`, a core dump, and
`/proc/<pid>/environ`, the last being the deliberate trade that buys not being in argv.

**The wrapping happens at every entry point, not only at the innermost one**, and that is worth
saying because it did not always. `password=` is a parameter of `connect()`, of the four
blocking spellings in `gantry_sftp.sync`, and of `GantrySFTPFileSystem` — each of which binds it
in its _own_ frame, for as long as your `with` block lasts. Wrapping inside
`open_ssh_transport` protects that function's binding and no other, so a traceback crossing any
of the outer ones rendered the plaintext while the environment dictionary one frame further
down rendered `'<redacted>'`. All of them now rebind on entry. The fsspec adapter is the
exception to the shape rather than to the rule: it is not a generator, but fsspec's registry
caches the instance for the life of the process, so the wrapping is on the attribute instead.

`tests/test_askpass.py` proves this twice, because two different mistakes are possible. One test
fails a connection through each entry point and asserts the plaintext appears in no frame a
reporter would capture; the other reads the list of functions taking a `password` out of the
source itself and asserts each one wraps, so an entry point added later fails by name rather
than quietly inheriting the gap.

### `options=` matches names the way `ssh` does

Option names are matched **case-insensitively**, because that is how `ssh` reads them. An
override spelled `stricthostkeychecking` or `STRICTHOSTKEYCHECKING` replaces the shipped
`StrictHostKeyChecking` rather than joining it on the command line, and warns exactly as the
canonical spelling does.

This is not cosmetic. `ssh` resolves a repeated keyword to the **first** `-o` on the line, and
this library emits its options sorted, where ASCII puts every uppercase letter before every
lowercase one. Matching on exact case therefore let `STRICTHOSTKEYCHECKING=no` land ahead of
the default and silently win, with no `InsecureOptionWarning`, because the warning was reading
the default under its own spelling. The same shape defeated `PermitLocalCommand=no` and the
`BatchMode` contradiction check above. Measured against OpenSSH 10.0p2; pinned by
`tests/test_transport.py::test_ssh_matches_option_names_case_insensitively_and_takes_the_first`,
which characterises `ssh` rather than us, so a change in that behaviour fails loudly.

### What the shipped defaults are

These `-o` options go on every command line unless you override them by name. A command-line `-o`
beats your `ssh_config`, so this is the short list of settings where what you wrote in the config
is not what `ssh` will use.

| Option                  | Shipped | Why                                                                                                                                             |
| ----------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `BatchMode`             | `yes`   | No prompting. A transfer hung on an invisible password prompt is the most common way an automated job fails silently. `password=` relaxes it.      |
| `StrictHostKeyChecking` | `yes`   | Refuse an unknown host key rather than trusting on first use. Weakening it warns.                                                                  |
| `PermitLocalCommand`    | `no`    | `LocalCommand` in an `ssh_config` runs a program on _this_ machine. An SFTP client has no business doing that.                                     |
| `ClearAllForwardings`   | `yes`   | Drop any forwarding a config tries to establish. Same reason.                                                                                      |
| `ForwardX11`            | `no`    | Same reason.                                                                                                                                       |
| `ForwardAgent`          | `no`    | Same reason.                                                                                                                                       |
| `ControlMaster`         | `no`    | Declines to _become_ a multiplexing master. This one is not a security default and it is the one below.                                             |

The table is `DEFAULT_SSH_OPTIONS` in the public `gantry_sftp.transport` namespace, so a program
can read what it is getting rather than trust this page; `tests/test_packaging.py` asserts the two
agree, which is what stops a new default shipping undocumented.

### Connection reuse, and why the master is not ours to start

Connecting is this library's weak spot — a fork, an exec and OpenSSH's own config parsing before
a packet moves — and `ControlMaster` multiplexing is the fix for a workload that connects often.
It is worth stating exactly what you get, because **one shipped default changes the answer**.

`ControlMaster=no` is on every command line, and `-o` beats the config file. Measured against
OpenSSH 10.0p2 with a config that asks for multiplexing:

```console
$ ssh -F cm.conf -G host | grep -i '^controlmaster\|^controlpath'
controlmaster auto
controlpath /tmp/cm-%r@%h:%p

$ ssh -o ControlMaster=no -F cm.conf -G host | grep -i '^controlmaster\|^controlpath'
controlmaster false
controlpath /tmp/cm-%r@%h:%p
```

So `ControlPath` survives and `ControlMaster` does not. Concretely:

- **An existing master is still used.** If something else already holds one at your `ControlPath`,
  every connection this library makes goes down it and costs a Unix socket handshake. Nothing is
  disabled on that path.
- **This library will not create one.** So if the only `ssh` on the machine is ours, setting
  `ControlMaster auto` in `~/.ssh/config` and changing nothing else buys **nothing**: the first
  connection declines to host the master, and there is never one for the second to reuse.

That default is deliberate rather than an oversight. Becoming a master means leaving a listening
socket behind that outlives the process and accepts further connections to that host — a side
effect worth having, and not one a library gets to take on your behalf without being asked.

Ask for it either way:

```python
# 1. Run your own master, and this library uses it with no argument at all.
#      ssh -MNf -S /tmp/cm-%r@%h:%p prod-sftp
#    with a matching `ControlPath` in your ssh_config.

# 2. Or let the first connection host it.
async with connect("prod-sftp", options={"ControlMaster": "auto"}) as sftp:
    ...
```

Option 2 replaces the shipped value rather than joining it on the command line, so there is no
repeated-keyword ambiguity to reason about. Option 1 is the better fit for a long-lived worker,
because the master's lifetime is then yours to end.

What this does **not** buy is CPU. Reuse removes the handshake and TCP slow start; it does not
change what this process spends per byte, which is the ceiling
[`benchmarks/README.md`](../benchmarks/README.md) measures.

### Arming your own askpass helper

`password=` is a convenience over a mechanism that is still fully available: set `SSH_ASKPASS`
to any program of yours and `SSH_ASKPASS_REQUIRE=force` through `env=`, and override
`BatchMode`. `SSH_ASKPASS_REQUIRE=force` is what arms the helper on a headless machine.
Measured: `SSH_ASKPASS` alone does not, and `DISPLAY` or `WAYLAND_DISPLAY` each arm it on their
own. This is also the path for a _passphrase_ on an encrypted private key.

## When the connection fails

```python
from gantry_sftp.exceptions import AuthenticationError, ConnectError, HostKeyError

try:
    async with open_ssh_transport("example.com", user="bob") as t, open_session(t) as sftp:
        ...
except AuthenticationError as e:
    ...  # credentials refused
except HostKeyError as e:
    ...  # the server's identity was not accepted -- do not retry blindly
except ConnectError as e:
    print(e.stderr)  # OpenSSH's own words, verbatim
```

**The thing worth having here is that nothing is re-diagnosed.** OpenSSH knew exactly what went
wrong and said so, so `ConnectError.stderr` carries that text unparsed rather than a summary of
it — and the two questions people actually ask, "was that my key?" and "has the host changed?",
are answered by `except` rather than by string matching in your own code.

It is **bounded**, which "untouched" used to imply it was not: the first 8 KiB and the last
56 KiB, with `... [N bytes of stderr omitted] ...` marking the gap. Both ends, because the
first lines say what was attempted and the last say how it ended, and `ssh -vvv` is precisely
the case that overflows it. A hostile server also writes to that stream, so it is a buffer with
a cap rather than a string with a promise.

Three things about that ladder are deliberate:

- **Unrecognised failures stay `ConnectError`.** A refused connection, a name that will not
  resolve, a cipher mismatch: none of them are guessed into a more specific class. One that
  sometimes means "we guessed" is worth less than one that always means what it says.
- **Host keys are checked before credentials.** Of the two possible misclassifications only one
  costs anything: reporting a _changed_ host key as a bad password tells you to check your
  credentials when what happened may be interception. OpenSSH prints a server-supplied banner to
  stderr, so a hostile server can put `Permission denied` in it. What it cannot do is remove the
  host-key line `ssh` itself writes.
- **Every marker was captured from a real server**, not written from memory. A marker that is
  subtly wrong does not fail loudly; it silently stops matching and the class quietly goes back
  to being decorative.

`ConnectError.hint` is the one thing on these errors that is _ours_ rather than OpenSSH's, and
it is separate from `stderr` for that reason, since merging them would put words in the server's
mouth. It is set only where this client's own configuration or environment made the failure
inevitable, and **there are exactly two such cases: the ones OpenSSH cannot explain itself.**

The first is when there is no stderr at all, because `ssh` never ran:

```
ConnectError: could not run 'ssh': No such file or directory
hint: 'ssh' was not found. This library does not implement SSH -- it runs the OpenSSH client
as a subprocess -- so an ssh client is a hard requirement. Install it (Debian/Ubuntu:
apt-get install openssh-client; Alpine: apk add openssh-client; RHEL/Fedora: dnf install
openssh-clients), or pass ssh_executable=... if it is installed somewhere PATH does not
reach. A distroless or scratch image has no package manager and cannot run this transport
at all.
```

`could not run 'ssh': No such file or directory` is diagnosable only by a reader who already
knows the answer, and this is the failure most likely to be somebody's _first_ experience of
the library; see [What it needs](../README.md#what-it-needs-read-this-before-you-install-it). A binary
that exists but will not execute gets a different hint, and a spawn that failed for a reason
that is nothing to do with the binary, such as out of memory or out of file descriptors, gets
none, because installing a package would not fix it.

The second is when the stderr is real and says the wrong thing:

```
AuthenticationError: connection closed by the remote end (exit status 255)
ssh stderr:
bob@host: Permission denied (keyboard-interactive,password).
hint: the server offered password authentication and this client had it switched off:
BatchMode=yes suppresses the askpass helper outright, so no password was ever sent.
Pass password=... to open_ssh_transport()
```

That line names the methods the _server_ offers and says nothing about the one we disabled.
Reading it is how people conclude the library is publickey-only. Note that it cannot be
produced from the text alone: `BatchMode=yes` with a working helper, and `BatchMode=no` with no
helper at all, are byte-identical on stderr, so the hint reads back the argv that was actually
spawned to tell them apart, and stays empty when a password _was_ offered and refused, because
why the server said no is not something this client knows.

`examples/connect_errors.py` runs this with no arguments, and `examples/password_auth.py`
covers the password half.

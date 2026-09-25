# Security

Wisp is a **local WireGuard client**. It has no servers, no accounts, no
telemetry, and makes no network connections of its own. The only traffic it is
responsible for is the tunnel it configures.

This document states what Wisp does and does not protect against, how each claim
is backed up, what the audit actually found, and where the remaining gaps are.
It is written to be checked rather than believed: every claim below names the
test or command that would falsify it.

## 1. Scope and honest positioning

**Wisp cannot be "more secure than Proton VPN or Mullvad".** Those are
*providers*: the security question there is servers in a jurisdiction, a
no-logs policy, warrant canaries, and independent audits (Cure53, X41) of those
things. Wisp has no servers, so there is nothing for it to be more or less
secure *at*. What Wisp can claim is narrower and checkable:

- It does not implement cryptography. It configures the kernel's WireGuard,
  which is the audited implementation, and uses libsodium for the only key
  operations it performs itself.
- It cannot leak what it does not have. There is no account, no identifier, no
  version check, and no telemetry, so there is no traffic to analyse, sell, or
  subpoena.
- The attack surface is small enough to read in an afternoon, and the half that
  runs as root accepts almost no input.

The relevant comparison is not to a provider but to `wg-quick`, the thing people
actually use. Against that, the meaningful differences are: configuration is
never executed as shell (see §3.1), the privileged half is a separate process
with one capability rather than a root shell script (see §3.5), and the
unprivileged half cannot send configuration at all (see §3.2).

## 2. Threat model

### Assets

1. **The tunnel private key and peer preshared keys.** Disclosure lets an
   attacker impersonate the user's peer, or decrypt recorded traffic if the
   session keys were captured.
2. **The routing configuration.** Anyone who can change routes can redirect all
   of the user's traffic to themselves without breaking the tunnel, silently.
   This is the asset people forget about, and it is the one a full tunnel's
   policy rules exist to protect.
3. **The DNS configuration.** Whoever controls the resolver sees every name
   looked up. A tunnel that carries packets but leaks DNS is not a useful
   tunnel.

### Adversaries considered

| # | Adversary | In scope |
|---|-----------|----------|
| A1 | A local unprivileged process, including one running as the GUI's own user | Yes |
| A2 | A different local user on the same machine | Yes |
| A3 | A hostile profile file (downloaded from a provider, a colleague, a pastebin) | Yes |
| A4 | A malicious or buggy peer on the far end of the tunnel | Partly (the kernel parses its packets, not Wisp) |
| A5 | A remote attacker with no local access | Only via A3 or a bug in the kernel's WireGuard |
| A6 | Local root, or a kernel compromise | **No** (out of scope by construction) |
| A7 | Physical access to an unlocked machine | **No** |

A1 is the interesting one. Wisp's own GUI runs as the user, so anyone who can
run code as that user can already talk to the helper. The design therefore
assumes A1 is *already* inside the socket's trust boundary, and makes sure
nothing useful can be done with that access beyond bringing a tunnel that
already exists on disk up or down.

A2 is the case the socket permissions and `SO_PEERCRED` exist for. A3 is the
case the strict parser and the no-hooks rule exist for.

## 3. Security properties and how they are enforced

### 3.1 Configuration is data, never code

`wg-quick` runs `PreUp`, `PostUp`, `PreDown`, `PostDown` through a shell as
root. That makes any downloadable profile a root code-execution primitive, and
it is how several real client vulnerabilities have worked.

Wisp parses those keys so the UI can *show* what a profile claims it will do,
and never executes them. `Hooks` is a display-only field; there is no `system()`,
`popen()`, or `execve()` of anything derived from a profile anywhere in the tree.

**Verification:** the integration test writes a profile whose `PostUp` is
`cp /etc/shadow /tmp/leak`, brings it up, asserts the profile is accepted with a
warning, and then checks that `/tmp/leak` does not exist. Checking the file
rather than the exit status matters: a run that "succeeds" while executing the
hook is the failure being tested for.

```bash
./scripts/integration-test.sh      # "a hook is accepted and reported as a warning"
```

### 3.2 The privileged helper cannot be given configuration

`wispd` accepts exactly one request shape: a verb and, for four of the five
verbs, a tunnel **name**. It is impossible to send it a private key, a peer, an
address, a route, or a file path. Configuration is read only from a directory
the client cannot write.

Profiles are opened `O_NOFOLLOW` after `lstat` rejects symlinks, non-regular
files and world-writable files (root-owned required when running as root); the
config directory itself is rejected when group/other-writable. A symlink
`home.conf -> /etc/shadow` therefore reads as "no profile", not as a file.

This is the single most important structural decision in the design. It means a
bug in the config parser is not a privilege-escalation bug, because an attacker
cannot reach the parser with input they control.

**Verification:** `handle_request` in `helper/main.cpp` has no code path that
reads configuration from the request. The integration test confirms the
practical consequence for the path-traversal case:

```bash
UP ../etc/passwd      ->  ERR invalid tunnel name
UP /etc/shadow        ->  ERR invalid tunnel name
UP -oProxyCommand=evil ->  ERR invalid tunnel name
```

### 3.3 The name is the whole attack surface, so it is validated as such

Because the name is the only caller-supplied value that becomes a filesystem
path, `is_valid_tunnel_name` is the entire defence:

- `[A-Za-z0-9_-]` only, 1-15 characters (`IFNAMSIZ - 1`)
- no leading `-` (cannot be read as an option) or `.` (cannot become `..`)
- an embedded NUL is rejected rather than treated as a terminator

It is also applied to the *output* of `LIST`, so a file in the config directory
whose name no client could ever request is never advertised.

**Verification:** `tests/ipc_test.cpp` covers separators, `..`, NUL, control
characters, shell metacharacters, over-length names, and empty names.

### 3.4 Responses and logs cannot be forged or split

Any caller-supplied string that reaches a response or a log line is a place
where a newline could fabricate a second protocol response, or split a log entry
so that the record an operator reads is not the real one.

Two functions close this:

- `is_valid_verb`: the helper validates the verb **before** dispatch, so an
  unrecognised verb never reaches a response or a log entry.
- `sanitize_for_display`: anything outside printable ASCII becomes `?`, and the
  result is length-capped (32 characters). Applied in both the error response
  and the log line.

Per-request logging is opt-in (`--verbose`). By default only startup, warnings
and refusals reach stderr, so 400ms `STATUS` polling does not write an activity
timeline to disk.

**Verification:**

```bash
printf 'UP\x01X\n' | socat - UNIX-CONNECT:$SOCK   ->  ERR unknown verb 'UP?X'
a 4000-byte verb                                  ->  a 51-byte reply, not an echo
```

Every assertion in the integration script also fails if a single request
produces more than one response line, which is what a successful response-split
would look like.

### 3.5 The privileged half is minimised, then hardened

`wispd` runs as root only long enough to bind the socket and set its ownership,
then restricts itself in `apply_process_hardening`:

| Measure | Effect |
|---|---|
| `prctl(PR_SET_NO_NEW_PRIVS)` | the helper can never gain rights by executing anything |
| `prctl(PR_SET_DUMPABLE, 0)` | another process cannot `ptrace` it or read `/proc/<pid>/mem` for key material |
| `setrlimit(RLIMIT_CORE, 0)` | a crash cannot write a private key to disk in a core dump |
| `mlockall(MCL_CURRENT)` | already-mapped key material cannot reach swap |
| `capset` to **only** `CAP_NET_ADMIN` | a bug is a network-configuration bug, not a root bug |

`MCL_CURRENT` rather than `MCL_FUTURE` is deliberate: `MCL_FUTURE` makes every
later allocation count against `RLIMIT_MEMLOCK`, and a failed allocation in a
daemon is a worse outcome than a key that might page. The tradeoff is stated
rather than hidden.

### 3.6 Socket access control is two-layered

1. The socket parent is created `0700` and verified (no symlink, no
   group/other write) before bind; the socket is `chmod 0600` and `chown`ed to
   the permitted uid before the capability drop.
2. Every accepted connection is checked with `SO_PEERCRED`; only uid 0 or the
   configured `--uid` is served, and refusals are logged.

The permissions are a convenience; `SO_PEERCRED` is the authoritative check,
because the kernel, not the filesystem, reports the connecting uid.

`--uid` is **required** and strictly numeric (`SUDO_UID` likewise). A
non-numeric value is rejected rather than truncated to 0.

### 3.7 Cryptography is libsodium's, not Wisp's

- Curve25519 key derivation and key generation come from libsodium
  (`crypto_scalarmult_curve25519`, `randombytes_buf`); private keys are clamped
  per RFC 7748.
- No cryptographic primitive is implemented in this repository. Wisp
  orchestrates the kernel's WireGuard, which is the audited implementation.
- Key comparison is constant-time (`keys_equal`).
- The GUI makes no network connections except the local helper socket. Theme
  choice is the only thing written to disk (`QSettings`); tunnel scores for
  Fastest are memory-only and vanish on quit. No probing, no server-list
  downloads, no telemetry.
- Every copy of a secret is wiped with `sodium_memzero` via `secure_wipe`: the
  raw profile text after parsing, `config.private_key`, each peer's preshared
  key, and the GUI's stored private key on clear and on destruction.
- The GUI keeps the private key in a `std::string`, not a `QString`. This is not
  a style choice: `QString` is implicitly shared and copied, which would leave
  copies of the secret in memory that nothing can wipe.
- `unbracketed IPv6` and other ambiguous endpoint spellings are rejected rather
  than guessed at, because a misparsed endpoint is a connection to the wrong
  host.

**Verification:** `tests/keys_test.cpp` (clamping, uniqueness, deterministic
derivation, distinctness, wiping). Constant-time comparison is a property of
libsodium's `sodium_memcmp`, not of Wisp's code.

### 3.8 DNS is applied without a shell, and validated as data

- `is_valid_dns_server` accepts **IP literals only**. A DNS value can therefore
  never be interpreted as a command-line option (`--config=/etc/shadow`) even if
  it reaches an argv.
- Commands are executed with `fork`/`execvp` and an explicit argv. There is no
  shell, so there is nothing for a metacharacter to do.
- Search domains must be real domain names, optionally with a leading `~` for a
  systemd-resolved routing domain. The allowed set excludes whitespace, control
  characters, `/`, `;`, quotes, and anything with a leading `-` or `.`. This is
  stricter than `wg-quick`: a domain that cannot be used is either
  a silently ignored entry (a DNS leak the user never sees) or a value that
  re-serialises into something that no longer parses back the same way, which
  is exactly finding F1 in §5.
- Wisp **refuses to write a symlinked `/etc/resolv.conf`**. A symlink there is
  how a write would be redirected somewhere it does not belong.
- The previous resolver configuration is backed up to
  `/run/wisp/resolv.conf.backup` (`0600`, atomic rename + `fsync`) before being
  replaced. `/run/wisp` is created `0700`.
- `--no-dns` leaves the resolver entirely untouched. A split tunnel whose DNS
  step fails stays up with a loud warning; a **full tunnel whose DNS step
  fails is torn down** (policy rules removed, link deleted) rather than left
  carrying packets with the old resolver. A tunnel that comes up with the DNS
  step silently skipped is a leak the user will not notice.

### 3.9 The parser fails closed

One bad key, port, or CIDR fails the **whole** parse. This is the opposite of
the forgiving behaviour a config parser usually has, and it is intentional: a
partially applied tunnel configuration is a silent traffic leak. Refusing to
bring anything up is loud and recoverable; a half-configured tunnel is neither.

Errors carry line numbers, because the failure mode this design is trying to
avoid is a user who cannot tell which line is wrong and therefore copies a
broken profile around.

### 3.10 Routing is planned so a full tunnel cannot capture itself

A full tunnel needs policy routing, or its own encrypted packets match the
default route pointing into the tunnel and loop back at themselves. Wisp
reproduces `wg-quick`'s mechanism exactly (`fwmark` plus an inverted-mark rule),
so what it installs is indistinguishable from what `wg-quick` installs, and
the same debugging advice applies.

The subtlety is that **the kernel has no "not equal to mark" comparison**;
`ip rule add not fwmark N` is expressed by setting `FIB_RULE_INVERT` in the rule
header. Getting this wrong does not produce an error. It produces either a
routing loop or a traffic leak. The behaviour was confirmed against iproute2's
own `ip/iprule.c` directly, and the constant is documented at the
point of use in `core/include/wisp/netlink.hpp`.

The interface is also raised **last**: create → set_device → addresses → routes
→ link up → policy rules → DNS. Raising a link before it is configured would
offer the kernel a window in which a default route exists with nothing to carry
it.

Two full-tunnel footguns are reported in `--dry-run` (`hostnames=`,
`single_stack=`) and refused with `--fail-closed`: an `Endpoint` hostname is
resolved with the system resolver *before* the tunnel exists (the query
reveals the destination in the clear (prefer IP literals), and a full tunnel
covering only one family (`0.0.0.0/0` without `::/0`) leaves the other family
outside the tunnel.

### 3.11 Resource bounds

A client that holds the allowed uid is inside the trust boundary, but it must
still not be able to make the helper allocate without bound or stall it:

| Bound | Value | Why |
|---|---|---|
| request size | 4096 bytes | the longest legitimate request is a verb plus a 15-character name |
| buffered bytes before a newline | 64 KiB | a peer that never sends a newline must not grow the buffer |
| concurrent connections | 32 | the accept loop is single-threaded |
| write timeout | 2000 ms | one peer that stops reading must not pin the daemon |

The helper is single-threaded over `poll()` rather than blocking on one socket,
so a quiet client costs nothing and no client can queue behind another.

## 4. Build hardening

Enabled by default (`WISP_HARDEN=ON`, `WISP_LTO=ON`).

Verified against the built binaries rather than assumed. Every line below is
the output of a command in §6:

| Mitigation | Evidence |
|---|---|
| PIE | `Type: DYN (Position-Independent Executable file)` |
| Full RELRO | `GNU_RELRO` program header present |
| Immediate binding | `FLAGS: BIND_NOW`, `FLAGS_1: NOW PIE` |
| Non-executable stack | `GNU_STACK ... RW` (not `RWE`) |
| Stack canaries | `-fstack-protector-strong`; `__stack_chk_fail` is referenced |
| Bounds-checked libc | `_FORTIFY_SOURCE=2`; `__recv_chk` is referenced |
| LTO | `Link-time optimisation enabled` at configure time |

`_FORTIFY_SOURCE` is only defined above `-O0`, because it is a no-op without
optimisation. A build that "enables" it at `-O0` has enabled nothing.

## 5. Findings

Three real defects were found and fixed during this audit. All three are
regression-tested; two are captured as named unit tests and one as a named
assertion in the integration script.

### F1: Config round-trip silently truncated a DNS list (found by fuzzing)

`fuzz_config` asserts that a profile which parses also survives
`serialize → parse` unchanged. It found an input that did not.

DNS search domains were stored unvalidated. A `#` **immediately after a comma**
(`DNS = foo,#bar`) is not treated as a comment on the way in, because comment
stripping requires whitespace before the `#`. But the serialiser joins list
entries with `", "`, adding exactly that whitespace, so on the way back out
the `#bar` was stripped as a comment and the entry vanished.

**Impact:** a profile that a provider issued could lose a DNS search domain
without the user ever seeing it. Silent, and a DNS-leak-flavoured failure.

**Fix:** `is_valid_search_domain` (`core/src/types.cpp`) validates every entry,
and the parser now **errors** on an invalid one instead of storing it.

**Regression test:** `rejects_dns_entries_that_would_break_the_round_trip` in
`tests/config_test.cpp`, using the reduced reproducer.

### F2: A newline in a verb could forge a response or split a log (found by fuzzing)

`fuzz_ipc` found that a leading newline survived request parsing (the trim
handled only `' '` and `'\t'`), so a newline stayed attached to the verb.

The more serious part: the helper echoed the raw verb into both the response and
the log line. A verb containing a newline could therefore **fabricate a second
protocol response**, or **split a log entry**, so that whoever read the log saw a
forged record and the real one was buried.

**Impact:** response forgery against a client that trusts the helper, and log
integrity loss. The second of those is worse, because it hides activity rather
than inventing it.

**Fix:** trim on full `isspace`; `is_valid_verb` is checked before dispatch;
`sanitize_for_display` is applied in both the error response and `log_line`.

**Regression tests:** `sanitize_for_display_keeps_output_on_one_line`,
`sanitized_output_never_contains_a_control_character`, and
`knows_which_verbs_are_defined` in `tests/ipc_test.cpp`.

### F3: A client that wrote a request and closed got no answer (found by the integration test)

Building the end-to-end script immediately exposed this: some requests returned
nothing at all.

Two things combined. A client that writes and then closes (which is what
`printf 'PING\n' | socat - UNIX-CONNECT:...` does, and what any shell script or
one-shot tool does) delivers its bytes and its hangup together. Depending on
timing, `poll()` reports that as `POLLIN|POLLHUP`, or as `POLLHUP` with the data
still sitting in the socket buffer. Then:

- the event handler treated `POLLHUP` as "close now" and could close without
  draining, and
- `service_connection` returned on `read() == 0` **before** the loop that turns
  buffered lines into responses, discarding a request it had already accepted.

The GUI never saw this, because it holds one connection open and waits. Every
other way of talking to the daemon did.

**Impact:** intermittent silent failure. The request was dropped with no error
anywhere: not to the caller, and not in the log. A monitoring script would see
"no answer" and could not distinguish it from the daemon being down.

**Fix:** the event handler services a connection on a hangup as well as on
readability, and `service_connection` processes every complete buffered line
after the read loop ends, whatever ended it. `Service::KeepOpen`/`Close` now
makes the two outcomes explicit instead of overloading a `bool`.

**Regression test:** the integration script repeats a write-then-close exchange
25 times and requires all 25 answers. Reverting either half of the fix makes it
fail (reverting the drain check loses 17 of 25).

### Checked and found clean

- `cppcheck --enable=warning,performance,portability` over `core`, `helper`,
  `tests`, `fuzz` and `bench`: no findings. `app/` is excluded because
  cppcheck cannot resolve Qt's `Q_PROPERTY` macro without Qt's build settings;
  that is a tool limitation, not a clean result, and it is stated here rather
  than counted as a pass.
- 128 unit tests under clang ASan + UBSan: zero reports.
- `wispd`'s entire IPC surface (every verb, every rejection path, the 4000-byte
  request, the 64 KiB buffer ceiling) driven over a real socket with the helper
  itself built under ASan + UBSan: zero reports. This matters more than the unit
  run, because the privileged component is the one whose memory errors would be
  exploitable, and it is the part the unit tests cannot reach.
- Fuzzing, current build: 294,770 config runs, 723,474 netlink runs and 309,711
  IPC runs, with no new failures.
- One perf finding from `cppcheck` (`DnsEnvironment` passed by value) was fixed
  to a const reference.

## 6. Reproducing all of the above

```bash
# Unit tests (128 cases) and the end-to-end test (needs socat + python3)
cmake -S . -B build && cmake --build build -j"$(nproc)"
cd build && ctest --output-on-failure

# The end-to-end script on its own, with its output
./scripts/integration-test.sh

# Memory and undefined-behaviour checking
cmake -S . -B build-san -DCMAKE_CXX_COMPILER=clang++ -DWISP_SANITIZE=ON -DWISP_LTO=OFF
cmake --build build-san -j"$(nproc)" && ./build-san/tests/wisp_tests

# The same end-to-end script with the sanitised helper (no GUI in that build,
# so the GUI checks are skipped and the protocol surface is still covered)
WISP_BUILD_DIR=build-san ./scripts/integration-test.sh

# Fuzzing (Clang only). Three targets, three invariants.
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DWISP_BUILD_FUZZERS=ON -DWISP_LTO=OFF
cmake --build build-fuzz -j"$(nproc)"
./build-fuzz/fuzz/fuzz_config  -max_total_time=60 /tmp/wisp-corpus/config
./build-fuzz/fuzz/fuzz_netlink -max_total_time=60 /tmp/wisp-corpus/netlink
./build-fuzz/fuzz/fuzz_ipc     -max_total_time=60 /tmp/wisp-corpus/ipc

# Static analysis
cppcheck --enable=warning,performance,portability --std=c++20 --inline-suppr \
  -I core/include core/src helper bench tests fuzz

# Build hardening, checked in the binaries rather than assumed
readelf -h  build/helper/wispd | grep Type
readelf -lW build/helper/wispd | grep -E "GNU_RELRO|GNU_STACK"
readelf -d  build/helper/wispd | grep -E "BIND_NOW|FLAGS"
nm -u build/helper/wispd | grep __stack_chk_fail
nm -u build/core/libwisp_core.a | grep _chk

# Benchmarks (not a security tool - included because "fast" and "small" are
# the same property when the attack surface is what you are trying to shrink)
./build/bench/wisp_bench
```

### Fuzzer invariants

| Target | Invariant |
|---|---|
| `fuzz_config` | anything that parses must survive serialize → parse unchanged |
| `fuzz_netlink` | no decoder may read out of bounds, for any input |
| `fuzz_ipc` | a request must round-trip; a verb and name must be either valid or rejected; sanitised output must contain no control character |

## 7. Known limitations

This section is the point of the document. A threat model without one is a
brochure.

1. **No live tunnel has been verified on real hardware.** The container this was
   developed in has no WireGuard kernel module and no `CAP_NET_ADMIN`
   (`ip link add ... type wireguard` returns `RTNETLINK answers: Operation not
   permitted`). Everything netlink-side is verified by inspecting the encoded
   bytes in unit tests, and the bring-up sequence is verified against fakes.
   **Wisp could be entirely correct at the kernel interface, or entirely broken,
   and nothing in this repository can currently tell the difference.** This is
   the single largest gap, and it is why the integration test prints that it
   does not cover bring-up. It must be tested on a machine with a real WireGuard
   module before anyone relies on it.
2. **No independent review.** Everything here is self-assessment by the author
   plus automated tooling. Fuzzing, sanitizers and static analysis are not a
   penetration test; a real one needs adversarial humans who are not the author.
3. **No integrity check on the config directory.** `/etc/wisp/tunnels` is only
   writable by root, so this is inside the trust boundary. But there is no
   signature or hash over profiles, so a profile cannot be verified as the one
   the provider issued. A hostile profile is *contained*
   (§3.1, §3.2, §3.9) rather than *authenticated*.
4. **`wispd` has no seccomp filter.** A syscall allowlist is the obvious next
   hardening step and is missing for now: the netlink path cannot be
   tested in this environment, and a filter with one wrong entry would turn into
   a mysterious runtime failure on real hardware with no way to diagnose it
   here. Adding it is a recommendation for whoever first runs this on a machine
   that can carry packets.
5. **Compromise of the user's session means tunnel control.** That user may
   bring existing tunnels up and down. They still cannot supply configuration,
   read keys back out, or read any profile's contents through the helper. The
   asymmetry is deliberate.
6. **`mlockall` may fail.** If `RLIMIT_MEMLOCK` is too low, key material can
   reach swap. The failure is reported as a note on startup rather than being
   fatal, and the tradeoff is argued in §3.5.
7. **`--keep-privileges` exists and is gated.** It is for debugging, it
   skips the capability drop, and it refuses unless `WISP_ALLOW_KEEP_PRIVILEGES=1`
   (or `--dry-run`). An unbypassable footgun is worse than none.
8. **`SO_PEERCRED` is the privilege boundary.** It is a kernel guarantee, not a
   cryptographic one. A kernel bug or local root defeats it, which is why both
   are out of scope (§2).
9. **DNS coverage depends on the detected backend.** systemd-resolved,
   `resolvconf`, and a plain `/etc/resolv.conf` are supported; an unusual
   resolver setup may fall back to reporting that DNS was not applied. A split
   tunnel reports honestly and stays up; a full tunnel tears down instead.
10. **No key rotation, revocation, or audit trail by default.** Per-request
    verb logs are opt-in (`--verbose`); refusals and warnings still go to
    stderr. There is no record of who connected beyond that.
11. **Key parsing is not constant-time.** `decode_key` branches on the input.
    This is not a leak: the input is a value the caller already knows, and it is
    never compared against a secret. Only the *comparison* of secrets
    (`keys_equal`) is constant-time.

## 8. Reporting a vulnerability

Open a [security advisory](https://github.com/Satin-networks/wisp/security/advisories/new)
on the Satin Networks `wisp` repo, or contact the maintainer privately for
anything that should not be public before a fix exists.

Please include the version (`wisp-app` reports it in the UI), the build options,
and whether the issue is in the unprivileged client or in `wispd`. A
reproducer (especially one shaped like a test in `tests/`) is worth more than
a description.

There is no bug bounty and no paid programme, because there is no revenue.
That is a real limitation on how much scrutiny this code will attract, and it is
worth knowing before you decide how much to trust it.

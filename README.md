# Wisp

A [Satin Networks](https://github.com/Satin-networks) opsec project: a local
WireGuard tunnel manager with a native desktop interface.

No account. No cloud. No telemetry. Your keys and profiles stay in files on
your own machine.

Three layers. `wisp-app` (Qt6/QML, unprivileged) shows the interface and
stats. It talks to `wispd` (root, the only privileged component) over a unix
socket, one line per request: `UP home`, `DOWN home`, `STATUS home`. `wispd`
reads profiles from `/etc/wisp/tunnels` and configures the kernel WireGuard
module over generic netlink. The kernel does the actual cryptography.

## Why another WireGuard client?

Because nearly every existing option is a *platform*: an account, a management
server, a control plane you have to trust. Wisp is the other thing: a client
that manages the tunnels already on your disk and talks to nobody.

## Security model

This is the part worth reading, because a VPN client is a program that handles
keys and touches the network. `SECURITY.md` has the full threat model, the audit
findings, and (more usefully) the list of what is *not* protected.

**We do not implement WireGuard.** The kernel module does the cryptography and
packet handling. Wisp configures it over generic netlink. Writing our own
transport would mean writing our own crypto, which is how VPN clients leak
traffic.

**Keys come from libsodium.** Key generation, derivation and comparison use
libsodium's audited Curve25519 primitives. No custom cryptography anywhere.

**The privileged surface is one socket, one verb, one name.** The client can
send `UP <name>`, `DOWN <name>` or `STATUS <name>`. It cannot send a
configuration, a key, or a path. `wispd` reads profiles from a root-owned
directory and refuses any name that is not `[A-Za-z0-9_-]{1,15}`, which is the
entire defence against path traversal. If the client could supply
configuration, every parser bug would become a privilege-escalation bug.

**Config files are data, never code.** wg-quick profiles may contain `PostUp`
and `PreUp` shell hooks. Wisp parses and displays them so you can see what a
profile intends, and never executes them. Executing shell from a downloaded
`.conf` is remote code execution as root.

**The interface is raised last.** Bring-up creates the link, pushes the crypto
configuration, assigns addresses and adds routes while the link is still down,
and only then brings it up. There is no window in which packets could leave
through a tunnel that is not yet encrypting. Any failure removes the interface
again rather than leaving a half-configured one behind.

**Configuration is parsed strictly.** A single bad key, port or CIDR fails the
whole parse. A partially-applied tunnel configuration is a silent failure mode
that leaks traffic, so it is better to refuse than to guess.

## Status

Linux only, and complete enough to be used, with one large caveat, stated up
front and again at the bottom of this section.

**Working**

- Strict wg-quick profile parsing and serialisation, with round-trip tests
- WireGuard key generation and public-key derivation (libsodium)
- Full generic-netlink driver: device configuration, peer and allowed-IP
  encoding, endpoint resolution, device state and byte-counter decoding
- Bring-up and tear-down orchestration, including cleanup on failure
- **Full-tunnel profiles**, via policy routing: a firewall mark plus
  `ip rule add not fwmark N` and a suppressed main-table rule, reproducing
  wg-quick's `Table = auto` mechanism exactly so the two are interchangeable
- **DNS configuration applied** through systemd-resolved, `resolvconf`, or a
  plain `/etc/resolv.conf`, with a backup and a revert on teardown
- Privileged helper with a name-only IPC surface, `SO_PEERCRED` checks,
  capability narrowing and process hardening
- Qt6 interface: tunnel list, animated connect control, live throughput graph,
  rate and handshake statistics, keypair generation
- Hardened, sanitised and fuzzed builds; see `SECURITY.md`

**Not finished**

- **Live tunnels have not been exercised end to end.** The development
  environment for this code had no `CAP_NET_ADMIN` and no WireGuard module, so
  the netlink encoding is verified by inspecting bytes in unit tests and the
  bring-up sequence against fakes. **Nothing here proves it works against a real
  kernel.** Test it on real hardware before relying on it.
- **macOS and Windows.** The netlink driver and `SO_PEERCRED` are Linux
  interfaces. Other platforms need `wireguard-go`/`wireguard.dll` and a
  different privilege mechanism.
- **No systemd unit or polkit policy** for the helper yet; it is started by
  hand.
- **No key rotation or profile signing.** A profile is contained, not
  authenticated.

## Building

Requires a C++20 compiler, CMake 3.20+, libsodium, and Qt6 for the GUI.

```sh
sudo apt install build-essential cmake pkg-config libsodium-dev \
                 qt6-base-dev qt6-declarative-dev \
                 qml6-module-qtquick-window qml6-module-qtqml-workerscript

cmake -S . -B build
cmake --build build -j
```

Qt is optional: without it, CMake still builds the core library, the privileged
helper, the tests, the benchmarks and the fuzzers.

```sh
cmake -S . -B build -DWISP_BUILD_APP=OFF
```

### Build options

| Option | Default | Effect |
| --- | --- | --- |
| `WISP_HARDEN` | `ON` | stack protector, `_FORTIFY_SOURCE=2`, PIE, full RELRO, immediate binding |
| `WISP_LTO` | `ON` | link-time optimisation |
| `WISP_SANITIZE` | `OFF` | clang ASan + UBSan, forces a debug build |
| `WISP_BUILD_TESTS` | `ON` | unit suite and the end-to-end script |
| `WISP_BUILD_HELPER` | `ON` | `wispd` |
| `WISP_BUILD_APP` | `ON` | Qt6 GUI (skipped silently if Qt is absent) |
| `WISP_BUILD_BENCH` | `ON` | micro-benchmarks |
| `WISP_BUILD_FUZZERS` | `OFF` | libFuzzer targets (clang only) |

`SECURITY.md` has the commands that verify the hardening actually landed in the
binaries, rather than trusting the flags.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

Two tests are registered: 128 unit cases, and an end-to-end script that drives
`wispd` over a real socket and loads the GUI against it (the script needs
`socat` and `python3`, and is skipped at configure time if they are missing).
Run it on its own for its full output:

```sh
./scripts/integration-test.sh
```

The unit suite covers profile parsing (including the rejection cases that
matter: path-like names, shorthand addresses, unbracketed IPv6 endpoints, keys
in the wrong section), key handling, netlink message encoding and decoding, the
IPC protocol, and the bring-up ordering and cleanup behaviour. The integration
script covers the protocol surface, input validation, response integrity, and
the promise that hooks are never executed.

Both found real bugs: see the findings section of `SECURITY.md`. That is the
argument for having them.

## Running

`wispd` needs root, and needs `--uid` so it knows who may talk to it.

```sh
sudo mkdir -p /etc/wisp/tunnels
sudo cp my-tunnel.conf /etc/wisp/tunnels/home.conf
sudo chmod 600 /etc/wisp/tunnels/*.conf

# --dry-run validates profiles and serves the socket without touching netlink,
# which is useful on a machine with no WireGuard module.
sudo ./build/helper/wispd --uid "$SUDO_UID" --dry-run

./build/app/wisp-app
```

| `wispd` flag | Effect |
| --- | --- |
| `--socket PATH` | unix socket to listen on (default `/run/wisp/wispd.sock`) |
| `--config-dir DIR` | directory of `<name>.conf` profiles |
| `--uid UID` | the only non-root user allowed to connect (or `SUDO_UID`; strictly numeric) |
| `--dry-run` | parse and report, never touch netlink |
| `--no-dns` | never modify the system resolver |
| `--keep-privileges` | skip the capability drop (debugging only, requires `WISP_ALLOW_KEEP_PRIVILEGES=1`) |
| `--verbose` | log every request (default: warnings/errors only, no activity timeline) |
| `--fail-closed` | hostname/single-stack profiles fail instead of warn; full-tunnel DNS failure always tears down |

The GUI accepts `--socket PATH`, or reads `WISP_SOCKET` from the environment.

A profile is a standard wg-quick file. Keys, `Address`, `AllowedIPs`, `Endpoint`
and `PersistentKeepalive` work as you would expect; `Table = auto` turns on
full-tunnel policy routing, `Table = off` installs no routes at all and leaves
routing to you, and `DNS` is applied on connect and reverted on disconnect.
`PreUp`/`PostUp`/`PreDown`/`PostDown` are shown in the interface and never run.
`docs/PROVIDERS.md` holds ten free providers with honest grades; only the A
grades meet a serious opsec bar.

## Performance

`./build/bench/wisp_bench` times the work Wisp does itself: parsing, netlink
encoding and decoding, and IPC validation. It leaves out the syscalls
and kernel work of a real bring-up, which is where nearly all the wall-clock
time actually goes, so the numbers below are a floor on cost, not a total.

Measured with a hardened Release build (GCC 13.3, LTO) on a shared container.
Single thread, best of five runs. Expect ±15% between runs on a shared machine;
these are for spotting regressions, not for quoting as a specification.

| Operation | Cost |
| --- | --- |
| `parse_config`, typical split profile (1.1 KB, 24 prefixes) | ~14 µs |
| `parse_config`, profile that fails on its last line | ~8 µs |
| `parse_config`, worst case (39 KB, 32 peers, 2048 prefixes) | ~0.56 ms |
| `Cidr::parse`: IPv4 / IPv6 | 193 ns / 288 ns |
| `Endpoint::parse` | 78 ns |
| `serialize_config` | ~22 µs |
| `build_set_device` | ~85 µs |
| `build_create_link`, `build_address`, `build_route` | 240-370 ns |
| `build_rule` (policy routing) | ~250 ns |
| `parse_device`, 32 peers | ~89 µs |
| whole path, no syscalls: parse → plan → encode | ~0.21 ms |

What this says:

- The whole client-side cost of a realistic bring-up is a fraction of a
  millisecond. It is invisible next to the netlink round trips it leads to.
- Parsing is **linear** in the number of prefixes, and dominated by
  `Cidr::parse`: at 193 ns for an IPv4 entry it accounts for roughly 70% of the
  ~270 ns each `AllowedIPs` entry costs end to end. A 2048-prefix profile is
  pathological, and it still parses in about half a millisecond.
- Decoding a kernel reply is roughly as expensive as encoding the configuration
  that produced it, which is why the GUI polls byte counters instead of
  re-reading the whole device state, and why `STATUS` returns a compact
  one-line summary rather than a serialised device.
- Anything reported at or below the ~0.6 ns/op measurement floor is dominated
  by loop overhead. The benchmark prints that floor next to its results so those
  figures can be read as "free" rather than as an exact cost.

`public_key_from_private` costs about 33 µs, which is worth knowing: it is why
the public key is derived once when a keypair is generated and cached, rather
than derived per frame.

## Layout

| Path | Contents |
| --- | --- |
| `core/` | Config parser, key handling, netlink driver, IPC, routing plan, DNS, bring-up logic |
| `helper/` | `wispd`, the privileged daemon |
| `app/` | Qt6 QML interface, controller, `Theme.qml` (5 themes × 6 accents) |
| `tests/` | Unit suite, no external test framework |
| `fuzz/` | libFuzzer targets and the invariants they check |
| `bench/` | Micro-benchmarks |
| `providers/` | Free-provider list (`docs/PROVIDERS.md`) plus a fill-in `template.conf` |
| `scripts/` | End-to-end integration test |
| `docs/` | Operator, profile, development, and architecture guides |
| `LICENSE` | MIT licence |
| `SECURITY.md` | Threat model, hardening evidence, audit findings, limitations |

The interface searches, sorts (Name/Fastest) and connects the fastest tunnel
from profiles already on disk. Fastest is memory-only live handshake +
throughput scoring: no probing, no downloads, no telemetry. To use free
servers, download their wg-quick `.conf` files yourself, check with
`wispd --dry-run --fail-closed`, then `sudo cp` + `chmod 600` into the tunnel
directory. Wisp never fetches server lists on its own: a bundled free list
would be unaudited exit nodes with unknown logging.

The core library has no Qt dependency, which is why the helper stays small and
the whole thing is testable without a display.

## Roadmap

1. Verify a live tunnel on real hardware, and use that to add a seccomp filter
   to `wispd`
2. systemd unit and polkit policy for the helper
3. Profile signing, so a profile can be authenticated rather than just contained
4. `ip rule` support for split routing by interface
5. macOS and Windows backends

## Licence

MIT, see `LICENSE`. Copyright Satin Networks.

WireGuard is a registered trademark of Jason A. Donenfeld. Wisp is an
independent client and is not affiliated with the WireGuard project.

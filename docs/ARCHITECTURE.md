# Wisp architecture

Wisp is two processes and a kernel module. The UI asks for tunnels by name.
The helper reads profiles from disk and configures the kernel. Nothing else
crosses the privilege boundary.

```
wisp-app (Qt6/QML, user)  --UP home-->  wispd (root, CAP_NET_ADMIN)  --netlink-->  kernel WireGuard
```

## Processes

`wisp-app` never touches netlink, never reads the config directory, and never
sends configuration anywhere. It can say `UP <name>`, `DOWN <name>`,
`STATUS <name>`, `LIST`, or `PING`. That is the whole protocol, one line per
request, one line per reply (`OK ...` / `ERR ...`).

`wispd` is the only privileged piece. It binds a `0600` socket owned by the
allowed uid, checks every peer with `SO_PEERCRED`, then drops everything but
`CAP_NET_ADMIN` (plus `NO_NEW_PRIVS`, non-dumpable, no core dumps,
`mlockall`). It reads `<name>.conf` from the config directory itself, so a
parser bug is not a privilege bug: the client cannot feed the parser input.

## Bring-up order

Create link (down) → push crypto config → assign addresses → add routes →
raise link → install policy rules → apply DNS. The link goes up late so no
packet can leave through a tunnel that is not encrypting yet. Any failure
deletes the link again instead of leaving half a tunnel behind.

Full tunnels (`AllowedIPs` covering `0.0.0.0/0` or `::/0`) use policy routing:
an fwmark plus an inverted-mark rule, the same mechanism as wg-quick's
`Table = auto`. Split tunnels just add specific routes to the main table.
`Table = off` installs no routes at all.

DNS goes through systemd-resolved, `resolvconf`, or a backed-up
`/etc/resolv.conf` rewrite (last resort, atomic rename, `0600` backup).
Hook keys (`PreUp`/`PostUp`/...) are parsed for display and never executed.
A full tunnel whose DNS step fails is torn down; a split tunnel stays up
with a warning.

## Where things live

| Path | What |
| --- | --- |
| `core/` | Parser, keys (libsodium), netlink codec, IPC, routing plan, DNS, orchestration. No Qt. |
| `helper/` | `wispd`. Small enough to read in one sitting. |
| `app/` | Qt6/QML UI and `WispController`. Theme choice is the only thing written to disk. Tunnel scores for Fastest are memory-only. |
| `app/qml/Theme.qml` | 5 themes × 6 accents, no network, no persistence of its own. |
| `tests/` | Unit suite (no framework) plus `integration_test.py` helpers. |
| `scripts/integration-test.sh` | End-to-end over a real socket with `--dry-run` (no netlink, no root needed). |
| `fuzz/` | libFuzzer targets: config round-trip, netlink bounds, IPC shape. |
| `bench/` | Micro-benchmarks for parse/encode/decode. |

## What Wisp is not

Not a VPN provider. There are no servers, accounts, or subscriptions here,
so compare against `wg-quick`, not against Mullvad or Proton. What Wisp adds
over `wg-quick`: configs are data (hooks never run), the privileged half is
one capability instead of a root shell script, and the UI cannot supply
configuration at all.

See `SECURITY.md` for the threat model, the audit findings, and the gaps
that remain (no live-tunnel verification yet, no seccomp filter, no profile
signing).

# Profiles

A profile is a wg-quick style file: an `[Interface]` section plus one
`[Peer]` section per peer. Key names are case-insensitive and `_`/`-`
are ignored, so `PrivateKey`, `private_key`, and `privatekey` all work.

One bad line fails the whole file. There are no partial applies: a tunnel
that is half configured leaks traffic without telling anyone, so the parser
refuses instead. Errors carry line numbers, and the first error wins.

## [Interface] keys

| Key | Meaning |
| --- | --- |
| `PrivateKey` | Required. 32-byte base64 Curve25519 key. |
| `Address` | Comma list of CIDRs assigned to the interface, e.g. `10.7.0.2/32, fd00:7::2/128`. Bare addresses become host routes. Shorthand (`10.1`, octal) rejected. |
| `DNS` | Comma list mixing resolver IPs and search domains. Only IP literals are used as resolvers; the rest must be valid domain names. Anything else fails the file. |
| `ListenPort` | 1-65535. Optional. |
| `MTU` | Optional, passed to link creation. |
| `FwMark` | Optional mark, decimal or `0x` hex. Overridden by the policy-routing mark on full tunnels. |
| `Table` | `auto` (policy routing table 51820), `off` (Wisp installs no routes), or a numeric table id. Default: main table for split tunnels, `auto` behaviour for full tunnels. |
| `SaveConfig` | Parsed and stored, `true`/`false`. informational. |
| `PreUp`, `PostUp`, `PreDown`, `PostDown` | Parsed so the UI can show them. Never executed. Each one adds a warning. |

## [Peer] keys

| Key | Meaning |
| --- | --- |
| `PublicKey` | Required per peer. 32-byte base64 key. |
| `PresharedKey` | Optional 32-byte base64 key. |
| `Endpoint` | `host:port`. IPv6 literals must be bracketed: `[2001:db8::1]:51820`. A bare hostname is accepted but resolved with the system resolver before the tunnel exists, which discloses the destination in the clear. Prefer IP literals; `--fail-closed` refuses hostnames outright. |
| `AllowedIPs` | Comma list of CIDRs routed into the tunnel. Any `0.0.0.0/0` or `::/0` makes it a full tunnel. |
| `PersistentKeepalive` | 0-65535 seconds. Explicit 0 means off. |

Keys in the wrong section are errors, not warnings. Unknown keys are ignored
with a warning. A file with no peers parses with a warning and carries no
traffic.

## DNS entries in detail

`DNS = 10.64.0.1, internal` gives one resolver and one search domain.
Resolvers must be IP literals so a value can never read as a command-line
flag downstream. Search domains allow letters, digits, `.`, `-`, `_`, and a
leading `~` (systemd-resolved routing domain). Leading `-`/`.`, whitespace,
`/`, `;`, quotes, and anything over 253 characters fail the file.

## Table semantics

- Split tunnel (no `0.0.0.0/0` or `::/0`): specific routes go to the main
  table, unless `Table` names another one. No policy rules.
- Full tunnel: routes go to the policy table and two rules per family are
  installed (`table main suppress_prefixlength 0` plus `not fwmark <mark>`),
  mirroring wg-quick exactly.
- `Table = off`: no routes, no rules. Routing is yours. DNS is still applied
  if the profile sets it, so double-check that combination.

## Dry-run fields

`UP <name>` against a `--dry-run` helper answers:

```
OK valid: addresses=N peers=N hooks=0/1 full_tunnel=0/1 table=N policies=0/1
  warnings=N hostnames=N single_stack=0/1
```

`hostnames` counts endpoints needing cleartext DNS. `single_stack` flags a
full tunnel covering one family only (the other family's traffic stays
outside the tunnel). Aim for `warnings=0 hostnames=0 single_stack=0` before
relying on a profile.

## Importing free configs safely

Free server lists are hostile input until proven otherwise. For each file:

1. `wispd --dry-run --fail-closed`, then `UP <name>`. Refusals here are the
   tool doing its job.
2. Read every warning. Hooks mean the issuer expected shell; hostnames mean
   cleartext resolution; `single_stack` means a leak on the uncovered family.
3. Only then copy into place: `sudo cp x.conf /etc/wisp/tunnels/` and
   `sudo chmod 600 /etc/wisp/tunnels/*.conf`.

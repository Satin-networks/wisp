# Free providers that work with Wisp

Wisp never fetches server lists, so this file is a curated starting point,
not a feed. Every entry needs a human to create an account (where required),
pull a WireGuard profile from the provider, and import it by hand. Plans
change, so confirm free terms on the homepage before relying on them.

Rule of thumb: only the A grades below meet a serious opsec bar
(independently audited, stated no-logs policy, free tier). B means usable
with eyes open. C means do not route sensitive traffic through it. Two
entries are here to stop bad ideas: they are incompatible or explicitly
logging, and they say so.

## The list

| # | Provider | Free terms (confirm) | Account | WireGuard path | Opsec note | Grade |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Proton VPN Free (protonvpn.com) | Free tier, unlimited bandwidth, slower speeds | Required | Official apps speak WireGuard; manual wg-quick export is not guaranteed on free accounts, verify | Swiss, audited, no-logs | A |
| 2 | Windscribe Free (windscribe.com) | 10 GB/month free | Required | Apps support WireGuard; config generator availability varies by account, verify | Published third-party audits; confirm currency | A |
| 3 | TunnelBear Free (tunnelbear.com) | 2 GB/month free | Required | Apps use WireGuard; manual export unverified | Annual independent audits, well documented | A |
| 4 | Hide.me Free (hide.me) | 10 GB/month free | Historically none needed, verify | Apps support WireGuard; manual export unverified | Claims no-logs; audit record thinner than the As | B |
| 5 | PrivadoVPN Free (privadovpn.com) | 10 GB/month free | Required | Apps support WireGuard; manual export unverified | Swiss-based, claims no-logs; no major public audit found | B |
| 6 | Cloudflare WARP (1.1.1.1) | Free, unlimited | None | WireGuard-derived protocol; wg-quick files via the community `wgcf` tool (unofficial, verify) | Cloudflare collects diagnostics per its policy; a CDN sees your exit traffic | B |
| 7 | Hotspot Shield Basic (hotspotshield.com) | Free tier, ad-supported | Required | Manual WireGuard export unverified | Free tier history includes ads and logging criticism | C |
| 8 | Avira Phantom Free (avira.com) | 500 MB/month free | Required | Manual WireGuard export unverified | Thin public audit record; tiny quota makes it a backup at best | C |
| 9 | RiseupVPN (riseup.net) | Free, no account, activist-run | None | None: OpenVPN only, incompatible with Wisp | Listed so nobody wastes an afternoon: trustworthy people, wrong protocol | C |
| 10 | VPN Gate (vpngate.net) | Free academic experiment | None | Mostly OpenVPN/L2TP; WireGuard rare to absent | Volunteer exits that keep logs by design. Reference only, never for sensitive traffic | C |

## Importing one

1. Sign up (if needed) on the provider homepage, never through a mirror or
   a "free configs" aggregator.
2. Export a WireGuard profile. If the provider only offers its own app and
   no file export, stop: pasting keys out of app storage by hand is error
   prone and usually violates the provider's terms.
3. Save it as `providers/.work/<name>.conf` (git-ignored scratch), then run
   the checks in `docs/PROFILES.md`: `--dry-run --fail-closed`, zero
   warnings, zero hostnames, zero single-stack.
4. `sudo cp providers/.work/<name>.conf /etc/wisp/tunnels/` and
   `sudo chmod 600 /etc/wisp/tunnels/*.conf`. Delete the scratch copy.

## What "safe" does not cover

A green grade is about the provider's honesty and hygiene, not about your
threat model. Exit traffic is visible to the exit operator by definition.
Free tiers get fewer servers, more congestion, and more motive to monetize
attention. For anything that matters, a paid audited provider with WireGuard
file export beats every row above.

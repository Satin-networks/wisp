# Operating Wisp

This is the run-it-on-a-real-machine companion to the README. Install order:
profiles on disk first, helper second, UI last.

## 1. Profiles on disk

`wispd` reads `<name>.conf` from one directory, default `/etc/wisp/tunnels`.
When running as root it enforces the layout and refuses to start otherwise:

```
sudo mkdir -p /etc/wisp/tunnels
sudo chown root:root /etc/wisp/tunnels
sudo chmod 700 /etc/wisp/tunnels
sudo cp home.conf /etc/wisp/tunnels/home.conf
sudo chmod 600 /etc/wisp/tunnels/*.conf
```

Rules that bite newcomers:

- File names are tunnel names. Only `[A-Za-z0-9_-]`, 1 to 15 characters, no
  leading `-` or `.`. Anything else is never listed and never served, even if
  the file sits in the directory.
- No symlinks, no group/other-writable files or directories. A symlink like
  `home.conf -> /etc/shadow` reads as "no profile", not as a file.
- Profiles are standard wg-quick files. See `docs/PROFILES.md` for the exact
  key set and what fails validation.

Check a profile before trusting it:

```
sudo ./build/helper/wispd --uid "$SUDO_UID" --dry-run
# then over the socket: UP home
# look for: valid, warnings=0, hostnames=0, single_stack=0
```

`--dry-run` parses and reports without touching netlink, so it runs fine on a
machine with no WireGuard module.

## 2. Starting the helper

`wispd` needs root (it creates interfaces) and a decision about who may talk
to it:

```
sudo ./build/helper/wispd --uid "$SUDO_UID"
```

Flags:

| Flag | Effect |
| --- | --- |
| `--socket PATH` | unix socket (default `/run/wisp/wispd.sock`) |
| `--config-dir DIR` | profile directory (default `/etc/wisp/tunnels`) |
| `--uid UID` | the one non-root uid allowed to connect. Strictly numeric; also read from `SUDO_UID` under sudo |
| `--dry-run` | validate only, never touch netlink |
| `--no-dns` | leave the system resolver alone |
| `--verbose` | log every request. Default logs only startup, warnings, and refusals |
| `--fail-closed` | refuse hostname endpoints and single-stack full tunnels instead of reporting them |
| `--keep-privileges` | skip the capability drop. Debugging only, needs `WISP_ALLOW_KEEP_PRIVILEGES=1` |

There is no systemd unit or polkit policy in the repo yet. A minimal unit to
adapt looks like this:

```ini
[Unit]
Description=Wisp privileged helper
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wispd --uid 1000
Restart=on-failure
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

Replace `1000` with the real uid. `NoNewPrivileges=yes` mirrors what the
daemon sets on itself with `prctl`.

## 3. DNS behaviour

Backend is probed once at startup: systemd-resolved (`resolvectl`) first,
then `resolvconf`, then a direct `/etc/resolv.conf` rewrite (refused when the
file is a symlink), else none.

- Split tunnel, DNS apply fails: tunnel stays up, message says DNS was left
  unchanged. Read it; a tunnel on the wrong resolver leaks names.
- Full tunnel, DNS apply fails: tunnel is torn down (rules removed, link
  deleted). Fail-closed beats a silent leak.
- `--no-dns` skips the resolver entirely, up and down.

## 4. Confirming the hardening landed

Flags are claims until checked against the binaries:

```sh
readelf -h  build/helper/wispd | grep Type            # DYN (PIE)
readelf -lW build/helper/wispd | grep -E "GNU_RELRO|GNU_STACK"
readelf -d  build/helper/wispd | grep -E "BIND_NOW|FLAGS"
nm -u build/helper/wispd | grep __stack_chk_fail      # canary present
nm -u build/core/libwisp_core.a | grep _chk            # fortified libc calls
```

At runtime, `--verbose` for one session shows the capability drop line and
per-request verbs. Day to day, leave it off: quiet mode exists so routine
`STATUS` polling does not write an activity timeline to disk.

## 5. The UI

```
./build/app/wisp-app [--socket PATH]
```

`WISP_SOCKET` works too. The window polls byte counters over one persistent
socket, backs off when hidden, and scores tunnels from live handshake and
throughput for the Fastest sort. Scores live in memory only and vanish on
quit. Theme choice is the only thing written to disk
(`~/.config/Wisp/Wisp.conf`).

Copy-key buttons clear the clipboard after 30 seconds. The private key itself
is never shown as a property; generating or clearing wipes the stored copy.

## 6. Troubleshooting

- `helper not reachable`: socket path wrong, helper not running, or wrong uid.
  Run with `--verbose` once and read stderr.
- `ERR invalid tunnel name`: the name breaks the `[A-Za-z0-9_-]` rule or is
  over 15 characters. Rename the file.
- `ERR no profile named 'x'`: missing file, or the file failed the safety
  checks (symlink, permissions, ownership). `ls -l` the directory.
- `profile 'x' is invalid at line N`: strict parser, first error wins with a
  line number. Fix that line and revalidate with `--dry-run`.
- `could not create interface`: not root, no `CAP_NET_ADMIN`, or no WireGuard
  module (`is the wireguard module loaded?` in helper errors).
- DNS unchanged on a split tunnel: backend is `none`, or the profile DNS
  failed validation. Check `--verbose` output and `docs/PROFILES.md`.
- GUI shows a tunnel but `STATUS` says not running: the interface is gone
  (reboot, manual `ip link del`). Toggle the tunnel to rebuild it.

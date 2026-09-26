# Branches

Two branches, different jobs.

## main

The Linux product. Everything here builds, runs, and passes on Linux:
hardened `wispd`, the Qt interface, 129 unit cases, the end-to-end script,
sanitizers, fuzzers, and CI. Merge rule: nothing lands unless the full suite
is green, same as any other change.

## windows

The port workshop. Holds the Windows backend contract (`docs/WINDOWS.md`),
the transport seams as they get cut, and runnable checks a Windows 10 box
can execute and report back. Merge rule into `main`: nothing crosses over
except portable code proven on Linux first. Untested Win32 stays on this
branch until real hardware has run it.

## Status

| Piece | Where | State |
| --- | --- | --- |
| Backend contract and merge checklist | `docs/WINDOWS.md` | Written |
| Transport seam (`peer_uid`, `bind_listener`) | `helper/main.cpp`, branch `windows` | Cut, Linux-verified |
| Portability harness (`wisp_winverify`) | `platform/windows/`, branch `windows` | Passes on Linux (112 checks); awaiting first Windows 10 run |
| Named-pipe listener | branch `windows` | Not started |
| Data plane (`wireguard-go` spike) | branch `windows` | Not started, needs Windows hardware |

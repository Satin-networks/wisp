# Development

## Configure presets

```sh
# Default: hardened release, core + helper + GUI + tests + benches
cmake -S . -B build
cmake --build build -j"$(nproc)"

# No GUI (servers, containers, minimal deps)
cmake -S . -B build -DWISP_BUILD_APP=OFF

# Sanitizers: clang ASan + UBSan, debug build, LTO off
cmake -S . -B build-san -DCMAKE_CXX_COMPILER=clang++ \
  -DWISP_SANITIZE=ON -DWISP_LTO=OFF
cmake --build build-san -j"$(nproc)"

# Fuzzers: clang + libFuzzer only
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ \
  -DWISP_BUILD_FUZZERS=ON -DWISP_LTO=OFF
cmake --build build-fuzz -j"$(nproc)"
```

Build options (`-D` at configure time):

| Option | Default | Effect |
| --- | --- | --- |
| `WISP_HARDEN` | `ON` | Stack protector, `_FORTIFY_SOURCE=2`, PIE, full RELRO, immediate binding |
| `WISP_LTO` | `ON` | Link-time optimisation (off under sanitizers) |
| `WISP_SANITIZE` | `OFF` | Clang ASan + UBSan, forces Debug |
| `WISP_BUILD_TESTS` | `ON` | Unit suite plus integration script registration |
| `WISP_BUILD_HELPER` | `ON` | `wispd` |
| `WISP_BUILD_APP` | `ON` | Qt6 GUI, skipped silently when Qt6 is absent |
| `WISP_BUILD_BENCH` | `ON` | Micro-benchmarks |
| `WISP_BUILD_FUZZERS` | `OFF` | libFuzzer targets, clang only |

## Tests

Unit suite first, always. Bespoke macros (`WISP_TEST`, `WISP_CHECK`,
`WISP_CHECK_EQ` in `tests/wisp_test.hpp`), no external framework:

```sh
./build/tests/wisp_tests            # 129 cases
./build-san/tests/wisp_tests        # same, under ASan + UBSan
ctest --test-dir build --output-on-failure
```

The end-to-end script drives `wispd --dry-run` over a real socket (needs
`socat` and `python3`) and loads the GUI offscreen against it. Skipped at
configure time when pieces are missing:

```sh
./scripts/integration-test.sh
WISP_BUILD_DIR=build-san ./scripts/integration-test.sh   # sanitized helper
```

Netlink bring-up itself is tested against fakes (`tests/tunnel_test.cpp`),
because creating interfaces needs `CAP_NET_ADMIN` and a WireGuard module.
Nothing here proves the kernel path works; that check needs real hardware.

## Fuzzing

Three targets, three invariants:

| Target | Invariant |
| --- | --- |
| `fuzz_config` | Anything that parses must survive serialize and parse unchanged |
| `fuzz_netlink` | No decoder reads out of bounds, for any input |
| `fuzz_ipc` | Requests round-trip; verbs/names are valid or rejected; sanitised output has no control characters |

```sh
./build-fuzz/fuzz/fuzz_config  -max_total_time=60 /tmp/wisp-corpus/config
./build-fuzz/fuzz/fuzz_netlink -max_total_time=60 /tmp/wisp-corpus/netlink
./build-fuzz/fuzz/fuzz_ipc     -max_total_time=60 /tmp/wisp-corpus/ipc
```

## Static analysis and hardening evidence

```sh
cppcheck --enable=warning,performance,portability --std=c++20 --inline-suppr \
  -I core/include core/src helper bench tests fuzz
```

`app/` is excluded: cppcheck cannot resolve Qt's `Q_PROPERTY` without Qt's
build settings. That is a tool limit, stated, not a pass.

```sh
readelf -h  build/helper/wispd | grep Type
readelf -lW build/helper/wispd | grep -E "GNU_RELRO|GNU_STACK"
readelf -d  build/helper/wispd | grep -E "BIND_NOW|FLAGS"
nm -u build/helper/wispd | grep __stack_chk_fail
nm -u build/core/libwisp_core.a | grep _chk
```

## UI checks

Qt is optional for the build but not for the eye. The integration script runs
the real QML offscreen and fails on binding errors. To exercise every theme
and accent the same way:

```sh
mkdir -p /tmp/themecheck /tmp/themert && chmod 700 /tmp/themert
printf '[General]\nthemeName=%s\naccentName=%s\n' Glacier Sky > /tmp/themecheck/Wisp.conf
QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software \
  XDG_CONFIG_HOME=/tmp/themecheck XDG_RUNTIME_DIR=/tmp/themert \
  WISP_SOCKET=/nonexistent.sock timeout 2 ./build/app/wisp-app
```

Repeat across `availableThemes` × `availableAccents` in
`app/wispcontroller.cpp` and grep stderr for QML errors. New QML files go in
`app/qml/` and must be registered in `app/CMakeLists.txt` (`qt_add_resources`),
or they silently miss the binary.

## Benchmarks

```sh
./build/bench/wisp_bench
```

Client-side costs only (parse, encode, decode, IPC validation), no syscalls.
Best-of-five on the author's container; treat numbers as regression tripwires
with about 15% noise, not as a spec sheet.

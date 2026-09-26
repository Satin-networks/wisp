#!/usr/bin/env bash
#
# End-to-end check of the parts of Wisp that can be exercised without
# CAP_NET_ADMIN: the privileged helper's IPC surface, its input validation, and
# the GUI's ability to load against a live helper.
#
# Run from anywhere:  scripts/integration-test.sh
#
# The helper is started with --dry-run, so it parses profiles and reports what
# it *would* do but never touches netlink. That is what makes this runnable in a
# container, and it is also why passing here does not mean the tunnel works:
# see the "not covered" note at the bottom.

set -u

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${WISP_BUILD_DIR:-$root_dir/build}"
work_dir="$(mktemp -d /tmp/wisp-integration.XXXXXX)"
chmod 700 "$work_dir"
socket_path="$work_dir/wispd.sock"
config_dir="$work_dir/tunnels"
gui_stderr="$work_dir/gui-stderr.txt"

helper_pid=""
verbose_pid=""
passed=0
failed=0

cleanup() {
    if [[ -n "$helper_pid" ]]; then
        kill "$helper_pid" 2>/dev/null
        wait "$helper_pid" 2>/dev/null
    fi
    if [[ -n "$verbose_pid" ]]; then
        kill "$verbose_pid" 2>/dev/null
        wait "$verbose_pid" 2>/dev/null
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

# Assertions
check() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        printf '  ok   %s\n' "$label"
        passed=$((passed + 1))
    else
        printf '  FAIL %s\n' "$label"
        printf '         expected: %s\n' "$expected"
        printf '         actual:   %s\n' "$actual"
        failed=$((failed + 1))
    fi
}

check_contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        printf '  ok   %s\n' "$label"
        passed=$((passed + 1))
    else
        printf '  FAIL %s\n' "$label"
        printf '         expected to contain: %s\n' "$needle"
        printf '         actual:              %s\n' "$haystack"
        failed=$((failed + 1))
    fi
}

# Sends one request and returns the single response line, stripped of the
# trailing newline. Fails loudly if the helper answers with more than one line,
# which is exactly the response-splitting behaviour the sanitiser exists to
# prevent.
ask() {
    local request="$1"
    local reply
    # The newline is appended here rather than by the caller: a request is only
    # complete when the helper sees the terminator, and sending one without it
    # would test nothing but the peer hanging up mid-line.
    reply="$(printf '%s\n' "$request" | socat - "UNIX-CONNECT:$socket_path" 2>/dev/null)"
    if [[ "$(printf '%s' "$reply" | wc -l)" -gt 0 ]]; then
        printf 'MULTIPLE-LINES: %s\n' "$(printf '%s' "$reply" | tr '\n' '|')"
        return
    fi
    printf '%s' "$reply"
}

# Preconditions
if [[ ! -x "$build_dir/helper/wispd" ]]; then
    echo "missing $build_dir/helper/wispd - build first (cmake --build build)" >&2
    exit 2
fi
if ! command -v socat >/dev/null; then
    echo "socat is required for this script" >&2
    exit 2
fi

# The GUI is optional here: a helper-only build (no Qt, or a
# sanitised build) can still be driven through its whole protocol surface, and
# running the privileged component under ASan is worth more than the extra
# confidence the GUI check would add.
has_gui=0
[[ -x "$build_dir/app/wisp-app" ]] && has_gui=1

mkdir -p "$config_dir"

# Valid 32-byte keys, base64 encoded. Deterministic so expected output is
# reproducible; these are throwaway values, not secrets.
python3 - "$config_dir" <<'PYTHON'
import base64
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])

def key(seed):
    return base64.b64encode(bytes((seed + i) % 256 for i in range(32))).decode()

(directory / "home-office.conf").write_text(
    "[Interface]\n"
    f"PrivateKey = {key(0)}\n"
    "Address = 10.7.0.2/32, fd00:7::2/128\n"
    "DNS = 10.64.0.1\n"
    "MTU = 1420\n"
    "ListenPort = 51820\n"
    "Table = off\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {key(40)}\n"
    f"PresharedKey = {key(80)}\n"
    "Endpoint = vpn.example.com:51820\n"
    "AllowedIPs = 10.64.0.0/24\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {key(120)}\n"
    "Endpoint = 198.51.100.7:51820\n"
    "AllowedIPs = 192.168.1.0/24, fd00:64::/64\n"
)

(directory / "full-tunnel.conf").write_text(
    "[Interface]\n"
    f"PrivateKey = {key(1)}\n"
    "Address = 10.7.0.3/32\n"
    "Table = auto\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {key(41)}\n"
    "Endpoint = 198.51.100.9:51820\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
)

# Hooks are parsed and reported but never executed, so this profile must still
# come up cleanly; the hook only shows up as a warning.
(directory / "hooked.conf").write_text(
    "[Interface]\n"
    f"PrivateKey = {key(2)}\n"
    "Address = 10.7.0.4/32\n"
    "PostUp = cp /etc/shadow /tmp/leak\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {key(42)}\n"
    "AllowedIPs = 10.64.0.0/24\n"
)

# Fails on line 2, so the error must name that line.
(directory / "broken.conf").write_text(
    "[Interface]\n"
    "PrivateKey = not-a-valid-key\n"
    "Address = 10.7.0.5/32\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {key(43)}\n"
    "AllowedIPs = 10.64.0.0/24\n"
)

# Must be invisible to LIST: the name is not one a client could ever ask for.
(directory / "not a name.conf").write_text("[Interface]\n")

# Production requires root-owned 600 profiles; enforce the same here so the
# helper's permission checks are exercised rather than bypassed by umask.
for child in directory.iterdir():
    child.chmod(0o600)
directory.chmod(0o700)
PYTHON
chmod 700 "$config_dir"

# Start the helper
"$build_dir/helper/wispd" \
    --socket "$socket_path" \
    --config-dir "$config_dir" \
    --uid "$(id -u)" \
    --dry-run --no-dns \
    >"$work_dir/helper-stdout.txt" 2>"$work_dir/helper-stderr.txt" &
helper_pid=$!

for _ in $(seq 1 100); do
    [[ -S "$socket_path" ]] && break
    sleep 0.05
done
if [[ ! -S "$socket_path" ]]; then
    echo "the helper did not create its socket:" >&2
    cat "$work_dir/helper-stderr.txt" >&2
    exit 1
fi

echo "protocol"
check "PING is answered" "OK pong" "$(ask 'PING')"
check "LIST is sorted and hides unusable names" \
    "OK broken,full-tunnel,home-office,hooked" "$(ask 'LIST')"

echo
echo "input validation"
check "a name with a path separator is refused" "ERR invalid tunnel name" \
    "$(ask 'UP ../etc/passwd')"
check "an absolute path is refused" "ERR invalid tunnel name" "$(ask 'UP /etc/shadow')"
check "an empty name is refused" "ERR invalid tunnel name" "$(ask 'UP')"
check "an unknown verb is refused" "ERR unknown verb 'FROBNICATE'" "$(ask 'FROBNICATE')"
check "a hyphen-leading name is refused" "ERR invalid tunnel name" \
    "$(ask 'UP -oProxyCommand=evil')"
check "a name longer than IFNAMSIZ is refused" "ERR invalid tunnel name" \
    "$(ask 'UP aaaaaaaaaaaaaaaaaaaaaaaa')"

echo
echo "response integrity"
# Anything a caller puts in a verb is echoed back inside the error message, so
# it has to be neutralised first. A control character must not survive into the
# response: a raw newline there would let a caller fabricate a second reply.
# Every ask() above would already have reported MULTIPLE-LINES had that
# happened, which is what makes this a real check rather than a display one.
check "a control character in a verb is neutralised" "ERR unknown verb 'UP?X'" \
    "$(ask "$(printf 'UP\x01X')")"
check "two requests on one connection get two answers" \
    "OK pong|OK broken,full-tunnel,home-office,hooked" \
    "$(printf 'PING\nLIST\n' | socat - "UNIX-CONNECT:$socket_path" 2>/dev/null | tr '\n' '|' | sed 's/|$//')"

# A client that writes a request and immediately closes is the normal shape for
# a script, and it is the shape that used to lose the answer: the hangup could
# be reported in the same poll event as the data, or even without POLLIN, and
# closing on that discarded a request that was already sitting in the buffer.
# Whether poll() reports it that way depends on timing, so this repeats the
# exchange rather than trusting a single sample. Each round is a fresh
# connection, which is the only way to make the race likely instead of hoping
# for it.
missed=0
for _ in $(seq 1 25); do
    [[ "$(ask 'PING')" == "OK pong" ]] || missed=$((missed + 1))
done
if [[ $missed -eq 0 ]]; then
    printf '  ok   a write-then-close client is answered 25 times out of 25\n'
    passed=$((passed + 1))
else
    printf '  FAIL a write-then-close client lost its answer %s times out of 25\n' "$missed"
    failed=$((failed + 1))
fi

# A caller must not be able to make the helper reflect unbounded input back at
# it. The cap is 32 characters, so a reply of roughly that size proves the echo
# is bounded rather than copied.
long_verb="$(printf 'a%.0s' $(seq 1 4000))"
long_reply="$(ask "$long_verb")"
if [[ ${#long_reply} -le 64 && "$long_reply" == "ERR unknown verb '"* ]]; then
    printf '  ok   a 4000-byte verb is echoed back truncated (%s bytes)\n' "${#long_reply}"
    passed=$((passed + 1))
else
    printf '  FAIL a 4000-byte verb produced a %s-byte reply\n' "${#long_reply}"
    failed=$((failed + 1))
fi

echo
echo "profiles (dry run)"
check_contains "a split tunnel validates" \
    "OK valid: addresses=2 peers=2 hooks=0 full_tunnel=0 table=254 policies=0" \
    "$(ask 'UP home-office')"
check_contains "Table = auto is recognised as a full tunnel" \
    "OK valid: addresses=1 peers=1 hooks=0 full_tunnel=1 table=51820 policies=1" \
    "$(ask 'UP full-tunnel')"
check "a malformed profile names the offending line" \
    "ERR profile 'broken' is invalid at line 2: PrivateKey is not a valid 32-byte base64 key" \
    "$(ask 'UP broken')"
check "a missing profile is reported plainly" "ERR no profile named 'nope'" "$(ask 'UP nope')"
check "STATUS on a tunnel that is not up is an error" "ERR not running" "$(ask 'STATUS home-office')"

# The hook must be reported as a warning rather than executed. If Wisp ever ran
# it, /tmp/leak would appear - so check for the file directly rather than
# trusting the exit status.
rm -f /tmp/leak
hook_reply="$(ask 'UP hooked')"
check_contains "a hook is accepted and reported as a warning" "warnings=1" "$hook_reply"
if [[ -e /tmp/leak ]]; then
    printf '  FAIL a PostUp hook was executed\n'
    failed=$((failed + 1))
    rm -f /tmp/leak
else
    printf '  ok   no hook was executed\n'
    passed=$((passed + 1))
fi

echo
echo "gui"
if [[ $has_gui -eq 0 ]]; then
    printf '  skip no GUI in %s - the helper is still fully exercised above\n' "$build_dir"
fi
# Loads the real QML against the running helper. Any QML error - a typo in a
# binding, a missing property, an undefined signal handler - is printed to
# stderr, so a silent stderr means the whole tree actually bound.
# XDG_RUNTIME_DIR is given a real value so Qt has nothing to complain about;
# otherwise it prints a notice about defaulting, which would drown out the
# diagnostics this check is actually looking for.
mkdir -p "$work_dir/runtime"
chmod 700 "$work_dir/runtime"
if [[ $has_gui -eq 1 ]]; then
    timeout 4 env \
        QT_QPA_PLATFORM=offscreen \
        QT_QUICK_BACKEND=software \
        XDG_RUNTIME_DIR="$work_dir/runtime" \
        WISP_SOCKET="$socket_path" \
        "$build_dir/app/wisp-app" >/dev/null 2>"$gui_stderr"
    gui_status=$?
    # 124 is timeout's own exit code, which is the expected outcome of asking a
    # GUI to run for four seconds.
    if [[ $gui_status -ne 124 && $gui_status -ne 0 ]]; then
        check "the gui exited cleanly" "0 or 124" "$gui_status"
    fi

    # A QML binding that references something that does not exist is reported
    # here and nowhere else - the window still opens and still looks plausible.
    # So this looks for the errors specifically rather than requiring a silent
    # stderr, which would make the check fail on unrelated Qt notices.
    gui_errors="$(grep -Ei 'typeerror|referenceerror|is not a function|unable to assign|cannot assign|is not defined|qml:[0-9]+|no such signal|Unknown method|Cannot read property' "$gui_stderr" || true)"
    if [[ -n "$gui_errors" ]]; then
        check "the gui loaded without QML errors" "" "$gui_errors"
    else
        printf '  ok   the gui loaded without QML errors\n'
        passed=$((passed + 1))
    fi

    # Anything else on stderr is reported without failing: it is context, not a
    # verdict, and Qt is entitled to its own notices.
    if [[ -s "$gui_stderr" ]]; then
        printf '  note gui stderr: %s\n' "$(tr '\n' ' ' <"$gui_stderr")"
    fi
fi

# The GUI is a client of the same socket, so it must not have disturbed it.
# Checked in both builds: a GUI that breaks the connection it shares is a bug
# whether or not this particular build has a GUI to run.
check "the helper is still healthy after the GUI check" "OK pong" "$(ask 'PING')"

echo
echo "helper invariants"
# The helper refuses to run without an explicit decision about who may connect.
if "$build_dir/helper/wispd" --socket "$work_dir/x.sock" --config-dir "$config_dir" \
    >/dev/null 2>&1; then
    printf '  FAIL the helper started with no --uid when SUDO_UID is unset\n'
    failed=$((failed + 1))
else
    printf '  ok   the helper refuses to start without --uid or SUDO_UID\n'
    passed=$((passed + 1))
fi

# Per-request logging is opt-in: quiet by default so STATUS polling does not
# write an activity timeline to disk.
if grep -q "PING -> ok" "$work_dir/helper-stderr.txt"; then
    printf '  FAIL per-request logging should be quiet by default\n'
    failed=$((failed + 1))
else
    printf '  ok   per-request logging is quiet by default\n'
    passed=$((passed + 1))
fi
check_contains "startup is still logged" "listening on" \
    "$(cat "$work_dir/helper-stderr.txt")"

# --verbose restores per-request lines, sanitised to one line.
"$build_dir/helper/wispd" \
    --socket "$work_dir/verbose.sock" \
    --config-dir "$config_dir" \
    --uid "$(id -u)" \
    --dry-run --no-dns --verbose \
    >"$work_dir/verbose-out.txt" 2>"$work_dir/verbose-err.txt" &
verbose_pid=$!
for _ in $(seq 1 100); do
    [[ -S "$work_dir/verbose.sock" ]] && break
    sleep 0.05
done
verbose_reply="$(printf 'PING\n' | socat - "UNIX-CONNECT:$work_dir/verbose.sock" 2>/dev/null)"
check "verbose helper answers" "OK pong" "$verbose_reply"
check_contains "verbose mode logs the verb sanitised" "PING -> ok" \
    "$(cat "$work_dir/verbose-err.txt")"
kill "$verbose_pid" 2>/dev/null
wait "$verbose_pid" 2>/dev/null

# Strict --uid parsing rejects non-numeric input rather than truncating to 0.
if "$build_dir/helper/wispd" --socket "$work_dir/x.sock" --config-dir "$config_dir" \
    --uid "abc" --dry-run >/dev/null 2>&1; then
    printf '  FAIL invalid --uid was accepted\n'
    failed=$((failed + 1))
else
    printf '  ok   invalid --uid is rejected\n'
    passed=$((passed + 1))
fi

# --fail-closed refuses hostname endpoints that would leak DNS in the clear.
check_contains "dry run reports hostname endpoints" "hostnames=1" "$(ask 'UP home-office')"

# Exit codes: help and version succeed without a uid, anything else fails.
check_exit() {
    local label="$1" expected="$2"
    shift 2
    "$@" >/dev/null 2>&1
    local status=$?
    if [[ "$status" -eq "$expected" ]]; then
        printf '  ok   %s\n' "$label"
        passed=$((passed + 1))
    else
        printf '  FAIL %s (exit %s, want %s)\n' "$label" "$status" "$expected"
        failed=$((failed + 1))
    fi
}

check_exit "--help exits 0 without --uid" 0 "$build_dir/helper/wispd" --help
check_exit "-h exits 0 without --uid" 0 "$build_dir/helper/wispd" -h
check_exit "--version exits 0 without --uid" 0 "$build_dir/helper/wispd" --version
check_exit "unknown flag exits nonzero" 2 "$build_dir/helper/wispd" --bogus --uid "$(id -u)"
check_exit "missing --uid exits nonzero" 2 env -u SUDO_UID "$build_dir/helper/wispd" --dry-run
check_contains "--version prints the daemon name" "wispd " \
    "$("$build_dir/helper/wispd" --version 2>/dev/null)"

echo
echo "$passed passed, $failed failed"
echo
echo "not covered here: a real tunnel. Without CAP_NET_ADMIN and the wireguard"
echo "module there is no interface to create, so bring-up, routing policy and"
echo "DNS application are only exercised in the unit tests, against fakes."

[[ $failed -eq 0 ]]

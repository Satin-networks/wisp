// wispd - the privileged half of Wisp.
//
// Everything that needs CAP_NET_ADMIN lives here, and nothing else does. The
// client is unprivileged and can send only a verb and a tunnel *name*. It can
// never send a configuration, a key, or a path: configuration is read from a
// directory only root can write.
//
// That single restriction is what keeps this daemon small enough to audit. If
// the client could supply configuration, every mistake in the parser would
// become a privilege-escalation bug.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "wisp/config.hpp"
#include "wisp/dns.hpp"
#include "wisp/ipc.hpp"
#include "wisp/keys.hpp"
#include "wisp/netlink.hpp"
#include "wisp/tunnel.hpp"

namespace {

constexpr std::size_t kMaxRequestBytes = 4096;

// A peer that keeps sending without ever completing a line must not be able to
// grow our buffer without bound. 64 KiB is far more than any legitimate request
// (the longest is a verb plus a 15-character name).
constexpr std::size_t kMaxBufferedBytes = 64 * 1024;

// How long to wait for a socket to drain before giving up on a peer that has
// stopped reading. Bounded so one stuck client cannot pin the daemon.
constexpr int kWriteTimeoutMs = 2000;

// Persistent connections are cheap, but the list still needs a ceiling: the
// accept loop is single-threaded, so an unbounded set of sockets is a cheap
// resource-exhaustion primitive for whoever holds the allowed uid.
constexpr std::size_t kMaxConnections = 32;

volatile std::sig_atomic_t g_running = 1;

void handle_signal(int) { g_running = 0; }

void log_line(const std::string& message) { std::cerr << "wispd: " << message << "\n"; }

bool g_verbose = false;

void verbose_log(const std::string& message) {
    if (g_verbose) log_line(message);
}

std::optional<uid_t> parse_uid_strict(const char* text) {
    if (text == nullptr || *text == '\0') return std::nullopt;
    for (const char* p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return std::nullopt;
    }
    errno = 0;
    const unsigned long value = std::strtoul(text, nullptr, 10);
    if (errno != 0 || value > 4294967295ul) return std::nullopt;
    return static_cast<uid_t>(value);
}

bool is_ip_literal(const std::string& host) {
    in_addr v4{};
    in6_addr v6{};
    return ::inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool dir_is_secure(const std::string& path) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) return false;
    if (!S_ISDIR(info.st_mode)) return false;
    if (S_ISLNK(info.st_mode)) return false;
    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) return false;
    if (::geteuid() == 0 && info.st_uid != 0) return false;
    return true;
}

struct Options {
    std::string socket_path = wisp::ipc::kDefaultSocketPath;
    std::string config_dir = wisp::ipc::kDefaultConfigDir;
    std::optional<uid_t> allowed_uid;
    bool dry_run = false;
    bool no_dns = false;
    bool keep_privileges = false;
    bool verbose = false;
    bool fail_closed = false;
    bool version = false;
    bool help = false;
};

void print_usage(std::ostream& out) {
    out << "usage: wispd [--socket PATH] [--config-dir DIR] [--uid UID]\n"
        << "             [--dry-run] [--no-dns] [--keep-privileges]\n"
        << "             [--verbose] [--fail-closed]\n"
        << "\n"
        << "  --socket PATH       unix socket to listen on (default "
        << wisp::ipc::kDefaultSocketPath << ")\n"
        << "  --config-dir DIR    directory of <name>.conf profiles (default "
        << wisp::ipc::kDefaultConfigDir << ")\n"
        << "  --uid UID           the only non-root user allowed to connect\n"
        << "  --dry-run           parse and report, but never touch netlink\n"
        << "  --no-dns            never modify the system resolver\n"
        << "  --keep-privileges   do not drop capabilities (for debugging)\n"
        << "  --verbose           log every request (default: warnings/errors only)\n"
        << "  --fail-closed       hostname/single-stack profiles fail instead of warn\n"
        << "  --version           print the version and exit\n";
}

std::optional<Options> parse_arguments(int argc, char** argv) {
    Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto next_value = [&]() -> std::optional<std::string> {
            if (i + 1 >= argc) return std::nullopt;
            return std::string(argv[++i]);
        };

        if (argument == "--help" || argument == "-h") {
            options.help = true;
        } else if (argument == "--dry-run") {
            options.dry_run = true;
        } else if (argument == "--no-dns") {
            options.no_dns = true;
        } else if (argument == "--keep-privileges") {
            options.keep_privileges = true;
        } else if (argument == "--verbose") {
            options.verbose = true;
        } else if (argument == "--fail-closed") {
            options.fail_closed = true;
        } else if (argument == "--version") {
            options.version = true;
        } else if (argument == "--socket") {
            const auto value = next_value();
            if (!value) return std::nullopt;
            options.socket_path = *value;
        } else if (argument == "--config-dir") {
            const auto value = next_value();
            if (!value) return std::nullopt;
            options.config_dir = *value;
        } else if (argument == "--uid") {
            const auto value = next_value();
            if (!value) return std::nullopt;
            const auto uid = parse_uid_strict(value->c_str());
            if (!uid) {
                std::cerr << "wispd: invalid --uid '" << *value << "'\n";
                return std::nullopt;
            }
            options.allowed_uid = *uid;
        } else {
            std::cerr << "wispd: unknown argument '" << argument << "'\n";
            return std::nullopt;
        }
    }

    if (!options.allowed_uid && !options.version && !options.help) {
        // Secure by default: refuse to run without an explicit decision about
        // who may talk to us.
        std::cerr << "wispd: --uid is required (or set SUDO_UID when using sudo)\n";
        return std::nullopt;
    }

    return options;
}

// Drops every capability except CAP_NET_ADMIN.
//
// As uid 0 with the full set, a bug anywhere (parser, IPC handler, some
// library) is a full-root bug. Narrowed to the one capability this daemon
// actually needs, the same bug can only misconfigure the network.
bool restrict_to_net_admin() {
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;

    __user_cap_data_struct data[2] = {};
    // CAP_NET_ADMIN is 12, so it lives in the low word.
    const std::uint32_t mask = 1u << CAP_NET_ADMIN;
    data[0].effective = mask;
    data[0].permitted = mask;
    data[0].inheritable = 0;
    data[1].effective = 0;
    data[1].permitted = 0;
    data[1].inheritable = 0;

    return ::syscall(SYS_capset, &header, data) == 0;
}

void apply_process_hardening(const Options& options) {
    // The helper must never gain rights through an exec of something else.
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        log_line(std::string("warning: could not set no_new_privs: ") + std::strerror(errno));
    }

    // Not dumpable: another process cannot ptrace us, so it cannot read key
    // material straight out of our address space.
    if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        log_line(std::string("warning: could not clear the dumpable flag: ") + std::strerror(errno));
    }

    // A crash must not write a private key to disk in a core dump.
    rlimit core_limit{};
    core_limit.rlim_cur = 0;
    core_limit.rlim_max = 0;
    if (::setrlimit(RLIMIT_CORE, &core_limit) != 0) {
        log_line(std::string("warning: could not disable core dumps: ") + std::strerror(errno));
    }

    // Lock what is already mapped so keys do not reach swap. CURRENT only:
    // FUTURE would charge every later allocation against RLIMIT_MEMLOCK, and a
    // failed malloc in a daemon is worse than a key that might page.
    if (::mlockall(MCL_CURRENT) != 0) {
        log_line(std::string("note: could not lock memory: ") + std::strerror(errno));
    }

    if (options.keep_privileges) {
        log_line("warning: keeping full privileges (--keep-privileges)");
        return;
    }

    if (!restrict_to_net_admin()) {
        log_line(std::string("warning: could not restrict capabilities: ") + std::strerror(errno));
    } else {
        verbose_log("dropped all capabilities except CAP_NET_ADMIN");
    }
}

std::optional<std::string> read_file(const std::string& path) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) return std::nullopt;
    if (S_ISLNK(info.st_mode)) return std::nullopt;
    if (!S_ISREG(info.st_mode)) return std::nullopt;
    if ((info.st_mode & S_IWOTH) != 0) return std::nullopt;
    if (::geteuid() == 0 && info.st_uid != 0) return std::nullopt;

    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    struct stat opened {};
    if (::fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode)) {
        ::close(fd);
        return std::nullopt;
    }
    std::string contents;
    char chunk[4096];
    for (;;) {
        const ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n > 0) {
            contents.append(chunk, static_cast<std::size_t>(n));
            if (contents.size() > 1024 * 1024) {
                ::close(fd);
                return std::nullopt;
            }
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        ::close(fd);
        return std::nullopt;
    }
    ::close(fd);
    return contents;
}

std::string config_path_for(const Options& options, const std::string& name) {
    return (std::filesystem::path(options.config_dir) / (name + ".conf")).string();
}

std::vector<std::string> list_tunnels(const Options& options) {
    std::vector<std::string> names;

    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(options.config_dir, error)) {
        if (entry.is_symlink(error)) continue;
        if (!entry.is_regular_file(error)) continue;
        if (entry.path().extension() != ".conf") continue;
        const auto name = entry.path().stem().string();
        // Only ever report names the client would be allowed to ask for.
        if (wisp::ipc::is_valid_tunnel_name(name)) names.push_back(name);
    }

    std::sort(names.begin(), names.end());
    return names;
}

std::string describe_device(const wisp::nl::DeviceState& state) {
    std::ostringstream out;
    out << "up peers=" << state.peers.size();

    std::uint64_t rx = 0;
    std::uint64_t tx = 0;
    std::uint64_t latest_handshake = 0;
    for (const auto& peer : state.peers) {
        rx += peer.rx_bytes;
        tx += peer.tx_bytes;
        latest_handshake = std::max(latest_handshake, peer.last_handshake_seconds);
    }

    out << " rx=" << rx << " tx=" << tx << " handshake=" << latest_handshake;
    if (state.listen_port) out << " listen_port=" << *state.listen_port;
    return out.str();
}

std::string handle_request(const Options& options, wisp::nl::Client& client,
                           wisp::DnsManager* dns, const std::string& line) {
    const auto request = wisp::ipc::parse_request(line);
    const auto& verb = request.verb;

    // Validate the verb before anything else, and sanitise it before quoting it
    // back. A verb can legally contain an embedded newline, so echoing it raw
    // would let a caller fabricate a second response line - or split their own
    // log entry, so that whoever reads the log sees a forged record.
    if (!wisp::ipc::is_valid_verb(verb)) {
        return wisp::ipc::encode_error("unknown verb '" + wisp::ipc::sanitize_for_display(verb) +
                                       "'");
    }

    if (verb == wisp::ipc::kPing) return wisp::ipc::encode_ok("pong");

    if (verb == wisp::ipc::kList) {
        std::string joined;
        for (const auto& name : list_tunnels(options)) {
            if (!joined.empty()) joined += ",";
            joined += name;
        }
        return wisp::ipc::encode_ok(joined);
    }

    // Reject anything that is not a plain interface name before it can be
    // turned into a filesystem path.
    if (!wisp::ipc::is_valid_tunnel_name(request.argument)) {
        return wisp::ipc::encode_error("invalid tunnel name");
    }
    const auto& name = request.argument;

    auto platform = wisp::make_netlink_platform(client);

    if (verb == wisp::ipc::kDown) {
        // Prefer the profile, which gives the exact plan the tunnel came up
        // with. If the file has since been deleted, rebuild the plan from the
        // kernel's own state so that policy rules do not outlive the tunnel.
        const auto plan = [&]() -> wisp::RoutingPlan {
            if (const auto text = read_file(config_path_for(options, name))) {
                const auto parsed = wisp::parse_config(*text);
                if (parsed.ok()) return wisp::RoutingPlan::derive(*parsed.interface);
            }
            if (const auto state = client.get_device(name)) {
                return wisp::RoutingPlan::from_device_state(*state);
            }
            return {};
        }();

        const auto result = wisp::tear_down(*platform, dns, plan, name);
        return result.ok ? wisp::ipc::encode_ok(result.message)
                         : wisp::ipc::encode_error(result.message);
    }

    if (verb == wisp::ipc::kStatus) {
        const auto state = client.get_device(name);
        if (!state) return wisp::ipc::encode_error("not running");
        return wisp::ipc::encode_ok(describe_device(*state));
    }

    // UP goes below. DOWN and STATUS are handled above.
    auto text = read_file(config_path_for(options, name));
    if (!text) return wisp::ipc::encode_error("no profile named '" + name + "'");

    const auto parsed = wisp::parse_config(*text);
    // The raw text contains the private key; clear it as soon as it has been
    // parsed rather than leaving it in the heap for the process lifetime.
    wisp::secure_wipe(*text);

    if (!parsed.ok()) {
        const auto& first = parsed.errors.front();
        std::ostringstream message;
        message << "profile '" << name << "' is invalid";
        if (first.line != 0) message << " at line " << first.line;
        message << ": " << first.message;
        return wisp::ipc::encode_error(message.str());
    }

    auto config = *parsed.interface;

    std::size_t hostname_endpoints = 0;
    for (const auto& peer : config.peers) {
        if (peer.endpoint && !is_ip_literal(peer.endpoint->host)) ++hostname_endpoints;
    }
    const auto plan_for_checks = wisp::RoutingPlan::derive(config);
    const bool single_stack_full =
        plan_for_checks.full_tunnel && !(plan_for_checks.has_v4 && plan_for_checks.has_v6);

    if (options.fail_closed) {
        if (hostname_endpoints > 0) {
            wisp::secure_wipe(config.private_key);
            for (auto& peer : config.peers) {
                if (peer.preshared_key) wisp::secure_wipe(*peer.preshared_key);
            }
            return wisp::ipc::encode_error(
                "endpoint hostname would be resolved in the clear before the tunnel exists");
        }
        if (single_stack_full) {
            wisp::secure_wipe(config.private_key);
            for (auto& peer : config.peers) {
                if (peer.preshared_key) wisp::secure_wipe(*peer.preshared_key);
            }
            return wisp::ipc::encode_error(
                "full tunnel covers one family only (add 0.0.0.0/0 and ::/0)");
        }
    }

    if (options.dry_run) {
        const auto plan = wisp::RoutingPlan::derive(config);
        std::ostringstream message;
        message << "valid: addresses=" << config.addresses.size()
                << " peers=" << config.peers.size()
                << " hooks=" << (config.hooks.empty() ? 0 : 1)
                << " full_tunnel=" << (plan.full_tunnel ? 1 : 0)
                << " table=" << plan.table
                << " policies=" << (plan.needs_policy_routing() ? 1 : 0)
                << " warnings=" << parsed.warnings.size() << " hostnames=" << hostname_endpoints
                << " single_stack=" << (single_stack_full ? 1 : 0);
        wisp::secure_wipe(config.private_key);
        return wisp::ipc::encode_ok(message.str());
    }

    // Tear down first so that applying a profile is idempotent rather than
    // failing on an interface left over from a previous run.
    wisp::tear_down(*platform, dns, wisp::RoutingPlan::derive(config), name);

    const auto result = wisp::bring_up(*platform, dns, config, name);

    // Key material has been handed to the kernel now; clear our copies so they
    // are not left in memory.
    wisp::secure_wipe(config.private_key);
    for (auto& peer : config.peers) {
        if (peer.preshared_key) wisp::secure_wipe(*peer.preshared_key);
    }

    if (!result.ok) return wisp::ipc::encode_error(result.message);
    return wisp::ipc::encode_ok(result.message);
}

// Writes a whole response, tolerating a socket that is momentarily full.
//
// The connection is non-blocking, so a short write is expected under load; the
// only real failure is the peer going away, which is reported so the caller can
// drop the connection. The poll() wait is bounded so a peer that stops reading
// cannot pin the daemon forever.
bool write_all(int fd, const std::string& data) {
    std::size_t written = 0;
    while (written < data.size()) {
        const ssize_t n = ::write(fd, data.data() + written, data.size() - written);
        if (n > 0) {
            written += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd writable{};
            writable.fd = fd;
            writable.events = POLLOUT;
            if (::poll(&writable, 1, kWriteTimeoutMs) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

// One accepted client. `input` holds bytes that arrived but do not yet make up
// a complete request line.
struct Connection {
    int fd = -1;
    std::string input;
};

// Who is on the other end of this connection, if the kernel will say.
// Kept separate from policy below so identity and authorization read as two
// steps instead of one tangled check.
std::optional<uid_t> peer_uid(int fd) {
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0) {
        return std::nullopt;
    }
    return credentials.uid;
}

bool peer_is_allowed(const Options& options, int fd) {
    const auto uid = peer_uid(fd);
    if (!uid) {
        log_line("refused a connection whose peer could not be identified");
        return false;
    }

    // uid 0 is always allowed, which is what lets root use the tool it manages.
    if (*uid == 0) return true;
    if (options.allowed_uid && *uid == *options.allowed_uid) return true;

    log_line("refused a connection from uid " + std::to_string(*uid));
    return false;
}

enum class Service { KeepOpen, Close };

// Reads everything available from one connection, then answers each complete
// request found in it.
//
// Order matters here. A client that writes and closes in one go (like
// `printf 'PING\n' | socat - UNIX-CONNECT:...`, or any one-shot script)
// delivers bytes and hangup together: read() hands back the request first and
// 0 right after. Returning on that first 0 would bin a request we already
// hold and leave the caller with silence. So buffered lines get processed
// after the read loop no matter how it ended.
Service service_connection(Connection& connection, const Options& options, wisp::nl::Client& client,
                           wisp::DnsManager* dns, std::string& scratch) {
    char chunk[1024];
    bool peer_closed = false;

    while (!peer_closed) {
        const ssize_t n = ::read(connection.fd, chunk, sizeof(chunk));
        if (n > 0) {
            connection.input.append(chunk, static_cast<std::size_t>(n));
            if (connection.input.size() > kMaxBufferedBytes) {
                // No newline after 64 KiB is not a request, it is a client
                // trying to make us allocate. Answer once and hang up.
                write_all(connection.fd, wisp::ipc::encode_error("request too large"));
                return Service::Close;
            }
            continue;
        }
        if (n == 0) {
            peer_closed = true;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return Service::Close;  // a read error we cannot recover from
    }

    while (wisp::ipc::take_request_line(connection.input, scratch)) {
        if (scratch.size() > kMaxRequestBytes) {
            write_all(connection.fd, wisp::ipc::encode_error("request too large"));
            return Service::Close;
        }

        const auto verb = wisp::ipc::parse_request(scratch).verb;
        // One request must never kill the daemon. Anything thrown below
        // (bad_alloc from a hostile input size, however capped) becomes a
        // single error reply on a closed connection, and the loop goes on.
        const std::string response = [&]() -> std::string {
            try {
                return handle_request(options, client, dns, scratch);
            } catch (const std::exception& failure) {
                log_line(std::string("request failed: ") + failure.what());
            } catch (...) {
                log_line("request failed with an unknown error");
            }
            return wisp::ipc::encode_error("internal error");
        }();
        // Per-request logging is opt-in: at 400ms STATUS polling it would
        // otherwise write a persistent activity timeline to stderr/journald.
        verbose_log(wisp::ipc::sanitize_for_display(verb) + " -> " +
                    (wisp::ipc::response_is_ok(response) ? "ok" : "error"));

        // A peer that has already gone away fails the write, which is fine:
        // the log entry above is the record that the request was handled. Any
        // remaining buffered lines are still parsed, so a client that pipelined
        // several requests and closed gets all of them acted on.
        if (!write_all(connection.fd, response) && !peer_closed) return Service::Close;
    }

    return peer_closed ? Service::Close : Service::KeepOpen;
}

// Creates, binds, and listens on the socket, then returns it. Empty on any
// failure, with the reason already logged and the fd closed, so no failure
// path can leak the descriptor.
std::optional<int> bind_listener(const Options& options) {
    const int server = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) {
        log_line(std::string("socket() failed: ") + std::strerror(errno));
        return std::nullopt;
    }
    const auto abandon = [&](const std::string& message) -> std::optional<int> {
        log_line(message);
        ::close(server);
        return std::nullopt;
    };

    {
        const auto parent =
            std::filesystem::path(options.socket_path).parent_path().string();
        std::error_code ignored;
        if (!parent.empty() && !std::filesystem::exists(parent, ignored)) {
            std::filesystem::create_directories(parent, ignored);
            ::chmod(parent.c_str(), 0700);
        }
        if (!parent.empty() && !dir_is_secure(parent)) {
            return abandon("refusing to bind: insecure socket directory " + parent);
        }
        if (::geteuid() == 0 && !options.dry_run && !dir_is_secure(options.config_dir)) {
            return abandon("refusing to start: insecure config directory " + options.config_dir);
        }
    }

    ::unlink(options.socket_path.c_str());

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (options.socket_path.size() >= sizeof(address.sun_path)) {
        return abandon("socket path is too long");
    }
    std::strncpy(address.sun_path, options.socket_path.c_str(), sizeof(address.sun_path) - 1);

    if (::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        return abandon(std::string("bind() failed: ") + std::strerror(errno) +
                       " (does the directory exist?)");
    }

    // The socket is the second half of the access control: only the allowed
    // user can open it at all, and the peer check runs on top. This needs
    // CAP_CHOWN, so it happens before the capability drop.
    ::chmod(options.socket_path.c_str(), S_IRUSR | S_IWUSR);
    if (::chown(options.socket_path.c_str(), *options.allowed_uid, static_cast<gid_t>(-1)) != 0) {
        log_line(std::string("chown() failed: ") + std::strerror(errno));
    }

    if (::listen(server, 8) < 0) {
        return abandon(std::string("listen() failed: ") + std::strerror(errno));
    }

    return server;
}

}  // namespace

int main(int argc, char** argv) {
    ::umask(077);

    std::optional<uid_t> sudo_uid;
    if (const char* value = std::getenv("SUDO_UID")) {
        sudo_uid = parse_uid_strict(value);
    }

    auto options = parse_arguments(argc, argv);
    if (!options) return 2;
    if (options->help) {
        print_usage(std::cout);
        return 0;
    }
    if (options->version) {
        std::cout << "wispd " << WISP_VERSION << "\n";
        return 0;
    }
    g_verbose = options->verbose;
    if (!options->allowed_uid && sudo_uid) options->allowed_uid = sudo_uid;

    if (!options->allowed_uid) {
        std::cerr << "wispd: no --uid given and SUDO_UID is not set\n";
        return 2;
    }

    if (options->keep_privileges && ::getenv("WISP_ALLOW_KEEP_PRIVILEGES") == nullptr &&
        !options->dry_run) {
        std::cerr << "wispd: --keep-privileges requires WISP_ALLOW_KEEP_PRIVILEGES=1\n";
        return 2;
    }

    if (*options->allowed_uid == 0) {
        log_line("note: --uid 0 changes nothing, uid 0 is always allowed");
    }

    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    if (::geteuid() != 0 && !options->dry_run) {
        log_line("warning: not running as root, so creating interfaces will fail");
    }

    // Resolve the DNS strategy up front, while we still hold the privileges
    // that reading /etc/resolv.conf and probing the system may need.
    const auto dns_environment = wisp::probe_environment();
    auto dns_backend = options->no_dns ? wisp::DnsBackend::None
                                       : wisp::select_backend(dns_environment);
    auto dns = wisp::make_dns_manager(dns_backend, dns_environment);
    wisp::DnsManager* dns_ptr = dns_backend == wisp::DnsBackend::None ? nullptr : dns.get();

    const auto server = bind_listener(*options);
    if (!server) return 1;
    const int listener = *server;

    log_line("listening on " + options->socket_path + " for uid " +
             std::to_string(*options->allowed_uid) + " (dns: " +
             wisp::dns_backend_name(dns_backend) + ")" + (options->dry_run ? " (dry run)" : ""));

    apply_process_hardening(*options);

    wisp::nl::Client client;

    // One persistent connection per client, multiplexed with poll(). Two wins:
    // no connect/accept round trip four times a second just to read byte
    // counters, and one idle client can never block the daemon for the rest.
    // A quiet connection costs nothing this way.
    std::vector<Connection> connections;
    std::string scratch;

    while (g_running) {
        std::vector<pollfd> watched;
        watched.reserve(connections.size() + 1);
        watched.push_back(pollfd{listener, POLLIN, 0});
        for (const auto& connection : connections) {
            watched.push_back(pollfd{connection.fd, POLLIN, 0});
        }

        const int ready = ::poll(watched.data(), watched.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            log_line(std::string("poll() failed: ") + std::strerror(errno));
            break;
        }

        if ((watched[0].revents & POLLIN) != 0) {
            const int connection = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (connection >= 0) {
                if (connections.size() >= kMaxConnections) {
                    log_line("refused a connection: too many outstanding");
                    ::close(connection);
                } else if (!peer_is_allowed(*options, connection)) {
                    ::close(connection);
                } else {
                    connections.push_back(Connection{connection, {}});
                }
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                // Transient accept failures (EMFILE, ECONNABORTED) must not
                // take the daemon down: log, pause so a persistent failure
                // cannot spin, and keep serving. Exiting here used to turn a
                // full fd table into a dead helper.
                log_line(std::string("accept() failed: ") + std::strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        // Index i in `watched` describes connections[i - 1], because the
        // listening socket occupies slot 0.
        //
        // Nothing is removed during this scan. Erasing an element part-way
        // through would shift every later connection down one place while the
        // revents array stayed put, so each remaining socket would be evaluated
        // against the previous socket's readiness - closing connections that
        // are perfectly healthy, and skipping ones with data waiting. Dead
        // sockets are marked here and swept once, after the loop.
        for (std::size_t i = 1; i < watched.size(); ++i) {
            const short revents = watched[i].revents;
            if (revents == 0) continue;

            Connection& connection = connections[i - 1];
            const bool readable = (revents & POLLIN) != 0;
            const bool broken = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;

            // Service on a hangup as well as on readability. Data and the
            // hangup can be reported in the same event, and the hangup bit can
            // arrive without POLLIN even though a whole request is sitting in
            // the socket buffer - so a connection that reports POLLHUP must
            // still be drained before it is closed, or those bytes are lost.
            bool keep = true;
            if (readable || broken) {
                keep = service_connection(connection, *options, client, dns_ptr, scratch) ==
                       Service::KeepOpen;
            }

            if (!keep || broken) {
                ::close(connection.fd);
                connection.fd = -1;
            }
        }

        std::erase_if(connections, [](const Connection& connection) { return connection.fd < 0; });
    }

    for (const auto& connection : connections) ::close(connection.fd);
    ::close(listener);
    ::unlink(options->socket_path.c_str());
    log_line("stopped");
    return 0;
}

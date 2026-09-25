// Micro-benchmarks for the parts of Wisp that run in a loop.
//
// These are not a substitute for profiling a live tunnel: the expensive parts
// of bringing a tunnel up are the syscalls and the kernel's own work, and none
// of that appears here. What this measures is the cost Wisp itself adds -
// parsing a profile, encoding netlink messages, decoding kernel replies and
// validating IPC input - so that a regression in any of those shows up as a
// number rather than as a vague feeling that the UI got slower.
//
// Method: timings are the *best* of several runs on a single thread. The best
// run is the least noisy estimator on a shared machine: system noise can only
// make a run slower, so the minimum is the closest thing to the true cost.
// Iteration counts are calibrated at runtime so slow and fast cases both get
// enough samples to be meaningful, and every benchmark rotates over a small set
// of inputs so that the optimiser cannot hoist a constant-input loop out of the
// measurement.

#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "wisp/config.hpp"
#include "wisp/ipc.hpp"
#include "wisp/keys.hpp"
#include "wisp/netlink.hpp"
#include "wisp/tunnel.hpp"
#include "wisp/types.hpp"

namespace {

using Clock = std::chrono::steady_clock;

constexpr double kTargetNanoseconds = 50.0e6;         // aim for ~50 ms per run
constexpr std::uint64_t kMaxIterations = 50'000'000;  // ceiling for cheap cases
constexpr int kRepetitions = 5;

std::uint64_t g_sink = 0;  // consumes every result, so nothing can be elided
int g_failures = 0;

void fail(const std::string& message) {
    std::fprintf(stderr, "benchmark setup failed: %s\n", message.c_str());
    ++g_failures;
}

// Stops the optimiser from discarding work whose result is never read.
template <typename T>
void consume(const T& value) {
    g_sink += static_cast<std::uint64_t>(value);
}

// Rotating index over an input set. Every set below is sized to a power of two
// so that this is a mask rather than a division: the cheapest benchmarks here
// take a few tens of nanoseconds, and a modulo would distort them. `check_inputs`
// verifies the power-of-two property before anything is timed.
std::size_t rot(std::uint64_t i, std::size_t size) {
    return static_cast<std::size_t>(i) & (size - 1u);
}

bool is_power_of_two(std::size_t value) { return value != 0 && (value & (value - 1u)) == 0; }

void check_inputs(const char* name, std::size_t size) {
    if (!is_power_of_two(size)) {
        fail(std::string("input set '") + name + "' has " + std::to_string(size) +
             " entries, which is not a power of two");
    }
}

// Stops the compiler from folding a pure call on constant input.
//
// parse_link_index, parse_error and is_valid_tunnel_name are pure functions of a
// buffer that never changes inside the loop, so with LTO the optimiser
// evaluates them once and replaces the whole loop with a constant addition. The
// first run of this benchmark reported 0.0 ns/op for exactly that reason, which
// is worse than useless: it looks like an unbelievably fast function rather than
// a broken measurement. The memory clobber tells the compiler the buffer may
// have been written, so a real call has to happen every iteration.
template <typename T>
void opaque(const T& value) {
    asm volatile("" : : "r"(&value) : "memory");
}

void section(const char* title) {
    std::printf("\n%s\n", title);
    std::printf("---------------------------------------------------------------------------\n");
}

void report(const std::string& name, double ns_per_op, std::uint64_t iterations) {
    std::printf("%-44s %11.1f ns/op %14.0f ops/s %10llu iters\n", name.c_str(), ns_per_op,
                1.0e9 / ns_per_op, static_cast<unsigned long long>(iterations));
}

// Runs `fn(iterations)` until a single call takes about 50 ms, then times it
// `kRepetitions` more times and keeps the fastest. `fn` must return a number
// that depends on the work done, which is what keeps the work alive.
template <typename Fn>
void bench(const std::string& name, Fn&& fn) {
    std::uint64_t iterations = 1;
    double ns_per_op = 0.0;

    for (int attempt = 0; attempt < 40; ++attempt) {
        const auto start = Clock::now();
        consume(fn(iterations));
        const double elapsed =
            std::chrono::duration<double, std::nano>(Clock::now() - start).count();
        ns_per_op = elapsed / static_cast<double>(iterations);
        if (elapsed >= kTargetNanoseconds || iterations >= kMaxIterations) break;

        // Grow geometrically but stop short of overshooting by more than 8x, so
        // calibration itself stays cheap.
        const double scale = kTargetNanoseconds / (elapsed > 0.0 ? elapsed : 1.0);
        const auto grown = static_cast<std::uint64_t>(
            static_cast<double>(iterations) * (scale < 8.0 ? scale : 8.0));
        iterations = std::min(kMaxIterations, std::max(iterations + 1, grown));
    }

    double best = ns_per_op;
    for (int repetition = 0; repetition < kRepetitions; ++repetition) {
        const auto start = Clock::now();
        consume(fn(iterations));
        const double elapsed =
            std::chrono::duration<double, std::nano>(Clock::now() - start).count();
        best = std::min(best, elapsed / static_cast<double>(iterations));
    }

    report(name, best, iterations);
}

// Inputs

// Deterministic, valid base64 keys. Real keys would make each run's input
// different, which is the opposite of what a benchmark wants.
std::string fake_key(int index, bool private_key) {
    std::array<unsigned char, wisp::kKeyBytes> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<unsigned char>((index * 31 + static_cast<int>(i) * 7 +
                                               (private_key ? 11 : 29)) & 0xff);
    }
    return wisp::encode_key(bytes.data(), bytes.size());
}

struct Profile {
    std::string label;
    std::string text;
    wisp::Interface parsed;
    wisp::RoutingPlan plan;
};

Profile make_profile(const std::string& label, int peer_count, int prefixes_per_peer,
                     bool full_tunnel) {
    Profile profile;
    profile.label = label;

    std::string text;
    text += "[Interface]\n";
    text += "PrivateKey = " + fake_key(0, true) + "\n";
    text += "Address = 10.7.0.2/32, fd00:7::2/128\n";
    text += "DNS = 10.64.0.1, 10.64.0.2, 2001:4860:4860::8888\n";
    text += "MTU = 1420\n";
    text += "ListenPort = 51820\n";
    text += std::string("Table = ") + (full_tunnel ? "auto" : "off") + "\n";

    for (int peer = 0; peer < peer_count; ++peer) {
        text += "\n[Peer]\n";
        text += "PublicKey = " + fake_key(peer + 1, false) + "\n";
        text += "PresharedKey = " + fake_key(peer + 100, false) + "\n";
        text += "Endpoint = 198.51.100." + std::to_string(10 + peer) + ":51820\n";
        text += "PersistentKeepalive = 25\n";

        std::string allowed = full_tunnel ? "0.0.0.0/0, ::/0" : "";
        for (int prefix = 0; prefix < prefixes_per_peer; ++prefix) {
            if (!allowed.empty()) allowed += ", ";
            // Spread across the RFC1918 ranges so the entries are realistic
            // rather than one long run of identical strings.
            if (prefix % 3 == 0) {
                allowed += "10." + std::to_string(peer) + "." + std::to_string(prefix) + ".0/24";
            } else if (prefix % 3 == 1) {
                allowed += "172.16." + std::to_string(peer) + "." + std::to_string(prefix) + "/24";
            } else {
                allowed += "192.168." + std::to_string(peer) + "." +
                           std::to_string(prefix) + "/24";
            }
        }
        text += "AllowedIPs = " + allowed + "\n";
    }

    profile.text = std::move(text);
    return profile;
}

// A profile that is only rejected at the very end, so the parser has to do all
// of its work before it can fail. This is the worst case for error handling.
std::string make_malformed_profile() {
    Profile profile = make_profile("temporary", 2, 4, false);
    std::string text = profile.text;
    text += "\n[Peer]\nPublicKey = not-a-valid-key\n";
    return text;
}

// A synthetic kernel reply, for benchmarking the decoder.
//
// There is no builder for a *reply* in the library - the builders produce
// requests - so the attribute encoding is repeated here. The decoded result
// is checked against the input before any timing runs, so if the real
// encoder's format ever drifts the benchmark fails loudly instead of quietly
// measuring an early return.

struct Attrs {
    std::vector<std::uint8_t> bytes;

    void raw(std::uint16_t type, const void* data, std::size_t len) {
        const std::size_t start = bytes.size();
        const auto total = static_cast<std::uint16_t>(4 + len);
        const auto* header = reinterpret_cast<const std::uint8_t*>(&total);
        bytes.insert(bytes.end(), header, header + 2);
        const auto* type_bytes = reinterpret_cast<const std::uint8_t*>(&type);
        bytes.insert(bytes.end(), type_bytes, type_bytes + 2);
        if (len != 0 && data != nullptr) {
            const auto* payload = static_cast<const std::uint8_t*>(data);
            bytes.insert(bytes.end(), payload, payload + len);
        }
        while ((bytes.size() - start) % 4 != 0) bytes.push_back(0);
    }

    template <typename T>
    void number(std::uint16_t type, T value) {
        raw(type, &value, sizeof(T));
    }

    void string(std::uint16_t type, const std::string& value) {
        raw(type, value.data(), value.size() + 1);  // NUL-terminated
    }

    void nested(std::uint16_t type, const Attrs& inner) {
        raw(static_cast<std::uint16_t>(type | NLA_F_NESTED), inner.bytes.data(), inner.bytes.size());
    }
};

std::vector<std::uint8_t> make_device_reply(int peer_count, int prefixes_per_peer) {
    Attrs attrs;
    attrs.string(WGDEVICE_A_IFNAME, "wg0");

    std::array<unsigned char, WG_KEY_LEN> device_key{};
    for (std::size_t i = 0; i < device_key.size(); ++i) {
        device_key[i] = static_cast<unsigned char>(i + 1);
    }
    attrs.raw(WGDEVICE_A_PUBLIC_KEY, device_key.data(), device_key.size());
    attrs.number<std::uint16_t>(WGDEVICE_A_LISTEN_PORT, 51820);
    attrs.number<std::uint32_t>(WGDEVICE_A_FWMARK, 51820);

    Attrs peers;
    for (int peer = 0; peer < peer_count; ++peer) {
        Attrs entry;

        std::array<unsigned char, WG_KEY_LEN> key{};
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<unsigned char>((peer + static_cast<int>(i)) & 0xff);
        }
        entry.raw(WGPEER_A_PUBLIC_KEY, key.data(), key.size());

        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(51820);
        ::inet_pton(AF_INET, "198.51.100.10", &endpoint.sin_addr);
        entry.raw(WGPEER_A_ENDPOINT, &endpoint, sizeof(endpoint));

        entry.number<std::uint16_t>(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, 25);

        timespec handshake{};
        handshake.tv_sec = 1758700000 + peer;
        entry.raw(WGPEER_A_LAST_HANDSHAKE_TIME, &handshake, sizeof(handshake));

        entry.number<std::uint64_t>(WGPEER_A_RX_BYTES, 1024ull * static_cast<std::uint64_t>(peer + 1));
        entry.number<std::uint64_t>(WGPEER_A_TX_BYTES, 2048ull * static_cast<std::uint64_t>(peer + 1));

        Attrs allowed;
        for (int prefix = 0; prefix < prefixes_per_peer; ++prefix) {
            Attrs one;
            one.number<std::uint16_t>(WGALLOWEDIP_A_FAMILY, static_cast<std::uint16_t>(AF_INET));
            one.number<std::uint8_t>(WGALLOWEDIP_A_CIDR_MASK, 24);
            in_addr address{};
            char text[32];
            std::snprintf(text, sizeof(text), "10.%d.%d.0", peer, prefix);
            ::inet_pton(AF_INET, text, &address);
            one.raw(WGALLOWEDIP_A_IPADDR, &address, sizeof(address));
            allowed.nested(0, one);
        }
        entry.nested(WGPEER_A_ALLOWEDIPS, allowed);
        peers.nested(0, entry);
    }
    attrs.nested(WGDEVICE_A_PEERS, peers);

    std::vector<std::uint8_t> reply;
    reply.reserve(sizeof(genlmsghdr) + attrs.bytes.size());
    reply.push_back(static_cast<std::uint8_t>(WG_CMD_GET_DEVICE));
    reply.push_back(1);  // generic netlink version
    reply.push_back(0);
    reply.push_back(0);  // reserved
    reply.insert(reply.end(), attrs.bytes.begin(), attrs.bytes.end());
    return reply;
}

}  // namespace

int main() {
    if (!wisp::crypto_init()) {
        std::fprintf(stderr, "libsodium could not be initialised\n");
        return 1;
    }

#ifdef NDEBUG
    constexpr const char* kBuildKind = "optimised, assertions off";
#else
    constexpr const char* kBuildKind = "debug, assertions on";
#endif
    std::printf("wisp benchmarks - best of %d runs, single thread, %s build\n", kRepetitions,
                kBuildKind);
    std::printf("compiler: %s\n", __VERSION__);
    std::printf("note: this measures Wisp's own work only. A live bring-up is dominated by\n");
    std::printf("      syscalls and kernel work, neither of which appears here.\n");

    // - inputs
    std::vector<Profile> profiles;
    profiles.push_back(make_profile("split, 1 peer, 2 prefixes", 1, 2, false));
    profiles.push_back(make_profile("split, 3 peers, 8 prefixes", 3, 8, false));
    profiles.push_back(make_profile("full tunnel, 1 peer", 1, 2, true));
    profiles.push_back(make_profile("full tunnel, 3 peers", 3, 4, true));
    profiles.push_back(make_profile("split, 8 peers, 32 prefixes", 8, 32, false));
    profiles.push_back(make_profile("full tunnel, 16 peers", 16, 8, true));
    profiles.push_back(make_profile("split, 32 peers, 64 prefixes", 32, 64, false));
    profiles.push_back(make_profile("split, 4 peers, 16 prefixes", 4, 16, false));

    for (auto& profile : profiles) {
        auto result = wisp::parse_config(profile.text);
        if (!result.ok()) {
            fail("profile '" + profile.label + "' did not parse");
            continue;
        }
        profile.parsed = *result.interface;
        profile.plan = wisp::RoutingPlan::derive(profile.parsed);
    }

    const std::string malformed = make_malformed_profile();
    if (wisp::parse_config(malformed).ok()) {
        fail("the malformed profile parsed, so the error path is untested");
    }

    // Encode-side inputs, all derived from the profiles above.
    std::vector<wisp::nl::DeviceConfig> device_configs;
    for (const auto& profile : profiles) {
        device_configs.push_back(wisp::to_device_config(profile.parsed, "wg0", profile.plan));
    }

    const auto device_reply = make_device_reply(32, 8);
    {
        const auto decoded = wisp::nl::parse_device(device_reply.data(), device_reply.size());
        std::size_t prefixes = 0;
        if (decoded) {
            for (const auto& peer : decoded->peers) prefixes += peer.allowed_ips.size();
        }
        if (!decoded || decoded->ifname != "wg0" || decoded->peers.size() != 32 ||
            prefixes != 32 * 8 || decoded->peers[0].rx_bytes != 1024) {
            fail("the synthetic device reply did not decode as built");
        }
    }

    // IPv4 and IPv6 are measured separately: inet_pton and the normalization
    // that follows cost very different amounts for the two families, and an
    // average over both hides whichever one regresses.
    std::vector<std::string> cidrs_v4;
    std::vector<std::string> cidrs_v6;
    for (int i = 0; i < 64; ++i) {
        // Every fourth entry is a bare address, which becomes a host route - a
        // separate branch in the parser.
        cidrs_v4.push_back(i % 4 == 0 ? "10.7." + std::to_string(i) + ".9"
                                      : "10." + std::to_string(i) + ".4.0/24");
        cidrs_v6.push_back(i % 4 == 0 ? "fd00:" + std::to_string(i) + "::5"
                                      : "fd00:" + std::to_string(i) + "::/64");
    }

    std::vector<std::string> endpoints;
    for (int i = 0; i < 32; ++i) {
        endpoints.push_back("vpn" + std::to_string(i) + ".example.com:51820");
        endpoints.push_back("[" + std::string("2001:db8::") + std::to_string(i + 1) + "]:51820");
    }

    check_inputs("profiles", profiles.size());
    check_inputs("device_configs", device_configs.size());
    check_inputs("cidrs_v4", cidrs_v4.size());
    check_inputs("cidrs_v6", cidrs_v6.size());
    check_inputs("endpoints", endpoints.size());

    // Two fixed profiles, so the shape of the scaling is visible rather than
    // averaged away. Indexing a fully built vector is safe here.
    const Profile& mid_profile = profiles[1];    // 3 peers, 24 prefixes
    const Profile& worst_profile = profiles[6];  // 32 peers, 2048 prefixes

    std::printf("\ninputs\n");
    std::printf("---------------------------------------------------------------------------\n");
    std::printf("%-38s %10s %12s %7s\n", "profile", "bytes", "peers", "prefixes");
    for (const auto& profile : profiles) {
        std::size_t prefixes = 0;
        for (const auto& peer : profile.parsed.peers) prefixes += peer.allowed_ips.size();
        std::printf("%-38s %10zu %12zu %7zu\n", profile.label.c_str(), profile.text.size(),
                    profile.parsed.peers.size(), prefixes);
    }

    // - parsing
    section("parsing");

    bench("parse_config - rotating profiles", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto& profile = profiles[rot(i, profiles.size())];
            const auto result = wisp::parse_config(profile.text);
            sink += result.ok() ? result.interface->peers.size() : 1000;
            consume(result.errors.size() + result.warnings.size());
        }
        return sink;
    });

    bench("parse_config - malformed, error on last line", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto result = wisp::parse_config(malformed);
            sink += result.ok() ? 1000 : result.errors.size();
        }
        return sink;
    });

    bench("parse_config - split, 3 peers, 24 prefixes", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto result = wisp::parse_config(mid_profile.text);
            sink += result.ok() ? result.interface->peers.size() : 1000;
        }
        return sink;
    });

    bench("parse_config - split, 32 peers, 2048 prefixes", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto result = wisp::parse_config(worst_profile.text);
            sink += result.ok() ? result.interface->peers.size() : 1000;
        }
        return sink;
    });

    bench("Cidr::parse - IPv4", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto cidr = wisp::Cidr::parse(cidrs_v4[rot(i, cidrs_v4.size())]);
            sink += cidr ? cidr->prefix : 1000;
        }
        return sink;
    });

    bench("Cidr::parse - IPv6", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto cidr = wisp::Cidr::parse(cidrs_v6[rot(i, cidrs_v6.size())]);
            sink += cidr ? cidr->prefix : 1000;
        }
        return sink;
    });

    bench("Endpoint::parse (hostname and bracketed v6)", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto endpoint = wisp::Endpoint::parse(endpoints[rot(i, endpoints.size())]);
            sink += endpoint ? endpoint->port : 1000;
        }
        return sink;
    });

    bench("Cidr::to_string", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto& profile = profiles[rot(i, profiles.size())];
            if (profile.parsed.addresses.empty()) {
                consume(1);
                continue;
            }
            const std::string rendered = profile.parsed.addresses[i % profile.parsed.addresses.size()].to_string();
            sink += rendered.size();
        }
        return sink;
    });

    // - serialising
    section("serialising");

    bench("serialize_config", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto& profile = profiles[rot(i, profiles.size())];
            const std::string text = wisp::serialize_config(profile.parsed);
            sink += text.size();
        }
        return sink;
    });

    bench("parse + serialize round-trip", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto& profile = profiles[rot(i, profiles.size())];
            const auto result = wisp::parse_config(profile.text);
            if (!result.ok()) {
                sink += 1000;
                continue;
            }
            const std::string text = wisp::serialize_config(*result.interface);
            const auto again = wisp::parse_config(text);
            sink += again.ok() ? text.size() : 1000;
        }
        return sink;
    });

    // - netlink encoding
    section("netlink encoding");

    bench("build_get_device", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto message = wisp::nl::build_get_device(30, static_cast<std::uint32_t>(i), "wg0");
            sink += message.size();
        }
        return sink;
    });

    bench("build_set_device - rotating device configs", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto& config = device_configs[rot(i, device_configs.size())];
            const auto message =
                wisp::nl::build_set_device(30, static_cast<std::uint32_t>(i), config);
            if (!message) {
                sink += 1000;
                continue;
            }
            sink += message->size();
        }
        return sink;
    });

    bench("build_create_link", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto message =
                wisp::nl::build_create_link(static_cast<std::uint32_t>(i), "wisp0", 1420);
            sink += message.size();
        }
        return sink;
    });

    bench("build_address", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        const auto cidr = wisp::Cidr::parse("10.7.0.2/32");
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto message = wisp::nl::build_address(static_cast<std::uint32_t>(i), 3, *cidr, true);
            sink += message.size();
        }
        return sink;
    });

    bench("build_route", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        const auto cidr = wisp::Cidr::parse("0.0.0.0/0");
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto message =
                wisp::nl::build_route(static_cast<std::uint32_t>(i), 3, *cidr, 51820, true);
            sink += message.size();
        }
        return sink;
    });

    bench("build_rule - fwmark, inverted", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        wisp::nl::RuleSpec spec;
        spec.table = wisp::kAutoPolicyTable;
        spec.fwmark = 51820;
        spec.priority = wisp::kFwmarkRulePriority;
        spec.invert = true;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto message = wisp::nl::build_rule(static_cast<std::uint32_t>(i), spec, true);
            sink += message.size();
        }
        return sink;
    });

    bench("build_rule - suppress_prefixlength", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        wisp::nl::RuleSpec spec;
        spec.table = wisp::kMainRoutingTable;
        spec.suppress_prefixlength = 0;
        spec.priority = wisp::kSuppressRulePriority;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto message = wisp::nl::build_rule(static_cast<std::uint32_t>(i), spec, true);
            sink += message.size();
        }
        return sink;
    });

    // - netlink decoding
    section("netlink decoding");

    bench("parse_device - 32 peers, 256 prefixes", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto state = wisp::nl::parse_device(device_reply.data(), device_reply.size());
            if (!state) {
                sink += 1000;
                continue;
            }
            sink += state->peers.size();
            for (const auto& peer : state->peers) sink += peer.allowed_ips.size();
        }
        return sink;
    });

    bench("parse_link_index", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        std::array<std::uint8_t, sizeof(ifinfomsg)> buffer{};
        ifinfomsg info{};
        info.ifi_index = 3;
        std::memcpy(buffer.data(), &info, sizeof(info));
        for (std::uint64_t i = 0; i < iterations; ++i) {
            opaque(buffer);
            const auto index = wisp::nl::parse_link_index(buffer.data(), buffer.size());
            sink += index ? *index : 1000;
        }
        return sink;
    });

    bench("parse_error", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        std::array<std::uint8_t, 4> buffer{};
        const std::int32_t code = -13;  // EACCES, the realistic failure
        std::memcpy(buffer.data(), &code, sizeof(code));
        for (std::uint64_t i = 0; i < iterations; ++i) {
            opaque(buffer);
            const auto parsed = wisp::nl::parse_error(buffer.data(), buffer.size());
            sink += parsed ? static_cast<std::uint64_t>(-*parsed + 4096) : 1000;
        }
        return sink;
    });

    // - end to end, without the syscalls
    section("end to end (no syscalls)");

    bench("parse + routing plan + to_device_config + encode", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto& profile = profiles[rot(i, profiles.size())];
            const auto result = wisp::parse_config(profile.text);
            if (!result.ok()) {
                sink += 1000;
                continue;
            }
            const auto plan = wisp::RoutingPlan::derive(*result.interface);
            const auto config = wisp::to_device_config(*result.interface, "wg0", plan);
            const auto message = wisp::nl::build_set_device(30, static_cast<std::uint32_t>(i), config);
            if (!message) {
                sink += 1000;
                continue;
            }
            sink += message->size() + (plan.needs_policy_routing() ? 1u : 0u);
        }
        return sink;
    });

    // - IPC
    section("ipc");

    bench("parse_request", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const auto request = wisp::ipc::parse_request("UP home-office\n");
            sink += request.verb.size() + request.argument.size();
        }
        return sink;
    });

    bench("encode_request + encode_ok", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const wisp::ipc::Request request{"STATUS", "home-office"};
            sink += wisp::ipc::encode_request(request).size();
            sink += wisp::ipc::encode_ok("up").size();
        }
        return sink;
    });

    bench("take_request_line - partial buffer", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            std::string buffer = "STATUS home-office\nPING\n";
            std::string line;
            if (wisp::ipc::take_request_line(buffer, line)) sink += line.size();
        }
        return sink;
    });

    const std::string acceptable_name = "home-office";
    const std::string rejected_name = "../../etc/shadow";
    bench("is_valid_tunnel_name", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            opaque(acceptable_name);
            sink += wisp::ipc::is_valid_tunnel_name(acceptable_name) ? 1 : 1000;
            sink += wisp::ipc::is_valid_tunnel_name(rejected_name) ? 1000 : 1;
        }
        return sink;
    });

    bench("sanitize_for_display - hostile input", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        const std::string hostile = "UP\r\nOK injected \x01\x02\x7f";
        for (std::uint64_t i = 0; i < iterations; ++i) {
            sink += wisp::ipc::sanitize_for_display(hostile).size();
        }
        return sink;
    });

    // - reference points
    section("reference");

    // The cost of an iteration that does nothing but the barrier and the
    // accumulate. Any result above that is small should be read as "this is
    // free relative to everything else" rather than as an exact figure: below
    // a nanosecond the loop itself is most of what is being measured.
    std::array<std::uint8_t, 4> baseline_buffer{};
    bench("empty loop (measurement floor)", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            opaque(baseline_buffer);
            sink += baseline_buffer[0] + 1;
        }
        return sink;
    });
    std::printf("  ^ an iteration that does nothing. Anything within a few tenths of a nanosecond\n");
    std::printf("    of this is dominated by loop overhead and is not measurable at this\n");
    std::printf("    granularity - read such a result as 'free', not as an exact cost.\n");

    // Not part of any hot path: called once when a key is generated. Included
    // because it is the single most expensive operation Wisp performs, and
    // knowing that number makes it obvious why keys are generated off the UI
    // thread's critical path and cached rather than derived per frame.
    const std::string private_key = fake_key(0, true);
    bench("public_key_from_private (Curve25519, not a hot path)", [&](std::uint64_t iterations) {
        std::uint64_t sink = 0;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            const std::string public_key = wisp::public_key_from_private(private_key);
            sink += public_key.size();
        }
        return sink;
    });

    if (g_sink == 0) std::fprintf(stderr, "warning: nothing was measured\n");

    std::printf("\n%s\n", g_failures == 0 ? "completed" : "completed with setup failures");
    return g_failures == 0 ? 0 : 1;
}

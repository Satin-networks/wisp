#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wisp {

// Cidr holds an IP network such as "10.0.0.0/24" or "::/0".
//
// Addresses stay in normalized text form (whatever inet_ntop prints) so two
// Cidrs built from different spellings of the same network still compare equal.
struct Cidr {
    std::string address;
    std::uint8_t prefix = 0;
    bool is_v6 = false;

    // A bare address with no "/" becomes a host route (/32 or /128).
    // Returns std::nullopt for anything that is not a valid network.
    static std::optional<Cidr> parse(std::string_view text);

    std::string to_string() const;

    bool operator==(const Cidr&) const = default;
};

// Endpoint is "host:port". IPv6 literals must be bracketed: "[2001:db8::1]:51820".
struct Endpoint {
    std::string host;
    std::uint16_t port = 0;

    static std::optional<Endpoint> parse(std::string_view text);

    std::string to_string() const;

    bool operator==(const Endpoint&) const = default;
};

// Search domains get checked harder than wg-quick bothers with. A value that
// is not a real domain either gets ignored silently somewhere downstream
// (a DNS leak nobody sees) or comes back out serialized in a shape that no
// longer parses the same way. Either outcome is worse than an error here.
// Anything that could read as a command-line flag to a resolver helper is
// out for the same reason.
bool is_valid_search_domain(std::string_view value);

// One tunnel definition: the contents of a single .conf file.
struct Peer {
    std::string public_key;
    std::optional<std::string> preshared_key;
    std::optional<Endpoint> endpoint;
    std::vector<Cidr> allowed_ips;
    std::optional<std::uint16_t> persistent_keepalive;

    bool operator==(const Peer&) const = default;
};

// wg-quick lets these be arbitrary shell commands (PreUp, PostUp, PreDown,
// PostDown), and even its Table/DNS handling runs through shell.
//
// Wisp parses them so the UI can show what a config claims it will do, and
// never executes them. Running shell out of a .conf file turns any
// downloadable profile into code execution as root, and the privileged side
// of this program must never be a shell.
struct Hooks {
    std::vector<std::string> pre_up;
    std::vector<std::string> post_up;
    std::vector<std::string> pre_down;
    std::vector<std::string> post_down;

    bool empty() const {
        return pre_up.empty() && post_up.empty() && pre_down.empty() && post_down.empty();
    }

    bool operator==(const Hooks&) const = default;
};

// Interface is one tunnel definition, i.e. the contents of a .conf file.
struct Interface {
    std::string private_key;

    std::vector<Cidr> addresses;
    std::vector<std::string> dns;
    std::vector<std::string> search_domains;

    std::optional<std::uint16_t> listen_port;
    std::optional<std::uint32_t> mtu;
    std::optional<std::uint32_t> fwmark;

    // "auto", "off", or a numeric routing table id.
    std::optional<std::string> table;
    bool save_config = false;

    std::vector<Peer> peers;
    Hooks hooks;

    // True when some peer's AllowedIPs covers a default route.
    bool routes_all_traffic() const;

    bool operator==(const Interface&) const = default;
};

}  // namespace wisp

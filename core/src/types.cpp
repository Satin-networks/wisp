#include "wisp/types.hpp"

#include <arpa/inet.h>

#include <string>

#include "util.hpp"

namespace wisp {

std::optional<Cidr> Cidr::parse(std::string_view text) {
    text = detail::trim(text);
    if (text.empty()) return std::nullopt;

    std::string_view addr_part = text;
    std::optional<unsigned long> explicit_prefix;

    if (const auto slash = text.find('/'); slash != std::string_view::npos) {
        addr_part = detail::trim(text.substr(0, slash));
        const auto prefix_part = detail::trim(text.substr(slash + 1));
        if (prefix_part.empty()) return std::nullopt;
        unsigned long value = 0;
        for (char c : prefix_part) {
            if (c < '0' || c > '9') return std::nullopt;
            value = value * 10 + static_cast<unsigned long>(c - '0');
            if (value > 128) return std::nullopt;  // no prefix is longer than 128
        }
        explicit_prefix = value;
    }
    if (addr_part.empty()) return std::nullopt;

    const std::string addr(addr_part);
    Cidr out;

    // inet_pton, not inet_aton: the shorthand forms ("10", "10.1", octal) would
    // parse to a different network than the author meant, so they stay rejected.
    in_addr v4{};
    if (::inet_pton(AF_INET, addr.c_str(), &v4) == 1) {
        if (explicit_prefix && *explicit_prefix > 32) return std::nullopt;
        out.is_v6 = false;
        out.prefix = static_cast<std::uint8_t>(explicit_prefix.value_or(32));
        char buf[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &v4, buf, sizeof(buf)) == nullptr) return std::nullopt;
        out.address = buf;
        return out;
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, addr.c_str(), &v6) == 1) {
        if (explicit_prefix && *explicit_prefix > 128) return std::nullopt;
        out.is_v6 = true;
        out.prefix = static_cast<std::uint8_t>(explicit_prefix.value_or(128));
        char buf[INET6_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET6, &v6, buf, sizeof(buf)) == nullptr) return std::nullopt;
        out.address = buf;
        return out;
    }

    return std::nullopt;
}

std::string Cidr::to_string() const {
    return address + "/" + std::to_string(prefix);
}

namespace {

std::optional<std::uint16_t> parse_port(std::string_view text) {
    text = detail::trim(text);
    if (text.empty() || text.size() > 5) return std::nullopt;
    unsigned long value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + static_cast<unsigned long>(c - '0');
    }
    if (value == 0 || value > 65535) return std::nullopt;
    return static_cast<std::uint16_t>(value);
}

}  // namespace

std::optional<Endpoint> Endpoint::parse(std::string_view text) {
    text = detail::trim(text);
    if (text.empty()) return std::nullopt;

    Endpoint out;

    if (text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        out.host = std::string(detail::trim(text.substr(1, close - 1)));
        if (out.host.empty()) return std::nullopt;

        std::string_view rest = text.substr(close + 1);
        if (rest.empty() || rest.front() != ':') return std::nullopt;
        rest.remove_prefix(1);

        const auto port = parse_port(rest);
        if (!port) return std::nullopt;
        out.port = *port;

        // Brackets mean an IPv6 literal, so it has to actually parse as one.
        in6_addr probe{};
        if (::inet_pton(AF_INET6, out.host.c_str(), &probe) != 1) return std::nullopt;
        return out;
    }

    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;

    out.host = std::string(detail::trim(text.substr(0, colon)));
    if (out.host.empty()) return std::nullopt;

    // A colon inside the host means an unbracketed IPv6 literal, which is
    // ambiguous with the port separator. Reject rather than guess: guessing
    // wrong here means connecting to the wrong peer.
    if (out.host.find(':') != std::string::npos) return std::nullopt;

    const auto port = parse_port(text.substr(colon + 1));
    if (!port) return std::nullopt;
    out.port = *port;
    return out;
}

std::string Endpoint::to_string() const {
    if (host.find(':') != std::string::npos) {
        return "[" + host + "]:" + std::to_string(port);
    }
    return host + ":" + std::to_string(port);
}

namespace {

// DNS names are capped at 253 characters by the DNS protocol itself.
constexpr std::size_t kMaxDomainLength = 253;

bool is_domain_character(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '-' || c == '_' || c == '~';
}

}  // namespace

bool is_valid_search_domain(std::string_view value) {
    if (value.empty() || value.size() > kMaxDomainLength) return false;

    // A leading '-' would be read as a flag by a resolver helper, and a
    // leading '.' would be a relative name. A leading '~' is meaningful: it is
    // systemd-resolved's marker for a routing domain, so it is allowed.
    if (value.front() == '-' || value.front() == '.') return false;

    for (const char c : value) {
        if (!is_domain_character(c)) return false;
    }
    return true;
}

bool Interface::routes_all_traffic() const {
    for (const auto& peer : peers) {
        for (const auto& net : peer.allowed_ips) {
            if (net.prefix == 0) return true;
        }
    }
    return false;
}

}  // namespace wisp

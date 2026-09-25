#include "wisp/config.hpp"

#include <cctype>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "util.hpp"
#include "wisp/keys.hpp"

namespace wisp {
namespace {

using detail::normalize_key_name;
using detail::split_list;
using detail::trim;

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos) {
            lines.push_back(text.substr(pos));
            break;
        }
        lines.push_back(text.substr(pos, nl - pos));
        pos = nl + 1;
    }
    return lines;
}

// Parse an unsigned 32-bit integer, accepting 0x-prefixed hex as wg does for
// FwMark.
std::optional<std::uint32_t> parse_uint(std::string_view text) {
    text = trim(text);
    if (text.empty()) return std::nullopt;

    unsigned base = 10;
    std::size_t i = 0;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        i = 2;
    }

    std::uint64_t value = 0;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        unsigned digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<unsigned>(c - '0');
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            digit = static_cast<unsigned>(c - 'a') + 10;
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            digit = static_cast<unsigned>(c - 'A') + 10;
        } else {
            return std::nullopt;
        }
        if (digit >= base) return std::nullopt;
        value = value * base + digit;
        if (value > 0xFFFFFFFFull) return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

std::optional<std::uint16_t> parse_port(std::string_view text) {
    const auto value = parse_uint(text);
    if (!value || *value == 0 || *value > 65535) return std::nullopt;
    return static_cast<std::uint16_t>(*value);
}

// PersistentKeepalive accepts an explicit 0 to mean "off".
std::optional<std::uint16_t> parse_keepalive(std::string_view text) {
    const auto value = parse_uint(text);
    if (!value || *value > 65535) return std::nullopt;
    return static_cast<std::uint16_t>(*value);
}

std::optional<bool> parse_bool(std::string_view text) {
    const auto lower = detail::ascii_lower(trim(text));
    if (lower == "true" || lower == "yes" || lower == "on" || lower == "1") return true;
    if (lower == "false" || lower == "no" || lower == "off" || lower == "0") return false;
    return std::nullopt;
}

// Keys that belong to the other section, so we can produce a precise error
// instead of quietly ignoring them.
bool is_peer_key(const std::string& key) {
    return key == "publickey" || key == "presharedkey" || key == "allowedips" ||
           key == "endpoint" || key == "persistentkeepalive";
}

bool is_interface_key(const std::string& key) {
    return key == "privatekey" || key == "address" || key == "dns" || key == "listenport" ||
           key == "mtu" || key == "fwmark" || key == "table" || key == "saveconfig" ||
           key == "preup" || key == "postup" || key == "predown" || key == "postdown";
}

}  // namespace

ParseResult parse_config(std::string_view text) {
    ParseResult result;
    Interface iface;

    enum class Section { None, InterfaceSection, PeerSection };
    Section section = Section::None;
    bool saw_interface_section = false;

    Peer peer;
    bool peer_open = false;
    std::size_t peer_line = 0;

    const auto commit_peer = [&]() {
        if (!peer_open) return;
        if (peer.public_key.empty()) {
            result.errors.push_back({peer_line, "[Peer] section has no PublicKey"});
        } else {
            iface.peers.push_back(std::move(peer));
        }
        peer = Peer{};
        peer_open = false;
    };

    const auto lines = split_lines(text);

    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::size_t line_no = i + 1;
        std::string_view line = lines[i];
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);

        // wg itself only treats '#' at the very start of a line as a comment,
        // but real-world configs carry inline comments and none of the fields
        // we accept can legitimately contain "#" preceded by whitespace.
        if (const auto hash = line.find('#'); hash != std::string_view::npos) {
            if (hash == 0 || std::isspace(static_cast<unsigned char>(line[hash - 1])) != 0) {
                line = line.substr(0, hash);
            }
        }

        line = trim(line);
        if (line.empty()) continue;

        if (line.front() == '[') {
            if (line.back() != ']') {
                result.errors.push_back({line_no, "section header is missing its closing ']'"});
                continue;
            }
            const auto raw_name = trim(line.substr(1, line.size() - 2));
            commit_peer();

            const auto name = normalize_key_name(raw_name);
            if (name == "interface") {
                section = Section::InterfaceSection;
                saw_interface_section = true;
            } else if (name == "peer") {
                section = Section::PeerSection;
                peer_open = true;
                peer_line = line_no;
            } else {
                result.errors.push_back({line_no, "unknown section [" + std::string(raw_name) + "]"});
                section = Section::None;
            }
            continue;
        }

        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            result.errors.push_back({line_no, "expected 'Key = Value'"});
            continue;
        }

        const auto raw_key = trim(line.substr(0, eq));
        const auto key = normalize_key_name(raw_key);
        const auto value = trim(line.substr(eq + 1));

        if (key.empty()) {
            result.errors.push_back({line_no, "missing key name"});
            continue;
        }
        if (value.empty()) {
            result.errors.push_back({line_no, "missing value for '" + std::string(raw_key) + "'"});
            continue;
        }
        if (section == Section::None) {
            result.errors.push_back(
                {line_no, "'" + std::string(raw_key) + "' appears before any section"});
            continue;
        }

        if (section == Section::InterfaceSection) {
            if (key == "privatekey") {
                if (!is_valid_key(value)) {
                    result.errors.push_back(
                        {line_no, "PrivateKey is not a valid 32-byte base64 key"});
                } else {
                    iface.private_key = std::string(value);
                }
            } else if (key == "address") {
                for (const auto piece : split_list(value, ',')) {
                    const auto cidr = Cidr::parse(piece);
                    if (!cidr) {
                        result.errors.push_back(
                            {line_no, "invalid Address '" + std::string(piece) + "'"});
                    } else {
                        iface.addresses.push_back(*cidr);
                    }
                }
            } else if (key == "dns") {
                for (const auto piece : split_list(value, ',')) {
                    // DNS carries both resolver addresses and search domains.
                    if (const auto as_ip = Cidr::parse(piece)) {
                        iface.dns.push_back(as_ip->address);
                    } else if (is_valid_search_domain(piece)) {
                        iface.search_domains.emplace_back(piece);
                    } else {
                        // Refuse it. An unusable entry either vanishes quietly
                        // (a DNS leak nobody sees) or comes back out serialized
                        // in a shape that no longer parses the same way.
                        result.errors.push_back(
                            {line_no, "invalid DNS entry '" + std::string(piece) +
                                          "' (expected an IP address or a domain name)"});
                    }
                }
            } else if (key == "listenport") {
                const auto port = parse_port(value);
                if (!port) {
                    result.errors.push_back({line_no, "ListenPort must be between 1 and 65535"});
                } else {
                    iface.listen_port = *port;
                }
            } else if (key == "mtu") {
                const auto mtu = parse_uint(value);
                if (!mtu || *mtu < 576 || *mtu > 65535) {
                    result.errors.push_back({line_no, "MTU must be between 576 and 65535"});
                } else {
                    iface.mtu = *mtu;
                }
            } else if (key == "fwmark") {
                const auto mark = parse_uint(value);
                if (!mark) {
                    result.errors.push_back({line_no, "FwMark must be a 32-bit number"});
                } else {
                    iface.fwmark = *mark;
                }
            } else if (key == "table") {
                const auto lower = detail::ascii_lower(value);
                if (lower == "auto" || lower == "off") {
                    iface.table = lower;
                } else if (const auto id = parse_uint(value)) {
                    iface.table = std::to_string(*id);
                } else {
                    result.errors.push_back({line_no, "Table must be 'auto', 'off' or a number"});
                }
            } else if (key == "saveconfig") {
                const auto flag = parse_bool(value);
                if (!flag) {
                    result.errors.push_back({line_no, "SaveConfig must be true or false"});
                } else {
                    iface.save_config = *flag;
                }
            } else if (key == "preup" || key == "postup" || key == "predown" || key == "postdown") {
                const std::string command(value);
                if (key == "preup") {
                    iface.hooks.pre_up.push_back(command);
                } else if (key == "postup") {
                    iface.hooks.post_up.push_back(command);
                } else if (key == "predown") {
                    iface.hooks.pre_down.push_back(command);
                } else {
                    iface.hooks.post_down.push_back(command);
                }
                result.warnings.push_back(
                    {line_no, std::string(raw_key) +
                                  " is not executed by Wisp; it is shown for information only"});
            } else if (is_peer_key(key)) {
                result.errors.push_back(
                    {line_no, "'" + std::string(raw_key) +
                                  "' is a [Peer] key and cannot appear in [Interface]"});
            } else {
                result.warnings.push_back(
                    {line_no, "ignoring unknown key '" + std::string(raw_key) + "'"});
            }
            continue;
        }

        // Section::PeerSection
        if (key == "publickey") {
            if (!is_valid_key(value)) {
                result.errors.push_back({line_no, "PublicKey is not a valid 32-byte base64 key"});
            } else {
                peer.public_key = std::string(value);
            }
        } else if (key == "presharedkey") {
            if (!is_valid_key(value)) {
                result.errors.push_back(
                    {line_no, "PresharedKey is not a valid 32-byte base64 key"});
            } else {
                peer.preshared_key = std::string(value);
            }
        } else if (key == "allowedips") {
            for (const auto piece : split_list(value, ',')) {
                const auto cidr = Cidr::parse(piece);
                if (!cidr) {
                    result.errors.push_back(
                        {line_no, "invalid AllowedIPs entry '" + std::string(piece) + "'"});
                } else {
                    peer.allowed_ips.push_back(*cidr);
                }
            }
        } else if (key == "endpoint") {
            const auto endpoint = Endpoint::parse(value);
            if (!endpoint) {
                result.errors.push_back({line_no,
                                         "invalid Endpoint '" + std::string(value) +
                                             "' (expected host:port, IPv6 in brackets)"});
            } else {
                peer.endpoint = *endpoint;
            }
        } else if (key == "persistentkeepalive") {
            const auto keepalive = parse_keepalive(value);
            if (!keepalive) {
                result.errors.push_back(
                    {line_no, "PersistentKeepalive must be between 0 and 65535 seconds"});
            } else if (*keepalive != 0) {
                peer.persistent_keepalive = *keepalive;
            }
        } else if (is_interface_key(key)) {
            result.errors.push_back(
                {line_no, "'" + std::string(raw_key) +
                              "' is an [Interface] key and cannot appear in [Peer]"});
        } else {
            result.warnings.push_back(
                {line_no, "ignoring unknown key '" + std::string(raw_key) + "'"});
        }
    }

    commit_peer();

    if (!saw_interface_section) {
        result.errors.push_back({0, "no [Interface] section found"});
    } else if (iface.private_key.empty()) {
        result.errors.push_back({0, "[Interface] section has no PrivateKey"});
    }
    if (saw_interface_section && iface.peers.empty()) {
        result.warnings.push_back({0, "config defines no peers, so the tunnel carries no traffic"});
    }

    if (!result.errors.empty()) {
        result.interface.reset();
        return result;
    }

    result.interface = std::move(iface);
    return result;
}

std::string serialize_config(const Interface& iface) {
    std::string out;
    out += "[Interface]\n";
    out += "PrivateKey = " + iface.private_key + "\n";

    if (!iface.addresses.empty()) {
        out += "Address = ";
        for (std::size_t i = 0; i < iface.addresses.size(); ++i) {
            if (i != 0) out += ", ";
            out += iface.addresses[i].to_string();
        }
        out += "\n";
    }

    if (!iface.dns.empty() || !iface.search_domains.empty()) {
        out += "DNS = ";
        bool first = true;
        const auto append = [&](const std::string& value) {
            if (!first) out += ", ";
            out += value;
            first = false;
        };
        for (const auto& server : iface.dns) append(server);
        for (const auto& domain : iface.search_domains) append(domain);
        out += "\n";
    }

    if (iface.mtu) out += "MTU = " + std::to_string(*iface.mtu) + "\n";
    if (iface.listen_port) out += "ListenPort = " + std::to_string(*iface.listen_port) + "\n";
    if (iface.fwmark) out += "FwMark = " + std::to_string(*iface.fwmark) + "\n";
    if (iface.table) out += "Table = " + *iface.table + "\n";
    if (iface.save_config) out += "SaveConfig = true\n";

    for (const auto& command : iface.hooks.pre_up) out += "PreUp = " + command + "\n";
    for (const auto& command : iface.hooks.post_up) out += "PostUp = " + command + "\n";
    for (const auto& command : iface.hooks.pre_down) out += "PreDown = " + command + "\n";
    for (const auto& command : iface.hooks.post_down) out += "PostDown = " + command + "\n";

    for (const auto& peer : iface.peers) {
        out += "\n[Peer]\n";
        out += "PublicKey = " + peer.public_key + "\n";
        if (peer.preshared_key) out += "PresharedKey = " + *peer.preshared_key + "\n";

        if (!peer.allowed_ips.empty()) {
            out += "AllowedIPs = ";
            for (std::size_t i = 0; i < peer.allowed_ips.size(); ++i) {
                if (i != 0) out += ", ";
                out += peer.allowed_ips[i].to_string();
            }
            out += "\n";
        }
        if (peer.endpoint) out += "Endpoint = " + peer.endpoint->to_string() + "\n";
        if (peer.persistent_keepalive) {
            out += "PersistentKeepalive = " + std::to_string(*peer.persistent_keepalive) + "\n";
        }
    }

    return out;
}

}  // namespace wisp

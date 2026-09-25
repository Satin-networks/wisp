#include "wisp/netlink.hpp"

#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "wisp/keys.hpp"

namespace wisp::nl {
namespace {

constexpr std::uint8_t kWireGuardGenlVersion = 1;
constexpr int kReceiveTimeoutSeconds = 5;
constexpr std::size_t kMaxMessagesPerTransaction = 64;

std::size_t align_up(std::size_t n) { return (n + 3) & ~std::size_t{3}; }

template <typename T>
void append_pod(std::vector<std::uint8_t>& out, const T& value) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), bytes, bytes + sizeof(T));
}

// Append one nlattr. Length includes the 4-byte header, and the whole
// attribute is padded to a 4-byte boundary, which is what the kernel walks.
void append_attr(std::vector<std::uint8_t>& out, std::uint16_t type, const void* data,
                 std::size_t len) {
    const std::size_t start = out.size();
    append_pod(out, static_cast<std::uint16_t>(4 + len));
    append_pod(out, type);
    if (len != 0 && data != nullptr) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        out.insert(out.end(), bytes, bytes + len);
    }
    while ((out.size() - start) % 4 != 0) out.push_back(0);
}

template <typename T>
void append_attr_number(std::vector<std::uint8_t>& out, std::uint16_t type, T value) {
    append_attr(out, type, &value, sizeof(T));
}

void append_attr_string(std::vector<std::uint8_t>& out, std::uint16_t type,
                        const std::string& value) {
    append_attr(out, type, value.data(), value.size() + 1);  // NUL-terminated
}

void append_attr_blob(std::vector<std::uint8_t>& out, std::uint16_t type,
                      const std::vector<std::uint8_t>& value) {
    append_attr(out, type, value.data(), value.size());
}

void append_attr_nested(std::vector<std::uint8_t>& out, std::uint16_t type,
                        const std::vector<std::uint8_t>& inner) {
    append_attr(out, static_cast<std::uint16_t>(type | NLA_F_NESTED), inner.data(), inner.size());
}

std::vector<std::uint8_t> build_message(std::uint16_t type, std::uint16_t flags, std::uint32_t seq,
                                        const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out;
    out.reserve(sizeof(nlmsghdr) + payload.size());
    append_pod(out, static_cast<std::uint32_t>(sizeof(nlmsghdr) + payload.size()));
    append_pod(out, type);
    append_pod(out, flags);
    append_pod(out, seq);
    append_pod(out, static_cast<std::uint32_t>(0));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> genl_payload(std::uint8_t command,
                                       const std::vector<std::uint8_t>& attributes) {
    std::vector<std::uint8_t> out;
    out.reserve(sizeof(genlmsghdr) + attributes.size());
    out.push_back(command);
    out.push_back(kWireGuardGenlVersion);
    append_pod(out, static_cast<std::uint16_t>(0));  // reserved
    out.insert(out.end(), attributes.begin(), attributes.end());
    return out;
}

std::optional<std::vector<std::uint8_t>> raw_key(const std::string& base64_key) {
    const auto decoded = wisp::decode_key(base64_key);
    if (!decoded) return std::nullopt;
    return std::vector<std::uint8_t>(decoded->begin(), decoded->end());
}

// The kernel's endpoint attribute is a raw sockaddr, so hostnames have to be
// resolved before we get here.
std::optional<std::vector<std::uint8_t>> encode_endpoint(const Endpoint& endpoint) {
    std::vector<std::uint8_t> out;

    in_addr v4{};
    if (::inet_pton(AF_INET, endpoint.host.c_str(), &v4) == 1) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(endpoint.port);
        addr.sin_addr = v4;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&addr);
        out.assign(bytes, bytes + sizeof(addr));
        return out;
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, endpoint.host.c_str(), &v6) == 1) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(endpoint.port);
        addr.sin6_addr = v6;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&addr);
        out.assign(bytes, bytes + sizeof(addr));
        return out;
    }

    return std::nullopt;
}

std::optional<Endpoint> decode_endpoint(const std::uint8_t* data, std::size_t len) {
    if (len < sizeof(sa_family_t)) return std::nullopt;

    sa_family_t family = 0;
    std::memcpy(&family, data, sizeof(family));

    char buffer[INET6_ADDRSTRLEN] = {};
    if (family == AF_INET && len >= sizeof(sockaddr_in)) {
        sockaddr_in addr{};
        std::memcpy(&addr, data, sizeof(addr));
        if (::inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer)) == nullptr) {
            return std::nullopt;
        }
        return Endpoint{std::string(buffer), ntohs(addr.sin_port)};
    }
    if (family == AF_INET6 && len >= sizeof(sockaddr_in6)) {
        sockaddr_in6 addr{};
        std::memcpy(&addr, data, sizeof(addr));
        if (::inet_ntop(AF_INET6, &addr.sin6_addr, buffer, sizeof(buffer)) == nullptr) {
            return std::nullopt;
        }
        return Endpoint{std::string(buffer), ntohs(addr.sin6_port)};
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> encode_allowed_ip(const Cidr& cidr) {
    std::vector<std::uint8_t> out;

    in_addr v4{};
    if (::inet_pton(AF_INET, cidr.address.c_str(), &v4) == 1) {
        append_attr_number<std::uint16_t>(out, WGALLOWEDIP_A_FAMILY,
                                         static_cast<std::uint16_t>(AF_INET));
        append_attr(out, WGALLOWEDIP_A_IPADDR, &v4, sizeof(v4));
        append_attr_number<std::uint8_t>(out, WGALLOWEDIP_A_CIDR_MASK, cidr.prefix);
        return out;
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, cidr.address.c_str(), &v6) == 1) {
        append_attr_number<std::uint16_t>(out, WGALLOWEDIP_A_FAMILY,
                                         static_cast<std::uint16_t>(AF_INET6));
        append_attr(out, WGALLOWEDIP_A_IPADDR, &v6, sizeof(v6));
        append_attr_number<std::uint8_t>(out, WGALLOWEDIP_A_CIDR_MASK, cidr.prefix);
        return out;
    }

    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> encode_peer(const Peer& peer) {
    const auto public_key = raw_key(peer.public_key);
    if (!public_key) return std::nullopt;

    std::vector<std::uint8_t> out;
    append_attr_blob(out, WGPEER_A_PUBLIC_KEY, *public_key);

    if (peer.preshared_key) {
        const auto preshared = raw_key(*peer.preshared_key);
        if (!preshared) return std::nullopt;
        append_attr_blob(out, WGPEER_A_PRESHARED_KEY, *preshared);
    }

    if (!peer.allowed_ips.empty()) {
        // Replace rather than append, so that applying the same profile twice
        // converges instead of accumulating stale routes.
        append_attr_number<std::uint32_t>(out, WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);

        std::vector<std::uint8_t> list;
        for (std::size_t i = 0; i < peer.allowed_ips.size(); ++i) {
            const auto encoded = encode_allowed_ip(peer.allowed_ips[i]);
            if (!encoded) return std::nullopt;
            append_attr_nested(list, static_cast<std::uint16_t>(i), *encoded);
        }
        append_attr_nested(out, WGPEER_A_ALLOWEDIPS, list);
    }

    if (peer.endpoint) {
        const auto encoded = encode_endpoint(*peer.endpoint);
        if (!encoded) return std::nullopt;  // hostname was not resolved
        append_attr_blob(out, WGPEER_A_ENDPOINT, *encoded);
    }

    if (peer.persistent_keepalive) {
        append_attr_number<std::uint16_t>(out, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                                         *peer.persistent_keepalive);
    }

    return out;
}

// Small views over netlink attributes, shared by the decoders below.
struct AttrView {
    std::uint16_t type = 0;  // NLA_TYPE_MASK already applied
    const std::uint8_t* payload = nullptr;
    std::size_t length = 0;
};

std::vector<AttrView> parse_attributes(const std::uint8_t* data, std::size_t len) {
    std::vector<AttrView> attributes;
    std::size_t offset = 0;
    while (offset + 4 <= len) {
        std::uint16_t attr_len = 0;
        std::uint16_t attr_type = 0;
        std::memcpy(&attr_len, data + offset, sizeof(attr_len));
        std::memcpy(&attr_type, data + offset + 2, sizeof(attr_type));

        if (attr_len < 4 || offset + attr_len > len) break;  // malformed: stop

        AttrView view;
        view.type = static_cast<std::uint16_t>(attr_type & NLA_TYPE_MASK);
        view.payload = data + offset + 4;
        view.length = attr_len - 4;
        attributes.push_back(view);

        offset += align_up(attr_len);
    }
    return attributes;
}

template <typename T>
bool read_number(const AttrView& view, T& out) {
    if (view.length < sizeof(T)) return false;
    std::memcpy(&out, view.payload, sizeof(T));
    return true;
}

std::string read_string(const AttrView& view) {
    std::size_t n = 0;
    while (n < view.length && view.payload[n] != 0) ++n;
    return std::string(reinterpret_cast<const char*>(view.payload), n);
}

std::optional<Cidr> decode_allowed_ip(const std::uint8_t* data, std::size_t len) {
    std::optional<std::uint16_t> family;
    std::optional<std::uint8_t> prefix;
    std::string address;

    for (const auto& attr : parse_attributes(data, len)) {
        if (attr.type == WGALLOWEDIP_A_FAMILY) {
            std::uint16_t value = 0;
            if (read_number(attr, value)) family = value;
        } else if (attr.type == WGALLOWEDIP_A_CIDR_MASK) {
            std::uint8_t value = 0;
            if (read_number(attr, value)) prefix = value;
        } else if (attr.type == WGALLOWEDIP_A_IPADDR) {
            char buffer[INET6_ADDRSTRLEN] = {};
            if (attr.length == sizeof(in_addr) &&
                ::inet_ntop(AF_INET, attr.payload, buffer, sizeof(buffer)) != nullptr) {
                address = buffer;
            } else if (attr.length == sizeof(in6_addr) &&
                       ::inet_ntop(AF_INET6, attr.payload, buffer, sizeof(buffer)) != nullptr) {
                address = buffer;
            }
        }
    }

    if (address.empty() || !family || !prefix) return std::nullopt;
    Cidr cidr;
    cidr.address = address;
    cidr.prefix = *prefix;
    cidr.is_v6 = (*family == AF_INET6);
    return cidr;
}

std::optional<PeerState> decode_peer(const std::uint8_t* data, std::size_t len) {
    PeerState peer;
    for (const auto& attr : parse_attributes(data, len)) {
        switch (attr.type) {
            case WGPEER_A_PUBLIC_KEY:
                if (attr.length == WG_KEY_LEN) peer.public_key = wisp::encode_key(attr.payload, WG_KEY_LEN);
                break;
            case WGPEER_A_PRESHARED_KEY:
                peer.has_preshared_key = true;
                break;
            case WGPEER_A_ENDPOINT:
                peer.endpoint = decode_endpoint(attr.payload, attr.length);
                break;
            case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: {
                std::uint16_t seconds = 0;
                if (read_number(attr, seconds) && seconds != 0) peer.persistent_keepalive = seconds;
                break;
            }
            case WGPEER_A_LAST_HANDSHAKE_TIME: {
                timespec timestamp{};
                if (attr.length >= sizeof(timestamp)) {
                    std::memcpy(&timestamp, attr.payload, sizeof(timestamp));
                    peer.last_handshake_seconds = static_cast<std::uint64_t>(timestamp.tv_sec);
                }
                break;
            }
            case WGPEER_A_RX_BYTES: {
                std::uint64_t bytes = 0;
                if (read_number(attr, bytes)) peer.rx_bytes = bytes;
                break;
            }
            case WGPEER_A_TX_BYTES: {
                std::uint64_t bytes = 0;
                if (read_number(attr, bytes)) peer.tx_bytes = bytes;
                break;
            }
            case WGPEER_A_ALLOWEDIPS: {
                for (const auto& entry : parse_attributes(attr.payload, attr.length)) {
                    if (const auto cidr = decode_allowed_ip(entry.payload, entry.length)) {
                        peer.allowed_ips.push_back(*cidr);
                    }
                }
                break;
            }
            default:
                break;
        }
    }
    if (peer.public_key.empty()) return std::nullopt;
    return peer;
}

}  // namespace

std::vector<std::uint8_t> build_get_family(std::uint32_t seq, const std::string& family_name) {
    std::vector<std::uint8_t> attributes;
    append_attr_string(attributes, CTRL_ATTR_FAMILY_NAME, family_name);
    return build_message(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq,
                         genl_payload(CTRL_CMD_GETFAMILY, attributes));
}

std::vector<std::uint8_t> build_get_device(std::uint16_t family_id, std::uint32_t seq,
                                           const std::string& ifname) {
    std::vector<std::uint8_t> attributes;
    append_attr_string(attributes, WGDEVICE_A_IFNAME, ifname);
    return build_message(family_id, NLM_F_REQUEST | NLM_F_ACK, seq,
                         genl_payload(WG_CMD_GET_DEVICE, attributes));
}

std::optional<std::vector<std::uint8_t>> build_set_device(std::uint16_t family_id,
                                                          std::uint32_t seq,
                                                          const DeviceConfig& config) {
    if (config.ifname.empty()) return std::nullopt;

    std::vector<std::uint8_t> attributes;
    append_attr_string(attributes, WGDEVICE_A_IFNAME, config.ifname);

    if (config.private_key) {
        const auto key = raw_key(*config.private_key);
        if (!key) return std::nullopt;
        append_attr_blob(attributes, WGDEVICE_A_PRIVATE_KEY, *key);
    }
    if (config.listen_port) {
        append_attr_number<std::uint16_t>(attributes, WGDEVICE_A_LISTEN_PORT, *config.listen_port);
    }
    if (config.fwmark) {
        append_attr_number<std::uint32_t>(attributes, WGDEVICE_A_FWMARK, *config.fwmark);
    }
    if (config.replace_peers) {
        append_attr_number<std::uint32_t>(attributes, WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    }

    if (!config.peers.empty()) {
        // The peers list is an array of indexed nested attributes.
        std::vector<std::uint8_t> peers;
        for (std::size_t i = 0; i < config.peers.size(); ++i) {
            const auto encoded = encode_peer(config.peers[i]);
            if (!encoded) return std::nullopt;
            append_attr_nested(peers, static_cast<std::uint16_t>(i), *encoded);
        }
        append_attr_nested(attributes, WGDEVICE_A_PEERS, peers);
    }

    return build_message(family_id, NLM_F_REQUEST | NLM_F_ACK, seq,
                         genl_payload(WG_CMD_SET_DEVICE, attributes));
}

std::vector<std::uint8_t> build_create_link(std::uint32_t seq, const std::string& ifname,
                                            std::optional<std::uint32_t> mtu) {
    ifinfomsg info{};
    info.ifi_family = AF_UNSPEC;
    info.ifi_change = 0xFFFFFFFF;

    std::vector<std::uint8_t> attributes;
    append_attr_string(attributes, IFLA_IFNAME, ifname);
    if (mtu) append_attr_number<std::uint32_t>(attributes, IFLA_MTU, *mtu);

    std::vector<std::uint8_t> linkinfo;
    append_attr_string(linkinfo, IFLA_INFO_KIND, "wireguard");
    append_attr_nested(attributes, IFLA_LINKINFO, linkinfo);

    std::vector<std::uint8_t> payload;
    append_pod(payload, info);
    payload.insert(payload.end(), attributes.begin(), attributes.end());

    return build_message(
        RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq, payload);
}

std::vector<std::uint8_t> build_delete_link(std::uint32_t seq, std::uint32_t ifindex) {
    ifinfomsg info{};
    info.ifi_family = AF_UNSPEC;
    info.ifi_index = static_cast<int>(ifindex);

    std::vector<std::uint8_t> payload;
    append_pod(payload, info);

    return build_message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq, payload);
}

std::vector<std::uint8_t> build_set_link(std::uint32_t seq, std::uint32_t ifindex, bool up,
                                         std::optional<std::uint32_t> mtu) {
    ifinfomsg info{};
    info.ifi_family = AF_UNSPEC;
    info.ifi_index = static_cast<int>(ifindex);
    info.ifi_flags = up ? IFF_UP : 0;
    info.ifi_change = IFF_UP;

    std::vector<std::uint8_t> attributes;
    if (mtu) append_attr_number<std::uint32_t>(attributes, IFLA_MTU, *mtu);

    std::vector<std::uint8_t> payload;
    append_pod(payload, info);
    payload.insert(payload.end(), attributes.begin(), attributes.end());

    return build_message(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq, payload);
}

std::vector<std::uint8_t> build_address(std::uint32_t seq, std::uint32_t ifindex, const Cidr& cidr,
                                        bool add) {
    ifaddrmsg message{};
    message.ifa_family = cidr.is_v6 ? AF_INET6 : AF_INET;
    message.ifa_prefixlen = cidr.prefix;
    message.ifa_scope = RT_SCOPE_UNIVERSE;
    message.ifa_index = ifindex;

    std::vector<std::uint8_t> attributes;
    in_addr v4{};
    in6_addr v6{};
    if (!cidr.is_v6 && ::inet_pton(AF_INET, cidr.address.c_str(), &v4) == 1) {
        append_attr(attributes, IFA_LOCAL, &v4, sizeof(v4));
        append_attr(attributes, IFA_ADDRESS, &v4, sizeof(v4));
    } else if (cidr.is_v6 && ::inet_pton(AF_INET6, cidr.address.c_str(), &v6) == 1) {
        append_attr(attributes, IFA_ADDRESS, &v6, sizeof(v6));
    }

    std::vector<std::uint8_t> payload;
    append_pod(payload, message);
    payload.insert(payload.end(), attributes.begin(), attributes.end());

    std::uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) flags |= NLM_F_CREATE | NLM_F_REPLACE;

    return build_message(add ? RTM_NEWADDR : RTM_DELADDR, flags, seq, payload);
}

std::vector<std::uint8_t> build_route(std::uint32_t seq, std::uint32_t ifindex, const Cidr& dst,
                                      std::uint32_t table, bool add) {
    rtmsg message{};
    message.rtm_family = dst.is_v6 ? AF_INET6 : AF_INET;
    message.rtm_dst_len = dst.prefix;
    message.rtm_table =
        table <= 255 ? static_cast<std::uint8_t>(table) : static_cast<std::uint8_t>(RT_TABLE_UNSPEC);
    message.rtm_protocol = RTPROT_BOOT;
    message.rtm_scope = RT_SCOPE_UNIVERSE;
    message.rtm_type = RTN_UNICAST;

    std::vector<std::uint8_t> attributes;

    // A /0 destination is the default route, which carries no RTA_DST.
    if (dst.prefix != 0) {
        in_addr v4{};
        in6_addr v6{};
        if (!dst.is_v6 && ::inet_pton(AF_INET, dst.address.c_str(), &v4) == 1) {
            append_attr(attributes, RTA_DST, &v4, sizeof(v4));
        } else if (dst.is_v6 && ::inet_pton(AF_INET6, dst.address.c_str(), &v6) == 1) {
            append_attr(attributes, RTA_DST, &v6, sizeof(v6));
        }
    }

    append_attr_number<std::uint32_t>(attributes, RTA_OIF, ifindex);

    // rtm_table is only 8 bits, so wider table ids travel in RTA_TABLE.
    if (table > 255) append_attr_number<std::uint32_t>(attributes, RTA_TABLE, table);

    std::vector<std::uint8_t> payload;
    append_pod(payload, message);
    payload.insert(payload.end(), attributes.begin(), attributes.end());

    std::uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) flags |= NLM_F_CREATE | NLM_F_REPLACE;

    return build_message(add ? RTM_NEWROUTE : RTM_DELROUTE, flags, seq, payload);
}

std::vector<std::uint8_t> build_rule(std::uint32_t seq, const RuleSpec& spec, bool add) {
    fib_rule_hdr header{};
    header.family = static_cast<std::uint8_t>(spec.family);
    header.action = spec.action;
    header.flags = spec.invert ? FIB_RULE_INVERT : 0;

    // rtm-style table fields are only 8 bits; wider ids travel in FRA_TABLE.
    if (spec.table < 256) {
        header.table = static_cast<std::uint8_t>(spec.table);
    } else {
        header.table = RT_TABLE_UNSPEC;
    }

    std::vector<std::uint8_t> attributes;
    if (spec.table >= 256) {
        append_attr_number<std::uint32_t>(attributes, FRA_TABLE, spec.table);
    }
    if (spec.priority) {
        append_attr_number<std::uint32_t>(attributes, FRA_PRIORITY, *spec.priority);
    }
    if (spec.fwmark) {
        append_attr_number<std::uint32_t>(attributes, FRA_FWMARK, *spec.fwmark);
    }
    if (spec.suppress_prefixlength) {
        append_attr_number<std::uint32_t>(attributes, FRA_SUPPRESS_PREFIXLEN,
                                         *spec.suppress_prefixlength);
    }

    std::vector<std::uint8_t> payload;
    append_pod(payload, header);
    payload.insert(payload.end(), attributes.begin(), attributes.end());

    std::uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
    // NLM_F_EXCL means we refuse to clobber a rule that is already there,
    // rather than silently adopting or replacing someone else's policy.
    if (add) flags |= NLM_F_CREATE | NLM_F_EXCL;

    return build_message(add ? RTM_NEWRULE : RTM_DELRULE, flags, seq, payload);
}

std::optional<std::uint16_t> parse_family_id(const std::uint8_t* data, std::size_t len) {
    if (len < sizeof(genlmsghdr)) return std::nullopt;
    for (const auto& attr :
         parse_attributes(data + sizeof(genlmsghdr), len - sizeof(genlmsghdr))) {
        if (attr.type == CTRL_ATTR_FAMILY_ID) {
            std::uint16_t id = 0;
            if (read_number(attr, id)) return id;
        }
    }
    return std::nullopt;
}

std::optional<DeviceState> parse_device(const std::uint8_t* data, std::size_t len) {
    if (len < sizeof(genlmsghdr)) return std::nullopt;
    if (data[0] != WG_CMD_GET_DEVICE) return std::nullopt;

    DeviceState state;
    bool saw_device = false;

    for (const auto& attr : parse_attributes(data + sizeof(genlmsghdr), len - sizeof(genlmsghdr))) {
        switch (attr.type) {
            case WGDEVICE_A_IFNAME:
                state.ifname = read_string(attr);
                saw_device = true;
                break;
            case WGDEVICE_A_PUBLIC_KEY:
                if (attr.length == WG_KEY_LEN) {
                    state.public_key = wisp::encode_key(attr.payload, WG_KEY_LEN);
                }
                break;
            case WGDEVICE_A_LISTEN_PORT: {
                std::uint16_t port = 0;
                if (read_number(attr, port) && port != 0) state.listen_port = port;
                break;
            }
            case WGDEVICE_A_FWMARK: {
                std::uint32_t mark = 0;
                if (read_number(attr, mark) && mark != 0) state.fwmark = mark;
                break;
            }
            case WGDEVICE_A_PEERS: {
                for (const auto& entry : parse_attributes(attr.payload, attr.length)) {
                    if (const auto peer = decode_peer(entry.payload, entry.length)) {
                        state.peers.push_back(*peer);
                    }
                }
                break;
            }
            default:
                break;
        }
    }

    if (!saw_device) return std::nullopt;
    return state;
}

std::optional<std::uint32_t> parse_link_index(const std::uint8_t* data, std::size_t len) {
    if (len < sizeof(ifinfomsg)) return std::nullopt;
    ifinfomsg info{};
    std::memcpy(&info, data, sizeof(info));
    return static_cast<std::uint32_t>(info.ifi_index);
}

std::optional<std::int32_t> parse_error(const std::uint8_t* data, std::size_t len) {
    if (len < sizeof(std::int32_t)) return std::nullopt;
    std::int32_t code = 0;
    std::memcpy(&code, data, sizeof(code));
    return code;
}

std::optional<Endpoint> resolve_endpoint(const Endpoint& endpoint) {
    in_addr probe_v4{};
    in6_addr probe_v6{};
    if (::inet_pton(AF_INET, endpoint.host.c_str(), &probe_v4) == 1 ||
        ::inet_pton(AF_INET6, endpoint.host.c_str(), &probe_v6) == 1) {
        return endpoint;  // already a literal
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* results = nullptr;
    if (::getaddrinfo(endpoint.host.c_str(), nullptr, &hints, &results) != 0 || results == nullptr) {
        return std::nullopt;
    }

    std::optional<Endpoint> resolved;
    for (addrinfo* entry = results; entry != nullptr && !resolved; entry = entry->ai_next) {
        char buffer[INET6_ADDRSTRLEN] = {};
        if (entry->ai_family == AF_INET) {
            const auto* addr = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
            if (::inet_ntop(AF_INET, &addr->sin_addr, buffer, sizeof(buffer)) != nullptr) {
                resolved = Endpoint{std::string(buffer), endpoint.port};
            }
        } else if (entry->ai_family == AF_INET6) {
            const auto* addr = reinterpret_cast<const sockaddr_in6*>(entry->ai_addr);
            if (::inet_ntop(AF_INET6, &addr->sin6_addr, buffer, sizeof(buffer)) != nullptr) {
                resolved = Endpoint{std::string(buffer), endpoint.port};
            }
        }
    }

    ::freeaddrinfo(results);
    return resolved;
}

Client::Client() {
    fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd_ < 0) {
        error_ = std::string("netlink socket failed: ") + std::strerror(errno);
        return;
    }

    // Named `local` rather than `address`, which would shadow the address()
    // member declared by this class.
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    local.nl_pid = 0;     // let the kernel pick the port id
    local.nl_groups = 0;  // unicast only

    if (::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        error_ = std::string("netlink bind failed: ") + std::strerror(errno);
        ::close(fd_);
        fd_ = -1;
        return;
    }

    // Without a timeout a dropped reply would hang the helper indefinitely.
    timeval timeout{};
    timeout.tv_sec = kReceiveTimeoutSeconds;
    timeout.tv_usec = 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

Client::~Client() {
    if (fd_ >= 0) ::close(fd_);
}

bool Client::transact(const std::vector<std::uint8_t>& request, std::vector<std::uint8_t>* response) {
    if (response != nullptr) response->clear();
    if (fd_ < 0) return false;

    if (::send(fd_, request.data(), request.size(), 0) < 0) {
        error_ = std::string("netlink send failed: ") + std::strerror(errno);
        return false;
    }

    std::vector<std::uint8_t> buffer(64 * 1024);

    for (std::size_t received_messages = 0; received_messages < kMaxMessagesPerTransaction;
         ++received_messages) {
        const ssize_t n = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                error_ = "timed out waiting for a netlink reply";
            } else {
                error_ = std::string("netlink recv failed: ") + std::strerror(errno);
            }
            return false;
        }

        std::size_t offset = 0;
        bool finished = false;

        while (offset + sizeof(nlmsghdr) <= static_cast<std::size_t>(n)) {
            nlmsghdr header{};
            std::memcpy(&header, buffer.data() + offset, sizeof(header));

            if (header.nlmsg_len < sizeof(nlmsghdr) ||
                offset + header.nlmsg_len > static_cast<std::size_t>(n)) {
                error_ = "malformed netlink message";
                return false;
            }

            const std::uint8_t* payload = buffer.data() + offset + sizeof(nlmsghdr);
            const std::size_t payload_len = header.nlmsg_len - sizeof(nlmsghdr);

            if (header.nlmsg_type == NLMSG_ERROR) {
                const auto code = parse_error(payload, payload_len);
                if (!code) {
                    error_ = "malformed netlink error message";
                    return false;
                }
                if (*code != 0) {
                    error_ = std::string("kernel rejected the request: ") + std::strerror(-*code);
                    return false;
                }
                finished = true;  // ACK
            } else if (header.nlmsg_type == NLMSG_DONE) {
                finished = true;
            } else if (response != nullptr) {
                *response = std::vector<std::uint8_t>(payload, payload + payload_len);
            }

            offset += align_up(header.nlmsg_len);
        }

        if (finished) return true;
    }

    error_ = "too many netlink messages in one exchange";
    return false;
}

std::uint16_t Client::wireguard_family() {
    if (wg_family_ != 0) return wg_family_;

    std::vector<std::uint8_t> response;
    if (!transact(build_get_family(++seq_, "wireguard"), &response)) return 0;

    const auto id = parse_family_id(response.data(), response.size());
    if (!id) {
        error_ = "could not read the wireguard family id (is the wireguard module loaded?)";
        return 0;
    }

    wg_family_ = *id;
    return wg_family_;
}

bool Client::set_device(const DeviceConfig& config) {
    const auto family = wireguard_family();
    if (family == 0) return false;

    // The kernel takes sockaddrs, so resolve any hostnames first.
    DeviceConfig ready = config;
    for (auto& peer : ready.peers) {
        if (!peer.endpoint) continue;
        const auto resolved = resolve_endpoint(*peer.endpoint);
        if (!resolved) {
            error_ = "could not resolve endpoint " + peer.endpoint->to_string();
            return false;
        }
        peer.endpoint = *resolved;
    }

    const auto message = build_set_device(family, ++seq_, ready);
    if (!message) {
        error_ = "device configuration could not be encoded";
        return false;
    }

    return transact(*message, nullptr);
}

std::optional<DeviceState> Client::get_device(const std::string& ifname) {
    const auto family = wireguard_family();
    if (family == 0) return std::nullopt;

    std::vector<std::uint8_t> response;
    if (!transact(build_get_device(family, ++seq_, ifname), &response)) return std::nullopt;

    return parse_device(response.data(), response.size());
}

std::optional<std::uint32_t> Client::interface_index(const std::string& ifname) {
    ifinfomsg info{};
    info.ifi_family = AF_UNSPEC;

    std::vector<std::uint8_t> attributes;
    append_attr_string(attributes, IFLA_IFNAME, ifname);

    std::vector<std::uint8_t> payload;
    append_pod(payload, info);
    payload.insert(payload.end(), attributes.begin(), attributes.end());

    std::vector<std::uint8_t> response;
    if (!transact(build_message(RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, ++seq_, payload),
                  &response)) {
        return std::nullopt;
    }

    return parse_link_index(response.data(), response.size());
}

std::optional<std::uint32_t> Client::create_link(const std::string& ifname,
                                                 std::optional<std::uint32_t> mtu) {
    if (!transact(build_create_link(++seq_, ifname, mtu), nullptr)) return std::nullopt;
    return interface_index(ifname);
}

bool Client::delete_link(std::uint32_t ifindex) {
    return transact(build_delete_link(++seq_, ifindex), nullptr);
}

bool Client::set_link(std::uint32_t ifindex, bool up, std::optional<std::uint32_t> mtu) {
    return transact(build_set_link(++seq_, ifindex, up, mtu), nullptr);
}

bool Client::address(std::uint32_t ifindex, const Cidr& cidr, bool add) {
    return transact(build_address(++seq_, ifindex, cidr, add), nullptr);
}

bool Client::route(std::uint32_t ifindex, const Cidr& dst, std::uint32_t table, bool add) {
    return transact(build_route(++seq_, ifindex, dst, table, add), nullptr);
}

bool Client::rule(const RuleSpec& spec, bool add) {
    return transact(build_rule(++seq_, spec, add), nullptr);
}

}  // namespace wisp::nl

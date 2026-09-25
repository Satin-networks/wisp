#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "wisp/keys.hpp"
#include "wisp/netlink.hpp"
#include "wisp_test.hpp"

using namespace wisp;
using namespace wisp::nl;

namespace {

constexpr std::size_t align_up(std::size_t n) { return (n + 3) & ~std::size_t{3}; }

struct RawHeader {
    std::uint32_t length;
    std::uint16_t type;
    std::uint16_t flags;
    std::uint32_t seq;
    std::uint32_t pid;
};

RawHeader read_header(const std::vector<std::uint8_t>& message) {
    RawHeader header{};
    std::memcpy(&header, message.data(), sizeof(header));
    return header;
}

struct TestAttr {
    std::uint16_t type;
    std::vector<std::uint8_t> payload;
};

// An independent attribute walker, so the encoding is verified by different
// code than the code that produced it.
std::vector<TestAttr> walk(const std::uint8_t* data, std::size_t len) {
    std::vector<TestAttr> attributes;
    std::size_t offset = 0;
    while (offset + 4 <= len) {
        std::uint16_t attr_len = 0;
        std::uint16_t attr_type = 0;
        std::memcpy(&attr_len, data + offset, sizeof(attr_len));
        std::memcpy(&attr_type, data + offset + 2, sizeof(attr_type));
        if (attr_len < 4 || offset + attr_len > len) break;

        TestAttr attr;
        attr.type = static_cast<std::uint16_t>(attr_type & NLA_TYPE_MASK);
        attr.payload.assign(data + offset + 4, data + offset + attr_len);
        attributes.push_back(attr);

        offset += align_up(attr_len);
    }
    return attributes;
}

// Attributes that live after the genlmsghdr.
std::vector<TestAttr> walk_genl(const std::vector<std::uint8_t>& message) {
    const std::size_t start = sizeof(nlmsghdr) + sizeof(genlmsghdr);
    return walk(message.data() + start, message.size() - start);
}

bool has_attr(const std::vector<TestAttr>& attributes, std::uint16_t type) {
    for (const auto& attr : attributes) {
        if (attr.type == type) return true;
    }
    return false;
}

std::optional<TestAttr> find_attr(const std::vector<TestAttr>& attributes, std::uint16_t type) {
    for (const auto& attr : attributes) {
        if (attr.type == type) return attr;
    }
    return std::nullopt;
}

std::string attr_string(const TestAttr& attr) {
    std::size_t n = 0;
    while (n < attr.payload.size() && attr.payload[n] != 0) ++n;
    return std::string(reinterpret_cast<const char*>(attr.payload.data()), n);
}

template <typename T>
T attr_number(const TestAttr& attr) {
    T value{};
    std::memcpy(&value, attr.payload.data(), sizeof(T));
    return value;
}

// Small encoder for building synthetic kernel replies
void put_bytes(std::vector<std::uint8_t>& out, const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    out.insert(out.end(), bytes, bytes + len);
}

template <typename T>
void put_number(std::vector<std::uint8_t>& out, T value) {
    put_bytes(out, &value, sizeof(T));
}

void put_attr(std::vector<std::uint8_t>& out, std::uint16_t type, const void* data,
              std::size_t len, bool nested = false) {
    const std::size_t start = out.size();
    put_number(out, static_cast<std::uint16_t>(4 + len));
    put_number(out, static_cast<std::uint16_t>(nested ? (type | NLA_F_NESTED) : type));
    if (len != 0) put_bytes(out, data, len);
    while ((out.size() - start) % 4 != 0) out.push_back(0);
}

void put_attr_string(std::vector<std::uint8_t>& out, std::uint16_t type, const std::string& value) {
    put_attr(out, type, value.data(), value.size() + 1);
}

void put_attr_nested(std::vector<std::uint8_t>& out, std::uint16_t type,
                     const std::vector<std::uint8_t>& inner) {
    put_attr(out, type, inner.data(), inner.size(), true);
}

std::vector<std::uint8_t> genl_header(std::uint8_t command) {
    std::vector<std::uint8_t> out;
    out.push_back(command);
    out.push_back(1);
    put_number(out, static_cast<std::uint16_t>(0));
    return out;
}

}  // namespace

// Message framing
WISP_TEST(nlmsg_header_is_well_formed) {
    const auto message = build_get_device(42, 7, "wisp0");
    const auto header = read_header(message);

    WISP_CHECK_EQ(header.length, static_cast<std::uint32_t>(message.size()));
    WISP_CHECK_EQ(header.type, static_cast<std::uint16_t>(42));
    WISP_CHECK_EQ(header.seq, 7u);
    WISP_CHECK_EQ(header.pid, 0u);
    WISP_CHECK((header.flags & NLM_F_REQUEST) != 0);
    WISP_CHECK((header.flags & NLM_F_ACK) != 0);
}

WISP_TEST(attributes_are_padded_to_four_bytes) {
    // "ab" plus a NUL is 3 payload bytes, which must be padded out to 8 total.
    const auto message = build_get_device(1, 1, "ab");
    const auto attributes = walk_genl(message);
    WISP_CHECK_EQ(attributes.size(), 1u);

    const std::size_t consumed = sizeof(nlmsghdr) + sizeof(genlmsghdr) + 8;
    WISP_CHECK_EQ(message.size(), consumed);
}

// Family lookup
WISP_TEST(get_family_requests_the_wireguard_family) {
    const auto message = build_get_family(3, "wireguard");
    const auto header = read_header(message);

    WISP_CHECK_EQ(header.type, static_cast<std::uint16_t>(GENL_ID_CTRL));
    WISP_CHECK_EQ(message[sizeof(nlmsghdr)], static_cast<std::uint8_t>(CTRL_CMD_GETFAMILY));

    const auto attributes = walk_genl(message);
    const auto name = find_attr(attributes, CTRL_ATTR_FAMILY_NAME);
    WISP_CHECK(name.has_value());
    if (name) WISP_CHECK_EQ(attr_string(*name), std::string("wireguard"));
}

WISP_TEST(parses_a_family_id_reply) {
    std::vector<std::uint8_t> payload = genl_header(CTRL_CMD_NEWFAMILY);
    const std::uint16_t family_id = 31;
    put_attr(payload, CTRL_ATTR_FAMILY_ID, &family_id, sizeof(family_id));

    const auto parsed = parse_family_id(payload.data(), payload.size());
    WISP_CHECK(parsed.has_value());
    if (parsed) WISP_CHECK_EQ(*parsed, family_id);
}

WISP_TEST(rejects_a_truncated_family_reply) {
    const std::uint8_t too_short[2] = {0, 0};
    WISP_CHECK(!parse_family_id(too_short, sizeof(too_short)).has_value());
}

// Device configuration
WISP_TEST(set_device_encodes_interface_fields) {
    const auto private_key = generate_private_key();
    const auto expected_private = decode_key(private_key);
    WISP_CHECK(expected_private.has_value());

    DeviceConfig config;
    config.ifname = "wisp0";
    config.private_key = private_key;
    config.listen_port = 51820;
    config.fwmark = 0x1234;
    config.replace_peers = true;

    const auto message = build_set_device(77, 9, config);
    WISP_CHECK(message.has_value());
    if (!message) return;

    const auto header = read_header(*message);
    WISP_CHECK_EQ(header.type, static_cast<std::uint16_t>(77));
    WISP_CHECK_EQ((*message)[sizeof(nlmsghdr)], static_cast<std::uint8_t>(WG_CMD_SET_DEVICE));

    const auto attributes = walk_genl(*message);

    const auto ifname = find_attr(attributes, WGDEVICE_A_IFNAME);
    WISP_CHECK(ifname.has_value());
    if (ifname) WISP_CHECK_EQ(attr_string(*ifname), std::string("wisp0"));

    const auto key = find_attr(attributes, WGDEVICE_A_PRIVATE_KEY);
    WISP_CHECK(key.has_value());
    if (key && expected_private) {
        WISP_CHECK_EQ(key->payload.size(), kKeyBytes);
        WISP_CHECK(std::equal(key->payload.begin(), key->payload.end(), expected_private->begin()));
    }

    const auto port = find_attr(attributes, WGDEVICE_A_LISTEN_PORT);
    WISP_CHECK(port.has_value());
    if (port) WISP_CHECK_EQ(attr_number<std::uint16_t>(*port), 51820);

    const auto mark = find_attr(attributes, WGDEVICE_A_FWMARK);
    WISP_CHECK(mark.has_value());
    if (mark) WISP_CHECK_EQ(attr_number<std::uint32_t>(*mark), 0x1234u);

    const auto flags = find_attr(attributes, WGDEVICE_A_FLAGS);
    WISP_CHECK(flags.has_value());
    if (flags) WISP_CHECK_EQ(attr_number<std::uint32_t>(*flags), WGDEVICE_F_REPLACE_PEERS);
}

WISP_TEST(set_device_encodes_a_peer_with_allowed_ips_and_endpoint) {
    DeviceConfig config;
    config.ifname = "wisp0";

    Peer peer;
    peer.public_key = generate_private_key();
    peer.endpoint = Endpoint{"203.0.113.9", 51820};
    peer.persistent_keepalive = 25;
    peer.allowed_ips.push_back(*Cidr::parse("0.0.0.0/0"));
    peer.allowed_ips.push_back(*Cidr::parse("fd00::/8"));
    config.peers.push_back(peer);

    const auto message = build_set_device(77, 9, config);
    WISP_CHECK(message.has_value());
    if (!message) return;

    const auto peers = find_attr(walk_genl(*message), WGDEVICE_A_PEERS);
    WISP_CHECK(peers.has_value());
    if (!peers) return;

    // Indexed nested array: one entry, numbered 0.
    const auto entries = walk(peers->payload.data(), peers->payload.size());
    WISP_CHECK_EQ(entries.size(), 1u);
    if (entries.empty()) return;
    WISP_CHECK_EQ(entries[0].type, 0u);

    const auto fields = walk(entries[0].payload.data(), entries[0].payload.size());

    const auto public_key = find_attr(fields, WGPEER_A_PUBLIC_KEY);
    WISP_CHECK(public_key.has_value());
    if (public_key) WISP_CHECK_EQ(public_key->payload.size(), kKeyBytes);

    const auto keepalive = find_attr(fields, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL);
    WISP_CHECK(keepalive.has_value());
    if (keepalive) WISP_CHECK_EQ(attr_number<std::uint16_t>(*keepalive), 25);

    const auto endpoint = find_attr(fields, WGPEER_A_ENDPOINT);
    WISP_CHECK(endpoint.has_value());
    if (endpoint) {
        WISP_CHECK_EQ(endpoint->payload.size(), sizeof(sockaddr_in));
        // Round-trip through the parser to confirm the address survived.
        sockaddr_in address{};
        std::memcpy(&address, endpoint->payload.data(), sizeof(address));
        char buffer[INET_ADDRSTRLEN] = {};
        WISP_CHECK(::inet_ntop(AF_INET, &address.sin_addr, buffer, sizeof(buffer)) != nullptr);
        WISP_CHECK_EQ(std::string(buffer), std::string("203.0.113.9"));
        WISP_CHECK_EQ(ntohs(address.sin_port), 51820);
    }

    const auto allowed = find_attr(fields, WGPEER_A_ALLOWEDIPS);
    WISP_CHECK(allowed.has_value());
    if (allowed) {
        const auto nets = walk(allowed->payload.data(), allowed->payload.size());
        WISP_CHECK_EQ(nets.size(), 2u);
        if (nets.size() == 2) {
            WISP_CHECK_EQ(nets[0].type, 0u);
            WISP_CHECK_EQ(nets[1].type, 1u);

            const auto first = walk(nets[0].payload.data(), nets[0].payload.size());
            const auto family = find_attr(first, WGALLOWEDIP_A_FAMILY);
            const auto mask = find_attr(first, WGALLOWEDIP_A_CIDR_MASK);
            const auto ip = find_attr(first, WGALLOWEDIP_A_IPADDR);
            WISP_CHECK(family.has_value() && mask.has_value() && ip.has_value());
            if (family && mask && ip) {
                WISP_CHECK_EQ(attr_number<std::uint16_t>(*family),
                              static_cast<std::uint16_t>(AF_INET));
                WISP_CHECK_EQ(attr_number<std::uint8_t>(*mask), static_cast<std::uint8_t>(0));
                WISP_CHECK_EQ(ip->payload.size(), sizeof(in_addr));
            }

            const auto second = walk(nets[1].payload.data(), nets[1].payload.size());
            const auto family6 = find_attr(second, WGALLOWEDIP_A_FAMILY);
            WISP_CHECK(family6.has_value());
            if (family6) {
                WISP_CHECK_EQ(attr_number<std::uint16_t>(*family6),
                              static_cast<std::uint16_t>(AF_INET6));
            }
        }
    }
}

WISP_TEST(set_device_marks_allowed_ips_for_replacement) {
    DeviceConfig config;
    config.ifname = "wisp0";

    Peer peer;
    peer.public_key = generate_private_key();
    peer.allowed_ips.push_back(*Cidr::parse("10.0.0.0/8"));
    config.peers.push_back(peer);

    const auto message = build_set_device(1, 1, config);
    WISP_CHECK(message.has_value());
    if (!message) return;

    const auto peers = find_attr(walk_genl(*message), WGDEVICE_A_PEERS);
    WISP_CHECK(peers.has_value());
    if (!peers) return;

    const auto entries = walk(peers->payload.data(), peers->payload.size());
    WISP_CHECK_EQ(entries.size(), 1u);
    if (entries.empty()) return;

    const auto fields = walk(entries[0].payload.data(), entries[0].payload.size());
    const auto flags = find_attr(fields, WGPEER_A_FLAGS);
    WISP_CHECK(flags.has_value());
    if (flags) {
        WISP_CHECK_EQ(attr_number<std::uint32_t>(*flags), WGPEER_F_REPLACE_ALLOWEDIPS);
    }
}

WISP_TEST(set_device_omits_absent_optional_fields) {
    DeviceConfig config;
    config.ifname = "wisp0";

    const auto message = build_set_device(1, 1, config);
    WISP_CHECK(message.has_value());
    if (!message) return;

    const auto attributes = walk_genl(*message);
    WISP_CHECK(!has_attr(attributes, WGDEVICE_A_PRIVATE_KEY));
    WISP_CHECK(!has_attr(attributes, WGDEVICE_A_LISTEN_PORT));
    WISP_CHECK(!has_attr(attributes, WGDEVICE_A_FWMARK));
    WISP_CHECK(!has_attr(attributes, WGDEVICE_A_FLAGS));
    WISP_CHECK(!has_attr(attributes, WGDEVICE_A_PEERS));
}

// Encoding must fail loudly rather than emit a message the kernel would
// partially apply.
WISP_TEST(set_device_refuses_unencodable_configs) {
    DeviceConfig no_ifname;
    WISP_CHECK(!build_set_device(1, 1, no_ifname).has_value());

    DeviceConfig bad_key;
    bad_key.ifname = "wisp0";
    bad_key.private_key = "not-a-key";
    WISP_CHECK(!build_set_device(1, 1, bad_key).has_value());

    DeviceConfig hostname_endpoint;
    hostname_endpoint.ifname = "wisp0";
    Peer peer;
    peer.public_key = generate_private_key();
    peer.endpoint = Endpoint{"vpn.example.com", 51820};  // must be resolved first
    hostname_endpoint.peers.push_back(peer);
    WISP_CHECK(!build_set_device(1, 1, hostname_endpoint).has_value());

    DeviceConfig bad_public_key;
    bad_public_key.ifname = "wisp0";
    Peer invalid;
    invalid.public_key = "nope";
    bad_public_key.peers.push_back(invalid);
    WISP_CHECK(!build_set_device(1, 1, bad_public_key).has_value());
}

WISP_TEST(rejects_a_set_device_config_with_an_invalid_preshared_key) {
    DeviceConfig config;
    config.ifname = "wisp0";
    Peer peer;
    peer.public_key = generate_private_key();
    peer.preshared_key = "invalid";
    config.peers.push_back(peer);
    WISP_CHECK(!build_set_device(1, 1, config).has_value());
}

// Decoding a kernel reply
WISP_TEST(parses_a_device_reply) {
    const auto public_key = generate_private_key();
    const auto raw_public = decode_key(public_key);
    WISP_CHECK(raw_public.has_value());
    if (!raw_public) return;

    const auto peer_key = generate_private_key();
    const auto raw_peer = decode_key(peer_key);
    WISP_CHECK(raw_peer.has_value());
    if (!raw_peer) return;

    // Build the peer's allowed IPs.
    std::vector<std::uint8_t> allowed;
    {
        std::vector<std::uint8_t> entry;
        const std::uint16_t family = AF_INET;
        put_attr(entry, WGALLOWEDIP_A_FAMILY, &family, sizeof(family));
        in_addr address{};
        ::inet_pton(AF_INET, "10.10.0.0", &address);
        put_attr(entry, WGALLOWEDIP_A_IPADDR, &address, sizeof(address));
        const std::uint8_t mask = 16;
        put_attr(entry, WGALLOWEDIP_A_CIDR_MASK, &mask, sizeof(mask));
        put_attr_nested(allowed, 0, entry);
    }

    std::vector<std::uint8_t> peer;
    {
        put_attr(peer, WGPEER_A_PUBLIC_KEY, raw_peer->data(), raw_peer->size());

        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(51820);
        ::inet_pton(AF_INET, "198.51.100.7", &endpoint.sin_addr);
        put_attr(peer, WGPEER_A_ENDPOINT, &endpoint, sizeof(endpoint));

        const std::uint16_t keepalive = 25;
        put_attr(peer, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &keepalive, sizeof(keepalive));

        timespec handshake{};
        handshake.tv_sec = 1'700'000'000;
        put_attr(peer, WGPEER_A_LAST_HANDSHAKE_TIME, &handshake, sizeof(handshake));

        const std::uint64_t rx = 4096;
        const std::uint64_t tx = 8192;
        put_attr(peer, WGPEER_A_RX_BYTES, &rx, sizeof(rx));
        put_attr(peer, WGPEER_A_TX_BYTES, &tx, sizeof(tx));
        put_attr(peer, WGPEER_A_ALLOWEDIPS, allowed.data(), allowed.size(), true);
    }

    std::vector<std::uint8_t> payload = genl_header(WG_CMD_GET_DEVICE);
    put_attr_string(payload, WGDEVICE_A_IFNAME, "wisp0");
    put_attr(payload, WGDEVICE_A_PUBLIC_KEY, raw_public->data(), raw_public->size());
    const std::uint16_t listen_port = 51820;
    put_attr(payload, WGDEVICE_A_LISTEN_PORT, &listen_port, sizeof(listen_port));
    const std::uint32_t fwmark = 0x99;
    put_attr(payload, WGDEVICE_A_FWMARK, &fwmark, sizeof(fwmark));

    std::vector<std::uint8_t> peers;
    put_attr_nested(peers, 0, peer);
    put_attr_nested(payload, WGDEVICE_A_PEERS, peers);

    const auto state = parse_device(payload.data(), payload.size());
    WISP_CHECK(state.has_value());
    if (!state) return;

    WISP_CHECK_EQ(state->ifname, std::string("wisp0"));
    WISP_CHECK_EQ(state->public_key, public_key);
    WISP_CHECK(state->listen_port.has_value() && *state->listen_port == 51820);
    WISP_CHECK(state->fwmark.has_value() && *state->fwmark == 0x99);

    WISP_CHECK_EQ(state->peers.size(), 1u);
    if (state->peers.empty()) return;

    const auto& parsed_peer = state->peers[0];
    WISP_CHECK_EQ(parsed_peer.public_key, peer_key);
    WISP_CHECK(parsed_peer.endpoint.has_value());
    if (parsed_peer.endpoint) {
        WISP_CHECK_EQ(parsed_peer.endpoint->host, std::string("198.51.100.7"));
        WISP_CHECK_EQ(parsed_peer.endpoint->port, 51820);
    }
    WISP_CHECK(parsed_peer.persistent_keepalive.has_value() &&
               *parsed_peer.persistent_keepalive == 25);
    WISP_CHECK_EQ(parsed_peer.last_handshake_seconds, 1700000000ull);
    WISP_CHECK_EQ(parsed_peer.rx_bytes, 4096ull);
    WISP_CHECK_EQ(parsed_peer.tx_bytes, 8192ull);

    WISP_CHECK_EQ(parsed_peer.allowed_ips.size(), 1u);
    if (!parsed_peer.allowed_ips.empty()) {
        WISP_CHECK_EQ(parsed_peer.allowed_ips[0].to_string(), std::string("10.10.0.0/16"));
        WISP_CHECK(!parsed_peer.allowed_ips[0].is_v6);
    }
}

WISP_TEST(device_reply_parsing_rejects_junk) {
    const std::uint8_t too_short[3] = {0, 0, 0};
    WISP_CHECK(!parse_device(too_short, sizeof(too_short)).has_value());

    // A GET_DEVICE reply with no device attributes is not a device.
    std::vector<std::uint8_t> empty_reply = genl_header(WG_CMD_GET_DEVICE);
    WISP_CHECK(!parse_device(empty_reply.data(), empty_reply.size()).has_value());

    // A reply for a different command must not be accepted.
    std::vector<std::uint8_t> wrong_command = genl_header(WG_CMD_SET_DEVICE);
    put_attr_string(wrong_command, WGDEVICE_A_IFNAME, "wisp0");
    WISP_CHECK(!parse_device(wrong_command.data(), wrong_command.size()).has_value());
}

WISP_TEST(parses_an_error_reply) {
    const std::int32_t busy = -EBUSY;
    const auto parsed = parse_error(reinterpret_cast<const std::uint8_t*>(&busy), sizeof(busy));
    WISP_CHECK(parsed.has_value());
    if (parsed) WISP_CHECK_EQ(*parsed, busy);

    const std::int32_t ack = 0;
    const auto ok = parse_error(reinterpret_cast<const std::uint8_t*>(&ack), sizeof(ack));
    WISP_CHECK(ok.has_value() && *ok == 0);
}

// Link and address handling
WISP_TEST(create_link_declares_the_wireguard_kind) {
    const auto message = build_create_link(5, "wisp0", std::nullopt);
    const auto header = read_header(message);

    WISP_CHECK_EQ(header.type, static_cast<std::uint16_t>(RTM_NEWLINK));
    WISP_CHECK((header.flags & NLM_F_CREATE) != 0);
    WISP_CHECK((header.flags & NLM_F_EXCL) != 0);

    // The ifinfomsg is the first thing after the header.
    ifinfomsg info{};
    std::memcpy(&info, message.data() + sizeof(nlmsghdr), sizeof(info));
    WISP_CHECK_EQ(static_cast<int>(info.ifi_family), static_cast<int>(AF_UNSPEC));

    const auto attributes =
        walk(message.data() + sizeof(nlmsghdr) + sizeof(ifinfomsg),
             message.size() - sizeof(nlmsghdr) - sizeof(ifinfomsg));

    const auto ifname = find_attr(attributes, IFLA_IFNAME);
    WISP_CHECK(ifname.has_value());
    if (ifname) WISP_CHECK_EQ(attr_string(*ifname), std::string("wisp0"));

    const auto linkinfo = find_attr(attributes, IFLA_LINKINFO);
    WISP_CHECK(linkinfo.has_value());
    if (linkinfo) {
        const auto inner = walk(linkinfo->payload.data(), linkinfo->payload.size());
        const auto kind = find_attr(inner, IFLA_INFO_KIND);
        WISP_CHECK(kind.has_value());
        if (kind) WISP_CHECK_EQ(attr_string(*kind), std::string("wireguard"));
    }
}

WISP_TEST(create_link_can_carry_an_mtu) {
    const auto message = build_create_link(5, "wisp0", 1420u);
    const auto attributes =
        walk(message.data() + sizeof(nlmsghdr) + sizeof(ifinfomsg),
             message.size() - sizeof(nlmsghdr) - sizeof(ifinfomsg));

    const auto mtu = find_attr(attributes, IFLA_MTU);
    WISP_CHECK(mtu.has_value());
    if (mtu) WISP_CHECK_EQ(attr_number<std::uint32_t>(*mtu), 1420u);
}

WISP_TEST(set_link_toggles_the_up_flag) {
    const auto up = build_set_link(1, 7, true, std::nullopt);
    ifinfomsg info{};
    std::memcpy(&info, up.data() + sizeof(nlmsghdr), sizeof(info));
    WISP_CHECK((info.ifi_flags & IFF_UP) != 0);
    WISP_CHECK((info.ifi_change & IFF_UP) != 0);
    WISP_CHECK_EQ(info.ifi_index, 7);

    const auto down = build_set_link(1, 7, false, std::nullopt);
    ifinfomsg down_info{};
    std::memcpy(&down_info, down.data() + sizeof(nlmsghdr), sizeof(down_info));
    WISP_CHECK((down_info.ifi_flags & IFF_UP) == 0);
    WISP_CHECK((down_info.ifi_change & IFF_UP) != 0);
}

WISP_TEST(parses_a_link_index) {
    std::vector<std::uint8_t> payload(sizeof(ifinfomsg), 0);
    ifinfomsg info{};
    info.ifi_index = 12;
    std::memcpy(payload.data(), &info, sizeof(info));

    const auto index = parse_link_index(payload.data(), payload.size());
    WISP_CHECK(index.has_value());
    if (index) WISP_CHECK_EQ(*index, 12u);

    WISP_CHECK(!parse_link_index(payload.data(), 2).has_value());
}

WISP_TEST(address_message_carries_family_and_prefix) {
    const auto v4 = build_address(1, 3, *Cidr::parse("10.7.0.2/24"), true);
    ifaddrmsg message{};
    std::memcpy(&message, v4.data() + sizeof(nlmsghdr), sizeof(message));
    WISP_CHECK_EQ(static_cast<int>(message.ifa_family), static_cast<int>(AF_INET));
    WISP_CHECK_EQ(static_cast<int>(message.ifa_prefixlen), 24);
    WISP_CHECK_EQ(static_cast<int>(message.ifa_index), 3);

    const auto attributes = walk(v4.data() + sizeof(nlmsghdr) + sizeof(ifaddrmsg),
                                v4.size() - sizeof(nlmsghdr) - sizeof(ifaddrmsg));
    // IPv4 gets both IFA_LOCAL and IFA_ADDRESS.
    WISP_CHECK(has_attr(attributes, IFA_LOCAL));
    WISP_CHECK(has_attr(attributes, IFA_ADDRESS));

    const auto v6 = build_address(1, 3, *Cidr::parse("fd00::2/64"), true);
    ifaddrmsg message6{};
    std::memcpy(&message6, v6.data() + sizeof(nlmsghdr), sizeof(message6));
    WISP_CHECK_EQ(static_cast<int>(message6.ifa_family), static_cast<int>(AF_INET6));
    WISP_CHECK_EQ(static_cast<int>(message6.ifa_prefixlen), 64);

    const auto attributes6 = walk(v6.data() + sizeof(nlmsghdr) + sizeof(ifaddrmsg),
                                 v6.size() - sizeof(nlmsghdr) - sizeof(ifaddrmsg));
    WISP_CHECK(has_attr(attributes6, IFA_ADDRESS));
    WISP_CHECK(!has_attr(attributes6, IFA_LOCAL));
}

WISP_TEST(address_delete_does_not_request_creation) {
    const auto message = build_address(1, 3, *Cidr::parse("10.7.0.2/24"), false);
    const auto header = read_header(message);
    WISP_CHECK_EQ(header.type, static_cast<std::uint16_t>(RTM_DELADDR));
    WISP_CHECK((header.flags & NLM_F_CREATE) == 0);
}

WISP_TEST(default_route_omits_the_destination) {
    const auto message = build_route(1, 9, *Cidr::parse("0.0.0.0/0"), 254, true);
    rtmsg route{};
    std::memcpy(&route, message.data() + sizeof(nlmsghdr), sizeof(route));
    WISP_CHECK_EQ(static_cast<int>(route.rtm_dst_len), 0);
    WISP_CHECK_EQ(static_cast<int>(route.rtm_table), 254);

    const auto attributes = walk(message.data() + sizeof(nlmsghdr) + sizeof(rtmsg),
                                message.size() - sizeof(nlmsghdr) - sizeof(rtmsg));
    WISP_CHECK(!has_attr(attributes, RTA_DST));

    const auto oif = find_attr(attributes, RTA_OIF);
    WISP_CHECK(oif.has_value());
    if (oif) WISP_CHECK_EQ(attr_number<std::uint32_t>(*oif), 9u);
}

WISP_TEST(route_with_a_prefix_carries_the_destination) {
    const auto message = build_route(1, 9, *Cidr::parse("10.10.0.0/16"), 254, true);
    rtmsg route{};
    std::memcpy(&route, message.data() + sizeof(nlmsghdr), sizeof(route));
    WISP_CHECK_EQ(static_cast<int>(route.rtm_dst_len), 16);

    const auto attributes = walk(message.data() + sizeof(nlmsghdr) + sizeof(rtmsg),
                                message.size() - sizeof(nlmsghdr) - sizeof(rtmsg));
    const auto dst = find_attr(attributes, RTA_DST);
    WISP_CHECK(dst.has_value());
    if (dst) {
        in_addr address{};
        std::memcpy(&address, dst->payload.data(), sizeof(address));
        char buffer[INET_ADDRSTRLEN] = {};
        WISP_CHECK(::inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr);
        WISP_CHECK_EQ(std::string(buffer), std::string("10.10.0.0"));
    }
}

// A table id above 255 cannot fit in rtm_table, so it has to travel in
// RTA_TABLE instead of being silently truncated.
WISP_TEST(wide_table_ids_use_the_rta_table_attribute) {
    const auto message = build_route(1, 9, *Cidr::parse("10.0.0.0/8"), 51820, true);
    rtmsg route{};
    std::memcpy(&route, message.data() + sizeof(nlmsghdr), sizeof(route));
    WISP_CHECK_EQ(static_cast<int>(route.rtm_table), static_cast<int>(RT_TABLE_UNSPEC));

    const auto attributes = walk(message.data() + sizeof(nlmsghdr) + sizeof(rtmsg),
                                message.size() - sizeof(nlmsghdr) - sizeof(rtmsg));
    const auto table = find_attr(attributes, RTA_TABLE);
    WISP_CHECK(table.has_value());
    if (table) WISP_CHECK_EQ(attr_number<std::uint32_t>(*table), 51820u);
}

WISP_TEST(resolve_endpoint_passes_through_literals) {
    const auto v4 = resolve_endpoint(Endpoint{"203.0.113.1", 1234});
    WISP_CHECK(v4.has_value());
    if (v4) WISP_CHECK_EQ(v4->host, std::string("203.0.113.1"));

    const auto v6 = resolve_endpoint(Endpoint{"2001:db8::1", 1234});
    WISP_CHECK(v6.has_value());
    if (v6) WISP_CHECK_EQ(v6->host, std::string("2001:db8::1"));
}

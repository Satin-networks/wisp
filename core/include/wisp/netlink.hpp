#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "wisp/types.hpp"

namespace wisp::nl {

// Kernel-reported state.
struct PeerState {
    std::string public_key;
    std::optional<Endpoint> endpoint;
    std::vector<Cidr> allowed_ips;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    std::uint64_t last_handshake_seconds = 0;  // 0 means never
    std::optional<std::uint16_t> persistent_keepalive;
    bool has_preshared_key = false;
};

struct DeviceState {
    std::string ifname;
    std::string public_key;
    std::optional<std::uint16_t> listen_port;
    std::optional<std::uint32_t> fwmark;
    std::vector<PeerState> peers;
};

// Configuration pushed into the kernel. Absent fields leave the device as-is;
// this mirrors how `wg set` behaves.
struct DeviceConfig {
    std::string ifname;
    std::optional<std::string> private_key;  // base64
    std::optional<std::uint16_t> listen_port;
    std::optional<std::uint32_t> fwmark;
    std::vector<Peer> peers;
    bool replace_peers = false;
};

// Message encoding.
//
// Every builder returns the exact bytes for sendto(). Encoding stays pure so
// the wire format can be unit-tested without a netlink socket or CAP_NET_ADMIN.
// This is the layer where a mistake quietly misconfigures a tunnel instead of
// failing loudly, so it gets tested byte for byte.
//
// Peer endpoints in DeviceConfig must already be IP literals. The kernel API
// takes addresses, not hostnames; Client::set_device resolves names first.

std::vector<std::uint8_t> build_get_family(std::uint32_t seq, const std::string& family_name);
std::vector<std::uint8_t> build_get_device(std::uint16_t family_id, std::uint32_t seq,
                                           const std::string& ifname);
// Returns std::nullopt when the configuration cannot be encoded, which happens
// for an invalid key or an endpoint host that is not an IP literal.
std::optional<std::vector<std::uint8_t>> build_set_device(std::uint16_t family_id,
                                                          std::uint32_t seq,
                                                          const DeviceConfig& config);

std::vector<std::uint8_t> build_create_link(std::uint32_t seq, const std::string& ifname,
                                            std::optional<std::uint32_t> mtu);
std::vector<std::uint8_t> build_delete_link(std::uint32_t seq, std::uint32_t ifindex);
std::vector<std::uint8_t> build_set_link(std::uint32_t seq, std::uint32_t ifindex, bool up,
                                         std::optional<std::uint32_t> mtu);
std::vector<std::uint8_t> build_address(std::uint32_t seq, std::uint32_t ifindex, const Cidr& cidr,
                                        bool add);
std::vector<std::uint8_t> build_route(std::uint32_t seq, std::uint32_t ifindex, const Cidr& dst,
                                      std::uint32_t table, bool add);

// A routing policy rule (fib_rule).
//
// `invert` is what makes "not fwmark N" work. The kernel has no unequal mark
// comparison: iproute2 expresses negation by setting FIB_RULE_INVERT in the
// rule header, and the kernel then treats the rule as matching everything
// except that selector. Get this wrong and there is no error, just a routing
// loop or a traffic leak, so the flag is called out here instead of left
// implied.
struct RuleSpec {
    int family = 2;                       // AF_INET
    std::uint32_t table = 0;
    std::optional<std::uint32_t> fwmark;
    std::optional<std::uint32_t> suppress_prefixlength;
    std::optional<std::uint32_t> priority;
    std::uint8_t action = 1;              // FR_ACT_TO_TBL
    bool invert = false;
};

std::vector<std::uint8_t> build_rule(std::uint32_t seq, const RuleSpec& spec, bool add);

// Decoding.
std::optional<std::uint16_t> parse_family_id(const std::uint8_t* data, std::size_t len);
std::optional<DeviceState> parse_device(const std::uint8_t* data, std::size_t len);
std::optional<std::uint32_t> parse_link_index(const std::uint8_t* data, std::size_t len);

// Negative errno carried in an NLMSG_ERROR reply, or 0 for an ACK.
std::optional<std::int32_t> parse_error(const std::uint8_t* data, std::size_t len);

// Socket layer. Thin by design: the builders above own all protocol knowledge,
// so this class only sends, receives, and checks ACKs.
class Client {
  public:
    Client();
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    bool ok() const { return fd_ >= 0; }
    const std::string& error() const { return error_; }
    void clear_error() { error_.clear(); }

    std::uint16_t wireguard_family();

    bool set_device(const DeviceConfig& config);
    std::optional<DeviceState> get_device(const std::string& ifname);

    std::optional<std::uint32_t> create_link(const std::string& ifname,
                                             std::optional<std::uint32_t> mtu);
    bool delete_link(std::uint32_t ifindex);
    bool set_link(std::uint32_t ifindex, bool up, std::optional<std::uint32_t> mtu);
    bool address(std::uint32_t ifindex, const Cidr& cidr, bool add);
    bool route(std::uint32_t ifindex, const Cidr& dst, std::uint32_t table, bool add);
    bool rule(const RuleSpec& spec, bool add);

    std::optional<std::uint32_t> interface_index(const std::string& ifname);

  private:
    // Returns true on success. An ACK-only exchange is a success with an empty
    // `response`, which is why this cannot be modelled as an optional.
    bool transact(const std::vector<std::uint8_t>& request, std::vector<std::uint8_t>* response);

    int fd_ = -1;
    std::uint32_t seq_ = 0;
    std::uint16_t wg_family_ = 0;
    std::string error_;
};

// Resolve an endpoint hostname to an IP literal. Returns the endpoint
// unchanged when it already holds an IP.
std::optional<Endpoint> resolve_endpoint(const Endpoint& endpoint);

}  // namespace wisp::nl

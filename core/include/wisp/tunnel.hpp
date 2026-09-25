#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "wisp/dns.hpp"
#include "wisp/netlink.hpp"
#include "wisp/types.hpp"

namespace wisp {

inline constexpr std::uint32_t kMainRoutingTable = 254;

// Same values wg-quick uses for Table = auto. Matching them keeps what Wisp
// installs indistinguishable from wg-quick output, so the two stay
// interchangeable and the same debugging advice applies either way.
inline constexpr std::uint32_t kAutoPolicyTable = 51820;

// Both rules sit just below the main rule (32766) so they are consulted first.
inline constexpr std::uint32_t kSuppressRulePriority = 32764;
inline constexpr std::uint32_t kFwmarkRulePriority = 32765;

// How a profile's traffic should be routed.
//
// A split tunnel needs no policy routing: only specific routes are added, so
// the ordinary path to the peer is never disturbed. A full tunnel does, because
// a default route pointing into the tunnel would also capture the tunnel's own
// encrypted packets and loop them straight back at themselves.
struct RoutingPlan {
    bool manage = true;  // false when Table = off: the operator owns routing
    bool full_tunnel = false;
    std::uint32_t table = kMainRoutingTable;
    std::uint32_t mark = 0;  // fwmark; 0 means none
    bool has_v4 = false;
    bool has_v6 = false;

    static RoutingPlan derive(const Interface& config);

    // Rebuild the plan from what the kernel actually reports, so teardown can
    // still remove policy rules after the profile file has been deleted.
    static RoutingPlan from_device_state(const nl::DeviceState& state);

    bool needs_policy_routing() const { return manage && full_tunnel; }
    bool sets_fwmark() const { return needs_policy_routing() && mark != 0; }

    bool operator==(const RoutingPlan&) const = default;
};

// The operations a bring-up needs. Expressed as an interface so the sequencing
// can be tested without root, a real interface, or a loaded wireguard module.
class TunnelPlatform {
  public:
    virtual ~TunnelPlatform() = default;

    virtual std::optional<std::uint32_t> create_link(const std::string& ifname,
                                                     std::optional<std::uint32_t> mtu) = 0;
    virtual std::optional<std::uint32_t> find_link(const std::string& ifname) = 0;
    virtual bool delete_link(std::uint32_t ifindex) = 0;
    virtual bool set_link(std::uint32_t ifindex, bool up, std::optional<std::uint32_t> mtu) = 0;
    virtual bool address(std::uint32_t ifindex, const Cidr& cidr, bool add) = 0;
    virtual bool route(std::uint32_t ifindex, const Cidr& dst, std::uint32_t table, bool add) = 0;
    virtual bool rule(const nl::RuleSpec& spec, bool add) = 0;
    virtual bool set_device(const nl::DeviceConfig& config) = 0;
};

struct TunnelResult {
    bool ok = false;
    std::string message;

    bool operator==(const TunnelResult&) const = default;
};

nl::DeviceConfig to_device_config(const Interface& config, const std::string& ifname,
                                  const RoutingPlan& plan);

// Bring a tunnel up: create the link, configure the crypto, assign addresses,
// add routes, raise the link, install policy rules, then apply DNS.
//
// `dns` may be null, which leaves the resolver completely untouched.
TunnelResult bring_up(TunnelPlatform& platform, DnsManager* dns, const Interface& config,
                      const std::string& ifname);

// Takes the routing plan rather than the whole profile: removing the link also
// removes its routes, so the only thing that must be undone explicitly is the
// policy rules - and the plan can be rebuilt from live device state when the
// profile file is no longer there to read.
TunnelResult tear_down(TunnelPlatform& platform, DnsManager* dns, const RoutingPlan& plan,
                       const std::string& ifname);

// A TunnelPlatform backed by real netlink.
std::unique_ptr<TunnelPlatform> make_netlink_platform(nl::Client& client);

}  // namespace wisp

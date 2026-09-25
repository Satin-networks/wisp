#include "wisp/tunnel.hpp"

#include <arpa/inet.h>

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace wisp {
namespace {

std::vector<int> families_for(const RoutingPlan& plan) {
    std::vector<int> families;
    if (plan.has_v4) families.push_back(AF_INET);
    if (plan.has_v6) families.push_back(AF_INET6);
    return families;
}

// The two rules that make a full tunnel work without routing loops:
//
//   1. "table main suppress_prefixlength 0"
//      Look in the main table but ignore its default route. This is what keeps
//      the specific route to the peer intact, so the encrypted packets have
//      somewhere to go.
//
//   2. "not fwmark <mark> table <table>"
//      Everything the WireGuard device has *not* marked goes into the tunnel
//      table. The kernel has no unequal-comparison for marks, so negation is
//      expressed through FIB_RULE_INVERT - see build_rule.
//
// Together: ordinary traffic is pulled into the tunnel, while the tunnel's own
// encrypted traffic falls through and leaves via the physical interface.
bool apply_policy_rules(TunnelPlatform& platform, const RoutingPlan& plan, bool add) {
    for (const int family : families_for(plan)) {
        nl::RuleSpec suppress;
        suppress.family = family;
        suppress.table = kMainRoutingTable;
        suppress.suppress_prefixlength = 0;
        suppress.priority = kSuppressRulePriority;

        nl::RuleSpec fwmark;
        fwmark.family = family;
        fwmark.table = plan.table;
        fwmark.fwmark = plan.mark;
        fwmark.invert = true;  // "not fwmark"
        fwmark.priority = kFwmarkRulePriority;

        if (add) {
            if (!platform.rule(suppress, true)) return false;
            if (!platform.rule(fwmark, true)) return false;
        } else {
            // Reverse order on the way out.
            if (!platform.rule(fwmark, false)) return false;
            if (!platform.rule(suppress, false)) return false;
        }
    }
    return true;
}

}  // namespace

RoutingPlan RoutingPlan::derive(const Interface& config) {
    RoutingPlan plan;

    if (config.table && *config.table == "off") {
        plan.manage = false;
        return plan;
    }

    for (const auto& peer : config.peers) {
        for (const auto& cidr : peer.allowed_ips) {
            if (cidr.is_v6) {
                plan.has_v6 = true;
            } else {
                plan.has_v4 = true;
            }
            if (cidr.prefix == 0) plan.full_tunnel = true;
        }
    }

    const bool explicit_table = config.table && *config.table != "auto";
    const std::uint32_t configured = explicit_table
                                        ? static_cast<std::uint32_t>(
                                              std::strtoul(config.table->c_str(), nullptr, 10))
                                        : kAutoPolicyTable;

    if (plan.full_tunnel) {
        plan.table = configured;
        // The mark and the table conventionally share a value, which is why
        // `wg show <if> fwmark` doubles as a way to discover the table.
        plan.mark = (config.fwmark && *config.fwmark != 0) ? *config.fwmark : configured;
    } else {
        // A split tunnel keeps to the main table unless one was named, because
        // specific routes cannot capture the path to the peer.
        plan.table = explicit_table ? configured : kMainRoutingTable;
        plan.mark = config.fwmark.value_or(0);
    }

    return plan;
}

RoutingPlan RoutingPlan::from_device_state(const nl::DeviceState& state) {
    RoutingPlan plan;

    for (const auto& peer : state.peers) {
        for (const auto& cidr : peer.allowed_ips) {
            if (cidr.is_v6) {
                plan.has_v6 = true;
            } else {
                plan.has_v4 = true;
            }
            if (cidr.prefix == 0) plan.full_tunnel = true;
        }
    }

    const std::uint32_t mark = state.fwmark.value_or(0);
    if (plan.full_tunnel && mark != 0) {
        plan.table = mark;
        plan.mark = mark;
    }
    return plan;
}

nl::DeviceConfig to_device_config(const Interface& config, const std::string& ifname,
                                  const RoutingPlan& plan) {
    nl::DeviceConfig device;
    device.ifname = ifname;
    device.private_key = config.private_key;
    device.listen_port = config.listen_port;
    device.fwmark = config.fwmark;

    if (plan.sets_fwmark()) {
        device.fwmark = plan.mark;
    }

    device.peers = config.peers;

    // Applying a profile is declarative: replace the peer set so that
    // re-applying converges instead of leaving peers from an earlier revision
    // in place.
    device.replace_peers = true;
    return device;
}

TunnelResult bring_up(TunnelPlatform& platform, DnsManager* dns, const Interface& config,
                      const std::string& ifname) {
    const auto plan = RoutingPlan::derive(config);

    const auto ifindex = platform.create_link(ifname, config.mtu);
    if (!ifindex) {
        return {false, "could not create interface " + ifname + " (does it already exist?)"};
    }

    const auto abandon = [&](const std::string& message) {
        // Leaving a half-configured interface behind produces a state that is
        // confusing to debug and may hold addresses we do not own.
        platform.delete_link(*ifindex);
        return TunnelResult{false, message};
    };

    // The link is still down here. Configuring the crypto before raising it
    // means no packet can leave through a tunnel that is not yet encrypting.
    if (!platform.set_device(to_device_config(config, ifname, plan))) {
        return abandon("could not configure the tunnel device");
    }

    for (const auto& cidr : config.addresses) {
        if (!platform.address(*ifindex, cidr, true)) {
            return abandon("could not assign address " + cidr.to_string());
        }
    }

    if (plan.manage) {
        for (const auto& peer : config.peers) {
            for (const auto& cidr : peer.allowed_ips) {
                if (!platform.route(*ifindex, cidr, plan.table, true)) {
                    return abandon("could not add route for " + cidr.to_string());
                }
            }
        }
    }

    // Raise the link before any policy rule points traffic at it: a rule
    // installed first would send packets into a table whose interface is down.
    if (!platform.set_link(*ifindex, true, config.mtu)) {
        return abandon("could not bring the interface up");
    }

    if (plan.needs_policy_routing() && !apply_policy_rules(platform, plan, true)) {
        // Pull out whatever went in. A failed bring-up must not leave rules
        // pointing at a table whose interface is about to be deleted. Cleanup
        // failures are ignored; there is nothing better to do with them here.
        apply_policy_rules(platform, plan, false);
        return abandon("could not install the policy routing rules");
    }

    if (dns != nullptr && !config.dns.empty()) {
        std::string dns_error;
        if (!dns->apply(ifname, config.dns, config.search_domains, dns_error)) {
            if (plan.full_tunnel) {
                apply_policy_rules(platform, plan, false);
                return abandon("DNS failed, tunnel torn down (fail-closed): " + dns_error);
            }
            return {true, ifname + " is up, but DNS was left unchanged: " + dns_error};
        }
    }

    return {true, ifname};
}

TunnelResult tear_down(TunnelPlatform& platform, DnsManager* dns, const RoutingPlan& plan,
                       const std::string& ifname) {
    if (dns != nullptr) {
        // Reverting a resolver we never changed is harmless, so this is
        // unconditional: better to restore a stale entry than to leave the
        // system pointed at a resolver inside a tunnel that is going away.
        std::string dns_error;
        dns->revert(ifname, dns_error);
    }

    // Drop the policy rules before the link, so traffic stops depending on the
    // tunnel's table instead of being aimed at an interface that is vanishing.
    if (plan.needs_policy_routing()) {
        apply_policy_rules(platform, plan, false);
    }

    const auto ifindex = platform.find_link(ifname);
    if (!ifindex) {
        // Already gone is a success: stopping a tunnel that is not running is
        // not an error the caller needs to handle.
        return {true, "interface " + ifname + " is not present"};
    }

    // Removing the link also drops its addresses and routes, so there is
    // nothing else to unwind.
    if (!platform.delete_link(*ifindex)) {
        return {false, "could not remove interface " + ifname};
    }
    return {true, ifname};
}

namespace {

class NetlinkPlatform final : public TunnelPlatform {
  public:
    explicit NetlinkPlatform(nl::Client& client) : client_(client) {}

    std::optional<std::uint32_t> create_link(const std::string& ifname,
                                             std::optional<std::uint32_t> mtu) override {
        return client_.create_link(ifname, mtu);
    }

    std::optional<std::uint32_t> find_link(const std::string& ifname) override {
        return client_.interface_index(ifname);
    }

    bool delete_link(std::uint32_t ifindex) override { return client_.delete_link(ifindex); }

    bool set_link(std::uint32_t ifindex, bool up, std::optional<std::uint32_t> mtu) override {
        return client_.set_link(ifindex, up, mtu);
    }

    bool address(std::uint32_t ifindex, const Cidr& cidr, bool add) override {
        return client_.address(ifindex, cidr, add);
    }

    bool route(std::uint32_t ifindex, const Cidr& dst, std::uint32_t table, bool add) override {
        return client_.route(ifindex, dst, table, add);
    }

    bool rule(const nl::RuleSpec& spec, bool add) override { return client_.rule(spec, add); }

    bool set_device(const nl::DeviceConfig& config) override {
        return client_.set_device(config);
    }

  private:
    nl::Client& client_;
};

}  // namespace

std::unique_ptr<TunnelPlatform> make_netlink_platform(nl::Client& client) {
    return std::make_unique<NetlinkPlatform>(client);
}

}  // namespace wisp

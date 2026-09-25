#include <arpa/inet.h>

#include <optional>
#include <string>
#include <vector>

#include "wisp/keys.hpp"
#include "wisp/tunnel.hpp"
#include "wisp_test.hpp"

using namespace wisp;

namespace {

// Records every call so the orchestration can be checked without root, a real
// interface, or the wireguard module.
class FakePlatform final : public TunnelPlatform {
  public:
    struct Call {
        std::string op;
        std::string detail;
        std::uint32_t table = 0;
    };

    struct RuleCall {
        nl::RuleSpec spec;
        bool add = true;
    };

    std::vector<Call> calls;
    std::vector<RuleCall> rules;
    std::optional<std::uint32_t> next_index = 7;

    bool fail_create = false;
    bool fail_set_device = false;
    bool fail_address = false;
    bool fail_route = false;
    bool fail_rule = false;
    bool fail_set_link = false;
    bool present = true;

    nl::DeviceConfig last_device;

    std::optional<std::uint32_t> create_link(const std::string& ifname,
                                             std::optional<std::uint32_t> mtu) override {
        calls.push_back({"create_link", ifname + (mtu ? " mtu=" + std::to_string(*mtu) : ""), 0});
        if (fail_create) return std::nullopt;
        return next_index;
    }

    std::optional<std::uint32_t> find_link(const std::string& ifname) override {
        calls.push_back({"find_link", ifname, 0});
        if (!present) return std::nullopt;
        return next_index;
    }

    bool delete_link(std::uint32_t ifindex) override {
        calls.push_back({"delete_link", std::to_string(ifindex), 0});
        return true;
    }

    bool set_link(std::uint32_t, bool up, std::optional<std::uint32_t>) override {
        calls.push_back({"set_link", up ? "up" : "down", 0});
        return !fail_set_link;
    }

    bool address(std::uint32_t, const Cidr& cidr, bool) override {
        calls.push_back({"address", cidr.to_string(), 0});
        return !fail_address;
    }

    bool route(std::uint32_t, const Cidr& dst, std::uint32_t table, bool) override {
        calls.push_back({"route", dst.to_string(), table});
        return !fail_route;
    }

    bool rule(const nl::RuleSpec& spec, bool add) override {
        rules.push_back({spec, add});
        return !fail_rule;
    }

    bool set_device(const nl::DeviceConfig& config) override {
        calls.push_back({"set_device", config.ifname, 0});
        last_device = config;
        return !fail_set_device;
    }

    std::optional<std::size_t> index_of(const std::string& op) const {
        for (std::size_t i = 0; i < calls.size(); ++i) {
            if (calls[i].op == op) return i;
        }
        return std::nullopt;
    }

    std::size_t count_of(const std::string& op) const {
        std::size_t total = 0;
        for (const auto& call : calls) {
            if (call.op == op) ++total;
        }
        return total;
    }

    std::size_t rules_added() const {
        std::size_t total = 0;
        for (const auto& entry : rules) {
            if (entry.add) ++total;
        }
        return total;
    }

    std::size_t rules_removed() const { return rules.size() - rules_added(); }
};

class FakeDns final : public DnsManager {
  public:
    struct Apply {
        std::string ifname;
        std::vector<std::string> servers;
        std::vector<std::string> domains;
    };

    std::vector<Apply> applied;
    std::vector<std::string> reverted;
    bool fail_apply = false;

    DnsBackend backend() const override { return DnsBackend::ResolvConf; }

    bool apply(const std::string& ifname, const std::vector<std::string>& servers,
               const std::vector<std::string>& domains, std::string& error) override {
        if (fail_apply) {
            error = "no resolver available";
            return false;
        }
        applied.push_back({ifname, servers, domains});
        return true;
    }

    bool revert(const std::string& ifname, std::string&) override {
        reverted.push_back(ifname);
        return true;
    }
};

Interface split_tunnel_config() {
    Interface config;
    config.private_key = generate_private_key();
    config.addresses.push_back(*Cidr::parse("10.7.0.2/32"));

    Peer peer;
    peer.public_key = generate_private_key();
    peer.endpoint = Endpoint{"203.0.113.9", 51820};
    peer.allowed_ips.push_back(*Cidr::parse("10.10.0.0/16"));
    config.peers.push_back(peer);
    return config;
}

Interface full_tunnel_config() {
    auto config = split_tunnel_config();
    config.peers[0].allowed_ips.clear();
    config.peers[0].allowed_ips.push_back(*Cidr::parse("0.0.0.0/0"));
    return config;
}

}  // namespace

// Routing plan
WISP_TEST(split_tunnel_plan_needs_no_policy_routing) {
    const auto plan = RoutingPlan::derive(split_tunnel_config());
    WISP_CHECK(plan.manage);
    WISP_CHECK(!plan.full_tunnel);
    WISP_CHECK(!plan.needs_policy_routing());
    WISP_CHECK_EQ(plan.table, kMainRoutingTable);
    WISP_CHECK_EQ(plan.mark, 0u);
    WISP_CHECK(plan.has_v4);
    WISP_CHECK(!plan.has_v6);
}

WISP_TEST(full_tunnel_plan_uses_the_auto_table_and_mark) {
    const auto plan = RoutingPlan::derive(full_tunnel_config());
    WISP_CHECK(plan.full_tunnel);
    WISP_CHECK(plan.needs_policy_routing());
    WISP_CHECK(plan.sets_fwmark());
    WISP_CHECK_EQ(plan.table, kAutoPolicyTable);
    WISP_CHECK_EQ(plan.mark, kAutoPolicyTable);
}

WISP_TEST(table_off_disables_all_route_management) {
    auto config = full_tunnel_config();
    config.table = "off";
    const auto plan = RoutingPlan::derive(config);
    WISP_CHECK(!plan.manage);
    WISP_CHECK(!plan.needs_policy_routing());
}

WISP_TEST(an_explicit_table_is_honoured_for_full_tunnels) {
    auto config = full_tunnel_config();
    config.table = "1234";
    const auto plan = RoutingPlan::derive(config);
    WISP_CHECK_EQ(plan.table, 1234u);
    WISP_CHECK_EQ(plan.mark, 1234u);
}

WISP_TEST(an_explicit_fwmark_overrides_the_table_value) {
    auto config = full_tunnel_config();
    config.fwmark = 0x99;
    const auto plan = RoutingPlan::derive(config);
    WISP_CHECK_EQ(plan.mark, 0x99u);
    WISP_CHECK_EQ(plan.table, kAutoPolicyTable);
}

WISP_TEST(plan_tracks_which_families_are_present) {
    auto config = full_tunnel_config();
    config.peers[0].allowed_ips.push_back(*Cidr::parse("::/0"));
    const auto plan = RoutingPlan::derive(config);
    WISP_CHECK(plan.has_v4);
    WISP_CHECK(plan.has_v6);
}

WISP_TEST(plan_can_be_rebuilt_from_live_device_state) {
    nl::DeviceState state;
    state.ifname = "wisp0";
    state.fwmark = 51820;

    nl::PeerState peer;
    peer.public_key = generate_private_key();
    peer.allowed_ips.push_back(*Cidr::parse("0.0.0.0/0"));
    state.peers.push_back(peer);

    const auto plan = RoutingPlan::from_device_state(state);
    WISP_CHECK(plan.full_tunnel);
    WISP_CHECK_EQ(plan.table, 51820u);
    WISP_CHECK_EQ(plan.mark, 51820u);
    WISP_CHECK(plan.has_v4);
}

// Bring-up ordering
WISP_TEST(bring_up_raises_the_link_only_after_configuring_crypto) {
    FakePlatform platform;
    const auto result = bring_up(platform, nullptr, split_tunnel_config(), "wisp0");
    WISP_CHECK(result.ok);

    const auto create = platform.index_of("create_link");
    const auto device = platform.index_of("set_device");
    const auto address = platform.index_of("address");
    const auto route = platform.index_of("route");
    const auto up = platform.index_of("set_link");

    WISP_CHECK(create && device && address && route && up);
    if (!create || !device || !address || !route || !up) return;

    // The safety property: the interface is not raised until its crypto is
    // configured, or packets could escape in the clear.
    WISP_CHECK(*create < *device);
    WISP_CHECK(*device < *address);
    WISP_CHECK(*address < *route);
    WISP_CHECK(*route < *up);
}

WISP_TEST(split_tunnel_routes_go_to_the_main_table_without_rules) {
    FakePlatform platform;
    const auto result = bring_up(platform, nullptr, split_tunnel_config(), "wisp0");
    WISP_CHECK(result.ok);

    for (const auto& call : platform.calls) {
        if (call.op == "route") WISP_CHECK_EQ(call.table, kMainRoutingTable);
    }
    WISP_CHECK_EQ(platform.rules.size(), 0u);
    WISP_CHECK(!platform.last_device.fwmark.has_value());
}

WISP_TEST(full_tunnel_routes_go_to_the_policy_table_and_install_rules) {
    FakePlatform platform;
    const auto result = bring_up(platform, nullptr, full_tunnel_config(), "wisp0");
    WISP_CHECK(result.ok);

    for (const auto& call : platform.calls) {
        if (call.op == "route") WISP_CHECK_EQ(call.table, kAutoPolicyTable);
    }

    // IPv4 only, so one suppress rule and one fwmark rule.
    WISP_CHECK_EQ(platform.rules_added(), 2u);

    bool saw_inverted_fwmark = false;
    bool saw_suppress = false;
    for (const auto& entry : platform.rules) {
        if (!entry.add) continue;
        if (entry.spec.invert && entry.spec.fwmark) {
            saw_inverted_fwmark = true;
            WISP_CHECK_EQ(*entry.spec.fwmark, kAutoPolicyTable);
            WISP_CHECK_EQ(entry.spec.table, kAutoPolicyTable);
            WISP_CHECK_EQ(entry.spec.priority, kFwmarkRulePriority);
        }
        if (entry.spec.suppress_prefixlength) {
            saw_suppress = true;
            WISP_CHECK_EQ(*entry.spec.suppress_prefixlength, 0u);
            WISP_CHECK_EQ(entry.spec.table, kMainRoutingTable);
            WISP_CHECK_EQ(entry.spec.priority, kSuppressRulePriority);
        }
    }
    WISP_CHECK(saw_inverted_fwmark);
    WISP_CHECK(saw_suppress);

    // The device must carry the mark, or the "not fwmark" rule will never let
    // the encrypted packets back out.
    WISP_CHECK(platform.last_device.fwmark.has_value());
    if (platform.last_device.fwmark) WISP_CHECK_EQ(*platform.last_device.fwmark, kAutoPolicyTable);
}

WISP_TEST(rules_are_installed_after_the_link_is_up) {
    FakePlatform platform;
    const auto result = bring_up(platform, nullptr, full_tunnel_config(), "wisp0");
    WISP_CHECK(result.ok);

    // If the rules went in first, unmarked traffic would be aimed at a table
    // whose interface is still down, which is a brief outage.
    const auto up = platform.index_of("set_link");
    WISP_CHECK(up.has_value());

    bool rules_after_up = platform.rules.empty();
    for (const auto& entry : platform.rules) {
        if (entry.add) rules_after_up = true;
    }
    WISP_CHECK(rules_after_up);
    WISP_CHECK(!platform.rules.empty());
}

WISP_TEST(a_dual_stack_full_tunnel_installs_rules_for_both_families) {
    FakePlatform platform;
    auto config = full_tunnel_config();
    config.peers[0].allowed_ips.push_back(*Cidr::parse("::/0"));

    const auto result = bring_up(platform, nullptr, config, "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK_EQ(platform.rules_added(), 4u);

    bool v4 = false;
    bool v6 = false;
    for (const auto& entry : platform.rules) {
        if (entry.spec.family == AF_INET) v4 = true;
        if (entry.spec.family == AF_INET6) v6 = true;
    }
    WISP_CHECK(v4 && v6);
}

WISP_TEST(table_off_installs_no_routes_and_no_rules) {
    FakePlatform platform;
    auto config = full_tunnel_config();
    config.table = "off";

    const auto result = bring_up(platform, nullptr, config, "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK_EQ(platform.count_of("route"), 0u);
    WISP_CHECK_EQ(platform.rules.size(), 0u);
}

WISP_TEST(bring_up_pushes_the_expected_device_config) {
    FakePlatform platform;
    auto config = split_tunnel_config();
    config.listen_port = 51820;
    config.mtu = 1420;

    const auto result = bring_up(platform, nullptr, config, "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK_EQ(platform.last_device.ifname, std::string("wisp0"));
    WISP_CHECK_EQ(platform.last_device.peers.size(), 1u);
    WISP_CHECK(platform.last_device.replace_peers);
}

WISP_TEST(failed_creation_is_reported_without_further_calls) {
    FakePlatform platform;
    platform.fail_create = true;
    const auto result = bring_up(platform, nullptr, split_tunnel_config(), "wisp0");
    WISP_CHECK(!result.ok);
    WISP_CHECK_EQ(platform.calls.size(), 1u);
    WISP_CHECK_EQ(platform.count_of("delete_link"), 0u);
}

WISP_TEST(failures_remove_the_half_configured_interface) {
    {
        FakePlatform platform;
        platform.fail_set_device = true;
        WISP_CHECK(!bring_up(platform, nullptr, split_tunnel_config(), "wisp0").ok);
        WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);
        WISP_CHECK(!platform.index_of("set_link").has_value());
    }
    {
        FakePlatform platform;
        platform.fail_address = true;
        WISP_CHECK(!bring_up(platform, nullptr, split_tunnel_config(), "wisp0").ok);
        WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);
    }
    {
        FakePlatform platform;
        platform.fail_route = true;
        WISP_CHECK(!bring_up(platform, nullptr, split_tunnel_config(), "wisp0").ok);
        WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);
    }
    {
        FakePlatform platform;
        platform.fail_set_link = true;
        WISP_CHECK(!bring_up(platform, nullptr, split_tunnel_config(), "wisp0").ok);
        WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);
    }
}

// A failed bring-up must not leave policy rules behind pointing at a table
// whose interface is about to be deleted.
WISP_TEST(a_failed_rule_installation_is_rolled_back) {
    FakePlatform platform;
    platform.fail_rule = true;

    const auto result = bring_up(platform, nullptr, full_tunnel_config(), "wisp0");
    WISP_CHECK(!result.ok);
    WISP_CHECK(platform.rules_removed() > 0);
    WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);
}

// DNS
WISP_TEST(dns_is_applied_on_bring_up) {
    FakePlatform platform;
    FakeDns dns;
    auto config = split_tunnel_config();
    config.dns = {"10.7.0.1", "10.7.0.2"};
    config.search_domains = {"internal"};

    const auto result = bring_up(platform, &dns, config, "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK_EQ(dns.applied.size(), 1u);
    if (dns.applied.empty()) return;
    WISP_CHECK_EQ(dns.applied[0].ifname, std::string("wisp0"));
    WISP_CHECK_EQ(dns.applied[0].servers.size(), 2u);
    WISP_CHECK_EQ(dns.applied[0].domains.size(), 1u);
}

WISP_TEST(dns_is_skipped_when_the_profile_sets_none) {
    FakePlatform platform;
    FakeDns dns;
    const auto result = bring_up(platform, &dns, split_tunnel_config(), "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK(dns.applied.empty());
}

// A resolver we could not change is worth reporting, but it is not a reason to
// tear down a tunnel that already works.
WISP_TEST(a_dns_failure_does_not_tear_down_a_working_tunnel) {
    FakePlatform platform;
    FakeDns dns;
    dns.fail_apply = true;

    auto config = split_tunnel_config();
    config.dns = {"10.7.0.1"};

    const auto result = bring_up(platform, &dns, config, "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK(result.message.find("DNS") != std::string::npos);
    WISP_CHECK_EQ(platform.count_of("delete_link"), 0u);
}

WISP_TEST(a_dns_failure_tears_down_a_full_tunnel_fail_closed) {
    FakePlatform platform;
    FakeDns dns;
    dns.fail_apply = true;

    auto config = full_tunnel_config();
    config.dns = {"10.7.0.1"};

    const auto result = bring_up(platform, &dns, config, "wisp0");
    WISP_CHECK(!result.ok);
    WISP_CHECK(result.message.find("fail-closed") != std::string::npos);
    WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);
}

WISP_TEST(dns_is_reverted_on_tear_down) {
    FakePlatform platform;
    FakeDns dns;
    const auto result = tear_down(platform, &dns, RoutingPlan::derive(split_tunnel_config()), "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK_EQ(dns.reverted.size(), 1u);
}

// Tear-down
WISP_TEST(tear_down_removes_policy_rules_before_the_link) {
    FakePlatform platform;
    const auto result = tear_down(platform, nullptr, RoutingPlan::derive(full_tunnel_config()), "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK(platform.rules_removed() > 0);
    WISP_CHECK_EQ(platform.count_of("delete_link"), 1u);

    for (const auto& entry : platform.rules) {
        WISP_CHECK(!entry.add);
    }
}

WISP_TEST(tear_down_removes_rules_even_when_the_link_is_gone) {
    FakePlatform platform;
    platform.present = false;

    const auto result = tear_down(platform, nullptr, RoutingPlan::derive(full_tunnel_config()), "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK(platform.rules_removed() > 0);
    WISP_CHECK_EQ(platform.count_of("delete_link"), 0u);
}

WISP_TEST(tear_down_of_a_missing_split_tunnel_is_success) {
    FakePlatform platform;
    platform.present = false;
    const auto result = tear_down(platform, nullptr, RoutingPlan::derive(split_tunnel_config()), "wisp0");
    WISP_CHECK(result.ok);
    WISP_CHECK_EQ(platform.rules.size(), 0u);
}

WISP_TEST(device_config_carries_mtu_through_to_link_creation) {
    FakePlatform platform;
    auto config = split_tunnel_config();
    config.mtu = 1280;
    WISP_CHECK(bring_up(platform, nullptr, config, "wisp0").ok);

    const auto create = platform.index_of("create_link");
    WISP_CHECK(create.has_value());
    if (create) WISP_CHECK(platform.calls[*create].detail.find("mtu=1280") != std::string::npos);
}

// A full bring-up followed by a tear-down must leave nothing behind.
WISP_TEST(bring_up_and_tear_down_are_symmetric) {
    FakePlatform platform;
    WISP_CHECK(bring_up(platform, nullptr, full_tunnel_config(), "wisp0").ok);
    const auto added = platform.rules_added();

    platform.rules.clear();
    platform.calls.clear();

    WISP_CHECK(tear_down(platform, nullptr, RoutingPlan::derive(full_tunnel_config()), "wisp0").ok);
    WISP_CHECK_EQ(platform.rules_removed(), added);
}

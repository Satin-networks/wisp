#include <string>
#include <vector>

#include "wisp/dns.hpp"
#include "wisp/types.hpp"
#include "wisp_test.hpp"

using namespace wisp;

// Backend selection
WISP_TEST(prefers_systemd_resolved_when_it_is_running) {
    DnsEnvironment environment;
    environment.resolvectl_available = true;
    environment.systemd_resolved_running = true;
    environment.resolvconf_available = true;
    environment.resolv_conf_is_regular_file = true;

    WISP_CHECK(select_backend(environment) == DnsBackend::SystemdResolved);
}

// resolvectl existing but resolved not running means something else owns the
// resolver, so handing DNS to resolvectl would do nothing useful.
WISP_TEST(falls_back_to_resolvconf_when_resolved_is_not_running) {
    DnsEnvironment environment;
    environment.resolvectl_available = true;
    environment.systemd_resolved_running = false;
    environment.resolvconf_available = true;

    WISP_CHECK(select_backend(environment) == DnsBackend::ResolvConf);
}

WISP_TEST(falls_back_to_the_file_when_no_manager_exists) {
    DnsEnvironment environment;
    environment.resolv_conf_is_regular_file = true;
    WISP_CHECK(select_backend(environment) == DnsBackend::ResolvConfFile);
}

// A symlinked resolv.conf belongs to something else. Overwriting it would
// fight that manager, so refusing is correct.
WISP_TEST(refuses_to_edit_a_symlinked_resolv_conf) {
    DnsEnvironment environment;
    environment.resolv_conf_is_regular_file = false;
    WISP_CHECK(select_backend(environment) == DnsBackend::None);
}

WISP_TEST(backend_names_are_stable) {
    WISP_CHECK_EQ(std::string(dns_backend_name(DnsBackend::None)), std::string("none"));
    WISP_CHECK_EQ(std::string(dns_backend_name(DnsBackend::SystemdResolved)),
                  std::string("systemd-resolved"));
    WISP_CHECK_EQ(std::string(dns_backend_name(DnsBackend::ResolvConf)), std::string("resolvconf"));
    WISP_CHECK_EQ(std::string(dns_backend_name(DnsBackend::ResolvConfFile)),
                  std::string("resolv.conf"));
}

// Validation
WISP_TEST(accepts_only_ip_literals_as_resolvers) {
    WISP_CHECK(is_valid_dns_server("1.1.1.1"));
    WISP_CHECK(is_valid_dns_server("10.7.0.1"));
    WISP_CHECK(is_valid_dns_server("2606:4700:4700::1111"));

    WISP_CHECK(!is_valid_dns_server(""));
    WISP_CHECK(!is_valid_dns_server("dns.example.com"));
    WISP_CHECK(!is_valid_dns_server("1.1.1.1 "));
    WISP_CHECK(!is_valid_dns_server("999.1.1.1"));
}

// IP literals only, so a resolver address can never read as a command-line flag.
WISP_TEST(rejects_resolvers_that_look_like_flags) {
    WISP_CHECK(!is_valid_dns_server("-oProxyCommand"));
    WISP_CHECK(!is_valid_dns_server("--config"));
    WISP_CHECK(!is_valid_dns_server("-1.1.1.1"));
}

WISP_TEST(accepts_ordinary_search_domains) {
    WISP_CHECK(is_valid_search_domain("example.com"));
    WISP_CHECK(is_valid_search_domain("internal"));
    WISP_CHECK(is_valid_search_domain("corp.example.co.uk"));
    WISP_CHECK(is_valid_search_domain("my-host"));
    WISP_CHECK(is_valid_search_domain("has_underscore"));
}

WISP_TEST(rejects_search_domains_that_could_inject_arguments) {
    WISP_CHECK(!is_valid_search_domain(""));
    WISP_CHECK(!is_valid_search_domain("-evil"));
    WISP_CHECK(!is_valid_search_domain(".leading"));
    WISP_CHECK(!is_valid_search_domain("has space"));
    WISP_CHECK(!is_valid_search_domain("semi;colon"));
    WISP_CHECK(!is_valid_search_domain("dollar$sign"));
    WISP_CHECK(!is_valid_search_domain("back`tick`"));
    WISP_CHECK(!is_valid_search_domain("new\nline"));
    WISP_CHECK(!is_valid_search_domain("slash/path"));
    WISP_CHECK(!is_valid_search_domain(std::string(300, 'a')));
}

// Command planning
WISP_TEST(plans_resolvectl_commands) {
    const auto commands = plan_dns_apply(DnsBackend::SystemdResolved, "wisp0", {"10.7.0.1"},
                                         {"internal"});
    WISP_CHECK_EQ(commands.size(), 2u);
    if (commands.size() != 2) return;

    // Fixed program, explicit argv: nothing is ever handed to a shell.
    WISP_CHECK_EQ(commands[0].program, std::string("resolvectl"));
    WISP_CHECK_EQ(commands[0].arguments,
                  (std::vector<std::string>{"dns", "wisp0", "10.7.0.1"}));
    WISP_CHECK(commands[0].stdin_data.empty());

    WISP_CHECK_EQ(commands[1].arguments,
                  (std::vector<std::string>{"domain", "wisp0", "~internal"}));
}

WISP_TEST(does_not_double_prefix_a_routing_domain) {
    const auto commands =
        plan_dns_apply(DnsBackend::SystemdResolved, "wisp0", {"10.7.0.1"}, {"~corp.internal"});
    WISP_CHECK_EQ(commands.size(), 2u);
    if (commands.size() != 2) return;
    WISP_CHECK_EQ(commands[1].arguments,
                  (std::vector<std::string>{"domain", "wisp0", "~corp.internal"}));
}

WISP_TEST(skips_the_domain_command_when_there_are_no_domains) {
    const auto commands = plan_dns_apply(DnsBackend::SystemdResolved, "wisp0", {"10.7.0.1"}, {});
    WISP_CHECK_EQ(commands.size(), 1u);
}

WISP_TEST(plans_resolvconf_with_the_config_on_stdin) {
    const auto commands = plan_dns_apply(DnsBackend::ResolvConf, "wisp0",
                                         {"10.7.0.1", "10.7.0.2"}, {"internal"});
    WISP_CHECK_EQ(commands.size(), 1u);
    if (commands.empty()) return;

    WISP_CHECK_EQ(commands[0].program, std::string("resolvconf"));
    WISP_CHECK_EQ(commands[0].arguments, (std::vector<std::string>{"-a", "wisp0"}));
    WISP_CHECK(commands[0].stdin_data.find("nameserver 10.7.0.1") != std::string::npos);
    WISP_CHECK(commands[0].stdin_data.find("nameserver 10.7.0.2") != std::string::npos);
    WISP_CHECK(commands[0].stdin_data.find("search internal") != std::string::npos);
}

WISP_TEST(planning_drops_invalid_entries) {
    const auto commands = plan_dns_apply(
        DnsBackend::SystemdResolved, "wisp0",
        {"10.0.0.1", "-oProxyCommand", "notanip", "10.0.0.2"}, {"good.com", "-bad", "has space"});
    WISP_CHECK_EQ(commands.size(), 2u);
    if (commands.size() != 2) return;

    WISP_CHECK_EQ(commands[0].arguments,
                  (std::vector<std::string>{"dns", "wisp0", "10.0.0.1", "10.0.0.2"}));
    WISP_CHECK_EQ(commands[1].arguments,
                  (std::vector<std::string>{"domain", "wisp0", "~good.com"}));
}

WISP_TEST(plans_nothing_when_there_are_no_usable_resolvers) {
    WISP_CHECK(plan_dns_apply(DnsBackend::SystemdResolved, "wisp0", {"bad"}, {}).empty());
    WISP_CHECK(plan_dns_apply(DnsBackend::ResolvConf, "wisp0", {}, {}).empty());
    WISP_CHECK(plan_dns_apply(DnsBackend::None, "wisp0", {"10.0.0.1"}, {}).empty());
}

WISP_TEST(plans_revert_commands) {
    const auto resolved = plan_dns_revert(DnsBackend::SystemdResolved, "wisp0");
    WISP_CHECK_EQ(resolved.size(), 1u);
    if (!resolved.empty()) {
        WISP_CHECK_EQ(resolved[0].program, std::string("resolvectl"));
        WISP_CHECK_EQ(resolved[0].arguments, (std::vector<std::string>{"revert", "wisp0"}));
    }

    const auto resolvconf = plan_dns_revert(DnsBackend::ResolvConf, "wisp0");
    WISP_CHECK_EQ(resolvconf.size(), 1u);
    if (!resolvconf.empty()) {
        WISP_CHECK_EQ(resolvconf[0].arguments,
                      (std::vector<std::string>{"-d", "wisp0", "-f"}));
    }

    WISP_CHECK(plan_dns_revert(DnsBackend::None, "wisp0").empty());
    WISP_CHECK(plan_dns_revert(DnsBackend::ResolvConfFile, "wisp0").empty());
}

WISP_TEST(renders_a_resolv_conf) {
    const auto contents = render_resolv_conf("wisp0", {"10.7.0.1"}, {"internal"});
    WISP_CHECK(contents.find("nameserver 10.7.0.1") != std::string::npos);
    WISP_CHECK(contents.find("search internal") != std::string::npos);
    WISP_CHECK(contents.find("wisp0") != std::string::npos);

    const auto plain = render_resolv_conf("wisp0", {"10.7.0.1"}, {});
    WISP_CHECK(plain.find("search") == std::string::npos);
}

// The manager must not attempt anything when there is no backend: silently
// doing nothing is better than an unknown edit to the resolver.
WISP_TEST(a_none_manager_reports_apply_as_unsupported_but_revert_as_done) {
    auto manager = make_dns_manager(DnsBackend::None);
    std::string error;
    WISP_CHECK(!manager->apply("wisp0", {"10.7.0.1"}, {}, error));
    WISP_CHECK(!error.empty());
    WISP_CHECK(manager->revert("wisp0", error));
    WISP_CHECK(manager->backend() == DnsBackend::None);
}

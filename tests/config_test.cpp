#include <string>

#include "wisp/config.hpp"
#include "wisp/keys.hpp"
#include "wisp_test.hpp"

using namespace wisp;

namespace {

struct Sample {
    std::string text;
    std::string private_key;
    std::string peer_key;
    std::string psk;
};

Sample make_sample() {
    Sample sample;
    sample.private_key = generate_private_key();
    sample.peer_key = generate_private_key();
    sample.psk = generate_preshared_key();

    sample.text =
        "[Interface]\n"
        "PrivateKey = " + sample.private_key + "\n" +
        "Address = 10.7.0.2/32, fd00:7::2/128\n"
        "DNS = 10.7.0.1, wisp.internal\n"
        "MTU = 1420\n"
        "ListenPort = 51820\n"
        "FwMark = 0x1234\n"
        "Table = auto\n"
        "\n"
        "[Peer]\n"
        "PublicKey = " + sample.peer_key + "\n" +
        "PresharedKey = " + sample.psk + "\n" +
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = vpn.example.com:51820\n"
        "PersistentKeepalive = 25\n";
    return sample;
}

std::string with_interface(const std::string& body) {
    return "[Interface]\nPrivateKey = " + generate_private_key() + "\n" + body;
}

std::string with_peer(const std::string& peer_body) {
    return with_interface("Address = 10.0.0.2/32\n") + "\n[Peer]\nPublicKey = " +
           generate_private_key() + "\n" + peer_body;
}

bool has_error_containing(const ParseResult& result, const std::string& needle) {
    for (const auto& error : result.errors) {
        if (error.message.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool has_warning_containing(const ParseResult& result, const std::string& needle) {
    for (const auto& warning : result.warnings) {
        if (warning.message.find(needle) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

WISP_TEST(parses_a_full_config) {
    const auto sample = make_sample();
    const auto result = parse_config(sample.text);
    WISP_CHECK(result.ok());
    if (!result.ok()) return;

    const auto& iface = *result.interface;
    WISP_CHECK_EQ(iface.private_key, sample.private_key);
    WISP_CHECK_EQ(iface.addresses.size(), 2u);
    WISP_CHECK_EQ(iface.addresses[0].to_string(), std::string("10.7.0.2/32"));
    WISP_CHECK_EQ(iface.addresses[1].to_string(), std::string("fd00:7::2/128"));

    // DNS lines carry both resolver addresses and search domains.
    WISP_CHECK_EQ(iface.dns.size(), 1u);
    WISP_CHECK_EQ(iface.dns[0], std::string("10.7.0.1"));
    WISP_CHECK_EQ(iface.search_domains.size(), 1u);
    WISP_CHECK_EQ(iface.search_domains[0], std::string("wisp.internal"));

    WISP_CHECK(iface.mtu.has_value() && *iface.mtu == 1420);
    WISP_CHECK(iface.listen_port.has_value() && *iface.listen_port == 51820);
    WISP_CHECK(iface.fwmark.has_value() && *iface.fwmark == 0x1234);
    WISP_CHECK(iface.table.has_value() && *iface.table == "auto");

    WISP_CHECK_EQ(iface.peers.size(), 1u);
    const auto& peer = iface.peers[0];
    WISP_CHECK_EQ(peer.public_key, sample.peer_key);
    WISP_CHECK(peer.preshared_key.has_value() && *peer.preshared_key == sample.psk);
    WISP_CHECK_EQ(peer.allowed_ips.size(), 2u);
    WISP_CHECK(peer.endpoint.has_value() && peer.endpoint->host == "vpn.example.com");
    WISP_CHECK(peer.endpoint.has_value() && peer.endpoint->port == 51820);
    WISP_CHECK(peer.persistent_keepalive.has_value() && *peer.persistent_keepalive == 25);
    WISP_CHECK(iface.routes_all_traffic());
}

WISP_TEST(serialize_round_trips_through_parse) {
    const auto sample = make_sample();
    const auto first = parse_config(sample.text);
    WISP_CHECK(first.ok());
    if (!first.ok()) return;

    const auto second = parse_config(serialize_config(*first.interface));
    WISP_CHECK(second.ok());
    if (!second.ok()) return;

    WISP_CHECK(*first.interface == *second.interface);
}

WISP_TEST(tolerates_comments_blank_lines_and_crlf) {
    const auto key = generate_private_key();
    const std::string text =
        "# leading comment\r\n"
        "\r\n"
        "  [Interface]  \r\n"
        "  PrivateKey   =   " + key + "   # inline comment\r\n" +
        "Address = 10.0.0.2/32\r\n"
        "\r\n";

    const auto result = parse_config(text);
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK_EQ(result.interface->private_key, key);
    WISP_CHECK_EQ(result.interface->addresses.size(), 1u);
}

WISP_TEST(key_and_section_names_are_case_insensitive) {
    const auto private_key = generate_private_key();
    const auto peer_key = generate_private_key();

    const auto result = parse_config("[interface]\nprivatekey = " + private_key +
                                     "\naddress = 10.0.0.2/32\n\n[PEER]\npublickey = " +
                                     peer_key + "\nallowedips = 10.0.0.0/24\n");
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK_EQ(result.interface->private_key, private_key);
    WISP_CHECK_EQ(result.interface->peers.size(), 1u);
    WISP_CHECK_EQ(result.interface->peers[0].public_key, peer_key);
}

WISP_TEST(rejects_invalid_private_key) {
    const auto result = parse_config("[Interface]\nPrivateKey = not-a-key\n");
    WISP_CHECK(!result.ok());
    WISP_CHECK(has_error_containing(result, "PrivateKey"));
    WISP_CHECK(!result.interface.has_value());
}

WISP_TEST(rejects_invalid_cidr) {
    WISP_CHECK(!parse_config(with_interface("Address = 10.0.0.0/33\n")).ok());
    WISP_CHECK(!parse_config(with_interface("Address = 300.1.1.1/24\n")).ok());
    WISP_CHECK(!parse_config(with_interface("Address = 10.0.0.2/abc\n")).ok());
}

// inet_aton-style shorthands would parse to a different network than written,
// so they must be refused rather than guessed at.
WISP_TEST(rejects_shorthand_address_forms) {
    WISP_CHECK(!parse_config(with_interface("Address = 10/8\n")).ok());
    WISP_CHECK(!parse_config(with_interface("Address = 10.1/16\n")).ok());
    WISP_CHECK(!parse_config(with_interface("Address = 0177.0.0.1/8\n")).ok());
}

WISP_TEST(parses_ipv6_endpoint_with_brackets) {
    const auto result =
        parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nEndpoint = [2001:db8::1]:51820\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    const auto& endpoint = *result.interface->peers[0].endpoint;
    WISP_CHECK_EQ(endpoint.host, std::string("2001:db8::1"));
    WISP_CHECK_EQ(endpoint.port, 51820);
}

WISP_TEST(rejects_ambiguous_unbracketed_ipv6_endpoint) {
    const auto result =
        parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nEndpoint = 2001:db8::1:51820\n"));
    WISP_CHECK(!result.ok());
    WISP_CHECK(has_error_containing(result, "Endpoint"));
}

WISP_TEST(rejects_endpoints_without_a_valid_port) {
    WISP_CHECK(!parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com\n")).ok());
    WISP_CHECK(!parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:0\n")).ok());
    WISP_CHECK(!parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:99999\n")).ok());
}

WISP_TEST(rejects_keys_in_the_wrong_section) {
    const auto peer_key_in_interface =
        parse_config(with_interface("PublicKey = " + generate_private_key() + "\n"));
    WISP_CHECK(!peer_key_in_interface.ok());
    WISP_CHECK(has_error_containing(peer_key_in_interface, "[Peer] key"));

    const auto interface_key_in_peer =
        parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nListenPort = 1234\n"));
    WISP_CHECK(!interface_key_in_peer.ok());
    WISP_CHECK(has_error_containing(interface_key_in_peer, "[Interface] key"));
}

WISP_TEST(rejects_config_without_interface_section) {
    const auto result = parse_config("[Peer]\nPublicKey = " + generate_private_key() + "\n");
    WISP_CHECK(!result.ok());
    WISP_CHECK(has_error_containing(result, "no [Interface] section"));
}

WISP_TEST(rejects_interface_without_private_key) {
    const auto result = parse_config("[Interface]\nAddress = 10.0.0.2/32\n");
    WISP_CHECK(!result.ok());
    WISP_CHECK(has_error_containing(result, "PrivateKey"));
}

WISP_TEST(rejects_unknown_section) {
    const auto result =
        parse_config(with_interface("Address = 10.0.0.2/32\n") + "\n[Wireguard]\nFoo = bar\n");
    WISP_CHECK(!result.ok());
    WISP_CHECK(has_error_containing(result, "unknown section"));
}

WISP_TEST(rejects_empty_config) {
    WISP_CHECK(!parse_config("").ok());
    WISP_CHECK(!parse_config("# only a comment\n").ok());
}

WISP_TEST(rejects_line_without_equals) {
    const auto result = parse_config(with_interface("Address = 10.0.0.2/32\nthis is not a key\n"));
    WISP_CHECK(!result.ok());
}

WISP_TEST(errors_carry_line_numbers) {
    const auto result = parse_config("[Interface]\nPrivateKey = bad\n");
    WISP_CHECK(!result.ok());
    if (result.errors.empty()) return;
    WISP_CHECK_EQ(result.errors[0].line, 2u);
}

WISP_TEST(unknown_keys_warn_but_do_not_fail) {
    const auto result = parse_config(with_interface("Address = 10.0.0.2/32\nSomethingNew = 5\n"));
    WISP_CHECK(result.ok());
    WISP_CHECK(has_warning_containing(result, "SomethingNew"));
}

// The harshest thing in a wg-quick file is PostUp: arbitrary shell. We keep it
// so the UI can show the user what a profile would do, and never run it.
WISP_TEST(hooks_are_parsed_and_flagged_as_not_executed) {
    const auto result = parse_config(
        with_interface("Address = 10.0.0.2/32\nPostUp = iptables -A FORWARD -j ACCEPT\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK_EQ(result.interface->hooks.post_up.size(), 1u);
    WISP_CHECK_EQ(result.interface->hooks.post_up[0],
                  std::string("iptables -A FORWARD -j ACCEPT"));
    WISP_CHECK(!result.interface->hooks.empty());
    WISP_CHECK(has_warning_containing(result, "not executed"));
}

WISP_TEST(hooks_survive_a_serialize_round_trip) {
    const auto result = parse_config(
        with_interface("Address = 10.0.0.2/32\nPreUp = echo hi\nPostDown = echo bye\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;

    const auto reparsed = parse_config(serialize_config(*result.interface));
    WISP_CHECK(reparsed.ok());
    if (!reparsed.ok()) return;
    WISP_CHECK_EQ(reparsed.interface->hooks.pre_up.size(), 1u);
    WISP_CHECK_EQ(reparsed.interface->hooks.post_down.size(), 1u);
}

WISP_TEST(keepalive_of_zero_means_disabled) {
    const auto result = parse_config(with_peer("AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 0\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK(!result.interface->peers[0].persistent_keepalive.has_value());
}

WISP_TEST(rejects_out_of_range_ports_and_mtu) {
    WISP_CHECK(!parse_config(with_interface("ListenPort = 0\n")).ok());
    WISP_CHECK(!parse_config(with_interface("ListenPort = 70000\n")).ok());
    WISP_CHECK(!parse_config(with_interface("MTU = 100\n")).ok());
    WISP_CHECK(!parse_config(with_interface("MTU = 999999\n")).ok());
}

WISP_TEST(accepts_table_modes) {
    const auto auto_table = parse_config(with_interface("Table = auto\n"));
    WISP_CHECK(auto_table.ok() && auto_table.interface->table == "auto");

    const auto off_table = parse_config(with_interface("Table = off\n"));
    WISP_CHECK(off_table.ok() && off_table.interface->table == "off");

    const auto numeric = parse_config(with_interface("Table = 51820\n"));
    WISP_CHECK(numeric.ok() && numeric.interface->table == "51820");

    WISP_CHECK(!parse_config(with_interface("Table = maybe\n")).ok());
}

WISP_TEST(parses_multiple_peers_in_order) {
    const auto private_key = generate_private_key();
    const auto first_peer = generate_private_key();
    const auto second_peer = generate_private_key();

    const std::string text = "[Interface]\nPrivateKey = " + private_key +
                             "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + first_peer +
                             "\nAllowedIPs = 10.1.0.0/16\n\n[Peer]\nPublicKey = " + second_peer +
                             "\nAllowedIPs = 10.2.0.0/16\n";

    const auto result = parse_config(text);
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK_EQ(result.interface->peers.size(), 2u);
    WISP_CHECK_EQ(result.interface->peers[0].public_key, first_peer);
    WISP_CHECK_EQ(result.interface->peers[1].public_key, second_peer);
}

WISP_TEST(rejects_peer_without_public_key) {
    const std::string text = "[Interface]\nPrivateKey = " + generate_private_key() +
                             "\nAddress = 10.0.0.2/32\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\n";
    const auto result = parse_config(text);
    WISP_CHECK(!result.ok());
    WISP_CHECK(has_error_containing(result, "PublicKey"));
}

WISP_TEST(reports_split_tunnel_configs) {
    const auto result = parse_config(with_peer("AllowedIPs = 10.9.0.0/16\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK(!result.interface->routes_all_traffic());
}

WISP_TEST(warns_when_a_config_has_no_peers) {
    const auto result = parse_config(with_interface("Address = 10.0.0.2/32\n"));
    WISP_CHECK(result.ok());
    WISP_CHECK(has_warning_containing(result, "no peers"));
}

WISP_TEST(rejects_dns_entries_that_are_neither_addresses_nor_domains) {
    WISP_CHECK(!parse_config(with_interface("DNS = 1.1.1.1, not a domain\n")).ok());
    WISP_CHECK(!parse_config(with_interface("DNS = 1.1.1.1, has/slash\n")).ok());
    WISP_CHECK(!parse_config(with_interface("DNS = -looks-like-a-flag\n")).ok());
    WISP_CHECK(!parse_config(with_interface("DNS = 1.1.1.1, semicolon;injection\n")).ok());

    // The good cases still work.
    WISP_CHECK(parse_config(with_interface("DNS = 1.1.1.1, example.com\n")).ok());
}

WISP_TEST(accepts_a_routing_domain_marker) {
    const auto result = parse_config(with_interface("DNS = 10.7.0.1, ~corp.internal\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK_EQ(result.interface->search_domains.size(), 1u);
    if (!result.interface->search_domains.empty()) {
        WISP_CHECK_EQ(result.interface->search_domains[0], std::string("~corp.internal"));
    }
}

// A regression found by fuzzing.
//
// A search domain beginning with '#' used to be stored verbatim and then
// written back out as "a, #b". Because the parser strips '#' when it follows
// whitespace, re-parsing silently truncated the list - so a profile changed
// meaning across a round trip. The fix is to validate the entry instead of
// storing whatever arrived, which is what this pins down.
WISP_TEST(rejects_dns_entries_that_would_break_the_round_trip) {
    // The trigger is subtle, which is exactly why the fuzzer found it rather
    // than a human: '#' directly after a comma. Comment stripping needs
    // whitespace before the '#', so it does not fire on the way in - but the
    // serialiser joins list entries with ", ", which puts whitespace there and
    // makes it fire on the way back out.
    WISP_CHECK(!parse_config(with_interface("DNS = foo,#bar\n")).ok());
    WISP_CHECK(!parse_config(with_interface("DNS = 10.7.0.1,#comment\n")).ok());
    WISP_CHECK(!parse_config(with_interface("DNS = 1.1.1.1,example.com,#tail\n")).ok());
}

// The mirror image: a genuinely commented value is stripped, not rejected.
WISP_TEST(a_comment_after_a_dns_value_is_stripped_not_rejected) {
    const auto result = parse_config(with_interface("DNS = 1.1.1.1 # my resolver\n"));
    WISP_CHECK(result.ok());
    if (!result.ok()) return;
    WISP_CHECK_EQ(result.interface->dns.size(), 1u);
    WISP_CHECK(result.interface->search_domains.empty());
}

// Paired with the test above: everything the parser accepts must serialise and
// parse back to exactly the same interface. This is the invariant the fuzzer
// checks continuously, asserted here on concrete inputs.
WISP_TEST(accepted_configs_round_trip_unchanged) {
    const std::vector<std::string> cases = {
        make_sample().text,
        with_interface("Address = 10.0.0.2/32, fd00::2/128\nDNS = 1.1.1.1, example.com, ~corp.internal\n"),
        with_interface("Address = 10.0.0.2/32\nTable = auto\nMTU = 1280\nPostUp = echo hi\n"),
        with_peer("AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = [2001:db8::1]:51820\n"),
        with_interface("Address = 10.0.0.2/32\nFwMark = 0x1234\nSaveConfig = true\n"),
        with_peer("AllowedIPs = 10.0.0.0/8\nPersistentKeepalive = 0\n"),
    };

    for (const auto& text : cases) {
        const auto first = parse_config(text);
        WISP_CHECK(first.ok());
        if (!first.ok()) continue;

        const auto second = parse_config(serialize_config(*first.interface));
        WISP_CHECK(second.ok());
        if (!second.ok()) continue;
        WISP_CHECK(*second.interface == *first.interface);
    }
}

WISP_TEST(cidr_normalizes_equivalent_spellings) {
    const auto expanded = Cidr::parse("2001:0db8:0000::1/64");
    const auto compact = Cidr::parse("2001:db8::1/64");
    WISP_CHECK(expanded.has_value() && compact.has_value());
    if (!expanded || !compact) return;
    WISP_CHECK_EQ(expanded->address, compact->address);
    WISP_CHECK(*expanded == *compact);
}

WISP_TEST(cidr_defaults_to_a_host_route) {
    const auto v4 = Cidr::parse("10.0.0.1");
    const auto v6 = Cidr::parse("fd00::1");
    WISP_CHECK(v4.has_value() && v4->prefix == 32 && !v4->is_v6);
    WISP_CHECK(v6.has_value() && v6->prefix == 128 && v6->is_v6);
}

WISP_TEST(endpoint_renders_ipv6_with_brackets) {
    const auto endpoint = Endpoint::parse("[fd00::1]:51820");
    WISP_CHECK(endpoint.has_value());
    if (!endpoint) return;
    WISP_CHECK_EQ(endpoint->to_string(), std::string("[fd00::1]:51820"));
}

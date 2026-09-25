#include <string>

#include "wisp/ipc.hpp"
#include "wisp_test.hpp"

using namespace wisp::ipc;

WISP_TEST(accepts_ordinary_tunnel_names) {
    WISP_CHECK(is_valid_tunnel_name("wisp0"));
    WISP_CHECK(is_valid_tunnel_name("home"));
    WISP_CHECK(is_valid_tunnel_name("work_vpn"));
    WISP_CHECK(is_valid_tunnel_name("a"));
    WISP_CHECK(is_valid_tunnel_name("wg-0"));
    WISP_CHECK(is_valid_tunnel_name("12345"));
    WISP_CHECK(is_valid_tunnel_name("abcdefghijklmno"));  // exactly 15
}

// The name is the only thing a client may specify, so this is the whole
// defence against the helper being tricked into reading an arbitrary file.
WISP_TEST(rejects_path_traversal_attempts) {
    WISP_CHECK(!is_valid_tunnel_name(".."));
    WISP_CHECK(!is_valid_tunnel_name("."));
    WISP_CHECK(!is_valid_tunnel_name("../etc/passwd"));
    WISP_CHECK(!is_valid_tunnel_name("/etc/passwd"));
    WISP_CHECK(!is_valid_tunnel_name("../../root/.ssh/id_rsa"));
    WISP_CHECK(!is_valid_tunnel_name("nested/name"));
    WISP_CHECK(!is_valid_tunnel_name("name.conf"));
    WISP_CHECK(!is_valid_tunnel_name(".hidden"));
    WISP_CHECK(!is_valid_tunnel_name("..\\windows"));
}

WISP_TEST(rejects_names_that_could_be_read_as_options) {
    WISP_CHECK(!is_valid_tunnel_name("-rf"));
    WISP_CHECK(!is_valid_tunnel_name("--config"));
    WISP_CHECK(!is_valid_tunnel_name("-"));
}

WISP_TEST(rejects_names_with_shell_or_space_characters) {
    WISP_CHECK(!is_valid_tunnel_name("a b"));
    WISP_CHECK(!is_valid_tunnel_name("a;b"));
    WISP_CHECK(!is_valid_tunnel_name("a|b"));
    WISP_CHECK(!is_valid_tunnel_name("a$b"));
    WISP_CHECK(!is_valid_tunnel_name("a`b`"));
    WISP_CHECK(!is_valid_tunnel_name("a\nb"));
    WISP_CHECK(!is_valid_tunnel_name("wisp0 "));

    // An embedded NUL must not be treated as the end of the name.
    const std::string_view with_embedded_nul("tunnel\0hidden", 13);
    WISP_CHECK(!is_valid_tunnel_name(with_embedded_nul));
}

WISP_TEST(rejects_empty_or_overlong_names) {
    WISP_CHECK(!is_valid_tunnel_name(""));
    WISP_CHECK(!is_valid_tunnel_name("abcdefghijklmnop"));  // 16: one past IFNAMSIZ - 1
}

WISP_TEST(knows_which_verbs_are_defined) {
    WISP_CHECK(is_valid_verb("PING"));
    WISP_CHECK(is_valid_verb("LIST"));
    WISP_CHECK(is_valid_verb("UP"));
    WISP_CHECK(is_valid_verb("DOWN"));
    WISP_CHECK(is_valid_verb("STATUS"));

    WISP_CHECK(!is_valid_verb(""));
    WISP_CHECK(!is_valid_verb("up"));  // verbs are case-sensitive
    WISP_CHECK(!is_valid_verb("UPS"));
    WISP_CHECK(!is_valid_verb("PING\n"));
}

// Without this, a caller could smuggle a newline into a response - fabricating
// a second line - or into a log entry, splitting it so the real record is not
// the one an operator reads.
WISP_TEST(sanitize_for_display_keeps_output_on_one_line) {
    WISP_CHECK_EQ(sanitize_for_display("UP\nDOWN"), std::string("UP?DOWN"));
    WISP_CHECK_EQ(sanitize_for_display("a\rb"), std::string("a?b"));
    // A tab is a control character too, so it is replaced as well: the result
    // is always printable ASCII and nothing else.
    WISP_CHECK_EQ(sanitize_for_display("a\tb"), std::string("a?b"));
    WISP_CHECK_EQ(sanitize_for_display(std::string("x\0y", 3)), std::string("x?y"));
    WISP_CHECK_EQ(sanitize_for_display("\xff\xfe"), std::string("??"));
    WISP_CHECK_EQ(sanitize_for_display("keep"), std::string("keep"));

    // Length-capped, so a huge verb cannot blow up a log line.
    WISP_CHECK_EQ(sanitize_for_display("abcdefghij", 4), std::string("abcd"));
    WISP_CHECK_EQ(sanitize_for_display("", 4), std::string(""));
}

WISP_TEST(sanitized_output_never_contains_a_control_character) {
    const std::string hostile = "UP\nDOWN\r\t\x01\x02\xff forged OK payload";
    const auto cleaned = sanitize_for_display(hostile);
    for (const char c : cleaned) {
        const auto byte = static_cast<unsigned char>(c);
        WISP_CHECK(byte >= 0x20 && byte < 0x7f);
    }
    WISP_CHECK(cleaned.find('\n') == std::string::npos);
}

WISP_TEST(parses_requests) {
    const auto bare = parse_request("PING");
    WISP_CHECK_EQ(bare.verb, std::string("PING"));
    WISP_CHECK_EQ(bare.argument, std::string(""));

    const auto with_argument = parse_request("UP wisp0\n");
    WISP_CHECK_EQ(with_argument.verb, std::string("UP"));
    WISP_CHECK_EQ(with_argument.argument, std::string("wisp0"));

    const auto messy = parse_request("  DOWN   wisp0  \r\n");
    WISP_CHECK_EQ(messy.verb, std::string("DOWN"));
    WISP_CHECK_EQ(messy.argument, std::string("wisp0"));

    const auto empty = parse_request("");
    WISP_CHECK_EQ(empty.verb, std::string(""));

    // Every kind of whitespace is trimmed, including newlines. Trimming only
    // spaces and tabs used to leave a leading newline attached to the verb,
    // which broke the parse/encode round trip. Fuzzing found it.
    const auto leading_newline = parse_request("\n UP wisp0");
    WISP_CHECK_EQ(leading_newline.verb, std::string("UP"));
    WISP_CHECK_EQ(leading_newline.argument, std::string("wisp0"));

    const auto tabs = parse_request("\tUP\twisp0\t");
    WISP_CHECK_EQ(tabs.verb, std::string("UP"));
    WISP_CHECK_EQ(tabs.argument, std::string("wisp0"));

    // A newline embedded in the middle still lands in the verb, which is why
    // the helper validates and sanitises rather than trusting it.
    const auto embedded = parse_request("UP\nDOWN wisp0");
    WISP_CHECK_EQ(embedded.verb, std::string("UP\nDOWN"));
    WISP_CHECK(!is_valid_verb(embedded.verb));
}

// The server keeps one connection open and feeds every read into a buffer, so
// pulling whole lines out of that buffer has to work for any split the kernel
// chooses - including several requests arriving in a single read.
WISP_TEST(takes_complete_lines_out_of_a_buffer) {
    std::string buffer;
    std::string line;

    WISP_CHECK(!take_request_line(buffer, line));
    WISP_CHECK_EQ(line, std::string(""));

    // A partial request must wait rather than be handed on half-formed.
    buffer = "PING";
    WISP_CHECK(!take_request_line(buffer, line));
    WISP_CHECK_EQ(buffer, std::string("PING"));

    buffer += "\n";
    WISP_CHECK(take_request_line(buffer, line));
    WISP_CHECK_EQ(line, std::string("PING\n"));
    WISP_CHECK_EQ(buffer, std::string(""));

    // Two requests in one read come out in order, and the leftover stays put.
    buffer = "UP wisp0\nDOWN wisp0\nSTATUS wi";
    WISP_CHECK(take_request_line(buffer, line));
    WISP_CHECK_EQ(line, std::string("UP wisp0\n"));
    WISP_CHECK(take_request_line(buffer, line));
    WISP_CHECK_EQ(line, std::string("DOWN wisp0\n"));
    WISP_CHECK(!take_request_line(buffer, line));
    WISP_CHECK_EQ(buffer, std::string("STATUS wi"));

    // The extracted line is exactly what parse_request expects, including a
    // bare newline that parses to an empty request rather than being skipped.
    buffer = "\n";
    WISP_CHECK(take_request_line(buffer, line));
    WISP_CHECK_EQ(parse_request(line).verb, std::string(""));
}

WISP_TEST(encodes_requests_that_parse_back) {
    const Request original{"UP", "wisp0"};
    WISP_CHECK_EQ(parse_request(encode_request(original)), original);

    const Request no_argument{"PING", ""};
    WISP_CHECK_EQ(parse_request(encode_request(no_argument)), no_argument);
}

WISP_TEST(encodes_responses) {
    WISP_CHECK_EQ(encode_ok(), std::string("OK\n"));
    WISP_CHECK_EQ(encode_ok("wisp0"), std::string("OK wisp0\n"));
    WISP_CHECK_EQ(encode_error("no such tunnel"), std::string("ERR no such tunnel\n"));
}

WISP_TEST(recognises_ok_responses) {
    WISP_CHECK(response_is_ok("OK\n"));
    WISP_CHECK(response_is_ok("OK wisp0\n"));
    WISP_CHECK(response_is_ok("OK"));

    WISP_CHECK(!response_is_ok("ERR nope\n"));
    WISP_CHECK(!response_is_ok("OKAY\n"));
    WISP_CHECK(!response_is_ok(""));
    WISP_CHECK(!response_is_ok("O"));
}

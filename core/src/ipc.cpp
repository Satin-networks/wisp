#include "wisp/ipc.hpp"

#include <algorithm>
#include <cctype>

namespace wisp::ipc {
namespace {

// IFNAMSIZ is 16, so an interface name is at most 15 characters.
constexpr std::size_t kMaxTunnelNameLength = 15;

constexpr std::string_view kKnownVerbs[] = {kPing, kList, kUp, kDown, kStatus};

// All whitespace, not just spaces and tabs. Trimming only ' ' and '\t' left a
// leading newline glued to the verb, which broke request round-tripping.
// Fuzzing caught it.
std::string_view trim(std::string_view text) {
    const auto not_space = [](char c) { return !std::isspace(static_cast<unsigned char>(c)); };
    while (!text.empty() && !not_space(text.front())) text.remove_prefix(1);
    while (!text.empty() && !not_space(text.back())) text.remove_suffix(1);
    return text;
}

bool is_name_character(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '-';
}

}  // namespace

bool is_valid_tunnel_name(std::string_view name) {
    if (name.empty() || name.size() > kMaxTunnelNameLength) return false;

    // A leading '-' could be read as an option by any tool reached from here,
    // and a leading '.' could begin a relative path that escapes the config
    // directory. Neither is ever a legitimate interface name.
    if (name.front() == '-' || name.front() == '.') return false;

    for (char c : name) {
        if (!is_name_character(c)) return false;
    }
    return true;
}

bool is_valid_verb(std::string_view verb) {
    for (const auto candidate : kKnownVerbs) {
        if (verb == candidate) return true;
    }
    return false;
}

std::string sanitize_for_display(std::string_view text, std::size_t max_length) {
    std::string out;
    out.reserve(std::min(text.size(), max_length));

    for (const char c : text) {
        if (out.size() >= max_length) break;
        const auto byte = static_cast<unsigned char>(c);
        // Printable ASCII only: this is what guarantees a single line.
        out.push_back(byte >= 0x20 && byte < 0x7f ? c : '?');
    }
    return out;
}

Request parse_request(std::string_view line) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    line = trim(line);

    Request request;
    if (const auto separator = line.find_first_of(" \t"); separator != std::string_view::npos) {
        request.verb = std::string(line.substr(0, separator));
        request.argument = std::string(trim(line.substr(separator + 1)));
    } else {
        request.verb = std::string(line);
    }
    return request;
}

std::string encode_request(const Request& request) {
    if (request.argument.empty()) return request.verb + "\n";
    return request.verb + " " + request.argument + "\n";
}

bool take_request_line(std::string& buffer, std::string& line) {
    const auto newline = buffer.find('\n');
    if (newline == std::string::npos) return false;

    line.assign(buffer, 0, newline + 1);
    buffer.erase(0, newline + 1);
    return true;
}

std::string encode_ok(const std::string& payload) {
    if (payload.empty()) return "OK\n";
    return "OK " + payload + "\n";
}

std::string encode_error(const std::string& message) { return "ERR " + message + "\n"; }

bool response_is_ok(std::string_view response) {
    while (!response.empty() && (response.back() == '\n' || response.back() == '\r')) {
        response.remove_suffix(1);
    }
    if (response.size() < 2) return false;
    if (response[0] != 'O' || response[1] != 'K') return false;
    // Must be exactly "OK", or "OK" followed by a separator - never "OKAY".
    return response.size() == 2 || response[2] == ' ';
}

}  // namespace wisp::ipc

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace wisp::ipc {

inline constexpr const char* kDefaultSocketPath = "/run/wisp/wispd.sock";
inline constexpr const char* kDefaultConfigDir = "/etc/wisp/tunnels";

// A request is one line: "<VERB> [argument]".
// A response is one line: "OK [payload]" or "ERR <message>".
inline constexpr std::string_view kPing = "PING";
inline constexpr std::string_view kList = "LIST";
inline constexpr std::string_view kUp = "UP";
inline constexpr std::string_view kDown = "DOWN";
inline constexpr std::string_view kStatus = "STATUS";

struct Request {
    std::string verb;
    std::string argument;

    bool operator==(const Request&) const = default;
};

// Tunnel names are limited to [A-Za-z0-9_-], at most 15 characters (the
// kernel's IFNAMSIZ - 1), and may not start with '-' or '.'.
//
// Because the name is the *only* thing a client may specify, this function is
// the entire defence against path traversal: the helper builds a config path
// from the name, so anything that could escape the config directory or be read
// as a command-line option has to be rejected here.
bool is_valid_tunnel_name(std::string_view name);

// True only for the verbs this protocol defines.
//
// The helper checks this before dispatching, so a verb that is not recognised
// never reaches a response or a log entry.
bool is_valid_verb(std::string_view verb);

// Renders arbitrary bytes safely inside a single-line protocol message or log
// entry: anything outside printable ASCII becomes '?', and the result is
// length-capped.
//
// This is what allows a rejected verb to be reported for debugging without
// echoing a newline. A raw newline in a response would fabricate a second
// response line, and one in a log entry would let a caller split their own
// entry - which is how activity gets hidden from whoever reads the log.
std::string sanitize_for_display(std::string_view text, std::size_t max_length = 32);

Request parse_request(std::string_view line);
std::string encode_request(const Request& request);

// Pulls one newline-terminated request out of an accumulation buffer.
//
// A socket read can return any number of bytes, so the server has to hold
// partial input until a whole line arrives. Returns true and moves the complete
// line (newline included) into `line` when one is present, leaving any trailing
// bytes in `buffer` for the next call.
//
// `buffer` grows with whatever the peer sends, so the caller is responsible for
// capping its size: a peer that never sends a newline must not be able to make
// the server allocate without bound.
bool take_request_line(std::string& buffer, std::string& line);

std::string encode_ok(const std::string& payload = {});
std::string encode_error(const std::string& message);
bool response_is_ok(std::string_view response);

}  // namespace wisp::ipc

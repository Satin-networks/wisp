#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "wisp/ipc.hpp"

// Invariants under fuzzing:
//
//   1. An accepted tunnel name contains nothing but [A-Za-z0-9_-] and is at
//      most 15 characters, does not start with '-' or '.', and has no embedded
//      NUL. This is the property the helper's path building depends on.
//   2. parse_request and encode_request round-trip.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);

    if (wisp::ipc::is_valid_tunnel_name(text)) {
        if (text.empty() || text.size() > 15) __builtin_trap();
        if (text.front() == '-' || text.front() == '.') __builtin_trap();
        for (const char c : text) {
            const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                 (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!allowed) __builtin_trap();
        }
        if (text.find('\0') != std::string_view::npos) __builtin_trap();
    }

    const auto request = wisp::ipc::parse_request(text);
    const auto encoded = wisp::ipc::encode_request(request);
    const auto reparsed = wisp::ipc::parse_request(encoded);

    if (!(reparsed == request)) __builtin_trap();

    //   3. Sanitised output is always a single, printable line. Everything that
    //      gets quoted back into a response or a log goes through this, so a
    //      control character surviving here would be a protocol-injection
    //      vector rather than a cosmetic problem.
    const auto cleaned = wisp::ipc::sanitize_for_display(text);
    if (cleaned.size() > 32) __builtin_trap();
    for (const char c : cleaned) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte >= 0x7f) __builtin_trap();
    }

    //   4. Framing is lossless. The server feeds arbitrary socket reads through
    //      take_request_line, so the concatenation of every line it hands back
    //      plus whatever is left in the buffer must be exactly what went in, in
    //      the same order. A byte lost here is a request silently dropped; a
    //      byte duplicated is a request executed twice.
    std::string buffer(text);
    const std::string original = buffer;
    std::string line;
    std::string rebuilt;
    std::size_t lines = 0;
    while (wisp::ipc::take_request_line(buffer, line)) {
        if (line.empty() || line.back() != '\n') __builtin_trap();
        if (line.find('\n') != line.size() - 1) __builtin_trap();
        rebuilt += line;
        if (++lines > original.size() + 1) __builtin_trap();
    }
    rebuilt += buffer;
    if (rebuilt != original) __builtin_trap();
    if (buffer.find('\n') != std::string::npos) __builtin_trap();

    return 0;
}

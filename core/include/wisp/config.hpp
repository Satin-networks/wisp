#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wisp/types.hpp"

namespace wisp {

struct ParseError {
    std::size_t line = 0;  // 1-based, 0 for whole-file problems
    std::string message;

    bool operator==(const ParseError&) const = default;
};

struct ParseResult {
    // Present only when there were no errors.
    std::optional<Interface> interface;

    std::vector<ParseError> errors;

    // Non-fatal notes: unknown keys, hooks that Wisp will not run, and so on.
    std::vector<ParseError> warnings;

    bool ok() const { return interface.has_value(); }
};

// Parse a wg-quick style configuration ("[Interface]" / "[Peer]" sections).
//
// Strict: one bad key, port or CIDR fails the whole parse. A half-applied
// tunnel config leaks traffic without telling anyone, so refusing beats
// guessing.
ParseResult parse_config(std::string_view text);

// Render an Interface back to canonical wg-quick format. Round-trips through
// parse_config.
std::string serialize_config(const Interface& iface);

}  // namespace wisp

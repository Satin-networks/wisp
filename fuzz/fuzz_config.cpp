#include <cstddef>
#include <cstdint>
#include <string_view>

#include "wisp/config.hpp"

// Invariant under fuzzing:
//
//   anything parse_config accepts must survive serialize -> parse unchanged.
//
// That is the property the whole application leans on. If a profile parses into
// a struct that cannot be rendered back and re-parsed identically, then what we
// show the user and what we hand the kernel can disagree - and the difference
// is a tunnel configuration nobody asked for.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);

    const auto first = wisp::parse_config(text);
    if (!first.ok() || !first.interface) return 0;

    const auto serialized = wisp::serialize_config(*first.interface);
    const auto second = wisp::parse_config(serialized);

    if (!second.ok() || !second.interface) __builtin_trap();
    if (!(*second.interface == *first.interface)) __builtin_trap();

    return 0;
}

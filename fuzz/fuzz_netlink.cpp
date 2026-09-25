#include <cstddef>
#include <cstdint>

#include "wisp/netlink.hpp"

// The decoders walk nested attribute lists whose lengths come from the buffer
// itself. A malformed length is the classic way to turn a parse into an
// out-of-bounds read, so every entry point is thrown arbitrary bytes here.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    (void)wisp::nl::parse_family_id(data, size);
    (void)wisp::nl::parse_device(data, size);
    (void)wisp::nl::parse_link_index(data, size);
    (void)wisp::nl::parse_error(data, size);
    return 0;
}

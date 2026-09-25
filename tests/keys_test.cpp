#include <algorithm>
#include <string>
#include <vector>

#include "wisp/keys.hpp"
#include "wisp_test.hpp"

using namespace wisp;

namespace {

// A key with a known byte pattern, so we exercise the real base64 round trip
// without hand-typing encoded strings.
std::vector<unsigned char> pattern_key(unsigned char value) {
    return std::vector<unsigned char>(kKeyBytes, value);
}

}  // namespace

WISP_TEST(encode_produces_canonical_length) {
    const auto raw = pattern_key(0x01);
    const auto encoded = encode_key(raw.data(), raw.size());
    WISP_CHECK_EQ(encoded.size(), kKeyBase64Length);
    WISP_CHECK(encoded.back() == '=');
}

WISP_TEST(encode_decode_round_trip) {
    for (unsigned char value = 1; value <= 5; ++value) {
        const auto raw = pattern_key(value);
        const auto encoded = encode_key(raw.data(), raw.size());
        const auto decoded = decode_key(encoded);
        WISP_CHECK(decoded.has_value());
        if (decoded) {
            WISP_CHECK(std::equal(decoded->begin(), decoded->end(), raw.begin()));
        }
    }
}

WISP_TEST(decoded_keys_compare_equal) {
    const auto raw = pattern_key(0x2a);
    const auto a = encode_key(raw.data(), raw.size());
    const auto b = encode_key(raw.data(), raw.size());
    WISP_CHECK(keys_equal(a, b));
}

WISP_TEST(different_keys_do_not_compare_equal) {
    const auto one = pattern_key(0x11);
    const auto two = pattern_key(0x22);
    WISP_CHECK(!keys_equal(encode_key(one.data(), one.size()), encode_key(two.data(), two.size())));
}

// Invalid keys must be rejected rather than silently repaired: a key that
// fails to parse but gets written to the kernel anyway is a broken tunnel.
WISP_TEST(rejects_malformed_keys) {
    WISP_CHECK(!is_valid_key(""));
    WISP_CHECK(!is_valid_key("too-short"));
    WISP_CHECK(!is_valid_key(std::string(kKeyBase64Length, 'A')));  // 44 chars, no padding
    WISP_CHECK(!is_valid_key("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
    // Valid base64 alphabet, but not 32 bytes of payload.
    WISP_CHECK(!is_valid_key("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"));
}

WISP_TEST(generated_private_keys_are_valid_and_clamped) {
    const auto key = generate_private_key();
    WISP_CHECK(is_valid_key(key));

    const auto decoded = decode_key(key);
    WISP_CHECK(decoded.has_value());
    if (decoded) {
        // RFC 7748 clamping, which `wg genkey` also applies.
        WISP_CHECK(((*decoded)[0] & 0x07) == 0);
        WISP_CHECK(((*decoded)[31] & 0x80) == 0);
        WISP_CHECK(((*decoded)[31] & 0x40) == 0x40);
    }
}

WISP_TEST(generated_private_keys_are_unique) {
    WISP_CHECK(generate_private_key() != generate_private_key());
}

WISP_TEST(public_key_derivation_is_deterministic) {
    const auto private_key = generate_private_key();
    const auto first = public_key_from_private(private_key);
    const auto second = public_key_from_private(private_key);

    WISP_CHECK(is_valid_key(first));
    WISP_CHECK_EQ(first, second);
    WISP_CHECK(first != private_key);
}

WISP_TEST(public_key_derivation_rejects_invalid_input) {
    WISP_CHECK(public_key_from_private("not-a-key").empty());
    WISP_CHECK(public_key_from_private("").empty());
}

WISP_TEST(distinct_private_keys_give_distinct_public_keys) {
    WISP_CHECK(public_key_from_private(generate_private_key()) !=
               public_key_from_private(generate_private_key()));
}

// Key material must not be left in memory after it has been used.
WISP_TEST(secure_wipe_clears_a_secret) {
    auto secret = generate_private_key();
    WISP_CHECK(!secret.empty());
    secure_wipe(secret);
    WISP_CHECK(secret.empty());

    std::string empty;
    secure_wipe(empty);  // must be safe on an empty string
    WISP_CHECK(empty.empty());
}

WISP_TEST(preshared_keys_are_distinct_and_valid) {
    const auto a = generate_preshared_key();
    const auto b = generate_preshared_key();
    WISP_CHECK(is_valid_key(a));
    WISP_CHECK(is_valid_key(b));
    WISP_CHECK(a != b);
}

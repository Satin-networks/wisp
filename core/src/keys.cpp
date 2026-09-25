#include "wisp/keys.hpp"

#include <sodium.h>

#include <cstring>

namespace wisp {
namespace {

// sodium_init() must run before any other libsodium call. Wrapping it in a
// function-local static means it happens exactly once, on first use, and is
// thread-safe without any locking of our own.
bool ensure_init() {
    static const bool initialised = [] { return sodium_init() >= 0; }();
    return initialised;
}

}  // namespace

bool crypto_init() { return ensure_init(); }

std::optional<std::vector<unsigned char>> decode_key(std::string_view base64_key) {
    if (!ensure_init()) return std::nullopt;
    if (base64_key.size() != kKeyBase64Length) return std::nullopt;

    std::vector<unsigned char> out(kKeyBytes);
    std::size_t written = 0;
    const char* end = nullptr;

    // Passing nullptr as the ignore set makes the decoder strict: any
    // character outside the base64 alphabet is an error, rather than being
    // silently skipped.
    const int rc = sodium_base642bin(out.data(), out.size(), base64_key.data(), base64_key.size(),
                                     nullptr, &written, &end, sodium_base64_VARIANT_ORIGINAL);
    if (rc != 0) return std::nullopt;
    if (written != kKeyBytes) return std::nullopt;
    if (end != base64_key.data() + base64_key.size()) return std::nullopt;

    return out;
}

bool is_valid_key(std::string_view key) { return decode_key(key).has_value(); }

std::string encode_key(const unsigned char* bytes, std::size_t len) {
    if (!ensure_init() || bytes == nullptr || len == 0) return {};

    const std::size_t capacity = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(capacity, '\0');
    sodium_bin2base64(out.data(), capacity, bytes, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

std::string generate_private_key() {
    if (!ensure_init()) return {};

    unsigned char sk[crypto_scalarmult_curve25519_SCALARBYTES];
    randombytes_buf(sk, sizeof sk);

    // Clamp exactly as `wg genkey` does, so the key we hand out is in the
    // canonical form that a peer's tooling expects.
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    return encode_key(sk, sizeof sk);
}

std::string generate_preshared_key() {
    if (!ensure_init()) return {};

    unsigned char psk[kKeyBytes];
    randombytes_buf(psk, sizeof psk);
    return encode_key(psk, sizeof psk);
}

std::string public_key_from_private(std::string_view private_key) {
    const auto decoded = decode_key(private_key);
    if (!decoded) return {};

    unsigned char pk[crypto_scalarmult_curve25519_BYTES];
    if (crypto_scalarmult_curve25519_base(pk, decoded->data()) != 0) return {};
    return encode_key(pk, sizeof pk);
}

void secure_wipe(std::string& secret) {
    if (secret.empty()) return;
    if (ensure_init()) {
        sodium_memzero(secret.data(), secret.size());
    } else {
        volatile char* bytes = secret.data();
        for (std::size_t i = 0; i < secret.size(); ++i) bytes[i] = 0;
    }
    secret.clear();
}

bool keys_equal(std::string_view a, std::string_view b) {
    const auto da = decode_key(a);
    const auto db = decode_key(b);
    if (!da || !db) return false;
    return sodium_memcmp(da->data(), db->data(), kKeyBytes) == 0;
}

}  // namespace wisp

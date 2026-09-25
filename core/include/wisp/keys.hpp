#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wisp {

// WireGuard keys are 32 raw bytes rendered as 44 characters of padded base64.
inline constexpr std::size_t kKeyBytes = 32;
inline constexpr std::size_t kKeyBase64Length = 44;

// Initialise libsodium. Safe to call more than once; returns false if the
// library could not initialise, in which case no key operation is usable.
bool crypto_init();

// Decode a base64 key. Returns std::nullopt unless the input is valid base64
// that decodes to exactly kKeyBytes.
std::optional<std::vector<unsigned char>> decode_key(std::string_view base64_key);

bool is_valid_key(std::string_view key);

// Canonical padded base64 encoding of a raw key.
std::string encode_key(const unsigned char* bytes, std::size_t len);

// A fresh clamped Curve25519 private key.
std::string generate_private_key();

// Derive the public key for a private key. Returns an empty string when
// private_key is not a valid key.
std::string public_key_from_private(std::string_view private_key);

// Constant-time comparison, so that key comparisons do not leak timing.
bool keys_equal(std::string_view a, std::string_view b);

// A random WireGuard preshared key.
std::string generate_preshared_key();

// Overwrite a secret in place and clear it.
//
// Key material should not be left lying in freed heap memory where a later
// allocation - or a core dump - could pick it up. Uses libsodium's memory
// barrier so the compiler cannot optimise the overwrite away.
void secure_wipe(std::string& secret);

}  // namespace wisp

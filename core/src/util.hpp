#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace wisp::detail {

inline std::string_view trim(std::string_view s) {
    const auto not_space = [](char c) { return !std::isspace(static_cast<unsigned char>(c)); };
    while (!s.empty() && !not_space(s.front())) s.remove_prefix(1);
    while (!s.empty() && !not_space(s.back())) s.remove_suffix(1);
    return s;
}

// Split on `sep`, trimming each piece and dropping empty ones.
inline std::vector<std::string_view> split_list(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    while (pos <= s.size()) {
        const auto next = s.find(sep, pos);
        std::string_view piece =
            (next == std::string_view::npos) ? s.substr(pos) : s.substr(pos, next - pos);
        piece = trim(piece);
        if (!piece.empty()) out.push_back(piece);
        if (next == std::string_view::npos) break;
        pos = next + 1;
    }
    return out;
}

inline std::string ascii_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
    return out;
}

// Key names compare case-insensitively with separators ignored, so
// "PrivateKey", "private_key" and "privatekey" are all the same key.
inline std::string normalize_key_name(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '_' || c == '-') continue;
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

}  // namespace wisp::detail

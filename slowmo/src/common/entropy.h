#pragma once

#include <cstdint>
#include <cstddef>
#include <cmath>

namespace tenet {

/// Compute Shannon entropy (bits) of a byte buffer.
/// Returns 0.0 for empty input; maximum is 8.0 (perfectly uniform distribution).
/// Uses log2f for performance on float-precision paths.
inline float shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0f;

    uint32_t freq[256] = {};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    float entropy = 0.0f;
    const float n = static_cast<float>(len);
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        float p = static_cast<float>(freq[i]) / n;
        entropy -= p * std::log2f(p);
    }
    return entropy;
}

}  // namespace tenet

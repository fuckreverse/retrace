#pragma once
#include <cstdint>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
namespace tenet::platform {
inline int trailing_zeros(uint64_t value) {
#if defined(_MSC_VER)
    unsigned long index;
    _BitScanForward64(&index, value);
    return static_cast<int>(index);
#else
    return __builtin_ctzll(value);
#endif
}
inline int population_count(uint64_t value) {
#if defined(_MSC_VER)
    // No CPU feature assumption (POPCNT is not required on x64).
    int count = 0;
    while (value) { value &= value - 1; ++count; }
    return count;
#else
    return __builtin_popcountll(value);
#endif
}
inline uint64_t byte_swap64(uint64_t value) {
#if defined(_MSC_VER)
    return _byteswap_uint64(value);
#else
    return __builtin_bswap64(value);
#endif
}
inline uint32_t byte_swap32(uint32_t value) {
#if defined(_MSC_VER)
    return _byteswap_ulong(value);
#else
    return __builtin_bswap32(value);
#endif
}
inline uint16_t byte_swap16(uint16_t value) {
#if defined(_MSC_VER)
    return _byteswap_ushort(value);
#else
    return __builtin_bswap16(value);
#endif
}
inline void prefetch(const void* address, int, int) {
#if !defined(_MSC_VER)
    __builtin_prefetch(address, 0, 1);
#else
    (void)address;
#endif
}

} // namespace tenet::platform

#if defined(_MSC_VER)
#define TENET_EXPECT(condition, expected) (condition)
#else
#define TENET_EXPECT(condition, expected) __builtin_expect((condition), (expected))
#endif

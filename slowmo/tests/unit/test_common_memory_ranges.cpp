#include <catch2/catch_test_macros.hpp>
#include "common/memory_ranges.h"
#include <array>
#include <random>

using tenet::MemoryRanges;

TEST_CASE("MemoryRanges matches a byte oracle through overlapping updates",
          "[unit][memory_ranges][regression]") {
    MemoryRanges<uint64_t> ranges;
    std::array<uint64_t, 128> oracle{};
    std::mt19937 rng(42);
    for (int step = 0; step < 2000; ++step) {
        const uint64_t first = rng() % oracle.size();
        const uint64_t size = std::min<uint64_t>(1 + rng() % 32, oracle.size() - first);
        const uint64_t value = 1 + rng() % 63;
        switch (rng() % 3) {
        case 0:
            ranges.assign(first, size, value);
            for (auto i = first; i < first + size; ++i) oracle[i] = value;
            break;
        case 1:
            ranges.erase(first, size);
            for (auto i = first; i < first + size; ++i) oracle[i] = 0;
            break;
        default:
            ranges.update(first, size, [=](uint64_t& tags) { tags |= value; });
            for (auto i = first; i < first + size; ++i) oracle[i] |= value;
        }
        std::array<uint64_t, 128> actual{};
        ranges.visit(0, actual.size(), [&](auto a, auto b, auto value) {
            for (auto i = a; i <= b; ++i) actual[i] = value;
        });
        REQUIRE(actual == oracle);
    }
}

TEST_CASE("MemoryRanges handles empty and top-of-address-space intervals",
          "[unit][memory_ranges][regression]") {
    MemoryRanges<uint64_t> ranges;
    ranges.assign(4, 0, 1);
    REQUIRE(ranges.empty());
    ranges.assign(UINT64_MAX - 3, 8, 7); // saturates, never wraps
    ranges.erase(UINT64_MAX - 2, 1);
    uint64_t count = 0;
    ranges.visit(UINT64_MAX - 3, 4, [&](auto first, auto last, auto value) {
        REQUIRE(value == 7);
        count += last - first + 1;
    });
    REQUIRE(count == 3);
}

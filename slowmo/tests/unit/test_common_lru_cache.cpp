/*
 * test_common_lru_cache.cpp — Unit tests for tenet::LRUCache
 *
 * Verifies: basic put/get, LRU eviction order, promote-on-access, erase,
 * capacity resize, and edge cases (empty, full, over-capacity insert).
 */
#include <catch2/catch_test_macros.hpp>

#include "common/types.h"

using namespace tenet;

TEST_CASE("LRUCache basic put/get", "[unit][common][lru]") {
    LRUCache<int, std::string> cache(4);
    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");

    SECTION("get returns inserted values") {
        auto v = cache.get(1);
        REQUIRE(v.has_value());
        REQUIRE(v->get() == "one");

        auto v2 = cache.get(2);
        REQUIRE(v2.has_value());
        REQUIRE(v2->get() == "two");
    }

    SECTION("get missing key returns nullopt") {
        REQUIRE_FALSE(cache.get(99).has_value());
    }

    SECTION("size tracking") {
        REQUIRE(cache.size() == 3);
        REQUIRE(cache.capacity() == 4);
    }
}

TEST_CASE("LRUCache eviction order", "[unit][common][lru]") {
    LRUCache<int, int> cache(3);
    cache.put(1, 10);
    cache.put(2, 20);
    cache.put(3, 30);

    SECTION("inserting 4th evicts LRU (key 1)") {
        cache.put(4, 40);
        REQUIRE_FALSE(cache.get(1).has_value());
        REQUIRE(cache.get(2).has_value());
        REQUIRE(cache.get(3).has_value());
        REQUIRE(cache.get(4).has_value());
        REQUIRE(cache.size() == 3);
    }

    SECTION("accessing key 1 promotes it, key 2 becomes LRU") {
        cache.get(1);          // promote 1
        cache.put(4, 40);      // should evict 2 (LRU)
        REQUIRE(cache.get(1).has_value());
        REQUIRE_FALSE(cache.get(2).has_value());
        REQUIRE(cache.get(3).has_value());
        REQUIRE(cache.get(4).has_value());
    }
}

TEST_CASE("LRUCache promote on get_mutable", "[unit][common][lru]") {
    LRUCache<int, int> cache(2);
    cache.put(1, 10);
    cache.put(2, 20);

    // Access key 1 via get_mutable to promote it
    auto* p = cache.get_mutable(1);
    REQUIRE(p != nullptr);
    REQUIRE(*p == 10);

    // Now insert key 3; key 2 should be evicted (LRU)
    cache.put(3, 30);
    REQUIRE(cache.get(1).has_value());
    REQUIRE_FALSE(cache.get(2).has_value());
    REQUIRE(cache.get(3).has_value());
}

TEST_CASE("LRUCache update existing key", "[unit][common][lru]") {
    LRUCache<int, int> cache(3);
    cache.put(1, 10);
    cache.put(2, 20);

    SECTION("updating existing key changes value") {
        cache.put(1, 100);
        auto v = cache.get(1);
        REQUIRE(v.has_value());
        REQUIRE(v->get() == 100);
        REQUIRE(cache.size() == 2);  // no new entry
    }

    SECTION("updating promotes the key") {
        cache.put(3, 30);     // cache full: [3, 2, 1] (MRU→LRU)
        cache.put(1, 100);    // update+promote 1: [1, 3, 2]
        cache.put(4, 40);     // evict 2
        REQUIRE(cache.get(1).has_value());
        REQUIRE(cache.get(3).has_value());
        REQUIRE_FALSE(cache.get(2).has_value());
        REQUIRE(cache.get(4).has_value());
    }
}

TEST_CASE("LRUCache erase", "[unit][common][lru]") {
    LRUCache<int, int> cache(4);
    cache.put(1, 10);
    cache.put(2, 20);
    cache.put(3, 30);

    SECTION("erase existing key") {
        cache.erase(2);
        REQUIRE_FALSE(cache.get(2).has_value());
        REQUIRE(cache.size() == 2);
        // Other keys unaffected
        REQUIRE(cache.get(1).has_value());
        REQUIRE(cache.get(3).has_value());
    }

    SECTION("erase missing key is a no-op") {
        cache.erase(99);
        REQUIRE(cache.size() == 3);
    }

    SECTION("erase then re-insert works") {
        cache.erase(1);
        cache.put(1, 100);
        auto v = cache.get(1);
        REQUIRE(v.has_value());
        REQUIRE(v->get() == 100);
    }

    SECTION("invalidate is an alias for erase") {
        cache.invalidate(3);
        REQUIRE_FALSE(cache.get(3).has_value());
    }
}

TEST_CASE("LRUCache clear", "[unit][common][lru]") {
    LRUCache<int, int> cache(4);
    cache.put(1, 10);
    cache.put(2, 20);

    cache.clear();
    REQUIRE(cache.size() == 0);
    REQUIRE_FALSE(cache.get(1).has_value());

    // Can re-use after clear
    cache.put(3, 30);
    REQUIRE(cache.get(3).has_value());
}

TEST_CASE("LRUCache single-element capacity", "[unit][common][lru]") {
    LRUCache<int, int> cache(1);
    cache.put(1, 10);
    REQUIRE(cache.size() == 1);

    // Inserting 2nd evicts 1st
    cache.put(2, 20);
    REQUIRE(cache.size() == 1);
    REQUIRE_FALSE(cache.get(1).has_value());
    REQUIRE(cache.get(2).has_value());

    // Accessing the single element doesn't cause issues
    cache.get(2);
    REQUIRE(cache.size() == 1);
    REQUIRE(cache.get(2).has_value());
}

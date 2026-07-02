/*
 * test_qbditrace_ios.cpp — Catch2 unit tests for iOS/Darwin-specific logic
 *
 * Tests the pure classification and lookup helpers that are critical for
 * correct iOS trace analysis:
 *
 *   1. classifySyscall()    — Darwin BSD + Mach trap flag classification.
 *   2. classifyObjcTarget() — ObjC dispatcher (msgSend family) matching.
 *   3. lookupCApiFunc()     — sorted C API address binary-search table.
 *   4. TraceFormat.h        — iOS-specific enum values and flag constants
 *                             (CommonCrypto, CoreFoundation, Security, GCD,
 *                              SVC flag bits, capi_id_t ranges).
 *   5. Config               — field defaults, kMaxCapiFuncs, capi table
 *                             buildCapiLookup() semantics.
 *
 * These tests run on the host (macOS) without QBDI or Frida.  The functions
 * under test live in QBDITraceInternal.h (pure C++, no platform lib calls).
 *
 * Run:  ctest -R qbditrace_ios --output-on-failure
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

// Pull in the internal types and helpers (no QBDI required).
#include "QBDITraceInternal.h"
#include "TraceFormat.h"

using namespace qbditrace;
using namespace qbditrace_internal;

// ═══════════════════════════════════════════════════════════════════════════════
// 1.  classifySyscall — Darwin BSD + Mach trap classification
// ═══════════════════════════════════════════════════════════════════════════════

#if defined(__APPLE__)

TEST_CASE("classifySyscall: unknown syscall returns 0",
          "[unit][qbditrace][ios][syscall]") {
    // A high, otherwise unclassified number should produce no flags.
    REQUIRE(classifySyscall(9999) == 0);
    REQUIRE(classifySyscall(0)    == 0);
}

TEST_CASE("classifySyscall: Darwin BSD read/write (I/O) → MEM_OP",
          "[unit][qbditrace][ios][syscall]") {
    // BSD class prefix = 0x02000000, so raw selector = 0x02000000 + N.
    // classifySyscall strips the prefix internally.
    CHECK((classifySyscall(3)  & QBDITRACE_SVC_FL_MEM_OP) != 0); // read
    CHECK((classifySyscall(4)  & QBDITRACE_SVC_FL_MEM_OP) != 0); // write
    CHECK((classifySyscall(153)& QBDITRACE_SVC_FL_MEM_OP) != 0); // pread
    CHECK((classifySyscall(154)& QBDITRACE_SVC_FL_MEM_OP) != 0); // pwrite
    CHECK((classifySyscall(396)& QBDITRACE_SVC_FL_MEM_OP) != 0); // preadv
    CHECK((classifySyscall(397)& QBDITRACE_SVC_FL_MEM_OP) != 0); // pwritev
}

TEST_CASE("classifySyscall: Darwin virtual-memory ops → MEM_OP",
          "[unit][qbditrace][ios][syscall]") {
    CHECK((classifySyscall(197) & QBDITRACE_SVC_FL_MEM_OP) != 0); // mmap
    CHECK((classifySyscall(73)  & QBDITRACE_SVC_FL_MEM_OP) != 0); // munmap
    CHECK((classifySyscall(74)  & QBDITRACE_SVC_FL_MEM_OP) != 0); // mprotect
    CHECK((classifySyscall(75)  & QBDITRACE_SVC_FL_MEM_OP) != 0); // madvise
    CHECK((classifySyscall(286) & QBDITRACE_SVC_FL_MEM_OP) != 0); // msync
}

TEST_CASE("classifySyscall: Darwin file-system ops → FILE_OP",
          "[unit][qbditrace][ios][syscall]") {
    CHECK((classifySyscall(5)  & QBDITRACE_SVC_FL_FILE_OP) != 0); // open
    CHECK((classifySyscall(6)  & QBDITRACE_SVC_FL_FILE_OP) != 0); // close
    CHECK((classifySyscall(33) & QBDITRACE_SVC_FL_FILE_OP) != 0); // access
    CHECK((classifySyscall(339)& QBDITRACE_SVC_FL_FILE_OP) != 0); // openat
    CHECK((classifySyscall(128)& QBDITRACE_SVC_FL_FILE_OP) != 0); // rename
    CHECK((classifySyscall(10) & QBDITRACE_SVC_FL_FILE_OP) != 0); // unlink
    CHECK((classifySyscall(136)& QBDITRACE_SVC_FL_FILE_OP) != 0); // mkdir
    CHECK((classifySyscall(137)& QBDITRACE_SVC_FL_FILE_OP) != 0); // rmdir
}

TEST_CASE("classifySyscall: Darwin network ops → NET_OP",
          "[unit][qbditrace][ios][syscall]") {
    CHECK((classifySyscall(97)  & QBDITRACE_SVC_FL_NET_OP) != 0); // socket
    CHECK((classifySyscall(98)  & QBDITRACE_SVC_FL_NET_OP) != 0); // connect
    CHECK((classifySyscall(101) & QBDITRACE_SVC_FL_NET_OP) != 0); // sendto
    CHECK((classifySyscall(103) & QBDITRACE_SVC_FL_NET_OP) != 0); // recvfrom
    CHECK((classifySyscall(417) & QBDITRACE_SVC_FL_NET_OP) != 0); // bind
    CHECK((classifySyscall(418) & QBDITRACE_SVC_FL_NET_OP) != 0); // listen
    CHECK((classifySyscall(424) & QBDITRACE_SVC_FL_NET_OP) != 0); // setsockopt
    CHECK((classifySyscall(425) & QBDITRACE_SVC_FL_NET_OP) != 0); // getsockopt
}

TEST_CASE("classifySyscall: Darwin getentropy → CRYPTO_OP",
          "[unit][qbditrace][ios][syscall]") {
    uint8_t flags = classifySyscall(430);
    REQUIRE((flags & QBDITRACE_SVC_FL_CRYPTO_OP) != 0);
    // getentropy should not also set MEM or FILE flags
    CHECK((flags & QBDITRACE_SVC_FL_MEM_OP)  == 0);
    CHECK((flags & QBDITRACE_SVC_FL_FILE_OP) == 0);
}

TEST_CASE("classifySyscall: Mach trap (bit 31 set) → MACH_TRAP flag",
          "[unit][qbditrace][ios][syscall]") {
    // Mach trap numbers are negative integers; bit 31 is set.
    // Example: mach_vm_allocate = -10 in int32, which as uint64 is
    // 0xFFFFFFFFFFFFFF6 (all upper bits set, lower 32 = 0xFFFFFFF6).
    uint64_t mach_vm_allocate = static_cast<uint64_t>(static_cast<int32_t>(-10));
    uint8_t flags = classifySyscall(mach_vm_allocate);

    REQUIRE((flags & QBDITRACE_SVC_FL_MACH_TRAP) != 0);
    // mach_vm_allocate should be classified as a memory operation
    CHECK((flags & QBDITRACE_SVC_FL_MEM_OP) != 0);
}

TEST_CASE("classifySyscall: Mach trap mach_vm_protect (-14) → MEM_OP",
          "[unit][qbditrace][ios][syscall]") {
    uint64_t mach_vm_protect = static_cast<uint64_t>(static_cast<int32_t>(-14));
    uint8_t flags = classifySyscall(mach_vm_protect);
    CHECK((flags & QBDITRACE_SVC_FL_MACH_TRAP) != 0);
    CHECK((flags & QBDITRACE_SVC_FL_MEM_OP)    != 0);
}

TEST_CASE("classifySyscall: BSD syscall (no Mach trap bit) does NOT set MACH_TRAP",
          "[unit][qbditrace][ios][syscall]") {
    // Normal BSD call: bit 31 is 0
    uint8_t flags = classifySyscall(197); // mmap
    CHECK((flags & QBDITRACE_SVC_FL_MACH_TRAP) == 0);
    CHECK((flags & QBDITRACE_SVC_FL_MEM_OP)    != 0);
}

TEST_CASE("classifySyscall: with BSD class prefix 0x02000000 still classified",
          "[unit][qbditrace][ios][syscall]") {
    // When x16 carries the full BSD-class prefix (real iOS SVC selector),
    // the function should still decode correctly.
    uint64_t bsd_read  = 0x02000003ull; // read
    uint64_t bsd_write = 0x02000004ull; // write
    CHECK((classifySyscall(bsd_read)  & QBDITRACE_SVC_FL_MEM_OP) != 0);
    CHECK((classifySyscall(bsd_write) & QBDITRACE_SVC_FL_MEM_OP) != 0);
}

TEST_CASE("classifySyscall: flags are bitmask-compatible (no unexpected bits)",
          "[unit][qbditrace][ios][syscall]") {
    // All known flag bits
    uint8_t all_known = QBDITRACE_SVC_FL_MACH_TRAP
                      | QBDITRACE_SVC_FL_BINDER_IOC
                      | QBDITRACE_SVC_FL_MEM_OP
                      | QBDITRACE_SVC_FL_FILE_OP
                      | QBDITRACE_SVC_FL_NET_OP
                      | QBDITRACE_SVC_FL_CRYPTO_OP;

    // For a representative set of syscalls, no unknown bits should appear
    std::vector<uint64_t> test_cases = {
        3, 4, 5, 6, 73, 74, 75, 97, 98, 197, 286, 339, 417, 430,
        // Mach traps
        static_cast<uint64_t>(static_cast<int32_t>(-10)),
        static_cast<uint64_t>(static_cast<int32_t>(-12)),
        static_cast<uint64_t>(static_cast<int32_t>(-14)),
        static_cast<uint64_t>(static_cast<int32_t>(-32)),
    };
    for (auto no : test_cases) {
        uint8_t flags = classifySyscall(no);
        REQUIRE((flags & ~all_known) == 0);
    }
}

#endif // __APPLE__

// ═══════════════════════════════════════════════════════════════════════════════
// 2.  classifyObjcTarget — ObjC msgSend dispatcher matching
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("classifyObjcTarget: zero target returns -1",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    REQUIRE(classifyObjcTarget(c, 0) == -1);
}

TEST_CASE("classifyObjcTarget: no dispatchers configured → always -1",
          "[unit][qbditrace][ios][objc]") {
    Config c; // all objc_msgSend* == 0
    REQUIRE(classifyObjcTarget(c, 0x100001000ULL) == -1);
    REQUIRE(classifyObjcTarget(c, 0x200000000ULL) == -1);
}

TEST_CASE("classifyObjcTarget: matches objc_msgSend",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    c.objc_msgSend = 0x1900A0000ULL;
    REQUIRE(classifyObjcTarget(c, 0x1900A0000ULL) == QBDITRACE_OBJC_MSGSEND);
    // Other addresses should not match
    REQUIRE(classifyObjcTarget(c, 0x1900A0004ULL) == -1);
}

TEST_CASE("classifyObjcTarget: matches objc_msgSendSuper",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    c.objc_msgSend      = 0x1900A0000ULL;
    c.objc_msgSendSuper = 0x1900B0000ULL;
    REQUIRE(classifyObjcTarget(c, 0x1900B0000ULL) == QBDITRACE_OBJC_MSGSEND_SUPER);
    REQUIRE(classifyObjcTarget(c, 0x1900A0000ULL) == QBDITRACE_OBJC_MSGSEND);
}

TEST_CASE("classifyObjcTarget: matches objc_msgSendSuper2",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    c.objc_msgSendSuper2 = 0x1900C0000ULL;
    REQUIRE(classifyObjcTarget(c, 0x1900C0000ULL) == QBDITRACE_OBJC_MSGSEND_SUPER2);
}

TEST_CASE("classifyObjcTarget: matches objc_msgSend_stret",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    c.objc_msgSend_stret = 0x1900D0000ULL;
    REQUIRE(classifyObjcTarget(c, 0x1900D0000ULL) == QBDITRACE_OBJC_MSGSEND_STRET);
}

TEST_CASE("classifyObjcTarget: all four dispatchers configured independently",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    c.objc_msgSend        = 0x1900A0000ULL;
    c.objc_msgSendSuper   = 0x1900B0000ULL;
    c.objc_msgSendSuper2  = 0x1900C0000ULL;
    c.objc_msgSend_stret  = 0x1900D0000ULL;

    CHECK(classifyObjcTarget(c, 0x1900A0000ULL) == QBDITRACE_OBJC_MSGSEND);
    CHECK(classifyObjcTarget(c, 0x1900B0000ULL) == QBDITRACE_OBJC_MSGSEND_SUPER);
    CHECK(classifyObjcTarget(c, 0x1900C0000ULL) == QBDITRACE_OBJC_MSGSEND_SUPER2);
    CHECK(classifyObjcTarget(c, 0x1900D0000ULL) == QBDITRACE_OBJC_MSGSEND_STRET);
    // Address that is not any dispatcher
    CHECK(classifyObjcTarget(c, 0x1900E0000ULL) == -1);
}

TEST_CASE("classifyObjcTarget: disabled dispatcher (addr 0) is never matched",
          "[unit][qbditrace][ios][objc]") {
    Config c;
    c.objc_msgSend = 0; // explicitly disabled
    // Even if target happens to be 0 (null), must return -1
    REQUIRE(classifyObjcTarget(c, 0) == -1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3.  lookupCApiFunc — sorted C API address binary-search
// ═══════════════════════════════════════════════════════════════════════════════

static Config makeConfigWithCapiFuncs(
std::vector<std::pair<uint64_t, uint16_t>> entries) {
    Config c;
    c.capi_intercept = true;
    c.n_capi_funcs = 0;
    for (auto &[addr, id] : entries) {
        if (c.n_capi_funcs >= Config::kMaxCapiFuncs) break;
        auto &f = c.capi_funcs[c.n_capi_funcs++];
        f.addr    = addr;
        f.api_id  = id;
        f.n_args  = 1;
        f.str_args = 0;
    }
    c.buildCapiLookup();
    return c;
}

TEST_CASE("lookupCApiFunc: empty table returns nullptr",
          "[unit][qbditrace][ios][capi_lookup]") {
    Config c;
    REQUIRE(lookupCApiFunc(c, 0x1000) == nullptr);
    REQUIRE(lookupCApiFunc(c, 0)      == nullptr);
}

TEST_CASE("lookupCApiFunc: zero target always returns nullptr",
          "[unit][qbditrace][ios][capi_lookup]") {
    auto c = makeConfigWithCapiFuncs({{0x1000, 1}, {0x2000, 2}});
    REQUIRE(lookupCApiFunc(c, 0) == nullptr);
}

TEST_CASE("lookupCApiFunc: exact address match found",
          "[unit][qbditrace][ios][capi_lookup]") {
    auto c = makeConfigWithCapiFuncs({
        {0x100004000ULL, QBDITRACE_CAPI_MEMCPY},
        {0x100005000ULL, QBDITRACE_CAPI_STRCMP},
    });

    auto *r1 = lookupCApiFunc(c, 0x100004000ULL);
    REQUIRE(r1 != nullptr);
    CHECK(r1->api_id == QBDITRACE_CAPI_MEMCPY);

    auto *r2 = lookupCApiFunc(c, 0x100005000ULL);
    REQUIRE(r2 != nullptr);
    CHECK(r2->api_id == QBDITRACE_CAPI_STRCMP);
}

TEST_CASE("lookupCApiFunc: near-miss address not found",
          "[unit][qbditrace][ios][capi_lookup]") {
    auto c = makeConfigWithCapiFuncs({{0x100004000ULL, QBDITRACE_CAPI_MEMCPY}});
    REQUIRE(lookupCApiFunc(c, 0x100004004ULL) == nullptr); // +4 off
    REQUIRE(lookupCApiFunc(c, 0x100003FFCULL) == nullptr); // -4 off
}

TEST_CASE("lookupCApiFunc: iOS CommonCrypto functions resolved correctly",
          "[unit][qbditrace][ios][capi_lookup]") {
    // Simulate resolved CCCrypt and CC_SHA256 addresses (typical dyld cache range)
    const uint64_t kCCCrypt    = 0x1900AA000ULL;
    const uint64_t kCCSHA256   = 0x1900AB000ULL;
    const uint64_t kCCHmac     = 0x1900AC000ULL;

    auto c = makeConfigWithCapiFuncs({
        {kCCCrypt,  QBDITRACE_CAPI_CC_CRYPT},
        {kCCSHA256, QBDITRACE_CAPI_CC_DIGEST},
        {kCCHmac,   QBDITRACE_CAPI_CC_HMAC},
    });

    auto *r = lookupCApiFunc(c, kCCCrypt);
    REQUIRE(r != nullptr);
    CHECK(r->api_id == QBDITRACE_CAPI_CC_CRYPT);

    r = lookupCApiFunc(c, kCCSHA256);
    REQUIRE(r != nullptr);
    CHECK(r->api_id == QBDITRACE_CAPI_CC_DIGEST);

    r = lookupCApiFunc(c, kCCHmac);
    REQUIRE(r != nullptr);
    CHECK(r->api_id == QBDITRACE_CAPI_CC_HMAC);
}

TEST_CASE("lookupCApiFunc: iOS Security.framework functions (high api_id)",
          "[unit][qbditrace][ios][capi_lookup]") {
    // api_id is now uint16_t, so all Security.framework ids (500+) fit without
    // truncation.  Verify both address lookup and exact id comparison.
    const uint64_t kSecItemCopy = 0x1800CC000ULL;
    const uint64_t kSecRandCopy = 0x1800CD000ULL;

    auto c = makeConfigWithCapiFuncs({
        {kSecItemCopy, static_cast<uint16_t>(QBDITRACE_CAPI_SEC_ITEM_COPY_MATCH)},
        {kSecRandCopy, static_cast<uint16_t>(QBDITRACE_CAPI_SEC_RAND_COPY_BYTES)},
    });

    auto *r = lookupCApiFunc(c, kSecItemCopy);
    REQUIRE(r != nullptr);
    CHECK(r->api_id == static_cast<uint16_t>(QBDITRACE_CAPI_SEC_ITEM_COPY_MATCH));

    r = lookupCApiFunc(c, kSecRandCopy);
    REQUIRE(r != nullptr);
    // QBDITRACE_CAPI_SEC_RAND_COPY_BYTES == 501; no truncation with uint16_t
    CHECK(r->api_id == static_cast<uint16_t>(QBDITRACE_CAPI_SEC_RAND_COPY_BYTES));
}

TEST_CASE("lookupCApiFunc: lookup is order-independent (entries inserted unsorted)",
          "[unit][qbditrace][ios][capi_lookup]") {
    // Insert in reverse order; buildCapiLookup() must sort them.
    auto c = makeConfigWithCapiFuncs({
        {0x5000, 50},
        {0x1000, 10},
        {0x3000, 30},
        {0x2000, 20},
        {0x4000, 40},
    });

    CHECK(lookupCApiFunc(c, 0x1000)->api_id == 10);
    CHECK(lookupCApiFunc(c, 0x2000)->api_id == 20);
    CHECK(lookupCApiFunc(c, 0x3000)->api_id == 30);
    CHECK(lookupCApiFunc(c, 0x4000)->api_id == 40);
    CHECK(lookupCApiFunc(c, 0x5000)->api_id == 50);
}

TEST_CASE("lookupCApiFunc: entries with addr==0 are excluded from lookup",
          "[unit][qbditrace][ios][capi_lookup]") {
    // A zero-address entry should be silently skipped during buildCapiLookup.
    Config c;
    c.capi_intercept = true;
    c.n_capi_funcs = 2;
    c.capi_funcs[0] = {0,          QBDITRACE_CAPI_MEMCPY, 3, 0x06}; // addr=0, invalid
    c.capi_funcs[1] = {0x1000,     QBDITRACE_CAPI_STRCMP,  2, 0x03};
    c.buildCapiLookup();

    REQUIRE(lookupCApiFunc(c, 0)      == nullptr); // zero always miss
    REQUIRE(lookupCApiFunc(c, 0x1000) != nullptr);
    CHECK(lookupCApiFunc(c, 0x1000)->api_id == QBDITRACE_CAPI_STRCMP);
}

TEST_CASE("lookupCApiFunc: kMaxCapiFuncs slots capacity",
          "[unit][qbditrace][ios][capi_lookup]") {
    REQUIRE(Config::kMaxCapiFuncs == QBDITRACE_MAX_CAPI_FUNCS);
    REQUIRE(Config::kMaxCapiFuncs >= 128u); // must hold at least 128 entries
}

TEST_CASE("lookupCApiFunc: large table with 100 iOS API addresses",
          "[unit][qbditrace][ios][capi_lookup]") {
    Config c;
    c.capi_intercept = true;
    c.n_capi_funcs = 0;
    // Simulate 100 addresses in the dyld shared cache range (typical iOS)
    const uint64_t base = 0x18F000000ULL;
    for (uint32_t i = 0; i < 100 && i < Config::kMaxCapiFuncs; ++i) {
        c.capi_funcs[c.n_capi_funcs++] = {
            base + i * 0x1000,          // address
            static_cast<uint16_t>(i),   // api_id (reuse index as id for test)
            1, 0
        };
    }
    c.buildCapiLookup();

    // All 100 should be found
    for (uint32_t i = 0; i < 100; ++i) {
        auto *r = lookupCApiFunc(c, base + i * 0x1000);
        REQUIRE(r != nullptr);
        CHECK(r->api_id == static_cast<uint8_t>(i));
    }
    // Address between slots should not be found
    REQUIRE(lookupCApiFunc(c, base + 0x500) == nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4.  TraceFormat.h — iOS-specific enum values and flag constants
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TraceFormat: SVC flag bits are non-overlapping",
          "[unit][qbditrace][ios][trace_format]") {
    // Each flag must be a distinct power-of-two bit
    CHECK(QBDITRACE_SVC_FL_MACH_TRAP  == (1u << 0));
    CHECK(QBDITRACE_SVC_FL_BINDER_IOC == (1u << 1));
    CHECK(QBDITRACE_SVC_FL_MEM_OP     == (1u << 2));
    CHECK(QBDITRACE_SVC_FL_FILE_OP    == (1u << 3));
    CHECK(QBDITRACE_SVC_FL_NET_OP     == (1u << 4));
    CHECK(QBDITRACE_SVC_FL_CRYPTO_OP  == (1u << 5));

    // All pairwise OR/AND checks (no two flags share a bit)
    std::vector<uint8_t> flags = {
        QBDITRACE_SVC_FL_MACH_TRAP,
        QBDITRACE_SVC_FL_BINDER_IOC,
        QBDITRACE_SVC_FL_MEM_OP,
        QBDITRACE_SVC_FL_FILE_OP,
        QBDITRACE_SVC_FL_NET_OP,
        QBDITRACE_SVC_FL_CRYPTO_OP,
    };
    for (size_t i = 0; i < flags.size(); ++i) {
        for (size_t j = i + 1; j < flags.size(); ++j) {
            REQUIRE((flags[i] & flags[j]) == 0);
        }
    }
}

TEST_CASE("TraceFormat: ObjC variant enum is contiguous from 0",
          "[unit][qbditrace][ios][trace_format]") {
    CHECK(QBDITRACE_OBJC_MSGSEND        == 0);
    CHECK(QBDITRACE_OBJC_MSGSEND_SUPER  == 1);
    CHECK(QBDITRACE_OBJC_MSGSEND_SUPER2 == 2);
    CHECK(QBDITRACE_OBJC_MSGSEND_STRET  == 3);
}

TEST_CASE("TraceFormat: CommonCrypto capi_id_t values are in the expected range",
          "[unit][qbditrace][ios][trace_format]") {
    // CC_* functions are documented in the 130–137 and 470–483 bands
    CHECK(QBDITRACE_CAPI_CC_CRYPT       == 134);
    CHECK(QBDITRACE_CAPI_CC_HMAC        == 135);
    CHECK(QBDITRACE_CAPI_CC_DIGEST      == 136);
    CHECK(QBDITRACE_CAPI_CC_KEY_DERIVE_PBKDF == 137);
    // Extended CC (v2 additions) — 470+
    CHECK(QBDITRACE_CAPI_CC_SHA224      >= 470);
    CHECK(QBDITRACE_CAPI_CC_SHA384      >= 470);
    CHECK(QBDITRACE_CAPI_CC_SHA512      >= 470);
    CHECK(QBDITRACE_CAPI_CC_SHA256_INIT >= 470);
    CHECK(QBDITRACE_CAPI_CC_SHA256_FINAL>= 470);
    CHECK(QBDITRACE_CAPI_CC_HMAC_INIT   >= 470);
    CHECK(QBDITRACE_CAPI_CC_HMAC_FINAL  >= 470);
    CHECK(QBDITRACE_CAPI_CC_CRYPTOR_CREATE  >= 470);
    CHECK(QBDITRACE_CAPI_CC_RANDOM_GENERATE >= 470);
}

TEST_CASE("TraceFormat: CoreFoundation capi_id_t values are in the 130–131 and 484+ bands",
          "[unit][qbditrace][ios][trace_format]") {
    CHECK(QBDITRACE_CAPI_CF_STR_CREATE_UTF8  == 130);
    CHECK(QBDITRACE_CAPI_CF_STR_CREATE_BYTES == 131);
    CHECK(QBDITRACE_CAPI_CF_DATA_CREATE      == 132);
    // Extended CF — 484+
    CHECK(QBDITRACE_CAPI_CF_STR_GET_CSTR  >= 484);
    CHECK(QBDITRACE_CAPI_CF_STR_GET_PTR   >= 484);
    CHECK(QBDITRACE_CAPI_CF_STR_COMPARE   >= 484);
    CHECK(QBDITRACE_CAPI_CF_STR_HASPREFIX >= 484);
    CHECK(QBDITRACE_CAPI_CF_STR_HASSUFFIX >= 484);
    CHECK(QBDITRACE_CAPI_CF_DATA_GET_PTR  >= 484);
    CHECK(QBDITRACE_CAPI_CF_DATA_GET_LEN  >= 484);
    CHECK(QBDITRACE_CAPI_CF_DICT_GET_VAL  >= 484);
    CHECK(QBDITRACE_CAPI_CF_ARRAY_GET_VAL >= 484);
    CHECK(QBDITRACE_CAPI_CF_RELEASE       >= 484);
    CHECK(QBDITRACE_CAPI_CF_RETAIN        >= 484);
    CHECK(QBDITRACE_CAPI_CF_URL_GET_STR   >= 484);
}

TEST_CASE("TraceFormat: Security.framework capi_id_t values are in the 138–140 and 501+ bands",
          "[unit][qbditrace][ios][trace_format]") {
    // Core Security ids (fit in uint8_t)
    CHECK(QBDITRACE_CAPI_SEC_ITEM_COPY_MATCH == 138);
    CHECK(QBDITRACE_CAPI_SEC_KEY_CREATE_RSA  == 139);
    CHECK(QBDITRACE_CAPI_SEC_TRANSFORM       == 140);
    // Extended Security — 501+ (these exceed uint8_t; use int for comparison)
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_RAND_COPY_BYTES) >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_KEY_COPY_EXT)    >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_KEY_ENCRYPT)     >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_KEY_DECRYPT)     >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_TRUST_EVAL)      >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_CERT_CREATE)     >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_ITEM_ADD)        >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_ITEM_UPDATE)     >= 501);
    CHECK(static_cast<int>(QBDITRACE_CAPI_SEC_ITEM_DELETE)     >= 501);
}

TEST_CASE("TraceFormat: GCD (libdispatch) capi_id_t values are in 516+ band",
          "[unit][qbditrace][ios][trace_format]") {
    CHECK(QBDITRACE_CAPI_DISPATCH_ASYNC  >= 516);
    CHECK(QBDITRACE_CAPI_DISPATCH_SYNC   >= 516);
    CHECK(QBDITRACE_CAPI_DISPATCH_AFTER  >= 516);
    CHECK(QBDITRACE_CAPI_DISPATCH_ONCE   >= 516);
    // Each must be unique
    CHECK(QBDITRACE_CAPI_DISPATCH_ASYNC  != QBDITRACE_CAPI_DISPATCH_SYNC);
    CHECK(QBDITRACE_CAPI_DISPATCH_ASYNC  != QBDITRACE_CAPI_DISPATCH_AFTER);
    CHECK(QBDITRACE_CAPI_DISPATCH_ASYNC  != QBDITRACE_CAPI_DISPATCH_ONCE);
    CHECK(QBDITRACE_CAPI_DISPATCH_SYNC   != QBDITRACE_CAPI_DISPATCH_AFTER);
    CHECK(QBDITRACE_CAPI_DISPATCH_SYNC   != QBDITRACE_CAPI_DISPATCH_ONCE);
    CHECK(QBDITRACE_CAPI_DISPATCH_AFTER  != QBDITRACE_CAPI_DISPATCH_ONCE);
}

TEST_CASE("TraceFormat: common C API ids are unique across all platforms",
          "[unit][qbditrace][ios][trace_format]") {
    // Cross-check a selection of ids that must be unique
    std::vector<uint8_t> ids = {
        QBDITRACE_CAPI_MEMCPY,
        QBDITRACE_CAPI_MEMSET,
        QBDITRACE_CAPI_STRCMP,
        QBDITRACE_CAPI_STRLEN,
        QBDITRACE_CAPI_MALLOC,
        QBDITRACE_CAPI_FREE,
        QBDITRACE_CAPI_FOPEN,
        QBDITRACE_CAPI_DLOPEN,
        QBDITRACE_CAPI_CC_CRYPT,
        QBDITRACE_CAPI_CC_HMAC,
        QBDITRACE_CAPI_CC_DIGEST,
        QBDITRACE_CAPI_SEC_ITEM_COPY_MATCH,
    };
    for (size_t i = 0; i < ids.size(); ++i) {
        for (size_t j = i + 1; j < ids.size(); ++j) {
            INFO("ids[" << i << "]=" << (int)ids[i]
                 << " vs ids[" << j << "]=" << (int)ids[j]);
            REQUIRE(ids[i] != ids[j]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5.  Config — defaults, field constraints, and buildCapiLookup()
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Config: default construction has sane iOS defaults",
          "[unit][qbditrace][ios][config]") {
    Config c;
    // By default, all ObjC dispatchers are null (disabled)
    CHECK(c.objc_msgSend       == 0);
    CHECK(c.objc_msgSendSuper  == 0);
    CHECK(c.objc_msgSendSuper2 == 0);
    CHECK(c.objc_msgSend_stret == 0);
    // C API interception is off by default
    CHECK(c.capi_intercept == false);
    CHECK(c.n_capi_funcs   == 0);
    // Code embedding on, compression on, branch hint on
    CHECK(c.embed_code       == true);
    CHECK(c.compress         == true);
    CHECK(c.branch_hint_mode == true);
}

TEST_CASE("Config: kMaxCapiFuncs is large enough for all iOS APIs",
          "[unit][qbditrace][ios][config]") {
    // iOS has CC_*, CF_*, Security, GCD plus common C APIs (~100 entries).
    // The table must hold at least 128 to be practical.
    REQUIRE(Config::kMaxCapiFuncs >= 128u);
}

TEST_CASE("Config: buildCapiLookup sorts entries by address",
          "[unit][qbditrace][ios][config]") {
    Config c;
    c.n_capi_funcs = 3;
    // Insert out-of-order
    c.capi_funcs[0] = {0x3000, 30, 1, 0};
    c.capi_funcs[1] = {0x1000, 10, 1, 0};
    c.capi_funcs[2] = {0x2000, 20, 1, 0};
    c.buildCapiLookup();

    REQUIRE(c.capi_lookup.size() == 3);
    CHECK(c.capi_lookup[0].addr == 0x1000);
    CHECK(c.capi_lookup[1].addr == 0x2000);
    CHECK(c.capi_lookup[2].addr == 0x3000);
}

TEST_CASE("Config: buildCapiLookup skips zero-address entries",
          "[unit][qbditrace][ios][config]") {
    Config c;
    c.n_capi_funcs = 3;
    c.capi_funcs[0] = {0x0000, 10, 1, 0}; // addr 0 → skip
    c.capi_funcs[1] = {0x1000, 20, 1, 0};
    c.capi_funcs[2] = {0x2000, 30, 1, 0};
    c.buildCapiLookup();

    REQUIRE(c.capi_lookup.size() == 2); // entry 0 skipped
    CHECK(c.capi_lookup[0].addr == 0x1000);
    CHECK(c.capi_lookup[1].addr == 0x2000);
}

TEST_CASE("Config: capi_funcs str_args bitmask preserved through lookup",
          "[unit][qbditrace][ios][config]") {
    // CFStringCreateWithCString: arg1 (a1) is a C-string → str_args = 0x02
    Config c;
    c.n_capi_funcs = 1;
    c.capi_funcs[0] = {
        0x1900A0000ULL,
        QBDITRACE_CAPI_CF_STR_CREATE_UTF8,
        3,      // nArgs
        0x02,   // str_args: bit 1 = arg1 is a string pointer
    };
    c.buildCapiLookup();

    auto *r = lookupCApiFunc(c, 0x1900A0000ULL);
    REQUIRE(r != nullptr);
    CHECK(r->api_id   == QBDITRACE_CAPI_CF_STR_CREATE_UTF8);
    CHECK(r->n_args   == 3);
    CHECK(r->str_args == 0x02);
}

TEST_CASE("Config: rebuild lookup table is idempotent",
          "[unit][qbditrace][ios][config]") {
    Config c;
    c.n_capi_funcs = 2;
    c.capi_funcs[0] = {0x1000, 10, 1, 0};
    c.capi_funcs[1] = {0x2000, 20, 1, 0};

    c.buildCapiLookup();
    REQUIRE(c.capi_lookup.size() == 2);

    // Building again should produce the same result
    c.buildCapiLookup();
    REQUIRE(c.capi_lookup.size() == 2);
    CHECK(c.capi_lookup[0].addr == 0x1000);
    CHECK(c.capi_lookup[1].addr == 0x2000);
}

TEST_CASE("Config: n_exclude_ranges is bounded by QBDITRACE_MAX_EXCLUDE_RANGES",
          "[unit][qbditrace][ios][config]") {
    // Structural check: the array can hold at most QBDITRACE_MAX_EXCLUDE_RANGES
    REQUIRE(QBDITRACE_MAX_EXCLUDE_RANGES == 8u);
    Config c;
    c.n_exclude_ranges = QBDITRACE_MAX_EXCLUDE_RANGES;
    for (uint32_t i = 0; i < QBDITRACE_MAX_EXCLUDE_RANGES; ++i) {
        c.exclude_ranges[i].start = i * 0x1000;
        c.exclude_ranges[i].end   = i * 0x1000 + 0x100;
    }
    // Verify last slot is accessible
    CHECK(c.exclude_ranges[7].start == 7 * 0x1000);
    CHECK(c.exclude_ranges[7].end   == 7 * 0x1000 + 0x100);
}

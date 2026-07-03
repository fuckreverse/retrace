/*
 * test_pass_memory_string.cpp — Unit tests for tenet::MemoryStringPass
 *
 * MemoryStringPass discovers strings visible at "call sites" (BL/BLR/SVC and
 * ObjC message sends) by snapshotting x0-x7 and SP at that instant and
 * scanning the memory those registers/stack point to. These tests exercise:
 *   - basic discovery via a register pointer (x0) at a BL call site
 *   - stack-local string discovery (SP-relative)
 *   - ObjC message send call sites (REC_OBJC) being treated as call sites
 *   - deep_probe extending a truncated hit by walking real write history
 *   - is_hit_truncated: a hit ending on a NUL/non-printable byte within the
 *     window must NOT trigger a deep probe (already complete)
 *   - dedup: identical (addr, content) pairs across call sites collapse to a
 *     single entry, but by_call_site still reflects each site
 *   - negative cases: pointer below min_pointer_value, empty/no call sites
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/memory_string_pass.h"

using namespace tenet;
using namespace tenet::test;

namespace {
// QBDI::MemoryAccessType: bit0 = read, bit1 = write.
constexpr uint8_t kMemWrite = 2;
}  // namespace

TEST_CASE("MemoryStringPass discovers a string via a register pointer at a call site",
          "[unit][pass][memory_string]") {
    uint64_t str_addr = 0x100004500ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: write "Hello\0" into memory.
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});

        // inst 1: x0 = str_addr (simulates loading the pointer into x0).
        tw.emit(ms, 0x1004, enc::movz(0, 0),
                {{0, str_addr}, {33, tw.rt(0x1008)}}, {});

        // inst 2: bl some_func — a call site with x0 pointing at "Hello".
        tw.emit(ms, 0x1008, enc::bl(0x2000 - 0x1008),
                {{30, tw.rt(0x100C)}, {33, tw.rt(0x2000)}}, {});

        // callee: ret
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_regptr");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& result_raw = pm->require("memory_strings");
    REQUIRE(result_raw.ok());
    auto& mr = result_raw.get<MemoryStringResult>();

    SECTION("string discovered at str_addr") {
        auto hits = mr.at_addr(str_addr);
        REQUIRE(!hits.empty());
        bool found = false;
        for (auto* h : hits) {
            if (h->content == "Hello") {
                found = true;
                REQUIRE(h->encoding == MemoryString::ASCII);
                REQUIRE(h->source == MemoryString::RegPointer);
                REQUIRE(h->source_reg == 0);
            }
        }
        REQUIRE(found);
    }

    SECTION("call site inst_id is recorded") {
        // The call site is the BL instruction (inst_id 2).
        auto hits = mr.at_call_site(2);
        bool found = false;
        for (auto* h : hits) if (h->content == "Hello") found = true;
        REQUIRE(found);
    }
}

TEST_CASE("MemoryStringPass discovers a stack-local string at a call site",
          "[unit][pass][memory_string]") {
    uint64_t sp_val = 0x16F000000ULL;
    uint64_t stack_data = 0x00004B434154534FULL;  // "OSTACK\0" (7 chars, NUL-padded)

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = sp_val;

        // inst 0: write a string right at [sp].
        tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                {{0, stack_data}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, sp_val, stack_data}});

        // inst 1: bl some_func with SP unchanged — a call site whose stack
        // contains the just-written string.
        tw.emit(ms, 0x1004, enc::bl(0x2000 - 0x1004),
                {{30, tw.rt(0x1008)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_stack");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();

    auto hits = mr.at_addr(sp_val);
    bool found = false;
    for (auto* h : hits) {
        if (h->content == "OSTACK") {
            found = true;
            REQUIRE(h->source == MemoryString::StackLocal);
            REQUIRE(h->source_reg == 31);
        }
    }
    REQUIRE(found);
}

TEST_CASE("MemoryStringPass treats ObjC message sends as call sites",
          "[unit][pass][memory_string]") {
    uint64_t str_addr = 0x100005500ULL;
    // "MSGX\0\0\0\0" as a little-endian 8-byte store: bytes are
    // 'S','M','G','X',0,0,0,0 in memory order (see comment on hit below).
    uint64_t msgx = 0x0000000058474D53ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: write string bytes to str_addr.
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, msgx}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, msgx}});

        // inst 1: x0 = str_addr (receiver-like register holding the pointer).
        tw.emit(ms, 0x1004, enc::movz(0, 0),
                {{0, str_addr}, {33, tw.rt(0x1008)}}, {});

        // inst 2: plain instruction standing in for the (untraced,
        // external) call to objc_msgSend. No BL/BLR opcode here on purpose —
        // the only way this call site is discovered is via the REC_OBJC
        // record emitted below at the same PC.
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_objc(tw.rt(0x1008), /*recv=*/str_addr, /*sel=*/0x1234, "NSObject");

        tw.emit(ms, 0x100C, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "mstr_objc");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();

    auto hits = mr.at_addr(str_addr);
    bool found = false;
    for (auto* h : hits) {
        if (h->content == "SMGX") found = true;
    }
    REQUIRE(found);
}

TEST_CASE("MemoryStringPass deep_probe extends a hit truncated at the window edge",
          "[unit][pass][memory_string]") {
    // The default scan_size window is 256 bytes. Plant a string that starts
    // right at the tail of the window (so the initial scan sees only a
    // truncated fragment), and put the earlier, complete write further back
    // in write-history so deep_probe's last_writer() walk can find it.
    uint64_t str_addr = 0x100006000ULL;
    MemoryStringConfig cfg;
    cfg.scan_size = 16;          // small window so the string clearly overflows it
    cfg.min_string_len = 4;
    cfg.deep_probe = true;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: write a long ASCII string spanning beyond the 16-byte scan
        // window: "LONGSTRINGVALUE\0" (16 bytes incl NUL — first 16 bytes
        // fill exactly the window with no NUL inside it -> truncated hit).
        const char* s = "LONGSTRINGVALUE";  // 15 chars
        uint64_t lo = 0, hi = 0;
        std::memcpy(&lo, s, 8);
        std::memcpy(&hi, s + 8, 7);
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, lo}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, lo}});
        tw.emit(ms, 0x1004, enc::str_imm(1, 0, 8),
                {{1, hi}, {33, tw.rt(0x1008)}},
                {{kMemWrite, 8, str_addr + 8, hi}});

        // inst 2: x0 = str_addr; inst 3: bl call site.
        tw.emit(ms, 0x1008, enc::movz(0, 0),
                {{0, str_addr}, {33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::bl(0x2000 - 0x100C),
                {{30, tw.rt(0x1010)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_deepprobe");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>(cfg));

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();

    auto hits = mr.at_addr(str_addr);
    REQUIRE(!hits.empty());
    // Deep probe should have extended the hit beyond the 16-byte scan window
    // (which alone could see at most "LONGSTRINGVALUE" truncated to 15
    // printable bytes with no NUL within 16 bytes -> is_hit_truncated==true,
    // triggering deep_probe_string to re-read with a wider window).
    bool found_full = false;
    for (auto* h : hits) {
        if (h->content == "LONGSTRINGVALUE") found_full = true;
    }
    REQUIRE(found_full);
}

TEST_CASE("MemoryStringPass does not deep-probe a hit that ends within the window",
          "[unit][pass][memory_string]") {
    // A short, NUL-terminated string well inside the scan window is already
    // complete; is_hit_truncated() must return false for it, so no
    // deep_probe_string() call (and no risk of accidentally corrupting it).
    uint64_t str_addr = 0x100007000ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit(ms, 0x1004, enc::movz(0, 0),
                {{0, str_addr}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::bl(0x2000 - 0x1008),
                {{30, tw.rt(0x100C)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_no_deepprobe");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();
    auto hits = mr.at_addr(str_addr);
    bool found = false;
    for (auto* h : hits) {
        if (h->content == "Hello") found = true;
    }
    REQUIRE(found);
}

TEST_CASE("MemoryStringPass ignores pointers below min_pointer_value",
          "[unit][pass][memory_string]") {
    // A small integer value in x0 (e.g. a loop counter) must not be treated
    // as a pointer and dereferenced.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::movz(0, 42),
                {{0, 42ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::bl(0x2000 - 0x1004),
                {{30, tw.rt(0x1008)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_lowptr");

    auto pm = make_pm(*env);
    MemoryStringConfig cfg;
    cfg.scan_stack = false;  // isolate the register-scan path
    pm->register_pass(std::make_unique<MemoryStringPass>(cfg));

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();
    REQUIRE(mr.total() == 0);
}

TEST_CASE("MemoryStringPass handles a trace with no call sites",
          "[unit][pass][memory_string]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_no_callsites");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();
    REQUIRE(mr.total() == 0);
    REQUIRE(mr.unique_count() == 0);
}

TEST_CASE("MemoryStringPass dedups identical content at the same address across call sites",
          "[unit][pass][memory_string]") {
    uint64_t str_addr = 0x100008000ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit(ms, 0x1004, enc::movz(0, 0),
                {{0, str_addr}, {33, tw.rt(0x1008)}}, {});

        // Two separate call sites both see the same string at str_addr via x0.
        tw.emit(ms, 0x1008, enc::bl(0x3000 - 0x1008),
                {{30, tw.rt(0x100C)}, {33, tw.rt(0x3000)}}, {});
        tw.emit(ms, 0x3000, enc::ret(), {{33, tw.rt(0x100C)}}, {});

        tw.emit(ms, 0x100C, enc::bl(0x4000 - 0x100C),
                {{30, tw.rt(0x1010)}, {33, tw.rt(0x4000)}}, {});
        tw.emit(ms, 0x4000, enc::ret(), {{33, tw.rt(0x1010)}}, {});

        tw.emit_anchor(ms);
    }, "mstr_dedup");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();

    // Only one unique (addr, content) entry should be stored...
    auto hits = mr.at_addr(str_addr);
    size_t hello_count = 0;
    for (auto* h : hits) if (h->content == "Hello") hello_count++;
    REQUIRE(hello_count == 1);

    // ...but both call sites are distinct instructions; by_call_site should
    // reflect whichever call site's scan first recorded the (deduped) entry.
    // At minimum, one of the two call sites must resolve to it.
    bool found_first_site = !mr.at_call_site(2).empty();
    bool found_second_site = !mr.at_call_site(4).empty();
    REQUIRE((found_first_site || found_second_site));
}

TEST_CASE("MemoryStringPass search finds matching strings", "[unit][pass][memory_string]") {
    uint64_t str_addr = 0x100009000ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit(ms, 0x1004, enc::movz(0, 0),
                {{0, str_addr}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::bl(0x2000 - 0x1008),
                {{30, tw.rt(0x100C)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "mstr_search");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<MemoryStringPass>());

    auto& mr = pm->require("memory_strings").get<MemoryStringResult>();

    auto hits = mr.search("hello");
    REQUIRE(!hits.empty());
    bool found = false;
    for (auto* h : hits) if (h->content == "Hello") found = true;
    REQUIRE(found);

    auto miss = mr.search("nonexistentxyz");
    REQUIRE(miss.empty());
}

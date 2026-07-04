/*
 * test_pass_string.cpp — Unit tests for tenet::StringPass
 *
 * StringPass discovers strings by reconstructing memory through MemoryModel
 * at the instant immediately after every memory *write* observed in the
 * trace (see string_pass.h for the full rationale). These tests exercise:
 *   - basic ASCII / UTF-16LE discovery from a write
 *   - multi-instruction string assembly (bytes written across several insts)
 *   - reference tracking (multiple instructions touching the same string)
 *   - time-consistency: a later write must not retroactively "complete" a
 *     string that was read earlier (no cross-time byte stitching)
 *   - memory reuse: a different string overwriting the same address
 *   - negative cases (empty/non-printable data, too-short runs)
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/memory/string_pass.h"

using namespace tenet;
using namespace tenet::test;

namespace {
// QBDI::MemoryAccessType: bit0 = read, bit1 = write.
constexpr uint8_t kMemRead  = 1;
constexpr uint8_t kMemWrite = 2;
}  // namespace

TEST_CASE("StringPass discovers ASCII string from a memory write", "[unit][pass][string]") {
    uint64_t str_addr = 0x100004500ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0" little-endian

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: str x0, [str_addr]  — writes "Hello\0" to memory
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit_anchor(ms);
    }, "string_ascii");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& result_raw = pm->require("strings");
    REQUIRE(result_raw.ok());
    auto& sr = result_raw.get<StringResult>();

    SECTION("string discovered at str_addr") {
        auto* s = sr.at_addr(str_addr);
        REQUIRE(s != nullptr);
        REQUIRE(s->addr == str_addr);
        REQUIRE(s->content == "Hello");
        REQUIRE(s->encoding == StringRef::ASCII);
    }

    SECTION("the writing instruction is recorded as a reference") {
        auto refs = sr.at_inst(0);
        REQUIRE(refs.size() == 1);
        REQUIRE(refs[0]->addr == str_addr);
        REQUIRE(refs[0]->references.size() == 1);
        REQUIRE(refs[0]->references[0].inst_id == 0);
        REQUIRE(refs[0]->references[0].pc == rt_pc(0x1000));
    }
}

TEST_CASE("StringPass ignores memory reads (only writes introduce content)",
          "[unit][pass][string]") {
    uint64_t str_addr = 0x100004600ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // A *read* of bytes that spell "Hello" — but since nothing ever
        // wrote them during the trace, MemoryModel has no writer for this
        // address and StringPass (write-driven) must not fabricate a hit.
        tw.emit(ms, 0x1000, enc::ldr_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemRead, 8, str_addr, hello}});
        tw.emit_anchor(ms);
    }, "string_read_only");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    REQUIRE(sr.at_addr(str_addr) == nullptr);
    REQUIRE(sr.total() == 0);
}

TEST_CASE("StringPass handles empty/zero writes", "[unit][pass][string]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Write to address 0 (should be skipped: addr == 0 is never a valid
        // memory access in the fixture's mem_access convention).
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, 0ULL}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, 0ULL, 0ULL}});
        tw.emit_anchor(ms);
    }, "string_empty");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    SECTION("no strings at address 0") {
        REQUIRE(sr.at_addr(0) == nullptr);
    }

    SECTION("total strings is 0") {
        REQUIRE(sr.total() == 0);
    }
}

TEST_CASE("StringPass ignores non-printable data", "[unit][pass][string]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Write all-zero bytes (not a string: NUL immediately terminates).
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, 0ULL}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, 0x300000000ULL, 0ULL}});
        tw.emit_anchor(ms);
    }, "string_nonprint");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    SECTION("no strings discovered from non-printable data") {
        REQUIRE(sr.at_addr(0x300000000ULL) == nullptr);
    }
    SECTION("total strings is 0") {
        REQUIRE(sr.total() == 0);
    }
}

TEST_CASE("StringPass search finds matching strings", "[unit][pass][string]") {
    uint64_t str_addr = 0x100005000ULL;
    uint64_t data = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, data}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, data}});
        tw.emit_anchor(ms);
    }, "string_search");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    auto hits = sr.search("hello");
    REQUIRE(hits.size() == 1);
    REQUIRE(hits[0]->content == "Hello");

    auto hits2 = sr.search("xyz");
    REQUIRE(hits2.empty());
}

TEST_CASE("StringPass discovers UTF-16LE string from a memory write", "[unit][pass][string]") {
    // "Hell" encoded as UTF-16LE: H\0 e\0 l\0 l\0  (8 bytes)
    // As a little-endian uint64 this is 0x006C006C00650048.
    uint64_t str_addr = 0x100006000ULL;
    uint64_t utf16_hell = 0x006C006C00650048ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: str x0, [str_addr] — writes 8 bytes of UTF-16LE data
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, utf16_hell}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, utf16_hell}});
        tw.emit_anchor(ms);
    }, "string_utf16");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& result_raw = pm->require("strings");
    REQUIRE(result_raw.ok());
    auto& sr = result_raw.get<StringResult>();

    SECTION("UTF-16LE string discovered at str_addr") {
        auto* s = sr.at_addr(str_addr);
        REQUIRE(s != nullptr);
        REQUIRE(s->addr == str_addr);
        REQUIRE(s->encoding == StringRef::UTF16LE);
        REQUIRE(s->content == "Hell");
    }

    SECTION("the writing instruction is recorded as a reference") {
        auto refs = sr.at_inst(0);
        REQUIRE(refs.size() == 1);
        REQUIRE(refs[0]->content == "Hell");
    }
}

TEST_CASE("StringPass tracks multiple references to the same string",
          "[unit][pass][string]") {
    uint64_t str_addr = 0x100007000ULL;
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: first write establishes the string.
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});
        // inst 1: a second, byte-identical write to the same address later
        // (e.g. re-initializing a buffer with the same constant). Exercises
        // the last_write_value/last_write_hit dedup shortcut in run().
        tw.emit(ms, 0x1004, enc::str_imm(0, 0, 0),
                {{33, tw.rt(0x1008)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit_anchor(ms);
    }, "string_multiref");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    auto* s = sr.at_addr(str_addr);
    REQUIRE(s != nullptr);
    REQUIRE(s->content == "Hello");

    // Both writes should be recorded as references to the *same* string
    // entry — not two separate entries — since the content is identical.
    REQUIRE(s->references.size() == 2);
    REQUIRE(s->references[0].inst_id == 0);
    REQUIRE(s->references[1].inst_id == 1);

    // Exactly one string was ever created (dedup didn't fork a duplicate).
    REQUIRE(sr.total() == 1);

    // Both instructions resolve to the same string via at_inst().
    REQUIRE(sr.at_inst(0).size() == 1);
    REQUIRE(sr.at_inst(1).size() == 1);
    REQUIRE(sr.at_inst(0)[0] == sr.at_inst(1)[0]);
}

TEST_CASE("StringPass reflects memory reuse with different content over time",
          "[unit][pass][string]") {
    uint64_t str_addr = 0x100008000ULL;
    uint64_t first  = 0x00000000324F4C48ULL;  // "HLO2\0\0\0\0" (8 bytes, NUL-padded)
    uint64_t second = 0x0000005249415042ULL;  // "BPAIR\0\0" (8 bytes, NUL-padded)

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, first}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, first}});
        // Overwrite the same address with different content — memory reuse.
        tw.emit(ms, 0x1004, enc::str_imm(0, 0, 0),
                {{0, second}, {33, tw.rt(0x1008)}},
                {{kMemWrite, 8, str_addr, second}});
        tw.emit_anchor(ms);
    }, "string_reuse");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    // addr_to_index reflects the *most recent* content at this address.
    auto* s = sr.at_addr(str_addr);
    REQUIRE(s != nullptr);
    REQUIRE(s->content == "BPAIR");

    // Both the old and new content were recorded as distinct string entries
    // (no cross-time byte stitching merged them into one).
    REQUIRE(sr.total() == 2);
    bool found_first = false, found_second = false;
    for (const auto& str : sr.strings) {
        if (str.content == "HLO2") found_first = true;
        if (str.content == "BPAIR") found_second = true;
    }
    REQUIRE(found_first);
    REQUIRE(found_second);
}

TEST_CASE("StringPass does not stitch bytes across different points in time",
          "[unit][pass][string]") {
    // Regression test for the original StringPass bug: a flat "last value
    // per address" byte cache could stitch together a byte written early in
    // the trace with a byte written to the adjacent address much later,
    // producing a string that never actually existed in memory at any
    // single instant. MemoryModel-backed reconstruction must not do this.
    uint64_t base = 0x100009000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: write "AB\0\0\0\0\0\0" at [base, base+8) — "AB" terminated
        // immediately by NUL, too short to qualify (MIN_STRING_LEN == 4).
        uint64_t early_val = 0x0000000000004241ULL;  // "AB" + NULs
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, early_val}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, base, early_val}});

        // inst 1 (much later in program order): write "WXYZ" right after
        // the first NUL byte, at [base+3, base+7). If bytes were merged
        // from a flat "latest value per address" cache irrespective of
        // time, this could look like "AB" immediately followed by "WXYZ"
        // with no NUL in between — a string that never coexisted in one
        // memory snapshot.
        uint32_t wxyz = 0x5A595857u;  // "WXYZ" little-endian as 4 bytes
        tw.emit(ms, 0x1004, enc::str_imm(1, 0, 0),
                {{1, wxyz}, {33, tw.rt(0x1008)}},
                {{kMemWrite, 4, base + 3, wxyz}});
        tw.emit_anchor(ms);
    }, "string_no_stitch");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());

    auto& sr = pm->require("strings").get<StringResult>();

    // At no single instant does [base, base+7) read as one continuous
    // printable run of length >= MIN_STRING_LEN with no embedded NUL:
    //   - After inst 0: "AB\0\0\0\0\0\0" -> longest printable run is "AB" (len 2, too short).
    //   - After inst 1: "AB\0WXYZ\0" -> "AB" is still only 2 chars (stops at
    //     the NUL at base+2); "WXYZ" alone is exactly 4 chars starting at
    //     base+3, which *does* qualify on its own merits (as a fresh write).
    // The key correctness property: no entry should ever equal "ABWXYZ" or
    // any string that pretends the NUL at base+2 didn't exist.
    for (const auto& s : sr.strings) {
        REQUIRE(s.content.find("AB") == std::string::npos);
    }

    // "WXYZ" should be discovered as its own independent string at base+3.
    auto* wxyz_str = sr.at_addr(base + 3);
    REQUIRE(wxyz_str != nullptr);
    REQUIRE(wxyz_str->content == "WXYZ");
}

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

// ═════════════════════════════════════════════════════════════════════════════
// Parallel shard merge correctness tests (#13)
//
// StringPass's WriteEventCollector was upgraded to support parallel scanning
// (supports_parallel()=true, clone(), merge()). These tests verify:
//   1. The collector declares supports_parallel()=true
//   2. clone() produces an independent collector with its own event buffer
//   3. merge() correctly concatenates events from all shards
//   4. The merged result matches a sequential scan of the same trace
//
// Since WriteEventCollector is a private inner class of StringPass, we test
// through the public ScanOrchestrator API: declare_scan registers the
// collector, and we verify the scan produces correct results whether run
// sequentially or in parallel mode.
// ═════════════════════════════════════════════════════════════════════════════

#include "analysis/pass_manager.h"

TEST_CASE("StringPass: parallel scan produces same result as sequential",
          "[unit][pass][string][parallel]") {
    // Generate a trace with multiple string writes at different addresses
    uint64_t addr_a = 0x100004000ULL;
    uint64_t addr_b = 0x100005000ULL;
    uint64_t addr_c = 0x100006000ULL;
    uint64_t hello_val = 0x006F6C6C6548ULL;  // "Hello\0"
    uint64_t world_val = 0x00646C726F77ULL;  // "world\0"

    auto gen = [&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: write "Hello" to addr_a
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello_val}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, addr_a, hello_val}});
        // inst 1: write "world" to addr_b
        tw.emit(ms, 0x1004, enc::str_imm(0, 0, 0),
                {{0, world_val}, {33, tw.rt(0x1008)}},
                {{kMemWrite, 8, addr_b, world_val}});
        // inst 2: write "Hello" to addr_c (same content, different address)
        tw.emit(ms, 0x1008, enc::str_imm(0, 0, 0),
                {{0, hello_val}, {33, tw.rt(0x100C)}},
                {{kMemWrite, 8, addr_c, hello_val}});
        tw.emit_anchor(ms);
    };

    // ── Sequential run ──
    auto env_seq = make_env(gen, "string_parallel_seq");
    REQUIRE(env_seq != nullptr);
    auto pm_seq = make_pm(*env_seq);
    pm_seq->set_no_parallel_scan(true);  // force sequential
    pm_seq->register_pass(std::make_unique<StringPass>());
    auto& seq_raw = pm_seq->require("strings");
    REQUIRE(seq_raw.ok());
    auto& seq_result = seq_raw.get<StringResult>();

    // ── Parallel run (same trace, different env to avoid cache) ──
    auto env_par = make_env(gen, "string_parallel_par");
    REQUIRE(env_par != nullptr);
    auto pm_par = make_pm(*env_par);
    pm_par->set_no_parallel_scan(false);  // allow parallel
    pm_par->register_pass(std::make_unique<StringPass>());
    auto& par_raw = pm_par->require("strings");
    REQUIRE(par_raw.ok());
    auto& par_result = par_raw.get<StringResult>();

    // ── Verify both runs discovered the same strings ──
    REQUIRE(par_result.total() == seq_result.total());

    // Check each address has the same content in both runs
    for (uint64_t addr : {addr_a, addr_b, addr_c}) {
        auto* s_seq = seq_result.at_addr(addr);
        auto* s_par = par_result.at_addr(addr);
        REQUIRE(s_seq != nullptr);
        REQUIRE(s_par != nullptr);
        REQUIRE(s_seq->content == s_par->content);
        REQUIRE(s_seq->encoding == s_par->encoding);
    }
}

TEST_CASE("StringPass: WriteEventCollector clone/merge preserves all write events",
          "[unit][pass][string][parallel]") {
    // This test verifies that the WriteEventCollector's clone() produces
    // an independent buffer and merge() correctly concatenates events.
    // We do this by running StringPass twice on the same trace and verifying
    // the number of discovered strings and references match exactly —
    // if clone/merge lost events, the second run would miss strings.

    uint64_t base_addr = 0x100007000ULL;
    constexpr int N_WRITES = 10;

    auto gen = [&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        for (int i = 0; i < N_WRITES; i++) {
            // Each write stores "Hello" + null terminator (8 bytes, high 2 = 0)
            // at a different address. The value varies slightly by i in the
            // low byte to make each write unique, but keeps it printable.
            // 0x006F6C6C6548 = "Hello\0" in little-endian
            uint64_t val = 0x006F6C6C6548ULL + (uint64_t(i) << 8);  // "Hell" + ('o'+i)
            uint64_t addr = base_addr + i * 8;
            tw.emit(ms, 0x1000 + i * 4, enc::str_imm(0, 0, 0),
                    {{0, val}, {33, tw.rt(0x1004 + i * 4)}},
                    {{kMemWrite, 8, addr, val}});
        }
        tw.emit_anchor(ms);
    };

    // Run 1: sequential
    auto env1 = make_env(gen, "string_clone_seq");
    auto pm1 = make_pm(*env1);
    pm1->set_no_parallel_scan(true);
    pm1->register_pass(std::make_unique<StringPass>());
    auto& r1 = pm1->require("strings").get<StringResult>();

    // Run 2: parallel enabled
    auto env2 = make_env(gen, "string_clone_par");
    auto pm2 = make_pm(*env2);
    pm2->set_no_parallel_scan(false);
    pm2->register_pass(std::make_unique<StringPass>());
    auto& r2 = pm2->require("strings").get<StringResult>();

    // Both runs should discover the same number of strings
    REQUIRE(r1.total() == r2.total());

    // Verify all N_WRITES addresses are present in both results
    for (int i = 0; i < N_WRITES; i++) {
        uint64_t addr = base_addr + i * 8;
        auto* s1 = r1.at_addr(addr);
        auto* s2 = r2.at_addr(addr);
        REQUIRE(s1 != nullptr);
        REQUIRE(s2 != nullptr);
        REQUIRE(s1->content == s2->content);
    }
}

TEST_CASE("StringPass uses MemoryModel::read_batch and keeps repeated-write references",
          "[unit][pass][string][batch]") {
    constexpr uint64_t str_addr = 0x10000A000ULL;
    constexpr uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Repeated identical writes to the same address should keep appending
        // references without creating duplicate strings.
        tw.emit(ms, 0x1000, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1004)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit(ms, 0x1004, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x1008)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit(ms, 0x1008, enc::str_imm(0, 0, 0),
                {{0, hello}, {33, tw.rt(0x100C)}},
                {{kMemWrite, 8, str_addr, hello}});
        tw.emit_anchor(ms);
    }, "string_batch_repeated_refs");

    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    auto* s = sr.at_addr(str_addr);
    REQUIRE(s != nullptr);
    REQUIRE(s->content == "Hello");
    REQUIRE(sr.total() == 1);

    REQUIRE(s->references.size() == 3);
    REQUIRE(s->references[0].inst_id == 0);
    REQUIRE(s->references[1].inst_id == 1);
    REQUIRE(s->references[2].inst_id == 2);

    REQUIRE(sr.at_inst(0).size() == 1);
    REQUIRE(sr.at_inst(1).size() == 1);
    REQUIRE(sr.at_inst(2).size() == 1);

}

TEST_CASE("StringPass memory reuse keeps per-epoch references ordered",
          "[unit][pass][string][batch]") {
    constexpr uint64_t str_addr = 0x10000B000ULL;
    constexpr uint64_t first  = 0x00000000324F4C48ULL;  // "HLO2"
    constexpr uint64_t second = 0x0000005249415042ULL;  // "BPAIR"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x2000, enc::str_imm(0, 0, 0),
                {{0, first}, {33, tw.rt(0x2004)}},
                {{kMemWrite, 8, str_addr, first}});
        tw.emit(ms, 0x2004, enc::str_imm(0, 0, 0),
                {{0, first}, {33, tw.rt(0x2008)}},
                {{kMemWrite, 8, str_addr, first}});

        tw.emit(ms, 0x2008, enc::str_imm(0, 0, 0),
                {{0, second}, {33, tw.rt(0x200C)}},
                {{kMemWrite, 8, str_addr, second}});
        tw.emit(ms, 0x200C, enc::str_imm(0, 0, 0),
                {{0, second}, {33, tw.rt(0x2010)}},
                {{kMemWrite, 8, str_addr, second}});
        tw.emit_anchor(ms);
    }, "string_batch_reuse_order");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    REQUIRE(sr.total() == 2);
    REQUIRE(sr.strings[0].content == "HLO2");
    REQUIRE(sr.strings[1].content == "BPAIR");

    REQUIRE(sr.strings[0].references.size() == 2);
    REQUIRE(sr.strings[0].references[0].inst_id == 0);
    REQUIRE(sr.strings[0].references[1].inst_id == 1);

    REQUIRE(sr.strings[1].references.size() == 2);
    REQUIRE(sr.strings[1].references[0].inst_id == 2);
    REQUIRE(sr.strings[1].references[1].inst_id == 3);

    auto* latest = sr.at_addr(str_addr);
    REQUIRE(latest != nullptr);
    REQUIRE(latest->content == "BPAIR");
}

TEST_CASE("StringPass keeps time-consistent windows when nearby writes evolve",
          "[unit][pass][string][batch]") {
    constexpr uint64_t base = 0x10000C000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        uint64_t early = 0x0000000000004241ULL;  // "AB" + NULs
        uint32_t wxyz = 0x5A595857u;             // "WXYZ"
        uint64_t uvwx = 0x0000000058575655ULL;   // "UVWX"

        tw.emit(ms, 0x3000, enc::str_imm(0, 0, 0),
                {{0, early}, {33, tw.rt(0x3004)}},
                {{kMemWrite, 8, base, early}});
        tw.emit(ms, 0x3004, enc::str_imm(1, 0, 0),
                {{1, wxyz}, {33, tw.rt(0x3008)}},
                {{kMemWrite, 4, base + 3, wxyz}});
        tw.emit(ms, 0x3008, enc::str_imm(2, 0, 0),
                {{2, uvwx}, {33, tw.rt(0x300C)}},
                {{kMemWrite, 8, base + 8, uvwx}});
        tw.emit_anchor(ms);
    }, "string_batch_time_consistent");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    for (const auto& s : sr.strings) {
        REQUIRE(s.content.find("ABWXYZ") == std::string::npos);
    }

    auto* wxyz = sr.at_addr(base + 3);
    REQUIRE(wxyz != nullptr);
    REQUIRE(wxyz->content == "WXYZ");
}

TEST_CASE("StringPass repeated non-string writes stay without references",
          "[unit][pass][string][batch][boundary]") {
    constexpr uint64_t addr = 0x10000D000ULL;
    constexpr uint64_t zero = 0ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x4000, enc::str_imm(0, 0, 0),
                {{0, zero}, {33, tw.rt(0x4004)}},
                {{kMemWrite, 8, addr, zero}});
        tw.emit(ms, 0x4004, enc::str_imm(0, 0, 0),
                {{0, zero}, {33, tw.rt(0x4008)}},
                {{kMemWrite, 8, addr, zero}});
        tw.emit(ms, 0x4008, enc::str_imm(0, 0, 0),
                {{0, zero}, {33, tw.rt(0x400C)}},
                {{kMemWrite, 8, addr, zero}});
        tw.emit_anchor(ms);
    }, "string_batch_non_string_repeat");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    REQUIRE(sr.total() == 0);
    REQUIRE(sr.at_inst(0).empty());
    REQUIRE(sr.at_inst(1).empty());
    REQUIRE(sr.at_inst(2).empty());
}

TEST_CASE("StringPass alias uses first overlapping hit when one probe matches many",
          "[unit][pass][string][batch][boundary]") {
    constexpr uint64_t base = 0x10000E000ULL;
    constexpr uint64_t abcd = 0x0000000044434241ULL;    // "ABCD"
    constexpr uint64_t efgh = 0x0000000048474645ULL;    // "EFGH"
    constexpr uint64_t bridge = 0x0000484746450044ULL;  // "D\0EFGH\0\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x5000, enc::str_imm(0, 0, 0),
                {{0, abcd}, {33, tw.rt(0x5004)}},
                {{kMemWrite, 8, base, abcd}});
        tw.emit(ms, 0x5004, enc::str_imm(0, 0, 0),
                {{0, efgh}, {33, tw.rt(0x5008)}},
                {{kMemWrite, 8, base + 5, efgh}});
        tw.emit(ms, 0x5008, enc::str_imm(0, 0, 0),
                {{0, bridge}, {33, tw.rt(0x500C)}},
                {{kMemWrite, 8, base + 3, bridge}});
        // Repeated identical write aliases to previous probe slot.
        tw.emit(ms, 0x500C, enc::str_imm(0, 0, 0),
                {{0, bridge}, {33, tw.rt(0x5010)}},
                {{kMemWrite, 8, base + 3, bridge}});
        tw.emit_anchor(ms);
    }, "string_batch_overlap_alias");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    auto* first = sr.at_addr(base);
    auto* second = sr.at_addr(base + 5);
    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    REQUIRE(first->content == "ABCD");
    REQUIRE(second->content == "EFGH");

    // inst 2 overlaps both strings; inst 3 aliases only the first overlapping hit.
    REQUIRE(first->references.size() == 3);
    REQUIRE(first->references[0].inst_id == 0);
    REQUIRE(first->references[1].inst_id == 2);
    REQUIRE(first->references[2].inst_id == 3);

    REQUIRE(second->references.size() == 2);
    REQUIRE(second->references[0].inst_id == 1);
    REQUIRE(second->references[1].inst_id == 2);

    auto at3 = sr.at_inst(3);
    REQUIRE(at3.size() == 1);
    REQUIRE(at3[0]->addr == base);
}

TEST_CASE("StringPass repeated writes across batch chunk still dedup correctly",
          "[unit][pass][string][batch][boundary]") {
    constexpr uint64_t addr = 0x10000F000ULL;
    constexpr uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0"
    constexpr int kWrites = 4300;                  // > previous 4096 chunk size

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 1024;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        for (int i = 0; i < kWrites; ++i) {
            uint64_t pc = 0x6000 + static_cast<uint64_t>(i) * 4;
            tw.emit(ms, pc, enc::str_imm(0, 0, 0),
                    {{0, hello}, {33, tw.rt(pc + 4)}},
                    {{kMemWrite, 8, addr, hello}});
        }
        tw.emit_anchor(ms);
    }, "string_batch_cross_chunk_repeat");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    auto* s = sr.at_addr(addr);
    REQUIRE(s != nullptr);
    REQUIRE(s->content == "Hello");
    REQUIRE(sr.total() == 1);
    REQUIRE(s->references.size() == static_cast<size_t>(kWrites));

    REQUIRE(sr.at_inst(0).size() == 1);
    REQUIRE(sr.at_inst(4095).size() == 1);
    REQUIRE(sr.at_inst(4096).size() == 1);
    REQUIRE(sr.at_inst(kWrites - 1).size() == 1);
}

TEST_CASE("StringPass A-B-A reuse keeps discovery and reference order",
          "[unit][pass][string][batch][boundary]") {
    constexpr uint64_t addr = 0x100010000ULL;
    constexpr uint64_t a = 0x006F6C6C6548ULL;  // "Hello\0"
    constexpr uint64_t b = 0x00646C726F57ULL;  // "World\0"

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x7000, enc::str_imm(0, 0, 0),
                {{0, a}, {33, tw.rt(0x7004)}},
                {{kMemWrite, 8, addr, a}});
        tw.emit(ms, 0x7004, enc::str_imm(0, 0, 0),
                {{0, a}, {33, tw.rt(0x7008)}},
                {{kMemWrite, 8, addr, a}});

        tw.emit(ms, 0x7008, enc::str_imm(0, 0, 0),
                {{0, b}, {33, tw.rt(0x700C)}},
                {{kMemWrite, 8, addr, b}});
        tw.emit(ms, 0x700C, enc::str_imm(0, 0, 0),
                {{0, b}, {33, tw.rt(0x7010)}},
                {{kMemWrite, 8, addr, b}});

        tw.emit(ms, 0x7010, enc::str_imm(0, 0, 0),
                {{0, a}, {33, tw.rt(0x7014)}},
                {{kMemWrite, 8, addr, a}});
        tw.emit(ms, 0x7014, enc::str_imm(0, 0, 0),
                {{0, a}, {33, tw.rt(0x7018)}},
                {{kMemWrite, 8, addr, a}});
        tw.emit_anchor(ms);
    }, "string_batch_a_b_a");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<StringPass>());
    auto& sr = pm->require("strings").get<StringResult>();

    REQUIRE(sr.total() == 3);
    REQUIRE(sr.strings[0].content == "Hello");
    REQUIRE(sr.strings[1].content == "World");
    REQUIRE(sr.strings[2].content == "Hello");

    REQUIRE(sr.strings[0].discovered_at == 0);
    REQUIRE(sr.strings[1].discovered_at == 2);
    REQUIRE(sr.strings[2].discovered_at == 4);

    REQUIRE(sr.strings[0].references.size() == 2);
    REQUIRE(sr.strings[0].references[0].inst_id == 0);
    REQUIRE(sr.strings[0].references[1].inst_id == 1);

    REQUIRE(sr.strings[1].references.size() == 2);
    REQUIRE(sr.strings[1].references[0].inst_id == 2);
    REQUIRE(sr.strings[1].references[1].inst_id == 3);

    REQUIRE(sr.strings[2].references.size() == 2);
    REQUIRE(sr.strings[2].references[0].inst_id == 4);
    REQUIRE(sr.strings[2].references[1].inst_id == 5);

    auto* latest = sr.at_addr(addr);
    REQUIRE(latest != nullptr);
    REQUIRE(latest == &sr.strings[2]);
}

/*
 * test_cross_thread_dataflow.cpp — Phase 3 cross-thread dataflow pass tests
 *
 * Verifies the cross_thread_dataflow pass on an interleaved two-thread trace:
 *
 *   1. A write on thread A followed by a read on thread B of the same address
 *      produces exactly one hand-off edge (A→B), ordered by consumer inst.
 *   2. Same-thread write→read produces NO edge (self-consumption).
 *   3. Repeated reads on thread B of the same written value collapse to one
 *      edge (generation dedup), but a NEW write (new generation) re-arms it.
 *   4. A read on thread B of a location last written by thread B is skipped.
 *   5. Channels aggregate by (addr, from, to) and sort by hand-off count.
 *   6. as_dataflow_edge() maps to the shared DataflowEdge representation
 *      (via_mem_addr set, via_reg 0) so DFG UIs can consume the edges.
 *   7. Edges can be expressed as producers/consumers queries via edges_before.
 *   8. A single-thread trace yields an empty result without error.
 *
 * Trace layout (v4):
 *   THREAD(100): STR [0x1000]          (write, gen 1)
 *   THREAD(100): STR [0x2000]          (write by A, later read by B)
 *   THREAD(200): LDR [0x1000]          (read → edge A→B)
 *   THREAD(200): LDR [0x1000]          (repeat read, dedup: no new edge)
 *   THREAD(100): STR [0x1000] again    (gen 2)
 *   THREAD(200): LDR [0x1000]          (read gen 2 → second edge)
 *   THREAD(200): STR [0x3000]; LDR [0x3000]   (same-thread: no edge)
 *
 * Run:  ctest -R 'cross_thread_dataflow' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/misc/cross_thread_dataflow_pass.h"
#include "analysis/passes/misc/thread_pass.h"

using namespace tenet;
using namespace tenet::test;

namespace {

constexpr uint64_t kTidA = 100;
constexpr uint64_t kTidB = 200;
constexpr uint64_t kAddrShared  = 0x1000;   // A writes, B reads (two generations)
constexpr uint64_t kAddrLate    = 0x2000;   // A writes; B never reads (no edge)
constexpr uint64_t kAddrBOnly   = 0x3000;   // B writes and reads (no edge)

constexpr uint8_t kMemRead  = 1;   // QBDI::MEMORY_READ
constexpr uint8_t kMemWrite = 2;   // QBDI::MEMORY_WRITE

/// Fixture default slide (trace_writer rt() adds this to static addresses).
constexpr uint64_t kSlide = 0x4000;
/// Runtime address the fixture emits for a static test address.
constexpr uint64_t rt_of(uint64_t a) { return a + kSlide; }

struct CrossThreadEnv {
    std::unique_ptr<TraceEnv> env;
    std::unique_ptr<PassManager> pm;
    const CrossThreadDataflowResult* result = nullptr;
};

CrossThreadEnv run_cross_thread_pass() {
    CrossThreadEnv out;

    out.env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.gpr[33] = tw.rt(0x2000);

        // ── chunk 1: thread A writes ──
        tw.emit_thread(kTidA);
        tw.emit_anchor(ms);
        // inst 0: A stores gen-1 value to kAddrShared
        tw.emit(ms, 0x2000, 0xD1000000u /*placeholder opcode*/,
                {{33, tw.rt(0x2004)}},
                {{kMemWrite, 8, tw.rt(kAddrShared), 0xAA11}});
        // inst 1: A stores to kAddrLate (no consumer)
        tw.emit(ms, 0x2004, 0xD1000001u,
                {{33, tw.rt(0x2008)}},
                {{kMemWrite, 8, tw.rt(kAddrLate), 0xBB22}});

        // ── chunk 2: thread B reads ──
        MachineState ms2;
        ms2.sp() = 0x16F100000ULL;
        ms2.gpr[33] = tw.rt(0x4000);
        tw.emit_thread(kTidB);
        tw.emit_anchor(ms2);
        // inst 2: B reads gen-1 → edge #1 (writer=0, reader=2)
        tw.emit(ms2, 0x4000, 0xD1000002u,
                {{0, 0xAA11ULL}, {33, tw.rt(0x4004)}},
                {{kMemRead, 8, tw.rt(kAddrShared), 0xAA11}});
        // inst 3: B re-reads same value → dedup, no new edge
        tw.emit(ms2, 0x4004, 0xD1000003u,
                {{0, 0xAA11ULL}, {33, tw.rt(0x4008)}},
                {{kMemRead, 8, tw.rt(kAddrShared), 0xAA11}});
        // inst 4: B writes its own location…
        tw.emit(ms2, 0x4008, 0xD1000004u,
                {{33, tw.rt(0x400C)}},
                {{kMemWrite, 8, tw.rt(kAddrBOnly), 0xCC33}});
        // inst 5: …and reads it back (same thread: no edge)
        tw.emit(ms2, 0x400C, 0xD1000005u,
                {{1, 0xCC33ULL}, {33, tw.rt(0x4010)}},
                {{kMemRead, 8, tw.rt(kAddrBOnly), 0xCC33}});

        // ── chunk 3: thread A writes a second generation ──
        MachineState ms3;
        ms3.sp() = 0x16F000000ULL;
        ms3.gpr[33] = tw.rt(0x2010);
        tw.emit_thread(kTidA);
        tw.emit_anchor(ms3);
        // inst 6: gen-2 write
        tw.emit(ms3, 0x2010, 0xD1000006u,
                {{33, tw.rt(0x2014)}},
                {{kMemWrite, 8, tw.rt(kAddrShared), 0xDD44}});

        // ── chunk 4: thread B reads gen-2 → edge #2 ──
        MachineState ms4;
        ms4.sp() = 0x16F100000ULL;
        ms4.gpr[33] = tw.rt(0x4020);
        tw.emit_thread(kTidB);
        tw.emit_anchor(ms4);
        // inst 7: B reads gen-2 → edge #2 (writer=6, reader=7)
        tw.emit(ms4, 0x4020, 0xD1000007u,
                {{0, 0xDD44ULL}, {33, tw.rt(0x4024)}},
                {{kMemRead, 8, tw.rt(kAddrShared), 0xDD44}});
    });

    // Run thread (dependency) + cross_thread_dataflow.
    out.pm = make_pm(*out.env);
    out.pm->register_pass(std::make_unique<ThreadPass>());
    out.pm->register_pass(std::make_unique<CrossThreadDataflowPass>());
    auto& raw = out.pm->require("cross_thread_dataflow");
    REQUIRE(raw.ok());
    out.result = &raw.get<CrossThreadDataflowResult>();
    return out;
}

}  // namespace

TEST_CASE("CrossThreadDataflow: hand-offs detected on interleaved trace",
          "[passes][multithread]") {
    const auto xenv = run_cross_thread_pass();
    const auto& r = *xenv.result;

    SECTION("exactly two edges (generation dedup collapses repeat reads)") {
        REQUIRE(r.edges.size() == 2);
    }

    SECTION("edges carry the right endpoints and threads") {
        REQUIRE(r.edges.size() == 2);
        CHECK(r.edges[0].from_inst_id == 0);   // gen-1 writer
        CHECK(r.edges[0].to_inst_id   == 2);   // gen-1 reader
        CHECK(r.edges[0].from_thread  == kTidA);
        CHECK(r.edges[0].to_thread    == kTidB);
        CHECK(r.edges[0].addr         == rt_of(kAddrShared));

        CHECK(r.edges[1].from_inst_id == 6);   // gen-2 writer
        CHECK(r.edges[1].to_inst_id   == 7);   // gen-2 reader
        CHECK(r.edges[1].addr         == rt_of(kAddrShared));
    }

    SECTION("same-thread write/read and unread locations produce no edges") {
        // kAddrBOnly (B writes, B reads) and kAddrLate (A writes, nobody
        // reads) must not contribute edges — verified by total == 2 and by
        // the addr assertions above (only kAddrShared appears).
        for (const auto& e : r.edges) {
            CHECK(e.addr == rt_of(kAddrShared));
        }
    }

    SECTION("channels aggregate by (addr, from, to)") {
        REQUIRE(r.channels.size() == 1);
        CHECK(r.channels[0].addr        == rt_of(kAddrShared));
        CHECK(r.channels[0].from_thread == kTidA);
        CHECK(r.channels[0].to_thread   == kTidB);
        CHECK(r.channels[0].edge_count  == 2);
        REQUIRE(r.channels[0].edge_indices.size() == 2);
    }

    SECTION("thread pair count") {
        CHECK(r.thread_pair_count == 1);
    }

    SECTION("edges map to DataflowEdge with via_mem_addr") {
        for (const auto& e : r.edges) {
            auto df = e.as_dataflow_edge();
            CHECK(df.from_inst_id == e.from_inst_id);
            CHECK(df.to_inst_id   == e.to_inst_id);
            CHECK(df.via_reg      == 0);
            CHECK(df.via_mem_addr == e.addr);
        }
    }

    SECTION("edges_before filters by consumer position") {
        auto before3 = r.edges_before(3);
        REQUIRE(before3.size() == 1);
        CHECK(before3[0]->to_inst_id == 2);
        auto before8 = r.edges_before(8);
        CHECK(before8.size() == 2);
    }
}

TEST_CASE("CrossThreadDataflow: single-thread trace yields empty result",
          "[passes][multithread]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.gpr[33] = tw.rt(0x2000);
        tw.emit_thread(100);
        tw.emit_anchor(ms);
        // Same-thread write→read: no hand-off possible.
        tw.emit(ms, 0x2000, 0xD1000000u, {{33, tw.rt(0x2004)}},
                {{kMemWrite, 8, tw.rt(0x1000), 1}});
        tw.emit(ms, 0x2004, 0xD1000001u, {{0, 1ULL}, {33, tw.rt(0x2008)}},
                {{kMemRead, 8, tw.rt(0x1000), 1}});
    });

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    pm->register_pass(std::make_unique<CrossThreadDataflowPass>());
    auto& raw = pm->require("cross_thread_dataflow");
    REQUIRE(raw.ok());
    const auto& r = raw.get<CrossThreadDataflowResult>();
    CHECK(r.edges.empty());
    CHECK(r.channels.empty());
}

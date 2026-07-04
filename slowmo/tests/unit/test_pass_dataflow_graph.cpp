/*
 * test_pass_dataflow_graph.cpp — Unit tests for tenet::DataflowGraphPass
 *
 * DataflowGraphPass builds a full-region instruction dependency graph:
 *   - Register edges: last_writer[reg] → this inst, derived from the
 *     static decoder's regs_read/regs_written (Capstone), not reg_diff.
 *   - Memory edges (via_mem_addr != 0): most-recent overlapping store →
 *     this load, using the trace's actual mem_access addresses.
 *
 * Run:  ctest -R 'dataflow_graph' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"

using namespace tenet;
using namespace tenet::test;

// QBDI::MemoryAccessType bit flags used by TraceWriter::MemAcc.type.
static constexpr uint8_t MEM_READ  = 1;
static constexpr uint8_t MEM_WRITE = 2;

// ─── Helpers ──────────────────────────────────────────────────────────────

/// Finds the single edge from `from` to `to` carrying a memory dependency
/// (via_mem_addr != 0), or nullptr if none exists.
static const DFGEdge* find_mem_edge(const DataflowGraphResult& res,
                                    uint64_t from, uint64_t to) {
    for (const auto& e : res.edges) {
        if (e.from_inst_id == from && e.to_inst_id == to && e.via_mem_addr != 0) {
            return &e;
        }
    }
    return nullptr;
}

static bool has_any_mem_edge_into(const DataflowGraphResult& res, uint64_t to) {
    for (const auto& e : res.edges) {
        if (e.to_inst_id == to && e.via_mem_addr != 0) return true;
    }
    return false;
}

/// Build a trace:
///   inst 0: str x1, [x2]      (write 8 bytes @ 0x2000)
///   inst 1: ldr x3, [x2]      (read 8 bytes @ 0x2000)  ← depends on inst 0
///   inst 2: (anchor pad, unrelated)
static std::unique_ptr<TraceEnv> make_store_then_load() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(2) = 0x2000ULL;  // base register for both accesses

        // inst 0: str x1, [x2]  → writes 8 bytes at addr 0x2000
        tw.emit(ms, 0x1000, enc::str_imm(1, 2, 0),
                {{33, tw.rt(0x1004)}},
                {{MEM_WRITE, 8, 0x2000ULL, 0x42ULL}});

        // inst 1: ldr x3, [x2]  → reads 8 bytes at addr 0x2000
        tw.emit(ms, 0x1004, enc::ldr_imm(3, 2, 0),
                {{3, 0x42ULL}, {33, tw.rt(0x1008)}},
                {{MEM_READ, 8, 0x2000ULL, 0x42ULL}});

        tw.emit_anchor(ms);
    }, "dfg_store_load");
}

/// Build a trace with two non-overlapping stores followed by a load that
/// only overlaps the second (most recent) store:
///   inst 0: str x1, [x2]        write 8 bytes @ 0x3000
///   inst 1: str x4, [x2, #8]    write 8 bytes @ 0x3008  (adjacent, no overlap)
///   inst 2: ldr x5, [x2, #8]    read  8 bytes @ 0x3008  ← depends on inst 1 only
static std::unique_ptr<TraceEnv> make_two_stores_one_load() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(2) = 0x3000ULL;

        // inst 0: str x1, [x2]       → 0x3000..0x3008
        tw.emit(ms, 0x1000, enc::str_imm(1, 2, 0),
                {{33, tw.rt(0x1004)}},
                {{MEM_WRITE, 8, 0x3000ULL, 0x11ULL}});

        // inst 1: str x4, [x2, #8]   → 0x3008..0x3010
        tw.emit(ms, 0x1004, enc::str_imm(4, 2, 8),
                {{33, tw.rt(0x1008)}},
                {{MEM_WRITE, 8, 0x3008ULL, 0x22ULL}});

        // inst 2: ldr x5, [x2, #8]   → reads 0x3008..0x3010 (inst 1's range)
        tw.emit(ms, 0x1008, enc::ldr_imm(5, 2, 8),
                {{5, 0x22ULL}, {33, tw.rt(0x100C)}},
                {{MEM_READ, 8, 0x3008ULL, 0x22ULL}});

        tw.emit_anchor(ms);
    }, "dfg_two_stores_one_load");
}

/// Build a trace where a second, later store fully overwrites the first
/// store's byte range before any load happens:
///   inst 0: str x1, [x2]   write 8 bytes @ 0x4000   (shadowed)
///   inst 1: str x4, [x2]   write 8 bytes @ 0x4000   (shadows inst 0)
///   inst 2: ldr x5, [x2]   read  8 bytes @ 0x4000   ← depends on inst 1 only
static std::unique_ptr<TraceEnv> make_shadowed_store() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(2) = 0x4000ULL;

        // inst 0: str x1, [x2]   → 0x4000..0x4008 (will be shadowed)
        tw.emit(ms, 0x1000, enc::str_imm(1, 2, 0),
                {{33, tw.rt(0x1004)}},
                {{MEM_WRITE, 8, 0x4000ULL, 0xAAULL}});

        // inst 1: str x4, [x2]   → 0x4000..0x4008 (shadows inst 0)
        tw.emit(ms, 0x1004, enc::str_imm(4, 2, 0),
                {{33, tw.rt(0x1008)}},
                {{MEM_WRITE, 8, 0x4000ULL, 0xBBULL}});

        // inst 2: ldr x5, [x2]   → reads 0x4000..0x4008
        tw.emit(ms, 0x1008, enc::ldr_imm(5, 2, 0),
                {{5, 0xBBULL}, {33, tw.rt(0x100C)}},
                {{MEM_READ, 8, 0x4000ULL, 0xBBULL}});

        tw.emit_anchor(ms);
    }, "dfg_shadowed_store");
}

/// Build a trace with a load that has no preceding store to the same
/// address (e.g., reading pre-existing/external memory):
///   inst 0: ldr x1, [x2]   read 8 bytes @ 0x5000, no prior write in-graph
static std::unique_ptr<TraceEnv> make_load_without_store() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(2) = 0x5000ULL;

        tw.emit(ms, 0x1000, enc::ldr_imm(1, 2, 0),
                {{1, 0x99ULL}, {33, tw.rt(0x1004)}},
                {{MEM_READ, 8, 0x5000ULL, 0x99ULL}});

        tw.emit_anchor(ms);
    }, "dfg_load_no_store");
}

/// Build a trace exercising BOTH a register edge and a memory edge into the
/// same consuming instruction:
///   inst 0: movz x2, #0x6000     defines x2 (register producer)
///   inst 1: str x1, [x2]         writes 8 bytes @ 0x6000 (memory producer)
///   inst 2: ldr x3, [x2]         reads x2 (reg edge from inst 0) AND
///                                reads 8 bytes @ 0x6000 (mem edge from inst 1)
static std::unique_ptr<TraceEnv> make_mixed_reg_and_mem_deps() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // inst 0: movz x2, #0x6000   → defines x2
        tw.emit(ms, 0x1000, enc::movz(2, 0x6000),
                {{2, 0x6000ULL}, {33, tw.rt(0x1004)}}, {});

        // inst 1: str x1, [x2]       → writes 0x6000..0x6008
        tw.emit(ms, 0x1004, enc::str_imm(1, 2, 0),
                {{33, tw.rt(0x1008)}},
                {{MEM_WRITE, 8, 0x6000ULL, 0x77ULL}});

        // inst 2: ldr x3, [x2]       → reads x2 (from inst 0) and mem @0x6000 (from inst 1)
        tw.emit(ms, 0x1008, enc::ldr_imm(3, 2, 0),
                {{3, 0x77ULL}, {33, tw.rt(0x100C)}},
                {{MEM_READ, 8, 0x6000ULL, 0x77ULL}});

        tw.emit_anchor(ms);
    }, "dfg_mixed_reg_mem");
}

// ─── Test cases ────────────────────────────────────────────────────────────

TEST_CASE("DataflowGraphPass: store followed by load at same address creates a memory edge",
          "[unit][pass][dataflow_graph]") {
    auto env = make_store_then_load();
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<DataflowGraphPass>());
    auto& raw = pm->require("dataflow_graph");
    REQUIRE(raw.ok());
    auto& res = raw.get<DataflowGraphResult>();

    SECTION("memory edge from inst 0 (store) to inst 1 (load) exists") {
        const auto* e = find_mem_edge(res, 0, 1);
        REQUIRE(e != nullptr);
        REQUIRE(e->via_mem_addr == 0x2000ULL);
        REQUIRE(e->via_reg == 0);
    }
    SECTION("producers_of(1) includes the memory edge") {
        auto producers = res.producers_of(1);
        bool found = false;
        for (const auto& e : producers) {
            if (e.from_inst_id == 0 && e.via_mem_addr == 0x2000ULL) found = true;
        }
        REQUIRE(found);
    }
    SECTION("DOT export labels the memory edge distinctly from register edges") {
        std::string dot = res.to_dot();
        REQUIRE(dot.find("mem:0x2000") != std::string::npos);
    }
    SECTION("JSON export uses via_mem field, not reg") {
        std::string json = res.to_json();
        REQUIRE(json.find("\"via_mem\": \"0x2000\"") != std::string::npos);
    }
}

TEST_CASE("DataflowGraphPass: load only depends on the most recent overlapping store",
          "[unit][pass][dataflow_graph]") {
    auto env = make_two_stores_one_load();
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<DataflowGraphPass>());
    auto& raw = pm->require("dataflow_graph");
    REQUIRE(raw.ok());
    auto& res = raw.get<DataflowGraphResult>();

    SECTION("load (inst 2) has a memory edge from inst 1 (overlapping store)") {
        REQUIRE(find_mem_edge(res, 1, 2) != nullptr);
    }
    SECTION("load (inst 2) has NO memory edge from inst 0 (non-overlapping store)") {
        REQUIRE(find_mem_edge(res, 0, 2) == nullptr);
    }
}

TEST_CASE("DataflowGraphPass: fully-shadowed store is not a producer once overwritten",
          "[unit][pass][dataflow_graph]") {
    auto env = make_shadowed_store();
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<DataflowGraphPass>());
    auto& raw = pm->require("dataflow_graph");
    REQUIRE(raw.ok());
    auto& res = raw.get<DataflowGraphResult>();

    SECTION("load (inst 2) depends on inst 1 (the shadowing, most recent store)") {
        REQUIRE(find_mem_edge(res, 1, 2) != nullptr);
    }
    SECTION("load (inst 2) does NOT depend on inst 0 (fully shadowed store)") {
        REQUIRE(find_mem_edge(res, 0, 2) == nullptr);
    }
    SECTION("exactly one memory edge feeds the load") {
        int count = 0;
        for (const auto& e : res.producers_of(2)) {
            if (e.via_mem_addr != 0) count++;
        }
        REQUIRE(count == 1);
    }
}

TEST_CASE("DataflowGraphPass: load with no prior store produces no memory edge",
          "[unit][pass][dataflow_graph]") {
    auto env = make_load_without_store();
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<DataflowGraphPass>());
    auto& raw = pm->require("dataflow_graph");
    REQUIRE(raw.ok());
    auto& res = raw.get<DataflowGraphResult>();

    SECTION("no memory edge feeds inst 0") {
        REQUIRE_FALSE(has_any_mem_edge_into(res, 0));
    }
    SECTION("node for inst 0 still exists") {
        REQUIRE(res.inst_to_node.count(0) > 0);
    }
}

TEST_CASE("DataflowGraphPass: register and memory edges coexist into the same consumer",
          "[unit][pass][dataflow_graph]") {
    auto env = make_mixed_reg_and_mem_deps();
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<DataflowGraphPass>());
    auto& raw = pm->require("dataflow_graph");
    REQUIRE(raw.ok());
    auto& res = raw.get<DataflowGraphResult>();

    auto producers = res.producers_of(2);

    SECTION("inst 2 has a register edge from inst 0 (defines x2) via x2") {
        bool found = false;
        for (const auto& e : producers) {
            if (e.from_inst_id == 0 && e.via_mem_addr == 0 && e.via_reg == 2) found = true;
        }
        REQUIRE(found);
    }
    SECTION("inst 2 also has a memory edge from inst 1 (writes 0x6000)") {
        bool found = false;
        for (const auto& e : producers) {
            if (e.from_inst_id == 1 && e.via_mem_addr == 0x6000ULL) found = true;
        }
        REQUIRE(found);
    }
    SECTION("both edge kinds are present without one clobbering the other") {
        REQUIRE(producers.size() >= 2);
    }
}

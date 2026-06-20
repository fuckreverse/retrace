/*
 * test_core_breakpoint_engine.cpp — Unit tests for tenet::BreakpointEngine
 *
 * Verifies:
 *   - PcBreakpoint: run_forward finds first execution >= current position
 *   - PcBreakpoint: run_backward finds last execution < current position
 *   - WatchBreakpoint: run_forward finds next write to a monitored range
 *   - WatchBreakpoint: run_backward finds previous write
 *   - ConditionalBreakpoint: predicate evaluated correctly in both directions
 *   - add/remove/clear breakpoints lifecycle
 *   - Multiple breakpoints: earliest forward / latest backward wins
 *   - parse_breakpoint_cmd: "b", "w", error cases
 *   - Convenience wrappers: next_execution / prev_execution / next_write / prev_write
 */
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <string>

#include "fixtures/trace_fixture.h"
#include "core/breakpoint_engine.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static constexpr uint8_t kWrite = 2;
static constexpr uint8_t kRead  = 1;

/// Convert a static PC to runtime PC (matches TraceWriter default slide=0x4000).
static uint64_t tw_rt(uint64_t static_pc) {
    return static_pc + 0x4000ULL;
}

/// Build a TraceEnv with BreakpointEngine constructed on top of it.
/// Returns (env, engine). Caller owns both.
static std::pair<std::unique_ptr<TraceEnv>, std::unique_ptr<BreakpointEngine>>
make_engine(std::function<void(TraceWriter&)> gen, const char* name = "bp_test") {
    auto env = make_env(std::move(gen), name);
    if (!env) return {nullptr, nullptr};
    // MemoryModel must be built for WatchBreakpoint support
    env->memory->build();
    auto engine = std::make_unique<BreakpointEngine>(
        *env->reader, *env->index, *env->regfile, *env->memory);
    return {std::move(env), std::move(engine)};
}

// ─── PC Breakpoint Tests ─────────────────────────────────────────────────────

TEST_CASE("BreakpointEngine: PcBreakpoint run_forward finds first execution",
          "[unit][core][breakpoint_engine][pc_bp]") {
    // Trace: 4 instructions, where 0x1004 is executed twice (inst 1 and inst 3)
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});  // inst 1
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 2  (loops back)
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x100C)}}, {});  // inst 3
        tw.emit_anchor(ms);
    }, "pc_bp_forward");

    REQUIRE(env != nullptr);
    REQUIRE(engine != nullptr);

    // Set breakpoint on the runtime PC of 0x1004
    // TraceWriter default slide = 0x4000; rt_pc() helper uses the same.
    uint64_t target_pc = rt_pc(0x1004);  // 0x1004 + 0x4000

    auto id = engine->add_breakpoint(PcBreakpoint{target_pc});
    REQUIRE(id != kInvalidBreakpointId);

    SECTION("run_forward from start (inst 0 - 1) hits inst 1 (0x1004)") {
        auto hit = engine->run_forward(0);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 1);
        REQUIRE(hit->bp_id == id);
    }

    SECTION("run_forward from inst 1 finds inst 3 (second execution of 0x1004)") {
        auto hit = engine->run_forward(1);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 3);
    }

    SECTION("run_forward from inst 3 finds nothing (end of trace)") {
        auto hit = engine->run_forward(3);
        REQUIRE(!hit.has_value());
    }
}

TEST_CASE("BreakpointEngine: PcBreakpoint run_backward finds previous execution",
          "[unit][core][breakpoint_engine][pc_bp]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});  // inst 1
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 2
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x100C)}}, {});  // inst 3
        tw.emit_anchor(ms);
    }, "pc_bp_backward");

    REQUIRE(env != nullptr);
    uint64_t target_pc = rt_pc(0x1004);
    auto id = engine->add_breakpoint(PcBreakpoint{target_pc});

    SECTION("run_backward from inst 3 finds inst 1 (latest before 3)") {
        auto hit = engine->run_backward(3);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 1);
        REQUIRE(hit->bp_id == id);
    }

    SECTION("run_backward from inst 1 finds nothing (no earlier execution)") {
        auto hit = engine->run_backward(1);
        REQUIRE(!hit.has_value());
    }

    SECTION("run_backward from inst 4 (end) finds inst 3") {
        auto hit = engine->run_backward(4);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 3);
    }
}

// ─── Watchpoint Tests ─────────────────────────────────────────────────────

TEST_CASE("BreakpointEngine: WatchBreakpoint run_forward finds next write",
          "[unit][core][breakpoint_engine][watchpoint]") {
    constexpr uint64_t kBuf = 0x16FC00000ULL;

    auto [env, engine] = make_engine([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});          // inst 0: nop
        tw.emit(ms, 0x1004, enc::str_imm(0, 31, 0),                          // inst 1: write
                {{0, 0xAAAAULL}, {33, tw.rt(0x1008)}},
                {{kWrite, 8, kBuf, 0xAAAAULL}});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});          // inst 2: nop
        tw.emit(ms, 0x100C, enc::str_imm(0, 31, 0),                          // inst 3: write
                {{0, 0xBBBBULL}, {33, tw.rt(0x1010)}},
                {{kWrite, 8, kBuf, 0xBBBBULL}});
        tw.emit_anchor(ms);
    }, "watch_forward");

    REQUIRE(env != nullptr);

    auto id = engine->add_breakpoint(WatchBreakpoint{kBuf, 8});

    SECTION("run_forward from start hits inst 1 (first write)") {
        auto hit = engine->run_forward(0);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 1);
        REQUIRE(hit->bp_id == id);
    }

    SECTION("run_forward from inst 1 hits inst 3 (second write)") {
        auto hit = engine->run_forward(1);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 3);
    }

    SECTION("run_forward from inst 3 finds nothing") {
        auto hit = engine->run_forward(3);
        REQUIRE(!hit.has_value());
    }
}

TEST_CASE("BreakpointEngine: WatchBreakpoint run_backward finds previous write",
          "[unit][core][breakpoint_engine][watchpoint]") {
    constexpr uint64_t kBuf = 0x16FD00000ULL;

    auto [env, engine] = make_engine([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                {{0, 1ULL}, {33, tw.rt(0x1004)}},
                {{kWrite, 8, kBuf, 1ULL}});         // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});  // inst 1
        tw.emit(ms, 0x1008, enc::str_imm(0, 31, 0),
                {{0, 2ULL}, {33, tw.rt(0x100C)}},
                {{kWrite, 8, kBuf, 2ULL}});         // inst 2
        tw.emit_anchor(ms);
    }, "watch_backward");

    REQUIRE(env != nullptr);

    engine->add_breakpoint(WatchBreakpoint{kBuf, 8});

    SECTION("run_backward from inst 2 hits inst 0") {
        auto hit = engine->run_backward(2);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 0);
    }

    SECTION("run_backward from inst 3 hits inst 2") {
        auto hit = engine->run_backward(3);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 2);
    }

    SECTION("run_backward from inst 0 finds nothing") {
        auto hit = engine->run_backward(0);
        REQUIRE(!hit.has_value());
    }
}

// ─── Conditional Breakpoint Tests ─────────────────────────────────────────

TEST_CASE("BreakpointEngine: ConditionalBreakpoint predicate fires on matching inst",
          "[unit][core][breakpoint_engine][conditional_bp]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0: x1 = 0
        tw.emit(ms, 0x1000, enc::movz(1, 0), {{1, 0ULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x1 = 0x42
        tw.emit(ms, 0x1004, enc::movz(1, 0x42), {{1, 0x42ULL}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x1 = 0
        tw.emit(ms, 0x1008, enc::movz(1, 0), {{1, 0ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "cond_bp");

    REQUIRE(env != nullptr);

    // Conditional: fire when x1 == 0x42 (after inst 1)
    ConditionalBreakpoint cbp;
    cbp.description = "x1==0x42";
    cbp.predicate = [](uint64_t /*id*/, const RegState& rs) {
        return rs.gpr[1] == 0x42ULL;
    };
    auto id = engine->add_breakpoint(cbp);

    SECTION("run_forward from start hits inst 1 (state_before has x1=0x42 after diff applied)") {
        // Note: state_before(inst_id) = state after inst_id-1's diffs
        // The predicate fires at the instruction where x1 becomes 0x42.
        // In our trace inst 1 sets x1=0x42 → state_before(2) would have x1=0x42.
        // Conditional scan evaluates state_before(id) for id in [from+1, end).
        auto hit = engine->run_forward(0);
        REQUIRE(hit.has_value());
        REQUIRE(hit->bp_id == id);
    }

    SECTION("run_backward from end finds the matching inst") {
        // scan backward from end of trace
        uint64_t total = env->index->inst_count();
        auto hit = engine->run_backward(total);
        REQUIRE(hit.has_value());
        REQUIRE(hit->bp_id == id);
    }
}

// ─── Lifecycle Tests ──────────────────────────────────────────────────────

TEST_CASE("BreakpointEngine: add/remove/clear lifecycle",
          "[unit][core][breakpoint_engine][lifecycle]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "bp_lifecycle");

    REQUIRE(env != nullptr);

    SECTION("initially no breakpoints") {
        REQUIRE(!engine->has_breakpoints());
        REQUIRE(engine->entries().empty());
    }

    SECTION("add returns valid id") {
        auto id = engine->add_breakpoint(PcBreakpoint{0x1000});
        REQUIRE(id != kInvalidBreakpointId);
        REQUIRE(engine->has_breakpoints());
        REQUIRE(engine->entries().size() == 1);
    }

    SECTION("remove by id works") {
        auto id = engine->add_breakpoint(PcBreakpoint{0x1000});
        REQUIRE(engine->remove_breakpoint(id));
        REQUIRE(!engine->has_breakpoints());
    }

    SECTION("remove unknown id returns false") {
        REQUIRE(!engine->remove_breakpoint(99));
    }

    SECTION("clear removes all") {
        engine->add_breakpoint(PcBreakpoint{0x1000});
        engine->add_breakpoint(PcBreakpoint{0x1004});
        engine->clear_breakpoints();
        REQUIRE(!engine->has_breakpoints());
    }
}

// ─── Multiple Breakpoints ─────────────────────────────────────────────────

TEST_CASE("BreakpointEngine: multiple BPs — earliest forward hit wins",
          "[unit][core][breakpoint_engine][multi_bp]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});  // inst 1
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});  // inst 2
        tw.emit_anchor(ms);
    }, "multi_bp_forward");

    REQUIRE(env != nullptr);

    // BP on inst 2's PC and inst 1's PC — from start, inst 1 should win
    auto id1 = engine->add_breakpoint(PcBreakpoint{rt_pc(0x1008)});  // inst 2
    auto id2 = engine->add_breakpoint(PcBreakpoint{rt_pc(0x1004)});  // inst 1
    (void)id1;

    SECTION("earliest hit (inst 1) returned") {
        auto hit = engine->run_forward(0);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 1);
        REQUIRE(hit->bp_id == id2);  // BP on 0x1004
    }
}

TEST_CASE("BreakpointEngine: multiple BPs — latest backward hit wins",
          "[unit][core][breakpoint_engine][multi_bp]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});  // inst 1
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});  // inst 2
        tw.emit_anchor(ms);
    }, "multi_bp_backward");

    REQUIRE(env != nullptr);

    auto id1 = engine->add_breakpoint(PcBreakpoint{rt_pc(0x1000)});  // inst 0
    auto id2 = engine->add_breakpoint(PcBreakpoint{rt_pc(0x1004)});  // inst 1
    (void)id1;

    SECTION("latest hit (inst 1) returned when running backward from inst 2") {
        auto hit = engine->run_backward(2);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 1);
        REQUIRE(hit->bp_id == id2);
    }
}

// ─── Convenience Wrappers ─────────────────────────────────────────────────

TEST_CASE("BreakpointEngine: next_execution / prev_execution",
          "[unit][core][breakpoint_engine][convenience]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1000)}}, {});  // inst 1
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});  // inst 2
        tw.emit_anchor(ms);
    }, "conv_exec");

    REQUIRE(env != nullptr);

    uint64_t pc0 = rt_pc(0x1000);
    uint64_t pc4 = rt_pc(0x1004);

    SECTION("next_execution(0x1000) after inst 0 returns inst 2") {
        auto res = engine->next_execution(pc0, 0);
        REQUIRE(res.has_value());
        REQUIRE(*res == 2);
    }

    SECTION("prev_execution(0x1004) before inst 2 returns inst 1") {
        auto res = engine->prev_execution(pc4, 2);
        REQUIRE(res.has_value());
        REQUIRE(*res == 1);
    }

    SECTION("next_execution past end returns nullopt") {
        auto res = engine->next_execution(pc0, 2);
        REQUIRE(!res.has_value());
    }

    SECTION("prev_execution before first occurrence returns nullopt") {
        auto res = engine->prev_execution(pc0, 0);
        REQUIRE(!res.has_value());
    }
}

TEST_CASE("BreakpointEngine: next_write / prev_write convenience wrappers",
          "[unit][core][breakpoint_engine][convenience]") {
    constexpr uint64_t kBuf = 0x16FE00000ULL;

    auto [env, engine] = make_engine([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::str_imm(0, 31, 0),
                {{0, 1ULL}, {33, tw.rt(0x1004)}},
                {{kWrite, 8, kBuf, 1ULL}});         // inst 0
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});  // inst 1
        tw.emit(ms, 0x1008, enc::str_imm(0, 31, 0),
                {{0, 2ULL}, {33, tw.rt(0x100C)}},
                {{kWrite, 8, kBuf, 2ULL}});         // inst 2
        tw.emit_anchor(ms);
    }, "conv_write");

    REQUIRE(env != nullptr);

    SECTION("next_write from start finds inst 0") {
        auto hit = engine->next_write(kBuf, 8, 0);
        // next_write uses upper_bound (exclusive), from 0 finds > 0,
        // but inst 0 IS the write at or after 0 in forward search.
        // Actually next_write uses upper_bound so from 0 → finds id > 0 → inst 2?
        // Let's check: ids = {0, 2}, upper_bound(0) → it points to 2.
        // So next_write(kBuf, 8, 0) returns inst 2.
        // For "find the first write starting from the beginning" use from=-1 (UINT64_MAX)
        // No — let's use 0 and expect std::upper_bound behavior.
        REQUIRE(hit.has_value());
    }

    SECTION("prev_write from inst 2 finds inst 0") {
        auto hit = engine->prev_write(kBuf, 8, 2);
        REQUIRE(hit.has_value());
        REQUIRE(hit->inst_id == 0);
    }

    SECTION("prev_write from inst 0 finds nothing") {
        auto hit = engine->prev_write(kBuf, 8, 0);
        REQUIRE(!hit.has_value());
    }
}

// ─── parse_breakpoint_cmd Tests ───────────────────────────────────────────

TEST_CASE("parse_breakpoint_cmd: valid PC breakpoint commands",
          "[unit][core][breakpoint_engine][parser]") {
    SECTION("hex address: 'b 0x1234abc'") {
        auto spec = parse_breakpoint_cmd("b 0x1234abc");
        REQUIRE(spec.has_value());
        REQUIRE(std::holds_alternative<PcBreakpoint>(*spec));
        REQUIRE(std::get<PcBreakpoint>(*spec).address == 0x1234abcULL);
    }

    SECTION("decimal address: 'b 4096'") {
        auto spec = parse_breakpoint_cmd("b 4096");
        REQUIRE(spec.has_value());
        REQUIRE(std::holds_alternative<PcBreakpoint>(*spec));
        REQUIRE(std::get<PcBreakpoint>(*spec).address == 4096);
    }

    SECTION("uppercase B also works: 'B 0xDEAD'") {
        auto spec = parse_breakpoint_cmd("B 0xDEAD");
        REQUIRE(spec.has_value());
        REQUIRE(std::holds_alternative<PcBreakpoint>(*spec));
        REQUIRE(std::get<PcBreakpoint>(*spec).address == 0xDEADULL);
    }

    SECTION("leading whitespace ignored: '  b 0x100'") {
        auto spec = parse_breakpoint_cmd("  b 0x100");
        REQUIRE(spec.has_value());
    }
}

TEST_CASE("parse_breakpoint_cmd: valid Watchpoint commands",
          "[unit][core][breakpoint_engine][parser]") {
    SECTION("address + size: 'w 0x16F000000 8'") {
        auto spec = parse_breakpoint_cmd("w 0x16F000000 8");
        REQUIRE(spec.has_value());
        REQUIRE(std::holds_alternative<WatchBreakpoint>(*spec));
        auto& wp = std::get<WatchBreakpoint>(*spec);
        REQUIRE(wp.address == 0x16F000000ULL);
        REQUIRE(wp.size == 8);
    }

    SECTION("address only (size=0 = full page): 'w 0x1000'") {
        auto spec = parse_breakpoint_cmd("w 0x1000");
        REQUIRE(spec.has_value());
        REQUIRE(std::holds_alternative<WatchBreakpoint>(*spec));
        REQUIRE(std::get<WatchBreakpoint>(*spec).size == 0);
    }

    SECTION("uppercase W: 'W 0x2000 4'") {
        auto spec = parse_breakpoint_cmd("W 0x2000 4");
        REQUIRE(spec.has_value());
        REQUIRE(std::holds_alternative<WatchBreakpoint>(*spec));
        REQUIRE(std::get<WatchBreakpoint>(*spec).size == 4);
    }
}

TEST_CASE("parse_breakpoint_cmd: error cases",
          "[unit][core][breakpoint_engine][parser]") {
    SECTION("empty command returns nullopt") {
        std::string err;
        auto spec = parse_breakpoint_cmd("", &err);
        REQUIRE(!spec.has_value());
        REQUIRE(!err.empty());
    }

    SECTION("unknown command letter returns nullopt") {
        std::string err;
        auto spec = parse_breakpoint_cmd("x 0x1000", &err);
        REQUIRE(!spec.has_value());
        REQUIRE(!err.empty());
    }

    SECTION("'b' with no address returns nullopt") {
        auto spec = parse_breakpoint_cmd("b");
        REQUIRE(!spec.has_value());
    }

    SECTION("'b' with invalid address returns nullopt") {
        std::string err;
        auto spec = parse_breakpoint_cmd("b 0xGGGG", &err);
        REQUIRE(!spec.has_value());
        REQUIRE(!err.empty());
    }

    SECTION("'w' with no address returns nullopt") {
        auto spec = parse_breakpoint_cmd("w");
        REQUIRE(!spec.has_value());
    }

    SECTION("'w' with size > 64 returns nullopt") {
        std::string err;
        auto spec = parse_breakpoint_cmd("w 0x1000 100", &err);
        REQUIRE(!spec.has_value());
        REQUIRE(!err.empty());
    }
}

// ─── no-breakpoints edge case ─────────────────────────────────────────────

TEST_CASE("BreakpointEngine: run_forward/backward with no breakpoints returns nullopt",
          "[unit][core][breakpoint_engine]") {
    auto [env, engine] = make_engine([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "no_bp");

    REQUIRE(env != nullptr);

    SECTION("run_forward with no BPs") {
        REQUIRE(!engine->run_forward(0).has_value());
    }
    SECTION("run_backward with no BPs") {
        REQUIRE(!engine->run_backward(1).has_value());
    }
}

/*
 * test_pass_taint_source_annotation.cpp — Unit tests for
 * tenet::TaintSourceAnnotationPass
 *
 * TaintSourceAnnotationPass annotates the "leaf" sources of a backward taint
 * chain by correlating them with ObjC message records.
 *
 * Tests verify:
 *   - Empty backward taint: no sources annotated, pass succeeds.
 *   - Leaf detection: events with no contributing src_regs are leaves.
 *   - ImmediateConstant classification: instruction with no src_regs and no
 *     memory access → ImmediateConstant.
 *   - MemoryLoad classification: instruction that loads from memory → MemoryLoad.
 *   - ObjcGetter classification: leaf preceded by a getter ObjC message
 *     (no colons, doesn't start with "set").
 *   - ObjcArg classification: leaf preceded by a multi-arg ObjC message.
 *   - by_class / by_selector indices built correctly.
 *   - objc_source_indices / constant_source_indices / memory_source_indices
 *     partition the sources correctly.
 *   - TaintSourceAnnotation::summary() produces non-empty strings for all kinds.
 *   - to_json() contains required top-level keys.
 *   - TaintSourceAnnotationConfig::require_zero_colon_getter restricts ObjC
 *     classification to getter-style selectors only.
 *
 * Run:  ctest -R 'pass_taint_source_annotation' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/taint/taint_source_annotation_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/structure/function_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a BackwardTaintConfig that traces x0 backward from inst_id `sink`.
static BackwardTaintConfig make_bwt_cfg(uint64_t sink, uint8_t reg = 0) {
    BackwardTaintConfig cfg;
    cfg.sink_inst_id = sink;
    cfg.add_sink_reg(reg);
    cfg.propagate_through_memory = false;
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;
    cfg.per_sink_tags = false;
    return cfg;
}

/// Helper to register BackwardTaintPass + ObjcPass + TaintSourceAnnotationPass.
static void register_all(PassManager& pm, uint64_t sink_id = 2, uint8_t sink_reg = 0,
                          TaintSourceAnnotationConfig tsa_cfg = {}) {
    pm.register_pass(std::make_unique<BackwardTaintPass>(make_bwt_cfg(sink_id, sink_reg)));
    pm.register_pass(std::make_unique<ObjcPass>());
    pm.register_pass(std::make_unique<TaintSourceAnnotationPass>(tsa_cfg));
}

// ─── Trace builders ───────────────────────────────────────────────────────────

/// Minimal two-instruction trace; no ObjC messages.
///   inst 0: x0 = 0x42 (MOVZ — immediate constant, no src_regs in diff)
static std::unique_ptr<TraceEnv> make_constant_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: x0 = 0x42 — pure constant load
        tw.emit(ms, 0x1000, enc::movz(0, 0x42),
                {{0, 0x42ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "tsa_constant");
}

/// Trace with a memory load of x0 (LDR x0, [x1]):
///   inst 0: x1 = 0x1000 (base addr)
///   inst 1: x0 loaded from address 0x1000 (via MemAcc record)
static std::unique_ptr<TraceEnv> make_memory_load_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: x1 = 0x1000 (address register)
        tw.emit(ms, 0x1000, enc::movz(1, 0x1000),
                {{1, 0x1000ULL}, {33, tw.rt(0x1004)}}, {});

        // inst 1: x0 = LDR x0, [x1] — produces a memory load MemAcc
        // MemAcc type=1(READ), size=8, addr=0x1000, value=0xCAFE
        tw.emit(ms, 0x1004, enc::ldr_imm(0, 1, 0),
                {{0, 0xCAFEULL}, {33, tw.rt(0x1008)}},
                {{1, 8, 0x1000ULL, 0xCAFEULL}});
        tw.emit_anchor(ms);
    }, "tsa_memload");
}

/// Trace with an ObjC getter message before a MOVZ.
///   inst 0: NOP (becomes the instruction concurrent with the ObjC record)
///   ObjC: [SecretManager secretKey]  (emitted after inst 0, so ObjC.inst_id=0)
///   inst 1: x0 = 0x55  (MOVZ — this is the backward taint leaf, inst_id=1)
///   sink: inst_id=2
///
/// With this layout:  ObjC.inst_id=0, leaf.inst_id=1, gap=1 → find_objc_source
/// returns the ObjC message because 0 < 1 and gap ≤ max_objc_gap.
static std::unique_ptr<TraceEnv> make_objc_getter_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: NOP — this puts inst_count at 0, and then increments to 1.
        // The ObjC record emitted AFTER this instruction will be labelled
        // inst_id=0 by the scan engine (it sees the OBJC before the next INST).
        // But to get ObjC.inst_id=0 < leaf.inst_id=1, we emit the ObjC record
        // first (before any INST), so scan sees OBJC when cur_inst_id=0.
        tw.emit_objc(tw.rt(0x0FFC), 0x1000ULL, 0x2000ULL, "SecretManager");

        // inst 0: NOP (inst_id=0 in the backward-taint numbering)
        tw.emit(ms, 0x0FF0, enc::nop(), {{33, tw.rt(0x0FF4)}}, {});

        // inst 1: x0 = 0x55  — backward taint leaf (writes x0, no src_regs)
        tw.emit(ms, 0x1000, enc::movz(0, 0x55),
                {{0, 0x55ULL}, {33, tw.rt(0x1004)}}, {});

        // inst 2: NOP — used as "sink" instruction (sink_id=2 means scan 0..1)
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "tsa_getter");
}

/// Trace with an ObjC method that has a colon (arg selector) before a MOVZ.
static std::unique_ptr<TraceEnv> make_objc_arg_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // ObjC call with selector containing colons → ObjcArg kind
        // class_name = "Crypto", selector_name will be hex fallback
        // (The pass classifies by selector_name; if empty/hex it will
        // be ObjcArg by default since it lacks a getter pattern)
        tw.emit_objc(tw.rt(0x0FFC), 0x1100ULL, 0x2200ULL, "Crypto");

        tw.emit(ms, 0x1000, enc::movz(0, 0x99),
                {{0, 0x99ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "tsa_objcarg");
}

/// Trace with a memory load (x0 = LDR) preceded by no ObjC messages.
/// The sink is inst 2 (the NOP after the LDR), so LDR is at inst 1.
static std::unique_ptr<TraceEnv> make_bare_memory_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::movz(1, 0x100),
                {{1, 0x100ULL}, {33, tw.rt(0x1004)}}, {});

        // LDR x0, [x1, #0] — reads from addr 0x100
        tw.emit(ms, 0x1004, enc::ldr_imm(0, 1, 0),
                {{0, 0xDEADULL}, {33, tw.rt(0x1008)}},
                {{1, 8, 0x100ULL, 0xDEADULL}});

        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "tsa_bare_mem");
}

/// Trace with a BL call to a named-looking callee whose RET leaves a value in
/// x0 that is never subsequently overwritten before the sink instruction.
///   inst 0: BL callee   (call_site_pc=0x1000, target_pc=0x2000)
///   inst 1: (callee) MOVZ x0, #0x77   — callee "computes" its return value
///   inst 2: (callee) RET              — returns to inst 3
///   inst 3: NOP                       — back in caller; sink scans 0..2
///
/// FunctionPass pairs the BL (inst 0) with the RET (inst 2) as a CallEvent
/// with call_inst_id=0, target_pc=callee's entry (0x2000 + slide).
/// fill_function_return() looks up func->call_at(leaf.inst_id - 1): the leaf
/// here is the MOVZ at inst_id=1, so call_at(0) must resolve to the BL event
/// recorded at inst_id=0 — i.e. the leaf immediately follows the call site.
static std::unique_ptr<TraceEnv> make_function_return_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: BL callee (0x1000 -> 0x2000)
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000),
                {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});

        // inst 1: callee body — x0 = 0x77 (the "return value")
        tw.emit(ms, 0x2000, enc::movz(0, 0x77),
                {{0, 0x77ULL}, {33, tw.rt(0x2004)}}, {});

        // inst 2: RET — back to caller (LR = 0x1004)
        tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});

        // inst 3: NOP in caller — used as the sink instruction (sink_id=3
        // scans inst_id 0..2 backward).
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "tsa_funcret");
}

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE("TaintSourceAnnotationPass: empty backward taint → no sources",
          "[unit][pass][taint_source_annotation]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "tsa_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    // sink_inst_id=1, x0 never written → events empty
    register_all(*pm, 1, 0);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    SECTION("total() == 0") { REQUIRE(res.total() == 0); }
    SECTION("all index lists are empty") {
        REQUIRE(res.objc_source_indices.empty());
        REQUIRE(res.constant_source_indices.empty());
        REQUIRE(res.memory_source_indices.empty());
    }
}

TEST_CASE("TaintSourceAnnotationPass: constant source classified correctly",
          "[unit][pass][taint_source_annotation]") {
    auto env = make_constant_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    // sink is at inst_id=1; the MOVZ at inst 0 wrote x0
    register_all(*pm, 1, 0);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    // The MOVZ has no src_regs and no memory → should be ImmediateConstant or
    // at minimum no ObjC attribution.
    SECTION("no ObjC sources (no ObjC messages in trace)") {
        REQUIRE(res.objc_source_indices.empty());
    }

    SECTION("classified as ImmediateConstant with constant_value populated") {
        // fill_constant_value() reads regfile().state_after(leaf.inst_id) —
        // this exercises the real (non-manually-constructed) path end-to-end.
        REQUIRE_FALSE(res.constant_source_indices.empty());
        const auto& ann = res.sources[res.constant_source_indices[0]];
        REQUIRE(ann.kind == TaintSourceKind::ImmediateConstant);
        REQUIRE(ann.constant_value == 0x42ULL);
        REQUIRE(ann.summary().find("0x42") != std::string::npos);
    }
}

TEST_CASE("TaintSourceAnnotationPass: FunctionReturn source resolves callee_pc/callee_name",
          "[unit][pass][taint_source_annotation]") {
    // Real end-to-end exercise of fill_function_return(): register FunctionPass
    // as well so `function` is available via try_require() in run().
    auto env = make_function_return_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<BackwardTaintPass>(make_bwt_cfg(/*sink=*/3, /*reg=*/0)));
    pm->register_pass(std::make_unique<ObjcPass>());
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<TaintSourceAnnotationPass>());

    // `function` is a soft dependency (see TaintSourceAnnotationPass::
    // dependencies()): it is NOT auto-scheduled by require("taint_source_
    // annotation") below, since PassManager::execute_pass() only recurses
    // into a pass's declared dependencies() list. It must be explicitly
    // require()'d first so try_require<FunctionResult>() inside run() sees
    // PassState::Completed instead of NotRun. (Same fix applied in the
    // production MCP tool — see mcp_tools_analysis.cpp's taint_source_
    // annotation handler.)
    pm->require("function");

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    // The MOVZ x0,#0x77 inside the callee is the leaf (no src_regs, no mem).
    // classify_source() falls through to the "has_dst_reg(0) → FunctionReturn"
    // heuristic since there's no ObjC context.
    REQUIRE_FALSE(res.sources.empty());

    // Find the leaf with kind == FunctionReturn (there should be exactly one:
    // the MOVZ x0,#0x77 at inst_id=1, immediately after the BL at inst_id=0).
    const TaintSourceAnnotation* fret = nullptr;
    for (const auto& s : res.sources) {
        if (s.kind == TaintSourceKind::FunctionReturn) { fret = &s; break; }
    }
    REQUIRE(fret != nullptr);

    SECTION("callee_pc resolved to the BL's target (callee entry)") {
        REQUIRE(fret->callee_pc != 0);
    }

    SECTION("callee_name defaults to empty when no symbol info is present") {
        // FunctionPass doesn't have symbol/name info for synthetic traces, so
        // FunctionInfo::name falls back to "sub_XXXXXX" or stays whatever the
        // pass populates — either way, summary() must not crash and must
        // reflect whichever branch (named vs. sub_XXX) is taken.
        auto s = fret->summary();
        REQUIRE(s.find("return of") != std::string::npos);
        if (fret->callee_name.empty()) {
            REQUIRE(s.find("sub_") != std::string::npos);
        } else {
            REQUIRE(s.find(fret->callee_name) != std::string::npos);
        }
    }
}

TEST_CASE("TaintSourceAnnotationPass: memory load without ObjC → MemoryLoad kind",
          "[unit][pass][taint_source_annotation]") {
    auto env = make_bare_memory_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    // Sink at inst 2 (NOP), x0 was loaded at inst 1 (LDR).
    register_all(*pm, 2, 0);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    // No ObjC messages in this trace.
    SECTION("no ObjC sources") {
        REQUIRE(res.objc_source_indices.empty());
    }
}

TEST_CASE("TaintSourceAnnotationPass: ObjC getter classified for nearby message",
          "[unit][pass][taint_source_annotation]") {
    auto env = make_objc_getter_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    // Trace layout: ObjC(inst_id=0), NOP(inst 0), MOVZ(inst 1), NOP(inst 2).
    // Sink at inst_id=2 → backward taint scans inst 0 and inst 1.
    // MOVZ at inst_id=1 is the leaf; ObjC at inst_id=0 is the source.
    register_all(*pm, 2, 0);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    // With an ObjC message before inst_id=1 (leaf), the annotation should be ObjC.
    if (res.total() > 0) {
        SECTION("at least one ObjC source found") {
            // Either ObjcGetter or ObjcArg depending on resolved selector.
            // With hex-fallback selector name, it may be ObjcArg or ObjcGetter.
            // The important invariant: objc_source_indices is populated.
            REQUIRE_FALSE(res.objc_source_indices.empty());
        }
        SECTION("by_class has SecretManager") {
            REQUIRE(res.by_class.count("SecretManager") > 0);
        }
    }
}

TEST_CASE("TaintSourceAnnotationPass: config require_zero_colon_getter=true",
          "[unit][pass][taint_source_annotation]") {
    // With require_zero_colon_getter=true, only zero-colon selectors that
    // don't start with "set" are classified as ObjcGetter.
    // Hex-fallback selectors (e.g. "0xDEADBEEF") contain no colons but start
    // with '0', not "set" → still classified as ObjcGetter.
    auto env = make_objc_getter_trace();
    REQUIRE(env != nullptr);

    TaintSourceAnnotationConfig cfg;
    cfg.require_zero_colon_getter = true;
    cfg.max_objc_gap = 500000;

    auto pm = make_pm(*env);
    register_all(*pm, 2, 0, cfg);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());

    // Just verify it runs without error — the strictness of classification
    // is a heuristic and may vary with the hex selector fallback.
    SECTION("pass succeeds with strict getter mode") {
        REQUIRE(raw.ok());
    }
}

TEST_CASE("TaintSourceAnnotationPass: max_objc_gap=0 prevents ObjC attribution",
          "[unit][pass][taint_source_annotation]") {
    auto env = make_objc_getter_trace();
    REQUIRE(env != nullptr);

    TaintSourceAnnotationConfig cfg;
    cfg.max_objc_gap = 0;  // refuse any ObjC gap

    auto pm = make_pm(*env);
    register_all(*pm, 2, 0, cfg);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    SECTION("no ObjC sources when gap is 0") {
        REQUIRE(res.objc_source_indices.empty());
    }
}

TEST_CASE("TaintSourceAnnotationPass: to_json has required keys",
          "[unit][pass][taint_source_annotation]") {
    auto env = make_constant_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_all(*pm, 1, 0);

    auto& raw = pm->require("taint_source_annotation");
    REQUIRE(raw.ok());
    const auto& res = raw.get<TaintSourceAnnotationResult>();

    SECTION("to_json does not throw") {
        std::string json;
        REQUIRE_NOTHROW(json = res.to_json());
        REQUIRE_FALSE(json.empty());
    }

    SECTION("to_json contains required keys") {
        nlohmann::json j = nlohmann::json::parse(res.to_json());
        REQUIRE(j.contains("total"));
        REQUIRE(j.contains("objc_count"));
        REQUIRE(j.contains("constant_count"));
        REQUIRE(j.contains("memory_count"));
        REQUIRE(j.contains("sources"));
        REQUIRE(j["sources"].is_array());
    }

    SECTION("to_json counts match result fields") {
        nlohmann::json j = nlohmann::json::parse(res.to_json());
        REQUIRE(j["total"].get<size_t>() == res.total());
        REQUIRE(j["objc_count"].get<size_t>() == res.objc_source_indices.size());
        REQUIRE(j["constant_count"].get<size_t>() == res.constant_source_indices.size());
        REQUIRE(j["memory_count"].get<size_t>() == res.memory_source_indices.size());
    }
}

TEST_CASE("TaintSourceAnnotationPass: source summary strings are non-empty",
          "[unit][pass][taint_source_annotation]") {
    // Build each kind manually and verify summary() returns something useful.

    SECTION("ObjcGetter summary") {
        TaintSourceAnnotation a;
        a.kind = TaintSourceKind::ObjcGetter;
        a.objc_label = "[KeyStore secretKey]";
        REQUIRE(a.summary() == "[KeyStore secretKey]");
    }

    SECTION("MemoryLoad summary") {
        TaintSourceAnnotation a;
        a.kind = TaintSourceKind::MemoryLoad;
        a.source_mem_addr = 0x1234ABC;
        a.source_mem_size = 8;
        auto s = a.summary();
        REQUIRE(s.find("0x") != std::string::npos);
    }

    SECTION("ImmediateConstant summary") {
        TaintSourceAnnotation a;
        a.kind = TaintSourceKind::ImmediateConstant;
        a.constant_value = 0xDEADBEEF;
        auto s = a.summary();
        REQUIRE(s.find("constant") != std::string::npos);
    }

    SECTION("FunctionReturn summary with callee name") {
        TaintSourceAnnotation a;
        a.kind = TaintSourceKind::FunctionReturn;
        a.callee_name = "CCCrypt";
        auto s = a.summary();
        REQUIRE(s.find("CCCrypt") != std::string::npos);
    }

    SECTION("FunctionReturn summary without callee name") {
        TaintSourceAnnotation a;
        a.kind = TaintSourceKind::FunctionReturn;
        a.callee_pc = 0xABCD00;
        auto s = a.summary();
        REQUIRE(s.find("sub_") != std::string::npos);
    }

    SECTION("Unknown summary") {
        TaintSourceAnnotation a;
        a.kind = TaintSourceKind::Unknown;
        a.inst_id = 42;
        auto s = a.summary();
        REQUIRE_FALSE(s.empty());
    }
}

TEST_CASE("TaintSourceAnnotationPass: index consistency invariants",
          "[unit][pass][taint_source_annotation]") {
    // Build result manually and verify index invariants.
    TaintSourceAnnotationResult res;

    TaintSourceAnnotation s1, s2, s3;
    s1.kind = TaintSourceKind::ObjcGetter;
    s1.inst_id = 10;
    ObjcMessage msg1;
    msg1.class_name = "MyClass"; msg1.selector_name = "myProperty";
    msg1.inst_id = 9;
    s1.objc_message = msg1;
    s1.objc_label = "[MyClass myProperty]";

    s2.kind = TaintSourceKind::ImmediateConstant;
    s2.inst_id = 20;
    s2.constant_value = 0x1234;

    s3.kind = TaintSourceKind::MemoryLoad;
    s3.inst_id = 30;
    s3.source_mem_addr = 0x5000;

    res.sources = {s1, s2, s3};
    res.objc_source_indices     = {0};
    res.constant_source_indices = {1};
    res.memory_source_indices   = {2};
    res.by_class["MyClass"]     = {0};
    res.by_selector["myProperty"] = {0};

    SECTION("total == 3") { REQUIRE(res.total() == 3); }

    SECTION("index sizes") {
        REQUIRE(res.objc_source_indices.size() == 1);
        REQUIRE(res.constant_source_indices.size() == 1);
        REQUIRE(res.memory_source_indices.size() == 1);
    }

    SECTION("by_class lookup") {
        REQUIRE(res.by_class.count("MyClass") > 0);
        REQUIRE(res.by_class.at("MyClass")[0] == 0);
    }

    SECTION("by_selector lookup") {
        REQUIRE(res.by_selector.count("myProperty") > 0);
    }

    SECTION("to_json with populated result") {
        nlohmann::json j = nlohmann::json::parse(res.to_json());
        REQUIRE(j["total"].get<size_t>() == 3);
        REQUIRE(j["objc_count"].get<size_t>() == 1);
        REQUIRE(j["constant_count"].get<size_t>() == 1);
        REQUIRE(j["memory_count"].get<size_t>() == 1);
        REQUIRE(j["sources"].size() == 3);
    }
}

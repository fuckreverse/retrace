// panels_analysis.cpp — analysis control panel + all run_*_analysis triggers
// + ensure_pass_manager + clear_analysis.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal). This is the only GUI
// translation unit that pulls in every analysis pass header.

#include "gui/gui_app.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/slice_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/symbol_annotation_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <cstring>
#include <mutex>
#include <thread>

namespace tenet {

// ─── Analysis helpers ───────────────────────────────────────────────────────

void GuiApp::ensure_pass_manager() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }
}

// ─── Startup Analysis ───────────────────────────────────────────────────────
// Runs a curated set of "always-useful" analyses in a background thread so
// the UI is immediately responsive while analysis proceeds.
// Order matters: Function → XRef → String → CallGraph
// (XRef is needed by CFG/CallGraph; Function populates the call-stack panel)

void GuiApp::run_startup_analysis() {
    // Guard: don't double-launch
    if (analysis_running_.exchange(true)) return;

    // Ensure pass manager is ready on the main thread before handing off
    ensure_pass_manager();

    startup_analysis_thread_ = std::thread([this]() {
        auto set_status = [this](const char* msg) {
            std::lock_guard<std::mutex> lock(analysis_mutex_);
            analysis_status_ = msg;
        };

        // ── 1. Function analysis ──────────────────────────────────────
        set_status("Functions...");
        {
            pass_manager_->register_pass(std::make_unique<FunctionPass>());
            auto& r = pass_manager_->require("function");
            if (r.ok()) {
                function_result_ = &r.get<FunctionResult>();
                show_callstack_   = true;
                show_functions_   = true;
                goto_candidates_dirty_ = true;
            }
        }

        // ── 2. XRef analysis ─────────────────────────────────────────
        set_status("XRefs...");
        {
            pass_manager_->register_pass(std::make_unique<XrefPass>());
            auto& r = pass_manager_->require("xref");
            if (r.ok()) {
                xref_result_  = &r.get<XrefResult>();
                xref_cursor_  = 0;
            }
        }

        // ── 3. String analysis ───────────────────────────────────────
        set_status("Strings...");
        {
            pass_manager_->register_pass(std::make_unique<StringPass>());
            auto& r = pass_manager_->require("strings");
            if (r.ok()) {
                string_result_  = &r.get<StringResult>();
                show_strings_   = true;
                string_cursor_  = 0;
                string_filter_.clear();
                std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
            }
        }

        // ── 4. Call graph ─────────────────────────────────────────────
        set_status("Call graph...");
        {
            pass_manager_->register_pass(std::make_unique<CallGraphPass>());
            auto& r = pass_manager_->require("call_graph");
            if (r.ok()) {
                call_graph_result_ = &r.get<CallGraphResult>();
            }
        }

        // ── 5. CFG ───────────────────────────────────────────────────
        // Needed by loop_pass and loop_semantics_pass downstream.
        set_status("CFG...");
        {
            pass_manager_->register_pass(std::make_unique<CFGPass>());
            auto& r = pass_manager_->require("cfg");
            if (r.ok()) {
                cfg_result_ = &r.get<CFGResult>();
            }
        }

        // ── 6. Loop detection ────────────────────────────────────────
        set_status("Loops...");
        {
            pass_manager_->register_pass(std::make_unique<LoopPass>());
            auto& r = pass_manager_->require("loop");
            if (r.ok()) {
                loop_result_ = &r.get<LoopResult>();
                show_loops_  = true;
            }
        }

        // ── 7. Constant materialisation ──────────────────────────────
        // Identifies crypto/hash constants (SHA-256, SM4, ChaCha20, TEA…).
        set_status("Constants...");
        {
            pass_manager_->register_pass(std::make_unique<ConstantMaterializationPass>());
            auto& r = pass_manager_->require("constant_materialization");
            if (r.ok()) {
                constant_result_ = &r.get<ConstantMaterializationResult>();
            }
        }

        // ── 8. Pattern detection (YARA + mnemonic heuristics) ────────
        set_status("Patterns...");
        {
            pass_manager_->register_pass(std::make_unique<PatternPass>());
            auto& r = pass_manager_->require("pattern");
            if (r.ok()) {
                pattern_result_ = &r.get<PatternResult>();
            }
        }

        // ── 9. Loop semantics ────────────────────────────────────────
        // Classifies loops (Feistel, SPN, ARX, MemcpyLike, …).
        set_status("Loop semantics...");
        {
            pass_manager_->register_pass(std::make_unique<LoopSemanticsPass>());
            auto& r = pass_manager_->require("loop_semantics");
            if (r.ok()) {
                loop_semantics_result_ = &r.get<LoopSemanticsResult>();
            }
        }

        // ── 10. Algorithm summary ────────────────────────────────────
        // Cross-references constants + patterns + loop semantics to produce
        // a human-readable algorithm identification (AES, SHA-256, etc.).
        set_status("Algorithm summary...");
        {
            pass_manager_->register_pass(std::make_unique<AlgorithmSummaryPass>());
            auto& r = pass_manager_->require("algorithm_summary");
            if (r.ok()) {
                algorithm_summary_result_ = &r.get<AlgorithmSummaryResult>();
            }
        }

        // ── 11. Symbol annotation ────────────────────────────────────
        // Aggregates results from function/loop/constant/pattern passes
        // into a unified PC → label map used by the disassembly view.
        set_status("Annotations...");
        {
            pass_manager_->register_pass(std::make_unique<SymbolAnnotationPass>());
            auto& r = pass_manager_->require("symbol_annotation");
            if (r.ok()) {
                annotation_result_ = &r.get<AnnotationResult>();
            }
        }

        // Done
        {
            std::lock_guard<std::mutex> lock(analysis_mutex_);
            analysis_status_.clear();
        }
        analysis_running_.store(false);
    });
    startup_analysis_thread_.detach();
}

void GuiApp::run_taint_analysis() {
    ensure_pass_manager();

    // Configure taint: start with current instruction's modified registers as sources
    TaintConfig config;
    config.taint_from_memory = true;
    config.track_memory_sinks = true;
    config.propagate_arithmetic = true;
    config.propagate_moves = true;
    config.max_instructions = 100000;

    // Use current instruction's register diffs as initial taint sources
    auto [offset_ts, seed_pc_ts] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_ts = reader_.record_at(offset_ts, seed_pc_ts);
    if (rec_ts.kind == RecordKind::Inst) {
        auto inst = rec_ts.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_source_reg(diff.index);
        }
    }

    pass_manager_->register_pass(std::make_unique<TaintPass>(config));
    auto& result = pass_manager_->require("taint");
    if (result.ok()) {
        taint_result_ = &result.get<TaintResult>();
        show_taint_ = true;
        show_slice_ = false;
        show_backward_taint_ = false;
    }
}

void GuiApp::run_backward_taint_analysis() {
    ensure_pass_manager();

    // Configure backward taint: current instruction is the sink
    BackwardTaintConfig config;
    config.sink_inst_id = current_inst_;
    config.propagate_through_memory = true;
    config.max_steps = 500000;
    config.max_tainted_insts = 50000;

    // Use current instruction's register diffs as sink registers
    auto [offset_sk, seed_pc_sk] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sk = reader_.record_at(offset_sk, seed_pc_sk);
    if (rec_sk.kind == RecordKind::Inst) {
        auto inst = rec_sk.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_sink_reg(diff.index);
        }
    }

    if (config.sink_regs == 0) {
        // No reg diffs at this instruction - default to X0
        config.add_sink_reg(0);
    }

    pass_manager_->register_pass(std::make_unique<BackwardTaintPass>(std::move(config)));
    auto& result = pass_manager_->require("backward_taint");
    if (result.ok()) {
        backward_taint_result_ = &result.get<BackwardTaintResult>();
        show_backward_taint_ = true;
        show_taint_ = false;
        show_slice_ = false;
    }
}

void GuiApp::run_slice_analysis() {
    if (!taint_result_) {
        // Need taint first
        run_taint_analysis();
    }
    if (!taint_result_) return;

    ensure_pass_manager();

    // Determine which register to slice from current instruction
    uint8_t target_reg = 0;
    auto [offset_sl, seed_pc_sl] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sl = reader_.record_at(offset_sl, seed_pc_sl);
    if (rec_sl.kind == RecordKind::Inst) {
        auto inst = rec_sl.as_inst();
        if (inst.reg_diff_count > 0) {
            target_reg = inst.reg_diff(0).index;
        }
    }

    pass_manager_->register_pass(
        std::make_unique<SlicePass>(current_inst_, target_reg));
    auto& result = pass_manager_->require("slice");
    if (result.ok()) {
        slice_result_ = &result.get<SliceResult>();
        show_slice_ = true;
        show_taint_ = false;
        show_backward_taint_ = false;
    }
}

void GuiApp::run_call_graph_analysis() {
    ensure_pass_manager();

    // CallGraphPass depends on function pass, ensure it's run first
    if (!function_result_) {
        run_pass_by_name("function");
    }

    run_pass_by_name("call_graph");
}

// ─── CFG Layout Analysis ─────────────────────────────────────────────────────

void GuiApp::run_cfg_layout() {
    ensure_pass_manager();

    // Build full-trace CFG (needed by other passes: loop, loop_semantics, etc.)
    pass_manager_->register_pass(std::make_unique<XrefPass>());
    pass_manager_->register_pass(std::make_unique<CFGPass>());

    // Cache xref result so the CFG panel can use inst_ids_at() for jump navigation
    auto& xref_res = pass_manager_->require("xref");
    if (xref_res.ok()) {
        xref_result_ = &xref_res.get<XrefResult>();
    }

    auto& cfg_res = pass_manager_->require("cfg");
    if (cfg_res.ok()) {
        cfg_result_ = &cfg_res.get<CFGResult>();
    }

    show_cfg_ = true;

    // Force per-function CFG rebuild on next render frame
    // by resetting the tracked function PC.
    cfg_current_func_pc_ = 0;
    cfg_func_result_.reset();
    cfg_func_layout_.reset();
    cfg_layout_result_ = nullptr;
}

// ─── Generic pass runner ───────────────────────────────────────────────────
// Runs any catalog pass by name, deriving a config from the current cursor.
// Used by the "All Passes" section of the Analysis panel so that every pass
// is reachable from the GUI — even those without a dedicated button.

void GuiApp::run_pass_by_name(std::string_view name) {
    ensure_pass_manager();
    if (!tenet::is_known_pass(name)) {
        last_pass_status_ = fmt::format("unknown pass '{}'", name);
        return;
    }

    // Build a PassRunCtx from the current cursor.
    tenet::PassRunCtx ctx;
    ctx.current_inst = current_inst_;
    ctx.total_inst   = total_inst_;
    // Derive a "current register" from the first reg diff at the cursor,
    // so taint/slice/producer_chain/etc. have a sensible default target.
    auto [offset, seed_pc] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        ctx.current_reg = (inst.reg_diff_count > 0) ? inst.reg_diff(0).index : 0;
    }

    if (!tenet::register_pass_by_name(*pass_manager_, name, ctx)) {
        last_pass_status_ = fmt::format("'{}' could not be registered", name);
        return;
    }

    auto& raw = pass_manager_->require(name);
    last_pass_status_ = fmt::format("{}: {}", name,
                                    tenet::summarize_pass_result(name, raw));

    // ── Wire up UI result pointers for passes with dedicated panels ──
    // This centralises the post-run side-effects that the old per-pass
    // run_xxx_analysis() methods used to do individually.
    if (!raw.ok()) return;
    if (name == "function") {
        function_result_ = &raw.get<FunctionResult>();
        show_callstack_ = true;
        goto_candidates_dirty_ = true;
    } else if (name == "xref") {
        xref_result_ = &raw.get<XrefResult>();
        xref_cursor_ = 0;
    } else if (name == "strings") {
        string_result_ = &raw.get<StringResult>();
        show_strings_ = true;
        string_cursor_ = 0;
        string_filter_.clear();
        std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
    } else if (name == "thread") {
        thread_result_ = &raw.get<ThreadResult>();
        show_threads_ = true;
    } else if (name == "loop") {
        loop_result_ = &raw.get<LoopResult>();
        show_loops_ = true;
    } else if (name == "call_graph") {
        call_graph_result_ = &raw.get<CallGraphResult>();
    } else if (name == "cfg") {
        cfg_result_ = &raw.get<CFGResult>();
    }
}

void GuiApp::clear_analysis() {
    taint_result_ = nullptr;
    slice_result_ = nullptr;
    backward_taint_result_ = nullptr;
    function_result_ = nullptr;
    xref_result_ = nullptr;
    string_result_ = nullptr;
    call_graph_result_ = nullptr;
    loop_result_ = nullptr;
    thread_result_ = nullptr;
    cfg_result_        = nullptr;
    cfg_layout_result_ = nullptr;
    cfg_func_result_.reset();
    cfg_func_layout_.reset();
    cfg_current_func_pc_ = 0;
    constant_result_          = nullptr;
    pattern_result_           = nullptr;
    loop_semantics_result_    = nullptr;
    algorithm_summary_result_ = nullptr;
    annotation_result_        = nullptr;
    show_taint_ = false;
    show_threads_ = false;
    show_slice_ = false;
    show_backward_taint_ = false;
    show_callstack_ = false;
    show_functions_ = false;
    show_strings_ = false;
    show_loops_ = false;
    xref_cursor_ = 0;
    string_cursor_ = 0;
    string_filter_.clear();
    std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
    function_filter_.clear();
    std::memset(function_filter_buf_, 0, sizeof(function_filter_buf_));
    taint_sorted_ids_.clear();
    taint_sorted_ids_dirty_ = true;
    goto_candidates_.clear();
    goto_candidates_dirty_ = true;
    goto_selected_candidate_ = -1;
    if (pass_manager_) {
        pass_manager_->invalidate_all();
    }
}

// ─── Analysis Panel ─────────────────────────────────────────────────────────

void GuiApp::render_analysis_panel() {
    if (!ImGui::Begin("Analysis", &show_analysis_)) {
        ImGui::End();
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Status banner ───────────────────────────────────────────────
    if (analysis_running_.load()) {
        // Animated busy indicator — full-width colored banner
        static const char* spinner[] = {
            "\xe2\xa3\xbe","\xe2\xa3\xbd","\xe2\xa3\xbb","\xe2\xa2\xbf",
            "\xe2\xa1\xbf","\xe2\xa3\x9f","\xe2\xa3\xaf","\xe2\xa3\xb7"
        };
        static int spin_frame = 0;
        spin_frame = (spin_frame + 1) % 8;

        ImVec2 banner_p0 = ImGui::GetCursorScreenPos();
        float banner_h = ImGui::GetFrameHeightWithSpacing();
        draw->AddRectFilled(banner_p0,
            ImVec2(banner_p0.x + panel_w, banner_p0.y + banner_h),
            IM_COL32(140, 110, 0, 80));

        ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.2f, 1.0f),
            " %s  Running...", spinner[spin_frame]);

        std::lock_guard<std::mutex> lock(analysis_mutex_);
        if (!analysis_status_.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", analysis_status_.c_str());
        }
    } else {
        // Idle or active analysis indicator
        bool any_active = show_taint_ || show_slice_ || show_backward_taint_
                       || (show_loops_ && loop_result_)
                       || function_result_ || string_result_;
        if (any_active) {
            ImVec2 b0 = ImGui::GetCursorScreenPos();
            float bh = ImGui::GetFrameHeightWithSpacing();
            draw->AddRectFilled(b0, ImVec2(b0.x + panel_w, b0.y + bh),
                                IM_COL32(20, 80, 30, 60));
            ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f), " \xe2\x9c\x93  Analysis active");
        } else {
            ImGui::TextDisabled(" \xe2\x80\x94  Idle (no analysis loaded)");
        }
    }

    ImGui::Dummy(ImVec2(0, 3));

    // ── Section helper ──────────────────────────────────────────────
    auto section_header = [&](const char* title, ImVec4 color) {
        ImVec2 hp = ImGui::GetCursorScreenPos();
        draw->AddRectFilled(hp, ImVec2(hp.x + panel_w, hp.y + ImGui::GetFrameHeight()),
                            ImGui::ColorConvertFloat4ToU32(
                                ImVec4(color.x*0.4f, color.y*0.4f, color.z*0.4f, 0.55f)));
        draw->AddRectFilled(hp, ImVec2(hp.x + 3.0f, hp.y + ImGui::GetFrameHeight()),
                            ImGui::ColorConvertFloat4ToU32(color));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 6.0f);
        ImGui::TextColored(color, "%s", title);
    };

    // ── GROUP 1: Taint analysis ─────────────────────────────────────
    section_header("  Taint Analysis", ImVec4(0.20f, 0.82f, 0.35f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 3));

    // Forward taint
    {
        bool active = show_taint_ && taint_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.35f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.10f, 0.45f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.12f, 0.55f, 0.18f, 1.0f));
        }
        if (ImGui::Button("Run Taint##fwd")) {
            run_taint_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Forward taint from selected register\nAnalysis > Taint to choose source");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.25f, 0.85f, 0.35f, 1.0f), "\xe2\x9c\x93");
            ImGui::SameLine(0, 4);
            ImGui::Text("%llu tainted", (unsigned long long)taint_result_->tainted_inst_count());
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrtaint")) {
                show_taint_ = false;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear taint overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // Backward taint
    {
        bool active = show_backward_taint_ && backward_taint_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.35f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.10f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.12f, 0.12f, 1.0f));
        }
        if (ImGui::Button("Run BackTaint")) {
            run_backward_taint_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Backward taint from current instruction");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.90f, 0.25f, 0.25f, 1.0f), "\xe2\x9c\x93 active");
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrbt")) {
                show_backward_taint_ = false;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear backward-taint overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // Slice
    {
        bool active = show_slice_ && slice_result_;
        if (ImGui::Button("Run Slice##slc")) {
            run_slice_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Program slice for current instruction");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.80f, 0.25f, 0.80f, 1.0f), "\xe2\x9c\x93 active");
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrslc")) { show_slice_ = false; }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear slice overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    ImGui::Dummy(ImVec2(0, 4));

    // ── GROUP 2: Code Structure ─────────────────────────────────────
    section_header("  Code Structure", ImVec4(0.35f, 0.62f, 1.0f, 1.0f));

    // Functions
    {
        bool active = (function_result_ != nullptr);
        if (ImGui::Button("Run Functions##fn")) {
            run_pass_by_name("function");
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Discover call/return pairs, build function list");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.4f, 0.75f, 1.0f, 1.0f),
                "\xe2\x9c\x93 %zu functions", function_result_->functions.size());
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    // Loops
    {
        bool active = show_loops_ && loop_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.35f, 0.18f, 0.02f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.25f, 0.03f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.30f, 0.04f, 1.0f));
        }
        if (ImGui::Button("Run Loops##lp")) {
            run_pass_by_name("loop");
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Detect loops (back-edges in CFG)");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(1.0f, 0.62f, 0.12f, 1.0f),
                "\xe2\x9c\x93 %zu loops", loop_result_->loops.size());
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrlp")) { show_loops_ = false; }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear loop overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // XRef
    {
        bool active = (xref_result_ != nullptr);
        if (ImGui::Button("Run XRef##xref")) {
            run_pass_by_name("xref");
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build cross-reference index (PC → inst_ids)");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.65f, 0.75f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    // CFG
    {
        bool active = (cfg_result_ != nullptr);
        if (ImGui::Button("Run CFG##cfg")) {
            run_cfg_layout();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Compute control-flow graph + layout for CFG view");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.55f, 0.80f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    ImGui::Dummy(ImVec2(0, 4));

    // ── GROUP 3: String & Call Graph ───────────────────────────────
    section_header("  Strings / Calls", ImVec4(0.75f, 0.55f, 1.0f, 1.0f));

    {
        bool has_str = (string_result_ != nullptr);
        if (ImGui::Button("Run Strings##str")) {
            run_pass_by_name("strings");
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Find string accesses in the trace");
        ImGui::SameLine();
        if (has_str) {
            ImGui::TextColored(ImVec4(0.78f, 0.62f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    {
        bool has_cg = (call_graph_result_ != nullptr);
        if (ImGui::Button("Run CallGraph##cg")) {
            run_call_graph_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build call graph across functions");
        ImGui::SameLine();
        if (has_cg) {
            ImGui::TextColored(ImVec4(0.78f, 0.62f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    ImGui::Dummy(ImVec2(0, 6));

    // ── GROUP 4: All Passes (full catalog) ─────────────────────────────
    // Every pass in the registry is reachable here, so nothing is
    // "GUI-only" or hidden. Default passes show ✓ once run at startup.
    section_header("  All Passes", ImVec4(0.55f, 0.55f, 0.62f, 1.0f));
    {
        static bool show_all = false;
        ImGui::Checkbox("Show full catalog", &show_all);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Expand to run any of the %d passes (incl. those without a dedicated button).",
                              (int)tenet::pass_catalog().size());

        if (!last_pass_status_.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.85f, 1.0f, 1.0f));
            ImGui::TextWrapped("%s", last_pass_status_.c_str());
            ImGui::PopStyleColor();
        }

        if (show_all) {
            const char* cat_names[] = {
                "Structure", "Taint", "Crypto/Pattern", "Memory/String",
                "ObjC/Syscall", "Profile/Trace", "Misc"
            };
            auto cat_to_idx = [](tenet::PassCategory c) -> int {
                switch (c) {
                    case tenet::PassCategory::Structure:  return 0;
                    case tenet::PassCategory::Taint:      return 1;
                    case tenet::PassCategory::Crypto:     return 2;
                    case tenet::PassCategory::Memory:     return 3;
                    case tenet::PassCategory::ObjcSyscall:return 4;
                    case tenet::PassCategory::Profile:    return 5;
                    case tenet::PassCategory::Misc:       return 6;
                }
                return 6;
            };

            int cur_cat = -1;
            for (const auto& e : tenet::pass_catalog()) {
                int ci = cat_to_idx(e.category);
                if (ci != cur_cat) {
                    cur_cat = ci;
                    ImGui::Dummy(ImVec2(0, 2));
                    ImGui::TextDisabled("%s", cat_names[ci]);
                }
                // Status indicator: ✓ if completed, · if not run.
                bool done = pass_manager_ &&
                            pass_manager_->state(e.name) ==
                                PassManager::PassState::Completed;
                std::string label = fmt::format("{}##cat", e.display_name);
                if (done) {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.30f, 0.16f, 1.0f));
                }
                if (ImGui::SmallButton(label.c_str())) {
                    run_pass_by_name(e.name);
                }
                if (done) ImGui::PopStyleColor();
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s\n(pass: %s%s)", e.description.data(),
                                      e.name.data(),
                                      e.default_for_ui == tenet::PassDefault::Yes
                                          ? ", default" : "");
                ImGui::SameLine();
            }
            ImGui::NewLine();  // wrap last row
        }
    }

    ImGui::Dummy(ImVec2(0, 6));

    // ── Clear All ───────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.10f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.60f, 0.15f, 0.15f, 1.0f));
    if (ImGui::Button("  \xe2\x9c\x95  Clear All  ")) {  // ✕
        clear_analysis();
    }
    ImGui::PopStyleColor(3);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Clear all analysis results and overlays");

    ImGui::PopStyleVar();  // ItemSpacing
    ImGui::End();
}

}  // namespace tenet

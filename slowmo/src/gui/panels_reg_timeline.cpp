// panels_reg_timeline.cpp — P2-12 Register Timeline Panel
//
// Displays a sparkline of a selected register's value over time, lets the user
// pick which register to track, jump to any write event, and also shows the
// producer-chain for any register at the current instruction.
//
// Pure C++ (no ObjC/Metal). References GuiApp members declared in gui_app.h.

#include "gui/gui_app.h"
#include "analysis/passes/profile/reg_timeline_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <thread>

namespace tenet {

// ─── reg_name helper (local copy, avoids circular include) ───────────────────
static const char* reg_name_str(uint8_t idx) {
    static const char* names[] = {
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9",
        "x10","x11","x12","x13","x14","x15","x16","x17","x18","x19",
        "x20","x21","x22","x23","x24","x25","x26","x27","x28",
        "fp","lr","sp","nzcv","pc"
    };
    if (idx < 34) return names[idx];
    return "??";
}

// ─── rebuild_reg_timeline ────────────────────────────────────────────────────
//
// Samples the register write history for reg_idx from the index.
// Stores at most kMaxSamples points so the sparkline doesn't stutter.
// Runs synchronously (called from UI thread during panel render, but
// only triggered once per reg change and cached thereafter).

static constexpr size_t kMaxSamples = 2048;

void GuiApp::rebuild_reg_timeline(uint8_t reg_idx) {
    reg_timeline_dirty_ = false;
    reg_timeline_data_.clear();
    reg_timeline_reg_ = reg_idx;

    if (total_inst_ == 0) return;

    // Use the RegTimelinePass to collect all writes.
    // We run it inline (blocking) with a capped entry limit for speed.
    ensure_pass_manager();

    RegTimelineConfig cfg;
    cfg.target_reg  = reg_idx;
    cfg.max_entries = 200000; // safety cap
    cfg.start_inst_id = 0;
    cfg.end_inst_id   = total_inst_;

    auto pass = std::make_unique<RegTimelinePass>(cfg);
    PassManager pm;
    pm.set_reader(&reader_);
    pm.set_index(&index_);
    pm.set_code_table(&code_table_);
    pm.set_regfile(&regfile_);
    pm.set_memory(&memory_);
    pm.set_decoder(&decoder_);
    pm.register_pass(std::move(pass));
    const auto& result = pm.require("reg_timeline");
    if (!result.ok()) return;

    const auto& tl = result.get<RegTimelineResult>();
    if (tl.entries.empty()) return;

    // Sub-sample to kMaxSamples if needed
    size_t n = tl.entries.size();
    size_t step = std::max(n / kMaxSamples, size_t(1));
    reg_timeline_data_.reserve(std::min(n, kMaxSamples));

    for (size_t i = 0; i < n; i += step) {
        const auto& e = tl.entries[i];
        reg_timeline_data_.push_back({e.inst_id, e.new_value});
    }
}

// ─── run_producer_chain ──────────────────────────────────────────────────────
//
// "Producer chain" in the UI is a quick-preview backward data-flow trace:
// given (inst_id, reg), find the instructions that contributed to that
// register's value. This used to run a bespoke, hand-rolled instruction
// decoder (ProducerChainPass) that mis-parsed several common AArch64
// encodings (LDP, ADRP+ADD, three-operand ops) and only ever followed a
// single source register per step. It has been replaced by BackwardTaintPass
// run in a capped "quick" mode — same underlying engine as the Taint menu,
// just with a small step budget so it stays snappy for interactive use.
// Caches the resulting inst_ids in producer_chain_ids_ so the instruction
// panel can highlight them.

void GuiApp::run_producer_chain(uint64_t inst_id, uint8_t reg_idx) {
    producer_chain_ids_.clear();
    show_producer_chain_ = false;
    producer_chain_start_inst_ = inst_id;
    producer_chain_reg_        = reg_idx;

    ensure_pass_manager();

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = inst_id;
    cfg.add_sink_reg(reg_idx);
    cfg.propagate_through_memory = true;
    cfg.cross_function = false;      // quick local preview, not a full trace
    cfg.build_dataflow_graph = false;
    cfg.per_sink_tags = false;
    cfg.max_steps = 2000;            // keep it fast for interactive UI use
    cfg.max_tainted_insts = 2000;

    auto pass = std::make_unique<BackwardTaintPass>(cfg);
    PassManager pm;
    pm.set_reader(&reader_);
    pm.set_index(&index_);
    pm.set_code_table(&code_table_);
    pm.set_regfile(&regfile_);
    pm.set_memory(&memory_);
    pm.set_decoder(&decoder_);
    pm.register_pass(std::move(pass));
    const auto& result = pm.require("backward_taint");
    if (!result.ok()) return;

    const auto& bt = result.get<BackwardTaintResult>();
    producer_chain_ids_.reserve(bt.contributing_count());
    for (auto it = bt.contributing_inst_ids.begin(); it != bt.contributing_inst_ids.end(); ++it) {
        producer_chain_ids_.push_back(*it);
    }
    // Sort so binary_search in instruction panel works correctly
    std::sort(producer_chain_ids_.begin(), producer_chain_ids_.end());
    show_producer_chain_ = !producer_chain_ids_.empty();
}

// ─── render_reg_timeline_panel ───────────────────────────────────────────────

void GuiApp::render_reg_timeline_panel() {
    if (!show_reg_timeline_) return;

    ImGui::SetNextWindowSize(ImVec2(640, 320), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Register Timeline##P212", &show_reg_timeline_)) {
        ImGui::End();
        return;
    }

    // ── Header: register picker ──────────────────────────────────────────
    ImGui::TextDisabled("Track register:");
    ImGui::SameLine();

    // Combo with all 34 AArch64 registers
    const char* cur_name = reg_name_str(reg_timeline_reg_);
    ImGui::SetNextItemWidth(80.0f);
    if (ImGui::BeginCombo("##regtl_reg", cur_name)) {
        for (uint8_t i = 0; i < 34; i++) {
            bool sel = (reg_timeline_reg_ == i);
            if (ImGui::Selectable(reg_name_str(i), sel)) {
                if (i != reg_timeline_reg_) {
                    reg_timeline_dirty_ = true;
                }
                reg_timeline_reg_ = i;
            }
            if (sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine(0, 8);
    if (ImGui::Button("Refresh")) {
        reg_timeline_dirty_ = true;
    }

    // Lazy build: only re-scan when dirty
    if (reg_timeline_dirty_) {
        rebuild_reg_timeline(reg_timeline_reg_);
    }

    ImGui::SameLine(0, 16);
    if (!reg_timeline_data_.empty()) {
        ImGui::TextDisabled("%zu write events", reg_timeline_data_.size());
    } else {
        ImGui::TextDisabled("No writes found");
    }

    ImGui::Separator();

    if (reg_timeline_data_.empty()) {
        ImGui::TextDisabled("Register %s was never written in this trace.", cur_name);
        ImGui::End();
        return;
    }

    // ── Sparkline canvas ─────────────────────────────────────────────────
    //
    // We draw the sparkline manually using ImDrawList so we can:
    //   1. Map inst_id → X position
    //   2. Map value   → Y position (normalised)
    //   3. Highlight the current instruction with a vertical cursor bar
    //   4. Show a hover tooltip with exact value / inst_id

    const ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    const float  canvas_w   = ImGui::GetContentRegionAvail().x;
    const float  canvas_h   = 180.0f;

    ImGui::InvisibleButton("##regtl_canvas", ImVec2(canvas_w, canvas_h));
    const bool hovered = ImGui::IsItemHovered();

    ImDrawList* dl = ImGui::GetWindowDrawList();

    // Background
    dl->AddRectFilled(canvas_pos,
                      ImVec2(canvas_pos.x + canvas_w, canvas_pos.y + canvas_h),
                      IM_COL32(18, 20, 30, 255));
    dl->AddRect(canvas_pos,
                ImVec2(canvas_pos.x + canvas_w, canvas_pos.y + canvas_h),
                IM_COL32(55, 60, 90, 255));

    // Compute value range
    uint64_t vmin = reg_timeline_data_[0].value;
    uint64_t vmax = reg_timeline_data_[0].value;
    for (const auto& pt : reg_timeline_data_) {
        if (pt.value < vmin) vmin = pt.value;
        if (pt.value > vmax) vmax = pt.value;
    }
    bool all_same = (vmin == vmax);

    uint64_t id_min = reg_timeline_data_.front().inst_id;
    uint64_t id_max = reg_timeline_data_.back().inst_id;
    if (id_max == id_min) id_max = id_min + 1;

    auto to_px = [&](const RegTimelinePoint& pt) -> ImVec2 {
        float x = canvas_pos.x + (float)(pt.inst_id - id_min) / (id_max - id_min) * canvas_w;
        float y;
        if (all_same) {
            y = canvas_pos.y + canvas_h * 0.5f;
        } else {
            y = canvas_pos.y + canvas_h - (float)(pt.value - vmin) / (vmax - vmin) * canvas_h;
            y = std::max(canvas_pos.y + 2.0f, std::min(canvas_pos.y + canvas_h - 2.0f, y));
        }
        return ImVec2(x, y);
    };

    // Grid lines (horizontal)
    for (int row = 0; row <= 4; row++) {
        float y = canvas_pos.y + canvas_h * row / 4.0f;
        dl->AddLine(ImVec2(canvas_pos.x, y),
                    ImVec2(canvas_pos.x + canvas_w, y),
                    IM_COL32(35, 38, 60, 200), 0.5f);
    }

    // Sparkline polyline
    const ImU32 line_col = IM_COL32(70, 170, 255, 220);
    for (size_t i = 1; i < reg_timeline_data_.size(); i++) {
        dl->AddLine(to_px(reg_timeline_data_[i-1]),
                    to_px(reg_timeline_data_[i]),
                    line_col, 1.5f);
    }

    // Dot markers (only when few points)
    if (reg_timeline_data_.size() <= 256) {
        for (const auto& pt : reg_timeline_data_) {
            dl->AddCircleFilled(to_px(pt), 2.5f, IM_COL32(100, 200, 255, 200));
        }
    }

    // Current instruction cursor bar
    {
        float cx = canvas_pos.x + (float)(current_inst_ - id_min) / (id_max - id_min) * canvas_w;
        cx = std::clamp(cx, canvas_pos.x, canvas_pos.x + canvas_w);
        dl->AddLine(ImVec2(cx, canvas_pos.y),
                    ImVec2(cx, canvas_pos.y + canvas_h),
                    IM_COL32(255, 200, 60, 200), 1.5f);
    }

    // Hover tooltip + click-to-navigate
    if (hovered) {
        ImVec2 mouse = ImGui::GetMousePos();
        float rel = (mouse.x - canvas_pos.x) / canvas_w;
        rel = std::clamp(rel, 0.0f, 1.0f);

        // Find nearest sample
        uint64_t target_id = id_min + (uint64_t)(rel * (id_max - id_min));
        auto it = std::lower_bound(reg_timeline_data_.begin(), reg_timeline_data_.end(),
                                   target_id, [](const RegTimelinePoint& p, uint64_t id){
                                       return p.inst_id < id;
                                   });
        if (it != reg_timeline_data_.end()) {
            const auto& pt = *it;
            dl->AddCircleFilled(to_px(pt), 5.0f, IM_COL32(255, 220, 80, 255));
            ImGui::SetTooltip("%s  →  0x%llx\ninst #%llu\nClick to navigate",
                              cur_name,
                              (unsigned long long)pt.value,
                              (unsigned long long)pt.inst_id);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                navigate_to(pt.inst_id);
            }
        }
    }

    // ── Value stats below the canvas ─────────────────────────────────────
    ImGui::Dummy(ImVec2(0.0f, canvas_h + 2.0f));  // advance cursor past canvas
    ImGui::Spacing();

    char vmin_str[24], vmax_str[24];
    snprintf(vmin_str, sizeof(vmin_str), "0x%llx", (unsigned long long)vmin);
    snprintf(vmax_str, sizeof(vmax_str), "0x%llx", (unsigned long long)vmax);
    ImGui::TextDisabled("min: %s  |  max: %s  |  range: %llu",
                        vmin_str, vmax_str,
                        (unsigned long long)(vmax - vmin));

    ImGui::Separator();

    // ── Producer Chain Section ────────────────────────────────────────────
    ImGui::TextUnformatted("Producer Chain");
    ImGui::SameLine();
    ImGui::TextDisabled("(data-flow backward trace)");

    {
        // Pick the register from the current register-panel right-click or default
        const char* pc_reg_name = reg_name_str(reg_timeline_reg_);
        char btn_label[64];
        snprintf(btn_label, sizeof(btn_label),
                 "Trace %s at inst #%llu##pc_btn",
                 pc_reg_name, (unsigned long long)current_inst_);
        if (ImGui::Button(btn_label)) {
            run_producer_chain(current_inst_, reg_timeline_reg_);
        }
    }

    if (show_producer_chain_ && !producer_chain_ids_.empty()) {
        ImGui::SameLine(0, 8);
        if (ImGui::Button("Clear##pc_clear")) {
            show_producer_chain_ = false;
            producer_chain_ids_.clear();
        }

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.6f, 1.0f),
                           "%zu contributing instructions highlighted",
                           producer_chain_ids_.size());
        ImGui::TextDisabled("(highlighted in yellow in the instruction panel)");

        // Quick table showing the contributing instructions (sorted by inst_id)
        if (ImGui::BeginTable("##chain_tbl", 3,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                ImVec2(0, 100))) {
            ImGui::TableSetupColumn("#",      ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Inst#",  ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            for (size_t i = 0; i < producer_chain_ids_.size(); i++) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%zu", i);
                ImGui::TableNextColumn();
                char idbuf[24];
                snprintf(idbuf, sizeof(idbuf), "%llu", (unsigned long long)producer_chain_ids_[i]);
                bool sel = false;
                if (ImGui::Selectable(idbuf, sel,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    navigate_to(producer_chain_ids_[i]);
                }
            }
            ImGui::EndTable();
        }
    } else if (show_producer_chain_ && producer_chain_ids_.empty()) {
        ImGui::TextDisabled("No chain found (register may have been loaded from immediate).");
    }

    ImGui::End();
}

}  // namespace tenet

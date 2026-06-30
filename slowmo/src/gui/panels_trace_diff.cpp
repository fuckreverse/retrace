// panels_trace_diff.cpp — P2-14 Multi-Trace Divergence View
//
// Compares two regions within the same trace (Region A and Region B) to find
// where execution diverges. Useful for differential cryptanalysis:
// run the same algorithm with two inputs and find where the paths fork.
//
// Uses TraceDiffPass under the hood.
//
// Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/trace_diff_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace tenet {

// ─── run_trace_diff ──────────────────────────────────────────────────────────

void GuiApp::run_trace_diff() {
    trace_diff_result_ = nullptr;
    diff_cursor_ = 0;

    if (diff_region_a_start_ == diff_region_a_end_ ||
        diff_region_b_start_ == diff_region_b_end_) {
        return;
    }

    ensure_pass_manager();

    TraceDiffConfig cfg;
    cfg.trace_a_start = diff_region_a_start_;
    cfg.trace_a_end   = diff_region_a_end_;
    cfg.trace_b_start = diff_region_b_start_;
    cfg.trace_b_end   = diff_region_b_end_;

    auto pass = std::make_unique<TraceDiffPass>(cfg);
    // Run in a private PassManager so it doesn't conflict with startup analysis
    auto pm = std::make_unique<PassManager>();
    pm->set_reader(&reader_);
    pm->set_index(&index_);
    pm->set_code_table(&code_table_);
    pm->set_regfile(&regfile_);
    pm->set_memory(&memory_);
    pm->set_decoder(&decoder_);
    pm->register_pass(std::move(pass));
    const auto& res = pm->require("trace_diff");
    if (!res.ok()) return;

    // Store a pointer into a locally owned result
    // (PassManager owns the result; we need it to outlive the panel)
    // Simple approach: keep the pm alive by transferring to a member.
    // For now store inline copy via const ref + move trick.
    // ─ We copy the result data into a member-owned TraceDiffResult ──────
    static TraceDiffResult s_result;  // static lifetime (single diff at a time)
    s_result = res.get<TraceDiffResult>();
    trace_diff_result_ = &s_result;
}

// ─── render_trace_diff_panel ─────────────────────────────────────────────────

void GuiApp::render_trace_diff_panel() {
    if (!show_trace_diff_) return;

    ImGui::SetNextWindowSize(ImVec2(800, 520), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Trace Diff##P214", &show_trace_diff_)) {
        ImGui::End();
        return;
    }

    // ── Region input ─────────────────────────────────────────────────────
    ImGui::TextUnformatted("Compare two execution regions within this trace:");
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
    ImGui::TextUnformatted("Region A");
    ImGui::PopStyleColor();

    ImGui::SameLine(80.0f);
    ImGui::TextUnformatted("Start inst#:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    if (ImGui::InputText("##a_start", diff_a_start_buf_, sizeof(diff_a_start_buf_),
                         ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsDecimal)) {
        diff_region_a_start_ = std::strtoull(diff_a_start_buf_, nullptr, 0);
    }
    ImGui::SameLine();
    ImGui::TextUnformatted("End inst#:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    if (ImGui::InputText("##a_end", diff_a_end_buf_, sizeof(diff_a_end_buf_),
                         ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsDecimal)) {
        diff_region_a_end_ = std::strtoull(diff_a_end_buf_, nullptr, 0);
    }
    ImGui::SameLine(0, 8);
    if (ImGui::SmallButton("Set A = current##a_cur")) {
        diff_region_a_start_ = (current_inst_ > 500) ? current_inst_ - 500 : 0;
        diff_region_a_end_   = current_inst_ + 500;
        snprintf(diff_a_start_buf_, sizeof(diff_a_start_buf_), "%llu",
                 (unsigned long long)diff_region_a_start_);
        snprintf(diff_a_end_buf_,   sizeof(diff_a_end_buf_),   "%llu",
                 (unsigned long long)diff_region_a_end_);
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.4f, 1.0f));
    ImGui::TextUnformatted("Region B");
    ImGui::PopStyleColor();

    ImGui::SameLine(80.0f);
    ImGui::TextUnformatted("Start inst#:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    if (ImGui::InputText("##b_start", diff_b_start_buf_, sizeof(diff_b_start_buf_),
                         ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsDecimal)) {
        diff_region_b_start_ = std::strtoull(diff_b_start_buf_, nullptr, 0);
    }
    ImGui::SameLine();
    ImGui::TextUnformatted("End inst#:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    if (ImGui::InputText("##b_end", diff_b_end_buf_, sizeof(diff_b_end_buf_),
                         ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsDecimal)) {
        diff_region_b_end_ = std::strtoull(diff_b_end_buf_, nullptr, 0);
    }

    ImGui::Spacing();

    const bool can_run = (diff_region_a_end_ > diff_region_a_start_) &&
                         (diff_region_b_end_ > diff_region_b_start_);

    if (!can_run) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
    }
    if (ImGui::Button("Run Diff##go") && can_run) {
        run_trace_diff();
    }
    if (!can_run) {
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled("(set valid start < end for both regions)");
    }

    ImGui::Separator();

    // ── Results ─────────────────────────────────────────────────────────
    if (!trace_diff_result_) {
        ImGui::TextDisabled("No diff results yet — enter regions above and click Run Diff.");
        ImGui::End();
        return;
    }

    const auto& dr = *trace_diff_result_;

    // Summary row
    if (!dr.has_divergence()) {
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f),
                           "✓  Regions are identical (%llu instructions matched)",
                           (unsigned long long)dr.matched_count);
    } else {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f),
                           "⚡  %llu diverged   |   %llu matched   |   %llu segments",
                           (unsigned long long)dr.total_diverged,
                           (unsigned long long)dr.matched_count,
                           (unsigned long long)dr.segments.size());
    }

    ImGui::Separator();

    // ── Diff type filter ─────────────────────────────────────────────────
    static bool show_cf     = true;   // ControlFlow
    static bool show_reg    = true;   // RegisterValue
    static bool show_mem    = true;   // MemoryValue
    static bool show_opcode = true;   // OpcodeChange

    ImGui::TextDisabled("Filter:");
    ImGui::SameLine();
    ImGui::Checkbox("ControlFlow##f",    &show_cf);
    ImGui::SameLine();
    ImGui::Checkbox("RegValue##f",       &show_reg);
    ImGui::SameLine();
    ImGui::Checkbox("MemValue##f",       &show_mem);
    ImGui::SameLine();
    ImGui::Checkbox("OpcodeChange##f",   &show_opcode);

    // ── Main diff table ──────────────────────────────────────────────────

    // Build filtered list
    static std::vector<const DivergeSegment*> filtered;
    filtered.clear();
    for (const auto& s : dr.segments) {
        if (!show_cf     && s.start_type == DiffType::ControlFlow)   continue;
        if (!show_reg    && s.start_type == DiffType::RegisterValue)  continue;
        if (!show_mem    && s.start_type == DiffType::MemoryValue)    continue;
        if (!show_opcode && s.start_type == DiffType::OpcodeChange)   continue;
        filtered.push_back(&s);
    }

    const float avail_h = ImGui::GetContentRegionAvail().y - 4.0f;
    if (ImGui::BeginTable("##diff_tbl", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_SizingFixedFit,
            ImVec2(0, avail_h))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Type",      ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Inst A",    ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Inst B",    ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("PC",        ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Detail",    ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // Use ImGuiListClipper for large result sets
        ImGuiListClipper clipper;
        clipper.Begin((int)filtered.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                const DivergeSegment* s = filtered[i];
                ImGui::TableNextRow();

                // Row background based on type
                ImVec4 type_col;
                const char* type_str;
                switch (s->start_type) {
                    case DiffType::ControlFlow:
                        type_col = ImVec4(1.0f, 0.5f, 0.2f, 1.0f);
                        type_str = "ControlFlow";
                        break;
                    case DiffType::RegisterValue:
                        type_col = ImVec4(0.4f, 0.8f, 1.0f, 1.0f);
                        type_str = "RegValue";
                        break;
                    case DiffType::MemoryValue:
                        type_col = ImVec4(0.8f, 0.6f, 1.0f, 1.0f);
                        type_str = "MemValue";
                        break;
                    case DiffType::OpcodeChange:
                        type_col = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
                        type_str = "OpcodeChange";
                        break;
                    default:
                        type_col = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
                        type_str = "?";
                }

                ImGui::TableNextColumn();
                ImGui::TextColored(type_col, "%s", type_str);

                ImGui::TableNextColumn();
                ImGui::Text("%llu", (unsigned long long)s->start_inst_a);

                ImGui::TableNextColumn();
                ImGui::Text("%llu", (unsigned long long)s->start_inst_b);

                ImGui::TableNextColumn();
                char pc_str[24];
                snprintf(pc_str, sizeof(pc_str), "0x%llx", (unsigned long long)s->start_pc);
                bool sel = ((size_t)i == diff_cursor_);
                if (ImGui::Selectable(pc_str, sel,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    diff_cursor_ = (size_t)i;
                    // Navigate to divergence start in trace A
                    if (s->start_inst_a < total_inst_) navigate_to(s->start_inst_a);
                }

                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", s->start_detail.c_str());
            }
        }
        clipper.End();

        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

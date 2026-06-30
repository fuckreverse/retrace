// panels_trace_fold.cpp — Trace Fold (loop-compressed trace) panel.
//
// Displays the TraceFoldResult from TraceFoldPass in a compact table showing
// folded loop regions: PC, iteration count, body size, removed instructions,
// and register delta summary.  Click any row to navigate to the first
// instruction of that region.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/trace_fold_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <string>
#include <vector>
#include <algorithm>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

void GuiApp::render_trace_fold_panel() {
    if (!ImGui::Begin("Trace Fold", &show_trace_fold_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!trace_fold_result_) {
        ImGui::TextDisabled("No trace fold analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Trace Fold")) {
            run_pass_by_name("trace_fold");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Fold repetitive loop iterations into summaries.\n"
                              "Requires 'loop' and 'xref' passes to complete first.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    // Format counts with M/K suffixes for readability.
    auto fmt_count = [](uint64_t n) -> std::string {
        if (n >= 1'000'000ULL)
            return fmt::format("{:.1f}M", n / 1'000'000.0);
        if (n >= 1'000ULL)
            return fmt::format("{:.1f}K", n / 1'000.0);
        return fmt::format("{}", n);
    };

    std::string orig_str  = fmt_count(trace_fold_result_->original_inst_count);
    std::string fold_str  = fmt_count(trace_fold_result_->folded_inst_count);
    float ratio = trace_fold_result_->compression_ratio;

    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_SCISSORS "  %s " ICON_FA_ARROW_RIGHT " %s  (\xc3\x97%.1f compression)  |  %zu regions folded",
        orig_str.c_str(), fold_str.c_str(), ratio,
        trace_fold_result_->folded_regions.size());

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        run_pass_by_name("trace_fold");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run Trace Fold analysis (clears current results)");

    ImGui::Separator();

    // ── Build sorted region index (by first_inst_id ascending) ─────────────
    const auto& regions = trace_fold_result_->folded_regions;
    std::vector<size_t> sorted_idx;
    sorted_idx.reserve(regions.size());
    for (size_t i = 0; i < regions.size(); ++i)
        sorted_idx.push_back(i);
    std::sort(sorted_idx.begin(), sorted_idx.end(),
              [&regions](size_t a, size_t b) {
                  return regions[a].first_inst_id < regions[b].first_inst_id;
              });

    ImGui::TextDisabled("%zu folded regions  |  %s instructions removed",
                        regions.size(),
                        fmt_count(trace_fold_result_->total_instructions_removed).c_str());
    ImGui::Separator();

    // ── Main table ─────────────────────────────────────────────────────────
    const float row_h    = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("TraceFoldTable", 5,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PC",         ImGuiTableColumnFlags_WidthFixed,   110.0f);
        ImGui::TableSetupColumn("Iterations", ImGuiTableColumnFlags_WidthFixed,    80.0f);
        ImGui::TableSetupColumn("Body Size",  ImGuiTableColumnFlags_WidthFixed,    80.0f);
        ImGui::TableSetupColumn("Removed",    ImGuiTableColumnFlags_WidthStretch, 0.35f);
        ImGui::TableSetupColumn("Reg Changes",ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(sorted_idx.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const FoldedRegion& fr = regions[sorted_idx[static_cast<size_t>(row)]];
                uint64_t slide = reader_.header().module_slide;
                uint64_t static_pc = fr.header_pc - slide;

                ImGui::TableNextRow();

                // ── Column 0: PC (static address, click to navigate) ───────
                ImGui::TableSetColumnIndex(0);
                char pc_label[48];
                snprintf(pc_label, sizeof(pc_label), "0x%llx##tf%d",
                         (unsigned long long)static_pc, row);
                if (ImGui::Selectable(pc_label, false,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    navigate_to(fr.first_inst_id);
                }

                // ── Hover tooltip: kept iterations + reg changes ───────────
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format(
                        "PC:    0x{:x}  (runtime 0x{:x})\n"
                        "Range: #{} – #{}\n",
                        static_pc, fr.header_pc,
                        fr.first_inst_id, fr.last_inst_id);

                    if (!fr.kept_iterations.empty()) {
                        tip += "\nKept iterations:\n";
                        for (const auto& ir : fr.kept_iterations)
                            tip += fmt::format("  #{} – #{}\n", ir.start, ir.end);
                    }

                    if (!fr.reg_changes.empty()) {
                        tip += "\nRegister changes across folded iterations:\n";
                        for (const auto& rc : fr.reg_changes) {
                            tip += fmt::format("  x{}: {:#018x} \xe2\x86\x92 {:#018x}\n",
                                               (unsigned)rc.reg,
                                               rc.first_val, rc.last_val);
                        }
                    }

                    tip += "\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());
                    if (ImGui::IsMouseDoubleClicked(0))
                        navigate_to(fr.first_inst_id);
                }

                // ── Right-click context menu ───────────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextDisabled("PC: 0x%llx", (unsigned long long)static_pc);
                    ImGui::TextDisabled("×%llu iter  |  #%llu–#%llu",
                                        (unsigned long long)fr.total_iterations,
                                        (unsigned long long)fr.first_inst_id,
                                        (unsigned long long)fr.last_inst_id);
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_FA_ARROW_RIGHT " Jump to Instructions")) {
                        navigate_to_instructions(fr.first_inst_id);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)fr.first_inst_id);
                    if (ImGui::MenuItem("Jump to End")) {
                        navigate_to(fr.last_inst_id);
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy PC")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)static_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // ── Column 1: Iterations ───────────────────────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%llu", (unsigned long long)fr.total_iterations);

                // ── Column 2: Body Size ────────────────────────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%llu instr", (unsigned long long)fr.instructions_per_iteration);

                // ── Column 3: Removed (coloured by magnitude) ─────────────
                ImGui::TableSetColumnIndex(3);
                {
                    ImVec4 col;
                    if (fr.total_instructions_folded >= 1'000'000ULL)
                        col = ImVec4(1.0f, 0.35f, 0.35f, 1.0f);   // red
                    else if (fr.total_instructions_folded >= 100'000ULL)
                        col = ImVec4(1.0f, 0.85f, 0.25f, 1.0f);   // yellow
                    else
                        col = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled); // grey
                    ImGui::TextColored(col, "%s",
                        fmt_count(fr.total_instructions_folded).c_str());
                }

                // ── Column 4: Reg Changes (count + hover detail) ──────────
                ImGui::TableSetColumnIndex(4);
                if (fr.reg_changes.empty()) {
                    ImGui::TextDisabled("—");
                } else {
                    ImGui::Text("%zu", fr.reg_changes.size());
                    if (ImGui::IsItemHovered()) {
                        std::string detail;
                        for (const auto& rc : fr.reg_changes) {
                            detail += fmt::format("x{}: {:#018x} \xe2\x86\x92 {:#018x}\n",
                                                  (unsigned)rc.reg,
                                                  rc.first_val, rc.last_val);
                        }
                        ImGui::SetTooltip("%s", detail.c_str());
                    }
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

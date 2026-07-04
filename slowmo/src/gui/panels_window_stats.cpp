// panels_window_stats.cpp — Sliding-window trace statistics panel.
//
// Displays the WindowStatsResult from WindowStatsPass in a table: one row
// per window, showing instruction count, mnemonic diversity (entropy),
// branch density, memory access counts, and top mnemonic. Highlights the
// hottest windows (by memory access, mnemonic diversity, branch density)
// called out in the header, and lets the user click a row to jump there.
//
// No-parameter pass (direct trace scan, no config to fill in) — mirrors the
// shape of panels_trace_fold.cpp.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/profile/window_stats_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <string>

#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

void GuiApp::render_window_stats_panel() {
    if (!ImGui::Begin("Window Stats", &show_window_stats_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!window_stats_result_) {
        ImGui::TextDisabled(ICON_FA_CHART_COLUMN "  Window Stats");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Sliding-window statistics over the whole trace: per-window "
            "mnemonic distribution, register activity, memory access "
            "density, and branch density. Useful for spotting hot regions, "
            "crypto loops, and data-processing phases at a glance.");
        ImGui::Spacing();
        if (ImGui::Button(ICON_FA_CHART_COLUMN " Run Window Stats")) {
            run_pass_by_name("window_stats");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Scan the entire trace in fixed-size windows.\nNo dependencies — runs directly.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;
    const auto& windows = window_stats_result_->windows;

    // ── Summary header ─────────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.75f, 1.0f),
        ICON_FA_CHART_COLUMN "  %llu windows  |  window size: %llu instructions",
        (unsigned long long)window_stats_result_->total_windows,
        (unsigned long long)window_stats_result_->window_size);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        run_pass_by_name("window_stats");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run Window Stats analysis (clears current results)");

    // ── Hottest-window shortcuts ────────────────────────────────────────────
    if (!windows.empty()) {
        auto jump_to_window = [&](size_t idx, const char* label) {
            if (idx >= windows.size()) return;
            char btn[64];
            snprintf(btn, sizeof(btn), "%s #%zu##wsjump", label, idx);
            if (ImGui::SmallButton(btn)) {
                navigate_to_instructions(windows[idx].start_inst_id);
            }
        };
        ImGui::Spacing();
        ImGui::TextDisabled("Jump to:");
        ImGui::SameLine();
        jump_to_window(window_stats_result_->hottest_mem_window, ICON_FA_DATABASE " Hottest Mem");
        ImGui::SameLine();
        jump_to_window(window_stats_result_->most_diverse_window, ICON_FA_SHUFFLE " Most Diverse");
        ImGui::SameLine();
        jump_to_window(window_stats_result_->densest_branch_window, ICON_FA_CODE_BRANCH " Densest Branch");
    }

    ImGui::Separator();

    // ── Main table ─────────────────────────────────────────────────────────
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("WindowStatsTable", 7,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",           ImGuiTableColumnFlags_WidthFixed,    50.0f);
        ImGui::TableSetupColumn("Range",       ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("Insts",       ImGuiTableColumnFlags_WidthFixed,    70.0f);
        ImGui::TableSetupColumn("Entropy",     ImGuiTableColumnFlags_WidthFixed,    70.0f);
        ImGui::TableSetupColumn("Branch%",     ImGuiTableColumnFlags_WidthFixed,    70.0f);
        ImGui::TableSetupColumn("Mem R/W",     ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("Top Mnemonic",ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(windows.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const WindowSnapshot& w = windows[static_cast<size_t>(row)];
                bool selected = (window_stats_cursor_ == static_cast<size_t>(row));

                ImGui::TableNextRow();

                // ── Column 0: index (click to select + navigate) ──────────
                ImGui::TableSetColumnIndex(0);
                char idx_label[32];
                snprintf(idx_label, sizeof(idx_label), "%d##ws%d", row, row);
                if (ImGui::Selectable(idx_label, selected,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    window_stats_cursor_ = static_cast<size_t>(row);
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    navigate_to_instructions(w.start_inst_id);
                }
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextDisabled("Window #%d", row);
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_FA_ARROW_RIGHT " Jump to Instructions")) {
                        navigate_to_instructions(w.start_inst_id);
                    }
                    ImGui::EndPopup();
                }

                // ── Column 1: instruction range ────────────────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("#%llu \xe2\x80\x93 #%llu",
                    (unsigned long long)w.start_inst_id, (unsigned long long)w.end_inst_id);

                // ── Column 2: instruction count ────────────────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%llu", (unsigned long long)w.instruction_count);

                // ── Column 3: mnemonic entropy (colour-coded) ──────────────
                ImGui::TableSetColumnIndex(3);
                {
                    ImVec4 col = w.mnemonic_entropy >= 3.5f
                        ? ImVec4(1.0f, 0.85f, 0.25f, 1.0f)       // high diversity
                        : ImGui::GetStyleColorVec4(ImGuiCol_Text);
                    ImGui::TextColored(col, "%.2f", w.mnemonic_entropy);
                }

                // ── Column 4: branch density (as %) ────────────────────────
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%.1f%%", w.branch_density * 100.0f);

                // ── Column 5: memory read/write counts ─────────────────────
                ImGui::TableSetColumnIndex(5);
                ImGui::TextDisabled("R:%llu W:%llu (%llu uniq)",
                    (unsigned long long)w.mem_read_count,
                    (unsigned long long)w.mem_write_count,
                    (unsigned long long)w.unique_mem_addrs);

                // ── Column 6: top mnemonic ──────────────────────────────────
                ImGui::TableSetColumnIndex(6);
                if (!w.top_mnemonics.empty()) {
                    ImGui::Text("id %u (\xc3\x97%llu)",
                        (unsigned)w.top_mnemonics.front().mnemonic_id,
                        (unsigned long long)w.top_mnemonics.front().count);
                    if (ImGui::IsItemHovered() && w.top_mnemonics.size() > 1) {
                        std::string tip;
                        for (const auto& m : w.top_mnemonics) {
                            tip += fmt::format("mnemonic id {}: \xc3\x97{}\n",
                                               m.mnemonic_id, m.count);
                        }
                        ImGui::SetTooltip("%s", tip.c_str());
                    }
                } else {
                    ImGui::TextDisabled("\xe2\x80\x94");
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

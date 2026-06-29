// panels_algorithm_summary.cpp — Algorithm Summary analysis panel.
//
// Displays the AlgorithmSummaryResult from AlgorithmSummaryPass in two views:
//   1. Candidates view: a scrollable table of every detected algorithm candidate
//      with rank, name, confidence bar, and evidence.
//   2. Summary Text view: the full Markdown summary text from the pass.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/algorithm_summary_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <string>
#include <vector>

namespace tenet {

void GuiApp::render_algorithm_summary_panel() {
    if (!ImGui::Begin("Algorithm Summary", &show_algorithm_summary_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!algorithm_summary_result_) {
        ImGui::TextDisabled("No algorithm summary analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Algorithm Summary")) {
            run_pass_by_name("algorithm_summary");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Analyze the trace and identify cryptographic,\n"
                              "compression, hashing, or other algorithm patterns.");
        }
        ImGui::End();
        return;
    }

    const AlgorithmSummaryResult& res = *algorithm_summary_result_;
    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    const char* crypto_badge = res.has_crypto() ? "  \xe2\x9a\xa0 CRYPTO" : "";  // ⚠
    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        "\xe2\x8c\x95  %zu candidate(s)%s",   // ⌕ U+2315 (was 🔍 U+1F50D emoji)
        res.total(), crypto_badge);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {  // ↺
        run_pass_by_name("algorithm_summary");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run algorithm summary analysis (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ───────────────────────────────────────────────────
    ImGui::RadioButton("Candidates", &algorithm_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Summary Text", &algorithm_view_mode_, 1);

    ImGui::Separator();

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 0: Candidates table
    // ══════════════════════════════════════════════════════════════════════
    if (algorithm_view_mode_ == 0) {

        if (res.candidates.empty()) {
            ImGui::TextDisabled("No algorithm candidates detected.");
            ImGui::End();
            return;
        }

        ImGui::TextDisabled("%zu algorithm(s) detected", res.candidates.size());
        ImGui::Separator();

        const float row_h = ImGui::GetTextLineHeightWithSpacing();
        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

        if (ImGui::BeginTable("AlgoTable", 4,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Rank",       ImGuiTableColumnFlags_WidthFixed,   50.0f);
            ImGui::TableSetupColumn("Algorithm",  ImGuiTableColumnFlags_WidthStretch, 0.30f);
            ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthStretch, 0.30f);
            ImGui::TableSetupColumn("Evidence",   ImGuiTableColumnFlags_WidthStretch, 0.40f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(res.candidates.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const AlgorithmCandidate& cand =
                        res.candidates[static_cast<size_t>(row)];

                    ImGui::TableNextRow();

                    // ── Rank column ─────────────────────────────────────
                    ImGui::TableSetColumnIndex(0);
                    char rank_label[32];
                    snprintf(rank_label, sizeof(rank_label), "#%d##algo%d", row + 1, row);
                    if (ImGui::Selectable(rank_label, false,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        if (cand.estimated_start != 0)
                            navigate_to(cand.estimated_start);
                    }
                    if (ImGui::IsItemHovered()) {
                        // Build tooltip with key PCs and full evidence
                        std::string tip = fmt::format(
                            "{}\nConfidence: {:.0f}%\n"
                            "Range: inst #{} – #{}",
                            cand.name,
                            cand.confidence * 100.0f,
                            cand.estimated_start,
                            cand.estimated_end);

                        if (!cand.key_pcs.empty()) {
                            tip += "\n\nKey PCs:";
                            size_t show = cand.key_pcs.size() < 8
                                          ? cand.key_pcs.size() : 8;
                            for (size_t k = 0; k < show; ++k)
                                tip += fmt::format("\n  0x{:x}", cand.key_pcs[k]);
                            if (cand.key_pcs.size() > show)
                                tip += fmt::format("\n  (+{} more)",
                                                   cand.key_pcs.size() - show);
                        }

                        if (!cand.evidence.empty())
                            tip += fmt::format("\n\nEvidence:\n{}", cand.evidence);

                        ImGui::SetTooltip("%s", tip.c_str());
                    }

                    // ── Algorithm Name column ────────────────────────────
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextColored(ImVec4(0.75f, 0.92f, 0.6f, 1.0f),
                                       "%s", cand.name.c_str());

                    // ── Confidence column (progress bar + label) ─────────
                    ImGui::TableSetColumnIndex(2);
                    {
                        // Choose colour based on confidence level
                        ImVec4 bar_col;
                        if (cand.confidence >= 0.8f)
                            bar_col = ImVec4(0.2f, 0.75f, 0.3f, 1.0f);   // green
                        else if (cand.confidence >= 0.5f)
                            bar_col = ImVec4(0.9f, 0.75f, 0.1f, 1.0f);   // yellow
                        else
                            bar_col = ImVec4(0.55f, 0.55f, 0.55f, 1.0f); // grey

                        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_col);
                        char conf_label[16];
                        snprintf(conf_label, sizeof(conf_label),
                                 "%.0f%%", cand.confidence * 100.0f);
                        ImGui::ProgressBar(cand.confidence,
                                           ImVec2(-FLT_MIN, 0.0f),
                                           conf_label);
                        ImGui::PopStyleColor();
                    }

                    // ── Evidence column (truncated) ──────────────────────
                    ImGui::TableSetColumnIndex(3);
                    if (cand.evidence.empty()) {
                        ImGui::TextDisabled("—");
                    } else {
                        // Truncate to first line or 64 chars for the cell
                        std::string short_ev = cand.evidence;
                        auto nl = short_ev.find('\n');
                        if (nl != std::string::npos)
                            short_ev = short_ev.substr(0, nl) + "…";
                        if (short_ev.size() > 64)
                            short_ev = short_ev.substr(0, 64) + "…";
                        ImGui::TextDisabled("%s", short_ev.c_str());
                    }
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 1: Summary Text (Markdown content)
    // ══════════════════════════════════════════════════════════════════════
    else {
        if (res.summary_text.empty()) {
            ImGui::TextDisabled("(no summary available)");
        } else {
            ImGui::PushStyleColor(ImGuiCol_ChildBg,
                                  ImGui::GetStyleColorVec4(ImGuiCol_WindowBg));
            if (ImGui::BeginChild("AlgoSummaryText", ImVec2(0.0f, 0.0f),
                                  ImGuiChildFlags_None,
                                  ImGuiWindowFlags_HorizontalScrollbar)) {
                ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
                ImGui::TextWrapped("%s", res.summary_text.c_str());
                ImGui::PopTextWrapPos();
            }
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }
    }

    ImGui::End();
}

}  // namespace tenet

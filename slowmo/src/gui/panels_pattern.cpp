// panels_pattern.cpp — Pattern recognition analysis panel.
//
// Displays the PatternResult from PatternPass in a filterable, virtualised
// table. Patterns are grouped by category (Crypto / AntiDebug / Other) and
// can be searched by name or description.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/pattern_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>

namespace tenet {

// ─── Category helpers ────────────────────────────────────────────────────────

static const char* category_str(PatternCategory cat) {
    switch (cat) {
        case PatternCategory::Crypto:      return "Crypto";
        case PatternCategory::AntiDebug:   return "AntiDebug";
        case PatternCategory::AntiTamper:  return "AntiTamper";
        case PatternCategory::Obfuscation: return "Obfuscation";
        case PatternCategory::Networking:  return "Networking";
        case PatternCategory::KeySchedule: return "KeySchedule";
        default:                           return "Unknown";
    }
}

static ImVec4 category_color(PatternCategory cat) {
    switch (cat) {
        case PatternCategory::Crypto:      return ImVec4(1.0f, 0.65f, 0.1f, 1.0f);  // orange
        case PatternCategory::AntiDebug:   return ImVec4(1.0f, 0.35f, 0.35f, 1.0f); // red
        case PatternCategory::AntiTamper:  return ImVec4(1.0f, 0.45f, 0.7f,  1.0f); // pink
        case PatternCategory::Obfuscation: return ImVec4(0.8f, 0.55f, 1.0f,  1.0f); // purple
        case PatternCategory::Networking:  return ImVec4(0.3f, 0.85f, 0.95f, 1.0f); // cyan
        case PatternCategory::KeySchedule: return ImVec4(1.0f, 0.85f, 0.2f,  1.0f); // yellow
        default:                           return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
    }
}

static ImVec4 confidence_color(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::High:   return ImVec4(0.35f, 0.90f, 0.45f, 1.0f); // green
        case PatternConfidence::Medium: return ImVec4(1.0f,  0.90f, 0.20f, 1.0f); // yellow
        case PatternConfidence::Low:    return ImVec4(0.50f, 0.50f, 0.50f, 1.0f); // grey
        default:                        return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
    }
}

static const char* confidence_str(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::High:   return "High";
        case PatternConfidence::Medium: return "Medium";
        case PatternConfidence::Low:    return "Low";
        default:                        return "?";
    }
}

// ─── render_pattern_panel ────────────────────────────────────────────────────

void GuiApp::render_pattern_panel() {
    if (!ImGui::Begin("Patterns", &show_pattern_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ────────────────────────────────────────────────────────
    if (!pattern_result_) {
        ImGui::TextDisabled("No pattern analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Pattern Analysis")) {
            run_pass_by_name("pattern");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Detect cryptographic algorithms, anti-debugging techniques\n"
                              "and obfuscation patterns using YARA rules.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ───────────────────────────────────────────────────────
    // Count per interesting category for the status line
    size_t n_crypto    = 0;
    size_t n_antidebug = 0;
    size_t n_other     = 0;
    {
        auto it = pattern_result_->by_category.find(PatternCategory::Crypto);
        if (it != pattern_result_->by_category.end()) n_crypto = it->second.size();
        it = pattern_result_->by_category.find(PatternCategory::AntiDebug);
        if (it != pattern_result_->by_category.end()) n_antidebug = it->second.size();
        n_other = pattern_result_->total() - n_crypto - n_antidebug;
    }

    ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.25f, 1.0f),
        "\xef\x8b\x9b  %zu matches   "     // shield icon
        "Crypto:%zu  AntiDebug:%zu  Other:%zu",
        pattern_result_->total(), n_crypto, n_antidebug, n_other);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {  // ↺
        run_pass_by_name("pattern");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run pattern analysis (clears current results)");

    ImGui::Separator();

    // ── View mode filter ─────────────────────────────────────────────────────
    ImGui::RadioButton("All",      &pattern_view_mode_, 0); ImGui::SameLine();
    ImGui::RadioButton("Crypto",   &pattern_view_mode_, 1); ImGui::SameLine();
    ImGui::RadioButton("AntiDebug",&pattern_view_mode_, 2); ImGui::SameLine();
    ImGui::RadioButton("Other",    &pattern_view_mode_, 3);

    // ── Search filter ────────────────────────────────────────────────────────
    ImGui::SetNextItemWidth(panel_w * 0.55f);
    if (ImGui::InputText("Filter##patternf", pattern_filter_buf_,
                         sizeof(pattern_filter_buf_))) {
        pattern_filter_ = pattern_filter_buf_;
        pattern_cursor_ = 0;
    }
    ImGui::SameLine(0, 6);
    if (ImGui::SmallButton("x##patclr")) {
        std::memset(pattern_filter_buf_, 0, sizeof(pattern_filter_buf_));
        pattern_filter_.clear();
        pattern_cursor_ = 0;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filter");

    // ── Build filtered index list ────────────────────────────────────────────
    // Holds indices into pattern_result_->matches.
    std::vector<size_t> filtered;
    filtered.reserve(pattern_result_->matches.size());

    for (size_t i = 0; i < pattern_result_->matches.size(); ++i) {
        const PatternMatch& m = pattern_result_->matches[i];

        // View-mode filter
        if (pattern_view_mode_ == 1 && m.category != PatternCategory::Crypto)
            continue;
        if (pattern_view_mode_ == 2 && m.category != PatternCategory::AntiDebug)
            continue;
        if (pattern_view_mode_ == 3 &&
            (m.category == PatternCategory::Crypto ||
             m.category == PatternCategory::AntiDebug))
            continue;

        // Text filter (case-sensitive substring on name + description)
        if (!pattern_filter_.empty()) {
            bool name_match = m.pattern_name.find(pattern_filter_) != std::string::npos;
            bool desc_match = m.description.find(pattern_filter_) != std::string::npos;
            if (!name_match && !desc_match) continue;
        }

        filtered.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu / %zu", filtered.size(),
                        pattern_result_->matches.size());
    ImGui::Separator();

    // ── Main table ───────────────────────────────────────────────────────────
    const float row_h   = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("PatternTable", 6,
            ImGuiTableFlags_Resizable    |
            ImGuiTableFlags_RowBg        |
            ImGuiTableFlags_BordersInnerV|
            ImGuiTableFlags_ScrollY      |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",          ImGuiTableColumnFlags_WidthFixed,   55.0f);
        ImGui::TableSetupColumn("Category",   ImGuiTableColumnFlags_WidthFixed,   82.0f);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed,   72.0f);
        ImGui::TableSetupColumn("Pattern",    ImGuiTableColumnFlags_WidthStretch, 0.28f);
        ImGui::TableSetupColumn("PC",         ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("Description",ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t idx = filtered[static_cast<size_t>(row)];
                const PatternMatch& m = pattern_result_->matches[idx];
                bool selected = (pattern_cursor_ == static_cast<size_t>(row));

                ImGui::TableNextRow();

                // ── Col 0: inst_id (clickable, navigates) ──────────────────
                ImGui::TableSetColumnIndex(0);
                char id_label[32];
                snprintf(id_label, sizeof(id_label), "#%llu##pm%zu",
                         (unsigned long long)m.start_inst_id, idx);
                if (ImGui::Selectable(id_label, selected,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    pattern_cursor_ = static_cast<size_t>(row);
                    navigate_to(m.start_inst_id);
                }

                // ── Tooltip on hover ───────────────────────────────────────
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format(
                        "[{}..{}]  {}\nCategory: {}  Confidence: {}\nPC: 0x{:x}\n\n{}",
                        m.start_inst_id, m.end_inst_id,
                        m.pattern_name,
                        category_str(m.category),
                        confidence_str(m.confidence),
                        m.anchor_pc,
                        m.description);

                    if (!m.constants_found.empty()) {
                        tip += "\n\nConstants:";
                        for (size_t ci = 0; ci < m.constants_found.size() && ci < 8; ++ci)
                            tip += fmt::format("\n  0x{:016x}", m.constants_found[ci]);
                        if (m.constants_found.size() > 8)
                            tip += fmt::format("\n  (+{} more)",
                                              m.constants_found.size() - 8);
                    }

                    if (!m.related_inst_ids.empty()) {
                        tip += fmt::format("\n\nRelated inst_ids: {}",
                                          m.related_inst_ids.size());
                    }

                    tip += "\n\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());
                    if (ImGui::IsMouseDoubleClicked(0))
                        navigate_to(m.start_inst_id);
                }

                // ── Right-click context menu ───────────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextDisabled("%s", m.pattern_name.c_str());
                    ImGui::TextDisabled("[%llu..%llu]",
                                        (unsigned long long)m.start_inst_id,
                                        (unsigned long long)m.end_inst_id);
                    ImGui::Separator();
                    if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions")) {
                        navigate_to_instructions(m.start_inst_id);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)m.start_inst_id);
                    if (ImGui::MenuItem("Jump to End")) {
                        navigate_to(m.end_inst_id);
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy PC")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)m.anchor_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // ── Col 1: Category ────────────────────────────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(category_color(m.category),
                                   "%s", category_str(m.category));

                // ── Col 2: Confidence ──────────────────────────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(confidence_color(m.confidence),
                                   "%s", confidence_str(m.confidence));

                // ── Col 3: Pattern name ────────────────────────────────────
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(m.pattern_name.c_str());

                // ── Col 4: PC (static, hex) ────────────────────────────────
                ImGui::TableSetColumnIndex(4);
                ImGui::TextDisabled("0x%llx",
                    (unsigned long long)(m.anchor_pc -
                                        reader_.header().module_slide));

                // ── Col 5: Description (truncated) ─────────────────────────
                ImGui::TableSetColumnIndex(5);
                // Truncate to ~60 chars so long descriptions don't thrash layout
                if (m.description.size() <= 60) {
                    ImGui::TextDisabled("%s", m.description.c_str());
                } else {
                    ImGui::TextDisabled("%.60s…", m.description.c_str());
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

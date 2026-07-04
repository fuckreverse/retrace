// panels_yara_mem_scan.cpp — YARA memory scan panel.
//
// Independent floating window for YaraMemScanPass.
// Shows a parameter form for YARA rule configuration, and a match list
// with category-based filtering.
//
// Split out of panels_analysis.cpp. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/memory/yara_mem_scan_pass.h"
#include "analysis/pass_registry.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ---------------------------------------------------------------------------
// Category helpers (reuse PatternCategory from pattern_pass.h)
// ---------------------------------------------------------------------------

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
        case PatternCategory::Crypto:      return ImVec4(1.0f, 0.65f, 0.1f, 1.0f);
        case PatternCategory::AntiDebug:   return ImVec4(1.0f, 0.35f, 0.35f, 1.0f);
        case PatternCategory::AntiTamper:  return ImVec4(1.0f, 0.45f, 0.7f,  1.0f);
        case PatternCategory::Obfuscation: return ImVec4(0.8f, 0.55f, 1.0f,  1.0f);
        case PatternCategory::Networking:  return ImVec4(0.3f, 0.85f, 0.95f, 1.0f);
        case PatternCategory::KeySchedule: return ImVec4(1.0f, 0.85f, 0.2f,  1.0f);
        default:                           return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
    }
}

static const char* confidence_str(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::Low:    return "Low";
        case PatternConfidence::Medium: return "Medium";
        case PatternConfidence::High:   return "High";
        default:                        return "?";
    }
}

// ---------------------------------------------------------------------------
// Run helper
// ---------------------------------------------------------------------------

void GuiApp::run_yara_mem_scan_with_params() {
    ensure_pass_manager();

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;

    if (yara_rules_path_buf_[0] != '\0') {
        cfg.user_rules_dir = std::filesystem::path(yara_rules_path_buf_);
    }

    // Invalidate previous result
    if (pass_manager_->state("yara_mem_scan") != PassManager::PassState::NotRun) {
        pass_manager_->invalidate_and_clear_blob("yara_mem_scan");
    }
    pass_manager_->register_pass(std::make_unique<YaraMemScanPass>(std::move(cfg)));
    yara_mem_result_ = nullptr;

    std::string name_str = "yara_mem_scan";
    enqueue_async(name_str, [this, name_str]() {
        auto& raw = pass_manager_->require(name_str);
        std::string summary = tenet::summarize_pass_result(name_str, raw);
        bool ok = raw.ok();
        post_apply([this, name_str, summary, ok]() {
            last_pass_status_ = fmt::format("{}: {}", name_str, summary);
            if (ok) apply_pass_result_pointers(name_str);
        });
    });
}

// ---------------------------------------------------------------------------
// Panel renderer
// ---------------------------------------------------------------------------

void GuiApp::render_yara_mem_scan_panel() {
    if (!ImGui::Begin("YARA Memory Scan", &show_yara_mem_scan_)) {
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── No result yet — show parameter form ───────────────────────────
    if (!yara_mem_result_) {
        ImGui::TextDisabled(ICON_FA_SHIELD_HALVED "  YARA Memory Scan");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Scan memory snapshots with YARA rules to detect crypto constants,\n"
            "anti-debug strings, network protocols, and more.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // YARA rules directory
        ImGui::Text("User YARA rules directory (optional):");
        ImGui::PushItemWidth(panel_w * 0.85f);
        ImGui::InputText("##yara_dir", yara_rules_path_buf_,
            sizeof(yara_rules_path_buf_));
        ImGui::PopItemWidth();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Path to a directory containing .yar rule files.\n"
                              "Default rules are loaded automatically.");

        ImGui::Spacing();

        if (ImGui::Button(ICON_FA_SHIELD_HALVED " Run YARA Scan")) {
            run_yara_mem_scan_with_params();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Scan all active memory pages at end of trace\n"
                              "using default + user YARA rules");

        ImGui::End();
        return;
    }

    // ── Result available ──────────────────────────────────────────────

    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_SHIELD_HALVED "  %zu matches  |  %llu pages scanned  |  %llu bytes",
        yara_mem_result_->total(),
        (unsigned long long)yara_mem_result_->pages_scanned,
        (unsigned long long)yara_mem_result_->bytes_scanned);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        yara_mem_result_ = nullptr;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run YARA scan with different rules");

    ImGui::Separator();

    // ── View-mode filter ─────────────────────────────────────────────
    ImGui::RadioButton("All",        &yara_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Crypto",     &yara_view_mode_, 1);
    ImGui::SameLine();
    ImGui::RadioButton("AntiDebug",  &yara_view_mode_, 2);
    ImGui::SameLine();
    ImGui::RadioButton("Other",      &yara_view_mode_, 3);

    // Text filter
    ImGui::SameLine(0, 8);
    ImGui::PushItemWidth(panel_w * 0.25f);
    if (ImGui::InputText("Filter##yf", yara_filter_buf_,
                         sizeof(yara_filter_buf_))) {
        yara_filter_ = yara_filter_buf_;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine(0, 4);
    if (ImGui::SmallButton("x##yfclr")) {
        std::memset(yara_filter_buf_, 0, sizeof(yara_filter_buf_));
        yara_filter_.clear();
    }

    ImGui::Separator();

    // ── Build filtered index ──────────────────────────────────────────
    const auto& matches = yara_mem_result_->matches;
    std::vector<size_t> filtered;
    filtered.reserve(matches.size());

    for (size_t i = 0; i < matches.size(); ++i) {
        const YaraMemMatch& m = matches[i];
        if (yara_view_mode_ == 1 && m.category != PatternCategory::Crypto)     continue;
        if (yara_view_mode_ == 2 && m.category != PatternCategory::AntiDebug)  continue;
        if (yara_view_mode_ == 3 &&
            (m.category == PatternCategory::Crypto ||
             m.category == PatternCategory::AntiDebug)) continue;
        if (!yara_filter_.empty()) {
            if (m.rule_name.find(yara_filter_) == std::string::npos &&
                m.description.find(yara_filter_) == std::string::npos)
                continue;
        }
        filtered.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu / %zu", filtered.size(), matches.size());
    ImGui::Separator();

    // ── Results table ─────────────────────────────────────────────────
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("YaraTable", 6,
            ImGuiTableFlags_Resizable    | ImGuiTableFlags_RowBg         |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY      |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Rule",       ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Category",   ImGuiTableColumnFlags_WidthFixed,   75.0f);
        ImGui::TableSetupColumn("Conf.",       ImGuiTableColumnFlags_WidthFixed,   50.0f);
        ImGui::TableSetupColumn("Match Addr",  ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("Len",         ImGuiTableColumnFlags_WidthFixed,   45.0f);
        ImGui::TableSetupColumn("inst#",       ImGuiTableColumnFlags_WidthFixed,   60.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t idx = filtered[static_cast<size_t>(row)];
                const YaraMemMatch& m = matches[idx];

                ImGui::TableNextRow();

                // Rule name — selectable
                ImGui::TableSetColumnIndex(0);
                char id_label[64];
                snprintf(id_label, sizeof(id_label), "%s##yr%zu", m.rule_name.c_str(), idx);
                if (ImGui::Selectable(id_label, false,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    if (m.at_inst_id != 0) navigate_to(m.at_inst_id);
                }
                if (ImGui::IsItemHovered()) {
                    std::string tip = m.description;
                    if (!m.scan_label.empty()) tip += "\nScan: " + m.scan_label;
                    tip += fmt::format("\n\nMatch at 0x{:x} + {} = 0x{:x}",
                                       m.scan_addr, m.match_offset, m.match_addr);
                    ImGui::SetTooltip("%s", tip.c_str());
                }

                // Category
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(category_color(m.category), "%s",
                                   category_str(m.category));

                // Confidence
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(confidence_str(m.confidence));

                // Match address
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("0x%llx", (unsigned long long)m.match_addr);

                // Match length
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%u", m.match_length);

                // inst#
                ImGui::TableSetColumnIndex(5);
                if (m.at_inst_id != 0) {
                    ImGui::TextDisabled("#%llu", (unsigned long long)m.at_inst_id);
                } else {
                    ImGui::TextDisabled("—");
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

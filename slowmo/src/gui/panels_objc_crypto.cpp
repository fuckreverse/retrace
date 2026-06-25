// panels_objc_crypto.cpp — ObjC × Crypto correlation panel.
//
// Displays the ObjcCryptoResult from ObjcCryptoPass, showing which ObjC
// call chains lead to crypto / anti-debug / pattern hits. Three view modes:
//   All       — every hit (ObjC-context + bare)
//   In ObjC   — only hits inside an ObjC dispatch chain
//   Bare      — only hits without any ObjC context
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/pattern_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>

namespace tenet {

// ── Color helpers (local) ──────────────────────────────────────────────────

static ImVec4 category_color(PatternCategory cat) {
    switch (cat) {
        case PatternCategory::Crypto:       return ImVec4(0.40f, 0.90f, 0.70f, 1.0f);  // teal-green
        case PatternCategory::AntiDebug:    return ImVec4(1.00f, 0.45f, 0.35f, 1.0f);  // red-orange
        case PatternCategory::AntiTamper:   return ImVec4(1.00f, 0.65f, 0.20f, 1.0f);  // amber
        case PatternCategory::Obfuscation:  return ImVec4(0.75f, 0.55f, 1.00f, 1.0f);  // violet
        case PatternCategory::Networking:   return ImVec4(0.40f, 0.75f, 1.00f, 1.0f);  // sky-blue
        case PatternCategory::KeySchedule:  return ImVec4(1.00f, 0.85f, 0.30f, 1.0f);  // gold
        default:                            return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
    }
}

static const char* category_label(PatternCategory cat) {
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

static ImVec4 confidence_color(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::High:   return ImVec4(0.30f, 0.95f, 0.40f, 1.0f);  // bright green
        case PatternConfidence::Medium: return ImVec4(1.00f, 0.80f, 0.20f, 1.0f);  // yellow
        case PatternConfidence::Low:    return ImVec4(0.65f, 0.65f, 0.65f, 1.0f);  // grey
        default:                        return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
    }
}

static const char* confidence_label(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::High:   return "High";
        case PatternConfidence::Medium: return "Med";
        case PatternConfidence::Low:    return "Low";
        default:                        return "?";
    }
}

// ── Main panel ────────────────────────────────────────────────────────────

void GuiApp::render_objc_crypto_panel() {
    if (!ImGui::Begin("ObjC Crypto", &show_objc_crypto_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ─────────────────────────────────────────────────────
    if (!objc_crypto_result_) {
        ImGui::TextDisabled("No ObjC Crypto analysis performed.");
        ImGui::Spacing();
        ImGui::TextWrapped("Correlates crypto / anti-debug pattern hits with the "
                           "ObjC call chain in which they occurred.");
        ImGui::Spacing();
        if (ImGui::Button("Run ObjC Crypto")) {
            run_pass_by_name("objc_crypto");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Run ObjcCryptoPass (requires PatternPass + ObjcPass).\n"
                              "Answers: which ObjC method chain calls this crypto code?");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ────────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.40f, 0.90f, 0.70f, 1.0f),
        "\xef\x87\xbb  %zu hits",          // lock icon approximation
        objc_crypto_result_->total());
    ImGui::SameLine(0, 12);
    ImGui::TextColored(ImVec4(0.40f, 0.75f, 1.00f, 1.0f),
        "In ObjC: %zu", objc_crypto_result_->in_objc_count());
    ImGui::SameLine(0, 12);
    ImGui::TextColored(ImVec4(0.65f, 0.65f, 0.65f, 1.0f),
        "Bare: %zu", objc_crypto_result_->bare_count());

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {  // ↺
        run_pass_by_name("objc_crypto");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run ObjC Crypto analysis (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ──────────────────────────────────────────────────
    ImGui::RadioButton("All",      &objc_crypto_view_mode_, 0); ImGui::SameLine();
    ImGui::RadioButton("In ObjC",  &objc_crypto_view_mode_, 1); ImGui::SameLine();
    ImGui::RadioButton("Bare",     &objc_crypto_view_mode_, 2);

    ImGui::Separator();

    // ── Search filter ─────────────────────────────────────────────────────
    ImGui::PushItemWidth(panel_w * 0.55f);
    if (ImGui::InputText("Filter##ocf", objc_crypto_filter_buf_,
                         sizeof(objc_crypto_filter_buf_))) {
        objc_crypto_filter_ = objc_crypto_filter_buf_;
        objc_crypto_cursor_ = 0;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine(0, 6);
    if (ImGui::SmallButton("x##ocfclr")) {
        std::memset(objc_crypto_filter_buf_, 0, sizeof(objc_crypto_filter_buf_));
        objc_crypto_filter_.clear();
        objc_crypto_cursor_ = 0;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filter");
    ImGui::SameLine(0, 6);
    ImGui::TextDisabled("(pattern name or ObjC chain)");

    // ── Build filtered index list ─────────────────────────────────────────
    const auto& hits = objc_crypto_result_->hits;
    std::vector<size_t> view_indices;
    switch (objc_crypto_view_mode_) {
        case 1: view_indices = objc_crypto_result_->objc_pattern_indices; break;
        case 2: view_indices = objc_crypto_result_->bare_pattern_indices;  break;
        default:
            view_indices.resize(hits.size());
            for (size_t i = 0; i < hits.size(); ++i) view_indices[i] = i;
            break;
    }

    std::vector<size_t> filtered;
    filtered.reserve(view_indices.size());
    for (size_t idx : view_indices) {
        const ObjcCryptoHit& h = hits[idx];
        if (!objc_crypto_filter_.empty()) {
            bool match = (h.pattern_name.find(objc_crypto_filter_) != std::string::npos)
                      || (h.objc_chain_summary().find(objc_crypto_filter_) != std::string::npos);
            if (!match) continue;
        }
        filtered.push_back(idx);
    }

    ImGui::TextDisabled("Showing %zu / %zu", filtered.size(), hits.size());
    ImGui::Separator();

    // ── Main table ────────────────────────────────────────────────────────
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("ObjcCryptoTable", 4,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",          ImGuiTableColumnFlags_WidthFixed,   60.0f);
        ImGui::TableSetupColumn("Pattern",    ImGuiTableColumnFlags_WidthStretch, 0.30f);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed,   72.0f);
        ImGui::TableSetupColumn("ObjC Chain", ImGuiTableColumnFlags_WidthStretch, 0.70f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t hit_idx = filtered[static_cast<size_t>(row)];
                const ObjcCryptoHit& hit = hits[hit_idx];
                bool selected = (objc_crypto_cursor_ == static_cast<size_t>(row));

                ImGui::TableNextRow();

                // ── Column 0: inst_id / navigation ───────────────────────
                ImGui::TableSetColumnIndex(0);
                char id_label[40];
                snprintf(id_label, sizeof(id_label), "#%llu##occ%zu",
                         (unsigned long long)hit.pattern_start_inst, hit_idx);
                if (ImGui::Selectable(id_label, selected,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    objc_crypto_cursor_ = static_cast<size_t>(row);
                    navigate_to(hit.pattern_start_inst);
                }

                // ── Hover tooltip ─────────────────────────────────────────
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format(
                        "Pattern: {}\nCategory: {}\nInst range: {} – {}\nAnchor PC: 0x{:x}\n",
                        hit.pattern_name,
                        category_label(hit.category),
                        hit.pattern_start_inst, hit.pattern_end_inst,
                        hit.anchor_pc);
                    if (!hit.description.empty())
                        tip += fmt::format("\n{}\n", hit.description);
                    const ObjcCallFrame* inner = hit.innermost_frame();
                    if (inner) {
                        tip += fmt::format("\nInnermost ObjC frame:\n"
                                           "  [{} {}]\n"
                                           "  inst_id: {}  PC: 0x{:x}\n"
                                           "  receiver: 0x{:x}",
                                           inner->class_name, inner->selector_name,
                                           inner->inst_id, inner->objc_pc,
                                           inner->receiver);
                    } else {
                        tip += "\n(no ObjC context — bare pattern)";
                    }
                    tip += "\n\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());
                    if (ImGui::IsMouseDoubleClicked(0))
                        navigate_to(hit.pattern_start_inst);
                }

                // ── Right-click context menu ───────────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextColored(category_color(hit.category),
                                       "%s", hit.pattern_name.c_str());
                    ImGui::TextDisabled("[%llu..%llu]",
                                        (unsigned long long)hit.pattern_start_inst,
                                        (unsigned long long)hit.pattern_end_inst);
                    ImGui::Separator();
                    if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions")) {
                        navigate_to_instructions(hit.pattern_start_inst);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)hit.pattern_start_inst);
                    if (ImGui::MenuItem("Jump to End")) {
                        navigate_to(hit.pattern_end_inst);
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy PC")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)hit.anchor_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // ── Column 1: pattern name ────────────────────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(category_color(hit.category),
                                   "%s", hit.pattern_name.c_str());
                ImGui::SameLine(0, 5);
                ImGui::TextDisabled("[%s]", category_label(hit.category));

                // ── Column 2: confidence ──────────────────────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(confidence_color(hit.confidence),
                                   "%s", confidence_label(hit.confidence));

                // ── Column 3: ObjC chain ──────────────────────────────────
                ImGui::TableSetColumnIndex(3);
                if (!hit.objc_stack.empty()) {
                    std::string chain = hit.objc_chain_summary();
                    // Expandable tree node for stack detail
                    char node_id[32];
                    snprintf(node_id, sizeof(node_id), "##ocstk%zu", hit_idx);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.60f, 0.85f, 1.00f, 1.0f));
                    bool open = ImGui::TreeNodeEx(node_id,
                        ImGuiTreeNodeFlags_SpanFullWidth |
                        ImGuiTreeNodeFlags_NoTreePushOnOpen, "%s", chain.c_str());
                    ImGui::PopStyleColor();

                    // Expanded: show each frame as a child row
                    if (open) {
                        ImGui::TreePush(node_id);
                        for (size_t fi = 0; fi < hit.objc_stack.size(); ++fi) {
                            const ObjcCallFrame& frame = hit.objc_stack[fi];
                            bool is_inner = (fi + 1 == hit.objc_stack.size());
                            ImGui::PushStyleColor(ImGuiCol_Text,
                                is_inner
                                    ? ImVec4(0.45f, 0.95f, 0.60f, 1.0f)   // innermost: green
                                    : ImVec4(0.70f, 0.70f, 0.70f, 1.0f)); // outer: grey
                            char frame_label[256];
                            snprintf(frame_label, sizeof(frame_label),
                                     "%s[%s %s] @ #%llu (0x%llx)",
                                     is_inner ? "\xe2\x86\x92 " : "  ",   // → or spaces
                                     frame.class_name.c_str(),
                                     frame.selector_name.c_str(),
                                     (unsigned long long)frame.inst_id,
                                     (unsigned long long)frame.objc_pc);
                            if (ImGui::Selectable(frame_label, false,
                                    ImGuiSelectableFlags_AllowOverlap)) {
                                navigate_to(frame.inst_id);
                            }
                            ImGui::PopStyleColor();
                        }
                        ImGui::TreePop();
                    }
                } else {
                    ImGui::TextDisabled("(bare)");
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

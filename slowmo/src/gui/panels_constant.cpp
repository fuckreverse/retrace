// panels_constant.cpp — Constant materialization analysis panel.
//
// Displays the ConstantMaterializationResult from ConstantMaterializationPass.
// Shows every movz+movk sequence recovered from the trace and highlights
// those that matched known algorithm constants (SHA-256, AES, SM3, SM4, …).
//
// Two view modes:
//   0 = All     : every materialized constant (identified + unknown)
//   1 = Identified Only : only those with a known_match
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/constant_materialization_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>

namespace tenet {

// ── Internal helpers ──────────────────────────────────────────────────────

/// Format a register index as "x0" … "x28", "fp", "lr", "sp".
static const char* reg_name(uint8_t idx) {
    static const char* kNames[] = {
        "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
        "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "fp",  "lr",  "sp",
    };
    if (idx < 32) return kNames[idx];
    return "??";
}

// ─────────────────────────────────────────────────────────────────────────────

void GuiApp::render_constant_panel() {
    if (!ImGui::Begin("Constants", &show_constant_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ────────────────────────────────────────────────────
    if (!constant_result_) {
        ImGui::TextDisabled("No constant analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Constant Analysis")) {
            run_pass_by_name("constant_materialization");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Scan the trace for movz+movk constant construction sequences\n"
                "and identify known algorithm constants (SHA-256, AES, SM3, SM4, …).");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ───────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        "\xe2\x97\x89  %zu total,  %zu identified",   // ◉ U+25C9 (was 🔐 U+1F510 emoji)
        constant_result_->total(),
        constant_result_->identified_count());

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {        // ↺
        run_pass_by_name("constant_materialization");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run constant analysis (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ─────────────────────────────────────────────────
    ImGui::RadioButton("All", &constant_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Identified Only", &constant_view_mode_, 1);

    ImGui::Separator();

    // ── Search / filter bar ──────────────────────────────────────────────
    ImGui::PushItemWidth(panel_w - 48.0f);
    if (ImGui::InputText("##constfilt", constant_filter_buf_,
                         sizeof(constant_filter_buf_))) {
        constant_filter_ = constant_filter_buf_;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine(0, 6);
    if (ImGui::SmallButton("x##clrconst")) {
        std::memset(constant_filter_buf_, 0, sizeof(constant_filter_buf_));
        constant_filter_.clear();
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filter");
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal) &&
        constant_filter_.empty()) {
        ImGui::SetTooltip("Filter by algorithm name or constant name");
    }

    // ── Build filtered row list (cached) ────────────────────────────────
    // Only rebuild when result pointer, view mode, or filter string changes.
    // This avoids O(N) vector construction + push_back + destructor every frame.
    if (constant_row_cache_.source  != constant_result_ ||
        constant_row_cache_.view_mode != constant_view_mode_ ||
        constant_row_cache_.filter  != constant_filter_) {

        auto& rows = constant_row_cache_.rows;
        rows.clear();
        rows.reserve(constant_result_->constants.size());

        for (const auto& c : constant_result_->constants) {
            if (constant_view_mode_ == 1 && c.known_match == nullptr)
                continue;
            if (!constant_filter_.empty()) {
                bool hit = false;
                if (c.known_match) {
                    if (c.known_match->algorithm.find(constant_filter_) != std::string::npos)
                        hit = true;
                    if (c.known_match->name.find(constant_filter_) != std::string::npos)
                        hit = true;
                }
                if (!hit) continue;
            }
            rows.push_back(&c);
        }

        constant_row_cache_.source    = constant_result_;
        constant_row_cache_.view_mode = constant_view_mode_;
        constant_row_cache_.filter    = constant_filter_;
    }
    const auto& rows = constant_row_cache_.rows;

    ImGui::TextDisabled("Showing %zu / %zu",
                        rows.size(), constant_result_->constants.size());
    ImGui::Separator();

    // ── Main table ───────────────────────────────────────────────────────
    const float row_h    = ImGui::GetTextLineHeightWithSpacing();
    ImVec2      tbl_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("ConstTable", 5,
            ImGuiTableFlags_Resizable      |
            ImGuiTableFlags_RowBg          |
            ImGuiTableFlags_BordersInnerV  |
            ImGuiTableFlags_ScrollY        |
            ImGuiTableFlags_SizingStretchProp,
            tbl_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",     ImGuiTableColumnFlags_WidthFixed,   60.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed,  145.0f);
        ImGui::TableSetupColumn("Reg",   ImGuiTableColumnFlags_WidthFixed,   38.0f);
        ImGui::TableSetupColumn("Parts", ImGuiTableColumnFlags_WidthFixed,   44.0f);
        ImGui::TableSetupColumn("Match", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(rows.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const MaterializedConstant& c =
                    *rows[static_cast<size_t>(row)];

                ImGui::TableNextRow();

                // ── Column 0: inst_id (selectable) ───────────────────
                ImGui::TableSetColumnIndex(0);
                char id_label[40];
                snprintf(id_label, sizeof(id_label), "#%llu##cm%d",
                         (unsigned long long)c.first_inst_id, row);
                if (ImGui::Selectable(id_label, false,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    navigate_to(c.first_inst_id);
                }

                // ── Tooltip on hover ─────────────────────────────────
                if (ImGui::IsItemHovered()) {
                    if (c.known_match) {
                        std::string tip = fmt::format(
                            "inst #{} – #{}\n"
                            "PC: 0x{:x} – 0x{:x}\n"
                            "Value: 0x{:016x}\n"
                            "Parts: {}\n"
                            "\n"
                            "Algorithm : {}\n"
                            "Name      : {}\n"
                            "Description: {}\n"
                            "\nRight-click for more options",
                            c.first_inst_id, c.last_inst_id,
                            c.pc_first, c.pc_last,
                            c.value,
                            (int)c.num_parts,
                            c.known_match->algorithm,
                            c.known_match->name,
                            c.known_match->description);
                        ImGui::SetTooltip("%s", tip.c_str());
                    } else {
                        std::string tip = fmt::format(
                            "inst #{} – #{}\n"
                            "PC: 0x{:x} – 0x{:x}\n"
                            "Value: 0x{:016x}\n"
                            "Parts: {}\n"
                            "No known match\n"
                            "\nRight-click for more options",
                            c.first_inst_id, c.last_inst_id,
                            c.pc_first, c.pc_last,
                            c.value,
                            (int)c.num_parts);
                        ImGui::SetTooltip("%s", tip.c_str());
                    }
                    if (ImGui::IsMouseDoubleClicked(0))
                        navigate_to(c.first_inst_id);
                }

                // ── Right-click context menu ──────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextDisabled("0x%016llx", (unsigned long long)c.value);
                    if (c.known_match)
                        ImGui::TextDisabled("%s:%s", c.known_match->algorithm.c_str(),
                                            c.known_match->name.c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions")) {
                        navigate_to_instructions(c.first_inst_id);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)c.first_inst_id);
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy Value")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%016llx",
                                 (unsigned long long)c.value);
                        ImGui::SetClipboardText(buf);
                    }
                    if (ImGui::MenuItem("Copy PC")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)c.pc_first);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // ── Column 1: Value ───────────────────────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("0x%016llx", (unsigned long long)c.value);

                // ── Column 2: Reg ─────────────────────────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(ImVec4(0.75f, 0.92f, 0.6f, 1.0f),
                                   "%s", reg_name(c.dst_reg));

                // ── Column 3: Parts ───────────────────────────────────
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%u", (unsigned)c.num_parts);

                // ── Column 4: Match ───────────────────────────────────
                ImGui::TableSetColumnIndex(4);
                if (c.known_match) {
                    // Green: "algorithm:name"
                    std::string match_str = fmt::format("{}:{}",
                        c.known_match->algorithm, c.known_match->name);
                    ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f),
                                       "%s", match_str.c_str());
                } else {
                    ImGui::TextDisabled("\xe2\x80\x94");  // —
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

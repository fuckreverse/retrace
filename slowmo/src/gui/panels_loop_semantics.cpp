// panels_loop_semantics.cpp — Loop semantic classification panel.
//
// Displays the LoopSemanticsResult from LoopSemanticsPass in a compact table:
//   PC | Kind (coloured) | Iters | Confidence (progress bar) | Features
//
// Click a row to navigate to sample_iter_start.
// Hover a row for a tooltip showing description, active registers, and body
// instruction count.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/loop_semantics_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <string>
#include <vector>

namespace tenet {

// ─── Color helpers ────────────────────────────────────────────────────────

/// Returns a display color for a LoopKind.
static ImVec4 loop_kind_color(LoopKind k) {
    switch (k) {
        case LoopKind::FeistelRound:  return ImVec4(1.00f, 0.65f, 0.20f, 1.0f); // orange
        case LoopKind::SPNRound:      return ImVec4(1.00f, 0.60f, 0.15f, 1.0f); // orange
        case LoopKind::ARXRound:      return ImVec4(1.00f, 0.70f, 0.25f, 1.0f); // orange
        case LoopKind::ShiftRotate:   return ImVec4(0.95f, 0.65f, 0.25f, 1.0f); // orange
        case LoopKind::Accumulator:   return ImVec4(0.45f, 0.70f, 1.00f, 1.0f); // blue
        case LoopKind::MemcpyLike:    return ImVec4(0.50f, 0.75f, 1.00f, 1.0f); // blue
        case LoopKind::CounterLoop:   return ImVec4(0.65f, 0.65f, 0.65f, 1.0f); // grey
        case LoopKind::Unknown:       return ImVec4(0.45f, 0.45f, 0.45f, 1.0f); // dark grey
    }
    return ImVec4(0.45f, 0.45f, 0.45f, 1.0f);
}

/// Returns the confidence bar color based on threshold.
static ImVec4 confidence_color(float c) {
    if (c >= 0.8f) return ImVec4(0.30f, 0.85f, 0.40f, 1.0f);  // green
    if (c >= 0.5f) return ImVec4(0.95f, 0.85f, 0.20f, 1.0f);  // yellow
    return ImVec4(0.55f, 0.55f, 0.55f, 1.0f);                  // grey
}

// ─── Register name helper ─────────────────────────────────────────────────

/// Returns the AArch64 register name for a register index (x0-x28, fp, lr, sp, nzcv, pc).
static const char* reg_name(uint8_t idx) {
    static const char* names[] = {
        "x0","x1","x2","x3","x4","x5","x6","x7",
        "x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23",
        "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
    };
    if (idx < 34) return names[idx];
    return "?";
}

// ─── Panel ────────────────────────────────────────────────────────────────

void GuiApp::render_loop_semantics_panel() {
    if (!ImGui::Begin("Loop Semantics", &show_loop_semantics_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!loop_semantics_result_) {
        ImGui::TextDisabled("No loop semantics analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Loop Semantics")) {
            run_pass_by_name("loop_semantics");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Classify loops by semantic behavior to identify crypto\n"
                              "round functions: Feistel, SPN, ARX, ShiftRotate, etc.\n"
                              "Depends on 'loop' and 'xref' passes.");
        }
        ImGui::End();
        return;
    }

    const LoopSemanticsResult& res = *loop_semantics_result_;
    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    size_t total_loops  = res.loop_semantics.size();
    size_t crypto_count = res.crypto_loops().size();

    ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.55f, 1.0f),
        "\xf0\x9f\x94\x84  %zu loops  |  %zu crypto",  // 🔄
        total_loops, crypto_count);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {  // ↺
        run_pass_by_name("loop_semantics");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run loop semantics analysis (clears current results)");

    ImGui::Separator();

    // ── Main table ─────────────────────────────────────────────────────────
    const float row_h   = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("LoopSemTable", 5,
            ImGuiTableFlags_Resizable    | ImGuiTableFlags_RowBg         |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY       |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PC",         ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("Kind",       ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("Iters",      ImGuiTableColumnFlags_WidthFixed,   55.0f);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("Features",   ImGuiTableColumnFlags_WidthStretch, 0.35f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(res.loop_semantics.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const LoopSemanticInfo& loop =
                    res.loop_semantics[static_cast<size_t>(row)];

                ImGui::TableNextRow();

                // ── PC column (selectable spanning all columns) ──────────
                ImGui::TableSetColumnIndex(0);
                char sel_label[48];
                snprintf(sel_label, sizeof(sel_label), "0x%llx##lsrow%d",
                         (unsigned long long)loop.header_pc, row);
                if (ImGui::Selectable(sel_label, false,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    if (loop.sample_iter_start != 0)
                        navigate_to(loop.sample_iter_start);
                }

                // ── Hover tooltip ────────────────────────────────────────
                if (ImGui::IsItemHovered()) {
                    // Build active_regs string
                    std::string active_str;
                    for (size_t i = 0; i < loop.active_regs.size(); ++i) {
                        if (i > 0) active_str += ", ";
                        active_str += reg_name(loop.active_regs[i]);
                    }
                    if (active_str.empty()) active_str = "(none)";

                    std::string tip = fmt::format(
                        "{}\n\nPC: 0x{:x}\nIterations: {}\nBody instructions: {}\n"
                        "Active regs: {}\nSample range: #{}\u2013#{}"
                        "\n\nRight-click for more options",
                        loop.description.empty() ? loop_kind_name(loop.kind)
                                                  : loop.description,
                        loop.header_pc,
                        loop.iteration_count,
                        loop.body_instruction_count,
                        active_str,
                        loop.sample_iter_start,
                        loop.sample_iter_end);
                    ImGui::SetTooltip("%s", tip.c_str());

                    if (ImGui::IsMouseDoubleClicked(0) && loop.sample_iter_start != 0)
                        navigate_to(loop.sample_iter_start);
                }

                // ── Right-click context menu ─────────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextDisabled("PC: 0x%llx", (unsigned long long)loop.header_pc);
                    ImGui::TextDisabled("%s  ×%llu", loop_kind_name(loop.kind),
                                        (unsigned long long)loop.iteration_count);
                    ImGui::Separator();
                    if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions",
                                        nullptr, false,
                                        loop.sample_iter_start != 0)) {
                        navigate_to_instructions(loop.sample_iter_start);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)loop.sample_iter_start);
                    if (ImGui::MenuItem("Copy PC")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)loop.header_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // ── Kind column ──────────────────────────────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(loop_kind_color(loop.kind),
                                   "%s", loop_kind_name(loop.kind));

                // ── Iters column ─────────────────────────────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%llu", (unsigned long long)loop.iteration_count);

                // ── Confidence column (inline progress bar) ───────────────
                ImGui::TableSetColumnIndex(3);
                {
                    ImVec4 bar_col = confidence_color(loop.confidence);
                    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_col);
                    char conf_label[32];
                    snprintf(conf_label, sizeof(conf_label), "%.0f%%##lsconf%d",
                             loop.confidence * 100.0f, row);
                    float bar_w = ImGui::GetContentRegionAvail().x;
                    ImGui::ProgressBar(loop.confidence,
                                       ImVec2(bar_w, row_h * 0.65f),
                                       conf_label);
                    ImGui::PopStyleColor();
                }

                // ── Features column ──────────────────────────────────────
                // Show small colored badges: S X R A M
                ImGui::TableSetColumnIndex(4);
                {
                    bool any = false;
                    auto feature_badge = [&](bool flag, const char* tag, ImVec4 col) {
                        if (!flag) return;
                        if (any) ImGui::SameLine(0, 3);
                        ImGui::TextColored(col, "%s", tag);
                        any = true;
                    };
                    feature_badge(loop.has_sbox_pattern,       "S",
                                  ImVec4(0.95f, 0.50f, 0.50f, 1.0f));  // red — S-box
                    feature_badge(loop.has_xor_mix,            "X",
                                  ImVec4(0.40f, 0.85f, 0.55f, 1.0f));  // green — XOR
                    feature_badge(loop.has_shift_rotate,       "R",
                                  ImVec4(0.50f, 0.75f, 1.00f, 1.0f));  // blue — Rotate
                    feature_badge(loop.has_addition_chain,     "A",
                                  ImVec4(0.95f, 0.85f, 0.30f, 1.0f));  // yellow — Add
                    feature_badge(loop.has_modular_arithmetic, "M",
                                  ImVec4(0.85f, 0.55f, 1.00f, 1.0f));  // purple — Mod
                    if (!any) ImGui::TextDisabled("—");
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

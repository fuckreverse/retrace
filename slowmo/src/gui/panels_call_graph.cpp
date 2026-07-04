// panels_call_graph.cpp — Call graph analysis panel.
//
// Displays the CallGraphResult from CallGraphPass in two views:
//   1. Hot Callees view: top-50 most-called functions with a progress bar.
//   2. Edges view:       every caller→callee edge with call counts and sites.
//
// Navigation to a function entry or call site uses XrefResult (if available)
// to resolve PC → inst_id; clicking is disabled when xref is absent.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/structure/xref_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ── Internal helpers ────────────────────────────────────────────────────────

/// Return "name" if non-empty, otherwise "0x<hex>".
static std::string node_label(const CallGraphNode& node) {
    if (!node.name.empty())
        return node.name;
    return fmt::format("0x{:x}", node.entry_pc);
}

/// Resolve a PC to the first inst_id via xref (if available).
/// Returns UINT64_MAX when navigation is not possible.
static uint64_t pc_to_inst_id(const XrefResult* xref, uint64_t pc) {
    if (!xref) return UINT64_MAX;
    return xref->first_inst_id_at(pc);
}

// ── Panel ───────────────────────────────────────────────────────────────────

void GuiApp::render_call_graph_panel() {
    if (!ImGui::Begin("Call Graph", &show_call_graph_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!call_graph_result_) {
        ImGui::TextDisabled("No call graph analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Call Graph")) {
            run_call_graph_analysis();
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Build the call graph from function analysis results.\n"
                              "Requires function analysis to be run first.");
        }
        ImGui::End();
        return;
    }

    const CallGraphResult& cg = *call_graph_result_;
    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_DIAGRAM_PROJECT "  %zu nodes  |  %zu edges  |  %llu calls  |  depth %llu",
        cg.nodes.size(),
        cg.edges.size(),
        (unsigned long long)cg.total_call_events,
        (unsigned long long)cg.max_depth);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        run_call_graph_analysis();
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run call graph analysis (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ───────────────────────────────────────────────────
    ImGui::RadioButton("Hot Callees", &call_graph_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Edges", &call_graph_view_mode_, 1);

    ImGui::Separator();

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 0: Hot Callees
    // ══════════════════════════════════════════════════════════════════════
    if (call_graph_view_mode_ == 0) {
        auto hot = cg.hottest_callees(50);

        ImGui::TextDisabled("Top %zu functions by calls received", hot.size());
        if (!xref_result_) {
            ImGui::SameLine(0, 8);
            ImGui::TextDisabled("(run XRef to enable navigation)");
        }
        ImGui::Separator();

        const uint64_t max_count = hot.empty() ? 1 : hot[0].second;

        const float row_h = ImGui::GetTextLineHeightWithSpacing();
        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

        if (ImGui::BeginTable("CgHotTable", 3,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Rank",       ImGuiTableColumnFlags_WidthFixed,   50.0f);
            ImGui::TableSetupColumn("Function",   ImGuiTableColumnFlags_WidthStretch, 0.55f);
            ImGui::TableSetupColumn("Call Count", ImGuiTableColumnFlags_WidthStretch, 0.45f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(hot.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const auto& [entry_pc, count] = hot[static_cast<size_t>(row)];
                    const CallGraphNode* node = cg.node_at(entry_pc);
                    bool selected = (call_graph_selected_pc_ == entry_pc);

                    ImGui::TableNextRow();

                    // Rank column — Selectable spans all columns
                    ImGui::TableSetColumnIndex(0);
                    char rank_label[32];
                    snprintf(rank_label, sizeof(rank_label), "%d##cgr%d", row + 1, row);

                    uint64_t nav_id = pc_to_inst_id(xref_result_, entry_pc);
                    bool can_nav = (nav_id != UINT64_MAX);

                    if (!can_nav) ImGui::BeginDisabled();
                    if (ImGui::Selectable(rank_label, selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        call_graph_selected_pc_ = entry_pc;
                        navigate_to(nav_id);
                    }
                    if (!can_nav) ImGui::EndDisabled();

                    // Tooltip: callers / callees counts
                    if (ImGui::IsItemHovered() && node) {
                        ImGui::SetTooltip(
                            "PC: 0x%llx\n"
                            "Outgoing calls made: %llu\n"
                            "Incoming calls received: %llu\n"
                            "Unique callers: %zu\n"
                            "Unique callees: %zu",
                            (unsigned long long)entry_pc,
                            (unsigned long long)node->total_calls_made,
                            (unsigned long long)node->total_calls_received,
                            node->incoming_edges.size(),
                            node->outgoing_edges.size());
                    }

                    // Function column
                    ImGui::TableSetColumnIndex(1);
                    if (node && !node->name.empty()) {
                        ImGui::TextColored(ImVec4(0.6f, 0.9f, 0.6f, 1.0f),
                                           "%s", node->name.c_str());
                    } else {
                        ImGui::TextDisabled("0x%llx", (unsigned long long)entry_pc);
                    }

                    // Call count column with progress bar overlay
                    ImGui::TableSetColumnIndex(2);
                    float frac = (max_count > 0)
                        ? static_cast<float>(count) / static_cast<float>(max_count)
                        : 0.0f;
                    char bar_label[32];
                    snprintf(bar_label, sizeof(bar_label), "%llu", (unsigned long long)count);
                    ImGui::PushStyleColor(ImGuiCol_PlotHistogram,
                                         ImVec4(0.25f, 0.60f, 0.90f, 0.75f));
                    ImGui::ProgressBar(frac, ImVec2(-FLT_MIN, 0.0f), bar_label);
                    ImGui::PopStyleColor();
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 1: Edges
    // ══════════════════════════════════════════════════════════════════════
    else {
        // ── Filter bar ────────────────────────────────────────────────────
        ImGui::PushItemWidth(panel_w * 0.60f);
        if (ImGui::InputText("Filter##cgef", call_graph_filter_buf_,
                             sizeof(call_graph_filter_buf_))) {
            call_graph_filter_ = call_graph_filter_buf_;
        }
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 6);
        if (ImGui::SmallButton("x##cgclr")) {
            std::memset(call_graph_filter_buf_, 0, sizeof(call_graph_filter_buf_));
            call_graph_filter_.clear();
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filter");

        // ── Build filtered edge list (case-sensitive substring on caller/callee label)
        std::vector<size_t> filtered;
        filtered.reserve(cg.edges.size());
        for (size_t i = 0; i < cg.edges.size(); ++i) {
            const CallGraphEdge& e = cg.edges[i];
            if (!call_graph_filter_.empty()) {
                std::string caller_str, callee_str;
                if (const CallGraphNode* cn = cg.node_at(e.caller_pc))
                    caller_str = node_label(*cn);
                else
                    caller_str = fmt::format("0x{:x}", e.caller_pc);
                if (const CallGraphNode* cn = cg.node_at(e.callee_pc))
                    callee_str = node_label(*cn);
                else
                    callee_str = fmt::format("0x{:x}", e.callee_pc);

                bool match = (caller_str.find(call_graph_filter_) != std::string::npos)
                          || (callee_str.find(call_graph_filter_) != std::string::npos);
                if (!match) continue;
            }
            filtered.push_back(i);
        }

        ImGui::TextDisabled("Showing %zu / %zu edges", filtered.size(), cg.edges.size());
        if (!xref_result_) {
            ImGui::SameLine(0, 8);
            ImGui::TextDisabled("(run XRef to enable navigation)");
        }
        ImGui::Separator();

        const float row_h = ImGui::GetTextLineHeightWithSpacing();
        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

        if (ImGui::BeginTable("CgEdgeTable", 4,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Caller",   ImGuiTableColumnFlags_WidthStretch, 0.35f);
            ImGui::TableSetupColumn("Callee",   ImGuiTableColumnFlags_WidthStretch, 0.35f);
            ImGui::TableSetupColumn("Count",    ImGuiTableColumnFlags_WidthFixed,   65.0f);
            ImGui::TableSetupColumn("Sites",    ImGuiTableColumnFlags_WidthFixed,   50.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(filtered.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    size_t idx = filtered[static_cast<size_t>(row)];
                    const CallGraphEdge& e = cg.edges[idx];

                    ImGui::TableNextRow();

                    // Caller column — Selectable spanning all columns
                    ImGui::TableSetColumnIndex(0);
                    std::string caller_label;
                    if (const CallGraphNode* cn = cg.node_at(e.caller_pc))
                        caller_label = node_label(*cn);
                    else
                        caller_label = fmt::format("0x{:x}", e.caller_pc);

                    char sel_id[80];
                    snprintf(sel_id, sizeof(sel_id), "%s##cge%zu",
                             caller_label.c_str(), idx);

                    // Navigate to first call site (if xref available)
                    uint64_t site_nav_id = UINT64_MAX;
                    if (!e.call_site_pcs.empty())
                        site_nav_id = pc_to_inst_id(xref_result_, e.call_site_pcs[0]);
                    bool can_nav = (site_nav_id != UINT64_MAX);

                    if (!can_nav) ImGui::BeginDisabled();
                    if (ImGui::Selectable(sel_id, false,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        navigate_to(site_nav_id);
                    }
                    if (!can_nav) ImGui::EndDisabled();

                    if (ImGui::IsItemHovered()) {
                        std::string tip = fmt::format(
                            "Caller: 0x{:x}\nCallee: 0x{:x}\nCall count: {}\n"
                            "Call sites ({}):",
                            e.caller_pc, e.callee_pc, e.call_count,
                            e.call_site_pcs.size());
                        size_t show = std::min(e.call_site_pcs.size(), size_t{8});
                        for (size_t k = 0; k < show; ++k)
                            tip += fmt::format("\n  0x{:x}", e.call_site_pcs[k]);
                        if (e.call_site_pcs.size() > 8)
                            tip += fmt::format("\n  (+{} more)",
                                               e.call_site_pcs.size() - 8);
                        if (can_nav)
                            tip += "\n\nClick to navigate to first call site";
                        ImGui::SetTooltip("%s", tip.c_str());
                    }

                    // Callee column
                    ImGui::TableSetColumnIndex(1);
                    if (const CallGraphNode* cn = cg.node_at(e.callee_pc)) {
                        if (!cn->name.empty()) {
                            ImGui::TextColored(ImVec4(0.6f, 0.9f, 0.6f, 1.0f),
                                               "%s", cn->name.c_str());
                        } else {
                            ImGui::TextDisabled("0x%llx", (unsigned long long)e.callee_pc);
                        }
                    } else {
                        ImGui::TextDisabled("0x%llx", (unsigned long long)e.callee_pc);
                    }

                    // Count column
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%llu", (unsigned long long)e.call_count);

                    // Sites column
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextDisabled("%zu", e.call_site_pcs.size());
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    ImGui::End();
}

}  // namespace tenet

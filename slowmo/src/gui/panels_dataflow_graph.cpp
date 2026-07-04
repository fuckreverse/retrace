// panels_dataflow_graph.cpp — Register-level data-flow graph panel.
//
// Independent floating window for DataflowGraphPass.
// Shows a parameter form (start/end inst_id range), then displays the
// resulting per-instruction node list with register/memory dependency
// edges. Selecting a node shows its producers (incoming edges) and
// consumers (outgoing edges) via the graph's O(1) adjacency index.
//
// Split out of panels_analysis.cpp. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>

#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ---------------------------------------------------------------------------
// Panel renderer
// ---------------------------------------------------------------------------

void GuiApp::render_dataflow_graph_panel() {
    if (!ImGui::Begin("Dataflow Graph", &show_dataflow_graph_)) {
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── No result yet — show parameter form ───────────────────────────
    if (!dataflow_graph_result_) {
        ImGui::TextDisabled(ICON_FA_DIAGRAM_PROJECT "  Dataflow Graph");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Build a register-level data-flow graph for an instruction "
            "range: each node is an executed instruction, edges represent "
            "register and memory dependencies (write \xe2\x86\x92 read).");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Start inst_id
        ImGui::Text("Start inst_id (hex or decimal):");
        ImGui::PushItemWidth(panel_w * 0.45f);
        bool start_entered = ImGui::InputText("##dfg_start", dataflow_graph_start_buf_,
            sizeof(dataflow_graph_start_buf_),
            ImGuiInputTextFlags_CharsHexadecimal |
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 4);
        if (ImGui::SmallButton("Cursor##dfg_start_cursor")) {
            snprintf(dataflow_graph_start_buf_, sizeof(dataflow_graph_start_buf_),
                     "%llu", (unsigned long long)current_inst_);
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Use the current cursor position");

        // End inst_id
        ImGui::Text("End inst_id (blank = start + 1000):");
        ImGui::PushItemWidth(panel_w * 0.45f);
        bool end_entered = ImGui::InputText("##dfg_end", dataflow_graph_end_buf_,
            sizeof(dataflow_graph_end_buf_),
            ImGuiInputTextFlags_CharsHexadecimal |
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();

        ImGui::Spacing();
        ImGui::TextDisabled("Graphs are capped at %d nodes for practical visualization.", 5000);
        ImGui::Spacing();

        // Run button
        if (ImGui::Button(ICON_FA_DIAGRAM_PROJECT " Build Graph") ||
            start_entered || end_entered) {
            run_dataflow_graph_with_params();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build the data-flow graph for the specified range");

        ImGui::End();
        return;
    }

    // ── Result available ──────────────────────────────────────────────
    const auto& nodes = dataflow_graph_result_->nodes;
    const auto& edges = dataflow_graph_result_->edges;

    ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.75f, 1.0f),
        ICON_FA_DIAGRAM_PROJECT "  %zu nodes, %zu edges", nodes.size(), edges.size());

    ImGui::SameLine(panel_w - 180.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        dataflow_graph_result_ = nullptr;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run with different parameters");
    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_FA_FILE_EXPORT " Export\xe2\x80\xa6")) {
        export_dataflow_graph_to_file();
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Export this graph to a DOT or JSON file");

    ImGui::Separator();

    // ── Two-pane layout: node list (left) + selected node detail (right) ──
    float left_w = panel_w * 0.55f;

    if (ImGui::BeginChild("DFGNodeList", ImVec2(left_w, 0), true)) {
        if (ImGui::BeginTable("DFGNodeTable", 3,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("inst_id",  ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("PC",       ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(nodes.size()));
            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const DataflowNode& n = nodes[static_cast<size_t>(row)];
                    bool selected = (dataflow_graph_cursor_ == static_cast<size_t>(row));

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    char id_label[32];
                    snprintf(id_label, sizeof(id_label), "#%llu##dfg%d",
                             (unsigned long long)n.inst_id, row);
                    if (ImGui::Selectable(id_label, selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        dataflow_graph_cursor_ = static_cast<size_t>(row);
                    }
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        navigate_to(n.inst_id);
                    }

                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextDisabled("0x%llx",
                        (unsigned long long)(n.pc - reader_.header().module_slide));

                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(n.mnemonic.c_str());
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }
    ImGui::EndChild();

    ImGui::SameLine();

    if (ImGui::BeginChild("DFGNodeDetail", ImVec2(0, 0), true)) {
        if (dataflow_graph_cursor_ < nodes.size()) {
            const DataflowNode& n = nodes[dataflow_graph_cursor_];
            ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.4f, 1.0f),
                "#%llu  0x%llx  %s",
                (unsigned long long)n.inst_id,
                (unsigned long long)(n.pc - reader_.header().module_slide),
                n.mnemonic.c_str());
            if (ImGui::SmallButton(ICON_FA_ARROW_RIGHT " Jump to Instruction")) {
                navigate_to_instructions(n.inst_id);
            }
            ImGui::Separator();

            auto producers = dataflow_graph_result_->producers_of(n.inst_id);
            ImGui::Text(ICON_FA_ARROW_LEFT "  Producers (%zu):", producers.size());
            if (producers.empty()) {
                ImGui::TextDisabled("  (none — value originates here or outside range)");
            }
            for (const auto& e : producers) {
                char lbl[64];
                snprintf(lbl, sizeof(lbl), "  #%llu##dfg_prod%llu",
                         (unsigned long long)e.from_inst_id,
                         (unsigned long long)e.from_inst_id);
                if (ImGui::Selectable(lbl)) {
                    navigate_to(e.from_inst_id);
                }
                ImGui::SameLine();
                if (e.via_mem_addr != 0) {
                    ImGui::TextDisabled("via mem 0x%llx", (unsigned long long)e.via_mem_addr);
                } else {
                    ImGui::TextDisabled("via x%u", (unsigned)e.via_reg);
                }
            }

            ImGui::Spacing();
            ImGui::Separator();

            auto consumers = dataflow_graph_result_->consumers_of(n.inst_id);
            ImGui::Text(ICON_FA_ARROW_RIGHT "  Consumers (%zu):", consumers.size());
            if (consumers.empty()) {
                ImGui::TextDisabled("  (none — value unused within range)");
            }
            for (const auto& e : consumers) {
                char lbl[64];
                snprintf(lbl, sizeof(lbl), "  #%llu##dfg_cons%llu",
                         (unsigned long long)e.to_inst_id,
                         (unsigned long long)e.to_inst_id);
                if (ImGui::Selectable(lbl)) {
                    navigate_to(e.to_inst_id);
                }
                ImGui::SameLine();
                if (e.via_mem_addr != 0) {
                    ImGui::TextDisabled("via mem 0x%llx", (unsigned long long)e.via_mem_addr);
                } else {
                    ImGui::TextDisabled("via x%u", (unsigned)e.via_reg);
                }
            }
        } else {
            ImGui::TextDisabled("Select a node to see its producers/consumers.");
        }
    }
    ImGui::EndChild();

    ImGui::End();
}

}  // namespace tenet

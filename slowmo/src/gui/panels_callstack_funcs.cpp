// panels_callstack_funcs.cpp — call stack panel, functions panel, and their
// context menus.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <algorithm>
#include <cstring>
#include <string>

namespace tenet {

// ─── Per-frame call-stack cache ──────────────────────────────────────────────

const std::vector<const CallEvent*>& GuiApp::current_call_stack() {
    if (callstack_frame_cache_.source  != function_result_ ||
        callstack_frame_cache_.inst_id != current_inst_) {
        if (function_result_) {
            callstack_frame_cache_.stack = function_result_->call_stack_at(current_inst_);
        } else {
            callstack_frame_cache_.stack.clear();
        }
        callstack_frame_cache_.source  = function_result_;
        callstack_frame_cache_.inst_id = current_inst_;

        // Rebuild label cache: one fmt::format call per entry, but only when
        // the stack actually changes (not every frame).
        const auto& stk = callstack_frame_cache_.stack;
        callstack_frame_cache_.labels.resize(stk.size());
        const uint64_t slide = reader_.header().module_slide;
        // Static indent buffer: max 64 levels * 2 spaces = 128 chars.
        // Use a fixed array to avoid std::string(n, ' ') heap allocation.
        static constexpr int kMaxIndentLevels = 64;
        static const auto s_indent = []() {
            std::array<std::string, kMaxIndentLevels> arr;
            for (int j = 0; j < kMaxIndentLevels; ++j)
                arr[j] = std::string(j * 2, ' ');
            return arr;
        }();
        for (size_t i = 0; i < stk.size(); ++i) {
            auto* evt = stk[i];
            uint64_t static_target = evt->target_pc - slide;
            std::string_view name;
            std::string name_buf;
            if (function_result_) {
                auto it = function_result_->functions.find(evt->target_pc);
                if (it != function_result_->functions.end()) {
                    name = it->second.name;
                } else {
                    name_buf = fmt::format("sub_{:x}", static_target);
                    name = name_buf;
                }
            }
            bool is_deepest = (i == stk.size() - 1);
            const std::string& indent = (i < kMaxIndentLevels)
                ? s_indent[i] : s_indent[kMaxIndentLevels - 1];
            callstack_frame_cache_.labels[i] = fmt::format("{}{} {}  @{}##frame{}",
                indent,
                is_deepest ? ">" : " ",
                name,
                evt->call_inst_id,
                i);
        }
    }
    return callstack_frame_cache_.stack;
}

// ─── Call Stack Panel ───────────────────────────────────────────────────────

void GuiApp::render_callstack_panel() {
    if (!ImGui::Begin("Call Stack", &show_callstack_)) {
        ImGui::End();
        return;
    }

    if (!function_result_) {
        ImGui::TextDisabled("(not computed - use Analysis > Function Analysis)");
        if (ImGui::Button("Run Function Analysis")) {
            run_pass_by_name("function");
        }
        ImGui::End();
        return;
    }

    // Navigation buttons
    if (ImGui::Button("Follow Call (e)")) {
        auto* evt = function_result_->call_at(current_inst_);
        if (evt && evt->call_inst_id + 1 < total_inst_) {
            navigate_to(evt->call_inst_id + 1);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Follow Return (F)")) {
        auto* evt = function_result_->return_at(current_inst_);
        if (evt) {
            navigate_to(evt->call_inst_id);
        } else {
            const auto& stack = current_call_stack();
            if (!stack.empty()) {
                navigate_to(stack.back()->call_inst_id);
            }
        }
    }

    ImGui::Separator();

    const auto& stack = current_call_stack();
    if (stack.empty()) {
        ImGui::TextDisabled("<top-level>");
    } else {
        // Show call stack as clickable items with right-click menu.
        // Labels are pre-built in current_call_stack() and cached in
        // callstack_frame_cache_.labels — no heap allocation per frame.
        const auto& labels = callstack_frame_cache_.labels;
        for (size_t i = 0; i < stack.size(); i++) {
            auto* evt = stack[i];
            bool is_deepest = (i == stack.size() - 1);
            uint64_t static_target = evt->target_pc - reader_.header().module_slide;

            // Clickable frame
            if (ImGui::Selectable(labels[i].c_str(), is_deepest,
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0)) {
                    // Double-click → jump to function ENTRY (first inst in callee)
                    navigate_to(evt->call_inst_id + 1);
                } else {
                    // Single click → jump to the CALL SITE instruction
                    navigate_to(evt->call_inst_id);
                }
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip(
                    "Single-click: jump to call site @%llu\n"
                    "Double-click: jump to function entry\n"
                    "Right-click: more options\n"
                    "Target: 0x%llx",
                    (unsigned long long)evt->call_inst_id,
                    (unsigned long long)static_target);
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                ctx_callstack_frame_ = i;
            }
            ImGui::OpenPopupOnItemClick("##cs_ctx", ImGuiPopupFlags_MouseButtonRight);
        }
    }

    // Render callstack context menu
    render_callstack_context_menu();

    ImGui::Separator();
    auto* func = function_result_->function_at(current_inst_);
    if (func) {
        ImGui::Text("In:");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%s", func->name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(calls=%llu, insts=%llu)",
            (unsigned long long)func->total_calls,
            (unsigned long long)func->total_instructions);
    }

    // Xref info
    if (xref_result_) {
        auto row = fetch_row(current_inst_);
        auto exec_count = xref_result_->execution_count(row.pc);
        if (exec_count > 0) {
            ImGui::Separator();
            ImGui::Text("PC xrefs:");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 1.0f, 1.0f),
                "%llu executions [%zu]",
                (unsigned long long)exec_count, xref_cursor_ + 1);
            ImGui::SameLine();
            if (ImGui::Button("Prev##xref")) {
                auto xrefs = xref_result_->inst_ids_at(row.pc);
                if (!xrefs.empty()) {
                    if (xref_cursor_ == 0) xref_cursor_ = xrefs.size() - 1;
                    else xref_cursor_--;
                    navigate_to(xrefs[xref_cursor_]);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Next##xref")) {
                auto xrefs = xref_result_->inst_ids_at(row.pc);
                if (!xrefs.empty()) {
                    xref_cursor_++;
                    if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
                    navigate_to(xrefs[xref_cursor_]);
                }
            }
        }
    }

    ImGui::End();
}

// ─── Call stack context menu ────────────────────────────────────────────────

void GuiApp::render_callstack_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_callstack_panel().

    if (!function_result_) {
        ImGui::BeginPopup("##cs_ctx");
        ImGui::EndPopup();
        return;
    }

    const auto& stack = current_call_stack();
    if (ImGui::BeginPopup("##cs_ctx")) {
        if (ctx_callstack_frame_ < stack.size()) {
            auto* evt = stack[ctx_callstack_frame_];
            ImGui::TextDisabled("Frame #%zu  @%llu",
                ctx_callstack_frame_, (unsigned long long)evt->call_inst_id);
            ImGui::Separator();
            if (ImGui::MenuItem("Jump to Call Site")) {
                navigate_to(evt->call_inst_id);
            }
            if (ImGui::MenuItem("Jump to Function Entry")) {
                navigate_to(evt->call_inst_id + 1);
            }
            if (ImGui::MenuItem("Run Xref on Target")) {
                if (!xref_result_) run_pass_by_name("xref");
                if (xref_result_) {
                    auto xrefs = xref_result_->inst_ids_at(evt->target_pc);
                    if (!xrefs.empty()) {
                        xref_cursor_ = 0;
                        navigate_to(xrefs[0]);
                    }
                }
            }
        }
        ImGui::EndPopup();
    }
}

// ─── Functions Panel ────────────────────────────────────────────────────────

void GuiApp::render_functions_panel() {
    if (!ImGui::Begin("Functions", &show_functions_)) {
        ImGui::End();
        return;
    }

    if (!function_result_) {
        ImGui::TextDisabled("No function analysis performed.");
        if (ImGui::Button("Run Function Analysis")) {
            run_pass_by_name("function");
        }
        ImGui::End();
        return;
    }

    // Header
    ImGui::Text("Discovered: %zu functions", function_result_->functions.size());

    // Filter
    ImGui::Separator();
    bool filter_changed = ImGui::InputText("Filter##func", function_filter_buf_, sizeof(function_filter_buf_));
    if (filter_changed) {
        function_filter_ = std::string(function_filter_buf_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear##funcfilter")) {
        function_filter_.clear();
        std::memset(function_filter_buf_, 0, sizeof(function_filter_buf_));
    }
    ImGui::SameLine();
    if (ImGui::Button("Run Call Graph")) {
        run_call_graph_analysis();
    }

    ImGui::Separator();

    // Build display list (filter + sort) — cached; rebuilt only when data/params change.
    // Use FuncListCache so we don't sort O(N log N) every frame.
    bool cache_stale = (func_list_cache_.source         != function_result_ ||
                        func_list_cache_.filter          != function_filter_ ||
                        func_list_cache_.sort_col        != function_sort_col_ ||
                        func_list_cache_.sort_ascending  != function_sort_ascending_);

    if (cache_stale) {
        func_list_cache_.entries.clear();
        func_list_cache_.entries.reserve(function_result_->functions.size());

        std::string lower_filter = function_filter_;
        std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::tolower);

        for (const auto& [pc, info] : function_result_->functions) {
            if (!function_filter_.empty()) {
                std::string lower_name = info.name;
                std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
                if (lower_name.find(lower_filter) == std::string::npos) continue;
            }
            func_list_cache_.entries.push_back({pc, &info});
        }

        // Sort once.
        // Column UserIDs: 0=Calls, 1=Name, 3=Insts  (Addr column was removed)
        switch (function_sort_col_) {
        case 0: // Calls
            std::sort(func_list_cache_.entries.begin(), func_list_cache_.entries.end(),
                [&](const auto& a, const auto& b) {
                    return function_sort_ascending_
                        ? a.info->total_calls < b.info->total_calls
                        : a.info->total_calls > b.info->total_calls;
                });
            break;
        case 1: // Name
            std::sort(func_list_cache_.entries.begin(), func_list_cache_.entries.end(),
                [&](const auto& a, const auto& b) {
                    return function_sort_ascending_
                        ? a.info->name < b.info->name
                        : a.info->name > b.info->name;
                });
            break;
        case 3: // Insts
            std::sort(func_list_cache_.entries.begin(), func_list_cache_.entries.end(),
                [&](const auto& a, const auto& b) {
                    return function_sort_ascending_
                        ? a.info->total_instructions < b.info->total_instructions
                        : a.info->total_instructions > b.info->total_instructions;
                });
            break;
        }

        func_list_cache_.source        = function_result_;
        func_list_cache_.filter        = function_filter_;
        func_list_cache_.sort_col      = function_sort_col_;
        func_list_cache_.sort_ascending = function_sort_ascending_;
    }

    // Use a local alias for cleaner code below
    const auto& entries = func_list_cache_.entries;

    ImGui::Text("Showing: %zu", entries.size());
    ImGui::Separator();

    // Table
    ImGuiTableFlags table_flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Sortable;

    if (ImGui::BeginTable("FunctionsTable", 3, table_flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthStretch, 0.0f, 1);
        ImGui::TableSetupColumn("Calls", ImGuiTableColumnFlags_WidthFixed, 50.0f, 0);
        ImGui::TableSetupColumn("Insts", ImGuiTableColumnFlags_WidthFixed, 60.0f, 3);
        ImGui::TableHeadersRow();

        // Handle sort specs: update parameters and invalidate cache for next frame rebuild.
        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
            if (sort_specs->SpecsDirty && sort_specs->SpecsCount > 0) {
                auto& spec = sort_specs->Specs[0];
                function_sort_ascending_ = (spec.SortDirection == ImGuiSortDirection_Ascending);
                function_sort_col_ = static_cast<int>(spec.ColumnUserID);
                sort_specs->SpecsDirty = false;
                // Invalidate cache — will be rebuilt before rendering (see cache_stale above).
                func_list_cache_.sort_col = -1;
            }
        }

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(entries.size()));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                const auto& entry = entries[i];
                const auto* info = entry.info;
                uint64_t static_pc = entry.pc - reader_.header().module_slide;

                ImGui::TableNextRow();

                // Name column (clickable)
                ImGui::TableSetColumnIndex(0);
                char label[256];
                snprintf(label, sizeof(label), "%s##func%d", info->name.c_str(), i);
                if (ImGui::Selectable(label, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    // Jump to first invocation
                    if (!info->call_event_indices.empty()) {
                        const auto& evt = function_result_->call_events[info->call_event_indices[0]];
                        navigate_to(evt.call_inst_id + 1);
                    }
                }
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format("{}\n0x{:016x}\ncalls: {}, insts: {}",
                        info->name, static_pc,
                        (unsigned long long)info->total_calls,
                        (unsigned long long)info->total_instructions);
                    if (call_graph_result_) {
                        auto* node = call_graph_result_->node_at(entry.pc);
                        if (node) {
                            tip += fmt::format("\ncallees: {}, callers: {}",
                                node->outgoing_edges.size(), node->incoming_edges.size());
                        }
                    }
                    tip += "\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());
                }
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ctx_func_pc_   = entry.pc;
                    ctx_func_name_ = info->name;
                    uint64_t s_pc  = entry.pc - reader_.header().module_slide;
                    ImGui::TextDisabled("%s", ctx_func_name_.c_str());
                    ImGui::TextDisabled("0x%llx", (unsigned long long)s_pc);
                    ImGui::Separator();
                    if (ImGui::MenuItem("Jump to First Call")) {
                        if (!info->call_event_indices.empty()) {
                            const auto& evt = function_result_->call_events[info->call_event_indices[0]];
                            navigate_to(evt.call_inst_id + 1);
                        }
                    }
                    if (ImGui::MenuItem("Copy Name")) {
                        ImGui::SetClipboardText(ctx_func_name_.c_str());
                    }
                    if (ImGui::MenuItem("Copy Address")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)s_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // Calls column
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%llu", (unsigned long long)info->total_calls);

                // Instructions column
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%llu", (unsigned long long)info->total_instructions);
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    // Call graph sub-view: show callers/callees for selected function
    // (shown below the table when call_graph is available)
    if (call_graph_result_ && ImGui::CollapsingHeader("Call Graph Info")) {
        auto* func = function_result_->function_at(current_inst_);
        if (func) {
            auto* node = call_graph_result_->node_at(func->entry_pc);
            if (node) {
                ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                    "Current: %s", func->name.c_str());

                if (!node->outgoing_edges.empty()) {
                    ImGui::Text("Callees (%zu):", node->outgoing_edges.size());
                    ImGui::Indent();
                    for (size_t ei = 0; ei < std::min(node->outgoing_edges.size(), size_t(8)); ei++) {
                        const auto& edge = call_graph_result_->edges[node->outgoing_edges[ei]];
                        std::string name;
                        if (call_graph_is_root_key(edge.callee_pc)) {
                            // A root pseudo-node can never actually be a callee
                            // (it only ever appears as a synthetic caller), but
                            // guard anyway for consistent display rather than
                            // subtracting module_slide from a tagged key.
                            name = fmt::format("<root@0x{:x}>",
                                call_graph_root_call_site(edge.callee_pc));
                        } else {
                            auto it = function_result_->functions.find(edge.callee_pc);
                            name = it != function_result_->functions.end()
                                ? it->second.name
                                : fmt::format("sub_{:x}", edge.callee_pc - reader_.header().module_slide);
                        }
                        ImGui::BulletText("%s (x%llu)", name.c_str(), (unsigned long long)edge.call_count);
                    }
                    if (node->outgoing_edges.size() > 8) {
                        ImGui::TextDisabled("  ...+%zu more", node->outgoing_edges.size() - 8);
                    }
                    ImGui::Unindent();
                }
                if (!node->incoming_edges.empty()) {
                    ImGui::Text("Callers (%zu):", node->incoming_edges.size());
                    ImGui::Indent();
                    for (size_t ei = 0; ei < std::min(node->incoming_edges.size(), size_t(8)); ei++) {
                        const auto& edge = call_graph_result_->edges[node->incoming_edges[ei]];
                        std::string name;
                        if (call_graph_is_root_key(edge.caller_pc)) {
                            // Caller is a synthetic root pseudo-node: its
                            // entry_pc is a tagged call-site PC, not a real
                            // function entry — subtracting module_slide from
                            // it would print a meaningless huge address.
                            name = fmt::format("<root@0x{:x}>",
                                call_graph_root_call_site(edge.caller_pc));
                        } else {
                            auto it = function_result_->functions.find(edge.caller_pc);
                            name = it != function_result_->functions.end()
                                ? it->second.name
                                : fmt::format("sub_{:x}", edge.caller_pc - reader_.header().module_slide);
                        }
                        ImGui::BulletText("%s (x%llu)", name.c_str(), (unsigned long long)edge.call_count);
                    }
                    if (node->incoming_edges.size() > 8) {
                        ImGui::TextDisabled("  ...+%zu more", node->incoming_edges.size() - 8);
                    }
                    ImGui::Unindent();
                }
            }
        } else {
            ImGui::TextDisabled("(navigate to a function to see call graph info)");
        }
    }

    // Function panel right-click menu
    render_func_context_menu();

    ImGui::End();
}

// ─── Function Panel Context Menu ─────────────────────────────────────────────

void GuiApp::render_func_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_function_panel().
    if (ImGui::BeginPopup("##func_ctx")) {
        ImGui::TextDisabled("%s", ctx_func_name_.c_str());
        uint64_t static_pc = ctx_func_pc_ - reader_.header().module_slide;
        ImGui::TextDisabled("0x%016llx", (unsigned long long)static_pc);
        ImGui::Separator();

        if (function_result_) {
            auto it = function_result_->functions.find(ctx_func_pc_);
            if (it != function_result_->functions.end()) {
                const auto& info = it->second;
                if (!info.call_event_indices.empty()) {
                    if (ImGui::MenuItem("Jump to First Invocation")) {
                        const auto& evt = function_result_->call_events[info.call_event_indices[0]];
                        navigate_to(evt.call_inst_id + 1);
                    }
                    if (info.call_event_indices.size() > 1) {
                        // Show jump to each invocation (up to 10)
                        if (ImGui::BeginMenu("Jump to Invocation...")) {
                            size_t limit = std::min(info.call_event_indices.size(), size_t(10));
                            for (size_t ci = 0; ci < limit; ci++) {
                                const auto& evt = function_result_->call_events[info.call_event_indices[ci]];
                                char lbl[48];
                                snprintf(lbl, sizeof(lbl), "  Call #%zu (@inst %llu)",
                                    ci + 1, (unsigned long long)evt.call_inst_id);
                                if (ImGui::MenuItem(lbl)) {
                                    navigate_to(evt.call_inst_id + 1);
                                }
                            }
                            if (info.call_event_indices.size() > 10) {
                                ImGui::TextDisabled("  ... and %zu more", info.call_event_indices.size() - 10);
                            }
                            ImGui::EndMenu();
                        }
                    }
                }
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Copy Name")) {
            ImGui::SetClipboardText(ctx_func_name_.c_str());
        }
        if (ImGui::MenuItem("Copy Address")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)static_pc);
            ImGui::SetClipboardText(buf);
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Run Xref on this Function")) {
            if (!xref_result_) run_pass_by_name("xref");
            if (xref_result_) {
                auto xrefs = xref_result_->inst_ids_at(ctx_func_pc_);
                if (!xrefs.empty()) {
                    xref_cursor_ = 0;
                    navigate_to(xrefs[0]);
                }
            }
        }

        if (call_graph_result_) {
            auto* node = call_graph_result_->node_at(ctx_func_pc_);
            if (node) {
                ImGui::Separator();
                ImGui::TextDisabled("Callers: %zu, Callees: %zu",
                    node->incoming_edges.size(), node->outgoing_edges.size());
            }
        }

        ImGui::EndPopup();
    }
}

}  // namespace tenet

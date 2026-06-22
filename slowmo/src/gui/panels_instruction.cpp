// panels_instruction.cpp — instruction list panel + per-instruction context menu.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/slice_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/cfg_layout_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <algorithm>
#include <string>

namespace tenet {

// ─── Instruction Panel ──────────────────────────────────────────────────────
// Redesigned: richer row markers, cleaner column headers, IDA-style current
// line indicator, search-result navigation strip, and bookmark count badge.

void GuiApp::render_instruction_panel() {
    ImGui::Begin("Instructions");

    // ── Header strip: search result nav + bookmark count ──────────────
    if (search_active_ && !search_results_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.08f, 0.15f, 0.12f, 1.0f));
        ImGui::BeginChild("##search_strip", ImVec2(0, ImGui::GetFrameHeightWithSpacing()), false,
                          ImGuiWindowFlags_NoScrollbar);
        ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f),
            "\xE2\x8C\x95  %zu results", search_results_.size());  // ⌕
        ImGui::SameLine(0, 10.0f);
        if (ImGui::SmallButton("\xe2\x97\x81##sprev")) {  // ◁
            if (search_current_ > 0) search_current_--;
            else search_current_ = search_results_.size() - 1;
            navigate_to(search_results_[search_current_]);
        }
        ImGui::SameLine(0, 2.0f);
        ImGui::TextDisabled("%zu / %zu", search_current_ + 1, search_results_.size());
        ImGui::SameLine(0, 2.0f);
        if (ImGui::SmallButton("\xe2\x96\xb7##snext")) {  // ▷
            search_current_++;
            if (search_current_ >= search_results_.size()) search_current_ = 0;
            navigate_to(search_results_[search_current_]);
        }
        ImGui::SameLine(0, 12.0f);
        if (ImGui::SmallButton("  \xc3\x97  ")) {  // ×
            search_active_ = false;
            search_results_.clear();
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear search");
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    if (!bookmarks_.empty()) {
        // Small right-aligned bookmark count
        char bm_label[32];
        snprintf(bm_label, sizeof(bm_label), "\xe2\x98\x86 %zu bookmarks", bookmarks_.size());  // ☆
        float text_w = ImGui::CalcTextSize(bm_label).x;
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - text_w + ImGui::GetCursorPosX());
        ImGui::TextColored(ImVec4(1.0f, 0.80f, 0.20f, 0.70f), "%s", bm_label);
    }

    // ── Instruction table ────────────────────────────────────────────────
    // Flags: scroll, alternating row bg, inner vertical borders, fixed columns
    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_NoHostExtendX;

    // Reserve the full remaining height
    float table_height = ImGui::GetContentRegionAvail().y;

    if (ImGui::BeginTable("InstTable", 5, table_flags, ImVec2(0, table_height))) {
        ImGui::TableSetupScrollFreeze(0, 1);  // Freeze header row
        // Col 0: narrow gutter (marker/bookmark/arrow)
        ImGui::TableSetupColumn(" ",        ImGuiTableColumnFlags_WidthFixed |
                                            ImGuiTableColumnFlags_NoResize, 22.0f);
        // Col 1: instruction index — fixed but wide enough for 7-digit numbers
        ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 64.0f);
        // Col 2: address — fixed monospace
        ImGui::TableSetupColumn("Address",  ImGuiTableColumnFlags_WidthFixed, 132.0f);
        // Col 3: mnemonic — fixed, auto-fitted to longest common mnemonic
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        // Col 4: operands — stretches to fill remaining space
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);

        // Custom styled header row (slightly taller, blue-tinted)
        ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, ImVec4(0.10f, 0.12f, 0.20f, 1.0f));
        ImGui::TableHeadersRow();
        ImGui::PopStyleColor();

        // ── Virtual list clipper for performance ─────────────────────────
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(total_inst_));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                uint64_t inst_id = static_cast<uint64_t>(i);
                auto row = fetch_row(inst_id);

                bool is_current   = (inst_id == current_inst_);
                bool is_bookmarked= row.has_bookmark;
                bool is_tainted   = show_taint_ && taint_result_ &&
                                    taint_result_->has_event_at(inst_id);
                bool is_sliced    = show_slice_ && slice_result_ &&
                                    slice_result_->is_in_slice(inst_id);
                bool is_back_taint= show_backward_taint_ && backward_taint_result_ &&
                                    backward_taint_result_->is_contributing(inst_id);
                bool is_search_hit= search_active_ &&
                                    std::binary_search(search_results_.begin(),
                                                       search_results_.end(), inst_id);

                // P2-12: producer chain highlight
                bool is_producer_chain = show_producer_chain_ && !producer_chain_ids_.empty() &&
                                         std::binary_search(producer_chain_ids_.begin(),
                                                            producer_chain_ids_.end(), inst_id);

                // Loop state
                bool is_loop_header = show_loops_ && loop_result_ &&
                                      loop_result_->is_loop_header(row.pc);
                uint32_t loop_depth = (show_loops_ && loop_result_) ?
                                      loop_result_->loop_depth_at(row.pc) : 0;
                bool is_in_loop     = loop_depth > 0;

                ImGui::TableNextRow();

                // ── Row background priority (high → low) ─────────────────
                // 1) current instruction: bright blue-white
                // 2) analysis overlays: taint/slice/backward-taint
                // 3) loop markers
                // 4) search hits: subtle gold
                if (is_current) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(30, 70, 145, 175));
                } else if (is_producer_chain) {
                    // P2-12: producer chain — warm amber highlight
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(120, 90, 10, 140));
                } else if (is_back_taint) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(110, 22, 22, 115));
                } else if (is_sliced) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(80, 22, 110, 115));
                } else if (is_tainted) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(20, 80, 28, 115));
                } else if (is_search_hit) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(90, 75, 10, 120));
                } else if (is_loop_header) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(140, 62, 4, 200));
                } else if (is_in_loop) {
                    float d = std::min(static_cast<float>(loop_depth - 1) * 0.06f, 0.18f);
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.26f + d, 0.13f, 0.02f, 0.38f)));
                }

                // ── Column 0: Gutter marker + invisible full-row hit-area ──
                // Pattern: render gutter text first, then SameLine + Selectable
                // with SpanAllColumns so it covers the entire row for click/hover
                // detection without shifting any column layout.
                ImGui::TableNextColumn();
                if (is_current && is_bookmarked) {
                    ImGui::TextColored(ImVec4(1.0f, 0.82f, 0.15f, 1.0f), "\xe2\x98\x85\xe2\x96\xb6");  // ★▶
                } else if (is_current) {
                    ImGui::TextColored(ImVec4(0.45f, 0.82f, 1.0f, 1.0f), " \xe2\x96\xb6");  // ▶
                } else if (is_bookmarked) {
                    ImGui::TextColored(ImVec4(1.0f, 0.82f, 0.15f, 1.0f), "\xe2\x98\x85 ");  // ★
                } else if (is_loop_header) {
                    ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.1f, 1.0f), "\xe2\x87\x86 ");   // ⇆
                } else if (is_in_loop) {
                    ImGui::TextColored(ImVec4(0.72f, 0.43f, 0.1f, 0.75f), "\xe2\x86\xba ");  // ↺
                } else {
                    ImGui::TextDisabled("  ");
                }
                // Overlay: transparent full-row Selectable for click & hover
                ImGui::SameLine(0, 0);
                ImGui::SetCursorPosX(ImGui::GetCursorPosX()
                                     - ImGui::GetItemRectSize().x
                                     - ImGui::GetStyle().ItemSpacing.x);
                {
                    char sel_id[32];
                    snprintf(sel_id, sizeof(sel_id), "##irow%llu", (unsigned long long)inst_id);
                    // Push transparent colors so Selectable is invisible
                    ImGui::PushStyleColor(ImGuiCol_Header,        ImVec4(0,0,0,0));
                    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(1,1,1,0.06f));
                    ImGui::PushStyleColor(ImGuiCol_HeaderActive,  ImVec4(1,1,1,0.10f));
                    ImGui::Selectable(sel_id, false,
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowOverlap,
                        ImVec2(0, ImGui::GetTextLineHeight()));
                    ImGui::PopStyleColor(3);

                    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
                        // Select without triggering auto-scroll — the user
                        // already sees the row they clicked, so keep the
                        // viewport where it is.
                        if (inst_id >= total_inst_)
                            inst_id = total_inst_ > 0 ? total_inst_ - 1 : 0;
                        nav_push(inst_id);
                        current_inst_ = inst_id;
                        taint_sorted_ids_dirty_ = true;
                    }
                    if (ImGui::IsItemHovered()) {
                        std::string tip;
                        tip += fmt::format("inst #{}\n", inst_id);
                        tip += fmt::format("addr: 0x{:016x}\n", row.static_pc);
                        tip += fmt::format("{} {}", row.mnemonic, row.operands);
                        if (row.mem_access_count > 0) {
                            tip += fmt::format("\n{} memory access(es)", row.mem_access_count);
                        }
                        tip += "\nRight-click for more options";
                        ImGui::SetTooltip("%s", tip.c_str());
                    }

                    // Right-click context menu: BeginPopupContextItem is the
                    // most reliable ImGui API - it both opens and renders the popup.
                    if (ImGui::BeginPopupContextItem(nullptr)) {
                        // Capture context on first open
                        ctx_inst_id_        = inst_id;
                        ctx_inst_pc_        = row.pc;
                        ctx_inst_static_pc_ = row.static_pc;
                        ctx_inst_disasm_    = fmt::format("{} {}", row.mnemonic, row.operands);
                        // Delegate rendering to the shared function
                        render_inst_context_menu_contents();
                        ImGui::EndPopup();
                    }
                }

                // ── Column 1: Instruction index ───────────────────────────
                ImGui::TableNextColumn();
                if (is_current) {
                    ImGui::TextColored(ImVec4(0.7f, 0.82f, 1.0f, 1.0f),
                        "%llu", (unsigned long long)inst_id);
                } else {
                    ImGui::TextDisabled("%llu", (unsigned long long)inst_id);
                }

                // ── Column 2: Address ─────────────────────────────────────
                ImGui::TableNextColumn();
                if (is_current) {
                    ImGui::TextColored(ImVec4(0.65f, 0.72f, 0.95f, 1.0f),
                        "%016llx", (unsigned long long)row.static_pc);
                } else {
                    ImGui::TextColored(ImVec4(0.50f, 0.52f, 0.65f, 1.0f),
                        "%016llx", (unsigned long long)row.static_pc);
                }

                // ── Column 3: Mnemonic (syntax-colored) ───────────────────
                ImGui::TableNextColumn();
                ImVec4 mnem_color = inst_color(row.mnemonic);
                ImGui::TextColored(mnem_color, "%s", row.mnemonic.c_str());

                // ── Column 4: Operands (tokenized highlighting) ───────────
                ImGui::TableNextColumn();
                render_operands_highlighted(row.operands);

            }
        }
        clipper.End();

        // ── Auto-scroll: bring current instruction into view ─────────
        // Only triggered by explicit navigation (navigate_to), not by mouse
        // clicks on a visible row (which leave the viewport unchanged).
        if (scroll_to_current_ && current_inst_ < total_inst_) {
            scroll_to_current_ = false;
            float item_h    = ImGui::GetTextLineHeightWithSpacing();
            float panel_h   = ImGui::GetWindowHeight();
            float target_y  = static_cast<float>(current_inst_) * item_h - panel_h * 0.45f;
            if (target_y < 0.0f) target_y = 0.0f;
            ImGui::SetScrollY(target_y);
        }

        ImGui::EndTable();
    }

    // Render instruction context menu (must be called before End())
    render_inst_context_menu();

    ImGui::End();
}

// ─── Instruction Panel Context Menu ─────────────────────────────────────────
// IDA-style per-instruction right-click menu with full analysis actions

void GuiApp::render_inst_context_menu_contents() {
    // ── Header: address + disasm ───────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.62f, 0.80f, 1.0f));
    ImGui::Text("inst #%llu", (unsigned long long)ctx_inst_id_);
    ImGui::Text("0x%016llx", (unsigned long long)ctx_inst_static_pc_);
    ImGui::PopStyleColor();
    ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.90f, 1.0f), "%s", ctx_inst_disasm_.c_str());
    ImGui::Separator();

    // ── Copy actions ──────────────────────────────────────────────────
    if (ImGui::BeginMenu("Copy")) {
        if (ImGui::MenuItem("Copy Address (hex)")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_inst_static_pc_);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Copy Address (decimal)")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)ctx_inst_static_pc_);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Copy Disassembly")) {
            ImGui::SetClipboardText(ctx_inst_disasm_.c_str());
        }
        if (ImGui::MenuItem("Copy Instruction ID")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)ctx_inst_id_);
            ImGui::SetClipboardText(buf);
        }
        ImGui::EndMenu();
    }

    ImGui::Separator();

    // ── Navigation ────────────────────────────────────────────────────
    if (ImGui::MenuItem("Navigate Here")) {
        navigate_to(ctx_inst_id_);
    }
    if (ImGui::MenuItem("Goto Instruction... (G)")) {
        show_goto_popup_ = true;
    }

    // Bookmark toggle
    bool is_bookmarked = std::binary_search(bookmarks_.begin(), bookmarks_.end(), ctx_inst_id_);
    if (is_bookmarked) {
        if (ImGui::MenuItem("\xe2\x98\x85 Remove Bookmark")) {  // ★
            auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), ctx_inst_id_);
            if (it != bookmarks_.end() && *it == ctx_inst_id_) {
                bookmarks_.erase(it);
                row_cache_.invalidate(ctx_inst_id_);
            }
        }
    } else {
        if (ImGui::MenuItem("\xe2\x98\x86 Add Bookmark (B)")) {  // ☆
            auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), ctx_inst_id_);
            bookmarks_.insert(it, ctx_inst_id_);
            row_cache_.invalidate(ctx_inst_id_);
        }
    }

    ImGui::Separator();

    // ── Taint analysis from this instruction ──────────────────────────
    if (ImGui::BeginMenu("Taint Analysis")) {
        const auto& state = regfile_.state_before(ctx_inst_id_);
        if (ImGui::MenuItem("Forward Taint from x0")) {
            navigate_to(ctx_inst_id_);
            run_taint_analysis();
        }
        ImGui::Separator();
        static const struct { uint8_t idx; const char* name; } kArgRegs[] = {
            {0,"x0"},{1,"x1"},{2,"x2"},{3,"x3"},{4,"x4"},{5,"x5"}
        };
        for (auto& reg : kArgRegs) {
            char label[32];
            snprintf(label, sizeof(label), "Forward Taint from %s = 0x%llx",
                     reg.name, (unsigned long long)state.gpr[reg.idx]);
            if (ImGui::MenuItem(label)) {
                navigate_to(ctx_inst_id_);
                run_taint_analysis();
            }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Backward Taint from here")) {
            navigate_to(ctx_inst_id_);
            run_backward_taint_analysis();
        }
        ImGui::EndMenu();
    }

    // ── Xref navigation ───────────────────────────────────────────────
    if (ImGui::BeginMenu("Xrefs")) {
        if (!xref_result_) {
            if (ImGui::MenuItem("Run Xref Analysis first")) {
                run_pass_by_name("xref");
            }
        } else {
            auto xrefs = xref_result_->inst_ids_at(ctx_inst_pc_);
            uint64_t exec_count = xref_result_->execution_count(ctx_inst_pc_);
            ImGui::TextDisabled("0x%llx: %llu executions",
                (unsigned long long)ctx_inst_static_pc_,
                (unsigned long long)exec_count);
            ImGui::Separator();
            if (!xrefs.empty()) {
                size_t limit = std::min(xrefs.size(), size_t(20));
                for (size_t xi = 0; xi < limit; xi++) {
                    char lbl[48];
                    snprintf(lbl, sizeof(lbl), "  Jump to inst #%llu", (unsigned long long)xrefs[xi]);
                    if (ImGui::MenuItem(lbl)) {
                        xref_cursor_ = xi;
                        navigate_to(xrefs[xi]);
                    }
                }
                if (xrefs.size() > 20) {
                    ImGui::TextDisabled("  ... and %zu more", xrefs.size() - 20);
                }
            } else {
                ImGui::TextDisabled("  (no other executions)");
            }
        }
        ImGui::EndMenu();
    }

    // ── Function context ──────────────────────────────────────────────
    if (function_result_) {
        ImGui::Separator();
        auto* func = function_result_->function_at(ctx_inst_id_);
        if (func) {
            ImGui::TextDisabled("In: %s", func->name.c_str());
            if (ImGui::MenuItem("Jump to Function Entry")) {
                auto it = function_result_->functions.find(func->entry_pc);
                if (it != function_result_->functions.end() &&
                    !it->second.call_event_indices.empty()) {
                    const auto& evt = function_result_->call_events[
                        it->second.call_event_indices[0]];
                    navigate_to(evt.call_inst_id + 1);
                }
            }
            auto* call = function_result_->call_at(ctx_inst_id_);
            if (call) {
                if (ImGui::MenuItem("Follow Call (Enter)")) {
                    navigate_to(call->call_inst_id + 1);
                }
            }
            auto* ret = function_result_->return_at(ctx_inst_id_);
            if (ret) {
                if (ImGui::MenuItem("Follow Return")) {
                    navigate_to(ret->call_inst_id);
                }
            }
        }
    }

    // ── P2-12: Data-flow analysis ─────────────────────────────────────
    ImGui::Separator();
    if (ImGui::BeginMenu("Data Flow (P2-12)")) {
        if (ImGui::MenuItem("Trace Producer Chain for x0")) {
            show_reg_timeline_ = true;
            run_producer_chain(ctx_inst_id_, 0);
        }
        if (ImGui::MenuItem("Trace Producer Chain for x1")) {
            show_reg_timeline_ = true;
            run_producer_chain(ctx_inst_id_, 1);
        }
        static const struct { uint8_t idx; const char* name; } kAllRegs[] = {
            {0,"x0"},{1,"x1"},{2,"x2"},{3,"x3"},{4,"x4"},{5,"x5"},
            {6,"x6"},{7,"x7"},{29,"fp"},{30,"lr"},{31,"sp"},{33,"pc"}
        };
        ImGui::Separator();
        for (const auto& reg : kAllRegs) {
            char lbl[48];
            snprintf(lbl, sizeof(lbl), "Producer chain for %s", reg.name);
            if (ImGui::MenuItem(lbl)) {
                show_reg_timeline_ = true;
                run_producer_chain(ctx_inst_id_, reg.idx);
            }
        }
        ImGui::Separator();
        if (show_producer_chain_) {
            if (ImGui::MenuItem("Clear Producer Chain Highlight")) {
                show_producer_chain_ = false;
                producer_chain_ids_.clear();
            }
        }
        ImGui::EndMenu();
    }

    // ── P2-13: Symbol info ────────────────────────────────────────────
    if (!dwarf_symbols_.empty()) {
        const DwarfSymbol* sym = dwarf_symbol_at(ctx_inst_pc_);
        if (sym) {
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.6f, 1.0f),
                               "%s +0x%llx",
                               sym->name.c_str(),
                               (unsigned long long)(ctx_inst_pc_ - sym->start));
            if (!sym->file.empty()) {
                ImGui::TextDisabled("  %s:%u", sym->file.c_str(), sym->line);
            }
        }
    }

    // ── Hex dump ──────────────────────────────────────────────────────
    ImGui::Separator();
    if (ImGui::MenuItem("Open PC in Hex Dump")) {
        open_hex_dump_at(ctx_inst_pc_);
    }

    // ── CFG ───────────────────────────────────────────────────────────
    if (show_cfg_ && cfg_result_) {
        if (ImGui::MenuItem("Show Block in CFG")) {
            // Select the block in CFG and center on it
            const CFGResult* acfg = cfg_func_result_ ? cfg_func_result_.get() : cfg_result_;
            auto* blk = acfg->block_containing(ctx_inst_pc_);
            if (blk && cfg_layout_result_) {
                cfg_selected_block_ = blk->start_pc;
                cfg_block_cursor_ = 0;
                auto it = cfg_layout_result_->block_layouts.find(blk->start_pc);
                if (it != cfg_layout_result_->block_layouts.end()) {
                    const auto& lo = it->second;
                    // Approximate centering (actual window size may differ)
                    cfg_scroll_.x = 300.0f - (lo.x + lo.width  * 0.5f) * cfg_zoom_;
                    cfg_scroll_.y = 200.0f - (lo.y + lo.height * 0.5f) * cfg_zoom_;
                }
            }
        }
    }
}

void GuiApp::render_inst_context_menu() {
    // No-op: instruction panel now uses BeginPopupContextItem inline.
}

}  // namespace tenet

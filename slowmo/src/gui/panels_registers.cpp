// panels_registers.cpp — register panel + register context menu.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/function_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace tenet {

namespace {

// Helper: AArch64 register index → name (x0-x28, fp, lr, sp, nzcv, pc).
static std::string reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == 29) return "fp";
    if (idx == 30) return "lr";
    if (idx == 31) return "sp";
    if (idx == 32) return "nzcv";
    if (idx == 33) return "pc";
    return "??";
}

}  // namespace

// ─── Register Panel ─────────────────────────────────────────────────────────

void GuiApp::render_register_panel() {
    if (!ImGui::Begin("Registers", &show_registers_)) {
        ImGui::End();
        return;
    }

    const auto& state = regfile_.state_before(current_inst_);

    // Get previous state for delta highlighting
    const bool has_prev = (current_inst_ > 0);
    RegState prev_state{};
    if (has_prev) {
        prev_state = regfile_.state_before(current_inst_ - 1);
    }

    // Determine read/written registers for current instruction
    std::vector<uint8_t> read_regs, write_regs;
    {
        auto [offset, seed_pc_rw] = index_.offset_of_with_pc(current_inst_, reader_);
        auto rec = reader_.record_at(offset, seed_pc_rw);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                write_regs.push_back(inst.reg_diff(i).index);
            }
            auto opcode = code_table_.opcode_at(inst.pc);
            if (opcode) {
                auto d = decoder_.decode(inst.pc, *opcode);
                if (d) {
                    read_regs.assign(d->regs_read.begin(),
                                     d->regs_read.begin() + d->regs_read_count);
                }
            }
        }
    }

    auto is_in = [](const std::vector<uint8_t>& vec, uint8_t idx) {
        for (auto v : vec) if (v == idx) return true;
        return false;
    };

    enum class RegHighlight { Normal, Read, Write, ReadWrite };
    auto get_reg_state = [&](uint8_t idx) -> RegHighlight {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return RegHighlight::ReadWrite;
        if (w)      return RegHighlight::Write;
        if (r)      return RegHighlight::Read;
        return RegHighlight::Normal;
    };

    auto state_to_color = [](RegHighlight s) -> ImVec4 {
        switch (s) {
            case RegHighlight::Read:      return reg_color_read();
            case RegHighlight::Write:     return reg_color_write();
            case RegHighlight::ReadWrite: return reg_color_both();
            default:                      return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
        }
    };

    // ── Compact header: legend + instruction count ──────────────────
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 2));

    // Colored legend dots
    ImDrawList* draw = ImGui::GetWindowDrawList();
    auto draw_dot = [&](ImVec4 col) {
        ImVec2 p = ImGui::GetCursorScreenPos();
        p.x += 5.0f; p.y += ImGui::GetTextLineHeight() * 0.5f - 3.0f;
        draw->AddCircleFilled(p, 4.0f, ImGui::ColorConvertFloat4ToU32(col));
        ImGui::Dummy(ImVec2(12, ImGui::GetTextLineHeight()));
    };

    draw_dot(reg_color_read());
    ImGui::SameLine(0, 2);
    ImGui::TextDisabled("R");
    ImGui::SameLine(0, 8);
    draw_dot(reg_color_write());
    ImGui::SameLine(0, 2);
    ImGui::TextDisabled("W");
    ImGui::SameLine(0, 8);
    draw_dot(reg_color_both());
    ImGui::SameLine(0, 2);
    ImGui::TextDisabled("RW");
    ImGui::SameLine();
    ImGui::TextDisabled("  |  inst #%llu", (unsigned long long)current_inst_);

    ImGui::PopStyleVar();

    // Thin separator with slightly different shade
    ImVec2 sep_p0 = ImGui::GetCursorScreenPos();
    sep_p0.y += 2.0f;
    draw->AddLine(sep_p0, ImVec2(sep_p0.x + ImGui::GetContentRegionAvail().x, sep_p0.y),
                  IM_COL32(70, 78, 110, 200), 1.0f);
    ImGui::Dummy(ImVec2(0, 4));

    // ── Render a register cell (name col + value col) ──────────────
    // Returns true if right-clicked
    auto render_reg_cell = [&](uint8_t idx, const char* name, uint64_t value,
                                uint64_t prev_value, bool changed_vs_prev) -> bool {
        RegHighlight rs  = get_reg_state(idx);
        ImVec4 color = state_to_color(rs);

        // Background tint for written registers
        ImVec2 cell_pos = ImGui::GetCursorScreenPos();
        float cell_w = ImGui::GetContentRegionAvail().x;
        float cell_h = ImGui::GetTextLineHeightWithSpacing();

        if (rs == RegHighlight::Write || rs == RegHighlight::ReadWrite) {
            // Strong highlight for written registers
            ImU32 bg = (rs == RegHighlight::ReadWrite)
                ? IM_COL32(80, 60, 20, 80)
                : IM_COL32(20, 70, 50, 80);
            draw->AddRectFilled(cell_pos, ImVec2(cell_pos.x + cell_w, cell_pos.y + cell_h - 1), bg);
        } else if (changed_vs_prev) {
            // Subtle change indicator (compared to previous instruction)
            draw->AddRectFilled(cell_pos, ImVec2(cell_pos.x + cell_w, cell_pos.y + cell_h - 1),
                                IM_COL32(40, 40, 70, 60));
        }

        // State indicator bar on the left edge
        if (rs != RegHighlight::Normal) {
            ImU32 bar_col = ImGui::ColorConvertFloat4ToU32(color);
            bar_col = (bar_col & 0x00FFFFFF) | 0xCC000000; // 80% alpha
            draw->AddRectFilled(cell_pos, ImVec2(cell_pos.x + 2.5f, cell_pos.y + cell_h - 1), bar_col);
        }

        // Name (fixed-width, dimmed)
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.62f, 0.80f, 1.0f));
        ImGui::SetNextItemWidth(32.0f);
        ImGui::Text("%-4s", name);
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 4);

        // Value (colored by state)
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        char val_str[24];
        snprintf(val_str, sizeof(val_str), "%016llx", (unsigned long long)value);

        char sel_id[32];
        snprintf(sel_id, sizeof(sel_id), "##reg%u", idx);
        ImGui::Selectable((std::string(val_str) + sel_id).c_str(),
                          false, ImGuiSelectableFlags_AllowOverlap, ImVec2(0, 0));
        ImGui::PopStyleColor();

        // Tooltip
        if (ImGui::IsItemHovered()) {
            if (changed_vs_prev || rs != RegHighlight::Normal) {
                char tip[128];
                if (changed_vs_prev && has_prev) {
                    int64_t delta = (int64_t)(value - prev_value);
                    snprintf(tip, sizeof(tip),
                             "%s = 0x%016llx\n\u0394 = %+lld (0x%llx)\nRight-click for options",
                             name, (unsigned long long)value,
                             (long long)delta, (unsigned long long)(value - prev_value));
                } else {
                    snprintf(tip, sizeof(tip),
                             "%s = 0x%016llx\nRight-click for options", name, (unsigned long long)value);
                }
                ImGui::SetTooltip("%s", tip);
            }
        }
        // BeginPopupContextItem is the most reliable right-click menu API.
        // It checks IsItemHovered internally on mouse release.
        bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
        if (ImGui::BeginPopupContextItem(nullptr)) {
            ctx_reg_idx_   = idx;
            ctx_reg_value_ = value;
            // ── Register context menu contents ────────────────────────
            std::string rname;
            if (idx <= 28) rname = fmt::format("x{}", idx);
            else if (idx == 29) rname = "fp";
            else if (idx == 30) rname = "lr";
            else if (idx == 31) rname = "sp";
            else rname = fmt::format("reg{}", idx);
            ImGui::TextDisabled("%s = 0x%016llx", rname.c_str(), (unsigned long long)value);
            ImGui::Separator();
            if (ImGui::MenuItem("Open Value in Hex Dump")) {
                open_hex_dump_at(value);
            }
            if (ImGui::MenuItem("Copy Value")) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)value);
                ImGui::SetClipboardText(buf);
            }
            ImGui::Separator();
            // ── P2-12: data-flow tools ─────────────────────────────────
            {
                char tl_label[64];
                snprintf(tl_label, sizeof(tl_label), "Track %s in Timeline", rname.c_str());
                if (ImGui::MenuItem(tl_label)) {
                    show_reg_timeline_   = true;
                    reg_timeline_reg_    = idx;
                    reg_timeline_dirty_  = true;
                }
                char pc_label[64];
                snprintf(pc_label, sizeof(pc_label), "Trace Producer Chain for %s", rname.c_str());
                if (ImGui::MenuItem(pc_label)) {
                    show_reg_timeline_ = true;
                    run_producer_chain(current_inst_, idx);
                }
            }
            if (idx == 30 && function_result_) {
                ImGui::Separator();
                if (ImGui::MenuItem("Follow LR (jump to call site)")) {
                    auto stack = function_result_->call_stack_at(current_inst_);
                    if (!stack.empty()) navigate_to(stack.back()->call_inst_id);
                }
            }
            if ((idx == 29 || idx == 31) && function_result_) {
                ImGui::Separator();
                ImGui::TextDisabled("(stack pointer/frame pointer)");
            }
            ImGui::EndPopup();
        }
        return right_clicked;
    };

    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(4, 1));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,  ImVec2(4, 1));

    // ── GPR table: 2 columns, x0-x28 ──────────────────────────────
    const float col_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
    ImGuiTableFlags tbl_flags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoPadOuterX;
    if (ImGui::BeginTable("GPR", 2, tbl_flags)) {
        ImGui::TableSetupColumn("Col0", ImGuiTableColumnFlags_WidthFixed, col_w);
        ImGui::TableSetupColumn("Col1", ImGuiTableColumnFlags_WidthFixed, col_w);

        for (int i = 0; i < 29; i += 2) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            {
                uint8_t ri = static_cast<uint8_t>(i);
                bool changed = has_prev && (state.gpr[i] != prev_state.gpr[i]);
                if (render_reg_cell(ri, reg_name(ri).c_str(), state.gpr[i],
                                    has_prev ? prev_state.gpr[i] : 0, changed)) {
                    ctx_reg_idx_   = ri;
                    ctx_reg_value_ = state.gpr[i];
                }
            }
            ImGui::TableNextColumn();
            if (i + 1 < 29) {
                uint8_t ri = static_cast<uint8_t>(i + 1);
                bool changed = has_prev && (state.gpr[i+1] != prev_state.gpr[i+1]);
                if (render_reg_cell(ri, reg_name(ri).c_str(), state.gpr[i+1],
                                    has_prev ? prev_state.gpr[i+1] : 0, changed)) {
                    ctx_reg_idx_   = ri;
                    ctx_reg_value_ = state.gpr[i+1];
                }
            }
        }
        ImGui::EndTable();
    }

    // ── Special registers ──────────────────────────────────────────
    // Thin divider
    ImVec2 sp_p0 = ImGui::GetCursorScreenPos();
    draw->AddLine(sp_p0, ImVec2(sp_p0.x + ImGui::GetContentRegionAvail().x, sp_p0.y),
                  IM_COL32(50, 55, 80, 180), 1.0f);
    ImGui::Dummy(ImVec2(0, 3));

    struct SpecReg { uint8_t idx; const char* name; uint64_t value; uint64_t prev; };
    SpecReg spec_regs[] = {
        { IDX_FP,   "fp",   state.fp(),   has_prev ? prev_state.fp()   : 0 },
        { IDX_LR,   "lr",   state.lr(),   has_prev ? prev_state.lr()   : 0 },
        { IDX_SP,   "sp",   state.sp(),   has_prev ? prev_state.sp()   : 0 },
        { IDX_PC,   "pc",   state.pc(),   has_prev ? prev_state.pc()   : 0 },
    };

    if (ImGui::BeginTable("SpecRegs", 2, tbl_flags)) {
        ImGui::TableSetupColumn("Col0", ImGuiTableColumnFlags_WidthFixed, col_w);
        ImGui::TableSetupColumn("Col1", ImGuiTableColumnFlags_WidthFixed, col_w);
        for (int si = 0; si < 4; si += 2) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            bool changed = has_prev && (spec_regs[si].value != spec_regs[si].prev);
            if (render_reg_cell(spec_regs[si].idx, spec_regs[si].name,
                                spec_regs[si].value, spec_regs[si].prev, changed)) {
                ctx_reg_idx_   = spec_regs[si].idx;
                ctx_reg_value_ = spec_regs[si].value;
            }
            ImGui::TableNextColumn();
            if (si + 1 < 4) {
                bool ch2 = has_prev && (spec_regs[si+1].value != spec_regs[si+1].prev);
                if (render_reg_cell(spec_regs[si+1].idx, spec_regs[si+1].name,
                                    spec_regs[si+1].value, spec_regs[si+1].prev, ch2)) {
                    ctx_reg_idx_   = spec_regs[si+1].idx;
                    ctx_reg_value_ = spec_regs[si+1].value;
                }
            }
        }
        ImGui::EndTable();
    }

    // NZCV flags — special display with individual flag bits
    {
        uint32_t nzcv = state.nzcv();
        bool nzcv_changed = has_prev && (nzcv != prev_state.nzcv());
        ImVec4 nzcv_col = get_reg_state(IDX_NZCV) != RegHighlight::Normal
            ? state_to_color(get_reg_state(IDX_NZCV))
            : (nzcv_changed ? ImVec4(0.85f, 0.75f, 0.40f, 1.0f) : ImVec4(0.55f, 0.62f, 0.80f, 1.0f));
        // Bit labels: N Z C V (bits 31,30,29,28 of NZCV)
        bool N = (nzcv >> 31) & 1, Z = (nzcv >> 30) & 1;
        bool C = (nzcv >> 29) & 1, V = (nzcv >> 28) & 1;
        ImGui::TextColored(ImVec4(0.55f, 0.62f, 0.80f, 1.0f), "nzcv");
        ImGui::SameLine(0, 4);
        auto flag_label = [&](bool set, const char* name) {
            if (set)
                ImGui::TextColored(nzcv_col, "%s", name);
            else
                ImGui::TextDisabled("%s", name);
            ImGui::SameLine(0, 3);
        };
        flag_label(N, "N"); flag_label(Z, "Z"); flag_label(C, "C"); flag_label(V, "V");
        ImGui::TextDisabled("(0x%x)", nzcv);
    }

    ImGui::PopStyleVar(2);

    // Render register context menu
    render_reg_context_menu();

    ImGui::End();
}

// ─── Context menu helpers (register) ────────────────────────────────────────

void GuiApp::render_reg_context_menu() {
    // No-op: register cell now uses BeginPopupContextItem inline in render_reg_cell().
}

}  // namespace tenet

// panels_vm_abstract.cpp — VM Abstract workspace + legacy single-panel.
//
// VM Workspace layout (independent floating window with its own DockSpace):
//
//  ┌────────────────────────────────────────────────────────────────────────┐
//  │  VM Workspace  [Linked ●]  [Run]  [Close]                             │
//  ├──────────────┬────────────────────────────────┬───────────────────────┤
//  │ VM Handlers  │  VM Steps (bytecode trace)     │  VM Registers / Stack │
//  │ (left ~18%)  │  (center-top ~55%)              │  (right ~27%)         │
//  │              ├────────────────────────────────┤                       │
//  │              │  Bytecode / Stats              │  VM Memory / Ctx      │
//  │              │  (center-bottom ~30%)          │  (right-bottom ~35%)  │
//  └──────────────┴────────────────────────────────┴───────────────────────┘
//
// Navigation:
//   - Clicking a VM step updates vm_ws_step_cursor_.
//   - When vm_ws_linked_==true, also calls navigate_to(inst_id_start) so the
//     native Instructions panel tracks the corresponding native code.
//   - Clicking a handler jumps to its first dispatch.
//
// Hints integration:
//   - VMRegisterFileHint → register or stack panel content.
//   - HandlerAsmHint → asm annotation lines shown in the steps panel.
//
// All sub-panels are in the same file to keep VM-specific state local.

#include "gui/gui_app.h"
#include "analysis/passes/vm/vm_abstract_pass.h"
#include "analysis/passes/vm/vm_decoder.h"
#include "analysis/passes/structure/xref_pass.h"

#include <imgui.h>
#include <imgui_internal.h>
#include <fmt/core.h>

#include <algorithm>
#include <cstring>
#include <numeric>
#include <string>
#include <vector>

#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ─── Shared helpers ──────────────────────────────────────────────────────────

static ImVec4 confidence_color_vmp(float c) {
    if (c >= 0.75f) return ImVec4(0.35f, 0.90f, 0.45f, 1.0f);
    if (c >= 0.50f) return ImVec4(1.0f,  0.90f, 0.20f, 1.0f);
    return ImVec4(0.50f, 0.50f, 0.50f, 1.0f);
}

static const char* dispatch_type_icon(DispatchType dt) {
    switch (dt) {
        case DispatchType::WhileSwitch:    return ICON_FA_ROTATE;
        case DispatchType::IndirectBranch: return ICON_FA_CODE_BRANCH;
        case DispatchType::CallTable:      return ICON_FA_TABLE_LIST;
        case DispatchType::ThreadedCode:   return ICON_FA_LINK;
        case DispatchType::Trampoline:     return ICON_FA_FORWARD;
        case DispatchType::FetchOnly:      return ICON_FA_CAMERA;
        default:                           return ICON_FA_CIRCLE_QUESTION;
    }
}

static std::string fmt_reg_mask(uint64_t mask) {
    std::string out;
    const char* names[34] = {
        "x0","x1","x2","x3","x4","x5","x6","x7",
        "x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23",
        "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
    };
    for (int i = 0; i < 34 && i < 64; ++i) {
        if (mask & (1ULL << i)) {
            if (!out.empty()) out += ',';
            out += names[i];
        }
    }
    return out.empty() ? "-" : out;
}

// Window / sub-panel names (must be stable across frames for DockBuilder)
static constexpr const char* kWsHandlers   = "VM Handlers##vmws";
static constexpr const char* kWsSteps      = "VM Steps##vmws";
static constexpr const char* kWsBytecode   = "Bytecode##vmws";
static constexpr const char* kWsRegisters  = "VM Registers##vmws";
static constexpr const char* kWsMemAccess  = "VM Memory##vmws";

// ─── render_vmws_handlers_panel ──────────────────────────────────────────────
// Left sidebar: handler list, sorted by freq or PC, with filter bar.

void GuiApp::render_vmws_handlers_panel() {
    if (!ImGui::Begin(kWsHandlers)) { ImGui::End(); return; }

    const auto& vm = *vm_abstract_result_;
    uint64_t slide = reader_.header().module_slide;

    // Filter + sort controls
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 4.0f);
    ImGui::InputTextWithHint("##hfilt", ICON_FA_MAGNIFYING_GLASS " Filter…",
                             vm_ws_handler_filter_, sizeof(vm_ws_handler_filter_));
    ImGui::Spacing();

    ImGui::RadioButton("Freq##hwsort", &vm_ws_handler_sort_, 0); ImGui::SameLine();
    ImGui::RadioButton("PC##hwsort",   &vm_ws_handler_sort_, 1);
    ImGui::Separator();

    std::string filt_str(vm_ws_handler_filter_);
    for (auto& c : filt_str) c = static_cast<char>(std::tolower(c));

    // Build sorted+filtered index
    std::vector<size_t> idx;
    idx.reserve(vm.handlers.size());
    for (size_t i = 0; i < vm.handlers.size(); ++i) {
        const auto& h = vm.handlers[i];
        if (!filt_str.empty()) {
            std::string label_lower = h.label;
            for (auto& c : label_lower) c = static_cast<char>(std::tolower(c));
            char pc_buf[24];
            snprintf(pc_buf, sizeof(pc_buf), "%llx",
                     (unsigned long long)(h.entry_pc - slide));
            if (label_lower.find(filt_str) == std::string::npos &&
                std::string(pc_buf).find(filt_str) == std::string::npos)
                continue;
        }
        idx.push_back(i);
    }
    if (vm_ws_handler_sort_ == 0) {
        std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
            return vm.handlers[a].execution_count > vm.handlers[b].execution_count;
        });
    } else {
        std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
            return vm.handlers[a].entry_pc < vm.handlers[b].entry_pc;
        });
    }

    uint64_t max_exec = 0;
    for (size_t i : idx) max_exec = std::max(max_exec, vm.handlers[i].execution_count);

    ImVec2 list_size(0.0f, ImGui::GetContentRegionAvail().y);
    ImGui::BeginChild("##hlist", list_size, ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);

    for (size_t ri = 0; ri < idx.size(); ++ri) {
        const VMHandler& h = vm.handlers[idx[ri]];
        bool selected = (vm_ws_handler_cursor_ == idx[ri]);

        // Mini heat-bar behind the selectable
        {
            ImVec2 pos = ImGui::GetCursorScreenPos();
            float bar_w = ImGui::GetContentRegionAvail().x;
            float bar_h = ImGui::GetTextLineHeightWithSpacing();
            float frac = max_exec > 0
                ? static_cast<float>(h.execution_count) / max_exec : 0.0f;
            ImGui::GetWindowDrawList()->AddRectFilled(
                pos, ImVec2(pos.x + bar_w * frac * 0.4f, pos.y + bar_h),
                IM_COL32(60, 100, 200, 50));
        }

        // Build display label
        char lbl[128];
        uint64_t static_pc = h.entry_pc - slide;
        if (!h.label.empty()) {
            snprintf(lbl, sizeof(lbl), "%s##hwsi%zu", h.label.c_str(), ri);
        } else {
            snprintf(lbl, sizeof(lbl), "handler_%llx##hwsi%zu",
                     (unsigned long long)static_pc, ri);
        }

        if (ImGui::Selectable(lbl, selected,
                ImGuiSelectableFlags_SpanAvailWidth)) {
            vm_ws_handler_cursor_ = idx[ri];
            // Jump to first dispatch in native trace
            if (xref_result_) {
                auto ids = xref_result_->inst_ids_at(h.entry_pc);
                if (!ids.empty()) {
                    if (vm_ws_linked_) navigate_to(ids.front());
                }
            }
        }

        if (ImGui::IsItemHovered()) {
            std::string tip = fmt::format(
                "PC:       0x{:x}\n"
                "Executions: {}\n"
                "Body PCs:   {}",
                static_pc, h.execution_count, h.body_pcs.size());
            if (!h.opcode_values.empty()) {
                tip += "\nOpcode(s):";
                for (auto ov : h.opcode_values) tip += fmt::format(" {}", ov);
            }
            ImGui::SetTooltip("%s", tip.c_str());
        }

        // Sub-text: PC + count
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
        ImGui::TextUnformatted("  ");
        ImGui::SameLine(0, 0);
        ImGui::Text("0x%llx  ×%llu",
                    (unsigned long long)static_pc,
                    (unsigned long long)h.execution_count);
        ImGui::PopStyleColor();

        // Opcode badge
        if (!h.opcode_values.empty()) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.55f, 0.90f, 0.70f, 1.0f),
                " [%llu]", (unsigned long long)h.opcode_values.front());
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

// ─── render_vmws_steps_panel ─────────────────────────────────────────────────
// Center-top: VM step trace with annotated asm from HandlerAsmHint.

void GuiApp::render_vmws_steps_panel() {
    if (!ImGui::Begin(kWsSteps)) { ImGui::End(); return; }

    const auto& vm   = *vm_abstract_result_;
    uint64_t   slide = reader_.header().module_slide;

    if (vm.steps.empty()) {
        ImGui::TextDisabled("No VM steps recorded.");
        ImGui::End(); return;
    }

    ImGui::TextDisabled("Total: %llu VM steps  ·  %llu native insts  ·  %.1f avg",
        (unsigned long long)vm.total_vm_steps,
        (unsigned long long)vm.total_native_instructions,
        vm.total_vm_steps > 0
            ? (double)vm.total_native_instructions / vm.total_vm_steps : 0.0);

    ImGui::Separator();

    // Table: Step# / Opcode / Handler / Asm / VM-PC
    const float avail_h = ImGui::GetContentRegionAvail().y;
    if (!ImGui::BeginTable("vmws_steps", 5,
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_RowBg     |
            ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_ScrollY   |
            ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.0f, avail_h))) {
        ImGui::End(); return;
    }

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed,   48.0f);
    ImGui::TableSetupColumn("Opcode",  ImGuiTableColumnFlags_WidthFixed,   68.0f);
    ImGui::TableSetupColumn("Handler", ImGuiTableColumnFlags_WidthFixed,  100.0f);
    ImGui::TableSetupColumn("Semantics / ASM", ImGuiTableColumnFlags_WidthStretch, 0.6f);
    ImGui::TableSetupColumn("VM-PC",   ImGuiTableColumnFlags_WidthFixed,   90.0f);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(vm.steps.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const VMStep& step = vm.steps[static_cast<size_t>(row)];
            bool selected = (vm_ws_step_cursor_ == static_cast<size_t>(row));

            ImGui::TableNextRow();
            ImGui::PushID(row);

            // ── Col 0: step number (selectable) ──
            ImGui::TableSetColumnIndex(0);
            char sid[24]; snprintf(sid, sizeof(sid), "%d", row + 1);
            if (ImGui::Selectable(sid, selected,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowOverlap)) {
                vm_ws_step_cursor_ = static_cast<size_t>(row);
                if (vm_ws_linked_) navigate_to(step.inst_id_start);
            }

            if (ImGui::IsItemHovered()) {
                std::string tip = fmt::format(
                    "Step #{}: inst #{} → #{}\n"
                    "Handler: 0x{:x}",
                    row + 1, step.inst_id_start, step.inst_id_end,
                    step.handler_entry_pc - slide);
                if (step.opcode_valid)
                    tip += fmt::format("\nOpcode idx: {}", step.opcode_value);
                if (step.vm_pc_valid)
                    tip += fmt::format("\nVM-PC: 0x{:x}", step.vm_pc_value);
                if (!step.vm_regs.empty()) {
                    tip += "\nVM regs:";
                    for (auto& [n, v] : step.vm_regs)
                        tip += fmt::format(" {}=0x{:x}", n, v);
                }
                ImGui::SetTooltip("%s", tip.c_str());
            }

            // Context menu
            if (ImGui::BeginPopupContextItem("##step_ctx")) {
                ImGui::TextDisabled("Step #%d", row + 1);
                ImGui::Separator();
                if (ImGui::MenuItem(ICON_FA_ARROW_RIGHT " Jump to Native")) {
                    navigate_to(step.inst_id_start);
                }
                if (ImGui::MenuItem(ICON_FA_FLAG " Jump to End")) {
                    navigate_to(step.inst_id_end);
                }
                ImGui::EndPopup();
            }

            // ── Col 1: decoded opcode index ──
            ImGui::TableSetColumnIndex(1);
            if (step.opcode_valid) {
                ImGui::TextColored(ImVec4(0.55f, 0.90f, 0.70f, 1.0f),
                    "idx=%llu", (unsigned long long)step.opcode_value);
            } else {
                ImGui::TextDisabled("-");
            }

            // ── Col 2: handler PC ──
            ImGui::TableSetColumnIndex(2);
            {
                const VMHandler* h = vm.handler_at(step.handler_entry_pc);
                if (h && !h->label.empty()) {
                    ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.45f, 1.0f),
                        "%s", h->label.c_str());
                } else {
                    ImGui::TextDisabled("0x%llx",
                        (unsigned long long)(step.handler_entry_pc - slide));
                }
            }

            // ── Col 3: asm — decoder output > HandlerAsmHint > fallback ──
            ImGui::TableSetColumnIndex(3);
            {
                bool shown = false;

                // Priority 1: VM bytecode decoder (per-instruction decode)
                if (vm_decoder_ && step.opcode_valid) {
                    auto decoded = vm_decoder_->decode(step, vm);
                    if (decoded.valid) {
                        ImGui::TextColored(ImVec4(0.90f, 0.80f, 1.0f, 1.0f),
                            "%s", decoded.asm_text.c_str());
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip("Decoded by '%s'\nOpcode: 0x%08llX → %s",
                                std::string(vm_decoder_->name()).c_str(),
                                (unsigned long long)step.opcode_value,
                                decoded.asm_text.c_str());
                        }
                        shown = true;
                    }
                }

                // Priority 2: HandlerAsmHint (static handler-level annotation)
                if (!shown && vm.handler_asm.has_value()) {
                    uint64_t h_static_pc = step.handler_entry_pc - slide;
                    auto it = vm.handler_asm->handler_asm.find(h_static_pc);
                    if (it != vm.handler_asm->handler_asm.end() && !it->second.empty()) {
                        const auto& lines = it->second;
                        ImGui::TextColored(ImVec4(0.75f, 0.85f, 1.0f, 1.0f),
                            "%s", lines.front().text.c_str());
                        if (lines.size() > 1 && ImGui::IsItemHovered()) {
                            ImGui::BeginTooltip();
                            for (const auto& ln : lines) {
                                if (ln.pc != 0)
                                    ImGui::TextDisabled("0x%llx  ", (unsigned long long)ln.pc);
                                ImGui::SameLine(0, 0);
                                ImGui::TextUnformatted(ln.text.c_str());
                            }
                            ImGui::EndTooltip();
                        }
                        shown = true;
                    }
                }

                // Fallback: handler label or inst range
                if (!shown) {
                    const VMHandler* h = vm.handler_at(step.handler_entry_pc);
                    if (h && !h->label.empty()) {
                        ImGui::TextDisabled("%s", h->label.c_str());
                    } else {
                        ImGui::TextDisabled("#%llu–#%llu",
                            (unsigned long long)step.inst_id_start,
                            (unsigned long long)step.inst_id_end);
                    }
                }
            }

            // ── Col 4: VM-PC ──
            // Display as bytecode offset (vm_pc - bytecode_base) when the base
            // is known — this maps directly to the offset you see in a hex editor
            // or IDA's bytecode view.  The full runtime address is in the tooltip.
            ImGui::TableSetColumnIndex(4);
            if (step.vm_pc_valid) {
                if (vm.bytecode_base != 0 && step.vm_pc_value >= vm.bytecode_base) {
                    uint64_t bc_off = step.vm_pc_value - vm.bytecode_base;
                    ImGui::TextDisabled("+0x%llx", (unsigned long long)bc_off);
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Bytecode offset +0x%llx\nRuntime: 0x%llx",
                            (unsigned long long)bc_off,
                            (unsigned long long)step.vm_pc_value);
                    }
                } else {
                    // No base known: show raw runtime address
                    ImGui::TextDisabled("0x%llx", (unsigned long long)step.vm_pc_value);
                }
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::PopID();
        }
    }
    clipper.End();
    ImGui::EndTable();
    ImGui::End();
}

// ─── render_vmws_bytecode_panel ──────────────────────────────────────────────
// Center-bottom: bytecode statistics + dispatcher summary.

void GuiApp::render_vmws_bytecode_panel() {
    if (!ImGui::Begin(kWsBytecode)) { ImGui::End(); return; }

    const auto& vm   = *vm_abstract_result_;
    uint64_t   slide = reader_.header().module_slide;

    if (ImGui::BeginTabBar("##bc_tabs")) {

        // ── Tab 1: Dispatcher summary ──────────────────────────────────
        if (ImGui::BeginTabItem(ICON_FA_INFO "  Dispatcher")) {
            const auto& d = vm.dispatcher;
            ImGui::Spacing();

            auto row = [](const char* k, const char* v) {
                ImGui::TextDisabled("%-28s", k);
                ImGui::SameLine(210.0f);
                ImGui::TextUnformatted(v);
            };
            char buf[64];

            snprintf(buf, sizeof(buf), "%s  (%.0f%%)",
                     dispatch_type_name(d.dispatch_type),
                     d.confidence * 100.0f);
            row("Dispatch type:", buf);

            snprintf(buf, sizeof(buf), "0x%llx",
                     (unsigned long long)(d.loop_header_pc - slide));
            row("Loop header (static):", buf);

            if (d.indirect_branch_pc) {
                snprintf(buf, sizeof(buf), "0x%llx",
                         (unsigned long long)(d.indirect_branch_pc - slide));
                row("Branch insn (static):", buf);
            }

            snprintf(buf, sizeof(buf), "%llu",
                     (unsigned long long)d.iteration_count);
            row("Dispatch iterations:", buf);

            snprintf(buf, sizeof(buf), "%zu", vm.handlers.size());
            row("Unique handlers:", buf);

            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)vm.total_vm_steps);
            row("VM steps:", buf);

            snprintf(buf, sizeof(buf), "%llu",
                     (unsigned long long)vm.total_native_instructions);
            row("Native instructions:", buf);

            if (vm.total_vm_steps > 0) {
                snprintf(buf, sizeof(buf), "%.1f",
                         (double)vm.total_native_instructions / vm.total_vm_steps);
                row("Avg insts/step:", buf);
            }

            if (vm.vm_pc_reg != 0xFF) {
                const char* rnames[34] = {
                    "x0","x1","x2","x3","x4","x5","x6","x7",
                    "x8","x9","x10","x11","x12","x13","x14","x15",
                    "x16","x17","x18","x19","x20","x21","x22","x23",
                    "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
                };
                row("VM-PC register:", rnames[vm.vm_pc_reg < 34 ? vm.vm_pc_reg : 0]);
            }

            if (vm.arch_type != VMArchType::Unknown)
                row("VM architecture:", vm_arch_name(vm.arch_type));

            if (vm.bytecode_base != 0) {
                snprintf(buf, sizeof(buf), "0x%llx – 0x%llx",
                         (unsigned long long)vm.bytecode_base,
                         (unsigned long long)vm.bytecode_end);
                row("Bytecode range:", buf);
            }

            ImGui::EndTabItem();
        }

        // ── Tab 2: Top handlers by frequency ───────────────────────────
        if (ImGui::BeginTabItem(ICON_FA_ARROW_UP_WIDE_SHORT "  Hot Handlers")) {
            auto sorted = vm.handlers_by_frequency();
            size_t limit = std::min(sorted.size(), size_t{30});

            if (ImGui::BeginTable("hfreq", 4,
                    ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_BordersInnerV)) {
                ImGui::TableSetupColumn("Rank", ImGuiTableColumnFlags_WidthFixed, 40.0f);
                ImGui::TableSetupColumn("PC",   ImGuiTableColumnFlags_WidthFixed, 90.0f);
                ImGui::TableSetupColumn("Label",ImGuiTableColumnFlags_WidthStretch, 0.4f);
                ImGui::TableSetupColumn("Count",ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableHeadersRow();

                for (size_t ri = 0; ri < limit; ++ri) {
                    const VMHandler* h = sorted[ri];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextDisabled("#%zu", ri + 1);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextDisabled("0x%llx",
                        (unsigned long long)(h->entry_pc - slide));
                    ImGui::TableSetColumnIndex(2);
                    if (!h->label.empty())
                        ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.45f, 1.0f),
                            "%s", h->label.c_str());
                    else
                        ImGui::TextDisabled("handler_%llx",
                            (unsigned long long)(h->entry_pc - slide));
                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("%llu", (unsigned long long)h->execution_count);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        // ── Tab 3: Opcode distribution ──────────────────────────────────
        if (ImGui::BeginTabItem(ICON_FA_CHART_BAR "  Opcodes")) {
            // Collect opcode → execution count
            std::vector<std::pair<uint64_t, uint64_t>> opc_counts; // (opcode, count)
            for (const auto& h : vm.handlers) {
                for (uint64_t ov : h.opcode_values) {
                    bool found = false;
                    for (auto& [op, cnt] : opc_counts) {
                        if (op == ov) { cnt += h.execution_count; found = true; break; }
                    }
                    if (!found) opc_counts.emplace_back(ov, h.execution_count);
                }
            }
            std::sort(opc_counts.begin(), opc_counts.end(),
                [](const auto& a, const auto& b){ return a.second > b.second; });

            if (opc_counts.empty()) {
                ImGui::TextDisabled("No opcode data — provide opcode_from_reg or opcode_size hint.");
            } else {
                uint64_t max_c = opc_counts.front().second;
                if (ImGui::BeginTable("opcdist", 3,
                        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 72.0f);
                    ImGui::TableSetupColumn("Dist",   ImGuiTableColumnFlags_WidthStretch, 0.6f);
                    ImGui::TableSetupColumn("Count",  ImGuiTableColumnFlags_WidthFixed,  80.0f);
                    ImGui::TableHeadersRow();
                    for (auto& [ov, cnt] : opc_counts) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextColored(ImVec4(0.55f, 0.90f, 0.70f, 1.0f),
                            "%llu", (unsigned long long)ov);
                        ImGui::TableSetColumnIndex(1);
                        {
                            float frac = max_c > 0 ? (float)cnt / max_c : 0.0f;
                            ImVec2 bp = ImGui::GetCursorScreenPos();
                            float bw  = ImGui::GetContentRegionAvail().x - 4.0f;
                            float bh  = ImGui::GetTextLineHeight() * 0.7f;
                            ImGui::GetWindowDrawList()->AddRectFilled(
                                bp, ImVec2(bp.x + bw * frac, bp.y + bh),
                                IM_COL32(80, 160, 220, 160));
                            ImGui::Dummy(ImVec2(bw, bh));
                        }
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%llu", (unsigned long long)cnt);
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}

// ─── render_vmws_registers_panel ─────────────────────────────────────────────
// Right-top: VM register file (register machine) or VM stack (stack machine).
// Shows values at the currently selected VM step.

void GuiApp::render_vmws_registers_panel() {
    if (!ImGui::Begin(kWsRegisters)) { ImGui::End(); return; }

    const auto& vm   = *vm_abstract_result_;
    bool has_rf_hint = vm.vm_register_file.has_value();
    bool has_regs    = has_rf_hint && vm.vm_register_file->has_regs();
    bool has_stack   = has_rf_hint && vm.vm_register_file->has_stack();
    bool is_mixed    = has_regs && has_stack;

    // Get the step at cursor
    const VMStep* cur_step = nullptr;
    if (vm_ws_step_cursor_ < vm.steps.size()) {
        cur_step = &vm.steps[vm_ws_step_cursor_];
    }

    // Previous step for change-highlighting
    const VMStep* prev_step = (vm_ws_step_cursor_ > 0 &&
        vm_ws_step_cursor_ - 1 < vm.steps.size())
        ? &vm.steps[vm_ws_step_cursor_ - 1] : nullptr;

    // Auto-lookup prev value for change detection
    auto find_prev_val = [&](const std::string& name, uint64_t& out) -> bool {
        if (!prev_step) return false;
        for (const auto& [pn, pv] : prev_step->vm_regs) {
            if (pn == name) { out = pv; return true; }
        }
        return false;
    };

    // Header
    if (is_mixed) {
        ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f),
            ICON_FA_DATABASE "  VM Registers + " ICON_FA_LAYER_GROUP " Stack");
    } else if (has_stack) {
        ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f),
            ICON_FA_LAYER_GROUP "  VM Stack");
    } else {
        ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f),
            ICON_FA_DATABASE "  VM Registers");
    }
    ImGui::SameLine();
    if (cur_step) {
        ImGui::TextDisabled("  step #%zu", vm_ws_step_cursor_ + 1);
    } else {
        ImGui::TextDisabled("  (no step selected)");
    }
    ImGui::Separator();

    if (!cur_step || cur_step->vm_regs.empty()) {
        if (!has_rf_hint) {
            ImGui::TextDisabled("No VM register file hint provided.");
            ImGui::TextWrapped(
                "Supply vm_registers (register machine) and/or vm_stack_sp_offset "
                "(stack machine) via MCP or hints_file.");
        } else {
            ImGui::TextDisabled("No register data at this step.");
        }
        ImGui::End(); return;
    }

    // Separate vm_regs into named-register entries and stack entries
    // Named registers: anything that is NOT "SP" or "S<n>"
    // Stack entries:   "SP", "S0", "S1", …
    // This heuristic works because the backend always emits named regs first,
    // then SP+stack-slots.
    std::vector<const std::pair<std::string,uint64_t>*> reg_entries, stack_entries;
    for (const auto& kv : cur_step->vm_regs) {
        const std::string& n = kv.first;
        bool is_sp   = (n == "SP");
        bool is_slot = (n.size() >= 2 && n[0] == 'S' && std::isdigit((unsigned char)n[1]));
        if (is_sp || is_slot) stack_entries.push_back(&kv);
        else                  reg_entries.push_back(&kv);
    }

    // Helper: render a register table section
    auto render_reg_table = [&](const char* table_id, float height,
        const std::vector<const std::pair<std::string,uint64_t>*>& entries)
    {
        if (ImGui::BeginTable(table_id, 3,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                ImVec2(0.0f, height))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Reg",  ImGuiTableColumnFlags_WidthFixed,  70.0f);
            ImGui::TableSetupColumn("Hex",  ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("Dec",  ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto* kv : entries) {
                const auto& [name, val] = *kv;
                ImGui::TableNextRow();

                uint64_t pval = 0;
                bool changed = find_prev_val(name, pval) && pval != val;

                ImGui::TableSetColumnIndex(0);
                if (changed)
                    ImGui::TextColored(ImVec4(0.40f, 0.90f, 0.50f, 1.0f), "%s", name.c_str());
                else
                    ImGui::TextDisabled("%s", name.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%016llx", (unsigned long long)val);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%llu", (unsigned long long)val);
            }
            ImGui::EndTable();
        }
    };

    // Helper: render a stack table section
    auto render_stack_table = [&](const char* table_id, float height,
        const std::vector<const std::pair<std::string,uint64_t>*>& entries)
    {
        if (ImGui::BeginTable(table_id, 2,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                ImVec2(0.0f, height))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Slot",  ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto* kv : entries) {
                const auto& [name, val] = *kv;
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (name == "SP")
                    ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.2f, 1.0f), "SP");
                else
                    ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f), "%s", name.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%016llx", (unsigned long long)val);
                ImGui::SameLine();
                ImGui::TextDisabled("  %llu", (unsigned long long)val);
            }
            ImGui::EndTable();
        }
    };

    float avail_h = ImGui::GetContentRegionAvail().y;

    if (is_mixed) {
        // ── Mixed mode: split panel vertically ────────────────────────────
        // Top half: named registers; bottom half: stack
        float split = avail_h * 0.55f;
        float stack_h = avail_h - split - ImGui::GetTextLineHeightWithSpacing() - 4.0f;

        if (!reg_entries.empty()) {
            render_reg_table("vmregs_mixed", split, reg_entries);
        }
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f),
            ICON_FA_LAYER_GROUP "  Stack");
        ImGui::Separator();
        if (!stack_entries.empty()) {
            render_stack_table("vmstack_mixed", stack_h, stack_entries);
        }
    } else if (has_stack) {
        // ── Pure stack machine view ───────────────────────────────────────
        render_stack_table("vmstack", avail_h,
            stack_entries.empty() ?
                [&]{ std::vector<const std::pair<std::string,uint64_t>*> all;
                     for (auto& kv : cur_step->vm_regs) all.push_back(&kv);
                     return all; }()
                : stack_entries);
    } else {
        // ── Pure register file view ───────────────────────────────────────
        render_reg_table("vmregs", avail_h,
            reg_entries.empty() ?
                [&]{ std::vector<const std::pair<std::string,uint64_t>*> all;
                     for (auto& kv : cur_step->vm_regs) all.push_back(&kv);
                     return all; }()
                : reg_entries);
    }

    ImGui::End();
}

// ─── render_vmws_memaccess_panel ─────────────────────────────────────────────
// Right-bottom: VM context fields + memory accesses for current step.

void GuiApp::render_vmws_memaccess_panel() {
    if (!ImGui::Begin(kWsMemAccess)) { ImGui::End(); return; }

    const auto& vm = *vm_abstract_result_;

    const VMStep* cur_step = nullptr;
    if (vm_ws_step_cursor_ < vm.steps.size()) {
        cur_step = &vm.steps[vm_ws_step_cursor_];
    }

    if (ImGui::BeginTabBar("##vmem_tabs")) {

        // ── Tab 1: VM context fields ───────────────────────────────────
        if (ImGui::BeginTabItem(ICON_FA_BOXES_STACKED "  VM Context")) {
            if (!cur_step || cur_step->ctx_fields.empty()) {
                ImGui::TextDisabled("No context field data.");
                ImGui::TextWrapped("Supply ctx_base_reg hint to enable.");
            } else {
                if (ImGui::BeginTable("vctx", 2,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                        ImGuiTableFlags_SizingStretchProp)) {
                    ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    for (const auto& [fn, fv] : cur_step->ctx_fields) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextDisabled("%s", fn.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("0x%llx", (unsigned long long)fv);
                        ImGui::SameLine();
                        ImGui::TextDisabled("  %llu", (unsigned long long)fv);
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        // ── Tab 2: Handler body PCs ────────────────────────────────────
        if (ImGui::BeginTabItem(ICON_FA_CODE "  Handler Body")) {
            if (!cur_step) {
                ImGui::TextDisabled("No step selected.");
            } else {
                const VMHandler* h = vm.handler_at(cur_step->handler_entry_pc);
                uint64_t slide = reader_.header().module_slide;
                if (!h) {
                    ImGui::TextDisabled("Handler not found.");
                } else {
                    ImGui::TextDisabled("Handler  0x%llx  ×%llu",
                        (unsigned long long)(h->entry_pc - slide),
                        (unsigned long long)h->execution_count);
                    ImGui::Separator();

                    // If asm hint available, show full annotated body
                    bool asm_shown = false;
                    if (vm.handler_asm.has_value()) {
                        auto it = vm.handler_asm->handler_asm.find(
                            h->entry_pc - slide);
                        if (it != vm.handler_asm->handler_asm.end()) {
                            asm_shown = true;
                            for (const auto& ln : it->second) {
                                if (ln.pc != 0) {
                                    ImGui::TextDisabled("0x%llx  ",
                                        (unsigned long long)ln.pc);
                                    ImGui::SameLine(0, 0);
                                }
                                ImGui::TextColored(ImVec4(0.80f, 0.85f, 1.0f, 1.0f),
                                    "%s", ln.text.c_str());
                            }
                        }
                    }

                    if (!asm_shown) {
                        // Fallback: show native body PCs
                        ImGui::TextDisabled("Native PCs (%zu):", h->body_pcs.size());
                        ImGui::BeginChild("##hbody", ImVec2(0, 0),
                            ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
                        for (uint64_t pc : h->body_pcs) {
                            if (ImGui::Selectable(
                                    fmt::format("0x{:x}##hbpc{:x}",
                                                pc - slide, pc).c_str())) {
                                if (xref_result_) {
                                    auto ids = xref_result_->inst_ids_at(pc);
                                    if (!ids.empty()) navigate_to(ids.front());
                                }
                            }
                        }
                        ImGui::EndChild();
                    }
                }
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}

// ─── render_vm_workspace ─────────────────────────────────────────────────────
// Top-level: create the floating host window + internal DockSpace + toolbar.

void GuiApp::render_vm_workspace() {
    if (!vm_ws_open_) return;
    if (!vm_abstract_result_) {
        // Auto-close if result was cleared
        vm_ws_open_ = false;
        return;
    }

    // ── Host window ──────────────────────────────────────────────────
    ImGui::SetNextWindowSize(ImVec2(1280, 760), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSizeConstraints(ImVec2(800, 500), ImVec2(FLT_MAX, FLT_MAX));

    ImGuiWindowFlags host_flags =
        ImGuiWindowFlags_NoDocking |   // Don't dock into main dockspace
        ImGuiWindowFlags_NoScrollbar;

    if (!ImGui::Begin("VM Workspace##vmws_host", &vm_ws_open_, host_flags)) {
        ImGui::End();
        return;
    }

    const auto& vm   = *vm_abstract_result_;
    uint64_t   slide = reader_.header().module_slide;

    // ── Workspace toolbar ────────────────────────────────────────────
    {
        const auto& d = vm.dispatcher;
        bool detected = (d.loop_header_pc != 0 || !vm.handlers.empty());

        // Status badge
        if (detected) {
            ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f),
                ICON_FA_MICROCHIP "  VM Detected");
        } else {
            ImGui::TextColored(ImVec4(0.75f, 0.30f, 0.30f, 1.0f),
                ICON_FA_CIRCLE_XMARK "  No VM found");
        }
        ImGui::SameLine(0, 12);

        // Dispatch type
        if (d.loop_header_pc != 0) {
            ImGui::TextColored(ImVec4(0.65f, 0.85f, 1.0f, 1.0f),
                "%s %s  (%.0f%%)",
                dispatch_type_icon(d.dispatch_type),
                dispatch_type_name(d.dispatch_type),
                d.confidence * 100.0f);
            ImGui::SameLine(0, 12);
        }

        // Handler / step counters
        ImGui::TextDisabled("%zu handlers  ·  %llu steps",
            vm.handlers.size(),
            (unsigned long long)vm.total_vm_steps);
        ImGui::SameLine(0, 16);

        // Link toggle
        ImGui::PushStyleColor(ImGuiCol_Button,
            vm_ws_linked_
            ? ImVec4(0.20f, 0.55f, 0.20f, 0.80f)
            : ImVec4(0.35f, 0.35f, 0.35f, 0.60f));
        if (ImGui::SmallButton(vm_ws_linked_
                ? ICON_FA_LINK "  Linked"
                : ICON_FA_LINK_SLASH "  Unlinked")) {
            vm_ws_linked_ = !vm_ws_linked_;
        }
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Toggle sync with native Instructions panel");

        ImGui::SameLine(0, 8);
        if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT "  Rerun")) {
            run_vm_abstract_with_hints();
            vm_ws_first_frame_ = true;   // rebuild DockSpace
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Re-run with the currently loaded hints file / auto-detect setting.");

        ImGui::SameLine(0, 8);
        static bool vm_ws_show_hints_editor = false;
        ImGui::PushStyleColor(ImGuiCol_Button,
            vm_ws_show_hints_editor
            ? ImVec4(0.20f, 0.45f, 0.65f, 0.80f)
            : ImVec4(0.35f, 0.35f, 0.35f, 0.60f));
        if (ImGui::SmallButton(ICON_FA_FILE_LINES "  Hints")) {
            vm_ws_show_hints_editor = !vm_ws_show_hints_editor;
        }
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Show/hide the hints file input");

        ImGui::SameLine(0, 4);
        static bool vm_ws_show_decoder_editor = false;
        ImGui::PushStyleColor(ImGuiCol_Button,
            vm_ws_show_decoder_editor
            ? ImVec4(0.40f, 0.25f, 0.60f, 0.80f)
            : ImVec4(0.35f, 0.35f, 0.35f, 0.60f));
        if (ImGui::SmallButton(ICON_FA_CODE "  Decoder")) {
            vm_ws_show_decoder_editor = !vm_ws_show_decoder_editor;
        }
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) {
            if (vm_decoder_)
                ImGui::SetTooltip("Decoder: %s\nClick to show/hide decoder settings",
                    std::string(vm_decoder_->name()).c_str());
            else
                ImGui::SetTooltip("No decoder loaded. Click to load one.");
        }

        // Decoder status badge in toolbar
        if (vm_decoder_) {
            ImGui::SameLine(0, 8);
            ImGui::TextColored(ImVec4(0.75f, 0.60f, 1.0f, 1.0f),
                ICON_FA_CHECK "  %s", std::string(vm_decoder_->name()).c_str());
        }

        ImGui::Separator();

        if (vm_ws_show_hints_editor) {
            render_vm_hints_input(ICON_FA_ARROW_ROTATE_LEFT "  Rerun with hints", 260.0f);
            ImGui::Separator();
        }

        if (vm_ws_show_decoder_editor) {
            render_vm_decoder_input();
            ImGui::Separator();
        }
    }

    // ── Internal DockSpace ───────────────────────────────────────────
    ImVec2 ds_size = ImGui::GetContentRegionAvail();
    if (vm_ws_dockspace_id_ == 0)
        vm_ws_dockspace_id_ = ImGui::GetID("VMWorkspaceDockSpace");

    ImGui::DockSpace(vm_ws_dockspace_id_, ds_size,
        ImGuiDockNodeFlags_PassthruCentralNode);

    // ── Default layout (first open only) ────────────────────────────
    if (vm_ws_first_frame_) {
        vm_ws_first_frame_ = false;

        ImGui::DockBuilderRemoveNode(vm_ws_dockspace_id_);
        ImGui::DockBuilderAddNode(vm_ws_dockspace_id_, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(vm_ws_dockspace_id_, ds_size);

        // Step 1: carve left (handlers, 18%)
        ImGuiID dk_left, dk_rest;
        ImGui::DockBuilderSplitNode(vm_ws_dockspace_id_, ImGuiDir_Left, 0.18f,
                                    &dk_left, &dk_rest);

        // Step 2: carve right (registers + memaccess, 27%)
        ImGuiID dk_center, dk_right;
        ImGui::DockBuilderSplitNode(dk_rest, ImGuiDir_Right, 0.27f,
                                    &dk_right, &dk_center);

        // Step 3: split center vertically (steps 70%, bytecode 30%)
        ImGuiID dk_center_top, dk_center_bot;
        ImGui::DockBuilderSplitNode(dk_center, ImGuiDir_Down, 0.30f,
                                    &dk_center_bot, &dk_center_top);

        // Step 4: split right vertically (registers 55%, memaccess 45%)
        ImGuiID dk_right_top, dk_right_bot;
        ImGui::DockBuilderSplitNode(dk_right, ImGuiDir_Down, 0.45f,
                                    &dk_right_bot, &dk_right_top);

        // Assign windows
        ImGui::DockBuilderDockWindow(kWsHandlers,  dk_left);
        ImGui::DockBuilderDockWindow(kWsSteps,     dk_center_top);
        ImGui::DockBuilderDockWindow(kWsBytecode,  dk_center_bot);
        ImGui::DockBuilderDockWindow(kWsRegisters, dk_right_top);
        ImGui::DockBuilderDockWindow(kWsMemAccess, dk_right_bot);

        ImGui::DockBuilderFinish(vm_ws_dockspace_id_);
    }

    ImGui::End();

    // ── Sub-panels (each is a normal ImGui window docked into the above) ──
    render_vmws_handlers_panel();
    render_vmws_steps_panel();
    render_vmws_bytecode_panel();
    render_vmws_registers_panel();
    render_vmws_memaccess_panel();
}

// ─── push_vm_hints_recent ───────────────────────────────────────────────────
// Records `path` at the front of the MRU list (de-duplicating), capped at 8
// entries. Process-lifetime only (not persisted) since hints files are
// tightly coupled to a specific binary/trace analysis session.
void GuiApp::push_vm_hints_recent(const std::string& path) {
    if (path.empty()) return;
    auto it = std::find(vm_hints_recent_.begin(), vm_hints_recent_.end(), path);
    if (it != vm_hints_recent_.end()) vm_hints_recent_.erase(it);
    vm_hints_recent_.insert(vm_hints_recent_.begin(), path);
    if (vm_hints_recent_.size() > 8) vm_hints_recent_.resize(8);
}

// ─── push_vm_decoder_recent ─────────────────────────────────────────────────
void GuiApp::push_vm_decoder_recent(const std::string& path) {
    if (path.empty()) return;
    auto it = std::find(vm_decoder_recent_.begin(), vm_decoder_recent_.end(), path);
    if (it != vm_decoder_recent_.end()) vm_decoder_recent_.erase(it);
    vm_decoder_recent_.insert(vm_decoder_recent_.begin(), path);
    if (vm_decoder_recent_.size() > 8) vm_decoder_recent_.resize(8);
}

// ─── load_vm_decoder ────────────────────────────────────────────────────────
void GuiApp::load_vm_decoder() {
    std::string path(vm_decoder_path_buf_);
    if (path.empty()) {
        vm_decoder_.reset();
        vm_decoder_status_.clear();
        return;
    }

    // Skip reload if same path is already loaded
    if (vm_decoder_ && vm_decoder_status_.find(path) != std::string::npos
        && vm_decoder_status_.rfind(ICON_FA_CIRCLE_CHECK, 0) == 0) {
        return;
    }

    try {
        vm_decoder_ = std::shared_ptr<VMBytecodeDecoder>(
            load_decoder_from_json(path).release());
        vm_decoder_status_ = fmt::format(
            ICON_FA_CIRCLE_CHECK "  Decoder '{}' loaded from {}",
            vm_decoder_->name(), path);
        push_vm_decoder_recent(path);
        save_vm_profile();
    } catch (const std::exception& e) {
        vm_decoder_.reset();
        vm_decoder_status_ = fmt::format(
            ICON_FA_CIRCLE_XMARK "  Failed to load decoder: {}", e.what());
    }
}

// ─── save_vm_profile ─────────────────────────────────────────────────────────
void GuiApp::save_vm_profile() {
    std::string module = reader_.header().module_name;
    if (module.empty()) return;
    vm_profiles_.upsert(module,
                        std::string(vm_hints_path_buf_),
                        std::string(vm_decoder_path_buf_));
    vm_profiles_.save();
}

// ─── restore_vm_profile ──────────────────────────────────────────────────────
void GuiApp::restore_vm_profile() {
    std::string module = reader_.header().module_name;
    if (module.empty()) return;
    const auto* prof = vm_profiles_.find(module);
    if (!prof) return;

    if (!prof->hints_file.empty() && vm_hints_path_buf_[0] == '\0') {
        std::snprintf(vm_hints_path_buf_, sizeof(vm_hints_path_buf_),
                      "%s", prof->hints_file.c_str());
        push_vm_hints_recent(prof->hints_file);
    }
    if (!prof->decoder_file.empty() && vm_decoder_path_buf_[0] == '\0') {
        std::snprintf(vm_decoder_path_buf_, sizeof(vm_decoder_path_buf_),
                      "%s", prof->decoder_file.c_str());
        push_vm_decoder_recent(prof->decoder_file);
    }
}

// ─── render_vm_decoder_input ─────────────────────────────────────────────────
// Renders a decoder file selector: drag-and-drop target, browse button,
// recent list, load button, status line. Visually parallel to the hints input.
void GuiApp::render_vm_decoder_input() {
    ImGui::TextWrapped(
        "Load a VM bytecode decoder definition (.json) to decode raw opcodes "
        "into readable assembly (e.g. 'XOR R3, R1, R2').");
    ImGui::Spacing();

    // ── Drag & drop / click-to-browse target ──────────────────────────
    const float dz_h = 46.0f;
    ImVec2 dz_pos = ImGui::GetCursorScreenPos();
    ImVec2 dz_size(ImGui::GetContentRegionAvail().x, dz_h);
    ImGui::InvisibleButton("##vm_decoder_dropzone", dz_size);
    bool dz_hovered = ImGui::IsItemHovered();
    bool dz_clicked = ImGui::IsItemClicked();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 dz_bg = dz_hovered
        ? IM_COL32(50, 45, 80, 200)
        : IM_COL32(32, 30, 44, 160);
    ImU32 dz_border = dz_hovered
        ? IM_COL32(150, 110, 230, 255)
        : IM_COL32(95, 85, 120, 200);
    dl->AddRectFilled(dz_pos, ImVec2(dz_pos.x + dz_size.x, dz_pos.y + dz_size.y),
                       dz_bg, 6.0f);
    dl->AddRect(dz_pos, ImVec2(dz_pos.x + dz_size.x, dz_pos.y + dz_size.y),
                dz_border, 6.0f, 0, 1.5f);

    const char* dz_text = vm_decoder_path_buf_[0] != '\0'
        ? vm_decoder_path_buf_
        : ICON_FA_CODE "  Drag & drop a decoder .json here, or click to browse";
    ImVec2 txt_sz = ImGui::CalcTextSize(dz_text);
    ImVec2 txt_pos(dz_pos.x + (dz_size.x - txt_sz.x) * 0.5f,
                    dz_pos.y + (dz_size.y - txt_sz.y) * 0.5f);
    if (txt_pos.x < dz_pos.x + 8.0f) txt_pos.x = dz_pos.x + 8.0f;
    ImVec4 txt_col = vm_decoder_path_buf_[0] != '\0'
        ? ImVec4(0.85f, 0.75f, 1.0f, 1.0f)
        : ImVec4(0.60f, 0.55f, 0.72f, 1.0f);
    dl->PushClipRect(dz_pos, ImVec2(dz_pos.x + dz_size.x, dz_pos.y + dz_size.y), true);
    dl->AddText(txt_pos, ImGui::GetColorU32(txt_col), dz_text);
    dl->PopClipRect();

    if (dz_hovered) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(vm_decoder_path_buf_[0] != '\0'
            ? "Click to choose a different decoder file"
            : "Click to browse for a decoder .json file");
    }

    if (dz_clicked) {
        std::string picked = pick_file_path(
            "Choose a VM bytecode decoder JSON", {"json"});
        if (!picked.empty()) {
            std::snprintf(vm_decoder_path_buf_, sizeof(vm_decoder_path_buf_),
                          "%s", picked.c_str());
            vm_decoder_status_.clear();
        }
    }

    ImGui::Spacing();

    // ── Recent decoder files ──────────────────────────────────────────
    if (!vm_decoder_recent_.empty()) {
        ImGui::TextDisabled(ICON_FA_CLOCK_ROTATE_LEFT "  Recent decoders:");
        for (size_t i = 0; i < vm_decoder_recent_.size(); ++i) {
            const std::string& p = vm_decoder_recent_[i];
            size_t slash = p.find_last_of('/');
            std::string short_name = (slash == std::string::npos) ? p : p.substr(slash + 1);
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(1000 + i));  // offset from hints IDs
            if (ImGui::SmallButton(short_name.c_str())) {
                std::snprintf(vm_decoder_path_buf_, sizeof(vm_decoder_path_buf_),
                              "%s", p.c_str());
                vm_decoder_status_.clear();
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", p.c_str());
            ImGui::PopID();
        }
    }

    ImGui::Spacing();

    // ── Load / Reload button ──────────────────────────────────────────
    bool can_load = vm_decoder_path_buf_[0] != '\0';
    ImGui::BeginDisabled(!can_load);
    if (ImGui::Button(ICON_FA_CODE "  Load Decoder", ImVec2(160, 0))) {
        load_vm_decoder();
    }
    ImGui::EndDisabled();
    if (!can_load && ImGui::IsItemHovered())
        ImGui::SetTooltip("Select a decoder file first.");

    // ── Clear button ──────────────────────────────────────────────────
    if (vm_decoder_) {
        ImGui::SameLine();
        if (ImGui::SmallButton(ICON_FA_XMARK "  Clear")) {
            vm_decoder_.reset();
            vm_decoder_path_buf_[0] = '\0';
            vm_decoder_status_ = ICON_FA_CIRCLE_XMARK "  Decoder cleared";
        }
    }

    // ── Status ────────────────────────────────────────────────────────
    if (!vm_decoder_status_.empty()) {
        ImGui::Spacing();
        ImVec4 col(0.85f, 0.85f, 0.85f, 1.0f);
        if (vm_decoder_status_.rfind(ICON_FA_CIRCLE_XMARK, 0) == 0)
            col = ImVec4(0.95f, 0.40f, 0.40f, 1.0f);
        else if (vm_decoder_status_.rfind(ICON_FA_CIRCLE_CHECK, 0) == 0)
            col = ImVec4(0.45f, 0.90f, 0.55f, 1.0f);
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(col, "%s", vm_decoder_status_.c_str());
        ImGui::PopTextWrapPos();
    }
}

// ─── render_vm_hints_input ────────────────────────────────────────────────
//
// vm_abstract is entirely hint-driven (see VMConfig's class comment in
// vm_abstract_pass.h) — dispatcher location, VM-PC, dispatch topology, and
// architecture type are all static facts that must come from IDA/Ghidra.
// This widget renders:
//   - a big drag-and-drop / click-to-browse target for the hints JSON file
//     (same schema as the MCP `vm_abstract` tool's `hints_file` argument),
//   - a plain text input as a fallback for typing/pasting a path directly,
//   - a "recent files" dropdown so switching back to a previously-used
//     hints file doesn't require re-browsing,
//   - the primary run/rerun button (label/width customizable by caller),
//   - a status line reporting load errors / success.
void GuiApp::render_vm_hints_input(const char* button_label, float button_width) {
    ImGui::TextWrapped(
        "Load static-analysis hints (dispatcher PC, handler entries, ...) "
        "from a JSON file — e.g. produced by IDA/Ghidra or the MCP "
        "vm_abstract tool's hints_file schema.");
    ImGui::Spacing();

    // ── Drag & drop / click-to-browse target ────────────────────────────
    // A visually distinct drop zone: dashed-look border box. Users can
    // either drag a .json file from Finder onto it, or click it to open
    // a native file picker (NSOpenPanel on macOS).
    const float dz_h = 52.0f;
    ImVec2 dz_pos = ImGui::GetCursorScreenPos();
    ImVec2 dz_size(ImGui::GetContentRegionAvail().x, dz_h);
    ImGui::InvisibleButton("##vm_hints_dropzone", dz_size);
    bool dz_hovered = ImGui::IsItemHovered();
    bool dz_clicked = ImGui::IsItemClicked();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 dz_bg = dz_hovered
        ? IM_COL32(40, 60, 90, 200)
        : IM_COL32(30, 32, 42, 160);
    ImU32 dz_border = dz_hovered
        ? IM_COL32(90, 160, 230, 255)
        : IM_COL32(90, 90, 110, 200);
    dl->AddRectFilled(dz_pos, ImVec2(dz_pos.x + dz_size.x, dz_pos.y + dz_size.y),
                       dz_bg, 6.0f);
    dl->AddRect(dz_pos, ImVec2(dz_pos.x + dz_size.x, dz_pos.y + dz_size.y),
                dz_border, 6.0f, 0, 1.5f);

    const char* dz_text = vm_hints_path_buf_[0] != '\0'
        ? vm_hints_path_buf_
        : ICON_FA_FILE_ARROW_UP "  Drag & drop a hints .json file here, or click to browse";
    ImVec2 txt_sz = ImGui::CalcTextSize(dz_text);
    // Clip long paths to the box width instead of overflowing.
    ImVec2 txt_pos(dz_pos.x + (dz_size.x - txt_sz.x) * 0.5f,
                    dz_pos.y + (dz_size.y - txt_sz.y) * 0.5f);
    if (txt_pos.x < dz_pos.x + 8.0f) txt_pos.x = dz_pos.x + 8.0f;
    ImVec4 txt_col = vm_hints_path_buf_[0] != '\0'
        ? ImVec4(0.75f, 0.90f, 1.0f, 1.0f)
        : ImVec4(0.65f, 0.65f, 0.72f, 1.0f);
    dl->PushClipRect(dz_pos, ImVec2(dz_pos.x + dz_size.x, dz_pos.y + dz_size.y), true);
    dl->AddText(txt_pos, ImGui::GetColorU32(txt_col), dz_text);
    dl->PopClipRect();

    if (dz_hovered) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(vm_hints_path_buf_[0] != '\0'
            ? "Click to choose a different hints file"
            : "Click to browse for a hints .json file");
    }

    if (dz_clicked) {
        std::string picked = pick_file_path(
            "Choose a VM hints JSON file", {"json"});
        if (!picked.empty()) {
            std::snprintf(vm_hints_path_buf_, sizeof(vm_hints_path_buf_),
                          "%s", picked.c_str());
            vm_hints_status_.clear();
        }
    }

    // Consume a globally-dropped file while this widget is on screen. We
    // only claim it if the drop happened over our window (best-effort:
    // ImGui doesn't give per-widget native drop targeting, so any drop
    // while the hints UI is visible is treated as "for this field" — this
    // matches user intent in practice since it's the only drop target).
    if (std::string dropped = take_dropped_file_path(); !dropped.empty()) {
        std::snprintf(vm_hints_path_buf_, sizeof(vm_hints_path_buf_),
                      "%s", dropped.c_str());
        vm_hints_status_.clear();
    }

    ImGui::Spacing();

    // ── Fallback: plain text input for typing/pasting a path ───────────
    if (ImGui::TreeNodeEx("Type a path instead", ImGuiTreeNodeFlags_None)) {
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextWithHint("##vm_hints_path", "Path to hints .json file",
                                  vm_hints_path_buf_, sizeof(vm_hints_path_buf_));
        ImGui::TreePop();
    }

    // ── Recent hints files ───────────────────────────────────────────────
    if (!vm_hints_recent_.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled(ICON_FA_CLOCK_ROTATE_LEFT "  Recent:");
        for (size_t i = 0; i < vm_hints_recent_.size(); ++i) {
            const std::string& p = vm_hints_recent_[i];
            // Show just the filename to keep the row compact; full path in tooltip.
            size_t slash = p.find_last_of('/');
            std::string short_name = (slash == std::string::npos) ? p : p.substr(slash + 1);
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::SmallButton(short_name.c_str())) {
                std::snprintf(vm_hints_path_buf_, sizeof(vm_hints_path_buf_),
                              "%s", p.c_str());
                vm_hints_status_.clear();
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", p.c_str());
            ImGui::PopID();
        }
    }

    ImGui::Spacing();

    bool can_run = vm_hints_path_buf_[0] != '\0';

    ImGui::BeginDisabled(!can_run);
    if (ImGui::Button(button_label, ImVec2(button_width, 0))) {
        run_vm_abstract_with_hints();
        push_vm_hints_recent(vm_hints_path_buf_);
    }
    ImGui::EndDisabled();
    if (!can_run && ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Load a hints file first.");
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(
            "Requires: loop + cfg + xref passes.\n"
            "They will run automatically if not yet completed.");
    }

    if (!vm_hints_status_.empty()) {
        ImGui::Spacing();
        // Color the status line by outcome so a failed/empty detection
        // (e.g. "0 handlers") is visually distinct from a real success —
        // the status text itself is tagged with an icon prefix by
        // run_vm_abstract_with_hints() (warning/error/check/spinner).
        ImVec4 col(0.85f, 0.85f, 0.85f, 1.0f);
        if (vm_hints_status_.rfind(ICON_FA_TRIANGLE_EXCLAMATION, 0) == 0)
            col = ImVec4(1.0f, 0.80f, 0.30f, 1.0f);       // warning: empty/no-VM result
        else if (vm_hints_status_.rfind(ICON_FA_CIRCLE_XMARK, 0) == 0)
            col = ImVec4(0.95f, 0.40f, 0.40f, 1.0f);       // error: pass failed / bad file
        else if (vm_hints_status_.rfind(ICON_FA_CIRCLE_CHECK, 0) == 0)
            col = ImVec4(0.45f, 0.90f, 0.55f, 1.0f);       // success
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(col, "%s", vm_hints_status_.c_str());
        ImGui::PopTextWrapPos();
    }
}

// ─── render_vm_hints_popup ───────────────────────────────────────────────────
// The shallow entry point for VM Abstract, opened directly from the main
// toolbar's "VM Hints..." / "VM Workspace" button group. This avoids the
// old flow of: Analysis menu > Reverse Eng / VM > VM Abstract Analysis >
// (find the collapsed "VM Hints" header) > load hints > Run > Open Workspace.
//
// Instead: toolbar click → this popup → load hints (drag/drop or browse) →
// Run → "Open VM Workspace" appears right here once a result exists.
void GuiApp::render_vm_hints_popup() {
    ImGui::SetNextWindowSize(ImVec2(460, 0), ImGuiCond_FirstUseEver);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse;

    if (!ImGui::Begin(ICON_FA_MICROCHIP "  VM Hints##vm_hints_popup",
                      &show_vm_hints_popup_, flags)) {
        ImGui::End();
        return;
    }

    if (vm_abstract_result_) {
        const auto& d = vm_abstract_result_->dispatcher;
        bool detected = (d.loop_header_pc != 0 || !vm_abstract_result_->handlers.empty());
        if (detected) {
            ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f),
                ICON_FA_CIRCLE_CHECK "  VM Detected — %zu handlers, %llu steps",
                vm_abstract_result_->handlers.size(),
                (unsigned long long)vm_abstract_result_->total_vm_steps);
        } else {
            ImGui::TextColored(ImVec4(0.75f, 0.75f, 0.75f, 1.0f),
                ICON_FA_CIRCLE_XMARK "  Ran, but no VM dispatcher found");
        }
        ImGui::Spacing();
        if (ImGui::Button(ICON_FA_UP_RIGHT_FROM_SQUARE "  Open VM Workspace",
                          ImVec2(-1, 0))) {
            vm_ws_open_          = true;
            vm_ws_first_frame_   = true;
            show_vm_hints_popup_ = false;
        }
        ImGui::Separator();
        ImGui::Spacing();
    }

    render_vm_hints_input(ICON_FA_PLAY "  Run VM Detection", -1.0f);

    // ── Decoder section (collapsible) ────────────────────────────────
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    if (ImGui::CollapsingHeader(ICON_FA_CODE "  Bytecode Decoder",
                                 ImGuiTreeNodeFlags_DefaultOpen)) {
        render_vm_decoder_input();
    }

    ImGui::End();
}

// ─── render_vm_abstract_panel (legacy single-panel) ─────────────────────────
// Retained for backward compatibility / the old "VM Abstract" dock tab.
// When the VM Workspace is open this is redundant, but both can coexist.

void GuiApp::render_vm_abstract_panel() {
    if (!ImGui::Begin("VM Abstract" ICON_FA_MICROCHIP "##VMPanel",
                      &show_vm_abstract_)) {
        ImGui::End(); return;
    }

    const float panel_w = ImGui::GetContentRegionAvail().x;

    if (!vm_abstract_result_) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.3f, 1.0f),
            ICON_FA_MICROCHIP "  VM Abstract Analysis");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Detects VM dispatchers (OLLVM / VMP / interpreter loops), "
            "extracts handler sets, and reconstructs the high-level bytecode "
            "execution trace.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        render_vm_hints_input(ICON_FA_PLAY "  Run VM Detection", panel_w * 0.55f);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::End(); return;
    }

    const auto& vm   = *vm_abstract_result_;
    uint64_t   slide = reader_.header().module_slide;
    const auto& d    = vm.dispatcher;
    bool detected    = (d.loop_header_pc != 0 || !vm.handlers.empty());

    // Status row
    if (detected) {
        ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f),
            ICON_FA_CIRCLE_CHECK "  VM Detected");
    } else {
        ImGui::TextColored(ImVec4(0.75f, 0.75f, 0.75f, 1.0f),
            ICON_FA_CIRCLE_XMARK "  No VM dispatcher found");
    }
    ImGui::SameLine(panel_w - 170.0f);
    if (ImGui::SmallButton(ICON_FA_UP_RIGHT_FROM_SQUARE " Open Workspace")) {
        vm_ws_open_        = true;
        vm_ws_first_frame_ = true;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Open full VM Workspace (IDA-style layout)");

    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        run_vm_abstract_with_hints();
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Re-run with the currently loaded hints file / auto-detect setting.");
    }
    ImGui::Separator();

    // Hints file input (collapsed by default once a result exists, so the
    // user can update hints and rerun without losing the result view).
    if (ImGui::CollapsingHeader(ICON_FA_FILE_LINES "  VM Hints")) {
        render_vm_hints_input(ICON_FA_ARROW_ROTATE_LEFT "  Rerun with hints", panel_w * 0.55f);
        ImGui::Separator();
    }

    // Quick summary table
    if (detected && d.loop_header_pc != 0) {
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(6, 2));
        if (ImGui::BeginTable("DispatcherInfo", 2,
                ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoPadOuterX)) {
            ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

            auto row = [&](const char* label, const char* value) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextDisabled("%s", label);
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(value);
            };
            char buf[64];
            snprintf(buf, sizeof(buf), "%s  (%.0f%%)",
                     dispatch_type_name(d.dispatch_type), d.confidence * 100.0f);
            row("Dispatch type:", buf);
            snprintf(buf, sizeof(buf), "0x%llx",
                     (unsigned long long)(d.loop_header_pc - slide));
            row("Loop header:", buf);
            snprintf(buf, sizeof(buf), "%llu iterations  ·  %zu handlers",
                     (unsigned long long)d.iteration_count, vm.handlers.size());
            row("Activity:", buf);
            snprintf(buf, sizeof(buf), "%llu VM steps",
                     (unsigned long long)vm.total_vm_steps);
            row("VM steps:", buf);

            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
        ImGui::Separator();
    }

    // Minimal handler list (compact, no full workspace needed)
    ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f),
        ICON_FA_CUBES "  Handlers (%zu)", vm.handlers.size());

    float list_h = ImGui::GetContentRegionAvail().y - 4.0f;
    if (ImGui::BeginTable("hl_compact", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.0f, list_h))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",          ImGuiTableColumnFlags_WidthFixed, 32.0f);
        ImGui::TableSetupColumn("Entry PC",   ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Label",      ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Opcode(s)",  ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableHeadersRow();

        // Sort by freq
        std::vector<size_t> idx(vm.handlers.size());
        std::iota(idx.begin(), idx.end(), 0);
        std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
            return vm.handlers[a].execution_count > vm.handlers[b].execution_count;
        });

        ImGuiListClipper cl; cl.Begin(static_cast<int>(idx.size()));
        while (cl.Step()) {
            for (int row = cl.DisplayStart; row < cl.DisplayEnd; ++row) {
                const auto& h = vm.handlers[idx[static_cast<size_t>(row)]];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("%d", row + 1);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("0x%llx",
                    (unsigned long long)(h.entry_pc - slide));
                ImGui::TableSetColumnIndex(2);
                if (!h.label.empty())
                    ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.45f, 1.0f),
                        "%s", h.label.c_str());
                else
                    ImGui::TextDisabled("handler_%llx",
                        (unsigned long long)(h.entry_pc - slide));
                ImGui::TableSetColumnIndex(3);
                if (!h.opcode_values.empty()) {
                    ImGui::TextColored(ImVec4(0.55f, 0.90f, 0.70f, 1.0f),
                        "%llu", (unsigned long long)h.opcode_values.front());
                } else {
                    ImGui::TextDisabled("-");
                }
            }
        }
        cl.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

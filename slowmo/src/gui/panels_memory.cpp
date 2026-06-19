// panels_memory.cpp — memory access panel, hex dump panel, memory context menu,
// and open_hex_dump_at helper.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/xref_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <cstring>
#include <string>

namespace tenet {

// ─── Open hex dump at address ────────────────────────────────────────────────

void GuiApp::open_hex_dump_at(uint64_t addr) {
    show_hex_dump_ = true;
    // Store the address for hex dump to display
    // We'll use the hex_dump_addr_ field (to be shown in render_hex_dump_panel)
    // For now, re-purpose ctx_mem_addr_ as the hex dump target
    ctx_mem_addr_ = addr;
}

// ─── Memory Panel ───────────────────────────────────────────────────────────

void GuiApp::render_memory_panel() {
    if (!ImGui::Begin("Memory Accesses", &show_memory_)) {
        ImGui::End();
        return;
    }

    auto [offset, seed_pc_mem] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec = reader_.record_at(offset, seed_pc_mem);
    if (rec.kind != RecordKind::Inst) {
        ImGui::TextDisabled("(no instruction)");
        ImGui::End();
        return;
    }

    auto inst = rec.as_inst();
    if (inst.mem_access_count == 0) {
        ImGui::TextDisabled("(no memory access)");
        ImGui::End();
        return;
    }

    // Hint text
    ImGui::TextDisabled("Double-click addr to open Hex Dump  |  Right-click for menu");
    ImGui::Separator();

    for (uint8_t i = 0; i < inst.mem_access_count; i++) {
        auto mem = inst.mem_access(i);
        bool is_write = (mem.type & 2) != 0;

        ImVec4 type_color = is_write ? ImVec4(1.0f, 0.3f, 0.3f, 1.0f)
                                     : ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        const char* type_label = is_write ? "WRITE" : "READ ";

        ImGui::TextColored(type_color, "%s", type_label);
        ImGui::SameLine();

        // ── Clickable address ──────────────────────────────────────
        char addr_label[48];
        snprintf(addr_label, sizeof(addr_label), "0x%016llx##memaddr%u",
                 (unsigned long long)mem.addr, i);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
        ImGui::Text("addr=");
        ImGui::SameLine(0, 0);

        // Use Selectable for click/double-click handling
        char sel_label[64];
        snprintf(sel_label, sizeof(sel_label), "0x%016llx##memsel%u",
                 (unsigned long long)mem.addr, i);
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
        if (ImGui::Selectable(sel_label, false,
                ImGuiSelectableFlags_AllowDoubleClick |
                ImGuiSelectableFlags_AllowOverlap,
                ImVec2(0, 0))) {
            // Single click: select (no action yet)
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Double-click: open in Hex Dump\nRight-click: context menu");
            if (ImGui::IsMouseDoubleClicked(0)) {
                open_hex_dump_at(mem.addr);
            }
        }
        if (ImGui::BeginPopupContextItem(nullptr)) {
            ctx_mem_addr_    = mem.addr;
            ctx_mem_inst_id_ = current_inst_;
            ImGui::TextDisabled("addr: 0x%016llx", (unsigned long long)mem.addr);
            ImGui::Separator();
            if (ImGui::MenuItem("Open in Hex Dump")) {
                open_hex_dump_at(mem.addr);
            }
            if (ImGui::MenuItem("Copy Address")) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mem.addr);
                ImGui::SetClipboardText(buf);
            }
            if (mem.size <= 8) {
                if (ImGui::MenuItem("Copy Value")) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mem.value);
                    ImGui::SetClipboardText(buf);
                }
            }
            ImGui::EndPopup();
        }
        ImGui::PopStyleColor();

        ImGui::SameLine();
        ImGui::Text("  size=%u", mem.size);

        if (mem.size <= 8) {
            ImGui::TextDisabled("  val =");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                "0x%016llx", (unsigned long long)mem.value);
        } else {
            ImGui::TextDisabled("  lo  =");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                "0x%016llx", (unsigned long long)mem.value);
            ImGui::TextDisabled("  hi  =");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                "0x%016llx", (unsigned long long)mem.value_hi);
        }

        // Hex bytes
        {
            uint8_t bytes[16];
            std::memcpy(bytes, &mem.value, 8);
            std::memcpy(bytes + 8, &mem.value_hi, 8);
            size_t n = (mem.size <= 16) ? mem.size : 8;
            std::string hex_str = "  hex: ";
            for (size_t b = 0; b < n; b++) {
                hex_str += fmt::format("{:02x} ", bytes[b]);
            }
            ImGui::TextDisabled("%s", hex_str.c_str());
        }

        // Quick action button: "Open in Hex Dump"
        ImGui::SameLine();
        char btn_label[32];
        snprintf(btn_label, sizeof(btn_label), "[Hex]##hd%u", i);
        if (ImGui::SmallButton(btn_label)) {
            open_hex_dump_at(mem.addr);
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Open address 0x%llx in Hex Dump",
                              (unsigned long long)mem.addr);
        }

        if (i + 1 < inst.mem_access_count) {
            ImGui::Separator();
        }
    }

    // Render context menu if requested
    render_mem_context_menu();

    ImGui::End();
}

// ─── Hex Dump Panel ─────────────────────────────────────────────────────────

void GuiApp::render_hex_dump_panel() {
    if (!ImGui::Begin("Hex Dump", &show_hex_dump_)) {
        ImGui::End();
        return;
    }

    // Determine which address to display:
    // 1) If ctx_mem_addr_ was set (via open_hex_dump_at), use that
    // 2) Otherwise use the first memory access of current instruction
    uint64_t display_addr = 0;
    bool has_addr = false;

    if (ctx_mem_addr_ != 0) {
        display_addr = ctx_mem_addr_;
        has_addr = true;
    } else {
        auto [offset, seed_pc_da] = index_.offset_of_with_pc(current_inst_, reader_);
        auto rec = reader_.record_at(offset, seed_pc_da);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            if (inst.mem_access_count > 0) {
                display_addr = inst.mem_access(0).addr;
                has_addr = true;
            }
        }
    }

    // Header with address input
    ImGui::Text("Jump to Address:");
    ImGui::SameLine();
    static char hex_addr_buf[32] = {};
    ImGui::SetNextItemWidth(160.0f);
    if (ImGui::InputText("##hexaddr", hex_addr_buf, sizeof(hex_addr_buf),
            ImGuiInputTextFlags_EnterReturnsTrue |
            ImGuiInputTextFlags_CharsHexadecimal)) {
        try {
            uint64_t addr = std::stoull(hex_addr_buf, nullptr, 16);
            display_addr = addr;
            ctx_mem_addr_ = addr;
            has_addr = true;
        } catch (...) {}
    }
    ImGui::SameLine();
    if (ImGui::Button("From Inst")) {
        // Reset to follow current instruction's memory access
        ctx_mem_addr_ = 0;
        std::memset(hex_addr_buf, 0, sizeof(hex_addr_buf));
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Show hex dump for current instruction's memory access");
    }

    if (!has_addr) {
        ImGui::Separator();
        ImGui::TextDisabled("(no memory access — enter an address above, or navigate to an instruction with memory access)");
        ImGui::End();
        return;
    }

    ImGui::Separator();
    ImGui::Text("Address: 0x%016llx", (unsigned long long)display_addr);

    uint64_t base_addr = display_addr & ~0xFULL;  // Align to 16 bytes

    // Get memory bytes from MemoryModel
    // We display 16 rows × 16 bytes
    const int kRows = 16;
    ImGui::Separator();

    // Column header
    ImGui::TextDisabled("           Address           | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII");
    ImGui::Separator();

    for (int row = -2; row < kRows - 2; row++) {
        uint64_t row_addr = base_addr + static_cast<uint64_t>(row) * 16;
        bool is_active_row = (display_addr >= row_addr && display_addr < row_addr + 16);

        // Address
        if (is_active_row) {
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f),
                "0x%016llx:", (unsigned long long)row_addr);
        } else {
            ImGui::TextDisabled("0x%016llx:", (unsigned long long)row_addr);
        }
        ImGui::SameLine();

        // Hex bytes — each byte is individually clickable
        for (int b = 0; b < 16; b++) {
            uint64_t byte_addr = row_addr + b;
            auto byte_val = memory_.byte_at(byte_addr, current_inst_);

            bool is_highlighted = (byte_addr == display_addr);

            if (b == 8) {
                ImGui::SameLine(0, 0);
                ImGui::TextDisabled(" ");
            }
            if (b > 0) ImGui::SameLine(0, 0);

            char byte_str[8];
            if (byte_val.has_value()) {
                snprintf(byte_str, sizeof(byte_str), "%02x ", *byte_val);
            } else {
                snprintf(byte_str, sizeof(byte_str), "?? ");
            }

            // Push unique ID for each byte so ImGui can track them
            ImGui::PushID(static_cast<int>(row * 16 + b));

            if (is_highlighted) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", byte_str);
            } else if (is_active_row) {
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "%s", byte_str);
            } else {
                ImGui::TextDisabled("%s", byte_str);
            }

            // Double-click: jump to the instruction that last wrote this byte
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                uint64_t writer = memory_.last_writer(byte_addr, 1, current_inst_);
                if (writer > 0) {
                    navigate_to(writer);
                }
            }
            // Single-click: update display address to this byte
            if (ImGui::IsItemClicked()) {
                display_addr = byte_addr;
                ctx_mem_addr_ = byte_addr;
            }
            // Tooltip on hover
            if (ImGui::IsItemHovered()) {
                uint64_t writer = memory_.last_writer(byte_addr, 1, current_inst_);
                if (writer > 0) {
                    ImGui::SetTooltip("0x%llx: last written by inst #%llu\nDouble-click to jump",
                        (unsigned long long)byte_addr, (unsigned long long)writer);
                } else {
                    ImGui::SetTooltip("0x%llx: no known writer",
                        (unsigned long long)byte_addr);
                }
            }

            ImGui::PopID();
        }

        // ASCII part
        ImGui::SameLine();
        char ascii_part[20] = {};
        for (int b = 0; b < 16; b++) {
            uint64_t byte_addr = row_addr + b;
            auto byte_val = memory_.byte_at(byte_addr, current_inst_);
            if (byte_val.has_value()) {
                uint8_t v = *byte_val;
                ascii_part[b] = (v >= 0x20 && v < 0x7F) ? static_cast<char>(v) : '.';
            } else {
                ascii_part[b] = '?';
            }
        }
        ascii_part[16] = '\0';
        ImGui::TextDisabled("| %s", ascii_part);
    }

    ImGui::Separator();
    ImGui::TextDisabled("Click: select byte  |  Double-click: jump to writer  |  'From Inst': follow current instruction");

    ImGui::End();
}

// ─── Context menu helpers (memory) ──────────────────────────────────────────

void GuiApp::render_mem_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_memory_panel().
    if (ImGui::BeginPopup("##mem_ctx")) {
        ImGui::TextDisabled("addr: 0x%016llx", (unsigned long long)ctx_mem_addr_);
        ImGui::Separator();
        if (ImGui::MenuItem("Open in Hex Dump")) {
            open_hex_dump_at(ctx_mem_addr_);
        }
        if (ImGui::MenuItem("Copy Address")) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_mem_addr_);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Goto Instruction")) {
            navigate_to(ctx_mem_inst_id_);
        }
        if (xref_result_) {
            ImGui::Separator();
            // Show how many times this address was accessed
            auto row = fetch_row(ctx_mem_inst_id_);
            auto count = xref_result_->execution_count(row.pc);
            if (count > 0) {
                ImGui::TextDisabled("PC executed %llu times", (unsigned long long)count);
                if (ImGui::MenuItem("Next Xref (x)")) {
                    auto xrefs = xref_result_->inst_ids_at(row.pc);
                    if (!xrefs.empty()) {
                        xref_cursor_++;
                        if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
                        navigate_to(xrefs[xref_cursor_]);
                    }
                }
            }
        }
        ImGui::EndPopup();
    }
}

}  // namespace tenet

// panels_memory_strings.cpp — Time-aware memory string discovery panel.
//
// Displays the MemoryStringResult from MemoryStringPass in a scrollable table
// with view-mode filtering (All / RegPointer / StackLocal) and content search.
// Each row is navigable: clicking the inst_id column jumps the trace cursor to
// the instruction at which the string was discovered.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/memory_string_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>

namespace tenet {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static const char* source_reg_name(uint8_t r) {
    static const char* kGprNames[8] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"
    };
    if (r < 8)  return kGprNames[r];
    if (r == 31) return "sp";
    return "";
}

static const char* encoding_name(MemoryString::Encoding enc) {
    switch (enc) {
        case MemoryString::ASCII:   return "ASCII";
        case MemoryString::UTF8:    return "UTF-8";
        case MemoryString::UTF16LE: return "UTF-16LE";
        default:                    return "?";
    }
}

static const char* source_label(MemoryString::Source src) {
    switch (src) {
        case MemoryString::RegPointer: return "Reg";
        case MemoryString::StackLocal: return "Stack";
        case MemoryString::DeepProbe:  return "Deep";
        case MemoryString::PageScan:   return "Page";
        default:                       return "?";
    }
}

// ---------------------------------------------------------------------------
// Panel renderer
// ---------------------------------------------------------------------------

void GuiApp::render_memory_strings_panel() {
    if (!ImGui::Begin("Memory Strings", &show_mem_strings_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!mem_string_result_) {
        ImGui::TextDisabled("No memory string analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Memory Strings")) {
            run_pass_by_name("memory_strings");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Scan memory for strings referenced or written during execution.\n"
                "Finds ASCII / UTF-8 / UTF-16LE strings via register pointers,\n"
                "stack locals, deep probes, and page scans.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        "\xe2\x8c\x95  %zu strings  |  %zu unique",   // ⌕ U+2315 (was fa-font U+F0C2 PUA)
        mem_string_result_->total(),
        mem_string_result_->unique_count());

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {   // ↺
        run_pass_by_name("memory_strings");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run memory string discovery (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ───────────────────────────────────────────────────
    ImGui::RadioButton("All",        &mem_string_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("RegPointer", &mem_string_view_mode_, 1);
    ImGui::SameLine();
    ImGui::RadioButton("StackLocal", &mem_string_view_mode_, 2);

    ImGui::Separator();

    // ── Search / filter ────────────────────────────────────────────────────
    ImGui::PushItemWidth(panel_w * 0.55f);
    if (ImGui::InputText("Filter##msf", mem_string_filter_buf_,
                         sizeof(mem_string_filter_buf_))) {
        mem_string_filter_ = mem_string_filter_buf_;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine(0, 6);
    if (ImGui::SmallButton("x##msclr")) {
        std::memset(mem_string_filter_buf_, 0, sizeof(mem_string_filter_buf_));
        mem_string_filter_.clear();
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filter");

    // ── Build filtered index list ──────────────────────────────────────────
    const auto& strings = mem_string_result_->strings;
    std::vector<size_t> filtered;
    filtered.reserve(strings.size());

    for (size_t i = 0; i < strings.size(); ++i) {
        const MemoryString& ms = strings[i];

        // View-mode filter
        if (mem_string_view_mode_ == 1 && ms.source != MemoryString::RegPointer)
            continue;
        if (mem_string_view_mode_ == 2 && ms.source != MemoryString::StackLocal)
            continue;

        // Content substring filter
        if (!mem_string_filter_.empty()) {
            if (ms.content.find(mem_string_filter_) == std::string::npos)
                continue;
        }

        filtered.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu / %zu", filtered.size(), strings.size());
    ImGui::Separator();

    // ── Main table ─────────────────────────────────────────────────────────
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("MemStrTable", 5,
            ImGuiTableFlags_Resizable    | ImGuiTableFlags_RowBg         |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY      |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed,   55.0f);
        ImGui::TableSetupColumn("Content", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Source",  ImGuiTableColumnFlags_WidthFixed,   60.0f);
        ImGui::TableSetupColumn("Addr",    ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("PC",      ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t idx = filtered[static_cast<size_t>(row)];
                const MemoryString& ms = strings[idx];

                ImGui::TableNextRow();

                // ── # (inst_id) — Selectable, navigates on click ──────────
                ImGui::TableSetColumnIndex(0);
                char id_label[32];
                snprintf(id_label, sizeof(id_label), "#%llu##ms%zu",
                         (unsigned long long)ms.discovered_at, idx);
                if (ImGui::Selectable(id_label, false,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    navigate_to(ms.discovered_at);
                }

                // Hover tooltip — full info
                if (ImGui::IsItemHovered()) {
                    const char* reg_name = source_reg_name(ms.source_reg);
                    std::string tip = fmt::format(
                        "Content: \"{}\"\n"
                        "Addr:    0x{:x}\n"
                        "Encoding: {}\n"
                        "Source:  {} {}",
                        ms.content,
                        ms.addr,
                        encoding_name(ms.encoding),
                        source_label(ms.source),
                        reg_name[0] ? reg_name : "(unknown)");
                    if (ms.call_site_pc != 0) {
                        tip += fmt::format("\nCall site PC: 0x{:x}",
                            ms.call_site_pc - reader_.header().module_slide);
                    }
                    tip += "\n\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());

                    if (ImGui::IsMouseDoubleClicked(0))
                        navigate_to(ms.discovered_at);
                }

                // ── Right-click context menu ───────────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    // Show truncated content as title
                    if (ms.content.size() <= 40)
                        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f),
                                           "\"%s\"", ms.content.c_str());
                    else
                        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f),
                                           "\"%.40s\xe2\x80\xa6\"", ms.content.c_str());
                    ImGui::TextDisabled("inst #%llu",
                                        (unsigned long long)ms.discovered_at);
                    ImGui::Separator();
                    if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions")) {
                        navigate_to_instructions(ms.discovered_at);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)ms.discovered_at);
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy String Content")) {
                        ImGui::SetClipboardText(ms.content.c_str());
                    }
                    if (ImGui::MenuItem("Copy Address")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)ms.addr);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // ── Content — truncated to 80 chars, yellow ───────────────
                ImGui::TableSetColumnIndex(1);
                if (ms.content.size() <= 80) {
                    ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f),
                                       "\"%s\"", ms.content.c_str());
                } else {
                    std::string truncated = ms.content.substr(0, 80) + "…";
                    ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f),
                                       "\"%s\"", truncated.c_str());
                }

                // ── Source — label + register name ────────────────────────
                ImGui::TableSetColumnIndex(2);
                {
                    const char* src  = source_label(ms.source);
                    const char* regn = source_reg_name(ms.source_reg);
                    if (regn[0])
                        ImGui::Text("%s/%s", src, regn);
                    else
                        ImGui::Text("%s", src);
                }

                // ── Addr — grey hex ───────────────────────────────────────
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("0x%llx", (unsigned long long)ms.addr);

                // ── PC (call_site_pc - slide) — grey hex ──────────────────
                ImGui::TableSetColumnIndex(4);
                if (ms.call_site_pc != 0) {
                    ImGui::TextDisabled("0x%llx",
                        (unsigned long long)(ms.call_site_pc -
                                             reader_.header().module_slide));
                } else {
                    ImGui::TextDisabled("—");
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

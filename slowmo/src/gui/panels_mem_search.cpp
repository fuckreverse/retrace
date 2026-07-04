// panels_mem_search.cpp — Memory/value byte-pattern search panel.
//
// Independent floating window for MemSearchPass.
// Two complementary search modes:
//   1. Byte-pattern search: hex bytes with optional wildcards (??)
//   2. Exact-value search: scalar values against reg/mem/immediate
//
// Split out of panels_analysis.cpp. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/memory/mem_search_pass.h"
#include "analysis/pass_registry.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static const char* source_str(MemSearchMatch::Source src) {
    switch (src) {
        case MemSearchMatch::MemWrite:  return "Mem";
        case MemSearchMatch::RegDiff:   return "Reg";
        case MemSearchMatch::Immediate: return "Imm";
        default:                        return "?";
    }
}

static ImVec4 source_color(MemSearchMatch::Source src) {
    switch (src) {
        case MemSearchMatch::MemWrite:  return ImVec4(0.75f, 0.55f, 1.0f, 1.0f);  // purple
        case MemSearchMatch::RegDiff:   return ImVec4(0.4f, 0.9f, 0.4f, 1.0f);   // green
        case MemSearchMatch::Immediate: return ImVec4(1.0f, 0.85f, 0.3f, 1.0f);  // yellow
        default:                        return ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
    }
}

/// Parse a hex byte string like "01 23 AB ?? CD" into bytes+mask.
/// Returns false on parse error.
static bool parse_hex_pattern(const char* buf,
                               std::vector<uint8_t>& out_bytes,
                               std::vector<uint8_t>& out_mask) {
    out_bytes.clear();
    out_mask.clear();
    std::string s(buf);
    std::string token;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == ' ' || s[i] == '\t') {
            if (token.empty()) continue;
            if (token == "??" || token == "**") {
                out_bytes.push_back(0x00);
                out_mask.push_back(0xFF);  // wildcard
            } else if (token.size() == 2) {
                char* end = nullptr;
                unsigned long val = strtoul(token.c_str(), &end, 16);
                if (!end || *end != '\0' || val > 255) return false;
                out_bytes.push_back(static_cast<uint8_t>(val));
                out_mask.push_back(0x00);  // exact
            } else {
                return false;
            }
            token.clear();
        } else {
            token += static_cast<char>(toupper(static_cast<unsigned char>(s[i])));
        }
    }
    return !out_bytes.empty();
}

// ---------------------------------------------------------------------------
// Run helper
// ---------------------------------------------------------------------------

void GuiApp::run_mem_search_with_params() {
    ensure_pass_manager();

    MemSearchConfig cfg;

    // Byte-pattern mode
    if (mem_search_pattern_buf_[0] != '\0') {
        std::vector<uint8_t> bytes, mask;
        if (parse_hex_pattern(mem_search_pattern_buf_, bytes, mask)) {
            MemSearchConfig::Pattern pat;
            pat.bytes = std::move(bytes);
            pat.mask  = std::move(mask);
            pat.label = mem_search_pattern_label_[0] ? mem_search_pattern_label_ : "pat0";
            cfg.patterns.push_back(std::move(pat));
        }
    }

    // Exact-value mode
    if (mem_search_exact_buf_[0] != '\0') {
        try {
            std::string s(mem_search_exact_buf_);
            // Strip optional "0x" prefix
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                s = s.substr(2);
            uint64_t val = std::stoull(s, nullptr, 16);
            cfg.exact_values.push_back(val);
        } catch (...) {}
    }

    cfg.match_32bit     = mem_search_match_32bit_;
    cfg.search_mem_writes = mem_search_search_mem_;
    cfg.search_reg_values = mem_search_search_reg_;
    cfg.search_immediates = mem_search_search_imm_;

    // Invalidate previous result
    if (pass_manager_->state("mem_search") != PassManager::PassState::NotRun) {
        pass_manager_->invalidate_and_clear_blob("mem_search");
    }
    pass_manager_->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    mem_search_result_ = nullptr;

    std::string name_str = "mem_search";
    enqueue_async(name_str, [this, name_str]() {
        auto& raw = pass_manager_->require(name_str);
        std::string summary = tenet::summarize_pass_result(name_str, raw);
        bool ok = raw.ok();
        post_apply([this, name_str, summary, ok]() {
            last_pass_status_ = fmt::format("{}: {}", name_str, summary);
            if (ok) apply_pass_result_pointers(name_str);
        });
    });
}

// ---------------------------------------------------------------------------
// Panel renderer
// ---------------------------------------------------------------------------

void GuiApp::render_mem_search_panel() {
    if (!ImGui::Begin("Memory Search", &show_mem_search_)) {
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── No result yet — show parameter form ───────────────────────────
    if (!mem_search_result_) {
        ImGui::TextDisabled(ICON_FA_MAGNIFYING_GLASS "  Memory / Value Search");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Search for byte patterns or exact scalar values across memory\n"
            "writes, register diffs, and MOVZ/MOVK immediates.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── Byte-pattern input ────────────────────────────────────────
        ImGui::Text("Byte Pattern (hex, use ?? for wildcard):");
        ImGui::PushItemWidth(panel_w * 0.85f);
        ImGui::InputText("##ms_pat", mem_search_pattern_buf_,
            sizeof(mem_search_pattern_buf_),
            ImGuiInputTextFlags_CharsHexadecimal |
            ImGuiInputTextFlags_CharsUppercase);
        ImGui::PopItemWidth();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Example: 01 23 ?? AB  (?? = wildcard byte)");

        ImGui::SameLine(0, 4);
        if (ImGui::SmallButton("x##ms_pat_clr")) {
            std::memset(mem_search_pattern_buf_, 0, sizeof(mem_search_pattern_buf_));
        }

        // Label
        ImGui::PushItemWidth(panel_w * 0.45f);
        ImGui::InputText("Label##ms_lbl", mem_search_pattern_label_,
            sizeof(mem_search_pattern_label_));
        ImGui::PopItemWidth();

        ImGui::Spacing();

        // ── Exact-value input ─────────────────────────────────────────
        ImGui::Text("Exact Value (hex):");
        ImGui::PushItemWidth(panel_w * 0.45f);
        ImGui::InputText("##ms_exact", mem_search_exact_buf_,
            sizeof(mem_search_exact_buf_),
            ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 4);
        if (ImGui::SmallButton("x##ms_ev_clr")) {
            std::memset(mem_search_exact_buf_, 0, sizeof(mem_search_exact_buf_));
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Clear exact value");

        ImGui::Checkbox("Also match 32-bit truncation", &mem_search_match_32bit_);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Match (value & 0xFFFFFFFF) as well");

        ImGui::Spacing();

        // ── Search scope ──────────────────────────────────────────────
        ImGui::Text("Search scope:");
        ImGui::Checkbox("Memory writes", &mem_search_search_mem_);
        ImGui::SameLine();
        ImGui::Checkbox("Register values", &mem_search_search_reg_);
        ImGui::SameLine();
        ImGui::Checkbox("Immediates (MOVZ/MOVK)", &mem_search_search_imm_);

        ImGui::Spacing();

        // ── Run button ───────────────────────────────────────────────
        bool has_input = (mem_search_pattern_buf_[0] != '\0' ||
                          mem_search_exact_buf_[0] != '\0');
        if (!has_input) ImGui::BeginDisabled();
        if (ImGui::Button(ICON_FA_MAGNIFYING_GLASS " Run Search") ) {
            run_mem_search_with_params();
        }
        if (!has_input) ImGui::EndDisabled();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Search the trace for the specified pattern or value");

        ImGui::End();
        return;
    }

    // ── Result available ──────────────────────────────────────────────

    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_MAGNIFYING_GLASS "  %zu matches  |  %llu bytes scanned  |  %llu instructions",
        mem_search_result_->matches.size(),
        (unsigned long long)mem_search_result_->bytes_scanned,
        (unsigned long long)mem_search_result_->instructions_scanned);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        mem_search_result_ = nullptr;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run search with different parameters");

    ImGui::Separator();

    // ── View-mode filter ─────────────────────────────────────────────
    ImGui::RadioButton("All",        &mem_search_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("MemWrite",   &mem_search_view_mode_, 1);
    ImGui::SameLine();
    ImGui::RadioButton("RegDiff",    &mem_search_view_mode_, 2);
    ImGui::SameLine();
    ImGui::RadioButton("Immediate",  &mem_search_view_mode_, 3);

    ImGui::Separator();

    // ── Build filtered index ──────────────────────────────────────────
    const auto& matches = mem_search_result_->matches;
    std::vector<size_t> filtered;
    filtered.reserve(matches.size());

    for (size_t i = 0; i < matches.size(); ++i) {
        const MemSearchMatch& m = matches[i];
        if (mem_search_view_mode_ == 1 && m.source != MemSearchMatch::MemWrite)  continue;
        if (mem_search_view_mode_ == 2 && m.source != MemSearchMatch::RegDiff)  continue;
        if (mem_search_view_mode_ == 3 && m.source != MemSearchMatch::Immediate) continue;
        filtered.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu / %zu", filtered.size(), matches.size());
    ImGui::Separator();

    // ── Results table ─────────────────────────────────────────────────
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("MemSearchTable", 6,
            ImGuiTableFlags_Resizable    | ImGuiTableFlags_RowBg         |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY      |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("inst#",   ImGuiTableColumnFlags_WidthFixed,  60.0f);
        ImGui::TableSetupColumn("PC",      ImGuiTableColumnFlags_WidthFixed,  90.0f);
        ImGui::TableSetupColumn("Source",  ImGuiTableColumnFlags_WidthFixed,  55.0f);
        ImGui::TableSetupColumn("Addr",    ImGuiTableColumnFlags_WidthFixed,  90.0f);
        ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed,  50.0f);
        ImGui::TableSetupColumn("Value",   ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t idx = filtered[static_cast<size_t>(row)];
                const MemSearchMatch& m = matches[idx];

                ImGui::TableNextRow();

                // inst# — selectable, navigates on click
                ImGui::TableSetColumnIndex(0);
                char id_label[32];
                snprintf(id_label, sizeof(id_label), "#%llu##ms%zu",
                         (unsigned long long)m.inst_id, idx);
                if (ImGui::Selectable(id_label, false,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    navigate_to(m.inst_id);
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("inst #%llu  |  PC: 0x%llx\n\nClick to navigate",
                        (unsigned long long)m.inst_id,
                        (unsigned long long)(m.pc - reader_.header().module_slide));
                }

                // PC (static)
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("0x%llx",
                    (unsigned long long)(m.pc - reader_.header().module_slide));

                // Source
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(source_color(m.source), "%s", source_str(m.source));

                // Addr
                ImGui::TableSetColumnIndex(3);
                if (m.addr != 0) {
                    ImGui::TextDisabled("0x%llx", (unsigned long long)m.addr);
                } else {
                    ImGui::TextDisabled("—");
                }

                // Offset
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%u", m.offset);

                // Value
                ImGui::TableSetColumnIndex(5);
                if (m.is_exact_value_match && m.matched_value != 0) {
                    ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f),
                        "0x%llx", (unsigned long long)m.matched_value);
                } else {
                    ImGui::TextDisabled("pat#%u", m.pattern_index);
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

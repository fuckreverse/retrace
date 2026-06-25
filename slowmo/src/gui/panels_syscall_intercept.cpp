// panels_syscall_intercept.cpp — iOS system API intercept results panel.
//
// Displays the SyscallInterceptResult from SyscallInterceptPass in two views:
//   1. All view:      scrollable table of every intercepted call with API name,
//                     summary, extracted key bytes, and ObjC context.
//   2. Crypto Only:   filtered to CommonCrypto / SecurityFramework / CryptoKit.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/syscall_intercept_pass.h"
#include <imgui.h>
#include <fmt/core.h>
#include <cstring>
#include <string>
#include <vector>

namespace tenet {

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return a display color for each ApiCategory.
static ImVec4 category_color(ApiCategory cat) {
    switch (cat) {
        case ApiCategory::CommonCrypto:
            return ImVec4(1.0f, 0.6f, 0.2f, 1.0f);   // orange
        case ApiCategory::SecurityFramework:
            return ImVec4(0.9f, 0.3f, 0.3f, 1.0f);   // red
        case ApiCategory::CryptoKit:
            return ImVec4(1.0f, 0.5f, 0.7f, 1.0f);   // pink
        case ApiCategory::Compression:
        case ApiCategory::CocoaFoundation:
        case ApiCategory::LibSystem:
        case ApiCategory::Custom:
        default:
            return ImVec4(0.55f, 0.75f, 0.95f, 1.0f); // blue-grey
    }
}

/// Return a short label for each ApiCategory.
static const char* category_label(ApiCategory cat) {
    switch (cat) {
        case ApiCategory::CommonCrypto:     return "CC";
        case ApiCategory::SecurityFramework:return "Sec";
        case ApiCategory::CryptoKit:        return "CKit";
        case ApiCategory::Compression:      return "Comp";
        case ApiCategory::CocoaFoundation:  return "Cocoa";
        case ApiCategory::LibSystem:        return "LibSys";
        case ApiCategory::Custom:           return "Custom";
        default:                            return "?";
    }
}

/// Render a hex dump of up to `max_bytes` from `data`, space-separated.
static std::string hex_dump(const std::vector<uint8_t>& data, size_t max_bytes) {
    std::string out;
    size_t n = std::min(data.size(), max_bytes);
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i > 0) out += ' ';
        char buf[4];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    if (data.size() > max_bytes)
        out += fmt::format(" (+{})", data.size() - max_bytes);
    return out;
}

/// Truncate `s` to at most `max_chars` characters, appending "…" if cut.
static std::string truncate(const std::string& s, size_t max_chars) {
    if (s.size() <= max_chars) return s;
    return s.substr(0, max_chars) + "\xe2\x80\xa6";   // U+2026 HORIZONTAL ELLIPSIS
}

/// True if `call` is a crypto-category call.
static bool is_crypto(const InterceptedCall& call) {
    return call.category == ApiCategory::CommonCrypto ||
           call.category == ApiCategory::SecurityFramework ||
           call.category == ApiCategory::CryptoKit;
}

// ── Main panel ────────────────────────────────────────────────────────────────

void GuiApp::render_syscall_intercept_panel() {
    if (!ImGui::Begin("API Intercepts", &show_syscall_intercept_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────────
    if (!syscall_result_) {
        ImGui::TextDisabled("No API intercept analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run API Intercept")) {
            run_pass_by_name("syscall_intercept");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Intercept and decode iOS system API calls in the trace.\n"
                              "Extracts crypto keys, IV, data lengths, and decoded summaries.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────────
    size_t crypto_count = 0;
    const auto& cc_it = syscall_result_->by_category.find(ApiCategory::CommonCrypto);
    if (cc_it != syscall_result_->by_category.end())
        crypto_count += cc_it->second.size();

    ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.25f, 1.0f),
        "\xef\xa3\xa8  %zu calls  |  %zu CommonCrypto",   // lock icon (PUA)
        syscall_result_->total(),
        crypto_count);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {  // ↺
        run_pass_by_name("syscall_intercept");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run API Intercept analysis (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ───────────────────────────────────────────────────────
    ImGui::RadioButton("All",         &syscall_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Crypto Only", &syscall_view_mode_, 1);

    ImGui::Separator();

    // ── Search filter ─────────────────────────────────────────────────────────
    ImGui::PushItemWidth(panel_w * 0.55f);
    if (ImGui::InputText("Filter##sysfilt", syscall_filter_buf_,
                         sizeof(syscall_filter_buf_))) {
        syscall_filter_ = syscall_filter_buf_;
        syscall_cursor_ = 0;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine(0, 6);
    if (ImGui::SmallButton("x##sysxfilt")) {
        std::memset(syscall_filter_buf_, 0, sizeof(syscall_filter_buf_));
        syscall_filter_.clear();
        syscall_cursor_ = 0;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filter");

    // ── Build filtered index list ──────────────────────────────────────────────
    std::vector<size_t> filtered;
    filtered.reserve(syscall_result_->calls.size());

    for (size_t i = 0; i < syscall_result_->calls.size(); ++i) {
        const InterceptedCall& c = syscall_result_->calls[i];

        // View-mode filter
        if (syscall_view_mode_ == 1 && !is_crypto(c))
            continue;

        // Text filter (callee_name or decoded_summary)
        if (!syscall_filter_.empty()) {
            bool in_name    = c.callee_name.find(syscall_filter_) != std::string::npos;
            bool in_summary = c.decoded_summary.find(syscall_filter_) != std::string::npos;
            if (!in_name && !in_summary)
                continue;
        }

        filtered.push_back(i);
    }

    ImGui::TextDisabled("Showing %zu / %zu", filtered.size(),
                        syscall_result_->calls.size());
    ImGui::Separator();

    // ── Main table ─────────────────────────────────────────────────────────────
    const float row_h   = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

    if (ImGui::BeginTable("SyscallTable", 5,
            ImGuiTableFlags_Resizable    |
            ImGuiTableFlags_RowBg        |
            ImGuiTableFlags_BordersInnerV|
            ImGuiTableFlags_ScrollY      |
            ImGuiTableFlags_SizingStretchProp,
            table_size)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",           ImGuiTableColumnFlags_WidthFixed,   60.0f);
        ImGui::TableSetupColumn("API",         ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("Summary",     ImGuiTableColumnFlags_WidthStretch, 0.42f);
        ImGui::TableSetupColumn("Key",         ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("ObjC Context",ImGuiTableColumnFlags_WidthStretch, 0.16f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t idx = filtered[static_cast<size_t>(row)];
                const InterceptedCall& call = syscall_result_->calls[idx];
                bool selected = (syscall_cursor_ == static_cast<size_t>(row));

                ImGui::TableNextRow();

                // ── Column 0: inst_id (clickable → navigate_to) ───────────────
                ImGui::TableSetColumnIndex(0);
                char id_label[40];
                snprintf(id_label, sizeof(id_label), "#%llu##sysid%zu",
                         (unsigned long long)call.inst_id, idx);
                if (ImGui::Selectable(id_label, selected,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    syscall_cursor_ = static_cast<size_t>(row);
                    navigate_to(call.inst_id);
                }

                // ── Hover tooltip ─────────────────────────────────────────────
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format(
                        "[{}]  {}\nPC:    0x{:x}\nCallee: 0x{:x}\nCat:   {} ({})",
                        call.inst_id,
                        call.callee_name,
                        call.call_site_pc,
                        call.callee_pc,
                        category_label(call.category),
                        (int)call.category);

                    tip += fmt::format("\n\nSummary:\n  {}", call.decoded_summary);

                    if (call.key_bytes.has_value() && !call.key_bytes->empty()) {
                        tip += fmt::format("\n\nKey ({} B):\n  {}",
                            call.key_bytes->size(),
                            hex_dump(*call.key_bytes, 16));
                    }
                    if (call.iv_bytes.has_value() && !call.iv_bytes->empty()) {
                        tip += fmt::format("\n\nIV ({} B):\n  {}",
                            call.iv_bytes->size(),
                            hex_dump(*call.iv_bytes, 16));
                    }
                    if (call.data_bytes.has_value() && !call.data_bytes->empty()) {
                        tip += fmt::format("\n\nData ({} B, first 16):\n  {}",
                            call.data_bytes->size(),
                            hex_dump(*call.data_bytes, 16));
                    }
                    if (call.has_return) {
                        tip += fmt::format("\n\nReturn: 0x{:x}", call.return_value);
                    }
                    if (call.objc_context.has_value()) {
                        tip += fmt::format("\n\nObjC: {}", *call.objc_context);
                    }

                    tip += "\n\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());
                    if (ImGui::IsMouseDoubleClicked(0))
                        navigate_to(call.inst_id);
                }

                // ── Right-click context menu ───────────────────────────────────
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ImGui::TextDisabled("%s", call.callee_name.c_str());
                    ImGui::TextDisabled("[%s]  inst #%llu",
                                        category_label(call.category),
                                        (unsigned long long)call.inst_id);
                    ImGui::Separator();
                    if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions")) {
                        navigate_to_instructions(call.inst_id);
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                          "the Instructions panel to the front",
                                          (unsigned long long)call.inst_id);
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy Call Site PC")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx",
                                 (unsigned long long)call.call_site_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    if (ImGui::MenuItem("Copy API Name")) {
                        ImGui::SetClipboardText(call.callee_name.c_str());
                    }
                    ImGui::EndPopup();
                }

                // ── Column 1: API name (coloured by category) ─────────────────
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(category_color(call.category),
                                   "%s", call.callee_name.c_str());

                // ── Column 2: Summary (truncated to 80 chars) ─────────────────
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(truncate(call.decoded_summary, 80).c_str());

                // ── Column 3: Key (first 8 bytes hex) ────────────────────────
                ImGui::TableSetColumnIndex(3);
                if (call.key_bytes.has_value() && !call.key_bytes->empty()) {
                    ImGui::TextColored(ImVec4(0.6f, 1.0f, 0.6f, 1.0f),
                                       "%s", hex_dump(*call.key_bytes, 8).c_str());
                } else {
                    ImGui::TextDisabled("—");
                }

                // ── Column 4: ObjC context ────────────────────────────────────
                ImGui::TableSetColumnIndex(4);
                if (call.objc_context.has_value()) {
                    ImGui::TextDisabled("%s",
                        truncate(*call.objc_context, 32).c_str());
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

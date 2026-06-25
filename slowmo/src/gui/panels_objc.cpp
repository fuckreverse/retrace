// panels_objc.cpp — Objective-C message analysis panel.
//
// Displays the ObjcResult from ObjcPass in two views:
//   1. Messages view: a scrollable table of every ObjC message send with
//      class, selector, arguments, return value and navigation.
//   2. Classes view: per-class summary (message count + unique selectors).
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/objc_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include <vector>

namespace tenet {

void GuiApp::render_objc_panel() {
    if (!ImGui::Begin("ObjC Messages", &show_objc_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!objc_result_) {
        ImGui::TextDisabled("No ObjC analysis performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run ObjC Analysis")) {
            run_pass_by_name("objc");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Analyze Objective-C message sends in the trace.\n"
                              "Extracts class names, selectors, arguments, and return values.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        "\xef\xa3\xbf  %zu messages  |  %zu classes",   // Apple  
        objc_result_->total_messages(),
        objc_result_->unique_classes());

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {  // ↺
        run_pass_by_name("objc");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run ObjC analysis (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ───────────────────────────────────────────────────
    ImGui::RadioButton("Messages", &objc_view_mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Classes", &objc_view_mode_, 1);

    ImGui::Separator();

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 0: Messages
    // ══════════════════════════════════════════════════════════════════════
    if (objc_view_mode_ == 0) {

        // ── Filters ───────────────────────────────────────────────────────
        bool filter_changed = false;
        ImGui::PushItemWidth((panel_w - 12.0f) * 0.45f);
        if (ImGui::InputText("Class##objcf", objc_class_filter_buf_,
                             sizeof(objc_class_filter_buf_))) {
            objc_class_filter_ = objc_class_filter_buf_;
            objc_msg_cursor_ = 0;
            filter_changed = true;
        }
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 6);
        ImGui::PushItemWidth((panel_w - 12.0f) * 0.45f);
        if (ImGui::InputText("Sel##objcf", objc_sel_filter_buf_,
                             sizeof(objc_sel_filter_buf_))) {
            objc_sel_filter_ = objc_sel_filter_buf_;
            objc_msg_cursor_ = 0;
            filter_changed = true;
        }
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 6);
        if (ImGui::SmallButton("x##clrfilt")) {
            std::memset(objc_class_filter_buf_, 0, sizeof(objc_class_filter_buf_));
            std::memset(objc_sel_filter_buf_, 0, sizeof(objc_sel_filter_buf_));
            objc_class_filter_.clear();
            objc_sel_filter_.clear();
            objc_msg_cursor_ = 0;
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear filters");

        // ── Build filtered message list ────────────────────────────────────
        // We store indices into objc_result_->messages to avoid copying.
        std::vector<size_t> filtered;
        filtered.reserve(objc_result_->messages.size());
        for (size_t i = 0; i < objc_result_->messages.size(); ++i) {
            const auto& msg = objc_result_->messages[i];
            if (!objc_class_filter_.empty()) {
                if (msg.class_name.find(objc_class_filter_) == std::string::npos)
                    continue;
            }
            if (!objc_sel_filter_.empty()) {
                if (msg.selector_name.find(objc_sel_filter_) == std::string::npos)
                    continue;
            }
            filtered.push_back(i);
        }

        ImGui::TextDisabled("Showing %zu / %zu", filtered.size(),
                            objc_result_->messages.size());
        ImGui::Separator();

        // ── Messages table ─────────────────────────────────────────────────
        const float row_h = ImGui::GetTextLineHeightWithSpacing();
        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

        if (ImGui::BeginTable("ObjcMsgTable", 6,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 55.0f);
            ImGui::TableSetupColumn("Class",    ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableSetupColumn("Selector", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("Args",     ImGuiTableColumnFlags_WidthStretch, 0.25f);
            ImGui::TableSetupColumn("Return",   ImGuiTableColumnFlags_WidthStretch, 0.15f);
            ImGui::TableSetupColumn("PC",       ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(filtered.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    size_t idx = filtered[static_cast<size_t>(row)];
                    const ObjcMessage& msg = objc_result_->messages[idx];
                    bool selected = (objc_msg_cursor_ == static_cast<size_t>(row));

                    ImGui::TableNextRow();

                    // inst_id column
                    ImGui::TableSetColumnIndex(0);
                    char id_label[32];
                    snprintf(id_label, sizeof(id_label), "#%llu##omsg%zu",
                             (unsigned long long)msg.inst_id, idx);
                    if (ImGui::Selectable(id_label, selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        objc_msg_cursor_ = static_cast<size_t>(row);
                        navigate_to(msg.inst_id);
                    }
                    if (ImGui::IsItemHovered()) {
                        // Build full tooltip
                        std::string tip = fmt::format(
                            "[{}] -[{} {}]\nPC: 0x{:x}\nReceiver: 0x{:x}\nVariant: {}",
                            msg.inst_id,
                            msg.class_name, msg.selector_name,
                            msg.pc, msg.receiver, (int)msg.variant);
                        if (msg.arg_count > 0) {
                            tip += "\nArgs:";
                            for (uint8_t k = 0; k < msg.arg_count; ++k) {
                                tip += fmt::format("\n  x{}: 0x{:x}", k + 2,
                                                   msg.args[k].value);
                                if (msg.args[k].deref_str.has_value())
                                    tip += fmt::format(" \"{}\"",
                                                       *msg.args[k].deref_str);
                            }
                        }
                        if (msg.has_return) {
                            tip += fmt::format("\nReturn: 0x{:x}", msg.return_value);
                            if (msg.return_deref_str.has_value())
                                tip += fmt::format(" \"{}\"", *msg.return_deref_str);
                        }
                        tip += "\n\nRight-click for more options";
                        ImGui::SetTooltip("%s", tip.c_str());
                        if (ImGui::IsMouseDoubleClicked(0))
                            navigate_to(msg.inst_id);
                    }

                    // ── Right-click context menu ───────────────────────
                    if (ImGui::BeginPopupContextItem(nullptr)) {
                        ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f),
                                           "%s", msg.class_name.c_str());
                        ImGui::TextColored(ImVec4(0.75f, 0.92f, 0.6f, 1.0f),
                                           "%s", msg.selector_name.c_str());
                        ImGui::TextDisabled("inst #%llu", (unsigned long long)msg.inst_id);
                        ImGui::Separator();
                        if (ImGui::MenuItem("\xe2\x86\x92 Jump to Instructions")) {
                            navigate_to_instructions(msg.inst_id);
                        }
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Navigate to inst #%llu and bring\n"
                                              "the Instructions panel to the front",
                                              (unsigned long long)msg.inst_id);
                        ImGui::Separator();
                        if (ImGui::MenuItem("Copy PC")) {
                            char buf[24];
                            snprintf(buf, sizeof(buf), "0x%llx",
                                     (unsigned long long)msg.pc);
                            ImGui::SetClipboardText(buf);
                        }
                        if (ImGui::MenuItem("Copy Selector")) {
                            ImGui::SetClipboardText(msg.selector_name.c_str());
                        }
                        ImGui::EndPopup();
                    }

                    // Class column
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f),
                                       "%s", msg.class_name.c_str());

                    // Selector column
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextColored(ImVec4(0.75f, 0.92f, 0.6f, 1.0f),
                                       "%s", msg.selector_name.c_str());

                    // Args column — show first arg with string dereference if any
                    ImGui::TableSetColumnIndex(3);
                    if (msg.arg_count > 0) {
                        if (msg.args[0].deref_str.has_value()) {
                            // Show string value prominently
                            ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.4f, 1.0f),
                                "\"%s\"", msg.args[0].deref_str->c_str());
                        } else {
                            // Show hex value
                            ImGui::TextDisabled("0x%llx", (unsigned long long)msg.args[0].value);
                        }
                        if (msg.arg_count > 1) {
                            ImGui::SameLine(0, 2);
                            ImGui::TextDisabled("+%u", (unsigned)(msg.arg_count - 1));
                        }
                    } else {
                        ImGui::TextDisabled("—");
                    }

                    // Return column
                    ImGui::TableSetColumnIndex(4);
                    if (msg.has_return) {
                        if (msg.return_deref_str.has_value()) {
                            ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f),
                                "\"%s\"", msg.return_deref_str->c_str());
                        } else {
                            ImGui::TextDisabled("0x%llx", (unsigned long long)msg.return_value);
                        }
                    } else {
                        ImGui::TextDisabled("—");
                    }

                    // PC column
                    ImGui::TableSetColumnIndex(5);
                    ImGui::TextDisabled("0x%llx",
                        (unsigned long long)(msg.pc - reader_.header().module_slide));
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 1: Classes
    // ══════════════════════════════════════════════════════════════════════
    else {
        // Sorted class list (hottest first)
        auto sorted = objc_result_->hottest_classes(SIZE_MAX);

        ImGui::TextDisabled("%zu unique classes", sorted.size());
        ImGui::Separator();

        if (ImGui::BeginTable("ObjcClassTable", 3,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Class",    ImGuiTableColumnFlags_WidthStretch, 0.45f);
            ImGui::TableSetupColumn("Messages", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Selectors",ImGuiTableColumnFlags_WidthStretch, 0.55f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(sorted.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const ObjcClassInfo* ci = sorted[static_cast<size_t>(row)];
                    ImGui::TableNextRow();

                    ImGui::TableSetColumnIndex(0);
                    bool class_sel = false;
                    char cls_label[128];
                    snprintf(cls_label, sizeof(cls_label), "%s##ocls%d",
                             ci->name.c_str(), row);
                    if (ImGui::Selectable(cls_label, class_sel,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        // Filter messages view to this class
                        strncpy(objc_class_filter_buf_, ci->name.c_str(),
                                sizeof(objc_class_filter_buf_) - 1);
                        objc_class_filter_buf_[sizeof(objc_class_filter_buf_)-1] = '\0';
                        objc_class_filter_ = ci->name;
                        std::memset(objc_sel_filter_buf_, 0, sizeof(objc_sel_filter_buf_));
                        objc_sel_filter_.clear();
                        objc_msg_cursor_ = 0;
                        objc_view_mode_ = 0;  // switch to messages view
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Click to filter Messages view to '%s'",
                                          ci->name.c_str());

                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%llu", (unsigned long long)ci->message_count);

                    ImGui::TableSetColumnIndex(2);
                    // Show comma-separated selector list (truncated)
                    std::string sel_str;
                    size_t si = 0;
                    for (const auto& sel : ci->selectors_seen) {
                        if (si > 0) sel_str += ", ";
                        if (si >= 4 && ci->selectors_seen.size() > 5) {
                            sel_str += fmt::format("(+{})", ci->selectors_seen.size() - si);
                            break;
                        }
                        sel_str += sel;
                        ++si;
                    }
                    ImGui::TextDisabled("%s", sel_str.c_str());
                    if (ImGui::IsItemHovered() && ci->selectors_seen.size() > 5) {
                        std::string full;
                        for (const auto& s : ci->selectors_seen)
                            full += s + "\n";
                        ImGui::SetTooltip("%s", full.c_str());
                    }
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    ImGui::End();
}

}  // namespace tenet

// panels_taint_source_annotation.cpp — "Taint Sources" panel.
//
// Visualizes TaintSourceAnnotationResult: the "leaf" origins of a backward
// taint chain (ObjC getter / memory load / constant / function return).
// This is the GUI counterpart of `--taint-source-annotation` (CLI) and the
// `taint_source_annotation` MCP tool — it turns a raw 500-instruction
// backward-taint chain into a handful of human-readable "where did this
// value ultimately come from" answers.
//
// Layout: single window, filter bar + kind tabs (All/ObjC/Memory/Constant/
// FnReturn) + a table of annotated sources. Selecting a row jumps the
// Instructions panel to that source's inst_id (like other analysis panels).

#include "gui/gui_app.h"
#include "analysis/passes/taint/taint_source_annotation_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <algorithm>
#include <cctype>
#include <cstring>

#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

namespace {

const char* kind_label(TaintSourceKind k) {
    switch (k) {
        case TaintSourceKind::ObjcGetter:        return "ObjC Getter";
        case TaintSourceKind::ObjcArg:            return "ObjC Arg";
        case TaintSourceKind::ObjcReturnValue:    return "ObjC Return";
        case TaintSourceKind::MemoryLoad:         return "Memory Load";
        case TaintSourceKind::ImmediateConstant:  return "Constant";
        case TaintSourceKind::FunctionReturn:     return "Fn Return";
        default:                                  return "Unknown";
    }
}

ImVec4 kind_color(TaintSourceKind k) {
    switch (k) {
        case TaintSourceKind::ObjcGetter:
        case TaintSourceKind::ObjcArg:
        case TaintSourceKind::ObjcReturnValue:
            return ImVec4(0.55f, 0.90f, 0.70f, 1.0f);   // green — ObjC
        case TaintSourceKind::MemoryLoad:
            return ImVec4(0.65f, 0.85f, 1.0f, 1.0f);    // blue — memory
        case TaintSourceKind::ImmediateConstant:
            return ImVec4(1.0f, 0.85f, 0.35f, 1.0f);    // amber — constant
        case TaintSourceKind::FunctionReturn:
            return ImVec4(0.85f, 0.65f, 1.0f, 1.0f);    // purple — call return
        default:
            return ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
    }
}

const char* kind_icon(TaintSourceKind k) {
    switch (k) {
        case TaintSourceKind::ObjcGetter:
        case TaintSourceKind::ObjcArg:
        case TaintSourceKind::ObjcReturnValue:
            return ICON_FA_COMMENT;
        case TaintSourceKind::MemoryLoad:
            return ICON_FA_DATABASE;
        case TaintSourceKind::ImmediateConstant:
            return ICON_FA_HASHTAG;
        case TaintSourceKind::FunctionReturn:
            return ICON_FA_ARROW_TURN_UP;
        default:
            return ICON_FA_CIRCLE_QUESTION;
    }
}

bool kind_matches_view_mode(TaintSourceKind k, int mode) {
    switch (mode) {
        case 0: return true;  // All
        case 1: return k == TaintSourceKind::ObjcGetter ||
                       k == TaintSourceKind::ObjcArg ||
                       k == TaintSourceKind::ObjcReturnValue;
        case 2: return k == TaintSourceKind::MemoryLoad;
        case 3: return k == TaintSourceKind::ImmediateConstant;
        case 4: return k == TaintSourceKind::FunctionReturn;
        default: return true;
    }
}

}  // namespace

void GuiApp::render_taint_source_annotation_panel() {
    if (!ImGui::Begin(ICON_FA_MAGNIFYING_GLASS_LOCATION "  Taint Sources##TaintSrcPanel",
                      &show_taint_source_annotation_)) {
        ImGui::End(); return;
    }

    if (!taint_source_annotation_result_) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.3f, 1.0f),
            ICON_FA_MAGNIFYING_GLASS_LOCATION "  Taint Source Annotation");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Traces every 'leaf' endpoint of a backward-taint chain back to "
            "its origin: an ObjC getter return value, a memory load, a "
            "hard-coded constant, or a function's return value. Answers "
            "'where did this key/IV/password ultimately come from?' without "
            "manually walking hundreds of contributing instructions.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Requires a Backward Taint sink first — position the cursor on "
            "the instruction/register you suspect holds sensitive data, "
            "then click Run below (Backward Taint will be started "
            "automatically at the current cursor if not already run).");
        ImGui::Spacing();
        if (ImGui::Button(ICON_FA_PLAY "  Run Taint Source Annotation",
                          ImVec2(320.0f, 0.0f))) {
            run_taint_source_annotation_analysis();
        }
        if (!last_pass_status_.empty()) {
            ImGui::Spacing();
            ImGui::TextWrapped("%s", last_pass_status_.c_str());
        }
        ImGui::End(); return;
    }

    const auto& res = *taint_source_annotation_result_;

    // ── Toolbar ──────────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f),
        ICON_FA_CIRCLE_CHECK "  %zu source(s)", res.total());
    ImGui::SameLine();
    ImGui::TextDisabled("  (ObjC: %zu, Mem: %zu, Const: %zu)",
        res.objc_source_indices.size(),
        res.memory_source_indices.size(),
        res.constant_source_indices.size());

    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 70.0f + ImGui::GetCursorPosX() -
                     ImGui::GetWindowContentRegionMin().x);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        force_rerun_pass("taint_source_annotation");
        run_taint_source_annotation_analysis();
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Re-run with the current Backward Taint result.");
    }

    ImGui::Separator();

    // ── Filter + kind tabs ──────────────────────────────────────────
    ImGui::SetNextItemWidth(260.0f);
    if (ImGui::InputTextWithHint("##tsa_filter", ICON_FA_MAGNIFYING_GLASS " Filter (label / summary)…",
                                  taint_source_annotation_filter_buf_,
                                  sizeof(taint_source_annotation_filter_buf_))) {
        taint_source_annotation_filter_ = taint_source_annotation_filter_buf_;
    }
    ImGui::SameLine();
    ImGui::RadioButton("All",      &taint_source_annotation_view_mode_, 0); ImGui::SameLine();
    ImGui::RadioButton("ObjC",     &taint_source_annotation_view_mode_, 1); ImGui::SameLine();
    ImGui::RadioButton("Memory",   &taint_source_annotation_view_mode_, 2); ImGui::SameLine();
    ImGui::RadioButton("Constant", &taint_source_annotation_view_mode_, 3); ImGui::SameLine();
    ImGui::RadioButton("Fn Return",&taint_source_annotation_view_mode_, 4);

    ImGui::Separator();

    // ── Build filtered index list ────────────────────────────────────
    std::string filt_lower = taint_source_annotation_filter_;
    for (auto& c : filt_lower) c = static_cast<char>(std::tolower((unsigned char)c));

    std::vector<size_t> idx;
    idx.reserve(res.sources.size());
    for (size_t i = 0; i < res.sources.size(); ++i) {
        const auto& s = res.sources[i];
        if (!kind_matches_view_mode(s.kind, taint_source_annotation_view_mode_))
            continue;
        if (!filt_lower.empty()) {
            std::string summary_lower = s.summary();
            for (auto& c : summary_lower) c = static_cast<char>(std::tolower((unsigned char)c));
            if (summary_lower.find(filt_lower) == std::string::npos)
                continue;
        }
        idx.push_back(i);
    }

    if (idx.empty()) {
        ImGui::TextDisabled("No sources match the current filter.");
        ImGui::End(); return;
    }

    if (taint_source_annotation_cursor_ >= idx.size())
        taint_source_annotation_cursor_ = 0;

    // ── Table ─────────────────────────────────────────────────────────
    const float avail_h = ImGui::GetContentRegionAvail().y;
    if (ImGui::BeginTable("tsa_table", 5,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.0f, avail_h))) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Kind",    ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Sink Reg",ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("PC",      ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Summary", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();

        static const char* reg_names[34] = {
            "x0","x1","x2","x3","x4","x5","x6","x7",
            "x8","x9","x10","x11","x12","x13","x14","x15",
            "x16","x17","x18","x19","x20","x21","x22","x23",
            "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
        };
        uint64_t slide = reader_.header().module_slide;

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(idx.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                size_t src_i = idx[static_cast<size_t>(row)];
                const auto& s = res.sources[src_i];
                bool selected = (taint_source_annotation_cursor_ == static_cast<size_t>(row));

                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(src_i));

                // Col 0: index (selectable, spans all columns)
                ImGui::TableSetColumnIndex(0);
                char idbuf[24]; snprintf(idbuf, sizeof(idbuf), "%d", row + 1);
                if (ImGui::Selectable(idbuf, selected,
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowOverlap)) {
                    taint_source_annotation_cursor_ = static_cast<size_t>(row);
                }
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                    ImGui::IsItemHovered()) {
                    navigate_to_instructions(s.inst_id);
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("inst #%llu\nDouble-click to jump to Instructions.",
                        (unsigned long long)s.inst_id);
                }
                if (ImGui::BeginPopupContextItem("##tsa_ctx")) {
                    ImGui::TextDisabled("Source #%d", row + 1);
                    ImGui::Separator();
                    if (ImGui::MenuItem(ICON_FA_ARROW_RIGHT " Jump to Instructions")) {
                        navigate_to_instructions(s.inst_id);
                    }
                    ImGui::EndPopup();
                }

                // Col 1: kind badge
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(kind_color(s.kind), "%s %s",
                    kind_icon(s.kind), kind_label(s.kind));

                // Col 2: sink register
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%s", s.sink_reg < 34 ? reg_names[s.sink_reg] : "?");

                // Col 3: PC (static, slide-adjusted)
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("0x%llx",
                    (unsigned long long)(s.pc >= slide ? s.pc - slide : s.pc));

                // Col 4: summary
                ImGui::TableSetColumnIndex(4);
                ImGui::TextColored(kind_color(s.kind), "%s", s.summary().c_str());
                if (s.kind == TaintSourceKind::MemoryLoad && s.source_mem_addr != 0 &&
                    ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Address: 0x%llx\nSize: %llu bytes",
                        (unsigned long long)s.source_mem_addr,
                        (unsigned long long)s.source_mem_size);
                }
                if (s.kind == TaintSourceKind::FunctionReturn && ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Callee PC: 0x%llx%s",
                        (unsigned long long)(s.callee_pc >= slide ? s.callee_pc - slide : s.callee_pc),
                        s.callee_name.empty() ? "" :
                            (" (" + s.callee_name + ")").c_str());
                }

                ImGui::PopID();
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    ImGui::End();
}

}  // namespace tenet

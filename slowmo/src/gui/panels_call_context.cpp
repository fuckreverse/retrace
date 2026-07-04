// panels_call_context.cpp — Rich call context panel.
//
// Independent floating window for CallContextPass.
// Shows a parameter form (target inst_id, context window size), and
// displays: surrounding instructions, call stack, and loop context.
//
// Split out of panels_analysis.cpp. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/profile/call_context_pass.h"
#include "analysis/pass_registry.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ---------------------------------------------------------------------------
// Run helper
// ---------------------------------------------------------------------------

void GuiApp::run_call_context_with_params() {
    ensure_pass_manager();

    CallContextConfig cfg;

    // Parse inst_id
    if (call_context_inst_buf_[0] != '\0') {
        try {
            std::string s(call_context_inst_buf_);
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                cfg.target_inst_id = std::stoull(s, nullptr, 16);
            else
                cfg.target_inst_id = std::stoull(s, nullptr, 0);
        } catch (...) {
            cfg.target_inst_id = current_inst_;
        }
    } else {
        cfg.target_inst_id = current_inst_;
    }

    cfg.context_before = call_context_before_;
    cfg.context_after  = call_context_after_;

    // Invalidate previous result
    if (pass_manager_->state("call_context") != PassManager::PassState::NotRun) {
        pass_manager_->invalidate_and_clear_blob("call_context");
    }
    pass_manager_->register_pass(std::make_unique<CallContextPass>(std::move(cfg)));
    call_context_result_ = nullptr;

    std::string name_str = "call_context";
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

void GuiApp::render_call_context_panel() {
    if (!ImGui::Begin("Call Context", &show_call_context_)) {
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── No result yet — show parameter form ───────────────────────────
    if (!call_context_result_) {
        ImGui::TextDisabled(ICON_FA_CODE "  Call Context");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Get rich context for an instruction: surrounding instructions,\n"
            "call stack reconstruction, and loop position information.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Target inst_id
        ImGui::Text("Target inst_id (hex or decimal):");
        ImGui::PushItemWidth(panel_w * 0.45f);
        bool inst_entered = ImGui::InputText("##cc_inst", call_context_inst_buf_,
            sizeof(call_context_inst_buf_),
            ImGuiInputTextFlags_CharsHexadecimal |
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 4);
        if (ImGui::SmallButton("Cursor##cc")) {
            snprintf(call_context_inst_buf_, sizeof(call_context_inst_buf_),
                     "%llu", (unsigned long long)current_inst_);
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Use the current cursor position");

        // Context before/after
        ImGui::AlignTextToFramePadding();
        ImGui::Text("Before:");
        ImGui::SameLine();
        ImGui::PushItemWidth(60.0f);
        ImGui::InputScalar("##cc_before", ImGuiDataType_U32, &call_context_before_);
        ImGui::PopItemWidth();

        ImGui::SameLine(0, 16);
        ImGui::Text("After:");
        ImGui::SameLine();
        ImGui::PushItemWidth(60.0f);
        ImGui::InputScalar("##cc_after", ImGuiDataType_U32, &call_context_after_);
        ImGui::PopItemWidth();

        ImGui::Spacing();

        // Run button
        if (ImGui::Button(ICON_FA_CODE " Get Context") || inst_entered) {
            run_call_context_with_params();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Analyze context for the specified instruction");

        ImGui::End();
        return;
    }

    // ── Result available ──────────────────────────────────────────────

    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_CODE "  Context for inst #%llu  (PC: 0x%llx)",
        (unsigned long long)call_context_result_->target_inst_id,
        (unsigned long long)(call_context_result_->target_pc -
                             reader_.header().module_slide));

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        // Pre-fill current inst_id
        snprintf(call_context_inst_buf_, sizeof(call_context_inst_buf_),
                 "%llu", (unsigned long long)call_context_result_->target_inst_id);
        call_context_result_ = nullptr;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run with different parameters");

    ImGui::Separator();

    // ── Surrounding instructions ─────────────────────────────────────
    if (!call_context_result_->instructions.empty()) {
        ImGui::Text("Surrounding Instructions:");
        ImGui::Spacing();

        for (const auto& inst : call_context_result_->instructions) {
            if (inst.is_target) {
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                    ">>> #%llu  0x%llx: %s",
                    (unsigned long long)inst.inst_id,
                    (unsigned long long)(inst.pc - reader_.header().module_slide),
                    inst.disassembly.c_str());
            } else {
                ImGui::TextDisabled("    #%llu  0x%llx: %s",
                    (unsigned long long)inst.inst_id,
                    (unsigned long long)(inst.pc - reader_.header().module_slide),
                    inst.disassembly.c_str());
            }
            // Click to navigate
            if (ImGui::IsItemClicked()) {
                navigate_to(inst.inst_id);
            }
        }
        ImGui::Separator();
    }

    // ── Call stack ────────────────────────────────────────────────────
    if (!call_context_result_->call_stack.empty()) {
        ImGui::Text(ICON_FA_LAYER_GROUP "  Call Stack (%zu frames):",
            call_context_result_->call_stack.size());
        ImGui::Spacing();

        for (size_t i = 0; i < call_context_result_->call_stack.size(); ++i) {
            const CallStackFrame& frame = call_context_result_->call_stack[i];
            ImGui::TextDisabled("  [%zu] 0x%llx -> 0x%llx%s  @ inst #%llu",
                i,
                (unsigned long long)(frame.call_site_pc - reader_.header().module_slide),
                (unsigned long long)(frame.callee_pc - reader_.header().module_slide),
                frame.is_tail_call ? " (tail)" : "",
                (unsigned long long)frame.call_inst_id);
            if (ImGui::IsItemClicked()) {
                navigate_to(frame.call_inst_id);
            }
        }
        ImGui::Separator();
    }

    // ── Loop context ──────────────────────────────────────────────────
    if (!call_context_result_->loop_contexts.empty()) {
        ImGui::Text(ICON_FA_REPEAT "  Loop Context:");
        ImGui::Spacing();

        for (const auto& lc : call_context_result_->loop_contexts) {
            ImGui::TextDisabled("  Header: 0x%llx  depth=%u  iterations=%llu",
                (unsigned long long)(lc.header_pc - reader_.header().module_slide),
                lc.nesting_depth,
                (unsigned long long)lc.total_iterations);
        }
        ImGui::Separator();
    }

    ImGui::End();
}

}  // namespace tenet

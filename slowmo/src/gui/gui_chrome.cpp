// gui_chrome.cpp — top-level menu bar + toolbar (the "chrome" around the dockspace).
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal). Needs imgui_internal.h
// for SeparatorEx/ImGuiSeparatorFlags_Vertical used by the toolbar.

#include "gui/gui_app.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/loop_pass.h"
#include "io/recent_files.h"

#include <imgui.h>
#include <imgui_internal.h>

#include <fmt/core.h>

#include <ctime>
#include <string>

namespace tenet {

// ─── Menu Bar ───────────────────────────────────────────────────────────────

void GuiApp::render_menu_bar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Trace...", "Cmd+O")) {
                // TODO: file dialog integration
            }

            // ── Recent files sub-menu ──────────────────────────────────────
            auto recent = RecentFiles::load();
            bool has_recent = !recent.empty();
            if (!has_recent) ImGui::BeginDisabled();
            if (ImGui::BeginMenu("Open Recent")) {
                for (const auto& entry : recent.entries()) {
                    // Format: "module_name  (N inst)  – /path/to/trace.bin"
                    // Shorten path to last 2 components for readability
                    std::string display;
                    {
                        auto p = entry.path;
                        // Find last two path separators
                        auto s2 = p.rfind('/');
                        if (s2 != std::string::npos && s2 > 0) {
                            auto s1 = p.rfind('/', s2 - 1);
                            if (s1 != std::string::npos) {
                                p = "\xe2\x80\xa6" + p.substr(s1);  // … + tail
                            }
                        }
                        // Format timestamp as "YYYY-MM-DD HH:MM"
                        char ts_buf[24] = {};
                        if (entry.last_opened > 0) {
                            time_t t = static_cast<time_t>(entry.last_opened);
                            struct tm tm_info{};
                            localtime_r(&t, &tm_info);
                            strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M", &tm_info);
                        }
                        display = fmt::format("{}   ({} inst)  {}",
                            entry.module_name.empty() ? p : entry.module_name,
                            entry.inst_count, ts_buf);
                    }
                    if (ImGui::MenuItem(display.c_str())) {
                        // Show the full path as tooltip even though we can't
                        // reload in this session (trace is already open)
                        // In a future implementation, this would re-open tenet
                        // with the selected trace. For now, copy path to clipboard.
                        ImGui::SetClipboardText(entry.path.c_str());
                    }
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("%s\n(path copied to clipboard on click)",
                                          entry.path.c_str());
                    }
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Clear Recent Files")) {
                    // Overwrite with empty list
                    RecentFiles empty;
                    empty.save();
                }
                ImGui::EndMenu();
            }
            if (!has_recent) ImGui::EndDisabled();

            ImGui::Separator();
            if (ImGui::MenuItem("Quit", "Cmd+Q")) {
                running_ = false;
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Settings...", "Cmd+,")) {
                show_settings_ = true;
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Registers", "R", &show_registers_);
            ImGui::MenuItem("Memory", "M", &show_memory_);
            ImGui::MenuItem("Call Stack", "F", &show_callstack_);
            ImGui::MenuItem("Analysis", "A", &show_analysis_);
            ImGui::MenuItem("Hex Dump", "H", &show_hex_dump_);
            ImGui::MenuItem("Strings", "I", &show_strings_);
            ImGui::MenuItem("Functions", "L", &show_functions_);
            ImGui::MenuItem("Threads", "T", &show_threads_);
            ImGui::Separator();
            ImGui::MenuItem("Minimap", "V", &show_minimap_);
            ImGui::MenuItem("Loop Highlight", "O", &show_loops_);
            ImGui::MenuItem("CFG View", "K", &show_cfg_);
            ImGui::Separator();
            ImGui::MenuItem("ObjC Messages",         nullptr, &show_objc_);
            ImGui::MenuItem("ObjC Crypto",           nullptr, &show_objc_crypto_);
            ImGui::MenuItem("Loop Semantics",        nullptr, &show_loop_semantics_);
            ImGui::MenuItem("Patterns",              nullptr, &show_pattern_);
            ImGui::MenuItem("Constants",             nullptr, &show_constant_);
            ImGui::MenuItem("Algorithm Summary",     nullptr, &show_algorithm_summary_);
            ImGui::MenuItem("Call Graph",            nullptr, &show_call_graph_);
            ImGui::MenuItem("Memory Strings",        nullptr, &show_mem_strings_);
            ImGui::MenuItem("API Intercepts",        nullptr, &show_syscall_intercept_);
            ImGui::MenuItem("Cache Sim",             nullptr, &show_cache_sim_);
            ImGui::MenuItem("Trace Fold",            nullptr, &show_trace_fold_);
            ImGui::Separator();
            // ── P2 panels ────────────────────────────────────────────
            ImGui::MenuItem("Register Timeline",     nullptr, &show_reg_timeline_);
            ImGui::MenuItem("Symbol Info (DWARF)",   nullptr, &show_dwarf_panel_);
            ImGui::MenuItem("Trace Diff",            nullptr, &show_trace_diff_);
            ImGui::Separator();
            ImGui::MenuItem("Output (Log)",          nullptr, &show_log_);
            ImGui::Separator();
            ImGui::MenuItem("Cache Manager",         nullptr, &show_cache_manager_);
            ImGui::MenuItem("ImGui Demo", nullptr, &show_demo_window_);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Navigate")) {
            if (ImGui::MenuItem("Goto Instruction...", "G")) {
                show_goto_popup_ = true;
            }
            if (ImGui::MenuItem("Search...", "/")) {
                show_search_popup_ = true;
            }
            ImGui::Separator();
            // Navigation history
            {
                bool can_back = can_nav_back();
                bool can_fwd  = can_nav_forward();
                if (!can_back) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Back", "Alt+Left")) {
                    nav_back();
                }
                if (!can_back) ImGui::EndDisabled();
                if (!can_fwd) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Forward", "Alt+Right")) {
                    nav_forward();
                }
                if (!can_fwd) ImGui::EndDisabled();
                // Show history size
                if (!nav_history_.empty()) {
                    ImGui::TextDisabled("  History: [%zu/%zu]",
                        nav_history_pos_ + 1, nav_history_.size());
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("First Instruction", "Home")) {
                navigate_to(0);
            }
            if (ImGui::MenuItem("Last Instruction", "End")) {
                navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Toggle Bookmark", "B")) {
                toggle_bookmark();
            }
            ImGui::Separator();
            // Follow call/return
            if (ImGui::MenuItem("Follow Call (enter callee)", "E")) {
                if (function_result_) {
                    auto* evt = function_result_->call_at(current_inst_);
                    if (evt && evt->call_inst_id + 1 < total_inst_) {
                        navigate_to(evt->call_inst_id + 1);
                    }
                }
            }
            if (ImGui::MenuItem("Follow Return (back to caller)", "R")) {
                if (function_result_) {
                    auto* evt = function_result_->return_at(current_inst_);
                    if (evt) {
                        navigate_to(evt->call_inst_id);
                    } else {
                        const auto& stk = current_call_stack();
                        if (!stk.empty()) {
                            navigate_to(stk.back()->call_inst_id);
                        }
                    }
                }
            }
            ImGui::Separator();
            // Taint jump
            if (show_taint_ && taint_result_) {
                if (ImGui::MenuItem("Next Tainted Inst", "]")) {
                    jump_taint_next();
                }
                if (ImGui::MenuItem("Prev Tainted Inst", "[")) {
                    jump_taint_prev();
                }
            }
            if (show_backward_taint_ && backward_taint_result_) {
                if (ImGui::MenuItem("Next Backward-Tainted Inst", "Shift+]")) {
                    jump_backward_taint_next();
                }
                if (ImGui::MenuItem("Prev Backward-Tainted Inst", "Shift+[")) {
                    jump_backward_taint_prev();
                }
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Analysis")) {
            if (ImGui::MenuItem("Forward Taint", "T")) {
                run_taint_analysis();
            }
            if (ImGui::MenuItem("Backward Taint", "Shift+B")) {
                run_backward_taint_analysis();
            }
            if (ImGui::MenuItem("Slice", "S")) {
                run_slice_analysis();
            }
            ImGui::Separator();
            // ── P2 data-flow tools ─────────────────────────────────
            if (ImGui::MenuItem("Register Timeline...", nullptr)) {
                show_reg_timeline_ = true;
                reg_timeline_dirty_ = true;
            }
            if (ImGui::MenuItem("Producer Chain (current reg)")) {
                show_reg_timeline_ = true;
                run_producer_chain(current_inst_, reg_timeline_reg_);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Function Analysis", "Shift+F")) {
                run_pass_by_name("function");
            }
            if (ImGui::MenuItem("Xref Analysis", "X")) {
                run_pass_by_name("xref");
            }
            if (ImGui::MenuItem("String Analysis", "I")) {
                run_pass_by_name("strings");
            }
            if (ImGui::MenuItem("Thread Analysis", "T")) {
                run_pass_by_name("thread");
            }
            if (ImGui::MenuItem("Call Graph Analysis")) {
                run_call_graph_analysis();
            }
            if (ImGui::MenuItem("Loop Analysis", "O")) {
                run_pass_by_name("loop");
            }
            if (ImGui::MenuItem("CFG Layout", "K")) {
                run_cfg_layout();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Clear All Analysis", "C")) {
                clear_analysis();
            }
            ImGui::EndMenu();
        }

        // Status indicator on the right side of menu bar
        {
            std::string status = fmt::format("  inst {}/{} ", current_inst_, total_inst_);
            float text_width = ImGui::CalcTextSize(status.c_str()).x;
            ImGui::SameLine(ImGui::GetWindowWidth() - text_width - 10.0f);
            ImGui::TextDisabled("%s", status.c_str());
        }

        ImGui::EndMenuBar();
    }
}

// ─── Toolbar ────────────────────────────────────────────────────────────────
// Redesigned: clear icon-like labels, logical grouping with visual separators,
// status badges on the right (Binary Ninja / IDA style)

void GuiApp::render_toolbar() {
    // ── Fixed position: pinned at the very top of the window area ─────
    // The application menu bar is now the native macOS NSMenu (screen top).
    // The ImGui menu bar window has been removed, so the toolbar starts
    // directly at WorkPos.y (the top of the SDL window client area).
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float toolbar_y = vp->WorkPos.y;
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, toolbar_y));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, kToolbarHeight));
    ImGui::SetNextWindowViewport(vp->ID);

    // Style overrides for toolbar: tighter frame padding for compact buttons
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,    ImVec2(5.0f, 3.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,     ImVec2(3.0f, 2.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(4.0f, 3.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    // Slightly different bg than main windows to distinguish toolbar area
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.085f, 0.090f, 0.115f, 1.0f));

    ImGui::Begin("##Toolbar", nullptr,
        ImGuiWindowFlags_NoTitleBar    | ImGuiWindowFlags_NoResize  |
        ImGuiWindowFlags_NoMove        | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoDocking     | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus);

    const float btn_h = ImGui::GetFrameHeight();

    // ── GROUP 1: History navigation ───────────────────────────────────
    {
        bool can_back = can_nav_back();
        bool can_fwd  = can_nav_forward();

        if (!can_back) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\x90##navback", ImVec2(26.0f, btn_h)))  // ← (UTF-8 U+2190)
            nav_back();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Back  Alt+\xe2\x86\x90\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        if (!can_back) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!can_fwd) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\x92##navfwd", ImVec2(26.0f, btn_h)))   // → (UTF-8 U+2192)
            nav_forward();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Forward  Alt+\xe2\x86\x92\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        if (!can_fwd) ImGui::EndDisabled();
    }

    // ── Separator ─────────────────────────────────────────────────────
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::PopStyleColor();
    ImGui::SameLine();

    // ── GROUP 2: Step / seek ─────────────────────────────────────────
    if (ImGui::Button("|<##seek0", ImVec2(26.0f, btn_h)))
        navigate_to(0);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("First instruction  Home");
    ImGui::SameLine();

    if (ImGui::Button("\xe2\x96\xb2##stepup", ImVec2(26.0f, btn_h))) {  // ▲
        if (current_inst_ > 0) navigate_to(current_inst_ - 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous instruction  \xe2\x86\x91");
    ImGui::SameLine();

    if (ImGui::Button("\xe2\x96\xbc##stepdn", ImVec2(26.0f, btn_h))) {  // ▼
        navigate_to(current_inst_ + 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next instruction  \xe2\x86\x93");
    ImGui::SameLine();

    if (ImGui::Button(">|##seekend", ImVec2(26.0f, btn_h)))
        navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Last instruction  End");

    // ── Separator ─────────────────────────────────────────────────────
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::PopStyleColor();
    ImGui::SameLine();

    // ── GROUP 3: Call/Return follow (only when function analysis available) ──
    if (function_result_) {
        bool has_call = (function_result_->call_at(current_inst_) != nullptr);
        bool has_ret  = (function_result_->return_at(current_inst_) != nullptr ||
                         !current_call_stack().empty());

        if (!has_call) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\xb3 Enter", ImVec2(0, btn_h))) {  // ↳
            auto* evt = function_result_->call_at(current_inst_);
            if (evt && evt->call_inst_id + 1 < total_inst_)
                navigate_to(evt->call_inst_id + 1);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Follow call into callee (E)");
        if (!has_call) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!has_ret) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\xb5 Return", ImVec2(0, btn_h))) {  // ↵
            auto* evt = function_result_->return_at(current_inst_);
            if (evt) {
                navigate_to(evt->call_inst_id);
            } else {
                const auto& stk = current_call_stack();
                if (!stk.empty()) navigate_to(stk.back()->call_inst_id);
            }
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Follow return to call site (R)");
        if (!has_ret) ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::PopStyleColor();
        ImGui::SameLine();
    }

    // ── GROUP 4: Taint navigation (only when active) ─────────────────
    bool has_taint_nav = (show_taint_ && taint_result_) ||
                         (show_backward_taint_ && backward_taint_result_);
    if (has_taint_nav) {
        if (show_taint_ && taint_result_) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.28f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.40f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.15f, 0.50f, 0.20f, 1.0f));
            if (ImGui::Button("\xe2\x97\x81 T", ImVec2(0, btn_h))) jump_taint_prev();  // ◁
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev tainted inst ([)");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.28f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.40f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.15f, 0.50f, 0.20f, 1.0f));
            if (ImGui::Button("T \xe2\x96\xb7", ImVec2(0, btn_h))) jump_taint_next();  // ▷
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next tainted inst (])");
            ImGui::SameLine();
        }
        if (show_backward_taint_ && backward_taint_result_) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button("\xe2\x97\x81 BT", ImVec2(0, btn_h))) jump_backward_taint_prev();  // ◁
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev backward-tainted inst");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button("BT \xe2\x96\xb7", ImVec2(0, btn_h))) jump_backward_taint_next();  // ▷
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next backward-tainted inst");
            ImGui::SameLine();
        }
        ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::PopStyleColor();
        ImGui::SameLine();
    }

    // ── GROUP 5: Current instruction info ────────────────────────────
    auto row = fetch_row(current_inst_);
    // PC in dimmed monospace style
    ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.70f, 1.0f),
        "0x%llx", (unsigned long long)row.static_pc);
    ImGui::SameLine(0, 8.0f);
    // Mnemonic colored
    ImGui::TextColored(inst_color(row.mnemonic), "%s", row.mnemonic.c_str());
    ImGui::SameLine(0, 4.0f);
    // Operands lighter
    ImGui::TextColored(ImVec4(0.78f, 0.78f, 0.84f, 1.0f), "%s", row.operands.c_str());

    // ── STATUS BADGES (right-aligned) ─────────────────────────────────
    // Compute total width for the right side to right-align it
    float win_w = ImGui::GetWindowWidth();

    // Build status string(s)
    bool has_status = analysis_running_.load() || show_taint_ || show_backward_taint_ ||
                      show_slice_ || (show_loops_ && loop_result_);

    if (has_status) {
        // estimate approx position
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine(0, 8.0f);

        if (analysis_running_.load()) {
            // Animated spinner character (cycle through ⣾⣽⣻⢿⡿⣟⣯⣷)
            static const char* spinner[] = {
                "\xe2\xa3\xbe","\xe2\xa3\xbd","\xe2\xa3\xbb","\xe2\xa2\xbf",
                "\xe2\xa1\xbf","\xe2\xa3\x9f","\xe2\xa3\xaf","\xe2\xa3\xb7"
            };
            static int spin_frame = 0;
            spin_frame = (spin_frame + 1) % 8;

            // Show the first running pass name + progress
            std::string status_text = "Analyzing...";
            if (pass_manager_) {
                for (auto pname : pass_manager_->all_passes()) {
                    if (pass_manager_->state(pname) == PassManager::PassState::Running) {
                        float pct = pass_manager_->progress_of(pname);
                        std::string_view display = pname;
                        if (auto* cat = tenet::find_pass_catalog_entry(pname))
                            display = cat->display_name;
                        status_text = fmt::format("{} {:d}%", display, (int)(pct * 100));
                        break;
                    }
                }
            }
            ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.2f, 1.0f),
                "%s %s", spinner[spin_frame], status_text.c_str());
        } else {
            // Show active analysis mode badges
            bool first_badge = true;
            auto badge = [&](const char* label, ImVec4 col) {
                if (!first_badge) ImGui::SameLine(0, 4.0f);
                first_badge = false;
                ImGui::PushStyleColor(ImGuiCol_Button, col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, col);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive,  col);
                ImGui::Button(label);
                ImGui::PopStyleColor(3);
            };
            if (show_backward_taint_ && backward_taint_result_)
                badge("BACK-TAINT", ImVec4(0.55f, 0.10f, 0.10f, 0.90f));
            else if (show_taint_ && taint_result_)
                badge("TAINT", ImVec4(0.10f, 0.40f, 0.12f, 0.90f));
            if (show_slice_ && slice_result_)
                badge("SLICE", ImVec4(0.40f, 0.10f, 0.42f, 0.90f));
            if (show_loops_ && loop_result_) {
                char loop_label[32];
                snprintf(loop_label, sizeof(loop_label), "\xe2\x86\xba %zu LOOPS",
                         loop_result_->loops.size());  // ↺
                badge(loop_label, ImVec4(0.38f, 0.20f, 0.03f, 0.90f));
            }
        }
    }

    // ── Right side: progress ─────────────────────────────────────────
    if (total_inst_ > 0) {
        // Right-align the counter
        char counter[48];
        snprintf(counter, sizeof(counter), "%llu / %llu",
                 (unsigned long long)(current_inst_ + 1),
                 (unsigned long long)total_inst_);
        float counter_w = ImGui::CalcTextSize(counter).x + 8.0f;
        float bar_w = 160.0f;
        float right_x = win_w - counter_w - bar_w - 16.0f;
        if (right_x > ImGui::GetCursorPosX()) {
            ImGui::SameLine(right_x);
        } else {
            ImGui::SameLine();
        }
        float progress = static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1);
        // Colored progress bar: accent blue fill
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.28f, 0.52f, 0.85f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg,       ImVec4(0.08f, 0.09f, 0.12f, 1.0f));
        ImGui::SetNextItemWidth(bar_w);
        ImGui::ProgressBar(progress, ImVec2(bar_w, btn_h), "");
        ImGui::PopStyleColor(2);
        ImGui::SameLine(0, 4.0f);
        ImGui::TextDisabled("%s", counter);
    }

    ImGui::End();
    ImGui::PopStyleColor(1);  // WindowBg
    ImGui::PopStyleVar(5);    // FramePadding, ItemSpacing, WindowPadding, WindowRounding, WindowBorderSize
}

}  // namespace tenet

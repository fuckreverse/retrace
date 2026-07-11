// gui_chrome.cpp — top-level menu bar + toolbar (the "chrome" around the dockspace).
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal). Needs imgui_internal.h
// for SeparatorEx/ImGuiSeparatorFlags_Vertical used by the toolbar.

#include "gui/gui_app.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "io/recent_files.h"

#include <imgui.h>
#include <imgui_internal.h>

#include "gui/icons/IconsFontAwesome6.h"

#include <fmt/core.h>

#include <ctime>
#include <string>

namespace tenet {

// ─── Menu Bar ───────────────────────────────────────────────────────────────
//
// On macOS the actual system menu bar is the native NSMenu built in
// gui_app.mm::setup_native_menu().  This ImGui menu bar is rendered ONLY
// when the native menu is absent (non-macOS builds, or if the window is
// embedded without an NSApp).  The two implementations must stay in sync.

void GuiApp::render_menu_bar() {
    if (ImGui::BeginMenuBar()) {

        // ╔═══════════════════════════════════╗
        // ║            File menu              ║
        // ╚═══════════════════════════════════╝
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Trace\xe2\x80\xa6", "Cmd+O")) {
                // TODO: file dialog integration
            }

            // ── Recent files sub-menu ──────────────────────────────────────
            auto recent = RecentFiles::load();
            bool has_recent = !recent.empty();
            if (!has_recent) ImGui::BeginDisabled();
            if (ImGui::BeginMenu("Open Recent")) {
                for (const auto& entry : recent.entries()) {
                    std::string display;
                    {
                        auto p = entry.path;
                        auto s2 = p.rfind('/');
                        if (s2 != std::string::npos && s2 > 0) {
                            auto s1 = p.rfind('/', s2 - 1);
                            if (s1 != std::string::npos)
                                p = "\xe2\x80\xa6" + p.substr(s1);  // …/tail
                        }
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
                    if (ImGui::MenuItem(display.c_str()))
                        ImGui::SetClipboardText(entry.path.c_str());
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s\n(path copied to clipboard on click)",
                                          entry.path.c_str());
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Clear Recent Files")) {
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

        // ╔════════════════════════════════════════════════════════════════════╗
        // ║  View menu  —  four sub-menus + Output / Cache at the bottom       ║
        // ╚════════════════════════════════════════════════════════════════════╝
        if (ImGui::BeginMenu("View")) {

            // ── Core Panels ──────────────────────────────────────────────
            if (ImGui::BeginMenu("Core Panels")) {
                ImGui::MenuItem("Registers",  "Cmd+R", &show_registers_);
                ImGui::MenuItem("Memory",     "Cmd+M", &show_memory_);
                ImGui::MenuItem("Hex Dump",   nullptr, &show_hex_dump_);
                ImGui::Separator();
                ImGui::MenuItem("Call Stack", nullptr, &show_callstack_);
                ImGui::MenuItem("Functions",  nullptr, &show_functions_);
                ImGui::MenuItem("Strings",    nullptr, &show_strings_);
                ImGui::MenuItem("Threads",    nullptr, &show_threads_);
                ImGui::Separator();
                ImGui::MenuItem("Analysis",   nullptr, &show_analysis_);
                ImGui::EndMenu();
            }

            // ── Visualization ─────────────────────────────────────────────
            if (ImGui::BeginMenu("Visualization")) {
                ImGui::MenuItem("CFG View",       nullptr, &show_cfg_);
                ImGui::MenuItem("Call Graph",     nullptr, &show_call_graph_);
                ImGui::MenuItem("Minimap",        nullptr, &show_minimap_);
                ImGui::MenuItem("Loop Highlight", nullptr, &show_loops_);
                ImGui::EndMenu();
            }

            // ── Analysis Results ─────────────────────────────────────────
            if (ImGui::BeginMenu("Analysis Results")) {
                ImGui::MenuItem("Patterns",          nullptr, &show_pattern_);
                ImGui::MenuItem("Constants",         nullptr, &show_constant_);
                ImGui::MenuItem("Loop Semantics",    nullptr, &show_loop_semantics_);
                ImGui::MenuItem("Algorithm Summary", nullptr, &show_algorithm_summary_);
                ImGui::Separator();
                ImGui::MenuItem("ObjC Messages",     nullptr, &show_objc_);
                ImGui::MenuItem("ObjC Crypto",       nullptr, &show_objc_crypto_);
                ImGui::MenuItem("API Intercepts",    nullptr, &show_syscall_intercept_);
                ImGui::Separator();
                ImGui::MenuItem("Memory Strings",    nullptr, &show_mem_strings_);
                ImGui::EndMenu();
            }

            // ── Profiling & Diff ──────────────────────────────────────────
            if (ImGui::BeginMenu("Profiling & Diff")) {
                ImGui::MenuItem("Trace Fold",          nullptr, &show_trace_fold_);
                ImGui::MenuItem("Window Stats",        nullptr, &show_window_stats_);
                ImGui::MenuItem("Dataflow Graph",      nullptr, &show_dataflow_graph_);
                ImGui::MenuItem("Register Timeline",   nullptr, &show_reg_timeline_);
                ImGui::MenuItem("Trace Diff",          nullptr, &show_trace_diff_);
                ImGui::Separator();
                ImGui::MenuItem("Symbol Info (DWARF)", nullptr, &show_dwarf_panel_);
                ImGui::EndMenu();
            }

            ImGui::Separator();
            ImGui::MenuItem("Output (Log)",  nullptr, &show_log_);
            ImGui::MenuItem("Cache Manager", nullptr, &show_cache_manager_);
            ImGui::Separator();
            // Developer tools — shown in ImGui menu (not native NSMenu)
            if (ImGui::MenuItem("Settings\xe2\x80\xa6", "Cmd+,"))
                show_settings_ = true;
            ImGui::MenuItem("ImGui Demo", nullptr, &show_demo_window_);
            ImGui::EndMenu();
        }

        // ╔═══════════════════════════════════╗
        // ║          Navigate menu            ║
        // ╚═══════════════════════════════════╝
        if (ImGui::BeginMenu("Navigate")) {
            if (ImGui::MenuItem("Go to Instruction\xe2\x80\xa6", "G"))
                show_goto_popup_ = true;
            if (ImGui::MenuItem("Search\xe2\x80\xa6", "/"))
                show_search_popup_ = true;
            ImGui::Separator();
            {
                bool can_back = can_nav_back();
                bool can_fwd  = can_nav_forward();
                if (!can_back) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Back", "Alt+\xe2\x86\x90")) nav_back();   // ←
                if (!can_back) ImGui::EndDisabled();
                if (!can_fwd)  ImGui::BeginDisabled();
                if (ImGui::MenuItem("Forward", "Alt+\xe2\x86\x92")) nav_forward();  // →
                if (!can_fwd)  ImGui::EndDisabled();
                if (!nav_history_.empty())
                    ImGui::TextDisabled("  history [%zu/%zu]",
                        nav_history_pos_ + 1, nav_history_.size());
            }
            ImGui::Separator();
            if (ImGui::MenuItem("First Instruction", "Home"))
                navigate_to(0);
            if (ImGui::MenuItem("Last Instruction", "End"))
                navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
            ImGui::Separator();
            if (ImGui::MenuItem("Toggle Bookmark", "B"))
                toggle_bookmark();
            ImGui::Separator();
            // Follow call / return (greyed out if unavailable)
            {
                bool has_call = (function_result_ != nullptr &&
                                 function_result_->call_at(current_inst_) != nullptr);
                bool has_ret  = (function_result_ != nullptr &&
                                 (function_result_->return_at(current_inst_) != nullptr ||
                                  !current_call_stack().empty()));
                if (!has_call) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Follow Call", "E")) {
                    auto* evt = function_result_->call_at(current_inst_);
                    if (evt && evt->call_inst_id + 1 < total_inst_)
                        navigate_to(evt->call_inst_id + 1);
                }
                if (!has_call) ImGui::EndDisabled();
                if (!has_ret) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Follow Return", "R")) {
                    if (function_result_) {
                        auto* evt = function_result_->return_at(current_inst_);
                        if (evt) {
                            navigate_to(evt->call_inst_id);
                        } else {
                            const auto& stk = current_call_stack();
                            if (!stk.empty()) navigate_to(stk.back()->call_inst_id);
                        }
                    }
                }
                if (!has_ret) ImGui::EndDisabled();
            }
            ImGui::Separator();
            // Taint jump — always shown; greyed when no active result
            {
                bool has_fwd  = (show_taint_ && taint_result_ != nullptr);
                bool has_back = (show_backward_taint_ && backward_taint_result_ != nullptr);
                if (!has_fwd) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Next Tainted Instruction",    "]"))        jump_taint_next();
                if (ImGui::MenuItem("Prev Tainted Instruction",    "["))        jump_taint_prev();
                if (!has_fwd) ImGui::EndDisabled();
                if (!has_back) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Next Backward-Tainted", "Shift+]"))  jump_backward_taint_next();
                if (ImGui::MenuItem("Prev Backward-Tainted", "Shift+["))  jump_backward_taint_prev();
                if (!has_back) ImGui::EndDisabled();
            }
            ImGui::EndMenu();
        }

        // ╔════════════════════════════════════════════════════════════════════╗
        // ║  Analysis menu  —  sub-menus by category, each triggers a pass run ║
        // ╚════════════════════════════════════════════════════════════════════╝
        if (ImGui::BeginMenu("Analysis")) {

            // ── Data Flow ─────────────────────────────────────────────────
            if (ImGui::BeginMenu("Data Flow")) {
                if (ImGui::MenuItem("Forward Taint\xe2\x80\xa6",  "Cmd+T"))
                    run_taint_analysis();
                if (ImGui::MenuItem("Backward Taint\xe2\x80\xa6", "Cmd+Shift+T"))
                    run_backward_taint_analysis();
                ImGui::Separator();
                if (ImGui::MenuItem("Register Timeline")) {
                    show_reg_timeline_ = true;
                    reg_timeline_dirty_ = true;
                }
                if (ImGui::MenuItem("Producer Chain")) {
                    show_reg_timeline_ = true;
                    run_producer_chain(current_inst_, reg_timeline_reg_);
                }
                ImGui::EndMenu();
            }

            // ── Structure ─────────────────────────────────────────────────
            if (ImGui::BeginMenu("Structure")) {
                if (ImGui::MenuItem("Function Analysis"))  run_pass_by_name("function");
                if (ImGui::MenuItem("Xref Analysis"))      run_pass_by_name("xref");
                if (ImGui::MenuItem("String Analysis"))    run_pass_by_name("strings");
                if (ImGui::MenuItem("Thread Analysis"))    run_pass_by_name("thread");
                ImGui::Separator();
                if (ImGui::MenuItem("Call Graph"))         run_call_graph_analysis();
                if (ImGui::MenuItem("Loop Analysis"))      run_pass_by_name("loop");
                if (ImGui::MenuItem("CFG Layout"))         run_cfg_layout();
                ImGui::EndMenu();
            }

            // ── Crypto & Pattern ──────────────────────────────────────────
            if (ImGui::BeginMenu("Crypto & Pattern")) {
                if (ImGui::MenuItem("Pattern Detection")) {
                    run_pass_by_name("pattern"); show_pattern_ = true;
                }
                if (ImGui::MenuItem("Constants")) {
                    run_pass_by_name("pattern"); show_constant_ = true;
                }
                if (ImGui::MenuItem("Loop Semantics")) {
                    run_pass_by_name("loop_semantics"); show_loop_semantics_ = true;
                }
                if (ImGui::MenuItem("Algorithm Summary")) {
                    run_pass_by_name("algorithm_summary"); show_algorithm_summary_ = true;
                }
                if (ImGui::MenuItem("ObjC Crypto")) {
                    run_pass_by_name("objc_crypto"); show_objc_crypto_ = true;
                }
                ImGui::EndMenu();
            }

            // ── ObjC / Platform API ─────────────────────────────────────────
            if (ImGui::BeginMenu("ObjC / API")) {
                if (ImGui::MenuItem("ObjC Messages")) {
                    run_pass_by_name("objc"); show_objc_ = true;
                }
                if (ImGui::MenuItem("API Intercepts")) {
                    run_pass_by_name("syscall_intercept"); show_syscall_intercept_ = true;
                }
                ImGui::EndMenu();
            }

            // ── Profiling ─────────────────────────────────────────────────
            if (ImGui::BeginMenu("Profiling")) {
                if (ImGui::MenuItem("Trace Fold")) {
                    run_pass_by_name("trace_fold"); show_trace_fold_ = true;
                }
                if (ImGui::MenuItem("Window Stats")) {
                    run_pass_by_name("window_stats"); show_window_stats_ = true;
                }
                if (ImGui::MenuItem("Dataflow Graph\xe2\x80\xa6")) {
                    // Needs a start/end inst_id range — open the panel's
                    // parameter form rather than running immediately (mirrors
                    // how Call Context works from the Tools menu).
                    show_dataflow_graph_ = true;
                    if (dataflow_graph_start_buf_[0] == '\0') {
                        snprintf(dataflow_graph_start_buf_, sizeof(dataflow_graph_start_buf_),
                                 "%llu", (unsigned long long)current_inst_);
                    }
                }
                if (ImGui::MenuItem("Trace Diff")) {
                    show_trace_diff_ = true;
                }
                if (ImGui::MenuItem("Memory Strings")) {
                    run_pass_by_name("memory_strings"); show_mem_strings_ = true;
                }
                ImGui::EndMenu();
            }

            ImGui::Separator();
            // Clear Taint (greyed out when no taint active)
            {
                bool has_taint = (show_taint_ || show_backward_taint_);
                if (!has_taint) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Clear Taint")) {
                    show_taint_ = show_backward_taint_ = false;
                    taint_result_          = nullptr;
                    backward_taint_result_ = nullptr;
                    taint_sorted_ids_dirty_ = true;
                    backward_taint_sorted_ids_dirty_ = true;
                }
                if (!has_taint) ImGui::EndDisabled();
            }
            if (ImGui::MenuItem("Clear All Analysis"))
                clear_analysis();
            ImGui::EndMenu();
        }

        // ╔═══════════════════════════════════╗
        // ║           Export menu             ║
        // ╚═══════════════════════════════════╝
        if (ImGui::BeginMenu("Export")) {
            if (ImGui::MenuItem("Export CFG\xe2\x80\xa6 (DOT)"))
                export_cfg_to_file();
            if (ImGui::MenuItem("Export Call Graph\xe2\x80\xa6 (DOT)"))
                export_call_graph_to_file();
            ImGui::Separator();
            {
                bool has_bt = (backward_taint_result_ != nullptr);
                if (!has_bt) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Export Backward Taint Graph\xe2\x80\xa6 (DOT)"))
                    export_backward_taint_graph_to_file();
                if (!has_bt) ImGui::EndDisabled();
            }
            if (ImGui::MenuItem("Export Dataflow Graph\xe2\x80\xa6 (DOT)")) {
                export_dataflow_graph_to_file();
            }
            if (ImGui::IsItemHovered() && !dataflow_graph_result_) {
                ImGui::SetTooltip("Build a Dataflow Graph first "
                                  "(Analysis > Profiling > Dataflow Graph\xe2\x80\xa6)");
            }
            ImGui::EndMenu();
        }

        // ╔═══════════════════════════════════╗
        // ║            Tools menu             ║
        // ╚═══════════════════════════════════╝
        if (ImGui::BeginMenu("Tools")) {
if (ImGui::MenuItem("Entropy\xe2\x80\xa6")) {
show_entropy_ = true;
if (ctx_mem_addr_ != 0 && entropy_addr_buf_[0] == '\0') {
    snprintf(entropy_addr_buf_, sizeof(entropy_addr_buf_),
             "%llx", (unsigned long long)ctx_mem_addr_);
}
}
            if (ImGui::MenuItem("Memory Snapshot\xe2\x80\xa6")) {
                show_mem_snapshot_ = true;
                if (mem_snapshot_inst_buf_[0] == '\0') {
                    snprintf(mem_snapshot_inst_buf_, sizeof(mem_snapshot_inst_buf_),
                             "%llu", (unsigned long long)current_inst_);
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Memory / Value Search\xe2\x80\xa6")) {
                // Covers both byte-pattern and exact-value/immediate search —
                // literal_search was merged into mem_search.
                show_mem_search_ = true;
            }
#ifdef TENET_HAS_YARA
            if (ImGui::MenuItem("YARA Scan\xe2\x80\xa6")) {
                show_yara_mem_scan_ = true;
            }
#else
            // Greyed out (rather than hidden) so users know the feature
            // exists but requires a rebuild with -DTENET_ENABLE_YARA=ON,
            // instead of clicking it and only then discovering — via a pass
            // failure — that it's unavailable in this build.
            ImGui::BeginDisabled();
            ImGui::MenuItem("YARA Scan\xe2\x80\xa6 (requires TENET_ENABLE_YARA)");
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("This build was compiled with -DTENET_ENABLE_YARA=OFF.\n"
                                  "Rebuild with YARA enabled to use this feature.");
            }
#endif
            ImGui::Separator();
            if (ImGui::MenuItem("Memory Write History\xe2\x80\xa6"))
                show_memory_ = true;
            if (ImGui::MenuItem("Call Context at Cursor\xe2\x80\xa6")) {
                show_call_context_ = true;
                snprintf(call_context_inst_buf_, sizeof(call_context_inst_buf_),
                         "%llu", (unsigned long long)current_inst_);
            }
            if (ImGui::MenuItem("Dataflow Graph from Cursor\xe2\x80\xa6")) {
                show_dataflow_graph_ = true;
                if (dataflow_graph_start_buf_[0] == '\0') {
                    snprintf(dataflow_graph_start_buf_, sizeof(dataflow_graph_start_buf_),
                             "%llu", (unsigned long long)current_inst_);
                }
            }
            ImGui::EndMenu();
        }

        // ── Right-side inst counter ──────────────────────────────────────
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
        if (ImGui::Button(ICON_FA_ARROW_LEFT "##navback", ImVec2(26.0f, btn_h)))
            nav_back();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Back  Alt+\xe2\x86\x90\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        if (!can_back) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!can_fwd) ImGui::BeginDisabled();
        if (ImGui::Button(ICON_FA_ARROW_RIGHT "##navfwd", ImVec2(26.0f, btn_h)))
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

    if (ImGui::Button(ICON_FA_CARET_UP "##stepup", ImVec2(26.0f, btn_h))) {
        if (current_inst_ > 0) navigate_to(current_inst_ - 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous instruction  \xe2\x86\x91");
    ImGui::SameLine();

    if (ImGui::Button(ICON_FA_CARET_DOWN "##stepdn", ImVec2(26.0f, btn_h))) {
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
        if (ImGui::Button(ICON_FA_RIGHT_TO_BRACKET " Enter", ImVec2(0, btn_h))) {
            auto* evt = function_result_->call_at(current_inst_);
            if (evt && evt->call_inst_id + 1 < total_inst_)
                navigate_to(evt->call_inst_id + 1);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Follow call into callee (E)");
        if (!has_call) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!has_ret) ImGui::BeginDisabled();
        if (ImGui::Button(ICON_FA_RIGHT_FROM_BRACKET " Return", ImVec2(0, btn_h))) {
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
            if (ImGui::Button(ICON_FA_CARET_LEFT " T", ImVec2(0, btn_h))) jump_taint_prev();
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev tainted inst ([)");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.28f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.40f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.15f, 0.50f, 0.20f, 1.0f));
            if (ImGui::Button("T " ICON_FA_CARET_RIGHT, ImVec2(0, btn_h))) jump_taint_next();
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next tainted inst (])");
            ImGui::SameLine();
        }
        if (show_backward_taint_ && backward_taint_result_) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button(ICON_FA_CARET_LEFT " BT", ImVec2(0, btn_h))) jump_backward_taint_prev();
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev backward-tainted inst");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button("BT " ICON_FA_CARET_RIGHT, ImVec2(0, btn_h))) jump_backward_taint_next();
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next backward-tainted inst");
            ImGui::SameLine();
        }
        ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::PopStyleColor();
        ImGui::SameLine();
    }

    // ── GROUP 4.5: VM Abstract quick access ──────────────────────────
    // Previously the only way to reach the VM Workspace was several menu
    // levels deep (Analysis > Reverse Eng / VM > VM Abstract Analysis, then
    // load hints, then "Open Workspace"). This toolbar shortcut collapses
    // that into a single always-visible click:
    //   - No result yet → opens the hints popup directly (skips the legacy
    //     panel entirely).
    //   - Result available → jumps straight into the VM Workspace.
    {
        bool has_vm_result = (vm_abstract_result_ != nullptr);
        ImVec4 vm_btn_col = has_vm_result
            ? ImVec4(0.15f, 0.35f, 0.55f, 0.90f)
            : ImVec4(0.30f, 0.30f, 0.36f, 0.70f);
        ImGui::PushStyleColor(ImGuiCol_Button, vm_btn_col);
        if (has_vm_result) {
            if (ImGui::Button(ICON_FA_MICROCHIP " VM Workspace", ImVec2(0, btn_h))) {
                vm_ws_open_        = true;
                vm_ws_first_frame_ = true;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Open the VM Workspace (IDA-style VM view)");

            ImGui::SameLine();
            if (ImGui::Button(ICON_FA_FILE_LINES "##vm_hints_quick", ImVec2(26.0f, btn_h))) {
                show_vm_hints_popup_ = true;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Load a different VM hints file");
        } else {
            if (ImGui::Button(ICON_FA_MICROCHIP " VM Hints...", ImVec2(0, btn_h))) {
                show_vm_hints_popup_ = true;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip(
                    "Load static-analysis hints (dispatcher PC, handler "
                    "entries, ...) to detect and explore a VM dispatcher.\n"
                    "Drag & drop the hints .json file, or click to browse.");
        }
        ImGui::PopStyleColor();

        ImGui::SameLine();
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
                          (show_loops_ && loop_result_);

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
        if (show_loops_ && loop_result_) {
                char loop_label[32];
                snprintf(loop_label, sizeof(loop_label), ICON_FA_ARROW_ROTATE_LEFT " %zu LOOPS",
                         loop_result_->loops.size());
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

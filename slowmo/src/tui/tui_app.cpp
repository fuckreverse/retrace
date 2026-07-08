#include "tui/tui_app.h"
#include "tui/panels/register_panel.h"
#include "tui/panels/memory_panel.h"
#include "tui/panels/callstack_panel.h"
#include "tui/panels/functions_panel.h"
#include "tui/panels/strings_panel.h"
#include "tui/panels/thread_panel.h"
#include "tui/panels/breakpoint_panel.h"
#include "tui/panels/results_panel.h"
#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/memory/string_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/misc/thread_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/crypto/algorithm_summary_pass.h"
#include "analysis/passes/crypto/objc_crypto_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/platform/syscall_intercept_pass.h"
#include "analysis/passes/memory/memory_string_pass.h"
#include "analysis/passes/memory/entropy_pass.h"
#include "analysis/passes/memory/mem_search_pass.h"
#include "analysis/passes/memory/memory_snapshot_pass.h"
#include "analysis/passes/memory/yara_mem_scan_pass.h"
#include "analysis/passes/profile/trace_fold_pass.h"
#include "analysis/passes/profile/reg_timeline_pass.h"
#include "analysis/passes/profile/call_context_pass.h"
#include "analysis/passes/profile/window_stats_pass.h"
#include "analysis/passes/profile/trace_diff_pass.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "analysis/passes/taint/taint_source_annotation_pass.h"
#include "analysis/passes/misc/thread_filter_pass.h"
#include "analysis/passes/vm/vm_abstract_pass.h"
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <fmt/core.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>

namespace tenet {

using namespace ftxui;

// ─── Helpers ──────────────────────────────────────────────────────────────

static std::string tui_reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == 29) return "fp";
    if (idx == 30) return "lr";
    if (idx == 31) return "sp";
    if (idx == 32) return "nzcv";
    if (idx == 33) return "pc";
    return "??";
}

static Color inst_color(const std::string& disasm) {
    if (disasm.find("b.") == 0 || disasm.find("b ") == 0 || disasm.find("cb") == 0 || disasm.find("tb") == 0)
        return Color::Yellow;
    if (disasm.find("ret") == 0 || disasm.find("blr") == 0 || disasm.find("br") == 0)
        return Color::Magenta;
    if (disasm.find("ldr") == 0 || disasm.find("ldp") == 0)
        return Color::Cyan;
    if (disasm.find("str") == 0 || disasm.find("stp") == 0)
        return Color::Red;
    if (disasm.find("svc") == 0)
        return Color::Green;
    return Color::White;
}

// ─── Constructor ────────────────────────────────────────────────────────────

TuiApp::TuiApp(TenetService& service)
    : reader_(service.reader()), index_(service.index()),
      code_table_(service.code_table()), decoder_(service.decoder()),
      regfile_(service.regfile()), memory_(service.memory()),
      screen_(ScreenInteractive::Fullscreen()),
      service_(&service) {
    // Initialize shared context
    ctx_.reader = &reader_;
    ctx_.index = &index_;
    ctx_.code_table = &code_table_;
    ctx_.decoder = &decoder_;
    ctx_.regfile = &regfile_;
    ctx_.memory = &memory_;
    ctx_.service = service_;
    ctx_.fetch_row = &TuiApp::fetch_row_trampoline;
    ctx_.fetch_row_self = this;
    ctx_.navigate_to_fn = &TuiApp::navigate_to_trampoline;
    ctx_.navigate_self = this;
    ctx_.run_pass_fn = &TuiApp::run_pass_trampoline;
    ctx_.run_pass_self = this;

    // Derive navigation state from service
    total_inst_ = service_->total_inst();
    current_inst_ = service_->current_inst();
    ctx_.bookmarks = service_->bookmarks();

    int h = screen_.dimy();
    viewport_height_ = (h > 6) ? h - 4 : 20;
    if (current_inst_ > 0) update_viewport();

    // Initialize hex dump view
    hex_dump_view_ = std::make_unique<HexDumpView>(memory_);
    hex_dump_view_->set_time(0);
    hex_dump_view_->set_address(0);

    // Create panels
    register_panel_ = std::make_unique<RegisterPanel>(ctx_);
    memory_panel_ = std::make_unique<MemoryPanel>(ctx_);
    callstack_panel_ = std::make_unique<CallstackPanel>(ctx_);
    functions_panel_ = std::make_unique<FunctionsPanel>(ctx_);
    strings_panel_ = std::make_unique<StringsPanel>(ctx_);
    thread_panel_ = std::make_unique<ThreadPanel>(ctx_);
    results_panel_ = std::make_unique<ResultsPanel>(ctx_);

    right_panels_ = {
        register_panel_.get(),
        memory_panel_.get(),
        callstack_panel_.get(),
        functions_panel_.get(),
        strings_panel_.get(),
        thread_panel_.get(),
        results_panel_.get(),
    };

    init_key_bindings();
}

void TuiApp::sync_context() {
    // Panels read from ctx_ directly (total_inst, current_inst, viewport_top,
    // viewport_height are reference aliases into ctx_). Sync other fields:
    ctx_.show_taint = show_taint_;
    ctx_.show_backward_taint = show_backward_taint_;
    ctx_.show_nzcv = show_nzcv_;
    ctx_.show_fpr = show_fpr_;
    ctx_.pass_manager = service_->pass_manager();
}

void TuiApp::focus_panel(Panel* p) {
    if (focused_panel_) focused_panel_->set_focused(false);
    focused_panel_ = p;
    if (p) p->set_focused(true);
}

// ─── Row fetching ───────────────────────────────────────────────────────────

InstructionRow TuiApp::fetch_row(uint64_t inst_id) {
    return service_->fetch_row(inst_id);
}

std::vector<InstructionRow> TuiApp::fetch_viewport_rows() {
    std::vector<InstructionRow> rows;
    rows.reserve(viewport_height_);
    for (int i = 0; i < viewport_height_; i++) {
        uint64_t id = viewport_top_ + i;
        if (id >= total_inst_) break;
        rows.push_back(fetch_row(id));
    }
    return rows;
}

// ─── Rendering ──────────────────────────────────────────────────────────────

Element TuiApp::render_instruction_list() {
    auto rows = fetch_viewport_rows();

    Elements lines;
    for (auto& row : rows) {
        bool is_cursor = (row.inst_id == current_inst_);
        bool is_search_hit = search_active_ &&
            search_current_ < search_results_.size() &&
            search_results_[search_current_] == row.inst_id;
bool is_tainted = show_taint_ && ctx_.taint_result && ctx_.taint_result->has_event_at(row.inst_id);
bool is_backward_tainted = show_backward_taint_ && ctx_.backward_taint_result &&
            ctx_.backward_taint_result->is_contributing(row.inst_id);

        // Loop state
        bool is_loop_header = show_loops_ && ctx_.loop_result && ctx_.loop_result->is_loop_header(row.pc);
        uint32_t loop_depth = (show_loops_ && ctx_.loop_result) ? ctx_.loop_result->loop_depth_at(row.pc) : 0;
        bool is_in_loop = loop_depth > 0;

        // Marker column: show loop indicator when relevant
        std::string marker_str;
        if (is_cursor)              marker_str = ">";
        else if (is_loop_header)    marker_str = "\xE2\x87\x86";   // ⇆ loop head
        else if (is_in_loop)        marker_str = "\xE2\x86\xBA";   // ↺ loop body
        else                        marker_str = " ";

        Color marker_color = is_cursor ? Color::Yellow
                           : is_loop_header ? Color::RGB(255, 140, 30)
                           : is_in_loop ? Color::RGB(180, 100, 30)
                           : Color::GrayDark;

        auto marker = text(marker_str) | color(marker_color);
        auto bookmark = text(row.has_bookmark ? "*" : " ");

        auto id_text = text(fmt::format("{:>8}", row.inst_id));
        auto pc_text = text(fmt::format("{:016x}", row.static_pc));
        auto disasm_text = text(row.disasm) | color(inst_color(row.disasm));

        Element line = hbox({
            marker,
            bookmark | color(Color::Red),
            text(" ") | size(WIDTH, EQUAL, 1),
            id_text | color(Color::GrayDark),
            text(" ") | size(WIDTH, EQUAL, 1),
            pc_text | color(Color::Cyan),
            text("  ") | size(WIDTH, EQUAL, 2),
            disasm_text,
        });

        if (is_cursor) {
            line = line | bgcolor(Color::GrayDark);
} else if (is_backward_tainted) {
line = line | bgcolor(Color::RedLight);
} else if (is_tainted) {
            line = line | bgcolor(Color::Green);
        } else if (is_search_hit) {
            line = line | bgcolor(Color::Blue);
        } else if (is_loop_header) {
            // Loop header: orange-brown background
            line = line | bgcolor(Color::RGB(80, 40, 5));
        } else if (is_in_loop) {
            // Loop body: depth-shaded dark amber
            int intensity = std::min(static_cast<int>(loop_depth - 1) * 12, 36);
            line = line | bgcolor(Color::RGB(45 + intensity, 25, 5));
        }

        lines.push_back(line);

        // Memory access lines (if enabled)
        if (show_mem_ && row.mem_access_count > 0) {
            auto [offset, seed_pc_mi] = index_.offset_of_with_pc(row.inst_id, reader_);
            auto rec = reader_.record_at(offset, seed_pc_mi);
            auto inst = rec.as_inst();
            for (uint8_t i = 0; i < inst.mem_access_count; i++) {
                auto mem = inst.mem_access(i);
                const char* type_str = (mem.type & 2) ? "W" : "R";
                auto mem_line = hbox({
                    text("          ") | size(WIDTH, EQUAL, 10),
                    text(fmt::format("[{}] 0x{:x} size={} val=0x{:x}",
                                     type_str, mem.addr, mem.size, mem.value))
                        | color(Color::GrayLight),
                });
                lines.push_back(mem_line);
            }
        }
    }

    return vbox(lines) | flex | frame;
}

Element TuiApp::render_status_bar() {
    std::string mode_str;
    Color mode_color = Color::Blue;

    if (show_cmd_dialog_) {
        mode_str = " CMD ";
        mode_color = Color::RGB(200, 100, 0);  // orange for command mode
    } else if (show_goto_dialog_) {
        mode_str = " GOTO ";
    } else if (show_search_dialog_) {
        mode_str = " SEARCH ";
    } else if (show_string_search_dialog_) {
        mode_str = " STR-FILTER ";
    } else if (show_function_filter_dialog_) {
        mode_str = " FUNC-FILTER ";
    } else if (breakpoint_panel_->focused() && breakpoint_panel_->visible()) {
        mode_str = " BREAKPOINTS ";
        mode_color = Color::Red;
    } else if (results_panel_->focused() && results_panel_->visible()) {
        mode_str = " RESULTS ";
        mode_color = Color::RGB(0, 130, 130);
    } else if (callstack_panel_->focused()) {
        mode_str = " CALLSTACK ";
    } else if (memory_panel_->focused()) {
        mode_str = " MEMORY ";
    } else if (strings_panel_->focused()) {
        mode_str = " STRINGS ";
    } else if (functions_panel_->focused()) {
        mode_str = " FUNCTIONS ";
    } else if (hex_dump_focused_) {
        mode_str = " HEX-DUMP ";
    } else if (search_active_) {
        mode_str = fmt::format(" SEARCH [{}/{}] ", search_current_ + 1, search_results_.size());
    } else if (show_backward_taint_) {
        if (!taint_jump_list_.empty())
            mode_str = fmt::format(" BACK-TAINT [{}/{}] ", taint_jump_cursor_ + 1, taint_jump_list_.size());
        else
            mode_str = " BACK-TAINT ";
    } else if (show_taint_) {
        if (!taint_jump_list_.empty())
            mode_str = fmt::format(" TAINT [{}/{}] ", taint_jump_cursor_ + 1, taint_jump_list_.size());
        else
            mode_str = " TAINT ";
    } else {
        // Show breakpoint count if any are set
        if (bp_engine_ && bp_engine_->has_breakpoints()) {
            mode_str = fmt::format(" NORMAL [{}bp] ", bp_engine_->entries().size());
            mode_color = Color::RGB(180, 50, 50);
        } else {
            mode_str = " NORMAL ";
        }
    }

    // Navigation history indicator: [pos/total]
    std::string nav_str;
    if (nav_history_.size() > 1) {
        nav_str = fmt::format("  hist[{}/{}]", nav_history_pos_ + 1, nav_history_.size());
    }

    auto left = hbox({
        text(mode_str) | bgcolor(mode_color) | color(Color::White),
        text(fmt::format("  inst {:>8} / {:<8}  pc={:016x}{}",
                         current_inst_, total_inst_,
                         fetch_row(current_inst_).static_pc,
                         nav_str))
            | color(Color::White),
    });

    // Compact help line — shows the most important new bindings
    auto right = text("j/k:nav g:goto /:srch b:bkm  \":\"cmd(:b/:w/:rc/:rb)  "
                      "t/S/B/C:analysis [/]:taint {/}:hist p:mem P:stk f/F L I O V H A q")
        | color(Color::GrayLight);

    // If there is a bp_status_msg_, show it as a second info line
    if (!bp_status_msg_.empty()) {
        auto msg_line = hbox({
            text(" ► ") | color(Color::Red) | bold,
            text(bp_status_msg_) | color(Color::Yellow),
        }) | bgcolor(Color::RGB(30, 10, 10)) | size(HEIGHT, EQUAL, 1);
        return vbox({
            hbox({left | flex, right}) | bgcolor(Color::Black) | size(HEIGHT, EQUAL, 1),
            msg_line,
        });
    }

    if (!cmd_error_.empty()) {
        auto err_line = hbox({
            text(" ! ") | color(Color::White) | bold | bgcolor(Color::Red),
            text(" " + cmd_error_) | color(Color::Red),
        }) | bgcolor(Color::RGB(30, 0, 0)) | size(HEIGHT, EQUAL, 1);
        return vbox({
            hbox({left | flex, right}) | bgcolor(Color::Black) | size(HEIGHT, EQUAL, 1),
            err_line,
        });
    }

    return hbox({left | flex, right}) | bgcolor(Color::Black) | size(HEIGHT, EQUAL, 1);
}

Element TuiApp::render_hex_dump_panel() {
    if (!hex_dump_view_) {
        return text("(hex dump not available)") | color(Color::GrayLight) | border;
    }

    // Update the time point to match the current instruction
    hex_dump_view_->set_time(current_inst_);

    // Render the hex dump with a focus indicator
    auto content = hex_dump_view_->render();
    if (hex_dump_focused_) {
        // Add a visual indicator that hex dump has focus
        auto focus_bar = hbox({
            text(" [HEX DUMP FOCUSED] ") | bgcolor(Color::Blue) | color(Color::White) | bold,
            text(" ↑↓:scroll PgUp/Dn:page g:goto </>:time-nav Esc:unfocus") | color(Color::GrayLight),
        });
        return vbox({focus_bar, content | flex}) | flex;
    }
    return content;
}

Element TuiApp::render_main_layout() {
    sync_context();

    // Render visible right-side panels via the panel registry
    Elements panel_elements;
    for (auto* p : right_panels_) {
        if (p && p->visible()) {
            panel_elements.push_back(p->render());
        }
    }
    // Breakpoint panel (lazily created, may be null)
    if (breakpoint_panel_ && breakpoint_panel_->visible()) {
        panel_elements.push_back(breakpoint_panel_->render());
    }

    // Build center content: instruction list with optional minimap on the left
    Element center;
    if (show_minimap_) {
        center = hbox({
            render_minimap_column(),
            render_instruction_list() | flex,
        });
    } else {
        center = render_instruction_list() | flex;
    }

    auto main = hbox({
        center | flex,
        vbox(panel_elements) | size(WIDTH, LESS_THAN, 50),
    });

    // If hex dump is visible, show it below the main content area
    if (show_hex_dump_ && hex_dump_view_) {
        auto hex_panel = render_hex_dump_panel() | size(HEIGHT, LESS_THAN, viewport_height_ / 2 + 4);
        return vbox({
            main | flex,
            hex_panel,
            render_status_bar(),
        });
    }

    return vbox({
        main | flex,
        render_status_bar(),
    });
}

// ─── Navigation ─────────────────────────────────────────────────────────────

void TuiApp::nav_push(uint64_t inst_id) {
    if (nav_history_navigating_) return;
    // Truncate forward history when navigating to a new location
    if (!nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1) {
        nav_history_.erase(
            nav_history_.begin() + static_cast<ptrdiff_t>(nav_history_pos_) + 1,
            nav_history_.end());
    }
    // Don't push duplicates
    if (!nav_history_.empty() && nav_history_.back() == inst_id) return;
    nav_history_.push_back(inst_id);
    if (nav_history_.size() > kMaxNavHistory) {
        nav_history_.erase(nav_history_.begin());
    }
    nav_history_pos_ = nav_history_.size() - 1;
}

void TuiApp::nav_back() {
if (!service_->can_nav_back()) return;
service_->nav_back();
current_inst_ = service_->current_inst();
update_viewport();
}

void TuiApp::nav_forward() {
if (!service_->can_nav_forward()) return;
service_->nav_forward();
current_inst_ = service_->current_inst();
update_viewport();
}

void TuiApp::navigate_to(uint64_t inst_id) {
service_->navigate_to(inst_id);
current_inst_ = service_->current_inst();
update_viewport();
}

void TuiApp::navigate_relative(int64_t delta) {
    if (delta > 0 && current_inst_ + static_cast<uint64_t>(delta) >= total_inst_) {
        current_inst_ = total_inst_ > 0 ? total_inst_ - 1 : 0;
    } else if (delta < 0 && current_inst_ < static_cast<uint64_t>(-delta)) {
        current_inst_ = 0;
    } else {
        current_inst_ = static_cast<uint64_t>(static_cast<int64_t>(current_inst_) + delta);
    }
    update_viewport();
}

void TuiApp::update_viewport() {
    // Keep cursor within viewport, scroll if needed
    if (current_inst_ < viewport_top_) {
        viewport_top_ = current_inst_;
    } else if (current_inst_ >= viewport_top_ + static_cast<uint64_t>(viewport_height_)) {
        viewport_top_ = current_inst_ - static_cast<uint64_t>(viewport_height_) + 1;
    }
}

void TuiApp::handle_resize() {
    int h = screen_.dimy();
    viewport_height_ = (h > 6) ? h - 4 : 20;
    update_viewport();
}

// ─── Search ─────────────────────────────────────────────────────────────────

void TuiApp::search_forward(const std::string& query) {
    search_query_ = query;
    search_results_.clear();
    search_current_ = 0;
    search_active_ = false;

    if (query.empty()) return;

    // Simple linear search (can be optimized with PC index in M4)
    for (uint64_t i = 0; i < total_inst_ && i < 1000000; i++) {
        auto row = fetch_row(i);
        if (row.disasm.find(query) != std::string::npos) {
            search_results_.push_back(i);
        }
    }

    if (!search_results_.empty()) {
        search_active_ = true;
        navigate_to(search_results_[0]);
    }
}

void TuiApp::search_next() {
    if (!search_active_ || search_results_.empty()) return;
    search_current_ = (search_current_ + 1) % search_results_.size();
    navigate_to(search_results_[search_current_]);
}

void TuiApp::search_prev() {
    if (!search_active_ || search_results_.empty()) return;
    search_current_ = (search_current_ + search_results_.size() - 1) % search_results_.size();
    navigate_to(search_results_[search_current_]);
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

void TuiApp::toggle_bookmark() {
service_->toggle_bookmark(current_inst_);
ctx_.bookmarks = service_->bookmarks();
}

// ─── Breakpoint Engine ──────────────────────────────────────────────────────

void TuiApp::ensure_bp_engine() {
    if (!bp_engine_) {
        bp_engine_ = std::make_unique<BreakpointEngine>(reader_, index_, regfile_, memory_);
    }
}

// ─── Command-mode dialog (':', like vim ex-commands) ─────────────────────────
// Supported commands:
//   b <addr>          — set PC breakpoint at <addr>
//   w <addr> [size]   — set write watchpoint at <addr> (size 1-64, 0=whole page)
//   d <id>            — delete breakpoint by id
//   bl                — list all active breakpoints
//   rc                — run (continue) forward to next breakpoint
//   rb                — run backward to previous breakpoint
//   bc                — clear all breakpoints

void TuiApp::open_cmd_dialog() {
    show_cmd_dialog_ = true;
    cmd_input_.clear();
    cmd_error_.clear();
}

void TuiApp::close_cmd_dialog() {
    show_cmd_dialog_ = false;
    cmd_input_.clear();
}

void TuiApp::execute_cmd() {
    cmd_error_.clear();

    // Trim leading whitespace
    size_t start = cmd_input_.find_first_not_of(" \t");
    if (start == std::string::npos) {
        close_cmd_dialog();
        return;
    }
    std::string trimmed = cmd_input_.substr(start);

    // Multi-letter commands (must check before single-letter)
    if (trimmed == "rc") {
        close_cmd_dialog();
        cmd_run_forward();
        return;
    }
    if (trimmed == "rb") {
        close_cmd_dialog();
        cmd_run_backward();
        return;
    }
    if (trimmed == "bl") {
        cmd_list_breakpoints();
        close_cmd_dialog();
        return;
    }
    if (trimmed == "bc") {
        ensure_bp_engine();
        bp_engine_->clear_breakpoints();
        bp_status_msg_ = "All breakpoints cleared.";
        close_cmd_dialog();
        return;
    }

    // ── Pass commands: ':pass <name>', ':passes', ':analyze' ──────────
    // These make every catalog pass reachable from the TUI.
    if (trimmed.rfind("pass ", 0) == 0) {
        std::string pname = trimmed.substr(5);
        // trim
        auto e = pname.find_last_not_of(" \t");
        if (e != std::string::npos) pname.erase(e + 1);
        auto s = pname.find_first_not_of(" \t");
        if (s != std::string::npos) pname.erase(0, s); else pname.clear();
        if (pname.empty()) {
            cmd_error_ = "usage: pass <name>  (use ':passes' to list)";
        } else {
            run_pass_by_name(pname);
            bp_status_msg_ = last_pass_status_;
        }
        close_cmd_dialog();
        return;
    }
    if (trimmed == "passes") {
        std::string msg = "Available passes (use ':pass <name>'):";
        for (const auto& e : tenet::pass_catalog()) {
            msg += fmt::format("\n  {:<24} {}", e.name, e.description);
        }
        bp_status_msg_ = msg;
        close_cmd_dialog();
        return;
    }
    if (trimmed == "analyze") {
        run_default_analysis();
        bp_status_msg_ = last_pass_status_;
        close_cmd_dialog();
        return;
    }

    // Single-letter commands with argument
    char cmd_char = trimmed[0];

    if (cmd_char == 'd' || cmd_char == 'D') {
        // Delete breakpoint: "d <id>"
        std::string_view sv(trimmed.c_str() + 1);
        while (!sv.empty() && (sv[0] == ' ' || sv[0] == '\t')) sv.remove_prefix(1);
        uint64_t id = 0;
        auto [p, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), id);
        if (ec != std::errc{}) {
            cmd_error_ = fmt::format("invalid breakpoint id '{}'", std::string(sv));
            return;
        }
        cmd_delete_breakpoint(static_cast<uint32_t>(id));
        close_cmd_dialog();
        return;
    }

    // Delegate to parse_breakpoint_cmd for 'b' and 'w'
    std::string parse_err;
    auto spec = parse_breakpoint_cmd(trimmed, &parse_err);
    if (!spec) {
        cmd_error_ = parse_err.empty() ? "unknown command" : parse_err;
        return;
    }
    ensure_bp_engine();
    BreakpointId id = bp_engine_->add_breakpoint(std::move(*spec));

    // Build confirmation message
    std::visit([&](const auto& s) {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, PcBreakpoint>) {
            bp_status_msg_ = fmt::format("BP#{} set: PC=0x{:x}", id, s.address);
        } else if constexpr (std::is_same_v<T, WatchBreakpoint>) {
            if (s.size == 0)
                bp_status_msg_ = fmt::format("BP#{} set: watch 0x{:x} (whole page)", id, s.address);
            else
                bp_status_msg_ = fmt::format("BP#{} set: watch 0x{:x}+{}", id, s.address, s.size);
        } else {
            bp_status_msg_ = fmt::format("BP#{} set", id);
        }
    }, *spec);

    close_cmd_dialog();
}

void TuiApp::cmd_run_forward() {
    ensure_bp_engine();
    if (!bp_engine_->has_breakpoints()) {
        bp_status_msg_ = "No breakpoints set. Use ':b <addr>' or ':w <addr> [size]'.";
        return;
    }
    auto hit = bp_engine_->run_forward(current_inst_);
    if (hit) {
        bp_status_msg_ = hit->description;
        navigate_to(hit->inst_id);
    } else {
        bp_status_msg_ = "No breakpoint hit forward from inst #" + std::to_string(current_inst_);
    }
}

void TuiApp::cmd_run_backward() {
    ensure_bp_engine();
    if (!bp_engine_->has_breakpoints()) {
        bp_status_msg_ = "No breakpoints set. Use ':b <addr>' or ':w <addr> [size]'.";
        return;
    }
    auto hit = bp_engine_->run_backward(current_inst_);
    if (hit) {
        bp_status_msg_ = hit->description;
        navigate_to(hit->inst_id);
    } else {
        bp_status_msg_ = "No breakpoint hit backward from inst #" + std::to_string(current_inst_);
    }
}

void TuiApp::cmd_list_breakpoints() {
    ensure_bp_engine();
    const auto& entries = bp_engine_->entries();
    if (entries.empty()) {
        bp_status_msg_ = "No active breakpoints.";
        return;
    }
    std::string msg;
    for (const auto& e : entries) {
        std::visit([&](const auto& s) {
            using T = std::decay_t<decltype(s)>;
            if constexpr (std::is_same_v<T, PcBreakpoint>) {
                msg += fmt::format("  BP#{} PC=0x{:x}\n", e.id, s.address);
            } else if constexpr (std::is_same_v<T, WatchBreakpoint>) {
                if (s.size == 0)
                    msg += fmt::format("  BP#{} watch 0x{:x} (page)\n", e.id, s.address);
                else
                    msg += fmt::format("  BP#{} watch 0x{:x}+{}\n", e.id, s.address, s.size);
            } else if constexpr (std::is_same_v<T, ConditionalBreakpoint>) {
                msg += fmt::format("  BP#{} cond '{}'\n", e.id, s.description);
            }
        }, e.spec);
    }
    bp_status_msg_ = msg.empty() ? "No active breakpoints." : msg;
    breakpoint_panel_->set_visible(true);
}

void TuiApp::cmd_delete_breakpoint(uint32_t id) {
    ensure_bp_engine();
    if (bp_engine_->remove_breakpoint(id)) {
        bp_status_msg_ = fmt::format("BP#{} removed.", id);
    } else {
        bp_status_msg_ = fmt::format("No breakpoint with id {}.", id);
    }
}

// ─── Dialogs ────────────────────────────────────────────────────────────────

void TuiApp::open_goto_dialog() {
    show_goto_dialog_ = true;
    goto_input_.clear();
}

void TuiApp::close_goto_dialog() {
    show_goto_dialog_ = false;
    goto_input_.clear();
}

void TuiApp::execute_goto() {
    try {
        uint64_t target = std::stoull(goto_input_);
        navigate_to(target);
    } catch (...) {
        // invalid input, ignore
    }
    close_goto_dialog();
}

void TuiApp::open_search_dialog() {
    show_search_dialog_ = true;
    search_input_.clear();
}

void TuiApp::close_search_dialog() {
    show_search_dialog_ = false;
    search_input_.clear();
}

void TuiApp::execute_search() {
    search_forward(search_input_);
    close_search_dialog();
}

// ─── Unified event handlers (single source of truth) ────────────────────────

bool TuiApp::handle_hex_dump_event(Event event) {
    if (!hex_dump_view_) return false;

    if (event == Event::Escape) {
        hex_dump_focused_ = false;
        return true;
    }
    // Cursor movement: h/l or left/right for byte-level navigation
    if (event == Event::Character('h') || event == Event::ArrowLeft) {
        hex_dump_view_->cursor_left();
        return true;
    }
    if (event == Event::Character('l') || event == Event::ArrowRight) {
        hex_dump_view_->cursor_right();
        return true;
    }
    // Row movement: j/k or up/down
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        hex_dump_view_->cursor_down();
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        hex_dump_view_->cursor_up();
        return true;
    }
    if (event == Event::PageDown) {
        hex_dump_view_->page_down();
        return true;
    }
    if (event == Event::PageUp) {
        hex_dump_view_->page_up();
        return true;
    }
    // Enter: jump to the instruction that last wrote the byte under cursor
    if (event == Event::Return) {
        uint64_t writer = hex_dump_view_->selected_last_writer();
        if (writer > 0) {
            navigate_to(writer);
            hex_dump_focused_ = false;  // Switch focus back to instruction view
        }
        return true;
    }
    if (event == Event::Character('g')) {
        auto [offset, seed_pc_g] = index_.offset_of_with_pc(current_inst_, reader_);
        auto rec = reader_.record_at(offset, seed_pc_g);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            if (inst.mem_access_count > 0) {
                hex_dump_view_->goto_address(inst.mem_access(0).addr);
            }
        }
        return true;
    }
    if (event == Event::Character('<') || event == Event::Character(',')) {
        hex_dump_view_->step_backward();
        return true;
    }
    if (event == Event::Character('>') || event == Event::Character('.')) {
        hex_dump_view_->step_forward();
        return true;
    }
    return false;
}

// ─── Key binding initialization (data-driven normal-mode dispatch) ──────────
//
// All simple key→action mappings are registered here, replacing the former
// 300+ line if-else chain. Complex bindings with multi-step logic are kept
// as lambdas. The registry is evaluated in insertion order; first match wins.

void TuiApp::init_key_bindings() {
    using Event = ftxui::Event;

    // ─── Quit ────────────────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('q'), [this] {
        screen_.ExitLoopClosure()(); return true;
    }, "quit");
    normal_keys_.bind(Event::Character('Q'), [this] {
        screen_.ExitLoopClosure()(); return true;
    }, "quit");

    // ─── Navigation ──────────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('j'), [this] { navigate_relative(1); return true; }, "down");
    normal_keys_.bind(Event::ArrowDown,      [this] { navigate_relative(1); return true; }, "down");
    normal_keys_.bind(Event::Character('k'), [this] { navigate_relative(-1); return true; }, "up");
    normal_keys_.bind(Event::ArrowUp,        [this] { navigate_relative(-1); return true; }, "up");
    normal_keys_.bind(Event::Character('K'), [this] {
        if (current_inst_ > 0) navigate_to(current_inst_ - 1);
        return true;
    }, "reverse step");
    normal_keys_.bind(Event::Character('G'), [this] {
        navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0); return true;
    }, "goto end");
    normal_keys_.bind(Event::Character('0'), [this] { navigate_to(0); return true; }, "goto start");
    normal_keys_.bind(Event::Character(' '), [this] {
        navigate_relative(viewport_height_ / 2); return true;
    }, "page down");
    normal_keys_.bind(Event::Character('d'), [this] {
        navigate_relative(viewport_height_ / 2); return true;
    }, "page down");
    normal_keys_.bind(Event::Character('u'), [this] {
        navigate_relative(-(viewport_height_ / 2)); return true;
    }, "page up");

    // ─── Dialogs ─────────────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('g'), [this] { open_goto_dialog(); return true; }, "goto");
    normal_keys_.bind(Event::Character('/'), [this] { open_search_dialog(); return true; }, "search");
    normal_keys_.bind(Event::Character(':'), [this] { open_cmd_dialog(); return true; }, "command");

    // ─── Search navigation ───────────────────────────────────────────────
    normal_keys_.bind(Event::Character('n'), [this] { search_next(); return true; }, "search next");
    normal_keys_.bind(Event::Character('N'), [this] { search_prev(); return true; }, "search prev");

    // ─── Bookmarks ───────────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('b'), [this] { toggle_bookmark(); return true; }, "bookmark");

    // ─── UI toggles ──────────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('r'), [this] { register_panel_->set_visible(!register_panel_->visible()); return true; }, "regs");
    normal_keys_.bind(Event::Character('m'), [this] { show_mem_ = !show_mem_; return true; }, "mem inline");
    normal_keys_.bind(Event::Character('M'), [this] { memory_panel_->set_visible(!memory_panel_->visible()); return true; }, "mem panel");
    normal_keys_.bind(Event::Character('z'), [this] { show_nzcv_ = !show_nzcv_; return true; }, "nzcv");
    normal_keys_.bind(Event::Character('V'), [this] { show_fpr_ = !show_fpr_; return true; }, "FPR/NEON");
    normal_keys_.bind(Event::Character('R'), [this] { service_->clear_row_cache(); return true; }, "refresh cache");

    // ─── Hex dump ────────────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('H'), [this] {
        show_hex_dump_ = !show_hex_dump_;
        if (show_hex_dump_ && hex_dump_view_) {
            hex_dump_focused_ = false;
            auto [offset, seed_pc_hd] = index_.offset_of_with_pc(current_inst_, reader_);
            auto rec = reader_.record_at(offset, seed_pc_hd);
            if (rec.kind == RecordKind::Inst) {
                auto inst = rec.as_inst();
                if (inst.mem_access_count > 0) {
                    hex_dump_view_->goto_address(inst.mem_access(0).addr);
                }
            }
            hex_dump_view_->set_time(current_inst_);
        }
        return true;
    }, "hex dump");
    normal_keys_.bind_if(Event::Tab,
        [this] { return show_hex_dump_; },
        [this] { hex_dump_focused_ = !hex_dump_focused_; return true; },
        "hex focus toggle");

    // ─── Analysis passes ─────────────────────────────────────────────────
normal_keys_.bind(Event::Character('t'), [this] { run_taint_analysis(); return true; }, "taint");
normal_keys_.bind(Event::Character('B'), [this] { run_backward_taint_analysis(); return true; }, "back taint");
    normal_keys_.bind(Event::Character('C'), [this] { clear_analysis(); return true; }, "clear analysis");

    // ─── Function/call navigation ────────────────────────────────────────
    normal_keys_.bind(Event::Character('f'), [this] {
        if (!ctx_.function_result) {
            run_pass_by_name("function");
        } else {
            callstack_panel_->set_visible(!callstack_panel_->visible());
        }
        return true;
    }, "functions/callstack");
    normal_keys_.bind(Event::Character('F'), [this] { follow_return(); return true; }, "follow return");
    normal_keys_.bind(Event::Character('e'), [this] { follow_call(); return true; }, "follow call");
    normal_keys_.bind(Event::Character('x'), [this] { goto_xref_next(); return true; }, "xref next");
    normal_keys_.bind(Event::Character('X'), [this] { goto_xref_prev(); return true; }, "xref prev");

    // ─── String panel (I) ────────────────────────────────────────────────
    normal_keys_.bind(Event::Character('I'), [this] {
        if (!ctx_.string_result) {
            run_pass_by_name("strings");
            strings_panel_->set_focused(true);
        } else if (!strings_panel_->visible()) {
            strings_panel_->set_visible(true);
            strings_panel_->set_focused(true);
        } else {
            strings_panel_->set_focused(!strings_panel_->focused());
        }
        return true;
    }, "strings panel");

    // ─── Function list panel (L) ─────────────────────────────────────────
    normal_keys_.bind(Event::Character('L'), [this] {
        if (!ctx_.function_result) {
            run_pass_by_name("function");
        }
        if (ctx_.function_result) {
            if (!functions_panel_->visible()) {
                functions_panel_->set_visible(true);
                functions_panel_->set_focused(true);
                functions_panel_->update_list();
            } else {
                functions_panel_->set_focused(!functions_panel_->focused());
            }
        }
        return true;
    }, "function list");

    // ─── Thread analysis (T = next switch) ───────────────────────────────
    normal_keys_.bind(Event::Character('T'), [this] {
        if (!ctx_.thread_result) run_pass_by_name("thread");
        if (ctx_.thread_result) {
            auto* ev = ctx_.thread_result->next_switch_after(current_inst_);
            if (ev) navigate_to(ev->inst_id);
        }
        return true;
    }, "thread next switch");

    // ─── Navigation history ──────────────────────────────────────────────
    normal_keys_.bind(Event::Character('{'), [this] { nav_back(); return true; }, "history back");
    normal_keys_.bind(Event::Character('}'), [this] { nav_forward(); return true; }, "history forward");

    // ─── Taint jump navigation ───────────────────────────────────────────
    normal_keys_.bind(Event::Character('['), [this] { goto_taint_prev(); return true; }, "taint prev");
    normal_keys_.bind(Event::Character(']'), [this] { goto_taint_next(); return true; }, "taint next");

    // ─── Callstack panel focus (P) ───────────────────────────────────────
    normal_keys_.bind(Event::Character('P'), [this] {
        if (callstack_panel_->visible() && ctx_.function_result) {
            callstack_panel_->set_focused(!callstack_panel_->focused());
        } else if (!ctx_.function_result) {
            run_pass_by_name("function");
            callstack_panel_->set_visible(true);
            callstack_panel_->set_focused(true);
        }
        return true;
    }, "callstack focus");

    // ─── Memory panel focus (p) ──────────────────────────────────────────
    normal_keys_.bind(Event::Character('p'), [this] {
        if (memory_panel_->visible()) {
            memory_panel_->set_focused(!memory_panel_->focused());
        } else {
            memory_panel_->set_visible(true);
            memory_panel_->set_focused(true);
        }
        return true;
    }, "memory focus");

    // ─── Loop analysis (O) ───────────────────────────────────────────────
    normal_keys_.bind(Event::Character('O'), [this] {
        if (!ctx_.loop_result) {
            run_pass_by_name("loop");
        } else {
            show_loops_ = !show_loops_;
        }
        return true;
    }, "loop analysis");

    // ─── Minimap toggle — overrides 'V' for FPR when needed ─────────────
    // Note: 'V' is already bound above for FPR toggle. The minimap toggle
    // uses a different key now to avoid conflict. The original code had two
    // 'V' bindings (line 1435 and 1586); the second was dead code. We keep
    // only the FPR toggle on 'V' and use the minimap as part of the layout.

    // ─── Breakpoint panel toggle (W) ─────────────────────────────────────
    normal_keys_.bind(Event::Character('W'), [this] {
        if (breakpoint_panel_->visible()) {
            breakpoint_panel_->set_focused(!breakpoint_panel_->focused());
        } else {
            breakpoint_panel_->set_visible(true);
            breakpoint_panel_->set_focused(true);
        }
        return true;
    }, "breakpoint panel");

    // ─── Analysis Results panel toggle (A) ────────────────────────────────
    // Browses every catalog pass (state + summary), drills into a per-item
    // result list for passes with structured output, and jumps to any
    // entry's inst_id. This is the TUI counterpart of the GUI's Analysis
    // panel + its ~20 dedicated result windows.
    normal_keys_.bind(Event::Character('A'), [this] {
        ensure_pass_manager();
        if (results_panel_->visible()) {
            results_panel_->set_focused(!results_panel_->focused());
        } else {
            results_panel_->set_visible(true);
            results_panel_->set_focused(true);
        }
        return true;
    }, "analysis results panel");

    // ─── Escape: dismiss messages ────────────────────────────────────────
    normal_keys_.bind_if(Event::Escape,
        [this] { return !bp_status_msg_.empty() || !cmd_error_.empty(); },
        [this] { bp_status_msg_.clear(); cmd_error_.clear(); return true; },
        "dismiss messages");
}

bool TuiApp::handle_event(Event event) {
    // Resize
    if (event == Event::Special({0})) {
        handle_resize();
        return true;
    }

    // ─── Panel focus delegation via Panel::handle_event ─────────────────
    if (functions_panel_->focused() && functions_panel_->visible() && ctx_.function_result) {
        return functions_panel_->handle_event(event);
    }
    if (callstack_panel_->focused() && callstack_panel_->visible() && ctx_.function_result) {
        return callstack_panel_->handle_event(event);
    }
    if (memory_panel_->focused()) {
        return memory_panel_->handle_event(event);
    }
    if (thread_panel_->focused() && thread_panel_->visible() && ctx_.thread_result) {
        return thread_panel_->handle_event(event);
    }
    if (strings_panel_->focused() && strings_panel_->visible() && ctx_.string_result) {
        return strings_panel_->handle_event(event);
    }
    if (hex_dump_focused_ && hex_dump_view_)
        return handle_hex_dump_event(event);
    if (breakpoint_panel_->focused() && breakpoint_panel_->visible()) {
        return breakpoint_panel_->handle_event(event);
    }
    if (results_panel_->focused() && results_panel_->visible()) {
        return results_panel_->handle_event(event);
    }

    // ─── Data-driven normal-mode dispatch ────────────────────────────────
    return normal_keys_.dispatch(event);
}

// ─── Component factories ────────────────────────────────────────────────────

Component TuiApp::make_goto_dialog() {
    auto input = Input(&goto_input_, "inst_id");
    input |= CatchEvent([&](Event event) {
        if (event == Event::Return) {
            execute_goto();
            return true;
        }
        if (event == Event::Escape) {
            close_goto_dialog();
            return true;
        }
        return false;
    });

    return Renderer(input, [input] {
        return window(text(" Goto Instruction "), input->Render()) | center;
    });
}

Component TuiApp::make_search_dialog() {
    auto input = Input(&search_input_, "pattern");
    input |= CatchEvent([&](Event event) {
        if (event == Event::Return) {
            execute_search();
            return true;
        }
        if (event == Event::Escape) {
            close_search_dialog();
            return true;
        }
        return false;
    });

    return Renderer(input, [input] {
        return window(text(" Search "), input->Render()) | center;
    });
}

Component TuiApp::make_main_component() {
    auto main = Renderer([&] {
        return render_main_layout();
    });

    main |= CatchEvent([&](Event event) {
        if (show_goto_dialog_ || show_search_dialog_) {
            return false;  // Let dialog handle it
        }
        return handle_event(event);
    });

    return main;
}

// ─── Taint jump helpers ─────────────────────────────────────────────────────

// ─── Loop Analysis ───────────────────────────────────────────────────────────

// ─── Minimap Column ──────────────────────────────────────────────────────────
// A narrow (3-char wide) vertical strip that summarizes the full trace.
// Each character row represents a bucket of instructions.
// Colors: bookmark=gold, back-taint=red, taint=green,
//         loop-header=orange, loop-body=amber, call=blue, other=gray.

ftxui::Element TuiApp::render_minimap_column() {
    using namespace ftxui;
    Elements rows;

    // Title
    rows.push_back(text("Map") | bold | color(Color::Yellow));
    rows.push_back(separator());

    if (total_inst_ == 0) {
        rows.push_back(text("   ") | color(Color::GrayDark));
        return vbox(rows) | size(WIDTH, EQUAL, 5) | border;
    }

    // Available height for the map (leave 2 rows for header)
    const int kMapRows = 40;  // fixed height in terminal rows

    for (int r = 0; r < kMapRows; r++) {
        uint64_t bucket_start = static_cast<uint64_t>(r) * total_inst_ / kMapRows;
        uint64_t bucket_end   = static_cast<uint64_t>(r + 1) * total_inst_ / kMapRows;
        if (bucket_start >= total_inst_) break;
        bucket_end = std::min(bucket_end, total_inst_);

        // Is current instruction in this bucket?
        bool is_current_bucket = (current_inst_ >= bucket_start && current_inst_ < bucket_end);

        // Classify bucket
        bool has_bookmark = false;
        bool has_taint = false;
        bool has_back_taint = false;
        bool has_loop_header = false;
        bool has_loop_body = false;
        bool has_call = false;

        uint64_t bucket_size = bucket_end - bucket_start;
        uint64_t sample_step = std::max(uint64_t(1), bucket_size / 6);
        for (uint64_t sid = bucket_start; sid < bucket_end; sid += sample_step) {
            auto srow = fetch_row(sid);
            if (srow.has_bookmark) has_bookmark = true;
            if (show_taint_ && ctx_.taint_result && ctx_.taint_result->has_event_at(sid))
                has_taint = true;
            if (show_backward_taint_ && ctx_.backward_taint_result &&
                ctx_.backward_taint_result->is_contributing(sid))
                has_back_taint = true;
            if (show_loops_ && ctx_.loop_result) {
                if (ctx_.loop_result->is_loop_header(srow.pc)) has_loop_header = true;
                else if (ctx_.loop_result->is_in_loop(srow.pc)) has_loop_body = true;
            }
            if (ctx_.function_result && ctx_.function_result->call_at(sid)) has_call = true;
        }

        // Choose display character and color
        std::string ch;
        Color col;
        if (has_bookmark)        { ch = "\xE2\x97\x86"; col = Color::RGB(255, 220, 40);  }  // ◆
        else if (has_back_taint) { ch = "\xe2\x96\x93"; col = Color::Red;                }  // ▓
        else if (has_taint)      { ch = "\xe2\x96\x92"; col = Color::Green;              }  // ▒
        else if (has_loop_header){ ch = "\xE2\x87\x86"; col = Color::RGB(255, 140, 30);  }  // ⇆
        else if (has_loop_body)  { ch = "\xe2\x96\x91"; col = Color::RGB(180, 100, 30);  }  // ░
        else if (has_call)       { ch = "\xe2\x94\x80"; col = Color::Blue;               }  // ─
        else                     { ch = "\xe2\x96\x91"; col = Color::GrayDark;           }  // ░

        // Current bucket highlight
        auto cell = text(ch) | color(col);
        if (is_current_bucket) {
            cell = hbox({ text(">") | color(Color::White), cell });
        } else {
            cell = hbox({ text(" "), cell });
        }
        rows.push_back(cell);
    }

    // Progress percentage at bottom
    float pct = total_inst_ > 0 ? static_cast<float>(current_inst_) * 100.0f / total_inst_ : 0.0f;
    rows.push_back(separator());
    rows.push_back(text(fmt::format("{:.0f}%", pct)) | color(Color::GrayLight));

    return vbox(rows) | size(WIDTH, EQUAL, 5) | border;
}

void TuiApp::rebuild_taint_jump_list() {
    taint_jump_list_.clear();
    taint_jump_cursor_ = 0;

    // Collect tainted inst IDs from whichever analysis is active
    if (show_taint_ && ctx_.taint_result) {
        for (uint64_t i = 0; i < total_inst_; i++) {
if (ctx_.taint_result->has_event_at(i)) taint_jump_list_.push_back(i);
}
} else if (show_backward_taint_ && ctx_.backward_taint_result) {
        for (uint64_t i = 0; i < total_inst_; i++) {
            if (ctx_.backward_taint_result->is_contributing(i)) taint_jump_list_.push_back(i);
        }
    }

    // Position cursor near current instruction
    if (!taint_jump_list_.empty()) {
        auto it = std::lower_bound(taint_jump_list_.begin(), taint_jump_list_.end(), current_inst_);
        taint_jump_cursor_ = static_cast<size_t>(it - taint_jump_list_.begin());
        if (taint_jump_cursor_ >= taint_jump_list_.size()) {
            taint_jump_cursor_ = taint_jump_list_.size() - 1;
        }
    }
}

void TuiApp::goto_taint_next() {
    if (taint_jump_list_.empty()) {
        rebuild_taint_jump_list();
        if (taint_jump_list_.empty()) return;
    }
    // Move to next entry strictly after current position
    for (size_t i = 0; i < taint_jump_list_.size(); i++) {
        size_t idx = (taint_jump_cursor_ + 1 + i) % taint_jump_list_.size();
        if (taint_jump_list_[idx] > current_inst_ ||
            taint_jump_list_.size() == 1) {
            taint_jump_cursor_ = idx;
            navigate_to(taint_jump_list_[idx]);
            return;
        }
    }
    // Wrap around
    taint_jump_cursor_ = 0;
    navigate_to(taint_jump_list_[0]);
}

void TuiApp::goto_taint_prev() {
    if (taint_jump_list_.empty()) {
        rebuild_taint_jump_list();
        if (taint_jump_list_.empty()) return;
    }
    // Move to previous entry strictly before current position
    for (size_t i = 0; i < taint_jump_list_.size(); i++) {
        size_t idx;
        if (taint_jump_cursor_ == 0) {
            idx = taint_jump_list_.size() - 1 - i;
        } else {
            idx = (taint_jump_cursor_ - 1 + taint_jump_list_.size() - i) % taint_jump_list_.size();
        }
        if (taint_jump_list_[idx] < current_inst_ ||
            taint_jump_list_.size() == 1) {
            taint_jump_cursor_ = idx;
            navigate_to(taint_jump_list_[idx]);
            return;
        }
    }
    // Wrap around
    taint_jump_cursor_ = taint_jump_list_.size() - 1;
    navigate_to(taint_jump_list_[taint_jump_cursor_]);
}

// ─── Analysis passes ────────────────────────────────────────────────────────

void TuiApp::run_taint_analysis() {
    ensure_pass_manager();
    auto* pm = service_->pass_manager();

    // Configure taint: start with current instruction's modified registers as sources
    TaintConfig config;
    config.taint_from_memory = true;
    config.track_memory_sinks = true;
    config.propagate_arithmetic = true;
    config.propagate_moves = true;
    config.max_instructions = 100000;

    // Use current instruction's register diffs as initial taint sources
    auto [offset_ts, seed_pc_ts] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_ts = reader_.record_at(offset_ts, seed_pc_ts);
    if (rec_ts.kind == RecordKind::Inst) {
        auto inst = rec_ts.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_source_reg(diff.index);
        }
    }

    pm->register_pass(std::make_unique<TaintPass>(config));
    auto& result = pm->require("taint");
    if (result.ok()) {
        ctx_.taint_result = &result.get<TaintResult>();
        show_taint_ = true;
        taint_jump_list_.clear();  // Will be rebuilt lazily
    }
}

void TuiApp::run_backward_taint_analysis() {
    ensure_pass_manager();
    auto* pm = service_->pass_manager();

    // Configure backward taint: current instruction is the sink
    BackwardTaintConfig config;
    config.sink_inst_id = current_inst_;
    config.propagate_through_memory = true;
    config.max_steps = 500000;
    config.max_tainted_insts = 50000;

    // Use current instruction's register diffs as sink registers
    auto [offset_sk, seed_pc_sk] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sk = reader_.record_at(offset_sk, seed_pc_sk);
    if (rec_sk.kind == RecordKind::Inst) {
        auto inst = rec_sk.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_sink_reg(diff.index);
        }
    }

    if (config.sink_regs == 0) {
        // No reg diffs at this instruction — default to X0
        config.add_sink_reg(0);
    }

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(config)));
    auto& result = pm->require("backward_taint");
    if (result.ok()) {
        ctx_.backward_taint_result = &result.get<BackwardTaintResult>();
        show_backward_taint_ = true;
        show_taint_ = false;
        taint_jump_list_.clear();
    }
}

void TuiApp::clear_analysis() {
ctx_.taint_result = nullptr;
ctx_.backward_taint_result = nullptr;
    ctx_.function_result = nullptr;
    ctx_.xref_result = nullptr;
    ctx_.string_result = nullptr;
    ctx_.call_graph_result = nullptr;
    ctx_.loop_result = nullptr;
    ctx_.thread_result = nullptr;

    // Extended (Results panel) results — reset alongside the legacy set so
    // ':analyze' / 'C' fully resets both old and new consumers together.
    ctx_.cfg_result = nullptr;
    ctx_.cfg_layout_result = nullptr;
    ctx_.pattern_result = nullptr;
    ctx_.loop_semantics_result = nullptr;
    ctx_.algorithm_summary_result = nullptr;
    ctx_.objc_result = nullptr;
    ctx_.objc_crypto_result = nullptr;
    ctx_.memory_string_result = nullptr;
    ctx_.entropy_result = nullptr;
    ctx_.syscall_intercept_result = nullptr;
    ctx_.trace_fold_result = nullptr;
    ctx_.vm_abstract_result = nullptr;
    ctx_.mem_search_result = nullptr;
    ctx_.memory_snapshot_result = nullptr;
    ctx_.yara_mem_scan_result = nullptr;
    ctx_.call_context_result = nullptr;
    ctx_.window_stats_result = nullptr;
    ctx_.dataflow_graph_result = nullptr;
    ctx_.reg_timeline_result = nullptr;
    ctx_.trace_diff_result = nullptr;
    ctx_.taint_source_annotation_result = nullptr;
    ctx_.thread_filter_result = nullptr;

show_taint_ = false;
show_backward_taint_ = false;
callstack_panel_->set_visible(false);
    functions_panel_->set_visible(false);
    strings_panel_->set_visible(false);
    show_loops_ = false;
    thread_panel_->set_visible(false);
    thread_panel_->set_focused(false);
    results_panel_->set_visible(false);
    results_panel_->set_focused(false);
    xref_cursor_ = 0;
    taint_jump_list_.clear();
    taint_jump_cursor_ = 0;
    functions_panel_->set_focused(false);
    callstack_panel_->set_focused(false);
    memory_panel_->set_focused(false);
    service_->clear_analysis();
}

// ─── Generic pass runner ───────────────────────────────────────────────────
// Lets the TUI run any catalog pass via ':pass <name>'. The default pass set
// is runnable via ':analyze'. This guarantees every pass is reachable from
// the TUI, mirroring the GUI "All Passes" section and the CLI --run-pass flag.

void TuiApp::ensure_pass_manager() {
    service_->ensure_pass_manager();
}

void TuiApp::wire_pass_result(std::string_view name, const PassResult& raw) {
    if (!raw.ok()) return;
    // ── Structure ───────────────────────────────────────────────────────
    if (name == "function") {
        ctx_.function_result = &raw.get<FunctionResult>();
        callstack_panel_->set_visible(true);
    } else if (name == "xref") {
        ctx_.xref_result = &raw.get<XrefResult>();
        xref_cursor_ = 0;
    } else if (name == "cfg") {
        ctx_.cfg_result = &raw.get<CFGResult>();
    } else if (name == "cfg_layout") {
        ctx_.cfg_layout_result = &raw.get<CFGLayoutResult>();
    } else if (name == "call_graph") {
        ctx_.call_graph_result = &raw.get<CallGraphResult>();
    } else if (name == "loop") {
        ctx_.loop_result = &raw.get<LoopResult>();
        show_loops_ = true;
    // ── Taint ───────────────────────────────────────────────────────────
    } else if (name == "taint") {
        ctx_.taint_result = &raw.get<TaintResult>();
        show_taint_ = true;
        taint_jump_list_.clear();
    } else if (name == "backward_taint") {
        ctx_.backward_taint_result = &raw.get<BackwardTaintResult>();
        show_backward_taint_ = true;
    } else if (name == "taint_source_annotation") {
        ctx_.taint_source_annotation_result = &raw.get<TaintSourceAnnotationResult>();
    // ── Crypto / Pattern ────────────────────────────────────────────────
    } else if (name == "pattern") {
        ctx_.pattern_result = &raw.get<PatternResult>();
    } else if (name == "loop_semantics") {
        ctx_.loop_semantics_result = &raw.get<LoopSemanticsResult>();
    } else if (name == "algorithm_summary") {
        ctx_.algorithm_summary_result = &raw.get<AlgorithmSummaryResult>();
    } else if (name == "objc_crypto") {
        ctx_.objc_crypto_result = &raw.get<ObjcCryptoResult>();
    // ── Memory / String ─────────────────────────────────────────────────
    } else if (name == "strings") {
        ctx_.string_result = &raw.get<StringResult>();
        strings_panel_->set_visible(true);
        strings_panel_->clear_filter();
    } else if (name == "memory_strings") {
        ctx_.memory_string_result = &raw.get<MemoryStringResult>();
    } else if (name == "memory_snapshot") {
        ctx_.memory_snapshot_result = &raw.get<MemorySnapshotResult>();
    } else if (name == "mem_search") {
        ctx_.mem_search_result = &raw.get<MemSearchResult>();
    } else if (name == "entropy") {
        ctx_.entropy_result = &raw.get<EntropyResult>();
    } else if (name == "yara_mem_scan") {
        ctx_.yara_mem_scan_result = &raw.get<YaraMemScanResult>();
    // ── Platform API ────────────────────────────────────────────────────
    } else if (name == "objc") {
        ctx_.objc_result = &raw.get<ObjcResult>();
    } else if (name == "syscall_intercept") {
        ctx_.syscall_intercept_result = &raw.get<SyscallInterceptResult>();
    // ── Profile / Trace ─────────────────────────────────────────────────
    } else if (name == "trace_fold") {
        ctx_.trace_fold_result = &raw.get<TraceFoldResult>();
    } else if (name == "reg_timeline") {
        ctx_.reg_timeline_result = &raw.get<RegTimelineResult>();
    } else if (name == "call_context") {
        ctx_.call_context_result = &raw.get<CallContextResult>();
    } else if (name == "window_stats") {
        ctx_.window_stats_result = &raw.get<WindowStatsResult>();
    } else if (name == "trace_diff") {
        ctx_.trace_diff_result = &raw.get<TraceDiffResult>();
    } else if (name == "dataflow_graph") {
        ctx_.dataflow_graph_result = &raw.get<DataflowGraphResult>();
    // ── Misc ────────────────────────────────────────────────────────────
    } else if (name == "thread") {
        ctx_.thread_result = &raw.get<ThreadResult>();
        thread_panel_->set_visible(true);
    } else if (name == "thread_filter") {
        ctx_.thread_filter_result = &raw.get<ThreadFilterResult>();
    } else if (name == "vm_abstract") {
        ctx_.vm_abstract_result = &raw.get<VMAbstractResult>();
    }
}

void TuiApp::run_pass_by_name(std::string_view name) {
    ensure_pass_manager();
    auto* pm = service_->pass_manager();

    if (!tenet::is_known_pass(name)) {
        last_pass_status_ = fmt::format("unknown pass '{}'", name);
        return;
    }

    tenet::PassRunCtx ctx;
    ctx.current_inst = current_inst_;
    ctx.total_inst   = total_inst_;
    // Derive a target register from the first reg diff at the cursor.
    auto [offset, seed_pc] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        ctx.current_reg = (inst.reg_diff_count > 0) ? inst.reg_diff(0).index : 0;
    }

    if (!tenet::register_pass_by_name(*pm, name, ctx)) {
        last_pass_status_ = fmt::format("'{}' could not be registered", name);
        return;
    }

    auto& raw = pm->require(name);
    last_pass_status_ = fmt::format("{}: {}", name,
                                    tenet::summarize_pass_result(name, raw));
    wire_pass_result(name, raw);

    // If the Results panel triggered this run (or the user ran ':pass X'),
    // jump straight into the detail view instead of leaving them staring at
    // a one-line status message — mirrors GUI's auto-open-window behavior.
    if (raw.ok()) {
        results_panel_->focus_pass(name);
    }
}

void TuiApp::run_default_analysis() {
    ensure_pass_manager();
    auto* pm = service_->pass_manager();

    tenet::register_default_passes(*pm);
    for (auto name : tenet::default_ui_pass_names()) {
        auto& raw = pm->require(name);
        wire_pass_result(name, raw);
    }
    last_pass_status_ = fmt::format("ran {} default passes",
                                    tenet::default_ui_pass_names().size());
}

void TuiApp::follow_call() {
    if (!ctx_.function_result) return;

    auto* evt = ctx_.function_result->call_at(current_inst_);
    if (evt && evt->call_inst_id + 1 < total_inst_) {
        // Jump to the first instruction of the callee
        navigate_to(evt->call_inst_id + 1);
    }
}

void TuiApp::follow_return() {
    if (!ctx_.function_result) return;

    auto* evt = ctx_.function_result->return_at(current_inst_);
    if (evt) {
        // Jump back to the instruction after the call site
        navigate_to(evt->call_inst_id);
    } else {
        // Not at a ret; try to find the calling frame and go back
        auto stack = ctx_.function_result->call_stack_at(current_inst_);
        if (!stack.empty()) {
            navigate_to(stack.back()->call_inst_id);
        }
    }
}

void TuiApp::goto_xref_next() {
    if (!ctx_.xref_result) {
        run_pass_by_name("xref");
        if (!ctx_.xref_result) return;
    }

    auto row = fetch_row(current_inst_);
    auto xrefs = ctx_.xref_result->inst_ids_at(row.pc);
    if (xrefs.empty()) return;

    // Find current position in xref list
    xref_cursor_++;
    if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
    navigate_to(xrefs[xref_cursor_]);
}

void TuiApp::goto_xref_prev() {
    if (!ctx_.xref_result) {
        run_pass_by_name("xref");
        if (!ctx_.xref_result) return;
    }

    auto row = fetch_row(current_inst_);
    auto xrefs = ctx_.xref_result->inst_ids_at(row.pc);
    if (xrefs.empty()) return;

    if (xref_cursor_ == 0) {
        xref_cursor_ = xrefs.size() - 1;
    } else {
        xref_cursor_--;
    }
    navigate_to(xrefs[xref_cursor_]);
}

// ─── Function list panel ──────────────────────────────────────────────────────

void TuiApp::open_function_filter_dialog() {
    show_function_filter_dialog_ = true;
    function_filter_input_.clear();
}

void TuiApp::close_function_filter_dialog() {
    show_function_filter_dialog_ = false;
    function_filter_input_.clear();
}

void TuiApp::execute_function_filter() {
    if (functions_panel_) functions_panel_->update_list();
    close_function_filter_dialog();
}

// ─── String analysis ────────────────────────────────────────────────────────

void TuiApp::open_string_search_dialog() {
    show_string_search_dialog_ = true;
    string_search_input_.clear();
}

void TuiApp::close_string_search_dialog() {
    show_string_search_dialog_ = false;
    string_search_input_.clear();
}

void TuiApp::execute_string_search() {
    if (strings_panel_) strings_panel_->set_filter(string_search_input_);
    close_string_search_dialog();
}

// ─── Run loop ───────────────────────────────────────────────────────────────

int TuiApp::run() {
    // Re-query terminal size now that we're about to enter the loop
    handle_resize();

    auto goto_input = Input(&goto_input_, "inst_id");
    auto search_input = Input(&search_input_, "pattern");
    auto string_search_input = Input(&string_search_input_, "filter");

    // Use a vertical container so we always have a focusable component
    auto function_filter_input = Input(&function_filter_input_, "filter");

    // Command-mode input (': b 0x1234', etc.)
    auto cmd_input = Input(&cmd_input_, "b 0xaddr / w 0xaddr [size] / rc / rb / bl / bc");

    auto input_container = Container::Stacked({
        goto_input,
        search_input,
        string_search_input,
        function_filter_input,
        cmd_input,
    });

    auto app = Renderer(input_container, [&] {
        Element document = render_main_layout();
        if (show_goto_dialog_) {
            auto dialog = window(text(" Goto Instruction "), goto_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_search_dialog_) {
            auto dialog = window(text(" Search "), search_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_string_search_dialog_) {
            auto dialog = window(text(" Filter Strings "), string_search_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_function_filter_dialog_) {
            auto dialog = window(text(" Filter Functions "), function_filter_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_cmd_dialog_) {
            // Command mode dialog: show command prompt with optional error hint
            Element input_elem = cmd_input->Render();
            if (!cmd_error_.empty()) {
                input_elem = vbox({
                    input_elem,
                    text(" Error: " + cmd_error_) | color(Color::Red) | bold,
                });
            }
            auto dialog = window(
                hbox({text(" : ") | bold | color(Color::Yellow), text("Command ")}),
                input_elem
            ) | size(WIDTH, GREATER_THAN, 55) | center;
            document = dbox({document, dialog});
        }
        return document;
    });

    app |= CatchEvent([&](Event event) {
        // Dialog mode: handle Enter/Escape, let input component handle the rest
        if (show_goto_dialog_) {
            if (event == Event::Return) {
                execute_goto();
                return true;
            }
            if (event == Event::Escape) {
                close_goto_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_search_dialog_) {
            if (event == Event::Return) {
                execute_search();
                return true;
            }
            if (event == Event::Escape) {
                close_search_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_string_search_dialog_) {
            if (event == Event::Return) {
                execute_string_search();
                return true;
            }
            if (event == Event::Escape) {
                close_string_search_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_function_filter_dialog_) {
            if (event == Event::Return) {
                execute_function_filter();
                return true;
            }
            if (event == Event::Escape) {
                close_function_filter_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_cmd_dialog_) {
            if (event == Event::Return) {
                execute_cmd();
                // If there's an error, keep the dialog open (don't close)
                // execute_cmd() calls close_cmd_dialog() internally on success
                return true;
            }
            if (event == Event::Escape) {
                close_cmd_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }

        return handle_event(event);
    });

    try {
        screen_.Loop(app);
    } catch (const std::exception& e) {
        // Ensure terminal is restored on exception
        fmt::print(stderr, "\nFatal TUI error: {}\n", e.what());
        fmt::print(stderr, "Run with -c for batch mode if TUI is unavailable.\n");
        return 1;
    }

    // Persist bookmarks and last cursor position to the index database
    index_.save_bookmarks(ctx_.bookmarks);
    index_.save_last_inst(current_inst_);

    return 0;
}

// ─── Batch mode ─────────────────────────────────────────────────────────────

int TuiApp::batch_mode(uint64_t start_id, uint64_t count, bool show_regs, bool show_mem) {
    (void)show_regs;
    (void)show_mem;

    const auto& hdr = reader_.header();

    fmt::print("Disassembly (inst_id {} to {}):\n", start_id, start_id + count - 1);
    fmt::print("{}\n", std::string(72, '-'));

    for (uint64_t i = 0; i < count && start_id + i < total_inst_; i++) {
        uint64_t id = start_id + i;
        auto row = fetch_row(id);

        fmt::print("{:>8}  {:016x}  {}\n", id, row.static_pc, row.disasm);

        if (show_regs && row.reg_diff_count > 0) {
            auto [offset_r, seed_pc_r] = index_.offset_of_with_pc(id, reader_);
            auto rec_r = reader_.record_at(offset_r, seed_pc_r);
            auto inst = rec_r.as_inst();
            fmt::print("          ");
            for (uint8_t j = 0; j < inst.reg_diff_count; j++) {
                auto diff = inst.reg_diff(j);
                fmt::print("{}=0x{:x} ", tui_reg_name(diff.index), diff.value);
            }
            fmt::print("\n");
        }

        if (show_mem && row.mem_access_count > 0) {
            auto [offset_m, seed_pc_m] = index_.offset_of_with_pc(id, reader_);
            auto rec_m = reader_.record_at(offset_m, seed_pc_m);
            auto inst = rec_m.as_inst();
            for (uint8_t j = 0; j < inst.mem_access_count; j++) {
                auto mem = inst.mem_access(j);
                const char* type_str = (mem.type & 2) ? "W" : "R";
                fmt::print("          [{}] 0x{:x} size={} val=0x{:x}\n",
                           type_str, mem.addr, mem.size, mem.value);
            }
        }
    }

    fmt::print("{}\n", std::string(72, '-'));

    if (show_regs) {
        uint64_t last_id = std::min(start_id + count - 1, total_inst_ - 1);
        fmt::print("\nRegister state before inst_id={}:\n", last_id);
        const auto& state = regfile_.state_before(last_id);
        for (int i = 0; i < 29; i += 4) {
            fmt::print("  x{:<2}=0x{:016x}  x{:<2}=0x{:016x}  x{:<2}=0x{:016x}  x{:<2}=0x{:016x}\n",
                       i, state.gpr[i], i+1, state.gpr[i+1],
                       i+2, state.gpr[i+2], i+3, state.gpr[i+3]);
        }
        fmt::print("  fp =0x{:016x}  lr =0x{:016x}  sp =0x{:016x}\n",
                   state.fp(), state.lr(), state.sp());
        fmt::print("  pc =0x{:016x}  nzcv={}\n", state.pc(), state.nzcv());
        auto stats = regfile_.cache_stats();
        fmt::print("\n  Cache stats: hits={} misses={}\n", stats.hits, stats.misses);
    }

    return 0;
}

}  // namespace tenet

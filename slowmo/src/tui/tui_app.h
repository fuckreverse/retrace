#pragma once

#include "common/types.h"
#include "common/instruction_row.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "core/breakpoint_engine.h"
#include "tui/hex_dump_view.h"
#include "tui/key_bindings.h"
#include "tui/tui_context.h"
#include "tui/panel.h"
#include "tui/panels/register_panel.h"
#include "tui/panels/memory_panel.h"
#include "tui/panels/callstack_panel.h"
#include "tui/panels/functions_panel.h"
#include "tui/panels/strings_panel.h"
#include "tui/panels/thread_panel.h"
#include "tui/panels/breakpoint_panel.h"
#include "tui/panels/results_panel.h"
#include "analysis/pass_manager.h"
#include "service/tenet_service.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace tenet {

// ─── TUI Application ──────────────────────────────────────────────────────
//
// TuiApp owns the main loop, navigation, command mode, and the panel registry.
// Each panel is an independent Panel subclass that renders and handles events.
// Panels communicate through the shared TuiContext struct.

class TuiApp {
public:
    /// Constructs the TUI from a shared TenetService instance.
    explicit TuiApp(TenetService& service);

    /// Destructor: joins any lingering async analysis thread.
    ~TuiApp() {
        if (async_thread_.joinable()) async_thread_.join();
    }

    /// Run the interactive TUI loop. Returns 0 on clean exit.
    int run();

    /// Batch mode: non-interactive dump (for -c / --batch CLI)
    int batch_mode(uint64_t start_id, uint64_t count, bool show_regs, bool show_mem);

private:
    // ─── Shared context (accessible by all panels) ────────────────────
    TuiContext ctx_;

    // ─── Data references (also stored in ctx_ for panels) ─────────────
    TraceReader& reader_;
    TraceIndex& index_;
    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile& regfile_;
    MemoryModel& memory_;

    // ─── Navigation state ───────────────────────────────────────────────
    uint64_t& total_inst_  = ctx_.total_inst;
    uint64_t& current_inst_ = ctx_.current_inst;
    uint64_t& viewport_top_ = ctx_.viewport_top;
    int& viewport_height_   = ctx_.viewport_height;

    // ─── Navigation history (browser-style back/forward) ──────────────
    static constexpr size_t kMaxNavHistory = 64;
    std::vector<uint64_t> nav_history_;
    size_t nav_history_pos_ = 0;
    bool nav_history_navigating_ = false;

    // ─── Search state ─────────────────────────────────────────────────
    std::string search_query_;
    std::vector<uint64_t> search_results_;
    size_t search_current_ = 0;
    bool search_active_ = false;

    // ─── UI toggles ───────────────────────────────────────────────────
    bool show_hex_dump_ = false;
    bool hex_dump_focused_ = false;
    bool show_minimap_ = true;
    bool show_mem_ = false;      // inline memory in instruction list (not the memory panel)
    bool show_nzcv_ = true;      // register display sub-option
    bool show_fpr_ = false;      // register display sub-option

    // ─── Service layer ─────────────────────────────────────────────────
    TenetService* service_ = nullptr;

    // ─── FTXUI components ───────────────────────────────────────────────
    ftxui::ScreenInteractive screen_;
    ftxui::Component main_component_;

    // ─── Panel registry ─────────────────────────────────────────────────
    // Panels are owned here and rendered in order by render_main_layout().
    std::unique_ptr<RegisterPanel>   register_panel_;
    std::unique_ptr<MemoryPanel>     memory_panel_;
    std::unique_ptr<CallstackPanel>  callstack_panel_;
    std::unique_ptr<FunctionsPanel>  functions_panel_;
    std::unique_ptr<StringsPanel>    strings_panel_;
    std::unique_ptr<ThreadPanel>     thread_panel_;
    std::unique_ptr<BreakpointPanel> breakpoint_panel_;
    std::unique_ptr<ResultsPanel>    results_panel_;

    /// Ordered list of right-side panels for rendering loop.
    std::vector<Panel*> right_panels_;

    /// The currently focused panel (nullptr = instruction list has focus).
    Panel* focused_panel_ = nullptr;

    /// Set focus to a specific panel (unfocuses the previous one).
    void focus_panel(Panel* p);

    // ─── Core rendering ─────────────────────────────────────────────────
    InstructionRow fetch_row(uint64_t inst_id);
    std::vector<InstructionRow> fetch_viewport_rows();

    ftxui::Element render_instruction_list();
    ftxui::Element render_status_bar();
    ftxui::Element render_hex_dump_panel();
    ftxui::Element render_main_layout();
    ftxui::Element render_minimap_column();

    // ─── Navigation ──────────────────────────────────────────────────────
    void navigate_to(uint64_t inst_id);
    void navigate_relative(int64_t delta);
    void nav_push(uint64_t inst_id);
    void nav_back();
    void nav_forward();
    void search_forward(const std::string& query);
    void search_next();
    void search_prev();
    void toggle_bookmark();
    void update_viewport();
    void handle_resize();

    // ─── Xref navigation ─────────────────────────────────────────────────
    void follow_call();
    void follow_return();
    void goto_xref_next();
    void goto_xref_prev();
    size_t xref_cursor_ = 0;

    // ─── Taint jump cache ─────────────────────────────────────────────
    std::vector<uint64_t> taint_jump_list_;
    size_t taint_jump_cursor_ = 0;
    void rebuild_taint_jump_list();
    void goto_taint_next();
    void goto_taint_prev();

    // ─── Modal dialogs ──────────────────────────────────────────────────
    bool show_goto_dialog_ = false;
    std::string goto_input_;
    void open_goto_dialog();
    void close_goto_dialog();
    void execute_goto();

    bool show_search_dialog_ = false;
    std::string search_input_;
    void open_search_dialog();
    void close_search_dialog();
    void execute_search();

    // Function filter dialog
    bool show_function_filter_dialog_ = false;
    std::string function_filter_input_;
    void open_function_filter_dialog();
    void close_function_filter_dialog();
    void execute_function_filter();

    // String search dialog
    bool show_string_search_dialog_ = false;
    std::string string_search_input_;
    void open_string_search_dialog();
    void close_string_search_dialog();
    void execute_string_search();

    // ─── Hex dump view ───────────────────────────────────────────────
    std::unique_ptr<HexDumpView> hex_dump_view_;

    // ─── Analysis passes ──────────────────────────────────────────────
    bool show_taint_ = false;
    bool show_backward_taint_ = false;

    void run_taint_analysis();
    void run_backward_taint_analysis();
    void clear_analysis();

    void ensure_pass_manager();
    void wire_pass_result(std::string_view name, const PassResult& raw);
    void run_pass_by_name(std::string_view name);
    void run_default_analysis();

    std::string last_pass_status_;

    // ── Async analysis ────────────────────────────────────────────────
    // Runs passes on a background thread to avoid blocking the TUI event
    // loop. Completion wakes the loop via screen_.PostEvent(Event::Custom).
    std::atomic<bool> async_running_{false};
    std::string async_pass_name_;         // pass being run (for status display)
    std::shared_ptr<const PassResult> async_result_;  // set by background thread
    bool async_ok_ = false;               // set by background thread
    std::thread async_thread_;
    void finish_async();                  // called on UI thread after completion
    void launch_async(std::string pass_name,
                      std::function<void()> run_fn);

    // ─── Loop analysis ────────────────────────────────────────────────
    bool show_loops_ = false;

    // ─── Breakpoint Engine ────────────────────────────────────────────
    std::unique_ptr<BreakpointEngine> bp_engine_;
    void ensure_bp_engine();

    // Command-mode dialog
    bool show_cmd_dialog_ = false;
    std::string cmd_input_;
    std::string cmd_error_;
    std::string bp_status_msg_;
    void open_cmd_dialog();
    void close_cmd_dialog();
    void execute_cmd();

    void cmd_run_forward();
    void cmd_run_backward();
    void cmd_list_breakpoints();
    void cmd_delete_breakpoint(uint32_t id);

    // ─── Unified event dispatch ───────────────────────────────────────
    bool handle_event(ftxui::Event event);
    bool handle_hex_dump_event(ftxui::Event event);

    // ─── Key binding registry ─────────────────────────────────────────
    KeyBindingRegistry normal_keys_;
    void init_key_bindings();

    // ─── Component factories ──────────────────────────────────────────
    ftxui::Component make_goto_dialog();
    ftxui::Component make_search_dialog();
    ftxui::Component make_main_component();

    // ─── Static trampoline for TuiContext callbacks ───────────────────
    static InstructionRow fetch_row_trampoline(void* self, uint64_t id) {
        return static_cast<TuiApp*>(self)->fetch_row(id);
    }
    static void navigate_to_trampoline(void* self, uint64_t id) {
        static_cast<TuiApp*>(self)->navigate_to(id);
    }
    static void run_pass_trampoline(void* self, std::string_view name) {
        static_cast<TuiApp*>(self)->run_pass_by_name(name);
    }

    // ─── Sync context (called before render/events) ──────────────────
    void sync_context();

};

}  // namespace tenet

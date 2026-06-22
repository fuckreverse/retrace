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
#include "analysis/pass_manager.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <memory>
#include <string>
#include <vector>

namespace tenet {

// Forward declarations for analysis pass results
struct TaintResult;
struct SliceResult;
struct BackwardTaintResult;
struct FunctionResult;
struct XrefResult;
struct StringResult;
struct CallEvent;
struct CallGraphResult;
struct LoopResult;
struct ThreadResult;

// ─── TUI Application State ────────────────────────────────────────────────

class TuiApp {
public:
    TuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
           InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory);

    /// Run the interactive TUI loop. Returns 0 on clean exit.
    int run();

    /// Batch mode: non-interactive dump (for -c / --batch CLI)
    int batch_mode(uint64_t start_id, uint64_t count, bool show_regs, bool show_mem);

private:
    // ─── Data references ──────────────────────────────────────────────
    TraceReader& reader_;
    TraceIndex& index_;
    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile& regfile_;
    MemoryModel& memory_;

    // ─── Navigation state ───────────────────────────────────────────────
    uint64_t total_inst_ = 0;
    uint64_t current_inst_ = 0;      // cursor position in instruction list
    uint64_t viewport_top_ = 0;        // first visible instruction
    int viewport_height_ = 20;       // will be updated from terminal size

    // ─── Navigation history (browser-style back/forward) ──────────────
    static constexpr size_t kMaxNavHistory = 64;
    std::vector<uint64_t> nav_history_;
    size_t nav_history_pos_ = 0;
    bool nav_history_navigating_ = false;  // suppress re-push during back/forward

    // ─── Search state ─────────────────────────────────────────────────
    std::string search_query_;
    std::vector<uint64_t> search_results_;
    size_t search_current_ = 0;
    bool search_active_ = false;

    // ─── Bookmarks ────────────────────────────────────────────────────
    std::vector<uint64_t> bookmarks_;

    // ─── UI toggles ───────────────────────────────────────────────────
    bool show_regs_ = true;
    bool show_mem_ = false;
    bool show_mem_panel_ = true;   // memory panel on right side
    bool show_nzcv_ = true;
    bool show_hex_dump_ = false;
    bool hex_dump_focused_ = false;
    bool show_fpr_ = false;        // NEON/FPR section in register panel (V to toggle)

    // ─── Cached rows ──────────────────────────────────────────────────
    LRUCache<uint64_t, InstructionRow> row_cache_{1024};

    // ─── FTXUI components ───────────────────────────────────────────────
    ftxui::ScreenInteractive screen_;
    ftxui::Component main_component_;

    // ─── Internal helpers ─────────────────────────────────────────────
    InstructionRow fetch_row(uint64_t inst_id);
    std::vector<InstructionRow> fetch_viewport_rows();

    ftxui::Element render_instruction_list();
    ftxui::Element render_register_panel();
    ftxui::Element render_memory_panel();
    ftxui::Element render_status_bar();
    ftxui::Element render_hex_dump_panel();
    ftxui::Element render_main_layout();

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

    // ─── Hex dump view ───────────────────────────────────────────────
    std::unique_ptr<HexDumpView> hex_dump_view_;

    // ─── Analysis passes ──────────────────────────────────────────────
    std::unique_ptr<PassManager> pass_manager_;
    const TaintResult* taint_result_ = nullptr;
    const SliceResult* slice_result_ = nullptr;
    const BackwardTaintResult* backward_taint_result_ = nullptr;
    bool show_taint_ = false;
    bool show_slice_ = false;
    bool show_backward_taint_ = false;

    void run_taint_analysis();
    void run_slice_analysis();
    void run_backward_taint_analysis();
    void clear_analysis();

    /// Run any catalog pass by name, deriving config from the current cursor.
    /// Stores a one-line summary in last_pass_status_.
    void run_pass_by_name(std::string_view name);

    /// Register & run the default-for-UI pass set (used by ':analyze').
    void run_default_analysis();

    /// Last generic pass run summary (shown in the status bar).
    std::string last_pass_status_;

    // ─── Function/Xref state ──────────────────────────────────────────
    const FunctionResult* function_result_ = nullptr;
    const XrefResult* xref_result_ = nullptr;
    const CallGraphResult* call_graph_result_ = nullptr;
    bool show_callstack_ = false;
    bool show_functions_ = false;

    // Callstack panel focus/interaction
    bool callstack_panel_focused_ = false;
    size_t callstack_cursor_ = 0;  // which frame is highlighted

    ftxui::Element render_callstack_panel();
    bool handle_callstack_panel_event(ftxui::Event event);
    void follow_call();        // Enter at call site → jump to target
    void follow_return();      // At ret → jump back to call site
    void goto_xref_next();     // Next execution of same PC
    void goto_xref_prev();     // Previous execution of same PC
    size_t xref_cursor_ = 0;   // Current position in xref list for this PC

    // ─── Taint jump cache ─────────────────────────────────────────────
    std::vector<uint64_t> taint_jump_list_;   // sorted list of tainted inst IDs
    size_t taint_jump_cursor_ = 0;
    void rebuild_taint_jump_list();           // called after taint analysis
    void goto_taint_next();
    void goto_taint_prev();

    // ─── Memory panel focus/interaction ───────────────────────────────
    bool memory_panel_focused_ = false;
    size_t memory_access_cursor_ = 0;  // which mem access is highlighted
    bool handle_memory_panel_event(ftxui::Event event);

    // ─── Function list panel state ──────────────────────────────────────
    bool function_panel_focused_ = false;
    size_t function_cursor_ = 0;
    std::string function_filter_;
    std::vector<uint64_t> sorted_function_pcs_;   // Sorted function entry PCs
    std::vector<size_t> filtered_function_indices_; // Indices into sorted_function_pcs_ after filter
    int function_sort_mode_ = 0; // 0=by calls desc, 1=by name, 2=by entry_pc

    void update_function_list();   // Sort and filter the function list
    void update_function_filter();
    ftxui::Element render_functions_panel();
    bool handle_function_panel_event(ftxui::Event event);

    // Function filter dialog
    bool show_function_filter_dialog_ = false;
    std::string function_filter_input_;
    void open_function_filter_dialog();
    void close_function_filter_dialog();
    void execute_function_filter();

    // ─── Thread analysis state ──────────────────────────────────────────
    const ThreadResult* thread_result_ = nullptr;
    bool show_threads_ = false;
    bool thread_panel_focused_ = false;
    size_t thread_cursor_ = 0;  // Selected thread in thread list

    ftxui::Element render_thread_panel();
    bool handle_thread_panel_event(ftxui::Event event);
    void goto_next_thread_switch();
    void goto_prev_thread_switch();

    // ─── Loop analysis state ────────────────────────────────────────────
    const LoopResult* loop_result_ = nullptr;
    bool show_loops_ = false;        // highlight loop instructions in list
    bool show_minimap_ = true;       // show vertical minimap on left side

    ftxui::Element render_minimap_column();  // narrow vertical minimap strip

    // ─── String analysis state ──────────────────────────────────────────
    const StringResult* string_result_ = nullptr;
    bool show_strings_ = false;
    bool string_panel_focused_ = false;
    size_t string_cursor_ = 0;          // Selected string in the list
    std::string string_filter_;         // Filter/search pattern for strings
    std::vector<size_t> filtered_string_indices_;  // Indices into StringResult::strings after filter

    void update_string_filter();
    ftxui::Element render_strings_panel();
    bool handle_string_panel_event(ftxui::Event event);

    // String search dialog
    bool show_string_search_dialog_ = false;
    std::string string_search_input_;
    void open_string_search_dialog();
    void close_string_search_dialog();
    void execute_string_search();

    // ─── Breakpoint Engine ────────────────────────────────────────────
    std::unique_ptr<BreakpointEngine> bp_engine_;
    void ensure_bp_engine();

    // Command-mode dialog (":"-prefixed commands like "b 0x1234", "w 0xaddr 8")
    bool show_cmd_dialog_ = false;
    std::string cmd_input_;
    std::string cmd_error_;       ///< last command error (shown in status bar)
    std::string bp_status_msg_;   ///< last breakpoint hit / status message
    void open_cmd_dialog();
    void close_cmd_dialog();
    void execute_cmd();           ///< parse and execute the command in cmd_input_

    // Internal breakpoint operations (called by execute_cmd)
    void cmd_run_forward();       ///< continue forward until next breakpoint
    void cmd_run_backward();      ///< continue backward until previous breakpoint
    void cmd_list_breakpoints();  ///< refresh bp_status_msg_ with active BPs
    void cmd_delete_breakpoint(uint32_t id);  ///< remove breakpoint by id

    // Breakpoint list panel
    bool show_bp_panel_ = false;
    size_t bp_panel_cursor_ = 0;
    bool bp_panel_focused_ = false;
    ftxui::Element render_bp_panel();
    bool handle_bp_panel_event(ftxui::Event event);

    // ─── Unified event dispatch (eliminates duplication between components) ──
    /// Returns true if the event was consumed.
    bool handle_event(ftxui::Event event);
    bool handle_hex_dump_event(ftxui::Event event);

    // ─── Component factories ──────────────────────────────────────────
    ftxui::Component make_goto_dialog();
    ftxui::Component make_search_dialog();
    ftxui::Component make_main_component();
};

}  // namespace tenet

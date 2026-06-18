#pragma once

#include "common/types.h"
#include "common/instruction_row.h"
#include "gui/gui_settings.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/cfg_layout_pass.h"

#include <SDL3/SDL.h>
#include <imgui.h>

#ifdef __OBJC__
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#endif

#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>

namespace tenet {

// Forward declarations
struct CFGResult;
struct TaintResult;
struct SliceResult;
struct BackwardTaintResult;
struct FunctionResult;
struct XrefResult;
struct StringResult;
struct CallGraphResult;
struct LoopResult;
struct ThreadResult;
struct ConstantMaterializationResult;
struct PatternResult;
struct LoopSemanticsResult;
struct AlgorithmSummaryResult;
struct AnnotationResult;

/// Main GUI Application using Dear ImGui + SDL3 + Metal
class GuiApp {
public:
    GuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
           InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory);
    ~GuiApp();

    /// Run the GUI event loop. Returns 0 on clean exit.
    int run();

private:
    // ─── Data references ──────────────────────────────────────────────
    TraceReader& reader_;
    TraceIndex& index_;
    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile& regfile_;
    MemoryModel& memory_;

    // ─── SDL / ImGui state ────────────────────────────────────────────
    SDL_Window* window_ = nullptr;
    SDL_Renderer* renderer_ = nullptr;
    bool running_ = true;
    float dpi_scale_ = 1.0f;
    bool first_frame_ = true;  // Used to set up default dock layout

    // ─── Metal rendering state ──────────────────────────────────────
#ifdef __OBJC__
    id<MTLCommandQueue> metal_command_queue_ = nil;
    MTLRenderPassDescriptor* metal_render_pass_desc_ = nil;
#else
    void* metal_command_queue_ = nullptr;
    void* metal_render_pass_desc_ = nullptr;
#endif

    // ─── Navigation state ───────────────────────────────────────────────
    uint64_t total_inst_ = 0;
    uint64_t current_inst_ = 0;

    // ─── Navigation history (back / forward) ─────────────────────────
    static constexpr size_t kMaxNavHistory = 64;
    std::vector<uint64_t> nav_history_;      // ring buffer of visited inst_ids
    size_t nav_history_pos_ = 0;             // current position in history
    bool nav_history_navigating_ = false;    // suppress push during back/fwd

    void nav_push(uint64_t inst_id);         // push to history after navigate_to
    void nav_back();                         // navigate backward in history
    void nav_forward();                      // navigate forward in history
    bool can_nav_back() const;
    bool can_nav_forward() const;

    // ─── Search state ─────────────────────────────────────────────────
    char search_buf_[256] = {};
    char goto_buf_[128] = {};
    std::vector<uint64_t> search_results_;
    size_t search_current_ = 0;
    bool search_active_ = false;
    bool show_goto_popup_ = false;
    bool show_search_popup_ = false;

    // ─── Goto popup state ────────────────────────────────────────────
    // Autocomplete candidates: (display string, inst_id to jump to)
    struct GotoCandidate {
        std::string display;    // e.g. "sub_1234 (0x1234)"
        std::string name;       // function name
        uint64_t    pc;         // function PC
        uint64_t    inst_id;    // first inst_id of this function
    };
    std::vector<GotoCandidate> goto_candidates_;
    int  goto_selected_candidate_ = -1;   // -1 = no selection
    bool goto_candidates_dirty_   = true;  // rebuild candidates when functions change
    void rebuild_goto_candidates();        // populate goto_candidates_ from function_result_
    void goto_commit(const char* buf);     // parse buf and navigate

    // ─── Bookmarks ────────────────────────────────────────────────────
    std::vector<uint64_t> bookmarks_;

    // ─── UI panel visibility ─────────────────────────────────────────
    bool show_registers_ = true;
    bool show_memory_ = true;
    bool show_callstack_ = false;
    bool show_functions_ = true;   // IDA-style: functions panel visible by default
    bool show_analysis_ = true;
    bool show_hex_dump_ = false;
    bool show_strings_ = false;
    bool show_demo_window_ = false;
    bool show_settings_ = false;

    // ─── Settings ────────────────────────────────────────────────────
    GuiSettings settings_;
    bool settings_font_dirty_ = false;   // Font needs rebuild
    std::vector<std::string> available_fonts_;  // Cached list
    std::string imgui_ini_path_;          // Persistent path for io.IniFilename

    // ─── Cached row data ────────────────────────────────────────────
    LRUCache<uint64_t, InstructionRow> row_cache_{4096};

    // ─── Analysis state ─────────────────────────────────────────────
    std::unique_ptr<PassManager> pass_manager_;
    const TaintResult* taint_result_ = nullptr;
    const SliceResult* slice_result_ = nullptr;
    const BackwardTaintResult* backward_taint_result_ = nullptr;
    const FunctionResult* function_result_ = nullptr;
    const XrefResult* xref_result_ = nullptr;
    const CallGraphResult* call_graph_result_ = nullptr;
    bool show_taint_ = false;
    bool show_slice_ = false;
    bool show_backward_taint_ = false;
    size_t xref_cursor_ = 0;

    // ─── Taint jump state ────────────────────────────────────────────
    // Cached sorted list of tainted inst_ids for fast prev/next navigation
    std::vector<uint64_t> taint_sorted_ids_;
    bool taint_sorted_ids_dirty_ = true;
    void ensure_taint_sorted();
    void jump_taint_next();
    void jump_taint_prev();
    void jump_backward_taint_next();
    void jump_backward_taint_prev();

    // ─── Memory-to-HexDump link ──────────────────────────────────────
    // When user clicks a memory address in the memory panel, open hex dump at that addr
    void open_hex_dump_at(uint64_t addr);

    // ─── Right-click context menus ───────────────────────────────────
    // Context state is set on right-click; popup opened via OpenPopupOnItemClick.
    uint64_t ctx_mem_addr_ = 0;
    uint64_t ctx_mem_inst_id_ = 0;
    uint8_t ctx_reg_idx_ = 0;
    uint64_t ctx_reg_value_ = 0;
    size_t ctx_callstack_frame_ = 0;

    // Instruction panel context menu state
    uint64_t ctx_inst_id_ = 0;        // instruction index (0-based)
    uint64_t ctx_inst_pc_ = 0;        // runtime PC
    uint64_t ctx_inst_static_pc_ = 0; // static PC (PC - slide)
    std::string ctx_inst_disasm_;     // disassembly text

    // Function panel context menu state
    uint64_t ctx_func_pc_ = 0;        // function start PC
    std::string ctx_func_name_;

    // String panel context menu state
    uint64_t ctx_string_inst_id_ = 0;
    std::string ctx_string_text_;

    void render_mem_context_menu();
    void render_reg_context_menu();
    void render_callstack_context_menu();
    void render_inst_context_menu();          // Instruction panel right-click menu (legacy)
    void render_inst_context_menu_contents(); // Renders only the menu items (no Begin/EndPopup)
    void render_func_context_menu();          // Function panel right-click menu
    void render_string_context_menu();        // String panel right-click menu

    // ─── Function list state ─────────────────────────────────────────
    char function_filter_buf_[256] = {};
    std::string function_filter_;
    int function_sort_col_ = 0;        // 0=calls, 1=name, 2=addr
    bool function_sort_ascending_ = false;

    // ─── Loop analysis state ──────────────────────────────────────
    const LoopResult* loop_result_ = nullptr;
    bool show_loops_ = false;        // highlight loop instructions
    bool show_minimap_ = true;       // show minimap panel

    // ─── CFG view state ───────────────────────────────────────────────
    const CFGResult*       cfg_result_        = nullptr;
    const CFGLayoutResult* cfg_layout_result_ = nullptr;
    bool   show_cfg_        = true;   // IDA-style: CFG tab visible by default
    // Pan/zoom for CFG canvas
    ImVec2 cfg_scroll_      = {0.0f, 0.0f};  // pan offset in pixels
    float  cfg_zoom_        = 1.0f;          // zoom factor
    // Which block is highlighted (current PC)
    uint64_t cfg_highlight_pc_ = 0;
    // Heatmap cache: max execution count across all blocks (for normalisation)
    uint64_t cfg_max_exec_count_  = 1;
    // Max taken_count across all edges (for edge width normalisation)
    uint64_t cfg_max_edge_count_  = 1;
    // Selected block for jump-to-trace (start_pc, 0 = none)
    uint64_t cfg_selected_block_  = 0;
    // Cursor into the inst_ids list of cfg_selected_block_
    size_t   cfg_block_cursor_    = 0;

    // ─── Thread analysis state ─────────────────────────────────────
    const ThreadResult* thread_result_ = nullptr;
    bool show_threads_ = false;

    // ─── String analysis state ─────────────────────────────────────
    const StringResult* string_result_ = nullptr;
    char string_filter_buf_[256] = {};
    std::string string_filter_;
    size_t string_cursor_ = 0;

    // ─── Startup deep-analysis results ────────────────────────────────
    const ConstantMaterializationResult* constant_result_          = nullptr;
    const PatternResult*                 pattern_result_           = nullptr;
    const LoopSemanticsResult*           loop_semantics_result_    = nullptr;
    const AlgorithmSummaryResult*        algorithm_summary_result_ = nullptr;
    const AnnotationResult*              annotation_result_        = nullptr;

    // ─── Async analysis ─────────────────────────────────────────────
    std::atomic<bool> analysis_running_{false};
    std::string analysis_status_;
    std::mutex analysis_mutex_;
    std::thread startup_analysis_thread_;  // background startup analysis

    // ─── Initialization ─────────────────────────────────────────────
    bool init_sdl();
    bool init_imgui();
    void shutdown();
    void setup_style();
    void setup_fonts();

    // ─── Main render ────────────────────────────────────────────────
    void render_frame();
    void render_menu_bar();
    void render_toolbar();
    void render_status_bar();   // Bottom status bar (VS Code / IDA style)

    // ─── Panels (implemented in separate files) ──────────────────────
    void render_instruction_panel();
    void render_register_panel();
    void render_memory_panel();
    void render_callstack_panel();
    void render_functions_panel();
    void render_analysis_panel();
    void render_hex_dump_panel();
    void render_strings_panel();
    void render_thread_panel();       // Thread timeline / switching panel
    void render_minimap_panel();      // Bird's-eye minimap
    void render_cfg_panel();          // CFG graph view
    void render_progress_overlay();  // Execution progress bar with markers

    // ─── Popups / Windows ───────────────────────────────────────────
    void render_goto_popup();
    void render_search_popup();
    void render_settings_window();
    void apply_settings();          // Apply current settings (font, theme, colors)
    void rebuild_fonts();           // Rebuild font atlas from settings

    // ─── Data helpers ───────────────────────────────────────────────
    InstructionRow fetch_row(uint64_t inst_id);
    void navigate_to(uint64_t inst_id);
    void toggle_bookmark();

    // ─── Analysis helpers ───────────────────────────────────────────
    void ensure_pass_manager();
    void run_startup_analysis();    // Runs essential analyses in background on startup
    void run_taint_analysis();
    void run_backward_taint_analysis();
    void run_slice_analysis();
    void run_function_analysis();
    void run_xref_analysis();
    void run_string_analysis();
    void run_call_graph_analysis();
    void run_thread_analysis();
    void run_loop_analysis();
    void run_cfg_layout();
    void clear_analysis();

    // ─── Rendering helpers ─────────────────────────────────────────
    void render_operands_highlighted(const std::string& operands);

    // ─── Color helpers ──────────────────────────────────────────────
    ImVec4 inst_color(const std::string& mnemonic) const;
    static ImVec4 reg_color_read();
    static ImVec4 reg_color_write();
    static ImVec4 reg_color_both();
};

}  // namespace tenet

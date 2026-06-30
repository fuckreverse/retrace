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
#include "analysis/pass_registry.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/trace_fold_pass.h"
#include "io/mcp/mcp_server.h"

#include <SDL3/SDL.h>
#include <SDL3/SDL_metal.h>
#include <imgui.h>

#ifdef __OBJC__
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#endif

#include <dispatch/dispatch.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <functional>
#include <unordered_map>

namespace tenet {

// Forward declarations
struct CFGResult;
struct TaintResult;
struct SliceResult;
struct BackwardTaintResult;
// FunctionResult, CallEvent, FunctionInfo: defined in function_pass.h (included above)
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
struct TraceDiffResult;          // P2-14 (defined in trace_diff_pass.h)
struct CacheSimResult;           // defined in cache_sim_pass.h
struct SyscallInterceptResult;   // defined in syscall_intercept_pass.h
// ObjcResult is defined in objc_pass.h (already included)
// MemoryStringResult is defined in memory_string_pass.h (already included)

/// Main GUI Application using Dear ImGui + SDL3 + Metal
class GuiApp {
public:
    GuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
           InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory,
           const std::filesystem::path& trace_path = {});
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

    // ─── Trace file path (for window title) ───────────────────────────
    std::filesystem::path trace_path_;

    // ─── SDL / ImGui state ────────────────────────────────────────────
    SDL_Window* window_ = nullptr;
    SDL_MetalView metal_view_ = nullptr;
    bool running_ = true;
    float dpi_scale_ = 1.0f;
    bool first_frame_ = true;  // Used to set up default dock layout

    // ─── Graceful shutdown state ─────────────────────────────────────
    // When the user clicks Close / Cmd+Q, we do NOT immediately stop the
    // render loop.  Instead we:
    //  1. Set shutdown_requested_ = true  (hides all panels, shows overlay)
    //  2. Kick off a background thread that cancels passes and joins workers
    //  3. When that thread finishes it sets shutdown_complete_ = true
    //  4. The render loop sees shutdown_complete_ and sets running_ = false
    // This keeps the window alive and animated during teardown.
    std::atomic<bool> shutdown_requested_{false};
    std::atomic<bool> shutdown_complete_{false};
    std::thread       shutdown_thread_;

    // Progress message updated by the shutdown thread (UI thread reads it).
    // Protected by shutdown_msg_mutex_.
    std::string       shutdown_msg_{"Cancelling analysis…"};
    std::mutex        shutdown_msg_mutex_;

    /// Begin the async shutdown sequence (safe to call from render loop).
    void begin_shutdown();
    /// Render the full-screen "Shutting down" overlay (called during teardown).
    void render_shutdown_overlay();

    // ─── Metal rendering state ──────────────────────────────────────
#ifdef __OBJC__
    id<MTLDevice> metal_device_ = nil;
    CAMetalLayer* metal_layer_ = nil;
    id<MTLCommandQueue> metal_command_queue_ = nil;
    MTLRenderPassDescriptor* metal_render_pass_desc_ = nil;
#else
    void* metal_device_ = nullptr;
    void* metal_layer_ = nullptr;
    void* metal_command_queue_ = nullptr;
    void* metal_render_pass_desc_ = nullptr;
#endif

    // In-flight frame throttle: limits the number of command buffers the CPU
    // can submit ahead of the GPU.  Without this, the render loop piles up
    // hundreds of command buffers (each retaining ~128 MB of IOAccelerator
    // heap), leading to 20-35 GB memory bloat.  Value of 3 = triple buffering.
    static constexpr int kMaxInflightFrames = 3;
    dispatch_semaphore_t frame_semaphore_ = nullptr;

    // ─── Navigation state ───────────────────────────────────────────────
    uint64_t total_inst_ = 0;
    uint64_t current_inst_ = 0;
    bool     scroll_to_current_ = false;  // set by navigate_to(); consumed once by auto-scroll

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
    bool show_strings_ = true;   // IDA-style: Strings shares the main area with Instructions/CFG
    bool show_demo_window_ = false;
    bool show_settings_ = false;
    bool show_log_ = true;         // Log panel visible by default (IDA Output style)

    // ─── Settings ────────────────────────────────────────────────────
    GuiSettings settings_;
    bool settings_font_dirty_ = false;   // Font needs rebuild
    std::vector<std::string> available_fonts_;  // Cached list

    // ─── MCP HTTP SSE server (in-GUI mode) ───────────────────────────
    // When the user starts the MCP server from the Settings panel, the
    // TenetMcpService is created here and runs in the background.
    std::unique_ptr<TenetMcpService> mcp_service_;

    // Guard: auto_start_mcp() is deferred to a background thread after the
    // first frame is rendered (so the macOS menu bar appears immediately).
    // This flag ensures the deferred start fires exactly once.
    std::atomic<bool> mcp_autostart_done_{false};

    // Pending settings (edited in UI, applied on Start/Restart)
    struct McpGuiSettings {
        char host[64]     = "127.0.0.1";
        int  port         = 10444;
        char username[64] = {};
        char password[64] = {};
    } mcp_gui_;

    // Status string shown in the MCP panel
    std::string mcp_status_msg_;

    // ─── Font settings preview (pending until user clicks Save) ───
    struct PendingFontSettings {
        std::string font_path;
        float font_size = 14.0f;
        int oversample_h = 3;
        int oversample_v = 2;
        bool pixel_snap = false;
        bool initialized = false;  // set to true when settings window opens
    };
    PendingFontSettings pending_font_;

    // ─── Cached row data ────────────────────────────────────────────
    LRUCache<uint64_t, InstructionRow> row_cache_{4096};

    // ─── Cached heatmap data for progress overlay ───────────────────
    // The execution-density heatmap is derived from xref_result_ and is
    // static once xref completes. Caching it avoids re-iterating the entire
    // roaring bitmap (tens of millions of entries) every frame.
    struct HeatmapCache {
        const XrefResult* source = nullptr;   // which xref_result_ was used
        float total_inst = 0.0f;              // total_inst_ at cache time
        std::vector<uint8_t> pixels;          // RGBA per pixel column (pre-multiplied heat)
    } heatmap_cache_;

    // ─── Cached call-depth sparkline for progress overlay ───────────
    // Computed once when function_result_ changes; reused every frame.
    // Stores sampled call-stack depth per pixel column (max 600 samples).
    struct SparklineCache {
        const FunctionResult* source = nullptr;  // which function_result_ was used
        uint64_t total_inst = 0;                  // total_inst_ at cache time
        std::vector<uint64_t> depths;             // depth per sample point
        uint64_t max_depth = 1;                   // normalisation ceiling
    } sparkline_cache_;

    // ─── Cached loop-header first-inst-id list for progress overlay ─
    // inst_ids_at() allocates a vector<uint64_t> + iterates Roaring64Map each call.
    // Loop headers are static once loop/xref results are set; cache them here.
    struct LoopHeaderCache {
        const struct LoopResult*  loop_src = nullptr;
        const XrefResult*         xref_src = nullptr;
        std::vector<uint64_t>     first_inst_ids;  // one entry per loop (front inst_id)
    } loop_header_cache_;

    // ─── Cached sorted call-site inst_ids for minimap panel ─────────
    // call_at() is unordered_map::find; minimap calls it N_buckets × 4 times/frame.
    // Cache a sorted vector of call inst_ids; use std::binary_search for range checks.
    struct MinimapCallCache {
        const FunctionResult* source = nullptr;
        std::vector<uint64_t> sorted_call_ids;  // sorted call_inst_id list
    } minimap_call_cache_;

    // ─── Pre-computed minimap pixel cache ────────────────────────────
    // Minimap used to call fetch_row() up to 4× per pixel row every frame,
    // causing hundreds of ZSTD block decompressions (cold cache misses) at
    // 100% CPU.  This cache stores one color + one representative PC per row;
    // it is rebuilt only when the panel dimensions, trace metadata, or any
    // relevant analysis result changes.  Rendering becomes a simple memcpy of
    // ImU32 values — zero fetch_row() calls per frame.
    struct MinimapPixelCache {
        // Invalidation keys — rebuilt whenever any of these change
        uint64_t              total_inst        = 0;
        int                   pixel_rows        = 0;   // panel height in integer pixels
        const TaintResult*         taint_src    = nullptr;
        const BackwardTaintResult* back_src     = nullptr;
        const LoopResult*          loop_src     = nullptr;
        const FunctionResult*      func_src     = nullptr;
        bool                       show_taint   = false;
        bool                       show_btaint  = false;
        bool                       show_loops   = false;
        // Payload — one entry per pixel row
        std::vector<ImU32>    colors;   // ImGui color per row
        std::vector<uint64_t> pcs;      // representative static_pc per row (for tooltip)
        std::vector<uint64_t> inst_ids; // representative inst_id per row (for tooltip)

        bool is_valid() const { return !colors.empty(); }
        void invalidate()  { colors.clear(); pcs.clear(); inst_ids.clear(); }
    } minimap_pixel_cache_;

    /// Rebuild minimap_pixel_cache_ for the given pixel_rows count.
    void rebuild_minimap_cache(int pixel_rows);

    // ─── Analysis state ─────────────────────────────────────────────
    std::unique_ptr<PassManager> pass_manager_;
    const TaintResult* taint_result_ = nullptr;
    const SliceResult* slice_result_ = nullptr;
    const BackwardTaintResult* backward_taint_result_ = nullptr;
    const FunctionResult* function_result_ = nullptr;
    const XrefResult* xref_result_ = nullptr;

// ─── Per-frame call-stack cache ───────────────────────────────────
// call_stack_at() is O(N) in call_events.  Multiple panels (callstack,
// context menu, follow-return) call it on current_inst_ every frame.
// Cache it here; invalidated when current_inst_ or function_result_ changes.
// labels: pre-built ImGui Selectable labels for each frame — rebuilt only
// when the stack itself changes (avoids per-frame fmt::format + heap alloc).
struct CallStackCache {
const FunctionResult* source    = nullptr;
uint64_t              inst_id   = UINT64_MAX;
std::vector<const CallEvent*> stack;
std::vector<std::string>      labels;  // one per stack entry, stable across frames
} callstack_frame_cache_;

    /// Return the cached call stack for current_inst_.  Recomputes if stale.
    const std::vector<const CallEvent*>& current_call_stack();
    const CallGraphResult* call_graph_result_ = nullptr;
    bool show_call_graph_ = false;
    int  call_graph_view_mode_ = 0;    // 0=Hot Callees, 1=Edges
    char call_graph_filter_buf_[128] = {};
    std::string call_graph_filter_;
    uint64_t call_graph_selected_pc_ = 0;

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

    // Cached sorted+filtered function entry list.
    // Rebuilt only when function_result_, filter, or sort params change.
    // info_ptr is a type-erased const FunctionInfo* to avoid including function_pass.h here.
    struct FuncListCache {
        const FunctionResult* source         = nullptr;
        std::string           filter;
        int                   sort_col       = -1;   // -1 = not yet sorted
        bool                  sort_ascending = false;
        // Sorted entries: (pc, FunctionInfo ptr)
        struct Entry { uint64_t pc; const FunctionInfo* info; };
        std::vector<Entry> entries;
    } func_list_cache_;

    // ─── Loop analysis state ──────────────────────────────────────
    const LoopResult* loop_result_ = nullptr;
    bool show_loops_ = false;        // highlight loop instructions
    bool show_minimap_ = true;       // show minimap panel

    // ─── Register Timeline (data-flow animation) ───────────────────
    // Shows a sparkline of a selected register's value over time
    bool show_reg_timeline_ = false;
    uint8_t reg_timeline_reg_ = 0;         // which register is being tracked
    bool reg_timeline_dirty_ = true;       // need to rebuild sparkline data
    struct RegTimelinePoint { uint64_t inst_id; uint64_t value; };
    std::vector<RegTimelinePoint> reg_timeline_data_;  // sampled timeline

    // Producer chain highlight: a set of inst_ids to highlight
    bool show_producer_chain_ = false;
    std::vector<uint64_t> producer_chain_ids_;  // inst_ids in chain
    uint64_t producer_chain_start_inst_ = 0;    // inst_id chain was built from
    uint8_t producer_chain_reg_ = 0;            // register chain was built for

    void rebuild_reg_timeline(uint8_t reg_idx);
    void run_producer_chain(uint64_t inst_id, uint8_t reg_idx);

    // ─── CFG view state ───────────────────────────────────────────────
    const CFGResult*       cfg_result_        = nullptr;   // Full-trace CFG (all functions)
    const CFGLayoutResult* cfg_layout_result_ = nullptr;   // Current function's layout
    bool   show_cfg_        = true;   // IDA-style: CFG tab visible by default
    // Pan/zoom for CFG canvas
    ImVec2 cfg_scroll_      = {0.0f, 0.0f};  // pan offset in pixels
    float  cfg_zoom_        = 1.0f;          // zoom factor
    // Heatmap cache: max execution count across all blocks (for normalisation)
    uint64_t cfg_max_exec_count_  = 1;
    // Max taken_count across all edges (for edge width normalisation)
    uint64_t cfg_max_edge_count_  = 1;
    // Selected block for jump-to-trace (start_pc, 0 = none)
    uint64_t cfg_selected_block_  = 0;
    // Cursor into the inst_ids list of cfg_selected_block_
    size_t   cfg_block_cursor_    = 0;
    // ── Per-function CFG ─────────────────────────────────────────────
    // When non-zero, CFG panel shows only this function's sub-graph.
    uint64_t cfg_current_func_pc_ = 0;
    // Owned copies of the per-function sub-graph and its layout
    std::unique_ptr<CFGResult>       cfg_func_result_;
    std::unique_ptr<CFGLayoutResult> cfg_func_layout_;
    /// Rebuild per-function CFG layout for the function at `func_entry_pc`.
    void rebuild_cfg_for_function(uint64_t func_entry_pc);

    // ── Edge lookup cache ─────────────────────────────────────────────
    // The edge-drawing loop used to do an O(E) linear search for every edge
    // in edge_layouts, leading to O(E²) work per frame.  This cache maps
    // (from_block, to_block) → index into active_cfg->edges, rebuilt whenever
    // active_cfg changes.  Lookup is O(1) with a flat hash map.
    const CFGResult* cfg_edge_lookup_source_ = nullptr;
    // Key = (from_block XOR-folded with to_block); stored as index into
    // active_cfg->edges so the pointer remains valid.
    // We use a simple std::unordered_map with a combined uint128-style key
    // encoded as two consecutive uint64 hashed together.
    struct EdgeKey {
        uint64_t from, to;
        bool operator==(const EdgeKey& o) const noexcept {
            return from == o.from && to == o.to;
        }
    };
    struct EdgeKeyHash {
        size_t operator()(const EdgeKey& k) const noexcept {
            // FNV-1a-inspired mix of two 64-bit values
            size_t h = 0xcbf29ce484222325ULL;
            h ^= k.from; h *= 0x100000001b3ULL;
            h ^= k.to;   h *= 0x100000001b3ULL;
            return h;
        }
    };
    std::unordered_map<EdgeKey, const CFGEdge*, EdgeKeyHash> cfg_edge_lookup_;
    /// Rebuild cfg_edge_lookup_ for the given CFGResult.
    void rebuild_cfg_edge_lookup(const CFGResult* cfg);

    // ─── Thread analysis state ─────────────────────────────────────
    const ThreadResult* thread_result_ = nullptr;
    bool show_threads_ = false;

    // ─── String analysis state ─────────────────────────────────────
    const StringResult* string_result_ = nullptr;
    char string_filter_buf_[256] = {};
    std::string string_filter_;
    size_t string_cursor_ = 0;
    int string_min_len_ = 4;    // length filter lower bound (inclusive); 4 = MIN_STRING_LEN
    int string_max_len_ = 256;  // length filter upper bound (inclusive); 256 = MAX_STRING_LEN

    // ─── Startup deep-analysis results ────────────────────────────────
    const ConstantMaterializationResult* constant_result_          = nullptr;
    const PatternResult*                 pattern_result_           = nullptr;
    const LoopSemanticsResult*           loop_semantics_result_    = nullptr;
    const AlgorithmSummaryResult*        algorithm_summary_result_ = nullptr;
    const AnnotationResult*              annotation_result_        = nullptr;

    // ─── Constant materialization analysis state ─────────────────────
    bool show_constant_ = false;
    int  constant_view_mode_ = 0;   // 0=All, 1=Identified Only
    char constant_filter_buf_[128] = {};
    std::string constant_filter_;

    // Cache for filtered row list — rebuilt only when filter/mode/result changes,
    // not every frame. This avoids O(N) vector rebuild + push_back overhead per frame.
    struct ConstantRowCache {
        const ConstantMaterializationResult* source = nullptr;
        int  view_mode = -1;
        std::string filter;
        std::vector<const struct MaterializedConstant*> rows;
    } constant_row_cache_;

    // ─── Pattern analysis state ────────────────────────────────────────
    bool show_pattern_ = false;
    int pattern_view_mode_ = 0;  // 0=All, 1=Crypto, 2=AntiDebug, 3=Other
    char pattern_filter_buf_[128] = {};
    std::string pattern_filter_;
    size_t pattern_cursor_ = 0;

    // ─── Loop Semantics analysis state ────────────────────────────────
    bool show_loop_semantics_ = false;

    // ─── Algorithm Summary analysis state ─────────────────────────────────
    bool show_algorithm_summary_ = false;
    int  algorithm_view_mode_    = 0;  // 0=Candidates, 1=Summary Text

    // ─── Memory String analysis state ──────────────────────────────────
    const MemoryStringResult* mem_string_result_ = nullptr;
    bool show_mem_strings_ = false;
    char mem_string_filter_buf_[256] = {};
    std::string mem_string_filter_;
    int mem_string_view_mode_ = 0;   // 0=All, 1=RegPointer, 2=StackLocal

    // ─── Cache simulation analysis state ──────────────────────────────
    const CacheSimResult* cache_sim_result_ = nullptr;
    bool show_cache_sim_ = false;
    int  cache_sim_view_mode_ = 0;  // 0=Overview, 1=Functions, 2=SideChannels, 3=HotLines

    // ─── Syscall / API intercept analysis state ─────────────────────
    const SyscallInterceptResult* syscall_result_ = nullptr;
    bool show_syscall_intercept_ = false;
    char syscall_filter_buf_[128] = {};
    std::string syscall_filter_;
    int  syscall_view_mode_ = 0;    // 0=All, 1=Crypto Only
    size_t syscall_cursor_ = 0;

    // ─── ObjC analysis state ───────────────────────────────────────────
    const ObjcResult* objc_result_ = nullptr;
    bool show_objc_ = false;

    // ObjC panel filter / cursor state
    char objc_class_filter_buf_[128] = {};
    std::string objc_class_filter_;
    char objc_sel_filter_buf_[128] = {};
    std::string objc_sel_filter_;
    size_t objc_msg_cursor_ = 0;       // selected row in message table
    int objc_view_mode_ = 0;           // 0 = Messages, 1 = Classes

    // ─── ObjC Crypto analysis state ────────────────────────────────────────
    const ObjcCryptoResult* objc_crypto_result_ = nullptr;
    bool show_objc_crypto_ = false;
    int  objc_crypto_view_mode_ = 0;   // 0=All, 1=In ObjC, 2=Bare
    char objc_crypto_filter_buf_[128] = {};
    std::string objc_crypto_filter_;
    size_t objc_crypto_cursor_ = 0;

    // ─── Trace Fold analysis state ─────────────────────────────────────────
    const TraceFoldResult* trace_fold_result_ = nullptr;
    bool show_trace_fold_ = false;

    // ─── Cache Manager panel state ─────────────────────────────────────────
    bool show_cache_manager_ = false;
    bool cache_manager_dirty_ = true;  ///< Re-load entry list from RocksDB next frame.
    std::vector<PassManager::BlobCacheEntry> cache_manager_entries_;
    std::string cache_manager_status_;  ///< One-line feedback shown below buttons.

    // ─── Multi-trace diff state (P2-14) ────────────────────────────────
    bool show_trace_diff_ = false;
    // Region A and B inst_id ranges to compare
    uint64_t diff_region_a_start_ = 0;
    uint64_t diff_region_a_end_   = 0;
    uint64_t diff_region_b_start_ = 0;
    uint64_t diff_region_b_end_   = 0;
    char diff_a_start_buf_[32] = {};
    char diff_a_end_buf_[32]   = {};
    char diff_b_start_buf_[32] = {};
    char diff_b_end_buf_[32]   = {};
    char diff_trace_b_path_buf_[512] = {};  ///< Cross-file trace B path input
    uint32_t diff_window_size_ = 16384;     ///< Resync window size
    const TraceDiffResult* trace_diff_result_ = nullptr;
    size_t diff_cursor_ = 0;
    void run_trace_diff();

    // ─── DWARF / symbol info state (P2-13) ─────────────────────────────
    // Simple symbol table loaded from a dSYM or map file.
    // Entry: (start_addr, end_addr, func_name, source_file, line_no)
    struct DwarfSymbol {
        uint64_t start;   // runtime start address (with slide applied)
        uint64_t end;     // exclusive end address (0 = unknown)
        std::string name; // demangled function name
        std::string file; // source file path
        uint32_t line;    // line number (0 = unknown)
    };
    std::vector<DwarfSymbol> dwarf_symbols_;
    std::string dwarf_load_status_;
    char dwarf_path_buf_[512] = {};

    /// Look up the DWARF symbol containing `addr`. Returns nullptr if not found.
    const DwarfSymbol* dwarf_symbol_at(uint64_t addr) const;
    /// Load symbols from a JSON export (addr→name map) or nm-style text file.
    void load_dwarf_symbols(const std::string& path);
    bool show_dwarf_panel_ = false;

    // ─── Async analysis ─────────────────────────────────────────────
    std::atomic<bool> analysis_running_{false};
    std::string analysis_status_;
    std::mutex analysis_mutex_;
    std::thread startup_analysis_thread_;  // background startup analysis

    // ─── Async analysis infrastructure ──────────────────────────────
    // A single worker thread processes a queue of analysis tasks so the
    // UI never blocks on `require()`.  Startup analysis runs on its own
    // thread (startup_analysis_thread_) and calls run_all(N) for parallelism;
    // manual triggers are enqueued here and run concurrently with startup.
    struct AnalysisTask {
        std::string pass_name;           // for display / dedup
        std::function<void()> work;      // runs on worker thread
    };
    std::mutex              analysis_queue_mutex_;
    std::condition_variable analysis_queue_cv_;
    std::deque<AnalysisTask> analysis_queue_;
    std::thread             analysis_worker_thread_;
    std::atomic<bool>       analysis_worker_stop_{false};

    /// Active analysis counter (startup + manual).  When it hits 0,
    /// analysis_running_ is cleared.
    std::atomic<int> active_analysis_count_{0};

    /// Tracks the number of live detached threads spawned by enqueue_async().
    /// stop_analysis_worker() waits for this to reach zero before returning,
    /// so that no detached thread can outlive the TraceIndex / PassManager.
    std::atomic<int>        detached_thread_count_{0};
    std::mutex              detached_thread_mutex_;
    std::condition_variable detached_thread_cv_;

    /// Results pending UI-thread application.  Worker threads post lambdas
    /// here; the UI thread drains them at the start of each frame.  This
    /// eliminates data races on result pointers (all writes happen on UI thread).
    std::mutex                      pending_apply_mutex_;
    std::vector<std::function<void()>> pending_apply_;

    /// Set to true by apply_pending_results() when at least one lambda was
    /// drained.  render_frame() reads this to perform a FocusWindow() call
    /// that makes newly-populated panels visible without stealing focus from
    /// whatever the user was doing.
    bool results_applied_this_frame_ = false;

    /// Window names that should have their dock tab made visible on the next
    /// frame after analysis results arrive.  Only populated when a pass
    /// produces a result whose panel is currently hidden behind another tab.
    /// Processed and cleared at the top of render_frame().
    std::vector<std::string> pending_focus_windows_;

    void analysis_worker_loop();       // runs on analysis_worker_thread_
    void enqueue_async(std::string pass_name, std::function<void()> work);
    void post_apply(std::function<void()> fn);   // thread-safe: queue for UI thread
    void apply_pending_results();                // call on UI thread each frame
    void start_analysis_worker();               // call once at startup
    void stop_analysis_worker();                // call on shutdown (joins worker)

    // ─── Native macOS menu bar ───────────────────────────────────────
    // NSMenu action callbacks run on the main thread (same as the render loop),
    // but they fire *outside* an ImGui frame.  To avoid corrupting ImGui state,
    // callbacks post lambdas into pending_native_actions_; render_frame() drains
    // them at the very start of each frame, before any ImGui calls.
    std::mutex                         native_action_mutex_;
    std::vector<std::function<void()>> pending_native_actions_;

    /// Called once after init_sdl() / init_imgui() to build the NSMenu tree.
    void setup_native_menu();
    /// Drain pending_native_actions_ on the UI/render thread (called every frame).
    void consume_native_actions();

    // Internal callbacks invoked by ObjC TenetMenuTarget / TenetMenuDelegate.
    // Declared public so the ObjC glue objects (defined in gui_app.mm, outside
    // namespace tenet) can call them without friendship hacks.
    // Uses long / void* to keep ObjC types out of this header.
public:
    void _post_native_action(long tag);      // called by TenetMenuTarget on menu click
    void _update_native_menu(void* nsMenu);  // called by TenetMenuDelegate before menu opens
private:

    /// Helper: safely get a completed pass result pointer, or nullptr.
    const PassResult* completed_result(std::string_view name);
    /// Apply UI-side result pointers for a completed pass (function, xref, etc.).
    void apply_pass_result_pointers(std::string_view name);

    // ─── Layout constants (shared by render_frame / toolbar / status bar) ──
    static constexpr float kToolbarHeight   = 30.0f;  // toolbar window height
    static constexpr float kTimelineHeight  = 32.0f;  // execution timeline height (4-lane)
    static constexpr float kStatusBarHeight = 22.0f;  // bottom status bar height

    // ─── Timeline watch address (right-click to set) ─────────────────
    // When non-zero, memory write events at this address are shown as
    // orange markers in the timeline's taint lane.
    uint64_t timeline_watch_addr_ = 0;

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
    void render_thread_panel();          // Thread timeline / switching panel
    void render_minimap_panel();         // Bird's-eye minimap
    void render_cfg_panel();             // CFG graph view
    void render_progress_overlay();      // Execution progress bar with markers
    void render_reg_timeline_panel();    // Register value history sparkline (P2-12)
    void render_dwarf_panel();           // DWARF / nm symbol info panel (P2-13)
    void render_trace_diff_panel();      // Multi-trace divergence view (P2-14)
    void render_pattern_panel();          // Pattern recognition (crypto/anti-debug)
    void render_constant_panel();         // Constant materialization / algorithm constant identification
    void render_cache_sim_panel();               // Cache simulation / side-channel
    void render_objc_panel();                  // Objective-C message analysis
    void render_objc_crypto_panel();           // ObjC x Crypto correlation
    void render_call_graph_panel();            // Call graph analysis
    void render_loop_semantics_panel();        // Loop semantic classification
    void render_algorithm_summary_panel();     // Algorithm identification summary
    void render_memory_strings_panel();          // Time-aware memory string discovery
    void render_trace_fold_panel();              // Trace fold (loop-compressed) view
    void render_syscall_intercept_panel();       // iOS system API intercept (CommonCrypto, etc.)
    void render_log_panel();                       // Output / Log panel (IDA-style)
    void render_cache_manager_panel();             // Pass-cache management panel

    // ─── Log panel state ─────────────────────────────────────────────
    // GuiLogEntry mirrors tenet::log::LogEntry but avoids including logger.h
    // in every GUI translation unit.
    struct GuiLogEntry {
        int         level;       // cast of tenet::log::Level
        double      timestamp;
        double      rss_mb;
        std::string message;
    };

    struct LogPanelState {
        std::vector<GuiLogEntry> entries;       // accumulated log entries
        bool auto_scroll = true;                // scroll to bottom on new entries
        int  level_filter = 0;                  // 0=All, 1=Info+, 2=Warn+, 3=Error only
        char filter_buf[256] = {};              // text filter
        std::string filter_text;
    } log_panel_;

    // ─── Popups / Windows ───────────────────────────────────────────
    void render_goto_popup();
    void render_search_popup();
    void render_settings_window();
    void apply_settings();          // Apply current settings (font, theme, colors)
    void rebuild_fonts();           // Rebuild font atlas from settings

    // ─── Data helpers ───────────────────────────────────────────────
    InstructionRow fetch_row(uint64_t inst_id);
    void navigate_to(uint64_t inst_id);
    /// Navigate to inst_id AND bring the "Instructions" dock tab to the front.
    /// Use this from any analysis panel's right-click "Jump to Instructions" action.
    void navigate_to_instructions(uint64_t inst_id);
    void toggle_bookmark();

    // ─── Analysis helpers ───────────────────────────────────────────
    void ensure_pass_manager();
    void run_startup_analysis();    // Runs essential analyses in background on startup
    void auto_start_mcp();         // Auto-start MCP HTTP server on GUI launch
    void run_taint_analysis();
    void run_backward_taint_analysis();
    void run_slice_analysis();
    void run_call_graph_analysis();
    void run_cfg_layout();
    void clear_analysis();

    // Export helpers: run the underlying pass (if needed) then write to disk.
    // On macOS these open an NSSavePanel to pick the destination.
    void export_cfg_to_file();
    void export_call_graph_to_file();
    void export_backward_taint_graph_to_file();

    /// Run any catalog pass by name, deriving config from the current cursor.
    /// Stores a one-line summary in last_pass_status_.
    void run_pass_by_name(std::string_view name);

    /// Force re-run a pass by invalidating both its in-memory result and its
    /// persisted RocksDB blob, then enqueue it for execution.
    /// Use for passes that have disk caches (xref, function, constant_materialization).
    void force_rerun_pass(std::string_view name);

    /// Last generic pass run summary (shown in the All Passes section).
    std::string last_pass_status_;

    // ─── Rendering helpers ─────────────────────────────────────────
    void render_operands_highlighted(const std::string& operands);

    // ─── Color helpers ──────────────────────────────────────────────
    ImVec4 inst_color(const std::string& mnemonic) const;
    static ImVec4 reg_color_read();
    static ImVec4 reg_color_write();
    static ImVec4 reg_color_both();
};

}  // namespace tenet

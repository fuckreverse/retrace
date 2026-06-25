#pragma once

#include "common/types.h"
#include "common/instruction_row.h"
#include <cstdint>
#include <string>
#include <vector>

namespace tenet {

// Forward declarations
class TraceReader;
class TraceIndex;
class CodeTable;
class InstructionDecoder;
class RegisterFile;
class MemoryModel;
class PassManager;
struct TaintResult;
struct SliceResult;
struct BackwardTaintResult;
struct FunctionResult;
struct XrefResult;
struct StringResult;
struct CallGraphResult;
struct LoopResult;
struct ThreadResult;

/// Shared context that all TUI panels can read from and write to.
/// Owned by TuiApp; panels hold a reference to it.
///
/// Design:  Public data members for simplicity (panels are trusted internal
///          code, not a plugin boundary). This avoids getter/setter bloat
///          for ~40 fields that panels need to access.
struct TuiContext {
    // ─── Data layer references ────────────────────────────────────────
    TraceReader*        reader = nullptr;
    TraceIndex*         index = nullptr;
    CodeTable*          code_table = nullptr;
    InstructionDecoder* decoder = nullptr;
    RegisterFile*       regfile = nullptr;
    MemoryModel*        memory = nullptr;

    // ─── Navigation state (read/write by panels) ──────────────────────
    uint64_t total_inst = 0;
    uint64_t current_inst = 0;
    uint64_t viewport_top = 0;
    int      viewport_height = 20;

    // ─── Analysis results (written by TuiApp pass wiring, read by panels) ─
    const TaintResult*         taint_result = nullptr;
    const SliceResult*         slice_result = nullptr;
    const BackwardTaintResult* backward_taint_result = nullptr;
    const FunctionResult*      function_result = nullptr;
    const XrefResult*          xref_result = nullptr;
    const StringResult*        string_result = nullptr;
    const CallGraphResult*     call_graph_result = nullptr;
    const LoopResult*          loop_result = nullptr;
    const ThreadResult*        thread_result = nullptr;

    bool show_taint = false;
    bool show_backward_taint = false;
    bool show_nzcv = true;
    bool show_fpr = false;

    // ─── Bookmarks (shared) ───────────────────────────────────────────
    std::vector<uint64_t> bookmarks;

    // ─── Row fetching (provided by TuiApp) ────────────────────────────
    /// Panels call this to fetch a decoded instruction row by id.
    /// Set by TuiApp to point at its fetch_row method.
    InstructionRow (*fetch_row)(void* self, uint64_t inst_id) = nullptr;
    void* fetch_row_self = nullptr;

    InstructionRow get_row(uint64_t inst_id) const {
        return fetch_row(fetch_row_self, inst_id);
    }

    // ─── Navigation callbacks (provided by TuiApp) ────────────────────
    void (*navigate_to_fn)(void* self, uint64_t inst_id) = nullptr;
    void* navigate_self = nullptr;

    void navigate_to(uint64_t inst_id) const {
        navigate_to_fn(navigate_self, inst_id);
    }

    // ─── Taint jump list (shared between panels) ──────────────────────
    std::vector<uint64_t> taint_jump_list;
    size_t taint_jump_cursor = 0;

    // ─── Search results (shared) ──────────────────────────────────────
    std::vector<uint64_t> search_results;
    size_t search_current = 0;
    bool search_active = false;
};

}  // namespace tenet

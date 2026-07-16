// tools/tenet/src/service/tenet_service.h
#pragma once

#include "common/types.h"
#include "common/instruction_row.h"
#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tenet {

// Forward declarations
class TraceReader;
class TraceIndex;
class CodeTable;
class InstructionDecoder;
class RegisterFile;
class MemoryModel;

// ─── Observer ────────────────────────────────────────────────────────────────

/// Frontends implement this to receive state-change notifications.
/// All callbacks are invoked on the thread that triggered the change
/// (may be a background analysis thread). Implementations must be
/// thread-safe or post to their own event loop.
class TenetServiceObserver {
public:
    virtual ~TenetServiceObserver() = default;

    /// A pass has completed (or failed). `name` is the pass key (e.g. "xref").
    virtual void on_pass_completed(std::string_view name) {}

    /// The cursor moved to a new instruction.
    virtual void on_navigation(uint64_t inst_id) {}

    /// A bookmark was toggled (added or removed).
    virtual void on_bookmark_changed() {}
};

// ─── TenetService ────────────────────────────────────────────────────────────

/// Central application-state manager shared by all frontends.
///
/// Owns: PassManager, instruction row cache, navigation state (cursor,
/// history, bookmarks, search), and typed pass-result pointers.
///
/// Does NOT own the backend objects (TraceReader, TraceIndex, RegisterFile,
/// MemoryModel, CodeTable, InstructionDecoder) — those are created in
/// main() and passed by reference.
class TenetService {
public:
    TenetService(TraceReader& reader,
                 TraceIndex& index,
                 CodeTable& code_table,
                 InstructionDecoder& decoder,
                 RegisterFile& regfile,
                 MemoryModel& memory,
                 const std::string& trace_path = {});

    ~TenetService();

    // Non-copyable, non-movable
    TenetService(const TenetService&) = delete;
    TenetService& operator=(const TenetService&) = delete;

    // ── Backend accessors (for panels that need direct access) ───────────
    TraceReader&        reader()  { return reader_; }
    TraceIndex&         index()   { return index_; }
    CodeTable&          code_table() { return code_table_; }
    InstructionDecoder& decoder() { return decoder_; }
    RegisterFile&       regfile() { return regfile_; }
    MemoryModel&        memory()  { return memory_; }
    const std::string&  trace_path() const { return trace_path_; }

    // ── Navigation ──────────────────────────────────────────────────────
    uint64_t current_inst() const { return current_inst_.load(std::memory_order_relaxed); }
    uint64_t total_inst()   const { return total_inst_.load(std::memory_order_relaxed); }

    void navigate_to(uint64_t inst_id);

    void nav_back();
    void nav_forward();
    bool can_nav_back() const;
    bool can_nav_forward() const;

    // ── Bookmarks ───────────────────────────────────────────────────────
    /// Thread-safe snapshot of bookmarks for cross-thread consumers.
    std::vector<uint64_t> bookmarks() const;
    void toggle_bookmark(uint64_t inst_id);
    bool has_bookmark(uint64_t inst_id) const;

    // ── Instruction row fetching (cached) ───────────────────────────────
    InstructionRow fetch_row(uint64_t inst_id);

    /// Drop all cached rows (e.g. after external state changes).
    void clear_row_cache() {
        std::lock_guard lk(row_cache_mutex_);
        row_cache_.clear();
    }

    // ── Pass management ─────────────────────────────────────────────────

    /// Ensure PassManager is created and wired to backend objects.
    /// Thread-safe lazy init: all callers see the same fully initialized
    /// instance before this returns.
    PassManager& ensure_pass_manager();

    /// Run the curated default startup passes (async-friendly).
    void run_default_passes();

    /// Run a single pass by name, deriving config from current cursor.
    /// Returns true if the pass completed successfully.
    bool run_pass(std::string_view name, const PassRunCtx& ctx = {});

    /// Access the underlying PassManager (may be nullptr if not yet created).
    /// Reads are synchronized with ensure_pass_manager() publication.
    PassManager* pass_manager();

    // ── Typed pass result accessors ─────────────────────────────────────
    // Each returns nullptr if the pass has not run or failed.
    // The returned pointer is valid until the pass is invalidated.
    // Callers should NOT cache these across pass re-runs; prefer
    // calling the accessor each time.

    template<typename T>
    const T* pass_result(std::string_view name) const {
        std::shared_lock<std::shared_mutex> lk(state_mutex_);
        auto it = pinned_results_.find(std::string(name));
        if (it == pinned_results_.end() || !it->second || !it->second->ok())
            return nullptr;
        return &it->second->get<T>();
    }

    /// Pin a pass result (keep it alive via shared_ptr) and return
    /// a typed pointer to its data.  Returns nullptr on failure.
    template<typename T>
    const T* pin_pass_result(std::string_view name) {
        auto* pm = pass_manager();
        if (!pm) return nullptr;
        auto sp = pm->require_shared(name);
        if (!sp || !sp->ok()) return nullptr;
        const T* ptr = &sp->get<T>();
        {
            std::unique_lock lk(state_mutex_);
            pinned_results_[std::string(name)] = sp;
        }
        notify_pass_completed(name);
        return ptr;
    }

    /// Clear all pinned pass results.
    void clear_analysis();

    // ── Search ──────────────────────────────────────────────────────────
    /// Thread-safe snapshots/values for cross-thread readers.
    std::vector<uint64_t> search_results() const;
    size_t search_current() const;
    bool search_active() const;

    /// Search from `from_inst` with wrap-around and return an immutable result
    /// snapshot suitable for direct frontend consumption.
    std::vector<uint64_t> search_forward(const std::string& query, uint64_t from_inst);
    void search_clear();

    // ── Observer management ─────────────────────────────────────────────
    void add_observer(TenetServiceObserver* obs);
    void remove_observer(TenetServiceObserver* obs);

private:
    // ── Notification helpers ────────────────────────────────────────────
    void notify_navigation(uint64_t inst_id);
    void notify_pass_completed(std::string_view name);
    void notify_bookmark_changed();

    // ── Navigation history ──────────────────────────────────────────────
    void nav_push(uint64_t inst_id);
    static constexpr size_t kMaxNavHistory = 64;
    std::vector<uint64_t> nav_history_;
    size_t nav_history_pos_ = 0;
    bool nav_history_navigating_ = false;

    // ── Backend references (non-owning) ─────────────────────────────────
    TraceReader& reader_;
    TraceIndex& index_;
    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile& regfile_;
    MemoryModel& memory_;
    std::string trace_path_;

    // ── Application state ───────────────────────────────────────────────
    std::atomic<uint64_t> current_inst_{0};
    std::atomic<uint64_t> total_inst_{0};
    std::vector<uint64_t> bookmarks_;
    // O(1) lookup mirror of bookmarks_ — populated alongside bookmarks_
    // on every mutation (toggle_bookmark, load). fetch_row() calls
    // has_bookmark() for every visible row, so O(N) std::find on the
    // vector was a per-frame hotspot.
    std::unordered_set<uint64_t> bookmark_set_;

    // ── Row cache ───────────────────────────────────────────────────────
    // Separate mutex: cache get() mutates LRU order, so it needs exclusive
    // access, but the critical section is very short (hash + promote).
    // This avoids blocking state_mutex_ readers during cache operations.
    LRUCache<uint64_t, InstructionRow> row_cache_{4096};
    mutable std::mutex row_cache_mutex_;

    // ── Pass engine ─────────────────────────────────────────────────────
    mutable std::mutex pass_manager_mutex_;
    std::once_flag pass_manager_once_;
    std::unique_ptr<PassManager> pass_manager_;

    // Keeps pass results alive (thread-safe shared_ptr ownership).
    std::unordered_map<std::string, std::shared_ptr<const PassResult>> pinned_results_;

    // ── Search state ────────────────────────────────────────────────────
    std::vector<uint64_t> search_results_;
    size_t search_current_ = 0;
    bool search_active_ = false;

    // ── Thread safety ───────────────────────────────────────────────────
    // Protects: nav_history_, bookmarks_, bookmark_set_, search_results_,
    //           search_current_, search_active_, pinned_results_.
    // Shared lock for read-only access (has_bookmark, search_results,
    //           pass_result, bookmarks).
    // Unique lock for mutations (navigate_to, toggle_bookmark, search_forward,
    //           clear_analysis, run_pass, pin_pass_result).
    //
    // row_cache_ has its own mutex (row_cache_mutex_) because LRU get()
    // mutates internal state.
    // current_inst_ and total_inst_ are atomic (no mutex needed).
    mutable std::shared_mutex state_mutex_;

    // ── Observers ───────────────────────────────────────────────────────
    mutable std::mutex observers_mutex_;
    std::vector<TenetServiceObserver*> observers_;
};

}  // namespace tenet

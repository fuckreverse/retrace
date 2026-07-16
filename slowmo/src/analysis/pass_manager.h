#pragma once

#include "common/types.h"
#include <any>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <optional>

namespace tenet {

// Forward declarations
class TraceReader;
class TraceIndex;
class CodeTable;
class RegisterFile;
class MemoryModel;
class InstructionDecoder;
// Infra layer forward declarations
class ScanOrchestrator;
class PageStats;
class StringResolver;
class CheckpointManager;

// ─── Pass result ──────────────────────────────────────────────────────────

/// Type-erased result container for pass outputs.
struct PassResult {
    enum Status { Success, Failed, Skipped };
    Status status = Skipped;
    std::string error_message;
    std::any data;

    template<typename T>
    static PassResult success(T&& result) {
        PassResult r;
        r.status = Success;
        r.data = std::make_any<std::decay_t<T>>(std::forward<T>(result));
        return r;
    }

    static PassResult failed(std::string msg) {
        PassResult r;
        r.status = Failed;
        r.error_message = std::move(msg);
        return r;
    }

    static PassResult skipped() {
        return PassResult{Skipped, {}, {}};
    }

    bool ok() const { return status == Success; }

    template<typename T>
    const T& get() const { return std::any_cast<const T&>(data); }
};

// ─── Analysis range ───────────────────────────────────────────────────────

struct AnalysisRange {
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id = UINT64_MAX;

    /// PC address ranges to exclude from analysis [start, end).
    /// Instructions with PC in any of these ranges are skipped by the scan engine.
    /// The excluded instructions still exist in the trace (RegisterFile/MemoryModel
    /// state reconstruction is unaffected) — they are simply not delivered to passes.
    std::vector<std::pair<uint64_t, uint64_t>> exclude_pc_ranges;

    bool is_full_trace() const { return start_inst_id == 0 && end_inst_id == UINT64_MAX; }

    /// Check if a PC falls within any excluded range.
    bool is_pc_excluded(uint64_t pc) const {
        for (const auto& [start, end] : exclude_pc_ranges) {
            if (pc >= start && pc < end) return true;
        }
        return false;
    }
};

// ─── Pass context ─────────────────────────────────────────────────────────

class PassManager;  // forward

/// Provides access to IO/Core layers and other pass results.
class PassContext {
public:
    PassContext(PassManager& pm, const AnalysisRange& range)
        : manager_(pm), range_(range) {}

    // IO layer
    TraceReader& reader();
    TraceIndex& index();
    CodeTable& code_table();

    // Core layer
    RegisterFile& regfile();
    MemoryModel& memory();
    InstructionDecoder& decoder();

    // Infra layer services
    ScanOrchestrator&  scan_orchestrator();
    PageStats&         page_stats();
    StringResolver&    string_resolver();
    CheckpointManager& checkpoint_manager();

    // Pass results (triggers dependency execution if needed)
    template<typename T>
    const T& require(std::string_view pass_name);

    /// Try to get a pass result without triggering execution.
    /// Returns nullptr if the pass was not registered, did not run, or failed.
    /// Use this for optional dependencies — call the dependency explicitly in
    /// dependencies() if you want it to run; use try_require in run() to
    /// consume its result when it may or may not be present.
    template<typename T>
    const T* try_require(std::string_view pass_name);

    const PassResult& require_raw(std::string_view pass_name);

    // Range
    const AnalysisRange& range() const { return range_; }

    // Progress — publishes to the shared ProgressManager task stream.
    void progress(float pct);
    void progress(float pct, std::string_view msg);
    /// True if the user requested cancellation (global or per-pass).
    bool cancelled() const;
    void cancel();

    /// Returns a reference to the global cancellation flag.  Thread-safe to
    /// read from any thread (lock-free atomic).  Intended for passes that
    /// spawn their own worker threads and need a lightweight cancellation
    /// check in tight inner loops.
    const std::atomic<bool>& global_cancel_flag() const;


    /// Whether parallel trace scanning is disabled at runtime.
    bool no_parallel_scan() const;

private:
    PassManager& manager_;
    AnalysisRange range_;

    // Set by PassManager::execute_pass for per-pass cancellation checks.
    std::atomic<bool>*  cancelled_flag_ = nullptr;
    std::string_view    pass_name_;  // for progress-message lookup

    friend class PassManager;
};

// ─── Analysis pass base ───────────────────────────────────────────────────

/// Base class for all analysis passes.
class AnalysisPass {
public:
    virtual ~AnalysisPass() = default;

    /// Unique name of this pass.
    virtual std::string_view name() const = 0;

    /// Human-readable description.
    virtual std::string_view description() const = 0;

    /// List of pass names this pass depends on (must run first).
    virtual std::vector<std::string_view> dependencies() const { return {}; }

    /// Execute the pass.
    virtual PassResult run(PassContext& ctx) = 0;

    /// Try to load a complete persisted result before any trace collector is
    /// declared or executed. Return std::nullopt on cache miss, incompatible
    /// configuration, corrupt data, or when this pass is not cacheable.
    ///
    /// Implementations must fully validate and deserialize the cached result;
    /// merely observing that a cache file exists is not sufficient because a
    /// failed load must fall back to the normal scan + run path.
    virtual std::optional<PassResult> try_load_cached(PassContext& ctx) {
        (void)ctx;
        return std::nullopt;
    }

    /// Declare scan collector requirements for Scan Fusion (default: none).
    /// Override to participate in unified trace scanning.
    /// Called before run() phase, after all passes are registered.
    virtual void declare_scan(class ScanOrchestrator& orchestrator, PassContext& ctx) {
        (void)orchestrator; (void)ctx;
    }

    /// Whether this pass participates in scan fusion.
    /// Default false. Scanning passes override to return true.
    /// PassManager uses this to decide whether to orchestrate scanning
    /// before calling run() in the require() path.
    virtual bool has_scan() const { return false; }

    /// Whether this pass supports incremental update.
    virtual bool supports_incremental() const { return false; }

    /// Incremental update (default: full re-run).
    virtual PassResult update(PassContext& ctx, const AnalysisRange& changed) {
        (void)changed;
        return run(ctx);
    }

    /// Estimated cost (for scheduling priority). Higher = slower.
    virtual float estimated_cost() const { return 1.0f; }
};

// ─── Pass manager ─────────────────────────────────────────────────────────

/// Manages pass registration, dependency resolution, caching, and execution.
/// Supports true parallel execution via per-pass atomic state and condition variables.
class PassManager {
public:
    PassManager();
    ~PassManager();

    // ─── Configuration (call before execution) ─────────────────────────

    /// Register a pass. Takes ownership.
    void register_pass(std::unique_ptr<AnalysisPass> pass);

    /// Set the IO/Core layer objects (must be called before running any pass).
    void set_reader(TraceReader* r)  { reader_ = r; }
    void set_index(TraceIndex* i)    { index_ = i; }
    void set_code_table(CodeTable* c) { code_table_ = c; }
    void set_regfile(RegisterFile* r) { regfile_ = r; }
    void set_memory(MemoryModel* m)  { memory_ = m; }
    void set_decoder(InstructionDecoder* d) { decoder_ = d; }

    /// Initialize Infra layer services. Must be called AFTER set_reader/set_index/
    /// set_code_table/set_regfile/set_memory/set_decoder.
    void init_infra();

    /// Set analysis range.
    void set_range(const AnalysisRange& range) { range_ = range; }


    /// Disable parallel trace scanning within individual passes.
    void set_no_parallel_scan(bool v) { no_parallel_scan_ = v; }
    bool no_parallel_scan() const { return no_parallel_scan_; }

    // ─── Memory pressure management ────────────────────────────────────

    /// Set the RSS limit in MB. When exceeded, non-critical passes are skipped.
    void set_rss_limit_mb(double limit_mb) { rss_limit_mb_ = limit_mb; }

    /// Check if memory pressure is high (RSS > limit).
    bool is_memory_pressure() const;

    // ─── Execution ─────────────────────────────────────────────────────

    /// Run a specific pass by name (and all its dependencies).
    /// Thread-safe: multiple threads can call require() concurrently.
    /// Uses lock-free fast path for already-completed passes.
    const PassResult& require(std::string_view pass_name);

    /// Shared-ownership variant of require(). Returns a shared_ptr that keeps
    /// the underlying PassResult (and the data it owns, e.g. a
    /// VMAbstractResult or TraceFoldResult) alive even if another thread
    /// concurrently invalidates or re-runs the pass and replaces the entry's
    /// result with a new one.
    ///
    /// Use this instead of require()/require_raw() whenever the caller needs
    /// to hold on to the result across some non-trivial span of time or
    /// across a thread boundary — e.g. the GUI caching a result pointer for
    /// rendering across many frames while the in-GUI MCP server (which
    /// shares this same PassManager, on its own request-handling thread)
    /// might concurrently invalidate/re-run the same pass.
    ///
    /// Returns nullptr only if the pass name is not registered at all.
    std::shared_ptr<const PassResult> require_shared(std::string_view pass_name);

    /// Run all registered passes in dependency order with true parallelism.
    ///
    /// Uses a dynamic ready-queue scheduler (LLVM New PassManager style):
    /// each pass has an atomic pending-deps counter; when it hits zero the
    /// pass is enqueued and any idle worker picks it up.  This eliminates
    /// the long-pole problem of level-by-level scheduling — a pass at
    /// "level 2" can start as soon as *its* deps finish, without waiting
    /// for the whole previous level.
    void run_all(size_t num_threads = 1);

    /// Invalidate a pass result (will re-run on next require).
    void invalidate(std::string_view pass_name);

    /// Invalidate all results.
    void invalidate_all();

    /// Invalidate a pass result AND delete its persisted RocksDB blob so that
    /// the next run performs a full re-computation instead of loading from cache.
    ///
    /// Passes that use save_pass_blob (and thus honour this call):
    ///   xref, function, constant_materialization, cfg, loop, call_graph,
    ///   disassembly, thread, loop_semantics, window_stats, syscall_intercept,
    ///   memory_strings, symbol_annotation.
    ///
    /// Safe to call for any pass name (no-op for passes without a cache blob).
    void invalidate_and_clear_blob(std::string_view pass_name);

    /// Request cancellation of all in-flight passes.  Passes that check
    /// `PassContext::cancelled()` will abort early.  Thread-safe.
    void cancel_all() {
        cancelled_.store(true, std::memory_order_release);
        // Wake any sleeping workers in run_all_parallel so they can exit.
        if (worker_cv_ && worker_mtx_) {
            std::lock_guard<std::mutex> lk(*worker_mtx_);
            worker_cv_->notify_all();
        }
    }

    /// Request cancellation of a single pass by name.  Thread-safe.
    void cancel(std::string_view pass_name);

    /// Reset all cancellation flags (global + per-pass).  Call this before
    /// starting a fresh analysis batch so previously-cancelled passes can run.
    void reset_cancel();

    // ─── Query ─────────────────────────────────────────────────────────

    enum class PassState : int { NotRun = 0, Running = 1, Completed = 2, Failed = 3 };
    PassState state(std::string_view pass_name) const;
    std::vector<std::string_view> all_passes() const;

    // ─── Cache management (for the Cache Manager panel) ────────────────

    /// Information about a single pass's persisted blob cache.
    struct BlobCacheEntry {
        std::string name;       ///< Pass name
        size_t      blob_size;  ///< Persisted blob size in bytes
        bool        in_memory;  ///< Whether an in-memory result exists
        PassState   state;      ///< Current pass execution state
    };

    /// Return information about all persisted pass-result blobs in the RocksDB
    /// index.  Each entry has a name, disk size, and whether there's also an
    /// in-memory result ready.
    std::vector<BlobCacheEntry> query_blob_info() const;

    /// Delete all persisted pass-result blobs from the RocksDB index in one
    /// batch.  Does NOT invalidate in-memory results.
    /// Returns the number of blobs deleted.
    size_t clear_all_blobs();

    /// Per-pass cancellation flag.
    bool is_pass_cancelled(std::string_view pass_name) const;

    // ─── Internal (used by PassContext) ────────────────────────────────

    TraceReader* reader()  { return reader_; }
    TraceIndex* index()    { return index_; }
    CodeTable* code_table() { return code_table_; }
    RegisterFile* regfile() { return regfile_; }
    MemoryModel* memory()  { return memory_; }
    InstructionDecoder* decoder() { return decoder_; }

    /// Global cancellation flag (set by cancel_all, read by all PassContexts).
    bool is_cancelled() const { return cancelled_.load(std::memory_order_acquire); }

private:
    struct PassEntry {
        std::unique_ptr<AnalysisPass> pass;

        // The result is stored behind a shared_ptr and *replaced* (never
        // mutated in place) on every (re-)execution or invalidation. This
        // means any thread that previously copied out `result_ptr` via
        // require_shared() keeps a strong reference to the old PassResult
        // (and the data it owns) even after a concurrent invalidate/re-run
        // swaps in a new one — eliminating the use-after-free window where
        // e.g. the GUI main thread renders a cached `const T*` into a
        // result that the MCP server's request thread concurrently
        // invalidated and destroyed in place.
        //
        // Readers on the fast path (require_raw/require<T>) still get a
        // plain reference for convenience; that's safe as long as the
        // reference isn't retained past the current synchronous call (which
        // holds true for every existing in-tree caller — pass dependency
        // resolution and MCP tool handlers that serialize the result to
        // JSON immediately). Callers that DO need to retain the result
        // across time or threads (GUI panels, MCP long-lived caches) must
        // use require_shared() instead.
        std::shared_ptr<const PassResult> result_ptr =
            std::make_shared<const PassResult>(PassResult::skipped());
        std::atomic<PassState> state{PassState::NotRun};
        std::mutex mtx;                   // protects result_ptr write
        std::condition_variable cv;       // signals completion

        // Dynamic scheduling fields (used only by run_all).
        std::atomic<size_t> pending_deps{0};   // # of deps not yet completed
        std::vector<size_t> dependents;        // indices of passes that depend on this one

        std::atomic<bool> cancelled{false};
        bool scan_executed{false};  // prevents re-scan in require() path
    };

    PassEntry* find_entry(std::string_view name);
    const PassEntry* find_entry(std::string_view name) const;

    /// Compute topological execution levels from dependency DAG.
    /// (Kept for fallback / debugging; run_all uses the dynamic scheduler.)
    std::vector<std::vector<std::string_view>> topological_levels() const;

    /// Internal: execute a pass (assumes we own execution via CAS).
    void execute_pass(PassEntry* entry);
    bool try_complete_from_cache(PassEntry* entry);

    /// Dynamic ready-queue scheduler used by run_all when num_threads > 1.
    void run_all_parallel(size_t num_threads);

    /// Build the reverse dependency graph (dependents[] + pending_deps)
    /// on all entries.  Called once at the start of run_all_parallel.
    void build_dependency_graph();

    std::vector<std::unique_ptr<PassEntry>> entries_;
    std::unordered_map<std::string_view, PassEntry*> name_map_;

    // IO/Core layer pointers (non-owning)
    TraceReader* reader_ = nullptr;
    TraceIndex* index_ = nullptr;
    CodeTable* code_table_ = nullptr;
    RegisterFile* regfile_ = nullptr;
    MemoryModel* memory_ = nullptr;
    InstructionDecoder* decoder_ = nullptr;

    // Infra layer services (owned)
    std::unique_ptr<ScanOrchestrator>  scan_orchestrator_;
    std::unique_ptr<PageStats>         page_stats_;
    std::unique_ptr<StringResolver>    string_resolver_;
    std::unique_ptr<CheckpointManager> checkpoint_manager_;

    bool no_parallel_scan_ = false;

    AnalysisRange range_;
    double rss_limit_mb_ = 0.0;  // 0 = no limit (default)
    mutable std::mutex registry_mutex_;  // protects entries_/name_map_ during registration

    // Global cancellation flag (set by cancel_all, read by PassContext::cancelled).
    std::atomic<bool> cancelled_{false};

    // Pointer to the active worker CV in run_all_parallel so cancel_all()
    // can wake sleeping workers immediately.  Protected by the same mutex
    // pointed to by worker_mtx_.  Null when not in run_all_parallel.
    std::condition_variable* worker_cv_ = nullptr;
    std::mutex*              worker_mtx_ = nullptr;

    static PassResult not_found_result_;

    friend class PassContext;
};

// ─── Template implementations ─────────────────────────────────────────────

template<typename T>
const T& PassContext::require(std::string_view pass_name) {
    const auto& result = require_raw(pass_name);
    return result.get<T>();
}

template<typename T>
const T* PassContext::try_require(std::string_view pass_name) {
    // Check state without triggering execution
    if (manager_.state(pass_name) != PassManager::PassState::Completed) {
        return nullptr;
    }
    const auto& result = require_raw(pass_name);
    if (!result.ok() || !result.data.has_value()) return nullptr;
    const T* p = std::any_cast<T>(&result.data);
    return p;
}

inline const std::atomic<bool>& PassContext::global_cancel_flag() const {
    return manager_.cancelled_;
}

}  // namespace tenet

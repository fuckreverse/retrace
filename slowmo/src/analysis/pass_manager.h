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

namespace tenet {

// Forward declarations
class TraceReader;
class TraceIndex;
class CodeTable;
class RegisterFile;
class MemoryModel;
class InstructionDecoder;
class TraceScanEngine;

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

    bool is_full_trace() const { return start_inst_id == 0 && end_inst_id == UINT64_MAX; }
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

    // Pass results (triggers dependency execution if needed)
    template<typename T>
    const T& require(std::string_view pass_name);

    const PassResult& require_raw(std::string_view pass_name);

    // Range
    const AnalysisRange& range() const { return range_; }

    // Progress
    void progress(float pct);
    void progress(float pct, std::string_view msg);
    bool cancelled() const { return cancelled_.load(); }
    void cancel() { cancelled_.store(true); }

    /// Access the shared trace scan engine (for passes that want to run collectors).
    TraceScanEngine* scan_engine();

private:
    PassManager& manager_;
    AnalysisRange range_;
    std::atomic<bool> cancelled_{false};
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

    /// Set analysis range.
    void set_range(const AnalysisRange& range) { range_ = range; }

    /// Set the shared trace scan engine.
    void set_scan_engine(TraceScanEngine* e) { scan_engine_ = e; }
    TraceScanEngine* scan_engine() { return scan_engine_; }

    // ─── Execution ─────────────────────────────────────────────────────

    /// Run a specific pass by name (and all its dependencies).
    /// Thread-safe: multiple threads can call require() concurrently.
    /// Uses lock-free fast path for already-completed passes.
    const PassResult& require(std::string_view pass_name);

    /// Run all registered passes in dependency order with true parallelism.
    /// Passes in the same topological level run concurrently.
    void run_all(size_t num_threads = 1);

    /// Invalidate a pass result (will re-run on next require).
    void invalidate(std::string_view pass_name);

    /// Invalidate all results.
    void invalidate_all();

    // ─── Query ─────────────────────────────────────────────────────────

    enum class PassState : int { NotRun = 0, Running = 1, Completed = 2, Failed = 3 };
    PassState state(std::string_view pass_name) const;
    std::vector<std::string_view> all_passes() const;

    // ─── Internal (used by PassContext) ────────────────────────────────

    TraceReader* reader()  { return reader_; }
    TraceIndex* index()    { return index_; }
    CodeTable* code_table() { return code_table_; }
    RegisterFile* regfile() { return regfile_; }
    MemoryModel* memory()  { return memory_; }
    InstructionDecoder* decoder() { return decoder_; }

private:
    struct PassEntry {
        std::unique_ptr<AnalysisPass> pass;
        PassResult result;
        std::atomic<PassState> state{PassState::NotRun};
        std::mutex mtx;                   // protects result write
        std::condition_variable cv;       // signals completion
    };

    PassEntry* find_entry(std::string_view name);
    const PassEntry* find_entry(std::string_view name) const;

    /// Compute topological execution levels from dependency DAG.
    std::vector<std::vector<std::string_view>> topological_levels() const;

    /// Internal: execute a pass (assumes we own execution via CAS).
    void execute_pass(PassEntry* entry);

    std::vector<std::unique_ptr<PassEntry>> entries_;
    std::unordered_map<std::string_view, PassEntry*> name_map_;

    // IO/Core layer pointers (non-owning)
    TraceReader* reader_ = nullptr;
    TraceIndex* index_ = nullptr;
    CodeTable* code_table_ = nullptr;
    RegisterFile* regfile_ = nullptr;
    MemoryModel* memory_ = nullptr;
    InstructionDecoder* decoder_ = nullptr;
    TraceScanEngine* scan_engine_ = nullptr;

    AnalysisRange range_;
    mutable std::mutex registry_mutex_;  // protects entries_/name_map_ during registration

    static PassResult not_found_result_;
};

// ─── Template implementations ─────────────────────────────────────────────

template<typename T>
const T& PassContext::require(std::string_view pass_name) {
    const auto& result = require_raw(pass_name);
    return result.get<T>();
}

}  // namespace tenet

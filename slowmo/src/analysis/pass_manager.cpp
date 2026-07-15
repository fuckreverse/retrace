#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "common/logger.h"
#include "common/Profiling.h"
#include "common/progress_manager.h"
#include "io/index_builder.h"
#include "infra/scan_orchestrator.h"
#include "infra/page_stats.h"
#include "infra/string_resolver.h"
#include "infra/checkpoint_manager.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <queue>
#include <stdexcept>
#include <unordered_set>

namespace tenet {

namespace {
std::string pass_task_id(std::string_view name) {
    return "pass:" + std::string(name);
}
}  // namespace

// ─── Static ────────────────────────────────────────────────────────────────

PassResult PassManager::not_found_result_ = PassResult::failed("pass not found");

// ─── PassContext ──────────────────────────────────────────────────────────

TraceReader& PassContext::reader()  { return *manager_.reader(); }
TraceIndex& PassContext::index()    { return *manager_.index(); }
CodeTable& PassContext::code_table() { return *manager_.code_table(); }
RegisterFile& PassContext::regfile() { return *manager_.regfile(); }
MemoryModel& PassContext::memory()  { return *manager_.memory(); }
InstructionDecoder& PassContext::decoder() { return *manager_.decoder(); }

ScanOrchestrator&  PassContext::scan_orchestrator()  { return *manager_.scan_orchestrator_; }
PageStats&         PassContext::page_stats()         { return *manager_.page_stats_; }
StringResolver&    PassContext::string_resolver()    { return *manager_.string_resolver_; }
CheckpointManager& PassContext::checkpoint_manager() { return *manager_.checkpoint_manager_; }

const PassResult& PassContext::require_raw(std::string_view pass_name) {
    return manager_.require(pass_name);
}

void PassContext::progress(float pct) {
    ProgressManager::global().update_fraction(pass_task_id(pass_name_), pct);
    LOG_DEBUG_M(::tenet::log::Module::Analysis, "pass progress: {:.0f}%", pct * 100.0f);
}
void PassContext::progress(float pct, std::string_view msg) {
    ProgressManager::global().update_fraction(pass_task_id(pass_name_), pct, "run", msg);
    LOG_DEBUG_M(::tenet::log::Module::Analysis, "pass progress: {:.0f}% — {}", pct * 100.0f, msg);
}

bool PassContext::cancelled() const {
    if (cancelled_flag_ && cancelled_flag_->load(std::memory_order_acquire))
        return true;
    return manager_.is_cancelled();
}
void PassContext::cancel() { manager_.cancel_all(); }

bool PassContext::no_parallel_scan() const { return manager_.no_parallel_scan(); }

// ─── PassManager ──────────────────────────────────────────────────────────

PassManager::PassManager() = default;
PassManager::~PassManager() = default;

void PassManager::init_infra() {
    // All IO/Core pointers must be set before calling this.
    if (!reader_ || !index_ || !regfile_ || !memory_) {
        LOG_WARN_M(::tenet::log::Module::Analysis,
            "PassManager::init_infra(): IO/Core pointers not fully set — skipping");
        return;
    }
    if (!scan_orchestrator_) {
        scan_orchestrator_ = std::make_unique<ScanOrchestrator>(
            *reader_, index_->inst_count(), index_);
    }
    if (!page_stats_) {
        page_stats_ = std::make_unique<PageStats>(*memory_);
    }
    if (!string_resolver_) {
        string_resolver_ = std::make_unique<StringResolver>(*memory_, *page_stats_);
    }
    if (!checkpoint_manager_) {
        checkpoint_manager_ = std::make_unique<CheckpointManager>(*regfile_);
    }
    {
        auto t0 = std::chrono::steady_clock::now();
        auto& progress = ProgressManager::global();
        progress.start("checkpoints", "initialization", "Build register checkpoints", 0, "scan");
        checkpoint_manager_->ensure_checkpoints([&progress](uint64_t done, uint64_t total) {
            progress.update("checkpoints", done, total,
                            "scan", "Building register checkpoints");
        });
        progress.complete("checkpoints", "Register checkpoints ready");
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        LOG_INFO_M(::tenet::log::Module::Analysis,
            "PassManager::init_infra(): checkpoints built in {:.1f} ms", ms);
    }
}

void PassManager::register_pass(std::unique_ptr<AnalysisPass> pass) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    auto name = pass->name();

    // If the pass was previously registered but then invalidated (NotRun state),
    // allow replacing the pass object so that a new config takes effect.
    // This is the expected pattern when re-running with different parameters
    // (e.g. vm_abstract with updated static hints).
    auto it = name_map_.find(name);
    if (it != name_map_.end()) {
        PassEntry* existing = it->second;
        std::lock_guard<std::mutex> elk(existing->mtx);
        if (existing->state.load(std::memory_order_acquire) == PassState::NotRun) {
            // Safe to replace: pass was invalidated and has not started running.
            existing->pass = std::move(pass);
            LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager: replaced invalidated pass '{}'", name);
            return;
        }
        // Pass is Running or Completed — silently ignore (idempotent).
        LOG_WARN_M(::tenet::log::Module::Analysis, "PassManager: duplicate registration of '{}' ignored", name);
        return;
    }

    auto entry = std::make_unique<PassEntry>();
    entry->pass = std::move(pass);
    auto* ptr = entry.get();
    entries_.push_back(std::move(entry));
    name_map_[name] = ptr;
}

// ─── Memory pressure ──────────────────────────────────────────────────────

bool PassManager::is_memory_pressure() const {
    if (rss_limit_mb_ <= 0.0) return false;
    return ::tenet::log::rss_mb() > rss_limit_mb_;
}

// ─── Lock-free fast path + CAS claiming ──────────────────────────────────

namespace {
// Per-thread keepalive table used by PassManager::require() so it can keep
// returning a plain `const PassResult&` (source-compatible with the ~100
// existing call sites) while staying safe against a *different* thread
// concurrently invalidating/re-running the same pass and replacing
// PassEntry::result_ptr.
//
// Keyed by PassEntry* so that unrelated passes required from the same
// thread (e.g. `require("cfg_layout")` immediately followed by
// `require("cfg")`, both used together afterwards — see batch_analysis.cpp
// run_export_cfg()) each get their own keepalive slot instead of clobbering
// one another. A single shared thread_local variable would silently
// invalidate the first reference as soon as the second require() ran.
//
// This table only grows to the number of distinct passes actually required
// from a given thread (bounded by the pass catalog size — a few dozen), so
// it is not a meaningful leak. Entries are naturally refreshed (not
// accumulated) on every require() of the same pass.
thread_local std::unordered_map<const void*, std::shared_ptr<const PassResult>>
    g_require_keepalive;
}  // namespace

const PassResult& PassManager::require(std::string_view pass_name) {
    auto* entry = find_entry(pass_name);
    if (!entry) return not_found_result_;

    // NOTE on lifetime: the returned reference stays valid at least until
    // this thread calls require()/require_shared() again for the *same*
    // pass (see g_require_keepalive above) — every existing in-tree caller
    // either uses the reference immediately or (as in run_export_cfg) keeps
    // references to two *different* passes alive simultaneously, which the
    // per-entry keepalive slots handle correctly. Callers that need to keep
    // a result alive across frames/threads regardless of what else runs
    // (GUI panel caches, long-lived MCP state) MUST use require_shared()
    // instead, which returns an owning shared_ptr the caller controls
    // directly.
    //
    // We take a local shared_ptr copy (via atomic_load) before dereferencing
    // so that even if another thread concurrently replaces entry->result_ptr
    // (invalidate/re-run), the object we're about to return a reference into
    // stays alive — the old PassResult is only destroyed once every
    // shared_ptr to it (including this thread's keepalive slot) is gone.
    auto refresh_and_return = [entry]() -> const PassResult& {
        auto ptr = std::atomic_load_explicit(&entry->result_ptr, std::memory_order_acquire);
        const PassResult& ref = *ptr;
        g_require_keepalive[entry] = std::move(ptr);
        return ref;
    };

    // Lock-free fast path: if already done, return immediately (no mutex).
    PassState s = entry->state.load(std::memory_order_acquire);
    if (s == PassState::Completed || s == PassState::Failed) {
        return refresh_and_return();
    }

    // Try to claim execution via CAS (NotRun -> Running).
    PassState expected = PassState::NotRun;
    if (entry->state.compare_exchange_strong(expected, PassState::Running,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
        // We own execution. Run dependencies first, then this pass.
        execute_pass(entry);
        return refresh_and_return();
    }

    // Someone else is running it. Wait until completion.
    std::unique_lock<std::mutex> lk(entry->mtx);
    entry->cv.wait(lk, [&entry] {
        PassState cur = entry->state.load(std::memory_order_acquire);
        return cur == PassState::Completed || cur == PassState::Failed;
    });
    lk.unlock();
    return refresh_and_return();
}

std::shared_ptr<const PassResult> PassManager::require_shared(std::string_view pass_name) {
    auto* entry = find_entry(pass_name);
    if (!entry) return nullptr;

    PassState s = entry->state.load(std::memory_order_acquire);
    if (s == PassState::Completed || s == PassState::Failed) {
        return std::atomic_load_explicit(&entry->result_ptr, std::memory_order_acquire);
    }

    PassState expected = PassState::NotRun;
    if (entry->state.compare_exchange_strong(expected, PassState::Running,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
        execute_pass(entry);
        return std::atomic_load_explicit(&entry->result_ptr, std::memory_order_acquire);
    }

    std::unique_lock<std::mutex> lk(entry->mtx);
    entry->cv.wait(lk, [&entry] {
        PassState cur = entry->state.load(std::memory_order_acquire);
        return cur == PassState::Completed || cur == PassState::Failed;
    });
    lk.unlock();
    return std::atomic_load_explicit(&entry->result_ptr, std::memory_order_acquire);
}

void PassManager::execute_pass(PassEntry* entry) {
    TENET_ZONE;
    TENET_ZONE_TEXT("pass: {}", entry->pass->name());

    const auto task_id = pass_task_id(entry->pass->name());
    ProgressManager::global().start(task_id, "pass", std::string(entry->pass->name()), 0, "dependencies");

    // Fast-path: skip immediately if global cancellation is requested.
    if (is_cancelled()) {
        std::lock_guard<std::mutex> lk(entry->mtx);
        std::atomic_store_explicit(&entry->result_ptr,
            std::make_shared<const PassResult>(PassResult::failed("cancelled")),
            std::memory_order_release);
        entry->state.store(PassState::Failed, std::memory_order_release);
        entry->cv.notify_all();
        ProgressManager::global().cancel(task_id, "Cancelled before execution");
        return;
    }

    // First, recursively ensure all dependencies are done.
    for (auto dep_name : entry->pass->dependencies()) {
        const auto& dep_result = require(dep_name);
        if (!dep_result.ok()) {
            // Dependency failed — propagate failure.
            LOG_WARN_M(::tenet::log::Module::Analysis, "pass '{}': dependency '{}' failed — skipping",
                     entry->pass->name(), dep_name);
            {
                std::lock_guard<std::mutex> lk(entry->mtx);
                std::atomic_store_explicit(&entry->result_ptr,
                    std::make_shared<const PassResult>(PassResult::failed(
                        std::string("dependency '") + std::string(dep_name) + "' failed")),
                    std::memory_order_release);
                entry->state.store(PassState::Failed, std::memory_order_release);
            }
            entry->cv.notify_all();
            ProgressManager::global().fail(task_id,
                std::string("dependency '") + std::string(dep_name) + "' failed");
            return;
        }
    }

    // Memory pressure check: skip non-critical passes when RSS exceeds limit.
    // Critical passes (cost < 2.0) always run; others are skipped under pressure.
    if (is_memory_pressure() && entry->pass->estimated_cost() >= 2.0f) {
        LOG_WARN_M(::tenet::log::Module::Analysis, "pass '{}': skipped due to memory pressure (RSS {:.0f}MB > {:.0f}MB limit)",
                 entry->pass->name(), ::tenet::log::rss_mb(), rss_limit_mb_);
        {
            std::lock_guard<std::mutex> lk(entry->mtx);
            std::atomic_store_explicit(&entry->result_ptr,
                std::make_shared<const PassResult>(PassResult::skipped()),
                std::memory_order_release);
            entry->state.store(PassState::Failed, std::memory_order_release);
        }
        entry->cv.notify_all();
        ProgressManager::global().fail(task_id, "skipped due to memory pressure");
        return;
    }

    // Execute the pass itself.
    LOG_DEBUG_M(::tenet::log::Module::Analysis, "pass '{}': starting", entry->pass->name());
    auto t0  = TENET_TIMER_START();
    double m0 = ::tenet::log::rss_mb();

    entry->cancelled.store(false, std::memory_order_relaxed);
    ProgressManager::global().update_fraction(task_id, 0.0f, "run", "Running analysis pass");

    PassContext ctx(*this, range_);
    ctx.pass_name_       = entry->pass->name();
    ctx.cancelled_flag_  = &entry->cancelled;

    // Scan Fusion: if this pass participates in scan fusion and hasn't been
    // scanned yet (require() path), orchestrate a single scan before run().
    // In run_all() path, the scan was already done in Phase 2.
    if (entry->pass->has_scan() && !entry->scan_executed) {
        ScanOrchestrator orch(*reader_, index_->inst_count(), index_);
        entry->pass->declare_scan(orch, ctx);
        if (orch.has_declarations()) {
            orch.execute_scan(range_, cancelled_, no_parallel_scan_);
        }
        entry->scan_executed = true;
    }

    PassResult result = entry->pass->run(ctx);

    double ms   = TENET_TIMER_MS(t0);
    double dmem = ::tenet::log::rss_mb() - m0;

    if (result.ok()) {
        LOG_INFO_M(::tenet::log::Module::Analysis, "pass '{}': OK  {:.1f}ms  mem {:+.1f}MB",
                 entry->pass->name(), ms, dmem);
    } else {
        LOG_WARN_M(::tenet::log::Module::Analysis, "pass '{}': FAILED  {:.1f}ms  — {}",
                 entry->pass->name(), ms, result.error_message);
    }

    const bool result_ok = result.ok();
    const std::string result_error = result.error_message;
    {
        std::lock_guard<std::mutex> lk(entry->mtx);
        bool ok = result_ok;
        // Build the new, immutable result behind a fresh shared_ptr and swap
        // it in atomically. The *old* shared_ptr (and the PassResult/data it
        // points to) is only decremented here; if some other thread is still
        // holding a strong reference obtained via require_shared() earlier,
        // the old object stays alive until that thread releases it too.
        std::atomic_store_explicit(&entry->result_ptr,
            std::make_shared<const PassResult>(std::move(result)),
            std::memory_order_release);
        entry->state.store(
            ok ? PassState::Completed : PassState::Failed,
            std::memory_order_release);
    }
    entry->cv.notify_all();
    if (result_ok) {
        auto task = ProgressManager::global().get(task_id);
        ProgressManager::global().complete(
            task_id, task && !task->message.empty() ? task->message : "Pass completed");
    } else if (entry->cancelled.load(std::memory_order_acquire) || is_cancelled()) {
        ProgressManager::global().cancel(task_id, result_error);
    } else {
        ProgressManager::global().fail(task_id, result_error);
    }
}

// ─── Parallel run_all using a dynamic ready-queue (LLVM New PM style) ─────
//
// Each pass has an atomic pending_deps counter initialised to the number of
// dependencies.  When a dependency completes, it decrements the counter of
// every pass that depends on it; the pass whose counter reaches zero is
// pushed onto the ready queue and any idle worker picks it up.
//
// This eliminates the long-pole problem of level-by-level scheduling: a
// pass at "level 2" can start as soon as *its* deps finish, without waiting
// for the whole previous level to drain.

void PassManager::build_dependency_graph() {
    // Reset scheduling state.
    for (auto& e : entries_) {
        e->pending_deps.store(0, std::memory_order_relaxed);
        e->dependents.clear();
    }

    // name → index
    ankerl::unordered_dense::map<std::string_view, size_t> idx_of;
    idx_of.reserve(entries_.size());
    for (size_t i = 0; i < entries_.size(); ++i) {
        idx_of[entries_[i]->pass->name()] = i;
    }

    // Count pending_deps and build reverse edges.
    for (size_t i = 0; i < entries_.size(); ++i) {
        for (auto dep : entries_[i]->pass->dependencies()) {
            auto it = idx_of.find(dep);
            if (it == idx_of.end()) continue;  // external/missing dep
            entries_[it->second]->dependents.push_back(i);
            entries_[i]->pending_deps.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

void PassManager::run_all_parallel(size_t num_threads) {
    TENET_ZONE_NAMED("PassManager::run_all_parallel");
    build_dependency_graph();

    // Ready queue: indices of passes whose deps are all satisfied.
    std::mutex q_mtx;
    std::condition_variable q_cv;
    std::vector<size_t> ready;
    ready.reserve(entries_.size());

    // Expose CV/mutex so cancel_all() can wake sleeping workers.
    worker_cv_  = &q_cv;
    worker_mtx_ = &q_mtx;

    // Seed with all zero-dep passes.
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i]->pending_deps.load(std::memory_order_acquire) == 0) {
            ready.push_back(i);
        }
    }

    std::atomic<size_t> completed{0};
    std::atomic<bool>   failed_dep{false};
    const size_t total = entries_.size();

    auto worker = [&]() {
        while (true) {
            size_t idx;
            {
                std::unique_lock<std::mutex> lk(q_mtx);
                q_cv.wait(lk, [&] {
                    return !ready.empty()
                        || completed.load(std::memory_order_acquire) == total
                        || cancelled_.load(std::memory_order_acquire);
                });
                if (cancelled_.load(std::memory_order_acquire)) {
                    return;  // global cancellation requested
                }
                if (ready.empty() &&
                    completed.load(std::memory_order_acquire) == total) {
                    return;  // everything done
                }
                if (ready.empty()) continue;  // spurious wakeup
                idx = ready.back();
                ready.pop_back();
            }

            // Run the pass.  require() uses CAS so only one thread actually
            // executes it; other workers that somehow picked the same idx
            // (shouldn't happen because the queue is drained under lock)
            // would just hit the fast path.
            auto& entry = entries_[idx];
            const auto& result = this->require(entry->pass->name());

            // If a dependency failed, skip downstream scheduling work —
            // require() already propagated the failure.
            if (!result.ok()) {
                failed_dep.store(true, std::memory_order_relaxed);
            }

            // Notify dependents.
            for (size_t dep_idx : entry->dependents) {
                size_t prev = entries_[dep_idx]->pending_deps.fetch_sub(
                    1, std::memory_order_acq_rel);
                if (prev == 1) {
                    std::lock_guard<std::mutex> lk(q_mtx);
                    ready.push_back(dep_idx);
                    q_cv.notify_one();
                }
            }

            size_t done = completed.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (done == total) {
                std::lock_guard<std::mutex> lk(q_mtx);
                q_cv.notify_all();  // wake any sleeping workers so they can exit
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(num_threads - 1);
    for (size_t i = 0; i + 1 < num_threads; ++i) {
        threads.emplace_back(worker);
    }
    worker();  // run on main thread too
    for (auto& t : threads) t.join();

    // Clear CV/mutex pointers before they go out of scope.
    worker_cv_  = nullptr;
    worker_mtx_ = nullptr;

    if (failed_dep.load(std::memory_order_relaxed)) {
        LOG_WARN_M(::tenet::log::Module::Analysis, "PassManager::run_all: one or more passes failed (see above)");
    }
}

void PassManager::run_all(size_t num_threads) {
    LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager::run_all: {} passes, {} threads, RSS limit={}MB",
             entries_.size(), num_threads,
             rss_limit_mb_ > 0 ? fmt::format("{:.0f}", rss_limit_mb_) : "none");

    // ── Phase 1: Declaration — each pass's declare_scan() registers collectors ──
    if (scan_orchestrator_) {
        PassContext ctx(*this, range_);
        for (auto& entry : entries_) {
            entry->pass->declare_scan(*scan_orchestrator_, ctx);
        }

        // ── Phase 2: Unified scan — one traversal serves all collectors ──
        if (scan_orchestrator_->has_declarations()) {
            LOG_INFO_M(::tenet::log::Module::Analysis,
                "PassManager: executing unified scan with {} collector(s)",
                scan_orchestrator_->has_declarations() ? "multiple" : "0");
            scan_orchestrator_->execute_scan(range_, cancelled_, no_parallel_scan_);
        }
    }

    // ── Phase 3: Execution — existing DAG scheduler (unchanged) ──
    if (num_threads <= 1 || entries_.size() <= 1) {
        // Sequential fallback: just require each pass in registration order.
        for (auto& entry : entries_) {
            require(entry->pass->name());
        }
        LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
        return;
    }

    run_all_parallel(num_threads);

    LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
}

// ─── Invalidation ─────────────────────────────────────────────────────────

void PassManager::invalidate(std::string_view pass_name) {
    auto* entry = find_entry(pass_name);
    if (!entry) return;

    std::lock_guard<std::mutex> lk(entry->mtx);
    entry->state.store(PassState::NotRun, std::memory_order_release);
    // Swap in a fresh "skipped" result rather than mutating the existing one
    // in place. Any thread holding a shared_ptr obtained via require_shared()
    // (e.g. the GUI rendering a cached result, or an MCP handler still
    // serializing a previous response) keeps its own reference alive and
    // unaffected by this invalidate — only *new* callers see NotRun/skipped.
    std::atomic_store_explicit(&entry->result_ptr,
        std::make_shared<const PassResult>(PassResult::skipped()),
        std::memory_order_release);
}

void PassManager::invalidate_all() {
    for (auto& entry : entries_) {
        std::lock_guard<std::mutex> lk(entry->mtx);
        entry->state.store(PassState::NotRun, std::memory_order_release);
        std::atomic_store_explicit(&entry->result_ptr,
            std::make_shared<const PassResult>(PassResult::skipped()),
            std::memory_order_release);
        entry->cancelled.store(false, std::memory_order_release);
    }
    cancelled_.store(false, std::memory_order_release);
}

void PassManager::invalidate_and_clear_blob(std::string_view pass_name) {
    // Reset in-memory state so the pass re-runs on next require().
    invalidate(pass_name);
    // Delete the persisted RocksDB blob so the pass doesn't reload from cache.
    if (index_) {
        index_->delete_pass_blob(pass_name);
    }
}

// ─── Per-pass cancellation ────────────────────────────────────────────────

void PassManager::cancel(std::string_view pass_name) {
    auto* e = find_entry(pass_name);
    if (e) e->cancelled.store(true, std::memory_order_release);
}

void PassManager::reset_cancel() {
    cancelled_.store(false, std::memory_order_release);
    for (auto& e : entries_) {
        e->cancelled.store(false, std::memory_order_release);
    }
}

bool PassManager::is_pass_cancelled(std::string_view pass_name) const {
    const auto* e = find_entry(pass_name);
    if (!e) return false;
    return e->cancelled.load(std::memory_order_acquire);
}

// ─── Query ────────────────────────────────────────────────────────────────

PassManager::PassState PassManager::state(std::string_view pass_name) const {
    const auto* entry = find_entry(pass_name);
    if (!entry) return PassState::NotRun;
    return entry->state.load(std::memory_order_acquire);
}

std::vector<std::string_view> PassManager::all_passes() const {
    std::vector<std::string_view> names;
    names.reserve(entries_.size());
    for (auto& e : entries_) {
        names.push_back(e->pass->name());
    }
    return names;
}

// ─── Internal helpers ─────────────────────────────────────────────────────

PassManager::PassEntry* PassManager::find_entry(std::string_view name) {
    auto it = name_map_.find(name);
    return (it != name_map_.end()) ? it->second : nullptr;
}

const PassManager::PassEntry* PassManager::find_entry(std::string_view name) const {
    auto it = name_map_.find(name);
    return (it != name_map_.end()) ? it->second : nullptr;
}

// ─── Cache management ─────────────────────────────────────────────────────

std::vector<PassManager::BlobCacheEntry> PassManager::query_blob_info() const {
    std::vector<BlobCacheEntry> result;
    if (!index_) return result;

    // Get all persisted blobs from RocksDB.
    auto blobs = index_->list_pass_blobs();
    result.reserve(blobs.size());
    for (const auto& b : blobs) {
        BlobCacheEntry entry;
        entry.name      = b.name;
        entry.blob_size = b.size;
        // Check if there's also an in-memory result.
        const auto* e = find_entry(entry.name);
        if (e) {
            PassState s = e->state.load(std::memory_order_acquire);
            entry.in_memory = (s == PassState::Completed);
            entry.state     = s;
        } else {
            entry.in_memory = false;
            entry.state     = PassState::NotRun;
        }
        result.push_back(std::move(entry));
    }
    return result;
}

size_t PassManager::clear_all_blobs() {
    if (!index_) return 0;
    return index_->delete_all_pass_blobs();
}

std::vector<std::vector<std::string_view>> PassManager::topological_levels() const {
    // Kahn's algorithm for topological sort with level tracking.
    std::unordered_map<std::string_view, size_t> in_degree;
    std::unordered_map<std::string_view, std::vector<std::string_view>> dependents;

    for (auto& entry : entries_) {
        auto name = entry->pass->name();
        if (in_degree.find(name) == in_degree.end()) {
            in_degree[name] = 0;
        }
        for (auto dep : entry->pass->dependencies()) {
            dependents[dep].push_back(name);
            in_degree[name]++;
        }
    }

    // Find all roots (in-degree 0).
    std::vector<std::string_view> current_level;
    for (auto& [name, deg] : in_degree) {
        if (deg == 0) {
            current_level.push_back(name);
        }
    }

    std::vector<std::vector<std::string_view>> levels;
    while (!current_level.empty()) {
        levels.push_back(current_level);
        std::vector<std::string_view> next_level;

        for (auto name : current_level) {
            auto it = dependents.find(name);
            if (it == dependents.end()) continue;
            for (auto dep_name : it->second) {
                in_degree[dep_name]--;
                if (in_degree[dep_name] == 0) {
                    next_level.push_back(dep_name);
                }
            }
        }

        current_level = std::move(next_level);
    }

    return levels;
}

}  // namespace tenet

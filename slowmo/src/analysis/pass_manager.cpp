#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "common/logger.h"
#include "io/index_builder.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <queue>
#include <stdexcept>
#include <unordered_set>

namespace tenet {

// ─── Static ────────────────────────────────────────────────────────────────

PassResult PassManager::not_found_result_ = PassResult::failed("pass not found");

// ─── PassContext ──────────────────────────────────────────────────────────

TraceReader& PassContext::reader()  { return *manager_.reader(); }
TraceIndex& PassContext::index()    { return *manager_.index(); }
CodeTable& PassContext::code_table() { return *manager_.code_table(); }
RegisterFile& PassContext::regfile() { return *manager_.regfile(); }
MemoryModel& PassContext::memory()  { return *manager_.memory(); }
InstructionDecoder& PassContext::decoder() { return *manager_.decoder(); }

const PassResult& PassContext::require_raw(std::string_view pass_name) {
    return manager_.require(pass_name);
}

void PassContext::progress(float pct) {
    if (progress_pct_) progress_pct_->store(pct, std::memory_order_relaxed);
    if (::tenet::log::is_enabled(::tenet::log::Level::Debug)) {
        ::tenet::log::detail::write(::tenet::log::Level::Debug,
            "pass progress: {:.0f}%", pct * 100.0f);
    }
}
void PassContext::progress(float pct, std::string_view msg) {
    if (progress_pct_) progress_pct_->store(pct, std::memory_order_relaxed);
    if (!msg.empty()) {
        manager_.set_progress_msg(pass_name_, msg);
    }
    if (::tenet::log::is_enabled(::tenet::log::Level::Debug)) {
        ::tenet::log::detail::write(::tenet::log::Level::Debug,
            "pass progress: {:.0f}% — {}", pct * 100.0f, msg);
    }
}

bool PassContext::cancelled() const {
    if (cancelled_flag_ && cancelled_flag_->load(std::memory_order_acquire))
        return true;
    return manager_.is_cancelled();
}
void PassContext::cancel() { manager_.cancel_all(); }

TraceScanEngine* PassContext::scan_engine() { return manager_.scan_engine(); }
bool PassContext::no_parallel_scan() const { return manager_.no_parallel_scan(); }

// ─── PassManager ──────────────────────────────────────────────────────────

PassManager::PassManager() = default;
PassManager::~PassManager() = default;

void PassManager::register_pass(std::unique_ptr<AnalysisPass> pass) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    auto entry = std::make_unique<PassEntry>();
    auto name = pass->name();
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

const PassResult& PassManager::require(std::string_view pass_name) {
    auto* entry = find_entry(pass_name);
    if (!entry) return not_found_result_;

    // Lock-free fast path: if already done, return immediately (no mutex).
    PassState s = entry->state.load(std::memory_order_acquire);
    if (s == PassState::Completed || s == PassState::Failed) {
        return entry->result;
    }

    // Try to claim execution via CAS (NotRun -> Running).
    PassState expected = PassState::NotRun;
    if (entry->state.compare_exchange_strong(expected, PassState::Running,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
        // We own execution. Run dependencies first, then this pass.
        execute_pass(entry);
        return entry->result;
    }

    // Someone else is running it. Wait until completion.
    std::unique_lock<std::mutex> lk(entry->mtx);
    entry->cv.wait(lk, [&entry] {
        PassState cur = entry->state.load(std::memory_order_acquire);
        return cur == PassState::Completed || cur == PassState::Failed;
    });
    return entry->result;
}

void PassManager::execute_pass(PassEntry* entry) {
    // First, recursively ensure all dependencies are done.
    for (auto dep_name : entry->pass->dependencies()) {
        const auto& dep_result = require(dep_name);
        if (!dep_result.ok()) {
            // Dependency failed — propagate failure.
            LOG_WARN("pass '{}': dependency '{}' failed — skipping",
                     entry->pass->name(), dep_name);
            {
                std::lock_guard<std::mutex> lk(entry->mtx);
                entry->result = PassResult::failed(
                    std::string("dependency '") + std::string(dep_name) + "' failed");
                entry->state.store(PassState::Failed, std::memory_order_release);
            }
            entry->cv.notify_all();
            return;
        }
    }

    // Memory pressure check: skip non-critical passes when RSS exceeds limit.
    // Critical passes (cost < 2.0) always run; others are skipped under pressure.
    if (is_memory_pressure() && entry->pass->estimated_cost() >= 2.0f) {
        LOG_WARN("pass '{}': skipped due to memory pressure (RSS {:.0f}MB > {:.0f}MB limit)",
                 entry->pass->name(), ::tenet::log::rss_mb(), rss_limit_mb_);
        {
            std::lock_guard<std::mutex> lk(entry->mtx);
            entry->result = PassResult::skipped();
            entry->state.store(PassState::Failed, std::memory_order_release);
        }
        entry->cv.notify_all();
        return;
    }

    // Execute the pass itself.
    LOG_DEBUG("pass '{}': starting", entry->pass->name());
    auto t0  = TENET_TIMER_START();
    double m0 = ::tenet::log::rss_mb();

    // Reset progress for this run.
    entry->progress_pct.store(0.0f, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(entry->progress_mtx);
        entry->progress_msg.clear();
    }
    entry->cancelled.store(false, std::memory_order_relaxed);

    PassContext ctx(*this, range_);
    ctx.pass_name_       = entry->pass->name();
    ctx.progress_pct_    = &entry->progress_pct;
    ctx.cancelled_flag_  = &entry->cancelled;
    PassResult result = entry->pass->run(ctx);

    double ms   = TENET_TIMER_MS(t0);
    double dmem = ::tenet::log::rss_mb() - m0;

    if (result.ok()) {
        LOG_INFO("pass '{}': OK  {:.1f}ms  mem {:+.1f}MB",
                 entry->pass->name(), ms, dmem);
    } else {
        LOG_WARN("pass '{}': FAILED  {:.1f}ms  — {}",
                 entry->pass->name(), ms, result.error_message);
    }

    {
        std::lock_guard<std::mutex> lk(entry->mtx);
        entry->result = std::move(result);
        entry->state.store(
            entry->result.ok() ? PassState::Completed : PassState::Failed,
            std::memory_order_release);
    }
    entry->cv.notify_all();
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
    build_dependency_graph();

    // Ready queue: indices of passes whose deps are all satisfied.
    std::mutex q_mtx;
    std::condition_variable q_cv;
    std::vector<size_t> ready;
    ready.reserve(entries_.size());

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
                    return !ready.empty() || completed.load(std::memory_order_acquire) == total;
                });
                if (ready.empty() &&
                    completed.load(std::memory_order_acquire) == total) {
                    return;  // everything done
                }
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

    if (failed_dep.load(std::memory_order_relaxed)) {
        LOG_WARN("PassManager::run_all: one or more passes failed (see above)");
    }
}

void PassManager::run_all(size_t num_threads) {
    LOG_INFO("PassManager::run_all: {} passes, {} threads, RSS limit={}MB",
             entries_.size(), num_threads,
             rss_limit_mb_ > 0 ? fmt::format("{:.0f}", rss_limit_mb_) : "none");

    if (num_threads <= 1 || entries_.size() <= 1) {
        // Sequential fallback: just require each pass in registration order.
        for (auto& entry : entries_) {
            require(entry->pass->name());
        }
        LOG_INFO("PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
        return;
    }

    run_all_parallel(num_threads);

    LOG_INFO("PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
}

// ─── Invalidation ─────────────────────────────────────────────────────────

void PassManager::invalidate(std::string_view pass_name) {
    auto* entry = find_entry(pass_name);
    if (!entry) return;

    std::lock_guard<std::mutex> lk(entry->mtx);
    entry->state.store(PassState::NotRun, std::memory_order_release);
    entry->result = PassResult::skipped();
}

void PassManager::invalidate_all() {
    for (auto& entry : entries_) {
        std::lock_guard<std::mutex> lk(entry->mtx);
        entry->state.store(PassState::NotRun, std::memory_order_release);
        entry->result = PassResult::skipped();
        entry->progress_pct.store(0.0f, std::memory_order_relaxed);
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

// ─── Progress query ──────────────────────────────────────────────────────

float PassManager::progress_of(std::string_view pass_name) const {
    const auto* e = find_entry(pass_name);
    if (!e) return 0.0f;
    return e->progress_pct.load(std::memory_order_relaxed);
}

std::string PassManager::progress_msg_of(std::string_view pass_name) const {
    const auto* e = find_entry(pass_name);
    if (!e) return {};
    std::lock_guard<std::mutex> lk(e->progress_mtx);
    return e->progress_msg;
}

bool PassManager::is_pass_cancelled(std::string_view pass_name) const {
    const auto* e = find_entry(pass_name);
    if (!e) return false;
    return e->cancelled.load(std::memory_order_acquire);
}

void PassManager::set_progress_msg(std::string_view pass_name, std::string_view msg) {
    auto* e = find_entry(pass_name);
    if (!e) return;
    std::lock_guard<std::mutex> lk(e->progress_mtx);
    e->progress_msg = std::string(msg);
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

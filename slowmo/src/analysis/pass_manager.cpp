#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "common/logger.h"

#include <algorithm>
#include <cassert>
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

void PassContext::progress(float /*pct*/) {}
void PassContext::progress(float /*pct*/, std::string_view /*msg*/) {}

TraceScanEngine* PassContext::scan_engine() { return manager_.scan_engine(); }

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

    PassContext ctx(*this, range_);
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

// ─── Parallel run_all using topological levels ────────────────────────────

void PassManager::run_all(size_t num_threads) {
    LOG_INFO("PassManager::run_all: {} passes, {} threads, RSS limit={}MB",
             entries_.size(), num_threads,
             rss_limit_mb_ > 0 ? fmt::format("{:.0f}", rss_limit_mb_) : "none");

    if (num_threads <= 1) {
        // Sequential fallback: just require each pass.
        for (auto& entry : entries_) {
            require(entry->pass->name());
        }
        LOG_INFO("PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
        return;
    }

    // Compute topological levels for true parallelism.
    auto levels = topological_levels();

    for (auto& level : levels) {
        if (level.size() == 1) {
            // Only one pass at this level — no need for threads.
            require(level[0]);
        } else {
            // Launch threads for each pass in this level.
            std::vector<std::thread> threads;
            threads.reserve(level.size());

            // Limit concurrency to num_threads.
            size_t batch_start = 0;
            while (batch_start < level.size()) {
                size_t batch_end = std::min(batch_start + num_threads, level.size());
                threads.clear();

                for (size_t i = batch_start; i < batch_end; ++i) {
                    threads.emplace_back([this, name = level[i]]() {
                        this->require(name);
                    });
                }

                for (auto& t : threads) {
                    t.join();
                }

                batch_start = batch_end;
            }
        }
    }

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
    }
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

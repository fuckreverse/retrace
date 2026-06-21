#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/thread_pass.h"
#include <cstdint>
#include <vector>
#include <roaring64map.hh>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct ThreadFilterConfig {
    /// Thread IDs to include.  Empty = include all threads (no filter).
    std::vector<uint64_t> include_thread_ids;

    /// If true, generate a per-thread instruction bitmap index.
    /// Allows O(1) "is inst_id on thread T?" and O(popcount) "insts on thread T".
    bool build_bitmaps = true;
};

// ─── Result ────────────────────────────────────────────────────────────────

struct ThreadFilterResult {
    /// Per-thread instruction-id bitmaps.
    /// thread_id → bitmap of all inst_ids that ran on that thread.
    ankerl::unordered_dense::map<uint64_t, roaring::Roaring64Map> thread_inst_bitmaps;

    /// Filtered bitmap (union of included threads).
    roaring::Roaring64Map included_inst_ids;

    /// Total number of threads observed.
    size_t thread_count = 0;

    /// Whether any thread filter was applied.
    bool is_filtered = false;

    /// Check if an inst_id belongs to any of the included threads.
    bool contains(uint64_t inst_id) const {
        if (!is_filtered) return true;
        return included_inst_ids.contains(inst_id);
    }

    /// Get all inst_ids on a specific thread (sorted ascending).
    std::vector<uint64_t> inst_ids_on(uint64_t thread_id) const {
        auto it = thread_inst_bitmaps.find(thread_id);
        if (it == thread_inst_bitmaps.end()) return {};
        std::vector<uint64_t> result;
        result.reserve(it->second.cardinality());
        for (auto v : it->second) result.push_back(v);
        return result;
    }

    /// Thread instruction count.
    uint64_t inst_count_on(uint64_t thread_id) const {
        auto it = thread_inst_bitmaps.find(thread_id);
        if (it == thread_inst_bitmaps.end()) return 0;
        return it->second.cardinality();
    }
};

// ─── ThreadFilterPass ──────────────────────────────────────────────────────

/// Builds per-thread instruction bitmaps from ThreadPass result.
/// Enables GUI thread-selector filtering:
///   - Select "Thread 1234" → only instructions from that thread are shown
///   - Bitmap operations allow O(1) check per instruction
///
/// Dependencies: thread
///
/// Result type: ThreadFilterResult
class ThreadFilterPass final : public AnalysisPass {
public:
    explicit ThreadFilterPass(ThreadFilterConfig cfg = {})
        : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "thread_filter"; }
    std::string_view description() const override {
        return "Per-thread instruction bitmap index for multi-thread trace filtering";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"thread"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 4.0f; }

private:
    ThreadFilterConfig cfg_;
};

}  // namespace tenet

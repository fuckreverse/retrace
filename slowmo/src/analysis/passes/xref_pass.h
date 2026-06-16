#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <vector>
#include <algorithm>
#include <roaring64map.hh>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Xref pass result ─────────────────────────────────────────────────────

/// PC → compressed bitmap of inst_ids that executed at that PC.
struct XrefResult {
    /// Forward index: PC → compressed bitmap of inst_ids that executed this PC.
    ankerl::unordered_dense::map<uint64_t, roaring::Roaring64Map> pc_to_inst_ids;

    /// Fast execution count per PC (avoids calling cardinality() on bitmap).
    ankerl::unordered_dense::map<uint64_t, uint64_t> pc_exec_count;

    /// Total unique PCs in the trace.
    size_t unique_pc_count = 0;

    /// Total inst_ids indexed.
    uint64_t total_indexed = 0;

    /// How many times was this PC executed?
    uint64_t execution_count(uint64_t pc) const {
        auto it = pc_exec_count.find(pc);
        if (it == pc_exec_count.end()) return 0;
        return it->second;
    }

    /// Check if a PC was ever executed.
    bool has_pc(uint64_t pc) const {
        return pc_exec_count.find(pc) != pc_exec_count.end();
    }

    /// Get the N hottest PCs (most executed).
    std::vector<std::pair<uint64_t, uint64_t>> hottest(size_t n) const {
        std::vector<std::pair<uint64_t, uint64_t>> entries;
        entries.reserve(pc_exec_count.size());
        for (const auto& [pc, count] : pc_exec_count) {
            entries.emplace_back(pc, count);
        }
        std::partial_sort(entries.begin(),
                          entries.begin() + std::min(n, entries.size()),
                          entries.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
        if (entries.size() > n) entries.resize(n);
        return entries;
    }

    /// Iterate all inst_ids at a given PC (for backward compat).
    /// Returns empty vector if PC not found. Use sparingly for large sets.
    std::vector<uint64_t> inst_ids_at(uint64_t pc) const {
        auto it = pc_to_inst_ids.find(pc);
        if (it == pc_to_inst_ids.end()) return {};
        std::vector<uint64_t> result;
        result.reserve(it->second.cardinality());
        for (auto val : it->second) {
            result.push_back(val);
        }
        return result;
    }
};

// ─── Xref collector (single-pass scan) ────────────────────────────────────

/// Collector that builds the xref index during a single-pass scan.
class XrefCollector final : public TraceCollector {
public:
    std::string_view name() const override { return "xref_collector"; }

    bool begin(uint64_t start, uint64_t end) override {
        (void)start; (void)end;
        return true;
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        result.pc_to_inst_ids[inst.pc].add(inst_id);
        result.pc_exec_count[inst.pc]++;
        result.total_indexed++;
    }

    void end() override {
        result.unique_pc_count = result.pc_exec_count.size();
    }

    XrefResult result;
};

// ─── Xref pass ────────────────────────────────────────────────────────────

/// Builds a PC → inst_id cross-reference index using Roaring64Map bitmaps.
/// Result type: XrefResult
class XrefPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "xref"; }
    std::string_view description() const override {
        return "Build PC cross-reference index (PC -> inst_id bitmap)";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 6.0f; }
};

}  // namespace tenet

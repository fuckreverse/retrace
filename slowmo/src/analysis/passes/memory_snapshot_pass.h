#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Configuration ────────────────────────────────────────────────────────

struct MemorySnapshotConfig {
    /// Explicit inst_ids at which to capture snapshots.
    std::vector<uint64_t> snapshot_inst_ids;

    /// Automatically snapshot x0-x7 pointed memory at BL/BLR instructions.
    bool snapshot_at_function_calls = true;

    /// How many bytes to capture per pointer.
    uint64_t snapshot_size = 64;

    /// Maximum total number of snapshots to capture.
    uint64_t max_snapshots = 1000;
};

// ─── Result types ─────────────────────────────────────────────────────────

/// A single captured memory region at a point in time.
struct MemoryRegion {
    uint64_t addr;                 // Start address of the snapshot
    std::vector<uint8_t> data;     // Actual bytes
    std::vector<bool> known;       // Which bytes have known values
    uint64_t at_inst_id;           // When this snapshot was taken
    std::string label;             // e.g. "x0 at BL sub_1234" or "user snapshot"
};

/// Aggregated result of the memory snapshot pass.
struct MemorySnapshotResult {
    /// All captured snapshots in order.
    std::vector<MemoryRegion> snapshots;

    /// inst_id → indices into `snapshots` vector.
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> by_inst_id;

    /// Get all snapshots taken at a specific inst_id.
    std::vector<const MemoryRegion*> snapshots_at(uint64_t inst_id) const {
        std::vector<const MemoryRegion*> result;
        auto it = by_inst_id.find(inst_id);
        if (it == by_inst_id.end()) return result;
        result.reserve(it->second.size());
        for (size_t idx : it->second) {
            result.push_back(&snapshots[idx]);
        }
        return result;
    }

    /// Total number of snapshots captured.
    size_t total() const { return snapshots.size(); }

    /// Format a memory region as a hex dump (xxd-style).
    static std::string hex_dump(const MemoryRegion& region);
};

// ─── Pass ─────────────────────────────────────────────────────────────────

/// Captures memory snapshots at configurable points in the trace.
/// Solves the "input data invisible" problem — see what input buffers
/// looked like when a function was called.
///
/// Result type: MemorySnapshotResult
class MemorySnapshotPass final : public AnalysisPass {
public:
    explicit MemorySnapshotPass(MemorySnapshotConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "memory_snapshot"; }
    std::string_view description() const override {
        return "Capture memory snapshots at function calls and explicit points";
    }

    std::vector<std::string_view> dependencies() const override {
        // Depend on "function" pass to get pre-computed call events (fast path).
        // If function pass is unavailable, falls back to linear scan.
        return {"function"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }

private:
    /// Capture a snapshot of `size` bytes at `addr` at time `at_inst_id`.
    /// Handles the 16-byte chunk limitation of MemoryModel::read().
    MemoryRegion capture_region(MemoryModel& memory, uint64_t addr,
                                uint64_t size, uint64_t at_inst_id,
                                std::string label);

    MemorySnapshotConfig config_;
};

}  // namespace tenet

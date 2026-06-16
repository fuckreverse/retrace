#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

namespace tenet {

/// Reconstructs the full register state at any instruction using
/// Anchor + Diff + LRU cache strategy.
///
/// Algorithm:
///   1. Find the nearest anchor before target inst_id (binary search)
///   2. Load the anchor's full GPR snapshot
///   3. Sequentially apply register diffs from anchor to target
///   4. Cache the result in LRU for subsequent nearby accesses
class RegisterFile {
public:
    RegisterFile(const TraceReader& reader, const TraceIndex& index);

    /// Get the register state BEFORE instruction `inst_id` executes.
    /// This is the primary query interface.
    const RegState& state_before(uint64_t inst_id);

    /// Get the register state AFTER instruction `inst_id` executes.
    /// Equivalent to state_before(inst_id) + applying inst_id's diffs.
    RegState state_after(uint64_t inst_id);

    /// Configure LRU cache capacity (default: 4096 entries ≈ 1.1 MB).
    void set_cache_capacity(size_t num_entries) { cache_.set_capacity(num_entries); }

    struct CacheStats {
        uint64_t hits = 0;
        uint64_t misses = 0;
    };
    CacheStats cache_stats() const { return cache_stats_; }

private:
    /// Rebuild register state at target_id by replaying from nearest anchor.
    RegState rebuild(uint64_t target_id);

    const TraceReader& reader_;
    const TraceIndex& index_;
    LRUCache<uint64_t, RegState> cache_{4096};
    CacheStats cache_stats_;
};

}  // namespace tenet

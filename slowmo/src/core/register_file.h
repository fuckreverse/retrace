#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <functional>

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

    /// Pre-populate the LRU cache for the range [start_id, end_id).
    ///
    /// Analysis passes that are about to access a dense sequence of instructions
    /// should call this once before the inner loop. The implementation samples
    /// the range every `stride` instructions (default: matches anchor_interval),
    /// rebuilding register state at each sample point and inserting it into the
    /// cache. Subsequent state_before() calls for any instruction within the
    /// range then find a nearby cached baseline and only need to replay diffs
    /// from that point (at most `stride` records) instead of from the nearest
    /// anchor (potentially thousands of records away).
    ///
    /// The optional `progress` callback is invoked with (samples_done, total)
    /// for long traces (e.g. during a full-trace sweep).
    ///
    /// warm_range() is safe to call multiple times and is a no-op for ranges
    /// already fully cached; it is also safe to call concurrently from different
    /// threads (each thread owns its own RegisterFile instance in tenet).
    ///
    /// @param start_id  First instruction id in the range to warm (inclusive).
    /// @param end_id    Last instruction id in the range to warm (exclusive).
    ///                  Pass UINT64_MAX to warm through the end of the trace.
    /// @param stride    Spacing between sampled checkpoints (0 = auto: use
    ///                  the anchor interval from the trace header, or 256).
    /// @param progress  Optional progress callback: (done, total) sample counts.
    void warm_range(uint64_t start_id, uint64_t end_id,
                    uint64_t stride = 0,
                    std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Pre-populate the cache at exactly one instruction id.
    /// Equivalent to state_before(inst_id) but discards the return value so
    /// the caller does not need to take a const-ref that may be invalidated by
    /// a later cache eviction.
    void warm_at(uint64_t inst_id);

    struct CacheStats {
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t warm_samples = 0;  ///< checkpoints inserted by warm_range()
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

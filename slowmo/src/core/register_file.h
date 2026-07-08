#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <functional>
#include <mutex>

namespace tenet {

/// Reconstructs the full register state at any instruction using
/// Anchor + Diff + LRU cache strategy.
///
/// Algorithm:
///   1. Find the nearest anchor before target inst_id (binary search)
///   2. Load the anchor's full GPR snapshot
///   3. Sequentially apply register diffs from anchor to target
///   4. Cache the result in LRU for subsequent nearby accesses
///
/// Thread-safety: a single RegisterFile instance IS shared across threads in
/// tenet (GUI render thread, MCP/RPC server threads, and background
/// PassManager worker threads all hold a reference to the same instance —
/// see GuiApp::regfile_ / PassManager::set_regfile()). All public accessors
/// therefore take an internal mutex around the LRU cache, and state_before()/
/// state_after() return RegState by value (a flat ~800-byte POD copy) rather
/// than a reference into the cache, since a reference could otherwise be
/// invalidated by a concurrent put()/eviction on another thread.
class RegisterFile {
public:
    RegisterFile(const TraceReader& reader, const TraceIndex& index);

    /// Get the register state BEFORE instruction `inst_id` executes.
    /// This is the primary query interface. Returned by value — safe to use
    /// after concurrent calls from other threads evict the cache entry.
    RegState state_before(uint64_t inst_id);

    /// Get the register state AFTER instruction `inst_id` executes.
    /// Equivalent to state_before(inst_id) + applying inst_id's diffs.
    RegState state_after(uint64_t inst_id);

    /// Configure LRU cache capacity (default: 4096 entries ≈ 1.1 MB).
    void set_cache_capacity(size_t num_entries) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_.set_capacity(num_entries);
    }

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
    /// already fully cached; it is also safe to call concurrently with other
    /// state_before()/state_after()/warm_*() calls from other threads on the
    /// same instance (internally serialized by mutex_).
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
    CacheStats cache_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_stats_;
    }

private:
    /// Rebuild register state at target_id by replaying from nearest anchor.
    /// Does not touch cache_ or cache_stats_ — safe to call without holding
    /// mutex_ (only reads from reader_/index_, which are themselves const&
    /// and safe for concurrent read access).
    RegState rebuild(uint64_t target_id);

    const TraceReader& reader_;
    const TraceIndex& index_;

    /// Guards cache_ and cache_stats_ against concurrent access from the GUI
    /// render thread, MCP/RPC server threads, and background analysis
    /// worker threads (see class-level thread-safety note above).
    mutable std::mutex mutex_;
    LRUCache<uint64_t, RegState> cache_{4096};
    CacheStats cache_stats_;
};

}  // namespace tenet

# Checkpoint-Only Register State Reconstruction

**Date:** 2026-07-10
**Status:** Design approved, ready for implementation plan

## Problem

`RegisterFile` has two query strategies for `state_before()` / `state_after()`:

1. **Dense checkpoint array** (O(K) fast path) — `build_checkpoints()` does one O(N) forward sweep, storing a full `RegState` snapshot every K instructions. Subsequent queries are O(K) — load checkpoint, replay at most K-1 diffs.
2. **Anchor + Diff + LRU cache** (slow path) — find nearest anchor (binary search), load snapshot, replay diffs. LRU cache (4096 entries, ~1.1 MB) amortizes repeated nearby queries.

**The problem: the fast path is never activated.** `build_checkpoints()` is never called in production code. All `state_before()` queries — from GUI rendering, TUI, MCP, RPC, WebSocket, and analysis passes — go through the slow path: LRU cache lookup → miss → `rebuild()` (a ~130-line forward scan duplicated from `RegisterFileCursor::advance_to()`).

Additionally, `warm_range()` / `warm_at()` exist as cache pre-population APIs, called by `trace_fold_pass`, `loop_semantics_pass`, and `memory_snapshot_pass`. These are band-aids for the slow path.

## Goal

Eliminate the slow path entirely. All `state_before()` / `state_after()` queries go through the dense checkpoint array. Remove `rebuild()`, `warm_range()`, `warm_at()`, LRU cache, and the mutex that protects them.

**Trade-off accepted:** ~80 MB memory for the checkpoint array (space) in exchange for O(K)≈O(256) uniform query latency (time) and ~200 lines of code deletion.

## Architecture

### Trigger Point

`PassManager::init_infra()` eagerly calls `CheckpointManager::ensure_checkpoints()` immediately after creating the `CheckpointManager` instance. This runs `build_checkpoints()` (one O(N) forward sweep) before any pass executes.

### Data Flow

```
init_infra() → ensure_checkpoints() → build_checkpoints()  [O(N), ~80MB, ~1-2s for 10M insts]
                                          ↓
                              checkpoints_[] (immutable array, lock-free read)
                                          ↓
state_before(inst_id) → state_before_ckpt() → O(K) replay  [lock-free, no mutex]
```

### Removal List (from RegisterFile)

| Removed | Reason |
|---------|--------|
| `LRUCache cache_` member | Subsumed by checkpoint array |
| `mutex_` | No shared mutable state after build (checkpoint array is immutable) |
| `rebuild()` (~130 lines) | Duplicates `RegisterFileCursor::advance_to()` forward scan |
| `warm_range()` | Checkpoint array is immutable — no pre-population needed |
| `warm_at()` | Same as above |
| `set_cache_capacity()` | LRU removed |
| `CacheStats::hits`, `misses`, `warm_samples` | LRU removed |

### Simplification List (CheckpointManager)

| Removed | Reason |
|---------|--------|
| `declare_warm_range()` | No pre-population in checkpoint model |
| `execute_warms()` | Same |
| `declared_ranges_` member | Same |

| Kept/Added | Purpose |
|-------------|---------|
| `ensure_checkpoints(progress)` | Idempotent build trigger |
| `has_checkpoints()` | Query state |
| `create_cursor()` | Unified cursor factory (was throw TODO, now implemented) |

## RegisterFile Changes

### `state_before()` — simplified to 3 lines

```cpp
RegState RegisterFile::state_before(uint64_t inst_id) {
    TENET_ZONE;
    if (!checkpoints_built_.load(std::memory_order_acquire)) {
        // Build in progress or not yet started — return empty state.
        // Only happens if a GUI thread queries before init_infra() completes.
        return RegState{};
    }
    cache_stats_.ckpt_queries.fetch_add(1, std::memory_order_relaxed);
    return state_before_ckpt(inst_id);
}
```

No mutex, no LRU lookup, no fallback branch.

### `state_before_ckpt()` — out-of-range safety

```cpp
RegState RegisterFile::state_before_ckpt(uint64_t inst_id) {
    if (checkpoints_.empty()) return RegState{};

    uint64_t idx = inst_id / ckpt_stride_;
    if (idx >= checkpoints_.size()) {
        // Out of range — return last checkpoint state (safe, not crash)
        cache_stats_.ckpt_fallbacks.fetch_add(1, std::memory_order_relaxed);
        return checkpoints_.back().state;
    }

    const auto& ckpt = checkpoints_[idx];
    RegState state = ckpt.state;  // copy

    if (inst_id == idx * ckpt_stride_) {
        return state;  // exact checkpoint hit
    }

    // Replay diffs from base_id to inst_id using a seeded cursor
    RegisterFileCursor cursor(reader_, index_);
    cursor.seed(state, idx * ckpt_stride_, ckpt.file_offset);
    return cursor.advance_to(inst_id);
}
```

No longer falls back to `rebuild()` for out-of-range — returns last checkpoint state.

### `state_after()` — unchanged

Calls `state_before()` then applies the instruction's diffs. Logic correct, automatically benefits from checkpoint fast path.

### `build_checkpoints()` — minor adjustments

- Remove `cache_.clear()` at the end (LRU no longer exists)
- `cache_stats_` fields become `std::atomic<uint64_t>` (no mutex protection)

### CacheStats — simplified

```cpp
struct CacheStats {
    std::atomic<uint64_t> ckpt_queries{0};
    std::atomic<uint64_t> ckpt_fallbacks{0};
};
```

### New accessors on RegisterFile

```cpp
const TraceReader& reader() const { return reader_; }
const TraceIndex&  index() const  { return index_; }
```

Needed by `CheckpointManager::create_cursor()`.

## CheckpointManager Changes

### Simplified API

```cpp
class CheckpointManager {
public:
    explicit CheckpointManager(RegisterFile& regfile);

    /// Build checkpoint array (idempotent). Call once at startup.
    void ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Create a RegisterFileCursor (unified factory).
    RegisterFileCursor create_cursor() const;

    bool has_checkpoints() const;

private:
    RegisterFile& regfile_;
    bool checkpoints_built_ = false;
};
```

### `create_cursor()` implementation

```cpp
RegisterFileCursor CheckpointManager::create_cursor() const {
    return RegisterFileCursor(regfile_.reader(), regfile_.index());
}
```

### `ensure_checkpoints()` — unchanged

Already idempotent with `checkpoints_built_` guard. Calls `regfile_.build_checkpoints(0, progress)`.

## init_infra() Integration

In `PassManager::init_infra()`, after creating `checkpoint_manager_`:

```cpp
if (!checkpoint_manager_) {
    checkpoint_manager_ = std::make_unique<CheckpointManager>(*regfile_);
}
checkpoint_manager_->ensure_checkpoints();  // eager build
```

No progress callback for now. Logging ("Building checkpoints..." + elapsed time) suffices. Can add optional progress to `init_infra()` later if needed.

## Pass Call-Site Changes

### trace_fold_pass (`trace_fold_pass.cpp:365-390`)

Delete the entire warm_range coalesce block (~25 lines):

```cpp
// DELETED:
constexpr uint64_t COALESCE_GAP = ANCHOR_INTERVAL_EST * 2;
std::vector<std::pair<uint64_t, uint64_t>> spans;
// ... entire sort + coalesce + flush_warm loop ...
```

Replace with comment:
```cpp
// Checkpoints are built eagerly at init_infra() — no per-range warm needed.
```

Step 4 (collect register/FPR diffs) unchanged — `regfile.state_before()` calls automatically use checkpoint fast path.

### loop_semantics_pass (`loop_semantics_pass.cpp:521-546`)

Delete the entire warm_ids coalesce block (~25 lines):

```cpp
// DELETED:
std::sort(warm_ids.begin(), warm_ids.end());
// ... entire coalesce + flush_warm loop ...
```

Replace with comment. Subsequent `state_before()` queries use checkpoint.

### memory_snapshot_pass (`memory_snapshot_pass.cpp:324`)

Delete `regfile.warm_at(ev.call_inst_id)` call. Subsequent `state_before()` uses checkpoint.

### vm_abstract_pass

Change direct `RegisterFileCursor(reader, index)` construction to `ctx.checkpoint_manager().create_cursor()`. Functionally equivalent, unified entry point.

### Other passes (no changes needed)

`objc_pass`, `pattern_pass`, `taint_source_annotation_pass`, `memory_string_pass`, `breakpoint_engine`, GUI/TUI/MCP/RPC/WS — all call `state_before()` / `state_after()` but not `warm_range` / `warm_at`. They automatically benefit from the checkpoint fast path with no code changes.

## Edge Cases

### Empty trace (inst_count == 0)

`build_checkpoints()` already guards: `if (total == 0) return;`. `checkpoints_` is empty. `state_before_ckpt()` guards with `if (checkpoints_.empty()) return RegState{};`.

### Out-of-range inst_id

`idx >= checkpoints_.size()` → return `checkpoints_.back().state`. Safe, no crash.

### Single-instruction trace (inst_count == 1)

`stride = max(64, ...) = 64`. `n_checkpoints = 1`. One checkpoint. `state_before(0)` hits. Normal.

### Duplicate `ensure_checkpoints()` calls

`checkpoints_built_` guard in CheckpointManager + `has_checkpoints()` check. Idempotent.

### Concurrent: build_checkpoints while GUI thread queries state_before

`init_infra()` runs single-threaded before any pass. But GUI render thread might query during build. `state_before()` checks `checkpoints_built_.load(acquire)` — if false (build in progress), returns `RegState{}`. After build completes (atomic release store), all subsequent queries see the checkpoint array.

## Testing

### Existing tests (must stay green)

`test_register_file.cpp` covers `state_before()` / `state_after()` correctness at various inst_ids. These tests should pass unchanged — checkpoint results match rebuild results.

### New test cases

1. **Empty trace** — `build_checkpoints()` on 0-instruction trace doesn't crash; `state_before(0)` returns empty `RegState`.
2. **Out-of-range** — `state_before(total + 100)` returns last checkpoint state, no crash.
3. **Idempotent build** — `ensure_checkpoints()` called twice doesn't rebuild (check `ckpt_queries` counter unchanged between calls).
4. **`create_cursor()`** — returns a `RegisterFileCursor` that can `advance_to()` and return correct `RegState`.

### Verification

- `ninja -j$(nproc)` clean build
- `ctest --output-on-failure` all tests pass
- No performance regression in pass execution (checkpoint O(K) vs LRU+rebuild variable)

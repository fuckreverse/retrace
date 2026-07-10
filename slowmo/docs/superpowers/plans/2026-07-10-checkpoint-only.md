# Checkpoint-Only Register State Reconstruction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate RegisterFile's LRU+rebuild slow path; all `state_before()` / `state_after()` queries go through the dense checkpoint array via eager `build_checkpoints()` at `init_infra()`.

**Architecture:** `PassManager::init_infra()` eagerly calls `CheckpointManager::ensure_checkpoints()`, which runs `RegisterFile::build_checkpoints()` (one O(N) forward sweep, ~80 MB). After build, the checkpoint array is immutable — all queries are lock-free O(K)≈O(256). LRU cache, `rebuild()`, `warm_range()`, `warm_at()`, and mutex are removed.

**Tech Stack:** C++17, CMake/Ninja, Catch2 testing, no new third-party dependencies

## Global Constraints

- Build target: `tenet_lib` (static library, `tools/tenet/CMakeLists.txt`)
- **Never** create new `build-xxx` directories or delete `_deps/`
- Incremental build must stay fast (single-file change in `src/core/` or `src/infra/` < 5s)
- Existing tests (`ctest --output-on-failure`) must stay green after every task
- Spec: `tools/tenet/docs/superpowers/specs/2026-07-10-checkpoint-only-design.md`

---

### Task 1: Add RegisterFile accessors + simplify CacheStats

**Files:**
- Modify: `tools/tenet/src/core/register_file.h`

**Interfaces:**
- Produces: `RegisterFile::reader()` and `RegisterFile::index()` const accessors (needed by `CheckpointManager::create_cursor()` in Task 4)
- Produces: `CacheStats` with atomic `ckpt_queries` / `ckpt_fallbacks` only (removes `hits` / `misses` / `warm_samples`)
- Produces: `cache_stats()` returns by value (no mutex needed — fields are atomic)

**Context:** This is a prep step — it changes the type of `CacheStats` but doesn't yet remove the LRU cache or mutex. The existing `state_before()` still works because it reads `cache_stats_.ckpt_queries` (which becomes atomic — update the increment to `fetch_add`). The TUI/Python consumers of `hits`/`misses` are handled in Task 6.

- [ ] **Step 1: Add reader() and index() accessors**

In `register_file.h`, in the `RegisterFile` class, after the `has_checkpoints()` method (line ~198), add:

```cpp
    const TraceReader& reader() const { return reader_; }
    const TraceIndex&  index() const  { return index_; }
```

- [ ] **Step 2: Simplify CacheStats to atomic fields**

Replace the `CacheStats` struct (lines 200-206) with:

```cpp
    struct CacheStats {
        std::atomic<uint64_t> ckpt_queries{0};
        std::atomic<uint64_t> ckpt_fallbacks{0};
    };
```

- [ ] **Step 3: Make cache_stats() lock-free**

Replace the `cache_stats()` method (lines 207-210) with:

```cpp
    CacheStats cache_stats() const {
        CacheStats copy;
        copy.ckpt_queries.store(cache_stats_.ckpt_queries.load(std::memory_order_relaxed),
                                 std::memory_order_relaxed);
        copy.ckpt_fallbacks.store(cache_stats_.ckpt_fallbacks.load(std::memory_order_relaxed),
                                   std::memory_order_relaxed);
        return copy;
    }
```

- [ ] **Step 4: Update state_before() to use atomic fetch_add**

In `register_file.cpp`, in `state_before()`, replace the `cache_stats_.ckpt_queries++` (inside mutex lock) with:

```cpp
    cache_stats_.ckpt_queries.fetch_add(1, std::memory_order_relaxed);
```

Remove the `{ std::lock_guard<std::mutex> lock(mutex_); ... }` block around it.

In `state_before_ckpt()`, replace `cache_stats_.ckpt_fallbacks++` (inside mutex lock) with:

```cpp
    cache_stats_.ckpt_fallbacks.fetch_add(1, std::memory_order_relaxed);
```

Remove the mutex lock around it.

- [ ] **Step 5: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
```

Expected: clean build. The TUI/Python consumers of `hits`/`misses` will have compile errors — that's expected, Task 6 fixes them. For now, temporarily comment out those lines if needed to get a clean build, but DO NOT commit those comments — Task 6 will fix them properly.

Actually, to keep the build green: the TUI and Python files reference `stats.hits` / `stats.misses`. Since those fields no longer exist, the build will fail. To avoid a broken intermediate state, defer the CacheStats field removal to Task 6 (which updates consumers). 

**Revised approach for Step 2-3:** Keep `hits` / `misses` / `warm_samples` as `std::atomic<uint64_t>` (instead of `uint64_t`) for now — this makes them thread-safe without changing the field names. Task 6 will remove them after updating consumers. So the CacheStats becomes:

```cpp
    struct CacheStats {
        std::atomic<uint64_t> hits{0};
        std::atomic<uint64_t> misses{0};
        std::atomic<uint64_t> warm_samples{0};
        std::atomic<uint64_t> ckpt_queries{0};
        std::atomic<uint64_t> ckpt_fallbacks{0};
    };
```

And update all `cache_stats_.hits++` etc. to `cache_stats_.hits.fetch_add(1, std::memory_order_relaxed)` throughout `register_file.cpp`. The `cache_stats()` method returns a copy with all 5 atomic fields loaded.

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/core/register_file.h tools/tenet/src/core/register_file.cpp
git commit -m "refactor(core): RegisterFile accessors + atomic CacheStats"
```

---

### Task 2: Simplify state_before() to checkpoint-only

**Files:**
- Modify: `tools/tenet/src/core/register_file.h` (remove `rebuild()` declaration, `warm_range()` / `warm_at()` / `set_cache_capacity()` declarations, `cache_` / `mutex_` members)
- Modify: `tools/tenet/src/core/register_file.cpp` (rewrite `state_before()`, `state_before_ckpt()`, remove `rebuild()` / `warm_range()` / `warm_at()`, update `build_checkpoints()`)

**Interfaces:**
- Produces: `state_before()` — lock-free, checkpoint-only, returns `RegState{}` if checkpoints not built yet
- Produces: `state_before_ckpt()` — empty-trace guard + out-of-range returns last checkpoint
- Removes: `rebuild()`, `warm_range()`, `warm_at()`, `set_cache_capacity()`, `cache_`, `mutex_`

**Context:** This is the core change. After this task, the LRU slow path is gone. `state_after()` is unchanged (it calls `state_before()` + applies diffs). The `warm_range()` / `warm_at()` callers (trace_fold, loop_semantics, memory_snapshot) will have compile errors — that's expected, Tasks 3 and 5 fix them. To keep the build green, do Task 3 and Task 5 immediately after this task (or in the same commit).

**Important:** Do NOT remove `hits` / `misses` / `warm_samples` from CacheStats yet — Task 6 handles consumer removal. But since `warm_range()` / `warm_at()` are removed, `warm_samples` will just stay at 0.

- [ ] **Step 1: Rewrite state_before() in register_file.cpp**

Replace the entire `state_before()` method with:

```cpp
RegState RegisterFile::state_before(uint64_t inst_id) {
    TENET_ZONE;

    // Checkpoint array is immutable after build — lock-free read.
    // If not built yet (e.g. GUI thread queries before init_infra() completes),
    // return empty state.
    if (!checkpoints_built_.load(std::memory_order_acquire)) {
        return RegState{};
    }
    cache_stats_.ckpt_queries.fetch_add(1, std::memory_order_relaxed);
    return state_before_ckpt(inst_id);
}
```

- [ ] **Step 2: Rewrite state_before_ckpt() in register_file.cpp**

Replace the entire `state_before_ckpt()` method with:

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

    uint64_t base_id = idx * ckpt_stride_;
    if (inst_id == base_id) {
        return state;  // exact checkpoint hit
    }

    // Replay diffs from base_id to inst_id using a seeded cursor
    RegisterFileCursor cursor(reader_, index_);
    cursor.seed(state, base_id, ckpt.file_offset);
    return cursor.advance_to(inst_id);
}
```

- [ ] **Step 3: Remove rebuild(), warm_range(), warm_at() from register_file.cpp**

Delete the entire `rebuild()` method (~130 lines), the entire `warm_at()` method, and the entire `warm_range()` method.

- [ ] **Step 4: Update build_checkpoints() in register_file.cpp**

In `build_checkpoints()`, remove the `cache_.clear()` call at the end (the `std::lock_guard<std::mutex> lock(mutex_); cache_.clear();` lines). The method otherwise stays the same.

- [ ] **Step 5: Remove declarations and members from register_file.h**

In `register_file.h`, remove:
- `void set_cache_capacity(size_t num_entries)` method (lines ~140-143)
- `void warm_range(...)` declaration (lines ~170-172)
- `void warm_at(uint64_t inst_id)` declaration (line ~178)
- `RegState rebuild(uint64_t target_id)` private declaration (line ~217)
- `mutable std::mutex mutex_` member (line ~229)
- `LRUCache<uint64_t, RegState> cache_{4096}` member (line ~230)
- Update the `cache_stats()` method: remove `std::lock_guard<std::mutex> lock(mutex_)` — just load atomics
- Update thread-safety comment (lines ~111-121) to reflect lock-free checkpoint model

- [ ] **Step 6: Build (expect errors in pass files)**

```bash
cd tools/tenet/build
ninja -j$(nproc) 2>&1 | head -30
```

Expected: compile errors in `trace_fold_pass.cpp` (warm_range), `loop_semantics_pass.cpp` (warm_range), `memory_snapshot_pass.cpp` (warm_at). These are fixed in Task 3 and Task 5. Do NOT commit yet.

- [ ] **Step 7: Commit (after Task 3 and Task 5 fix the callers)**

This commit will be combined with Task 3 and Task 5 changes, or done as a squash. For now, stage the register_file changes and proceed to Task 3.

---

### Task 3: Remove warm_range calls from trace_fold_pass and loop_semantics_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/profile/trace_fold_pass.cpp` (delete warm_range coalesce block ~lines 365-390)
- Modify: `tools/tenet/src/analysis/passes/crypto/loop_semantics_pass.cpp` (delete warm_ids coalesce block ~lines 521-546)

**Interfaces:**
- Removes: `regfile.warm_range()` calls
- Preserves: all subsequent `state_before()` queries (now use checkpoint fast path)

- [ ] **Step 1: Remove warm_range block from trace_fold_pass.cpp**

In `trace_fold_pass.cpp`, find the block starting with `constexpr uint64_t COALESCE_GAP = ANCHOR_INTERVAL_EST * 2;` (around line 365) and ending with the `flush_warm(span_start, span_end);` call before Step 4 (around line 390). Delete the entire block including the `spans` vector construction, sort, coalesce loop, and `flush_warm` lambda.

Replace with a single comment:

```cpp
    // Checkpoints are built eagerly at init_infra() — no per-range warm needed.
```

- [ ] **Step 2: Remove warm_range block from loop_semantics_pass.cpp**

In `loop_semantics_pass.cpp`, find the block starting with `std::sort(warm_ids.begin(), warm_ids.end());` (around line 521) and ending with `flush_warm(span_start, span_end);` (around line 545). Delete the entire block including sort, unique, coalesce loop, and `flush_warm` lambda.

Also remove the `COALESCE_GAP` constant and `warm_ids` vector construction if they become unused.

Replace with a single comment:

```cpp
            // Checkpoints are built eagerly at init_infra() — no per-range warm needed.
```

- [ ] **Step 3: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc) 2>&1 | head -20
```

Expected: `trace_fold_pass.cpp` and `loop_semantics_pass.cpp` compile clean. `memory_snapshot_pass.cpp` still has `warm_at` error — fixed in Task 5.

- [ ] **Step 4: Run affected tests**

```bash
cd tools/tenet/build
ctest -R "trace_fold|loop_semantics" --output-on-failure
```

Expected: all pass.

- [ ] **Step 5: Commit (combined with Task 2 and Task 5)**

---

### Task 4: Implement CheckpointManager::create_cursor() + simplify API

**Files:**
- Modify: `tools/tenet/src/infra/checkpoint_manager.h` (remove `declare_warm_range` / `execute_warms` / `declared_ranges_`, keep `ensure_checkpoints` / `create_cursor` / `has_checkpoints`)
- Modify: `tools/tenet/src/infra/checkpoint_manager.cpp` (implement `create_cursor()`, remove `declare_warm_range` / `execute_warms`)

**Interfaces:**
- Produces: `CheckpointManager::create_cursor()` — returns `RegisterFileCursor(regfile_.reader(), regfile_.index())`
- Removes: `declare_warm_range()`, `execute_warms()`, `declared_ranges_`, `Range` struct

- [ ] **Step 1: Simplify checkpoint_manager.h**

Replace the entire `CheckpointManager` class with:

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

- [ ] **Step 2: Implement create_cursor() in checkpoint_manager.cpp**

Replace the `throw std::runtime_error(...)` in `create_cursor()` with:

```cpp
RegisterFileCursor CheckpointManager::create_cursor() const {
    return RegisterFileCursor(regfile_.reader(), regfile_.index());
}
```

- [ ] **Step 3: Remove declare_warm_range and execute_warms from checkpoint_manager.cpp**

Delete the `declare_warm_range()` and `execute_warms()` method implementations. Remove `#include <algorithm>` if it was only used by `execute_warms()`.

- [ ] **Step 4: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
```

Expected: clean build (if Task 2 and Task 3 are also staged). If `memory_snapshot_pass.cpp` still fails on `warm_at`, proceed to Task 5 first.

- [ ] **Step 5: Commit (combined with Task 2, 3, 5)**

---

### Task 5: Remove warm_at from memory_snapshot_pass + migrate vm_abstract_pass cursor

**Files:**
- Modify: `tools/tenet/src/analysis/passes/memory/memory_snapshot_pass.cpp` (delete `warm_at` block ~lines 311-332)
- Modify: `tools/tenet/src/analysis/passes/vm/vm_abstract_pass.cpp` (change `RegisterFileCursor(cursor(ctx.reader(), ctx.index()))` to `ctx.checkpoint_manager().create_cursor()`)

**Interfaces:**
- Removes: `regfile.warm_at()` call
- Produces: vm_abstract_pass uses `CheckpointManager::create_cursor()` instead of direct cursor construction

- [ ] **Step 1: Remove warm_at block from memory_snapshot_pass.cpp**

In `memory_snapshot_pass.cpp`, find the block starting with the comment `// ── Opt: pre-cache regfile for all call sites before the loop ──` (around line 311) and ending with the closing `}` of that block (around line 332). Delete the entire block including the timing, the `for` loop calling `warm_at`, and the `LOG_DEBUG` for warm timing.

Replace with a single comment:

```cpp
            // Checkpoints are built eagerly at init_infra() — no per-call-site warm needed.
```

- [ ] **Step 2: Migrate vm_abstract_pass cursor construction**

In `vm_abstract_pass.cpp` (around line 572), find:

```cpp
RegisterFileCursor cursor(ctx.reader(), ctx.index());
```

Replace with:

```cpp
RegisterFileCursor cursor = ctx.checkpoint_manager().create_cursor();
```

- [ ] **Step 3: Build and verify (combined with Tasks 2, 3, 4)**

```bash
cd tools/tenet/build
ninja -j$(nproc)
```

Expected: clean build, zero errors.

- [ ] **Step 4: Run full test suite**

```bash
cd tools/tenet/build
ctest --output-on-failure -j8
```

Expected: all tests pass.

- [ ] **Step 5: Commit (combined with Tasks 2, 3, 4)**

```bash
git add tools/tenet/src/core/register_file.h tools/tenet/src/core/register_file.cpp \
    tools/tenet/src/infra/checkpoint_manager.h tools/tenet/src/infra/checkpoint_manager.cpp \
    tools/tenet/src/analysis/passes/profile/trace_fold_pass.cpp \
    tools/tenet/src/analysis/passes/crypto/loop_semantics_pass.cpp \
    tools/tenet/src/analysis/passes/memory/memory_snapshot_pass.cpp \
    tools/tenet/src/analysis/passes/vm/vm_abstract_pass.cpp
git commit -m "feat(core): checkpoint-only register state reconstruction

Remove LRU cache, rebuild(), warm_range(), warm_at() from RegisterFile.
All state_before() queries now go through the immutable dense checkpoint
array (lock-free O(K) replay). CheckpointManager simplified to
ensure_checkpoints() + create_cursor(). Pass warm_range/warm_at calls
removed from trace_fold, loop_semantics, memory_snapshot. vm_abstract
uses CheckpointManager::create_cursor()."
```

---

### Task 6: Wire init_infra() eager checkpoint build + fix TUI/Python consumers

**Files:**
- Modify: `tools/tenet/src/analysis/pass_manager.cpp` (add `ensure_checkpoints()` call in `init_infra()`)
- Modify: `tools/tenet/src/tui/tui_app.cpp` (update cache stats display)
- Modify: `tools/tenet/src/tui/panels/register_panel.cpp` (update cache stats display)
- Modify: `tools/tenet/src/python/tenet_bindings.cpp` (update cache stats dict)
- Modify: `tools/tenet/src/core/register_file.h` (remove `hits` / `misses` / `warm_samples` from CacheStats — now that consumers are updated)

**Interfaces:**
- Produces: `init_infra()` eagerly calls `checkpoint_manager_->ensure_checkpoints()` after creating the manager
- Produces: TUI/Python show `ckpt_queries` / `ckpt_fallbacks` instead of `hits` / `misses`

- [ ] **Step 1: Add ensure_checkpoints() to init_infra()**

In `pass_manager.cpp`, in `init_infra()`, after the `checkpoint_manager_` creation block, add:

```cpp
    if (checkpoint_manager_) {
        LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager: building register checkpoints...");
        checkpoint_manager_->ensure_checkpoints();
        LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager: checkpoints built");
    }
```

- [ ] **Step 2: Update TUI cache stats display in tui_app.cpp**

In `tui_app.cpp` (around line 1877-1878), replace:

```cpp
auto stats = regfile_.cache_stats();
fmt::print("\n  Cache stats: hits={} misses={}\n", stats.hits, stats.misses);
```

with:

```cpp
auto stats = regfile_.cache_stats();
fmt::print("\n  Checkpoint stats: queries={} fallbacks={}\n",
    stats.ckpt_queries.load(), stats.ckpt_fallbacks.load());
```

- [ ] **Step 3: Update TUI register panel in register_panel.cpp**

In `register_panel.cpp` (around line 173-174), replace:

```cpp
reg_lines.push_back(text(fmt::format("Cache: {} hits / {} misses",
    stats.hits, stats.misses))
| color(Color::GrayLight));
```

with:

```cpp
reg_lines.push_back(text(fmt::format("Checkpoints: {} queries / {} fallbacks",
    stats.ckpt_queries.load(), stats.ckpt_fallbacks.load()))
| color(Color::GrayLight));
```

- [ ] **Step 4: Update Python bindings in tenet_bindings.cpp**

In `tenet_bindings.cpp` (around lines 174-178), replace the cache_stats dict construction:

```cpp
py::dict d;
d["ckpt_queries"] = s.ckpt_queries.load();
d["ckpt_fallbacks"] = s.ckpt_fallbacks.load();
return d;
```

- [ ] **Step 5: Remove hits/misses/warm_samples from CacheStats**

In `register_file.h`, update `CacheStats` to:

```cpp
    struct CacheStats {
        std::atomic<uint64_t> ckpt_queries{0};
        std::atomic<uint64_t> ckpt_fallbacks{0};
    };
```

In `register_file.cpp`, remove any remaining `cache_stats_.hits` / `cache_stats_.misses` / `cache_stats_.warm_samples` references (in `state_before()`, `warm_at()`, `warm_range()` — but those methods are already removed in Task 2, so there should be none left).

- [ ] **Step 6: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
```

Expected: clean build, zero errors.

- [ ] **Step 7: Run full test suite**

```bash
cd tools/tenet/build
ctest --output-on-failure -j8
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add tools/tenet/src/analysis/pass_manager.cpp \
    tools/tenet/src/tui/tui_app.cpp \
    tools/tenet/src/tui/panels/register_panel.cpp \
    tools/tenet/src/python/tenet_bindings.cpp \
    tools/tenet/src/core/register_file.h
git commit -m "feat(infra): eager checkpoint build in init_infra + update consumers

init_infra() now calls ensure_checkpoints() after creating
CheckpointManager. TUI and Python bindings updated to show
ckpt_queries/ckpt_fallbacks instead of LRU hits/misses. CacheStats
simplified to checkpoint-only fields."
```

---

### Task 7: Update analysis-layer.md documentation

**Files:**
- Modify: `tools/tenet/docs/analysis-layer.md` (update RegisterFile section if present)

**Context:** The analysis-layer.md documents the Analysis layer architecture. The Core layer (RegisterFile) is documented in `core-layer.md`. Check which file describes RegisterFile's query strategy and update it.

- [ ] **Step 1: Check core-layer.md for RegisterFile documentation**

Read `tools/tenet/docs/core-layer.md` (or `ARCHITECTURE.md`) to find where RegisterFile's two query strategies are described.

- [ ] **Step 2: Update the RegisterFile section**

Replace the description of "two query strategies" with the checkpoint-only model:
- Dense checkpoint array built eagerly at `init_infra()`
- All `state_before()` / `state_after()` queries are lock-free O(K)
- LRU cache, `rebuild()`, `warm_range()`, `warm_at()` removed
- CheckpointManager provides `ensure_checkpoints()` + `create_cursor()`

- [ ] **Step 3: Commit**

```bash
git add tools/tenet/docs/
git commit -m "docs: update RegisterFile description for checkpoint-only model"
```

---

## Self-Review Notes

After implementing all tasks:

1. **Spec coverage:** All sections of the spec are covered — RegisterFile simplification (Task 2), CheckpointManager (Task 4), pass call-site changes (Tasks 3, 5), init_infra integration (Task 6), edge case handling (Task 2 empty/out-of-range guards), testing (each task runs tests).

2. **Placeholder scan:** No TBD/TODO. `create_cursor()` implementation is shown in Task 4. All code blocks are complete.

3. **Type consistency:** `CacheStats` fields: `ckpt_queries` / `ckpt_fallbacks` consistent across all tasks. `create_cursor()` returns `RegisterFileCursor` by value (movable). `ensure_checkpoints()` signature unchanged from existing code.

4. **Task ordering:** Tasks 2-5 must be committed together (they have interdependent compile dependencies). Task 6 depends on all previous. Task 7 is documentation.

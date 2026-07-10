# Tenet Infra Layer — Framework-Level Services for Analysis Passes

## Overview

The Infra layer is a new architectural layer between Core and Analysis that centralizes framework-level capabilities currently duplicated across individual passes. It provides four shared services — `ScanOrchestrator`, `PageStats`, `StringResolver`, and `CheckpointManager` — exposed to passes via `PassContext` independent accessors.

**Design goals:**

- Eliminate redundant trace traversals (Scan Fusion: one scan serves all collectors)
- Eliminate duplicated memory page statistics computation
- Eliminate duplicated string parsing logic
- Eliminate ad-hoc register checkpoint strategy decisions
- Maintain backward compatibility — existing passes work unchanged

## Architecture

```
Frontend (TUI/GUI/CLI)
        ↕
Pass Pipeline (XRef, Taint, CFG, String, Pattern, ...)
        ↕  PassContext exposes Infra services
Infra Layer (ScanOrchestrator, PageStats, StringResolver, CheckpointManager)
        ↕
Core (RegisterFile + MemoryModel + InstructionDecoder + TritonBridge)
        ↕
IO (TraceReader mmap + RocksDB Index)
```

**Key principle:** Infra services encapsulate *strategies* (when to build, how to cache, how to fuse scans), while Core services provide *mechanisms* (raw register reconstruction, raw memory reads). Passes consume Infra services and never touch Core strategy decisions directly.

## Current Problems

### Problem 1: No Scan Fusion (5-8× redundant trace scans)

`PassManager::run_all()` does NOT call `TraceScanEngine::run()`. Each scan-based pass creates its own `TraceScanEngine` via `ctx.make_scan_engine()` and independently traverses the entire trace:

- `xref_pass` — scans for call/ret patterns
- `function_pass` — scans for function boundaries
- `window_stats_pass` — scans for window statistics
- `dataflow_graph_pass` — scans for dataflow edges
- `loop_pass` — scans for loop back-edges
- `call_graph_pass` — scans for call graph edges

Result: the same trace is sequentially scanned 5-8 times, each costing O(N). A 10M-instruction trace takes ~60s of redundant scanning.

### Problem 2: Duplicated Memory Page Statistics

`entropy_pass` and `memory_string_pass` both independently:
1. Call `MemoryModel::active_pages()` to enumerate pages
2. Call `MemoryModel::read_region()` to read each page's bytes
3. Compute page-level statistics (entropy, string candidacy)

No shared caching — if both passes run, every page is read twice.

### Problem 3: Duplicated String Parsing

`memory_string_pass`, `objc_pass`, and `syscall_intercept_pass` each implement their own C-string parsing from memory:
1. Read bytes via `MemoryModel::read_region()`
2. Scan for printable ASCII sequences
3. Validate string boundaries

Three independent implementations of the same logic.

### Problem 4: Ad-hoc Checkpoint Strategy

`RegisterFile` provides `build_checkpoints()` and `warm_range()`, but each pass decides independently:
- When to call `build_checkpoints()` (some call it, some don't)
- What ranges to `warm_range()` (overlapping ranges warmed multiple times)

No deduplication, no unified policy.

## Services

### Service 1: ScanOrchestrator

**Purpose:** Unified Scan Fusion orchestration — one trace scan serves all declared collectors.

**Lifecycle:** Eager (created at `PassManager` init, scan executed before pass `run()` phase).

**Interface:**

```cpp
// src/infra/scan_orchestrator.h

namespace tenet {

/// Declarative collector requirement — a pass declares what scan data it needs.
struct ScanDeclaration {
    std::string_view pass_name;     // declaring pass name
    TraceCollector*  collector;      // collector instance (pass owns it)
    bool             wants_parallel; // supports parallel scanning
};

class ScanOrchestrator {
public:
    explicit ScanOrchestrator(const TraceReader& reader, uint64_t inst_count,
                               const TraceIndex* index = nullptr);

    /// Declare a collector requirement (pass calls during declare_scan phase)
    void declare(ScanDeclaration decl);

    /// Execute unified scan — adds all declared collectors to one TraceScanEngine,
    /// then single run()/run_parallel() serves all.
    /// Returns instructions processed.
    uint64_t execute_scan(const AnalysisRange& range,
                          const std::atomic<bool>& cancel_token,
                          bool no_parallel = false);

    /// Get collector for a pass name (pass reads results after scan)
    TraceCollector* collector_for(std::string_view pass_name) const;

    bool has_declarations() const;
    void reset();
};

}  // namespace tenet
```

**AnalysisPass integration — new virtual method:**

```cpp
class AnalysisPass {
    // ... existing ...

    /// Declare scan collector requirements (default: none).
    /// Override to participate in Scan Fusion.
    /// Called before run() phase, after all passes are registered.
    virtual void declare_scan(ScanOrchestrator& orchestrator) { (void)orchestrator; }
};
```

**PassManager execution flow:**

```
run_all() {
    // Phase 1: Declaration — each pass's declare_scan() registers collectors
    for each pass in registration_order:
        pass->declare_scan(scan_orchestrator_)

    // Phase 2: Unified scan — one traversal serves all collectors
    if (scan_orchestrator_.has_declarations())
        scan_orchestrator_.execute_scan(range_, cancelled_, no_parallel_scan_)

    // Phase 3: Execution — existing run_all_parallel DAG scheduler (unchanged)
    // Passes read results from their collectors in run()
    run_all_parallel(num_threads)
}
```

**Backward compatibility:** Passes that don't override `declare_scan()` are unaffected. Passes that still use `ctx.make_scan_engine()` directly continue to work (they just don't participate in fusion).

### Service 2: PageStats

**Purpose:** Cached page-level memory statistics (entropy, string candidacy, access timeline).

**Lifecycle:** Lazy — built on first access.

**Interface:**

```cpp
// src/infra/page_stats.h

namespace tenet {

struct PageSummary {
    uint64_t page_addr;         // page-aligned address
    uint64_t first_access;      // first inst_id that accessed this page
    uint64_t last_access;       // last inst_id that accessed this page
    uint32_t write_count;       // write events
    uint32_t read_count;        // read events
    bool     has_strings;       // heuristic: contains readable strings
    double   entropy;           // page entropy (0.0-8.0, -1.0 = not computed)
};

class PageStats {
public:
    explicit PageStats(MemoryModel& memory);

    void ensure_built();

    const PageSummary* page(uint64_t page_addr) const;
    const std::vector<PageSummary>& all_pages() const;

    /// Pages with entropy > threshold (entropy_pass consumes this)
    std::vector<const PageSummary*> high_entropy_pages(double threshold = 7.0) const;

    /// Pages that may contain strings (memory_string_pass consumes this)
    std::vector<const PageSummary*> string_candidate_pages() const;

    bool is_built() const;
};

}  // namespace tenet
```

**Relationship to Core:** `MemoryModel::active_pages()` returns raw `PageActivity` structs. `PageStats` builds on that, incrementally computing entropy and string heuristics. The raw page bytes are read once via `MemoryModel::read_region()` and cached.

### Service 3: StringResolver

**Purpose:** Unified string parsing from memory with cross-pass caching.

**Lifecycle:** Lazy — built on first access.

**Interface:**

```cpp
// src/infra/string_resolver.h

namespace tenet {

struct ResolvedString {
    uint64_t addr;              // string start address
    std::string value;          // parsed string value
    uint64_t inst_id;           // time of memory read
    enum Kind { CStr, Utf16, Raw } kind;
    size_t   length;            // raw byte length
};

class StringResolver {
public:
    StringResolver(MemoryModel& memory, PageStats& page_stats);

    void ensure_built(uint64_t at_inst_id = UINT64_MAX);

    std::optional<ResolvedString> resolve(uint64_t addr, uint64_t at_inst_id);
    std::vector<ResolvedString> resolve_region(uint64_t base_addr, size_t size,
                                                uint64_t at_inst_id);
    const std::vector<ResolvedString>& all_strings() const;

    bool is_built() const;
};

}  // namespace tenet
```

**Relationship to PageStats:** Uses `PageStats::string_candidate_pages()` to filter which pages to scan, avoiding full memory traversal.

### Service 4: CheckpointManager

**Purpose:** Unified register checkpoint strategy — ensures checkpoints built once, warm ranges deduplicated.

**Lifecycle:** Eager — checkpoints built at `PassManager` init; warm ranges declared by passes, executed in batch.

**Interface:**

```cpp
// src/infra/checkpoint_manager.h

namespace tenet {

class CheckpointManager {
public:
    explicit CheckpointManager(RegisterFile& regfile);

    /// Build checkpoint array (idempotent — only once)
    void ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Declare a range needing warm (pass calls during declare_scan or run)
    void declare_warm_range(uint64_t start_id, uint64_t end_id);

    /// Execute all declared warms (merge overlapping, batch warm)
    void execute_warms();

    /// Create a RegisterFileCursor (unified factory)
    RegisterFileCursor create_cursor() const;

    bool has_checkpoints() const;
};

}  // namespace tenet
```

**Relationship to Core:** `RegisterFile::build_checkpoints()` and `warm_range()` are the underlying mechanisms. `CheckpointManager` ensures they're called once with merged ranges, not redundantly per-pass.

## PassContext Integration

`PassContext` gains four independent accessors, following the existing pattern of `ctx.reader()`, `ctx.regfile()`, etc:

```cpp
class PassContext {
public:
    // ... existing IO/Core accessors ...

    // Infra layer services
    ScanOrchestrator&  scan_orchestrator();
    PageStats&         page_stats();
    StringResolver&    string_resolver();
    CheckpointManager& checkpoint_manager();
};
```

**PassManager** owns the Infra services as `unique_ptr` members, initialized via `init_infra()` after IO/Core pointers are set:

```cpp
class PassManager {
    // ... existing ...
    std::unique_ptr<ScanOrchestrator>  scan_orchestrator_;
    std::unique_ptr<PageStats>         page_stats_;
    std::unique_ptr<StringResolver>    string_resolver_;
    std::unique_ptr<CheckpointManager> checkpoint_manager_;

    void init_infra();  // call after set_reader/set_memory/etc.
};
```

## File Structure

```
src/infra/
├── scan_orchestrator.h
├── scan_orchestrator.cpp
├── page_stats.h
├── page_stats.cpp
├── string_resolver.h
├── string_resolver.cpp
├── checkpoint_manager.h
├── checkpoint_manager.cpp
└── infra_context.h        # (optional — inline accessors in PassContext instead)
```

No `infra_context.h` — accessors are inlined directly in `pass_manager.h` to match existing patterns.

## Migration Strategy

| Phase | Service | Passes Migrated |
|-------|---------|-----------------|
| Phase 0 | Directory + CMake + empty shells | None (pure addition) |
| Phase 1 | CheckpointManager | Passes calling `regfile.build_checkpoints()` directly → use `ctx.checkpoint_manager()` |
| Phase 2 | ScanOrchestrator | `xref`, `function`, `window_stats`, `dataflow_graph`, `loop`, `call_graph` — override `declare_scan()` |
| Phase 3 | PageStats | `entropy_pass`, `memory_string_pass` |
| Phase 4 | StringResolver | `memory_string_pass`, `objc_pass`, `syscall_intercept_pass` |

Each phase is independently testable. Old code doesn't need to migrate all at once — `ctx.make_scan_engine()` remains available for passes that haven't migrated.

## Non-Goals

- **Not** replacing `TraceScanEngine` — ScanOrchestrator wraps it
- **Not** replacing `MemoryModel` — PageStats/StringResolver build on it
- **Not** replacing `RegisterFile` — CheckpointManager wraps its strategy
- **Not** forcing all passes to migrate — backward compatible
- **Not** adding new analysis capabilities — this is a refactoring for performance/maintainability

## Success Criteria

1. All existing tests pass (`ctest --output-on-failure`)
2. Scan-based passes participate in Scan Fusion (verified by log showing single `execute_scan` call)
3. `entropy_pass` and `memory_string_pass` share page statistics (verified by PageStats cache hit logging)
4. String parsing logic exists in exactly one place (`StringResolver`)
5. `RegisterFile::build_checkpoints()` is called at most once per analysis run
6. Build time stays fast (incremental build < 5s for single-file change in `src/infra/`)

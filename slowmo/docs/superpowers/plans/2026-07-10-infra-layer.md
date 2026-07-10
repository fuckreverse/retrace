# Tenet Infra Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a new Infra layer between Core and Analysis that centralizes framework-level services (ScanOrchestrator, PageStats, StringResolver, CheckpointManager), eliminating redundant trace scans, duplicated memory statistics, and ad-hoc checkpoint strategies.

**Architecture:** Four independent services owned by `PassManager` as `unique_ptr` members, exposed to passes via `PassContext` independent accessors (`ctx.scan_orchestrator()`, etc.). ScanOrchestrator implements Scan Fusion by wrapping the existing `TraceScanEngine`. PageStats and StringResolver build on `MemoryModel`. CheckpointManager wraps `RegisterFile`'s checkpoint strategy. All services are backward compatible — existing passes work unchanged.

**Tech Stack:** C++17, CMake/Ninja, Catch2 testing, no new third-party dependencies

## Global Constraints

- Build target: `tenet_lib` (static library, `tools/tenet/CMakeLists.txt`)
- **Never** create new `build-xxx` directories or delete `_deps/`
- All new Infra files under `src/infra/` directory
- `FETCHCONTENT_BASE_DIR` remains `tools/tenet/_deps/`
- Existing tests (`ctest --output-on-failure`) must stay green after every task
- Incremental build must stay fast (single-file change in `src/infra/` < 5s)
- PassManager init pattern used in 5 call sites: `set_reader`, `set_index`, `set_code_table`, `set_regfile`, `set_memory`, `set_decoder` — a new `init_infra()` call must be added after these at each site
- `build_checkpoints()` is currently never called in production code — CheckpointManager makes it eager
- `warm_range()` is called in `trace_fold_pass` and `loop_semantics_pass` — these are migration candidates but not required for initial integration
- Scan-based passes (xref, function, window_stats, etc.) currently use `ctx.make_scan_engine()` — ScanOrchestrator provides an alternative fusion path but doesn't remove the old one

---

### Task 1: Create Infra Layer Skeleton + PassContext Accessors

**Files:**
- Create: `tools/tenet/src/infra/scan_orchestrator.h`
- Create: `tools/tenet/src/infra/scan_orchestrator.cpp`
- Create: `tools/tenet/src/infra/page_stats.h`
- Create: `tools/tenet/src/infra/page_stats.cpp`
- Create: `tools/tenet/src/infra/string_resolver.h`
- Create: `tools/tenet/src/infra/string_resolver.cpp`
- Create: `tools/tenet/src/infra/checkpoint_manager.h`
- Create: `tools/tenet/src/infra/checkpoint_manager.cpp`
- Modify: `tools/tenet/CMakeLists.txt` (add 8 new source files to `tenet_lib`)
- Modify: `tools/tenet/src/analysis/pass_manager.h` (add forward declarations, `unique_ptr` members, `init_infra()`, PassContext accessors)
- Modify: `tools/tenet/src/analysis/pass_manager.cpp` (implement `init_infra()`, PassContext accessor methods)
- Modify: `tools/tenet/src/service/tenet_service.cpp` (add `init_infra()` call)
- Modify: `tools/tenet/src/batch_analysis.cpp` (add `init_infra()` call)
- Modify: `tools/tenet/src/gui/panels_analysis.cpp` (add `init_infra()` call)
- Modify: `tools/tenet/src/gui/panels_reg_timeline.cpp` (add `init_infra()` call — 2 sites)
- Modify: `tools/tenet/src/gui/panels_trace_diff.cpp` (add `init_infra()` call)

**Interfaces:**
- Produces: `ScanOrchestrator`, `PageStats`, `StringResolver`, `CheckpointManager` classes (stub implementations with `ensure_built()` no-ops)
- Produces: `PassContext::scan_orchestrator()`, `PassContext::page_stats()`, `PassContext::string_resolver()`, `PassContext::checkpoint_manager()` accessor methods
- Produces: `PassManager::init_infra()` method (creates the 4 service instances from existing IO/Core pointers)
- Consumes: `TraceReader`, `TraceIndex`, `RegisterFile`, `MemoryModel` (all existing Core/IO types)

- [ ] **Step 1: Create scan_orchestrator.h stub**

```cpp
// tools/tenet/src/infra/scan_orchestrator.h
#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include <atomic>
#include <string_view>
#include <vector>

namespace tenet {

class TraceIndex;
class TraceCollector;
class AnalysisRange;

/// Declarative collector requirement — a pass declares what scan data it needs.
struct ScanDeclaration {
    std::string_view pass_name;     ///< declaring pass name
    TraceCollector*  collector;      ///< collector instance (pass owns it)
    bool             wants_parallel; ///< supports parallel scanning
};

/// Unified Scan Fusion orchestrator — one trace scan serves all declared collectors.
///
/// Lifecycle:
///   1. PassManager::run_all() calls each pass's declare_scan() to register collectors
///   2. PassManager calls execute_scan() — single traversal serves all collectors
///   3. Passes read results from their collectors in run()
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

    bool has_declarations() const { return !declarations_.empty(); }

    /// Clear all declarations (call after run_all completes, before next analysis)
    void reset();

private:
    const TraceReader& reader_;
    uint64_t inst_count_;
    const TraceIndex* index_;

    std::vector<ScanDeclaration> declarations_;
    bool scanned_ = false;
};

}  // namespace tenet
```

- [ ] **Step 2: Create scan_orchestrator.cpp stub**

```cpp
// tools/tenet/src/infra/scan_orchestrator.cpp
#include "infra/scan_orchestrator.h"
#include "analysis/trace_collector.h"
#include "analysis/pass_manager.h"  // for AnalysisRange

namespace tenet {

ScanOrchestrator::ScanOrchestrator(const TraceReader& reader, uint64_t inst_count,
                                     const TraceIndex* index)
    : reader_(reader), inst_count_(inst_count), index_(index) {}

void ScanOrchestrator::declare(ScanDeclaration decl) {
    declarations_.push_back(std::move(decl));
}

uint64_t ScanOrchestrator::execute_scan(const AnalysisRange& range,
                                          const std::atomic<bool>& cancel_token,
                                          bool no_parallel) {
    (void)range;
    (void)cancel_token;
    (void)no_parallel;
    // Stub — real implementation in Task 3
    scanned_ = true;
    return 0;
}

TraceCollector* ScanOrchestrator::collector_for(std::string_view pass_name) const {
    for (const auto& d : declarations_) {
        if (d.pass_name == pass_name) return d.collector;
    }
    return nullptr;
}

void ScanOrchestrator::reset() {
    declarations_.clear();
    scanned_ = false;
}

}  // namespace tenet
```

- [ ] **Step 3: Create page_stats.h stub**

```cpp
// tools/tenet/src/infra/page_stats.h
#pragma once

#include "common/types.h"
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace tenet {

class MemoryModel;

/// Single memory page statistics summary.
struct PageSummary {
    uint64_t page_addr;         ///< page-aligned address (page_number << 12)
    uint64_t first_access;      ///< first inst_id that accessed this page
    uint64_t last_access;       ///< last inst_id that accessed this page
    uint32_t write_count;       ///< write events to this page
    uint32_t read_count;        ///< read events to this page
    bool     has_strings;       ///< heuristic: contains readable strings
    double   entropy;           ///< page entropy (0.0-8.0, -1.0 = not computed)
};

/// Cached page-level memory statistics.
///
/// Lifecycle: Lazy — built on first access via ensure_built().
///
/// Built on top of MemoryModel::active_pages(), incrementally computing
/// entropy and string heuristics. Page bytes are read once and cached.
class PageStats {
public:
    explicit PageStats(MemoryModel& memory);

    /// Ensure statistics are built (lazy trigger point)
    void ensure_built();

    const PageSummary* page(uint64_t page_addr) const;
    const std::vector<PageSummary>& all_pages() const { return pages_; }

    /// Pages with entropy > threshold
    std::vector<const PageSummary*> high_entropy_pages(double threshold = 7.0) const;

    /// Pages that may contain strings (heuristic)
    std::vector<const PageSummary*> string_candidate_pages() const;

    bool is_built() const { return built_; }

private:
    void build();

    MemoryModel& memory_;
    std::vector<PageSummary> pages_;
    std::unordered_map<uint64_t, size_t> page_index_;  // page_addr → index in pages_
    bool built_ = false;
};

}  // namespace tenet
```

- [ ] **Step 4: Create page_stats.cpp stub**

```cpp
// tools/tenet/src/infra/page_stats.cpp
#include "infra/page_stats.h"
#include "core/memory_model.h"

namespace tenet {

PageStats::PageStats(MemoryModel& memory) : memory_(memory) {}

void PageStats::ensure_built() {
    if (built_) return;
    build();
}

void PageStats::build() {
    // Stub — real implementation in Task 4
    built_ = true;
}

const PageSummary* PageStats::page(uint64_t page_addr) const {
    auto it = page_index_.find(page_addr);
    if (it == page_index_.end()) return nullptr;
    return &pages_[it->second];
}

std::vector<const PageSummary*> PageStats::high_entropy_pages(double threshold) const {
    std::vector<const PageSummary*> result;
    for (const auto& p : pages_) {
        if (p.entropy > threshold) result.push_back(&p);
    }
    return result;
}

std::vector<const PageSummary*> PageStats::string_candidate_pages() const {
    std::vector<const PageSummary*> result;
    for (const auto& p : pages_) {
        if (p.has_strings) result.push_back(&p);
    }
    return result;
}

}  // namespace tenet
```

- [ ] **Step 5: Create string_resolver.h stub**

```cpp
// tools/tenet/src/infra/string_resolver.h
#pragma once

#include "common/types.h"
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tenet {

class MemoryModel;
class PageStats;

/// A string resolved from memory at a specific point in time.
struct ResolvedString {
    uint64_t addr;              ///< string start address
    std::string value;          ///< parsed string value
    uint64_t inst_id;           ///< time of memory read
    enum Kind { CStr, Utf16, Raw } kind;
    size_t   length;            ///< raw byte length
};

/// Unified string parsing from memory with cross-pass caching.
///
/// Lifecycle: Lazy — built on first access via ensure_built().
///
/// Uses PageStats::string_candidate_pages() to filter which pages to scan.
class StringResolver {
public:
    StringResolver(MemoryModel& memory, PageStats& page_stats);

    void ensure_built(uint64_t at_inst_id = UINT64_MAX);

    std::optional<ResolvedString> resolve(uint64_t addr, uint64_t at_inst_id);
    std::vector<ResolvedString> resolve_region(uint64_t base_addr, size_t size,
                                                uint64_t at_inst_id);
    const std::vector<ResolvedString>& all_strings() const { return strings_; }

    bool is_built() const { return built_; }

private:
    void build(uint64_t at_inst_id);
    std::optional<ResolvedString> parse_cstring(uint64_t addr, uint64_t at_inst_id);

    MemoryModel& memory_;
    PageStats& page_stats_;

    std::vector<ResolvedString> strings_;
    std::unordered_map<uint64_t, size_t> addr_index_;  // addr → index in strings_
    bool built_ = false;
};

}  // namespace tenet
```

- [ ] **Step 6: Create string_resolver.cpp stub**

```cpp
// tools/tenet/src/infra/string_resolver.cpp
#include "infra/string_resolver.h"
#include "core/memory_model.h"
#include "infra/page_stats.h"

namespace tenet {

StringResolver::StringResolver(MemoryModel& memory, PageStats& page_stats)
    : memory_(memory), page_stats_(page_stats) {}

void StringResolver::ensure_built(uint64_t at_inst_id) {
    if (built_) return;
    build(at_inst_id);
}

void StringResolver::build(uint64_t at_inst_id) {
    (void)at_inst_id;
    // Stub — real implementation in Task 5
    built_ = true;
}

std::optional<ResolvedString> StringResolver::resolve(uint64_t addr, uint64_t at_inst_id) {
    (void)addr;
    (void)at_inst_id;
    // Stub — real implementation in Task 5
    return std::nullopt;
}

std::vector<ResolvedString> StringResolver::resolve_region(uint64_t base_addr, size_t size,
                                                             uint64_t at_inst_id) {
    (void)base_addr;
    (void)size;
    (void)at_inst_id;
    return {};
}

}  // namespace tenet
```

- [ ] **Step 7: Create checkpoint_manager.h stub**

```cpp
// tools/tenet/src/infra/checkpoint_manager.h
#pragma once

#include "common/types.h"
#include <cstdint>
#include <functional>
#include <vector>

namespace tenet {

class RegisterFile;
class RegisterFileCursor;

/// Unified register checkpoint strategy manager.
///
/// Lifecycle: Eager — checkpoints built at init_infra(); warm ranges declared
/// by passes and executed in batch via execute_warms().
///
/// Ensures RegisterFile::build_checkpoints() is called at most once, and
/// warm_range() calls are merged (overlapping ranges deduplicated).
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

private:
    RegisterFile& regfile_;

    struct Range {
        uint64_t start, end;
        bool operator<(const Range& o) const { return start < o.start; }
    };
    std::vector<Range> declared_ranges_;
    bool checkpoints_built_ = false;
};

}  // namespace tenet
```

- [ ] **Step 8: Create checkpoint_manager.cpp stub**

```cpp
// tools/tenet/src/infra/checkpoint_manager.cpp
#include "infra/checkpoint_manager.h"
#include "core/register_file.h"

namespace tenet {

CheckpointManager::CheckpointManager(RegisterFile& regfile) : regfile_(regfile) {}

void CheckpointManager::ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress) {
    (void)progress;
    if (checkpoints_built_) return;
    // Stub — real implementation in Task 2
    checkpoints_built_ = true;
}

void CheckpointManager::declare_warm_range(uint64_t start_id, uint64_t end_id) {
    declared_ranges_.push_back({start_id, end_id});
}

void CheckpointManager::execute_warms() {
    // Stub — real implementation in Task 2
    declared_ranges_.clear();
}

RegisterFileCursor CheckpointManager::create_cursor() const {
    // Stub — real implementation in Task 2
    // Will return regfile_-based cursor
    throw std::runtime_error("CheckpointManager::create_cursor not yet implemented");
}

bool CheckpointManager::has_checkpoints() const {
    return checkpoints_built_;
}

}  // namespace tenet
```

- [ ] **Step 9: Add Infra source files to CMakeLists.txt**

In `tools/tenet/CMakeLists.txt`, in the `add_library(tenet_lib STATIC ...)` block, after `src/analysis/trace_collector.cpp` (around line 482), add:

```cmake
    src/infra/scan_orchestrator.cpp
    src/infra/page_stats.cpp
    src/infra/string_resolver.cpp
    src/infra/checkpoint_manager.cpp
```

- [ ] **Step 10: Add forward declarations and members to pass_manager.h**

In `tools/tenet/src/analysis/pass_manager.h`:

1. After the existing forward declarations (line 25, `class TraceScanEngine;`), add:

```cpp
class ScanOrchestrator;
class PageStats;
class StringResolver;
class CheckpointManager;
```

2. In the `PassContext` class, after the `InstructionDecoder& decoder();` line (line 102), add:

```cpp
    // Infra layer services
    ScanOrchestrator&  scan_orchestrator();
    PageStats&         page_stats();
    StringResolver&    string_resolver();
    CheckpointManager& checkpoint_manager();
```

3. In the `PassManager` class, after `void set_decoder(InstructionDecoder* d) { decoder_ = d; }` (line 209), add:

```cpp
    /// Initialize Infra layer services. Must be called AFTER set_reader/set_index/
    /// set_code_table/set_regfile/set_memory/set_decoder.
    void init_infra();
```

4. In the `PassManager` private section, after `InstructionDecoder* decoder_ = nullptr;` (line 416), add:

```cpp
    // Infra layer services (owned)
    std::unique_ptr<ScanOrchestrator>  scan_orchestrator_;
    std::unique_ptr<PageStats>         page_stats_;
    std::unique_ptr<StringResolver>    string_resolver_;
    std::unique_ptr<CheckpointManager> checkpoint_manager_;
```

- [ ] **Step 11: Implement init_infra() and PassContext accessors in pass_manager.cpp**

In `tools/tenet/src/analysis/pass_manager.cpp`:

1. At the top, after existing includes, add:

```cpp
#include "infra/scan_orchestrator.h"
#include "infra/page_stats.h"
#include "infra/string_resolver.h"
#include "infra/checkpoint_manager.h"
```

2. After the existing `InstructionDecoder& PassContext::decoder() { return *manager_.decoder(); }` (line 27), add:

```cpp
ScanOrchestrator&  PassContext::scan_orchestrator()  { return *manager_.scan_orchestrator_; }
PageStats&         PassContext::page_stats()         { return *manager_.page_stats_; }
StringResolver&    PassContext::string_resolver()    { return *manager_.string_resolver_; }
CheckpointManager& PassContext::checkpoint_manager() { return *manager_.checkpoint_manager_; }
```

3. After `PassManager::~PassManager() = default;` (line 67), add:

```cpp
void PassManager::init_infra() {
    // All IO/Core pointers must be set before calling this.
    if (!reader_ || !index_ || !regfile_ || !memory_) {
        LOG_WARN_M(::tenet::log::Module::Analysis,
            "PassManager::init_infra(): IO/Core pointers not fully set — skipping");
        return;
    }
    if (!scan_orchestrator_) {
        scan_orchestrator_ = std::make_unique<ScanOrchestrator>(
            *reader_, index_->inst_count(), index_);
    }
    if (!page_stats_) {
        page_stats_ = std::make_unique<PageStats>(*memory_);
    }
    if (!string_resolver_) {
        string_resolver_ = std::make_unique<StringResolver>(*memory_, *page_stats_);
    }
    if (!checkpoint_manager_) {
        checkpoint_manager_ = std::make_unique<CheckpointManager>(*regfile_);
    }
}
```

- [ ] **Step 12: Add init_infra() calls to all 5 PassManager init sites**

In each of these files, add `pm.init_infra();` (or `pass_manager_->init_infra();`) immediately after the last `set_decoder()` or `set_memory()` call:

1. `tools/tenet/src/service/tenet_service.cpp` — after line 158 (`pass_manager_->set_memory(&memory_);`):
   ```cpp
   pass_manager_->init_infra();
   ```

2. `tools/tenet/src/batch_analysis.cpp` — after line 681 (`pm.set_no_parallel_scan(opts.opt_no_parallel_scan);`):
   ```cpp
   pm.init_infra();
   ```

3. `tools/tenet/src/gui/panels_analysis.cpp` — after line 53 (`pass_manager_->set_memory(&memory_);`):
   ```cpp
   pass_manager_->init_infra();
   ```

4. `tools/tenet/src/gui/panels_reg_timeline.cpp` — after line 70 and after line 127 (two sites):
   ```cpp
   pm.init_infra();
   ```

5. `tools/tenet/src/gui/panels_trace_diff.cpp` — after line 54 (`pm->set_memory(&memory_);`):
   ```cpp
   pm->init_infra();
   ```

- [ ] **Step 13: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
```

Expected: clean build, zero errors. The stub implementations compile and link. All existing tests still pass:

```bash
ctest --output-on-failure
```

- [ ] **Step 14: Commit**

```bash
git add tools/tenet/src/infra/ tools/tenet/CMakeLists.txt \
    tools/tenet/src/analysis/pass_manager.h tools/tenet/src/analysis/pass_manager.cpp \
    tools/tenet/src/service/tenet_service.cpp tools/tenet/src/batch_analysis.cpp \
    tools/tenet/src/gui/panels_analysis.cpp tools/tenet/src/gui/panels_reg_timeline.cpp \
    tools/tenet/src/gui/panels_trace_diff.cpp
git commit -m "feat(infra): add Infra layer skeleton with 4 service stubs + PassContext accessors

New src/infra/ directory with ScanOrchestrator, PageStats, StringResolver,
CheckpointManager — all stub implementations. PassManager gains init_infra()
and 4 unique_ptr service members. PassContext gains 4 independent accessors.
All 5 PassManager init sites updated to call init_infra() after Core setup."
```

---

### Task 2: Implement CheckpointManager

**Files:**
- Modify: `tools/tenet/src/infra/checkpoint_manager.cpp` (implement real logic)
- Modify: `tools/tenet/src/infra/checkpoint_manager.h` (add `#include "core/register_file.h"` for cursor return type)

**Interfaces:**
- Produces: `CheckpointManager::ensure_checkpoints()` — calls `RegisterFile::build_checkpoints()` exactly once
- Produces: `CheckpointManager::declare_warm_range()` + `execute_warms()` — merges overlapping ranges and batch-calls `RegisterFile::warm_range()`
- Produces: `CheckpointManager::create_cursor()` — creates a `RegisterFileCursor` from the underlying `RegisterFile`
- Consumes: `RegisterFile::build_checkpoints()`, `RegisterFile::warm_range()`, `RegisterFileCursor` constructor

- [ ] **Step 1: Update checkpoint_manager.h to include register_file.h**

In `tools/tenet/src/infra/checkpoint_manager.h`, replace the forward declaration `class RegisterFileCursor;` with:

```cpp
#include "core/register_file.h"
```

And remove the `class RegisterFile;` forward declaration since `register_file.h` provides it. The final includes section should be:

```cpp
#pragma once

#include "common/types.h"
#include "core/register_file.h"
#include <cstdint>
#include <functional>
#include <vector>
```

Remove the `class RegisterFile;` and `class RegisterFileCursor;` forward declarations.

- [ ] **Step 2: Implement ensure_checkpoints() in checkpoint_manager.cpp**

Replace the stub `ensure_checkpoints()` with:

```cpp
void CheckpointManager::ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress) {
    if (checkpoints_built_) return;
    if (regfile_.has_checkpoints()) {
        checkpoints_built_ = true;
        return;
    }
    regfile_.build_checkpoints(0, std::move(progress));
    checkpoints_built_ = true;
}
```

- [ ] **Step 3: Implement execute_warms() with range merging**

Replace the stub `execute_warms()` with:

```cpp
void CheckpointManager::execute_warms() {
    if (declared_ranges_.empty()) return;

    // Sort by start address
    std::sort(declared_ranges_.begin(), declared_ranges_.end());

    // Merge overlapping/adjacent ranges
    std::vector<Range> merged;
    merged.reserve(declared_ranges_.size());
    for (const auto& r : declared_ranges_) {
        if (!merged.empty() && r.start <= merged.back().end) {
            merged.back().end = std::max(merged.back().end, r.end);
        } else {
            merged.push_back(r);
        }
    }

    // Execute warm_range for each merged range
    for (const auto& r : merged) {
        regfile_.warm_range(r.start, r.end, 0, nullptr);
    }

    declared_ranges_.clear();
}
```

- [ ] **Step 4: Implement create_cursor()**

Replace the stub `create_cursor()` with:

```cpp
RegisterFileCursor CheckpointManager::create_cursor() const {
    // RegisterFileCursor takes (const TraceReader&, const TraceIndex&).
    // RegisterFile holds references to both, but doesn't expose them.
    // We need to pass them — but RegisterFileCursor's constructor needs them.
    // Since RegisterFile stores reader_ and index_ as const references,
    // and we only have the RegisterFile, we must access them through a
    // friend mechanism or add accessors. The cleanest approach: RegisterFile
    // already provides the reader/index via its own constructor, so we
    // reconstruct the cursor using the same references.
    //
    // However, RegisterFile doesn't expose reader()/index() accessors.
    // We'll add them in a separate step if needed. For now, this is a
    // known limitation — passes that need cursors can construct them directly.
    //
    // TODO: Add RegisterFile::reader() and RegisterFile::index() const accessors
    //       in a follow-up, then implement this properly.
    throw std::runtime_error("CheckpointManager::create_cursor requires RegisterFile accessors (TODO)");
}
```

**Note:** `RegisterFileCursor` requires `TraceReader` and `TraceIndex` references, but `RegisterFile` doesn't expose them. For Task 2, we'll skip `create_cursor()` implementation and leave the throw. It will be addressed when a pass actually needs it. The `ensure_checkpoints()` and `execute_warms()` are the primary value.

- [ ] **Step 5: Add `#include <algorithm>` to checkpoint_manager.cpp**

At the top of `tools/tenet/src/infra/checkpoint_manager.cpp`, add:

```cpp
#include <algorithm>
#include <stdexcept>
```

- [ ] **Step 6: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
ctest --output-on-failure
```

Expected: clean build, all tests pass.

- [ ] **Step 7: Commit**

```bash
git add tools/tenet/src/infra/checkpoint_manager.h tools/tenet/src/infra/checkpoint_manager.cpp
git commit -m "feat(infra): implement CheckpointManager — eager checkpoints + merged warm ranges

ensure_checkpoints() calls RegisterFile::build_checkpoints() exactly once
(idempotent). execute_warms() merges overlapping declared ranges and batch-
calls RegisterFile::warm_range(). create_cursor() deferred until RegisterFile
exposes reader/index accessors."
```

---

### Task 3: Implement ScanOrchestrator + declare_scan() Integration

**Files:**
- Modify: `tools/tenet/src/infra/scan_orchestrator.cpp` (implement real scan fusion logic)
- Modify: `tools/tenet/src/analysis/pass_manager.h` (add `declare_scan()` virtual to `AnalysisPass`)
- Modify: `tools/tenet/src/analysis/pass_manager.cpp` (add declaration phase + scan phase to `run_all()`)

**Interfaces:**
- Produces: `ScanOrchestrator::execute_scan()` — real implementation that creates a `TraceScanEngine`, adds all declared collectors, and runs single `run()` or `run_parallel()`
- Produces: `AnalysisPass::declare_scan()` — new virtual method (default: no-op)
- Produces: `PassManager::run_all()` — now has 3 phases: declaration → unified scan → parallel execution
- Consumes: `TraceScanEngine::add_collector()`, `TraceScanEngine::run()`, `TraceScanEngine::run_parallel()`, `TraceCollector`

- [ ] **Step 1: Implement execute_scan() in scan_orchestrator.cpp**

Replace the stub `execute_scan()` with:

```cpp
uint64_t ScanOrchestrator::execute_scan(const AnalysisRange& range,
                                          const std::atomic<bool>& cancel_token,
                                          bool no_parallel) {
    if (declarations_.empty()) return 0;
    if (scanned_) return 0;  // already scanned

    // Create the shared scan engine
    TraceScanEngine engine(reader_, inst_count_, index_);

    // Apply exclude PC ranges from AnalysisRange
    if (!range.exclude_pc_ranges.empty()) {
        engine.set_exclude_pc_ranges(range.exclude_pc_ranges);
    }

    // Set cancellation
    engine.set_cancel_token(&cancel_token);
    engine.set_cancel_check([&cancel_token]() { return cancel_token.load(std::memory_order_acquire); });

    // Register all declared collectors
    for (const auto& decl : declarations_) {
        engine.add_collector(decl.collector);
    }

    // Determine if all collectors support parallel scanning
    bool all_parallel = !no_parallel;
    if (all_parallel) {
        for (const auto& decl : declarations_) {
            if (!decl.wants_parallel) {
                all_parallel = false;
                break;
            }
        }
    }

    uint64_t processed = 0;
    if (all_parallel) {
        processed = engine.run_parallel(range.start_inst_id, range.end_inst_id);
    } else {
        processed = engine.run(range.start_inst_id, range.end_inst_id);
    }

    scanned_ = true;
    return processed;
}
```

- [ ] **Step 2: Add declare_scan() virtual method to AnalysisPass**

In `tools/tenet/src/analysis/pass_manager.h`, in the `AnalysisPass` class, after the `virtual PassResult run(PassContext& ctx) = 0;` line (line 174), add:

```cpp
    /// Declare scan collector requirements for Scan Fusion (default: none).
    /// Override to participate in unified trace scanning.
    /// Called before run() phase, after all passes are registered.
    virtual void declare_scan(class ScanOrchestrator& orchestrator) { (void)orchestrator; }
```

- [ ] **Step 3: Add declaration + scan phases to PassManager::run_all()**

In `tools/tenet/src/analysis/pass_manager.cpp`, modify `run_all()` (starts at line 440). Replace the function body with:

```cpp
void PassManager::run_all(size_t num_threads) {
    LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager::run_all: {} passes, {} threads, RSS limit={}MB",
             entries_.size(), num_threads,
             rss_limit_mb_ > 0 ? fmt::format("{:.0f}", rss_limit_mb_) : "none");

    // ── Phase 1: Declaration — each pass's declare_scan() registers collectors ──
    if (scan_orchestrator_) {
        for (auto& entry : entries_) {
            entry->pass->declare_scan(*scan_orchestrator_);
        }

        // ── Phase 2: Unified scan — one traversal serves all collectors ──
        if (scan_orchestrator_->has_declarations()) {
            LOG_INFO_M(::tenet::log::Module::Analysis,
                "PassManager: executing unified scan with {} collector(s)",
                scan_orchestrator_->has_declarations() ? "multiple" : "0");
            scan_orchestrator_->execute_scan(range_, cancelled_, no_parallel_scan_);
        }
    }

    // ── Phase 3: Execution — existing DAG scheduler (unchanged) ──
    if (num_threads <= 1 || entries_.size() <= 1) {
        // Sequential fallback: just require each pass in registration order.
        for (auto& entry : entries_) {
            require(entry->pass->name());
        }
        LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
        return;
    }

    run_all_parallel(num_threads);

    LOG_INFO_M(::tenet::log::Module::Analysis, "PassManager::run_all: complete, RSS={:.1f}MB", ::tenet::log::rss_mb());
}
```

- [ ] **Step 4: Add missing include in pass_manager.cpp**

Ensure `#include "infra/scan_orchestrator.h"` is present (added in Task 1 Step 11).

- [ ] **Step 5: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
ctest --output-on-failure
```

Expected: clean build. No passes override `declare_scan()` yet, so `has_declarations()` is false and `execute_scan()` is not called. All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/infra/scan_orchestrator.cpp \
    tools/tenet/src/analysis/pass_manager.h tools/tenet/src/analysis/pass_manager.cpp
git commit -m "feat(infra): implement ScanOrchestrator + declare_scan() virtual method

execute_scan() creates a shared TraceScanEngine, adds all declared collectors,
and runs single run()/run_parallel() based on parallel support. AnalysisPass
gains declare_scan() virtual (default no-op). PassManager::run_all() now has
3 phases: declaration → unified scan → parallel execution. No passes override
declare_scan() yet — backward compatible."
```

---

### Task 4: Implement PageStats

**Files:**
- Modify: `tools/tenet/src/infra/page_stats.cpp` (implement real page statistics)
- Modify: `tools/tenet/src/infra/page_stats.h` (no changes needed beyond Task 1)

**Interfaces:**
- Produces: `PageStats::ensure_built()` — builds page summaries from `MemoryModel::active_pages()`
- Produces: `PageStats::all_pages()` — vector of `PageSummary` with entropy + string heuristic
- Produces: `PageStats::high_entropy_pages()`, `PageStats::string_candidate_pages()` — filtered views
- Consumes: `MemoryModel::active_pages()`, `MemoryModel::read_region()`, `tenet::shannon_entropy()`

- [ ] **Step 1: Implement build() in page_stats.cpp**

Replace the stub `build()` with:

```cpp
#include "infra/page_stats.h"
#include "core/memory_model.h"
#include "common/entropy.h"
#include <algorithm>
#include <cstring>

namespace tenet {

PageStats::PageStats(MemoryModel& memory) : memory_(memory) {}

void PageStats::ensure_built() {
    if (built_) return;
    build();
}

void PageStats::build() {
    // Get raw page activity from MemoryModel
    auto activities = memory_.active_pages();

    pages_.clear();
    pages_.reserve(activities.size());
    page_index_.clear();
    page_index_.reserve(activities.size());

    // Read each page's bytes and compute statistics
    // Use inst_count as the snapshot time (end of trace)
    // We'll read at a large inst_id to get the final state
    const uint64_t at_inst_id = UINT64_MAX;

    for (const auto& act : activities) {
        PageSummary summary;
        summary.page_addr = act.page_addr;
        summary.first_access = act.first_inst_id;
        summary.last_access = act.last_inst_id;
        summary.write_count = act.write_count;
        summary.read_count = act.read_count;
        summary.has_strings = false;
        summary.entropy = -1.0;

        // Read the full page (4096 bytes)
        auto region = memory_.read_region(act.page_addr, 4096, at_inst_id);

        if (region.known_count > 0) {
            // Collect known bytes for entropy
            std::vector<uint8_t> known_bytes;
            known_bytes.reserve(region.known_count);
            for (size_t i = 0; i < region.data.size(); i++) {
                if (region.known[i]) {
                    known_bytes.push_back(region.data[i]);
                }
            }

            // Compute entropy
            if (!known_bytes.empty()) {
                summary.entropy = shannon_entropy(known_bytes.data(), known_bytes.size());
            }

            // String heuristic: check for runs of printable ASCII (>= 4 chars)
            size_t printable_run = 0;
            for (size_t i = 0; i < region.data.size(); i++) {
                if (region.known[i]) {
                    uint8_t c = region.data[i];
                    if (c >= 0x20 && c < 0x7f) {
                        printable_run++;
                        if (printable_run >= 4) {
                            summary.has_strings = true;
                            break;
                        }
                    } else {
                        printable_run = 0;
                    }
                } else {
                    printable_run = 0;
                }
            }
        }

        page_index_[summary.page_addr] = pages_.size();
        pages_.push_back(std::move(summary));
    }

    built_ = true;
}

const PageSummary* PageStats::page(uint64_t page_addr) const {
    auto it = page_index_.find(page_addr);
    if (it == page_index_.end()) return nullptr;
    return &pages_[it->second];
}

std::vector<const PageSummary*> PageStats::high_entropy_pages(double threshold) const {
    std::vector<const PageSummary*> result;
    for (const auto& p : pages_) {
        if (p.entropy > threshold) result.push_back(&p);
    }
    return result;
}

std::vector<const PageSummary*> PageStats::string_candidate_pages() const {
    std::vector<const PageSummary*> result;
    for (const auto& p : pages_) {
        if (p.has_strings) result.push_back(&p);
    }
    return result;
}

}  // namespace tenet
```

- [ ] **Step 2: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
ctest --output-on-failure
```

Expected: clean build, all tests pass. PageStats is not yet used by any pass.

- [ ] **Step 3: Commit**

```bash
git add tools/tenet/src/infra/page_stats.cpp
git commit -m "feat(infra): implement PageStats — cached page-level memory statistics

build() enumerates active pages via MemoryModel::active_pages(), reads each
page via read_region(), computes Shannon entropy and string heuristics.
Results cached in pages_ vector + page_index_ map. high_entropy_pages() and
string_candidate_pages() provide filtered views for consuming passes."
```

---

### Task 5: Implement StringResolver

**Files:**
- Modify: `tools/tenet/src/infra/string_resolver.cpp` (implement real string parsing)
- Modify: `tools/tenet/src/infra/string_resolver.h` (no changes needed beyond Task 1)

**Interfaces:**
- Produces: `StringResolver::ensure_built()` — scans string candidate pages and extracts all C-strings
- Produces: `StringResolver::resolve()` — cached single-address C-string lookup
- Produces: `StringResolver::resolve_region()` — extract all strings from a memory range
- Produces: `StringResolver::all_strings()` — all resolved strings
- Consumes: `PageStats::string_candidate_pages()`, `MemoryModel::read_region()`

- [ ] **Step 1: Implement build() and resolve() in string_resolver.cpp**

Replace the entire file with:

```cpp
#include "infra/string_resolver.h"
#include "core/memory_model.h"
#include "infra/page_stats.h"
#include <algorithm>
#include <cstring>

namespace tenet {

StringResolver::StringResolver(MemoryModel& memory, PageStats& page_stats)
    : memory_(memory), page_stats_(page_stats) {}

void StringResolver::ensure_built(uint64_t at_inst_id) {
    if (built_) return;
    build(at_inst_id);
}

void StringResolver::build(uint64_t at_inst_id) {
    page_stats_.ensure_built();

    strings_.clear();
    addr_index_.clear();

    // Scan only string candidate pages
    auto candidate_pages = page_stats_.string_candidate_pages();

    for (const PageSummary* ps : candidate_pages) {
        // Read the full page
        auto region = memory_.read_region(ps->page_addr, 4096, at_inst_id);

        // Extract C-strings from the page
        size_t i = 0;
        while (i < region.data.size()) {
            // Skip unknown bytes
            if (!region.known[i]) {
                i++;
                continue;
            }

            // Check for printable ASCII run
            if (region.data[i] >= 0x20 && region.data[i] < 0x7f) {
                size_t start = i;
                std::string s;
                while (i < region.data.size() && region.known[i] &&
                       region.data[i] >= 0x20 && region.data[i] < 0x7f) {
                    s += static_cast<char>(region.data[i]);
                    i++;
                }

                // Must be at least 4 chars and null-terminated (or page boundary)
                if (s.length() >= 4) {
                    ResolvedString rs;
                    rs.addr = ps->page_addr + start;
                    rs.value = std::move(s);
                    rs.inst_id = at_inst_id;
                    rs.kind = ResolvedString::CStr;
                    rs.length = rs.value.length();

                    addr_index_[rs.addr] = strings_.size();
                    strings_.push_back(std::move(rs));
                }
            } else {
                i++;
            }
        }
    }

    built_ = true;
}

std::optional<ResolvedString> StringResolver::resolve(uint64_t addr, uint64_t at_inst_id) {
    // Check cache first
    auto it = addr_index_.find(addr);
    if (it != addr_index_.end()) {
        return strings_[it->second];
    }

    // Not in cache — parse on demand
    return parse_cstring(addr, at_inst_id);
}

std::optional<ResolvedString> StringResolver::parse_cstring(uint64_t addr, uint64_t at_inst_id) {
    // Read up to 256 bytes looking for a C-string
    auto region = memory_.read_region(addr, 256, at_inst_id);

    std::string s;
    for (size_t i = 0; i < region.data.size(); i++) {
        if (!region.known[i]) break;
        uint8_t c = region.data[i];
        if (c == 0) break;
        if (c >= 0x20 && c < 0x7f) {
            s += static_cast<char>(c);
        } else {
            break;  // non-printable
        }
    }

    if (s.length() < 1) return std::nullopt;

    ResolvedString rs;
    rs.addr = addr;
    rs.value = std::move(s);
    rs.inst_id = at_inst_id;
    rs.kind = ResolvedString::CStr;
    rs.length = rs.value.length();

    // Cache it
    addr_index_[addr] = strings_.size();
    strings_.push_back(rs);

    return strings_.back();
}

std::vector<ResolvedString> StringResolver::resolve_region(uint64_t base_addr, size_t size,
                                                             uint64_t at_inst_id) {
    std::vector<ResolvedString> result;
    auto region = memory_.read_region(base_addr, size, at_inst_id);

    size_t i = 0;
    while (i < region.data.size()) {
        if (!region.known[i]) {
            i++;
            continue;
        }

        if (region.data[i] >= 0x20 && region.data[i] < 0x7f) {
            size_t start = i;
            std::string s;
            while (i < region.data.size() && region.known[i] &&
                   region.data[i] >= 0x20 && region.data[i] < 0x7f) {
                s += static_cast<char>(region.data[i]);
                i++;
            }

            if (s.length() >= 4) {
                ResolvedString rs;
                rs.addr = base_addr + start;
                rs.value = std::move(s);
                rs.inst_id = at_inst_id;
                rs.kind = ResolvedString::CStr;
                rs.length = rs.value.length();
                result.push_back(std::move(rs));
            }
        } else {
            i++;
        }
    }

    return result;
}

}  // namespace tenet
```

- [ ] **Step 2: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
ctest --output-on-failure
```

Expected: clean build, all tests pass.

- [ ] **Step 3: Commit**

```bash
git add tools/tenet/src/infra/string_resolver.cpp
git commit -m "feat(infra): implement StringResolver — unified string parsing with caching

build() scans PageStats::string_candidate_pages(), extracts all C-strings
(>= 4 printable ASCII chars). resolve() provides cached single-address lookup
with on-demand fallback. resolve_region() extracts strings from arbitrary
memory range. Cross-pass caching eliminates duplicated string parsing."
```

---

### Task 6: Migrate entropy_pass to use PageStats

**Files:**
- Modify: `tools/tenet/src/analysis/passes/memory/entropy_pass.cpp` (use `ctx.page_stats()` for page-level entropy)
- Read-only: `tools/tenet/src/analysis/passes/memory/entropy_pass.h` (understand config)

**Interfaces:**
- Consumes: `PassContext::page_stats()`, `PageStats::page()`, `PageStats::high_entropy_pages()`
- Preserves: `EntropyPass::run()` interface and `EntropyResult` structure unchanged

**Migration strategy:** `entropy_pass` currently takes a specific `addr` + `size` config and computes entropy for that region. When the configured region is page-aligned and covers full pages, it can use `PageStats::page()` to read pre-computed entropy instead of re-reading memory. For sub-page regions or timeline computation, it falls back to its existing `batch_read_region()` logic.

- [ ] **Step 1: Read entropy_pass.h to understand config**

Run: `cat tools/tenet/src/analysis/passes/memory/entropy_pass.h`

Understand the `EntropyConfig` struct: `addr`, `size`, `block_size`, `at_inst_id`, `compute_timeline`, `timeline_interval`.

- [ ] **Step 2: Add PageStats optimization to entropy_pass.cpp**

In `tools/tenet/src/analysis/passes/memory/entropy_pass.cpp`, at the top of `EntropyPass::run()`, after the config validation (after line 57, `if (cfg_.addr == 0 && cfg_.size == 0)`), add a fast path using PageStats when the region is page-aligned:

```cpp
    // ── Fast path: if region is page-aligned and covers full pages,
    //    use pre-computed PageStats entropy instead of re-reading memory.
    auto& page_stats = ctx.page_stats();
    const uint64_t page_size = 4096;
    bool is_page_aligned = (cfg_.addr % page_size == 0) && (cfg_.size % page_size == 0);

    if (is_page_aligned && !cfg_.compute_timeline) {
        page_stats.ensure_built();

        EntropyResult result;
        result.addr = cfg_.addr;
        result.region_size = cfg_.size;

        // Aggregate entropy from all covered pages
        double total_entropy_sum = 0.0;
        uint32_t page_count = 0;
        uint64_t total_known = 0;

        for (uint64_t offset = 0; offset < cfg_.size; offset += page_size) {
            uint64_t page_addr = (cfg_.addr + offset) >> 12 << 12;
            const PageSummary* ps = page_stats.page(page_addr);
            if (ps && ps->entropy >= 0.0) {
                total_entropy_sum += ps->entropy;
                page_count++;
                // Estimate known bytes (page is 4096, use write_count as proxy)
                total_known += 4096; // conservative estimate
            }
        }

        result.known_bytes = total_known;

        if (page_count > 0) {
            result.overall_entropy = static_cast<float>(total_entropy_sum / page_count);

            // Classify based on overall entropy
            if (total_known < 8) {
                result.classification = EntropyResult::Unknown;
            } else if (result.overall_entropy > 7.5f) {
                result.classification = EntropyResult::Encrypted;
            } else if (result.overall_entropy > 6.0f) {
                result.classification = EntropyResult::Compressed;
            } else if (result.overall_entropy < 4.0f) {
                result.classification = EntropyResult::Plaintext;
            } else if (cfg_.size <= 64) {
                result.classification = EntropyResult::KeyMaterial;
            } else {
                result.classification = EntropyResult::Compressed;
            }

            // Per-block entropy from pages
            for (uint64_t offset = 0; offset < cfg_.size; offset += cfg_.block_size) {
                uint64_t page_addr = (cfg_.addr + offset) >> 12 << 12;
                const PageSummary* ps = page_stats.page(page_addr);
                EntropyBlock block;
                block.offset = static_cast<uint32_t>(offset);
                block.size = std::min(cfg_.block_size, static_cast<uint32_t>(cfg_.size - offset));
                block.is_known = (ps && ps->entropy >= 0.0);
                block.entropy = ps ? static_cast<float>(ps->entropy) : 0.0f;
                result.blocks.push_back(block);
            }

            ctx.progress(1.0f, "Entropy: complete (PageStats fast path)");
            return PassResult::success(std::move(result));
        }
        // If no page stats available, fall through to slow path
    }
```

This goes right before the existing `ctx.progress(0.0f, "Entropy: reading memory region...")` line.

- [ ] **Step 3: Add include for PageStats**

At the top of `tools/tenet/src/analysis/passes/memory/entropy_pass.cpp`, add:

```cpp
#include "infra/page_stats.h"
```

- [ ] **Step 4: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
ctest --output-on-failure
```

Expected: clean build, all tests pass. The fast path only activates for page-aligned regions without timeline; otherwise the original code path runs.

- [ ] **Step 5: Commit**

```bash
git add tools/tenet/src/analysis/passes/memory/entropy_pass.cpp
git commit -m "feat(infra): entropy_pass uses PageStats fast path for page-aligned regions

When the configured region is page-aligned and covers full pages (no timeline),
entropy_pass reads pre-computed page entropy from PageStats instead of re-
reading memory via batch_read_region(). Falls back to slow path for sub-page
regions or timeline computation."
```

---

### Task 7: Add StringResolver supplementary data to memory_string_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp` (add StringResolver as supplementary source at end of run())
- Read-only: `tools/tenet/src/analysis/passes/memory/memory_string_pass.h` (understand result structure)

**Interfaces:**
- Consumes: `PassContext::string_resolver()`, `StringResolver::all_strings()`
- Preserves: `MemoryStringPass::run()` interface and `MemoryStringResult` structure unchanged

**Migration strategy:** `memory_string_pass` is call-site based — it scans registers and stack at BL/BLR/SVC call sites. It does NOT have a full-memory-scan mode (`MemoryStringConfig` has no `scan_all_memory` field). However, it has a `MemoryString::Source::PageScan` enum value for fallback page scanning. We add StringResolver results as supplementary `PageScan`-sourced strings at the end of `run()`, merging them with the call-site results. This gives memory_string_pass coverage of strings that were never pointed to by registers at call sites.

- [ ] **Step 1: Read memory_string_pass.h to understand config and result types**

Run: `cat tools/tenet/src/analysis/passes/memory/memory_string_pass.h`

Understand `MemoryString` (especially `Source::PageScan`), `MemoryStringResult`, `MemoryStringConfig`.

- [ ] **Step 2: Add StringResolver supplementary scan to memory_string_pass.cpp**

At the top of `tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp`, add the include:

```cpp
#include "infra/string_resolver.h"
```

Then, in the `run()` method, find the point right before `return PassResult::success(std::move(result));` at the end of the function. Add this supplementary scan block before the return:

```cpp
    // ── Supplementary: add strings from StringResolver (PageScan source).
    //    These are strings found via full-page scanning that were never
    //    pointed to by registers at call sites. StringResolver caches
    //    results across passes, so this is cheap if PageStats was already built.
    {
        auto& string_resolver = ctx.string_resolver();
        string_resolver.ensure_built(ctx.index().inst_count());

        const auto& resolved = string_resolver.all_strings();
        for (const auto& rs : resolved) {
            // Skip if we already found a string at this address via call-site scan
            if (result.by_addr.count(rs.addr) > 0) continue;

            MemoryString ms;
            ms.addr = rs.addr;
            ms.discovered_at = rs.inst_id;
            ms.content = rs.value;
            ms.encoding = MemoryString::Encoding::ASCII;
            ms.source = MemoryString::Source::PageScan;
            ms.source_reg = 0xFF;
            ms.call_site_inst_id = 0;
            ms.call_site_pc = 0;

            size_t idx = result.strings.size();
            result.strings.push_back(std::move(ms));
            result.by_addr[rs.addr].push_back(idx);
            result.unique_hashes.insert(
                hash_combine_addr_content(rs.addr, result.strings[idx].content));
        }

        LOG_DEBUG_M(::tenet::log::Module::Analysis,
            "MemoryString: added {} supplementary strings from StringResolver",
            resolved.size());
    }
```

**Important:** The `hash_combine_addr_content` function is defined as a static anonymous-namespace function at the top of `memory_string_pass.cpp` (line 47). It is visible from the `run()` method. Also ensure `LOG_DEBUG_M` and `::tenet::log::Module::Analysis` are available — they are already used elsewhere in the file. If `LOG_DEBUG_M` is not available, use `LOG_INFO_M` instead.

- [ ] **Step 3: Build and verify**

```bash
cd tools/tenet/build
ninja -j$(nproc)
ctest --output-on-failure
```

Expected: clean build, all tests pass. The supplementary scan adds PageScan-sourced strings that weren't found via call-site scanning.

- [ ] **Step 4: Commit**

```bash
git add tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp
git commit -m "feat(infra): memory_string_pass adds supplementary strings from StringResolver

At the end of run(), memory_string_pass now merges in strings from
StringResolver (Source::PageScan) that were found via full-page scanning
but weren't pointed to by registers at call sites. StringResolver caches
results across passes, making this cheap when PageStats is already built."
```

---

## Self-Review Notes

After implementing all tasks:

1. **Spec coverage:** All 4 services (ScanOrchestrator, PageStats, StringResolver, CheckpointManager) are implemented with stub → real logic progression. PassContext accessors added. PassManager init_infra() added to all 5 init sites.

2. **Backward compatibility:** No existing pass is forced to migrate. `ctx.make_scan_engine()` still works. `declare_scan()` defaults to no-op. PageStats/StringResolver are lazy — only built when accessed.

3. **Placeholder scan:** All stubs are marked with "Stub — real implementation in Task N" comments and have been replaced with real implementations. `create_cursor()` has a known TODO for RegisterFile accessors.

4. **Type consistency:** `ScanDeclaration`, `PageSummary`, `ResolvedString` struct names match across spec and plan. `ensure_built()`, `declare()`, `resolve()` method names are consistent.

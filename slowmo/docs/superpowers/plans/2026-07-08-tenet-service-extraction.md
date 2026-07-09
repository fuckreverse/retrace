# TenetService Extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract a `TenetService` class from `GuiApp`/`TuiApp`/`batch_analysis` that encapsulates all shared application state (navigation, pass results, row cache, bookmarks) and backend access, leaving frontends as pure rendering shells.

**Architecture:** `TenetService` owns PassManager, instruction row cache, navigation state (current_inst, history, bookmarks, search), and all pass result pointers. GUI/TUI/MCP/CLI consume it through a single public API. An observer pattern (`TenetServiceObserver`) notifies frontends of state changes (pass completed, navigation, bookmark toggle). `TuiContext` becomes a thin adapter; `GuiApp` drops ~60% of its data members.

**Tech Stack:** C++20, CMake/Ninja, Catch2 (unit tests)

## Global Constraints

- Build targets: `tenet_lib` (backend + TenetService), `tenet_gui_lib` (GUI), `tenet` (executable)
- **Never** create new `build-xxx` directories or delete `_deps/`
- All new files under `src/service/` directory
- Incremental: each task produces a compiling, passing build; no big-bang refactor
- Existing tests (`ctest`) must stay green after every task
- GuiApp/TuiApp/batch_analysis must produce identical runtime behavior throughout

---

### Task 1: Create TenetService Header with Core API Surface

**Files:**
- Create: `tools/tenet/src/service/tenet_service.h`
- Create: `tools/tenet/src/service/tenet_service.cpp`
- Modify: `tools/tenet/CMakeLists.txt` (add to `tenet_lib` sources)
- Test: `tools/tenet/tests/test_tenet_service.cpp` (if test target exists); otherwise verified by `ninja` compile + existing ctest

**Interfaces:**
- Produces: `TenetService` class with constructor, `fetch_row()`, `navigate_to()`, `current_inst()`, `total_inst()`, observer registration
- Produces: `TenetServiceObserver` abstract base class

This task defines the skeleton. No frontend is changed yet.

- [ ] **Step 1: Create `src/service/tenet_service.h`**

```cpp
// tools/tenet/src/service/tenet_service.h
#pragma once

#include "common/types.h"
#include "common/instruction_row.h"
#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace tenet {

// Forward declarations
class TraceReader;
class TraceIndex;
class CodeTable;
class InstructionDecoder;
class RegisterFile;
class MemoryModel;
class TenetMcpService;
class BreakpointEngine;

// ─── Observer ────────────────────────────────────────────────────────────────

/// Frontends implement this to receive state-change notifications.
/// All callbacks are invoked on the thread that triggered the change
/// (may be a background analysis thread). Implementations must be
/// thread-safe or post to their own event loop.
class TenetServiceObserver {
public:
    virtual ~TenetServiceObserver() = default;

    /// A pass has completed (or failed). `name` is the pass key (e.g. "xref").
    virtual void on_pass_completed(std::string_view name) {}

    /// The cursor moved to a new instruction.
    virtual void on_navigation(uint64_t inst_id) {}

    /// A bookmark was toggled (added or removed).
    virtual void on_bookmark_changed() {}
};

// ─── TenetService ────────────────────────────────────────────────────────────

/// Central application-state manager shared by all frontends.
///
/// Owns: PassManager, instruction row cache, navigation state (cursor,
/// history, bookmarks, search), and typed pass-result pointers.
///
/// Does NOT own the backend objects (TraceReader, TraceIndex, RegisterFile,
/// MemoryModel, CodeTable, InstructionDecoder) — those are created in
/// main() and passed by reference.
class TenetService {
public:
    TenetService(TraceReader& reader,
                 TraceIndex& index,
                 CodeTable& code_table,
                 InstructionDecoder& decoder,
                 RegisterFile& regfile,
                 MemoryModel& memory,
                 const std::string& trace_path = {});

    ~TenetService();

    // Non-copyable, non-movable
    TenetService(const TenetService&) = delete;
    TenetService& operator=(const TenetService&) = delete;

    // ── Backend accessors (for panels that need direct access) ───────────
    TraceReader&        reader()  { return reader_; }
    TraceIndex&         index()   { return index_; }
    CodeTable&          code_table() { return code_table_; }
    InstructionDecoder& decoder() { return decoder_; }
    RegisterFile&       regfile() { return regfile_; }
    MemoryModel&        memory()  { return memory_; }
    const std::string&  trace_path() const { return trace_path_; }

    // ── Navigation ──────────────────────────────────────────────────────
    uint64_t current_inst() const { return current_inst_; }
    uint64_t total_inst()   const { return total_inst_; }

    void navigate_to(uint64_t inst_id);

    void nav_back();
    void nav_forward();
    bool can_nav_back() const;
    bool can_nav_forward() const;

    // ── Bookmarks ───────────────────────────────────────────────────────
    const std::vector<uint64_t>& bookmarks() const { return bookmarks_; }
    void toggle_bookmark(uint64_t inst_id);
    bool has_bookmark(uint64_t inst_id) const;

    // ── Instruction row fetching (cached) ───────────────────────────────
    InstructionRow fetch_row(uint64_t inst_id);

    // ── Pass management ─────────────────────────────────────────────────

    /// Ensure PassManager is created and wired to backend objects.
    /// Idempotent — safe to call multiple times.
    PassManager& ensure_pass_manager();

    /// Run the curated default startup passes (async-friendly).
    void run_default_passes();

    /// Run a single pass by name, deriving config from current cursor.
    /// Returns true if the pass completed successfully.
    bool run_pass(std::string_view name, const PassRunCtx& ctx = {});

    /// Access the underlying PassManager (may be nullptr if not yet created).
    PassManager* pass_manager() { return pass_manager_.get(); }

    // ── Typed pass result accessors ─────────────────────────────────────
    // Each returns nullptr if the pass has not run or failed.
    // The returned pointer is valid until the pass is invalidated.
    // Callers should NOT cache these across pass re-runs; prefer
    // calling the accessor each time.

    template<typename T>
    const T* pass_result(std::string_view name) const {
        auto it = pinned_results_.find(std::string(name));
        if (it == pinned_results_.end() || !it->second || !it->second->ok())
            return nullptr;
        return &it->second->get<T>();
    }

    /// Pin a pass result (keep it alive via shared_ptr) and return
    /// a typed pointer to its data.  Returns nullptr on failure.
    template<typename T>
    const T* pin_pass_result(std::string_view name) {
        if (!pass_manager_) return nullptr;
        auto sp = pass_manager_->require_shared(name);
        if (!sp || !sp->ok()) return nullptr;
        pinned_results_[std::string(name)] = sp;
        const T* ptr = &sp->get<T>();
        notify_pass_completed(name);
        return ptr;
    }

    /// Clear all pinned pass results.
    void clear_analysis();

    // ── Search ──────────────────────────────────────────────────────────
    const std::vector<uint64_t>& search_results() const { return search_results_; }
    size_t search_current() const { return search_current_; }
    bool search_active() const { return search_active_; }

    void search_forward(const std::string& query, uint64_t from_inst);
    void search_clear();

    // ── Observer management ─────────────────────────────────────────────
    void add_observer(TenetServiceObserver* obs);
    void remove_observer(TenetServiceObserver* obs);

private:
    // ── Notification helpers ────────────────────────────────────────────
    void notify_navigation(uint64_t inst_id);
    void notify_pass_completed(std::string_view name);
    void notify_bookmark_changed();

    // ── Navigation history ──────────────────────────────────────────────
    void nav_push(uint64_t inst_id);
    static constexpr size_t kMaxNavHistory = 64;
    std::vector<uint64_t> nav_history_;
    size_t nav_history_pos_ = 0;
    bool nav_history_navigating_ = false;

    // ── Backend references (non-owning) ─────────────────────────────────
    TraceReader& reader_;
    TraceIndex& index_;
    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile& regfile_;
    MemoryModel& memory_;
    std::string trace_path_;

    // ── Application state ───────────────────────────────────────────────
    uint64_t total_inst_ = 0;
    uint64_t current_inst_ = 0;
    std::vector<uint64_t> bookmarks_;

    // ── Row cache ───────────────────────────────────────────────────────
    LRUCache<uint64_t, InstructionRow> row_cache_{4096};

    // ── Pass engine ─────────────────────────────────────────────────────
    std::unique_ptr<PassManager> pass_manager_;

    // Keeps pass results alive (thread-safe shared_ptr ownership).
    std::unordered_map<std::string, std::shared_ptr<const PassResult>> pinned_results_;

    // ── Search state ────────────────────────────────────────────────────
    std::vector<uint64_t> search_results_;
    size_t search_current_ = 0;
    bool search_active_ = false;

    // ── Observers ───────────────────────────────────────────────────────
    mutable std::mutex observers_mutex_;
    std::vector<TenetServiceObserver*> observers_;
};

}  // namespace tenet
```

- [ ] **Step 2: Create `src/service/tenet_service.cpp`**

```cpp
// tools/tenet/src/service/tenet_service.cpp
#include "service/tenet_service.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"

#include <algorithm>

namespace tenet {

// ─── Construction / Destruction ─────────────────────────────────────────────

TenetService::TenetService(TraceReader& reader,
                           TraceIndex& index,
                           CodeTable& code_table,
                           InstructionDecoder& decoder,
                           RegisterFile& regfile,
                           MemoryModel& memory,
                           const std::string& trace_path)
    : reader_(reader), index_(index), code_table_(code_table),
      decoder_(decoder), regfile_(regfile), memory_(memory),
      trace_path_(trace_path.empty() ? reader.path() : trace_path) {
    total_inst_ = index.inst_count();

    // Restore persisted state from RocksDB
    bookmarks_ = index_.load_bookmarks();
    uint64_t last = index_.load_last_inst();
    if (last > 0 && last < total_inst_) {
        current_inst_ = last;
    }
}

TenetService::~TenetService() {
    // Persist cursor position for "continue where you left off"
    index_.save_last_inst(current_inst_);
}

// ─── Navigation ─────────────────────────────────────────────────────────────

void TenetService::navigate_to(uint64_t inst_id) {
    if (inst_id >= total_inst_) inst_id = total_inst_ - 1;
    current_inst_ = inst_id;
    if (!nav_history_navigating_) {
        nav_push(inst_id);
    }
    notify_navigation(inst_id);
}

void TenetService::nav_push(uint64_t inst_id) {
    // Truncate forward history if we navigated backward then somewhere new
    if (nav_history_pos_ + 1 < nav_history_.size()) {
        nav_history_.resize(nav_history_pos_ + 1);
    }
    nav_history_.push_back(inst_id);
    if (nav_history_.size() > kMaxNavHistory) {
        nav_history_.erase(nav_history_.begin());
    }
    nav_history_pos_ = nav_history_.size() - 1;
}

void TenetService::nav_back() {
    if (!can_nav_back()) return;
    nav_history_navigating_ = true;
    nav_history_pos_--;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

void TenetService::nav_forward() {
    if (!can_nav_forward()) return;
    nav_history_navigating_ = true;
    nav_history_pos_++;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

bool TenetService::can_nav_back() const {
    return nav_history_pos_ > 0;
}

bool TenetService::can_nav_forward() const {
    return nav_history_pos_ + 1 < nav_history_.size();
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

void TenetService::toggle_bookmark(uint64_t inst_id) {
    auto it = std::find(bookmarks_.begin(), bookmarks_.end(), inst_id);
    if (it != bookmarks_.end()) {
        bookmarks_.erase(it);
    } else {
        bookmarks_.push_back(inst_id);
    }
    index_.save_bookmarks(bookmarks_);
    notify_bookmark_changed();
}

bool TenetService::has_bookmark(uint64_t inst_id) const {
    return std::find(bookmarks_.begin(), bookmarks_.end(), inst_id) != bookmarks_.end();
}

// ─── Instruction row fetching ───────────────────────────────────────────────

InstructionRow TenetService::fetch_row(uint64_t inst_id) {
    // Check cache first
    auto cached = row_cache_.get(inst_id);
    if (cached) return cached->get();

    // Build row from backend
    InstructionRow row{};
    row.inst_id = inst_id;

    auto [offset, seed_pc] = index_.offset_of_with_pc(inst_id, reader_);
    if (offset == 0) return row;

    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind != RecordKind::Inst) return row;

    auto inst = rec.as_inst();
    row.pc = inst.pc;
    row.static_pc = inst.pc - reader_.header().module_slide;
    row.nzcv = inst.nzcv;
    row.reg_diff_count = inst.n_regdiff;
    row.mem_access_count = inst.n_memacc;
    row.has_bookmark = has_bookmark(inst_id);

    // Decode instruction
    auto opcode = code_table_.opcode_at(inst.pc);
    if (opcode) {
        auto decoded = decoder_.decode(inst.pc, *opcode);
        if (decoded) {
            row.disasm = decoded->disasm;
            row.mnemonic = decoded->mnemonic;
            row.operands = decoded->operands;
        }
    }

    row_cache_.put(inst_id, row);
    return row;
}

// ─── Pass management ────────────────────────────────────────────────────────

PassManager& TenetService::ensure_pass_manager() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }
    return *pass_manager_;
}

void TenetService::run_default_passes() {
    auto& pm = ensure_pass_manager();
    register_default_passes(pm);
    for (auto name : default_ui_pass_names()) {
        auto sp = pm.require_shared(name);
        if (sp && sp->ok()) {
            pinned_results_[std::string(name)] = sp;
            notify_pass_completed(name);
        }
    }
}

bool TenetService::run_pass(std::string_view name, const PassRunCtx& ctx) {
    auto& pm = ensure_pass_manager();
    if (!register_pass_by_name(pm, name, ctx)) return false;
    auto sp = pm.require_shared(name);
    if (!sp || !sp->ok()) return false;
    pinned_results_[std::string(name)] = sp;
    notify_pass_completed(name);
    return true;
}

void TenetService::clear_analysis() {
    pinned_results_.clear();
    if (pass_manager_) {
        pass_manager_->cancel_all();
        pass_manager_->invalidate_all();
    }
}

// ─── Search ─────────────────────────────────────────────────────────────────

void TenetService::search_forward(const std::string& query, uint64_t from_inst) {
    search_results_.clear();
    search_current_ = 0;
    if (query.empty()) {
        search_active_ = false;
        return;
    }
    search_active_ = true;

    // Simple linear search through instruction disassembly
    for (uint64_t i = from_inst; i < total_inst_ && search_results_.size() < 10000; ++i) {
        auto row = fetch_row(i);
        if (row.disasm.find(query) != std::string::npos) {
            search_results_.push_back(i);
        }
    }
    // Wrap around
    for (uint64_t i = 0; i < from_inst && search_results_.size() < 10000; ++i) {
        auto row = fetch_row(i);
        if (row.disasm.find(query) != std::string::npos) {
            search_results_.push_back(i);
        }
    }
}

void TenetService::search_clear() {
    search_results_.clear();
    search_current_ = 0;
    search_active_ = false;
}

// ─── Observers ──────────────────────────────────────────────────────────────

void TenetService::add_observer(TenetServiceObserver* obs) {
    std::lock_guard lock(observers_mutex_);
    observers_.push_back(obs);
}

void TenetService::remove_observer(TenetServiceObserver* obs) {
    std::lock_guard lock(observers_mutex_);
    observers_.erase(std::remove(observers_.begin(), observers_.end(), obs), observers_.end());
}

void TenetService::notify_navigation(uint64_t inst_id) {
    std::lock_guard lock(observers_mutex_);
    for (auto* obs : observers_) obs->on_navigation(inst_id);
}

void TenetService::notify_pass_completed(std::string_view name) {
    std::lock_guard lock(observers_mutex_);
    for (auto* obs : observers_) obs->on_pass_completed(name);
}

void TenetService::notify_bookmark_changed() {
    std::lock_guard lock(observers_mutex_);
    for (auto* obs : observers_) obs->on_bookmark_changed();
}

}  // namespace tenet
```

- [ ] **Step 3: Add to CMakeLists.txt**

In `tools/tenet/CMakeLists.txt`, add `src/service/tenet_service.cpp` to the `tenet_lib` sources list (after the last `src/tui/` entry):

```cmake
    src/tui/panels/results_panel.cpp
    src/service/tenet_service.cpp
)
```

- [ ] **Step 4: Build to verify compilation**

```bash
cd tools/tenet/build && ninja -j$(nproc)
```

Expected: Compiles cleanly. No test failures.

- [ ] **Step 5: Run existing tests**

```bash
cd tools/tenet/build && ctest --output-on-failure
```

Expected: All existing tests pass (TenetService is defined but not yet used by any frontend).

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/service/tenet_service.h \
        tools/tenet/src/service/tenet_service.cpp \
        tools/tenet/CMakeLists.txt
git commit -m "feat(tenet): add TenetService skeleton — shared application state layer

Extract the core application-state API (navigation, bookmarks, row cache,
pass management, observer pattern) into TenetService.  No frontend uses
it yet — this commit establishes the interface and verifies it compiles."
```

---

### Task 2: Wire TenetService into main.cpp and TuiApp

**Files:**
- Modify: `tools/tenet/src/main.cpp` — create `TenetService` and pass it to frontends
- Modify: `tools/tenet/src/tui/tui_app.h` — accept `TenetService&` instead of 6 raw refs
- Modify: `tools/tenet/src/tui/tui_app.cpp` — delegate fetch_row/navigate_to/bookmarks/pass management to service
- Modify: `tools/tenet/src/tui/tui_context.h` — add `TenetService*` field

**Interfaces:**
- Consumes: `TenetService` from Task 1
- Produces: `TuiApp` that works identically to before but delegates to `TenetService`

The key strategy: **dual-path migration**. `TuiApp` keeps its old backend references but routes through `TenetService` for shared-state operations. Old code paths still compile; we migrate method by method.

- [ ] **Step 1: Add `TenetService&` to TuiApp constructor (keep old refs as fallback)**

In `tui_app.h`, add a `TenetService* service_` member and a constructor overload:

```cpp
// New constructor — preferred
TuiApp(TenetService& service);

// Old constructor — still compiles for backward compat during migration
TuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
       InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory);
```

In `tui_app.cpp`, implement the new constructor that delegates backend references from `service`:
```cpp
TuiApp::TuiApp(TenetService& service)
    : reader_(service.reader()), index_(service.index()),
      code_table_(service.code_table()), decoder_(service.decoder()),
      regfile_(service.regfile()), memory_(service.memory()),
      service_(&service) {
    // ... same body as old constructor, but use service_ for shared state
    total_inst_ = service_->total_inst();
    current_inst_ = service_->current_inst();
    bookmarks_ = service_->bookmarks();  // copy initial state
    // ... rest of init
}
```

- [ ] **Step 2: Add `TenetService*` to `TuiContext`**

In `tui_context.h`:
```cpp
/// If non-null, the shared application service. Panels can use this for
/// navigation and data access instead of raw backend pointers.
TenetService* service = nullptr;
```

- [ ] **Step 3: Delegate `TuiApp::fetch_row` to `TenetService::fetch_row`**

In `tui_app.cpp`, change the `fetch_row` implementation:
```cpp
InstructionRow TuiApp::fetch_row(uint64_t inst_id) {
    if (service_) return service_->fetch_row(inst_id);
    // ... old implementation as fallback
}
```

- [ ] **Step 4: Delegate `TuiApp::navigate_to` to `TenetService::navigate_to`**

In `tui_app.cpp`:
```cpp
void TuiApp::navigate_to(uint64_t inst_id) {
    if (service_) {
        service_->navigate_to(inst_id);
        current_inst_ = service_->current_inst();
        // sync viewport
        if (inst_id < viewport_top_ || inst_id >= viewport_top_ + viewport_height_)
            viewport_top_ = (inst_id > 5) ? inst_id - 5 : 0;
        return;
    }
    // ... old implementation
}
```

- [ ] **Step 5: Delegate `ensure_pass_manager` to TenetService**

In `tui_app.cpp`:
```cpp
void TuiApp::ensure_pass_manager() {
    if (service_) {
        pass_manager_.reset();  // don't own our own
        // Use service's PassManager
        return;
    }
    // ... old code
}
```

And update `run_default_analysis()` and `run_pass_by_name()` to use `service_->ensure_pass_manager()` / `service_->pass_manager()` when `service_` is available.

- [ ] **Step 6: Update main.cpp to create TenetService**

```cpp
// After MemoryModel construction:
TenetService service(reader, index, code_table, decoder, regfile, memory, opts.trace_path);

// Replace:
//   TuiApp app(reader, index, code_table, decoder, regfile, memory);
// With:
TuiApp app(service);
```

Keep the old constructor call for GUI (Task 3 will migrate GUI).

- [ ] **Step 7: Build and test**

```bash
cd tools/tenet/build && ninja -j$(nproc)
```

Expected: Compiles. TUI launches and works identically.

- [ ] **Step 8: Run TUI smoke test**

If a test trace file is available, launch TUI mode and verify: navigation (j/k/G/gg), bookmarks (B), search (/), pass execution (:run xref).

- [ ] **Step 9: Commit**

```bash
git add tools/tenet/src/main.cpp \
        tools/tenet/src/tui/tui_app.h \
        tools/tenet/src/tui/tui_app.cpp \
        tools/tenet/src/tui/tui_context.h
git commit -m "refactor(tui): wire TuiApp through TenetService

TuiApp now accepts TenetService& and delegates fetch_row, navigate_to,
bookmarks, and pass management to the shared service layer.  Old
constructor is retained for backward compat during migration."
```

---

### Task 3: Wire TenetService into GuiApp

**Files:**
- Modify: `tools/tenet/src/gui/gui_app.h` — accept `TenetService&`, remove duplicated state
- Modify: `tools/tenet/src/gui/gui_app.mm` — new constructor, delegate to service
- Modify: `tools/tenet/src/gui/navigation.cpp` — delegate nav/fetch to service
- Modify: `tools/tenet/src/main.cpp` — pass service to GuiApp

**Interfaces:**
- Consumes: `TenetService` from Task 1
- Produces: `GuiApp` that delegates shared state to `TenetService`

Strategy: same dual-path migration. `GuiApp` gains a `TenetService* service_` member. Navigation, bookmarks, row cache, PassManager lifecycle delegate to service. GUI-only state (panel visibility, rendering caches, filter buffers, Metal state) stays in GuiApp.

- [ ] **Step 1: Add `TenetService* service_` to `GuiApp`**

In `gui_app.h`, add near the top of the private members section:
```cpp
TenetService* service_ = nullptr;
```

And add a new constructor overload:
```cpp
GuiApp(TenetService& service, const std::filesystem::path& trace_path = {});
```

- [ ] **Step 2: Implement new constructor in gui_app.mm**

```cpp
GuiApp::GuiApp(TenetService& service, const std::filesystem::path& trace_path)
    : reader_(service.reader()), index_(service.index()),
      code_table_(service.code_table()), decoder_(service.decoder()),
      regfile_(service.regfile()), memory_(service.memory()),
      trace_path_(trace_path.empty() ? service.trace_path() : trace_path.string()),
      service_(&service) {
    total_inst_ = service_->total_inst();
    current_inst_ = service_->current_inst();
    bookmarks_ = service_->bookmarks();

    vm_profiles_ = VMProfiles::load();
    restore_vm_profile();
}
```

- [ ] **Step 3: Delegate fetch_row to service in navigation.cpp**

At the top of `GuiApp::fetch_row()`:
```cpp
InstructionRow GuiApp::fetch_row(uint64_t inst_id) {
    if (service_) return service_->fetch_row(inst_id);
    // ... existing implementation
}
```

- [ ] **Step 4: Delegate navigate_to to service in navigation.cpp**

```cpp
void GuiApp::navigate_to(uint64_t inst_id) {
    if (service_) {
        service_->navigate_to(inst_id);
        current_inst_ = service_->current_inst();
        scroll_to_current_ = true;
        return;
    }
    // ... existing implementation
}
```

Do the same for `nav_back()`, `nav_forward()`, `toggle_bookmark()`.

- [ ] **Step 5: Delegate PassManager to service**

In the GUI's `ensure_pass_manager()` (in `panels_analysis.cpp` or wherever it is):
```cpp
if (service_) {
    if (!pass_manager_) {
        // Borrow from service
        pass_manager_.reset();
    }
    return service_->ensure_pass_manager();
}
```

This is the trickiest part — the GUI's async analysis thread posts results via `post_apply()`. For now, keep the GUI's own async machinery but have it call `service_->pin_pass_result()` when applying results. This preserves existing thread-safety guarantees.

- [ ] **Step 6: Update main.cpp to pass service to GuiApp**

```cpp
#if TENET_HAS_GUI
    if (!opts.force_tui) {
        GuiApp gui(service, opts.trace_path);
        gui.set_vm_paths(opts.vm_hints_file, opts.vm_decoder_file);
        return gui.run();
    }
#endif
```

- [ ] **Step 7: Build and test**

```bash
cd tools/tenet/build && ninja -j$(nproc)
```

Expected: Compiles. GUI launches and works identically.

- [ ] **Step 8: Smoke test GUI**

Launch with a test trace. Verify: instruction scrolling, register panel, memory panel, bookmarks (Ctrl+B/Cmd+B), navigation history (back/forward), CFG view, xref analysis.

- [ ] **Step 9: Commit**

```bash
git add tools/tenet/src/gui/gui_app.h \
        tools/tenet/src/gui/gui_app.mm \
        tools/tenet/src/gui/navigation.cpp \
        tools/tenet/src/main.cpp
git commit -m "refactor(gui): wire GuiApp through TenetService

GuiApp now delegates navigation, fetch_row, bookmarks, and pass
management to TenetService.  Async analysis machinery is preserved;
results are pinned through the service for thread-safe lifetime."
```

---

### Task 4: Wire TenetService into batch_analysis

**Files:**
- Modify: `tools/tenet/src/batch_analysis.h` — accept `TenetService&`
- Modify: `tools/tenet/src/batch_analysis.cpp` — use service for PassManager
- Modify: `tools/tenet/src/main.cpp` — pass service to batch_analysis

**Interfaces:**
- Consumes: `TenetService` from Task 1
- Produces: `run_batch_analysis` that uses service's PassManager

- [ ] **Step 1: Add TenetService overload to batch_analysis.h**

```cpp
int run_batch_analysis(const CliOptions& opts, TenetService& service);
```

- [ ] **Step 2: Implement in batch_analysis.cpp**

```cpp
int run_batch_analysis(const CliOptions& opts, TenetService& service) {
    auto& reader = service.reader();
    auto& index = service.index();
    auto& code_table = service.code_table();
    auto& decoder = service.decoder();
    auto& regfile = service.regfile();
    auto& memory = service.memory();

    // Use service's PassManager instead of creating a local one
    auto& pm = service.ensure_pass_manager();

    // ... rest of the function is unchanged (pass registration + result extraction)
}
```

Alternatively, implement by calling the existing function:
```cpp
int run_batch_analysis(const CliOptions& opts, TenetService& service) {
    return run_batch_analysis(opts, service.reader(), service.index(),
                              service.code_table(), service.decoder(),
                              service.regfile(), service.memory());
}
```

The second approach is simpler for Task 4 and preserves the existing code path exactly. The batch path can be further unified later.

- [ ] **Step 3: Update main.cpp**

```cpp
if (has_analysis_option) {
    return tenet::run_batch_analysis(opts, service);
}
```

- [ ] **Step 4: Build and test**

```bash
cd tools/tenet/build && ninja -j$(nproc) && ctest --output-on-failure
```

Expected: All existing tests pass. CLI batch analysis works identically.

- [ ] **Step 5: Commit**

```bash
git add tools/tenet/src/batch_analysis.h \
        tools/tenet/src/batch_analysis.cpp \
        tools/tenet/src/main.cpp
git commit -m "refactor(cli): wire batch_analysis through TenetService

CLI batch path now accepts TenetService&, unifying backend object
lifecycle with GUI/TUI.  Existing 6-ref overload preserved."
```

---

### Task 5: Wire TenetService into MCP server

**Files:**
- Modify: `tools/tenet/src/io/mcp/mcp_server.h` — add constructor from TenetService&
- Modify: `tools/tenet/src/io/mcp/mcp_server.cpp` — implement new constructor
- Modify: `tools/tenet/src/main.cpp` (MCP path, if separate from GUI)
- Modify: `tools/tenet/src/gui/gui_app.mm` (in-GUI MCP startup)

**Interfaces:**
- Consumes: `TenetService` from Task 1
- Produces: `TenetMcpService` constructable from `TenetService&`

- [ ] **Step 1: Add TenetService constructor to TenetMcpService**

In `mcp_server.h`:
```cpp
/// Construct from TenetService — uses service's backend refs and PassManager.
TenetMcpService(TenetService& service);
```

- [ ] **Step 2: Implement it in mcp_server.cpp**

```cpp
TenetMcpService::TenetMcpService(TenetService& service)
    : reader_(service.reader()), index_(service.index()),
      regfile_(service.regfile()), memory_(service.memory()),
      pm_(&service.ensure_pass_manager()),
      code_table_(&service.code_table()),
      decoder_(&service.decoder()) {
    register_all_tools();
}
```

- [ ] **Step 3: Update GUI's MCP auto-start to use service if available**

In `gui_app.mm` or `panels_misc.cpp` (wherever `auto_start_mcp()` lives):
```cpp
if (service_) {
    mcp_service_ = std::make_unique<TenetMcpService>(*service_);
} else {
    mcp_service_ = std::make_unique<TenetMcpService>(reader_, index_, regfile_, memory_,
                                                      pass_manager_.get(), &code_table_, &decoder_);
}
```

- [ ] **Step 4: Update main.cpp MCP path (if CLI --mcp mode exists)**

If `main.cpp` has a standalone MCP launch path, update it to use `TenetService`.

- [ ] **Step 5: Build, test, and verify MCP startup**

```bash
cd tools/tenet/build && ninja -j$(nproc)
```

Launch GUI with MCP auto-start enabled and verify the MCP server responds to `tools/list`.

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/io/mcp/mcp_server.h \
        tools/tenet/src/io/mcp/mcp_server.cpp \
        tools/tenet/src/gui/gui_app.mm \
        tools/tenet/src/main.cpp
git commit -m "refactor(mcp): TenetMcpService constructable from TenetService

MCP server can now be created from TenetService&, sharing the same
PassManager instance used by GUI/TUI.  Old constructor preserved."
```

---

### Task 6: Remove Duplicated State from GuiApp and TuiApp

**Files:**
- Modify: `tools/tenet/src/gui/gui_app.h` — remove duplicated members, add accessors through service_
- Modify: `tools/tenet/src/gui/gui_app.mm` — remove old constructor (keep only service-based)
- Modify: `tools/tenet/src/gui/navigation.cpp` — drop fallback paths
- Modify: `tools/tenet/src/gui/panels_analysis.cpp` — use service's pass results
- Modify: `tools/tenet/src/tui/tui_app.h` — remove duplicated members
- Modify: `tools/tenet/src/tui/tui_app.cpp` — drop fallback paths
- Modify: `tools/tenet/src/main.cpp` — remove old constructor calls

**Interfaces:**
- Consumes: Migrated `GuiApp`/`TuiApp` from Tasks 2-3
- Produces: Clean frontends with no duplicated state; all shared state lives in `TenetService`

This is the cleanup task. After Tasks 2-5 verified everything works through `service_`, we remove the old code paths.

- [ ] **Step 1: Remove old GuiApp constructor (6-ref version)**

Delete the old constructor in both `gui_app.h` and `gui_app.mm`. Only the `GuiApp(TenetService&, path)` constructor remains.

- [ ] **Step 2: Remove duplicated members from GuiApp**

From `gui_app.h`, remove these members (they now live in TenetService):
- `bookmarks_` → use `service_->bookmarks()`
- `nav_history_`, `nav_history_pos_`, `nav_history_navigating_` → use `service_->nav_back()` etc.
- `row_cache_` → use `service_->fetch_row()`
- `search_results_`, `search_current_`, `search_active_` → use `service_->search_results()` etc.
- `current_inst_` → use `service_->current_inst()` (keep a local cache for frame-consistent reads)
- `total_inst_` → use `service_->total_inst()`

Keep `pass_manager_` as a raw pointer alias: `PassManager* pass_manager() { return service_->pass_manager(); }`

Keep `pinned_results_` — GUI needs its own pinning for thread safety between render thread and MCP thread. But delegate the storage to service when possible.

- [ ] **Step 3: Update all GUI panel files that reference removed members**

For each `panels_*.cpp` that uses `bookmarks_`, `current_inst_`, `total_inst_`, etc., replace with `service_->xxx()` calls. Since `service_` is a private member of `GuiApp`, and panels are implemented as GuiApp member functions, this is straightforward find-and-replace.

- [ ] **Step 4: Remove old TuiApp constructor**

Delete the old 6-ref constructor. Only `TuiApp(TenetService&)` remains.

- [ ] **Step 5: Remove duplicated members from TuiApp**

Same removals as GuiApp: `bookmarks_`, navigation history, row_cache_, search state.

- [ ] **Step 6: Update TuiContext to use service**

`TuiContext` can now expose service methods directly instead of raw backend pointers. For panels that still need raw access (RegisterPanel's `regfile->state_before()`), keep the pointer in TuiContext but source it from `service->regfile()`.

- [ ] **Step 7: Remove old 6-ref overload of run_batch_analysis**

If no other callers remain, remove the old `run_batch_analysis(opts, reader, index, ...)` overload.

- [ ] **Step 8: Update main.cpp**

Remove the old constructor call patterns. `TenetService` should be the single gateway:
```cpp
TenetService service(reader, index, code_table, decoder, regfile, memory, opts.trace_path);

if (has_analysis_option)
    return tenet::run_batch_analysis(opts, service);

if (opts.batch_mode) {
    TuiApp app(service);
    return app.batch_mode(...);
}

#if TENET_HAS_GUI
if (!opts.force_tui) {
    GuiApp gui(service, opts.trace_path);
    gui.set_vm_paths(opts.vm_hints_file, opts.vm_decoder_file);
    return gui.run();
}
#endif

TuiApp app(service);
return app.run();
```

- [ ] **Step 9: Build, test extensively**

```bash
cd tools/tenet/build && ninja -j$(nproc) && ctest --output-on-failure
```

- [ ] **Step 10: Smoke test all three frontends**

1. CLI: `./tenet --xref trace.bin` (batch analysis output)
2. TUI: `./tenet --tui trace.bin` (navigation, bookmarks, search, pass execution)
3. GUI: `./tenet trace.bin` (all panels, MCP server, CFG, taint)

- [ ] **Step 11: Commit**

```bash
git add -A tools/tenet/src/
git commit -m "refactor: remove duplicated state — all shared state lives in TenetService

GuiApp/TuiApp/batch_analysis now use TenetService as sole source of
truth for navigation, bookmarks, row cache, pass results.  Old
6-reference constructors and duplicate members removed."
```

---

### Task 7: Update Documentation

**Files:**
- Modify: `tools/tenet/docs/ARCHITECTURE.md` — add Service layer description
- Modify: `tools/tenet/docs/ui-layer.md` — update frontend architecture

**Interfaces:**
- Consumes: Final architecture from Task 6
- Produces: Updated documentation reflecting the Service layer

- [ ] **Step 1: Update ARCHITECTURE.md**

Add a new "Service Layer" section between Analysis and Frontend layers:

```markdown
### Service Layer

`TenetService` (src/service/tenet_service.h) is the central application-state
manager shared by all frontends. It owns:

- PassManager lifecycle (ensure_pass_manager, run_pass, run_default_passes)
- Navigation state (cursor, history, bookmarks, search)
- Instruction row cache (LRU 4096)
- Pass result lifetime management (pinned shared_ptr)

Frontends (GUI/TUI/CLI/MCP) receive a TenetService& in their constructor
and delegate all shared-state operations to it. The observer pattern
(TenetServiceObserver) delivers async notifications (pass completed,
navigation change, bookmark toggle) to subscribed frontends.

```
Architecture diagram update:
```
Frontend (TUI/GUI/CLI/MCP)
        ↕  TenetServiceObserver callbacks
Service Layer (TenetService)
        ↕
Pass Pipeline (XRef, Taint, CFG, ...)
        ↕  PassManager auto-schedule
Core (RegisterFile + MemoryModel + TritonBridge)
        ↕
IO (TraceReader mmap + RocksDB Index)
```

- [ ] **Step 2: Update ui-layer.md**

Update the frontend section to reflect that GUI/TUI now go through TenetService instead of directly holding backend references.

- [ ] **Step 3: Commit**

```bash
git add tools/tenet/docs/ARCHITECTURE.md tools/tenet/docs/ui-layer.md
git commit -m "docs: document TenetService layer in architecture docs"
```

---

### Task 8: Verification — Build All Configurations

**Files:** None modified (verification only)

- [ ] **Step 1: Full clean build (Debug)**

```bash
cd tools/tenet/build
cmake .. && ninja -j$(nproc)
```

- [ ] **Step 2: Build without GUI**

```bash
cd tools/tenet/build
cmake .. -DTENET_ENABLE_GUI=OFF && ninja -j$(nproc)
```

Verifies `TenetService` compiles without ImGui/SDL3 dependencies.

- [ ] **Step 3: Build without Triton**

```bash
cd tools/tenet/build-no-triton
cmake .. -DTENET_ENABLE_TRITON=OFF && ninja -j$(nproc)
```

- [ ] **Step 4: Run all unit tests**

```bash
cd tools/tenet/build && ctest --output-on-failure
```

- [ ] **Step 5: Verify no regressions in MCP tool count**

Launch tenet in MCP stdio mode and verify `tools/list` returns the same number of tools as before the refactor.

- [ ] **Step 6: Final commit tag**

```bash
git tag tenet-service-v1 -m "TenetService extraction complete"
```

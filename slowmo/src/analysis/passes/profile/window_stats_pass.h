#pragma once

#include "analysis/pass_manager.h"
#include "infra/scan_orchestrator.h"
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <memory>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct WindowStatsConfig {
    /// Window size in instructions.
    uint64_t window_size = 1000;
    /// Stride between windows (default = window_size for non-overlapping).
    uint64_t stride = 0;  // 0 means stride = window_size
    /// Track top-N mnemonics per window.
    uint32_t top_mnemonics = 10;
    /// Track memory access hotspots.
    bool track_mem_hotspots = true;
    /// Track register activity.
    bool track_reg_activity = true;
};

// ─── Window snapshot ───────────────────────────────────────────────────────

struct WindowSnapshot {
    uint64_t start_inst_id;
    uint64_t end_inst_id;
    uint64_t instruction_count;

    /// Mnemonic distribution: (mnemonic_id, count) sorted by count desc.
    /// `mnemonic_id` is an internal grouping key (opcode >> 21) used for
    /// fast hot-loop classification; `mnemonic` is the human-readable
    /// instruction name (e.g. "add", "ldr"), resolved once per top-N entry
    /// at window-flush time via the Capstone-backed InstructionDecoder —
    /// NOT decoded per-instruction, so it doesn't affect scan throughput.
    /// May be empty if no decoder/PC sample was available (e.g. serialized
    /// results loaded from an older cache format).
    struct MnemonicStat {
        uint16_t mnemonic_id;
        uint64_t count;
        std::string mnemonic;
    };
    std::vector<MnemonicStat> top_mnemonics;

    /// Register write activity: reg_index → write_count.
    std::array<uint32_t, 34> reg_write_counts = {};

    /// Memory access density (unique addresses / total accesses).
    uint64_t mem_read_count = 0;
    uint64_t mem_write_count = 0;
    uint64_t unique_mem_addrs = 0;

    /// Unique PCs in this window (instruction diversity).
    uint64_t unique_pcs = 0;

    /// Shannon entropy of mnemonic distribution (higher = more diverse).
    float mnemonic_entropy = 0.0f;

    /// Control flow density (branches / total instructions).
    float branch_density = 0.0f;
};

// ─── Result ────────────────────────────────────────────────────────────────

struct WindowStatsResult {
    std::vector<WindowSnapshot> windows;
    uint64_t total_windows = 0;
    uint64_t window_size = 0;

    /// Hottest windows by various metrics.
    size_t hottest_mem_window = 0;     // Most memory accesses
    size_t most_diverse_window = 0;    // Highest mnemonic entropy
    size_t densest_branch_window = 0;  // Most branches
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Sliding window statistics: computes per-window metrics over the trace
/// for identifying hot regions, crypto loops, data processing phases, etc.
///
/// Dependencies: none (direct TraceReader scan).
///
/// Result type: WindowStatsResult
class WindowStatsPass final : public AnalysisPass {
public:
    explicit WindowStatsPass(WindowStatsConfig cfg = {});  // defined in .cpp
    ~WindowStatsPass() override;  // defined in .cpp where WindowStatsCollector is complete
    WindowStatsPass(WindowStatsPass&&) noexcept;  // defined in .cpp
    WindowStatsPass& operator=(WindowStatsPass&&) noexcept;  // defined in .cpp
    WindowStatsPass(const WindowStatsPass&) = delete;
    WindowStatsPass& operator=(const WindowStatsPass&) = delete;

    std::string_view name() const override { return "window_stats"; }
    std::string_view description() const override {
        return "Sliding window statistics (mnemonic distribution, memory hotspots, etc.)";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }

    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }

private:
    class WindowStatsCollector;  // forward declare (defined in .cpp)
    std::unique_ptr<WindowStatsCollector> collector_;
    WindowStatsConfig cfg_;
};

}  // namespace tenet

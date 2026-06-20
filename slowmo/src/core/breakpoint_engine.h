#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/memory_model.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <variant>

namespace tenet {

// ─── Breakpoint types ─────────────────────────────────────────────────────

/// PC breakpoint: fires when the PC of any instruction equals `address`.
/// This is O(1) thanks to the XRef index (pc_to_inst_ids bitmap).
struct PcBreakpoint {
    uint64_t address;   ///< Runtime (slid) PC to stop at.
};

/// Memory write watchpoint: fires when any instruction writes to the address
/// range [address, address + size). O(log N) via TraceIndex::MEM_WRITE CF.
struct WatchBreakpoint {
    uint64_t address;   ///< Start of monitored region.
    uint16_t size;      ///< Length in bytes (1..64). 0 = any write to the page.
};

/// Conditional breakpoint: fires when the user-supplied predicate returns true.
/// Evaluated at every instruction between current_pos and the search limit.
/// Expensive for long traces — use with care.
struct ConditionalBreakpoint {
    // Evaluated on (inst_id, state_before).
    // Return true to "hit" this breakpoint.
    std::function<bool(uint64_t inst_id, const RegState&)> predicate;
    std::string description;  ///< Human-readable description for the TUI status bar.
};

using BreakpointSpec = std::variant<PcBreakpoint, WatchBreakpoint, ConditionalBreakpoint>;

// ─── Breakpoint handle ────────────────────────────────────────────────────

/// Opaque handle returned by add_breakpoint(). Used to remove a breakpoint.
using BreakpointId = uint32_t;
static constexpr BreakpointId kInvalidBreakpointId = 0;

// ─── Hit result ───────────────────────────────────────────────────────────

struct BreakpointHit {
    uint64_t inst_id;           ///< The instruction where the breakpoint fired.
    BreakpointId bp_id;         ///< Which breakpoint was triggered.
    std::string description;    ///< Human-readable hit description.
};

// ─── BreakpointEngine ─────────────────────────────────────────────────────

/// Time-travel breakpoint and watchpoint engine.
///
/// Design principles:
///   • PC breakpoints are O(1): resolved entirely from the in-memory
///     XRef bitmap (pc_to_inst_ids) without rescanning the trace.
///   • Memory write watchpoints are O(log N): resolved via the RocksDB
///     mem_write column family which is keyed by (addr_page, offset, inst_id).
///   • Conditional breakpoints are O(N): the engine scans sequentially from
///     current_pos in the requested direction, evaluating the predicate at
///     each instruction.
///   • Both forward (continue) and backward (reverse-continue) directions
///     are supported for all breakpoint types.
///
/// Usage:
///   BreakpointEngine engine(reader, index, regfile, memory);
///   auto id = engine.add_breakpoint(PcBreakpoint{0x1000});
///   auto hit = engine.run_forward(current_inst_id);  // find next hit
///   if (hit) navigate_to(hit->inst_id);
class BreakpointEngine {
public:
    BreakpointEngine(const TraceReader& reader,
                     const TraceIndex& index,
                     RegisterFile& regfile,
                     const MemoryModel& memory);

    // ─── Lifecycle ────────────────────────────────────────────────────

    /// Add a breakpoint. Returns a handle for later removal.
    BreakpointId add_breakpoint(BreakpointSpec spec);

    /// Remove a breakpoint by handle.
    bool remove_breakpoint(BreakpointId id);

    /// Remove all breakpoints.
    void clear_breakpoints();

    /// Check if any breakpoints are registered.
    bool has_breakpoints() const { return !entries_.empty(); }

    /// List all active breakpoints (for display in TUI status bar).
    struct BreakpointEntry {
        BreakpointId id;
        BreakpointSpec spec;
        bool enabled = true;
    };
    const std::vector<BreakpointEntry>& entries() const { return entries_; }

    // ─── Search (forward / backward) ──────────────────────────────────

    /// Search forward from `from_inst_id` (exclusive) for the next hit.
    /// Returns the hit if found, or nullopt if no breakpoint fires before
    /// the end of the trace (or before `limit` instructions are checked for
    /// conditional breakpoints).
    std::optional<BreakpointHit> run_forward(
        uint64_t from_inst_id,
        uint64_t limit = UINT64_MAX) const;

    /// Search backward from `from_inst_id` (exclusive) for the previous hit.
    std::optional<BreakpointHit> run_backward(
        uint64_t from_inst_id,
        uint64_t limit = UINT64_MAX) const;

    // ─── Convenience wrappers (single-breakpoint "step-to") ───────────

    /// Find the next occurrence of a specific PC at or after `from_inst_id`.
    /// Returns nullopt if the PC was never executed after that point.
    std::optional<uint64_t> next_execution(uint64_t pc, uint64_t from_inst_id) const;

    /// Find the previous occurrence of a specific PC before `from_inst_id`.
    std::optional<uint64_t> prev_execution(uint64_t pc, uint64_t from_inst_id) const;

    /// Find the next write to `address` after `from_inst_id`.
    std::optional<BreakpointHit> next_write(uint64_t address, uint16_t size,
                                            uint64_t from_inst_id) const;

    /// Find the previous write to `address` before `from_inst_id`.
    std::optional<BreakpointHit> prev_write(uint64_t address, uint16_t size,
                                            uint64_t from_inst_id) const;

private:
    const TraceReader& reader_;
    const TraceIndex& index_;
    RegisterFile& regfile_;
    const MemoryModel& memory_;

    std::vector<BreakpointEntry> entries_;
    BreakpointId next_id_ = 1;  // starts at 1; 0 is kInvalidBreakpointId

    // ─── Per-type resolution helpers ──────────────────────────────────

    /// Resolve all inst_ids for a PC breakpoint from the XRef index.
    /// Returns sorted vector (ascending).
    std::vector<uint64_t> resolve_pc_bp(const PcBreakpoint& bp) const;

    /// Resolve all inst_ids for a WatchBreakpoint from the mem_write CF.
    /// Returns sorted vector (ascending).
    std::vector<uint64_t> resolve_watch_bp(const WatchBreakpoint& bp) const;

    /// Format a hit description string for the status bar.
    static std::string format_hit(const BreakpointEntry& entry, uint64_t inst_id);
};

// ─── TUI helpers ─────────────────────────────────────────────────────────

/// Parse a TUI breakpoint command string and return a BreakpointSpec.
/// Supports:
///   "b 0x1234abc"      → PcBreakpoint{0x1234abc}
///   "w 0x1234 8"       → WatchBreakpoint{0x1234, 8}
///   "w 0x1234"         → WatchBreakpoint{0x1234, 0}  (any write to page)
/// Returns nullopt on parse error; sets `error_msg` if non-null.
std::optional<BreakpointSpec> parse_breakpoint_cmd(
    const std::string& cmd,
    std::string* error_msg = nullptr);

}  // namespace tenet

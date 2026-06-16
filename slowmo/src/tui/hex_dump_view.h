#pragma once

#include "core/memory_model.h"

#include <ftxui/dom/elements.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace tenet {

/// Hex dump memory view component.
///
/// Displays a hex dump of a memory region starting at a given base address,
/// at a specific point in time (inst_id). Supports scrolling, address jumping,
/// and time navigation (step to next/previous modification of the visible region).
class HexDumpView {
public:
    explicit HexDumpView(MemoryModel& memory);

    /// Set the starting address for the hex dump.
    void set_address(uint64_t base_addr);

    /// Set the time point (inst_id) for the memory snapshot.
    void set_time(uint64_t inst_id);

    /// Set the number of display rows (each row = 16 bytes).
    void set_rows(int num_rows);

    // ─── Navigation ────────────────────────────────────────────────────

    /// Scroll up by `lines` rows (each row = 16 bytes).
    void scroll_up(int lines = 1);

    /// Scroll down by `lines` rows (each row = 16 bytes).
    void scroll_down(int lines = 1);

    /// Scroll up by one page (num_rows_ rows).
    void page_up();

    /// Scroll down by one page (num_rows_ rows).
    void page_down();

    /// Jump to a specific address (aligned to 16-byte boundary).
    void goto_address(uint64_t addr);

    // ─── Time navigation ────────────────────────────────────────────────

    /// Move to the next inst_id that modifies any byte in the current visible region.
    void step_forward();

    /// Move to the previous inst_id that modifies any byte in the current visible region.
    void step_backward();

    // ─── Rendering ──────────────────────────────────────────────────────

    /// Render the hex dump as an FTXUI Element.
    ftxui::Element render();

    // ─── Status ─────────────────────────────────────────────────────────

    /// Current base address of the view.
    uint64_t current_address() const;

    /// Current time point (inst_id).
    uint64_t current_time() const;

private:
    MemoryModel& memory_;

    uint64_t base_addr_ = 0;
    uint64_t at_inst_id_ = 0;
    int num_rows_ = 16;  // Each row = 16 bytes, default 16 rows = 256 bytes

    static constexpr int BYTES_PER_ROW = 16;

    /// Cached row data for the current viewport.
    struct CachedRow {
        uint64_t addr;
        std::array<uint8_t, 16> data{};
        std::array<bool, 16> known{};
        std::array<bool, 16> modified{};  // bytes written at exactly at_inst_id_
    };

    std::vector<CachedRow> cached_rows_;
    bool cache_valid_ = false;

    /// Refresh the cache by reading from the MemoryModel.
    void refresh_cache();

    /// Collect all inst_ids that wrote to the visible region,
    /// sorted ascending. Used for step_forward / step_backward.
    std::vector<uint64_t> collect_modification_times();
};

}  // namespace tenet

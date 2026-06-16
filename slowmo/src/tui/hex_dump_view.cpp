#include "tui/hex_dump_view.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_set>

#include <fmt/core.h>
#include <ftxui/dom/elements.hpp>

namespace tenet {

using namespace ftxui;

// ─── Constructor ─────────────────────────────────────────────────────────────

HexDumpView::HexDumpView(MemoryModel& memory)
    : memory_(memory) {}

// ─── Parameter setters ──────────────────────────────────────────────────────

void HexDumpView::set_address(uint64_t base_addr) {
    if (base_addr_ != base_addr) {
        base_addr_ = base_addr;
        cache_valid_ = false;
    }
}

void HexDumpView::set_time(uint64_t inst_id) {
    if (at_inst_id_ != inst_id) {
        at_inst_id_ = inst_id;
        cache_valid_ = false;
    }
}

void HexDumpView::set_rows(int num_rows) {
    if (num_rows_ != num_rows) {
        num_rows_ = num_rows;
        cache_valid_ = false;
    }
}

// ─── Navigation ─────────────────────────────────────────────────────────────

void HexDumpView::scroll_up(int lines) {
    base_addr_ -= static_cast<uint64_t>(lines) * BYTES_PER_ROW;
    cache_valid_ = false;
}

void HexDumpView::scroll_down(int lines) {
    base_addr_ += static_cast<uint64_t>(lines) * BYTES_PER_ROW;
    cache_valid_ = false;
}

void HexDumpView::page_up() {
    scroll_up(num_rows_);
}

void HexDumpView::page_down() {
    scroll_down(num_rows_);
}

void HexDumpView::goto_address(uint64_t addr) {
    // Align down to 16-byte boundary
    base_addr_ = addr & ~static_cast<uint64_t>(BYTES_PER_ROW - 1);
    cache_valid_ = false;
}

// ─── Time navigation ────────────────────────────────────────────────────────

void HexDumpView::step_forward() {
    auto times = collect_modification_times();
    // Find the first time > at_inst_id_
    auto it = std::upper_bound(times.begin(), times.end(), at_inst_id_);
    if (it != times.end()) {
        at_inst_id_ = *it;
        cache_valid_ = false;
    }
    // If no later modification, stay at current time
}

void HexDumpView::step_backward() {
    auto times = collect_modification_times();
    // Find the last time < at_inst_id_
    auto it = std::lower_bound(times.begin(), times.end(), at_inst_id_);
    if (it != times.begin()) {
        --it;
        at_inst_id_ = *it;
        cache_valid_ = false;
    }
    // If no earlier modification, stay at current time
}

// ─── Status ─────────────────────────────────────────────────────────────────

uint64_t HexDumpView::current_address() const {
    return base_addr_;
}

uint64_t HexDumpView::current_time() const {
    return at_inst_id_;
}

// ─── Cache management ───────────────────────────────────────────────────────

void HexDumpView::refresh_cache() {
    cached_rows_.clear();
    cached_rows_.reserve(num_rows_);

    for (int r = 0; r < num_rows_; r++) {
        uint64_t row_addr = base_addr_ + static_cast<uint64_t>(r) * BYTES_PER_ROW;

        CachedRow row;
        row.addr = row_addr;

        // Read 16 bytes at row_addr at the current time point
        auto result = memory_.read(row_addr, BYTES_PER_ROW, at_inst_id_);
        row.data = result.data;
        row.known = result.known;

        // Determine which bytes were modified at exactly at_inst_id_
        for (int b = 0; b < BYTES_PER_ROW; b++) {
            row.modified[b] = result.known[b] && result.writer_id[b] == at_inst_id_;
        }

        cached_rows_.push_back(std::move(row));
    }

    cache_valid_ = true;
}

std::vector<uint64_t> HexDumpView::collect_modification_times() {
    // Ensure cache is valid before we read
    if (!cache_valid_) {
        refresh_cache();
    }

    std::unordered_set<uint64_t> seen;
    std::vector<uint64_t> times;

    for (const auto& row : cached_rows_) {
        // Query write history for this row's 16-byte range
        auto history = memory_.write_history(row.addr, BYTES_PER_ROW);
        for (uint64_t t : history) {
            if (seen.insert(t).second) {
                times.push_back(t);
            }
        }
    }

    std::sort(times.begin(), times.end());
    return times;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

Element HexDumpView::render() {
    if (!cache_valid_) {
        refresh_cache();
    }

    Elements lines;

    // ─── Header ──────────────────────────────────────────────────────────
    //   Address          Hex Dump                                    ASCII
    //   ──────────────────────────────────────────────────────────────────

    auto header = hbox({
        text(" Address        ") | bold | color(Color::Yellow),
        text("  ") | size(WIDTH, EQUAL, 2),
        text("Hex Dump") | bold | color(Color::Yellow),
        text("                                   ") | size(WIDTH, EQUAL, 35),
        text("  ") | size(WIDTH, EQUAL, 2),
        text("ASCII") | bold | color(Color::Yellow),
    });
    lines.push_back(header);
    lines.push_back(hbox({text("─") | color(Color::GrayDark)}) | flex);

    // ─── Data rows ──────────────────────────────────────────────────────
    for (const auto& row : cached_rows_) {
        Elements hex_parts;
        Elements ascii_parts;

        for (int b = 0; b < BYTES_PER_ROW; b++) {
            // Add extra spacing in the middle of the row (after byte 7)
            if (b == 8) {
                hex_parts.push_back(text("  ") | size(WIDTH, EQUAL, 2));
            }

            if (row.known[b]) {
                std::string byte_str = fmt::format("{:02X}", row.data[b]);

                if (row.modified[b]) {
                    // Byte modified at current inst_id → red bold
                    hex_parts.push_back(text(byte_str) | color(Color::Red) | bold);
                } else {
                    // Normal known byte → white
                    hex_parts.push_back(text(byte_str) | color(Color::White));
                }
            } else {
                // Unknown byte → "??" in gray
                hex_parts.push_back(text("??") | color(Color::GrayDark));
            }

            // Separator between bytes (single space, except after byte 7 handled above)
            if (b < BYTES_PER_ROW - 1 && b != 7) {
                hex_parts.push_back(text(" ") | size(WIDTH, EQUAL, 1));
            }

            // ASCII representation
            if (row.known[b]) {
                char c = static_cast<char>(row.data[b]);
                if (row.modified[b]) {
                    // Modified byte in ASCII → red
                    std::string s(1, std::isprint(static_cast<unsigned char>(c)) ? c : '.');
                    ascii_parts.push_back(text(s) | color(Color::Red) | bold);
                } else {
                    std::string s(1, std::isprint(static_cast<unsigned char>(c)) ? c : '.');
                    ascii_parts.push_back(text(s) | color(Color::White));
                }
            } else {
                // Unknown byte in ASCII → gray dot
                ascii_parts.push_back(text(".") | color(Color::GrayDark));
            }
        }

        // Address column (dark gray)
        auto addr_text = text(fmt::format(" 0x{:X}", row.addr)) | color(Color::GrayDark);

        // Assemble the line: address | hex bytes | ASCII
        auto line = hbox({
            addr_text | size(WIDTH, EQUAL, 18),
            text("  ") | size(WIDTH, EQUAL, 2),
            hbox(hex_parts),
            text("  ") | size(WIDTH, EQUAL, 2),
            hbox(ascii_parts),
        });

        lines.push_back(line);
    }

    // ─── Footer with navigation info ────────────────────────────────────
    lines.push_back(hbox({text("─") | color(Color::GrayDark)}) | flex);
    lines.push_back(hbox({
        text(" ↑↓/jk:scroll  PgUp/PgDn:page  g:goto  </>:time-nav") | color(Color::GrayLight),
        text("  ") | size(WIDTH, EQUAL, 2),
        text(fmt::format("@inst={}", at_inst_id_)) | color(Color::Cyan),
    }));

    return vbox(lines) | flex | border;
}

}  // namespace tenet

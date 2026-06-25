#include "tui/panels/memory_panel.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/memory_model.h"

#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <fmt/core.h>

#include <cstring>

namespace tenet {

using namespace ftxui;

Element MemoryPanel::render() {
    Elements lines;

    // Header with focus indicator
    auto header_label = focused()
        ? text("[MEMORY ACCESSES]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Memory Accesses") | bold | color(Color::Yellow);
    lines.push_back(header_label);
    lines.push_back(separator());

    // Get current instruction's memory accesses
    auto [offset, seed_pc] = ctx_.index->offset_of_with_pc(ctx_.current_inst, *ctx_.reader);
    auto rec = ctx_.reader->record_at(offset, seed_pc);
    if (rec.kind != RecordKind::Inst) {
        lines.push_back(text("(no instruction)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
    }

    auto inst = rec.as_inst();
    if (inst.mem_access_count == 0) {
        lines.push_back(text("(no memory access)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
    }

    // Clamp cursor
    if (access_cursor_ >= inst.mem_access_count) {
        access_cursor_ = inst.mem_access_count > 0 ? inst.mem_access_count - 1 : 0;
    }

    for (uint8_t i = 0; i < inst.mem_access_count; i++) {
        auto mem = inst.mem_access(i);
        bool is_write = (mem.type & 2) != 0;
        const char* type_label = is_write ? "WRITE" : "READ ";
        Color type_color = is_write ? Color::Red : Color::Green;
        bool is_selected = focused() && (static_cast<size_t>(i) == access_cursor_);

        // Access header: type + address + size (with cursor indicator)
        auto cursor_mark = text(is_selected ? ">" : " ") | color(Color::Yellow);
        auto access_header = hbox({
            cursor_mark,
            text(type_label) | color(type_color) | bold,
            text(fmt::format("  addr=0x{:016x}  size={}", mem.addr, mem.size))
                | color(Color::White),
        });
        if (is_selected) {
            access_header = access_header | bgcolor(Color::GrayDark);
        }
        lines.push_back(access_header);

        // Value display
        if (mem.size <= 8) {
            lines.push_back(hbox({
                text("  val =") | color(Color::GrayLight),
                text(fmt::format(" 0x{:016x}", mem.value)) | color(Color::Cyan),
            }));
        } else {
            // 16-byte access (Q register / LDP)
            lines.push_back(hbox({
                text("  lo  =") | color(Color::GrayLight),
                text(fmt::format(" 0x{:016x}", mem.value)) | color(Color::Cyan),
            }));
            lines.push_back(hbox({
                text("  hi  =") | color(Color::GrayLight),
                text(fmt::format(" 0x{:016x}", mem.value_hi)) | color(Color::Cyan),
            }));
        }

        // Hex dump of the value (byte-by-byte, little-endian)
        {
            std::string hex_str = "  hex: ";
            uint8_t bytes[16];
            std::memcpy(bytes, &mem.value, 8);
            std::memcpy(bytes + 8, &mem.value_hi, 8);
            size_t n = (mem.size <= 16) ? mem.size : 8;
            for (size_t b = 0; b < n; b++) {
                hex_str += fmt::format("{:02x} ", bytes[b]);
            }
            lines.push_back(text(hex_str) | color(Color::GrayDark));
        }

        // For writes: show the last writer of this address
        if (is_write && ctx_.memory) {
            uint64_t writer = ctx_.memory->last_writer(mem.addr, mem.size, ctx_.current_inst);
            if (writer > 0) {
                lines.push_back(hbox({
                    text("  writer @") | color(Color::GrayLight),
                    text(fmt::format("{}", writer)) | color(Color::Magenta),
                }));
            }
        }

        if (i + 1 < inst.mem_access_count) {
            lines.push_back(separator());
        }
    }

    // Footer hint when focused
    if (focused()) {
        lines.push_back(separator());
        lines.push_back(text("j/k:select Enter:jump-to-writer Esc:unfocus") | color(Color::GrayDark));
    }

    return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
}

bool MemoryPanel::handle_event(Event event) {
    if (event == Event::Escape) {
        set_focused(false);
        return true;
    }

    // Get current instruction's memory access count
    auto [offset, seed_pc] = ctx_.index->offset_of_with_pc(ctx_.current_inst, *ctx_.reader);
    auto rec = ctx_.reader->record_at(offset, seed_pc);
    if (rec.kind != RecordKind::Inst) {
        set_focused(false);
        return true;
    }
    auto inst = rec.as_inst();
    if (inst.mem_access_count == 0) {
        set_focused(false);
        return true;
    }

    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (access_cursor_ + 1 < static_cast<size_t>(inst.mem_access_count)) {
            access_cursor_++;
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (access_cursor_ > 0) {
            access_cursor_--;
        }
        return true;
    }

    // Enter: jump to the instruction that last wrote the selected address
    if (event == Event::Return) {
        if (access_cursor_ < static_cast<size_t>(inst.mem_access_count)) {
            auto mem = inst.mem_access(static_cast<uint8_t>(access_cursor_));
            if (ctx_.memory) {
                uint64_t writer = ctx_.memory->last_writer(
                    mem.addr, static_cast<uint8_t>(mem.size), ctx_.current_inst);
                if (writer > 0) {
                    ctx_.navigate_to(writer);
                }
            }
            set_focused(false);
        }
        return true;
    }

    return false;
}

}  // namespace tenet

#include "breakpoint_panel.h"
#include "core/breakpoint_engine.h"

#include <fmt/format.h>
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

namespace tenet {

Element BreakpointPanel::render() {
    Elements lines;

    // Header with focus indicator
    auto header_label = focused_
        ? text("[BREAKPOINTS]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text(" Breakpoints ") | bold | color(Color::Yellow);
    lines.push_back(header_label | center);
    lines.push_back(separator());

    if (!engine_) {
        lines.push_back(text("(no engine)") | color(Color::GrayDark) | center);
        return vbox(lines) | size(WIDTH, GREATER_THAN, 28) | border;
    }

    const auto& entries = engine_->entries();
    if (entries.empty()) {
        lines.push_back(text(" (none) ") | color(Color::GrayDark) | center);
    } else {
        for (size_t i = 0; i < entries.size(); i++) {
            const auto& e = entries[i];
            bool is_cursor = (i == cursor_);

            std::string label;
            std::visit([&](const auto& s) {
                using T = std::decay_t<decltype(s)>;
                if constexpr (std::is_same_v<T, PcBreakpoint>) {
                    label = fmt::format("#{} PC=0x{:x}", e.id, s.address);
                } else if constexpr (std::is_same_v<T, WatchBreakpoint>) {
                    if (s.size == 0)
                        label = fmt::format("#{} W 0x{:x} (pg)", e.id, s.address);
                    else
                        label = fmt::format("#{} W 0x{:x}+{}", e.id, s.address, s.size);
                } else if constexpr (std::is_same_v<T, ConditionalBreakpoint>) {
                    label = fmt::format("#{} cond:{}", e.id, s.description.substr(0, 12));
                }
            }, e.spec);

            auto row = hbox({
                text(is_cursor ? ">" : " ") | color(Color::Yellow),
                text(e.enabled ? " \u25cf " : " \u25cb ") | color(e.enabled ? Color::Red : Color::GrayDark),
                text(label) | color(is_cursor ? Color::White : Color::GrayLight),
            });

            if (is_cursor && focused_) {
                row = row | bgcolor(Color::GrayDark);
            }
            lines.push_back(row);
        }
    }

    // Footer
    lines.push_back(separator());
    if (focused_) {
        lines.push_back(text("j/k:nav d:delete c:clear Enter:jump Esc:unfocus") | color(Color::GrayDark));
    } else {
        lines.push_back(text("Focus to manage breakpoints") | color(Color::GrayDark));
    }

    return vbox(lines) | size(WIDTH, GREATER_THAN, 28) | border;
}

bool BreakpointPanel::handle_event(Event event) {
    if (!engine_) return false;

    const auto& entries = engine_->entries();

    if (event == Event::Escape) {
        focused_ = false;
        return true;
    }

    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (!entries.empty()) {
            cursor_ = (cursor_ + 1) % entries.size();
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (!entries.empty()) {
            cursor_ = (cursor_ + entries.size() - 1) % entries.size();
        }
        return true;
    }

    if (event == Event::Character('d') || event == Event::Character('x')) {
        if (!entries.empty() && cursor_ < entries.size()) {
            uint32_t id = entries[cursor_].id;
            engine_->remove_breakpoint(id);
            // Adjust cursor if it's past the end after deletion
            if (cursor_ >= engine_->entries().size() && cursor_ > 0) {
                cursor_--;
            }
        }
        return true;
    }

    if (event == Event::Character('c')) {
        engine_->clear_breakpoints();
        cursor_ = 0;
        return true;
    }

    // Enter: jump to the nearest occurrence of the selected breakpoint
    if (event == Event::Return) {
        if (!entries.empty() && cursor_ < entries.size()) {
            // Create a temporary engine to search for this specific breakpoint
            BreakpointEngine temp(*ctx_.reader, *ctx_.index, *ctx_.regfile, *ctx_.memory);
            temp.add_breakpoint(entries[cursor_].spec);
            auto hit = temp.run_forward(ctx_.current_inst);
            if (!hit) hit = temp.run_backward(ctx_.current_inst);
            if (hit) {
                ctx_.navigate_to(hit->inst_id);
                focused_ = false;
            }
        }
        return true;
    }

    return false;
}

}  // namespace tenet

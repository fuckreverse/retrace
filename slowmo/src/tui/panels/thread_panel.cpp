#include "thread_panel.h"

#include "tui/tui_context.h"
#include "analysis/passes/misc/thread_pass.h"

#include <fmt/format.h>
#include <ftxui/dom/elements.hpp>

namespace tenet {

using namespace ftxui;

// ─── render ──────────────────────────────────────────────────────────────

Element ThreadPanel::render() {
    Elements lines;

    // Header — highlight when focused.
    auto header_label = focused_
        ? text("[THREADS]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Threads")  | bold | color(Color::Yellow);
    lines.push_back(header_label);
    lines.push_back(separator());

    const auto* tr = ctx_.thread_result;
    if (!tr) {
        lines.push_back(text("(not computed)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 30) | border;
    }

    // Summary line.
    lines.push_back(hbox({
        text(fmt::format(" {} threads, {} switches",
            tr->thread_count(),
            tr->switch_count())) | color(Color::Cyan),
    }));
    lines.push_back(separator());

    // Current (active) thread indicator.
    uint64_t cur_tid = tr->thread_at(ctx_.current_inst);
    if (cur_tid != 0) {
        lines.push_back(hbox({
            text(fmt::format(" Active: tid=0x{:x}", cur_tid))
                | color(Color::Green) | bold,
        }));
        lines.push_back(separator());
    }

    // Thread list.
    size_t idx = 0;
    for (const auto& [tid, info] : tr->threads) {
        bool is_selected = (idx == cursor_);
        bool is_active   = (tid == cur_tid);

        auto line_text = fmt::format(" tid=0x{:x}  insts={}",
                                     tid, info.total_instructions);
        if (info.switch_in_count > 1) {
            line_text += fmt::format("  sw={}", info.switch_in_count);
        }

        Element line_elem;
        if (is_selected && focused_) {
            line_elem = text(line_text)
                | bgcolor(Color::Blue) | color(Color::White);
        } else if (is_active) {
            line_elem = text(line_text)
                | color(Color::Green) | bold;
        } else {
            line_elem = text(line_text) | color(Color::White);
        }
        lines.push_back(line_elem);
        idx++;
    }

    // Footer keybinding hint.
    lines.push_back(separator());
    lines.push_back(
        text(" t:toggle  T:next-switch  Enter:filter")
            | color(Color::GrayLight));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 35) | border;
}

// ─── handle_event ────────────────────────────────────────────────────────

bool ThreadPanel::handle_event(Event event) {
    const auto* tr = ctx_.thread_result;

    // Escape — unfocus.
    if (event == Event::Escape) {
        set_focused(false);
        return true;
    }

    // j / Down — move cursor down.
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (tr && cursor_ < tr->thread_count() - 1) {
            cursor_++;
        }
        return true;
    }

    // k / Up — move cursor up.
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (cursor_ > 0) {
            cursor_--;
        }
        return true;
    }

    // Enter — jump to first instruction of selected thread.
    if (event == Event::Return) {
        if (tr && cursor_ < tr->thread_count()) {
            size_t i = 0;
            for (const auto& [tid, info] : tr->threads) {
                if (i == cursor_) {
                    ctx_.navigate_to(info.first_seen_inst);
                    set_focused(false);
                    break;
                }
                i++;
            }
        }
        return true;
    }

    // T / n — jump to next thread switch.
    if (event == Event::Character('T') || event == Event::Character('n')) {
        goto_next_thread_switch();
        return true;
    }

    // P / p / N — jump to previous thread switch.
    if (event == Event::Character('p') || event == Event::Character('N')) {
        goto_prev_thread_switch();
        return true;
    }

    return false;
}

// ─── switch helpers ──────────────────────────────────────────────────────

void ThreadPanel::goto_next_thread_switch() {
    const auto* tr = ctx_.thread_result;
    if (!tr) return;
    auto* ev = tr->next_switch_after(ctx_.current_inst);
    if (ev) {
        ctx_.navigate_to(ev->inst_id);
    }
}

void ThreadPanel::goto_prev_thread_switch() {
    const auto* tr = ctx_.thread_result;
    if (!tr) return;
    auto* ev = tr->prev_switch_before(ctx_.current_inst);
    if (ev) {
        ctx_.navigate_to(ev->inst_id);
    }
}

}  // namespace tenet

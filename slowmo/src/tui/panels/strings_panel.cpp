#include "strings_panel.h"

#include "tui/tui_context.h"
#include "analysis/passes/string_pass.h"

#include <fmt/format.h>
#include <ftxui/dom/elements.hpp>

namespace tenet {

using namespace ftxui;

// ─── update_filter ───────────────────────────────────────────────────────

void StringsPanel::update_filter() {
    filtered_indices_.clear();
    const auto* sr = ctx_.string_result;
    if (!sr) return;

    if (filter_.empty()) {
        // Show all strings.
        for (size_t i = 0; i < sr->strings.size(); i++) {
            filtered_indices_.push_back(i);
        }
    } else {
        // Case-insensitive substring match via StringResult::search().
        auto results = sr->search(filter_);
        for (auto* ref : results) {
            size_t idx = static_cast<size_t>(ref - sr->strings.data());
            filtered_indices_.push_back(idx);
        }
    }

    // Clamp cursor.
    if (cursor_ >= filtered_indices_.size() && !filtered_indices_.empty()) {
        cursor_ = filtered_indices_.size() - 1;
    }
}

// ─── render ──────────────────────────────────────────────────────────────

Element StringsPanel::render() {
    Elements lines;

    const auto* sr = ctx_.string_result;

    // Header — highlight when focused.
    auto header_label = focused_
        ? text("[STRINGS]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Strings")  | bold | color(Color::Yellow);

    lines.push_back(hbox({
        header_label,
        text(fmt::format("  ({}/{})",
            filtered_indices_.size(),
            sr ? sr->total() : 0)) | color(Color::GrayLight),
    }));

    // Show active filter.
    if (!filter_.empty()) {
        lines.push_back(hbox({
            text("  filter: ") | color(Color::GrayLight),
            text(filter_) | color(Color::Cyan),
        }));
    }
    lines.push_back(separator());

    if (!sr || filtered_indices_.empty()) {
        lines.push_back(text("(no strings)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
    }

    // Show a window of strings around the cursor.
    const int visible_count = 12;
    int start = 0;
    int total = static_cast<int>(filtered_indices_.size());
    if (total > visible_count) {
        start = static_cast<int>(cursor_) - visible_count / 2;
        if (start < 0) start = 0;
        if (start + visible_count > total) start = total - visible_count;
    }
    int end = std::min(start + visible_count, total);

    for (int i = start; i < end; i++) {
        size_t str_idx = filtered_indices_[i];
        const auto& ref = sr->strings[str_idx];
        bool is_cursor = (static_cast<size_t>(i) == cursor_);

        // Truncate long strings for display.
        std::string display_str = ref.content;
        if (display_str.size() > 32) {
            display_str = display_str.substr(0, 29) + "...";
        }

        // Encoding label.
        const char* enc_label = "A";
        if (ref.encoding == StringRef::UTF16LE) enc_label = "U";
        else if (ref.encoding == StringRef::UTF8) enc_label = "8";
        else if (ref.encoding == StringRef::Wide) enc_label = "W";

        auto line = hbox({
            text(is_cursor ? ">" : " ") | color(Color::Yellow),
            text(fmt::format("[{}]", enc_label)) | color(Color::GrayLight),
            text(" ") | size(WIDTH, EQUAL, 1),
            text(fmt::format("{:x}", ref.addr)) | color(Color::Cyan),
            text(" ") | size(WIDTH, EQUAL, 1),
            text(fmt::format("\"{}\"", display_str)) | color(Color::Green),
            text(fmt::format(" ({})", ref.references.size())) | color(Color::GrayLight),
        });

        if (is_cursor) {
            line = line | bgcolor(Color::GrayDark);
        }
        lines.push_back(line);
    }

    // Footer with keybinding help.
    lines.push_back(separator());
    lines.push_back(text("j/k:nav Enter:jump /:filter c:clear g/G:top/bot") | color(Color::GrayDark));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
}

// ─── handle_event ────────────────────────────────────────────────────────

bool StringsPanel::handle_event(Event event) {
    // Escape — unfocus.
    if (event == Event::Escape) {
        set_focused(false);
        return true;
    }

    // j / Down — move cursor down.
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (!filtered_indices_.empty() &&
            cursor_ < filtered_indices_.size() - 1) {
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

    // Enter — jump to the instruction that first discovered this string.
    if (event == Event::Return) {
        if (!filtered_indices_.empty() &&
            cursor_ < filtered_indices_.size()) {
            size_t str_idx = filtered_indices_[cursor_];
            const auto& ref = ctx_.string_result->strings[str_idx];
            ctx_.navigate_to(ref.discovered_at);
            set_focused(false);
        }
        return true;
    }

    // / — open filter input (signals to parent that filter dialog is needed).
    if (event == Event::Character('/')) {
        // The parent TuiApp handles dialog display; this returns false to
        // let the parent intercept, or we can signal via a callback.
        // For panel encapsulation, we just return true and the parent checks
        // a flag or the panel exposes a "wants_filter_dialog" state.
        // For now, return false so the parent's dialog handling picks it up.
        return false;
    }

    // c / C — clear filter.
    if (event == Event::Character('c') || event == Event::Character('C')) {
        clear_filter();
        return true;
    }

    // G — jump to last string.
    if (event == Event::Character('G')) {
        if (!filtered_indices_.empty()) {
            cursor_ = filtered_indices_.size() - 1;
        }
        return true;
    }

    // g — jump to first string.
    if (event == Event::Character('g')) {
        cursor_ = 0;
        return true;
    }

    return false;
}

}  // namespace tenet

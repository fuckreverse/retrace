#include "functions_panel.h"
#include "analysis/passes/structure/function_pass.h"
#include "io/trace_reader.h"

#include <algorithm>
#include <fmt/format.h>
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

namespace tenet {

// ─── Sorting / filtering ─────────────────────────────────────────────────────

void FunctionsPanel::update_list() {
    if (!ctx_.function_result) return;

    // Collect all entry PCs
    sorted_pcs_.clear();
    sorted_pcs_.reserve(ctx_.function_result->functions.size());
    for (const auto& [pc, info] : ctx_.function_result->functions) {
        sorted_pcs_.push_back(pc);
    }

    // Sort based on current mode
    switch (sort_mode_) {
    case 0:  // by call count descending
        std::sort(sorted_pcs_.begin(), sorted_pcs_.end(),
            [&](uint64_t a, uint64_t b) {
                return ctx_.function_result->functions.at(a).total_calls >
                       ctx_.function_result->functions.at(b).total_calls;
            });
        break;
    case 1:  // by name ascending
        std::sort(sorted_pcs_.begin(), sorted_pcs_.end(),
            [&](uint64_t a, uint64_t b) {
                return ctx_.function_result->functions.at(a).name <
                       ctx_.function_result->functions.at(b).name;
            });
        break;
    case 2:  // by entry PC ascending
        std::sort(sorted_pcs_.begin(), sorted_pcs_.end());
        break;
    }

    update_filter();
}

void FunctionsPanel::update_filter() {
    filtered_indices_.clear();
    if (!ctx_.function_result) return;

    if (filter_.empty()) {
        for (size_t i = 0; i < sorted_pcs_.size(); i++) {
            filtered_indices_.push_back(i);
        }
    } else {
        // Case-insensitive substring match on function name
        std::string lower_filter = filter_;
        std::transform(lower_filter.begin(), lower_filter.end(),
                       lower_filter.begin(), ::tolower);
        for (size_t i = 0; i < sorted_pcs_.size(); i++) {
            const auto& info = ctx_.function_result->functions.at(sorted_pcs_[i]);
            std::string lower_name = info.name;
            std::transform(lower_name.begin(), lower_name.end(),
                           lower_name.begin(), ::tolower);
            if (lower_name.find(lower_filter) != std::string::npos) {
                filtered_indices_.push_back(i);
            }
        }
    }

    if (cursor_ >= filtered_indices_.size()) {
        cursor_ = filtered_indices_.empty() ? 0 : filtered_indices_.size() - 1;
    }
}

// ─── Render ──────────────────────────────────────────────────────────────────

Element FunctionsPanel::render() {
    Elements lines;

    // Header with focus indicator and stats
    const char* sort_label = "calls";
    if (sort_mode_ == 1) sort_label = "name";
    else if (sort_mode_ == 2) sort_label = "addr";

    auto header_label = focused_
        ? text("[FUNCTIONS]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Functions") | bold | color(Color::Yellow);

    lines.push_back(hbox({
        header_label,
        text(fmt::format("  ({}/{}) sort:{}",
            filtered_indices_.size(),
            ctx_.function_result ? ctx_.function_result->functions.size() : 0,
            sort_label)) | color(Color::GrayLight),
    }));

    if (!filter_.empty()) {
        lines.push_back(hbox({
            text("  filter: ") | color(Color::GrayLight),
            text(filter_) | color(Color::Cyan),
        }));
    }
    lines.push_back(separator());

    if (!ctx_.function_result || filtered_indices_.empty()) {
        lines.push_back(text("(no functions)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 42) | border;
    }

    // Windowed display around cursor
    const int visible_count = 14;
    int start = 0;
    int total = static_cast<int>(filtered_indices_.size());
    if (total > visible_count) {
        start = static_cast<int>(cursor_) - visible_count / 2;
        if (start < 0) start = 0;
        if (start + visible_count > total) start = total - visible_count;
    }
    int end = std::min(start + visible_count, total);

    for (int i = start; i < end; i++) {
        size_t idx = filtered_indices_[i];
        uint64_t pc = sorted_pcs_[idx];
        const auto& info = ctx_.function_result->functions.at(pc);
        bool is_cursor = (static_cast<size_t>(i) == cursor_);

        uint64_t static_pc = pc - ctx_.reader->header().module_slide;

        // Truncate long names for display
        std::string display_name = info.name;
        if (display_name.size() > 22) {
            display_name = display_name.substr(0, 19) + "...";
        }

        auto line = hbox({
            text(is_cursor ? ">" : " ") | color(Color::Yellow),
            text(fmt::format("{:x}", static_pc)) | color(Color::Cyan),
            text(" ") | size(WIDTH, EQUAL, 1),
            text(display_name) | color(Color::White),
            text(fmt::format(" c={} i={}",
                info.total_calls, info.total_instructions)) | color(Color::GrayLight),
        });

        if (is_cursor) {
            line = line | bgcolor(Color::GrayDark);
        }
        lines.push_back(line);
    }

    // Footer with help
    lines.push_back(separator());
    lines.push_back(
        text("j/k:nav Enter:jump /:filter c:clear s:sort g/G:top/bot") | color(Color::GrayDark));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 42) | border;
}

// ─── Event handling ──────────────────────────────────────────────────────────

bool FunctionsPanel::handle_event(Event event) {
    if (event == Event::Escape) {
        focused_ = false;
        return true;
    }

    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (!filtered_indices_.empty() &&
            cursor_ < filtered_indices_.size() - 1) {
            cursor_++;
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (cursor_ > 0) {
            cursor_--;
        }
        return true;
    }

    if (event == Event::Return) {
        // Jump to the first call of the selected function
        if (!filtered_indices_.empty() &&
            cursor_ < filtered_indices_.size()) {
            size_t idx = filtered_indices_[cursor_];
            uint64_t pc = sorted_pcs_[idx];
            const auto& info = ctx_.function_result->functions.at(pc);
            if (!info.call_event_indices.empty()) {
                // call_inst_id + 1 = first instruction inside the callee
                const auto& evt = ctx_.function_result->call_events[info.call_event_indices[0]];
                ctx_.navigate_to(evt.call_inst_id + 1);
            }
            focused_ = false;
        }
        return true;
    }

    if (event == Event::Character('/')) {
        // Enter filter mode: append typed chars until Enter/Esc
        // For now, clear the filter (the dialog is handled by TuiApp)
        // This event is intercepted so the panel can signal intent.
        return false;  // Let TuiApp open the filter dialog
    }

    if (event == Event::Character('c') || event == Event::Character('C')) {
        // Clear filter
        filter_.clear();
        update_filter();
        cursor_ = 0;
        return true;
    }

    if (event == Event::Character('s') || event == Event::Character('S')) {
        // Cycle sort mode: calls → name → addr → calls ...
        sort_mode_ = (sort_mode_ + 1) % 3;
        update_list();
        cursor_ = 0;
        return true;
    }

    if (event == Event::Character('g')) {
        cursor_ = 0;
        return true;
    }
    if (event == Event::Character('G')) {
        if (!filtered_indices_.empty()) {
            cursor_ = filtered_indices_.size() - 1;
        }
        return true;
    }

    return false;
}

}  // namespace tenet

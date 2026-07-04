#include "callstack_panel.h"
#include "analysis/passes/structure/function_pass.h"
#include "io/trace_reader.h"

#include <fmt/format.h>
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

namespace tenet {

Element CallstackPanel::render() {
    Elements lines;

    // Header with focus indicator
    auto header_label = focused_
        ? text("[CALL STACK]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Call Stack") | bold | color(Color::Yellow);
    lines.push_back(header_label);
    lines.push_back(separator());

    if (!ctx_.function_result) {
        lines.push_back(text("(not computed)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 30) | border;
    }

    auto stack = ctx_.function_result->call_stack_at(ctx_.current_inst);
    if (stack.empty()) {
        lines.push_back(text("<top-level>") | color(Color::GrayLight));
    } else {
        for (size_t i = 0; i < stack.size(); i++) {
            auto* evt = stack[i];
            uint64_t static_target = evt->target_pc - ctx_.reader->header().module_slide;
            std::string label;

            // Look up function name
            auto it = ctx_.function_result->functions.find(evt->target_pc);
            if (it != ctx_.function_result->functions.end()) {
                label = it->second.name;
            } else {
                label = fmt::format("sub_{:x}", static_target);
            }

            bool is_frame_cursor = focused_ && (cursor_ == i);
            bool is_current_frame = (i == stack.size() - 1);

            auto frame_marker = text(is_frame_cursor ? ">" : (is_current_frame ? "*" : " "))
                | color(is_frame_cursor ? Color::White : Color::Yellow);

            auto depth_prefix = std::string(i * 2, ' ');
            auto line = hbox({
                text(depth_prefix) | size(WIDTH, EQUAL, static_cast<int>(i * 2)),
                frame_marker,
                text(" "),
                text(label) | color(Color::Cyan),
                text(fmt::format("  @{}", evt->call_inst_id)) | color(Color::GrayLight),
            });

            if (is_frame_cursor) {
                line = line | bgcolor(Color::GrayDark);
            }
            lines.push_back(line);
        }
    }

    // Show current function
    lines.push_back(separator());
    auto* func = ctx_.function_result->function_at(ctx_.current_inst);
    if (func) {
        lines.push_back(hbox({
            text("In: ") | color(Color::White),
            text(func->name) | color(Color::Cyan),
            text(fmt::format("  (calls={})", func->total_calls)) | color(Color::GrayLight),
        }));
    }

    // Footer hint when focused
    if (focused_) {
        lines.push_back(separator());
        lines.push_back(text("j/k:frame Enter:call-site c:func-entry Esc:unfocus") | color(Color::GrayDark));
    }

    return vbox(lines) | size(WIDTH, GREATER_THAN, 30) | border;
}

bool CallstackPanel::handle_event(Event event) {
    if (event == Event::Escape) {
        focused_ = false;
        return true;
    }

    if (!ctx_.function_result) return true;

    auto stack = ctx_.function_result->call_stack_at(ctx_.current_inst);
    if (stack.empty()) {
        return true;
    }

    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (cursor_ + 1 < stack.size()) {
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
        // Jump to the call site (the bl/blr instruction that made this call)
        if (cursor_ < stack.size()) {
            auto* evt = stack[cursor_];
            ctx_.navigate_to(evt->call_inst_id);
            focused_ = false;
        }
        return true;
    }

    if (event == Event::Character('c') || event == Event::Character('C')) {
        // Jump to the function entry (first instruction of the callee)
        if (cursor_ < stack.size()) {
            auto* evt = stack[cursor_];
            ctx_.navigate_to(evt->call_inst_id + 1);  // +1 = first inst in callee
            focused_ = false;
        }
        return true;
    }

    if (event == Event::Character('g')) {
        cursor_ = 0;
        return true;
    }
    if (event == Event::Character('G')) {
        if (!stack.empty()) cursor_ = stack.size() - 1;
        return true;
    }

    return false;
}

}  // namespace tenet

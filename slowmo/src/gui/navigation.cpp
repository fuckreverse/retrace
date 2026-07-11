// navigation.cpp — row fetching, navigation history, bookmarks, taint jumps.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"

#include <fmt/core.h>

#include <algorithm>
#include <string>

namespace tenet {

// ─── Data helpers ───────────────────────────────────────────────────────────

InstructionRow GuiApp::fetch_row(uint64_t inst_id) {
    return service_->fetch_row(inst_id);
}

// ─── Navigation History ─────────────────────────────────────────────────────

void GuiApp::nav_push(uint64_t inst_id) {
    if (nav_history_navigating_) return;
    // If we're in the middle of the history (after going back), truncate forward history
    if (!nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1) {
        nav_history_.erase(nav_history_.begin() + static_cast<ptrdiff_t>(nav_history_pos_) + 1,
                           nav_history_.end());
    }
    // Avoid duplicate consecutive entries
    if (!nav_history_.empty() && nav_history_.back() == inst_id) return;
    nav_history_.push_back(inst_id);
    if (nav_history_.size() > kMaxNavHistory) {
        nav_history_.erase(nav_history_.begin());
    }
    nav_history_pos_ = nav_history_.size() - 1;
}

void GuiApp::nav_back() {
    service_->nav_back();
    current_inst_ = service_->current_inst();
    scroll_to_current_ = true;
}

void GuiApp::nav_forward() {
    service_->nav_forward();
    current_inst_ = service_->current_inst();
    scroll_to_current_ = true;
}

bool GuiApp::can_nav_back() const {
    return nav_history_pos_ > 0;
}

bool GuiApp::can_nav_forward() const {
    return !nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1;
}

void GuiApp::navigate_to(uint64_t inst_id) {
    service_->navigate_to(inst_id);
    current_inst_ = service_->current_inst();
    scroll_to_current_ = true;
    taint_sorted_ids_dirty_ = true;
}

void GuiApp::navigate_to_instructions(uint64_t inst_id) {
    navigate_to(inst_id);
    // Bring the "Instructions" dock tab to the front so the user can see where
    // we landed.  pending_focus_windows_ is processed at the top of each frame
    // inside the DockSpaceHost scope (render_frame), which calls SetWindowFocus.
    pending_focus_windows_.push_back("Instructions");
}

void GuiApp::toggle_bookmark() {
    service_->toggle_bookmark(current_inst_);
    bookmarks_ = service_->bookmarks();
    row_cache_.put(current_inst_, fetch_row(current_inst_));
}

// ─── Taint jump helpers ──────────────────────────────────────────────────────

void GuiApp::ensure_taint_sorted() {
    if (!taint_sorted_ids_dirty_) return;
    taint_sorted_ids_.clear();
    if (taint_result_) {
        for (uint64_t id : taint_result_->tainted_inst_ids) {
            taint_sorted_ids_.push_back(id);
        }
        std::sort(taint_sorted_ids_.begin(), taint_sorted_ids_.end());
    }
    taint_sorted_ids_dirty_ = false;
}

void GuiApp::ensure_backward_taint_sorted() {
    if (!backward_taint_sorted_ids_dirty_) return;
    backward_taint_sorted_ids_.clear();
    if (backward_taint_result_) {
        backward_taint_sorted_ids_.reserve(
            backward_taint_result_->contributing_count());
        for (uint64_t id : backward_taint_result_->contributing_inst_ids) {
            backward_taint_sorted_ids_.push_back(id);
        }
        std::sort(backward_taint_sorted_ids_.begin(),
                  backward_taint_sorted_ids_.end());
    }
    backward_taint_sorted_ids_dirty_ = false;
}

void GuiApp::jump_taint_next() {
    if (!taint_result_) return;
    ensure_taint_sorted();
    if (taint_sorted_ids_.empty()) return;
    auto it = std::upper_bound(taint_sorted_ids_.begin(), taint_sorted_ids_.end(), current_inst_);
    if (it == taint_sorted_ids_.end()) {
        // Wrap around
        navigate_to(taint_sorted_ids_.front());
    } else {
        navigate_to(*it);
    }
}

void GuiApp::jump_taint_prev() {
    if (!taint_result_) return;
    ensure_taint_sorted();
    if (taint_sorted_ids_.empty()) return;
    auto it = std::lower_bound(taint_sorted_ids_.begin(), taint_sorted_ids_.end(), current_inst_);
    if (it == taint_sorted_ids_.begin()) {
        // Wrap around
        navigate_to(taint_sorted_ids_.back());
    } else {
        --it;
        navigate_to(*it);
    }
}

void GuiApp::jump_backward_taint_next() {
    if (!backward_taint_result_) return;
    ensure_backward_taint_sorted();
    if (backward_taint_sorted_ids_.empty()) return;
    auto it = std::upper_bound(backward_taint_sorted_ids_.begin(),
                               backward_taint_sorted_ids_.end(),
                               current_inst_);
    if (it == backward_taint_sorted_ids_.end()) {
        navigate_to(backward_taint_sorted_ids_.front());
    } else {
        navigate_to(*it);
    }
}

void GuiApp::jump_backward_taint_prev() {
    if (!backward_taint_result_) return;
    ensure_backward_taint_sorted();
    if (backward_taint_sorted_ids_.empty()) return;
    auto it = std::lower_bound(backward_taint_sorted_ids_.begin(),
                               backward_taint_sorted_ids_.end(),
                               current_inst_);
    if (it == backward_taint_sorted_ids_.begin()) {
        navigate_to(backward_taint_sorted_ids_.back());
    } else {
        --it;
        navigate_to(*it);
    }
}

}  // namespace tenet

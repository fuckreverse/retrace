// navigation.cpp — row fetching, navigation history, bookmarks, taint jumps.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/backward_taint_pass.h"

#include <fmt/core.h>

#include <algorithm>
#include <string>

namespace tenet {

// ─── Data helpers ───────────────────────────────────────────────────────────

InstructionRow GuiApp::fetch_row(uint64_t inst_id) {
    auto cached = row_cache_.get(inst_id);
    if (cached) return *cached;

    InstructionRow row{};
    row.inst_id = inst_id;

    auto [offset, seed_pc] = index_.offset_of_with_pc(inst_id, reader_);
    // Pass seed_pc: record_at(offset, seed_pc) sets resolved_pc so as_inst()
    // uses the correct 6-byte v5 header layout (vs 16-byte v4) when needed.
    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind != RecordKind::Inst) {
        row.disasm = "<not an instruction>";
        row_cache_.put(inst_id, row);
        return row;
    }

    auto inst = rec.as_inst();
    row.pc = inst.pc;
    row.static_pc = inst.pc - reader_.header().module_slide;
    row.nzcv = inst.nzcv;
    row.reg_diff_count = inst.reg_diff_count;
    row.mem_access_count = inst.mem_access_count;

    auto opcode = code_table_.opcode_at(inst.pc);
    if (opcode) {
        auto d = decoder_.decode(inst.pc, *opcode);
        if (d) {
            row.mnemonic = d->mnemonic;
            row.operands = d->op_str;
            row.disasm = fmt::format("{} {}", d->mnemonic, d->op_str);
        } else {
            row.mnemonic = ".word";
            row.operands = fmt::format("0x{:08x}", *opcode);
            row.disasm = fmt::format(".word 0x{:08x}", *opcode);
        }
    } else {
        row.mnemonic = "";
        row.operands = "";
        row.disasm = "<no code>";
    }

    row.has_bookmark = std::binary_search(bookmarks_.begin(), bookmarks_.end(), inst_id);

    row_cache_.put(inst_id, row);
    return row;
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
    if (!can_nav_back()) return;
    nav_history_navigating_ = true;
    nav_history_pos_--;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

void GuiApp::nav_forward() {
    if (!can_nav_forward()) return;
    nav_history_navigating_ = true;
    nav_history_pos_++;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

bool GuiApp::can_nav_back() const {
    return nav_history_pos_ > 0;
}

bool GuiApp::can_nav_forward() const {
    return !nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1;
}

void GuiApp::navigate_to(uint64_t inst_id) {
    if (inst_id >= total_inst_) inst_id = total_inst_ > 0 ? total_inst_ - 1 : 0;
    nav_push(inst_id);
    current_inst_ = inst_id;
    // Mark taint sorted list dirty so next jump recomputes
    taint_sorted_ids_dirty_ = true;
}

void GuiApp::toggle_bookmark() {
    auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), current_inst_);
    if (it != bookmarks_.end() && *it == current_inst_) {
        bookmarks_.erase(it);
    } else {
        bookmarks_.insert(it, current_inst_);
    }
    // Invalidate cache for this row so bookmark state is refreshed
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
    // Build sorted list on the fly from backward taint contributing inst_ids
    std::vector<uint64_t> ids;
    for (uint64_t id = 0; id < total_inst_; id++) {
        if (backward_taint_result_->is_contributing(id)) {
            ids.push_back(id);
        }
    }
    if (ids.empty()) return;
    auto it = std::upper_bound(ids.begin(), ids.end(), current_inst_);
    if (it == ids.end()) {
        navigate_to(ids.front());
    } else {
        navigate_to(*it);
    }
}

void GuiApp::jump_backward_taint_prev() {
    if (!backward_taint_result_) return;
    std::vector<uint64_t> ids;
    for (uint64_t id = 0; id < total_inst_; id++) {
        if (backward_taint_result_->is_contributing(id)) {
            ids.push_back(id);
        }
    }
    if (ids.empty()) return;
    auto it = std::lower_bound(ids.begin(), ids.end(), current_inst_);
    if (it == ids.begin()) {
        navigate_to(ids.back());
    } else {
        --it;
        navigate_to(*it);
    }
}

}  // namespace tenet

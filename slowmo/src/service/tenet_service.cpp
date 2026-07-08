// tools/tenet/src/service/tenet_service.cpp
#include "service/tenet_service.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"

#include <algorithm>

namespace tenet {

// ─── Construction / Destruction ─────────────────────────────────────────────

TenetService::TenetService(TraceReader& reader,
                           TraceIndex& index,
                           CodeTable& code_table,
                           InstructionDecoder& decoder,
                           RegisterFile& regfile,
                           MemoryModel& memory,
                           const std::string& trace_path)
    : reader_(reader), index_(index), code_table_(code_table),
      decoder_(decoder), regfile_(regfile), memory_(memory),
      trace_path_(trace_path.empty() ? reader.path().string() : trace_path) {
    total_inst_ = index.inst_count();

    // Restore persisted state from RocksDB
    bookmarks_ = index_.load_bookmarks();
    uint64_t last = index_.load_last_inst();
    if (last > 0 && last < total_inst_) {
        current_inst_ = last;
    }
}

TenetService::~TenetService() {
    // Persist cursor position for "continue where you left off"
    index_.save_last_inst(current_inst_);
}

// ─── Navigation ─────────────────────────────────────────────────────────────

void TenetService::navigate_to(uint64_t inst_id) {
    if (total_inst_ > 0 && inst_id >= total_inst_) inst_id = total_inst_ - 1;
    current_inst_ = inst_id;
    if (!nav_history_navigating_) {
        nav_push(inst_id);
    }
    notify_navigation(inst_id);
}

void TenetService::nav_push(uint64_t inst_id) {
    // Truncate forward history if we navigated backward then somewhere new
    if (nav_history_pos_ + 1 < nav_history_.size()) {
        nav_history_.resize(nav_history_pos_ + 1);
    }
    nav_history_.push_back(inst_id);
    if (nav_history_.size() > kMaxNavHistory) {
        nav_history_.erase(nav_history_.begin());
    }
    nav_history_pos_ = nav_history_.size() - 1;
}

void TenetService::nav_back() {
    if (!can_nav_back()) return;
    nav_history_navigating_ = true;
    nav_history_pos_--;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

void TenetService::nav_forward() {
    if (!can_nav_forward()) return;
    nav_history_navigating_ = true;
    nav_history_pos_++;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

bool TenetService::can_nav_back() const {
    return nav_history_pos_ > 0;
}

bool TenetService::can_nav_forward() const {
    return nav_history_pos_ + 1 < nav_history_.size();
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

void TenetService::toggle_bookmark(uint64_t inst_id) {
    auto it = std::find(bookmarks_.begin(), bookmarks_.end(), inst_id);
    if (it != bookmarks_.end()) {
        bookmarks_.erase(it);
    } else {
        bookmarks_.push_back(inst_id);
    }
    index_.save_bookmarks(bookmarks_);
    notify_bookmark_changed();
}

bool TenetService::has_bookmark(uint64_t inst_id) const {
    return std::find(bookmarks_.begin(), bookmarks_.end(), inst_id) != bookmarks_.end();
}

// ─── Instruction row fetching ───────────────────────────────────────────────

InstructionRow TenetService::fetch_row(uint64_t inst_id) {
    // Check cache first
    auto cached = row_cache_.get(inst_id);
    if (cached) return cached->get();

    // Build row from backend
    InstructionRow row{};
    row.inst_id = inst_id;

    auto offset_result = index_.offset_of_with_pc(inst_id, reader_);
    if (offset_result.offset == 0) return row;

    auto rec = reader_.record_at(offset_result.offset, offset_result.seed_pc);
    if (rec.kind != RecordKind::Inst) return row;

    auto inst = rec.as_inst();
    uint64_t pc = inst.pc != 0 ? inst.pc : rec.resolved_pc;
    row.pc = pc;
    row.static_pc = pc - reader_.header().module_slide;
    row.nzcv = inst.nzcv_flags();
    row.reg_diff_count = inst.reg_diff_count;
    row.mem_access_count = inst.mem_access_count;
    row.has_bookmark = has_bookmark(inst_id);

    // Decode instruction
    auto opcode = code_table_.opcode_at(pc);
    if (opcode) {
        auto decoded = decoder_.decode(pc, *opcode);
        if (decoded) {
            row.mnemonic = std::string(decoded->mnemonic_sv());
            row.operands = std::string(decoded->op_str_sv());
            row.disasm = row.operands.empty()
                             ? row.mnemonic
                             : row.mnemonic + " " + row.operands;
        }
    }

    row_cache_.put(inst_id, row);
    return row;
}

// ─── Pass management ────────────────────────────────────────────────────────

PassManager& TenetService::ensure_pass_manager() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }
    return *pass_manager_;
}

void TenetService::run_default_passes() {
    auto& pm = ensure_pass_manager();
    register_default_passes(pm);
    for (auto name : default_ui_pass_names()) {
        auto sp = pm.require_shared(name);
        if (sp && sp->ok()) {
            pinned_results_[std::string(name)] = sp;
            notify_pass_completed(name);
        }
    }
}

bool TenetService::run_pass(std::string_view name, const PassRunCtx& ctx) {
    auto& pm = ensure_pass_manager();
    if (!register_pass_by_name(pm, name, ctx)) return false;
    auto sp = pm.require_shared(name);
    if (!sp || !sp->ok()) return false;
    pinned_results_[std::string(name)] = sp;
    notify_pass_completed(name);
    return true;
}

void TenetService::clear_analysis() {
    pinned_results_.clear();
    if (pass_manager_) {
        pass_manager_->cancel_all();
        pass_manager_->invalidate_all();
    }
}

// ─── Search ─────────────────────────────────────────────────────────────────

void TenetService::search_forward(const std::string& query, uint64_t from_inst) {
    search_results_.clear();
    search_current_ = 0;
    if (query.empty()) {
        search_active_ = false;
        return;
    }
    search_active_ = true;

    // Simple linear search through instruction disassembly
    for (uint64_t i = from_inst; i < total_inst_ && search_results_.size() < 10000; ++i) {
        auto row = fetch_row(i);
        if (row.disasm.find(query) != std::string::npos) {
            search_results_.push_back(i);
        }
    }
    // Wrap around
    for (uint64_t i = 0; i < from_inst && search_results_.size() < 10000; ++i) {
        auto row = fetch_row(i);
        if (row.disasm.find(query) != std::string::npos) {
            search_results_.push_back(i);
        }
    }
}

void TenetService::search_clear() {
    search_results_.clear();
    search_current_ = 0;
    search_active_ = false;
}

// ─── Observers ──────────────────────────────────────────────────────────────

void TenetService::add_observer(TenetServiceObserver* obs) {
    std::lock_guard lock(observers_mutex_);
    observers_.push_back(obs);
}

void TenetService::remove_observer(TenetServiceObserver* obs) {
    std::lock_guard lock(observers_mutex_);
    observers_.erase(std::remove(observers_.begin(), observers_.end(), obs), observers_.end());
}

void TenetService::notify_navigation(uint64_t inst_id) {
    std::vector<TenetServiceObserver*> snapshot;
    {
        std::lock_guard lock(observers_mutex_);
        snapshot = observers_;
    }
    for (auto* obs : snapshot) obs->on_navigation(inst_id);
}

void TenetService::notify_pass_completed(std::string_view name) {
    std::vector<TenetServiceObserver*> snapshot;
    {
        std::lock_guard lock(observers_mutex_);
        snapshot = observers_;
    }
    for (auto* obs : snapshot) obs->on_pass_completed(name);
}

void TenetService::notify_bookmark_changed() {
    std::vector<TenetServiceObserver*> snapshot;
    {
        std::lock_guard lock(observers_mutex_);
        snapshot = observers_;
    }
    for (auto* obs : snapshot) obs->on_bookmark_changed();
}

}  // namespace tenet

// tools/tenet/src/service/tenet_service.cpp
#include "service/tenet_service.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/passes/structure/xref_pass.h"

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
    total_inst_.store(index.inst_count(), std::memory_order_relaxed);

    // Restore persisted state from RocksDB
    {
        std::unique_lock lk(state_mutex_);
        bookmarks_ = index_.load_bookmarks();
        // Build O(1) lookup mirror
        for (uint64_t bm : bookmarks_) bookmark_set_.insert(bm);
    }
    uint64_t last = index_.load_last_inst();
    uint64_t total = total_inst_.load(std::memory_order_relaxed);
    if (last > 0 && last < total) {
        current_inst_.store(last, std::memory_order_relaxed);
    }
}

TenetService::~TenetService() {
    // Persist cursor position for "continue where you left off"
    index_.save_last_inst(current_inst_.load(std::memory_order_relaxed));
}

// ─── Navigation ─────────────────────────────────────────────────────────────

void TenetService::navigate_to(uint64_t inst_id) {
    uint64_t total = total_inst_.load(std::memory_order_relaxed);
    if (total > 0 && inst_id >= total) inst_id = total - 1;
    current_inst_.store(inst_id, std::memory_order_relaxed);
    {
        std::unique_lock lk(state_mutex_);
        if (!nav_history_navigating_) {
            nav_push(inst_id);
        }
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
    std::unique_lock lk(state_mutex_);
    // Inline can_nav_back() check — can't call it while holding the lock
    // (it would try to acquire state_mutex_ in shared mode → deadlock).
    if (nav_history_pos_ == 0) return;
    nav_history_navigating_ = true;
    nav_history_pos_--;
    uint64_t target = nav_history_[nav_history_pos_];
    lk.unlock();
    navigate_to(target);
    {
        std::unique_lock lk2(state_mutex_);
        nav_history_navigating_ = false;
    }
}

void TenetService::nav_forward() {
    std::unique_lock lk(state_mutex_);
    // Inline can_nav_forward() check — can't call it while holding the lock.
    if (nav_history_pos_ + 1 >= nav_history_.size()) return;
    nav_history_navigating_ = true;
    nav_history_pos_++;
    uint64_t target = nav_history_[nav_history_pos_];
    lk.unlock();
    navigate_to(target);
    {
        std::unique_lock lk2(state_mutex_);
        nav_history_navigating_ = false;
    }
}

bool TenetService::can_nav_back() const {
    std::shared_lock lk(state_mutex_);
    return nav_history_pos_ > 0;
}

bool TenetService::can_nav_forward() const {
    std::shared_lock lk(state_mutex_);
    return nav_history_pos_ + 1 < nav_history_.size();
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

void TenetService::toggle_bookmark(uint64_t inst_id) {
    std::unique_lock lk(state_mutex_);
    auto it = std::find(bookmarks_.begin(), bookmarks_.end(), inst_id);
    if (it != bookmarks_.end()) {
        bookmarks_.erase(it);
        bookmark_set_.erase(inst_id);
    } else {
        bookmarks_.push_back(inst_id);
        bookmark_set_.insert(inst_id);
    }
    auto bm_copy = bookmarks_;  // copy under lock
    lk.unlock();
    index_.save_bookmarks(bm_copy);
    notify_bookmark_changed();
}

bool TenetService::has_bookmark(uint64_t inst_id) const {
    std::shared_lock lk(state_mutex_);
    return bookmark_set_.count(inst_id) > 0;
}

// ─── Instruction row fetching ───────────────────────────────────────────────

InstructionRow TenetService::fetch_row(uint64_t inst_id) {
    // Check cache first (short lock — LRU get mutates order)
    {
        std::lock_guard lk(row_cache_mutex_);
        auto cached = row_cache_.get(inst_id);
        if (cached) return cached->get();
    }

    // Build row from backend (no lock needed — backend objects are thread-safe)
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

    // Insert into cache (short lock)
    {
        std::lock_guard lk(row_cache_mutex_);
        row_cache_.put(inst_id, row);
    }
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
        pass_manager_->init_infra();
    }
    return *pass_manager_;
}

void TenetService::run_default_passes() {
    auto& pm = ensure_pass_manager();
    register_default_passes(pm);
    for (auto name : default_ui_pass_names()) {
        auto sp = pm.require_shared(name);
        if (sp && sp->ok()) {
            std::unique_lock lk(state_mutex_);
            pinned_results_[std::string(name)] = sp;
            lk.unlock();
            notify_pass_completed(name);
        }
    }
}

bool TenetService::run_pass(std::string_view name, const PassRunCtx& ctx) {
    auto& pm = ensure_pass_manager();
    if (!register_pass_by_name(pm, name, ctx)) return false;
    auto sp = pm.require_shared(name);
    if (!sp || !sp->ok()) return false;
    {
        std::unique_lock lk(state_mutex_);
        pinned_results_[std::string(name)] = sp;
    }
    notify_pass_completed(name);
    return true;
}

void TenetService::clear_analysis() {
    {
        std::unique_lock lk(state_mutex_);
        pinned_results_.clear();
    }
    if (pass_manager_) {
        pass_manager_->cancel_all();
        pass_manager_->invalidate_all();
    }
    {
        std::lock_guard lk(row_cache_mutex_);
        row_cache_.clear();
    }
}

// ─── Search ─────────────────────────────────────────────────────────────────

void TenetService::search_forward(const std::string& query, uint64_t from_inst) {
    // ── Phase 1: clear search state and read xref pin (brief lock) ──────
    std::shared_ptr<const PassResult> xref_sp;
    {
        std::unique_lock lk(state_mutex_);
        search_results_.clear();
        search_current_ = 0;
        if (query.empty()) {
            search_active_ = false;
            return;
        }
        search_active_ = true;
        auto it = pinned_results_.find("xref");
        if (it != pinned_results_.end()) xref_sp = it->second;
    }
    // Lock released — the actual search computation runs lock-free.

    // Local result buffer — avoids holding state_mutex_ during the scan.
    std::vector<uint64_t> results;

    // ── Fast path: XrefResult-accelerated search ──────────────────────
    if (xref_sp && xref_sp->ok()) {
        const auto& xref = xref_sp->get<XrefResult>();
        if (xref.unique_pc_count > 0) {
            std::vector<uint64_t> matched;
            for (const auto& [pc, exec_count] : xref.pc_exec_count) {
                auto opcode = code_table_.opcode_at(pc);
                if (!opcode) continue;
                auto decoded = decoder_.decode(pc, *opcode);
                if (!decoded) continue;
                std::string_view disasm_sv = decoded->op_str_sv();
                std::string disasm;
                if (disasm_sv.empty()) {
                    disasm = std::string(decoded->mnemonic_sv());
                } else {
                    disasm = std::string(decoded->mnemonic_sv()) + " " +
                             std::string(disasm_sv);
                }
                if (disasm.find(query) == std::string::npos) continue;
                auto ids = xref.inst_ids_at(pc);
                for (uint64_t id : ids) {
                    matched.push_back(id);
                    if (matched.size() >= 10000) break;
                }
                if (matched.size() >= 10000) break;
            }
            std::sort(matched.begin(), matched.end());
            auto it = std::lower_bound(matched.begin(), matched.end(), from_inst);
            for (auto i = it; i != matched.end(); ++i)
                results.push_back(*i);
            for (auto i = matched.begin(); i != it; ++i)
                results.push_back(*i);
        }
    }

    // ── Fallback: linear scan with PC dedup ───────────────────────────
    if (results.empty() && !xref_sp) {
        uint64_t total = total_inst_.load(std::memory_order_relaxed);
        ankerl::unordered_dense::set<uint64_t> seen_pcs;
        ankerl::unordered_dense::set<uint64_t> matching_pcs;

        auto check_inst = [&](uint64_t i) {
            auto row = fetch_row(i);  // fetch_row has its own lock — no deadlock
            bool matches;
            if (matching_pcs.count(row.pc)) {
                matches = true;
            } else if (seen_pcs.count(row.pc)) {
                matches = false;
            } else {
                seen_pcs.insert(row.pc);
                matches = row.disasm.find(query) != std::string::npos;
                if (matches) matching_pcs.insert(row.pc);
            }
            if (matches) {
                results.push_back(i);
            }
        };

        for (uint64_t i = from_inst; i < total && results.size() < 10000; ++i) {
            check_inst(i);
        }
        for (uint64_t i = 0; i < from_inst && results.size() < 10000; ++i) {
            check_inst(i);
        }
    }

    // ── Phase 2: store results (brief lock) ───────────────────────────
    {
        std::unique_lock lk(state_mutex_);
        search_results_ = std::move(results);
    }
}

void TenetService::search_clear() {
    std::unique_lock lk(state_mutex_);
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

#include "core/register_file.h"
#include "common/Profiling.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace tenet {

// ═══════════════════════════════════════════════════════════════════════════
// RegisterFileCursor implementation
// ═══════════════════════════════════════════════════════════════════════════

RegisterFileCursor::RegisterFileCursor(const TraceReader& reader, const TraceIndex& index)
    : reader_(reader), index_(index)
    , num_gpr_(reader.header().num_gpr)
    , is_v5_((reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0)
    , is_v6_((reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0)
    , is_v7_((reader.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0)
{
    if (is_v7_ && is_v5_)      inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
    else if (is_v7_)           inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_v7_t);
    else if (is_v5_)           inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_v5_t);
    else                      inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_t);

    memacc_size_ = is_v6_ ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                          : sizeof(qbditrace::qbditrace_memacc_t);
    anchor_total_ = sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr_ * 8
                  + (is_v7_ ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0);

    reader_.pin_all();
}

RegisterFileCursor::~RegisterFileCursor() {
    reader_.unpin_all();
}

void RegisterFileCursor::seed(const RegState& state, uint64_t inst_id,
                              uint64_t file_offset) {
    state_ = state;
    current_inst_id_ = inst_id;
    current_offset_ = file_offset;
    initialized_ = true;
    has_pre_fixup_pc_ = false;
}

void RegisterFileCursor::init_from_anchor(uint64_t target_inst_id) {
    auto anchor_info = index_.nearest_anchor_before(target_inst_id);

    current_offset_ = anchor_info.file_offset;
    current_inst_id_ = anchor_info.inst_id;

    const uint8_t* ptr = reader_.data_at(current_offset_);
    if (current_offset_ < reader_.file_size() &&
        ptr[0] == qbditrace::QBDITRACE_REC_ANCHOR) {
        const uint8_t* gpr_start = ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
        const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(gpr_start);
        uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr_);
        std::memcpy(state_.gpr, gpr_ptr, count * 8);
        if (is_v7_) {
            const uint64_t* fpr_lo = reinterpret_cast<const uint64_t*>(gpr_start + num_gpr_ * 8);
            const uint64_t* fpr_hi = fpr_lo + AARCH64_FPR_COUNT;
            for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
                state_.fpr[i].lo = fpr_lo[i];
                state_.fpr[i].hi = fpr_hi[i];
            }
        }
        current_offset_ += anchor_total_;
    }

    initialized_ = true;
    has_pre_fixup_pc_ = false;
}

const RegState& RegisterFileCursor::advance_to(uint64_t target_inst_id) {
    if (!initialized_) {
        init_from_anchor(target_inst_id);
    }

    // Restore pre-fixup PC from the previous call (undo the PC patch so the
    // running PC is correct for the forward scan).
    if (has_pre_fixup_pc_) {
        state_.gpr[IDX_PC] = pre_fixup_pc_;
        has_pre_fixup_pc_ = false;
    }

    const uint64_t file_end = reader_.file_size();

    // Forward scan: process instructions from current_inst_id_ to target-1,
    // applying diffs. After the loop, state_ = state_before(target).
    while (current_inst_id_ < target_inst_id && current_offset_ < file_end) {
        const uint8_t* ptr = reader_.data_at(current_offset_);
        const uint8_t kind = ptr[0];

        if (kind == qbditrace::QBDITRACE_REC_INST) {
            const uint8_t nzcv      = ptr[1];
            const uint8_t n_regdiff = ptr[2];
            const uint8_t n_mem     = ptr[3];
            uint8_t n_fprdiff = 0;
            if (is_v7_ && is_v5_) {
                n_fprdiff = ptr[6];
            } else if (is_v7_) {
                n_fprdiff = ptr[16];
            }

            // Update PC for this instruction
            if (is_v5_) {
                int16_t pc_delta;
                std::memcpy(&pc_delta, ptr + 4, 2);
                state_.gpr[IDX_PC] += static_cast<int64_t>(pc_delta);
            } else if (is_v7_) {
                std::memcpy(&state_.gpr[IDX_PC], ptr + 4, 8);
            } else {
                std::memcpy(&state_.gpr[IDX_PC], ptr + 8, 8);
            }

            // Apply GPR diffs
            const uint8_t* diffs = ptr + inst_hdr_size_;
            for (uint8_t i = 0; i < n_regdiff; i++) {
                const auto* d = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                    diffs + i * sizeof(qbditrace::qbditrace_regdiff_t));
                if (d->reg_index < AARCH64_GPR_COUNT) {
                    state_.gpr[d->reg_index] = d->value;
                }
            }

            // Apply FPR diffs (v7 only)
            if (is_v7_ && n_fprdiff > 0) {
                const uint8_t* fpr_diffs = diffs +
                    n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t);
                for (uint8_t i = 0; i < n_fprdiff; i++) {
                    const auto* d = reinterpret_cast<const qbditrace::qbditrace_fprdiff_t*>(
                        fpr_diffs + i * sizeof(qbditrace::qbditrace_fprdiff_t));
                    if (d->fpr_index < AARCH64_FPR_COUNT) {
                        state_.fpr[d->fpr_index].lo = d->lo;
                        state_.fpr[d->fpr_index].hi = d->hi;
                    }
                }
            }

            // Update NZCV
            if (nzcv != 0) {
                state_.gpr[IDX_NZCV] = nzcv & 0xF;
            }

            size_t rec_size = inst_hdr_size_
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_fprdiff * sizeof(qbditrace::qbditrace_fprdiff_t)
                + n_mem     * memacc_size_;
            current_offset_ += rec_size;
            current_inst_id_++;

        } else if (kind == qbditrace::QBDITRACE_REC_ANCHOR) {
            // Fresh anchor — overwrite state entirely
            const uint8_t* gpr_start = ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
            const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(gpr_start);
            uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr_);
            std::memcpy(state_.gpr, gpr_ptr, count * 8);
            if (is_v7_) {
                const uint64_t* fpr_lo = reinterpret_cast<const uint64_t*>(gpr_start + num_gpr_ * 8);
                const uint64_t* fpr_hi = fpr_lo + AARCH64_FPR_COUNT;
                for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
                    state_.fpr[i].lo = fpr_lo[i];
                    state_.fpr[i].hi = fpr_hi[i];
                }
            }
            current_offset_ += anchor_total_;

        } else {
            // Skip non-INST/non-ANCHOR records
            auto rec = reader_.record_at(current_offset_);
            rec.is_v7 = is_v7_;
            current_offset_ += rec.byte_size(num_gpr_);
        }
    }

    // ── PC fixup ────────────────────────────────────────────────────────
    // After the forward scan, state_.gpr[IDX_PC] = PC of the last processed
    // instruction (target-1). state_before(target) needs target's PC.
    // Peek at the record at current_offset_ (which should be target's INST
    // record, or a non-INST record before it) to read target's PC.
    //
    // We save the pre-fixup PC so the next advance_to() can restore it,
    // keeping the running PC correct for v5 delta accumulation.
    pre_fixup_pc_ = state_.gpr[IDX_PC];
    has_pre_fixup_pc_ = true;

    {
        uint64_t peek_offset = current_offset_;
        while (peek_offset < file_end) {
            const uint8_t* ptr = reader_.data_at(peek_offset);
            uint8_t kind = ptr[0];

            if (kind == qbditrace::QBDITRACE_REC_INST) {
                if (is_v5_) {
                    int16_t pc_delta;
                    std::memcpy(&pc_delta, ptr + 4, 2);
                    state_.gpr[IDX_PC] += static_cast<int64_t>(pc_delta);
                } else if (is_v7_) {
                    std::memcpy(&state_.gpr[IDX_PC], ptr + 4, 8);
                } else {
                    std::memcpy(&state_.gpr[IDX_PC], ptr + 8, 8);
                }
                break;
            } else if (kind == qbditrace::QBDITRACE_REC_ANCHOR) {
                const auto* a_hdr =
                    reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                state_.gpr[IDX_PC] = a_hdr->pc;
                break;
            } else {
                auto rec = reader_.record_at(peek_offset);
                rec.is_v7 = is_v7_;
                peek_offset += rec.byte_size(num_gpr_);
            }
        }
    }

    return state_;
}

// ═══════════════════════════════════════════════════════════════════════════
// RegisterFile implementation
// ═══════════════════════════════════════════════════════════════════════════

RegisterFile::RegisterFile(const TraceReader& reader, const TraceIndex& index)
    : reader_(reader), index_(index) {}

RegState RegisterFile::state_before(uint64_t inst_id) {
    TENET_ZONE;

    // Checkpoint array is immutable after build — lock-free read.
    // If not built yet (e.g. GUI thread queries before init_infra() completes),
    // or the trace is empty, return an empty state without counting a query.
    if (!checkpoints_built_.load(std::memory_order_acquire) || checkpoints_.empty()) {
        return RegState{};
    }
    counters_.ckpt_queries.fetch_add(1, std::memory_order_relaxed);
    return state_before_ckpt(inst_id);
}

RegState RegisterFile::state_after(uint64_t inst_id) {
    // Get state before, then apply this instruction's diffs
    RegState state = state_before(inst_id);

    // Find the instruction record and apply its diffs
    auto [offset, seed_pc] = index_.offset_of_with_pc(inst_id, reader_);

    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        // Apply GPR diffs
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (diff.index < AARCH64_GPR_COUNT) {
                state.gpr[diff.index] = diff.value;
            }
        }
        // Apply FPR diffs (v7 only)
        for (uint8_t i = 0; i < inst.fpr_diff_count; i++) {
            auto diff = inst.fpr_diff(i);
            if (diff.index < AARCH64_FPR_COUNT) {
                state.fpr[diff.index].lo = diff.lo;
                state.fpr[diff.index].hi = diff.hi;
            }
        }
        // Update NZCV if captured
        if (inst.nzcv != 0) {
            state.gpr[IDX_NZCV] = inst.nzcv & 0xF;
        }
    }

    return state;
}

std::vector<std::array<uint64_t, 31>> RegisterFile::sample_gprs(
    const uint64_t* inst_ids, size_t count)
{
    std::vector<std::array<uint64_t, 31>> result(count);
    if (count == 0) {
        return result;
    }

    // Match the scalar fast path exactly: before checkpoints exist we do not
    // reconstruct from anchors for batch queries.
    if (!checkpoints_built_.load(std::memory_order_acquire)) {
        return result;
    }
    if (checkpoints_.empty()) {
        return result;
    }

    struct Request {
        uint64_t ckpt_idx;
        uint64_t inst_id;
        size_t output_index;
        bool fallback;
    };

    std::vector<Request> requests;
    requests.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const uint64_t inst_id = inst_ids[i];
        const uint64_t ckpt_idx = inst_id / ckpt_stride_;
        requests.push_back({
            ckpt_idx,
            inst_id,
            i,
            ckpt_idx >= checkpoints_.size(),
        });
    }

    std::sort(requests.begin(), requests.end(), [](const Request& a,
                                                   const Request& b) {
        if (a.ckpt_idx != b.ckpt_idx) return a.ckpt_idx < b.ckpt_idx;
        if (a.inst_id != b.inst_id) return a.inst_id < b.inst_id;
        return a.output_index < b.output_index;
    });

    size_t i = 0;
    while (i < requests.size()) {
        if (requests[i].fallback) {
            const auto& state = checkpoints_.back().state;
            do {
                std::copy_n(state.gpr, 31, result[requests[i].output_index].begin());
                ++i;
            } while (i < requests.size() && requests[i].fallback);
            continue;
        }

        const uint64_t ckpt_idx = requests[i].ckpt_idx;
        const auto& ckpt = checkpoints_[ckpt_idx];
        const uint64_t base_id = ckpt_idx * ckpt_stride_;
        RegisterFileCursor cursor(reader_, index_);
        cursor.seed(ckpt.state, base_id, ckpt.file_offset);

        do {
            const RegState* state_ptr = &ckpt.state;
            if (requests[i].inst_id != base_id) {
                state_ptr = &cursor.advance_to(requests[i].inst_id);
            }
            std::copy_n(state_ptr->gpr, 31, result[requests[i].output_index].begin());
            ++i;
        } while (i < requests.size() &&
                 !requests[i].fallback &&
                 requests[i].ckpt_idx == ckpt_idx);
    }

    return result;
}

RegState RegisterFile::state_before_ckpt(uint64_t inst_id) {
    if (checkpoints_.empty()) return RegState{};

    uint64_t idx = inst_id / ckpt_stride_;

    if (idx >= checkpoints_.size()) {
        // Out of range — return last checkpoint state (safe, not crash)
        counters_.ckpt_fallbacks.fetch_add(1, std::memory_order_relaxed);
        return checkpoints_.back().state;
    }

    const auto& ckpt = checkpoints_[idx];
    RegState state = ckpt.state;  // copy

    uint64_t base_id = idx * ckpt_stride_;
    if (inst_id == base_id) {
        return state;  // exact checkpoint hit
    }

    // Replay diffs from base_id to inst_id using a seeded cursor
    RegisterFileCursor cursor(reader_, index_);
    cursor.seed(state, base_id, ckpt.file_offset);
    return cursor.advance_to(inst_id);
}

// ═══════════════════════════════════════════════════════════════════════════
// Dense checkpoint array implementation
// ═══════════════════════════════════════════════════════════════════════════

void RegisterFile::build_checkpoints(uint64_t stride,
                                     std::function<void(uint64_t, uint64_t)> progress) {
    if (checkpoints_built_.load(std::memory_order_acquire)) {
        return;
    }

    std::lock_guard<std::mutex> lock(build_mutex_);
    if (checkpoints_built_.load(std::memory_order_relaxed)) {
        return;
    }

    const uint64_t total = index_.inst_count();
    if (total == 0) {
        ckpt_stride_ = 0;
        checkpoints_.clear();
        checkpoints_built_.store(true, std::memory_order_release);
        return;
    }

    // Auto-stride: target ~80 MB memory budget
    if (stride == 0) {
        constexpr size_t TARGET_MEM = 80 * 1024 * 1024;
        size_t per_ckpt = sizeof(Checkpoint);  // ~800 bytes
        stride = std::max<uint64_t>(64, (total * per_ckpt) / TARGET_MEM);
    }

    ckpt_stride_ = stride;
    size_t n_checkpoints = static_cast<size_t>((total + stride - 1) / stride);
    checkpoints_.resize(n_checkpoints);

    // Single forward sweep using cursor
    RegisterFileCursor cursor(reader_, index_);
    uint64_t done = 0;
    for (uint64_t id = 0; id < total; id += stride) {
        cursor.advance_to(id);
        auto& ckpt = checkpoints_[id / stride];
        ckpt.state = cursor.state();
        ckpt.file_offset = cursor.current_offset();
        ++done;
        if (progress && (done % 1024 == 0 || done == n_checkpoints)) {
            progress(done, n_checkpoints);
        }
    }

    checkpoints_built_.store(true, std::memory_order_release);
}

// ═══════════════════════════════════════════════════════════════════════════
// ThreadIsolatedCursor implementation
// ═══════════════════════════════════════════════════════════════════════════

ThreadIsolatedCursor::ThreadIsolatedCursor(const TraceReader& reader,
                                           const TraceIndex& index,
                                           uint64_t thread_id)
    : reader_(reader), index_(index), thread_id_(thread_id)
    , num_gpr_(reader.header().num_gpr)
    , is_v5_((reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0)
    , is_v6_((reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0)
    , is_v7_((reader.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0)
{
    if (is_v7_ && is_v5_)      inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
    else if (is_v7_)           inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_v7_t);
    else if (is_v5_)           inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_v5_t);
    else                       inst_hdr_size_ = sizeof(qbditrace::qbditrace_inst_head_t);

    memacc_size_ = is_v6_ ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                          : sizeof(qbditrace::qbditrace_memacc_t);
    anchor_total_ = sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr_ * 8
                  + (is_v7_ ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0);

    reader_.pin_all();
}

ThreadIsolatedCursor::~ThreadIsolatedCursor() {
    reader_.unpin_all();
}

void ThreadIsolatedCursor::load_anchor_state(const uint8_t* ptr) {
    const uint8_t* gpr_start = ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
    const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(gpr_start);
    uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr_);
    std::memcpy(state_.gpr, gpr_ptr, count * 8);
    if (is_v7_) {
        const uint64_t* fpr_lo = reinterpret_cast<const uint64_t*>(gpr_start + num_gpr_ * 8);
        const uint64_t* fpr_hi = fpr_lo + AARCH64_FPR_COUNT;
        for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
            state_.fpr[i].lo = fpr_lo[i];
            state_.fpr[i].hi = fpr_hi[i];
        }
    }
}

void ThreadIsolatedCursor::init_from_anchor(uint64_t target_inst_id) {
    auto anchor_info = index_.nearest_thread_anchor_before(target_inst_id, thread_id_);

    current_offset_ = anchor_info.file_offset;
    current_inst_id_ = anchor_info.inst_id;
    // nearest_thread_anchor_before() starts on an anchor owned by this thread;
    // if the preceding THREAD marker lies outside the seek window, retain that
    // ownership explicitly rather than waiting to observe a new marker.
    in_target_chunk_ = (anchor_info.file_offset !=
                        sizeof(qbditrace::qbditrace_file_header_t));

    // Seed the thread's v5 PC chain from the anchor's absolute PC (the anchor
    // itself is the state at the NEXT instruction of this thread, whose delta
    // from the anchor is 0 — the writer guarantees this on re-anchor).
    const uint8_t* ptr = reader_.data_at(current_offset_);
    if (current_offset_ < reader_.file_size() &&
        ptr[0] == qbditrace::QBDITRACE_REC_ANCHOR) {
        const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
        load_anchor_state(ptr);
        state_.gpr[IDX_PC] = ah->pc;
        current_offset_ += anchor_total_;
    }

    initialized_ = true;
}

const RegState& ThreadIsolatedCursor::advance_to(uint64_t target_inst_id) {
    if (!initialized_) {
        init_from_anchor(target_inst_id);
    }

    const uint64_t file_end = reader_.file_size();

    while (current_inst_id_ < target_inst_id && current_offset_ < file_end) {
        const uint8_t* ptr = reader_.data_at(current_offset_);
        const uint8_t kind = ptr[0];

        if (kind == qbditrace::QBDITRACE_REC_THREAD) {
            // Chunk ownership switch.
            const auto* th = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(ptr);
            in_target_chunk_ = (th->thread_id == thread_id_);
            current_offset_ += sizeof(qbditrace::qbditrace_thread_head_t);
            continue;
        }

        if (!in_target_chunk_) {
            // Foreign chunk: skip without applying its register diffs, but
            // still advance the GLOBAL instruction id. inst_id is file-wide,
            // not per-thread, and is the query coordinate used by all passes.
            auto rec = reader_.record_at(current_offset_);
            rec.is_v7 = is_v7_;
            if (kind == qbditrace::QBDITRACE_REC_INST) {
                current_inst_id_++;
            }
            current_offset_ += rec.byte_size(num_gpr_);
            continue;
        }

        if (kind == qbditrace::QBDITRACE_REC_INST) {
            const uint8_t n_regdiff = ptr[2];
            const uint8_t n_mem     = ptr[3];
            uint8_t n_fprdiff = 0;
            if (is_v7_ && is_v5_)      n_fprdiff = ptr[6];
            else if (is_v7_)           n_fprdiff = ptr[16];

            if (is_v5_) {
                int16_t pc_delta;
                std::memcpy(&pc_delta, ptr + 4, 2);
                state_.gpr[IDX_PC] += static_cast<int64_t>(pc_delta);
            } else if (is_v7_) {
                std::memcpy(&state_.gpr[IDX_PC], ptr + 4, 8);
            } else {
                std::memcpy(&state_.gpr[IDX_PC], ptr + 8, 8);
            }

            const uint8_t* diffs = ptr + inst_hdr_size_;
            for (uint8_t i = 0; i < n_regdiff; i++) {
                const auto* d = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                    diffs + i * sizeof(qbditrace::qbditrace_regdiff_t));
                if (d->reg_index < AARCH64_GPR_COUNT) {
                    state_.gpr[d->reg_index] = d->value;
                }
            }

            if (is_v7_ && n_fprdiff > 0) {
                const uint8_t* fpr_diffs = diffs +
                    n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t);
                for (uint8_t i = 0; i < n_fprdiff; i++) {
                    const auto* d = reinterpret_cast<const qbditrace::qbditrace_fprdiff_t*>(
                        fpr_diffs + i * sizeof(qbditrace::qbditrace_fprdiff_t));
                    if (d->fpr_index < AARCH64_FPR_COUNT) {
                        state_.fpr[d->fpr_index].lo = d->lo;
                        state_.fpr[d->fpr_index].hi = d->hi;
                    }
                }
            }

            const uint8_t nzcv = ptr[1];
            if (nzcv != 0) {
                state_.gpr[IDX_NZCV] = nzcv & 0xF;
            }

            current_offset_ += inst_hdr_size_
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_fprdiff * sizeof(qbditrace::qbditrace_fprdiff_t)
                + n_mem * memacc_size_;
            current_inst_id_++;

        } else if (kind == qbditrace::QBDITRACE_REC_ANCHOR) {
            // Thread-owned anchor: full state overwrite.
            load_anchor_state(ptr);
            const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
            state_.gpr[IDX_PC] = ah->pc;
            current_offset_ += anchor_total_;

        } else {
            // Other records of the same thread (SVC/CAPI/…) — skip.
            auto rec = reader_.record_at(current_offset_);
            rec.is_v7 = is_v7_;
            current_offset_ += rec.byte_size(num_gpr_);
        }
    }

    return state_;
}

RegState RegisterFile::state_before_thread(uint64_t inst_id, uint64_t thread_id) {
    TENET_ZONE;

    // Single-producer trace: no THREAD markers anywhere → plain semantics.
    if (!index_.anchors_have_threads()) {
        return state_before(inst_id);
    }
    // Checkpoints are built over the interleaved stream and are meaningless
    // for a single thread's reconstruction — always use the isolated cursor.
    ThreadIsolatedCursor cursor(reader_, index_, thread_id);
    return cursor.advance_to(inst_id);
}

}  // namespace tenet

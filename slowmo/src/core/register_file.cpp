#include "core/register_file.h"
#include "common/Profiling.h"
#include <algorithm>
#include <cstring>

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

    // Fast path: dense checkpoint array (lock-free, immutable after build)
    if (checkpoints_built_.load(std::memory_order_acquire)) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_stats_.ckpt_queries++;
        }
        return state_before_ckpt(inst_id);
    }

    // Fallback: LRU cache + anchor replay
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (auto cached = cache_.get(inst_id)) {
            cache_stats_.hits++;
            return cached->get();
        }
        cache_stats_.misses++;
    }

    RegState state = rebuild(inst_id);

    std::lock_guard<std::mutex> lock(mutex_);
    cache_.put(inst_id, state);
    return state;
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

void RegisterFile::warm_at(uint64_t inst_id) {
    bool cached;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cached = static_cast<bool>(cache_.get(inst_id));
    }
    if (!cached) {
        RegState state = rebuild(inst_id);
        std::lock_guard<std::mutex> lock(mutex_);
        cache_.put(inst_id, state);
        cache_stats_.warm_samples++;
    }
}

void RegisterFile::warm_range(uint64_t start_id, uint64_t end_id,
                               uint64_t stride,
                               std::function<void(uint64_t, uint64_t)> progress) {
    // Clamp end_id to the actual trace length.
    const uint64_t total_insts = index_.inst_count();
    if (end_id == UINT64_MAX || end_id > total_insts) {
        end_id = total_insts;
    }
    if (start_id >= end_id) {
        return;
    }

    if (stride == 0) {
        stride = 256;
    }

    uint64_t n_samples = (end_id - start_id + stride - 1) / stride;
    uint64_t done = 0;

    for (uint64_t id = start_id; id < end_id; id += stride) {
        bool cached;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cached = static_cast<bool>(cache_.get(id));
        }
        if (!cached) {
            RegState state = rebuild(id);
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.put(id, state);
            cache_stats_.warm_samples++;
        }
        ++done;
        if (progress) {
            progress(done, n_samples);
        }
    }
}

RegState RegisterFile::rebuild(uint64_t target_id) {
    RegState state{};
    const uint32_t num_gpr = reader_.header().num_gpr;
    const bool is_v5 = (reader_.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
    const bool is_v6 = (reader_.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    const bool is_v7 = (reader_.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;

    size_t inst_hdr_size;
    if (is_v7 && is_v5)      inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
    else if (is_v7)           inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_v7_t);
    else if (is_v5)           inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_v5_t);
    else                      inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_t);

    const size_t memacc_size = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)
        : sizeof(qbditrace::qbditrace_memacc_t);
    const size_t anchor_total =
        sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8
        + (is_v7 ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0);

    auto anchor_info = index_.nearest_anchor_before(target_id);

    reader_.pin_all();
    const uint64_t file_end = reader_.file_size();
    uint64_t scan_offset = anchor_info.file_offset;
    const uint8_t* ptr = reader_.data_at(scan_offset);

    if (scan_offset < file_end && ptr[0] == qbditrace::QBDITRACE_REC_ANCHOR) {
        const uint8_t* gpr_start = ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
        const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(gpr_start);
        uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
        std::memcpy(state.gpr, gpr_ptr, count * 8);
        if (is_v7) {
            const uint64_t* fpr_lo = reinterpret_cast<const uint64_t*>(gpr_start + num_gpr * 8);
            const uint64_t* fpr_hi = fpr_lo + AARCH64_FPR_COUNT;
            for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
                state.fpr[i].lo = fpr_lo[i];
                state.fpr[i].hi = fpr_hi[i];
            }
        }
        scan_offset += anchor_total;
    }

    uint64_t current_inst_id = anchor_info.inst_id;

    while (current_inst_id < target_id && scan_offset < file_end) {
        ptr = reader_.data_at(scan_offset);
        const uint8_t kind = ptr[0];

        if (kind == qbditrace::QBDITRACE_REC_INST) {
            const uint8_t nzcv      = ptr[1];
            const uint8_t n_regdiff = ptr[2];
            const uint8_t n_mem     = ptr[3];
            uint8_t n_fprdiff = 0;
            if (is_v7 && is_v5) {
                n_fprdiff = ptr[6];
            } else if (is_v7) {
                n_fprdiff = ptr[16];
            }

            if (is_v5) {
                int16_t pc_delta;
                std::memcpy(&pc_delta, ptr + 4, 2);
                state.gpr[IDX_PC] += static_cast<int64_t>(pc_delta);
            } else if (is_v7) {
                std::memcpy(&state.gpr[IDX_PC], ptr + 4, 8);
            } else {
                std::memcpy(&state.gpr[IDX_PC], ptr + 8, 8);
            }

            const uint8_t* diffs = ptr + inst_hdr_size;

            for (uint8_t i = 0; i < n_regdiff; i++) {
                const auto* d = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                    diffs + i * sizeof(qbditrace::qbditrace_regdiff_t));
                if (d->reg_index < AARCH64_GPR_COUNT) {
                    state.gpr[d->reg_index] = d->value;
                }
            }

            if (is_v7 && n_fprdiff > 0) {
                const uint8_t* fpr_diffs = diffs +
                    n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t);
                for (uint8_t i = 0; i < n_fprdiff; i++) {
                    const auto* d = reinterpret_cast<const qbditrace::qbditrace_fprdiff_t*>(
                        fpr_diffs + i * sizeof(qbditrace::qbditrace_fprdiff_t));
                    if (d->fpr_index < AARCH64_FPR_COUNT) {
                        state.fpr[d->fpr_index].lo = d->lo;
                        state.fpr[d->fpr_index].hi = d->hi;
                    }
                }
            }

            if (nzcv != 0) {
                state.gpr[IDX_NZCV] = nzcv & 0xF;
            }

            size_t rec_size = inst_hdr_size
                + n_regdiff  * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_fprdiff  * sizeof(qbditrace::qbditrace_fprdiff_t)
                + n_mem      * memacc_size;
            scan_offset += rec_size;

            current_inst_id++;

        } else if (kind == qbditrace::QBDITRACE_REC_ANCHOR) {
            const uint8_t* gpr_start = ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
            const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(gpr_start);
            uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
            std::memcpy(state.gpr, gpr_ptr, count * 8);
            if (is_v7) {
                const uint64_t* fpr_lo = reinterpret_cast<const uint64_t*>(gpr_start + num_gpr * 8);
                const uint64_t* fpr_hi = fpr_lo + AARCH64_FPR_COUNT;
                for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
                    state.fpr[i].lo = fpr_lo[i];
                    state.fpr[i].hi = fpr_hi[i];
                }
            }
            scan_offset += anchor_total;

        } else {
            auto rec = reader_.record_at(scan_offset);
            rec.is_v7 = is_v7;
            scan_offset += rec.byte_size(num_gpr);
        }
    }

    // Set PC from the target instruction's record
    auto [target_offset, target_seed_pc] = index_.offset_of_with_pc(target_id, reader_);
    auto target_rec = reader_.record_at(target_offset, target_seed_pc);
    if (target_rec.kind == RecordKind::Inst) {
        state.gpr[IDX_PC] = target_rec.as_inst().pc;
    }

    reader_.unpin_all();
    return state;
}

// ═══════════════════════════════════════════════════════════════════════════
// Dense checkpoint array implementation
// ═══════════════════════════════════════════════════════════════════════════

void RegisterFile::build_checkpoints(uint64_t stride,
                                     std::function<void(uint64_t, uint64_t)> progress) {
    const uint64_t total = index_.inst_count();
    if (total == 0) return;

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

    // Clear LRU cache to free memory (checkpoints subsume it)
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

RegState RegisterFile::state_before_ckpt(uint64_t inst_id) {
    uint64_t idx = inst_id / ckpt_stride_;
    uint64_t base_id = idx * ckpt_stride_;

    if (idx >= checkpoints_.size()) {
        // Out of range — fallback to rebuild
        std::lock_guard<std::mutex> lock(mutex_);
        cache_stats_.ckpt_fallbacks++;
        return rebuild(inst_id);
    }

    const auto& ckpt = checkpoints_[idx];
    RegState state = ckpt.state;  // copy

    if (inst_id == base_id) {
        return state;  // exact checkpoint hit
    }

    // Replay diffs from base_id to inst_id using a seeded cursor
    RegisterFileCursor cursor(reader_, index_);
    cursor.seed(state, base_id, ckpt.file_offset);
    return cursor.advance_to(inst_id);
}

}  // namespace tenet

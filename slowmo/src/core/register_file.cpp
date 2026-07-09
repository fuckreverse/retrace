#include "core/register_file.h"
#include "common/Profiling.h"
#include <algorithm>
#include <cstring>

namespace tenet {

RegisterFile::RegisterFile(const TraceReader& reader, const TraceIndex& index)
    : reader_(reader), index_(index) {}

RegState RegisterFile::state_before(uint64_t inst_id) {
    TENET_ZONE;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Check LRU cache first
        if (auto cached = cache_.get(inst_id)) {
            cache_stats_.hits++;
            return cached->get();
        }
        cache_stats_.misses++;
    }

    // Cache miss: rebuild from nearest anchor. Done outside the lock since
    // rebuild() only touches reader_/index_ (safe for concurrent readers) and
    // can be relatively expensive (anchor-to-target replay) — holding the
    // mutex here would serialize unrelated threads on unrelated inst_ids.
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

    // Scan forward from the sparse offset to find the exact inst_id
    // (offset_of already does this, so we can directly read the record)
    // Pass seed_pc for v5 traces so as_inst() uses the correct 6-byte header layout.
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

    // Auto-select stride: aim for ~256 samples per anchor interval.
    // The anchor interval from the file header gives the natural rebuild
    // granularity; using the same stride means each warm sample covers exactly
    // one anchor→sample window, so subsequent state_before() calls within that
    // window need to replay at most `stride` INST records.
    if (stride == 0) {
        // Prefer the anchor interval stored in the index.
        // TraceIndex::SPARSE_INTERVAL is the offset granularity (not anchors),
        // so fall back to a sensible default of 256 if unavailable.
        stride = 256;
    }

    // Compute how many sample points we will visit.
    uint64_t n_samples = (end_id - start_id + stride - 1) / stride;
    uint64_t done = 0;

    for (uint64_t id = start_id; id < end_id; id += stride) {
        // Skip if already cached (avoid rebuilding what we already have).
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

    // ── Header sizes for record byte-size calculations ──
    // v4:    qbditrace_inst_head_t       (16 bytes)
    // v5:    qbditrace_inst_head_v5_t    (6 bytes)
    // v7:    qbditrace_inst_head_v7_t    (24 bytes)
    // v7+v5: qbditrace_inst_head_v7_v5_t (8 bytes)
    size_t inst_hdr_size;
    if (is_v7 && is_v5)      inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_v7_v5_t);
    else if (is_v7)           inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_v7_t);
    else if (is_v5)           inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_v5_t);
    else                      inst_hdr_size = sizeof(qbditrace::qbditrace_inst_head_t);

    const size_t memacc_size = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)
        : sizeof(qbditrace::qbditrace_memacc_t);
    // anchor: kind(1)+reserved(3)+pad(4)+pc(8) = 16, then num_gpr*8 + [fpr 512B if v7]
    const size_t anchor_total =
        sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8
        + (is_v7 ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0);

    // Find nearest anchor before target_id
    auto anchor_info = index_.nearest_anchor_before(target_id);

    // ── Offset-based scan (works for both mmap and block-compressed) ──
    reader_.pin_all();  // keep decompressed blocks stable during rebuild
    const uint64_t file_end = reader_.file_size();
    uint64_t scan_offset = anchor_info.file_offset;
    const uint8_t* ptr = reader_.data_at(scan_offset);

    // Load anchor's full register snapshot directly from raw bytes
    if (scan_offset < file_end && ptr[0] == qbditrace::QBDITRACE_REC_ANCHOR) {
        const uint8_t* gpr_start = ptr + sizeof(qbditrace::qbditrace_anchor_head_t);
        const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(gpr_start);
        uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
        std::memcpy(state.gpr, gpr_ptr, count * 8);
        // v7: load FPR snapshot (32 × lo + 32 × hi appended after GPR block)
        if (is_v7) {
            const uint64_t* fpr_lo = reinterpret_cast<const uint64_t*>(gpr_start + num_gpr * 8);
            const uint64_t* fpr_hi = fpr_lo + AARCH64_FPR_COUNT;
            for (uint8_t i = 0; i < AARCH64_FPR_COUNT; ++i) {
                state.fpr[i].lo = fpr_lo[i];
                state.fpr[i].hi = fpr_hi[i];
            }
        }
        scan_offset += anchor_total;
        ptr = reader_.data_at(scan_offset);
    }

    // ── Replay diffs from anchor to target_id using offset-based scan ──
    // This avoids RecordView/InstView construction overhead for potentially
    // hundreds of records between anchor and target. On GB traces with sparse
    // index (every 256 insts), each rebuild touches up to 256 records.
    uint64_t current_inst_id = anchor_info.inst_id;

    while (current_inst_id < target_id && scan_offset < file_end) {
        ptr = reader_.data_at(scan_offset);
        const uint8_t kind = ptr[0];

        if (kind == qbditrace::QBDITRACE_REC_INST) {
            // ptr layout: [kind(1), nzcv(1), n_regdiff(1), n_mem(1), ...]
            const uint8_t nzcv      = ptr[1];
            const uint8_t n_regdiff = ptr[2];
            const uint8_t n_mem     = ptr[3];
            // n_fprdiff: only present in v7 headers; read from the correct offset.
            uint8_t n_fprdiff = 0;
            if (is_v7 && is_v5) {
                // qbditrace_inst_head_v7_v5_t: [kind,nzcv,n_regdiff,n_mem,delta_lo,delta_hi,n_fprdiff,reserved]
                n_fprdiff = ptr[6];
            } else if (is_v7) {
                // qbditrace_inst_head_v7_t: [kind,nzcv,n_regdiff,n_mem, pad4, pc8, n_fprdiff, ...]
                // n_fprdiff is at offset sizeof(qbditrace_inst_head_t) = 16
                n_fprdiff = ptr[16];
            }

            // Update PC for this instruction.
            // The writer excludes PC from reg_diffs (it's captured via
            // anchors), so we must reconstruct it ourselves:
            //   v5: accumulate pc_delta (int16 at byte offset 4)
            //   v4/v7-non-v5: read absolute PC from the INST header
            if (is_v5) {
                int16_t pc_delta;
                std::memcpy(&pc_delta, ptr + 4, 2);
                state.gpr[IDX_PC] += static_cast<int64_t>(pc_delta);
            } else if (is_v7) {
                // qbditrace_inst_head_v7_t: pc at byte offset 4
                std::memcpy(&state.gpr[IDX_PC], ptr + 4, 8);
            } else {
                // qbditrace_inst_head_t: pc at byte offset 8 (after 4B fields + 4B pad)
                std::memcpy(&state.gpr[IDX_PC], ptr + 8, 8);
            }

            // GPR diffs start right after the header
            const uint8_t* diffs = ptr + inst_hdr_size;

            // Apply GPR diffs
            for (uint8_t i = 0; i < n_regdiff; i++) {
                const auto* d = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                    diffs + i * sizeof(qbditrace::qbditrace_regdiff_t));
                if (d->reg_index < AARCH64_GPR_COUNT) {
                    state.gpr[d->reg_index] = d->value;
                }
            }

            // Apply FPR diffs (v7 only)
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

            // Update NZCV
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
            // Fresh anchor — overwrite state entirely
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
            // Skip non-INST/non-ANCHOR records (THREAD, EVENT, SVC, OBJC, CODE)
            auto rec = reader_.record_at(scan_offset);
            rec.is_v7 = is_v7;  // needed for anchor byte_size()
            scan_offset += rec.byte_size(num_gpr);
        }
    }

    // Set PC to the target instruction's PC.
    // The writer excludes PC from reg_diffs (captured via anchors only), so
    // the replay loop above never updates PC through diffs. We read the PC
    // directly from the target instruction's record:
    //   v5: offset_of_with_pc returns the accumulated running PC as seed_pc
    //   v4/v7: as_inst() reads the absolute PC from the INST header
    auto [target_offset, target_seed_pc] = index_.offset_of_with_pc(target_id, reader_);
    auto target_rec = reader_.record_at(target_offset, target_seed_pc);
    if (target_rec.kind == RecordKind::Inst) {
        state.gpr[IDX_PC] = target_rec.as_inst().pc;
    }

    reader_.unpin_all();
    return state;
}

}  // namespace tenet

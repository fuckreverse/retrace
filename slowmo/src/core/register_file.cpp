#include "core/register_file.h"
#include <algorithm>
#include <cstring>

namespace tenet {

RegisterFile::RegisterFile(const TraceReader& reader, const TraceIndex& index)
    : reader_(reader), index_(index) {}

const RegState& RegisterFile::state_before(uint64_t inst_id) {
    // Check LRU cache first
    if (auto cached = cache_.get(inst_id)) {
        cache_stats_.hits++;
        return cached->get();
    }

    // Cache miss: rebuild from nearest anchor
    cache_stats_.misses++;
    RegState state = rebuild(inst_id);
    cache_.put(inst_id, state);

    // Return reference to the cached value
    return cache_.get(inst_id)->get();
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
        // Apply register diffs
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (diff.index < AARCH64_GPR_COUNT) {
                state.gpr[diff.index] = diff.value;
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
    if (!cache_.get(inst_id)) {
        RegState state = rebuild(inst_id);
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
        if (!cache_.get(id)) {
            RegState state = rebuild(id);
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

    // ── Header sizes for record byte-size calculations ──
    // v4: qbditrace_inst_head_t  (kind+nzcv+n_regdiff+n_mem=4 + pad4 + pc=8 = 16 bytes)
    // v5: qbditrace_inst_head_v5_t (kind+nzcv+n_regdiff+n_mem=4 + pc_delta=2 = 6 bytes)
    // Sizes include compiler alignment padding; always use sizeof() to stay in sync.
    const size_t inst_hdr_size = is_v5
        ? sizeof(qbditrace::qbditrace_inst_head_v5_t)
        : sizeof(qbditrace::qbditrace_inst_head_t);
    // anchor: kind(1)+reserved(3)+pad(4)+pc(8) = 16, then num_gpr * 8
    const size_t anchor_total =
        sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;

    // Find nearest anchor before target_id
    auto anchor_info = index_.nearest_anchor_before(target_id);

    // ── Raw pointer into mmap ──
    const uint8_t* base = reader_.data();
    const uint8_t* end_ptr = base + reader_.file_size();
    const uint8_t* ptr = base + anchor_info.file_offset;

    // Load anchor's full register snapshot directly from raw bytes
    if (ptr < end_ptr && ptr[0] == qbditrace::QBDITRACE_REC_ANCHOR) {
        // GPR values start after the anchor header (sizeof = 16 due to alignment padding)
        const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(
            ptr + sizeof(qbditrace::qbditrace_anchor_head_t));
        uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
        std::memcpy(state.gpr, gpr_ptr, count * 8);
        ptr += anchor_total;
    }

    // ── Replay diffs from anchor to target_id using raw pointer scan ──
    // This avoids RecordView/InstView construction overhead for potentially
    // hundreds of records between anchor and target. On GB traces with sparse
    // index (every 256 insts), each rebuild touches up to 256 records.
    uint64_t current_inst_id = anchor_info.inst_id;

    while (current_inst_id < target_id && ptr < end_ptr) {
        const uint8_t kind = ptr[0];

        if (kind == qbditrace::QBDITRACE_REC_INST) {
            // ptr layout: [kind(1), nzcv(1), n_regdiff(1), n_mem(1), ...]
            const uint8_t nzcv = ptr[1];
            const uint8_t n_regdiff = ptr[2];
            const uint8_t n_mem = ptr[3];

            // reg_diffs start right after the header
            const uint8_t* diffs = ptr + inst_hdr_size;

            // Apply register diffs directly from mmap bytes.
            // qbditrace_regdiff_t layout: reg_index(u8) @0 + pad(7) + value(u64) @8
            // stride = sizeof(qbditrace_regdiff_t) = 16 bytes
            for (uint8_t i = 0; i < n_regdiff; i++) {
                const auto* d = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                    diffs + i * sizeof(qbditrace::qbditrace_regdiff_t));
                if (d->reg_index < AARCH64_GPR_COUNT) {
                    state.gpr[d->reg_index] = d->value;
                }
            }

            // Update NZCV
            if (nzcv != 0) {
                state.gpr[IDX_NZCV] = nzcv & 0xF;
            }

            // Advance pointer: header + diffs + mems
            // sizeof(qbditrace_regdiff_t) = 16, sizeof(qbditrace_memacc_t) = 32
            size_t rec_size = inst_hdr_size
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_mem     * sizeof(qbditrace::qbditrace_memacc_t);
            ptr += rec_size;

            // Prefetch next record header into L1
            __builtin_prefetch(ptr, 0, 3);

            current_inst_id++;

        } else if (kind == qbditrace::QBDITRACE_REC_ANCHOR) {
            // Fresh anchor — overwrite state entirely
            const uint64_t* gpr_ptr = reinterpret_cast<const uint64_t*>(
                ptr + sizeof(qbditrace::qbditrace_anchor_head_t));
            uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
            std::memcpy(state.gpr, gpr_ptr, count * 8);
            ptr += anchor_total;

        } else {
            // Skip non-INST/non-ANCHOR records (THREAD, EVENT, SVC, OBJC, CODE)
            // We need to compute byte_size for the unknown record type.
            auto rec = reader_.record_at(static_cast<uint64_t>(ptr - base));
            ptr += rec.byte_size(num_gpr);
        }
    }

    return state;
}

}  // namespace tenet

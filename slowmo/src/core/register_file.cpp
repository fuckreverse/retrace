#include "core/register_file.h"
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
    uint64_t offset = index_.offset_of(inst_id, reader_);

    // Scan forward from the sparse offset to find the exact inst_id
    // (offset_of already does this, so we can directly read the record)
    auto rec = reader_.record_at(offset);
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

RegState RegisterFile::rebuild(uint64_t target_id) {
    RegState state{};
    const uint32_t num_gpr = reader_.header().num_gpr;

    // Find nearest anchor before target_id
    auto anchor_info = index_.nearest_anchor_before(target_id);

    // Load anchor's full register snapshot
    auto anchor_rec = reader_.record_at(anchor_info.file_offset);
    if (anchor_rec.kind == RecordKind::Anchor) {
        auto anchor = anchor_rec.as_anchor(num_gpr);
        uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
        for (uint32_t i = 0; i < count; i++) {
            state.gpr[i] = anchor.gpr_values[i];
        }
    }

    // Now replay diffs from anchor's inst_id to target_id
    // Start scanning from the record after the anchor
    uint64_t current_offset = anchor_info.file_offset +
                              anchor_rec.byte_size(num_gpr);
    uint64_t current_inst_id = anchor_info.inst_id;

    while (current_inst_id < target_id && current_offset < reader_.file_size()) {
        auto rec = reader_.record_at(current_offset);
        size_t rec_size = rec.byte_size(num_gpr);

        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();

            // Apply register diffs
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                auto diff = inst.reg_diff(i);
                if (diff.index < AARCH64_GPR_COUNT) {
                    state.gpr[diff.index] = diff.value;
                }
            }

            // Update NZCV
            if (inst.nzcv != 0) {
                state.gpr[IDX_NZCV] = inst.nzcv & 0xF;
            }

            current_inst_id++;
        } else if (rec.kind == RecordKind::Anchor) {
            // If we encounter another anchor, use it directly (fresher state)
            auto anchor = rec.as_anchor(num_gpr);
            uint32_t count = std::min(static_cast<uint32_t>(AARCH64_GPR_COUNT), num_gpr);
            for (uint32_t i = 0; i < count; i++) {
                state.gpr[i] = anchor.gpr_values[i];
            }
        }

        current_offset += rec_size;
    }

    return state;
}

}  // namespace tenet

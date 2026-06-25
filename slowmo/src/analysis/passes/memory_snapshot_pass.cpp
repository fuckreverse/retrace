#include "analysis/passes/memory_snapshot_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"
#include <fmt/core.h>
#include <algorithm>
#include <cstring>

namespace tenet {

// ─── Hex dump formatting ──────────────────────────────────────────────────

std::string MemorySnapshotResult::hex_dump(const MemoryRegion& region) {
    std::string result;
    const size_t bytes_per_line = 16;
    const size_t total = region.data.size();

    for (size_t offset = 0; offset < total; offset += bytes_per_line) {
        // Address column
        result += fmt::format("{:08x}: ", region.addr + offset);

        // Hex bytes (two groups of 8)
        for (size_t i = 0; i < bytes_per_line; ++i) {
            if (i == 8) result += ' ';
            size_t idx = offset + i;
            if (idx < total && region.known[idx]) {
                result += fmt::format("{:02x}", region.data[idx]);
            } else if (idx < total) {
                result += "??";
            } else {
                result += "  ";
            }
            result += ' ';
        }

        // ASCII column
        result += ' ';
        for (size_t i = 0; i < bytes_per_line && (offset + i) < total; ++i) {
            size_t idx = offset + i;
            if (region.known[idx]) {
                uint8_t c = region.data[idx];
                result += (c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.';
            } else {
                result += '.';
            }
        }
        result += '\n';
    }
    return result;
}

// ─── Region capture (handles 16-byte chunk limit) ─────────────────────────

MemoryRegion MemorySnapshotPass::capture_region(MemoryModel& memory,
                                                 uint64_t addr,
                                                 uint64_t size,
                                                 uint64_t at_inst_id,
                                                 std::string label) {
    MemoryRegion region;
    region.addr = addr;
    region.at_inst_id = at_inst_id;
    region.label = std::move(label);
    region.data.resize(size, 0);
    region.known.resize(size, false);

    // MemoryModel::read() supports max 16 bytes per call, so we chunk.
    constexpr uint64_t chunk_size = 16;
    for (uint64_t off = 0; off < size; off += chunk_size) {
        uint64_t remaining = size - off;
        uint8_t read_size = static_cast<uint8_t>(std::min(remaining, chunk_size));

        MemReadResult mr = memory.read(addr + off, read_size, at_inst_id);

        for (uint8_t i = 0; i < read_size; ++i) {
            region.data[off + i] = mr.data[i];
            region.known[off + i] = mr.known[i];
        }
    }

    return region;
}

// ─── Pass implementation ──────────────────────────────────────────────────

PassResult MemorySnapshotPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& memory = ctx.memory();
    auto& regfile = ctx.regfile();
    auto& code_table = ctx.code_table();

    const auto& range = ctx.range();
    uint64_t end_id = std::min(range.end_inst_id, index.inst_count());
    if (end_id == 0) end_id = index.inst_count();

    MemorySnapshotResult result;

    // Helper: check if we've hit the snapshot limit.
    auto limit_reached = [&]() -> bool {
        return result.snapshots.size() >= config_.max_snapshots;
    };

    // Helper: add a snapshot and update the by_inst_id index.
    auto add_snapshot = [&](MemoryRegion&& region) {
        uint64_t iid = region.at_inst_id;
        size_t idx = result.snapshots.size();
        result.snapshots.push_back(std::move(region));
        result.by_inst_id[iid].push_back(idx);
    };

    // ─── Sort explicit snapshot_inst_ids for efficient lookup ─────────────
    auto explicit_ids = config_.snapshot_inst_ids;
    std::sort(explicit_ids.begin(), explicit_ids.end());

    // ─── Scan the trace ──────────────────────────────────────────────────
    size_t explicit_cursor = 0;  // index into sorted explicit_ids

    // Seek directly to start position using index (avoid scanning prefix)
    // Note: this file uses 1-based inst_id (incremented after seeing each Inst).
    // range.start_inst_id is 1-based, so we seek to (start - 1) in 0-based terms.
    uint64_t start_0based = (range.start_inst_id > 0) ? (range.start_inst_id - 1) : 0;
    uint64_t start_offset = 0;
    if (start_0based > 0) {
        auto [off, pc] = index.offset_of_with_pc(start_0based, reader);
        start_offset = off;
    }

    auto it_begin = (start_0based > 0) ? TraceReader::Iterator(&reader, start_offset) : reader.begin();
    uint64_t inst_id = (start_0based > 0) ? start_0based : 0;

    for (auto it = it_begin; it != reader.end(); ++it) {
        if (ctx.cancelled() || limit_reached()) break;

        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();
        inst_id++;

        if (inst_id > end_id) break;

        // Report progress periodically.
        if ((inst_id & 0xFFFF) == 0) {
            float pct = static_cast<float>(inst_id - range.start_inst_id) /
                        static_cast<float>(end_id - range.start_inst_id + 1);
            ctx.progress(pct, "Scanning for snapshot points");
        }

        // ─── Check explicit snapshot points ──────────────────────────────
        while (explicit_cursor < explicit_ids.size() &&
               explicit_ids[explicit_cursor] == inst_id) {
            // Snapshot register-pointed memory (x0-x7) and SP-relative
            const RegState& regs = regfile.state_before(inst_id);

            // Snapshot SP-relative (stack frame)
            uint64_t sp = regs.sp();
            if (sp != 0) {
                auto region = capture_region(memory, sp, config_.snapshot_size,
                                             inst_id, fmt::format("SP at inst #{}", inst_id));
                add_snapshot(std::move(region));
                if (limit_reached()) break;
            }

            // Snapshot x0-x7 if they look like pointers
            for (int r = 0; r < 8; ++r) {
                uint64_t val = regs.gpr[r];
                if (val >= 0x100000000ULL) {  // Likely a pointer on AArch64
                    auto region = capture_region(memory, val, config_.snapshot_size,
                                                 inst_id,
                                                 fmt::format("x{} at inst #{}", r, inst_id));
                    add_snapshot(std::move(region));
                    if (limit_reached()) break;
                }
            }

            explicit_cursor++;
        }

        if (limit_reached()) break;

        // ─── Check for BL/BLR (function call auto-snapshot) ──────────────
        if (config_.snapshot_at_function_calls) {
            auto opcode_opt = code_table.opcode_at(inst.pc);
            if (!opcode_opt) continue;

            uint32_t opcode = *opcode_opt;
            bool is_bl  = (opcode & 0xFC000000u) == 0x94000000u;
            bool is_blr = (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;

            if (is_bl || is_blr) {
                const RegState& regs = regfile.state_before(inst_id);

                // Determine target PC for the label
                uint64_t target_pc = 0;
                if (is_bl) {
                    // BL imm26: sign-extend the 26-bit offset and shift left 2
                    int64_t imm26 = (int64_t)(int32_t)((opcode & 0x03FFFFFFu) << 6) >> 4;
                    target_pc = inst.pc + imm26;
                } else {
                    // BLR Xn: register index is bits [9:5]
                    uint8_t rn = (opcode >> 5) & 0x1F;
                    if (rn < 31) {
                        target_pc = regs.gpr[rn];
                    }
                }

                std::string target_label = target_pc ?
                    fmt::format("sub_{:x}", target_pc) : "unknown";

                // Snapshot x0-x7 if they look like pointers
                for (int r = 0; r < 8; ++r) {
                    if (limit_reached()) break;

                    uint64_t val = regs.gpr[r];
                    if (val >= 0x100000000ULL) {  // Likely a pointer on AArch64
                        auto region = capture_region(
                            memory, val, config_.snapshot_size, inst_id,
                            fmt::format("x{} at BL {}", r, target_label));
                        add_snapshot(std::move(region));
                    }
                }
            }
        }
    }

    ctx.progress(1.0f, fmt::format("Done: {} snapshots captured", result.total()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

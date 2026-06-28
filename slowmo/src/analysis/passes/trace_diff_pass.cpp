#include "analysis/passes/trace_diff_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>

namespace tenet {

// ─── Main pass execution ──────────────────────────────────────────────────

PassResult TraceDiffPass::run(PassContext& ctx) {
    TraceDiffResult result;

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const uint64_t total_insts = index.inst_count();

    // Validate config ranges
    uint64_t a_start = config_.trace_a_start;
    uint64_t a_end = std::min(config_.trace_a_end, total_insts);
    uint64_t b_start = config_.trace_b_start;
    uint64_t b_end = std::min(config_.trace_b_end, total_insts);

    // Validate config ranges — empty regions mean the user hasn't configured
    // the comparison yet; treat as skipped rather than failed.
    if (a_start >= a_end || b_start >= b_end) {
        return PassResult::skipped();
    }

    const uint64_t region_a_len = a_end - a_start;
    const uint64_t region_b_len = b_end - b_start;
    const uint64_t compare_len = std::min(region_a_len, region_b_len);

    ctx.progress(0.0f, "TraceDiff: collecting region A instructions...");

    // ─── Collect instruction views from region A ──────────────────────────

    struct InstSnapshot {
        uint64_t pc;
        uint8_t reg_diff_count;
        uint8_t mem_access_count;
        // Stored register diffs
        struct RegDiff {
            uint8_t index;
            uint64_t value;
        };
        RegDiff reg_diffs[8];
        // Stored memory accesses
        struct MemAcc {
            uint8_t type;
            uint64_t addr;
            uint64_t value;
        };
        MemAcc mem_accs[8];
    };

    // Collect region A
    std::vector<InstSnapshot> region_a;
    region_a.reserve(compare_len);

    {
        // Use the sparse offset index to jump directly to a_start, avoiding
        // an O(a_start) scan from the beginning of the trace.
        uint64_t inst_id = 0;
        uint64_t start_offset = 0;
        if (a_start > 256) {
            start_offset = ctx.index().offset_of(a_start, reader);
            inst_id = a_start;
        }
        auto it_start = (start_offset > 0)
            ? TraceReader::Iterator(&reader, start_offset)
            : reader.begin();

        for (auto it = it_start; it != reader.end() && inst_id < a_end; ++it) {
            auto rec = *it;
            if (rec.kind != RecordKind::Inst) continue;
            if (inst_id < a_start) { inst_id++; continue; }

            auto inst = rec.as_inst();
            InstSnapshot snap{};
            snap.pc = inst.pc;
            snap.reg_diff_count = std::min(inst.reg_diff_count, uint8_t(8));
            snap.mem_access_count = std::min(inst.mem_access_count, uint8_t(8));

            for (uint8_t i = 0; i < snap.reg_diff_count; i++) {
                auto rd = inst.reg_diff(i);
                snap.reg_diffs[i] = {rd.index, rd.value};
            }
            for (uint8_t i = 0; i < snap.mem_access_count; i++) {
                auto ma = inst.mem_access(i);
                snap.mem_accs[i] = {ma.type, ma.addr, ma.value};
            }

            region_a.push_back(snap);
            inst_id++;

            if (region_a.size() >= compare_len) break;
            if (ctx.cancelled()) return PassResult::failed("cancelled");
        }
    }

    ctx.progress(0.4f, "TraceDiff: comparing with region B...");

    // ─── Iterate region B and compare against collected region A ──────────

    const uint64_t progress_interval = std::max(compare_len / 50, uint64_t(1));
    uint64_t b_offset = 0;

    {
        // Use the sparse offset index to jump directly to b_start.
        uint64_t inst_id = 0;
        uint64_t start_offset = 0;
        if (b_start > 256) {
            start_offset = ctx.index().offset_of(b_start, reader);
            inst_id = b_start;
        }
        auto it_start = (start_offset > 0)
            ? TraceReader::Iterator(&reader, start_offset)
            : reader.begin();

        for (auto it = it_start; it != reader.end() && inst_id < b_end; ++it) {
            auto rec = *it;
            if (rec.kind != RecordKind::Inst) continue;
            if (inst_id < b_start) { inst_id++; continue; }

            if (b_offset >= compare_len) break;

            auto inst_b = rec.as_inst();
            const auto& snap_a = region_a[b_offset];

            bool has_diff = false;

            // 1. Compare PC (control flow divergence)
            if (snap_a.pc != inst_b.pc) {
                DiffEntry entry;
                entry.inst_offset_a = b_offset;
                entry.inst_offset_b = b_offset;
                entry.pc = snap_a.pc;
                entry.type = DiffType::ControlFlow;
                entry.detail = fmt::format("PC diverged: A=0x{:x} B=0x{:x}", snap_a.pc, inst_b.pc);
                result.diffs.push_back(std::move(entry));
                has_diff = true;

                // Record diverge point (unique)
                if (result.diverge_points.empty() || result.diverge_points.back() != snap_a.pc) {
                    result.diverge_points.push_back(snap_a.pc);
                }
            } else {
                // Same PC — compare opcode
                auto opcode_a = code_table.opcode_at(snap_a.pc);
                auto opcode_b = code_table.opcode_at(inst_b.pc);

                if (opcode_a && opcode_b && *opcode_a != *opcode_b) {
                    // 2. Opcode change (unusual — same PC but different opcode,
                    //    could happen with self-modifying code)
                    DiffEntry entry;
                    entry.inst_offset_a = b_offset;
                    entry.inst_offset_b = b_offset;
                    entry.pc = snap_a.pc;
                    entry.type = DiffType::OpcodeChange;
                    entry.detail = fmt::format("Opcode differs at PC 0x{:x}: A=0x{:08x} B=0x{:08x}",
                                              snap_a.pc, *opcode_a, *opcode_b);
                    result.diffs.push_back(std::move(entry));
                    has_diff = true;
                }

                // 3. Compare register diffs (value differences)
                {
                    uint8_t count_a = snap_a.reg_diff_count;
                    uint8_t count_b = std::min(inst_b.reg_diff_count, uint8_t(8));
                    bool reg_differs = false;

                    if (count_a != count_b) {
                        reg_differs = true;
                    } else {
                        for (uint8_t i = 0; i < count_a; i++) {
                            auto rd_b = inst_b.reg_diff(i);
                            if (snap_a.reg_diffs[i].index != rd_b.index ||
                                snap_a.reg_diffs[i].value != rd_b.value) {
                                reg_differs = true;
                                break;
                            }
                        }
                    }

                    if (reg_differs) {
                        DiffEntry entry;
                        entry.inst_offset_a = b_offset;
                        entry.inst_offset_b = b_offset;
                        entry.pc = snap_a.pc;
                        entry.type = DiffType::RegisterValue;

                        // Build detail string showing first differing register
                        std::string detail = fmt::format("Reg diff at PC 0x{:x}: ", snap_a.pc);
                        uint8_t min_count = std::min(count_a, count_b);
                        bool found_specific = false;
                        for (uint8_t i = 0; i < min_count; i++) {
                            auto rd_b = inst_b.reg_diff(i);
                            if (snap_a.reg_diffs[i].value != rd_b.value &&
                                snap_a.reg_diffs[i].index == rd_b.index) {
                                detail += fmt::format("x{}(A=0x{:x} B=0x{:x})",
                                                     snap_a.reg_diffs[i].index,
                                                     snap_a.reg_diffs[i].value,
                                                     rd_b.value);
                                found_specific = true;
                                break;
                            }
                        }
                        if (!found_specific) {
                            detail += fmt::format("count A={} B={}", count_a, count_b);
                        }

                        entry.detail = std::move(detail);
                        result.diffs.push_back(std::move(entry));
                        has_diff = true;
                    }
                }

                // 4. Compare memory accesses (value differences)
                {
                    uint8_t count_a = snap_a.mem_access_count;
                    uint8_t count_b = std::min(inst_b.mem_access_count, uint8_t(8));
                    bool mem_differs = false;

                    if (count_a != count_b) {
                        mem_differs = true;
                    } else {
                        for (uint8_t i = 0; i < count_a; i++) {
                            auto ma_b = inst_b.mem_access(i);
                            if (snap_a.mem_accs[i].addr != ma_b.addr ||
                                snap_a.mem_accs[i].value != ma_b.value) {
                                mem_differs = true;
                                break;
                            }
                        }
                    }

                    if (mem_differs) {
                        DiffEntry entry;
                        entry.inst_offset_a = b_offset;
                        entry.inst_offset_b = b_offset;
                        entry.pc = snap_a.pc;
                        entry.type = DiffType::MemoryValue;

                        std::string detail = fmt::format("Mem diff at PC 0x{:x}: ", snap_a.pc);
                        uint8_t min_count = std::min(count_a, count_b);
                        bool found_specific = false;
                        for (uint8_t i = 0; i < min_count; i++) {
                            auto ma_b = inst_b.mem_access(i);
                            if (snap_a.mem_accs[i].value != ma_b.value) {
                                detail += fmt::format("[0x{:x}](A=0x{:x} B=0x{:x})",
                                                     snap_a.mem_accs[i].addr,
                                                     snap_a.mem_accs[i].value,
                                                     ma_b.value);
                                found_specific = true;
                                break;
                            }
                        }
                        if (!found_specific) {
                            detail += fmt::format("count A={} B={}", count_a, count_b);
                        }

                        entry.detail = std::move(detail);
                        result.diffs.push_back(std::move(entry));
                        has_diff = true;
                    }
                }
            }

            if (has_diff) {
                result.diverged_count++;
            } else {
                result.matched_count++;
            }

            b_offset++;
            inst_id++;

            if (b_offset % progress_interval == 0) {
                ctx.progress(0.4f + 0.6f * (static_cast<float>(b_offset) / compare_len),
                             fmt::format("TraceDiff: {}/{} compared, {} diffs found",
                                         b_offset, compare_len, result.diffs.size()));
            }
            if (ctx.cancelled()) return PassResult::failed("cancelled");
        }
    }

    // If regions have different lengths, note trailing instructions as divergence
    if (region_a_len != region_b_len) {
        uint64_t extra = (region_a_len > region_b_len)
                             ? (region_a_len - compare_len)
                             : (region_b_len - compare_len);
        result.diverged_count += extra;
    }

    ctx.progress(1.0f, fmt::format("TraceDiff: done — {} matched, {} diverged, {} diff entries",
                                    result.matched_count, result.diverged_count,
                                    result.diffs.size()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

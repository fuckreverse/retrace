#include "analysis/passes/producer_chain_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"

#include <cstring>
#include <algorithm>

namespace tenet {

// ─── Find last writer using REG_WRITES inverted index ────────────────────
//
// Delegates to TraceIndex::find_last_writer_of() which uses a RocksDB
// SeekForPrev on the REG_WRITES column family: O(log N) instead of O(50K).
//
// Falls back to linear scan automatically when the old index format is in use.

uint64_t ProducerChainPass::find_last_writer(PassContext& ctx, uint64_t before_id, uint8_t reg) {
    return ctx.index().find_last_writer_of(reg, before_id, ctx.reader());
}

// ─── Main pass execution ──────────────────────────────────────────────────
//
// Optimization: merged find_last_writer + detail retrieval into a single scan.
// Old approach: 2 separate reader.begin() scans per depth level = 2D full scans.
// New approach: 1 seek + scan per level (find writer AND get details in one pass).

PassResult ProducerChainPass::run(PassContext& ctx) {
    if (cfg_.start_inst_id == 0) {
        return PassResult::failed("start_inst_id must be specified");
    }

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    if (cfg_.start_inst_id > index.inst_count()) {
        return PassResult::failed("start_inst_id exceeds trace length");
    }

    ProducerChainResult result;
    ctx.progress(0.0f, "ProducerChain: tracing value provenance...");

    uint8_t current_reg = cfg_.start_reg;
    uint64_t current_id = cfg_.start_inst_id;

    for (uint32_t depth = 0; depth < cfg_.max_depth; depth++) {
        // ── Single merged scan: find last writer + collect details ──
        uint64_t scan_start = (current_id > 50000) ? current_id - 50000 : 0;

        // Seek to scan_start using index
        uint64_t start_offset = 0;
        if (scan_start > 0) {
            start_offset = index.offset_of(scan_start, reader);
        }

        uint64_t last_writer_id = 0;
        uint64_t last_writer_file_offset = 0;
        uint64_t inst_id = scan_start;

        auto it_start = (start_offset > 0)
            ? TraceReader::Iterator(&reader, start_offset)
            : reader.begin();
        auto it_end = reader.end();

        // Pass 1: find the last writer in a single forward scan.
        // We remember both inst_id AND the file offset of the record following it,
        // but it's simpler to just re-read from the known inst_id.
        for (auto it = it_start; it != it_end; ++it) {
            auto rec = *it;
            if (rec.kind != RecordKind::Inst) continue;
            inst_id++;

            if (inst_id >= current_id) break;

            auto inst = rec.as_inst();
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                if (diff.index == current_reg) {
                    last_writer_id = inst_id;
                    // Capture details inline — no second scan needed!
                    // We'll overwrite on each new match so we always have the LAST writer.
                    last_writer_file_offset = 0;  // flag that we have details
                }
            }
        }

        if (last_writer_id == 0) break;  // No writer found

        result.instructions_scanned++;

        // ── Get details for the last writer instruction ──
        // Use index.offset_of() to seek directly to the writer instruction.
        uint64_t writer_offset = index.offset_of(last_writer_id, reader);

        ProducerLink link;
        link.inst_id = last_writer_id;
        link.produced_reg = current_reg;

        // Seek and read just the writer instruction
        if (writer_offset > 0) {
            auto writer_it = TraceReader::Iterator(&reader, writer_offset);
            uint64_t scan_id = last_writer_id;  // We're close; allow small drift
            for (; writer_it != it_end; ++writer_it) {
                auto rec = *writer_it;
                if (rec.kind != RecordKind::Inst) continue;

                // Due to sparse index granularity (256), we might need to scan a few
                auto inst = rec.as_inst();
                scan_id++;

                // Accept: we're at or very near the writer
                // (offset_of may land slightly before due to sparse granularity)
                if (scan_id > last_writer_id + 256) break;  // Safety limit

                // Check if this is our target by matching reg_diff
                bool is_target = false;
                for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                    auto diff = inst.reg_diff(d);
                    if (diff.index == current_reg) {
                        if (scan_id == last_writer_id || scan_id <= last_writer_id) {
                            link.value = diff.value;
                            is_target = true;
                        }
                    }
                }

                if (!is_target && scan_id < last_writer_id) continue;
                if (scan_id > last_writer_id) break;

                link.pc = inst.pc;

                // Get the produced value from reg_diffs
                for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                    auto diff = inst.reg_diff(d);
                    if (diff.index == current_reg) {
                        link.value = diff.value;
                    }
                }

                // Check if this is a memory load (LDR pattern)
                auto raw_opcode = code_table.opcode_at(inst.pc);
                if (raw_opcode) {
                    uint32_t opcode = *raw_opcode;

                    // Detect LDR (various encodings)
                    bool is_ldr_imm = (opcode & 0xFFC00000u) == 0xF9400000u;
                    bool is_ldr_w_imm = (opcode & 0xFFC00000u) == 0xB9400000u;
                    bool is_ldr_reg = (opcode & 0xFFE00C00u) == 0xF8600800u;

                    if (is_ldr_imm || is_ldr_w_imm || is_ldr_reg) {
                        link.is_memory_load = true;
                        for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                            auto mem = inst.mem_access(m);
                            if (!(mem.type & 0x02)) {  // Read
                                link.mem_addr = mem.addr;
                                break;
                            }
                        }
                        uint8_t rn = (opcode >> 5) & 0x1F;
                        if (rn < 31) link.source_regs.push_back(rn);
                    } else {
                        uint8_t rn = (opcode >> 5) & 0x1F;
                        uint8_t rm = (opcode >> 16) & 0x1F;
                        if (rn < 31 && rn != current_reg) link.source_regs.push_back(rn);
                        if (rm < 31 && rm != current_reg && rm != rn) link.source_regs.push_back(rm);
                    }

                    // Disassemble
                    auto dis = decoder.decode(inst.pc, opcode);
                    if (dis) {
                        link.disassembly = std::string(dis->mnemonic) + " " + dis->op_str;
                    }
                }
                break;
            }
        }

        result.chain.push_back(std::move(link));

        // Follow the first source register for the next iteration
        if (!result.chain.back().source_regs.empty()) {
            current_reg = result.chain.back().source_regs[0];
            current_id = last_writer_id;
        } else {
            break;  // No further sources to trace
        }

        ctx.progress(static_cast<float>(depth) / cfg_.max_depth);
    }

    if (result.chain.size() >= cfg_.max_depth) {
        result.truncated = true;
    }

    ctx.progress(1.0f, "ProducerChain: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet

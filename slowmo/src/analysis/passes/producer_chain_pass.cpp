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
// Each depth level:
//   1. find_last_writer() — O(log N) via REG_WRITES inverted index.
//   2. offset_of_with_pc() + record_at() — O(log N) direct random access.
// No linear scanning at all.

PassResult ProducerChainPass::run(PassContext& ctx) {
    if (cfg_.start_inst_id == 0) {
        return PassResult::skipped();
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
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }

        // ── Step 1: O(log N) jump to the last writer ──
        uint64_t last_writer_id = find_last_writer(ctx, current_id, current_reg);
        if (last_writer_id == 0) break;  // No writer found

        result.instructions_scanned++;

        // ── Step 2: Direct random access to the writer instruction ──
        auto [writer_offset, writer_seed_pc] = index.offset_of_with_pc(last_writer_id, reader);

        ProducerLink link;
        link.inst_id = last_writer_id;
        link.produced_reg = current_reg;

        auto rec = reader.record_at(writer_offset, writer_seed_pc);
        if (rec.kind != RecordKind::Inst) break;  // Shouldn't happen

        auto inst = rec.as_inst();
        link.pc = inst.pc;

        // Single pass over reg_diffs: extract the produced value
        for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
            auto diff = inst.reg_diff(d);
            if (diff.index == current_reg) {
                link.value = diff.value;
                break;
            }
        }

        // Check if this is a memory load (LDR pattern) and extract source regs
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

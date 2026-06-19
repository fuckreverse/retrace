#include "analysis/passes/disassembly_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <string_view>

namespace tenet {

// ─── Mnemonic classification helper ──────────────────────────────────────

namespace {

/// Check if string_view starts with a prefix (C++17 compatible).
inline bool sw(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

/// Classify a mnemonic into instruction category flags on a PCDisasmEntry.
inline void classify_mnemonic(std::string_view m, PCDisasmEntry& info) {
    // Branch
    if (!m.empty()) {
        if (m[0] == 'b') {
            if (m.size() == 1 || m[1] == '.' || m[1] == ' ') {
                info.is_branch = true;
            } else if (m[1] == 'l') {
                info.is_call = true;  // bl, blr
            }
        }
        if (sw(m, "cb") || sw(m, "tb")) {
            info.is_branch = true;
        }
    }
    // Return
    if (sw(m, "ret")) info.is_return = true;
    // Load
    if (sw(m, "ldr") || sw(m, "ldp") || sw(m, "ldur")) {
        info.is_load = true;
    }
    // Store
    if (sw(m, "str") || sw(m, "stp") || sw(m, "stur")) {
        info.is_store = true;
    }
    // System
    if (sw(m, "svc") || sw(m, "mrs") || sw(m, "msr") ||
        sw(m, "dc") || sw(m, "ic") || sw(m, "tlbi")) {
        info.is_system = true;
    }
}

}  // anonymous namespace

// ─── DisassemblyPass::run ────────────────────────────────────────────────
//
// Design: build a DisasmTable with
//   • pc_table   — one PCDisasmEntry per *unique* PC (O(unique PCs))
//   • inst_to_pc — flat vector mapping inst_id→PC   (O(N_instructions × 8B))
//
// This replaces the previous approach that materialised a full DisasmEntry
// (with copied strings) for every instruction — O(N × ~120B).
//
// For a trace of 10M instructions over 5000 unique PCs the old approach
// used ~1.2 GB; the new approach uses ~80 MB (5000 × 120B + 10M × 8B).

PassResult DisassemblyPass::run(PassContext& ctx) {
    auto& reader     = ctx.reader();
    auto& index      = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder    = ctx.decoder();

    const auto& hdr   = reader.header();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // ─── Phase 1: Build pc_table from code table (O(unique PCs)) ─────────
    // Decode each unique opcode exactly once.

    DisasmTable result;
    {
        auto all_entries = code_table.all_entries();
        result.pc_table.reserve(all_entries.size());

        for (const auto& [pc, opcode] : all_entries) {
            PCDisasmEntry info;
            info.pc        = pc;
            info.static_pc = pc - hdr.module_slide;
            info.opcode    = opcode;

            auto d = decoder.decode(pc, opcode);
            if (d) {
                info.mnemonic    = d->mnemonic;
                info.op_str      = d->op_str;
                info.full_disasm = fmt::format("{} {}", d->mnemonic, d->op_str);
                classify_mnemonic(d->mnemonic_sv(), info);
                info.valid = true;
            } else {
                info.full_disasm = fmt::format(".word 0x{:08x}", opcode);
                info.valid = false;
            }

            result.pc_table.emplace(pc, std::move(info));
        }
    }

    ctx.progress(0.1f, fmt::format("DisasmTable: {} unique PCs decoded", result.pc_table.size()));

    // ─── Phase 2: Build inst_to_pc index (O(N_instructions × 8B)) ────────
    // We only store the PC per instruction, not a full DisasmEntry.
    // Actual DisasmEntry objects are synthesised on-demand via lookup().

    const uint64_t total = (end > start) ? (end - start) : 0;
    result.base_inst_id = start;
    result.inst_to_pc.reserve(total);

    uint64_t inst_id  = 0;
    uint64_t processed = 0;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        if (inst_id < start) {
            inst_id++;
            continue;
        }

        auto inst = rec.as_inst();
        result.inst_to_pc.push_back(inst.pc);

        inst_id++;
        processed++;

        if ((processed & 0x1FFFF) == 0) {  // every ~131K instructions
            ctx.progress(0.1f + 0.9f * static_cast<float>(processed) /
                         static_cast<float>(total > 0 ? total : 1));
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
        }
    }

    ctx.progress(1.0f, fmt::format(
        "DisasmTable: {} instructions indexed, {} unique PCs",
        result.inst_to_pc.size(), result.pc_table.size()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

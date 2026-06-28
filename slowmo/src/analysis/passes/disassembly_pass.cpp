#include "analysis/passes/disassembly_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <string_view>
#include <cstring>

namespace tenet {

// ─── DisasmTable partial serialization helpers ────────────────────────────
//
// Only the inst_to_pc mapping is persisted; the pc_table is reconstructed
// from the code table (which is already in memory from code section parsing).
//
// Blob format (all little-endian):
//   u32  magic         = 0x44534D54 ("DSMT")
//   u32  version       = 1
//   u64  base_inst_id
//   u64  num_inst_to_pc
//   u64[] inst_to_pc[num_inst_to_pc]

namespace {

static constexpr uint32_t DSMT_BLOB_MAGIC   = 0x44534D54u;  // "DSMT"
static constexpr uint32_t DSMT_BLOB_VERSION = 1u;

std::string disasm_serialize_inst_to_pc(const DisasmTable& tbl) {
    const size_t n = tbl.inst_to_pc.size();
    const size_t total = 4 + 4 + 8 + 8 + n * 8;

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(DSMT_BLOB_MAGIC);
    write_u32(DSMT_BLOB_VERSION);
    write_u64(tbl.base_inst_id);
    write_u64(static_cast<uint64_t>(n));
    for (uint64_t pc : tbl.inst_to_pc) write_u64(pc);

    return buf;
}

bool disasm_deserialize_inst_to_pc(const std::string& blob,
                                    uint64_t& base_inst_id_out,
                                    std::vector<uint64_t>& inst_to_pc_out) {
    if (blob.size() < 4 + 4 + 8 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != DSMT_BLOB_MAGIC)   return false;
    if (read_u32() != DSMT_BLOB_VERSION) return false;

    base_inst_id_out = read_u64();
    uint64_t n = read_u64();
    if (p + n * 8 > end) return false;
    inst_to_pc_out.resize(static_cast<size_t>(n));
    for (uint64_t i = 0; i < n; i++) inst_to_pc_out[i] = read_u64();

    return true;
}

}  // anonymous namespace (disasm serialization)

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

    const uint64_t total_insts = index.inst_count();

    // ─── Phase 1: Build pc_table from code table (O(unique PCs)) ─────────
    // This is fast and always runs (code_table is already in memory).

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

    // ─── Fast path: load inst_to_pc from persisted cache ──────────────────
    // pc_table is rebuilt above; only inst_to_pc needs to come from the cache.
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("disassembly", blob)) {
            uint64_t cached_base = 0;
            std::vector<uint64_t> cached_inst_to_pc;
            if (disasm_deserialize_inst_to_pc(blob, cached_base, cached_inst_to_pc)) {
                result.base_inst_id = cached_base;
                result.inst_to_pc   = std::move(cached_inst_to_pc);
                ctx.progress(1.0f, fmt::format(
                    "DisasmTable: {} instructions indexed, {} unique PCs (from cache)",
                    result.inst_to_pc.size(), result.pc_table.size()));
                return PassResult::success(std::move(result));
            }
        }
    }

    // ─── Phase 2: Build inst_to_pc via collector ──────────────────────────

    const uint64_t total = (end > start) ? (end - start) : 0;
    result.base_inst_id = start;

    DisassemblyCollector collector(start, total);

    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress([&](uint64_t processed, uint64_t total_count) {
            if (total_count > 0) {
                ctx.progress(0.1f + 0.9f * static_cast<float>(processed) /
                             static_cast<float>(total_count));
            }
        });
        local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
        local_engine.add_collector(&collector);
        local_engine.run(start, end);
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    result.inst_to_pc = collector.take_inst_to_pc();

    // ─── Persist inst_to_pc for future sessions ───────────────────────────
    if (range.is_full_trace()) {
        std::string blob = disasm_serialize_inst_to_pc(result);
        if (!blob.empty()) {
            index.save_pass_blob("disassembly", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format(
        "DisasmTable: {} instructions indexed, {} unique PCs",
        result.inst_to_pc.size(), result.pc_table.size()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "common/aarch64_classify.h"

#include <fmt/core.h>
#include <algorithm>
#include <string_view>

#include "common/byte_codec.h"

namespace tenet {

// ─── CFGResult serialization helpers ──────────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic    = 0x43464700 ("CFG\0")
//   u32  version  = 1
//   u64  num_blocks
//   for each BasicBlock:
//     u64  start_pc
//     u64  end_pc
//     u64  execution_count
//     u8   terminator      (cast of TerminatorKind)
//     u64  num_instructions
//     u64[] instructions[num_instructions]
//   u64  num_edges
//   for each CFGEdge:
//     u64  from_block
//     u64  to_block
//     u64  taken_count
//     u8   is_fallthrough

namespace {

static constexpr uint32_t CFG_BLOB_MAGIC   = 0x43464700u;  // "CFG\0"
static constexpr uint32_t CFG_BLOB_VERSION = 1u;

std::string cfg_serialize(const CFGResult& res) {
    ByteWriter w;

    w.u32(CFG_BLOB_MAGIC);
    w.u32(CFG_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.blocks.size()));

    for (const auto& [start_pc, blk] : res.blocks) {
        w.u64(blk.start_pc);
        w.u64(blk.end_pc);
        w.u64(blk.execution_count);
        w.u8(static_cast<uint8_t>(blk.terminator));
        w.u64(static_cast<uint64_t>(blk.instructions.size()));
        for (uint64_t pc : blk.instructions) w.u64(pc);
    }

    w.u64(static_cast<uint64_t>(res.edges.size()));
    for (const auto& e : res.edges) {
        w.u64(e.from_block);
        w.u64(e.to_block);
        w.u64(e.taken_count);
        w.u8(e.is_fallthrough ? 1u : 0u);
    }

    return std::move(w).take();
}

bool cfg_deserialize(const std::string& blob, CFGResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != CFG_BLOB_MAGIC)   return false;
    if (r.u32() != CFG_BLOB_VERSION) return false;

    uint64_t n_blocks = r.u64();
    for (uint64_t i = 0; i < n_blocks; i++) {
        BasicBlock blk;
        blk.start_pc        = r.u64();
        blk.end_pc          = r.u64();
        blk.execution_count = r.u64();
        blk.terminator      = static_cast<TerminatorKind>(r.u8());
        uint64_t n_insns    = r.u64();
        if (!r.ok()) return false;
        blk.instructions.resize(static_cast<size_t>(n_insns));
        for (uint64_t j = 0; j < n_insns; j++) {
            blk.instructions[j] = r.u64();
        }
        out.blocks.emplace(blk.start_pc, std::move(blk));
    }

    uint64_t n_edges = r.u64();
    if (!r.ok()) return false;
    out.edges.reserve(static_cast<size_t>(n_edges));
    for (uint64_t i = 0; i < n_edges; i++) {
        CFGEdge e;
        e.from_block     = r.u64();
        e.to_block       = r.u64();
        e.taken_count    = r.u64();
        e.is_fallthrough = r.u8() != 0;
        out.edges.push_back(e);
    }

    return r.ok();
}

}  // anonymous namespace (cfg serialization)

// ─── AArch64 branch classification helpers ────────────────────────────────

namespace {

/// AArch64 opcode-based terminator classification (no Capstone needed).
/// Returns Fallthrough for non-branch instructions.
///
/// Delegates the actual bit-pattern matching to common/aarch64_classify.h
/// (shared with function_pass, memory_string_pass, memory_snapshot_pass)
/// rather than re-deriving masks here. This previously had its own
/// hand-rolled masks for BR/BLR/RET (0xFE1FFC1F) that omitted bits [24:21]
/// (the `opc` field that actually distinguishes BR/BLR/RET from each
/// other), so BLR and RET were silently misclassified as BR
/// (IndirectBranch) whenever bits [24:21] were checked first — see the
/// correct mask (0xFFFFFC1F) already used elsewhere in the codebase.
static TerminatorKind classify_opcode_terminator(uint32_t opcode) {
    // Unconditional branch immediate: B (bit[31]=0, [30:26]=00101)
    if (aarch64::is_b(opcode)) return TerminatorKind::Branch;

    // Branch with link: BL (bit[31]=1, [30:26]=00101)
    if (aarch64::is_bl(opcode)) return TerminatorKind::Call;

    // Conditional branch: B.cond ([31:25]=0101010, [4]=0)
    if (aarch64::is_b_cond(opcode)) return TerminatorKind::ConditionalBranch;

    // Compare and branch zero/nonzero: CBZ/CBNZ ([30:25]=011010)
    if ((opcode & 0x7E000000) == 0x34000000) return TerminatorKind::ConditionalBranch;

    // Test and branch: TBZ/TBNZ ([30:25]=011011)
    if ((opcode & 0x7E000000) == 0x36000000) return TerminatorKind::ConditionalBranch;

    // RET (and RETAA/RETAB pointer-auth variants) must be checked before
    // BR/BLR: RETAA/RETAB set bits outside the plain is_ret() mask.
    if (aarch64::is_ret(opcode)) return TerminatorKind::Return;
    if ((opcode & 0xFEFFFCFF) == 0xD65F0BFF) return TerminatorKind::Return;  // RETAA/RETAB

    // BLR (and BLRAA/BLRAB/BLRAAZ/BLRABZ pointer-auth variants): call.
    if (aarch64::is_blr(opcode)) return TerminatorKind::Call;
    if ((opcode & 0xFEFFF800) == 0xD63F0800) return TerminatorKind::Call;  // BLRAA/BLRAB/...

    // Branch register: BR (unconditional, non-call, non-return).
    if (aarch64::is_br(opcode)) return TerminatorKind::IndirectBranch;

    return TerminatorKind::Fallthrough;
}

/// Classify an instruction mnemonic into a TerminatorKind.
/// Returns nullopt for non-branch instructions (ordinary fallthrough).
/// Used as fallback when opcode-based classification is not available.
std::optional<TerminatorKind> classify_terminator(std::string_view mnemonic) {
    // Unconditional branch: b
    if (mnemonic == "b") {
        return TerminatorKind::Branch;
    }
    // Conditional branch: b.eq, b.ne, b.lt, b.gt, b.le, b.ge, b.hi, b.lo, ...
    // Capstone renders these as "b.eq", "b.ne", etc.
    if (mnemonic.size() > 2 && mnemonic[0] == 'b' && mnemonic[1] == '.') {
        return TerminatorKind::ConditionalBranch;
    }
    // Compare-and-branch: cbz, cbnz
    if (mnemonic == "cbz" || mnemonic == "cbnz") {
        return TerminatorKind::ConditionalBranch;
    }
    // Test-and-branch: tbz, tbnz
    if (mnemonic == "tbz" || mnemonic == "tbnz") {
        return TerminatorKind::ConditionalBranch;
    }
    // Call: bl, blr
    if (mnemonic == "bl") {
        return TerminatorKind::Call;
    }
    if (mnemonic == "blr") {
        return TerminatorKind::Call;
    }
    // Return: ret
    if (mnemonic == "ret") {
        return TerminatorKind::Return;
    }
    // Indirect branch: br (not blr, which is a call)
    if (mnemonic == "br") {
        return TerminatorKind::IndirectBranch;
    }
    return std::nullopt;
}

/// Extract the branch target PC directly from the 32-bit AArch64 opcode.
/// Uses pure bitfield extraction — no Capstone decode needed.
/// Returns nullopt for indirect branches (BR/BLR/RET) whose target is
/// not statically determinable.
std::optional<uint64_t> extract_branch_target_from_opcode(uint64_t pc, uint32_t opcode) {
    uint64_t target = aarch64::direct_branch_target(pc, opcode);
    return target != 0 ? std::optional<uint64_t>{target} : std::nullopt;
}

}  // anonymous namespace

// ─── CFGPass::CFGEdgeCollector out-of-line methods ───────────────────────────

void CFGPass::CFGEdgeCollector::merge(TraceCollector& shard) {
    auto& other = static_cast<CFGEdgeCollector&>(shard);
    for (const auto& [key, count] : other.edge_counts) {
        edge_counts[key] += count;
    }
}

void CFGPass::CFGEdgeCollector::on_inst(uint64_t /*inst_id*/, const InstView& inst) {
    uint64_t cur_block_start;

    // Fast path: check locality cache before O(log B) lookup
    if (inst.pc >= cached_block_start_ && inst.pc <= cached_block_end_) {
        cur_block_start = cached_block_start_;
    } else {
        const BasicBlock* cur_block = cfg->block_containing(inst.pc);
        if (cur_block) {
            cur_block_start = cur_block->start_pc;
            cached_block_start_ = cur_block->start_pc;
            cached_block_end_   = cur_block->end_pc;
        } else {
            cur_block_start = UINT64_MAX;
            // Invalidate cache so the next instruction won't false-hit
            cached_block_start_ = 0;
            cached_block_end_   = 0;
        }
    }

    // 1. Inter-block edge: previous instruction was in a different block.
    if (prev_block_start != UINT64_MAX && cur_block_start != UINT64_MAX &&
        prev_block_start != cur_block_start) {
        edge_counts[EdgeKey{prev_block_start, cur_block_start}]++;
    }

    // 2. Self-loop back edge: a backward branch landed on the start of
    //    the *same* block we were already in.  Without this, loops whose
    //    body is a single basic block (e.g.  add; cmp; b.lt back) would
    //    have no back edge, and LoopPass would fail to detect them.
    //
    //    Detection: prev and current are in the same block, the current
    //    instruction is the block's start_pc, and the previous PC was
    //    not the block's start_pc (i.e. we branched back from deeper in
    //    the block, not fell through from above).
    if (prev_block_start != UINT64_MAX &&
        prev_block_start == cur_block_start &&
        cur_block_start != UINT64_MAX &&
        inst.pc == cur_block_start &&
        prev_pc != cur_block_start &&
        prev_pc != UINT64_MAX) {
        edge_counts[EdgeKey{cur_block_start, cur_block_start}]++;
    }

    prev_block_start = cur_block_start;
    prev_pc = inst.pc;
}

// ─── CFGPass::build_blocks ──────────────────────────────────────────────────

bool CFGPass::build_blocks(PassContext& ctx) {
    if (blocks_built_) return true;

    // Try to get xref results — if not available yet, we can't build blocks.
    const auto* xref = ctx.try_require<XrefResult>("xref");
    if (!xref) return false;

    auto& code_table = ctx.code_table();

    // ── Phase 1: Collect all unique PCs and sort them ─────────────────────

    std::vector<uint64_t> sorted_pcs;
    sorted_pcs.reserve(xref->unique_pc_count);
    for (const auto& [pc, _] : xref->pc_exec_count) {
        sorted_pcs.push_back(pc);
    }
    std::sort(sorted_pcs.begin(), sorted_pcs.end());

    // ── Phase 2: Identify basic block boundaries ─────────────────────────

    ankerl::unordered_dense::set<uint64_t> block_leaders;
    block_leaders.reserve(sorted_pcs.size());

    // First PC is always a leader
    if (!sorted_pcs.empty()) {
        block_leaders.insert(sorted_pcs[0]);
    }

    // Cache: PC → TerminatorKind for instructions that are terminators.
    ankerl::unordered_dense::map<uint64_t, TerminatorKind> terminator_cache;

    for (uint64_t pc : sorted_pcs) {
        auto opcode = code_table.opcode_at(pc);
        if (!opcode) continue;

        auto kind = classify_opcode_terminator(*opcode);
        if (kind == TerminatorKind::Fallthrough) continue;

        terminator_cache.emplace(pc, kind);

        uint64_t fallthrough_pc = pc + 4;
        if (xref->has_pc(fallthrough_pc)) {
            block_leaders.insert(fallthrough_pc);
        }

        if (kind == TerminatorKind::Branch ||
            kind == TerminatorKind::ConditionalBranch ||
            kind == TerminatorKind::Call) {
            if (aarch64::is_blr(*opcode) || aarch64::is_br(*opcode) ||
                aarch64::is_ret(*opcode))
                continue;
            auto target = extract_branch_target_from_opcode(pc, *opcode);
            if (target && xref->has_pc(*target)) {
                block_leaders.insert(*target);
            }
        }
    }

    // ── Phase 3: Form basic blocks ───────────────────────────────────────

    BasicBlock current_block;
    bool in_block = false;

    auto finalize_block = [&](BasicBlock& blk) {
        auto cache_it = terminator_cache.find(blk.end_pc);
        if (cache_it != terminator_cache.end()) {
            blk.terminator = cache_it->second;
        }
        for (uint64_t insn_pc : blk.instructions) {
            blk.execution_count += xref->execution_count(insn_pc);
        }
        result_.blocks.emplace(blk.start_pc, std::move(blk));
    };

    for (uint64_t pc : sorted_pcs) {
        if (block_leaders.count(pc)) {
            if (in_block) {
                finalize_block(current_block);
            }
            current_block = BasicBlock{};
            current_block.start_pc = pc;
            current_block.end_pc = pc;
            current_block.instructions.push_back(pc);
            current_block.terminator = TerminatorKind::Fallthrough;
            in_block = true;
        } else if (in_block) {
            current_block.end_pc = pc;
            current_block.instructions.push_back(pc);
        }
    }

    if (in_block) {
        finalize_block(current_block);
    }

    blocks_built_ = true;
    return true;
}

// ─── CFGPass::declare_scan ──────────────────────────────────────────────────

void CFGPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    // CFGEdgeCollector needs a populated CFGResult (blocks) to resolve
    // which block each PC belongs to.  Blocks are built from xref data.
    // In run_all() Phase 1, xref hasn't been computed yet, so we can't
    // build blocks — skip registration.  The actual scan will happen in
    // run() via execute_pass()'s local ScanOrchestrator, where xref is
    // guaranteed to be available (dependencies are resolved first).
    if (!build_blocks(ctx)) return;

    // If xref recorded PC transitions, we can build edges directly without
    // a trace scan — skip collector registration.
    const auto* xref = ctx.try_require<XrefResult>("xref");
    if (xref && !xref->pc_transitions.empty()) {
        transitions_available_ = true;
        return;  // no scan needed
    }

    collector_ = std::make_unique<CFGEdgeCollector>(&result_);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/true});
}

// ─── CFGPass::run ───────────────────────────────────────────────────────────

PassResult CFGPass::run(PassContext& ctx) {
    auto& index = ctx.index();
    const auto& range = ctx.range();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("cfg", blob)) {
            CFGResult cached;
            if (cfg_deserialize(blob, cached)) {
                cached.build_adjacency();
                ctx.progress(1.0f, fmt::format(
                    "CFG: {} blocks, {} edges (from cache)",
                    cached.block_count(), cached.edge_count()));
                collector_.reset();
                return PassResult::success(std::move(cached));
            }
        }
    }

    // Build blocks if not already done (by declare_scan or previous call)
    build_blocks(ctx);

    auto& reader = ctx.reader();

    // ── Phase 4: Build edges ─────────────────────────────────────────────
    // Two paths: (a) reuse xref's pc_transitions (no scan), or (b) use the
    // trace scan results from CFGEdgeCollector.

    EdgeCountMap edge_counts;

    if (transitions_available_) {
        // Path (a): build edges from xref pc_transitions — no scan needed.
        // This eliminates CFGPass's separate full-trace scan entirely.
        const auto* xref = ctx.try_require<XrefResult>("xref");
        if (!xref) {
            return PassResult::failed("xref result not available");
        }

        // 1. Direct edges from non-sequential transitions.
        for (const auto& t : xref->pc_transitions) {
            const auto* from_blk = result_.block_containing(t.from_pc);
            const auto* to_blk   = result_.block_containing(t.to_pc);
            if (from_blk && to_blk) {
                edge_counts[{from_blk->start_pc, to_blk->start_pc}] += t.count;
            }
        }

        // 2. Infer fallthrough edges (sequential, pc → pc+4).
        // For each block, fallthrough_count = exec_count(end_pc) - taken_count.
        // pc_transitions is sorted by from_pc, so we binary-search the range
        // of transitions originating from each block's end_pc.
        const auto& transitions = xref->pc_transitions;
        for (const auto& [start_pc, block] : result_.blocks) {
            uint64_t end_pc = block.end_pc;
            uint64_t exec = xref->execution_count(end_pc);
            if (exec == 0) continue;

            // Sum non-sequential transition counts from end_pc.
            uint64_t taken = 0;
            auto it = std::lower_bound(transitions.begin(), transitions.end(), end_pc,
                [](const XrefResult::PCTransition& t, uint64_t v) { return t.from_pc < v; });
            for (; it != transitions.end() && it->from_pc == end_pc; ++it) {
                taken += it->count;
            }

            uint64_t fallthrough = (exec > taken) ? (exec - taken) : 0;
            if (fallthrough == 0) continue;

            // Find the block containing end_pc + 4.
            uint64_t next_pc = end_pc + 4;
            if (!xref->has_pc(next_pc)) continue;
            const auto* next_blk = result_.block_containing(next_pc);
            if (next_blk) {
                edge_counts[{start_pc, next_blk->start_pc}] += fallthrough;
            }
        }

        ctx.progress(0.9f, fmt::format(
            "CFG: {} edges from xref transitions (no scan)", edge_counts.size()));
    } else {
        // Path (b): use trace scan results from CFGEdgeCollector.
        // collector_ must have been populated by declare_scan() + ScanOrchestrator.
        if (!collector_) {
            return PassResult::failed("declare_scan() was not called before run()");
        }
        edge_counts = std::move(collector_->edge_counts);
    }

    // ── Phase 5: Build final edge list ───────────────────────────────────
    result_.edges.reserve(edge_counts.size());

    for (const auto& [key, count] : edge_counts) {
        CFGEdge edge;
        edge.from_block = key.from_block;
        edge.to_block = key.to_block;
        edge.taken_count = count;

        // Determine if this is a fallthrough edge.
        auto it = result_.blocks.find(key.from_block);
        if (it != result_.blocks.end()) {
            const auto& src_block = it->second;
            uint64_t expected_fallthrough = src_block.end_pc + 4;
            if (key.to_block == expected_fallthrough) {
                switch (src_block.terminator) {
                    case TerminatorKind::Branch:
                    case TerminatorKind::IndirectBranch:
                    case TerminatorKind::Return:
                        edge.is_fallthrough = false;
                        break;
                    default:
                        edge.is_fallthrough = true;
                        break;
                }
            } else {
                edge.is_fallthrough = false;
            }
        } else {
            edge.is_fallthrough = false;
        }

        result_.edges.push_back(std::move(edge));
    }

    // Build O(1) adjacency index for successor/predecessor queries.
    result_.build_adjacency();

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = cfg_serialize(result_);
        if (!blob.empty()) {
            index.save_pass_blob("cfg", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("CFG: {} blocks, {} edges",
                             result_.block_count(), result_.edge_count()));

    // Move result_ out and reset state for potential re-use
    CFGResult final_result = std::move(result_);
    collector_.reset();
    blocks_built_ = false;
    transitions_available_ = false;
    result_ = CFGResult{};  // reset for potential re-use

    return PassResult::success(std::move(final_result));
}

}  // namespace tenet

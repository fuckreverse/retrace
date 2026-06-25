#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>
#include <string_view>

namespace tenet {

// ─── AArch64 branch classification helpers ────────────────────────────────

namespace {

/// AArch64 opcode-based terminator classification (no Capstone needed).
/// Returns Fallthrough for non-branch instructions.
static TerminatorKind classify_opcode_terminator(uint32_t opcode) {
    // Unconditional branch immediate: B (bit[31]=0, [30:26]=00101)
    if ((opcode & 0xFC000000) == 0x14000000) return TerminatorKind::Branch;

    // Branch with link: BL (bit[31]=1, [30:26]=00101)
    if ((opcode & 0xFC000000) == 0x94000000) return TerminatorKind::Call;

    // Conditional branch: B.cond ([31:25]=0101010, [4]=0)
    if ((opcode & 0xFE000010) == 0x54000000) return TerminatorKind::ConditionalBranch;

    // Compare and branch zero/nonzero: CBZ/CBNZ ([30:25]=011010)
    if ((opcode & 0x7E000000) == 0x34000000) return TerminatorKind::ConditionalBranch;

    // Test and branch: TBZ/TBNZ ([30:25]=011011)
    if ((opcode & 0x7E000000) == 0x36000000) return TerminatorKind::ConditionalBranch;

    // Branch register: BR ([24:21]=0000)
    if ((opcode & 0xFE1FFC1F) == 0xD61F0000) return TerminatorKind::IndirectBranch;

    // BLR: [24:21]=0001
    if ((opcode & 0xFE1FFC1F) == 0xD63F0000) return TerminatorKind::Call;

    // BLRAA/BLRAB/BLRAAZ/BLRABZ (pointer auth variants)
    if ((opcode & 0xFEFFF800) == 0xD63F0800) return TerminatorKind::Call;

    // RET: [24:21]=0010
    if ((opcode & 0xFE1FFC1F) == 0xD65F0000) return TerminatorKind::Return;
    // RETAA/RETAB (pointer auth)
    if ((opcode & 0xFEFFFCFF) == 0xD65F0BFF) return TerminatorKind::Return;

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

/// Extract the branch target PC from a decoded instruction's operand string.
/// For AArch64, Capstone encodes the target as "#0xADDR" in the op_str.
std::optional<uint64_t> extract_branch_target(std::string_view op_str) {
    // Look for "#0x" pattern which Capstone uses for branch targets
    auto pos = op_str.find("#0x");
    if (pos == std::string_view::npos) {
        pos = op_str.find("#0X");
    }
    if (pos == std::string_view::npos) {
        // For cbz/cbnz/tbz/tbnz, the target is the last operand
        // e.g. "cbz x0, #0x1000" — find the last "#0x"
        pos = op_str.rfind('#');
        if (pos == std::string_view::npos) return std::nullopt;
        if (pos + 1 < op_str.size() && (op_str[pos + 1] == '0') &&
            (op_str[pos + 2] == 'x' || op_str[pos + 2] == 'X')) {
            // OK, found "#0x"
        } else {
            return std::nullopt;
        }
    } else {
        // Skip "#0x" prefix
        pos += 3;  // skip past "#0x"
    }

    // Parse hex number starting at pos
    // op_str is backed by a null-terminated char[] so .data() + pos is safe for strtoull
    char* endp = nullptr;
    uint64_t target = std::strtoull(op_str.data() + pos, &endp, 16);
    if (endp != op_str.data() + pos && target != 0) {
        return target;
    }
    return std::nullopt;
}

}  // anonymous namespace

// ─── CFGPass implementation ────────────────────────────────────────────────

PassResult CFGPass::run(PassContext& ctx) {
    // Require xref pass results to get the set of executed PCs
    const auto& xref = ctx.require<XrefResult>("xref");
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    CFGResult result;

    // ── Phase 1: Collect all unique PCs and sort them ─────────────────────

    std::vector<uint64_t> sorted_pcs;
    sorted_pcs.reserve(xref.unique_pc_count);
    for (const auto& [pc, _] : xref.pc_to_inst_ids) {
        sorted_pcs.push_back(pc);
    }
    std::sort(sorted_pcs.begin(), sorted_pcs.end());

    // ── Phase 2: Identify basic block boundaries ─────────────────────────
    // A new basic block starts at:
    //   - The very first PC in the trace
    //   - The target of any branch (call/branch/conditional branch)
    //   - The instruction after a call/branch/conditional/return
    // A basic block ends at:
    //   - Any branch instruction (including calls and returns)
    //   - The instruction before a branch target

    // Collect all PCs that are block leaders
    ankerl::unordered_dense::set<uint64_t> block_leaders;
    block_leaders.reserve(sorted_pcs.size());

    // First PC is always a leader
    if (!sorted_pcs.empty()) {
        block_leaders.insert(sorted_pcs[0]);
    }

    // Cache: PC → TerminatorKind for instructions that are terminators.
    // Populated during Phase 2, reused in Phase 3 to avoid redundant decoding.
    ankerl::unordered_dense::map<uint64_t, TerminatorKind> terminator_cache;

    // For each PC, classify terminator using fast opcode bitmask first,
    // falling back to Capstone decode only when we need the branch target.
    for (uint64_t pc : sorted_pcs) {
        auto opcode = code_table.opcode_at(pc);
        if (!opcode) continue;

        // Fast path: classify directly from 32-bit opcode (no Capstone)
        auto kind = classify_opcode_terminator(*opcode);
        if (kind == TerminatorKind::Fallthrough) continue;

        // Cache the decoded terminator kind for Phase 3
        terminator_cache.emplace(pc, kind);

        // The instruction after a branch/call/return starts a new block
        uint64_t fallthrough_pc = pc + 4;
        if (xref.pc_to_inst_ids.count(fallthrough_pc)) {
            block_leaders.insert(fallthrough_pc);
        }

        // The target of a direct branch starts a new block.
        // We need Capstone only here to extract the branch target immediate.
        if (kind == TerminatorKind::Branch ||
            kind == TerminatorKind::ConditionalBranch ||
            kind == TerminatorKind::Call) {
            auto d = decoder.decode(pc, *opcode);
            if (d) {
                auto target = extract_branch_target(d->op_str);
                if (target && xref.pc_to_inst_ids.count(*target)) {
                    block_leaders.insert(*target);
                }
            }
        }
        // Indirect branches (blr, br, ret) — target unknown statically,
        // but we don't need to mark targets since dynamic edges will be
        // discovered during trace walk.
    }

    // ── Phase 3: Form basic blocks ───────────────────────────────────────
    // Walk sorted PCs. Start a new block at each leader, and extend the
    // current block until the next leader or end of PCs.

    BasicBlock current_block;
    bool in_block = false;

    // Helper: finalize a block — look up terminator from cache (no re-decode),
    // accumulate execution count, and emplace into result.
    auto finalize_block = [&](BasicBlock& blk) {
        auto cache_it = terminator_cache.find(blk.end_pc);
        if (cache_it != terminator_cache.end()) {
            blk.terminator = cache_it->second;
        }
        for (uint64_t insn_pc : blk.instructions) {
            blk.execution_count += xref.execution_count(insn_pc);
        }
        result.blocks.emplace(blk.start_pc, std::move(blk));
    };

    for (uint64_t pc : sorted_pcs) {
        if (block_leaders.count(pc)) {
            // Save the previous block if we were building one
            if (in_block) {
                finalize_block(current_block);
            }
            // Start a new block
            current_block = BasicBlock{};
            current_block.start_pc = pc;
            current_block.end_pc = pc;
            current_block.instructions.push_back(pc);
            current_block.terminator = TerminatorKind::Fallthrough;
            in_block = true;
        } else if (in_block) {
            // Extend current block
            current_block.end_pc = pc;
            current_block.instructions.push_back(pc);
        }
    }

    // Don't forget the last block
    if (in_block) {
        finalize_block(current_block);
    }

    // ── Phase 4: Walk the trace to build edges and count taken ───────────
    // For each consecutive pair of instructions in the trace, if they belong
    // to different blocks, create an edge from the source block to the
    // destination block.
    //
    // Uses TraceScanEngine::run_parallel() for multi-threaded scanning.

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // Edge accumulator: (from_block_start, to_block_start) → taken_count
    struct EdgeKey {
        uint64_t from_block;
        uint64_t to_block;
        bool operator==(const EdgeKey& o) const {
            return from_block == o.from_block && to_block == o.to_block;
        }
    };
    struct EdgeKeyHash {
        size_t operator()(const EdgeKey& k) const {
            size_t h1 = std::hash<uint64_t>{}(k.from_block);
            size_t h2 = std::hash<uint64_t>{}(k.to_block);
            return h1 ^ (h2 * 0x9e3779b97f4a7c15ULL + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
        }
    };

    using EdgeCountMap = ankerl::unordered_dense::map<EdgeKey, uint64_t, EdgeKeyHash>;

    /// Collector that accumulates CFG edge counts during trace scan.
    /// Supports parallel sharding: each shard independently tracks block
    /// transitions, then merge() sums edge counts.
    ///
    /// Locality cache: most consecutive trace instructions fall within the
    /// same basic block, so we cache the current block's [start, end] range.
    /// On cache hit we skip the O(log B) upper_bound lookup entirely.
    struct CFGEdgeCollector final : public TraceCollector {
        const CFGResult* cfg;       // Shared (read-only) block map
        EdgeCountMap edge_counts;
        uint64_t prev_block_start = UINT64_MAX;
        uint64_t prev_pc = UINT64_MAX;  // PC of the previous instruction

        // Locality cache — avoids block_containing() for sequential PCs
        uint64_t cached_block_start_ = 0;
        uint64_t cached_block_end_   = 0;   // inclusive, matching BasicBlock::end_pc

        explicit CFGEdgeCollector(const CFGResult* c) : cfg(c) {}

        std::string_view name() const override { return "cfg_edge_collector"; }
        bool supports_parallel() const override { return true; }

        std::unique_ptr<TraceCollector> clone() const override {
            return std::make_unique<CFGEdgeCollector>(cfg);
        }

        void merge(TraceCollector& shard) override {
            auto& other = static_cast<CFGEdgeCollector&>(shard);
            for (const auto& [key, count] : other.edge_counts) {
                edge_counts[key] += count;
            }
        }

        void on_inst(uint64_t /*inst_id*/, const InstView& inst) override {
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
    };

    CFGEdgeCollector collector(&result);
    TraceScanEngine engine(reader, index.inst_count(), &index);
    engine.add_collector(&collector);
    engine.set_progress([&](uint64_t processed, uint64_t total) {
        ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
    });
    engine.set_cancel_check([&]() { return ctx.cancelled(); });
    if (ctx.no_parallel_scan()) {
        engine.run(start, end);
    } else {
        engine.run_parallel(start, end);
    }

    auto& edge_counts = collector.edge_counts;

    // ── Phase 5: Build final edge list ───────────────────────────────────
    result.edges.reserve(edge_counts.size());

    for (const auto& [key, count] : edge_counts) {
        CFGEdge edge;
        edge.from_block = key.from_block;
        edge.to_block = key.to_block;
        edge.taken_count = count;

        // Determine if this is a fallthrough edge.
        // A fallthrough edge is one where the destination block immediately
        // follows the source block in address space (to_block's start_pc ==
        // from_block's end_pc + 4) AND the source block's terminator is not
        // an unconditional branch/indirect branch/return.
        auto it = result.blocks.find(key.from_block);
        if (it != result.blocks.end()) {
            const auto& src_block = it->second;
            uint64_t expected_fallthrough = src_block.end_pc + 4;
            if (key.to_block == expected_fallthrough) {
                // Only mark as fallthrough if the source block doesn't
                // unconditionally jump away (unconditional b, br, ret)
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

        result.edges.push_back(std::move(edge));
    }

    ctx.progress(1.0f, fmt::format("CFG: {} blocks, {} edges",
                             result.block_count(), result.edge_count()));

    // Build O(1) adjacency index for successor/predecessor queries.
    result.build_adjacency();

    return PassResult::success(std::move(result));
}

}  // namespace tenet

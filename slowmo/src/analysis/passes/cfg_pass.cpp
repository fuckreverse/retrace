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

/// Classify an instruction mnemonic into a TerminatorKind.
/// Returns nullopt for non-branch instructions (ordinary fallthrough).
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
    std::unordered_set<uint64_t> block_leaders;
    block_leaders.reserve(sorted_pcs.size());

    // First PC is always a leader
    if (!sorted_pcs.empty()) {
        block_leaders.insert(sorted_pcs[0]);
    }

    // For each PC, decode and identify branch targets and fallthrough-after-branch
    for (uint64_t pc : sorted_pcs) {
        auto opcode = code_table.opcode_at(pc);
        if (!opcode) continue;

        auto d = decoder.decode(pc, *opcode);
        if (!d) continue;

        auto term = classify_terminator(d->mnemonic);
        if (!term) continue;

        // The instruction after a branch/call/return starts a new block
        uint64_t fallthrough_pc = pc + 4;
        if (xref.pc_to_inst_ids.count(fallthrough_pc)) {
            block_leaders.insert(fallthrough_pc);
        }

        // The target of a branch starts a new block
        // For direct branches (b, b.cond, cbz, cbnz, tbz, tbnz, bl)
        // we extract the target from the operand string
        if (*term == TerminatorKind::Branch ||
            *term == TerminatorKind::ConditionalBranch ||
            *term == TerminatorKind::Call) {
            auto target = extract_branch_target(d->op_str);
            if (target && xref.pc_to_inst_ids.count(*target)) {
                block_leaders.insert(*target);
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

    for (uint64_t pc : sorted_pcs) {
        if (block_leaders.count(pc)) {
            // Save the previous block if we were building one
            if (in_block) {
                // Classify the terminator of the block
                auto opcode = code_table.opcode_at(current_block.end_pc);
                if (opcode) {
                    auto d = decoder.decode(current_block.end_pc, *opcode);
                    if (d) {
                        auto term = classify_terminator(d->mnemonic);
                        current_block.terminator = term.value_or(TerminatorKind::Fallthrough);
                    }
                }
                // Compute execution count
                for (uint64_t insn_pc : current_block.instructions) {
                    current_block.execution_count += xref.execution_count(insn_pc);
                }
                result.blocks.emplace(current_block.start_pc, std::move(current_block));
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
        auto opcode = code_table.opcode_at(current_block.end_pc);
        if (opcode) {
            auto d = decoder.decode(current_block.end_pc, *opcode);
            if (d) {
                auto term = classify_terminator(d->mnemonic);
                current_block.terminator = term.value_or(TerminatorKind::Fallthrough);
            }
        }
        for (uint64_t insn_pc : current_block.instructions) {
            current_block.execution_count += xref.execution_count(insn_pc);
        }
        result.blocks.emplace(current_block.start_pc, std::move(current_block));
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

    using EdgeCountMap = std::unordered_map<EdgeKey, uint64_t, EdgeKeyHash>;

    /// Collector that accumulates CFG edge counts during trace scan.
    /// Supports parallel sharding: each shard independently tracks block
    /// transitions, then merge() sums edge counts.
    struct CFGEdgeCollector final : public TraceCollector {
        const CFGResult* cfg;       // Shared (read-only) block map
        EdgeCountMap edge_counts;
        uint64_t prev_block_start = UINT64_MAX;

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
            const BasicBlock* cur_block = cfg->block_containing(inst.pc);
            uint64_t cur_block_start = cur_block ? cur_block->start_pc : UINT64_MAX;

            if (prev_block_start != UINT64_MAX && cur_block_start != UINT64_MAX &&
                prev_block_start != cur_block_start) {
                edge_counts[EdgeKey{prev_block_start, cur_block_start}]++;
            }
            prev_block_start = cur_block_start;
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
    return PassResult::success(std::move(result));
}

}  // namespace tenet

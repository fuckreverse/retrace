#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <string>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct ProducerChainConfig {
    /// Starting instruction ID.
    uint64_t start_inst_id = 0;
    /// Starting register to trace back.
    uint8_t start_reg = 0;
    /// Maximum depth of the chain (0 = unlimited, default 64).
    uint32_t max_depth = 64;
    /// Follow memory loads (LDR → trace the address producer too).
    bool follow_memory = true;
};

// ─── Chain link ────────────────────────────────────────────────────────────

struct ProducerLink {
    uint64_t inst_id;          // Instruction that produced the value
    uint64_t pc;               // PC of that instruction
    uint8_t  produced_reg;     // Which register was written
    uint64_t value;            // Value that was produced

    /// Source registers that were read by this instruction.
    std::vector<uint8_t> source_regs;

    /// If this was a memory load, the address loaded from.
    uint64_t mem_addr = 0;
    bool is_memory_load = false;

    /// Disassembly (optional, filled if decoder available).
    std::string disassembly;
};

// ─── Result ────────────────────────────────────────────────────────────────

struct ProducerChainResult {
    /// The chain from target instruction backwards to the first producer.
    /// chain[0] = the target instruction, chain[last] = the ultimate source.
    std::vector<ProducerLink> chain;

    /// Was the chain truncated due to max_depth?
    bool truncated = false;

    /// Total instructions scanned (for performance reporting).
    uint64_t instructions_scanned = 0;
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Lightweight producer chain: traces the origin of a register value
/// by following reg_diff backwards without requiring Triton taint engine.
///
/// Algorithm:
///   1. At start_inst_id, find which instruction last wrote start_reg.
///   2. At that instruction, determine which source registers were read.
///   3. For each source register, find its last writer, and recurse.
///   4. Stop when: no writer found, depth limit reached, or value is immediate.
///
/// This is O(depth * log N) per level via RocksDB REG_WRITES inverted index
/// and direct random access (offset_of_with_pc + record_at), with no linear
/// scanning. Typically 100-1000x faster than full backward taint for simple
/// "where did this value come from" queries.
///
/// Dependencies: none.
///
/// Result type: ProducerChainResult
class ProducerChainPass final : public AnalysisPass {
public:
    explicit ProducerChainPass(ProducerChainConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "producer_chain"; }
    std::string_view description() const override {
        return "Lightweight backward register value provenance (no Triton)";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 3.0f; }

private:
    ProducerChainConfig cfg_;

    /// Find the most recent instruction before `before_id` that wrote `reg`.
    /// Returns 0 if not found within a reasonable scan distance.
    uint64_t find_last_writer(PassContext& ctx, uint64_t before_id, uint8_t reg);
};

}  // namespace tenet

#include "analysis/passes/vm_abstract_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/trace_collector.h"
#include "common/aarch64_classify.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "io/code_table.h"
#include "io/trace_reader.h"

#include <fmt/core.h>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace tenet {

// ─── Internal helpers ────────────────────────────────────────────────────────

namespace {

/// Number of dispatch iterations to sample for register state comparison.
constexpr uint32_t MAX_SAMPLE_ITERATIONS = 16;


// ─── Find indirect branches in loop body ─────────────────────────────────

/// Search the basic blocks of a loop body for BR or BLR instructions.
/// Returns the PC of the first indirect branch found, or 0 if none.
/// Sets `is_blr` to true if the found instruction is BLR (call-table dispatch).
uint64_t find_indirect_branch_in_loop(
    const LoopInfo& loop,
    const CFGResult& cfg,
    const CodeTable& code_table,
    bool& is_blr)
{
    is_blr = false;

    // Prefer CFG terminator classification (more reliable)
    for (uint64_t body_pc : loop.body_pcs) {
        auto it = cfg.blocks.find(body_pc);
        if (it == cfg.blocks.end()) continue;
        if (it->second.terminator == TerminatorKind::IndirectBranch) {
            // Check opcode to distinguish BR vs BLR
            auto code = code_table.opcode_at(it->second.end_pc);
            if (code.has_value()) {
                is_blr = aarch64::is_blr(*code);
            }
            return it->second.end_pc;
        }
    }

    // Fallback: scan raw opcode bytes for BR/BLR encoding
    for (uint64_t body_pc : loop.body_pcs) {
        auto code = code_table.opcode_at(body_pc);
        if (!code.has_value()) continue;
        uint32_t opcode = *code;
        if (aarch64::is_br(opcode)) {
            return body_pc;
        }
        if (aarch64::is_blr(opcode)) {
            is_blr = true;
            return body_pc;
        }
    }
    return 0;
}

// ─── Classify dispatcher type ────────────────────────────────────────────

DispatchType classify_dispatch_type(
    const LoopInfo& loop,
    const CFGResult& cfg,
    bool is_blr)
{
    if (is_blr) return DispatchType::CallTable;

    // Count conditional branches in loop body — a switch-case cascade
    // has many (one per case), while a computed jump table has few.
    uint32_t cond_branch_count = 0;
    for (uint64_t body_pc : loop.body_pcs) {
        auto it = cfg.blocks.find(body_pc);
        if (it == cfg.blocks.end()) continue;
        if (it->second.terminator == TerminatorKind::ConditionalBranch) {
            cond_branch_count++;
        }
    }
    if (cond_branch_count >= 3) return DispatchType::WhileSwitch;
    return DispatchType::IndirectBranch;
}

// ─── Infer VM-PC register ────────────────────────────────────────────────

/// Identify which register holds the VM program counter by looking for a
/// register whose value increments by a small constant step across dispatch
/// iterations.
///
/// Returns the register index (0-28) or 0xFF if not found.
uint8_t infer_vm_pc_register(
    RegisterFile& regfile,
    const std::vector<uint64_t>& header_inst_ids)
{
    if (header_inst_ids.size() < 4) return 0xFF;

    uint32_t n = std::min(static_cast<uint32_t>(header_inst_ids.size()),
                          MAX_SAMPLE_ITERATIONS);

    std::vector<RegState> states;
    states.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        states.push_back(regfile.state_before(header_inst_ids[i]));
    }

    uint8_t best_reg = 0xFF;
    float best_score = 0.0f;

    for (uint8_t r = 0; r <= 28; ++r) {
        // Compute deltas between consecutive iterations
        int64_t first_delta = static_cast<int64_t>(states[1].gpr[r]) -
                              static_cast<int64_t>(states[0].gpr[r]);
        if (first_delta == 0) continue;  // Invariant register

        uint32_t matching = 0;
        for (uint32_t i = 1; i < n; ++i) {
            int64_t d = static_cast<int64_t>(states[i].gpr[r]) -
                        static_cast<int64_t>(states[i - 1].gpr[r]);
            if (d == first_delta) matching++;
        }

        float consistency = static_cast<float>(matching) / static_cast<float>(n - 1);

        // VM-PC should increment by a small positive constant (1, 2, 4, 8)
        bool plausible_step = (first_delta >= 1 && first_delta <= 8);
        float score = consistency * (plausible_step ? 1.5f : 0.5f);

        if (score > best_score) {
            best_score = score;
            best_reg = r;
        }
    }

    // Require at least 80% consistency with a plausible step
    if (best_score < 1.2f) return 0xFF;
    return best_reg;
}

// ─── VMCollector — single-pass trace scan for handler discovery ──────────

/// Collector that observes every INST record to:
///   1. Track which handler PC follows each dispatch indirect-branch PC
///   2. Record the inst_id boundaries of each handler execution
///   3. Accumulate register/memory effects per handler
///
/// This replaces the naïve "seek to each header inst_id" approach with a
/// single sequential O(N) scan that is scan-fusion friendly.

struct HandlerExecution {
    uint64_t dispatch_inst_id = 0;   // inst_id of the header hit
    uint64_t handler_entry_pc = 0;
    uint64_t handler_first_inst_id = 0;
    uint64_t handler_last_inst_id = 0;
    uint64_t regs_read_mask = 0;
    uint64_t regs_written_mask = 0;
    uint32_t mem_reads = 0;
    uint32_t mem_writes = 0;
    std::vector<uint64_t> body_pcs;  // unique PCs visited during this execution
};

class VMCollector final : public TraceCollector {
public:
    VMCollector(uint64_t dispatch_header_pc,
                uint64_t indirect_branch_pc,
                const ankerl::unordered_dense::set<uint64_t>& body_pc_set)
        : dispatch_header_pc_(dispatch_header_pc)
        , indirect_branch_pc_(indirect_branch_pc)
        , body_pc_set_(body_pc_set) {}

    std::string_view name() const override { return "VMCollector"; }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        uint64_t pc = inst.pc;

        // ── State machine: track dispatch → handler transitions ──────────

        if (pc == dispatch_header_pc_) {
            // Entering a new dispatch iteration.
            // If we were inside a handler, close it.
            if (state_ == State::InHandler && !executions_.empty()) {
                executions_.back().handler_last_inst_id = last_inst_id_;
            }
            state_ = State::InDispatcher;
            current_dispatch_inst_id_ = inst_id;
        }
        else if (state_ == State::InDispatcher) {
            if (pc == indirect_branch_pc_) {
                // Hit the dispatch branch — next instruction is handler entry
                state_ = State::AwaitHandler;
            } else if (!body_pc_set_.contains(pc)) {
                // PC left the loop body (subroutine call etc.) — abort this dispatch
                state_ = State::Idle;
            }
        }
        else if (state_ == State::AwaitHandler) {
            // First instruction after BR — this is the handler entry
            HandlerExecution exec;
            exec.dispatch_inst_id = current_dispatch_inst_id_;
            exec.handler_entry_pc = pc;
            exec.handler_first_inst_id = inst_id;
            executions_.push_back(exec);
            state_ = State::InHandler;
            handler_pc_set_.clear();
            handler_pc_set_.insert(pc);
            // Record effects from this first instruction too
            accumulate_effects(inst);
        }
        else if (state_ == State::InHandler && !executions_.empty()) {
            // Inside a handler — accumulate effects
            auto& exec = executions_.back();
            if (handler_pc_set_.insert(pc).second) {
                exec.body_pcs.push_back(pc);
            }
            accumulate_effects(inst);
        }

        last_inst_id_ = inst_id;
    }

    void end() override {
        // Close the last handler if we ended mid-execution
        if (state_ == State::InHandler && !executions_.empty()) {
            executions_.back().handler_last_inst_id = last_inst_id_;
        }
    }

    std::vector<HandlerExecution>& executions() { return executions_; }

private:
    void accumulate_effects(const InstView& inst) {
        if (executions_.empty()) return;
        auto& exec = executions_.back();

        for (uint8_t d = 0; d < inst.reg_diff_count; ++d) {
            auto rd = inst.reg_diff(d);
            if (rd.index < 34) {
                exec.regs_written_mask |= (1ULL << rd.index);
            }
        }

        // Track register reads from instruction encoding
        // (approximation: any register that is NOT only written is likely read)
        // For now, use the code table if available — but InstView doesn't expose
        // read registers directly. We accumulate from mem_access base regs instead.
        for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
            auto ma = inst.mem_access(m);
            if (ma.type & 0x01) exec.mem_reads++;    // MEMORY_READ bit
            else if (ma.type & 0x02) exec.mem_writes++;  // MEMORY_WRITE bit
        }
    }

    enum class State { Idle, InDispatcher, AwaitHandler, InHandler };

    uint64_t dispatch_header_pc_;
    uint64_t indirect_branch_pc_;
    const ankerl::unordered_dense::set<uint64_t>& body_pc_set_;

    State state_ = State::Idle;
    uint64_t current_dispatch_inst_id_ = 0;
    uint64_t last_inst_id_ = 0;

    std::vector<HandlerExecution> executions_;
    ankerl::unordered_dense::set<uint64_t> handler_pc_set_;  // PCs in current handler execution
};

}  // anonymous namespace

// ─── VMAbstractPass::run ─────────────────────────────────────────────────

PassResult VMAbstractPass::run(PassContext& ctx) {
    // ── Step 1: Get dependencies ────────────────────────────────────────
    const auto& loop_result = ctx.require<LoopResult>("loop");
    const auto& cfg_result  = ctx.require<CFGResult>("cfg");
    const auto& xref        = ctx.require<XrefResult>("xref");

    auto& regfile    = ctx.regfile();
    auto& code_table = ctx.code_table();

    VMAbstractResult result;
    const auto& range = ctx.range();

    ctx.progress(0.0f, "VM abstract: scanning for dispatcher candidates...");

    // ── Step 2: Find dispatcher candidates ──────────────────────────────
    //
    // A VM dispatcher is a loop with:
    //   - High iteration count (many VM opcodes executed)
    //   - An indirect branch (BR Xn) in the body
    //   - The BR targets many distinct PCs (different handlers)

    struct Candidate {
        size_t   loop_index = 0;
        uint64_t header_pc = 0;
        uint64_t indirect_branch_pc = 0;
        uint64_t iteration_count = 0;
        float    score = 0.0f;
        bool     is_blr = false;          // BLR dispatch (call-table style)
        std::vector<uint64_t> header_inst_ids;
    };

    std::vector<Candidate> candidates;

    if (config_.dispatcher.has_value()) {
        // ── Hint-driven ─────────────────────────────────────────────────
        const auto& hint = *config_.dispatcher;
        Candidate cand;
        cand.header_pc = hint.loop_header_pc;
        cand.indirect_branch_pc = hint.indirect_branch_pc;

        bool loop_found = false;
        for (size_t i = 0; i < loop_result.loops.size(); ++i) {
            if (loop_result.loops[i].header_pc == hint.loop_header_pc) {
                cand.loop_index = i;
                cand.iteration_count = loop_result.loops[i].iteration_count;
                loop_found = true;
                break;
            }
        }

        if (!loop_found) {
            ctx.progress(1.0f, fmt::format(
                "VM abstract: hinted dispatcher at {:#x} not found in loop results",
                hint.loop_header_pc));
            return PassResult::success(std::move(result));
        }

        bool hint_is_blr = false;
        if (cand.indirect_branch_pc == 0) {
            cand.indirect_branch_pc = find_indirect_branch_in_loop(
                loop_result.loops[cand.loop_index], cfg_result, code_table, hint_is_blr);
        } else {
            // Check if the hinted PC is BLR
            auto code = code_table.opcode_at(cand.indirect_branch_pc);
            if (code.has_value()) hint_is_blr = aarch64::is_blr(*code);
        }

        cand.is_blr = hint_is_blr;
        cand.score = 10.0f;
        candidates.push_back(std::move(cand));

    } else if (config_.auto_detect) {
        // ── Auto-detection ──────────────────────────────────────────────
        for (size_t i = 0; i < loop_result.loops.size(); ++i) {
            if (ctx.cancelled()) return PassResult::failed("Cancelled");

            const auto& loop = loop_result.loops[i];
            if (loop.iteration_count < config_.min_dispatch_iterations) continue;

            bool cand_is_blr = false;
            uint64_t br_pc = find_indirect_branch_in_loop(loop, cfg_result, code_table, cand_is_blr);
            if (br_pc == 0) continue;

            Candidate cand;
            cand.loop_index = i;
            cand.header_pc = loop.header_pc;
            cand.indirect_branch_pc = br_pc;
            cand.iteration_count = loop.iteration_count;
            cand.is_blr = cand_is_blr;

            // Score: high iterations + compact body → likely dispatcher
            float iter_score = std::min(1.0f,
                static_cast<float>(loop.iteration_count) / 100.0f);
            float body_compactness = loop.body_pcs.size() < 50  ? 1.0f :
                                     loop.body_pcs.size() < 200 ? 0.5f : 0.2f;
            cand.score = iter_score * 0.6f + body_compactness * 0.4f;

            candidates.push_back(std::move(cand));
        }

        std::sort(candidates.begin(), candidates.end(),
                  [](const Candidate& a, const Candidate& b) {
                      return a.score > b.score;
                  });
    }

    if (candidates.empty()) {
        ctx.progress(1.0f, "VM abstract: no VM dispatcher found");
        return PassResult::success(std::move(result));
    }

    // Collect header inst_ids for each candidate from XRef
    for (auto& cand : candidates) {
        if (!xref.has_pc(cand.header_pc)) continue;
        cand.header_inst_ids.reserve(
            std::min(static_cast<uint64_t>(10000), cand.iteration_count));
        for (uint64_t iid : xref.inst_ids_at(cand.header_pc)) {
            if (iid < range.start_inst_id) continue;
            if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
            cand.header_inst_ids.push_back(iid);
            if (cand.header_inst_ids.size() >= 10000) break;
        }
    }

    // Pick the best candidate that has enough header hits
    Candidate* best = nullptr;
    for (auto& c : candidates) {
        if (c.header_inst_ids.size() >= 3) {
            best = &c;
            break;
        }
    }

    if (!best) {
        ctx.progress(1.0f, "VM abstract: no valid VM dispatcher found");
        return PassResult::success(std::move(result));
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    const auto& loop = loop_result.loops[best->loop_index];

    ctx.progress(0.15f, fmt::format(
        "VM abstract: dispatcher at {:#x} ({} iterations), running trace scan...",
        best->header_pc, best->iteration_count));

    // ── Step 3: Single-pass trace scan to discover handlers ─────────────
    //
    // Use a VMCollector in a TraceScanEngine to find every dispatch→handler
    // transition in one sequential pass.  This is dramatically faster than
    // seeking to each header inst_id individually.

    ankerl::unordered_dense::set<uint64_t> body_pc_set(
        loop.body_pcs.begin(), loop.body_pcs.end());

    VMCollector collector(best->header_pc, best->indirect_branch_pc, body_pc_set);

    {
        auto engine = ctx.make_scan_engine();
        engine.add_collector(&collector);
        engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                ctx.progress(0.15f + 0.45f * static_cast<float>(processed) /
                             static_cast<float>(total));
            }
        });
        engine.set_cancel_check([&]() { return ctx.cancelled(); });
        engine.run(range.start_inst_id, range.end_inst_id);
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    auto& executions = collector.executions();

    if (executions.empty()) {
        ctx.progress(1.0f, "VM abstract: no handler executions found");
        return PassResult::success(std::move(result));
    }

    // Count distinct handler entry PCs
    ankerl::unordered_dense::set<uint64_t> unique_handler_pcs;
    for (const auto& exec : executions) {
        if (exec.handler_entry_pc != 0) {
            unique_handler_pcs.insert(exec.handler_entry_pc);
        }
    }

    if (unique_handler_pcs.size() < config_.min_handler_count) {
        ctx.progress(1.0f, fmt::format(
            "VM abstract: only {} distinct targets (need >= {}), not a VM",
            unique_handler_pcs.size(), config_.min_handler_count));
        return PassResult::success(std::move(result));
    }

    ctx.progress(0.6f, fmt::format(
        "VM abstract: found {} handlers across {} executions",
        unique_handler_pcs.size(), executions.size()));

    // ── Step 4: Build dispatcher info ───────────────────────────────────

    result.dispatcher.loop_header_pc = best->header_pc;
    result.dispatcher.indirect_branch_pc = best->indirect_branch_pc;
    result.dispatcher.iteration_count = best->iteration_count;
    result.dispatcher.confidence = std::min(1.0f, best->score);
    result.dispatcher.dispatch_type = classify_dispatch_type(loop, cfg_result, best->is_blr);

    // Identify state vs invariant registers across dispatch iterations
    {
        uint32_t n = std::min(static_cast<uint32_t>(best->header_inst_ids.size()),
                              MAX_SAMPLE_ITERATIONS);
        std::vector<RegState> states;
        states.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            states.push_back(regfile.state_before(best->header_inst_ids[i]));
        }

        for (uint8_t r = 0; r <= 28; ++r) {
            bool changed = false;
            for (uint32_t i = 1; i < n; ++i) {
                if (states[i].gpr[r] != states[0].gpr[r]) {
                    changed = true;
                    break;
                }
            }
            if (changed) result.dispatcher.state_regs.push_back(r);
            else         result.dispatcher.invariant_regs.push_back(r);
        }
    }

    // ── Step 5: Identify VM-PC register ─────────────────────────────────

    ctx.progress(0.65f, "VM abstract: identifying VM-PC register...");

    if (config_.vm_pc.has_value() && config_.vm_pc->reg != 0xFF) {
        result.vm_pc_reg = config_.vm_pc->reg;
        result.bytecode_base = config_.vm_pc->bytecode_base;
    } else {
        result.vm_pc_reg = infer_vm_pc_register(regfile, best->header_inst_ids);
    }

    // Infer bytecode address range from observed VM-PC values
    if (result.vm_pc_reg != 0xFF) {
        uint32_t n = std::min(static_cast<uint32_t>(best->header_inst_ids.size()),
                              MAX_SAMPLE_ITERATIONS);
        uint64_t min_vpc = UINT64_MAX, max_vpc = 0;
        for (uint32_t i = 0; i < n; ++i) {
            auto state = regfile.state_before(best->header_inst_ids[i]);
            uint64_t vpc = state.gpr[result.vm_pc_reg];
            if (vpc < min_vpc) min_vpc = vpc;
            if (vpc > max_vpc) max_vpc = vpc;
        }
        if (min_vpc != UINT64_MAX) {
            result.bytecode_base = min_vpc;
            uint64_t opcode_size = 8;  // default assumption
            if (config_.opcode_format.has_value() && config_.opcode_format->opcode_size > 0) {
                opcode_size = config_.opcode_format->opcode_size;
            }
            result.bytecode_end = max_vpc + opcode_size;
        }
    }

    // ── Step 6: Build handler objects ────────────────────────────────────

    ctx.progress(0.7f, "VM abstract: building handler profiles...");

    // Merge provided handler PCs with discovered ones (deduplicated)
    ankerl::unordered_dense::set<uint64_t> handler_pc_set;
    std::vector<uint64_t> handler_pcs;
    auto add_handler_pc = [&](uint64_t pc) {
        if (handler_pc_set.insert(pc).second) handler_pcs.push_back(pc);
    };
    for (uint64_t pc : config_.handler_entry_pcs) add_handler_pc(pc);
    for (uint64_t pc : unique_handler_pcs) add_handler_pc(pc);
    std::sort(handler_pcs.begin(), handler_pcs.end());

    // Group executions by handler entry PC
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> exec_by_handler;
    for (size_t i = 0; i < executions.size(); ++i) {
        exec_by_handler[executions[i].handler_entry_pc].push_back(i);
    }

    for (uint64_t hpc : handler_pcs) {
        VMHandler handler;
        handler.entry_pc = hpc;

        auto it = exec_by_handler.find(hpc);
        if (it != exec_by_handler.end()) {
            handler.execution_count = it->second.size();

            // Merge register/memory effects and body PCs from all executions
            ankerl::unordered_dense::set<uint64_t> all_body_pcs;
            all_body_pcs.insert(hpc);
            for (size_t idx : it->second) {
                const auto& exec = executions[idx];
                handler.regs_read_mask  |= exec.regs_read_mask;
                handler.regs_written_mask |= exec.regs_written_mask;
                handler.mem_reads += exec.mem_reads;
                handler.mem_writes += exec.mem_writes;
                for (uint64_t bpc : exec.body_pcs) all_body_pcs.insert(bpc);
            }

            // Build sorted body_pcs list
            handler.body_pcs.assign(all_body_pcs.begin(), all_body_pcs.end());
            std::sort(handler.body_pcs.begin(), handler.body_pcs.end());

            // exit_pc = last body PC (highest address in the handler)
            if (!handler.body_pcs.empty()) {
                handler.exit_pc = handler.body_pcs.back();
            }
        }

        // Apply semantic label from config hint
        auto label_it = config_.handler_names.find(hpc);
        if (label_it != config_.handler_names.end()) {
            handler.label = label_it->second;
        }

        result.handler_by_pc[hpc] = result.handlers.size();
        result.handlers.push_back(std::move(handler));
    }

    // ── Step 6b: Infer VM architecture type ────────────────────────────

    if (config_.arch_type_hint != VMArchType::Unknown) {
        result.arch_type = config_.arch_type_hint;
    } else {
        // Lightweight inference from handler memory access patterns:
        //   - StackMachine: handlers frequently push/pop via a single pointer
        //     (one register has many writes with small constant offsets → SP-like)
        //   - RegisterMachine: handlers read/write at fixed offsets from a base
        //     register (the VM register file), spread across many distinct offsets
        //
        // Heuristic: look at dispatcher invariant_regs. For each invariant reg,
        // check if handlers predominantly write near it (SP-like → stack) or read
        // at scattered fixed offsets (regfile-like → register machine).
        //
        // Simple signal: if most handlers do both reads AND writes (load+store
        // with roughly equal counts), it's likely a register machine accessing a
        // regfile. If handlers mostly just push (write) or pop (read), it's a stack.

        uint32_t load_dominant = 0, store_dominant = 0, balanced = 0;
        for (const auto& h : result.handlers) {
            if (h.execution_count == 0) continue;
            uint32_t avg_reads  = h.mem_reads  / static_cast<uint32_t>(h.execution_count);
            uint32_t avg_writes = h.mem_writes / static_cast<uint32_t>(h.execution_count);
            if (avg_reads == 0 && avg_writes == 0) continue;
            if (avg_reads > avg_writes * 2)       load_dominant++;
            else if (avg_writes > avg_reads * 2)  store_dominant++;
            else                                   balanced++;
        }

        uint32_t total = load_dominant + store_dominant + balanced;
        if (total >= 3) {
            // Stack machines: most handlers are either push-only or pop-only
            if (load_dominant + store_dominant > balanced * 2) {
                result.arch_type = VMArchType::StackMachine;
            }
            // Register machines: most handlers do balanced read+write
            else if (balanced > (load_dominant + store_dominant)) {
                result.arch_type = VMArchType::RegisterMachine;
            }
        }
    }

    // ── Step 7: Build VM execution trace (step sequence) ────────────────

    ctx.progress(0.8f, "VM abstract: building VM step sequence...");

    result.steps.reserve(executions.size());

    for (const auto& exec : executions) {
        VMStep step;
        step.inst_id_start = exec.dispatch_inst_id;
        step.inst_id_end = exec.handler_last_inst_id;
        step.handler_entry_pc = exec.handler_entry_pc;

        // Decode VM-PC value and opcode
        if (result.vm_pc_reg != 0xFF) {
            auto state = regfile.state_before(exec.dispatch_inst_id);
            step.vm_pc_value = state.gpr[result.vm_pc_reg];
            step.vm_pc_valid = true;

            if (config_.opcode_format.has_value()) {
                auto& ofmt = *config_.opcode_format;
                if (ofmt.opcode_size > 0 && ofmt.opcode_size <= 8) {
                    auto& memory = ctx.memory();
                    auto mem = memory.read(step.vm_pc_value,
                                           static_cast<uint8_t>(ofmt.opcode_size),
                                           exec.dispatch_inst_id);
                    // Check that all requested bytes are known
                    bool all_known = true;
                    for (uint8_t b = 0; b < ofmt.opcode_size; ++b) {
                        if (!mem.known[b]) { all_known = false; break; }
                    }
                    if (all_known) {
                        uint64_t raw = 0;
                        std::memcpy(&raw, mem.data.data(),
                                    std::min(static_cast<size_t>(ofmt.opcode_size),
                                             sizeof(raw)));
                        step.opcode_value = (raw & ofmt.opcode_mask) >> ofmt.opcode_shift;
                        step.opcode_valid = true;

                        // Record opcode→handler mapping
                        auto hit = result.handler_by_pc.find(step.handler_entry_pc);
                        if (hit != result.handler_by_pc.end()) {
                            auto& h = result.handlers[hit->second];
                            bool dup = false;
                            for (uint64_t ov : h.opcode_values) {
                                if (ov == step.opcode_value) { dup = true; break; }
                            }
                            if (!dup) h.opcode_values.push_back(step.opcode_value);
                        }
                    }
                }
            }
        }

        // Decode VM context structure fields if hint provided
        if (config_.vm_context.has_value() && config_.vm_context->ctx_base_reg != 0xFF) {
            auto& vctx = *config_.vm_context;
            auto state = regfile.state_before(exec.dispatch_inst_id);
            uint64_t ctx_base = state.gpr[vctx.ctx_base_reg];
            auto& memory = ctx.memory();

            for (const auto& field : vctx.fields) {
                uint64_t field_addr = ctx_base + field.offset;
                auto mem = memory.read(field_addr, 8, exec.dispatch_inst_id);
                // Check that at least 8 bytes are known
                bool known = true;
                for (uint8_t b = 0; b < 8; ++b) {
                    if (!mem.known[b]) { known = false; break; }
                }
                if (known) {
                    uint64_t val = 0;
                    std::memcpy(&val, mem.data.data(), 8);
                    step.ctx_fields.emplace_back(field.name, val);
                }
            }
        }

        result.steps.push_back(std::move(step));
    }

    // ── Step 8: Statistics ──────────────────────────────────────────────

    result.total_vm_steps = result.steps.size();
    result.total_native_instructions = 0;
    for (const auto& step : result.steps) {
        if (step.inst_id_end > step.inst_id_start) {
            result.total_native_instructions += (step.inst_id_end - step.inst_id_start + 1);
        }
    }

    ctx.progress(1.0f, fmt::format(
        "VM abstract: dispatcher at {:#x}, {} handlers, {} VM steps, VM-PC={}",
        result.dispatcher.loop_header_pc,
        result.handlers.size(),
        result.total_vm_steps,
        result.vm_pc_reg != 0xFF ? fmt::format("x{}", result.vm_pc_reg) : "unknown"));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

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

// ─── ThreadedCollector — single-pass scan for threaded-code VMs ──────────
//
// Threaded-code (direct-threaded / indirect-threaded) VMs have no central
// dispatcher loop.  Instead every handler ends with an inline "fetch next
// opcode + branch to next handler" sequence.  The observable pattern in the
// trace is:
//
//   handler_A body ... → dispatch_pc_1 (fetch/decode) → BR Xn → handler_B body
//   handler_B body ... → dispatch_pc_2 (fetch/decode) → BR Xn → handler_C body
//   ...
//
// where dispatch_pc_* is one of the "threaded dispatch PCs" provided by the
// user (the common tail-fetch PCs shared by every handler).
//
// Detection strategy:
//   1. The user supplies a set of "dispatch PCs" (the common fetch+dispatch
//      instruction addresses that appear in every handler's tail).
//   2. The collector observes every instruction.  When it hits a dispatch PC,
//      it closes the current handler and begins watching for the next handler
//      entry (the first new PC after the next BR Xn in the dispatch sequence).
//
// This is architecturally identical to VMCollector's InDispatcher→AwaitHandler
// transition, except that "loop header hit" is replaced by "dispatch PC hit".

class ThreadedCollector final : public TraceCollector {
public:
    ThreadedCollector(const ankerl::unordered_dense::set<uint64_t>& dispatch_pc_set,
                      const ankerl::unordered_dense::set<uint64_t>& indirect_branch_pcs)
        : dispatch_pc_set_(dispatch_pc_set)
        , indirect_branch_pcs_(indirect_branch_pcs) {}

    std::string_view name() const override { return "ThreadedCollector"; }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        uint64_t pc = inst.pc;

        switch (state_) {
            case State::Idle:
            case State::InHandler:
                if (dispatch_pc_set_.contains(pc)) {
                    // Entering the tail-dispatch sequence; close the current handler.
                    if (state_ == State::InHandler && !executions_.empty()) {
                        executions_.back().handler_last_inst_id = last_inst_id_;
                    }
                    state_ = State::InDispatch;
                    current_dispatch_inst_id_ = inst_id;
                } else if (state_ == State::InHandler && !executions_.empty()) {
                    auto& exec = executions_.back();
                    if (handler_pc_set_.insert(pc).second) {
                        exec.body_pcs.push_back(pc);
                    }
                    accumulate_effects(inst);
                }
                break;

            case State::InDispatch:
                if (indirect_branch_pcs_.contains(pc)) {
                    // The dispatch BR — next instruction is the new handler entry.
                    state_ = State::AwaitHandler;
                } else if (!dispatch_pc_set_.contains(pc)) {
                    // Unexpected PC in dispatch sequence — reset.
                    state_ = State::Idle;
                }
                break;

            case State::AwaitHandler:
                // First instruction after BR — handler entry.
                {
                    HandlerExecution exec;
                    exec.dispatch_inst_id     = current_dispatch_inst_id_;
                    exec.handler_entry_pc     = pc;
                    exec.handler_first_inst_id = inst_id;
                    executions_.push_back(exec);
                    state_ = State::InHandler;
                    handler_pc_set_.clear();
                    handler_pc_set_.insert(pc);
                    accumulate_effects(inst);
                }
                break;
        }

        last_inst_id_ = inst_id;
    }

    void end() override {
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
            if (rd.index < 34) exec.regs_written_mask |= (1ULL << rd.index);
        }
        for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
            auto ma = inst.mem_access(m);
            if (ma.type & 0x01) exec.mem_reads++;
            else if (ma.type & 0x02) exec.mem_writes++;
        }
    }

    enum class State { Idle, InDispatch, AwaitHandler, InHandler };

    const ankerl::unordered_dense::set<uint64_t>& dispatch_pc_set_;
    const ankerl::unordered_dense::set<uint64_t>& indirect_branch_pcs_;

    State    state_                    = State::Idle;
    uint64_t current_dispatch_inst_id_ = 0;
    uint64_t last_inst_id_             = 0;

    std::vector<HandlerExecution>       executions_;
    ankerl::unordered_dense::set<uint64_t> handler_pc_set_;
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

    // ── FetchOnly short-circuit ───────────────────────────────────────────
    //
    // Some VMs obfuscate the handler-dispatch decision itself beyond what any
    // generic collector state-machine can recognize — e.g. a CFF-wrapped
    // binary-search / linear opcode-compare tree where *every* comparison
    // node (not just the final "handler selected" edge) routes through the
    // same "BL cff_stub -> computed RET" primitive.  In that case there is no
    // PC that unambiguously means "handler entry", so VMCollector/
    // ThreadedCollector cannot attribute executions to handlers at all.
    //
    // FetchOnly sidesteps handler discovery entirely: it only requires a
    // single stable "fetch / loop-back" anchor PC (`dispatcher.loop_header_pc`)
    // that is hit exactly once per VM instruction (e.g. the interpreter
    // loop's back-edge landing point). At each hit, it snapshots VM state
    // (vm_pc, ctx_fields, vm_registers) via the same Step-7 logic used by the
    // other topologies — no loop/CFG dependency, no handler classification,
    // no opcode decoding.
    // A FetchOnly hint may anchor on either a code PC (`loop_header_pc`,
    // resolved via xref below) or a memory location (`mem_anchor_addr`,
    // resolved via MemoryModel::write_history below) — see DispatcherHint
    // for why the memory anchor exists (heavily CFF-obfuscated VMs where the
    // fetch/PC++ logic has no single stable PC).
    bool fetch_only_pc_anchor =
        (config_.dispatch_type_hint == DispatchType::FetchOnly) &&
        config_.dispatcher.has_value() &&
        config_.dispatcher->loop_header_pc != 0;
    bool fetch_only_mem_anchor =
        (config_.dispatch_type_hint == DispatchType::FetchOnly) &&
        config_.dispatcher.has_value() &&
        config_.dispatcher->mem_anchor_addr != 0;
    bool fetch_only_short_circuit = fetch_only_pc_anchor || fetch_only_mem_anchor;

    // ── ThreadedCode short-circuit ───────────────────────────────────────
    //
    // ThreadedCode topology has no real dispatch loop header: every handler
    // tail-chains directly into the next handler via a shared "fetch+decode"
    // instruction sequence (threaded_dispatch_pcs) followed by an indirect
    // (or, on heavily-CFF'd binaries, a *computed-RET*-based) transfer.
    // On such binaries the "loop" pass — which only sees back-edges realized
    // as direct B/B.cond/BR/BLR in the *dynamic* CFG — frequently cannot
    // detect the real interpreter loop at all (CFF stubs implement every
    // control-flow edge, including the loop back-edge, as
    // "BL stub -> computed index -> ADD LR,LR,offset -> RET", which the CFG
    // call/return pairing does not recognize as a loop back-edge).
    //
    // When the caller explicitly asks for ThreadedCode via dispatch_type_hint
    // and supplies threaded_dispatch_pcs, skip the loop-lookup requirement
    // entirely and go straight to the ThreadedCollector path below — it only
    // needs the dispatch PC set + indirect-branch PC set, never a LoopInfo.
    bool threaded_short_circuit =
        (config_.dispatch_type_hint == DispatchType::ThreadedCode) &&
        !config_.threaded_dispatch_pcs.empty();

    if (fetch_only_mem_anchor) {
        // Memory-anchor FetchOnly: header_inst_ids come from
        // MemoryModel::write_history() on `mem_anchor_addr`, not from an
        // xref PC lookup. Populate header_inst_ids right here (the generic
        // "Collect header inst_ids for each candidate from XRef" loop below
        // skips this candidate since header_pc == 0 has no xref entry — see
        // the `cand.header_pc != 0` guard there).
        Candidate cand;
        cand.header_pc = 0;  // no single code PC for this anchor — see mem_anchor_addr
        cand.score = 10.0f;

        auto write_ids = ctx.memory().write_history(
            config_.dispatcher->mem_anchor_addr, config_.dispatcher->mem_anchor_size);
        cand.header_inst_ids.reserve(std::min<size_t>(write_ids.size(), 20000));
        for (uint64_t iid : write_ids) {
            if (iid < range.start_inst_id) continue;
            if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
            cand.header_inst_ids.push_back(iid);
            if (cand.header_inst_ids.size() >= 20000) break;
        }
        candidates.push_back(std::move(cand));

    } else if (fetch_only_pc_anchor) {
        Candidate cand;
        cand.header_pc = config_.dispatcher->loop_header_pc;
        cand.score = 10.0f;
        candidates.push_back(std::move(cand));

    } else if (threaded_short_circuit) {
        Candidate cand;
        cand.header_pc = *config_.threaded_dispatch_pcs.begin();
        cand.indirect_branch_pc = config_.dispatcher.has_value()
            ? config_.dispatcher->indirect_branch_pc : 0;
        cand.score = 10.0f;
        candidates.push_back(std::move(cand));

    } else if (config_.dispatcher.has_value()) {
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
                "VM abstract: hinted dispatcher at {:#x} not found in loop results "
                "(if this VM's back-edge is realized via CFF-computed RET rather than "
                "a direct B/BR, try dispatch_type_hint=ThreadedCode + threaded_dispatch_pcs "
                "instead of dispatcher_pc)",
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

    // Decide which collector to use.
    bool use_threaded = (config_.dispatch_type_hint == DispatchType::ThreadedCode)
                     && !config_.threaded_dispatch_pcs.empty();
    bool use_fetch_only = fetch_only_short_circuit;

    // `loop` is only meaningful for the loop-based (!use_threaded && !use_fetch_only)
    // path below (classify_dispatch_type() at the bottom of this block). The
    // threaded_short_circuit / fetch_only_short_circuit candidate's loop_index
    // is a dummy (0) — never dereference loop_result.loops with it.
    static const LoopInfo kEmptyLoop{};
    const LoopInfo& loop = (use_threaded || use_fetch_only || best->loop_index >= loop_result.loops.size())
        ? kEmptyLoop
        : loop_result.loops[best->loop_index];

    ctx.progress(0.15f, fmt::format(
        "VM abstract: dispatcher at {:#x} ({} iterations), running trace scan...",
        best->header_pc, best->iteration_count));

    // ── Step 3: Single-pass trace scan to discover handlers ─────────────
    //
    // Two modes depending on dispatch topology:
    //
    //   WhileSwitch / IndirectBranch / CallTable:
    //     Use VMCollector (state: InDispatcher → AwaitHandler → InHandler).
    //     Anchored on the loop header PC.
    //
    //   ThreadedCode:
    //     Use ThreadedCollector (state: InDispatch → AwaitHandler → InHandler).
    //     Anchored on the set of threaded_dispatch_pcs provided by the user.
    //     Falls back to VMCollector if no threaded_dispatch_pcs are given.

    // Storage for whichever collector is active.
    // One of these will be engaged; executions_ points to the live one.
    std::vector<HandlerExecution>* executions_ptr = nullptr;

    // VMCollector path (default)
    ankerl::unordered_dense::set<uint64_t> body_pc_set;
    std::unique_ptr<VMCollector> vm_collector;

    // ThreadedCollector path
    ankerl::unordered_dense::set<uint64_t> threaded_dispatch_pc_set;
    ankerl::unordered_dense::set<uint64_t> threaded_br_pc_set;
    std::unique_ptr<ThreadedCollector> threaded_collector;

    // FetchOnly path: no state machine, no trace scan engine at all — the
    // XRef-derived `best->header_inst_ids` (every hit of dispatcher_pc) *is*
    // the full execution list. One HandlerExecution per hit, all fields
    // beyond dispatch_inst_id left at their zero defaults (no handler concept).
    std::vector<HandlerExecution> fetch_only_executions;

    if (use_fetch_only) {
        fetch_only_executions.reserve(best->header_inst_ids.size());
        for (uint64_t iid : best->header_inst_ids) {
            HandlerExecution exec;
            exec.dispatch_inst_id      = iid;
            exec.handler_entry_pc      = 0;   // no handler concept in this mode
            exec.handler_first_inst_id = 0;
            exec.handler_last_inst_id  = iid; // step "ends" at the same fetch point
            fetch_only_executions.push_back(exec);
        }
        executions_ptr = &fetch_only_executions;

        // Synthesise dispatcher info: the fetch anchor IS the loop header.
        result.dispatcher.loop_header_pc     = best->header_pc;
        result.dispatcher.indirect_branch_pc = 0;
        result.dispatcher.iteration_count    = fetch_only_executions.size();
        result.dispatcher.dispatch_type      = DispatchType::FetchOnly;
        result.dispatcher.confidence         = 0.9f;  // user-provided hint

    } else if (use_threaded) {
        // Build dispatch PC set from user hints.
        // threaded_dispatch_pcs are stored as runtime addresses (with slide)
        // consistent with how dispatcher_hint.loop_header_pc is stored.
        for (uint64_t pc : config_.threaded_dispatch_pcs) {
            threaded_dispatch_pc_set.insert(pc);
        }
        // Collect all indirect-branch PCs reachable from any of the dispatch PCs.
        // We scan the CFG for BR/BLR instructions within a short window around
        // each dispatch PC.  Alternatively, the user can include the BR itself in
        // threaded_dispatch_pcs and we will detect it via the CFG.
        // For now, add any BR/BLR that immediately follows a dispatch PC in the
        // code_table (this covers the common "LDR X8, [X20, X0, LSL #3]; BR X8"
        // pattern).
        for (uint64_t dpc : threaded_dispatch_pc_set) {
            // Walk up to 8 instructions forward looking for a BR/BLR
            uint64_t probe = dpc;
            for (int step_i = 0; step_i < 8; ++step_i) {
                auto code = code_table.opcode_at(probe);
                if (code.has_value()) {
                    if (aarch64::is_br(*code) || aarch64::is_blr(*code)) {
                        threaded_br_pc_set.insert(probe);
                        break;
                    }
                }
                probe += 4;  // AArch64: fixed 4-byte instruction
            }
        }
        // Also include any indirect branch PC from the best candidate if
        // it was auto-detected (handles mixed-topology traces).
        if (best->indirect_branch_pc != 0) {
            threaded_br_pc_set.insert(best->indirect_branch_pc);
        }

        threaded_collector = std::make_unique<ThreadedCollector>(
            threaded_dispatch_pc_set, threaded_br_pc_set);

        auto engine = ctx.make_scan_engine();
        engine.add_collector(threaded_collector.get());
        engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                ctx.progress(0.15f + 0.45f * static_cast<float>(processed) /
                             static_cast<float>(total));
            }
        });
        engine.set_cancel_check([&]() { return ctx.cancelled(); });
        engine.run(range.start_inst_id, range.end_inst_id);

        executions_ptr = &threaded_collector->executions();

        // Synthesise dispatcher info (no real loop, fill with sentinel values)
        result.dispatcher.loop_header_pc     = 0;
        result.dispatcher.indirect_branch_pc =
            threaded_br_pc_set.empty() ? 0 : *threaded_br_pc_set.begin();
        result.dispatcher.iteration_count    = executions_ptr->size();
        result.dispatcher.dispatch_type      = DispatchType::ThreadedCode;
        result.dispatcher.confidence         = 0.9f;  // user-provided hint

    } else {
        // ── WhileSwitch / IndirectBranch / CallTable path (original) ────
        body_pc_set.insert(loop.body_pcs.begin(), loop.body_pcs.end());
        vm_collector = std::make_unique<VMCollector>(
            best->header_pc, best->indirect_branch_pc, body_pc_set);

        {
            auto engine = ctx.make_scan_engine();
            engine.add_collector(vm_collector.get());
            engine.set_progress([&](uint64_t processed, uint64_t total) {
                if (total > 0) {
                    ctx.progress(0.15f + 0.45f * static_cast<float>(processed) /
                                 static_cast<float>(total));
                }
            });
            engine.set_cancel_check([&]() { return ctx.cancelled(); });
            engine.run(range.start_inst_id, range.end_inst_id);
        }

        executions_ptr = &vm_collector->executions();
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    auto& executions = *executions_ptr;

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

    // FetchOnly has no handler concept at all — skip the min_handler_count
    // gate entirely (unique_handler_pcs will always be empty/0 since every
    // exec.handler_entry_pc is 0 in this mode).
    if (!use_fetch_only && unique_handler_pcs.size() < config_.min_handler_count) {
        ctx.progress(1.0f, fmt::format(
            "VM abstract: only {} distinct targets (need >= {}), not a VM",
            unique_handler_pcs.size(), config_.min_handler_count));
        return PassResult::success(std::move(result));
    }

    if (use_fetch_only) {
        ctx.progress(0.6f, fmt::format(
            "VM abstract: FetchOnly mode — {} fetch-cycle snapshots", executions.size()));
    } else {
        ctx.progress(0.6f, fmt::format(
            "VM abstract: found {} handlers across {} executions",
            unique_handler_pcs.size(), executions.size()));
    }

    // ── Step 4: Build dispatcher info ───────────────────────────────────
    //
    // ThreadedCode / FetchOnly paths: dispatcher info was already filled
    // during Step 3 (no real loop header, or the anchor PC IS the header
    // with no separate indirect-branch/handler classification).  Only fill
    // for loop-based topologies here.

    if (!use_threaded && !use_fetch_only) {
        result.dispatcher.loop_header_pc   = best->header_pc;
        result.dispatcher.indirect_branch_pc = best->indirect_branch_pc;
        result.dispatcher.iteration_count  = best->iteration_count;
        result.dispatcher.confidence       = std::min(1.0f, best->score);
        result.dispatcher.dispatch_type    = classify_dispatch_type(loop, cfg_result, best->is_blr);

        // Identify state vs invariant registers across dispatch iterations
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
                    changed = true; break;
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
    } else if (!use_threaded) {
        // Auto-inference requires loop header inst_ids (not available for
        // ThreadedCode). Works for both loop-based topologies and FetchOnly
        // (best->header_inst_ids is populated identically in both cases).
        result.vm_pc_reg = infer_vm_pc_register(regfile, best->header_inst_ids);
    }

    // Infer bytecode address range from observed VM-PC values.
    // For ThreadedCode, sample from dispatch inst_ids recorded by the collector.
    if (result.vm_pc_reg != 0xFF) {
        uint32_t n;
        std::vector<uint64_t> sample_inst_ids;
        if (use_threaded) {
            // Sample dispatch inst_ids from the first N executions
            n = std::min(static_cast<uint32_t>(executions.size()),
                         MAX_SAMPLE_ITERATIONS);
            sample_inst_ids.reserve(n);
            for (uint32_t i = 0; i < n; ++i) {
                sample_inst_ids.push_back(executions[i].dispatch_inst_id);
            }
        } else {
            n = std::min(static_cast<uint32_t>(best->header_inst_ids.size()),
                         MAX_SAMPLE_ITERATIONS);
            sample_inst_ids = std::vector<uint64_t>(
                best->header_inst_ids.begin(),
                best->header_inst_ids.begin() + n);
        }
        uint32_t n_real = static_cast<uint32_t>(sample_inst_ids.size());
        uint64_t min_vpc = UINT64_MAX, max_vpc = 0;
        for (uint32_t i = 0; i < n_real; ++i) {
            auto state = regfile.state_before(sample_inst_ids[i]);
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
        //
        // Timing contract for register reads:
        //   dispatch_inst_id  = inst_id of the loop-header instruction.
        //   handler_first_inst_id = inst_id of the very first instruction of
        //                          the handler body (after the indirect branch).
        //
        //   state_before(dispatch_inst_id):  register values BEFORE the
        //       dispatcher loop body starts executing.  Good for VM-PC (which
        //       was set by the previous handler and has not been touched yet by
        //       the current dispatcher iteration).
        //
        //   state_before(handler_first_inst_id): register values just before
        //       the handler's first instruction.  This is AFTER the dispatcher
        //       has fully executed the opcode-decode stub (e.g. bl 0x885F48 for
        //       the bnlabel VMP), so any decode result in a scratch register
        //       (e.g. x0) reflects the decoded opcode for this step.
        if (result.vm_pc_reg != 0xFF) {
            // VM-PC: read at dispatcher entry — it holds the bytecode pointer
            // that the dispatcher is about to decode.  Using dispatch_inst_id
            // is intentional here (it hasn't been advanced yet by this
            // iteration's fetch logic).
            auto state_dispatch = regfile.state_before(exec.dispatch_inst_id);
            step.vm_pc_value = state_dispatch.gpr[result.vm_pc_reg];
            step.vm_pc_valid = true;

            if (config_.opcode_format.has_value()) {
                auto& ofmt = *config_.opcode_format;

                // ── Mode B: register snapshot after decode stub ────────────
                // The target register (e.g. x0) is set by the dispatcher's
                // opcode-decode stub which runs BETWEEN dispatch_inst_id and
                // handler_first_inst_id.  We must read it at the handler
                // boundary (state_before handler entry) — NOT at the loop
                // header where the stub hasn't run yet.
                if (ofmt.opcode_from_reg != 0xFF) {
                    if (exec.handler_first_inst_id != 0) {
                        auto state_handler = regfile.state_before(
                            exec.handler_first_inst_id);
                        step.opcode_value = state_handler.gpr[ofmt.opcode_from_reg];
                    } else {
                        // Fallback: no handler_first recorded, use dispatch state
                        step.opcode_value = state_dispatch.gpr[ofmt.opcode_from_reg];
                    }
                    step.opcode_valid = true;
                }
                // ── Mode A: memory read at VM-PC + deobfuscation pipeline ──
                // Read the raw opcode bytes from the bytecode buffer at the
                // address (vm_pc_value + opcode_byte_offset).  This works only
                // when the bytecode memory was written through the trace.  If
                // the bytecode is a read-only mmap'd file section with no
                // recorded writes, MemReadResult::known[] will be all-false and
                // decoding silently skips this step.
                else if (ofmt.opcode_size > 0 && ofmt.opcode_size <= 8) {
                    auto& memory = ctx.memory();
                    // Apply opcode_byte_offset: skip prefix bytes to reach the opcode field.
                    uint64_t read_addr = step.vm_pc_value +
                                        static_cast<uint64_t>(ofmt.opcode_byte_offset);
                    auto mem = memory.read(read_addr,
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
                        // Step 1: mask + shift
                        uint64_t val = (raw & ofmt.opcode_mask) >> ofmt.opcode_shift;

                        // Step 2: apply ordered deobfuscation transforms
                        for (const auto& step_def : ofmt.deobfuscation_steps) {
                            using Op = OpcodeDeobfStep::Op;
                            switch (step_def.op) {
                                case Op::sub:   val -= step_def.imm; break;
                                case Op::add:   val += step_def.imm; break;
                                case Op::xor_:  val ^= step_def.imm; break;
                                case Op::and_:  val &= step_def.imm; break;
                                case Op::or_:   val |= step_def.imm; break;
                                case Op::lsr:   val >>= step_def.imm; break;
                                case Op::lsl:   val <<= step_def.imm; break;
                                case Op::mul:   val *= step_def.imm; break;
                                case Op::ror: {
                                    // Rotate right by imm bits within a 64-bit word.
                                    // Normalise shift amount to [0, 63].
                                    uint8_t r = static_cast<uint8_t>(step_def.imm & 63u);
                                    if (r > 0) val = (val >> r) | (val << (64u - r));
                                    break;
                                }
                                case Op::bswap: {
                                    // Byte-swap within the specified width (2/4/8).
                                    uint8_t w = step_def.imm ? static_cast<uint8_t>(step_def.imm) : 8u;
                                    if (w >= 8) {
                                        val = __builtin_bswap64(val);
                                    } else if (w == 4) {
                                        val = __builtin_bswap32(static_cast<uint32_t>(val));
                                    } else if (w == 2) {
                                        val = __builtin_bswap16(static_cast<uint16_t>(val));
                                    }
                                    break;
                                }
                                case Op::neg:   val = static_cast<uint64_t>(-static_cast<int64_t>(val)); break;
                                case Op::not_:  val = ~val; break;
                            }
                        }

                        step.opcode_value = val;
                        step.opcode_valid = true;
                    }
                }

                // ── Record opcode→handler mapping (both modes) ─────────────
                if (step.opcode_valid) {
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

        // ── VM context / register file snapshot ─────────────────────────
        //
        // state_dispatch (state_before dispatch_inst_id) is needed below
        // even when vm_pc_reg == 0xFF.  Compute it lazily here if not already
        // computed by the vm_pc_reg block above (where it was declared in scope).
        // We use a lambda-initialized const ref to avoid the double-call cost.
        //
        // For the ctx_base and rf_base pointers: these are almost always
        // invariant registers (they point to a heap-allocated VM state struct
        // that never moves).  Reading them at dispatch_inst_id or
        // handler_first_inst_id yields the same value.  We use
        // dispatch_inst_id for consistency.
        //
        // For the MEMORY values at those pointers (vm_ctx fields, VM
        // registers, SP): we query at dispatch_inst_id.  The MemoryModel
        // returns "the last write that happened BEFORE dispatch_inst_id",
        // which is exactly the state left by the PREVIOUS handler — i.e., the
        // VM register file contents that the current step's handler will see
        // as its inputs.  This is the correct semantic for a VM-register panel.
        bool need_ctx_state = (config_.vm_context.has_value() &&
                               config_.vm_context->ctx_base_reg != 0xFF) ||
                              config_.vm_register_file.has_value();
        // Use the state already fetched by vm_pc_reg block, or fetch it now.
        // We re-fetch unconditionally when needed; RegisterFile caches states,
        // so a second call with the same inst_id is an O(1) LRU hit.
        const RegState* p_state_dispatch = nullptr;
        RegState lazy_state_dispatch;
        if (need_ctx_state) {
            if (result.vm_pc_reg != 0xFF) {
                // Already computed as state_dispatch inside the block above.
                // Re-fetch (LRU cache hit, ~ns).
                lazy_state_dispatch = regfile.state_before(exec.dispatch_inst_id);
            } else {
                lazy_state_dispatch = regfile.state_before(exec.dispatch_inst_id);
            }
            p_state_dispatch = &lazy_state_dispatch;
        }

        // Decode VM context structure fields if hint provided
        if (config_.vm_context.has_value() && config_.vm_context->ctx_base_reg != 0xFF) {
            auto& vctx = *config_.vm_context;
            // ctx_base_reg is invariant; read it from state_before dispatch.
            uint64_t ctx_base = p_state_dispatch->gpr[vctx.ctx_base_reg];
            auto& memory = ctx.memory();

            for (const auto& field : vctx.fields) {
                // Clamp field size to [1, 8]; 0 defaults to 8.
                uint8_t fsz = (field.size > 0 && field.size <= 8) ? field.size : uint8_t(8);
                uint64_t field_addr = ctx_base + field.offset;
                auto mem = memory.read(field_addr, fsz, exec.dispatch_inst_id);
                bool known = true;
                for (uint8_t b = 0; b < fsz; ++b) {
                    if (!mem.known[b]) { known = false; break; }
                }
                if (known) {
                    uint64_t val = 0;
                    std::memcpy(&val, mem.data.data(), fsz);
                    step.ctx_fields.emplace_back(field.name, val);
                }
            }
        }

        // ── VM Register File snapshot ────────────────────────────────────
        // Read named VM registers and/or VM stack from the RF base pointer.
        // Memory time-point: dispatch_inst_id (= values left by the previous
        // handler, which are the inputs to the current step).
        //
        // Register file and stack are no longer mutually exclusive: a VM may
        // have both (e.g. JVM-style mixed architecture).  When both are
        // configured, both are emitted into step.vm_regs.
        if (config_.vm_register_file.has_value()) {
            auto& rf = *config_.vm_register_file;
            auto& memory = ctx.memory();

            // Determine RF base address from an invariant host register.
            // rf_base_reg is expected to be invariant (never changed by
            // handler code); reading it from state_dispatch is correct.
            uint64_t rf_base = 0;
            bool rf_base_valid = false;
            if (rf.rf_base_reg != 0xFF) {
                rf_base = p_state_dispatch->gpr[rf.rf_base_reg];
                rf_base_valid = true;
            } else if (config_.vm_context.has_value() &&
                       config_.vm_context->ctx_base_reg != 0xFF) {
                rf_base = p_state_dispatch->gpr[config_.vm_context->ctx_base_reg];
                rf_base_valid = true;
            }

            if (rf_base_valid) {
                // ── Register machine: read named VM registers ──────────────
                // Supports up to 16 bytes (SIMD/XMM).  Values > 8 bytes are
                // stored as two adjacent uint64 entries: "V0_lo" / "V0_hi".
                for (const auto& vreg : rf.regs) {
                    // Clamp to a meaningful max (16B for SIMD); default to 8.
                    uint8_t sz = (vreg.size > 0 && vreg.size <= 16)
                                     ? vreg.size : uint8_t(8);
                    uint64_t addr = rf_base + vreg.offset;

                    if (sz <= 8) {
                        // ── scalar path ──
                        auto mem = memory.read(addr, sz, exec.dispatch_inst_id);
                        bool known = true;
                        for (uint8_t b = 0; b < sz; ++b) {
                            if (!mem.known[b]) { known = false; break; }
                        }
                        if (known) {
                            uint64_t val = 0;
                            std::memcpy(&val, mem.data.data(), sz);
                            step.vm_regs.emplace_back(vreg.name, val);
                        }
                    } else {
                        // ── 128-bit SIMD path: read as two 8-byte halves ──
                        // Read first 8 bytes (lo)
                        auto mem_lo = memory.read(addr,     8, exec.dispatch_inst_id);
                        auto mem_hi = memory.read(addr + 8, 8, exec.dispatch_inst_id);
                        bool lo_ok = true, hi_ok = true;
                        for (uint8_t b = 0; b < 8; ++b) {
                            if (!mem_lo.known[b]) lo_ok = false;
                            if (!mem_hi.known[b]) hi_ok = false;
                        }
                        if (lo_ok) {
                            uint64_t lo = 0;
                            std::memcpy(&lo, mem_lo.data.data(), 8);
                            step.vm_regs.emplace_back(vreg.name + "_lo", lo);
                        }
                        if (hi_ok) {
                            uint64_t hi = 0;
                            std::memcpy(&hi, mem_hi.data.data(), 8);
                            step.vm_regs.emplace_back(vreg.name + "_hi", hi);
                        }
                    }
                }

                // ── Stack machine: read SP pointer, then stack slots ───────
                // SP lives inside the ctx/RF region at stack_sp_offset.
                // The SP value itself is a pointer into a separate stack buffer.
                //
                // Stack growth direction is configurable via rf.stack_direction:
                //
                //   Descending (default, full-descending):
                //     SP points to the last pushed item.
                //     TOS = *SP, next = *(SP + elem), ...
                //     Slot i: SP + i * elem
                //
                //   Ascending (full-ascending / empty-ascending):
                //     SP points to the next free slot.
                //     TOS = *(SP - elem), next = *(SP - 2*elem), ...
                //     Slot i: SP - (i + 1) * elem
                //
                if (rf.has_stack()) {
                    auto sp_mem = memory.read(rf_base + rf.stack_sp_offset, 8,
                                              exec.dispatch_inst_id);
                    bool sp_ok = true;
                    for (uint8_t b = 0; b < 8; ++b) {
                        if (!sp_mem.known[b]) { sp_ok = false; break; }
                    }
                    if (sp_ok) {
                        uint64_t sp = 0;
                        std::memcpy(&sp, sp_mem.data.data(), 8);
                        // Record the SP value itself for display
                        step.vm_regs.emplace_back("SP", sp);

                        uint8_t  elem  = rf.stack_elem_size > 0 ? rf.stack_elem_size : uint8_t(8);
                        uint32_t depth = rf.stack_depth     > 0 ? rf.stack_depth     : 8u;

                        using Dir = VMRegisterFileHint::StackDirection;
                        bool ascending = (rf.stack_direction == Dir::Ascending);

                        for (uint32_t si = 0; si < depth; ++si) {
                            uint64_t slot_addr;
                            if (ascending) {
                                // Ascending stack: TOS is below SP.
                                // slot 0 = *(SP - elem), slot 1 = *(SP - 2*elem), ...
                                slot_addr = sp - static_cast<uint64_t>(si + 1) * elem;
                            } else {
                                // Descending stack: TOS is at SP.
                                // slot 0 = *SP, slot 1 = *(SP + elem), ...
                                slot_addr = sp + static_cast<uint64_t>(si) * elem;
                            }
                            auto sm = memory.read(slot_addr, elem, exec.dispatch_inst_id);
                            bool sok = true;
                            for (uint8_t b = 0; b < elem; ++b) {
                                if (!sm.known[b]) { sok = false; break; }
                            }
                            if (sok) {
                                uint64_t sv = 0;
                                std::memcpy(&sv, sm.data.data(), elem);
                                step.vm_regs.emplace_back(fmt::format("S{}", si), sv);
                            }
                        }
                    }
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

    // ── Step 9: Carry hints into result for VM Workspace UI ────────────
    result.vm_register_file = config_.vm_register_file;
    result.handler_asm      = config_.handler_asm;

    ctx.progress(1.0f, fmt::format(
        "VM abstract: dispatcher at {:#x}, {} handlers, {} VM steps, VM-PC={}",
        result.dispatcher.loop_header_pc,
        result.handlers.size(),
        result.total_vm_steps,
        result.vm_pc_reg != 0xFF ? fmt::format("x{}", result.vm_pc_reg) : "unknown"));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

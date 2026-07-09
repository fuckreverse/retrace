#include "analysis/passes/vm/vm_abstract_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/trace_collector.h"
#include "common/aarch64_classify.h"
#include "common/logger.h"
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

/// Locate the dispatch instruction inside an ALREADY-HINTED dispatcher loop
/// (`VMConfig::dispatcher->loop_header_pc`). This is structural completion,
/// not detection: the loop itself is a caller-provided fact, and a dispatch
/// loop body has exactly one indirect branch by construction, so finding it
/// mechanically (CFG terminator lookup, falling back to a raw opcode scan)
/// is deterministic. Only used when the caller supplies `loop_header_pc` but
/// omits `indirect_branch_pc` — supplying both skips this entirely.
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

/// Purely mechanical classification from the already-hinted dispatch
/// instruction's encoding — NOT a statistical heuristic. `is_blr` is a fact
/// read directly from the opcode at the (hint-provided) indirect-branch PC,
/// so "BLR → CallTable" is deterministic. When it's a plain BR, we label it
/// IndirectBranch; distinguishing a genuine WhileSwitch (compare-cascade)
/// from a jump-table IndirectBranch from trace shape alone is exactly the
/// kind of guess static analysis already answers for free — callers who
/// care about that distinction should set `VMConfig::dispatch_type_hint`
/// explicitly instead of relying on this fallback.
DispatchType classify_dispatch_type(bool is_blr) {
    return is_blr ? DispatchType::CallTable : DispatchType::IndirectBranch;
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

    // ── Step 2: Resolve the hinted dispatcher into a Candidate ───────────
    //
    // There is exactly one source of truth for "where is the VM dispatcher":
    // the caller's hint (`dispatcher`, `threaded_dispatch_pcs`, or a FetchOnly
    // anchor). This block never scores or ranks loops — it only resolves the
    // hint into the loop/PC bookkeeping the rest of the pass needs.

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
            std::string msg = fmt::format(
                "VM abstract: hinted dispatcher at {:#x} not found in loop results "
                "(if this VM's back-edge is realized via CFF-computed RET rather than "
                "a direct B/BR, try dispatch_type_hint=ThreadedCode + threaded_dispatch_pcs "
                "instead of dispatcher_pc)",
                hint.loop_header_pc);
            ctx.progress(1.0f, msg);
            // Use WARN (not the default DEBUG progress-log path) so this is
            // visible in the GUI Log panel / stderr at the default log level
            // — without this, a bad hints_file silently produces an
            // all-zero VMAbstractResult with no visible explanation.
            LOG_WARN_M(::tenet::log::Module::Analysis, "{}", msg);
            LOG_WARN_M(::tenet::log::Module::Analysis,
                "VM abstract: is loop_header_pc a RUNTIME address (static_pc + "
                "module_slide)? {} loop(s) were detected in this trace.",
                loop_result.loops.size());
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
    }

    // No candidate means the caller didn't supply a usable dispatcher hint
    // (FetchOnly anchor, ThreadedCode dispatch PCs, or a plain dispatcher
    // hint). This pass never scans loops looking for "VM-shaped" candidates
    // — see VMConfig's class comment — so an empty candidate list here is a
    // caller error, not "no VM found".
    if (candidates.empty()) {
        static constexpr const char* kMsg =
            "VM abstract: no dispatcher hint provided (set VMConfig::dispatcher, "
            "threaded_dispatch_pcs, or a FetchOnly anchor from static analysis)";
        ctx.progress(1.0f, kMsg);
        LOG_WARN_M(::tenet::log::Module::Analysis, "{}", kMsg);
        return PassResult::success(std::move(result));
    }

    // Collect header inst_ids for each candidate from XRef
    // (mem-anchor FetchOnly candidates already populated header_inst_ids
    // above and have header_pc == 0, which has no xref entry — skip them
    // here via the has_pc() guard so they aren't accidentally cleared.)
    for (auto& cand : candidates) {
        if (cand.header_pc == 0) continue;  // mem-anchor FetchOnly: already populated
        if (!xref.has_pc(cand.header_pc)) {
            uint64_t slide = ctx.reader().header().module_slide;
            uint64_t base  = ctx.reader().header().module_base;
            uint64_t guess_plus  = cand.header_pc + slide;   // hint was static, needs +slide
            uint64_t guess_minus = cand.header_pc - slide;   // hint was runtime from another run
            bool plus_hits  = xref.has_pc(guess_plus);
            bool minus_hits = xref.has_pc(guess_minus);

            if (plus_hits) {
                // High-confidence fix: the caller almost certainly hinted the
                // STATIC (IDA/file) address. Tell them exactly what to use.
                LOG_WARN_M(::tenet::log::Module::Analysis,
                    "VM abstract: hinted PC {:#x} was never executed (0 xref hits), "
                    "but {:#x} (= hint + module_slide {:#x}) WAS executed {} time(s). "
                    "Your hints file almost certainly has the STATIC/file address — "
                    "use {:#x} as dispatcher_pc instead (this trace's module_base={:#x}).",
                    cand.header_pc, guess_plus, slide,
                    xref.execution_count(guess_plus), guess_plus, base);
            } else if (minus_hits) {
                LOG_WARN_M(::tenet::log::Module::Analysis,
                    "VM abstract: hinted PC {:#x} was never executed (0 xref hits), "
                    "but {:#x} (= hint - module_slide {:#x}) WAS executed {} time(s). "
                    "Your hints file may have a runtime address from a DIFFERENT "
                    "trace/run (ASLR slide changes per launch) — use {:#x} as "
                    "dispatcher_pc for THIS trace instead.",
                    cand.header_pc, guess_minus, slide,
                    xref.execution_count(guess_minus), guess_minus);
            } else {
                LOG_WARN_M(::tenet::log::Module::Analysis,
                    "VM abstract: hinted PC {:#x} was never executed in this trace "
                    "(0 xref hits), and neither hint+slide ({:#x}) nor hint-slide "
                    "({:#x}) was executed either — this trace's module_base={:#x} "
                    "module_slide={:#x}. Double-check the address comes from THIS "
                    "binary/run (not a stale IDA bookmark or a different trace), and "
                    "that it's inside the traced range.",
                    cand.header_pc, guess_plus, guess_minus, base, slide);
            }
            continue;
        }
        cand.header_inst_ids.reserve(cand.iteration_count);
        for (uint64_t iid : xref.inst_ids_at(cand.header_pc)) {
            if (iid < range.start_inst_id) continue;
            if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
            cand.header_inst_ids.push_back(iid);
        }
        LOG_INFO_M(::tenet::log::Module::Analysis,
            "VM abstract: hinted PC {:#x} hit {} time(s) in [{}, {}) "
            "(need >= 3 to be usable as a dispatcher candidate)",
            cand.header_pc, cand.header_inst_ids.size(),
            range.start_inst_id,
            range.end_inst_id == UINT64_MAX ? -1 : static_cast<int64_t>(range.end_inst_id));
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
        static constexpr const char* kMsg =
            "VM abstract: no valid VM dispatcher found (hinted PC(s) matched "
            "fewer than 3 times in the analysis range — see prior log lines "
            "for per-candidate hit counts)";
        ctx.progress(1.0f, kMsg);
        LOG_WARN_M(::tenet::log::Module::Analysis, "{}", kMsg);
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
            // Set handler_first to dispatch+1 so that opcode_from_reg reads
            // state_before(iid+1) == state_after(iid), capturing the value
            // written by the fetch instruction (e.g. LDR W1,[X8,X0]).
            exec.handler_first_inst_id = iid + 1;
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

        // Prefer the caller's explicit hint (from static analysis) for the
        // loop-based topologies; only fall back to the mechanical BLR/BR
        // read when the caller didn't say WhileSwitch/IndirectBranch/CallTable.
        switch (config_.dispatch_type_hint) {
            case DispatchType::WhileSwitch:
            case DispatchType::IndirectBranch:
            case DispatchType::CallTable:
                result.dispatcher.dispatch_type = config_.dispatch_type_hint;
                break;
            default:
                result.dispatcher.dispatch_type = classify_dispatch_type(best->is_blr);
                break;
        }

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

    // ── Step 5: Identify VM-PC source ───────────────────────────────────
    //
    // VM-PC is derived from a field named "pc" or "ip" in either
    // vm_context->ctx_fields or vm_register_file->regs.  This unifies the
    // formerly separate vm_pc_reg hint with the ctx/regs definitions,
    // eliminating the duplicate "pc" definition problem.
    //
    // The field can be:
    //   (a) Host-register-backed (vm_registers with from_host_reg set) —
    //       read directly from RegisterFile.
    //   (b) Memory-backed (ctx_fields or vm_registers with offset) —
    //       read via MemoryModel at ctx_base/rf_base + offset.

    ctx.progress(0.65f, "VM abstract: identifying VM-PC source...");

    // Find the VM-PC field in ctx_fields or vm_registers.
    const VMContextHint::Field* ctx_pc_field = nullptr;
    if (config_.vm_context.has_value() && config_.vm_context->ctx_base_reg != 0xFF) {
        for (const auto& f : config_.vm_context->fields) {
            if (f.name == "pc" || f.name == "ip") {
                ctx_pc_field = &f;
                break;
            }
        }
    }
    const VMRegisterFileHint::VMReg* vmreg_pc = nullptr;
    if (config_.vm_register_file.has_value()) {
        for (const auto& r : config_.vm_register_file->regs) {
            if (r.name == "pc" || r.name == "ip") {
                vmreg_pc = &r;
                break;
            }
        }
    }
    bool has_vm_pc = (ctx_pc_field != nullptr) || (vmreg_pc != nullptr);

    // Helper: read VM-PC value at a given dispatch inst_id.
    // Returns nullopt if the value cannot be read.
    auto& memory_ref = ctx.memory();
    auto read_vm_pc = [&](uint64_t inst_id) -> std::optional<uint64_t> {
        auto state = regfile.state_before(inst_id);
        if (vmreg_pc) {
            // Mode (b): host-register-backed
            if (vmreg_pc->from_host_reg != 0xFF && vmreg_pc->from_host_reg <= 28) {
                return state.gpr[vmreg_pc->from_host_reg];
            }
            // Mode (a): memory-backed via rf_base or ctx_base
            uint64_t base = 0;
            bool base_valid = false;
            if (config_.vm_register_file->rf_base_reg != 0xFF) {
                base = state.gpr[config_.vm_register_file->rf_base_reg];
                base_valid = true;
            } else if (config_.vm_context.has_value() &&
                       config_.vm_context->ctx_base_reg != 0xFF) {
                base = state.gpr[config_.vm_context->ctx_base_reg];
                base_valid = true;
            }
            if (!base_valid) return std::nullopt;
            uint8_t sz = (vmreg_pc->size > 0 && vmreg_pc->size <= 8)
                             ? vmreg_pc->size : uint8_t(8);
            auto mem = memory_ref.read(base + vmreg_pc->offset, sz, inst_id);
            for (uint8_t b = 0; b < sz; ++b)
                if (!mem.known[b]) return std::nullopt;
            uint64_t val = 0;
            std::memcpy(&val, mem.data.data(), sz);
            return val;
        }
        if (ctx_pc_field && config_.vm_context->ctx_base_reg != 0xFF) {
            uint64_t base = state.gpr[config_.vm_context->ctx_base_reg];
            uint8_t sz = (ctx_pc_field->size > 0 && ctx_pc_field->size <= 8)
                             ? ctx_pc_field->size : uint8_t(8);
            auto mem = memory_ref.read(base + ctx_pc_field->offset, sz, inst_id);
            for (uint8_t b = 0; b < sz; ++b)
                if (!mem.known[b]) return std::nullopt;
            uint64_t val = 0;
            std::memcpy(&val, mem.data.data(), sz);
            return val;
        }
        return std::nullopt;
    };

    result.vm_pc_tracked = has_vm_pc;

    // Infer bytecode address range from observed VM-PC values.
    // For ThreadedCode, sample from dispatch inst_ids recorded by the collector.
    if (has_vm_pc) {
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
            auto vpc = read_vm_pc(sample_inst_ids[i]);
            if (!vpc) continue;
            if (*vpc < min_vpc) min_vpc = *vpc;
            if (*vpc > max_vpc) max_vpc = *vpc;
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

    // ── Step 6b: VM architecture type ───────────────────────────────────
    //
    // Always taken from the hint — never inferred from handler memory-access
    // ratios. Load/store balance is a weak, easily-confounded signal (a
    // register machine handler that only reads, or a stack machine handler
    // that swaps two slots, looks identical to the "wrong" category), and
    // static analysis already knows the answer with certainty. Prefer
    // reading `vm_register_file` (has_stack()/has_regs()/is_mixed()) when
    // you need this programmatically.
    result.arch_type = config_.arch_type_hint;

    // ── Step 6c: Warm the register-file cache for the step-building pass ──
    //
    // Step 7 below calls regfile.state_before() twice per execution
    // (dispatch_inst_id and handler_first_inst_id) and `executions` is
    // produced by a single sequential trace scan, so these inst_ids are
    // visited in strictly increasing order. Despite that ordering,
    // RegisterFile::state_before() has NO notion of "the last id we
    // rebuilt" — a cache miss unconditionally rebuilds from the nearest
    // ANCHOR record (by default every 1024 instructions, see
    // TraceFormat.h), replaying every INST diff in between. Without
    // pre-warming, two increasing-but-not-identical inst_ids that both
    // miss the small LRU cache each pay that full anchor-to-target
    // replay cost independently — for a trace with hundreds of thousands
    // to millions of VM steps this dominates total pass runtime, which is
    // why Step 7 looks disproportionately slow for how little work it
    // conceptually does per iteration.
    //
    // warm_range() does one forward sweep over the whole span up front,
    // inserting a cached checkpoint every `stride` instructions. Step 7's
    // state_before() calls then only need to replay at most `stride`
    // records from the nearest checkpoint instead of the nearest anchor
    // (which can be much farther away), turning the common case into a
    // handful of diff replays instead of hundreds.
    if (!executions.empty()) {
        uint64_t warm_start = executions.front().dispatch_inst_id;
        uint64_t warm_end   = executions.back().handler_last_inst_id;
        // handler_last_inst_id may be 0 (FetchOnly / handler never closed)
        // or land before dispatch_inst_id in edge cases — fall back to
        // dispatch_inst_id + 1 so warm_range() always sees a valid range.
        if (warm_end <= warm_start) warm_end = warm_start + 1;
        regfile.warm_range(warm_start, warm_end + 1, /*stride=*/0,
            [&](uint64_t done, uint64_t total) {
                if (total > 0) {
                    ctx.progress(0.72f + 0.08f * static_cast<float>(done) /
                                 static_cast<float>(total));
                }
            });
    }
    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    // ── Step 7: Build VM execution trace (step sequence) ────────────────

    ctx.progress(0.8f, "VM abstract: building VM step sequence...");

    result.steps.reserve(executions.size());

    // ── Rolling key state ────────────────────────────────────────────────
    //
    // When the deobfuscation pipeline contains rolling-key ops (xor_rolling,
    // add_rolling, sub_rolling), their `imm` field seeds the initial key.
    // After each decoded opcode, the key is updated according to
    // `rolling_key_update`. This vector mirrors the deobfuscation_steps
    // array — rolling_keys[i] holds the CURRENT rolling key for step i
    // (only meaningful when step i is a rolling op; other entries are 0).
    std::vector<uint64_t> rolling_keys;
    if (config_.opcode_format.has_value()) {
        auto& ofmt = *config_.opcode_format;
        rolling_keys.resize(ofmt.deobfuscation_steps.size(), 0);
        for (size_t i = 0; i < ofmt.deobfuscation_steps.size(); ++i) {
            using Op = OpcodeDeobfStep::Op;
            auto op = ofmt.deobfuscation_steps[i].op;
            if (op == Op::xor_rolling || op == Op::add_rolling || op == Op::sub_rolling) {
                rolling_keys[i] = ofmt.deobfuscation_steps[i].imm;  // seed
            }
        }
    }

    // This loop (one VMStep built per handler execution — register-state
    // reconstruction via regfile.state_before(), optional memory reads for
    // Mode-A opcode decode, plus the deobfuscation pipeline below) is the
    // single most expensive part of VMAbstractPass for large traces:
    // `executions` commonly holds hundreds of thousands to millions of
    // entries, yet previously this whole block ran between the 0.8 and 1.0
    // progress marks with NO intermediate update — the UI would sit at 80%
    // for the entire duration and then jump straight to 100%, and a
    // cancellation request wasn't observed until the loop finished. Report
    // progress in batches (cheap, no string formatting) and check
    // ctx.cancelled() periodically so both the progress bar and Cancel
    // button behave responsively here too.
    const size_t total_execs = executions.size();
    constexpr size_t kProgressBatch = 4096;
    size_t exec_idx = 0;
    for (const auto& exec : executions) {
        if ((exec_idx % kProgressBatch) == 0) {
            if (ctx.cancelled()) return PassResult::failed("Cancelled");
            if (total_execs > 0) {
                ctx.progress(0.8f + 0.2f * static_cast<float>(exec_idx) /
                             static_cast<float>(total_execs));
            }
        }
        ++exec_idx;

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
        if (has_vm_pc) {
            // VM-PC: read at dispatcher entry — it holds the bytecode pointer
            // that the dispatcher is about to decode.  Using dispatch_inst_id
            // is intentional here (it hasn't been advanced yet by this
            // iteration's fetch logic).
            auto vpc = read_vm_pc(exec.dispatch_inst_id);
            if (vpc) {
                step.vm_pc_value = *vpc;
                step.vm_pc_valid = true;
            }

            // state_dispatch is needed below for opcode decode and ctx/regs.
            auto state_dispatch = regfile.state_before(exec.dispatch_inst_id);

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
                        for (size_t si = 0; si < ofmt.deobfuscation_steps.size(); ++si) {
                            const auto& step_def = ofmt.deobfuscation_steps[si];
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
                                    uint8_t r = static_cast<uint8_t>(step_def.imm & 63u);
                                    if (r > 0) val = (val >> r) | (val << (64u - r));
                                    break;
                                }
                                case Op::bswap: {
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
                                // ── Rolling-key stateful ops ────────────────
                                case Op::xor_rolling: val ^= rolling_keys[si]; break;
                                case Op::add_rolling: val += rolling_keys[si]; break;
                                case Op::sub_rolling: val -= rolling_keys[si]; break;
                            }
                        }

                        step.opcode_value = val;
                        step.opcode_valid = true;

                        // Step 3: update rolling keys for the NEXT step
                        for (size_t si = 0; si < ofmt.deobfuscation_steps.size(); ++si) {
                            using Op = OpcodeDeobfStep::Op;
                            auto op = ofmt.deobfuscation_steps[si].op;
                            if (op != Op::xor_rolling && op != Op::add_rolling && op != Op::sub_rolling)
                                continue;
                            switch (ofmt.rolling_key_update) {
                                case RollingKeyUpdate::XorOpcode:
                                    rolling_keys[si] ^= val; break;
                                case RollingKeyUpdate::AddOpcode:
                                    rolling_keys[si] += val; break;
                                case RollingKeyUpdate::SubOpcode:
                                    rolling_keys[si] -= val; break;
                                case RollingKeyUpdate::HashOpcode:
                                    rolling_keys[si] = rolling_keys[si] * 31 + val; break;
                            }
                        }
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
        // even when VM-PC is not configured.  Compute it lazily here if not
        // already computed by the VM-PC block above.
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
                              config_.vm_register_file.has_value() ||
                              config_.operand_format.has_value();
        // Use the state already fetched by VM-PC block, or fetch it now.
        // We re-fetch unconditionally when needed; RegisterFile caches states,
        // so a second call with the same inst_id is an O(1) LRU hit.
        const RegState* p_state_dispatch = nullptr;
        RegState lazy_state_dispatch;
        if (need_ctx_state) {
            // Always fetch (LRU cache hit if VM-PC block already fetched it).
            lazy_state_dispatch = regfile.state_before(exec.dispatch_inst_id);
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

            // ── Compute inst_file_offset (vm_pc - bytecode_base) ─────────
            // The base can come from:
            //   (a) config_.inst_file_offset_base (explicitly configured), or
            //   (b) a ctx_field named "bytecode_base" (read above into step.ctx_fields)
            if (step.vm_pc_valid) {
                uint64_t base = 0;
                bool base_found = false;
                if (config_.inst_file_offset_base_set) {
                    base = config_.inst_file_offset_base;
                    base_found = true;
                } else {
                    for (const auto& [name, val] : step.ctx_fields) {
                        if (name == "bytecode_base") {
                            base = val;
                            base_found = true;
                            break;
                        }
                    }
                }
                if (base_found && step.vm_pc_value >= base) {
                    step.inst_file_offset = step.vm_pc_value - base;
                    step.inst_file_offset_valid = true;
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

            // ── Register machine: read named VM registers ──────────────
            // Two storage modes per register:
            //   (a) Memory-backed (default): rf_base + offset → MemoryModel.
            //   (b) Host-register-backed:    from_host_reg → RegisterFile.
            // Supports up to 16 bytes (SIMD/XMM).  Values > 8 bytes are
            // stored as two adjacent uint64 entries: "V0_lo" / "V0_hi".
            for (const auto& vreg : rf.regs) {
                // ── Mode (b): host-register-backed ──
                if (vreg.from_host_reg != 0xFF && vreg.from_host_reg <= 28) {
                    step.vm_regs.emplace_back(
                        vreg.name, p_state_dispatch->gpr[vreg.from_host_reg]);
                    continue;
                }

                // ── Mode (a): memory-backed ──
                if (!rf_base_valid) continue;

                uint8_t sz = (vreg.size > 0 && vreg.size <= 16)
                                 ? vreg.size : uint8_t(8);
                uint64_t addr = rf_base + vreg.offset;

                if (sz <= 8) {
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

            if (rf_base_valid) {

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

        // ── Operand field decoding ────────────────────────────────────
        //
        // When an OperandFormatHint is provided and we have a valid VM-PC,
        // decode each operand field from the bytecode buffer at
        // (vm_pc_value + field.byte_offset), applying the same
        // mask + shift + deobfuscation pipeline as opcode decode.
        if (config_.operand_format.has_value() && step.vm_pc_valid) {
            auto& opfmt = *config_.operand_format;
            auto& memory = ctx.memory();

            for (const auto& field : opfmt.fields) {
                if (field.size == 0 || field.size > 8) continue;

                uint64_t field_addr = step.vm_pc_value +
                                      static_cast<uint64_t>(field.byte_offset);
                auto mem = memory.read(field_addr,
                                       static_cast<uint8_t>(field.size),
                                       exec.dispatch_inst_id);
                bool all_known = true;
                for (uint8_t b = 0; b < field.size; ++b) {
                    if (!mem.known[b]) { all_known = false; break; }
                }
                if (!all_known) continue;

                uint64_t raw = 0;
                std::memcpy(&raw, mem.data.data(),
                            std::min(static_cast<size_t>(field.size), sizeof(raw)));

                uint64_t val = (raw & field.mask) >> field.shift;

                // Apply per-field deobfuscation pipeline
                for (const auto& ds : field.deobfuscation_steps) {
                    using Op = OpcodeDeobfStep::Op;
                    switch (ds.op) {
                        case Op::sub:   val -= ds.imm; break;
                        case Op::add:   val += ds.imm; break;
                        case Op::xor_:  val ^= ds.imm; break;
                        case Op::and_:  val &= ds.imm; break;
                        case Op::or_:   val |= ds.imm; break;
                        case Op::lsr:   val >>= ds.imm; break;
                        case Op::lsl:   val <<= ds.imm; break;
                        case Op::mul:   val *= ds.imm; break;
                        case Op::ror: {
                            uint8_t r = static_cast<uint8_t>(ds.imm & 63u);
                            if (r > 0) val = (val >> r) | (val << (64u - r));
                            break;
                        }
                        case Op::bswap: {
                            uint8_t w = ds.imm ? static_cast<uint8_t>(ds.imm) : 8u;
                            if (w >= 8)      val = __builtin_bswap64(val);
                            else if (w == 4) val = __builtin_bswap32(static_cast<uint32_t>(val));
                            else if (w == 2) val = __builtin_bswap16(static_cast<uint16_t>(val));
                            break;
                        }
                        case Op::neg:   val = static_cast<uint64_t>(-static_cast<int64_t>(val)); break;
                        case Op::not_:  val = ~val; break;
                        // Rolling ops are not supported for operand fields
                        // (they only make sense for opcode decode chains).
                        case Op::xor_rolling: break;
                        case Op::add_rolling: break;
                        case Op::sub_rolling: break;
                    }
                }

                VMOperand operand;
                operand.name = field.name;
                operand.value = val;
                operand.size_bytes = field.size;
                step.operands.push_back(std::move(operand));
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

    std::string final_msg = fmt::format(
        "VM abstract: dispatcher at {:#x}, {} handlers, {} VM steps, VM-PC={}",
        result.dispatcher.loop_header_pc,
        result.handlers.size(),
        result.total_vm_steps,
        result.vm_pc_tracked ? "tracked" : "unknown");
    ctx.progress(1.0f, final_msg);
    // Always visible at the default log level (not gated behind
    // TENET_LOG=DEBUG like the generic progress-message log path) — this is
    // the single most useful line for confirming a hints file actually
    // "took": dispatcher != 0x0 and handlers/steps > 0.
    LOG_INFO_M(::tenet::log::Module::Analysis, "{}", final_msg);
    if (result.handlers.empty() || result.total_vm_steps == 0) {
        LOG_WARN_M(::tenet::log::Module::Analysis,
            "VM abstract: dispatcher was found but produced 0 handlers/steps — "
            "this usually means the indirect-branch PC or handler classification "
            "inside the dispatch loop didn't match this binary. Check "
            "indirect_branch_pc in the hints and dispatch_type_hint.");
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet

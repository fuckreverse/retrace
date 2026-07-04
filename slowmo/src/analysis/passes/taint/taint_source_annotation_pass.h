#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include <cstdint>
#include <string>
#include <vector>
#include "ankerl/unordered_dense.h"
#include <optional>

namespace tenet {

struct FunctionResult;  // forward declaration (analysis/passes/structure/function_pass.h)

// ─── Taint Source Annotation ───────────────────────────────────────────────

/// The origin category of a taint source — what ultimately produced the value.
enum class TaintSourceKind {
    ObjcGetter,          // Return value of an ObjC getter method
    ObjcArg,             // Argument to an ObjC method call
    ObjcReturnValue,     // General ObjC return value
    MemoryLoad,          // Loaded from a memory address (no ObjC context)
    ImmediateConstant,   // Hard-coded constant (from MOVZ/MOVK chain)
    FunctionReturn,      // Return value of a non-ObjC function
    Unknown,
};

/// A single annotated taint source: the "endpoint" of a backward taint chain.
/// An endpoint is an instruction in the backward taint result where the value
/// CANNOT be traced further back (i.e., the instruction has no prior source
/// in the contributing set — it's a leaf in the dependency tree).
struct TaintSourceAnnotation {
    uint64_t inst_id;           // inst_id of the source instruction
    uint64_t pc;                // PC of the source instruction
    TaintSourceKind kind;

    // ── ObjC getter annotation ────────────────────────────────────────
    // Populated when kind == ObjcGetter or ObjcArg or ObjcReturnValue.

    /// The ObjC message that produced the value.
    std::optional<ObjcMessage> objc_message;

    /// Human-readable label e.g. "[CryptoEngine secretKey]" or
    /// "[NSUserDefaults objectForKey:]"
    std::string objc_label;

    // ── Memory source annotation ──────────────────────────────────────
    // Populated when kind == MemoryLoad.

    uint64_t source_mem_addr = 0;   // The address that was loaded
    uint64_t source_mem_size = 0;

    // ── Constant annotation ────────────────────────────────────────────
    // Populated when kind == ImmediateConstant.

    uint64_t constant_value = 0;

    // ── Function return annotation ─────────────────────────────────────
    // Populated when kind == FunctionReturn.

    uint64_t callee_pc = 0;
    std::string callee_name;  // Symbol name if available

    // ── Sink attribution ──────────────────────────────────────────────
    /// Which original sink register this source feeds (AArch64 reg index).
    uint8_t sink_reg = 0;

    /// Human-readable summary of this source.
    std::string summary() const;
};

// ─── TaintSourceAnnotationResult ─────────────────────────────────────────

struct TaintSourceAnnotationResult {
    /// All annotated sources, ordered by inst_id ascending.
    std::vector<TaintSourceAnnotation> sources;

    /// ObjC getter sources (most likely key/IV origins).
    std::vector<size_t> objc_source_indices;

    /// Constant sources (possible hard-coded keys).
    std::vector<size_t> constant_source_indices;

    /// Memory load sources (key loaded from memory, no ObjC attribution).
    std::vector<size_t> memory_source_indices;

    /// Index: ObjC selector_name → source indices
    ankerl::unordered_dense::map<std::string, std::vector<size_t>> by_selector;

    /// Index: ObjC class_name → source indices
    ankerl::unordered_dense::map<std::string, std::vector<size_t>> by_class;

    size_t total() const { return sources.size(); }

    /// Serialize to JSON.
    std::string to_json() const;
};

// ─── TaintSourceAnnotationConfig ─────────────────────────────────────────

struct TaintSourceAnnotationConfig {
    /// Maximum instruction gap to look back for an ObjC message that could
    /// be the source of a loaded value.
    /// If the backward taint source is a LDR and an ObjC call returned a
    /// value within `max_objc_gap` instructions earlier, we attribute the
    /// load to that ObjC method's return value.
    uint64_t max_objc_gap = 200000;

    /// Consider an ObjC message as a "getter" if the selector contains no
    /// colons AND the selector name does not start with "set".
    /// e.g. `secretKey`, `token`, `password`, `authKey`.
    bool require_zero_colon_getter = false;  // false = annotate ALL matching ObjC msgs

    /// Annotate even sources that have no ObjC context (memory loads, constants).
    bool annotate_bare_sources = true;
};

// ─── TaintSourceAnnotationPass ───────────────────────────────────────────

/// Annotates the "leaf" sources of a BackwardTaintResult by correlating them
/// with ObjC message send records.
///
/// ## Core algorithm
///
/// 1. Identify **leaf instructions** in the backward taint result:
///    An instruction is a leaf if it appears in BackwardTaintResult::events
///    but NONE of its src_regs / src_mem_addrs trace to earlier contributing
///    instructions (i.e., the dependency chain terminates here).
///    In practice: leaves are the events where `loads_from_memory` is true
///    and the load address has no prior writer in the taint set, OR where the
///    instruction writes from an immediate constant.
///
/// 2. For each leaf, scan ObjcResult::messages backward from the leaf's
///    inst_id to find the most recent ObjC message with a matching return
///    value context:
///    - If the most recent ObjC call was a *getter* (no args or property-style
///      selector), and it occurred within `max_objc_gap` instructions before
///      the load, annotate this source as ObjcGetter.
///    - If the source is an LDR from an address that was previously written
///      by code that received an ObjC return value, annotate as ObjcReturnValue.
///
/// 3. If no ObjC match is found, annotate as:
///    - ImmediateConstant: if the leaf comes from a MOVZ/MOVK constant load
///    - FunctionReturn: if the leaf comes right after a BL (LR restoration)
///    - MemoryLoad: generic unattributed load
///
/// ## Key insight for algorithm reversing
///
/// When you run `--backward-taint` on an encryption call and get a chain
/// of 500+ contributing instructions, this pass quickly tells you:
///   "x3 (the key) ultimately came from [CryptoManager secretKeyForUser:]"
///   "x5 (the IV) was loaded from 0x1234abc (no ObjC context — hard-coded)"
///
/// This dramatically reduces the manual investigation needed to understand
/// where the key material originates in the ObjC method hierarchy.
///
/// Dependencies: backward_taint (required), objc (required)
/// Result type: TaintSourceAnnotationResult
class TaintSourceAnnotationPass final : public AnalysisPass {
public:
    explicit TaintSourceAnnotationPass(TaintSourceAnnotationConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "taint_source_annotation"; }
    std::string_view description() const override {
        return "Annotate backward taint leaf sources with ObjC getter / memory context";
    }

    std::vector<std::string_view> dependencies() const override {
        // NOTE: `function` is intentionally NOT listed as a hard dependency
        // here, even though run() consults it (via ctx.try_require) to
        // attribute FunctionReturn sources to a callee name/pc. Making it a
        // hard dependency would cause this pass to fail outright whenever
        // FunctionPass hasn't been registered/hasn't completed (e.g. in
        // callers that only care about ObjC/memory/constant sources and
        // never registered FunctionPass) — that's a worse failure mode than
        // simply leaving callee_name empty. Callers that want FunctionReturn
        // attribution should register FunctionPass themselves (pass_registry
        // does this automatically for the production pass catalog).
        return {"backward_taint", "objc"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.5f; }

private:
    TaintSourceAnnotationConfig config_;

    /// Find the ObjC message most likely responsible for the value at inst_id.
    /// Searches backward from inst_id for up to max_objc_gap instructions.
    const ObjcMessage* find_objc_source(const ObjcResult& objc,
                                         uint64_t inst_id) const;

    /// Determine the kind of a leaf event.
    ///
    /// `func` (optional, may be nullptr if FunctionPass wasn't registered) is
    /// consulted to disambiguate FunctionReturn from ImmediateConstant: both
    /// present identically at the BackwardTaintEvent level (no src_regs, no
    /// memory access — e.g. a MOVZ or the register-diff left behind by a
    /// RET/BLR), so the only reliable signal is whether the leaf instruction
    /// immediately follows a recorded call site (func->call_at(ev.inst_id-1)).
    TaintSourceKind classify_source(const BackwardTaintEvent& ev,
                                     const ObjcMessage* objc_msg,
                                     const FunctionResult* func = nullptr) const;
};

}  // namespace tenet

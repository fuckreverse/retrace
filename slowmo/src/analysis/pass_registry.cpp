// Pass Registry — implementation.
//
// Central catalog + generic registration dispatch for all analysis passes.
// See pass_registry.h for the design rationale.

#include "analysis/pass_registry.h"

#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/taint_source_annotation_pass.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/thread_filter_pass.h"

#include "analysis/passes/taint_pass.h"
#include "analysis/passes/backward_taint_pass.h"

#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/memory_snapshot_pass.h"
#include "analysis/passes/mem_search_pass.h"
#include "analysis/passes/entropy_pass.h"
#include "analysis/passes/yara_mem_scan_pass.h"

#include "analysis/passes/syscall_intercept_pass.h"

#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/reg_timeline_pass.h"
#include "analysis/passes/call_context_pass.h"
#include "analysis/passes/window_stats_pass.h"
#include "analysis/passes/trace_diff_pass.h"
#include "analysis/passes/dataflow_graph_pass.h"
#include "analysis/passes/vm_abstract_pass.h"
#include "analysis/passes/vm_hints_json.h"

#include <fmt/core.h>

namespace tenet {

namespace {

/// Whether `pm` already has a pass named `name`.
bool pm_has_pass(PassManager& pm, std::string_view name) {
    for (auto n : pm.all_passes()) {
        if (n == name) return true;
    }
    return false;
}

/// Parse a hex string like "DEADBEEF" or "deadbeef" (no 0x prefix required)
/// into a byte vector. Returns empty on failure.
std::vector<uint8_t> parse_hex_pattern(std::string_view s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    // Skip optional "0x" prefix and spaces.
    size_t i = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) i = 2;
    uint8_t hi = 0;
    bool have_hi = false;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c == ' ' || c == '\t') continue;
        int v = hexval(c);
        if (v < 0) return {};
        if (!have_hi) {
            hi = static_cast<uint8_t>(v << 4);
            have_hi = true;
        } else {
            out.push_back(static_cast<uint8_t>(hi | v));
            have_hi = false;
        }
    }
    return out;
}

/// Factory: create a pass instance by name, deriving its config from `ctx`.
/// Returns nullptr for unknown names. Does NOT register the pass or its
/// dependencies — that is the caller's job (see register_pass_by_name).
std::unique_ptr<AnalysisPass> create_pass_by_name(std::string_view name,
                                                  const PassRunCtx& ctx) {
    // ── No-config / default-config passes ──────────────────────────────
    // Structure
    if (name == "function") {
        FunctionConfig cfg;
        cfg.full_mode = ctx.function_full_mode;
        return std::make_unique<FunctionPass>(std::move(cfg));
    }
    if (name == "xref")                    return std::make_unique<XrefPass>();
    if (name == "cfg")                     return std::make_unique<CFGPass>();
    if (name == "cfg_layout")              return std::make_unique<CFGLayoutPass>();
    if (name == "call_graph")              return std::make_unique<CallGraphPass>();
    if (name == "loop")                    return std::make_unique<LoopPass>();
    // Crypto
if (name == "pattern")                 return std::make_unique<PatternPass>();
// "constant_materialization" was merged into "pattern" (see PatternResult::constants).
if (name == "loop_semantics")          return std::make_unique<LoopSemanticsPass>();
    if (name == "algorithm_summary")       return std::make_unique<AlgorithmSummaryPass>();
    if (name == "objc_crypto")             return std::make_unique<ObjcCryptoPass>();
    // Memory
    if (name == "strings")                 return std::make_unique<StringPass>();
    if (name == "memory_strings")          return std::make_unique<MemoryStringPass>();
    if (name == "yara_mem_scan")           return std::make_unique<YaraMemScanPass>();
    // ObjC / Syscall
    if (name == "objc")                    return std::make_unique<ObjcPass>();
    if (name == "syscall_intercept")       return std::make_unique<SyscallInterceptPass>();
    // Profile
    if (name == "window_stats")            return std::make_unique<WindowStatsPass>();
    if (name == "trace_fold")              return std::make_unique<TraceFoldPass>();
    // Misc
    if (name == "thread")                  return std::make_unique<ThreadPass>();

    // ── Config-driven passes (derive from ctx) ─────────────────────────
    if (name == "taint") {
        TaintConfig c;
        c.source_inst_id = ctx.current_inst;
        c.add_source_reg(ctx.current_reg);
        c.taint_from_memory = true;
        c.track_memory_sinks = true;
        c.propagate_arithmetic = true;
        c.propagate_moves = true;
        c.max_instructions = 100000;
        return std::make_unique<TaintPass>(std::move(c));
    }
    if (name == "backward_taint") {
        BackwardTaintConfig c;
        c.sink_inst_id = ctx.current_inst;
        c.add_sink_reg(ctx.current_reg);
        c.propagate_through_memory = true;
        c.max_steps = 500000;
        c.max_tainted_insts = 50000;
        return std::make_unique<BackwardTaintPass>(std::move(c));
    }
    if (name == "taint_source_annotation") {
        return std::make_unique<TaintSourceAnnotationPass>();
    }
    if (name == "reg_timeline") {
        RegTimelineConfig c;
        c.target_reg = ctx.current_reg;
        c.start_inst_id = ctx.range_start;
        c.end_inst_id = ctx.range_end;
        return std::make_unique<RegTimelinePass>(std::move(c));
    }
    if (name == "call_context") {
        CallContextConfig c;
        c.target_inst_id = ctx.current_inst;
        return std::make_unique<CallContextPass>(std::move(c));
    }
    if (name == "entropy") {
        EntropyConfig c;
        c.at_inst_id = ctx.current_inst;
        c.addr       = ctx.entropy_addr;
        c.size       = ctx.entropy_size;
        return std::make_unique<EntropyPass>(std::move(c));
    }
    if (name == "mem_search") {
        MemSearchConfig c;
        c.start_inst_id = ctx.range_start;
        c.end_inst_id = ctx.range_end;
        for (const auto& hex : ctx.mem_search_patterns) {
            auto bytes = parse_hex_pattern(hex);
            if (!bytes.empty()) {
                c.patterns.emplace_back(std::move(bytes), std::string(hex));
            }
        }
        // Exact-value search (formerly the standalone literal_search pass).
        c.exact_values = ctx.literal_search_values;
        if (!c.exact_values.empty()) {
            c.search_immediates = true;
        }
        return std::make_unique<MemSearchPass>(std::move(c));
    }
    if (name == "memory_snapshot") {
        MemorySnapshotConfig c;
        c.snapshot_inst_ids = {ctx.current_inst};
        c.snapshot_at_function_calls = true;
        return std::make_unique<MemorySnapshotPass>(std::move(c));
    }
    if (name == "thread_filter") {
        ThreadFilterConfig c;
        c.include_thread_ids = ctx.thread_ids;
        c.build_bitmaps = true;
        return std::make_unique<ThreadFilterPass>(std::move(c));
    }
    if (name == "trace_diff") {
        TraceDiffConfig c;
        uint64_t mid = ctx.total_inst ? ctx.total_inst / 2 : 0;
        c.trace_a_start = 0;
        c.trace_a_end = mid;
        c.trace_b_start = mid;
        c.trace_b_end = ctx.total_inst;
        return std::make_unique<TraceDiffPass>(std::move(c));
    }
    if (name == "dataflow_graph") {
        DataflowGraphConfig c;
        c.start_inst_id = ctx.current_inst;
        c.end_inst_id = (ctx.range_end == UINT64_MAX)
                            ? std::min<uint64_t>(ctx.current_inst + 1000, ctx.total_inst)
                            : ctx.range_end;
        return std::make_unique<DataflowGraphPass>(std::move(c));
    }
    if (name == "vm_abstract") {
        // VM dispatcher auto-detection is unreliable on real traces (pure
        // heuristic on loop iteration count + indirect-branch shape).
        // Require the caller to have supplied static-analysis hints (via a
        // hints JSON file) or to have explicitly opted into auto-detection;
        // otherwise refuse to register the pass (caller sees registration
        // failure and should prompt the user for hints instead).
        VMConfig cfg;
        if (!ctx.vm_hints_file.empty()) {
            if (!load_vm_hints_from_json(ctx.vm_hints_file, cfg)) {
                return nullptr;
            }
        }
        cfg.auto_detect = ctx.vm_auto_detect;
        if (!cfg.has_any_static_hint() && !ctx.vm_auto_detect) {
            return nullptr;
        }
        return std::make_unique<VMAbstractPass>(std::move(cfg));
    }

    // Should be unreachable: catalog promises a case for every entry.
    return nullptr;
}

}  // namespace

// ─── Catalog ───────────────────────────────────────────────────────────────

const std::vector<PassCatalogEntry>& pass_catalog() {
    static const std::vector<PassCatalogEntry> catalog = {
        // — Structure —
        {"function",              "Functions",     "Discover call/return pairs, build function list",        PassCategory::Structure, PassDefault::Yes},
        {"xref",                  "XRefs",         "PC → inst_ids cross-reference index",                    PassCategory::Structure, PassDefault::Yes},
        {"cfg",                   "CFG",           "Control-flow graph (basic blocks + edges)",              PassCategory::Structure, PassDefault::Yes},
        {"cfg_layout",            "CFG Layout",    "Graph layout coordinates for CFG view",                  PassCategory::Structure, PassDefault::No},
        {"call_graph",            "Call Graph",    "Inter-function call graph",                              PassCategory::Structure, PassDefault::Yes},
        {"loop",                  "Loops",         "Detect loops via back-edges in CFG",                     PassCategory::Structure, PassDefault::Yes},

        // — Taint —
        {"taint",                 "Taint",         "Forward taint from current register",                    PassCategory::Taint,     PassDefault::No},
        {"backward_taint",        "Back Taint",    "Backward taint from current instruction",                PassCategory::Taint,     PassDefault::No},
        {"taint_source_annotation","Taint Sources","Annotate backward-taint endpoints (ObjC/mem/const)",     PassCategory::Taint,     PassDefault::No},

        // — Crypto / Pattern —
        // NOTE: "constant_materialization" (movz+movk crypto constant matching)
        // was merged into "pattern" — see PatternResult::constants. It is no
        // longer a separately-registrable pass.
        {"pattern",               "Patterns",      "Crypto/anti-debug patterns + materialized constants",    PassCategory::Crypto,    PassDefault::Yes},
        {"loop_semantics",        "Loop Semantics","Classify loops (Feistel/SPN/ARX/memcpy…)",               PassCategory::Crypto,    PassDefault::Yes},
        {"algorithm_summary",     "Algorithm",     "Cross-reference constants+patterns→algorithm ID",        PassCategory::Crypto,    PassDefault::Yes},
        {"objc_crypto",           "ObjC×Crypto",   "Correlate crypto patterns with ObjC call stacks",        PassCategory::Crypto,    PassDefault::No},

        // — Memory / String —
        {"strings",               "Strings",       "String accesses in the trace",                           PassCategory::Memory,    PassDefault::Yes},
        {"memory_strings",        "Mem Strings",   "Time-aware string discovery via memory reconstruction",  PassCategory::Memory,    PassDefault::No},
        {"memory_snapshot",       "Mem Snapshot",  "Capture memory snapshots at call sites / inst_ids",      PassCategory::Memory,    PassDefault::No},
        {"mem_search",            "Mem Search",    "Multi-pattern + exact-value/immediate search on memory/registers", PassCategory::Memory, PassDefault::No},
        {"entropy",               "Entropy",       "Shannon entropy of a memory region (ciphertext detect)", PassCategory::Memory,    PassDefault::No},
        {"yara_mem_scan",         "YARA Mem Scan", "YARA scan of memory pages (crypto constants in mem)",    PassCategory::Memory,    PassDefault::No},

        // — Platform API —
        {"objc",                  "ObjC",          "Objective-C message send analysis",                      PassCategory::PlatformApi, PassDefault::No},
        {"syscall_intercept",     "Syscalls",      "Intercept crypto/system API calls (platform-aware)",    PassCategory::PlatformApi, PassDefault::No},

        // — Profile / Trace —
        {"trace_fold",            "Trace Fold",    "Fold repetitive loop iterations into summaries",         PassCategory::Profile,   PassDefault::No},
        {"reg_timeline",          "Reg Timeline",  "Timeline of all writes to a register",                   PassCategory::Profile,   PassDefault::No},
        {"call_context",          "Call Context",  "Call stack + loop position + neighbors at an inst",      PassCategory::Profile,   PassDefault::No},
        {"window_stats",          "Window Stats",  "Sliding window statistics (hot regions, entropy…)",      PassCategory::Profile,   PassDefault::No},
        {"trace_diff",            "Trace Diff",    "Compare two trace regions for divergence",               PassCategory::Profile,   PassDefault::No},
        {"dataflow_graph",        "Dataflow",      "Register-level data-flow graph for a region",            PassCategory::Profile,   PassDefault::No},

        // — Misc —
        {"thread",                "Threads",       "Thread timeline / switching",                            PassCategory::Misc,      PassDefault::Yes},
        {"thread_filter",         "Thread Filter", "Per-thread instruction bitmaps for filtering",           PassCategory::Misc,      PassDefault::No},
        {"vm_abstract",           "VM Abstract",   "VM dispatcher detection, handler extraction, execution abstraction", PassCategory::Structure, PassDefault::No},
    };
    return catalog;
}

const PassCatalogEntry* find_pass_catalog_entry(std::string_view name) {
    for (const auto& e : pass_catalog()) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

bool is_known_pass(std::string_view name) {
    return find_pass_catalog_entry(name) != nullptr;
}

std::vector<std::string_view> default_ui_pass_names() {
    std::vector<std::string_view> out;
    for (const auto& e : pass_catalog()) {
        if (e.default_for_ui == PassDefault::Yes) out.push_back(e.name);
    }
    return out;
}

// ─── Registration ──────────────────────────────────────────────────────────

void register_default_passes(PassManager& pm) {
    // Default passes all have no-config or default-constructible configs, so
    // we can register them with empty PassRunCtx.
    PassRunCtx ctx;
    for (auto name : default_ui_pass_names()) {
        register_pass_by_name(pm, name, ctx);
    }
}

void register_all_passes(PassManager& pm, const PassRunCtx& ctx) {
    // Register every pass in the catalog.  register_pass_by_name() handles
    // dependencies recursively and is idempotent (skips already-registered
    // passes), so this is safe to call on a pm that already has some passes.
    for (const auto& entry : pass_catalog()) {
        register_pass_by_name(pm, entry.name, ctx);
    }
}

bool register_pass_by_name(PassManager& pm, std::string_view name,
                           const PassRunCtx& ctx) {
    if (!is_known_pass(name)) return false;
    if (pm_has_pass(pm, name)) return true;  // idempotent

    auto pass = create_pass_by_name(name, ctx);
    if (!pass) return false;

    // Register dependencies first (recursively), so require() finds them
    // when the pass executes. This lets any pass be run standalone — e.g.
    // `--run-pass call_graph` auto-pulls `function`.
    for (auto dep : pass->dependencies()) {
        register_pass_by_name(pm, dep, ctx);
    }
    pm.register_pass(std::move(pass));
    return true;
}

// ─── Result summary ────────────────────────────────────────────────────────

namespace {

/// Safely get a pointer to the typed result, or nullptr.
template <typename T>
const T* try_get(const PassResult& r) {
    if (!r.ok() || !r.data.has_value()) return nullptr;
    return std::any_cast<T>(&r.data);
}

std::string cat_count(std::string_view label, size_t n) {
    return fmt::format("{}: {}", label, n);
}

}  // namespace

std::string summarize_pass_result(std::string_view name, const PassResult& result) {
    if (!result.ok()) {
        return result.error_message.empty()
            ? std::string("failed")
            : ("failed: " + result.error_message);
    }

    // Structure
    if (name == "function") {
        if (auto* r = try_get<FunctionResult>(result))
            return cat_count("functions", r->functions.size());
    }
    if (name == "xref") {
        if (auto* r = try_get<XrefResult>(result))
            return fmt::format("unique PCs: {}, insts indexed: {}",
                               r->unique_pc_count, r->total_indexed);
    }
    if (name == "cfg") {
        if (auto* r = try_get<CFGResult>(result))
            return fmt::format("blocks: {}, edges: {}", r->blocks.size(), r->edges.size());
    }
    if (name == "cfg_layout") {
        if (auto* r = try_get<CFGLayoutResult>(result))
            return fmt::format("block layouts: {}", r->block_layouts.size());
    }
    if (name == "call_graph") {
        if (auto* r = try_get<CallGraphResult>(result))
            return fmt::format("nodes: {}, edges: {}, max depth: {}",
                               r->nodes.size(), r->edges.size(), r->max_depth);
    }
    if (name == "loop") {
        if (auto* r = try_get<LoopResult>(result))
            return cat_count("loops", r->loops.size());
    }

    // Taint
    if (name == "taint") {
        if (auto* r = try_get<TaintResult>(result))
            return fmt::format("tainted insts: {}", r->tainted_inst_count());
    }
    if (name == "backward_taint") {
        if (auto* r = try_get<BackwardTaintResult>(result))
            return fmt::format("contributing insts: {}, depth: {}",
                               r->contributing_count(), r->max_depth);
    }
    if (name == "taint_source_annotation") {
        if (auto* r = try_get<TaintSourceAnnotationResult>(result))
            return cat_count("sources", r->total());
    }

// Crypto
if (name == "pattern") {
if (auto* r = try_get<PatternResult>(result))
return fmt::format("matches: {} | constants: {} ({} identified)",
r->total(), r->constants.total(), r->constants.identified_count());
}
if (name == "loop_semantics") {
        if (auto* r = try_get<LoopSemanticsResult>(result))
            return fmt::format("loops: {} ({} crypto)", r->loop_semantics.size(),
                               r->crypto_loops().size());
    }
    if (name == "algorithm_summary") {
        if (auto* r = try_get<AlgorithmSummaryResult>(result))
            return cat_count("algorithms", r->total());
    }
    if (name == "objc_crypto") {
        if (auto* r = try_get<ObjcCryptoResult>(result))
            return fmt::format("hits: {} ({} in ObjC)", r->total(), r->in_objc_count());
    }

    // Memory
    if (name == "strings") {
        if (auto* r = try_get<StringResult>(result))
            return cat_count("strings", r->strings.size());
    }
    if (name == "memory_strings") {
        if (auto* r = try_get<MemoryStringResult>(result))
            return fmt::format("strings: {} ({} unique)", r->total(), r->unique_count());
    }
    if (name == "memory_snapshot") {
        if (auto* r = try_get<MemorySnapshotResult>(result))
            return cat_count("snapshots", r->total());
    }
    if (name == "mem_search") {
        if (auto* r = try_get<MemSearchResult>(result))
            return fmt::format("matches: {}, scanned {} insts",
                               r->matches.size(), r->instructions_scanned);
    }
    if (name == "entropy") {
        if (auto* r = try_get<EntropyResult>(result))
            return fmt::format("entropy: {:.2f} ({})", r->overall_entropy,
                               r->known_bytes);
    }
    if (name == "yara_mem_scan") {
        if (auto* r = try_get<YaraMemScanResult>(result))
            return fmt::format("matches: {}, pages scanned: {}",
                               r->matches.size(), r->pages_scanned);
    }

    // ObjC / Syscall
    if (name == "objc") {
        if (auto* r = try_get<ObjcResult>(result))
            return fmt::format("messages: {}, classes: {}",
                               r->messages.size(), r->classes.size());
    }
    if (name == "syscall_intercept") {
        if (auto* r = try_get<SyscallInterceptResult>(result))
            return cat_count("intercepted calls", r->total());
    }

    // Profile
    if (name == "trace_fold") {
        if (auto* r = try_get<TraceFoldResult>(result))
            return fmt::format("folded regions: {}, removed {} insts ({}x)",
                               r->folded_regions.size(),
                               r->total_instructions_removed, r->compression_ratio);
    }
    if (name == "reg_timeline") {
        if (auto* r = try_get<RegTimelineResult>(result))
            return cat_count("writes", r->total_writes);
    }
    if (name == "call_context") {
        if (auto* r = try_get<CallContextResult>(result))
            return fmt::format("stack depth: {}, context insts: {}",
                               r->call_stack.size(), r->instructions.size());
    }
    if (name == "window_stats") {
        if (auto* r = try_get<WindowStatsResult>(result))
            return cat_count("windows", r->total_windows);
    }
    if (name == "trace_diff") {
        if (auto* r = try_get<TraceDiffResult>(result))
            return fmt::format("diverged: {}, matched: {}",
                               r->total_diverged, r->matched_count);
    }
    if (name == "dataflow_graph") {
        if (auto* r = try_get<DataflowGraphResult>(result))
            return fmt::format("nodes: {}, edges: {}", r->nodes.size(), r->edges.size());
    }

    // Misc
    if (name == "thread") {
        if (auto* r = try_get<ThreadResult>(result))
            return fmt::format("threads: {}, switches: {}",
                               r->thread_count(), r->switch_count());
    }
    if (name == "thread_filter") {
        if (auto* r = try_get<ThreadFilterResult>(result))
            return fmt::format("threads: {}, filtered: {}",
                               r->thread_count, r->is_filtered ? "yes" : "no");
    }
    if (name == "vm_abstract") {
        if (auto* r = try_get<VMAbstractResult>(result))
            return fmt::format("dispatcher: {:#x}, {} handlers, {} steps",
                               r->dispatcher.loop_header_pc,
                               r->handlers.size(), r->total_vm_steps);
    }

    return "ok";
}

}  // namespace tenet

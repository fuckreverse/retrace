// Tool registrations: analysis, search, pass
// These are the higher-level analysis tools that combine multiple passes.

#include "mcp_server.h"
#include "mcp_helpers.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "core/instruction_decoder.h"
#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"

#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/pattern_pass.h"  // also defines ConstantMaterializationResult
#include "analysis/passes/function_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/annotation_view.h"
#include "analysis/passes/memory_snapshot_pass.h"
#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/syscall_intercept_pass.h"
#include "analysis/passes/taint_source_annotation_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/trace_diff_pass.h"
#include "analysis/passes/reg_timeline_pass.h"
#include "analysis/passes/mem_search_pass.h"
#include "analysis/passes/call_context_pass.h"
#include "analysis/passes/window_stats_pass.h"
#include "analysis/passes/entropy_pass.h"
#include "analysis/passes/literal_search_pass.h"
#include "analysis/passes/vm_abstract_pass.h"

#include <fmt/core.h>

#include <fstream>
#include <string>
#include <sstream>

using json = nlohmann::json;

namespace tenet {

// ═══════════════════════════════════════════════════════════════════════════
// Analysis tools (pattern, strings, constants, loops, algorithm, objc, etc.)
// ═══════════════════════════════════════════════════════════════════════════

void TenetMcpService::register_analysis_tools() {
    // ── pattern_scan ──────────────────────────────────────────────────────
    register_tool(
        {"pattern_scan",
         "Detect crypto, anti-debug, anti-tamper, and obfuscation patterns "
         "in the trace. Returns matches with category, confidence, and "
         "instruction ranges.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            tenet::register_pass_by_name(*pm_, "pattern");
            const auto& result = require_pass<PatternResult>(pm_, "pattern", "Pattern pass failed");

            json matches = json::array();
            for (const auto& m : result.matches) {
                matches.push_back({
                    {"pattern_name",  m.pattern_name},
                    {"category",      pattern_category_str(m.category)},
                    {"confidence",    pattern_confidence_str(m.confidence)},
                    {"start_inst_id", m.start_inst_id},
                    {"end_inst_id",   m.end_inst_id},
                    {"anchor_pc",     fmt::format("0x{:X}", rebase(m.anchor_pc))},
                    {"description",   m.description}
                });
            }
            return {{"total", result.total()}, {"matches", std::move(matches)}};
        }
    );

    // ── strings_scan ──────────────────────────────────────────────────────
    register_tool(
        {"strings_scan",
         "Discover printable strings in traced memory accesses. "
         "Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more results).",
         {{"type", "object"},
          {"properties", {
              {"offset", {{"type", "integer"}, {"description", "Pagination: skip first N strings"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Pagination: max strings per page (max 500)"}, {"default", 500}}}
          }}}},
        [this](const json& args) -> json {
            tenet::register_pass_by_name(*pm_, "strings");
            const auto& result = require_pass<StringResult>(pm_, "strings", "String pass failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(500)), size_t(500));
            json strings = json::array();
            size_t start_i = std::min(offset, result.strings.size());
            size_t end_i = std::min(start_i + limit, result.strings.size());
            for (size_t i = start_i; i < end_i; i++) {
                const auto& s = result.strings[i];
                strings.push_back({
                    {"addr", fmt::format("0x{:X}", s.addr)},
                    {"content", s.content},
                    {"encoding", s.encoding == StringRef::ASCII ? "ASCII" :
                                 s.encoding == StringRef::UTF8  ? "UTF8"  :
                                 s.encoding == StringRef::UTF16LE ? "UTF16" : "Wide"},
                    {"ref_count", s.references.size()}
                });
            }
            bool has_more = end_i < result.strings.size();
            return {{"total", result.total()},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"strings", std::move(strings)}};
        }
    );

    // ── constants_scan ────────────────────────────────────────────────────
    register_tool(
        {"constants_scan",
         "Extract materialized constants (movz+movk sequences). Identifies "
         "known algorithm constants (AES S-box, SHA round constants, etc.).",
         {{"type", "object"},
          {"properties", {
              {"min_parts", {{"type", "integer"}, {"description", "Min movz+movk parts"}, {"default", 2}}}
          }}}},
        [this](const json& args) -> json {
            // Constant materialization was merged into "pattern" (see
            // PatternResult::constants) — register PatternPass and read the
            // embedded ConstantMaterializationResult.
            auto pass = std::make_unique<PatternPass>();
            pass->set_constants_min_parts(args.value("min_parts", uint8_t(2)));
            pm_->register_pass(std::move(pass));
            const auto& pattern_result = require_pass<PatternResult>(pm_, "pattern", "Constants pass failed");
            const auto& result = pattern_result.constants;

            json identified = json::array();
            for (size_t idx : result.identified_indices) {
                const auto& c = result.constants[idx];
                identified.push_back({
                    {"value",     fmt::format("0x{:016X}", c.value)},
                    {"reg",       c.dst_reg},
                    {"algorithm", c.known_match->algorithm},
                    {"name",      c.known_match->name},
                    {"inst_range", {c.first_inst_id, c.last_inst_id}}
                });
            }

            json by_algo;
            for (const auto& [algo, indices] : result.by_algorithm) {
                by_algo[algo] = indices.size();
            }

            return {{"total", result.total()},
                    {"identified_count", result.identified_count()},
                    {"identified_constants", std::move(identified)},
                    {"by_algorithm", std::move(by_algo)}};
        }
    );

    // ── loop_semantics ────────────────────────────────────────────────────
    register_tool(
        {"loop_semantics",
         "Identify round functions and crypto loop semantics. Detects "
         "Feistel rounds, SPN rounds, ARX patterns, S-box lookups, etc.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            tenet::register_pass_by_name(*pm_, "loop");
            tenet::register_pass_by_name(*pm_, "loop_semantics");
            const auto& result = require_pass<LoopSemanticsResult>(pm_, "loop_semantics", "Loop semantics failed");

            json loops = json::array();
            for (const auto& l : result.loop_semantics) {
                loops.push_back({
                    {"pc", fmt::format("0x{:X}", rebase(l.header_pc))},
                    {"iteration_count", l.iteration_count},
                    {"kind", loop_kind_name(l.kind)},
                    {"confidence", l.confidence},
                    {"description", l.description},
                    {"body_instruction_count", l.body_instruction_count},
                    {"has_sbox_pattern", l.has_sbox_pattern},
                    {"has_xor_mix", l.has_xor_mix},
                    {"has_shift_rotate", l.has_shift_rotate}
                });
            }
            return {{"loops", std::move(loops)}};
        }
    );

    // ── algorithm_summary ─────────────────────────────────────────────────
    register_tool(
        {"algorithm_summary",
         "Generate an algorithm identification summary. Combines pattern "
         "matching, constant identification, loop semantics, and call graph "
         "analysis to identify cryptographic algorithms in the trace.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            // "constant_materialization" was merged into "pattern" — see
            // PatternResult::constants.
            tenet::register_pass_by_name(*pm_, "pattern");
            tenet::register_pass_by_name(*pm_, "loop");
            tenet::register_pass_by_name(*pm_, "loop_semantics");
            tenet::register_pass_by_name(*pm_, "function");
            tenet::register_pass_by_name(*pm_, "call_graph");
            tenet::register_pass_by_name(*pm_, "algorithm_summary");
            const auto& result = require_pass<AlgorithmSummaryResult>(pm_, "algorithm_summary", "Algorithm summary failed");
            return result.summary_json;
        }
    );

    // ── objc_messages ─────────────────────────────────────────────────────
    register_tool(
        {"objc_messages",
         "Analyze Objective-C message sends (objc_msgSend calls) in the "
         "trace. Returns class names, selectors, arguments, and return values. "
         "Both filters use substring matching and can be combined.",
         {{"type", "object"},
          {"properties", {
              {"class_filter",    {{"type", "string"}, {"description", "Filter by class name (exact match, optional)"}}},
              {"selector_filter", {{"type", "string"}, {"description", "Filter by selector name substring (e.g. 'encryptData' matches 'encryptData:withKey:', optional)"}}}
          }}}},
        [this](const json& args) -> json {
            auto pass = std::make_unique<ObjcPass>();
            if (args.contains("class_filter")) {
                pass->set_class_filter(args["class_filter"].get<std::string>());
            }
            if (args.contains("selector_filter")) {
                pass->set_selector_filter(args["selector_filter"].get<std::string>());
            }
            pm_->register_pass(std::move(pass));
            const auto& result = require_pass<ObjcResult>(pm_, "objc", "ObjC pass failed");
            return result.to_json();
        }
    );

    // ── symbol_annotation ─────────────────────────────────────────────────
    register_tool(
        {"symbol_annotation",
         "Generate symbol annotations for all PCs (function labels, loop "
         "indicators, constant markers, pattern identifiers). "
         "Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more PCs).",
         {{"type", "object"},
          {"properties", {
              {"offset", {{"type", "integer"}, {"description", "Pagination: skip first N annotated PCs"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Pagination: max PCs per page (max 1000)"}, {"default", 1000}}}
          }}}},
        [this](const json& args) -> json {
            // Not a registered pass: this tool just aggregates the results of
            // three independent passes on the fly via build_annotation_view().
            // Constant materialization was merged into "pattern" (see
            // PatternResult::constants), so only function/loop/pattern need
            // to be scheduled here.
            // Each require_pass<T>() below still schedules its pass in the
            // background and throws PassNotReady if not yet complete, so the
            // non-blocking MCP semantics are unchanged.
            tenet::register_pass_by_name(*pm_, "function");
            tenet::register_pass_by_name(*pm_, "loop");
            tenet::register_pass_by_name(*pm_, "pattern");

            const auto& func_result  = require_pass<FunctionResult>(pm_, "function", "Function pass failed");
            const auto& loop_result  = require_pass<LoopResult>(pm_, "loop", "Loop pass failed");
            const auto& pat_result   = require_pass<PatternResult>(pm_, "pattern", "Pattern pass failed");
            const auto& const_result = pat_result.constants;

            auto result = build_annotation_view(&func_result, &loop_result, &const_result, &pat_result);

            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(1000)), size_t(1000));
            json annotations = json::array();
            size_t count = 0;
            size_t skipped = 0;
            for (const auto& [pc, anns] : result.by_pc) {
                if (skipped < offset) { skipped++; continue; }
                if (count >= limit) break;
                for (const auto& a : anns) {
                    annotations.push_back({
                        {"pc", fmt::format("0x{:X}", rebase(pc))},
                        {"label", a.label},
                        {"detail", a.detail},
                        {"kind", static_cast<int>(a.kind)}
                    });
                }
                count++;
            }
            bool has_more = (offset + count) < result.by_pc.size();
            return {{"total_pcs", result.by_pc.size()},
                    {"offset", offset},
                    {"returned", count},
                    {"has_more", has_more},
                    {"next_offset", has_more ? offset + count : offset},
                    {"annotations", std::move(annotations)}};
        }
    );

    // ── memory_snapshot ───────────────────────────────────────────────────
    register_tool(
        {"memory_snapshot",
         "Capture memory snapshots at specific instruction IDs. Shows "
         "the memory state around register-pointed regions at those moments.",
         {{"type", "object"},
          {"properties", {
              {"inst_ids",      {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Instruction IDs to snapshot"}}},
              {"snapshot_size", {{"type", "integer"}, {"description", "Bytes per region"}, {"default", 64}}}
          }},
          {"required", json::array({"inst_ids"})}}},
        [this](const json& args) -> json {
            MemorySnapshotConfig cfg;
            for (const auto& id : args.at("inst_ids")) {
                cfg.snapshot_inst_ids.push_back(id.get<uint64_t>());
            }
            cfg.snapshot_size = args.value("snapshot_size", uint32_t(64));
            pm_->register_pass(std::make_unique<MemorySnapshotPass>(std::move(cfg)));
            const auto& result = require_pass<MemorySnapshotResult>(pm_, "memory_snapshot", "Memory snapshot failed");

            json snapshots = json::array();
            for (const auto& region : result.snapshots) {
                snapshots.push_back({
                    {"addr", fmt::format("0x{:X}", region.addr)},
                    {"at_inst_id", region.at_inst_id},
                    {"label", region.label},
                    {"hex_dump", MemorySnapshotResult::hex_dump(region)}
                });
            }
            return {{"total", result.total()}, {"snapshots", std::move(snapshots)}};
        }
    );

    // ── objc_crypto ───────────────────────────────────────────────────────
    register_tool(
        {"objc_crypto",
         "Correlate crypto pattern hits with ObjC call stack context. "
         "Shows which ObjC methods are active when crypto operations occur.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            tenet::register_pass_by_name(*pm_, "objc");
            // "constant_materialization" was merged into "pattern" — see
            // PatternResult::constants.
            tenet::register_pass_by_name(*pm_, "pattern");
            tenet::register_pass_by_name(*pm_, "objc_crypto");
            const auto& result = require_pass<ObjcCryptoResult>(pm_, "objc_crypto", "ObjC crypto failed");
            return json::parse(result.to_json());
        }
    );

    // ── syscall_intercept ─────────────────────────────────────────────────
    register_tool(
        {"syscall_intercept",
         "Extract crypto/system API call parameters (auto-selects per platform: "
         "CommonCrypto/Security.framework on iOS, BoringSSL/OpenSSL on Android). "
         "Captures key material, IV, input/output data from crypto API calls.",
         {{"type", "object"},
          {"properties", {
              {"capture_bytes", {{"type", "integer"}, {"description", "Bytes per pointer arg"}, {"default", 64}}}
          }}}},
        [this](const json& args) -> json {
            SyscallInterceptConfig cfg;
            cfg.capture_bytes = args.value("capture_bytes", uint32_t(64));
            tenet::register_pass_by_name(*pm_, "objc");
            pm_->register_pass(std::make_unique<SyscallInterceptPass>(std::move(cfg)));
            const auto& result = require_pass<SyscallInterceptResult>(pm_, "syscall_intercept", "Syscall intercept failed");
            return json::parse(result.to_json());
        }
    );

    // ── taint_source_annotation ───────────────────────────────────────────
    register_tool(
        {"taint_source_annotation",
         "Run backward taint from (sink_inst_id, sink_reg) and annotate the "
         "resulting leaf sources with ObjC getter/argument context, memory "
         "load addresses, materialized constants, or callee return values. "
         "Answers 'where did this register's value ultimately come from?' "
         "-- e.g. '[CryptoManager secretKey]', 'constant 0xDEADBEEF', or "
         "'return of CCCrypt()'.",
         {{"type", "object"},
          {"properties", {
              {"sink_inst_id", {{"type", "integer"}, {"description", "Instruction ID where the value is observed (backward taint starting point)"}}},
              {"sink_reg",     {{"type", json::array({"integer", "string"})}, {"description", "Sink register: integer index OR name string ('x0','lr','sp', etc.)"}, {"default", 0}}},
              {"max_steps",    {{"type", "integer"}, {"description", "Max backward walk steps (0=unlimited)"}, {"default", 500000}}}
          }},
          {"required", json::array({"sink_inst_id"})}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            BackwardTaintConfig bt_cfg;
            bt_cfg.sink_inst_id = args.at("sink_inst_id").get<uint64_t>();
            bt_cfg.add_sink_reg(args.contains("sink_reg") ? parse_reg(args.at("sink_reg")) : uint8_t(0));
            bt_cfg.propagate_through_memory = true;
            uint64_t max_steps = args.value("max_steps", uint64_t(500000));
            if (max_steps > 0) bt_cfg.max_steps = max_steps;

            pm_->register_pass(std::make_unique<BackwardTaintPass>(std::move(bt_cfg)));
            tenet::register_pass_by_name(*pm_, "objc");
            // Optional: enables FunctionReturn source attribution (callee
            // name/pc). taint_source_annotation degrades gracefully if this
            // pass is absent -- see TaintSourceAnnotationPass::dependencies().
            //
            // NOTE: `function` is intentionally NOT a listed dependency of
            // taint_source_annotation (see its dependencies() comment), so
            // PassManager::execute_pass() will never run it automatically as
            // part of resolving "taint_source_annotation" below -- it must be
            // require()'d explicitly here so ctx.try_require<FunctionResult>()
            // inside TaintSourceAnnotationPass::run() actually finds a
            // Completed state instead of silently seeing "not run yet" and
            // leaving callee_pc/callee_name empty on every FunctionReturn hit.
            tenet::register_pass_by_name(*pm_, "function");
            pm_->require("function");
            pm_->register_pass(std::make_unique<TaintSourceAnnotationPass>());

            const auto& result = require_pass<TaintSourceAnnotationResult>(pm_, "taint_source_annotation", "Taint source annotation failed");
            return json::parse(result.to_json());
        }
    );

    // ── trace_fold ────────────────────────────────────────────────────────
    register_tool(
        {"trace_fold",
         "Fold (compress) repetitive LOOP iterations in the trace. For each "
         "loop that runs many times, this keeps only the first/last few "
         "representative iterations and summarizes the rest as one "
         "'folded region' (iteration count, average body size, and which "
         "GPR/FPR registers changed — with a monotonic/oscillating/constant "
         "pattern hint). Useful for quickly spotting which hot loop consumed "
         "most of a huge trace before deciding whether to --exclude-range it "
         "or inspect it in detail (e.g. with loop_semantics). This does NOT "
         "analyze function call sequences — see call_graph/call_context for "
         "that. Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more regions).",
         {{"type", "object"},
          {"properties", {
              {"offset", {{"type", "integer"}, {"description", "Pagination: skip first N folded regions"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Pagination: max regions per page (max 500)"}, {"default", 500}}}
          }}}},
        [this](const json& args) -> json {
            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            tenet::register_pass_by_name(*pm_, "loop");
            tenet::register_pass_by_name(*pm_, "function");
            tenet::register_pass_by_name(*pm_, "trace_fold");
            const auto& result = require_pass<TraceFoldResult>(pm_, "trace_fold", "Trace fold failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(500)), size_t(500));
            json regions = json::array();
            size_t start_i = std::min(offset, result.folded_regions.size());
            size_t end_i = std::min(start_i + limit, result.folded_regions.size());
            for (size_t i = start_i; i < end_i; i++) {
                const auto& r = result.folded_regions[i];
                json reg_changes = json::array();
                for (const auto& rc : r.reg_changes) {
                    reg_changes.push_back({
                        {"reg", fmt::format("x{}", rc.reg)},
                        {"first_val", fmt::format("0x{:X}", rc.first_val)},
                        {"last_val", fmt::format("0x{:X}", rc.last_val)},
                        {"pattern", reg_change_pattern_name(rc.pattern)}
                    });
                }
                json fpr_changes = json::array();
                for (const auto& fc : r.fpr_changes) {
                    fpr_changes.push_back({
                        {"reg", fmt::format("v{}", fc.reg)},
                        {"first", fmt::format("0x{:016X}{:016X}", fc.first_hi, fc.first_lo)},
                        {"last", fmt::format("0x{:016X}{:016X}", fc.last_hi, fc.last_lo)}
                    });
                }
                regions.push_back({
                    {"header_pc", fmt::format("0x{:X}", rebase(r.header_pc))},
                    {"total_iterations", r.total_iterations},
                    {"instructions_per_iteration", r.instructions_per_iteration},
                    {"total_instructions_folded", r.total_instructions_folded},
                    {"inst_range", {r.first_inst_id, r.last_inst_id}},
                    {"reg_changes", std::move(reg_changes)},
                    {"fpr_changes", std::move(fpr_changes)}
                });
            }
            bool has_more = end_i < result.folded_regions.size();
            return {{"total_regions", result.folded_regions.size()},
                    {"original_inst_count", result.original_inst_count},
                    {"folded_inst_count", result.folded_inst_count},
                    {"compression_ratio", result.compression_ratio},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"regions", std::move(regions)}};
        }
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Search tools (memory search, literal search, reg timeline, producer chain)
// ═══════════════════════════════════════════════════════════════════════════

void TenetMcpService::register_search_tools() {
    // ── mem_search ────────────────────────────────────────────────────────
    register_tool(
        {"mem_search",
         "Search for a byte pattern in all traced memory writes. "
         "Useful for finding where a known value (key, magic bytes, etc.) "
         "first appears or is computed.",
         {{"type", "object"},
          {"properties", {
              {"hex_pattern", {{"type", "string"}, {"description", "Hex bytes to search, e.g. '4AES' or 'DEADBEEF'"}}},
              {"text",        {{"type", "string"}, {"description", "ASCII text to search (alternative to hex_pattern)"}}},
              {"limit",       {{"type", "integer"}, {"description", "Max results"}, {"default", 50}}}
          }}}},
        [this](const json& args) -> json {
            MemSearchConfig cfg;
            if (args.contains("hex_pattern")) {
                // Parse hex pattern string into bytes+mask
                MemSearchConfig::Pattern pat;
                std::string hex = args["hex_pattern"].get<std::string>();
                pat.label = hex;
                // Parse space-separated hex bytes, ?? for wildcards
                std::istringstream iss(hex);
                std::string token;
                while (iss >> token) {
                    if (token == "??" || token == "??") {
                        pat.bytes.push_back(0);
                        pat.mask.push_back(0);
                    } else {
                        pat.bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                        pat.mask.push_back(0xFF);
                    }
                }
                cfg.patterns.push_back(std::move(pat));
            } else if (args.contains("text")) {
                MemSearchConfig::Pattern pat;
                std::string text = args["text"].get<std::string>();
                pat.label = text;
                for (char c : text) {
                    pat.bytes.push_back(static_cast<uint8_t>(c));
                    pat.mask.push_back(0xFF);
                }
                cfg.patterns.push_back(std::move(pat));
            } else {
                throw std::runtime_error("Provide hex_pattern or text");
            }
            cfg.max_matches = args.value("limit", uint64_t(50));

            pm_->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
            const auto& result = require_pass<MemSearchResult>(pm_, "mem_search", "Mem search failed");

            json hits = json::array();
            for (const auto& m : result.matches) {
                hits.push_back({
                    {"addr", fmt::format("0x{:X}", m.addr)},
                    {"inst_id", m.inst_id},
                    {"pc", fmt::format("0x{:X}", rebase(m.pc))},
                    {"source", m.source == MemSearchMatch::MemWrite ? "mem_write" : "reg_diff"},
                    {"pattern_index", m.pattern_index}
                });
            }
            return {{"total_matches", result.matches.size()},
                    {"instructions_scanned", result.instructions_scanned},
                    {"hits", std::move(hits)}};
        }
    );

    // ── reg_timeline ──────────────────────────────────────────────────────
    register_tool(
        {"reg_timeline",
         "Show how a register's value changes over time. Returns a timeline "
         "of (inst_id, pc, old_value, new_value) entries for the specified register. "
         "Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more entries).",
         {{"type", "object"},
          {"properties", {
              {"reg_index",     {{"type", json::array({"integer", "string"})}, {"description", "Register: integer index (0-33) OR name string ('x0','lr','sp', etc.)"}}},
              {"start_inst_id", {{"type", "integer"}, {"description", "Start from this instruction"}, {"default", 0}}},
              {"end_inst_id",   {{"type", "integer"}, {"description", "End at this instruction (0=end)"}, {"default", 0}}},
              {"offset",        {{"type", "integer"}, {"description", "Pagination: skip first N entries"}, {"default", 0}}},
              {"limit",         {{"type", "integer"}, {"description", "Pagination: max entries per page (max 2000)"}, {"default", 500}}}
          }},
          {"required", json::array({"reg_index"})}}},
        [this](const json& args) -> json {
            uint8_t target_reg = parse_reg(args.at("reg_index"));
            RegTimelineConfig cfg;
            cfg.target_reg = target_reg;
            cfg.start_inst_id = args.value("start_inst_id", uint64_t(0));
            cfg.end_inst_id = args.value("end_inst_id", uint64_t(0));
            cfg.max_entries = 0; // fetch all; pagination happens in output stage

            pm_->register_pass(std::make_unique<RegTimelinePass>(std::move(cfg)));
            const auto& result = require_pass<RegTimelineResult>(pm_, "reg_timeline", "Reg timeline failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit  = std::min(args.value("limit", size_t(500)), size_t(2000));
            size_t start_i = std::min(offset, result.entries.size());
            size_t end_i   = std::min(start_i + limit, result.entries.size());

            json timeline = json::array();
            for (size_t i = start_i; i < end_i; i++) {
                const auto& e = result.entries[i];
                timeline.push_back({
                    {"inst_id", e.inst_id},
                    {"pc",  fmt::format("0x{:X}", rebase(e.pc))},
                    {"old", fmt::format("0x{:X}", e.old_value)},
                    {"new", fmt::format("0x{:X}", e.new_value)}
                });
            }
            bool has_more = end_i < result.entries.size();
            return {{"reg", kRegNames[target_reg]},
                    {"total_writes", result.total_writes},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"timeline", std::move(timeline)}};
        }
    );

    // ── literal_search ────────────────────────────────────────────────────
    register_tool(
        {"literal_search",
         "Search for a literal (integer/float) value in register values "
         "and memory accesses throughout the trace.",
         {{"type", "object"},
          {"properties", {
              {"value", {{"type", "string"}, {"description", "Value to search (hex or decimal)"}}},
              {"limit", {{"type", "integer"}, {"description", "Max results"}, {"default", 50}}}
          }},
          {"required", json::array({"value"})}}},
        [this](const json& args) -> json {
            LiteralSearchConfig cfg;
            cfg.search_values.push_back(parse_hex(args.at("value").get<std::string>()));
            cfg.max_results = args.value("limit", uint64_t(50));

            pm_->register_pass(std::make_unique<LiteralSearchPass>(std::move(cfg)));
            const auto& result = require_pass<LiteralSearchResult>(pm_, "literal_search", "Literal search failed");

            json hits = json::array();
            for (const auto& h : result.hits) {
                const char* src = (h.source == LiteralHit::RegDiff) ? "reg" :
                                  (h.source == LiteralHit::MemWrite) ? "mem" : "imm";
                hits.push_back({
                    {"inst_id",  h.inst_id},
                    {"pc",       fmt::format("0x{:X}", rebase(h.pc))},
                    {"source",   src},
                    {"matched_value", fmt::format("0x{:X}", h.matched_value)}
                });
            }
            return {{"total", result.hits.size()},
                    {"instructions_scanned", result.instructions_scanned},
                    {"hits", std::move(hits)}};
        }
    );

    // ── call_context ──────────────────────────────────────────────────────
    register_tool(
        {"call_context",
         "Show the function call context (call stack) at a given instruction. "
         "Provide EITHER inst_id (exact instruction index) OR pc (address, hex string). "
         "When pc is given, the first inst_id that executed at that address is used. "
         "The 'depth' parameter is silently ignored (kept for forward compatibility).",
         {{"type", "object"},
          {"properties", {
              {"inst_id", {{"type", "integer"}, {"description", "Instruction ID (preferred if known)"}}},
              {"pc",      {{"type", "string"},  {"description", "PC address (hex string, e.g. '0x100A92E54'). Used when inst_id is not provided."}}}
          }}}},
        [this](const json& args) -> json {
            // Resolve target inst_id from inst_id or pc
            uint64_t target_inst_id = 0;
            if (args.contains("inst_id")) {
                target_inst_id = args.at("inst_id").get<uint64_t>();
            } else if (args.contains("pc")) {
                uint64_t runtime_pc = unrebase(parse_hex(args.at("pc").get<std::string>()));
                tenet::register_pass_by_name(*pm_, "xref");
                const auto& xref_raw = require_pass_nb(pm_, "xref");
                if (!xref_raw.ok())
                    throw std::runtime_error("xref pass failed: " + xref_raw.error_message);
                const auto& xref = xref_raw.get<XrefResult>();
                auto ids = xref.inst_ids_at(runtime_pc);
                if (ids.empty())
                    throw std::runtime_error(fmt::format(
                        "No instruction found at PC {}. Use search_pc to check if this address was executed.",
                        args.at("pc").get<std::string>()));
                target_inst_id = ids.front();
            } else {
                throw std::runtime_error("Provide 'inst_id' or 'pc' to identify the target instruction.");
            }

            CallContextConfig cfg;
            cfg.target_inst_id = target_inst_id;

            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            tenet::register_pass_by_name(*pm_, "loop");
            tenet::register_pass_by_name(*pm_, "function");
            pm_->register_pass(std::make_unique<CallContextPass>(std::move(cfg)));
            const auto& result = require_pass<CallContextResult>(pm_, "call_context", "Call context failed");

            json frames = json::array();
            for (const auto& f : result.call_stack) {
                frames.push_back({
                    {"call_site_pc",   fmt::format("0x{:X}", rebase(f.call_site_pc))},
                    {"callee_pc",      fmt::format("0x{:X}", rebase(f.callee_pc))},
                    {"call_inst_id",   f.call_inst_id},
                    {"return_inst_id", f.return_inst_id},
                    {"is_tail_call",   f.is_tail_call}
                });
            }
            return {{"target_inst_id", result.target_inst_id},
                    {"target_pc", fmt::format("0x{:X}", rebase(result.target_pc))},
                    {"call_stack_depth", result.call_stack.size()},
                    {"call_stack", std::move(frames)}};
        }
    );

    // ── window_stats ──────────────────────────────────────────────────────
    register_tool(
        {"window_stats",
         "Compute instruction-mix statistics over a window of instructions. "
         "Counts branches, loads, stores, arithmetic, crypto ops, etc. "
         "Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more windows).",
         {{"type", "object"},
          {"properties", {
              {"start_inst_id", {{"type", "integer"}, {"description", "Start instruction ID"}, {"default", 0}}},
              {"end_inst_id",   {{"type", "integer"}, {"description", "End instruction ID (0=end)"}, {"default", 0}}},
              {"window_size",   {{"type", "integer"}, {"description", "Sliding window size"}, {"default", 1000}}},
              {"offset",        {{"type", "integer"}, {"description", "Pagination: skip first N windows"}, {"default", 0}}},
              {"limit",         {{"type", "integer"}, {"description", "Pagination: max windows per page (max 500)"}, {"default", 100}}}
          }}}},
        [this](const json& args) -> json {
            WindowStatsConfig cfg;
            cfg.window_size = args.value("window_size", uint64_t(1000));

            pm_->register_pass(std::make_unique<WindowStatsPass>(std::move(cfg)));
            const auto& result = require_pass<WindowStatsResult>(pm_, "window_stats", "Window stats failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit  = std::min(args.value("limit", size_t(100)), size_t(500));
            size_t start_i = std::min(offset, result.windows.size());
            size_t end_i   = std::min(start_i + limit, result.windows.size());

            json windows = json::array();
            for (size_t i = start_i; i < end_i; i++) {
                const auto& w = result.windows[i];
                windows.push_back({
                    {"start", w.start_inst_id},
                    {"end",   w.end_inst_id},
                    {"instruction_count", w.instruction_count},
                    {"mem_read_count", w.mem_read_count},
                    {"mem_write_count", w.mem_write_count},
                    {"unique_pcs", w.unique_pcs},
                    {"branch_density", w.branch_density},
                    {"mnemonic_entropy", w.mnemonic_entropy}
                });
            }
            bool has_more = end_i < result.windows.size();
            return {{"total_windows", result.total_windows},
                    {"window_size", result.window_size},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"windows", std::move(windows)}};
        }
    );

    // ── entropy_analysis ──────────────────────────────────────────────────
    register_tool(
        {"entropy_analysis",
         "Compute Shannon entropy over memory write patterns. High-entropy "
         "regions often indicate encryption or compression output. "
         "Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more blocks).",
         {{"type", "object"},
          {"properties", {
              {"offset", {{"type", "integer"}, {"description", "Pagination: skip first N blocks"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Pagination: max blocks per page (max 500)"}, {"default", 100}}}
          }}}},
        [this](const json& args) -> json {
            tenet::register_pass_by_name(*pm_, "entropy");
            const auto& result = require_pass<EntropyResult>(pm_, "entropy", "Entropy failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit  = std::min(args.value("limit", size_t(100)), size_t(500));
            size_t start_i = std::min(offset, result.blocks.size());
            size_t end_i   = std::min(start_i + limit, result.blocks.size());

            json blocks_arr = json::array();
            for (size_t i = start_i; i < end_i; i++) {
                const auto& b = result.blocks[i];
                blocks_arr.push_back({
                    {"offset",  b.offset},
                    {"size",    b.size},
                    {"entropy", b.entropy},
                    {"is_known", b.is_known}
                });
            }
            bool has_more = end_i < result.blocks.size();
            const char* cls_names[] = {"Unknown", "Plaintext", "Compressed", "Encrypted", "KeyMaterial"};
            return {{"addr", fmt::format("0x{:X}", result.addr)},
                    {"overall_entropy", result.overall_entropy},
                    {"classification", cls_names[static_cast<int>(result.classification)]},
                    {"region_size", result.region_size},
                    {"known_bytes", result.known_bytes},
                    {"total_blocks", result.blocks.size()},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"blocks", std::move(blocks_arr)}};
        }
    );

    // ── memory_strings ────────────────────────────────────────────────────
    register_tool(
        {"memory_strings",
         "Extract strings from memory at a specific point in time. Unlike "
         "strings_scan (which scans write events), this reads continuous "
         "memory regions for printable strings.",
         {{"type", "object"},
          {"properties", {
              {"at_inst_id", {{"type", "integer"}, {"description", "Read memory state as of this instruction"}}},
              {"min_length", {{"type", "integer"}, {"description", "Minimum string length"}, {"default", 4}}}
          }},
          {"required", json::array({"at_inst_id"})}}},
        [this](const json& args) -> json {
            MemoryStringConfig cfg;
            cfg.min_string_len = args.value("min_length", size_t(4));

            pm_->register_pass(std::make_unique<MemoryStringPass>(std::move(cfg)));
            const auto& result = require_pass<MemoryStringResult>(pm_, "memory_strings", "Memory strings failed");

            json strings = json::array();
            size_t limit = std::min(result.strings.size(), size_t(500));
            for (size_t i = 0; i < limit; i++) {
                const auto& s = result.strings[i];
                strings.push_back({
                    {"addr", fmt::format("0x{:X}", s.addr)},
                    {"content", s.content},
                    {"discovered_at", s.discovered_at},
                    {"encoding", s.encoding == MemoryString::ASCII ? "ASCII" :
                                 s.encoding == MemoryString::UTF8  ? "UTF8"  : "UTF16"}
                });
            }
            return {{"total", result.total()},
                    {"unique_count", result.unique_count()},
                    {"strings", std::move(strings)},
                    {"truncated", result.strings.size() > limit}};
        }
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Pass tools -- raw pass execution for advanced users
// ═══════════════════════════════════════════════════════════════════════════

void TenetMcpService::register_pass_tools() {
    // ── functions ─────────────────────────────────────────────────────────
    register_tool(
        {"functions",
         "List all detected functions in the trace. Returns function PCs, "
         "names (if available), instruction ranges, and call counts. "
         "Supports pagination via offset/limit "
         "(use has_more + next_offset to fetch more functions).",
         {{"type", "object"},
          {"properties", {
              {"offset", {{"type", "integer"}, {"description", "Pagination: skip first N functions"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Pagination: max functions per page (max 500)"}, {"default", 500}}}
          }}}},
        [this](const json& args) -> json {
            tenet::register_pass_by_name(*pm_, "function");
            const auto& result = require_pass<FunctionResult>(pm_, "function", "Function pass failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(500)), size_t(500));
            json funcs = json::array();
            size_t count = 0;
            size_t skipped = 0;
            for (const auto& [pc, info] : result.functions) {
                if (skipped < offset) { skipped++; continue; }
                if (count >= limit) break;
                funcs.push_back({
                    {"pc",          fmt::format("0x{:X}", rebase(info.entry_pc))},
                    {"name",        info.name},
                    {"total_calls", info.total_calls},
                    {"total_instructions", info.total_instructions}
                });
                count++;
            }
            bool has_more = (offset + count) < result.functions.size();
            return {{"total", result.functions.size()},
                    {"offset", offset},
                    {"returned", count},
                    {"has_more", has_more},
                    {"next_offset", has_more ? offset + count : offset},
                    {"functions", std::move(funcs)}};
        }
    );

    // ── loops ─────────────────────────────────────────────────────────────
    register_tool(
        {"loops",
         "Detect loops in the trace. Returns loop header PCs, iteration "
         "counts, body sizes, and nesting information.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            tenet::register_pass_by_name(*pm_, "loop");
            const auto& result = require_pass<LoopResult>(pm_, "loop", "Loop pass failed");

            json loops = json::array();
            for (const auto& l : result.loops) {
                loops.push_back({
                    {"header_pc",       fmt::format("0x{:X}", rebase(l.header_pc))},
                    {"back_edge_pc",    fmt::format("0x{:X}", rebase(l.back_edge_pc))},
                    {"iteration_count", l.iteration_count},
                    {"body_pc_count",   l.body_pcs.size()},
                    {"nesting_depth",   l.nesting_depth}
                });
            }
            return {{"total", result.loops.size()},
                    {"max_nesting_depth", result.max_nesting_depth},
                    {"loops", std::move(loops)}};
        }
    );

    // ── xref ──────────────────────────────────────────────────────────────
    register_tool(
        {"xref",
         "Get cross-reference statistics: unique PCs, execution counts, "
         "hot addresses. The XRef pass builds a complete PC->inst_id index.",
         {{"type", "object"},
          {"properties", {
              {"top_n", {{"type", "integer"}, {"description", "Top N hot PCs"}, {"default", 20}}}
          }}}},
        [this](const json& args) -> json {
            tenet::register_pass_by_name(*pm_, "xref");
            const auto& xref = require_pass<XrefResult>(pm_, "xref", "XRef pass failed");

            size_t top_n = args.value("top_n", 20);
            auto hot = xref.hottest(top_n);
            json hot_arr = json::array();
            for (const auto& [pc, count] : hot) {
                hot_arr.push_back({
                    {"pc",    fmt::format("0x{:X}", rebase(pc))},
                    {"count", count}
                });
            }
            return {{"unique_pcs", xref.unique_pc_count},
                    {"total_instructions", xref.total_indexed},
                    {"hot_pcs", std::move(hot_arr)}};
        }
    );

    // ── trace_diff ────────────────────────────────────────────────────────
    register_tool(
        {"trace_diff",
         "Compare two instruction ranges in the trace. Shows register and "
         "memory state differences, useful for analyzing different loop "
         "iterations or comparing function calls. "
         "Supports pagination via offset/limit on the divergence segments.",
         {{"type", "object"},
          {"properties", {
              {"range_a_start", {{"type", "integer"}, {"description", "First range start inst_id"}}},
              {"range_a_end",   {{"type", "integer"}, {"description", "First range end inst_id"}}},
              {"range_b_start", {{"type", "integer"}, {"description", "Second range start inst_id"}}},
              {"range_b_end",   {{"type", "integer"}, {"description", "Second range end inst_id"}}},
              {"trace_b_path",  {{"type", "string"},  {"description", "Optional: path to trace B file for cross-file comparison. Empty = same trace."}}},
              {"offset",        {{"type", "integer"}, {"description", "Pagination: skip first N divergence segments"}, {"default", 0}}},
              {"limit",         {{"type", "integer"}, {"description", "Pagination: max segments per page (max 1000)"}, {"default", 200}}}
          }},
          {"required", json::array({"range_a_start", "range_a_end", "range_b_start", "range_b_end"})}}},
        [this](const json& args) -> json {
            TraceDiffConfig cfg;
            cfg.trace_a_start = args.at("range_a_start").get<uint64_t>();
            cfg.trace_a_end   = args.at("range_a_end").get<uint64_t>();
            cfg.trace_b_start = args.at("range_b_start").get<uint64_t>();
            cfg.trace_b_end   = args.at("range_b_end").get<uint64_t>();
            if (args.contains("trace_b_path")) {
                cfg.trace_b_path = args.at("trace_b_path").get<std::string>();
            }

            pm_->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));
            const auto& result = require_pass<TraceDiffResult>(pm_, "trace_diff", "Trace diff failed");

            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(200)), size_t(1000));
            size_t start_i = std::min(offset, result.segments.size());
            size_t end_i = std::min(start_i + limit, result.segments.size());

            json segs_arr = json::array();
            for (size_t i = start_i; i < end_i; i++) {
                const auto& s = result.segments[i];
                segs_arr.push_back({
                    {"start_inst_a", s.start_inst_a},
                    {"start_inst_b", s.start_inst_b},
                    {"start_pc", fmt::format("0x{:X}", rebase(s.start_pc))},
                    {"type", std::string(diff_type_name(s.start_type))},
                    {"detail", s.start_detail},
                    {"resynced", s.resynced},
                    {"resync_inst_a", s.resync_inst_a},
                    {"resync_inst_b", s.resync_inst_b},
                    {"resync_pc", fmt::format("0x{:X}", rebase(s.resync_pc))},
                    {"skip_a", s.skip_a},
                    {"skip_b", s.skip_b}
                });
            }
            bool has_more = end_i < result.segments.size();
            return {{"segments", std::move(segs_arr)},
                    {"total_segments", result.segments.size()},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"matched_count", result.matched_count},
                    {"total_diverged", result.total_diverged},
                    {"resync_count", result.resync_count},
                    {"has_divergence", result.has_divergence()},
                    {"truncated", result.truncated}};
        }
    );

    // ── find_function ─────────────────────────────────────────────────────
    // This is deliberately placed here (not in core) because it depends on
    // FunctionPass which is an analysis-layer pass.
    register_tool(
        {"find_function",
         "Find a function by name substring or by PC address. "
         "Returns the function's entry PC, instruction range (first_inst_id / last_inst_id), "
         "call count, and total instruction count. "
         "This is the primary way to locate a function before calling disasm, taint, or CFG tools. "
         "Use name_query for a substring match (case-insensitive). "
         "Use pc to look up by exact entry address.",
         {{"type", "object"},
          {"properties", {
              {"name_query", {{"type", "string"}, {"description", "Case-insensitive substring to match in function name"}}},
              {"pc",         {{"type", "string"}, {"description", "Exact function entry PC (hex string)"}}},
              {"limit",      {{"type", "integer"}, {"description", "Max results for name search"}, {"default", 10}}}
          }}}},
        [this](const json& args) -> json {
            tenet::register_pass_by_name(*pm_, "function");
            tenet::register_pass_by_name(*pm_, "xref");
            const auto& fn_result = require_pass<FunctionResult>(pm_, "function", "Function pass failed");

            // XRef for inst_id lookup
            bool has_xref = false;
            const XrefResult* xref = nullptr;
            const auto& xref_raw = pm_->require("xref");
            if (xref_raw.ok()) { xref = &xref_raw.get<XrefResult>(); has_xref = true; }

            auto make_entry = [&](const FunctionInfo& info) -> json {
                json e = {
                    {"pc",          fmt::format("0x{:X}", rebase(info.entry_pc))},
                    {"name",        info.name},
                    {"total_calls", info.total_calls},
                    {"total_instructions", info.total_instructions}
                };
                // Find first inst_id via xref
                if (has_xref && xref) {
                    auto ids = xref->inst_ids_at(info.entry_pc);
                    if (!ids.empty()) {
                        e["first_inst_id"] = ids.front();
                    }
                }
                // Derive last inst_id from call events (latest return)
                uint64_t last_return = 0;
                for (auto idx : info.call_event_indices) {
                    if (idx < fn_result.call_events.size()) {
                        uint64_t ret_id = fn_result.call_events[idx].return_inst_id;
                        if (ret_id > last_return) last_return = ret_id;
                    }
                }
                if (last_return > 0) e["last_inst_id"] = last_return;
                return e;
            };

            // Lookup by exact PC
            if (args.contains("pc")) {
                uint64_t target_pc = unrebase(parse_hex(args["pc"].get<std::string>()));
                auto it = fn_result.functions.find(target_pc);
                if (it == fn_result.functions.end()) {
                    return {{"found", false},
                            {"error", fmt::format("No function at PC 0x{:X}", rebase(target_pc))}};
                }
                return {{"found", true}, {"function", make_entry(it->second)}};
            }

            // Search by name substring
            std::string query;
            if (args.contains("name_query")) {
                query = args["name_query"].get<std::string>();
                for (auto& c : query) c = static_cast<char>(std::tolower(c));
            }
            size_t limit = args.value("limit", size_t(10));

            json matches = json::array();
            for (const auto& [pc, info] : fn_result.functions) {
                if (matches.size() >= limit) break;
                if (!query.empty()) {
                    std::string name_lower = info.name;
                    for (auto& c : name_lower) c = static_cast<char>(std::tolower(c));
                    if (name_lower.find(query) == std::string::npos) continue;
                }
                matches.push_back(make_entry(info));
            }
            return {{"total_functions", fn_result.functions.size()},
                    {"matches", std::move(matches)},
                    {"truncated", fn_result.functions.size() > limit && query.empty()}};
        }
    );

    // ── vm_abstract ──────────────────────────────────────────────────────
    register_tool(
        {"vm_abstract",
         "Detect and analyze Virtual Machine (VM) based obfuscation in the trace. "
         "Identifies the VM dispatcher loop, extracts handler set, decodes VM opcodes, "
         "and reconstructs the VM execution trace (bytecode → handler mapping). "
         "Supports WhileSwitch, IndirectBranch, CallTable, ThreadedCode, and FetchOnly topologies. "
         "REQUIRES at least one static-analysis hint (e.g. 'dispatcher_pc' from IDA/Ghidra) "
         "or 'hints_file'. The purely heuristic dispatcher auto-detection (loop iteration "
         "count + indirect-branch shape) is disabled by default because it has a very high "
         "false-positive/false-negative rate on real traces; pass auto_detect=true to opt "
         "into it anyway (not recommended). "
         "Use this when you suspect VM/VMP protection.",
         {{"type", "object"},
          {"properties", {
              // ── Dispatcher location ──
              {"dispatcher_pc",        {{"type", "string"},  {"description", "Hint: PC of the dispatch loop header (hex). From IDA static analysis."}}},
              {"indirect_branch_pc",   {{"type", "string"},  {"description", "Hint: PC of the BR/BLR instruction that selects handlers (hex)."}}},
              {"mem_anchor_addr",      {{"type", "string"},  {"description", "Hint (FetchOnly only): runtime address of a memory location written exactly once per VM instruction (hex). Alternative to dispatcher_pc for heavily CFF-obfuscated VMs where NO single stable PC exists. E.g. '0x13B3444F0' = ctx_base + field_offset. Resolved via MemoryModel::write_history()."}}},
              {"mem_anchor_size",      {{"type", "integer"}, {"description", "Hint (FetchOnly + mem_anchor_addr): byte width of the write to watch for (1/2/4/8, default 4)."}}},
              {"handler_entry_pcs",    {{"type", "array"},   {"items", {{"type", "string"}}}, {"description", "Hint: known handler entry PCs (hex array). From IDA jump table analysis."}}},
              // ── Dispatch topology ──
              {"dispatch_type",        {{"type", "string"},  {"description", "Hint: force dispatch topology: 'WhileSwitch'|'IndirectBranch'|'CallTable'|'ThreadedCode'|'Trampoline'|'FetchOnly'. 'FetchOnly' skips handler/opcode discovery entirely and just snapshots VM state (vm_pc/ctx_fields/vm_registers) once per hit of 'dispatcher_pc' — use when the handler-selection logic itself is too obfuscated to recognize (e.g. a CFF-wrapped opcode-compare tree) but there is still one stable per-VM-instruction 'fetch/loop-back' anchor PC. Default: auto-detect."}}},
              {"threaded_dispatch_pcs",{{"type", "array"},   {"items", {{"type", "string"}}}, {"description", "Hint (ThreadedCode only): set of runtime fetch/dispatch tail PCs shared by every handler (hex array). E.g. the LDR+BR pair at the end of each handler. Required when dispatch_type='ThreadedCode'."}}},
              // ── VM-PC ──
              {"vm_pc_reg",            {{"type", "string"},  {"description", "Hint: host register holding VM program counter (e.g. 'x19', 'x20')."}}},
              {"bytecode_base",        {{"type", "string"},  {"description", "Hint: base address of bytecode buffer (hex)."}}},
              // ── Opcode format ──
              {"opcode_size",          {{"type", "integer"}, {"description", "Hint: bytes per opcode (1, 2, or 4). Mode A (memory read)."}}},
              {"opcode_byte_offset",   {{"type", "integer"}, {"description", "Hint: byte offset of the opcode field within the instruction word (default 0). E.g. if insn layout is [imm16][opcode8], set opcode_size=1, opcode_byte_offset=2. Mode A only."}}},
              {"opcode_mask",          {{"type", "string"},  {"description", "Hint: mask applied to extract opcode from loaded word (hex). Mode A."}}},
              {"opcode_shift",         {{"type", "integer"}, {"description", "Hint: right-shift after masking. Mode A."}}},
              {"opcode_deobf_steps",   {{"type", "array"},   {"items", {{"type", "object"}}}, {"description", "Hint: ordered deobfuscation transforms applied to (raw & mask) >> shift. Each element: {\"op\": \"sub|add|xor|and|or|lsr|lsl|mul|ror|bswap|neg|not\", \"imm\": <integer>}. ror=rotate-right, bswap=byte-swap (imm=width 2/4/8), neg=two's-complement negate, not=bitwise-NOT. Mode A only."}}},
              {"opcode_from_reg",      {{"type", "string"},  {"description", "Hint: host register (e.g. 'x0') that holds the already-decoded opcode index at dispatch time. Mode B — skips memory read entirely. Use when a decoder stub runs before the dispatch branch."}}},
              // ── VM context ──
              {"ctx_base_reg",         {{"type", "string"},  {"description", "Hint: register holding VM context struct pointer (e.g. 'x21')."}}},
              {"ctx_fields",           {{"type", "array"},   {"items", {{"type", "object"}}}, {"description", "Hint: named fields within vm_ctx struct. Each element: {\"name\":\"ip\", \"offset\":0, \"size\":4, \"is_pointer\":false}. size defaults to 8. is_pointer=true formats value as 0x.... Enables VM Context panel."}}},
              // ── VM register file ──
              {"vm_registers",         {{"type", "array"},   {"items", {{"type", "object"}}}, {"description", "Hint: VM register file layout. Each element: {\"name\":\"R0\", \"offset\":0, \"size\":8, \"is_float\":false, \"is_pointer\":false}. size 1/2/4/8/16 (16=SIMD, shown as _lo/_hi pair). offset from rf_base_reg (or ctx_base_reg). Enables VM register panel."}}},
              {"rf_base_reg",          {{"type", "string"},  {"description", "Hint: host register holding VM register-file base pointer (overrides ctx_base_reg for RF reads). E.g. 'x20'."}}},
              // ── VM stack ──
              {"vm_stack_sp_offset",   {{"type", "integer"}, {"description", "Hint: byte offset within vm_ctx/rf_base where VM stack pointer lives. Enables stack panel (can coexist with vm_registers for mixed-type VMs)."}}},
              {"vm_stack_depth",       {{"type", "integer"}, {"description", "Hint: stack slots visible in VM stack panel (default 8)."}}},
              {"vm_stack_elem_size",   {{"type", "integer"}, {"description", "Hint: VM stack element size in bytes (1/2/4/8, default 8)."}}},
              {"vm_stack_direction",   {{"type", "string"},  {"description", "Hint: stack growth direction: 'descending' (default, SP=TOS, slot_i=SP+i*elem) or 'ascending' (SP=next-free, slot_i=SP-(i+1)*elem)."}}},
              // ── Handler asm ──
              {"handler_asm_map",      {{"type", "object"},  {"description", "Hint: static disassembly for handler bodies. Keys = handler static PC (hex string), values = array of {\"pc\": \"0x...\", \"text\": \"...\"}. Enables annotated asm in VM instruction panel."}}},
              // ── Misc ──
              {"hints_file",           {{"type", "string"},  {"description", "Path to a JSON file containing any/all of the above hints. Merged with inline args (inline args take priority). JSON keys match arg names."}}},
              {"auto_detect",          {{"type", "boolean"}, {"description", "Explicitly opt into the heuristic dispatcher auto-detection (loop iteration count + indirect-branch shape) when NO static hint is provided. This heuristic has a very high false-positive/false-negative rate on real traces and is DISABLED by default — you should almost always supply at least 'dispatcher_pc' (or another hint) from IDA/Ghidra static analysis instead of relying on this."}, {"default", false}}},
              {"force_rerun",          {{"type", "boolean"}, {"description", "Force re-run even if a cached result exists (use when hints have changed)"}, {"default", false}}},
              {"steps_offset",         {{"type", "integer"}, {"description", "Pagination: skip first N VM steps"}, {"default", 0}}},
              {"steps_limit",          {{"type", "integer"}, {"description", "Pagination: max VM steps per page (max 2000)"}, {"default", 500}}}
          }}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            VMConfig cfg;

            // ── hints_file: load JSON file and merge with inline args ──────────
            // File values are the base; inline args override them. Loaded up
            // front so that EVERY hint field below (dispatcher_pc, vm_pc_reg,
            // opcode format, ctx_base_reg, ...) can come from either source —
            // this makes "hints_file only, no inline args" a fully supported
            // usage pattern, which matters now that hints are required.
            json file_hints = json::object();
            if (args.contains("hints_file")) {
                std::string hpath = args["hints_file"].get<std::string>();
                std::ifstream hf(hpath);
                if (hf.good()) {
                    try { hf >> file_hints; }
                    catch (...) { file_hints = json::object(); }
                }
            }
            // Merge: file_hints is base, args override
            auto get_hint = [&](const char* key) -> const json* {
                if (args.contains(key)) return &args.at(key);
                if (file_hints.contains(key)) return &file_hints.at(key);
                return nullptr;
            };

            // Auto-detection is opt-in only (see tool description): the pure
            // heuristic has a very high false-positive/false-negative rate on
            // real traces. Default false; gated/checked again below once all
            // hints have been merged in.
            {
                const json* ad = get_hint("auto_detect");
                cfg.auto_detect = ad ? ad->get<bool>() : false;
            }

            // ── Static hints from IDA ── (inline args OR hints_file)
            //
            // dispatcher_pc / indirect_branch_pc: normally both describe a
            // classic loop-based dispatcher (loop_header_pc + the BR/BLR that
            // selects handlers). But indirect_branch_pc is also meaningful on
            // its own for dispatch_type=ThreadedCode, where there is no real
            // loop header — it just tells the ThreadedCollector which PC(s)
            // mark "handler selected, next instruction is the new handler
            // entry". So construct a DispatcherHint (loop_header_pc left 0)
            // even when only indirect_branch_pc is present.
            {
                const json* dp  = get_hint("dispatcher_pc");
                const json* ibp = get_hint("indirect_branch_pc");
                const json* maa = get_hint("mem_anchor_addr");
                const json* mas = get_hint("mem_anchor_size");
                if (dp || ibp || maa) {
                    DispatcherHint dh;
                    if (dp)  dh.loop_header_pc     = unrebase(parse_hex(dp->get<std::string>()));
                    if (ibp) dh.indirect_branch_pc = unrebase(parse_hex(ibp->get<std::string>()));
                    // mem_anchor_addr is a runtime address (already has ASLR slide)
                    if (maa) dh.mem_anchor_addr = parse_hex(maa->get<std::string>());
                    if (mas) dh.mem_anchor_size = static_cast<uint8_t>(mas->get<int>());
                    cfg.dispatcher = dh;
                }
            }

            if (const json* hep = get_hint("handler_entry_pcs")) {
                for (const auto& pc_str : *hep) {
                    cfg.handler_entry_pcs.push_back(unrebase(parse_hex(pc_str.get<std::string>())));
                }
            }

            // ── Dispatch topology ─────────────────────────────────────────
            if (const json* dt_j = get_hint("dispatch_type")) {
                const std::string& dt = dt_j->get_ref<const std::string&>();
                if      (dt == "WhileSwitch")    cfg.dispatch_type_hint = DispatchType::WhileSwitch;
                else if (dt == "IndirectBranch") cfg.dispatch_type_hint = DispatchType::IndirectBranch;
                else if (dt == "CallTable")      cfg.dispatch_type_hint = DispatchType::CallTable;
                else if (dt == "ThreadedCode")   cfg.dispatch_type_hint = DispatchType::ThreadedCode;
                else if (dt == "Trampoline")     cfg.dispatch_type_hint = DispatchType::Trampoline;
                else if (dt == "FetchOnly")      cfg.dispatch_type_hint = DispatchType::FetchOnly;
            }
            if (const json* tdp = get_hint("threaded_dispatch_pcs")) {
                for (const auto& pc_str : *tdp) {
                    // Runtime addresses: apply rebase (user passes static PC, we add slide)
                    cfg.threaded_dispatch_pcs.push_back(
                        unrebase(parse_hex(pc_str.get<std::string>())));
                }
            }

            if (const json* vpr = get_hint("vm_pc_reg")) {
                VMPCHint vph;
                vph.reg = parse_reg(*vpr);
                if (const json* bb = get_hint("bytecode_base")) {
                    vph.bytecode_base = parse_hex(bb->get<std::string>());
                }
                cfg.vm_pc = vph;
            }

            // ── Opcode format / deobfuscation ──────────────────────────────
            // Construct OpcodeFormatHint when any of the opcode-related hints is present.
            {
                const json* op_size   = get_hint("opcode_size");
                const json* op_reg    = get_hint("opcode_from_reg");
                const json* op_deobf  = get_hint("opcode_deobf_steps");
                const json* op_offset = get_hint("opcode_byte_offset");
                const json* op_mask   = get_hint("opcode_mask");
                const json* op_shift  = get_hint("opcode_shift");

                if (op_size || op_reg || op_deobf || op_offset) {
                    OpcodeFormatHint ofh;

                    // Mode B: register snapshot
                    if (op_reg) {
                        ofh.opcode_from_reg = parse_reg(*op_reg);
                    }

                    // Mode A fields (ignored when opcode_from_reg is set)
                    if (op_size) {
                        ofh.opcode_size = static_cast<uint8_t>(op_size->get<int>());
                    }
                    if (op_offset) {
                        ofh.opcode_byte_offset = static_cast<uint8_t>(op_offset->get<int>());
                    }
                    if (op_mask) {
                        ofh.opcode_mask = parse_hex(op_mask->get<std::string>());
                    }
                    ofh.opcode_shift = static_cast<uint8_t>(op_shift ? op_shift->get<int>() : 0);

                    // Deobfuscation step sequence
                    if (op_deobf) {
                        // Helper: parse op name string to enum
                        auto parse_op = [](const std::string& s) -> OpcodeDeobfStep::Op {
                            if (s == "sub")   return OpcodeDeobfStep::Op::sub;
                            if (s == "add")   return OpcodeDeobfStep::Op::add;
                            if (s == "xor")   return OpcodeDeobfStep::Op::xor_;
                            if (s == "and")   return OpcodeDeobfStep::Op::and_;
                            if (s == "or")    return OpcodeDeobfStep::Op::or_;
                            if (s == "lsr")   return OpcodeDeobfStep::Op::lsr;
                            if (s == "lsl")   return OpcodeDeobfStep::Op::lsl;
                            if (s == "mul")   return OpcodeDeobfStep::Op::mul;
                            if (s == "ror")   return OpcodeDeobfStep::Op::ror;
                            if (s == "bswap") return OpcodeDeobfStep::Op::bswap;
                            if (s == "neg")   return OpcodeDeobfStep::Op::neg;
                            if (s == "not")   return OpcodeDeobfStep::Op::not_;
                            throw std::runtime_error("Unknown deobf op: " + s);
                        };

                        for (const auto& elem : *op_deobf) {
                            OpcodeDeobfStep ds;
                            ds.op = parse_op(elem.at("op").get<std::string>());
                            // imm may be integer or hex string (or absent for neg/not)
                            if (elem.contains("imm")) {
                                if (elem.at("imm").is_number()) {
                                    ds.imm = elem["imm"].get<uint64_t>();
                                } else {
                                    ds.imm = parse_hex(elem["imm"].get<std::string>());
                                }
                            }
                            ofh.deobfuscation_steps.push_back(ds);
                        }
                    }

                    cfg.opcode_format = std::move(ofh);
                }
            }

            if (const json* cbr = get_hint("ctx_base_reg")) {
                VMContextHint vch;
                vch.ctx_base_reg = parse_reg(*cbr);
                cfg.vm_context = vch;
            }

            // ── VM Context fields hint (merged with ctx_base_reg above) ──────
            {
                const json* ctx_fields_j = get_hint("ctx_fields");
                if (ctx_fields_j && ctx_fields_j->is_array()) {
                    // Ensure we have a VMContextHint object (may already exist)
                    if (!cfg.vm_context.has_value()) {
                        cfg.vm_context = VMContextHint{};
                    }
                    for (const auto& cf : *ctx_fields_j) {
                        VMContextHint::Field field;
                        field.name       = cf.value("name", std::string{});
                        field.offset     = cf.value("offset", uint32_t(0));
                        field.size       = static_cast<uint8_t>(cf.value("size", 8));
                        field.is_pointer = cf.value("is_pointer", false);
                        if (!field.name.empty())
                            cfg.vm_context->fields.push_back(std::move(field));
                    }
                }
            }

            // ── VM Register File hint ─────────────────────────────────────────
            {
                const json* vm_regs_j  = get_hint("vm_registers");
                const json* rf_base_j  = get_hint("rf_base_reg");
                const json* sp_off_j   = get_hint("vm_stack_sp_offset");
                const json* sp_dep_j   = get_hint("vm_stack_depth");
                const json* sp_elem_j  = get_hint("vm_stack_elem_size");
                const json* sp_dir_j   = get_hint("vm_stack_direction");

                if (vm_regs_j || rf_base_j || sp_off_j) {
                    VMRegisterFileHint rfh;

                    if (rf_base_j)
                        rfh.rf_base_reg = parse_reg(*rf_base_j);

                    if (vm_regs_j) {
                        for (const auto& rv : *vm_regs_j) {
                            VMRegisterFileHint::VMReg vreg;
                            vreg.name       = rv.value("name", std::string{});
                            vreg.offset     = rv.value("offset", uint32_t(0));
                            vreg.size       = static_cast<uint8_t>(rv.value("size", 8));
                            vreg.is_float   = rv.value("is_float", false);
                            vreg.is_pointer = rv.value("is_pointer", false);
                            if (!vreg.name.empty())
                                rfh.regs.push_back(std::move(vreg));
                        }
                    }

                    if (sp_off_j)
                        rfh.stack_sp_offset = sp_off_j->get<uint32_t>();
                    if (sp_dep_j)
                        rfh.stack_depth = sp_dep_j->get<uint32_t>();
                    if (sp_elem_j)
                        rfh.stack_elem_size = static_cast<uint8_t>(sp_elem_j->get<int>());
                    if (sp_dir_j && sp_dir_j->is_string()) {
                        const std::string& dir = sp_dir_j->get_ref<const std::string&>();
                        if (dir == "ascending") {
                            rfh.stack_direction = VMRegisterFileHint::StackDirection::Ascending;
                        }
                        // "descending" is the default; no action needed
                    }

                    cfg.vm_register_file = std::move(rfh);
                }
            }

            // ── Handler ASM map ───────────────────────────────────────────────
            {
                const json* asm_j = get_hint("handler_asm_map");
                if (asm_j && asm_j->is_object()) {
                    HandlerAsmHint hah;
                    (void)0;  // static PCs stored as-is; slide handled by UI
                    for (auto& [pc_str, lines] : asm_j->items()) {
                        // Key is static hex PC string
                        uint64_t static_pc = parse_hex(pc_str);
                        // Store as static PC (no slide applied — UI adds slide)
                        std::vector<HandlerAsmEntry> entries;
                        if (lines.is_array()) {
                            for (const auto& line : lines) {
                                HandlerAsmEntry e;
                                if (line.is_string()) {
                                    // Shorthand: just the asm text, no pc
                                    e.pc   = 0;
                                    e.text = line.get<std::string>();
                                } else {
                                    // Full form: {"pc": "0x...", "text": "..."}
                                    if (line.contains("pc"))
                                        e.pc = parse_hex(line["pc"].get<std::string>());
                                    e.text = line.value("text", std::string{});
                                }
                                if (!e.text.empty())
                                    entries.push_back(std::move(e));
                            }
                        }
                        hah.handler_asm[static_pc] = std::move(entries);
                    }
                    cfg.handler_asm = std::move(hah);
                }
            }

            // ── Require at least one static hint (or explicit auto_detect opt-in) ──
            // The heuristic dispatcher auto-detection has a very high false-
            // positive/false-negative rate on real traces, so it must not run
            // silently. Fail loudly and tell the caller what to do instead.
            if (!cfg.has_any_static_hint() && !cfg.auto_detect) {
                throw std::runtime_error(
                    "vm_abstract requires at least one static-analysis hint "
                    "(e.g. 'dispatcher_pc' from IDA/Ghidra static analysis, or "
                    "'hints_file' pointing to a JSON hints file). The heuristic "
                    "dispatcher auto-detection is disabled by default because it "
                    "has a very high false-positive/false-negative rate on real "
                    "traces. Pass auto_detect=true to explicitly opt into it "
                    "anyway (not recommended).");
            }

            // ── Run the pass ──
            // force_rerun: explicitly requested re-run with new hints.
            // Only invalidate when explicitly requested (not on every hint call)
            // to avoid a reset → run → reset → run loop.
            bool force_rerun = args.value("force_rerun", false);
            if (force_rerun) {
                auto cur_state = pm_->state("vm_abstract");
                if (cur_state == PassManager::PassState::Completed) {
                    pm_->invalidate_and_clear_blob("vm_abstract");
                }
            }

            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            tenet::register_pass_by_name(*pm_, "loop");
            pm_->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));
            const auto& result = require_pass<VMAbstractResult>(pm_, "vm_abstract", "VM abstract pass failed");

            // ── Build response ──
            json output;

            // Dispatcher info
            output["dispatcher"] = {
                {"loop_header_pc",     fmt::format("0x{:X}", rebase(result.dispatcher.loop_header_pc))},
                {"indirect_branch_pc", fmt::format("0x{:X}", rebase(result.dispatcher.indirect_branch_pc))},
                {"dispatch_type",      dispatch_type_name(result.dispatcher.dispatch_type)},
                {"iteration_count",    result.dispatcher.iteration_count},
                {"confidence",         result.dispatcher.confidence}
            };

            // State registers
            {
                json state_regs_arr = json::array();
                for (uint8_t r : result.dispatcher.state_regs) {
                    state_regs_arr.push_back(kRegNames[r]);
                }
                output["dispatcher"]["state_regs"] = std::move(state_regs_arr);
            }

            // Architecture
            output["arch_type"] = vm_arch_name(result.arch_type);
            if (result.vm_pc_reg != 0xFF) {
                output["vm_pc_reg"] = std::string(kRegNames[result.vm_pc_reg]);
            }
            if (result.bytecode_base != 0) {
                output["bytecode_range"] = {
                    {"start", fmt::format("0x{:X}", result.bytecode_base)},
                    {"end",   fmt::format("0x{:X}", result.bytecode_end)}
                };
            }

            // Handlers
            json handlers_arr = json::array();
            for (const auto& h : result.handlers) {
                json hj = {
                    {"entry_pc",        fmt::format("0x{:X}", rebase(h.entry_pc))},
                    {"execution_count", h.execution_count},
                    {"label",           h.label}
                };
                if (!h.opcode_values.empty()) {
                    json opcodes = json::array();
                    for (auto ov : h.opcode_values) opcodes.push_back(fmt::format("0x{:X}", ov));
                    hj["opcode_values"] = std::move(opcodes);
                }
                handlers_arr.push_back(std::move(hj));
            }
            output["handlers"] = std::move(handlers_arr);
            output["handler_count"] = result.handlers.size();

            // VM execution steps (paginated)
            size_t steps_offset = args.value("steps_offset", size_t(0));
            size_t steps_limit = std::min(args.value("steps_limit", size_t(500)), size_t(2000));
            size_t steps_start = std::min(steps_offset, result.steps.size());
            size_t steps_end = std::min(steps_start + steps_limit, result.steps.size());

            json steps_arr = json::array();
            for (size_t i = steps_start; i < steps_end; i++) {
                const auto& s = result.steps[i];
                json sj = {
                    {"inst_id_start",   s.inst_id_start},
                    {"inst_id_end",     s.inst_id_end},
                    {"handler_entry_pc", fmt::format("0x{:X}", rebase(s.handler_entry_pc))}
                };
                if (s.opcode_valid) sj["opcode"] = fmt::format("0x{:X}", s.opcode_value);
                if (s.vm_pc_valid) sj["vm_pc"] = fmt::format("0x{:X}", s.vm_pc_value);

                // Add handler label if available
                const VMHandler* handler = result.handler_at(s.handler_entry_pc);
                if (handler && !handler->label.empty()) sj["label"] = handler->label;

                steps_arr.push_back(std::move(sj));
            }
            output["steps"] = std::move(steps_arr);
            output["total_vm_steps"] = result.total_vm_steps;
            output["steps_offset"] = steps_offset;
            output["steps_returned"] = steps_end - steps_start;
            bool has_more_steps = steps_end < result.steps.size();
            output["has_more_steps"] = has_more_steps;
            if (has_more_steps) output["next_steps_offset"] = steps_end;

            // Statistics
            output["total_native_instructions"] = result.total_native_instructions;

            return output;
        }
    );
}

}  // namespace tenet
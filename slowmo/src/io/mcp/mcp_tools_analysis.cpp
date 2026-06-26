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

#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/passes/symbol_annotation_pass.h"
#include "analysis/passes/memory_snapshot_pass.h"
#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/syscall_intercept_pass.h"
#include "analysis/passes/taint_source_annotation_pass.h"
#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/trace_diff_pass.h"
#include "analysis/passes/reg_timeline_pass.h"
#include "analysis/passes/mem_search_pass.h"
#include "analysis/passes/call_context_pass.h"
#include "analysis/passes/producer_chain_pass.h"
#include "analysis/passes/window_stats_pass.h"
#include "analysis/passes/entropy_pass.h"
#include "analysis/passes/literal_search_pass.h"

#include <fmt/core.h>

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
            pm_->register_pass(std::make_unique<PatternPass>());
            const auto& result = require_pass<PatternResult>(pm_, "pattern", "Pattern pass failed");

            json matches = json::array();
            for (const auto& m : result.matches) {
                matches.push_back({
                    {"pattern_name",  m.pattern_name},
                    {"category",      pattern_category_str(m.category)},
                    {"confidence",    pattern_confidence_str(m.confidence)},
                    {"start_inst_id", m.start_inst_id},
                    {"end_inst_id",   m.end_inst_id},
                    {"anchor_pc",     fmt::format("0x{:X}", m.anchor_pc)},
                    {"description",   m.description}
                });
            }
            return {{"total", result.total()}, {"matches", std::move(matches)}};
        }
    );

    // ── strings_scan ──────────────────────────────────────────────────────
    register_tool(
        {"strings_scan",
         "Discover printable strings in traced memory accesses.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<StringPass>());
            const auto& result = require_pass<StringResult>(pm_, "strings", "String pass failed");

            json strings = json::array();
            size_t limit = std::min(result.strings.size(), size_t(500));
            for (size_t i = 0; i < limit; i++) {
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
            return {{"total", result.total()}, {"strings", std::move(strings)},
                    {"truncated", result.strings.size() > limit}};
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
            auto pass = std::make_unique<ConstantMaterializationPass>();
            pass->set_min_parts(args.value("min_parts", uint8_t(2)));
            pm_->register_pass(std::move(pass));
            const auto& result = require_pass<ConstantMaterializationResult>(pm_, "constant_materialization", "Constants pass failed");

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
            pm_->register_pass(std::make_unique<XrefPass>());
            pm_->register_pass(std::make_unique<CFGPass>());
            pm_->register_pass(std::make_unique<LoopPass>());
            pm_->register_pass(std::make_unique<LoopSemanticsPass>());
            const auto& result = require_pass<LoopSemanticsResult>(pm_, "loop_semantics", "Loop semantics failed");

            json loops = json::array();
            for (const auto& l : result.loop_semantics) {
                loops.push_back({
                    {"pc", fmt::format("0x{:X}", l.header_pc)},
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
            pm_->register_pass(std::make_unique<XrefPass>());
            pm_->register_pass(std::make_unique<CFGPass>());
            pm_->register_pass(std::make_unique<PatternPass>());
            pm_->register_pass(std::make_unique<ConstantMaterializationPass>());
            pm_->register_pass(std::make_unique<LoopPass>());
            pm_->register_pass(std::make_unique<LoopSemanticsPass>());
            pm_->register_pass(std::make_unique<FunctionPass>());
            pm_->register_pass(std::make_unique<CallGraphPass>());
            pm_->register_pass(std::make_unique<AlgorithmSummaryPass>());
            const auto& result = require_pass<AlgorithmSummaryResult>(pm_, "algorithm_summary", "Algorithm summary failed");
            return result.summary_json;
        }
    );

    // ── objc_messages ─────────────────────────────────────────────────────
    register_tool(
        {"objc_messages",
         "Analyze Objective-C message sends (objc_msgSend calls) in the "
         "trace. Returns class names, selectors, arguments, and return values.",
         {{"type", "object"},
          {"properties", {
              {"class_filter", {{"type", "string"}, {"description", "Filter by class name (optional)"}}}
          }}}},
        [this](const json& args) -> json {
            auto pass = std::make_unique<ObjcPass>();
            if (args.contains("class_filter")) {
                pass->set_class_filter(args["class_filter"].get<std::string>());
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
         "indicators, constant markers, pattern identifiers).",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<XrefPass>());
            pm_->register_pass(std::make_unique<CFGPass>());
            pm_->register_pass(std::make_unique<FunctionPass>());
            pm_->register_pass(std::make_unique<LoopPass>());
            pm_->register_pass(std::make_unique<ConstantMaterializationPass>());
            pm_->register_pass(std::make_unique<PatternPass>());
            pm_->register_pass(std::make_unique<SymbolAnnotationPass>());
            const auto& result = require_pass<AnnotationResult>(pm_, "symbol_annotation", "Annotation pass failed");

            json annotations = json::array();
            size_t count = 0;
            for (const auto& [pc, anns] : result.by_pc) {
                if (count >= 1000) break;
                for (const auto& a : anns) {
                    annotations.push_back({
                        {"pc", fmt::format("0x{:X}", pc)},
                        {"label", a.label},
                        {"detail", a.detail},
                        {"kind", static_cast<int>(a.kind)}
                    });
                }
                count++;
            }
            return {{"total_pcs", result.by_pc.size()},
                    {"annotations", std::move(annotations)},
                    {"truncated", result.by_pc.size() > 1000}};
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
            pm_->register_pass(std::make_unique<ObjcPass>());
            pm_->register_pass(std::make_unique<ConstantMaterializationPass>());
            pm_->register_pass(std::make_unique<PatternPass>());
            pm_->register_pass(std::make_unique<ObjcCryptoPass>());
            const auto& result = require_pass<ObjcCryptoResult>(pm_, "objc_crypto", "ObjC crypto failed");
            return json::parse(result.to_json());
        }
    );

    // ── syscall_intercept ─────────────────────────────────────────────────
    register_tool(
        {"syscall_intercept",
         "Extract iOS system API call parameters (CommonCrypto, "
         "Security.framework, CryptoKit). Captures key material, "
         "IV, input/output data from crypto API calls.",
         {{"type", "object"},
          {"properties", {
              {"capture_bytes", {{"type", "integer"}, {"description", "Bytes per pointer arg"}, {"default", 64}}}
          }}}},
        [this](const json& args) -> json {
            SyscallInterceptConfig cfg;
            cfg.capture_bytes = args.value("capture_bytes", uint32_t(64));
            pm_->register_pass(std::make_unique<ObjcPass>());
            pm_->register_pass(std::make_unique<SyscallInterceptPass>(std::move(cfg)));
            const auto& result = require_pass<SyscallInterceptResult>(pm_, "syscall_intercept", "Syscall intercept failed");
            return json::parse(result.to_json());
        }
    );

    // ── taint_source_annotation ───────────────────────────────────────────
    register_tool(
        {"taint_source_annotation",
         "Auto-detect potential taint sources in the trace. Identifies "
         "function entry parameters, ObjC method arguments, memory-mapped "
         "I/O, and other common source points.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<ObjcPass>());
            pm_->register_pass(std::make_unique<FunctionPass>());
            pm_->register_pass(std::make_unique<TaintSourceAnnotationPass>());
            const auto& result = require_pass<TaintSourceAnnotationResult>(pm_, "taint_source_annotation", "Taint source annotation failed");
            return json::parse(result.to_json());
        }
    );

    // ── trace_fold ────────────────────────────────────────────────────────
    register_tool(
        {"trace_fold",
         "Fold (compress) the trace by merging repeated call sequences. "
         "Shows a high-level summary of function call patterns and their "
         "repetition counts.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<XrefPass>());
            pm_->register_pass(std::make_unique<CFGPass>());
            pm_->register_pass(std::make_unique<LoopPass>());
            pm_->register_pass(std::make_unique<FunctionPass>());
            pm_->register_pass(std::make_unique<TraceFoldPass>());
            const auto& result = require_pass<TraceFoldResult>(pm_, "trace_fold", "Trace fold failed");

            json regions = json::array();
            size_t limit = std::min(result.folded_regions.size(), size_t(500));
            for (size_t i = 0; i < limit; i++) {
                const auto& r = result.folded_regions[i];
                regions.push_back({
                    {"header_pc", fmt::format("0x{:X}", r.header_pc)},
                    {"total_iterations", r.total_iterations},
                    {"instructions_per_iteration", r.instructions_per_iteration},
                    {"total_instructions_folded", r.total_instructions_folded},
                    {"inst_range", {r.first_inst_id, r.last_inst_id}}
                });
            }
            return {{"total_regions", result.folded_regions.size()},
                    {"original_inst_count", result.original_inst_count},
                    {"folded_inst_count", result.folded_inst_count},
                    {"compression_ratio", result.compression_ratio},
                    {"regions", std::move(regions)},
                    {"truncated", result.folded_regions.size() > limit}};
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
                    {"pc", fmt::format("0x{:X}", m.pc)},
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
         "of (inst_id, pc, old_value, new_value) entries for the specified register.",
         {{"type", "object"},
          {"properties", {
              {"reg_index",     {{"type", "integer"}, {"description", "Register index (0-33)"}}},
              {"start_inst_id", {{"type", "integer"}, {"description", "Start from this instruction"}, {"default", 0}}},
              {"end_inst_id",   {{"type", "integer"}, {"description", "End at this instruction (0=end)"}, {"default", 0}}},
              {"limit",         {{"type", "integer"}, {"description", "Max timeline entries"}, {"default", 200}}}
          }},
          {"required", json::array({"reg_index"})}}},
        [this](const json& args) -> json {
            RegTimelineConfig cfg;
            cfg.target_reg = args.at("reg_index").get<uint8_t>();
            cfg.start_inst_id = args.value("start_inst_id", uint64_t(0));
            cfg.end_inst_id = args.value("end_inst_id", uint64_t(0));
            cfg.max_entries = args.value("limit", uint64_t(200));

            pm_->register_pass(std::make_unique<RegTimelinePass>(std::move(cfg)));
            const auto& result = require_pass<RegTimelineResult>(pm_, "reg_timeline", "Reg timeline failed");

            json timeline = json::array();
            for (const auto& e : result.entries) {
                timeline.push_back({
                    {"inst_id", e.inst_id},
                    {"pc",  fmt::format("0x{:X}", e.pc)},
                    {"old", fmt::format("0x{:X}", e.old_value)},
                    {"new", fmt::format("0x{:X}", e.new_value)}
                });
            }
            return {{"reg", kRegNames[cfg.target_reg]},
                    {"total_writes", result.total_writes},
                    {"timeline", std::move(timeline)},
                    {"entry_count", result.entries.size()}};
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
                    {"pc",       fmt::format("0x{:X}", h.pc)},
                    {"source",   src},
                    {"matched_value", fmt::format("0x{:X}", h.matched_value)}
                });
            }
            return {{"total", result.hits.size()},
                    {"instructions_scanned", result.instructions_scanned},
                    {"hits", std::move(hits)}};
        }
    );

    // ── producer_chain ────────────────────────────────────────────────────
    register_tool(
        {"producer_chain",
         "Find the chain of producers for a register at a given instruction. "
         "Walks backward through register assignments and memory loads to "
         "build a compact chain showing where the value originated.",
         {{"type", "object"},
          {"properties", {
              {"inst_id",   {{"type", "integer"}, {"description", "Instruction ID to start from"}}},
              {"reg_index", {{"type", "integer"}, {"description", "Register index"}}},
              {"max_depth", {{"type", "integer"}, {"description", "Max chain depth"}, {"default", 20}}}
          }},
          {"required", json::array({"inst_id", "reg_index"})}}},
        [this](const json& args) -> json {
            ProducerChainConfig cfg;
            cfg.start_inst_id = args.at("inst_id").get<uint64_t>();
            cfg.start_reg = args.at("reg_index").get<uint8_t>();
            cfg.max_depth = args.value("max_depth", uint32_t(20));

            pm_->register_pass(std::make_unique<ProducerChainPass>(std::move(cfg)));
            const auto& result = require_pass<ProducerChainResult>(pm_, "producer_chain", "Producer chain failed");

            json chain = json::array();
            for (const auto& link : result.chain) {
                json lk = {
                    {"inst_id", link.inst_id},
                    {"pc",      fmt::format("0x{:X}", link.pc)},
                    {"produced_reg", link.produced_reg},
                    {"value", fmt::format("0x{:X}", link.value)},
                    {"is_memory_load", link.is_memory_load}
                };
                if (!link.disassembly.empty()) lk["disassembly"] = link.disassembly;
                if (link.mem_addr != 0) lk["mem_addr"] = fmt::format("0x{:X}", link.mem_addr);
                chain.push_back(std::move(lk));
            }
            return {{"depth", result.chain.size()},
                    {"chain", std::move(chain)},
                    {"truncated", result.truncated}};
        }
    );

    // ── call_context ──────────────────────────────────────────────────────
    register_tool(
        {"call_context",
         "Show the function call context (call stack) at a given instruction.",
         {{"type", "object"},
          {"properties", {
              {"inst_id", {{"type", "integer"}, {"description", "Instruction ID"}}}
          }},
          {"required", json::array({"inst_id"})}}},
        [this](const json& args) -> json {
            CallContextConfig cfg;
            cfg.target_inst_id = args.at("inst_id").get<uint64_t>();

            pm_->register_pass(std::make_unique<XrefPass>());
            pm_->register_pass(std::make_unique<CFGPass>());
            pm_->register_pass(std::make_unique<LoopPass>());
            pm_->register_pass(std::make_unique<FunctionPass>());
            pm_->register_pass(std::make_unique<CallContextPass>(std::move(cfg)));
            const auto& result = require_pass<CallContextResult>(pm_, "call_context", "Call context failed");

            json frames = json::array();
            for (const auto& f : result.call_stack) {
                frames.push_back({
                    {"call_site_pc", fmt::format("0x{:X}", f.call_site_pc)},
                    {"callee_pc",    fmt::format("0x{:X}", f.callee_pc)},
                    {"call_inst_id", f.call_inst_id},
                    {"return_addr",  fmt::format("0x{:X}", f.return_addr)}
                });
            }
            return {{"target_inst_id", result.target_inst_id},
                    {"target_pc", fmt::format("0x{:X}", result.target_pc)},
                    {"call_stack_depth", result.call_stack.size()},
                    {"call_stack", std::move(frames)}};
        }
    );

    // ── window_stats ──────────────────────────────────────────────────────
    register_tool(
        {"window_stats",
         "Compute instruction-mix statistics over a window of instructions. "
         "Counts branches, loads, stores, arithmetic, crypto ops, etc.",
         {{"type", "object"},
          {"properties", {
              {"start_inst_id", {{"type", "integer"}, {"description", "Start instruction ID"}, {"default", 0}}},
              {"end_inst_id",   {{"type", "integer"}, {"description", "End instruction ID (0=end)"}, {"default", 0}}},
              {"window_size",   {{"type", "integer"}, {"description", "Sliding window size"}, {"default", 1000}}}
          }}}},
        [this](const json& args) -> json {
            WindowStatsConfig cfg;
            cfg.window_size = args.value("window_size", uint64_t(1000));

            pm_->register_pass(std::make_unique<WindowStatsPass>(std::move(cfg)));
            const auto& result = require_pass<WindowStatsResult>(pm_, "window_stats", "Window stats failed");

            json windows = json::array();
            size_t limit = std::min(result.windows.size(), size_t(100));
            for (size_t i = 0; i < limit; i++) {
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
            return {{"total_windows", result.total_windows},
                    {"window_size", result.window_size},
                    {"windows", std::move(windows)},
                    {"truncated", result.windows.size() > limit}};
        }
    );

    // ── entropy_analysis ──────────────────────────────────────────────────
    register_tool(
        {"entropy_analysis",
         "Compute Shannon entropy over memory write patterns. High-entropy "
         "regions often indicate encryption or compression output.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<EntropyPass>());
            const auto& result = require_pass<EntropyResult>(pm_, "entropy", "Entropy failed");

            json blocks_arr = json::array();
            size_t limit = std::min(result.blocks.size(), size_t(100));
            for (size_t i = 0; i < limit; i++) {
                const auto& b = result.blocks[i];
                blocks_arr.push_back({
                    {"offset",  b.offset},
                    {"size",    b.size},
                    {"entropy", b.entropy},
                    {"is_known", b.is_known}
                });
            }
            const char* cls_names[] = {"Unknown", "Plaintext", "Compressed", "Encrypted", "KeyMaterial"};
            return {{"addr", fmt::format("0x{:X}", result.addr)},
                    {"overall_entropy", result.overall_entropy},
                    {"classification", cls_names[static_cast<int>(result.classification)]},
                    {"region_size", result.region_size},
                    {"known_bytes", result.known_bytes},
                    {"blocks", std::move(blocks_arr)},
                    {"truncated", result.blocks.size() > limit}};
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
         "names (if available), instruction ranges, and call counts.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<FunctionPass>());
            const auto& result = require_pass<FunctionResult>(pm_, "function", "Function pass failed");

            json funcs = json::array();
            for (const auto& [pc, info] : result.functions) {
                funcs.push_back({
                    {"pc",          fmt::format("0x{:X}", info.entry_pc)},
                    {"name",        info.name},
                    {"total_calls", info.total_calls},
                    {"total_instructions", info.total_instructions}
                });
            }
            return {{"total", result.functions.size()}, {"functions", std::move(funcs)}};
        }
    );

    // ── loops ─────────────────────────────────────────────────────────────
    register_tool(
        {"loops",
         "Detect loops in the trace. Returns loop header PCs, iteration "
         "counts, body sizes, and nesting information.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            pm_->register_pass(std::make_unique<XrefPass>());
            pm_->register_pass(std::make_unique<CFGPass>());
            pm_->register_pass(std::make_unique<LoopPass>());
            const auto& result = require_pass<LoopResult>(pm_, "loop", "Loop pass failed");

            json loops = json::array();
            for (const auto& l : result.loops) {
                loops.push_back({
                    {"header_pc",       fmt::format("0x{:X}", l.header_pc)},
                    {"back_edge_pc",    fmt::format("0x{:X}", l.back_edge_pc)},
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
            pm_->register_pass(std::make_unique<XrefPass>());
            const auto& xref = require_pass<XrefResult>(pm_, "xref", "XRef pass failed");

            size_t top_n = args.value("top_n", 20);
            auto hot = xref.hottest(top_n);
            json hot_arr = json::array();
            for (const auto& [pc, count] : hot) {
                hot_arr.push_back({
                    {"pc",    fmt::format("0x{:X}", pc)},
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
         "iterations or comparing function calls.",
         {{"type", "object"},
          {"properties", {
              {"range_a_start", {{"type", "integer"}, {"description", "First range start inst_id"}}},
              {"range_a_end",   {{"type", "integer"}, {"description", "First range end inst_id"}}},
              {"range_b_start", {{"type", "integer"}, {"description", "Second range start inst_id"}}},
              {"range_b_end",   {{"type", "integer"}, {"description", "Second range end inst_id"}}}
          }},
          {"required", json::array({"range_a_start", "range_a_end", "range_b_start", "range_b_end"})}}},
        [this](const json& args) -> json {
            TraceDiffConfig cfg;
            cfg.trace_a_start = args.at("range_a_start").get<uint64_t>();
            cfg.trace_a_end   = args.at("range_a_end").get<uint64_t>();
            cfg.trace_b_start = args.at("range_b_start").get<uint64_t>();
            cfg.trace_b_end   = args.at("range_b_end").get<uint64_t>();

            pm_->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));
            const auto& result = require_pass<TraceDiffResult>(pm_, "trace_diff", "Trace diff failed");

            json diffs_arr = json::array();
            size_t limit = std::min(result.diffs.size(), size_t(200));
            for (size_t i = 0; i < limit; i++) {
                const auto& d = result.diffs[i];
                diffs_arr.push_back({
                    {"pc", fmt::format("0x{:X}", d.pc)},
                    {"inst_offset_a", d.inst_offset_a},
                    {"inst_offset_b", d.inst_offset_b},
                    {"type", static_cast<int>(d.type)},
                    {"detail", d.detail}
                });
            }
            return {{"diffs", std::move(diffs_arr)},
                    {"matched_count", result.matched_count},
                    {"diverged_count", result.diverged_count},
                    {"has_divergence", result.has_divergence()},
                    {"truncated", result.diffs.size() > limit}};
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
            pm_->register_pass(std::make_unique<FunctionPass>());
            pm_->register_pass(std::make_unique<XrefPass>());
            const auto& fn_result = require_pass<FunctionResult>(pm_, "function", "Function pass failed");

            // XRef for inst_id lookup
            bool has_xref = false;
            const XrefResult* xref = nullptr;
            const auto& xref_raw = pm_->require("xref");
            if (xref_raw.ok()) { xref = &xref_raw.get<XrefResult>(); has_xref = true; }

            auto make_entry = [&](const FunctionInfo& info) -> json {
                json e = {
                    {"pc",          fmt::format("0x{:X}", info.entry_pc)},
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
                uint64_t target_pc = parse_hex(args["pc"].get<std::string>());
                auto it = fn_result.functions.find(target_pc);
                if (it == fn_result.functions.end()) {
                    return {{"found", false},
                            {"error", fmt::format("No function at PC 0x{:X}", target_pc)}};
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
}

}  // namespace tenet
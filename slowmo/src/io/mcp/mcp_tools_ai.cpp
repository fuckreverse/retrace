// Tool registrations: evidence, batch, hypothesis
// These are the AI-facing tools for structured reasoning and anti-hallucination.

#include "mcp_server.h"
#include "mcp_helpers.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>

#include <string>
#include <vector>
#include <cctype>

using json = nlohmann::json;

namespace tenet {

// =====================================================================
// Evidence verification tools (anti-hallucination)
// =====================================================================

void TenetMcpService::register_evidence_tools() {
    register_tool(
        {"verify_evidence",
         "Verify that data cited by the AI actually exists in the trace. "
         "Supports checking: register values, memory contents, and instruction mnemonics "
         "at specific instruction IDs. Used by the hypothesis ledger to ensure all "
         "evidence references are grounded in real trace data (anti-hallucination). "
         "Returns pass/fail for each check with details on mismatches.",
         {{"type", "object"},
          {"properties", {
              {"checks", {
                  {"type", "array"},
                  {"description", "Array of evidence claims to verify against the trace"},
                  {"items", {
                      {"type", "object"},
                      {"properties", {
                          {"type", {{"type", "string"},
                                    {"enum", json::array({"register", "memory", "instruction"})},
                                    {"description", "Type of evidence to verify"}}},
                          {"inst_id", {{"type", "integer"},
                                       {"description", "Instruction ID where the claim is made"}}},
                          {"register", {{"type", "string"},
                                        {"description", "(type=register) Register name, e.g. 'x0', 'lr'"}}},
                          {"expected_value", {{"type", "string"},
                                              {"description", "(type=register) Expected hex value, e.g. '0xdeadbeef'"}}},
                          {"address", {{"type", "string"},
                                       {"description", "(type=memory) Memory address to check"}}},
                          {"expected_bytes", {{"type", "string"},
                                              {"description", "(type=memory) Expected hex bytes, e.g. '48656c6c6f'"}}},
                          {"expected_mnemonic", {{"type", "string"},
                                                  {"description", "(type=instruction) Expected mnemonic, e.g. 'aese'"}}},
                          {"expected_pc", {{"type", "string"},
                                           {"description", "(type=instruction) Expected PC address"}}}
                      }},
                      {"required", json::array({"type", "inst_id"})}
                  }}
              }}
          }},
          {"required", json::array({"checks"})}}},
        [this](const json& args) -> json {
            auto checks = args.at("checks");
            if (checks.empty()) throw std::runtime_error("No checks provided");

            json results = json::array();
            int passed = 0;
            for (size_t i = 0; i < checks.size(); i++) {
                const auto& check = checks[i];
                std::string check_type = check.at("type").get<std::string>();
                uint64_t inst_id = check.at("inst_id").get<uint64_t>();

                json verdict;
                if (check_type == "register") {
                    std::string reg = check.value("register", "");
                    std::string expected = check.value("expected_value", "");
                    int idx = reg_name_to_idx(reg);
                    if (idx < 0) {
                        verdict = {{"valid", false}, {"reason", "Unknown register: " + reg}};
                    } else {
                        const auto& state = regfile_.state_before(inst_id);
                        uint64_t actual_val = state.gpr[idx];
                        std::string exp_clean = expected;
                        if (exp_clean.size() > 2 && (exp_clean.substr(0,2) == "0x" || exp_clean.substr(0,2) == "0X"))
                            exp_clean = exp_clean.substr(2);
                        bool parse_ok = true;
                        uint64_t expected_val = 0;
                        try { expected_val = std::stoull(exp_clean, nullptr, 16); }
                        catch (...) { parse_ok = false; }

                        if (!parse_ok) {
                            verdict = {{"valid", false}, {"reason", "Cannot parse expected value: " + expected}};
                        } else if (actual_val == expected_val) {
                            verdict = {{"valid", true},
                                       {"actual_value", fmt::format("0x{:X}", actual_val)}};
                        } else {
                            verdict = {{"valid", false},
                                       {"reason", fmt::format("Register {} = 0x{:X}, expected 0x{:X}",
                                                              reg, actual_val, expected_val)},
                                       {"actual_value", fmt::format("0x{:X}", actual_val)}};
                        }
                    }
                } else if (check_type == "memory") {
                    std::string addr_str = check.value("address", "");
                    std::string expected_bytes = check.value("expected_bytes", "");
                    uint64_t addr = parse_hex(addr_str);
                    size_t size = expected_bytes.size() / 2;
                    if (size == 0) size = 1;

                    auto rr = memory_.read_region(addr, size, inst_id);
                    std::string actual_hex;
                    for (size_t j = 0; j < rr.data.size(); j++) {
                        if (rr.known[j])
                            actual_hex += fmt::format("{:02x}", rr.data[j]);
                        else
                            actual_hex += "??";
                    }
                    std::string exp_norm;
                    for (char c : expected_bytes) {
                        if (c != ' ') exp_norm += static_cast<char>(std::tolower(c));
                    }
                    if (actual_hex.find(exp_norm) != std::string::npos) {
                        verdict = {{"valid", true}, {"actual_hex", actual_hex}};
                    } else {
                        verdict = {{"valid", false},
                                   {"reason", fmt::format("Memory mismatch at {}", addr_str)},
                                   {"expected", exp_norm},
                                   {"actual", actual_hex}};
                    }
                } else if (check_type == "instruction") {
                    std::string expected_mnem = check.value("expected_mnemonic", "");
                    std::string expected_pc = check.value("expected_pc", "");

                    auto [offset, seed_pc] = index_.offset_of_with_pc(inst_id, reader_);
                    auto rv = reader_.record_at(offset, seed_pc);
                    bool valid = true;
                    std::vector<std::string> reasons;
                    std::string actual_mnem, actual_pc_str;

                    if (rv.kind == RecordKind::Inst) {
                        auto inst = rv.as_inst();
                        actual_pc_str = fmt::format("0x{:X}", inst.pc);

                        if (code_table_ && decoder_) {
                            auto opcode = code_table_->opcode_at(inst.pc);
                            if (opcode) {
                                auto disasm = decoder_->decode(inst.pc, *opcode);
                                if (disasm) actual_mnem = disasm->mnemonic;
                            }
                        }

                        if (!expected_mnem.empty()) {
                            std::string m_lower = actual_mnem, e_lower = expected_mnem;
                            for (auto& c : m_lower) c = static_cast<char>(std::tolower(c));
                            for (auto& c : e_lower) c = static_cast<char>(std::tolower(c));
                            if (m_lower.find(e_lower) == std::string::npos) {
                                valid = false;
                                reasons.push_back("Mnemonic '" + expected_mnem + "' not found (actual: " + actual_mnem + ")");
                            }
                        }
                        if (!expected_pc.empty()) {
                            uint64_t exp_pc_val = parse_hex(expected_pc);
                            if (inst.pc != exp_pc_val) {
                                valid = false;
                                reasons.push_back(fmt::format("PC mismatch: expected {}, actual 0x{:X}",
                                                              expected_pc, inst.pc));
                            }
                        }
                    } else {
                        valid = false;
                        reasons.push_back("inst_id does not point to an instruction record");
                    }

                    if (valid) {
                        verdict = {{"valid", true},
                                   {"actual_mnemonic", actual_mnem},
                                   {"actual_pc", actual_pc_str}};
                    } else {
                        std::string reason_str;
                        for (size_t r = 0; r < reasons.size(); r++) {
                            if (r > 0) reason_str += "; ";
                            reason_str += reasons[r];
                        }
                        verdict = {{"valid", false}, {"reason", reason_str}};
                    }
                } else {
                    verdict = {{"valid", false}, {"reason", "Unknown check type: " + check_type}};
                }

                verdict["check_index"] = i;
                verdict["check_type"] = check_type;
                if (verdict.value("valid", false)) passed++;
                results.push_back(std::move(verdict));
            }

            return {{"all_valid", passed == static_cast<int>(checks.size())},
                    {"checks_passed", passed},
                    {"checks_total", checks.size()},
                    {"results", std::move(results)}};
        }
    );
}

// =====================================================================
// Batch query tool
// =====================================================================

void TenetMcpService::register_batch_tools() {
    register_tool(
        {"batch_query",
         "Execute multiple tool queries in a single MCP call to reduce round-trip "
         "latency. Up to 20 queries can be batched. Each query specifies a tool name "
         "and its parameters. Results are returned in order. Useful when you need "
         "register states at multiple points, or want to combine memread + disasm + "
         "regstate for the same instruction range.",
         {{"type", "object"},
          {"properties", {
              {"queries", {
                  {"type", "array"},
                  {"description", "Array of queries to execute"},
                  {"items", {
                      {"type", "object"},
                      {"properties", {
                          {"tool", {{"type", "string"},
                                    {"description", "Tool name to call (e.g. 'get_regs', 'memread', 'disasm')"}}},
                          {"params", {{"type", "object"},
                                      {"description", "Parameters for the tool"}}}
                      }},
                      {"required", json::array({"tool", "params"})}
                  }},
                  {"maxItems", 20}
              }}
          }},
          {"required", json::array({"queries"})}}},
        [this](const json& args) -> json {
            auto queries = args.at("queries");
            if (queries.empty()) throw std::runtime_error("No queries provided");
            if (queries.size() > 20) throw std::runtime_error("Maximum 20 queries per batch");

            json results = json::array();
            int errors = 0;
            for (size_t i = 0; i < queries.size(); i++) {
                const auto& q = queries[i];
                std::string tool_name = q.at("tool").get<std::string>();
                json tool_params = q.value("params", json::object());

                auto it = tool_handlers_.find(tool_name);
                if (it == tool_handlers_.end()) {
                    results.push_back({{"index", i}, {"tool", tool_name},
                                       {"error", "Unknown tool: " + tool_name}});
                    errors++;
                    continue;
                }
                try {
                    json result = it->second(tool_params);
                    results.push_back({{"index", i}, {"tool", tool_name},
                                       {"result", std::move(result)}});
                } catch (const std::exception& e) {
                    results.push_back({{"index", i}, {"tool", tool_name},
                                       {"error", std::string(e.what())}});
                    errors++;
                }
            }
            return {{"batch_size", queries.size()},
                    {"results", std::move(results)},
                    {"errors", errors}};
        }
    );
}

// =====================================================================
// Hypothesis tools (8 tools + ledger state machine)
// =====================================================================

void TenetMcpService::register_hypothesis_tools() {
    // -- hypothesis_add
    register_tool(
        {"hypothesis_add",
         "Propose and immediately activate a new hypothesis about the trace. "
         "REQUIRED before drawing any conclusion. Forces structured reasoning: "
         "hypothesis_add -> hypothesis_evidence (+ verify_evidence) -> hypothesis_conclude. "
         "Returns the hypothesis ID (e.g. 'H001') to use in subsequent calls.",
         {{"type", "object"},
          {"properties", {
              {"statement", {{"type", "string"},
                             {"description", "The hypothesis statement (what you believe might be true)"}}},
              {"category", {{"type", "string"},
                            {"enum", json::array({"crypto_algorithm", "key_source", "data_flow",
                                                  "function_purpose", "obfuscation", "anti_debug", "general"})},
                            {"description", "Category of the hypothesis"},
                            {"default", "general"}}},
              {"conflicts_with", {{"type", "array"},
                                  {"items", {{"type", "string"}}},
                                  {"description", "IDs of hypotheses that conflict with this one"}}}
          }},
          {"required", json::array({"statement"})}}},
        [this](const json& args) -> json {
            std::string statement = args.at("statement").get<std::string>();
            std::string category = args.value("category", "general");
            std::vector<std::string> conflicts;
            if (args.contains("conflicts_with")) {
                for (const auto& c : args["conflicts_with"])
                    conflicts.push_back(c.get<std::string>());
            }
            json result = ledger_.add(statement, category, conflicts);
            // Auto-activate so LLM can immediately add evidence without an extra step
            if (result.contains("id")) {
                ledger_.activate(result["id"].get<std::string>());
                result["status"] = "active";
            }
            return result;
        }
    );

    // hypothesis_activate removed: hypothesis_add now auto-activates the new hypothesis.
    // Explicit activate is rarely needed and added unnecessary LLM round-trips.

    // -- hypothesis_evidence
    register_tool(
        {"hypothesis_evidence",
         "Add evidence to a hypothesis. Evidence should reference concrete trace data "
         "(instruction IDs, register values, memory contents). Set verified=true ONLY "
         "after using verify_evidence to confirm the data exists in the trace.",
         {{"type", "object"},
          {"properties", {
              {"id", {{"type", "string"}, {"description", "Hypothesis ID"}}},
              {"description", {{"type", "string"}, {"description", "What this evidence shows"}}},
              {"source_tool", {{"type", "string"},
                               {"description", "Which tool produced this evidence (e.g. 'taint_forward', 'memread')"}}},
              {"inst_id", {{"type", "integer"}, {"description", "Related instruction ID (if applicable)"}}},
              {"data", {{"type", "object"}, {"description", "Raw evidence data from the tool"}}},
              {"supports", {{"type", "boolean"},
                            {"description", "True if evidence supports hypothesis, false if it contradicts"},
                            {"default", true}}},
              {"verified", {{"type", "boolean"},
                            {"description", "True ONLY if verify_evidence has confirmed this data exists"},
                            {"default", false}}}
          }},
          {"required", json::array({"id", "description", "source_tool"})}}},
        [this](const json& args) -> json {
            std::string hid = args.at("id").get<std::string>();
            std::string desc = args.at("description").get<std::string>();
            std::string source = args.at("source_tool").get<std::string>();
            std::optional<uint64_t> inst_id;
            if (args.contains("inst_id")) inst_id = args["inst_id"].get<uint64_t>();
            json data = args.value("data", json(nullptr));
            bool supports = args.value("supports", true);
            bool verified = args.value("verified", false);
            return ledger_.add_evidence(hid, desc, source, inst_id, data, supports, verified);
        }
    );

    // -- hypothesis_conclude
    register_tool(
        {"hypothesis_conclude",
         "Conclude a hypothesis (confirm it as true). REQUIRES at least one "
         "piece of verified evidence. Cannot conclude if conflicting hypotheses "
         "are already concluded.",
         {{"type", "object"},
          {"properties", {
              {"id", {{"type", "string"}, {"description", "Hypothesis ID to conclude"}}},
              {"conclusion", {{"type", "string"}, {"description", "Final conclusion statement"}}}
          }},
          {"required", json::array({"id", "conclusion"})}}},
        [this](const json& args) -> json {
            return ledger_.conclude(
                args.at("id").get<std::string>(),
                args.at("conclusion").get<std::string>());
        }
    );

    // -- hypothesis_abandon
    register_tool(
        {"hypothesis_abandon",
         "Abandon a hypothesis (evidence disproved it or it's no longer relevant).",
         {{"type", "object"},
          {"properties", {
              {"id", {{"type", "string"}, {"description", "Hypothesis ID to abandon"}}},
              {"reason", {{"type", "string"}, {"description", "Why this hypothesis is being abandoned"}}}
          }},
          {"required", json::array({"id", "reason"})}}},
        [this](const json& args) -> json {
            return ledger_.abandon(
                args.at("id").get<std::string>(),
                args.at("reason").get<std::string>());
        }
    );

    // -- hypothesis_list
    register_tool(
        {"hypothesis_list",
         "List all hypotheses in the ledger. Shows status, confidence, evidence counts, "
         "and conflicts. Use to review the current state of analysis reasoning.",
         {{"type", "object"},
          {"properties", {
              {"status", {{"type", "string"},
                          {"enum", json::array({"proposed", "active", "concluded", "abandoned"})},
                          {"description", "Filter by status (optional, default: show all)"}}}
          }}}},
        [this](const json& args) -> json {
            return ledger_.list_all(args.value("status", ""));
        }
    );

    // -- hypothesis_get
    register_tool(
        {"hypothesis_get",
         "Get full details of a hypothesis including all evidence items.",
         {{"type", "object"},
          {"properties", {
              {"id", {{"type", "string"}, {"description", "Hypothesis ID"}}}
          }},
          {"required", json::array({"id"})}}},
        [this](const json& args) -> json {
            return ledger_.get(args.at("id").get<std::string>());
        }
    );

    // -- hypothesis_mark_reviewed
    register_tool(
        {"hypothesis_mark_reviewed",
         "Mark a hypothesis as reviewed (audited for correctness). "
         "Use after manually verifying a concluded hypothesis to distinguish "
         "reviewed conclusions from unreviewed ones in hypothesis_list.",
         {{"type", "object"},
          {"properties", {
              {"id", {{"type", "string"}, {"description", "Hypothesis ID"}}}
          }},
          {"required", json::array({"id"})}}},
        [this](const json& args) -> json {
            return ledger_.mark_reviewed(args.at("id").get<std::string>());
        }
    );
}

}  // namespace tenet

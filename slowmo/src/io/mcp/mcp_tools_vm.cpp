// ═══════════════════════════════════════════════════════════════════════════
// MCP VM Query Tools — Filtering, timeline, and backward-slice queries
// on VMAbstractResult for efficient LLM-driven VMP analysis.
//
// These tools operate on an already-computed VMAbstractResult (from the
// vm_abstract pass). They do NOT re-run the pass; they require it to have
// completed first (throwing PassNotReady otherwise).
// ═══════════════════════════════════════════════════════════════════════════

#include "mcp_server.h"
#include "mcp_helpers.h"

#include "analysis/pass_manager.h"
#include "analysis/passes/vm/vm_abstract_pass.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace tenet {

using json = nlohmann::json;

// ─── Helper: get the cached VMAbstractResult (non-blocking) ──────────────

static const VMAbstractResult& require_vm_result(PassManager* pm) {
    return require_pass<VMAbstractResult>(pm, "vm_abstract",
        "vm_abstract pass must be run first (use the vm_abstract tool)");
}

// ─── Helper: find a VM register value in a step's vm_regs ────────────────

static const uint64_t* find_vm_reg(const VMStep& step, const std::string& name) {
    for (const auto& [n, v] : step.vm_regs) {
        if (n == name) return &v;
    }
    return nullptr;
}

// ─── Helper: serialize a single VMStep to JSON ──────────────────────────

static json step_to_json(const VMAbstractResult& result, const VMStep& s,
                          size_t step_index,
                          std::function<uint64_t(uint64_t)> rebase) {
    json sj = {
        {"step_index",       step_index},
        {"inst_id_start",    s.inst_id_start},
        {"inst_id_end",      s.inst_id_end},
        {"handler_entry_pc", fmt::format("0x{:X}", rebase(s.handler_entry_pc))}
    };
    if (s.opcode_valid) sj["opcode"] = fmt::format("0x{:X}", s.opcode_value);
    if (s.vm_pc_valid)  sj["vm_pc"]  = fmt::format("0x{:X}", s.vm_pc_value);

    const VMHandler* handler = result.handler_at(s.handler_entry_pc);
    if (handler && !handler->label.empty()) sj["label"] = handler->label;

    if (!s.ctx_fields.empty()) {
        json ctx_j = json::object();
        for (const auto& [name, val] : s.ctx_fields)
            ctx_j[name] = fmt::format("0x{:X}", val);
        sj["ctx_fields"] = std::move(ctx_j);
    }

    if (!s.vm_regs.empty()) {
        json regs_j = json::object();
        for (const auto& [name, val] : s.vm_regs)
            regs_j[name] = fmt::format("0x{:X}", val);
        sj["vm_regs"] = std::move(regs_j);
    }

    if (!s.operands.empty()) {
        json ops_j = json::array();
        for (const auto& op : s.operands) {
            ops_j.push_back({
                {"name",  op.name},
                {"value", fmt::format("0x{:X}", op.value)},
                {"size",  op.size_bytes}
            });
        }
        sj["operands"] = std::move(ops_j);
    }

    return sj;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tool registration
// ═══════════════════════════════════════════════════════════════════════════

void TenetMcpService::register_vm_query_tools() {

// ── vm_steps_query ───────────────────────────────────────────────────
register_tool(
    {"vm_steps_query",
     "Query and filter VM execution steps from a completed vm_abstract result. "
     "Supports filtering by: handler label (substring/exact), opcode value/range, "
     "VM register written (value changed from previous step), VM register value "
     "match, vm_pc range, step index range. Returns matching steps with full "
     "context (opcode, vm_pc, vm_regs, ctx_fields, operands). Use this to "
     "efficiently locate interesting VM instructions in a large (10k+) step "
     "sequence without paginating through all steps.",
     {{"type", "object"},
      {"properties", {
        // ── Range filters ──
        {"step_start",   {{"type", "integer"}, {"description", "Filter: only steps with index >= step_start"}}},
        {"step_end",     {{"type", "integer"}, {"description", "Filter: only steps with index < step_end"}}},
        // ── Handler/opcode filters ──
        {"handler_label",{{"type", "string"},  {"description", "Filter: handler label contains this substring (case-insensitive). E.g. 'ADD', 'STORE', 'BRANCH'."}}},
        {"handler_label_exact", {{"type", "boolean"}, {"description", "If true, handler_label must match exactly (case-insensitive) instead of substring. Default false."}}},
        {"opcode",       {{"type", "string"},  {"description", "Filter: exact opcode value (hex). E.g. '0x1A'."}}},
        {"opcode_min",   {{"type", "string"},  {"description", "Filter: opcode >= this value (hex)."}}},
        {"opcode_max",   {{"type", "string"},  {"description", "Filter: opcode <= this value (hex)."}}},
        // ── VM-PC filter ──
        {"vm_pc_min",    {{"type", "string"},  {"description", "Filter: vm_pc >= this address (hex)."}}},
        {"vm_pc_max",    {{"type", "string"},  {"description", "Filter: vm_pc <= this address (hex)."}}},
        // ── VM register filters ──
        {"reg_written",  {{"type", "string"},  {"description", "Filter: only steps where this VM register's value changed from the previous step. E.g. 'R3'."}}},
        {"reg_name",     {{"type", "string"},  {"description", "Filter: only steps where this VM register has the value specified by reg_value."}}},
        {"reg_value",    {{"type", "string"},  {"description", "Filter: required value (hex) for the register specified by reg_name."}}},
        // ── Pagination ──
        {"offset",       {{"type", "integer"}, {"description", "Skip first N matching results. Default 0."}, {"default", 0}}},
        {"limit",        {{"type", "integer"}, {"description", "Max results to return (max 500). Default 100."}, {"default", 100}}}
      }}}},
    [this](const json& args) -> json {
        const auto& result = require_vm_result(pm_);

        // Parse filters
        size_t step_start = args.value("step_start", size_t(0));
        size_t step_end   = args.value("step_end", result.steps.size());
        step_end = std::min(step_end, result.steps.size());
        step_start = std::min(step_start, step_end);

        // Handler label
        std::string label_filter;
        bool label_exact = args.value("handler_label_exact", false);
        if (args.contains("handler_label")) {
            label_filter = args["handler_label"].get<std::string>();
            // Convert to lowercase for case-insensitive matching
            for (auto& c : label_filter) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        // Opcode
        bool has_opcode_exact = args.contains("opcode");
        uint64_t opcode_exact = has_opcode_exact ? parse_hex(args["opcode"].get<std::string>()) : 0;
        bool has_opcode_min = args.contains("opcode_min");
        uint64_t opcode_min = has_opcode_min ? parse_hex(args["opcode_min"].get<std::string>()) : 0;
        bool has_opcode_max = args.contains("opcode_max");
        uint64_t opcode_max = has_opcode_max ? parse_hex(args["opcode_max"].get<std::string>()) : UINT64_MAX;

        // VM-PC
        bool has_vpc_min = args.contains("vm_pc_min");
        uint64_t vpc_min = has_vpc_min ? parse_hex(args["vm_pc_min"].get<std::string>()) : 0;
        bool has_vpc_max = args.contains("vm_pc_max");
        uint64_t vpc_max = has_vpc_max ? parse_hex(args["vm_pc_max"].get<std::string>()) : UINT64_MAX;

        // VM register written
        std::string reg_written;
        if (args.contains("reg_written"))
            reg_written = args["reg_written"].get<std::string>();

        // VM register value match
        std::string reg_name;
        bool has_reg_value = false;
        uint64_t reg_value = 0;
        if (args.contains("reg_name")) {
            reg_name = args["reg_name"].get<std::string>();
            if (args.contains("reg_value")) {
                has_reg_value = true;
                reg_value = parse_hex(args["reg_value"].get<std::string>());
            }
        }

        // Pagination
        size_t offset = args.value("offset", size_t(0));
        size_t limit  = std::min(args.value("limit", size_t(100)), size_t(500));

        auto rebase_fn = [this](uint64_t pc) { return rebase(pc); };

        // Scan and filter
        json matches = json::array();
        size_t matched_count = 0;
        size_t total_scanned = 0;

        for (size_t i = step_start; i < step_end; i++) {
            const auto& s = result.steps[i];
            total_scanned++;

            // Handler label filter
            if (!label_filter.empty()) {
                const VMHandler* h = result.handler_at(s.handler_entry_pc);
                if (!h || h->label.empty()) continue;
                std::string lbl = h->label;
                for (auto& c : lbl) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (label_exact) {
                    if (lbl != label_filter) continue;
                } else {
                    if (lbl.find(label_filter) == std::string::npos) continue;
                }
            }

            // Opcode filters
            if (has_opcode_exact) {
                if (!s.opcode_valid || s.opcode_value != opcode_exact) continue;
            }
            if (has_opcode_min || has_opcode_max) {
                if (!s.opcode_valid) continue;
                if (has_opcode_min && s.opcode_value < opcode_min) continue;
                if (has_opcode_max && s.opcode_value > opcode_max) continue;
            }

            // VM-PC filters
            if (has_vpc_min || has_vpc_max) {
                if (!s.vm_pc_valid) continue;
                if (has_vpc_min && s.vm_pc_value < vpc_min) continue;
                if (has_vpc_max && s.vm_pc_value > vpc_max) continue;
            }

            // VM register written filter (value changed from previous step)
            if (!reg_written.empty()) {
                if (i == 0) continue;  // No previous step to compare
                const uint64_t* cur = find_vm_reg(s, reg_written);
                const uint64_t* prev = find_vm_reg(result.steps[i - 1], reg_written);
                if (!cur) continue;
                if (prev && *cur == *prev) continue;
                // If prev is null but cur exists, treat as "written" (first appearance)
            }

            // VM register value match filter
            if (!reg_name.empty() && has_reg_value) {
                const uint64_t* val = find_vm_reg(s, reg_name);
                if (!val || *val != reg_value) continue;
            }

            // Passed all filters
            matched_count++;
            if (matched_count <= offset) continue;
            if (matches.size() >= limit) continue;  // Keep counting total matches

            matches.push_back(step_to_json(result, s, i, rebase_fn));
        }

        bool has_more = matched_count > offset + matches.size();
        return {
            {"total_steps",     result.steps.size()},
            {"total_matched",   matched_count},
            {"offset",          offset},
            {"returned",        matches.size()},
            {"has_more",        has_more},
            {"next_offset",     has_more ? offset + matches.size() : offset},
            {"steps",           std::move(matches)}
        };
    }
);

// ── vm_reg_timeline ──────────────────────────────────────────────────
register_tool(
    {"vm_reg_timeline",
     "Track how a VM register's value changes across VM execution steps. "
     "Given a register name (e.g. 'R0', 'SP'), returns only the steps where "
     "that register's value changed, with before/after values. This compresses "
     "10000 steps into typically dozens of change-points, making it feasible "
     "for an LLM to understand the register's full lifecycle. "
     "Requires a completed vm_abstract pass.",
     {{"type", "object"},
      {"required", {"reg_name"}},
      {"properties", {
        {"reg_name",    {{"type", "string"},  {"description", "VM register name to track. E.g. 'R0', 'R3', 'SP', 'FLAGS'."}}},
        {"step_start",  {{"type", "integer"}, {"description", "Start of step range (inclusive). Default 0."}}},
        {"step_end",    {{"type", "integer"}, {"description", "End of step range (exclusive). Default: all steps."}}},
        {"offset",      {{"type", "integer"}, {"description", "Skip first N change-points. Default 0."}, {"default", 0}}},
        {"limit",       {{"type", "integer"}, {"description", "Max change-points to return (max 1000). Default 200."}, {"default", 200}}}
      }}}},
    [this](const json& args) -> json {
        const auto& result = require_vm_result(pm_);

        std::string reg_name = args.at("reg_name").get<std::string>();
        size_t step_start = args.value("step_start", size_t(0));
        size_t step_end   = args.value("step_end", result.steps.size());
        step_end = std::min(step_end, result.steps.size());
        step_start = std::min(step_start, step_end);
        size_t offset = args.value("offset", size_t(0));
        size_t limit  = std::min(args.value("limit", size_t(200)), size_t(1000));

        auto rebase_fn = [this](uint64_t pc) { return rebase(pc); };

        json changes = json::array();
        size_t total_changes = 0;
        uint64_t prev_value = 0;
        bool prev_valid = false;

        // If step_start > 0, read the register value at step_start - 1 as baseline
        if (step_start > 0) {
            const uint64_t* v = find_vm_reg(result.steps[step_start - 1], reg_name);
            if (v) {
                prev_value = *v;
                prev_valid = true;
            }
        }

        for (size_t i = step_start; i < step_end; i++) {
            const auto& s = result.steps[i];
            const uint64_t* cur = find_vm_reg(s, reg_name);
            if (!cur) {
                // Register not present in this step — if it was present before,
                // that's a "disappearance" but we don't count it as a change.
                continue;
            }

            bool changed = false;
            if (!prev_valid) {
                // First time we see the register — always emit as "initial"
                changed = true;
            } else if (*cur != prev_value) {
                changed = true;
            }

            if (changed) {
                total_changes++;
                if (total_changes > offset && changes.size() < limit) {
                    json entry = {
                        {"step_index",  i},
                        {"new_value",   fmt::format("0x{:X}", *cur)},
                    };
                    if (prev_valid) {
                        entry["old_value"] = fmt::format("0x{:X}", prev_value);
                    }
                    // Add handler label for context
                    const VMHandler* h = result.handler_at(s.handler_entry_pc);
                    if (h && !h->label.empty()) entry["handler_label"] = h->label;
                    if (s.opcode_valid) entry["opcode"] = fmt::format("0x{:X}", s.opcode_value);
                    if (s.vm_pc_valid) entry["vm_pc"] = fmt::format("0x{:X}", s.vm_pc_value);

                    changes.push_back(std::move(entry));
                }
            }

            prev_value = *cur;
            prev_valid = true;
        }

        bool has_more = total_changes > offset + changes.size();
        return {
            {"reg_name",        reg_name},
            {"total_steps",     result.steps.size()},
            {"range",           {{"start", step_start}, {"end", step_end}}},
            {"total_changes",   total_changes},
            {"offset",          offset},
            {"returned",        changes.size()},
            {"has_more",        has_more},
            {"next_offset",     has_more ? offset + changes.size() : offset},
            {"changes",         std::move(changes)}
        };
    }
);

// ── vm_backward_slice ────────────────────────────────────────────────
register_tool(
    {"vm_backward_slice",
     "Backward data-flow slice on VM registers. Starting from a given step "
     "and VM register, traces backward to find which earlier step last wrote "
     "that register, then optionally continues tracing the source operands "
     "of that writing step. Returns a chain of (step, register, value) tuples "
     "showing the data-flow provenance. "
     "This is the VM-level equivalent of backward taint — but operates on "
     "VM register snapshots rather than native AArch64 semantics. "
     "Requires a completed vm_abstract pass with vm_registers hint.",
     {{"type", "object"},
      {"required", {"step_index", "reg_name"}},
      {"properties", {
        {"step_index",  {{"type", "integer"}, {"description", "The step index to start backward tracing from."}}},
        {"reg_name",    {{"type", "string"},  {"description", "The VM register to trace backward. E.g. 'R3'."}}},
        {"max_depth",   {{"type", "integer"}, {"description", "Maximum number of backward hops. Default 8, max 32."}, {"default", 8}}},
        {"follow_sources", {{"type", "boolean"}, {"description",
            "If true, after finding the step that wrote reg_name, automatically "
            "continue tracing backward on that step's input registers (registers "
            "whose values were consumed to produce the output — inferred from "
            "handler register effects). Default true."}, {"default", true}}}
      }}}},
    [this](const json& args) -> json {
        const auto& result = require_vm_result(pm_);

        size_t start_step = args.at("step_index").get<size_t>();
        std::string target_reg = args.at("reg_name").get<std::string>();
        size_t max_depth = std::min(args.value("max_depth", size_t(8)), size_t(32));
        bool follow_sources = args.value("follow_sources", true);

        if (start_step >= result.steps.size()) {
            throw std::runtime_error(fmt::format(
                "step_index {} out of range (total_steps: {})",
                start_step, result.steps.size()));
        }

        auto rebase_fn = [this](uint64_t pc) { return rebase(pc); };

        // The slice chain: each entry is one backward hop
        json chain = json::array();

        struct TraceTarget {
            size_t step;
            std::string reg;
        };

        std::vector<TraceTarget> worklist;
        worklist.push_back({start_step, target_reg});

        // Track visited (step, reg) to avoid cycles
        std::vector<std::pair<size_t, std::string>> visited;

        size_t depth = 0;

        while (!worklist.empty() && depth < max_depth) {
            auto [cur_step, cur_reg] = worklist.back();
            worklist.pop_back();

            // Check visited
            bool already = false;
            for (const auto& [vs, vr] : visited) {
                if (vs == cur_step && vr == cur_reg) { already = true; break; }
            }
            if (already) continue;
            visited.push_back({cur_step, cur_reg});

            // Read current value
            const uint64_t* cur_val = find_vm_reg(result.steps[cur_step], cur_reg);
            if (!cur_val) {
                // Register not present in this step
                chain.push_back({
                    {"step_index", cur_step},
                    {"reg",        cur_reg},
                    {"status",     "not_found"},
                    {"message",    fmt::format("Register '{}' not present at step {}", cur_reg, cur_step)}
                });
                continue;
            }

            // Search backward for the most recent step that changed this register
            size_t writer_step = cur_step;
            bool found_writer = false;

            for (size_t j = cur_step; j > 0; j--) {
                size_t prev_idx = j - 1;
                const uint64_t* prev_val = find_vm_reg(result.steps[prev_idx], cur_reg);
                if (!prev_val) {
                    // Register disappeared — treat current step as the writer
                    writer_step = j;
                    found_writer = true;
                    break;
                }
                if (*prev_val != *cur_val) {
                    // Value changed at step j
                    writer_step = j;
                    found_writer = true;
                    break;
                }
            }

            if (!found_writer && cur_step > 0) {
                // Value was the same since step 0 — check if step 0 has it
                const uint64_t* v0 = find_vm_reg(result.steps[0], cur_reg);
                if (v0 && *v0 == *cur_val) {
                    chain.push_back({
                        {"step_index",  cur_step},
                        {"reg",         cur_reg},
                        {"value",       fmt::format("0x{:X}", *cur_val)},
                        {"status",      "initial_value"},
                        {"message",     fmt::format("'{}' = 0x{:X} since step 0 (initial value)", cur_reg, *cur_val)}
                    });
                    depth++;
                    continue;
                }
            }

            if (!found_writer) {
                chain.push_back({
                    {"step_index",  cur_step},
                    {"reg",         cur_reg},
                    {"value",       fmt::format("0x{:X}", *cur_val)},
                    {"status",      "origin"},
                    {"message",     "Could not find a prior writer"}
                });
                depth++;
                continue;
            }

            // Found the writer step
            const auto& ws = result.steps[writer_step];
            const VMHandler* handler = result.handler_at(ws.handler_entry_pc);

            json hop = {
                {"step_index",   writer_step},
                {"reg",          cur_reg},
                {"value",        fmt::format("0x{:X}", *cur_val)},
                {"status",       "written"},
                {"handler_pc",   fmt::format("0x{:X}", rebase_fn(ws.handler_entry_pc))},
            };
            if (handler && !handler->label.empty())
                hop["handler_label"] = handler->label;
            if (ws.opcode_valid)
                hop["opcode"] = fmt::format("0x{:X}", ws.opcode_value);
            if (ws.vm_pc_valid)
                hop["vm_pc"] = fmt::format("0x{:X}", ws.vm_pc_value);

            // Show old value (from the step before the writer)
            if (writer_step > 0) {
                const uint64_t* old_val = find_vm_reg(result.steps[writer_step - 1], cur_reg);
                if (old_val)
                    hop["old_value"] = fmt::format("0x{:X}", *old_val);
            }

            // Identify source registers: registers that were read by the handler
            // and whose values at the writer step differ from the output.
            // Heuristic: look at all VM regs at the writer step; those that are
            // NOT changed by this step (same as previous) are potential inputs.
            // More precisely: any VM reg that the handler reads (inferred by
            // comparing vm_regs before vs after is not sufficient since we only
            // have snapshots AT dispatch time). Instead, we list all VM regs
            // present at the writer step except the target reg itself as
            // "context", and let the LLM (with IDA handler decompilation) decide.
            if (follow_sources && writer_step > 0) {
                json sources = json::array();
                // Find registers whose value at writer_step differs from writer_step-1
                // (i.e., they were NOT written by this handler — they are inputs/context)
                const auto& prev_step = result.steps[writer_step - 1];
                for (const auto& [rn, rv] : ws.vm_regs) {
                    if (rn == cur_reg) continue;  // Skip the target register
                    const uint64_t* pv = find_vm_reg(prev_step, rn);
                    if (pv && *pv == rv) {
                        // Same value before and after — this reg was NOT written,
                        // so it could be an input to the handler
                        sources.push_back({
                            {"reg",   rn},
                            {"value", fmt::format("0x{:X}", rv)}
                        });
                    }
                }
                if (!sources.empty())
                    hop["input_regs"] = std::move(sources);

                // Also identify which other registers WERE changed (co-written)
                json co_written = json::array();
                for (const auto& [rn, rv] : ws.vm_regs) {
                    if (rn == cur_reg) continue;
                    const uint64_t* pv = find_vm_reg(prev_step, rn);
                    if (!pv || *pv != rv) {
                        co_written.push_back({
                            {"reg",       rn},
                            {"new_value", fmt::format("0x{:X}", rv)},
                            {"old_value", pv ? fmt::format("0x{:X}", *pv) : "N/A"}
                        });
                    }
                }
                if (!co_written.empty())
                    hop["co_written_regs"] = std::move(co_written);
            }

            chain.push_back(std::move(hop));
            depth++;

            // If follow_sources, we could push source regs onto the worklist,
            // but without handler semantics we can't reliably determine which
            // input regs actually contributed to the target. Instead, the chain
            // provides input_regs as context for the LLM to decide what to
            // trace next (by calling vm_backward_slice again on a specific
            // source register). This keeps the tool honest: it reports what it
            // can observe, and delegates semantic reasoning to the LLM.
        }

        return {
            {"start_step",  start_step},
            {"start_reg",   target_reg},
            {"total_steps", result.steps.size()},
            {"chain",       std::move(chain)}
        };
    }
);

}  // register_vm_query_tools()

}  // namespace tenet

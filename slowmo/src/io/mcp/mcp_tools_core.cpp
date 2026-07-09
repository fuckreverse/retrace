// Tool registrations: trace, query, taint, graph
// These are the "core" tools that operate on the trace data model directly.

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

#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"

#include <fmt/core.h>

#include <string>

using json = nlohmann::json;

namespace tenet {

// =====================================================================
// Trace info & disassembly tools
// =====================================================================

void TenetMcpService::register_trace_tools() {
    // -- trace_info
    register_tool(
        {"trace_info",
         "Get metadata about the loaded trace: architecture, instruction count, "
         "module base/slide, address range, flags. The trace is already loaded "
         "in this server process -- no need to call trace_open.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            const auto& hdr = reader_.header();
            const auto& stats = index_.stats();
            uint64_t ibase = image_base_.load(std::memory_order_relaxed);
            return {
                {"status", "loaded"},
                {"arch", hdr.arch == 1 ? "AArch64" : "x86_64"},
                {"gpr_count", hdr.num_gpr},
                {"module_name", hdr.module_name},
                {"module_base", fmt::format("0x{:X}", hdr.module_base)},
                {"module_slide", fmt::format("0x{:X}", hdr.module_slide)},
                {"image_base",  fmt::format("0x{:X}", ibase)},
                {"address_range", {
                    {"start", fmt::format("0x{:X}", rebase(hdr.trace_start))},
                    {"end",   fmt::format("0x{:X}", rebase(hdr.trace_end))}
                }},
                {"file_size", reader_.file_size()},
                {"flags", {
                    {"has_mem",  hdr.has_mem()},
                    {"has_nzcv", hdr.has_nzcv()},
                    {"reg_diff", hdr.reg_diff()},
                    {"has_code", hdr.has_code()}
                }},
                {"instruction_count", stats.inst_count},
                {"anchor_count", stats.anchor_count}
            };
        }
    );

    // -- disasm
    register_tool(
        {"disasm",
         "Disassemble instructions from the trace. Returns PC, register diffs, "
         "and memory accesses for each instruction. Efficiently reads directly "
         "from the mmap'd trace -- no subprocess overhead.",
         {{"type", "object"},
          {"properties", {
              {"start_inst_id", {{"type", "integer"}, {"description", "Starting instruction ID (0-based)"}, {"default", 0}}},
              {"count",         {{"type", "integer"}, {"description", "Number of instructions (max 500)"}, {"default", 50}}},
              {"show_regs",     {{"type", "boolean"}, {"description", "Include register diffs"}, {"default", true}}},
              {"show_mem",      {{"type", "boolean"}, {"description", "Include memory accesses"}, {"default", true}}}
          }}}},
        [this](const json& args) -> json {
            uint64_t start = args.value("start_inst_id", uint64_t(0));
            uint64_t count = std::min(args.value("count", uint64_t(50)), uint64_t(500));
            bool show_regs = args.value("show_regs", true);
            bool show_mem = args.value("show_mem", true);

            uint64_t end = std::min(start + count, index_.inst_count());
            json rows = json::array();
            for (uint64_t id = start; id < end; id++) {
                auto [offset, seed_pc] = index_.offset_of_with_pc(id, reader_);
                auto rv = reader_.record_at(offset, seed_pc);
                if (rv.kind != RecordKind::Inst) continue;
                auto inst = rv.as_inst();

                json row;
                row["inst_id"] = id;
                row["pc"]      = fmt::format("0x{:X}", rebase(inst.pc));

                // Disassemble if decoder available
                if (code_table_) {
                    auto opcode = code_table_->opcode_at(inst.pc);
                    if (opcode && decoder_) {
                        auto disasm = decoder_->decode(inst.pc, *opcode);
                        if (disasm) {
                            row["mnemonic"] = disasm->mnemonic;
                            row["operands"] = disasm->op_str;
                        }
                    }
                }

                if (show_regs) {
                    json diffs = json::array();
                    for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                        auto rd = inst.reg_diff(i);
                        diffs.push_back({{"reg", kRegNames[rd.index]},
                                         {"value", fmt::format("0x{:X}", rd.value)}});
                    }
                    row["reg_diffs"] = std::move(diffs);
                }

                if (show_mem) {
                    json mems = json::array();
                    for (uint8_t i = 0; i < inst.mem_access_count; i++) {
                        auto m = inst.mem_access(i);
                        mems.push_back({
                            {"type", (m.type & 2) ? "W" : "R"},
                            {"addr", fmt::format("0x{:X}", m.addr)},
                            {"size", m.size},
                            {"value", fmt::format("0x{:X}", m.value)}
                        });
                    }
                    row["mem_accesses"] = std::move(mems);
                }

                rows.push_back(std::move(row));
            }
            return {{"rows", std::move(rows)}, {"start", start}, {"count", end - start}};
        }
    );
}

// =====================================================================
// Query tools (register state, memory read, write history, PC search)
// =====================================================================

void TenetMcpService::register_query_tools() {
    // -- get_regs
    register_tool(
        {"get_regs",
         "Get all 34 AArch64 GPR values at a specific instruction. "
         "Reconstructs register state via ANCHOR+diff chain -- instant lookup "
         "from the in-memory RegisterFile cache. "
         "Provide EITHER inst_id OR pc (hex string). "
         "When pc is given, registers at the FIRST execution of that address are returned.",
         {{"type", "object"},
          {"properties", {
              {"inst_id", {{"type", "integer"}, {"description", "Instruction ID (preferred if known)"}}},
              {"pc",      {{"type", "string"},  {"description", "PC address (hex string). Used when inst_id is not provided."}}},
              {"when",    {{"type", "string"}, {"description", "\"before\" or \"after\" the instruction"}, {"default", "before"}}}
          }}}},
        [this](const json& args) -> json {
            uint64_t inst_id = 0;
            if (args.contains("inst_id")) {
                inst_id = args.at("inst_id").get<uint64_t>();
            } else if (args.contains("pc")) {
                uint64_t runtime_pc = unrebase(parse_hex(args.at("pc").get<std::string>()));
                if (pm_) {
                    tenet::register_pass_by_name(*pm_, "xref");
                    const auto& xref_raw = require_pass_nb(pm_, "xref");
                    if (xref_raw.ok()) {
                        const auto& xref = xref_raw.get<XrefResult>();
                        uint64_t first = xref.first_inst_id_at(runtime_pc);
                        if (first == UINT64_MAX)
                            throw std::runtime_error(fmt::format(
                                "No instruction found at PC {}. Use search_pc to check execution history.",
                                args.at("pc").get<std::string>()));
                        inst_id = first;
                    }
                }
            } else {
                throw std::runtime_error("Provide 'inst_id' or 'pc'.");
            }
            std::string when = args.value("when", "before");
            const auto& state = (when == "after")
                ? regfile_.state_after(inst_id)
                : regfile_.state_before(inst_id);
            json regs;
            for (int i = 0; i < 34; i++) {
                regs[kRegNames[i]] = fmt::format("0x{:X}", state.gpr[i]);
            }
            return {{"inst_id", inst_id}, {"when", when}, {"regs", std::move(regs)}};
        }
    );

    // get_reg intentionally removed: get_regs already returns all registers
    // including individual lookup.  Having both tools confuses LLM tool selection.

    // -- memread
    register_tool(
        {"memread",
         "Read memory contents at a specific address and point in time. "
         "Uses the MemoryModel's write-history tracking for time-travel reads. "
         "For large reads (>4096 bytes), consider using batch_query with multiple "
         "smaller memread calls if only partial regions are known.",
         {{"type", "object"},
          {"properties", {
              {"addr",       {{"type", "string"}, {"description", "Memory address (hex string, e.g. '0x16fdff200')"}}},
              {"size",       {{"type", "integer"}, {"description", "Bytes to read (max 65536)"}, {"default", 16}}},
              {"at_inst_id", {{"type", "integer"}, {"description", "Read memory state as of this instruction"}}}
          }},
          {"required", json::array({"addr", "at_inst_id"})}}},
        [this](const json& args) -> json {
            uint64_t addr = parse_hex(args.at("addr").get<std::string>());
            size_t size = std::min(args.value("size", 16), 65536);
            uint64_t inst_id = args.at("at_inst_id").get<uint64_t>();

            auto rr = memory_.read_region(addr, size, inst_id);
            std::string hex_str;
            hex_str.reserve(size * 3);
            for (size_t i = 0; i < rr.data.size(); i++) {
                if (rr.known[i]) {
                    hex_str += fmt::format("{:02X} ", rr.data[i]);
                } else {
                    hex_str += "?? ";
                }
            }

            json result = {{"addr", fmt::format("0x{:X}", addr)},
                           {"size", size},
                           {"inst_id", inst_id},
                           {"known_count", rr.known_count},
                           {"hex", hex_str}};

            // Include byte-level arrays only for small reads (≤4096) to
            // keep JSON response size manageable for large reads.
            if (size <= 4096) {
                json data_arr = json::array();
                json known_arr = json::array();
                for (size_t i = 0; i < rr.data.size(); i++) {
                    data_arr.push_back(rr.data[i]);
                    known_arr.push_back(rr.known[i]);
                }
                result["data"] = std::move(data_arr);
                result["known"] = std::move(known_arr);
            }
            return result;
        }
    );

    // -- mem_write_history
    register_tool(
        {"mem_write_history",
         "Get all recorded writes to a memory address range. "
         "Returns chronological list of write events with instruction ID, "
         "PC, value, and size. Supports pagination via offset/limit when "
         "there are many writes (use has_more + next_offset to continue).",
         {{"type", "object"},
          {"properties", {
              {"addr",   {{"type", "string"}, {"description", "Memory address (hex string)"}}},
              {"size",   {{"type", "integer"}, {"description", "Size of region (max 16)"}, {"default", 8}}},
              {"offset", {{"type", "integer"}, {"description", "Pagination offset (skip first N results)"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Max results per page (max 500)"}, {"default", 500}}}
          }},
          {"required", json::array({"addr"})}}},
        [this](const json& args) -> json {
            uint64_t addr = parse_hex(args.at("addr").get<std::string>());
            size_t size = std::min(args.value("size", 8), 16);
            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(500)), size_t(500));
            auto write_ids = memory_.write_history(addr, size);
            json writes_arr = json::array();
            size_t start_i = std::min(offset, write_ids.size());
            size_t end_i = std::min(start_i + limit, write_ids.size());
            for (size_t i = start_i; i < end_i; i++) {
                writes_arr.push_back(write_ids[i]);
            }
            bool has_more = end_i < write_ids.size();
            return {{"addr", fmt::format("0x{:X}", addr)},
                    {"total_writes", write_ids.size()},
                    {"offset", offset},
                    {"returned", end_i - start_i},
                    {"has_more", has_more},
                    {"next_offset", has_more ? end_i : offset},
                    {"write_inst_ids", std::move(writes_arr)},
                    {"note", "Each entry is an inst_id that wrote to this address. Use get_regs/disasm to inspect."}};
        }
    );

    // -- search_pc
    register_tool(
        {"search_pc",
         "Find all instruction IDs that executed at a given PC address. "
         "Uses the XRef pass index for O(1) lookup when available. "
         "Supports pagination via offset/limit when a PC is executed many times "
         "(use has_more + next_offset to fetch subsequent pages).",
         {{"type", "object"},
          {"properties", {
              {"pc",     {{"type", "string"}, {"description", "PC address (hex string)"}}},
              {"offset", {{"type", "integer"}, {"description", "Pagination offset (skip first N results)"}, {"default", 0}}},
              {"limit",  {{"type", "integer"}, {"description", "Max results per page (max 1000)"}, {"default", 100}}}
          }},
          {"required", json::array({"pc"})}}},
        [this](const json& args) -> json {
            uint64_t displayed_pc = parse_hex(args.at("pc").get<std::string>());
            uint64_t runtime_pc = unrebase(displayed_pc);
            size_t offset = args.value("offset", size_t(0));
            size_t limit = std::min(args.value("limit", size_t(100)), size_t(1000));

            if (pm_) {
                tenet::register_pass_by_name(*pm_, "xref");
                const auto& raw = require_pass_nb(pm_, "xref");
                if (raw.ok()) {
                    const auto& xref = raw.get<XrefResult>();
                    auto ids = xref.inst_ids_at(runtime_pc);
                    uint64_t exec_count = xref.execution_count(runtime_pc);
                    size_t start_i = std::min(offset, ids.size());
                    size_t end_i = std::min(start_i + limit, ids.size());
                    json page_ids = json::array();
                    for (size_t i = start_i; i < end_i; i++) {
                        page_ids.push_back(ids[i]);
                    }
                    bool has_more = end_i < ids.size();
                    return {{"pc", fmt::format("0x{:X}", displayed_pc)},
                            {"exec_count", exec_count},
                            {"offset", offset},
                            {"returned", end_i - start_i},
                            {"has_more", has_more},
                            {"next_offset", has_more ? end_i : offset},
                            {"inst_ids", std::move(page_ids)}};
                }
            }
            return {{"pc", fmt::format("0x{:X}", displayed_pc)},
                    {"inst_ids", json::array()},
                    {"warning", "xref pass not available"}};
        }
    );
}

// =====================================================================
// Taint analysis tools
// =====================================================================

void TenetMcpService::register_taint_tools() {
    // -- taint_forward
    register_tool(
        {"taint_forward",
         "Perform precise forward taint analysis using Triton semantic engine. "
         "Starting from a register (or memory address) at a specific instruction, "
         "trace data flow forward through the execution. Returns the complete "
         "propagation chain. This is EXACT taint -- handles implicit operands, "
         "sub-register aliases, conditional execution correctly. "
         "Runs in-process with zero startup overhead. "
         "Supports pagination of the steps list via steps_offset/steps_limit "
         "(use has_more_steps + next_steps_offset to continue).",
         {{"type", "object"},
          {"properties", {
              {"reg_index",              {{"type", json::array({"integer", "string"})}, {"description", "Register to taint: integer index (0=x0,29=fp,30=lr,31=sp,33=pc) OR name string ('x0','lr','sp','pc')"}}},
              {"inst_id",                {{"type", "integer"}, {"description", "Instruction ID to start from (0 = trace start)"}, {"default", 0}}},
              {"mem_addrs",              {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Additional memory addresses to taint (hex)"}}},
              {"stop_pcs",               {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Stop at these PCs (hex)"}}},
              {"max_width",              {{"type", "integer"}, {"description", "Stop when taint exceeds N registers"}, {"default", 0}}},
              {"propagate_through_calls", {{"type", "boolean"}, {"description", "Follow taint into function calls"}, {"default", true}}},
              {"steps_offset",           {{"type", "integer"}, {"description", "Pagination: skip first N steps"}, {"default", 0}}},
              {"steps_limit",            {{"type", "integer"}, {"description", "Pagination: max steps per page (max 2000)"}, {"default", 1000}}}
          }},
          {"required", json::array({"reg_index"})}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            TaintConfig cfg;
            cfg.add_source_reg(parse_reg(args.at("reg_index")));
            cfg.source_inst_id = args.value("inst_id", uint64_t(0));
            cfg.propagate_through_calls = args.value("propagate_through_calls", true);
            cfg.max_taint_width = args.value("max_width", uint32_t(0));

            if (args.contains("mem_addrs")) {
                for (const auto& a : args["mem_addrs"]) {
                    cfg.source_mem_addrs.push_back(parse_hex(a.get<std::string>()));
                }
            }
            if (args.contains("stop_pcs")) {
                for (const auto& p : args["stop_pcs"]) {
                    cfg.stop_pcs.push_back(unrebase(parse_hex(p.get<std::string>())));
                }
            }

            tenet::register_pass_by_name(*pm_, "xref");
            pm_->register_pass(std::make_unique<TaintPass>(std::move(cfg)));
            const auto& raw = require_pass_nb(pm_, "taint");
            if (!raw.ok()) throw std::runtime_error("Taint pass failed: " + raw.error_message);
            const auto& result = raw.get<TaintResult>();

            json output;
            output["statistics"] = {
                {"events_count", result.events.size()},
                {"steps_count", result.steps.size()},
                {"instructions_processed", result.instructions_processed},
                {"tainted_memory_count", result.tainted_memory_count()},
                {"kill_events", result.kill_events_count},
                {"call_crossings", result.call_crossings}
            };

            if (!result.stop_reason.empty()) output["stop_reason"] = result.stop_reason;

            std::vector<uint8_t> tainted;
            for (uint64_t m = result.tainted_regs; m; m &= m - 1)
                tainted.push_back(static_cast<uint8_t>(__builtin_ctzll(m)));
            output["tainted_regs_final"] = tainted;

            size_t steps_offset = args.value("steps_offset", size_t(0));
            size_t steps_limit = std::min(args.value("steps_limit", size_t(1000)), size_t(2000));
            json steps_arr = json::array();
            size_t steps_start = std::min(steps_offset, result.steps.size());
            size_t steps_end = std::min(steps_start + steps_limit, result.steps.size());
            for (size_t i = steps_start; i < steps_end; i++) {
                const auto& s = result.steps[i];
                json step = {
                    {"inst_id", s.inst_id},
                    {"pc", fmt::format("0x{:X}", rebase(s.pc))},
                    {"type", propagation_type_str(s.type)},
                    {"triton_resolved", s.triton_resolved}
                };
                if (s.dst_reg != 0xFF) step["dst_reg"] = s.dst_reg;
                if (s.dst_mem_addr != 0) {
                    step["dst_mem"] = fmt::format("0x{:X}", s.dst_mem_addr);
                    step["dst_mem_size"] = s.dst_mem_size;
                }
                steps_arr.push_back(std::move(step));
            }
            output["steps"] = std::move(steps_arr);
            output["total_steps"] = result.steps.size();
            output["steps_offset"] = steps_offset;
            output["steps_returned"] = steps_end - steps_start;
            bool has_more_steps = steps_end < result.steps.size();
            output["has_more_steps"] = has_more_steps;
            if (has_more_steps) output["next_steps_offset"] = steps_end;
            return output;
        }
    );

    // -- taint_backward
    register_tool(
        {"taint_backward",
         "Perform precise backward taint analysis (reverse data-flow). "
         "Starting from a register at a specific instruction (the 'sink'), "
         "walk backward to find all instructions that contributed to "
         "computing that value. Resolves memory-mediated dependencies. "
         "Supports pagination of the events list via events_offset/events_limit "
         "(use has_more_events + next_events_offset to continue).",
         {{"type", "object"},
          {"properties", {
              {"sink_inst_id",  {{"type", "integer"}, {"description", "Instruction ID where the value is observed"}}},
              {"sink_reg",      {{"type", json::array({"integer", "string"})}, {"description", "Sink register: integer index OR name string ('x0','lr','sp', etc.)"}}},
              {"max_steps",     {{"type", "integer"}, {"description", "Max backward walk steps (0=unlimited)"}, {"default", 10000}}},
              {"events_offset", {{"type", "integer"}, {"description", "Pagination: skip first N events"}, {"default", 0}}},
              {"events_limit",  {{"type", "integer"}, {"description", "Pagination: max events per page (max 2000)"}, {"default", 500}}}
          }},
          {"required", json::array({"sink_inst_id", "sink_reg"})}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            BackwardTaintConfig cfg;
            cfg.sink_inst_id = args.at("sink_inst_id").get<uint64_t>();
            cfg.add_sink_reg(parse_reg(args.at("sink_reg")));
            cfg.propagate_through_memory = true;
            cfg.build_dataflow_graph = true;
            cfg.per_sink_tags = true;
            uint64_t max_steps = args.value("max_steps", uint64_t(10000));
            if (max_steps > 0) cfg.max_steps = max_steps;

            pm_->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
            const auto& raw = require_pass_nb(pm_, "backward_taint");
            if (!raw.ok()) throw std::runtime_error("Backward taint failed: " + raw.error_message);
            const auto& result = raw.get<BackwardTaintResult>();

            json output;
            output["contributing_count"] = result.contributing_count();
            output["max_depth"] = result.max_depth;

            std::vector<uint8_t> involved;
            for (uint64_t m = result.all_involved_regs; m; m &= m - 1)
                involved.push_back(static_cast<uint8_t>(__builtin_ctzll(m)));
            output["involved_regs"] = involved;

            size_t events_offset = args.value("events_offset", size_t(0));
            size_t events_limit = std::min(args.value("events_limit", size_t(500)), size_t(2000));
            json events_arr = json::array();
            size_t ev_start = std::min(events_offset, result.events.size());
            size_t ev_end = std::min(ev_start + events_limit, result.events.size());
            for (size_t i = ev_start; i < ev_end; i++) {
                const auto& ev = result.events[i];
                json ev_json = {
                    {"inst_id", ev.inst_id},
                    {"pc", fmt::format("0x{:X}", rebase(ev.pc))},
                    {"dst_reg", ev.dst_reg},
                    {"src_regs", ev.src_regs_list()}
                };
                if (ev.loads_from_memory) {
                    json addrs = json::array();
                    for (auto a : ev.src_mem_addrs) addrs.push_back(fmt::format("0x{:X}", a));
                    ev_json["loads_from"] = std::move(addrs);
                }
                events_arr.push_back(std::move(ev_json));
            }
            output["events"] = std::move(events_arr);
            output["total_events"] = result.events.size();
            output["events_offset"] = events_offset;
            output["events_returned"] = ev_end - ev_start;
            bool has_more_events = ev_end < result.events.size();
            output["has_more_events"] = has_more_events;
            if (has_more_events) output["next_events_offset"] = ev_end;
            return output;
        }
    );

    // -- critical_path
    register_tool(
        {"critical_path",
         "Compute the critical data-flow path: intersection of forward taint "
         "from a source and backward taint from a sink. Returns exactly the "
         "instruction sequence that transforms source data into the sink value.",
         {{"type", "object"},
          {"properties", {
              {"source_reg",     {{"type", json::array({"integer", "string"})}, {"description", "Source register: integer index (0=x0,29=fp,30=lr,31=sp,33=pc) OR name string ('x0','lr','sp', etc.)"}}},
              {"source_inst_id", {{"type", "integer"}, {"description", "Source instruction ID"}}},
              {"sink_reg",       {{"type", json::array({"integer", "string"})}, {"description", "Sink register: integer index OR name string"}}},
              {"sink_inst_id",   {{"type", "integer"}, {"description", "Sink instruction ID"}}}
          }},
          {"required", json::array({"source_reg", "source_inst_id", "sink_reg", "sink_inst_id"})}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            uint8_t source_reg = parse_reg(args.at("source_reg"));
            uint64_t source_inst = args.at("source_inst_id").get<uint64_t>();
            uint8_t sink_reg = parse_reg(args.at("sink_reg"));
            uint64_t sink_inst = args.at("sink_inst_id").get<uint64_t>();

            TaintConfig ft_cfg;
            ft_cfg.add_source_reg(source_reg);
            ft_cfg.source_inst_id = source_inst;
            tenet::register_pass_by_name(*pm_, "xref");
            pm_->register_pass(std::make_unique<TaintPass>(std::move(ft_cfg)));

            BackwardTaintConfig bt_cfg;
            bt_cfg.sink_inst_id = sink_inst;
            bt_cfg.add_sink_reg(sink_reg);
            bt_cfg.propagate_through_memory = true;
            pm_->register_pass(std::make_unique<BackwardTaintPass>(std::move(bt_cfg)));

            const auto& ft_raw = require_pass_nb(pm_, "taint");
            const auto& bt_raw = require_pass_nb(pm_, "backward_taint");
            if (!ft_raw.ok()) throw std::runtime_error("Forward taint failed");
            if (!bt_raw.ok()) throw std::runtime_error("Backward taint failed");

            const auto& ft = ft_raw.get<TaintResult>();
            const auto& bt = bt_raw.get<BackwardTaintResult>();
            auto cp = bt.critical_path(ft);

            json output;
            output["critical_path_count"] = cp.cardinality();
            output["backward_count"] = bt.contributing_count();
            output["forward_count"] = ft.tainted_inst_count();
            json ids = json::array();
            uint64_t count = 0;
            for (auto it = cp.begin(); it != cp.end() && count < 200; ++it, ++count) {
                ids.push_back(*it);
            }
            output["instruction_ids"] = std::move(ids);
            if (cp.cardinality() > 200) output["truncated"] = true;
            return output;
        }
    );
}

// =====================================================================
// Graph tools (CFG, call graph, dataflow graph)
// =====================================================================

void TenetMcpService::register_graph_tools() {
    // -- cfg_export
    register_tool(
        {"cfg_export",
         "Export the Control Flow Graph. Returns DOT or JSON format.",
         {{"type", "object"},
          {"properties", {
              {"format", {{"type", "string"}, {"description", "\"dot\" or \"json\""}, {"default", "json"}}}
          }}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");
            std::string format = args.value("format", "json");

            tenet::register_pass_by_name(*pm_, "xref");
            tenet::register_pass_by_name(*pm_, "cfg");
            tenet::register_pass_by_name(*pm_, "cfg_layout");

            const auto& raw = require_pass_nb(pm_, "cfg_layout");
            if (!raw.ok()) throw std::runtime_error("CFG pass failed: " + raw.error_message);
            const auto& layout = raw.get<CFGLayoutResult>();

            if (format == "dot") {
                return {{"format", "dot"}, {"dot", layout.dot_annotated}};
            }

            // Pull execution counts / instruction PCs / edge kind from the
            // underlying CFGResult (cfg_layout only carries geometry).
            const auto& cfg_raw = require_pass_nb(pm_, "cfg");
            const CFGResult* cfg = (cfg_raw.ok()) ? &cfg_raw.get<CFGResult>() : nullptr;

            // Cap per-block disassembly preview: large CFGs would otherwise
            // produce a huge JSON payload just for text nobody scrolls to.
            constexpr size_t kMaxDisasmLines = 24;
            constexpr size_t kMaxBlocksForDisasm = 500;
            bool emit_disasm = cfg && cfg->blocks.size() <= kMaxBlocksForDisasm;

            static const char* kArrowNames[] = {"down", "left", "up", "right", "none"};
            auto arrow_name = [](GraphEdge::ArrowDirection a) -> const char* {
                auto idx = static_cast<size_t>(a);
                return idx < 5 ? kArrowNames[idx] : "down";
            };

            json blocks = json::array();
            for (const auto& [pc, bl] : layout.block_layouts) {
                json block = {{"pc", fmt::format("0x{:X}", rebase(pc))},
                              {"x", bl.x}, {"y", bl.y},
                              {"width", bl.width}, {"height", bl.height}};

                if (cfg) {
                    auto it = cfg->blocks.find(pc);
                    if (it != cfg->blocks.end()) {
                        const auto& blk = it->second;
                        block["executions"] = blk.execution_count;
                        if (emit_disasm && code_table_ && decoder_) {
                            json disasm = json::array();
                            size_t n = 0;
                            for (uint64_t insn_pc : blk.instructions) {
                                if (n++ >= kMaxDisasmLines) break;
                                auto opcode = code_table_->opcode_at(insn_pc);
                                std::string line;
                                if (opcode) {
                                    auto d = decoder_->decode(insn_pc, *opcode);
                                    if (d) {
                                        line = fmt::format("0x{:x}  {} {}", rebase(insn_pc), d->mnemonic, d->op_str);
                                    } else {
                                        line = fmt::format("0x{:x}  .word 0x{:08x}", rebase(insn_pc), *opcode);
                                    }
                                } else {
                                    line = fmt::format("0x{:x}  <no code>", rebase(insn_pc));
                                }
                                disasm.push_back(std::move(line));
                            }
                            block["disasm"] = std::move(disasm);
                        }
                    }
                }
                blocks.push_back(std::move(block));
            }

            json edges = json::array();
            for (const auto& el : layout.edge_layouts) {
                json edge = {
                    {"from", fmt::format("0x{:X}", rebase(el.from_block))},
                    {"to",   fmt::format("0x{:X}", rebase(el.to_block))},
                    {"arrow", arrow_name(el.arrow)}
                };
                if (cfg) {
                    // O(1) lookup via cfg's adjacency index instead of an O(E) linear
                    // scan per layout edge (which would make this loop O(E^2)).
                    for (const auto* e : cfg->successors(el.from_block)) {
                        if (e->to_block == el.to_block) {
                            edge["taken_count"] = e->taken_count;
                            edge["kind"] = e->is_fallthrough ? "fallthrough" : "branch";
                            break;
                        }
                    }
                }
                edges.push_back(std::move(edge));
            }
            return {{"format", "json"}, {"blocks", std::move(blocks)}, {"edges", std::move(edges)}};
        }
    );

    // -- call_graph
    register_tool(
        {"call_graph",
         "Generate the function call graph. Returns nodes (functions) and "
         "edges (call relationships) with call counts.",
         {{"type", "object"},
          {"properties", {
              {"format", {{"type", "string"}, {"description", "\"dot\" or \"json\""}, {"default", "json"}}}
          }}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            tenet::register_pass_by_name(*pm_, "function");
            tenet::register_pass_by_name(*pm_, "call_graph");

            const auto& raw = require_pass_nb(pm_, "call_graph");
            if (!raw.ok()) throw std::runtime_error("Call graph failed: " + raw.error_message);
            const auto& cg = raw.get<CallGraphResult>();

            // Root pseudo-node keys (see tenet::call_graph_is_root_key()) are
            // tagged call-site PCs, not real function addresses — rebase()
            // (runtime_pc - slide + image_base) would corrupt the tag bit's
            // arithmetic and print a meaningless address. Render those as
            // "root@<rebased call-site pc>" instead; rebase only the real
            // (untagged) call-site component.
            auto pc_str = [this](uint64_t pc) -> std::string {
                if (tenet::call_graph_is_root_key(pc))
                    return fmt::format("root@0x{:X}", rebase(tenet::call_graph_root_call_site(pc)));
                return fmt::format("0x{:X}", rebase(pc));
            };

            json nodes = json::array();
            for (const auto& [pc, node] : cg.nodes) {
                nodes.push_back({
                    {"pc",   pc_str(pc)},
                    {"name", node.name.empty() ? fmt::format("sub_{:X}", rebase(pc)) : node.name},
                    {"is_root",        node.is_root},
                    {"calls_made",     node.total_calls_made},
                    {"calls_received", node.total_calls_received}
                });
            }
            json edges = json::array();
            for (const auto& edge : cg.edges) {
                edges.push_back({
                    {"caller", pc_str(edge.caller_pc)},
                    {"callee", pc_str(edge.callee_pc)},
                    {"call_count", edge.call_count}
                });
            }
            return {{"nodes", std::move(nodes)}, {"edges", std::move(edges)}};
        }
    );

    // -- dataflow_graph
    register_tool(
        {"dataflow_graph",
         "Build a data-flow graph for a range of instructions. "
         "Shows producer-consumer relationships between instructions. "
         "Use max_nodes to cap output size for large ranges (default 500). "
         "Prefer small ranges (< 200 instructions) for detailed analysis.",
         {{"type", "object"},
          {"properties", {
              {"start_inst_id", {{"type", "integer"}, {"description", "Start instruction ID"}}},
              {"end_inst_id",   {{"type", "integer"}, {"description", "End instruction ID"}}},
              {"format",        {{"type", "string"}, {"description", "\"json\" or \"dot\""}, {"default", "json"}}},
              {"max_nodes",     {{"type", "integer"}, {"description", "Max nodes in output (default 500, max 5000). Truncates large graphs."}, {"default", 500}}}
          }},
          {"required", json::array({"start_inst_id", "end_inst_id"})}}},
        [this](const json& args) -> json {
            if (!pm_) throw std::runtime_error("PassManager not available");

            DataflowGraphConfig cfg;
            cfg.start_inst_id = args.at("start_inst_id").get<uint64_t>();
            cfg.end_inst_id = args.at("end_inst_id").get<uint64_t>();
            std::string format = args.value("format", "json");
            size_t max_nodes = std::min(args.value("max_nodes", size_t(500)), size_t(5000));

            pm_->register_pass(std::make_unique<DataflowGraphPass>(std::move(cfg)));
            const auto& raw = require_pass_nb(pm_, "dataflow_graph");
            if (!raw.ok()) throw std::runtime_error("Dataflow graph failed: " + raw.error_message);
            const auto& dfg = raw.get<DataflowGraphResult>();

            if (format == "dot") {
                return {{"format", "dot"}, {"dot", dfg.to_dot()}};
            }
            // Parse the full JSON, then truncate nodes array if needed
            json result = json::parse(dfg.to_json());
            if (result.contains("nodes") && result["nodes"].is_array()) {
                size_t node_count = result["nodes"].size();
                if (node_count > max_nodes) {
                    json trimmed = json::array();
                    for (size_t ni = 0; ni < max_nodes; ni++) {
                        trimmed.push_back(result["nodes"][ni]);
                    }
                    result["nodes"] = std::move(trimmed);
                    result["truncated"] = true;
                    result["total_nodes"] = node_count;
                    result["returned_nodes"] = max_nodes;
                }
            }
            return result;
        }
    );
}

}  // namespace tenet

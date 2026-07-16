#include "ws/ws_analysis_jobs.h"

#include "analysis/passes/structure/function_pass.h"
#include "io/mcp/mcp_server.h"
#include "service/tenet_service.h"
#include "ws/ws_protocol.h"

#include "tenet_ws_generated.h"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace tenet {

namespace fbs = tenet::ws;

std::string build_get_call_stack_reply_bytes(TenetService& service,
                                             uint32_t msg_id,
                                             uint64_t inst_id) {
    return build_ws_reply_or_error(msg_id, 3, "GetCallStack", [&]() {
        auto* func_result = service.pass_result<FunctionResult>("function");
        if (!func_result) {
            service.ensure_pass_manager();
            if (!service.run_pass("function")) {
                throw std::runtime_error("function pass failed");
            }
            func_result = service.pass_result<FunctionResult>("function");
            if (!func_result) {
                throw std::runtime_error("function pass unavailable");
            }
        }

        flatbuffers::FlatBufferBuilder fbb(1024);
        std::vector<flatbuffers::Offset<fbs::CallStackEntry>> stack_entries;
        std::string current_func_name;

        auto stack = func_result->call_stack_at(inst_id);
        stack_entries.reserve(stack.size());
        for (const auto* evt : stack) {
            std::string fname;
            auto it = func_result->functions.find(evt->target_pc);
            if (it != func_result->functions.end()) {
                fname = it->second.name;
            }
            auto fname_off = fbb.CreateString(fname);
            stack_entries.push_back(fbs::CreateCallStackEntry(
                fbb,
                static_cast<uint32_t>(evt->depth),
                evt->call_inst_id,
                evt->return_inst_id,
                evt->call_site_pc,
                evt->target_pc,
                fname_off));
        }

        const auto* fi = func_result->function_at(inst_id);
        if (fi) current_func_name = fi->name;

        auto stack_vec = fbb.CreateVector(stack_entries);
        auto cfn = fbb.CreateString(current_func_name);
        auto resp = fbs::CreateGetCallStackResponse(fbb, stack_vec, cfn);
        fbb.Finish(resp);
        return build_ws_envelope_bytes(msg_id, fbs::MessageType_GetCallStackResp, fbb);
    });
}

std::string build_get_functions_reply_bytes(TenetService& service,
                                            uint32_t msg_id) {
    return build_ws_reply_or_error(msg_id, 3, "GetFunctions", [&]() {
        auto* func_result = service.pass_result<FunctionResult>("function");
        if (!func_result) {
            service.ensure_pass_manager();
            if (!service.run_pass("function")) {
                throw std::runtime_error("function pass failed");
            }
            func_result = service.pass_result<FunctionResult>("function");
            if (!func_result) {
                throw std::runtime_error("function pass unavailable");
            }
        }

        flatbuffers::FlatBufferBuilder fbb(4096);
        std::vector<flatbuffers::Offset<fbs::FunctionEntry>> func_entries;
        func_entries.reserve(func_result->functions.size());
        for (const auto& [pc, info] : func_result->functions) {
            auto name_off = fbb.CreateString(info.name);
            func_entries.push_back(fbs::CreateFunctionEntry(
                fbb, pc, name_off,
                static_cast<uint32_t>(info.total_calls),
                info.total_instructions));
        }

        auto fv = fbb.CreateVector(func_entries);
        auto resp = fbs::CreateGetFunctionsResponse(fbb, fv);
        fbb.Finish(resp);
        return build_ws_envelope_bytes(msg_id, fbs::MessageType_GetFunctionsResp, fbb);
    });
}

std::string build_search_forward_reply_bytes(TenetService& service,
                                             uint32_t msg_id,
                                             const std::string& query,
                                             uint64_t from_inst) {
    return build_search_forward_reply_bytes(msg_id, [&]() {
        return service.search_forward(query, from_inst);
    });
}

std::string build_run_analysis_reply_bytes(TenetMcpService& dispatcher,
                                           uint32_t msg_id,
                                           const std::string& tool_name,
                                           const std::string& params_json) {
    bool ok = true;
    std::string error;
    std::string json_out;

    try {
        nlohmann::json args = nlohmann::json::object();
        if (!params_json.empty()) {
            args = nlohmann::json::parse(params_json);
            if (!args.is_object()) args = nlohmann::json::object();
        }
        nlohmann::json result = dispatcher.call_tool(tool_name, args);
        json_out = result.dump();
    } catch (const std::exception& e) {
        ok = false;
        error = e.what();
    } catch (...) {
        ok = false;
        error = "unknown exception";
    }

    flatbuffers::FlatBufferBuilder fbb(json_out.size() + 256);
    auto name_off = fbb.CreateString(tool_name);
    auto err_off = fbb.CreateString(error);
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> data_off = 0;
    if (ok && !json_out.empty()) {
        data_off = fbb.CreateVector(
            reinterpret_cast<const uint8_t*>(json_out.data()), json_out.size());
    }
    auto resp = fbs::CreateRunAnalysisResponse(fbb, name_off, ok, data_off, err_off);
    fbb.Finish(resp);
    return build_ws_envelope_bytes(msg_id, fbs::MessageType_RunAnalysisResp, fbb);
}

}  // namespace tenet

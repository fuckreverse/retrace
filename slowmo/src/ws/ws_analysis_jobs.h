#pragma once

#include "ws/ws_protocol.h"

#include <cstdint>
#include <string>
#include <utility>

namespace tenet {

class TenetService;
class TenetMcpService;
namespace fbs = tenet::ws;

// These helpers build the final bytes sent by WS handlers.
// Callers serialize only the jobs that need exclusive pass-manager / MCP access.
// SearchForward is intentionally safe to run without analysis_mutex_: it snapshots
// the pinned xref result under TenetService::state_mutex_ and fetch_row() uses its
// own row-cache mutex.
std::string build_get_call_stack_reply_bytes(TenetService& service,
                                             uint32_t msg_id,
                                             uint64_t inst_id);

std::string build_get_functions_reply_bytes(TenetService& service,
                                            uint32_t msg_id);

template <typename Fn>
std::string build_search_forward_reply_bytes(uint32_t msg_id,
                                             Fn&& run_search);

std::string build_search_forward_reply_bytes(TenetService& service,
                                             uint32_t msg_id,
                                             const std::string& query,
                                             uint64_t from_inst);

std::string build_run_analysis_reply_bytes(TenetMcpService& dispatcher,
                                           uint32_t msg_id,
                                           const std::string& tool_name,
                                           const std::string& params_json);

template <typename Fn>
std::string build_search_forward_reply_bytes(uint32_t msg_id,
                                             Fn&& run_search) {
    return build_ws_reply_or_error(msg_id, 3, "SearchForward", [&]() {
        auto results = std::forward<Fn>(run_search)();
        flatbuffers::FlatBufferBuilder fbb(results.size() * 8 + 64);
        auto rv = fbb.CreateVector(results.data(), results.size());
        auto resp = fbs::CreateSearchForwardResponse(
            fbb, rv, static_cast<uint32_t>(results.size()));
        fbb.Finish(resp);
        return build_ws_envelope_bytes(msg_id, fbs::MessageType_SearchForwardResp, fbb);
    });
}

}  // namespace tenet

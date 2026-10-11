// slowmo/src/ws/ws_handlers_nav.cpp
//
// Navigation, bookmark, trace-info, and search WebSocket handlers.
// SearchForward computes on a worker thread and only sends on the uWS loop;
// the other handlers remain synchronous on the event loop thread.
#include "ws/tenet_ws_service.h"
#include "io/trace_reader.h"
#include "ws/ws_analysis_jobs.h"
#include "ws/ws_async_reply_dispatcher.h"
#include "ws/ws_protocol.h"

// uWebSockets includes (only in .cpp, not in header)
#include <App.h>

// FlatBuffers generated header
#include "tenet_ws_generated.h"

#include <cstring>
#include <vector>

namespace tenet {

using namespace tenet::ws;  // FlatBuffers namespace

// Per-socket user data (uWS template parameter) — mirrors tenet_ws_service.cpp.
struct PerSocketData {};

namespace {

/// Wrap a finished payload FlatBuffer in a ws::Envelope and send it over the
/// WebSocket connection.
void send_envelope(void* ws, uint32_t msg_id, MessageType type,
                    flatbuffers::FlatBufferBuilder& fbb) {
    auto bytes = build_ws_envelope_bytes(msg_id, type, fbb);
    auto sv = std::string_view(bytes.data(), bytes.size());
    static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws)->send(sv, uWS::BINARY);
}

}  // namespace

// ─── Navigation ──────────────────────────────────────────────────────────────

void TenetWSService::handle_navigate(void* ws, uint32_t msg_id,
                                      const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "Navigate: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<NavigateRequest>(payload);
    uint64_t inst_id = req->inst_id();

    service_.navigate_to(inst_id);

    flatbuffers::FlatBufferBuilder fbb(64);
    auto resp = CreateNavigateResponse(fbb, service_.current_inst());
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_NavigateResp, fbb);
}

void TenetWSService::handle_nav_back(void* ws, uint32_t msg_id) {
    bool ok = service_.can_nav_back();
    if (ok) {
        service_.nav_back();
    }

    flatbuffers::FlatBufferBuilder fbb(64);
    auto resp = CreateNavBackResponse(fbb, service_.current_inst(), ok);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_NavBackResp, fbb);
}

void TenetWSService::handle_nav_forward(void* ws, uint32_t msg_id) {
    bool ok = service_.can_nav_forward();
    if (ok) {
        service_.nav_forward();
    }

    flatbuffers::FlatBufferBuilder fbb(64);
    auto resp = CreateNavForwardResponse(fbb, service_.current_inst(), ok);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_NavForwardResp, fbb);
}

// ─── Bookmarks ───────────────────────────────────────────────────────────────

void TenetWSService::handle_toggle_bookmark(void* ws, uint32_t msg_id,
                                              const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "ToggleBookmark: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<ToggleBookmarkRequest>(payload);
    uint64_t inst_id = req->inst_id();

    service_.toggle_bookmark(inst_id);

    auto bm = service_.bookmarks();
    flatbuffers::FlatBufferBuilder fbb(64 + bm.size() * 8);
    auto bm_vec = fbb.CreateVector(bm.data(), bm.size());
    auto resp = CreateToggleBookmarkResponse(fbb, bm_vec);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_ToggleBookmarkResp, fbb);
}

void TenetWSService::handle_get_bookmarks(void* ws, uint32_t msg_id) {
    auto bm = service_.bookmarks();
    flatbuffers::FlatBufferBuilder fbb(64 + bm.size() * 8);
    auto bm_vec = fbb.CreateVector(bm.data(), bm.size());
    auto resp = CreateGetBookmarksResponse(fbb, bm_vec);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_GetBookmarksResp, fbb);
}

// ─── Trace Info ──────────────────────────────────────────────────────────────

void TenetWSService::handle_get_trace_info(void* ws, uint32_t msg_id) {
    const auto& hdr = service_.reader().header();

    flatbuffers::FlatBufferBuilder fbb(512);
    auto module_name = fbb.CreateString(hdr.module_name);
    auto trace_path = fbb.CreateString(service_.trace_path());

    auto resp = CreateGetTraceInfoResponse(
        fbb,
        service_.total_inst(),
        service_.current_inst(),
        module_name,
        hdr.module_base,
        hdr.module_slide,
        trace_path,
        hdr.version,
        static_cast<uint8_t>(hdr.target_os),
        hdr.has_fpr(),
        hdr.has_code(),
        hdr.num_gpr);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_GetTraceInfoResp, fbb);
}

// ─── Search ──────────────────────────────────────────────────────────────────

void TenetWSService::handle_search_forward(void* ws, uint32_t msg_id,
                                            const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "SearchForward: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<SearchForwardRequest>(payload);
    std::string query = req->query() ? req->query()->str() : "";
    uint64_t from = req->from_inst();

    auto token = async_reply_dispatcher_ ? async_reply_dispatcher_->token_for(ws)
                                         : WSAsyncReplyDispatcher::ConnectionToken{};
    if (!token.valid()) {
        send_error(ws, msg_id, 3, "SearchForward: connection unavailable");
        return;
    }
    if (async_reply_dispatcher_->is_stopping()) {
        send_error(ws, msg_id, 4, "SearchForward: server is shutting down");
        return;
    }

    bool enqueued = async_reply_dispatcher_->dispatch(
        token,
        [this, msg_id, query = std::move(query), from]() mutable {
            return build_search_forward_reply_bytes(service_, msg_id, query, from);
        });
    if (!enqueued) {
        send_error(ws, msg_id, 4, "SearchForward: server is shutting down");
    }
}

void TenetWSService::handle_search_clear(void* ws, uint32_t msg_id) {
    service_.search_clear();

    auto bytes = build_ws_envelope_bytes(msg_id, MessageType_SearchClearResp,
                                         static_cast<const uint8_t*>(nullptr), 0);
    auto sv = std::string_view(bytes.data(), bytes.size());
    static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws)->send(sv, uWS::BINARY);
}

void TenetWSService::handle_get_search_results(void* ws, uint32_t msg_id) {
    auto results = service_.search_results();

    flatbuffers::FlatBufferBuilder fbb(results.size() * 8 + 64);
    auto rv = fbb.CreateVector(results.data(), results.size());
    auto resp = CreateGetSearchResultsResponse(
        fbb, rv,
        static_cast<uint32_t>(service_.search_current()),
        service_.search_active());
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_GetSearchResultsResp, fbb);
}

}  // namespace tenet

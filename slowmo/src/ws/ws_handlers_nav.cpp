// tools/tenet/src/ws/ws_handlers_nav.cpp
//
// Navigation, bookmark, trace-info, and search WebSocket handlers.
// All handlers are synchronous (run on the uWS event loop thread).
#include "ws/tenet_ws_service.h"
#include "common/types.h"
#include "io/trace_reader.h"

// uWebSockets includes (only in .cpp, not in header)
#include <App.h>

// FlatBuffers generated header
#include "tenet_ws_generated.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace tenet {

using namespace tenet::ws;  // FlatBuffers namespace

// Per-socket user data (uWS template parameter) — mirrors tenet_ws_service.cpp.
struct PerSocketData {};

namespace {

/// Wrap a finished inner FlatBufferBuilder payload in an Envelope and send it
/// over the WebSocket connection.  Same pattern as ws_handlers_hotpath.cpp.
void send_envelope(void* ws, uint32_t msg_id, MessageType type,
                    flatbuffers::FlatBufferBuilder& fbb) {
    flatbuffers::FlatBufferBuilder env_fbb(fbb.GetSize() + 64);
    auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
    auto env = CreateEnvelope(env_fbb, msg_id, type, pv);
    env_fbb.Finish(env);

    auto sv = std::string_view(
        reinterpret_cast<const char*>(env_fbb.GetBufferPointer()),
        env_fbb.GetSize());
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

    auto& bm = service_.bookmarks();
    flatbuffers::FlatBufferBuilder fbb(64 + bm.size() * 8);
    auto bm_vec = fbb.CreateVector(bm.data(), bm.size());
    auto resp = CreateToggleBookmarkResponse(fbb, bm_vec);
    fbb.Finish(resp);

    send_envelope(ws, msg_id, MessageType_ToggleBookmarkResp, fbb);
}

void TenetWSService::handle_get_bookmarks(void* ws, uint32_t msg_id) {
    auto& bm = service_.bookmarks();
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

    // Synchronous: blocks the event loop for the duration of the search.
    // This is intentional — TenetService is not thread-safe, so dispatching
    // to a worker thread would race with other handlers touching service_
    // state (row cache, search results, register file, etc.).
    // TODO: async search requires TenetService-level locking or a
    //       copy-on-write snapshot mechanism before it can be safely
    //       offloaded to a background thread.
    service_.search_forward(query, from);

    auto& results = service_.search_results();
    flatbuffers::FlatBufferBuilder fbb(results.size() * 8 + 64);
    auto rv = fbb.CreateVector(results.data(), results.size());
    auto resp = CreateSearchForwardResponse(fbb, rv,
                                             static_cast<uint32_t>(results.size()));
    fbb.Finish(resp);
    send_envelope(ws, msg_id, MessageType_SearchForwardResp, fbb);
}

void TenetWSService::handle_search_clear(void* ws, uint32_t msg_id) {
    service_.search_clear();

    // No response body defined in the schema — send an empty envelope.
    flatbuffers::FlatBufferBuilder fbb(32);
    fbb.Finish(CreateEnvelope(fbb, msg_id, MessageType_SearchClearResp, 0));

    auto sv = std::string_view(
        reinterpret_cast<const char*>(fbb.GetBufferPointer()),
        fbb.GetSize());
    static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws)->send(sv, uWS::BINARY);
}

void TenetWSService::handle_get_search_results(void* ws, uint32_t msg_id) {
    auto& results = service_.search_results();

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

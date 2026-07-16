// tools/tenet/src/ws/ws_handlers_analysis.cpp
//
// Pass management and data query WebSocket handlers.
// analysis_mutex_ only serializes heavy analysis jobs (pass execution / MCP
// tool dispatch). Light handlers rely on TenetService's internal locks
// (state_mutex_ / row_cache_mutex_) and backend thread safety guarantees.

#include "ws/tenet_ws_service.h"
#include "common/progress_manager.h"
#include "analysis/pass_manager.h"
#include "core/memory_model.h"
#include "io/mcp/mcp_server.h"  // TenetMcpService::call_tool for generic channel
#include "ws/ws_analysis_jobs.h"
#include "ws/ws_analysis_task_queue.h"
#include "ws/ws_async_reply_dispatcher.h"
#include "ws/ws_protocol.h"

// uWebSockets
#include <App.h>

// FlatBuffers generated header
#include "tenet_ws_generated.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace tenet {

// Use namespace alias — `using namespace tenet::ws` would clash with
// tenet::PassState, tenet::CallStackEntry, tenet::FunctionEntry, etc.
namespace fbs = tenet::ws;

struct PerSocketData {};

namespace {

void send_envelope(void* ws_ptr, uint32_t msg_id, fbs::MessageType type,
                    flatbuffers::FlatBufferBuilder& fbb) {
    auto bytes = build_ws_envelope_bytes(msg_id, type, fbb);
    auto sv = std::string_view(bytes.data(), bytes.size());
    static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws_ptr)->send(sv, uWS::BINARY);
}

}  // namespace

// ─── Pass Management ────────────────────────────────────────────────────────

void TenetWSService::handle_run_pass(void* ws, uint32_t msg_id,
                                      const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "RunPass: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<fbs::RunPassRequest>(payload);
    std::string name = req->name() ? req->name()->str() : "";
    if (name.empty()) {
        send_error(ws, msg_id, 2, "RunPass: empty pass name");
        return;
    }

    // Build PassRunCtx from request fields
    PassRunCtx ctx{};
    ctx.current_inst = service_.current_inst();
    ctx.total_inst   = service_.total_inst();
    if (req->taint_inst_id() != 0) {
        ctx.current_inst = req->taint_inst_id();
    }
    if (req->taint_regs() && req->taint_regs()->size() > 0) {
        ctx.current_reg = static_cast<uint8_t>((*req->taint_regs())[0]);
    }

    // Enqueue the analysis task BEFORE sending "accepted". If the intake
    // gate is closed (shutdown in progress), reject immediately — no
    // "accepted but never ran" gap.
    //
    // The lambda captures `name` by copy (not move) so that `name` remains
    // valid for the accepted reply and progress tracking below.  Pass names
    // are short strings; the extra copy is negligible.
    bool enqueued = analysis_task_queue_ && analysis_task_queue_->enqueue(
        [this, name, ctx]() {
            std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
            service_.run_pass(name, ctx);
        });

    if (!enqueued) {
        send_error(ws, msg_id, 4, "RunPass: server is shutting down");
        return;
    }

    ProgressManager::global().start("pass:" + name, "pass", name, 0, "queued");
    flatbuffers::FlatBufferBuilder fbb(256);
    auto name_off = fbb.CreateString(name);
    auto msg_off = fbb.CreateString("accepted");
    auto resp = fbs::CreateRunPassResponse(fbb, name_off, true, msg_off);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_RunPassResp, fbb);
}

void TenetWSService::handle_run_default_passes(void* ws, uint32_t msg_id) {
    // Enqueue BEFORE sending "accepted" — if shutting down, reject immediately.
    bool enqueued = analysis_task_queue_ && analysis_task_queue_->enqueue([this]() {
        std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
        service_.run_default_passes();
    });

    if (!enqueued) {
        send_error(ws, msg_id, 4, "RunDefaultPasses: server is shutting down");
        return;
    }

    flatbuffers::FlatBufferBuilder fbb(64);
    auto msg_off = fbb.CreateString("accepted");
    auto resp = fbs::CreateRunDefaultPassesResponse(fbb, true, msg_off);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_RunDefaultPassesResp, fbb);
}

void TenetWSService::handle_clear_analysis(void* ws, uint32_t msg_id) {
    std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
    service_.clear_analysis();

    flatbuffers::FlatBufferBuilder fbb(32);
    auto resp = fbs::CreateClearAnalysisResponse(fbb, true);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_ClearAnalysisResp, fbb);
}

void TenetWSService::handle_get_pass_result(void* ws, uint32_t msg_id,
                                             const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "GetPassResult: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<fbs::GetPassResultRequest>(payload);
    std::string name = req->name() ? req->name()->str() : "";
    std::string format = req->format() ? req->format()->str() : "json";

    auto* pm = service_.pass_manager();
    if (!pm) {
        send_error(ws, msg_id, 3, "PassManager not initialized");
        return;
    }

    auto sp = pm->require_shared(name);
    if (!sp || !sp->ok()) {
        send_error(ws, msg_id, 3, "Pass '" + name + "' not available");
        return;
    }

    // Stub JSON response — full pass result serialization is complex
    // (25+ result types). Will reuse MCP tool handlers' JSON serialization.
    std::string json_stub = "{\"pass\":\"" + name + "\",\"status\":\"completed\"}";

    flatbuffers::FlatBufferBuilder fbb(json_stub.size() + 256);
    auto name_off = fbb.CreateString(name);
    auto format_off = fbb.CreateString(format);
    auto data_vec = fbb.CreateVector(
        reinterpret_cast<const uint8_t*>(json_stub.data()), json_stub.size());
    auto resp = fbs::CreateGetPassResultResponse(fbb, name_off, format_off,
                                                  data_vec, false, 0);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_GetPassResultResp, fbb);
}

void TenetWSService::handle_get_progress(void* ws, uint32_t msg_id) {
    flatbuffers::FlatBufferBuilder fbb(2048);
    std::vector<flatbuffers::Offset<fbs::ProgressTaskMsg>> entries;
    const auto tasks = ProgressManager::global().snapshot();
    entries.reserve(tasks.size());
    for (const auto& task : tasks) {
        entries.push_back(fbs::CreateProgressTaskMsg(
            fbb, fbb.CreateString(task.id), fbb.CreateString(task.kind),
            fbb.CreateString(task.label), fbb.CreateString(task.phase),
            fbb.CreateString(ProgressManager::state_name(task.state)), task.progress,
            task.completed, task.total, fbb.CreateString(task.message),
            fbb.CreateString(task.error), task.revision));
    }
    auto resp = fbs::CreateGetProgressResponse(fbb, fbb.CreateVector(entries));
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_GetProgressResp, fbb);
}

void TenetWSService::handle_get_pass_catalog(void* ws, uint32_t msg_id) {
    auto* pm = service_.pass_manager();

    flatbuffers::FlatBufferBuilder fbb(1024);
    std::vector<flatbuffers::Offset<fbs::PassCatalogEntry>> entries;

    if (pm) {
        std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
        auto passes = pm->all_passes();
        entries.reserve(passes.size());
        for (auto pass_name : passes) {
            auto pm_state = pm->state(pass_name);
            fbs::PassState fb_state = fbs::PassState_NotRun;
            switch (pm_state) {
            case PassManager::PassState::NotRun:    fb_state = fbs::PassState_NotRun; break;
            case PassManager::PassState::Running:   fb_state = fbs::PassState_Running; break;
            case PassManager::PassState::Completed: fb_state = fbs::PassState_Completed; break;
            case PassManager::PassState::Failed:    fb_state = fbs::PassState_Failed; break;
            }
            auto name_off = fbb.CreateString(pass_name.data(), pass_name.size());
            auto display_off = fbb.CreateString(pass_name.data(), pass_name.size());
            auto cat_off = fbb.CreateString("");
            entries.push_back(fbs::CreatePassCatalogEntry(fbb, name_off, display_off,
                                                           cat_off, fb_state));
        }
    }

    auto entries_vec = fbb.CreateVector(entries);
    auto resp = fbs::CreateGetPassCatalogResponse(fbb, entries_vec);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_GetPassCatalogResp, fbb);
}

// ─── Data Queries ───────────────────────────────────────────────────────────

void TenetWSService::handle_get_call_stack(void* ws, uint32_t msg_id,
                                            const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "GetCallStack: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<fbs::GetCallStackRequest>(payload);
    uint64_t inst_id = req->inst_id();

    auto token = async_reply_dispatcher_ ? async_reply_dispatcher_->token_for(ws)
                                         : WSAsyncReplyDispatcher::ConnectionToken{};
    if (!token.valid()) {
        send_error(ws, msg_id, 3, "GetCallStack: connection unavailable");
        return;
    }

    bool enqueued = async_reply_dispatcher_->dispatch(token, [this, msg_id, inst_id]() {
        std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
        return build_get_call_stack_reply_bytes(service_, msg_id, inst_id);
    });
    if (!enqueued) {
        send_error(ws, msg_id, 4, "GetCallStack: server is shutting down");
    }
}

void TenetWSService::handle_get_last_writer(void* ws, uint32_t msg_id,
                                             const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "GetLastWriter: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<fbs::GetLastWriterRequest>(payload);
    uint64_t addr = req->addr();
    uint32_t size = req->size();
    uint64_t before = req->before_inst();

    uint64_t writer = service_.memory().last_writer(
        addr, static_cast<uint8_t>(std::min(size, 8u)), before);

    flatbuffers::FlatBufferBuilder fbb(64);
    auto resp = fbs::CreateGetLastWriterResponse(fbb, writer);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_GetLastWriterResp, fbb);
}

void TenetWSService::handle_get_write_history(void* ws, uint32_t msg_id,
                                               const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "GetWriteHistory: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<fbs::GetWriteHistoryRequest>(payload);
    uint64_t addr = req->addr();
    uint32_t size = req->size();
    uint32_t offset = req->offset();
    uint32_t limit = std::min(req->limit(), 10000u);

    auto all_writers = service_.memory().write_history(
        addr, static_cast<uint8_t>(std::min(size, 8u)));

    // Apply offset + limit pagination
    bool has_more = false;
    uint32_t next_offset = 0;
    std::vector<uint64_t> page;
    if (offset < all_writers.size()) {
        auto end = std::min(static_cast<size_t>(offset + limit), all_writers.size());
        page.assign(all_writers.begin() + offset, all_writers.begin() + end);
        has_more = end < all_writers.size();
        next_offset = static_cast<uint32_t>(end);
    }

    flatbuffers::FlatBufferBuilder fbb(page.size() * 8 + 64);
    auto wv = fbb.CreateVector(page.data(), page.size());
    auto resp = fbs::CreateGetWriteHistoryResponse(fbb, wv, has_more, next_offset);
    fbb.Finish(resp);
    send_envelope(ws, msg_id, fbs::MessageType_GetWriteHistoryResp, fbb);
}

void TenetWSService::handle_get_functions(void* ws, uint32_t msg_id) {
    auto token = async_reply_dispatcher_ ? async_reply_dispatcher_->token_for(ws)
                                         : WSAsyncReplyDispatcher::ConnectionToken{};
    if (!token.valid()) {
        send_error(ws, msg_id, 3, "GetFunctions: connection unavailable");
        return;
    }

    bool enqueued = async_reply_dispatcher_->dispatch(token, [this, msg_id]() {
        std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
        return build_get_functions_reply_bytes(service_, msg_id);
    });
    if (!enqueued) {
        send_error(ws, msg_id, 4, "GetFunctions: server is shutting down");
    }
}

// ─── Generic Analysis Channel ───────────────────────────────────────────────
//
// Dispatches to any registered analysis tool by name via the in-process MCP
// service (call_tool), then returns the tool's JSON result as raw bytes. This
// covers every MCP analysis capability over WS without a bespoke message type.

void TenetWSService::handle_run_analysis(void* ws, uint32_t msg_id,
                                          const uint8_t* payload, size_t len) {
    if (!payload || len == 0) {
        send_error(ws, msg_id, 2, "RunAnalysis: missing payload");
        return;
    }
    auto* req = flatbuffers::GetRoot<fbs::RunAnalysisRequest>(payload);
    std::string tool_name = req->tool_name() ? req->tool_name()->str() : "";
    std::string params_json = req->params_json() ? req->params_json()->str() : "";

    if (tool_name.empty()) {
        send_error(ws, msg_id, 2, "RunAnalysis: empty tool_name");
        return;
    }
    if (!mcp_dispatch_) {
        send_error(ws, msg_id, 3, "RunAnalysis: dispatcher unavailable");
        return;
    }

    auto token = async_reply_dispatcher_ ? async_reply_dispatcher_->token_for(ws)
                                         : WSAsyncReplyDispatcher::ConnectionToken{};
    if (!token.valid()) {
        send_error(ws, msg_id, 3, "RunAnalysis: connection unavailable");
        return;
    }

    bool enqueued = async_reply_dispatcher_->dispatch(token, [this,
                                              msg_id,
                                              tool_name = std::move(tool_name),
                                              params_json = std::move(params_json)]() mutable {
        std::lock_guard<std::mutex> analysis_lock(analysis_mutex_);
        return build_run_analysis_reply_bytes(*mcp_dispatch_, msg_id, tool_name, params_json);
    });
    if (!enqueued) {
        send_error(ws, msg_id, 4, "RunAnalysis: server is shutting down");
    }
}

}  // namespace tenet

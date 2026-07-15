// tools/tenet/src/ws/tenet_ws_service.cpp
#include "ws/tenet_ws_service.h"
#include "common/logger.h"
#include "io/mcp/mcp_server.h"  // TenetMcpService — in-process tool dispatcher

// uWebSockets includes (only in .cpp, not in header)
#include <App.h>

// FlatBuffers generated header
#include "tenet_ws_generated.h"

#include <fmt/format.h>

namespace tenet {

using namespace tenet::ws;  // FlatBuffers namespace

// Per-socket user data (uWS template parameter)
struct PerSocketData {};

// ─── Construction / Destruction ─────────────────────────────────────────────

TenetWSService::TenetWSService(TenetService& service)
    : service_(service) {
    service_.add_observer(this);
    // Build an in-process MCP dispatcher over the same backend. No transport is
    // started; we only use its call_tool() registry for the generic RunAnalysis
    // channel. Runs synchronously on the event loop thread like other handlers.
    mcp_dispatch_ = std::make_unique<TenetMcpService>(service_);
}

TenetWSService::~TenetWSService() {
    stop();
    service_.remove_observer(this);
}

// ─── Start / Stop ───────────────────────────────────────────────────────────

uint16_t TenetWSService::start(uint16_t port) {
    if (running_.load()) return port_.load();

    // Initialize the shared pass engine before any WS worker or event-loop
    // handler can access it concurrently.
    service_.ensure_pass_manager();
    loop_thread_ = std::thread([this, port]() {
        event_loop_main(port);
    });

    // Wait for the event loop thread to finish setup (success or failure).
    while (!ready_.load() && loop_thread_.joinable()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return port_.load();
}

void TenetWSService::stop() {
    if (!running_.load()) return;
    running_.store(false);

    // Close the listen socket and all client connections from the event loop thread
    auto* loop_ptr = loop_.load();
    if (loop_ptr) {
        auto* loop = static_cast<uWS::Loop*>(loop_ptr);
        loop->defer([this]() {
            if (listen_socket_) {
                us_listen_socket_close(0, listen_socket_);
                listen_socket_ = nullptr;
            }
            // Close all active client connections so app.run() can exit
            for (auto* client : clients_) {
                static_cast<uWS::WebSocket<false, true, PerSocketData>*>(client)->close();
            }
            clients_.clear();
        });
    }

    {
        std::lock_guard<std::mutex> lock(workers_mutex_);
        for (auto& worker : analysis_workers_) worker.wait();
        analysis_workers_.clear();
    }
    if (loop_thread_.joinable()) {
        loop_thread_.join();
    }
    loop_.store(nullptr);
}

// ─── Event Loop ─────────────────────────────────────────────────────────────

void TenetWSService::event_loop_main(uint16_t port) {
    uWS::App app;

    // Assign loop_ BEFORE app.listen() so observer callbacks can use it
    // as soon as running_ becomes true.
    loop_.store(uWS::Loop::get());

    app.ws<PerSocketData>("/*", {
        .compression = uWS::DISABLED,
        .maxPayloadLength = 16 * 1024 * 1024,  // 16 MB
        .maxBackpressure = 64 * 1024 * 1024,    // 64 MB

        .open = [this](auto* ws) {
            clients_.push_back(ws);
            LOG_INFO_M(log::Module::Mcp, "[ws] client connected (total: {})",
                       clients_.size());
        },

        .message = [this](auto* ws, std::string_view data, uWS::OpCode op) {
            if (op != uWS::BINARY) return;  // ignore text frames
            handle_message(ws,
                           reinterpret_cast<const uint8_t*>(data.data()),
                           data.size());
        },

        .close = [this](auto* ws, int /*code*/, std::string_view /*msg*/) {
            clients_.erase(
                std::remove(clients_.begin(), clients_.end(),
                            static_cast<void*>(ws)),
                clients_.end());
            LOG_INFO_M(log::Module::Mcp, "[ws] client disconnected (total: {})",
                       clients_.size());
        },
    });

    app.listen(port, [this, port](us_listen_socket_t* socket) {
        if (socket) {
            listen_socket_ = socket;
            port_.store(us_socket_local_port(0,
                reinterpret_cast<us_socket_t*>(socket)));
            running_.store(true);
            LOG_INFO_M(log::Module::Mcp, "[ws] listening on ws://127.0.0.1:{}",
                       port_.load());
        } else {
            LOG_INFO_M(log::Module::Mcp, "[ws] failed to listen on port {}", port);
        }
        ready_.store(true);  // signal start() that setup is done (success or failure)
    });

    app.run();  // blocks until all sockets closed
    running_.store(false);
}

// ─── Message Dispatch ───────────────────────────────────────────────────────

void TenetWSService::handle_message(void* ws, const uint8_t* data, size_t len) {
    auto* env = flatbuffers::GetRoot<Envelope>(data);
    if (!env) {
        send_error(ws, 0, 1, "invalid envelope");
        return;
    }

    auto msg_id = env->msg_id();
    auto type = env->type();
    auto* payload = env->payload();
    const uint8_t* payload_data = payload ? payload->data() : nullptr;
    size_t payload_len = payload ? payload->size() : 0;

    switch (type) {
    // Hot path
    case MessageType_FetchRowsReq:
        handle_fetch_rows(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetRegsReq:
        handle_get_regs(ws, msg_id, payload_data, payload_len); break;
    case MessageType_ReadMemoryReq:
        handle_read_memory(ws, msg_id, payload_data, payload_len); break;

    // Navigation
    case MessageType_NavigateReq:
        handle_navigate(ws, msg_id, payload_data, payload_len); break;
    case MessageType_NavBackReq:
        handle_nav_back(ws, msg_id); break;
    case MessageType_NavForwardReq:
        handle_nav_forward(ws, msg_id); break;
    case MessageType_ToggleBookmarkReq:
        handle_toggle_bookmark(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetBookmarksReq:
        handle_get_bookmarks(ws, msg_id); break;
    case MessageType_GetTraceInfoReq:
        handle_get_trace_info(ws, msg_id); break;

    // Search
    case MessageType_SearchForwardReq:
        handle_search_forward(ws, msg_id, payload_data, payload_len); break;
    case MessageType_SearchClearReq:
        handle_search_clear(ws, msg_id); break;
    case MessageType_GetSearchResultsReq:
        handle_get_search_results(ws, msg_id); break;

    // Pass management
    case MessageType_RunPassReq:
        handle_run_pass(ws, msg_id, payload_data, payload_len); break;
    case MessageType_RunDefaultPassesReq:
        handle_run_default_passes(ws, msg_id); break;
    case MessageType_ClearAnalysisReq:
        handle_clear_analysis(ws, msg_id); break;
    case MessageType_GetPassResultReq:
        handle_get_pass_result(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetPassCatalogReq:
        handle_get_pass_catalog(ws, msg_id); break;
    case MessageType_GetProgressReq:
        handle_get_progress(ws, msg_id); break;

    // Data queries
    case MessageType_GetCallStackReq:
        handle_get_call_stack(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetLastWriterReq:
        handle_get_last_writer(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetWriteHistoryReq:
        handle_get_write_history(ws, msg_id, payload_data, payload_len); break;
    case MessageType_GetFunctionsReq:
        handle_get_functions(ws, msg_id); break;

    // Generic analysis channel (dispatches to any registered MCP tool by name)
    case MessageType_RunAnalysisReq:
        handle_run_analysis(ws, msg_id, payload_data, payload_len); break;

    default:
        send_error(ws, msg_id, 1,
                   fmt::format("unknown message type: {}", static_cast<int>(type)));
        break;
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

void TenetWSService::broadcast(const uint8_t* buf, size_t len) {
    auto sv = std::string_view(reinterpret_cast<const char*>(buf), len);
    for (auto* client : clients_) {
        static_cast<uWS::WebSocket<false, true, PerSocketData>*>(client)->send(
            sv, uWS::BINARY);
    }
}

void TenetWSService::send_error(void* ws, uint32_t msg_id, uint32_t code,
                                 const std::string& message) {
    flatbuffers::FlatBufferBuilder fbb(256);
    auto err = CreateErrorResponse(fbb, code, fbb.CreateString(message));
    fbb.Finish(err);

    flatbuffers::FlatBufferBuilder env_fbb(256 + fbb.GetSize());
    auto payload_vec = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
    auto env = CreateEnvelope(env_fbb, msg_id, MessageType_ErrorResp, payload_vec);
    env_fbb.Finish(env);

    auto sv = std::string_view(
        reinterpret_cast<const char*>(env_fbb.GetBufferPointer()),
        env_fbb.GetSize());
    static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws)->send(sv, uWS::BINARY);
}

// ─── Observer Callbacks (called from any thread) ────────────────────────────

void TenetWSService::on_navigation(uint64_t inst_id) {
    if (!running_.load()) return;
    auto* loop_ptr = loop_.load();
    if (!loop_ptr) return;
    static_cast<uWS::Loop*>(loop_ptr)->defer([this, inst_id]() {
        flatbuffers::FlatBufferBuilder fbb(64);
        auto evt = CreateEvtNavigationMsg(fbb, inst_id);
        fbb.Finish(evt);

        flatbuffers::FlatBufferBuilder env_fbb(64 + fbb.GetSize());
        auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
        auto env = CreateEnvelope(env_fbb, 0, MessageType_EvtNavigation, pv);
        env_fbb.Finish(env);
        broadcast(env_fbb.GetBufferPointer(), env_fbb.GetSize());
    });
}

void TenetWSService::on_pass_completed(std::string_view name) {
    if (!running_.load()) return;
    auto* loop_ptr = loop_.load();
    if (!loop_ptr) return;
    std::string name_copy(name);
    static_cast<uWS::Loop*>(loop_ptr)->defer([this, name_copy]() {
        flatbuffers::FlatBufferBuilder fbb(256);
        auto evt = CreateEvtPassCompletedMsg(fbb, fbb.CreateString(name_copy),
                                              true, 0);
        fbb.Finish(evt);

        flatbuffers::FlatBufferBuilder env_fbb(256 + fbb.GetSize());
        auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
        auto env = CreateEnvelope(env_fbb, 0, MessageType_EvtPassCompleted, pv);
        env_fbb.Finish(env);
        broadcast(env_fbb.GetBufferPointer(), env_fbb.GetSize());
    });
}

void TenetWSService::on_bookmark_changed() {
    if (!running_.load()) return;
    auto* loop_ptr = loop_.load();
    if (!loop_ptr) return;
    static_cast<uWS::Loop*>(loop_ptr)->defer([this]() {
        auto& bm = service_.bookmarks();
        flatbuffers::FlatBufferBuilder fbb(64 + bm.size() * 8);
        auto bm_vec = fbb.CreateVector(bm.data(), bm.size());
        auto evt = CreateEvtBookmarkChangedMsg(fbb, bm_vec);
        fbb.Finish(evt);

        flatbuffers::FlatBufferBuilder env_fbb(64 + fbb.GetSize());
        auto pv = env_fbb.CreateVector(fbb.GetBufferPointer(), fbb.GetSize());
        auto env = CreateEnvelope(env_fbb, 0, MessageType_EvtBookmarkChanged, pv);
        env_fbb.Finish(env);
        broadcast(env_fbb.GetBufferPointer(), env_fbb.GetSize());
    });
}

}  // namespace tenet

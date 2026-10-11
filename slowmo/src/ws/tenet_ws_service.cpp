// slowmo/src/ws/tenet_ws_service.cpp
#include "ws/tenet_ws_service.h"
#include "common/logger.h"
#include "io/mcp/mcp_server.h"  // TenetMcpService — in-process tool dispatcher
#include "ws/ws_async_reply_dispatcher.h"
#include "ws/ws_analysis_task_queue.h"
#include "ws/ws_protocol.h"

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
    // channel. Access stays serialized by analysis_mutex_ even when handlers
    // run on worker threads.
    mcp_dispatch_ = std::make_unique<TenetMcpService>(service_);
}

TenetWSService::~TenetWSService() {
    if (loop_thread_.joinable() &&
        loop_thread_.get_id() == std::this_thread::get_id()) {
        LOG_INFO_M(log::Module::Mcp,
                   "[ws] destructor on loop thread is unsupported; destroy from external thread after join");
        std::abort();
    }
    stop();
    service_.remove_observer(this);
}

// ─── Start / Stop ───────────────────────────────────────────────────────────

uint16_t TenetWSService::start(uint16_t port) {
    if (running_.load()) return port_.load();

    ready_.store(false);
    stopping_.store(false);

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
    const bool called_from_loop_thread =
        loop_thread_.joinable() && loop_thread_.get_id() == std::this_thread::get_id();

    if (stopping_.exchange(true)) {
        if (called_from_loop_thread) {
            LOG_INFO_M(log::Module::Mcp,
                       "[ws] stop() re-entered on loop thread; join must be performed by another thread");
            return;
        }
        if (loop_thread_.joinable()) {
            loop_thread_.join();
        }
        return;
    }

    // 1. Close the intake gate — no new analysis tasks may be enqueued.
    if (analysis_task_queue_) {
        analysis_task_queue_->stop();
    }

    // 2. Drain async reply dispatcher workers.
    if (async_reply_dispatcher_) {
        async_reply_dispatcher_->stop();
    }

    // 3. Close sockets on the event loop.
    auto* loop_ptr = loop_.load();
    if (loop_ptr) {
        auto* loop = static_cast<uWS::Loop*>(loop_ptr);
        loop->defer([this]() {
            if (listen_socket_) {
                us_listen_socket_close(0, listen_socket_);
                listen_socket_ = nullptr;
            }
            for (auto* client : clients_) {
                static_cast<uWS::WebSocket<false, true, PerSocketData>*>(client)->close();
            }
            clients_.clear();
        });
    }

    if (called_from_loop_thread) {
        LOG_INFO_M(log::Module::Mcp,
                   "[ws] stop() called on loop thread; object must stay alive until an external thread joins");
        return;
    }

    if (loop_thread_.joinable()) {
        loop_thread_.join();
    }

    running_.store(false);
    ready_.store(false);
    loop_.store(nullptr);
    port_.store(0);
    listen_socket_ = nullptr;
}

// ─── Event Loop ─────────────────────────────────────────────────────────────

void TenetWSService::event_loop_main(uint16_t port) {
    uWS::App app;

    // Assign loop_ before listen/open so observer callbacks and deferred
    // response delivery can hop back onto the event loop thread immediately.
    // stop() blocks new jobs, waits for active workers to finish, then closes
    // sockets on the loop thread. Replies already queued via defer either send
    // before close or become harmless stale drops after the close callback
    // unregisters the connection generation.
    // Contract: stop() may be called on the loop thread to initiate shutdown,
    // but ownership/lifetime must remain valid until an external thread (or
    // destructor off-loop) performs the final join. Loop-thread destruction is
    // explicitly rejected to avoid detach/UAF hazards.
    loop_.store(uWS::Loop::get());
    analysis_task_queue_ = std::make_unique<WSAnalysisTaskQueue>();
    async_reply_dispatcher_ = std::make_unique<WSAsyncReplyDispatcher>(
        [this](std::function<void()> fn) {
            auto* loop_ptr = loop_.load();
            if (!loop_ptr || stopping_.load()) return;
            static_cast<uWS::Loop*>(loop_ptr)->defer(std::move(fn));
        },
        [](void* ws, std::string_view payload) {
            static_cast<uWS::WebSocket<false, true, PerSocketData>*>(ws)->send(
                payload, uWS::BINARY);
        });

    app.ws<PerSocketData>("/*", {
        .compression = uWS::DISABLED,
        .maxPayloadLength = 16 * 1024 * 1024,  // 16 MB
        .maxBackpressure = 64 * 1024 * 1024,    // 64 MB

        .open = [this](auto* ws) {
            clients_.push_back(ws);
            if (async_reply_dispatcher_) {
                async_reply_dispatcher_->register_connection(ws);
            }
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
            if (async_reply_dispatcher_) {
                async_reply_dispatcher_->unregister_connection(ws);
            }
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

    app.run();  // blocks until all sockets close and deferred callbacks drain
    analysis_task_queue_.reset();
    async_reply_dispatcher_.reset();
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
    auto bytes = build_ws_error_envelope_bytes(msg_id, code, message);
    auto sv = std::string_view(bytes.data(), bytes.size());
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

        auto bytes = build_ws_envelope_bytes(0, MessageType_EvtNavigation, fbb);
        broadcast(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
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

        auto bytes = build_ws_envelope_bytes(0, MessageType_EvtPassCompleted, fbb);
        broadcast(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    });
}

void TenetWSService::on_bookmark_changed() {
    if (!running_.load()) return;
    auto* loop_ptr = loop_.load();
    if (!loop_ptr) return;
    static_cast<uWS::Loop*>(loop_ptr)->defer([this]() {
        auto bm = service_.bookmarks();
        flatbuffers::FlatBufferBuilder fbb(64 + bm.size() * 8);
        auto bm_vec = fbb.CreateVector(bm.data(), bm.size());
        auto evt = CreateEvtBookmarkChangedMsg(fbb, bm_vec);
        fbb.Finish(evt);

        auto bytes = build_ws_envelope_bytes(0, MessageType_EvtBookmarkChanged, fbb);
        broadcast(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    });
}

}  // namespace tenet

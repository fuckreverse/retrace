// tools/tenet/src/ws/tenet_ws_service.h
#pragma once

#include "service/tenet_service.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// Forward declarations (avoid including uWS in the header)
struct us_listen_socket_t;

namespace tenet {

/// High-performance WebSocket service using uWebSockets + FlatBuffers.
/// Exposes the full TenetService API over binary WebSocket frames.
class TenetWSService : public TenetServiceObserver {
public:
    explicit TenetWSService(TenetService& service);
    ~TenetWSService() override;

    TenetWSService(const TenetWSService&) = delete;
    TenetWSService& operator=(const TenetWSService&) = delete;

    /// Start the WebSocket server.  Spawns the uWS event loop thread.
    /// Returns the actual listening port (useful when port=0 for OS-assigned).
    uint16_t start(uint16_t port = 9090);

    /// Stop the server and join the event loop thread.
    void stop();

    bool running() const { return running_.load(); }
    uint16_t port() const { return port_.load(); }

    // ── TenetServiceObserver ────────────────────────────────────
    void on_pass_completed(std::string_view name) override;
    void on_navigation(uint64_t inst_id) override;
    void on_bookmark_changed() override;

private:
    void event_loop_main(uint16_t port);
    void handle_message(void* ws, const uint8_t* data, size_t len);
    void broadcast(const uint8_t* buf, size_t len);
    void send_error(void* ws, uint32_t msg_id, uint32_t code,
                    const std::string& message);

    // ── Handler methods (implemented in ws_handlers_stub.cpp) ────────
    void handle_fetch_rows(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_regs(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_read_memory(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_navigate(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_nav_back(void* ws, uint32_t msg_id);
    void handle_nav_forward(void* ws, uint32_t msg_id);
    void handle_toggle_bookmark(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_bookmarks(void* ws, uint32_t msg_id);
    void handle_get_trace_info(void* ws, uint32_t msg_id);
    void handle_search_forward(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_search_clear(void* ws, uint32_t msg_id);
    void handle_get_search_results(void* ws, uint32_t msg_id);
    void handle_run_pass(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_run_default_passes(void* ws, uint32_t msg_id);
    void handle_clear_analysis(void* ws, uint32_t msg_id);
    void handle_get_pass_state(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_pass_result(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_pass_catalog(void* ws, uint32_t msg_id);
    void handle_get_call_stack(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_last_writer(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_write_history(void* ws, uint32_t msg_id, const uint8_t* payload, size_t len);
    void handle_get_functions(void* ws, uint32_t msg_id);

    TenetService& service_;
    std::thread loop_thread_;
    std::atomic<bool> running_{false};
    std::atomic<uint16_t> port_{0};

    // uWS internals (opaque here; cast in .cpp)
    void* loop_ = nullptr;           // uWS::Loop*
    us_listen_socket_t* listen_socket_ = nullptr;

    // Connected clients — accessed ONLY from the event loop thread.
    std::vector<void*> clients_;     // uWS::WebSocket<false>* pointers
};

}  // namespace tenet

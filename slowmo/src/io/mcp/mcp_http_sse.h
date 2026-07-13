#pragma once

// ─── McpHttpSseTransport ───────────────────────────────────────────────────
//
// HTTP/1.1 Server-Sent Events (SSE) transport for the Model Context Protocol.
// Implements the MCP 2024-11-05 HTTP+SSE transport spec:
//
//   GET  /sse          — establish SSE stream, returns text/event-stream
//                        Server sends: event: endpoint\ndata: /messages?sid=<id>\n\n
//   POST /messages     — send a JSON-RPC request (query param: ?sid=<id>)
//   GET  /health       — returns 200 OK (liveness probe)
//
// Wire format:
//   - Client POSTs newline-terminated JSON-RPC to /messages
//   - Server sends JSON-RPC responses as SSE events on the /sse stream
//   - Each SSE event: "data: <json>\n\n"
//
// Auth (optional):
//   If a non-empty username/password is configured, every request must carry
//   "Authorization: Basic <base64(user:pass)>" or receive 401.
//
// Concurrency:
//   - Listener thread accepts new connections.
//   - Each client connection gets its own handler thread.
//   - Tool handlers are called under a shared dispatch mutex (same as stdio mode).
//
// Usage:
//   McpHttpSseTransport transport(message_handler, "127.0.0.1", 10444);
//   transport.set_auth("admin", "secret");   // optional
//   transport.start();  // non-blocking, spawns listener thread
//   // ...
//   transport.stop();

#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <memory>

#include <nlohmann/json.hpp>

namespace tenet {

// ─── SSE client session ────────────────────────────────────────────────────

struct SseSession {
    int         fd = -1;                ///< connected client socket
    std::string id;                     ///< session UUID
    std::mutex  write_mutex;            ///< guards writes to fd
    std::atomic<bool> alive{true};

    /// Send a JSON-RPC response as SSE event.
    /// Thread-safe (may be called from POST handler thread).
    void send_event(const nlohmann::json& payload);

    /// Send raw SSE data string (already formatted).
    void send_raw(const std::string& data);
};

// ─── McpHttpSseTransport ───────────────────────────────────────────────────

class McpHttpSseTransport {
public:
    using MessageHandler = std::function<nlohmann::json(const nlohmann::json& msg)>;

    McpHttpSseTransport(MessageHandler handler,
                        const std::string& host = "127.0.0.1",
                        uint16_t port = 10444);
    ~McpHttpSseTransport();

    // Non-copyable
    McpHttpSseTransport(const McpHttpSseTransport&) = delete;
    McpHttpSseTransport& operator=(const McpHttpSseTransport&) = delete;

    /// Optional Basic Auth.  Empty strings = no auth required.
    void set_auth(const std::string& username, const std::string& password);

    /// Start listener thread (non-blocking).
    bool start();

    /// Stop server and close all connections.
    void stop();

    bool is_running() const { return running_.load(); }

    std::string host() const { return host_; }
    uint16_t    port() const { return port_; }

    /// Number of currently active SSE sessions.
    size_t session_count() const;

private:
    void listener_loop();
    void handle_client(int client_fd);

    // HTTP parsing / response helpers
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string query;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
        bool valid = false;
    };
    static HttpRequest parse_http_request(int fd);
    static void send_http_response(int fd, int status,
                                   const std::string& content_type,
                                   const std::string& body,
                                   const std::string& extra_headers = "");
    static void send_sse_headers(int fd);

    // Auth
    bool check_auth(const HttpRequest& req) const;
    static std::string base64_encode(const std::string& s);

    // Session management
    std::shared_ptr<SseSession> get_session(const std::string& sid);
    std::shared_ptr<SseSession> create_session(int fd);
    void remove_session(const std::string& sid);

    MessageHandler handler_;
    std::string host_;
    uint16_t    port_;
    int         server_fd_ = -1;

    std::atomic<bool> running_{false};
    std::thread       listener_thread_;

    // Auth config
    std::string auth_username_;
    std::string auth_password_;
    std::string auth_b64_expected_;  // pre-computed base64(user:pass)
    bool        auth_enabled_ = false;

    // Session registry
    mutable std::mutex sessions_mutex_;
    std::unordered_map<std::string, std::shared_ptr<SseSession>> sessions_;

    // Dispatch mutex: serialises tool handler calls (same model as stdio)
    std::mutex dispatch_mutex_;

    // Per-client threads
    std::mutex clients_mutex_;
    std::vector<std::thread> client_threads_;

    static std::string generate_uuid();
};

}  // namespace tenet

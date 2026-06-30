#pragma once

// ─── McpHttpTransport ──────────────────────────────────────────────────────
//
// Streamable HTTP transport for the Model Context Protocol (MCP 2025-03-26).
//
// Single endpoint that accepts POST, GET, and DELETE:
//
//   POST /mcp        — client sends a JSON-RPC request/notification/response.
//                       Server replies with application/json (synchronous) or
//                       text/event-stream (streaming, optional).
//   GET  /mcp        — open an SSE stream for server-initiated messages (optional).
//   DELETE /mcp      — terminate the session.
//   GET  /health     — liveness probe (returns 200 OK).
//
// Session management:
//   - Server assigns Mcp-Session-Id in the InitializeResult response.
//   - Client must send Mcp-Session-Id header on all subsequent requests.
//   - Server returns 400 for missing/invalid session IDs.
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
//   McpHttpTransport transport(message_handler, "127.0.0.1", 7080);
//   transport.set_auth("admin", "secret");   // optional
//   transport.start();  // non-blocking, spawns listener thread
//   // ...
//   transport.stop();

#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

#include <nlohmann/json.hpp>

namespace tenet {

class McpHttpTransport {
public:
    using MessageHandler = std::function<nlohmann::json(const nlohmann::json& msg)>;

    McpHttpTransport(MessageHandler handler,
                     const std::string& host = "127.0.0.1",
                     uint16_t port = 7080);
    ~McpHttpTransport();

    // Non-copyable
    McpHttpTransport(const McpHttpTransport&) = delete;
    McpHttpTransport& operator=(const McpHttpTransport&) = delete;

    /// Optional Basic Auth.  Empty strings = no auth required.
    void set_auth(const std::string& username, const std::string& password);

    /// Enable/disable session ID requirement (default: false = no session needed).
    /// When disabled, Mcp-Session-Id header is neither issued nor checked.
    void set_require_session(bool require) { require_session_ = require; }

    /// Start listener thread (non-blocking).
    bool start();

    /// Stop server and close all connections.
    void stop();

    bool is_running() const { return running_.load(); }

    std::string host() const { return host_; }
    uint16_t    port() const { return port_; }

    /// Actual listening port (differs from configured port when port=0).
    uint16_t listening_port() const { return listening_port_; }

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

    // Auth
    bool check_auth(const HttpRequest& req) const;
    static std::string base64_encode(const std::string& s);

    // Session management
    bool check_session(const HttpRequest& req, int client_fd);

    MessageHandler handler_;
    std::string host_;
    uint16_t    port_;
    int         server_fd_ = -1;
    uint16_t    listening_port_ = 0;  // actual port after bind (useful when port_==0)

    std::atomic<bool> running_{false};
    std::thread       listener_thread_;

    // Auth config
    std::string auth_username_;
    std::string auth_password_;
    std::string auth_b64_expected_;  // pre-computed base64(user:pass)
    bool        auth_enabled_ = false;

    // Session: single active session (tenet is single-trace, single-session)
    bool        require_session_ = false;  // when false, skip session ID check entirely
    std::mutex  session_mutex_;
    std::string session_id_;          // empty = no active session
    bool        session_ever_created_ = false; // true once first initialize completes

    // NOTE: dispatch_mutex_ removed — concurrency is now managed by
    // TenetMcpService::tool_rw_mutex_ (shared_mutex with read/write classification).
    // Read-only tools execute in parallel; write tools acquire exclusive lock.

    // Per-client threads
    std::mutex clients_mutex_;
    std::vector<std::thread> client_threads_;

    static std::string generate_uuid();
};

}  // namespace tenet

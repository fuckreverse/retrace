#pragma once

// ─── MCP Hub: Multi-Instance Coordination ─────────────────────────────────
//
// Architecture:
//
//   MCP Client (CatPaw)
//       │
//       ▼ HTTP (port 10444)
//   ┌──────────────────────────┐
//   │  Hub Instance            │  ← platform-lock elected, auto-failover
//   │  (also serves its own    │
//   │   trace via MCP tools)   │
//   │                          │
//   │  Instance Registry       │
//   │  Request Router          │
//   └──────┬───────┬───────────┘
//          │ TCP   │ TCP
//          ▼       ▼
//     Worker A   Worker B      ← no listening port, reverse-connect to hub
//     (trace_A)  (trace_B)
//
// Protocol:
//   Worker connects to hub's port 10444. First line: "WORKER/1.0\n"
//   Then newline-delimited JSON messages:
//     {"type":"register","id":"...","pid":N,"trace_file":"...","module_name":"..."}
//     {"type":"registered","session_mode":false}
//     {"type":"rpc","id":"req-1","msg":<JSON-RPC request>}
//     {"type":"rpc_response","id":"req-1","msg":<JSON-RPC response>}
//     {"type":"heartbeat","id":"..."}
//     {"type":"hub_shutdown"}
//
// Election:
//   Cross-platform advisory exclusive lock on the per-user mcp-hub.lock file.
//   Process crash → OS lock auto-released → workers detect TCP disconnect
//   → attempt lock acquisition → winner becomes new hub
//
// Modes:
//   sessionless (default): every tool call must specify instance parameter.
//     select_instance tool is NOT available.
//   session: select_instance sets session-level default instance.
//     instance parameter is optional.

#include "common/platform_compat.h"
#include "common/platform_file_lock.h"
#include "common/platform_paths.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace tenet {

// ─── Hub Configuration ────────────────────────────────────────────────────

struct McpHubConfig {
    std::string host          = "127.0.0.1";
    uint16_t    port          = 10444;  ///< Fixed hub port
    std::string lock_dir;              ///< Directory for lock file (default: ~/.tenet)
    bool        session_mode  = false;  ///< false = sessionless (default), true = session mode
    std::string instance_name;         ///< Optional custom instance name
};

// ─── Hub Election (cross-platform advisory lock) ───────────────────────────

class HubElection {
public:
    HubElection(const std::string& lock_dir,
                platform::pid_t_compat pid, uint16_t hub_port,
                const std::string& trace_file,
                const std::string& instance_id);
    ~HubElection();

    /// Try to acquire the hub role via a non-blocking advisory lock.
    /// Returns true if this instance is now the hub.
    bool try_acquire();

    /// Publish the actual listener port after the hub transport has started.
    bool update_port(uint16_t hub_port);

    /// Release the hub role (graceful shutdown) and its platform lock.
    void release();

    /// Read current hub info from the lock file (if another instance is hub).
    struct HubInfo {
        bool        valid       = false;
        platform::pid_t_compat pid = 0;
        uint16_t    port        = 0;
        std::string trace_file;
        std::string instance_id;
    };
    HubInfo read_current() const;

    bool is_hub() const { return is_hub_; }
    bool has_lock() const { return lock_.valid(); }

private:
    std::string lock_path_;
    platform::FileLock lock_;
    bool is_hub_ = false;
    platform::pid_t_compat pid_;
    uint16_t hub_port_;
    uint64_t start_time_ = 0;
    std::string trace_file_;
    std::string instance_id_;
};

// ─── Hub Instance (connected worker or hub itself) ────────────────────────

struct HubInstance {
    std::string id;
    platform::pid_t_compat pid = 0;
    std::string trace_file;
    std::string module_name;
    bool        is_hub       = false;
    platform::socket_t sock_fd = platform::kInvalidSocket;  ///< Guarded by socket_mutex_; invalid for hub itself
    mutable std::mutex socket_mutex_;
    std::atomic<int64_t> last_heartbeat_ticks{0};

    // Pending request tracking (for async request→response matching)
    struct PendingRequest {
        nlohmann::json response;
        bool           completed = false;
        bool           error     = false;
    };
    std::mutex pending_mutex;
    std::condition_variable pending_cv;
    std::unordered_map<std::string, PendingRequest> pending;

    // Socket lifecycle: send holds this lock across ::send(); close/shutdown
    // acquires the same lock before invalidating sock_fd to avoid fd reuse races.
    bool send(const nlohmann::json& msg);
    bool has_socket() const;
    bool matches_socket(platform::socket_t fd) const;
    void attach_socket(platform::socket_t fd);
    void shutdown_socket();
    void shutdown_socket_if(platform::socket_t expected_fd);
    void close_socket();
    void close_socket_if(platform::socket_t expected_fd);
};

// Tracks active upgraded WebSocket sessions separately from generic client fds.
// Worker-bound sessions are keyed by the exact HubInstance identity so an old
// generation can be torn down without touching a replacement that reused the
// same string id.
class BoundWsSessionRegistry {
public:
    struct SessionToken {
        platform::socket_t fd = platform::kInvalidSocket;
        uint64_t generation = 0;
    };

    SessionToken register_session(platform::socket_t fd, const std::shared_ptr<HubInstance>& bound_instance);
    void unregister_session(SessionToken token);
    void unregister_session(platform::socket_t fd);

    std::vector<platform::socket_t> sessions_for_instance(const std::shared_ptr<HubInstance>& bound_instance) const;
    std::vector<platform::socket_t> hub_local_sessions() const;
    std::vector<platform::socket_t> all_sessions() const;
    bool has_session(platform::socket_t fd) const;

private:
    struct Binding {
        std::weak_ptr<HubInstance> bound_instance;
        const HubInstance*         identity = nullptr;
        bool                       hub_local = false;
        uint64_t                   generation = 0;
    };

    mutable std::mutex mutex_;
    uint64_t next_generation_ = 1;
    std::unordered_map<platform::socket_t, Binding> sessions_by_fd_;
    std::unordered_map<const HubInstance*, std::unordered_set<platform::socket_t>> sessions_by_instance_;
    std::unordered_set<platform::socket_t> hub_local_fds_;
};

// ─── Hub Transport ─────────────────────────────────────────────────────────
//
// Listens on a single port. Detects HTTP (MCP client) vs worker connections
// by peeking at the first bytes:
//   - "WORKER/1.0\n" → worker TCP connection (newline-delimited JSON)
//   - Anything else  → HTTP connection (existing Streamable HTTP protocol)

class McpHubTransport {
public:
    using MessageHandler = std::function<nlohmann::json(const nlohmann::json& msg)>;
    using InstanceInfoProvider = std::function<nlohmann::json()>;

    McpHubTransport(MessageHandler handler,
                    const std::string& host, uint16_t port,
                    bool session_mode,
                    const std::string& hub_instance_id);
    ~McpHubTransport();

    McpHubTransport(const McpHubTransport&) = delete;
    McpHubTransport& operator=(const McpHubTransport&) = delete;

    /// Start listener (non-blocking, spawns listener thread).
    bool start();
    void stop();

    bool is_running() const { return running_.load(); }
    uint16_t listening_port() const { return listening_port_; }
    std::string host() const { return host_; }

    // ── Instance registry ─────────────────────────────────────────────
    void set_instance_info_provider(InstanceInfoProvider provider) {
        instance_info_provider_ = std::move(provider);
    }

    /// List all connected instances (including hub itself).
    nlohmann::json list_instances() const;

    /// Check if an instance is registered.
    bool has_instance(const std::string& id) const;

    /// Forward a JSON-RPC request to a worker instance.
    /// Throws on timeout or if instance is not connected.
    nlohmann::json forward_request(const std::string& instance_id,
                                    const nlohmann::json& rpc_request,
                                    int timeout_ms = 30000);

    /// Notify all workers that hub is shutting down.
    void notify_shutdown();

    bool session_mode() const { return session_mode_; }

private:
    struct HttpRequest;

    void listener_loop();
    void handle_http_client(platform::socket_t fd, const std::string& addr, bool peer_is_loopback);
    void handle_websocket_client(platform::socket_t fd, const std::string& addr, bool peer_is_loopback, const HttpRequest& req);
    void handle_worker_connection(platform::socket_t fd, const std::string& addr);

    nlohmann::json handle_ws_rpc(const std::string& bound_instance,
                                 const std::shared_ptr<HubInstance>& bound_worker,
                                 const nlohmann::json& msg);

    // HTTP helpers (same protocol as McpHttpTransport)
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string query;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
        bool valid = false;
    };
    static HttpRequest parse_http_request(platform::socket_t fd);
    static void send_http_response(platform::socket_t fd, int status,
                                   const std::string& content_type,
                                   const std::string& body,
                                   const std::string& extra_headers = "");
    static bool send_all(platform::socket_t fd, std::string_view data);
    static bool has_token_ci(std::string_view header_value, std::string_view token);

    // Worker registry
    mutable std::mutex registry_mutex_;
    std::unordered_map<std::string, std::shared_ptr<HubInstance>> instances_;

    // Request ID counter
    std::atomic<uint64_t> next_request_id_{1};

    // Cleanup
    void reap_stale_workers();
    void shutdown_ws_sessions_for_instance(const std::shared_ptr<HubInstance>& inst);
    void shutdown_all_ws_sessions();
    static void shutdown_fds(const std::vector<platform::socket_t>& fds);

    friend struct McpHubTransportTestAccess;

    MessageHandler handler_;
    InstanceInfoProvider instance_info_provider_;
    std::string host_;
    uint16_t port_;
    uint16_t listening_port_ = 0;
    platform::socket_t server_fd_ = platform::kInvalidSocket;
    bool session_mode_;
    std::string hub_instance_id_;

    std::atomic<bool> running_{false};
    std::thread listener_thread_;

    // Per-client threads
    std::mutex clients_mutex_;
    std::vector<std::thread> client_threads_;
    std::unordered_set<platform::socket_t> active_client_fds_;
    BoundWsSessionRegistry bound_ws_sessions_;

    // Heartbeat reaper thread
    std::thread reaper_thread_;
    std::atomic<bool> reaper_running_{false};
};

// ─── Worker Transport ──────────────────────────────────────────────────────
//
// Connects to hub via TCP. Does NOT listen on any port.
// Receives JSON-RPC requests from hub, executes them via the handler,
// and sends back responses.

class McpWorkerTransport {
public:
    using MessageHandler = std::function<nlohmann::json(const nlohmann::json& msg)>;


    McpWorkerTransport(MessageHandler handler,
                       const std::string& hub_host, uint16_t hub_port,
                       const std::string& instance_id,
                       platform::pid_t_compat pid,
                       const std::string& trace_file,
                       const std::string& module_name);
    ~McpWorkerTransport();

    McpWorkerTransport(const McpWorkerTransport&) = delete;
    McpWorkerTransport& operator=(const McpWorkerTransport&) = delete;

    /// Connect to hub and enter request loop. Blocks until:
    /// - Connection lost (returns → caller should attempt re-election)
    /// - stop() called
    void run();

    void stop();
    bool is_connected() const { return connected_.load(); }

private:
    bool connect_to_hub();
    void register_with_hub();
    void request_loop();
    void send_heartbeat();
    bool send_json(const nlohmann::json& msg);
    bool recv_line(std::string& line);
    platform::socket_t current_socket_fd() const;
    void install_socket(platform::socket_t fd);
    void shutdown_connection();
    void close_connection();

    friend struct McpWorkerTransportTestAccess;

    MessageHandler handler_;
    std::string hub_host_;
    uint16_t hub_port_;
    std::string instance_id_;
    platform::pid_t_compat pid_;
    std::string trace_file_;
    std::string module_name_;

    platform::socket_t sock_fd_ = platform::kInvalidSocket;  // Guarded by socket_mutex_
    mutable std::mutex socket_mutex_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> running_{true};

    std::thread heartbeat_thread_;

    // Recv buffer for newline-delimited protocol
    std::string recv_buf_;
    std::mutex recv_mutex_;

    // Session mode (learned from hub during registration)
    bool session_mode_ = false;
};

}  // namespace tenet

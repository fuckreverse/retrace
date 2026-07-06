#pragma once

// ─── MCP Hub: Multi-Instance Coordination ─────────────────────────────────
//
// Architecture:
//
//   MCP Client (CatPaw)
//       │
//       ▼ HTTP (port 10444)
//   ┌──────────────────────────┐
//   │  Hub Instance            │  ← flock-elected, auto-failover
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
//   flock(LOCK_EX | LOCK_NB) on ~/.tenet/mcp-hub.lock
//   Process crash → flock auto-released → workers detect TCP disconnect
//   → attempt flock → winner becomes new hub
//
// Modes:
//   sessionless (default): every tool call must specify instance parameter.
//     select_instance tool is NOT available.
//   session: select_instance sets session-level default instance.
//     instance parameter is optional.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
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

// ─── Hub Election (flock-based) ────────────────────────────────────────────

class HubElection {
public:
    HubElection(const std::string& lock_dir,
                pid_t pid, uint16_t hub_port,
                const std::string& trace_file,
                const std::string& instance_id);
    ~HubElection();

    /// Try to acquire hub role via flock(LOCK_EX | LOCK_NB).
    /// Returns true if this instance is now the hub.
    bool try_acquire();

    /// Release hub role (graceful shutdown). Unlocks flock and closes fd.
    void release();

    /// Read current hub info from the lock file (if another instance is hub).
    struct HubInfo {
        bool        valid       = false;
        pid_t       pid         = 0;
        uint16_t    port        = 0;
        std::string trace_file;
        std::string instance_id;
    };
    HubInfo read_current() const;

    bool is_hub() const { return is_hub_; }
    int  fd()     const { return fd_; }

private:
    std::string lock_path_;
    int  fd_          = -1;
    bool is_hub_      = false;
    pid_t pid_;
    uint16_t hub_port_;
    std::string trace_file_;
    std::string instance_id_;
};

// ─── Hub Instance (connected worker or hub itself) ────────────────────────

struct HubInstance {
    std::string id;
    pid_t       pid          = 0;
    std::string trace_file;
    std::string module_name;
    bool        is_hub       = false;
    int         sock_fd      = -1;       ///< -1 for hub itself
    std::chrono::steady_clock::time_point last_heartbeat;

    // Pending request tracking (for async request→response matching)
    struct PendingRequest {
        nlohmann::json response;
        bool           completed = false;
        bool           error     = false;
    };
    std::mutex pending_mutex;
    std::condition_variable pending_cv;
    std::unordered_map<std::string, PendingRequest> pending;

    // Write queue (for sending messages to this worker)
    std::mutex write_mutex;
    void send(const nlohmann::json& msg);
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
    void listener_loop();
    void handle_http_client(int fd, const std::string& addr);
    void handle_worker_connection(int fd, const std::string& addr);

    // HTTP helpers (same protocol as McpHttpTransport)
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

    // Worker registry
    mutable std::mutex registry_mutex_;
    std::unordered_map<std::string, std::unique_ptr<HubInstance>> instances_;

    // Request ID counter
    std::atomic<uint64_t> next_request_id_{1};

    // Cleanup
    void reap_stale_workers();

    MessageHandler handler_;
    InstanceInfoProvider instance_info_provider_;
    std::string host_;
    uint16_t port_;
    uint16_t listening_port_ = 0;
    int server_fd_ = -1;
    bool session_mode_;
    std::string hub_instance_id_;

    std::atomic<bool> running_{false};
    std::thread listener_thread_;

    // Per-client threads
    std::mutex clients_mutex_;
    std::vector<std::thread> client_threads_;

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
                       pid_t pid,
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
    void close_connection();

    MessageHandler handler_;
    std::string hub_host_;
    uint16_t hub_port_;
    std::string instance_id_;
    pid_t pid_;
    std::string trace_file_;
    std::string module_name_;

    int sock_fd_ = -1;
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

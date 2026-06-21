#pragma once

#include "common/types.h"
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace tenet {

class TraceReader;
class TraceIndex;
class RegisterFile;
class MemoryModel;
class PassManager;

// ─── JSON-RPC 2.0 over Unix Domain Socket ─────────────────────────────────
//
// Wire format: each message is a JSON string terminated by newline ('\n').
//
// Request:
//   { "jsonrpc": "2.0", "id": <int|str>, "method": "<method>", "params": {...} }
//
// Response:
//   { "jsonrpc": "2.0", "id": <id>, "result": {...} }
//   { "jsonrpc": "2.0", "id": <id>, "error": { "code": <int>, "message": "<msg>" } }
//
// Supported methods:
//   get_reg        (inst_id, reg_name) → value (hex string)
//   get_regs       (inst_id)           → { reg_name: value_hex, ... }
//   read_mem       (addr, size, inst_id) → { data: [byte...], known: [bool...] }
//   get_inst       (inst_id)           → { pc, disasm, mem_accesses }
//   get_range      (start, end)        → [ inst_row... ]  (up to 1000)
//   get_stats      ()                  → { inst_count, anchor_count, ... }
//   get_xref       (pc)                → [inst_id...]
//   get_taint      (inst_id, regs)     → { steps:[], tainted_regs:[] }
//   get_cfg        ()                  → DOT string
//   get_call_graph ()                  → DOT string
//   ping           ()                  → { pong: true }

// ─── RPC method handler ────────────────────────────────────────────────────

struct RpcRequest {
    std::string jsonrpc;
    std::string id_str;      ///< Stringified id (works for both int and string)
    bool        id_is_int = false;
    int64_t     id_int    = 0;
    std::string method;
    std::string params_json; ///< Raw JSON string of the "params" field
};

struct RpcResponse {
    std::string id_str;
    bool        id_is_int = false;
    int64_t     id_int    = 0;
    std::string result_json;  ///< Non-empty on success
    int         error_code = 0;
    std::string error_message;

    bool is_error() const { return error_code != 0; }
    std::string to_json() const;
};

/// Method handler: receives parsed request, returns response.
using RpcMethodHandler = std::function<RpcResponse(const RpcRequest&)>;

// ─── RpcServer ────────────────────────────────────────────────────────────

/// Minimal JSON-RPC 2.0 server over a Unix Domain Socket (UDS).
///
/// Lifecycle:
///   1. Construct with a socket path.
///   2. Register method handlers via register_method().
///   3. Call start() — creates a background thread that accepts connections.
///   4. Call stop() to shut down.
///
/// One client connection is handled at a time (sequential model).
/// Each newline-terminated JSON request is dispatched synchronously.
/// Concurrent clients are serialized via an internal mutex.
///
/// Thread safety: register_method() must be called before start().
///                Handlers are called from the worker thread.
class RpcServer {
public:
    explicit RpcServer(const std::string& socket_path);
    ~RpcServer();

    // Non-copyable, non-movable
    RpcServer(const RpcServer&) = delete;
    RpcServer& operator=(const RpcServer&) = delete;

    /// Register a method handler. Must be called before start().
    void register_method(const std::string& method, RpcMethodHandler handler);

    /// Start the server (creates background listener thread).
    bool start();

    /// Stop the server gracefully.
    void stop();

    /// Check whether the server is running.
    bool is_running() const { return running_.load(); }

    /// Path of the Unix socket.
    const std::string& socket_path() const { return socket_path_; }

private:
    void listener_thread();
    void handle_client(int client_fd);
    RpcResponse dispatch(const std::string& json_line);

    std::string socket_path_;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex handler_mutex_;
    std::unordered_map<std::string, RpcMethodHandler> handlers_;
};

// ─── TenetRpcService ─────────────────────────────────────────────────────

/// High-level service that wires together tenet's analysis objects and
/// exposes them over a JSON-RPC Unix socket.
///
/// Registers the standard set of tenet methods:
///   ping, get_stats, get_reg, get_regs, read_mem, get_range,
///   get_xref, get_cfg, get_call_graph
///
/// Usage:
///   TenetRpcService svc(reader, index, regfile, memory, pm);
///   svc.start("/tmp/tenet-<pid>.sock");
///   // ... analysis runs ...
///   svc.stop();
class TenetRpcService {
public:
    TenetRpcService(TraceReader& reader,
                    TraceIndex& index,
                    RegisterFile& regfile,
                    MemoryModel& memory,
                    PassManager* pm = nullptr);
    ~TenetRpcService();

    /// Start the RPC server. Returns false on bind/listen failure.
    bool start(const std::string& socket_path = "");

    /// Stop the RPC server.
    void stop();

    /// Whether the server is listening.
    bool is_running() const;

    /// Effective socket path (useful when auto-generated).
    const std::string& socket_path() const;

private:
    void register_methods();

    TraceReader& reader_;
    TraceIndex& index_;
    RegisterFile& regfile_;
    MemoryModel& memory_;
    PassManager* pm_;

    std::unique_ptr<RpcServer> server_;
};

}  // namespace tenet

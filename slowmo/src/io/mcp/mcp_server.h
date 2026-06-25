#pragma once

#include "hypothesis_ledger.h"
#include "discipline_injector.h"
#include "common/types.h"

#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace tenet {

class TraceReader;
class TraceIndex;
class RegisterFile;
class MemoryModel;
class PassManager;
class CodeTable;
class InstructionDecoder;
class McpHttpSseTransport;

// ─── MCP Transport Mode ────────────────────────────────────────────────────

enum class McpTransportMode {
    Stdio,    ///< JSON-RPC 2.0 over stdin/stdout (default; used by Claude Desktop, etc.)
    HttpSse,  ///< HTTP + Server-Sent Events (MCP 2024-11-05 HTTP transport)
};

// ─── HTTP SSE Configuration ────────────────────────────────────────────────

struct McpHttpConfig {
    std::string host     = "127.0.0.1";  ///< Bind address ("0.0.0.0" to expose on all interfaces)
    uint16_t    port     = 7080;
    std::string username;                ///< Basic Auth username (empty = no auth)
    std::string password;
};

// ─── MCP Protocol over stdio ───────────────────────────────────────────────
//
// Model Context Protocol (MCP) 2024-11-05 transport over stdin/stdout.
//
// Wire format: newline-delimited JSON-RPC 2.0.
//   - Requests/responses are JSON objects terminated by '\n'.
//   - Diagnostic logs go to stderr (invisible to MCP client).
//
// MCP lifecycle:
//   Client → initialize (capabilities negotiation)
//   Server ← result (protocolVersion, capabilities, serverInfo)
//   Client → notifications/initialized
//   Client → tools/list
//   Client → tools/call { name, arguments }
//   ...
//   Client → EOF (stdin closed)

// ─── MCP Tool Schema ───────────────────────────────────────────────────────

struct McpToolSchema {
    std::string name;
    std::string description;
    nlohmann::json input_schema;  // JSON Schema for the tool's parameters
};

// ─── MCP Tool Handler ──────────────────────────────────────────────────────

/// Handler receives parsed arguments JSON, returns result JSON.
/// On error, throw std::runtime_error or return a JSON with "error" key.
using McpToolHandler = std::function<nlohmann::json(const nlohmann::json& arguments)>;

// ─── McpStdioTransport ─────────────────────────────────────────────────────

/// Reads newline-delimited JSON-RPC from stdin, writes to stdout.
/// Runs on the calling thread (blocking).
class McpStdioTransport {
public:
    using MessageHandler = std::function<nlohmann::json(const nlohmann::json& msg)>;

    explicit McpStdioTransport(MessageHandler handler);

    /// Run the transport loop (blocks until stdin EOF or stop() is called).
    void run();

    /// Signal the transport to stop.
    void stop();

private:
    MessageHandler handler_;
    std::atomic<bool> running_{true};
};

// ─── TenetMcpService ───────────────────────────────────────────────────────

/// High-level MCP service that exposes tenet's analysis capabilities
/// as MCP tools.
///
/// Supports two transport modes:
///   - Stdio  (default): JSON-RPC 2.0 over stdin/stdout.  Call run() to block.
///   - HttpSse:          HTTP + SSE transport.  Call start_http() to run
///                       in the background; call stop() to shut down.
///
/// All core objects (reader, index, regfile, memory, pm) are held by
/// reference — they must outlive this service.
class TenetMcpService {
public:
    TenetMcpService(TraceReader& reader,
                    TraceIndex& index,
                    RegisterFile& regfile,
                    MemoryModel& memory,
                    PassManager* pm,
                    CodeTable* code_table = nullptr,
                    InstructionDecoder* decoder = nullptr);
    ~TenetMcpService();

    // ── Stdio mode ─────────────────────────────────────────────────────
    /// Run the MCP server in stdio mode (blocks on stdin). Returns when stdin closes.
    void run();

    // ── HTTP SSE mode ──────────────────────────────────────────────────
    /// Start HTTP SSE server in background.  Returns false on bind failure.
    bool start_http(const McpHttpConfig& cfg = {});

    /// Stop the HTTP SSE server (no-op if not running).
    void stop_http();

    /// Returns true if the HTTP SSE server is currently accepting connections.
    bool http_running() const;

    /// Effective HTTP config (valid after start_http() succeeds).
    McpHttpConfig http_config() const { return http_cfg_; }

    // ── General ────────────────────────────────────────────────────────
    /// Stop whichever transport is active.
    void stop();

    /// Number of active tools registered.
    size_t tool_count() const { return tool_schemas_.size(); }

    /// Call a registered tool by name.  Throws if tool is not found.
    /// Exposed for testing and programmatic access; bypasses the JSON-RPC
    /// envelope and discipline injection.
    nlohmann::json call_tool(const std::string& name,
                             const nlohmann::json& arguments = nlohmann::json::object()) {
        auto it = tool_handlers_.find(name);
        if (it == tool_handlers_.end())
            throw std::runtime_error("Unknown tool: " + name);
        return it->second(arguments);
    }

private:
    /// Register a tool with its schema and handler.
    void register_tool(McpToolSchema schema, McpToolHandler handler);

    /// Register all tenet analysis tools.
    void register_all_tools();

    /// Process a single JSON-RPC message and return a response.
    /// Returns nullptr JSON for notifications (no response needed).
    nlohmann::json process_message(const nlohmann::json& msg);

    // ── Tool registration helpers (grouped by category) ────────────────
    //    Implemented in mcp_tools_core.cpp / mcp_tools_analysis.cpp /
    //    mcp_tools_ai.cpp respectively.
    void register_trace_tools();
    void register_query_tools();
    void register_taint_tools();
    void register_graph_tools();
    void register_analysis_tools();
    void register_search_tools();
    void register_pass_tools();
    void register_evidence_tools();
    void register_batch_tools();
    void register_hypothesis_tools();

    // ── Internal state ─────────────────────────────────────────────────
    TraceReader& reader_;
    TraceIndex& index_;
    RegisterFile& regfile_;
    MemoryModel& memory_;
    PassManager* pm_;
    CodeTable* code_table_;
    InstructionDecoder* decoder_;

    std::vector<McpToolSchema> tool_schemas_;
    std::unordered_map<std::string, McpToolHandler> tool_handlers_;

    // Stdio transport
    std::unique_ptr<McpStdioTransport> stdio_transport_;

    // HTTP SSE transport
    std::unique_ptr<McpHttpSseTransport> http_transport_;
    McpHttpConfig http_cfg_;

    int tool_call_count_ = 0;

    HypothesisLedger ledger_;
    DisciplineInjector discipline_;
};

}  // namespace tenet

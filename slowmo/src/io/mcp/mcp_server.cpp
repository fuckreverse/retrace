#include "mcp_server.h"
#include "mcp_http_sse.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>

#include <iostream>
#include <string>

using json = nlohmann::json;

namespace tenet {

// ─── Constants ────────────────────────────────────────────────────────────

static constexpr const char* MCP_PROTOCOL_VERSION = "2024-11-05";
static constexpr const char* MCP_SERVER_NAME = "tenet-trace-analyzer";
static constexpr const char* MCP_SERVER_VERSION = "1.0.0";

// ─── Helper: log to stderr ────────────────────────────────────────────────

static void mcp_log(const std::string& msg) {
    fmt::print(stderr, "[tenet-mcp] {}\n", msg);
}

// ─── McpStdioTransport ───────────────────────────────────────────────────

McpStdioTransport::McpStdioTransport(MessageHandler handler)
    : handler_(std::move(handler)) {}

void McpStdioTransport::run() {
    mcp_log("Waiting for JSON-RPC messages on stdin...");

    std::string line;
    while (running_.load() && std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json response;
        try {
            json msg = json::parse(line);
            response = handler_(msg);
        } catch (const json::parse_error& e) {
            response = {
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32700}, {"message", std::string("Parse error: ") + e.what()}}}
            };
        }

        // Notifications get null response — don't send
        if (response.is_null()) continue;

        std::cout << response.dump() << "\n";
        std::cout.flush();
    }

    mcp_log("Transport closed (stdin EOF).");
}

void McpStdioTransport::stop() {
    running_.store(false);
}

// ─── TenetMcpService ────────────────────────────────────────────────────

TenetMcpService::TenetMcpService(TraceReader& reader,
                                   TraceIndex& index,
                                   RegisterFile& regfile,
                                   MemoryModel& memory,
                                   PassManager* pm,
                                   CodeTable* code_table,
                                   InstructionDecoder* decoder)
    : reader_(reader), index_(index), regfile_(regfile), memory_(memory),
      pm_(pm), code_table_(code_table), decoder_(decoder) {

    register_all_tools();
    mcp_log(fmt::format("Registered {} MCP tools", tool_schemas_.size()));
}

TenetMcpService::~TenetMcpService() {
    stop();
}

void TenetMcpService::register_tool(McpToolSchema schema, McpToolHandler handler) {
    tool_handlers_[schema.name] = std::move(handler);
    tool_schemas_.push_back(std::move(schema));
}

void TenetMcpService::run() {
    mcp_log(fmt::format("tenet-mcp server v{} starting...", MCP_SERVER_VERSION));
    mcp_log(fmt::format("Protocol: MCP {}", MCP_PROTOCOL_VERSION));
    mcp_log(fmt::format("Tools loaded: {}", tool_schemas_.size()));
    mcp_log(fmt::format("Trace: {} instructions", index_.inst_count()));

    stdio_transport_ = std::make_unique<McpStdioTransport>(
        [this](const json& msg) -> json { return process_message(msg); }
    );
    stdio_transport_->run();

    mcp_log("tenet-mcp server exiting.");
}

bool TenetMcpService::start_http(const McpHttpConfig& cfg) {
    http_cfg_ = cfg;
    http_transport_ = std::make_unique<McpHttpSseTransport>(
        [this](const json& msg) -> json { return process_message(msg); },
        cfg.host, cfg.port
    );
    if (!cfg.username.empty()) {
        http_transport_->set_auth(cfg.username, cfg.password);
    }
    bool ok = http_transport_->start();
    if (ok) {
        mcp_log(fmt::format("HTTP SSE server started on {}:{}", cfg.host, cfg.port));
    }
    return ok;
}

void TenetMcpService::stop_http() {
    if (http_transport_) {
        http_transport_->stop();
        mcp_log("HTTP SSE server stopped.");
    }
}

bool TenetMcpService::http_running() const {
    return http_transport_ && http_transport_->is_running();
}

void TenetMcpService::stop() {
    if (stdio_transport_) stdio_transport_->stop();
    stop_http();
}

json TenetMcpService::process_message(const json& msg) {
    std::string method = msg.value("method", "");
    auto msg_id = msg.contains("id") ? msg["id"] : json(nullptr);

    // Notifications (no id) — no response
    if (msg_id.is_null() && !msg.contains("id")) {
        if (method == "notifications/initialized") {
            mcp_log("Client initialized.");
        }
        return nullptr;
    }

    if (method == "initialize") {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg_id},
            {"result", {
                {"protocolVersion", MCP_PROTOCOL_VERSION},
                {"capabilities", {
                    {"tools", {{"listChanged", false}}}
                }},
                {"serverInfo", {
                    {"name", MCP_SERVER_NAME},
                    {"version", MCP_SERVER_VERSION}
                }}
            }}
        };
    }

    if (method == "tools/list") {
        json tools_arr = json::array();
        for (const auto& schema : tool_schemas_) {
            tools_arr.push_back({
                {"name", schema.name},
                {"description", schema.description},
                {"inputSchema", schema.input_schema}
            });
        }
        return {
            {"jsonrpc", "2.0"},
            {"id", msg_id},
            {"result", {{"tools", std::move(tools_arr)}}}
        };
    }

    if (method == "tools/call") {
        auto params = msg.value("params", json::object());
        std::string tool_name = params.value("name", "");
        json arguments = params.value("arguments", json::object());

        auto it = tool_handlers_.find(tool_name);
        if (it == tool_handlers_.end()) {
            json error_result = {{"error", "Unknown tool: " + tool_name}};
            return {
                {"jsonrpc", "2.0"},
                {"id", msg_id},
                {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", error_result.dump()}}})},
                    {"isError", true}
                }}
            };
        }

        try {
            tool_call_count_++;
            json result = it->second(arguments);

            // Inject discipline reminder if applicable
            auto reminder = discipline_.on_tool_call(tool_name);
            if (!reminder.empty()) {
                result["_discipline"] = reminder;
            }

            std::string text = result.dump(2);
            return {
                {"jsonrpc", "2.0"},
                {"id", msg_id},
                {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", std::move(text)}}})},
                    {"isError", false}
                }}
            };
        } catch (const std::exception& e) {
            mcp_log(fmt::format("Tool {} error: {}", tool_name, e.what()));
            json error_result = {{"error", e.what()}};
            return {
                {"jsonrpc", "2.0"},
                {"id", msg_id},
                {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", error_result.dump()}}})},
                    {"isError", true}
                }}
            };
        }
    }

    if (method == "ping") {
        return {{"jsonrpc", "2.0"}, {"id", msg_id}, {"result", json::object()}};
    }

    return {
        {"jsonrpc", "2.0"},
        {"id", msg_id},
        {"error", {{"code", -32601}, {"message", "Method not found: " + method}}}
    };
}

// ─── Tool Registration ──────────────────────────────────────────────────

void TenetMcpService::register_all_tools() {
    register_trace_tools();
    register_query_tools();
    register_taint_tools();
    register_graph_tools();
    register_analysis_tools();
    register_search_tools();
    register_pass_tools();
    register_evidence_tools();
    register_batch_tools();
    register_hypothesis_tools();
}

}  // namespace tenet

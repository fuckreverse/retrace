#include "mcp_server.h"
#include "mcp_http.h"
#include "mcp_helpers.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>

#include <cmath>
#include <iostream>
#include <string>

using json = nlohmann::json;

namespace tenet {

// ─── Constants ────────────────────────────────────────────────────────────

static constexpr const char* MCP_PROTOCOL_VERSION = "2025-03-26";
static constexpr const char* MCP_SERVER_NAME = "tenet-trace-analyzer";
static constexpr const char* MCP_SERVER_VERSION = "1.0.0";

// ─── Helper: log to stderr ────────────────────────────────────────────────

static void mcp_log(const std::string& msg) {
    try {
        fmt::print(stderr, "[tenet-mcp] {}\n", msg);
    } catch (...) {
        // stderr may be closed (e.g. parent process / pipe gone) — ignore.
    }
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
    http_transport_ = std::make_unique<McpHttpTransport>(
        [this](const json& msg) -> json { return process_message(msg); },
        cfg.host, cfg.port
    );
    if (!cfg.username.empty()) {
        http_transport_->set_auth(cfg.username, cfg.password);
    }
    bool ok = http_transport_->start();
    if (ok) {
        mcp_log(fmt::format("Streamable HTTP server started on {}:{}", cfg.host, cfg.port));
    }
    return ok;
}

void TenetMcpService::stop_http() {
    if (http_transport_) {
        http_transport_->stop();
        mcp_log("HTTP server stopped.");
    }
}

bool TenetMcpService::http_running() const {
    return http_transport_ && http_transport_->is_running();
}

uint16_t TenetMcpService::http_listening_port() const {
    return http_transport_ ? http_transport_->listening_port() : 0;
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
            tool_call_count_.fetch_add(1, std::memory_order_relaxed);

            // Concurrency: write tools (hypothesis_*) acquire exclusive lock;
            // all other tools acquire shared lock for parallel execution.
            json result;
            if (is_write_tool(tool_name)) {
                std::unique_lock<std::shared_mutex> lk(tool_rw_mutex_);
                result = it->second(arguments);
            } else {
                std::shared_lock<std::shared_mutex> lk(tool_rw_mutex_);
                result = it->second(arguments);
            }

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
        } catch (const PassNotReady& e) {
            mcp_log(fmt::format("Tool {} pass not ready: {} ({:.0f}%)",
                                tool_name, e.pass_name, e.progress * 100));
            json retry_info = {
                {"status",         "processing"},
                {"pass",           e.pass_name},
                {"progress",       std::round(e.progress * 100.0) / 100.0},
                {"progress_pct",   fmt::format("{:.0f}%", e.progress * 100)},
                {"message",        e.progress_msg.empty()
                                       ? fmt::format("Pass '{}' is still running", e.pass_name)
                                       : e.progress_msg},
                {"retry_after_ms", 1000}
            };
            return {
                {"jsonrpc", "2.0"},
                {"id", msg_id},
                {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", retry_info.dump()}}})},
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

// ─── rebase / unrebase ──────────────────────────────────────────────────

uint64_t TenetMcpService::rebase(uint64_t runtime_pc) const noexcept {
    return runtime_pc - reader_.header().module_slide
           + image_base_.load(std::memory_order_relaxed);
}

uint64_t TenetMcpService::unrebase(uint64_t displayed_pc) const noexcept {
    return displayed_pc - image_base_.load(std::memory_order_relaxed)
           + reader_.header().module_slide;
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

    // ── set_image_base ────────────────────────────────────────────────────
    // Registered here (not in mcp_tools_core.cpp) because it directly mutates
    // service state (image_base_) and needs access to both reader_ and image_base_.
    register_tool(
        {"set_image_base",
         "Set the image base used for all PC addresses returned by MCP tools. "
         "All PCs are rebased as: displayed_pc = runtime_pc - module_slide + image_base. "
         "Default is 0x100000000 (IDA's default for ARM64 Mach-O binaries). "
         "Use 0 to get slide-relative static offsets. "
         "Use module_slide (from trace_info) to get raw runtime addresses. "
         "Input PCs (e.g. for search_pc, stop_pcs) must also use the rebased space.",
         {{"type", "object"},
          {"properties", {
              {"image_base", {{"type", "string"},
                              {"description", "New image base as hex string (e.g. '0x100000000')"}}}
          }},
          {"required", json::array({"image_base"})}}},
        [this](const json& args) -> json {
            uint64_t new_base = parse_hex(args.at("image_base").get<std::string>());
            uint64_t old_base = image_base_.exchange(new_base, std::memory_order_relaxed);
            uint64_t slide    = reader_.header().module_slide;
            return {
                {"ok", true},
                {"old_image_base", fmt::format("0x{:X}", old_base)},
                {"new_image_base", fmt::format("0x{:X}", new_base)},
                {"module_slide",   fmt::format("0x{:X}", slide)},
                {"note", "All subsequent PC values from MCP tools will use the new image base."}
            };
        }
    );

    // Classify write tools: hypothesis_* tools mutate HypothesisLedger state.
    // set_image_base mutates image_base_ (atomic, but logically a write).
    // All other tools are read-only (or their data structures have internal
    // synchronisation) and can execute concurrently.
    for (const auto& schema : tool_schemas_) {
        if (schema.name.rfind("hypothesis_", 0) == 0 ||
            schema.name == "set_image_base") {
            write_tools_.insert(schema.name);
        }
    }
}

bool TenetMcpService::is_write_tool(const std::string& tool_name) const {
    return write_tools_.count(tool_name) > 0;
}

}  // namespace tenet

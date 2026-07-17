#include "mcp_server.h"
#include "mcp_http.h"
#include "mcp_hub.h"
#include "mcp_helpers.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "service/tenet_service.h"
#include "common/logger.h"
#include "common/progress_manager.h"

#include <fmt/core.h>

#include <cmath>
#include <iostream>
#include <string>
#include <unistd.h>
#include <random>
#include <chrono>

using json = nlohmann::json;

namespace tenet {

// ─── Constants ────────────────────────────────────────────────────────────

static constexpr const char* MCP_PROTOCOL_VERSION = "2025-03-26";
static constexpr const char* MCP_SERVER_NAME = "tenet-trace-analyzer";
static constexpr const char* MCP_SERVER_VERSION = "1.0.0";

// ─── Helper: log to the Mcp module ─────────────────────────────────────────
//
// All MCP diagnostics go through the shared tenet::log system (module=Mcp)
// so they can be filtered with TENET_LOG_MODULES=mcp and are visible in the
// GUI's Output panel. stderr is never touched by JSON-RPC framing (stdout
// only), so this cannot corrupt the protocol stream.

// Compact one-line summary of a JSON value for logging (never dumps large
// payloads — keeps request logs greppable and cheap even at Info level).
static std::string json_brief(const json& j, size_t max_len = 200) {
    std::string s;
    try {
        s = j.dump();
    } catch (...) {
        return "<unprintable>";
    }
    if (s.size() > max_len) {
        s.resize(max_len);
        s += "...";
    }
    return s;
}

// ─── McpStdioTransport ───────────────────────────────────────────────────

McpStdioTransport::McpStdioTransport(MessageHandler handler)
    : handler_(std::move(handler)) {}

void McpStdioTransport::run() {
    LOG_INFO_M(log::Module::Mcp, "stdio transport: waiting for JSON-RPC messages on stdin...");

    std::string line;
    while (running_.load() && std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json response;
        try {
            json msg = json::parse(line);
            LOG_TRACE_M(log::Module::Mcp, "stdio recv: {}", json_brief(msg));
            response = handler_(msg);
        } catch (const json::parse_error& e) {
            LOG_WARN_M(log::Module::Mcp, "stdio: JSON parse error: {}", e.what());
            response = {
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32700}, {"message", std::string("Parse error: ") + e.what()}}}
            };
        }

        // Notifications get null response — don't send
        if (response.is_null()) continue;

        LOG_TRACE_M(log::Module::Mcp, "stdio send: {}", json_brief(response));
        std::cout << response.dump() << "\n";
        std::cout.flush();
    }

    LOG_INFO_M(log::Module::Mcp, "stdio transport closed (stdin EOF).");
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
    : service_(nullptr),
      reader_(reader), index_(index), regfile_(regfile), memory_(memory),
      pm_(pm), code_table_(code_table), decoder_(decoder) {

    register_all_tools();
    LOG_INFO_M(log::Module::Mcp, "service initialized: {} tools registered ({} write tools)",
               tool_schemas_.size(), write_tools_.size());
}

TenetMcpService::TenetMcpService(TenetService& service)
    : service_(&service),
      reader_(service.reader()), index_(service.index()),
      regfile_(service.regfile()), memory_(service.memory()),
      pm_(&service.ensure_pass_manager()),
      code_table_(&service.code_table()),
      decoder_(&service.decoder()) {

    register_all_tools();
    LOG_INFO_M(log::Module::Mcp, "service initialized (via TenetService): {} tools registered ({} write tools)",
               tool_schemas_.size(), write_tools_.size());
}

TenetMcpService::~TenetMcpService() {
    stop();
}

void TenetMcpService::register_tool(McpToolSchema schema, McpToolHandler handler) {
    tool_handlers_[schema.name] = std::move(handler);
    tool_schemas_.push_back(std::move(schema));
}

void TenetMcpService::run() {
    LOG_INFO_M(log::Module::Mcp,
               "tenet-mcp server v{} starting (protocol {}, {} tools, {} instructions, stdio)",
               MCP_SERVER_VERSION, MCP_PROTOCOL_VERSION, tool_schemas_.size(), index_.inst_count());

    stdio_transport_ = std::make_unique<McpStdioTransport>(
        [this](const json& msg) -> json { return process_message(msg); }
    );
    stdio_transport_->run();

    LOG_INFO_M(log::Module::Mcp, "tenet-mcp server exiting (handled {} tool calls).",
               tool_call_count_.load(std::memory_order_relaxed));
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
    http_transport_->set_require_session(cfg.require_session);
    bool ok = http_transport_->start();
    if (ok) {
        LOG_INFO_M(log::Module::Mcp,
                   "Streamable HTTP server started on {}:{} (session: {}, auth: {}, {} tools)",
                   cfg.host, http_transport_->listening_port(),
                   cfg.require_session ? "required" : "disabled",
                   cfg.username.empty() ? "disabled" : "enabled",
                   tool_schemas_.size());
    } else {
        LOG_ERROR_M(log::Module::Mcp, "failed to start Streamable HTTP server on {}:{}",
                    cfg.host, cfg.port);
    }
    return ok;
}

void TenetMcpService::stop_http() {
    if (http_transport_) {
        http_transport_->stop();
        LOG_INFO_M(log::Module::Mcp, "HTTP server stopped (handled {} tool calls).",
                   tool_call_count_.load(std::memory_order_relaxed));
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

    // Stop hub/worker mode
    if (worker_transport_) {
        worker_transport_->stop();
        if (worker_thread_.joinable()) worker_thread_.join();
        worker_transport_.reset();
    }
    if (hub_transport_) {
        hub_transport_->stop();
        hub_transport_.reset();
    }
    if (hub_election_) {
        hub_election_->release();
        hub_election_.reset();
    }
}

json TenetMcpService::process_message(const json& msg) {
    auto msg_id = msg.contains("id") ? msg["id"] : json(nullptr);

    if (!msg.is_object()) {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg_id},
            {"error", {{"code", -32600}, {"message", "Invalid Request: expected JSON object"}}}
        };
    }

    if (msg.value("jsonrpc", std::string("")) != "2.0") {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg_id},
            {"error", {{"code", -32600}, {"message", "Invalid Request: jsonrpc must be '2.0'"}}}
        };
    }

    std::string method = msg.value("method", "");

    // Notifications (no id) — no response
    if (msg_id.is_null() && !msg.contains("id")) {
        if (method == "notifications/initialized") {
            LOG_INFO_M(log::Module::Mcp, "client initialized (handshake complete)");
        } else {
            LOG_DEBUG_M(log::Module::Mcp, "notification: {}", method);
        }
        return nullptr;
    }

    if (method == "initialize") {
        auto client_info = msg.value("params", json::object()).value("clientInfo", json::object());
        LOG_INFO_M(log::Module::Mcp, "initialize: client={} version={}",
                   client_info.value("name", "?"), client_info.value("version", "?"));
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
        // High-frequency / low-signal — Debug only to avoid drowning out
        // actual tool-call activity at the default Info level.
        LOG_DEBUG_M(log::Module::Mcp, "tools/list: returning {} tools", tool_schemas_.size());
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
            LOG_WARN_M(log::Module::Mcp, "tools/call {}: unknown tool", tool_name);
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

        // ── Request-lifecycle logging ────────────────────────────────────
        // Principle: every tool call gets exactly one start line (Debug, with
        // the argument summary) and exactly one end line (Info, with outcome
        // + timing). This is enough to answer "what is the MCP server doing
        // right now / how long did X take" without flooding stderr — no
        // per-line dumps of large results, no logging inside hot loops.
        int seq = tool_call_count_.fetch_add(1, std::memory_order_relaxed) + 1;
        LOG_DEBUG_M(log::Module::Mcp, "tools/call #{} {} args={}",
                    seq, tool_name, json_brief(arguments));
        auto t0 = TENET_TIMER_START();

        try {
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
            LOG_INFO_M(log::Module::Mcp, "tools/call #{} {} OK  {:.1f}ms  result={}B",
                       seq, tool_name, TENET_TIMER_MS(t0), text.size());
            return {
                {"jsonrpc", "2.0"},
                {"id", msg_id},
                {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", std::move(text)}}})},
                    {"isError", false}
                }}
            };
        } catch (const PassNotReady& e) {
            LOG_INFO_M(log::Module::Mcp,
                       "tools/call #{} {} PENDING  {:.1f}ms  pass='{}' progress={:.0f}%",
                       seq, tool_name, TENET_TIMER_MS(t0), e.pass_name, e.progress * 100);
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
            LOG_WARN_M(log::Module::Mcp, "tools/call #{} {} FAILED  {:.1f}ms  error={}",
                       seq, tool_name, TENET_TIMER_MS(t0), e.what());
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
        // Pure liveness probe, often on a timer — Trace only.
        LOG_TRACE_M(log::Module::Mcp, "ping");
        return {{"jsonrpc", "2.0"}, {"id", msg_id}, {"result", json::object()}};
    }

    LOG_WARN_M(log::Module::Mcp, "unknown method: {}", method);
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
    register_vm_query_tools();
    register_evidence_tools();
    register_batch_tools();
    register_hypothesis_tools();

    register_tool(
        {"progress_tasks",
         "Return structured progress snapshots for active and completed backend tasks. "
         "Use kind to filter (pass, index, initialization).",
         {{"type", "object"},
          {"properties", {
              {"kind", {{"type", "string"}, {"description", "Optional task kind filter"}}}
          }}}},
        [](const json& args) -> json {
            const auto kind = args.value("kind", std::string{});
            json tasks = json::array();
            for (const auto& task : ProgressManager::global().snapshot(kind)) {
                tasks.push_back({
                    {"id", task.id}, {"kind", task.kind}, {"label", task.label},
                    {"phase", task.phase},
                    {"state", ProgressManager::state_name(task.state)},
                    {"progress", task.progress}, {"completed", task.completed},
                    {"total", task.total}, {"message", task.message},
                    {"error", task.error}, {"revision", task.revision}
                });
            }
            return {{"tasks", std::move(tasks)}};
        });

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

// ═══════════════════════════════════════════════════════════════════════════
// Hub mode implementation
// ═══════════════════════════════════════════════════════════════════════════

json TenetMcpService::instance_info_json() const {
    return {
        {"id",          instance_id_},
        {"pid",         static_cast<int>(getpid())},
        {"trace_file",  trace_file_},
        {"module_name", module_name_},
        {"is_hub",      true}
    };
}

json TenetMcpService::hub_list_instances() const {
    if (!hub_transport_) return json::object();
    return hub_transport_->list_instances();
}

bool TenetMcpService::start_hub(const McpHubConfig& cfg) {
    hub_cfg_ = cfg;
    hub_session_mode_ = cfg.session_mode;

    // Generate instance ID if not set
    if (instance_id_.empty()) {
        instance_id_ = cfg.instance_name.empty()
            ? fmt::format("tenet-{}", getpid())
            : cfg.instance_name;
    }

    // Get trace file and module name
    trace_file_ = reader_.path().string();
    module_name_ = reader_.header().module_name;

    // Attempt flock election
    hub_election_ = std::make_unique<HubElection>(
        cfg.lock_dir, getpid(), cfg.port, trace_file_, instance_id_);

    if (!hub_election_->try_acquire()) {
        LOG_INFO_M(log::Module::Mcp, "hub: election failed, another instance is hub");
        return false;
    }

    // We are the hub — start the hub transport
    hub_transport_ = std::make_unique<McpHubTransport>(
        [this](const json& msg) -> json { return process_message_hub(msg); },
        cfg.host, cfg.port,
        cfg.session_mode,
        instance_id_);

    hub_transport_->set_instance_info_provider([this]() -> json {
        return instance_info_json();
    });

    if (!hub_transport_->start()) {
        LOG_ERROR_M(log::Module::Mcp, "hub: failed to start transport on {}:{}", cfg.host, cfg.port);
        hub_election_->release();
        hub_election_.reset();
        hub_transport_.reset();
        return false;
    }

    // Inject instance parameter into all tool schemas
    inject_instance_param(!cfg.session_mode);  // required in sessionless mode

    // Register hub-specific tools (list_instances, select_instance)
    register_hub_tools();

    LOG_INFO_M(log::Module::Mcp, "hub: started on {}:{} (id={}, session_mode={})",
               cfg.host, cfg.port, instance_id_, cfg.session_mode);
    return true;
}

bool TenetMcpService::start_worker(const McpHubConfig& cfg) {
    hub_cfg_ = cfg;

    // Generate instance ID if not set
    if (instance_id_.empty()) {
        instance_id_ = cfg.instance_name.empty()
            ? fmt::format("tenet-{}", getpid())
            : cfg.instance_name;
    }

    trace_file_ = reader_.path().string();
    module_name_ = reader_.header().module_name;

    // Try to read hub info from lock file
    HubElection::HubInfo hub_info;
    {
        HubElection probe(cfg.lock_dir, getpid(), cfg.port, trace_file_, instance_id_);
        hub_info = probe.read_current();
    }

    if (!hub_info.valid) {
        LOG_WARN_M(log::Module::Mcp, "worker: no hub found in lock file");
        return false;
    }

    LOG_INFO_M(log::Module::Mcp, "worker: connecting to hub at {}:{} (id={})",
               cfg.host, hub_info.port, instance_id_);

    worker_transport_ = std::make_unique<McpWorkerTransport>(
        [this](const json& msg) -> json { return process_message(msg); },
        cfg.host, hub_info.port,
        instance_id_, getpid(),
        trace_file_, module_name_);

    // Run worker in background thread
    worker_thread_ = std::thread([this] {
        worker_transport_->run();
    });

    return true;
}

void TenetMcpService::inject_instance_param(bool required) {
    for (auto& schema : tool_schemas_) {
        // Skip hub-specific tools (they handle instance themselves)
        if (schema.name == "list_instances" || schema.name == "select_instance")
            continue;

        // Add instance property if not already present
        if (!schema.input_schema.contains("properties")) {
            schema.input_schema["properties"] = json::object();
        }
        schema.input_schema["properties"]["instance"] = {
            {"type", "string"},
            {"description",
             required
                ? "REQUIRED: target instance ID. Call list_instances to see available instances."
                : "Target instance ID (optional, uses session default if omitted). Call list_instances to see available instances."}
        };

        if (required) {
            if (!schema.input_schema.contains("required")) {
                schema.input_schema["required"] = json::array();
            }
            schema.input_schema["required"].push_back("instance");
        }
    }
}

void TenetMcpService::register_hub_tools() {
    // ── list_instances ─────────────────────────────────────────────────
    register_tool(
        {"list_instances",
         "List all tenet MCP instances and their status. "
         "Returns each instance's id, pid, trace_file, module_name, and is_hub flag. "
         "Call this first to find the instance ID you need, then pass it as the "
         "'instance' parameter to other tools.",
         {{"type", "object"}, {"properties", json::object()}}},
        [this](const json&) -> json {
            if (hub_transport_) {
                return hub_transport_->list_instances();
            }
            return {{"instances", json::array()}};
        }
    );

    // ── select_instance (session mode only) ────────────────────────────
    if (hub_session_mode_) {
        register_tool(
            {"select_instance",
             "Set the default instance for the current session. "
             "After calling this, subsequent tool calls without an 'instance' "
             "parameter will be routed to the selected instance.",
             {{"type", "object"},
              {"properties", {
                  {"instance", {{"type", "string"},
                   {"description", "Instance ID to set as default"}}}
              }},
              {"required", json::array({"instance"})}}},
            [this](const json& args) -> json {
                std::string inst = args.at("instance").get<std::string>();
                if (!hub_transport_ || !hub_transport_->has_instance(inst)) {
                    throw std::runtime_error("Unknown instance: " + inst);
                }
                std::lock_guard<std::mutex> lk(session_state_mutex_);
                session_default_instance_["_default"] = inst;
                return {{"ok", true}, {"default_instance", inst}};
            }
        );
    }
}

json TenetMcpService::process_message_hub(const json& msg) {
    auto msg_id = msg.contains("id") ? msg["id"] : json(nullptr);

    if (!msg.is_object()) {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg_id},
            {"error", {{"code", -32600}, {"message", "Invalid Request: expected JSON object"}}}
        };
    }

    if (msg.value("jsonrpc", std::string("")) != "2.0") {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg_id},
            {"error", {{"code", -32600}, {"message", "Invalid Request: jsonrpc must be '2.0'"}}}
        };
    }

    std::string method = msg.value("method", "");

    // Notifications — pass through
    if (msg_id.is_null() && !msg.contains("id")) {
        return process_message(msg);
    }

    // initialize and ping — handle locally
    if (method == "initialize" || method == "ping") {
        return process_message(msg);
    }

    // tools/list — handle locally (schemas already have instance param)
    if (method == "tools/list") {
        return process_message(msg);
    }

    // tools/call — route based on instance parameter
    if (method == "tools/call") {
        auto params = msg.value("params", json::object());
        std::string tool_name = params.value("name", "");
        json arguments = params.value("arguments", json::object());

        // Hub-specific tools are handled locally
        if (tool_name == "list_instances" || tool_name == "select_instance") {
            return process_message(msg);
        }

        // Extract instance parameter
        std::string target_instance;
        if (arguments.contains("instance")) {
            if (!arguments["instance"].is_string()) {
                json err = {{"error", "Invalid params: 'instance' must be a string."}};
                return {{"jsonrpc", "2.0"}, {"id", msg_id},
                        {"result", {{"content", json::array({{{"type", "text"}, {"text", err.dump()}}})},
                                    {"isError", true}}}};
            }
            target_instance = arguments["instance"].get<std::string>();
            // Strip instance from arguments before forwarding
            json clean_args = arguments;
            clean_args.erase("instance");

            json forwarded = msg;
            forwarded["params"]["arguments"] = std::move(clean_args);

            if (target_instance == instance_id_) {
                return process_message(forwarded);
            }

            if (hub_transport_ && hub_transport_->has_instance(target_instance)) {
                try {
                    return hub_transport_->forward_request(target_instance, forwarded);
                } catch (const std::exception& e) {
                    json err = {{"error", e.what()}};
                    return {{"jsonrpc", "2.0"}, {"id", msg_id},
                            {"result", {{"content", json::array({{{"type", "text"}, {"text", err.dump()}}})},
                                        {"isError", true}}}};
                }
            }

            json err = {{"error", "Unknown instance: " + target_instance +
                ". Call list_instances to see available instances."}};
            return {{"jsonrpc", "2.0"}, {"id", msg_id},
                    {"result", {{"content", json::array({{{"type", "text"}, {"text", err.dump()}}})},
                                {"isError", true}}}};
        }

        // No instance parameter — check session mode
        if (hub_session_mode_) {
            std::lock_guard<std::mutex> lk(session_state_mutex_);
            auto it = session_default_instance_.find("_default");
            if (it != session_default_instance_.end()) {
                target_instance = it->second;
            }

            if (target_instance.empty()) {
                json err = {{"error", "No instance specified and no default set. "
                    "Call select_instance first or provide the 'instance' parameter."}};
                return {{"jsonrpc", "2.0"}, {"id", msg_id},
                        {"result", {{"content", json::array({{{"type", "text"}, {"text", err.dump()}}})},
                                    {"isError", true}}}};
            }

            if (target_instance == instance_id_) {
                return process_message(msg);
            }

            if (hub_transport_ && hub_transport_->has_instance(target_instance)) {
                try {
                    return hub_transport_->forward_request(target_instance, msg);
                } catch (const std::exception& e) {
                    json err = {{"error", e.what()}};
                    return {{"jsonrpc", "2.0"}, {"id", msg_id},
                            {"result", {{"content", json::array({{{"type", "text"}, {"text", err.dump()}}})},
                                        {"isError", true}}}};
                }
            }
        }

        // Sessionless mode without instance parameter
        json err = {{"error", "Missing required 'instance' parameter. "
            "Call list_instances to see available instances, then pass "
            "instance='<id>' to this tool."}};
        return {{"jsonrpc", "2.0"}, {"id", msg_id},
                {"result", {{"content", json::array({{{"type", "text"}, {"text", err.dump()}}})},
                            {"isError", true}}}};
    }

    // Other methods — handle locally
    return process_message(msg);
}

}  // namespace tenet

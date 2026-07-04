#include "rpc_server.h"

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"
#include "common/types.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/taint/taint_pass.h"

#include <nlohmann/json.hpp>
#include <fmt/core.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <sstream>
#include <algorithm>

using json = nlohmann::json;

namespace tenet {

// ─── RpcResponse serialisation ────────────────────────────────────────────

std::string RpcResponse::to_json() const {
    json resp;
    resp["jsonrpc"] = "2.0";
    if (id_is_int) resp["id"] = id_int;
    else           resp["id"] = id_str;

    if (is_error()) {
        resp["error"] = {{"code", error_code}, {"message", error_message}};
    } else {
        // result_json is already a JSON string — embed it
        try {
            resp["result"] = json::parse(result_json);
        } catch (...) {
            resp["result"] = result_json;
        }
    }
    return resp.dump() + "\n";
}

// ─── JSON-RPC 2.0 parse helpers ───────────────────────────────────────────

namespace {

RpcResponse make_error(const std::string& id_str, bool id_is_int, int64_t id_int,
                       int code, const std::string& msg) {
    RpcResponse r;
    r.id_str    = id_str;
    r.id_is_int = id_is_int;
    r.id_int    = id_int;
    r.error_code    = code;
    r.error_message = msg;
    return r;
}

RpcResponse make_result(const std::string& id_str, bool id_is_int, int64_t id_int,
                        const std::string& result_json) {
    RpcResponse r;
    r.id_str      = id_str;
    r.id_is_int   = id_is_int;
    r.id_int      = id_int;
    r.result_json = result_json;
    return r;
}

bool parse_request(const std::string& line, RpcRequest& req, RpcResponse& err_resp) {
    json j;
    try {
        j = json::parse(line);
    } catch (const std::exception& e) {
        err_resp = make_error("null", false, 0, -32700,
                              std::string("Parse error: ") + e.what());
        return false;
    }

    // id
    if (j.contains("id")) {
        if (j["id"].is_number_integer()) {
            req.id_is_int = true;
            req.id_int = j["id"].get<int64_t>();
            req.id_str = std::to_string(req.id_int);
        } else {
            req.id_str = j.value("id", "null");
        }
    } else {
        req.id_str = "null";
    }

    // method
    if (!j.contains("method") || !j["method"].is_string()) {
        err_resp = make_error(req.id_str, req.id_is_int, req.id_int,
                              -32600, "Invalid Request: missing method");
        return false;
    }
    req.method = j["method"].get<std::string>();

    // params
    if (j.contains("params")) {
        req.params_json = j["params"].dump();
    } else {
        req.params_json = "{}";
    }

    return true;
}

/// Get a uint64 param, accepting both integer and "0x..." hex string.
uint64_t get_u64(const json& params, const std::string& key, uint64_t default_val = 0) {
    if (!params.contains(key)) return default_val;
    const auto& v = params[key];
    if (v.is_number()) return v.get<uint64_t>();
    if (v.is_string()) {
        const std::string& s = v.get<std::string>();
        return std::stoull(s, nullptr, 0);  // handles "0x..." and decimal
    }
    return default_val;
}

/// Register name to index (AArch64).
static const char* kRegNames[] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
};

int reg_name_to_idx(const std::string& name) {
    for (int i = 0; i < 34; i++) {
        if (name == kRegNames[i]) return i;
    }
    // Also accept "x29"/"x30" aliases
    if (name == "x29") return 29;
    if (name == "x30") return 30;
    return -1;
}

}  // anonymous namespace

// ─── RpcServer ────────────────────────────────────────────────────────────

RpcServer::RpcServer(const std::string& socket_path)
    : socket_path_(socket_path) {}

RpcServer::~RpcServer() {
    stop();
}

void RpcServer::register_method(const std::string& method, RpcMethodHandler handler) {
    std::lock_guard<std::mutex> lock(handler_mutex_);
    handlers_[method] = std::move(handler);
}

bool RpcServer::start() {
    // Create UDS
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) return false;

    // Remove stale socket file
    ::unlink(socket_path_.c_str());

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }
    if (listen(server_fd_, 8) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    // Set non-blocking so stop() can interrupt accept()
    int flags = fcntl(server_fd_, F_GETFL, 0);
    fcntl(server_fd_, F_SETFL, flags | O_NONBLOCK);

    running_.store(true);
    worker_ = std::thread([this] { listener_thread(); });
    return true;
}

void RpcServer::stop() {
    running_.store(false);
    if (server_fd_ >= 0) {
        ::shutdown(server_fd_, SHUT_RDWR);
        ::close(server_fd_);
        server_fd_ = -1;
        ::unlink(socket_path_.c_str());
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}

void RpcServer::listener_thread() {
    while (running_.load()) {
        // Poll with 200ms timeout (non-blocking accept loop)
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(server_fd_, &rfds);
        struct timeval tv{0, 200000};  // 200ms
        int ret = select(server_fd_ + 1, &rfds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        struct sockaddr_un client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd_,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) continue;
        handle_client(client_fd);
        ::close(client_fd);
    }
}

void RpcServer::handle_client(int client_fd) {
    // Read newline-terminated JSON messages until EOF
    std::string buf;
    char tmp[4096];

    while (true) {
        ssize_t n = ::recv(client_fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, static_cast<size_t>(n));

        // Process all complete lines in buf
        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, pos);
            buf.erase(0, pos + 1);
            if (line.empty()) continue;

            std::string resp_json = dispatch(line).to_json();
            ::send(client_fd, resp_json.data(), resp_json.size(), 0);
        }
    }
    // Flush remaining partial line if any (shouldn't happen in well-behaved clients)
    if (!buf.empty() && buf != "\n") {
        std::string resp_json = dispatch(buf).to_json();
        ::send(client_fd, resp_json.data(), resp_json.size(), 0);
    }
}

RpcResponse RpcServer::dispatch(const std::string& json_line) {
    RpcRequest req;
    RpcResponse err;
    if (!parse_request(json_line, req, err)) return err;

    std::lock_guard<std::mutex> lock(handler_mutex_);
    auto it = handlers_.find(req.method);
    if (it == handlers_.end()) {
        return make_error(req.id_str, req.id_is_int, req.id_int,
                          -32601, "Method not found: " + req.method);
    }
    try {
        return it->second(req);
    } catch (const std::exception& e) {
        return make_error(req.id_str, req.id_is_int, req.id_int,
                          -32603, std::string("Internal error: ") + e.what());
    }
}

// ─── TenetRpcService ─────────────────────────────────────────────────────

TenetRpcService::TenetRpcService(TraceReader& reader, TraceIndex& index,
                                  RegisterFile& regfile, MemoryModel& memory,
                                  PassManager* pm)
    : reader_(reader), index_(index), regfile_(regfile), memory_(memory), pm_(pm) {}

TenetRpcService::~TenetRpcService() { stop(); }

bool TenetRpcService::start(const std::string& socket_path) {
    std::string path = socket_path;
    if (path.empty()) {
        path = fmt::format("/tmp/tenet-{}.sock", static_cast<int>(::getpid()));
    }
    server_ = std::make_unique<RpcServer>(path);
    register_methods();
    return server_->start();
}

void TenetRpcService::stop() {
    if (server_) server_->stop();
}

bool TenetRpcService::is_running() const {
    return server_ && server_->is_running();
}

const std::string& TenetRpcService::socket_path() const {
    static std::string empty;
    return server_ ? server_->socket_path() : empty;
}

void TenetRpcService::register_methods() {
    using namespace std::string_literals;

    // ── ping ──────────────────────────────────────────────────────────────
    server_->register_method("ping", [](const RpcRequest& req) {
        return make_result(req.id_str, req.id_is_int, req.id_int,
                           R"({"pong":true})");
    });

    // ── get_stats ─────────────────────────────────────────────────────────
    server_->register_method("get_stats", [this](const RpcRequest& req) {
        const auto& stats = index_.stats();
        json r;
        r["inst_count"]    = stats.inst_count;
        r["anchor_count"]  = stats.anchor_count;
        r["code_count"]    = stats.code_count;
        r["build_seconds"] = stats.build_seconds;
        r["module_name"]   = reader_.header().module_name;
        r["module_base"]   = fmt::format("0x{:X}", reader_.header().module_base);
        r["module_slide"]  = fmt::format("0x{:X}", reader_.header().module_slide);
        r["file_size"]     = reader_.file_size();
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_reg ───────────────────────────────────────────────────────────
    server_->register_method("get_reg", [this](const RpcRequest& req) {
        json params = json::parse(req.params_json);
        uint64_t inst_id = get_u64(params, "inst_id");
        std::string reg_name = params.value("reg_name", "x0");

        int idx = reg_name_to_idx(reg_name);
        if (idx < 0) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32602, "Unknown register: " + reg_name);
        }
        const auto& state = regfile_.state_before(inst_id);
        json r;
        r["reg_name"] = reg_name;
        r["value"]    = fmt::format("0x{:X}", state.gpr[idx]);
        r["inst_id"]  = inst_id;
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_regs ──────────────────────────────────────────────────────────
    server_->register_method("get_regs", [this](const RpcRequest& req) {
        json params = json::parse(req.params_json);
        uint64_t inst_id = get_u64(params, "inst_id");
        const auto& state = regfile_.state_before(inst_id);
        json r;
        r["inst_id"] = inst_id;
        json regs;
        for (int i = 0; i < 34; i++) {
            regs[kRegNames[i]] = fmt::format("0x{:X}", state.gpr[i]);
        }
        r["regs"] = std::move(regs);
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── read_mem ──────────────────────────────────────────────────────────
    server_->register_method("read_mem", [this](const RpcRequest& req) {
        json params = json::parse(req.params_json);
        uint64_t addr    = get_u64(params, "addr");
        uint64_t size    = get_u64(params, "size", 16);
        uint64_t inst_id = get_u64(params, "inst_id", index_.inst_count());

        // Cap to 4KB for safety
        size = std::min(size, uint64_t(4096));

        auto rr = memory_.read_region(addr, static_cast<size_t>(size), inst_id);

        json r;
        r["addr"]    = fmt::format("0x{:X}", addr);
        r["size"]    = size;
        r["inst_id"] = inst_id;
        json data_arr = json::array();
        json known_arr = json::array();
        for (size_t i = 0; i < rr.data.size(); i++) {
            data_arr.push_back(rr.data[i]);
            known_arr.push_back(rr.known[i]);
        }
        r["data"]        = std::move(data_arr);
        r["known"]       = std::move(known_arr);
        r["known_count"] = rr.known_count;
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_range ─────────────────────────────────────────────────────────
    server_->register_method("get_range", [this](const RpcRequest& req) {
        json params = json::parse(req.params_json);
        uint64_t start = get_u64(params, "start", 0);
        uint64_t end   = get_u64(params, "end", start + 100);
        // Cap range
        uint64_t count = std::min(end - start, uint64_t(1000));
        end = start + count;

        json rows = json::array();
        for (uint64_t id = start; id < end && id < index_.inst_count(); id++) {
            auto [offset, seed_pc] = index_.offset_of_with_pc(id, reader_);
            auto rv = reader_.record_at(offset, seed_pc);
            if (rv.kind != RecordKind::Inst) continue;
            auto inst = rv.as_inst();

            json row;
            row["inst_id"] = id;
            row["pc"]      = fmt::format("0x{:X}", inst.pc);

            json diffs = json::array();
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                auto rd = inst.reg_diff(i);
                diffs.push_back({{"reg", kRegNames[rd.index]},
                                 {"value", fmt::format("0x{:X}", rd.value)}});
            }
            row["reg_diffs"] = std::move(diffs);

            json mems = json::array();
            for (uint8_t i = 0; i < inst.mem_access_count; i++) {
                auto m = inst.mem_access(i);
                mems.push_back({
                    {"type", (m.type & 2) ? "W" : "R"},
                    {"addr", fmt::format("0x{:X}", m.addr)},
                    {"size", m.size},
                    {"value", fmt::format("0x{:X}", m.value)}
                });
            }
            row["mem_accesses"] = std::move(mems);
            rows.push_back(std::move(row));
        }
        json r;
        r["rows"]  = std::move(rows);
        r["start"] = start;
        r["end"]   = end;
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_xref ──────────────────────────────────────────────────────────
    // Returns all inst_ids that executed at a given PC (via XRef pass result if available).
    server_->register_method("get_xref", [this](const RpcRequest& req) {
        json params = json::parse(req.params_json);
        uint64_t pc = get_u64(params, "pc");

        json r;
        r["pc"]    = fmt::format("0x{:X}", pc);

        if (pm_) {
            const auto& xref_raw = pm_->require("xref");
            if (xref_raw.ok()) {
                const auto& xref = xref_raw.get<XrefResult>();
                auto inst_ids = xref.inst_ids_at(pc);
                // Limit to 10000 results
                if (inst_ids.size() > 10000) inst_ids.resize(10000);
                r["inst_ids"]  = std::move(inst_ids);
                r["exec_count"] = xref.execution_count(pc);
                return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
            }
        }
        // XRef pass not available — do a linear scan (expensive, warn)
        r["inst_ids"]  = json::array();
        r["exec_count"] = 0;
        r["warning"]    = "xref pass not available";
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_cfg ───────────────────────────────────────────────────────────
    server_->register_method("get_cfg", [this](const RpcRequest& req) {
        if (!pm_) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32603, "PassManager not available");
        }
        const auto& raw = pm_->require("cfg_layout");
        if (!raw.ok()) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32603, "CFG layout pass failed: " + raw.error_message);
        }
        const auto& layout = raw.get<CFGLayoutResult>();
        json r;
        r["dot"] = layout.dot_annotated;
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_call_graph ────────────────────────────────────────────────────
    server_->register_method("get_call_graph", [this](const RpcRequest& req) {
        if (!pm_) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32603, "PassManager not available");
        }
        const auto& raw = pm_->require("call_graph");
        if (!raw.ok()) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32603, "Call graph pass failed: " + raw.error_message);
        }
        const auto& cg = raw.get<CallGraphResult>();
        json r;
        json nodes = json::array();
        for (const auto& [pc, node] : cg.nodes) {
            nodes.push_back({
                {"pc",   fmt::format("0x{:X}", pc)},
                {"name", node.name.empty() ? fmt::format("sub_{:X}", pc) : node.name},
                {"calls_made",     node.total_calls_made},
                {"calls_received", node.total_calls_received}
            });
        }
        json edges = json::array();
        for (const auto& edge : cg.edges) {
            edges.push_back({
                {"caller",     fmt::format("0x{:X}", edge.caller_pc)},
                {"callee",     fmt::format("0x{:X}", edge.callee_pc)},
                {"call_count", edge.call_count}
            });
        }
        r["nodes"] = std::move(nodes);
        r["edges"] = std::move(edges);
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });

    // ── get_taint ─────────────────────────────────────────────────────────
    // Runs/returns existing taint pass result for the given source regs.
    server_->register_method("get_taint", [this](const RpcRequest& req) {
        json params = json::parse(req.params_json);
        uint64_t inst_id = get_u64(params, "inst_id", 0);
        (void)inst_id;

        if (!pm_) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32603, "PassManager not available");
        }
        const auto& raw = pm_->require("taint");
        if (!raw.ok()) {
            return make_error(req.id_str, req.id_is_int, req.id_int,
                              -32603, "Taint pass not run or failed: " + raw.error_message);
        }
        const auto& taint = raw.get<TaintResult>();
        json r;
        r["instructions_processed"] = taint.instructions_processed;

        // Tainted registers (final state)
        json tainted_regs = json::array();
        {
            uint64_t mask = taint.tainted_regs;
            while (mask) {
                int bit = __builtin_ctzll(mask);
                if (bit < 34) tainted_regs.push_back(kRegNames[bit]);
                mask &= mask - 1;
            }
        }
        r["tainted_regs"] = std::move(tainted_regs);
        r["step_count"]   = taint.steps.size();

        json steps_arr = json::array();
        size_t limit = std::min(taint.steps.size(), size_t(500));
        for (size_t i = 0; i < limit; i++) {
            const auto& s = taint.steps[i];
            steps_arr.push_back({
                {"inst_id", s.inst_id},
                {"pc",      fmt::format("0x{:X}", s.pc)},
                {"dst_reg", (s.dst_reg < 34) ? kRegNames[s.dst_reg] : "?"}
            });
        }
        r["steps"]            = std::move(steps_arr);
        if (taint.steps.size() > 500) r["steps_truncated"] = true;
        return make_result(req.id_str, req.id_is_int, req.id_int, r.dump());
    });
}

}  // namespace tenet

#include "mcp_hub.h"
#include "common/logger.h"

#include <fmt/core.h>

#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <cstring>
#include <sstream>
#include <algorithm>
#include <random>
#include <chrono>

using json = nlohmann::json;

namespace tenet {

// ═══════════════════════════════════════════════════════════════════════════
// HubElection — flock-based leader election
// ═══════════════════════════════════════════════════════════════════════════

static std::string get_default_lock_dir() {
    const char* home = getenv("HOME");
    if (!home) home = "/tmp";
    return std::string(home) + "/.tenet";
}

static constexpr uint32_t HUB_LOCK_MAGIC = 0x54485542;  // "THUB"

struct HubLockFileData {
    uint32_t magic;           // HUB_LOCK_MAGIC
    pid_t    hub_pid;
    uint16_t hub_port;
    uint64_t start_time;      // epoch seconds
    char     trace_file[256];
    char     instance_id[64];
};

HubElection::HubElection(const std::string& lock_dir,
                         pid_t pid, uint16_t hub_port,
                         const std::string& trace_file,
                         const std::string& instance_id)
    : pid_(pid), hub_port_(hub_port),
      trace_file_(trace_file), instance_id_(instance_id) {
    std::string dir = lock_dir.empty() ? get_default_lock_dir() : lock_dir;
    lock_path_ = dir + "/mcp-hub.lock";

    // Ensure directory exists
    ::mkdir(dir.c_str(), 0755);
}

HubElection::~HubElection() {
    release();
}

bool HubElection::try_acquire() {
    if (is_hub_) return true;

    fd_ = ::open(lock_path_.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd_ < 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub-election: open({}) failed: {}",
                    lock_path_, strerror(errno));
        return false;
    }

    // Non-blocking exclusive lock
    if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // Someone else holds the lock
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        LOG_ERROR_M(log::Module::Mcp, "hub-election: flock failed: {}", strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    // We got the lock — write our info
    HubLockFileData data{};
    data.magic      = HUB_LOCK_MAGIC;
    data.hub_pid    = pid_;
    data.hub_port   = hub_port_;
    data.start_time = static_cast<uint64_t>(time(nullptr));
    std::strncpy(data.trace_file, trace_file_.c_str(), sizeof(data.trace_file) - 1);
    std::strncpy(data.instance_id, instance_id_.c_str(), sizeof(data.instance_id) - 1);

    // Truncate and write
    ::ftruncate(fd_, 0);
    ::pwrite(fd_, &data, sizeof(data), 0);
    ::fsync(fd_);

    is_hub_ = true;
    LOG_INFO_M(log::Module::Mcp, "hub-election: acquired hub role (pid={}, port={}, lock={})",
               pid_, hub_port_, lock_path_);
    return true;
}

void HubElection::release() {
    if (!is_hub_) return;

    if (fd_ >= 0) {
        // Truncate the lock file content before unlocking
        ::ftruncate(fd_, 0);
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
    }
    is_hub_ = false;
    LOG_INFO_M(log::Module::Mcp, "hub-election: released hub role");
}

HubElection::HubInfo HubElection::read_current() const {
    HubInfo info;
    int fd = ::open(lock_path_.c_str(), O_RDONLY);
    if (fd < 0) return info;

    // Try shared lock (non-blocking) — if it fails, someone holds EX lock
    // and is actively the hub. If it succeeds, we can read safely.
    // Actually, we don't need to lock to read — flock ensures writer
    // consistency. Just read.
    HubLockFileData data{};
    ssize_t n = ::pread(fd, &data, sizeof(data), 0);
    ::close(fd);

    if (n < (ssize_t)sizeof(data)) return info;
    if (data.magic != HUB_LOCK_MAGIC) return info;

    // Verify the hub process is still alive
    if (data.hub_pid > 0 && ::kill(data.hub_pid, 0) != 0) {
        // Process is dead — lock file is stale
        return info;
    }

    info.valid       = true;
    info.pid         = data.hub_pid;
    info.port        = data.hub_port;
    info.trace_file  = data.trace_file;
    info.instance_id = data.instance_id;
    return info;
}

// ═══════════════════════════════════════════════════════════════════════════
// HubInstance — write queue
// ═══════════════════════════════════════════════════════════════════════════

void HubInstance::send(const json& msg) {
    std::string data = msg.dump() + "\n";
    std::lock_guard<std::mutex> lk(write_mutex);
    if (sock_fd >= 0) {
        // MSG_NOSIGNAL to avoid SIGPIPE on broken connection
        ::send(sock_fd, data.data(), data.size(), MSG_NOSIGNAL);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// McpHubTransport — hub-side transport (HTTP + worker TCP on same port)
// ═══════════════════════════════════════════════════════════════════════════

static constexpr const char* WORKER_PROTOCOL_GREETING = "WORKER/1.0\n";

McpHubTransport::McpHubTransport(MessageHandler handler,
                                 const std::string& host, uint16_t port,
                                 bool session_mode,
                                 const std::string& hub_instance_id)
    : handler_(std::move(handler)),
      host_(host), port_(port),
      session_mode_(session_mode),
      hub_instance_id_(hub_instance_id) {}

McpHubTransport::~McpHubTransport() {
    stop();
}

bool McpHubTransport::start() {
    server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub: socket() failed: {}", strerror(errno));
        return false;
    }

    int optval = 1;
    ::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port_);
    if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (::bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub: bind({}:{}) failed: {}", host_, port_, strerror(errno));
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    if (::listen(server_fd_, 128) < 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub: listen() failed: {}", strerror(errno));
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    struct sockaddr_in bound_addr{};
    socklen_t bound_len = sizeof(bound_addr);
    if (::getsockname(server_fd_, reinterpret_cast<struct sockaddr*>(&bound_addr), &bound_len) == 0) {
        listening_port_ = ntohs(bound_addr.sin_port);
    } else {
        listening_port_ = port_;
    }

    int flags = ::fcntl(server_fd_, F_GETFL, 0);
    ::fcntl(server_fd_, F_SETFL, flags | O_NONBLOCK);

    running_.store(true);
    listener_thread_ = std::thread([this] { listener_loop(); });

    // Start heartbeat reaper
    reaper_running_.store(true);
    reaper_thread_ = std::thread([this] {
        while (reaper_running_.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            reap_stale_workers();
        }
    });

    LOG_INFO_M(log::Module::Mcp, "hub: listening on {}:{} (session_mode={})",
               host_, listening_port_, session_mode_ ? "true" : "false");
    return true;
}

void McpHubTransport::stop() {
    if (!running_.exchange(false)) return;

    // Notify workers
    notify_shutdown();

    // Stop listener
    int sfd = server_fd_;
    if (sfd >= 0) ::shutdown(sfd, SHUT_RDWR);
    if (listener_thread_.joinable()) listener_thread_.join();
    if (sfd >= 0) { ::close(sfd); server_fd_ = -1; }

    // Stop reaper
    reaper_running_.store(false);
    if (reaper_thread_.joinable()) reaper_thread_.join();

    // Join client threads
    {
        std::vector<std::thread> threads_to_join;
        {
            std::lock_guard<std::mutex> lk(clients_mutex_);
            threads_to_join = std::move(client_threads_);
        }
        for (auto& t : threads_to_join) {
            if (t.joinable()) t.join();
        }
    }

    // Close all worker connections
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        for (auto& [id, inst] : instances_) {
            if (inst && inst->sock_fd >= 0) {
                ::close(inst->sock_fd);
                inst->sock_fd = -1;
            }
            // Wake up any pending requests
            inst->pending_cv.notify_all();
        }
        instances_.clear();
    }
}

void McpHubTransport::listener_loop() {
    while (running_.load()) {
        int sfd = server_fd_;
        if (sfd < 0) break;

        struct pollfd pfd{sfd, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 200);
        if (ret <= 0) continue;
        if (!running_.load()) break;

        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(sfd,
                                 reinterpret_cast<struct sockaddr*>(&client_addr),
                                 &client_len);
        if (client_fd < 0) continue;

        char ip_buf[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
        std::string client_id = fmt::format("{}:{}", ip_buf, ntohs(client_addr.sin_port));

        struct timeval recv_tv{10, 0};
        ::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));
        int ka = 1;
        ::setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));

        std::lock_guard<std::mutex> lk(clients_mutex_);
        client_threads_.emplace_back([this, client_fd, client_id] {
            // Peek at first bytes to detect protocol
            char peek_buf[16] = {};
            ssize_t peeked = ::recv(client_fd, peek_buf, sizeof(peek_buf) - 1, MSG_PEEK);

            if (peeked > 0 && strncmp(peek_buf, "WORKER/", 7) == 0) {
                // Worker connection
                handle_worker_connection(client_fd, client_id);
            } else {
                // HTTP connection (MCP client)
                handle_http_client(client_fd, client_id);
            }
            ::close(client_fd);

            // Self-cleanup: remove finished threads
            std::lock_guard<std::mutex> lk2(clients_mutex_);
            client_threads_.erase(
                std::remove_if(client_threads_.begin(), client_threads_.end(),
                    [](const std::thread& t) {
                        // Can't check joinable without joining, but we can
                        // use a trick: threads that are done will have
                        // id == this thread. We'll just let them accumulate
                        // and clean up in stop().
                        return false;
                    }),
                client_threads_.end());
        });
    }
}

// ─── HTTP handling (reuses McpHttpTransport protocol) ─────────────────────

McpHubTransport::HttpRequest McpHubTransport::parse_http_request(int fd) {
    HttpRequest req;
    std::string raw;
    raw.reserve(4096);
    char buf[1024];
    while (true) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return req;
        raw.append(buf, static_cast<size_t>(n));
        size_t hdr_end = raw.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
            std::string body_prefix;
            if (hdr_end + 4 < raw.size())
                body_prefix = raw.substr(hdr_end + 4);
            raw = raw.substr(0, hdr_end + 4);

            std::istringstream ss(raw);
            std::string request_line;
            std::getline(ss, request_line);
            if (!request_line.empty() && request_line.back() == '\r')
                request_line.pop_back();

            std::istringstream rl(request_line);
            std::string ver, full_path;
            rl >> req.method >> full_path >> ver;

            size_t q = full_path.find('?');
            if (q != std::string::npos) {
                req.path  = full_path.substr(0, q);
                req.query = full_path.substr(q + 1);
            } else {
                req.path = full_path;
            }

            std::string hdr_line;
            while (std::getline(ss, hdr_line)) {
                if (!hdr_line.empty() && hdr_line.back() == '\r') hdr_line.pop_back();
                if (hdr_line.empty()) break;
                size_t colon = hdr_line.find(':');
                if (colon != std::string::npos) {
                    std::string key = hdr_line.substr(0, colon);
                    std::string val = hdr_line.substr(colon + 1);
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                        val.erase(val.begin());
                    for (auto& c : key) c = static_cast<char>(std::tolower(c));
                    req.headers[key] = val;
                }
            }

            size_t content_length = 0;
            auto it = req.headers.find("content-length");
            if (it != req.headers.end()) {
                try { content_length = static_cast<size_t>(std::stoul(it->second)); }
                catch (...) {}
            }
            content_length = std::min(content_length, size_t(1024 * 1024));
            req.body = std::move(body_prefix);
            while (req.body.size() < content_length) {
                size_t need = content_length - req.body.size();
                size_t chunk = std::min(need, sizeof(buf));
                ssize_t nb = ::recv(fd, buf, chunk, 0);
                if (nb <= 0) break;
                req.body.append(buf, static_cast<size_t>(nb));
            }
            req.valid = !req.method.empty() && !req.path.empty();
            return req;
        }
        if (raw.size() > 16 * 1024) return req;
    }
}

void McpHubTransport::send_http_response(int fd, int status,
                                         const std::string& content_type,
                                         const std::string& body,
                                         const std::string& extra_headers) {
    const char* reason = (status == 200) ? "OK"
                       : (status == 202) ? "Accepted"
                       : (status == 204) ? "No Content"
                       : (status == 400) ? "Bad Request"
                       : (status == 401) ? "Unauthorized"
                       : (status == 404) ? "Not Found"
                       : (status == 405) ? "Method Not Allowed"
                       : (status == 408) ? "Request Timeout"
                       : (status == 502) ? "Bad Gateway"
                       : "Internal Server Error";

    std::string resp = fmt::format(
        "HTTP/1.1 {} {}\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, Mcp-Session-Id\r\n"
        "Connection: close\r\n"
        "{}"
        "\r\n"
        "{}",
        status, reason, content_type, body.size(),
        extra_headers.empty() ? "" : extra_headers + "\r\n",
        body);
    ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
}

void McpHubTransport::handle_http_client(int fd, const std::string& addr) {
    auto req = parse_http_request(fd);
    if (!req.valid) return;

    auto t0 = TENET_TIMER_START();
    auto log_response = [&](int status) {
        double ms = TENET_TIMER_MS(t0);
        if (req.path == "/health") {
            LOG_TRACE_M(log::Module::Mcp, "hub-http {} {} {} -> {}  {:.1f}ms",
                        addr, req.method, req.path, status, ms);
        } else if (status >= 400) {
            LOG_WARN_M(log::Module::Mcp, "hub-http {} {} {} -> {}  {:.1f}ms",
                       addr, req.method, req.path, status, ms);
        } else {
            LOG_DEBUG_M(log::Module::Mcp, "hub-http {} {} {} -> {}  {:.1f}ms",
                        addr, req.method, req.path, status, ms);
        }
    };

    if (req.method == "OPTIONS") {
        send_http_response(fd, 204, "text/plain", "");
        log_response(204);
        return;
    }

    if (req.path == "/health") {
        send_http_response(fd, 200, "application/json", R"({"status":"ok"})");
        log_response(200);
        return;
    }

    if (req.path == "/mcp" && req.method == "POST") {
        if (req.body.empty()) {
            send_http_response(fd, 400, "application/json",
                               R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Empty request body"}})");
            log_response(400);
            return;
        }

        json msg;
        try {
            msg = json::parse(req.body);
        } catch (const json::parse_error& e) {
            json err_resp = {
                {"jsonrpc", "2.0"}, {"id", nullptr},
                {"error", {{"code", -32700}, {"message", std::string("Parse error: ") + e.what()}}}
            };
            send_http_response(fd, 200, "application/json", err_resp.dump());
            log_response(200);
            return;
        }

        // Dispatch to handler (which is TenetMcpService::process_message_hub)
        json response;
        try {
            response = handler_(msg);
        } catch (const std::exception& e) {
            response = {
                {"jsonrpc", "2.0"},
                {"id", msg.value("id", json(nullptr))},
                {"error", {{"code", -32603}, {"message", std::string("Internal error: ") + e.what()}}}
            };
        }

        if (response.is_null()) {
            send_http_response(fd, 202, "application/json", R"({"accepted":true})");
            log_response(202);
            return;
        }

        send_http_response(fd, 200, "application/json", response.dump());
        log_response(200);
        return;
    }

    if (req.path == "/mcp" && req.method == "DELETE") {
        send_http_response(fd, 200, "application/json",
                           R"({"status":"ok","message":"Session management handled by hub"})");
        log_response(200);
        return;
    }

    if (req.path == "/mcp" && req.method == "GET") {
        send_http_response(fd, 405, "application/json",
                           R"({"error":"Use POST /mcp for all interactions."})");
        log_response(405);
        return;
    }

    send_http_response(fd, 404, "application/json", R"({"error":"Not Found"})");
    log_response(404);
}

// ─── Worker connection handling ───────────────────────────────────────────

void McpHubTransport::handle_worker_connection(int fd, const std::string& addr) {
    // Read the "WORKER/1.0\n" greeting
    char greeting[64] = {};
    ssize_t n = ::recv(fd, greeting, sizeof(greeting) - 1, 0);
    if (n <= 0) return;

    std::string greeting_str(greeting, n);
    // Verify it's our protocol
    if (greeting_str.find("WORKER/1.0") == std::string::npos) return;

    // The greeting might also contain the registration message on the same recv.
    // Parse any remaining data after the greeting line.
    std::string extra;
    size_t nl = greeting_str.find('\n');
    if (nl != std::string::npos && nl + 1 < greeting_str.size()) {
        extra = greeting_str.substr(nl + 1);
    }

    // Read registration message
    json reg_msg;
    if (!extra.empty()) {
        // Try parsing extra as the registration JSON
        try {
            reg_msg = json::parse(extra);
        } catch (...) {
            reg_msg = json();
        }
    }
    if (reg_msg.empty() || !reg_msg.contains("type")) {
        // Read next line
        std::string line = extra;
        if (!line.empty() && line.back() == '\n') {
            // Already have a complete line
        } else {
            char buf[4096];
            while (line.find('\n') == std::string::npos) {
                ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
                if (r <= 0) return;
                line.append(buf, r);
                if (line.size() > 65536) return;
            }
        }
        try {
            reg_msg = json::parse(line.substr(0, line.find('\n')));
        } catch (...) {
            LOG_WARN_M(log::Module::Mcp, "hub: worker {} sent invalid registration", addr);
            return;
        }
    }

    if (reg_msg.value("type", "") != "register") {
        LOG_WARN_M(log::Module::Mcp, "hub: worker {} expected 'register', got '{}'",
                   addr, reg_msg.value("type", ""));
        return;
    }

    std::string worker_id = reg_msg.value("id", "");
    if (worker_id.empty()) {
        LOG_WARN_M(log::Module::Mcp, "hub: worker {} missing 'id' in registration", addr);
        return;
    }

    // Register the worker
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        // Remove existing instance with same ID (reconnection)
        if (instances_.count(worker_id)) {
            int old_fd = instances_[worker_id]->sock_fd;
            if (old_fd >= 0 && old_fd != fd) {
                ::close(old_fd);
            }
        }
        auto inst = std::make_unique<HubInstance>();
        inst->id            = worker_id;
        inst->pid           = reg_msg.value("pid", 0);
        inst->trace_file    = reg_msg.value("trace_file", "");
        inst->module_name   = reg_msg.value("module_name", "");
        inst->is_hub        = false;
        inst->sock_fd       = fd;
        inst->last_heartbeat = std::chrono::steady_clock::now();
        instances_[worker_id] = std::move(inst);
    }

    LOG_INFO_M(log::Module::Mcp, "hub: worker '{}' registered (pid={}, trace={}, addr={})",
               worker_id, reg_msg.value("pid", 0), reg_msg.value("trace_file", ""), addr);

    // Send registration confirmation
    json confirm = {
        {"type", "registered"},
        {"hub_id", hub_instance_id_},
        {"session_mode", session_mode_}
    };
    std::string confirm_str = confirm.dump() + "\n";
    ::send(fd, confirm_str.data(), confirm_str.size(), MSG_NOSIGNAL);

    // Enter read loop (heartbeat + rpc_response from this worker)
    std::string recv_buf;
    char buf[65536];
    while (running_.load()) {
        struct pollfd pfd{fd, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 30000);  // 30s timeout
        if (ret <= 0) {
            if (ret == 0) {
                // Timeout — check if worker is still alive
                std::lock_guard<std::mutex> lk(registry_mutex_);
                auto it = instances_.find(worker_id);
                if (it == instances_.end()) break;  // Removed
                auto age = std::chrono::steady_clock::now() - it->second->last_heartbeat;
                if (age > std::chrono::seconds(60)) {
                    LOG_WARN_M(log::Module::Mcp, "hub: worker '{}' heartbeat timeout (60s), disconnecting",
                               worker_id);
                    break;
                }
                continue;
            }
            break;  // Error
        }

        ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
        if (r <= 0) break;  // Connection closed

        recv_buf.append(buf, r);

        // Process complete lines
        size_t pos;
        while ((pos = recv_buf.find('\n')) != std::string::npos) {
            std::string line = recv_buf.substr(0, pos);
            recv_buf.erase(0, pos + 1);

            if (line.empty()) continue;

            json msg;
            try {
                msg = json::parse(line);
            } catch (...) {
                continue;
            }

            std::string msg_type = msg.value("type", "");

            if (msg_type == "heartbeat") {
                std::lock_guard<std::mutex> lk(registry_mutex_);
                auto it = instances_.find(worker_id);
                if (it != instances_.end()) {
                    it->second->last_heartbeat = std::chrono::steady_clock::now();
                }
            } else if (msg_type == "rpc_response") {
                std::string req_id = msg.value("id", "");
                json response = msg.value("msg", json());
                bool is_error = msg.value("error", false);

                std::lock_guard<std::mutex> lk(registry_mutex_);
                auto it = instances_.find(worker_id);
                if (it != instances_.end()) {
                    auto& pending = it->second->pending;
                    auto pit = pending.find(req_id);
                    if (pit != pending.end()) {
                        pit->second.response  = std::move(response);
                        pit->second.error     = is_error;
                        pit->second.completed = true;
                        it->second->pending_cv.notify_all();
                    }
                }
            } else if (msg_type == "unregister") {
                LOG_INFO_M(log::Module::Mcp, "hub: worker '{}' unregistered gracefully", worker_id);
                break;
            }
        }
    }

    // Clean up: remove worker from registry
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto it = instances_.find(worker_id);
        if (it != instances_.end() && it->second->sock_fd == fd) {
            it->second->sock_fd = -1;
            // Wake up any pending requests with error
            for (auto& [rid, pr] : it->second->pending) {
                pr.completed = true;
                pr.error = true;
                pr.response = {{"error", "Worker disconnected"}};
            }
            it->second->pending_cv.notify_all();
            instances_.erase(it);
        }
    }

    LOG_INFO_M(log::Module::Mcp, "hub: worker '{}' disconnected", worker_id);
}

// ─── Instance registry operations ─────────────────────────────────────────

json McpHubTransport::list_instances() const {
    json arr = json::array();

    // Hub instance first
    if (instance_info_provider_) {
        json hub_info = instance_info_provider_();
        hub_info["is_hub"] = true;
        arr.push_back(hub_info);
    }

    // Worker instances
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        for (const auto& [id, inst] : instances_) {
            arr.push_back({
                {"id", inst->id},
                {"pid", inst->pid},
                {"trace_file", inst->trace_file},
                {"module_name", inst->module_name},
                {"is_hub", false}
            });
        }
    }

    return {{"instances", std::move(arr)}};
}

bool McpHubTransport::has_instance(const std::string& id) const {
    if (id == hub_instance_id_) return true;
    std::lock_guard<std::mutex> lk(registry_mutex_);
    return instances_.count(id) > 0;
}

json McpHubTransport::forward_request(const std::string& instance_id,
                                       const json& rpc_request,
                                       int timeout_ms) {
    std::string req_id = fmt::format("req-{}", next_request_id_.fetch_add(1));

    // Get the worker instance
    HubInstance* inst = nullptr;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto it = instances_.find(instance_id);
        if (it == instances_.end() || it->second->sock_fd < 0) {
            throw std::runtime_error("Instance not connected: " + instance_id);
        }
        inst = it->second.get();

        // Register pending request
        inst->pending[req_id] = {};
    }

    // Send request to worker
    json fwd = {
        {"type", "rpc"},
        {"id", req_id},
        {"msg", rpc_request}
    };
    inst->send(fwd);

    // Wait for response
    {
        std::unique_lock<std::mutex> lk(inst->pending_mutex);
        auto it = inst->pending.find(req_id);
        if (it == inst->pending.end()) {
            throw std::runtime_error("Pending request vanished");
        }

        bool ok = inst->pending_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
            [&] { return it->second.completed; });

        if (!ok) {
            // Timeout
            std::lock_guard<std::mutex> rlk(registry_mutex_);
            auto rit = instances_.find(instance_id);
            if (rit != instances_.end()) {
                rit->second->pending.erase(req_id);
            }
            throw std::runtime_error("Request timeout (" + std::to_string(timeout_ms) + "ms)");
        }

        json response = std::move(it->second.response);
        bool is_error = it->second.error;

        // Clean up
        {
            std::lock_guard<std::mutex> rlk(registry_mutex_);
            auto rit = instances_.find(instance_id);
            if (rit != instances_.end()) {
                rit->second->pending.erase(req_id);
            }
        }

        if (is_error) {
            throw std::runtime_error(response.value("error", "Unknown worker error"));
        }

        return response;
    }
}

void McpHubTransport::notify_shutdown() {
    json msg = {{"type", "hub_shutdown"}};
    std::lock_guard<std::mutex> lk(registry_mutex_);
    for (auto& [id, inst] : instances_) {
        if (inst && inst->sock_fd >= 0) {
            inst->send(msg);
        }
    }
}

void McpHubTransport::reap_stale_workers() {
    std::vector<std::string> stale;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto now = std::chrono::steady_clock::now();
        for (const auto& [id, inst] : instances_) {
            auto age = now - inst->last_heartbeat;
            if (age > std::chrono::seconds(90)) {
                stale.push_back(id);
            }
        }
    }

    for (const auto& id : stale) {
        LOG_WARN_M(log::Module::Mcp, "hub: reaping stale worker '{}' (no heartbeat 90s)", id);
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto it = instances_.find(id);
        if (it != instances_.end()) {
            if (it->second->sock_fd >= 0) {
                ::close(it->second->sock_fd);
                it->second->sock_fd = -1;
            }
            for (auto& [rid, pr] : it->second->pending) {
                pr.completed = true;
                pr.error = true;
                pr.response = {{"error", "Worker reaped (stale)"}};
            }
            it->second->pending_cv.notify_all();
            instances_.erase(it);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// McpWorkerTransport — connects to hub, receives requests, sends responses
// ═══════════════════════════════════════════════════════════════════════════

McpWorkerTransport::McpWorkerTransport(MessageHandler handler,
                                       const std::string& hub_host, uint16_t hub_port,
                                       const std::string& instance_id,
                                       pid_t pid,
                                       const std::string& trace_file,
                                       const std::string& module_name)
    : handler_(std::move(handler)),
      hub_host_(hub_host), hub_port_(hub_port),
      instance_id_(instance_id), pid_(pid),
      trace_file_(trace_file), module_name_(module_name) {}

McpWorkerTransport::~McpWorkerTransport() {
    stop();
    close_connection();
}

bool McpWorkerTransport::connect_to_hub() {
    sock_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(hub_port_);
    if (::inet_pton(AF_INET, hub_host_.c_str(), &addr.sin_addr) <= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    // 5s connect timeout
    int flags = ::fcntl(sock_fd_, F_GETFL, 0);
    ::fcntl(sock_fd_, F_SETFL, flags | O_NONBLOCK);

    int ret = ::connect(sock_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    if (ret < 0) {
        struct pollfd pfd{sock_fd_, POLLOUT, 0};
        ret = ::poll(&pfd, 1, 5000);
        if (ret <= 0) {
            ::close(sock_fd_);
            sock_fd_ = -1;
            return false;
        }
        int err = 0;
        socklen_t errlen = sizeof(err);
        ::getsockopt(sock_fd_, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (err != 0) {
            ::close(sock_fd_);
            sock_fd_ = -1;
            return false;
        }
    }

    // Restore blocking mode
    ::fcntl(sock_fd_, F_SETFL, flags);

    // Keepalive
    int ka = 1;
    ::setsockopt(sock_fd_, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));

    return true;
}

void McpWorkerTransport::register_with_hub() {
    // Send greeting
    std::string greeting = WORKER_PROTOCOL_GREETING;
    ::send(sock_fd_, greeting.data(), greeting.size(), MSG_NOSIGNAL);

    // Send registration
    json reg = {
        {"type", "register"},
        {"id", instance_id_},
        {"pid", pid_},
        {"trace_file", trace_file_},
        {"module_name", module_name_}
    };
    send_json(reg);

    // Wait for confirmation
    std::string line;
    if (!recv_line(line)) {
        LOG_WARN_M(log::Module::Mcp, "worker: no registration confirmation from hub");
        return;
    }

    try {
        json resp = json::parse(line);
        if (resp.value("type", "") == "registered") {
            session_mode_ = resp.value("session_mode", false);
            LOG_INFO_M(log::Module::Mcp, "worker: registered with hub '{}' (session_mode={})",
                       resp.value("hub_id", "?"), session_mode_);
        }
    } catch (...) {
        LOG_WARN_M(log::Module::Mcp, "worker: invalid registration response from hub");
    }
}

void McpWorkerTransport::run() {
    while (running_.load()) {
        // Try to connect
        if (!connect_to_hub()) {
            // Hub not reachable — wait and retry
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        connected_.store(true);
        register_with_hub();

        if (!connected_.load()) {
            close_connection();
            continue;
        }

        // Start heartbeat thread
        heartbeat_thread_ = std::thread([this] {
            while (running_.load() && connected_.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                if (!running_.load() || !connected_.load()) break;
                send_heartbeat();
            }
        });

        // Enter request loop
        request_loop();

        // Cleanup
        connected_.store(false);
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
        close_connection();

        if (running_.load()) {
            LOG_INFO_M(log::Module::Mcp, "worker: connection to hub lost, will retry...");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void McpWorkerTransport::request_loop() {
    recv_buf_.clear();
    char buf[65536];

    while (running_.load() && connected_.load()) {
        struct pollfd pfd{sock_fd_, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 30000);
        if (ret <= 0) {
            if (ret == 0) continue;  // Timeout, loop again
            break;  // Error
        }

        ssize_t n = ::recv(sock_fd_, buf, sizeof(buf), 0);
        if (n <= 0) break;  // Connection closed

        recv_buf_.append(buf, n);

        // Process complete lines
        size_t pos;
        while ((pos = recv_buf_.find('\n')) != std::string::npos) {
            std::string line = recv_buf_.substr(0, pos);
            recv_buf_.erase(0, pos + 1);

            if (line.empty()) continue;

            json msg;
            try {
                msg = json::parse(line);
            } catch (...) {
                continue;
            }

            std::string msg_type = msg.value("type", "");

            if (msg_type == "rpc") {
                std::string req_id = msg.value("id", "");
                json rpc_request = msg.value("msg", json());

                // Execute the request via handler
                json rpc_response;
                bool is_error = false;
                try {
                    rpc_response = handler_(rpc_request);
                } catch (const std::exception& e) {
                    rpc_response = {
                        {"jsonrpc", "2.0"},
                        {"id", rpc_request.value("id", json(nullptr))},
                        {"error", {{"code", -32603}, {"message", e.what()}}}
                    };
                    is_error = true;
                }

                // Send response back to hub
                json response_msg = {
                    {"type", "rpc_response"},
                    {"id", req_id},
                    {"msg", rpc_response}
                };
                if (is_error) response_msg["error"] = true;
                send_json(response_msg);

            } else if (msg_type == "hub_shutdown") {
                LOG_INFO_M(log::Module::Mcp, "worker: hub shutdown notification received");
                connected_.store(false);
                return;
            } else if (msg_type == "ping") {
                // Simple ping from hub
                json pong = {{"type", "pong"}};
                send_json(pong);
            }
        }
    }
}

void McpWorkerTransport::send_heartbeat() {
    json hb = {{"type", "heartbeat"}, {"id", instance_id_}};
    send_json(hb);
}

bool McpWorkerTransport::send_json(const json& msg) {
    std::string data = msg.dump() + "\n";
    ssize_t n = ::send(sock_fd_, data.data(), data.size(), MSG_NOSIGNAL);
    return n == (ssize_t)data.size();
}

bool McpWorkerTransport::recv_line(std::string& line) {
    while (recv_buf_.find('\n') == std::string::npos) {
        char buf[4096];
        ssize_t n = ::recv(sock_fd_, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        recv_buf_.append(buf, n);
        if (recv_buf_.size() > 65536) return false;
    }
    size_t pos = recv_buf_.find('\n');
    line = recv_buf_.substr(0, pos);
    recv_buf_.erase(0, pos + 1);
    return true;
}

void McpWorkerTransport::close_connection() {
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
    recv_buf_.clear();
}

void McpWorkerTransport::stop() {
    running_.store(false);
    connected_.store(false);
    if (sock_fd_ >= 0) {
        ::shutdown(sock_fd_, SHUT_RDWR);
    }
}

}  // namespace tenet

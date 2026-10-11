#include "mcp_hub.h"
#include "mcp_websocket.h"
#include "common/logger.h"
#include "common/platform_compat.h"
#include "common/platform_file_lock.h"
#include "common/platform_paths.h"

#include <fmt/core.h>

// platform_compat.h already pulls in the right socket headers per platform
// (winsock2.h/ws2tcpip.h on Windows, sys/socket.h/netinet/in.h/arpa/inet.h
// on POSIX) as well as poll()/errno/signal() equivalents (platform::poll_one,
// platform::last_socket_error, SIGPIPE handling in ensure_sockets_initialized)
// -- don't duplicate POSIX-only includes here, they'd break the Windows build.

#include <cstring>
#include <sstream>
#include <algorithm>
#include <random>
#include <chrono>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <string_view>

using json = nlohmann::json;

namespace tenet {
namespace {

std::string json_rpc_error(int code, const std::string& message, const json& id = nullptr) {
    return json{{"jsonrpc", "2.0"},
                {"id", id},
                {"error", {{"code", code}, {"message", message}}}}
        .dump();
}

int64_t heartbeat_now_ticks() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::chrono::milliseconds heartbeat_age(const tenet::HubInstance& inst) {
    const int64_t ticks = inst.last_heartbeat_ticks.load(std::memory_order_relaxed);
    return std::chrono::milliseconds(heartbeat_now_ticks() - ticks);
}

bool send_all_fd(platform::socket_t fd, std::string_view data) {
    return platform::send_all(fd, data.data(), data.size());
}

void mark_pending_error(tenet::HubInstance::PendingRequest& pending, std::string_view error_message) {
    pending.completed = true;
    pending.error = true;
    pending.response = {{"error", std::string(error_message)}};
}

void fail_all_pending(const std::shared_ptr<tenet::HubInstance>& inst, std::string_view error_message) {
    if (!inst) {
        return;
    }
    {
        std::lock_guard<std::mutex> lk(inst->pending_mutex);
        for (auto& [rid, pending] : inst->pending) {
            (void)rid;
            mark_pending_error(pending, error_message);
        }
    }
    inst->pending_cv.notify_all();
}

void ensure_instance_for_ws_call(json& msg, const std::string& bound_instance) {
    if (!msg.is_object()) {
        throw std::runtime_error("Invalid JSON-RPC message type");
    }

    const std::string method = msg.value("method", "");
    if (method.empty()) {
        throw std::runtime_error("Missing JSON-RPC method");
    }

    if (method != "tools/call") {
        return;
    }

    if (!msg.contains("params") || !msg["params"].is_object()) {
        msg["params"] = json::object();
    }
    json& params = msg["params"];

    if (!params.contains("arguments") || !params["arguments"].is_object()) {
        params["arguments"] = json::object();
    }
    json& arguments = params["arguments"];

    if (arguments.contains("instance")) {
        if (!arguments["instance"].is_string()) {
            throw std::runtime_error("params.arguments.instance must be a string");
        }
        const std::string supplied = arguments["instance"].get<std::string>();
        if (supplied != bound_instance) {
            throw std::runtime_error(
                "instance mismatch: websocket is bound to '" + bound_instance +
                "' but request targets '" + supplied + "'");
        }
        return;
    }

    arguments["instance"] = bound_instance;
}

}  // namespace


// ═══════════════════════════════════════════════════════════════════════════
// HubElection — cross-platform advisory-lock leader election
// ═══════════════════════════════════════════════════════════════════════════

static std::string get_default_lock_dir() {
    return platform::user_config_dir().string();
}

static constexpr uint32_t HUB_LOCK_MAGIC = 0x54485542;  // "THUB"

struct HubLockFileData {
    uint32_t magic;           // HUB_LOCK_MAGIC
    platform::pid_t_compat hub_pid;
    uint16_t hub_port;
    uint64_t start_time;      // epoch seconds
    char     trace_file[256];
    char     instance_id[64];
};

HubElection::HubElection(const std::string& lock_dir,
                         platform::pid_t_compat pid, uint16_t hub_port,
                         const std::string& trace_file,
                         const std::string& instance_id)
    : pid_(pid), hub_port_(hub_port),
      trace_file_(trace_file), instance_id_(instance_id) {
    std::string dir = lock_dir.empty() ? get_default_lock_dir() : lock_dir;
    lock_path_ = dir + "/mcp-hub.lock";

    platform::ensure_directory(dir);
}

HubElection::~HubElection() {
    release();
}

bool HubElection::try_acquire() {
    if (is_hub_) return true;

    auto [file_lock, result] = platform::FileLock::try_acquire(lock_path_);
    if (result == platform::FileLock::Result::HeldElsewhere) {
        return false;
    }
    if (result == platform::FileLock::Result::IoError) {
        LOG_ERROR_M(log::Module::Mcp, "hub-election: acquiring {} failed", lock_path_);
        return false;
    }

    // We got the lock — write our info.
    HubLockFileData data{};
    data.magic      = HUB_LOCK_MAGIC;
    data.hub_pid    = pid_;
    data.hub_port   = hub_port_;
    start_time_     = static_cast<uint64_t>(time(nullptr));
    data.start_time = start_time_;
    std::strncpy(data.trace_file, trace_file_.c_str(), sizeof(data.trace_file) - 1);
    std::strncpy(data.instance_id, instance_id_.c_str(), sizeof(data.instance_id) - 1);
    if (!file_lock.write_at_start(&data, sizeof(data))) {
        LOG_ERROR_M(log::Module::Mcp, "hub-election: failed to write {}", lock_path_);
        return false;
    }

    lock_ = std::move(file_lock);
    is_hub_ = true;
    LOG_INFO_M(log::Module::Mcp, "hub-election: acquired hub role (pid={}, port={}, lock={})",
               pid_, hub_port_, lock_path_);
    return true;
}

bool HubElection::update_port(uint16_t hub_port) {
    if (!is_hub_ || !lock_.valid()) return false;

    HubLockFileData data{};
    data.magic      = HUB_LOCK_MAGIC;
    data.hub_pid    = pid_;
    data.hub_port   = hub_port;
    data.start_time = start_time_;
    std::strncpy(data.trace_file, trace_file_.c_str(), sizeof(data.trace_file) - 1);
    std::strncpy(data.instance_id, instance_id_.c_str(), sizeof(data.instance_id) - 1);
    if (!lock_.write_at_start(&data, sizeof(data))) {
        LOG_ERROR_M(log::Module::Mcp, "hub-election: failed to publish listener port {}", hub_port);
        return false;
    }

    hub_port_ = hub_port;
    LOG_INFO_M(log::Module::Mcp, "hub-election: published listener port {}", hub_port_);
    return true;
}

void HubElection::release() {
    if (!is_hub_) return;

    lock_.release();
    is_hub_ = false;
    LOG_INFO_M(log::Module::Mcp, "hub-election: released hub role");
}

HubElection::HubInfo HubElection::read_current() const {
    HubInfo info;
    auto [file_lock, result] = platform::FileLock::try_acquire(lock_path_);
    if (result == platform::FileLock::Result::IoError) return info;

    HubLockFileData data{};
    size_t n = file_lock.read_at_start(&data, sizeof(data));
    if (n != sizeof(data)) return info;
    if (data.magic != HUB_LOCK_MAGIC) return info;

    // Verify the hub process is still alive.
    if (data.hub_pid > 0 && !platform::process_alive(data.hub_pid)) {
        // Process is dead — lock file is stale.
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

bool HubInstance::send(const json& msg) {
    std::string data = msg.dump() + "\n";
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (!platform::socket_valid(sock_fd)) {
        return false;
    }
    return send_all_fd(sock_fd, data);
}

bool HubInstance::has_socket() const {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    return platform::socket_valid(sock_fd);
}

bool HubInstance::matches_socket(platform::socket_t fd) const {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    return sock_fd == fd;
}

void HubInstance::attach_socket(platform::socket_t fd) {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    sock_fd = fd;
}

void HubInstance::shutdown_socket() {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (platform::socket_valid(sock_fd)) {
        platform::shutdown_both(sock_fd);
    }
}

void HubInstance::shutdown_socket_if(platform::socket_t expected_fd) {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (sock_fd == expected_fd && platform::socket_valid(sock_fd)) {
        platform::shutdown_both(sock_fd);
    }
}

void HubInstance::close_socket() {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (platform::socket_valid(sock_fd)) {
        platform::socket_t fd = sock_fd;
        sock_fd = platform::kInvalidSocket;
        platform::shutdown_both(fd);
    }
}

void HubInstance::close_socket_if(platform::socket_t expected_fd) {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (sock_fd == expected_fd && platform::socket_valid(sock_fd)) {
        platform::socket_t fd = sock_fd;
        sock_fd = platform::kInvalidSocket;
        platform::shutdown_both(fd);
    }
}

BoundWsSessionRegistry::SessionToken BoundWsSessionRegistry::register_session(
    platform::socket_t fd, const std::shared_ptr<HubInstance>& bound_instance) {
    std::lock_guard<std::mutex> lk(mutex_);

    if (!platform::socket_valid(fd)) {
        return {};
    }

    auto existing = sessions_by_fd_.find(fd);
    if (existing != sessions_by_fd_.end()) {
        if (existing->second.hub_local) {
            hub_local_fds_.erase(fd);
        } else if (existing->second.identity != nullptr) {
            auto map_it = sessions_by_instance_.find(existing->second.identity);
            if (map_it != sessions_by_instance_.end()) {
                map_it->second.erase(fd);
                if (map_it->second.empty()) {
                    sessions_by_instance_.erase(map_it);
                }
            }
        }
        sessions_by_fd_.erase(existing);
    }

    Binding binding;
    binding.generation = next_generation_++;
    if (bound_instance) {
        binding.bound_instance = bound_instance;
        binding.identity = bound_instance.get();
        binding.hub_local = false;
        sessions_by_instance_[binding.identity].insert(fd);
    } else {
        binding.identity = nullptr;
        binding.hub_local = true;
        hub_local_fds_.insert(fd);
    }
    sessions_by_fd_[fd] = std::move(binding);
    return SessionToken{fd, sessions_by_fd_[fd].generation};
}

void BoundWsSessionRegistry::unregister_session(SessionToken token) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = sessions_by_fd_.find(token.fd);
    if (it == sessions_by_fd_.end() || it->second.generation != token.generation) {
        return;
    }

    if (it->second.hub_local) {
        hub_local_fds_.erase(token.fd);
    } else if (it->second.identity != nullptr) {
        auto map_it = sessions_by_instance_.find(it->second.identity);
        if (map_it != sessions_by_instance_.end()) {
            map_it->second.erase(token.fd);
            if (map_it->second.empty()) {
                sessions_by_instance_.erase(map_it);
            }
        }
    }

    sessions_by_fd_.erase(it);
}

void BoundWsSessionRegistry::unregister_session(platform::socket_t fd) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = sessions_by_fd_.find(fd);
    if (it == sessions_by_fd_.end()) {
        return;
    }

    if (it->second.hub_local) {
        hub_local_fds_.erase(fd);
    } else if (it->second.identity != nullptr) {
        auto map_it = sessions_by_instance_.find(it->second.identity);
        if (map_it != sessions_by_instance_.end()) {
            map_it->second.erase(fd);
            if (map_it->second.empty()) {
                sessions_by_instance_.erase(map_it);
            }
        }
    }

    sessions_by_fd_.erase(it);
}

std::vector<platform::socket_t> BoundWsSessionRegistry::sessions_for_instance(const std::shared_ptr<HubInstance>& bound_instance) const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<platform::socket_t> out;
    if (!bound_instance) {
        return out;
    }

    auto it = sessions_by_instance_.find(bound_instance.get());
    if (it == sessions_by_instance_.end()) {
        return out;
    }
    out.reserve(it->second.size());
    for (platform::socket_t fd : it->second) {
        out.push_back(fd);
    }
    return out;
}

std::vector<platform::socket_t> BoundWsSessionRegistry::hub_local_sessions() const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<platform::socket_t> out;
    out.reserve(hub_local_fds_.size());
    for (platform::socket_t fd : hub_local_fds_) {
        out.push_back(fd);
    }
    return out;
}

std::vector<platform::socket_t> BoundWsSessionRegistry::all_sessions() const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<platform::socket_t> out;
    out.reserve(sessions_by_fd_.size());
    for (const auto& [fd, _binding] : sessions_by_fd_) {
        out.push_back(fd);
    }
    return out;
}

bool BoundWsSessionRegistry::has_session(platform::socket_t fd) const {
    std::lock_guard<std::mutex> lk(mutex_);
    return sessions_by_fd_.count(fd) > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// McpHubTransport — hub-side transport (HTTP + worker TCP on same port)
// ═══════════════════════════════════════════════════════════════════════════

static constexpr const char* WORKER_PROTOCOL_GREETING = "WORKER/1.0\n";
static constexpr size_t kWsTextPayloadLimit = mcpws::kMaxTextPayload;

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
    platform::ensure_sockets_initialized();
    server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!platform::socket_valid(server_fd_)) {
        LOG_ERROR_M(log::Module::Mcp, "hub: socket() failed: {}", platform::last_socket_error_string());
        return false;
    }

    if (!platform::set_reuseaddr(server_fd_)) {
        LOG_WARN_M(log::Module::Mcp, "hub: failed to set SO_REUSEADDR: {}",
                   platform::last_socket_error_string());
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port_);
    if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1) {
        LOG_ERROR_M(log::Module::Mcp, "hub: invalid listen address '{}'", host_);
        platform::close_socket(server_fd_);
        server_fd_ = platform::kInvalidSocket;
        return false;
    }

    if (::bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub: bind({}:{}) failed: {}", host_, port_, platform::last_socket_error_string());
        platform::close_socket(server_fd_);
        server_fd_ = platform::kInvalidSocket;
        return false;
    }

    if (::listen(server_fd_, 128) < 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub: listen() failed: {}", platform::last_socket_error_string());
        platform::close_socket(server_fd_);
        server_fd_ = platform::kInvalidSocket;
        return false;
    }

    struct sockaddr_in bound_addr{};
    platform::socklen_compat_t bound_len = sizeof(bound_addr);
    if (::getsockname(server_fd_, reinterpret_cast<struct sockaddr*>(&bound_addr), &bound_len) != 0) {
        LOG_ERROR_M(log::Module::Mcp, "hub: getsockname() failed: {}",
                    platform::last_socket_error_string());
        platform::close_socket(server_fd_);
        server_fd_ = platform::kInvalidSocket;
        return false;
    }
    listening_port_ = ntohs(bound_addr.sin_port);

    if (!platform::set_nonblocking(server_fd_)) {
        LOG_ERROR_M(log::Module::Mcp, "hub: failed to set listener non-blocking: {}",
                    platform::last_socket_error_string());
        platform::close_socket(server_fd_);
        server_fd_ = platform::kInvalidSocket;
        return false;
    }

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

    // Notify workers so they can reconnect/re-elect quickly.
    notify_shutdown();
    shutdown_all_ws_sessions();

    // Stop listener accept loop first.
    platform::socket_t sfd = server_fd_;
    if (platform::socket_valid(sfd)) {
        platform::shutdown_both(sfd);
    }

    // Force all active client sockets out of recv()/poll() before joining.
    std::vector<platform::socket_t> fds_to_shutdown;
    {
        std::lock_guard<std::mutex> lk(clients_mutex_);
        fds_to_shutdown.reserve(active_client_fds_.size());
        for (platform::socket_t fd : active_client_fds_) {
            fds_to_shutdown.push_back(fd);
        }
    }
    for (platform::socket_t fd : fds_to_shutdown) {
        if (platform::socket_valid(fd)) {
            platform::shutdown_both(fd);
        }
    }

    if (listener_thread_.joinable() &&
        listener_thread_.get_id() != std::this_thread::get_id()) {
        listener_thread_.join();
    }
    if (platform::socket_valid(sfd)) {
        platform::close_socket(sfd);
        server_fd_ = platform::kInvalidSocket;
    }

    // Stop reaper.
    reaper_running_.store(false);
    if (reaper_thread_.joinable() &&
        reaper_thread_.get_id() != std::this_thread::get_id()) {
        reaper_thread_.join();
    }

    // Join client threads (never self-join).
    std::vector<std::thread> threads_to_join;
    {
        std::lock_guard<std::mutex> lk(clients_mutex_);
        threads_to_join = std::move(client_threads_);
    }
    for (auto& t : threads_to_join) {
        if (!t.joinable()) continue;
        if (t.get_id() == std::this_thread::get_id()) {
            t.detach();
            continue;
        }
        t.join();
    }

    // Close all worker connections.
    std::vector<std::shared_ptr<HubInstance>> instances_to_close;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        for (auto& [id, inst] : instances_) {
            (void)id;
            if (inst) {
                inst->close_socket();
                instances_to_close.push_back(inst);
            }
        }
        instances_.clear();
    }
    for (const auto& inst : instances_to_close) {
        fail_all_pending(inst, "Hub stopped");
    }
}

void McpHubTransport::shutdown_fds(const std::vector<platform::socket_t>& fds) {
    for (platform::socket_t fd : fds) {
        if (platform::socket_valid(fd)) {
            platform::shutdown_both(fd);
        }
    }
}

void McpHubTransport::shutdown_ws_sessions_for_instance(const std::shared_ptr<HubInstance>& inst) {
    shutdown_fds(bound_ws_sessions_.sessions_for_instance(inst));
}

void McpHubTransport::shutdown_all_ws_sessions() {
    shutdown_fds(bound_ws_sessions_.all_sessions());
}

void McpHubTransport::listener_loop() {
    while (running_.load()) {
        platform::socket_t sfd = server_fd_;
        if (!platform::socket_valid(sfd)) break;

        int ret = platform::poll_one(sfd, platform::kPollIn, 200);
        if (ret <= 0) continue;
        if (!running_.load()) break;

        struct sockaddr_in client_addr{};
        platform::socklen_compat_t client_len = sizeof(client_addr);
        platform::socket_t client_fd = ::accept(sfd,
                                 reinterpret_cast<struct sockaddr*>(&client_addr),
                                 &client_len);
        if (!platform::socket_valid(client_fd)) continue;

        char ip_buf[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
        std::string client_id = fmt::format("{}:{}", ip_buf, ntohs(client_addr.sin_port));

        platform::set_recv_timeout(client_fd, 10000);
        platform::set_keepalive(client_fd);

        {
            std::lock_guard<std::mutex> lk(clients_mutex_);
            active_client_fds_.insert(client_fd);
        }

        const bool peer_is_loopback = mcpws::is_loopback_address(client_id);
        std::lock_guard<std::mutex> lk(clients_mutex_);
        client_threads_.emplace_back([this, client_fd, client_id, peer_is_loopback] {
            // Peek at first bytes to detect protocol
            char peek_buf[16] = {};
            ssize_t peeked;
            do {
                peeked = ::recv(client_fd, peek_buf, sizeof(peek_buf) - 1, MSG_PEEK);
            } while (peeked < 0 && platform::last_socket_error() == platform::kEIntr);

            if (peeked > 0 && strncmp(peek_buf, "WORKER/", 7) == 0) {
                // Worker connection
                handle_worker_connection(client_fd, client_id);
            } else {
                // HTTP/WS connection
                handle_http_client(client_fd, client_id, peer_is_loopback);
            }

            {
                std::lock_guard<std::mutex> lk2(clients_mutex_);
                active_client_fds_.erase(client_fd);
            }
            platform::close_socket(client_fd);
        });
    }
}

// ─── HTTP handling (reuses McpHttpTransport protocol) ─────────────────────

McpHubTransport::HttpRequest McpHubTransport::parse_http_request(platform::socket_t fd) {
    HttpRequest req;
    std::string raw;
    raw.reserve(4096);
    char buf[1024];
    while (true) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0 && platform::last_socket_error() == platform::kEIntr) continue;
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
                if (nb < 0 && platform::last_socket_error() == platform::kEIntr) continue;
                if (nb <= 0) break;
                req.body.append(buf, static_cast<size_t>(nb));
            }
            req.valid = !req.method.empty() && !req.path.empty();
            return req;
        }
        if (raw.size() > 16 * 1024) return req;
    }
}

bool McpHubTransport::send_all(platform::socket_t fd, std::string_view data) {
    return send_all_fd(fd, data);
}

bool McpHubTransport::has_token_ci(std::string_view header_value, std::string_view token) {
    auto ieq = [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    };

    size_t pos = 0;
    while (pos < header_value.size()) {
        while (pos < header_value.size() && std::isspace(static_cast<unsigned char>(header_value[pos]))) {
            ++pos;
        }
        size_t end = pos;
        while (end < header_value.size() && header_value[end] != ',') {
            ++end;
        }
        size_t tok_end = end;
        while (tok_end > pos && std::isspace(static_cast<unsigned char>(header_value[tok_end - 1]))) {
            --tok_end;
        }
        std::string_view part = header_value.substr(pos, tok_end - pos);
        if (part.size() == token.size() &&
            std::equal(part.begin(), part.end(), token.begin(), token.end(), ieq)) {
            return true;
        }
        pos = (end < header_value.size()) ? end + 1 : end;
    }
    return false;
}

void McpHubTransport::send_http_response(platform::socket_t fd, int status,
                                         const std::string& content_type,
                                         const std::string& body,
                                         const std::string& extra_headers) {
    const char* reason = (status == 101) ? "Switching Protocols"
                       : (status == 200) ? "OK"
                       : (status == 202) ? "Accepted"
                       : (status == 204) ? "No Content"
                       : (status == 400) ? "Bad Request"
                       : (status == 401) ? "Unauthorized"
                       : (status == 403) ? "Forbidden"
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
    send_all(fd, resp);
}

json McpHubTransport::handle_ws_rpc(const std::string& bound_instance,
                                   const std::shared_ptr<HubInstance>& bound_worker,
                                   const json& msg) {
    if (!msg.is_object()) {
        return {
            {"jsonrpc", "2.0"},
            {"id", nullptr},
            {"error", {{"code", -32600}, {"message", "Invalid Request: expected JSON object"}}}
        };
    }

    if (msg.value("jsonrpc", std::string("")) != "2.0") {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg.value("id", json(nullptr))},
            {"error", {{"code", -32600}, {"message", "Invalid Request: jsonrpc must be '2.0'"}}}
        };
    }

    if (bound_worker && !bound_worker->has_socket()) {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg.value("id", json(nullptr))},
            {"error", {{"code", -32001}, {"message", "Bound worker disconnected"}}}
        };
    }

    json routed = msg;
    try {
        ensure_instance_for_ws_call(routed, bound_instance);
    } catch (const std::exception& e) {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg.value("id", json(nullptr))},
            {"error", {{"code", -32602}, {"message", std::string("Invalid params: ") + e.what()}}}
        };
    }

    try {
        return handler_(routed);
    } catch (const std::exception& e) {
        return {
            {"jsonrpc", "2.0"},
            {"id", msg.value("id", json(nullptr))},
            {"error", {{"code", -32603}, {"message", std::string("Internal error: ") + e.what()}}}
        };
    }
}

void McpHubTransport::handle_websocket_client(platform::socket_t fd,
                                              const std::string& addr,
                                              bool peer_is_loopback,
                                              const HttpRequest& req) {
    std::shared_ptr<HubInstance> bound_worker;

    auto path_result = mcpws::extract_ws_instance_from_path(req.path);
    if (!path_result.ok) {
        send_http_response(fd, 404, "application/json", R"({"error":"Unknown instance"})");
        LOG_WARN_M(log::Module::Mcp, "hub-ws {} {} -> 404 ({})", addr, req.path, path_result.error);
        return;
    }

    if (!peer_is_loopback) {
        send_http_response(fd, 403, "application/json", R"({"error":"WebSocket loopback clients only"})");
        LOG_WARN_M(log::Module::Mcp, "hub-ws {} {} -> 403 (non-loopback peer)", addr, req.path);
        return;
    }

    const std::string& bound_instance = path_result.instance;
    if (bound_instance != hub_instance_id_) {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto it = instances_.find(bound_instance);
        if (it == instances_.end()) {
            send_http_response(fd, 404, "application/json", R"({"error":"Unknown instance"})");
            LOG_WARN_M(log::Module::Mcp, "hub-ws {} {} -> 404 (instance='{}' not found)",
                       addr, req.path, bound_instance);
            return;
        }
        bound_worker = it->second;
    }

    if (req.method != "GET") {
        send_http_response(fd, 405, "application/json",
                           R"({"error":"WebSocket endpoint requires GET"})");
        LOG_WARN_M(log::Module::Mcp, "hub-ws {} {} -> 405 (method={})", addr, req.path, req.method);
        return;
    }

    auto up_it = req.headers.find("upgrade");
    auto conn_it = req.headers.find("connection");
    auto ver_it = req.headers.find("sec-websocket-version");
    auto key_it = req.headers.find("sec-websocket-key");

    if (up_it == req.headers.end() ||
        !has_token_ci(up_it->second, "websocket") ||
        conn_it == req.headers.end() ||
        !has_token_ci(conn_it->second, "upgrade") ||
        ver_it == req.headers.end() || ver_it->second != "13" ||
        key_it == req.headers.end() ||
        !mcpws::is_valid_websocket_key(key_it->second)) {
        send_http_response(fd, 400, "application/json",
                           R"({"error":"Invalid WebSocket handshake"})");
        LOG_WARN_M(log::Module::Mcp, "hub-ws {} {} -> 400 (invalid handshake)", addr, req.path);
        return;
    }

    std::string accept = mcpws::websocket_accept_key(key_it->second);
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n"
        "\r\n";
    if (!send_all(fd, response)) {
        return;
    }

    struct WsSessionGuard {
        BoundWsSessionRegistry* registry = nullptr;
        BoundWsSessionRegistry::SessionToken token{};
        bool active = false;

        ~WsSessionGuard() {
            if (active && registry != nullptr) {
                registry->unregister_session(token);
            }
        }
    } ws_guard{&bound_ws_sessions_, {}, true};
    ws_guard.token = bound_ws_sessions_.register_session(fd, bound_worker);

    LOG_INFO_M(log::Module::Mcp, "hub-ws {} connected to instance '{}'", addr, bound_instance);

    json connected = {
        {"jsonrpc", "2.0"},
        {"method", "tenet/connected"},
        {"params", {{"instance", bound_instance}}}
    };
    if (!send_all(fd, mcpws::encode_server_text_frame(connected.dump()))) {
        return;
    }

    std::string recv_buf = req.body;
    recv_buf.reserve(std::max<size_t>(recv_buf.size(), 4096));
    char tmp[4096];

    while (running_.load()) {
        while (!recv_buf.empty()) {
            auto dec = mcpws::decode_client_frame(recv_buf, kWsTextPayloadLimit);
            if (dec.status == mcpws::WsDecodeStatus::NeedMoreData) {
                break;
            }

            if (dec.status != mcpws::WsDecodeStatus::Ok) {
                uint16_t code = 1002;
                if (dec.status == mcpws::WsDecodeStatus::PayloadTooLarge) {
                    code = 1009;
                } else if (dec.status == mcpws::WsDecodeStatus::UnsupportedFrame) {
                    code = 1003;
                }
                std::string reason = dec.error;
                if (reason.size() > 123) {
                    reason.resize(123);
                }
                auto close_frame = mcpws::encode_server_close_frame(code, reason);
                send_all(fd, close_frame);
                return;
            }

            recv_buf.erase(0, dec.consumed);
            const auto& frame = dec.frame;

            if (frame.opcode == mcpws::WsOpcode::Ping) {
                auto pong = mcpws::encode_server_control_frame(mcpws::WsOpcode::Pong, frame.payload);
                if (!send_all(fd, pong)) return;
                continue;
            }
            if (frame.opcode == mcpws::WsOpcode::Pong) {
                continue;
            }
            if (frame.opcode == mcpws::WsOpcode::Close) {
                std::string payload = frame.payload.empty()
                    ? std::string{}
                    : frame.payload.substr(0, std::min<size_t>(frame.payload.size(), 123));
                auto close = mcpws::encode_server_control_frame(mcpws::WsOpcode::Close, payload);
                send_all(fd, close);
                return;
            }

            if (frame.opcode != mcpws::WsOpcode::Text) {
                auto close = mcpws::encode_server_close_frame(1003, "unsupported frame");
                send_all(fd, close);
                return;
            }

            json req_msg;
            try {
                req_msg = json::parse(frame.payload);
            } catch (const json::parse_error& e) {
                // Parse error must not close WS; return JSON-RPC error response.
                if (send_all(fd, mcpws::encode_server_text_frame(
                        json_rpc_error(-32700, std::string("Parse error: ") + e.what())))) {
                    continue;
                }
                return;
            }

            if (!req_msg.is_object()) {
                if (!send_all(fd, mcpws::encode_server_text_frame(
                        json_rpc_error(-32600, "Invalid Request: expected JSON object")))) {
                    return;
                }
                continue;
            }

            // Notification: no id field -> no response frame.
            if (!req_msg.contains("id")) {
                if (req_msg.value("jsonrpc", std::string("")) != "2.0") {
                    if (!send_all(fd, mcpws::encode_server_text_frame(
                            json_rpc_error(-32600, "Invalid Request: jsonrpc must be '2.0'")))) {
                        return;
                    }
                    continue;
                }
                (void)handle_ws_rpc(bound_instance, bound_worker, req_msg);
                continue;
            }

            json rsp = handle_ws_rpc(bound_instance, bound_worker, req_msg);
            if (rsp.is_null()) {
                continue;
            }

            if (!send_all(fd, mcpws::encode_server_text_frame(rsp.dump()))) {
                return;
            }
        }

        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            int err = platform::last_socket_error();
            if (err == platform::kEIntr) continue;
            if (err == platform::kEAgain || err == platform::kEWouldBlock) continue;
            break;
        }
        if (n == 0) break;
        recv_buf.append(tmp, static_cast<size_t>(n));
    }

    LOG_INFO_M(log::Module::Mcp, "hub-ws {} disconnected from instance '{}'", addr, bound_instance);
}

void McpHubTransport::handle_http_client(platform::socket_t fd, const std::string& addr, bool peer_is_loopback) {
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

    if (req.path.rfind("/ws/", 0) == 0) {
        handle_websocket_client(fd, addr, peer_is_loopback, req);
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

void McpHubTransport::handle_worker_connection(platform::socket_t fd, const std::string& addr) {
    // Read the "WORKER/1.0\n" greeting
    char greeting[64] = {};
    ssize_t n;
    do {
        n = ::recv(fd, greeting, sizeof(greeting) - 1, 0);
    } while (n < 0 && platform::last_socket_error() == platform::kEIntr);
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
                if (r < 0 && platform::last_socket_error() == platform::kEIntr) continue;
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

    std::shared_ptr<HubInstance> inst;
    std::shared_ptr<HubInstance> replaced_inst;

    // Register the worker
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto existing = instances_.find(worker_id);
        if (existing != instances_.end()) {
            replaced_inst = existing->second;
            if (replaced_inst) {
                replaced_inst->close_socket();
            }
        }
        inst = std::make_shared<HubInstance>();
        inst->id             = worker_id;
        inst->pid            = reg_msg.value("pid", 0);
        inst->trace_file     = reg_msg.value("trace_file", "");
        inst->module_name    = reg_msg.value("module_name", "");
        inst->is_hub         = false;
        inst->attach_socket(fd);
        inst->last_heartbeat_ticks.store(heartbeat_now_ticks(), std::memory_order_relaxed);
        instances_[worker_id] = inst;
    }
    shutdown_ws_sessions_for_instance(replaced_inst);
    fail_all_pending(replaced_inst, "Worker replaced by reconnect");

    LOG_INFO_M(log::Module::Mcp, "hub: worker '{}' registered (pid={}, trace={}, addr={})",
               worker_id, reg_msg.value("pid", 0), reg_msg.value("trace_file", ""), addr);

    // Send registration confirmation
    json confirm = {
        {"type", "registered"},
        {"hub_id", hub_instance_id_},
        {"session_mode", session_mode_}
    };
    if (!inst->send(confirm)) {
        std::shared_ptr<HubInstance> failed_inst;
        {
            std::lock_guard<std::mutex> lk(registry_mutex_);
            auto it = instances_.find(worker_id);
            if (it != instances_.end() && it->second == inst) {
                failed_inst = it->second;
                failed_inst->close_socket_if(fd);
                instances_.erase(it);
            }
        }
        shutdown_ws_sessions_for_instance(failed_inst);
        fail_all_pending(failed_inst, "Worker registration confirmation failed");
        return;
    }

    // Enter read loop (heartbeat + rpc_response from this worker)
    std::string recv_buf;
    char buf[65536];
    while (running_.load()) {
        int ret = platform::poll_one(fd, platform::kPollIn, 30000);  // 30s timeout
        if (ret <= 0) {
            if (ret == 0) {
                // Timeout — check if worker is still alive
                std::shared_ptr<HubInstance> live_inst;
                {
                    std::lock_guard<std::mutex> lk(registry_mutex_);
                    auto it = instances_.find(worker_id);
                    if (it == instances_.end()) break;  // Removed
                    live_inst = it->second;
                }
                auto age = heartbeat_age(*live_inst);
                if (age > std::chrono::seconds(60)) {
                    LOG_WARN_M(log::Module::Mcp, "hub: worker '{}' heartbeat timeout (60s), disconnecting",
                               worker_id);
                    live_inst->shutdown_socket_if(fd);
                    break;
                }
                continue;
            }
            break;  // Error
        }

        ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
        if (r < 0 && platform::last_socket_error() == platform::kEIntr) continue;
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
                std::shared_ptr<HubInstance> live_inst;
                {
                    std::lock_guard<std::mutex> lk(registry_mutex_);
                    auto it = instances_.find(worker_id);
                    if (it != instances_.end()) {
                        live_inst = it->second;
                    }
                }
                if (live_inst) {
                    live_inst->last_heartbeat_ticks.store(heartbeat_now_ticks(), std::memory_order_relaxed);
                }
            } else if (msg_type == "rpc_response") {
                std::string req_id = msg.value("id", "");
                json response = msg.value("msg", json());
                bool is_error = msg.value("error", false);

                std::shared_ptr<HubInstance> response_inst;
                {
                    std::lock_guard<std::mutex> lk(registry_mutex_);
                    auto it = instances_.find(worker_id);
                    if (it != instances_.end()) {
                        response_inst = it->second;
                    }
                }
                if (response_inst) {
                    std::lock_guard<std::mutex> pending_lk(response_inst->pending_mutex);
                    auto pit = response_inst->pending.find(req_id);
                    if (pit != response_inst->pending.end()) {
                        pit->second.response  = std::move(response);
                        pit->second.error     = is_error;
                        pit->second.completed = true;
                        response_inst->pending_cv.notify_all();
                    }
                }
            } else if (msg_type == "unregister") {
                LOG_INFO_M(log::Module::Mcp, "hub: worker '{}' unregistered gracefully", worker_id);
                break;
            }
        }
    }

    // Clean up: remove worker from registry
    std::shared_ptr<HubInstance> disconnected_inst;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto it = instances_.find(worker_id);
        if (it != instances_.end() && it->second->matches_socket(fd)) {
            disconnected_inst = it->second;
            disconnected_inst->close_socket_if(fd);
            instances_.erase(it);
        }
    }
    shutdown_ws_sessions_for_instance(disconnected_inst);
    fail_all_pending(disconnected_inst, "Worker disconnected");

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

    std::shared_ptr<HubInstance> inst;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        auto it = instances_.find(instance_id);
        if (it == instances_.end() || !it->second || !it->second->has_socket()) {
            throw std::runtime_error("Instance not connected: " + instance_id);
        }
        inst = it->second;
    }

    {
        std::lock_guard<std::mutex> pending_lk(inst->pending_mutex);
        inst->pending[req_id] = {};
    }

    json fwd = {
        {"type", "rpc"},
        {"id", req_id},
        {"msg", rpc_request}
    };
    if (!inst->send(fwd)) {
        std::shared_ptr<HubInstance> failed_inst;
        {
            std::lock_guard<std::mutex> lk(registry_mutex_);
            auto current = instances_.find(instance_id);
            if (current != instances_.end() && current->second == inst) {
                failed_inst = current->second;
                failed_inst->close_socket();
                instances_.erase(current);
            }
        }
        shutdown_ws_sessions_for_instance(failed_inst);
        fail_all_pending(failed_inst, "Failed to send request to worker");
        throw std::runtime_error("Failed to send request to worker");
    }

    std::unique_lock<std::mutex> lk(inst->pending_mutex);
    auto it = inst->pending.find(req_id);
    if (it == inst->pending.end()) {
        throw std::runtime_error("Pending request vanished");
    }

    bool ok = inst->pending_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
        [&] { return it->second.completed; });

    if (!ok) {
        inst->pending.erase(it);
        throw std::runtime_error("Request timeout (" + std::to_string(timeout_ms) + "ms)");
    }

    json response = std::move(it->second.response);
    bool is_error = it->second.error;
    inst->pending.erase(it);
    lk.unlock();

    if (is_error) {
        throw std::runtime_error(response.value("error", "Unknown worker error"));
    }

    return response;
}

void McpHubTransport::notify_shutdown() {
    json msg = {{"type", "hub_shutdown"}};
    std::vector<std::shared_ptr<HubInstance>> instances;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        for (auto& [id, inst] : instances_) {
            (void)id;
            if (inst && inst->has_socket()) {
                instances.push_back(inst);
            }
        }
    }

    for (const auto& inst : instances) {
        if (!inst->send(msg)) {
            std::shared_ptr<HubInstance> failed_inst;
            {
                std::lock_guard<std::mutex> lk(registry_mutex_);
                auto current = instances_.find(inst->id);
                if (current != instances_.end() && current->second == inst) {
                    failed_inst = current->second;
                    failed_inst->close_socket();
                    instances_.erase(current);
                }
            }
            shutdown_ws_sessions_for_instance(inst);
            fail_all_pending(failed_inst ? failed_inst : inst, "Hub shutdown notification failed");
        }
    }
}

void McpHubTransport::reap_stale_workers() {
    std::vector<std::string> stale;
    {
        std::lock_guard<std::mutex> lk(registry_mutex_);
        for (const auto& [id, inst] : instances_) {
            auto age = heartbeat_age(*inst);
            if (age > std::chrono::seconds(90)) {
                stale.push_back(id);
            }
        }
    }

    for (const auto& id : stale) {
        LOG_WARN_M(log::Module::Mcp, "hub: reaping stale worker '{}' (no heartbeat 90s)", id);
        std::shared_ptr<HubInstance> stale_inst;
        {
            std::lock_guard<std::mutex> lk(registry_mutex_);
            auto it = instances_.find(id);
            if (it == instances_.end()) {
                continue;
            }
            stale_inst = it->second;
            stale_inst->close_socket();
            instances_.erase(it);
        }
        shutdown_ws_sessions_for_instance(stale_inst);
        fail_all_pending(stale_inst, "Worker reaped (stale)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// McpWorkerTransport — connects to hub, receives requests, sends responses
// ═══════════════════════════════════════════════════════════════════════════

McpWorkerTransport::McpWorkerTransport(MessageHandler handler,
                                       const std::string& hub_host, uint16_t hub_port,
                                       const std::string& instance_id,
                                       platform::pid_t_compat pid,
                                       const std::string& trace_file,
                                       const std::string& module_name)
    : handler_(std::move(handler)),
      hub_host_(hub_host), hub_port_(hub_port),
      instance_id_(instance_id), pid_(pid),
      trace_file_(trace_file), module_name_(module_name) {}

McpWorkerTransport::~McpWorkerTransport() {
    stop();
}

bool McpWorkerTransport::connect_to_hub() {
    platform::ensure_sockets_initialized();
    platform::socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!platform::socket_valid(fd)) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(hub_port_);
    if (::inet_pton(AF_INET, hub_host_.c_str(), &addr.sin_addr) <= 0) {
        platform::close_socket(fd);
        return false;
    }

    // 5s connect timeout
    if (!platform::set_nonblocking(fd)) {
        LOG_ERROR_M(log::Module::Mcp, "worker: failed to set hub socket non-blocking: {}",
                    platform::last_socket_error_string());
        platform::close_socket(fd);
        return false;
    }

    int ret = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret < 0 && platform::last_socket_error() != platform::kEInProgress) {
        platform::close_socket(fd);
        return false;
    }

    if (ret < 0) {
        ret = platform::poll_one(fd, platform::kPollOut, 5000);
        if (ret <= 0) {
            platform::close_socket(fd);
            return false;
        }
        int err = 0;
        platform::socklen_compat_t errlen = sizeof(err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen) != 0) {
            LOG_WARN_M(log::Module::Mcp, "worker: getsockopt(SO_ERROR) failed: {}",
                       platform::last_socket_error_string());
            platform::close_socket(fd);
            return false;
        }
        if (err != 0) {
            platform::close_socket(fd);
            return false;
        }
    }

    // Restore blocking mode
    if (!platform::set_blocking(fd)) {
        LOG_WARN_M(log::Module::Mcp, "worker: failed to restore blocking mode: {}",
                   platform::last_socket_error_string());
    }

    // Keepalive
    platform::set_keepalive(fd);

    install_socket(fd);
    return true;
}

void McpWorkerTransport::register_with_hub() {
    // Send greeting without taking the send lock recursively.
    const platform::socket_t fd = current_socket_fd();
    if (!platform::socket_valid(fd)) {
        connected_.store(false);
        return;
    }

    std::string greeting = WORKER_PROTOCOL_GREETING;
    {
        std::lock_guard<std::mutex> lk(socket_mutex_);
        if (sock_fd_ != fd || !platform::socket_valid(sock_fd_) || !send_all_fd(sock_fd_, greeting)) {
            connected_.store(false);
            return;
        }
    }

    // Send registration
    json reg = {
        {"type", "register"},
        {"id", instance_id_},
        {"pid", pid_},
        {"trace_file", trace_file_},
        {"module_name", module_name_}
    };
    if (!send_json(reg)) {
        connected_.store(false);
        return;
    }

    // Wait for confirmation
    std::string line;
    if (!recv_line(line)) {
        LOG_WARN_M(log::Module::Mcp, "worker: no registration confirmation from hub");
        connected_.store(false);
        return;
    }

    try {
        json resp = json::parse(line);
        if (resp.value("type", "") == "registered") {
            session_mode_ = resp.value("session_mode", false);
            LOG_INFO_M(log::Module::Mcp, "worker: registered with hub '{}' (session_mode={})",
                       resp.value("hub_id", "?"), session_mode_);
            return;
        }
        LOG_WARN_M(log::Module::Mcp, "worker: unexpected registration response from hub");
    } catch (...) {
        LOG_WARN_M(log::Module::Mcp, "worker: invalid registration response from hub");
    }
    connected_.store(false);
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
        const platform::socket_t fd = current_socket_fd();
        if (!platform::socket_valid(fd)) {
            break;
        }
        int ret = platform::poll_one(fd, platform::kPollIn, 30000);
        if (ret <= 0) {
            if (ret == 0) continue;  // Timeout, loop again
            break;  // Error
        }

        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0 && platform::last_socket_error() == platform::kEIntr) continue;
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
                if (!send_json(response_msg)) {
                    connected_.store(false);
                    return;
                }

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
    if (!send_json(hb)) {
        connected_.store(false);
    }
}

bool McpWorkerTransport::send_json(const json& msg) {
    std::string data = msg.dump() + "\n";
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (!platform::socket_valid(sock_fd_)) {
        return false;
    }
    return send_all_fd(sock_fd_, data);
}

bool McpWorkerTransport::recv_line(std::string& line) {
    while (recv_buf_.find('\n') == std::string::npos) {
        const platform::socket_t fd = current_socket_fd();
        if (!platform::socket_valid(fd)) return false;
        char buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0 && platform::last_socket_error() == platform::kEIntr) continue;
        if (n <= 0) return false;
        recv_buf_.append(buf, n);
        if (recv_buf_.size() > 65536) return false;
    }
    size_t pos = recv_buf_.find('\n');
    line = recv_buf_.substr(0, pos);
    recv_buf_.erase(0, pos + 1);
    return true;
}

platform::socket_t McpWorkerTransport::current_socket_fd() const {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    return sock_fd_;
}

void McpWorkerTransport::install_socket(platform::socket_t fd) {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    sock_fd_ = fd;
}

void McpWorkerTransport::shutdown_connection() {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (platform::socket_valid(sock_fd_)) {
        platform::shutdown_both(sock_fd_);
    }
}

void McpWorkerTransport::close_connection() {
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (platform::socket_valid(sock_fd_)) {
        platform::socket_t fd = sock_fd_;
        sock_fd_ = platform::kInvalidSocket;
        platform::close_socket(fd);
    }
    recv_buf_.clear();
}

void McpWorkerTransport::stop() {
    running_.store(false);
    connected_.store(false);
    shutdown_connection();
}

}  // namespace tenet

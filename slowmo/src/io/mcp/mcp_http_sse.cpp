#include "mcp_http_sse.h"

#include <fmt/core.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <cstring>
#include <sstream>
#include <algorithm>
#include <random>
#include <chrono>

using json = nlohmann::json;

namespace tenet {

// ─── helpers ──────────────────────────────────────────────────────────────

static void mcp_sse_log(const std::string& msg) {
    fmt::print(stderr, "[tenet-mcp-sse] {}\n", msg);
}

// ─── SseSession ───────────────────────────────────────────────────────────

void SseSession::send_event(const json& payload) {
    send_raw("data: " + payload.dump() + "\n\n");
}

void SseSession::send_raw(const std::string& data) {
    if (!alive.load()) return;
    std::lock_guard<std::mutex> lk(write_mutex);
    if (!alive.load()) return;
    ssize_t total = 0;
    const char* ptr = data.data();
    ssize_t remaining = static_cast<ssize_t>(data.size());
    while (remaining > 0) {
        ssize_t n = ::send(fd, ptr + total, static_cast<size_t>(remaining), MSG_NOSIGNAL);
        if (n <= 0) { alive.store(false); return; }
        total += n;
        remaining -= n;
    }
}

// ─── UUID ─────────────────────────────────────────────────────────────────

std::string McpHttpSseTransport::generate_uuid() {
    static std::mt19937_64 rng{
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count())
    };
    uint64_t hi = rng();
    uint64_t lo = rng();
    return fmt::format("{:016x}{:016x}", hi, lo);
}

// ─── Base64 ───────────────────────────────────────────────────────────────

std::string McpHttpSseTransport::base64_encode(const std::string& s) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((s.size() + 2) / 3) * 4);
    for (size_t i = 0; i < s.size(); i += 3) {
        uint32_t b =
            (static_cast<uint8_t>(s[i]) << 16) |
            ((i + 1 < s.size()) ? (static_cast<uint8_t>(s[i+1]) << 8) : 0) |
            ((i + 2 < s.size()) ? static_cast<uint8_t>(s[i+2]) : 0);
        out += tbl[(b >> 18) & 63];
        out += tbl[(b >> 12) & 63];
        out += (i + 1 < s.size()) ? tbl[(b >> 6) & 63] : '=';
        out += (i + 2 < s.size()) ? tbl[ b       & 63] : '=';
    }
    return out;
}

// ─── HTTP request parser ──────────────────────────────────────────────────

McpHttpSseTransport::HttpRequest McpHttpSseTransport::parse_http_request(int fd) {
    HttpRequest req;

    // Read headers (up to 16KB)
    std::string raw;
    raw.reserve(4096);
    char buf[1024];
    while (true) {
        // peek to see if \r\n\r\n is available
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return req;
        raw.append(buf, static_cast<size_t>(n));
        // Check for end of headers
        size_t hdr_end = raw.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
            // Any bytes after header end belong to body
            std::string body_prefix;
            if (hdr_end + 4 < raw.size()) {
                body_prefix = raw.substr(hdr_end + 4);
            }
            raw = raw.substr(0, hdr_end + 4);

            // Parse request line
            std::istringstream ss(raw);
            std::string request_line;
            std::getline(ss, request_line);
            if (!request_line.empty() && request_line.back() == '\r')
                request_line.pop_back();

            std::istringstream rl(request_line);
            std::string ver;
            std::string full_path;
            rl >> req.method >> full_path >> ver;

            // Separate path from query
            size_t q = full_path.find('?');
            if (q != std::string::npos) {
                req.path  = full_path.substr(0, q);
                req.query = full_path.substr(q + 1);
            } else {
                req.path = full_path;
            }

            // Parse headers
            std::string hdr_line;
            while (std::getline(ss, hdr_line)) {
                if (!hdr_line.empty() && hdr_line.back() == '\r') hdr_line.pop_back();
                if (hdr_line.empty()) break;
                size_t colon = hdr_line.find(':');
                if (colon != std::string::npos) {
                    std::string key = hdr_line.substr(0, colon);
                    std::string val = hdr_line.substr(colon + 1);
                    // Trim whitespace
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                        val.erase(val.begin());
                    // Lowercase key
                    for (auto& c : key) c = static_cast<char>(std::tolower(c));
                    req.headers[key] = val;
                }
            }

            // Read body if Content-Length is present
            size_t content_length = 0;
            auto it = req.headers.find("content-length");
            if (it != req.headers.end()) {
                try { content_length = static_cast<size_t>(std::stoul(it->second)); }
                catch (...) {}
            }

            req.body = std::move(body_prefix);
            // Read remaining body bytes (cap at 1MB)
            content_length = std::min(content_length, size_t(1024 * 1024));
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
        if (raw.size() > 16 * 1024) return req;  // reject oversized headers
    }
}

// ─── HTTP response helpers ────────────────────────────────────────────────

void McpHttpSseTransport::send_http_response(int fd, int status,
                                              const std::string& content_type,
                                              const std::string& body,
                                              const std::string& extra_headers) {
    const char* reason = (status == 200) ? "OK"
                       : (status == 204) ? "No Content"
                       : (status == 400) ? "Bad Request"
                       : (status == 401) ? "Unauthorized"
                       : (status == 404) ? "Not Found"
                       : (status == 405) ? "Method Not Allowed"
                       : "Internal Server Error";

    std::string resp = fmt::format(
        "HTTP/1.1 {} {}\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Connection: close\r\n"
        "{}"
        "\r\n"
        "{}",
        status, reason, content_type, body.size(),
        extra_headers.empty() ? "" : extra_headers + "\r\n",
        body);
    ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
}

void McpHttpSseTransport::send_sse_headers(int fd) {
    static const char* hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "\r\n";
    ::send(fd, hdr, strlen(hdr), MSG_NOSIGNAL);
}

// ─── Auth ─────────────────────────────────────────────────────────────────

bool McpHttpSseTransport::check_auth(const HttpRequest& req) const {
    if (!auth_enabled_) return true;
    auto it = req.headers.find("authorization");
    if (it == req.headers.end()) return false;
    const std::string& val = it->second;
    // "Basic <b64>"
    if (val.size() < 7 || val.substr(0, 6) != "Basic ") return false;
    return val.substr(6) == auth_b64_expected_;
}

// ─── Session management ───────────────────────────────────────────────────

std::shared_ptr<SseSession> McpHttpSseTransport::create_session(int fd) {
    auto sess = std::make_shared<SseSession>();
    sess->fd = fd;
    sess->id = generate_uuid();
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    sessions_[sess->id] = sess;
    return sess;
}

std::shared_ptr<SseSession> McpHttpSseTransport::get_session(const std::string& sid) {
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    auto it = sessions_.find(sid);
    return (it != sessions_.end()) ? it->second : nullptr;
}

void McpHttpSseTransport::remove_session(const std::string& sid) {
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    sessions_.erase(sid);
}

size_t McpHttpSseTransport::session_count() const {
    std::lock_guard<std::mutex> lk(sessions_mutex_);
    return sessions_.size();
}

// ─── Constructor / Destructor ─────────────────────────────────────────────

McpHttpSseTransport::McpHttpSseTransport(MessageHandler handler,
                                          const std::string& host,
                                          uint16_t port)
    : handler_(std::move(handler)), host_(host), port_(port) {}

McpHttpSseTransport::~McpHttpSseTransport() {
    stop();
}

void McpHttpSseTransport::set_auth(const std::string& username,
                                    const std::string& password) {
    if (username.empty()) {
        auth_enabled_ = false;
        return;
    }
    auth_username_    = username;
    auth_password_    = password;
    auth_b64_expected_ = base64_encode(username + ":" + password);
    auth_enabled_     = true;
}

// ─── Start / Stop ─────────────────────────────────────────────────────────

bool McpHttpSseTransport::start() {
    server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        mcp_sse_log(fmt::format("socket() failed: {}", strerror(errno)));
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
        mcp_sse_log(fmt::format("bind() failed: {}", strerror(errno)));
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    if (::listen(server_fd_, 16) < 0) {
        mcp_sse_log(fmt::format("listen() failed: {}", strerror(errno)));
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    // Non-blocking for select-based accept loop
    int flags = ::fcntl(server_fd_, F_GETFL, 0);
    ::fcntl(server_fd_, F_SETFL, flags | O_NONBLOCK);

    running_.store(true);
    listener_thread_ = std::thread([this] { listener_loop(); });
    mcp_sse_log(fmt::format("HTTP SSE server listening on {}:{}", host_, port_));
    return true;
}

void McpHttpSseTransport::stop() {
    if (!running_.exchange(false)) return;

    // Shutdown server socket to unblock select()/accept() in listener thread.
    // We shutdown but DON'T close yet — listener thread still references server_fd_.
    int sfd = server_fd_;
    if (sfd >= 0) {
        ::shutdown(sfd, SHUT_RDWR);
    }

    // Mark all sessions as dead and shutdown their fds to unblock I/O
    {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        for (auto& [sid, sess] : sessions_) {
            sess->alive.store(false);
            if (sess->fd >= 0) ::shutdown(sess->fd, SHUT_RDWR);
        }
        // Don't clear yet — client threads may still reference sessions
    }

    // Wait for listener thread to exit (it checks running_ flag)
    if (listener_thread_.joinable()) listener_thread_.join();

    // Now close the server socket — listener is done
    if (sfd >= 0) {
        ::close(sfd);
        server_fd_ = -1;
    }

    // Join all client threads (they should exit quickly since sessions are dead
    // and fds are shut down)
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

    // Now safe to clear sessions — no client threads are running
    {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_.clear();
    }
}

// ─── Listener loop ────────────────────────────────────────────────────────

void McpHttpSseTransport::listener_loop() {
    while (running_.load()) {
        int sfd = server_fd_;  // snapshot — may become -1 during stop()
        if (sfd < 0) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sfd, &rfds);
        struct timeval tv{0, 200000};  // 200ms
        int ret = ::select(sfd + 1, &rfds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;
        if (!running_.load()) break;

        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(sfd,
                                 reinterpret_cast<struct sockaddr*>(&client_addr),
                                 &client_len);
        if (client_fd < 0) continue;

        // Set a receive timeout on client fd so handler threads don't block forever
        struct timeval recv_tv{5, 0};  // 5 second timeout
        ::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));

        // Spawn a per-client thread
        std::lock_guard<std::mutex> lk(clients_mutex_);
        client_threads_.emplace_back([this, client_fd] {
            handle_client(client_fd);
            ::close(client_fd);
        });

        // Reap finished threads periodically
        client_threads_.erase(
            std::remove_if(client_threads_.begin(), client_threads_.end(),
                           [](std::thread& t) {
                               if (!t.joinable()) return true;
                               return false;
                           }),
            client_threads_.end());
    }
}

// ─── Per-client handler ───────────────────────────────────────────────────

// Parse query string into key→value map
static std::unordered_map<std::string, std::string> parse_query(const std::string& qs) {
    std::unordered_map<std::string, std::string> out;
    std::istringstream ss(qs);
    std::string token;
    while (std::getline(ss, token, '&')) {
        size_t eq = token.find('=');
        if (eq != std::string::npos) {
            out[token.substr(0, eq)] = token.substr(eq + 1);
        }
    }
    return out;
}

void McpHttpSseTransport::handle_client(int client_fd) {
    auto req = parse_http_request(client_fd);
    if (!req.valid) return;

    // CORS preflight
    if (req.method == "OPTIONS") {
        send_http_response(client_fd, 204, "text/plain", "");
        return;
    }

    // Auth check
    if (!check_auth(req)) {
        send_http_response(client_fd, 401, "application/json",
                           R"({"error":"Unauthorized"})",
                           "WWW-Authenticate: Basic realm=\"tenet-mcp\"");
        return;
    }

    // Health probe
    if (req.path == "/health") {
        send_http_response(client_fd, 200, "application/json",
                           R"({"status":"ok"})");
        return;
    }

    // ── GET /sse — establish SSE stream ───────────────────────────────
    if (req.path == "/sse" && req.method == "GET") {
        auto session = create_session(client_fd);
        mcp_sse_log(fmt::format("SSE client connected, session={}", session->id));

        // Send SSE headers
        send_sse_headers(client_fd);

        // Send endpoint event so client knows where to POST
        std::string endpoint_url = fmt::format("/messages?sid={}", session->id);
        std::string endpoint_evt = fmt::format(
            "event: endpoint\ndata: {}\n\n", endpoint_url);
        session->send_raw(endpoint_evt);

        // Keep-alive: send periodic comments until session dies.
        // Use short sleeps so stop() can join this thread quickly.
        {
            int ping_counter = 0;
            while (running_.load() && session->alive.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!running_.load() || !session->alive.load()) break;
                if (++ping_counter >= 150) {  // ~15 seconds
                    session->send_raw(": ping\n\n");
                    ping_counter = 0;
                }
            }
        }

        remove_session(session->id);
        mcp_sse_log(fmt::format("SSE client disconnected, session={}", session->id));
        return;
    }

    // ── POST /messages — receive JSON-RPC request ──────────────────────
    if (req.path == "/messages" && req.method == "POST") {
        auto qp = parse_query(req.query);
        std::string sid = qp.count("sid") ? qp["sid"] : "";

        // Immediately ACK the POST with 202
        send_http_response(client_fd, 202, "application/json",
                           R"({"accepted":true})");

        // Find the SSE session for this request
        auto session = get_session(sid);
        if (!session) {
            mcp_sse_log(fmt::format("POST /messages: unknown sid={}", sid));
            return;
        }

        // Parse and dispatch the JSON-RPC message
        if (req.body.empty()) return;

        json response;
        try {
            json msg = json::parse(req.body);

            // Serialize tool handler calls
            std::lock_guard<std::mutex> dispatch_lk(dispatch_mutex_);
            response = handler_(msg);
        } catch (const json::parse_error& e) {
            response = {
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32700},
                           {"message", std::string("Parse error: ") + e.what()}}}
            };
        } catch (const std::exception& e) {
            response = {
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32603},
                           {"message", std::string("Internal error: ") + e.what()}}}
            };
        }

        // Notifications → null response, don't send
        if (response.is_null()) return;

        // Send response back over the SSE stream
        session->send_event(response);
        return;
    }

    // Unknown path
    send_http_response(client_fd, 404, "application/json",
                       R"({"error":"Not Found"})");
}

}  // namespace tenet

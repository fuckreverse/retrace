#include "mcp_http.h"

#include <fmt/core.h>

#include <sys/socket.h>
#include <poll.h>
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

static void mcp_http_log(const std::string& msg) {
    try {
        fmt::print(stderr, "[tenet-mcp-http] {}\n", msg);
    } catch (...) {
        // stderr may be closed (e.g. parent process / pipe gone) — ignore.
    }
}

// ─── UUID ─────────────────────────────────────────────────────────────────

std::string McpHttpTransport::generate_uuid() {
    static std::mt19937_64 rng{
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count())
    };
    uint64_t hi = rng();
    uint64_t lo = rng();
    return fmt::format("{:016x}{:016x}", hi, lo);
}

// ─── Base64 ───────────────────────────────────────────────────────────────

std::string McpHttpTransport::base64_encode(const std::string& s) {
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

McpHttpTransport::HttpRequest McpHttpTransport::parse_http_request(int fd) {
    HttpRequest req;

    // Read headers (up to 16KB)
    std::string raw;
    raw.reserve(4096);
    char buf[1024];
    while (true) {
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

void McpHttpTransport::send_http_response(int fd, int status,
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
                       : (status == 409) ? "Conflict"
                       : "Internal Server Error";

    std::string resp = fmt::format(
        "HTTP/1.1 {} {}\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version\r\n"
        "Access-Control-Expose-Headers: Mcp-Session-Id\r\n"
        "Connection: close\r\n"
        "{}"
        "\r\n"
        "{}",
        status, reason, content_type, body.size(),
        extra_headers.empty() ? "" : extra_headers + "\r\n",
        body);
    ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
}

// ─── Auth ─────────────────────────────────────────────────────────────────

bool McpHttpTransport::check_auth(const HttpRequest& req) const {
    if (!auth_enabled_) return true;
    auto it = req.headers.find("authorization");
    if (it == req.headers.end()) return false;
    const std::string& val = it->second;
    // "Basic <b64>"
    if (val.size() < 7 || val.substr(0, 6) != "Basic ") return false;
    return val.substr(6) == auth_b64_expected_;
}

// ─── Session management ───────────────────────────────────────────────────
//
// Streamable HTTP: server assigns Mcp-Session-Id in the initialize response.
// Subsequent requests must carry this header.  Invalid/missing → 400.
// Only one session is active at a time (tenet serves a single trace).

bool McpHttpTransport::check_session(const HttpRequest& req, int client_fd) {
    std::lock_guard<std::mutex> lk(session_mutex_);
    if (session_id_.empty()) {
        // No active session (either fresh start or after DELETE).
        // Allow the request through — handle_client will check if the method
        // is "initialize" and reject non-initialize calls gracefully.
        return true;
    }
    auto it = req.headers.find("mcp-session-id");
    if (it == req.headers.end()) {
        // Client forgot the session header.  Give a helpful error rather than
        // a silent 400: mention that initialize can be used to get a new one.
        send_http_response(client_fd, 400, "application/json",
                           R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Missing Mcp-Session-Id header. Send initialize to obtain a session ID."}})");
        return false;
    }
    if (it->second != session_id_) {
        // Stale session from a previous connection.  Let the client re-initialize.
        send_http_response(client_fd, 400, "application/json",
                           R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid or expired Mcp-Session-Id. Send initialize to start a new session."}})");
        return false;
    }
    return true;
}

// ─── Constructor / Destructor ─────────────────────────────────────────────

McpHttpTransport::McpHttpTransport(MessageHandler handler,
                                    const std::string& host,
                                    uint16_t port)
    : handler_(std::move(handler)), host_(host), port_(port) {}

McpHttpTransport::~McpHttpTransport() {
    stop();
}

void McpHttpTransport::set_auth(const std::string& username,
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

bool McpHttpTransport::start() {
    server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        mcp_http_log(fmt::format("socket() failed: {}", strerror(errno)));
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
        mcp_http_log(fmt::format("bind() failed: {}", strerror(errno)));
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    if (::listen(server_fd_, 128) < 0) {
        mcp_http_log(fmt::format("listen() failed: {}", strerror(errno)));
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    // Read back the actual port (important when port_==0, i.e. OS-assigned)
    struct sockaddr_in bound_addr{};
    socklen_t bound_len = sizeof(bound_addr);
    if (::getsockname(server_fd_, reinterpret_cast<struct sockaddr*>(&bound_addr), &bound_len) == 0) {
        listening_port_ = ntohs(bound_addr.sin_port);
    } else {
        listening_port_ = port_;  // fallback
    }

    // Non-blocking for poll-based accept loop
    int flags = ::fcntl(server_fd_, F_GETFL, 0);
    ::fcntl(server_fd_, F_SETFL, flags | O_NONBLOCK);

    running_.store(true);
    listener_thread_ = std::thread([this] { listener_loop(); });
    mcp_http_log(fmt::format("Streamable HTTP server listening on {}:{}", host_, listening_port_));
    return true;
}

void McpHttpTransport::stop() {
    if (!running_.exchange(false)) return;

    // Shutdown server socket to unblock poll()/accept() in listener thread.
    int sfd = server_fd_;
    if (sfd >= 0) {
        ::shutdown(sfd, SHUT_RDWR);
    }

    // Wait for listener thread to exit
    if (listener_thread_.joinable()) listener_thread_.join();

    // Now close the server socket
    if (sfd >= 0) {
        ::close(sfd);
        server_fd_ = -1;
    }

    // Join all client threads
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

    // Clear session
    {
        std::lock_guard<std::mutex> lk(session_mutex_);
        session_id_.clear();
    }
}

// ─── Listener loop ────────────────────────────────────────────────────────

void McpHttpTransport::listener_loop() {
    while (running_.load()) {
        int sfd = server_fd_;
        if (sfd < 0) break;

        struct pollfd pfd{sfd, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 200);  // 200ms timeout
        if (ret <= 0) continue;
        if (!running_.load()) break;

        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(sfd,
                                 reinterpret_cast<struct sockaddr*>(&client_addr),
                                 &client_len);
        if (client_fd < 0) continue;

        // Receive timeout: give the client up to 10 seconds to send the full
        // HTTP request headers+body.  We do NOT set a send timeout here because
        // tool handlers (taint, algorithm_summary, etc.) may legitimately block
        // for tens of seconds before the response is ready — a send timeout
        // would disconnect the client mid-computation.
        struct timeval recv_tv{10, 0};
        ::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));
        // TCP keepalive: keeps the connection alive when the server is computing
        // a long-running pass (the connection goes idle from the network's view).
        int ka = 1;
        ::setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));

        // Spawn a per-client thread
        std::lock_guard<std::mutex> lk(clients_mutex_);
        client_threads_.emplace_back([this, client_fd] {
            handle_client(client_fd);
            ::close(client_fd);
        });

        // Reap finished threads periodically (joinable but already exited)
        // NOTE: We can't detect if a thread has finished without join, so
        // we just keep them and clean up in stop(). This is fine since each
        // HTTP request is short-lived in Streamable HTTP (no SSE keep-alive).
    }
}

// ─── Per-client handler ───────────────────────────────────────────────────
//
// Streamable HTTP transport:
//   POST /mcp   — JSON-RPC request → synchronous JSON response
//   GET  /mcp   — not supported (server-push SSE; tenet doesn't initiate)
//   DELETE /mcp — terminate session
//   GET /health — liveness probe

void McpHttpTransport::handle_client(int client_fd) {
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

    // ── POST /mcp — JSON-RPC request ──────────────────────────────────
    if (req.path == "/mcp" && req.method == "POST") {
        if (req.body.empty()) {
            send_http_response(client_fd, 400, "application/json",
                               R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Empty request body"}})");
            return;
        }

        json msg;
        try {
            msg = json::parse(req.body);
        } catch (const json::parse_error& e) {
            json err_resp = {
                {"jsonrpc", "2.0"},
                {"id", nullptr},
                {"error", {{"code", -32700},
                           {"message", std::string("Parse error: ") + e.what()}}}
            };
            send_http_response(client_fd, 200, "application/json", err_resp.dump());
            return;
        }

        std::string method = msg.value("method", "");

        // ── Initialize: special handling — assign session ──────────────
        if (method == "initialize") {
            // Dispatch to handler (initialize is inherently single-shot)
            json response = handler_(msg);

            std::string session_hdr;
            if (require_session_) {
                // Assign a new session ID
                std::string new_session_id = generate_uuid();
                {
                    std::lock_guard<std::mutex> lk(session_mutex_);
                    session_id_ = new_session_id;
                    session_ever_created_ = true;
                }
                mcp_http_log(fmt::format("Session created: {}", new_session_id));
                session_hdr = fmt::format("Mcp-Session-Id: {}", new_session_id);
            }

            send_http_response(client_fd, 200, "application/json",
                               response.dump(), session_hdr);
            return;
        }

        // ── All other requests: require valid session (if enabled) ─────
        if (require_session_) {
            if (!check_session(req, client_fd)) return;

            // If there is still no active session after check_session (e.g. after
            // a DELETE terminated the session and no initialize was sent), return a
            // helpful error that guides the client to re-initialize.
            {
                std::lock_guard<std::mutex> lk(session_mutex_);
                if (session_id_.empty()) {
                    auto msg_id = msg.contains("id") ? msg["id"] : json(nullptr);
                    json err_resp = {
                        {"jsonrpc", "2.0"},
                        {"id", msg_id},
                        {"error", {{"code", -32600},
                                   {"message", "No active session. Send initialize to start a new session."}}}
                    };
                    send_http_response(client_fd, 400, "application/json", err_resp.dump());
                    return;
                }
            }
        }

        // Dispatch to handler — concurrency managed by TenetMcpService
        // (read tools run in parallel, write tools acquire exclusive lock).
        json response;
        try {
            response = handler_(msg);
        } catch (const std::exception& e) {
            response = {
                {"jsonrpc", "2.0"},
                {"id", msg.value("id", json(nullptr))},
                {"error", {{"code", -32603},
                           {"message", std::string("Internal error: ") + e.what()}}}
            };
        }

        // Notifications → null response
        if (response.is_null()) {
            send_http_response(client_fd, 202, "application/json",
                               R"({"accepted":true})");
            return;
        }

        // Return Mcp-Session-Id in all responses (only when session is enabled)
        std::string session_hdr;
        if (require_session_) {
            std::lock_guard<std::mutex> lk(session_mutex_);
            if (!session_id_.empty()) {
                session_hdr = fmt::format("Mcp-Session-Id: {}", session_id_);
            }
        }
        send_http_response(client_fd, 200, "application/json",
                           response.dump(), session_hdr);
        return;
    }

    // ── DELETE /mcp — terminate session ───────────────────────────────
    if (req.path == "/mcp" && req.method == "DELETE") {
        if (require_session_) {
            if (!check_session(req, client_fd)) return;

            {
                std::lock_guard<std::mutex> lk(session_mutex_);
                mcp_http_log(fmt::format("Session terminated: {}", session_id_));
                session_id_.clear();
            }

            send_http_response(client_fd, 200, "application/json",
                               R"({"status":"session_terminated"})");
        } else {
            // Session management disabled — DELETE is a no-op
            send_http_response(client_fd, 200, "application/json",
                               R"({"status":"ok","message":"Session management disabled"})");
        }
        return;
    }

    // ── GET /mcp — server-initiated SSE stream ────────────────────────
    // MCP spec allows GET for server-push notifications.
    // tenet doesn't initiate messages (all tool calls are request→response),
    // so we return 405.  Clients can still use POST for all interactions.
    if (req.path == "/mcp" && req.method == "GET") {
        send_http_response(client_fd, 405, "application/json",
                           R"({"error":"Server-initiated SSE not supported. Use POST /mcp for all interactions."})");
        return;
    }

    // ── Legacy SSE endpoints — helpful error for clients using old protocol
    if (req.path == "/sse" || req.path == "/messages") {
        send_http_response(client_fd, 404, "application/json",
                           R"({"error":"Legacy SSE transport removed. Use POST /mcp (Streamable HTTP, MCP 2025-03-26+)."})");
        return;
    }

    // Unknown path
    send_http_response(client_fd, 404, "application/json",
                       R"({"error":"Not Found"})");
}

}  // namespace tenet

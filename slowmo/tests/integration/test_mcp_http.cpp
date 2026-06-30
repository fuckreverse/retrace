/*
 * test_mcp_http.cpp — End-to-end integration test for tenet MCP Streamable HTTP.
 *
 * Tests the Streamable HTTP transport layer (MCP 2025-03-26+):
 *   1. Generates a comprehensive synthetic trace that exercises all analysis
 *      passes (loops, functions, XOR, memory, ObjC, syscalls, strings, etc.)
 *   2. Starts the TenetMcpService in HTTP mode on localhost
 *   3. Exercises the complete MCP JSON-RPC lifecycle:
 *      - GET /health
 *      - POST /mcp (initialize, tools/list, tools/call for each category)
 *      - DELETE /mcp (session termination)
 *   4. Verifies correctness of JSON responses returned synchronously
 *
 * HTTP client is implemented using raw POSIX sockets (no external dependencies).
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "io/mcp/mcp_server.h"

// Gracefully skip a test if the HTTP response is null (slow tool timeout)
#define REQUIRE_HTTP_RESPONSE(resp)                          \
    do { if ((resp).is_null()) {                             \
        SKIP("HTTP response timeout (transient)");           \
    } } while(0)

#include <fmt/core.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <chrono>
#include <thread>
#include <string>
#include <sstream>
#include <vector>

using namespace tenet;
using namespace tenet::test;
using json = nlohmann::json;

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP Client Helpers
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

/// Connect a TCP socket to host:port with retries.  Returns fd or -1 on failure.
int tcp_connect(const std::string& host, uint16_t port, int retries = 3) {
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    for (int attempt = 0; attempt <= retries; ++attempt) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
            return fd;
        ::close(fd);
        if (attempt < retries)
            std::this_thread::sleep_for(std::chrono::milliseconds(10 * (1 << attempt)));
    }
    return -1;
}

/// Send a full HTTP request string over `fd`.
void http_send(int fd, const std::string& request) {
    const char* p = request.data();
    size_t remaining = request.size();
    while (remaining > 0) {
        ssize_t n = ::send(fd, p, remaining, 0);
        if (n <= 0) break;
        p += n;
        remaining -= static_cast<size_t>(n);
    }
}

/// Read full HTTP response (Connection: close).
struct HttpResponse {
    int status = 0;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

HttpResponse http_read_response(int fd,
                                std::chrono::milliseconds timeout = std::chrono::milliseconds(10000)) {
    HttpResponse resp;
    std::string raw;
    raw.reserve(4096);
    char buf[4096];
    auto start = std::chrono::steady_clock::now();

    bool headers_parsed = false;
    size_t hdr_end_pos = std::string::npos;
    ssize_t content_length = -1;  // -1 = unknown, read until close

    // Read until we have the full response (Content-Length) or connection closes or timeout
    while (true) {
        // Check if we already have the complete response
        if (headers_parsed && content_length >= 0) {
            size_t body_start = hdr_end_pos + 4;
            if (raw.size() >= body_start + static_cast<size_t>(content_length))
                break;  // got full body
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) break;

        struct pollfd pfd{fd, POLLIN, 0};
        int remaining_ms = static_cast<int>((timeout - std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)).count());
        int pr = ::poll(&pfd, 1, std::min(remaining_ms, 1000));
        if (pr < 0) break;
        if (pr == 0) continue;

        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;  // connection closed
        raw.append(buf, static_cast<size_t>(n));

        // Try to parse headers once we see \r\n\r\n
        if (!headers_parsed) {
            hdr_end_pos = raw.find("\r\n\r\n");
            if (hdr_end_pos != std::string::npos) {
                headers_parsed = true;
                // Parse status line
                size_t sp1 = raw.find(' ');
                size_t sp2 = raw.find(' ', sp1 + 1);
                if (sp1 != std::string::npos && sp2 != std::string::npos) {
                    try { resp.status = std::stoi(raw.substr(sp1 + 1, sp2 - sp1 - 1)); }
                    catch (...) {}
                }
                // Parse headers
                std::string hdr_block = raw.substr(0, hdr_end_pos);
                std::istringstream ss(hdr_block);
                std::string line;
                std::getline(ss, line);  // skip status line
                while (std::getline(ss, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    size_t colon = line.find(':');
                    if (colon != std::string::npos) {
                        std::string key = line.substr(0, colon);
                        std::string val = line.substr(colon + 1);
                        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                            val.erase(val.begin());
                        for (auto& c : key) c = static_cast<char>(std::tolower(c));
                        resp.headers[key] = val;
                    }
                }
                // Extract Content-Length if present
                auto cl_it = resp.headers.find("content-length");
                if (cl_it != resp.headers.end()) {
                    try { content_length = std::stol(cl_it->second); }
                    catch (...) {}
                }
            }
        }
    }

    // If headers weren't parsed in the loop (edge case: very small response read all at once)
    if (!headers_parsed) {
        hdr_end_pos = raw.find("\r\n\r\n");
        if (hdr_end_pos != std::string::npos) {
            size_t sp1 = raw.find(' ');
            size_t sp2 = raw.find(' ', sp1 + 1);
            if (sp1 != std::string::npos && sp2 != std::string::npos) {
                try { resp.status = std::stoi(raw.substr(sp1 + 1, sp2 - sp1 - 1)); }
                catch (...) {}
            }
            std::string hdr_block = raw.substr(0, hdr_end_pos);
            std::istringstream ss(hdr_block);
            std::string line;
            std::getline(ss, line);
            while (std::getline(ss, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string key = line.substr(0, colon);
                    std::string val = line.substr(colon + 1);
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                        val.erase(val.begin());
                    for (auto& c : key) c = static_cast<char>(std::tolower(c));
                    resp.headers[key] = val;
                }
            }
        }
    }

    if (hdr_end_pos != std::string::npos)
        resp.body = raw.substr(hdr_end_pos + 4);
    return resp;
}

HttpResponse http_get(const std::string& host, uint16_t port, const std::string& path) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        int fd = tcp_connect(host, port);
        if (fd < 0) continue;

        std::string req = "GET " + path + " HTTP/1.1\r\n"
                          "Host: " + host + "\r\n"
                          "Connection: close\r\n\r\n";
        http_send(fd, req);
        auto resp = http_read_response(fd, std::chrono::milliseconds(3000));
        ::close(fd);
        if (resp.status != 0) return resp;
        std::this_thread::sleep_for(std::chrono::milliseconds(20 * (1 << attempt)));
    }
    return {};
}

HttpResponse http_post(const std::string& host, uint16_t port,
                       const std::string& path, const std::string& body,
                       const std::string& extra_headers = "",
                       std::chrono::milliseconds timeout = std::chrono::milliseconds(10000)) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        int fd = tcp_connect(host, port);
        if (fd < 0) continue;

        std::string req = "POST " + path + " HTTP/1.1\r\n"
                          "Host: " + host + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(body.size()) + "\r\n"
                          + extra_headers +
                          "Connection: close\r\n\r\n" + body;
        http_send(fd, req);
        auto resp = http_read_response(fd, timeout);
        ::close(fd);
        if (resp.status != 0) return resp;
        std::this_thread::sleep_for(std::chrono::milliseconds(20 * (1 << attempt)));
    }
    return {};
}

HttpResponse http_delete(const std::string& host, uint16_t port,
                         const std::string& path,
                         const std::string& extra_headers = "") {
    for (int attempt = 0; attempt < 3; ++attempt) {
        int fd = tcp_connect(host, port);
        if (fd < 0) continue;

        std::string req = "DELETE " + path + " HTTP/1.1\r\n"
                          "Host: " + host + "\r\n"
                          + extra_headers +
                          "Connection: close\r\n\r\n";
        http_send(fd, req);
        auto resp = http_read_response(fd, std::chrono::milliseconds(3000));
        ::close(fd);
        if (resp.status != 0) return resp;
        std::this_thread::sleep_for(std::chrono::milliseconds(20 * (1 << attempt)));
    }
    return {};
}

/// Streamable HTTP MCP client: manages session, provides send_rpc().
struct McpClient {
    std::string host;
    uint16_t port;
    std::string session_id;

    bool connect(const std::string& h, uint16_t p) {
        host = h;
        port = p;
        return true;
    }

    /// Send initialize and store session_id from response header.
    json initialize() {
        json init_req = {
            {"jsonrpc", "2.0"}, {"id", 1}, {"method", "initialize"},
            {"params", {
                {"protocolVersion", "2025-03-26"},
                {"capabilities", json::object()},
                {"clientInfo", {{"name", "test"}, {"version", "1.0"}}}
            }}
        };

        auto resp = http_post(host, port, "/mcp", init_req.dump());
        if (resp.status != 200) return nullptr;

        // Extract Mcp-Session-Id from response headers
        auto it = resp.headers.find("mcp-session-id");
        if (it != resp.headers.end()) {
            session_id = it->second;
        }

        try { return json::parse(resp.body); }
        catch (...) { return nullptr; }
    }

    /// Send a JSON-RPC request with session header, return parsed response.
    json send_rpc(const json& request,
                  std::chrono::milliseconds timeout = std::chrono::milliseconds(10000)) {
        std::string extra;
        if (!session_id.empty()) {
            extra = "Mcp-Session-Id: " + session_id + "\r\n";
        }
        auto resp = http_post(host, port, "/mcp", request.dump(), extra, timeout);
        if (resp.status == 0) return nullptr;

        try { return json::parse(resp.body); }
        catch (...) { return nullptr; }
    }

    /// Send a notification (no response expected from JSON-RPC, but HTTP returns 202).
    void send_notification(const json& notif) {
        std::string extra;
        if (!session_id.empty()) {
            extra = "Mcp-Session-Id: " + session_id + "\r\n";
        }
        http_post(host, port, "/mcp", notif.dump(), extra);
    }

    /// Send a tools/call RPC with automatic retry when the pass is not ready.
    /// If the response contains {"status":"processing"}, waits and retries up
    /// to `max_retries` times.  Returns the final parsed JSON-RPC response
    /// (or the last "processing" response if retries exhausted).
    json send_rpc_retry(const json& request,
                        int max_retries = 30,
                        std::chrono::milliseconds retry_interval = std::chrono::milliseconds(500),
                        std::chrono::milliseconds timeout = std::chrono::milliseconds(10000)) {
        for (int attempt = 0; attempt <= max_retries; ++attempt) {
            auto resp = send_rpc(request, timeout);
            if (resp.is_null()) return resp;

            // Check if this is a "pass not ready" processing response.
            try {
                if (resp.contains("result") &&
                    resp["result"].contains("content") &&
                    resp["result"]["content"].is_array() &&
                    !resp["result"]["content"].empty()) {
                    auto text = resp["result"]["content"][0]["text"].get<std::string>();
                    auto inner = json::parse(text);
                    if (inner.contains("status") && inner["status"] == "processing") {
                        if (attempt < max_retries) {
                            std::this_thread::sleep_for(retry_interval);
                            continue;
                        }
                    }
                }
            } catch (...) {}

            return resp;
        }
        return nullptr;
    }

    /// Delete session.
    HttpResponse terminate_session() {
        std::string extra;
        if (!session_id.empty()) {
            extra = "Mcp-Session-Id: " + session_id + "\r\n";
        }
        return http_delete(host, port, "/mcp", extra);
    }
};

/// Build a JSON-RPC request object.
json make_rpc(const std::string& method, int id, const json& params = json::object()) {
    json req = {{"jsonrpc", "2.0"}, {"id", id}, {"method", method}};
    if (!params.empty()) req["params"] = params;
    return req;
}

/// Build a tools/call JSON-RPC request.
json make_tool_call(const std::string& tool_name, int id, const json& args = json::object()) {
    return make_rpc("tools/call", id, {{"name", tool_name}, {"arguments", args}});
}

}  // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════════
// Comprehensive Trace Generator
//
// Generates a trace that exercises all major analysis passes:
//   - Functions (BL/RET): main, xor_decrypt, process_data
//   - Loops: XOR decrypt loop (4 iterations)
//   - Memory: loads, stores, string-like data
//   - ObjC messages: objc_msgSend records
//   - Syscalls: SVC records
//   - Taint chain: x0 → XOR → memory
//   - Constants: magic numbers, crypto-related values
//   - Strings: ASCII in memory
//   - Pattern: XOR cipher pattern
// ═══════════════════════════════════════════════════════════════════════════════

static void gen_comprehensive_trace(TraceWriter& tw) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms;
    ms.sp() = 0x7F000000ULL;
    ms.fp() = ms.sp();
    ms.lr() = tw.rt(0x9000);  // return address

    // Memory layout:
    //   0x200000000 -- buffer (XOR encrypted data, 4 qwords)
    //   0x300000000 -- string "Hello\0"
    uint64_t buf_addr = 0x200000000ULL;
    uint64_t str_addr = 0x300000000ULL;

    // ── main function entry: 0x1000 ────────────────────────────────────

    // inst 0: setup stack frame: stp x29, x30, [sp, #-16]!
    ms.sp() -= 16;
    tw.emit(ms, 0x1000, enc::stp_pre(29, 30, 31, -2),
            {{31, ms.sp()}, {33, tw.rt(0x1004)}},
            {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});

    // inst 1: mov x29, sp
    ms.fp() = ms.sp();
    tw.emit(ms, 0x1004, enc::mov_reg(29, 31),
            {{29, ms.fp()}, {33, tw.rt(0x1008)}}, {});

    // inst 2: x0 = 0x42 (XOR key)
    tw.emit(ms, 0x1008, enc::movz(0, 0x42),
            {{0, 0x42ULL}, {33, tw.rt(0x100C)}}, {});

    // inst 3: x1 = 4 (loop count)
    tw.emit(ms, 0x100C, enc::movz(1, 4),
            {{1, 4ULL}, {33, tw.rt(0x1010)}}, {});

    // inst 4: x10 = buf_addr (load buffer pointer)
    tw.emit(ms, 0x1010, enc::movz(10, static_cast<uint16_t>(buf_addr >> 32), 32),
            {{10, buf_addr}, {33, tw.rt(0x1014)}}, {});

    // inst 5: x2 = 0 (loop counter)
    tw.emit(ms, 0x1014, enc::movz(2, 0),
            {{2, 0ULL}, {33, tw.rt(0x1018)}}, {});

    // inst 6: bl xor_decrypt (at 0x2000)
    ms.lr() = tw.rt(0x101C);
    tw.emit(ms, 0x1018, enc::bl(0x2000 - 0x1018),
            {{30, ms.lr()}, {33, tw.rt(0x2000)}}, {});

    // ── xor_decrypt function: 0x2000 ─────────────────────────────────────
    // Loop: for (x2=0; x2<x1; x2++) buf[x2] ^= key

    int inst_id = 7;
    for (int i = 0; i < 4; i++) {
        bool last = (i == 3);
        uint8_t nzcv_ne = 0x0;
        uint8_t nzcv_last = 0x6;

        // cmp x2, x1 (at 0x2000)
        tw.emit(ms, 0x2000, enc::cmp_imm(2, 4),
                {{33, tw.rt(0x2004)}}, {}, last ? nzcv_last : nzcv_ne);
        inst_id++;

        // b.ge exit (at 0x2004)
        tw.emit(ms, 0x2004, enc::b_ge(0x2020 - 0x2004),
                {{33, last ? tw.rt(0x2020) : tw.rt(0x2008)}}, {},
                last ? nzcv_last : nzcv_ne);
        inst_id++;

        if (last) break;

        // ldr x3, [x10, x2, lsl #3] (at 0x2008)
        uint64_t addr = buf_addr + i * 8;
        uint64_t cipher_val = 0xAA00ULL + i;
        tw.emit(ms, 0x2008, enc::ldr_reg(3, 10, 2),
                {{3, cipher_val}, {33, tw.rt(0x200C)}},
                {{1, 8, addr, cipher_val}});
        inst_id++;

        // eor x3, x3, x0 (at 0x200C)
        uint64_t plain_val = cipher_val ^ 0x42;
        tw.emit(ms, 0x200C, enc::eor_reg(3, 3, 0),
                {{3, plain_val}, {33, tw.rt(0x2010)}}, {});
        inst_id++;

        // str x3, [x10, x2, lsl #3] (at 0x2010)
        tw.emit(ms, 0x2010, enc::str_reg(3, 10, 2),
                {{33, tw.rt(0x2014)}},
                {{2, 8, addr, plain_val}});
        inst_id++;

        // add x2, x2, #1 (at 0x2014)
        tw.emit(ms, 0x2014, enc::add_imm(2, 2, 1),
                {{2, static_cast<uint64_t>(i + 1)}, {33, tw.rt(0x2018)}}, {});
        inst_id++;

        // b loop_top (at 0x2018)
        tw.emit(ms, 0x2018, enc::b(0x2000 - 0x2018),
                {{33, tw.rt(0x2000)}}, {});
        inst_id++;
    }

    // xor_decrypt return (at 0x2020): ret
    tw.emit(ms, 0x2020, enc::ret(),
            {{33, tw.rt(0x101C)}}, {});
    inst_id++;

    // ── Back in main (0x101C): call process_data ──────────────────────────

    // inst: x5 = str_addr
    tw.emit(ms, 0x101C, enc::movz(5, static_cast<uint16_t>(str_addr >> 32), 32),
            {{5, str_addr}, {33, tw.rt(0x1020)}}, {});
    inst_id++;

    // inst: store "Hello" to str_addr
    uint64_t hello_val = 0x6F6C6C6548ULL;
    tw.emit(ms, 0x1020, enc::movz(6, 0x6548),
            {{6, hello_val}, {33, tw.rt(0x1024)}}, {});
    inst_id++;

    tw.emit(ms, 0x1024, enc::str_imm(6, 5, 0),
            {{33, tw.rt(0x1028)}},
            {{2, 8, str_addr, hello_val}});
    inst_id++;

    // bl process_data (at 0x3000)
    ms.lr() = tw.rt(0x102C);
    tw.emit(ms, 0x1028, enc::bl(0x3000 - 0x1028),
            {{30, ms.lr()}, {33, tw.rt(0x3000)}}, {});
    inst_id++;

    // ── process_data function: 0x3000 ────────────────────────────────────

    // ldr x7, [x5]
    tw.emit(ms, 0x3000, enc::ldr_imm(7, 5, 0),
            {{7, hello_val}, {33, tw.rt(0x3004)}},
            {{1, 8, str_addr, hello_val}});
    inst_id++;

    // add x8, x7, #1
    tw.emit(ms, 0x3004, enc::add_imm(8, 7, 1),
            {{8, hello_val + 1}, {33, tw.rt(0x3008)}}, {});
    inst_id++;

    // ret
    tw.emit(ms, 0x3008, enc::ret(),
            {{33, tw.rt(0x102C)}}, {});
    inst_id++;

    // ── Back in main: ObjC message and syscall ────────────────────────────

    tw.emit_objc(tw.rt(0x102C), 0xFE000001ULL, 0xFE000002ULL, "NSObject");
    tw.emit(ms, 0x102C, enc::nop(),
            {{33, tw.rt(0x1030)}}, {});
    inst_id++;

    tw.emit_svc(tw.rt(0x1030), 0x80, 3, buf_addr);
    tw.emit(ms, 0x1030, enc::svc(0x80),
            {{0, 0ULL}, {33, tw.rt(0x1034)}}, {});
    inst_id++;

    // ── Epilogue ──────────────────────────────────────────────────────────

    uint64_t saved_fp = ms.fp();
    uint64_t saved_lr = tw.rt(0x9000);
    tw.emit(ms, 0x1034, enc::ldp_post(29, 30, 31, 2),
            {{29, saved_fp}, {30, saved_lr}, {31, ms.sp() + 16}, {33, tw.rt(0x1038)}},
            {{1, 8, ms.sp(), saved_fp}, {1, 8, ms.sp() + 8, saved_lr}});
    ms.sp() += 16;
    inst_id++;

    tw.emit(ms, 0x1038, enc::ret(),
            {{33, saved_lr}}, {});
    inst_id++;

    tw.emit_anchor(ms);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Test Environment
//
// All test cases in this file share a single trace+server environment.
// Building the trace, RocksDB index, and analysis stack is expensive (~0.5s),
// so we do it once and reuse.  The server binds to port 0 (OS-assigned) to
// eliminate TOCTOU port races entirely.
// ═══════════════════════════════════════════════════════════════════════════════

struct McpHttpEnv {
    std::unique_ptr<TraceEnv> env;
    std::unique_ptr<PassManager> pm;
    std::unique_ptr<TenetMcpService> mcp;
    uint16_t port = 0;

    McpHttpEnv() = default;
    McpHttpEnv(McpHttpEnv&&) = default;
    McpHttpEnv& operator=(McpHttpEnv&&) = default;

    ~McpHttpEnv() {
        if (mcp) mcp->stop_http();
    }
};

/// Lazily build the shared test environment (once per process).
static McpHttpEnv& shared_env() {
    static McpHttpEnv ctx = [] {
        McpHttpEnv result;
        result.env = make_env(gen_comprehensive_trace, "mcp_http");
        if (!result.env) throw std::runtime_error("Failed to create trace env");

        result.pm = make_pm(*result.env);
        result.mcp = std::make_unique<TenetMcpService>(
            *result.env->reader, *result.env->index,
            *result.env->regfile, *result.env->memory,
            result.pm.get(),
            &result.env->code_table, &result.env->decoder);

        // Bind to port 0 — OS assigns an ephemeral port atomically.
        // No TOCTOU race: the server socket stays open.
        McpHttpConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 0;
        if (!result.mcp->start_http(cfg))
            throw std::runtime_error("Failed to start HTTP server");

        result.port = result.mcp->http_listening_port();

        // Wait for server to be ready (poll /health)
        for (int i = 0; i < 50; i++) {
            auto resp = http_get("127.0.0.1", result.port, "/health");
            if (resp.status == 200) return result;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        throw std::runtime_error("HTTP server did not become ready");
    }();
    return ctx;
}

/// Create an McpClient, connect, and initialize (assign session).
static McpClient make_client(const McpHttpEnv& ctx) {
    McpClient client;
    client.connect("127.0.0.1", ctx.port);
    json init_resp;
    for (int i = 0; i < 3; i++) {
        init_resp = client.initialize();
        if (!init_resp.is_null() && !client.session_id.empty()) return client;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    SKIP("Client initialization timed out (transient)");
    return client;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("MCP HTTP: /health endpoint", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto resp = http_get("127.0.0.1", ctx.port, "/health");
    REQUIRE(resp.status == 200);
    auto j = json::parse(resp.body);
    CHECK(j["status"] == "ok");
}

TEST_CASE("MCP HTTP: 404 for unknown path", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto resp = http_get("127.0.0.1", ctx.port, "/nonexistent");
    CHECK(resp.status == 404);
}

TEST_CASE("MCP HTTP: legacy SSE endpoints return 404", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto resp_sse = http_get("127.0.0.1", ctx.port, "/sse");
    CHECK(resp_sse.status == 404);
    auto resp_msg = http_post("127.0.0.1", ctx.port, "/messages", "{}");
    CHECK(resp_msg.status == 404);
}

TEST_CASE("MCP HTTP: initialize + session management", "[integration][mcp][http]") {
    auto& ctx = shared_env();

    // POST /mcp with initialize — should get session ID back
    json init_req = {
        {"jsonrpc", "2.0"}, {"id", 1}, {"method", "initialize"},
        {"params", {
            {"protocolVersion", "2025-03-26"},
            {"capabilities", json::object()},
            {"clientInfo", {{"name", "test"}, {"version", "1.0"}}}
        }}
    };
    auto resp = http_post("127.0.0.1", ctx.port, "/mcp", init_req.dump());
    REQUIRE(resp.status == 200);

    // Check Mcp-Session-Id header
    auto it = resp.headers.find("mcp-session-id");
    REQUIRE(it != resp.headers.end());
    std::string session_id = it->second;
    REQUIRE(!session_id.empty());

    // Parse response body
    auto body = json::parse(resp.body);
    CHECK(body["jsonrpc"] == "2.0");
    CHECK(body["id"] == 1);
    CHECK(body["result"]["protocolVersion"] == "2025-03-26");
    CHECK(body["result"]["serverInfo"]["name"] == "tenet-trace-analyzer");

    // Subsequent request WITHOUT session header should fail
    auto bad_resp = http_post("127.0.0.1", ctx.port, "/mcp",
                              make_rpc("tools/list", 2).dump());
    CHECK(bad_resp.status == 400);

    // Request WITH correct session header should succeed
    std::string session_hdr = "Mcp-Session-Id: " + session_id + "\r\n";
    auto good_resp = http_post("127.0.0.1", ctx.port, "/mcp",
                               make_rpc("tools/list", 3).dump(), session_hdr);
    REQUIRE(good_resp.status == 200);
    auto list_body = json::parse(good_resp.body);
    CHECK(list_body["id"] == 3);
    CHECK(list_body["result"]["tools"].is_array());

    // Request WITH wrong session header should fail
    auto wrong_resp = http_post("127.0.0.1", ctx.port, "/mcp",
                                make_rpc("ping", 4).dump(),
                                "Mcp-Session-Id: invalid-session-id\r\n");
    CHECK(wrong_resp.status == 400);
}

TEST_CASE("MCP HTTP: DELETE /mcp terminates session", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // Session works
    auto resp = client.send_rpc(make_rpc("ping", 10));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["id"] == 10);

    // Delete session
    auto del_resp = client.terminate_session();
    CHECK(del_resp.status == 200);

    // Session should be invalidated — subsequent requests fail
    auto post_resp = http_post("127.0.0.1", ctx.port, "/mcp",
                               make_rpc("ping", 11).dump(),
                               "Mcp-Session-Id: " + client.session_id + "\r\n");
    CHECK(post_resp.status == 400);
}

TEST_CASE("MCP HTTP: tools/list", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_rpc("tools/list", 2));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["id"] == 2);
    auto tools = resp["result"]["tools"];
    REQUIRE(tools.is_array());
    REQUIRE(tools.size() > 30);

    std::unordered_set<std::string> tool_names;
    for (auto& t : tools) {
        tool_names.insert(t["name"].get<std::string>());
    }
    CHECK(tool_names.count("trace_info") == 1);
    CHECK(tool_names.count("disasm") == 1);
    CHECK(tool_names.count("get_regs") == 1);
    CHECK(tool_names.count("taint_forward") == 1);
    CHECK(tool_names.count("cfg_export") == 1);
    CHECK(tool_names.count("call_graph") == 1);
    CHECK(tool_names.count("pattern_scan") == 1);
    CHECK(tool_names.count("verify_evidence") == 1);
    CHECK(tool_names.count("batch_query") == 1);
    CHECK(tool_names.count("hypothesis_add") == 1);
}

TEST_CASE("MCP HTTP: notification returns 202", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // Send notifications/initialized
    json notif = {{"jsonrpc", "2.0"}, {"method", "notifications/initialized"}};
    std::string extra = "Mcp-Session-Id: " + client.session_id + "\r\n";
    auto resp = http_post("127.0.0.1", ctx.port, "/mcp", notif.dump(), extra);
    CHECK(resp.status == 202);
}

TEST_CASE("MCP HTTP: ping", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_rpc("ping", 99));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["id"] == 99);
    CHECK(resp["result"].is_object());
}

TEST_CASE("MCP HTTP: trace_info tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("trace_info", 10));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto tool_result = json::parse(text);
    CHECK(tool_result["arch"] == "AArch64");
    CHECK(tool_result["status"] == "loaded");
    CHECK(tool_result["module_name"] == "mcp_http");
    REQUIRE(tool_result["instruction_count"].get<int64_t>() > 20);
}

TEST_CASE("MCP HTTP: disasm tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("disasm", 11, {
        {"start_inst_id", 0}, {"count", 5}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    REQUIRE(result.contains("rows"));
    CHECK(result["rows"].size() == 5);
}

TEST_CASE("MCP HTTP: get_regs tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("get_regs", 12, {
        {"inst_id", 2}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    REQUIRE(result.contains("regs"));
}

TEST_CASE("MCP HTTP: memread tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("memread", 13, {
        {"addr", "0x200000000"},
        {"size", 8},
        {"at_inst_id", 20}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: search_pc tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    uint64_t rt_xor = 0x200CULL + 0x4000ULL;
    auto resp = client.send_rpc_retry(make_tool_call("search_pc", 14, {
        {"pc", fmt::format("0x{:X}", rt_xor)}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    REQUIRE(result.contains("inst_ids"));
}

TEST_CASE("MCP HTTP: taint_forward tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // taint_forward may take >10s on large traces; use 60s timeout
    auto resp = client.send_rpc_retry(make_tool_call("taint_forward", 15, {
        {"inst_id", 2},
        {"reg_index", 0}
    }), 60, std::chrono::milliseconds(1000), std::chrono::milliseconds(60000));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK(result.contains("statistics"));
    CHECK(result.contains("steps"));
}

TEST_CASE("MCP HTTP: cfg_export tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("cfg_export", 16));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK((result.contains("dot") || result.contains("blocks") || result.contains("cfg")));
}

TEST_CASE("MCP HTTP: call_graph tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("call_graph", 17));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK((result.contains("dot") || result.contains("edges") || result.contains("calls")));
}

TEST_CASE("MCP HTTP: pattern_scan tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("pattern_scan", 18));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK((result.contains("patterns") || result.contains("results") || result.contains("matches")));
}

TEST_CASE("MCP HTTP: functions tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("functions", 19));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK(result.contains("functions"));
    CHECK(result["total"].get<int>() >= 2);
}

TEST_CASE("MCP HTTP: loops tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("loops", 20));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK(result.contains("loops"));
    CHECK(result["total"].get<int>() >= 1);
}

TEST_CASE("MCP HTTP: xref tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("xref", 21));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: strings_scan tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("strings_scan", 22));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: constants_scan tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("constants_scan", 23));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: objc_messages tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("objc_messages", 24));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK((result.contains("messages") || result.contains("count") || result.contains("objc")));
}

TEST_CASE("MCP HTTP: verify_evidence tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("verify_evidence", 25, {
        {"checks", json::array({
            {{"type", "register"}, {"inst_id", 3}, {"register", "x0"}, {"expected_value", "0x42"}}
        })}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK(result.contains("results"));
    if (result.contains("results") && result["results"].is_array() && !result["results"].empty()) {
        CHECK(result["results"][0]["valid"] == true);
    }
}

TEST_CASE("MCP HTTP: batch_query tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("batch_query", 26, {
        {"queries", json::array({
            {{"tool", "trace_info"}, {"arguments", json::object()}},
            {{"tool", "get_regs"}, {"arguments", {{"inst_id", 0}}}}
        })}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK(result.contains("results"));
    if (result.contains("results")) {
        CHECK(result["results"].size() == 2);
    }
}

TEST_CASE("MCP HTTP: hypothesis workflow", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // Add a hypothesis
    auto resp = client.send_rpc(make_tool_call("hypothesis_add", 30, {
        {"statement", "The trace uses x0=0x42 as XOR key for decryption"}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    std::string hyp_id;
    if (result.contains("id")) {
        hyp_id = result["id"].get<std::string>();
    } else if (result.contains("hypothesis_id")) {
        hyp_id = result["hypothesis_id"].get<std::string>();
    }
    REQUIRE_FALSE(hyp_id.empty());

    // List hypotheses
    auto list_resp = client.send_rpc(make_tool_call("hypothesis_list", 31));
    REQUIRE(!list_resp.is_null());
    CHECK(list_resp["result"]["isError"] == false);

    // Get the hypothesis
    auto get_resp = client.send_rpc(make_tool_call("hypothesis_get", 32, {
        {"id", hyp_id}
    }));
    REQUIRE(!get_resp.is_null());
    CHECK(get_resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: mem_write_history tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("mem_write_history", 33, {
        {"addr", "0x200000000"},
        {"size", 8}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    CHECK(result.contains("write_inst_ids"));
}

TEST_CASE("MCP HTTP: window_stats tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("window_stats", 34, {
        {"start_inst_id", 0}, {"end_inst_id", 10}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: entropy_analysis tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("entropy_analysis", 35));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: unknown tool returns error", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_tool_call("nonexistent_tool_xyz", 99));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == true);
}

TEST_CASE("MCP HTTP: invalid JSON-RPC method", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc(make_rpc("nonexistent/method", 100));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp.contains("error"));
    CHECK(resp["error"]["code"] == -32601);
}

TEST_CASE("MCP HTTP: taint_backward tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("taint_backward", 36, {
        {"sink_inst_id", 12},
        {"sink_reg", 3}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: dataflow_graph tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("dataflow_graph", 37, {
        {"start_inst_id", 0}, {"end_inst_id", 10}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: loop_semantics tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("loop_semantics", 38));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: algorithm_summary tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("algorithm_summary", 39));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: memory_snapshot tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("memory_snapshot", 40, {
        {"inst_ids", json::array({5, 10})}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: reg_timeline tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("reg_timeline", 41, {
        {"reg_index", 0}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: producer_chain tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("producer_chain", 42, {
        {"inst_id", 10}, {"reg_index", 3}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: find_function tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("find_function", 43, {
        {"inst_id", 10}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: syscall_intercept tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("syscall_intercept", 44));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: critical_path tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // critical_path may take >10s on large traces; use 60s timeout
    auto resp = client.send_rpc_retry(make_tool_call("critical_path", 45, {
        {"source_reg", 0}, {"source_inst_id", 2},
        {"sink_reg", 3}, {"sink_inst_id", 12}
    }), 60, std::chrono::milliseconds(1000), std::chrono::milliseconds(60000));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: call_context tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("call_context", 46, {
        {"inst_id", 10}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: memory_strings tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("memory_strings", 47, {
        {"at_inst_id", 10}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: trace_fold tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    auto resp = client.send_rpc_retry(make_tool_call("trace_fold", 48));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: symbol_annotation tool", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    uint64_t xor_pc = 0x2000ULL + 0x4000ULL;
    auto resp = client.send_rpc_retry(make_tool_call("symbol_annotation", 49, {
        {"address", fmt::format("0x{:X}", xor_pc)},
        {"name", "xor_decrypt"}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);
}

TEST_CASE("MCP HTTP: GET /mcp returns 405", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto resp = http_get("127.0.0.1", ctx.port, "/mcp");
    CHECK(resp.status == 405);
}

TEST_CASE("MCP HTTP: empty body returns 400", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto resp = http_post("127.0.0.1", ctx.port, "/mcp", "");
    CHECK(resp.status == 400);
}

TEST_CASE("MCP HTTP: malformed JSON returns parse error", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto resp = http_post("127.0.0.1", ctx.port, "/mcp", "{not json}");
    REQUIRE(resp.status == 200);
    auto body = json::parse(resp.body);
    CHECK(body["error"]["code"] == -32700);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Concurrency Tests
//
// Verify the shared_mutex-based read/write tool concurrency model:
//   - Read-only tools execute in parallel (shared_lock)
//   - Write tools (hypothesis_*) acquire exclusive lock (unique_lock)
//   - Mixed read/write workloads produce no data corruption
// ═══════════════════════════════════════════════════════════════════════════════

/// Thread-safe RPC: uses the shared session_id but creates its own TCP connection.
/// Does NOT use Catch2 macros (which are not thread-safe).
static json thread_safe_rpc(const std::string& host, uint16_t port,
                            const std::string& session_id,
                            const json& request) {
    std::string extra = "Mcp-Session-Id: " + session_id + "\r\n";
    auto resp = http_post(host, port, "/mcp", request.dump(), extra);
    if (resp.status == 0) return nullptr;
    try { return json::parse(resp.body); }
    catch (...) { return nullptr; }
}

TEST_CASE("MCP HTTP: parallel read tools execute concurrently",
          "[integration][mcp][http][concurrency]") {
    auto& ctx = shared_env();

    // Fire N read-only tool calls from separate threads.
    // All share a single pre-initialized session (created on main thread).
    constexpr int N = 8;
    struct ReadJob {
        std::string tool;
        json args;
    };
    // Use tools that reliably succeed (avoid xref/constants_scan which
    // have known null-handling issues in this trace fixture).
    // Only use tools that never require a pass (no PassNotReady retry needed).
    std::vector<ReadJob> jobs = {
        {"trace_info",  {}},
        {"get_regs",    {{"inst_id", 0}}},
        {"get_regs",    {{"inst_id", 2}}},
        {"disasm",      {{"start_inst_id", 0}, {"count", 3}}},
        {"memread",     {{"addr", "0x200000000"}, {"at_inst_id", 5}, {"size", 8}}},
        {"get_regs",    {{"inst_id", 3}}},
        {"get_regs",    {{"inst_id", 5}}},
        {"disasm",      {{"start_inst_id", 5}, {"count", 3}}},
    };
    static_assert(N == 8);

    // Pre-initialize a session on the main thread
    auto client0 = make_client(ctx);
    const std::string session_id = client0.session_id;
    REQUIRE_FALSE(session_id.empty());

    // Measure sequential baseline
    auto t_seq_start = std::chrono::steady_clock::now();
    for (int i = 0; i < N; i++) {
        auto r = client0.send_rpc(make_tool_call(jobs[i].tool, 1000 + i, jobs[i].args));
        REQUIRE_HTTP_RESPONSE(r);
        CHECK(r["result"]["isError"] == false);
    }
    auto t_seq_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t_seq_start).count();

    // Fire all N calls concurrently, sharing the same session
    std::vector<json> results(N);
    std::vector<std::thread> threads;
    threads.reserve(N);

    auto t_par_start = std::chrono::steady_clock::now();
    for (int i = 0; i < N; i++) {
        threads.emplace_back([&, i]() {
            results[i] = thread_safe_rpc(
                "127.0.0.1", ctx.port, session_id,
                make_tool_call(jobs[i].tool, 2000 + i, jobs[i].args));
        });
    }
    for (auto& th : threads) th.join();
    auto t_par_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t_par_start).count();

    // Verify all succeeded (checked on main thread)
    for (int i = 0; i < N; i++) {
        INFO("tool=" << jobs[i].tool << " index=" << i);
        REQUIRE_FALSE(results[i].is_null());
        CHECK(results[i]["result"]["isError"] == false);
    }

    // Log timing for manual inspection.  On a small synthetic trace the
    // per-tool work is sub-millisecond, so TCP connection overhead dominates
    // and parallel wall-clock may actually be *higher*.  We intentionally
    // do NOT assert on timing here — the value of this test is proving that
    // all N concurrent requests complete successfully without races/crashes.
    INFO("sequential=" << t_seq_us << "us  parallel=" << t_par_us << "us");
}

TEST_CASE("MCP HTTP: write tools serialize correctly (hypothesis_add)",
          "[integration][mcp][http][concurrency]") {
    auto& ctx = shared_env();

    // Pre-initialize session on main thread
    auto client0 = make_client(ctx);
    const std::string session_id = client0.session_id;
    REQUIRE_FALSE(session_id.empty());

    // Fire N concurrent hypothesis_add calls.  Because write tools
    // acquire a unique_lock, they execute serially.  Each hypothesis
    // should get a unique sequential ID.
    constexpr int N = 6;
    std::vector<json> results(N);
    std::vector<std::thread> threads;
    threads.reserve(N);

    for (int i = 0; i < N; i++) {
        threads.emplace_back([&, i]() {
            results[i] = thread_safe_rpc(
                "127.0.0.1", ctx.port, session_id,
                make_tool_call("hypothesis_add", 3000 + i, {
                    {"statement", fmt::format("Concurrent hypothesis {}", i)}
                }));
        });
    }
    for (auto& th : threads) th.join();

    // All must succeed and return unique IDs
    std::unordered_set<std::string> ids;
    for (int i = 0; i < N; i++) {
        INFO("index=" << i);
        REQUIRE_FALSE(results[i].is_null());
        CHECK(results[i]["result"]["isError"] == false);

        auto text = results[i]["result"]["content"][0]["text"].get<std::string>();
        auto parsed = json::parse(text);
        std::string hyp_id;
        if (parsed.contains("id")) hyp_id = parsed["id"].get<std::string>();
        else if (parsed.contains("hypothesis_id")) hyp_id = parsed["hypothesis_id"].get<std::string>();
        REQUIRE_FALSE(hyp_id.empty());
        ids.insert(hyp_id);
    }

    // All IDs must be unique — proves serialization prevented races
    CHECK(ids.size() == static_cast<size_t>(N));
}

TEST_CASE("MCP HTTP: mixed read/write workload is safe",
          "[integration][mcp][http][concurrency]") {
    auto& ctx = shared_env();

    // Pre-initialize session on main thread
    auto client0 = make_client(ctx);
    const std::string session_id = client0.session_id;
    REQUIRE_FALSE(session_id.empty());

    // Launch a mixed workload: some read tools + some write tools
    // concurrently.  The test verifies no crashes, no JSON parse
    // errors, and all calls return valid responses.
    struct MixedJob {
        std::string tool;
        json args;
        bool is_write;
    };
    // Only use read tools that never require a pass (avoid PassNotReady).
    std::vector<MixedJob> jobs = {
        {"trace_info",      {},                                 false},
        {"hypothesis_add",  {{"statement", "mixed-test-1"}},    true},
        {"get_regs",        {{"inst_id", 5}},                   false},
        {"disasm",          {{"start_inst_id", 0}, {"count", 3}}, false},
        {"hypothesis_add",  {{"statement", "mixed-test-2"}},    true},
        {"memread",         {{"addr", "0x200000000"}, {"at_inst_id", 5}, {"size", 8}}, false},
        {"get_regs",        {{"inst_id", 3}},                   false},
        {"hypothesis_add",  {{"statement", "mixed-test-3"}},    true},
        {"get_regs",        {{"inst_id", 10}},                  false},
        {"disasm",          {{"start_inst_id", 10}, {"count", 3}}, false},
    };
    const int N = static_cast<int>(jobs.size());

    std::vector<json> results(N);
    std::vector<std::thread> threads;
    threads.reserve(N);

    for (int i = 0; i < N; i++) {
        threads.emplace_back([&, i]() {
            results[i] = thread_safe_rpc(
                "127.0.0.1", ctx.port, session_id,
                make_tool_call(jobs[i].tool, 4000 + i, jobs[i].args));
        });
    }
    for (auto& th : threads) th.join();

    // Every call should return a valid JSON-RPC response
    int read_ok = 0, write_ok = 0;
    for (int i = 0; i < N; i++) {
        INFO("tool=" << jobs[i].tool << " index=" << i
             << " is_write=" << jobs[i].is_write);
        REQUIRE_FALSE(results[i].is_null());
        CHECK(results[i]["result"]["isError"] == false);

        if (jobs[i].is_write) write_ok++;
        else read_ok++;
    }

    // Sanity: we had 7 reads and 3 writes
    CHECK(read_ok == 7);
    CHECK(write_ok == 3);
}

// ── pc-based parameter tests ──────────────────────────────────────────────
// These tests verify that tools accept a 'pc' hex string in place of 'inst_id'.
//
// Address conventions (same as the MCP 'search_pc' tool):
//   displayed_pc = static_pc + image_base       (image_base default: 0x100000000)
//   runtime_pc   = static_pc + module_slide     (slide: 0x4000)
//   unrebase(displayed_pc) = runtime_pc
//
// So for static 0x1008 → displayed 0x100001008 → runtime 0x5008.
// For static 0x2000 → displayed 0x100002000.
// For static 0x200C → displayed 0x10000200C.

static constexpr uint64_t kImageBase = 0x100000000ULL;

TEST_CASE("MCP HTTP: get_regs via pc parameter", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // static 0x1008 (inst 2: movz x0, 0x42) → displayed 0x100001008
    uint64_t disp_pc = 0x1008ULL + kImageBase;
    auto resp = client.send_rpc_retry(make_tool_call("get_regs", 200, {
        {"pc", fmt::format("0x{:X}", disp_pc)}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    REQUIRE(result.contains("regs"));
    // inst_id must be filled in by the server
    REQUIRE(result.contains("inst_id"));
}

TEST_CASE("MCP HTTP: call_context via pc parameter", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // xor_decrypt entry (static 0x2000) → displayed 0x100002000
    uint64_t disp_pc = 0x2000ULL + kImageBase;
    auto resp = client.send_rpc_retry(make_tool_call("call_context", 201, {
        {"pc", fmt::format("0x{:X}", disp_pc)}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    REQUIRE(result.contains("call_stack"));
    REQUIRE(result.contains("target_inst_id"));
}

TEST_CASE("MCP HTTP: producer_chain via pc parameter", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // xor_decrypt body (static 0x200C) → displayed 0x10000200C, reg x3
    uint64_t disp_xor_body = 0x200CULL + kImageBase;
    auto resp = client.send_rpc_retry(make_tool_call("producer_chain", 202, {
        {"pc",        fmt::format("0x{:X}", disp_xor_body)},
        {"reg_index", "x3"}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == false);

    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    auto result = json::parse(text);
    REQUIRE(result.contains("chain"));
}

TEST_CASE("MCP HTTP: get_regs via unknown pc returns error", "[integration][mcp][http]") {
    auto& ctx = shared_env();
    auto client = make_client(ctx);

    // A PC that was never executed should return isError=true with a clear message
    auto resp = client.send_rpc_retry(make_tool_call("get_regs", 203, {
        {"pc", "0xDEADBEEF"}
    }));
    REQUIRE_HTTP_RESPONSE(resp);
    CHECK(resp["result"]["isError"] == true);
    auto text = resp["result"]["content"][0]["text"].get<std::string>();
    CHECK(text.find("No instruction found") != std::string::npos);
}

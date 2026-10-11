#include <catch2/catch_test_macros.hpp>

#include "io/mcp/mcp_hub.h"

#include "common/platform_compat.h"

#include <algorithm>

using json = nlohmann::json;
using namespace tenet;

namespace tenet {

struct McpWorkerTransportTestAccess {
    static void install_socket(McpWorkerTransport& worker, platform::socket_t fd) {
        worker.install_socket(fd);
    }

    static platform::socket_t current_socket_fd(const McpWorkerTransport& worker) {
        return worker.current_socket_fd();
    }

    static bool send_json(McpWorkerTransport& worker, const json& msg) {
        return worker.send_json(msg);
    }

    static void shutdown_connection(McpWorkerTransport& worker) {
        worker.shutdown_connection();
    }

    static void close_connection(McpWorkerTransport& worker) {
        worker.close_connection();
    }
};

}  // namespace tenet

namespace {

int make_socketpair(platform::socket_t fds[2]) {
    platform::ensure_sockets_initialized();
    auto listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!platform::socket_valid(listener)) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    platform::socklen_compat_t length = sizeof(address);
    bool ok = ::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0
           && ::listen(listener, 1) == 0
           && ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
    if (ok) {
        fds[0] = ::socket(AF_INET, SOCK_STREAM, 0);
        ok = platform::socket_valid(fds[0])
          && ::connect(fds[0], reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
        if (ok) { fds[1] = ::accept(listener, nullptr, nullptr); ok = platform::socket_valid(fds[1]); }
    }
    platform::close_socket(listener);
    if (!ok) { platform::close_socket(fds[0]); platform::close_socket(fds[1]); }
    return ok ? 0 : -1;
}

}  // namespace

TEST_CASE("mcp hub instance send is blocked by close lifecycle", "[unit][mcp][hub]") {
    platform::socket_t fds[2] = {platform::kInvalidSocket, platform::kInvalidSocket};
    REQUIRE(make_socketpair(fds) == 0);

    HubInstance inst;
    inst.attach_socket(fds[0]);

    REQUIRE(inst.has_socket());
    REQUIRE(inst.matches_socket(fds[0]));
    REQUIRE(inst.send(json{{"type", "ping"}}));

    char buf[256] = {};
    ssize_t n = ::recv(fds[1], buf, sizeof(buf), 0);
    REQUIRE(n > 0);

    inst.close_socket_if(fds[0]);
    REQUIRE_FALSE(inst.has_socket());
    REQUIRE_FALSE(inst.matches_socket(fds[0]));
    REQUIRE_FALSE(inst.send(json{{"type", "ping"}}));

    platform::close_socket(fds[1]);
}

TEST_CASE("mcp worker transport socket lifecycle helpers are synchronized", "[unit][mcp][hub]") {
    platform::socket_t fds[2] = {platform::kInvalidSocket, platform::kInvalidSocket};
    REQUIRE(make_socketpair(fds) == 0);

    McpWorkerTransport worker([](const json& msg) { return msg; },
                              "127.0.0.1", 10444,
                              "iid", 1,
                              "/tmp/trace.bin", "module");

    McpWorkerTransportTestAccess::install_socket(worker, fds[0]);
    REQUIRE(McpWorkerTransportTestAccess::current_socket_fd(worker) == fds[0]);
    REQUIRE(McpWorkerTransportTestAccess::send_json(worker, json{{"type", "hello"}}));

    char buf[256] = {};
    ssize_t n = ::recv(fds[1], buf, sizeof(buf), 0);
    REQUIRE(n > 0);

    McpWorkerTransportTestAccess::shutdown_connection(worker);
    McpWorkerTransportTestAccess::close_connection(worker);
    REQUIRE(McpWorkerTransportTestAccess::current_socket_fd(worker) == platform::kInvalidSocket);
    REQUIRE_FALSE(McpWorkerTransportTestAccess::send_json(worker, json{{"type", "bye"}}));

    platform::close_socket(fds[1]);
}

TEST_CASE("mcp hub websocket registry isolates worker generations", "[unit][mcp][hub]") {
    BoundWsSessionRegistry registry;

    auto old_worker = std::make_shared<HubInstance>();
    old_worker->id = "iid";
    auto new_worker = std::make_shared<HubInstance>();
    new_worker->id = "iid";

    registry.register_session(11, old_worker);
    registry.register_session(22, new_worker);
    registry.register_session(33, nullptr);

    auto old_fds = registry.sessions_for_instance(old_worker);
    auto new_fds = registry.sessions_for_instance(new_worker);
    auto hub_fds = registry.hub_local_sessions();
    std::sort(old_fds.begin(), old_fds.end());
    std::sort(new_fds.begin(), new_fds.end());
    std::sort(hub_fds.begin(), hub_fds.end());

    REQUIRE(old_fds == std::vector<platform::socket_t>{11});
    REQUIRE(new_fds == std::vector<platform::socket_t>{22});
    REQUIRE(hub_fds == std::vector<platform::socket_t>{33});
    REQUIRE(registry.has_session(11));
    REQUIRE(registry.has_session(22));
    REQUIRE(registry.has_session(33));

    registry.unregister_session(11);
    registry.unregister_session(33);

    REQUIRE(registry.sessions_for_instance(old_worker).empty());
    REQUIRE(registry.hub_local_sessions().empty());
    REQUIRE(registry.sessions_for_instance(new_worker) == std::vector<platform::socket_t>{22});
    REQUIRE_FALSE(registry.has_session(11));
    REQUIRE(registry.has_session(22));
    REQUIRE_FALSE(registry.has_session(33));
}

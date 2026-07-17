#include <catch2/catch_test_macros.hpp>

#include "io/mcp/mcp_hub.h"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>

using json = nlohmann::json;
using namespace tenet;

namespace tenet {

struct McpWorkerTransportTestAccess {
    static void install_socket(McpWorkerTransport& worker, int fd) {
        worker.install_socket(fd);
    }

    static int current_socket_fd(const McpWorkerTransport& worker) {
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

int make_socketpair(int fds[2]) {
    return ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
}

}  // namespace

TEST_CASE("mcp hub instance send is blocked by close lifecycle", "[unit][mcp][hub]") {
    int fds[2] = {-1, -1};
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

    ::close(fds[1]);
}

TEST_CASE("mcp worker transport socket lifecycle helpers are synchronized", "[unit][mcp][hub]") {
    int fds[2] = {-1, -1};
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
    REQUIRE(McpWorkerTransportTestAccess::current_socket_fd(worker) == -1);
    REQUIRE_FALSE(McpWorkerTransportTestAccess::send_json(worker, json{{"type", "bye"}}));

    ::close(fds[1]);
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

    REQUIRE(old_fds == std::vector<int>{11});
    REQUIRE(new_fds == std::vector<int>{22});
    REQUIRE(hub_fds == std::vector<int>{33});
    REQUIRE(registry.has_session(11));
    REQUIRE(registry.has_session(22));
    REQUIRE(registry.has_session(33));

    registry.unregister_session(11);
    registry.unregister_session(33);

    REQUIRE(registry.sessions_for_instance(old_worker).empty());
    REQUIRE(registry.hub_local_sessions().empty());
    REQUIRE(registry.sessions_for_instance(new_worker) == std::vector<int>{22});
    REQUIRE_FALSE(registry.has_session(11));
    REQUIRE(registry.has_session(22));
    REQUIRE_FALSE(registry.has_session(33));
}

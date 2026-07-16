#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "io/mcp/mcp_server.h"
#include "service/tenet_service.h"
#include "tenet_ws_generated.h"
#include "ws/ws_analysis_jobs.h"
#include "ws/ws_async_reply_dispatcher.h"
#include "ws/ws_protocol.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace tenet;

using namespace tenet::test;

namespace {

std::unique_ptr<TenetService> make_service(TraceEnv& env) {
    return std::make_unique<TenetService>(
        *env.reader, *env.index, env.code_table, env.decoder,
        *env.regfile, *env.memory);
}

struct FakeLoop {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::function<void()>> deferred;

    void defer(std::function<void()> fn) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            deferred.push_back(std::move(fn));
        }
        cv.notify_all();
    }

    bool wait_for_count(size_t want,
                        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)) {
        std::unique_lock<std::mutex> lock(mutex);
        return cv.wait_for(lock, timeout, [&] { return deferred.size() >= want; });
    }

    void flush_all() {
        std::vector<std::function<void()>> ready;
        {
            std::lock_guard<std::mutex> lock(mutex);
            ready.swap(deferred);
        }
        for (auto& fn : ready) fn();
    }
};

struct SendRecord {
    void* socket = nullptr;
    std::string payload;
};

}  // namespace

TEST_CASE("WSAsyncReplyDispatcher sends one deferred reply from worker result",
          "[unit][ws]") {
    FakeLoop loop;
    std::mutex sends_mutex;
    std::vector<SendRecord> sends;
    WSAsyncReplyDispatcher dispatcher(
        [&](std::function<void()> fn) { loop.defer(std::move(fn)); },
        [&](void* socket, std::string_view payload) {
            std::lock_guard<std::mutex> lock(sends_mutex);
            sends.push_back({socket, std::string(payload)});
        });

    int socket_storage = 0;
    auto token = dispatcher.register_connection(&socket_storage);
    const auto loop_thread = std::this_thread::get_id();
    std::promise<std::thread::id> worker_thread_promise;
    auto worker_thread_future = worker_thread_promise.get_future();

    REQUIRE(dispatcher.dispatch(token, [&] {
        worker_thread_promise.set_value(std::this_thread::get_id());
        return std::string("serialized-response");
    }));

    REQUIRE(loop.wait_for_count(1));
    REQUIRE(worker_thread_future.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    CHECK(worker_thread_future.get() != loop_thread);

    {
        std::lock_guard<std::mutex> lock(sends_mutex);
        CHECK(sends.empty());
    }

    loop.flush_all();

    std::lock_guard<std::mutex> lock(sends_mutex);
    REQUIRE(sends.size() == 1);
    CHECK(sends[0].socket == &socket_storage);
    CHECK(sends[0].payload == "serialized-response");
}

TEST_CASE("WSAsyncReplyDispatcher drops deferred reply after disconnect",
          "[unit][ws]") {
    FakeLoop loop;
    std::vector<SendRecord> sends;
    WSAsyncReplyDispatcher dispatcher(
        [&](std::function<void()> fn) { loop.defer(std::move(fn)); },
        [&](void* socket, std::string_view payload) {
            sends.push_back({socket, std::string(payload)});
        });

    int socket_storage = 0;
    auto token = dispatcher.register_connection(&socket_storage);
    REQUIRE(dispatcher.dispatch(token, [] {
        return std::string("late-response");
    }));

    REQUIRE(loop.wait_for_count(1));
    dispatcher.unregister_connection(&socket_storage);
    loop.flush_all();

    CHECK(sends.empty());
}

TEST_CASE("WSAsyncReplyDispatcher rejects pointer reuse with stale generation",
          "[unit][ws]") {
    FakeLoop loop;
    std::vector<SendRecord> sends;
    WSAsyncReplyDispatcher dispatcher(
        [&](std::function<void()> fn) { loop.defer(std::move(fn)); },
        [&](void* socket, std::string_view payload) {
            sends.push_back({socket, std::string(payload)});
        });

    int socket_storage = 0;
    auto stale = dispatcher.register_connection(&socket_storage);
    REQUIRE(dispatcher.dispatch(stale, [] {
        return std::string("stale-response");
    }));

    REQUIRE(loop.wait_for_count(1));
    dispatcher.unregister_connection(&socket_storage);
    auto current = dispatcher.register_connection(&socket_storage);

    CHECK(stale.generation != current.generation);
    CHECK_FALSE(dispatcher.is_current(stale));
    CHECK(dispatcher.is_current(current));

    loop.flush_all();
    CHECK(sends.empty());
}

TEST_CASE("WSAsyncReplyDispatcher stop waits for workers and suppresses sends",
          "[unit][ws]") {
    FakeLoop loop;
    std::vector<SendRecord> sends;
    WSAsyncReplyDispatcher dispatcher(
        [&](std::function<void()> fn) { loop.defer(std::move(fn)); },
        [&](void* socket, std::string_view payload) {
            sends.push_back({socket, std::string(payload)});
        });

    int socket_storage = 0;
    auto token = dispatcher.register_connection(&socket_storage);
    std::promise<void> started;
    auto started_future = started.get_future();
    std::promise<void> release;
    auto release_future = release.get_future().share();

    REQUIRE(dispatcher.dispatch(token, [&, release_future] {
        started.set_value();
        release_future.wait();
        return std::string("should-not-send");
    }));

    REQUIRE(started_future.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    auto stop_future = std::async(std::launch::async, [&] {
        dispatcher.stop();
    });

    CHECK(stop_future.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
    release.set_value();
    REQUIRE(stop_future.wait_for(std::chrono::seconds(1)) == std::future_status::ready);

    loop.flush_all();
    CHECK(sends.empty());
}

TEST_CASE("build_ws_envelope_bytes preserves msg id type and payload",
          "[unit][ws]") {
    flatbuffers::FlatBufferBuilder payload_builder(128);
    auto tool_name = payload_builder.CreateString("taint_search");
    auto error = payload_builder.CreateString("");
    auto response = tenet::ws::CreateRunAnalysisResponse(
        payload_builder, tool_name, true, 0, error);
    payload_builder.Finish(response);

    auto envelope_bytes = build_ws_envelope_bytes(
        77,
        tenet::ws::MessageType_RunAnalysisResp,
        payload_builder.GetBufferPointer(),
        payload_builder.GetSize());

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 77);
    CHECK(envelope->type() == tenet::ws::MessageType_RunAnalysisResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* inner = flatbuffers::GetRoot<tenet::ws::RunAnalysisResponse>(
        envelope->payload()->data());
    REQUIRE(inner != nullptr);
    CHECK(inner->ok());
    REQUIRE(inner->tool_name() != nullptr);
    CHECK(inner->tool_name()->str() == "taint_search");
}

TEST_CASE("build_ws_envelope_bytes omits payload for empty bodies",
          "[unit][ws]") {
    auto envelope_bytes = build_ws_envelope_bytes(
        91,
        tenet::ws::MessageType_SearchClearResp,
        static_cast<const uint8_t*>(nullptr),
        0);

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 91);
    CHECK(envelope->type() == tenet::ws::MessageType_SearchClearResp);
    CHECK(envelope->payload() == nullptr);
}

TEST_CASE("build_ws_reply_or_error returns ErrorResp with original msg id",
          "[unit][ws]") {
    auto envelope_bytes = build_ws_reply_or_error(
        123,
        7,
        "GetFunctions",
        []() -> std::string {
            throw std::runtime_error("boom");
        });

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 123);
    CHECK(envelope->type() == tenet::ws::MessageType_ErrorResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* err = flatbuffers::GetRoot<tenet::ws::ErrorResponse>(
        envelope->payload()->data());
    REQUIRE(err != nullptr);
    CHECK(err->code() == 7);
    REQUIRE(err->message() != nullptr);
    CHECK(err->message()->str().find("GetFunctions") != std::string::npos);
    CHECK(err->message()->str().find("boom") != std::string::npos);
}

TEST_CASE("build_get_functions_reply_bytes returns typed envelope",
          "[unit][ws]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000),
                {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
        tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "ws_job_functions");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);
    auto envelope_bytes = build_get_functions_reply_bytes(*svc, 200);

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 200);
    CHECK(envelope->type() == tenet::ws::MessageType_GetFunctionsResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* resp = flatbuffers::GetRoot<tenet::ws::GetFunctionsResponse>(
        envelope->payload()->data());
    REQUIRE(resp != nullptr);
    REQUIRE(resp->functions() != nullptr);
    CHECK(resp->functions()->size() >= 1);
}

TEST_CASE("build_get_call_stack_reply_bytes returns typed envelope",
          "[unit][ws]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000),
                {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
        tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "ws_job_callstack_ok");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);
    auto envelope_bytes = build_get_call_stack_reply_bytes(*svc, 201, 1);

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 201);
    CHECK(envelope->type() == tenet::ws::MessageType_GetCallStackResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* resp = flatbuffers::GetRoot<tenet::ws::GetCallStackResponse>(
        envelope->payload()->data());
    REQUIRE(resp != nullptr);
    REQUIRE(resp->entries() != nullptr);
    CHECK(resp->entries()->size() >= 1);
}

TEST_CASE("build_run_analysis_reply_bytes preserves msg id on invalid json",
          "[unit][ws]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "ws_job_run_analysis_error");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);
    TenetMcpService dispatcher(*svc);
    auto envelope_bytes = build_run_analysis_reply_bytes(
        dispatcher, 202, "trace_info", "{");

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 202);
    CHECK(envelope->type() == tenet::ws::MessageType_RunAnalysisResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* resp = flatbuffers::GetRoot<tenet::ws::RunAnalysisResponse>(
        envelope->payload()->data());
    REQUIRE(resp != nullptr);
    CHECK_FALSE(resp->ok());
    REQUIRE(resp->error() != nullptr);
    CHECK_FALSE(resp->error()->str().empty());
}

TEST_CASE("build_search_forward_reply_bytes returns typed envelope",
          "[unit][ws]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_reg(0, 0, 0), {{0, 1}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::nop(), {{33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "ws_job_search_forward_ok");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);
    auto envelope_bytes = build_search_forward_reply_bytes(*svc, 210, "nop", 2);

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 210);
    CHECK(envelope->type() == tenet::ws::MessageType_SearchForwardResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* resp = flatbuffers::GetRoot<tenet::ws::SearchForwardResponse>(
        envelope->payload()->data());
    REQUIRE(resp != nullptr);
    REQUIRE(resp->results() != nullptr);
    CHECK(resp->count() == 3);
    REQUIRE(resp->results()->size() == 3);
    CHECK(resp->results()->Get(0) == 2);
    CHECK(resp->results()->Get(1) == 3);
    CHECK(resp->results()->Get(2) == 0);
}

TEST_CASE("build_search_forward_reply_bytes converts exceptions to ErrorResp",
          "[unit][ws]") {
    auto envelope_bytes = build_search_forward_reply_bytes(
        211,
        []() -> std::vector<uint64_t> {
            throw std::runtime_error("search blew up");
        });

    auto* envelope = flatbuffers::GetRoot<tenet::ws::Envelope>(
        reinterpret_cast<const uint8_t*>(envelope_bytes.data()));
    REQUIRE(envelope != nullptr);
    CHECK(envelope->msg_id() == 211);
    CHECK(envelope->type() == tenet::ws::MessageType_ErrorResp);
    REQUIRE(envelope->payload() != nullptr);

    auto* err = flatbuffers::GetRoot<tenet::ws::ErrorResponse>(
        envelope->payload()->data());
    REQUIRE(err != nullptr);
    CHECK(err->code() == 3);
    REQUIRE(err->message() != nullptr);
    CHECK(err->message()->str().find("SearchForward") != std::string::npos);
    CHECK(err->message()->str().find("search blew up") != std::string::npos);
}

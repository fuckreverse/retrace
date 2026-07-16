#include <catch2/catch_test_macros.hpp>

#include "ws/ws_analysis_task_queue.h"
#include "ws/ws_async_reply_dispatcher.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace tenet;

namespace {

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

// ─── WSAnalysisTaskQueue ──────────────────────────────────────────────────

TEST_CASE("WSAnalysisTaskQueue enqueue returns true and runs task",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;
    std::atomic<int> counter{0};

    REQUIRE(queue.enqueue([&] { counter.fetch_add(1); }));

    // Give the async worker time to run
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(counter.load() == 1);
}

TEST_CASE("WSAnalysisTaskQueue enqueue rejects after stop",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;
    std::atomic<int> counter{0};

    REQUIRE(queue.enqueue([&] { counter.fetch_add(1); }));
    queue.stop();

    CHECK(queue.is_stopping());
    CHECK_FALSE(queue.enqueue([&] { counter.fetch_add(1); }));

    // Only the first task should have run
    CHECK(counter.load() == 1);
}

TEST_CASE("WSAnalysisTaskQueue stop drains all workers",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;
    std::atomic<int> counter{0};

    for (int i = 0; i < 4; ++i) {
        REQUIRE(queue.enqueue([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            counter.fetch_add(1);
        }));
    }

    queue.stop();
    // After stop, all workers must have completed
    CHECK(counter.load() == 4);
}

TEST_CASE("WSAnalysisTaskQueue concurrent stop and enqueue — no tasks run after gate closes",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;
    std::atomic<int> executed{0};

    // Start a blocking task so we can observe the gate closing
    std::promise<void> release;
    auto release_future = release.get_future().share();
    std::promise<void> started;
    auto started_future = started.get_future();

    REQUIRE(queue.enqueue([&] {
        started.set_value();
        release_future.wait();
        executed.fetch_add(1);
    }));

    REQUIRE(started_future.wait_for(std::chrono::seconds(1))
            == std::future_status::ready);

    // Now stop() on another thread — it should block until the worker finishes
    auto stop_future = std::async(std::launch::async, [&] {
        queue.stop();
    });

    // stop() should set the gate quickly, even though the worker is still running
    // Spin until the gate is observed closed
    for (int i = 0; i < 200; ++i) {
        if (queue.is_stopping()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    REQUIRE(queue.is_stopping());

    // Any enqueue after gate closes must return false
    int enqueues_attempted = 0;
    int enqueues_rejected = 0;
    for (int i = 0; i < 10; ++i) {
        ++enqueues_attempted;
        if (!queue.enqueue([&] { executed.fetch_add(1); })) {
            ++enqueues_rejected;
        }
    }
    CHECK(enqueues_rejected == enqueues_attempted);

    // Release the blocking worker
    release.set_value();

    // stop() should complete now
    REQUIRE(stop_future.wait_for(std::chrono::seconds(2)) == std::future_status::ready);

    // Only the first (pre-gate) task should have executed
    CHECK(executed.load() == 1);
}

TEST_CASE("WSAnalysisTaskQueue enqueue returns false for null task",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;
    CHECK_FALSE(queue.enqueue(nullptr));
}

TEST_CASE("WSAnalysisTaskQueue stop is idempotent",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;
    std::atomic<int> counter{0};

    REQUIRE(queue.enqueue([&] { counter.fetch_add(1); }));
    queue.stop();
    queue.stop();  // second call must not deadlock or crash
    CHECK(counter.load() == 1);
}

// ─── WSAsyncReplyDispatcher stopping recheck under lock ──────────────────

// ─── Moved-from alias safety ─────────────────────────────────────────────────
//
// Regression test: handle_run_pass used to move-capture `name` into the
// lambda and then reference `name` (now moved-from) for the accepted reply
// and progress tracking.  Verify that the safe pattern (copy-capture) works
// correctly — both the worker lambda and the caller see the same value.

TEST_CASE("Enqueue task with copy-captured string — both worker and caller see original name",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;

    std::string name = "taint";  // short SSO string

    std::promise<std::string> worker_promise;
    auto worker_future = worker_promise.get_future();

    // Copy-capture `name` (same pattern as the fixed handle_run_pass).
    REQUIRE(queue.enqueue([&, name]() {
        worker_promise.set_value(name);
    }));

    // `name` must still be valid on the caller side after enqueue.
    CHECK(name == "taint");

    // Worker must also see the same value.
    REQUIRE(worker_future.wait_for(std::chrono::seconds(1))
            == std::future_status::ready);
    CHECK(worker_future.get() == "taint");
}

TEST_CASE("Enqueue task with copy-captured long string — no moved-from alias",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;

    // Long string that exceeds SSO to test heap allocation correctness.
    std::string name(200, 'x');

    std::promise<std::string> worker_promise;
    auto worker_future = worker_promise.get_future();

    REQUIRE(queue.enqueue([&, name]() {
        worker_promise.set_value(name);
    }));

    // Caller's `name` must be untouched.
    CHECK(name.size() == 200);
    CHECK(name == std::string(200, 'x'));

    REQUIRE(worker_future.wait_for(std::chrono::seconds(1))
            == std::future_status::ready);
    CHECK(worker_future.get() == std::string(200, 'x'));
}

TEST_CASE("Multiple enqueue with same-named variable — each copy is independent",
          "[unit][ws]") {
    WSAnalysisTaskQueue queue;

    std::vector<std::future<std::string>> futures;
    std::vector<std::string> expected;

    for (int i = 0; i < 5; ++i) {
        std::string name = "pass_" + std::to_string(i);
        expected.push_back(name);

        auto prom = std::make_shared<std::promise<std::string>>();
        futures.push_back(prom->get_future());

        REQUIRE(queue.enqueue([name, prom]() {
            prom->set_value(name);
        }));
    }

    for (int i = 0; i < 5; ++i) {
        REQUIRE(futures[i].wait_for(std::chrono::seconds(1))
                == std::future_status::ready);
        CHECK(futures[i].get() == expected[i]);
    }
}

TEST_CASE("WSAsyncReplyDispatcher dispatch rejects after stop",
          "[unit][ws]") {
    FakeLoop loop;
    std::vector<SendRecord> sends;
    WSAsyncReplyDispatcher dispatcher(
        [&](std::function<void()> fn) { loop.defer(std::move(fn)); },
        [&](void* socket, std::string_view payload) {
            sends.push_back({socket, std::string(payload)});
        });

    int socket = 0;
    auto token = dispatcher.register_connection(&socket);

    dispatcher.stop();

    // dispatch after stop must be a no-op — no worker spawned
    CHECK_FALSE(dispatcher.dispatch(token, [] { return std::string("late"); }));

    // Give potential worker time to spawn (it shouldn't)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    loop.flush_all();

    CHECK(sends.empty());
}

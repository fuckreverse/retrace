#include <catch2/catch_test_macros.hpp>

#include "common/progress_manager.h"

#include <stdexcept>
#include <thread>
#include <vector>

using namespace tenet;

TEST_CASE("ProgressManager exposes structured lifecycle snapshots", "[progress]") {
    ProgressManager manager;

    manager.start("index", "index", "Build trace index", 100);
    manager.update("index", 25, "scan", "Scanning records");

    auto running = manager.get("index");
    REQUIRE(running.has_value());
    CHECK(running->state == ProgressState::Running);
    CHECK(running->completed == 25);
    CHECK(running->total == 100);
    CHECK(running->progress == 0.25f);
    CHECK(running->phase == "scan");
    CHECK(running->message == "Scanning records");

    manager.complete("index", "Index ready");
    auto completed = manager.get("index");
    REQUIRE(completed.has_value());
    CHECK(completed->state == ProgressState::Completed);
    CHECK(completed->progress == 1.0f);
    CHECK(completed->message == "Index ready");
    CHECK(completed->revision > running->revision);
}

TEST_CASE("ProgressManager publishes immutable updates to subscribers", "[progress]") {
    ProgressManager manager;
    std::vector<ProgressTask> events;
    auto subscription = manager.subscribe([&events](const ProgressTask& task) {
        events.push_back(task);
    });

    manager.start("pass:xref", "pass", "xref");
    manager.update_fraction("pass:xref", 0.4f, "analyze", "Collecting xrefs");
    manager.fail("pass:xref", "cancelled");

    REQUIRE(events.size() == 3);
    CHECK(events[0].state == ProgressState::Running);
    CHECK(events[1].progress == 0.4f);
    CHECK(events[2].state == ProgressState::Failed);
    CHECK(events[2].error == "cancelled");
}

TEST_CASE("ProgressManager isolates listener failures", "[progress]") {
    ProgressManager manager;
    int delivered = 0;
    auto failing = manager.subscribe([](const ProgressTask&) {
        throw std::runtime_error("listener failed");
    });
    auto healthy = manager.subscribe([&delivered](const ProgressTask&) {
        ++delivered;
    });

    CHECK_NOTHROW(manager.start("index", "index", "Build index"));
    CHECK(delivered == 1);
    CHECK(manager.get("index").has_value());
}

TEST_CASE("ProgressManager can remove a task family without affecting other tasks", "[progress]") {
    ProgressManager manager;
    manager.start("pass:xref", "pass", "xref");
    manager.start("pass:cfg", "pass", "cfg");
    manager.start("index", "index", "index");

    manager.erase_kind("pass");

    CHECK(manager.snapshot("pass").empty());
    CHECK(manager.get("index").has_value());
}

TEST_CASE("ProgressManager supports concurrent writers and filtered snapshots", "[progress]") {
    ProgressManager manager;
    constexpr int kTaskCount = 16;
    std::vector<std::thread> threads;
    threads.reserve(kTaskCount);

    for (int i = 0; i < kTaskCount; ++i) {
        threads.emplace_back([&manager, i] {
            const auto id = "pass:" + std::to_string(i);
            manager.start(id, "pass", id, 10);
            manager.update(id, 10, "done", "Done");
            manager.complete(id);
        });
    }
    for (auto& thread : threads) thread.join();

    auto tasks = manager.snapshot("pass");
    REQUIRE(tasks.size() == kTaskCount);
    for (const auto& task : tasks) {
        CHECK(task.state == ProgressState::Completed);
        CHECK(task.progress == 1.0f);
    }
}

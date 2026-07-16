#pragma once

#include <atomic>
#include <functional>
#include <future>
#include <mutex>
#include <vector>

namespace tenet {

/// Thread-safe, stop-aware queue for analysis worker tasks (pass execution,
/// MCP tool dispatch). All analysis_workers_ paths must go through enqueue()
/// so that stop() can atomically reject new work and drain running tasks.
///
/// Lifecycle:
///   1. stop() sets the intake gate (stopping_ = true) and waits for
///      outstanding workers to finish — no new enqueue() may succeed after
///      the gate closes.
///   2. enqueue() returns false iff the gate is already closed, allowing
///      callers to reject the request *before* sending an "accepted" reply.
class WSAnalysisTaskQueue {
public:
    WSAnalysisTaskQueue() = default;
    ~WSAnalysisTaskQueue();

    WSAnalysisTaskQueue(const WSAnalysisTaskQueue&) = delete;
    WSAnalysisTaskQueue& operator=(const WSAnalysisTaskQueue&) = delete;

    /// Attempt to enqueue a background task.  Returns true if the task was
    /// accepted and started; false if the queue is stopping (caller should
    /// send an error reply instead of "accepted").
    ///
    /// The task runs on a std::async worker thread. Completed workers are
    /// reaped on the next enqueue() or stop() call.
    bool enqueue(std::function<void()> task);

    /// Close the intake gate, wait for all running workers to finish, then
    /// clear the worker list.  Safe to call multiple times.
    void stop();

    /// Returns true after stop() has been called (intake gate closed).
    bool is_stopping() const { return stopping_.load(); }

private:
    void reap_finished_workers_locked();

    std::atomic<bool> stopping_{false};
    std::mutex workers_mutex_;
    std::vector<std::future<void>> workers_;
};

}  // namespace tenet

#include "ws/ws_analysis_task_queue.h"

#include <chrono>
#include <utility>

namespace tenet {

WSAnalysisTaskQueue::~WSAnalysisTaskQueue() {
    stop();
}

bool WSAnalysisTaskQueue::enqueue(std::function<void()> task) {
    if (!task) return false;

    std::lock_guard<std::mutex> lock(workers_mutex_);
    if (stopping_.load()) return false;  // intake gate closed under lock

    reap_finished_workers_locked();
    workers_.push_back(std::async(std::launch::async, std::move(task)));
    return true;
}

void WSAnalysisTaskQueue::stop() {
    if (stopping_.exchange(true)) return;  // already stopped / idempotent

    // Move workers out from under the lock before waiting, so that
    // enqueue() callers aren't blocked while we wait for long-running
    // tasks to finish.  No new workers can be added because the intake
    // gate (stopping_) is already closed.
    std::vector<std::future<void>> to_drain;
    {
        std::lock_guard<std::mutex> lock(workers_mutex_);
        to_drain.swap(workers_);
    }

    for (auto& w : to_drain) w.wait();
    // to_drain destroyed here — futures are consumed
}

void WSAnalysisTaskQueue::reap_finished_workers_locked() {
    for (auto it = workers_.begin(); it != workers_.end();) {
        if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            it = workers_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace tenet

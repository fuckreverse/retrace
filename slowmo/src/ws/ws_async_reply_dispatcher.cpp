#include "ws/ws_async_reply_dispatcher.h"

#include <chrono>
#include <utility>

namespace tenet {

WSAsyncReplyDispatcher::WSAsyncReplyDispatcher(DeferFn defer_fn, SendFn send_fn)
    : defer_fn_(std::move(defer_fn)),
      send_fn_(std::move(send_fn)) {}

WSAsyncReplyDispatcher::~WSAsyncReplyDispatcher() {
    stop();
}

void WSAsyncReplyDispatcher::reset() {
    stop();
    stopping_.store(false);
}

void WSAsyncReplyDispatcher::stop() {
    // Set the intake gate under the lock so that any concurrent dispatch()
    // that has already acquired workers_mutex_ will finish its enqueue
    // before we drain below, and any dispatch() that checks after this
    // point will see stopping_ == true under the same lock.
    {
        std::lock_guard<std::mutex> lock(workers_mutex_);
        if (stopping_.load()) return;  // idempotent
        stopping_.store(true);
    }
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.clear();
    }
    // Move workers out from under the lock before waiting, so that
    // concurrent dispatch() callers are not blocked while we wait for
    // long-running workers.  No new workers can be added because the
    // intake gate is already closed.
    std::vector<std::future<void>> to_drain;
    {
        std::lock_guard<std::mutex> lock(workers_mutex_);
        to_drain.swap(workers_);
    }
    for (auto& w : to_drain) w.wait();
}

WSAsyncReplyDispatcher::ConnectionToken
WSAsyncReplyDispatcher::register_connection(void* socket) {
    if (socket == nullptr) return {};
    const uint64_t generation = next_generation_.fetch_add(1);
    std::lock_guard<std::mutex> lock(connections_mutex_);
    connections_[socket] = generation;
    return {socket, generation};
}

void WSAsyncReplyDispatcher::unregister_connection(void* socket) {
    if (socket == nullptr) return;
    std::lock_guard<std::mutex> lock(connections_mutex_);
    connections_.erase(socket);
}

WSAsyncReplyDispatcher::ConnectionToken
WSAsyncReplyDispatcher::token_for(void* socket) const {
    if (socket == nullptr || stopping_.load()) return {};
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(socket);
    if (it == connections_.end()) return {};
    return {it->first, it->second};
}

bool WSAsyncReplyDispatcher::is_current(const ConnectionToken& token) const {
    if (!token.valid() || stopping_.load()) return false;
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(token.socket);
    return it != connections_.end() && it->second == token.generation;
}

bool WSAsyncReplyDispatcher::dispatch(ConnectionToken token,
                                      std::function<std::string()> build_response) {
    if (!token.valid() || !build_response) return false;

    std::lock_guard<std::mutex> lock(workers_mutex_);
    // Recheck under lock — stop() sets stopping_ while holding this mutex,
    // so the check is atomic with the enqueue.
    if (stopping_.load()) return false;
    reap_finished_workers_locked();
    workers_.push_back(std::async(std::launch::async,
                                  [this, token, build_response = std::move(build_response)]() mutable {
        std::string payload = build_response();
        if (stopping_.load()) return;
        defer_fn_([this, token, payload = std::move(payload)]() mutable {
            if (!is_current(token)) return;
            send_fn_(token.socket, payload);
        });
    }));
    return true;
}

void WSAsyncReplyDispatcher::reap_finished_workers_locked() {
    for (auto it = workers_.begin(); it != workers_.end();) {
        if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            it = workers_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace tenet

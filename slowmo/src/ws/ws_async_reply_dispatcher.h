#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace tenet {

class WSAsyncReplyDispatcher {
public:
    struct ConnectionToken {
        void* socket = nullptr;
        uint64_t generation = 0;

        [[nodiscard]] bool valid() const {
            return socket != nullptr && generation != 0;
        }
    };

    using DeferFn = std::function<void(std::function<void()>)>;
    using SendFn = std::function<void(void*, std::string_view)>;

    WSAsyncReplyDispatcher(DeferFn defer_fn, SendFn send_fn);
    ~WSAsyncReplyDispatcher();

    WSAsyncReplyDispatcher(const WSAsyncReplyDispatcher&) = delete;
    WSAsyncReplyDispatcher& operator=(const WSAsyncReplyDispatcher&) = delete;

    void reset();
    void stop();

    /// Returns true after stop() has been called.
    bool is_stopping() const { return stopping_.load(); }

    ConnectionToken register_connection(void* socket);
    void unregister_connection(void* socket);
    [[nodiscard]] ConnectionToken token_for(void* socket) const;
    [[nodiscard]] bool is_current(const ConnectionToken& token) const;

    [[nodiscard]] bool dispatch(ConnectionToken token,
                                std::function<std::string()> build_response);

private:
    void reap_finished_workers_locked();

    DeferFn defer_fn_;
    SendFn send_fn_;
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> next_generation_{1};

    mutable std::mutex connections_mutex_;
    std::unordered_map<void*, uint64_t> connections_;

    std::mutex workers_mutex_;
    std::vector<std::future<void>> workers_;
};

}  // namespace tenet

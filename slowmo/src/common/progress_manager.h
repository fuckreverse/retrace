#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tenet {

enum class ProgressState : uint8_t {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
};

struct ProgressTask {
    std::string id;
    std::string kind;
    std::string label;
    std::string phase;
    ProgressState state = ProgressState::Pending;
    float progress = 0.0f;
    uint64_t completed = 0;
    uint64_t total = 0;
    std::string message;
    std::string error;
    uint64_t revision = 0;
    std::chrono::system_clock::time_point started_at{};
    std::chrono::system_clock::time_point updated_at{};
};

class ProgressManager {
public:
    using Listener = std::function<void(const ProgressTask&)>;

    class Subscription {
    public:
        Subscription() = default;
        Subscription(const Subscription&) = delete;
        Subscription& operator=(const Subscription&) = delete;
        Subscription(Subscription&& other) noexcept;
        Subscription& operator=(Subscription&& other) noexcept;
        ~Subscription();

        void reset();

    private:
        struct State;
        Subscription(std::weak_ptr<State> state, uint64_t id);

        std::weak_ptr<State> state_;
        uint64_t id_ = 0;
        friend class ProgressManager;
    };

    ProgressManager();

    void start(std::string id, std::string kind, std::string label,
               uint64_t total = 0, std::string phase = {});
    void update(std::string_view id, uint64_t completed,
                std::string_view phase = {}, std::string_view message = {});
    void update(std::string_view id, uint64_t completed, uint64_t total,
                std::string_view phase = {}, std::string_view message = {});
    void update_fraction(std::string_view id, float progress,
                         std::string_view phase = {}, std::string_view message = {});
    void complete(std::string_view id, std::string_view message = {});
    void fail(std::string_view id, std::string_view error);
    void cancel(std::string_view id, std::string_view message = {});
    void erase(std::string_view id);

    std::optional<ProgressTask> get(std::string_view id) const;
    std::vector<ProgressTask> snapshot(std::string_view kind = {}) const;
    Subscription subscribe(Listener listener);

    static ProgressManager& global();
    static const char* state_name(ProgressState state) noexcept;

private:
    std::shared_ptr<Subscription::State> state_;

    template <typename Mutator>
    void mutate(std::string_view id, Mutator&& mutator);
    static void notify(const std::vector<Listener>& listeners, const ProgressTask& task);
};

}  // namespace tenet

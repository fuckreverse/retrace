#include "common/progress_manager.h"

#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace tenet {

struct ProgressManager::Subscription::State {
    mutable std::mutex mutex;
    std::unordered_map<std::string, ProgressTask> tasks;
    std::unordered_map<uint64_t, Listener> listeners;
    uint64_t next_listener_id = 1;
    uint64_t next_revision = 1;
};

ProgressManager::Subscription::Subscription(std::weak_ptr<State> state, uint64_t id)
    : state_(std::move(state)), id_(id) {}

ProgressManager::Subscription::Subscription(Subscription&& other) noexcept
    : state_(std::move(other.state_)), id_(std::exchange(other.id_, 0)) {}

ProgressManager::Subscription& ProgressManager::Subscription::operator=(Subscription&& other) noexcept {
    if (this != &other) {
        reset();
        state_ = std::move(other.state_);
        id_ = std::exchange(other.id_, 0);
    }
    return *this;
}

ProgressManager::Subscription::~Subscription() { reset(); }

void ProgressManager::Subscription::reset() {
    if (id_ == 0) return;
    if (auto state = state_.lock()) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->listeners.erase(id_);
    }
    id_ = 0;
    state_.reset();
}

ProgressManager::ProgressManager() : state_(std::make_shared<Subscription::State>()) {}

void ProgressManager::start(std::string id, std::string kind, std::string label,
                            uint64_t total, std::string phase) {
    ProgressTask task;
    task.id = std::move(id);
    task.kind = std::move(kind);
    task.label = std::move(label);
    task.phase = std::move(phase);
    task.state = ProgressState::Running;
    task.total = total;
    task.started_at = std::chrono::system_clock::now();
    task.updated_at = task.started_at;

    std::vector<Listener> listeners;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        task.revision = state_->next_revision++;
        state_->tasks[task.id] = task;
        listeners.reserve(state_->listeners.size());
        for (const auto& [_, listener] : state_->listeners) listeners.push_back(listener);
    }
    notify(listeners, task);
}

template <typename Mutator>
void ProgressManager::mutate(std::string_view id, Mutator&& mutator) {
    ProgressTask task;
    std::vector<Listener> listeners;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        auto it = state_->tasks.find(std::string(id));
        if (it == state_->tasks.end()) return;
        mutator(it->second);
        it->second.updated_at = std::chrono::system_clock::now();
        it->second.revision = state_->next_revision++;
        task = it->second;
        listeners.reserve(state_->listeners.size());
        for (const auto& [_, listener] : state_->listeners) listeners.push_back(listener);
    }
    notify(listeners, task);
}

void ProgressManager::update(std::string_view id, uint64_t completed,
                             std::string_view phase, std::string_view message) {
    mutate(id, [&](ProgressTask& task) {
        task.completed = completed;
        if (task.total != 0) {
            task.progress = std::clamp(static_cast<float>(completed) /
                                       static_cast<float>(task.total), 0.0f, 1.0f);
        }
        if (!phase.empty()) task.phase = phase;
        if (!message.empty()) task.message = message;
    });
}

void ProgressManager::update(std::string_view id, uint64_t completed, uint64_t total,
                             std::string_view phase, std::string_view message) {
    mutate(id, [&](ProgressTask& task) {
        task.completed = completed;
        task.total = total;
        task.progress = total == 0 ? 0.0f : std::clamp(
            static_cast<float>(completed) / static_cast<float>(total), 0.0f, 1.0f);
        if (!phase.empty()) task.phase = phase;
        if (!message.empty()) task.message = message;
    });
}

void ProgressManager::update_fraction(std::string_view id, float progress,
                                      std::string_view phase, std::string_view message) {
    mutate(id, [&](ProgressTask& task) {
        task.progress = std::clamp(progress, 0.0f, 1.0f);
        if (task.total != 0) {
            task.completed = static_cast<uint64_t>(task.progress * static_cast<float>(task.total));
        }
        if (!phase.empty()) task.phase = phase;
        if (!message.empty()) task.message = message;
    });
}

void ProgressManager::complete(std::string_view id, std::string_view message) {
    mutate(id, [&](ProgressTask& task) {
        task.state = ProgressState::Completed;
        task.progress = 1.0f;
        if (task.total != 0) task.completed = task.total;
        if (!message.empty()) task.message = message;
        task.error.clear();
    });
}

void ProgressManager::fail(std::string_view id, std::string_view error) {
    mutate(id, [&](ProgressTask& task) {
        task.state = ProgressState::Failed;
        task.error = std::string(error);
    });
}

void ProgressManager::cancel(std::string_view id, std::string_view message) {
    mutate(id, [&](ProgressTask& task) {
        task.state = ProgressState::Cancelled;
        if (!message.empty()) task.message = message;
    });
}

void ProgressManager::erase(std::string_view id) {
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->tasks.erase(std::string(id));
}

void ProgressManager::erase_kind(std::string_view kind) {
    std::lock_guard<std::mutex> lock(state_->mutex);
    for (auto it = state_->tasks.begin(); it != state_->tasks.end();) {
        if (it->second.kind == kind) it = state_->tasks.erase(it);
        else ++it;
    }
}

std::optional<ProgressTask> ProgressManager::get(std::string_view id) const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    auto it = state_->tasks.find(std::string(id));
    if (it == state_->tasks.end()) return std::nullopt;
    return it->second;
}

std::vector<ProgressTask> ProgressManager::snapshot(std::string_view kind) const {
    std::vector<ProgressTask> result;
    std::lock_guard<std::mutex> lock(state_->mutex);
    result.reserve(state_->tasks.size());
    for (const auto& [_, task] : state_->tasks) {
        if (kind.empty() || task.kind == kind) result.push_back(task);
    }
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.revision < rhs.revision;
    });
    return result;
}

ProgressManager::Subscription ProgressManager::subscribe(Listener listener) {
    std::lock_guard<std::mutex> lock(state_->mutex);
    const uint64_t id = state_->next_listener_id++;
    state_->listeners.emplace(id, std::move(listener));
    return Subscription(state_, id);
}

ProgressManager& ProgressManager::global() {
    static ProgressManager manager;
    return manager;
}

const char* ProgressManager::state_name(ProgressState state) noexcept {
    switch (state) {
    case ProgressState::Pending: return "pending";
    case ProgressState::Running: return "running";
    case ProgressState::Completed: return "completed";
    case ProgressState::Failed: return "failed";
    case ProgressState::Cancelled: return "cancelled";
    }
    return "unknown";
}

void ProgressManager::notify(const std::vector<Listener>& listeners, const ProgressTask& task) {
    for (const auto& listener : listeners) {
        if (!listener) continue;
        try {
            listener(task);
        } catch (...) {
            // Progress observers are frontends/diagnostics. Their failure must
            // never abort the backend operation that emitted the update.
        }
    }
}

}  // namespace tenet

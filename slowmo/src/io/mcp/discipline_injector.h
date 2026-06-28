#pragma once

#include <string>
#include <mutex>

#include <nlohmann/json.hpp>

namespace tenet {

// ─── Discipline Injector ─────────────────────────────────────────────────
//
// Periodic rule reinjection to combat LLM drift during long sessions.

class DisciplineInjector {
public:
    explicit DisciplineInjector(int short_interval = 5, int full_interval = 20);

    /// Called after each tool call. Returns a discipline message (or empty).
    std::string on_tool_call(const std::string& tool_name);

    void reset();
    nlohmann::json stats() const;

private:
    int short_interval_;
    int full_interval_;
    mutable std::mutex mutex_;  // protects call_count_ and reminder_index_
    int call_count_ = 0;
    int reminder_index_ = 0;

    static const char* full_rules();
    static const char* short_reminder(int index);
    static constexpr int kNumReminders = 5;
};

}  // namespace tenet

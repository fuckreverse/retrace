#pragma once

#include <ftxui/component/event.hpp>

#include <functional>
#include <string_view>
#include <vector>

namespace tenet {

/// A single key binding entry: maps a key (Event) to an action.
/// Condition is checked first — if it returns false, the binding is skipped.
struct KeyBinding {
    ftxui::Event key;
    std::function<bool()> action;        // returns true if event was consumed
    std::function<bool()> condition;     // nullptr = always active
    std::string_view description;        // for help text generation
};

/// Registry of key bindings for the TUI normal mode.
/// Bindings are evaluated in insertion order; first match wins.
class KeyBindingRegistry {
public:
    /// Add a binding that is always active.
    void bind(ftxui::Event key, std::function<bool()> action,
              std::string_view description = {}) {
        entries_.push_back({key, std::move(action), nullptr, description});
    }

    /// Add a binding that is only active when condition returns true.
    void bind_if(ftxui::Event key, std::function<bool()> condition,
                 std::function<bool()> action,
                 std::string_view description = {}) {
        entries_.push_back({key, std::move(action), std::move(condition), description});
    }

    /// Try to dispatch an event. Returns true if consumed.
    bool dispatch(const ftxui::Event& event) const {
        for (const auto& entry : entries_) {
            if (entry.key != event) continue;
            if (entry.condition && !entry.condition()) continue;
            return entry.action();
        }
        return false;
    }

    /// Access all entries (for help text generation).
    const std::vector<KeyBinding>& entries() const { return entries_; }

private:
    std::vector<KeyBinding> entries_;
};

}  // namespace tenet

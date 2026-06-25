#pragma once

#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <string_view>

namespace tenet {

/// Abstract base class for TUI panels.
///
/// Each panel owns its own state (cursor, filter, focus) and communicates with
/// the rest of the app through TuiContext (forward-declared, injected at
/// construction). Panels are rendered in a registry loop by TuiApp.
class Panel {
public:
    virtual ~Panel() = default;

    /// Unique identifier for this panel (e.g. "registers", "callstack").
    virtual std::string_view id() const = 0;

    /// Human-readable title shown in panel header.
    virtual std::string_view title() const = 0;

    /// Whether the panel should currently be rendered.
    virtual bool visible() const = 0;

    /// Toggle visibility (called from key bindings).
    virtual void set_visible(bool v) = 0;

    /// Whether this panel currently holds input focus.
    bool focused() const { return focused_; }
    void set_focused(bool f) { focused_ = f; }

    /// Render the panel's FTXUI Element.
    virtual ftxui::Element render() = 0;

    /// Try to handle an event. Returns true if consumed.
    /// Only called when the panel is visible AND focused.
    virtual bool handle_event(ftxui::Event event) { (void)event; return false; }

protected:
    bool focused_ = false;
};

}  // namespace tenet

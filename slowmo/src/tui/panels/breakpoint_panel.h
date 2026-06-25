#pragma once

#include "tui/panel.h"
#include "tui/tui_context.h"
#include <cstddef>

namespace tenet {

class BreakpointEngine;

/// Breakpoint panel — lists all registered breakpoints and allows
/// navigating, jumping to, and deleting them.
class BreakpointPanel final : public Panel {
public:
    BreakpointPanel(TuiContext& ctx, BreakpointEngine* engine)
        : ctx_(ctx), engine_(engine) {}

    std::string_view id() const override { return "breakpoints"; }
    std::string_view title() const override { return "Breakpoints"; }

    bool visible() const override { return visible_; }
    void set_visible(bool v) override { visible_ = v; }

    ftxui::Element render() override;
    bool handle_event(ftxui::Event event) override;

private:
    TuiContext& ctx_;
    BreakpointEngine* engine_;
    bool visible_ = false;
    size_t cursor_ = 0;
};

}  // namespace tenet

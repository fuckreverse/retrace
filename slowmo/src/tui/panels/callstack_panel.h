#pragma once

#include "tui/panel.h"
#include "tui/tui_context.h"
#include <cstddef>

namespace tenet {

/// Call stack panel — shows the active call stack at the current instruction
/// and allows navigating between frames.
class CallstackPanel final : public Panel {
public:
    explicit CallstackPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id() const override { return "callstack"; }
    std::string_view title() const override { return "Call Stack"; }

    bool visible() const override { return visible_; }
    void set_visible(bool v) override { visible_ = v; }

    ftxui::Element render() override;
    bool handle_event(ftxui::Event event) override;

private:
    TuiContext& ctx_;
    bool visible_ = false;
    size_t cursor_ = 0;
};

}  // namespace tenet

#pragma once

#include "tui/panel.h"

#include <cstddef>

namespace tenet {

struct TuiContext;

/// Panel that displays thread information: thread list, active thread,
/// switch events, and navigation to thread switches / first instructions.
class ThreadPanel final : public Panel {
public:
    explicit ThreadPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id()    const override { return "threads"; }
    std::string_view title() const override { return "Threads"; }

    bool visible()           const override { return visible_; }
    void set_visible(bool v)       override { visible_ = v; }

    ftxui::Element render()                    override;
    bool           handle_event(ftxui::Event event) override;

private:
    void goto_next_thread_switch();
    void goto_prev_thread_switch();

    TuiContext& ctx_;
    bool   visible_ = false;
    size_t cursor_  = 0;
};

}  // namespace tenet

#pragma once

#include "tui/panel.h"

namespace tenet {

struct TuiContext;

/// Panel displaying AArch64 GPR (and optionally NEON FPR) register state
/// at the current instruction, with read/write colouring.
class RegisterPanel : public Panel {
public:
    explicit RegisterPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id()    const override { return "registers"; }
    std::string_view title() const override { return "Registers"; }
    bool visible()           const override { return visible_; }
    void set_visible(bool v)       override { visible_ = v; }

    ftxui::Element render() override;
    bool handle_event(ftxui::Event event) override;

private:
    TuiContext& ctx_;
    bool visible_ = true;
};

}  // namespace tenet

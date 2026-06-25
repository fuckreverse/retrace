#pragma once

#include "tui/panel.h"
#include "tui/tui_context.h"

#include <cstddef>

namespace tenet {

/// Memory access panel.
///
/// Displays the memory accesses (reads and writes) performed by the current
/// instruction. When focused, the user can move a cursor up/down to select an
/// individual access and press Enter to jump to the instruction that last
/// wrote the selected address (via MemoryModel::last_writer).
class MemoryPanel : public Panel {
public:
    explicit MemoryPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id() const override { return "memory"; }
    std::string_view title() const override { return "Memory Accesses"; }
    bool visible() const override { return visible_; }
    void set_visible(bool v) override { visible_ = v; }

    ftxui::Element render() override;
    bool handle_event(ftxui::Event event) override;

private:
    TuiContext& ctx_;

    /// Index of the currently highlighted memory access entry.
    size_t access_cursor_ = 0;

    bool visible_ = true;
};

}  // namespace tenet

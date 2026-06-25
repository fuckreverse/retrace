#pragma once

#include "tui/panel.h"

#include <cstddef>
#include <string>
#include <vector>

namespace tenet {

struct TuiContext;

/// Panel that displays discovered strings from the string pass.
/// Supports cursor navigation, filtering, and jumping to the instruction
/// that first discovered the selected string.
class StringsPanel final : public Panel {
public:
    explicit StringsPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id()    const override { return "strings"; }
    std::string_view title() const override { return "Strings"; }

    bool visible()           const override { return visible_; }
    void set_visible(bool v)       override { visible_ = v; }

    ftxui::Element render()                        override;
    bool           handle_event(ftxui::Event event) override;

    /// Apply the current filter string (called externally after dialog input).
    void set_filter(const std::string& f) { filter_ = f; update_filter(); cursor_ = 0; }

    /// Clear the filter and show all strings.
    void clear_filter() { filter_.clear(); update_filter(); cursor_ = 0; }

private:
    void update_filter();

    TuiContext& ctx_;
    bool visible_ = false;
    size_t cursor_ = 0;
    std::string filter_;
    std::vector<size_t> filtered_indices_;
};

}  // namespace tenet

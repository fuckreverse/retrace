#pragma once

#include "tui/panel.h"
#include "tui/tui_context.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tenet {

/// Functions panel — lists all discovered functions with sorting and filtering.
/// Allows jumping to a function's first call site.
class FunctionsPanel final : public Panel {
public:
    explicit FunctionsPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id() const override { return "functions"; }
    std::string_view title() const override { return "Functions"; }

    bool visible() const override { return visible_; }
    void set_visible(bool v) override { visible_ = v; }

    ftxui::Element render() override;
    bool handle_event(ftxui::Event event) override;

    /// Rebuild the sorted PC list and reapply filter.
    /// Call after function_result becomes available or sort mode changes.
    void update_list();

private:
    /// Reapply filter_ to the current sorted_pcs_ list.
    void update_filter();

    TuiContext& ctx_;
    bool visible_ = false;

    size_t cursor_ = 0;
    std::string filter_;
    std::vector<uint64_t> sorted_pcs_;
    std::vector<size_t> filtered_indices_;
    int sort_mode_ = 0;  // 0 = by calls desc, 1 = by name, 2 = by entry_pc
};

}  // namespace tenet

#pragma once

#include "tui/panel.h"
#include "tui/tui_context.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tenet {

/// One row in the drilled-down detail view of a pass result.
/// `jump_inst_id` is only meaningful when `jumpable` is true.
struct ResultEntry {
    std::string text;
    uint64_t jump_inst_id = 0;
    bool jumpable = false;
};

/// Results panel — the TUI counterpart of the GUI "Analysis" panel plus its
/// ~20 dedicated result windows, unified into a single two-level browser:
///
///   Level 0 (catalog view): every pass in tenet::pass_catalog(), showing
///     state (NotRun/Running/Completed/Failed) and a one-line summary via
///     summarize_pass_result(). Enter runs the pass (if NotRun/Failed) or
///     drills into its detail view (if Completed).
///
///   Level 1 (detail view): a scrollable list of ResultEntry rows produced
///     by build_result_entries() for the selected pass. Enter on a jumpable
///     row navigates the instruction cursor there. Escape returns to the
///     catalog view.
///
/// This gives every catalog pass a real result browser in the TUI instead of
/// the previous single-line last_pass_status_ summary, without requiring a
/// bespoke panel class per pass (which the GUI can afford via ~20 floating
/// ImGui windows, but a terminal UI cannot).
class ResultsPanel final : public Panel {
public:
    explicit ResultsPanel(TuiContext& ctx) : ctx_(ctx) {}

    std::string_view id() const override { return "results"; }
    std::string_view title() const override { return "Analysis Results"; }

    bool visible() const override { return visible_; }
    void set_visible(bool v) override { visible_ = v; }

    ftxui::Element render() override;
    bool handle_event(ftxui::Event event) override;

    /// Force the panel open and drill straight into `pass_name`'s detail
    /// view (used by ":pass <name>" and other pass triggers so the result
    /// is immediately visible instead of requiring a manual navigate step).
    void focus_pass(std::string_view pass_name);

private:
    TuiContext& ctx_;
    bool visible_ = false;

    // ─── Level 0: catalog cursor ────────────────────────────────────────
    size_t catalog_cursor_ = 0;

    // ─── Level 1: detail view state ─────────────────────────────────────
    bool in_detail_ = false;
    std::string detail_pass_name_;
    std::vector<ResultEntry> detail_entries_;
    size_t detail_cursor_ = 0;

    void enter_detail(std::string_view pass_name);
    void leave_detail();
    void rebuild_detail_entries();

    ftxui::Element render_catalog();
    ftxui::Element render_detail();
};

/// Build the flat list of navigable/inspectable entries for a completed
/// pass's result. Returns an empty vector for passes with no structured
/// per-item breakdown (the catalog summary line is all there is) or when
/// the pass hasn't completed successfully yet.
std::vector<ResultEntry> build_result_entries(const TuiContext& ctx, std::string_view pass_name);

}  // namespace tenet

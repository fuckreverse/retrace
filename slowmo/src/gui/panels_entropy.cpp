// panels_entropy.cpp — Shannon entropy analysis panel.
//
// Displays the EntropyResult from EntropyPass: overall entropy + classification,
// per-block entropy table, and optional timeline curve.
//
// When no result is available, shows an inline address/size input form
// (similar to the VM hints input pattern) so the user can trigger entropy
// analysis on any memory region.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/memory/entropy_pass.h"
#include "analysis/pass_registry.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cmath>
#include <cstring>
#include <vector>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

static const char* classification_name(EntropyResult::Classification cls) {
    switch (cls) {
        case EntropyResult::Unknown:    return "Unknown";
        case EntropyResult::Plaintext:  return "Plaintext";
        case EntropyResult::Compressed: return "Compressed";
        case EntropyResult::Encrypted:  return "Encrypted";
        case EntropyResult::KeyMaterial: return "KeyMaterial";
        default:                        return "?";
    }
}

static ImVec4 classification_color(EntropyResult::Classification cls) {
    switch (cls) {
        case EntropyResult::Plaintext:  return ImVec4(0.4f, 0.9f, 0.4f, 1.0f);  // green
        case EntropyResult::Compressed: return ImVec4(1.0f, 0.85f, 0.3f, 1.0f);  // yellow
        case EntropyResult::Encrypted:  return ImVec4(1.0f, 0.35f, 0.35f, 1.0f); // red
        case EntropyResult::KeyMaterial:return ImVec4(0.6f, 0.6f, 1.0f, 1.0f);   // blue
        default:                        return ImVec4(0.6f, 0.6f, 0.6f, 1.0f);   // grey
    }
}

static ImVec4 entropy_color(float entropy) {
    // Gradient: green (0.0) → yellow (4.0) → orange (6.0) → red (8.0)
    if (entropy < 4.0f)
        return ImVec4(0.4f + entropy / 4.0f * 0.6f, 0.9f, 0.4f, 1.0f);
    if (entropy < 6.0f) {
        float t = (entropy - 4.0f) / 2.0f;
        return ImVec4(1.0f, 0.9f - t * 0.3f, 0.4f - t * 0.4f, 1.0f);
    }
    float t = (entropy - 6.0f) / 2.0f;
    return ImVec4(1.0f, 0.6f - t * 0.25f, 0.0f, 1.0f);
}

// ---------------------------------------------------------------------------
// Run helper — invalidates old result and runs entropy with current input
// ---------------------------------------------------------------------------

void GuiApp::run_entropy_with_addr() {
    ensure_pass_manager();

    uint64_t addr = 0;
    try { addr = std::stoull(entropy_addr_buf_, nullptr, 16); } catch (...) {}

    // Build a custom EntropyConfig directly (bypassing pass_registry) because
    // compute_timeline is not exposed in PassRunCtx.
    EntropyConfig cfg;
    cfg.addr             = addr;
    cfg.size             = entropy_size_input_;
    cfg.at_inst_id       = current_inst_;
    cfg.compute_timeline = entropy_timeline_input_;

    // Invalidate any previous entropy result so the new one replaces it.
    // invalidate_and_clear_blob() resets state to NotRun, which allows
    // register_pass() to replace the pass object with the new config.
    if (pass_manager_->state("entropy") != PassManager::PassState::NotRun) {
        pass_manager_->invalidate_and_clear_blob("entropy");
    }

    // Register (or replace) with our custom config.
    pass_manager_->register_pass(std::make_unique<EntropyPass>(std::move(cfg)));

    // Clear the GUI-side result pointer so the "no result" view doesn't
    // flash the stale data while the new analysis is in-flight.
    entropy_result_ = nullptr;

    std::string name_str = "entropy";
    enqueue_async(name_str, [this, name_str]() {
        auto& raw = pass_manager_->require(name_str);
        std::string summary = tenet::summarize_pass_result(name_str, raw);
        bool ok = raw.ok();
        post_apply([this, name_str, summary, ok]() {
            last_pass_status_ = fmt::format("{}: {}", name_str, summary);
            if (ok) apply_pass_result_pointers(name_str);
        });
    });
}

// ---------------------------------------------------------------------------
// Panel renderer
// ---------------------------------------------------------------------------

void GuiApp::render_entropy_panel() {
    if (!ImGui::Begin("Entropy", &show_entropy_)) {
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── No result yet — show inline address/size input ────────────────────
    if (!entropy_result_) {
        ImGui::TextDisabled("Shannon Entropy Analysis");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Computes Shannon entropy of a memory region at a given point\n"
            "in the trace. High entropy (7.5+) suggests ciphertext; low\n"
            "entropy (<4.0) suggests plaintext.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Address input (hex)
        ImGui::AlignTextToFramePadding();
        ImGui::Text("Address:");
        ImGui::SameLine();
        ImGui::PushItemWidth(panel_w * 0.55f);
        bool addr_entered = ImGui::InputText("##ent_addr", entropy_addr_buf_,
            sizeof(entropy_addr_buf_),
            ImGuiInputTextFlags_CharsHexadecimal |
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();
        ImGui::SameLine(0, 4);
        if (ImGui::SmallButton("From Mem##ent")) {
            // Use the current memory context address (from hex dump / memory panel)
            if (ctx_mem_addr_ != 0) {
                snprintf(entropy_addr_buf_, sizeof(entropy_addr_buf_),
                         "%llx", (unsigned long long)ctx_mem_addr_);
            }
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Use the address from the Memory / Hex Dump panel");

        // Size input
        ImGui::AlignTextToFramePadding();
        ImGui::Text("Size:   ");
        ImGui::SameLine();
        ImGui::PushItemWidth(panel_w * 0.3f);
        ImGui::InputScalar("##ent_size", ImGuiDataType_U32, &entropy_size_input_);
        ImGui::PopItemWidth();

        // Timeline checkbox
        ImGui::Checkbox("Compute timeline", &entropy_timeline_input_);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Sample entropy at multiple points in time\n"
                              "to detect encryption boundaries");

        ImGui::Spacing();

        // Run button
        bool has_addr = (entropy_addr_buf_[0] != '\0');
        if (!has_addr) {
            ImGui::BeginDisabled();
        }
        if (ImGui::Button(ICON_FA_CHART_BAR " Run Entropy Analysis") || (addr_entered && has_addr)) {
            run_entropy_with_addr();
        }
        if (!has_addr) {
            ImGui::EndDisabled();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Compute Shannon entropy of the specified memory region");

        ImGui::End();
        return;
    }

    // ── Result available ──────────────────────────────────────────────────

    // ── Summary header ────────────────────────────────────────────────────
    const char* cls_name = classification_name(entropy_result_->classification);
    ImVec4 cls_color = classification_color(entropy_result_->classification);

    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_CHART_BAR "  Entropy: %.3f", entropy_result_->overall_entropy);
    ImGui::SameLine();
    ImGui::TextColored(cls_color, "[%s]", cls_name);
    ImGui::SameLine();
    ImGui::TextDisabled("(0x%llx, %u bytes, %u known)",
        (unsigned long long)entropy_result_->addr,
        entropy_result_->region_size,
        entropy_result_->known_bytes);

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        // Pre-fill the previous address before clearing the pointer
        uint64_t prev_addr = entropy_result_->addr;
        snprintf(entropy_addr_buf_, sizeof(entropy_addr_buf_),
                 "%llx", (unsigned long long)prev_addr);
        entropy_size_input_ = entropy_result_->region_size;
        entropy_result_ = nullptr;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run entropy analysis with different parameters");

    ImGui::Separator();

    // ── Per-block entropy table ───────────────────────────────────────────
    if (!entropy_result_->blocks.empty()) {
        ImGui::Text("Per-block entropy (block size = %u bytes):",
            entropy_result_->blocks.empty() ? 0u :
                entropy_result_->blocks[0].size);
        ImGui::Spacing();

        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y * 0.45f);
        if (ImGui::BeginTable("EntBlocksTable", 4,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Size",    ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Entropy", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Bar",     ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(entropy_result_->blocks.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const EntropyBlock& b = entropy_result_->blocks[static_cast<size_t>(row)];
                    ImGui::TableNextRow();

                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextDisabled("0x%llx", (unsigned long long)b.offset);

                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%u", b.size);

                    ImGui::TableSetColumnIndex(2);
                    ImVec4 ecolor = entropy_color(b.entropy);
                    ImGui::TextColored(ecolor, "%.3f", b.entropy);

                    ImGui::TableSetColumnIndex(3);
                    // Mini bar graph
                    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ecolor);
                    char bar_label[32];
                    snprintf(bar_label, sizeof(bar_label), "##eb%d", row);
                    ImGui::ProgressBar(b.entropy / 8.0f, ImVec2(-1, 0), bar_label);
                    ImGui::PopStyleColor();
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    // ── Transitions ───────────────────────────────────────────────────────
    if (!entropy_result_->transitions.empty()) {
        ImGui::Separator();
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f),
            ICON_FA_BOLT " %zu transition%s detected",
            entropy_result_->transitions.size(),
            entropy_result_->transitions.size() == 1 ? "" : "s");
        for (const auto& tr : entropy_result_->transitions) {
            ImGui::TextDisabled("  inst #%llu: %.2f -> %.2f (%+.2f)",
                (unsigned long long)tr.inst_id,
                tr.entropy_before, tr.entropy_after, tr.delta);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Click to navigate");
            }
            if (ImGui::IsItemClicked()) {
                navigate_to(tr.inst_id);
            }
        }
    }

    // ── Timeline curve ────────────────────────────────────────────────────
    if (!entropy_result_->timeline.empty()) {
        ImGui::Separator();
        ImGui::Text("Entropy Timeline");
        ImGui::Spacing();

        // Build float array for PlotLines
        std::vector<float> values;
        values.reserve(entropy_result_->timeline.size());
        for (const auto& te : entropy_result_->timeline) {
            values.push_back(te.overall_entropy);
        }

        // Draw the timeline as a plot
        ImVec2 plot_size(panel_w - 20.0f, 120.0f);
        ImGui::PushStyleColor(ImGuiCol_PlotLines, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_PlotLinesHovered, ImVec4(1.0f, 1.0f, 0.4f, 1.0f));
        ImGui::PlotLines("##ent_timeline", values.data(), static_cast<int>(values.size()),
            0, nullptr, 0.0f, 8.0f, plot_size);
        ImGui::PopStyleColor(2);

        // Hover tooltip: show inst_id + entropy
        if (ImGui::IsItemHovered() && !entropy_result_->timeline.empty()) {
            ImGui::BeginTooltip();
            // Map mouse X to sample index
            ImVec2 rect_min = ImGui::GetItemRectMin();
            ImVec2 rect_max = ImGui::GetItemRectMax();
            float t = (ImGui::GetMousePos().x - rect_min.x) / (rect_max.x - rect_min.x);
            int idx = static_cast<int>(t * static_cast<float>(entropy_result_->timeline.size() - 1));
            idx = std::clamp(idx, 0, static_cast<int>(entropy_result_->timeline.size()) - 1);
            const auto& te = entropy_result_->timeline[static_cast<size_t>(idx)];
            ImGui::Text("inst #%llu  entropy: %.3f  known: %u",
                (unsigned long long)te.inst_id, te.overall_entropy, te.known_bytes);
            if (ImGui::IsMouseClicked(0)) {
                navigate_to(te.inst_id);
            }
            ImGui::EndTooltip();
        }

        // Label the axes
        ImGui::TextDisabled("%.0f", 0.0f);
        ImGui::SameLine(plot_size.x + 20.0f);
        ImGui::TextDisabled("%.0f", 8.0f);
    }

    ImGui::End();
}

}  // namespace tenet

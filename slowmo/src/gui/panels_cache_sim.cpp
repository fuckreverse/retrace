// panels_cache_sim.cpp — Cache simulation / side-channel analysis panel.
//
// Displays the CacheSimResult from CacheSimPass in four views:
//   0. Overview:       Per-level miss-rate progress bars + global summary.
//   1. Functions:      Per-function cache stats sorted by L1D miss count.
//   2. Side Channels:  Timing side-channel candidates with CV and reason.
//   3. Hot Lines:      Hottest cache lines by miss count.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/cache_sim_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <string>
#include <vector>
#include <algorithm>

namespace tenet {

// ── helpers ────────────────────────────────────────────────────────────────

/// Map a miss rate [0,1] to a colour: green → yellow → red.
static ImVec4 miss_rate_color(double rate) {
    auto r = static_cast<float>(rate);
    if (r < 0.05f) return ImVec4(0.35f, 0.85f, 0.35f, 1.0f);  // green  (< 5%)
    if (r < 0.20f) return ImVec4(1.0f,  0.82f, 0.2f,  1.0f);  // yellow (5–20%)
    return             ImVec4(1.0f,  0.35f, 0.25f, 1.0f);      // red    (≥ 20%)
}

/// Map a CV value to a colour: low CV = grey, high CV = red.
static ImVec4 cv_color(double cv) {
    auto c = static_cast<float>(cv);
    if (c < 0.10f) return ImVec4(0.55f, 0.55f, 0.55f, 1.0f);  // grey   (< 10%)
    if (c < 0.30f) return ImVec4(1.0f,  0.82f, 0.2f,  1.0f);  // yellow (10–30%)
    return             ImVec4(1.0f,  0.35f, 0.25f, 1.0f);      // red    (≥ 30%)
}

/// Format a large integer as "1.23M", "456K", or plain number.
static std::string fmt_count(uint64_t n) {
    if (n >= 1'000'000ULL)
        return fmt::format("{:.2f}M", static_cast<double>(n) / 1e6);
    if (n >= 1'000ULL)
        return fmt::format("{:.1f}K", static_cast<double>(n) / 1e3);
    return fmt::format("{}", n);
}

// ── panel ──────────────────────────────────────────────────────────────────

void GuiApp::render_cache_sim_panel() {
    if (!ImGui::Begin("Cache Sim", &show_cache_sim_)) {
        ImGui::End();
        return;
    }

    // ── No result yet ──────────────────────────────────────────────────────
    if (!cache_sim_result_) {
        ImGui::TextDisabled("No cache simulation performed.");
        ImGui::Spacing();
        if (ImGui::Button("Run Cache Sim")) {
            run_pass_by_name("cache_sim");
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Simulate cache behaviour across the trace.\n"
                "Computes per-level hit/miss rates, identifies timing\n"
                "side-channel candidates (high CV), and hot cache lines.");
        }
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Summary header ─────────────────────────────────────────────────────
    double omr = cache_sim_result_->overall_miss_rate();
    ImGui::TextColored(miss_rate_color(omr),
        "\xf0\x9f\x97\x84  Overall miss rate: %.1f%%  |  %s instructions",
        omr * 100.0,
        fmt_count(cache_sim_result_->total_instructions).c_str());

    // Side-channel warning badge
    if (!cache_sim_result_->sidechannels.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.1f, 1.0f),
            "  \xe2\x9a\xa0  %zu side-channel(s)",   // ⚠
            cache_sim_result_->sidechannels.size());
    }

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton("\xe2\x86\xba Rerun")) {   // ↺
        run_pass_by_name("cache_sim");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run cache simulation (clears current results)");

    ImGui::Separator();

    // ── View mode toggle ───────────────────────────────────────────────────
    ImGui::RadioButton("Overview",      &cache_sim_view_mode_, 0); ImGui::SameLine();
    ImGui::RadioButton("Functions",     &cache_sim_view_mode_, 1); ImGui::SameLine();
    ImGui::RadioButton("Side Channels", &cache_sim_view_mode_, 2); ImGui::SameLine();
    ImGui::RadioButton("Hot Lines",     &cache_sim_view_mode_, 3);

    ImGui::Separator();

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 0: Overview
    // ══════════════════════════════════════════════════════════════════════
    if (cache_sim_view_mode_ == 0) {

        // Per-level miss-rate bars
        for (const auto& lvl : cache_sim_result_->level_stats) {
            double mr = lvl.miss_rate();
            ImVec4 bar_col = miss_rate_color(mr);

            // Label line: "L1D: 15.3% miss rate (1.23M misses / 8.10M total)"
            ImGui::TextColored(ImVec4(0.75f, 0.92f, 1.0f, 1.0f),
                "%s", lvl.name.c_str());
            ImGui::SameLine(55.0f);
            ImGui::TextColored(bar_col, "%.1f%% miss", mr * 100.0);
            ImGui::SameLine();
            ImGui::TextDisabled("(%s misses / %s total)",
                fmt_count(lvl.misses).c_str(),
                fmt_count(lvl.total_accesses).c_str());

            // Coloured progress bar for miss rate
            char bar_id[32];
            snprintf(bar_id, sizeof(bar_id), "##missbar_%s", lvl.name.c_str());
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_col);
            ImGui::ProgressBar(static_cast<float>(mr),
                ImVec2(panel_w * 0.6f, 0.0f), "");
            ImGui::PopStyleColor();

            // Hit rate on same line
            ImGui::SameLine();
            ImGui::TextDisabled("%.1f%% hit", lvl.hit_rate() * 100.0);

            ImGui::Spacing();
        }

        ImGui::Separator();

        // Total instructions
        ImGui::TextDisabled("Total instructions traced: %s",
            fmt_count(cache_sim_result_->total_instructions).c_str());

        ImGui::Spacing();

        // Summary text
        std::string sum = cache_sim_result_->summary();
        if (!sum.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.8f, 1.0f));
            ImGui::TextWrapped("%s", sum.c_str());
            ImGui::PopStyleColor();
        }

        // Side-channel highlight
        if (!cache_sim_result_->sidechannels.empty()) {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.1f, 1.0f),
                "\xe2\x9a\xa0  %zu timing side-channel candidate(s) detected!",
                cache_sim_result_->sidechannels.size());
            ImGui::TextDisabled("  Switch to \"Side Channels\" view for details.");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 1: Functions (sorted by mean L1D misses, descending)
    // ══════════════════════════════════════════════════════════════════════
    else if (cache_sim_view_mode_ == 1) {

        // Build sorted index (descending mean L1D misses)
        std::vector<size_t> order;
        order.reserve(cache_sim_result_->function_stats.size());
        for (size_t i = 0; i < cache_sim_result_->function_stats.size(); ++i)
            order.push_back(i);
        std::sort(order.begin(), order.end(),
            [&](size_t a, size_t b) {
                return cache_sim_result_->function_stats[a].mean_l1d_misses() >
                       cache_sim_result_->function_stats[b].mean_l1d_misses();
            });

        ImGui::TextDisabled("%zu functions", order.size());
        ImGui::Separator();

        const float row_h  = ImGui::GetTextLineHeightWithSpacing();
        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

        if (ImGui::BeginTable("CacheSimFuncTable", 4,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Function",   ImGuiTableColumnFlags_WidthStretch, 0.42f);
            ImGui::TableSetupColumn("Calls",      ImGuiTableColumnFlags_WidthFixed,  60.0f);
            ImGui::TableSetupColumn("Avg Misses", ImGuiTableColumnFlags_WidthFixed,  90.0f);
            ImGui::TableSetupColumn("CV",         ImGuiTableColumnFlags_WidthFixed,  70.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(order.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const auto& fs =
                        cache_sim_result_->function_stats[order[static_cast<size_t>(row)]];
                    double cv  = fs.cv_l1d_misses();
                    double avg = fs.mean_l1d_misses();

                    ImGui::TableNextRow();

                    // Function name / PC column (selectable → navigate)
                    ImGui::TableSetColumnIndex(0);
                    char sel_id[128];
                    snprintf(sel_id, sizeof(sel_id), "%s##csfn%d",
                             fs.name.empty()
                                 ? fmt::format("0x{:x}", fs.entry_pc).c_str()
                                 : fs.name.c_str(),
                             row);
                    bool selected = false;
                    if (ImGui::Selectable(sel_id, selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        navigate_to(fs.entry_pc);
                    }
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip(
                            "PC: 0x%llx\nCalls: %llu\nMin misses: %llu\n"
                            "Max misses: %llu\nCV: %.2f%%",
                            (unsigned long long)fs.entry_pc,
                            (unsigned long long)fs.total_calls,
                            (unsigned long long)fs.min_l1d_misses(),
                            (unsigned long long)fs.max_l1d_misses(),
                            cv * 100.0);
                    }

                    // Calls column
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextDisabled("%llu", (unsigned long long)fs.total_calls);

                    // Avg misses column
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextColored(miss_rate_color(avg / 1000.0),
                        "%s", fmt_count(static_cast<uint64_t>(avg)).c_str());

                    // CV column — high CV highlighted red
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextColored(cv_color(cv), "%.1f%%", cv * 100.0);
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 2: Side Channels
    // ══════════════════════════════════════════════════════════════════════
    else if (cache_sim_view_mode_ == 2) {

        if (cache_sim_result_->sidechannels.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.35f, 1.0f),
                "\xe2\x9c\x93  No timing side-channels detected");   // ✓
            ImGui::TextDisabled("  All functions show low variation in cache miss counts.");
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.1f, 1.0f),
                "\xe2\x9a\xa0  %zu candidate(s)",
                cache_sim_result_->sidechannels.size());
            ImGui::Separator();

            const float row_h  = ImGui::GetTextLineHeightWithSpacing();
            ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

            if (ImGui::BeginTable("CacheSimSCTable", 3,
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_SizingStretchProp,
                    table_size)) {

                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch, 0.40f);
                ImGui::TableSetupColumn("CV",       ImGuiTableColumnFlags_WidthFixed,  70.0f);
                ImGui::TableSetupColumn("Reason",   ImGuiTableColumnFlags_WidthStretch, 0.60f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(
                    static_cast<int>(cache_sim_result_->sidechannels.size()));

                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const auto& sc =
                            cache_sim_result_->sidechannels[static_cast<size_t>(row)];

                        ImGui::TableNextRow();

                        // Function column — ⚠ icon + name
                        ImGui::TableSetColumnIndex(0);
                        char sel_id[128];
                        snprintf(sel_id, sizeof(sel_id),
                            "\xe2\x9a\xa0 %s##cssc%d",   // ⚠
                            sc.function_name.empty()
                                ? fmt::format("0x{:x}", sc.entry_pc).c_str()
                                : sc.function_name.c_str(),
                            row);
                        bool selected = false;
                        if (ImGui::Selectable(sel_id, selected,
                                ImGuiSelectableFlags_SpanAllColumns)) {
                            navigate_to(sc.entry_pc);
                        }
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip(
                                "PC: 0x%llx\nCalls: %llu\n"
                                "Min misses: %llu  Max misses: %llu\nCV: %.2f%%",
                                (unsigned long long)sc.entry_pc,
                                (unsigned long long)sc.total_calls,
                                (unsigned long long)sc.min_misses,
                                (unsigned long long)sc.max_misses,
                                sc.cv * 100.0);
                        }

                        // CV column — red gradient
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextColored(cv_color(sc.cv), "%.1f%%", sc.cv * 100.0);

                        // Reason column
                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextDisabled("%s", sc.reason.c_str());
                    }
                }
                clipper.End();
                ImGui::EndTable();
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // VIEW 3: Hot Lines
    // ══════════════════════════════════════════════════════════════════════
    else {

        ImGui::TextDisabled("%zu hot cache lines",
            cache_sim_result_->hottest_lines.size());
        ImGui::Separator();

        const float row_h  = ImGui::GetTextLineHeightWithSpacing();
        ImVec2 table_size(0.0f, ImGui::GetContentRegionAvail().y - row_h * 0.3f);

        if (ImGui::BeginTable("CacheSimHotTable", 3,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp,
                table_size)) {

            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Addr",     ImGuiTableColumnFlags_WidthFixed,  120.0f);
            ImGui::TableSetupColumn("Misses",   ImGuiTableColumnFlags_WidthFixed,   90.0f);
            ImGui::TableSetupColumn("Hit Rate", ImGuiTableColumnFlags_WidthStretch, 0.50f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(
                static_cast<int>(cache_sim_result_->hottest_lines.size()));

            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    const auto& hl =
                        cache_sim_result_->hottest_lines[static_cast<size_t>(row)];
                    uint64_t total  = hl.hits + hl.misses;
                    double   hr     = total ? static_cast<double>(hl.hits) / total : 0.0;

                    ImGui::TableNextRow();

                    // Addr column — hoverable tooltip (no navigate: not an inst_id)
                    ImGui::TableSetColumnIndex(0);
                    char addr_label[48];
                    snprintf(addr_label, sizeof(addr_label),
                             "0x%llx##cshl%d", (unsigned long long)hl.addr, row);
                    ImGui::Selectable(addr_label, false,
                        ImGuiSelectableFlags_SpanAllColumns);
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip(
                            "Cache line base: 0x%llx\n"
                            "Hits: %s  Misses: %s\n"
                            "Hit rate: %.1f%%",
                            (unsigned long long)hl.addr,
                            fmt_count(hl.hits).c_str(),
                            fmt_count(hl.misses).c_str(),
                            hr * 100.0);
                    }

                    // Misses column
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextColored(miss_rate_color(1.0 - hr),
                        "%s", fmt_count(hl.misses).c_str());

                    // Hit Rate column — coloured progress bar
                    ImGui::TableSetColumnIndex(2);
                    ImVec4 bar_col = miss_rate_color(1.0 - hr);
                    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_col);
                    char bar_ov[32];
                    snprintf(bar_ov, sizeof(bar_ov), "%.1f%%", hr * 100.0);
                    ImGui::ProgressBar(static_cast<float>(hr),
                        ImVec2(-1.0f, 0.0f), bar_ov);
                    ImGui::PopStyleColor();
                }
            }
            clipper.End();
            ImGui::EndTable();
        }
    }

    ImGui::End();
}

}  // namespace tenet

// panels_cache_manager.cpp — Pass-cache management panel.
//
// Displays a table of all persisted pass-result blobs in the RocksDB index
// (name, disk size, in-memory state) and provides per-entry and global
// management actions (delete blob, force re-run).
//
// Accessible via:  View > Cache Manager  (or keyboard shortcut planned later)

#include "gui/gui_app.h"
#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"

#include <imgui.h>
#include <fmt/core.h>

#include <algorithm>
#include <numeric>
#include <string>
#include <vector>

#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ─── Size formatting helper ──────────────────────────────────────────────────

namespace {

/// Format byte size as a compact human-readable string.
/// e.g. 1234 → "1.2 KB",  2097152 → "2.0 MB"
std::string format_size(size_t bytes) {
    if (bytes < 1024)
        return fmt::format("{} B", bytes);
    if (bytes < 1024 * 1024)
        return fmt::format("{:.1f} KB", static_cast<double>(bytes) / 1024.0);
    if (bytes < 1024 * 1024 * 1024)
        return fmt::format("{:.1f} MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    return fmt::format("{:.2f} GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
}

/// Return a human-readable state label.
const char* state_label(PassManager::PassState s) {
    switch (s) {
        case PassManager::PassState::NotRun:   return "not run";
        case PassManager::PassState::Running:  return "running";
        case PassManager::PassState::Completed: return "loaded";
        case PassManager::PassState::Failed:   return "failed";
    }
    return "?";
}

/// Return a color for a pass state.
ImVec4 state_color(PassManager::PassState s, bool in_memory) {
    switch (s) {
        case PassManager::PassState::Completed:
            return in_memory ? ImVec4(0.35f, 0.90f, 0.45f, 1.0f)   // green: in memory
                             : ImVec4(0.45f, 0.60f, 0.80f, 1.0f);  // blue: only on disk
        case PassManager::PassState::Running:
            return ImVec4(1.0f, 0.85f, 0.20f, 1.0f);   // yellow
        case PassManager::PassState::Failed:
            return ImVec4(0.90f, 0.35f, 0.35f, 1.0f);  // red
        case PassManager::PassState::NotRun:
        default:
            return ImVec4(0.45f, 0.60f, 0.80f, 1.0f);  // muted blue: cached on disk only
    }
}

}  // anonymous namespace

// ─── Cache Manager Panel ─────────────────────────────────────────────────────

void GuiApp::render_cache_manager_panel() {
    if (!show_cache_manager_) return;

    ImGui::SetNextWindowSize(ImVec2(620, 480), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Cache Manager", &show_cache_manager_,
                      ImGuiWindowFlags_NoCollapse)) {
        ImGui::End();
        return;
    }

    const float panel_w = ImGui::GetContentRegionAvail().x;
    ImDrawList* draw    = ImGui::GetWindowDrawList();

    // ── Header: summary + global actions ────────────────────────────────
    {
        ImVec2 hdr_p0 = ImGui::GetCursorScreenPos();
        float  hdr_h  = ImGui::GetFrameHeightWithSpacing() * 2.0f + 6.0f;
        draw->AddRectFilled(hdr_p0,
            ImVec2(hdr_p0.x + panel_w, hdr_p0.y + hdr_h),
            IM_COL32(20, 30, 50, 120));

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8.0f);
        ImGui::TextColored(ImVec4(0.55f, 0.80f, 1.0f, 1.0f),
            ICON_FA_DATABASE "  Pass Cache Manager");  // ▤ U+25A4 (was 🗄 U+1F5C4 emoji)

        // Reload button (refresh cache info list)
        ImGui::SameLine(panel_w - 120.0f);
        if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_RIGHT " Refresh")) {  // ↻
            cache_manager_dirty_ = true;
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Reload cache information from RocksDB");

        // Summary line
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8.0f);
        size_t total_bytes = 0;
        for (const auto& e : cache_manager_entries_)
            total_bytes += e.blob_size;

        ImGui::TextDisabled("  %zu entries  ·  %s total disk usage",
            cache_manager_entries_.size(), format_size(total_bytes).c_str());

        ImGui::Dummy(ImVec2(0, 4.0f));
    }

    // ── Refresh cache info if dirty ──────────────────────────────────────
    if (cache_manager_dirty_) {
        cache_manager_dirty_ = false;
        if (pass_manager_) {
            cache_manager_entries_ = pass_manager_->query_blob_info();
            // Sort by blob_size descending so largest caches appear first.
            std::sort(cache_manager_entries_.begin(), cache_manager_entries_.end(),
                [](const auto& a, const auto& b) { return a.blob_size > b.blob_size; });
        }
    }

    // ── Global action buttons ────────────────────────────────────────────
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f, 4.0f));

    bool any_entries = !cache_manager_entries_.empty();

    if (!any_entries) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.10f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.60f, 0.15f, 0.15f, 1.0f));
    if (ImGui::Button("  " ICON_FA_XMARK "  Delete All Caches  ")) {  // ✕
        if (pass_manager_) {
            size_t n = pass_manager_->clear_all_blobs();
            cache_manager_entries_.clear();
            cache_manager_status_ = fmt::format("Deleted {} cache blob(s).", n);
        }
    }
    ImGui::PopStyleColor(3);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip(
            "Delete all persisted pass blobs from the RocksDB index.\n"
            "Each pass will fully re-run (without a disk shortcut) the next\n"
            "time it is required.  In-memory results are NOT cleared.");
    if (!any_entries) ImGui::EndDisabled();

    ImGui::SameLine(0, 8.0f);

    // Invalidate All: wipes both in-memory AND disk, like pressing Clear All
    // in the Analysis panel, but only for passes that have disk blobs.
    if (!any_entries) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.20f, 0.05f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.28f, 0.07f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.60f, 0.36f, 0.10f, 1.0f));
    if (ImGui::Button("  " ICON_FA_ARROW_ROTATE_LEFT "  Invalidate All  ")) {  // ↺
        if (pass_manager_) {
            // Invalidate in-memory result AND delete blob for each cached pass.
            for (const auto& e : cache_manager_entries_) {
                pass_manager_->invalidate_and_clear_blob(e.name);
            }
            cache_manager_status_ = fmt::format(
                "Invalidated {} pass result(s). They will re-run from scratch next time.",
                cache_manager_entries_.size());
            cache_manager_entries_.clear();
        }
    }
    ImGui::PopStyleColor(3);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip(
            "Invalidate both in-memory results AND disk blobs for all cached passes.\n"
            "Equivalent to 'force re-run' for each pass individually.");
    if (!any_entries) ImGui::EndDisabled();

    ImGui::PopStyleVar();  // FramePadding

    // Status message
    if (!cache_manager_status_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.70f, 0.90f, 0.55f, 1.0f));
        ImGui::TextWrapped("%s", cache_manager_status_.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::Separator();

    // ── Cache entries table ──────────────────────────────────────────────
    // Columns: Status | Pass Name | Disk Size | Memory | Actions
    constexpr ImGuiTableFlags kTableFlags =
        ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_RowBg         | ImGuiTableFlags_Resizable     |
        ImGuiTableFlags_ScrollY       | ImGuiTableFlags_SizingStretchProp;

    float table_h = ImGui::GetContentRegionAvail().y - 4.0f;
    if (ImGui::BeginTable("##cache_tbl", 5, kTableFlags,
                          ImVec2(panel_w, table_h))) {
        ImGui::TableSetupScrollFreeze(0, 1);  // freeze header row
        ImGui::TableSetupColumn("##state",  ImGuiTableColumnFlags_WidthFixed,  18.0f);
        ImGui::TableSetupColumn("Pass",     ImGuiTableColumnFlags_WidthStretch, 2.0f);
        ImGui::TableSetupColumn("Disk",     ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Memory",   ImGuiTableColumnFlags_WidthFixed,  72.0f);
        ImGui::TableSetupColumn("Actions",  ImGuiTableColumnFlags_WidthFixed,  80.0f);
        ImGui::TableHeadersRow();

        if (cache_manager_entries_.empty()) {
            // No cached blobs — show a hint.
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("(no cached pass blobs)");
            ImGui::TableSetColumnIndex(2);
            ImGui::TableSetColumnIndex(3);
            ImGui::TableSetColumnIndex(4);
        }

        // Track pending deletions (don't mutate while iterating).
        std::string pending_delete;
        std::string pending_invalidate;

        for (size_t i = 0; i < cache_manager_entries_.size(); ++i) {
            auto& e = cache_manager_entries_[i];

            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(i));

            // ── Column 0: State dot ──────────────────────────────────────
            ImGui::TableSetColumnIndex(0);
            {
                ImVec4 col = state_color(e.state, e.in_memory);
                const char* dot = e.in_memory
                    ? ICON_FA_CIRCLE   // ◉ (filled circle: in memory)
                    : "\xe2\x97\x8b";  // ○ (empty circle: disk only)
                ImGui::TextColored(col, "%s", dot);
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("State: %s\n%s",
                        state_label(e.state),
                        e.in_memory ? "Result is loaded in memory"
                                    : "Only persisted on disk (not yet loaded)");
                }
            }

            // ── Column 1: Pass name ──────────────────────────────────────
            ImGui::TableSetColumnIndex(1);
            {
                // Look up display name from catalog (falls back to raw name).
                std::string_view display = e.name;
                if (auto* cat = tenet::find_pass_catalog_entry(e.name))
                    display = cat->display_name;

                ImVec4 name_col = state_color(e.state, e.in_memory);
                ImGui::TextColored(name_col, "%s", std::string(display).c_str());
                if (ImGui::IsItemHovered() && display != e.name) {
                    ImGui::SetTooltip("pass key: %s", e.name.c_str());
                }
            }

            // ── Column 2: Disk size ──────────────────────────────────────
            ImGui::TableSetColumnIndex(2);
            {
                // Draw a subtle fill bar proportional to the largest entry.
                size_t max_size = 1;
                for (const auto& x : cache_manager_entries_)
                    if (x.blob_size > max_size) max_size = x.blob_size;

                float frac = static_cast<float>(e.blob_size) /
                             static_cast<float>(max_size);

                ImVec2 p0 = ImGui::GetCursorScreenPos();
                float cell_w = ImGui::GetContentRegionAvail().x;
                float cell_h = ImGui::GetFrameHeight();
                // Background fill bar
                draw->AddRectFilled(p0,
                    ImVec2(p0.x + cell_w * frac, p0.y + cell_h),
                    IM_COL32(40, 70, 120, 80));

                ImGui::TextUnformatted(format_size(e.blob_size).c_str());
            }

            // ── Column 3: Memory state ───────────────────────────────────
            ImGui::TableSetColumnIndex(3);
            if (e.in_memory) {
                ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f), "✓ loaded");
            } else {
                ImGui::TextDisabled("—");
            }

            // ── Column 4: Action buttons ─────────────────────────────────
            ImGui::TableSetColumnIndex(4);
            {
                // [↺] Force re-run (invalidate both disk + memory)
                if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT "##inv")) {  // ↺
                    pending_invalidate = e.name;
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Invalidate: delete disk blob + in-memory result\n"
                                      "Pass will re-run from scratch next time");

                ImGui::SameLine(0, 4.0f);

                // [✕] Delete blob only (keep in-memory result if present)
                ImGui::PushStyleColor(ImGuiCol_Button,
                    ImVec4(0.30f, 0.08f, 0.08f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                    ImVec4(0.50f, 0.12f, 0.12f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                    ImVec4(0.65f, 0.16f, 0.16f, 1.0f));
                if (ImGui::SmallButton(ICON_FA_XMARK "##del")) {  // ✕
                    pending_delete = e.name;
                }
                ImGui::PopStyleColor(3);
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Delete disk blob only\n"
                                      "In-memory result (if any) is kept");
            }

            ImGui::PopID();
        }  // for each entry

        ImGui::EndTable();

        // Apply pending actions (outside the table iteration loop).
        if (!pending_invalidate.empty()) {
            if (pass_manager_) {
                pass_manager_->invalidate_and_clear_blob(pending_invalidate);
            }
            cache_manager_status_ = fmt::format(
                "Invalidated '{}': disk blob deleted, pass will re-run next time.",
                pending_invalidate);
            cache_manager_dirty_ = true;
        }
        if (!pending_delete.empty()) {
            // Delete only the disk blob; keep the in-memory result as-is.
            index_.delete_pass_blob(pending_delete);
            cache_manager_status_ = fmt::format(
                "Deleted disk blob for '{}'. In-memory result (if any) is unchanged.",
                pending_delete);
            cache_manager_dirty_ = true;
        }
    }  // BeginTable

    ImGui::End();
}

}  // namespace tenet

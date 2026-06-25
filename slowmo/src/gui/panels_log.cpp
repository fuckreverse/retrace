// panels_log.cpp — IDA-style Output / Log panel
//
// Displays log messages (from LOG_INFO/LOG_DEBUG/LOG_WARN/LOG_ERROR macros
// and external events like MCP status) in a scrollable, filterable panel
// at the bottom of the GUI.  Inspired by IDA Pro's "Output" window.

#include "gui/gui_app.h"
#include "common/logger.h"

#include <imgui.h>
#include <fmt/core.h>

#include <algorithm>
#include <cctype>

namespace tenet {

// ─── Color helpers for log levels ───────────────────────────────────────────

static ImVec4 log_level_color(int lv) {
    switch (static_cast<log::Level>(lv)) {
        case log::Level::Error: return ImVec4(1.00f, 0.30f, 0.30f, 1.0f);  // red
        case log::Level::Warn:  return ImVec4(1.00f, 0.75f, 0.20f, 1.0f);  // orange
        case log::Level::Info:  return ImVec4(0.40f, 0.80f, 1.00f, 1.0f);  // cyan
        case log::Level::Debug: return ImVec4(0.40f, 0.90f, 0.40f, 1.0f);  // green
        case log::Level::Trace: return ImVec4(0.60f, 0.60f, 0.65f, 1.0f);  // gray
        default:                return ImVec4(0.70f, 0.70f, 0.70f, 1.0f);
    }
}

static const char* log_level_tag(int lv) {
    switch (static_cast<log::Level>(lv)) {
        case log::Level::Error: return "ERROR";
        case log::Level::Warn:  return "WARN ";
        case log::Level::Info:  return "INFO ";
        case log::Level::Debug: return "DEBUG";
        case log::Level::Trace: return "TRACE";
        default:                return "     ";
    }
}

static bool passes_level_filter(int lv, int filter) {
    auto level = static_cast<log::Level>(lv);
    // filter: 0=All, 1=Info+, 2=Warn+, 3=Error only
    switch (filter) {
        case 1: return level <= log::Level::Info;   // Info, Warn, Error (lower = more severe)
        case 2: return level <= log::Level::Warn;   // Warn, Error
        case 3: return level == log::Level::Error;  // Error only
        default: return true;                       // All
    }
}

// ─── Log panel implementation ───────────────────────────────────────────────

void GuiApp::render_log_panel() {
    // Drain new log entries from the ring buffer (thread-safe)
    {
        std::vector<log::LogEntry> raw;
        log::gui_log_drain(raw);
        for (auto& e : raw) {
            log_panel_.entries.push_back({
                static_cast<int>(e.level),
                e.timestamp,
                e.rss_mb,
                std::move(e.message)
            });
        }
    }

    // Cap total entries to prevent unbounded growth
    constexpr size_t kMaxDisplayEntries = 8192;
    if (log_panel_.entries.size() > kMaxDisplayEntries) {
        log_panel_.entries.erase(
            log_panel_.entries.begin(),
            log_panel_.entries.begin() +
                static_cast<ptrdiff_t>(log_panel_.entries.size() - kMaxDisplayEntries));
    }

    ImGui::Begin("Output", &show_log_);

    // ─── Toolbar row: level filter + text filter + clear + auto-scroll ────
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 2));

        // Level filter combo
        const char* level_labels[] = { "All", "Info+", "Warn+", "Error" };
        ImGui::SetNextItemWidth(70.0f);
        ImGui::Combo("##LogLevel", &log_panel_.level_filter,
                     level_labels, IM_ARRAYSIZE(level_labels));
        ImGui::SameLine();

        // Text filter
        ImGui::SetNextItemWidth(200.0f);
        if (ImGui::InputTextWithHint("##LogFilter", "Filter...",
                log_panel_.filter_buf, sizeof(log_panel_.filter_buf))) {
            log_panel_.filter_text = log_panel_.filter_buf;
        }
        ImGui::SameLine();

        // Clear button
        if (ImGui::Button("Clear")) {
            log_panel_.entries.clear();
        }
        ImGui::SameLine();

        // Auto-scroll toggle
        ImGui::Checkbox("Auto-scroll", &log_panel_.auto_scroll);
        ImGui::SameLine();

        // Entry count
        ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.65f, 1.0f),
            "(%zu entries)", log_panel_.entries.size());

        ImGui::PopStyleVar();
    }

    ImGui::Separator();

    // ─── Scrollable log content ─────────────────────────────────────────
    ImGui::BeginChild("LogContent", ImVec2(0, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);

    bool has_filter = !log_panel_.filter_text.empty();

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 1));

    for (const auto& entry : log_panel_.entries) {
        // Level filter
        if (!passes_level_filter(entry.level, log_panel_.level_filter))
            continue;

        // Text filter (case-insensitive substring match)
        if (has_filter) {
            bool found = false;
            const auto& msg = entry.message;
            const auto& flt = log_panel_.filter_text;
            for (size_t i = 0; i + flt.size() <= msg.size(); ++i) {
                bool match = true;
                for (size_t j = 0; j < flt.size(); ++j) {
                    if (std::tolower(static_cast<unsigned char>(msg[i + j])) !=
                        std::tolower(static_cast<unsigned char>(flt[j]))) {
                        match = false;
                        break;
                    }
                }
                if (match) { found = true; break; }
            }
            if (!found) continue;
        }

        // Timestamp
        ImGui::TextColored(ImVec4(0.40f, 0.42f, 0.50f, 1.0f),
            "[%7.3fs]", entry.timestamp);
        ImGui::SameLine();

        // Level tag
        ImGui::TextColored(log_level_color(entry.level),
            " %s", log_level_tag(entry.level));
        ImGui::SameLine();

        // Message
        ImGui::TextColored(ImVec4(0.82f, 0.84f, 0.88f, 1.0f),
            "  %s", entry.message.c_str());
    }

    ImGui::PopStyleVar();

    // Auto-scroll to bottom when new entries arrive
    if (log_panel_.auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10.0f) {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();
    ImGui::End();
}

}  // namespace tenet

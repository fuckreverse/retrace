// panels_misc.cpp — thread panel, strings panel + its context menu, progress
// overlay (timeline), minimap panel, and status bar.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/function_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace tenet {

// ─── Thread Panel ────────────────────────────────────────────────────────────

void GuiApp::render_thread_panel() {
    if (!ImGui::Begin("Threads", &show_threads_)) {
        ImGui::End();
        return;
    }

    if (!thread_result_) {
        if (ImGui::Button("Run Thread Analysis")) {
            run_pass_by_name("thread");
        }
        ImGui::End();
        return;
    }

    // Summary
    ImGui::Text("Threads: %zu  |  Context Switches: %zu",
        thread_result_->thread_count(), thread_result_->switch_count());
    ImGui::Separator();

    // Active thread at current instruction
    uint64_t cur_tid = thread_result_->thread_at(current_inst_);
    if (cur_tid != 0) {
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f),
            "Active Thread: tid=0x%llx", (unsigned long long)cur_tid);
    } else {
        ImGui::TextDisabled("Active Thread: unknown");
    }

    // Navigation buttons
    if (ImGui::Button("< Prev Switch")) {
        auto* ev = thread_result_->prev_switch_before(current_inst_);
        if (ev) navigate_to(ev->inst_id);
    }
    ImGui::SameLine();
    if (ImGui::Button("Next Switch >")) {
        auto* ev = thread_result_->next_switch_after(current_inst_);
        if (ev) navigate_to(ev->inst_id);
    }

    ImGui::Separator();

    // Thread list table
    if (ImGui::BeginTable("ThreadTable", 4,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Thread ID", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Instructions", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Switches", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Range", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& [tid, info] : thread_result_->threads) {
            ImGui::TableNextRow();
            bool is_active = (tid == cur_tid);

            // Thread ID
            ImGui::TableNextColumn();
            char label[64];
            snprintf(label, sizeof(label), "0x%llx", (unsigned long long)tid);
            if (is_active) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", label);
            } else {
                ImGui::Text("%s", label);
            }
            // Double-click to jump to first instruction of this thread
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                navigate_to(info.first_seen_inst);
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Double-click to jump to first instruction of this thread");
            }

            // Instructions
            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)info.total_instructions);

            // Switch count
            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)info.switch_in_count);

            // Range
            ImGui::TableNextColumn();
            ImGui::TextDisabled("#%llu - #%llu",
                (unsigned long long)info.first_seen_inst,
                (unsigned long long)info.last_seen_inst);
        }
        ImGui::EndTable();
    }

    // Spans section (collapsible)
    ImGui::Separator();
    if (ImGui::CollapsingHeader("Execution Spans", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Total spans: %zu", thread_result_->spans.size());
        // Show spans around current instruction
        auto* cur_span = thread_result_->span_at(current_inst_);
        if (cur_span) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f),
                "Current span: tid=0x%llx [#%llu - #%llu] (%llu insts)",
                (unsigned long long)cur_span->thread_id,
                (unsigned long long)cur_span->start_inst_id,
                (unsigned long long)cur_span->end_inst_id,
                (unsigned long long)cur_span->inst_count);
        }
    }

    ImGui::End();
}

// ─── Strings Panel ──────────────────────────────────────────────────────────

void GuiApp::render_strings_panel() {
    if (!ImGui::Begin("Strings", &show_strings_)) {
        ImGui::End();
        return;
    }

    // Header with count
    if (string_result_) {
        ImGui::Text("Discovered: %zu strings", string_result_->total());
    } else {
        ImGui::TextDisabled("No string analysis performed.");
        if (ImGui::Button("Run String Analysis")) {
            run_pass_by_name("strings");
        }
        ImGui::End();
        return;
    }

    // Filter input
    ImGui::Separator();
    bool filter_changed = ImGui::InputText("Filter", string_filter_buf_, sizeof(string_filter_buf_));
    if (filter_changed) {
        string_filter_ = std::string(string_filter_buf_);
        string_cursor_ = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        string_filter_.clear();
        std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
        string_cursor_ = 0;
    }
    ImGui::SameLine();
    // Length range filter (inclusive). Default [MIN_STRING_LEN, MAX_STRING_LEN]
    // means no filtering; adjusting either bound narrows the list.
    ImGui::PushItemWidth(180);
    if (ImGui::DragIntRange2("Len", &string_min_len_, &string_max_len_,
            1.0f,
            static_cast<int>(StringResult::MIN_STRING_LEN),
            static_cast<int>(StringResult::MAX_STRING_LEN),
            "%d", "%d")) {
        string_cursor_ = 0;
    }
    ImGui::PopItemWidth();

    ImGui::Separator();

    // Get filtered strings
    // 1) text filter (substring search) → candidate list
    // 2) length filter [string_min_len_, string_max_len_] (inclusive)
    std::vector<const StringRef*> display_strings;
    if (string_filter_.empty()) {
        display_strings.reserve(string_result_->strings.size());
        for (const auto& s : string_result_->strings) {
            display_strings.push_back(&s);
        }
    } else {
        display_strings = string_result_->search(string_filter_);
    }

    // Apply length filter (inclusive bounds)
    auto len_ok = [this](const StringRef* s) {
        auto len = static_cast<int>(s->content.size());
        return len >= string_min_len_ && len <= string_max_len_;
    };
    if (string_min_len_ > static_cast<int>(StringResult::MIN_STRING_LEN) ||
        string_max_len_ < static_cast<int>(StringResult::MAX_STRING_LEN)) {
        display_strings.erase(
            std::remove_if(display_strings.begin(), display_strings.end(),
                           [&](const StringRef* s) { return !len_ok(s); }),
            display_strings.end());
    }

    ImGui::Text("Showing: %zu", display_strings.size());
    ImGui::Separator();

    // Table with string list
    if (ImGui::BeginTable("StringsTable", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Addr", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Enc", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Content", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Refs", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(display_strings.size()));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                const StringRef* ref = display_strings[i];
                bool is_selected = (static_cast<size_t>(i) == string_cursor_);

                ImGui::TableNextRow();

                // Address column
                ImGui::TableSetColumnIndex(0);
                char label[64];
                snprintf(label, sizeof(label), "0x%llx##str%d",
                         (unsigned long long)ref->addr, i);
                if (ImGui::Selectable(label, is_selected,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    string_cursor_ = static_cast<size_t>(i);
                    // Jump to the instruction that discovered this string
                    navigate_to(ref->discovered_at);
                }
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format("\"{}\"\nDiscovered at inst #{}\nRight-click for options",
                        ref->content, ref->discovered_at);
                    ImGui::SetTooltip("%s", tip.c_str());
                    if (ImGui::IsMouseDoubleClicked(0)) {
                        navigate_to(ref->discovered_at);
                    }
                }
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ctx_string_inst_id_ = ref->discovered_at;
                    ctx_string_text_    = ref->content;
                    ImGui::TextDisabled("\"%s\"", ctx_string_text_.c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("Jump to Discovery")) {
                        navigate_to(ctx_string_inst_id_);
                    }
                    if (ImGui::MenuItem("Copy String")) {
                        ImGui::SetClipboardText(ctx_string_text_.c_str());
                    }
                    ImGui::EndPopup();
                }

                // Encoding column
                ImGui::TableSetColumnIndex(1);
                const char* enc_str = "A";
                if (ref->encoding == StringRef::UTF16LE) enc_str = "U16";
                else if (ref->encoding == StringRef::UTF8) enc_str = "U8";
                else if (ref->encoding == StringRef::Wide) enc_str = "W";
                ImGui::TextUnformatted(enc_str);

                // Length column (content size in bytes)
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(std::to_string(ref->content.size()).c_str());

                // Content column
                ImGui::TableSetColumnIndex(3);
                // Truncate for display
                std::string display = ref->content;
                if (display.size() > 64) {
                    display = display.substr(0, 61) + "...";
                }
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "\"%s\"",
                                   display.c_str());

                // References count column
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%zu", ref->references.size());
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    // String panel right-click menu
    render_string_context_menu();

    ImGui::End();
}

// ─── String Panel Context Menu ────────────────────────────────────────────────

void GuiApp::render_string_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_string_panel().

    if (ImGui::BeginPopup("##str_ctx")) {
        ImGui::TextDisabled("\"%s\"", ctx_string_text_.c_str());
        ImGui::Separator();

        if (ImGui::MenuItem("Jump to Discovery")) {
            navigate_to(ctx_string_inst_id_);
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Copy String")) {
            ImGui::SetClipboardText(ctx_string_text_.c_str());
        }

        if (ImGui::MenuItem("Search for This String")) {
            // Put the string into the search buffer and trigger search
            strncpy(search_buf_, ctx_string_text_.c_str(), sizeof(search_buf_) - 1);
            search_buf_[sizeof(search_buf_) - 1] = '\0';
            // Run search
            std::string query(search_buf_);
            search_results_.clear();
            search_current_ = 0;
            search_active_ = false;
            if (!query.empty()) {
                for (uint64_t i = 0; i < total_inst_ && i < 1000000; i++) {
                    auto row = fetch_row(i);
                    if (row.disasm.find(query) != std::string::npos) {
                        search_results_.push_back(i);
                    }
                }
                if (!search_results_.empty()) {
                    search_active_ = true;
                    navigate_to(search_results_[0]);
                }
            }
        }

        ImGui::Separator();

        if (xref_result_) {
            // Show xrefs for the instruction that found this string
            auto row = fetch_row(ctx_string_inst_id_);
            auto xrefs = xref_result_->inst_ids_at(row.pc);
            if (!xrefs.empty()) {
                if (ImGui::BeginMenu("Xrefs (Discovery PC)")) {
                    size_t limit = std::min(xrefs.size(), size_t(10));
                    for (size_t xi = 0; xi < limit; xi++) {
                        char lbl[48];
                        snprintf(lbl, sizeof(lbl), "  inst #%llu", (unsigned long long)xrefs[xi]);
                        if (ImGui::MenuItem(lbl)) {
                            navigate_to(xrefs[xi]);
                        }
                    }
                    ImGui::EndMenu();
                }
            }
        }

        ImGui::EndPopup();
    }
}

// ─── Progress Overlay / Timeline ──────────────────────────────────────────────
// Multi-lane execution timeline with:
//  - Lane 0 (top):    execution density heatmap (hot=bright, cold=dark)
//  - Lane 1 (mid-top): taint / backward-taint overlays
//  - Lane 2 (mid-bot): call-depth sparkline (function call stack depth over time)
//  - Lane 3 (bottom): bookmarks, loop headers, search hits, current cursor
//  - Memory-access activity markers (orange) for a watched address
//  - Click + drag to seek; hover tooltip with full disasm preview

void GuiApp::render_progress_overlay() {
    if (total_inst_ == 0) return;

    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float bar_height = 32.0f;   // taller: 4 lanes + depth sparkline
    const float bar_y = vp->WorkPos.y + ImGui::GetFrameHeight() * 2.2f;
    ImVec2 bar_pos(vp->WorkPos.x, bar_y);
    ImVec2 bar_size(vp->WorkSize.x, bar_height);

    ImGui::SetNextWindowPos(bar_pos);
    ImGui::SetNextWindowSize(bar_size);
    ImGui::SetNextWindowBgAlpha(0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoDecoration;

    if (!ImGui::Begin("##Timeline", nullptr, flags)) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetWindowPos();
    float W = ImGui::GetWindowWidth();
    float H = bar_height;

    // ── Track background ─────────────────────────────────────────────
    draw->AddRectFilled(p0, ImVec2(p0.x + W, p0.y + H), IM_COL32(15, 17, 24, 240));
    draw->AddLine(p0, ImVec2(p0.x + W, p0.y), IM_COL32(60, 70, 110, 80), 1.0f);

    // ── Lane layout ──────────────────────────────────────────────────
    // Lane 0: heatmap background         [0,         H*0.30)
    // Lane 1: taint overlays             [H*0.30,    H*0.52)
    // Lane 2: call-depth sparkline       [H*0.52,    H*0.80)
    // Lane 3: markers + cursor fill      [H*0.80,    H)
    const float L0_top = 0.0f;
    const float L0_bot = H * 0.30f;
    const float L1_top = H * 0.30f;
    const float L1_bot = H * 0.52f;
    const float L2_top = H * 0.52f;
    const float L2_bot = H * 0.80f;
    const float L3_top = H * 0.80f;

    // ── Helper: inst_id → x ──────────────────────────────────────────
    auto inst_to_x = [&](uint64_t id) -> float {
        return p0.x + static_cast<float>(id) / static_cast<float>(total_inst_) * W;
    };

    // ── LANE 0: Execution density heatmap ─────────────────────────────
    // Sample the execution frequency per pixel column using xref exec counts.
    // The heatmap is cached because it's derived from xref_result_ (static
    // once xref completes) — re-iterating the roaring bitmap every frame
    // would freeze the UI on large traces (tens of millions of inst_ids).
    {
        const int kPixels = static_cast<int>(W);
        if (kPixels > 0 && xref_result_) {
            // Rebuild cache if xref result changed or total_inst changed
            // or pixel count changed (window resize).
            bool need_rebuild = false;
            if (heatmap_cache_.source != xref_result_) need_rebuild = true;
            if (heatmap_cache_.total_inst != static_cast<float>(total_inst_)) need_rebuild = true;
            if (static_cast<int>(heatmap_cache_.pixels.size()) != kPixels * 4) need_rebuild = true;

            if (need_rebuild) {
                heatmap_cache_.source = xref_result_;
                heatmap_cache_.total_inst = static_cast<float>(total_inst_);
                heatmap_cache_.pixels.assign(kPixels * 4, 0);

                // Find max exec count for normalization
                uint64_t max_count = 1;
                for (const auto& [pc, cnt] : xref_result_->pc_exec_count) {
                    if (cnt > max_count) max_count = cnt;
                }
                // Accumulate per-pixel max
                std::vector<uint64_t> pixel_max(kPixels, 0);
                for (const auto& [pc, cnt] : xref_result_->pc_exec_count) {
                    auto inst_ids = xref_result_->inst_ids_at(pc);
                    for (uint64_t id : inst_ids) {
                        int px = static_cast<int>(
                            static_cast<float>(id) / static_cast<float>(total_inst_) * static_cast<float>(kPixels));
                        if (px >= 0 && px < kPixels) {
                            if (cnt > pixel_max[px]) pixel_max[px] = cnt;
                        }
                    }
                }
                // Pre-compute RGBA colors
                for (int px = 0; px < kPixels; px++) {
                    if (pixel_max[px] == 0) continue;
                    float heat = std::min(1.0f, static_cast<float>(pixel_max[px]) /
                                               static_cast<float>(max_count));
                    uint8_t r, g, b;
                    if (heat < 0.33f) {
                        float t = heat / 0.33f;
                        r = static_cast<uint8_t>(18 + t * (26 - 18));
                        g = static_cast<uint8_t>(22 + t * (95 - 22));
                        b = static_cast<uint8_t>(28 + t * (138 - 28));
                    } else if (heat < 0.67f) {
                        float t = (heat - 0.33f) / 0.34f;
                        r = static_cast<uint8_t>(26 + t * (34 - 26));
                        g = static_cast<uint8_t>(95 + t * (197 - 95));
                        b = static_cast<uint8_t>(138 + t * (255 - 138));
                    } else {
                        float t = (heat - 0.67f) / 0.33f;
                        r = static_cast<uint8_t>(34  + t * (255 - 34));
                        g = static_cast<uint8_t>(197 + t * (255 - 197));
                        b = 255;
                    }
                    uint8_t alpha = static_cast<uint8_t>(80 + heat * 155);
                    heatmap_cache_.pixels[px * 4 + 0] = r;
                    heatmap_cache_.pixels[px * 4 + 1] = g;
                    heatmap_cache_.pixels[px * 4 + 2] = b;
                    heatmap_cache_.pixels[px * 4 + 3] = alpha;
                }
            }

            // Draw from cache
            for (int px = 0; px < kPixels; px++) {
                uint8_t a = heatmap_cache_.pixels[px * 4 + 3];
                if (a == 0) continue;
                uint8_t r = heatmap_cache_.pixels[px * 4 + 0];
                uint8_t g = heatmap_cache_.pixels[px * 4 + 1];
                uint8_t b = heatmap_cache_.pixels[px * 4 + 2];
                float fx = p0.x + static_cast<float>(px);
                draw->AddLine(ImVec2(fx, p0.y + L0_top),
                              ImVec2(fx, p0.y + L0_bot),
                              IM_COL32(r, g, b, a), 1.0f);
            }
        } else if (!xref_result_) {
            // Fallback: simple progress fill when xref is not available
            float progress = (total_inst_ > 1)
                ? static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1)
                : 0.0f;
            float fill_x = p0.x + progress * W;
            draw->AddRectFilledMultiColor(
                p0, ImVec2(fill_x, p0.y + L0_bot),
                IM_COL32(32, 60, 115, 120), IM_COL32(42, 85, 155, 150),
                IM_COL32(42, 85, 155, 150), IM_COL32(32, 60, 115, 120));
        }
    }

    // Subtle separator between heatmap and taint lanes
    draw->AddLine(ImVec2(p0.x, p0.y + L0_bot),
                  ImVec2(p0.x + W, p0.y + L0_bot),
                  IM_COL32(40, 45, 65, 100), 1.0f);

    // ── LANE 1: Taint overlays ────────────────────────────────────────
    if (show_taint_ && taint_result_ && !taint_sorted_ids_.empty()) {
        const size_t kMax = 3000;
        size_t step = std::max(size_t(1), taint_sorted_ids_.size() / kMax);
        for (size_t ti = 0; ti < taint_sorted_ids_.size(); ti += step) {
            float tx = inst_to_x(taint_sorted_ids_[ti]);
            draw->AddLine(ImVec2(tx, p0.y + L1_top),
                          ImVec2(tx, p0.y + L1_bot),
                          IM_COL32(42, 195, 82, 180), 1.0f);
        }
    }
    if (show_backward_taint_ && backward_taint_result_) {
        size_t shown = 0;
        for (uint64_t id = 0; id < total_inst_ && shown < 3000; id++) {
            if (backward_taint_result_->is_contributing(id)) {
                float tx = inst_to_x(id);
                draw->AddLine(ImVec2(tx, p0.y + L1_top),
                              ImVec2(tx, p0.y + L1_bot),
                              IM_COL32(215, 55, 55, 180), 1.0f);
                shown++;
            }
        }
    }

    // ── Memory-access activity for watched address (orange) ───────────
    // If ctx_mem_addr_ is set, mark all accesses to that address in timeline
    if (timeline_watch_addr_ != 0) {
        auto writes = memory_.write_history(timeline_watch_addr_, 1);
        for (uint64_t wid : writes) {
            float wx = inst_to_x(wid);
            draw->AddLine(ImVec2(wx, p0.y + L1_top),
                          ImVec2(wx, p0.y + L1_bot),
                          IM_COL32(255, 140, 30, 200), 1.5f);
        }
    }

    // ── LANE 2: Call-depth sparkline ──────────────────────────────────
    // Show function call stack depth as a filled area chart.
    // The sparkline data is pre-computed and cached in sparkline_cache_ to
    // avoid calling call_stack_at() ~600 times per frame (each O(N) scan).
    if (function_result_ && !function_result_->call_events.empty()) {
        // ── Rebuild cache if stale ────────────────────────────────────
        if (sparkline_cache_.source != function_result_ ||
            sparkline_cache_.total_inst != total_inst_) {
            const int kSamples = std::min(static_cast<int>(W), 600);
            uint64_t sample_step = std::max(uint64_t(1),
                total_inst_ / static_cast<uint64_t>(kSamples));

            sparkline_cache_.depths.resize(static_cast<size_t>(kSamples + 1));
            sparkline_cache_.max_depth = 1;

            for (int si = 0; si <= kSamples; si++) {
                uint64_t sample_id = static_cast<uint64_t>(si) * sample_step;
                if (sample_id >= total_inst_) sample_id = total_inst_ - 1;
                // depth_at is O(log N) via binary search on depth_table_
                uint64_t d = function_result_->depth_at(sample_id);
                sparkline_cache_.depths[static_cast<size_t>(si)] = d;
                if (d > sparkline_cache_.max_depth) sparkline_cache_.max_depth = d;
            }
            if (sparkline_cache_.max_depth > 24) sparkline_cache_.max_depth = 24;

            sparkline_cache_.source     = function_result_;
            sparkline_cache_.total_inst = total_inst_;
        }

        // ── Render from cache ─────────────────────────────────────────
        const int kSamples = static_cast<int>(sparkline_cache_.depths.size()) - 1;
        uint64_t sample_step = std::max(uint64_t(1),
            total_inst_ / static_cast<uint64_t>(kSamples));
        const uint64_t max_depth = sparkline_cache_.max_depth;
        const float sparkline_h = L2_bot - L2_top;

        float prev_x = p0.x, prev_y = p0.y + L2_bot;
        uint64_t prev_depth = 0;
        for (int si = 0; si <= kSamples; si++) {
            uint64_t sample_id = static_cast<uint64_t>(si) * sample_step;
            if (sample_id >= total_inst_) sample_id = total_inst_ - 1;

            uint64_t depth = sparkline_cache_.depths[static_cast<size_t>(si)];
            if (depth > max_depth) depth = max_depth;

            float fx = inst_to_x(sample_id);
            float fy = p0.y + L2_bot - (static_cast<float>(depth) / static_cast<float>(max_depth)) * sparkline_h;

            if (si > 0 && (depth != prev_depth || si == kSamples)) {
                draw->AddRectFilledMultiColor(
                    ImVec2(prev_x, prev_y), ImVec2(fx, p0.y + L2_bot),
                    IM_COL32(40, 100, 200, 60), IM_COL32(40, 100, 200, 60),
                    IM_COL32(40, 100, 200, 20), IM_COL32(40, 100, 200, 20));
                draw->AddLine(ImVec2(prev_x, prev_y), ImVec2(fx, prev_y),
                              IM_COL32(60, 140, 255, 150), 1.0f);
            }
            prev_x = fx;
            prev_y = fy;
            prev_depth = depth;
        }
    }

    // Subtle separator between depth and marker lanes
    draw->AddLine(ImVec2(p0.x, p0.y + L3_top),
                  ImVec2(p0.x + W, p0.y + L3_top),
                  IM_COL32(40, 45, 65, 80), 1.0f);

    // ── LANE 3: Markers (bookmarks, loops, calls, search) ────────────

    // Loop header markers (orange notches)
    if (show_loops_ && loop_result_ && xref_result_) {
        for (const auto& loop : loop_result_->loops) {
            auto inst_ids = xref_result_->inst_ids_at(loop.header_pc);
            if (!inst_ids.empty()) {
                float lx = inst_to_x(inst_ids.front());
                draw->AddRectFilled(
                    ImVec2(lx - 1.0f, p0.y + L3_top),
                    ImVec2(lx + 1.0f, p0.y + H),
                    IM_COL32(255, 138, 24, 200));
            }
        }
    }

    // Call event markers (small blue ticks)
    if (function_result_) {
        const size_t kMaxCalls = 2000;
        size_t call_shown = 0;
        for (const auto& evt : function_result_->call_events) {
            if (call_shown++ >= kMaxCalls) break;
            float cx = inst_to_x(evt.call_inst_id);
            draw->AddLine(
                ImVec2(cx, p0.y + L3_top),
                ImVec2(cx, p0.y + H),
                IM_COL32(60, 145, 255, 100), 1.0f);
        }
    }

    // Search-hit sparks (gold)
    if (search_active_ && !search_results_.empty()) {
        const size_t kMaxHits = 1000;
        size_t step = std::max(size_t(1), search_results_.size() / kMaxHits);
        for (size_t hi = 0; hi < search_results_.size(); hi += step) {
            float hx = inst_to_x(search_results_[hi]);
            draw->AddLine(ImVec2(hx, p0.y),
                          ImVec2(hx, p0.y + H),
                          IM_COL32(255, 200, 30, 180), 1.0f);
        }
    }

    // Bookmark diamonds (in marker lane)
    for (uint64_t bid : bookmarks_) {
        float bx = inst_to_x(bid);
        float cy = p0.y + L3_top + (H - L3_top) * 0.5f;
        float r  = 3.5f;
        draw->AddQuadFilled(
            ImVec2(bx,     cy - r),
            ImVec2(bx + r, cy),
            ImVec2(bx,     cy + r),
            ImVec2(bx - r, cy),
            IM_COL32(255, 205, 45, 235));
        draw->AddQuad(
            ImVec2(bx,     cy - r),
            ImVec2(bx + r, cy),
            ImVec2(bx,     cy + r),
            ImVec2(bx - r, cy),
            IM_COL32(255, 240, 130, 160), 1.0f);
    }

    // ── Current position cursor ───────────────────────────────────────
    float progress = (total_inst_ > 1)
        ? static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1)
        : 0.0f;
    float fill_x = p0.x + progress * W;

    draw->AddLine(ImVec2(fill_x, p0.y), ImVec2(fill_x, p0.y + H),
                  IM_COL32(110, 175, 255, 255), 2.0f);
    draw->AddTriangleFilled(
        ImVec2(fill_x - 4.0f, p0.y),
        ImVec2(fill_x + 4.0f, p0.y),
        ImVec2(fill_x, p0.y + 7.0f),
        IM_COL32(140, 195, 255, 230));

    // ── Bottom separator ─────────────────────────────────────────────
    draw->AddLine(ImVec2(p0.x, p0.y + H - 0.5f),
                  ImVec2(p0.x + W, p0.y + H - 0.5f),
                  IM_COL32(50, 55, 80, 180), 1.0f);

    // ── Interaction: hover tooltip + click/drag to seek ──────────────
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::InvisibleButton("##timeline_btn", ImVec2(W, H),
        ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);

    bool is_hovered = ImGui::IsItemHovered();
    bool is_active  = ImGui::IsItemActive();

    if ((is_active && ImGui::IsMouseDown(ImGuiMouseButton_Left)) || ImGui::IsItemClicked()) {
        float mx = ImGui::GetIO().MousePos.x;
        float rel = (mx - p0.x) / W;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t target = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (target >= total_inst_) target = total_inst_ - 1;
            navigate_to(target);
        }
    }

    // Right-click to watch/unwatch memory address
    if (is_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
        ImGui::OpenPopup("##timeline_ctx");
    }
    if (ImGui::BeginPopup("##timeline_ctx")) {
        ImGui::TextDisabled("Timeline Options");
        ImGui::Separator();
        if (timeline_watch_addr_ != 0) {
            ImGui::TextDisabled("Watching: 0x%llx", (unsigned long long)timeline_watch_addr_);
            if (ImGui::MenuItem("Clear Memory Watch")) {
                timeline_watch_addr_ = 0;
            }
        } else {
            ImGui::TextDisabled("No memory address watched");
        }
        // Show watch from current hex dump address
        if (ctx_mem_addr_ != 0) {
            char lbl[64];
            snprintf(lbl, sizeof(lbl), "Watch 0x%llx in Timeline",
                     (unsigned long long)ctx_mem_addr_);
            if (ImGui::MenuItem(lbl)) {
                timeline_watch_addr_ = ctx_mem_addr_;
            }
        }
        ImGui::EndPopup();
    }

    if (is_hovered) {
        float mx = ImGui::GetIO().MousePos.x;
        float rel = (mx - p0.x) / W;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t hover_id = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (hover_id >= total_inst_) hover_id = total_inst_ - 1;
            auto hover_row = fetch_row(hover_id);

            // Show call depth in tooltip if available
            std::string depth_info;
            if (function_result_) {
                auto stk = function_result_->call_stack_at(hover_id);
                if (!stk.empty()) {
                    depth_info = fmt::format("\nCall depth: {}", stk.size());
                    if (!stk.empty()) {
                        auto* func = function_result_->function_at(hover_id);
                        if (func) depth_info += fmt::format(" ({})", func->name);
                    }
                }
            }

            ImGui::SetTooltip("#%llu  0x%llx\n%s%s\n(left-click/drag: seek | right-click: watch addr)",
                (unsigned long long)hover_id,
                (unsigned long long)hover_row.static_pc,
                hover_row.disasm.c_str(),
                depth_info.c_str());
        }

        // Vertical hover line (dim)
        float mx_screen = ImGui::GetIO().MousePos.x;
        draw->AddLine(ImVec2(mx_screen, p0.y),
                      ImVec2(mx_screen, p0.y + H),
                      IM_COL32(200, 200, 200, 50), 1.0f);
    }

    ImGui::End();
    ImGui::PopStyleVar(2);
}

// ─── Minimap Panel ────────────────────────────────────────────────────────────
// Bird's-eye view of the entire trace. Each pixel row represents a bucket of
// N instructions. Colors encode instruction types and analysis results.
// Clicking navigates to the corresponding instruction.

void GuiApp::render_minimap_panel() {
    ImGuiWindowFlags win_flags = ImGuiWindowFlags_NoScrollbar;
    if (!ImGui::Begin("Minimap", &show_minimap_, win_flags)) {
        ImGui::End();
        return;
    }

    if (total_inst_ == 0) {
        ImGui::TextDisabled("(no trace)");
        ImGui::End();
        return;
    }

    ImVec2 avail = ImGui::GetContentRegionAvail();
    float panel_w = avail.x;
    float panel_h = avail.y;

    // Minimum usable size
    if (panel_w < 10.0f || panel_h < 10.0f) {
        ImGui::End();
        return;
    }

    // Reserve space for the minimap canvas
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##minimap_canvas", ImVec2(panel_w, panel_h));
    bool canvas_hovered = ImGui::IsItemHovered();
    bool canvas_clicked = ImGui::IsItemClicked();

    ImDrawList* draw = ImGui::GetWindowDrawList();

    // Background
    draw->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + panel_w, canvas_pos.y + panel_h),
                        IM_COL32(18, 18, 22, 255));

    // Instructions per pixel row
    int pixel_rows = static_cast<int>(panel_h);
    if (pixel_rows < 1) pixel_rows = 1;
    uint64_t bucket_size = std::max(uint64_t(1), total_inst_ / static_cast<uint64_t>(pixel_rows));

    for (int row = 0; row < pixel_rows; row++) {
        uint64_t bucket_start = static_cast<uint64_t>(row) * bucket_size;
        uint64_t bucket_end = std::min(bucket_start + bucket_size, total_inst_);
        if (bucket_start >= total_inst_) break;

        float y0 = canvas_pos.y + static_cast<float>(row);
        float y1 = y0 + 1.0f;

        // Classify this bucket by sampling a few instructions
        bool has_taint = false;
        bool has_back_taint = false;
        bool has_bookmark = false;
        bool has_loop_header = false;
        bool has_loop_body = false;
        bool has_call = false;
        bool has_branch = false;

        // Sample up to 4 instructions per bucket for efficiency
        uint64_t sample_step = std::max(uint64_t(1), bucket_size / 4);
        for (uint64_t sid = bucket_start; sid < bucket_end; sid += sample_step) {
            auto srow = fetch_row(sid);

            if (show_taint_ && taint_result_ && taint_result_->has_event_at(sid))
                has_taint = true;
            if (show_backward_taint_ && backward_taint_result_ &&
                backward_taint_result_->is_contributing(sid))
                has_back_taint = true;
            if (srow.has_bookmark) has_bookmark = true;
            if (show_loops_ && loop_result_) {
                if (loop_result_->is_loop_header(srow.pc)) has_loop_header = true;
                else if (loop_result_->is_in_loop(srow.pc)) has_loop_body = true;
            }
            if (function_result_ && function_result_->call_at(sid)) has_call = true;
            if (srow.disasm.size() > 0 &&
                (srow.disasm[0] == 'b' || srow.disasm.find("bl") == 0)) has_branch = true;
        }

        // Choose color based on analysis priority
        ImU32 col;
        if (has_bookmark)       col = IM_COL32(255, 220, 40,  255);
        else if (has_back_taint) col = IM_COL32(220, 60,  60,  200);
        else if (has_taint)      col = IM_COL32(40,  200, 80,  200);
        else if (has_loop_header) col = IM_COL32(255, 140, 30, 230);
        else if (has_loop_body)  col = IM_COL32(140, 80,  20,  180);
        else if (has_call)       col = IM_COL32(80,  140, 255, 150);
        else if (has_branch)     col = IM_COL32(200, 200, 60,  120);
        else                     col = IM_COL32(55,  58,  70,  255);

        draw->AddLine(ImVec2(canvas_pos.x, y0), ImVec2(canvas_pos.x + panel_w, y1), col, 1.0f);
    }

    // Current position indicator: bright horizontal line
    {
        float cur_y = canvas_pos.y +
            static_cast<float>(current_inst_) / static_cast<float>(total_inst_) * panel_h;
        draw->AddLine(ImVec2(canvas_pos.x, cur_y), ImVec2(canvas_pos.x + panel_w, cur_y),
                      IM_COL32(255, 255, 255, 240), 2.0f);
        // Viewport window indicator (yellow bracket)
        // Estimate visible range from instruction panel scroll
        uint64_t vis_rows = 40;  // conservative estimate
        float vis_start_y = canvas_pos.y +
            static_cast<float>(current_inst_ > vis_rows / 2 ? current_inst_ - vis_rows / 2 : 0) /
            static_cast<float>(total_inst_) * panel_h;
        float vis_end_y = canvas_pos.y +
            static_cast<float>(std::min(current_inst_ + vis_rows / 2, total_inst_)) /
            static_cast<float>(total_inst_) * panel_h;
        draw->AddRect(ImVec2(canvas_pos.x, vis_start_y),
                      ImVec2(canvas_pos.x + panel_w, vis_end_y),
                      IM_COL32(255, 220, 60, 160), 0.0f, 0, 1.5f);
    }

    // Handle click: navigate to clicked instruction
    if (canvas_clicked || (canvas_hovered && ImGui::IsMouseDown(0))) {
        float my = ImGui::GetIO().MousePos.y;
        float rel = (my - canvas_pos.y) / panel_h;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t target = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (target >= total_inst_) target = total_inst_ - 1;
            navigate_to(target);
        }
    }

    // Hover tooltip
    if (canvas_hovered) {
        float my = ImGui::GetIO().MousePos.y;
        float rel = (my - canvas_pos.y) / panel_h;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t hover_id = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (hover_id >= total_inst_) hover_id = total_inst_ - 1;
            auto hover_row = fetch_row(hover_id);
            ImGui::SetTooltip("inst %llu\n0x%llx  %s\n(click to navigate)",
                (unsigned long long)hover_id,
                (unsigned long long)hover_row.static_pc,
                hover_row.disasm.c_str());
        }
    }

    // Legend at bottom (only if panel is tall enough)
    if (panel_h > 80.0f) {
        float legend_y = canvas_pos.y + panel_h + 4.0f;
        if (ImGui::GetCursorScreenPos().y < legend_y) {
            ImGui::SetCursorScreenPos(ImVec2(canvas_pos.x, canvas_pos.y + panel_h - 36.0f));
        }
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.55f, 1.0f));
        ImGui::TextUnformatted("Click to navigate");
        ImGui::PopStyleColor();
    }

    ImGui::End();
}

// ─── Status Bar ─────────────────────────────────────────────────────────────
// VS Code / IDA style: fixed-height strip at the very bottom of the viewport.
// Shows: inst position | mnemonic | active analyses | trace stats | mode badges

void GuiApp::render_status_bar() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float bar_y = vp->WorkPos.y + vp->WorkSize.y - kStatusBarHeight;

    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, bar_y));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, kStatusBarHeight));
    ImGui::SetNextWindowViewport(vp->ID);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(8.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.055f, 0.060f, 0.085f, 1.0f));

    ImGui::Begin("##StatusBar", nullptr,
        ImGuiWindowFlags_NoTitleBar    | ImGuiWindowFlags_NoResize  |
        ImGuiWindowFlags_NoMove        | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoDocking     | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoFocusOnAppearing);

    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor();

    // ─── Left section: position + current instruction ────────────────
    // Instruction index / total (IDA style: "0001234 / 0056789")
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.65f, 0.85f, 1.0f));
    ImGui::TextUnformatted("\xe2\x96\xb6");   // ▶
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 4.0f);

    ImGui::TextColored(ImVec4(0.80f, 0.85f, 1.00f, 1.0f),
        "%llu / %llu",
        (unsigned long long)current_inst_,
        (unsigned long long)total_inst_);

    ImGui::SameLine(0, 10.0f);

    // Progress percentage
    float pct = (total_inst_ > 1)
        ? 100.0f * static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1)
        : 0.0f;
    ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.65f, 1.0f), "(%.1f%%)", pct);

    ImGui::SameLine(0, 14.0f);

    // Current PC in muted monospace
    {
        auto row = fetch_row(current_inst_);
        if (!row.mnemonic.empty()) {
            // Vertical separator
            ImGui::TextColored(ImVec4(0.25f, 0.28f, 0.38f, 1.0f), "|");
            ImGui::SameLine(0, 10.0f);

            ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.65f, 1.0f),
                "0x%llx", (unsigned long long)row.static_pc);
            ImGui::SameLine(0, 6.0f);
            ImGui::TextColored(inst_color(row.mnemonic), "%s", row.mnemonic.c_str());
            ImGui::SameLine(0, 4.0f);
            ImGui::TextColored(ImVec4(0.70f, 0.72f, 0.80f, 1.0f), "%s", row.operands.c_str());
        }
    }

    // ─── Right section: active analyses + bookmarks + file ───────────
    // We compute items right-to-left, accumulate total width, then set cursor.
    // For simplicity, build a string for the right side and right-align.
    std::string right;

    // Bookmarks count
    if (!bookmarks_.empty()) {
        right += fmt::format("  \xe2\x98\x85 {} bkm", bookmarks_.size());  // ★
    }

    // Active analyses badges
    if (show_taint_ && taint_result_) {
        right += "  [TAINT]";
    }
    if (show_backward_taint_ && backward_taint_result_) {
        right += "  [BT]";
    }
    if (show_slice_ && slice_result_) {
        right += "  [SLICE]";
    }
    if (show_loops_ && loop_result_) {
        right += fmt::format("  [\xe2\x86\xba {}L]", loop_result_->loops.size());  // ↺
    }
    if (analysis_running_.load() && pass_manager_) {
        // Find running passes and show the first one's name + progress.
        int running_count = 0;
        std::string_view running_name;
        float running_pct = 0.0f;
        for (auto name : pass_manager_->all_passes()) {
            if (pass_manager_->state(name) == PassManager::PassState::Running) {
                running_count++;
                if (running_count == 1) {
                    running_name = name;
                    running_pct  = pass_manager_->progress_of(name);
                }
            }
        }
        if (running_count == 1) {
            std::string_view display = running_name;
            if (auto* cat = tenet::find_pass_catalog_entry(running_name))
                display = cat->display_name;
            right += fmt::format("  \xe2\xa3\xbe {} {:d}%", display, (int)(running_pct * 100));
        } else if (running_count > 1) {
            right += fmt::format("  \xe2\xa3\xbe {} passes", running_count);
        } else {
            right += "  \xe2\xa3\xbe Analyzing...";  // still transitioning
        }
    }

    // Search result position
    if (search_active_ && !search_results_.empty()) {
        right += fmt::format("  Search: {}/{}", search_current_ + 1, search_results_.size());
    }

    if (!right.empty()) {
        float text_w = ImGui::CalcTextSize(right.c_str()).x;
        float win_w  = ImGui::GetWindowWidth();
        ImGui::SameLine(win_w - text_w - 8.0f);
        ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.70f, 1.0f), "%s", right.c_str());
    }

    ImGui::End();
}

}  // namespace tenet

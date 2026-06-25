// popups.cpp — Goto popup, Search popup, Settings window, and goto helpers
// (rebuild_goto_candidates / goto_commit).
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/xref_pass.h"

#include <imgui.h>
#include <fmt/core.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>

namespace tenet {

// ─── Goto helpers ────────────────────────────────────────────────────────────

/// Rebuild the autocomplete candidate list from the function result.
/// Sorted by call count descending (most used functions first).
void GuiApp::rebuild_goto_candidates() {
    goto_candidates_.clear();
    if (!function_result_) return;

    // Build candidates from function map
    for (const auto& [pc, info] : function_result_->functions) {
        // Find the first inst_id for this function entry
        uint64_t inst_id = 0;
        bool found = false;
        // Look up the first call event that enters this function
        for (const auto& idx : info.call_event_indices) {
            if (idx < function_result_->call_events.size()) {
                const auto& evt = function_result_->call_events[idx];
                if (!found || evt.call_inst_id + 1 < inst_id) {
                    inst_id = evt.call_inst_id + 1;
                    found = true;
                }
            }
        }
        if (!found) inst_id = 0; // fallback

        // Format display: "func_name (0x1234abcd)"
        char disp[192];
        snprintf(disp, sizeof(disp), "%s  (0x%llx)",
                 info.name.c_str(), (unsigned long long)pc);

        goto_candidates_.push_back({disp, info.name, pc, inst_id});
    }

    // Sort by call count descending (most frequently called first)
    std::sort(goto_candidates_.begin(), goto_candidates_.end(),
              [&](const GotoCandidate& a, const GotoCandidate& b) {
                  auto it_a = function_result_->functions.find(a.pc);
                  auto it_b = function_result_->functions.find(b.pc);
                  uint64_t ca = (it_a != function_result_->functions.end()) ? it_a->second.total_calls : 0;
                  uint64_t cb = (it_b != function_result_->functions.end()) ? it_b->second.total_calls : 0;
                  if (ca != cb) return ca > cb;
                  return a.name < b.name;
              });

    goto_candidates_dirty_ = false;
}

/// Parse the input string and navigate:
///   - "0x<hex>" or bare hex (contains a-f) → treat as STATIC address (IDA address),
///     add module_slide to get runtime address, then look up in xref index.
///   - pure decimal digits → treat as instruction ID
///   - otherwise → search function names
///
/// Note: IDA always shows static (slide-adjusted) addresses.  Users naturally
/// paste addresses from IDA, so we add module_slide before the xref lookup.
void GuiApp::goto_commit(const char* buf) {
    if (!buf || buf[0] == '\0') return;

    std::string s(buf);

    // Trim whitespace
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
    if (s.empty()) return;

    // Helper: look up a static address → navigate to first inst at that PC.
    // Converts static → runtime by adding module_slide, then queries xref.
    // Falls back to the function-candidate list if xref not yet built.
    auto goto_static_addr = [&](uint64_t static_addr) -> bool {
        const uint64_t slide   = reader_.header().module_slide;
        const uint64_t runtime = static_addr + slide;

        // Try xref index first (exact PC hit)
        if (xref_result_) {
            auto ids = xref_result_->inst_ids_at(runtime);
            if (!ids.empty()) {
                navigate_to(ids[0]);
                return true;
            }
        }

        // Xref not built yet: try matching against function entry PCs
        // (function_result_ stores runtime PCs, so compare directly)
        if (function_result_) {
            auto it = function_result_->functions.find(runtime);
            if (it != function_result_->functions.end()) {
                const auto& info = it->second;
                if (!info.call_event_indices.empty()) {
                    uint64_t inst_id = function_result_->call_events[
                        info.call_event_indices[0]].call_inst_id + 1;
                    navigate_to(inst_id);
                    return true;
                }
            }
        }
        return false;
    };

    // 1a. Explicit hex address: starts with "0x" or "0X"
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        try {
            uint64_t addr = std::stoull(s.substr(2), nullptr, 16);
            goto_static_addr(addr);
        } catch (...) {}
        return;
    }

    // 1b. Bare hex string (no 0x prefix but contains a-f/A-F chars)?
    //     Require at least 4 chars and all chars valid hex digits to avoid
    //     ambiguity with short decimal numbers.
    {
        bool has_hex_digit = false;
        bool all_hex       = !s.empty();
        for (char c : s) {
            char lc = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if ((lc >= 'a' && lc <= 'f')) { has_hex_digit = true; }
            else if (!((c >= '0' && c <= '9'))) { all_hex = false; break; }
        }
        if (all_hex && has_hex_digit && s.size() >= 4) {
            try {
                uint64_t addr = std::stoull(s, nullptr, 16);
                goto_static_addr(addr);
            } catch (...) {}
            return;
        }
    }

    // 2. Pure decimal digits → instruction ID
    bool all_digits = !s.empty();
    for (char c : s) {
        if (c < '0' || c > '9') { all_digits = false; break; }
    }
    if (all_digits) {
        try {
            uint64_t target = std::stoull(s);
            if (target < total_inst_) navigate_to(target);
        } catch (...) {}
        return;
    }

    // 3. Function name lookup (exact match, then prefix/contains)
    if (!goto_candidates_.empty()) {
        // Lowercase query for case-insensitive matching
        std::string query = s;
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        // Exact match first
        for (const auto& c : goto_candidates_) {
            std::string lower = c.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower == query) {
                navigate_to(c.inst_id);
                return;
            }
        }
        // Prefix match
        for (const auto& c : goto_candidates_) {
            std::string lower = c.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.compare(0, query.size(), query) == 0) {
                navigate_to(c.inst_id);
                return;
            }
        }
        // Contains match
        for (const auto& c : goto_candidates_) {
            std::string lower = c.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.find(query) != std::string::npos) {
                navigate_to(c.inst_id);
                return;
            }
        }
    }
}

// ─── Goto Popup ─────────────────────────────────────────────────────────────

void GuiApp::render_goto_popup() {
    if (!show_goto_popup_) return;

    // Rebuild candidates if function result is available and dirty
    if (goto_candidates_dirty_ && function_result_) {
        rebuild_goto_candidates();
    }

    // Widen the popup when we have function candidates to show
    bool has_candidates = !goto_candidates_.empty();
    if (has_candidates) {
        ImGui::SetNextWindowSize(ImVec2(480.0f, 0.0f), ImGuiCond_Appearing);
    }

    ImGui::OpenPopup("Go to...");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Go to...", &show_goto_popup_,
                               ImGuiWindowFlags_AlwaysAutoResize)) {

        // ─── Hint text ──────────────────────────────────────────────────
        ImGui::TextDisabled("0x<static addr> (IDA addr), inst #<id>, or function name:");
        ImGui::Spacing();

        // ─── Input field ────────────────────────────────────────────────
        ImGui::SetNextItemWidth(has_candidates ? 440.0f : 280.0f);
        bool enter_pressed = ImGui::InputText("##goto_input", goto_buf_, sizeof(goto_buf_),
                                              ImGuiInputTextFlags_EnterReturnsTrue |
                                              ImGuiInputTextFlags_AutoSelectAll);

        // Auto-focus on first appearance
        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere(-1);
        }

        // Down arrow in input → move to candidate list
        bool arrow_down = ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_DownArrow);

        // ─── Commit on Enter ────────────────────────────────────────────
        if (enter_pressed) {
            // goto_buf_ always contains the best text to navigate to:
            // - user typed it directly, OR
            // - single-click on candidate filled it with the function name
            // goto_commit() handles hex/decimal/function-name parsing
            goto_commit(goto_buf_);
            show_goto_popup_ = false;
            goto_selected_candidate_ = -1;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return;
        }

        // ─── Autocomplete candidate list ────────────────────────────────
        if (has_candidates) {
            std::string query(goto_buf_);
            // Lowercase
            std::string ql = query;
            std::transform(ql.begin(), ql.end(), ql.begin(), ::tolower);

            // Collect matching candidates (limit display to 12)
            std::vector<const GotoCandidate*> visible;
            if (ql.empty()) {
                // Show top-N by call count
                for (size_t i = 0; i < goto_candidates_.size() && visible.size() < 12; i++) {
                    visible.push_back(&goto_candidates_[i]);
                }
            } else {
                // Filter: prefix first, then contains
                for (const auto& c : goto_candidates_) {
                    std::string cl = c.name;
                    std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);
                    if (cl.compare(0, ql.size(), ql) == 0) {
                        visible.push_back(&c);
                        if (visible.size() >= 12) break;
                    }
                }
                if (visible.size() < 12) {
                    for (const auto& c : goto_candidates_) {
                        std::string cl = c.name;
                        std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);
                        if (cl.find(ql) != std::string::npos &&
                            cl.compare(0, ql.size(), ql) != 0) {
                            visible.push_back(&c);
                            if (visible.size() >= 12) break;
                        }
                    }
                }
            }

            if (!visible.empty()) {
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextDisabled("Functions (%zu):", visible.size());
                ImGui::Spacing();

                // Keyboard navigation in list
                if (arrow_down || ImGui::IsItemFocused()) {
                    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && goto_selected_candidate_ < (int)visible.size() - 1)
                        goto_selected_candidate_++;
                    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && goto_selected_candidate_ > 0)
                        goto_selected_candidate_--;
                }

                // List child window for scrolling
                float list_h = std::min((int)visible.size(), 10) * ImGui::GetTextLineHeightWithSpacing() + 4.0f;
                ImGui::BeginChild("##goto_list", ImVec2(440.0f, list_h), false,
                                  ImGuiWindowFlags_NoScrollbar);

                for (int i = 0; i < (int)visible.size(); i++) {
                    const auto* c = visible[i];
                    bool selected = (goto_selected_candidate_ == i);

                    // Get call count for display
                    uint64_t calls = 0;
                    if (function_result_) {
                        auto it = function_result_->functions.find(c->pc);
                        if (it != function_result_->functions.end())
                            calls = it->second.total_calls;
                    }

                    // Format entry: name + address + call count
                    char row_buf[220];
                    snprintf(row_buf, sizeof(row_buf), "%-40s  %5llu calls",
                             c->display.c_str(), (unsigned long long)calls);

                    // Color: dim non-selected, highlight selected
                    if (selected) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.85f, 0.3f, 1.0f));
                    } else {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 0.75f, 0.75f, 1.0f));
                    }

                    if (ImGui::Selectable(row_buf, selected,
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                        if (ImGui::IsMouseDoubleClicked(0)) {
                            navigate_to(c->inst_id);
                            show_goto_popup_ = false;
                            goto_selected_candidate_ = -1;
                            std::memset(goto_buf_, 0, sizeof(goto_buf_));
                            ImGui::PopStyleColor();
                            ImGui::EndChild();
                            ImGui::EndPopup();
                            return;
                        }
                        goto_selected_candidate_ = i;
                        // Single-click: copy name into input field
                        std::strncpy(goto_buf_, c->name.c_str(), sizeof(goto_buf_) - 1);
                        goto_buf_[sizeof(goto_buf_) - 1] = '\0';
                    }
                    ImGui::PopStyleColor();
                }

                ImGui::EndChild();
            } else if (!ql.empty()) {
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextDisabled("(no matching functions)");
                ImGui::Spacing();
            }
        }

        // ─── Bottom buttons ─────────────────────────────────────────────
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Go", ImVec2(80, 0))) {
            // goto_buf_ is always authoritative: user typed it or click filled it
            goto_commit(goto_buf_);
            show_goto_popup_ = false;
            goto_selected_candidate_ = -1;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(80, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            show_goto_popup_ = false;
            goto_selected_candidate_ = -1;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
        }

        // ─── Keyboard tip ───────────────────────────────────────────────
        ImGui::SameLine();
        ImGui::TextDisabled("  Enter=go  ↑↓=select  DblClick=jump");

        ImGui::EndPopup();
    }
}

// ─── Search Popup ───────────────────────────────────────────────────────────

void GuiApp::render_search_popup() {
    if (!show_search_popup_) return;

    ImGui::OpenPopup("Search");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Search", &show_search_popup_,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Search disassembly:");

        bool enter_pressed = ImGui::InputText("##search", search_buf_, sizeof(search_buf_),
                                              ImGuiInputTextFlags_EnterReturnsTrue);

        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere(-1);
        }

        if (enter_pressed || ImGui::Button("Find")) {
            // Execute search
            std::string query(search_buf_);
            search_results_.clear();
            search_current_ = 0;
            search_active_ = false;

            if (!query.empty()) {
                // Linear search (limited to first 1M instructions for responsiveness)
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

            show_search_popup_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            show_search_popup_ = false;
            ImGui::CloseCurrentPopup();
        }

        if (search_active_ && !search_results_.empty()) {
            ImGui::Text("Results: %zu found (showing %zu/%zu)",
                search_results_.size(), search_current_ + 1, search_results_.size());
        }

        ImGui::EndPopup();
    }
}

// ─── Settings Window ────────────────────────────────────────────────────────

void GuiApp::render_settings_window() {
    ImGui::SetNextWindowSize(ImVec2(550, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Settings", &show_settings_)) {
        ImGui::End();
        if (!show_settings_) pending_font_.initialized = false;
        return;
    }
    // If user clicked the X button, show_settings_ is now false
    if (!show_settings_) {
        pending_font_.initialized = false;
        ImGui::End();
        return;
    }

    bool changed = false;

    // Initialize pending font settings when window first opens
    if (!pending_font_.initialized) {
        pending_font_.font_path = settings_.font_path;
        pending_font_.font_size = settings_.font_size;
        pending_font_.oversample_h = settings_.oversample_h;
        pending_font_.oversample_v = settings_.oversample_v;
        pending_font_.pixel_snap = settings_.pixel_snap;
        pending_font_.initialized = true;
    }

    if (ImGui::BeginTabBar("SettingsTabs")) {

        // ─── Font Tab ──────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Font")) {
            ImGui::SeparatorText("Font Selection");

            // Font path combo (operates on pending settings)
            {
                std::string current_name = pending_font_.font_path.empty()
                    ? "Auto (system default)"
                    : pending_font_.font_path.substr(pending_font_.font_path.rfind('/') + 1);

                if (ImGui::BeginCombo("Font", current_name.c_str())) {
                    if (ImGui::Selectable("Auto (system default)", pending_font_.font_path.empty())) {
                        pending_font_.font_path.clear();
                    }
                    ImGui::Separator();

                    for (const auto& path : available_fonts_) {
                        std::string name = path.substr(path.rfind('/') + 1);
                        bool selected = (path == pending_font_.font_path);
                        if (ImGui::Selectable(name.c_str(), selected)) {
                            pending_font_.font_path = path;
                        }
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip("%s", path.c_str());
                        }
                    }
                    ImGui::EndCombo();
                }
            }

            // Font size slider (operates on pending)
            ImGui::SliderFloat("Size", &pending_font_.font_size, 6.0f, 48.0f, "%.1f pt");

            // Oversampling
            ImGui::SeparatorText("Anti-Aliasing");
            ImGui::SliderInt("Oversampling H", &pending_font_.oversample_h, 1, 4);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Horizontal sub-pixel AA. 3 is optimal for HiDPI Retina.\nHigher values cost more font atlas VRAM.");
            }
            ImGui::SliderInt("Oversampling V", &pending_font_.oversample_v, 1, 4);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Vertical sub-pixel AA. 2 eliminates vertical aliasing on Retina.\nSet to 1 only on non-HiDPI displays.");
            }

            // Pixel snap
            ImGui::Checkbox("Pixel Snap", &pending_font_.pixel_snap);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Snap glyphs to integer pixel boundaries.\nKeep OFF on HiDPI Retina displays for sharper text.");
            }

            // Custom font path input
            ImGui::SeparatorText("Custom Font Path");
            static char custom_path_buf[512] = {};
            if (custom_path_buf[0] == '\0' && !pending_font_.font_path.empty()) {
                strncpy(custom_path_buf, pending_font_.font_path.c_str(), sizeof(custom_path_buf) - 1);
            }
            ImGui::SetNextItemWidth(-80.0f);
            ImGui::InputText("##CustomPath", custom_path_buf, sizeof(custom_path_buf));
            ImGui::SameLine();
            if (ImGui::Button("Apply##font_path")) {
                pending_font_.font_path = custom_path_buf;
            }
            ImGui::TextDisabled("Enter full path to .ttf/.otf file");

            // ─── Preview area ────────────────────────────────────────────
            ImGui::SeparatorText("Preview");
            // Use font scale to simulate the pending font size relative to current
            float preview_scale = pending_font_.font_size / settings_.font_size;
            ImGui::BeginChild("FontPreview", ImVec2(0, 100), ImGuiChildFlags_Borders);
            ImGui::SetWindowFontScale(preview_scale);
            ImGui::Text("AaBbCcDd 0123456789");
            ImGui::Text("mov x0, #0x1234; ldr x1, [sp, #0x10]");
            ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1.0f), "x0 x1 sp lr fp pc");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::EndChild();

            // ─── Save / Cancel buttons for font changes ──────────────────
            ImGui::Spacing();
            bool font_differs = (pending_font_.font_path != settings_.font_path ||
                                 pending_font_.font_size != settings_.font_size ||
                                 pending_font_.oversample_h != settings_.oversample_h ||
                                 pending_font_.oversample_v != settings_.oversample_v ||
                                 pending_font_.pixel_snap != settings_.pixel_snap);

            ImGui::BeginDisabled(!font_differs);
            if (ImGui::Button("Save Font Settings")) {
                settings_.font_path = pending_font_.font_path;
                settings_.font_size = pending_font_.font_size;
                settings_.oversample_h = pending_font_.oversample_h;
                settings_.oversample_v = pending_font_.oversample_v;
                settings_.pixel_snap = pending_font_.pixel_snap;
                settings_font_dirty_ = true;
                settings_.save(GuiSettings::default_path());
            }
            ImGui::EndDisabled();

            ImGui::SameLine();
            ImGui::BeginDisabled(!font_differs);
            if (ImGui::Button("Cancel##font")) {
                pending_font_.font_path = settings_.font_path;
                pending_font_.font_size = settings_.font_size;
                pending_font_.oversample_h = settings_.oversample_h;
                pending_font_.oversample_v = settings_.oversample_v;
                pending_font_.pixel_snap = settings_.pixel_snap;
            }
            ImGui::EndDisabled();

            if (font_differs) {
                ImGui::SameLine();
                ImGui::TextDisabled("(unsaved changes)");
            }

            ImGui::EndTabItem();
        }

        // ─── Theme Tab ─────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Theme")) {
            ImGui::SeparatorText("Color Theme");

            int theme_idx = static_cast<int>(settings_.theme);
            const char* theme_names[] = {"Dark", "Light", "Classic"};
            if (ImGui::Combo("Theme", &theme_idx, theme_names, 3)) {
                settings_.theme = static_cast<GuiSettings::Theme>(theme_idx);
                changed = true;
            }

            ImGui::SeparatorText("Row Spacing");
            if (ImGui::SliderFloat("Item Spacing Y", &settings_.row_spacing, 0.0f, 8.0f, "%.1f")) {
                changed = true;
            }

            ImGui::SeparatorText("Columns");
            if (ImGui::Checkbox("Show Instruction Index (#)", &settings_.show_inst_index)) {
                changed = true;
            }
            if (ImGui::Checkbox("Show Address Column", &settings_.show_address)) {
                changed = true;
            }

            ImGui::EndTabItem();
        }

        // ─── Colors Tab ────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Colors")) {
            ImGui::SeparatorText("Instruction Mnemonic Colors");

            auto color_edit = [&](const char* label, float col[4]) {
                if (ImGui::ColorEdit4(label, col, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_AlphaBar)) {
                    changed = true;
                }
            };

            color_edit("Branch (b, b.xx, cbz, tbz)", settings_.colors.branch);
            color_edit("Call (bl)", settings_.colors.call);
            color_edit("Return (ret, blr, br)", settings_.colors.ret);
            color_edit("Load (ldr, ldp, ...)", settings_.colors.load);
            color_edit("Store (str, stp, ...)", settings_.colors.store);
            color_edit("Syscall (svc, brk)", settings_.colors.syscall);
            color_edit("Arithmetic (add, sub, ...)", settings_.colors.arith);
            color_edit("Compare (cmp, tst)", settings_.colors.cmp);
            color_edit("Move (mov, mvn)", settings_.colors.mov);

            ImGui::SeparatorText("Operand Colors");
            color_edit("Registers (x0, sp, ...)", settings_.colors.reg_operand);
            color_edit("Immediates (#0x...)", settings_.colors.imm_operand);

            ImGui::Separator();
            if (ImGui::Button("Reset to Defaults")) {
                settings_.colors = GuiSettings::HighlightColors{};
                changed = true;
            }

            ImGui::EndTabItem();
        }

        // ─── MCP Server Tab ────────────────────────────────────────────
        if (ImGui::BeginTabItem("MCP Server")) {
            bool mcp_running = mcp_service_ && mcp_service_->http_running();

            // Status indicator
            ImGui::SeparatorText("Status");
            if (mcp_running) {
                ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.3f, 1.0f), "● Running");
                ImGui::SameLine();
                ImGui::TextDisabled("http://%s:%d/sse", mcp_gui_.host, mcp_gui_.port);
            } else {
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "● Stopped");
            }

            if (!mcp_status_msg_.empty()) {
                ImGui::TextWrapped("%s", mcp_status_msg_.c_str());
            }

            // Settings (disabled while running to prevent confusion)
            ImGui::SeparatorText("Configuration");
            ImGui::BeginDisabled(mcp_running);

            ImGui::SetNextItemWidth(160.0f);
            ImGui::InputText("Host / Interface", mcp_gui_.host, sizeof(mcp_gui_.host));
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip(
                    "Bind address.\n"
                    "127.0.0.1 = localhost only (safe default)\n"
                    "0.0.0.0   = all network interfaces");
            }

            ImGui::SetNextItemWidth(100.0f);
            ImGui::InputInt("Port", &mcp_gui_.port);
            mcp_gui_.port = std::max(1, std::min(65535, mcp_gui_.port));

            ImGui::SeparatorText("Basic Auth (optional)");

            ImGui::SetNextItemWidth(160.0f);
            ImGui::InputText("Username", mcp_gui_.username, sizeof(mcp_gui_.username));

            ImGui::SetNextItemWidth(160.0f);
            ImGui::InputText("Password", mcp_gui_.password, sizeof(mcp_gui_.password),
                             ImGuiInputTextFlags_Password);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Leave both empty to disable authentication.");
            }

            ImGui::EndDisabled();

            // Control buttons
            ImGui::SeparatorText("Controls");

            if (!mcp_running) {
                if (ImGui::Button("Start##mcp", ImVec2(90, 0))) {
                    McpHttpConfig cfg;
                    cfg.host     = mcp_gui_.host;
                    cfg.port     = static_cast<uint16_t>(mcp_gui_.port);
                    cfg.username = mcp_gui_.username;
                    cfg.password = mcp_gui_.password;

                    // Ensure PassManager is available
                    ensure_pass_manager();

                    mcp_service_ = std::make_unique<TenetMcpService>(
                        reader_, index_, regfile_, memory_,
                        pass_manager_.get(), &code_table_, &decoder_);

                    if (mcp_service_->start_http(cfg)) {
                        mcp_status_msg_ = fmt::format(
                            "Server started on {}:{}", cfg.host, cfg.port);
                    } else {
                        mcp_status_msg_ = fmt::format(
                            "ERROR: Failed to bind {}:{} — check if port is in use.",
                            cfg.host, cfg.port);
                        mcp_service_.reset();
                    }
                }
            } else {
                if (ImGui::Button("Stop##mcp", ImVec2(90, 0))) {
                    mcp_service_->stop_http();
                    mcp_status_msg_ = "Server stopped.";
                }
                ImGui::SameLine();
                if (ImGui::Button("Restart##mcp", ImVec2(90, 0))) {
                    mcp_service_->stop_http();

                    McpHttpConfig cfg;
                    cfg.host     = mcp_gui_.host;
                    cfg.port     = static_cast<uint16_t>(mcp_gui_.port);
                    cfg.username = mcp_gui_.username;
                    cfg.password = mcp_gui_.password;

                    if (mcp_service_->start_http(cfg)) {
                        mcp_status_msg_ = fmt::format(
                            "Server restarted on {}:{}", cfg.host, cfg.port);
                    } else {
                        mcp_status_msg_ = fmt::format(
                            "ERROR: Failed to restart on {}:{}", cfg.host, cfg.port);
                    }
                }
            }

            // Claude Desktop config hint
            ImGui::SeparatorText("Usage");
            ImGui::TextWrapped(
                "Add to Claude Desktop config (claude_desktop_config.json):");
            if (ImGui::BeginChild("McpConfigHint", ImVec2(0, 80),
                                  ImGuiChildFlags_Borders)) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.9f, 0.7f, 1.0f));
                ImGui::TextWrapped(
                    "\"tenet\": {\n"
                    "  \"command\": \"npx\",\n"
                    "  \"args\": [\"@modelcontextprotocol/server-sse\",\n"
                    "            \"http://%s:%d/sse\"]\n"
                    "}",
                    mcp_gui_.host, mcp_gui_.port);
                ImGui::PopStyleColor();
            }
            ImGui::EndChild();

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::Separator();

    // ─── Apply non-font settings immediately ────────────────────────────
    if (changed) {
        apply_settings();
        settings_.save(GuiSettings::default_path());
    }

    ImGui::End();
}

}  // namespace tenet

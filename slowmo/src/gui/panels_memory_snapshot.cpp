// panels_memory_snapshot.cpp — Memory snapshot capture + hex dump panel.
//
// Independent floating window for MemorySnapshotPass.
// Shows a parameter form to configure snapshot points, and a hex-dump
// view of captured snapshots.
//
// Split out of panels_analysis.cpp. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/memory/memory_snapshot_pass.h"
#include "analysis/pass_registry.h"

#include <imgui.h>
#include <fmt/core.h>

#include <cstring>
#include <string>
#include "gui/icons/IconsFontAwesome6.h"

namespace tenet {

// ---------------------------------------------------------------------------
// Run helper
// ---------------------------------------------------------------------------

void GuiApp::run_mem_snapshot_with_params() {
    ensure_pass_manager();

    MemorySnapshotConfig cfg;

    // Parse explicit inst_ids from input buffer (comma-separated)
    if (mem_snapshot_inst_buf_[0] != '\0') {
        std::string buf(mem_snapshot_inst_buf_);
        std::string token;
        for (size_t i = 0; i <= buf.size(); ++i) {
            if (i == buf.size() || buf[i] == ',' || buf[i] == ' ') {
                if (!token.empty()) {
                    try {
                        uint64_t id = std::stoull(token, nullptr, 0);
                        cfg.snapshot_inst_ids.push_back(id);
                    } catch (...) {}
                }
                token.clear();
            } else {
                token += buf[i];
            }
        }
    }

    cfg.snapshot_at_function_calls = mem_snapshot_auto_calls_;
    cfg.snapshot_size              = mem_snapshot_size_input_;

    // Invalidate previous result
    if (pass_manager_->state("memory_snapshot") != PassManager::PassState::NotRun) {
        pass_manager_->invalidate_and_clear_blob("memory_snapshot");
    }
    pass_manager_->register_pass(std::make_unique<MemorySnapshotPass>(std::move(cfg)));
    mem_snapshot_result_ = nullptr;

    std::string name_str = "memory_snapshot";
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
// Hex dump helper — renders a single MemoryRegion as xxd-style dump
// ---------------------------------------------------------------------------

static void render_hex_dump(const MemoryRegion& region, uint64_t slide) {
    const size_t bytes_per_line = 16;
    const auto& data = region.data;
    const auto& known = region.known;

    for (size_t off = 0; off < data.size(); off += bytes_per_line) {
        // Address
        ImGui::TextDisabled("0x%llx:", (unsigned long long)(region.addr + off));
        ImGui::SameLine();

        // Hex bytes
        std::string hex;
        std::string ascii;
        for (size_t j = 0; j < bytes_per_line && (off + j) < data.size(); ++j) {
            size_t idx = off + j;
            if (known[idx]) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02x ", data[idx]);
                hex += buf;
                ascii += (data[idx] >= 0x20 && data[idx] < 0x7f)
                         ? static_cast<char>(data[idx]) : '.';
            } else {
                hex += "?? ";
                ascii += ' ';
            }
        }
        // Pad hex to fixed width
        while (hex.size() < 48) hex += ' ';

        ImGui::TextUnformatted(hex.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.8f, 0.6f, 1.0f), "%s", ascii.c_str());
    }
}

// ---------------------------------------------------------------------------
// Panel renderer
// ---------------------------------------------------------------------------

void GuiApp::render_memory_snapshot_panel() {
    if (!ImGui::Begin("Memory Snapshots", &show_mem_snapshot_)) {
        ImGui::End();
        return;
    }

    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── No result yet — show parameter form ───────────────────────────
    if (!mem_snapshot_result_) {
        ImGui::TextDisabled(ICON_FA_CAMERA "  Memory Snapshot");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Capture memory snapshots at function calls and explicit points.\n"
            "See what input buffers looked like when a function was called.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Inst_id input (comma-separated for multiple)
        ImGui::Text("Snapshot at inst_id (comma-separated):");
        ImGui::PushItemWidth(panel_w * 0.55f);
        ImGui::InputText("##msnap_inst", mem_snapshot_inst_buf_,
            sizeof(mem_snapshot_inst_buf_));
        ImGui::PopItemWidth();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Instruction IDs to snapshot at.\n"
                              "Leave empty if using auto-snapshot at calls.");

        // Size input
        ImGui::AlignTextToFramePadding();
        ImGui::Text("Bytes per snapshot:");
        ImGui::SameLine();
        ImGui::PushItemWidth(panel_w * 0.2f);
        ImGui::InputScalar("##msnap_size", ImGuiDataType_U32, &mem_snapshot_size_input_);
        ImGui::PopItemWidth();

        // Auto-snapshot at calls
        ImGui::Checkbox("Auto-snapshot at BL/BLR calls", &mem_snapshot_auto_calls_);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Automatically capture x0-x7 pointed memory\n"
                              "at every function call instruction");

        ImGui::Spacing();

        // Run button
        bool has_input = (mem_snapshot_inst_buf_[0] != '\0' || mem_snapshot_auto_calls_);
        if (!has_input) ImGui::BeginDisabled();
        if (ImGui::Button(ICON_FA_CAMERA " Capture Snapshots")) {
            run_mem_snapshot_with_params();
        }
        if (!has_input) ImGui::EndDisabled();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Run the memory snapshot pass with current parameters");

        ImGui::End();
        return;
    }

    // ── Result available ──────────────────────────────────────────────

    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
        ICON_FA_CAMERA "  %zu snapshots captured",
        mem_snapshot_result_->total());

    ImGui::SameLine(panel_w - 90.0f);
    if (ImGui::SmallButton(ICON_FA_ARROW_ROTATE_LEFT " Rerun")) {
        mem_snapshot_result_ = nullptr;
        mem_snapshot_selected_ = -1;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Re-run with different parameters");

    ImGui::Separator();

    const auto& snapshots = mem_snapshot_result_->snapshots;

    // ── Split view: left = snapshot list, right = hex dump ────────────
    float list_w = panel_w * 0.35f;

    // Snapshot list
    ImGui::BeginChild("SnapList", ImVec2(list_w, 0), ImGuiChildFlags_ResizeX);
    for (size_t i = 0; i < snapshots.size(); ++i) {
        const MemoryRegion& sr = snapshots[i];
        char label[128];
        if (sr.label.empty()) {
            snprintf(label, sizeof(label), "#%zu  0x%llx  @%llu",
                     i, (unsigned long long)sr.addr,
                     (unsigned long long)sr.at_inst_id);
        } else {
            snprintf(label, sizeof(label), "#%zu  %s", i, sr.label.c_str());
        }

        bool is_selected = (mem_snapshot_selected_ == static_cast<int>(i));
        if (ImGui::Selectable(label, is_selected)) {
            mem_snapshot_selected_ = static_cast<int>(i);
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("inst #%llu  addr=0x%llx  %zu bytes\n%s",
                (unsigned long long)sr.at_inst_id,
                (unsigned long long)sr.addr,
                sr.data.size(),
                sr.label.c_str());
        }
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // Hex dump of selected snapshot
    ImGui::BeginChild("SnapHexDump");
    if (mem_snapshot_selected_ >= 0 &&
        mem_snapshot_selected_ < static_cast<int>(snapshots.size())) {
        const MemoryRegion& sr = snapshots[mem_snapshot_selected_];

        // Header
        ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f),
            "Snapshot #%d: 0x%llx  (%zu bytes)",
            mem_snapshot_selected_,
            (unsigned long long)sr.addr,
            sr.data.size());
        if (!sr.label.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("(%s)", sr.label.c_str());
        }
        ImGui::TextDisabled("@ inst #%llu", (unsigned long long)sr.at_inst_id);
        ImGui::Separator();

        // Count known bytes
        size_t known_count = 0;
        for (bool k : sr.known) { if (k) ++known_count; }
        ImGui::TextDisabled("%zu / %zu bytes known (%.0f%%)",
            known_count, sr.known.size(),
            sr.known.empty() ? 0.0 : 100.0 * static_cast<double>(known_count) / sr.known.size());

        ImGui::Spacing();

        // Navigation button
        if (ImGui::SmallButton(ICON_FA_ARROW_RIGHT " Jump to inst")) {
            navigate_to(sr.at_inst_id);
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Actual hex dump
        render_hex_dump(sr, reader_.header().module_slide);
    } else {
        ImGui::TextDisabled("Select a snapshot from the list to view its hex dump.");
    }
    ImGui::EndChild();

    ImGui::End();
}

}  // namespace tenet

// panels_cfg.cpp — interactive CFG graph view + per-function CFG rebuild.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>

namespace tenet {

// ─── Per-function CFG rebuild ─────────────────────────────────────────────────
// Extract the sub-CFG for `func_entry_pc` from the full-trace CFG, compute
// layout with GraphGridLayout, and store owned copies in cfg_func_result_ /
// cfg_func_layout_.  The render_cfg_panel reads from these instead of the
// full-trace layout.

void GuiApp::rebuild_cfg_for_function(uint64_t func_entry_pc) {
    if (!cfg_result_ || func_entry_pc == 0) {
        cfg_func_result_.reset();
        cfg_func_layout_.reset();
        cfg_layout_result_ = nullptr;
        cfg_current_func_pc_ = 0;
        return;
    }

    // Extract function sub-graph
    auto sub = cfg_result_->extract_function(func_entry_pc);
    if (sub.blocks.empty()) {
        cfg_func_result_.reset();
        cfg_func_layout_.reset();
        cfg_layout_result_ = nullptr;
        cfg_current_func_pc_ = func_entry_pc;
        return;
    }

    cfg_func_result_ = std::make_unique<CFGResult>(std::move(sub));

    // Run GraphGridLayout directly (no PassManager needed)
    constexpr size_t LARGE_CFG_THRESHOLD = 2000;
    const size_t num_blocks = cfg_func_result_->blocks.size();

    Graph layout_graph;
    layout_graph.reserve(num_blocks);
    const int insn_height = 14;
    const int default_block_width = 200;
    const int default_block_height = 24;

    for (const auto& [pc, block] : cfg_func_result_->blocks) {
        GraphBlock gb;
        gb.entry  = pc;
        gb.width  = default_block_width;
        gb.height = insn_height * static_cast<int>(block.instructions.size() + 1);
        gb.height = std::max(gb.height, default_block_height);
        layout_graph[pc] = gb;
    }
    for (const auto& edge : cfg_func_result_->edges) {
        auto it = layout_graph.find(edge.from_block);
        if (it != layout_graph.end()) {
            it->second.edges.emplace_back(GraphEdge(edge.to_block));
        }
    }

    uint64_t entry = func_entry_pc;
    // If entry block not present, fallback to first block
    if (layout_graph.find(entry) == layout_graph.end()) {
        entry = cfg_func_result_->blocks.begin()->first;
    }

    auto lt = (num_blocks > LARGE_CFG_THRESHOLD)
        ? GraphGridLayout::LayoutType::Narrow
        : GraphGridLayout::LayoutType::Medium;
    GraphGridLayout layout_algo(lt);
    if (num_blocks > LARGE_CFG_THRESHOLD) {
        layout_algo.setLayoutOptimization(false);
    }

    auto func_layout = std::make_unique<CFGLayoutResult>();
    layout_algo.calculateLayout(layout_graph, entry,
                                func_layout->canvas_width, func_layout->canvas_height);

    for (const auto& [pc, gb] : layout_graph) {
        BlockLayout bl;
        bl.x = gb.x; bl.y = gb.y; bl.width = gb.width; bl.height = gb.height;
        func_layout->block_layouts[pc] = bl;
    }
    func_layout->edge_layouts.reserve(cfg_func_result_->edges.size());
    for (const auto& [pc, gb] : layout_graph) {
        for (const auto& ge : gb.edges) {
            EdgeLayout el;
            el.from_block = pc;
            el.to_block   = ge.target;
            el.polyline   = ge.polyline;
            el.arrow      = ge.arrow;
            func_layout->edge_layouts.push_back(std::move(el));
        }
    }

    cfg_func_layout_ = std::move(func_layout);
    cfg_layout_result_ = cfg_func_layout_.get();
    cfg_current_func_pc_ = func_entry_pc;

    // Reset pan/zoom and selection
    cfg_scroll_ = ImVec2(0.0f, 0.0f);
    cfg_zoom_   = 1.0f;
    cfg_selected_block_ = 0;
    cfg_block_cursor_   = 0;

    // Recompute heatmap max for this sub-graph
    cfg_max_exec_count_ = 1;
    cfg_max_edge_count_ = 1;
    for (const auto& [pc, blk] : cfg_func_result_->blocks) {
        if (blk.execution_count > cfg_max_exec_count_)
            cfg_max_exec_count_ = blk.execution_count;
    }
    for (const auto& edge : cfg_func_result_->edges) {
        if (edge.taken_count > cfg_max_edge_count_)
            cfg_max_edge_count_ = edge.taken_count;
    }

    // Auto-fit the graph into the available space
    // (will be applied on next render frame since we don't know avail size here;
    //  zoom=1 + scroll centered on entry block is a good default)
    if (!cfg_func_layout_->block_layouts.empty()) {
        auto it = cfg_func_layout_->block_layouts.find(func_entry_pc);
        if (it == cfg_func_layout_->block_layouts.end()) {
            it = cfg_func_layout_->block_layouts.begin();
        }
        const auto& lo = it->second;
        // Center on entry block (approximate — real centering happens in render)
        cfg_scroll_.x = 200.0f - lo.x * cfg_zoom_;
        cfg_scroll_.y = 40.0f  - lo.y * cfg_zoom_;
    }
}

// ─── Edge lookup cache ───────────────────────────────────────────────────────
// Builds an O(1) (from_block, to_block) → CFGEdge* map so that the edge
// drawing loop doesn't need an O(E) inner scan per edge.
// Called once per function change; cost is O(E) and amortised over many frames.

void GuiApp::rebuild_cfg_edge_lookup(const CFGResult* cfg) {
    cfg_edge_lookup_.clear();
    cfg_edge_lookup_source_ = cfg;
    if (!cfg) return;
    cfg_edge_lookup_.reserve(cfg->edges.size() * 2);
    for (const auto& edge : cfg->edges) {
        cfg_edge_lookup_[{edge.from_block, edge.to_block}] = &edge;
    }
}

// ─── CFG Panel ───────────────────────────────────────────────────────────────
// An interactive, pannable, zoomable CFG view.
// Blocks are drawn as rounded rectangles with instruction text.
// Edges are drawn as polylines with arrowheads.

void GuiApp::render_cfg_panel() {
    if (!ImGui::Begin("CFG", &show_cfg_)) {
        ImGui::End();
        return;
    }

    // ── Auto-detect function change and rebuild per-function CFG ──────
    // When full-trace CFG data is available, track which function the
    // current instruction belongs to.  If it changed, extract that
    // function's sub-graph and re-layout automatically.
    if (cfg_result_ && function_result_ && total_inst_ > 0) {
        const FunctionInfo* cur_func = function_result_->function_at(current_inst_);
        uint64_t wanted_pc = cur_func ? cur_func->entry_pc : 0;
        if (wanted_pc != cfg_current_func_pc_) {
            rebuild_cfg_for_function(wanted_pc);
        }
    }

    // Effective CFG data: use per-function sub-graph when available, else full-trace
    const CFGResult* active_cfg = cfg_func_result_ ? cfg_func_result_.get() : cfg_result_;

    // Rebuild edge lookup cache if active_cfg changed.
    // This is O(E) but happens only on function switch, not every frame.
    if (active_cfg != cfg_edge_lookup_source_) {
        rebuild_cfg_edge_lookup(active_cfg);
    }

    // ── Toolbar row 1: controls ───────────────────────────────────────
    if (ImGui::Button("Run CFG Layout")) {
        run_cfg_layout();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::SliderFloat("Zoom##cfg", &cfg_zoom_, 0.05f, 8.0f, "%.1fx");
    ImGui::SameLine();
    if (ImGui::Button("Reset View")) {
        cfg_scroll_ = ImVec2(0.0f, 0.0f);
        cfg_zoom_ = 1.0f;
    }
    ImGui::SameLine();
    // "Center on current block" button
    if (ImGui::Button("Center Here") && active_cfg && cfg_layout_result_) {
        uint64_t cur_pc2 = 0;
        if (total_inst_ > 0) cur_pc2 = fetch_row(current_inst_).pc;
        auto* blk2 = active_cfg->block_containing(cur_pc2);
        if (blk2) {
            auto it2 = cfg_layout_result_->block_layouts.find(blk2->start_pc);
            if (it2 != cfg_layout_result_->block_layouts.end()) {
                const auto& lo = it2->second;
                ImVec2 avail2 = ImGui::GetContentRegionAvail();
                cfg_scroll_.x = avail2.x * 0.5f - (lo.x + lo.width  * 0.5f) * cfg_zoom_;
                cfg_scroll_.y = avail2.y * 0.5f - (lo.y + lo.height * 0.5f) * cfg_zoom_;
            }
        }
    }

    // ── Toolbar row 2: stats + current function name ───────────────────
    if (cfg_layout_result_) {
        // Show current function name if available
        if (cfg_current_func_pc_ != 0 && function_result_) {
            auto fit = function_result_->functions.find(cfg_current_func_pc_);
            if (fit != function_result_->functions.end()) {
                ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.6f, 1.0f),
                    "%s", fit->second.name.c_str());
                ImGui::SameLine();
            }
        }
        ImGui::TextDisabled("%zu blocks, %zu edges",
            cfg_layout_result_->block_layouts.size(),
            cfg_layout_result_->edge_layouts.size());
    } else if (!cfg_result_) {
        ImGui::TextDisabled("(no CFG data — run Analysis > CFG Layout)");
    } else {
        ImGui::TextDisabled("(waiting for function data...)");
    }

    // Jump controls for selected block
    if (cfg_selected_block_ != 0 && xref_result_) {
        auto inst_ids = xref_result_->inst_ids_at(cfg_selected_block_);
        if (!inst_ids.empty()) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f),
                "Block 0x%llx (%zu visits)",
                (unsigned long long)cfg_selected_block_,
                inst_ids.size());
            ImGui::SameLine();
            if (ImGui::Button("|<##cfg_first")) {
                cfg_block_cursor_ = 0;
                navigate_to(inst_ids[0]);
            }
            ImGui::SetItemTooltip("Jump to first visit in trace");
            ImGui::SameLine();
            if (ImGui::Button("<##cfg_prev") && cfg_block_cursor_ > 0) {
                cfg_block_cursor_--;
                navigate_to(inst_ids[cfg_block_cursor_]);
            }
            ImGui::SetItemTooltip("Previous visit");
            ImGui::SameLine();
            ImGui::Text("%zu/%zu", cfg_block_cursor_ + 1, inst_ids.size());
            ImGui::SameLine();
            if (ImGui::Button(">##cfg_next") && cfg_block_cursor_ + 1 < inst_ids.size()) {
                cfg_block_cursor_++;
                navigate_to(inst_ids[cfg_block_cursor_]);
            }
            ImGui::SetItemTooltip("Next visit");
            ImGui::SameLine();
            if (ImGui::Button(">|##cfg_last")) {
                cfg_block_cursor_ = inst_ids.size() - 1;
                navigate_to(inst_ids[cfg_block_cursor_]);
            }
            ImGui::SetItemTooltip("Jump to last visit in trace");
        }
    }

    ImGui::Separator();

    if (!cfg_layout_result_ || cfg_layout_result_->block_layouts.empty()) {
        ImGui::TextDisabled("No CFG available.\nRun Analysis > CFG Layout first.");
        ImGui::End();
        return;
    }

    // ── Canvas ────────────────────────────────────────────────────────
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    if (canvas_size.x < 10.0f || canvas_size.y < 10.0f) {
        ImGui::End();
        return;
    }

    ImVec2 canvas_origin = ImGui::GetCursorScreenPos();

    // Invisible button captures mouse events for the canvas area
    ImGui::InvisibleButton("##cfg_canvas", canvas_size,
        ImGuiButtonFlags_MouseButtonLeft |
        ImGuiButtonFlags_MouseButtonRight |
        ImGuiButtonFlags_MouseButtonMiddle);

    bool canvas_hovered = ImGui::IsItemHovered();
    bool canvas_active  = ImGui::IsItemActive();

    // Pan with left mouse drag
    if (canvas_active && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        ImVec2 delta = ImGui::GetIO().MouseDelta;
        cfg_scroll_.x += delta.x;
        cfg_scroll_.y += delta.y;
    }

    // Zoom with scroll wheel
    if (canvas_hovered) {
        float scroll = ImGui::GetIO().MouseWheel;
        if (scroll != 0.0f) {
            // Zoom towards mouse cursor
            ImVec2 mouse_pos = ImGui::GetIO().MousePos;
            ImVec2 mouse_canvas = ImVec2(
                mouse_pos.x - canvas_origin.x - cfg_scroll_.x,
                mouse_pos.y - canvas_origin.y - cfg_scroll_.y);

            float old_zoom = cfg_zoom_;
            cfg_zoom_ *= (scroll > 0.0f ? 1.1f : 0.9f);
            cfg_zoom_ = std::max(0.05f, std::min(cfg_zoom_, 8.0f));

            float scale_change = cfg_zoom_ / old_zoom;
            cfg_scroll_.x -= mouse_canvas.x * (scale_change - 1.0f);
            cfg_scroll_.y -= mouse_canvas.y * (scale_change - 1.0f);
        }
    }

    // Draw background
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(canvas_origin,
        ImVec2(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y),
        IM_COL32(18, 20, 26, 255));

    // Grid dots for reference
    {
        const float grid_step = 40.0f * cfg_zoom_;
        float grid_x = fmodf(cfg_scroll_.x, grid_step);
        float grid_y = fmodf(cfg_scroll_.y, grid_step);
        for (float x = canvas_origin.x + grid_x; x < canvas_origin.x + canvas_size.x; x += grid_step) {
            for (float y = canvas_origin.y + grid_y; y < canvas_origin.y + canvas_size.y; y += grid_step) {
                draw->AddCircleFilled(ImVec2(x, y), 1.0f, IM_COL32(50, 55, 70, 120));
            }
        }
    }

    // Helper: convert layout coordinate to screen coordinate
    auto to_screen = [&](float lx, float ly) -> ImVec2 {
        return ImVec2(
            canvas_origin.x + cfg_scroll_.x + lx * cfg_zoom_,
            canvas_origin.y + cfg_scroll_.y + ly * cfg_zoom_);
    };

    // Clip to canvas
    draw->PushClipRect(canvas_origin,
        ImVec2(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y), true);

    // Determine the "current" block (containing current_inst_'s PC)
    uint64_t cur_pc = 0;
    if (total_inst_ > 0) {
        auto row = fetch_row(current_inst_);
        cur_pc = row.pc;
    }
    // Find block containing cur_pc
    uint64_t highlight_block_pc = 0;
    if (active_cfg) {
        auto* blk = active_cfg->block_containing(cur_pc);
        if (blk) highlight_block_pc = blk->start_pc;
    }

    // ── Helper: heatmap colour (cold blue → hot red) ──────────────────
    // t in [0,1]; returns RGBA
    auto heatmap_color = [](float t, uint8_t alpha) -> ImU32 {
        // cold (0) = dark blue, warm (0.5) = teal/green, hot (1) = red/orange
        t = std::max(0.0f, std::min(t, 1.0f));
        uint8_t r, g, b;
        if (t < 0.5f) {
            float s = t * 2.0f;
            r = static_cast<uint8_t>(20  + s * 60);   // 20→80
            g = static_cast<uint8_t>(60  + s * 100);  // 60→160
            b = static_cast<uint8_t>(120 - s * 60);   // 120→60
        } else {
            float s = (t - 0.5f) * 2.0f;
            r = static_cast<uint8_t>(80  + s * 175);  // 80→255
            g = static_cast<uint8_t>(160 - s * 130);  // 160→30
            b = static_cast<uint8_t>(60  - s * 50);   // 60→10
        }
        return IM_COL32(r, g, b, alpha);
    };

    // Handle click on canvas to select a block
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && !ImGui::IsMouseDragging(ImGuiMouseButton_Left, 3.0f)) {
        ImVec2 mouse = ImGui::GetIO().MousePos;
        // Convert mouse position to layout coordinates
        float lx = (mouse.x - canvas_origin.x - cfg_scroll_.x) / cfg_zoom_;
        float ly = (mouse.y - canvas_origin.y - cfg_scroll_.y) / cfg_zoom_;

        // Hit-test all blocks
        uint64_t clicked_block = 0;
        for (const auto& [bpc, lo] : cfg_layout_result_->block_layouts) {
            if (lx >= lo.x && lx <= lo.x + lo.width &&
                ly >= lo.y && ly <= lo.y + lo.height) {
                clicked_block = bpc;
                break;
            }
        }
        if (clicked_block != 0 && clicked_block != cfg_selected_block_) {
            cfg_selected_block_ = clicked_block;
            cfg_block_cursor_   = 0;
            // Auto-navigate to first execution of this block
            if (xref_result_) {
                uint64_t first = xref_result_->first_inst_id_at(clicked_block);
                if (first != UINT64_MAX) navigate_to(first);
            }
        }
    }

    // ── Draw edges ───────────────────────────────────────────────────
    for (const auto& edge : cfg_layout_result_->edge_layouts) {
        if (edge.polyline.size() < 2) continue;

        // Defaults
        ImU32 edge_color = IM_COL32(70, 75, 100, 180);
        float  edge_width = 1.0f;

        if (active_cfg) {
            // O(1) lookup via prebuilt hash map (was O(E) linear scan each edge)
            auto lit = cfg_edge_lookup_.find({edge.from_block, edge.to_block});
            if (lit != cfg_edge_lookup_.end()) {
                const CFGEdge& cfg_edge = *lit->second;
                // Width proportional to taken_count (log scale, 1..4px)
                float t_edge = (cfg_max_edge_count_ > 1)
                    ? static_cast<float>(cfg_edge.taken_count) / static_cast<float>(cfg_max_edge_count_)
                    : 0.0f;
                edge_width = 1.0f + t_edge * 3.0f;

                // Hue: fallthrough = green tint, branch = orange/red tint, scaled by hotness
                if (cfg_edge.is_fallthrough) {
                    uint8_t g_val = static_cast<uint8_t>(100 + t_edge * 155);
                    edge_color = IM_COL32(40, g_val, 60, 200);
                } else {
                    uint8_t r_val = static_cast<uint8_t>(120 + t_edge * 135);
                    edge_color = IM_COL32(r_val, static_cast<uint8_t>(80 - t_edge * 40), 40, 200);
                }

                // Extra highlight if this edge connects to/from current block
                bool is_active_edge = (cfg_edge.from_block == highlight_block_pc ||
                                       cfg_edge.to_block   == highlight_block_pc);
                if (is_active_edge) {
                    edge_color = IM_COL32(100, 200, 255, 255);
                    edge_width = std::max(edge_width, 2.0f);
                }
            }
        }

        // Draw polyline segments
        for (size_t i = 0; i + 1 < edge.polyline.size(); ++i) {
            ImVec2 p0 = to_screen(edge.polyline[i].x, edge.polyline[i].y);
            ImVec2 p1 = to_screen(edge.polyline[i + 1].x, edge.polyline[i + 1].y);
            draw->AddLine(p0, p1, edge_color, edge_width);
        }

        // Arrowhead at last segment
        if (edge.polyline.size() >= 2) {
            size_t n = edge.polyline.size();
            ImVec2 tip  = to_screen(edge.polyline[n - 1].x, edge.polyline[n - 1].y);
            ImVec2 base = to_screen(edge.polyline[n - 2].x, edge.polyline[n - 2].y);
            float dx = tip.x - base.x;
            float dy = tip.y - base.y;
            float len = sqrtf(dx * dx + dy * dy);
            if (len > 0.001f) {
                float ux = dx / len, uy = dy / len;
                float px = -uy, py = ux;
                float arrow_len  = (6.0f + edge_width * 2.0f) * cfg_zoom_;
                float arrow_half = (3.0f + edge_width) * cfg_zoom_;
                ImVec2 left  = ImVec2(tip.x - ux * arrow_len + px * arrow_half,
                                       tip.y - uy * arrow_len + py * arrow_half);
                ImVec2 right = ImVec2(tip.x - ux * arrow_len - px * arrow_half,
                                       tip.y - uy * arrow_len - py * arrow_half);
                draw->AddTriangleFilled(tip, left, right, edge_color);
            }
        }
    }

    // ── Draw blocks ──────────────────────────────────────────────────
    const float corner_radius = 4.0f;
    const float font_size = 11.0f * cfg_zoom_;
    ImVec2 mouse_pos_canvas = ImGui::GetIO().MousePos;

    for (const auto& [block_pc, layout] : cfg_layout_result_->block_layouts) {
        ImVec2 tl = to_screen((float)layout.x, (float)layout.y);
        ImVec2 br = to_screen((float)(layout.x + layout.width),
                               (float)(layout.y + layout.height));

        // Skip blocks outside canvas (rough cull)
        if (br.x < canvas_origin.x || tl.x > canvas_origin.x + canvas_size.x) continue;
        if (br.y < canvas_origin.y || tl.y > canvas_origin.y + canvas_size.y) continue;

        // ── Compute heatmap intensity ─────────────────────────────────
        float heat = 0.0f;
        uint64_t exec_count = 0;
        if (active_cfg) {
            auto it_blk = active_cfg->blocks.find(block_pc);
            if (it_blk != active_cfg->blocks.end()) {
                exec_count = it_blk->second.execution_count;
                if (cfg_max_exec_count_ > 0)
                    heat = static_cast<float>(exec_count) / static_cast<float>(cfg_max_exec_count_);
            }
        }
        // Use log scale so cold blocks (executed once) are visible
        if (exec_count > 0 && cfg_max_exec_count_ > 1) {
            heat = logf(1.0f + static_cast<float>(exec_count)) /
                   logf(1.0f + static_cast<float>(cfg_max_exec_count_));
        }

        // ── State flags ───────────────────────────────────────────────
        bool is_current   = (block_pc == highlight_block_pc);    // block containing current PC
        bool is_selected  = (block_pc == cfg_selected_block_);   // user-clicked block
        bool is_hovered   = (mouse_pos_canvas.x >= tl.x && mouse_pos_canvas.x <= br.x &&
                             mouse_pos_canvas.y >= tl.y && mouse_pos_canvas.y <= br.y &&
                             canvas_hovered);

        // ── Colours ───────────────────────────────────────────────────
        ImU32 bg_color, border_color, header_color;

        if (is_current) {
            // Bright blue for the block the trace cursor is in
            bg_color     = IM_COL32(30, 70, 130, 245);
            border_color = IM_COL32(80, 180, 255, 255);
            header_color = IM_COL32(50, 110, 180, 255);
        } else if (is_selected) {
            // Cyan outline for user-selected block
            bg_color     = heatmap_color(heat, 230);
            border_color = IM_COL32(0, 220, 220, 255);
            header_color = IM_COL32(0, 100, 120, 255);
        } else if (exec_count == 0) {
            // Never executed (dead code or not-yet-visited) — dim grey
            bg_color     = IM_COL32(20, 22, 28, 200);
            border_color = IM_COL32(50, 55, 70, 150);
            header_color = IM_COL32(28, 30, 38, 200);
        } else {
            // Heatmap colouring for executed blocks
            bg_color     = heatmap_color(heat, 220);
            border_color = heatmap_color(heat, 255);
            header_color = heatmap_color(heat * 0.8f, 255);
        }

        // Lighten border on hover
        if (is_hovered && !is_current && !is_selected) {
            border_color = IM_COL32(200, 200, 255, 255);
        }

        draw->AddRectFilled(tl, br, bg_color, corner_radius);
        draw->AddRect(tl, br, border_color, corner_radius, 0,
                      is_current || is_selected ? 2.0f : 1.0f);

        // Header bar with address
        float header_h = 16.0f * cfg_zoom_;
        draw->AddRectFilled(tl, ImVec2(br.x, tl.y + header_h),
            header_color, corner_radius, ImDrawFlags_RoundCornersTop);

        // Draw text only if zoom is large enough to be readable
        if (cfg_zoom_ >= 0.35f) {
            // Address + exec count in header
            char addr_buf[64];
            if (exec_count > 0) {
                snprintf(addr_buf, sizeof(addr_buf), "0x%llx  ×%llu",
                    (unsigned long long)block_pc,
                    (unsigned long long)exec_count);
            } else {
                snprintf(addr_buf, sizeof(addr_buf), "0x%llx",
                    (unsigned long long)block_pc);
            }
            draw->AddText(nullptr, font_size,
                ImVec2(tl.x + 4.0f * cfg_zoom_, tl.y + 2.0f * cfg_zoom_),
                IM_COL32(220, 230, 255, 230),
                addr_buf);

            // Instruction body
            if (active_cfg) {
                auto it = active_cfg->blocks.find(block_pc);
                if (it != active_cfg->blocks.end()) {
                    const auto& blk = it->second;
                    float text_y = tl.y + header_h + 2.0f * cfg_zoom_;

                    if (cfg_zoom_ >= 0.7f) {
                        // Show individual instructions
                        for (size_t i = 0; i < blk.instructions.size() && text_y + font_size < br.y; ++i) {
                            uint64_t insn_pc = blk.instructions[i];
                            bool is_cur_insn = (insn_pc == cur_pc);
                            ImU32 insn_color = is_cur_insn
                                ? IM_COL32(255, 245, 60, 255)   // bright yellow for current insn
                                : IM_COL32(200, 210, 225, 200);

                            // Current-instruction marker on left
                            if (is_cur_insn) {
                                draw->AddTriangleFilled(
                                    ImVec2(tl.x + 2.0f * cfg_zoom_,    text_y + font_size * 0.15f),
                                    ImVec2(tl.x + 2.0f * cfg_zoom_,    text_y + font_size * 0.85f),
                                    ImVec2(tl.x + 5.0f * cfg_zoom_,    text_y + font_size * 0.5f),
                                    IM_COL32(255, 240, 60, 255));
                            }

                            // Get disassembly
                            auto opcode = code_table_.opcode_at(insn_pc);
                            std::string disasm_str;
                            if (opcode) {
                                auto d = decoder_.decode(insn_pc, *opcode);
                                if (d) {
                                    disasm_str = fmt::format("{:x}: {} {}",
                                        insn_pc - reader_.header().module_slide,
                                        d->mnemonic, d->op_str);
                                } else {
                                    disasm_str = fmt::format("{:x}: .word 0x{:08x}",
                                        insn_pc - reader_.header().module_slide, *opcode);
                                }
                            } else {
                                disasm_str = fmt::format("{:x}: ?", insn_pc);
                            }

                            float text_x  = tl.x + 7.0f * cfg_zoom_;
                            float max_w   = br.x - text_x - 4.0f * cfg_zoom_;
                            if (max_w > 0.0f) {
                                draw->AddText(nullptr, font_size,
                                    ImVec2(text_x, text_y), insn_color,
                                    disasm_str.c_str(),
                                    disasm_str.c_str() + disasm_str.size(),
                                    max_w);
                            }
                            text_y += font_size + 1.5f * cfg_zoom_;
                        }
                    } else {
                        // Compact: instruction count + exec count
                        char cnt_buf[64];
                        snprintf(cnt_buf, sizeof(cnt_buf), "%zu insns", blk.instructions.size());
                        draw->AddText(nullptr, font_size,
                            ImVec2(tl.x + 4.0f * cfg_zoom_, text_y),
                            IM_COL32(180, 190, 210, 200), cnt_buf);
                    }
                }
            }
        }

        // Hover tooltip with execution count + right-click menu trigger
        if (is_hovered && ImGui::IsItemHovered()) {
            std::string tip = fmt::format(
                "0x{:016x}\n{} executions\n",
                (unsigned long long)block_pc,
                (unsigned long long)exec_count);
            if (active_cfg) {
                auto it = active_cfg->blocks.find(block_pc);
                if (it != active_cfg->blocks.end()) {
                    tip += fmt::format("{} instructions in block\n", it->second.instructions.size());
                }
            }
            tip += "Left-click: select & navigate\nRight-click: more options";
            ImGui::SetTooltip("%s", tip.c_str());

            // Right-click → CFG block context menu
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                // Store block info for context menu
                ImGui::OpenPopup("##cfg_ctx");
                // Save state for menu
                ctx_inst_pc_        = block_pc;  // reuse ctx field for block PC
                ctx_inst_static_pc_ = block_pc - reader_.header().module_slide;
            }
        }
    }

    // ── CFG right-click context menu ─────────────────────────────────
    if (ImGui::BeginPopup("##cfg_ctx")) {
        ImGui::TextDisabled("Block: 0x%llx", (unsigned long long)ctx_inst_static_pc_);
        if (active_cfg) {
            auto it = active_cfg->blocks.find(ctx_inst_pc_);
            if (it != active_cfg->blocks.end()) {
                ImGui::TextDisabled("%zu instructions, %llu executions",
                    it->second.instructions.size(),
                    (unsigned long long)it->second.execution_count);
            }
        }
        ImGui::Separator();

        // Navigation
        if (ImGui::MenuItem("Navigate to Block Entry")) {
            if (xref_result_) {
                uint64_t first = xref_result_->first_inst_id_at(ctx_inst_pc_);
                if (first != UINT64_MAX) {
                    cfg_selected_block_ = ctx_inst_pc_;
                    cfg_block_cursor_ = 0;
                    navigate_to(first);
                }
            }
        }
        if (xref_result_) {
            auto ids = xref_result_->inst_ids_at(ctx_inst_pc_);
            if (!ids.empty() && ImGui::BeginMenu(fmt::format("Jump to Execution ({})...", ids.size()).c_str())) {
                size_t limit = std::min(ids.size(), size_t(15));
                for (size_t xi = 0; xi < limit; xi++) {
                    char lbl[48];
                    snprintf(lbl, sizeof(lbl), "  inst #%llu", (unsigned long long)ids[xi]);
                    if (ImGui::MenuItem(lbl)) {
                        cfg_selected_block_ = ctx_inst_pc_;
                        cfg_block_cursor_   = xi;
                        navigate_to(ids[xi]);
                    }
                }
                if (ids.size() > 15) {
                    ImGui::TextDisabled("  ... and %zu more", ids.size() - 15);
                }
                ImGui::EndMenu();
            }
        }

        ImGui::Separator();

        // Zoom controls
        if (ImGui::MenuItem("Zoom In (+)")) {
            cfg_zoom_ = std::min(cfg_zoom_ * 1.25f, 8.0f);
        }
        if (ImGui::MenuItem("Zoom Out (-)")) {
            cfg_zoom_ = std::max(cfg_zoom_ * 0.8f, 0.05f);
        }
        if (ImGui::MenuItem("Reset Zoom (1:1)")) {
            cfg_zoom_   = 1.0f;
        }
        if (ImGui::MenuItem("Fit to Window")) {
            // Auto-fit: center all blocks
            if (cfg_layout_result_ && !cfg_layout_result_->block_layouts.empty()) {
                float lo_x = FLT_MAX, lo_y = FLT_MAX, hi_x = -FLT_MAX, hi_y = -FLT_MAX;
                for (const auto& [bpc, lo] : cfg_layout_result_->block_layouts) {
                    lo_x = std::min(lo_x, static_cast<float>(lo.x));
                    lo_y = std::min(lo_y, static_cast<float>(lo.y));
                    hi_x = std::max(hi_x, static_cast<float>(lo.x + lo.width));
                    hi_y = std::max(hi_y, static_cast<float>(lo.y + lo.height));
                }
                float avail_w = ImGui::GetWindowWidth();
                float avail_h = ImGui::GetWindowHeight();
                float box_w = hi_x - lo_x;
                float box_h = hi_y - lo_y;
                if (box_w > 0 && box_h > 0) {
                    cfg_zoom_ = std::min(avail_w / box_w, avail_h / box_h) * 0.85f;
                    cfg_zoom_ = std::max(0.05f, std::min(cfg_zoom_, 8.0f));
                    cfg_scroll_.x = avail_w * 0.5f - (lo_x + box_w * 0.5f) * cfg_zoom_;
                    cfg_scroll_.y = avail_h * 0.5f - (lo_y + box_h * 0.5f) * cfg_zoom_;
                }
            }
        }

        ImGui::Separator();

        // Copy
        if (ImGui::MenuItem("Copy Block Address")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_inst_static_pc_);
            ImGui::SetClipboardText(buf);
        }

        ImGui::EndPopup();
    }

    draw->PopClipRect();

    ImGui::End();
}

}  // namespace tenet

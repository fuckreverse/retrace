#include "results_panel.h"

#include "analysis/pass_registry.h"
#include "analysis/pass_manager.h"

#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/crypto/algorithm_summary_pass.h"
#include "analysis/passes/crypto/objc_crypto_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/platform/syscall_intercept_pass.h"
#include "analysis/passes/memory/memory_string_pass.h"
#include "analysis/passes/memory/entropy_pass.h"
#include "analysis/passes/memory/mem_search_pass.h"
#include "analysis/passes/memory/memory_snapshot_pass.h"
#include "analysis/passes/memory/yara_mem_scan_pass.h"
#include "analysis/passes/profile/trace_fold_pass.h"
#include "analysis/passes/profile/reg_timeline_pass.h"
#include "analysis/passes/profile/call_context_pass.h"
#include "analysis/passes/profile/window_stats_pass.h"
#include "analysis/passes/profile/trace_diff_pass.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "analysis/passes/taint/taint_source_annotation_pass.h"
#include "analysis/passes/misc/thread_filter_pass.h"
#include "analysis/passes/vm/vm_abstract_pass.h"

#include "io/trace_reader.h"

#include <algorithm>
#include <fmt/format.h>
#include <ftxui/dom/elements.hpp>

namespace tenet {

using namespace ftxui;

// ─── build_result_entries() ────────────────────────────────────────────────
//
// One branch per pass that has a structured, per-item breakdown worth
// browsing. Passes not listed here (or with no items) just show their
// one-line summarize_pass_result() text in the catalog view — there is
// nothing further to drill into.

std::vector<ResultEntry> build_result_entries(const TuiContext& ctx, std::string_view name) {
    std::vector<ResultEntry> out;

    if (name == "cfg") {
        if (auto* r = ctx.cfg_result) {
            for (const auto& [pc, block] : r->blocks) {
                out.push_back({
                    fmt::format("{:016x}  insts={:<4} exec={:<6} term={}",
                                pc, block.instructions.size(), block.execution_count,
                                static_cast<int>(block.terminator)),
                    0, false});
            }
        }
    } else if (name == "call_graph") {
        if (auto* r = ctx.call_graph_result) {
            std::vector<std::pair<uint64_t, const CallGraphNode*>> nodes;
            for (const auto& [pc, node] : r->nodes) nodes.emplace_back(pc, &node);
            std::sort(nodes.begin(), nodes.end(), [](auto& a, auto& b) {
                return a.second->total_calls_received > b.second->total_calls_received;
            });
            for (auto& [pc, node] : nodes) {
                out.push_back({
                    fmt::format("{:016x}  {:<28} in={:<6} out={:<6}",
                                pc, node->name.empty() ? "(unnamed)" : node->name,
                                node->total_calls_received, node->total_calls_made),
                    0, false});
            }
        }
    } else if (name == "pattern") {
        if (auto* r = ctx.pattern_result) {
            for (const auto& m : r->matches) {
                out.push_back({
                    fmt::format("[{}] {}  @{:016x}  insts=[{},{}]",
                                static_cast<int>(m.confidence), m.pattern_name, m.anchor_pc,
                                m.start_inst_id, m.end_inst_id),
                    m.start_inst_id, true});
            }
            for (const auto& c : r->constants.constants) {
                std::string label = c.known_match
                    ? fmt::format("const 0x{:x} ({} {})", c.value, c.known_match->algorithm, c.known_match->name)
                    : fmt::format("const 0x{:x} (unidentified)", c.value);
                out.push_back({fmt::format("{}  x{}  @inst {}", label, c.dst_reg, c.first_inst_id),
                                c.first_inst_id, true});
            }
        }
    } else if (name == "loop_semantics") {
        if (auto* r = ctx.loop_semantics_result) {
            for (const auto& ls : r->loop_semantics) {
                out.push_back({
                    fmt::format("{:016x}  {:<14} conf={:.2f}  iters={}  {}",
                                ls.header_pc, loop_kind_name(ls.kind), ls.confidence,
                                ls.iteration_count, ls.description),
                    ls.sample_iter_start, ls.sample_iter_start > 0});
            }
        }
    } else if (name == "algorithm_summary") {
        if (auto* r = ctx.algorithm_summary_result) {
            for (const auto& c : r->candidates) {
                out.push_back({
                    fmt::format("{:<24} conf={:.2f}{}  {}",
                                c.name, c.confidence, c.is_speculative ? " (speculative)" : "",
                                c.evidence),
                    c.estimated_start, true});
            }
        }
    } else if (name == "objc") {
        if (auto* r = ctx.objc_result) {
            for (const auto& m : r->messages) {
                out.push_back({
                    fmt::format("[{}] {} {}  @inst {}",
                                m.class_name.empty() ? "?" : m.class_name,
                                m.selector_name.empty() ? "?" : m.selector_name,
                                m.has_return ? fmt::format("-> 0x{:x}", m.return_value) : "",
                                m.inst_id),
                    m.inst_id, true});
            }
        }
    } else if (name == "objc_crypto") {
        if (auto* r = ctx.objc_crypto_result) {
            for (const auto& h : r->hits) {
                out.push_back({
                    fmt::format("{}  @inst {}", h.objc_chain_summary(), h.pattern_start_inst),
                    h.pattern_start_inst, true});
            }
        }
    } else if (name == "syscall_intercept") {
        if (auto* r = ctx.syscall_intercept_result) {
            for (const auto& c : r->calls) {
                out.push_back({
                    fmt::format("{:<24} cat={:<2} @inst {}  {}",
                                c.callee_name, static_cast<int>(c.category), c.inst_id,
                                c.decoded_summary),
                    c.inst_id, true});
            }
        }
    } else if (name == "memory_strings") {
        if (auto* r = ctx.memory_string_result) {
            for (const auto& s : r->strings) {
                out.push_back({
                    fmt::format("0x{:016x}  @inst {}  \"{}\"", s.addr, s.call_site_inst_id, s.content),
                    s.call_site_inst_id, true});
            }
        }
    } else if (name == "strings") {
        // Handled by StringsPanel already (dedicated panel); no detail here.
    } else if (name == "entropy") {
        if (auto* r = ctx.entropy_result) {
            out.push_back({fmt::format("overall entropy={:.3f}  classification={}  known={}/{}",
                                       r->overall_entropy, static_cast<int>(r->classification),
                                       r->known_bytes, r->region_size),
                           0, false});
            for (const auto& b : r->blocks) {
                out.push_back({fmt::format("  off=0x{:x} size={} entropy={:.3f} known={}",
                                           b.offset, b.size, b.entropy, b.is_known),
                               0, false});
            }
            for (const auto& t : r->transitions) {
                out.push_back({fmt::format("  transition @inst {}  {:.2f} -> {:.2f} (d={:.2f})",
                                           t.inst_id, t.entropy_before, t.entropy_after, t.delta),
                               t.inst_id, true});
            }
        }
    } else if (name == "yara_mem_scan") {
        if (auto* r = ctx.yara_mem_scan_result) {
            for (const auto& m : r->matches) {
                out.push_back({
                    fmt::format("{:<28} @0x{:x}  @inst {}  {}",
                                m.rule_name, m.match_addr, m.at_inst_id, m.description),
                    m.at_inst_id, true});
            }
        }
    } else if (name == "mem_search") {
        if (auto* r = ctx.mem_search_result) {
            for (const auto& m : r->matches) {
                const char* src = m.source == MemSearchMatch::MemWrite ? "mem"
                                 : m.source == MemSearchMatch::RegDiff ? "reg" : "imm";
                out.push_back({
                    fmt::format("[{}] @inst {}  pc=0x{:x}  addr=0x{:x}  value=0x{:x}",
                                src, m.inst_id, m.pc, m.addr, m.matched_value),
                    m.inst_id, true});
            }
        }
    } else if (name == "memory_snapshot") {
        if (auto* r = ctx.memory_snapshot_result) {
            for (const auto& s : r->snapshots) {
                out.push_back({
                    fmt::format("0x{:016x}  @inst {}  {} bytes  {}",
                                s.addr, s.at_inst_id, s.data.size(), s.label),
                    s.at_inst_id, true});
            }
        }
    } else if (name == "call_context") {
        if (auto* r = ctx.call_context_result) {
            out.push_back({fmt::format("target: inst {} pc=0x{:x}, stack depth={}",
                                       r->target_inst_id, r->target_pc, r->call_stack.size()),
                           r->target_inst_id, true});
            for (const auto& f : r->call_stack) {
                out.push_back({fmt::format("  frame: call@inst {} callee=0x{:x}{}",
                                           f.call_inst_id, f.callee_pc,
                                           f.is_tail_call ? " (tail)" : ""),
                               f.call_inst_id, true});
            }
            for (const auto& ci : r->instructions) {
                out.push_back({fmt::format("{}{:>8}  0x{:x}  {}",
                                           ci.is_target ? "-> " : "   ", ci.inst_id, ci.pc,
                                           ci.disassembly),
                               ci.inst_id, true});
            }
        }
    } else if (name == "window_stats") {
        if (auto* r = ctx.window_stats_result) {
            for (size_t i = 0; i < r->windows.size(); i++) {
                const auto& w = r->windows[i];
                out.push_back({
                    fmt::format("win[{}] insts=[{},{}] entropy={:.2f} branch_density={:.2f} "
                                "mem_r={} mem_w={} unique_pcs={}",
                                i, w.start_inst_id, w.end_inst_id, w.mnemonic_entropy,
                                w.branch_density, w.mem_read_count, w.mem_write_count, w.unique_pcs),
                    w.start_inst_id, true});
            }
        }
    } else if (name == "dataflow_graph") {
        if (auto* r = ctx.dataflow_graph_result) {
            for (const auto& n : r->nodes) {
                out.push_back({
                    fmt::format("@inst {}  0x{:x}  {}", n.inst_id, n.pc, n.mnemonic),
                    n.inst_id, true});
            }
        }
    } else if (name == "reg_timeline") {
        if (auto* r = ctx.reg_timeline_result) {
            for (const auto& e : r->entries) {
                out.push_back({
                    fmt::format("@inst {}  pc=0x{:x}  reg={}  0x{:x} -> 0x{:x}",
                                e.inst_id, e.pc, e.reg_index, e.old_value, e.new_value),
                    e.inst_id, true});
            }
        }
    } else if (name == "trace_diff") {
        if (auto* r = ctx.trace_diff_result) {
            for (const auto& s : r->segments) {
                out.push_back({
                    fmt::format("[{}] A@{} B@{} pc=0x{:x}  {}{}",
                                diff_type_name(s.start_type), s.start_inst_a, s.start_inst_b,
                                s.start_pc, s.start_detail,
                                s.resynced ? fmt::format("  resync A@{} B@{}", s.resync_inst_a, s.resync_inst_b) : "  (no resync)"),
                    s.start_inst_a, true});
            }
        }
    } else if (name == "taint_source_annotation") {
        if (auto* r = ctx.taint_source_annotation_result) {
            for (const auto& s : r->sources) {
                out.push_back({fmt::format("{}", s.summary()), 0, false});
            }
        }
    } else if (name == "trace_fold") {
        if (auto* r = ctx.trace_fold_result) {
            for (const auto& region : r->folded_regions) {
                (void)region;
            }
            out.push_back({fmt::format("folded regions: {}, removed {} insts ({}x)",
                                       r->folded_regions.size(), r->total_instructions_removed,
                                       r->compression_ratio),
                           0, false});
        }
    } else if (name == "vm_abstract") {
        if (auto* r = ctx.vm_abstract_result) {
            out.push_back({fmt::format("dispatcher @0x{:x}  arch={}  vm_pc={}  steps={}",
                                       r->dispatcher.loop_header_pc, static_cast<int>(r->arch_type),
                                       r->vm_pc_tracked ? "tracked" : "unknown", r->total_vm_steps),
                           0, false});
            for (auto* h : r->handlers_by_frequency()) {
                out.push_back({
                    fmt::format("handler @0x{:016x}  exec={:<6}  body_pcs={:<4}  {}",
                                h->entry_pc, h->execution_count, h->body_pcs.size(), h->label),
                    0, false});
            }
        }
    } else if (name == "thread_filter") {
        if (auto* r = ctx.thread_filter_result) {
            (void)r;
            // ThreadFilterResult has no per-item list worth browsing beyond
            // the one-line catalog summary (thread_count / is_filtered).
        }
    }

    return out;
}

// ─── ResultsPanel ───────────────────────────────────────────────────────────

void ResultsPanel::enter_detail(std::string_view pass_name) {
    in_detail_ = true;
    detail_pass_name_ = std::string(pass_name);
    detail_cursor_ = 0;
    rebuild_detail_entries();
}

void ResultsPanel::leave_detail() {
    in_detail_ = false;
    detail_pass_name_.clear();
    detail_entries_.clear();
    detail_cursor_ = 0;
}

void ResultsPanel::rebuild_detail_entries() {
    detail_entries_ = build_result_entries(ctx_, detail_pass_name_);
    if (detail_cursor_ >= detail_entries_.size()) {
        detail_cursor_ = detail_entries_.empty() ? 0 : detail_entries_.size() - 1;
    }
}

void ResultsPanel::focus_pass(std::string_view pass_name) {
    visible_ = true;
    set_focused(true);
    // Find and select this pass in the catalog so Escape from the detail
    // view lands back on it.
    const auto& catalog = tenet::pass_catalog();
    for (size_t i = 0; i < catalog.size(); i++) {
        if (catalog[i].name == pass_name) {
            catalog_cursor_ = i;
            break;
        }
    }
    enter_detail(pass_name);
    // If there's nothing to browse, don't force an empty detail view on the
    // user — fall back to the catalog row (summary line is still visible
    // there via summarize_pass_result()).
    if (detail_entries_.empty()) leave_detail();
}

// ─── Rendering ──────────────────────────────────────────────────────────────

namespace {

Color state_color(PassManager::PassState st) {
    switch (st) {
        case PassManager::PassState::Running:   return Color::Yellow;
        case PassManager::PassState::Completed: return Color::Green;
        case PassManager::PassState::Failed:    return Color::Red;
        default:                                return Color::GrayDark;
    }
}

const char* state_icon(PassManager::PassState st) {
    switch (st) {
        case PassManager::PassState::Running:   return "\xe2\x96\xb6"; // ▶
        case PassManager::PassState::Completed: return "\xe2\x9c\x93"; // ✓
        case PassManager::PassState::Failed:    return "\xc3\x97";     // ×
        default:                                return "\xc2\xb7";     // ·
    }
}

}  // namespace

Element ResultsPanel::render_catalog() {
    Elements lines;

    auto header_label = focused_
        ? text("[ANALYSIS RESULTS]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Analysis Results") | bold | color(Color::Yellow);
    lines.push_back(header_label);
    lines.push_back(separator());

    const auto& catalog = tenet::pass_catalog();

    const int visible_count = 20;
    int total = static_cast<int>(catalog.size());
    int start = 0;
    if (total > visible_count) {
        start = static_cast<int>(catalog_cursor_) - visible_count / 2;
        if (start < 0) start = 0;
        if (start + visible_count > total) start = total - visible_count;
    }
    int end = std::min(start + visible_count, total);

    for (int i = start; i < end; i++) {
        const auto& entry = catalog[i];
        bool is_cursor = (static_cast<size_t>(i) == catalog_cursor_);

        auto st = ctx_.pass_manager ? ctx_.pass_manager->state(entry.name)
                                     : PassManager::PassState::NotRun;

        std::string summary;
        if (st == PassManager::PassState::Completed && ctx_.pass_manager) {
            auto entries = build_result_entries(ctx_, entry.name);
            summary = !entries.empty() ? fmt::format("{} items", entries.size()) : "";
        } else if (st == PassManager::PassState::Running) {
            summary = fmt::format("{:.0f}%", ctx_.pass_manager->progress_of(entry.name) * 100.0f);
        } else if (st == PassManager::PassState::Failed) {
            summary = "failed";
        }

        auto line = hbox({
            text(is_cursor ? ">" : " ") | color(Color::Yellow),
            text(fmt::format(" {} ", state_icon(st))) | color(state_color(st)),
            text(fmt::format("{:<16}", std::string(entry.display_name))) | color(Color::White),
            text(summary) | color(Color::GrayLight),
        });
        if (is_cursor) line = line | bgcolor(Color::GrayDark);
        lines.push_back(line);
    }

    lines.push_back(separator());
    lines.push_back(text("j/k:nav Enter:run/open R:force-rerun Esc:close") | color(Color::GrayDark));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
}

Element ResultsPanel::render_detail() {
    Elements lines;

    auto header_label = focused_
        ? text(fmt::format("[{}]", detail_pass_name_)) | bold | bgcolor(Color::Blue) | color(Color::White)
        : text(detail_pass_name_) | bold | color(Color::Yellow);
    lines.push_back(hbox({header_label, text(fmt::format("  ({} items)", detail_entries_.size())) | color(Color::GrayLight)}));
    lines.push_back(separator());

    if (detail_entries_.empty()) {
        lines.push_back(text("(no items — see summary in catalog view)") | color(Color::GrayLight));
    } else {
        const int visible_count = 20;
        int total = static_cast<int>(detail_entries_.size());
        int start = 0;
        if (total > visible_count) {
            start = static_cast<int>(detail_cursor_) - visible_count / 2;
            if (start < 0) start = 0;
            if (start + visible_count > total) start = total - visible_count;
        }
        int end = std::min(start + visible_count, total);

        for (int i = start; i < end; i++) {
            const auto& e = detail_entries_[i];
            bool is_cursor = (static_cast<size_t>(i) == detail_cursor_);
            auto line = hbox({
                text(is_cursor ? ">" : " ") | color(Color::Yellow),
                text(e.jumpable ? "\xe2\x86\x92 " : "  ") | color(Color::Cyan),
                text(e.text) | color(Color::White),
            });
            if (is_cursor) line = line | bgcolor(Color::GrayDark);
            lines.push_back(line);
        }
    }

    lines.push_back(separator());
    lines.push_back(text("j/k:nav Enter:jump Esc:back") | color(Color::GrayDark));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 50) | border;
}

Element ResultsPanel::render() {
    return in_detail_ ? render_detail() : render_catalog();
}

// ─── Event handling ─────────────────────────────────────────────────────────

bool ResultsPanel::handle_event(Event event) {
    if (in_detail_) {
        if (event == Event::Escape) {
            leave_detail();
            return true;
        }
        if (event == Event::Character('j') || event == Event::ArrowDown) {
            if (!detail_entries_.empty() && detail_cursor_ < detail_entries_.size() - 1) detail_cursor_++;
            return true;
        }
        if (event == Event::Character('k') || event == Event::ArrowUp) {
            if (detail_cursor_ > 0) detail_cursor_--;
            return true;
        }
        if (event == Event::Character('g')) { detail_cursor_ = 0; return true; }
        if (event == Event::Character('G')) {
            if (!detail_entries_.empty()) detail_cursor_ = detail_entries_.size() - 1;
            return true;
        }
        if (event == Event::Return) {
            if (!detail_entries_.empty() && detail_cursor_ < detail_entries_.size()) {
                const auto& e = detail_entries_[detail_cursor_];
                if (e.jumpable) {
                    ctx_.navigate_to(e.jump_inst_id);
                    set_focused(false);
                }
            }
            return true;
        }
        return false;
    }

    // Catalog view
    if (event == Event::Escape) {
        set_focused(false);
        return true;
    }
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        const auto& catalog = tenet::pass_catalog();
        if (catalog_cursor_ + 1 < catalog.size()) catalog_cursor_++;
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (catalog_cursor_ > 0) catalog_cursor_--;
        return true;
    }
    if (event == Event::Character('g')) { catalog_cursor_ = 0; return true; }
    if (event == Event::Character('G')) {
        const auto& catalog = tenet::pass_catalog();
        if (!catalog.empty()) catalog_cursor_ = catalog.size() - 1;
        return true;
    }
    if (event == Event::Return) {
        const auto& catalog = tenet::pass_catalog();
        if (catalog_cursor_ < catalog.size()) {
            const auto& entry = catalog[catalog_cursor_];
            auto st = ctx_.pass_manager ? ctx_.pass_manager->state(entry.name)
                                         : PassManager::PassState::NotRun;
            if (st == PassManager::PassState::Completed) {
                enter_detail(entry.name);
            } else if (st != PassManager::PassState::Running) {
                // NotRun / Failed — request a run. The result becomes
                // browsable on a subsequent Enter once it completes.
                ctx_.run_pass(entry.name);
            }
        }
        return true;
    }
    if (event == Event::Character('R')) {
        // Force re-run the selected pass (drops cache, re-registers).
        const auto& catalog = tenet::pass_catalog();
        if (catalog_cursor_ < catalog.size()) {
            ctx_.run_pass(catalog[catalog_cursor_].name);
        }
        return true;
    }
    return false;
}

}  // namespace tenet

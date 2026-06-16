#include "tui/tui_app.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/disassembly_pass.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/slice_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <fmt/core.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace tenet {

using namespace ftxui;

// ─── Helpers ──────────────────────────────────────────────────────────────

static std::string reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == 29) return "fp";
    if (idx == 30) return "lr";
    if (idx == 31) return "sp";
    if (idx == 32) return "nzcv";
    if (idx == 33) return "pc";
    return "??";
}

static Color inst_color(const std::string& disasm) {
    if (disasm.find("b.") == 0 || disasm.find("b ") == 0 || disasm.find("cb") == 0 || disasm.find("tb") == 0)
        return Color::Yellow;
    if (disasm.find("ret") == 0 || disasm.find("blr") == 0 || disasm.find("br") == 0)
        return Color::Magenta;
    if (disasm.find("ldr") == 0 || disasm.find("ldp") == 0)
        return Color::Cyan;
    if (disasm.find("str") == 0 || disasm.find("stp") == 0)
        return Color::Red;
    if (disasm.find("svc") == 0)
        return Color::Green;
    return Color::White;
}

// ─── Constructor ────────────────────────────────────────────────────────────

TuiApp::TuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
               InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory)
    : reader_(reader), index_(index), code_table_(code_table),
      decoder_(decoder), regfile_(regfile), memory_(memory),
      screen_(ScreenInteractive::Fullscreen()) {
    total_inst_ = index.inst_count();
    int h = screen_.dimy();
    viewport_height_ = (h > 6) ? h - 4 : 20;  // reserve for status bar, default 20 if unknown

    // Initialize hex dump view
    hex_dump_view_ = std::make_unique<HexDumpView>(memory_);
    hex_dump_view_->set_time(0);
    hex_dump_view_->set_address(0);
}

// ─── Row fetching ───────────────────────────────────────────────────────────

InstructionRow TuiApp::fetch_row(uint64_t inst_id) {
    auto cached = row_cache_.get(inst_id);
    if (cached) return *cached;

    InstructionRow row;
    row.inst_id = inst_id;

    uint64_t offset = index_.offset_of(inst_id, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind != RecordKind::Inst) {
        row.disasm = "<not an instruction>";
        row_cache_.put(inst_id, row);
        return row;
    }

    auto inst = rec.as_inst();
    row.pc = inst.pc;
    row.static_pc = inst.pc - reader_.header().module_slide;
    row.nzcv = inst.nzcv;
    row.reg_diff_count = inst.reg_diff_count;
    row.mem_access_count = inst.mem_access_count;

    auto opcode = code_table_.opcode_at(inst.pc);
    if (opcode) {
        auto d = decoder_.decode(inst.pc, *opcode);
        if (d) {
            row.disasm = fmt::format("{} {}", d->mnemonic, d->op_str);
        } else {
            row.disasm = fmt::format(".word 0x{:08x}", *opcode);
        }
    } else {
        row.disasm = "<no code>";
    }

    row.has_bookmark = std::binary_search(bookmarks_.begin(), bookmarks_.end(), inst_id);

    row_cache_.put(inst_id, row);
    return row;
}

std::vector<InstructionRow> TuiApp::fetch_viewport_rows() {
    std::vector<InstructionRow> rows;
    rows.reserve(viewport_height_);
    for (int i = 0; i < viewport_height_; i++) {
        uint64_t id = viewport_top_ + i;
        if (id >= total_inst_) break;
        rows.push_back(fetch_row(id));
    }
    return rows;
}

// ─── Rendering ──────────────────────────────────────────────────────────────

Element TuiApp::render_instruction_list() {
    auto rows = fetch_viewport_rows();

    Elements lines;
    for (auto& row : rows) {
        bool is_cursor = (row.inst_id == current_inst_);
        bool is_search_hit = search_active_ &&
            search_current_ < search_results_.size() &&
            search_results_[search_current_] == row.inst_id;
        bool is_tainted = show_taint_ && taint_result_ && taint_result_->has_event_at(row.inst_id);
        bool is_sliced = show_slice_ && slice_result_ && slice_result_->is_in_slice(row.inst_id);
        bool is_backward_tainted = show_backward_taint_ && backward_taint_result_ &&
            backward_taint_result_->is_contributing(row.inst_id);

        // Loop state
        bool is_loop_header = show_loops_ && loop_result_ && loop_result_->is_loop_header(row.pc);
        uint32_t loop_depth = (show_loops_ && loop_result_) ? loop_result_->loop_depth_at(row.pc) : 0;
        bool is_in_loop = loop_depth > 0;

        // Marker column: show loop indicator when relevant
        std::string marker_str;
        if (is_cursor)              marker_str = ">";
        else if (is_loop_header)    marker_str = "\xE2\x87\x86";   // ⇆ loop head
        else if (is_in_loop)        marker_str = "\xE2\x86\xBA";   // ↺ loop body
        else                        marker_str = " ";

        Color marker_color = is_cursor ? Color::Yellow
                           : is_loop_header ? Color::RGB(255, 140, 30)
                           : is_in_loop ? Color::RGB(180, 100, 30)
                           : Color::GrayDark;

        auto marker = text(marker_str) | color(marker_color);
        auto bookmark = text(row.has_bookmark ? "*" : " ");

        auto id_text = text(fmt::format("{:>8}", row.inst_id));
        auto pc_text = text(fmt::format("{:016x}", row.static_pc));
        auto disasm_text = text(row.disasm) | color(inst_color(row.disasm));

        Element line = hbox({
            marker,
            bookmark | color(Color::Red),
            text(" ") | size(WIDTH, EQUAL, 1),
            id_text | color(Color::GrayDark),
            text(" ") | size(WIDTH, EQUAL, 1),
            pc_text | color(Color::Cyan),
            text("  ") | size(WIDTH, EQUAL, 2),
            disasm_text,
        });

        if (is_cursor) {
            line = line | bgcolor(Color::GrayDark);
        } else if (is_backward_tainted) {
            line = line | bgcolor(Color::RedLight);
        } else if (is_sliced) {
            line = line | bgcolor(Color::Magenta);
        } else if (is_tainted) {
            line = line | bgcolor(Color::Green);
        } else if (is_search_hit) {
            line = line | bgcolor(Color::Blue);
        } else if (is_loop_header) {
            // Loop header: orange-brown background
            line = line | bgcolor(Color::RGB(80, 40, 5));
        } else if (is_in_loop) {
            // Loop body: depth-shaded dark amber
            int intensity = std::min(static_cast<int>(loop_depth - 1) * 12, 36);
            line = line | bgcolor(Color::RGB(45 + intensity, 25, 5));
        }

        lines.push_back(line);

        // Memory access lines (if enabled)
        if (show_mem_ && row.mem_access_count > 0) {
            uint64_t offset = index_.offset_of(row.inst_id, reader_);
            auto rec = reader_.record_at(offset);
            auto inst = rec.as_inst();
            for (uint8_t i = 0; i < inst.mem_access_count; i++) {
                auto mem = inst.mem_access(i);
                const char* type_str = (mem.type & 2) ? "W" : "R";
                auto mem_line = hbox({
                    text("          ") | size(WIDTH, EQUAL, 10),
                    text(fmt::format("[{}] 0x{:x} size={} val=0x{:x}",
                                     type_str, mem.addr, mem.size, mem.value))
                        | color(Color::GrayLight),
                });
                lines.push_back(mem_line);
            }
        }
    }

    return vbox(lines) | flex | frame;
}

Element TuiApp::render_register_panel() {
    const auto& state = regfile_.state_before(current_inst_);

    // Determine which registers are read/written by the current instruction
    std::vector<uint8_t> read_regs, write_regs;
    {
        uint64_t offset = index_.offset_of(current_inst_, reader_);
        auto rec = reader_.record_at(offset);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            // Written registers from trace reg_diffs (ground truth)
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                write_regs.push_back(inst.reg_diff(i).index);
            }
            // Read registers from Capstone decode
            auto opcode = code_table_.opcode_at(inst.pc);
            if (opcode) {
                auto d = decoder_.decode(inst.pc, *opcode);
                if (d) {
                    read_regs.assign(d->regs_read.begin(),
                                     d->regs_read.begin() + d->regs_read_count);
                }
            }
        }
    }

    // Helper: check if a register index is in a set
    auto is_in = [](const std::vector<uint8_t>& vec, uint8_t idx) {
        for (auto v : vec) if (v == idx) return true;
        return false;
    };

    // Color for register value: green=read, red=written, yellow=both, white=neither
    auto reg_value_color = [&](uint8_t idx) -> Color {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return Color::Yellow;
        if (w) return Color::RedLight;
        if (r) return Color::GreenLight;
        return Color::White;
    };

    // Color for register name label
    auto reg_label_color = [&](uint8_t idx) -> Color {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return Color::Yellow;
        if (w) return Color::Red;
        if (r) return Color::Green;
        return Color::Cyan;
    };

    Elements reg_lines;
    reg_lines.push_back(hbox({
        text("Registers") | bold | color(Color::Yellow),
        text("  ") | size(WIDTH, EQUAL, 2),
        text("R") | color(Color::Green),
        text("/") | color(Color::GrayLight),
        text("W") | color(Color::Red),
        text("/") | color(Color::GrayLight),
        text("RW") | color(Color::Yellow),
    }));
    reg_lines.push_back(separator());

    for (int i = 0; i < 29; i += 2) {
        auto name1 = reg_name(i);
        auto name2 = reg_name(i + 1);
        auto line = hbox({
            text(fmt::format("{:>3}=", name1)) | color(reg_label_color(i)),
            text(fmt::format("{:016x}", state.gpr[i])) | color(reg_value_color(i)),
            text("  ") | size(WIDTH, EQUAL, 2),
            text(fmt::format("{:>3}=", name2)) | color(reg_label_color(i + 1)),
            text(fmt::format("{:016x}", state.gpr[i + 1])) | color(reg_value_color(i + 1)),
        });
        reg_lines.push_back(line);
    }

    // fp, lr, sp, pc, nzcv
    reg_lines.push_back(separator());
    reg_lines.push_back(hbox({
        text(" fp=") | color(reg_label_color(IDX_FP)),
        text(fmt::format("{:016x}", state.fp())) | color(reg_value_color(IDX_FP)),
    }));
    reg_lines.push_back(hbox({
        text(" lr=") | color(reg_label_color(IDX_LR)),
        text(fmt::format("{:016x}", state.lr())) | color(reg_value_color(IDX_LR)),
    }));
    reg_lines.push_back(hbox({
        text(" sp=") | color(reg_label_color(IDX_SP)),
        text(fmt::format("{:016x}", state.sp())) | color(reg_value_color(IDX_SP)),
    }));
    reg_lines.push_back(hbox({
        text(" pc=") | color(reg_label_color(IDX_PC)),
        text(fmt::format("{:016x}", state.pc())) | color(reg_value_color(IDX_PC)),
    }));
    if (show_nzcv_) {
        reg_lines.push_back(hbox({
            text("nzcv=") | color(reg_label_color(IDX_NZCV)),
            text(fmt::format("{:x}", state.nzcv())) | color(reg_value_color(IDX_NZCV)),
        }));
    }

    // Cache stats
    reg_lines.push_back(separator());
    auto stats = regfile_.cache_stats();
    reg_lines.push_back(text(fmt::format("Cache: {} hits / {} misses", stats.hits, stats.misses))
                        | color(Color::GrayLight));

    return vbox(reg_lines) | size(WIDTH, GREATER_THAN, 38) | border;
}

Element TuiApp::render_memory_panel() {
    Elements lines;
    // Header with focus indicator
    auto header_label = memory_panel_focused_
        ? text("[MEMORY ACCESSES]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Memory Accesses") | bold | color(Color::Yellow);
    lines.push_back(header_label);
    lines.push_back(separator());

    // Get current instruction's memory accesses
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind != RecordKind::Inst) {
        lines.push_back(text("(no instruction)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
    }

    auto inst = rec.as_inst();
    if (inst.mem_access_count == 0) {
        lines.push_back(text("(no memory access)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
    }

    // Clamp cursor
    if (memory_access_cursor_ >= inst.mem_access_count) {
        memory_access_cursor_ = inst.mem_access_count > 0 ? inst.mem_access_count - 1 : 0;
    }

    for (uint8_t i = 0; i < inst.mem_access_count; i++) {
        auto mem = inst.mem_access(i);
        bool is_write = (mem.type & 2) != 0;
        const char* type_label = is_write ? "WRITE" : "READ ";
        Color type_color = is_write ? Color::Red : Color::Green;
        bool is_selected = memory_panel_focused_ && (static_cast<size_t>(i) == memory_access_cursor_);

        // Access header: type + address + size (with cursor indicator)
        auto cursor_mark = text(is_selected ? ">" : " ") | color(Color::Yellow);
        auto access_header = hbox({
            cursor_mark,
            text(type_label) | color(type_color) | bold,
            text(fmt::format("  addr=0x{:016x}  size={}", mem.addr, mem.size))
                | color(Color::White),
        });
        if (is_selected) {
            access_header = access_header | bgcolor(Color::GrayDark);
        }
        lines.push_back(access_header);

        // Value display
        if (mem.size <= 8) {
            lines.push_back(hbox({
                text("  val =") | color(Color::GrayLight),
                text(fmt::format(" 0x{:016x}", mem.value)) | color(Color::Cyan),
            }));
        } else {
            // 16-byte access (Q register / LDP)
            lines.push_back(hbox({
                text("  lo  =") | color(Color::GrayLight),
                text(fmt::format(" 0x{:016x}", mem.value)) | color(Color::Cyan),
            }));
            lines.push_back(hbox({
                text("  hi  =") | color(Color::GrayLight),
                text(fmt::format(" 0x{:016x}", mem.value_hi)) | color(Color::Cyan),
            }));
        }

        // Hex dump of the value (byte-by-byte, little-endian)
        {
            std::string hex_str = "  hex: ";
            uint8_t bytes[16];
            std::memcpy(bytes, &mem.value, 8);
            std::memcpy(bytes + 8, &mem.value_hi, 8);
            size_t n = (mem.size <= 16) ? mem.size : 8;
            for (size_t b = 0; b < n; b++) {
                hex_str += fmt::format("{:02x} ", bytes[b]);
            }
            lines.push_back(text(hex_str) | color(Color::GrayDark));
        }

        if (i + 1 < inst.mem_access_count) {
            lines.push_back(separator());
        }
    }

    // Footer hint when focused
    if (memory_panel_focused_) {
        lines.push_back(separator());
        lines.push_back(text("j/k:select Enter/H:hex-dump Esc:unfocus") | color(Color::GrayDark));
    }

    return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
}

bool TuiApp::handle_memory_panel_event(Event event) {
    if (event == Event::Escape) {
        memory_panel_focused_ = false;
        return true;
    }

    // Get current instruction's memory access count
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind != RecordKind::Inst) {
        memory_panel_focused_ = false;
        return true;
    }
    auto inst = rec.as_inst();
    if (inst.mem_access_count == 0) {
        memory_panel_focused_ = false;
        return true;
    }

    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (memory_access_cursor_ + 1 < static_cast<size_t>(inst.mem_access_count)) {
            memory_access_cursor_++;
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (memory_access_cursor_ > 0) {
            memory_access_cursor_--;
        }
        return true;
    }

    // Enter or H: open Hex Dump at the selected memory address
    if (event == Event::Return || event == Event::Character('H') || event == Event::Character('h')) {
        if (memory_access_cursor_ < static_cast<size_t>(inst.mem_access_count)) {
            auto mem = inst.mem_access(static_cast<uint8_t>(memory_access_cursor_));
            // Show and focus the hex dump panel at this address
            show_hex_dump_ = true;
            hex_dump_focused_ = false;
            if (hex_dump_view_) {
                hex_dump_view_->set_time(current_inst_);
                hex_dump_view_->goto_address(mem.addr);
            }
            memory_panel_focused_ = false;
        }
        return true;
    }

    return false;
}

Element TuiApp::render_status_bar() {
    std::string mode_str;
    if (show_goto_dialog_) mode_str = " GOTO ";
    else if (show_search_dialog_) mode_str = " SEARCH ";
    else if (show_string_search_dialog_) mode_str = " STR-FILTER ";
    else if (show_function_filter_dialog_) mode_str = " FUNC-FILTER ";
    else if (callstack_panel_focused_) mode_str = " CALLSTACK ";
    else if (memory_panel_focused_) mode_str = " MEMORY ";
    else if (string_panel_focused_) mode_str = " STRINGS ";
    else if (function_panel_focused_) mode_str = " FUNCTIONS ";
    else if (hex_dump_focused_) mode_str = " HEX-DUMP ";
    else if (search_active_) mode_str = fmt::format(" SEARCH [{}/{}] ", search_current_ + 1, search_results_.size());
    else if (show_backward_taint_) {
        if (!taint_jump_list_.empty())
            mode_str = fmt::format(" BACK-TAINT [{}/{}] ", taint_jump_cursor_ + 1, taint_jump_list_.size());
        else
            mode_str = " BACK-TAINT ";
    }
    else if (show_taint_) {
        if (!taint_jump_list_.empty())
            mode_str = fmt::format(" TAINT [{}/{}] ", taint_jump_cursor_ + 1, taint_jump_list_.size());
        else
            mode_str = " TAINT ";
    }
    else if (show_slice_) {
        if (!taint_jump_list_.empty())
            mode_str = fmt::format(" SLICE [{}/{}] ", taint_jump_cursor_ + 1, taint_jump_list_.size());
        else
            mode_str = " SLICE ";
    }
    else mode_str = " NORMAL ";

    // Navigation history indicator: [pos/total]
    std::string nav_str;
    if (nav_history_.size() > 1) {
        nav_str = fmt::format("  hist[{}/{}]", nav_history_pos_ + 1, nav_history_.size());
    }

    auto left = hbox({
        text(mode_str) | bgcolor(Color::Blue) | color(Color::White),
        text(fmt::format("  inst {:>8} / {:<8}  pc={:016x}{}",
                         current_inst_, total_inst_,
                         fetch_row(current_inst_).static_pc,
                         nav_str))
            | color(Color::White),
    });

    // Compact help line — shows the most important new bindings
    auto right = text("j/k:nav g:goto /:srch b:bkm t/S/B/C:analysis  "
                      "[/]:taint {/}:hist p:mem P:stk  f/F/e/x L I O V H q")
        | color(Color::GrayLight);

    return hbox({left | flex, right}) | bgcolor(Color::Black) | size(HEIGHT, EQUAL, 1);
}

Element TuiApp::render_hex_dump_panel() {
    if (!hex_dump_view_) {
        return text("(hex dump not available)") | color(Color::GrayLight) | border;
    }

    // Update the time point to match the current instruction
    hex_dump_view_->set_time(current_inst_);

    // Render the hex dump with a focus indicator
    auto content = hex_dump_view_->render();
    if (hex_dump_focused_) {
        // Add a visual indicator that hex dump has focus
        auto focus_bar = hbox({
            text(" [HEX DUMP FOCUSED] ") | bgcolor(Color::Blue) | color(Color::White) | bold,
            text(" ↑↓:scroll PgUp/Dn:page g:goto </>:time-nav Esc:unfocus") | color(Color::GrayLight),
        });
        return vbox({focus_bar, content | flex}) | flex;
    }
    return content;
}

Element TuiApp::render_main_layout() {
    Elements right_panels;
    if (show_regs_) {
        right_panels.push_back(render_register_panel());
    }
    if (show_mem_panel_) {
        right_panels.push_back(render_memory_panel());
    }
    if (show_callstack_) {
        right_panels.push_back(render_callstack_panel());
    }
    if (show_functions_) {
        right_panels.push_back(render_functions_panel());
    }
    if (show_strings_) {
        right_panels.push_back(render_strings_panel());
    }

    // Build center content: instruction list with optional minimap on the left
    Element center;
    if (show_minimap_) {
        center = hbox({
            render_minimap_column(),
            render_instruction_list() | flex,
        });
    } else {
        center = render_instruction_list() | flex;
    }

    auto main = hbox({
        center | flex,
        vbox(right_panels) | size(WIDTH, LESS_THAN, 50),
    });

    // If hex dump is visible, show it below the main content area
    if (show_hex_dump_ && hex_dump_view_) {
        auto hex_panel = render_hex_dump_panel() | size(HEIGHT, LESS_THAN, viewport_height_ / 2 + 4);
        return vbox({
            main | flex,
            hex_panel,
            render_status_bar(),
        });
    }

    return vbox({
        main | flex,
        render_status_bar(),
    });
}

// ─── Navigation ─────────────────────────────────────────────────────────────

void TuiApp::nav_push(uint64_t inst_id) {
    if (nav_history_navigating_) return;
    // Truncate forward history when navigating to a new location
    if (!nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1) {
        nav_history_.erase(
            nav_history_.begin() + static_cast<ptrdiff_t>(nav_history_pos_) + 1,
            nav_history_.end());
    }
    // Don't push duplicates
    if (!nav_history_.empty() && nav_history_.back() == inst_id) return;
    nav_history_.push_back(inst_id);
    if (nav_history_.size() > kMaxNavHistory) {
        nav_history_.erase(nav_history_.begin());
    }
    nav_history_pos_ = nav_history_.size() - 1;
}

void TuiApp::nav_back() {
    if (nav_history_.empty() || nav_history_pos_ == 0) return;
    nav_history_pos_--;
    nav_history_navigating_ = true;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

void TuiApp::nav_forward() {
    if (nav_history_.empty() || nav_history_pos_ >= nav_history_.size() - 1) return;
    nav_history_pos_++;
    nav_history_navigating_ = true;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

void TuiApp::navigate_to(uint64_t inst_id) {
    if (inst_id >= total_inst_) inst_id = total_inst_ > 0 ? total_inst_ - 1 : 0;
    nav_push(inst_id);  // record in history (no-op when back/forward navigating)
    current_inst_ = inst_id;
    update_viewport();
}

void TuiApp::navigate_relative(int64_t delta) {
    if (delta > 0 && current_inst_ + static_cast<uint64_t>(delta) >= total_inst_) {
        current_inst_ = total_inst_ > 0 ? total_inst_ - 1 : 0;
    } else if (delta < 0 && current_inst_ < static_cast<uint64_t>(-delta)) {
        current_inst_ = 0;
    } else {
        current_inst_ = static_cast<uint64_t>(static_cast<int64_t>(current_inst_) + delta);
    }
    update_viewport();
}

void TuiApp::update_viewport() {
    // Keep cursor within viewport, scroll if needed
    if (current_inst_ < viewport_top_) {
        viewport_top_ = current_inst_;
    } else if (current_inst_ >= viewport_top_ + static_cast<uint64_t>(viewport_height_)) {
        viewport_top_ = current_inst_ - static_cast<uint64_t>(viewport_height_) + 1;
    }
}

void TuiApp::handle_resize() {
    int h = screen_.dimy();
    viewport_height_ = (h > 6) ? h - 4 : 20;
    update_viewport();
}

// ─── Search ─────────────────────────────────────────────────────────────────

void TuiApp::search_forward(const std::string& query) {
    search_query_ = query;
    search_results_.clear();
    search_current_ = 0;
    search_active_ = false;

    if (query.empty()) return;

    // Simple linear search (can be optimized with PC index in M4)
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

void TuiApp::search_next() {
    if (!search_active_ || search_results_.empty()) return;
    search_current_ = (search_current_ + 1) % search_results_.size();
    navigate_to(search_results_[search_current_]);
}

void TuiApp::search_prev() {
    if (!search_active_ || search_results_.empty()) return;
    search_current_ = (search_current_ + search_results_.size() - 1) % search_results_.size();
    navigate_to(search_results_[search_current_]);
}

// ─── Bookmarks ──────────────────────────────────────────────────────────────

void TuiApp::toggle_bookmark() {
    auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), current_inst_);
    if (it != bookmarks_.end() && *it == current_inst_) {
        bookmarks_.erase(it);
    } else {
        bookmarks_.insert(it, current_inst_);
    }
    // Invalidate cache for this row
    row_cache_.put(current_inst_, fetch_row(current_inst_));
}

// ─── Dialogs ────────────────────────────────────────────────────────────────

void TuiApp::open_goto_dialog() {
    show_goto_dialog_ = true;
    goto_input_.clear();
}

void TuiApp::close_goto_dialog() {
    show_goto_dialog_ = false;
    goto_input_.clear();
}

void TuiApp::execute_goto() {
    try {
        uint64_t target = std::stoull(goto_input_);
        navigate_to(target);
    } catch (...) {
        // invalid input, ignore
    }
    close_goto_dialog();
}

void TuiApp::open_search_dialog() {
    show_search_dialog_ = true;
    search_input_.clear();
}

void TuiApp::close_search_dialog() {
    show_search_dialog_ = false;
    search_input_.clear();
}

void TuiApp::execute_search() {
    search_forward(search_input_);
    close_search_dialog();
}

// ─── Unified event handlers (single source of truth) ────────────────────────

bool TuiApp::handle_hex_dump_event(Event event) {
    if (!hex_dump_view_) return false;

    if (event == Event::Escape) {
        hex_dump_focused_ = false;
        return true;
    }
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        hex_dump_view_->scroll_down(1);
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        hex_dump_view_->scroll_up(1);
        return true;
    }
    if (event == Event::PageDown) {
        hex_dump_view_->page_down();
        return true;
    }
    if (event == Event::PageUp) {
        hex_dump_view_->page_up();
        return true;
    }
    if (event == Event::Character('g')) {
        uint64_t offset = index_.offset_of(current_inst_, reader_);
        auto rec = reader_.record_at(offset);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            if (inst.mem_access_count > 0) {
                hex_dump_view_->goto_address(inst.mem_access(0).addr);
            }
        }
        return true;
    }
    if (event == Event::Character('<') || event == Event::Character(',')) {
        hex_dump_view_->step_backward();
        return true;
    }
    if (event == Event::Character('>') || event == Event::Character('.')) {
        hex_dump_view_->step_forward();
        return true;
    }
    return false;
}

bool TuiApp::handle_string_panel_event(Event event) {
    if (event == Event::Escape) {
        string_panel_focused_ = false;
        return true;
    }
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (!filtered_string_indices_.empty() &&
            string_cursor_ < filtered_string_indices_.size() - 1) {
            string_cursor_++;
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (string_cursor_ > 0) {
            string_cursor_--;
        }
        return true;
    }
    if (event == Event::Return) {
        // Jump to the instruction that first discovered this string
        if (!filtered_string_indices_.empty() &&
            string_cursor_ < filtered_string_indices_.size()) {
            size_t str_idx = filtered_string_indices_[string_cursor_];
            const auto& ref = string_result_->strings[str_idx];
            navigate_to(ref.discovered_at);
            string_panel_focused_ = false;
        }
        return true;
    }
    if (event == Event::Character('/')) {
        open_string_search_dialog();
        return true;
    }
    if (event == Event::Character('c') || event == Event::Character('C')) {
        // Clear filter
        string_filter_.clear();
        update_string_filter();
        string_cursor_ = 0;
        return true;
    }
    if (event == Event::Character('G')) {
        // Jump to last string
        if (!filtered_string_indices_.empty()) {
            string_cursor_ = filtered_string_indices_.size() - 1;
        }
        return true;
    }
    if (event == Event::Character('g')) {
        // Jump to first string
        string_cursor_ = 0;
        return true;
    }
    return false;
}

bool TuiApp::handle_event(Event event) {
    // Resize
    if (event == Event::Special({0})) {
        handle_resize();
        return true;
    }

    // Function panel focused mode — intercept first
    if (function_panel_focused_ && show_functions_ && function_result_) {
        return handle_function_panel_event(event);
    }

    // Callstack panel focused mode — intercept first
    if (callstack_panel_focused_ && show_callstack_ && function_result_) {
        return handle_callstack_panel_event(event);
    }

    // Memory panel focused mode — intercept first
    if (memory_panel_focused_) {
        return handle_memory_panel_event(event);
    }

    // String panel focused mode — intercept first
    if (string_panel_focused_ && show_strings_ && string_result_) {
        return handle_string_panel_event(event);
    }

    // Hex dump focused mode — intercept first
    if (hex_dump_focused_ && hex_dump_view_) {
        return handle_hex_dump_event(event);
    }

    // Normal mode keybindings
    if (event == Event::Character('q') || event == Event::Character('Q')) {
        screen_.ExitLoopClosure()();
        return true;
    }
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        navigate_relative(1);
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        navigate_relative(-1);
        return true;
    }
    if (event == Event::Character('g')) {
        open_goto_dialog();
        return true;
    }
    if (event == Event::Character('/')) {
        open_search_dialog();
        return true;
    }
    if (event == Event::Character('n')) {
        search_next();
        return true;
    }
    if (event == Event::Character('N')) {
        search_prev();
        return true;
    }
    if (event == Event::Character('b')) {
        toggle_bookmark();
        return true;
    }
    if (event == Event::Character('r')) {
        show_regs_ = !show_regs_;
        return true;
    }
    if (event == Event::Character('m')) {
        show_mem_ = !show_mem_;
        return true;
    }
    if (event == Event::Character('M')) {
        show_mem_panel_ = !show_mem_panel_;
        return true;
    }
    if (event == Event::Character('H')) {
        show_hex_dump_ = !show_hex_dump_;
        if (show_hex_dump_ && hex_dump_view_) {
            hex_dump_focused_ = false;
            uint64_t offset = index_.offset_of(current_inst_, reader_);
            auto rec = reader_.record_at(offset);
            if (rec.kind == RecordKind::Inst) {
                auto inst = rec.as_inst();
                if (inst.mem_access_count > 0) {
                    hex_dump_view_->goto_address(inst.mem_access(0).addr);
                }
            }
            hex_dump_view_->set_time(current_inst_);
        }
        return true;
    }
    if (event == Event::Tab) {
        if (show_hex_dump_) {
            hex_dump_focused_ = !hex_dump_focused_;
            return true;
        }
    }
    if (event == Event::Character('G')) {
        navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
        return true;
    }
    if (event == Event::Character('0')) {
        navigate_to(0);
        return true;
    }
    if (event == Event::Character(' ') || event == Event::Character('d')) {
        navigate_relative(viewport_height_ / 2);
        return true;
    }
    if (event == Event::Character('u')) {
        navigate_relative(-(viewport_height_ / 2));
        return true;
    }
    if (event == Event::Character('z')) {
        show_nzcv_ = !show_nzcv_;
        return true;
    }
    if (event == Event::Character('R')) {
        row_cache_.clear();
        return true;
    }
    if (event == Event::Character('t')) {
        run_taint_analysis();
        return true;
    }
    if (event == Event::Character('S')) {
        run_slice_analysis();
        return true;
    }
    if (event == Event::Character('B')) {
        run_backward_taint_analysis();
        return true;
    }
    if (event == Event::Character('C')) {
        clear_analysis();
        return true;
    }
    if (event == Event::Character('f')) {
        if (!function_result_) {
            run_function_analysis();
        } else {
            show_callstack_ = !show_callstack_;
        }
        return true;
    }
    if (event == Event::Character('F')) {
        follow_return();
        return true;
    }
    if (event == Event::Character('e')) {
        follow_call();
        return true;
    }
    if (event == Event::Character('x')) {
        goto_xref_next();
        return true;
    }
    if (event == Event::Character('X')) {
        goto_xref_prev();
        return true;
    }
    if (event == Event::Character('I')) {
        if (!string_result_) {
            run_string_analysis();
            string_panel_focused_ = true;
        } else if (!show_strings_) {
            show_strings_ = true;
            string_panel_focused_ = true;
        } else {
            // Panel is visible — toggle focus
            string_panel_focused_ = !string_panel_focused_;
        }
        return true;
    }
    if (event == Event::Character('L')) {
        if (!function_result_) {
            run_function_analysis();
        }
        if (function_result_) {
            if (!show_functions_) {
                show_functions_ = true;
                function_panel_focused_ = true;
                update_function_list();
            } else {
                function_panel_focused_ = !function_panel_focused_;
            }
        }
        return true;
    }

    // ─── Navigation history: { = back, } = forward ──────────────────────────
    if (event == Event::Character('{')) {
        nav_back();
        return true;
    }
    if (event == Event::Character('}')) {
        nav_forward();
        return true;
    }

    // ─── Taint jump: [ = prev tainted inst, ] = next tainted inst ───────────
    if (event == Event::Character('[')) {
        goto_taint_prev();
        return true;
    }
    if (event == Event::Character(']')) {
        goto_taint_next();
        return true;
    }

    // ─── Callstack panel focus toggle (P) ───────────────────────────────────
    if (event == Event::Character('P')) {
        if (show_callstack_ && function_result_) {
            callstack_panel_focused_ = !callstack_panel_focused_;
        } else if (!function_result_) {
            run_function_analysis();
            show_callstack_ = true;
            callstack_panel_focused_ = true;
        }
        return true;
    }

    // ─── Memory panel focus toggle (p) ──────────────────────────────────────
    if (event == Event::Character('p')) {
        if (show_mem_panel_) {
            memory_panel_focused_ = !memory_panel_focused_;
            memory_access_cursor_ = 0;
        } else {
            show_mem_panel_ = true;
            memory_panel_focused_ = true;
            memory_access_cursor_ = 0;
        }
        return true;
    }

    // ─── Loop analysis (O) / loop highlight toggle (o) / minimap toggle (V) ─
    if (event == Event::Character('O')) {
        // Run loop analysis (first time) or toggle highlight
        if (!loop_result_) {
            if (!pass_manager_) {
                pass_manager_ = std::make_unique<PassManager>();
                pass_manager_->set_reader(&reader_);
                pass_manager_->set_index(&index_);
                pass_manager_->set_code_table(&code_table_);
                pass_manager_->set_decoder(&decoder_);
                pass_manager_->set_regfile(&regfile_);
                pass_manager_->set_memory(&memory_);
            }
            run_loop_analysis();
        } else {
            show_loops_ = !show_loops_;
        }
        return true;
    }
    if (event == Event::Character('V')) {
        show_minimap_ = !show_minimap_;
        return true;
    }

    return false;
}

// ─── Component factories ────────────────────────────────────────────────────

Component TuiApp::make_goto_dialog() {
    auto input = Input(&goto_input_, "inst_id");
    input |= CatchEvent([&](Event event) {
        if (event == Event::Return) {
            execute_goto();
            return true;
        }
        if (event == Event::Escape) {
            close_goto_dialog();
            return true;
        }
        return false;
    });

    return Renderer(input, [input] {
        return window(text(" Goto Instruction "), input->Render()) | center;
    });
}

Component TuiApp::make_search_dialog() {
    auto input = Input(&search_input_, "pattern");
    input |= CatchEvent([&](Event event) {
        if (event == Event::Return) {
            execute_search();
            return true;
        }
        if (event == Event::Escape) {
            close_search_dialog();
            return true;
        }
        return false;
    });

    return Renderer(input, [input] {
        return window(text(" Search "), input->Render()) | center;
    });
}

Component TuiApp::make_main_component() {
    auto main = Renderer([&] {
        return render_main_layout();
    });

    main |= CatchEvent([&](Event event) {
        if (show_goto_dialog_ || show_search_dialog_) {
            return false;  // Let dialog handle it
        }
        return handle_event(event);
    });

    return main;
}

// ─── Taint jump helpers ─────────────────────────────────────────────────────

// ─── Loop Analysis ───────────────────────────────────────────────────────────

void TuiApp::run_loop_analysis() {
    if (!pass_manager_) return;
    pass_manager_->register_pass(std::make_unique<LoopPass>());
    auto& result = pass_manager_->require("loop");
    if (result.ok()) {
        loop_result_ = &result.get<LoopResult>();
        show_loops_ = true;
    }
}

// ─── Minimap Column ──────────────────────────────────────────────────────────
// A narrow (3-char wide) vertical strip that summarizes the full trace.
// Each character row represents a bucket of instructions.
// Colors: bookmark=gold, back-taint=red, taint=green,
//         loop-header=orange, loop-body=amber, call=blue, other=gray.

ftxui::Element TuiApp::render_minimap_column() {
    using namespace ftxui;
    Elements rows;

    // Title
    rows.push_back(text("Map") | bold | color(Color::Yellow));
    rows.push_back(separator());

    if (total_inst_ == 0) {
        rows.push_back(text("   ") | color(Color::GrayDark));
        return vbox(rows) | size(WIDTH, EQUAL, 5) | border;
    }

    // Available height for the map (leave 2 rows for header)
    const int kMapRows = 40;  // fixed height in terminal rows

    for (int r = 0; r < kMapRows; r++) {
        uint64_t bucket_start = static_cast<uint64_t>(r) * total_inst_ / kMapRows;
        uint64_t bucket_end   = static_cast<uint64_t>(r + 1) * total_inst_ / kMapRows;
        if (bucket_start >= total_inst_) break;
        bucket_end = std::min(bucket_end, total_inst_);

        // Is current instruction in this bucket?
        bool is_current_bucket = (current_inst_ >= bucket_start && current_inst_ < bucket_end);

        // Classify bucket
        bool has_bookmark = false;
        bool has_taint = false;
        bool has_back_taint = false;
        bool has_loop_header = false;
        bool has_loop_body = false;
        bool has_call = false;

        uint64_t bucket_size = bucket_end - bucket_start;
        uint64_t sample_step = std::max(uint64_t(1), bucket_size / 6);
        for (uint64_t sid = bucket_start; sid < bucket_end; sid += sample_step) {
            auto srow = fetch_row(sid);
            if (srow.has_bookmark) has_bookmark = true;
            if (show_taint_ && taint_result_ && taint_result_->has_event_at(sid))
                has_taint = true;
            if (show_backward_taint_ && backward_taint_result_ &&
                backward_taint_result_->is_contributing(sid))
                has_back_taint = true;
            if (show_loops_ && loop_result_) {
                if (loop_result_->is_loop_header(srow.pc)) has_loop_header = true;
                else if (loop_result_->is_in_loop(srow.pc)) has_loop_body = true;
            }
            if (function_result_ && function_result_->call_at(sid)) has_call = true;
        }

        // Choose display character and color
        std::string ch;
        Color col;
        if (has_bookmark)        { ch = "\xE2\x97\x86"; col = Color::RGB(255, 220, 40);  }  // ◆
        else if (has_back_taint) { ch = "\xe2\x96\x93"; col = Color::Red;                }  // ▓
        else if (has_taint)      { ch = "\xe2\x96\x92"; col = Color::Green;              }  // ▒
        else if (has_loop_header){ ch = "\xE2\x87\x86"; col = Color::RGB(255, 140, 30);  }  // ⇆
        else if (has_loop_body)  { ch = "\xe2\x96\x91"; col = Color::RGB(180, 100, 30);  }  // ░
        else if (has_call)       { ch = "\xe2\x94\x80"; col = Color::Blue;               }  // ─
        else                     { ch = "\xe2\x96\x91"; col = Color::GrayDark;           }  // ░

        // Current bucket highlight
        auto cell = text(ch) | color(col);
        if (is_current_bucket) {
            cell = hbox({ text(">") | color(Color::White), cell });
        } else {
            cell = hbox({ text(" "), cell });
        }
        rows.push_back(cell);
    }

    // Progress percentage at bottom
    float pct = total_inst_ > 0 ? static_cast<float>(current_inst_) * 100.0f / total_inst_ : 0.0f;
    rows.push_back(separator());
    rows.push_back(text(fmt::format("{:.0f}%", pct)) | color(Color::GrayLight));

    return vbox(rows) | size(WIDTH, EQUAL, 5) | border;
}

void TuiApp::rebuild_taint_jump_list() {
    taint_jump_list_.clear();
    taint_jump_cursor_ = 0;

    // Collect tainted inst IDs from whichever analysis is active
    if (show_taint_ && taint_result_) {
        for (uint64_t i = 0; i < total_inst_; i++) {
            if (taint_result_->has_event_at(i)) taint_jump_list_.push_back(i);
        }
    } else if (show_slice_ && slice_result_) {
        for (uint64_t i = 0; i < total_inst_; i++) {
            if (slice_result_->is_in_slice(i)) taint_jump_list_.push_back(i);
        }
    } else if (show_backward_taint_ && backward_taint_result_) {
        for (uint64_t i = 0; i < total_inst_; i++) {
            if (backward_taint_result_->is_contributing(i)) taint_jump_list_.push_back(i);
        }
    }

    // Position cursor near current instruction
    if (!taint_jump_list_.empty()) {
        auto it = std::lower_bound(taint_jump_list_.begin(), taint_jump_list_.end(), current_inst_);
        taint_jump_cursor_ = static_cast<size_t>(it - taint_jump_list_.begin());
        if (taint_jump_cursor_ >= taint_jump_list_.size()) {
            taint_jump_cursor_ = taint_jump_list_.size() - 1;
        }
    }
}

void TuiApp::goto_taint_next() {
    if (taint_jump_list_.empty()) {
        rebuild_taint_jump_list();
        if (taint_jump_list_.empty()) return;
    }
    // Move to next entry strictly after current position
    for (size_t i = 0; i < taint_jump_list_.size(); i++) {
        size_t idx = (taint_jump_cursor_ + 1 + i) % taint_jump_list_.size();
        if (taint_jump_list_[idx] > current_inst_ ||
            taint_jump_list_.size() == 1) {
            taint_jump_cursor_ = idx;
            navigate_to(taint_jump_list_[idx]);
            return;
        }
    }
    // Wrap around
    taint_jump_cursor_ = 0;
    navigate_to(taint_jump_list_[0]);
}

void TuiApp::goto_taint_prev() {
    if (taint_jump_list_.empty()) {
        rebuild_taint_jump_list();
        if (taint_jump_list_.empty()) return;
    }
    // Move to previous entry strictly before current position
    for (size_t i = 0; i < taint_jump_list_.size(); i++) {
        size_t idx;
        if (taint_jump_cursor_ == 0) {
            idx = taint_jump_list_.size() - 1 - i;
        } else {
            idx = (taint_jump_cursor_ - 1 + taint_jump_list_.size() - i) % taint_jump_list_.size();
        }
        if (taint_jump_list_[idx] < current_inst_ ||
            taint_jump_list_.size() == 1) {
            taint_jump_cursor_ = idx;
            navigate_to(taint_jump_list_[idx]);
            return;
        }
    }
    // Wrap around
    taint_jump_cursor_ = taint_jump_list_.size() - 1;
    navigate_to(taint_jump_list_[taint_jump_cursor_]);
}

// ─── Analysis passes ────────────────────────────────────────────────────────

void TuiApp::run_taint_analysis() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }

    // Configure taint: start with current instruction's modified registers as sources
    TaintConfig config;
    config.taint_from_memory = true;
    config.track_memory_sinks = true;
    config.propagate_arithmetic = true;
    config.propagate_moves = true;
    config.max_instructions = 100000;

    // Use current instruction's register diffs as initial taint sources
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.source_regs.insert(diff.index);
        }
    }

    pass_manager_->register_pass(std::make_unique<TaintPass>(config));
    auto& result = pass_manager_->require("taint");
    if (result.ok()) {
        taint_result_ = &result.get<TaintResult>();
        show_taint_ = true;
        show_slice_ = false;
        taint_jump_list_.clear();  // Will be rebuilt lazily
    }
}

void TuiApp::run_slice_analysis() {
    if (!taint_result_) {
        // Need taint first
        run_taint_analysis();
    }
    if (!taint_result_) return;

    // Determine which register to slice from current instruction
    uint8_t target_reg = 0;
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        if (inst.reg_diff_count > 0) {
            target_reg = inst.reg_diff(0).index;
        }
    }

    pass_manager_->register_pass(
        std::make_unique<SlicePass>(current_inst_, target_reg));
    auto& result = pass_manager_->require("slice");
    if (result.ok()) {
        slice_result_ = &result.get<SliceResult>();
        show_slice_ = true;
        show_taint_ = false;
        taint_jump_list_.clear();
    }
}

void TuiApp::run_backward_taint_analysis() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }

    // Configure backward taint: current instruction is the sink
    BackwardTaintConfig config;
    config.sink_inst_id = current_inst_;
    config.propagate_through_memory = true;
    config.max_steps = 500000;
    config.max_tainted_insts = 50000;

    // Use current instruction's register diffs as sink registers
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.sink_regs.insert(diff.index);
        }
    }

    if (config.sink_regs.empty()) {
        // No reg diffs at this instruction — default to X0
        config.sink_regs.insert(0);
    }

    pass_manager_->register_pass(std::make_unique<BackwardTaintPass>(std::move(config)));
    auto& result = pass_manager_->require("backward_taint");
    if (result.ok()) {
        backward_taint_result_ = &result.get<BackwardTaintResult>();
        show_backward_taint_ = true;
        show_taint_ = false;
        show_slice_ = false;
        taint_jump_list_.clear();
    }
}

void TuiApp::clear_analysis() {
    taint_result_ = nullptr;
    slice_result_ = nullptr;
    backward_taint_result_ = nullptr;
    function_result_ = nullptr;
    xref_result_ = nullptr;
    string_result_ = nullptr;
    call_graph_result_ = nullptr;
    loop_result_ = nullptr;
    show_taint_ = false;
    show_slice_ = false;
    show_backward_taint_ = false;
    show_callstack_ = false;
    show_functions_ = false;
    show_strings_ = false;
    show_loops_ = false;
    xref_cursor_ = 0;
    string_cursor_ = 0;
    string_filter_.clear();
    filtered_string_indices_.clear();
    function_cursor_ = 0;
    function_filter_.clear();
    sorted_function_pcs_.clear();
    filtered_function_indices_.clear();
    function_panel_focused_ = false;
    callstack_panel_focused_ = false;
    callstack_cursor_ = 0;
    taint_jump_list_.clear();
    taint_jump_cursor_ = 0;
    memory_panel_focused_ = false;
    memory_access_cursor_ = 0;
    if (pass_manager_) {
        pass_manager_->invalidate_all();
    }
}

void TuiApp::run_function_analysis() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }

    pass_manager_->register_pass(std::make_unique<FunctionPass>());
    auto& result = pass_manager_->require("function");
    if (result.ok()) {
        function_result_ = &result.get<FunctionResult>();
        show_callstack_ = true;
    }
}

void TuiApp::run_xref_analysis() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }

    pass_manager_->register_pass(std::make_unique<XrefPass>());
    auto& result = pass_manager_->require("xref");
    if (result.ok()) {
        xref_result_ = &result.get<XrefResult>();
        xref_cursor_ = 0;
    }
}

Element TuiApp::render_callstack_panel() {
    Elements lines;
    // Header with focus indicator
    auto header_label = callstack_panel_focused_
        ? text("[CALL STACK]") | bold | bgcolor(Color::Blue) | color(Color::White)
        : text("Call Stack") | bold | color(Color::Yellow);
    lines.push_back(header_label);
    lines.push_back(separator());

    if (!function_result_) {
        lines.push_back(text("(not computed)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 30) | border;
    }

    auto stack = function_result_->call_stack_at(current_inst_);
    if (stack.empty()) {
        lines.push_back(text("<top-level>") | color(Color::GrayLight));
    } else {
        // Show from bottom (deepest) to top, with callstack_cursor_ highlighting
        for (size_t i = 0; i < stack.size(); i++) {
            auto* evt = stack[i];
            uint64_t static_target = evt->target_pc - reader_.header().module_slide;
            std::string label;

            // Look up function name
            auto it = function_result_->functions.find(evt->target_pc);
            if (it != function_result_->functions.end()) {
                label = it->second.name;
            } else {
                label = fmt::format("sub_{:x}", static_target);
            }

            bool is_frame_cursor = callstack_panel_focused_ && (callstack_cursor_ == i);
            bool is_current_frame = (i == stack.size() - 1);

            auto frame_marker = text(is_frame_cursor ? ">" : (is_current_frame ? "*" : " "))
                | color(is_frame_cursor ? Color::White : Color::Yellow);

            auto depth_prefix = std::string(i * 2, ' ');
            auto line = hbox({
                text(depth_prefix) | size(WIDTH, EQUAL, static_cast<int>(i * 2)),
                frame_marker,
                text(" "),
                text(label) | color(Color::Cyan),
                text(fmt::format("  @{}", evt->call_inst_id)) | color(Color::GrayLight),
            });

            if (is_frame_cursor) {
                line = line | bgcolor(Color::GrayDark);
            }
            lines.push_back(line);
        }
    }

    // Show current function
    lines.push_back(separator());
    auto* func = function_result_->function_at(current_inst_);
    if (func) {
        lines.push_back(hbox({
            text("In: ") | color(Color::White),
            text(func->name) | color(Color::Cyan),
            text(fmt::format("  (calls={})", func->total_calls)) | color(Color::GrayLight),
        }));
    }

    // Show xref info for current PC
    if (xref_result_) {
        auto row = fetch_row(current_inst_);
        auto exec_count = xref_result_->execution_count(row.pc);
        if (exec_count > 0) {
            lines.push_back(separator());
            lines.push_back(hbox({
                text("PC xrefs: ") | color(Color::White),
                text(fmt::format("{} executions", exec_count)) | color(Color::Magenta),
                text(fmt::format("  [{}]", xref_cursor_ + 1)) | color(Color::GrayLight),
            }));
        }
    }

    // Footer hint when focused
    if (callstack_panel_focused_) {
        lines.push_back(separator());
        lines.push_back(text("j/k:frame Enter:call-site c:func-entry Esc:unfocus") | color(Color::GrayDark));
    }

    return vbox(lines) | size(WIDTH, GREATER_THAN, 30) | border;
}

bool TuiApp::handle_callstack_panel_event(Event event) {
    if (event == Event::Escape) {
        callstack_panel_focused_ = false;
        return true;
    }

    auto stack = function_result_->call_stack_at(current_inst_);
    if (stack.empty()) {
        if (event == Event::Escape) {
            callstack_panel_focused_ = false;
        }
        return true;
    }

    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (callstack_cursor_ + 1 < stack.size()) {
            callstack_cursor_++;
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (callstack_cursor_ > 0) {
            callstack_cursor_--;
        }
        return true;
    }

    if (event == Event::Return) {
        // Jump to the call site (the bl/blr instruction that made this call)
        if (callstack_cursor_ < stack.size()) {
            auto* evt = stack[callstack_cursor_];
            navigate_to(evt->call_inst_id);
            callstack_panel_focused_ = false;
        }
        return true;
    }

    if (event == Event::Character('c') || event == Event::Character('C')) {
        // Jump to the function entry (first instruction of the callee)
        if (callstack_cursor_ < stack.size()) {
            auto* evt = stack[callstack_cursor_];
            navigate_to(evt->call_inst_id + 1);  // +1 = first inst in callee
            callstack_panel_focused_ = false;
        }
        return true;
    }

    if (event == Event::Character('g')) {
        callstack_cursor_ = 0;
        return true;
    }
    if (event == Event::Character('G')) {
        if (!stack.empty()) callstack_cursor_ = stack.size() - 1;
        return true;
    }

    return false;
}

void TuiApp::follow_call() {
    if (!function_result_) return;

    auto* evt = function_result_->call_at(current_inst_);
    if (evt && evt->call_inst_id + 1 < total_inst_) {
        // Jump to the first instruction of the callee
        navigate_to(evt->call_inst_id + 1);
    }
}

void TuiApp::follow_return() {
    if (!function_result_) return;

    auto* evt = function_result_->return_at(current_inst_);
    if (evt) {
        // Jump back to the instruction after the call site
        navigate_to(evt->call_inst_id);
    } else {
        // Not at a ret; try to find the calling frame and go back
        auto stack = function_result_->call_stack_at(current_inst_);
        if (!stack.empty()) {
            navigate_to(stack.back()->call_inst_id);
        }
    }
}

void TuiApp::goto_xref_next() {
    if (!xref_result_) {
        run_xref_analysis();
        if (!xref_result_) return;
    }

    auto row = fetch_row(current_inst_);
    auto xrefs = xref_result_->inst_ids_at(row.pc);
    if (xrefs.empty()) return;

    // Find current position in xref list
    xref_cursor_++;
    if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
    navigate_to(xrefs[xref_cursor_]);
}

void TuiApp::goto_xref_prev() {
    if (!xref_result_) {
        run_xref_analysis();
        if (!xref_result_) return;
    }

    auto row = fetch_row(current_inst_);
    auto xrefs = xref_result_->inst_ids_at(row.pc);
    if (xrefs.empty()) return;

    if (xref_cursor_ == 0) {
        xref_cursor_ = xrefs.size() - 1;
    } else {
        xref_cursor_--;
    }
    navigate_to(xrefs[xref_cursor_]);
}

// ─── Function list panel ──────────────────────────────────────────────────────

void TuiApp::run_call_graph_analysis() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }

    pass_manager_->register_pass(std::make_unique<CallGraphPass>());
    auto& result = pass_manager_->require("call_graph");
    if (result.ok()) {
        call_graph_result_ = &result.get<CallGraphResult>();
    }
}

void TuiApp::update_function_list() {
    if (!function_result_) return;

    // Build sorted list of function PCs
    sorted_function_pcs_.clear();
    sorted_function_pcs_.reserve(function_result_->functions.size());
    for (const auto& [pc, info] : function_result_->functions) {
        sorted_function_pcs_.push_back(pc);
    }

    // Sort based on mode
    switch (function_sort_mode_) {
    case 0: // by call count descending
        std::sort(sorted_function_pcs_.begin(), sorted_function_pcs_.end(),
            [&](uint64_t a, uint64_t b) {
                return function_result_->functions.at(a).total_calls >
                       function_result_->functions.at(b).total_calls;
            });
        break;
    case 1: // by name
        std::sort(sorted_function_pcs_.begin(), sorted_function_pcs_.end(),
            [&](uint64_t a, uint64_t b) {
                return function_result_->functions.at(a).name <
                       function_result_->functions.at(b).name;
            });
        break;
    case 2: // by entry PC
        std::sort(sorted_function_pcs_.begin(), sorted_function_pcs_.end());
        break;
    }

    update_function_filter();
}

void TuiApp::update_function_filter() {
    filtered_function_indices_.clear();
    if (!function_result_) return;

    if (function_filter_.empty()) {
        for (size_t i = 0; i < sorted_function_pcs_.size(); i++) {
            filtered_function_indices_.push_back(i);
        }
    } else {
        // Case-insensitive substring match on function name
        std::string lower_filter = function_filter_;
        std::transform(lower_filter.begin(), lower_filter.end(),
                       lower_filter.begin(), ::tolower);
        for (size_t i = 0; i < sorted_function_pcs_.size(); i++) {
            const auto& info = function_result_->functions.at(sorted_function_pcs_[i]);
            std::string lower_name = info.name;
            std::transform(lower_name.begin(), lower_name.end(),
                           lower_name.begin(), ::tolower);
            if (lower_name.find(lower_filter) != std::string::npos) {
                filtered_function_indices_.push_back(i);
            }
        }
    }

    if (function_cursor_ >= filtered_function_indices_.size()) {
        function_cursor_ = filtered_function_indices_.empty() ? 0 :
                           filtered_function_indices_.size() - 1;
    }
}

void TuiApp::open_function_filter_dialog() {
    show_function_filter_dialog_ = true;
    function_filter_input_.clear();
}

void TuiApp::close_function_filter_dialog() {
    show_function_filter_dialog_ = false;
    function_filter_input_.clear();
}

void TuiApp::execute_function_filter() {
    function_filter_ = function_filter_input_;
    update_function_filter();
    function_cursor_ = 0;
    close_function_filter_dialog();
}

bool TuiApp::handle_function_panel_event(Event event) {
    if (event == Event::Escape) {
        function_panel_focused_ = false;
        return true;
    }
    if (event == Event::Character('j') || event == Event::ArrowDown) {
        if (!filtered_function_indices_.empty() &&
            function_cursor_ < filtered_function_indices_.size() - 1) {
            function_cursor_++;
        }
        return true;
    }
    if (event == Event::Character('k') || event == Event::ArrowUp) {
        if (function_cursor_ > 0) {
            function_cursor_--;
        }
        return true;
    }
    if (event == Event::Return) {
        // Jump to the first call of this function
        if (!filtered_function_indices_.empty() &&
            function_cursor_ < filtered_function_indices_.size()) {
            size_t idx = filtered_function_indices_[function_cursor_];
            uint64_t pc = sorted_function_pcs_[idx];
            const auto& info = function_result_->functions.at(pc);
            if (!info.call_event_indices.empty()) {
                // Jump to first invocation (call_inst_id + 1 = first instruction in callee)
                const auto& evt = function_result_->call_events[info.call_event_indices[0]];
                navigate_to(evt.call_inst_id + 1);
            }
            function_panel_focused_ = false;
        }
        return true;
    }
    if (event == Event::Character('/')) {
        open_function_filter_dialog();
        return true;
    }
    if (event == Event::Character('c') || event == Event::Character('C')) {
        // Clear filter
        function_filter_.clear();
        update_function_filter();
        function_cursor_ = 0;
        return true;
    }
    if (event == Event::Character('s') || event == Event::Character('S')) {
        // Cycle sort mode
        function_sort_mode_ = (function_sort_mode_ + 1) % 3;
        update_function_list();
        function_cursor_ = 0;
        return true;
    }
    if (event == Event::Character('G')) {
        if (!filtered_function_indices_.empty()) {
            function_cursor_ = filtered_function_indices_.size() - 1;
        }
        return true;
    }
    if (event == Event::Character('g')) {
        function_cursor_ = 0;
        return true;
    }
    return false;
}

Element TuiApp::render_functions_panel() {
    Elements lines;

    // Header
    const char* sort_label = "calls";
    if (function_sort_mode_ == 1) sort_label = "name";
    else if (function_sort_mode_ == 2) sort_label = "addr";

    lines.push_back(hbox({
        text("Functions") | bold | color(Color::Yellow),
        text(fmt::format("  ({}/{}) sort:{}",
            filtered_function_indices_.size(),
            function_result_ ? function_result_->functions.size() : 0,
            sort_label)) | color(Color::GrayLight),
    }));

    if (!function_filter_.empty()) {
        lines.push_back(hbox({
            text("  filter: ") | color(Color::GrayLight),
            text(function_filter_) | color(Color::Cyan),
        }));
    }
    lines.push_back(separator());

    if (!function_result_ || filtered_function_indices_.empty()) {
        lines.push_back(text("(no functions)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 42) | border;
    }

    // Show a window of functions around the cursor
    const int visible_count = 14;
    int start = 0;
    int total = static_cast<int>(filtered_function_indices_.size());
    if (total > visible_count) {
        start = static_cast<int>(function_cursor_) - visible_count / 2;
        if (start < 0) start = 0;
        if (start + visible_count > total) start = total - visible_count;
    }
    int end = std::min(start + visible_count, total);

    for (int i = start; i < end; i++) {
        size_t idx = filtered_function_indices_[i];
        uint64_t pc = sorted_function_pcs_[idx];
        const auto& info = function_result_->functions.at(pc);
        bool is_cursor = (static_cast<size_t>(i) == function_cursor_);

        uint64_t static_pc = pc - reader_.header().module_slide;

        // Truncate name for display
        std::string display_name = info.name;
        if (display_name.size() > 22) {
            display_name = display_name.substr(0, 19) + "...";
        }

        auto line = hbox({
            text(is_cursor ? ">" : " ") | color(Color::Yellow),
            text(fmt::format("{:x}", static_pc)) | color(Color::Cyan),
            text(" ") | size(WIDTH, EQUAL, 1),
            text(display_name) | color(Color::White),
            text(fmt::format(" c={} i={}",
                info.total_calls, info.total_instructions)) | color(Color::GrayLight),
        });

        if (is_cursor) {
            line = line | bgcolor(Color::GrayDark);
        }
        lines.push_back(line);
    }

    // Callers/callees sub-view for selected function
    if (call_graph_result_ && !filtered_function_indices_.empty() &&
        function_cursor_ < filtered_function_indices_.size()) {
        size_t idx = filtered_function_indices_[function_cursor_];
        uint64_t pc = sorted_function_pcs_[idx];
        auto* node = call_graph_result_->node_at(pc);
        if (node) {
            lines.push_back(separator());
            // Show callees
            if (!node->outgoing_edges.empty()) {
                lines.push_back(text("Callees:") | color(Color::Green));
                int shown = 0;
                for (auto edge_idx : node->outgoing_edges) {
                    if (shown >= 4) {
                        lines.push_back(text(fmt::format("  ...+{} more",
                            node->outgoing_edges.size() - 4)) | color(Color::GrayLight));
                        break;
                    }
                    const auto& edge = call_graph_result_->edges[edge_idx];
                    auto callee_it = function_result_->functions.find(edge.callee_pc);
                    std::string callee_name = callee_it != function_result_->functions.end()
                        ? callee_it->second.name
                        : fmt::format("sub_{:x}", edge.callee_pc - reader_.header().module_slide);
                    if (callee_name.size() > 18) callee_name = callee_name.substr(0, 15) + "...";
                    lines.push_back(hbox({
                        text(fmt::format("  {} x{}", callee_name, edge.call_count))
                            | color(Color::GrayLight),
                    }));
                    shown++;
                }
            }
            // Show callers
            if (!node->incoming_edges.empty()) {
                lines.push_back(text("Callers:") | color(Color::Magenta));
                int shown = 0;
                for (auto edge_idx : node->incoming_edges) {
                    if (shown >= 4) {
                        lines.push_back(text(fmt::format("  ...+{} more",
                            node->incoming_edges.size() - 4)) | color(Color::GrayLight));
                        break;
                    }
                    const auto& edge = call_graph_result_->edges[edge_idx];
                    auto caller_it = function_result_->functions.find(edge.caller_pc);
                    std::string caller_name = caller_it != function_result_->functions.end()
                        ? caller_it->second.name
                        : fmt::format("sub_{:x}", edge.caller_pc - reader_.header().module_slide);
                    if (caller_name.size() > 18) caller_name = caller_name.substr(0, 15) + "...";
                    lines.push_back(hbox({
                        text(fmt::format("  {} x{}", caller_name, edge.call_count))
                            | color(Color::GrayLight),
                    }));
                    shown++;
                }
            }
        }
    }

    // Footer with help
    lines.push_back(separator());
    lines.push_back(text("j/k:nav Enter:jump /:filter s:sort") | color(Color::GrayDark));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 42) | border;
}

// ─── String analysis ────────────────────────────────────────────────────────

void TuiApp::run_string_analysis() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }

    pass_manager_->register_pass(std::make_unique<StringPass>());
    auto& result = pass_manager_->require("strings");
    if (result.ok()) {
        string_result_ = &result.get<StringResult>();
        show_strings_ = true;
        string_cursor_ = 0;
        update_string_filter();
    }
}

void TuiApp::update_string_filter() {
    filtered_string_indices_.clear();
    if (!string_result_) return;

    if (string_filter_.empty()) {
        // Show all strings
        for (size_t i = 0; i < string_result_->strings.size(); i++) {
            filtered_string_indices_.push_back(i);
        }
    } else {
        // Case-insensitive substring match
        auto results = string_result_->search(string_filter_);
        for (auto* ref : results) {
            // Find index in strings vector
            size_t idx = static_cast<size_t>(ref - string_result_->strings.data());
            filtered_string_indices_.push_back(idx);
        }
    }

    if (string_cursor_ >= filtered_string_indices_.size()) {
        string_cursor_ = filtered_string_indices_.empty() ? 0 : filtered_string_indices_.size() - 1;
    }
}

void TuiApp::open_string_search_dialog() {
    show_string_search_dialog_ = true;
    string_search_input_.clear();
}

void TuiApp::close_string_search_dialog() {
    show_string_search_dialog_ = false;
    string_search_input_.clear();
}

void TuiApp::execute_string_search() {
    string_filter_ = string_search_input_;
    update_string_filter();
    string_cursor_ = 0;
    close_string_search_dialog();
}

Element TuiApp::render_strings_panel() {
    Elements lines;

    // Header
    lines.push_back(hbox({
        text("Strings") | bold | color(Color::Yellow),
        text(fmt::format("  ({}/{})",
            filtered_string_indices_.size(),
            string_result_ ? string_result_->total() : 0)) | color(Color::GrayLight),
    }));

    if (!string_filter_.empty()) {
        lines.push_back(hbox({
            text("  filter: ") | color(Color::GrayLight),
            text(string_filter_) | color(Color::Cyan),
        }));
    }
    lines.push_back(separator());

    if (!string_result_ || filtered_string_indices_.empty()) {
        lines.push_back(text("(no strings)") | color(Color::GrayLight));
        return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
    }

    // Show a window of strings around the cursor
    const int visible_count = 12;
    int start = 0;
    int total = static_cast<int>(filtered_string_indices_.size());
    if (total > visible_count) {
        start = static_cast<int>(string_cursor_) - visible_count / 2;
        if (start < 0) start = 0;
        if (start + visible_count > total) start = total - visible_count;
    }
    int end = std::min(start + visible_count, total);

    for (int i = start; i < end; i++) {
        size_t str_idx = filtered_string_indices_[i];
        const auto& ref = string_result_->strings[str_idx];
        bool is_cursor = (static_cast<size_t>(i) == string_cursor_);

        // Truncate long strings for display
        std::string display_str = ref.content;
        if (display_str.size() > 32) {
            display_str = display_str.substr(0, 29) + "...";
        }

        // Encoding label
        const char* enc_label = "A";
        if (ref.encoding == StringRef::UTF16LE) enc_label = "U";
        else if (ref.encoding == StringRef::UTF8) enc_label = "8";
        else if (ref.encoding == StringRef::Wide) enc_label = "W";

        auto line = hbox({
            text(is_cursor ? ">" : " ") | color(Color::Yellow),
            text(fmt::format("[{}]", enc_label)) | color(Color::GrayLight),
            text(" ") | size(WIDTH, EQUAL, 1),
            text(fmt::format("{:x}", ref.addr)) | color(Color::Cyan),
            text(" ") | size(WIDTH, EQUAL, 1),
            text(fmt::format("\"{}\"", display_str)) | color(Color::Green),
            text(fmt::format(" ({})", ref.references.size())) | color(Color::GrayLight),
        });

        if (is_cursor) {
            line = line | bgcolor(Color::GrayDark);
        }
        lines.push_back(line);
    }

    // Footer with help
    lines.push_back(separator());
    lines.push_back(text("j/k:nav Enter:jump /:filter") | color(Color::GrayDark));

    return vbox(lines) | size(WIDTH, GREATER_THAN, 40) | border;
}

// ─── Run loop ───────────────────────────────────────────────────────────────

int TuiApp::run() {
    // Re-query terminal size now that we're about to enter the loop
    handle_resize();

    auto goto_input = Input(&goto_input_, "inst_id");
    auto search_input = Input(&search_input_, "pattern");
    auto string_search_input = Input(&string_search_input_, "filter");

    // Use a vertical container so we always have a focusable component
    auto function_filter_input = Input(&function_filter_input_, "filter");

    auto input_container = Container::Stacked({
        goto_input,
        search_input,
        string_search_input,
        function_filter_input,
    });

    auto app = Renderer(input_container, [&] {
        Element document = render_main_layout();
        if (show_goto_dialog_) {
            auto dialog = window(text(" Goto Instruction "), goto_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_search_dialog_) {
            auto dialog = window(text(" Search "), search_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_string_search_dialog_) {
            auto dialog = window(text(" Filter Strings "), string_search_input->Render()) | center;
            document = dbox({document, dialog});
        } else if (show_function_filter_dialog_) {
            auto dialog = window(text(" Filter Functions "), function_filter_input->Render()) | center;
            document = dbox({document, dialog});
        }
        return document;
    });

    app |= CatchEvent([&](Event event) {
        // Dialog mode: handle Enter/Escape, let input component handle the rest
        if (show_goto_dialog_) {
            if (event == Event::Return) {
                execute_goto();
                return true;
            }
            if (event == Event::Escape) {
                close_goto_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_search_dialog_) {
            if (event == Event::Return) {
                execute_search();
                return true;
            }
            if (event == Event::Escape) {
                close_search_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_string_search_dialog_) {
            if (event == Event::Return) {
                execute_string_search();
                return true;
            }
            if (event == Event::Escape) {
                close_string_search_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }
        if (show_function_filter_dialog_) {
            if (event == Event::Return) {
                execute_function_filter();
                return true;
            }
            if (event == Event::Escape) {
                close_function_filter_dialog();
                return true;
            }
            return false;  // Let input component handle typing
        }

        return handle_event(event);
    });

    try {
        screen_.Loop(app);
    } catch (const std::exception& e) {
        // Ensure terminal is restored on exception
        fmt::print(stderr, "\nFatal TUI error: {}\n", e.what());
        fmt::print(stderr, "Run with -c for batch mode if TUI is unavailable.\n");
        return 1;
    }
    return 0;
}

// ─── Batch mode ─────────────────────────────────────────────────────────────

int TuiApp::batch_mode(uint64_t start_id, uint64_t count, bool show_regs, bool show_mem) {
    (void)show_regs;
    (void)show_mem;

    const auto& hdr = reader_.header();

    fmt::print("Disassembly (inst_id {} to {}):\n", start_id, start_id + count - 1);
    fmt::print("{}\n", std::string(72, '-'));

    for (uint64_t i = 0; i < count && start_id + i < total_inst_; i++) {
        uint64_t id = start_id + i;
        auto row = fetch_row(id);

        fmt::print("{:>8}  {:016x}  {}\n", id, row.static_pc, row.disasm);

        if (show_regs && row.reg_diff_count > 0) {
            uint64_t offset = index_.offset_of(id, reader_);
            auto rec = reader_.record_at(offset);
            auto inst = rec.as_inst();
            fmt::print("          ");
            for (uint8_t j = 0; j < inst.reg_diff_count; j++) {
                auto diff = inst.reg_diff(j);
                fmt::print("{}=0x{:x} ", reg_name(diff.index), diff.value);
            }
            fmt::print("\n");
        }

        if (show_mem && row.mem_access_count > 0) {
            uint64_t offset = index_.offset_of(id, reader_);
            auto rec = reader_.record_at(offset);
            auto inst = rec.as_inst();
            for (uint8_t j = 0; j < inst.mem_access_count; j++) {
                auto mem = inst.mem_access(j);
                const char* type_str = (mem.type & 2) ? "W" : "R";
                fmt::print("          [{}] 0x{:x} size={} val=0x{:x}\n",
                           type_str, mem.addr, mem.size, mem.value);
            }
        }
    }

    fmt::print("{}\n", std::string(72, '-'));

    if (show_regs) {
        uint64_t last_id = std::min(start_id + count - 1, total_inst_ - 1);
        fmt::print("\nRegister state before inst_id={}:\n", last_id);
        const auto& state = regfile_.state_before(last_id);
        for (int i = 0; i < 29; i += 4) {
            fmt::print("  x{:<2}=0x{:016x}  x{:<2}=0x{:016x}  x{:<2}=0x{:016x}  x{:<2}=0x{:016x}\n",
                       i, state.gpr[i], i+1, state.gpr[i+1],
                       i+2, state.gpr[i+2], i+3, state.gpr[i+3]);
        }
        fmt::print("  fp =0x{:016x}  lr =0x{:016x}  sp =0x{:016x}\n",
                   state.fp(), state.lr(), state.sp());
        fmt::print("  pc =0x{:016x}  nzcv={}\n", state.pc(), state.nzcv());
        auto stats = regfile_.cache_stats();
        fmt::print("\n  Cache stats: hits={} misses={}\n", stats.hits, stats.misses);
    }

    return 0;
}

}  // namespace tenet

#include "tui/panels/register_panel.h"
#include "tui/tui_context.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "core/register_file.h"

#include <fmt/format.h>

using namespace ftxui;

namespace tenet {

// ─── Helpers ───────────────────────────────────────────────────────────────

static std::string reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == 29) return "fp";
    if (idx == 30) return "lr";
    if (idx == 31) return "sp";
    if (idx == 32) return "nzcv";
    if (idx == 33) return "pc";
    return "??";
}

// ─── Render ────────────────────────────────────────────────────────────────

Element RegisterPanel::render() {
    const auto& state = ctx_.regfile->state_before(ctx_.current_inst);

    // Determine which registers are read / written by the current instruction.
    std::vector<uint8_t> read_regs, write_regs;
    {
        auto [offset, seed_pc] = ctx_.index->offset_of_with_pc(
            ctx_.current_inst, *ctx_.reader);
        auto rec = ctx_.reader->record_at(offset, seed_pc);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                write_regs.push_back(inst.reg_diff(i).index);
            }
            auto opcode = ctx_.code_table->opcode_at(inst.pc);
            if (opcode) {
                auto d = ctx_.decoder->decode(inst.pc, *opcode);
                if (d) {
                    read_regs.assign(d->regs_read.begin(),
                                     d->regs_read.begin() + d->regs_read_count);
                }
            }
        }
    }

    auto is_in = [](const std::vector<uint8_t>& vec, uint8_t idx) {
        for (auto v : vec) if (v == idx) return true;
        return false;
    };

    auto reg_value_color = [&](uint8_t idx) -> Color {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return Color::Yellow;
        if (w) return Color::RedLight;
        if (r) return Color::GreenLight;
        return Color::White;
    };

    auto reg_label_color = [&](uint8_t idx) -> Color {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return Color::Yellow;
        if (w) return Color::Red;
        if (r) return Color::Green;
        return Color::Cyan;
    };

    // ── Header ─────────────────────────────────────────────────────────
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

    // ── GPR x0–x28 (two per row) ──────────────────────────────────────
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

    // ── Special registers ─────────────────────────────────────────────
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
    if (ctx_.show_nzcv) {
        reg_lines.push_back(hbox({
            text("nzcv=") | color(reg_label_color(IDX_NZCV)),
            text(fmt::format("{:x}", state.nzcv())) | color(reg_value_color(IDX_NZCV)),
        }));
    }

    // ── NEON FPR v0–v31 ───────────────────────────────────────────────
    if (ctx_.reader->header().has_fpr()) {
        reg_lines.push_back(separator());
        if (ctx_.show_fpr) {
            reg_lines.push_back(hbox({
                text("NEON v0–v31") | bold | color(Color::Magenta),
                text("  (V to hide)") | color(Color::GrayLight),
            }));
            reg_lines.push_back(separator());
            for (uint8_t vi = 0; vi < AARCH64_FPR_COUNT; ++vi) {
                const FprValue& fval = state.fpr[vi];
                bool fpr_written = false;
                {
                    auto [off, spc] = ctx_.index->offset_of_with_pc(
                        ctx_.current_inst, *ctx_.reader);
                    auto frec = ctx_.reader->record_at(off, spc);
                    if (frec.kind == RecordKind::Inst) {
                        auto fi = frec.as_inst();
                        for (uint8_t fd = 0; fd < fi.fpr_diff_count; fd++) {
                            if (fi.fpr_diff(fd).index == vi) { fpr_written = true; break; }
                        }
                    }
                }
                Color vname_col = fpr_written ? Color::RedLight : Color::Magenta;
                Color val_col   = fpr_written ? Color::RedLight : Color::White;
                auto fpr_line = hbox({
                    text(fmt::format("v{:<2}=", vi)) | color(vname_col),
                    text(fmt::format("{:016x}", fval.hi)) | color(val_col),
                    text(":") | color(Color::GrayLight),
                    text(fmt::format("{:016x}", fval.lo)) | color(val_col),
                });
                reg_lines.push_back(fpr_line);
            }
        } else {
            reg_lines.push_back(hbox({
                text("NEON v0–v31") | bold | color(Color::GrayDark),
                text("  (V to show)") | color(Color::GrayLight),
            }));
        }
    }

    // ── Checkpoint stats ────────────────────────────────────────────
    reg_lines.push_back(separator());
    auto stats = ctx_.regfile->cache_stats();
    reg_lines.push_back(text(fmt::format("Checkpoints: {} queries / {} fallbacks",
                                         stats.ckpt_queries,
                                         stats.ckpt_fallbacks))
                        | color(Color::GrayLight));

    return vbox(reg_lines) | size(WIDTH, GREATER_THAN, 38) | border;
}

// ─── Event handling ────────────────────────────────────────────────────────

bool RegisterPanel::handle_event(ftxui::Event event) {
    (void)event;
    return false;
}

}  // namespace tenet

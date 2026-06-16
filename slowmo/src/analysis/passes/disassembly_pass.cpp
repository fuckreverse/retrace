#include "analysis/passes/disassembly_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <string_view>

namespace tenet {

PassResult DisassemblyPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    const auto& hdr = reader.header();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    std::vector<DisasmEntry> entries;
    entries.reserve(end - start);

    uint64_t inst_id = 0;
    uint64_t processed = 0;
    uint64_t total = end - start;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        if (inst_id < start) {
            inst_id++;
            continue;
        }

        auto inst = rec.as_inst();
        DisasmEntry entry;
        entry.inst_id = inst_id;
        entry.pc = inst.pc;
        entry.static_pc = inst.pc - hdr.module_slide;

        auto opcode = code_table.opcode_at(inst.pc);
        if (opcode) {
            entry.opcode = *opcode;
            auto d = decoder.decode(inst.pc, *opcode);
            if (d) {
                entry.mnemonic = d->mnemonic;
                entry.op_str = d->op_str;
                entry.full_disasm = fmt::format("{} {}", d->mnemonic, d->op_str);

                // Classify
                std::string_view m = d->mnemonic_sv();
                entry.is_branch = m.find("b.") == 0 || m.find("b ") == 0 ||
                                  m.find("cb") == 0 || m.find("tb") == 0;
                entry.is_call = m.find("bl") == 0 || m.find("blr") == 0;
                entry.is_return = m.find("ret") == 0;
                entry.is_load = m.find("ldr") == 0 || m.find("ldp") == 0 ||
                                m.find("ldur") == 0 || m.find("ldrb") == 0 ||
                                m.find("ldrh") == 0 || m.find("ldrs") == 0;
                entry.is_store = m.find("str") == 0 || m.find("stp") == 0 ||
                                 m.find("stur") == 0 || m.find("strb") == 0 ||
                                 m.find("strh") == 0;
                entry.is_system = m.find("svc") == 0 || m.find("mrs") == 0 ||
                                  m.find("msr") == 0 || m.find("dc") == 0 ||
                                  m.find("ic") == 0 || m.find("tlbi") == 0;
            } else {
                entry.full_disasm = fmt::format(".word 0x{:08x}", *opcode);
            }
        } else {
            entry.full_disasm = "<no code>";
        }

        entries.push_back(std::move(entry));
        inst_id++;
        processed++;

        if (processed % 10000 == 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
        }

        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
    }

    ctx.progress(1.0f, fmt::format("Disassembled {} instructions", entries.size()));
    return PassResult::success(std::move(entries));
}

}  // namespace tenet

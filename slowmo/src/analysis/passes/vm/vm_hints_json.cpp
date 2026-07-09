#include "analysis/passes/vm/vm_hints_json.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

namespace tenet {

using json = nlohmann::json;

namespace {

uint64_t parse_hex_str(const std::string& s) {
    return std::stoull(s, nullptr, 16);
}

/// Converts an IDA-displayed address into a runtime address:
///   runtime_pc = displayed_pc - image_base + module_slide
/// (see the address-convention comment in vm_hints_json.h). A no-op when
/// image_base == 0 (the default), preserving old behavior for callers/tests
/// that pass raw runtime addresses directly.
uint64_t rebase_hint_pc(uint64_t displayed_pc, uint64_t module_slide, uint64_t image_base) {
    if (image_base == 0) return displayed_pc;
    return displayed_pc - image_base + module_slide;
}

uint8_t parse_reg_field(const json& v) {
    if (v.is_number()) return static_cast<uint8_t>(v.get<int>());
    std::string s = v.get<std::string>();
    if (!s.empty() && (s[0] == 'x' || s[0] == 'X')) s = s.substr(1);
    return static_cast<uint8_t>(std::stoul(s));
}

OpcodeDeobfStep::Op parse_deobf_op(const std::string& s) {
    if (s == "sub")   return OpcodeDeobfStep::Op::sub;
    if (s == "add")   return OpcodeDeobfStep::Op::add;
    if (s == "xor")   return OpcodeDeobfStep::Op::xor_;
    if (s == "and")   return OpcodeDeobfStep::Op::and_;
    if (s == "or")    return OpcodeDeobfStep::Op::or_;
    if (s == "lsr")   return OpcodeDeobfStep::Op::lsr;
    if (s == "lsl")   return OpcodeDeobfStep::Op::lsl;
    if (s == "mul")   return OpcodeDeobfStep::Op::mul;
    if (s == "ror")   return OpcodeDeobfStep::Op::ror;
    if (s == "bswap") return OpcodeDeobfStep::Op::bswap;
    if (s == "neg")          return OpcodeDeobfStep::Op::neg;
    if (s == "not")          return OpcodeDeobfStep::Op::not_;
    if (s == "xor_rolling")  return OpcodeDeobfStep::Op::xor_rolling;
    if (s == "add_rolling")  return OpcodeDeobfStep::Op::add_rolling;
    if (s == "sub_rolling")  return OpcodeDeobfStep::Op::sub_rolling;
    throw std::runtime_error("Unknown deobf op: " + s);
}

}  // namespace

bool load_vm_hints_from_json(const std::string& path, VMConfig& cfg,
                             uint64_t module_slide, uint64_t image_base) {
    std::ifstream f(path);
    if (!f.good()) {
        fmt::print(stderr, "Error: VM hints file not found: {}\n", path);
        return false;
    }
    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        fmt::print(stderr, "Error: VM hints file is not valid JSON: {}\n", e.what());
        return false;
    }

    // Shorthand: parse a hex PC string field and rebase it (IDA-displayed ->
    // runtime). See rebase_hint_pc() / the address-convention comment above.
    auto rebase = [&](uint64_t displayed_pc) {
        return rebase_hint_pc(displayed_pc, module_slide, image_base);
    };

    try {
        if (j.contains("dispatcher_pc")) {
            DispatcherHint dh;
            dh.loop_header_pc = rebase(parse_hex_str(j["dispatcher_pc"].get<std::string>()));
            if (j.contains("indirect_branch_pc")) {
                dh.indirect_branch_pc = rebase(parse_hex_str(j["indirect_branch_pc"].get<std::string>()));
            }
            // Memory-write anchor (alternative to loop_header_pc for
            // heavily CFF-obfuscated VMs — see DispatcherHint docs). Unlike
            // the other PC fields, this is already documented as a runtime
            // address (derived from an observed heap pointer at
            // hint-authoring time), so it is NOT rebased — matches the MCP
            // tool's handling of mem_anchor_addr.
            if (j.contains("mem_anchor_addr")) {
                dh.mem_anchor_addr = parse_hex_str(j["mem_anchor_addr"].get<std::string>());
            }
            if (j.contains("mem_anchor_size")) {
                dh.mem_anchor_size = static_cast<uint8_t>(j["mem_anchor_size"].get<int>());
            }
            cfg.dispatcher = dh;
        }

        if (j.contains("handler_entry_pcs")) {
            for (const auto& pc_str : j["handler_entry_pcs"]) {
                cfg.handler_entry_pcs.push_back(rebase(parse_hex_str(pc_str.get<std::string>())));
            }
        }

        if (j.contains("dispatch_type")) {
            const std::string& dt = j["dispatch_type"].get_ref<const std::string&>();
            if      (dt == "WhileSwitch")    cfg.dispatch_type_hint = DispatchType::WhileSwitch;
            else if (dt == "IndirectBranch") cfg.dispatch_type_hint = DispatchType::IndirectBranch;
            else if (dt == "CallTable")      cfg.dispatch_type_hint = DispatchType::CallTable;
            else if (dt == "ThreadedCode")   cfg.dispatch_type_hint = DispatchType::ThreadedCode;
            else if (dt == "Trampoline")     cfg.dispatch_type_hint = DispatchType::Trampoline;
            else if (dt == "FetchOnly")      cfg.dispatch_type_hint = DispatchType::FetchOnly;
        }
        if (j.contains("threaded_dispatch_pcs")) {
            for (const auto& pc_str : j["threaded_dispatch_pcs"]) {
                cfg.threaded_dispatch_pcs.push_back(rebase(parse_hex_str(pc_str.get<std::string>())));
            }
        }

        if (j.contains("opcode_size") || j.contains("opcode_from_reg") ||
            j.contains("opcode_deobf_steps") || j.contains("opcode_byte_offset")) {
            OpcodeFormatHint ofh;
            if (j.contains("opcode_from_reg")) {
                ofh.opcode_from_reg = parse_reg_field(j["opcode_from_reg"]);
            }
            if (j.contains("opcode_size")) {
                ofh.opcode_size = static_cast<uint8_t>(j["opcode_size"].get<int>());
            }
            if (j.contains("opcode_byte_offset")) {
                ofh.opcode_byte_offset = static_cast<uint8_t>(j["opcode_byte_offset"].get<int>());
            }
            if (j.contains("opcode_mask")) {
                ofh.opcode_mask = parse_hex_str(j["opcode_mask"].get<std::string>());
            }
            ofh.opcode_shift = static_cast<uint8_t>(j.value("opcode_shift", 0));

            if (j.contains("opcode_deobf_steps")) {
                for (const auto& elem : j["opcode_deobf_steps"]) {
                    OpcodeDeobfStep ds;
                    ds.op = parse_deobf_op(elem.at("op").get<std::string>());
                    if (elem.contains("imm")) {
                        ds.imm = elem.at("imm").is_number()
                            ? elem["imm"].get<uint64_t>()
                            : parse_hex_str(elem["imm"].get<std::string>());
                    }
                    ofh.deobfuscation_steps.push_back(ds);
                }
            }
            // Rolling key update rule (only meaningful when deobf steps
            // contain xor_rolling / add_rolling / sub_rolling).
            if (j.contains("rolling_key_update")) {
                const std::string& rku = j["rolling_key_update"].get_ref<const std::string&>();
                if      (rku == "xor_opcode")  ofh.rolling_key_update = RollingKeyUpdate::XorOpcode;
                else if (rku == "add_opcode")  ofh.rolling_key_update = RollingKeyUpdate::AddOpcode;
                else if (rku == "sub_opcode")  ofh.rolling_key_update = RollingKeyUpdate::SubOpcode;
                else if (rku == "hash_opcode") ofh.rolling_key_update = RollingKeyUpdate::HashOpcode;
            }

            cfg.opcode_format = std::move(ofh);
        }

        // ── Operand format ─────────────────────────────────────────────
        if (j.contains("operand_fields") || j.contains("instruction_size")) {
            VMConfig::OperandFormatHint opfmt;
            if (j.contains("instruction_size")) {
                opfmt.instruction_size = static_cast<uint8_t>(j["instruction_size"].get<int>());
            }
            if (j.contains("operand_fields")) {
                for (const auto& fj : j["operand_fields"]) {
                    VMConfig::OperandFieldDesc fd;
                    fd.name        = fj.value("name", std::string{});
                    fd.byte_offset = static_cast<uint8_t>(fj.value("byte_offset", 0));
                    fd.size        = static_cast<uint8_t>(fj.value("size", 1));
                    if (fj.contains("mask")) {
                        fd.mask = fj["mask"].is_number()
                            ? fj["mask"].get<uint64_t>()
                            : parse_hex_str(fj["mask"].get<std::string>());
                    }
                    fd.shift = static_cast<uint8_t>(fj.value("shift", 0));
                    if (fj.contains("deobf_steps")) {
                        for (const auto& ds : fj["deobf_steps"]) {
                            OpcodeDeobfStep step;
                            step.op = parse_deobf_op(ds.at("op").get<std::string>());
                            if (ds.contains("imm")) {
                                step.imm = ds["imm"].is_number()
                                    ? ds["imm"].get<uint64_t>()
                                    : parse_hex_str(ds["imm"].get<std::string>());
                            }
                            fd.deobfuscation_steps.push_back(step);
                        }
                    }
                    if (!fd.name.empty()) opfmt.fields.push_back(std::move(fd));
                }
            }
            cfg.operand_format = std::move(opfmt);
        }

        if (j.contains("ctx_base_reg") || j.contains("ctx_fields")) {
            if (!cfg.vm_context.has_value()) cfg.vm_context = VMContextHint{};
            if (j.contains("ctx_base_reg")) {
                cfg.vm_context->ctx_base_reg = parse_reg_field(j["ctx_base_reg"]);
            }
            if (j.contains("ctx_fields")) {
                for (const auto& cf : j["ctx_fields"]) {
                    VMContextHint::Field field;
                    field.name       = cf.value("name", std::string{});
                    field.offset     = cf.value("offset", uint32_t(0));
                    field.size       = static_cast<uint8_t>(cf.value("size", 8));
                    field.is_pointer = cf.value("is_pointer", false);
                    if (!field.name.empty()) cfg.vm_context->fields.push_back(std::move(field));
                }
            }
        }

        if (j.contains("vm_registers") || j.contains("rf_base_reg") ||
            j.contains("vm_stack_sp_offset")) {
            VMRegisterFileHint rfh;
            if (j.contains("rf_base_reg")) rfh.rf_base_reg = parse_reg_field(j["rf_base_reg"]);
            if (j.contains("vm_registers")) {
                for (const auto& rv : j["vm_registers"]) {
                    VMRegisterFileHint::VMReg vreg;
                    vreg.name       = rv.value("name", std::string{});
                    vreg.offset     = rv.value("offset", uint32_t(0));
                    vreg.size       = static_cast<uint8_t>(rv.value("size", 8));
                    vreg.is_float   = rv.value("is_float", false);
                    vreg.is_pointer = rv.value("is_pointer", false);
                    if (rv.contains("from_host_reg")) {
                        vreg.from_host_reg = parse_reg_field(rv["from_host_reg"]);
                    }
                    if (!vreg.name.empty()) rfh.regs.push_back(std::move(vreg));
                }
            }
            if (j.contains("vm_stack_sp_offset")) {
                rfh.stack_sp_offset = j["vm_stack_sp_offset"].get<uint32_t>();
            }
            if (j.contains("vm_stack_depth")) {
                rfh.stack_depth = j["vm_stack_depth"].get<uint32_t>();
            }
            if (j.contains("vm_stack_elem_size")) {
                rfh.stack_elem_size = static_cast<uint8_t>(j["vm_stack_elem_size"].get<int>());
            }
            if (j.contains("vm_stack_direction") && j["vm_stack_direction"].is_string()) {
                if (j["vm_stack_direction"].get_ref<const std::string&>() == "ascending") {
                    rfh.stack_direction = VMRegisterFileHint::StackDirection::Ascending;
                }
            }
            cfg.vm_register_file = std::move(rfh);
        }

        if (j.contains("handler_asm_map") && j["handler_asm_map"].is_object()) {
            HandlerAsmHint hah;
            for (auto& [pc_str, lines] : j["handler_asm_map"].items()) {
                uint64_t static_pc = parse_hex_str(pc_str);
                std::vector<HandlerAsmEntry> entries;
                if (lines.is_array()) {
                    for (const auto& line : lines) {
                        HandlerAsmEntry e;
                        if (line.is_string()) {
                            e.text = line.get<std::string>();
                        } else {
                            if (line.contains("pc")) e.pc = parse_hex_str(line["pc"].get<std::string>());
                            e.text = line.value("text", std::string{});
                        }
                        if (!e.text.empty()) entries.push_back(std::move(e));
                    }
                }
                hah.handler_asm[static_pc] = std::move(entries);
            }
            cfg.handler_asm = std::move(hah);
        }

        if (j.contains("inst_file_offset_base") && j["inst_file_offset_base"].is_string()) {
            cfg.inst_file_offset_base = rebase(parse_hex_str(j["inst_file_offset_base"].get<std::string>()));
            cfg.inst_file_offset_base_set = true;
        }

        if (j.contains("handler_names") && j["handler_names"].is_object()) {
            // Unlike handler_asm_map (keyed by static PC, rebased by the UI
            // when displaying), handler_names keys are looked up directly
            // against VMHandler::entry_pc (a runtime address collected from
            // the trace) in VMAbstractPass — so they must be rebased here
            // just like dispatcher_pc/handler_entry_pcs, or an IDA-address
            // handler_names map will simply never match anything.
            for (auto& [pc_str, name] : j["handler_names"].items()) {
                if (name.is_string()) {
                    cfg.handler_names[rebase(parse_hex_str(pc_str))] = name.get<std::string>();
                }
            }
        }
    } catch (const std::exception& e) {
        fmt::print(stderr, "Error: VM hints file has invalid field(s): {}\n", e.what());
        return false;
    }

    return true;
}

}  // namespace tenet

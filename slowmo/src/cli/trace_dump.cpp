#include "cli/trace_dump.h"

#include "io/trace_reader.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"
#include "TraceFormat.h"

#include <fmt/core.h>
#include <cstring>
#include <string>

namespace tenet {

// ─── GPR / FPR register name lookup ───────────────────────────────────────

static const char* gpr_name(uint8_t idx) {
    if (idx <= 28) {
        static char buf[4];
        std::snprintf(buf, sizeof(buf), "x%u", idx);
        return buf;  // NOLINT: static storage
    }
    switch (idx) {
    case 29: return "fp";
    case 30: return "lr";
    case 31: return "sp";
    case 32: return "nzcv";
    case 33: return "pc";
    default: return "?";
    }
}

static const char* fpr_name(uint8_t idx) {
    static char buf[5];
    std::snprintf(buf, sizeof(buf), "v%u", idx);
    return buf;  // NOLINT: static storage
}

static const char* event_name(uint8_t ev) {
    switch (ev) {
    case qbditrace::QBDITRACE_EV_SEQ_ENTRY:   return "SEQ_ENTRY";
    case qbditrace::QBDITRACE_EV_SEQ_EXIT:    return "SEQ_EXIT";
    case qbditrace::QBDITRACE_EV_XFER_CALL:   return "XFER_CALL";
    case qbditrace::QBDITRACE_EV_XFER_RETURN: return "XFER_RETURN";
    default: return "UNKNOWN";
    }
}

static const char* mem_type_str(uint8_t type) {
    bool read  = (type & 0x01) != 0;
    bool write = (type & 0x02) != 0;
    if (read && write) return "RW";
    if (write)         return "W";
    if (read)          return "R";
    return "?";
}

static const char* retval_source_name(uint8_t source_kind) {
    switch (source_kind) {
    case qbditrace::QBDITRACE_REC_SVC:      return "svc";
    case qbditrace::QBDITRACE_REC_OBJC:     return "objc";
    case qbditrace::QBDITRACE_REC_CAPICALL: return "capi";
    default:                                return "unknown";
    }
}

static const char* unknown_return_label(bool has_call_metadata) {
    return has_call_metadata ? "unknown" : "unknown (legacy)";
}

static std::string capi_name(uint16_t api_id) {
    switch (api_id) {
    case qbditrace::QBDITRACE_CAPI_MEMCPY: return "memcpy";
    case 600: return "EVP_EncryptInit_ex";
    case 601: return "EVP_EncryptUpdate";
    case 602: return "EVP_EncryptFinal_ex";
    case 603: return "EVP_DecryptInit_ex";
    case 604: return "EVP_DecryptUpdate";
    case 605: return "EVP_DecryptFinal_ex";
    default:  return fmt::format("unknown_api_{}", api_id);
    }
}

static const char* syscall_name(uint64_t raw_syscall_no, TargetOS target_os) {
    if (target_os == TargetOS::iOS) {
        switch (raw_syscall_no & 0x00ffffffULL) {
        case 3:   return "read";
        case 4:   return "write";
        case 5:   return "open";
        case 6:   return "close";
        case 20:  return "getpid";
        case 26:  return "ptrace";
        case 29:  return "recv";
        case 74:  return "mprotect";
        case 97:  return "socket";
        case 98:  return "connect";
        case 133: return "send";
        case 197: return "mmap";
        case 463: return "openat";
        default:  return "unknown";
        }
    }

    switch (raw_syscall_no) {
    case 56:  return "openat";
    case 57:  return "close";
    case 63:  return "read";
    case 64:  return "write";
    case 117: return "ptrace";
    case 172: return "getpid";
    case 198: return "socket";
    default:  return "unknown";
    }
}

// ─── JSON helpers ──────────────────────────────────────────────────────────

static std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

// ─── Text format ──────────────────────────────────────────────────────────

static void dump_header_text(const FileHeader& hdr, std::ostream& out) {
    out << "=== header ===\n"
        << "  magic:       0x" << fmt::format("{:08X}", hdr.magic) << "\n"
        << "  version:     " << hdr.version << "\n"
        << "  arch:        " << (hdr.arch == 1 ? "AArch64" : "x86_64") << "\n"
        << "  num_gpr:     " << hdr.num_gpr << "\n"
        << "  module:      " << hdr.module_name << "\n"
        << "  base:        0x" << fmt::format("{:016X}", hdr.module_base) << "\n"
        << "  slide:       0x" << fmt::format("{:016X}", hdr.module_slide) << "\n"
        << "  range:       0x" << fmt::format("{:016X}", hdr.trace_start)
        << " - 0x" << fmt::format("{:016X}", hdr.trace_end) << "\n"
        << "  flags:       0x" << fmt::format("{:016X}", hdr.flags) << "\n"
        << "  target_os:   " << target_os_name(hdr.target_os) << "\n"
        << "\n";
}

static void dump_inst_text(uint64_t inst_id, const InstView& inst,
                           InstructionDecoder& decoder, const CodeTable& ct,
                           const DumpOptions& opts, std::ostream& out) {
    // Disassembly
    std::string disasm;
    auto opcode = ct.opcode_at(inst.pc);
    if (opcode) {
        disasm = decoder.format(inst.pc, *opcode);
    } else {
        disasm = fmt::format("0x{:X}: <no code>", inst.pc);
    }

    out << fmt::format("INST #{:<6} {:40s}  nzcv=0x{:02X}", inst_id, disasm, inst.nzcv);

    // Branch hint
    if (inst.branch_hint()) {
        const char* bh = "";
        switch (inst.branch_hint()) {
        case 1: bh = "CALL"; break;
        case 2: bh = "RET"; break;
        case 4: bh = "BRANCH"; break;
        default: bh = "?"; break;
        }
        out << fmt::format(" [{}]", bh);
    }
    out << "\n";

    // GPR diffs
    if (opts.include_regs && inst.reg_diff_count > 0) {
        for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
            auto diff = inst.reg_diff(d);
            out << fmt::format("    {} = 0x{:016X}\n", gpr_name(diff.index), diff.value);
        }
    }

    // FPR diffs
    if (opts.include_regs && inst.fpr_diff_count > 0) {
        for (uint8_t f = 0; f < inst.fpr_diff_count; f++) {
            auto fd = inst.fpr_diff(f);
            out << fmt::format("    fpr_diffs {} = lo:0x{:016X} hi:0x{:016X}\n",
                               fpr_name(fd.index), fd.lo, fd.hi);
        }
    }

    // Memory accesses
    if (opts.include_mem && inst.mem_access_count > 0) {
        for (uint8_t m = 0; m < inst.mem_access_count; m++) {
            auto ma = inst.mem_access(m);
            out << fmt::format("    mem {} size={}: addr=0x{:016X} val=0x{:016X}",
                               mem_type_str(ma.type), ma.size, ma.addr, ma.value);
            if (ma.value_hi) {
                out << fmt::format(" val_hi=0x{:016X}", ma.value_hi);
            }
            if (ma.has_old_value) {
                out << fmt::format(" old=0x{:016X}", ma.old_value);
                if (ma.old_value_hi) {
                    out << fmt::format(" old_hi=0x{:016X}", ma.old_value_hi);
                }
            }
            out << "\n";
        }
    }
}

// ─── JSONL format ─────────────────────────────────────────────────────────

static void dump_header_jsonl(const FileHeader& hdr, std::ostream& out) {
    out << fmt::format(
        "{{\"type\":\"header\",\"version\":{},\"arch\":{},"
        "\"num_gpr\":{},\"module\":\"{}\","
        "\"base\":\"0x{:X}\",\"slide\":\"0x{:X}\","
        "\"trace_start\":\"0x{:X}\",\"trace_end\":\"0x{:X}\","
        "\"flags\":\"0x{:X}\",\"target_os\":\"{}\"}}\n",
        hdr.version, hdr.arch, hdr.num_gpr,
        json_escape(hdr.module_name),
        hdr.module_base, hdr.module_slide,
        hdr.trace_start, hdr.trace_end,
        hdr.flags, target_os_name(hdr.target_os));
}

static void dump_inst_jsonl(uint64_t inst_id, const InstView& inst,
                            InstructionDecoder& decoder, const CodeTable& ct,
                            const DumpOptions& opts, std::ostream& out) {
    out << fmt::format("{{\"type\":\"inst\",\"id\":{},\"pc\":\"0x{:X}\"", inst_id, inst.pc);

    // Disassembly
    auto opcode = ct.opcode_at(inst.pc);
    if (opcode) {
        auto d = decoder.decode(inst.pc, *opcode);
        if (d) {
            out << fmt::format(",\"mnemonic\":\"{}\",\"operands\":\"{}\"",
                               json_escape(d->mnemonic_sv()),
                               json_escape(d->op_str_sv()));
        }
    }

    out << fmt::format(",\"nzcv\":{}", inst.nzcv);

    if (inst.branch_hint()) {
        out << fmt::format(",\"branch_hint\":{}", inst.branch_hint());
    }

    // GPR diffs
    if (opts.include_regs && inst.reg_diff_count > 0) {
        out << ",\"gpr_diffs\":[";
        for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
            auto diff = inst.reg_diff(d);
            if (d > 0) out << ",";
            out << fmt::format("{{\"reg\":\"{}\",\"val\":\"0x{:X}\"}}",
                               gpr_name(diff.index), diff.value);
        }
        out << "]";
    }

    // FPR diffs
    if (opts.include_regs && inst.fpr_diff_count > 0) {
        out << ",\"fpr_diffs\":[";
        for (uint8_t f = 0; f < inst.fpr_diff_count; f++) {
            auto fd = inst.fpr_diff(f);
            if (f > 0) out << ",";
            out << fmt::format("{{\"reg\":\"{}\",\"lo\":\"0x{:X}\",\"hi\":\"0x{:X}\"}}",
                               fpr_name(fd.index), fd.lo, fd.hi);
        }
        out << "]";
    }

    // Memory accesses
    if (opts.include_mem && inst.mem_access_count > 0) {
        out << ",\"mem_accesses\":[";
        for (uint8_t m = 0; m < inst.mem_access_count; m++) {
            auto ma = inst.mem_access(m);
            if (m > 0) out << ",";
            out << fmt::format("{{\"type\":\"{}\",\"size\":{},\"addr\":\"0x{:X}\","
                               "\"val\":\"0x{:X}\"",
                               mem_type_str(ma.type), ma.size, ma.addr, ma.value);
            if (ma.value_hi) {
                out << fmt::format(",\"val_hi\":\"0x{:X}\"", ma.value_hi);
            }
            if (ma.has_old_value) {
                out << fmt::format(",\"old\":\"0x{:X}\"", ma.old_value);
                if (ma.old_value_hi) {
                    out << fmt::format(",\"old_hi\":\"0x{:X}\"", ma.old_value_hi);
                }
            }
            out << "}";
        }
        out << "]";
    }

    out << "}\n";
}

// ─── Main dump implementation ─────────────────────────────────────────────

Result<DumpStats> dump_trace(TraceReader& reader,
                             const DumpOptions& options,
                             std::ostream& out) {
    const auto& hdr = reader.header();

    // Validate header
    if (hdr.magic != TRACE_MAGIC) {
        return Error(ErrorCode::InvalidMagic, "invalid trace magic");
    }
    if (hdr.version < 4 || hdr.version > TRACE_VERSION_MAX) {
        return Error(ErrorCode::VersionMismatch,
                     fmt::format("unsupported trace version {}", hdr.version));
    }

    DumpStats stats{};

    // ── Pass 1: Build CodeTable from REC_CODE records ───────────────────
    CodeTable code_table;
    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Code) {
            auto code = rec.as_code();
            if (code.size == 4) {
                uint32_t opcode = 0;
                std::memcpy(&opcode, code.bytes, 4);
                code_table.insert(code.pc, opcode);
            }
        }
    }

    // Initialize instruction decoder
    InstructionDecoder decoder;
    if (!decoder.init()) {
        return Error(ErrorCode::CapstoneError, "failed to initialize instruction decoder");
    }

    // ── Output header ────────────────────────────────────────────────────
    if (options.format == DumpFormat::Text) {
        dump_header_text(hdr, out);
    } else {
        dump_header_jsonl(hdr, out);
    }

    // ── Pass 2: Dump all records ─────────────────────────────────────────
    uint64_t inst_id = 0;
    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        stats.records++;

        switch (rec.kind) {
        case RecordKind::Inst: {
            auto inst = rec.as_inst();
            inst_id++;
            stats.inst_records++;

            if (options.format == DumpFormat::Text) {
                dump_inst_text(inst_id, inst, decoder, code_table, options, out);
            } else {
                dump_inst_jsonl(inst_id, inst, decoder, code_table, options, out);
            }

            // Honor --limit
            if (options.limit > 0 && stats.inst_records >= options.limit) {
                return stats;
            }
            break;
        }

        case RecordKind::Thread: {
            auto tv = rec.as_thread();
            if (options.format == DumpFormat::Text) {
                out << fmt::format("THREAD tid=0x{:X}\n", tv.thread_id);
            } else {
                out << fmt::format("{{\"type\":\"thread\",\"tid\":\"0x{:X}\"}}\n", tv.thread_id);
            }
            break;
        }

        case RecordKind::Event: {
            auto ev = rec.as_event();
            if (options.format == DumpFormat::Text) {
                out << fmt::format("EVENT {} addr=0x{:016X}", event_name(ev.event), ev.addr);
                if (ev.site) {
                    out << fmt::format(" site=0x{:016X}", ev.site);
                }
                out << "\n";
            } else {
                out << fmt::format("{{\"type\":\"event\",\"event\":\"{}\",\"addr\":\"0x{:X}\"",
                                   event_name(ev.event), ev.addr);
                if (ev.site) {
                    out << fmt::format(",\"site\":\"0x{:X}\"", ev.site);
                }
                out << "}\n";
            }
            break;
        }

        case RecordKind::Svc: {
            auto sv = rec.as_svc();
            if (options.format == DumpFormat::Text) {
                out << fmt::format("SVC name={} raw_syscall_no={} pc=0x{:016X} return={}",
                                   syscall_name(sv.syscall_no, hdr.target_os), sv.syscall_no, sv.pc,
                                   unknown_return_label(rec.is_v8));
                for (int a = 0; a < 6; a++) {
                    out << fmt::format(" arg{}=0x{:016X}", a, sv.args[a]);
                }
                out << "\n";
            } else {
                out << fmt::format("{{\"type\":\"svc\",\"name\":\"{}\",\"pc\":\"0x{:X}\",\"raw_syscall_no\":{},\"return\":null", syscall_name(sv.syscall_no, hdr.target_os), sv.pc, sv.syscall_no);
                out << ",\"args\":[";
                for (int a = 0; a < 6; a++) {
                    if (a > 0) out << ",";
                    out << fmt::format("\"0x{:X}\"", sv.args[a]);
                }
                out << "]}\n";
            }
            break;
        }

        case RecordKind::Objc: {
            auto ov = rec.as_objc();
            const bool class_known = ov.cls[0] != '\0';
            const char* selector_source = ov.is_v8 ? "inline" : "hex";
            const char* selector_resolution = !ov.is_v8 ? "unresolved"
                : (ov.flags & QBDITRACE_OBJC_FL_SEL_READ_FAIL) ? "read_failed"
                : (ov.flags & QBDITRACE_OBJC_FL_SEL_TRUNCATED) ? "truncated"
                : "resolved";
            const bool is_stret = ov.variant == qbditrace::QBDITRACE_OBJC_MSGSEND_STRET;
            if (options.format == DumpFormat::Text) {
                out << fmt::format("OBJC pc=0x{:016X} recv=0x{:016X} sel=0x{:016X} class={} class_resolution={} selector={} selector_source={} selector_resolution={} return={}\n",
                                   ov.pc, ov.recv, ov.sel,
                                   class_known ? ov.cls : "unknown",
                                   class_known ? "resolved" : "unknown",
                                   ov.selector_name[0] != '\0' ? ov.selector_name : "unknown",
                                   selector_source, selector_resolution,
                                   is_stret ? "stret_raw" : unknown_return_label(ov.is_v8));
            } else {
                out << fmt::format("{{\"type\":\"objc\",\"pc\":\"0x{:X}\","
                                   "\"recv\":\"0x{:X}\",\"sel\":\"0x{:X}\","
                                   "\"class\":{},\"class_resolution\":\"{}\","
                                   "\"selector\":{},\"selector_source\":\"{}\","
                                   "\"selector_resolution\":\"{}\",\"return_kind\":\"{}\",\"return\":null}}\n",
                                   ov.pc, ov.recv, ov.sel,
                                   class_known ? fmt::format("\"{}\"", json_escape(ov.cls)) : "null",
                                   class_known ? "resolved" : "unknown",
                                   ov.selector_name[0] != '\0' ? fmt::format("\"{}\"", json_escape(ov.selector_name)) : "null",
                                   selector_source, selector_resolution,
                                   is_stret ? "stret_raw" : unknown_return_label(ov.is_v8));
            }
            break;
        }

        case RecordKind::CapiCall: {
            auto cc = rec.as_capicall();
            const auto api_name = capi_name(cc.api_id);
            if (options.format == DumpFormat::Text) {
                out << fmt::format("CAPICALL name={} api_id={} pc=0x{:016X} target=0x{:016X} return={}\n",
                                   api_name, cc.api_id, cc.pc, cc.target,
                                   unknown_return_label(cc.is_v8));
                for (uint8_t a = 0; a < cc.arg_count && a < 8; a++) {
                    out << fmt::format("    arg{}=0x{:016X}\n", a, cc.args[a]);
                }
                for (uint8_t s = 0; s < cc.str_count; s++) {
                    auto sv = cc.str_at(s);
                    out << fmt::format("    str[{}]: arg{} len={} \"{}\"\n",
                                       s, static_cast<int>(sv.arg_idx),
                                       static_cast<int>(sv.str_len),
                                       json_escape(sv.data));
                }
            } else {
                out << fmt::format("{{\"type\":\"capicall\",\"name\":\"{}\",\"api_id\":{},"
                                   "\"pc\":\"0x{:X}\",\"target\":\"0x{:X}\",\"return\":null",
                                   api_name, cc.api_id, cc.pc, cc.target);
                out << ",\"args\":[";
                for (uint8_t a = 0; a < cc.arg_count && a < 8; a++) {
                    if (a > 0) out << ",";
                    out << fmt::format("\"0x{:X}\"", cc.args[a]);
                }
                out << "]";
                if (cc.str_count > 0) {
                    out << ",\"strings\":[";
                    for (uint8_t s = 0; s < cc.str_count; s++) {
                        auto sv = cc.str_at(s);
                        if (s > 0) out << ",";
                        out << fmt::format("{{\"arg_idx\":{},\"data\":\"{}\"}}",
                                           static_cast<int>(sv.arg_idx),
                                           json_escape(sv.data));
                    }
                    out << "]";
                }
                out << "}\n";
            }
            break;
        }

        case RecordKind::Retval: {
            auto rv = rec.as_retval();
const bool errno_valid = (rv.flags & QBDITRACE_RET_FL_ERRNO_VALID) != 0;
// raw_error is only meaningful when the syscall actually failed:
// Darwin sets the carry flag (nzcv bit 29) and returns errno in x0;
// Linux returns -errno in x0 (range [-4095, -1]). Mirroring the pass
// semantics avoids showing a successful return value as a fake error.
const int64_t signed_x0 = static_cast<int64_t>(rv.x0);
bool has_raw_error = false;
int64_t raw_error = 0;
if (rv.source_kind == qbditrace::QBDITRACE_REC_SVC) {
    if (hdr.target_os == TargetOS::iOS && (rv.nzcv & (1u << 29)) != 0) {
        has_raw_error = true;
        raw_error = static_cast<int64_t>(rv.x0);
    } else if (hdr.target_os != TargetOS::iOS &&
               signed_x0 < 0 && signed_x0 >= -4095) {
        has_raw_error = true;
        raw_error = signed_x0;
    }
}
            if (options.format == DumpFormat::Text) {
                out << fmt::format("RETVAL source_kind={} source_id={} site=0x{:016X} target=0x{:016X} x0=0x{:016X}",
                                   retval_source_name(rv.source_kind), rv.source_id,
                                   rv.site, rv.target, rv.x0);
                out << fmt::format(" errno_valid={}", errno_valid ? "true" : "false");
                if (errno_valid) {
                    out << fmt::format(" errno={}->{}", rv.errno_before, rv.errno_after);
                }
                if (has_raw_error) {
                    out << fmt::format(" raw_error={}", raw_error);
                }
                out << "\n";
            } else {
                out << fmt::format("{{\"type\":\"retval\",\"source_kind\":\"{}\",\"source_id\":{},\"site\":\"0x{:X}\",\"target\":\"0x{:X}\",\"x0\":\"0x{:X}\",\"errno_valid\":{}",
                                   retval_source_name(rv.source_kind), rv.source_id,
                                   rv.site, rv.target, rv.x0,
                                   errno_valid ? "true" : "false");
                if (errno_valid) {
                    out << fmt::format(",\"errno_before\":{},\"errno_after\":{}", rv.errno_before, rv.errno_after);
                }
                if (has_raw_error) {
                    out << fmt::format(",\"raw_error\":{}", raw_error);
                }
                out << "}\n";
            }
            break;
        }

        case RecordKind::MemImg: {
            const auto memimg = rec.as_memimg();
            if (options.format == DumpFormat::Text) {
                out << fmt::format("MEMIMG seq={} addr=0x{:016X} len={}\n",
                                   memimg.seq, memimg.addr, memimg.len);
            } else {
                out << fmt::format("{{\"type\":\"memimg\",\"seq\":{},"
                                   "\"addr\":\"0x{:X}\",\"len\":{}}}\n",
                                   memimg.seq, memimg.addr, memimg.len);
            }
            break;
        }

        case RecordKind::Anchor: {
            // Anchor records are internal state markers; skip in dump output
            break;
        }

        case RecordKind::Code: {
            // Code records are consumed by CodeTable; skip in dump output
            break;
        }

        default:
            break;
        }
    }

    return stats;
}

}  // namespace tenet

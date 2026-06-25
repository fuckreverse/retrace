#include "analysis/passes/memory_string_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"
#include <fmt/core.h>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace tenet {

// ─── String scanning in a byte buffer ─────────────────────────────────────

std::vector<MemoryStringPass::ScanHit>
MemoryStringPass::scan_for_strings(const std::vector<uint8_t>& data,
                                    const std::vector<bool>& known,
                                    size_t min_len, size_t max_len) {
    std::vector<ScanHit> hits;
    const size_t size = data.size();

    // ─── Phase 1: ASCII / UTF-8 scan ─────────────────────────────────────
    size_t i = 0;
    while (i < size) {
        // Skip unknown or non-printable bytes
        if (!known[i] || !std::isprint(static_cast<unsigned char>(data[i]))) {
            i++;
            continue;
        }

        // Found a printable byte — extend the run
        size_t start = i;
        while (i < size && known[i]) {
            uint8_t c = data[i];
            // Accept printable ASCII + common whitespace (tab, newline, CR)
            if (std::isprint(static_cast<unsigned char>(c)) ||
                c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                break;
            }
        }

        size_t len = i - start;
        if (len >= min_len) {
            ScanHit hit;
            hit.offset = start;
            hit.content = std::string(reinterpret_cast<const char*>(data.data() + start),
                                      std::min(len, max_len));
            // Trim trailing whitespace/newlines
            while (!hit.content.empty() &&
                   (hit.content.back() == '\n' || hit.content.back() == '\r' ||
                    hit.content.back() == '\t' || hit.content.back() == ' ')) {
                hit.content.pop_back();
            }
            if (hit.content.size() >= min_len) {
                // Heuristic: check if it's likely UTF-8 (multi-byte sequences)
                bool has_multibyte = false;
                for (char c : hit.content) {
                    if (static_cast<unsigned char>(c) > 127) {
                        has_multibyte = true;
                        break;
                    }
                }
                hit.encoding = has_multibyte ? MemoryString::UTF8 : MemoryString::ASCII;
                hits.push_back(std::move(hit));
            }
        }
    }

    // ─── Phase 2: UTF-16LE scan ──────────────────────────────────────────
    // Look for sequences of [printable_byte, 0x00] pairs
    i = 0;
    while (i + 1 < size) {
        if (!known[i] || !known[i + 1] || data[i + 1] != 0x00 ||
            !std::isprint(static_cast<unsigned char>(data[i]))) {
            i += 2;
            continue;
        }

        size_t start = i;
        std::string utf8_content;
        while (i + 1 < size && known[i] && known[i + 1] && data[i + 1] == 0x00) {
            uint8_t c = data[i];
            if (std::isprint(static_cast<unsigned char>(c)) ||
                c == '\t' || c == '\n' || c == '\r') {
                utf8_content += static_cast<char>(c);
                i += 2;
            } else {
                break;
            }
        }

        if (utf8_content.size() >= min_len) {
            // Avoid duplicate if we already found this as ASCII at same offset
            bool duplicate = false;
            for (const auto& h : hits) {
                if (h.offset == start && h.content == utf8_content) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                ScanHit hit;
                hit.offset = start;
                hit.content = utf8_content.substr(0, max_len);
                hit.encoding = MemoryString::UTF16LE;
                hits.push_back(std::move(hit));
            }
        }
    }

    return hits;
}

// ─── Deep probe: find complete string at earlier time ─────────────────────

std::string MemoryStringPass::deep_probe_string(MemoryModel& memory,
                                                 uint64_t addr,
                                                 uint64_t current_inst_id,
                                                 const std::string& current_content) {
    if (!config_.deep_probe || current_inst_id == 0) return current_content;

    // Strategy: the current string might be truncated because some bytes
    // haven't been written yet or were partially overwritten.
    // Try reading more bytes at the same time point first (extend forward).
    size_t current_len = current_content.size();
    size_t probe_size = std::min(config_.max_string_len, current_len + 128);

    auto region = memory.read_region(addr, probe_size, current_inst_id);

    // Find the actual string length at this time point
    size_t actual_len = 0;
    for (size_t i = 0; i < region.data.size(); ++i) {
        if (!region.known[i]) break;
        uint8_t c = region.data[i];
        if (c == 0) break;  // null terminator
        if (!std::isprint(static_cast<unsigned char>(c)) &&
            c != '\t' && c != '\n' && c != '\r') break;
        actual_len++;
    }

    if (actual_len > current_len) {
        return std::string(reinterpret_cast<const char*>(region.data.data()), actual_len);
    }

    // If still truncated (unknown bytes), try earlier time points
    // by stepping backward in increments
    if (actual_len < probe_size && current_inst_id > 0) {
        uint64_t step = std::max<uint64_t>(1, current_inst_id / (config_.deep_probe_max_steps + 1));
        std::string best = current_content;

        for (size_t attempt = 0; attempt < config_.deep_probe_max_steps; attempt++) {
            uint64_t probe_time = current_inst_id - std::min(current_inst_id, step * (attempt + 1));
            if (probe_time == 0) break;

            auto probe_result = memory.read_region(addr, probe_size, probe_time);

            size_t probe_len = 0;
            for (size_t i = 0; i < probe_result.data.size(); ++i) {
                if (!probe_result.known[i]) break;
                uint8_t c = probe_result.data[i];
                if (c == 0) break;
                if (!std::isprint(static_cast<unsigned char>(c)) &&
                    c != '\t' && c != '\n' && c != '\r') break;
                probe_len++;
            }

            if (probe_len > best.size()) {
                best = std::string(reinterpret_cast<const char*>(probe_result.data.data()), probe_len);
            }

            // If we found a null-terminated string longer than current, good enough
            if (probe_len > current_len && probe_len < probe_result.data.size() &&
                probe_result.known[probe_len] && probe_result.data[probe_len] == 0) {
                break;
            }
        }

        return best;
    }

    return current_content;
}

// ─── Pass implementation ──────────────────────────────────────────────────

PassResult MemoryStringPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& memory = ctx.memory();
    auto& regfile = ctx.regfile();
    auto& code_table = ctx.code_table();

    const auto& range = ctx.range();
    uint64_t end_id = std::min(range.end_inst_id, index.inst_count());
    if (end_id == 0) end_id = index.inst_count();

    MemoryStringResult result;

    // Helper: add a discovered string to result (with deduplication).
    auto add_string = [&](MemoryString&& ms) {
        // Dedup: same content at same address — keep earliest discovery
        std::string key = fmt::format("{}:{}", ms.addr, ms.content);
        if (result.unique_contents.count(key)) return;
        result.unique_contents.insert(key);

        size_t idx = result.strings.size();
        result.by_addr[ms.addr].push_back(idx);
        result.by_call_site[ms.call_site_inst_id].push_back(idx);
        result.strings.push_back(std::move(ms));
    };

    // ─── Main scan: iterate trace looking for BL/BLR/SVC/OBJC ────────────
    uint64_t inst_id = 0;
    size_t call_sites_processed = 0;

    // Report 0% immediately so the UI shows the pass is active.
    ctx.progress(0.0f, "Scanning call sites for strings");

    for (auto it = reader.begin(); it != reader.end(); ++it) {
        if (ctx.cancelled()) break;

        auto rec = *it;

        // Handle ObjC records — class/selector names are metadata strings
        if (rec.kind == RecordKind::Objc) {
            // ObjC records carry selector + class name implicitly at a specific inst_id
            // (handled separately; the selector/class are in the record itself)
            continue;
        }

        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();
        inst_id++;

        if (inst_id < range.start_inst_id) continue;
        if (inst_id > end_id) break;

        // Progress reporting — update every ~2048 instructions so the UI
        // shows meaningful progress (0x3FFF = 16383 was too coarse).
        if ((inst_id & 0x7FF) == 0) {
            float pct = static_cast<float>(inst_id - range.start_inst_id) /
                        static_cast<float>(end_id - range.start_inst_id + 1);
            ctx.progress(pct, "Scanning call sites for strings");
        }

        // ─── Detect call instructions (BL/BLR) and SVC via opcode bitmask ─
        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (!opcode_opt) continue;

        uint32_t opcode = *opcode_opt;
        bool is_bl  = (opcode & 0xFC000000u) == 0x94000000u;
        bool is_blr = (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;
        bool is_svc = (opcode & 0xFFE0001Fu) == 0xD4000001u;
        bool is_call = is_bl || is_blr;

        if (!is_call && !is_svc) continue;

        // Rate limit
        if (config_.max_call_sites > 0 && call_sites_processed >= config_.max_call_sites) break;
        call_sites_processed++;

        // ─── Get register state at this call site ─────────────────────────
        const RegState& regs = regfile.state_before(inst_id);

        // ─── Scan x0-x7 for pointer-like values ──────────────────────────
        for (int r = 0; r < 8; ++r) {
            uint64_t val = regs.gpr[r];
            if (val < config_.min_pointer_value) continue;

            // Read memory at this pointer
            auto region = memory.read_region(val, config_.scan_size, inst_id);
            if (region.known_count < config_.min_string_len) continue;

            // Scan for strings in the read region
            auto hits = scan_for_strings(region.data, region.known,
                                          config_.min_string_len, config_.max_string_len);

            for (auto& hit : hits) {
                // Deep probe: try to get the complete string
                std::string full_content = hit.content;
                if (config_.deep_probe && hit.offset == 0) {
                    full_content = deep_probe_string(memory, val + hit.offset,
                                                     inst_id, hit.content);
                }

                MemoryString ms;
                ms.addr = val + hit.offset;
                ms.discovered_at = inst_id;
                ms.content = std::move(full_content);
                ms.encoding = static_cast<MemoryString::Encoding>(hit.encoding);
                ms.source = MemoryString::RegPointer;
                ms.source_reg = static_cast<uint8_t>(r);
                ms.call_site_inst_id = inst_id;
                ms.call_site_pc = inst.pc;
                add_string(std::move(ms));
            }
        }

        // ─── Scan stack (SP-relative) ────────────────────────────────────
        if (config_.scan_stack) {
            uint64_t sp = regs.sp();
            if (sp >= config_.min_pointer_value) {
                auto region = memory.read_region(sp, config_.stack_scan_size, inst_id);
                if (region.known_count >= config_.min_string_len) {
                    auto hits = scan_for_strings(region.data, region.known,
                                                  config_.min_string_len, config_.max_string_len);
                    for (auto& hit : hits) {
                        MemoryString ms;
                        ms.addr = sp + hit.offset;
                        ms.discovered_at = inst_id;
                        ms.content = std::move(hit.content);
                        ms.encoding = static_cast<MemoryString::Encoding>(hit.encoding);
                        ms.source = MemoryString::StackLocal;
                        ms.source_reg = 31;  // SP
                        ms.call_site_inst_id = inst_id;
                        ms.call_site_pc = inst.pc;
                        add_string(std::move(ms));
                    }
                }
            }
        }
    }

    ctx.progress(1.0f, fmt::format("Done: {} strings ({} unique) from {} call sites",
                                    result.total(), result.unique_count(),
                                    call_sites_processed));
    return PassResult::success(std::move(result));
}

// ─── Search implementation ────────────────────────────────────────────────

std::vector<const MemoryString*> MemoryStringResult::search(const std::string& pattern) const {
    std::vector<const MemoryString*> matches;
    // Case-insensitive substring search
    std::string lower_pattern;
    lower_pattern.reserve(pattern.size());
    for (char c : pattern) lower_pattern += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    for (const auto& s : strings) {
        std::string lower_content;
        lower_content.reserve(s.content.size());
        for (char c : s.content) lower_content += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (lower_content.find(lower_pattern) != std::string::npos) {
            matches.push_back(&s);
        }
    }
    return matches;
}

}  // namespace tenet

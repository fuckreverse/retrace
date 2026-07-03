#include "analysis/passes/memory_string_pass.h"
#include "analysis/trace_collector.h"
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

// ─── MemoryStringResult serialization helpers ─────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x4D535452 ("MSTR")
//   u32  version = 1
//   u64  num_strings
//   for each MemoryString:
//     u64  addr
//     u64  discovered_at
//     u32  content_len; u8[] content
//     u8   encoding
//     u8   source
//     u8   source_reg
//     u64  call_site_inst_id
//     u64  call_site_pc

namespace {

static constexpr uint32_t MSTR_BLOB_MAGIC   = 0x4D535452u;  // "MSTR"
static constexpr uint32_t MSTR_BLOB_VERSION = 1u;

std::string memory_string_serialize(const MemoryStringResult& res) {
    size_t total = 4 + 4 + 8;  // magic, version, num_strings
    for (const auto& s : res.strings) {
        total += 8 + 8;                     // addr, discovered_at
        total += 4 + s.content.size();      // content
        total += 1 + 1 + 1 + 8 + 8;        // encoding, source, source_reg, call_site ids
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u8  = [&](uint8_t  v) { std::memcpy(p, &v, 1); p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };

    write_u32(MSTR_BLOB_MAGIC);
    write_u32(MSTR_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.strings.size()));

    for (const auto& s : res.strings) {
        write_u64(s.addr);
        write_u64(s.discovered_at);
        write_u32(static_cast<uint32_t>(s.content.size()));
        std::memcpy(p, s.content.data(), s.content.size());
        p += s.content.size();
        write_u8(static_cast<uint8_t>(s.encoding));
        write_u8(static_cast<uint8_t>(s.source));
        write_u8(s.source_reg);
        write_u64(s.call_site_inst_id);
        write_u64(s.call_site_pc);
    }

    return buf;
}

bool memory_string_deserialize(const std::string& blob, MemoryStringResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };

    if (read_u32() != MSTR_BLOB_MAGIC)   return false;
    if (read_u32() != MSTR_BLOB_VERSION) return false;

    uint64_t n = read_u64();
    out.strings.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        if (p + 8 + 8 + 4 > end) return false;
        MemoryString s;
        s.addr         = read_u64();
        s.discovered_at = read_u64();
        uint32_t clen   = read_u32();
        if (p + clen > end) return false;
        s.content.assign(p, clen);
        p += clen;
        if (p + 1 + 1 + 1 + 8 + 8 > end) return false;
        s.encoding        = static_cast<MemoryString::Encoding>(read_u8());
        s.source          = static_cast<MemoryString::Source>(read_u8());
        s.source_reg      = read_u8();
        s.call_site_inst_id = read_u64();
        s.call_site_pc    = read_u64();

        // Rebuild index structures
        size_t idx = out.strings.size();
        out.by_addr[s.addr].push_back(idx);
        out.by_call_site[s.call_site_inst_id].push_back(idx);
        // Rebuild unique_contents set
        std::string key = fmt::format("{}:{}", s.addr, s.content);
        out.unique_contents.insert(key);
        out.strings.push_back(std::move(s));
    }

    return true;
}

}  // anonymous namespace (memory_string serialization)

// ─── MemoryStringCollector ────────────────────────────────────────────────

bool MemoryStringCollector::begin(uint64_t /*start_inst_id*/,
                                   uint64_t /*end_inst_id*/) {
    call_sites_.clear();
    return true;
}

void MemoryStringCollector::add_call_site(uint64_t inst_id, uint64_t pc) {
    if (config_.max_call_sites > 0 && call_sites_.size() >= config_.max_call_sites) return;
    // De-dup: an ObjC message send and the BL/BLR to objc_msgSend it lowers
    // to can both be observed at the same inst_id in some trace configs.
    if (!call_sites_.empty() && call_sites_.back().inst_id == inst_id) return;
    call_sites_.push_back({inst_id, pc});
}

void MemoryStringCollector::on_inst(uint64_t inst_id, const InstView& inst) {
    // Detect call instructions (BL/BLR) and SVC via opcode bitmask.
    auto opcode_opt = code_table_.opcode_at(inst.pc);
    if (!opcode_opt) return;

    uint32_t opcode = *opcode_opt;
    bool is_bl  = (opcode & 0xFC000000u) == 0x94000000u;
    bool is_blr = (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;
    bool is_svc = (opcode & 0xFFE0001Fu) == 0xD4000001u;
    bool is_call = is_bl || is_blr;

    if (!is_call && !is_svc) return;

    add_call_site(inst_id, inst.pc);
}

void MemoryStringCollector::on_objc(uint64_t inst_id, const ObjcView& objc) {
    // ObjC message sends (objc_msgSend and friends) pass their arguments in
    // x0 (receiver), x1 (selector), x2-x7 (method args) — the same GPR
    // convention Phase 2 already scans for regular calls. Treating each
    // REC_OBJC record as a call site lets MemoryStringPass discover strings
    // passed as Objective-C method arguments (e.g. NSString* parameters),
    // which the opcode-only BL/BLR/SVC detection in on_inst() cannot see
    // since objc_msgSend is an external (non-traced) library call.
    add_call_site(inst_id, objc.pc);
}

// ─── String scanning in a byte buffer ─────────────────────────────────────

std::vector<MemoryStringPass::ScanHit>
MemoryStringPass::scan_for_strings(const std::vector<uint8_t>& data,
                                    const std::vector<bool>& known,
                                    size_t min_len, size_t max_len) {
    std::vector<ScanHit> hits;
    const size_t size = data.size();

    // Tracks which offsets already produced an ASCII/UTF-8 hit, so the
    // UTF-16LE pass below can skip duplicate-offset checks in O(1) instead
    // of an O(hits) linear scan per candidate (this loop runs per call site,
    // and there can be tens of thousands of call sites in a large trace).
    ankerl::unordered_dense::set<size_t> ascii_hit_offsets;

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
                ascii_hit_offsets.insert(start);
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
            // Avoid duplicate if we already found this exact run as ASCII at
            // the same offset. O(1) set lookup instead of an O(hits) linear
            // scan — this function runs once per call site (potentially
            // tens of thousands of times per trace), so the difference
            // between O(1) and O(hits) here is significant in aggregate.
            bool duplicate = ascii_hit_offsets.count(start) != 0;
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

// ─── Truncation check ───────────────────────────────────────────────────

bool MemoryStringPass::is_hit_truncated(const ScanHit& hit,
                                         const MemoryModel::RegionReadResult& region) {
    size_t byte_len = hit.content.size() * (hit.encoding == MemoryString::UTF16LE ? 2 : 1);
    size_t end = hit.offset + byte_len;

    // Ran off the end of the scanned window entirely — definitely truncated.
    if (end >= region.data.size()) return true;

    // Stopped because the next byte's value is unknown (not yet observed at
    // this point in time) rather than because it was a NUL/non-printable
    // byte — also worth a deep probe, since the "real" byte may simply not
    // have been written yet from this vantage point.
    if (!region.known[end]) return true;

    return false;
}

// ─── Deep probe: find complete string at earlier time ─────────────────────

namespace {

/// Measure the length of a printable run at the start of a reconstructed
/// region (stops at the first unknown byte, NUL terminator, or
/// non-printable/non-whitespace byte).
size_t printable_run_length(const MemoryModel::RegionReadResult& region) {
    size_t len = 0;
    for (size_t i = 0; i < region.data.size(); ++i) {
        if (!region.known[i]) break;
        uint8_t c = region.data[i];
        if (c == 0) break;
        if (!std::isprint(static_cast<unsigned char>(c)) &&
            c != '\t' && c != '\n' && c != '\r') break;
        len++;
    }
    return len;
}

}  // namespace

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
    size_t actual_len = printable_run_length(region);

    std::string best = current_content;
    if (actual_len > best.size()) {
        best = std::string(reinterpret_cast<const char*>(region.data.data()), actual_len);
    }

    // If the string is still truncated by unknown bytes, walk the *actual*
    // write history of this byte range instead of sampling equidistant time
    // points blindly. MemoryModel::last_writer() gives us the exact inst_id
    // of the most recent write covering [addr, addr+probe_size) before a
    // given point — following that chain backward visits only instants
    // where this memory genuinely changed, so a narrow "the string was
    // assembled over 3 instructions, 2M instructions ago" window is never
    // skipped by a coarse fixed stride the way the old implementation could.
    if (actual_len < probe_size) {
        uint64_t probe_time = current_inst_id;
        uint8_t probe_span = static_cast<uint8_t>(std::min<size_t>(probe_size, 16));

        for (size_t attempt = 0; attempt < config_.deep_probe_max_steps; attempt++) {
            // NOTE: MemoryModel::last_writer() returns 0 both for "no write
            // found" and for "the write happened at inst_id 0" — an
            // inherent ambiguity in that API. In practice string-bearing
            // writes essentially never occur at the very first instruction
            // of a trace, so treating 0 as "stop" here is a safe simplification.
            uint64_t writer = memory.last_writer(addr, probe_span, probe_time);
            if (writer == 0 || writer >= probe_time) break;  // no earlier write found

            auto probe_result = memory.read_region(addr, probe_size, writer + 1);
            size_t probe_len = printable_run_length(probe_result);

            if (probe_len > best.size()) {
                best = std::string(reinterpret_cast<const char*>(probe_result.data.data()), probe_len);
            }

            // Good enough: found a NUL-terminated string longer than the
            // original truncated content.
            if (probe_len > current_len && probe_len < probe_result.data.size() &&
                probe_result.known[probe_len] && probe_result.data[probe_len] == 0) {
                break;
            }

            // Continue walking backward from just before this write.
            probe_time = writer;
        }
    }

    return best;
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

    // ── Fast path: load from persisted cache ──────────────────────────────
    // Only cache for default config + full trace to avoid config mismatches.
    const bool is_default_cfg =
        config_.scan_size == 256 &&
        config_.min_pointer_value == 0x100000000ULL &&
        config_.scan_stack &&
        config_.stack_scan_size == 512 &&
        config_.max_call_sites == 0 &&
        config_.deep_probe &&
        config_.deep_probe_max_steps == 50 &&
        config_.min_string_len == 4 &&
        config_.max_string_len == 512;
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("memory_strings", blob)) {
            MemoryStringResult cached;
            if (memory_string_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Done: {} strings ({} unique) (from cache)",
                    cached.total(), cached.unique_count()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    ctx.progress(0.0f, "Scanning call sites for strings");

    // ─── Phase 1: collect call sites via collector ─────────────────────────
    MemoryStringCollector collector(code_table, config_);

    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        uint64_t total_insts = index.inst_count();
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                // Phase 1 = first 30% of progress
                ctx.progress(static_cast<float>(processed) / static_cast<float>(total) * 0.3f);
            }
        });
        local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    const auto& call_sites = collector.call_sites();

    // ─── Phase 2: analyze each call site with regfile + memory ────────────
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

    size_t call_sites_processed = 0;

    for (size_t ci = 0; ci < call_sites.size(); ++ci) {
        if (ctx.cancelled()) break;

        const auto& site = call_sites[ci];

        // Skip call sites outside the requested range.
        if (site.inst_id < range.start_inst_id) continue;
        if (site.inst_id > end_id) continue;

        call_sites_processed++;

        // Progress: Phase 2 = 30%-100%
        if ((ci & 0xFF) == 0) {
            float pct = 0.3f + 0.7f * static_cast<float>(ci) /
                        static_cast<float>(call_sites.size());
            ctx.progress(pct, "Analyzing call sites for strings");
        }

        // ─── Get register state at this call site ─────────────────────────
        const RegState& regs = regfile.state_before(site.inst_id);

        // ─── Scan x0-x7 for pointer-like values ──────────────────────────
        for (int r = 0; r < 8; ++r) {
            uint64_t val = regs.gpr[r];
            if (val < config_.min_pointer_value) continue;

            // Read memory at this pointer
            auto region = memory.read_region(val, config_.scan_size, site.inst_id);
            if (region.known_count < config_.min_string_len) continue;

            // Scan for strings in the read region
            auto hits = scan_for_strings(region.data, region.known,
                                          config_.min_string_len, config_.max_string_len);

            for (auto& hit : hits) {
                // Deep probe: only worth attempting when this hit was
                // actually truncated by the edge of the scanned window
                // (i.e. it runs all the way to the last byte we read) —
                // a hit that ends earlier already hit a NUL terminator or a
                // non-printable byte within the window, so it is complete
                // and re-probing would be wasted MemoryModel/RocksDB work.
                // Applies to every hit in the window, not just offset==0:
                // a register can point into the middle of a struct whose
                // string field starts mid-window just as validly as one
                // whose string starts at the pointer itself.
                std::string full_content = hit.content;
                if (config_.deep_probe && is_hit_truncated(hit, region)) {
                    full_content = deep_probe_string(memory, val + hit.offset,
                                                     site.inst_id, hit.content);
                }

                MemoryString ms;
                ms.addr = val + hit.offset;
                ms.discovered_at = site.inst_id;
                ms.content = std::move(full_content);
                ms.encoding = static_cast<MemoryString::Encoding>(hit.encoding);
                ms.source = MemoryString::RegPointer;
                ms.source_reg = static_cast<uint8_t>(r);
                ms.call_site_inst_id = site.inst_id;
                ms.call_site_pc = site.pc;
                add_string(std::move(ms));
            }
        }

        // ─── Scan stack (SP-relative) ────────────────────────────────────
        if (config_.scan_stack) {
            uint64_t sp = regs.sp();
            if (sp >= config_.min_pointer_value) {
                auto region = memory.read_region(sp, config_.stack_scan_size, site.inst_id);
                if (region.known_count >= config_.min_string_len) {
                    auto hits = scan_for_strings(region.data, region.known,
                                                  config_.min_string_len, config_.max_string_len);
                    for (auto& hit : hits) {
                        std::string full_content = hit.content;
                        if (config_.deep_probe && is_hit_truncated(hit, region)) {
                            full_content = deep_probe_string(memory, sp + hit.offset,
                                                             site.inst_id, hit.content);
                        }

                        MemoryString ms;
                        ms.addr = sp + hit.offset;
                        ms.discovered_at = site.inst_id;
                        ms.content = std::move(full_content);
                        ms.encoding = static_cast<MemoryString::Encoding>(hit.encoding);
                        ms.source = MemoryString::StackLocal;
                        ms.source_reg = 31;  // SP
                        ms.call_site_inst_id = site.inst_id;
                        ms.call_site_pc = site.pc;
                        add_string(std::move(ms));
                    }
                }
            }
        }
    }

    // ── Persist result for future sessions ───────────────────────────────
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob = memory_string_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("memory_strings", blob.data(), blob.size());
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

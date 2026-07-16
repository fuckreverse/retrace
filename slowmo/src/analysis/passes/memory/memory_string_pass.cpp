#include "analysis/passes/memory/memory_string_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"
#include "common/byte_codec.h"
#include "infra/string_resolver.h"
#include <fmt/core.h>
#include <algorithm>
#include <array>
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

/// Combine an address and a string content into a single 64-bit hash.
/// Used as the dedup key in MemoryStringResult::unique_hashes, replacing
/// the previous fmt::format("{}:{}", addr, content) string key.
///
/// Collisions: with a 64-bit hash and ~500K entries the birthday-bound
/// collision probability is ~10⁻⁵, which is acceptable for a dedup
/// statistic that only feeds unique_count().  The addr is mixed in
/// explicitly (not just via hashing the formatted digits) so two strings
/// with identical content at different addresses are NOT collapsed.
inline uint64_t hash_combine_addr_content(uint64_t addr, const std::string& content) {
    // FNV-1a on content
    uint64_t h = 0xcbf29ce484222325ULL;
    for (unsigned char c : content) {
        h ^= c;
        h *= 0x100000001b3ULL;
    }
    // boost::hash_combine style mix with addr
    h ^= addr + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

std::string memory_string_serialize(const MemoryStringResult& res) {
    ByteWriter w;

    w.u32(MSTR_BLOB_MAGIC);
    w.u32(MSTR_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.strings.size()));

    for (const auto& s : res.strings) {
        w.u64(s.addr);
        w.u64(s.discovered_at);
        w.u32(static_cast<uint32_t>(s.content.size()));
        w.bytes(s.content.data(), s.content.size());
        w.u8(static_cast<uint8_t>(s.encoding));
        w.u8(static_cast<uint8_t>(s.source));
        w.u8(s.source_reg);
        w.u64(s.call_site_inst_id);
        w.u64(s.call_site_pc);
    }

    return std::move(w).take();
}

bool memory_string_deserialize(const std::string& blob, MemoryStringResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != MSTR_BLOB_MAGIC)   return false;
    if (r.u32() != MSTR_BLOB_VERSION) return false;

    uint64_t n = r.u64();
    out.strings.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        MemoryString s;
        s.addr         = r.u64();
        s.discovered_at = r.u64();
        uint32_t clen   = r.u32();
        if (!r.ok()) return false;
        s.content.resize(clen);
        r.bytes(s.content.data(), clen);
        s.encoding        = static_cast<MemoryString::Encoding>(r.u8());
        s.source          = static_cast<MemoryString::Source>(r.u8());
        s.source_reg      = r.u8();
        s.call_site_inst_id = r.u64();
        s.call_site_pc    = r.u64();

        // Rebuild index structures
        size_t idx = out.strings.size();
        out.by_addr[s.addr].push_back(idx);
        out.by_call_site[s.call_site_inst_id].push_back(idx);
        // Rebuild unique_hashes set (combined hash of addr + content)
        uint64_t h = hash_combine_addr_content(s.addr, s.content);
        out.unique_hashes.insert(h);
        out.strings.push_back(std::move(s));
    }

    return r.ok();
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
MemoryStringPass::scan_for_strings(const uint8_t* data,
                                    const uint8_t* known,
                                    size_t size,
                                    size_t min_len, size_t max_len) {
    std::vector<ScanHit> hits;
    if (size == 0) return hits;
    // Most windows contain only a handful of strings; reserve once to avoid
    // repeated reallocs across the (potentially tens of thousands of) call
    // sites this runs for.
    hits.reserve(8);

    // Tracks which offsets already produced an ASCII/UTF-8 hit, so the
    // UTF-16LE pass below can skip duplicate-offset checks in O(1) instead
    // of an O(hits) linear scan per candidate.  A flat bitmap is dramatically
    // cheaper than the previous ankerl::unordered_dense::set<size_t> which
    // allocated a bucket array on every call.
    //
    // The common scan windows are <= 512 bytes (scan_size=256, stack 512),
    // so a stack array covers them with zero allocation; larger windows fall
    // back to a heap vector.
    constexpr size_t STACK_BMP = 512;
    std::array<uint8_t, STACK_BMP> stack_bmp{};
    std::vector<uint8_t> heap_bmp;
    uint8_t* bmp;
    if (size <= STACK_BMP) {
        bmp = stack_bmp.data();
    } else {
        heap_bmp.assign(size, 0);
        bmp = heap_bmp.data();
    }

    // ─── Phase 1: ASCII / UTF-8 scan ─────────────────────────────────────
    size_t i = 0;
    while (i < size) {
        // Skip unknown or non-printable bytes
        if (!known[i] || !std::isprint(data[i])) {
            i++;
            continue;
        }

        // Found a printable byte — extend the run
        size_t start = i;
        while (i < size && known[i]) {
            uint8_t c = data[i];
            // Accept printable ASCII + common whitespace (tab, newline, CR)
            if (std::isprint(c) || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                break;
            }
        }

        size_t len = i - start;
        if (len >= min_len) {
            ScanHit hit;
            hit.offset = start;
            hit.content.assign(reinterpret_cast<const char*>(data + start),
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
                bmp[start] = 1;
                hits.push_back(std::move(hit));
            }
        }
    }

    // ─── Phase 2: UTF-16LE scan ──────────────────────────────────────────
    // Look for sequences of [printable_byte, 0x00] pairs
    i = 0;
    while (i + 1 < size) {
        if (!known[i] || !known[i + 1] || data[i + 1] != 0x00 ||
            !std::isprint(data[i])) {
            i += 2;
            continue;
        }

        size_t start = i;
        std::string utf8_content;
        while (i + 1 < size && known[i] && known[i + 1] && data[i + 1] == 0x00) {
            uint8_t c = data[i];
            if (std::isprint(c) || c == '\t' || c == '\n' || c == '\r') {
                utf8_content += static_cast<char>(c);
                i += 2;
            } else {
                break;
            }
        }

        if (utf8_content.size() >= min_len) {
            // Avoid duplicate if we already found this exact run as ASCII at
            // the same offset. O(1) bitmap lookup instead of an O(hits) linear
            // scan — this function runs once per call site (potentially
            // tens of thousands of times per trace), so the difference
            // between O(1) and O(hits) here is significant in aggregate.
            if (!bmp[start]) {
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

void MemoryStringPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    collector_ = std::make_unique<MemoryStringCollector>(code_table, config_);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}

std::optional<PassResult> MemoryStringPass::try_load_cached(PassContext& ctx) {
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
    if (!is_default_cfg || !ctx.range().is_full_trace()) return std::nullopt;

    std::string blob;
    if (!ctx.index().load_pass_blob("memory_strings", blob)) return std::nullopt;

    MemoryStringResult cached;
    if (!memory_string_deserialize(blob, cached)) return std::nullopt;

    collector_.reset();
    ctx.progress(1.0f, fmt::format(
        "Done: {} strings ({} unique) (from cache)",
        cached.total(), cached.unique_count()));
    return PassResult::success(std::move(cached));
}

PassResult MemoryStringPass::run(PassContext& ctx) {
    auto& index = ctx.index();
    auto& memory = ctx.memory();
    auto& regfile = ctx.regfile();

    const auto& range = ctx.range();
    uint64_t end_id = std::min(range.end_inst_id, index.inst_count());
    if (end_id == 0) end_id = index.inst_count();
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

    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    ctx.progress(0.3f, "Scanning call sites for strings");

    const auto& call_sites = collector_->call_sites();

    // ─── Phase 2: analyze each call site with regfile + memory ────────────
    MemoryStringResult result;

    // Reusable byte buffer for the "known" mask. MemoryModel::read_region
    // returns std::vector<bool> (bit-packed); probing it byte-by-byte inside
    // the scan hot loops is slow because every access is a word-fetch + bit
    // shift. We flatten it to 1 byte per element once per read_region and
    // hand scan_for_strings raw pointers — the scan loops then become plain
    // byte arrays the compiler can vectorise. The buffer is resized (never
    // reallocated after the first large window) and reused across every call
    // site, so it costs zero per-iteration allocation.
    std::vector<uint8_t> known_bytes;

    // Helper: add a discovered string to result (with deduplication).
    auto add_string = [&](MemoryString&& ms) {
        // Dedup: same content at same address — keep earliest discovery.
        // Uses a combined 64-bit hash of (addr, content) instead of the
        // previous fmt::format("{}:{}", ...) string key — avoids per-entry
        // string allocation + format parsing on the hot add path.
        uint64_t h = hash_combine_addr_content(ms.addr, ms.content);
        if (!result.unique_hashes.insert(h).second) return;

        size_t idx = result.strings.size();
        result.by_addr[ms.addr].push_back(idx);
        result.by_call_site[ms.call_site_inst_id].push_back(idx);
        result.strings.push_back(std::move(ms));
    };

    // Helper: read-scan-probe a single memory window. Shared by the register
    // and stack paths so the flattening + deep-probe logic lives in one place.
    auto scan_region = [&](const MemoryModel::RegionReadResult& region,
                           uint64_t base_addr, uint64_t inst_id, uint64_t pc,
                           MemoryString::Source src, uint8_t src_reg) {
        if (region.known_count < config_.min_string_len) return;

        const size_t sz = region.data.size();
        if (known_bytes.size() < sz) known_bytes.resize(sz);
        for (size_t i = 0; i < sz; ++i)
            known_bytes[i] = region.known[i] ? 1 : 0;

        auto hits = scan_for_strings(region.data.data(), known_bytes.data(), sz,
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
                full_content = deep_probe_string(memory, base_addr + hit.offset,
                                                 inst_id, hit.content);
            }

            MemoryString ms;
            ms.addr = base_addr + hit.offset;
            ms.discovered_at = inst_id;
            ms.content = std::move(full_content);
            ms.encoding = static_cast<MemoryString::Encoding>(hit.encoding);
            ms.source = src;
            ms.source_reg = src_reg;
            ms.call_site_inst_id = inst_id;
            ms.call_site_pc = pc;
            add_string(std::move(ms));
        }
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

        // Per-call-site pointer dedup. It is common for several of x0-x7
        // (or SP) to hold the same pointer (e.g. x0 and x1 aliasing the same
        // buffer, or SP == a register). Re-reading and re-scanning the same
        // address at the same instant is pure waste — the hits would be
        // identical and deduplicated by add_string anyway. A 9-slot linear
        // scan is cheaper than a single read_region, so this is a strict win.
        uint64_t seen_ptrs[9];
        int n_seen = 0;
        auto already_seen = [&](uint64_t v) {
            for (int k = 0; k < n_seen; ++k)
                if (seen_ptrs[k] == v) return true;
            return false;
        };
        auto remember = [&](uint64_t v) {
            if (n_seen < 9) seen_ptrs[n_seen++] = v;
        };

        // ─── Scan x0-x7 for pointer-like values ──────────────────────────
        for (int r = 0; r < 8; ++r) {
            uint64_t val = regs.gpr[r];
            if (val < config_.min_pointer_value) continue;
            if (already_seen(val)) continue;
            remember(val);

            auto region = memory.read_region(val, config_.scan_size, site.inst_id);
            scan_region(region, val, site.inst_id, site.pc,
                        MemoryString::RegPointer, static_cast<uint8_t>(r));
        }

        // ─── Scan stack (SP-relative) ────────────────────────────────────
        if (config_.scan_stack) {
            uint64_t sp = regs.sp();
            if (sp >= config_.min_pointer_value && !already_seen(sp)) {
                remember(sp);
                auto region = memory.read_region(sp, config_.stack_scan_size, site.inst_id);
                scan_region(region, sp, site.inst_id, site.pc,
                            MemoryString::StackLocal, 31);  // SP
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

    // ── Supplementary: add strings from StringResolver (PageScan source).
    //    These are strings found via full-page scanning that were never
    //    pointed to by registers at call sites. StringResolver caches
    //    results across passes, so this is cheap if PageStats was already built.
    {
        auto& string_resolver = ctx.string_resolver();
        string_resolver.ensure_built(ctx.index().inst_count());

        const auto& resolved = string_resolver.all_strings();
        for (const auto& rs : resolved) {
            // Skip if we already found a string at this address via call-site scan
            if (result.by_addr.count(rs.addr) > 0) continue;

            MemoryString ms;
            ms.addr = rs.addr;
            ms.discovered_at = rs.inst_id;
            ms.content = rs.value;
            ms.encoding = MemoryString::Encoding::ASCII;
            ms.source = MemoryString::Source::PageScan;
            ms.source_reg = 0xFF;
            ms.call_site_inst_id = 0;
            ms.call_site_pc = 0;

            size_t idx = result.strings.size();
            result.strings.push_back(std::move(ms));
            result.by_addr[rs.addr].push_back(idx);
            result.unique_hashes.insert(
                hash_combine_addr_content(rs.addr, result.strings[idx].content));
        }
    }

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

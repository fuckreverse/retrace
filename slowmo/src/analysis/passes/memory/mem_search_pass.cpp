#include "analysis/passes/memory/mem_search_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "common/aarch64_classify.h"

#ifdef TENET_HAS_YARA
#include <yara.h>
#endif

#include <fmt/core.h>
#include <algorithm>
#include <cstring>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Lifecycle ────────────────────────────────────────────────────────────

MemSearchPass::~MemSearchPass() {
#ifdef TENET_HAS_YARA
    if (yr_rules_) {
        yr_rules_destroy(yr_rules_);
        yr_rules_ = nullptr;
    }
#endif
}

MemSearchPass::MemSearchPass(MemSearchPass&& o) noexcept
    : cfg_(std::move(o.cfg_))
#ifdef TENET_HAS_YARA
    , yr_rules_(o.yr_rules_)
#endif
{
#ifdef TENET_HAS_YARA
    o.yr_rules_ = nullptr;
#endif
}

MemSearchPass& MemSearchPass::operator=(MemSearchPass&& o) noexcept {
    if (this != &o) {
#ifdef TENET_HAS_YARA
        if (yr_rules_) yr_rules_destroy(yr_rules_);
        yr_rules_ = o.yr_rules_;
        o.yr_rules_ = nullptr;
#endif
        cfg_ = std::move(o.cfg_);
    }
    return *this;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

bool MemSearchPass::has_wildcards() const {
    for (const auto& pat : cfg_.patterns) {
        if (!pat.mask.empty()) {
            for (uint8_t m : pat.mask) {
                if (m == 0xFF) return true;
            }
        }
    }
    return false;
}

bool MemSearchPass::match_at(const uint8_t* data, size_t data_len, size_t pos,
                             const MemSearchConfig::Pattern& pat) {
    if (pos + pat.bytes.size() > data_len) return false;
    for (size_t i = 0; i < pat.bytes.size(); i++) {
        if (i < pat.mask.size() && pat.mask[i] == 0xFF) continue;  // wildcard
        if (data[pos + i] != pat.bytes[i]) return false;
    }
    return true;
}

// ─── YARA integration ─────────────────────────────────────────────────────

#ifdef TENET_HAS_YARA

namespace {

struct MemSearchYaraCtx {
    MemSearchResult* result;
    const std::vector<uint64_t>* offset_to_inst_id;
    const std::vector<uint64_t>* offset_to_pc;
    const std::vector<uint64_t>* offset_to_addr;
    const std::vector<uint8_t>* offset_to_size;
    MemSearchMatch::Source source;
    size_t entry_size;  // bytes per entry in the buffer (8 for reg, 16 for mem)
    uint64_t max_matches = 0;  // 0 = unlimited (mirrors MemSearchConfig::max_matches)
    const std::function<bool()>* cancel_check = nullptr;
};

int memsearch_yara_callback(YR_SCAN_CONTEXT* context, int message,
                            void* message_data, void* user_data) {
    auto* ctx = static_cast<MemSearchYaraCtx*>(user_data);
    if (ctx->cancel_check && *ctx->cancel_check && (*ctx->cancel_check)()) {
        return CALLBACK_ABORT;
    }
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    auto* rule = static_cast<YR_RULE*>(message_data);

    // Parse pattern_index from rule identifier: "pat_<idx>"
    uint8_t pattern_index = 0;
    if (rule->identifier && std::strncmp(rule->identifier, "pat_", 4) == 0) {
        pattern_index = static_cast<uint8_t>(std::atoi(rule->identifier + 4));
    }

    // Iterate all matching strings for precise offsets. Enforce max_matches
    // per pattern here — YARA itself has no notion of "stop after N hits for
    // this rule", so without this cap a hot pattern could accumulate
    // unbounded matches across the whole scanned buffer.
    if (pattern_index >= ctx->result->by_pattern.size()) return CALLBACK_CONTINUE;

    YR_STRING* str;
    yr_rule_strings_foreach(rule, str) {
        if (ctx->max_matches > 0 &&
            ctx->result->by_pattern[pattern_index].size() >= ctx->max_matches) {
            break;
        }
        YR_MATCH* match;
        yr_string_matches_foreach(context, str, match) {
            if (ctx->max_matches > 0 &&
                ctx->result->by_pattern[pattern_index].size() >= ctx->max_matches) {
                break;
            }
            size_t buf_offset = match->offset;
            size_t entry_idx = buf_offset / ctx->entry_size;
            size_t within_offset = buf_offset % ctx->entry_size;

            if (entry_idx >= ctx->offset_to_inst_id->size()) continue;

            MemSearchMatch m;
            m.inst_id = (*ctx->offset_to_inst_id)[entry_idx];
            m.pc = (*ctx->offset_to_pc)[entry_idx];
            m.addr = ctx->offset_to_addr ? (*ctx->offset_to_addr)[entry_idx] + within_offset : 0;
            m.offset = static_cast<uint16_t>(within_offset);
            m.pattern_index = pattern_index;
            m.source = ctx->source;
            m.is_exact_value_match = false;

            ctx->result->by_pattern[pattern_index].push_back(ctx->result->matches.size());
            ctx->result->matches.push_back(m);
        }
    }

    return CALLBACK_CONTINUE;
}

}  // anonymous namespace

bool MemSearchPass::compile_patterns_to_yara() {
    if (yr_initialize() != ERROR_SUCCESS) {
        return false;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        return false;
    }

    // Generate YARA source from user patterns.
    // Each pattern becomes a rule with a hex string.
    // Example: rule pat_0 { strings: $s = { DE AD BE EF } condition: $s }
    std::string yara_src;
    for (size_t i = 0; i < cfg_.patterns.size(); i++) {
        const auto& pat = cfg_.patterns[i];
        std::string hex_str;
        for (size_t j = 0; j < pat.bytes.size(); j++) {
            if (j > 0) hex_str += ' ';
            if (j < pat.mask.size() && pat.mask[j] == 0xFF) {
                hex_str += "??";
            } else {
                hex_str += fmt::format("{:02X}", pat.bytes[j]);
            }
        }
        yara_src += fmt::format(
            "rule pat_{} {{ strings: $s = {{ {} }} condition: $s }}\n",
            i, hex_str);
    }

    int errors = yr_compiler_add_string(compiler, yara_src.c_str(), nullptr);
    if (errors > 0) {
        yr_compiler_destroy(compiler);
        return false;
    }

    if (yr_compiler_get_rules(compiler, &yr_rules_) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return false;
    }

    yr_compiler_destroy(compiler);
    return true;
}

void MemSearchPass::yara_scan_buffer(
    const uint8_t* data, size_t len,
    const std::vector<uint64_t>& offset_to_inst_id,
    const std::vector<uint64_t>& offset_to_pc,
    const std::vector<uint64_t>& offset_to_addr,
    const std::vector<uint8_t>& offset_to_size,
    MemSearchMatch::Source source,
    MemSearchResult& result,
    const std::function<bool()>& cancel_check)
{
    if (!yr_rules_ || len == 0) return;

    // Determine entry_size from average (for mem writes it's 16, for regs it's 8)
    size_t entry_size = (source == MemSearchMatch::MemWrite) ? 16 : 8;

    MemSearchYaraCtx ctx;
    ctx.result = &result;
    ctx.offset_to_inst_id = &offset_to_inst_id;
    ctx.offset_to_pc = &offset_to_pc;
    ctx.offset_to_addr = &offset_to_addr;
    ctx.offset_to_size = &offset_to_size;
    ctx.source = source;
    ctx.entry_size = entry_size;
    ctx.max_matches = cfg_.max_matches;
    ctx.cancel_check = &cancel_check;

    yr_rules_scan_mem(yr_rules_, data, len, 0, memsearch_yara_callback, &ctx, 0);
}

#endif  // TENET_HAS_YARA

// ─── Main pass execution ──────────────────────────────────────────────────
//
// Two independent search facilities share this pass:
//
//   - `patterns`     : arbitrary-length byte sequences (with wildcards),
//                      matched via YARA (if available) or a linear scan.
//   - `exact_values` : specific scalar values, matched via an O(1) hash-map
//                      lookup against register diffs, memory-write values,
//                      and MOVZ/MOVK instruction immediates. This absorbs
//                      what used to be the standalone LiteralSearchPass.
//
// Both facilities can be enabled simultaneously. `linear_scan()` handles
// both in a single trace traversal when patterns don't use the YARA path
// (or when there are no byte patterns at all, i.e. exact_values-only mode).
// When YARA *is* used for byte patterns, exact_values are matched in a
// second, lightweight pass afterward — this keeps the (rarely-combined)
// two facilities decoupled without duplicating the YARA buffer-construction
// machinery for a case that doesn't benefit from it.

PassResult MemSearchPass::run(PassContext& ctx) {
    if (cfg_.patterns.empty() && cfg_.exact_values.empty()) {
        return PassResult::skipped();
    }

    auto& index = ctx.index();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    MemSearchResult result;
    result.by_pattern.resize(cfg_.patterns.size());
    result.by_value.resize(cfg_.exact_values.size());

    if (cfg_.patterns.empty()) {
        // exact_values only — a single linear_scan() pass covers everything,
        // no need for the YARA buffer-construction machinery at all.
        linear_scan(ctx, result);
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        return PassResult::success(std::move(result));
    }

    // ─── Strategy selection (byte patterns) ────────────────────────────────
    //
    // YARA path: Build contiguous buffer from mem-writes (and optionally regs),
    // compile patterns into YARA hex rules, run Aho-Corasick multi-pattern match.
    //
    // Advantage: O(BufferSize + TotalMatches) instead of O(Insts × Patterns).
    // For 10 patterns × 1M instructions, this is 10× faster or more.
    //
    // YARA path is available when:
    //   1. TENET_HAS_YARA is defined
    //   2. Patterns compile successfully (YARA supports wildcards via ??)
    //
    // Fallback: linear per-instruction scan (always correct), which also
    // handles exact_values inline.

#ifdef TENET_HAS_YARA
    bool use_yara = compile_patterns_to_yara();
#else
    bool use_yara = false;
#endif

    if (!use_yara) {
        // linear_scan() handles both patterns and exact_values in one pass.
        linear_scan(ctx, result);
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        return PassResult::success(std::move(result));
    }

#ifdef TENET_HAS_YARA
    {
        auto& reader = ctx.reader();

        ctx.progress(0.0f, "MemSearch: building contiguous buffers for YARA scan...");

        const uint64_t start = cfg_.start_inst_id;
        const uint64_t end = std::min(cfg_.end_inst_id, total_insts);

        // ── MERGED single-pass buffer construction ──────────────────────
        // Previously this did 2 independent full trace scans (one for mem-writes,
        // one for reg-diffs). Now we build both buffers in a single traversal,
        // saving 50% of I/O time on GB-level traces.

        std::vector<uint8_t> mem_buf;
        std::vector<uint64_t> mem_inst_ids;
        std::vector<uint64_t> mem_pcs;
        std::vector<uint64_t> mem_addrs;
        std::vector<uint8_t> mem_sizes;

        std::vector<uint8_t> reg_buf;
        std::vector<uint64_t> reg_inst_ids;
        std::vector<uint64_t> reg_pcs;
        std::vector<uint64_t> reg_addrs;
        std::vector<uint8_t> reg_sizes;

        if (cfg_.search_mem_writes) {
            size_t est_writes = (end - start) / 2;
            mem_buf.reserve(est_writes * 16);
            mem_inst_ids.reserve(est_writes);
            mem_pcs.reserve(est_writes);
            mem_addrs.reserve(est_writes);
            mem_sizes.reserve(est_writes);
        }

        if (cfg_.search_reg_values) {
            size_t est_diffs = (end - start);
            reg_buf.reserve(est_diffs * 8);
            reg_inst_ids.reserve(est_diffs);
            reg_pcs.reserve(est_diffs);
        }

        {
            uint64_t inst_id = 0;
            reader.advise_sequential();

            for (auto it = reader.begin(); it != reader.end(); ++it) {
                auto rec = *it;
                if (rec.kind != RecordKind::Inst) continue;

                inst_id++;
                if (inst_id < start) continue;
                if (inst_id > end) break;

                if (inst_id % 10000 == 0 && ctx.cancelled()) {
                    return PassResult::failed("cancelled by user");
                }

                auto inst = rec.as_inst();

                // Collect mem-write entries
                if (cfg_.search_mem_writes) {
                    for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                        auto mem = inst.mem_access(m);
                        if (!(mem.type & 0x02)) continue;  // skip reads

                        uint8_t entry[16] = {};
                        size_t actual_size = std::min(static_cast<size_t>(mem.size), size_t(16));
                        std::memcpy(entry, &mem.value, 8);
                        std::memcpy(entry + 8, &mem.value_hi, 8);

                        mem_buf.insert(mem_buf.end(), entry, entry + 16);
                        mem_inst_ids.push_back(inst_id);
                        mem_pcs.push_back(inst.pc);
                        mem_addrs.push_back(mem.addr);
                        mem_sizes.push_back(static_cast<uint8_t>(actual_size));
                    }
                }

                // Collect reg-diff entries
                if (cfg_.search_reg_values) {
                    for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                        auto diff = inst.reg_diff(d);
                        uint8_t entry[8];
                        std::memcpy(entry, &diff.value, 8);
                        reg_buf.insert(reg_buf.end(), entry, entry + 8);
                        reg_inst_ids.push_back(inst_id);
                        reg_pcs.push_back(inst.pc);
                        reg_addrs.push_back(0);
                        reg_sizes.push_back(8);
                    }
                }
            }

            result.instructions_scanned = end - start;
        }

        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }

        // ── YARA scan: mem-writes ───────────────────────────────────────
        if (cfg_.search_mem_writes && !mem_buf.empty()) {
            result.bytes_scanned += mem_buf.size();

            ctx.progress(0.4f, fmt::format("MemSearch: YARA scanning {} mem-write entries...",
                                            mem_inst_ids.size()));

            yara_scan_buffer(mem_buf.data(), mem_buf.size(),
                            mem_inst_ids, mem_pcs, mem_addrs, mem_sizes,
                            MemSearchMatch::MemWrite, result,
                            [&]() { return ctx.cancelled(); });
        }

        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }

        // ── YARA scan: reg-diffs ────────────────────────────────────────
        if (cfg_.search_reg_values && !reg_buf.empty()) {
            result.bytes_scanned += reg_buf.size();

            ctx.progress(0.7f, fmt::format("MemSearch: YARA scanning {} reg-diff entries...",
                                            reg_inst_ids.size()));

            yara_scan_buffer(reg_buf.data(), reg_buf.size(),
                            reg_inst_ids, reg_pcs, reg_addrs, reg_sizes,
                            MemSearchMatch::RegDiff, result,
                            [&]() { return ctx.cancelled(); });
        }

        reader.advise_random();
    }

    // ── Exact-value search runs as a lightweight second pass ────────────
    // (only when combined with a YARA-accelerated pattern search; the
    // exact_values-only and non-YARA-patterns cases are already fully
    // handled by linear_scan() above). scan_patterns=false avoids re-running
    // the byte-pattern brute force we already did via YARA above.
    if (!cfg_.exact_values.empty()) {
        ctx.progress(0.85f, "MemSearch: scanning for exact values...");
        MemSearchResult exact_only;
        exact_only.by_value.resize(cfg_.exact_values.size());

        linear_scan(ctx, exact_only, /*scan_patterns=*/false);

        // Merge exact-value matches into the main result, re-basing indices.
        size_t base = result.matches.size();
        for (auto& m : exact_only.matches) {
            result.matches.push_back(m);
        }
        for (size_t vi = 0; vi < exact_only.by_value.size(); vi++) {
            for (size_t idx : exact_only.by_value[vi]) {
                result.by_value[vi].push_back(base + idx);
            }
        }
        result.bytes_scanned += exact_only.bytes_scanned;
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }
    ctx.progress(1.0f, fmt::format("MemSearch: {} matches", result.matches.size()));
    return PassResult::success(std::move(result));
#endif
}

// ─── Linear scan: byte patterns (fallback) + exact values (always) ────────

void MemSearchPass::linear_scan(PassContext& ctx, MemSearchResult& result, bool scan_patterns) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const uint64_t total_insts = index.inst_count();
    const uint64_t start = cfg_.start_inst_id;
    const uint64_t end = std::min(cfg_.end_inst_id, total_insts);
    const uint64_t progress_interval = std::max(total_insts / 100, uint64_t(1));

    const bool do_patterns = scan_patterns && !cfg_.patterns.empty();
    const bool do_exact = !cfg_.exact_values.empty();

    ctx.progress(0.0f, do_patterns ? "MemSearch: linear scan (no YARA)..."
                                    : "MemSearch: exact-value scan...");

    // ── O(1) exact-value lookup maps (mirrors former LiteralSearchPass) ───
    // map[val] → indices into cfg_.exact_values, so a single hash lookup per
    // candidate value resolves all matching search values at once (handles
    // duplicate/overlapping values without an O(N) inner loop).
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> map_64;
    ankerl::unordered_dense::map<uint32_t, std::vector<size_t>> map_32;
    if (do_exact) {
        map_64.reserve(cfg_.exact_values.size());
        for (size_t i = 0; i < cfg_.exact_values.size(); i++) {
            map_64[cfg_.exact_values[i]].push_back(i);
            if (cfg_.match_32bit) {
                uint32_t v32 = static_cast<uint32_t>(cfg_.exact_values[i] & 0xFFFFFFFF);
                map_32[v32].push_back(i);
            }
        }
    }

    auto record_exact_hit = [&](uint64_t inst_id, uint64_t pc, uint64_t val,
                                 size_t vi, MemSearchMatch::Source src,
                                 uint64_t addr) {
        if (cfg_.max_matches > 0 && result.by_value[vi].size() >= cfg_.max_matches) {
            return;
        }
        MemSearchMatch m;
        m.inst_id = inst_id;
        m.pc = pc;
        m.addr = addr;
        m.offset = 0;
        m.pattern_index = static_cast<uint8_t>(vi);
        m.source = src;
        m.matched_value = val;
        m.is_exact_value_match = true;
        result.by_value[vi].push_back(result.matches.size());
        result.matches.push_back(m);
    };

    auto lookup_exact = [&](uint64_t val) -> const std::vector<size_t>* {
        auto it64 = map_64.find(val);
        if (it64 != map_64.end()) return &it64->second;
        if (cfg_.match_32bit && (val >> 32) == 0) {
            auto it32 = map_32.find(static_cast<uint32_t>(val));
            if (it32 != map_32.end()) return &it32->second;
        }
        return nullptr;
    };

    uint64_t inst_id = 0;
    reader.advise_sequential();

    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        inst_id++;
        if (inst_id < start) continue;
        if (inst_id > end) break;

        auto inst = rec.as_inst();
        result.instructions_scanned++;

        // ── Memory write values: byte patterns + exact values ──────────
        if (cfg_.search_mem_writes) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (!(mem.type & 0x02)) continue;

                uint8_t buf[16];
                std::memcpy(buf, &mem.value, 8);
                std::memcpy(buf + 8, &mem.value_hi, 8);
                size_t buf_len = std::min(static_cast<size_t>(mem.size), size_t(16));
                result.bytes_scanned += buf_len;

                if (do_patterns) {
                    for (size_t pi = 0; pi < cfg_.patterns.size(); pi++) {
                        const auto& pat = cfg_.patterns[pi];
                        if (pat.bytes.size() > buf_len) continue;
                        // Skip this pattern entirely once it has hit max_matches —
                        // without this, the inner `break` below only stops the
                        // current mem-access's offset scan, so the same pattern
                        // would keep accumulating unbounded matches across
                        // subsequent mem-accesses/instructions.
                        if (cfg_.max_matches > 0 &&
                            result.by_pattern[pi].size() >= cfg_.max_matches) {
                            continue;
                        }

                        for (size_t offset = 0; offset + pat.bytes.size() <= buf_len; offset++) {
                            if (match_at(buf, buf_len, offset, pat)) {
                                MemSearchMatch match;
                                match.inst_id = inst_id;
                                match.pc = inst.pc;
                                match.addr = mem.addr + offset;
                                match.offset = static_cast<uint16_t>(offset);
                                match.pattern_index = static_cast<uint8_t>(pi);
                                match.source = MemSearchMatch::MemWrite;
                                match.is_exact_value_match = false;
                                result.by_pattern[pi].push_back(result.matches.size());
                                result.matches.push_back(match);

                                if (cfg_.max_matches > 0 &&
                                    result.by_pattern[pi].size() >= cfg_.max_matches) {
                                    break;
                                }
                            }
                        }
                    }
                }

                if (do_exact) {
                    if (auto* indices = lookup_exact(mem.value)) {
                        for (size_t vi : *indices) {
                            record_exact_hit(inst_id, inst.pc, mem.value, vi,
                                              MemSearchMatch::MemWrite, mem.addr);
                        }
                    }
                }
            }
        }

        // ── Register diff values: byte patterns + exact values ─────────
        if (cfg_.search_reg_values) {
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);

                if (do_patterns) {
                    uint8_t buf[8];
                    std::memcpy(buf, &diff.value, 8);
                    result.bytes_scanned += 8;

                    for (size_t pi = 0; pi < cfg_.patterns.size(); pi++) {
                        const auto& pat = cfg_.patterns[pi];
                        if (pat.bytes.size() > 8) continue;
                        // Same max_matches guard as the mem-write path above —
                        // previously this loop had no cap at all, so a pattern
                        // occurring frequently in reg-diffs could grow
                        // result.by_pattern[pi] unbounded.
                        if (cfg_.max_matches > 0 &&
                            result.by_pattern[pi].size() >= cfg_.max_matches) {
                            continue;
                        }

                        for (size_t offset = 0; offset + pat.bytes.size() <= 8; offset++) {
                            if (match_at(buf, 8, offset, pat)) {
                                MemSearchMatch match;
                                match.inst_id = inst_id;
                                match.pc = inst.pc;
                                match.addr = 0;
                                match.offset = static_cast<uint16_t>(offset);
                                match.pattern_index = static_cast<uint8_t>(pi);
                                match.source = MemSearchMatch::RegDiff;
                                match.is_exact_value_match = false;
                                result.by_pattern[pi].push_back(result.matches.size());
                                result.matches.push_back(match);
                                break;
                            }
                        }
                    }
                }

                if (do_exact) {
                    if (auto* indices = lookup_exact(diff.value)) {
                        for (size_t vi : *indices) {
                            record_exact_hit(inst_id, inst.pc, diff.value, vi,
                                              MemSearchMatch::RegDiff, 0);
                        }
                    }
                }
            }
        }

        // ── MOVZ/MOVK instruction immediates: exact values only ─────────
        // Byte-pattern matching against a lone 16-bit immediate is rarely
        // useful (patterns are meant for multi-byte sequences like keys/IVs),
        // so only the exact-value path inspects immediates.
        if (do_exact && cfg_.search_immediates) {
            if (auto opcode = code_table.opcode_at(inst.pc)) {
                if (aarch64::is_movz(*opcode) || aarch64::is_movk(*opcode)) {
                    uint64_t imm = static_cast<uint64_t>(aarch64::movzk_imm16(*opcode))
                                   << aarch64::movzk_shift(*opcode);
                    if (auto* indices = lookup_exact(imm)) {
                        for (size_t vi : *indices) {
                            record_exact_hit(inst_id, inst.pc, imm, vi,
                                              MemSearchMatch::Immediate, 0);
                        }
                    }
                }
            }
        }

        if (inst_id % progress_interval == 0) {
            ctx.progress(static_cast<float>(inst_id - start) /
                         static_cast<float>(std::max<uint64_t>(end - start, 1)));
            if (ctx.cancelled()) {
                return;
            }
        }
    }

    ctx.progress(1.0f, "MemSearch: complete");
}

}  // namespace tenet

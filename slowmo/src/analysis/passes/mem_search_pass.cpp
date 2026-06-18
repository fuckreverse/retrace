#include "analysis/passes/mem_search_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#ifdef TENET_HAS_YARA
#include <yara.h>
#endif

#include <fmt/core.h>
#include <algorithm>
#include <cstring>

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
};

int memsearch_yara_callback(YR_SCAN_CONTEXT* context, int message,
                            void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    auto* ctx = static_cast<MemSearchYaraCtx*>(user_data);
    auto* rule = static_cast<YR_RULE*>(message_data);

    // Parse pattern_index from rule identifier: "pat_<idx>"
    uint8_t pattern_index = 0;
    if (rule->identifier && std::strncmp(rule->identifier, "pat_", 4) == 0) {
        pattern_index = static_cast<uint8_t>(std::atoi(rule->identifier + 4));
    }

    // Iterate all matching strings for precise offsets
    YR_STRING* str;
    yr_rule_strings_foreach(rule, str) {
        YR_MATCH* match;
        yr_string_matches_foreach(context, str, match) {
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
    MemSearchResult& result)
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

    yr_rules_scan_mem(yr_rules_, data, len, 0, memsearch_yara_callback, &ctx, 0);
}

#endif  // TENET_HAS_YARA

// ─── Main pass execution ──────────────────────────────────────────────────

PassResult MemSearchPass::run(PassContext& ctx) {
    if (cfg_.patterns.empty()) {
        return PassResult::failed("No search patterns specified");
    }

    auto& reader = ctx.reader();
    auto& index = ctx.index();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    MemSearchResult result;
    result.by_pattern.resize(cfg_.patterns.size());

    // ─── Strategy selection ───────────────────────────────────────────────
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
    // Fallback: linear per-instruction scan (always correct).

#ifdef TENET_HAS_YARA
    bool use_yara = compile_patterns_to_yara();
#else
    bool use_yara = false;
#endif

    if (use_yara) {
#ifdef TENET_HAS_YARA
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

        // ── YARA scan: mem-writes ───────────────────────────────────────
        if (cfg_.search_mem_writes && !mem_buf.empty()) {
            result.bytes_scanned += mem_buf.size();

            ctx.progress(0.4f, fmt::format("MemSearch: YARA scanning {} mem-write entries...",
                                            mem_inst_ids.size()));

            yara_scan_buffer(mem_buf.data(), mem_buf.size(),
                            mem_inst_ids, mem_pcs, mem_addrs, mem_sizes,
                            MemSearchMatch::MemWrite, result);
        }

        // ── YARA scan: reg-diffs ────────────────────────────────────────
        if (cfg_.search_reg_values && !reg_buf.empty()) {
            result.bytes_scanned += reg_buf.size();

            ctx.progress(0.7f, fmt::format("MemSearch: YARA scanning {} reg-diff entries...",
                                            reg_inst_ids.size()));

            yara_scan_buffer(reg_buf.data(), reg_buf.size(),
                            reg_inst_ids, reg_pcs, reg_addrs, reg_sizes,
                            MemSearchMatch::RegDiff, result);
        }

        reader.advise_random();
        ctx.progress(1.0f, fmt::format("MemSearch: {} matches via YARA", result.matches.size()));
        return PassResult::success(std::move(result));
#endif
    }

    // ─── Fallback: linear scan ────────────────────────────────────────────
    linear_scan(ctx, result);
    return PassResult::success(std::move(result));
}

// ─── Fallback linear scan (original logic, always correct) ────────────────

void MemSearchPass::linear_scan(PassContext& ctx, MemSearchResult& result) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();

    const uint64_t total_insts = index.inst_count();
    const uint64_t start = cfg_.start_inst_id;
    const uint64_t end = std::min(cfg_.end_inst_id, total_insts);
    const uint64_t progress_interval = std::max(total_insts / 100, uint64_t(1));

    ctx.progress(0.0f, "MemSearch: linear scan (no YARA)...");

    uint64_t inst_id = 0;

    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        inst_id++;
        if (inst_id < start) continue;
        if (inst_id > end) break;

        auto inst = rec.as_inst();
        result.instructions_scanned++;

        // Search memory write values
        if (cfg_.search_mem_writes) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (!(mem.type & 0x02)) continue;

                uint8_t buf[16];
                std::memcpy(buf, &mem.value, 8);
                std::memcpy(buf + 8, &mem.value_hi, 8);
                size_t buf_len = std::min(static_cast<size_t>(mem.size), size_t(16));
                result.bytes_scanned += buf_len;

                for (size_t pi = 0; pi < cfg_.patterns.size(); pi++) {
                    const auto& pat = cfg_.patterns[pi];
                    if (pat.bytes.size() > buf_len) continue;

                    for (size_t offset = 0; offset + pat.bytes.size() <= buf_len; offset++) {
                        if (match_at(buf, buf_len, offset, pat)) {
                            MemSearchMatch match;
                            match.inst_id = inst_id;
                            match.pc = inst.pc;
                            match.addr = mem.addr + offset;
                            match.offset = static_cast<uint16_t>(offset);
                            match.pattern_index = static_cast<uint8_t>(pi);
                            match.source = MemSearchMatch::MemWrite;
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
        }

        // Search register diff values
        if (cfg_.search_reg_values) {
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                uint8_t buf[8];
                std::memcpy(buf, &diff.value, 8);
                result.bytes_scanned += 8;

                for (size_t pi = 0; pi < cfg_.patterns.size(); pi++) {
                    const auto& pat = cfg_.patterns[pi];
                    if (pat.bytes.size() > 8) continue;

                    for (size_t offset = 0; offset + pat.bytes.size() <= 8; offset++) {
                        if (match_at(buf, 8, offset, pat)) {
                            MemSearchMatch match;
                            match.inst_id = inst_id;
                            match.pc = inst.pc;
                            match.addr = 0;
                            match.offset = static_cast<uint16_t>(offset);
                            match.pattern_index = static_cast<uint8_t>(pi);
                            match.source = MemSearchMatch::RegDiff;
                            result.by_pattern[pi].push_back(result.matches.size());
                            result.matches.push_back(match);
                            break;
                        }
                    }
                }
            }
        }

        if (inst_id % progress_interval == 0) {
            ctx.progress(static_cast<float>(inst_id - start) / (end - start));
        }
    }

    ctx.progress(1.0f, "MemSearch: complete");
}

}  // namespace tenet

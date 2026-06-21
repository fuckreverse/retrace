#include "yara_mem_scan_pass.h"

#include "analysis/pass_manager.h"
#include "core/memory_model.h"
#include "io/code_table.h"
#include "common/entropy.h"

#include <fmt/core.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#ifdef TENET_HAS_YARA
#include <yara.h>
#endif

namespace tenet {

// ─── YaraMemScanResult helpers ────────────────────────────────────────────

std::vector<const YaraMemMatch*>
YaraMemScanResult::by_category(PatternCategory cat) const {
    std::vector<const YaraMemMatch*> out;
    for (const auto& m : matches) {
        if (m.category == cat) out.push_back(&m);
    }
    return out;
}

// ─── Constructor / Destructor ─────────────────────────────────────────────

YaraMemScanPass::YaraMemScanPass(YaraMemScanConfig cfg)
    : cfg_(std::move(cfg)) {}

YaraMemScanPass::~YaraMemScanPass() {
#ifdef TENET_HAS_YARA
    if (yr_rules_) {
        yr_rules_destroy(yr_rules_);
        yr_rules_ = nullptr;
    }
    yr_finalize();
#endif
}

YaraMemScanPass::YaraMemScanPass(YaraMemScanPass&&) noexcept = default;
YaraMemScanPass& YaraMemScanPass::operator=(YaraMemScanPass&&) noexcept = default;

// ─── YARA helpers ─────────────────────────────────────────────────────────

#ifdef TENET_HAS_YARA

namespace {

/// YARA callback state for collecting matches.
struct YaraCallbackCtx {
    YaraMemScanResult* result;
    uint64_t           base_addr;
    uint64_t           at_inst_id;
    std::string        label;
};

/// YARA rule match callback (called per-match).
static int yara_callback(YR_SCAN_CONTEXT* ctx, int msg, void* msg_data, void* user_data) {
    (void)ctx;
    if (msg != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    auto* yr_rule = static_cast<YR_RULE*>(msg_data);
    auto* cb_ctx  = static_cast<YaraCallbackCtx*>(user_data);

    // Extract meta fields
    std::string description, cat_str, conf_str;
    YR_META* meta;
    yr_rule_metas_foreach(yr_rule, meta) {
        if (meta->type == META_TYPE_STRING) {
            if (std::string_view(meta->identifier) == "description")
                description = meta->string;
            else if (std::string_view(meta->identifier) == "category")
                cat_str = meta->string;
            else if (std::string_view(meta->identifier) == "confidence")
                conf_str = meta->string;
        }
    }

    PatternCategory  cat  = PatternPass::parse_category(cat_str);
    PatternConfidence conf = PatternPass::parse_confidence(conf_str);

    // Enumerate match strings to find first match offset and length
    YR_STRING* yr_str;
    yr_rule_strings_foreach(yr_rule, yr_str) {
        YR_MATCH* match;
        yr_string_matches_foreach(ctx, yr_str, match) {
            YaraMemMatch m;
            m.rule_name    = yr_rule->identifier;
            m.category     = cat;
            m.confidence   = conf;
            m.description  = description;
            m.scan_addr    = cb_ctx->base_addr;
            m.match_offset = static_cast<uint64_t>(match->offset);
            m.match_addr   = cb_ctx->base_addr + m.match_offset;
            m.match_length = static_cast<uint32_t>(match->match_length);
            m.at_inst_id   = cb_ctx->at_inst_id;
            m.scan_label   = cb_ctx->label;
            cb_ctx->result->matches.push_back(std::move(m));
        }
    }
    return CALLBACK_CONTINUE;
}

}  // anonymous namespace

bool YaraMemScanPass::load_rules(const std::filesystem::path& default_dir) {
    yr_initialize();

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        return false;
    }

    auto add_dir = [&](const std::filesystem::path& dir) -> bool {
        if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
            return true;  // not an error
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.path().extension() != ".yar") continue;
            FILE* f = fopen(entry.path().c_str(), "r");
            if (!f) continue;
            int err = yr_compiler_add_file(compiler, f, nullptr,
                                           entry.path().filename().c_str());
            fclose(f);
            if (err > 0) {
                // Compiler warnings — not fatal
            }
        }
        return true;
    };

    auto add_file = [&](const std::filesystem::path& fpath) -> bool {
        if (!std::filesystem::exists(fpath)) return true;
        if (std::filesystem::is_directory(fpath)) return add_dir(fpath);
        FILE* f = fopen(fpath.c_str(), "r");
        if (!f) return false;
        int err = yr_compiler_add_file(compiler, f, nullptr,
                                       fpath.filename().c_str());
        fclose(f);
        return err == 0;
    };

    // 1. Default rules dir
    add_dir(default_dir);

    // 2. User-supplied extra rules
    for (const auto& extra : cfg_.extra_rules) {
        add_file(extra);
    }

    // 3. User rules dir
    if (!cfg_.user_rules_dir.empty()) {
        add_dir(cfg_.user_rules_dir);
    }

    if (yr_compiler_get_rules(compiler, &yr_rules_) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return false;
    }
    yr_compiler_destroy(compiler);
    rules_loaded_ = true;
    return true;
}

void YaraMemScanPass::scan_buffer(const uint8_t* data, size_t size,
                                   uint64_t base_addr, uint64_t at_inst_id,
                                   const std::string& label,
                                   YaraMemScanResult& result) {
    if (!yr_rules_ || size == 0) return;

    // Entropy pre-filter
    if (cfg_.min_entropy_threshold > 0.0f) {
        float ent = tenet::shannon_entropy(data, size);
        if (ent < cfg_.min_entropy_threshold) {
            result.pages_skipped_entropy++;
            return;
        }
    }

    YaraCallbackCtx cb_ctx{&result, base_addr, at_inst_id, label};
    yr_rules_scan_mem(yr_rules_,
                      data, size,
                      SCAN_FLAGS_FAST_MODE,
                      yara_callback, &cb_ctx,
                      /* timeout */ 10);

    result.pages_scanned++;
    result.bytes_scanned += size;
}

float YaraMemScanPass::compute_shannon_entropy(const uint8_t* data, size_t size) {
return tenet::shannon_entropy(data, size);
}

#endif  // TENET_HAS_YARA

// ─── YaraMemScanPass::run ─────────────────────────────────────────────────

PassResult YaraMemScanPass::run(PassContext& ctx) {
#ifndef TENET_HAS_YARA
    return PassResult::failed("YaraMemScanPass: YARA support not compiled in (TENET_ENABLE_YARA=OFF)");
#else
    // Find default rules directory (same dir as executable ../../rules, or next to binary)
    std::filesystem::path default_rules_dir;
    {
        // Try well-known locations relative to CWD / executable
        // 1. <cwd>/rules/
        auto cwd_rules = std::filesystem::current_path() / "rules";
        if (std::filesystem::exists(cwd_rules)) {
            default_rules_dir = cwd_rules;
        }
        // 2. ../rules/ (build/ dir scenario)
        auto up_rules = std::filesystem::current_path() / ".." / "rules";
        if (default_rules_dir.empty() && std::filesystem::exists(up_rules)) {
            default_rules_dir = std::filesystem::canonical(up_rules);
        }
    }

    if (!load_rules(default_rules_dir)) {
        return PassResult::failed("YaraMemScanPass: failed to load YARA rules");
    }

    YaraMemScanResult result;
    auto& memory = ctx.memory();

    // ── Explicit scan points ─────────────────────────────────────────────
    for (const auto& sp : cfg_.scan_points) {
        uint64_t sz = sp.size == 0 ? 4096 : sp.size;
        sz = std::min(sz, cfg_.max_bytes_per_page);
        uint64_t inst_id = (sp.inst_id == 0) ? ctx.index().inst_count() : sp.inst_id;

        auto rr = memory.read_region(sp.addr, sz, inst_id);
        if (rr.known_count == 0) continue;

        scan_buffer(rr.data.data(), rr.data.size(),
                    sp.addr, inst_id, sp.label, result);
    }

    // ── Auto-scan active pages ────────────────────────────────────────────
    if (cfg_.auto_scan_all_pages) {
        uint64_t trace_end = ctx.index().inst_count();
        auto pages = memory.active_pages();

        for (const auto& page : pages) {
            if (page.write_count < cfg_.min_writes_per_page) continue;

            // Scan at last-write point so we see the final state of the page
            uint64_t at_id = std::min(page.last_inst_id + 1, trace_end);
            uint64_t sz = std::min(static_cast<uint64_t>(4096), cfg_.max_bytes_per_page);

            auto rr = memory.read_region(page.page_addr, sz, at_id);
            if (rr.known_count < 4) continue;  // skip pages with almost no known data

            std::string label = fmt::format("page@0x{:X}", page.page_addr);
            scan_buffer(rr.data.data(), rr.data.size(),
                        page.page_addr, at_id, label, result);
        }
    }

    // ── Code buffer scan ─────────────────────────────────────────────────
    // Reconstruct a contiguous byte buffer from the CodeTable's sorted entries.
    // Each entry is (runtime_pc, opcode_u32_le); we write them in PC order so
    // YARA can match byte patterns that span adjacent instructions.
    if (cfg_.scan_code_buffer) {
        try {
            auto& ct = ctx.code_table();
            auto entries = ct.all_entries();  // sorted vector<pair<uint64_t,uint32_t>>
            if (!entries.empty()) {
                // Flatten: write each 4-byte opcode in little-endian order
                std::vector<uint8_t> code_bytes;
                code_bytes.reserve(entries.size() * 4);
                for (const auto& [pc, opcode] : entries) {
                    code_bytes.push_back(static_cast<uint8_t>(opcode & 0xFF));
                    code_bytes.push_back(static_cast<uint8_t>((opcode >> 8) & 0xFF));
                    code_bytes.push_back(static_cast<uint8_t>((opcode >> 16) & 0xFF));
                    code_bytes.push_back(static_cast<uint8_t>((opcode >> 24) & 0xFF));
                }
                uint64_t base_addr = entries.front().first;
                scan_buffer(code_bytes.data(), code_bytes.size(),
                            base_addr, 0, "code_buffer", result);
            }
        } catch (...) {
            // code_table may not be available in all contexts — silently skip
        }
    }

    // Remove duplicate matches (same rule + addr + inst_id)
    std::sort(result.matches.begin(), result.matches.end(),
        [](const YaraMemMatch& a, const YaraMemMatch& b) {
            if (a.rule_name != b.rule_name) return a.rule_name < b.rule_name;
            if (a.match_addr != b.match_addr) return a.match_addr < b.match_addr;
            return a.at_inst_id < b.at_inst_id;
        });
    result.matches.erase(std::unique(result.matches.begin(), result.matches.end(),
        [](const YaraMemMatch& a, const YaraMemMatch& b) {
            return a.rule_name == b.rule_name && a.match_addr == b.match_addr
                   && a.at_inst_id == b.at_inst_id;
        }), result.matches.end());

    return PassResult::success(std::move(result));
#endif
}

}  // namespace tenet

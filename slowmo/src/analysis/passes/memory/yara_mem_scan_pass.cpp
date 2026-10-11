#include "common/platform_file.h"
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

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

namespace tenet {

// ─── Executable path resolution ────────────────────────────────────────────
//
// Resolving the default rules directory relative to the process's *current
// working directory* (as the previous implementation did) is fragile: the
// GUI app may be launched from Finder (cwd = "/"), tests may be invoked via
// `ctest` from an arbitrary directory, and CLI users may pass an absolute
// path to the `tenet` binary from anywhere. In all of those cases
// `<cwd>/rules` / `<cwd>/../rules` do not exist, silently yielding zero
// loaded rules — the pass still reports success (0 matches), which is
// indistinguishable from "ran fine, target just has no crypto in memory".
//
// Resolving relative to the *executable's own path* is robust to all of the
// above, mirroring how `tenet/rules/` sits next to the build output
// (`slowmo/build/tenet` -> `slowmo/rules/`).
namespace {

/// Best-effort absolute path to the running executable. Returns an empty
/// path if it could not be determined (caller falls back to cwd-relative
/// lookup only).
std::filesystem::path current_executable_path() {
#if defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);  // first call: query required size
    std::string buf(size, '\0');
    if (_NSGetExecutablePath(buf.data(), &size) != 0) return {};
    std::error_code ec;
    auto resolved = std::filesystem::canonical(buf, ec);
    return ec ? std::filesystem::path(buf) : resolved;
#elif defined(__linux__)
    std::error_code ec;
    auto resolved = std::filesystem::canonical("/proc/self/exe", ec);
    return ec ? std::filesystem::path() : resolved;
#else
    return {};
#endif
}

}  // namespace

std::vector<std::filesystem::path> YaraMemScanPass::find_default_rules_dirs() {
    std::vector<std::filesystem::path> out;
    auto add_unique = [&](std::filesystem::path p) {
        if (p.empty()) return;
        std::error_code ec;
        auto canon = std::filesystem::weakly_canonical(p, ec);
        if (!ec) p = canon;
        if (std::find(out.begin(), out.end(), p) == out.end()) out.push_back(std::move(p));
    };

    // 1. Relative to the executable's own directory — robust regardless of
    //    cwd. Covers both the flat build layout (bin next to rules/) and a
    //    one-level-deeper install layout (bin/ + rules/ siblings under a
    //    common prefix, or an .app bundle's Contents/MacOS/).
    auto exe = current_executable_path();
    if (!exe.empty()) {
        auto exe_dir = exe.parent_path();
        add_unique(exe_dir / "rules");
        add_unique(exe_dir / ".." / "rules");
        add_unique(exe_dir / ".." / ".." / "rules");
    }

    // 2. Relative to cwd — secondary fallback, kept for compatibility with
    //    any existing scripts/docs/tests that rely on `cd build && ./tenet`.
    auto cwd = std::filesystem::current_path();
    add_unique(cwd / "rules");
    add_unique(cwd / ".." / "rules");

    return out;
}

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
    const std::function<bool()>* cancel_check = nullptr;
};

/// YARA rule match callback (called per-match).
static int yara_callback(YR_SCAN_CONTEXT* ctx, int msg, void* msg_data, void* user_data) {
    (void)ctx;
    auto* cb_ctx  = static_cast<YaraCallbackCtx*>(user_data);
    if (cb_ctx->cancel_check && *cb_ctx->cancel_check && (*cb_ctx->cancel_check)()) {
        return CALLBACK_ABORT;
    }
    if (msg != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    auto* yr_rule = static_cast<YR_RULE*>(msg_data);

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

bool YaraMemScanPass::load_rules(const std::vector<std::filesystem::path>& default_dirs,
                                  uint64_t& n_loaded,
                                  std::vector<std::string>& searched) {
    n_loaded = 0;
    yr_initialize();

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        return false;
    }

    auto add_dir = [&](const std::filesystem::path& dir) {
        searched.push_back(dir.string());
        if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
            return;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.path().extension() != ".yar") continue;
            FILE* f = tenet::platform::open_file(entry.path(), "r");
            if (!f) continue;
            int err = yr_compiler_add_file(compiler, f, nullptr,
                                           entry.path().filename().c_str());
            fclose(f);
            if (err == 0) {
                n_loaded++;
            }
            // err > 0: compiler warnings/errors for this file — not fatal to
            // the overall load, but this file does not count as loaded.
        }
    };

    auto add_file = [&](const std::filesystem::path& fpath) {
        if (std::filesystem::is_directory(fpath)) {
            add_dir(fpath);
            return;
        }
        searched.push_back(fpath.string());
        if (!std::filesystem::exists(fpath)) return;
        FILE* f = tenet::platform::open_file(fpath, "r");
        if (!f) return;
        int err = yr_compiler_add_file(compiler, f, nullptr,
                                       fpath.filename().c_str());
        fclose(f);
        if (err == 0) n_loaded++;
    };

    // 1. Default rules dirs (executable-relative first, then cwd-relative).
    for (const auto& dir : default_dirs) {
        add_dir(dir);
    }

    // 2. User-supplied extra rules (files or directories).
    for (const auto& extra : cfg_.extra_rules) {
        add_file(extra);
    }

    // 3. User rules dir.
    if (!cfg_.user_rules_dir.empty()) {
        add_dir(cfg_.user_rules_dir);
    }

    if (yr_compiler_get_rules(compiler, &yr_rules_) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return false;
    }
    yr_compiler_destroy(compiler);
    rules_loaded_ = (n_loaded > 0);
    return n_loaded > 0;
}

void YaraMemScanPass::scan_buffer(const uint8_t* data, size_t size,
                                   uint64_t base_addr, uint64_t at_inst_id,
                                   const std::string& label,
                                   YaraMemScanResult& result,
                                   const std::function<bool()>& cancel_check) {
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
    cb_ctx.cancel_check = &cancel_check;
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
    auto default_dirs = find_default_rules_dirs();

    uint64_t n_loaded = 0;
    std::vector<std::string> searched;
    bool compiler_ok = load_rules(default_dirs, n_loaded, searched);

    if (!compiler_ok) {
        return PassResult::failed("YaraMemScanPass: failed to initialize YARA compiler");
    }
    if (n_loaded == 0) {
        // Loading "succeeded" (the compiler didn't error), but zero .yar
        // files were actually found/compiled anywhere we looked. Reporting
        // success here would be indistinguishable from "scanned fine, no
        // crypto found" — fail loudly instead and tell the user exactly
        // which directories were searched so they can fix their rules_dir
        // or extra_rules configuration.
        std::string dirs_str;
        for (const auto& d : searched) {
            if (!dirs_str.empty()) dirs_str += ", ";
            dirs_str += d;
        }
        return PassResult::failed(fmt::format(
            "YaraMemScanPass: no .yar rule files found. Searched: [{}]. "
            "Pass an explicit rules directory via YaraMemScanConfig::user_rules_dir "
            "or --yara-rules.", dirs_str));
    }

    YaraMemScanResult result;
    result.rules_loaded = n_loaded;
    result.rule_search_dirs = searched;
    auto& memory = ctx.memory();

    ctx.progress(0.0f, "YaraMemScan: scanning explicit points...");

    // ── Explicit scan points ─────────────────────────────────────────────
    for (const auto& sp : cfg_.scan_points) {
        if (ctx.cancelled()) return PassResult::failed("YaraMemScan: cancelled by user");

        uint64_t sz = sp.size == 0 ? 4096 : sp.size;
        sz = std::min(sz, cfg_.max_bytes_per_page);
        uint64_t inst_id = (sp.inst_id == 0) ? ctx.index().inst_count() : sp.inst_id;

        auto rr = memory.read_region(sp.addr, sz, inst_id);
        if (rr.known_count == 0) continue;

        scan_buffer(rr.data.data(), rr.data.size(),
                    sp.addr, inst_id, sp.label, result,
                    [&]() { return ctx.cancelled(); });
    }

    // ── Auto-scan active pages ────────────────────────────────────────────
    if (cfg_.auto_scan_all_pages) {
        ctx.progress(0.1f, "YaraMemScan: scanning active pages...");

        uint64_t trace_end = ctx.index().inst_count();
        auto pages = memory.active_pages();
        const size_t total_pages = pages.size();
        size_t page_idx = 0;

        for (const auto& page : pages) {
            if (ctx.cancelled()) return PassResult::failed("YaraMemScan: cancelled by user");

            page_idx++;
            if (page_idx % 64 == 0 && total_pages > 0) {
                ctx.progress(0.1f + 0.7f * static_cast<float>(page_idx) /
                             static_cast<float>(total_pages),
                             "YaraMemScan: scanning active pages...");
            }

            if (page.write_count < cfg_.min_writes_per_page) continue;

            // Scan at last-write point so we see the final state of the page
            uint64_t at_id = std::min(page.last_inst_id + 1, trace_end);
            uint64_t sz = std::min(static_cast<uint64_t>(4096), cfg_.max_bytes_per_page);

            auto rr = memory.read_region(page.page_addr, sz, at_id);
            if (rr.known_count < 4) continue;  // skip pages with almost no known data

            std::string label = fmt::format("page@0x{:X}", page.page_addr);
            scan_buffer(rr.data.data(), rr.data.size(),
                        page.page_addr, at_id, label, result,
                        [&]() { return ctx.cancelled(); });
        }
    }

    if (ctx.cancelled()) return PassResult::failed("YaraMemScan: cancelled by user");

    // ── Code buffer scan ─────────────────────────────────────────────────
    // Reconstruct a contiguous byte buffer from the CodeTable's sorted entries.
    // Each entry is (runtime_pc, opcode_u32_le); we write them in PC order so
    // YARA can match byte patterns that span adjacent instructions.
    if (cfg_.scan_code_buffer) {
        if (ctx.cancelled()) return PassResult::failed("YaraMemScan: cancelled by user");
        ctx.progress(0.8f, "YaraMemScan: scanning code buffer...");
        try {
            auto& ct = ctx.code_table();
            auto entries = ct.all_entries();  // sorted vector<pair<uint64_t,uint32_t>>
            if (!entries.empty()) {
                // Flatten: write each 4-byte opcode in little-endian order
                std::vector<uint8_t> code_bytes;
                code_bytes.reserve(entries.size() * 4);
                for (const auto& [pc, opcode] : entries) {
                    (void)pc;
                    if ((code_bytes.size() % (4096 * 4)) == 0 && ctx.cancelled()) {
                        return PassResult::failed("YaraMemScan: cancelled by user");
                    }
                    code_bytes.push_back(static_cast<uint8_t>(opcode & 0xFF));
                    code_bytes.push_back(static_cast<uint8_t>((opcode >> 8) & 0xFF));
                    code_bytes.push_back(static_cast<uint8_t>((opcode >> 16) & 0xFF));
                    code_bytes.push_back(static_cast<uint8_t>((opcode >> 24) & 0xFF));
                }
                uint64_t base_addr = entries.front().first;
                scan_buffer(code_bytes.data(), code_bytes.size(),
                            base_addr, 0, "code_buffer", result,
                            [&]() { return ctx.cancelled(); });
            }
        } catch (...) {
            // code_table may not be available in all contexts — silently skip
        }
    }

    if (ctx.cancelled()) return PassResult::failed("YaraMemScan: cancelled by user");

    ctx.progress(0.9f, "YaraMemScan: deduplicating results...");

    // Remove duplicate matches (same rule + addr + inst_id)
    if (ctx.cancelled()) return PassResult::failed("YaraMemScan: cancelled by user");

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

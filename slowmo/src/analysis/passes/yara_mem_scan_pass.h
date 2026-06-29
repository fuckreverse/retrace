#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/pattern_pass.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <filesystem>

#ifdef TENET_HAS_YARA
struct YR_RULES;
#endif

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct YaraMemScanConfig {
    /// YARA rule files or directories to load (in addition to the default rules dir).
    /// Each entry can be a .yar file path or a directory containing .yar files.
    std::vector<std::filesystem::path> extra_rules;

    /// Memory snapshot points: list of (addr, size, inst_id) to scan.
    /// If empty, all pages that were written during the trace are scanned at
    /// their last-write point.
    struct ScanPoint {
        uint64_t addr;
        uint64_t size;      ///< 0 = full page (4096 bytes)
        uint64_t inst_id;   ///< 0 = end of trace
        std::string label;
    };
    std::vector<ScanPoint> scan_points;

    /// Automatically scan all active memory pages at end of trace.
    bool auto_scan_all_pages = true;

    /// When auto-scanning, skip pages whose total write count is below this.
    uint32_t min_writes_per_page = 1;

    /// Maximum bytes to scan per page (to limit scan time on huge allocations).
    uint64_t max_bytes_per_page = 65536;

    /// Path for user-supplied .yar rule files (in addition to defaults).
    std::filesystem::path user_rules_dir;

    /// Whether to scan the code (instruction bytes) buffer through memory rules.
    /// This finds crypto constants embedded in code sections.
    bool scan_code_buffer = false;

    /// Minimum entropy threshold: only auto-scan pages with Shannon entropy > this.
    /// Set 0.0 to scan all pages.  Set 4.0 to skip zero/uniform pages.
    float min_entropy_threshold = 0.0f;
};

// ─── Per-match result ──────────────────────────────────────────────────────

/// A single YARA rule match against a memory snapshot.
struct YaraMemMatch {
    std::string rule_name;
    PatternCategory category;
    PatternConfidence confidence;
    std::string description;

    uint64_t scan_addr;     ///< Base address of the scanned buffer
    uint64_t match_offset;  ///< Byte offset within the buffer where match starts
    uint64_t match_addr;    ///< Absolute runtime address (scan_addr + match_offset)
    uint32_t match_length;  ///< Length of the matched region
    uint64_t at_inst_id;    ///< Trace time at which the snapshot was taken
    std::string scan_label; ///< Human-readable label for the scan point
};

/// Full result of the YaraMemScanPass.
struct YaraMemScanResult {
    std::vector<YaraMemMatch> matches;

    /// How many memory pages (or scan points) were actually scanned.
    uint64_t pages_scanned = 0;

    /// Total bytes scanned.
    uint64_t bytes_scanned = 0;

    /// Number of pages that had insufficient entropy and were skipped.
    uint64_t pages_skipped_entropy = 0;

    /// Convenience: get all matches of a specific category.
    std::vector<const YaraMemMatch*> by_category(PatternCategory cat) const;

    size_t total() const { return matches.size(); }
};

// ─── YaraMemScanPass ──────────────────────────────────────────────────────

/// Performs YARA rule scanning against memory snapshots extracted from the trace.
///
/// Unlike PatternPass which scans register-value/syscall/code buffers, this pass
/// scans *heap/stack memory* — the actual data buffers that the target code
/// reads and writes.  This finds:
///
///   • Crypto constants materialised in memory (AES S-Box, SHA-256 IV etc.)
///   • Network protocols embedded in plaintext/ciphertext data
///   • Anti-debug strings (ptrace, JDWP, frida-server etc.)
///   • Key material / DER-encoded certificates
///   • Packed/compressed payloads (PKZIP, zlib magic bytes)
///
/// Memory snapshots are obtained via MemoryModel::read_region() at configurable
/// points in the trace.  Auto-scanning mode visits all active pages at their
/// final state (end of trace).
///
/// YARA rules are loaded from:
///   1. Default rules directory: <exe_dir>/../rules/
///   2. User-supplied extra_rules paths
///   3. config.user_rules_dir
///
/// Dependencies: none (optional: function pass for function-call scan points).
///
/// Result type: YaraMemScanResult
class YaraMemScanPass final : public AnalysisPass {
public:
    explicit YaraMemScanPass(YaraMemScanConfig cfg = {});
    ~YaraMemScanPass() override;

    YaraMemScanPass(YaraMemScanPass&&) noexcept;
    YaraMemScanPass& operator=(YaraMemScanPass&&) noexcept;
    YaraMemScanPass(const YaraMemScanPass&) = delete;
    YaraMemScanPass& operator=(const YaraMemScanPass&) = delete;

    std::string_view name() const override { return "yara_mem_scan"; }
    std::string_view description() const override {
        return "YARA-rule scanning of memory snapshots (heap/stack crypto constants & patterns)";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 12.0f; }

private:
#ifdef TENET_HAS_YARA
    bool load_rules(const std::filesystem::path& default_dir);
    void scan_buffer(const uint8_t* data, size_t size,
                     uint64_t base_addr, uint64_t at_inst_id,
                     const std::string& label,
                     YaraMemScanResult& result,
                     const std::function<bool()>& cancel_check = {});
    static float compute_shannon_entropy(const uint8_t* data, size_t size);

    YR_RULES* yr_rules_ = nullptr;
#endif

    YaraMemScanConfig cfg_;
    bool rules_loaded_ = false;
};

}  // namespace tenet

#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "analysis/passes/memory/string_pass.h"  // reuse StringRef, StringResult types
#include "core/memory_model.h"            // MemoryModel::RegionReadResult
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Configuration ────────────────────────────────────────────────────────

struct MemoryStringConfig {
    /// Maximum bytes to read per pointer (scan window).
    size_t scan_size = 256;

    /// Minimum pointer value to consider valid (AArch64: >= 4GB).
    uint64_t min_pointer_value = 0x100000000ULL;

    /// Whether to scan SP-relative memory (stack strings).
    bool scan_stack = true;

    /// Stack scan window (bytes above and below SP).
    size_t stack_scan_size = 512;

    /// Maximum number of call sites to process (0 = unlimited).
    size_t max_call_sites = 0;

    /// Whether to do deep probe: when a partial string is found,
    /// try earlier time points to find the complete version.
    bool deep_probe = true;

    /// Maximum number of *actual writes* to walk backward through when deep
    /// probing (via MemoryModel::last_writer() / write-history traversal),
    /// not a fixed instruction-count stride — each step corresponds to one
    /// real write that touched the probed address.
    size_t deep_probe_max_steps = 50;

    /// Minimum string length to report.
    size_t min_string_len = 4;

    /// Maximum string length to report.
    size_t max_string_len = 512;
};

// ─── Result types ─────────────────────────────────────────────────────────

/// A string discovered through time-aware memory reconstruction.
struct MemoryString {
    uint64_t addr;               // String start address in memory
    uint64_t discovered_at;      // inst_id when this string was observed
    std::string content;         // UTF-8 string content

    enum Encoding { ASCII, UTF8, UTF16LE };
    Encoding encoding = ASCII;

    /// How this string was discovered.
    enum Source {
        RegPointer,    // Found via register pointing to this address
        StackLocal,    // Found on the stack near SP
        DeepProbe,     // Found by probing earlier time point
        PageScan,      // Found via full page scan (fallback)
    };
    Source source = RegPointer;

    /// Which register pointed to this string (0-7 for x0-x7, 31 for SP).
    uint8_t source_reg = 0xFF;

    /// The call site inst_id where this was found (for RegPointer/StackLocal).
    uint64_t call_site_inst_id = 0;

    /// PC of the call instruction.
    uint64_t call_site_pc = 0;
};

/// Result of the memory string pass.
struct MemoryStringResult {
    std::vector<MemoryString> strings;

    /// addr → indices (multiple strings at same addr, different times).
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> by_addr;

    /// inst_id → indices (all strings visible at a call site).
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> by_call_site;

    /// Deduplicated (addr, content) hash set — used only for O(1)
    /// "already found?" checks during add_string() and for the
    /// unique_count() statistic.  Stores a combined hash of (addr, content)
    /// rather than the formatted string "addr:content" to avoid per-entry
    /// string allocation + fmt::format overhead on the hot add path.
    ankerl::unordered_dense::set<uint64_t> unique_hashes;

    /// Lookup strings at a specific address.
    std::vector<const MemoryString*> at_addr(uint64_t addr) const {
        std::vector<const MemoryString*> result;
        auto it = by_addr.find(addr);
        if (it == by_addr.end()) return result;
        for (size_t idx : it->second) result.push_back(&strings[idx]);
        return result;
    }

    /// Lookup strings found at a specific call site.
    std::vector<const MemoryString*> at_call_site(uint64_t inst_id) const {
        std::vector<const MemoryString*> result;
        auto it = by_call_site.find(inst_id);
        if (it == by_call_site.end()) return result;
        for (size_t idx : it->second) result.push_back(&strings[idx]);
        return result;
    }

    /// Search strings by content substring (case-insensitive).
    std::vector<const MemoryString*> search(const std::string& pattern) const;

    /// Total count.
    size_t total() const { return strings.size(); }

    /// Count of unique (addr, content) pairs.
    size_t unique_count() const { return unique_hashes.size(); }
};

// ─── MemoryStringCollector ────────────────────────────────────────────────

/// TraceCollector that identifies call-site instructions (BL/BLR/SVC) and
/// Objective-C message sends (REC_OBJC) during a single sequential scan.
/// Collects (inst_id, pc) pairs for both kinds of call sites — ObjC messages
/// pass their arguments through the same x0-x7 GPR convention as a regular
/// AArch64 call, so Phase 2's register/stack scan applies unchanged to them.
///
/// The heavy analysis (regfile snapshot, memory read, string scanning) is done
/// afterwards in MemoryStringPass::run(), since it requires random-access
/// queries to RegisterFile and MemoryModel.
class MemoryStringCollector final : public TraceCollector {
public:
    struct CallSite {
        uint64_t inst_id;
        uint64_t pc;
    };

    explicit MemoryStringCollector(const CodeTable& code_table,
                                    const MemoryStringConfig& config)
        : code_table_(code_table), config_(config) {}

    std::string_view name() const override { return "MemoryStringCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void on_objc(uint64_t inst_id, const ObjcView& objc) override;
    void end() override {}

    const std::vector<CallSite>& call_sites() const { return call_sites_; }

private:
    const CodeTable& code_table_;
    const MemoryStringConfig& config_;
    std::vector<CallSite> call_sites_;

    /// Add a call site, respecting max_call_sites and de-duplicating
    /// (an ObjC REC_OBJC record and its underlying BL to objc_msgSend can
    /// both land on the same inst_id/pc in some trace configurations).
    void add_call_site(uint64_t inst_id, uint64_t pc);
};

// ─── Pass ─────────────────────────────────────────────────────────────────

/// Time-aware string discovery pass.
///
/// Unlike the basic StringPass which builds a flat byte cache from all memory
/// events (losing temporal information), this pass reconstructs memory state at
/// specific "interesting" points in time (function calls, SVCs, ObjC messages)
/// and scans for strings in the reconstructed memory.
///
/// This discovers strings that:
/// - Only exist temporarily (overwritten later)
/// - Are pointed to by registers at call sites (function arguments)
/// - Live on the stack as local variables
/// - Were missed by the basic StringPass due to temporal overlap
///
/// Result type: MemoryStringResult
class MemoryStringPass final : public AnalysisPass {
public:
    explicit MemoryStringPass(MemoryStringConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "memory_strings"; }
    std::string_view description() const override {
        return "Time-aware string discovery via memory reconstruction at call sites";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // Standalone — uses raw trace + memory model + register file
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }

private:
    /// Scan a memory region for printable strings.
    /// Returns all strings found (may be multiple within one region).
    ///
    /// `data` points at `size` raw bytes; `known` points at `size` bytes that
    /// are 1 when the corresponding data byte was observed (written) at the
    /// queried point in time and 0 otherwise.  Passing `known` as a plain byte
    /// array (instead of the std::vector<bool> returned by MemoryModel) keeps
    /// the inner scan loops branch-light and vectorisable — bit-packed
    /// vector<bool> access dominated the hot loop profile.
    struct ScanHit {
        size_t offset;        // offset within the scanned region
        std::string content;
        MemoryString::Encoding encoding;
    };
    std::vector<ScanHit> scan_for_strings(const uint8_t* data,
                                           const uint8_t* known,
                                           size_t size,
                                           size_t min_len, size_t max_len);

    /// Whether a hit was cut off by the edge of the scanned region (as
    /// opposed to ending on a NUL terminator or non-printable byte found
    /// *within* the region) — only such hits can possibly be extended by
    /// deep_probe_string(), since anything ending mid-window is already
    /// known-complete.
    static bool is_hit_truncated(const ScanHit& hit, const MemoryModel::RegionReadResult& region);

    /// Try to find a more complete version of a partial string by probing
    /// earlier time points.
    ///
    /// Unlike a blind equidistant backward sweep, this walks the *actual*
    /// write history of the byte range via MemoryModel::last_writer(),
    /// so every probe point corresponds to a real write that touched this
    /// address — no time is wasted sampling instants where nothing changed,
    /// and no real "this is where the string was assembled" instant is
    /// skipped over by a coarse fixed stride.
    std::string deep_probe_string(MemoryModel& memory, uint64_t addr,
                                   uint64_t current_inst_id,
                                   const std::string& current_content);

    MemoryStringConfig config_;
};

}  // namespace tenet

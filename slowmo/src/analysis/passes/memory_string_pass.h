#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/string_pass.h"  // reuse StringRef, StringResult types
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

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

    /// Maximum backward time steps for deep probe.
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
    std::unordered_map<uint64_t, std::vector<size_t>> by_addr;

    /// inst_id → indices (all strings visible at a call site).
    std::unordered_map<uint64_t, std::vector<size_t>> by_call_site;

    /// Deduplicated content set (for quick "already found?" checks).
    std::unordered_set<std::string> unique_contents;

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

    /// Count of unique string contents.
    size_t unique_count() const { return unique_contents.size(); }
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
    struct ScanHit {
        size_t offset;        // offset within the scanned region
        std::string content;
        MemoryString::Encoding encoding;
    };
    std::vector<ScanHit> scan_for_strings(const std::vector<uint8_t>& data,
                                           const std::vector<bool>& known,
                                           size_t min_len, size_t max_len);

    /// Try to find a more complete version of a partial string by probing
    /// earlier time points.
    std::string deep_probe_string(MemoryModel& memory, uint64_t addr,
                                   uint64_t current_inst_id,
                                   const std::string& current_content);

    MemoryStringConfig config_;
};

}  // namespace tenet

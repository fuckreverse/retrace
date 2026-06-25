#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/constant_materialization_pass.h"
#include <cstdint>
#include <string>
#include <vector>
#include <ankerl/unordered_dense.h>
#include <filesystem>

#ifdef TENET_HAS_YARA
// Forward declare YARA types to avoid leaking yara.h
struct YR_RULES;
#endif

namespace tenet {

// ─── Pattern category and confidence ──────────────────────────────────────

enum class PatternCategory {
    Crypto,         // Cryptographic algorithms
    AntiDebug,      // Anti-debugging techniques
    AntiTamper,     // Anti-tamper / integrity checks
    Obfuscation,    // Code obfuscation
    Networking,     // Network communication patterns
    KeySchedule,    // Key schedule / key expansion
};

enum class PatternConfidence {
    Low,            // Possible false positive
    Medium,         // High likelihood
    High,          // Almost certain
};

// ─── Single pattern match ─────────────────────────────────────────────────

struct PatternMatch {
    std::string pattern_name;                   // e.g. "AES S-Box Lookup", "ptrace anti-debug"
    PatternCategory category;
    PatternConfidence confidence;
    uint64_t start_inst_id = 0;                 // Pattern start position
    uint64_t end_inst_id = 0;                   // Pattern end position
    uint64_t anchor_pc = 0;                     // Key PC address
    std::string description;                    // Human-readable description
    std::vector<uint64_t> related_inst_ids;     // All inst_ids involved in the pattern

    // For crypto patterns: identified constants
    std::vector<uint64_t> constants_found;
};

// ─── Pattern pass result ──────────────────────────────────────────────────

struct PatternResult {
    std::vector<PatternMatch> matches;

    // Category index: category → indices into matches
    ankerl::unordered_dense::map<PatternCategory, std::vector<size_t>> by_category;

    /// Get all crypto-related matches.
    std::vector<const PatternMatch*> crypto_matches() const;

    /// Get all anti-debug matches.
    std::vector<const PatternMatch*> anti_debug_matches() const;

    /// Total number of pattern matches.
    size_t total() const { return matches.size(); }
};

// ─── Pattern analysis pass (YARA-based) ───────────────────────────────────

/// Detects cryptographic algorithm usage and anti-debug/anti-tamper patterns
/// using libyara for rule-based matching on trace data buffers.
///
/// The pass constructs several scannable buffers from the trace:
///   1. Register value buffer: concatenated 8-byte LE register diff values
///   2. Syscall buffer: 16-byte entries [inst_id(8) | syscall_no(2) | pad(6)]
///   3. Code buffer: raw opcode bytes from the code table
///
/// YARA rules are loaded from the rules/ directory (configurable).
///
/// Additionally, mnemonic-based detection (hardware crypto, XOR loops,
/// constant loading) is performed inline as before but can be extended
/// via custom YARA rules over the code buffer.
///
/// Result type: PatternResult
class PatternPass final : public AnalysisPass {
public:
    PatternPass();
    ~PatternPass() override;

    // Non-copyable, movable
    PatternPass(PatternPass&&) noexcept;
    PatternPass& operator=(PatternPass&&) noexcept;
    PatternPass(const PatternPass&) = delete;
    PatternPass& operator=(const PatternPass&) = delete;

    std::string_view name() const override { return "pattern"; }
    std::string_view description() const override {
        return "Detect crypto, anti-debug, and obfuscation patterns via YARA rules";
    }

    /// Optional soft dependency: if constant_materialization has already run,
    /// PatternPass will use its results for Detector3 (constant loading)
    /// instead of re-scanning the trace with the same logic.
    std::vector<std::string_view> dependencies() const override {
        return {};  // Hard dependencies: none. constant_materialization is consumed
                    // opportunistically via try_require() in run().
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 10.0f; }

    /// Set the directory containing .yar rule files.
    /// Must be called before run(). Defaults to "<exe_dir>/../rules/".
    void set_rules_dir(const std::filesystem::path& dir) { rules_dir_ = dir; }

    // ─── Public types (needed by YARA callback in .cpp) ──────────────────

    struct SyscallEntry {
        uint64_t inst_id;
        uint16_t syscall_no;
    };

    /// Parse category string from YARA meta.
    static PatternCategory parse_category(const std::string& s);
    /// Parse confidence string from YARA meta.
    static PatternConfidence parse_confidence(const std::string& s);

private:
    // ─── YARA integration ────────────────────────────────────────────────

    /// Load and compile all .yar files from rules_dir_.
    bool load_rules();

    /// Scan a buffer with YARA rules and collect matches into result.
    /// `buffer_name` identifies which buffer (for offset→inst_id mapping).
    void yara_scan_buffer(const uint8_t* data, size_t size,
                          const std::string& buffer_name,
                          PatternResult& result);

    // ─── Buffer construction ─────────────────────────────────────────────

    /// Build the register-value buffer from trace.
    /// Returns the buffer and a mapping: byte_offset → inst_id.
    struct RegValueBuffer {
        std::vector<uint8_t> data;
        std::vector<uint64_t> offset_to_inst_id;  // one entry per 8-byte slot
    };

    /// Build the syscall buffer from trace.
    struct SyscallBuffer {
        std::vector<uint8_t> data;
        std::vector<SyscallEntry> entries;
    };

    /// Build the code buffer (continuous opcode bytes from code table).
    struct CodeBuffer {
        std::vector<uint8_t> data;
        std::vector<uint64_t> offset_to_pc;  // byte offset → PC
    };
    CodeBuffer build_code_buffer(PassContext& ctx);

    // ─── Unified trace scan (replaces separate buffer + mnemonic scans) ──

    /// Single-pass scan that simultaneously:
    ///   - Optionally builds the reg_value buffer (for YARA scanning)
    ///   - Optionally builds the syscall buffer (for YARA scanning)
    ///   - Runs HW crypto detection (PC-deduped)
    ///   - Runs XOR loop detection (sliding window)
    ///   - Runs constant loading detection (movz+movk sequences)
    ///
    /// When `reg_buf` / `sys_buf` are non-null, the corresponding YARA
    /// buffer is built during the scan.  When null, buffer construction
    /// (and the regfile access it implies) is skipped entirely — this is
    /// the fast path when YARA is not compiled in or has no rules.
    ///
    /// When `constmat` is non-null, constant loading detection is skipped
    /// (its results are synthesised from constmat after the scan).
    ///
    /// This replaces the previous two full-trace scans with one, halving
    /// the trace I/O for PatternPass when YARA is active, and keeping the
    /// no-YARA path to a single scan (same as before).
    void scan_trace_unified(PassContext& ctx,
                            RegValueBuffer* reg_buf,
                            SyscallBuffer* sys_buf,
                            PatternResult& result,
                            const ConstantMaterializationResult* constmat);

    /// Convert ConstantMaterializationResult entries into PatternMatch objects
    /// and append them to result (replaces Detector3).
    static void constmat_to_pattern_matches(const ConstantMaterializationResult& cm,
                                             PatternResult& result);

    /// Build the by_category index from the matches vector.
    void build_category_index(PatternResult& result);

    /// Add a match and return a reference to it in the result.
    PatternMatch& add_match(PatternResult& result, PatternMatch match);

    // ─── State ───────────────────────────────────────────────────────────

    std::filesystem::path rules_dir_;
#ifdef TENET_HAS_YARA
    YR_RULES* yr_rules_ = nullptr;
#endif
    bool rules_loaded_ = false;

    // Cached syscall buffer from unified scan (unused — kept for ABI compat)
    SyscallBuffer cached_syscall_buf_;
    bool cached_syscall_buf_built_ = false;
};

}  // namespace tenet

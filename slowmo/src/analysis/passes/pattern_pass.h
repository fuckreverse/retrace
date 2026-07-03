#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
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

// ─── PatternCollector ─────────────────────────────────────────────────────

/// TraceCollector that runs all mnemonic-based pattern detectors in a single
/// sequential scan: HW crypto detection, XOR loop detection, and constant
/// loading detection.  Also optionally builds YARA reg-value and syscall
/// buffers during the same scan.
class PatternCollector final : public TraceCollector {
public:
    // ─── Public types (also used by PatternPass for YARA) ─────────────────

    struct SyscallEntry {
        uint64_t inst_id;
        uint16_t syscall_no;
    };

    struct RegValueBuffer {
        std::vector<uint8_t> data;
        std::vector<uint64_t> offset_to_inst_id;  // one entry per 8-byte slot
    };

    struct SyscallBuffer {
        std::vector<uint8_t> data;
        std::vector<SyscallEntry> entries;
    };

    PatternCollector(CodeTable& code_table,
                     InstructionDecoder& decoder,
                     RegisterFile* regfile,
                     bool build_yara_buffers,
                     const ConstantMaterializationResult* constmat,
                     uint32_t target_os = 0);

    std::string_view name() const override { return "PatternCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void end() override;

    /// Take ownership of results after scan completes.
    PatternResult take_result() { return std::move(result_); }
    RegValueBuffer take_reg_buf() { return std::move(reg_buf_); }
    SyscallBuffer take_sys_buf() { return std::move(sys_buf_); }

private:
    // ─── Mnemonic classification ──────────────────────────────────────────

    enum MnemonicClass : uint8_t {
        MC_OTHER        = 0,
        MC_HW_AES       = 1,
        MC_HW_SHA       = 2,
        MC_EOR          = 3,
        MC_MOVZ         = 4,
        MC_MOVK         = 5,
        MC_SVC          = 6,
    };

    struct PCInfo {
        MnemonicClass cls = MC_OTHER;
        char mnemonic[12]{};
        bool is_svc = false;
    };

    PatternMatch& add_match(PatternMatch match);

    /// Emit the currently-buffered XOR-loop candidate as a PatternMatch,
    /// choosing confidence based on how "loop-like" it looked (see the
    /// XOR loop detector state comment above). `end_pc` is the anchor PC
    /// to record (the instruction that broke the run, or 0 at end-of-trace).
    void flush_xor_loop_match(uint64_t end_pc);

    /// Emit the currently-buffered movz/movk load-sequence candidate as a
    /// PatternMatch. Always Low confidence: unlike constant_materialization
    /// (which this detector only runs as a fallback for, see the "Skipped
    /// when constmat result is available" comment at the call site), this
    /// path never checks the *value* being loaded against a known
    /// cryptographic constant table — it only knows "a register got
    /// assembled from >=3 immediate parts", which any 32/64-bit literal
    /// (pointer, offset, magic number, ...) can trigger.
    void flush_const_load_match();

    // ─── Configuration ───────────────────────────────────────────────────

    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile* regfile_;          // nullable; only needed for syscall buffer
    bool build_yara_buffers_;
    const ConstantMaterializationResult* constmat_;

    // ─── Pre-built PC classification ─────────────────────────────────────

    ankerl::unordered_dense::map<uint64_t, PCInfo> pc_info_;

    // 1-entry cache for pc_info lookup (high locality in loops)
    uint64_t last_pc_ = ~0ULL;
    MnemonicClass last_cls_ = MC_OTHER;
    const char* last_mn_str_ = "";
    bool last_is_svc_ = false;

    // ─── HW crypto detector state ────────────────────────────────────────

    struct HWCryptoSite {
        MnemonicClass cls = MC_OTHER;
        char mn[12]{};
        uint64_t exec_count   = 0;
        uint64_t first_inst_id = 0;
        uint64_t last_inst_id  = 0;
    };
    ankerl::unordered_dense::map<uint64_t, HWCryptoSite> hw_sites_;

    // ─── XOR loop detector state ─────────────────────────────────────────
    //
    // Heuristic note: a sliding window of "many EOR instructions" alone is
    // NOT sufficient evidence of a crypto round function — dense bit-packing
    // / checksum / masking code can trigger the same signature without any
    // loop structure at all.  To cut down on false positives we also track
    // how many *distinct* PCs appear across the whole candidate run: a real
    // loop body re-executes a small, fixed set of PCs over and over, whereas
    // straight-line code marching through many EORs keeps visiting new PCs
    // (unique PCs ~= instruction count).  We use that ratio to separate
    // "looks like a loop" (Medium confidence) from "just EOR-dense
    // straight-line code" (Low confidence, clearly labeled as such) instead
    // of asserting one fixed confidence for both cases.
    static constexpr size_t XOR_WINDOW_SIZE = 8;
    static constexpr size_t XOR_THRESHOLD  = 4;
    // If the number of distinct PCs seen in the run is <= this fraction of
    // the window size, treat it as "small repeating code region" (i.e.
    // consistent with an actual loop body) rather than straight-line code.
    static constexpr size_t XOR_LOOP_MAX_UNIQUE_PCS = XOR_WINDOW_SIZE / 2;

    // Parallel ring buffers: xor_ring_[i] says "was the i-th most recent
    // instruction an eor", xor_pc_ring_[i] says "what PC was it at". Both
    // are needed because when the window first fills up and the run is
    // detected, the instructions that were already sitting in the window
    // (but arrived before we started tracking `in_xor_loop_`) must still be
    // counted — otherwise the very first flush of a run would only see the
    // *last* instruction and always look like "1 unique PC", regardless of
    // whether the preceding 7 executions were actually a repeating loop
    // body or 7 unrelated straight-line instructions (see
    // seed_from_ring_window() below).
    bool xor_ring_[XOR_WINDOW_SIZE] = {};
    uint64_t xor_pc_ring_[XOR_WINDOW_SIZE] = {};
    uint64_t xor_inst_id_ring_[XOR_WINDOW_SIZE] = {};
    size_t xor_ring_pos_ = 0;
    size_t xor_ring_size_ = 0;
    size_t xor_eor_count_ = 0;
    bool in_xor_loop_ = false;
    uint64_t xor_loop_start_ = 0;
    std::vector<uint64_t> xor_loop_insts_;
    // Distinct PCs observed across the whole candidate run; used to decide
    // the confidence level when the match is flushed. A run that only ever
    // touches a handful of PCs looks like a tight loop body; one that keeps
    // visiting new PCs looks like straight-line code and gets downgraded to
    // Low confidence.
    ankerl::unordered_dense::set<uint64_t> xor_loop_unique_pcs_;

    /// Called exactly once, when a candidate run first starts (i.e. the
    /// window has just filled up and crossed XOR_THRESHOLD): backfills
    /// xor_loop_insts_/xor_loop_unique_pcs_ with the EOR instructions that
    /// are already sitting in the ring buffer (the ones that made the
    /// window cross the threshold in the first place), not just the one
    /// instruction that triggered detection.
    void seed_xor_loop_from_ring();

    // ─── Constant loading detector state ─────────────────────────────────

    static constexpr size_t CONST_LOAD_THRESHOLD = 3;

    bool in_load_seq_ = false;
    uint64_t load_seq_start_ = 0;
    std::vector<uint64_t> load_seq_insts_;
    uint64_t last_movz_pc_ = 0;

    // ─── YARA buffer state ───────────────────────────────────────────────

    static constexpr uint8_t REG_X16 = 16;   // Darwin syscall number register
    static constexpr uint8_t REG_X8  = 8;    // Linux/Android syscall number register
    static constexpr size_t SYSCALL_ENTRY_SIZE = 16;
    uint8_t syscall_reg_;                      // platform-selected syscall register

    RegValueBuffer reg_buf_;
    SyscallBuffer sys_buf_;

    // ─── Result ──────────────────────────────────────────────────────────

    PatternResult result_;
};

// ─── Pattern analysis pass (YARA-based) ───────────────────────────────────

/// Detects cryptographic algorithm usage and anti-debug/anti-tamper patterns.
/// Now delegates the trace scan to PatternCollector for scan fusion.
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
    void set_rules_dir(const std::filesystem::path& dir) { rules_dir_ = dir; }

    /// Parse category string from YARA meta.
    static PatternCategory parse_category(const std::string& s);
    /// Parse confidence string from YARA meta.
    static PatternConfidence parse_confidence(const std::string& s);

    // ─── Public types (needed by YARA callback in .cpp) ──────────────────

    using SyscallEntry = PatternCollector::SyscallEntry;

private:
    // ─── YARA integration ────────────────────────────────────────────────

    bool load_rules();

    void yara_scan_buffer(const uint8_t* data, size_t size,
                          const std::string& buffer_name,
                          PatternResult& result);

    struct CodeBuffer {
        std::vector<uint8_t> data;
        std::vector<uint64_t> offset_to_pc;
    };
    CodeBuffer build_code_buffer(PassContext& ctx);

    /// Convert ConstantMaterializationResult entries into PatternMatch objects.
    static void constmat_to_pattern_matches(const ConstantMaterializationResult& cm,
                                             PatternResult& result);

    /// Build the by_category index from the matches vector.
    void build_category_index(PatternResult& result);

    // ─── State ───────────────────────────────────────────────────────────

    std::filesystem::path rules_dir_;
#ifdef TENET_HAS_YARA
    YR_RULES* yr_rules_ = nullptr;
#endif
    bool rules_loaded_ = false;
};

}  // namespace tenet

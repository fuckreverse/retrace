#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <optional>
#include <ankerl/unordered_dense.h>
#include <filesystem>

#ifdef TENET_HAS_YARA
// Forward declare YARA types to avoid leaking yara.h
struct YR_RULES;
#endif

namespace tenet {

// ─── Known constant database (movz+movk constant materialization) ────────
//
// Absorbed from the former standalone `constant_materialization` pass:
// pattern's own instruction scan already visits every MOVZ/MOVK, so
// tracking materialized constants here avoids a second full trace pass
// and a duplicate MOVZ/MOVK decoder (see PatternCollector below).

/// A known constant that can be identified in movz+movk sequences.
struct KnownConstant {
    uint64_t value;
    std::string name;          // e.g. "SHA256_H0"
    std::string algorithm;     // e.g. "SHA-256"
    std::string description;   // e.g. "SHA-256 initial hash value H0"
    bool is_32bit;             // true if only lower 32 bits are significant

    KnownConstant(uint64_t v, std::string n, std::string algo,
                  std::string desc, bool is_32 = false)
        : value(v), name(std::move(n)), algorithm(std::move(algo)),
          description(std::move(desc)), is_32bit(is_32) {}
};

/// A constant value fully materialized through a movz+movk sequence in the trace.
struct MaterializedConstant {
    uint64_t value;                 // The final 64-bit constant value
    uint8_t dst_reg;                // Destination register index (x0-x28)
    uint64_t first_inst_id;         // inst_id of the movz
    uint64_t last_inst_id;          // inst_id of the last movk
    uint64_t pc_first;              // PC of the movz
    uint64_t pc_last;               // PC of the last movk
    uint8_t num_parts;              // Number of instructions (1=movz only, 2-4=movz+movk)

    // If identified, which known constant it matches
    const KnownConstant* known_match = nullptr;

    /// How many 16-bit slots were actually set (determines value width).
    uint8_t width_slots() const { return num_parts; }

    /// Is this a 32-bit constant (only hw0 and hw1 set)?
    bool is_32bit() const { return num_parts <= 2; }
};

/// Result of scanning movz+movk constant-construction sequences and
/// cross-referencing them against the known-constant database.
///
/// This used to be its own top-level pass result (`constant_materialization`);
/// it is now a sub-result embedded in PatternResult (see PatternResult::constants)
/// since PatternCollector computes it as part of its single trace scan.
struct ConstantMaterializationResult {
    /// All materialized constants found, sorted by first_inst_id.
    std::vector<MaterializedConstant> constants;

    /// Constants that matched a known algorithm constant.
    std::vector<size_t> identified_indices;   // indices into constants[]

    /// Group by algorithm: algorithm_name → indices into constants[]
    ankerl::unordered_dense::map<std::string, std::vector<size_t>> by_algorithm;

    /// Total number of materialized constants found.
    size_t total() const { return constants.size(); }

    /// Total number of identified (known) constants.
    size_t identified_count() const { return identified_indices.size(); }

    /// Get all constants matching a specific algorithm.
    std::vector<const MaterializedConstant*> for_algorithm(const std::string& algo) const {
        std::vector<const MaterializedConstant*> out;
        auto it = by_algorithm.find(algo);
        if (it != by_algorithm.end()) {
            for (size_t idx : it->second) {
                out.push_back(&constants[idx]);
            }
        }
        return out;
    }
};

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

    /// Materialized movz+movk constants found during the same scan (absorbed
    /// from the former standalone `constant_materialization` pass). Populated
    /// unconditionally by PatternCollector — every identified constant here
    /// also has a corresponding entry in `matches` (KeySchedule category) for
    /// uniform consumption, but code that wants the raw MaterializedConstant
    /// records (value, dst_reg, num_parts, known_match, ...) should use this
    /// field directly.
    ConstantMaterializationResult constants;

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
/// materialization (movz+movk) tracking.  Also optionally builds YARA
/// reg-value and syscall buffers during the same scan.
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
                     uint8_t constmat_min_parts,
                     uint32_t target_os = 0);

    std::string_view name() const override { return "PatternCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void end() override;

    /// Take ownership of results after scan completes.
    PatternResult take_result() { return std::move(result_); }
    RegValueBuffer take_reg_buf() { return std::move(reg_buf_); }
    SyscallBuffer take_sys_buf() { return std::move(sys_buf_); }

    /// Build the known-constants database (once, lazily, process-wide).
    /// Public + idempotent because the pattern-blob deserializer
    /// (pattern_pass.cpp) may need the database populated before any
    /// PatternCollector has been constructed (cache fast-path).
    static void build_known_db();

    /// Match a value against the known-constants database. Public because
    /// the pattern-blob deserializer (pattern_pass.cpp) needs to rebuild
    /// known_match pointers for cached MaterializedConstant entries.
    static const KnownConstant* lookup_known_constant(uint64_t value);

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

    // ─── Constant materialization (movz+movk) helpers ──────────────────────

    /// In-progress constant construction being tracked for a register.
    struct PendingConstant {
        uint64_t value = 0;             // Accumulated value
        uint8_t dst_reg = 0;            // Register index
        uint64_t first_inst_id = 0;     // inst_id of the movz
        uint64_t last_inst_id = 0;      // inst_id of the latest movk
        uint64_t pc_first = 0;          // PC of the movz
        uint64_t pc_last = 0;           // PC of the latest movk
        uint8_t num_parts = 0;          // Count of movz+movk instructions
        uint16_t shift_mask = 0;        // Bitmask of which hw shifts have been set
        bool active = false;            // Is this slot tracking a constant?
    };

    /// Decoded MOVZ/MOVK immediate + shift + destination register.
    struct MovImm {
        uint16_t imm16 = 0;
        uint8_t hw = 0;         // shift = hw * 16  (0, 1, 2, 3)
        uint8_t rd = 0;         // register index
        bool is_64bit = false;  // true = Xd, false = Wd
    };

    /// Try to decode a MOVZ/MOVK instruction from a raw opcode.
    /// Returns nullopt if the opcode is not a MOVZ or MOVK respectively.
    static std::optional<MovImm> decode_movz(uint32_t opcode);
    static std::optional<MovImm> decode_movk(uint32_t opcode);

    /// Flush a completed pending constant into constmat_result_ (subject to
    /// constmat_min_parts_).
    void flush_pending_constant(PendingConstant& pending);

    /// Build by_algorithm/identified_indices on constmat_result_, then
    /// append one PatternMatch (KeySchedule category) per constant so the
    /// unified `matches` view also reflects constant-materialization hits.
    void finalize_constants();

    // ─── Configuration ───────────────────────────────────────────────────

    CodeTable& code_table_;
    InstructionDecoder& decoder_;
    RegisterFile* regfile_;          // nullable; only needed for syscall buffer
    bool build_yara_buffers_;
    uint8_t constmat_min_parts_;     // min movz+movk parts to report (see PatternPass::set_constants_min_parts)

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

    // ─── Constant materialization detector state (movz+movk) ──────────────

    std::array<PendingConstant, 31> constmat_pending_{};
    ConstantMaterializationResult constmat_result_;

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
/// Delegates the trace scan to PatternCollector for scan fusion. Also owns
/// what used to be the standalone `constant_materialization` pass: movz+movk
/// constant tracking is folded into the same single trace scan (see
/// PatternResult::constants).
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
        return "Detect crypto constants, anti-debug, and obfuscation patterns via YARA rules";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — operates directly on trace + code_table + decoder.
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 12.0f; }

    /// Set the directory containing .yar rule files.
    void set_rules_dir(const std::filesystem::path& dir) { rules_dir_ = dir; }

    /// Set minimum number of movz+movk parts to report for the absorbed
    /// constant-materialization sub-detector (default: 2). Set to 1 to
    /// include standalone movz instructions.
    void set_constants_min_parts(uint8_t n) { constmat_min_parts_ = n; }

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

    /// Build the by_category index from the matches vector.
    void build_category_index(PatternResult& result);

    // ─── State ───────────────────────────────────────────────────────────

    std::filesystem::path rules_dir_;
#ifdef TENET_HAS_YARA
    YR_RULES* yr_rules_ = nullptr;
#endif
    bool rules_loaded_ = false;
    uint8_t constmat_min_parts_ = 2;
};

}  // namespace tenet

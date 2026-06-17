#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>

namespace tenet {

// ─── Known constant database ──────────────────────────────────────────────

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

// ─── Materialized constant record ─────────────────────────────────────────

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

// ─── Pass result ──────────────────────────────────────────────────────────

struct ConstantMaterializationResult {
    /// All materialized constants found, sorted by first_inst_id.
    std::vector<MaterializedConstant> constants;

    /// Constants that matched a known algorithm constant.
    std::vector<size_t> identified_indices;   // indices into constants[]

    /// Group by algorithm: algorithm_name → indices into constants[]
    std::unordered_map<std::string, std::vector<size_t>> by_algorithm;

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

// ─── Constant materialization pass ────────────────────────────────────────

/// Tracks AArch64 movz+movk instruction sequences to recover 64-bit constants
/// being constructed at runtime, then cross-references against a database of
/// known cryptographic / algorithmic constants.
///
/// AArch64 constant construction:
///   MOVZ Xd, #imm16, LSL #shift   → Xd = imm16 << shift (clear other bits)
///   MOVK Xd, #imm16, LSL #shift   → Xd[shift+15:shift] = imm16 (keep rest)
///
/// This pass extracts the final 64-bit value after a complete sequence and
/// matches it against known constants for SHA-256, AES, SM3, SM4, TEA, etc.
///
/// Result type: ConstantMaterializationResult
class ConstantMaterializationPass final : public AnalysisPass {
public:
    ConstantMaterializationPass();
    ~ConstantMaterializationPass() override = default;

    std::string_view name() const override { return "constant_materialization"; }
    std::string_view description() const override {
        return "Track movz+movk constant construction and identify known algorithm constants";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — operates directly on trace + code_table + decoder
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }

    /// Set minimum number of movz+movk parts to report (default: 2).
    /// Set to 1 to include standalone movz instructions.
    void set_min_parts(uint8_t n) { min_parts_ = n; }

private:
    // ─── Internal types ──────────────────────────────────────────────────

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

    /// Parse a MOVZ instruction and extract imm16, shift, and dst register.
    struct MovImm {
        uint16_t imm16 = 0;
        uint8_t hw = 0;         // shift = hw * 16  (0, 1, 2, 3)
        uint8_t rd = 0;         // register index
        bool is_64bit = false;  // true = Xd, false = Wd
    };

    /// Try to decode a MOVZ/MOVK instruction from a raw opcode.
    /// Returns nullopt if the opcode is not a MOVZ or MOVK.
    static std::optional<MovImm> decode_movz(uint32_t opcode);
    static std::optional<MovImm> decode_movk(uint32_t opcode);

    /// Flush a completed pending constant into the result.
    void flush_pending(PendingConstant& pending, ConstantMaterializationResult& result);

    /// Build the known-constants database.
    void build_known_db();

    /// Match a value against the known constants database.
    const KnownConstant* lookup(uint64_t value) const;

    /// Build by_algorithm index and identified_indices.
    void build_indices(ConstantMaterializationResult& result);

    // ─── State ───────────────────────────────────────────────────────────

    uint8_t min_parts_ = 2;

    /// Known constants database (value → KnownConstant).
    std::unordered_map<uint64_t, KnownConstant> known_db_;
    /// For 32-bit constants, also index the lower 32 bits.
    std::unordered_map<uint32_t, const KnownConstant*> known_db_32_;

    bool db_initialized_ = false;
};

}  // namespace tenet

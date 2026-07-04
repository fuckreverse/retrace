#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct EntropyConfig {
    /// Memory address to analyze.
    uint64_t addr = 0;
    /// Size of the region (bytes).
    uint32_t size = 256;
    /// At which instruction ID to sample memory (0 = end of trace).
    uint64_t at_inst_id = 0;
    /// Block size for per-block entropy calculation.
    uint32_t block_size = 16;
    /// Also compute entropy timeline (entropy of the region at multiple points).
    bool compute_timeline = false;
    /// Timeline sample interval (every N instructions that write to the region).
    uint32_t timeline_interval = 100;
};

// ─── Entropy block ─────────────────────────────────────────────────────────

struct EntropyBlock {
    uint64_t offset;        // Byte offset within the region
    uint32_t size;          // Block size
    float entropy;          // Shannon entropy (0.0 = all same, 8.0 = perfectly random)
    bool is_known = false;  // True if all bytes are known (were written during trace)
};

// ─── Entropy timeline entry ────────────────────────────────────────────────

struct EntropyTimelineEntry {
    uint64_t inst_id;       // Sampling point
    float overall_entropy;  // Entropy of the full region at this point
    uint32_t known_bytes;   // How many bytes have been written by this point
};

// ─── Result ────────────────────────────────────────────────────────────────

struct EntropyResult {
    /// Per-block entropy values.
    std::vector<EntropyBlock> blocks;

    /// Overall entropy of the full region.
    float overall_entropy = 0.0f;

    /// Classification based on entropy.
    enum Classification {
        Unknown,
        Plaintext,         // entropy < 4.0
        Compressed,        // entropy 6.0-7.5
        Encrypted,         // entropy > 7.5
        KeyMaterial,       // entropy 4.0-6.0 + small size
    } classification = Unknown;

    /// Entropy timeline (if requested).
    std::vector<EntropyTimelineEntry> timeline;

    /// Entropy transition points (where entropy changes significantly).
    struct Transition {
        uint64_t inst_id;
        float entropy_before;
        float entropy_after;
        float delta;        // after - before
    };
    std::vector<Transition> transitions;

    /// Region metadata.
    uint64_t addr = 0;
    uint32_t region_size = 0;
    uint32_t known_bytes = 0;
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Computes Shannon entropy of a memory region at a given point in time.
/// Useful for identifying ciphertext (high entropy), plaintext (low entropy),
/// and encryption boundaries (entropy transitions).
///
/// Dependencies: none (uses MemoryModel directly).
///
/// Result type: EntropyResult
class EntropyPass final : public AnalysisPass {
public:
    explicit EntropyPass(EntropyConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "entropy"; }
    std::string_view description() const override {
        return "Shannon entropy analysis of memory regions (ciphertext detection)";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 3.0f; }

private:
    EntropyConfig cfg_;

    /// Compute Shannon entropy of a byte buffer.
    static float compute_entropy(const uint8_t* data, size_t len);
};

}  // namespace tenet
